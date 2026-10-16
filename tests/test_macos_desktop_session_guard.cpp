// SPDX-License-Identifier: GPL-3.0-or-later
#include "platform/macos/mac_desktop_session_guard.h"
#include "platform/macos/native_display_reconfiguration.h"
#include "platform/macos/native_display_snapshot.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace {

using namespace rdp::macos;

constexpr NativeDisplayObservation kDisplay{
    100, 0, 0, 1512, 982, 3024, 1964, 0};

struct DisplayFixture final {
    std::array<NativeDisplayObservation, 1> sample{kDisplay};
    std::size_t calls{};
};

[[nodiscard]] NativeDisplayReadStatus readDisplay(
    void* context, std::span<NativeDisplayObservation> destination,
    std::size_t& count) noexcept {
    auto& fixture = *static_cast<DisplayFixture*>(context);
    ++fixture.calls;
    count = fixture.sample.size();
    for (std::size_t index = 0;
         index < (std::min)(destination.size(), fixture.sample.size());
         ++index) {
        destination[index] = fixture.sample[index];
    }
    return NativeDisplayReadStatus::Ok;
}

[[nodiscard]] std::uint64_t refreshGeometry(
    NativeDisplayGeometryRefresh& geometry, DisplayFixture& fixture) {
    const auto result = geometry.refresh(&readDisplay, &fixture);
    assert(result);
    return *result;
}

struct FakeSessionWatchBackend final {
    NativeSessionChangeRecorder recorder{};
    NativeSessionChangeRecorder lastRecorder{};
    std::uint64_t registrationEpoch{};
    std::uint64_t lastRegistrationEpoch{};
    std::size_t installs{};
    std::size_t removals{};
    bool installSucceeds{true};
    bool removeSucceeds{true};
    bool eventDuringInstall{};

    static bool install(void* context, const std::uint64_t epoch,
                        const NativeSessionChangeRecorder recorder) noexcept {
        auto& self = *static_cast<FakeSessionWatchBackend*>(context);
        ++self.installs;
        if (!self.installSucceeds) {
            return false;
        }
        self.recorder = recorder;
        self.lastRecorder = recorder;
        self.registrationEpoch = epoch;
        self.lastRegistrationEpoch = epoch;
        if (self.eventDuringInstall) {
            recorder(epoch);
        }
        return true;
    }

    static bool remove(void* context) noexcept {
        auto& self = *static_cast<FakeSessionWatchBackend*>(context);
        ++self.removals;
        if (!self.removeSucceeds) {
            return false;
        }
        self.recorder = nullptr;
        self.registrationEpoch = 0;
        return true;
    }

    [[nodiscard]] NativeSessionChangeWatchCallbacks callbacks() noexcept {
        return {this, &install, &remove};
    }

    void notify() noexcept {
        assert(recorder != nullptr && registrationEpoch != 0);
        recorder(registrationEpoch);
    }

    void notifyDelayed() noexcept {
        assert(lastRecorder != nullptr && lastRegistrationEpoch != 0);
        lastRecorder(lastRegistrationEpoch);
    }
};

void startSessionWatch(NativeSessionChangeWatch& watch,
                       FakeSessionWatchBackend& backend) {
    const auto result = watch.startWithCallbacks(backend.callbacks());
    assert(result);
    assert(watch.registered());
    assert(NativeSessionChangeWatch::coveredRevision());
}

struct FakeDesktopAccess final {
    MacDesktopSessionObservation session{501, 501, true, true};
    ScreenCapturePreflightStatus capture{ScreenCapturePreflightStatus::Granted};
    MacInputPermissionStatus input{MacInputPermissionStatus::Trusted};
    MacDesktopSessionGuard* guard{};
    FakeSessionWatchBackend* sessionWatch{};
    std::size_t sessionReads{};
    std::size_t captureReads{};
    std::size_t inputReads{};
    bool failSessionRead{};
    bool changeSessionDuringCapture{};
    bool changeTopologyDuringCapture{};
    bool changeSessionWatchDuringCapture{};
    bool changeSessionWatchDuringInput{};
    bool closeDuringCapture{};
    bool reenterDuringInput{};
    bool reentrantResult{true};

    static bool readSession(
        void* context, MacDesktopSessionObservation& observation) noexcept {
        auto& self = *static_cast<FakeDesktopAccess*>(context);
        ++self.sessionReads;
        if (self.failSessionRead) {
            return false;
        }
        observation = self.session;
        return true;
    }

    static ScreenCapturePreflightStatus readCapture(void* context) noexcept {
        auto& self = *static_cast<FakeDesktopAccess*>(context);
        ++self.captureReads;
        if (self.changeSessionDuringCapture) {
            ++self.session.sessionUserId;
        }
        if (self.changeTopologyDuringCapture) {
            NativeDisplayReconfigurationWatch::recordTopologyChange();
        }
        if (self.changeSessionWatchDuringCapture &&
            self.sessionWatch != nullptr) {
            self.sessionWatch->notify();
        }
        if (self.closeDuringCapture && self.guard != nullptr) {
            self.guard->close();
        }
        return self.capture;
    }

    static MacInputPermissionStatus readInput(void* context) noexcept {
        auto& self = *static_cast<FakeDesktopAccess*>(context);
        ++self.inputReads;
        if (self.changeSessionWatchDuringInput &&
            self.sessionWatch != nullptr) {
            self.sessionWatch->notify();
        }
        if (self.reenterDuringInput && self.guard != nullptr) {
            self.reentrantResult =
                self.guard->allows(MacDesktopAccessKind::Capture);
        }
        return self.input;
    }

    [[nodiscard]] MacDesktopSessionReadCallbacks sessionCallbacks() noexcept {
        return {this, &readSession};
    }

    [[nodiscard]] MacDesktopPermissionReadCallbacks
    permissionCallbacks() noexcept {
        return {this, &readCapture, &readInput};
    }
};

void testLifecycle() {
    FakeSessionWatchBackend watchBackend;
    NativeSessionChangeWatch watch;
    startSessionWatch(watch, watchBackend);

    NativeDisplayGeometryRefresh geometry;
    DisplayFixture display;
    const auto generation = refreshGeometry(geometry, display);

    FakeDesktopAccess backend;
    MacDesktopSessionGuard guard(
        geometry, generation, 501, backend.sessionCallbacks(),
        backend.permissionCallbacks());
    assert(!guard.closed());
    assert(guard.targetUserId() == 501);
    assert(guard.geometryGeneration() == generation);

    assert(guard.allows(MacDesktopAccessKind::Capture));
    assert(backend.sessionReads == 2);
    assert(backend.captureReads == 1);
    assert(backend.inputReads == 0);

    assert(guard.allows(MacDesktopAccessKind::Input));
    assert(backend.sessionReads == 4);
    assert(backend.captureReads == 1);
    assert(backend.inputReads == 1);

    guard.close();
    assert(guard.closed());
    assert(guard.targetUserId() == 0);
    assert(guard.geometryGeneration() == 0);
    assert(!guard.allows(MacDesktopAccessKind::Capture));
    assert(backend.captureReads == 1);
}

void testValidationDenials() {
    FakeSessionWatchBackend watchBackend;
    NativeSessionChangeWatch watch;
    startSessionWatch(watch, watchBackend);

    NativeDisplayGeometryRefresh geometry;
    DisplayFixture display;
    const auto generation = refreshGeometry(geometry, display);

    {
        FakeDesktopAccess backend;
        MacDesktopSessionGuard guard(
            geometry, generation, 0, backend.sessionCallbacks(),
            backend.permissionCallbacks());
        assert(guard.closed());
    }
    {
        FakeDesktopAccess backend;
        auto session = backend.sessionCallbacks();
        session.read = nullptr;
        MacDesktopSessionGuard guard(
            geometry, generation, 501, session, backend.permissionCallbacks());
        assert(guard.closed());
    }
    {
        FakeDesktopAccess backend;
        auto permissions = backend.permissionCallbacks();
        permissions.capture = nullptr;
        MacDesktopSessionGuard guard(
            geometry, generation, 501, backend.sessionCallbacks(), permissions);
        assert(guard.closed());
    }

    for (int denial = 0; denial < 4; ++denial) {
        FakeDesktopAccess backend;
        if (denial == 0) {
            backend.session.sessionUserId = 502;
        } else if (denial == 1) {
            backend.session.effectiveUserId = 502;
        } else if (denial == 2) {
            backend.session.onConsole = false;
        } else {
            backend.session.loginComplete = false;
        }
        MacDesktopSessionGuard guard(
            geometry, generation, 501, backend.sessionCallbacks(),
            backend.permissionCallbacks());
        assert(!guard.allows(MacDesktopAccessKind::Capture));
        assert(guard.closed());
        assert(backend.captureReads == 0);
    }

    {
        FakeDesktopAccess backend;
        backend.capture = ScreenCapturePreflightStatus::NotGranted;
        MacDesktopSessionGuard guard(
            geometry, generation, 501, backend.sessionCallbacks(),
            backend.permissionCallbacks());
        assert(!guard.allows(MacDesktopAccessKind::Capture));
        assert(guard.closed() && backend.captureReads == 1);
    }
    {
        FakeDesktopAccess backend;
        backend.input = MacInputPermissionStatus::NotTrusted;
        MacDesktopSessionGuard guard(
            geometry, generation, 501, backend.sessionCallbacks(),
            backend.permissionCallbacks());
        assert(!guard.allows(MacDesktopAccessKind::Input));
        assert(guard.closed() && backend.inputReads == 1);
    }
    {
        FakeDesktopAccess backend;
        MacDesktopSessionGuard guard(
            geometry, generation, 501, backend.sessionCallbacks(),
            backend.permissionCallbacks());
        assert(!guard.allows(static_cast<MacDesktopAccessKind>(99)));
        assert(guard.closed());
    }
}

void testRevocationAndReentry() {
    FakeSessionWatchBackend watchBackend;
    NativeSessionChangeWatch watch;
    startSessionWatch(watch, watchBackend);

    {
        NativeDisplayGeometryRefresh geometry;
        DisplayFixture display;
        const auto generation = refreshGeometry(geometry, display);
        FakeDesktopAccess backend;
        MacDesktopSessionGuard guard(
            geometry, generation, 501, backend.sessionCallbacks(),
            backend.permissionCallbacks());
        backend.changeSessionDuringCapture = true;
        assert(!guard.allows(MacDesktopAccessKind::Capture));
        assert(guard.closed());
        assert(backend.sessionReads == 2 && backend.captureReads == 1);
    }

    {
        NativeDisplayGeometryRefresh geometry;
        DisplayFixture display;
        const auto generation = refreshGeometry(geometry, display);
        FakeDesktopAccess backend;
        MacDesktopSessionGuard guard(
            geometry, generation, 501, backend.sessionCallbacks(),
            backend.permissionCallbacks());
        backend.changeTopologyDuringCapture = true;
        assert(!guard.allows(MacDesktopAccessKind::Capture));
        assert(guard.closed());
    }

    {
        NativeDisplayGeometryRefresh geometry;
        DisplayFixture display;
        const auto generation = refreshGeometry(geometry, display);
        FakeDesktopAccess backend;
        MacDesktopSessionGuard guard(
            geometry, generation, 501, backend.sessionCallbacks(),
            backend.permissionCallbacks());
        backend.guard = &guard;
        backend.reenterDuringInput = true;
        assert(!guard.allows(MacDesktopAccessKind::Input));
        assert(!backend.reentrantResult);
        assert(guard.closed());
    }

    {
        NativeDisplayGeometryRefresh geometry;
        DisplayFixture display;
        const auto generation = refreshGeometry(geometry, display);
        FakeDesktopAccess backend;
        MacDesktopSessionGuard guard(
            geometry, generation, 501, backend.sessionCallbacks(),
            backend.permissionCallbacks());
        backend.guard = &guard;
        backend.closeDuringCapture = true;
        assert(!guard.allows(MacDesktopAccessKind::Capture));
        assert(guard.closed());
    }

    {
        NativeDisplayGeometryRefresh geometry;
        DisplayFixture display;
        const auto generation = refreshGeometry(geometry, display);
        FakeDesktopAccess backend;
        MacDesktopSessionGuard guard(
            geometry, generation, 501, backend.sessionCallbacks(),
            backend.permissionCallbacks());
        assert(guard.allows(MacDesktopAccessKind::Capture));
        DisplayFixture replacement;
        const auto nextGeneration = refreshGeometry(geometry, replacement);
        assert(nextGeneration > generation);
        assert(!guard.allows(MacDesktopAccessKind::Capture));
        assert(guard.closed());
    }

    {
        NativeDisplayGeometryRefresh geometry;
        DisplayFixture display;
        const auto generation = refreshGeometry(geometry, display);
        FakeDesktopAccess backend;
        MacDesktopSessionGuard guard(
            geometry, generation, 501, backend.sessionCallbacks(),
            backend.permissionCallbacks());
        backend.failSessionRead = true;
        assert(!guard.allows(MacDesktopAccessKind::Capture));
        assert(guard.closed() && backend.captureReads == 0);
    }
}

void testSwitchAwayBackRevocation() {
    FakeSessionWatchBackend watchBackend;
    NativeSessionChangeWatch watch;
    startSessionWatch(watch, watchBackend);

    NativeDisplayGeometryRefresh geometry;
    DisplayFixture display;
    const auto generation = refreshGeometry(geometry, display);
    FakeDesktopAccess backend;
    MacDesktopSessionGuard guard(
        geometry, generation, 501, backend.sessionCallbacks(),
        backend.permissionCallbacks());

    assert(guard.allows(MacDesktopAccessKind::Capture));
    const auto beforeSwitch = NativeSessionChangeWatch::coveredRevision();
    assert(beforeSwitch);
    watchBackend.notify();
    watchBackend.notify();
    const auto afterSwitch = NativeSessionChangeWatch::coveredRevision();
    assert(afterSwitch && *afterSwitch > *beforeSwitch);
    assert(!guard.allows(MacDesktopAccessKind::Capture));
    assert(guard.closed());
    assert(backend.captureReads == 1);
}

void testMidOperationEpochChange() {
    FakeSessionWatchBackend watchBackend;
    NativeSessionChangeWatch watch;
    startSessionWatch(watch, watchBackend);

    {
        NativeDisplayGeometryRefresh geometry;
        DisplayFixture display;
        const auto generation = refreshGeometry(geometry, display);
        FakeDesktopAccess backend;
        backend.sessionWatch = &watchBackend;
        backend.changeSessionWatchDuringCapture = true;
        MacDesktopSessionGuard guard(
            geometry, generation, 501, backend.sessionCallbacks(),
            backend.permissionCallbacks());
        assert(!guard.allows(MacDesktopAccessKind::Capture));
        assert(guard.closed());
        assert(backend.sessionReads == 2 && backend.captureReads == 1);
    }
    {
        NativeDisplayGeometryRefresh geometry;
        DisplayFixture display;
        const auto generation = refreshGeometry(geometry, display);
        FakeDesktopAccess backend;
        backend.sessionWatch = &watchBackend;
        backend.changeSessionWatchDuringInput = true;
        MacDesktopSessionGuard guard(
            geometry, generation, 501, backend.sessionCallbacks(),
            backend.permissionCallbacks());
        assert(!guard.allows(MacDesktopAccessKind::Input));
        assert(guard.closed());
        assert(backend.sessionReads == 2 && backend.inputReads == 1);
    }
}

void testWatchRegistrationRetirement() {
    assert(!NativeSessionChangeWatch::coveredRevision());

    {
        NativeSessionChangeWatch invalid;
        const auto result = invalid.startWithCallbacks({});
        assert(!result);
        assert(result.error() ==
               NativeSessionChangeWatchError::InvalidCallbacks);
    }
    {
        FakeSessionWatchBackend failedBackend;
        failedBackend.installSucceeds = false;
        NativeSessionChangeWatch failedWatch;
        const auto result =
            failedWatch.startWithCallbacks(failedBackend.callbacks());
        assert(!result);
        assert(result.error() ==
               NativeSessionChangeWatchError::RegistrationFailed);
        assert(failedBackend.installs == 1 &&
               failedBackend.removals == 1);
        assert(!failedWatch.registered());
        assert(!NativeSessionChangeWatch::coveredRevision());
    }

    FakeSessionWatchBackend firstBackend;
    NativeSessionChangeWatch firstWatch;
    startSessionWatch(firstWatch, firstBackend);
    const auto firstRevision = NativeSessionChangeWatch::coveredRevision();
    assert(firstRevision);

    FakeSessionWatchBackend duplicateBackend;
    NativeSessionChangeWatch duplicateWatch;
    const auto duplicate =
        duplicateWatch.startWithCallbacks(duplicateBackend.callbacks());
    assert(!duplicate);
    assert(duplicate.error() ==
           NativeSessionChangeWatchError::AlreadyRegistered);
    assert(duplicateBackend.installs == 0);

    assert(firstWatch.stop());
    assert(!NativeSessionChangeWatch::coveredRevision());
    assert(firstWatch.stop());
    firstBackend.notifyDelayed();
    assert(!NativeSessionChangeWatch::coveredRevision());

    FakeSessionWatchBackend replacementBackend;
    replacementBackend.eventDuringInstall = true;
    NativeSessionChangeWatch replacementWatch;
    startSessionWatch(replacementWatch, replacementBackend);
    const auto replacementRevision =
        NativeSessionChangeWatch::coveredRevision();
    assert(replacementRevision && *replacementRevision > *firstRevision);

    firstBackend.notifyDelayed();
    const auto afterDelayed = NativeSessionChangeWatch::coveredRevision();
    assert(afterDelayed && *afterDelayed == *replacementRevision);

    replacementBackend.removeSucceeds = false;
    const auto failedRemoval = replacementWatch.stop();
    assert(!failedRemoval);
    assert(failedRemoval.error() ==
           NativeSessionChangeWatchError::RemovalFailed);
    assert(!NativeSessionChangeWatch::coveredRevision());

    FakeSessionWatchBackend blockedBackend;
    NativeSessionChangeWatch blockedWatch;
    const auto blocked =
        blockedWatch.startWithCallbacks(blockedBackend.callbacks());
    assert(!blocked);
    assert(blocked.error() ==
           NativeSessionChangeWatchError::AlreadyRegistered);
    assert(blockedBackend.installs == 0);

    replacementBackend.removeSucceeds = true;
    assert(replacementWatch.stop());
    startSessionWatch(blockedWatch, blockedBackend);
    assert(blockedWatch.stop());
}

void testWatchUnavailableDenial() {
    NativeDisplayGeometryRefresh geometry;
    DisplayFixture display;
    const auto generation = refreshGeometry(geometry, display);
    FakeDesktopAccess backend;

    MacDesktopSessionGuard unavailableGuard(
        geometry, generation, 501, backend.sessionCallbacks(),
        backend.permissionCallbacks());
    assert(unavailableGuard.closed());
    assert(!unavailableGuard.allows(MacDesktopAccessKind::Capture));
    assert(backend.sessionReads == 0 && backend.captureReads == 0);

    FakeSessionWatchBackend watchBackend;
    NativeSessionChangeWatch watch;
    startSessionWatch(watch, watchBackend);
    MacDesktopSessionGuard coveredGuard(
        geometry, generation, 501, backend.sessionCallbacks(),
        backend.permissionCallbacks());
    assert(!coveredGuard.closed());

    assert(watch.stop());
    assert(!coveredGuard.allows(MacDesktopAccessKind::Capture));
    assert(coveredGuard.closed());
    assert(backend.captureReads == 0);

    MacDesktopSessionGuard stoppedCoverageGuard(
        geometry, generation, 501, backend.sessionCallbacks(),
        backend.permissionCallbacks());
    assert(stoppedCoverageGuard.closed());
}


} // namespace

int main(const int argumentCount, const char* const arguments[]) {
    if (argumentCount != 2) {
        return 2;
    }
    const std::string_view testCase = arguments[1];
    if (testCase == "lifecycle") {
        testLifecycle();
    } else if (testCase == "validation-denials") {
        testValidationDenials();
    } else if (testCase == "revocation-reentry") {
        testRevocationAndReentry();
    } else if (testCase == "switch-away-back-revocation") {
        testSwitchAwayBackRevocation();
    } else if (testCase == "mid-operation-epoch-change") {
        testMidOperationEpochChange();
    } else if (testCase == "watch-registration-retirement") {
        testWatchRegistrationRetirement();
    } else if (testCase == "watch-unavailable-denial") {
        testWatchUnavailableDenial();
    } else {
        return 2;
    }
    return 0;
}
