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

struct FakeDesktopAccess final {
    MacDesktopSessionObservation session{501, 501, true, true};
    ScreenCapturePreflightStatus capture{ScreenCapturePreflightStatus::Granted};
    MacInputPermissionStatus input{MacInputPermissionStatus::Trusted};
    MacDesktopSessionGuard* guard{};
    std::size_t sessionReads{};
    std::size_t captureReads{};
    std::size_t inputReads{};
    bool failSessionRead{};
    bool changeSessionDuringCapture{};
    bool changeTopologyDuringCapture{};
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
        return self.capture;
    }

    static MacInputPermissionStatus readInput(void* context) noexcept {
        auto& self = *static_cast<FakeDesktopAccess*>(context);
        ++self.inputReads;
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
    } else {
        return 2;
    }
    return 0;
}
