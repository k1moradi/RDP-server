// SPDX-License-Identifier: GPL-3.0-or-later
#include "platform/macos/mac_input_controller.h"
#include "platform/macos/native_display_reconfiguration.h"
#include "platform/macos/native_display_snapshot.h"
#include "platform/macos/native_session_change_watch.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace {

using rdp::macos::MacInputCallbacks;
using rdp::macos::MacInputController;
using rdp::macos::MacInputEvent;
using rdp::macos::MacKeyInput;
using rdp::macos::MacNativeInputCommand;
using rdp::macos::MacNativeInputKind;
using rdp::macos::MacPointerButton;
using rdp::macos::MacPointerButtonInput;
using rdp::macos::MacPointerMoveInput;
using rdp::macos::MacScrollAxis;
using rdp::macos::MacScrollInput;
using rdp::macos::NativeDisplayGeometryRefresh;
using rdp::macos::NativeDisplayObservation;
using rdp::macos::NativeDisplayReadStatus;
using rdp::macos::NativeDisplayReconfigurationWatch;
using rdp::macos::NativeSessionChangeRecorder;
using rdp::macos::NativeSessionChangeWatch;
using rdp::macos::NativeSessionChangeWatchCallbacks;

struct SessionWatchFixture final {
    NativeSessionChangeRecorder recorder{};
    std::uint64_t registrationEpoch{};
    std::size_t installCalls{};
    std::size_t removeCalls{};

    static bool install(void* const context, const std::uint64_t epoch,
                        const NativeSessionChangeRecorder callback) noexcept {
        auto& self = *static_cast<SessionWatchFixture*>(context);
        ++self.installCalls;
        self.registrationEpoch = epoch;
        self.recorder = callback;
        return callback != nullptr && epoch != 0;
    }

    static bool remove(void* const context) noexcept {
        auto& self = *static_cast<SessionWatchFixture*>(context);
        ++self.removeCalls;
        self.recorder = nullptr;
        self.registrationEpoch = 0;
        return true;
    }

    [[nodiscard]] NativeSessionChangeWatchCallbacks callbacks() noexcept {
        return {this, &install, &remove};
    }

    void recordChange() const noexcept {
        assert(recorder != nullptr && registrationEpoch != 0);
        recorder(registrationEpoch);
    }
};

SessionWatchFixture* gSessionWatchFixture{};

struct NativeDisplayFixture final {
    std::array<NativeDisplayObservation, 4> displays{};
    std::size_t count{1};
    std::size_t calls{};
};

[[nodiscard]] NativeDisplayReadStatus readSyntheticDisplays(
    void* const context, std::span<NativeDisplayObservation> destination,
    std::size_t& count) noexcept {
    auto& fixture = *static_cast<NativeDisplayFixture*>(context);
    ++fixture.calls;
    count = fixture.count;
    if (count > destination.size()) {
        return NativeDisplayReadStatus::Unavailable;
    }
    std::copy_n(fixture.displays.begin(), count, destination.begin());
    return NativeDisplayReadStatus::Ok;
}

[[nodiscard]] NativeDisplayFixture retinaFixture() noexcept {
    NativeDisplayFixture fixture;
    fixture.displays[0] = {
        100, 0.0, 0.0, 100.0, 100.0, 200, 200, 0, 0.0};
    return fixture;
}

[[nodiscard]] NativeDisplayFixture gappedFixture() noexcept {
    NativeDisplayFixture fixture;
    fixture.count = 2;
    fixture.displays[0] = {
        100, 0.0, 0.0, 100.0, 100.0, 200, 200, 0, 0.0};
    fixture.displays[1] = {
        200, 150.0, 0.0, 100.0, 100.0, 200, 200, 0, 0.0};
    return fixture;
}

[[nodiscard]] std::uint64_t refresh(
    NativeDisplayGeometryRefresh& geometry, NativeDisplayFixture& fixture) {
    const auto generation =
        geometry.refresh(&readSyntheticDisplays, &fixture);
    assert(generation);
    return *generation;
}

struct FakeInputBackend final {
    std::array<MacNativeInputCommand, 128> commands{};
    std::array<std::size_t, 64> batchSizes{};
    std::size_t commandCount{};
    std::size_t batchCount{};
    std::size_t forcedAccepted{static_cast<std::size_t>(-1)};
    MacInputController* controller{};
    bool cancelDuringSend{};
    bool reenterDuringSend{};
    bool revokeTopologyDuringSend{};
    bool revokeSessionDuringSend{};
    bool reentrantResult{true};

    static std::size_t send(
        void* const context,
        const std::span<const MacNativeInputCommand> input) noexcept {
        auto& self = *static_cast<FakeInputBackend*>(context);
        assert(self.batchCount < self.batchSizes.size());
        assert(self.commandCount + input.size() <= self.commands.size());
        self.batchSizes[self.batchCount++] = input.size();
        for (const auto& command : input) {
            self.commands[self.commandCount++] = command;
        }
        if (self.reenterDuringSend && self.controller != nullptr) {
            self.reentrantResult = self.controller->handle(
                MacKeyInput{12, 0x20, false, true});
        }
        if (self.cancelDuringSend && self.controller != nullptr) {
            self.cancelDuringSend = false;
            self.controller->cancel();
        }
        if (self.revokeTopologyDuringSend) {
            self.revokeTopologyDuringSend = false;
            NativeDisplayReconfigurationWatch::recordTopologyChange();
        }
        if (self.revokeSessionDuringSend) {
            self.revokeSessionDuringSend = false;
            assert(gSessionWatchFixture != nullptr);
            gSessionWatchFixture->recordChange();
        }
        return self.forcedAccepted == static_cast<std::size_t>(-1)
            ? input.size()
            : self.forcedAccepted;
    }

    [[nodiscard]] MacInputCallbacks callbacks() noexcept {
        return {this, &send};
    }
};

void assertNear(const double actual, const double expected) noexcept {
    assert(std::fabs(actual - expected) < 1e-9);
}

void testLifecycle() {
    NativeDisplayGeometryRefresh geometry;
    auto fixture = retinaFixture();
    const auto generation = refresh(geometry, fixture);
    FakeInputBackend backend;
    MacInputController controller(
        geometry, backend.callbacks(), generation);
    backend.controller = &controller;
    assert(!controller.closed() && controller.generation() == generation);

    assert(controller.handle(MacKeyInput{0, 0x1e, false, true}));
    assert(backend.commandCount == 1 && backend.batchSizes[0] == 1);
    assert(backend.commands[0].kind == MacNativeInputKind::KeyDown);
    assert(backend.commands[0].virtualKeyCode == 0);
    assert(controller.handle(MacKeyInput{0, 0x1e, false, true}));
    assert(backend.commandCount == 1);

    assert(controller.handle(MacPointerMoveInput{0, 0}));
    assert(backend.commands[1].kind == MacNativeInputKind::PointerMove);
    assertNear(backend.commands[1].xPoints, 0.25);
    assertNear(backend.commands[1].yPoints, 0.25);
    assert(!backend.commands[1].dragging);

    assert(controller.handle(MacPointerButtonInput{
        199, 199, MacPointerButton::X2, true}));
    assert(backend.batchSizes[2] == 2);
    assert(backend.commands[2].kind == MacNativeInputKind::PointerMove);
    assert(backend.commands[3].kind == MacNativeInputKind::ButtonDown);
    assert(backend.commands[3].button == MacPointerButton::X2);
    assertNear(backend.commands[3].xPoints, 99.75);
    assertNear(backend.commands[3].yPoints, 99.75);

    assert(controller.handle(MacPointerMoveInput{100, 120}));
    assert(backend.commands[4].kind == MacNativeInputKind::PointerMove);
    assert(backend.commands[4].dragging);
    assert(backend.commands[4].dragButton == MacPointerButton::X2);

    const std::size_t beforeHalfScroll = backend.commandCount;
    assert(controller.handle(
        MacScrollInput{100, 120, 60, MacScrollAxis::Vertical}));
    assert(backend.commandCount == beforeHalfScroll);
    assert(controller.handle(
        MacScrollInput{100, 120, 60, MacScrollAxis::Vertical}));
    assert(backend.commands[5].kind == MacNativeInputKind::VerticalScroll);
    assert(backend.commands[5].scrollSteps == 1);
    assert(controller.handle(
        MacScrollInput{100, 120, -240, MacScrollAxis::Horizontal}));
    assert(
        backend.commands[6].kind == MacNativeInputKind::HorizontalScroll);
    assert(backend.commands[6].scrollSteps == -2);

    // Break uses the native key captured at make time rather than trusting a
    // later caller-supplied translation.
    assert(controller.handle(MacKeyInput{999, 0x1e, false, false}));
    assert(backend.commands[7].kind == MacNativeInputKind::KeyUp);
    assert(backend.commands[7].virtualKeyCode == 0);

    controller.cancel();
    assert(controller.closed() && controller.generation() == 0);
    assert(backend.commands[8].kind == MacNativeInputKind::ButtonUp);
    assert(backend.commands[8].button == MacPointerButton::X2);
    const std::size_t finalCount = backend.commandCount;
    controller.cancel();
    assert(backend.commandCount == finalCount);
}

void testValidationDenials() {
    {
        NativeDisplayGeometryRefresh geometry;
        auto fixture = gappedFixture();
        const auto generation = refresh(geometry, fixture);
        FakeInputBackend backend;
        MacInputController controller(
            geometry, backend.callbacks(), generation);
        assert(!controller.handle(MacPointerMoveInput{250, 10}));
        assert(controller.closed() && backend.commandCount == 0);
    }

    const std::array<MacInputEvent, 4> invalidEvents{
        MacKeyInput{1, 0, false, true},
        MacPointerButtonInput{
            1, 1, static_cast<MacPointerButton>(99), true},
        MacScrollInput{
            1, 1, 120, static_cast<MacScrollAxis>(99)},
        MacScrollInput{
            1, 1,
            rdp::macos::kMacInputScrollUnitsPerStep *
                (rdp::macos::kMaximumMacInputScrollSteps + 1),
            MacScrollAxis::Vertical},
    };
    for (const auto& event : invalidEvents) {
        NativeDisplayGeometryRefresh geometry;
        auto fixture = retinaFixture();
        const auto generation = refresh(geometry, fixture);
        FakeInputBackend backend;
        MacInputController controller(
            geometry, backend.callbacks(), generation);
        assert(!controller.handle(event));
        assert(controller.closed() && backend.commandCount == 0);
    }

    // A repeated make for the same RDP scan identity cannot silently change
    // its already-held native macOS key mapping.
    {
        NativeDisplayGeometryRefresh geometry;
        auto fixture = retinaFixture();
        const auto generation = refresh(geometry, fixture);
        FakeInputBackend backend;
        MacInputController controller(
            geometry, backend.callbacks(), generation);
        assert(controller.handle(MacKeyInput{4, 0x30, false, true}));
        assert(!controller.handle(MacKeyInput{5, 0x30, false, true}));
        assert(controller.closed());
        assert(backend.commandCount == 2);
        assert(backend.commands[1].kind == MacNativeInputKind::KeyUp);
        assert(backend.commands[1].virtualKeyCode == 4);
    }

    // Missing callbacks, zero/stale generation, and already-revoked topology
    // are inert before any native command can be requested.
    {
        NativeDisplayGeometryRefresh geometry;
        auto fixture = retinaFixture();
        const auto generation = refresh(geometry, fixture);
        FakeInputBackend backend;
        MacInputController missing(geometry, {}, generation);
        assert(missing.closed());
        MacInputController zero(geometry, backend.callbacks(), 0);
        assert(zero.closed());
        MacInputController stale(
            geometry, backend.callbacks(), generation + 1);
        assert(stale.closed());
        NativeDisplayReconfigurationWatch::recordTopologyChange();
        MacInputController topology(
            geometry, backend.callbacks(), generation);
        assert(topology.closed());
        assert(backend.commandCount == 0);
    }
}

void testRevocationAndCleanup() {
    // Short native acceptance is terminal. Held input is released only while
    // the exact geometry/topology epoch remains current.
    {
        NativeDisplayGeometryRefresh geometry;
        auto fixture = retinaFixture();
        const auto generation = refresh(geometry, fixture);
        FakeInputBackend backend;
        MacInputController controller(
            geometry, backend.callbacks(), generation);
        assert(controller.handle(MacKeyInput{44, 0x1e, true, true}));
        backend.forcedAccepted = 1;
        assert(!controller.handle(MacPointerButtonInput{
            10, 10, MacPointerButton::Left, true}));
        assert(controller.closed());
        assert(
            backend.batchSizes[1] == 2 &&
            backend.batchSizes[2] == 1);
        assert(backend.commands[3].kind == MacNativeInputKind::KeyUp);
        assert(backend.commands[3].virtualKeyCode == 44);
    }

    // Reentry is denied. Cancellation from inside the native callback is
    // deferred until the successful make returns, then releases exactly once.
    {
        NativeDisplayGeometryRefresh geometry;
        auto fixture = retinaFixture();
        const auto generation = refresh(geometry, fixture);
        FakeInputBackend backend;
        MacInputController controller(
            geometry, backend.callbacks(), generation);
        backend.controller = &controller;
        backend.reenterDuringSend = true;
        assert(controller.handle(MacKeyInput{3, 0x20, false, true}));
        assert(!backend.reentrantResult);
        controller.cancel();
    }
    {
        NativeDisplayGeometryRefresh geometry;
        auto fixture = retinaFixture();
        const auto generation = refresh(geometry, fixture);
        FakeInputBackend backend;
        MacInputController controller(
            geometry, backend.callbacks(), generation);
        backend.controller = &controller;
        backend.cancelDuringSend = true;
        assert(!controller.handle(MacKeyInput{3, 0x20, false, true}));
        assert(controller.closed());
        assert(backend.commandCount == 2);
        assert(backend.commands[0].kind == MacNativeInputKind::KeyDown);
        assert(backend.commands[1].kind == MacNativeInputKind::KeyUp);
    }

    // A refreshed geometry generation terminally revokes the old controller
    // without injecting cleanup into the replacement desktop epoch.
    {
        NativeDisplayGeometryRefresh geometry;
        auto fixture = retinaFixture();
        const auto generation = refresh(geometry, fixture);
        FakeInputBackend backend;
        MacInputController controller(
            geometry, backend.callbacks(), generation);
        assert(controller.handle(MacKeyInput{7, 0x21, false, true}));
        auto replacement = retinaFixture();
        const auto nextGeneration = refresh(geometry, replacement);
        assert(nextGeneration > generation);
        assert(!controller.handle(MacPointerMoveInput{1, 1}));
        assert(controller.closed());
        assert(backend.commandCount == 1);
    }

    // A topology change that races one accepted synthetic native callback is
    // caught by the post-call fence; no stale-generation release is emitted.
    {
        NativeDisplayGeometryRefresh geometry;
        auto fixture = retinaFixture();
        const auto generation = refresh(geometry, fixture);
        FakeInputBackend backend;
        MacInputController controller(
            geometry, backend.callbacks(), generation);
        backend.revokeTopologyDuringSend = true;
        assert(!controller.handle(MacKeyInput{7, 0x21, false, true}));
        assert(controller.closed() && backend.commandCount == 1);
    }
}

void testSessionWatchRevocation() {
    assert(gSessionWatchFixture != nullptr);

    // Session loss is independent of unchanged geometry/topology. Held input
    // must be discarded rather than released into the potentially new user.
    {
        NativeDisplayGeometryRefresh geometry;
        auto fixture = retinaFixture();
        const auto generation = refresh(geometry, fixture);
        FakeInputBackend backend;
        MacInputController controller(geometry, backend.callbacks(), generation);
        assert(controller.handle(MacKeyInput{9, 0x22, false, true}));
        assert(controller.handle(MacPointerButtonInput{
            20, 20, MacPointerButton::Right, true}));
        assert(backend.commandCount == 3);

        gSessionWatchFixture->recordChange();
        assert(!controller.handle(MacPointerMoveInput{20, 20}));
        assert(controller.closed());
        assert(backend.commandCount == 3);
        controller.cancel();
        controller.cancel();
        assert(backend.commandCount == 3);

        // A later watch event with identical geometry cannot revive this owner.
        gSessionWatchFixture->recordChange();
        assert(!controller.handle(MacKeyInput{9, 0x22, false, false}));
        assert(backend.commandCount == 3);
    }

    // Revocation observed while the native callback is active fences the
    // accepted callback result before handle() can report success. No cleanup
    // callback is submitted after continuity is lost.
    {
        NativeDisplayGeometryRefresh geometry;
        auto fixture = retinaFixture();
        const auto generation = refresh(geometry, fixture);
        FakeInputBackend backend;
        MacInputController controller(geometry, backend.callbacks(), generation);
        backend.revokeSessionDuringSend = true;
        assert(!controller.handle(MacKeyInput{11, 0x23, false, true}));
        assert(controller.closed());
        assert(backend.commandCount == 1);
        assert(backend.commands[0].kind == MacNativeInputKind::KeyDown);
        controller.cancel();
        assert(backend.commandCount == 1);
    }
}

} // namespace

int main(const int argumentCount, const char* const arguments[]) {
    if (argumentCount != 2) {
        return 2;
    }
    SessionWatchFixture sessionWatchFixture;
    NativeSessionChangeWatch sessionWatch;
    gSessionWatchFixture = &sessionWatchFixture;
    const auto watchStarted = sessionWatch.startWithCallbacks(
        sessionWatchFixture.callbacks());
    assert(watchStarted);

    const std::string_view testCase = arguments[1];
    if (testCase == "lifecycle") {
        testLifecycle();
    } else if (testCase == "validation-denials") {
        testValidationDenials();
    } else if (testCase == "revocation-cleanup") {
        testRevocationAndCleanup();
    } else if (testCase == "session-watch-revocation") {
        testSessionWatchRevocation();
    } else {
        return 2;
    }
    assert(sessionWatch.stop());
    assert(sessionWatchFixture.removeCalls == 1);
    gSessionWatchFixture = nullptr;
    return 0;
}
