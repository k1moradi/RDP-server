// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows/windows_capture_session_guard.h"
#include "windows/windows_input_controller.h"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>

using namespace rdp_server::windows;

namespace
{

struct FakeSessionSource final
{
    std::uint32_t processSessionId{42};
    bool active{true};
    bool fail{};
    bool reenter{};
    bool notifyOnRead{};
    unsigned reads{};
    WindowsCaptureSessionGenerationGuard *guard{};
    bool reentrantResult{true};
    WindowsCaptureSessionChangeResult notificationResult{
        WindowsCaptureSessionChangeResult::ignored};

    static bool read(
        void *context, std::uint32_t targetSessionId,
        WindowsCaptureSessionObservation &observation) noexcept
    {
        auto &self = *static_cast<FakeSessionSource *>(context);
        ++self.reads;
        if (self.reenter && self.guard != nullptr)
        {
            WindowsCaptureGeneration nested{};
            const auto reader = self.guard->reader();
            self.reentrantResult =
                reader.read != nullptr &&
                reader.read(reader.context, nested);
        }
        if (self.notifyOnRead && self.guard != nullptr)
        {
            self.notificationResult =
                self.guard->notifySessionChange(targetSessionId);
        }
        if (self.fail)
        {
            return false;
        }
        observation = {
            targetSessionId, self.processSessionId, self.active};
        return true;
    }

    [[nodiscard]] WindowsCaptureSessionReadCallbacks callbacks() noexcept
    {
        return {this, &read};
    }
};

struct FakeGenerationSource final
{
    WindowsCaptureGeneration current{101, 202};
    bool fail{};
    unsigned reads{};

    static bool read(
        void *context, WindowsCaptureGeneration &output) noexcept
    {
        auto &self = *static_cast<FakeGenerationSource *>(context);
        ++self.reads;
        if (self.fail)
        {
            return false;
        }
        output = self.current;
        return true;
    }

    [[nodiscard]] WindowsCaptureGenerationReader callbacks() noexcept
    {
        return {this, &read};
    }
};

struct FakeInputBackend final
{
    std::array<WindowsNativeInputCommand, 16> commands{};
    std::size_t commandCount{};
    WindowsCaptureSessionGenerationGuard *guard{};
    bool sentAfterRevocation{};

    static std::size_t send(
        void *context,
        std::span<const WindowsNativeInputCommand> commands) noexcept
    {
        auto &self = *static_cast<FakeInputBackend *>(context);
        assert(self.commandCount + commands.size() <= self.commands.size());
        if (self.guard != nullptr && self.guard->closed())
        {
            self.sentAfterRevocation = true;
        }
        for (const auto &command : commands)
        {
            self.commands[self.commandCount++] = command;
        }
        return commands.size();
    }

    [[nodiscard]] WindowsInputCallbacks callbacks() noexcept
    {
        return {this, &send};
    }
};

struct FakeFramePipeline final
{
    std::array<std::byte, 4> pixels{
        std::byte{0x12}, std::byte{0x34},
        std::byte{0x56}, std::byte{0xff}};
    std::array<char, 8> retirementOrder{};
    std::byte token{};
    std::size_t retirementOrderCount{};
    unsigned acquisitions{};
    unsigned maps{};
    unsigned unmaps{};
    unsigned releases{};
    WindowsCaptureSessionGenerationGuard *sessionGuard{};
    WindowsDxgiCaptureCycle *captureCycle{};
    WindowsInputController *inputController{};
    bool revokeDuringMap{};
    bool teardownDeferredDuringMap{};
    bool postRevocationInputAccepted{true};
    WindowsCaptureCycleResult nestedCaptureResult{
        WindowsCaptureCycleResult::failed};
    WindowsCaptureSessionChangeResult notificationResult{
        WindowsCaptureSessionChangeResult::ignored};

    static WindowsDxgiAcquireResult acquire(
        void *context, std::uint32_t, void *&resource,
        WindowsDxgiFrameInfo &) noexcept
    {
        auto &self = *static_cast<FakeFramePipeline *>(context);
        ++self.acquisitions;
        resource = &self.token;
        return WindowsDxgiAcquireResult::acquired;
    }

    static WindowsDxgiReleaseResult release(
        void *context, void *resource) noexcept
    {
        auto &self = *static_cast<FakeFramePipeline *>(context);
        assert(resource == &self.token);
        ++self.releases;
        assert(self.retirementOrderCount < self.retirementOrder.size());
        self.retirementOrder[self.retirementOrderCount++] = 'R';
        return WindowsDxgiReleaseResult::released;
    }

    static WindowsD3D11MapResult map(
        void *context, void *resource,
        WindowsD3D11MappedData &output) noexcept
    {
        auto &self = *static_cast<FakeFramePipeline *>(context);
        assert(resource == &self.token);
        ++self.maps;
        output = {
            self.pixels.data(), self.pixels.size(), {1, 1}, 4, &self.token};
        if (self.revokeDuringMap)
        {
            assert(self.sessionGuard != nullptr);
            assert(self.captureCycle != nullptr);
            assert(self.inputController != nullptr);
            self.revokeDuringMap = false;
            self.notificationResult =
                retireWindowsNativeConsumersOnSessionChange(
                    *self.sessionGuard, *self.captureCycle,
                    *self.inputController, 42);
            self.teardownDeferredDuringMap =
                self.unmaps == 0 && self.releases == 0;
            self.nestedCaptureResult = self.captureCycle->captureFrame(0);
            self.postRevocationInputAccepted =
                self.inputController->handle(
                    WindowsKeyInput{0x20, false, true});
        }
        return WindowsD3D11MapResult::mapped;
    }

    static void unmap(void *context, void *handle) noexcept
    {
        auto &self = *static_cast<FakeFramePipeline *>(context);
        assert(handle == &self.token);
        ++self.unmaps;
        assert(self.retirementOrderCount < self.retirementOrder.size());
        self.retirementOrder[self.retirementOrderCount++] = 'U';
    }

    [[nodiscard]] WindowsDxgiFrameCallbacks frameCallbacks() noexcept
    {
        return {this, &acquire, &release};
    }

    [[nodiscard]] WindowsD3D11StagingCallbacks stagingCallbacks() noexcept
    {
        return {this, &map, &unmap};
    }
};

[[nodiscard]] WindowsDesktopLayout onePixelLayout() noexcept
{
    WindowsDesktopLayout layout{};
    layout.monitorCount = 1;
    layout.virtualBounds = {0, 0, 1, 1};
    layout.monitors[0] = layout.virtualBounds;
    return layout;
}

} // namespace

void windowsCaptureSessionGenerationActiveLifetime()
{
    FakeSessionSource session{};
    FakeGenerationSource generation{};
    WindowsCaptureSessionGenerationGuard guard(
        42, session.callbacks(), generation.callbacks());
    session.guard = &guard;
    assert(!guard.closed());

    WindowsCaptureGeneration observed{};
    auto reader = guard.reader();
    assert(reader.read != nullptr &&
           reader.read(reader.context, observed));
    assert((observed == WindowsCaptureGeneration{101, 202}));
    assert(session.reads == 1 && generation.reads == 1);

    FakeFramePipeline native{};
    WindowsDxgiCaptureCycle cycle(
        onePixelLayout(), native.frameCallbacks(),
        native.stagingCallbacks(), {}, guard.reader(), observed);
    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    assert(cycle.frame().pixels.empty());

    std::array<std::byte, 4> owned{};
    FramebufferView view{};
    assert(cycle.copyFrameTo(owned, view) ==
           WindowsCaptureConsumeResult::consumed);
    assert(view.valid() && view.pixels.data() == owned.data());
    assert(view.widthPixels == 1 && view.heightPixels == 1 &&
           view.strideBytes == 4);
    assert(owned == native.pixels);
    assert(native.acquisitions == 1 && native.maps == 1 &&
           native.unmaps == 1 && native.releases == 1);
    assert(session.reads >= 6 && generation.reads == session.reads);

#ifdef _WIN32
    const auto nativeCallbacks = windowsCaptureSessionReadCallbacks();
    assert(nativeCallbacks.read != nullptr);
#endif
}

void windowsCaptureSessionRevocationDenials()
{
    auto rejected = [](
        FakeSessionSource &session,
        FakeGenerationSource &generation) noexcept {
        WindowsCaptureSessionGenerationGuard guard(
            42, session.callbacks(), generation.callbacks());
        WindowsCaptureGeneration output{7, 9};
        const auto reader = guard.reader();
        assert(reader.read != nullptr);
        assert(!reader.read(reader.context, output));
        assert((output == WindowsCaptureGeneration{7, 9}));
        assert(guard.closed());
        const unsigned sessionReads = session.reads;
        const unsigned generationReads = generation.reads;
        assert(!reader.read(reader.context, output));
        assert(session.reads == sessionReads &&
               generation.reads == generationReads);
    };

    FakeSessionSource wrongProcess{};
    FakeGenerationSource wrongProcessGeneration{};
    wrongProcess.processSessionId = 43;
    rejected(wrongProcess, wrongProcessGeneration);
    assert(wrongProcessGeneration.reads == 0);

    FakeSessionSource inactive{};
    FakeGenerationSource inactiveGeneration{};
    inactive.active = false;
    rejected(inactive, inactiveGeneration);
    assert(inactiveGeneration.reads == 0);

    FakeSessionSource unavailable{};
    FakeGenerationSource unavailableGeneration{};
    unavailable.fail = true;
    rejected(unavailable, unavailableGeneration);
    assert(unavailableGeneration.reads == 0);

    FakeSessionSource epochSession{};
    FakeGenerationSource epochUnavailable{};
    epochUnavailable.fail = true;
    rejected(epochSession, epochUnavailable);

    FakeSessionSource zeroEpochSession{};
    FakeGenerationSource zeroEpoch{};
    zeroEpoch.current = {0, 202};
    rejected(zeroEpochSession, zeroEpoch);

    FakeSessionSource reentrantSession{};
    FakeGenerationSource reentrantGeneration{};
    WindowsCaptureSessionGenerationGuard reentrantGuard(
        42, reentrantSession.callbacks(), reentrantGeneration.callbacks());
    reentrantSession.guard = &reentrantGuard;
    reentrantSession.reenter = true;
    WindowsCaptureGeneration reentrantOutput{3, 4};
    const auto reentrantReader = reentrantGuard.reader();
    assert(!reentrantReader.read(
        reentrantReader.context, reentrantOutput));
    assert(!reentrantSession.reentrantResult &&
           reentrantGuard.closed() &&
           (reentrantOutput == WindowsCaptureGeneration{3, 4}));

    FakeSessionSource invalidSource{};
    FakeGenerationSource invalidGeneration{};
    WindowsCaptureSessionGenerationGuard zeroTarget(
        0, invalidSource.callbacks(), invalidGeneration.callbacks());
    WindowsCaptureSessionGenerationGuard sentinelTarget(
        std::numeric_limits<std::uint32_t>::max(),
        invalidSource.callbacks(), invalidGeneration.callbacks());
    WindowsCaptureSessionGenerationGuard noSessionReader(
        42, {}, invalidGeneration.callbacks());
    WindowsCaptureSessionGenerationGuard noGenerationReader(
        42, invalidSource.callbacks(), {});
    assert(zeroTarget.closed() && sentinelTarget.closed() &&
           noSessionReader.closed() && noGenerationReader.closed());
    assert(zeroTarget.reader().read == nullptr &&
           sentinelTarget.reader().read == nullptr &&
           noSessionReader.reader().read == nullptr &&
           noGenerationReader.reader().read == nullptr);

    // State can revoke an already mapped frame before any caller-owned
    // snapshot is written. Existing RAII still unmaps before ReleaseFrame.
    FakeSessionSource liveSession{};
    FakeGenerationSource liveGeneration{};
    WindowsCaptureSessionGenerationGuard liveGuard(
        42, liveSession.callbacks(), liveGeneration.callbacks());
    WindowsCaptureGeneration pinned{};
    auto liveReader = liveGuard.reader();
    assert(liveReader.read(liveReader.context, pinned));
    FakeFramePipeline native{};
    WindowsDxgiCaptureCycle cycle(
        onePixelLayout(), native.frameCallbacks(), native.stagingCallbacks(),
        {}, liveGuard.reader(), pinned);
    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    liveSession.active = false;
    std::array<std::byte, 4> destination{};
    destination.fill(std::byte{0xee});
    FramebufferView view{};
    assert(cycle.copyFrameTo(destination, view) ==
           WindowsCaptureConsumeResult::closed);
    assert(cycle.closed() && view.pixels.empty());
    assert(native.unmaps == 1 && native.releases == 1);
    for (const auto value : destination)
    {
        assert(value == std::byte{0xee});
    }
}

void windowsCaptureSessionChangeRevocation()
{
    FakeSessionSource session{};
    FakeGenerationSource generation{};
    WindowsCaptureSessionGenerationGuard guard(
        42, session.callbacks(), generation.callbacks());
    session.guard = &guard;

    WindowsCaptureGeneration pinned{};
    const auto reader = guard.reader();
    assert(reader.read != nullptr &&
           reader.read(reader.context, pinned));
    assert((pinned == WindowsCaptureGeneration{101, 202}));

    assert(guard.notifySessionChange(43) ==
           WindowsCaptureSessionChangeResult::ignored);
    assert(!guard.closed());

    FakeFramePipeline native{};
    WindowsDxgiCaptureCycle cycle(
        onePixelLayout(), native.frameCallbacks(), native.stagingCallbacks(),
        {}, guard.reader(), pinned);
    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    assert(native.acquisitions == 1 && native.maps == 1);

    assert(guard.notifySessionChange(42) ==
           WindowsCaptureSessionChangeResult::revoked);
    assert(guard.closed());
    assert(guard.notifySessionChange(42) ==
           WindowsCaptureSessionChangeResult::alreadyClosed);

    std::array<std::byte, 4> destination{};
    destination.fill(std::byte{0xee});
    FramebufferView view{};
    assert(cycle.copyFrameTo(destination, view) ==
           WindowsCaptureConsumeResult::closed);
    assert(cycle.closed() && view.pixels.empty());
    assert(native.unmaps == 1 && native.releases == 1);
    for (const auto value : destination)
    {
        assert(value == std::byte{0xee});
    }

    WindowsCaptureGeneration stale{7, 9};
    assert(!reader.read(reader.context, stale));
    assert((stale == WindowsCaptureGeneration{7, 9}));
}

void windowsCaptureSessionChangeDenials()
{
    FakeSessionSource zeroSession{};
    FakeGenerationSource zeroGeneration{};
    WindowsCaptureSessionGenerationGuard zeroGuard(
        42, zeroSession.callbacks(), zeroGeneration.callbacks());
    assert(zeroGuard.notifySessionChange(0) ==
           WindowsCaptureSessionChangeResult::invalidSession);
    assert(zeroGuard.closed());

    FakeSessionSource sentinelSession{};
    FakeGenerationSource sentinelGeneration{};
    WindowsCaptureSessionGenerationGuard sentinelGuard(
        42, sentinelSession.callbacks(), sentinelGeneration.callbacks());
    assert(sentinelGuard.notifySessionChange(
               std::numeric_limits<std::uint32_t>::max()) ==
           WindowsCaptureSessionChangeResult::invalidSession);
    assert(sentinelGuard.closed());

    // A target change delivered synchronously while WTS state is being read
    // must prevent the old session/device generation from being published.
    FakeSessionSource reentrantSession{};
    FakeGenerationSource reentrantGeneration{};
    WindowsCaptureSessionGenerationGuard reentrantGuard(
        42, reentrantSession.callbacks(), reentrantGeneration.callbacks());
    reentrantSession.guard = &reentrantGuard;
    reentrantSession.notifyOnRead = true;
    WindowsCaptureGeneration output{3, 4};
    const auto reader = reentrantGuard.reader();
    assert(reader.read != nullptr);
    assert(!reader.read(reader.context, output));
    assert(reentrantSession.notificationResult ==
           WindowsCaptureSessionChangeResult::revoked);
    assert(reentrantGuard.closed());
    assert(reentrantGeneration.reads == 0);
    assert((output == WindowsCaptureGeneration{3, 4}));
}


void windowsCaptureSessionChangeCoordinatedInputRevocation()
{
    FakeSessionSource session{};
    FakeGenerationSource generation{};
    WindowsCaptureSessionGenerationGuard guard(
        42, session.callbacks(), generation.callbacks());
    WindowsCaptureGeneration pinned{};
    const auto reader = guard.reader();
    assert(reader.read != nullptr &&
           reader.read(reader.context, pinned));

    FakeFramePipeline native{};
    WindowsDxgiCaptureCycle cycle(
        onePixelLayout(), native.frameCallbacks(), native.stagingCallbacks(),
        {}, guard.reader(), pinned);
    FakeInputBackend inputBackend{};
    inputBackend.guard = &guard;
    WindowsInputController input(
        onePixelLayout(), inputBackend.callbacks(), guard.reader(), pinned);

    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    assert(input.handle(WindowsKeyInput{0x1e, false, true}));
    assert(input.handle(WindowsPointerButtonInput{
        {0, 0}, WindowsPointerButton::left, true}));
    assert(inputBackend.commandCount == 3);
    assert(native.unmaps == 0 && native.releases == 0);

    assert(retireWindowsNativeConsumersOnSessionChange(
               guard, cycle, input, 43) ==
           WindowsCaptureSessionChangeResult::ignored);
    assert(!guard.closed() && !cycle.closed() && !input.closed());
    assert(native.unmaps == 0 && native.releases == 0);
    assert(inputBackend.commandCount == 3);

    assert(retireWindowsNativeConsumersOnSessionChange(
               guard, cycle, input, 42) ==
           WindowsCaptureSessionChangeResult::revoked);
    assert(guard.closed() && cycle.closed() && input.closed());
    assert(!inputBackend.sentAfterRevocation);
    assert(inputBackend.commandCount == 3);
    assert(native.unmaps == 1 && native.releases == 1);
    assert(native.retirementOrderCount == 2);
    assert(native.retirementOrder[0] == 'U' &&
           native.retirementOrder[1] == 'R');

    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::closed);
    assert(!input.handle(WindowsKeyInput{0x1e, false, false}));

    assert(retireWindowsNativeConsumersOnSessionChange(
               guard, cycle, input, 42) ==
           WindowsCaptureSessionChangeResult::alreadyClosed);
    input.cancel();
    cycle.cancel();
    assert(inputBackend.commandCount == 3);
    assert(native.unmaps == 1 && native.releases == 1);

    FakeSessionSource invalidSessionSource{};
    FakeGenerationSource invalidGenerationSource{};
    WindowsCaptureSessionGenerationGuard invalidGuard(
        42, invalidSessionSource.callbacks(),
        invalidGenerationSource.callbacks());
    WindowsCaptureGeneration invalidPinned{};
    const auto invalidReader = invalidGuard.reader();
    assert(invalidReader.read != nullptr &&
           invalidReader.read(invalidReader.context, invalidPinned));
    FakeFramePipeline invalidNative{};
    WindowsDxgiCaptureCycle invalidCycle(
        onePixelLayout(), invalidNative.frameCallbacks(),
        invalidNative.stagingCallbacks(), {}, invalidGuard.reader(),
        invalidPinned);
    FakeInputBackend invalidInputBackend{};
    invalidInputBackend.guard = &invalidGuard;
    WindowsInputController invalidInput(
        onePixelLayout(), invalidInputBackend.callbacks(),
        invalidGuard.reader(), invalidPinned);
    assert(invalidCycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    assert(invalidInput.handle(WindowsKeyInput{0x30, false, true}));
    assert(retireWindowsNativeConsumersOnSessionChange(
               invalidGuard, invalidCycle, invalidInput, 0) ==
           WindowsCaptureSessionChangeResult::invalidSession);
    assert(invalidGuard.closed() && invalidCycle.closed() &&
           invalidInput.closed());
    assert(invalidInputBackend.commandCount == 1);
    assert(!invalidInputBackend.sentAfterRevocation);
    assert(invalidNative.unmaps == 1 && invalidNative.releases == 1);
}

void windowsCaptureSessionChangeCallbackRevocation()
{
    FakeSessionSource session{};
    FakeGenerationSource generation{};
    WindowsCaptureSessionGenerationGuard guard(
        42, session.callbacks(), generation.callbacks());
    WindowsCaptureGeneration pinned{};
    const auto reader = guard.reader();
    assert(reader.read != nullptr &&
           reader.read(reader.context, pinned));

    FakeInputBackend inputBackend{};
    inputBackend.guard = &guard;
    WindowsInputController input(
        onePixelLayout(), inputBackend.callbacks(), guard.reader(), pinned);
    assert(input.handle(WindowsKeyInput{0x1e, false, true}));
    assert(inputBackend.commandCount == 1);

    FakeFramePipeline native{};
    WindowsDxgiCaptureCycle cycle(
        onePixelLayout(), native.frameCallbacks(), native.stagingCallbacks(),
        {}, guard.reader(), pinned);
    native.sessionGuard = &guard;
    native.captureCycle = &cycle;
    native.inputController = &input;
    native.revokeDuringMap = true;

    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::closed);
    assert(native.notificationResult ==
           WindowsCaptureSessionChangeResult::revoked);
    assert(native.teardownDeferredDuringMap);
    assert(native.nestedCaptureResult == WindowsCaptureCycleResult::closed);
    assert(!native.postRevocationInputAccepted);
    assert(guard.closed() && cycle.closed() && input.closed());
    assert(native.acquisitions == 1 && native.maps == 1);
    assert(native.unmaps == 1 && native.releases == 1);
    assert(native.retirementOrderCount == 2);
    assert(native.retirementOrder[0] == 'U' &&
           native.retirementOrder[1] == 'R');
    assert(inputBackend.commandCount == 1);
    assert(!inputBackend.sentAfterRevocation);
    assert(cycle.frame().pixels.empty());

    cycle.cancel();
    input.cancel();
    assert(native.unmaps == 1 && native.releases == 1);
    assert(inputBackend.commandCount == 1);
}

void windowsInputSessionChangeHeldStateRetirement()
{
    {
        FakeSessionSource session{};
        FakeGenerationSource generation{};
        WindowsCaptureSessionGenerationGuard guard(
            42, session.callbacks(), generation.callbacks());
        WindowsCaptureGeneration pinned{};
        const auto reader = guard.reader();
        assert(reader.read != nullptr &&
               reader.read(reader.context, pinned));

        FakeInputBackend backend{};
        backend.guard = &guard;
        WindowsInputController input(
            onePixelLayout(), backend.callbacks(), guard.reader(), pinned);
        assert(input.handle(WindowsKeyInput{0x1e, false, true}));
        assert(input.handle(WindowsPointerButtonInput{
            {0, 0}, WindowsPointerButton::right, true}));
        assert(backend.commandCount == 3);

        input.cancel();
        assert(input.closed());
        assert(backend.commandCount == 5);
        assert(backend.commands[3].kind == WindowsNativeInputKind::keyUp);
        assert(backend.commands[3].scanCode == 0x1e);
        assert(backend.commands[4].kind == WindowsNativeInputKind::buttonUp);
        assert(backend.commands[4].button == WindowsPointerButton::right);
        assert(!backend.sentAfterRevocation);
        input.cancel();
        assert(backend.commandCount == 5);
    }

    {
        FakeSessionSource session{};
        FakeGenerationSource generation{};
        WindowsCaptureSessionGenerationGuard guard(
            42, session.callbacks(), generation.callbacks());
        WindowsCaptureGeneration pinned{};
        const auto reader = guard.reader();
        assert(reader.read != nullptr &&
               reader.read(reader.context, pinned));

        FakeInputBackend backend{};
        backend.guard = &guard;
        WindowsInputController input(
            onePixelLayout(), backend.callbacks(), guard.reader(), pinned);
        assert(input.handle(WindowsKeyInput{0x1e, true, true}));
        assert(input.handle(WindowsPointerButtonInput{
            {0, 0}, WindowsPointerButton::x1, true}));
        assert(backend.commandCount == 3);

        assert(guard.notifySessionChange(42) ==
               WindowsCaptureSessionChangeResult::revoked);
        input.cancel();
        assert(input.closed());
        assert(backend.commandCount == 3);
        assert(!backend.sentAfterRevocation);
        assert(!input.handle(WindowsKeyInput{0x1e, true, false}));
        input.cancel();
        assert(backend.commandCount == 3);
    }
}
