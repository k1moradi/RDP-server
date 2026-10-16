// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows/windows_capture_session_guard.h"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <limits>

using namespace rdp_server::windows;

namespace
{

struct FakeSessionSource final
{
    std::uint32_t processSessionId{42};
    bool active{true};
    bool fail{};
    bool reenter{};
    unsigned reads{};
    WindowsCaptureSessionGenerationGuard *guard{};
    bool reentrantResult{true};

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

struct FakeFramePipeline final
{
    std::array<std::byte, 4> pixels{
        std::byte{0x12}, std::byte{0x34},
        std::byte{0x56}, std::byte{0xff}};
    std::byte token{};
    unsigned acquisitions{};
    unsigned maps{};
    unsigned unmaps{};
    unsigned releases{};

    static WindowsDxgiAcquireResult acquire(
        void *context, std::uint32_t, void *&resource) noexcept
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
        return WindowsD3D11MapResult::mapped;
    }

    static void unmap(void *context, void *handle) noexcept
    {
        auto &self = *static_cast<FakeFramePipeline *>(context);
        assert(handle == &self.token);
        ++self.unmaps;
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
