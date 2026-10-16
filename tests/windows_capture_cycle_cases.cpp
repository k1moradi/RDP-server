// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows/windows_dxgi_capture_cycle.h"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>

using namespace rdp_server::windows;

namespace
{
struct FakeCaptureCycle final
{
    std::array<char, 32> order{};
    std::size_t count{};
    std::array<std::byte, 32> pixels{};
    std::byte token{};
    WindowsDxgiCaptureCycle *cycle{};
    WindowsDxgiAcquireResult acquireResult{WindowsDxgiAcquireResult::acquired};
    WindowsDxgiReleaseResult releaseResult{WindowsDxgiReleaseResult::released};
    WindowsD3D11MapResult mapResult{WindowsD3D11MapResult::mapped};
    std::size_t readableBytes{24};
    unsigned acquisitions{}, releases{}, maps{}, unmaps{};
    bool cancelDuringAcquire{}, cancelDuringMap{}, cancelDuringUnmap{};
    bool reenterDuringMap{}, viewClearedOnUnmap{};
    WindowsCaptureCycleResult reentrantResult{WindowsCaptureCycleResult::failed};

    void record(char value) noexcept
    {
        assert(count < order.size());
        order[count++] = value;
    }

    static WindowsDxgiAcquireResult acquire(
        void *context, std::uint32_t, void *&resource) noexcept
    {
        auto &self = *static_cast<FakeCaptureCycle *>(context);
        self.record('A');
        ++self.acquisitions;
        if (self.cancelDuringAcquire && self.cycle)
            self.cycle->cancel();
        if (self.acquireResult == WindowsDxgiAcquireResult::acquired)
            resource = &self.token;
        return self.acquireResult;
    }

    static WindowsDxgiReleaseResult release(void *context,
                                          void *resource) noexcept
    {
        auto &self = *static_cast<FakeCaptureCycle *>(context);
        assert(resource == &self.token);
        self.record('R');
        ++self.releases;
        return self.releaseResult;
    }

    static WindowsD3D11MapResult map(
        void *context, void *resource,
        WindowsD3D11MappedData &output) noexcept
    {
        auto &self = *static_cast<FakeCaptureCycle *>(context);
        assert(resource == &self.token);
        self.record('S');
        ++self.maps;
        if (self.reenterDuringMap && self.cycle)
            self.reentrantResult = self.cycle->captureFrame(0);
        if (self.cancelDuringMap && self.cycle)
            self.cycle->cancel();
        if (self.mapResult == WindowsD3D11MapResult::mapped)
            output = {self.pixels.data(), self.readableBytes,
                      {2, 2}, 12, &self.token};
        return self.mapResult;
    }

    static void unmap(void *context, void *handle) noexcept
    {
        auto &self = *static_cast<FakeCaptureCycle *>(context);
        assert(handle == &self.token);
        self.record('U');
        ++self.unmaps;
        if (self.cycle)
        {
            self.viewClearedOnUnmap = self.cycle->frame().pixels.empty();
            if (self.cancelDuringUnmap)
                self.cycle->cancel();
        }
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

[[nodiscard]] WindowsDesktopLayout sampleLayout() noexcept
{
    WindowsDesktopLayout layout{};
    layout.monitorCount = 1;
    layout.virtualBounds = {-120, 0, 320, 240};
    layout.monitors[0] = layout.virtualBounds;
    return layout;
}
} // namespace

void windowsCaptureCycleOrderedLifetime()
{
    FakeCaptureCycle source{};
    {
        WindowsDxgiCaptureCycle cycle(
            sampleLayout(), source.frameCallbacks(), source.stagingCallbacks());
        source.cycle = &cycle;
        assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
        assert(cycle.frame().valid() && cycle.frame().strideBytes == 12);
        assert(cycle.frame().pixels.data() == source.pixels.data());
        assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::busy);
        assert(cycle.topologyUnchanged(sampleLayout()));
        assert(cycle.releaseFrame());
        assert(source.viewClearedOnUnmap);
        assert(source.count == 4 && source.order[0] == 'A' &&
               source.order[1] == 'S' && source.order[2] == 'U' &&
               source.order[3] == 'R');
        assert(cycle.frame().pixels.empty() && !cycle.releaseFrame());

        source.acquireResult = WindowsDxgiAcquireResult::timeout;
        assert(cycle.captureFrame(12) == WindowsCaptureCycleResult::timeout);
        source.acquireResult = WindowsDxgiAcquireResult::acquired;
        source.mapResult = WindowsD3D11MapResult::notReady;
        assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::notReady);
        assert(!cycle.closed() && cycle.frame().pixels.empty());
        assert(source.unmaps == 1 && source.releases == 2);
        source.mapResult = WindowsD3D11MapResult::mapped;
        assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
        auto changed = sampleLayout();
        changed.monitors[0].widthPixels = 300;
        assert(!cycle.topologyUnchanged(changed));
        assert(cycle.closed() && cycle.frame().pixels.empty());
        assert(source.unmaps == 2 && source.releases == 3);
        assert(source.order[source.count - 2] == 'U' &&
               source.order[source.count - 1] == 'R');
    }
    assert(source.unmaps == 2 && source.releases == 3);
    FakeCaptureCycle destructor{};
    {
        WindowsDxgiCaptureCycle owner(
            sampleLayout(), destructor.frameCallbacks(),
            destructor.stagingCallbacks());
        assert(owner.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    }
    assert(destructor.unmaps == 1 && destructor.releases == 1);
}

void windowsCaptureCycleLifecycleDenials()
{
    FakeCaptureCycle source{};
    WindowsDxgiCaptureCycle cycle(
        sampleLayout(), source.frameCallbacks(), source.stagingCallbacks());
    source.cycle = &cycle;
    assert(cycle.captureFrame(kMaximumWindowsDxgiFrameWaitMilliseconds + 1) ==
           WindowsCaptureCycleResult::invalidWait);
    assert(source.acquisitions == 0 && !cycle.closed());
    source.reenterDuringMap = true;
    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    assert(source.reentrantResult == WindowsCaptureCycleResult::busy);
    assert(cycle.releaseFrame());

    FakeCaptureCycle lost{};
    lost.acquireResult = WindowsDxgiAcquireResult::accessLost;
    WindowsDxgiCaptureCycle lostCycle(
        sampleLayout(), lost.frameCallbacks(), lost.stagingCallbacks());
    assert(lostCycle.captureFrame(0) == WindowsCaptureCycleResult::accessLost);
    assert(lostCycle.closed() && lost.releases == 0 && lost.unmaps == 0);

    FakeCaptureCycle truncated{};
    truncated.readableBytes = 12;
    WindowsDxgiCaptureCycle invalidFrame(
        sampleLayout(), truncated.frameCallbacks(), truncated.stagingCallbacks());
    assert(invalidFrame.captureFrame(0) == WindowsCaptureCycleResult::failed);
    assert(invalidFrame.closed() && truncated.unmaps == 1 &&
           truncated.releases == 1);

    FakeCaptureCycle lostDuringRelease{};
    lostDuringRelease.releaseResult = WindowsDxgiReleaseResult::accessLost;
    WindowsDxgiCaptureCycle releaseCycle(
        sampleLayout(), lostDuringRelease.frameCallbacks(),
        lostDuringRelease.stagingCallbacks());
    assert(releaseCycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    assert(!releaseCycle.releaseFrame() && releaseCycle.closed());
    assert(lostDuringRelease.unmaps == 1 && lostDuringRelease.releases == 1);

    FakeCaptureCycle acquireCancelled{};
    acquireCancelled.cancelDuringAcquire = true;
    WindowsDxgiCaptureCycle cancelledAcquire(
        sampleLayout(), acquireCancelled.frameCallbacks(),
        acquireCancelled.stagingCallbacks());
    acquireCancelled.cycle = &cancelledAcquire;
    assert(cancelledAcquire.captureFrame(0) == WindowsCaptureCycleResult::closed);
    assert(cancelledAcquire.closed() && acquireCancelled.maps == 0 &&
           acquireCancelled.releases == 1);

    FakeCaptureCycle mappingCancelled{};
    mappingCancelled.cancelDuringMap = true;
    WindowsDxgiCaptureCycle cancelledMap(
        sampleLayout(), mappingCancelled.frameCallbacks(),
        mappingCancelled.stagingCallbacks());
    mappingCancelled.cycle = &cancelledMap;
    assert(cancelledMap.captureFrame(0) == WindowsCaptureCycleResult::closed);
    assert(cancelledMap.closed() && mappingCancelled.unmaps == 1 &&
           mappingCancelled.releases == 1);
    assert(mappingCancelled.order[mappingCancelled.count - 2] == 'U' &&
           mappingCancelled.order[mappingCancelled.count - 1] == 'R');

    FakeCaptureCycle unmapCancelled{};
    unmapCancelled.cancelDuringUnmap = true;
    WindowsDxgiCaptureCycle cancelledUnmap(
        sampleLayout(), unmapCancelled.frameCallbacks(),
        unmapCancelled.stagingCallbacks());
    unmapCancelled.cycle = &cancelledUnmap;
    assert(cancelledUnmap.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    assert(!cancelledUnmap.releaseFrame() && cancelledUnmap.closed());
    assert(unmapCancelled.unmaps == 1 && unmapCancelled.releases == 1);

    FakeCaptureCycle noLayout{};
    WindowsDxgiCaptureCycle invalid(
        {}, noLayout.frameCallbacks(), noLayout.stagingCallbacks());
    assert(invalid.closed() &&
           invalid.captureFrame(0) == WindowsCaptureCycleResult::closed);
}
