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
    unsigned damageReads{};
    std::uint64_t *rotateSessionDuringDamageRead{};
    bool cancelDuringAcquire{}, cancelDuringMap{}, cancelDuringUnmap{};
    bool reenterDuringMap{}, viewClearedOnUnmap{};
    std::uint64_t *rotateSessionDuringMap{};
    WindowsCaptureCycleResult reentrantResult{WindowsCaptureCycleResult::failed};

    void record(char value) noexcept
    {
        assert(count < order.size());
        order[count++] = value;
    }

    static WindowsDxgiAcquireResult acquire(
        void *context, std::uint32_t, void *&resource,
        WindowsDxgiFrameInfo &) noexcept
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
        if (self.rotateSessionDuringMap != nullptr)
        {
            ++*self.rotateSessionDuringMap;
        }
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

    static WindowsDxgiDamageReadResult readDamage(
        void *context, std::span<WindowsDxgiMoveRectangle>,
        std::span<WindowsDxgiRectangle> dirty,
        std::size_t &moveCount, std::size_t &dirtyCount) noexcept
    {
        auto &self = *static_cast<FakeCaptureCycle *>(context);
        ++self.damageReads;
        if (self.rotateSessionDuringDamageRead != nullptr)
        {
            ++*self.rotateSessionDuringDamageRead;
        }
        assert(!dirty.empty());
        dirty[0] = {0, 0, 1, 1};
        moveCount = 0;
        dirtyCount = 1;
        return WindowsDxgiDamageReadResult::ready;
    }
    [[nodiscard]] WindowsDxgiDamageReadCallbacks damageCallbacks() noexcept
    {
        return {this, &readDamage};
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
struct FakeCaptureGeneration final
{
    std::uint64_t session{11};
    std::uint64_t device{23};
    unsigned reads{};
    unsigned cancelAtRead{};
    bool fail{};
    bool reenter{};
    WindowsDxgiCaptureCycle *cycle{};
    WindowsCaptureCycleResult reentrantResult{WindowsCaptureCycleResult::failed};

    static bool observe(void *context, WindowsCaptureGeneration &out) noexcept
    {
        auto &self = *static_cast<FakeCaptureGeneration *>(context);
        ++self.reads;
        if (self.reenter && self.cycle != nullptr)
        {
            self.reentrantResult = self.cycle->captureFrame(0);
        }
        if (self.cancelAtRead == self.reads && self.cycle != nullptr)
        {
            self.cycle->cancel();
        }
        if (!self.fail)
        {
            out = {self.session, self.device};
        }
        return !self.fail;
    }
    [[nodiscard]] WindowsCaptureGenerationReader callbacks() noexcept
    {
        return {this, &observe};
    }
};

struct RotatingCaptureConsumer final
{
    FakeCaptureGeneration *generation{};
    static bool consume(void *context, const FramebufferView &frame) noexcept
    {
        auto &self = *static_cast<RotatingCaptureConsumer *>(context);
        assert(frame.valid());
        ++self.generation->device;
        return true;
    }
};

struct ScopedCaptureConsumer
{
    FakeCaptureCycle *backend{};
    WindowsDxgiCaptureCycle *cycle{};
    unsigned callbacks{};
    bool reject{};
    bool cancelDuringCallback{};
    bool changeLayoutDuringCallback{};
    bool attemptReentry{};

    static bool receive(void *context, const FramebufferView &view) noexcept
    {
        auto &self = *static_cast<ScopedCaptureConsumer *>(context);
        ++self.callbacks;
        self.backend->record('C');
        assert(view.valid() && view.widthPixels == 2 && view.heightPixels == 2);
        assert(view.strideBytes == 12 && view.pixels.size() == 24);
        assert(view.pixels.data() == self.backend->pixels.data());
        assert(view.pixels[0] == std::byte{0x25});
        assert(view.pixels[12] == std::byte{0x68});
        assert(self.backend->unmaps + 1 == self.backend->maps);
        assert(self.backend->releases + 1 == self.backend->acquisitions);
        // The callback borrows a valid view, but it cannot observe/reenter
        // the cycle as another consumer before the current lease is released.
        assert(self.cycle->frame().pixels.empty());
        if (self.attemptReentry)
        {
            assert(self.cycle->consumeFrame({&self, &receive}) ==
                   WindowsCaptureConsumeResult::busy);
            assert(self.cycle->captureFrame(0) ==
                   WindowsCaptureCycleResult::busy);
            assert(!self.cycle->releaseFrame());
        }
        if (self.changeLayoutDuringCallback)
        {
            auto latest = sampleLayout();
            latest.monitors[0].widthPixels = 300;
            assert(!self.cycle->topologyUnchanged(latest));
        }
        if (self.cancelDuringCallback)
        {
            self.cycle->cancel();
        }
        return !self.reject;
    }

    [[nodiscard]] WindowsCaptureFrameConsumer consumer() noexcept
    {
        return {this, &receive};
    }
};

} // namespace

void windowsCaptureCycleSynchronousConsumeLifetime()
{
    FakeCaptureCycle source{};
    source.pixels[0] = std::byte{0x25};
    source.pixels[12] = std::byte{0x68};
    WindowsDxgiCaptureCycle cycle(
        sampleLayout(), source.frameCallbacks(), source.stagingCallbacks());
    source.cycle = &cycle;
    ScopedCaptureConsumer sink{&source, &cycle};

    assert(cycle.consumeFrame(sink.consumer()) ==
           WindowsCaptureConsumeResult::noFrame);
    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    sink.attemptReentry = true;
    assert(cycle.consumeFrame(sink.consumer()) ==
           WindowsCaptureConsumeResult::consumed);
    assert(source.count == 5 && source.order[0] == 'A' &&
           source.order[1] == 'S' && source.order[2] == 'C' &&
           source.order[3] == 'U' && source.order[4] == 'R');
    assert(sink.callbacks == 1 && source.unmaps == 1 &&
           source.releases == 1 && source.viewClearedOnUnmap);
    assert(!cycle.closed() && cycle.frame().pixels.empty() &&
           !cycle.releaseFrame());

    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    sink.attemptReentry = false;
    sink.reject = true;
    assert(cycle.consumeFrame(sink.consumer()) ==
           WindowsCaptureConsumeResult::rejected);
    assert(sink.callbacks == 2 && source.unmaps == 2 &&
           source.releases == 2 && !cycle.closed());
}

void windowsCaptureCycleSynchronousConsumeDenials()
{
    FakeCaptureCycle source{};
    source.pixels[0] = std::byte{0x25};
    source.pixels[12] = std::byte{0x68};
    WindowsDxgiCaptureCycle cycle(
        sampleLayout(), source.frameCallbacks(), source.stagingCallbacks());
    source.cycle = &cycle;
    ScopedCaptureConsumer sink{&source, &cycle};

    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    assert(cycle.consumeFrame({}) ==
           WindowsCaptureConsumeResult::invalidConsumer);
    assert(source.unmaps == 1 && source.releases == 1 &&
           source.viewClearedOnUnmap && sink.callbacks == 0 && !cycle.closed());
    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    sink.cancelDuringCallback = true;
    assert(cycle.consumeFrame(sink.consumer()) ==
           WindowsCaptureConsumeResult::closed);
    assert(cycle.closed() && source.unmaps == 2 &&
           source.releases == 2 && source.viewClearedOnUnmap);
    cycle.cancel();
    assert(source.unmaps == 2 && source.releases == 2);

    FakeCaptureCycle topology{};
    topology.pixels[0] = std::byte{0x25};
    topology.pixels[12] = std::byte{0x68};
    WindowsDxgiCaptureCycle topologyCycle(
        sampleLayout(), topology.frameCallbacks(), topology.stagingCallbacks());
    topology.cycle = &topologyCycle;
    ScopedCaptureConsumer topologySink{&topology, &topologyCycle};
    topologySink.changeLayoutDuringCallback = true;
    assert(topologyCycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    assert(topologyCycle.consumeFrame(topologySink.consumer()) ==
           WindowsCaptureConsumeResult::closed);
    assert(topologyCycle.closed() && topology.unmaps == 1 &&
           topology.releases == 1 && topology.viewClearedOnUnmap);

    FakeCaptureCycle lost{};
    lost.pixels[0] = std::byte{0x25};
    lost.pixels[12] = std::byte{0x68};
    WindowsDxgiCaptureCycle lostCycle(
        sampleLayout(), lost.frameCallbacks(), lost.stagingCallbacks());
    lost.cycle = &lostCycle;
    ScopedCaptureConsumer lostSink{&lost, &lostCycle};
    assert(lostCycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    lost.releaseResult = WindowsDxgiReleaseResult::accessLost;
    assert(lostCycle.consumeFrame(lostSink.consumer()) ==
           WindowsCaptureConsumeResult::releaseFailed);
    assert(lostCycle.closed() && lost.unmaps == 1 &&
           lost.releases == 1 && lost.viewClearedOnUnmap);
}

void windowsCapturePackedCopyLifetime()
{
    FakeCaptureCycle source{};
    source.pixels.fill(std::byte{0xf1});
    source.pixels[0] = std::byte{0x55}; // Blue, first row.
    source.pixels[7] = std::byte{0x77};
    source.pixels[12] = std::byte{0x66}; // Second row follows padding.
    source.pixels[19] = std::byte{0x88};
    WindowsDxgiCaptureCycle cycle(
        sampleLayout(), source.frameCallbacks(), source.stagingCallbacks());
    source.cycle = &cycle;

    std::array<std::byte, 20> destination{};
    destination.fill(std::byte{0xaa});
    FramebufferView owned{};
    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    assert(cycle.copyFrameTo(destination, owned) ==
           WindowsCaptureConsumeResult::consumed);
    assert(owned.valid() && owned.widthPixels == 2 &&
           owned.heightPixels == 2 && owned.strideBytes == 8);
    assert(owned.pixels.size() == 16 &&
           owned.pixels.data() == destination.data());
    assert(destination[0] == std::byte{0x55} &&
           destination[7] == std::byte{0x77});
    assert(destination[8] == std::byte{0x66} &&
           destination[15] == std::byte{0x88});
    assert(destination[16] == std::byte{0xaa});
    assert(source.count == 4 && source.order[0] == 'A' &&
           source.order[1] == 'S' && source.order[2] == 'U' &&
           source.order[3] == 'R');
    assert(source.viewClearedOnUnmap && source.unmaps == 1 &&
           source.releases == 1 && cycle.frame().pixels.empty());

    // The DXGI texture may be reused or destroyed; caller bytes persist.
    source.pixels.fill(std::byte{});
    assert(owned.pixels[0] == std::byte{0x55} &&
           owned.pixels[8] == std::byte{0x66});
    assert(cycle.copyFrameTo(destination, owned) ==
           WindowsCaptureConsumeResult::noFrame);
    assert(owned.pixels.empty());
}

void windowsCapturePackedCopyDenials()
{
    FakeCaptureCycle source{};
    WindowsDxgiCaptureCycle cycle(
        sampleLayout(), source.frameCallbacks(), source.stagingCallbacks());
    source.cycle = &cycle;
    std::array<std::byte, 20> destination{};
    destination.fill(std::byte{0xcc});
    FramebufferView owned{};

    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    assert(cycle.copyFrameTo(std::span(destination).first(15), owned) ==
           WindowsCaptureConsumeResult::rejected);
    assert(source.unmaps == 1 && source.releases == 1 &&
           source.viewClearedOnUnmap && owned.pixels.empty());
    for (const auto pixel : destination)
    {
        assert(pixel == std::byte{0xcc});
    }

    // An alias of mapped GPU bytes would dangle after DXGI unmap.
    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    assert(cycle.copyFrameTo(std::span(source.pixels).first(20), owned) ==
           WindowsCaptureConsumeResult::rejected);
    assert(source.unmaps == 2 && source.releases == 2 &&
           owned.pixels.empty());

    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    assert(cycle.copyFrameTo(
               std::span(source.pixels).subspan(4, 16), owned) ==
           WindowsCaptureConsumeResult::rejected);
    assert(source.unmaps == 3 && source.releases == 3 &&
           owned.pixels.empty());

    // A successful memcpy is NOT a successfully released frame.
    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    source.releaseResult = WindowsDxgiReleaseResult::accessLost;
    assert(cycle.copyFrameTo(destination, owned) ==
           WindowsCaptureConsumeResult::releaseFailed);
    assert(cycle.closed() && owned.pixels.empty() &&
           source.unmaps == 4 && source.releases == 4);
    assert(cycle.copyFrameTo(destination, owned) ==
           WindowsCaptureConsumeResult::closed);
}

void windowsCaptureGenerationPinnedLifetime()
{
    FakeCaptureCycle source{};
    FakeCaptureGeneration generation{};
    WindowsDxgiCaptureCycle cycle(
        sampleLayout(), source.frameCallbacks(), source.stagingCallbacks(),
        source.damageCallbacks(), generation.callbacks(), {11, 23});
    generation.cycle = &cycle;
    generation.reenter = true;
    assert(!cycle.closed());
    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    assert(generation.reentrantResult == WindowsCaptureCycleResult::busy);
    // Guarded cycles forbid unchecked raw-frame borrows entirely.
    assert(cycle.frame().pixels.empty());

    std::array<PortableRectangle, 2> damage{};
    std::size_t damageCount = 99;
    assert(cycle.readFrameDamage(damage, damageCount) ==
           WindowsCaptureDamageResult::ready);
    assert(damageCount == 1 && source.damageReads == 1 &&
           (damage[0] == PortableRectangle{0, 0, 1, 1}));
    assert(source.unmaps == 0 && source.releases == 0);

    std::array<std::byte, 16> pixels{};
    FramebufferView owned{};
    assert(cycle.copyFrameTo(pixels, owned) ==
           WindowsCaptureConsumeResult::consumed);
    assert(owned.valid() && owned.pixels.data() == pixels.data());
    assert(owned.widthPixels == 2 && owned.heightPixels == 2 &&
           owned.strideBytes == 8);
    assert(source.unmaps == 1 && source.releases == 1);
    assert(!cycle.closed() && generation.reads >= 5);
    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    assert(cycle.releaseFrame());
    assert(source.unmaps == 2 && source.releases == 2);
    cycle.cancel();
    cycle.cancel();
    assert(source.unmaps == 2 && source.releases == 2);
}

void windowsCaptureGenerationRevocationDenials()
{
    // An observed generation is a revocation discriminator only, never OS
    // authorization. Initial mismatch forbids native frame acquisition.
    FakeCaptureCycle staleSource{};
    FakeCaptureGeneration stale{};
    WindowsDxgiCaptureCycle staleCycle(
        sampleLayout(), staleSource.frameCallbacks(), staleSource.stagingCallbacks(),
        {}, stale.callbacks(), {11, 23});
    stale.session = 12;
    assert(staleCycle.captureFrame(0) == WindowsCaptureCycleResult::closed);
    assert(staleCycle.closed() && staleSource.acquisitions == 0 &&
           staleSource.unmaps == 0 && staleSource.releases == 0);

    // A device/session change inside native Map must not expose its view.
    FakeCaptureCycle mappingSource{};
    FakeCaptureGeneration mappingGeneration{};
    mappingSource.rotateSessionDuringMap = &mappingGeneration.session;
    WindowsDxgiCaptureCycle mappingCycle(
        sampleLayout(), mappingSource.frameCallbacks(),
        mappingSource.stagingCallbacks(),
        {}, mappingGeneration.callbacks(), {11, 23});
    assert(mappingCycle.captureFrame(0) == WindowsCaptureCycleResult::closed);
    assert(mappingCycle.closed() && mappingSource.acquisitions == 1 &&
           mappingSource.maps == 1 && mappingSource.unmaps == 1 &&
           mappingSource.releases == 1 &&
           mappingCycle.frame().pixels.empty());
    mappingCycle.cancel();
    assert(mappingSource.releases == 1);

    // A snapshot must not be published after a generation switch while
    // its borrowed mapping was held, including after a completed memcpy.
    FakeCaptureCycle consumingSource{};
    FakeCaptureGeneration consumingGeneration{};
    WindowsDxgiCaptureCycle consumingCycle(
        sampleLayout(), consumingSource.frameCallbacks(),
        consumingSource.stagingCallbacks(),
        {}, consumingGeneration.callbacks(), {11, 23});
    assert(consumingCycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    std::array<std::byte, 16> destination{};
    destination.fill(std::byte{0xee});
    FramebufferView candidate{};
    ++consumingGeneration.device;
    assert(consumingCycle.copyFrameTo(destination, candidate) ==
           WindowsCaptureConsumeResult::closed);
    assert(candidate.pixels.empty() && consumingCycle.closed());
    assert(consumingSource.unmaps == 1 && consumingSource.releases == 1);
    for (const auto pixel : destination)
    {
        assert(pixel == std::byte{0xee});
    }

    FakeCaptureCycle callbackSource{};
    FakeCaptureGeneration callbackGeneration{};
    WindowsDxgiCaptureCycle callbackCycle(
        sampleLayout(), callbackSource.frameCallbacks(), callbackSource.stagingCallbacks(),
        {}, callbackGeneration.callbacks(), {11, 23});
    assert(callbackCycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    RotatingCaptureConsumer consumer{&callbackGeneration};
    assert(callbackCycle.consumeFrame({&consumer, &RotatingCaptureConsumer::consume}) ==
           WindowsCaptureConsumeResult::closed);
    assert(callbackCycle.closed() && callbackSource.unmaps == 1 &&
           callbackSource.releases == 1);

    // A generation changed INSIDE the damage callback must not publish
    // partial normalized regions or leak the outstanding mapped frame.
    FakeCaptureCycle damageSource{};
    FakeCaptureGeneration damageGeneration{};
    damageSource.rotateSessionDuringDamageRead = &damageGeneration.session;
    WindowsDxgiCaptureCycle damageCycle(
        sampleLayout(), damageSource.frameCallbacks(),
        damageSource.stagingCallbacks(), damageSource.damageCallbacks(),
        damageGeneration.callbacks(), {11, 23});
    assert(damageCycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    std::array<PortableRectangle, 2> dirty{};
    dirty[0] = {7, 8, 9, 10};
    std::size_t dirtyCount = 41;
    assert(damageCycle.readFrameDamage(dirty, dirtyCount) ==
           WindowsCaptureDamageResult::closed);
    assert(damageCycle.closed() && damageSource.damageReads == 1 &&
           damageSource.unmaps == 1 && damageSource.releases == 1);
    assert(dirtyCount == 41 &&
           (dirty[0] == PortableRectangle{7, 8, 9, 10}));

    // Missing/partial/zero generation sources are terminal, not opt-out.
    FakeCaptureCycle missingSource{};
    FakeCaptureGeneration missingGeneration{};
    WindowsDxgiCaptureCycle missingReader(
        sampleLayout(), missingSource.frameCallbacks(), missingSource.stagingCallbacks(),
        {}, {}, {11, 23});
    WindowsDxgiCaptureCycle zeroGeneration(
        sampleLayout(), missingSource.frameCallbacks(), missingSource.stagingCallbacks(),
        {}, missingGeneration.callbacks(), {});
    WindowsDxgiCaptureCycle missingContext(
        sampleLayout(), missingSource.frameCallbacks(), missingSource.stagingCallbacks(),
        {}, {nullptr, &FakeCaptureGeneration::observe}, {11, 23});
    assert(missingReader.closed() && zeroGeneration.closed() &&
           missingContext.closed());
    assert(missingSource.acquisitions == 0);

    // Failed observations and callbacks that cancel reentrantly are denied.
    FakeCaptureCycle failedSource{};
    FakeCaptureGeneration failedGeneration{};
    failedGeneration.fail = true;
    WindowsDxgiCaptureCycle failed(
        sampleLayout(), failedSource.frameCallbacks(), failedSource.stagingCallbacks(),
        {}, failedGeneration.callbacks(), {11, 23});
    assert(failed.captureFrame(0) == WindowsCaptureCycleResult::closed);
    assert(failedSource.acquisitions == 0 && failed.closed());

    FakeCaptureCycle cancelledSource{};
    FakeCaptureGeneration cancelledGeneration{};
    WindowsDxgiCaptureCycle cancelled(
        sampleLayout(), cancelledSource.frameCallbacks(), cancelledSource.stagingCallbacks(),
        {}, cancelledGeneration.callbacks(), {11, 23});
    cancelledGeneration.cycle = &cancelled;
    cancelledGeneration.cancelAtRead = 1;
    assert(cancelled.captureFrame(0) == WindowsCaptureCycleResult::closed);
    assert(cancelledSource.acquisitions == 0 && cancelled.closed());
}

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
