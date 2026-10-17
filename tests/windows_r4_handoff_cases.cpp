// SPDX-License-Identifier: GPL-3.0-or-later
#include "rdp/x264_avc420_segmented_frame_producer.h"
#include "windows/windows_dxgi_capture_cycle.h"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>

using namespace rdp_server::rdp;
using namespace rdp_server::windows;

namespace
{

constexpr PixelSize kVisible{160, 90};
constexpr PixelSize kCoded{160, 96};
constexpr std::size_t kRowPitch =
    static_cast<std::size_t>(kVisible.widthPixels) * 4U + 32U;
constexpr std::uint64_t kPresentationGeneration = 8101;
constexpr std::uint64_t kCaptureEpoch = 9101;
constexpr std::uint16_t kSurfaceId = 7;
constexpr std::array<Rectangle, 1> kRegions{
    Rectangle{0, 0, kVisible.widthPixels, kVisible.heightPixels}};
constexpr std::array<GfxAvc420QuantQuality, 1> kQuality{{{23, 80}}};

std::array<std::byte, 22> advertisement()
{
    return {std::byte{0x12}, {}, {}, {}, std::byte{22}, {}, {}, {},
            std::byte{1}, {}, std::byte{5}, std::byte{1}, std::byte{8}, {},
            std::byte{4}, {}, {}, {}, std::byte{0x10}, {}, {}, {}};
}

GfxPresentationReceipt emit(
    GfxPresentationLifecycle &lifecycle,
    std::uint64_t generation)
{
    std::array<std::byte, 24> bytes{};
    GfxPresentationReceipt receipt{};
    assert(lifecycle.prepareCommand(generation, bytes, receipt));
    return receipt;
}

// Pure R4 state-machine setup for an offline compatibility test. This is not
// R3 Share/DVC authorization and is never connected to a network writer.
void mapSurface(
    GfxPresentationLifecycle &lifecycle,
    std::uint64_t generation,
    PixelSize visible = kVisible)
{
    assert(lifecycle.open(generation));
    assert(lifecycle.acceptCapabilities(generation, advertisement()));
    auto receipt = emit(lifecycle, generation);
    assert(lifecycle.completeCommand(receipt, receipt.bytes));
    assert(lifecycle.configureSurface(generation, kSurfaceId, visible));
    receipt = emit(lifecycle, generation);
    assert(lifecycle.completeCommand(receipt, receipt.bytes));
    receipt = emit(lifecycle, generation);
    assert(lifecycle.completeCommand(receipt, receipt.bytes));
    assert(lifecycle.stage() == GfxPresentationStage::Mapped);
}

WindowsDesktopLayout r4Layout() noexcept
{
    WindowsDesktopLayout layout{};
    layout.monitorCount = 1;
    layout.virtualBounds = {0, 0, kVisible.widthPixels, kVisible.heightPixels};
    layout.monitors[0] = layout.virtualBounds;
    return layout;
}

struct FakeR4Generation final
{
    std::uint64_t session{101};
    std::uint64_t device{202};
    unsigned reads{};

    static bool read(void *context, WindowsCaptureGeneration &out) noexcept
    {
        auto &self = *static_cast<FakeR4Generation *>(context);
        ++self.reads;
        out = {self.session, self.device};
        return true;
    }

    [[nodiscard]] WindowsCaptureGenerationReader callbacks() noexcept
    {
        return {this, &read};
    }
};

struct FakeR4NativeFrame final
{
    std::vector<std::byte> pixels{
        kRowPitch * static_cast<std::size_t>(kVisible.heightPixels)};
    std::byte token{};
    WindowsDxgiCaptureCycle *cycle{};
    char order[5]{};
    std::size_t orderCount{};
    unsigned acquisitions{};
    unsigned maps{};
    unsigned unmaps{};
    unsigned releases{};

    FakeR4NativeFrame()
    {
        for (std::uint32_t y = 0; y < kVisible.heightPixels; ++y)
        {
            const auto row = static_cast<std::size_t>(y) * kRowPitch;
            for (std::uint32_t x = 0; x < kVisible.widthPixels; ++x)
            {
                const auto at = row + static_cast<std::size_t>(x) * 4U;
                pixels[at] = static_cast<std::byte>((x + y) & 0xffU);
                pixels[at + 1U] =
                    static_cast<std::byte>((2U * x + y) & 0xffU);
                pixels[at + 2U] =
                    static_cast<std::byte>((x + 3U * y) & 0xffU);
                pixels[at + 3U] = std::byte{0x7f};
            }
            for (std::size_t at =
                     row + static_cast<std::size_t>(kVisible.widthPixels) * 4U;
                 at < row + kRowPitch; ++at)
            {
                pixels[at] = std::byte{0xee};
            }
        }
    }

    void record(char value) noexcept
    {
        assert(orderCount < 5U);
        order[orderCount++] = value;
    }

    static WindowsDxgiAcquireResult acquire(
        void *context, std::uint32_t, void *&resource,
        WindowsDxgiFrameInfo &) noexcept
    {
        auto &self = *static_cast<FakeR4NativeFrame *>(context);
        self.record('A');
        ++self.acquisitions;
        resource = &self.token;
        return WindowsDxgiAcquireResult::acquired;
    }

    static WindowsDxgiReleaseResult release(
        void *context, void *resource) noexcept
    {
        auto &self = *static_cast<FakeR4NativeFrame *>(context);
        assert(resource == &self.token);
        self.record('R');
        ++self.releases;
        return WindowsDxgiReleaseResult::released;
    }

    static WindowsD3D11MapResult map(
        void *context, void *resource,
        WindowsD3D11MappedData &out) noexcept
    {
        auto &self = *static_cast<FakeR4NativeFrame *>(context);
        assert(resource == &self.token);
        self.record('S');
        ++self.maps;
        out = {self.pixels.data(), self.pixels.size(), kVisible,
               kRowPitch, &self.token};
        return WindowsD3D11MapResult::mapped;
    }

    static void unmap(void *context, void *handle) noexcept
    {
        auto &self = *static_cast<FakeR4NativeFrame *>(context);
        assert(handle == &self.token);
        self.record('U');
        ++self.unmaps;
        assert(self.cycle != nullptr);
        assert(self.cycle->frame().pixels.empty());
    }

    [[nodiscard]] WindowsDxgiFrameCallbacks frameCallbacks() noexcept
    {
        return {this, &acquire, &release};
    }

    [[nodiscard]] WindowsD3D11StagingCallbacks stagingCallbacks() noexcept
    {
        return {this, &map, &unmap};
    }

    void assertReleasedAfterConsumer() const noexcept
    {
        assert(orderCount == 5U);
        assert(order[0] == 'A' && order[1] == 'S' &&
               order[2] == 'C' && order[3] == 'U' && order[4] == 'R');
        assert(acquisitions == 1U && maps == 1U &&
               unmaps == 1U && releases == 1U);
    }
};

struct R4BgraSink final
{
    FakeR4NativeFrame *native{};
    FakeR4Generation *generation{};
    WindowsDxgiCaptureCycle *cycle{};
    GfxPresentationLifecycle *lifecycle{};
    X264Avc420SegmentedFrameProducer *producer{};
    GfxAvc420SegmentedFrame *prepared{};
    std::uint64_t presentationGeneration{kPresentationGeneration};
    std::uint64_t captureEpoch{kCaptureEpoch};
    std::uint32_t frameId{101};
    WindowsCaptureGeneration observed{};
    unsigned calls{};
    bool rotateSession{};
    bool resizeDuringConsume{};

    static bool consume(
        void *context, const FramebufferView &frame,
        WindowsCaptureGeneration captureGeneration) noexcept
    {
        auto &self = *static_cast<R4BgraSink *>(context);
        ++self.calls;
        self.native->record('C');
        self.observed = captureGeneration;

        assert(frame.valid());
        assert(frame.widthPixels == kVisible.widthPixels);
        assert(frame.heightPixels == kVisible.heightPixels);
        assert(frame.strideBytes == kRowPitch);
        assert(frame.pixels.size() ==
               kRowPitch * static_cast<std::size_t>(kVisible.heightPixels));
        assert(frame.pixels.data() == self.native->pixels.data());
        assert(frame.pixels[0] == std::byte{0x00});
        assert(frame.pixels[1] == std::byte{0x00});
        assert(frame.pixels[2] == std::byte{0x00});
        assert(frame.pixels[3] == std::byte{0x7f});
        assert(frame.pixels[
                   static_cast<std::size_t>(kVisible.widthPixels) * 4U] ==
               std::byte{0xee});

        // The future composition owner maps the richer R6 {session,device}
        // identity to this separately managed R4-local capture epoch. This
        // fixture chooses an epoch only to exercise R4's production ingress
        // state machine; it grants no R2/R3 authority.
        const X264BgraFrameRequest request{
            kSurfaceId, self.frameId, frame, 73,
            kRegions, kQuality, self.captureEpoch};
        assert(self.producer->prepareBgra(
            *self.lifecycle, self.presentationGeneration,
            request, *self.prepared));
        assert(self.prepared->valid());

        if (self.rotateSession)
            ++self.generation->session;
        if (self.resizeDuringConsume)
        {
            auto changed = r4Layout();
            changed.virtualBounds.widthPixels += 16U;
            changed.monitors[0].widthPixels += 16U;
            assert(!self.cycle->topologyUnchanged(changed));
        }
        return true;
    }

    [[nodiscard]] WindowsR4BgraFrameConsumer callbacks() noexcept
    {
        return {this, &consume};
    }
};

void openR4(
    GfxPresentationLifecycle &lifecycle,
    X264Avc420SegmentedFrameProducer &producer,
    std::uint64_t captureEpoch = kCaptureEpoch)
{
    mapSurface(lifecycle, kPresentationGeneration);
    assert(producer.openBgraCapture(
        kPresentationGeneration, captureEpoch, kCoded, kVisible));
    assert(producer.captureGeneration() == captureEpoch);
}

} // namespace

void windowsCaptureR4BgraLayoutContract()
{
    GfxPresentationLifecycle lifecycle;
    X264Avc420SegmentedFrameProducer producer;
    openR4(lifecycle, producer);

    FakeR4NativeFrame native{};
    FakeR4Generation generation{};
    WindowsDxgiCaptureCycle cycle(
        r4Layout(), native.frameCallbacks(), native.stagingCallbacks(),
        {}, generation.callbacks(), {101, 202});
    native.cycle = &cycle;
    GfxAvc420SegmentedFrame prepared;
    R4BgraSink sink{
        &native, &generation, &cycle, &lifecycle, &producer, &prepared};

    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    assert(cycle.consumeR4Frame(sink.callbacks()) ==
           WindowsCaptureConsumeResult::consumed);
    assert(sink.calls == 1U);
    assert((sink.observed == WindowsCaptureGeneration{101, 202}));
    assert(!cycle.closed());
    assert(prepared.valid() && !prepared.wireBytes().empty());
    native.assertReleasedAfterConsumer();

    // No R3 sender exists in this fixture. Retire the prepared owned frame
    // through R4's exact zero-byte cancellation before reusing the producer.
    assert(producer.cancelUnwrittenDelivery(lifecycle, prepared));
    assert(!prepared.valid());

    // A fixture/legacy cycle with no generation may still support its older
    // synchronous consumer, but it cannot become an R4 publication source.
    FakeR4NativeFrame unguardedNative{};
    WindowsDxgiCaptureCycle unguarded(
        r4Layout(), unguardedNative.frameCallbacks(),
        unguardedNative.stagingCallbacks());
    unguardedNative.cycle = &unguarded;
    GfxAvc420SegmentedFrame denied;
    R4BgraSink unguardedSink{
        &unguardedNative, &generation, &unguarded,
        &lifecycle, &producer, &denied};
    assert(unguarded.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    assert(unguarded.consumeR4Frame(unguardedSink.callbacks()) ==
           WindowsCaptureConsumeResult::closed);
    assert(unguarded.closed() && unguardedSink.calls == 0U);
    assert(!denied.valid());
    assert(unguardedNative.orderCount == 4U);
    assert(unguardedNative.order[0] == 'A' &&
           unguardedNative.order[1] == 'S' &&
           unguardedNative.order[2] == 'U' &&
           unguardedNative.order[3] == 'R');
}

void windowsCaptureR4FrameLifetimeRevocation()
{
    GfxPresentationLifecycle lifecycle;
    X264Avc420SegmentedFrameProducer producer;
    openR4(lifecycle, producer);

    FakeR4NativeFrame native{};
    FakeR4Generation generation{};
    WindowsDxgiCaptureCycle cycle(
        r4Layout(), native.frameCallbacks(), native.stagingCallbacks(),
        {}, generation.callbacks(), {101, 202});
    native.cycle = &cycle;
    GfxAvc420SegmentedFrame prepared;
    R4BgraSink sink{
        &native, &generation, &cycle, &lifecycle, &producer, &prepared};
    sink.rotateSession = true;

    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    const auto result = cycle.consumeR4Frame(sink.callbacks());
    const bool publishable = result == WindowsCaptureConsumeResult::consumed;
    assert(result == WindowsCaptureConsumeResult::closed);
    assert(!publishable);
    assert(sink.calls == 1U && cycle.closed());
    assert(prepared.valid());
    native.assertReleasedAfterConsumer();

    // R4 preparation necessarily completed while the native mapping was
    // valid, but the R6 post-consumer session check revoked the publication.
    // Before any R3 submit, consume the exact unwritten R4 owner.
    assert(producer.cancelUnwrittenDelivery(lifecycle, prepared));
    assert(!prepared.valid());
    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::closed);
}

void windowsCaptureR4MonitorReplacementDenials()
{
    GfxPresentationLifecycle lifecycle;
    X264Avc420SegmentedFrameProducer producer;
    openR4(lifecycle, producer);

    // A fresh DXGI owner uses a different nonzero device epoch even if monitor
    // geometry happens to be identical. The old cycle must not invoke R4.
    FakeR4NativeFrame replacementNative{};
    FakeR4Generation replacementGeneration{};
    WindowsDxgiCaptureCycle replaced(
        r4Layout(), replacementNative.frameCallbacks(),
        replacementNative.stagingCallbacks(), {},
        replacementGeneration.callbacks(), {101, 202});
    replacementNative.cycle = &replaced;
    GfxAvc420SegmentedFrame stale;
    R4BgraSink replacementSink{
        &replacementNative, &replacementGeneration, &replaced,
        &lifecycle, &producer, &stale};
    assert(replaced.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    ++replacementGeneration.device;
    assert(replaced.consumeR4Frame(replacementSink.callbacks()) ==
           WindowsCaptureConsumeResult::closed);
    assert(replacementSink.calls == 0U && replaced.closed());
    assert(!stale.valid());
    assert(replacementNative.orderCount == 4U);
    assert(replacementNative.order[0] == 'A' &&
           replacementNative.order[1] == 'S' &&
           replacementNative.order[2] == 'U' &&
           replacementNative.order[3] == 'R');

    // The composition owner—not R6—advances R4's scalar ingress epoch when
    // the richer native capture identity is replaced. Rebind only after the
    // old native cycle is terminal; this offline fixture grants no admission.
    constexpr std::uint64_t replacementCaptureEpoch = kCaptureEpoch + 1U;
    assert(producer.openBgraCapture(
        kPresentationGeneration, replacementCaptureEpoch, kCoded, kVisible));

    FakeR4NativeFrame freshNative{};
    WindowsDxgiCaptureCycle fresh(
        r4Layout(), freshNative.frameCallbacks(), freshNative.stagingCallbacks(),
        {}, replacementGeneration.callbacks(), {101, 203});
    freshNative.cycle = &fresh;
    GfxAvc420SegmentedFrame freshPrepared;
    R4BgraSink freshSink{
        &freshNative, &replacementGeneration, &fresh,
        &lifecycle, &producer, &freshPrepared};
    freshSink.captureEpoch = replacementCaptureEpoch;
    freshSink.frameId = 102;
    assert(fresh.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    assert(fresh.consumeR4Frame(freshSink.callbacks()) ==
           WindowsCaptureConsumeResult::consumed);
    assert(freshPrepared.valid());
    freshNative.assertReleasedAfterConsumer();
    assert(producer.cancelUnwrittenDelivery(lifecycle, freshPrepared));

    // A resize observed during the synchronous R4 borrow is terminal for the
    // old capture cycle. Its already-prepared output is canceled before any
    // hypothetical R3 submission and native map/frame retirement stays ordered.
    GfxPresentationLifecycle resizeLifecycle;
    X264Avc420SegmentedFrameProducer resizeProducer;
    openR4(resizeLifecycle, resizeProducer, kCaptureEpoch + 2U);
    FakeR4NativeFrame resizedNative{};
    FakeR4Generation resizedGeneration{};
    WindowsDxgiCaptureCycle resized(
        r4Layout(), resizedNative.frameCallbacks(),
        resizedNative.stagingCallbacks(), {},
        resizedGeneration.callbacks(), {101, 202});
    resizedNative.cycle = &resized;
    GfxAvc420SegmentedFrame resizedPrepared;
    R4BgraSink resizedSink{
        &resizedNative, &resizedGeneration, &resized,
        &resizeLifecycle, &resizeProducer, &resizedPrepared};
    resizedSink.captureEpoch = kCaptureEpoch + 2U;
    resizedSink.resizeDuringConsume = true;
    assert(resized.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    assert(resized.consumeR4Frame(resizedSink.callbacks()) ==
           WindowsCaptureConsumeResult::closed);
    assert(resizedSink.calls == 1U && resized.closed());
    assert(resizedPrepared.valid());
    resizedNative.assertReleasedAfterConsumer();
    assert(resizeProducer.cancelUnwrittenDelivery(
        resizeLifecycle, resizedPrepared));
    assert(!resizedPrepared.valid());
}
