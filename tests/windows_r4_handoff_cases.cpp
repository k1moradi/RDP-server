// SPDX-License-Identifier: GPL-3.0-or-later
#include "rdp/bgra_nv12_converter.h"
#include "windows/windows_dxgi_capture_cycle.h"

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
    BgraNv12Converter converter{};
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

        // Exercise the actual R4 BGRA ingestion primitive while D3D11 remains
        // mapped. BgraNv12Converter retains only its independent NV12 scratch.
        const bool converted =
            self.converter.convert(frame, kVisible, kCoded, 73);
        assert(converted);
        const auto picture = self.converter.picture();
        assert((picture.codedGeometry == kCoded));
        assert(picture.yStrideBytes == kCoded.widthPixels);
        assert(picture.uvStrideBytes == kCoded.widthPixels);
        assert(!picture.yPlane.empty() && !picture.uvPlane.empty());
        assert(picture.pts == 73);

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

} // namespace

void windowsCaptureR4BgraLayoutContract()
{
    FakeR4NativeFrame native{};
    FakeR4Generation generation{};
    WindowsDxgiCaptureCycle cycle(
        r4Layout(), native.frameCallbacks(), native.stagingCallbacks(),
        {}, generation.callbacks(), {101, 202});
    native.cycle = &cycle;
    R4BgraSink sink{&native, &generation, &cycle};

    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    assert(cycle.consumeR4Frame(sink.callbacks()) ==
           WindowsCaptureConsumeResult::consumed);
    assert(sink.calls == 1U);
    assert((sink.observed == WindowsCaptureGeneration{101, 202}));
    assert(!cycle.closed());
    native.assertReleasedAfterConsumer();

    // A fixture/legacy cycle with no generation may still support its older
    // synchronous consumer, but it cannot become an R4 publication source.
    FakeR4NativeFrame unguardedNative{};
    WindowsDxgiCaptureCycle unguarded(
        r4Layout(), unguardedNative.frameCallbacks(),
        unguardedNative.stagingCallbacks());
    unguardedNative.cycle = &unguarded;
    R4BgraSink unguardedSink{&unguardedNative, &generation, &unguarded};
    assert(unguarded.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    assert(unguarded.consumeR4Frame(unguardedSink.callbacks()) ==
           WindowsCaptureConsumeResult::closed);
    assert(unguarded.closed() && unguardedSink.calls == 0U);
    assert(unguardedNative.orderCount == 4U);
    assert(unguardedNative.order[0] == 'A' &&
           unguardedNative.order[1] == 'S' &&
           unguardedNative.order[2] == 'U' &&
           unguardedNative.order[3] == 'R');
}

void windowsCaptureR4FrameLifetimeRevocation()
{
    FakeR4NativeFrame native{};
    FakeR4Generation generation{};
    WindowsDxgiCaptureCycle cycle(
        r4Layout(), native.frameCallbacks(), native.stagingCallbacks(),
        {}, generation.callbacks(), {101, 202});
    native.cycle = &cycle;
    R4BgraSink sink{&native, &generation, &cycle};
    sink.rotateSession = true;

    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    const auto result = cycle.consumeR4Frame(sink.callbacks());
    const bool publishable = result == WindowsCaptureConsumeResult::consumed;
    assert(result == WindowsCaptureConsumeResult::closed);
    assert(!publishable);
    assert(sink.calls == 1U && cycle.closed());
    native.assertReleasedAfterConsumer();

    // Conversion happened synchronously while the mapping was alive, but the
    // post-consumer session check refused to report publication success.
    assert(!sink.converter.picture().yPlane.empty());
    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::closed);
}

void windowsCaptureR4MonitorReplacementDenials()
{
    // A fresh DXGI owner uses a different nonzero device epoch even if monitor
    // geometry happens to be identical. The old cycle must not invoke R4.
    FakeR4NativeFrame replacementNative{};
    FakeR4Generation replacementGeneration{};
    WindowsDxgiCaptureCycle replaced(
        r4Layout(), replacementNative.frameCallbacks(),
        replacementNative.stagingCallbacks(), {},
        replacementGeneration.callbacks(), {101, 202});
    replacementNative.cycle = &replaced;
    R4BgraSink replacementSink{
        &replacementNative, &replacementGeneration, &replaced};
    assert(replaced.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    ++replacementGeneration.device;
    assert(replaced.consumeR4Frame(replacementSink.callbacks()) ==
           WindowsCaptureConsumeResult::closed);
    assert(replacementSink.calls == 0U && replaced.closed());
    assert(replacementNative.orderCount == 4U);
    assert(replacementNative.order[0] == 'A' &&
           replacementNative.order[1] == 'S' &&
           replacementNative.order[2] == 'U' &&
           replacementNative.order[3] == 'R');

    // A resize observed during the synchronous R4 borrow is terminal for the
    // old capture cycle and still releases map then DXGI lease after return.
    FakeR4NativeFrame resizedNative{};
    FakeR4Generation resizedGeneration{};
    WindowsDxgiCaptureCycle resized(
        r4Layout(), resizedNative.frameCallbacks(),
        resizedNative.stagingCallbacks(), {},
        resizedGeneration.callbacks(), {101, 202});
    resizedNative.cycle = &resized;
    R4BgraSink resizedSink{&resizedNative, &resizedGeneration, &resized};
    resizedSink.resizeDuringConsume = true;
    assert(resized.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    assert(resized.consumeR4Frame(resizedSink.callbacks()) ==
           WindowsCaptureConsumeResult::closed);
    assert(resizedSink.calls == 1U && resized.closed());
    resizedNative.assertReleasedAfterConsumer();
}
