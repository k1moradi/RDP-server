// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "bgra_nv12_converter.h"
#include "gfx_avc420_picture.h"
#include "gfx_avc420_segmented_frame.h"
#include "x264_avc420_encoder.h"

namespace rdp_server::rdp
{

struct X264Avc420FrameRequest final
{
    std::uint16_t surfaceId{};
    std::uint32_t frameId{};
    X264Nv12PictureView picture{};
    std::span<const Rectangle> regions{};
    std::span<const GfxAvc420QuantQuality> quantQualities{};
};

struct X264BgraFrameRequest final
{
    std::uint16_t surfaceId{};
    std::uint32_t frameId{};
    FramebufferView framebuffer{};
    std::int64_t pts{};
    std::span<const Rectangle> regions{};
    std::span<const GfxAvc420QuantQuality> quantQualities{};
};

// One R4 codec producer bound to one presentation generation and geometry.
// It does not own the presentation lifecycle, channel, scheduler, capture or
// transport. The caller serializes all methods on the same R4 event thread.
//
// PTS contract: the current x264 configuration is fixed 60 fps CFR with
// b_vfr_input=0, no B frames and no lookahead. Request PTS values are opaque
// signed 64-bit labels forwarded to x264, not frame-order, scheduling,
// authorization, publication or ACK state. Duplicate, decreasing, skipped and
// extreme values are therefore valid. No PTS baseline/counter is retained.
// Revisit this contract before enabling VFR input or frame reordering.
class X264Avc420SegmentedFrameProducer final
{
public:
    X264Avc420SegmentedFrameProducer() noexcept = default;
    ~X264Avc420SegmentedFrameProducer() = default;

    X264Avc420SegmentedFrameProducer(
        const X264Avc420SegmentedFrameProducer &) = delete;
    X264Avc420SegmentedFrameProducer &operator=(
        const X264Avc420SegmentedFrameProducer &) = delete;
    X264Avc420SegmentedFrameProducer(
        X264Avc420SegmentedFrameProducer &&) = delete;
    X264Avc420SegmentedFrameProducer &operator=(
        X264Avc420SegmentedFrameProducer &&) = delete;

    [[nodiscard]] bool open(std::uint64_t generation,
                            PixelSize codedGeometry,
                            PixelSize visibleGeometry) noexcept;
    void reset() noexcept;

    [[nodiscard]] bool valid() const noexcept;
    [[nodiscard]] std::uint64_t generation() const noexcept;
    [[nodiscard]] PixelSize codedGeometry() const noexcept;
    [[nodiscard]] PixelSize visibleGeometry() const noexcept;

    // Encode one NV12 picture and transactionally reserve its complete
    // START_FRAME..END_FRAME + RDP8 segmented-data payload. Ordinary
    // backpressure/authorization-state denials are checked before x264 runs.
    // If x264 ran but publication could not be reserved, codec reference
    // history is rebuilt immediately so no later P-frame can depend on an
    // unsent picture. Output must be invalid on entry and changes only on
    // success; live frame owners are never overwritten.
    [[nodiscard]] bool prepare(
        GfxPresentationLifecycle &lifecycle, std::uint64_t generation,
        const X264Avc420FrameRequest &request,
        GfxAvc420SegmentedFrame &output) noexcept;

    // Consume a complete synchronously borrowed BGRA/XRGB desktop frame.
    // Reject occupied-output/envelope/lifecycle denials before converting.
    // The R4-owned NV12
    // scratch is borrowed only by this producer's synchronous prepare().
    [[nodiscard]] bool prepareBgra(
        GfxPresentationLifecycle &lifecycle, std::uint64_t generation,
        const X264BgraFrameRequest &request,
        GfxAvc420SegmentedFrame &output) noexcept;

    // Cancel a prepared frame only after R3 has conclusively established
    // zero cumulative accepted bytes and retired all wireBytes() borrows.
    // Exact lifecycle cancellation invalidates frame first; then x264 is
    // rebuilt so the next accepted frame is an independent IDR. A rebuild
    // failure revokes the presentation and leaves this producer unusable.
    [[nodiscard]] bool cancelUnwrittenDelivery(
        GfxPresentationLifecycle &lifecycle,
        GfxAvc420SegmentedFrame &frame) noexcept;

    // R3 calls this only after the full owned outer wire span was delivered.
    // Success retires and invalidates frame; rejection leaves it unchanged.
    [[nodiscard]] bool completeDelivery(
        GfxPresentationLifecycle &lifecycle,
        GfxAvc420SegmentedFrame &frame,
        std::size_t deliveredWireBytes) noexcept;

    // Terminal/partial transport failure revokes the presentation through the
    // existing lifecycle, retires frame and drops x264 reference history for
    // this generation. Rejected stale/wrong aborts leave frame unchanged.
    [[nodiscard]] bool abortDelivery(
        GfxPresentationLifecycle &lifecycle,
        GfxAvc420SegmentedFrame &frame) noexcept;

private:
    [[nodiscard]] bool rebuildEncoder() noexcept;

    X264Avc420Encoder encoder_{};
    BgraNv12Converter bgraConverter_{};
    std::uint64_t generation_{};
    PixelSize codedGeometry_{};
    PixelSize visibleGeometry_{};
};

} // namespace rdp_server::rdp
