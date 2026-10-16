// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

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

// One R4 codec producer bound to one presentation generation and geometry.
// It does not own the presentation lifecycle, channel, scheduler, capture or
// transport. The caller serializes all methods on the same R4 event thread.
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
    // unsent picture. Output changes only on success.
    [[nodiscard]] bool prepare(
        GfxPresentationLifecycle &lifecycle, std::uint64_t generation,
        const X264Avc420FrameRequest &request,
        GfxAvc420SegmentedFrame &output) noexcept;

    // R3 calls this only after the full owned outer wire span was delivered.
    [[nodiscard]] bool completeDelivery(
        GfxPresentationLifecycle &lifecycle,
        const GfxAvc420SegmentedFrame &frame,
        std::size_t deliveredWireBytes) noexcept;

    // Terminal/partial transport failure revokes the presentation through the
    // existing lifecycle and drops x264 reference history for this generation.
    [[nodiscard]] bool abortDelivery(
        GfxPresentationLifecycle &lifecycle,
        const GfxAvc420SegmentedFrame &frame) noexcept;

private:
    [[nodiscard]] bool rebuildEncoder() noexcept;

    X264Avc420Encoder encoder_{};
    std::uint64_t generation_{};
    PixelSize codedGeometry_{};
    PixelSize visibleGeometry_{};
};

} // namespace rdp_server::rdp
