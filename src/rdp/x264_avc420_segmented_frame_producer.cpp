// SPDX-License-Identifier: GPL-3.0-or-later
#include "x264_avc420_segmented_frame_producer.h"

#include <utility>

namespace rdp_server::rdp
{

bool X264Avc420SegmentedFrameProducer::open(
    std::uint64_t generation, PixelSize codedGeometry,
    PixelSize visibleGeometry) noexcept
{
    reset();
    if (generation == 0 || !encoder_.open(codedGeometry, visibleGeometry))
        return false;

    generation_ = generation;
    codedGeometry_ = codedGeometry;
    visibleGeometry_ = visibleGeometry;
    return true;
}

void X264Avc420SegmentedFrameProducer::reset() noexcept
{
    encoder_.reset();
    generation_ = 0;
    codedGeometry_ = {};
    visibleGeometry_ = {};
}

bool X264Avc420SegmentedFrameProducer::valid() const noexcept
{
    return generation_ != 0 && encoder_.valid();
}

std::uint64_t X264Avc420SegmentedFrameProducer::generation() const noexcept
{
    return valid() ? generation_ : 0;
}

PixelSize X264Avc420SegmentedFrameProducer::codedGeometry() const noexcept
{
    return valid() ? codedGeometry_ : PixelSize{};
}

PixelSize X264Avc420SegmentedFrameProducer::visibleGeometry() const noexcept
{
    return valid() ? visibleGeometry_ : PixelSize{};
}

bool X264Avc420SegmentedFrameProducer::rebuildEncoder() noexcept
{
    if (generation_ == 0 || codedGeometry_.widthPixels == 0 ||
        codedGeometry_.heightPixels == 0 ||
        visibleGeometry_.widthPixels == 0 ||
        visibleGeometry_.heightPixels == 0)
    {
        reset();
        return false;
    }

    if (encoder_.open(codedGeometry_, visibleGeometry_))
        return true;

    reset();
    return false;
}

bool X264Avc420SegmentedFrameProducer::prepare(
    GfxPresentationLifecycle &lifecycle, std::uint64_t generation,
    const X264Avc420FrameRequest &request,
    GfxAvc420SegmentedFrame &output) noexcept
{
    const GfxAvc420Picture metadata{
        request.surfaceId,
        request.frameId,
        codedGeometry_,
        request.regions,
        request.quantQualities,
        {},
        visibleGeometry_,
    };

    // Reject every deterministic lifecycle and AVC420 envelope mismatch
    // before x264 advances reference state. The encoded Annex-B payload is
    // intentionally excluded from metadata validation.
    if (!valid() || generation != generation_ ||
        request.surfaceId != lifecycle.surfaceId() ||
        request.picture.codedGeometry != codedGeometry_ ||
        !gfxAvc420PictureMetadataValid(metadata) ||
        !lifecycle.canSubmitFrame(generation))
    {
        return false;
    }

    X264EncodedPicture encoded;
    if (!encoder_.encode(request.picture, encoded))
    {
        // A failed x264 call is conservatively treated as reference-state
        // uncertainty. Reopen now so any later accepted picture starts IDR.
        (void)rebuildEncoder();
        return false;
    }

    const GfxAvc420Picture picture{
        request.surfaceId,
        request.frameId,
        codedGeometry_,
        request.regions,
        request.quantQualities,
        encoded.annexB,
        visibleGeometry_,
    };

    GfxAvc420SegmentedFrame candidate;
    if (!prepareGfxAvc420SegmentedFrame(
            lifecycle, generation, picture, candidate))
    {
        // x264 already accepted this picture. If R4 cannot reserve the exact
        // corresponding outbound frame, discard the reference history rather
        // than allowing the next P-frame to depend on bytes the client never
        // received.
        (void)rebuildEncoder();
        return false;
    }

    output = std::move(candidate);
    return true;
}

bool X264Avc420SegmentedFrameProducer::completeDelivery(
    GfxPresentationLifecycle &lifecycle,
    const GfxAvc420SegmentedFrame &frame,
    std::size_t deliveredWireBytes) noexcept
{
    if (!valid() || frame.generation() != generation_)
        return false;
    return completeGfxAvc420SegmentedFrameDelivery(
        lifecycle, frame, deliveredWireBytes);
}

bool X264Avc420SegmentedFrameProducer::abortDelivery(
    GfxPresentationLifecycle &lifecycle,
    const GfxAvc420SegmentedFrame &frame) noexcept
{
    if (!valid() || frame.generation() != generation_)
        return false;
    if (!abortGfxAvc420SegmentedFrameDelivery(lifecycle, frame))
        return false;

    // The client may have received any prefix of the aborted frame. The
    // lifecycle is terminal for this generation, so retain no codec history.
    reset();
    return true;
}

} // namespace rdp_server::rdp
