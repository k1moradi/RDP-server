// SPDX-License-Identifier: GPL-3.0-or-later
#include "gfx_avc420_segmented_frame.h"

#include "gfx_segmented_data.h"

#include <utility>

namespace rdp_server::rdp
{

GfxAvc420SegmentedFrame::GfxAvc420SegmentedFrame(
    GfxAvc420SegmentedFrame && other) noexcept
    : wireBytes_(std::move(other.wireBytes_)),
      receipt_(other.receipt_),
      graphicsBytes_(other.graphicsBytes_)
{
    other.invalidate();
}

GfxAvc420SegmentedFrame &
GfxAvc420SegmentedFrame::operator=(
    GfxAvc420SegmentedFrame && other) noexcept
{
    if (this != &other)
    {
        wireBytes_ = std::move(other.wireBytes_);
        receipt_ = other.receipt_;
        graphicsBytes_ = other.graphicsBytes_;
        other.invalidate();
    }
    return *this;
}

bool prepareGfxAvc420SegmentedFrame(
    GfxPresentationLifecycle &lifecycle, std::uint64_t generation,
    const GfxAvc420Picture &picture,
    GfxAvc420SegmentedFrame &output) noexcept
{
    const std::size_t graphicsBytes =
        gfxAvc420PictureBytes(picture.regions.size(),
                              picture.annexBPicture.size());
    const std::size_t segmentedBytes = gfxSegmentedDataBytes(graphicsBytes);
    if (graphicsBytes == 0 || segmentedBytes == 0)
        return false;

    try
    {
        std::vector<std::byte> wireBytes(segmentedBytes);
        GfxFrameDeliveryReceipt receipt{};
        if (!lifecycle.prepareAvc420Picture(
                generation, picture,
                std::span<std::byte>{wireBytes}.first(graphicsBytes),
                receipt))
        {
            return false;
        }

        // buildGfxSegmentedData explicitly supports exact in-place expansion.
        // All sizes were preflighted above, so failure here indicates an
        // internal framing invariant mismatch after lifecycle reservation.
        const std::size_t written = buildGfxSegmentedData(
            std::span<const std::byte>{wireBytes}.first(graphicsBytes),
            wireBytes);
        if (written != segmentedBytes || receipt.bytes != graphicsBytes)
        {
            (void)lifecycle.abortFrameDelivery(receipt);
            return false;
        }

        GfxAvc420SegmentedFrame candidate;
        candidate.wireBytes_ = std::move(wireBytes);
        candidate.receipt_ = receipt;
        candidate.graphicsBytes_ = graphicsBytes;
        output = std::move(candidate);
        return true;
    }
    catch (...)
    {
        return false;
    }
}

bool cancelUnwrittenGfxAvc420SegmentedFrameDelivery(
    GfxPresentationLifecycle &lifecycle,
    GfxAvc420SegmentedFrame &frame) noexcept
{
    if (!frame.valid() || frame.receipt_.bytes != frame.graphicsBytes_)
        return false;
    if (!lifecycle.cancelUnwrittenFrameDelivery(frame.receipt_))
        return false;

    frame.invalidate();
    return true;
}

bool completeGfxAvc420SegmentedFrameDelivery(
    GfxPresentationLifecycle &lifecycle,
    const GfxAvc420SegmentedFrame &frame,
    std::size_t deliveredWireBytes) noexcept
{
    if (!frame.valid() || deliveredWireBytes != frame.wireBytes_.size() ||
        frame.receipt_.bytes != frame.graphicsBytes_)
    {
        return false;
    }
    return lifecycle.completeFrameDelivery(frame.receipt_,
                                            frame.graphicsBytes_);
}

bool abortGfxAvc420SegmentedFrameDelivery(
    GfxPresentationLifecycle &lifecycle,
    const GfxAvc420SegmentedFrame &frame) noexcept
{
    if (!frame.valid() || frame.receipt_.bytes != frame.graphicsBytes_)
        return false;
    return lifecycle.abortFrameDelivery(frame.receipt_);
}

} // namespace rdp_server::rdp
