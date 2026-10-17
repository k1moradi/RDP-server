// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "gfx_avc420_picture.h"
#include "gfx_clearcodec.h"
#include "gfx_presentation_lifecycle.h"

namespace rdp_server::rdp
{

// Stable R4-owned bytes for one already-encoded graphics frame after RDP8
// segmented-data framing. The historical type name is retained to avoid an
// API rename; the same move-only owner now carries AVC420 or the mandatory
// ClearCodec fallback. This is not a DVC, transport, scheduler or authorization
// object. R3 must retain it through its authorized publication receipt.
class GfxAvc420SegmentedFrame final
{
public:
    GfxAvc420SegmentedFrame() = default;
    ~GfxAvc420SegmentedFrame() = default;

    GfxAvc420SegmentedFrame(const GfxAvc420SegmentedFrame &) = delete;
    GfxAvc420SegmentedFrame &operator=(const GfxAvc420SegmentedFrame &) = delete;
    // A live frame carries a private lifecycle receipt. It can be transferred
    // into a fresh owner, but never overwritten because this object does not
    // own the lifecycle needed to retire an existing receipt.
    GfxAvc420SegmentedFrame(GfxAvc420SegmentedFrame && other) noexcept;
    GfxAvc420SegmentedFrame &
    operator=(GfxAvc420SegmentedFrame &&) = delete;

    [[nodiscard]] std::span<const std::byte> wireBytes() const noexcept
    {
        return wireBytes_;
    }
    [[nodiscard]] std::uint64_t generation() const noexcept
    {
        return receipt_.generation;
    }
    [[nodiscard]] std::uint32_t frameId() const noexcept
    {
        return receipt_.frameId;
    }
    [[nodiscard]] bool valid() const noexcept
    {
        return !wireBytes_.empty() && graphicsBytes_ != 0 &&
               receipt_.serial != 0;
    }

private:
    friend bool prepareGfxAvc420SegmentedFrame(
        GfxPresentationLifecycle &, std::uint64_t,
        const GfxAvc420Picture &, GfxAvc420SegmentedFrame &) noexcept;
    friend bool prepareGfxClearCodecSegmentedFrame(
        GfxPresentationLifecycle &, std::uint64_t,
        const GfxClearCodecFrameRequest &,
        GfxAvc420SegmentedFrame &) noexcept;
    friend bool cancelUnwrittenGfxAvc420SegmentedFrameDelivery(
        GfxPresentationLifecycle &, GfxAvc420SegmentedFrame &) noexcept;
    friend bool completeGfxAvc420SegmentedFrameDelivery(
        GfxPresentationLifecycle &, GfxAvc420SegmentedFrame &,
        std::size_t) noexcept;
    friend bool abortGfxAvc420SegmentedFrameDelivery(
        GfxPresentationLifecycle &, GfxAvc420SegmentedFrame &) noexcept;

    void invalidate() noexcept
    {
        // Release the owned payload so a canceled or moved-from object cannot
        // expose stale bytes if the object is later reused.
        std::vector<std::byte> empty;
        wireBytes_.swap(empty);
        receipt_ = {};
        graphicsBytes_ = 0;
    }

    std::vector<std::byte> wireBytes_{};
    GfxFrameDeliveryReceipt receipt_{};
    std::size_t graphicsBytes_{};
};

// Serialize through the existing mapped-surface lifecycle, then wrap the
// complete START_FRAME..END_FRAME graphics bytes in RDP8 segmented data.
// Output must not already own a frame. On ordinary rejection, output remains
// unchanged and no frame is reserved. Any impossible post-reservation framing
// inconsistency is terminally aborted.
[[nodiscard]] bool prepareGfxAvc420SegmentedFrame(
    GfxPresentationLifecycle &lifecycle, std::uint64_t generation,
    const GfxAvc420Picture &picture,
    GfxAvc420SegmentedFrame &output) noexcept;

// Mandatory ClearCodec fallback uses the identical move-only publication owner,
// RDP8 segmentation and receipt retirement path; only frame serialization
// differs. Output remains unchanged on deterministic rejection.
[[nodiscard]] bool prepareGfxClearCodecSegmentedFrame(
    GfxPresentationLifecycle &lifecycle, std::uint64_t generation,
    const GfxClearCodecFrameRequest &request,
    GfxAvc420SegmentedFrame &output) noexcept;

// R3 may call this only after conclusively proving that no byte from this
// frame has been accepted and after retiring every borrow of wireBytes().
// R4 validates the exact pending receipt but cannot prove transport progress.
// On success the frame is invalidated and cannot later complete or abort.
[[nodiscard]] bool cancelUnwrittenGfxAvc420SegmentedFrameDelivery(
    GfxPresentationLifecycle &lifecycle,
    GfxAvc420SegmentedFrame &frame) noexcept;

// R3 calls this only after the entire wireBytes() span has been delivered on
// its independently authorized Graphics DVC. The outer segmented byte count
// is checked here before publishing the existing inner frame receipt/ACK.
// Exact successful completion consumes the publication owner; failed or short
// completion leaves it intact for the caller's still-pending transport state.
[[nodiscard]] bool completeGfxAvc420SegmentedFrameDelivery(
    GfxPresentationLifecycle &lifecycle,
    GfxAvc420SegmentedFrame &frame,
    std::size_t deliveredWireBytes) noexcept;

// R3 calls this after terminal/partial transport failure. The existing
// presentation lifecycle revokes the active generation. Successful abort also
// consumes the publication owner; a rejected stale/wrong abort leaves it intact.
[[nodiscard]] bool abortGfxAvc420SegmentedFrameDelivery(
    GfxPresentationLifecycle &lifecycle,
    GfxAvc420SegmentedFrame &frame) noexcept;

} // namespace rdp_server::rdp
