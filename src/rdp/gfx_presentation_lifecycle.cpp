// SPDX-License-Identifier: GPL-3.0-or-later
#include "gfx_presentation_lifecycle.h"

#include <algorithm>
#include <limits>

namespace rdp_server::rdp
{

bool GfxPresentationLifecycle::active(std::uint64_t generation) const noexcept
{
    return generation != 0 && generation_ == generation &&
           stage_ != GfxPresentationStage::Inactive &&
           stage_ != GfxPresentationStage::Rejected;
}

bool GfxPresentationLifecycle::open(std::uint64_t authorizedGeneration) noexcept
{
    if (authorizedGeneration == 0 || authorizedGeneration <= latestGeneration_)
    {
        return false;
    }
    disconnect();
    latestGeneration_ = authorizedGeneration;
    generation_ = authorizedGeneration;
    acknowledgements_.reset(authorizedGeneration);
    stage_ = GfxPresentationStage::AwaitCapabilities;
    return true;
}

void GfxPresentationLifecycle::disconnect() noexcept
{
    stage_ = GfxPresentationStage::Inactive;
    generation_ = 0;
    pending_ = {};
    pendingFrame_ = {};
    pendingFrameCodec_ = PendingFrameCodec::None;
    surfaceId_ = 0;
    clearCodecSequence_ = 0;
    lastUnwrittenAvc420CancellationSerial_ = 0;
    avc420Enabled_ = false;
    geometry_ = {};
    originX_ = 0;
    originY_ = 0;
    confirmation_.fill(std::byte{});
    acknowledgements_.reset(0);
    // lastSerial_ and latestGeneration_ persist across reconnects.
}

bool GfxPresentationLifecycle::acceptCapabilities(
    std::uint64_t generation,
    std::span<const std::byte> advertisement) noexcept
{
    if (!active(generation) ||
        stage_ != GfxPresentationStage::AwaitCapabilities)
    {
        return false;
    }
    const auto negotiated = negotiateGfxCapabilities(advertisement);
    if (!negotiated.accepted() ||
        negotiated.confirmationBytes != confirmation_.size())
    {
        stage_ = GfxPresentationStage::Rejected;
        acknowledgements_.reset(0);
        return false;
    }
    confirmation_ = negotiated.confirmation;
    avc420Enabled_ = negotiated.avc420Enabled;
    stage_ = GfxPresentationStage::ConfirmReady;
    return true;
}

bool GfxPresentationLifecycle::configureSurface(
    std::uint64_t generation, std::uint16_t surfaceId,
    PixelSize geometry, std::uint32_t originX,
    std::uint32_t originY) noexcept
{
    if (!active(generation) ||
        stage_ != GfxPresentationStage::SurfaceUnconfigured ||
        geometry.widthPixels == 0 ||
        geometry.heightPixels == 0 ||
        geometry.widthPixels > std::numeric_limits<std::uint16_t>::max() ||
        geometry.heightPixels > std::numeric_limits<std::uint16_t>::max())
    {
        return false;
    }
    surfaceId_ = surfaceId;
    geometry_ = geometry;
    originX_ = originX;
    originY_ = originY;
    stage_ = GfxPresentationStage::CreateReady;
    return true;
}

bool GfxPresentationLifecycle::prepareCommand(
    std::uint64_t generation, std::span<std::byte> output,
    GfxPresentationReceipt &receipt) noexcept
{
    if (!active(generation) || lastSerial_ ==
            std::numeric_limits<std::uint64_t>::max())
    {
        return false;
    }
    GfxPresentationStage inFlight{};
    GfxPresentationCommand command{};
    std::size_t written{};
    switch (stage_)
    {
    case GfxPresentationStage::ConfirmReady:
        if (output.size() < confirmation_.size()) { return false; }
        std::copy(confirmation_.begin(), confirmation_.end(), output.begin());
        written = confirmation_.size();
        inFlight = GfxPresentationStage::ConfirmInFlight;
        command = GfxPresentationCommand::Confirm;
        break;
    case GfxPresentationStage::CreateReady:
        written = buildGfxCreateSurfaceCommand({surfaceId_, geometry_}, output);
        inFlight = GfxPresentationStage::CreateInFlight;
        command = GfxPresentationCommand::Create;
        break;
    case GfxPresentationStage::MapReady:
        written = buildGfxMapSurfaceToOutputCommand(
            {surfaceId_, originX_, originY_}, output);
        inFlight = GfxPresentationStage::MapInFlight;
        command = GfxPresentationCommand::Map;
        break;
    case GfxPresentationStage::DeleteReady:
        written = buildGfxDeleteSurfaceCommand(surfaceId_, output);
        inFlight = GfxPresentationStage::DeleteInFlight;
        command = GfxPresentationCommand::Delete;
        break;
    default:
        return false;
    }
    if (written == 0) { return false; }
    stage_ = inFlight;
    pending_ = {generation_, ++lastSerial_, command, written};
    receipt = pending_;
    return true;
}

bool GfxPresentationLifecycle::completeCommand(
    const GfxPresentationReceipt &receipt,
    std::size_t deliveredBytes) noexcept
{
    if (!active(receipt.generation) || receipt != pending_ ||
        deliveredBytes != pending_.bytes)
    {
        return false;
    }
    GfxPresentationStage next{};
    switch (stage_)
    {
    case GfxPresentationStage::ConfirmInFlight:
        if (receipt.command != GfxPresentationCommand::Confirm) { return false; }
        next = GfxPresentationStage::SurfaceUnconfigured;
        break;
    case GfxPresentationStage::CreateInFlight:
        if (receipt.command != GfxPresentationCommand::Create) { return false; }
        next = GfxPresentationStage::MapReady;
        break;
    case GfxPresentationStage::MapInFlight:
        if (receipt.command != GfxPresentationCommand::Map) { return false; }
        next = GfxPresentationStage::Mapped;
        break;
    case GfxPresentationStage::DeleteInFlight:
        if (receipt.command != GfxPresentationCommand::Delete) { return false; }
        next = GfxPresentationStage::SurfaceUnconfigured;
        // Value is irrelevant in this stage; zero remains wire-valid when mapped.
        surfaceId_ = 0;
        geometry_ = {};
        break;
    default:
        return false;
    }
    pending_ = {};
    stage_ = next;
    return true;
}

bool GfxPresentationLifecycle::requestSurfaceDelete(
    std::uint64_t generation) noexcept
{
    if (!active(generation) || stage_ != GfxPresentationStage::Mapped ||
        pendingFrame_.serial != 0)
    {
        return false;
    }
    acknowledgements_.reset(generation);
    stage_ = GfxPresentationStage::DeleteReady;
    return true;
}

bool GfxPresentationLifecycle::canSubmitFrame(
    std::uint64_t generation) const noexcept
{
    return active(generation) && stage_ == GfxPresentationStage::Mapped &&
           pendingFrame_.serial == 0 &&
           (!acknowledgements_.expectingAcknowledgements() ||
            acknowledgements_.outstandingFrames() <
                GfxFrameAckWindow::kMaximumPendingFrames);
}

bool GfxPresentationLifecycle::canReserveFrame(
    std::uint64_t generation, std::uint32_t frameId) const noexcept
{
    return canSubmitFrame(generation) &&
           lastSerial_ != std::numeric_limits<std::uint64_t>::max() &&
           acknowledgements_.canRecordFrame(generation, frameId);
}

bool GfxPresentationLifecycle::hasOutstandingFrame(
    std::uint64_t generation, std::uint32_t frameId) const noexcept
{
    return active(generation) &&
           acknowledgements_.hasOutstandingFrame(generation, frameId);
}

bool GfxPresentationLifecycle::beginFrameDelivery(
    std::uint64_t generation, std::uint32_t frameId, std::size_t frameBytes,
    GfxFrameDeliveryReceipt &receipt) noexcept
{
    if (frameBytes == 0 || !canReserveFrame(generation, frameId))
        return false;
    pendingFrame_ = {generation, ++lastSerial_, frameId, frameBytes};
    pendingFrameCodec_ = PendingFrameCodec::None;
    receipt = pendingFrame_;
    return true;
}

bool GfxPresentationLifecycle::prepareAvc420Picture(
    std::uint64_t generation, const GfxAvc420Picture &picture,
    std::span<std::byte> output, GfxFrameDeliveryReceipt &receipt) noexcept
{
    // R3 must have separately authorized this graphics DVC. Opening R4's
    // offline lifecycle cannot authorize a peer, capture or transport.
    const PixelSize visible =
        picture.visibleGeometry.widthPixels == 0 &&
        picture.visibleGeometry.heightPixels == 0
            ? picture.codedGeometry : picture.visibleGeometry;
    if (!avc420Enabled_ ||
        (visible.widthPixels & 1U) != 0U ||
        (visible.heightPixels & 1U) != 0U ||
        !canReserveFrame(generation, picture.frameId) ||
        picture.surfaceId != surfaceId_ ||
        visible != geometry_)
    {
        return false;
    }
    const std::size_t written = buildGfxAvc420Picture(picture, output);
    if (written == 0)
        return false; // Builder validates before writing any output.
    // No concurrent state mutation is possible on this single-owner
    // synchronous path between preflight and reservation.
    if (!beginFrameDelivery(generation, picture.frameId, written, receipt))
        return false;
    pendingFrameCodec_ = PendingFrameCodec::Avc420;
    return true;
}

bool GfxPresentationLifecycle::prepareClearCodecFrame(
    std::uint64_t generation,
    const GfxClearCodecFrameRequest &request,
    std::span<std::byte> output,
    GfxFrameDeliveryReceipt &receipt) noexcept
{
    if (!canReserveFrame(generation, request.frameId) ||
        request.surfaceId != surfaceId_ ||
        request.framebuffer.widthPixels != geometry_.widthPixels ||
        request.framebuffer.heightPixels != geometry_.heightPixels)
    {
        return false;
    }

    const std::size_t written = buildGfxClearCodecFrame(
        request, clearCodecSequence_, output);
    if (written == 0U ||
        !beginFrameDelivery(
            generation, request.frameId, written, receipt))
    {
        return false;
    }

    pendingFrameCodec_ = PendingFrameCodec::ClearCodec;
    return true;
}

bool GfxPresentationLifecycle::cancelUnwrittenFrameDelivery(
    const GfxFrameDeliveryReceipt &receipt) noexcept
{
    if (!active(receipt.generation) ||
        stage_ != GfxPresentationStage::Mapped ||
        pendingFrame_.serial == 0 || receipt != pendingFrame_)
    {
        return false;
    }

    // Only the exact unsent reservation is retired. Earlier ACK-tracked
    // frames, client observations, mapped surface and generation survive.
    // ClearCodec sequence is deliberately not consumed by zero publication.
    // R3 can cancel the moved AVC420 frame without access to x264. Retain
    // its exact canceled serial so the producer can force a recovery IDR.
    if (pendingFrameCodec_ == PendingFrameCodec::Avc420)
        lastUnwrittenAvc420CancellationSerial_ = pendingFrame_.serial;
    pendingFrame_ = {};
    pendingFrameCodec_ = PendingFrameCodec::None;
    return true;
}

bool GfxPresentationLifecycle::completeFrameDelivery(
    const GfxFrameDeliveryReceipt &receipt,
    std::size_t deliveredBytes) noexcept
{
    if (!active(receipt.generation) || pendingFrame_.serial == 0 ||
        receipt != pendingFrame_ || deliveredBytes != pendingFrame_.bytes)
        return false;
    const PendingFrameCodec deliveredCodec = pendingFrameCodec_;

    // Only R3's complete send receipt can publish an ACK-tracked frame.
    if (!acknowledgements_.noteFrameSent(receipt.generation, receipt.frameId))
    {
        disconnect(); // ACK correlation lost after send: fail closed.
        return false;
    }

    if (deliveredCodec == PendingFrameCodec::ClearCodec)
    {
        clearCodecSequence_ = static_cast<std::uint8_t>(
            static_cast<unsigned>(clearCodecSequence_) + 1U);
    }
    pendingFrame_ = {};
    pendingFrameCodec_ = PendingFrameCodec::None;
    return true;
}

bool GfxPresentationLifecycle::abortFrameDelivery(
    const GfxFrameDeliveryReceipt &receipt) noexcept
{
    if (!active(receipt.generation) || pendingFrame_.serial == 0 ||
        receipt != pendingFrame_)
        return false;
    // Partial frame bytes cannot be followed by any new graphics PDU.
    disconnect();
    return true;
}

bool GfxPresentationLifecycle::onFrameAcknowledge(
    std::uint64_t generation, std::span<const std::byte> pdu,
    GfxFrameAckWindowResult &result) noexcept
{
    if (!active(generation) || stage_ != GfxPresentationStage::Mapped)
    {
        return false;
    }
    const auto response = acknowledgements_.onFrameAcknowledge(generation, pdu);
    if (response == GfxFrameAckWindowResult::InvalidPdu ||
        response == GfxFrameAckWindowResult::StaleGeneration)
    {
        return false;
    }
    result = response;
    return true;
}

} // namespace rdp_server::rdp
