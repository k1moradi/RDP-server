// SPDX-License-Identifier: GPL-3.0-or-later

#include "gfx_frame_acknowledge.h"

namespace rdp_server::rdp
{
namespace
{

[[nodiscard]] constexpr std::uint16_t readU16(
    std::span<const std::byte> buffer, std::size_t offset) noexcept
{
    return static_cast<std::uint16_t>(
        std::to_integer<std::uint16_t>(buffer[offset]) |
        (std::to_integer<std::uint16_t>(buffer[offset + 1U]) << 8U));
}

[[nodiscard]] constexpr std::uint32_t readU32(
    std::span<const std::byte> buffer, std::size_t offset) noexcept
{
    return std::to_integer<std::uint32_t>(buffer[offset]) |
           (std::to_integer<std::uint32_t>(buffer[offset + 1U]) << 8U) |
           (std::to_integer<std::uint32_t>(buffer[offset + 2U]) << 16U) |
           (std::to_integer<std::uint32_t>(buffer[offset + 3U]) << 24U);
}

} // namespace

bool parseGfxFrameAcknowledge(std::span<const std::byte> pdu,
                              GfxFrameAcknowledgement &output) noexcept
{
    // Check the complete PDU size before any fixed-offset read. No prefix,
    // suffix or second command is consumed by this single-PDU parser.
    if (pdu.size() != kGfxFrameAcknowledgePduBytes ||
        readU16(pdu, 0U) != kGfxFrameAcknowledgeCommand ||
        readU16(pdu, 2U) != 0 ||
        readU32(pdu, 4U) != kGfxFrameAcknowledgePduBytes)
    {
        return false;
    }

    const GfxFrameAcknowledgement decoded{
        .queueDepth = readU32(pdu, 8U),
        .frameId = readU32(pdu, 12U),
        .totalFramesDecoded = readU32(pdu, 16U)};
    output = decoded;
    return true;
}

void GfxFrameAckWindow::reset(std::uint64_t channelGeneration) noexcept
{
    channelGeneration_ = channelGeneration;
    pendingCount_ = 0;
    clientQueueDepthBytes_ = 0;
    expectingAcknowledgements_ = channelGeneration != 0;
}

bool GfxFrameAckWindow::noteFrameSent(
    std::uint64_t channelGeneration, std::uint32_t frameId) noexcept
{
    if (channelGeneration == 0 || channelGeneration != channelGeneration_)
    {
        return false;
    }
    if (!expectingAcknowledgements_)
    {
        // MS-RDPEGFX 3.2.5.13 forbids waiting for ACKs after suspension.
        return true;
    }
    for (std::size_t index = 0; index < pendingCount_; ++index)
    {
        if (pendingFrames_[index] == frameId)
        {
            return false; // Cannot correlate duplicate pending IDs.
        }
    }
    if (pendingCount_ == pendingFrames_.size())
    {
        return false; // Bounded backpressure; do not lose old ACK IDs.
    }
    pendingFrames_[pendingCount_++] = frameId;
    return true;
}

GfxFrameAckWindowResult GfxFrameAckWindow::onFrameAcknowledge(
    std::uint64_t channelGeneration,
    std::span<const std::byte> pdu) noexcept
{
    if (channelGeneration == 0 || channelGeneration != channelGeneration_)
    {
        return GfxFrameAckWindowResult::StaleGeneration;
    }
    GfxFrameAcknowledgement ack{};
    if (!parseGfxFrameAcknowledge(pdu, ack))
    {
        return GfxFrameAckWindowResult::InvalidPdu;
    }
    if (ack.acknowledgementsSuspended())
    {
        pendingCount_ = 0;
        clientQueueDepthBytes_ = 0;
        expectingAcknowledgements_ = false;
        return GfxFrameAckWindowResult::Suspended;
    }

    // A finite queueDepth explicitly resumes ACKs after suspension.
    expectingAcknowledgements_ = true;
    clientQueueDepthBytes_ = ack.queueDepth;
    for (std::size_t index = 0; index < pendingCount_; ++index)
    {
        if (pendingFrames_[index] == ack.frameId)
        {
            pendingFrames_[index] = pendingFrames_[--pendingCount_];
            return GfxFrameAckWindowResult::Acknowledged;
        }
    }
    return GfxFrameAckWindowResult::Unmatched;
}

} // namespace rdp_server::rdp
