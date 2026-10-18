// SPDX-License-Identifier: GPL-3.0-or-later
#include "rdp_clipboard_static_channel.h"
#include "mcs_channel_connection.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace rdp_server::server::transport
{
namespace
{
constexpr std::uint32_t kChannelFirst = 0x00000001U;
constexpr std::uint32_t kChannelLast = 0x00000002U;
constexpr std::uint32_t kChannelShowProtocol = 0x00000010U;
constexpr std::uint32_t kChannelSuspend = 0x00000020U;
constexpr std::uint32_t kChannelResume = 0x00000040U;
constexpr std::uint32_t kChannelShadowPersistent = 0x00000080U;
constexpr std::size_t kChannelHeaderBytes = 8U;

[[nodiscard]] std::uint32_t readLe32(
    std::span<const std::uint8_t> bytes, std::size_t offset) noexcept
{
    return static_cast<std::uint32_t>(bytes[offset]) |
           (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U) |
           (static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U);
}

void writeLe32(std::span<std::uint8_t> bytes, std::size_t offset,
               std::uint32_t value) noexcept
{
    for (std::size_t index = 0U; index < 4U; ++index)
        bytes[offset + index] = static_cast<std::uint8_t>(
            value >> (index * 8U));
}
} // namespace

bool RdpClipboardStaticChannelRoute::start(
    std::uint32_t assignedUserId, std::uint16_t channelId,
    std::uint64_t generation, std::size_t chunkBytes) noexcept
{
    if (active_ || generation == 0U || generation <= lastGeneration_ ||
        assignedUserId < 1001U || assignedUserId > 65536U ||
        channelId == 0U ||
        chunkBytes < kRdpStaticVirtualChannelDefaultChunkBytes ||
        chunkBytes > kRdpStaticVirtualChannelMaximumChunkBytes)
        return false;

    assignedUserId_ = assignedUserId;
    channelId_ = channelId;
    generation_ = generation;
    lastGeneration_ = generation;
    chunkBytes_ = chunkBytes;
    active_ = true;
    return true;
}

RdpClipboardChunkIntake RdpClipboardStaticChannelRoute::receive(
    std::uint16_t channelId, std::uint64_t generation,
    std::span<const std::uint8_t> virtualChannelData,
    std::span<const std::uint8_t> &completePdu) noexcept
{
    completePdu = {};
    if (!active_ || channelId != channelId_ || generation != generation_ ||
        virtualChannelData.size() <= kChannelHeaderBytes ||
        virtualChannelData.size() - kChannelHeaderBytes > chunkBytes_)
    {
        close();
        return RdpClipboardChunkIntake::Rejected;
    }

    const std::uint32_t totalLength = readLe32(virtualChannelData, 0U);
    const std::uint32_t flags = readLe32(virtualChannelData, 4U);
    // Client-to-server SUSPEND/RESUME and SHADOW_PERSISTENT are ignored
    // by definition. Unsupported compression and unknown bits are terminal.
    constexpr std::uint32_t permittedFlags =
        kChannelFirst | kChannelLast | kChannelShowProtocol |
        kChannelSuspend | kChannelResume | kChannelShadowPersistent;
    if ((flags & ~permittedFlags) != 0U ||
        totalLength < 8U || totalLength > clipboard::kMaximumPduBytes)
    {
        close();
        return RdpClipboardChunkIntake::Rejected;
    }

    const bool first = (flags & kChannelFirst) != 0U;
    const bool last = (flags & kChannelLast) != 0U;
    const auto fragment = virtualChannelData.subspan(kChannelHeaderBytes);
    if ((assembling_ && first) || (!assembling_ && !first) ||
        (first && fragment.size() > totalLength) ||
        (!first && expectedInboundBytes_ != totalLength))
    {
        close();
        return RdpClipboardChunkIntake::Rejected;
    }

    if (first)
    {
        inboundPdu_.clear();
        expectedInboundBytes_ = totalLength;
        assembling_ = true;
    }
    if (fragment.size() > expectedInboundBytes_ - inboundPdu_.size() ||
        (!last && inboundPdu_.size() + fragment.size() >= expectedInboundBytes_) ||
        (last && inboundPdu_.size() + fragment.size() != expectedInboundBytes_))
    {
        close();
        return RdpClipboardChunkIntake::Rejected;
    }
    try
    {
        if (first)
            inboundPdu_.reserve(expectedInboundBytes_);
        inboundPdu_.insert(
            inboundPdu_.end(), fragment.begin(), fragment.end());
    }
    catch (...)
    {
        close();
        return RdpClipboardChunkIntake::Rejected;
    }

    if (!last)
        return RdpClipboardChunkIntake::NeedMore;

    assembling_ = false;
    expectedInboundBytes_ = 0U;
    clipboard::PduView decoded{};
    if (!clipboard::decodePdu(inboundPdu_, decoded))
    {
        close();
        return RdpClipboardChunkIntake::Rejected;
    }
    completePdu = inboundPdu_;
    return RdpClipboardChunkIntake::Complete;
}

bool RdpClipboardStaticChannelRoute::advanceReplySequence() noexcept
{
    if (replySequence_ == std::numeric_limits<std::uint64_t>::max())
        return false;
    ++replySequence_;
    return true;
}

bool RdpClipboardStaticChannelRoute::advanceSliceSequence() noexcept
{
    if (writeSliceSequence_ == std::numeric_limits<std::uint64_t>::max())
        return false;
    ++writeSliceSequence_;
    return true;
}

bool RdpClipboardStaticChannelRoute::preparePacket() noexcept
{
    if (!active_ || outboundOffset_ >= outboundPdu_.size())
        return false;
    const std::size_t payloadBytes = std::min(
        chunkBytes_, outboundPdu_.size() - outboundOffset_);
    std::array<std::uint8_t,
               kRdpStaticVirtualChannelMaximumChunkBytes +
                   kChannelHeaderBytes> virtualChannelData;
    auto data = std::span(virtualChannelData).first(
        kChannelHeaderBytes + payloadBytes);
    std::uint32_t flags = kChannelShowProtocol;
    if (outboundOffset_ == 0U)
        flags |= kChannelFirst;
    if (outboundOffset_ + payloadBytes == outboundPdu_.size())
        flags |= kChannelLast;
    writeLe32(data, 0U, static_cast<std::uint32_t>(outboundPdu_.size()));
    writeLe32(data, 4U, flags);
    std::copy_n(outboundPdu_.begin() +
                    static_cast<std::ptrdiff_t>(outboundOffset_),
                payloadBytes, data.begin() + kChannelHeaderBytes);
    const auto length = encodeMcsSendDataIndication(
        assignedUserId_, channelId_, 0U, 3U, data, pendingPacket_);
    if (!length || !advanceSliceSequence())
        return false;
    pendingLength_ = *length;
    pendingOffset_ = 0U;
    pendingPayloadBytes_ = payloadBytes;
    return true;
}

bool RdpClipboardStaticChannelRoute::queue(
    std::span<const std::uint8_t> completePdu) noexcept
{
    clipboard::PduView decoded{};
    if (!active_ || !outboundPdu_.empty() ||
        !clipboard::decodePdu(completePdu, decoded) ||
        !advanceReplySequence())
    {
        close();
        return false;
    }
    try
    {
        outboundPdu_.assign(completePdu.begin(), completePdu.end());
    }
    catch (...)
    {
        close();
        return false;
    }
    outboundOffset_ = 0U;
    if (!preparePacket())
    {
        close();
        return false;
    }
    return true;
}

RdpClipboardStaticChannelWriteView
RdpClipboardStaticChannelRoute::pending() const noexcept
{
    if (!active_ || outboundPdu_.empty() ||
        pendingOffset_ >= pendingLength_)
        return {};
    return {
        std::span(pendingPacket_).subspan(
            pendingOffset_, pendingLength_ - pendingOffset_),
        generation_, replySequence_, writeSliceSequence_};
}

RdpClipboardWriteOutcome RdpClipboardStaticChannelRoute::onAcceptedBytes(
    std::uint64_t generation, std::uint64_t replySequence,
    std::uint64_t writeSliceSequence, std::size_t acceptedBytes) noexcept
{
    const auto slice = pending();
    if (!slice || generation != generation_ ||
        replySequence != replySequence_ ||
        writeSliceSequence != writeSliceSequence_ ||
        acceptedBytes == 0U || acceptedBytes > slice.wireBytes.size())
    {
        close();
        return RdpClipboardWriteOutcome::Rejected;
    }
    pendingOffset_ += acceptedBytes;
    if (pendingOffset_ != pendingLength_)
    {
        if (!advanceSliceSequence())
        {
            close();
            return RdpClipboardWriteOutcome::Rejected;
        }
        return RdpClipboardWriteOutcome::Pending;
    }

    outboundOffset_ += pendingPayloadBytes_;
    pendingLength_ = 0U;
    pendingOffset_ = 0U;
    pendingPayloadBytes_ = 0U;
    if (outboundOffset_ == outboundPdu_.size())
    {
        outboundPdu_.clear();
        outboundOffset_ = 0U;
        return RdpClipboardWriteOutcome::Delivered;
    }
    if (!preparePacket())
    {
        close();
        return RdpClipboardWriteOutcome::Rejected;
    }
    return RdpClipboardWriteOutcome::Pending;
}

void RdpClipboardStaticChannelRoute::close() noexcept
{
    active_ = false;
    assignedUserId_ = 0U;
    channelId_ = 0U;
    generation_ = 0U;
    chunkBytes_ = 0U;
    inboundPdu_.clear();
    outboundPdu_.clear();
    assembling_ = false;
    expectedInboundBytes_ = 0U;
    outboundOffset_ = 0U;
    pendingLength_ = 0U;
    pendingOffset_ = 0U;
    pendingPayloadBytes_ = 0U;
}
} // namespace rdp_server::server::transport
