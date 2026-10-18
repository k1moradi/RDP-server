// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "clipboard/clipboard_protocol.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace rdp_server::server::transport
{

// Offline framing mechanics only; construction/start is NEVER an R2 lease,
// Share permission, or proof of a negotiated static-channel role. The single
// McsSessionLifecycle owns the live instance; only its private R2 path starts
// or consumes it. Not thread-safe. All returned spans are synchronous borrows.
enum class RdpClipboardChunkIntake : std::uint8_t
{
    Rejected,
    NeedMore,
    Complete,
};

enum class RdpClipboardWriteOutcome : std::uint8_t
{
    Rejected,
    Pending,
    Delivered,
};

struct RdpClipboardStaticChannelView
{
    std::uint16_t channelId{};
    std::uint64_t generation{};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return channelId != 0U && generation != 0U;
    }
};

struct RdpClipboardStaticChannelWriteView
{
    std::span<const std::uint8_t> wireBytes{};
    std::uint64_t routeGeneration{};
    std::uint64_t replySequence{};
    std::uint64_t writeSliceSequence{};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return !wireBytes.empty() && routeGeneration != 0U &&
               replySequence != 0U && writeSliceSequence != 0U;
    }
};

// MS-RDPBCGR 2.2.6.1, 3.1.5.2: one bounded, uncompressed static VC
// stream in each direction. Contains whole MCS SendDataIndication TPKTs
// for outbound receipts. Receives ONLY pre-parsed MCS userData on the
// verified channel; the R3 session owns the TPKT/MCS ingress parser.
class RdpClipboardStaticChannelRoute final
{
public:
    RdpClipboardStaticChannelRoute() = default;
    RdpClipboardStaticChannelRoute(
        const RdpClipboardStaticChannelRoute &) = delete;
    RdpClipboardStaticChannelRoute &operator=(
        const RdpClipboardStaticChannelRoute &) = delete;

    [[nodiscard]] bool start(std::uint32_t assignedUserId,
                             std::uint16_t channelId,
                             std::uint64_t generation,
                             std::size_t chunkBytes) noexcept;
    [[nodiscard]] RdpClipboardStaticChannelView view() const noexcept
    {
        return active_ ? RdpClipboardStaticChannelView{channelId_, generation_}
                       : RdpClipboardStaticChannelView{};
    }
    [[nodiscard]] std::uint64_t lastGeneration() const noexcept
    {
        return lastGeneration_;
    }
    [[nodiscard]] bool idle() const noexcept
    {
        return !assembling_ && outboundPdu_.empty();
    }

    // On Complete, completePdu borrows R3-owned, exactly decoded CLIPRDR
    // bytes, never static-VC/MCS/TPKT envelopes. Invalid input retires route.
    [[nodiscard]] RdpClipboardChunkIntake receive(
        std::uint16_t channelId, std::uint64_t generation,
        std::span<const std::uint8_t> virtualChannelData,
        std::span<const std::uint8_t> &completePdu) noexcept;

    // Each queued PDU is validated, copied once, then emitted as contiguous
    // exact TLS-plaintext TPKT slices. A partial accepted receipt advances
    // the suffix but never completes publication. Zero is NOT a receipt.
    [[nodiscard]] bool queue(
        std::span<const std::uint8_t> completePdu) noexcept;
    [[nodiscard]] RdpClipboardStaticChannelWriteView pending() const noexcept;
    [[nodiscard]] RdpClipboardWriteOutcome onAcceptedBytes(
        std::uint64_t generation, std::uint64_t replySequence,
        std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;

    // Terminal for this generation; retain high-water generation/sequence
    // counters so restarting this offline codec cannot revive a stale slice.
    void close() noexcept;

private:
    [[nodiscard]] bool preparePacket() noexcept;
    [[nodiscard]] bool advanceReplySequence() noexcept;
    [[nodiscard]] bool advanceSliceSequence() noexcept;

    static constexpr std::size_t kMaximumTpktBytes = 16399U;
    std::array<std::uint8_t, kMaximumTpktBytes> pendingPacket_{};
    std::vector<std::uint8_t> inboundPdu_{};
    std::vector<std::uint8_t> outboundPdu_{};
    std::size_t expectedInboundBytes_{};
    std::size_t outboundOffset_{};
    std::size_t pendingLength_{};
    std::size_t pendingOffset_{};
    std::size_t pendingPayloadBytes_{};
    std::size_t chunkBytes_{};
    std::uint32_t assignedUserId_{};
    std::uint16_t channelId_{};
    std::uint64_t generation_{};
    std::uint64_t lastGeneration_{};
    std::uint64_t replySequence_{};
    std::uint64_t writeSliceSequence_{};
    bool assembling_{};
    bool active_{};
};

} // namespace rdp_server::server::transport
