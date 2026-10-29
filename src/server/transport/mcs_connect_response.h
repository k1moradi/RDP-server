// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "gcc_conference_create.h"
#include "mcs_connect_initial.h"
#include "security_negotiation.h"
#include "tpkt_x224.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace rdp_server::server::transport
{

// A bounded OFFLINE MCS/GCC response encoder (MS-RDPBCGR 2.2.1.4).
// It neither writes to SSL/socket nor authorizes a user, OS session,
// MCS domain, channel allocation, or desktop. Bytes are not publishable until
// the sole R3 owner has a freshly revalidated R2 admission, has allocated the
// response identifiers, and owns a stable outbound write receipt.
inline constexpr std::size_t kMaximumMcsResponseBytes = 2048;

struct McsConnectResponse
{
    std::array<std::uint8_t, kMaximumMcsResponseBytes> packet{};
    std::size_t length{};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return length != 0U && length <= packet.size();
    }
    [[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept
    {
        return length <= packet.size()
                   ? std::span(packet).first(length)
                   : std::span<const std::uint8_t>{};
    }
};


struct McsConnectResponseAllocation
{
    std::uint32_t gccNodeId{};
    std::uint16_t ioChannelId{};
    std::array<std::uint16_t, kMaximumStaticChannelCount> staticChannelIds{};
    std::uint8_t staticChannelCount{};
    [[nodiscard]] explicit operator bool() const noexcept
    {
        return gccNodeId != 0U && ioChannelId != 0U &&
               staticChannelCount <= staticChannelIds.size();
    }
    [[nodiscard]] std::span<const std::uint16_t> staticChannels() const noexcept
    {
        return staticChannelCount <= staticChannelIds.size()
                   ? std::span(staticChannelIds).first(staticChannelCount)
                   : std::span<const std::uint16_t>{};
    }
};

[[nodiscard]] std::optional<McsConnectResponseAllocation>
planMcsConnectResponseAllocation(
    const McsDomainParameters &negotiatedDomain,
    const GccClientSettings &clientSettings) noexcept;
[[nodiscard]] std::optional<McsConnectResponseAllocation>
planMcsConnectResponseAllocation(const McsConnectInitial &client) noexcept;

struct McsConnectResponseWriteView
{
    std::span<const std::uint8_t> bytes{};
    std::uint64_t replySequence{};
    std::uint64_t writeSliceSequence{};
    [[nodiscard]] explicit operator bool() const noexcept
    {
        return !bytes.empty() && replySequence != 0U &&
               writeSliceSequence != 0U;
    }
};

enum class McsConnectResponseWriteOutcome : std::uint8_t
{
    Pending,
    Delivered,
    Rejected,
};

class McsConnectResponseWriteGate final
{
public:
    McsConnectResponseWriteGate() noexcept = default;
    McsConnectResponseWriteGate(const McsConnectResponseWriteGate &) = delete;
    McsConnectResponseWriteGate &operator=(const McsConnectResponseWriteGate &) = delete;
    McsConnectResponseWriteGate(McsConnectResponseWriteGate &&) = delete;
    McsConnectResponseWriteGate &operator=(McsConnectResponseWriteGate &&) = delete;
    [[nodiscard]] bool queue(const McsConnectResponse &response) noexcept;
    [[nodiscard]] McsConnectResponseWriteView pendingWrite() const noexcept;
    [[nodiscard]] McsConnectResponseWriteOutcome onBytesWritten(
        std::uint64_t replySequence, std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;
    void close() noexcept;
private:
    [[nodiscard]] bool advanceReplySequence() noexcept;
    [[nodiscard]] bool advanceWriteSliceSequence() noexcept;
    McsConnectResponse pending_{};
    std::size_t bytesWritten_{};
    std::uint64_t replySequence_{};
    std::uint64_t writeSliceSequence_{};
    bool delivered_{};
    bool closed_{};
};

[[nodiscard]] bool matchesMcsSecurityNegotiationReplay(
    const GccClientSettings &clientSettings,
    const SecurityNegotiationProvenance &provenance) noexcept;

// Pure anti-tamper correlation for Enhanced RDP Security. R1 must supply
// immutable provenance for BOTH values from the original X.224 exchange.
// clientRequestedProtocols is the client's entire request bitmask; the
// Client Core block separately replays the one serverSelectedProtocol.
// Current syntax support is PROTOCOL_SSL and PROTOCOL_HYBRID only.
// This comparison grants no authentication, admission or response authority.
[[nodiscard]] bool matchesMcsSecurityNegotiationReplay(
    const McsConnectInitial &client,
    std::uint32_t clientRequestedProtocols,
    std::uint32_t serverSelectedProtocol) noexcept;

// Input must have come from a checked MCS Connect-Initial; this function
// independently validates the GCC client blocks and negotiates T.125
// DomainParameters. Channel IDs are caller-supplied, NOT assigned here,
// and correspond in order to the client's requested static channels.
// clientRequestedProtocols is replayed EXACTLY in Server Core Data and may
// contain PROTOCOL_SSL, PROTOCOL_HYBRID, or both; unsupported protocol bits
// fail closed. The caller still must correlate serverSelectedProtocol using
// matchesMcsSecurityNegotiationReplay before any bytes can be published.
// gccNodeId is T.124 UserID [1001, 65535] inclusive.
[[nodiscard]] McsConnectResponse encodeMcsConnectResponse(
    const McsConnectInitial &client,
    std::span<const std::uint16_t> staticChannelIds,
    std::uint32_t gccNodeId,
    std::uint32_t clientRequestedProtocols) noexcept;

[[nodiscard]] McsConnectResponse encodeMcsConnectResponseFromNegotiatedState(
    const McsDomainParameters &negotiatedDomain,
    std::size_t expectedStaticChannelCount,
    std::span<const std::uint16_t> staticChannelIds,
    std::uint32_t gccNodeId,
    std::uint32_t clientRequestedProtocols) noexcept;

} // namespace rdp_server::server::transport
