// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "mcs_connect_initial.h"

#include <array>
#include <cstddef>
#include <cstdint>
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
        return length != 0;
    }
    [[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept
    {
        return std::span(packet).first(length);
    }
};

// Input must have come from a checked MCS Connect-Initial; this function
// independently validates the GCC client blocks and negotiates T.125
// DomainParameters. Channel IDs are caller-supplied, NOT assigned here,
// and correspond in order to the client's requested static channels.
// Only current diagnostic PROTOCOL_SSL=1 is supported; selected TLS
// does NOT imply NLA/CredSSP or any authenticated desktop session.
// gccNodeId is T.124 UserID [1001, 65536] inclusive.
[[nodiscard]] McsConnectResponse encodeMcsConnectResponse(
    const McsConnectInitial &client,
    std::span<const std::uint16_t> staticChannelIds,
    std::uint32_t gccNodeId,
    std::uint32_t clientRequestedProtocols) noexcept;

} // namespace rdp_server::server::transport
