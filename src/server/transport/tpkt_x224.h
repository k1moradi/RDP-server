// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace rdp_server::server::transport
{

// Only the initial TPKT/X.224 Connection Request is supported here.
// X.224's one-byte Length Indicator limits this PDU to 260 bytes.
// Full MCS, TLS/CredSSP, session establishment and desktop access are NOT
// implemented. All input is untrusted; the parser borrows no surviving bytes.
inline constexpr std::size_t kMaximumConnectionRequestBytes = 260;

enum class ConnectionError : std::uint8_t
{
    None,
    InvalidTpkt,
    InvalidX224,
    InvalidPrefix,
    InvalidNegotiation,
    InvalidCorrelation,
};

struct ConnectionRequest
{
    bool hasNegotiation{};
    bool hasClientPrefix{};
    bool hasCorrelation{};
    std::uint8_t negotiationFlags{};
    std::uint32_t requestedProtocols{};
};

struct ConnectionParseResult
{
    ConnectionRequest request{};
    ConnectionError error{ConnectionError::None};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == ConnectionError::None;
    }
};

// A validated TPKT header size; does not authorize allocation of its payload.
[[nodiscard]] std::optional<std::size_t> connectionRequestLength(
    std::span<const std::uint8_t> header) noexcept;

// MS-RDPBCGR 2.2.1.1: parses request metadata; DOES NOT select a security
// protocol or emit a connection-confirm response. Unknown security capability
// bits are preserved for later policy, not implicitly accepted.
[[nodiscard]] ConnectionParseResult parseConnectionRequest(
    std::span<const std::uint8_t> packet) noexcept;

} // namespace rdp_server::server::transport
