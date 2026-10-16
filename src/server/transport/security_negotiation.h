// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "tpkt_x224.h"

#include <array>
#include <cstdint>

namespace rdp_server::server::transport
{

// This is a preauthentication protocol decision, NEVER session admission.
// The probe only supports PROTOCOL_SSL (TLS), never Standard RDP security.
enum class SecurityDecision : std::uint8_t
{
    Reject,
    Tls,
};

struct SecurityReply
{
    SecurityDecision decision{SecurityDecision::Reject};
    std::array<std::uint8_t, 19> packet{};
    // Meaningful only for a successful RDP_NEG_RSP. A NEG_FAILURE packet's
    // final DWORD is a failureCode and must never be mistaken for selection.
    std::uint32_t selectedProtocol{};
};

// Immutable anti-tamper provenance captured by R1 from the one original
// X.224 negotiation exchange. It is transport metadata only: these scalars
// do not authenticate a principal, authorize an OS session or admit R3.
struct SecurityNegotiationProvenance
{
    std::uint32_t clientRequestedProtocols{};
    std::uint32_t serverSelectedProtocol{};

    friend constexpr bool operator==(
        const SecurityNegotiationProvenance &,
        const SecurityNegotiationProvenance &) noexcept = default;
};

// RFC 1006 + MS-RDPBCGR 2.2.1.2, with X.224 Connection Confirm (CC)
// and an eight-byte RDP_NEG_RSP or RDP_NEG_FAILURE payload.
//
// Fail closed for legacy, malformed or non-TLS proposals. On success the
// caller MAY perform a TLS handshake; that is NOT CredSSP/NLA or a desktop
// session, and no bytes from an unauthenticated client may reach MCS.
[[nodiscard]] SecurityReply negotiateDiagnosticTls(
    const ConnectionParseResult &request) noexcept;

} // namespace rdp_server::server::transport
