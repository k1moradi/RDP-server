// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "tpkt_x224.h"

#include <array>
#include <cstdint>

namespace rdp_server::server::transport
{

// This is a preauthentication protocol decision, NEVER session admission.
// Standard RDP security is never supported. Policy is fixed before any
// peer-controlled bytes are consumed and cannot change mid-connection.
enum class SecurityNegotiationPolicy : std::uint8_t
{
    DiagnosticTlsOnly,
    HybridNla,
};

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
// DiagnosticTlsOnly preserves the historical TLS-only diagnostic behavior.
// HybridNla selects PROTOCOL_HYBRID only when the client explicitly offered
// HYBRID; SSL-only offers receive HYBRID_REQUIRED_BY_SERVER. Neither policy
// authenticates a principal, authorizes an OS session or admits R3.
[[nodiscard]] SecurityReply negotiateSecurity(
    const ConnectionParseResult &request,
    SecurityNegotiationPolicy policy) noexcept;

// Source-compatible diagnostic wrapper for existing callers/tests.
[[nodiscard]] SecurityReply negotiateDiagnosticTls(
    const ConnectionParseResult &request) noexcept;

} // namespace rdp_server::server::transport
