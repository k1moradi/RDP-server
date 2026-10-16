// SPDX-License-Identifier: GPL-3.0-or-later
#include "security_negotiation.h"

namespace rdp_server::server::transport
{

SecurityReply negotiateDiagnosticTls(
    const ConnectionParseResult &request) noexcept
{
    // TPKT(4) + X.224 CC(7) + RDP_NEG_{RSP,FAILURE}(8).
    // CC destination reference = 0, source reference = 0x1234, class = 0.
    SecurityReply result{
        SecurityDecision::Reject,
        {0x03, 0x00, 0x00, 0x13,
         0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
         0x03, 0x00, 0x08, 0x00,
         0x01, 0x00, 0x00, 0x00},
    };
    // Do not negotiate based on unknown flag bits. All other requested
    // security protocols are rejected unless TLS is explicitly included.
    // The request may also advertise HYBRID; selecting TLS here is only
    // permissible for a diagnostic which refuses application data later.
    constexpr std::uint8_t kCorrelationOnly = 0x08U;
    if (request &&
        request.request.hasNegotiation &&
        // Restricted Admin and Remote Credential Guard require CredSSP,
        // which the diagnostic does not provide. Reject unknown flags too.
        (request.request.negotiationFlags & ~kCorrelationOnly) == 0 &&
        (request.request.requestedProtocols & kRdpProtocolSsl) != 0)
    {
        result.decision = SecurityDecision::Tls;
        result.packet[11] = 0x02; // TYPE_RDP_NEG_RSP
        result.selectedProtocol = kRdpProtocolSsl;
        // selectedProtocol = PROTOCOL_SSL (1), LE, already in [15..18].
    }
    // Otherwise TYPE_RDP_NEG_FAILURE and SSL_REQUIRED_BY_SERVER (1).
    return result;
}

} // namespace rdp_server::server::transport
