// SPDX-License-Identifier: GPL-3.0-or-later
#include "security_negotiation.h"

namespace rdp_server::server::transport
{
namespace
{
constexpr std::uint8_t kCorrelationInfoPresent = 0x08U;
constexpr std::uint32_t kSslRequiredByServer = 0x00000001U;
constexpr std::uint32_t kHybridRequiredByServer = 0x00000005U;

void writeLittleEndian32(std::array<std::uint8_t, 19> &packet,
                         std::uint32_t value) noexcept
{
    packet[15] = static_cast<std::uint8_t>(value & 0xffU);
    packet[16] = static_cast<std::uint8_t>((value >> 8U) & 0xffU);
    packet[17] = static_cast<std::uint8_t>((value >> 16U) & 0xffU);
    packet[18] = static_cast<std::uint8_t>((value >> 24U) & 0xffU);
}
}

SecurityReply negotiateSecurity(
    const ConnectionParseResult &request,
    SecurityNegotiationPolicy policy) noexcept
{
    SecurityReply result{
        SecurityDecision::Reject,
        {0x03, 0x00, 0x00, 0x13,
         0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
         0x03, 0x00, 0x08, 0x00,
         0x01, 0x00, 0x00, 0x00},
    };

    const std::uint32_t requiredProtocol =
        policy == SecurityNegotiationPolicy::HybridNla
            ? kRdpProtocolHybrid
            : kRdpProtocolSsl;
    const std::uint32_t failureCode =
        policy == SecurityNegotiationPolicy::HybridNla
            ? kHybridRequiredByServer
            : kSslRequiredByServer;
    writeLittleEndian32(result.packet, failureCode);

    // R1 does not implement Restricted Admin or Remote Credential Guard
    // semantics. Correlation information is independently parsed/bounded.
    if (!request ||
        !request.request.hasNegotiation ||
        (request.request.negotiationFlags & ~kCorrelationInfoPresent) != 0 ||
        (request.request.requestedProtocols & requiredProtocol) == 0)
    {
        return result;
    }

    result.decision = SecurityDecision::Tls;
    result.packet[11] = 0x02; // TYPE_RDP_NEG_RSP
    result.selectedProtocol = requiredProtocol;
    writeLittleEndian32(result.packet, requiredProtocol);
    return result;
}

SecurityReply negotiateDiagnosticTls(
    const ConnectionParseResult &request) noexcept
{
    return negotiateSecurity(
        request, SecurityNegotiationPolicy::DiagnosticTlsOnly);
}

} // namespace rdp_server::server::transport
