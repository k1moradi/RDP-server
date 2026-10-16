// SPDX-License-Identifier: GPL-3.0-or-later
#include "transport/security_negotiation.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <array>
#include <cstdint>

using namespace rdp_server::server::transport;

int main()
{
    ConnectionParseResult request{};
    request.request.hasNegotiation = true;
    request.request.requestedProtocols = 0x01;
    const auto tls = negotiateDiagnosticTls(request);
    assert(tls.decision == SecurityDecision::Tls);
    assert(tls.selectedProtocol == kRdpProtocolSsl);
    assert((tls.packet == std::array<std::uint8_t, 19>{
        3, 0, 0, 19, 14, 0xd0, 0, 0, 0x12, 0x34, 0,
        2, 0, 8, 0, 1, 0, 0, 0}));
    request.request.requestedProtocols = 0x03; // TLS + HYBRID offer
    const auto tlsFromCombinedOffer = negotiateDiagnosticTls(request);
    assert(tlsFromCombinedOffer.decision == SecurityDecision::Tls);
    assert(tlsFromCombinedOffer.selectedProtocol == kRdpProtocolSsl);

    request.request.requestedProtocols = 0x02; // HYBRID only
    const auto rejected = negotiateDiagnosticTls(request);
    assert(rejected.decision == SecurityDecision::Reject);
    assert(rejected.selectedProtocol == 0U);
    assert((rejected.packet == std::array<std::uint8_t, 19>{
        3, 0, 0, 19, 14, 0xd0, 0, 0, 0x12, 0x34, 0,
        3, 0, 8, 0, 1, 0, 0, 0}));

    request.request.requestedProtocols = 1;
    request.request.negotiationFlags = 0x01; // Restricted Admin: CredSSP required
    assert(negotiateDiagnosticTls(request).decision == SecurityDecision::Reject);
    request.request.negotiationFlags = 0x02; // Remote Credential Guard
    assert(negotiateDiagnosticTls(request).decision == SecurityDecision::Reject);
    request.request.negotiationFlags = 0x04; // Unsupported reserved flag
    assert(negotiateDiagnosticTls(request).decision == SecurityDecision::Reject);
    request.request.negotiationFlags = 0x08; // Valid correlation marker
    assert(negotiateDiagnosticTls(request).decision == SecurityDecision::Tls);
    request.request.negotiationFlags = 0;

    // Explicit serving NLA policy selects HYBRID and never silently
    // downgrades an SSL-only client to the diagnostic TLS path.
    request = {};
    request.request.hasNegotiation = true;
    request.request.requestedProtocols = kRdpProtocolSsl | kRdpProtocolHybrid;
    const auto hybridCombined = negotiateSecurity(
        request, SecurityNegotiationPolicy::HybridNla);
    assert(hybridCombined.decision == SecurityDecision::Tls);
    assert(hybridCombined.selectedProtocol == kRdpProtocolHybrid);
    assert((hybridCombined.packet == std::array<std::uint8_t, 19>{
        3, 0, 0, 19, 14, 0xd0, 0, 0, 0x12, 0x34, 0,
        2, 0, 8, 0, 2, 0, 0, 0}));

    request.request.requestedProtocols = kRdpProtocolHybrid;
    const auto hybridOnly = negotiateSecurity(
        request, SecurityNegotiationPolicy::HybridNla);
    assert(hybridOnly.decision == SecurityDecision::Tls);
    assert(hybridOnly.selectedProtocol == kRdpProtocolHybrid);

    request.request.requestedProtocols = kRdpProtocolSsl;
    const auto hybridRequired = negotiateSecurity(
        request, SecurityNegotiationPolicy::HybridNla);
    assert(hybridRequired.decision == SecurityDecision::Reject);
    assert(hybridRequired.selectedProtocol == 0U);
    assert((hybridRequired.packet == std::array<std::uint8_t, 19>{
        3, 0, 0, 19, 14, 0xd0, 0, 0, 0x12, 0x34, 0,
        3, 0, 8, 0, 5, 0, 0, 0}));

    request.request.requestedProtocols =
        kRdpProtocolSsl | kRdpProtocolHybrid;
    request.request.negotiationFlags = 0x08;
    assert(negotiateSecurity(
        request, SecurityNegotiationPolicy::HybridNla).decision ==
        SecurityDecision::Tls);
    for (const std::uint8_t unsupportedFlag :
         {std::uint8_t{0x01}, std::uint8_t{0x02}, std::uint8_t{0x04}})
    {
        request.request.negotiationFlags = unsupportedFlag;
        assert(negotiateSecurity(
            request, SecurityNegotiationPolicy::HybridNla).decision ==
            SecurityDecision::Reject);
    }
    request.request.negotiationFlags = 0;

    request.request.requestedProtocols = 0;
    assert(negotiateDiagnosticTls(request).decision == SecurityDecision::Reject);
    assert(negotiateSecurity(
        request, SecurityNegotiationPolicy::HybridNla).decision ==
        SecurityDecision::Reject);
    request.request.hasNegotiation = false;
    request.request.requestedProtocols = 1; // stale metadata does not authorize
    assert(negotiateDiagnosticTls(request).decision == SecurityDecision::Reject);
    request.error = ConnectionError::InvalidTpkt;
    request.request.hasNegotiation = true;
    assert(negotiateDiagnosticTls(request).decision == SecurityDecision::Reject);
}
