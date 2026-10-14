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
    assert((tls.packet == std::array<std::uint8_t, 19>{
        3, 0, 0, 19, 14, 0xd0, 0, 0, 0x12, 0x34, 0,
        2, 0, 8, 0, 1, 0, 0, 0}));
    request.request.requestedProtocols = 0x03; // TLS + HYBRID offer
    assert(negotiateDiagnosticTls(request).decision == SecurityDecision::Tls);

    request.request.requestedProtocols = 0x02; // HYBRID only
    const auto rejected = negotiateDiagnosticTls(request);
    assert(rejected.decision == SecurityDecision::Reject);
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

    request.request.requestedProtocols = 0;
    assert(negotiateDiagnosticTls(request).decision == SecurityDecision::Reject);
    request.request.hasNegotiation = false;
    request.request.requestedProtocols = 1; // stale metadata does not authorize
    assert(negotiateDiagnosticTls(request).decision == SecurityDecision::Reject);
    request.error = ConnectionError::InvalidTpkt;
    request.request.hasNegotiation = true;
    assert(negotiateDiagnosticTls(request).decision == SecurityDecision::Reject);
}
