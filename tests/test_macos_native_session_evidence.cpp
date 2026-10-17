// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/security/macos_native_session_evidence.h"

#include <cassert>
#include <cstdint>
#include <limits>

int main()
{
    using namespace rdp_server::server::security;

    MacNativeSessionEvidence evidence{};
    MacNativeSessionEvidenceReader reader;
    const auto status = reader.readCurrent(evidence);

    assert(!evidence.matchesAuthenticatedUserId(0));
    assert(!evidence.matchesAuthenticatedUserId(
        std::numeric_limits<std::uint32_t>::max()));

    if (status == MacNativeSessionEvidenceStatus::Unavailable)
    {
        assert(evidence.consoleUserId == 0);
        assert(evidence.auditSessionId == 0);
        assert(evidence.securitySessionId == 0);
        return 0;
    }

    assert(status == MacNativeSessionEvidenceStatus::Observed);
    assert(evidence.consoleUserId != 0);
    assert(evidence.auditUserId == evidence.consoleUserId);
    assert(evidence.auditSessionId != 0);
    assert(evidence.securitySessionId != 0);

    // Matching the host UID is still candidate evidence only; no CTest can
    // promote it to authenticated RDP admission.
    assert(evidence.matchesAuthenticatedUserId(evidence.consoleUserId));

    auto replay = evidence;
    ++replay.auditSessionId;
    assert(!evidence.sameNativeSession(replay));

    replay = evidence;
    ++replay.securitySessionId;
    assert(!evidence.sameNativeSession(replay));
    return 0;
}
