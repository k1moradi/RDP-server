// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/security/windows_native_session_evidence.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>

int main()
{
    using namespace rdp_server::server::security;

    WindowsNativeSessionEvidence evidence{};
    WindowsNativeSessionEvidenceReader reader;
    const auto status = reader.readCurrent(evidence);

    assert(!evidence.matchesAuthenticatedSid({}));
    if (status == WindowsNativeSessionEvidenceStatus::Unavailable)
    {
        assert(evidence.userSidBytes == 0);
        assert(evidence.sessionId == 0);
        return 0;
    }

    assert(status == WindowsNativeSessionEvidenceStatus::Observed);
    assert(evidence.userSidBytes != 0);
    assert(evidence.userSidBytes <= evidence.userSid.size());
    assert(evidence.sessionId != 0);
    assert(evidence.logonTime100Nanoseconds > 0);

    const std::span<const std::byte> observedSid{
        evidence.userSid.data(), evidence.userSidBytes};
    // This is candidate-native evidence only. Echoing its SID in a test is
    // never an RDP authentication proof or a capability issuance.
    assert(evidence.matchesAuthenticatedSid(observedSid));

    auto replay = evidence;
    replay.sessionId =
        evidence.sessionId == std::numeric_limits<std::uint32_t>::max() - 1
            ? evidence.sessionId - 1
            : evidence.sessionId + 1;
    assert(!evidence.sameNativeSession(replay));

    replay = evidence;
    replay.authenticationIdLow ^= 1U;
    assert(!evidence.sameNativeSession(replay));
    return 0;
}
