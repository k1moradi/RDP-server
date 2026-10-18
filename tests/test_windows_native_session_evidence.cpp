// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/security/windows_native_session_evidence.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string_view>

int main(int argumentCount, char **arguments)
{
    using namespace rdp_server::server::security;

    if (argumentCount == 2)
    {
        // Exercise the production identity comparator deterministically,
        // even when hosted WTS/LSA cannot observe an interactive desktop.
        // These are candidate evidence values, NEVER an admission lease.
        assert(std::string_view{arguments[1]} == "reused-session-id-denials");
        WindowsNativeSessionEvidence pinned{};
        pinned.userSid[0] = std::byte{0x01};
        pinned.userSidBytes = 1;
        pinned.sessionId = 42;
        pinned.authenticationIdLow = 101;
        pinned.authenticationIdHigh = 202;
        pinned.logonTime100Nanoseconds = 303;
        pinned.logonType = 2;
        assert(pinned.sameNativeSession(pinned));

        auto reusedNumber = pinned;
        reusedNumber.authenticationIdLow ^= 1U;
        assert(!pinned.sameNativeSession(reusedNumber));

        reusedNumber = pinned;
        reusedNumber.authenticationIdHigh ^= 1;
        assert(!pinned.sameNativeSession(reusedNumber));

        reusedNumber = pinned;
        ++reusedNumber.logonTime100Nanoseconds;
        assert(!pinned.sameNativeSession(reusedNumber));
        return 0;
    }

    assert(argumentCount == 1);
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
