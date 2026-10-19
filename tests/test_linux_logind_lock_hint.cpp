// SPDX-License-Identifier: GPL-3.0-or-later
#include "security/linux_logind_console_evidence.h"

#include <string_view>

using namespace rdp_server::server::security;

// Pure, non-authorizing consistency facts; no logind, GSS, listener,
// synthetic positive admission, or physical host access is involved.
int main(int argc, char **argv)
{
    if (argc != 2 || argv[1] == nullptr ||
        std::string_view(argv[1]) != "seat0-lock-hint-denials")
        return 2;

    const LogindActiveSeatFacts sameSeat{"session-1", 1000U};
    const LogindSessionFacts reportedUnlocked{
        "session-1", "seat0", ":0", "x11", "user",
        1000U, 1000U, 42U, true, true, false, true};

    // Passing a consistency predicate is never authenticated admission.
    if (!consistentLogindSessionFacts(reportedUnlocked, sameSeat))
        return 1;

    auto locked = reportedUnlocked;
    locked.unlockedHint = false;
    if (consistentLogindSessionFacts(locked, sameSeat))
        return 1;

    // A default/unsampled hint must deny even if all other facts match.
    auto missingHint = LogindSessionFacts{};
    missingHint.sessionId = "session-1";
    missingHint.seat = "seat0";
    missingHint.display = ":0";
    missingHint.sessionType = "x11";
    missingHint.sessionClass = "user";
    missingHint.seatOwnerUid = 1000U;
    missingHint.sessionOwnerUid = 1000U;
    missingHint.sessionStartRealtimeMicroseconds = 42U;
    missingHint.graphicalSeat = true;
    missingHint.active = true;
    if (consistentLogindSessionFacts(missingHint, sameSeat))
        return 1;

    auto inactive = reportedUnlocked;
    inactive.active = false;
    if (consistentLogindSessionFacts(inactive, sameSeat))
        return 1;
    auto remote = reportedUnlocked;
    remote.remote = true;
    if (consistentLogindSessionFacts(remote, sameSeat))
        return 1;
    if (consistentLogindSessionFacts(
            reportedUnlocked, {"different-session", 1000U}))
        return 1;
    return 0;
}
