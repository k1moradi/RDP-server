// SPDX-License-Identifier: GPL-3.0-or-later
#include "security/linux_logind_console_evidence.h"

#include <string_view>

using namespace rdp_server::server::security;

// Pure candidate-consistency denials only; no live logind, GSS, R1 listener,
// authenticated lease, desktop or physical-session acceptance is involved.
int main(int argc, char **argv)
{
    if (argc != 2 || argv[1] == nullptr ||
        std::string_view(argv[1]) != "seat0-session-identity-denials")
        return 2;

    const LogindSessionFacts physical{
        "session-1", "seat0", ":0", "x11", "user",
        1000U, 1000U, 42U, true, true, false};
    const LogindActiveSeatFacts sameSeat{"session-1", 1000U};

    if (!consistentLogindSessionFacts(physical, sameSeat))
        return 1; // Candidate-only; never a production R2 authorization.

    auto changedUid = physical;
    changedUid.sessionOwnerUid = 1001U;
    if (consistentLogindSessionFacts(changedUid, sameSeat))
        return 1;

    auto missingStart = physical;
    missingStart.sessionStartRealtimeMicroseconds = 0;
    if (consistentLogindSessionFacts(missingStart, sameSeat))
        return 1;

    auto lockScreen = physical;
    lockScreen.sessionClass = "lock-screen";
    if (consistentLogindSessionFacts(lockScreen, sameSeat))
        return 1;

    auto inactive = physical;
    inactive.active = false;
    if (consistentLogindSessionFacts(inactive, sameSeat))
        return 1;

    auto remote = physical;
    remote.remote = true;
    if (consistentLogindSessionFacts(remote, sameSeat))
        return 1;

    if (consistentLogindSessionFacts(physical, {"other-session", 1000U}) ||
        consistentLogindSessionFacts(physical, {"session-1", 1001U}))
        return 1;

    return 0;
}
