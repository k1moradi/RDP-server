// SPDX-License-Identifier: GPL-3.0-or-later
#include "security/linux_logind_console_evidence.h"

#include <cassert>
#include <optional>
#include <string_view>

using namespace rdp_server::server::security;

namespace
{
class OfflineEvidenceSource final : public ConsoleOsEvidenceSource
{
public:
    ConsoleSessionObservation session{};
    std::uint64_t now{1001U};

    ConsoleAccountObservation readUnixAccount(std::string_view) noexcept override
    {
        return {};
    }

    ConsoleSessionObservation readActiveConsole() noexcept override
    {
        return session;
    }

    std::optional<std::uint64_t> readMonotonicMilliseconds() noexcept override
    {
        return now;
    }
};
} // namespace

int main(int argc, char **argv)
{
    if (argc != 2 || argv[1] == nullptr)
        return 2;
    const std::string_view testCase{argv[1]};

    if (testCase == "seat0-session-identity-denials")
    {
        const LogindSessionFacts physical{
            "session-1", "seat0", ":0", "x11", "user",
            1000U, 1000U, 42U, true, true, false};
        const LogindActiveSeatFacts sameSeat{"session-1", 1000U};

        assert(consistentLogindSessionFacts(physical, sameSeat));

        auto changedUid = physical;
        changedUid.sessionOwnerUid = 1001U;
        assert(!consistentLogindSessionFacts(changedUid, sameSeat));

        auto missingStart = physical;
        missingStart.sessionStartRealtimeMicroseconds = 0;
        assert(!consistentLogindSessionFacts(missingStart, sameSeat));

        auto lockScreen = physical;
        lockScreen.sessionClass = "lock-screen";
        assert(!consistentLogindSessionFacts(lockScreen, sameSeat));

        auto inactive = physical;
        inactive.active = false;
        assert(!consistentLogindSessionFacts(inactive, sameSeat));

        auto remote = physical;
        remote.remote = true;
        assert(!consistentLogindSessionFacts(remote, sameSeat));

        assert(!consistentLogindSessionFacts(
            physical, {"other-session", 1000U}));
        assert(!consistentLogindSessionFacts(
            physical, {"session-1", 1001U}));
        return 0;
    }

    if (testCase == "no-config-standalone-current-x11-selection")
    {
        OfflineEvidenceSource source;
        source.session = {
            ConsoleEvidenceReadStatus::Observed,
            "session-1", "seat0", ":42", 1000U, 77U, 1000U,
            true, true, 1000U, ConsoleDesktopLockState::Unlocked, false};

        const auto selected = selectCurrentPhysicalX11Desktop(source);
        assert(selected.eligible());
        assert(selected.sessionId() == "session-1");
        assert(selected.display() == ":42");
        assert(selected.ownerUid == 1000U);
        assert(selected.sessionGeneration == 77U);

        auto wrongOwner = source.session;
        wrongOwner.localProcessUid = 1001U;
        source.session = wrongOwner;
        assert(!selectCurrentPhysicalX11Desktop(source).eligible());

        source.session = {
            ConsoleEvidenceReadStatus::Observed,
            "session-1", "seat0", ":42", 1000U, 77U, 1000U,
            true, true, 1000U, ConsoleDesktopLockState::Locked, false};
        assert(!selectCurrentPhysicalX11Desktop(source).eligible());

        source.session.lockState = ConsoleDesktopLockState::Unlocked;
        source.session.remote = true;
        assert(!selectCurrentPhysicalX11Desktop(source).eligible());

        source.session.remote = false;
        source.session.display = {};
        assert(!selectCurrentPhysicalX11Desktop(source).eligible());

        source.session.display = ":42";
        source.now = 4001U;
        assert(!selectCurrentPhysicalX11Desktop(source).eligible());
        return 0;
    }

    return 2;
}
