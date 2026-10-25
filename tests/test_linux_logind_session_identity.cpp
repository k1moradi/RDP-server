// SPDX-License-Identifier: GPL-3.0-or-later
#include "security/linux_logind_console_evidence.h"
#include "security/linux_logind_session_change_watch.h"
#include "server/runtime/linux_runtime_security.h"

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

    ConsoleAccountObservation readUnixAccount(
        std::string_view account) noexcept override
    {
        if (account != "owner")
            return {};
        return {ConsoleEvidenceReadStatus::Observed, "owner", 1000U};
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

    if (testCase == "logind-monitor-baseline-zero-poll")
    {
        LinuxLogindSessionChangeSource monitor;
        const auto diagnostics = monitor.diagnostics();
        if (!diagnostics.monitorAvailable)
            return 77;
        assert(diagnostics.systemdAvailable);
        assert(diagnostics.monitorCreated);
        assert(diagnostics.descriptorAvailable);
        assert(diagnostics.eventsAvailable);
        assert(diagnostics.initialState !=
               LinuxLogindMonitorState::Unavailable);
        assert(diagnostics.initialFlushSucceeded);
        assert(diagnostics.baselineState !=
               LinuxLogindMonitorState::Unavailable);
        if (diagnostics.baselineState == LinuxLogindMonitorState::Changed)
            return 77;

        const auto firstPoll = monitor.pollChange();
        if (firstPoll == ConsoleSessionChange::Changed)
            return 77;
        assert(firstPoll == ConsoleSessionChange::None);
        assert(monitor.nativeFd() >= 0);
        assert(monitor.nativeEvents() > 0);
        return 0;
    }

    if (testCase == "no-config-standalone-current-x11-selection")
    {
        OfflineEvidenceSource source;
        source.session = {
            ConsoleEvidenceReadStatus::Observed,
            "session-1", "seat0", ":42", 1000U, 77U, 1000U,
            true, true, 1000U, ConsoleDesktopLockState::Unlocked, false};

        // R5 selects only from the trusted native observation. No
        // RuntimeConfigurationView, config file or process DISPLAY exists in
        // this fixture.
        const auto selected = selectCurrentPhysicalX11Desktop(source);
        assert(selected.eligible());
        assert(selected.sessionId() == "session-1");
        assert(selected.display() == ":42");
        assert(selected.ownerUid == 1000U);
        assert(selected.sessionGeneration == 77U);

        // Exercise the exact production no-config standalone policy/admission
        // seam landed by R7: principal-free native target policy, then the
        // StandalonePassword R2 request, then a fresh evidence inspection.
        using namespace rdp_server::server::runtime;
        const ConsoleIdentityRuleInput rule{
            {}, "owner", "seat0", selected.display(), selected.ownerUid,
            kConsoleViewPermission | kConsoleInputPermission};

        LinuxRuntimeSecurityConfiguration security;
        LinuxRuntimeAdmissionConfiguration admission;
        assert(security.configureStandalonePersonalDesktop(rule));
        assert(admission.configureStandalonePersonalDesktop(rule, security));

        const auto request = admission.request(
            security, ConsoleEvidenceAuthenticationKind::StandalonePassword);
        assert(request.has_value());
        assert(request->authenticationKind ==
               ConsoleEvidenceAuthenticationKind::StandalonePassword);
        assert(request->kerberosPrincipal.empty());
        assert(request->unixAccount == "owner");
        assert(request->seat == "seat0");
        assert(request->display == ":42");
        assert(request->requestedPermissions ==
               (kConsoleViewPermission | kConsoleInputPermission));

        const ConsoleIdentityPolicy* policy = security.policy();
        assert(policy != nullptr);
        ConsoleCandidateSessionFingerprint fingerprint;
        const ConsoleOsEvidenceInspector inspector;
        assert(inspector.inspectWithSessionFingerprint(
                   *policy, *request, source, fingerprint) ==
               ConsoleEvidenceMatch::CandidateOnly);
        assert(fingerprint.accountUid == 1000U);
        assert(fingerprint.consoleOwnerUid == 1000U);
        assert(fingerprint.sessionGeneration == 77U);
        assert(std::string_view(
                   fingerprint.sessionId.data(),
                   fingerprint.sessionIdLength) == "session-1");

        // Selector denials remain pre-listener and cannot be repaired by GUI
        // text, a process DISPLAY variable or caller-supplied identity data.
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
