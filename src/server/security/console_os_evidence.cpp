// SPDX-License-Identifier: GPL-3.0-or-later
#include "console_os_evidence.h"

#include <algorithm>

namespace rdp_server::server::security
{
namespace
{

[[nodiscard]] bool validSessionId(std::string_view sessionId) noexcept
{
    if (sessionId.empty() || sessionId.size() > 64)
    {
        return false;
    }
    for (const char character : sessionId)
    {
        if ((character < 'a' || character > 'z') &&
            (character < 'A' || character > 'Z') &&
            (character < '0' || character > '9') &&
            character != '_' && character != '-')
        {
            return false;
        }
    }
    return true;
}

// One shared reader/validator keeps the existing fast inspection path
// nonallocating and avoids a second, potentially inconsistent OS sample.
[[nodiscard]] ConsoleEvidenceMatch inspectCandidate(
    const ConsoleIdentityPolicy &policy,
    const ConsoleEvidenceRequest &request,
    ConsoleOsEvidenceSource &source,
    ConsoleCandidateSessionFingerprint *candidateFingerprint) noexcept
{
    // Never accept a caller-supplied local UID or owner UID. The provider
    // reads independent account and physical-console observations afresh.
    // The standalone path must remain principal-free rather than borrowing or
    // inventing the Kerberos identity stored in the configured OS-account rule.
    const bool kerberosIdentity =
        request.authenticationKind ==
        ConsoleEvidenceAuthenticationKind::KerberosPrincipal;
    const bool standaloneIdentity =
        request.authenticationKind ==
        ConsoleEvidenceAuthenticationKind::StandalonePassword;
    if ((!kerberosIdentity && !standaloneIdentity) ||
        (kerberosIdentity && request.kerberosPrincipal.empty()) ||
        (standaloneIdentity && !request.kerberosPrincipal.empty()) ||
        request.unixAccount.empty() ||
        request.seat.empty() || request.display.empty() ||
        request.requestedPermissions == 0 ||
        (request.requestedPermissions & ~kConsoleAllowedPermissions) != 0)
    {
        return ConsoleEvidenceMatch::Denied;
    }

    const ConsoleAccountObservation account =
        source.readUnixAccount(request.unixAccount);
    if (account.status != ConsoleEvidenceReadStatus::Observed ||
        account.unixAccount != request.unixAccount ||
        account.uid == 0 || account.uid == 0xffffffffU)
    {
        return ConsoleEvidenceMatch::Denied;
    }

    const ConsoleSessionObservation session = source.readActiveConsole();
    if (session.status != ConsoleEvidenceReadStatus::Observed ||
        !session.active || !session.physical ||
        !validSessionId(session.sessionId) ||
        session.sessionGeneration == 0 ||
        session.seat != request.seat ||
        session.display != request.display ||
        session.ownerUid == 0 || session.ownerUid != account.uid)
    {
        return ConsoleEvidenceMatch::Denied;
    }

    const std::optional<std::uint64_t> now =
        source.readMonotonicMilliseconds();
    if (!now.has_value() ||
        session.observedAtMonotonicMilliseconds == 0 ||
        *now < session.observedAtMonotonicMilliseconds ||
        *now - session.observedAtMonotonicMilliseconds >
            kMaximumConsoleObservationAgeMilliseconds)
    {
        return ConsoleEvidenceMatch::Denied;
    }

    // M1.14 is a candidate-policy check only. A controlled fake provider
    // in CTest can reach CandidateOnly, but can NEVER issue desktop access.
    ConsolePolicyMatch policyMatch = ConsolePolicyMatch::Denied;
    if (kerberosIdentity)
    {
        const ConsoleIdentityRequest policyCandidate{
            request.kerberosPrincipal,
            account.unixAccount,
            session.seat,
            session.display,
            account.uid,
            session.ownerUid,
            request.requestedPermissions};
        policyMatch = policy.matchCandidate(policyCandidate);
    }
    else
    {
        policyMatch = policy.matchNativeAccountCandidate(
            account.unixAccount,
            session.seat,
            session.display,
            account.uid,
            session.ownerUid,
            request.requestedPermissions);
    }
    if (policyMatch != ConsolePolicyMatch::CandidateOnly)
        return ConsoleEvidenceMatch::Denied;

    if (candidateFingerprint != nullptr)
    {
        // The session ID was already syntax/length checked, and this copy
        // is taken from the SAME sampled attributes used for policy.
        std::copy(session.sessionId.begin(), session.sessionId.end(),
                  candidateFingerprint->sessionId.begin());
        candidateFingerprint->sessionIdLength = session.sessionId.size();
        candidateFingerprint->accountUid = account.uid;
        candidateFingerprint->consoleOwnerUid = session.ownerUid;
        candidateFingerprint->sessionGeneration = session.sessionGeneration;
        candidateFingerprint->observedAtMonotonicMilliseconds =
            session.observedAtMonotonicMilliseconds;
        candidateFingerprint->evaluatedAtMonotonicMilliseconds = *now;
    }
    return ConsoleEvidenceMatch::CandidateOnly;
}

} // namespace

ConsoleEvidenceMatch ConsoleOsEvidenceInspector::inspect(
    const ConsoleIdentityPolicy &policy,
    const ConsoleEvidenceRequest &request,
    ConsoleOsEvidenceSource &source) const noexcept
{
    return inspectCandidate(policy, request, source, nullptr);
}

ConsoleEvidenceMatch
ConsoleOsEvidenceInspector::inspectWithSessionFingerprint(
    const ConsoleIdentityPolicy &policy,
    const ConsoleEvidenceRequest &request,
    ConsoleOsEvidenceSource &source,
    ConsoleCandidateSessionFingerprint &candidateFingerprint) const noexcept
{
    candidateFingerprint = {}; // Never expose an old candidate on failure.
    return inspectCandidate(policy, request, source, &candidateFingerprint);
}

} // namespace rdp_server::server::security
