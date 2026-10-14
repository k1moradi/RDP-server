// SPDX-License-Identifier: GPL-3.0-or-later
#include "console_session_lifecycle.h"

#include <algorithm>
#include <array>
#include <string_view>

namespace rdp_server::server::security
{
namespace
{

template <std::size_t Capacity>
[[nodiscard]] bool copyBounded(
    std::array<char, Capacity> &destination,
    std::size_t &length, std::string_view value) noexcept
{
    if (value.empty() || value.size() >= destination.size())
    {
        return false;
    }
    // No string allocation, no caller-owned view stored across checks.
    std::copy(value.begin(), value.end(), destination.begin());
    length = value.size();
    return true;
}

[[nodiscard]] bool sameConsoleIdentity(
    const ConsoleCandidateSessionFingerprint &initial,
    const ConsoleCandidateSessionFingerprint &latest) noexcept
{
    return initial.sessionIdLength == latest.sessionIdLength &&
           std::string_view(initial.sessionId.data(), initial.sessionIdLength) ==
               std::string_view(latest.sessionId.data(), latest.sessionIdLength) &&
           initial.accountUid == latest.accountUid &&
           initial.consoleOwnerUid == latest.consoleOwnerUid &&
           initial.sessionGeneration == latest.sessionGeneration;
}

} // namespace

ConsoleEvidenceRequest ConsoleSessionLifecycleMonitor::requestView() const noexcept
{
    return {
        {kerberosPrincipal_.data(), kerberosPrincipalLength_},
        {unixAccount_.data(), unixAccountLength_},
        {seat_.data(), seatLength_},
        {display_.data(), displayLength_},
        requestedPermissions_};
}

ConsoleLifecycleState ConsoleSessionLifecycleMonitor::observe(
    const ConsoleIdentityPolicy &policy,
    const ConsoleEvidenceRequest &request,
    ConsoleOsEvidenceSource &source) noexcept
{
    if (state_ != ConsoleLifecycleState::NotObserved)
    {
        return state_; // Never rebind this connection to a new identity.
    }

    ConsoleCandidateSessionFingerprint initialFingerprint{};
    if (ConsoleOsEvidenceInspector{}.inspectWithSessionFingerprint(
            policy, request, source, initialFingerprint) !=
            ConsoleEvidenceMatch::CandidateOnly ||
        !copyBounded(kerberosPrincipal_, kerberosPrincipalLength_,
                     request.kerberosPrincipal) ||
        !copyBounded(unixAccount_, unixAccountLength_, request.unixAccount) ||
        !copyBounded(seat_, seatLength_, request.seat) ||
        !copyBounded(display_, displayLength_, request.display))
    {
        revoke();
        return state_;
    }

    requestedPermissions_ = request.requestedPermissions;
    fingerprint_ = initialFingerprint;
    state_ = ConsoleLifecycleState::CandidateOnly;
    return state_;
}

ConsoleLifecycleState ConsoleSessionLifecycleMonitor::revalidate(
    const ConsoleIdentityPolicy &policy,
    ConsoleOsEvidenceSource &source) noexcept
{
    if (state_ == ConsoleLifecycleState::Revoked)
    {
        return state_; // No retry or OS call after terminal revocation.
    }
    if (state_ != ConsoleLifecycleState::CandidateOnly)
    {
        revoke(); // No refresh without a successful initial observation.
        return state_;
    }

    ConsoleCandidateSessionFingerprint currentFingerprint{};
    if (ConsoleOsEvidenceInspector{}.inspectWithSessionFingerprint(
            policy, requestView(), source, currentFingerprint) !=
            ConsoleEvidenceMatch::CandidateOnly ||
        !sameConsoleIdentity(fingerprint_, currentFingerprint) ||
        currentFingerprint.observedAtMonotonicMilliseconds <
            fingerprint_.observedAtMonotonicMilliseconds ||
        currentFingerprint.evaluatedAtMonotonicMilliseconds <
            fingerprint_.evaluatedAtMonotonicMilliseconds)
    {
        revoke();
        return state_;
    }

    // Accept this as the new comparison baseline, but NEVER turn the
    // candidate into an authorized session, token or X11 capability.
    fingerprint_ = currentFingerprint;
    return state_;
}

void ConsoleSessionLifecycleMonitor::revoke() noexcept
{
    // Preserve terminal state while discarding all observed identity text.
    // This is not a GSS/desktop teardown routine; the runtime is deny-only.
    kerberosPrincipal_.fill('\0');
    unixAccount_.fill('\0');
    seat_.fill('\0');
    display_.fill('\0');
    kerberosPrincipalLength_ = 0;
    unixAccountLength_ = 0;
    seatLength_ = 0;
    displayLength_ = 0;
    requestedPermissions_ = 0;
    fingerprint_ = {};
    state_ = ConsoleLifecycleState::Revoked;
}

} // namespace rdp_server::server::security
