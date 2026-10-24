// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "current_owner_sharing_authority.h"
#include "standalone_ntlmv2.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace rdp_server::server::security
{

// Ordinary Stop is the only R2 teardown reason that may retain the
// service-lifetime, memory-only standalone credential. Every other reason is a
// terminal credential boundary.
[[nodiscard]] constexpr bool shouldRetireStandaloneApplicationCredential(
    OwnerConsentRevocationReason reason) noexcept
{
    // Portable HostControl lifecycle matrix. Keep this exhaustive so Linux,
    // macOS and future Windows ownership cannot silently diverge:
    // ordinary Stop retains only the configured memory-only credential;
    // every terminal authorization/security boundary retires it.
    switch (reason)
    {
    case OwnerConsentRevocationReason::Stop:
        return false;
    case OwnerConsentRevocationReason::LockOrUnknown:
    case OwnerConsentRevocationReason::Logout:
    case OwnerConsentRevocationReason::UserSwitch:
    case OwnerConsentRevocationReason::SessionReplacement:
    case OwnerConsentRevocationReason::CredentialChange:
    case OwnerConsentRevocationReason::AuthorityExpired:
    case OwnerConsentRevocationReason::NativeAuthorizationLost:
        return true;
    }
    return true; // Unknown future reasons fail closed.
}

enum class StandaloneCredentialSessionState : std::uint8_t
{
    Unbound,
    Matches,
    LockOrUnknown,
    TerminalSessionChanged,
};

// Non-secret native-session fingerprint associated with the current standalone
// credential generation. It owns no password/hash/authentication capability.
// R10 keeps it only so an ordinary Stop cannot let a later lock/logout/user
// switch/session replacement inherit the retained credential.
class StandaloneCredentialSessionBinding final
{
public:
    void clear() noexcept
    {
        sessionId_.fill('\0');
        sessionIdLength_ = 0U;
        ownerUid_ = 0U;
        sessionGeneration_ = 0U;
        bound_ = false;
    }

    [[nodiscard]] bool bound() const noexcept { return bound_; }

    [[nodiscard]] bool bind(
        const ConsoleSessionObservation& session,
        const std::optional<std::uint64_t>& now) noexcept
    {
        clear();
        if (!validIdentity(session, now) ||
            session.lockState != ConsoleDesktopLockState::Unlocked)
        {
            return false;
        }

        std::copy(
            session.sessionId.begin(), session.sessionId.end(),
            sessionId_.begin());
        sessionIdLength_ = session.sessionId.size();
        ownerUid_ = session.ownerUid;
        sessionGeneration_ = session.sessionGeneration;
        bound_ = true;
        return true;
    }

    [[nodiscard]] StandaloneCredentialSessionState assess(
        const ConsoleSessionObservation& session,
        const std::optional<std::uint64_t>& now) const noexcept
    {
        if (!bound_)
            return StandaloneCredentialSessionState::Unbound;
        if (!validIdentity(session, now) ||
            session.ownerUid != ownerUid_ ||
            session.sessionGeneration != sessionGeneration_ ||
            session.sessionId.size() != sessionIdLength_ ||
            session.sessionId != std::string_view{
                sessionId_.data(), sessionIdLength_})
        {
            return StandaloneCredentialSessionState::TerminalSessionChanged;
        }
        if (session.lockState != ConsoleDesktopLockState::Unlocked)
            return StandaloneCredentialSessionState::LockOrUnknown;
        return StandaloneCredentialSessionState::Matches;
    }

private:
    [[nodiscard]] static bool validIdentity(
        const ConsoleSessionObservation& session,
        const std::optional<std::uint64_t>& now) noexcept
    {
        return session.status == ConsoleEvidenceReadStatus::Observed &&
               session.active && session.physical && !session.remote &&
               session.seat == "seat0" &&
               !session.sessionId.empty() &&
               session.sessionId.size() <= 64U &&
               session.ownerUid != 0U &&
               session.localProcessUid == session.ownerUid &&
               session.sessionGeneration != 0U &&
               now.has_value() &&
               *now >= session.observedAtMonotonicMilliseconds &&
               *now - session.observedAtMonotonicMilliseconds <=
                   kMaximumConsoleObservationAgeMilliseconds;
    }

    std::array<char, 65> sessionId_{};
    std::size_t sessionIdLength_{};
    std::uint32_t ownerUid_{};
    std::uint64_t sessionGeneration_{};
    bool bound_{};
};

[[nodiscard]] inline StandaloneCredentialSessionState
refreshStandaloneCredentialSessionBinding(
    StandaloneCredentialSessionBinding& binding,
    ConsoleOsEvidenceSource& evidenceSource,
    bool bindWhenUnbound) noexcept
{
    const ConsoleSessionObservation session =
        evidenceSource.readActiveConsole();
    const std::optional<std::uint64_t> now =
        evidenceSource.readMonotonicMilliseconds();
    if (!binding.bound())
    {
        if (bindWhenUnbound && binding.bind(session, now))
            return StandaloneCredentialSessionState::Matches;
        return StandaloneCredentialSessionState::Unbound;
    }
    return binding.assess(session, now);
}

// One R2 credential-replacement transaction shared by platform HostControls.
// Replacement intent invalidates any prior owner-consent generation before the
// production credential owner consumes and scrubs the mutable password. The
// returned observation is descriptive only; native admission, owner permission
// and listener Start remain independent later gates.
[[nodiscard]] inline StandalonePasswordCredentialObservation
replaceStandaloneApplicationCredential(
    StandalonePasswordCredentialOwner& credentialOwner,
    CurrentOwnerSharingAuthority& ownerAuthority,
    std::u16string_view username,
    std::span<char16_t> password) noexcept
{
    ownerAuthority.revoke(OwnerConsentRevocationReason::CredentialChange);

    if (!credentialOwner.configure(username, password))
        return credentialOwner.observation();

    const auto observation = credentialOwner.observation();
    if (observation.configured && observation.generation != 0U)
        return observation;

    credentialOwner.revoke();
    return credentialOwner.observation();
}

} // namespace rdp_server::server::security
