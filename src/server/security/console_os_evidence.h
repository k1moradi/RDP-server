// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "console_identity_policy.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace rdp_server::server::security
{

// A provider is an injection boundary, NOT a certificate of OS trust.
// Only a future audited, privileged/read-only NSS + session-owner adapter
// may supply production observations. This milestone ships NO such adapter.
// M1.16 supplies bounded NSS account data, but NOT session-owner evidence;
// it is not a complete audited production authorization provider.
enum class ConsoleEvidenceReadStatus : std::uint8_t
{
    Unavailable,
    Observed,
    Conflicting,
};

// Borrowed views remain valid until inspect() returns. Implementations must
// not retain the account argument or return views into temporary storage.
struct ConsoleAccountObservation
{
    ConsoleEvidenceReadStatus status{ConsoleEvidenceReadStatus::Unavailable};
    std::string_view unixAccount{};
    std::uint32_t uid{};
};

enum class ConsoleDesktopLockState : std::uint8_t
{
    Unknown,
    Unlocked,
    Locked,
};

struct ConsoleSessionObservation
{
    ConsoleEvidenceReadStatus status{ConsoleEvidenceReadStatus::Unavailable};
    std::string_view sessionId{};
    std::string_view seat{};
    std::string_view display{};
    std::uint32_t ownerUid{};
    // Nonzero provider lifecycle generation, changed on logout/user switch.
    std::uint64_t sessionGeneration{};
    // Same monotonic millisecond clock domain as readMonotonicMilliseconds().
    std::uint64_t observedAtMonotonicMilliseconds{};
    bool active{};
    bool physical{};
    // Native process identity; never supplied by GUI or a network peer.
    std::uint32_t localProcessUid{};
    // Unknown is distinct from unlocked and fails positive owner consent.
    ConsoleDesktopLockState lockState{ConsoleDesktopLockState::Unknown};
    bool remote{};
};

// Source is not owned by the inspector. Each inspect() samples afresh.
// A provider must serialize its own observations; no session lease or TOCTOU
// protection is implied, and no method permits mutation of host resources.
class ConsoleOsEvidenceSource
{
public:
    virtual ~ConsoleOsEvidenceSource() = default;
    ConsoleOsEvidenceSource() = default;
    ConsoleOsEvidenceSource(const ConsoleOsEvidenceSource &) = delete;
    ConsoleOsEvidenceSource &operator=(const ConsoleOsEvidenceSource &) = delete;

    [[nodiscard]] virtual ConsoleAccountObservation readUnixAccount(
        std::string_view account) noexcept = 0;
    [[nodiscard]] virtual ConsoleSessionObservation readActiveConsole() noexcept = 0;
    [[nodiscard]] virtual std::optional<std::uint64_t>
    readMonotonicMilliseconds() noexcept = 0;
};

// Caller may propose ONLY identity, account, seat, display and permissions;
// it cannot provide the UNIX UID or observed physical-console owner UID.
// The Kerberos principal itself is still NOT authenticated at this boundary.
struct ConsoleEvidenceRequest
{
    std::string_view kerberosPrincipal{};
    std::string_view unixAccount{};
    std::string_view seat{};
    std::string_view display{};
    std::uint32_t requestedPermissions{};
};

enum class ConsoleEvidenceMatch : std::uint8_t
{
    Denied,
    CandidateOnly, // Never trusted authentication, authorization or a capability.
};

inline constexpr std::uint64_t
    kMaximumConsoleObservationAgeMilliseconds = 2000;

// Owning, bounded identity of a *candidate* observation, not an OS-issued
// session token. A matching fake provider can also produce this structure.
// Session generation is a lifecycle discriminator, not a permission lease.
struct ConsoleCandidateSessionFingerprint
{
    std::array<char, 65> sessionId{};
    std::size_t sessionIdLength{};
    std::uint32_t accountUid{};
    std::uint32_t consoleOwnerUid{};
    std::uint64_t sessionGeneration{};
    std::uint64_t observedAtMonotonicMilliseconds{};
    std::uint64_t evaluatedAtMonotonicMilliseconds{};
};

// Non-owning, read-only, stateless consistency check. Even CandidateOnly
// cannot authorize a session: current runtime GSS/credentials gate denies.
// A future authorization broker must independently authenticate GSS identity,
// use an audited OS adapter, and bind/revoke a live session capability.
class ConsoleOsEvidenceInspector final
{
public:
    [[nodiscard]] ConsoleEvidenceMatch inspect(
        const ConsoleIdentityPolicy &policy,
        const ConsoleEvidenceRequest &request,
        ConsoleOsEvidenceSource &source) const noexcept;

    // Same source reads and policy checks as inspect(), but make an owning
    // snapshot of their already-validated session identity. On failure the
    // output is cleared. It can NEVER represent authorization or admission.
    [[nodiscard]] ConsoleEvidenceMatch inspectWithSessionFingerprint(
        const ConsoleIdentityPolicy &policy,
        const ConsoleEvidenceRequest &request,
        ConsoleOsEvidenceSource &source,
        ConsoleCandidateSessionFingerprint &candidateFingerprint) const noexcept;
};

} // namespace rdp_server::server::security
