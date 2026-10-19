// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "console_os_evidence.h"
#include "linux_nss_console_evidence.h"

#include <array>
#include <cstdint>
#include <string_view>

namespace rdp_server::server::security
{

// Testable, non-authorizing consistency facts. Synthetic values here do
// NOT attest a login: the production reader obtains them via sd-login.
// The session start time is a CLOCK_REALTIME lifecycle identifier, NOT a
// monotonic freshness timestamp or a revocable authorization lease.
struct LogindSessionFacts
{
    std::string_view sessionId{};
    std::string_view seat{};
    std::string_view display{};
    std::string_view sessionType{};
    std::string_view sessionClass{};
    std::uint32_t seatOwnerUid{};
    std::uint32_t sessionOwnerUid{};
    std::uint64_t sessionStartRealtimeMicroseconds{};
    bool graphicalSeat{};
    bool active{};
    bool remote{};
    // sd_session_get_locked_hint reported 0 (unlocked). Unknown, unsupported
    // and locked hints are deny-only; a false hint is NOT host-owner consent
    // and must not be treated as a definitive desktop lock attestation.
    bool unlockedHint{};
};

// The second seat sample detects a switch DURING the read, but cannot
// prevent a switch AFTER the read. It never grants any access capability.
struct LogindActiveSeatFacts
{
    std::string_view sessionId{};
    std::uint32_t ownerUid{};
};

[[nodiscard]] bool consistentLogindSessionFacts(
    const LogindSessionFacts &session,
    const LogindActiveSeatFacts &secondSeat) noexcept;

// Linux-only logind/NSS evidence source. It is NOT an authorization service.
// The source owns returned string buffers; callers must finish synchronous
// inspection before reusing/destroying the source. Use one instance per
// connection, not concurrently (returned views borrow those buffers).
// No logind/PAM/X11 or production state is modified, and no listener starts.
// If libsystemd was absent at build time or unavailable at runtime, all
// session observations are Unavailable; NSS account lookup still works.
class LinuxLogindReadOnlyEvidenceSource final : public ConsoleOsEvidenceSource
{
public:
    [[nodiscard]] ConsoleAccountObservation readUnixAccount(
        std::string_view account) noexcept override;

    [[nodiscard]] ConsoleSessionObservation readActiveConsole() noexcept override;

    [[nodiscard]] std::optional<std::uint64_t>
    readMonotonicMilliseconds() noexcept override;

private:
    LinuxNssReadOnlyEvidenceSource accountSource_{};
    std::array<char, 65> sessionIdBytes_{};
    std::array<char, 9> displayBytes_{};
};

} // namespace rdp_server::server::security
