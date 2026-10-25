// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "console_os_evidence.h"
#include "linux_nss_console_evidence.h"

#include <array>
#include <cstddef>
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

enum class LinuxCurrentX11DesktopStatus : std::uint8_t
{
    Unavailable,
    Eligible,
};

struct LinuxCurrentX11DesktopSelection final
{
    LinuxCurrentX11DesktopStatus status{
        LinuxCurrentX11DesktopStatus::Unavailable};
    std::array<char, 65> sessionIdBytes{};
    std::array<char, 9> displayBytes{};
    std::size_t sessionIdLength{};
    std::size_t displayLength{};
    std::uint32_t ownerUid{};
    std::uint64_t sessionGeneration{};

    [[nodiscard]] bool eligible() const noexcept
    {
        return status == LinuxCurrentX11DesktopStatus::Eligible;
    }
    [[nodiscard]] std::string_view sessionId() const noexcept
    {
        return {sessionIdBytes.data(), sessionIdLength};
    }
    [[nodiscard]] std::string_view display() const noexcept
    {
        return {displayBytes.data(), displayLength};
    }
};

// Read-only no-config desktop targeting from the same trusted native evidence
// boundary used by R2. No DISPLAY environment or GUI text is accepted.
[[nodiscard]] LinuxCurrentX11DesktopSelection
selectCurrentPhysicalX11Desktop(ConsoleOsEvidenceSource &source) noexcept;

enum class LinuxLogindObservationFailure : std::uint8_t
{
    None,
    SystemdUnavailable,
    GraphicalSeatUnavailable,
    ActiveSessionUnavailable,
    SessionMetadataUnavailable,
    SessionMetadataInvalid,
    SessionChangedDuringSample,
    ClockUnavailable,
    ProcessUidUnavailable,
};

[[nodiscard]] constexpr std::string_view linuxLogindObservationFailureName(
    LinuxLogindObservationFailure failure) noexcept
{
    using Failure = LinuxLogindObservationFailure;
    switch (failure)
    {
    case Failure::None: return "none";
    case Failure::SystemdUnavailable: return "systemd-unavailable";
    case Failure::GraphicalSeatUnavailable: return "graphical-seat-unavailable";
    case Failure::ActiveSessionUnavailable: return "active-session-unavailable";
    case Failure::SessionMetadataUnavailable: return "session-metadata-unavailable";
    case Failure::SessionMetadataInvalid: return "session-metadata-invalid";
    case Failure::SessionChangedDuringSample: return "session-changed-during-sample";
    case Failure::ClockUnavailable: return "clock-unavailable";
    case Failure::ProcessUidUnavailable: return "process-uid-unavailable";
    }
    return "session-metadata-unavailable";
}

// Bounded non-authorizing diagnostics for physical acceptance. Raw account
// names and raw logind session identifiers are intentionally absent.
struct LinuxLogindObservationDiagnostics final
{
    bool sampleAttempted{};
    bool systemdAvailable{};
    bool graphicalSeatAvailable{};
    bool activeSessionFound{};
    std::array<char, 17> sessionTypeBytes{};
    std::array<char, 33> sessionClassBytes{};
    std::array<char, 17> seatBytes{};
    std::array<char, 9> displayBytes{};
    std::size_t sessionTypeLength{};
    std::size_t sessionClassLength{};
    std::size_t seatLength{};
    std::size_t displayLength{};
    bool active{};
    bool remote{};
    ConsoleDesktopLockState lockState{ConsoleDesktopLockState::Unknown};
    bool processUidMatchesOwnerUid{};
    bool sessionGenerationStable{};
    // Native logind lifecycle generation, not a raw session identifier.
    std::uint64_t sessionGeneration{};
    LinuxLogindObservationFailure failure{
        LinuxLogindObservationFailure::SystemdUnavailable};

    [[nodiscard]] std::string_view sessionType() const noexcept
    {
        return {sessionTypeBytes.data(), sessionTypeLength};
    }
    [[nodiscard]] std::string_view sessionClass() const noexcept
    {
        return {sessionClassBytes.data(), sessionClassLength};
    }
    [[nodiscard]] std::string_view seat() const noexcept
    {
        return {seatBytes.data(), seatLength};
    }
    [[nodiscard]] std::string_view display() const noexcept
    {
        return {displayBytes.data(), displayLength};
    }
};

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

    [[nodiscard]] const LinuxLogindObservationDiagnostics&
    diagnostics() const noexcept
    {
        return diagnostics_;
    }

private:
    LinuxNssReadOnlyEvidenceSource accountSource_{};
    std::array<char, 65> sessionIdBytes_{};
    std::array<char, 9> displayBytes_{};
    LinuxLogindObservationDiagnostics diagnostics_{};
};

} // namespace rdp_server::server::security
