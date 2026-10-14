// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "console_os_evidence.h"

#include <cstdint>
#include <mutex>
#include <optional>

namespace rdp_server::server::security
{

// A process-local correlation number for a pending *candidate evaluation*.
// NOT unpredictable, cryptographically authenticated, or an access token.
struct ConsoleProviderOperationTicket
{
    std::uint64_t value{};
};

enum class ConsoleProviderOperationState : std::uint8_t
{
    NotStarted,
    Pending,
    CandidateOnly, // Evidence was consistent; NEVER desktop permission.
    Abandoned,     // Terminal: timeout, invalid reply, cancel or fault.
};

// Thread-safe, single-use RESULT QUARANTINE for an eventual provider
// operation. This class never calls NSS/logind, starts a worker, controls
// a process, issues a session handle, or grants any channel permission.
// It only rejects late, foreign, malformed and cancelled results.
//
// All timestamps are CALLER-SUPPLIED CLOCK_MONOTONIC milliseconds.
// A deadline is enforced only when expireAt() or complete() is invoked.
// An unresponsive provider is NOT forcibly interrupted: a separate
// execution-isolation mechanism must own its lifetime and resources.
// Each method locks a short in-process mutex; never execute callbacks
// or a blocking provider inside this object's critical section.
class ConsoleProviderOperationQuarantine final
{
public:
    ConsoleProviderOperationQuarantine() noexcept = default;
    ConsoleProviderOperationQuarantine(
        const ConsoleProviderOperationQuarantine &) = delete;
    ConsoleProviderOperationQuarantine &operator=(
        const ConsoleProviderOperationQuarantine &) = delete;

    inline static constexpr std::uint64_t kMaximumBudgetMilliseconds = 2000;

    // Exactly one begin per instance. Zero/overflow/nonpositive budget
    // refuses and irreversibly abandons the operation.
    [[nodiscard]] std::optional<ConsoleProviderOperationTicket> begin(
        std::uint64_t monotonicNowMilliseconds,
        std::uint64_t budgetMilliseconds) noexcept;

    // A candidate reply may be accepted only from this exact ticket,
    // within [start, deadline) and only while Pending. Denied replies
    // abandon immediately. A late response can NEVER reopen it.
    [[nodiscard]] ConsoleProviderOperationState complete(
        ConsoleProviderOperationTicket ticket,
        ConsoleEvidenceMatch evidenceResult,
        std::uint64_t monotonicNowMilliseconds) noexcept;

    // Owner-driven deadline check; not a timer or scheduled callback.
    [[nodiscard]] ConsoleProviderOperationState expireAt(
        std::uint64_t monotonicNowMilliseconds) noexcept;

    void cancel() noexcept;

    [[nodiscard]] ConsoleProviderOperationState state() const noexcept;

private:
    mutable std::mutex mutex_{};
    std::uint64_t ticket_{};
    std::uint64_t startedAt_{};
    std::uint64_t deadline_{};
    ConsoleProviderOperationState state_{ConsoleProviderOperationState::NotStarted};
};

} // namespace rdp_server::server::security
