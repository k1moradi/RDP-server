// SPDX-License-Identifier: GPL-3.0-or-later
#include "console_provider_operation_quarantine.h"

#include <atomic>
#include <limits>
#include <mutex>

namespace rdp_server::server::security
{
namespace
{

// Correlates replies across distinct guard instances. These sequential
// identifiers are NOT secrets or a substitute for source authentication.
// Overflow fails closed instead of wrapping to a previously issued ID.
std::atomic<std::uint64_t> nextTicket{0};

[[nodiscard]] std::uint64_t allocateTicket() noexcept
{
    std::uint64_t last = nextTicket.load(std::memory_order_relaxed);
    while (last != std::numeric_limits<std::uint64_t>::max())
    {
        if (nextTicket.compare_exchange_weak(
                last, last + 1, std::memory_order_relaxed,
                std::memory_order_relaxed))
        {
            return last + 1;
        }
    }
    return 0; // Permanently exhausted; NEVER wrap to a reused ticket.
}

} // namespace

std::optional<ConsoleProviderOperationTicket>
ConsoleProviderOperationQuarantine::begin(
    std::uint64_t monotonicNowMilliseconds,
    std::uint64_t budgetMilliseconds) noexcept
{
    const std::lock_guard lock(mutex_);
    if (state_ != ConsoleProviderOperationState::NotStarted)
    {
        // Starting a second provider request cannot refresh a candidate
        // or retry an abandoned result; revoke even if it was accepted.
        state_ = ConsoleProviderOperationState::Abandoned;
        return std::nullopt;
    }
    if (monotonicNowMilliseconds == 0 ||
        budgetMilliseconds == 0 ||
        budgetMilliseconds > kMaximumBudgetMilliseconds ||
        monotonicNowMilliseconds >
            std::numeric_limits<std::uint64_t>::max() - budgetMilliseconds)
    {
        state_ = ConsoleProviderOperationState::Abandoned;
        return std::nullopt;
    }

    const std::uint64_t ticket = allocateTicket();
    if (ticket == 0)
    {
        state_ = ConsoleProviderOperationState::Abandoned;
        return std::nullopt;
    }
    ticket_ = ticket;
    startedAt_ = monotonicNowMilliseconds;
    deadline_ = monotonicNowMilliseconds + budgetMilliseconds;
    state_ = ConsoleProviderOperationState::Pending;
    return ConsoleProviderOperationTicket{ticket};
}

ConsoleProviderOperationState ConsoleProviderOperationQuarantine::complete(
    ConsoleProviderOperationTicket ticket,
    ConsoleEvidenceMatch evidenceResult,
    std::uint64_t monotonicNowMilliseconds) noexcept
{
    const std::lock_guard lock(mutex_);
    if (state_ == ConsoleProviderOperationState::Abandoned)
    {
        return state_; // A cancelled/late reply is forever quarantined.
    }
    if (state_ != ConsoleProviderOperationState::Pending ||
        ticket.value == 0 || ticket.value != ticket_ ||
        monotonicNowMilliseconds < startedAt_ ||
        monotonicNowMilliseconds >= deadline_ ||
        evidenceResult != ConsoleEvidenceMatch::CandidateOnly)
    {
        state_ = ConsoleProviderOperationState::Abandoned;
        return state_;
    }
    state_ = ConsoleProviderOperationState::CandidateOnly;
    return state_;
}

ConsoleProviderOperationState ConsoleProviderOperationQuarantine::expireAt(
    std::uint64_t monotonicNowMilliseconds) noexcept
{
    const std::lock_guard lock(mutex_);
    if (state_ == ConsoleProviderOperationState::NotStarted ||
        state_ == ConsoleProviderOperationState::Pending)
    {
        if (state_ == ConsoleProviderOperationState::NotStarted ||
            monotonicNowMilliseconds < startedAt_ ||
            monotonicNowMilliseconds >= deadline_)
        {
            state_ = ConsoleProviderOperationState::Abandoned;
        }
    }
    return state_;
}

void ConsoleProviderOperationQuarantine::cancel() noexcept
{
    const std::lock_guard lock(mutex_);
    state_ = ConsoleProviderOperationState::Abandoned;
}

ConsoleProviderOperationState ConsoleProviderOperationQuarantine::state() const noexcept
{
    const std::lock_guard lock(mutex_);
    return state_;
}

} // namespace rdp_server::server::security
