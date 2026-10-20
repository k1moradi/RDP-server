// SPDX-License-Identifier: GPL-3.0-or-later
#include "console_identity_policy.h"

#include <algorithm>
#include <limits>
#include <string_view>

namespace rdp_server::server::security
{
namespace
{

[[nodiscard]] constexpr bool asciiAlpha(char c) noexcept
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

[[nodiscard]] constexpr bool asciiDigit(char c) noexcept
{
    return c >= '0' && c <= '9';
}

[[nodiscard]] bool validPrincipal(std::string_view value) noexcept
{
    // Exact, case-sensitive user principal, no wildcard or DNS/realm
    // canonicalization. Service TERMSRV/* identities cannot impersonate
    // an end user; the system GSS provider owns the authenticated name.
    if (value.size() < 3 || value.size() > 128 ||
        value.starts_with("TERMSRV/"))
    {
        return false;
    }
    const auto at = value.find('@');
    if (at == 0 || at == value.npos || at + 1 == value.size() ||
        value.find('@', at + 1) != value.npos)
    {
        return false;
    }
    if (!asciiAlpha(value[0]) && !asciiDigit(value[0]))
    {
        return false;
    }
    for (std::size_t i = 0; i < value.size(); ++i)
    {
        const char c = value[i];
        if (i == at)
        {
            continue;
        }
        if (i < at)
        {
            if (!asciiAlpha(c) && !asciiDigit(c) &&
                c != '.' && c != '_' && c != '-')
            {
                return false;
            }
        }
        else if (!(c >= 'A' && c <= 'Z') &&
                 !asciiDigit(c) && c != '.' && c != '-')
        {
            return false;
        }
    }
    return value[at - 1] != '.' && value[at + 1] != '.' &&
           value.back() != '.' && value.back() != '-';
}

[[nodiscard]] bool validAccount(std::string_view value) noexcept
{
    if (value.empty() || value.size() > 32 || value == "root" ||
        ((value[0] < 'a' || value[0] > 'z') && value[0] != '_'))
    {
        return false;
    }
    for (const char c : value)
    {
        if ((c < 'a' || c > 'z') && !asciiDigit(c) &&
            c != '_' && c != '-')
        {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool validSeat(std::string_view seat) noexcept
{
    // Current scope: one explicitly selected physical seat, no implicit
    // alternate virtual/Xvnc seats.
    return seat == "seat0";
}

[[nodiscard]] bool validDisplay(std::string_view display) noexcept
{
    if (display.size() < 2 || display.size() > 8 || display[0] != ':' ||
        (display.size() > 2 && display[1] == '0'))
    {
        return false;
    }
    for (std::size_t i = 1; i < display.size(); ++i)
    {
        if (!asciiDigit(display[i]))
        {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool validRule(const ConsoleIdentityRuleInput &rule) noexcept
{
    return validPrincipal(rule.kerberosPrincipal) &&
           validAccount(rule.unixAccount) &&
           validSeat(rule.seat) &&
           validDisplay(rule.display) &&
           rule.localUid != 0 && rule.localUid != 0xffffffffU &&
           (rule.permissions & kConsoleViewPermission) != 0 &&
           (rule.permissions & ~kConsoleAllowedPermissions) == 0;
}

template <std::size_t N>
void copyExact(std::array<char, N> &target,
               std::string_view text) noexcept
{
    // A local length bound is required even though add() validates every
    // field: the static archive is built at -O3 -Werror=array-bounds and
    // this helper must be independently memory-safe.
    std::size_t offset = 0;
    for (const char c : text)
    {
        if (offset + 1 >= target.size())
        {
            break;
        }
        target[offset++] = c;
    }
    target[offset] = '\0';
}

template <std::size_t N>
[[nodiscard]] std::string_view view(
    const std::array<char, N> &bytes) noexcept
{
    return std::string_view(bytes.data());
}

} // namespace

bool ConsoleIdentityPolicy::nextGeneration(
    std::uint64_t &next) const noexcept
{
    const std::uint64_t current =
        generation_.load(std::memory_order_relaxed);
    if (current == (std::numeric_limits<std::uint64_t>::max)())
    {
        next = 0;
        return false;
    }
    next = current + 1U;
    return next != 0;
}

void ConsoleIdentityPolicy::clearRules() noexcept
{
    rules_.fill(Rule{});
    count_ = 0;
}

ConsoleRuleError ConsoleIdentityPolicy::add(
    const ConsoleIdentityRuleInput &rule) noexcept
{
    if (!validRule(rule))
    {
        return ConsoleRuleError::InvalidRule;
    }
    for (std::size_t i = 0; i < count_; ++i)
    {
        const auto &existing = rules_[i];
        // Deny ambiguous/multiple mappings for a single Kerberos user at
        // one console, even when requested UID/permissions differ.
        if (view(existing.principal) == rule.kerberosPrincipal &&
            view(existing.seat) == rule.seat &&
            view(existing.display) == rule.display)
        {
            return ConsoleRuleError::Duplicate;
        }
    }
    if (count_ == rules_.size())
    {
        return ConsoleRuleError::Full;
    }

    std::uint64_t next = 0;
    if (!nextGeneration(next))
    {
        // Generation zero is terminal fail-closed state. Clearing the rules
        // prevents an unobservable identity mutation if the epoch exhausts.
        clearRules();
        generation_.store(0, std::memory_order_release);
        return ConsoleRuleError::GenerationExhausted;
    }

    Rule newRule{};
    copyExact(newRule.principal, rule.kerberosPrincipal);
    copyExact(newRule.account, rule.unixAccount);
    copyExact(newRule.seat, rule.seat);
    copyExact(newRule.display, rule.display);
    newRule.uid = rule.localUid;
    newRule.permissions = rule.permissions;
    rules_[count_++] = newRule;
    generation_.store(next, std::memory_order_release);
    return ConsoleRuleError::None;
}

ConsoleRuleError ConsoleIdentityPolicy::replaceSingle(
    const ConsoleIdentityRuleInput &rule) noexcept
{
    if (!validRule(rule))
    {
        return ConsoleRuleError::InvalidRule;
    }

    std::uint64_t next = 0;
    if (!nextGeneration(next))
    {
        clearRules();
        generation_.store(0, std::memory_order_release);
        return ConsoleRuleError::GenerationExhausted;
    }

    Rule newRule{};
    copyExact(newRule.principal, rule.kerberosPrincipal);
    copyExact(newRule.account, rule.unixAccount);
    copyExact(newRule.seat, rule.seat);
    copyExact(newRule.display, rule.display);
    newRule.uid = rule.localUid;
    newRule.permissions = rule.permissions;

    // Publish the epoch only after the replacement bytes are complete.
    // External serialization prevents concurrent rule readers while this
    // mutation is in progress; generation is the cross-owner revocation fence.
    clearRules();
    rules_[0] = newRule;
    count_ = 1U;
    generation_.store(next, std::memory_order_release);
    return ConsoleRuleError::None;
}

bool ConsoleIdentityPolicy::revokeAll() noexcept
{
    std::uint64_t next = 0;
    if (!nextGeneration(next))
    {
        clearRules();
        generation_.store(0, std::memory_order_release);
        return false;
    }

    clearRules();
    generation_.store(next, std::memory_order_release);
    return true;
}

ConsolePolicyMatch ConsoleIdentityPolicy::matchCandidate(
    const ConsoleIdentityRequest &request) const noexcept
{
    if (!validPrincipal(request.kerberosPrincipal) ||
        !validAccount(request.unixAccount) ||
        !validSeat(request.seat) ||
        !validDisplay(request.display) ||
        request.localUid == 0 ||
        request.localUid != request.observedConsoleOwnerUid ||
        request.requestedPermissions == 0 ||
        (request.requestedPermissions & ~kConsoleAllowedPermissions) != 0)
    {
        return ConsolePolicyMatch::Denied;
    }
    for (std::size_t i = 0; i < count_; ++i)
    {
        const auto &rule = rules_[i];
        if (view(rule.principal) == request.kerberosPrincipal &&
            view(rule.account) == request.unixAccount &&
            view(rule.seat) == request.seat &&
            view(rule.display) == request.display &&
            rule.uid == request.localUid &&
            (rule.permissions & request.requestedPermissions) ==
                request.requestedPermissions)
        {
            return ConsolePolicyMatch::CandidateOnly;
        }
    }
    return ConsolePolicyMatch::Denied;
}

ConsolePolicyMatch ConsoleIdentityPolicy::matchNativeAccountCandidate(
    std::string_view unixAccount,
    std::string_view seat,
    std::string_view display,
    std::uint32_t localUid,
    std::uint32_t observedConsoleOwnerUid,
    std::uint32_t requestedPermissions) const noexcept
{
    if (!validAccount(unixAccount) ||
        !validSeat(seat) ||
        !validDisplay(display) ||
        localUid == 0 ||
        localUid != observedConsoleOwnerUid ||
        requestedPermissions == 0 ||
        (requestedPermissions & ~kConsoleAllowedPermissions) != 0)
    {
        return ConsolePolicyMatch::Denied;
    }

    for (std::size_t index = 0; index < count_; ++index)
    {
        const auto &rule = rules_[index];
        if (view(rule.account) == unixAccount &&
            view(rule.seat) == seat &&
            view(rule.display) == display &&
            rule.uid == localUid &&
            (rule.permissions & requestedPermissions) ==
                requestedPermissions)
        {
            return ConsolePolicyMatch::CandidateOnly;
        }
    }
    return ConsolePolicyMatch::Denied;
}

ConsolePolicyMatch ConsoleIdentityPolicy::matchPrincipalAccountCandidate(
    std::string_view kerberosPrincipal,
    std::string_view unixAccount,
    std::uint64_t expectedGeneration) const noexcept
{
    if (expectedGeneration == 0 || generation() != expectedGeneration ||
        !validPrincipal(kerberosPrincipal) || !validAccount(unixAccount))
    {
        return ConsolePolicyMatch::Denied;
    }

    bool found = false;
    std::string_view configuredAccount;
    for (std::size_t index = 0; index < count_; ++index)
    {
        const auto &rule = rules_[index];
        if (view(rule.principal) != kerberosPrincipal)
        {
            continue;
        }
        const std::string_view account = view(rule.account);
        if (!found)
        {
            configuredAccount = account;
            found = true;
        }
        else if (account != configuredAccount)
        {
            return ConsolePolicyMatch::Denied;
        }
    }

    if (!found || configuredAccount != unixAccount)
    {
        return ConsolePolicyMatch::Denied;
    }
    return generation() == expectedGeneration
        ? ConsolePolicyMatch::CandidateOnly
        : ConsolePolicyMatch::Denied;
}

} // namespace rdp_server::server::security
