// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_nss_console_evidence.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <pwd.h>
#include <string_view>
#include <time.h>
#include <utility>

namespace rdp_server::server::security
{
namespace
{

inline constexpr std::size_t kMaximumUnixAccountLength = 32;
inline constexpr std::size_t kNssLookupBufferBytes = 16 * 1024;

[[nodiscard]] bool validUnixAccount(std::string_view account) noexcept
{
    // Mirror M1.14's conservative account grammar before invoking NSS.
    // Reject NUL (including embedded NUL), control bytes and aliases;
    // never allow a caller-supplied account to be silently truncated.
    if (account.empty() || account.size() > kMaximumUnixAccountLength ||
        account == "root" ||
        ((account.front() < 'a' || account.front() > 'z') &&
         account.front() != '_'))
    {
        return false;
    }

    for (const char character : account)
    {
        if ((character < 'a' || character > 'z') &&
            (character < '0' || character > '9') &&
            character != '_' && character != '-')
        {
            return false;
        }
    }
    return true;
}

} // namespace

ConsoleAccountObservation LinuxNssReadOnlyEvidenceSource::readUnixAccount(
    std::string_view account) noexcept
{
    if (!validUnixAccount(account))
    {
        return {};
    }

    // Fixed, bounded stack buffers: no heap allocation, no implicit getpwnam
    // static storage and no unbounded retry when an NSS backend returns ERANGE.
    std::array<char, kMaximumUnixAccountLength + 1> accountName{};
    std::copy(account.begin(), account.end(), accountName.begin());
    std::array<char, kNssLookupBufferBytes> lookupBuffer;
    passwd accountRecord{};
    passwd *resolvedAccount = nullptr;

    const int errorCode = ::getpwnam_r(
        accountName.data(), &accountRecord,
        lookupBuffer.data(), lookupBuffer.size(), &resolvedAccount);
    if (errorCode != 0 || resolvedAccount != &accountRecord ||
        accountRecord.pw_name == nullptr ||
        !std::in_range<std::uint32_t>(accountRecord.pw_uid) ||
        accountRecord.pw_uid == 0 ||
        accountRecord.pw_uid == std::numeric_limits<std::uint32_t>::max())
    {
        return {};
    }

    // A successful NSS response must preserve the exact requested spelling.
    // Do not accept aliases, case folding, or canonicalization as identity.
    if (std::strcmp(accountRecord.pw_name, accountName.data()) != 0)
    {
        return {ConsoleEvidenceReadStatus::Conflicting, {}, 0};
    }
    return {ConsoleEvidenceReadStatus::Observed, account,
            static_cast<std::uint32_t>(accountRecord.pw_uid)};
}

ConsoleSessionObservation
LinuxNssReadOnlyEvidenceSource::readActiveConsole() noexcept
{
    // No authoritative logind session ID, owner, seat, display, lifecycle
    // generation or freshness observation exists in this adapter.
    // It is unsafe to infer these fields from environment variables,
    // /tmp/.X11-unix, login records, a process UID or the NSS account.
    return {};
}

std::optional<std::uint64_t>
LinuxNssReadOnlyEvidenceSource::readMonotonicMilliseconds() noexcept
{
    timespec monotonicTime{};
    if (::clock_gettime(CLOCK_MONOTONIC, &monotonicTime) != 0 ||
        monotonicTime.tv_sec < 0 ||
        monotonicTime.tv_nsec < 0 ||
        monotonicTime.tv_nsec >= 1000000000L)
    {
        return std::nullopt;
    }

    constexpr std::uint64_t kMillisecondsPerSecond = 1000;
    constexpr std::uint64_t kNanosecondsPerMillisecond = 1000000;
    const auto seconds = static_cast<std::uint64_t>(monotonicTime.tv_sec);
    const auto fractionalMilliseconds =
        static_cast<std::uint64_t>(monotonicTime.tv_nsec) /
        kNanosecondsPerMillisecond;
    if (seconds > (std::numeric_limits<std::uint64_t>::max() -
                   fractionalMilliseconds) / kMillisecondsPerSecond)
    {
        return std::nullopt;
    }

    return seconds * kMillisecondsPerSecond + fractionalMilliseconds;
}

} // namespace rdp_server::server::security
