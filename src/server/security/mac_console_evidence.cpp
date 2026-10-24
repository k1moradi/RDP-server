// SPDX-License-Identifier: GPL-3.0-or-later
#include "mac_console_evidence.h"

#if defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#endif
#include <pwd.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <limits>

namespace rdp_server::server::security
{

namespace
{
#if defined(__APPLE__)
struct DictionaryOwner final
{
    CFDictionaryRef dict_{};
    explicit DictionaryOwner(CFDictionaryRef d) noexcept : dict_(d) {}
    ~DictionaryOwner() noexcept
    {
        if (dict_ != nullptr)
            ::CFRelease(dict_);
    }
    DictionaryOwner(const DictionaryOwner&) = delete;
    DictionaryOwner& operator=(const DictionaryOwner&) = delete;
    [[nodiscard]] CFDictionaryRef get() const noexcept { return dict_; }
};

[[nodiscard]] bool readBoolFromDict(
    CFDictionaryRef dict, CFStringRef key, bool& out) noexcept
{
    const auto* val = ::CFDictionaryGetValue(dict, key);
    if (val == nullptr || ::CFGetTypeID(static_cast<CFTypeRef>(val)) != ::CFBooleanGetTypeID())
        return false;
    out = ::CFBooleanGetValue(static_cast<CFBooleanRef>(val));
    return true;
}
#endif
} // namespace

MacConsoleOsEvidenceSource::MacConsoleOsEvidenceSource() noexcept
    : nativeEvidence_(&defaultNativeEvidence_)
{
}

MacConsoleOsEvidenceSource::MacConsoleOsEvidenceSource(
    MacNativeSessionEvidenceSource& nativeEvidence) noexcept
    : nativeEvidence_(&nativeEvidence)
{
}

ConsoleAccountObservation MacConsoleOsEvidenceSource::readUnixAccount(
    std::string_view account) noexcept
{
    if (account.empty() || account.size() >= accountBuffer_.size())
        return {};
    std::array<char, 256> nullTerminated{};
    std::memcpy(nullTerminated.data(), account.data(), account.size());
    nullTerminated[account.size()] = '\0';

    const passwd* pw = ::getpwnam(nullTerminated.data());
    if (pw == nullptr || pw->pw_name == nullptr)
        return {};

    const std::size_t nameLen = std::strlen(pw->pw_name);
    if (nameLen == 0 || nameLen >= accountBuffer_.size())
        return {};
    std::memcpy(accountBuffer_.data(), pw->pw_name, nameLen);
    accountBuffer_[nameLen] = '\0';

    ConsoleAccountObservation obs;
    obs.status = ConsoleEvidenceReadStatus::Observed;
    obs.unixAccount = std::string_view(accountBuffer_.data(), nameLen);
    obs.uid = static_cast<std::uint32_t>(pw->pw_uid);
    return obs;
}

ConsoleSessionObservation MacConsoleOsEvidenceSource::readActiveConsole() noexcept
{
    const auto maybeNow = readMonotonicMilliseconds();
    if (!maybeNow.has_value() || nativeEvidence_ == nullptr)
        return {};

    MacNativeSessionEvidence nativeEv{};
    if (nativeEvidence_->readCurrent(nativeEv) != MacNativeSessionEvidenceStatus::Observed)
        return {};

    if (nativeEv.consoleUserId == 0 ||
        nativeEv.consoleUserId == static_cast<std::uint32_t>(-1) ||
        nativeEv.consoleUserBytes == 0)
        return {};

    const uid_t effectiveUid = ::geteuid();
    if (static_cast<std::uint32_t>(effectiveUid) != nativeEv.consoleUserId)
        return {};

    bool onConsole = true;
    bool loginDone = true;
#if defined(__APPLE__)
    DictionaryOwner sessionDict(::CGSessionCopyCurrentDictionary());
    if (sessionDict.get() != nullptr)
    {
        (void)readBoolFromDict(sessionDict.get(), kCGSessionOnConsoleKey, onConsole);
        (void)readBoolFromDict(sessionDict.get(), kCGSessionLoginDoneKey, loginDone);
    }
#endif

    const std::uint64_t sessionGen = nativeEv.auditSessionId != 0
        ? nativeEv.auditSessionId
        : (nativeEv.securitySessionId != 0
            ? static_cast<std::uint64_t>(nativeEv.securitySessionId)
            : 1U);

    const int written = std::snprintf(
        sessionIdBuffer_.data(), sessionIdBuffer_.size(),
        "mac-%u-%llu",
        nativeEv.consoleUserId,
        static_cast<unsigned long long>(sessionGen));
    if (written <= 0 || static_cast<std::size_t>(written) >= sessionIdBuffer_.size())
        return {};

    ConsoleSessionObservation obs;
    obs.status = ConsoleEvidenceReadStatus::Observed;
    obs.sessionId = std::string_view(sessionIdBuffer_.data(), static_cast<std::size_t>(written));
    obs.seat = "seat0";
    obs.display = ":0";
    obs.ownerUid = nativeEv.consoleUserId;
    obs.sessionGeneration = sessionGen;
    obs.observedAtMonotonicMilliseconds = *maybeNow;
    obs.active = onConsole;
    obs.physical = true;
    obs.localProcessUid = static_cast<std::uint32_t>(effectiveUid);
    obs.lockState = (onConsole && loginDone)
        ? ConsoleDesktopLockState::Unlocked
        : ConsoleDesktopLockState::Locked;
    obs.remote = false;
    return obs;
}

std::optional<std::uint64_t>
MacConsoleOsEvidenceSource::readMonotonicMilliseconds() noexcept
{
    const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    if (now < 0)
        return std::nullopt;
    return static_cast<std::uint64_t>(now);
}

} // namespace rdp_server::server::security
