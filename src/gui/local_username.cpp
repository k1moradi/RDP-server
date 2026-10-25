// SPDX-License-Identifier: GPL-3.0-or-later
#include "local_username.h"

#include <QtGlobal>

#include <array>
#include <cstddef>
#include <memory>

#if defined(Q_OS_WIN)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wtsapi32.h>
#elif defined(Q_OS_MACOS)
#include <SystemConfiguration/SystemConfiguration.h>
#include <sys/types.h>
#elif defined(Q_OS_LINUX)
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace rdp::gui
{
namespace
{

[[nodiscard]] bool isRejectedSystemName(const QString& foldedName)
{
    constexpr std::array rejectedNames{
        "root", "system", "localsystem", "local service", "network service",
        "daemon", "nobody", "bin", "sys", "sync", "games", "man", "lp",
        "mail", "news", "uucp", "proxy", "backup", "list", "irc", "gnats",
        "www-data", "loginwindow", "defaultaccount", "wdagutilityaccount"};
    for (const char* rejected : rejectedNames)
    {
        if (foldedName == QLatin1StringView(rejected))
            return true;
    }
    return false;
}

#if defined(Q_OS_WIN)
struct WtsMemoryDeleter
{
    void operator()(wchar_t* memory) const noexcept
    {
        if (memory != nullptr)
            WTSFreeMemory(memory);
    }
};
#elif defined(Q_OS_MACOS)
class ScopedConsoleUser final
{
public:
    explicit ScopedConsoleUser(CFStringRef value) noexcept : value_(value) {}
    ~ScopedConsoleUser()
    {
        if (value_ != nullptr)
            CFRelease(value_);
    }

    ScopedConsoleUser(const ScopedConsoleUser&) = delete;
    ScopedConsoleUser& operator=(const ScopedConsoleUser&) = delete;

    [[nodiscard]] CFStringRef get() const noexcept { return value_; }

private:
    CFStringRef value_{};
};
#endif

} // namespace

bool isSafeLocalUsernameSuggestion(const QStringView username)
{
    if (username.isEmpty() || username.size() > 256)
        return false;

    const QString candidate = username.toString();
    if (candidate != candidate.trimmed() ||
        candidate.startsWith(QLatin1Char('_')) ||
        candidate.endsWith(QLatin1Char('$')))
    {
        return false;
    }

    for (const QChar codeUnit : candidate)
    {
        const auto category = codeUnit.category();
        if (codeUnit == QLatin1Char('/') || codeUnit == QLatin1Char('\\') ||
            category == QChar::Other_Control ||
            category == QChar::Other_Surrogate ||
            category == QChar::Other_NotAssigned)
        {
            return false;
        }
    }

    return !isRejectedSystemName(candidate.toCaseFolded());
}

QString currentLocalUsernameSuggestion()
{
#if defined(Q_OS_WIN)
    DWORD sessionId = 0U;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &sessionId) ||
        sessionId == 0U)
    {
        return {};
    }

    LPWSTR rawUsername = nullptr;
    DWORD byteCount = 0U;
    if (!WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            sessionId,
            WTSUserName,
            &rawUsername,
            &byteCount) ||
        rawUsername == nullptr)
    {
        return {};
    }
    std::unique_ptr<wchar_t, WtsMemoryDeleter> usernameOwner(rawUsername);

    const std::size_t maximumCodeUnits =
        static_cast<std::size_t>(byteCount) / sizeof(wchar_t);
    std::size_t codeUnitCount = 0U;
    while (codeUnitCount < maximumCodeUnits &&
           rawUsername[codeUnitCount] != L'\0')
    {
        ++codeUnitCount;
    }
    if (codeUnitCount == 0U || codeUnitCount > 256U)
        return {};

    const QString candidate = QString::fromWCharArray(
        rawUsername, static_cast<qsizetype>(codeUnitCount));
    return isSafeLocalUsernameSuggestion(candidate) ? candidate : QString{};

#elif defined(Q_OS_MACOS)
    uid_t userId = 0;
    gid_t groupId = 0;
    ScopedConsoleUser consoleUser(
        SCDynamicStoreCopyConsoleUser(nullptr, &userId, &groupId));
    if (consoleUser.get() == nullptr || userId == 0)
        return {};

    std::array<char, 4096> utf8Username{};
    if (!CFStringGetCString(
            consoleUser.get(),
            utf8Username.data(),
            static_cast<CFIndex>(utf8Username.size()),
            kCFStringEncodingUTF8))
    {
        return {};
    }

    const QString candidate = QString::fromUtf8(utf8Username.data());
    return isSafeLocalUsernameSuggestion(candidate) ? candidate : QString{};

#elif defined(Q_OS_LINUX)
    const uid_t userId = geteuid();
    if (userId == 0)
        return {};

    passwd passwordRecord{};
    passwd* record = nullptr;
    std::array<char, 16384> storage{};
    if (getpwuid_r(
            userId,
            &passwordRecord,
            storage.data(),
            storage.size(),
            &record) != 0 ||
        record != &passwordRecord ||
        passwordRecord.pw_name == nullptr)
    {
        return {};
    }

    const QString candidate = QString::fromLocal8Bit(passwordRecord.pw_name);
    if (!isSafeLocalUsernameSuggestion(candidate))
        return {};

    if (passwordRecord.pw_shell != nullptr)
    {
        const QString shell = QString::fromLocal8Bit(passwordRecord.pw_shell);
        if (shell.endsWith(QStringLiteral("/nologin")) ||
            shell.endsWith(QStringLiteral("/false")))
        {
            return {};
        }
    }

    if (passwordRecord.pw_dir != nullptr)
    {
        const QString home = QString::fromLocal8Bit(passwordRecord.pw_dir);
        if (home == QStringLiteral("/nonexistent") ||
            home == QStringLiteral("/var/empty"))
        {
            return {};
        }
    }

    return candidate;
#else
    return {};
#endif
}

} // namespace rdp::gui
