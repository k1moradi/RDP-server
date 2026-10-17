// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows_native_session_evidence.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <ntsecapi.h>
#include <wtsapi32.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

namespace rdp_server::server::security
{
namespace
{

class OwnedHandle final
{
public:
    explicit OwnedHandle(HANDLE handle = nullptr) noexcept : handle_(handle) {}
    ~OwnedHandle()
    {
        if (handle_ != nullptr)
        {
            (void)::CloseHandle(handle_);
        }
    }
    OwnedHandle(const OwnedHandle &) = delete;
    OwnedHandle &operator=(const OwnedHandle &) = delete;

    [[nodiscard]] HANDLE get() const noexcept { return handle_; }

private:
    HANDLE handle_{};
};

class LsaBuffer final
{
public:
    explicit LsaBuffer(
        PSECURITY_LOGON_SESSION_DATA data = nullptr) noexcept : data_(data) {}
    ~LsaBuffer()
    {
        if (data_ != nullptr)
        {
            (void)::LsaFreeReturnBuffer(data_);
        }
    }
    LsaBuffer(const LsaBuffer &) = delete;
    LsaBuffer &operator=(const LsaBuffer &) = delete;

    [[nodiscard]] PSECURITY_LOGON_SESSION_DATA get() const noexcept
    {
        return data_;
    }

private:
    PSECURITY_LOGON_SESSION_DATA data_{};
};

template <typename Value>
[[nodiscard]] bool readWtsScalar(
    DWORD sessionId, WTS_INFO_CLASS informationClass,
    Value &value) noexcept
{
    LPWSTR raw = nullptr;
    DWORD bytes = 0;
    if (!::WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE, sessionId, informationClass,
            &raw, &bytes))
    {
        return false;
    }

    const bool valid = raw != nullptr && bytes == sizeof(Value);
    if (valid)
    {
        std::memcpy(&value, raw, sizeof(Value));
    }
    if (raw != nullptr)
    {
        ::WTSFreeMemory(raw);
    }
    return valid;
}

[[nodiscard]] bool supportedInteractiveLogonType(ULONG logonType) noexcept
{
    return logonType == Interactive || logonType == CachedInteractive;
}

} // namespace

bool WindowsNativeSessionEvidence::matchesAuthenticatedSid(
    std::span<const std::byte> authenticatedSid) const noexcept
{
    return userSidBytes != 0 &&
           userSidBytes <= userSid.size() &&
           authenticatedSid.size() == userSidBytes &&
           std::equal(
               authenticatedSid.begin(), authenticatedSid.end(),
               userSid.begin());
}

bool WindowsNativeSessionEvidence::sameNativeSession(
    const WindowsNativeSessionEvidence &other) const noexcept
{
    return userSidBytes != 0 &&
           userSidBytes == other.userSidBytes &&
           std::equal(
               userSid.begin(), userSid.begin() + userSidBytes,
               other.userSid.begin()) &&
           sessionId == other.sessionId &&
           authenticationIdLow == other.authenticationIdLow &&
           authenticationIdHigh == other.authenticationIdHigh &&
           logonTime100Nanoseconds == other.logonTime100Nanoseconds &&
           logonType == other.logonType;
}

WindowsNativeSessionEvidenceStatus
WindowsNativeSessionEvidenceReader::readCurrent(
    WindowsNativeSessionEvidence &evidence) const noexcept
{
    evidence = {};

    HANDLE rawToken = nullptr;
    if (!::OpenProcessToken(
            ::GetCurrentProcess(), TOKEN_QUERY, &rawToken))
    {
        return WindowsNativeSessionEvidenceStatus::Unavailable;
    }
    OwnedHandle token{rawToken};

    DWORD processSessionId = 0;
    if (!::ProcessIdToSessionId(
            ::GetCurrentProcessId(), &processSessionId) ||
        processSessionId == 0 ||
        processSessionId == std::numeric_limits<DWORD>::max())
    {
        return WindowsNativeSessionEvidenceStatus::Unavailable;
    }

    DWORD tokenSessionId = 0;
    DWORD returnedBytes = 0;
    if (!::GetTokenInformation(
            token.get(), TokenSessionId, &tokenSessionId,
            sizeof(tokenSessionId), &returnedBytes) ||
        returnedBytes != sizeof(tokenSessionId) ||
        tokenSessionId != processSessionId)
    {
        return WindowsNativeSessionEvidenceStatus::Unavailable;
    }

    TOKEN_STATISTICS statistics{};
    returnedBytes = 0;
    if (!::GetTokenInformation(
            token.get(), TokenStatistics, &statistics,
            sizeof(statistics), &returnedBytes) ||
        returnedBytes != sizeof(statistics) ||
        statistics.TokenType != TokenPrimary)
    {
        return WindowsNativeSessionEvidenceStatus::Unavailable;
    }

    static_assert(
        kMaximumWindowsNativeSidBytes >= SECURITY_MAX_SID_SIZE);
    alignas(TOKEN_USER)
        std::array<std::byte, sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE>
            userBuffer{};
    returnedBytes = 0;
    if (!::GetTokenInformation(
            token.get(), TokenUser, userBuffer.data(),
            static_cast<DWORD>(userBuffer.size()), &returnedBytes) ||
        returnedBytes > userBuffer.size())
    {
        return WindowsNativeSessionEvidenceStatus::Unavailable;
    }

    const auto *const tokenUser =
        reinterpret_cast<const TOKEN_USER *>(userBuffer.data());
    if (tokenUser->User.Sid == nullptr ||
        !::IsValidSid(tokenUser->User.Sid))
    {
        return WindowsNativeSessionEvidenceStatus::Unavailable;
    }
    const DWORD sidBytes = ::GetLengthSid(tokenUser->User.Sid);
    if (sidBytes == 0 || sidBytes > evidence.userSid.size())
    {
        return WindowsNativeSessionEvidenceStatus::Unavailable;
    }

    PSECURITY_LOGON_SESSION_DATA rawLogon = nullptr;
    const NTSTATUS lsaStatus =
        ::LsaGetLogonSessionData(
            &statistics.AuthenticationId, &rawLogon);
    LsaBuffer logon{rawLogon};
    if (lsaStatus != 0 || logon.get() == nullptr ||
        logon.get()->Sid == nullptr ||
        !::IsValidSid(logon.get()->Sid) ||
        !::EqualSid(tokenUser->User.Sid, logon.get()->Sid) ||
        logon.get()->Session != processSessionId ||
        !supportedInteractiveLogonType(logon.get()->LogonType) ||
        logon.get()->LogonTime.QuadPart <= 0)
    {
        return WindowsNativeSessionEvidenceStatus::Unavailable;
    }

    WTS_CONNECTSTATE_CLASS state = WTSInit;
    USHORT protocolType = std::numeric_limits<USHORT>::max();
    if (!readWtsScalar(
            processSessionId, WTSConnectState, state) ||
        state != WTSActive ||
        !readWtsScalar(
            processSessionId, WTSClientProtocolType, protocolType) ||
        protocolType != 0)
    {
        return WindowsNativeSessionEvidenceStatus::Unavailable;
    }

    if (!::CopySid(
            static_cast<DWORD>(evidence.userSid.size()),
            evidence.userSid.data(), tokenUser->User.Sid))
    {
        evidence = {};
        return WindowsNativeSessionEvidenceStatus::Unavailable;
    }

    evidence.userSidBytes = sidBytes;
    evidence.sessionId = static_cast<std::uint32_t>(processSessionId);
    evidence.authenticationIdLow =
        statistics.AuthenticationId.LowPart;
    evidence.authenticationIdHigh =
        statistics.AuthenticationId.HighPart;
    evidence.logonTime100Nanoseconds =
        logon.get()->LogonTime.QuadPart;
    evidence.logonType =
        static_cast<std::uint32_t>(logon.get()->LogonType);
    return WindowsNativeSessionEvidenceStatus::Observed;
}

} // namespace rdp_server::server::security
