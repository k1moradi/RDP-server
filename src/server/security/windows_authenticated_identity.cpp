// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows_authenticated_identity.h"

#if defined(_WIN32)

#include <algorithm>
#include <array>
#include <limits>
#include <utility>

namespace rdp_server::server::security
{
namespace
{

[[nodiscard]] bool readTokenSid(
    HANDLE token,
    std::array<std::byte, kMaximumWindowsNativeSidBytes> &sid,
    std::size_t &sidBytes) noexcept
{
    sid.fill(std::byte{0});
    sidBytes = 0;
    if (token == nullptr || token == INVALID_HANDLE_VALUE)
        return false;

    static_assert(
        kMaximumWindowsNativeSidBytes >= SECURITY_MAX_SID_SIZE);
    alignas(TOKEN_USER)
        std::array<std::byte, sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE>
            userBuffer{};

    DWORD returnedBytes = 0;
    if (!::GetTokenInformation(
            token, TokenUser, userBuffer.data(),
            static_cast<DWORD>(userBuffer.size()), &returnedBytes) ||
        returnedBytes < sizeof(TOKEN_USER) ||
        returnedBytes > userBuffer.size())
    {
        return false;
    }

    const auto *const user =
        reinterpret_cast<const TOKEN_USER *>(userBuffer.data());
    if (user->User.Sid == nullptr || !::IsValidSid(user->User.Sid))
        return false;

    const DWORD length = ::GetLengthSid(user->User.Sid);
    if (length == 0 || length > sid.size() ||
        !::CopySid(
            static_cast<DWORD>(sid.size()), sid.data(), user->User.Sid))
    {
        sid.fill(std::byte{0});
        return false;
    }

    sidBytes = static_cast<std::size_t>(length);
    return true;
}

} // namespace

void WindowsSspiAuthenticatedIdentityProof::TokenHandleCloser::operator()(
    void *handle) const noexcept
{
    if (handle != nullptr && handle != INVALID_HANDLE_VALUE)
        (void)::CloseHandle(static_cast<HANDLE>(handle));
}

WindowsSspiAuthenticatedIdentityProof::
    ~WindowsSspiAuthenticatedIdentityProof()
{
    revoke();
}

WindowsSspiAuthenticatedIdentityBindResult
WindowsSspiAuthenticatedIdentityProof::bindAcceptedSecurityContext(
    CtxtHandle &acceptedContext) noexcept
{
    clearIdentity();
    if (!SecIsValidHandle(&acceptedContext))
    {
        return WindowsSspiAuthenticatedIdentityBindResult::
            InvalidSecurityContext;
    }

    void *rawToken = nullptr;
    const SECURITY_STATUS status =
        ::QuerySecurityContextToken(&acceptedContext, &rawToken);
    if (status != SEC_E_OK || rawToken == nullptr)
    {
        if (rawToken != nullptr)
            (void)::CloseHandle(static_cast<HANDLE>(rawToken));
        return WindowsSspiAuthenticatedIdentityBindResult::
            SecurityTokenUnavailable;
    }

    return adoptOwnedToken(rawToken);
}

WindowsSspiAuthenticatedIdentityBindResult
WindowsSspiAuthenticatedIdentityProof::adoptOwnedToken(
    void *rawToken) noexcept
{
    clearIdentity();
    OwnedTokenHandle candidate{rawToken};
    if (!candidate)
    {
        return WindowsSspiAuthenticatedIdentityBindResult::
            SecurityTokenUnavailable;
    }

    std::array<std::byte, kMaximumWindowsNativeSidBytes> candidateSid{};
    std::size_t candidateSidBytes = 0;
    if (!readTokenSid(
            static_cast<HANDLE>(candidate.get()),
            candidateSid, candidateSidBytes))
    {
        return WindowsSspiAuthenticatedIdentityBindResult::
            AuthenticatedSidUnavailable;
    }

    if (nextGeneration_ ==
        (std::numeric_limits<std::uint64_t>::max)())
    {
        return WindowsSspiAuthenticatedIdentityBindResult::
            GenerationExhausted;
    }

    sid_ = candidateSid;
    sidBytes_ = candidateSidBytes;
    token_ = std::move(candidate);
    activeGeneration_ = ++nextGeneration_;
    return WindowsSspiAuthenticatedIdentityBindResult::Bound;
}

void WindowsSspiAuthenticatedIdentityProof::revoke() noexcept
{
    clearIdentity();
}

std::uint64_t
WindowsSspiAuthenticatedIdentityProof::authenticationGeneration()
    const noexcept
{
    return activeGeneration_ != 0 && currentTokenMatchesPinnedSid()
        ? activeGeneration_
        : 0;
}

bool WindowsSspiAuthenticatedIdentityProof::matchesAuthenticatedSid(
    std::span<const std::byte> sid) const noexcept
{
    return activeGeneration_ != 0 &&
           sidBytes_ != 0 &&
           sid.size() == sidBytes_ &&
           std::equal(sid.begin(), sid.end(), sid_.begin()) &&
           currentTokenMatchesPinnedSid();
}

bool WindowsSspiAuthenticatedIdentityProof::readCurrentTokenSid(
    std::array<std::byte, kMaximumWindowsNativeSidBytes> &sid,
    std::size_t &sidBytes) const noexcept
{
    return token_ &&
           readTokenSid(
               static_cast<HANDLE>(token_.get()), sid, sidBytes);
}

bool WindowsSspiAuthenticatedIdentityProof::
    currentTokenMatchesPinnedSid() const noexcept
{
    if (!token_ || sidBytes_ == 0 || sidBytes_ > sid_.size())
        return false;

    std::array<std::byte, kMaximumWindowsNativeSidBytes> currentSid{};
    std::size_t currentSidBytes = 0;
    return readCurrentTokenSid(currentSid, currentSidBytes) &&
           currentSidBytes == sidBytes_ &&
           std::equal(
               currentSid.begin(),
               currentSid.begin() +
                   static_cast<std::ptrdiff_t>(currentSidBytes),
               sid_.begin());
}

void WindowsSspiAuthenticatedIdentityProof::clearIdentity() noexcept
{
    token_.reset();
    sid_.fill(std::byte{0});
    sidBytes_ = 0;
    activeGeneration_ = 0;
}

} // namespace rdp_server::server::security

#endif
