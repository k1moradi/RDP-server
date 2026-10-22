// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "native_desktop_authorization.h"

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <windows.h>
#include <sspi.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace rdp_server::server::security
{

enum class WindowsSspiAuthenticatedIdentityBindResult : std::uint8_t
{
    Bound,
    InvalidSecurityContext,
    SecurityTokenUnavailable,
    AuthenticatedSidUnavailable,
    GenerationExhausted,
};

class WindowsSspiAuthenticatedIdentityProofTestAccess;

// R2-owned authenticated identity extracted from an already-accepted SSPI
// security context. QuerySecurityContextToken is the only production bind
// entry: callers cannot supply SID bytes or native WTS evidence as identity.
//
// The returned SSPI token is owned for this proof lifetime and closed on
// revoke/replacement/destruction. The proof retains no password, username,
// protocol token or delegated credential bytes. The R2/R10 owner must revoke
// this object when the accepted CredSSP/SSPI authentication lifetime ends.
class WindowsSspiAuthenticatedIdentityProof final
    : public WindowsAuthenticatedIdentityProof
{
public:
    WindowsSspiAuthenticatedIdentityProof() noexcept = default;
    ~WindowsSspiAuthenticatedIdentityProof() override;

    WindowsSspiAuthenticatedIdentityProof(
        const WindowsSspiAuthenticatedIdentityProof &) = delete;
    WindowsSspiAuthenticatedIdentityProof &operator=(
        const WindowsSspiAuthenticatedIdentityProof &) = delete;
    WindowsSspiAuthenticatedIdentityProof(
        WindowsSspiAuthenticatedIdentityProof &&) = delete;
    WindowsSspiAuthenticatedIdentityProof &operator=(
        WindowsSspiAuthenticatedIdentityProof &&) = delete;

    [[nodiscard]] WindowsSspiAuthenticatedIdentityBindResult
    bindAcceptedSecurityContext(CtxtHandle &acceptedContext) noexcept;

    void revoke() noexcept;

    [[nodiscard]] std::uint64_t authenticationGeneration()
        const noexcept override;
    [[nodiscard]] bool matchesAuthenticatedSid(
        std::span<const std::byte> sid) const noexcept override;

private:
    friend class WindowsSspiAuthenticatedIdentityProofTestAccess;

    struct TokenHandleCloser final
    {
        void operator()(void *handle) const noexcept;
    };
    using OwnedTokenHandle = std::unique_ptr<void, TokenHandleCloser>;

    [[nodiscard]] WindowsSspiAuthenticatedIdentityBindResult
    adoptOwnedToken(void *rawToken) noexcept;
    [[nodiscard]] bool readCurrentTokenSid(
        std::array<std::byte, kMaximumWindowsNativeSidBytes> &sid,
        std::size_t &sidBytes) const noexcept;
    [[nodiscard]] bool currentTokenMatchesPinnedSid() const noexcept;
    void clearIdentity() noexcept;

    OwnedTokenHandle token_{};
    std::array<std::byte, kMaximumWindowsNativeSidBytes> sid_{};
    std::size_t sidBytes_{};
    std::uint64_t activeGeneration_{};
    std::uint64_t nextGeneration_{};
};

} // namespace rdp_server::server::security

#endif
