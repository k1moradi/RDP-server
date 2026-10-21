// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "current_owner_sharing_authority.h"
#include "macos_native_session_evidence.h"
#include "windows_native_session_evidence.h"

#include <cstdint>
#include <span>
#include <string_view>

namespace rdp_server::server::security
{

inline constexpr std::uint32_t kNativeDesktopAuthorizationPermissions =
    kConsoleViewPermission | kConsoleInputPermission;

enum class NativeDesktopAuthorizationBindResult : std::uint8_t
{
    Bound,
    InvalidPermissions,
    AuthenticatedIdentityUnavailable,
    NativeSessionUnavailable,
    AuthenticatedIdentityMismatch,
    OwnerAuthorizationUnavailable,
    GenerationExhausted,
};

// These proof interfaces are R2-only inputs. Native evidence cannot implement
// authentication: production implementations must be backed by the selected
// CredSSP/NLA identity owner and change generation on credential revocation or
// replacement. Downstream R10/R5/R6 code receives only the const authorization
// object and its synchronous visitor.
class WindowsAuthenticatedIdentityProof
{
public:
    virtual ~WindowsAuthenticatedIdentityProof() = default;
    WindowsAuthenticatedIdentityProof() = default;
    WindowsAuthenticatedIdentityProof(
        const WindowsAuthenticatedIdentityProof &) = delete;
    WindowsAuthenticatedIdentityProof &operator=(
        const WindowsAuthenticatedIdentityProof &) = delete;

    [[nodiscard]] virtual std::uint64_t authenticationGeneration()
        const noexcept = 0;
    [[nodiscard]] virtual bool matchesAuthenticatedSid(
        std::span<const std::byte> sid) const noexcept = 0;
};

class MacAuthenticatedIdentityProof
{
public:
    virtual ~MacAuthenticatedIdentityProof() = default;
    MacAuthenticatedIdentityProof() = default;
    MacAuthenticatedIdentityProof(const MacAuthenticatedIdentityProof &) = delete;
    MacAuthenticatedIdentityProof &operator=(
        const MacAuthenticatedIdentityProof &) = delete;

    [[nodiscard]] virtual std::uint64_t authenticationGeneration()
        const noexcept = 0;
    [[nodiscard]] virtual bool matchesAuthenticatedUserId(
        std::uint32_t userId) const noexcept = 0;
};

class WindowsNativeDesktopAuthorization;
class MacNativeDesktopAuthorization;

// Opaque borrowed view valid only during the visitor callback. It cannot be
// copied or moved. Scalar generations are freshness selectors only and cannot
// reconstruct authority after the callback returns.
class WindowsNativeDesktopAuthorizationView final
{
public:
    WindowsNativeDesktopAuthorizationView(
        const WindowsNativeDesktopAuthorizationView &) = delete;
    WindowsNativeDesktopAuthorizationView &operator=(
        const WindowsNativeDesktopAuthorizationView &) = delete;
    WindowsNativeDesktopAuthorizationView(
        WindowsNativeDesktopAuthorizationView &&) = delete;
    WindowsNativeDesktopAuthorizationView &operator=(
        WindowsNativeDesktopAuthorizationView &&) = delete;

    [[nodiscard]] std::span<const std::byte> authenticatedSid() const noexcept;
    [[nodiscard]] std::uint32_t wtsSessionId() const noexcept;
    [[nodiscard]] std::uint32_t authenticationIdLow() const noexcept;
    [[nodiscard]] std::int32_t authenticationIdHigh() const noexcept;
    [[nodiscard]] std::int64_t logonTime100Nanoseconds() const noexcept;
    [[nodiscard]] std::uint32_t permissionMask() const noexcept;
    [[nodiscard]] std::uint64_t authenticationGeneration() const noexcept;
    [[nodiscard]] std::uint64_t authorizationGeneration() const noexcept;
    [[nodiscard]] OwnerSharingAuthorizationEpoch ownerAuthorizationEpoch()
        const noexcept;

private:
    friend class WindowsNativeDesktopAuthorization;

    WindowsNativeDesktopAuthorizationView(
        const WindowsNativeSessionEvidence &evidence,
        std::uint32_t permissionMask,
        std::uint64_t authenticationGeneration,
        std::uint64_t authorizationGeneration,
        OwnerSharingAuthorizationEpoch ownerAuthorizationEpoch) noexcept;

    const WindowsNativeSessionEvidence *evidence_{};
    std::uint32_t permissionMask_{};
    std::uint64_t authenticationGeneration_{};
    std::uint64_t authorizationGeneration_{};
    OwnerSharingAuthorizationEpoch ownerAuthorizationEpoch_{};
};

using WindowsNativeDesktopAuthorizationVisitor = bool (*)(
    const WindowsNativeDesktopAuthorizationView &authorization,
    void *context) noexcept;

class MacNativeDesktopAuthorizationView final
{
public:
    MacNativeDesktopAuthorizationView(
        const MacNativeDesktopAuthorizationView &) = delete;
    MacNativeDesktopAuthorizationView &operator=(
        const MacNativeDesktopAuthorizationView &) = delete;
    MacNativeDesktopAuthorizationView(
        MacNativeDesktopAuthorizationView &&) = delete;
    MacNativeDesktopAuthorizationView &operator=(
        MacNativeDesktopAuthorizationView &&) = delete;

    [[nodiscard]] std::uint32_t authenticatedUserId() const noexcept;
    [[nodiscard]] std::string_view consoleUser() const noexcept;
    [[nodiscard]] std::uint32_t auditUserId() const noexcept;
    [[nodiscard]] std::uint64_t auditSessionId() const noexcept;
    [[nodiscard]] std::uint32_t securitySessionId() const noexcept;
    [[nodiscard]] std::uint32_t securitySessionAttributes() const noexcept;
    [[nodiscard]] std::uint32_t permissionMask() const noexcept;
    [[nodiscard]] std::uint64_t authenticationGeneration() const noexcept;
    [[nodiscard]] std::uint64_t authorizationGeneration() const noexcept;
    [[nodiscard]] OwnerSharingAuthorizationEpoch ownerAuthorizationEpoch()
        const noexcept;

private:
    friend class MacNativeDesktopAuthorization;

    MacNativeDesktopAuthorizationView(
        const MacNativeSessionEvidence &evidence,
        std::uint32_t permissionMask,
        std::uint64_t authenticationGeneration,
        std::uint64_t authorizationGeneration,
        OwnerSharingAuthorizationEpoch ownerAuthorizationEpoch) noexcept;

    const MacNativeSessionEvidence *evidence_{};
    std::uint32_t permissionMask_{};
    std::uint64_t authenticationGeneration_{};
    std::uint64_t authorizationGeneration_{};
    OwnerSharingAuthorizationEpoch ownerAuthorizationEpoch_{};
};

using MacNativeDesktopAuthorizationVisitor = bool (*)(
    const MacNativeDesktopAuthorizationView &authorization,
    void *context) noexcept;

// R2-owned one-grant authority. bindAuthenticatedIdentity() is the mutable
// issuer side and must remain inside R2 composition. Downstream native owners
// receive a const reference: they can only inspect generation and enter visit().
//
// Calls are serialized on the R2/R10 owner thread. CurrentOwnerSharingAuthority
// may publish revocation concurrently through its atomic epoch. Every visit
// revalidates authenticated identity, fresh native session evidence and the
// exact owner grant/revocation epoch before and after the callback.
class WindowsNativeDesktopAuthorization final
{
public:
    WindowsNativeDesktopAuthorization(
        WindowsAuthenticatedIdentityProof &authenticatedIdentity,
        WindowsNativeSessionEvidenceSource &nativeEvidence,
        CurrentOwnerSharingAuthority &ownerSharingAuthority) noexcept;

    WindowsNativeDesktopAuthorization(
        const WindowsNativeDesktopAuthorization &) = delete;
    WindowsNativeDesktopAuthorization &operator=(
        const WindowsNativeDesktopAuthorization &) = delete;
    WindowsNativeDesktopAuthorization(
        WindowsNativeDesktopAuthorization &&) = delete;
    WindowsNativeDesktopAuthorization &operator=(
        WindowsNativeDesktopAuthorization &&) = delete;

    [[nodiscard]] NativeDesktopAuthorizationBindResult bindAuthenticatedIdentity(
        std::uint32_t requestedPermissions) noexcept;
    void revoke() noexcept;

    [[nodiscard]] std::uint64_t authorizationGeneration() const noexcept;
    [[nodiscard]] bool visit(
        std::uint64_t expectedAuthorizationGeneration,
        std::uint32_t requiredPermissions,
        WindowsNativeDesktopAuthorizationVisitor visitor,
        void *context) const noexcept;

private:
    [[nodiscard]] bool revalidatesCurrentGrant() const noexcept;
    void clearGrant() const noexcept;

    WindowsAuthenticatedIdentityProof *authenticatedIdentity_{};
    WindowsNativeSessionEvidenceSource *nativeEvidence_{};
    CurrentOwnerSharingAuthority *ownerSharingAuthority_{};

    mutable WindowsNativeSessionEvidence evidence_{};
    mutable OwnerSharingAuthorizationEpoch ownerAuthorizationEpoch_{};
    mutable std::uint32_t permissionMask_{};
    mutable std::uint64_t authenticationGeneration_{};
    mutable std::uint64_t activeAuthorizationGeneration_{};
    std::uint64_t nextAuthorizationGeneration_{};
};

class MacNativeDesktopAuthorization final
{
public:
    MacNativeDesktopAuthorization(
        MacAuthenticatedIdentityProof &authenticatedIdentity,
        MacNativeSessionEvidenceSource &nativeEvidence,
        CurrentOwnerSharingAuthority &ownerSharingAuthority) noexcept;

    MacNativeDesktopAuthorization(
        const MacNativeDesktopAuthorization &) = delete;
    MacNativeDesktopAuthorization &operator=(
        const MacNativeDesktopAuthorization &) = delete;
    MacNativeDesktopAuthorization(
        MacNativeDesktopAuthorization &&) = delete;
    MacNativeDesktopAuthorization &operator=(
        MacNativeDesktopAuthorization &&) = delete;

    [[nodiscard]] NativeDesktopAuthorizationBindResult bindAuthenticatedIdentity(
        std::uint32_t requestedPermissions) noexcept;
    void revoke() noexcept;

    [[nodiscard]] std::uint64_t authorizationGeneration() const noexcept;
    [[nodiscard]] bool visit(
        std::uint64_t expectedAuthorizationGeneration,
        std::uint32_t requiredPermissions,
        MacNativeDesktopAuthorizationVisitor visitor,
        void *context) const noexcept;

private:
    [[nodiscard]] bool revalidatesCurrentGrant() const noexcept;
    void clearGrant() const noexcept;

    MacAuthenticatedIdentityProof *authenticatedIdentity_{};
    MacNativeSessionEvidenceSource *nativeEvidence_{};
    CurrentOwnerSharingAuthority *ownerSharingAuthority_{};

    mutable MacNativeSessionEvidence evidence_{};
    mutable OwnerSharingAuthorizationEpoch ownerAuthorizationEpoch_{};
    mutable std::uint32_t permissionMask_{};
    mutable std::uint64_t authenticationGeneration_{};
    mutable std::uint64_t activeAuthorizationGeneration_{};
    std::uint64_t nextAuthorizationGeneration_{};
};

} // namespace rdp_server::server::security
