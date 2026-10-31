// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "current_owner_sharing_authority.h"
#include "macos_native_session_evidence.h"
#include "windows_native_session_evidence.h"

#include <cstdint>
#include <span>
#include <string_view>

namespace rdp_server::server::transport
{
class OwnedPreauthTcpConnection;
}

namespace rdp_server::server::security
{

class MacConsoleAdmissionBroker;

inline constexpr std::uint32_t kNativeDesktopAuthorizationPermissions =
    kConsoleViewPermission | kConsoleInputPermission;

enum class NativeDesktopAuthenticationKind : std::uint8_t
{
    ExistingOsAccount,
    StandalonePassword,
};

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

// R2-only proof of one already-authenticated RDP session. Authentication kind
// determines whether native OS identity equality is required. Standalone
// password sessions prove their exact connection/TLS/credential lifetime
// instead; they must never fabricate a SID, UID or Kerberos principal.
//
// The proof is borrowed synchronously by the authorization owner and may not be
// copied or moved. A nonzero generation is a freshness selector, never a
// capability by itself.
class NativeDesktopAuthenticatedSessionProof
{
public:
    virtual ~NativeDesktopAuthenticatedSessionProof() = default;
    NativeDesktopAuthenticatedSessionProof() = default;
    NativeDesktopAuthenticatedSessionProof(
        const NativeDesktopAuthenticatedSessionProof &) = delete;
    NativeDesktopAuthenticatedSessionProof &operator=(
        const NativeDesktopAuthenticatedSessionProof &) = delete;
    NativeDesktopAuthenticatedSessionProof(
        NativeDesktopAuthenticatedSessionProof &&) = delete;
    NativeDesktopAuthenticatedSessionProof &operator=(
        NativeDesktopAuthenticatedSessionProof &&) = delete;

    [[nodiscard]] virtual NativeDesktopAuthenticationKind authenticationKind()
        const noexcept = 0;
    [[nodiscard]] virtual std::uint64_t authenticationGeneration()
        const noexcept = 0;
    [[nodiscard]] virtual bool revalidatesAuthenticatedSession()
        const noexcept = 0;

    // Only ExistingOsAccount proofs override the platform identity matcher.
    // Standalone defaults deliberately deny OS-account identity matching.
    [[nodiscard]] virtual bool matchesWindowsOsAccountSid(
        std::span<const std::byte> /* sid */) const noexcept
    {
        return false;
    }
    [[nodiscard]] virtual bool matchesMacOsAccountUserId(
        std::uint32_t /* userId */) const noexcept
    {
        return false;
    }

private:
    friend class MacConsoleAdmissionBroker;

    // R2-private provenance observations for a concrete admission broker.
    // Generic proofs deny by default: neither a scalar generation nor an
    // arbitrary R1 object can be promoted to native authority.
    [[nodiscard]] virtual bool revalidatesOwnedR1Connection(
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            & /* connection */) const noexcept
    {
        return false;
    }
    [[nodiscard]] virtual std::uint64_t configuredCredentialGeneration()
        const noexcept
    {
        return 0U;
    }
};

class WindowsAuthenticatedIdentityProof
    : public NativeDesktopAuthenticatedSessionProof
{
public:
    ~WindowsAuthenticatedIdentityProof() override = default;
    WindowsAuthenticatedIdentityProof() = default;
    WindowsAuthenticatedIdentityProof(
        const WindowsAuthenticatedIdentityProof &) = delete;
    WindowsAuthenticatedIdentityProof &operator=(
        const WindowsAuthenticatedIdentityProof &) = delete;

    [[nodiscard]] NativeDesktopAuthenticationKind authenticationKind()
        const noexcept final
    {
        return NativeDesktopAuthenticationKind::ExistingOsAccount;
    }
    [[nodiscard]] bool revalidatesAuthenticatedSession()
        const noexcept final
    {
        return authenticationGeneration() != 0;
    }
    [[nodiscard]] bool matchesWindowsOsAccountSid(
        std::span<const std::byte> sid) const noexcept final
    {
        return matchesAuthenticatedSid(sid);
    }

    [[nodiscard]] virtual std::uint64_t authenticationGeneration()
        const noexcept override = 0;
    [[nodiscard]] virtual bool matchesAuthenticatedSid(
        std::span<const std::byte> sid) const noexcept = 0;
};

class MacAuthenticatedIdentityProof
    : public NativeDesktopAuthenticatedSessionProof
{
public:
    ~MacAuthenticatedIdentityProof() override = default;
    MacAuthenticatedIdentityProof() = default;
    MacAuthenticatedIdentityProof(const MacAuthenticatedIdentityProof &) = delete;
    MacAuthenticatedIdentityProof &operator=(
        const MacAuthenticatedIdentityProof &) = delete;

    [[nodiscard]] NativeDesktopAuthenticationKind authenticationKind()
        const noexcept final
    {
        return NativeDesktopAuthenticationKind::ExistingOsAccount;
    }
    [[nodiscard]] bool revalidatesAuthenticatedSession()
        const noexcept final
    {
        return authenticationGeneration() != 0;
    }
    [[nodiscard]] bool matchesMacOsAccountUserId(
        std::uint32_t userId) const noexcept final
    {
        return matchesAuthenticatedUserId(userId);
    }

    [[nodiscard]] virtual std::uint64_t authenticationGeneration()
        const noexcept override = 0;
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

    [[nodiscard]] NativeDesktopAuthenticationKind authenticationKind()
        const noexcept;
    [[nodiscard]] std::span<const std::byte> nativeSessionUserSid()
        const noexcept;
    // ExistingOsAccount compatibility view. Standalone sessions return empty:
    // the local native SID is not the remote application's authenticated ID.
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
        NativeDesktopAuthenticationKind authenticationKind,
        std::uint32_t permissionMask,
        std::uint64_t authenticationGeneration,
        std::uint64_t authorizationGeneration,
        OwnerSharingAuthorizationEpoch ownerAuthorizationEpoch) noexcept;

    const WindowsNativeSessionEvidence *evidence_{};
    NativeDesktopAuthenticationKind authenticationKind_{
        NativeDesktopAuthenticationKind::ExistingOsAccount};
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

    [[nodiscard]] NativeDesktopAuthenticationKind authenticationKind()
        const noexcept;
    [[nodiscard]] std::uint32_t nativeConsoleUserId() const noexcept;
    // ExistingOsAccount compatibility view. Standalone sessions return zero:
    // the local console UID is not the remote application's authenticated ID.
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
        NativeDesktopAuthenticationKind authenticationKind,
        std::uint32_t permissionMask,
        std::uint64_t authenticationGeneration,
        std::uint64_t authorizationGeneration,
        OwnerSharingAuthorizationEpoch ownerAuthorizationEpoch) noexcept;

    const MacNativeSessionEvidence *evidence_{};
    NativeDesktopAuthenticationKind authenticationKind_{
        NativeDesktopAuthenticationKind::ExistingOsAccount};
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
        NativeDesktopAuthenticatedSessionProof &authenticatedSession,
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

    [[nodiscard]] NativeDesktopAuthorizationBindResult bindAuthenticatedSession(
        std::uint32_t requestedPermissions) noexcept;
    // Compatibility spelling for ExistingOsAccount callers. Authorization kind
    // is always taken from the R2 proof, never from the caller.
    [[nodiscard]] NativeDesktopAuthorizationBindResult bindAuthenticatedIdentity(
        std::uint32_t requestedPermissions) noexcept
    {
        return bindAuthenticatedSession(requestedPermissions);
    }
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

    NativeDesktopAuthenticatedSessionProof *authenticatedSession_{};
    WindowsNativeSessionEvidenceSource *nativeEvidence_{};
    CurrentOwnerSharingAuthority *ownerSharingAuthority_{};

    mutable WindowsNativeSessionEvidence evidence_{};
    mutable NativeDesktopAuthenticationKind authenticationKind_{
        NativeDesktopAuthenticationKind::ExistingOsAccount};
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
        NativeDesktopAuthenticatedSessionProof &authenticatedSession,
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

    [[nodiscard]] NativeDesktopAuthorizationBindResult bindAuthenticatedSession(
        std::uint32_t requestedPermissions) noexcept;
    [[nodiscard]] NativeDesktopAuthorizationBindResult bindAuthenticatedIdentity(
        std::uint32_t requestedPermissions) noexcept
    {
        return bindAuthenticatedSession(requestedPermissions);
    }
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

    NativeDesktopAuthenticatedSessionProof *authenticatedSession_{};
    MacNativeSessionEvidenceSource *nativeEvidence_{};
    CurrentOwnerSharingAuthority *ownerSharingAuthority_{};

    mutable MacNativeSessionEvidence evidence_{};
    mutable NativeDesktopAuthenticationKind authenticationKind_{
        NativeDesktopAuthenticationKind::ExistingOsAccount};
    mutable OwnerSharingAuthorizationEpoch ownerAuthorizationEpoch_{};
    mutable std::uint32_t permissionMask_{};
    mutable std::uint64_t authenticationGeneration_{};
    mutable std::uint64_t activeAuthorizationGeneration_{};
    std::uint64_t nextAuthorizationGeneration_{};
    // Serialized R2 owner thread only. Never nest protected visitor callbacks.
    mutable bool visitInProgress_{};
};

} // namespace rdp_server::server::security
