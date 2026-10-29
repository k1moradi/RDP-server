// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "server/runtime/runtime_host_control.h"

#include <QString>
#include <QStringList>
#include <QVector>
#include <cstddef>
#include <cstdint>

namespace rdp::gui
{

// Exactly one R10 interface identity/address pair. Display text grants no bind.
struct LanInterfaceChoice
{
    QString stableId;
    QString displayName;
    QString address;
};

// Opaque R10 client identity is usable only while the current snapshot agrees.
struct ActiveClientChoice
{
    std::uint64_t opaqueId{};
    QString displayName;
};

// Qt-facing projection only. R10 remains the sole command/status authority;
// these fields never mint an R2 lease, native permission or listener.
struct HostStatus
{
    // A single R10 status observation, never a second Qt session owner.
    rdp_server::server::runtime::RuntimeHostStage stage{
        rdp_server::server::runtime::RuntimeHostStage::Stopped};
    rdp_server::server::runtime::RuntimeProductHostState productState{
        rdp_server::server::runtime::RuntimeProductHostState::Error};
    bool listenerReady{};
    bool controlAvailable{};
    bool credentialsConfigured{};
    rdp_server::server::runtime::RuntimeCredentialCapabilities
        credentialCapabilities{};
    bool desktopAuthorized{};
    // Redacted R10 product facts only. Qt does not interpret R2 grant enums,
    // permission masks, native-session identities or revocation state.
    rdp_server::server::runtime::RuntimeSharingPermissionStatus
        sharingPermission{};
    bool tlsReady{};
    // Exact read-only R10 observation, with Unknown client trust.
    rdp_server::server::runtime::RuntimeTlsIdentityStatus tlsIdentity{};
    bool captureInputReady{};
    bool graphicsReady{};
    bool nativeDesktopInitializing{};
    bool nativeDesktopReady{};
    bool clientDisconnected{};
    bool sharing{};
    bool startPending{};
    rdp_server::server::runtime::RuntimeClipboardState clipboardState{
        rdp_server::server::runtime::RuntimeClipboardState::Unavailable};
    QString desktop;
    QVector<LanInterfaceChoice> approvedLanInterfaces;
    QString recommendedInterfaceId;
    QString recommendedAddress;
    std::uint16_t recommendedPort{3389U};
    rdp_server::server::runtime::RuntimeHostRecommendationSource
        recommendationSource{
            rdp_server::server::runtime::RuntimeHostRecommendationSource::Unavailable};
    QVector<ActiveClientChoice> activeClients;
    std::size_t clientCount{};
    rdp_server::server::runtime::RuntimeTlsCertificateFingerprint
        tlsFingerprint{};
    bool tlsFingerprintAvailable{};
    QString lanAddress;
    QString failure;
    QStringList clients;
    QStringList pendingClients;
    QStringList authenticationFailures;
    QStringList disconnected;
    QStringList revoked;
    // R10 lifecycle permission only; independent of credentialsConfigured.
    // Appended to preserve existing aggregate-initializer field positions.
    bool credentialEditingAllowed{};
    // Product-safe per-peer authentication presentation. The detailed string
    // is derived only from redacted R10 enums and never from token/parser text.
    bool remoteAuthenticationFailed{};
    bool localDesktopAuthorizationFailed{};
    QString authenticationDiagnostic;
    // Presentation-only subtype for a peer that disconnected before
    // authentication completed. It grants no protocol or native authority.
    bool remoteAuthenticationIncomplete{};
    // Advanced-only, read-only diagnostics supplied by R10. Qt neither
    // inspects TLS/certificate internals nor treats these values as authority.
    rdp_server::server::runtime::RuntimeAcceptedClientTlsConnectionDiagnostics
        tlsConnection{};
    rdp_server::server::runtime::RuntimeTlsCertificateProfile
        tlsCertificateProfile{
            rdp_server::server::runtime::RuntimeTlsCertificateProfile::Unavailable};
    QString selectedEndpoint;
    // Advanced-only, read-only redacted NTLM Type-1 structure supplied by
    // R10. No token bytes or authentication authority cross this UI boundary.
    rdp_server::server::runtime::RuntimeAcceptedClientNtlmTypeOneDiagnostics
        ntlmTypeOne{};
    // Complete bounded R10 diagnostic snapshot for Advanced presentation and
    // explicit export. Qt owns no parser, timer or connection state.
    rdp_server::server::runtime::RuntimeAcceptedClientPreauthDiagnostics
        acceptedClientDiagnostics{};
    // Product classification only when the existing verifier supplied the
    // typed credential-rejection fact.
    bool remoteAuthenticationInvalidCredentials{};
};

struct HostRequest
{
    QString interfaceId;
    QString interfaceAddress;
    std::uint16_t port{3389U};
};

// Thin UI adapter around R10's single typed RuntimeHostControl contract.
// It owns no runtime state and command success is never sharing proof.
class HostControl final
{
public:
    explicit HostControl(
        rdp_server::server::runtime::RuntimeHostControl& runtime) noexcept;

    [[nodiscard]] HostStatus status() const;
    [[nodiscard]] bool requestExistingOsAccount();
    [[nodiscard]] bool configureStandalonePassword(
        const QString& username, const QString& password);
    [[nodiscard]] bool requestHostPermission(
        const rdp_server::server::runtime::RuntimeHostPermissionRequest&
            request = {});
    [[nodiscard]] bool start(const HostRequest& request);
    [[nodiscard]] bool disconnectClient(std::uint64_t opaqueClientId);
    void stop();
    void stopAndRevoke();

private:
    rdp_server::server::runtime::RuntimeHostControl& runtime_;
};

} // namespace rdp::gui
