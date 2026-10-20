// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "server/runtime/runtime_host_control.h"

#include <QString>
#include <QStringList>
#include <QVector>
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
    bool listenerReady{};
    bool controlAvailable{};
    bool credentialsConfigured{};
    bool desktopAuthorized{};
    // Exact R2/R10 read-only grant observation. This is presentation state,
    // never an authorization capability or a copy of requested GUI intent.
    rdp_server::server::runtime::RuntimeOwnerGrantObservation ownerGrant{};
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
    QVector<ActiveClientChoice> activeClients;
    QString lanAddress;
    QString failure;
    QStringList clients;
    QStringList pendingClients;
    QStringList authenticationFailures;
    QStringList disconnected;
    QStringList revoked;
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
    [[nodiscard]] bool requestHostPermission(
        const rdp_server::server::runtime::RuntimeHostPermissionRequest&
            request = {});
    [[nodiscard]] bool start(const HostRequest& request);
    [[nodiscard]] bool disconnectClient(std::uint64_t opaqueClientId);
    void stopAndRevoke();

private:
    rdp_server::server::runtime::RuntimeHostControl& runtime_;
};

} // namespace rdp::gui
