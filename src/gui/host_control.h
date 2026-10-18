// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "server/runtime/runtime_host_control.h"

#include <QString>
#include <QStringList>
#include <cstdint>

namespace rdp::gui
{

// Qt-facing projection only. R10 remains the sole command/status authority;
// these fields never mint an R2 lease, native permission or listener.
struct HostStatus
{
    bool controlAvailable{};
    bool credentialsConfigured{};
    bool desktopAuthorized{};
    bool tlsReady{};
    bool captureInputReady{};
    bool sharing{};
    bool startPending{};
    QString desktop;
    QStringList approvedLanInterfaces;
    QString lanAddress;
    QString failure;
    QStringList clients;
    QStringList authenticationFailures;
    QStringList disconnected;
    QStringList revoked;
};

struct HostRequest
{
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
    [[nodiscard]] bool start(const HostRequest& request);
    void stopAndRevoke();

private:
    rdp_server::server::runtime::RuntimeHostControl& runtime_;
};

} // namespace rdp::gui
