// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <QString>
#include <QStringList>
#include <cstdint>
namespace rdp::gui {
// R10 alone owns network, TLS, native permission, and admission lifetimes.
// Snapshots are descriptive; no UI flag is an authorization token.
struct HostStatus {
    bool controlAvailable = false;
    bool credentialProviderReady = false;
    bool desktopAuthorized = false;
    bool tlsReady = false;
    bool firewallReady = false;
    bool captureInputReady = false;
    bool sharing = false;
    QString desktop;
    QString lanAddress;
    QString failure;
    QStringList clients;
    QStringList authenticationFailures;
    QStringList disconnected;
    QStringList revoked;
};
struct HostRequest {
    QString desktop;
    QString interfaceAddress;
    std::uint16_t port = 3389;
};
class HostControl {
public:
    virtual ~HostControl() = default;
    [[nodiscard]] virtual HostStatus status() const = 0;
    [[nodiscard]] virtual bool start(const HostRequest&) = 0;
    virtual void stopAndRevoke() = 0;
};
// Production launch has no R10 control API yet: deny, never simulate success.
class UnavailableHostControl final : public HostControl {
public:
    [[nodiscard]] HostStatus status() const override {
        HostStatus value;
        value.failure = QStringLiteral("R10 host-control API and R2 native admission are unavailable");
        return value;
    }
    [[nodiscard]] bool start(const HostRequest&) override { return false; }
    void stopAndRevoke() override {}
};
}
