// SPDX-License-Identifier: GPL-3.0-or-later
#include "desktop_window.h"
#include "host_control.h"
#include "server/runtime/runtime_host_control.h"

#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>

#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

using namespace rdp::gui;
using namespace rdp_server::server::runtime;

class FakeRuntimeHost final : public RuntimeHostControl
{
public:
    std::vector<RuntimeHostInterface> interfaces;
    RuntimeHostStatus snapshot;
    RuntimeHostOptions lastOptions;
    int configureCalls{};
    int startCalls{};
    int stopCalls{};
    int revokeCalls{};
    bool configureSucceeds{true};
    bool startSucceeds{};
    bool refuseRetirement{};

    [[nodiscard]] std::vector<RuntimeHostInterface>
    enumerateLocalInterfaces() const override { return interfaces; }
    [[nodiscard]] RuntimeHostStatus status() const override { return snapshot; }

    [[nodiscard]] RuntimeHostResult configure(
        const RuntimeHostOptions& options) override
    {
        ++configureCalls;
        lastOptions = options;
        return configureSucceeds
            ? RuntimeHostResult{RuntimeHostError::None, false}
            : RuntimeHostResult{RuntimeHostError::InvalidConfiguration, false};
    }

    [[nodiscard]] RuntimeHostResult requestCredentialSetup(
        rdp_server::server::security::LanCredentialChoice) override
    { return {RuntimeHostError::ControlUnavailable, false}; }

    [[nodiscard]] RuntimeHostResult requestHostPermissionSetup() override
    { return {RuntimeHostError::ControlUnavailable, false}; }

    [[nodiscard]] RuntimeHostResult startSharing() override
    {
        ++startCalls;
        return startSucceeds
            ? RuntimeHostResult{RuntimeHostError::None, false}
            : RuntimeHostResult{RuntimeHostError::ControlUnavailable, false};
    }

    [[nodiscard]] RuntimeHostResult stopSharing() override
    {
        ++stopCalls;
        if (!refuseRetirement)
            snapshot.stage = RuntimeHostStage::Stopped;
        return {RuntimeHostError::None, false};
    }

    [[nodiscard]] RuntimeHostResult disconnectClient(std::uint64_t) override
    { return {RuntimeHostError::ClientNotFound, false}; }

    [[nodiscard]] RuntimeHostResult revokeSharing() override
    {
        ++revokeCalls;
        if (!refuseRetirement)
            snapshot.stage = RuntimeHostStage::Revoked;
        return {RuntimeHostError::None, false};
    }
};

int main(int argc, char** argv)
{
    QApplication application(argc, argv);

    if (argc > 1 && QString::fromLocal8Bit(argv[1]) == "runtime")
    {
        UnavailableRuntimeHostControl unavailable;
        HostControl production(unavailable);
        DesktopWindow window(production);
        assert(!production.status().controlAvailable);
        assert(!production.start({}));
        assert(!window.canStart());
        assert(unavailable.status().stage == RuntimeHostStage::Stopped);
        return 0;
    }

    FakeRuntimeHost runtime;
    HostControl host(runtime);
    if (argc > 1 && QString::fromLocal8Bit(argv[1]) == "close")
    {
        DesktopWindow window(host);
        window.show();
        application.processEvents();
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.snapshot.stage = RuntimeHostStage::ClientAuthenticating;
        runtime.refuseRetirement = true;
        window.refresh();
        assert(!window.close());
        assert(window.isVisible() && runtime.stopCalls == 1 &&
               runtime.revokeCalls == 1);
        runtime.refuseRetirement = false;
        assert(window.close());
        assert(runtime.stopCalls == 2 && runtime.revokeCalls == 2);
        assert(runtime.snapshot.stage == RuntimeHostStage::Revoked);
        return 0;
    }

    {
        DesktopWindow window(host);
        assert(runtime.startCalls == 0 && runtime.configureCalls == 0 &&
               !window.canStart());
        auto* next = window.findChild<QPushButton*>("nextPage");
        auto* back = window.findChild<QPushButton*>("backPage");
        auto* start = window.findChild<QPushButton*>("startSharing");
        auto* stop = window.findChild<QPushButton*>("stopSharing");
        auto* secret = window.findChild<QLineEdit*>("password");
        auto* confirm = window.findChild<QLineEdit*>("confirmation");
        auto* interfaceSelection = window.findChild<QComboBox*>("lanInterface");
        auto* clients = window.findChild<QLabel*>("clientStatus");
        auto* copy = window.findChild<QPushButton*>("copyLanAddress");
        assert(next && back && start && stop && secret && confirm &&
               interfaceSelection && clients && copy);
        assert(!copy->isEnabled());

        for (int page = 0; page < 5; ++page)
            next->click();
        assert(!start->isEnabled() && !stop->isEnabled());
        assert(!secret->isEnabled() && !confirm->isEnabled());

        secret->setText("test-only-secret");
        confirm->setText("does-not-match");
        assert(!window.blockedReason().contains("test-only-secret"));

        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.snapshot.credentialsConfigured = true;
        runtime.snapshot.hostOwnerAuthorized = true;
        runtime.snapshot.tlsIdentityReady = true;
        runtime.snapshot.nativeDesktopReady = true;
        runtime.interfaces = {RuntimeHostInterface{
            "ethernet-1", "Private Ethernet", {"192.168.0.10"}, false, true}};
        window.refresh();
        assert(!window.canStart());

        interfaceSelection->setCurrentIndex(1);
        window.refresh();
        secret->setEnabled(true);
        confirm->setEnabled(true);
        assert(!window.canStart() &&
               window.blockedReason().contains("confirmation mismatch"));
        assert(!window.blockedReason().contains("test-only-secret"));
        confirm->setText("test-only-secret");
        assert(window.canStart());
        secret->setEnabled(false);
        confirm->setEnabled(false);
        assert(window.canStart() && start->isEnabled());

        runtime.startSucceeds = true;
        start->click();
        assert(runtime.configureCalls == 1 && runtime.startCalls == 1);
        assert(runtime.lastOptions.interfaceId == "ethernet-1");
        assert(runtime.lastOptions.localAddress == "192.168.0.10");
        assert(runtime.lastOptions.port == 3389U &&
               runtime.lastOptions.lanRequested);
        assert(!host.status().sharing);
        assert(!copy->isEnabled());

        runtime.snapshot.stage = RuntimeHostStage::ClientConnected;
        runtime.snapshot.boundEndpoint = "192.168.0.10:3389";
        runtime.snapshot.activeClients = {
            RuntimeHostClient{7U, "192.168.0.44", false, true, true}};
        window.refresh();
        assert(stop->isEnabled() && copy->isEnabled() &&
               clients->text().contains("192.168.0.44"));
        copy->click();
        assert(application.clipboard()->text() == "192.168.0.10:3389");

        runtime.interfaces.clear();
        window.refresh();
        assert(!window.canStart());
        stop->click();
        assert(runtime.stopCalls == 1 && runtime.revokeCalls == 1);
        assert(!host.status().sharing && !copy->isEnabled());

        for (int page = 0; page < 5; ++page)
            back->click();
        window.close();
    }
    return 0;
}
