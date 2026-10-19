// SPDX-License-Identifier: GPL-3.0-or-later
#include "desktop_window.h"
#include "host_control.h"
#include "server/runtime/runtime_host_control.h"

#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QTimer>
#include <algorithm>

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
    int credentialSetupCalls{};
    int permissionSetupCalls{};
    int startCalls{};
    int stopCalls{};
    int revokeCalls{};
    int disconnectCalls{};
    std::uint64_t lastDisconnectedId{};
    bool disconnectSucceeds{};
    bool configureSucceeds{true};
    bool credentialSetupSucceeds{};
    bool permissionSetupSucceeds{};
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
        rdp_server::server::security::LanCredentialChoice choice) override
    {
        ++credentialSetupCalls;
        assert(choice ==
               rdp_server::server::security::LanCredentialChoice::ExistingOsAccount);
        return credentialSetupSucceeds
            ? RuntimeHostResult{RuntimeHostError::None, false}
            : RuntimeHostResult{RuntimeHostError::ControlUnavailable, false};
    }

    [[nodiscard]] RuntimeHostResult requestHostPermissionSetup() override
    {
        ++permissionSetupCalls;
        return permissionSetupSucceeds
            ? RuntimeHostResult{RuntimeHostError::None, false}
            : RuntimeHostResult{RuntimeHostError::ControlUnavailable, false};
    }

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

    [[nodiscard]] RuntimeHostResult disconnectClient(
        const std::uint64_t opaqueClientId) override
    {
        ++disconnectCalls;
        lastDisconnectedId = opaqueClientId;
        if (!disconnectSucceeds)
            return {RuntimeHostError::ClientNotFound, false};
        auto& activeClients = snapshot.activeClients;
        activeClients.erase(std::remove_if(activeClients.begin(), activeClients.end(),
            [opaqueClientId](const RuntimeHostClient& client) {
                return client.opaqueId == opaqueClientId;
            }), activeClients.end());
        return {RuntimeHostError::None, false};
    }

    [[nodiscard]] RuntimeHostResult revokeSharing() override
    {
        ++revokeCalls;
        if (!refuseRetirement)
        {
            snapshot.stage = RuntimeHostStage::Revoked;
            snapshot.clipboardState = RuntimeClipboardState::Retired;
        }
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
        assert(!production.requestExistingOsAccount());
        assert(!production.requestHostPermission());
        assert(!production.start({}));
        assert(!window.canStart());
        assert(unavailable.status().stage == RuntimeHostStage::Stopped);
        return 0;
    }

    FakeRuntimeHost runtime;
    HostControl host(runtime);

    // Drive the real modal close confirmation through Qt's event loop.
    // No native hosting or permission is started by this test helper.
    const auto queueCloseChoice = [](DesktopWindow& window,
                                     const QString& buttonName) {
        QTimer::singleShot(0, &window, [buttonName] {
            auto* confirmation =
                qobject_cast<QMessageBox*>(QApplication::activeModalWidget());
            assert(confirmation && confirmation->textFormat() == Qt::PlainText);
            auto* selected = confirmation->findChild<QPushButton*>(buttonName);
            assert(selected);
            selected->click();
        });
    };

    if (argc > 1 && QString::fromLocal8Bit(argv[1]) == "lifecycle-stages")
    {
        runtime.snapshot.lastError = RuntimeHostError::None;
        DesktopWindow window(host);
        auto* lifecycle = window.findChild<QLabel*>("hostLifecycleStatus");
        auto* stop = window.findChild<QPushButton*>("stopSharing");
        assert(lifecycle && stop && lifecycle->textFormat() == Qt::PlainText);

        const auto checkStage = [&](RuntimeHostStage stage, const char* label) {
            runtime.snapshot.stage = stage;
            window.refresh();
            assert(lifecycle->text().contains(QString::fromLatin1(label)));
        };
        checkStage(RuntimeHostStage::Stopped, "Stopped");
        checkStage(RuntimeHostStage::PackageInstalled, "Installed");
        checkStage(RuntimeHostStage::CredentialsConfigured, "OS credentials");
        checkStage(RuntimeHostStage::ListenerAvailable, "readiness unconfirmed");
        runtime.snapshot.listenerAvailable = true;
        checkStage(RuntimeHostStage::ListenerAvailable, "Listener ready");
        checkStage(RuntimeHostStage::ClientAuthenticating, "Peer authenticating");
        checkStage(RuntimeHostStage::ShareActivated, "Share activated");
        checkStage(RuntimeHostStage::DesktopVisible, "Desktop visible");
        checkStage(RuntimeHostStage::ClientConnected, "no visible client confirmed");
        runtime.snapshot.activeClients = {
            RuntimeHostClient{17U, "192.168.9.17", false, true, true}};
        checkStage(RuntimeHostStage::ClientConnected, "Client connected");
        checkStage(RuntimeHostStage::Revoked, "revoked/stopped");

        // R2 terminal error can hide projected Share before R10 retirement.
        runtime.snapshot.stage = RuntimeHostStage::ClientConnected;
        runtime.snapshot.lastError = RuntimeHostError::HostSessionStale;
        window.refresh();
        assert(!host.status().sharing && !host.status().startPending);
        assert(stop->isEnabled());
        stop->click();
        assert(runtime.stopCalls == 1 && runtime.revokeCalls == 1);
        assert(runtime.snapshot.stage == RuntimeHostStage::Revoked);

        runtime.snapshot.stage = RuntimeHostStage::ClientConnected;
        runtime.snapshot.lastError = RuntimeHostError::ControlUnavailable;
        window.refresh();
        assert(lifecycle->text().contains("Host control unavailable"));
        assert(!window.canStart() && runtime.startCalls == 0);
        return 0;
    }

    if (argc > 1 && QString::fromLocal8Bit(argv[1]) == "client-stage")
    {
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.snapshot.stage = RuntimeHostStage::ClientAuthenticating;
        runtime.snapshot.boundEndpoint = "192.168.0.10:3389";
        runtime.snapshot.activeClients = {
            {10U, "192.168.0.101", true, false, false},
            {11U, "192.168.0.102", false, true, false},
            {12U, "192.168.0.103", false, true, true},
            {13U, "192.168.0.104", false, false, true}};
        DesktopWindow window(host);
        auto* activity = window.findChild<QLabel*>("clientStatus");
        auto* endpoint = window.findChild<QLabel*>("boundLanEndpoint");
        auto* selected = window.findChild<QComboBox*>("activeClientSelection");
        auto* disconnect = window.findChild<QPushButton*>("disconnectClient");
        assert(activity && endpoint && selected && disconnect);

        const auto authenticating = host.status();
        assert(authenticating.clients.isEmpty());
        assert(authenticating.pendingClients.size() == 4);
        assert(authenticating.activeClients.size() == 4);
        assert(activity->text().contains("Authenticating: 192.168.0.101"));
        assert(activity->text().contains(
            "Share activated; desktop pending: 192.168.0.102"));
        assert(activity->text().contains(
            "Desktop not confirmed: 192.168.0.103"));
        assert(activity->text().contains("Connected clients: None"));
        assert(selected->count() == 5 && !disconnect->isEnabled());

        runtime.snapshot.stage = RuntimeHostStage::ClientConnected;
        window.refresh();
        const auto connected = host.status();
        assert(connected.clients.size() == 1);
        assert(connected.clients.front() == "192.168.0.103");
        assert(connected.pendingClients.size() == 3);
        assert(activity->text().contains(
            "Connected clients: 192.168.0.103"));
        assert(!activity->text().contains(
            "Connected clients: 192.168.0.101"));
        selected->setCurrentIndex(1);
        assert(disconnect->isEnabled());

        // R10 retirement hides all former peers and the former endpoint,
        // even if an inconsistent status payload retains stale field data.
        runtime.snapshot.stage = RuntimeHostStage::Stopped;
        window.refresh();
        assert(host.status().clients.isEmpty());
        assert(host.status().pendingClients.isEmpty());
        assert(host.status().activeClients.isEmpty());
        assert(host.status().lanAddress.isEmpty());
        assert(endpoint->text().contains("not reported"));
        assert(activity->text().contains("Connected clients: None"));
        assert(activity->text().contains(
            "Authenticating / desktop pending: None"));
        assert(!activity->text().contains("192.168.0.101"));
        assert(selected->count() == 1 && !disconnect->isEnabled());

        runtime.snapshot.stage = RuntimeHostStage::ClientConnected;
        runtime.snapshot.lastError = RuntimeHostError::ControlUnavailable;
        window.refresh();
        assert(!host.status().controlAvailable);
        assert(host.status().clients.isEmpty());
        assert(host.status().activeClients.isEmpty());
        assert(host.status().lanAddress.isEmpty());
        assert(!disconnect->isEnabled());
        // A rate-limit result is a redacted authentication failure, not a
        // success and not a forced revocation of unrelated live clients.
        runtime.snapshot.lastError = RuntimeHostError::AuthenticationRateLimited;
        runtime.snapshot.stage = RuntimeHostStage::ClientConnected;
        window.refresh();
        const auto limited = host.status();
        assert(limited.authenticationFailures.size() == 1);
        assert(limited.authenticationFailures.front() ==
               QStringLiteral("Authentication temporarily rate-limited"));
        assert(limited.failure ==
               QStringLiteral("Authentication temporarily rate-limited"));

        // Even an internally inconsistent late snapshot cannot present a
        // stale owner as authorized or keep its old endpoint and clients.
        runtime.snapshot.lastError = RuntimeHostError::HostSessionStale;
        runtime.snapshot.hostOwnerAuthorized = true;
        runtime.snapshot.nativeDesktopReady = true;
        runtime.snapshot.credentialsConfigured = true;
        runtime.snapshot.tlsIdentityReady = true;
        window.refresh();
        const auto stale = host.status();
        assert(!stale.desktopAuthorized && !stale.captureInputReady);
        assert(!stale.sharing && !stale.startPending);
        assert(stale.clients.isEmpty() && stale.pendingClients.isEmpty());
        assert(stale.activeClients.isEmpty() && stale.lanAddress.isEmpty());
        assert(stale.failure.contains("fresh authorization required"));
        assert(!host.start({"some-interface", "192.168.0.10", 3389U}));
        assert(!host.disconnectClient(12U));
        assert(runtime.configureCalls == 0 && runtime.startCalls == 0 &&
               runtime.disconnectCalls == 0);
        return 0;
    }

    if (argc > 1 && QString::fromLocal8Bit(argv[1]) == "r10-lan-selector")
    {
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.snapshot.credentialsConfigured = true;
        runtime.snapshot.hostOwnerAuthorized = true;
        runtime.snapshot.tlsIdentityReady = true;
        runtime.snapshot.nativeDesktopReady = true;
        runtime.interfaces = {
            {"ethernet-1", "Trusted Ethernet",
             {"192.168.2.21", "fe80::1234"}, false, true},
            {"duplicate-id", "First duplicated ID",
             {"192.168.2.22"}, false, true},
            {"duplicate-id", "Second duplicated ID",
             {"192.168.2.23"}, false, true},
            {"wildcards", "Unbindable",
             {"0.0.0.0", "::", "[::]"}, false, true},
            {"loopback", "Localhost", {"127.0.0.1"}, true, true},
            {"disabled", "Unapproved", {"192.168.2.24"}, false, false}};
        DesktopWindow window(host);
        auto* interfaces = window.findChild<QComboBox*>("lanInterface");
        auto* start = window.findChild<QPushButton*>("startSharing");
        assert(interfaces && start);
        const auto eligible = host.status().approvedLanInterfaces;
        assert(eligible.size() == 2);
        assert(interfaces->count() == 3); // Placeholder + valid IPv4/IPv6.
        assert(interfaces->itemText(1).contains("192.168.2.21"));
        assert(interfaces->itemText(2).contains("fe80::1234"));
        assert(!window.canStart() && !start->isEnabled());

        // The same R10 selector used on Start must reject an invalid
        // native identity, a wildcard endpoint and a zero listening port.
        assert(!host.start({"duplicate-id", "192.168.2.22", 3389U}));
        assert(!host.start({"wildcards", "0.0.0.0", 3389U}));
        assert(!host.start({"ethernet-1", "192.168.2.21", 0U}));
        assert(runtime.configureCalls == 0 && runtime.startCalls == 0);

        interfaces->setCurrentIndex(2);
        assert(window.canStart() && start->isEnabled());
        start->click();
        assert(runtime.configureCalls == 1 && runtime.startCalls == 1);
        assert(runtime.lastOptions.interfaceId == "ethernet-1");
        assert(runtime.lastOptions.localAddress == "fe80::1234");
        assert(!host.status().sharing); // A clicked Start grants no Share.

        runtime.interfaces.clear(); // Revoke even the displayed selection.
        window.refresh();
        assert(interfaces->count() == 1);
        assert(!window.canStart() && !start->isEnabled());
        assert(runtime.configureCalls == 1 && runtime.startCalls == 1);
        return 0;
    }

    if (argc > 1 && QString::fromLocal8Bit(argv[1]) == "plain-runtime-text")
    {
        // R10's runtime-facing labels must never interpret a peer or endpoint
        // as a Qt rich-text link/image, even if the peer reports markup.
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.snapshot.stage = RuntimeHostStage::ClientConnected;
        runtime.snapshot.boundEndpoint = "<a href='https://invalid.example/'>host</a>";
        runtime.snapshot.activeClients = {
            RuntimeHostClient{
                17U, "<img src='file:///tmp/untrusted.svg'>", false, true, true}};
        runtime.interfaces = {
            {"ethernet-1", "<a href='https://invalid.example/'>Ethernet</a>",
             {"192.168.0.10"}, false, true}};
        DesktopWindow window(host);
        auto* endpoint = window.findChild<QLabel*>("boundLanEndpoint");
        auto* activity = window.findChild<QLabel*>("clientStatus");
        auto* selected = window.findChild<QLabel*>("selectedLanInterfaceStatus");
        auto* error = window.findChild<QLabel*>("hostErrorExplanation");
        auto* selection = window.findChild<QComboBox*>("lanInterface");
        assert(endpoint && activity && selected && error && selection);
        selection->setCurrentIndex(1);
        window.refresh();
        assert(endpoint->textFormat() == Qt::PlainText);
        assert(activity->textFormat() == Qt::PlainText);
        assert(selected->textFormat() == Qt::PlainText);
        assert(error->textFormat() == Qt::PlainText);
        assert(endpoint->text().contains("<a href="));
        assert(activity->text().contains("<img src="));
        assert(selected->text().contains("<a href="));
        assert(!window.canStart());
        assert(runtime.configureCalls == 0 && runtime.startCalls == 0);
        return 0;
    }

    if (argc > 1 && QString::fromLocal8Bit(argv[1]) == "lan-client")
    {
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.snapshot.credentialsConfigured = true;
        runtime.snapshot.hostOwnerAuthorized = true;
        runtime.snapshot.tlsIdentityReady = true;
        runtime.snapshot.nativeDesktopReady = true;
        // Same IP on two native interfaces requires the exact R10 stable ID.
        runtime.interfaces = {
            {"ethernet-1", "Private Ethernet", {"192.168.0.10"}, false, true},
            {"wifi-2", "Private Wi-Fi", {"192.168.0.10"}, false, true},
            {"loopback", "Loopback", {"127.0.0.1"}, true, false}};
        DesktopWindow window(host);
        auto* lan = window.findChild<QComboBox*>("lanInterface");
        auto* selected = window.findChild<QLabel*>("selectedLanInterfaceStatus");
        auto* endpoint = window.findChild<QLabel*>("boundLanEndpoint");
        auto* trust = window.findChild<QLabel*>("tlsIdentityStatus");
        auto* error = window.findChild<QLabel*>("hostErrorExplanation");
        auto* start = window.findChild<QPushButton*>("startSharing");
        auto* clients = window.findChild<QComboBox*>("activeClientSelection");
        auto* disconnect = window.findChild<QPushButton*>("disconnectClient");
        assert(lan && selected && endpoint && trust && error && start &&
               clients && disconnect);
        assert(lan->count() == 3); // Placeholder and two eligible interfaces.
        assert(lan->itemText(2).contains("Private Wi-Fi"));
        assert(endpoint->text().contains("not reported"));
        assert(trust->text().contains("no client trust is inferred"));
        assert(!disconnect->isEnabled());
        assert(!host.disconnectClient(7U));
        assert(runtime.disconnectCalls == 0);

        lan->setCurrentIndex(2);
        assert(selected->text().contains("Private Wi-Fi"));
        runtime.snapshot.credentialsConfigured = false;
        window.refresh();
        assert(!host.start({"wifi-2", "192.168.0.10", 3389U}));
        assert(!start->isEnabled() && runtime.configureCalls == 0);
        runtime.snapshot.credentialsConfigured = true;
        window.refresh();
        assert(window.canStart());
        runtime.startSucceeds = true;
        start->click();
        assert(runtime.configureCalls == 1 && runtime.startCalls == 1);
        assert(runtime.lastOptions.interfaceId == "wifi-2");
        assert(runtime.lastOptions.localAddress == "192.168.0.10");
        assert(!host.status().sharing); // A successful command is not Share.

        runtime.snapshot.stage = RuntimeHostStage::ClientConnected;
        runtime.snapshot.boundEndpoint = "192.168.0.10:3389";
        runtime.snapshot.activeClients = {
            RuntimeHostClient{7U, "192.168.0.44", false, true, true}};
        window.refresh();
        assert(endpoint->text().contains("192.168.0.10:3389"));
        assert(clients->count() == 2 && !disconnect->isEnabled());
        clients->setCurrentIndex(1);
        assert(disconnect->isEnabled());
        assert(!host.disconnectClient(8U));
        assert(runtime.disconnectCalls == 0);
        runtime.disconnectSucceeds = true;
        disconnect->click();
        assert(runtime.disconnectCalls == 1 && runtime.lastDisconnectedId == 7U);
        assert(!disconnect->isEnabled() && clients->count() == 1);
        runtime.snapshot.lastError = RuntimeHostError::AccessRevoked;
        window.refresh();
        assert(error->text().contains("Sharing access revoked"));
        return 0;
    }

    if (argc > 1 && QString::fromLocal8Bit(argv[1]) == "access")
    {
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.credentialSetupSucceeds = true;
        runtime.permissionSetupSucceeds = true;
        DesktopWindow window(host);
        auto* configureAccount =
            window.findChild<QPushButton*>("configureOsAccount");
        auto* requestPermission =
            window.findChild<QPushButton*>("requestHostPermission");
        assert(configureAccount && requestPermission);
        assert(configureAccount->isEnabled());
        assert(!requestPermission->isEnabled());

        configureAccount->click();
        assert(runtime.credentialSetupCalls == 1);
        assert(!host.status().credentialsConfigured);
        assert(!requestPermission->isEnabled() && !window.canStart());

        runtime.snapshot.credentialsConfigured = true;
        window.refresh();
        assert(requestPermission->isEnabled());
        requestPermission->click();
        assert(runtime.permissionSetupCalls == 1);
        assert(!host.status().desktopAuthorized);
        assert(!window.canStart());

        runtime.snapshot.hostOwnerAuthorized = true;
        window.refresh();
        assert(host.status().desktopAuthorized);
        assert(!window.canStart()); // TLS/native/interface gates are still absent.
        return 0;
    }

    if (argc > 1 && QString::fromLocal8Bit(argv[1]) == "close-consent")
    {
        DesktopWindow window(host);
        window.show();
        application.processEvents();
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.snapshot.stage = RuntimeHostStage::ClientAuthenticating;
        window.refresh();

        // Dismissing the dialog must not cause Stop, Revoke or hiding.
        queueCloseChoice(window, "keepSharingWindowOpen");
        assert(!window.close() && window.isVisible());
        assert(runtime.stopCalls == 0 && runtime.revokeCalls == 0);

        // An explicit Stop still cannot close until R10 confirms retirement.
        runtime.refuseRetirement = true;
        queueCloseChoice(window, "confirmStopSharingAndClose");
        assert(!window.close() && window.isVisible());
        assert(runtime.stopCalls == 1 && runtime.revokeCalls == 1);

        runtime.refuseRetirement = false;
        queueCloseChoice(window, "confirmStopSharingAndClose");
        assert(window.close());
        assert(runtime.stopCalls == 2 && runtime.revokeCalls == 2);
        assert(runtime.snapshot.stage == RuntimeHostStage::Revoked);

        // An already-stopped GUI closes without another Stop or prompt.
        DesktopWindow stoppedWindow(host);
        stoppedWindow.show();
        application.processEvents();
        assert(stoppedWindow.close());
        assert(runtime.stopCalls == 2 && runtime.revokeCalls == 2);
        return 0;
    }

    if (argc > 1 && QString::fromLocal8Bit(argv[1]) == "close")
    {
        DesktopWindow window(host);
        window.show();
        application.processEvents();
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.snapshot.stage = RuntimeHostStage::ClientAuthenticating;
        runtime.refuseRetirement = true;
        window.refresh();
        queueCloseChoice(window, "confirmStopSharingAndClose");
        assert(!window.close());
        assert(window.isVisible() && runtime.stopCalls == 1 &&
               runtime.revokeCalls == 1);
        runtime.refuseRetirement = false;
        queueCloseChoice(window, "confirmStopSharingAndClose");
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
        auto* clipboard = window.findChild<QLabel*>("clipboardStatus");
        auto* copy = window.findChild<QPushButton*>("copyLanAddress");
        assert(next && back && start && stop && secret && confirm &&
               interfaceSelection && clients && clipboard && copy);
        assert(clipboard->text().contains("unavailable"));
        assert(!copy->isEnabled());

        runtime.snapshot.clipboardState = RuntimeClipboardState::Denied;
        window.refresh();
        assert(clipboard->text().contains("denied"));
        runtime.snapshot.clipboardState = RuntimeClipboardState::Unavailable;
        window.refresh();
        assert(clipboard->text().contains("unavailable"));

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
        // Rendering-only fixture: this does not mint an R2 lease or R3 route.
        runtime.snapshot.clipboardState = RuntimeClipboardState::Enabled;
        runtime.snapshot.boundEndpoint = "192.168.0.10:3389";
        runtime.snapshot.activeClients = {
            RuntimeHostClient{7U, "192.168.0.44", false, true, true}};
        window.refresh();
        assert(stop->isEnabled() && copy->isEnabled() &&
               clients->text().contains("192.168.0.44"));
        assert(clipboard->text().contains("enabled"));
        copy->click();
        assert(application.clipboard()->text() == "192.168.0.10:3389");

        runtime.interfaces.clear();
        window.refresh();
        assert(!window.canStart());
        stop->click();
        assert(runtime.stopCalls == 1 && runtime.revokeCalls == 1);
        assert(!host.status().sharing && !copy->isEnabled());
        assert(clipboard->text().contains("retired"));

        for (int page = 0; page < 5; ++page)
            back->click();
        window.close();
    }
    return 0;
}
