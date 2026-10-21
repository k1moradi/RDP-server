// SPDX-License-Identifier: GPL-3.0-or-later
#include "desktop_window.h"
#include "host_control.h"
#include "server/runtime/runtime_host_control.h"
#include "server/security/console_identity_policy.h"

#if defined(__linux__)
#include "server/runtime/linux_runtime_host_control.h"
#endif

#include <QAbstractButton>
#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QLabel>
#include <QPushButton>
#include <QSpinBox>
#include <QStackedWidget>

#include <algorithm>
#include <cassert>
#include <cstddef>
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
    RuntimeHostPermissionRequest lastPermissionRequest;
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
    bool deriveProductStatusFromLegacy{true};

    [[nodiscard]] std::vector<RuntimeHostInterface>
    enumerateLocalInterfaces() const override
    {
        return interfaces;
    }

    [[nodiscard]] RuntimeHostStatus status() const override
    {
        RuntimeHostStatus result = snapshot;
        if (!deriveProductStatusFromLegacy)
            return result;

        result.product.controlAvailable =
            result.lastError != RuntimeHostError::ControlUnavailable;
        // This generic fake represents the previously available typed host
        // surface; production capability truth still comes only from R10.
        result.product.credentialCapabilities.existingOsAccount =
            result.product.controlAvailable;
        result.product.eligibleLanInterfaces = interfaces;
        result.product.recommendedEndpoint =
            recommendRuntimePrivateLanEndpoint(interfaces);
        result.product.boundEndpoint = result.boundEndpoint;
        result.product.clientCount = result.activeClients.size();
        result.product.activeClientIds.clear();
        for (const RuntimeHostClient& client : result.activeClients)
        {
            if (client.opaqueId != 0U)
                result.product.activeClientIds.emplace_back(client.opaqueId);
        }
        result.product.credentialsConfigured =
            result.credentialsConfigured;
        result.product.ownerAuthorized = result.hostOwnerAuthorized;
        result.product.ownerPermission = result.ownerGrant;
        result.product.tlsIdentityReady = result.tlsIdentityReady;
        if (result.tlsIdentity.fingerprintAvailable)
        {
            result.product.tlsFingerprint =
                result.tlsIdentity.certificateSha256;
            result.product.tlsFingerprintAvailable = true;
        }
        result.product.state = runtimeProductStateFor(
            result.stage, result.lastError, result.nativeDesktopReady);
        result.product.lastErrorMessage =
            result.lastError == RuntimeHostError::None
            ? std::string{}
            : std::string(runtimeHostErrorMessage(result.lastError));
        return result;
    }

    [[nodiscard]] RuntimeHostResult configure(
        const RuntimeHostOptions& options) override
    {
        ++configureCalls;
        lastOptions = options;
        return configureSucceeds
            ? RuntimeHostResult{RuntimeHostError::None, false}
            : RuntimeHostResult{
                  RuntimeHostError::InvalidConfiguration, false};
    }

    [[nodiscard]] RuntimeHostResult requestCredentialSetup(
        rdp_server::server::security::LanCredentialChoice choice) override
    {
        ++credentialSetupCalls;
        assert(
            choice ==
            rdp_server::server::security::LanCredentialChoice::
                ExistingOsAccount);
        return credentialSetupSucceeds
            ? RuntimeHostResult{RuntimeHostError::None, false}
            : RuntimeHostResult{
                  RuntimeHostError::ControlUnavailable, false};
    }

    [[nodiscard]] RuntimeHostResult requestHostPermissionSetup(
        const RuntimeHostPermissionRequest& request = {}) override
    {
        ++permissionSetupCalls;
        lastPermissionRequest = request;
        return permissionSetupSucceeds
            ? RuntimeHostResult{RuntimeHostError::None, false}
            : RuntimeHostResult{
                  RuntimeHostError::ControlUnavailable, false};
    }

    [[nodiscard]] RuntimeHostResult startSharing() override
    {
        ++startCalls;
        return startSucceeds
            ? RuntimeHostResult{RuntimeHostError::None, false}
            : RuntimeHostResult{
                  RuntimeHostError::ControlUnavailable, false};
    }

    [[nodiscard]] RuntimeHostResult stopSharing() override
    {
        ++stopCalls;
        if (refuseRetirement)
        {
            deriveProductStatusFromLegacy = false;
            snapshot.product.state = RuntimeProductHostState::Stopping;
        }
        else
        {
            deriveProductStatusFromLegacy = true;
            snapshot.stage = RuntimeHostStage::Stopped;
        }
        return {RuntimeHostError::None, false};
    }

    [[nodiscard]] RuntimeHostResult disconnectClient(
        std::uint64_t opaqueClientId) override
    {
        ++disconnectCalls;
        lastDisconnectedId = opaqueClientId;
        if (!disconnectSucceeds)
            return {RuntimeHostError::ClientNotFound, false};

        auto& clients = snapshot.activeClients;
        clients.erase(
            std::remove_if(
                clients.begin(), clients.end(),
                [opaqueClientId](const RuntimeHostClient& client) {
                    return client.opaqueId == opaqueClientId;
                }),
            clients.end());
        return {RuntimeHostError::None, false};
    }

    [[nodiscard]] RuntimeHostResult revokeSharing() override
    {
        ++revokeCalls;
        if (!refuseRetirement)
        {
            deriveProductStatusFromLegacy = true;
            snapshot.stage = RuntimeHostStage::Revoked;
            snapshot.clipboardState = RuntimeClipboardState::Retired;
        }
        return {RuntimeHostError::None, false};
    }
};

namespace
{

QAbstractButton* sharingToggle(DesktopWindow& window)
{
    auto* toggle =
        window.findChild<QAbstractButton*>("sharingToggle");
    assert(toggle && toggle->isCheckable());
    return toggle;
}

QLabel* requiredLabel(DesktopWindow& window, const char* name)
{
    auto* result = window.findChild<QLabel*>(name);
    assert(result && result->textFormat() == Qt::PlainText);
    return result;
}

QPushButton* requiredButton(DesktopWindow& window, const char* name)
{
    auto* result = window.findChild<QPushButton*>(name);
    assert(result);
    return result;
}

QComboBox* requiredCombo(DesktopWindow& window, const char* name)
{
    auto* result = window.findChild<QComboBox*>(name);
    assert(result);
    return result;
}

QAction* requiredAction(DesktopWindow& window, const char* name)
{
    auto* result = window.findChild<QAction*>(name);
    assert(result);
    return result;
}

void prepareReadyHost(FakeRuntimeHost& runtime)
{
    runtime.snapshot.lastError = RuntimeHostError::None;
    runtime.snapshot.credentialsConfigured = true;
    runtime.snapshot.hostOwnerAuthorized = true;
    runtime.snapshot.tlsIdentityReady = true;
    runtime.snapshot.product.credentialCapabilities.existingOsAccount = true;
    runtime.interfaces = {
        RuntimeHostInterface{
            "ethernet-1", "Private Ethernet",
            {"192.168.0.10"}, false, true}};
}

void assertNoRoadLabelsInUserText(DesktopWindow& window)
{
    const auto containsRoadLabel = [](const QString& text) {
        return text.contains("R1", Qt::CaseInsensitive) ||
               text.contains("R2", Qt::CaseInsensitive) ||
               text.contains("R10", Qt::CaseInsensitive);
    };

    for (QLabel* item : window.findChildren<QLabel*>())
        assert(!containsRoadLabel(item->text()));
    for (QAbstractButton* item : window.findChildren<QAbstractButton*>())
        assert(!containsRoadLabel(item->text()));
    for (QComboBox* combo : window.findChildren<QComboBox*>())
    {
        for (int index = 0; index < combo->count(); ++index)
            assert(!containsRoadLabel(combo->itemText(index)));
    }
}

void checkDashboardDefaults(FakeRuntimeHost& runtime, HostControl& host)
{
    runtime.snapshot.lastError = RuntimeHostError::None;
    runtime.interfaces = {
        RuntimeHostInterface{
            "ethernet-1", "Private Ethernet",
            {"192.168.1.42"}, false, true}};

    DesktopWindow window(host);
    assert(window.findChild<QStackedWidget*>() == nullptr);
    assert(window.findChild<QObject*>("backPage") == nullptr);
    assert(window.findChild<QObject*>("nextPage") == nullptr);
    assert(window.findChild<QObject*>("password") == nullptr);
    assert(window.findChild<QObject*>("confirmation") == nullptr);
    assert(window.findChild<QObject*>("allowClipboard") == nullptr);
    assert(window.findChild<QObject*>(
               "setApplicationPasswordUnsupported") == nullptr);

    auto* title = requiredLabel(window, "serverStateTitle");
    auto* address = requiredLabel(window, "connectionAddress");
    auto* access = requiredLabel(window, "credentialStatus");
    auto* advanced =
        requiredButton(window, "advancedDisclosure");
    auto* advancedPanel = window.findChild<QWidget*>("advancedPanel");
    auto* toggle = sharingToggle(window);

    assert(title->text() == QStringLiteral("RDP Server — Stopped"));
    assert(address->text() == QStringLiteral("192.168.1.42:3389"));
    assert(access->text().contains("Existing OS Account"));
    assert(advancedPanel && advancedPanel->isHidden());
    assert(!toggle->isChecked() && !toggle->isEnabled());

    advanced->click();
    assert(!advancedPanel->isHidden());
    advanced->click();
    assert(advancedPanel->isHidden());

    assertNoRoadLabelsInUserText(window);
}

} // namespace

int main(int argc, char** argv)
{
    QApplication application(argc, argv);

    FakeRuntimeHost runtime;
    HostControl host(runtime);
    const QString mode =
        argc > 1 ? QString::fromLocal8Bit(argv[1]) : QString();

    if (mode == "runtime")
    {
        UnavailableRuntimeHostControl unavailable;
        HostControl production(unavailable);
        DesktopWindow window(production);
        assert(!production.status().controlAvailable);
        assert(!production.requestExistingOsAccount());
        assert(!production.requestHostPermission());
        assert(!production.start({}));
        assert(!window.canStart());
        assert(!sharingToggle(window)->isEnabled());
        assert(unavailable.status().stage == RuntimeHostStage::Stopped);
        return 0;
    }

#if defined(__linux__)
    if (mode == "linux-real-host-control")
    {
        LinuxRuntimeHostControl realRuntime;
        HostControl controller(realRuntime);
        DesktopWindow window(controller);
        auto* toggle = sharingToggle(window);
        auto* copy = requiredButton(window, "copyLanAddress");
        assert(controller.status().controlAvailable);
        assert(!window.canStart());
        assert(!toggle->isEnabled() && !toggle->isChecked());
        assert(!copy->isEnabled());
        controller.stopAndRevoke();
        window.refresh();
        assert(controller.status().stage == RuntimeHostStage::Revoked);
        return 0;
    }
#endif

    if (mode == "dashboard")
    {
        checkDashboardDefaults(runtime, host);
        return 0;
    }

    if (mode == "toggle-authority")
    {
        prepareReadyHost(runtime);
        runtime.startSucceeds = true;
        DesktopWindow window(host);
        auto* toggle = sharingToggle(window);
        auto* title = requiredLabel(window, "serverStateTitle");
        assert(window.canStart() && toggle->isEnabled());
        assert(!toggle->isChecked());

        toggle->click();
        assert(runtime.configureCalls == 1 && runtime.startCalls == 1);
        assert(!toggle->isChecked());
        assert(title->text().contains("Stopped"));

        runtime.snapshot.stage = RuntimeHostStage::ListenerAvailable;
        runtime.snapshot.listenerAvailable = true;
        runtime.snapshot.boundEndpoint = "192.168.0.10:3389";
        window.refresh();
        assert(toggle->isChecked());
        assert(title->text().contains("Listening"));

        runtime.refuseRetirement = true;
        toggle->click();
        assert(runtime.stopCalls == 1 && runtime.revokeCalls == 1);
        assert(toggle->isChecked());
        assert(title->text().contains("Stopping"));

        runtime.refuseRetirement = false;
        runtime.snapshot.stage = RuntimeHostStage::Revoked;
        window.refresh();
        assert(!toggle->isChecked());
        assert(title->text().contains("Stopped"));
        return 0;
    }

    if (mode == "tray-lifecycle")
    {
        prepareReadyHost(runtime);
        runtime.snapshot.stage = RuntimeHostStage::ClientConnected;
        runtime.snapshot.boundEndpoint = "192.168.0.10:3389";
        runtime.snapshot.clipboardState = RuntimeClipboardState::Enabled;
        runtime.snapshot.nativeDesktopReady = true;
        runtime.snapshot.activeClients = {
            RuntimeHostClient{
                7U, "192.168.0.44", false, true, true}};

        DesktopWindow window(host);
        window.show();
        application.processEvents();
        auto* open = requiredAction(window, "trayOpen");
        auto* copy = requiredAction(window, "trayCopyAddress");
        auto* sharing = requiredAction(window, "traySharing");
        auto* clients = requiredAction(window, "trayConnectedClients");
        auto* quit = requiredAction(window, "trayQuit");
        assert(copy->isEnabled());
        assert(sharing->text().contains("Stop"));
        assert(clients->text().contains("1 connected device"));

        assert(!window.close());
        assert(!window.isVisible());
        assert(runtime.stopCalls == 0 && runtime.revokeCalls == 0);
        assert(
            host.status().clipboardState ==
            RuntimeClipboardState::Enabled);

        open->trigger();
        assert(window.isVisible());
        copy->trigger();
        assert(
            application.clipboard()->text() ==
            QStringLiteral("192.168.0.10:3389"));

        runtime.refuseRetirement = true;
        quit->trigger();
        assert(runtime.stopCalls == 1 && runtime.revokeCalls == 1);
        assert(runtime.snapshot.stage == RuntimeHostStage::ClientConnected);
        assert(
            host.status().clipboardState ==
            RuntimeClipboardState::Enabled);

        runtime.refuseRetirement = false;
        quit->trigger();
        assert(runtime.stopCalls == 2 && runtime.revokeCalls == 2);
        assert(runtime.snapshot.stage == RuntimeHostStage::Revoked);
        assert(
            host.status().clipboardState ==
            RuntimeClipboardState::Retired);
        return 0;
    }

    if (mode == "hide-preserves-sharing")
    {
        prepareReadyHost(runtime);
        runtime.snapshot.stage = RuntimeHostStage::ClientConnected;
        runtime.snapshot.boundEndpoint = "192.168.0.10:3389";
        runtime.snapshot.clipboardState = RuntimeClipboardState::Enabled;
        runtime.snapshot.nativeDesktopReady = true;
        runtime.snapshot.activeClients = {
            RuntimeHostClient{
                9U, "192.168.0.44", false, true, true}};

        DesktopWindow window(host);
        window.show();
        application.processEvents();
        window.hide();
        application.processEvents();
        assert(!window.isVisible());
        assert(runtime.stopCalls == 0 && runtime.revokeCalls == 0);
        assert(host.status().sharing);
        assert(
            host.status().clipboardState ==
            RuntimeClipboardState::Enabled);

        host.stopAndRevoke();
        window.refresh();
        assert(runtime.stopCalls == 1 && runtime.revokeCalls == 1);
        assert(!host.status().sharing);
        assert(
            host.status().clipboardState ==
            RuntimeClipboardState::Retired);
        return 0;
    }

    if (mode == "close" || mode == "close-consent")
    {
        prepareReadyHost(runtime);
        runtime.snapshot.stage = RuntimeHostStage::ClientAuthenticating;
        DesktopWindow window(host);
        window.show();
        application.processEvents();

        assert(!window.close());
        assert(!window.isVisible());
        assert(runtime.stopCalls == 0 && runtime.revokeCalls == 0);

        auto* quit = requiredAction(window, "trayQuit");
        runtime.refuseRetirement = true;
        quit->trigger();
        assert(runtime.stopCalls == 1 && runtime.revokeCalls == 1);
        assert(
            runtime.snapshot.stage ==
            RuntimeHostStage::ClientAuthenticating);

        runtime.refuseRetirement = false;
        quit->trigger();
        assert(runtime.stopCalls == 2 && runtime.revokeCalls == 2);
        assert(runtime.snapshot.stage == RuntimeHostStage::Revoked);
        return 0;
    }

    if (mode == "unsupported-password")
    {
        prepareReadyHost(runtime);
        DesktopWindow window(host);
        assert(window.findChild<QObject*>("password") == nullptr);
        assert(window.findChild<QObject*>("confirmation") == nullptr);
        assert(window.findChild<QObject*>(
                   "setApplicationPasswordUnsupported") == nullptr);
        assert(
            requiredLabel(window, "credentialStatus")
                ->text().contains("Existing OS Account"));
        assert(
            requiredLabel(window, "authenticationModeStatus")
                ->text().contains("Existing OS Account"));
        return 0;
    }

    if (mode == "access")
    {
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.credentialSetupSucceeds = true;
        runtime.permissionSetupSucceeds = true;
        DesktopWindow window(host);
        auto* configure =
            requiredButton(window, "configureOsAccount");
        auto* permission =
            requiredButton(window, "requestHostPermission");
        auto* input =
            window.findChild<QCheckBox*>("allowRemoteInput");
        auto* lifetime =
            window.findChild<QSpinBox*>(
                "ownerPermissionLifetimeMinutes");
        assert(configure && permission && input && lifetime);
        assert(configure->isEnabled());
        assert(!permission->isEnabled());
        assert(input->isChecked());

        configure->click();
        assert(runtime.credentialSetupCalls == 1);
        runtime.snapshot.credentialsConfigured = true;
        window.refresh();
        assert(permission->isEnabled());

        input->setChecked(false);
        lifetime->setValue(7);
        permission->click();
        assert(runtime.permissionSetupCalls == 1);
        assert(!runtime.lastPermissionRequest.allowInput);
        assert(!runtime.lastPermissionRequest.allowClipboard);
        assert(
            runtime.lastPermissionRequest.requestedLifetimeMilliseconds ==
            7U * 60U * 1000U);
        assert(!window.canStart());
        return 0;
    }

    if (mode == "owner-grant-observation")
    {
        using namespace rdp_server::server::security;

        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.snapshot.credentialsConfigured = true;
        runtime.snapshot.hostOwnerAuthorized = true;
        runtime.snapshot.ownerGrant = RuntimeOwnerGrantObservation{
            RuntimeOwnerGrantState::Active,
            kConsoleViewPermission | kConsoleInputPermission,
            6U * 60U * 1000U + 58U * 1000U};

        DesktopWindow window(host);
        auto* permission =
            requiredLabel(window, "permissionStatus");
        assert(permission->text().contains(
            "Scope: screen, keyboard/mouse"));
        assert(permission->text().contains("Remaining: 6 min 58 sec"));

        runtime.snapshot.hostOwnerAuthorized = false;
        runtime.snapshot.ownerGrant = RuntimeOwnerGrantObservation{
            RuntimeOwnerGrantState::Expired,
            kConsoleAllowedPermissions,
            15U * 60U * 1000U};
        window.refresh();
        assert(permission->text().contains("expired"));
        assert(!permission->text().contains("Scope:"));
        return 0;
    }

    if (mode == "tls-identity")
    {
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.snapshot.tlsIdentity.state =
            RuntimeTlsIdentityState::ConfiguredUnbound;
        runtime.snapshot.tlsIdentity.fingerprintAvailable = true;
        for (std::size_t index = 0;
             index <
             runtime.snapshot.tlsIdentity.certificateSha256.size();
             ++index)
        {
            runtime.snapshot.tlsIdentity.certificateSha256[index] =
                static_cast<std::uint8_t>(index);
        }

        DesktopWindow window(host);
        auto* tls = requiredLabel(window, "tlsIdentityStatus");
        const QString fingerprint = QStringLiteral(
            "00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:"
            "10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F");
        assert(tls->text().contains(fingerprint));
        assert(tls->text().contains("Client trust: unknown"));

        runtime.snapshot.stage = RuntimeHostStage::ListenerAvailable;
        runtime.snapshot.listenerAvailable = true;
        runtime.snapshot.tlsIdentityReady = true;
        runtime.snapshot.boundEndpoint = "192.168.0.10:3389";
        runtime.snapshot.listenerGeneration = 11U;
        runtime.snapshot.tlsIdentity.endpointGeneration = 11U;
        runtime.snapshot.tlsIdentity.state =
            RuntimeTlsIdentityState::BoundAndMatched;
        window.refresh();
        assert(tls->text().contains("active LAN endpoint"));
        assert(tls->text().contains(fingerprint));

        runtime.snapshot.tlsIdentity.certificateSha256.fill(0xa5U);
        window.refresh();
        assert(!tls->text().contains(fingerprint));
        assert(tls->text().contains("A5:A5:A5:A5"));

        runtime.snapshot.lastError = RuntimeHostError::HostSessionStale;
        window.refresh();
        assert(tls->text().contains("unavailable"));
        assert(!tls->text().contains("A5:A5"));
        return 0;
    }

    if (mode == "terminal-listener")
    {
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.snapshot.stage = RuntimeHostStage::ListenerAvailable;
        runtime.snapshot.listenerAvailable = true;
        runtime.snapshot.boundEndpoint = "192.168.0.10:3389";
        DesktopWindow window(host);
        auto* toggle = sharingToggle(window);
        assert(toggle->isChecked());

        runtime.snapshot.lastError = RuntimeHostError::HostSessionStale;
        window.refresh();
        assert(toggle->isChecked());
        toggle->click();
        assert(runtime.stopCalls == 1 && runtime.revokeCalls == 1);
        assert(runtime.snapshot.stage == RuntimeHostStage::Revoked);
        assert(!toggle->isChecked());
        return 0;
    }

    if (mode == "lifecycle-stages")
    {
        runtime.deriveProductStatusFromLegacy = false;
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.snapshot.product.controlAvailable = true;
        DesktopWindow window(host);
        auto* lifecycle =
            requiredLabel(window, "hostLifecycleStatus");
        const auto check =
            [&](RuntimeProductHostState state, const char* text) {
                runtime.snapshot.product.state = state;
                window.refresh();
                assert(lifecycle->text().contains(
                    QString::fromLatin1(text)));
            };
        check(RuntimeProductHostState::Stopped, "Stopped");
        check(RuntimeProductHostState::Starting, "Starting");
        check(RuntimeProductHostState::Listening, "Listening");
        check(RuntimeProductHostState::Authenticating, "authenticating");
        check(RuntimeProductHostState::DesktopInitializing, "Preparing");
        check(RuntimeProductHostState::Connected, "connected");
        check(RuntimeProductHostState::Stopping, "Stopping");
        check(RuntimeProductHostState::Error, "error");
        return 0;
    }

    if (mode == "client-stage")
    {
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.snapshot.stage = RuntimeHostStage::ClientAuthenticating;
        runtime.snapshot.boundEndpoint = "192.168.0.10:3389";
        runtime.snapshot.activeClients = {
            {10U, "192.168.0.101", true, false, false},
            {11U, "192.168.0.102", false, true, false},
            {12U, "192.168.0.103", false, true, true}};
        DesktopWindow window(host);
        auto* activity = requiredLabel(window, "clientStatus");
        assert(activity->text().contains("Connecting"));
        assert(!activity->text().contains("Connected: 192.168.0.103"));

        runtime.snapshot.stage = RuntimeHostStage::ClientConnected;
        runtime.snapshot.nativeDesktopReady = true;
        window.refresh();
        assert(activity->text().contains("Connected: 192.168.0.103"));

        runtime.snapshot.stage = RuntimeHostStage::Stopped;
        window.refresh();
        assert(activity->text() == QStringLiteral("No connected devices"));
        return 0;
    }

    if (mode == "graphics-native-status")
    {
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.snapshot.stage = RuntimeHostStage::ShareActivated;
        runtime.snapshot.listenerAvailable = true;
        runtime.snapshot.boundEndpoint = "192.168.0.10:3389";
        runtime.snapshot.activeClients = {
            {21U, "192.168.0.121", false, true, true}};
        DesktopWindow window(host);
        auto* lifecycle =
            requiredLabel(window, "hostLifecycleStatus");

        assert(lifecycle->text().contains("Preparing"));
        const QString initializingText = lifecycle->text();
        runtime.snapshot.graphicsReady = true;
        window.refresh();
        assert(lifecycle->text() == initializingText);
        runtime.snapshot.nativeDesktopInitializing = true;
        window.refresh();
        assert(lifecycle->text() == initializingText);
        runtime.snapshot.stage = RuntimeHostStage::DesktopVisible;
        runtime.snapshot.nativeDesktopInitializing = false;
        window.refresh();
        assert(lifecycle->text().contains("Preparing"));
        runtime.snapshot.nativeDesktopReady = true;
        window.refresh();
        assert(lifecycle->text().contains("connected"));
        return 0;
    }

    if (mode == "product-status-authority")
    {
        runtime.deriveProductStatusFromLegacy = false;
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.snapshot.stage = RuntimeHostStage::ClientConnected;
        runtime.snapshot.listenerAvailable = true;
        runtime.snapshot.nativeDesktopReady = true;
        runtime.snapshot.boundEndpoint = "10.9.9.9:3389";
        runtime.snapshot.credentialsConfigured = true;
        runtime.snapshot.hostOwnerAuthorized = true;
        runtime.snapshot.tlsIdentityReady = true;
        runtime.snapshot.activeClients = {
            {77U, "192.168.50.77", false, true, true}};
        runtime.interfaces = {
            {"ethernet-1", "Ethernet", {"192.168.50.10"}, false, true},
            {"wifi-2", "Wi-Fi", {"192.168.50.20"}, false, true}};

        auto& product = runtime.snapshot.product;
        product.state = RuntimeProductHostState::Stopped;
        product.controlAvailable = true;
        product.eligibleLanInterfaces = runtime.interfaces;
        product.recommendedEndpoint =
            {"wifi-2", "192.168.50.20", 3389U};
        product.credentialCapabilities.existingOsAccount = true;
        product.credentialsConfigured = true;
        product.ownerAuthorized = true;
        product.tlsIdentityReady = true;

        DesktopWindow window(host);
        auto* toggle = sharingToggle(window);
        auto* title = requiredLabel(window, "serverStateTitle");
        auto* address = requiredLabel(window, "connectionAddress");
        auto* interfaces = requiredCombo(window, "lanInterface");

        assert(!toggle->isChecked());
        assert(title->text().contains("Stopped"));
        assert(interfaces->currentData().toString() ==
               QStringLiteral("192.168.50.20"));
        assert(address->text() ==
               QStringLiteral("192.168.50.20:3389"));

        runtime.snapshot.stage = RuntimeHostStage::Stopped;
        runtime.snapshot.listenerAvailable = false;
        runtime.snapshot.nativeDesktopReady = false;
        runtime.snapshot.boundEndpoint.clear();
        product.state = RuntimeProductHostState::Connected;
        product.boundEndpoint = "192.168.50.20:3389";
        product.clientCount = 1U;
        product.activeClientIds = {77U};
        window.refresh();
        assert(toggle->isChecked());
        assert(title->text().contains("Connected"));
        assert(address->text() ==
               QStringLiteral("192.168.50.20:3389"));
        assert(host.status().clientCount == 1U);
        assert(host.status().activeClients.size() == 1U);
        assert(host.status().activeClients.front().opaqueId == 77U);

        product.state = RuntimeProductHostState::Stopping;
        window.refresh();
        assert(toggle->isChecked());
        assert(title->text().contains("Stopping"));

        product.state = RuntimeProductHostState::Error;
        product.lastErrorMessage = "Host operation failed";
        window.refresh();
        assert(!toggle->isChecked());
        assert(title->text().contains("Error"));
        assert(requiredLabel(window, "sharingReadinessStatus")
                   ->text().contains("Host operation failed"));
        return 0;
    }

    if (mode == "r10-lan-selector")
    {
        prepareReadyHost(runtime);
        runtime.interfaces = {
            {"ethernet-1", "Trusted Ethernet",
             {"192.168.2.21", "fe80::1234"}, false, true},
            {"duplicate-id", "First duplicate",
             {"192.168.2.22"}, false, true},
            {"duplicate-id", "Second duplicate",
             {"192.168.2.23"}, false, true},
            {"loopback", "Localhost", {"127.0.0.1"}, true, true}};
        runtime.startSucceeds = true;

        DesktopWindow window(host);
        auto* interfaces = requiredCombo(window, "lanInterface");
        auto* address = requiredLabel(window, "connectionAddress");
        auto* toggle = sharingToggle(window);
        assert(interfaces->count() == 3);
        assert(interfaces->currentData().toString() ==
               QStringLiteral("192.168.2.21"));
        assert(address->text() == QStringLiteral("192.168.2.21:3389"));
        assert(window.canStart() && toggle->isEnabled());

        interfaces->setCurrentIndex(2);
        assert(address->text() ==
               QStringLiteral("[fe80::1234]:3389"));
        toggle->click();
        assert(runtime.configureCalls == 1 && runtime.startCalls == 1);
        assert(runtime.lastOptions.interfaceId == "ethernet-1");
        assert(runtime.lastOptions.localAddress == "fe80::1234");
        assert(!toggle->isChecked());
        return 0;
    }

    if (mode == "plain-runtime-text")
    {
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.snapshot.stage = RuntimeHostStage::ClientConnected;
        runtime.snapshot.boundEndpoint =
            "<a href='https://invalid.example/'>host</a>";
        runtime.snapshot.activeClients = {
            RuntimeHostClient{
                17U, "<img src='file:///tmp/untrusted.svg'>",
                false, true, true}};
        runtime.interfaces = {
            {"ethernet-1",
             "<a href='https://invalid.example/'>Ethernet</a>",
             {"192.168.0.10"}, false, true}};

        DesktopWindow window(host);
        auto* address = requiredLabel(window, "connectionAddress");
        auto* activity = requiredLabel(window, "clientStatus");
        auto* selected =
            requiredLabel(window, "selectedLanInterfaceStatus");
        assert(address->text().contains("<a href="));
        assert(selected->text().contains("<a href="));
        assert(activity->text().contains("<img src=") ||
               activity->text().contains("No connected devices"));
        return 0;
    }

    if (mode == "lan-client")
    {
        prepareReadyHost(runtime);
        runtime.snapshot.nativeDesktopReady = true;
        runtime.interfaces = {
            {"ethernet-1", "Private Ethernet",
             {"192.168.0.10"}, false, true},
            {"wifi-2", "Private Wi-Fi",
             {"192.168.0.11"}, false, true}};
        runtime.startSucceeds = true;

        DesktopWindow window(host);
        auto* interfaces = requiredCombo(window, "lanInterface");
        auto* toggle = sharingToggle(window);
        auto* clients =
            requiredCombo(window, "activeClientSelection");
        auto* disconnect =
            requiredButton(window, "disconnectClient");
        assert(interfaces->currentIndex() == 1);
        interfaces->setCurrentIndex(2);
        toggle->click();
        assert(runtime.lastOptions.interfaceId == "wifi-2");
        assert(runtime.lastOptions.localAddress == "192.168.0.11");

        runtime.snapshot.stage = RuntimeHostStage::ClientConnected;
        runtime.snapshot.boundEndpoint = "192.168.0.11:3389";
        runtime.snapshot.activeClients = {
            RuntimeHostClient{
                7U, "192.168.0.44", false, true, true}};
        window.refresh();
        assert(sharingToggle(window)->isChecked());
        assert(clients->count() == 2);
        clients->setCurrentIndex(1);
        assert(disconnect->isEnabled());

        runtime.disconnectSucceeds = true;
        disconnect->click();
        assert(runtime.disconnectCalls == 1);
        assert(runtime.lastDisconnectedId == 7U);
        return 0;
    }

    if (mode == "positive-workflow")
    {
        runtime.snapshot.lastError = RuntimeHostError::None;
        DesktopWindow window(host);
        auto* credentials =
            requiredLabel(window, "credentialStatus");
        auto* permission =
            requiredLabel(window, "permissionStatus");
        assert(credentials->text().contains("Existing OS Account"));
        assert(permission->text().contains("not established"));
        assert(!window.canStart());

        prepareReadyHost(runtime);
        window.refresh();
        assert(window.canStart());
        assert(sharingToggle(window)->isEnabled());
        return 0;
    }

    // Default full-path regression: one page, auto-address, authoritative
    // toggle, connected-device projection and explicit Stop/Revoke.
    checkDashboardDefaults(runtime, host);
    prepareReadyHost(runtime);
    runtime.startSucceeds = true;
    {
        DesktopWindow window(host);
        auto* toggle = sharingToggle(window);
        auto* copy = requiredButton(window, "copyLanAddress");
        assert(window.canStart() && toggle->isEnabled());
        copy->click();
        assert(
            application.clipboard()->text() ==
            QStringLiteral("192.168.0.10:3389"));

        toggle->click();
        assert(runtime.configureCalls == 1 && runtime.startCalls == 1);
        assert(!toggle->isChecked());

        runtime.snapshot.stage = RuntimeHostStage::ClientConnected;
        runtime.snapshot.listenerAvailable = true;
        runtime.snapshot.boundEndpoint = "192.168.0.10:3389";
        runtime.snapshot.nativeDesktopReady = true;
        runtime.snapshot.activeClients = {
            RuntimeHostClient{
                7U, "192.168.0.44", false, true, true}};
        window.refresh();
        assert(toggle->isChecked());
        assert(
            requiredLabel(window, "clientStatus")
                ->text().contains("192.168.0.44"));

        toggle->click();
        assert(runtime.stopCalls == 1 && runtime.revokeCalls == 1);
        assert(!toggle->isChecked());
    }

    return 0;
}
