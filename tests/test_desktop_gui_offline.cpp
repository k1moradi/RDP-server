// SPDX-License-Identifier: GPL-3.0-or-later
#include "desktop_window.h"
#include "host_control.h"
#include "local_username.h"
#include "server/runtime/runtime_host_control.h"

#if defined(__linux__)
#include "server/runtime/linux_runtime_host_control.h"
#endif
#if defined(__APPLE__)
#include "server/runtime/mac_runtime_host_control.h"
#endif

#include <QAbstractButton>
#include <QAction>
#include <QApplication>
#include <QByteArray>
#include <QCheckBox>
#include <QColorSpace>
#include <QClipboard>
#include <QComboBox>
#include <QFont>
#include <QGroupBox>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QPointF>
#include <QScrollArea>
#include <QScrollBar>
#include <QStringList>
#include <QSpinBox>
#include <QStackedWidget>
#include <QStyleOptionFrame>
#include <QTabWidget>
#include <QWizard>

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>
#include <string_view>
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
    int standaloneCredentialCalls{};
    int permissionSetupCalls{};
    int startCalls{};
    int stopCalls{};
    int revokeCalls{};
    int disconnectCalls{};
    std::uint64_t lastDisconnectedId{};
    bool disconnectSucceeds{};
    bool configureSucceeds{true};
    bool configurePreparesTlsIdentity{};
    bool credentialSetupSucceeds{};
    bool standaloneCredentialSucceeds{};
    bool permissionSetupSucceeds{};
    bool startSucceeds{};
    bool publishListenerOnSuccessfulStart{};
    bool refuseRetirement{};
    bool deriveProductStatusFromLegacy{true};
    std::u16string lastStandaloneUsername;
    std::u16string lastStandalonePassword;
    std::vector<std::string> commandOrder;

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
        result.product.credentialCapabilities
            .standalonePasswordConfigurationAvailable = true;
        result.product.credentialsConfigured =
            result.credentialsConfigured;
        result.product.ownerAuthorized = result.hostOwnerAuthorized;
        if (result.product.controlAvailable &&
            !result.product.sharingPermission.activeGrant &&
            result.product.sharingPermission.denial ==
                RuntimeSharingPermissionDenial::Unavailable)
        {
            result.product.sharingPermission.canRequest = true;
            result.product.sharingPermission.denial =
                RuntimeSharingPermissionDenial::PermissionRequired;
        }
        if (result.stage == RuntimeHostStage::Revoked ||
            result.lastError == RuntimeHostError::AccessRevoked)
        {
            result.product.sharingPermission = {
                false, false, false, false, 0U,
                RuntimeSharingPermissionDenial::PermissionRevoked};
        }
        else if (result.lastError == RuntimeHostError::HostSessionStale)
        {
            result.product.sharingPermission = {
                false, false, false, false, 0U,
                RuntimeSharingPermissionDenial::LoggedInDesktopChanged};
        }
        result.product.tlsIdentityReady = result.tlsIdentityReady;
        if (result.tlsIdentity.fingerprintAvailable)
        {
            result.product.tlsFingerprint =
                result.tlsIdentity.certificateSha256;
            result.product.tlsFingerprintAvailable = true;
        }
        result.product.state = runtimeProductStateFor(
            result.stage, result.lastError, result.nativeDesktopReady);
        result.product.credentialEditingAllowed =
            result.product.controlAvailable &&
            runtimeProductCredentialEditingAllowed(
                result.stage, result.product.state);
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
        commandOrder.emplace_back("endpoint");
        lastOptions = options;
        if (configureSucceeds && configurePreparesTlsIdentity)
        {
            snapshot.tlsIdentityReady = true;
            snapshot.tlsIdentity.state =
                RuntimeTlsIdentityState::ConfiguredUnbound;
            snapshot.tlsIdentity.fingerprintAvailable = true;
            snapshot.tlsIdentity.certificateSha256.fill(0x42U);
        }
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

    [[nodiscard]] bool configureStandaloneApplicationPassword(
        std::u16string_view username,
        std::span<char16_t> password) noexcept override
    {
        ++standaloneCredentialCalls;
        commandOrder.emplace_back("credential");
        lastStandaloneUsername.assign(username.begin(), username.end());
        lastStandalonePassword.assign(password.begin(), password.end());
        const bool valid =
            standaloneCredentialSucceeds && !username.empty() &&
            !password.empty();
        for (char16_t& codeUnit : password)
        {
            volatile char16_t* const volatileCodeUnit = &codeUnit;
            *volatileCodeUnit = u'\0';
        }
        if (valid)
        {
            snapshot.credentialsConfigured = true;
            snapshot.product.configuredStandaloneUsername.assign(
                username.begin(), username.end());
            // Production R2 revokes owner consent whenever the standalone
            // credential generation changes. Model that authority boundary so
            // GUI orchestration cannot accidentally rely on a stale snapshot.
            snapshot.hostOwnerAuthorized = false;
        }
        return valid;
    }

    [[nodiscard]] RuntimeHostResult requestHostPermissionSetup(
        const RuntimeHostPermissionRequest& request = {}) override
    {
        ++permissionSetupCalls;
        commandOrder.emplace_back("permission");
        lastPermissionRequest = request;
        if (permissionSetupSucceeds)
            snapshot.hostOwnerAuthorized = true;
        return permissionSetupSucceeds
            ? RuntimeHostResult{RuntimeHostError::None, false}
            : RuntimeHostResult{
                  RuntimeHostError::ControlUnavailable, false};
    }

    [[nodiscard]] RuntimeHostResult startSharing() override
    {
        ++startCalls;
        commandOrder.emplace_back("listener");
        if (startSucceeds && publishListenerOnSuccessfulStart)
        {
            snapshot.stage = RuntimeHostStage::ListenerAvailable;
            snapshot.listenerAvailable = true;
            snapshot.boundEndpoint =
                lastOptions.localAddress + ":" +
                std::to_string(lastOptions.port);
        }
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
            snapshot.listenerAvailable = false;
            snapshot.boundEndpoint.clear();
            snapshot.hostOwnerAuthorized = false;
            snapshot.tlsIdentityReady = false;
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
            snapshot.credentialsConfigured = false;
            snapshot.hostOwnerAuthorized = false;
            snapshot.listenerAvailable = false;
            snapshot.boundEndpoint.clear();
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

void assertEnabledParentChain(const QWidget& widget)
{
    for (const QWidget* current = &widget;
         current != nullptr;
         current = current->parentWidget())
    {
        assert(current->isEnabled());
    }
}

[[nodiscard]] bool isQtFocusTarget(const QWidget& widget)
{
    if (widget.hasFocus())
        return true;
    const QWidget* const topLevel = widget.window();
    return topLevel != nullptr && topLevel->focusWidget() == &widget;
}

void assertInteractiveCredentialEditor(const QLineEdit& editor)
{
    assert(editor.isVisible());
    assert(editor.isEnabled());
    assert(!editor.isReadOnly());
    assertEnabledParentChain(editor);
    assert(editor.focusPolicy() == Qt::StrongFocus);

    QStyleOptionFrame styleOption;
    styleOption.initFrom(&editor);
    assert(styleOption.state.testFlag(QStyle::State_Enabled));
    assert(editor.cursor().shape() == Qt::IBeamCursor);
}

void typeWithKeyEvents(
    QApplication& application, QLineEdit& editor, const QString& text)
{
    assertInteractiveCredentialEditor(editor);

    if (!isQtFocusTarget(editor))
    {
        editor.setFocus(Qt::OtherFocusReason);
        application.processEvents();
    }
    // Bare Xvfb has no window manager to activate the top-level X11 window.
    // In that environment QWidget::focusWidget() is the deterministic Qt
    // focus-chain target even though QWidget::hasFocus() remains false.
    assert(isQtFocusTarget(editor));
    for (const QChar character : text)
    {
        const QString input{character};
        const int key = static_cast<int>(character.toUpper().unicode());
        QKeyEvent press(QEvent::KeyPress, key, Qt::NoModifier, input);
        QApplication::sendEvent(&editor, &press);
        QKeyEvent release(QEvent::KeyRelease, key, Qt::NoModifier, input);
        QApplication::sendEvent(&editor, &release);
    }
    application.processEvents();
}

void sendTabKey(QApplication& application, QWidget& widget)
{
    assert(isQtFocusTarget(widget));
    QKeyEvent press(
        QEvent::KeyPress, Qt::Key_Tab, Qt::NoModifier,
        QStringLiteral("\t"));
    QApplication::sendEvent(&widget, &press);
    QKeyEvent release(
        QEvent::KeyRelease, Qt::Key_Tab, Qt::NoModifier,
        QStringLiteral("\t"));
    QApplication::sendEvent(&widget, &release);
    application.processEvents();
}

void prepareReadyHost(FakeRuntimeHost& runtime)
{
    runtime.snapshot.lastError = RuntimeHostError::None;
    runtime.snapshot.credentialsConfigured = true;
    runtime.snapshot.hostOwnerAuthorized = true;
    runtime.snapshot.tlsIdentityReady = true;
    runtime.snapshot.product.credentialCapabilities.existingOsAccount = true;
    runtime.snapshot.product.sharingPermission = {
        true, true, true, true, 15U * 60U * 1000U,
        RuntimeSharingPermissionDenial::None};
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

void checkQColorSpaceMetadataFixtures()
{
    const QColorSpace srgb(QColorSpace::SRgb);
    assert(srgb.isValid());

    const QByteArray validIccProfile = srgb.iccProfile();
    assert(!validIccProfile.isEmpty());
    assert(QColorSpace::fromIccProfile(validIccProfile).isValid());

    // Exercise the same public Qt primary-points validation boundary without
    // consulting a physical display, ColorSync, EDID or a host ICC profile.
    const QColorSpace validPrimaries(
        QPointF(0.3127, 0.3290),
        QPointF(0.6400, 0.3300),
        QPointF(0.3000, 0.6000),
        QPointF(0.1500, 0.0600),
        QColorSpace::TransferFunction::SRgb);
    assert(validPrimaries.isValid());

    // Qt validates each chromaticity independently. Make one point
    // unambiguously invalid (x + y > 1) rather than assuming duplicate
    // primaries are rejected. This may emit Qt's diagnostic here; the fixture
    // proves only validation behavior, never the provenance of an owner's
    // Cocoa/display-profile warning.
    const QColorSpace malformedPrimaries(
        QPointF(0.3127, 0.3290),
        QPointF(0.6400, 0.3300),
        QPointF(0.3000, 0.6000),
        QPointF(0.8000, 0.4000),
        QColorSpace::TransferFunction::SRgb);
    assert(!malformedPrimaries.isValid());

    const QByteArray malformedIccProfile =
        QByteArrayLiteral("not-an-icc-profile");
    assert(!QColorSpace::fromIccProfile(malformedIccProfile).isValid());
}

void checkRound2TabsAndMainSimplicity(
    FakeRuntimeHost& runtime, HostControl& host)
{
    runtime.snapshot.lastError = RuntimeHostError::None;
    runtime.interfaces = {
        RuntimeHostInterface{
            "ethernet-1", "Private Ethernet",
            {"192.168.1.42"}, false, true}};

    DesktopWindow window(host);
    assert(window.findChild<QWizard*>() == nullptr);
    assert(window.findChild<QObject*>("backPage") == nullptr);
    assert(window.findChild<QObject*>("nextPage") == nullptr);
    auto* username = window.findChild<QLineEdit*>("standaloneUsername");
    auto* password = window.findChild<QLineEdit*>("sessionPassword");
    auto* confirmation =
        window.findChild<QLineEdit*>("sessionPasswordConfirm");
    assert(username && password && confirmation);
    assert(window.findChild<QObject*>("allowClipboard") == nullptr);
    for (QObject* item : window.findChildren<QObject*>())
        assert(!item->objectName().contains(
            QStringLiteral("clipboard"), Qt::CaseInsensitive));
    assert(window.findChild<QObject*>(
               "setApplicationPasswordUnsupported") == nullptr);
    assert(window.findChild<QObject*>("advancedDisclosure") == nullptr);
    assert(window.findChild<QObject*>("advancedPanel") == nullptr);

    const auto tabContainers = window.findChildren<QTabWidget*>();
    assert(tabContainers.size() == 1);
    auto* tabs = tabContainers.front();
    assert(tabs->objectName() == QStringLiteral("settingsTabs"));
    assert(tabs->count() == 2);
    assert(tabs->tabText(0) == QStringLiteral("Main"));
    assert(tabs->tabText(1) == QStringLiteral("Advanced"));
    assert(tabs->currentIndex() == 0);

    // QTabWidget implements its pages with an internal QStackedWidget.
    // The source contract rejects application-created wizard/stacked-page
    // navigation; at runtime any stack must therefore remain inside the one
    // approved tab container rather than act as a competing top-level flow.
    for (QStackedWidget* stack : window.findChildren<QStackedWidget*>())
        assert(tabs->isAncestorOf(stack));

    auto* mainTab = window.findChild<QWidget*>("mainTab");
    auto* advancedTab = window.findChild<QWidget*>("advancedTab");
    assert(mainTab && advancedTab);
    assert(tabs->widget(0) == mainTab);
    assert(tabs->widget(1) == advancedTab);

    auto* title = requiredLabel(window, "serverStateTitle");
    auto* address = requiredLabel(window, "connectionAddress");
    auto* copy = requiredButton(window, "copyLanAddress");
    auto* credential = requiredLabel(window, "credentialStatus");
    auto* toggle = sharingToggle(window);
    auto* input = window.findChild<QCheckBox*>("allowRemoteInput");
    auto* permissionRequest = requiredButton(window, "requestHostPermission");
    auto* clients = requiredCombo(window, "activeClientSelection");
    auto* disconnect = requiredButton(window, "disconnectClient");
    assert(input);

    assert(mainTab->isAncestorOf(title));
    assert(mainTab->isAncestorOf(address));
    assert(mainTab->isAncestorOf(copy));
    assert(mainTab->isAncestorOf(credential));
    assert(mainTab->isAncestorOf(toggle));
    assert(mainTab->isAncestorOf(input));
    assert(!mainTab->isAncestorOf(permissionRequest));
    assert(advancedTab->isAncestorOf(permissionRequest));
    assert(mainTab->isAncestorOf(username));
    assert(mainTab->isAncestorOf(password));
    assert(mainTab->isAncestorOf(confirmation));
    assert(mainTab->isAncestorOf(clients));
    assert(mainTab->isAncestorOf(disconnect));

    auto* interfaceOverride = requiredCombo(window, "lanInterface");
    auto* port = window.findChild<QSpinBox*>("sharingPort");
    auto* lifetime =
        window.findChild<QSpinBox*>("ownerPermissionLifetimeMinutes");
    auto* permission = requiredLabel(window, "permissionStatus");
    auto* authMode = requiredLabel(window, "authenticationModeStatus");
    auto* tls = requiredLabel(window, "tlsIdentityStatus");
    auto* selected = requiredLabel(window, "selectedLanInterfaceStatus");
    auto* lifecycle = requiredLabel(window, "hostLifecycleStatus");
    auto* productStatus = requiredLabel(window, "sharingReadinessStatus");
    auto* runtimeReadiness = requiredLabel(window, "runtimeReadinessStatus");
    auto* clientSummary = requiredLabel(window, "clientStatus");
    auto* error = requiredLabel(window, "hostErrorExplanation");
    auto* scroll = window.findChild<QScrollArea*>("advancedScrollArea");
    assert(port && lifetime && scroll);

    for (QWidget* advancedOnly :
         {static_cast<QWidget*>(interfaceOverride),
          static_cast<QWidget*>(port),
          static_cast<QWidget*>(lifetime),
          static_cast<QWidget*>(permission),
          static_cast<QWidget*>(authMode),
          static_cast<QWidget*>(tls),
          static_cast<QWidget*>(selected),
          static_cast<QWidget*>(lifecycle),
          static_cast<QWidget*>(productStatus),
          static_cast<QWidget*>(runtimeReadiness),
          static_cast<QWidget*>(clientSummary),
          static_cast<QWidget*>(error)})
    {
        assert(advancedTab->isAncestorOf(advancedOnly));
        assert(!mainTab->isAncestorOf(advancedOnly));
    }

    assert(scroll->widgetResizable());
    assert(scroll->widget());
    assert(advancedTab->isAncestorOf(scroll->widget()));
    for (const char* groupName :
         {"networkGroup", "securityGroup", "desktopGroup", "diagnosticsGroup"})
    {
        auto* group = window.findChild<QGroupBox*>(groupName);
        assert(group && advancedTab->isAncestorOf(group));
    }

#if defined(__linux__)
    auto* linuxStatus = requiredLabel(window, "linuxPrerequisiteStatus");
    auto* linuxRefresh =
        requiredButton(window, "refreshLinuxPrerequisites");
    assert(advancedTab->isAncestorOf(linuxStatus));
    assert(advancedTab->isAncestorOf(linuxRefresh));
#endif

    assert(title->text() == QStringLiteral("RDP Server — Stopped"));
    assert(address->text() ==
           QStringLiteral("Local address: 192.168.1.42"));
    assert(!copy->isEnabled());
    assert(credential->text().contains("Session Password"));
    assert(!toggle->isChecked() && !toggle->isEnabled());
    assertNoRoadLabelsInUserText(window);
    assertNoRoadLabelsInUserText(window);
}

void checkRound2AdvancedGroupsScrollable(
    FakeRuntimeHost& runtime,
    HostControl& host,
    QApplication& application)
{
    runtime.snapshot.lastError = RuntimeHostError::None;
    runtime.interfaces = {
        RuntimeHostInterface{
            "ethernet-1", "Private Ethernet",
            {"192.168.1.42"}, false, true}};

    DesktopWindow window(host);
    window.resize(560, 520);
    window.show();
    application.processEvents();

    auto* tabs = window.findChild<QTabWidget*>("settingsTabs");
    auto* scroll = window.findChild<QScrollArea*>("advancedScrollArea");
    assert(tabs && scroll && tabs->count() == 2);
    tabs->setCurrentIndex(1);
    application.processEvents();
    assert(scroll->isVisible());
    assert(scroll->widgetResizable());
    assert(scroll->widget());

    scroll->widget()->setMinimumHeight(scroll->viewport()->height() + 240);
    application.processEvents();
    auto* vertical = scroll->verticalScrollBar();
    assert(vertical && vertical->maximum() > 0);
    vertical->setValue(vertical->maximum());
    assert(vertical->value() == vertical->maximum());
    scroll->ensureWidgetVisible(
        requiredLabel(window, "hostErrorExplanation"));
    application.processEvents();
}

void checkRound2RecommendationRefreshFailClosed()
{
    FakeRuntimeHost runtime;
    runtime.deriveProductStatusFromLegacy = false;
    runtime.snapshot.lastError = RuntimeHostError::None;
    runtime.snapshot.product.controlAvailable = true;
    runtime.snapshot.product.state = RuntimeProductHostState::Stopped;
    runtime.snapshot.product.credentialCapabilities.existingOsAccount = true;
    runtime.snapshot.product.eligibleLanInterfaces = {
        {"lan-default", "Ethernet", {"192.168.1.5"}, false, true},
        {"vpn-virtual", "VPN", {"10.180.105.86"}, false, true}};
    runtime.snapshot.product.recommendedEndpoint = {
        "lan-default", "192.168.1.5", 3389U,
        RuntimeHostAddressFamily::Ipv4, true, true, {}, false,
        RuntimeHostRecommendationSource::PreferredRoute};

    HostControl host(runtime);
    DesktopWindow window(host);
    auto* address = requiredLabel(window, "connectionAddress");
    auto* copy = requiredButton(window, "copyLanAddress");
    auto* trayCopy = requiredAction(window, "trayCopyAddress");
    auto* interfaceOverride = requiredCombo(window, "lanInterface");
    assert(address->text() ==
           QStringLiteral("Local address: 192.168.1.5"));
    assert(!copy->isEnabled() && !trayCopy->isEnabled());
    assert(interfaceOverride->currentData().toString() ==
           QStringLiteral("192.168.1.5"));

    interfaceOverride->setCurrentIndex(2);
    assert(interfaceOverride->currentData().toString() ==
           QStringLiteral("10.180.105.86"));
    assert(address->text() ==
           QStringLiteral("Local address: 192.168.1.5"));

    runtime.snapshot.product.recommendedEndpoint = {};
    runtime.snapshot.product.recommendedEndpoint.ambiguous = true;
    runtime.snapshot.product.recommendedEndpoint.source =
        RuntimeHostRecommendationSource::Ambiguous;
    window.refresh();
    assert(host.status().recommendationSource ==
           RuntimeHostRecommendationSource::Ambiguous);
    assert(address->text() ==
           QStringLiteral(
               "Multiple private networks found. Choose a network in Advanced."));
    assert(!copy->isEnabled() && !trayCopy->isEnabled());
    assert(interfaceOverride->currentData().toString() ==
           QStringLiteral("10.180.105.86"));

    runtime.snapshot.product.recommendedEndpoint = {};
    window.refresh();
    assert(host.status().recommendationSource ==
           RuntimeHostRecommendationSource::Unavailable);
    assert(address->text() ==
           QStringLiteral(
               "Automatic network selection unavailable. Choose a network in Advanced."));
    assert(!copy->isEnabled() && !trayCopy->isEnabled());
}

void checkDashboardPresentationPolish()
{
    FakeRuntimeHost runtime;
    runtime.snapshot.lastError = RuntimeHostError::None;
    runtime.interfaces = {
        RuntimeHostInterface{
            "ethernet-1", "Private Ethernet",
            {"192.168.1.42"}, false, true}};
    HostControl host(runtime);
    DesktopWindow window(host);

    auto* address = requiredLabel(window, "connectionAddress");
    assert(address->text() ==
           QStringLiteral("Local address: 192.168.1.42"));
    const QFont addressFont = address->font();
    assert(addressFont.bold());
    const auto basePointSize = window.font().pointSizeF();
    if (basePointSize > 0.0)
        assert(addressFont.pointSizeF() > basePointSize);
    const auto interaction = address->textInteractionFlags();
    assert(interaction.testFlag(Qt::TextSelectableByMouse));
    assert(interaction.testFlag(Qt::TextSelectableByKeyboard));
    assert(address->accessibleName() ==
           QStringLiteral("Remote Desktop address"));

    UnavailableRuntimeHostControl unavailableRuntime;
    HostControl unavailableHost(unavailableRuntime);
    DesktopWindow unavailableWindow(unavailableHost);
    auto* platform = requiredLabel(
        unavailableWindow, "platformSupportStatus");
    auto* credential = requiredLabel(
        unavailableWindow, "credentialStatus");
    auto* permission = requiredLabel(
        unavailableWindow, "permissionStatus");
    auto* readiness = requiredLabel(
        unavailableWindow, "sharingReadinessStatus");

    assert(!platform->isHidden());
    assert(platform->text().startsWith(
        QStringLiteral("Remote hosting is not available")));
    assert(credential->isHidden());
    assert(permission->isHidden());
    assert(readiness->isHidden());
}

} // namespace

int main(int argc, char** argv)
{
    QApplication application(argc, argv);

    FakeRuntimeHost runtime;
    HostControl host(runtime);
    const QString mode =
        argc > 1 ? QString::fromLocal8Bit(argv[1]) : QString();

    if (mode == "automatic-tls-preparation-order")
    {
        FakeRuntimeHost runtime;
        prepareReadyHost(runtime);
        runtime.snapshot.tlsIdentityReady = false;
        runtime.configurePreparesTlsIdentity = true;
        runtime.startSucceeds = true;
        HostControl host(runtime);
        DesktopWindow window(host);
        assert(window.canStart());
        assert(host.start({
            QStringLiteral("ethernet-1"),
            QStringLiteral("192.168.0.10"), 3389U}));
        assert(runtime.configureCalls == 1);
        assert(runtime.startCalls == 1);

        FakeRuntimeHost missingIdentity;
        prepareReadyHost(missingIdentity);
        missingIdentity.snapshot.tlsIdentityReady = false;
        missingIdentity.startSucceeds = true;
        HostControl denied(missingIdentity);
        assert(!denied.start({
            QStringLiteral("ethernet-1"),
            QStringLiteral("192.168.0.10"), 3389U}));
        assert(missingIdentity.configureCalls == 1);
        assert(missingIdentity.startCalls == 0);
        return 0;
    }

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

#if defined(__APPLE__)
    if (mode == "macos-real-host-control")
    {
#if !defined(RDP_SERVER_OWNER_ACCEPTANCE_TEST_UI)
        return 77;
#endif
        MacRuntimeHostControl realRuntime;
        HostControl controller(realRuntime);
        DesktopWindow window(controller);
        auto* toggle = sharingToggle(window);
        auto* copy = requiredButton(window, "copyLanAddress");
        auto* username = window.findChild<QLineEdit*>("standaloneUsername");
        auto* password = window.findChild<QLineEdit*>("sessionPassword");
        auto* confirmation = window.findChild<QLineEdit*>("sessionPasswordConfirm");

        assert(controller.status().controlAvailable);
        assert(username && password && confirmation);
        assert(username->isEnabled() && !username->isReadOnly());
        assert(password->isEnabled() && !password->isReadOnly());
        assert(confirmation->isEnabled() && !confirmation->isReadOnly());
        assert(!window.canStart());
        assert(!toggle->isEnabled() && !toggle->isChecked());
        assert(!copy->isEnabled());

        controller.stopAndRevoke();
        window.refresh();
        assert(controller.status().stage == RuntimeHostStage::Revoked);
        return 0;
    }

    if (mode == "macos-gui-parity")
    {
#if !defined(RDP_SERVER_OWNER_ACCEPTANCE_TEST_UI)
        return 77;
#endif
        MacRuntimeHostControl realRuntime;
        HostControl host(realRuntime);
        DesktopWindow window(host);
        window.show();
        application.processEvents();
        auto* username = window.findChild<QLineEdit*>("standaloneUsername");
        auto* password = window.findChild<QLineEdit*>("sessionPassword");
        auto* confirmation = window.findChild<QLineEdit*>("sessionPasswordConfirm");
        auto* toggle = sharingToggle(window);
        auto* copy = requiredButton(window, "copyLanAddress");
        auto* address = requiredLabel(window, "connectionAddress");

        assert(username && password && confirmation && toggle && copy && address);

        // 1. Exact widget properties
        assert(username->isVisible());
        assert(username->isEnabled());
        assert(!username->isReadOnly());
        assert(username->echoMode() == QLineEdit::Normal);
        assert(username->focusPolicy() == Qt::StrongFocus);
        assert(username->text() == currentLocalUsernameSuggestion());
        if (!username->text().isEmpty())
            assert(isSafeLocalUsernameSuggestion(username->text()));

        assert(password->isVisible());
        assert(password->isEnabled());
        assert(!password->isReadOnly());
        assert(password->echoMode() == QLineEdit::Password);
        assert(password->focusPolicy() == Qt::StrongFocus);
        assert(password->text().isEmpty());

        assert(confirmation->isVisible());
        assert(confirmation->isEnabled());
        assert(!confirmation->isReadOnly());
        assert(confirmation->echoMode() == QLineEdit::Password);
        assert(confirmation->focusPolicy() == Qt::StrongFocus);
        assert(confirmation->text().isEmpty());

        // 2. Keyboard entry simulation
        username->clear();
        QKeyEvent userKey(QEvent::KeyPress, Qt::Key_U, Qt::NoModifier, QStringLiteral("u"));
        QApplication::sendEvent(username, &userKey);
        assert(username->text() == QStringLiteral("u"));

        QKeyEvent passKey(QEvent::KeyPress, Qt::Key_P, Qt::NoModifier, QStringLiteral("p"));
        QApplication::sendEvent(password, &passKey);
        assert(password->text() == QStringLiteral("p"));
        assert(password->echoMode() == QLineEdit::Password);

        QKeyEvent confKey(QEvent::KeyPress, Qt::Key_X, Qt::NoModifier, QStringLiteral("x"));
        QApplication::sendEvent(confirmation, &confKey);
        assert(confirmation->text() == QStringLiteral("x"));
        assert(confirmation->echoMode() == QLineEdit::Password);

        // Mismatched passwords: canStart is false, toggle remains disabled and unchecked
        assert(!window.canStart());
        assert(!toggle->isEnabled());
        assert(!toggle->isChecked());

        // Matching passwords
        confirmation->clear();
        QKeyEvent confMatchKey(QEvent::KeyPress, Qt::Key_P, Qt::NoModifier, QStringLiteral("p"));
        QApplication::sendEvent(confirmation, &confMatchKey);
        assert(confirmation->text() == password->text());
        assert(window.canStart());
        assert(toggle->isEnabled());
        assert(!toggle->isChecked());

        // 3. Focus / tab order verification
        username->setFocus();
        assert(username->hasFocus());
        password->setFocus();
        assert(password->hasFocus());
        confirmation->setFocus();
        assert(confirmation->hasFocus());

        return 0;
    }
#endif

    if (mode == "qcolor-metadata")
    {
        checkQColorSpaceMetadataFixtures();
        return 0;
    }

    if (mode == "round2-tabs")
    {
        checkRound2TabsAndMainSimplicity(runtime, host);
        return 0;
    }

    if (mode == "round2-endpoint-refresh")
    {
        checkRound2RecommendationRefreshFailClosed();
        return 0;
    }

    if (mode == "round2-advanced-scroll")
    {
        checkRound2AdvancedGroupsScrollable(runtime, host, application);
        return 0;
    }

    if (mode == "dashboard-polish")
    {
        checkDashboardPresentationPolish();
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
        assert(title->text().contains("Sharing"));

        runtime.refuseRetirement = true;
        toggle->click();
        assert(runtime.stopCalls == 1 && runtime.revokeCalls == 0);
        assert(toggle->isChecked());
        assert(title->text().contains("Sharing"));

        runtime.refuseRetirement = false;
        // The refusal case above deliberately switched this fake to an
        // explicit authoritative Stopping product snapshot. Restore the
        // ordinary legacy-derived fake before emulating runtime-confirmed
        // ordinary Stop; otherwise stale Stopping remains authoritative.
        runtime.deriveProductStatusFromLegacy = true;
        runtime.snapshot.stage = RuntimeHostStage::Stopped;
        runtime.snapshot.listenerAvailable = false;
        runtime.snapshot.boundEndpoint.clear();
        runtime.snapshot.hostOwnerAuthorized = false;
        window.refresh();
        assert(!toggle->isChecked());
        assert(toggle->isEnabled());
        assert(title->text().contains("Stopped"));
        return 0;
    }

    if (mode == "tray-lifecycle")
    {
        prepareReadyHost(runtime);
        runtime.snapshot.stage = RuntimeHostStage::ClientConnected;
        runtime.snapshot.listenerAvailable = true;
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

    if (mode == "rdp-client-credential-guidance")
    {
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.snapshot.product.credentialCapabilities.standalonePassword =
            true;
        runtime.interfaces = {
            RuntimeHostInterface{
                "ethernet-1", "Private Ethernet",
                {"192.168.0.10"}, false, true}};
        runtime.standaloneCredentialSucceeds = true;
        runtime.permissionSetupSucceeds = true;
        runtime.configurePreparesTlsIdentity = true;
        runtime.startSucceeds = true;

        DesktopWindow window(host);
        auto* mainTab = window.findChild<QWidget*>("mainTab");
        auto* advancedTab = window.findChild<QWidget*>("advancedTab");
        auto* guidance =
            requiredLabel(window, "rdpClientCredentialGuidance");
        auto* username =
            window.findChild<QLineEdit*>("standaloneUsername");
        auto* password =
            window.findChild<QLineEdit*>("sessionPassword");
        auto* confirmation =
            window.findChild<QLineEdit*>("sessionPasswordConfirm");
        assert(mainTab && advancedTab && username && password && confirmation);
        assert(mainTab->isAncestorOf(guidance));
        assert(!advancedTab->isAncestorOf(guidance));
        assert(!guidance->isHidden());
        assert(guidance->textFormat() == Qt::PlainText);
        assert(guidance->text() ==
               QStringLiteral(
                   "Use this Username and Session Password as the credentials "
                   "in your RDP client."));
        assert(!guidance->text().contains(
            QStringLiteral("automatically"), Qt::CaseInsensitive));
        assert(password->echoMode() == QLineEdit::Password);
        assert(confirmation->echoMode() == QLineEdit::Password);

        username->setText(QStringLiteral("owner"));
        password->setText(QStringLiteral("owner-test-password"));
        confirmation->setText(password->text());
        assert(window.canStart());

        sharingToggle(window)->click();
        assert(runtime.standaloneCredentialCalls == 1);
        assert(runtime.lastStandaloneUsername == u"owner");
        assert(runtime.lastStandalonePassword == u"owner-test-password");
        assert(username->text() == QStringLiteral("owner"));
        assert(password->text().isEmpty());
        assert(confirmation->text().isEmpty());
        assert(!guidance->isHidden());
        assert(guidance->text() ==
               QStringLiteral(
                   "Use this Username and Session Password as the credentials "
                   "in your RDP client."));

        for (QLabel* item : window.findChildren<QLabel*>())
        {
            assert(!item->text().contains(
                QStringLiteral("owner-test-password")));
        }
        for (QAbstractButton* button :
             window.findChildren<QAbstractButton*>())
        {
            assert(button->text() != QStringLiteral("Copy Password"));
        }
        assertNoRoadLabelsInUserText(window);
        return 0;
    }


    if (mode == "configured-username-replacement")
    {
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.snapshot.product.credentialCapabilities.standalonePassword = true;
        runtime.interfaces = {
            RuntimeHostInterface{
                "ethernet-1", "Private Ethernet",
                {"192.168.0.10"}, false, true}};
        runtime.standaloneCredentialSucceeds = true;
        runtime.permissionSetupSucceeds = true;
        runtime.configurePreparesTlsIdentity = true;
        runtime.startSucceeds = true;
        runtime.publishListenerOnSuccessfulStart = true;

        DesktopWindow window(host);
        auto* username =
            window.findChild<QLineEdit*>("standaloneUsername");
        auto* password =
            window.findChild<QLineEdit*>("sessionPassword");
        auto* confirmation =
            window.findChild<QLineEdit*>("sessionPasswordConfirm");
        auto* guidance =
            requiredLabel(window, "rdpClientCredentialGuidance");
        auto* toggle = sharingToggle(window);
        assert(username && password && confirmation);

        username->setText(QStringLiteral("original-owner"));
        password->setText(QStringLiteral("original-test-password"));
        confirmation->setText(password->text());
        assert(window.canStart());
        toggle->click();
        assert(toggle->isChecked());
        assert(runtime.lastStandaloneUsername == u"original-owner");
        assert(runtime.standaloneCredentialCalls == 1);
        assert(password->text().isEmpty() && confirmation->text().isEmpty());

        toggle->click();
        assert(!toggle->isChecked());
        assert(username->isEnabled() && !username->isReadOnly());
        assert(host.status().credentialsConfigured);
        assert(runtime.revokeCalls == 0);

        username->setText(QStringLiteral("different-owner"));
        assert(!window.canStart());
        assert(window.blockedReason() ==
               QStringLiteral(
                   "Enter and confirm a new Session Password to change Username"));
        assert(guidance->text() ==
               QStringLiteral(
                   "To use the changed Username, enter and confirm a new "
                   "Session Password, then turn Sharing ON."));
        assert(!toggle->isEnabled());
        assert(runtime.standaloneCredentialCalls == 1);
        assert(runtime.lastStandaloneUsername == u"original-owner");

        // Restoring the committed identifier reuses the existing credential.
        username->setText(QStringLiteral("original-owner"));
        assert(window.canStart());
        assert(guidance->text() ==
               QStringLiteral(
                   "Use this Username and Session Password as the credentials "
                   "in your RDP client."));
        assert(runtime.standaloneCredentialCalls == 1);

        // A new identifier takes effect only with a matching replacement.
        username->setText(QStringLiteral("different-owner"));
        password->setText(QStringLiteral("replacement-test-password"));
        confirmation->setText(QStringLiteral("different-confirmation"));
        assert(!window.canStart());
        confirmation->setText(password->text());
        assert(window.canStart());
        toggle->click();
        assert(toggle->isChecked());
        assert(runtime.standaloneCredentialCalls == 2);
        assert(runtime.lastStandaloneUsername == u"different-owner");
        assert(password->text().isEmpty() && confirmation->text().isEmpty());
        assert(guidance->text() ==
               QStringLiteral(
                   "Use this Username and Session Password as the credentials "
                   "in your RDP client."));
        for (QLabel* item : window.findChildren<QLabel*>())
            assert(!item->text().contains(
                QStringLiteral("replacement-test-password")));
        return 0;
    }

    if (mode == "unsupported-password")
    {
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.interfaces = {
            RuntimeHostInterface{
                "ethernet-1", "Private Ethernet",
                {"192.168.0.10"}, false, true}};
        DesktopWindow window(host);
        assert(window.findChild<QLineEdit*>("standaloneUsername"));
        assert(window.findChild<QLineEdit*>("sessionPassword"));
        assert(window.findChild<QLineEdit*>("sessionPasswordConfirm"));
        assert(
            requiredLabel(window, "credentialStatus")
                ->text().contains("Session Password"));
        assert(!runtime.snapshot.product.credentialCapabilities.standalonePassword);
        return 0;
    }

    if (mode == "owner-gui-credential-parity")
    {
#if !defined(RDP_SERVER_OWNER_ACCEPTANCE_TEST_UI)
        return 77;
#endif
        static_assert(!kStandalonePasswordProductCapabilityApproved);
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.interfaces = {
            RuntimeHostInterface{
                "ethernet-1", "Private Ethernet",
                {"192.168.1.5"}, false, true}};
        runtime.standaloneCredentialSucceeds = true;
        runtime.permissionSetupSucceeds = true;
        runtime.configurePreparesTlsIdentity = true;
        runtime.startSucceeds = true;

        DesktopWindow window(host);
        window.show();
        application.processEvents();

        auto* tabs = window.findChild<QTabWidget*>("settingsTabs");
        auto* mainTab = window.findChild<QWidget*>("mainTab");
        auto* username =
            window.findChild<QLineEdit*>("standaloneUsername");
        auto* password =
            window.findChild<QLineEdit*>("sessionPassword");
        auto* confirmation =
            window.findChild<QLineEdit*>("sessionPasswordConfirm");
        auto* toggle = sharingToggle(window);
        auto* copy = requiredButton(window, "copyLanAddress");
        auto* address = requiredLabel(window, "connectionAddress");
        auto* readiness = requiredLabel(window, "sharingReadinessStatus");
        auto* availability =
            requiredLabel(window, "sharingAvailabilityStatus");
        assert(tabs && mainTab && username && password && confirmation);
        assert(tabs->isEnabled());
        assert(mainTab->isEnabled());
        assert(tabs->isTabEnabled(0));
        assert(tabs->currentWidget() == mainTab);

        for (QLineEdit* editor : {username, password, confirmation})
            assertInteractiveCredentialEditor(*editor);
        assert(username->echoMode() == QLineEdit::Normal);
        assert(password->echoMode() == QLineEdit::Password);
        assert(confirmation->echoMode() == QLineEdit::Password);
#if defined(__linux__)
        assert(!username->styleSheet().isEmpty());
        assert(username->styleSheet() == password->styleSheet());
        assert(password->styleSheet() == confirmation->styleSheet());
#endif
        assert(address->text() ==
               QStringLiteral("Local address: 192.168.1.5"));
        assert(!copy->isEnabled());
        assert(!toggle->isChecked());
        assert(!host.status().listenerReady);
        assert(runtime.startCalls == 0);
        assert(window.blockedReason() ==
               QStringLiteral("Enter a Session Password"));
        assert(availability->text() ==
               QStringLiteral("Enter a Session Password"));

        username->clear();
        username->setFocus(Qt::OtherFocusReason);
        application.processEvents();
        assert(isQtFocusTarget(*username));
        typeWithKeyEvents(
            application, *username, QStringLiteral("owner"));

        sendTabKey(application, *username);
        assert(isQtFocusTarget(*password));
        typeWithKeyEvents(
            application, *password, QStringLiteral("ownertest123"));

        sendTabKey(application, *password);
        assert(isQtFocusTarget(*confirmation));
        typeWithKeyEvents(
            application, *confirmation, QStringLiteral("different123"));
        assert(username->text() == QStringLiteral("owner"));
        assert(password->text() == QStringLiteral("ownertest123"));
        assert(confirmation->text() == QStringLiteral("different123"));
        assert(!window.canStart());
        assert(!toggle->isEnabled());
        assert(window.blockedReason().contains(
            QStringLiteral("does not match")));
        assert(readiness->text().contains(
            QStringLiteral("does not match")));
        assert(availability->text().contains(
            QStringLiteral("does not match")));

        confirmation->clear();
        typeWithKeyEvents(
            application, *confirmation, QStringLiteral("ownertest123"));
        assert(window.canStart());
        assert(toggle->isEnabled());
        assert(availability->isHidden());
        for (QLineEdit* editor : {username, password, confirmation})
            assertInteractiveCredentialEditor(*editor);

        toggle->click();
        assert(runtime.standaloneCredentialCalls == 1);
        assert(runtime.lastStandaloneUsername == u"owner");
        assert(runtime.lastStandalonePassword == u"ownertest123");
        assert(runtime.permissionSetupCalls == 1);
        assert(runtime.lastPermissionRequest.allowInput);
        assert(!runtime.lastPermissionRequest.allowClipboard);
        assert(runtime.configureCalls == 1);
        assert(runtime.startCalls == 1);
        assert(runtime.lastOptions.interfaceId == "ethernet-1");
        assert(runtime.lastOptions.localAddress == "192.168.1.5");
        assert(runtime.lastOptions.port == 3389U);
        assert((runtime.commandOrder ==
                std::vector<std::string>{
                    "credential", "permission", "endpoint", "listener"}));
        assert(password->text().isEmpty());
        assert(confirmation->text().isEmpty());

        // Command success is not listener authority. Presentation stays
        // pre-listener until the runtime publishes the bound endpoint.
        assert(!host.status().listenerReady);
        assert(!toggle->isChecked());
        assert(address->text() ==
               QStringLiteral("Local address: 192.168.1.5"));
        assert(!copy->isEnabled());

        runtime.snapshot.stage = RuntimeHostStage::ListenerAvailable;
        runtime.snapshot.listenerAvailable = true;
        runtime.snapshot.boundEndpoint = "192.168.1.5:3389";
        window.refresh();
        assert(host.status().listenerReady);
        assert(toggle->isChecked());
        assert(address->text() ==
               QStringLiteral("Connect to: 192.168.1.5:3389"));
        assert(copy->isEnabled());
        for (QLineEdit* editor : {username, password, confirmation})
        {
            assert(!editor->isEnabled());
            assert(editor->isReadOnly());
        }
        return 0;
    }

    if (mode == "owner-acceptance-editor-properties")
    {
#if !defined(RDP_SERVER_OWNER_ACCEPTANCE_TEST_UI)
        // The public Release surface intentionally remains gated off.
        // Qualification builds compile this exact test with the acceptance
        // surface enabled; ordinary Release runs register a benign skip.
        return 77;
#else
        static_assert(!kStandalonePasswordProductCapabilityApproved);
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.interfaces = {
            RuntimeHostInterface{
                "ethernet-1", "Private Ethernet",
                {"192.168.1.5"}, false, true}};
        runtime.snapshot.product.credentialCapabilities.standalonePassword = false;

        DesktopWindow window(host);
        window.show();
        application.processEvents();

        auto* username = window.findChild<QLineEdit*>("standaloneUsername");
        auto* password = window.findChild<QLineEdit*>("sessionPassword");
        auto* confirmation =
            window.findChild<QLineEdit*>("sessionPasswordConfirm");
        assert(username && password && confirmation);

        for (QLineEdit* editor : {username, password, confirmation})
        {
            assert(editor->isVisible());
            assert(editor->isEnabled());
            assert(!editor->isReadOnly());
            assert(editor->focusPolicy() != Qt::NoFocus);
            assert(editor->parentWidget() != nullptr);
            assert(editor->parentWidget()->isEnabled());
        }
        assert(username->echoMode() == QLineEdit::Normal);
        assert(password->echoMode() == QLineEdit::Password);
        assert(confirmation->echoMode() == QLineEdit::Password);

        username->setText(QStringLiteral("owner"));
        password->setText(QStringLiteral("owner-test-password"));
        confirmation->setText(password->text());
        application.processEvents();
        assert(username->text() == QStringLiteral("owner"));
        assert(password->text() == QStringLiteral("owner-test-password"));
        assert(confirmation->text() == password->text());
        assert(window.canStart());
        assert(sharingToggle(window)->isEnabled());

        // Property/editability observation is non-authorizing.
        assert(runtime.standaloneCredentialCalls == 0);
        assert(runtime.permissionSetupCalls == 0);
        assert(runtime.configureCalls == 0);
        assert(runtime.startCalls == 0);
        return 0;
#endif
    }

    if (mode == "debug-owner-acceptance-release-gate")
    {
#if !defined(RDP_SERVER_OWNER_ACCEPTANCE_TEST_UI)
        // This test target keeps assertions enabled with -UNDEBUG even in a
        // Release build, so NDEBUG cannot describe the linked UI library.
        // CMake supplies this macro only for Debug or explicit acceptance UI.
        return 77;
#endif
        static_assert(!kStandalonePasswordProductCapabilityApproved);
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.interfaces = {
            RuntimeHostInterface{
                "ethernet-1", "Private Ethernet",
                {"192.168.0.10"}, false, true}};
        runtime.snapshot.product.credentialCapabilities.standalonePassword = false;

        DesktopWindow window(host);
        auto* username = window.findChild<QLineEdit*>("standaloneUsername");
        auto* password = window.findChild<QLineEdit*>("sessionPassword");
        auto* confirmation =
            window.findChild<QLineEdit*>("sessionPasswordConfirm");
        assert(username && password && confirmation);
        assert(!username->isHidden());
        assert(!password->isHidden());
        assert(!confirmation->isHidden());
        assert(!runtime.snapshot.product.credentialCapabilities.standalonePassword);
        assert(!sharingToggle(window)->isEnabled());
        return 0;
    }

    if (mode == "consumer-workflow")
    {
#if !defined(RDP_SERVER_OWNER_ACCEPTANCE_TEST_UI)
        // This test target keeps assertions enabled with -UNDEBUG even in a
        // Release build, so NDEBUG cannot describe the linked UI library.
        // CMake supplies this macro only for Debug or explicit acceptance UI.
        return 77;
#endif
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.interfaces = {
            RuntimeHostInterface{
                "ethernet-1", "Private Ethernet",
                {"192.168.0.10"}, false, true}};
        runtime.standaloneCredentialSucceeds = true;
        runtime.permissionSetupSucceeds = true;
        runtime.configurePreparesTlsIdentity = true;
        runtime.startSucceeds = true;

        DesktopWindow window(host);
        auto* password =
            window.findChild<QLineEdit*>("sessionPassword");
        auto* confirmation =
            window.findChild<QLineEdit*>("sessionPasswordConfirm");
        auto* toggle = sharingToggle(window);
        auto* copy = requiredButton(window, "copyLanAddress");
        auto* address = requiredLabel(window, "connectionAddress");
        assert(password && confirmation);
        assert(address->text() ==
               QStringLiteral("Local address: 192.168.0.10"));
        assert(!copy->isEnabled());

        password->setText(QStringLiteral("owner-test-password"));
        confirmation->setText(QStringLiteral("different"));
        assert(!window.canStart());
        confirmation->setText(password->text());
        assert(window.canStart());

        toggle->click();
        assert((runtime.commandOrder ==
                std::vector<std::string>{
                    "credential", "permission", "endpoint", "listener"}));
        assert(password->text().isEmpty());
        assert(confirmation->text().isEmpty());
        assert(!runtime.lastPermissionRequest.allowClipboard);
        assert(host.status().clipboardState ==
               RuntimeClipboardState::Unavailable);
        assert(!toggle->isChecked());
        assert(!copy->isEnabled());

        runtime.snapshot.stage = RuntimeHostStage::ListenerAvailable;
        runtime.snapshot.listenerAvailable = true;
        runtime.snapshot.boundEndpoint = "192.168.0.10:3389";
        window.refresh();
        assert(toggle->isChecked());
        assert(address->text() ==
               QStringLiteral("Connect to: 192.168.0.10:3389"));
        assert(copy->isEnabled());
        assert(host.status().clipboardState ==
               RuntimeClipboardState::Unavailable);
        return 0;
    }

    if (mode == "consumer-password-stop-restart")
    {
#if !defined(RDP_SERVER_OWNER_ACCEPTANCE_TEST_UI)
        return 77;
#endif
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.interfaces = {
            RuntimeHostInterface{
                "ethernet-1", "Private Ethernet",
                {"192.168.0.10"}, false, true}};
        runtime.standaloneCredentialSucceeds = true;
        runtime.permissionSetupSucceeds = true;
        runtime.configurePreparesTlsIdentity = true;
        runtime.startSucceeds = true;
        runtime.publishListenerOnSuccessfulStart = true;

        DesktopWindow window(host);
        auto* username =
            window.findChild<QLineEdit*>("standaloneUsername");
        auto* password =
            window.findChild<QLineEdit*>("sessionPassword");
        auto* confirmation =
            window.findChild<QLineEdit*>("sessionPasswordConfirm");
        auto* toggle = sharingToggle(window);
        auto* credentialStatus =
            requiredLabel(window, "credentialStatus");
        assert(username && password && confirmation);

        username->setText(QStringLiteral("rdp"));
        password->setText(QStringLiteral("owner-test-password"));
        confirmation->setText(password->text());
        assert(window.canStart());

        // Three complete ON/OFF cycles prove that cleared editors reuse the
        // one memory-only credential. A fourth ON leaves the fixture in the
        // listener-authoritative state requested by the product workflow.
        for (int cycle = 0; cycle < 3; ++cycle)
        {
            toggle->click();
            assert(runtime.snapshot.stage ==
                   RuntimeHostStage::ListenerAvailable);
            assert(toggle->isChecked());
            assert(password->text().isEmpty());
            assert(confirmation->text().isEmpty());
            assert(username->text() == QStringLiteral("rdp"));
            assert(runtime.lastStandaloneUsername == std::u16string{u"rdp"});
            assert(runtime.snapshot.product.configuredStandaloneUsername ==
                   std::u16string{u"rdp"});
            assert(host.status().credentialsConfigured);
            assert(host.status().configuredStandaloneUsername ==
                   QStringLiteral("rdp"));
            assert(credentialStatus->text() ==
                   QStringLiteral(
                       "Session Password configured for this app session"));
            assert(runtime.standaloneCredentialCalls == 1);
            assert(runtime.permissionSetupCalls == cycle + 1);
            assert(runtime.startCalls == cycle + 1);

            toggle->click();
            assert(runtime.snapshot.stage == RuntimeHostStage::Stopped);
            assert(!toggle->isChecked());
            assert(runtime.revokeCalls == 0);
            assert(host.status().credentialsConfigured);
            assert(!host.status().desktopAuthorized);
            assert(window.blockedReason().isEmpty());
            assert(window.canStart());
            assert(toggle->isEnabled());
        }

        toggle->click();
        assert(runtime.snapshot.stage ==
               RuntimeHostStage::ListenerAvailable);
        assert(toggle->isChecked());
        assert(runtime.standaloneCredentialCalls == 1);
        assert(runtime.permissionSetupCalls == 4);
        assert(runtime.startCalls == 4);
        assert(runtime.stopCalls == 3);
        assert(runtime.revokeCalls == 0);
        assert(std::count(
                   runtime.commandOrder.begin(), runtime.commandOrder.end(),
                   std::string{"credential"}) == 1);
        return 0;
    }

    if (mode == "admission-failure-reason-product-diagnostic")
    {
        runtime.snapshot.lastError = RuntimeHostError::AuthenticationRejected;
        runtime.snapshot.stage = RuntimeHostStage::ListenerAvailable;
        runtime.snapshot.listenerAvailable = true;
        runtime.snapshot.credentialsConfigured = true;
        runtime.snapshot.hostOwnerAuthorized = true;
        runtime.snapshot.acceptedClientPreauthDiagnostics.available = true;
        runtime.snapshot.acceptedClientPreauthDiagnostics.credSspTransition =
            RuntimeAcceptedClientCredSspTransition::CredentialsVerified;
        runtime.snapshot.acceptedClientPreauthDiagnostics.ntlmEnvelope =
            RuntimeAcceptedClientNtlmEnvelope::DirectNtlm;
        runtime.snapshot.acceptedClientPreauthDiagnostics.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::Admission;
        runtime.snapshot.acceptedClientPreauthDiagnostics
            .standaloneFailureStage =
                RuntimeAcceptedClientStandaloneFailureStage::Admission;
        runtime.snapshot.acceptedClientPreauthDiagnostics
            .admissionFailureReason =
                RuntimeAcceptedClientAdmissionFailureReason::
                    SessionMonitorUnavailable;

        const HostStatus failed = host.status();
        assert(failed.localDesktopAuthorizationFailed);
        assert(!failed.remoteAuthenticationFailed);
        assert(failed.listenerReady);
        assert(failed.credentialsConfigured);
        assert(failed.authenticationDiagnostic ==
               QStringLiteral(
                   "Local desktop authorization: session monitor unavailable"));

        runtime.snapshot.acceptedClientPreauthDiagnostics
            .admissionFailureReason =
                RuntimeAcceptedClientAdmissionFailureReason::
                    SessionChangedBeforeSample;
        const HostStatus changed = host.status();
        assert(changed.localDesktopAuthorizationFailed);
        assert(!changed.remoteAuthenticationFailed);
        assert(changed.authenticationDiagnostic ==
               QStringLiteral(
                   "Local desktop authorization: active session changed"));
        return 0;
    }

    if (mode == "advanced-runtime-security-diagnostics")
    {
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.snapshot.stage = RuntimeHostStage::ListenerAvailable;
        runtime.snapshot.listenerAvailable = true;
        runtime.snapshot.listenerGeneration = 73U;
        runtime.snapshot.selectedEndpoint = "192.168.0.10:3389";
        runtime.snapshot.boundEndpoint = "192.168.0.10:3389";
        runtime.snapshot.tlsIdentityReady = true;
        runtime.snapshot.tlsIdentity.state =
            RuntimeTlsIdentityState::BoundAndMatched;
        runtime.snapshot.tlsIdentity.endpointGeneration =
            runtime.snapshot.listenerGeneration;
        runtime.snapshot.tlsIdentity.fingerprintAvailable = true;
        runtime.snapshot.tlsIdentity.certificateSha256.fill(0xabU);
        runtime.snapshot.tlsCertificateProfile =
            RuntimeTlsCertificateProfile::SelfSignedExactIpSan;
        runtime.snapshot.acceptedClientPreauthDiagnostics.available = true;
        runtime.snapshot.acceptedClientPreauthDiagnostics
            .tlsHandshakeStage =
                RuntimeAcceptedClientTlsHandshakeStage::Established;
        runtime.snapshot.acceptedClientPreauthDiagnostics
            .tlsConnection.protocolVersion =
                RuntimeAcceptedClientTlsProtocolVersion::Tls12;
        constexpr std::string_view cipherName{
            "ECDHE-RSA-AES256-GCM-SHA384"};
        static_assert(
            cipherName.size() <= kMaximumRuntimeTlsCipherNameBytes);
        std::copy(
            cipherName.begin(), cipherName.end(),
            runtime.snapshot.acceptedClientPreauthDiagnostics
                .tlsConnection.cipherName.begin());
        runtime.snapshot.acceptedClientPreauthDiagnostics
            .tlsConnection.cipherNameBytes = cipherName.size();

        DesktopWindow window(host);
        auto* mainTab = window.findChild<QWidget*>("mainTab");
        auto* tlsIdentity = requiredLabel(window, "tlsIdentityStatus");
        assert(mainTab != nullptr);
        assert(tlsIdentity->text().contains(
            QStringLiteral("TLS version: TLS 1.2")));
        assert(tlsIdentity->text().contains(
            QStringLiteral("Cipher: ECDHE-RSA-AES256-GCM-SHA384")));
        assert(tlsIdentity->text().contains(
            QStringLiteral("SHA-256: AB:AB:AB:AB")));
        assert(tlsIdentity->text().contains(
            QStringLiteral(
                "Selected endpoint: 192.168.0.10:3389")));
        assert(tlsIdentity->text().contains(
            QStringLiteral(
                "Certificate profile: Self-signed, exact-IP SAN")));

        for (QLabel* item : mainTab->findChildren<QLabel*>())
        {
            const QString text = item->text();
            assert(!text.contains(
                QStringLiteral("TLS version"), Qt::CaseInsensitive));
            assert(!text.contains(
                QStringLiteral("ECDHE-RSA"), Qt::CaseInsensitive));
            assert(!text.contains(
                QStringLiteral("Self-signed"), Qt::CaseInsensitive));
            assert(!text.contains(
                QStringLiteral("AB:AB:AB"), Qt::CaseInsensitive));
        }

        for (const QString& disallowedClaim :
             {QStringLiteral("wrong password"),
              QStringLiteral("target identity rejection"),
              QStringLiteral("certificate rejection"),
              QStringLiteral("local desktop authorization failure"),
              QStringLiteral("RDP-SERVER")})
        {
            assert(!tlsIdentity->text().contains(
                disallowedClaim, Qt::CaseInsensitive));
        }

        // Missing negotiated values stay missing. The existing certificate
        // fingerprint remains visible because R10 still supplies it, while
        // Qt must not reconstruct version/cipher/profile/selected endpoint.
        runtime.snapshot.selectedEndpoint.clear();
        runtime.snapshot.tlsCertificateProfile =
            RuntimeTlsCertificateProfile::Unavailable;
        runtime.snapshot.acceptedClientPreauthDiagnostics.tlsConnection = {};
        window.refresh();
        assert(!tlsIdentity->text().contains(
            QStringLiteral("TLS version"), Qt::CaseInsensitive));
        assert(!tlsIdentity->text().contains(
            QStringLiteral("Cipher:"), Qt::CaseInsensitive));
        assert(!tlsIdentity->text().contains(
            QStringLiteral("Selected endpoint:"), Qt::CaseInsensitive));
        assert(!tlsIdentity->text().contains(
            QStringLiteral("Certificate profile:"), Qt::CaseInsensitive));
        assert(tlsIdentity->text().contains(
            QStringLiteral("SHA-256: AB:AB:AB:AB")));
        return 0;
    }


    if (mode == "advanced-runtime-type1-structural-profile")
    {
        runtime.snapshot.lastError =
            RuntimeHostError::AuthenticationIncompletePeerClosed;
        runtime.snapshot.stage = RuntimeHostStage::ListenerAvailable;
        runtime.snapshot.listenerAvailable = true;
        runtime.snapshot.listenerGeneration = 73U;
        runtime.snapshot.boundEndpoint = "192.168.0.10:3389";
        runtime.snapshot.selectedEndpoint = "192.168.0.10:3389";
        runtime.snapshot.credentialsConfigured = true;
        runtime.snapshot.hostOwnerAuthorized = true;
        runtime.snapshot.product.sharingPermission = {
            true, true, true, true, 15U * 60U * 1000U,
            RuntimeSharingPermissionDenial::None};
        runtime.snapshot.tlsIdentityReady = true;
        runtime.snapshot.tlsIdentity.state =
            RuntimeTlsIdentityState::BoundAndMatched;
        runtime.snapshot.tlsIdentity.endpointGeneration =
            runtime.snapshot.listenerGeneration;
        runtime.snapshot.tlsIdentity.fingerprintAvailable = true;
        runtime.snapshot.tlsIdentity.certificateSha256.fill(0xcdU);
        runtime.snapshot.tlsCertificateProfile =
            RuntimeTlsCertificateProfile::SelfSignedExactIpSan;

        auto& diagnostics =
            runtime.snapshot.acceptedClientPreauthDiagnostics;
        diagnostics.available = true;
        diagnostics.tlsHandshakeStage =
            RuntimeAcceptedClientTlsHandshakeStage::Established;
        diagnostics.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::NtlmChallenge;
        diagnostics.credSspTransition =
            RuntimeAcceptedClientCredSspTransition::Closed;
        diagnostics.ntlmEnvelope =
            RuntimeAcceptedClientNtlmEnvelope::DirectNtlm;
        diagnostics.directNtlmTypeTwoQueued = true;
        diagnostics.directNtlmTypeTwoDelivered = true;
        diagnostics.termination = RuntimeAcceptedClientTermination::PeerEof;
        diagnostics.tlsConnection.protocolVersion =
            RuntimeAcceptedClientTlsProtocolVersion::Tls13;
        constexpr std::string_view cipherName{"TLS_AES_256_GCM_SHA384"};
        static_assert(cipherName.size() <= kMaximumRuntimeTlsCipherNameBytes);
        std::copy(
            cipherName.begin(), cipherName.end(),
            diagnostics.tlsConnection.cipherName.begin());
        diagnostics.tlsConnection.cipherNameBytes = cipherName.size();
        diagnostics.ntlmTypeOne.observed = true;
        diagnostics.ntlmTypeOne.versionPresent = true;
        diagnostics.ntlmTypeOne.majorVersion = 6U;
        diagnostics.ntlmTypeOne.minorVersion = 0U;
        diagnostics.ntlmTypeOne.buildNumber = 6001U;
        diagnostics.ntlmTypeOne.ntlmRevision = 0x0fU;

        DesktopWindow window(host);
        auto* mainTab = window.findChild<QWidget*>("mainTab");
        auto* tlsIdentity = requiredLabel(window, "tlsIdentityStatus");
        auto* availability =
            requiredLabel(window, "sharingAvailabilityStatus");
        auto* diagnostic =
            requiredLabel(window, "hostErrorExplanation");
        assert(mainTab != nullptr);
        assert(sharingToggle(window)->isChecked());
        assert(availability->text() ==
               QStringLiteral(
                   "Client disconnected before completing authentication."));
        assert(diagnostic->text() ==
               QStringLiteral(
                   "Client disconnected before completing authentication. "
                   "NTLM Type 2 was committed locally; Type 3 was not observed."));
        assert(tlsIdentity->text().contains(
            QStringLiteral("TLS version: TLS 1.3")));
        assert(tlsIdentity->text().contains(
            QStringLiteral("Cipher: TLS_AES_256_GCM_SHA384")));
        assert(tlsIdentity->text().contains(
            QStringLiteral("Selected endpoint: 192.168.0.10:3389")));
        assert(tlsIdentity->text().contains(
            QStringLiteral(
                "Certificate profile: Self-signed, exact-IP SAN")));
        assert(tlsIdentity->text().contains(
            QStringLiteral("SHA-256: CD:CD:CD:CD")));
        assert(tlsIdentity->text().contains(
            QStringLiteral(
                "Client profile: NTLM Type 1; "
                "version 6.0.6001 (revision 0x0F)")));

        for (QLabel* item : mainTab->findChildren<QLabel*>())
        {
            assert(!item->text().contains(
                QStringLiteral("NTLM Type 1"), Qt::CaseInsensitive));
            assert(!item->text().contains(
                QStringLiteral("6.0.6001"), Qt::CaseInsensitive));
        }

        for (const QString& disallowedClaim :
             {QStringLiteral("wrong password"),
              QStringLiteral("bad certificate"),
              QStringLiteral("native admission failed"),
              QStringLiteral("target identity mismatch")})
        {
            assert(!tlsIdentity->text().contains(
                disallowedClaim, Qt::CaseInsensitive));
            assert(!availability->text().contains(
                disallowedClaim, Qt::CaseInsensitive));
            assert(!diagnostic->text().contains(
                disallowedClaim, Qt::CaseInsensitive));
        }

        diagnostics.ntlmTypeOne.versionPresent = false;
        window.refresh();
        assert(tlsIdentity->text().contains(
            QStringLiteral(
                "Client profile: NTLM Type 1; version not supplied")));

        diagnostics.ntlmTypeOne = {};
        window.refresh();
        assert(!tlsIdentity->text().contains(
            QStringLiteral("Client profile:"), Qt::CaseInsensitive));
        return 0;
    }


    if (mode == "configured-username-runtime-projection")
    {
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.snapshot.credentialsConfigured = true;
        runtime.snapshot.product.credentialCapabilities.standalonePassword =
            true;
        runtime.snapshot.product.configuredStandaloneUsername =
            u"runtime-owner";

        DesktopWindow window(host);
        auto* username =
            window.findChild<QLineEdit*>("standaloneUsername");
        assert(username);
        assert(username->text() == QStringLiteral("runtime-owner"));
        assert(host.status().configuredStandaloneUsername ==
               QStringLiteral("runtime-owner"));
        assert(runtime.credentialSetupCalls == 0);
        assert(runtime.standaloneCredentialCalls == 0);
        assert(runtime.permissionSetupCalls == 0);
        assert(runtime.configureCalls == 0);
        assert(runtime.startCalls == 0);
        assert(runtime.stopCalls == 0);
        assert(runtime.revokeCalls == 0);
        assert(runtime.disconnectCalls == 0);
        window.refresh();
        assert(username->text() == QStringLiteral("runtime-owner"));
        return 0;
    }

    if (mode == "advanced-authentication-diagnostics-export-redaction")
    {
        runtime.snapshot.lastError =
            RuntimeHostError::AuthenticationIncompletePeerClosed;
        runtime.snapshot.stage = RuntimeHostStage::ListenerAvailable;
        runtime.snapshot.listenerAvailable = true;
        runtime.snapshot.listenerGeneration = 91U;
        runtime.snapshot.boundEndpoint = "192.168.0.10:3389";
        runtime.snapshot.selectedEndpoint = "192.168.0.10:3389";
        runtime.snapshot.credentialsConfigured = true;
        runtime.snapshot.product.configuredStandaloneUsername =
            u"DO_NOT_EXPORT_RUNTIME_USERNAME_31CF";
        runtime.snapshot.hostOwnerAuthorized = true;
        runtime.snapshot.product.sharingPermission = {
            true, true, true, true, 15U * 60U * 1000U,
            RuntimeSharingPermissionDenial::None};
        runtime.snapshot.tlsIdentityReady = true;
        runtime.snapshot.tlsIdentity.state =
            RuntimeTlsIdentityState::BoundAndMatched;
        runtime.snapshot.tlsIdentity.endpointGeneration =
            runtime.snapshot.listenerGeneration;
        runtime.snapshot.tlsIdentity.fingerprintAvailable = true;
        runtime.snapshot.tlsIdentity.certificateSha256.fill(0xefU);

        auto& diagnostics =
            runtime.snapshot.acceptedClientPreauthDiagnostics;
        diagnostics.available = true;
        diagnostics.acceptedClientId = 41U;
        diagnostics.ntlmEnvelope =
            RuntimeAcceptedClientNtlmEnvelope::DirectNtlm;
        diagnostics.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::NtlmChallenge;
        diagnostics.protocolStage =
            RuntimeAcceptedClientProtocolStage::PreAdmission;
        diagnostics.credSspTransition =
            RuntimeAcceptedClientCredSspTransition::Closed;
        diagnostics.directNtlmTypeTwoQueued = true;
        diagnostics.directNtlmTypeTwoDelivered = true;
        diagnostics.preType3Termination =
            RuntimeAcceptedClientPreType3Termination::PeerEof;
        diagnostics.termination =
            RuntimeAcceptedClientTermination::PeerEof;
        diagnostics.ntlmTypeOne.observed = true;
        diagnostics.tlsConnection.protocolVersion =
            RuntimeAcceptedClientTlsProtocolVersion::Tls13;
        diagnostics.acceptedToTlsEstablishedAvailable = true;
        diagnostics.acceptedToTlsEstablishedMicroseconds = 101U;
        diagnostics.tlsEstablishedToTypeOneAvailable = true;
        diagnostics.tlsEstablishedToTypeOneMicroseconds = 202U;
        diagnostics.typeOneToTypeTwoQueuedAvailable = true;
        diagnostics.typeOneToTypeTwoQueuedMicroseconds = 303U;
        diagnostics.directNtlmTypeTwoCreationToDeliveryAgeAvailable = true;
        diagnostics.directNtlmTypeTwoCreationToDeliveryMicroseconds = 404U;
        diagnostics.directNtlmTypeTwoToPeerEofAvailable = true;
        diagnostics.directNtlmTypeTwoToPeerEofMicroseconds = 505U;
        diagnostics.preauthElapsedAtPeerEofAvailable = true;
        diagnostics.preauthElapsedAtPeerEofMicroseconds = 1515U;
        diagnostics.preTlsTransportAttributionAvailable = true;
        diagnostics.acceptedToFirstClientTransportByteMicroseconds = 11U;
        diagnostics.firstClientTransportByteToX224CompleteMicroseconds = 22U;
        diagnostics.x224CompleteToFirstServerTransportByteMicroseconds = 33U;
        diagnostics.firstServerTransportByteToX224ConfirmCompleteMicroseconds =
            44U;
        diagnostics.x224ConfirmCompleteToFirstTlsClientByteMicroseconds = 55U;
        diagnostics.firstTlsClientByteToFirstTlsServerByteMicroseconds = 66U;
        diagnostics.firstTlsServerByteToTlsEstablishedMicroseconds = 77U;

        DesktopWindow window(host);
        auto* advanced =
            requiredLabel(window, "authenticationDiagnosticsStatus");
        auto* save = requiredButton(window, "saveDiagnostics");
        auto* username =
            window.findChild<QLineEdit*>("standaloneUsername");
        auto* password =
            window.findChild<QLineEdit*>("sessionPassword");
        auto* confirmation =
            window.findChild<QLineEdit*>("sessionPasswordConfirm");
        assert(advanced && save && username && password && confirmation);
        username->setText(QStringLiteral("diagnostic-user-sentinel"));
        password->setText(QStringLiteral("DO_NOT_EXPORT_PASSWORD_7A1F"));
        confirmation->setText(password->text());

        window.refresh();
        const QString exportText = window.diagnosticExportText();
        for (const QString& requiredText :
             {QStringLiteral("Endpoint: 192.168.0.10:3389"),
              QStringLiteral("Connection ID: 41"),
              QStringLiteral(
                  "Connection stage: NTLM challenge / pre-admission"),
              QStringLiteral("TLS version: TLS 1.3"),
              QStringLiteral("Certificate SHA-256: EF:EF:EF:EF"),
              QStringLiteral("NTLM Type 1: received"),
              QStringLiteral(
                  "NTLM Type 2: committed locally by the server TLS writer"),
              QStringLiteral("NTLM Type 3: not observed"),
              QStringLiteral("TCP FIN / peer EOF before Type 3"),
              QStringLiteral("accept -> TLS established: 101 us"),
              QStringLiteral("Type 2 queued -> local TLS commit: 404 us"),
              QStringLiteral("Type 2 commit -> peer EOF: 505 us"),
              QStringLiteral("accept -> first client byte: 11 us"),
              QStringLiteral("first TLS server -> TLS established: 77 us"),
              QStringLiteral("Microsoft error 0x204 is a generic client code")})
        {
            assert(advanced->text().contains(requiredText));
            assert(exportText.contains(requiredText));
        }
        assert(save->isEnabled());
        assert(!exportText.contains(
            QStringLiteral("DO_NOT_EXPORT_PASSWORD_7A1F")));
        assert(!exportText.contains(
            QStringLiteral("diagnostic-user-sentinel")));
        assert(!exportText.contains(
            QStringLiteral("DO_NOT_EXPORT_RUNTIME_USERNAME_31CF")));
        assert(!exportText.contains(
            QStringLiteral("NTLM challenge:"), Qt::CaseInsensitive));
        assert(!exportText.contains(
            QStringLiteral("session key:"), Qt::CaseInsensitive));
        assert(!exportText.contains(
            QStringLiteral("authentication response:"),
            Qt::CaseInsensitive));
        return 0;
    }

    if (mode == "authentication-first-failure-classification")
    {
        runtime.snapshot.stage = RuntimeHostStage::ListenerAvailable;
        runtime.snapshot.listenerAvailable = true;
        runtime.snapshot.listenerGeneration = 92U;
        runtime.snapshot.boundEndpoint = "192.168.0.10:3389";
        runtime.snapshot.credentialsConfigured = true;
        runtime.snapshot.hostOwnerAuthorized = true;
        runtime.snapshot.product.sharingPermission = {
            true, true, true, true, 15U * 60U * 1000U,
            RuntimeSharingPermissionDenial::None};
        auto& diagnostics =
            runtime.snapshot.acceptedClientPreauthDiagnostics;
        diagnostics.available = true;
        diagnostics.acceptedClientId = 51U;
        diagnostics.ntlmEnvelope =
            RuntimeAcceptedClientNtlmEnvelope::DirectNtlm;
        diagnostics.protocolStage =
            RuntimeAcceptedClientProtocolStage::PreAdmission;
        diagnostics.admissionFailureReason =
            RuntimeAcceptedClientAdmissionFailureReason::None;

        DesktopWindow window(host);
        auto* availability =
            requiredLabel(window, "sharingAvailabilityStatus");
        auto* advanced =
            requiredLabel(window, "authenticationDiagnosticsStatus");

        runtime.snapshot.lastError =
            RuntimeHostError::AuthenticationIncompletePeerClosed;
        diagnostics.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::NtlmChallenge;
        diagnostics.credSspTransition =
            RuntimeAcceptedClientCredSspTransition::Closed;
        diagnostics.directNtlmTypeTwoDelivered = true;
        diagnostics.standaloneFailureStage =
            RuntimeAcceptedClientStandaloneFailureStage::NtlmNegotiation;
        diagnostics.termination =
            RuntimeAcceptedClientTermination::PeerEof;
        diagnostics.preType3Termination =
            RuntimeAcceptedClientPreType3Termination::PeerEof;
        window.refresh();
        assert(availability->text() == QStringLiteral(
            "Client disconnected before completing authentication."));
        assert(advanced->text().contains(availability->text()));

        runtime.snapshot.lastError = RuntimeHostError::AuthenticationRejected;
        diagnostics.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::NtlmAuthenticate;
        diagnostics.credSspTransition =
            RuntimeAcceptedClientCredSspTransition::Failed;
        diagnostics.standaloneCredentialsRejected = true;
        diagnostics.termination =
            RuntimeAcceptedClientTermination::OwnerCancellation;
        diagnostics.preType3Termination =
            RuntimeAcceptedClientPreType3Termination::None;
        window.refresh();
        const HostStatus invalid = host.status();
        assert(invalid.remoteAuthenticationInvalidCredentials);
        assert(!invalid.remoteAuthenticationIncomplete);
        assert(!invalid.localDesktopAuthorizationFailed);
        assert(availability->text() ==
               QStringLiteral("Invalid credentials."));
        assert(advanced->text().contains(
            QStringLiteral("First failure: Invalid credentials.")));

        diagnostics.standaloneCredentialsRejected = false;
        diagnostics.credSspTransition =
            RuntimeAcceptedClientCredSspTransition::CredentialsVerified;
        diagnostics.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::Admission;
        diagnostics.standaloneFailureStage =
            RuntimeAcceptedClientStandaloneFailureStage::Admission;
        diagnostics.admissionFailureReason =
            RuntimeAcceptedClientAdmissionFailureReason::
                SessionMonitorUnavailable;
        window.refresh();
        const HostStatus admission = host.status();
        assert(admission.localDesktopAuthorizationFailed);
        assert(!admission.remoteAuthenticationInvalidCredentials);
        assert(!admission.remoteAuthenticationIncomplete);
        assert(availability->text() ==
               QStringLiteral("Native desktop admission denied."));
        assert(advanced->text().contains(
            QStringLiteral(
                "First failure: Native desktop admission denied.")));
        assert(advanced->text().contains(
            QStringLiteral("Microsoft error 0x204 is a generic client code")));
        assert(!advanced->text().contains(
            QStringLiteral("server unreachable"), Qt::CaseInsensitive));
        return 0;
    }

    if (mode == "authinfo-failure-connection-replacement-redaction")
    {
        // Post-Type-3 authInfo rejection is not a bad-password diagnosis,
        // native admission denial, or pre-Type-3 peer close.
        runtime.snapshot.lastError = RuntimeHostError::AuthenticationRejected;
        runtime.snapshot.stage = RuntimeHostStage::ListenerAvailable;
        runtime.snapshot.listenerAvailable = true;
        runtime.snapshot.listenerGeneration = 204U;
        runtime.snapshot.boundEndpoint = "192.168.0.10:3389";
        runtime.snapshot.selectedEndpoint = "192.168.0.10:3389";
        runtime.snapshot.credentialsConfigured = true;
        runtime.snapshot.product.configuredStandaloneUsername =
            u"OWNER_USERNAME_ZE9";
        runtime.snapshot.hostOwnerAuthorized = true;
        runtime.snapshot.product.sharingPermission = {
            true, true, true, true, 15U * 60U * 1000U,
            RuntimeSharingPermissionDenial::None};

        constexpr std::uint64_t failedConnectionId = 741'900'001ULL;
        constexpr std::uint64_t replacementConnectionId = 742'900'002ULL;
        const QString failedConnectionText =
            QStringLiteral("Connection ID: %1")
                .arg(static_cast<qulonglong>(failedConnectionId));
        const QString replacementConnectionText =
            QStringLiteral("Connection ID: %1")
                .arg(static_cast<qulonglong>(replacementConnectionId));

        auto& diagnostics =
            runtime.snapshot.acceptedClientPreauthDiagnostics;
        diagnostics.available = true;
        diagnostics.acceptedClientId = failedConnectionId;
        diagnostics.ntlmEnvelope =
            RuntimeAcceptedClientNtlmEnvelope::DirectNtlm;
        diagnostics.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::CredentialDelegation;
        diagnostics.protocolStage =
            RuntimeAcceptedClientProtocolStage::PreAdmission;
        diagnostics.credSspTransition =
            RuntimeAcceptedClientCredSspTransition::Failed;
        diagnostics.standaloneFailureStage =
            RuntimeAcceptedClientStandaloneFailureStage::AuthInfo;
        diagnostics.standaloneCredentialGeneration = 71U;
        diagnostics.standaloneAuthInfoFailureReason =
            RuntimeAcceptedClientAuthInfoFailureReason::CredentialMismatch;
        diagnostics.termination =
            RuntimeAcceptedClientTermination::ProtocolError;
        diagnostics.ntlmTypeOne.observed = true;
        diagnostics.directNtlmTypeTwoQueued = true;
        diagnostics.directNtlmTypeTwoDelivered = true;
        diagnostics.acceptedToTlsEstablishedAvailable = true;
        diagnostics.acceptedToTlsEstablishedMicroseconds = 741111U;
        diagnostics.tlsEstablishedToTypeOneAvailable = true;
        diagnostics.tlsEstablishedToTypeOneMicroseconds = 741222U;

        const auto require = [](bool condition, const char* failure) {
            if (!condition)
            {
                std::fprintf(stderr, "authInfo GUI replacement: %s\n", failure);
                std::abort();
            }
        };

        DesktopWindow window(host);
        auto* availability =
            window.findChild<QLabel*>("sharingAvailabilityStatus");
        auto* mainDiagnostic =
            window.findChild<QLabel*>("hostErrorExplanation");
        auto* activity = window.findChild<QLabel*>("clientStatus");
        auto* advanced =
            window.findChild<QLabel*>("authenticationDiagnosticsStatus");
        auto* username =
            window.findChild<QLineEdit*>("standaloneUsername");
        auto* password =
            window.findChild<QLineEdit*>("sessionPassword");
        auto* confirmation =
            window.findChild<QLineEdit*>("sessionPasswordConfirm");
        require(availability && mainDiagnostic && activity && advanced &&
                    username && password && confirmation,
                "required offscreen GUI control missing");

        const QStringList secretMarkers{
            QStringLiteral("OWNER_USERNAME_ZE9"),
            QStringLiteral("PENDING_USERNAME_ZE9"),
            QStringLiteral("SESSION_PASSWORD_ZE9"),
            QStringLiteral("DELEGATED_DOMAIN_ZE9"),
            QStringLiteral("NTLM_PROOF_ZE9"),
            QStringLiteral("AUTHINFO_ZE9"),
            QStringLiteral("MIC_ZE9"),
            QStringLiteral("BINDING_TOKEN_ZE9"),
            QStringLiteral("TLS_SESSION_SECRET_ZE9")};
        username->setText(secretMarkers[1]);
        const QString enteredSecret =
            secretMarkers.mid(2).join(QLatin1Char('|'));
        password->setText(enteredSecret);
        confirmation->setText(enteredSecret);

        window.refresh();
        const HostStatus failed = host.status();
        require(failed.remoteAuthenticationFailed &&
                    !failed.remoteAuthenticationInvalidCredentials &&
                    !failed.remoteAuthenticationIncomplete &&
                    !failed.localDesktopAuthorizationFailed,
                "authInfo failure was promoted to an unsupported classification");
        require(availability->text() ==
                    QStringLiteral("Remote client authentication failed.") &&
                    activity->text().contains(availability->text()),
                "Main/Activity did not retain generic post-Type-3 failure");
        require(mainDiagnostic->text().contains(
                    QStringLiteral("credential verification failed")) &&
                    advanced->text().contains(failedConnectionText) &&
                    advanced->text().contains(QStringLiteral(
                        "Final authInfo: delegated credentials did not match")) &&
                    advanced->text().contains(
                        QStringLiteral("credential delegation / pre-admission")) &&
                    advanced->text().contains(QStringLiteral("741111 us")) &&
                    advanced->text().contains(
                        QStringLiteral("NTLM Type 3: received")) &&
                    advanced->text().contains(QStringLiteral(
                        "First failure: Remote client authentication failed.")),
                "post-Type-3 diagnostic evidence lost or misclassified");

        const QString previousExport = window.diagnosticExportText();
        require(previousExport.contains(failedConnectionText) &&
                    previousExport.contains(QStringLiteral("741111 us")) &&
                    previousExport.contains(QStringLiteral(
                        "Final authInfo: delegated credentials did not match")),
                "old peer's bounded final-authInfo diagnostics are absent");
        for (const QString& marker : secretMarkers)
            require(!previousExport.contains(marker),
                    "secret sentinel leaked in failed-peer export");

        // R10 replaces the entire typed snapshot; Qt caches no old peer.
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.snapshot.stage = RuntimeHostStage::ClientAuthenticating;
        runtime.snapshot.activeClients = {
            RuntimeHostClient{replacementConnectionId, "192.168.0.55", true, false, false}};
        diagnostics = {};
        diagnostics.available = true;
        diagnostics.acceptedClientId = replacementConnectionId;
        diagnostics.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::Tls;
        diagnostics.protocolStage =
            RuntimeAcceptedClientProtocolStage::PreAdmission;
        diagnostics.credSspTransition =
            RuntimeAcceptedClientCredSspTransition::AwaitingToken;
        diagnostics.termination = RuntimeAcceptedClientTermination::Open;
        diagnostics.acceptedToTlsEstablishedAvailable = true;
        diagnostics.acceptedToTlsEstablishedMicroseconds = 742222U;
        window.refresh();

        const HostStatus replacement = host.status();
        const QString replacementExport = window.diagnosticExportText();
        require(!replacement.remoteAuthenticationFailed &&
                    !replacement.remoteAuthenticationIncomplete &&
                    !replacement.remoteAuthenticationInvalidCredentials &&
                    !replacement.localDesktopAuthorizationFailed,
                "replacement inherited terminal authentication state");
        require(availability->text().isEmpty() &&
                    activity->text().contains(QStringLiteral("Connecting:")) &&
                    !mainDiagnostic->text().contains(
                        QStringLiteral("credential verification failed")) &&
                    !mainDiagnostic->text().contains(
                        QStringLiteral("Client disconnected")),
                "Main/Activity retained the retired authInfo failure");
        for (const QString& current :
             {advanced->text(), replacementExport})
        {
            require(current.contains(replacementConnectionText) &&
                        current.contains(QStringLiteral("742222 us")) &&
                        current.contains(QStringLiteral("NTLM Type 3: not observed")) &&
                        current.contains(QStringLiteral(
                            "First failure: No typed authentication failure observed.")),
                    "new accepted peer's status is not current");
        }
        for (const QString& current :
             {mainDiagnostic->text(), activity->text(),
              advanced->text(), replacementExport})
        {
            for (const QString& retired :
                 {failedConnectionText,
                  QStringLiteral("741111 us"),
                  QStringLiteral("741222 us"),
                  QStringLiteral("credential delegation"),
                  QStringLiteral("credential verification failed"),
                  QStringLiteral("Final authInfo:")})
                require(!current.contains(retired),
                        "old accepted peer metadata survived replacement");
        }
        for (const QString& marker : secretMarkers)
            require(!replacementExport.contains(marker),
                    "secret sentinel leaked in replacement export");

        runtime.snapshot.activeClients.clear();
        runtime.snapshot.stage = RuntimeHostStage::ListenerAvailable;
        diagnostics = {};
        window.refresh();
        const QString emptyExport = window.diagnosticExportText();
        require(advanced->text().contains(
                    QStringLiteral("Connection ID: unavailable")) &&
                    emptyExport.contains(
                        QStringLiteral("Connection ID: unavailable")) &&
                    !advanced->text().contains(replacementConnectionText) &&
                    !emptyExport.contains(replacementConnectionText) &&
                    !advanced->text().contains(QStringLiteral("742222 us")) &&
                    !emptyExport.contains(QStringLiteral("742222 us")) &&
                    activity->text() == QStringLiteral("No connected devices"),
                "last accepted peer survived retirement");
        return 0;
    }

    if (mode == "authinfo-typed-advanced-only-and-generation-retirement")
    {
        // R10's non-secret, connection-scoped reason is presentation-only.
        // This test neither consults R2 internals nor grants native admission.
        runtime.snapshot.lastError = RuntimeHostError::AuthenticationRejected;
        runtime.snapshot.stage = RuntimeHostStage::ListenerAvailable;
        runtime.snapshot.listenerAvailable = true;
        runtime.snapshot.listenerGeneration = 915U;
        runtime.snapshot.credentialsConfigured = true;

        auto& diagnostics =
            runtime.snapshot.acceptedClientPreauthDiagnostics;
        diagnostics.available = true;
        diagnostics.acceptedClientId = 915'004U;
        diagnostics.standaloneCredentialGeneration = 53U;
        diagnostics.credSspTransition =
            RuntimeAcceptedClientCredSspTransition::Failed;
        diagnostics.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::CredentialDelegation;
        diagnostics.standaloneFailureStage =
            RuntimeAcceptedClientStandaloneFailureStage::AuthInfo;

        DesktopWindow window(host);
        auto* availability =
            requiredLabel(window, "sharingAvailabilityStatus");
        auto* activity = requiredLabel(window, "clientStatus");
        auto* mainDiagnostic =
            requiredLabel(window, "hostErrorExplanation");
        auto* advanced =
            requiredLabel(window, "authenticationDiagnosticsStatus");

        const auto require = [](bool condition, const char* message) {
            if (!condition)
            {
                std::fprintf(stderr, "typed authInfo GUI: %s\n", message);
                std::abort();
            }
        };
        using Reason = RuntimeAcceptedClientAuthInfoFailureReason;
        struct FailureCase final
        {
            Reason reason;
            const char* text;
        };
        constexpr FailureCase cases[]{
            {Reason::FrameOrSessionInvalid,
             "final credential frame invalid"},
            {Reason::ProtectedCredentialOrSignSealFailure,
             "protected credential unwrap failed"},
            {Reason::CredentialStructureOrTypeFailure,
             "delegated credential structure invalid"},
            {Reason::DelegatedDomainRejected,
             "delegated credential domain rejected"},
            {Reason::CredentialUnavailableOrRevoked,
             "session credential unavailable or revoked"},
            {Reason::CredentialMismatch,
             "delegated credentials did not match"},
            {Reason::FrameReleaseFailure,
             "final credential frame release failed"}};

        for (const FailureCase& failure : cases)
        {
            diagnostics.standaloneAuthInfoFailureReason = failure.reason;
            window.refresh();
            const QString expected =
                QStringLiteral("Final authInfo: ") +
                QString::fromLatin1(failure.text);
            const QString exportText = window.diagnosticExportText();
            const HostStatus status = host.status();
            require(status.remoteAuthenticationFailed &&
                        !status.remoteAuthenticationInvalidCredentials &&
                        !status.remoteAuthenticationIncomplete &&
                        !status.localDesktopAuthorizationFailed,
                    "typed authInfo changed product failure classification");
            require(availability->text() ==
                        QStringLiteral("Remote client authentication failed.") &&
                        activity->text().contains(availability->text()) &&
                        !mainDiagnostic->text().contains(
                            QStringLiteral("Final authInfo:")) &&
                        !activity->text().contains(
                            QStringLiteral("Final authInfo:")),
                    "typed authInfo escaped into Main or Activity");
            require(advanced->text().contains(expected) &&
                        exportText.contains(expected) &&
                        advanced->text().count(
                            QStringLiteral("Final authInfo:")) == 1 &&
                        exportText.count(
                            QStringLiteral("Final authInfo:")) == 1,
                    "bounded final-authInfo category is absent or duplicated");
        }

        // No category, no real accepted client, no credential generation,
        // wrong stage and verified credentials must each suppress the detail.
        diagnostics.standaloneAuthInfoFailureReason = Reason::None;
        window.refresh();
        require(!advanced->text().contains(QStringLiteral("Final authInfo:")),
                "None projected an invented authInfo category");

        diagnostics.standaloneAuthInfoFailureReason = Reason::CredentialMismatch;
        diagnostics.acceptedClientId = 0U;
        window.refresh();
        require(!advanced->text().contains(QStringLiteral("Final authInfo:")),
                "missing connection lifetime projected an authInfo category");
        diagnostics.acceptedClientId = 915'004U;

        diagnostics.standaloneCredentialGeneration = 0U;
        window.refresh();
        require(!advanced->text().contains(QStringLiteral("Final authInfo:")),
                "missing credential generation projected an authInfo category");
        diagnostics.standaloneCredentialGeneration = 53U;

        diagnostics.standaloneFailureStage =
            RuntimeAcceptedClientStandaloneFailureStage::PubKeyAuth;
        window.refresh();
        require(!advanced->text().contains(QStringLiteral("Final authInfo:")),
                "unrelated authentication stage reused authInfo reason");
        diagnostics.standaloneFailureStage =
            RuntimeAcceptedClientStandaloneFailureStage::AuthInfo;

        diagnostics.credSspTransition =
            RuntimeAcceptedClientCredSspTransition::CredentialsVerified;
        window.refresh();
        require(!advanced->text().contains(QStringLiteral("Final authInfo:")),
                "verified credentials retained a failure reason");
        diagnostics.credSspTransition =
            RuntimeAcceptedClientCredSspTransition::Failed;

        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.snapshot.stage = RuntimeHostStage::ClientAuthenticating;
        runtime.snapshot.activeClients = {
            RuntimeHostClient{915'005U, "192.168.0.65", true, false, false}};
        diagnostics = {};
        diagnostics.available = true;
        diagnostics.acceptedClientId = 915'005U;
        diagnostics.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::Tls;
        diagnostics.credSspTransition =
            RuntimeAcceptedClientCredSspTransition::AwaitingToken;
        window.refresh();
        const QString replacementExport = window.diagnosticExportText();
        for (const QString& current :
             {availability->text(), activity->text(),
              mainDiagnostic->text(), advanced->text(), replacementExport})
        {
            require(!current.contains(QStringLiteral("Final authInfo:")) &&
                        !current.contains(QStringLiteral("915004")),
                    "new peer inherited old authInfo reason or connection ID");
        }
        require(advanced->text().contains(QStringLiteral("Connection ID: 915005")) &&
                    replacementExport.contains(QStringLiteral("Connection ID: 915005")),
                "replacement connection identity missing from diagnostics");
        return 0;
    }

    if (mode == "authentication-diagnostics-connection-replacement")
    {
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.snapshot.stage = RuntimeHostStage::ClientAuthenticating;
        runtime.snapshot.listenerAvailable = true;
        runtime.snapshot.listenerGeneration = 93U;
        runtime.snapshot.boundEndpoint = "192.168.0.10:3389";
        auto& diagnostics =
            runtime.snapshot.acceptedClientPreauthDiagnostics;
        diagnostics.available = true;
        diagnostics.acceptedClientId = 61U;
        diagnostics.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::NtlmChallenge;
        diagnostics.protocolStage =
            RuntimeAcceptedClientProtocolStage::PreAdmission;
        diagnostics.ntlmTypeOne.observed = true;
        diagnostics.acceptedToTlsEstablishedAvailable = true;
        diagnostics.acceptedToTlsEstablishedMicroseconds = 6111U;

        DesktopWindow window(host);
        auto* advanced =
            requiredLabel(window, "authenticationDiagnosticsStatus");
        assert(advanced->text().contains(
            QStringLiteral("Connection ID: 61")));
        assert(advanced->text().contains(QStringLiteral("6111 us")));

        diagnostics = {};
        diagnostics.available = true;
        diagnostics.acceptedClientId = 62U;
        diagnostics.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::Tls;
        diagnostics.protocolStage =
            RuntimeAcceptedClientProtocolStage::PreAdmission;
        diagnostics.acceptedToTlsEstablishedAvailable = true;
        diagnostics.acceptedToTlsEstablishedMicroseconds = 6222U;
        window.refresh();

        const QString exportText = window.diagnosticExportText();
        assert(advanced->text().contains(
            QStringLiteral("Connection ID: 62")));
        assert(advanced->text().contains(QStringLiteral("6222 us")));
        assert(!advanced->text().contains(
            QStringLiteral("Connection ID: 61")));
        assert(!advanced->text().contains(QStringLiteral("6111 us")));
        assert(exportText.contains(QStringLiteral("Connection ID: 62")));
        assert(!exportText.contains(QStringLiteral("Connection ID: 61")));
        assert(!exportText.contains(QStringLiteral("6111 us")));
        return 0;
    }

    if (mode == "authentication-incomplete-before-native-admission")
    {
        runtime.snapshot.lastError =
            RuntimeHostError::AuthenticationIncompletePeerClosed;
        runtime.snapshot.stage = RuntimeHostStage::ListenerAvailable;
        runtime.snapshot.listenerAvailable = true;
        runtime.snapshot.boundEndpoint = "192.168.0.10:3389";
        runtime.snapshot.credentialsConfigured = true;
        runtime.snapshot.hostOwnerAuthorized = true;
        runtime.snapshot.product.sharingPermission = {
            true, true, true, true, 15U * 60U * 1000U,
            RuntimeSharingPermissionDenial::None};
        runtime.snapshot.acceptedClientPreauthDiagnostics.available = true;
        runtime.snapshot.acceptedClientPreauthDiagnostics.credSspTransition =
            RuntimeAcceptedClientCredSspTransition::Closed;
        runtime.snapshot.acceptedClientPreauthDiagnostics.ntlmEnvelope =
            RuntimeAcceptedClientNtlmEnvelope::DirectNtlm;
        runtime.snapshot.acceptedClientPreauthDiagnostics.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::NtlmChallenge;
        runtime.snapshot.acceptedClientPreauthDiagnostics
            .directNtlmTypeTwoQueued = true;
        runtime.snapshot.acceptedClientPreauthDiagnostics
            .directNtlmTypeTwoDelivered = true;
        runtime.snapshot.acceptedClientPreauthDiagnostics
            .standaloneFailureStage =
                RuntimeAcceptedClientStandaloneFailureStage::NtlmNegotiation;
        runtime.snapshot.acceptedClientPreauthDiagnostics
            .admissionFailureReason =
                RuntimeAcceptedClientAdmissionFailureReason::None;
        runtime.snapshot.acceptedClientPreauthDiagnostics.termination =
            RuntimeAcceptedClientTermination::PeerEof;

        // R10's current target observation is authoritative status, but it is
        // not a typed target-identity failure diagnosis and cannot authorize
        // target-rejection product language.
        runtime.snapshot.listenerGeneration = 73U;
        runtime.snapshot.connectionTargetIdentity.numericEndpointAddress =
            "192.168.0.10";
        runtime.snapshot.connectionTargetIdentity.port = 3389U;
        runtime.snapshot.connectionTargetIdentity.targetClass =
            RuntimeConnectionTargetClass::Ip;
        runtime.snapshot.connectionTargetIdentity.serviceClass =
            RuntimeConnectionServiceClass::Termsrv;
        runtime.snapshot.connectionTargetIdentity.protocolServerIdentity =
            u"RDP-SERVER";
        runtime.snapshot.connectionTargetIdentity.serviceIdentityProfile =
            RuntimeServiceIdentityProfile::FixedName;
        runtime.snapshot.connectionTargetIdentity.startGeneration =
            runtime.snapshot.listenerGeneration;
        runtime.snapshot.acceptedClientPreauthDiagnostics.clientTargetClass =
            RuntimeConnectionTargetClass::Ip;
        runtime.snapshot.acceptedClientPreauthDiagnostics.serviceClass =
            RuntimeConnectionServiceClass::Termsrv;
        runtime.snapshot.acceptedClientPreauthDiagnostics
            .serviceIdentityProfile =
                RuntimeServiceIdentityProfile::FixedName;
        runtime.snapshot.acceptedClientPreauthDiagnostics
            .connectionTargetGeneration =
                runtime.snapshot.listenerGeneration;
        runtime.interfaces = {
            RuntimeHostInterface{
                "ethernet-1", "Private Ethernet",
                {"192.168.0.10"}, false, true}};

        DesktopWindow window(host);
        auto* mainTab = window.findChild<QWidget*>("mainTab");
        auto* availability =
            requiredLabel(window, "sharingAvailabilityStatus");
        auto* diagnostic =
            requiredLabel(window, "hostErrorExplanation");
        auto* authenticationDiagnostics =
            requiredLabel(window, "authenticationDiagnosticsStatus");
        auto* activity =
            requiredLabel(window, "clientStatus");
        auto* password =
            window.findChild<QLineEdit*>("sessionPassword");
        auto* confirmation =
            window.findChild<QLineEdit*>("sessionPasswordConfirm");
        assert(mainTab && password && confirmation);

        const HostStatus incomplete = host.status();
        assert(!incomplete.localDesktopAuthorizationFailed);
        assert(incomplete.remoteAuthenticationFailed);
        assert(incomplete.remoteAuthenticationIncomplete);
        assert(incomplete.listenerReady);
        assert(incomplete.credentialsConfigured);
        assert(sharingToggle(window)->isChecked());
        assert(password->text().isEmpty());
        assert(confirmation->text().isEmpty());
        assert(!availability->isHidden());
        assert(availability->text() ==
               QStringLiteral(
                   "Client disconnected before completing authentication."));
        assert(activity->text().contains(
            QStringLiteral(
                "Client disconnected before completing authentication.")));
        assert(diagnostic->text() ==
               QStringLiteral(
                   "Client disconnected before completing authentication. "
                   "NTLM Type 2 was committed locally; Type 3 was not observed."));
        for (const QString& disallowedClaim :
             {QStringLiteral("wrong password"),
              QStringLiteral("local desktop"),
              QStringLiteral("native admission"),
              QStringLiteral("stage=admission"),
              QStringLiteral("target identity"),
              QStringLiteral("target principal"),
              QStringLiteral("RDP-SERVER")})
        {
            assert(!availability->text().contains(
                disallowedClaim, Qt::CaseInsensitive));
            assert(!diagnostic->text().contains(
                disallowedClaim, Qt::CaseInsensitive));
            assert(!activity->text().contains(
                disallowedClaim, Qt::CaseInsensitive));
        }

        // A challenge-stage snapshot alone is not a delivery receipt.
        // Keep Main neutral and fall back to a less-specific redacted
        // diagnostic when only the queued boundary is retained.
        runtime.snapshot.acceptedClientPreauthDiagnostics
            .directNtlmTypeTwoDelivered = false;
        window.refresh();
        assert(availability->text() ==
               QStringLiteral(
                   "Client disconnected before completing authentication."));
        assert(diagnostic->text() ==
               QStringLiteral(
                   "Client disconnected before completing authentication."));
        assert(authenticationDiagnostics->text().contains(
            QStringLiteral("NTLM Type 2: queued locally")));
        assert(authenticationDiagnostics->text().contains(
            QStringLiteral("NTLM Type 3: not observed")));
        runtime.snapshot.acceptedClientPreauthDiagnostics
            .directNtlmTypeTwoDelivered = true;
        window.refresh();
        for (QLabel* item : mainTab->findChildren<QLabel*>())
        {
            assert(!item->text().contains(
                QStringLiteral("NTLMSSP"), Qt::CaseInsensitive));
            assert(!item->text().contains(
                QStringLiteral("Direct NTLM"), Qt::CaseInsensitive));
        }

        // An AuthenticationRejected snapshot with no typed admission reason
        // must not be rewritten into a peer-disconnect or native-admission
        // claim. Typed R10 state is the only product classification authority.
        runtime.snapshot.lastError = RuntimeHostError::AuthenticationRejected;
        runtime.snapshot.acceptedClientPreauthDiagnostics.credSspTransition =
            RuntimeAcceptedClientCredSspTransition::Failed;
        runtime.snapshot.acceptedClientPreauthDiagnostics.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::Admission;
        runtime.snapshot.acceptedClientPreauthDiagnostics
            .standaloneFailureStage =
                RuntimeAcceptedClientStandaloneFailureStage::Admission;
        window.refresh();

        const HostStatus untypedAdmission = host.status();
        assert(!untypedAdmission.localDesktopAuthorizationFailed);
        assert(untypedAdmission.remoteAuthenticationFailed);
        assert(!untypedAdmission.remoteAuthenticationIncomplete);
        assert(!untypedAdmission.remoteAuthenticationInvalidCredentials);
        assert(untypedAdmission.authenticationDiagnostic.isEmpty());
        assert(availability->text() ==
               QStringLiteral("Remote client authentication failed."));
        assert(diagnostic->text() ==
               QStringLiteral("Diagnostics: Client authentication rejected"));
        assert(authenticationDiagnostics->text().contains(
            QStringLiteral(
                "First failure: Remote client authentication failed.")));
        assert(sharingToggle(window)->isChecked());
        assert(password->text().isEmpty());
        assert(confirmation->text().isEmpty());
        return 0;
    }

    if (mode == "authentication-failure-product-language")
    {
#if !defined(RDP_SERVER_OWNER_ACCEPTANCE_TEST_UI)
        return 77;
#endif
        runtime.snapshot.lastError = RuntimeHostError::AuthenticationRejected;
        runtime.snapshot.stage = RuntimeHostStage::ListenerAvailable;
        runtime.snapshot.listenerAvailable = true;
        runtime.snapshot.boundEndpoint = "192.168.0.10:3389";
        runtime.snapshot.credentialsConfigured = true;
        runtime.snapshot.hostOwnerAuthorized = true;
        runtime.snapshot.product.sharingPermission = {
            true, true, true, true, 15U * 60U * 1000U,
            RuntimeSharingPermissionDenial::None};
        runtime.snapshot.acceptedClientPreauthDiagnostics.available = true;
        runtime.snapshot.acceptedClientPreauthDiagnostics.credSspTransition =
            RuntimeAcceptedClientCredSspTransition::Failed;
        runtime.snapshot.acceptedClientPreauthDiagnostics.ntlmEnvelope =
            RuntimeAcceptedClientNtlmEnvelope::DirectNtlm;
        runtime.snapshot.acceptedClientPreauthDiagnostics
            .standaloneFailureStage =
                RuntimeAcceptedClientStandaloneFailureStage::NtlmNegotiation;
        runtime.interfaces = {
            RuntimeHostInterface{
                "ethernet-1", "Private Ethernet",
                {"192.168.0.10"}, false, true}};

        DesktopWindow window(host);
        auto* mainTab = window.findChild<QWidget*>("mainTab");
        auto* availability =
            requiredLabel(window, "sharingAvailabilityStatus");
        auto* diagnostic =
            requiredLabel(window, "hostErrorExplanation");
        auto* readiness =
            requiredLabel(window, "sharingReadinessStatus");
        auto* password =
            window.findChild<QLineEdit*>("sessionPassword");
        auto* confirmation =
            window.findChild<QLineEdit*>("sessionPasswordConfirm");
        assert(mainTab && password && confirmation);

        const HostStatus failed = host.status();
        assert(failed.productState == RuntimeProductHostState::Listening);
        assert(failed.listenerReady);
        assert(failed.credentialsConfigured);
        assert(sharingToggle(window)->isChecked());
        assert(password->text().isEmpty());
        assert(confirmation->text().isEmpty());
        assert(!availability->isHidden());
        assert(availability->text() ==
               QStringLiteral("Remote client authentication failed."));

        for (QLabel* item : mainTab->findChildren<QLabel*>())
        {
            assert(!item->text().contains(
                QStringLiteral("invalid-gss-wrapper"),
                Qt::CaseInsensitive));
            assert(!item->text().contains(
                QStringLiteral("NTLMSSP"), Qt::CaseInsensitive));
            assert(!item->text().contains(
                QStringLiteral("Direct NTLM"), Qt::CaseInsensitive));
        }
        assert(diagnostic->text() ==
               QStringLiteral(
                   "Authentication: CredSSP — Direct NTLM — negotiation failed"));
        assert(!diagnostic->text().contains(
            QStringLiteral("invalid-gss-wrapper"), Qt::CaseInsensitive));
        assert(!diagnostic->text().contains(
            QStringLiteral("NTLMSSP"), Qt::CaseInsensitive));

        // CredSSP credentials are already verified here. A native Admission
        // failure is local-desktop authorization, not remote authentication.
        runtime.snapshot.acceptedClientPreauthDiagnostics.credSspTransition =
            RuntimeAcceptedClientCredSspTransition::CredentialsVerified;
        runtime.snapshot.acceptedClientPreauthDiagnostics.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::Admission;
        runtime.snapshot.acceptedClientPreauthDiagnostics
            .standaloneFailureStage =
                RuntimeAcceptedClientStandaloneFailureStage::Admission;
        runtime.snapshot.acceptedClientPreauthDiagnostics
            .admissionFailureReason =
                RuntimeAcceptedClientAdmissionFailureReason::
                    SessionMonitorUnavailable;
        window.refresh();

        const HostStatus admissionFailed = host.status();
        assert(admissionFailed.localDesktopAuthorizationFailed);
        assert(!admissionFailed.remoteAuthenticationFailed);
        assert(admissionFailed.listenerReady);
        assert(admissionFailed.credentialsConfigured);
        assert(sharingToggle(window)->isChecked());
        assert(!availability->isHidden());
        assert(availability->text() ==
               QStringLiteral(
                   "Native desktop admission denied."));
        assert(diagnostic->text() ==
               QStringLiteral(
                   "Local desktop authorization: session monitor unavailable"));
        for (const QString& internalText :
             {QStringLiteral("stage=admission"),
              QStringLiteral("CandidateOnly")})
        {
            assert(!availability->text().contains(
                internalText, Qt::CaseInsensitive));
            assert(!diagnostic->text().contains(
                internalText, Qt::CaseInsensitive));
        }
        assertNoRoadLabelsInUserText(window);

        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.snapshot.stage = RuntimeHostStage::ClientAuthenticating;
        runtime.snapshot.acceptedClientPreauthDiagnostics.credSspTransition =
            RuntimeAcceptedClientCredSspTransition::CredentialsVerified;
        runtime.snapshot.acceptedClientPreauthDiagnostics.authenticationStage =
            RuntimeAcceptedClientAuthenticationStage::Authenticated;
        runtime.snapshot.acceptedClientPreauthDiagnostics
            .standaloneFailureStage =
                RuntimeAcceptedClientStandaloneFailureStage::None;
        runtime.snapshot.acceptedClientPreauthDiagnostics
            .admissionFailureReason =
                RuntimeAcceptedClientAdmissionFailureReason::None;
        window.refresh();
        assert(host.status().productState ==
               RuntimeProductHostState::Authenticating);
        assert(readiness->text() ==
               QStringLiteral("A remote device is authenticating."));
        assert(availability->isHidden());

        runtime.snapshot.stage = RuntimeHostStage::ClientConnected;
        runtime.snapshot.nativeDesktopReady = true;
        runtime.snapshot.activeClients = {
            RuntimeHostClient{
                42U, "192.168.0.44", false, true, true}};
        window.refresh();
        assert(host.status().productState ==
               RuntimeProductHostState::Connected);
        assert(readiness->text() == QStringLiteral("Sharing is on."));
        assert(host.status().credentialsConfigured);
        assert(host.status().listenerReady);
        return 0;
    }

    if (mode == "consumer-password-change-rerequests-permission")
    {
#if !defined(RDP_SERVER_OWNER_ACCEPTANCE_TEST_UI)
        return 77;
#endif
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.snapshot.credentialsConfigured = true;
        runtime.snapshot.hostOwnerAuthorized = true;
        runtime.snapshot.product.sharingPermission = {
            true, true, true, true, 15U * 60U * 1000U,
            RuntimeSharingPermissionDenial::None};
        runtime.interfaces = {
            RuntimeHostInterface{
                "ethernet-1", "Private Ethernet",
                {"192.168.0.10"}, false, true}};
        runtime.standaloneCredentialSucceeds = true;
        runtime.permissionSetupSucceeds = true;
        runtime.configurePreparesTlsIdentity = true;
        runtime.startSucceeds = true;

        DesktopWindow window(host);
        auto* username =
            window.findChild<QLineEdit*>("standaloneUsername");
        auto* password =
            window.findChild<QLineEdit*>("sessionPassword");
        auto* confirmation =
            window.findChild<QLineEdit*>("sessionPasswordConfirm");
        assert(username && password && confirmation);
        assert(username->isEnabled() && !username->isReadOnly());
        assert(password->isEnabled() && !password->isReadOnly());
        assert(confirmation->isEnabled() && !confirmation->isReadOnly());
        assert(password->echoMode() == QLineEdit::Password);
        assert(confirmation->echoMode() == QLineEdit::Password);
        password->setText(QStringLiteral("replacement-owner-password"));
        confirmation->setText(password->text());

        sharingToggle(window)->click();

        assert(runtime.standaloneCredentialCalls == 1);
        assert(runtime.permissionSetupCalls == 1);
        assert(runtime.lastPermissionRequest.allowInput);
        assert(!runtime.lastPermissionRequest.allowClipboard);
        assert(host.status().clipboardState ==
               RuntimeClipboardState::Unavailable);
        assert((runtime.commandOrder ==
                std::vector<std::string>{
                    "credential", "permission", "endpoint", "listener"}));
        assert(runtime.configureCalls == 1);
        assert(runtime.startCalls == 1);
        return 0;
    }

    if (mode == "consumer-workflow-failure")
    {
#if !defined(RDP_SERVER_OWNER_ACCEPTANCE_TEST_UI)
        // This test target keeps assertions enabled with -UNDEBUG even in a
        // Release build, so NDEBUG cannot describe the linked UI library.
        // CMake supplies this macro only for Debug or explicit acceptance UI.
        return 77;
#endif
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.interfaces = {
            RuntimeHostInterface{
                "ethernet-1", "Private Ethernet",
                {"192.168.0.10"}, false, true}};
        DesktopWindow window(host);
        auto* password =
            window.findChild<QLineEdit*>("sessionPassword");
        auto* confirmation =
            window.findChild<QLineEdit*>("sessionPasswordConfirm");
        password->setText(QStringLiteral("owner-test-password"));
        confirmation->setText(password->text());
        sharingToggle(window)->click();
        assert(runtime.standaloneCredentialCalls == 1);
        assert(runtime.permissionSetupCalls == 0);
        assert(runtime.configureCalls == 0);
        assert(runtime.startCalls == 0);
        assert(!sharingToggle(window)->isChecked());
        assert(
            requiredLabel(window, "hostErrorExplanation")
                ->text().contains("provisioning failed"));
        return 0;
    }

    if (mode == "consumer-listener-start-failure-clipboard-dormant")
    {
#if !defined(RDP_SERVER_OWNER_ACCEPTANCE_TEST_UI)
        return 77;
#endif
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.interfaces = {
            RuntimeHostInterface{
                "ethernet-1", "Private Ethernet",
                {"192.168.0.10"}, false, true}};
        runtime.standaloneCredentialSucceeds = true;
        runtime.permissionSetupSucceeds = true;
        runtime.configurePreparesTlsIdentity = true;
        runtime.startSucceeds = false;

        DesktopWindow window(host);
        auto* password =
            window.findChild<QLineEdit*>("sessionPassword");
        auto* confirmation =
            window.findChild<QLineEdit*>("sessionPasswordConfirm");
        auto* toggle = sharingToggle(window);
        auto* copy = requiredButton(window, "copyLanAddress");
        auto* address = requiredLabel(window, "connectionAddress");
        assert(password && confirmation);
        password->setText(QStringLiteral("owner-test-password"));
        confirmation->setText(password->text());
        assert(window.canStart());

        toggle->click();

        assert((runtime.commandOrder ==
                std::vector<std::string>{
                    "credential", "permission", "endpoint", "listener"}));
        assert(runtime.standaloneCredentialCalls == 1);
        assert(runtime.permissionSetupCalls == 1);
        assert(runtime.configureCalls == 1);
        assert(runtime.startCalls == 1);
        assert(!runtime.lastPermissionRequest.allowClipboard);
        assert(host.status().clipboardState ==
               RuntimeClipboardState::Unavailable);
        assert(!toggle->isChecked());
        assert(!copy->isEnabled());
        assert(address->text() ==
               QStringLiteral("Local address: 192.168.0.10"));
        assert(
            requiredLabel(window, "hostErrorExplanation")
                ->text().contains("listener"));
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
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.snapshot.credentialsConfigured = true;
        runtime.snapshot.hostOwnerAuthorized = true;
        runtime.snapshot.product.sharingPermission = {
            true, true, true, true,
            6U * 60U * 1000U + 58U * 1000U,
            RuntimeSharingPermissionDenial::None};

        DesktopWindow window(host);
        auto* permission =
            requiredLabel(window, "permissionStatus");
        assert(permission->text().startsWith(
            QStringLiteral("Sharing allowed for 6 min")));
        assert(permission->text().contains(
            QStringLiteral("screen and keyboard/mouse")));
        assert(!permission->text().contains(
            QStringLiteral("clipboard"), Qt::CaseInsensitive));

        runtime.snapshot.hostOwnerAuthorized = false;
        runtime.snapshot.product.sharingPermission = {
            true, false, false, false, 0U,
            RuntimeSharingPermissionDenial::PermissionExpired};
        window.refresh();
        assert(permission->text() == QStringLiteral("Permission expired"));
        return 0;
    }

    if (mode == "permission-product-language")
    {
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.snapshot.credentialsConfigured = true;
        runtime.deriveProductStatusFromLegacy = false;
        runtime.snapshot.product.controlAvailable = true;
        runtime.snapshot.product.state = RuntimeProductHostState::Stopped;
        runtime.snapshot.product.credentialsConfigured = true;
        runtime.snapshot.product.credentialCapabilities.existingOsAccount = true;

        DesktopWindow window(host);
        auto* permission = requiredLabel(window, "permissionStatus");
        auto* request = requiredButton(window, "requestHostPermission");

        runtime.snapshot.product.sharingPermission = {
            true, false, false, false, 0U,
            RuntimeSharingPermissionDenial::PermissionRequired};
        window.refresh();
        assert(permission->text() ==
               QStringLiteral("Sharing permission required"));
        assert(request->isEnabled());

        runtime.snapshot.product.sharingPermission = {
            false, false, false, false, 0U,
            RuntimeSharingPermissionDenial::ComputerLocked};
        window.refresh();
        assert(permission->text() == QStringLiteral("Computer is locked"));
        assert(!request->isEnabled());

        runtime.snapshot.product.sharingPermission = {
            true, false, false, false, 0U,
            RuntimeSharingPermissionDenial::LoggedInDesktopChanged};
        window.refresh();
        assert(permission->text() ==
               QStringLiteral("Logged-in desktop changed"));
        assert(request->isEnabled());

        runtime.snapshot.product.sharingPermission = {
            true, false, false, false, 0U,
            RuntimeSharingPermissionDenial::PermissionRevoked};
        window.refresh();
        assert(permission->text() ==
               QStringLiteral("Sharing permission revoked"));
        assert(request->isEnabled());

        runtime.snapshot.hostOwnerAuthorized = true;
        runtime.snapshot.product.ownerAuthorized = true;
        runtime.snapshot.product.sharingPermission = {
            true, true, true, false,
            14U * 60U * 1000U + 59U * 1000U,
            RuntimeSharingPermissionDenial::None};
        window.refresh();
        assert(permission->text().startsWith(
            QStringLiteral("Sharing allowed for 14 min")));
        assert(permission->text().contains(QStringLiteral("screen only")));
        assertNoRoadLabelsInUserText(window);
        return 0;
    }

    if (mode == "permission-requestability-gates-sharing")
    {
        runtime.snapshot.lastError = RuntimeHostError::None;
        runtime.interfaces = {
            RuntimeHostInterface{
                "ethernet-1", "Private Ethernet",
                {"192.168.0.10"}, false, true}};
        runtime.deriveProductStatusFromLegacy = false;

        auto& product = runtime.snapshot.product;
        product.controlAvailable = true;
        product.state = RuntimeProductHostState::Stopped;
        product.credentialsConfigured = true;
        product.credentialCapabilities.existingOsAccount = true;
        product.eligibleLanInterfaces = runtime.interfaces;
        product.recommendedEndpoint =
            recommendRuntimePrivateLanEndpoint(runtime.interfaces);
        product.ownerAuthorized = false;
        product.sharingPermission = {
            false, false, false, false, 0U,
            RuntimeSharingPermissionDenial::Unavailable};

        DesktopWindow window(host);
        auto* permission = requiredLabel(window, "permissionStatus");
        auto* request = requiredButton(window, "requestHostPermission");
        auto* toggle = sharingToggle(window);
        auto* traySharing = requiredAction(window, "traySharing");

        assert(permission->text() ==
               QStringLiteral("Sharing permission unavailable"));
        assert(!request->isEnabled());
        assert(!window.canStart());
        assert(!toggle->isEnabled() && !toggle->isChecked());
        assert(!traySharing->isEnabled());
        assert(runtime.permissionSetupCalls == 0);
        assert(runtime.configureCalls == 0);
        assert(runtime.startCalls == 0);

        product.sharingPermission = {
            true, false, false, false, 0U,
            RuntimeSharingPermissionDenial::PermissionRequired};
        window.refresh();

        assert(permission->text() ==
               QStringLiteral("Sharing permission required"));
        assert(request->isEnabled());
        assert(window.canStart());
        assert(toggle->isEnabled() && !toggle->isChecked());
        assert(traySharing->isEnabled());
        assert(runtime.permissionSetupCalls == 0);
        assert(runtime.configureCalls == 0);
        assert(runtime.startCalls == 0);

        // Requestability is not a grant. The explicit Sharing action asks R10
        // for local permission first; this failing fixture must never proceed
        // to endpoint configuration or listener Start.
        toggle->click();
        assert(runtime.permissionSetupCalls == 1);
        assert(runtime.configureCalls == 0);
        assert(runtime.startCalls == 0);
        assert(!toggle->isChecked());
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
        product.recommendedEndpoint = {
            "wifi-2", "192.168.50.20", 3389U,
            RuntimeHostAddressFamily::Ipv4, true, true, 10U, false,
            RuntimeHostRecommendationSource::PreferredRoute};
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
               QStringLiteral("Local address: 192.168.50.20"));

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
        assert(title->text().contains("Sharing"));
        assert(address->text() ==
               QStringLiteral("Connect to: 192.168.50.20:3389"));
        assert(host.status().clientCount == 1U);
        assert(host.status().activeClients.size() == 1U);
        assert(host.status().activeClients.front().opaqueId == 77U);

        product.state = RuntimeProductHostState::Stopping;
        window.refresh();
        assert(toggle->isChecked());
        assert(title->text().contains("Sharing"));

        product.state = RuntimeProductHostState::Error;
        product.lastErrorMessage = "Host operation failed";
        window.refresh();
        assert(!toggle->isChecked());
        assert(title->text().contains("Stopped"));
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
        assert(interfaces->currentIndex() == 1);
        assert(address->text() == QStringLiteral("Local address: 192.168.2.21"));
        assert(window.canStart() && toggle->isEnabled());

        interfaces->setCurrentIndex(2);
        assert(address->text() ==
               QStringLiteral("Local address: 192.168.2.21"));
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
        runtime.snapshot.listenerAvailable = true;
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
        assert(interfaces->currentIndex() == 0);
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

    if (mode == "product-hosting-listener-readiness")
    {
        prepareReadyHost(runtime);
        runtime.deriveProductStatusFromLegacy = false;
        runtime.snapshot.stage = RuntimeHostStage::Stopped;
        runtime.snapshot.listenerAvailable = false;
        runtime.snapshot.lastError = RuntimeHostError::None;

        auto& product = runtime.snapshot.product;
        product.state = RuntimeProductHostState::Listening;
        assert(host.status().listenerReady);

        product.state = RuntimeProductHostState::Connected;
        assert(host.status().listenerReady);

        product.state = RuntimeProductHostState::Stopped;
        assert(!host.status().listenerReady);

        product.state = RuntimeProductHostState::Connected;
        runtime.snapshot.lastError = RuntimeHostError::AccessRevoked;
        assert(!host.status().listenerReady);
        return 0;
    }

    if (mode == "local-username-default-no-password-prefill")
    {
        DesktopWindow window(host);
        auto* username = window.findChild<QLineEdit*>("standaloneUsername");
        auto* password = window.findChild<QLineEdit*>("sessionPassword");
        auto* confirmation =
            window.findChild<QLineEdit*>("sessionPasswordConfirm");
        assert(username && password && confirmation);

        const QString suggestion = currentLocalUsernameSuggestion();
        assert(username->text() == suggestion);
        if (!suggestion.isEmpty())
            assert(isSafeLocalUsernameSuggestion(suggestion));

        // Representative system/service identities must never become a
        // first-launch convenience default.
        assert(isSafeLocalUsernameSuggestion(
            QStringLiteral("ordinary-user")));
        assert(!isSafeLocalUsernameSuggestion(QStringLiteral("root")));
        assert(!isSafeLocalUsernameSuggestion(QStringLiteral("SYSTEM")));
        assert(!isSafeLocalUsernameSuggestion(QStringLiteral("daemon")));
        assert(!isSafeLocalUsernameSuggestion(
            QStringLiteral("_windowserver")));
        assert(!isSafeLocalUsernameSuggestion(QStringLiteral("machine$")));
        assert(!isSafeLocalUsernameSuggestion(QStringLiteral("bad\\name")));
        assert(!isSafeLocalUsernameSuggestion(QStringLiteral("bad/name")));

        assert(username->echoMode() == QLineEdit::Normal);
        assert(password->text().isEmpty());
        assert(confirmation->text().isEmpty());
        assert(password->echoMode() == QLineEdit::Password);
        assert(confirmation->echoMode() == QLineEdit::Password);

        // Replacing the non-secret suggestion never populates either
        // independent Session Password field. Editability itself is covered
        // by the owner-acceptance capability tests, not this Release-safe case.
        username->setText(QStringLiteral("remote-alias"));
        assert(username->text() == QStringLiteral("remote-alias"));
        assert(password->text().isEmpty());
        assert(confirmation->text().isEmpty());
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
        assert(credentials->text().contains("Session Password"));
        assert(permission->text() ==
               QStringLiteral("Sharing permission required"));
        assert(!window.canStart());

        prepareReadyHost(runtime);
        window.refresh();
        assert(window.canStart());
        assert(sharingToggle(window)->isEnabled());
        return 0;
    }

    // Default full-path regression: one page, auto-address, authoritative
    // toggle, connected-device projection and explicit Stop/Revoke.
    checkRound2TabsAndMainSimplicity(runtime, host);
    prepareReadyHost(runtime);
    runtime.startSucceeds = true;
    {
        DesktopWindow window(host);
        auto* toggle = sharingToggle(window);
        auto* copy = requiredButton(window, "copyLanAddress");
        assert(window.canStart() && toggle->isEnabled());
        const QString clipboardBefore = application.clipboard()->text();
        assert(!copy->isEnabled());
        copy->click();
        assert(application.clipboard()->text() == clipboardBefore);

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
        assert(runtime.stopCalls == 1 && runtime.revokeCalls == 0);
        assert(!toggle->isChecked());
    }

    return 0;
}
