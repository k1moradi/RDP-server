// SPDX-License-Identifier: GPL-3.0-or-later
#include "desktop_window.h"
#if defined(Q_OS_LINUX)
#include "linux_prerequisites.h"
#endif
#include <QApplication>
#include <QClipboard>
#include <QCloseEvent>
#include <QComboBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSpinBox>
#include <QSignalBlocker>
#include <QStackedWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <QVariant>
#include <algorithm>
namespace rdp::gui {
namespace {
QLabel* label(const QString& message) {
    // Set the format before assigning runtime text. Constructing QLabel with
    // that text would first invoke AutoText's HTML detection/parsing.
    auto* result = new QLabel();
    result->setTextFormat(Qt::PlainText);
    result->setText(message);
    result->setWordWrap(true);
    return result;
}

QString clipboardStatusText(
    const rdp_server::server::runtime::RuntimeClipboardState state)
{
    using rdp_server::server::runtime::RuntimeClipboardState;
    switch (state) {
    case RuntimeClipboardState::Unavailable:
        return "Clipboard unavailable: no current authenticated CLIPRDR session.";
    case RuntimeClipboardState::Enabled:
        return "Clipboard enabled for the current authenticated session.";
    case RuntimeClipboardState::Retired:
        return "Clipboard retired: reconnect and reauthorization are required.";
    case RuntimeClipboardState::Denied:
        return "Clipboard denied by current session policy.";
    }
    return "Clipboard unavailable: invalid session state.";
}

// R10 stages are presentation evidence, never a new GUI state machine.
QString hostLifecycleText(const HostStatus& state)
{
    using rdp_server::server::runtime::RuntimeHostStage;
    if (!state.controlAvailable)
        return QStringLiteral("Host control unavailable; listener and clients unconfirmed.");

    switch (state.stage) {
    case RuntimeHostStage::Stopped:
        return QStringLiteral("Stopped; no active listener confirmed.");
    case RuntimeHostStage::PackageInstalled:
        return QStringLiteral("Installed; sharing not started.");
    case RuntimeHostStage::CredentialsConfigured:
        return QStringLiteral("OS credentials configured; listener not ready.");
    case RuntimeHostStage::ListenerAvailable:
        return state.listenerReady
            ? QStringLiteral("Listener ready; waiting for desktop connection.")
            : QStringLiteral("Listener readiness unconfirmed.");
    case RuntimeHostStage::ClientAuthenticating:
        return QStringLiteral("Peer authenticating; desktop not yet visible.");
    case RuntimeHostStage::ShareActivated:
        return QStringLiteral("Share activated; desktop not yet visible.");
    case RuntimeHostStage::DesktopVisible:
        return QStringLiteral("Desktop visible; client not yet confirmed.");
    case RuntimeHostStage::ClientConnected:
        return state.clients.isEmpty()
            ? QStringLiteral("Client-connected stage; no visible client confirmed.")
            : QStringLiteral("Client connected; desktop visible.");
    case RuntimeHostStage::Revoked:
        return QStringLiteral("Sharing revoked/stopped.");
    }
    return QStringLiteral("Unrecognized R10 hosting stage.");
}

// R2 may suppress visible Share on stale authorization before the R10 owner
// retires the raw stage. Never treat that diagnostic as Stop or close proof.
[[nodiscard]] bool mayStillBeHosting(const HostStatus& state) noexcept
{
    using rdp_server::server::runtime::RuntimeHostStage;
    switch (state.stage) {
    case RuntimeHostStage::ListenerAvailable:
    case RuntimeHostStage::ClientAuthenticating:
    case RuntimeHostStage::ShareActivated:
    case RuntimeHostStage::DesktopVisible:
    case RuntimeHostStage::ClientConnected:
        return true;
    case RuntimeHostStage::Stopped:
    case RuntimeHostStage::PackageInstalled:
    case RuntimeHostStage::CredentialsConfigured:
    case RuntimeHostStage::Revoked:
        return state.sharing || state.startPending;
    }
    return true; // Unknown future stages must fail closed.
}
}
DesktopWindow::DesktopWindow(HostControl& host, QWidget* parent)
    : QWidget(parent), host_(host), pages_(new QStackedWidget(this)),
      desktops_(new QComboBox(this)), interfaces_(new QComboBox(this)),
      clientSelection_(new QComboBox(this)),
      port_(new QSpinBox(this)), password_(new QLineEdit(this)),
      confirmation_(new QLineEdit(this)),
      configureOsAccount_(new QPushButton("Use Existing OS Account", this)),
      requestHostPermission_(new QPushButton("Request Host Permission", this)),
      start_(new QPushButton("Start Sharing", this)),
      stop_(new QPushButton("Stop Sharing / Revoke", this)),
      disconnect_(new QPushButton("Disconnect Selected Client", this)),
      copy_(new QPushButton("Copy LAN Address", this)),
      desktopStatus_(label({})), credentialStatus_(label({})),
      permissionStatus_(label({})), clipboardStatus_(label({})),
      selectedInterfaceStatus_(label({})), endpointStatus_(label({})),
      errorStatus_(label({})), tlsIdentityStatus_(label({})),
      hostLifecycleStatus_(label({})), status_(label({})), activity_(label({})) {
    setWindowTitle("RDP-server - LAN desktop sharing");
    setMinimumSize(600, 440);
    auto* root = new QVBoxLayout(this);
    root->addWidget(pages_);
    auto page = [this](const QString& heading) {
        auto* widget = new QWidget(this);
        auto* layout = new QVBoxLayout(widget);
        layout->addWidget(label(heading));
        pages_->addWidget(widget);
        return layout;
    };
    auto* welcome = page("Welcome: Share an existing logged-in desktop on your LAN");
    welcome->addWidget(label("No cloud account or internet required. Before sharing, "
        "R2 compatible OS authentication, R10 host runtime, an authorized desktop, "
        "TLS identity and screen/input access must all be available."));
    welcome->addWidget(label("Opening this application never starts a listener, capture or permissions prompt."));
    welcome->addStretch();
    auto* desktop = page("Choose an authorized logged-in desktop");
    desktops_->setObjectName("desktopSelection");
    desktops_->addItem("No admitted desktop (R2 authorization pending)");
    desktop->addWidget(desktops_);
    desktop->addWidget(desktopStatus_);
    desktop->addWidget(label("Desktop selection cannot grant R2 admission. Failed authorization remains blocked."));
    desktop->addStretch();
    auto* credentials = page("Credentials: OS-backed RDP/NLA authentication");
    credentials->addWidget(label("OS-backed credentials require an R2 compatible provider. "
        "Application access password is a future feature and is NOT an RDP/NLA password."));
    configureOsAccount_->setObjectName("configureOsAccount");
    credentials->addWidget(configureOsAccount_);
    credentials->addWidget(credentialStatus_);
    password_->setObjectName("password");
    confirmation_->setObjectName("confirmation");
    password_->setPlaceholderText("Future application access password (disabled)");
    confirmation_->setPlaceholderText("Confirm future application password (disabled)");
    password_->setEchoMode(QLineEdit::Password);
    confirmation_->setEchoMode(QLineEdit::Password);
    password_->setEnabled(false);
    confirmation_->setEnabled(false);
    credentials->addWidget(password_);
    credentials->addWidget(confirmation_);
    credentials->addStretch();
    auto* network = page("LAN interface and listening port");
    interfaces_->setObjectName("lanInterface");
    interfaces_->addItem("No R10-validated LAN interface available", QString());
    port_->setRange(1, 65535);
    port_->setValue(3389);
    auto* form = new QFormLayout();
    form->addRow("Interface", interfaces_);
    form->addRow("Port", port_);
    network->addLayout(form);
    selectedInterfaceStatus_->setObjectName("selectedLanInterfaceStatus");
    network->addWidget(selectedInterfaceStatus_);
    network->addWidget(label("R10 must validate and bind the selected private LAN interface. "
        "No wildcard/public listener is selected by the GUI."));
    network->addStretch();
    auto* permissions = page("Platform security prerequisites");
    permissions->addWidget(label("Firewall: authorize inbound RDP on the trusted LAN interface only. "
        "TLS: clients must verify the host identity/fingerprint; a certificate is not automatically trusted."));
    tlsIdentityStatus_->setObjectName("tlsIdentityStatus");
    permissions->addWidget(tlsIdentityStatus_);
    permissions->addWidget(label("Linux X11 logged-in seat, Windows interactive desktop, and macOS Screen "
        "Recording/Accessibility/Input Monitoring are platform-dependent. macOS TCC consent is requested "
        "later by the real native owner, never as authentication."));
#if defined(Q_OS_LINUX)
    // R5: display read-only native seat/X11 prerequisites without creating
    // an R2 selection, listener, X11 capture, logind watcher or input owner.
    auto* linuxPrerequisites = label(
        "Linux X11 prerequisites not yet inspected; no native admission.");
    linuxPrerequisites->setObjectName("linuxPrerequisiteStatus");
    permissions->addWidget(linuxPrerequisites);
    auto* refreshLinux = new QPushButton("Refresh Linux X11 prerequisites", this);
    refreshLinux->setObjectName("refreshLinuxPrerequisites");
    permissions->addWidget(refreshLinux);
    connect(refreshLinux, &QPushButton::clicked, this, [linuxPrerequisites] {
        requestLinuxPrerequisites(linuxPrerequisites);
    });
    // Probe asynchronously only after the window event loop starts. Launch
    // remains unprivileged and does not start sharing or capture pixels.
    QTimer::singleShot(0, linuxPrerequisites, [linuxPrerequisites] {
        requestLinuxPrerequisites(linuxPrerequisites);
    });
#endif
    requestHostPermission_->setObjectName("requestHostPermission");
    permissions->addWidget(requestHostPermission_);
    permissions->addWidget(permissionStatus_);
    permissions->addStretch();
    auto* sharing = page("Sharing and connection status");
    start_->setObjectName("startSharing");
    stop_->setObjectName("stopSharing");
    auto* actions = new QHBoxLayout();
    actions->addWidget(start_);
    actions->addWidget(stop_);
    sharing->addLayout(actions);
    clipboardStatus_->setObjectName("clipboardStatus");
    sharing->addWidget(clipboardStatus_);
    hostLifecycleStatus_->setObjectName("hostLifecycleStatus");
    sharing->addWidget(hostLifecycleStatus_);
    sharing->addWidget(status_);
    endpointStatus_->setObjectName("boundLanEndpoint");
    sharing->addWidget(endpointStatus_);
    errorStatus_->setObjectName("hostErrorExplanation");
    sharing->addWidget(errorStatus_);
    copy_->setObjectName("copyLanAddress");
    sharing->addWidget(copy_);
    clientSelection_->setObjectName("activeClientSelection");
    clientSelection_->addItem("Select an active client", QVariant());
    disconnect_->setObjectName("disconnectClient");
    auto* clientActions = new QHBoxLayout();
    clientActions->addWidget(clientSelection_);
    clientActions->addWidget(disconnect_);
    sharing->addLayout(clientActions);
    activity_->setObjectName("clientStatus");
    sharing->addWidget(activity_);
    sharing->addStretch();
    auto* navigation = new QHBoxLayout();
    auto* back = new QPushButton("Back", this);
    auto* next = new QPushButton("Next", this);
    back->setObjectName("backPage");
    next->setObjectName("nextPage");
    navigation->addWidget(back);
    navigation->addWidget(next);
    root->addLayout(navigation);
    connect(back, &QPushButton::clicked, this, [this] { changePage(pages_->currentIndex() - 1); });
    connect(next, &QPushButton::clicked, this, [this] { changePage(pages_->currentIndex() + 1); });
    connect(configureOsAccount_, &QPushButton::clicked, this, [this] {
        (void)host_.requestExistingOsAccount();
        refresh(); // Only a later R10 snapshot may report configured state.
    });
    connect(requestHostPermission_, &QPushButton::clicked, this, [this] {
        (void)host_.requestHostPermission();
        refresh(); // A request never fabricates desktop authorization.
    });
    connect(start_, &QPushButton::clicked, this, [this] {
        const auto snapshot = host_.status();
        if (snapshot.sharing || snapshot.startPending || !blockedReason(snapshot).isEmpty()) return;
        const HostRequest request{interfaces_->currentData(Qt::UserRole + 1).toString(),
            interfaces_->currentData().toString(),
            static_cast<std::uint16_t>(port_->value())};
        (void)host_.start(request); // Never use return value as active-sharing proof.
        refresh();
    });
    connect(stop_, &QPushButton::clicked, this, [this] {
        const auto snapshot = host_.status();
        if (!mayStillBeHosting(snapshot)) return;
        host_.stopAndRevoke();
        refresh();
    });
    connect(disconnect_, &QPushButton::clicked, this, [this] {
        const auto snapshot = host_.status();
        const QVariant selectedClient = clientSelection_->currentData();
        if (!snapshot.controlAvailable ||
            (!snapshot.sharing && !snapshot.startPending) ||
            !selectedClient.isValid())
            return;
        bool validId = false;
        const auto selectedId = selectedClient.toULongLong(&validId);
        if (!validId || selectedId == 0 ||
            !std::ranges::any_of(snapshot.activeClients,
                [selectedId](const ActiveClientChoice& client) {
                    return client.opaqueId == selectedId;
                }))
            return;
        (void)host_.disconnectClient(static_cast<std::uint64_t>(selectedId));
        refresh(); // R10 status, not the click, confirms disconnect.
    });
    connect(copy_, &QPushButton::clicked, this, [this] {
        const auto state = host_.status();
        if (state.sharing && !state.lanAddress.isEmpty())
            QApplication::clipboard()->setText(state.lanAddress);
    });
    connect(interfaces_, &QComboBox::currentIndexChanged, this, [this](int) { refresh(); });
    connect(clientSelection_, &QComboBox::currentIndexChanged, this, [this](int) { refresh(); });
    connect(password_, &QLineEdit::textChanged, this, [this] { refresh(); });
    connect(confirmation_, &QLineEdit::textChanged, this, [this] { refresh(); });
    refresh();
}
void DesktopWindow::changePage(int index) {
    if (index >= 0 && index < pages_->count()) pages_->setCurrentIndex(index);
}
QString DesktopWindow::blockedReason() const {
    return blockedReason(host_.status());
}
QString DesktopWindow::blockedReason(const HostStatus& state) const {
    if (!state.controlAvailable) return "R10 host control unavailable";
    if (!state.credentialsConfigured) return "OS-backed credentials are not configured";
    if (!state.desktopAuthorized || state.desktop.isEmpty()
        || desktops_->currentData().toString() != state.desktop)
        return "Logged-in desktop not R2-authorized";
    if (!state.tlsReady) return "TLS identity unavailable";
    if (!state.captureInputReady) return "Screen/input permissions unavailable";
    const QString selectedInterface = interfaces_->currentData().toString();
    const QString selectedInterfaceId =
        interfaces_->currentData(Qt::UserRole + 1).toString();
    if (selectedInterface.isEmpty() || selectedInterfaceId.isEmpty() ||
        !std::ranges::any_of(state.approvedLanInterfaces,
            [&](const LanInterfaceChoice& candidate) {
                return candidate.stableId == selectedInterfaceId &&
                       candidate.address == selectedInterface;
            }))
        return "R10-approved LAN interface not selected";
    if (password_->isEnabled() &&
        (password_->text().isEmpty() || password_->text() != confirmation_->text()))
        return "Application password confirmation mismatch";
    return {};
}
bool DesktopWindow::canStart() const {
    const auto state = host_.status();
    return !state.sharing && !state.startPending && blockedReason(state).isEmpty();
}
void DesktopWindow::refresh() {
    const auto snapshot = host_.status();
    const QString previousInterface = interfaces_->currentData().toString();
    const QString previousInterfaceId =
        interfaces_->currentData(Qt::UserRole + 1).toString();
    const QVariant previousClientId = clientSelection_->currentData();
    // A refreshed R10/R2 snapshot invalidates removed interface/session choices.
    {
        const QSignalBlocker blocked(desktops_);
        desktops_->clear();
        desktops_->addItem("No admitted desktop", QString());
        if (snapshot.desktopAuthorized && !snapshot.desktop.isEmpty()) {
            desktops_->addItem(snapshot.desktop, snapshot.desktop);
            desktops_->setCurrentIndex(1);
        }
    }
    {
        const QSignalBlocker blocked(interfaces_);
        interfaces_->clear();
        interfaces_->addItem("Select R10-approved LAN interface", QString());
        for (const LanInterfaceChoice& choice : snapshot.approvedLanInterfaces) {
            if (choice.address.isEmpty() || choice.stableId.isEmpty())
                continue;
            const QString name = choice.displayName.isEmpty()
                ? choice.address : choice.displayName + " (" + choice.address + ")";
            interfaces_->addItem(name, choice.address);
            interfaces_->setItemData(interfaces_->count() - 1,
                                     choice.stableId, Qt::UserRole + 1);
        }
        for (int index = 1; index < interfaces_->count(); ++index) {
            if (interfaces_->itemData(index).toString() == previousInterface &&
                interfaces_->itemData(index, Qt::UserRole + 1).toString() ==
                    previousInterfaceId) {
                interfaces_->setCurrentIndex(index);
                break;
            }
        }
    }
    {
        const QSignalBlocker blocked(clientSelection_);
        clientSelection_->clear();
        clientSelection_->addItem("Select an active client", QVariant());
        for (const ActiveClientChoice& client : snapshot.activeClients) {
            if (client.opaqueId == 0)
                continue;
            const QVariant opaqueId = QVariant::fromValue<qulonglong>(client.opaqueId);
            if (clientSelection_->findData(opaqueId) < 0)
                clientSelection_->addItem(client.displayName, opaqueId);
        }
        const int index = clientSelection_->findData(previousClientId);
        if (index > 0)
            clientSelection_->setCurrentIndex(index);
    }
    selectedInterfaceStatus_->setText(interfaces_->currentIndex() > 0
        ? "Selected R10 LAN interface: " + interfaces_->currentText()
        : "No R10-approved LAN interface selected.");
    endpointStatus_->setText(snapshot.lanAddress.isEmpty()
        ? "Bound LAN endpoint: not reported by R10; no listener is implied."
        : "R10-reported bound LAN endpoint: " + snapshot.lanAddress);
    errorStatus_->setText(snapshot.failure.isEmpty()
        ? "R10 host error: none reported."
        : "R10 host error: " + snapshot.failure);
    tlsIdentityStatus_->setText(snapshot.tlsReady
        ? "TLS identity readiness reported by R10. SHA-256 fingerprint and client trust status are not supplied; no client trust is inferred."
        : "TLS identity unavailable. SHA-256 fingerprint and client trust status are not supplied by R10/R1.");
    desktopStatus_->setText(snapshot.desktopAuthorized && !snapshot.desktop.isEmpty()
        ? "R2-authorized desktop reported: " + snapshot.desktop
        : "Authorization unavailable: " + (snapshot.failure.isEmpty()
            ? "No authenticated host-owner admission" : snapshot.failure));
    credentialStatus_->setText(snapshot.credentialsConfigured
        ? "Existing OS-account access policy configured. The RDP client must still authenticate with that OS account."
        : "OS-account access is not configured. Application passwords are unsupported for NLA.");
    permissionStatus_->setText(snapshot.desktopAuthorized
        ? "Host-owner desktop permission is current."
        : "Host-owner permission is not established; Start remains blocked.");
    configureOsAccount_->setEnabled(
        snapshot.controlAvailable && !snapshot.sharing && !snapshot.startPending);
    requestHostPermission_->setEnabled(
        snapshot.controlAvailable && snapshot.credentialsConfigured &&
        !snapshot.sharing && !snapshot.startPending);
    const QString denial = blockedReason(snapshot);
    clipboardStatus_->setText(clipboardStatusText(snapshot.clipboardState));
    hostLifecycleStatus_->setText(hostLifecycleText(snapshot));
    start_->setEnabled(!snapshot.sharing && !snapshot.startPending && denial.isEmpty());
    stop_->setEnabled(mayStillBeHosting(snapshot));
    clientSelection_->setEnabled(snapshot.controlAvailable &&
        (snapshot.sharing || snapshot.startPending) &&
        !snapshot.activeClients.isEmpty());
    disconnect_->setEnabled(clientSelection_->isEnabled() &&
        clientSelection_->currentIndex() > 0);
    copy_->setEnabled(snapshot.sharing && !snapshot.lanAddress.isEmpty());
    status_->setText(!snapshot.controlAvailable
        ? "R10 control unavailable; hosting retirement unconfirmed."
        : (snapshot.sharing
            ? (snapshot.lanAddress.isEmpty()
                ? "R10 reports sharing; LAN address unavailable."
                : "R10 sharing address: " + snapshot.lanAddress)
            : (snapshot.startPending ? "R10 start pending; sharing not confirmed."
                : "Not sharing. " +
                    (snapshot.failure.isEmpty() ? denial : snapshot.failure))));
    activity_->setText("Connected clients: " + (snapshot.clients.isEmpty() ? "None" : snapshot.clients.join(", "))
        + "\nAuthenticating / desktop pending: " +
            (snapshot.pendingClients.isEmpty() ? "None" : snapshot.pendingClients.join(", "))
        + "\nAuthentication failures: " + (snapshot.authenticationFailures.isEmpty()
            ? "None" : snapshot.authenticationFailures.join(", "))
        + "\nDisconnected: " + (snapshot.disconnected.isEmpty() ? "None" : snapshot.disconnected.join(", "))
        + "\nLocked/revoked: " + (snapshot.revoked.isEmpty() ? "None" : snapshot.revoked.join(", ")));
}
void DesktopWindow::closeEvent(QCloseEvent* event) {
    const auto state = host_.status();
    if (mayStillBeHosting(state)) {
        // A window close is not permission to hide unattended sharing or
        // silently Stop. Only an explicit user choice may request R10 retirement.
        QMessageBox confirmation(this);
        confirmation.setWindowTitle("Stop remote desktop sharing?");
        confirmation.setIcon(QMessageBox::Warning);
        confirmation.setTextFormat(Qt::PlainText);
        confirmation.setText(
            "The sharing window cannot be hidden while a session is active. "
            "Stop sharing and revoke access before closing, or keep the window open.");
        auto* stopAndClose = confirmation.addButton(
            "Stop Sharing and Close", QMessageBox::AcceptRole);
        stopAndClose->setObjectName("confirmStopSharingAndClose");
        auto* keepOpen = confirmation.addButton(
            "Keep Window Open", QMessageBox::RejectRole);
        keepOpen->setObjectName("keepSharingWindowOpen");
        confirmation.setDefaultButton(keepOpen);
        confirmation.exec();
        if (confirmation.clickedButton() != stopAndClose) {
            event->ignore();
            return;
        }

        // R10 alone retires active ownership. A successful command is not
        // retirement proof; keep the GUI visible until its status confirms it.
        host_.stopAndRevoke();
        const auto after = host_.status();
        if (!after.controlAvailable || mayStillBeHosting(after)) {
            refresh();
            event->ignore(); // Never orphan unconfirmed active sharing.
            return;
        }
    }
    QWidget::closeEvent(event);
}
}
