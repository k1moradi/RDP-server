// SPDX-License-Identifier: GPL-3.0-or-later
#include "desktop_window.h"
#include <QApplication>
#include <QClipboard>
#include <QCloseEvent>
#include <QComboBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QSignalBlocker>
#include <QStackedWidget>
#include <QVBoxLayout>
namespace rdp::gui {
namespace {
QLabel* label(const QString& message) {
    auto* result = new QLabel(message);
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
}
DesktopWindow::DesktopWindow(HostControl& host, QWidget* parent)
    : QWidget(parent), host_(host), pages_(new QStackedWidget(this)),
      desktops_(new QComboBox(this)), interfaces_(new QComboBox(this)),
      port_(new QSpinBox(this)), password_(new QLineEdit(this)),
      confirmation_(new QLineEdit(this)),
      configureOsAccount_(new QPushButton("Use Existing OS Account", this)),
      requestHostPermission_(new QPushButton("Request Host Permission", this)),
      start_(new QPushButton("Start Sharing", this)),
      stop_(new QPushButton("Stop Sharing / Revoke", this)),
      copy_(new QPushButton("Copy LAN Address", this)),
      desktopStatus_(label({})), credentialStatus_(label({})),
      permissionStatus_(label({})), clipboardStatus_(label({})),
      status_(label({})), activity_(label({})) {
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
    network->addWidget(label("R10 must validate and bind the selected private LAN interface. "
        "No wildcard/public listener is selected by the GUI."));
    network->addStretch();
    auto* permissions = page("Platform security prerequisites");
    permissions->addWidget(label("Firewall: authorize inbound RDP on the trusted LAN interface only. "
        "TLS: clients must verify the host identity/fingerprint; a certificate is not automatically trusted."));
    permissions->addWidget(label("Linux X11 logged-in seat, Windows interactive desktop, and macOS Screen "
        "Recording/Accessibility/Input Monitoring are platform-dependent. macOS TCC consent is requested "
        "later by the real native owner, never as authentication."));
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
    sharing->addWidget(status_);
    copy_->setObjectName("copyLanAddress");
    sharing->addWidget(copy_);
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
        const HostRequest request{interfaces_->currentData().toString(),
            static_cast<std::uint16_t>(port_->value())};
        (void)host_.start(request); // Never use return value as active-sharing proof.
        refresh();
    });
    connect(stop_, &QPushButton::clicked, this, [this] {
        const auto snapshot = host_.status();
        if (!snapshot.sharing && !snapshot.startPending) return;
        host_.stopAndRevoke();
        refresh();
    });
    connect(copy_, &QPushButton::clicked, this, [this] {
        const auto state = host_.status();
        if (state.sharing && !state.lanAddress.isEmpty())
            QApplication::clipboard()->setText(state.lanAddress);
    });
    connect(interfaces_, &QComboBox::currentIndexChanged, this, [this](int) { refresh(); });
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
    if (selectedInterface.isEmpty() || !state.approvedLanInterfaces.contains(selectedInterface))
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
        for (const auto& address : snapshot.approvedLanInterfaces) {
            if (!address.isEmpty() && interfaces_->findData(address) == -1)
                interfaces_->addItem(address, address);
        }
        const int index = interfaces_->findData(previousInterface);
        if (index > 0) interfaces_->setCurrentIndex(index);
    }
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
    start_->setEnabled(!snapshot.sharing && !snapshot.startPending && denial.isEmpty());
    stop_->setEnabled(snapshot.sharing || snapshot.startPending);
    copy_->setEnabled(snapshot.sharing && !snapshot.lanAddress.isEmpty());
    status_->setText(snapshot.sharing
        ? (snapshot.lanAddress.isEmpty() ? "R10 reports sharing; LAN address unavailable."
            : "R10 sharing address: " + snapshot.lanAddress)
        : (snapshot.startPending ? "R10 start pending; sharing not confirmed."
            : "Not sharing. " + (snapshot.failure.isEmpty() ? denial : snapshot.failure)));
    activity_->setText("Connected clients: " + (snapshot.clients.isEmpty() ? "None" : snapshot.clients.join(", "))
        + "\nAuthentication failures: " + (snapshot.authenticationFailures.isEmpty()
            ? "None" : snapshot.authenticationFailures.join(", "))
        + "\nDisconnected: " + (snapshot.disconnected.isEmpty() ? "None" : snapshot.disconnected.join(", "))
        + "\nLocked/revoked: " + (snapshot.revoked.isEmpty() ? "None" : snapshot.revoked.join(", ")));
}
void DesktopWindow::closeEvent(QCloseEvent* event) {
    const auto state = host_.status();
    if (state.sharing || state.startPending) {
        // Only R10 may retire the authoritative listener/connection owner.
        host_.stopAndRevoke();
        const auto after = host_.status();
        if (after.sharing || after.startPending) {
            refresh();
            event->ignore(); // Do not orphan a pending/active server.
            return;
        }
    }
    QWidget::closeEvent(event);
}
}
