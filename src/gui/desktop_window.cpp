// SPDX-License-Identifier: GPL-3.0-or-later
#include "desktop_window.h"
#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QStackedWidget>
#include <QVBoxLayout>
namespace rdp::gui {
namespace {
QLabel* label(const QString& message) {
    auto* result = new QLabel(message);
    result->setWordWrap(true);
    return result;
}
}
DesktopWindow::DesktopWindow(HostControl& host, QWidget* parent)
    : QWidget(parent), host_(host), pages_(new QStackedWidget(this)),
      desktops_(new QComboBox(this)), interfaces_(new QComboBox(this)),
      port_(new QSpinBox(this)), password_(new QLineEdit(this)),
      confirmation_(new QLineEdit(this)), start_(new QPushButton("Start Sharing", this)),
      stop_(new QPushButton("Stop Sharing / Revoke", this)),
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
    desktop->addWidget(label("Desktop selection cannot grant R2 admission. Failed authorization remains blocked."));
    desktop->addStretch();
    auto* credentials = page("Credentials: OS-backed RDP/NLA authentication");
    credentials->addWidget(label("OS-backed credentials require an R2 compatible provider. "
        "Application access password is a future feature and is NOT an RDP/NLA password."));
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
    permissions->addStretch();
    auto* sharing = page("Sharing and connection status");
    start_->setObjectName("startSharing");
    stop_->setObjectName("stopSharing");
    auto* actions = new QHBoxLayout();
    actions->addWidget(start_);
    actions->addWidget(stop_);
    sharing->addLayout(actions);
    sharing->addWidget(status_);
    auto* copy = new QPushButton("Copy LAN Address", this);
    copy->setObjectName("copyLanAddress");
    sharing->addWidget(copy);
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
    connect(start_, &QPushButton::clicked, this, [this] {
        if (!canStart()) return;
        const auto snapshot = host_.status();
        const HostRequest request{snapshot.desktop, interfaces_->currentData().toString(),
            static_cast<std::uint16_t>(port_->value())};
        (void)host_.start(request); // Never use return value as active-sharing proof.
        refresh();
    });
    connect(stop_, &QPushButton::clicked, this, [this] {
        if (!host_.status().sharing) return;
        host_.stopAndRevoke();
        refresh();
    });
    connect(copy, &QPushButton::clicked, this, [this] {
        const auto state = host_.status();
        if (state.sharing && !state.lanAddress.isEmpty())
            QApplication::clipboard()->setText(state.lanAddress);
    });
    connect(password_, &QLineEdit::textChanged, this, [this] { refresh(); });
    connect(confirmation_, &QLineEdit::textChanged, this, [this] { refresh(); });
    refresh();
}
void DesktopWindow::changePage(int index) {
    if (index >= 0 && index < pages_->count()) pages_->setCurrentIndex(index);
}
QString DesktopWindow::blockedReason() const {
    const auto state = host_.status();
    if (!state.controlAvailable) return "R10 host control unavailable";
    if (!state.credentialProviderReady) return "Compatible R2 OS-backed credential provider unavailable";
    if (!state.desktopAuthorized || state.desktop.isEmpty()) return "Logged-in desktop not R2-authorized";
    if (!state.tlsReady) return "TLS identity unavailable";
    if (!state.firewallReady) return "Firewall prerequisite unavailable";
    if (!state.captureInputReady) return "Screen/input permissions unavailable";
    if (interfaces_->currentData().toString().isEmpty()) return "Validated LAN interface not selected";
    if (password_->isEnabled() &&
        (password_->text().isEmpty() || password_->text() != confirmation_->text()))
        return "Application password confirmation mismatch";
    return {};
}
bool DesktopWindow::canStart() const {
    return !host_.status().sharing && blockedReason().isEmpty();
}
void DesktopWindow::refresh() {
    const auto snapshot = host_.status();
    start_->setEnabled(canStart());
    stop_->setEnabled(snapshot.sharing);
    status_->setText(snapshot.sharing && !snapshot.lanAddress.isEmpty()
        ? "R10 sharing address: " + snapshot.lanAddress
        : "Not sharing. " + (snapshot.failure.isEmpty() ? blockedReason() : snapshot.failure));
    activity_->setText("Connected clients: " + (snapshot.clients.isEmpty() ? "None" : snapshot.clients.join(", "))
        + "\nAuthentication failures: " + (snapshot.authenticationFailures.isEmpty()
            ? "None" : snapshot.authenticationFailures.join(", "))
        + "\nDisconnected: " + (snapshot.disconnected.isEmpty() ? "None" : snapshot.disconnected.join(", "))
        + "\nLocked/revoked: " + (snapshot.revoked.isEmpty() ? "None" : snapshot.revoked.join(", ")));
}
}
