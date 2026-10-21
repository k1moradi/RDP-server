// SPDX-License-Identifier: GPL-3.0-or-later
#include "desktop_window.h"

#include "server/security/console_identity_policy.h"
#include "toggle_switch.h"

#if defined(Q_OS_LINUX)
#include "linux_prerequisites.h"
#endif

#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QCloseEvent>
#include <QComboBox>
#include <QFont>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenu>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QStyle>
#include <QSystemTrayIcon>
#include <QTimer>
#include <QVBoxLayout>
#include <QVariant>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <tuple>

namespace rdp::gui
{
namespace
{

QLabel* label(const QString& message, QWidget* parent = nullptr)
{
    // Set the format before assigning runtime text. Constructing QLabel with
    // that text would first invoke AutoText's HTML detection/parsing.
    auto* result = new QLabel(parent);
    result->setTextFormat(Qt::PlainText);
    result->setText(message);
    result->setWordWrap(true);
    return result;
}

QLabel* heading(const QString& message, QWidget* parent)
{
    auto* result = label(message, parent);
    QFont headingFont = result->font();
    headingFont.setBold(true);
    result->setFont(headingFont);
    return result;
}

QString ownerPermissionStatusText(const HostStatus& status)
{
    using rdp_server::server::runtime::RuntimeOwnerGrantState;
    using namespace rdp_server::server::security;

    switch (status.ownerGrant.state)
    {
    case RuntimeOwnerGrantState::Active:
    {
        if (!status.desktopAuthorized)
            break;

        const std::uint32_t permissions =
            status.ownerGrant.effectivePermissionMask;
        if ((permissions & kConsoleViewPermission) == 0U ||
            (permissions & ~kConsoleAllowedPermissions) != 0U)
        {
            return QStringLiteral(
                "Local sharing permission is current, but its effective "
                "scope is unavailable.");
        }

        QString scope = QStringLiteral("screen");
        if ((permissions & kConsoleInputPermission) != 0U)
            scope += QStringLiteral(", keyboard/mouse");
        if ((permissions & kConsoleClipboardPermission) != 0U)
            scope += QStringLiteral(", clipboard");

        const std::uint64_t remainingMilliseconds =
            status.ownerGrant.remainingMilliseconds;
        QString remaining;
        if (remainingMilliseconds < 1000U)
        {
            remaining = QStringLiteral("<1 sec");
        }
        else
        {
            const std::uint64_t totalSeconds = remainingMilliseconds / 1000U;
            const std::uint64_t minutes = totalSeconds / 60U;
            const std::uint64_t seconds = totalSeconds % 60U;
            remaining = minutes == 0U
                ? QStringLiteral("%1 sec").arg(
                      static_cast<qulonglong>(seconds))
                : QStringLiteral("%1 min %2 sec")
                      .arg(static_cast<qulonglong>(minutes))
                      .arg(static_cast<qulonglong>(seconds));
        }

        return QStringLiteral(
                   "Local sharing permission is current. Scope: %1. "
                   "Remaining: %2.")
            .arg(scope, remaining);
    }
    case RuntimeOwnerGrantState::Expired:
        return QStringLiteral(
            "Local sharing permission expired. Allow sharing again before "
            "starting.");
    case RuntimeOwnerGrantState::Unavailable:
        break;
    }

    return status.desktopAuthorized
        ? QStringLiteral(
              "Local sharing permission is current; detailed lifetime "
              "information is unavailable.")
        : QStringLiteral(
              "Local sharing permission is not established.");
}

QString tlsIdentityStatusText(const HostStatus& status)
{
    using rdp_server::server::runtime::RuntimeTlsIdentityState;

    const auto& identity = status.tlsIdentity;
    if (!status.controlAvailable ||
        identity.state == RuntimeTlsIdentityState::Unavailable)
    {
        return QStringLiteral(
            "TLS fingerprint unavailable. Client trust is not implied.");
    }

    QString explanation;
    switch (identity.state)
    {
    case RuntimeTlsIdentityState::Unavailable:
        return QStringLiteral("TLS fingerprint unavailable.");
    case RuntimeTlsIdentityState::ConfiguredUnbound:
        explanation = QStringLiteral(
            "TLS certificate configured; no bound LAN listener is confirmed.");
        break;
    case RuntimeTlsIdentityState::BoundAndMatched:
        explanation = status.listenerReady && !status.lanAddress.isEmpty() &&
                      identity.fingerprintAvailable
            ? QStringLiteral("TLS certificate matches the active LAN endpoint: ") +
                  status.lanAddress
            : QStringLiteral(
                  "TLS certificate binding is not yet confirmed for the "
                  "active endpoint.");
        break;
    case RuntimeTlsIdentityState::CertificateMismatch:
        explanation = QStringLiteral(
            "TLS certificate does not match the selected LAN endpoint.");
        break;
    case RuntimeTlsIdentityState::InterfaceUnavailable:
        explanation = QStringLiteral(
            "Selected LAN interface is unavailable; TLS identity is "
            "unconfirmed.");
        break;
    case RuntimeTlsIdentityState::InvalidEndpoint:
        explanation = QStringLiteral(
            "Selected LAN endpoint is invalid; TLS identity is unconfirmed.");
        break;
    }

    if (identity.fingerprintAvailable)
    {
        using rdp_server::server::runtime::RuntimeTlsCertificateFingerprint;
        constexpr std::size_t certificateSha256Size =
            std::tuple_size_v<RuntimeTlsCertificateFingerprint>;
        static_assert(certificateSha256Size == 32U);
        constexpr std::size_t fingerprintCharacterCount =
            certificateSha256Size * 3U - 1U;
        static_assert(fingerprintCharacterCount == 95U);

        constexpr char hexDigits[] = "0123456789ABCDEF";
        std::array<char, fingerprintCharacterCount> fingerprint{};
        for (std::size_t index = 0; index < certificateSha256Size; ++index)
        {
            const auto byte = identity.certificateSha256[index];
            const std::size_t offset = index * 3U;
            fingerprint[offset] = hexDigits[byte >> 4U];
            fingerprint[offset + 1U] = hexDigits[byte & 0x0fU];
            if (index + 1U < certificateSha256Size)
                fingerprint[offset + 2U] = ':';
        }
        explanation += QStringLiteral("\nSHA-256: ") +
            QString::fromLatin1(
                fingerprint.data(),
                static_cast<qsizetype>(fingerprint.size()));
    }
    else
    {
        explanation += QStringLiteral("\nSHA-256: unavailable.");
    }

    explanation += QStringLiteral(
        "\nClient trust: unknown. Verify the fingerprint independently.");
    return explanation;
}

QString hostLifecycleText(const HostStatus& state)
{
    using rdp_server::server::runtime::RuntimeHostStage;

    if (!state.controlAvailable)
        return QStringLiteral("Hosting control is unavailable.");

    switch (state.stage)
    {
    case RuntimeHostStage::Stopped:
        return QStringLiteral("Stopped.");
    case RuntimeHostStage::PackageInstalled:
        return QStringLiteral("Installed; sharing is stopped.");
    case RuntimeHostStage::CredentialsConfigured:
        return QStringLiteral("Access configured; sharing is stopped.");
    case RuntimeHostStage::ListenerAvailable:
        return state.listenerReady
            ? (state.clientDisconnected
                   ? QStringLiteral(
                         "Listening; the previous device disconnected.")
                   : QStringLiteral("Listening for a remote device."))
            : QStringLiteral("Starting the LAN listener.");
    case RuntimeHostStage::ClientAuthenticating:
        return QStringLiteral("A remote device is authenticating.");
    case RuntimeHostStage::ShareActivated:
        if (state.nativeDesktopInitializing && state.graphicsReady)
            return QStringLiteral("Preparing the local desktop.");
        if (state.graphicsReady)
            return state.nativeDesktopReady
                ? QStringLiteral("Desktop ready; waiting for visibility.")
                : QStringLiteral("Graphics ready; preparing the local desktop.");
        return QStringLiteral("Remote session activated; preparing graphics.");
    case RuntimeHostStage::DesktopVisible:
        return state.nativeDesktopReady
            ? QStringLiteral("Desktop is visible remotely.")
            : QStringLiteral("Desktop visibility is not yet confirmed.");
    case RuntimeHostStage::ClientConnected:
        return state.nativeDesktopReady && !state.clients.isEmpty()
            ? QStringLiteral("Remote device connected.")
            : QStringLiteral("Connection established; desktop is not yet confirmed.");
    case RuntimeHostStage::Revoked:
        return QStringLiteral("Sharing stopped.");
    }

    return QStringLiteral("Unknown hosting state.");
}

[[nodiscard]] bool mayStillBeHosting(const HostStatus& state) noexcept
{
    using rdp_server::server::runtime::RuntimeHostStage;

    switch (state.stage)
    {
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

    return true;
}

QString platformUnavailableText(const HostStatus& status)
{
    if (status.controlAvailable)
        return {};

#if defined(Q_OS_MACOS)
    return QStringLiteral(
        "Remote hosting is not available on macOS in this build yet.");
#elif defined(Q_OS_WIN)
    return QStringLiteral(
        "Remote hosting is not available on Windows in this build yet.");
#elif defined(Q_OS_LINUX)
    return QStringLiteral(
        "Remote hosting is not available in this Linux build or configuration.");
#else
    return QStringLiteral(
        "Remote hosting is not available on this platform in this build.");
#endif
}

QString formatEndpoint(const QString& address, const int port)
{
    if (address.isEmpty())
        return {};
    if (address.contains(':') && !address.startsWith('['))
        return QStringLiteral("[%1]:%2").arg(address).arg(port);
    return QStringLiteral("%1:%2").arg(address).arg(port);
}

} // namespace

DesktopWindow::DesktopWindow(HostControl& host, QWidget* parent)
    : QWidget(parent),
      host_(host),
      sharingToggle_(new ToggleSwitchWidget(this)),
      interfaces_(new QComboBox(this)),
      clientSelection_(new QComboBox(this)),
      port_(new QSpinBox(this)),
      allowRemoteInput_(new QCheckBox(
          QStringLiteral("Allow keyboard/mouse"), this)),
      permissionLifetimeMinutes_(new QSpinBox(this)),
      configureOsAccount_(new QPushButton(
          QStringLiteral("Use Existing OS Account"), this)),
      requestHostPermission_(new QPushButton(
          QStringLiteral("Allow Sharing on This Computer"), this)),
      disconnect_(new QPushButton(QStringLiteral("Disconnect"), this)),
      copy_(new QPushButton(QStringLiteral("Copy"), this)),
      advancedToggle_(new QPushButton(QStringLiteral("Advanced ▸"), this)),
      advancedPanel_(new QWidget(this)),
      serverStateTitle_(heading(QStringLiteral("RDP Server — Stopped"), this)),
      platformStatus_(label({}, this)),
      addressStatus_(label({}, this)),
      credentialStatus_(label({}, this)),
      permissionStatus_(label({}, this)),
      selectedInterfaceStatus_(label({}, this)),
      errorStatus_(label({}, this)),
      tlsIdentityStatus_(label({}, this)),
      hostLifecycleStatus_(label({}, this)),
      status_(label({}, this)),
      activity_(label({}, this)),
      authenticationModeStatus_(label(
          QStringLiteral("Authentication mode: Existing OS Account"), this)),
      trayIcon_(new QSystemTrayIcon(this)),
      trayMenu_(new QMenu(this)),
      trayOpen_(new QAction(QStringLiteral("Open"), trayMenu_)),
      trayCopy_(new QAction(QStringLiteral("Copy Address"), trayMenu_)),
      traySharing_(new QAction(QStringLiteral("Start Sharing"), trayMenu_)),
      trayClients_(new QAction(QStringLiteral("No connected devices"), trayMenu_)),
      trayQuit_(new QAction(QStringLiteral("Quit"), trayMenu_))
{
    setWindowTitle(QStringLiteral("RDP Server"));
    setMinimumSize(560, 520);

    serverStateTitle_->setObjectName("serverStateTitle");
    platformStatus_->setObjectName("platformSupportStatus");
    addressStatus_->setObjectName("connectionAddress");
    credentialStatus_->setObjectName("credentialStatus");
    permissionStatus_->setObjectName("permissionStatus");
    selectedInterfaceStatus_->setObjectName("selectedLanInterfaceStatus");
    errorStatus_->setObjectName("hostErrorExplanation");
    tlsIdentityStatus_->setObjectName("tlsIdentityStatus");
    hostLifecycleStatus_->setObjectName("hostLifecycleStatus");
    status_->setObjectName("sharingReadinessStatus");
    activity_->setObjectName("clientStatus");
    authenticationModeStatus_->setObjectName("authenticationModeStatus");

    sharingToggle_->setObjectName("sharingToggle");
    sharingToggle_->setAccessibleName(QStringLiteral("Start or stop sharing"));
    configureOsAccount_->setObjectName("configureOsAccount");
    requestHostPermission_->setObjectName("requestHostPermission");
    allowRemoteInput_->setObjectName("allowRemoteInput");
    copy_->setObjectName("copyLanAddress");
    clientSelection_->setObjectName("activeClientSelection");
    disconnect_->setObjectName("disconnectClient");
    advancedToggle_->setObjectName("advancedDisclosure");
    advancedPanel_->setObjectName("advancedPanel");
    interfaces_->setObjectName("lanInterface");
    port_->setObjectName("sharingPort");
    permissionLifetimeMinutes_->setObjectName("ownerPermissionLifetimeMinutes");

    trayIcon_->setObjectName("systemTrayIcon");
    trayOpen_->setObjectName("trayOpen");
    trayCopy_->setObjectName("trayCopyAddress");
    traySharing_->setObjectName("traySharing");
    trayClients_->setObjectName("trayConnectedClients");
    trayQuit_->setObjectName("trayQuit");
    trayClients_->setEnabled(false);

    auto* root = new QVBoxLayout(this);
    root->addWidget(serverStateTitle_);
    root->addWidget(platformStatus_);

    root->addWidget(heading(QStringLiteral("This computer"), this));
    auto* addressRow = new QHBoxLayout();
    addressRow->addWidget(addressStatus_, 1);
    addressRow->addWidget(copy_);
    root->addLayout(addressRow);

    root->addWidget(heading(QStringLiteral("Access"), this));
    root->addWidget(credentialStatus_);
    root->addWidget(configureOsAccount_);
    root->addWidget(permissionStatus_);
    root->addWidget(requestHostPermission_);

    root->addWidget(heading(QStringLiteral("Sharing"), this));
    auto* sharingRow = new QHBoxLayout();
    sharingRow->addWidget(sharingToggle_);
    sharingRow->addWidget(status_, 1);
    root->addLayout(sharingRow);
    allowRemoteInput_->setChecked(true);
    root->addWidget(allowRemoteInput_);

    root->addWidget(heading(QStringLiteral("Connected devices"), this));
    auto* clientRow = new QHBoxLayout();
    clientSelection_->addItem(QStringLiteral("No connected devices"), QVariant());
    clientRow->addWidget(clientSelection_, 1);
    clientRow->addWidget(disconnect_);
    root->addLayout(clientRow);
    root->addWidget(activity_);

    root->addWidget(advancedToggle_);

    auto* advancedLayout = new QVBoxLayout(advancedPanel_);
    auto* advancedForm = new QFormLayout();
    interfaces_->addItem(QStringLiteral("No private LAN interface available"),
                         QString());
    port_->setRange(1, 65535);
    port_->setValue(3389);
    permissionLifetimeMinutes_->setRange(1, 60);
    permissionLifetimeMinutes_->setValue(15);
    permissionLifetimeMinutes_->setSuffix(QStringLiteral(" min"));
    advancedForm->addRow(QStringLiteral("Interface override"), interfaces_);
    advancedForm->addRow(QStringLiteral("Port"), port_);
    advancedForm->addRow(
        QStringLiteral("Permission lifetime"), permissionLifetimeMinutes_);
    advancedLayout->addLayout(advancedForm);
    advancedLayout->addWidget(authenticationModeStatus_);
    advancedLayout->addWidget(tlsIdentityStatus_);
    advancedLayout->addWidget(selectedInterfaceStatus_);
    advancedLayout->addWidget(hostLifecycleStatus_);
    advancedLayout->addWidget(errorStatus_);

#if defined(Q_OS_LINUX)
    auto* linuxPrerequisites = label(
        QStringLiteral(
            "Linux X11 prerequisites not yet inspected; no desktop access "
            "is implied."),
        advancedPanel_);
    linuxPrerequisites->setObjectName("linuxPrerequisiteStatus");
    advancedLayout->addWidget(linuxPrerequisites);
    auto* refreshLinux =
        new QPushButton(QStringLiteral("Refresh Linux X11 prerequisites"),
                        advancedPanel_);
    refreshLinux->setObjectName("refreshLinuxPrerequisites");
    advancedLayout->addWidget(refreshLinux);
    connect(refreshLinux, &QPushButton::clicked, this, [linuxPrerequisites] {
        requestLinuxPrerequisites(linuxPrerequisites);
    });
    QTimer::singleShot(0, linuxPrerequisites, [linuxPrerequisites] {
        requestLinuxPrerequisites(linuxPrerequisites);
    });
#endif

    root->addWidget(advancedPanel_);
    root->addStretch();
    setAdvancedVisible(false);

    trayMenu_->addAction(trayOpen_);
    trayMenu_->addAction(trayCopy_);
    trayMenu_->addAction(traySharing_);
    trayMenu_->addAction(trayClients_);
    trayMenu_->addSeparator();
    trayMenu_->addAction(trayQuit_);
    trayIcon_->setContextMenu(trayMenu_);
    trayIcon_->setToolTip(QStringLiteral("RDP Server"));
    trayIcon_->setIcon(
        QApplication::style()->standardIcon(QStyle::SP_ComputerIcon));
    if (QSystemTrayIcon::isSystemTrayAvailable())
        trayIcon_->show();

    connect(advancedToggle_, &QPushButton::clicked, this, [this] {
        setAdvancedVisible(advancedPanel_->isHidden());
    });
    connect(configureOsAccount_, &QPushButton::clicked, this, [this] {
        userFacingError_.clear();
        if (!host_.requestExistingOsAccount())
            userFacingError_ =
                QStringLiteral("Existing OS Account access could not be configured.");
        refresh();
    });
    connect(requestHostPermission_, &QPushButton::clicked, this, [this] {
        rdp_server::server::runtime::RuntimeHostPermissionRequest request;
        request.allowInput = allowRemoteInput_->isChecked();
        // Clipboard stays outside the product UI until production activation
        // is explicitly approved by the owning runtime milestone.
        request.allowClipboard = false;
        request.requestedLifetimeMilliseconds =
            static_cast<std::uint64_t>(permissionLifetimeMinutes_->value()) *
            60'000U;
        userFacingError_.clear();
        if (!host_.requestHostPermission(request))
            userFacingError_ =
                QStringLiteral("Local sharing permission could not be requested.");
        refresh();
    });
    connect(sharingToggle_, &ToggleSwitchWidget::clicked,
            this, [this](const bool requestedOn) {
        const HostStatus snapshot = host_.status();
        {
            const QSignalBlocker blocked(sharingToggle_);
            sharingToggle_->setChecked(mayStillBeHosting(snapshot));
        }
        if (requestedOn)
            requestStart();
        else
            requestStop();
    });
    connect(disconnect_, &QPushButton::clicked, this, [this] {
        const HostStatus snapshot = host_.status();
        const QVariant selectedClient = clientSelection_->currentData();
        if (!snapshot.controlAvailable ||
            (!snapshot.sharing && !snapshot.startPending) ||
            !selectedClient.isValid())
            return;

        bool validId = false;
        const auto selectedId = selectedClient.toULongLong(&validId);
        if (!validId || selectedId == 0 ||
            !std::ranges::any_of(
                snapshot.activeClients,
                [selectedId](const ActiveClientChoice& client) {
                    return client.opaqueId == selectedId;
                }))
            return;

        userFacingError_.clear();
        if (!host_.disconnectClient(static_cast<std::uint64_t>(selectedId)))
            userFacingError_ =
                QStringLiteral("The selected device could not be disconnected.");
        refresh();
    });
    connect(copy_, &QPushButton::clicked, this, [this] {
        const QString address = displayedAddress(host_.status());
        if (!address.isEmpty())
            QApplication::clipboard()->setText(address);
    });
    connect(interfaces_, &QComboBox::currentIndexChanged,
            this, [this](int) { refresh(); });
    connect(port_, &QSpinBox::valueChanged, this, [this](int) { refresh(); });
    connect(clientSelection_, &QComboBox::currentIndexChanged,
            this, [this](int) { refresh(); });

    connect(trayOpen_, &QAction::triggered, this, [this] {
        showNormal();
        raise();
        activateWindow();
    });
    connect(trayCopy_, &QAction::triggered, this, [this] {
        const QString address = displayedAddress(host_.status());
        if (!address.isEmpty())
            QApplication::clipboard()->setText(address);
    });
    connect(traySharing_, &QAction::triggered, this, [this] {
        if (mayStillBeHosting(host_.status()))
            requestStop();
        else
            requestStart();
    });
    connect(trayQuit_, &QAction::triggered, this, [this] {
        requestQuit();
    });
    connect(trayIcon_, &QSystemTrayIcon::activated, this,
            [this](QSystemTrayIcon::ActivationReason reason) {
        if (reason == QSystemTrayIcon::Trigger ||
            reason == QSystemTrayIcon::DoubleClick)
        {
            showNormal();
            raise();
            activateWindow();
        }
    });

    refresh();
}

void DesktopWindow::setAdvancedVisible(const bool visible)
{
    advancedPanel_->setVisible(visible);
    advancedToggle_->setText(
        visible ? QStringLiteral("Advanced ▾")
                : QStringLiteral("Advanced ▸"));
}

QString DesktopWindow::blockedReason() const
{
    return blockedReason(host_.status());
}

QString DesktopWindow::blockedReason(const HostStatus& state) const
{
    if (!state.controlAvailable)
        return QStringLiteral("Remote hosting is unavailable in this build");
    if (!state.credentialsConfigured)
        return QStringLiteral("Existing OS Account access is not configured");
    if (!state.desktopAuthorized || state.desktop.isEmpty())
        return QStringLiteral("Local sharing permission is not established");
    if (!state.tlsReady)
        return QStringLiteral("TLS identity is not ready");

    const QString selectedInterface = interfaces_->currentData().toString();
    const QString selectedInterfaceId =
        interfaces_->currentData(Qt::UserRole + 1).toString();
    if (selectedInterface.isEmpty() || selectedInterfaceId.isEmpty() ||
        !std::ranges::any_of(
            state.approvedLanInterfaces,
            [&](const LanInterfaceChoice& candidate) {
                return candidate.stableId == selectedInterfaceId &&
                       candidate.address == selectedInterface;
            }))
    {
        return QStringLiteral("No private LAN interface is available");
    }

    return {};
}

bool DesktopWindow::canStart() const
{
    const HostStatus state = host_.status();
    return !mayStillBeHosting(state) && blockedReason(state).isEmpty();
}

HostRequest DesktopWindow::currentHostRequest() const
{
    return HostRequest{
        interfaces_->currentData(Qt::UserRole + 1).toString(),
        interfaces_->currentData().toString(),
        static_cast<std::uint16_t>(port_->value())};
}

QString DesktopWindow::displayedAddress(const HostStatus& snapshot) const
{
    if (!snapshot.lanAddress.isEmpty())
        return snapshot.lanAddress;
    return formatEndpoint(interfaces_->currentData().toString(), port_->value());
}

void DesktopWindow::requestStart()
{
    const HostStatus snapshot = host_.status();
    if (mayStillBeHosting(snapshot))
    {
        refresh();
        return;
    }

    const QString denial = blockedReason(snapshot);
    if (!denial.isEmpty())
    {
        startRequested_ = false;
        userFacingError_ = denial;
        refresh();
        return;
    }

    userFacingError_.clear();
    stopRequested_ = false;
    startRequested_ = host_.start(currentHostRequest());
    if (!startRequested_)
        userFacingError_ = QStringLiteral("Sharing could not be started.");
    refresh();
}

void DesktopWindow::requestStop()
{
    const HostStatus snapshot = host_.status();
    if (!mayStillBeHosting(snapshot))
    {
        stopRequested_ = false;
        refresh();
        return;
    }

    userFacingError_.clear();
    startRequested_ = false;
    stopRequested_ = true;
    host_.stopAndRevoke();
    refresh();
}

void DesktopWindow::requestQuit()
{
    quitRequested_ = true;
    startRequested_ = false;
    stopRequested_ = true;
    userFacingError_.clear();

    // Explicit Quit always enters the runtime's Stop/Revoke path first.
    host_.stopAndRevoke();
    refresh();

    if (!mayStillBeHosting(host_.status()))
        QApplication::quit();
}

void DesktopWindow::updateTray(
    const HostStatus& snapshot, const QString& address)
{
    trayCopy_->setEnabled(!address.isEmpty());
    traySharing_->setText(
        mayStillBeHosting(snapshot)
            ? (stopRequested_ ? QStringLiteral("Stopping…")
                              : QStringLiteral("Stop Sharing"))
            : (startRequested_ ? QStringLiteral("Starting…")
                               : QStringLiteral("Start Sharing")));
    traySharing_->setEnabled(
        mayStillBeHosting(snapshot) || canStart());

    if (!snapshot.clients.isEmpty())
    {
        trayClients_->setText(
            snapshot.clients.size() == 1
                ? QStringLiteral("1 connected device")
                : QStringLiteral("%1 connected devices")
                      .arg(snapshot.clients.size()));
    }
    else if (!snapshot.pendingClients.isEmpty())
    {
        trayClients_->setText(
            QStringLiteral("%1 device connecting")
                .arg(snapshot.pendingClients.size()));
    }
    else
    {
        trayClients_->setText(QStringLiteral("No connected devices"));
    }

    trayIcon_->setToolTip(
        address.isEmpty()
            ? serverStateTitle_->text()
            : serverStateTitle_->text() + QStringLiteral(" — ") + address);
}

void DesktopWindow::refresh()
{
    const HostStatus snapshot = host_.status();
    const QString previousInterface = interfaces_->currentData().toString();
    const QString previousInterfaceId =
        interfaces_->currentData(Qt::UserRole + 1).toString();
    const QVariant previousClientId = clientSelection_->currentData();

    {
        const QSignalBlocker blocked(interfaces_);
        interfaces_->clear();
        interfaces_->addItem(
            QStringLiteral("No private LAN interface available"), QString());

        for (const LanInterfaceChoice& choice : snapshot.approvedLanInterfaces)
        {
            if (choice.address.isEmpty() || choice.stableId.isEmpty())
                continue;
            const QString name = choice.displayName.isEmpty()
                ? choice.address
                : choice.displayName + QStringLiteral(" (") +
                      choice.address + QStringLiteral(")");
            interfaces_->addItem(name, choice.address);
            interfaces_->setItemData(
                interfaces_->count() - 1,
                choice.stableId, Qt::UserRole + 1);
        }

        int selectedIndex = 0;
        for (int index = 1; index < interfaces_->count(); ++index)
        {
            if (interfaces_->itemData(index).toString() == previousInterface &&
                interfaces_->itemData(
                    index, Qt::UserRole + 1).toString() == previousInterfaceId)
            {
                selectedIndex = index;
                break;
            }
        }

        // Prefer a private IPv4 address for the product default, then fall
        // back to the first runtime-approved private address. Manual Advanced
        // overrides remain sticky while that exact interface/address survives.
        if (selectedIndex == 0)
        {
            for (int index = 1; index < interfaces_->count(); ++index)
            {
                if (!interfaces_->itemData(index).toString().contains(':'))
                {
                    selectedIndex = index;
                    break;
                }
            }
            if (selectedIndex == 0 && interfaces_->count() > 1)
                selectedIndex = 1;
        }
        interfaces_->setCurrentIndex(selectedIndex);
    }

    {
        const QSignalBlocker blocked(clientSelection_);
        clientSelection_->clear();
        clientSelection_->addItem(
            QStringLiteral("No connected devices"), QVariant());
        for (const ActiveClientChoice& client : snapshot.activeClients)
        {
            if (client.opaqueId == 0)
                continue;
            const QVariant opaqueId =
                QVariant::fromValue<qulonglong>(client.opaqueId);
            if (clientSelection_->findData(opaqueId) < 0)
                clientSelection_->addItem(client.displayName, opaqueId);
        }
        const int index = clientSelection_->findData(previousClientId);
        if (index > 0)
            clientSelection_->setCurrentIndex(index);
    }

    if (mayStillBeHosting(snapshot))
        startRequested_ = false;
    else
        stopRequested_ = false;
    if (!snapshot.failure.isEmpty() || !snapshot.controlAvailable)
        startRequested_ = false;

    const bool authoritativeOn = mayStillBeHosting(snapshot);
    {
        const QSignalBlocker blocked(sharingToggle_);
        sharingToggle_->setChecked(authoritativeOn);
    }

    if (stopRequested_ && authoritativeOn)
        serverStateTitle_->setText(QStringLiteral("RDP Server — Stopping…"));
    else if (authoritativeOn &&
             (snapshot.listenerReady || snapshot.sharing))
        serverStateTitle_->setText(QStringLiteral("RDP Server — Sharing"));
    else if (authoritativeOn || startRequested_ || snapshot.startPending)
        serverStateTitle_->setText(QStringLiteral("RDP Server — Starting…"));
    else
        serverStateTitle_->setText(QStringLiteral("RDP Server — Stopped"));

    const QString platformMessage = platformUnavailableText(snapshot);
    platformStatus_->setText(platformMessage);
    platformStatus_->setVisible(!platformMessage.isEmpty());

    const QString address = displayedAddress(snapshot);
    addressStatus_->setText(
        address.isEmpty()
            ? QStringLiteral("No private LAN address available")
            : address);
    copy_->setEnabled(!address.isEmpty());

    credentialStatus_->setText(
        snapshot.credentialsConfigured
            ? QStringLiteral(
                  "Existing OS Account mode is configured. Remote clients "
                  "must sign in with that account.")
            : QStringLiteral(
                  "Existing OS Account mode. Configure access before sharing."));
    configureOsAccount_->setEnabled(
        snapshot.controlAvailable && !authoritativeOn && !startRequested_);

    permissionStatus_->setText(ownerPermissionStatusText(snapshot));
    requestHostPermission_->setEnabled(
        snapshot.controlAvailable && snapshot.credentialsConfigured &&
        !authoritativeOn && !startRequested_);
    allowRemoteInput_->setEnabled(
        snapshot.controlAvailable && !authoritativeOn && !startRequested_);
    permissionLifetimeMinutes_->setEnabled(
        snapshot.controlAvailable && snapshot.credentialsConfigured &&
        !authoritativeOn && !startRequested_);

    const QString denial = blockedReason(snapshot);
    sharingToggle_->setEnabled(
        authoritativeOn || (!startRequested_ && denial.isEmpty()));

    if (stopRequested_ && authoritativeOn)
    {
        status_->setText(QStringLiteral("Stopping sharing…"));
    }
    else if (authoritativeOn &&
             (snapshot.listenerReady || snapshot.sharing))
    {
        status_->setText(QStringLiteral("Sharing is on."));
    }
    else if (authoritativeOn || startRequested_ || snapshot.startPending)
    {
        status_->setText(QStringLiteral("Starting sharing…"));
    }
    else if (snapshot.failure.isEmpty() && denial.isEmpty())
    {
        status_->setText(QStringLiteral("Ready to share."));
    }
    else
    {
        status_->setText(
            QStringLiteral("Not ready: ") +
            (snapshot.failure.isEmpty() ? denial : snapshot.failure));
    }

    selectedInterfaceStatus_->setText(
        interfaces_->currentIndex() > 0
            ? QStringLiteral("Interface: ") + interfaces_->currentText()
            : QStringLiteral("Interface: unavailable"));
    tlsIdentityStatus_->setText(tlsIdentityStatusText(snapshot));
    hostLifecycleStatus_->setText(hostLifecycleText(snapshot));
    errorStatus_->setText(
        !userFacingError_.isEmpty()
            ? QStringLiteral("Last action: ") + userFacingError_
            : (snapshot.failure.isEmpty()
                   ? QStringLiteral("Diagnostics: no host error reported.")
                   : QStringLiteral("Diagnostics: ") + snapshot.failure));

    const bool clientActionsEnabled =
        snapshot.controlAvailable &&
        (snapshot.sharing || snapshot.startPending) &&
        !snapshot.activeClients.isEmpty();
    clientSelection_->setEnabled(clientActionsEnabled);
    disconnect_->setEnabled(
        clientActionsEnabled && clientSelection_->currentIndex() > 0);

    if (!snapshot.clients.isEmpty())
    {
        activity_->setText(
            QStringLiteral("Connected: ") + snapshot.clients.join(", "));
    }
    else if (!snapshot.pendingClients.isEmpty())
    {
        activity_->setText(
            QStringLiteral("Connecting: ") +
            snapshot.pendingClients.join(", "));
    }
    else if (!snapshot.authenticationFailures.isEmpty())
    {
        activity_->setText(
            QStringLiteral("No connected devices. ") +
            snapshot.authenticationFailures.join(", "));
    }
    else
    {
        activity_->setText(QStringLiteral("No connected devices"));
    }

    updateTray(snapshot, address);

    if (quitRequested_ && !authoritativeOn)
        QApplication::quit();
}

void DesktopWindow::closeEvent(QCloseEvent* event)
{
    if (mayStillBeHosting(host_.status()))
    {
        // Closing presentation while sharing is not Stop authority. Keep the
        // one runtime owner alive and make it reachable from the tray/menu bar.
        hide();
        event->ignore();
        return;
    }

    QWidget::closeEvent(event);
}

} // namespace rdp::gui
