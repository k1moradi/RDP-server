// SPDX-License-Identifier: GPL-3.0-or-later
#include "desktop_window.h"

#include "local_username.h"
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
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPushButton>
#include <QScrollArea>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QStyle>
#include <QSystemTrayIcon>
#include <QTabWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <QVariant>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <tuple>

namespace rdp::gui
{
namespace
{

[[nodiscard]] constexpr bool ownerAcceptancePasswordUiEnabled() noexcept
{
#if !defined(NDEBUG) || defined(RDP_SERVER_ENABLE_OWNER_ACCEPTANCE_UI)
    return true;
#else
    return false;
#endif
}

[[nodiscard]] constexpr bool hasAutomaticLanRecommendation(
    const rdp_server::server::runtime::RuntimeHostRecommendationSource source)
    noexcept
{
    using Source =
        rdp_server::server::runtime::RuntimeHostRecommendationSource;
    return source == Source::PreferredRoute ||
           source == Source::SoleEligibleInterface;
}

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

void configureCredentialEditor(QLineEdit& editor)
{
    // Credential entry remains interactive while Sharing is blocked by
    // missing credentials, owner consent or endpoint readiness.
    editor.setFocusPolicy(Qt::StrongFocus);
    editor.setCursor(Qt::IBeamCursor);

#if defined(Q_OS_LINUX)
    // Some Linux desktop themes make an unfocused enabled QLineEdit resemble a
    // disabled field. Preserve theme palette roles, while making the enabled,
    // focused and disabled borders structurally distinct.
    editor.setStyleSheet(QStringLiteral(
        "QLineEdit {"
        " background-color: palette(base);"
        " color: palette(text);"
        " border: 1px solid palette(mid);"
        " border-radius: 4px;"
        " padding: 4px 6px;"
        "}"
        "QLineEdit:focus {"
        " border: 2px solid palette(highlight);"
        " padding: 3px 5px;"
        "}"
        "QLineEdit:disabled {"
        " background-color: palette(window);"
        " color: palette(mid);"
        " border: 1px dashed palette(mid);"
        "}"));
#endif
}

QString ownerPermissionStatusText(const HostStatus& status)
{
    using Denial =
        rdp_server::server::runtime::RuntimeSharingPermissionDenial;

    const auto& permission = status.sharingPermission;
    if (permission.activeGrant && permission.viewAllowed)
    {
        const QString lifetime =
            permission.remainingMilliseconds < 60'000U
                ? QStringLiteral("less than 1 min")
                : QStringLiteral("%1 min").arg(
                      static_cast<qulonglong>(
                          permission.remainingMilliseconds / 60'000U));
        const QString scope = permission.inputAllowed
            ? QStringLiteral("screen and keyboard/mouse")
            : QStringLiteral("screen only");
        return QStringLiteral("Sharing allowed for %1 — %2")
            .arg(lifetime, scope);
    }

    switch (permission.denial)
    {
    case Denial::None:
    case Denial::PermissionRequired:
        return QStringLiteral("Sharing permission required");
    case Denial::PermissionExpired:
        return QStringLiteral("Permission expired");
    case Denial::ComputerLocked:
        return QStringLiteral("Computer is locked");
    case Denial::LoggedInDesktopChanged:
        return QStringLiteral("Logged-in desktop changed");
    case Denial::PermissionRevoked:
        return QStringLiteral("Sharing permission revoked");
    case Denial::Unavailable:
        return QStringLiteral("Sharing permission unavailable");
    }
    return QStringLiteral("Sharing permission unavailable");
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
                      status.tlsFingerprintAvailable
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

    if (status.tlsFingerprintAvailable)
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
            const auto byte = status.tlsFingerprint[index];
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
    using State = rdp_server::server::runtime::RuntimeProductHostState;
    switch (state.productState)
    {
    case State::Stopped: return QStringLiteral("Stopped.");
    case State::Starting: return QStringLiteral("Starting.");
    case State::Listening:
        return state.clientDisconnected
            ? QStringLiteral("Listening; the previous device disconnected.")
            : QStringLiteral("Listening for a remote device.");
    case State::Authenticating:
        return QStringLiteral("A remote device is authenticating.");
    case State::DesktopInitializing:
        return QStringLiteral("Preparing the local desktop.");
    case State::Connected:
        return QStringLiteral("Remote device connected.");
    case State::Stopping: return QStringLiteral("Stopping.");
    case State::Error:
        return state.failure.isEmpty()
            ? QStringLiteral("Hosting error.")
            : QStringLiteral("Hosting error: ") + state.failure;
    }
    return QStringLiteral("Hosting error.");
}

[[nodiscard]] bool mayStillBeHosting(const HostStatus& state) noexcept
{
    return rdp_server::server::runtime::runtimeProductStateMayHost(
        state.productState);
}

[[nodiscard]] bool sharingToggleOn(const HostStatus& state) noexcept
{
    return rdp_server::server::runtime::runtimeProductStateSharingToggleOn(
        state.productState);
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
      tabs_(new QTabWidget(this)),
      mainTab_(new QWidget(tabs_)),
      advancedTab_(new QWidget(tabs_)),
      sharingToggle_(new ToggleSwitchWidget(mainTab_)),
      interfaces_(new QComboBox(advancedTab_)),
      clientSelection_(new QComboBox(mainTab_)),
      port_(new QSpinBox(advancedTab_)),
      allowRemoteInput_(new QCheckBox(
          QStringLiteral("Allow keyboard/mouse"), mainTab_)),
      permissionLifetimeMinutes_(new QSpinBox(advancedTab_)),
      username_(new QLineEdit(mainTab_)),
      sessionPassword_(new QLineEdit(mainTab_)),
      sessionPasswordConfirm_(new QLineEdit(mainTab_)),
      usernameLabel_(label(QStringLiteral("Username"), mainTab_)),
      sessionPasswordLabel_(label(QStringLiteral("Session Password"), mainTab_)),
      sessionPasswordConfirmLabel_(label(QStringLiteral("Confirm"), mainTab_)),
      configureOsAccount_(new QPushButton(
          QStringLiteral("Use Existing OS Account"), mainTab_)),
      requestHostPermission_(new QPushButton(
          QStringLiteral("Allow Sharing on This Computer"), mainTab_)),
      disconnect_(new QPushButton(QStringLiteral("Disconnect"), mainTab_)),
      copy_(new QPushButton(QStringLiteral("Copy"), mainTab_)),
      serverStateTitle_(heading(QStringLiteral("RDP Server — Stopped"), mainTab_)),
      platformStatus_(label({}, mainTab_)),
      addressStatus_(label({}, mainTab_)),
      credentialStatus_(label({}, mainTab_)),
      sharingAvailabilityStatus_(label({}, mainTab_)),
      permissionStatus_(label({}, advancedTab_)),
      selectedInterfaceStatus_(label({}, advancedTab_)),
      errorStatus_(label({}, advancedTab_)),
      tlsIdentityStatus_(label({}, advancedTab_)),
      hostLifecycleStatus_(label({}, advancedTab_)),
      status_(label({}, advancedTab_)),
      activity_(label({}, advancedTab_)),
      authenticationModeStatus_(label(
          QStringLiteral("Authentication mode: Existing OS Account"), advancedTab_)),
      runtimeReadinessStatus_(label({}, advancedTab_)),
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
    sharingAvailabilityStatus_->setObjectName("sharingAvailabilityStatus");
    permissionStatus_->setObjectName("permissionStatus");
    selectedInterfaceStatus_->setObjectName("selectedLanInterfaceStatus");
    errorStatus_->setObjectName("hostErrorExplanation");
    tlsIdentityStatus_->setObjectName("tlsIdentityStatus");
    hostLifecycleStatus_->setObjectName("hostLifecycleStatus");
    status_->setObjectName("sharingReadinessStatus");
    activity_->setObjectName("clientStatus");
    authenticationModeStatus_->setObjectName("authenticationModeStatus");
    runtimeReadinessStatus_->setObjectName("runtimeReadinessStatus");

    QFont addressFont = addressStatus_->font();
    addressFont.setBold(true);
    const auto addressPointSize = addressFont.pointSizeF();
    if (addressPointSize > 0.0)
        addressFont.setPointSizeF(addressPointSize + 2.0);
    addressStatus_->setFont(addressFont);
    addressStatus_->setTextInteractionFlags(
        Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
    addressStatus_->setAccessibleName(QStringLiteral("Remote Desktop address"));

    sharingToggle_->setObjectName("sharingToggle");
    sharingToggle_->setAccessibleName(QStringLiteral("Start or stop sharing"));
    username_->setObjectName("standaloneUsername");
    // Username is only a non-authorizing convenience suggestion from the
    // current interactive local account. No OS password is queried or
    // populated; Session Password remains independently user-entered.
    username_->setText(currentLocalUsernameSuggestion());
    username_->setAccessibleName(QStringLiteral("Username"));
    configureCredentialEditor(*username_);
    sessionPassword_->setObjectName("sessionPassword");
    sessionPassword_->setEchoMode(QLineEdit::Password);
    sessionPassword_->setPlaceholderText(
        QStringLiteral("Enter Session Password"));
    sessionPassword_->setAccessibleName(QStringLiteral("Session Password"));
    configureCredentialEditor(*sessionPassword_);
    sessionPasswordConfirm_->setObjectName("sessionPasswordConfirm");
    sessionPasswordConfirm_->setEchoMode(QLineEdit::Password);
    sessionPasswordConfirm_->setPlaceholderText(
        QStringLiteral("Confirm Session Password"));
    sessionPasswordConfirm_->setAccessibleName(
        QStringLiteral("Confirm Session Password"));
    configureCredentialEditor(*sessionPasswordConfirm_);
    usernameLabel_->setObjectName("standaloneUsernameLabel");
    sessionPasswordLabel_->setObjectName("sessionPasswordLabel");
    sessionPasswordConfirmLabel_->setObjectName("sessionPasswordConfirmLabel");
    configureOsAccount_->setObjectName("configureOsAccount");
    requestHostPermission_->setObjectName("requestHostPermission");
    allowRemoteInput_->setObjectName("allowRemoteInput");
    copy_->setObjectName("copyLanAddress");
    clientSelection_->setObjectName("activeClientSelection");
    disconnect_->setObjectName("disconnectClient");
    tabs_->setObjectName("settingsTabs");
    mainTab_->setObjectName("mainTab");
    advancedTab_->setObjectName("advancedTab");
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
    tabs_->addTab(mainTab_, QStringLiteral("Main"));
    tabs_->addTab(advancedTab_, QStringLiteral("Advanced"));
    root->addWidget(tabs_);

    auto* mainLayout = new QVBoxLayout(mainTab_);
    mainLayout->addWidget(serverStateTitle_);
    mainLayout->addWidget(platformStatus_);

    mainLayout->addWidget(heading(QStringLiteral("This computer"), mainTab_));
    auto* addressRow = new QHBoxLayout();
    addressRow->addWidget(addressStatus_, 1);
    addressRow->addWidget(copy_);
    mainLayout->addLayout(addressRow);

    mainLayout->addWidget(heading(QStringLiteral("Access"), mainTab_));
    auto* accessForm = new QFormLayout();
    accessForm->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    accessForm->addRow(usernameLabel_, username_);
    accessForm->addRow(sessionPasswordLabel_, sessionPassword_);
    accessForm->addRow(sessionPasswordConfirmLabel_, sessionPasswordConfirm_);
    usernameLabel_->setBuddy(username_);
    sessionPasswordLabel_->setBuddy(sessionPassword_);
    sessionPasswordConfirmLabel_->setBuddy(sessionPasswordConfirm_);
    QWidget::setTabOrder(username_, sessionPassword_);
    QWidget::setTabOrder(sessionPassword_, sessionPasswordConfirm_);
    QWidget::setTabOrder(sessionPasswordConfirm_, sharingToggle_);
    mainLayout->addLayout(accessForm);
    mainLayout->addWidget(credentialStatus_);
    configureOsAccount_->setParent(advancedTab_);

    mainLayout->addWidget(heading(QStringLiteral("Sharing"), mainTab_));
    auto* sharingRow = new QHBoxLayout();
    sharingRow->addWidget(sharingToggle_);
    sharingRow->addStretch();
    mainLayout->addLayout(sharingRow);
    mainLayout->addWidget(sharingAvailabilityStatus_);
    allowRemoteInput_->setChecked(true);
    mainLayout->addWidget(allowRemoteInput_);
    requestHostPermission_->setParent(advancedTab_);

    mainLayout->addWidget(heading(QStringLiteral("Connected devices"), mainTab_));
    auto* clientRow = new QHBoxLayout();
    clientSelection_->addItem(QStringLiteral("No connected devices"), QVariant());
    clientRow->addWidget(clientSelection_, 1);
    clientRow->addWidget(disconnect_);
    mainLayout->addLayout(clientRow);
    mainLayout->addStretch();

    interfaces_->addItem(QStringLiteral("No private LAN interface available"),
                         QString());
    port_->setRange(1, 65535);
    port_->setValue(3389);
    permissionLifetimeMinutes_->setRange(1, 60);
    permissionLifetimeMinutes_->setValue(15);
    permissionLifetimeMinutes_->setSuffix(QStringLiteral(" min"));

    auto* advancedTabLayout = new QVBoxLayout(advancedTab_);
    advancedTabLayout->setContentsMargins(0, 0, 0, 0);
    auto* advancedScroll = new QScrollArea(advancedTab_);
    advancedScroll->setObjectName("advancedScrollArea");
    advancedScroll->setWidgetResizable(true);
    advancedScroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    auto* advancedContent = new QWidget(advancedScroll);
    advancedContent->setObjectName("advancedContent");
    auto* advancedLayout = new QVBoxLayout(advancedContent);

    auto* networkGroup =
        new QGroupBox(QStringLiteral("Network"), advancedContent);
    networkGroup->setObjectName("networkGroup");
    auto* networkForm = new QFormLayout(networkGroup);
    networkForm->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    networkForm->setRowWrapPolicy(QFormLayout::WrapLongRows);
    networkForm->addRow(QStringLiteral("Automatic selection"),
                        selectedInterfaceStatus_);
    networkForm->addRow(QStringLiteral("Interface override"), interfaces_);
    networkForm->addRow(QStringLiteral("Port"), port_);
    advancedLayout->addWidget(networkGroup);

    auto* securityGroup =
        new QGroupBox(QStringLiteral("Security"), advancedContent);
    securityGroup->setObjectName("securityGroup");
    auto* securityForm = new QFormLayout(securityGroup);
    securityForm->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    securityForm->setRowWrapPolicy(QFormLayout::WrapLongRows);
    securityForm->addRow(QStringLiteral("Authentication"),
                         authenticationModeStatus_);
    securityForm->addRow(QStringLiteral("Permission lifetime"),
                         permissionLifetimeMinutes_);
    securityForm->addRow(QStringLiteral("Existing OS Account"),
                         configureOsAccount_);
    securityForm->addRow(QStringLiteral("Owner permission action"),
                         requestHostPermission_);
    securityForm->addRow(QStringLiteral("Owner permission"),
                         permissionStatus_);
    securityForm->addRow(QStringLiteral("TLS identity"),
                         tlsIdentityStatus_);
    advancedLayout->addWidget(securityGroup);

    auto* desktopGroup =
        new QGroupBox(QStringLiteral("Desktop"), advancedContent);
    desktopGroup->setObjectName("desktopGroup");
    auto* desktopLayout = new QVBoxLayout(desktopGroup);
#if defined(Q_OS_LINUX)
    auto* linuxPrerequisites = label(
        formatLinuxPrerequisites(LinuxDesktopPrerequisiteProjection{}),
        desktopGroup);
    linuxPrerequisites->setObjectName("linuxPrerequisiteStatus");
    desktopLayout->addWidget(linuxPrerequisites);
    auto* refreshLinux =
        new QPushButton(QStringLiteral("Refresh Linux X11 prerequisites"),
                        desktopGroup);
    refreshLinux->setObjectName("refreshLinuxPrerequisites");
    desktopLayout->addWidget(refreshLinux);
    connect(refreshLinux, &QPushButton::clicked, this, [linuxPrerequisites] {
        requestLinuxPrerequisites(linuxPrerequisites);
    });
    QTimer::singleShot(0, linuxPrerequisites, [linuxPrerequisites] {
        requestLinuxPrerequisites(linuxPrerequisites);
    });
#else
    auto* desktopPrerequisites = label(
        QStringLiteral(
            "Desktop prerequisites are managed by the platform runtime."),
        desktopGroup);
    desktopPrerequisites->setObjectName("desktopPrerequisiteStatus");
    desktopLayout->addWidget(desktopPrerequisites);
#endif
    advancedLayout->addWidget(desktopGroup);

    auto* diagnosticsGroup =
        new QGroupBox(QStringLiteral("Diagnostics"), advancedContent);
    diagnosticsGroup->setObjectName("diagnosticsGroup");
    auto* diagnosticsLayout = new QVBoxLayout(diagnosticsGroup);
    diagnosticsLayout->addWidget(activity_);
    diagnosticsLayout->addWidget(hostLifecycleStatus_);
    diagnosticsLayout->addWidget(status_);
    diagnosticsLayout->addWidget(runtimeReadinessStatus_);
    diagnosticsLayout->addWidget(errorStatus_);
    advancedLayout->addWidget(diagnosticsGroup);
    advancedLayout->addStretch();

    advancedScroll->setWidget(advancedContent);
    advancedTabLayout->addWidget(advancedScroll);

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

    connect(username_, &QLineEdit::textChanged, this, [this] { refresh(); });
    connect(sessionPassword_, &QLineEdit::textChanged, this, [this] { refresh(); });
    connect(sessionPasswordConfirm_, &QLineEdit::textChanged, this, [this] { refresh(); });

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
            this, [this](int) {
                manualInterfaceOverride_ = true;
                refresh();
            });
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

QString DesktopWindow::blockedReason() const
{
    return blockedReason(host_.status());
}

QString DesktopWindow::blockedReason(const HostStatus& state) const
{
    if (!state.controlAvailable)
        return QStringLiteral("Remote hosting is unavailable in this build");

    const bool standaloneSurfaceSelected =
        standalonePasswordSurfaceAvailable(state);
    const bool configuredStandaloneCredential =
        standaloneCredentialReady(state);
    const bool replacementPasswordStarted =
        !sessionPassword_->text().isEmpty() ||
        !sessionPasswordConfirm_->text().isEmpty();
    const bool existingOsCredentialReady =
        state.credentialsConfigured &&
        state.credentialCapabilities.existingOsAccount &&
        !standaloneSurfaceSelected;

    if (!standaloneSurfaceSelected && !existingOsCredentialReady)
        return QStringLiteral("Session Password is not qualified for this Release build");

    if (standaloneSurfaceSelected)
    {
        // Cleared password editors mean "reuse the configured memory-only
        // credential", never "the credential disappeared". Any new secret
        // input instead starts an explicit replacement transaction that is
        // committed only by the Sharing action below.
        if (replacementPasswordStarted)
        {
            if (username_->text().isEmpty())
                return QStringLiteral("Enter a username");
            if (sessionPassword_->text().isEmpty())
                return QStringLiteral("Enter a Session Password");
            if (sessionPasswordConfirm_->text().isEmpty())
                return QStringLiteral("Confirm the Session Password");
            if (sessionPassword_->text() != sessionPasswordConfirm_->text())
                return QStringLiteral("Session Password confirmation does not match");
        }
        else if (!configuredStandaloneCredential)
        {
            if (username_->text().isEmpty())
                return QStringLiteral("Enter a username");
            return QStringLiteral("Enter a Session Password");
        }
    }

    // R10's product projection distinguishes a requestable local consent
    // action from an already-active owner grant. R7 may expose the explicit
    // Sharing action when consent can be requested, but a machine with no
    // eligible owner session must remain fail-closed before any Start attempt.
    if (!state.desktopAuthorized && !state.sharingPermission.canRequest)
        return ownerPermissionStatusText(state);

    // R1 prepares an exact-endpoint TLS identity only after the user requests
    // Sharing. Do not require that preparation artifact before the toggle can
    // invoke the R10 configure transaction; HostControl rechecks it before
    // startSharing() is allowed to reach R1's listener.
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
        return state.recommendationSource ==
                       rdp_server::server::runtime::
                           RuntimeHostRecommendationSource::Ambiguous
            ? QStringLiteral(
                  "Choose a private LAN interface in Advanced")
            : QStringLiteral("No private LAN interface is available");
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
    return snapshot.listenerReady && !snapshot.lanAddress.isEmpty()
        ? snapshot.lanAddress
        : QString{};
}

QString DesktopWindow::addressPresentation(const HostStatus& snapshot) const
{
    const QString connectable = displayedAddress(snapshot);
    if (!connectable.isEmpty())
        return QStringLiteral("Connect to: ") + connectable;
    if (hasAutomaticLanRecommendation(snapshot.recommendationSource) &&
        !snapshot.recommendedAddress.isEmpty())
        return QStringLiteral("Local address: ") + snapshot.recommendedAddress;
    return {};
}

bool DesktopWindow::standalonePasswordSurfaceAvailable(
    const HostStatus& snapshot) const noexcept
{
    return snapshot.controlAvailable &&
           (snapshot.credentialCapabilities.standalonePassword ||
            (ownerAcceptancePasswordUiEnabled() &&
             snapshot.credentialCapabilities
                 .standalonePasswordConfigurationAvailable));
}

bool DesktopWindow::standaloneCredentialReady(
    const HostStatus& snapshot) const noexcept
{
    // R7 owns one visible standalone-password surface. When that surface is
    // selected, R10's configured-credential fact is the authority for reuse;
    // cleared GUI editors do not revoke or reconstruct the secret.
    return snapshot.credentialsConfigured &&
           standalonePasswordSurfaceAvailable(snapshot);
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
        userFacingError_ = denial;
        refresh();
        return;
    }

    userFacingError_.clear();

    const QString password = sessionPassword_->text();
    if (!password.isEmpty())
    {
        const bool credentialConfigured =
            host_.configureStandalonePassword(username_->text(), password);
        sessionPassword_->clear();
        sessionPasswordConfirm_->clear();
        if (!credentialConfigured)
        {
            userFacingError_ = QStringLiteral(
                "Automatic Session Password provisioning failed. "
                "Use an unlocked physical desktop session.");
            refresh();
            return;
        }
    }

    // Standalone credential replacement revokes the prior R2 owner-consent
    // generation. Re-read R10 after credential setup so an earlier GUI
    // snapshot can never skip the fresh local View/Input permission request.
    const HostStatus permissionSnapshot = host_.status();
    if (!permissionSnapshot.desktopAuthorized)
    {
        rdp_server::server::runtime::RuntimeHostPermissionRequest permission;
        permission.allowInput = allowRemoteInput_->isChecked();
        permission.allowClipboard = false;
        permission.requestedLifetimeMilliseconds =
            static_cast<std::uint64_t>(permissionLifetimeMinutes_->value()) *
            60'000U;
        if (!host_.requestHostPermission(permission))
        {
            userFacingError_ = host_.status().failure.isEmpty()
                ? QStringLiteral(
                    "Local View/Input permission could not be granted. "
                    "Check that this computer is unlocked and locally owned.")
                : host_.status().failure;
            refresh();
            return;
        }
    }

    if (!host_.start(currentHostRequest()))
        userFacingError_ = host_.status().failure.isEmpty()
            ? QStringLiteral(
                "The LAN endpoint could not be prepared or the listener could "
                "not be started.")
            : host_.status().failure;
    refresh();
}

void DesktopWindow::requestStop()
{
    const HostStatus snapshot = host_.status();
    if (!mayStillBeHosting(snapshot))
    {
        refresh();
        return;
    }

    userFacingError_.clear();
    host_.stop();
    refresh();
}

void DesktopWindow::requestQuit()
{
    quitRequested_ = true;
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
    using ProductState =
        rdp_server::server::runtime::RuntimeProductHostState;
    switch (snapshot.productState)
    {
    case ProductState::Starting:
        traySharing_->setText(QStringLiteral("Starting…")); break;
    case ProductState::Stopping:
        traySharing_->setText(QStringLiteral("Stopping…")); break;
    case ProductState::Listening:
    case ProductState::Authenticating:
    case ProductState::DesktopInitializing:
    case ProductState::Connected:
        traySharing_->setText(QStringLiteral("Stop Sharing")); break;
    case ProductState::Stopped:
    case ProductState::Error:
        traySharing_->setText(QStringLiteral("Start Sharing")); break;
    }
    traySharing_->setEnabled(
        snapshot.productState != ProductState::Starting &&
        snapshot.productState != ProductState::Stopping &&
        (sharingToggleOn(snapshot) || canStart()));

    if (snapshot.clientCount != 0U &&
        snapshot.productState ==
            rdp_server::server::runtime::RuntimeProductHostState::Connected)
    {
        trayClients_->setText(
            snapshot.clientCount == 1U
                ? QStringLiteral("1 connected device")
                : QStringLiteral("%1 connected devices")
                      .arg(static_cast<qulonglong>(snapshot.clientCount)));
    }
    else if (snapshot.clientCount != 0U)
    {
        trayClients_->setText(
            snapshot.clientCount == 1U
                ? QStringLiteral("1 device connecting")
                : QStringLiteral("%1 devices connecting")
                      .arg(static_cast<qulonglong>(snapshot.clientCount)));
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
            snapshot.recommendationSource ==
                    rdp_server::server::runtime::
                        RuntimeHostRecommendationSource::Ambiguous
                ? QStringLiteral("Choose a private LAN interface")
                : QStringLiteral("No private LAN interface available"),
            QString());

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
        if (manualInterfaceOverride_)
        {
            if (previousInterface.isEmpty() && previousInterfaceId.isEmpty())
            {
                selectedIndex = 0;
            }
            else
            {
                for (int index = 1; index < interfaces_->count(); ++index)
                {
                    if (interfaces_->itemData(index).toString() ==
                            previousInterface &&
                        interfaces_->itemData(
                            index, Qt::UserRole + 1).toString() ==
                            previousInterfaceId)
                    {
                        selectedIndex = index;
                        break;
                    }
                }
                if (selectedIndex == 0)
                    manualInterfaceOverride_ = false;
            }
        }

        // R10 owns the automatic endpoint recommendation. Follow each fresh
        // recommendation unless the user made an Advanced override that still
        // names the exact current stable interface/address pair.
        if (!manualInterfaceOverride_ &&
            hasAutomaticLanRecommendation(snapshot.recommendationSource) &&
            !snapshot.recommendedInterfaceId.isEmpty() &&
            !snapshot.recommendedAddress.isEmpty())
        {
            for (int index = 1; index < interfaces_->count(); ++index)
            {
                if (interfaces_->itemData(index).toString() ==
                        snapshot.recommendedAddress &&
                    interfaces_->itemData(
                        index, Qt::UserRole + 1).toString() ==
                            snapshot.recommendedInterfaceId)
                {
                    selectedIndex = index;
                    break;
                }
            }
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

    const bool authoritativeOn = sharingToggleOn(snapshot);
    {
        const QSignalBlocker blocked(sharingToggle_);
        sharingToggle_->setChecked(authoritativeOn);
    }

    using ProductState =
        rdp_server::server::runtime::RuntimeProductHostState;
    serverStateTitle_->setText(
        mayStillBeHosting(snapshot)
            ? QStringLiteral("RDP Server — Sharing")
            : QStringLiteral("RDP Server — Stopped"));

    const QString platformMessage = platformUnavailableText(snapshot);
    platformStatus_->setText(platformMessage);
    platformStatus_->setVisible(!platformMessage.isEmpty());

    // Keep unsupported builds quiet on the default dashboard: the platform
    // banner is the single user-facing explanation, while Advanced retains
    // diagnostics for troubleshooting.
    const bool showHostingDetails = snapshot.controlAvailable;
    credentialStatus_->setVisible(showHostingDetails);
    permissionStatus_->setVisible(showHostingDetails);
    status_->setVisible(showHostingDetails);

    const QString address = displayedAddress(snapshot);
    const QString addressText = addressPresentation(snapshot);
    if (!addressText.isEmpty())
    {
        addressStatus_->setText(addressText);
    }
    else if (snapshot.recommendationSource ==
             rdp_server::server::runtime::
                 RuntimeHostRecommendationSource::Ambiguous)
    {
        addressStatus_->setText(QStringLiteral(
            "Multiple private networks found. Choose a network in Advanced."));
    }
    else if (!snapshot.approvedLanInterfaces.isEmpty())
    {
        addressStatus_->setText(QStringLiteral(
            "Automatic network selection unavailable. Choose a network in Advanced."));
    }
    else
    {
        addressStatus_->setText(
            QStringLiteral("No private LAN address available"));
    }
    copy_->setEnabled(snapshot.listenerReady && !address.isEmpty());

    const bool standaloneVisible =
        standalonePasswordSurfaceAvailable(snapshot);
    username_->setVisible(standaloneVisible);
    sessionPassword_->setVisible(standaloneVisible);
    sessionPasswordConfirm_->setVisible(standaloneVisible);
    usernameLabel_->setVisible(standaloneVisible);
    sessionPasswordLabel_->setVisible(standaloneVisible);
    sessionPasswordConfirmLabel_->setVisible(standaloneVisible);

    // R10 owns credential mutation authority. The acceptance surface may
    // expose the production credential owner before public Release
    // qualification, but R7 must not infer editability from credential
    // readiness, permission, endpoint, TLS or other unrelated facts.
    const bool standaloneEditable =
        standaloneVisible && snapshot.credentialEditingAllowed;
    for (QLineEdit* editor :
         {username_, sessionPassword_, sessionPasswordConfirm_})
    {
        editor->setEnabled(standaloneEditable);
        editor->setReadOnly(!standaloneEditable);
    }

    const bool configuredStandaloneCredential =
        standaloneCredentialReady(snapshot);
    credentialStatus_->setText(
        configuredStandaloneCredential
            ? QStringLiteral("Session Password configured for this app session")
            : (standaloneVisible
                ? QStringLiteral(
                      "Session Password is memory-only and is configured when "
                      "you explicitly turn Sharing on.")
                : QStringLiteral(
                      "Session Password is awaiting product qualification.")));
    authenticationModeStatus_->setText(
        standaloneVisible
            ? QStringLiteral("Authentication mode: Session Password")
            : (snapshot.credentialCapabilities.existingOsAccount
                ? QStringLiteral("Authentication mode: Existing OS Account")
                : QStringLiteral("Authentication mode unavailable")));
    configureOsAccount_->setEnabled(
        snapshot.controlAvailable &&
        snapshot.credentialCapabilities.existingOsAccount &&
        !mayStillBeHosting(snapshot));

    permissionStatus_->setText(ownerPermissionStatusText(snapshot));
    requestHostPermission_->setEnabled(
        snapshot.controlAvailable && snapshot.credentialsConfigured &&
        snapshot.sharingPermission.canRequest &&
        !mayStillBeHosting(snapshot));
    allowRemoteInput_->setEnabled(
        snapshot.controlAvailable && snapshot.sharingPermission.canRequest &&
        !mayStillBeHosting(snapshot));
    permissionLifetimeMinutes_->setEnabled(
        snapshot.controlAvailable && snapshot.credentialsConfigured &&
        snapshot.sharingPermission.canRequest &&
        !mayStillBeHosting(snapshot));

    const QString denial = blockedReason(snapshot);
    const QString sharingAvailabilityMessage =
        snapshot.remoteAuthenticationFailed
            ? QStringLiteral("Remote client authentication failed.")
            : (!mayStillBeHosting(snapshot) && snapshot.controlAvailable
                ? (snapshot.failure.isEmpty() ? denial : snapshot.failure)
                : QString{});
    sharingAvailabilityStatus_->setText(sharingAvailabilityMessage);
    sharingAvailabilityStatus_->setVisible(
        !sharingAvailabilityMessage.isEmpty());

    sharingToggle_->setEnabled(
        snapshot.productState != ProductState::Starting &&
        snapshot.productState != ProductState::Stopping &&
        (authoritativeOn ||
         (snapshot.productState == ProductState::Stopped &&
          denial.isEmpty())));

    switch (snapshot.productState)
    {
    case ProductState::Starting:
        status_->setText(QStringLiteral("Starting sharing…")); break;
    case ProductState::Listening:
        status_->setText(QStringLiteral("Listening for a remote device.")); break;
    case ProductState::Authenticating:
        status_->setText(QStringLiteral("A remote device is authenticating.")); break;
    case ProductState::DesktopInitializing:
        status_->setText(QStringLiteral("Preparing the local desktop.")); break;
    case ProductState::Connected:
        status_->setText(QStringLiteral("Sharing is on.")); break;
    case ProductState::Stopping:
        status_->setText(QStringLiteral("Stopping sharing…")); break;
    case ProductState::Error:
        status_->setText(
            snapshot.failure.isEmpty()
                ? QStringLiteral("Hosting error.")
                : QStringLiteral("Hosting error: ") + snapshot.failure);
        break;
    case ProductState::Stopped:
        if (snapshot.failure.isEmpty() && denial.isEmpty())
            status_->setText(QStringLiteral("Ready to share."));
        else
            status_->setText(
                QStringLiteral("Not ready: ") +
                (snapshot.failure.isEmpty() ? denial : snapshot.failure));
        break;
    }

    if (!snapshot.lanAddress.isEmpty())
    {
        selectedInterfaceStatus_->setText(
            QStringLiteral("Active endpoint: ") + snapshot.lanAddress);
    }
    else if (snapshot.recommendationSource ==
             rdp_server::server::runtime::
                 RuntimeHostRecommendationSource::Ambiguous)
    {
        selectedInterfaceStatus_->setText(
            QStringLiteral(
                "Automatic selection is ambiguous; choose an interface override."));
    }
    else if (hasAutomaticLanRecommendation(snapshot.recommendationSource) &&
             !snapshot.recommendedAddress.isEmpty() &&
             snapshot.recommendedPort != 0U)
    {
        selectedInterfaceStatus_->setText(
            QStringLiteral("Automatic: ") +
            formatEndpoint(
                snapshot.recommendedAddress,
                static_cast<int>(snapshot.recommendedPort)));
    }
    else
    {
        selectedInterfaceStatus_->setText(
            QStringLiteral("Automatic selection is unavailable."));
    }
    tlsIdentityStatus_->setText(tlsIdentityStatusText(snapshot));
    hostLifecycleStatus_->setText(hostLifecycleText(snapshot));
    runtimeReadinessStatus_->setText(
        QStringLiteral("Readiness: protocol %1; native desktop %2.\n"
                       "Selected desktop: %3")
            .arg(
                snapshot.graphicsReady
                    ? QStringLiteral("ready")
                    : (snapshot.listenerReady
                        ? QStringLiteral("waiting")
                        : QStringLiteral("inactive")),
                snapshot.nativeDesktopReady
                    ? QStringLiteral("ready")
                    : (snapshot.nativeDesktopInitializing
                        ? QStringLiteral("initializing")
                        : QStringLiteral("inactive")),
                snapshot.desktop.isEmpty()
                    ? QStringLiteral(
                          "No eligible physical X11 desktop "
                          "(Wayland is not supported).")
                    : snapshot.desktop));
    errorStatus_->setText(
        !userFacingError_.isEmpty()
            ? QStringLiteral("Last action: ") + userFacingError_
            : (!snapshot.authenticationDiagnostic.isEmpty()
                   ? snapshot.authenticationDiagnostic
                   : (snapshot.failure.isEmpty()
                          ? QStringLiteral(
                                "Diagnostics: no host error reported.")
                          : QStringLiteral("Diagnostics: ") +
                                snapshot.failure)));

    const bool clientActionsEnabled =
        snapshot.controlAvailable &&
        mayStillBeHosting(snapshot) &&
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
