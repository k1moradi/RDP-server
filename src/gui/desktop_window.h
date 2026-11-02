// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "host_control.h"
#include "server/runtime/runtime_user_preferences.h"

#include <QWidget>

#include <optional>
#include <utility>

class QAction;
class QCheckBox;
class QCloseEvent;
class QComboBox;
class QLabel;
class QLineEdit;
class QMenu;
class QPushButton;
class QSpinBox;
class QSystemTrayIcon;
class QTabWidget;

namespace rdp::gui
{

class ToggleSwitchWidget;

// Production supplies R2's public preferences boundary. Offline fake-host
// fixtures inject memory-only functions, never a second file/path/store.
struct DesktopPreferencesAccess final
{
    using Preferences = rdp_server::server::runtime::RuntimeUserPreferences;
    using Status =
        rdp_server::server::runtime::RuntimeUserPreferencesStorageStatus;
    Status (*load)(Preferences&) noexcept = nullptr;
    Status (*save)(const Preferences&) noexcept = nullptr;
};

class DesktopWindow final : public QWidget
{
public:
    explicit DesktopWindow(
        HostControl& host, QWidget* parent = nullptr,
        DesktopPreferencesAccess preferencesAccess = {});

    void refresh();
    // CLI-only Qt presentation; R10 retains every credential/Start decision.
    [[nodiscard]] bool applyStartupOptions(
        const QString* usernameOverride, const QString* passwordOverride,
        bool requestSharingConfirmation);
    [[nodiscard]] bool canStart() const;
    [[nodiscard]] QString blockedReason() const;
    [[nodiscard]] QString diagnosticExportText() const;

protected:
    void closeEvent(QCloseEvent* event) override;

private:
    [[nodiscard]] QString blockedReason(const HostStatus& snapshot) const;
    [[nodiscard]] QString displayedAddress(const HostStatus& snapshot) const;
    [[nodiscard]] QString addressPresentation(const HostStatus& snapshot) const;
    [[nodiscard]] bool standalonePasswordSurfaceAvailable(
        const HostStatus& snapshot) const noexcept;
    [[nodiscard]] bool standaloneCredentialReady(
        const HostStatus& snapshot) const noexcept;
    [[nodiscard]] bool configuredUsernameChanged(
        const HostStatus& snapshot) const;
    [[nodiscard]] HostRequest currentHostRequest() const;
    void saveOwnerPreferences();
    void requestStart();
    void requestStop();
    void requestQuit();
    void exportDiagnostics();
    void updateTray(const HostStatus& snapshot, const QString& address);

    HostControl& host_;
    DesktopPreferencesAccess preferencesAccess_;
    DesktopPreferencesAccess::Preferences savedPreferences_;

    QTabWidget* tabs_;
    QWidget* mainTab_;
    QWidget* advancedTab_;
    ToggleSwitchWidget* sharingToggle_;
    QComboBox* interfaces_;
    QComboBox* clientSelection_;
    QSpinBox* port_;
    QCheckBox* allowRemoteInput_;
    QSpinBox* permissionLifetimeMinutes_;
    QLineEdit* username_;
    QLineEdit* sessionPassword_;
    QLineEdit* sessionPasswordConfirm_;
    QLabel* usernameLabel_;
    QLabel* sessionPasswordLabel_;
    QLabel* sessionPasswordConfirmLabel_;
    QLabel* rdpClientCredentialGuidance_;
    QPushButton* configureOsAccount_;
    QPushButton* requestHostPermission_;
    QPushButton* disconnect_;
    QPushButton* copy_;

    QLabel* serverStateTitle_;
    QLabel* platformStatus_;
    QLabel* addressStatus_;
    QLabel* credentialStatus_;
    QLabel* sharingAvailabilityStatus_;
    QLabel* startupSharingNotice_;
    QLabel* permissionStatus_;
    QLabel* selectedInterfaceStatus_;
    QLabel* errorStatus_;
    QLabel* tlsIdentityStatus_;
    QLabel* hostLifecycleStatus_;
    QLabel* status_;
    QLabel* activity_;
    QLabel* authenticationModeStatus_;
    QLabel* runtimeReadinessStatus_;
    QLabel* authenticationDiagnosticsStatus_;
    QPushButton* exportDiagnostics_;

    QSystemTrayIcon* trayIcon_;
    QMenu* trayMenu_;
    QAction* trayOpen_;
    QAction* trayCopy_;
    QAction* traySharing_;
    QAction* trayClients_;
    QAction* trayQuit_;

    bool manualInterfaceOverride_{false};
    // A restored interface is a hint, not a fresh owner activation. Keep
    // only the exact pending activated pair until R2 confirms persistence.
    std::optional<std::pair<QString, QString>> pendingOwnerInterfacePreference_;
    bool startupUsernameOverrideActive_{false};
    // R2-restored or explicitly owner-saved Username is a presentation
    // override only; it does not configure R10 credentials or grant access.
    bool restoredUsernameActive_{false};
    // An in-progress edit has precedence until validation/storage completes.
    bool usernameOwnerEdited_{false};
    bool quitRequested_{false};
    QString userFacingError_;
    // Last authoritative non-secret Username projected by R10. This is only
    // presentation state used to preserve an in-progress owner edit.
    QString configuredStandaloneUsername_;
};

} // namespace rdp::gui
