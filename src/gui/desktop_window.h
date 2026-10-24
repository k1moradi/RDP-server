// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "host_control.h"

#include <QWidget>

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

class DesktopWindow final : public QWidget
{
public:
    explicit DesktopWindow(HostControl& host, QWidget* parent = nullptr);

    void refresh();
    [[nodiscard]] bool canStart() const;
    [[nodiscard]] QString blockedReason() const;

protected:
    void closeEvent(QCloseEvent* event) override;

private:
    [[nodiscard]] QString blockedReason(const HostStatus& snapshot) const;
    [[nodiscard]] QString displayedAddress(const HostStatus& snapshot) const;
    [[nodiscard]] QString addressPresentation(const HostStatus& snapshot) const;
    [[nodiscard]] bool standalonePasswordSurfaceAvailable(
        const HostStatus& snapshot) const noexcept;
    [[nodiscard]] HostRequest currentHostRequest() const;
    void requestStart();
    void requestStop();
    void requestQuit();
    void updateTray(const HostStatus& snapshot, const QString& address);

    HostControl& host_;

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
    QPushButton* configureOsAccount_;
    QPushButton* requestHostPermission_;
    QPushButton* disconnect_;
    QPushButton* copy_;

    QLabel* serverStateTitle_;
    QLabel* platformStatus_;
    QLabel* addressStatus_;
    QLabel* credentialStatus_;
    QLabel* sharingAvailabilityStatus_;
    QLabel* permissionStatus_;
    QLabel* selectedInterfaceStatus_;
    QLabel* errorStatus_;
    QLabel* tlsIdentityStatus_;
    QLabel* hostLifecycleStatus_;
    QLabel* status_;
    QLabel* activity_;
    QLabel* authenticationModeStatus_;
    QLabel* runtimeReadinessStatus_;

    QSystemTrayIcon* trayIcon_;
    QMenu* trayMenu_;
    QAction* trayOpen_;
    QAction* trayCopy_;
    QAction* traySharing_;
    QAction* trayClients_;
    QAction* trayQuit_;

    bool manualInterfaceOverride_{false};
    bool quitRequested_{false};
    QString userFacingError_;
};

} // namespace rdp::gui
