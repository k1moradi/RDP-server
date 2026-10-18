// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "host_control.h"
#include <QWidget>
class QCloseEvent;
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;
class QStackedWidget;
namespace rdp::gui {
class DesktopWindow final : public QWidget {
public:
    explicit DesktopWindow(HostControl& host, QWidget* parent = nullptr);
    void refresh();
    [[nodiscard]] bool canStart() const;
    [[nodiscard]] QString blockedReason() const;
protected:
    void closeEvent(QCloseEvent* event) override;
private:
    HostControl& host_;
    QStackedWidget* pages_;
    QComboBox* desktops_;
    QComboBox* interfaces_;
    QSpinBox* port_;
    QLineEdit* password_;
    QLineEdit* confirmation_;
    QPushButton* start_;
    QPushButton* stop_;
    QPushButton* copy_;
    QLabel* desktopStatus_;
    QLabel* clipboardStatus_;
    QLabel* status_;
    QLabel* activity_;
    [[nodiscard]] QString blockedReason(const HostStatus& snapshot) const;
    void changePage(int index);
};
}
