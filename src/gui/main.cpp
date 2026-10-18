// SPDX-License-Identifier: GPL-3.0-or-later
#include "desktop_window.h"
#include <QApplication>
int main(int argc, char** argv) {
    QApplication application(argc, argv);
    rdp::gui::UnavailableHostControl control;
    rdp::gui::DesktopWindow window(control);
    window.show();
    return application.exec();
}
