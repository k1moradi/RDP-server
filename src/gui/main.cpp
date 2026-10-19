// SPDX-License-Identifier: GPL-3.0-or-later
#include "desktop_window.h"
#include "host_control.h"
#include "server/runtime/runtime_host_control.h"
#if defined(__linux__)
#include "server/runtime/linux_runtime_host_control.h"
#endif

#include <QApplication>

int main(int argc, char** argv)
{
    QApplication application(argc, argv);
#if defined(__linux__)
    // One concrete R10 owner, with no positive R2/R1 authorization.
    rdp_server::server::runtime::LinuxRuntimeHostControl runtime;
#else
    rdp_server::server::runtime::UnavailableRuntimeHostControl runtime;
#endif
    rdp::gui::HostControl control(runtime);
    rdp::gui::DesktopWindow window(control);
    window.show();
    return application.exec();
}
