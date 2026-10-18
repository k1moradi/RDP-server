// SPDX-License-Identifier: GPL-3.0-or-later
// R5 production parser behavior; synthetic logind replies confer no R2 lease.
#include "linux_prerequisites.h"
#include "desktop_window.h"
#include "host_control.h"

#include <QApplication>
#include <QLabel>
#include <QPushButton>
#include <QString>
#include <QStringView>

#include <cassert>

int main(int argc, char** argv)
{
    QApplication application(argc, argv);
    rdp_server::server::runtime::UnavailableRuntimeHostControl runtime;
    rdp::gui::HostControl control(runtime);
    rdp::gui::DesktopWindow window(control);
    auto* statusLabel = window.findChild<QLabel*>(QStringLiteral("linuxPrerequisiteStatus"));
    assert(statusLabel != nullptr);
    assert(window.findChild<QPushButton*>(QStringLiteral("refreshLinuxPrerequisites")) != nullptr);
    assert(!window.canStart());
    using rdp::gui::assessLinuxPrerequisites;
    using rdp::gui::formatLinuxPrerequisites;

    const QString session = QStringLiteral("c2");
    const QString x11 = QStringLiteral("x11");
    const QString display = QStringLiteral(":0");
    const QString native = QStringLiteral(
        "Seat=seat0\nType=x11\nActive=yes\nRemote=no\nState=active\nDisplay=:0\n");
    const auto assess = [&](const QString& identity, const QString& type,
                            const QString& currentDisplay,
                            const QString& evidence,
                            const QString& missing = QString()) {
        return assessLinuxPrerequisites(identity, type, currentDisplay,
                                        evidence, missing);
    };
    const auto reported = assess(session, x11, display, native);
    assert(reported.activePhysicalX11Seat0);
    const QString report = formatLinuxPrerequisites(reported);
    assert(report.contains(QStringLiteral("R2 authorization still required")));
    assert(report.contains(QStringLiteral("generation: unavailable")));
    assert(report.contains(QStringLiteral("not installed or enabled")));
    assert(report.contains(QStringLiteral("No login-screen sharing")));
    assert(!assess(session, QStringLiteral("wayland"), display, native)
                .activePhysicalX11Seat0);
    assert(!assess(session, x11, QStringLiteral(":99"), native)
                .activePhysicalX11Seat0);
    assert(!assess(session, x11, display,
                   QStringLiteral("Seat=seat1\nType=x11\nActive=yes\n"
                                  "Remote=no\nState=active\nDisplay=:0\n"))
                .activePhysicalX11Seat0);
    assert(!assess(session, x11, display,
                   QStringLiteral("Seat=seat0\nType=x11\nActive=yes\n"
                                  "Remote=yes\nState=active\nDisplay=:0\n"))
                .activePhysicalX11Seat0);
    assert(!assess(session, x11, display,
                   QStringLiteral("Seat=seat0\nType=x11\nActive=no\n"
                                  "Remote=no\nState=active\nDisplay=:0\n"))
                .activePhysicalX11Seat0);
    assert(!assess(session, x11, display,
                   QStringLiteral("Seat=seat0\nType=x11\nActive=yes\n"
                                  "Remote=no\nState=closing\nDisplay=:0\n"))
                .activePhysicalX11Seat0);
    assert(!assess(QStringLiteral("../c2"), x11, display, native)
                .activePhysicalX11Seat0);
    assert(!assess(QStringLiteral("-p"), x11, display, native)
                .activePhysicalX11Seat0);
    const auto noLogind = assess(session, x11, display, {});
    assert(!noLogind.activePhysicalX11Seat0);
    assert(formatLinuxPrerequisites(noLogind)
               .contains(QStringLiteral("no matching active physical")));
    const auto noLibraries = assess(session, x11, display, native,
                                   QStringLiteral("libxcb-xtest.so.0"));
    assert(noLibraries.activePhysicalX11Seat0);
    assert(formatLinuxPrerequisites(noLibraries)
               .contains(QStringLiteral("missing runtime libraries")));
    return 0;
}
