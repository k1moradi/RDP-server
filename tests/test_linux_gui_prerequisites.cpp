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
        "User=1000\nSeat=seat0\nType=x11\nActive=yes\nRemote=no\n"
        "State=active\nDisplay=:0\nLockedHint=no\n");
    const auto assess = [&](const QString& identity, const QString& type,
                            const QString& currentDisplay,
                            const QString& evidence,
                            const QString& missing = QString()) {
        return assessLinuxPrerequisites(1000U, identity, type, currentDisplay,
                                        evidence, missing);
    };
    const auto reported = assess(session, x11, display, native);
    assert(reported.activePhysicalX11Seat0);
    assert(reported.processUid == 1000U);
    assert(reported.sessionUserId == QStringLiteral("1000"));
    assert(reported.seat == QStringLiteral("seat0"));
    assert(reported.sessionType == QStringLiteral("x11"));
    assert(reported.active == QStringLiteral("yes"));
    assert(reported.remote == QStringLiteral("no"));
    assert(reported.state == QStringLiteral("active"));
    assert(reported.lockedHint == QStringLiteral("no"));
    const QString report = formatLinuxPrerequisites(reported);
    assert(report.contains(QStringLiteral("R2 authorization still required")));
    assert(report.contains(QStringLiteral("Current process UID: 1000")));
    assert(report.contains(QStringLiteral("logind Active: yes")));
    assert(report.contains(QStringLiteral("logind Remote: no")));
    assert(report.contains(QStringLiteral("LockedHint (advisory only): no")));
    assert(report.contains(QStringLiteral("R2 admission/session generation: unavailable")));
    assert(report.contains(QStringLiteral("R5 capture geometry/generation: unavailable")));
    assert(report.contains(QStringLiteral("not installed or enabled")));
    assert(report.contains(QStringLiteral("No login-screen sharing")));
    assert(!assess(session, QStringLiteral("wayland"), display, native)
                .activePhysicalX11Seat0);
    assert(!assess(session, x11, QStringLiteral(":99"), native)
                .activePhysicalX11Seat0);
    assert(!assess(session, x11, display,
                   QStringLiteral("User=1000\nSeat=seat1\nType=x11\nActive=yes\n"
                                  "Remote=no\nState=active\nDisplay=:0\n"
                                  "LockedHint=no\n"))
                .activePhysicalX11Seat0);
    assert(!assess(session, x11, display,
                   QStringLiteral("User=1000\nSeat=seat0\nType=x11\nActive=yes\n"
                                  "Remote=yes\nState=active\nDisplay=:0\n"
                                  "LockedHint=no\n"))
                .activePhysicalX11Seat0);
    assert(!assess(session, x11, display,
                   QStringLiteral("User=1000\nSeat=seat0\nType=x11\nActive=no\n"
                                  "Remote=no\nState=active\nDisplay=:0\n"
                                  "LockedHint=no\n"))
                .activePhysicalX11Seat0);
    assert(!assess(session, x11, display,
                   QStringLiteral("User=1000\nSeat=seat0\nType=x11\nActive=yes\n"
                                  "Remote=no\nState=closing\nDisplay=:0\n"
                                  "LockedHint=no\n"))
                .activePhysicalX11Seat0);
    assert(!assess(QStringLiteral("../c2"), x11, display, native)
                .activePhysicalX11Seat0);
    assert(!assess(QStringLiteral("-p"), x11, display, native)
                .activePhysicalX11Seat0);
    assert(!assessLinuxPrerequisites(
                0U, session, x11, display, native, {}).activePhysicalX11Seat0);
    assert(!assessLinuxPrerequisites(
                1001U, session, x11, display, native, {}).activePhysicalX11Seat0);
    const QString lockedNative = QStringLiteral(
        "User=1000\nSeat=seat0\nType=x11\nActive=yes\nRemote=no\n"
        "State=active\nDisplay=:0\nLockedHint=yes\n");
    const auto locked = assess(session, x11, display, lockedNative);
    assert(locked.activePhysicalX11Seat0);
    assert(formatLinuxPrerequisites(locked).contains(
        QStringLiteral("LockedHint (advisory only): yes")));

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
