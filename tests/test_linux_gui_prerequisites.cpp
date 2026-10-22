// SPDX-License-Identifier: GPL-3.0-or-later
// R5 Linux GUI prerequisite projection; synthetic observations create no authority.
#include "linux_prerequisites.h"
#include "desktop_window.h"
#include "host_control.h"

#include <QApplication>
#include <QLabel>
#include <QPushButton>
#include <QString>
#include <QStringView>

#include <array>
#include <cassert>

namespace
{
using rdp::gui::LinuxInputSupport;
using rdp::gui::LinuxPrerequisiteState;
using rdp::gui::assessLinuxPrerequisites;
using rdp::gui::formatLinuxPrerequisites;
using rdp::gui::projectLinuxPrerequisites;

const QString kSession = QStringLiteral("c2");
const QString kX11 = QStringLiteral("x11");
const QString kDisplay = QStringLiteral(":0");
const QString kNative = QStringLiteral(
    "User=1000\nSeat=seat0\nType=x11\nActive=yes\nRemote=no\n"
    "State=active\nDisplay=:0\nLockedHint=no\n");

auto assess(const QString& identity, const QString& type,
            const QString& currentDisplay, const QString& evidence,
            const QString& missing = QString())
{
    return assessLinuxPrerequisites(
        1000U, identity, type, currentDisplay, evidence, missing);
}

void checkStructuredProjection(rdp::gui::DesktopWindow& window)
{
    auto* statusLabel =
        window.findChild<QLabel*>(QStringLiteral("linuxPrerequisiteStatus"));
    assert(statusLabel != nullptr);
    assert(window.findChild<QPushButton*>(
               QStringLiteral("refreshLinuxPrerequisites")) != nullptr);
    assert(!window.canStart());

    assert(statusLabel->text() == QStringLiteral(
        "Linux desktop\n"
        "Session type: Unknown\n"
        "Display: Unknown\n"
        "Active local session: Unknown\n"
        "Unlocked: Unknown\n"
        "Physical session: Unknown\n"
        "Input support: Unknown"));

    const auto reported = assess(kSession, kX11, kDisplay, kNative);
    assert(reported.activePhysicalX11Seat0);
    assert(reported.sessionDisplayName == kDisplay);

    const auto projection = projectLinuxPrerequisites(reported);
    assert(projection.sessionType == QStringLiteral("X11"));
    assert(projection.display == kDisplay);
    assert(projection.activeLocalSession == LinuxPrerequisiteState::Yes);
    assert(projection.unlocked == LinuxPrerequisiteState::Yes);
    assert(projection.physicalSession == LinuxPrerequisiteState::Yes);
    assert(projection.inputSupport == LinuxInputSupport::Available);

    const QString report = formatLinuxPrerequisites(projection);
    assert(report == QStringLiteral(
        "Linux desktop\n"
        "Session type: X11\n"
        "Display: :0\n"
        "Active local session: Yes\n"
        "Unlocked: Yes\n"
        "Physical session: Yes\n"
        "Input support: Available"));

    const std::array<QStringView, 8> forbidden{{
        QStringView{u"R2"}, QStringView{u"R5"},
        QStringView{u"authorization"}, QStringView{u"generation"},
        QStringView{u"logind"}, QStringView{u"UID"},
        QStringView{u"capture"}, QStringView{u"XTEST"},
    }};
    for (const QStringView term : forbidden)
        assert(!QStringView{report}.contains(term, Qt::CaseInsensitive));
}

void checkEvidenceDenials()
{
    assert(!assess(kSession, QStringLiteral("wayland"), kDisplay, kNative)
                .activePhysicalX11Seat0);
    assert(!assess(kSession, kX11, QStringLiteral(":99"), kNative)
                .activePhysicalX11Seat0);
    assert(!assess(kSession, kX11, kDisplay,
                   QStringLiteral("User=1000\nSeat=seat1\nType=x11\nActive=yes\n"
                                  "Remote=no\nState=active\nDisplay=:0\n"
                                  "LockedHint=no\n"))
                .activePhysicalX11Seat0);
    assert(!assess(kSession, kX11, kDisplay,
                   QStringLiteral("User=1000\nSeat=seat0\nType=x11\nActive=yes\n"
                                  "Remote=yes\nState=active\nDisplay=:0\n"
                                  "LockedHint=no\n"))
                .activePhysicalX11Seat0);
    assert(!assess(kSession, kX11, kDisplay,
                   QStringLiteral("User=1000\nSeat=seat0\nType=x11\nActive=no\n"
                                  "Remote=no\nState=active\nDisplay=:0\n"
                                  "LockedHint=no\n"))
                .activePhysicalX11Seat0);
    assert(!assess(kSession, kX11, kDisplay,
                   QStringLiteral("User=1000\nSeat=seat0\nType=x11\nActive=yes\n"
                                  "Remote=no\nState=closing\nDisplay=:0\n"
                                  "LockedHint=no\n"))
                .activePhysicalX11Seat0);
    assert(!assess(QStringLiteral("../c2"), kX11, kDisplay, kNative)
                .activePhysicalX11Seat0);
    assert(!assess(QStringLiteral("-p"), kX11, kDisplay, kNative)
                .activePhysicalX11Seat0);
    assert(!assessLinuxPrerequisites(
                0U, kSession, kX11, kDisplay, kNative, {})
                .activePhysicalX11Seat0);
    assert(!assessLinuxPrerequisites(
                1001U, kSession, kX11, kDisplay, kNative, {})
                .activePhysicalX11Seat0);

    const QString lockedNative = QStringLiteral(
        "User=1000\nSeat=seat0\nType=x11\nActive=yes\nRemote=no\n"
        "State=active\nDisplay=:0\nLockedHint=yes\n");
    const auto lockedProjection = projectLinuxPrerequisites(
        assess(kSession, kX11, kDisplay, lockedNative));
    assert(lockedProjection.activeLocalSession == LinuxPrerequisiteState::Yes);
    assert(lockedProjection.unlocked == LinuxPrerequisiteState::No);
    assert(lockedProjection.physicalSession == LinuxPrerequisiteState::Yes);

    const auto noLogind =
        projectLinuxPrerequisites(assess(kSession, kX11, kDisplay, {}));
    assert(noLogind.sessionType == QStringLiteral("Unknown"));
    assert(noLogind.activeLocalSession == LinuxPrerequisiteState::Unknown);
    assert(noLogind.unlocked == LinuxPrerequisiteState::Unknown);
    assert(noLogind.physicalSession == LinuxPrerequisiteState::Unknown);
    assert(noLogind.inputSupport == LinuxInputSupport::Unknown);

    const QString waylandNative = QStringLiteral(
        "User=1000\nSeat=seat0\nType=wayland\nActive=yes\nRemote=no\n"
        "State=active\nDisplay=:0\nLockedHint=no\n");
    const auto waylandProjection = projectLinuxPrerequisites(
        assess(kSession, QStringLiteral("wayland"), kDisplay, waylandNative));
    assert(waylandProjection.sessionType == QStringLiteral("Wayland"));
    assert(waylandProjection.inputSupport == LinuxInputSupport::Unavailable);

    const auto noInputLibrary = projectLinuxPrerequisites(
        assess(kSession, kX11, kDisplay, kNative,
               QStringLiteral("libxcb-xtest.so.0")));
    assert(noInputLibrary.inputSupport == LinuxInputSupport::Unavailable);

    const auto captureLibraryMissing = projectLinuxPrerequisites(
        assess(kSession, kX11, kDisplay, kNative,
               QStringLiteral("libxcb-shm.so.0")));
    assert(captureLibraryMissing.inputSupport == LinuxInputSupport::Available);
}
} // namespace

int main(int argc, char** argv)
{
    QApplication application(argc, argv);
    rdp_server::server::runtime::UnavailableRuntimeHostControl runtime;
    rdp::gui::HostControl control(runtime);
    rdp::gui::DesktopWindow window(control);

    const QString mode =
        argc > 1 ? QString::fromLocal8Bit(argv[1]) : QString();
    if (mode == QStringLiteral("structured-projection"))
    {
        checkStructuredProjection(window);
        return 0;
    }

    checkEvidenceDenials();
    return 0;
}
