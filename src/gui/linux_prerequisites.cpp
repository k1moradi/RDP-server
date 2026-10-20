// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_prerequisites.h"

#include <QByteArray>
#include <QLabel>
#include <QLibrary>
#include <QProcess>
#include <QProcessEnvironment>
#include <QStringList>
#include <QTimer>
#include <QtGlobal>

#include <array>
#include <cstdint>
#include <unistd.h>

namespace rdp::gui
{
namespace
{
constexpr int kLogindTimeoutMilliseconds = 1500;
constexpr qsizetype kMaximumSessionTextLength = 64;
constexpr qsizetype kMaximumLogindReplyBytes = 4096;

// Reject terminal-control, path, whitespace and argument-like characters
// before using an environment-derived logind session identifier.
[[nodiscard]] bool safeSessionId(QStringView sessionId) noexcept
{
    if (sessionId.isEmpty() || sessionId.size() > kMaximumSessionTextLength ||
        sessionId.front() == QLatin1Char('-'))
        return false;

    for (const QChar character : sessionId)
    {
        const ushort code = character.unicode();
        if (!((code >= 'a' && code <= 'z') ||
              (code >= 'A' && code <= 'Z') ||
              (code >= '0' && code <= '9') ||
              code == '_' || code == '-'))
            return false;
    }
    return true;
}

[[nodiscard]] QString missingX11Libraries()
{
    // Loading these libraries checks only client runtime prerequisites. It
    // never connects to the X server, reads pixels, or grants XTEST input.
    static constexpr std::array<const char*, 11> libraryNames{{
        "libX11.so.6", "libXext.so.6", "libXrandr.so.2",
        "libXtst.so.6", "libxcb.so.1", "libxcb-shm.so.0",
        "libxcb-damage.so.0", "libxcb-xtest.so.0",
        "libxcb-randr.so.0", "libxcb-xfixes.so.0",
        "libxcb-xinput.so.0"
    }};
    QStringList missing;
    for (const char* libraryName : libraryNames)
    {
        QLibrary library(QString::fromLatin1(libraryName));
        if (!library.load())
            missing.push_back(QString::fromLatin1(libraryName));
    }
    return missing.join(QStringLiteral(", "));
}

[[nodiscard]] QString property(QStringView properties, QStringView key)
{
    const QString reply = properties.toString();
    for (const QString& line : reply.split(QLatin1Char('\n')))
    {
        const qsizetype separator = line.indexOf(QLatin1Char('='));
        if (separator > 0 && QStringView(line).left(separator) == key)
            return line.mid(separator + 1).trimmed();
    }
    return {};
}
} // namespace

LinuxPrerequisiteObservation assessLinuxPrerequisites(
    const std::uint64_t processUid, QStringView sessionId,
    QStringView sessionType, QStringView displayName,
    QStringView logindProperties, QStringView missingLibraries)
{
    LinuxPrerequisiteObservation result;
    const bool validSessionId = safeSessionId(sessionId);
    result.processUid = processUid;
    result.sessionId = validSessionId ? sessionId.toString() : QString();
    result.sessionUserId =
        property(logindProperties, QStringView{u"User"});
    result.seat = property(logindProperties, QStringView{u"Seat"});
    result.sessionType = property(logindProperties, QStringView{u"Type"});
    result.active = property(logindProperties, QStringView{u"Active"});
    result.remote = property(logindProperties, QStringView{u"Remote"});
    result.state = property(logindProperties, QStringView{u"State"});
    result.lockedHint =
        property(logindProperties, QStringView{u"LockedHint"});
    result.displayName = displayName.left(kMaximumSessionTextLength).toString();
    result.missingLibraries = missingLibraries.toString();

    // A matching logind observation is still NOT an authenticated R2
    // desktop selection. DISPLAY can be configured or point at Xvfb.
    // LockedHint is recorded below only as advisory evidence; it is never
    // treated as a positive unlock or physical-presence attestation.
    const QString processUidText =
        QString::number(static_cast<qulonglong>(processUid));
    result.activePhysicalX11Seat0 =
        processUid != 0U && validSessionId &&
        sessionType == QStringView{u"x11"} && !displayName.isEmpty() &&
        result.sessionUserId == processUidText &&
        result.seat == QStringLiteral("seat0") &&
        result.sessionType == QStringLiteral("x11") &&
        result.active == QStringLiteral("yes") &&
        result.remote == QStringLiteral("no") &&
        result.state == QStringLiteral("active") &&
        property(logindProperties, QStringView{u"Display"}) == displayName;
    return result;
}

QString formatLinuxPrerequisites(
    const LinuxPrerequisiteObservation& observation)
{
    const QString session = observation.sessionId.isEmpty()
        ? QStringLiteral("unverified")
        : observation.sessionId;
    const QString display = observation.displayName.isEmpty()
        ? QStringLiteral("not set")
        : observation.displayName;
    const QString nativeStatus = observation.activePhysicalX11Seat0
        ? QStringLiteral("seat0 X11 candidate observed; R2 authorization still required")
        : QStringLiteral("no matching active physical seat0 X11 observation");
    const QString libraryStatus = observation.missingLibraries.isEmpty()
        ? QStringLiteral("X11/XShm/RandR/XTEST client libraries located")
        : QStringLiteral("missing runtime libraries: ") +
          observation.missingLibraries;
    const auto evidence = [](const QString& value) {
        return value.isEmpty() ? QStringLiteral("unavailable") : value;
    };
    return QStringLiteral("Linux graphical prerequisites (read-only):\n")
        + nativeStatus
        + QStringLiteral("\nCurrent process UID: ")
        + QString::number(static_cast<qulonglong>(observation.processUid))
        + QStringLiteral("\nCurrent process session: ") + session
        + QStringLiteral("\nlogind session UID: ")
        + evidence(observation.sessionUserId)
        + QStringLiteral("\nlogind Seat: ") + evidence(observation.seat)
        + QStringLiteral("\nlogind Type: ") + evidence(observation.sessionType)
        + QStringLiteral("\nlogind Active: ") + evidence(observation.active)
        + QStringLiteral("\nlogind Remote: ") + evidence(observation.remote)
        + QStringLiteral("\nlogind State: ") + evidence(observation.state)
        + QStringLiteral("\nlogind LockedHint (advisory only): ")
        + evidence(observation.lockedHint)
        + QStringLiteral("\nDISPLAY: ") + display
        + QStringLiteral("\n") + libraryStatus
        + QStringLiteral("\nR2 authenticated desktop: see host authorization above")
        + QStringLiteral("\nR2 admission/session generation: unavailable to preflight")
        + QStringLiteral("\nR5 capture geometry/generation: unavailable until the R2-selected X11 owner exists")
        + QStringLiteral("\nAfter-login automatic launch: not installed or enabled by this ZIP")
        + QStringLiteral("\nNo login-screen sharing before a local graphical login.");
}

void requestLinuxPrerequisites(QLabel* statusLabel)
{
    if (!statusLabel)
        return;

    // One outstanding read-only query per view: an old reply cannot race a
    // new refresh or overwrite a replacement session's observation.
    if (statusLabel->findChild<QProcess*>() != nullptr)
        return;
    statusLabel->setTextFormat(Qt::PlainText);
    statusLabel->setText(QStringLiteral("Checking Linux graphical prerequisites (read-only)..."));
    const QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
    const QString sessionId = environment.value(QStringLiteral("XDG_SESSION_ID"));
    const QString sessionType = environment.value(QStringLiteral("XDG_SESSION_TYPE"));
    const QString display = environment.value(QStringLiteral("DISPLAY"));
    const QString missingLibraries = missingX11Libraries();
    const std::uint64_t processUid =
        static_cast<std::uint64_t>(::getuid());

    auto showResult = [statusLabel, processUid, sessionId, sessionType, display,
                       missingLibraries](const QString& logindProperties) {
        const auto observation = assessLinuxPrerequisites(
            processUid, sessionId, sessionType, display, logindProperties,
            missingLibraries);
        statusLabel->setText(formatLinuxPrerequisites(observation));
    };

    if (!safeSessionId(sessionId))
    {
        showResult({});
        return;
    }

    auto* process = new QProcess(statusLabel);
    process->setProgram(QStringLiteral("loginctl"));
    process->setArguments({QStringLiteral("show-session"), sessionId,
                           QStringLiteral("--no-pager"),
                           QStringLiteral("-p"), QStringLiteral("User"),
                           QStringLiteral("-p"), QStringLiteral("Seat"),
                           QStringLiteral("-p"), QStringLiteral("Type"),
                           QStringLiteral("-p"), QStringLiteral("Active"),
                           QStringLiteral("-p"), QStringLiteral("Remote"),
                           QStringLiteral("-p"), QStringLiteral("Display"),
                           QStringLiteral("-p"), QStringLiteral("State"),
                           QStringLiteral("-p"), QStringLiteral("LockedHint")});
    process->setProcessChannelMode(QProcess::SeparateChannels);
    process->setReadChannel(QProcess::StandardOutput);
    process->setStandardInputFile(QProcess::nullDevice());

    QObject::connect(process, &QProcess::finished, statusLabel,
        [process, showResult](int exitCode, QProcess::ExitStatus exitStatus) {
            const QByteArray output = process->readAllStandardOutput();
            const bool usable = exitStatus == QProcess::NormalExit &&
                                exitCode == 0 &&
                                output.size() <= kMaximumLogindReplyBytes;
            showResult(usable ? QString::fromUtf8(output) : QString());
            process->deleteLater();
        });
    QObject::connect(process, &QProcess::errorOccurred, statusLabel,
        [process, showResult](QProcess::ProcessError error) {
            if (error == QProcess::FailedToStart)
            {
                showResult({});
                process->deleteLater();
            }
        });
    process->start();
    QTimer::singleShot(kLogindTimeoutMilliseconds, process, [process] {
        if (process->state() != QProcess::NotRunning)
            process->kill();
    });
}
} // namespace rdp::gui
