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
    // never connects to the X server, reads pixels or enables native input.
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

[[nodiscard]] LinuxPrerequisiteState projectedState(
    const bool evidenceComplete, const bool value) noexcept
{
    if (!evidenceComplete)
        return LinuxPrerequisiteState::Unknown;
    return value ? LinuxPrerequisiteState::Yes : LinuxPrerequisiteState::No;
}

[[nodiscard]] QString prerequisiteStateText(
    const LinuxPrerequisiteState state)
{
    switch (state)
    {
    case LinuxPrerequisiteState::Unknown:
        return QStringLiteral("Unknown");
    case LinuxPrerequisiteState::No:
        return QStringLiteral("No");
    case LinuxPrerequisiteState::Yes:
        return QStringLiteral("Yes");
    }
    return QStringLiteral("Unknown");
}

[[nodiscard]] QString inputSupportText(const LinuxInputSupport support)
{
    switch (support)
    {
    case LinuxInputSupport::Unknown:
        return QStringLiteral("Unknown");
    case LinuxInputSupport::Unavailable:
        return QStringLiteral("Unavailable");
    case LinuxInputSupport::Available:
        return QStringLiteral("Available");
    }
    return QStringLiteral("Unknown");
}

[[nodiscard]] bool isX11(const QString& sessionType) noexcept
{
    return sessionType.compare(QStringLiteral("x11"), Qt::CaseInsensitive) == 0;
}

[[nodiscard]] QString displaySessionType(const QString& sessionType)
{
    if (sessionType.isEmpty())
        return QStringLiteral("Unknown");
    if (isX11(sessionType))
        return QStringLiteral("X11");
    if (sessionType.compare(
            QStringLiteral("wayland"), Qt::CaseInsensitive) == 0)
        return QStringLiteral("Wayland");
    return sessionType;
}

[[nodiscard]] bool missingXcbInputLibraries(
    const QString& missingLibraries) noexcept
{
    return missingLibraries.contains(QStringLiteral("libxcb.so.1")) ||
           missingLibraries.contains(QStringLiteral("libxcb-xtest.so.0"));
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
    result.sessionUserId = property(logindProperties, QStringView{u"User"});
    result.seat = property(logindProperties, QStringView{u"Seat"});
    result.sessionType = property(logindProperties, QStringView{u"Type"});
    result.active = property(logindProperties, QStringView{u"Active"});
    result.remote = property(logindProperties, QStringView{u"Remote"});
    result.state = property(logindProperties, QStringView{u"State"});
    result.lockedHint = property(logindProperties, QStringView{u"LockedHint"});
    result.displayName = displayName.left(kMaximumSessionTextLength).toString();
    result.sessionDisplayName =
        property(logindProperties, QStringView{u"Display"});
    result.missingLibraries = missingLibraries.toString();

    // A matching observation is still only read-only prerequisite evidence.
    // DISPLAY can be configured or point at Xvfb; no native owner is created.
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
        result.sessionDisplayName == displayName;
    return result;
}

LinuxDesktopPrerequisiteProjection projectLinuxPrerequisites(
    const LinuxPrerequisiteObservation& observation)
{
    LinuxDesktopPrerequisiteProjection projection;
    projection.sessionType = displaySessionType(observation.sessionType);
    projection.display = observation.displayName.isEmpty()
        ? QStringLiteral("Unknown")
        : observation.displayName;

    const QString processUidText =
        QString::number(static_cast<qulonglong>(observation.processUid));
    const bool activeEvidenceComplete =
        observation.processUid != 0U && !observation.sessionId.isEmpty() &&
        !observation.sessionUserId.isEmpty() && !observation.active.isEmpty() &&
        !observation.remote.isEmpty() && !observation.state.isEmpty();
    const bool activeLocalSession =
        observation.sessionUserId == processUidText &&
        observation.active == QStringLiteral("yes") &&
        observation.remote == QStringLiteral("no") &&
        observation.state == QStringLiteral("active");
    projection.activeLocalSession =
        projectedState(activeEvidenceComplete, activeLocalSession);

    if (observation.lockedHint == QStringLiteral("no"))
        projection.unlocked = LinuxPrerequisiteState::Yes;
    else if (observation.lockedHint == QStringLiteral("yes"))
        projection.unlocked = LinuxPrerequisiteState::No;

    const bool physicalEvidenceComplete =
        activeEvidenceComplete && !observation.seat.isEmpty() &&
        !observation.sessionType.isEmpty() &&
        !observation.displayName.isEmpty() &&
        !observation.sessionDisplayName.isEmpty();
    projection.physicalSession = projectedState(
        physicalEvidenceComplete, observation.activePhysicalX11Seat0);

    if (observation.sessionType.isEmpty())
    {
        projection.inputSupport = LinuxInputSupport::Unknown;
    }
    else if (!isX11(observation.sessionType) ||
             observation.displayName.isEmpty() ||
             missingXcbInputLibraries(observation.missingLibraries))
    {
        projection.inputSupport = LinuxInputSupport::Unavailable;
    }
    else
    {
        // "Available" means the read-only client-side XCB/XTEST runtime
        // prerequisites are present. This probe does not connect to the X
        // server to test or enable the extension.
        projection.inputSupport = LinuxInputSupport::Available;
    }

    return projection;
}

QString formatLinuxPrerequisites(
    const LinuxDesktopPrerequisiteProjection& projection)
{
    const QString sessionType = projection.sessionType.isEmpty()
        ? QStringLiteral("Unknown")
        : projection.sessionType;
    const QString display = projection.display.isEmpty()
        ? QStringLiteral("Unknown")
        : projection.display;
    return QStringLiteral("Linux desktop\nSession type: ") + sessionType
        + QStringLiteral("\nDisplay: ") + display
        + QStringLiteral("\nActive local session: ")
        + prerequisiteStateText(projection.activeLocalSession)
        + QStringLiteral("\nUnlocked: ")
        + prerequisiteStateText(projection.unlocked)
        + QStringLiteral("\nPhysical session: ")
        + prerequisiteStateText(projection.physicalSession)
        + QStringLiteral("\nInput support: ")
        + inputSupportText(projection.inputSupport);
}

void requestLinuxPrerequisites(QLabel* statusLabel)
{
    if (!statusLabel)
        return;
    if (statusLabel->findChild<QProcess*>() != nullptr)
        return;

    statusLabel->setTextFormat(Qt::PlainText);
    statusLabel->setText(QStringLiteral("Checking Linux desktop status..."));
    const QProcessEnvironment environment =
        QProcessEnvironment::systemEnvironment();
    const QString sessionId =
        environment.value(QStringLiteral("XDG_SESSION_ID"));
    const QString sessionType =
        environment.value(QStringLiteral("XDG_SESSION_TYPE"));
    const QString display = environment.value(QStringLiteral("DISPLAY"));
    const QString missingLibraries = missingX11Libraries();
    const std::uint64_t processUid =
        static_cast<std::uint64_t>(::getuid());

    auto showResult = [statusLabel, processUid, sessionId, sessionType, display,
                       missingLibraries](const QString& logindProperties) {
        const auto observation = assessLinuxPrerequisites(
            processUid, sessionId, sessionType, display, logindProperties,
            missingLibraries);
        statusLabel->setText(formatLinuxPrerequisites(
            projectLinuxPrerequisites(observation)));
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
