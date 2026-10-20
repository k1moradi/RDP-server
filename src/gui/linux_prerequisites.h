// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <QString>
#include <QStringView>

#include <cstdint>

class QLabel;

namespace rdp::gui
{
// Read-only desktop diagnostics, never a native R2 admission capability.
// The parser accepts injected logind text for negative offline testing.
struct LinuxPrerequisiteObservation final
{
    bool activePhysicalX11Seat0{};
    std::uint64_t processUid{};
    QString sessionId;
    QString sessionUserId;
    QString seat;
    QString sessionType;
    QString active;
    QString remote;
    QString state;
    QString lockedHint;
    QString displayName;
    QString missingLibraries;
};

[[nodiscard]] LinuxPrerequisiteObservation assessLinuxPrerequisites(
    std::uint64_t processUid, QStringView sessionId, QStringView sessionType,
    QStringView displayName, QStringView logindProperties,
    QStringView missingLibraries);

[[nodiscard]] QString formatLinuxPrerequisites(
    const LinuxPrerequisiteObservation& observation);

// Async, non-authorizing status query. Uses only the current GUI process's
// session environment and a bounded read-only loginctl show-session call.
// Caller owns statusLabel; no process, descriptor, or observation escapes it.
void requestLinuxPrerequisites(QLabel* statusLabel);
} // namespace rdp::gui
