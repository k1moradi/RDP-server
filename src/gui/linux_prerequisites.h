// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <QString>
#include <QStringView>

#include <cstdint>

class QLabel;

namespace rdp::gui
{
// Read-only desktop observations. These are presentation evidence only and
// never create native desktop authority.
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
    QString sessionDisplayName;
    QString missingLibraries;
};

enum class LinuxPrerequisiteState : std::uint8_t
{
    Unknown,
    No,
    Yes,
};

enum class LinuxInputSupport : std::uint8_t
{
    Unknown,
    Unavailable,
    Available,
};

// Compact read-only projection for the product UI. Field names and values are
// intentionally user-facing rather than implementation diagnostics.
struct LinuxDesktopPrerequisiteProjection final
{
    QString sessionType;
    QString display;
    LinuxPrerequisiteState activeLocalSession{LinuxPrerequisiteState::Unknown};
    LinuxPrerequisiteState unlocked{LinuxPrerequisiteState::Unknown};
    LinuxPrerequisiteState physicalSession{LinuxPrerequisiteState::Unknown};
    LinuxInputSupport inputSupport{LinuxInputSupport::Unknown};
};

[[nodiscard]] LinuxPrerequisiteObservation assessLinuxPrerequisites(
    std::uint64_t processUid, QStringView sessionId, QStringView sessionType,
    QStringView displayName, QStringView logindProperties,
    QStringView missingLibraries);

[[nodiscard]] LinuxDesktopPrerequisiteProjection projectLinuxPrerequisites(
    const LinuxPrerequisiteObservation& observation);

[[nodiscard]] QString formatLinuxPrerequisites(
    const LinuxDesktopPrerequisiteProjection& projection);

// Async, non-authorizing status query. Uses only the current GUI process's
// session environment, client-runtime library presence and a bounded read-only
// loginctl show-session call. It never starts capture, injects input, opens a
// listener or requests sharing permission.
void requestLinuxPrerequisites(QLabel* statusLabel);
} // namespace rdp::gui
