// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <QString>
#include <QStringView>

namespace rdp::gui
{

// A non-authorizing convenience suggestion for the standalone Username field.
// Empty means the platform could not safely identify an interactive local user.
[[nodiscard]] QString currentLocalUsernameSuggestion();

// Validates only whether a local account name is suitable as a UI default.
// It never maps the remote credential to an OS identity.
[[nodiscard]] bool isSafeLocalUsernameSuggestion(QStringView username);

} // namespace rdp::gui
