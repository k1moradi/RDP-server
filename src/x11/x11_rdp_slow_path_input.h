// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "x11_input_event.h"
#include "core/geometry.h"
#include "server/transport/mcs_channel_connection.h"

#include <optional>

// Only a deterministic, explicitly supported subset of the already-decoded
// R3 slow-path event formats is translated. This is NOT an authorization
// gateway: R2 must revalidate every event before the translated XTEST sink.
// Unmapped keyboard, Unicode, relative, extended and wheel forms currently
// fail closed, rather than guessing at desktop layout or pointer position.
[[nodiscard]] std::optional<X11InputEvent>
translateRdpSlowPathX11Input(
    const rdp_server::server::transport::RdpSlowPathInputEvent &event,
    PixelSize geometry) noexcept;
