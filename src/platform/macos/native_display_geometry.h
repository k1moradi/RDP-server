// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "platform/macos/desktop_display_geometry.h"
#include "platform/macos/native_display_snapshot.h"

#include <cstdint>
#include <expected>

namespace rdp::macos {

enum class NativeDisplayGeometryError : std::uint8_t {
    InvalidSnapshot,
    UnsupportedRotation,
    UnsupportedMixedScale,
    UnrepresentablePlacement,
};

// Converts native logical-point observations into a VIRTUAL COMPOSITOR pixel
// layout for RDP. Physical pixel origins are chosen relative to the minimum
// logical display bounds; these are NOT CoreGraphics native framebuffer
// origins. Multi-display composition is possible only under one uniform,
// isotropic scale with integer pixel-aligned offsets. Mixed-scale layouts
// require an explicit R4 composition contract and therefore fail closed.
// Output owns its mappings and preserves the source generation; a failure
// cannot partially publish a DesktopDisplayGeometry object.
[[nodiscard]] std::expected<DesktopDisplayGeometry, NativeDisplayGeometryError>
makeDesktopGeometry(const NativeDisplaySnapshot& native) noexcept;

#if defined(__APPLE__)
// Read-only native display query, no screen access, authorization or TCC prompt.
[[nodiscard]] std::expected<DesktopDisplayGeometry, NativeDisplayGeometryError>
queryNativeDesktopGeometry(std::uint64_t generation) noexcept;
#endif

} // namespace rdp::macos
