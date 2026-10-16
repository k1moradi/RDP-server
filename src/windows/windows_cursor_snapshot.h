// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "windows_desktop_geometry.h"

#include <cstdint>

namespace rdp_server::windows
{

inline constexpr std::uint32_t kMaximumWindowsCursorDimension = 256;

enum class WindowsCursorReadResult
{
    ready,
    hidden,
    invalid,
    failed,
};

// Native cursor facts sampled synchronously on the authorized capture-owner
// thread. Coordinates are Win32 virtual-screen pixels before layout translation.
struct WindowsNativeCursorObservation final
{
    WindowsNativePoint position{};
    std::uint32_t widthPixels{};
    std::uint32_t heightPixels{};
    std::uint32_t hotspotX{};
    std::uint32_t hotspotY{};
};

struct WindowsCursorSnapshot final
{
    bool visible{};
    WindowsDesktopPoint position{};
    std::uint32_t widthPixels{};
    std::uint32_t heightPixels{};
    std::uint32_t hotspotX{};
    std::uint32_t hotspotY{};

    friend bool operator==(const WindowsCursorSnapshot &,
                           const WindowsCursorSnapshot &) = default;
};

struct WindowsCursorReadCallbacks final
{
    void *context{};
    WindowsCursorReadResult (*read)(
        void *context, WindowsNativeCursorObservation &observation) noexcept{};
};

// Translate one read-only native cursor observation into the validated desktop
// coordinate space. Hidden is a successful snapshot that clears stale cursor
// metadata. Failures leave output unchanged. This does not authorize a session,
// retain a native cursor handle, extract shape pixels or schedule an R4 update.
[[nodiscard]] WindowsCursorReadResult readWindowsCursorSnapshot(
    const WindowsDesktopLayout &layout, WindowsCursorReadCallbacks callbacks,
    WindowsCursorSnapshot &output) noexcept;

#ifdef _WIN32
// Read-only Win32 observer. The caller must already be bound to the correct,
// independently authorized interactive session/desktop before invoking it.
[[nodiscard]] WindowsCursorReadCallbacks windowsCursorReadCallbacks() noexcept;
#endif

} // namespace rdp_server::windows
