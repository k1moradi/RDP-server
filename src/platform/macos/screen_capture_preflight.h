// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace rdp::macos {

enum class ScreenCapturePreflightStatus : std::uint8_t {
    Unavailable,
    NotGranted,
    Granted,
};

// A synchronous, borrowed provider: no callback or context is retained.
// Caller serializes any mutable callback context with concurrent changes.
// Re-query on each call; never cache a prior permission grant across TCC
// revocation, app identity changes, or native session transitions.
// This is permission evidence ONLY, never R2 OS/session admission.
using ScreenCapturePreflightProbe = bool (*)(void* context) noexcept;

[[nodiscard]] ScreenCapturePreflightStatus evaluateScreenCapturePreflight(
    ScreenCapturePreflightProbe probe, void* context) noexcept;

// macOS-only CoreGraphics preflight (no permission prompt or screen access).
// Requires an appropriate per-user, signed application context. A true
// result does not guarantee that ScreenCaptureKit can start or continue.
#if defined(__APPLE__)
[[nodiscard]] ScreenCapturePreflightStatus queryNativeScreenCapturePreflight() noexcept;
#endif

} // namespace rdp::macos
