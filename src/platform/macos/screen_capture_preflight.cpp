// SPDX-License-Identifier: GPL-3.0-or-later
#include "platform/macos/screen_capture_preflight.h"

#if defined(__APPLE__)
#include <CoreGraphics/CoreGraphics.h>
#endif

namespace rdp::macos {

ScreenCapturePreflightStatus evaluateScreenCapturePreflight(
    const ScreenCapturePreflightProbe probe, void* const context) noexcept {
    if (probe == nullptr) {
        return ScreenCapturePreflightStatus::Unavailable;
    }
    return probe(context) ? ScreenCapturePreflightStatus::Granted
                          : ScreenCapturePreflightStatus::NotGranted;
}

#if defined(__APPLE__)
namespace {

[[nodiscard]] bool readNativePreflight(void*) noexcept {
    return CGPreflightScreenCaptureAccess();
}

} // namespace

ScreenCapturePreflightStatus queryNativeScreenCapturePreflight() noexcept {
    // Only a preflight: never call CGRequestScreenCaptureAccess in this path.
    return evaluateScreenCapturePreflight(&readNativePreflight, nullptr);
}
#endif

} // namespace rdp::macos
