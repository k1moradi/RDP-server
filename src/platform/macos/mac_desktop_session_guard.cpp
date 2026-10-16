// SPDX-License-Identifier: GPL-3.0-or-later
#include "platform/macos/mac_desktop_session_guard.h"

#include <limits>

#if defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <unistd.h>
#endif

namespace rdp::macos {

MacDesktopSessionGuard::MacDesktopSessionGuard(
    const NativeDisplayGeometryRefresh& geometry,
    const std::uint64_t geometryGeneration,
    const std::uint32_t targetUserId,
    const MacDesktopSessionReadCallbacks sessionReader,
    const MacDesktopPermissionReadCallbacks permissionReader) noexcept
    : geometry_(&geometry),
      geometryGeneration_(geometryGeneration),
      targetUserId_(targetUserId),
      sessionReader_(sessionReader),
      permissionReader_(permissionReader) {
    const auto topologyRevision = geometry.topologyRevision(geometryGeneration);
    const auto sessionWatchRevision =
        NativeSessionChangeWatch::coveredRevision();
    if (geometryGeneration_ == 0 || targetUserId_ == 0 ||
        targetUserId_ == std::numeric_limits<std::uint32_t>::max() ||
        sessionReader_.read == nullptr || permissionReader_.capture == nullptr ||
        permissionReader_.input == nullptr || !topologyRevision ||
        *topologyRevision == 0 || !sessionWatchRevision ||
        *sessionWatchRevision == 0) {
        invalidate();
        return;
    }
    topologyRevision_ = *topologyRevision;
    sessionWatchRevision_ = *sessionWatchRevision;
}

bool MacDesktopSessionGuard::geometryCurrent() const noexcept {
    if (geometry_ == nullptr || geometryGeneration_ == 0 ||
        topologyRevision_ == 0) {
        return false;
    }
    const auto current = geometry_->topologyRevision(geometryGeneration_);
    return current && *current == topologyRevision_;
}

bool MacDesktopSessionGuard::sessionWatchCurrent() const noexcept {
    return sessionWatchRevision_ != 0 &&
           NativeSessionChangeWatch::current(sessionWatchRevision_);
}

bool MacDesktopSessionGuard::sessionCurrent(
    MacDesktopSessionObservation& observation) noexcept {
    if (sessionReader_.read == nullptr ||
        !sessionReader_.read(sessionReader_.context, observation)) {
        return false;
    }
    return observation.sessionUserId == targetUserId_ &&
           observation.effectiveUserId == targetUserId_ &&
           observation.onConsole && observation.loginComplete;
}

void MacDesktopSessionGuard::invalidate() noexcept {
    closed_ = true;
    geometry_ = nullptr;
    geometryGeneration_ = 0;
    topologyRevision_ = 0;
    sessionWatchRevision_ = 0;
    targetUserId_ = 0;
}

bool MacDesktopSessionGuard::allows(const MacDesktopAccessKind access) noexcept {
    if (closed_) {
        return false;
    }
    if (operationInProgress_) {
        invalidate();
        return false;
    }

    operationInProgress_ = true;
    MacDesktopSessionObservation before{};
    bool permitted = sessionWatchCurrent() && geometryCurrent() &&
                     sessionCurrent(before);

    if (permitted) {
        switch (access) {
        case MacDesktopAccessKind::Capture:
            permitted = permissionReader_.capture(permissionReader_.context) ==
                        ScreenCapturePreflightStatus::Granted;
            break;
        case MacDesktopAccessKind::Input:
            permitted = permissionReader_.input(permissionReader_.context) ==
                        MacInputPermissionStatus::Trusted;
            break;
        default:
            permitted = false;
            break;
        }
    }

    MacDesktopSessionObservation after{};
    if (permitted) {
        permitted = sessionCurrent(after) && after == before &&
                    geometryCurrent();
    }

    operationInProgress_ = false;
    if (permitted) {
        // Final success gate closes on an observed switch even when both
        // synchronous Quartz session observations compare equal.
        permitted = sessionWatchCurrent();
    }
    if (!permitted || closed_) {
        invalidate();
        return false;
    }
    return true;
}

void MacDesktopSessionGuard::close() noexcept {
    if (!closed_) {
        invalidate();
    }
}

#if defined(__APPLE__)
namespace {

class DictionaryOwner final {
public:
    explicit DictionaryOwner(CFDictionaryRef dictionary) noexcept
        : dictionary_(dictionary) {}

    ~DictionaryOwner() noexcept {
        if (dictionary_ != nullptr) {
            CFRelease(dictionary_);
        }
    }

    DictionaryOwner(const DictionaryOwner&) = delete;
    DictionaryOwner& operator=(const DictionaryOwner&) = delete;

    [[nodiscard]] CFDictionaryRef get() const noexcept { return dictionary_; }

private:
    CFDictionaryRef dictionary_{};
};

[[nodiscard]] bool readUnsigned32(CFDictionaryRef dictionary,
                                  CFStringRef key,
                                  std::uint32_t& output) noexcept {
    const auto* value = CFDictionaryGetValue(dictionary, key);
    if (value == nullptr ||
        CFGetTypeID(static_cast<CFTypeRef>(value)) != CFNumberGetTypeID()) {
        return false;
    }

    std::int64_t signedValue{};
    if (!CFNumberGetValue(static_cast<CFNumberRef>(value),
                          kCFNumberSInt64Type, &signedValue) ||
        signedValue < 0 ||
        static_cast<std::uint64_t>(signedValue) >
            std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }
    output = static_cast<std::uint32_t>(signedValue);
    return true;
}

[[nodiscard]] bool readBoolean(CFDictionaryRef dictionary,
                               CFStringRef key,
                               bool& output) noexcept {
    const auto* value = CFDictionaryGetValue(dictionary, key);
    if (value == nullptr ||
        CFGetTypeID(static_cast<CFTypeRef>(value)) != CFBooleanGetTypeID()) {
        return false;
    }
    output = CFBooleanGetValue(static_cast<CFBooleanRef>(value));
    return true;
}

[[nodiscard]] bool readNativeDesktopSession(
    void*, MacDesktopSessionObservation& observation) noexcept {
    DictionaryOwner dictionary(CGSessionCopyCurrentDictionary());
    if (dictionary.get() == nullptr) {
        return false;
    }

    std::uint32_t sessionUserId{};
    bool onConsole{};
    bool loginComplete{};
    if (!readUnsigned32(dictionary.get(), kCGSessionUserIDKey, sessionUserId) ||
        !readBoolean(dictionary.get(), kCGSessionOnConsoleKey, onConsole) ||
        !readBoolean(dictionary.get(), kCGSessionLoginDoneKey, loginComplete)) {
        return false;
    }

    const auto effectiveUser = static_cast<std::uint64_t>(geteuid());
    if (effectiveUser > std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }

    observation = {
        sessionUserId,
        static_cast<std::uint32_t>(effectiveUser),
        onConsole,
        loginComplete,
    };
    return true;
}

[[nodiscard]] ScreenCapturePreflightStatus readNativeCapturePermission(
    void*) noexcept {
    return queryNativeScreenCapturePreflight();
}

[[nodiscard]] MacInputPermissionStatus readNativeInputPermission(
    void*) noexcept {
    return queryNativeMacInputPermissionStatus();
}

} // namespace

MacDesktopSessionReadCallbacks macDesktopSessionReadCallbacks() noexcept {
    return {nullptr, &readNativeDesktopSession};
}

MacDesktopPermissionReadCallbacks macDesktopPermissionReadCallbacks() noexcept {
    return {nullptr, &readNativeCapturePermission, &readNativeInputPermission};
}
#endif

} // namespace rdp::macos
