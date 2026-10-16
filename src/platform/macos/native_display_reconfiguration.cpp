// SPDX-License-Identifier: GPL-3.0-or-later
#include "platform/macos/native_display_reconfiguration.h"

#include <atomic>
#include <cstdint>
#include <limits>

#if defined(__APPLE__)
#include <CoreGraphics/CoreGraphics.h>
#endif

namespace rdp::macos {
namespace {

// Process-lifetime globals prevent callback userInfo use-after-free even if
// CoreGraphics has an already-running notification when removal is requested.
std::atomic<std::uint64_t> s_revision{1};
#if defined(__APPLE__)
std::atomic<bool> s_registrationReserved{false};

void quartzDisplayChanged(CGDirectDisplayID,
                          CGDisplayChangeSummaryFlags, void*) noexcept {
    // No CoreGraphics calls, allocations, locks or native session access
    // on an OS reconfiguration callback.
    NativeDisplayReconfigurationWatch::recordTopologyChange();
}
#endif

} // namespace

NativeDisplayReconfigurationWatch::~NativeDisplayReconfigurationWatch() noexcept {
#if defined(__APPLE__)
    if (registered_) {
        // On removal error the static callback remains memory-safe and the
        // reservation remains held, deliberately preventing duplicate owners.
        (void)stopNative();
    }
#endif
}

std::uint64_t NativeDisplayReconfigurationWatch::revision() noexcept {
    return s_revision.load(std::memory_order_acquire);
}

bool NativeDisplayReconfigurationWatch::changedSince(
    const std::uint64_t observedRevision) noexcept {
    const auto current = revision();
    return observedRevision == 0 || current == 0 || observedRevision != current;
}

void NativeDisplayReconfigurationWatch::recordTopologyChange() noexcept {
    auto observed = s_revision.load(std::memory_order_relaxed);
    while (observed != 0) {
        const auto next = observed == std::numeric_limits<std::uint64_t>::max()
                              ? 0ULL : observed + 1ULL;
        if (s_revision.compare_exchange_weak(
                observed, next, std::memory_order_release,
                std::memory_order_relaxed)) {
            return;
        }
    }
}

#if defined(__APPLE__)
std::expected<void, NativeDisplayWatchError>
NativeDisplayReconfigurationWatch::startNative() noexcept {
    if (registered_) {
        return std::unexpected(NativeDisplayWatchError::AlreadyRegistered);
    }
    bool expected = false;
    if (!s_registrationReserved.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel)) {
        return std::unexpected(NativeDisplayWatchError::AlreadyRegistered);
    }
    if (CGDisplayRegisterReconfigurationCallback(
            &quartzDisplayChanged, nullptr) != kCGErrorSuccess) {
        s_registrationReserved.store(false, std::memory_order_release);
        return std::unexpected(NativeDisplayWatchError::RegistrationFailed);
    }
    registered_ = true;
    recordTopologyChange(); // Old geometry predates notification coverage.
    return {};
}

std::expected<void, NativeDisplayWatchError>
NativeDisplayReconfigurationWatch::stopNative() noexcept {
    if (!registered_) {
        return {};
    }
    recordTopologyChange(); // Retire geometry before removing coverage.
    if (CGDisplayRemoveReconfigurationCallback(
            &quartzDisplayChanged, nullptr) != kCGErrorSuccess) {
        return std::unexpected(NativeDisplayWatchError::RemovalFailed);
    }
    registered_ = false;
    s_registrationReserved.store(false, std::memory_order_release);
    return {};
}
#endif

} // namespace rdp::macos
