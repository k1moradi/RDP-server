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
std::atomic<bool> s_nativeCoverageActive{false};

void quartzDisplayChanged(CGDirectDisplayID,
                          CGDisplayChangeSummaryFlags, void*) noexcept {
    // No CoreGraphics calls, allocations, locks or native session access
    // on an OS reconfiguration callback.
    NativeDisplayReconfigurationWatch::recordTopologyChange();
}

bool installQuartzDisplayWatch(
    void*, const NativeDisplayReconfigurationWatch::ChangeRecorder recorder) noexcept {
    if (recorder == nullptr) {
        return false;
    }
    return CGDisplayRegisterReconfigurationCallback(
               &quartzDisplayChanged, nullptr) == kCGErrorSuccess;
}

bool removeQuartzDisplayWatch(void*) noexcept {
    return CGDisplayRemoveReconfigurationCallback(
               &quartzDisplayChanged, nullptr) == kCGErrorSuccess;
}
#endif

} // namespace

NativeDisplayReconfigurationWatch::~NativeDisplayReconfigurationWatch() noexcept {
#if defined(__APPLE__)
    if (registered_) {
        // On removal error the static callback remains memory-safe and the
        // reservation remains held, deliberately preventing duplicate owners.
        (void)stopWithCallbacks();
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
NativeDisplayReconfigurationWatch::startWithCallbacks(
    const Callbacks callbacks) noexcept {
    if (registered_) {
        return std::unexpected(NativeDisplayWatchError::AlreadyRegistered);
    }
    if (callbacks.install == nullptr || callbacks.remove == nullptr) {
        return std::unexpected(NativeDisplayWatchError::InvalidCallbacks);
    }
    if (revision() == 0) {
        return std::unexpected(NativeDisplayWatchError::RevisionExhausted);
    }

    bool expected = false;
    if (!s_registrationReserved.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel)) {
        return std::unexpected(NativeDisplayWatchError::AlreadyRegistered);
    }

    callbacks_ = callbacks;
    if (!callbacks_.install(callbacks_.context, &recordTopologyChange)) {
        callbacks_ = {};
        s_registrationReserved.store(false, std::memory_order_release);
        return std::unexpected(NativeDisplayWatchError::RegistrationFailed);
    }

    registered_ = true;
    s_nativeCoverageActive.store(true, std::memory_order_release);
    recordTopologyChange(); // Old geometry predates notification coverage.
    if (revision() != 0) {
        return {};
    }

    // Numeric exhaustion is terminal. Retire native coverage and the installed
    // callback before reporting failure; ambiguous removal remains fail-closed.
    s_nativeCoverageActive.store(false, std::memory_order_release);
    if (!callbacks_.remove(callbacks_.context)) {
        return std::unexpected(NativeDisplayWatchError::RemovalFailed);
    }
    registered_ = false;
    callbacks_ = {};
    s_registrationReserved.store(false, std::memory_order_release);
    return std::unexpected(NativeDisplayWatchError::RevisionExhausted);
}

std::expected<void, NativeDisplayWatchError>
NativeDisplayReconfigurationWatch::stopWithCallbacks() noexcept {
    if (!registered_) {
        return {};
    }

    // Coverage becomes unavailable before callback retirement. If removal is
    // ambiguous, the reservation stays held but no fresh native geometry may
    // treat that observer as reliable coverage.
    s_nativeCoverageActive.store(false, std::memory_order_release);
    recordTopologyChange(); // Retire geometry before removing coverage.
    if (!callbacks_.remove(callbacks_.context)) {
        return std::unexpected(NativeDisplayWatchError::RemovalFailed);
    }
    registered_ = false;
    callbacks_ = {};
    s_registrationReserved.store(false, std::memory_order_release);
    return {};
}

std::expected<void, NativeDisplayWatchError>
NativeDisplayReconfigurationWatch::startNative() noexcept {
    return startWithCallbacks({
        nullptr, &installQuartzDisplayWatch, &removeQuartzDisplayWatch});
}

std::expected<void, NativeDisplayWatchError>
NativeDisplayReconfigurationWatch::stopNative() noexcept {
    return stopWithCallbacks();
}

bool NativeDisplayReconfigurationWatch::nativeCoverageActive() noexcept {
    return s_nativeCoverageActive.load(std::memory_order_acquire) &&
           revision() != 0;
}
#endif

} // namespace rdp::macos
