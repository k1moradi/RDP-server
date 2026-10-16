// SPDX-License-Identifier: GPL-3.0-or-later
#include "platform/macos/native_session_change_watch.h"

#include <atomic>
#include <cstdint>
#include <limits>

namespace rdp::macos {
namespace {

enum class CoverageState : std::uint8_t {
    Unavailable,
    Registering,
    Active,
    Retiring,
};

std::atomic<std::uint64_t> s_revision{1};
std::atomic<std::uint64_t> s_registrationEpoch{0};
std::atomic<CoverageState> s_coverageState{CoverageState::Unavailable};
std::atomic<bool> s_registrationReserved{false};

[[nodiscard]] bool advanceRevision() noexcept {
    auto observed = s_revision.load(std::memory_order_relaxed);
    while (observed != 0) {
        const auto next = observed == std::numeric_limits<std::uint64_t>::max()
                              ? 0ULL
                              : observed + 1ULL;
        if (s_revision.compare_exchange_weak(
                observed, next, std::memory_order_release,
                std::memory_order_relaxed)) {
            if (next == 0) {
                s_registrationEpoch.store(0, std::memory_order_release);
                s_coverageState.store(CoverageState::Unavailable,
                                      std::memory_order_release);
            }
            return next != 0;
        }
    }
    return false;
}

void releaseRegistrationReservation() noexcept {
    s_registrationReserved.store(false, std::memory_order_release);
}

} // namespace

NativeSessionChangeWatch::~NativeSessionChangeWatch() noexcept {
    if (registered_) {
        // A failed removal leaves the process reservation held; callbacks
        // remain object-independent and therefore cannot dangle.
        (void)stop();
    }
}

std::optional<std::uint64_t>
NativeSessionChangeWatch::coveredRevision() noexcept {
    if (s_coverageState.load(std::memory_order_acquire) !=
        CoverageState::Active) {
        return std::nullopt;
    }

    const auto registrationEpoch =
        s_registrationEpoch.load(std::memory_order_acquire);
    const auto revision = s_revision.load(std::memory_order_acquire);
    if (registrationEpoch == 0 || revision == 0) {
        return std::nullopt;
    }

    if (s_coverageState.load(std::memory_order_acquire) !=
            CoverageState::Active ||
        s_registrationEpoch.load(std::memory_order_acquire) !=
            registrationEpoch) {
        return std::nullopt;
    }
    return revision;
}

bool NativeSessionChangeWatch::current(
    const std::uint64_t observedRevision) noexcept {
    if (observedRevision == 0) {
        return false;
    }
    const auto currentRevision = coveredRevision();
    return currentRevision && *currentRevision == observedRevision;
}

void NativeSessionChangeWatch::recordSessionChange(
    const std::uint64_t registrationEpoch) noexcept {
    const auto state = s_coverageState.load(std::memory_order_acquire);
    if ((state != CoverageState::Registering &&
         state != CoverageState::Active) ||
        registrationEpoch == 0 ||
        s_registrationEpoch.load(std::memory_order_acquire) !=
            registrationEpoch) {
        return;
    }

    // This minimal callback path performs no allocation, locking, user lookup,
    // permission query, capture, or input injection.
    (void)advanceRevision();
}

std::expected<void, NativeSessionChangeWatchError>
NativeSessionChangeWatch::startWithCallbacks(
    const NativeSessionChangeWatchCallbacks callbacks) noexcept {
    if (registered_) {
        return std::unexpected(
            NativeSessionChangeWatchError::AlreadyRegistered);
    }
    if (callbacks.install == nullptr || callbacks.remove == nullptr) {
        return std::unexpected(
            NativeSessionChangeWatchError::InvalidCallbacks);
    }
    if (s_revision.load(std::memory_order_acquire) == 0) {
        return std::unexpected(
            NativeSessionChangeWatchError::RevisionExhausted);
    }

    bool expected = false;
    if (!s_registrationReserved.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel)) {
        return std::unexpected(
            NativeSessionChangeWatchError::AlreadyRegistered);
    }

    s_coverageState.store(CoverageState::Registering,
                          std::memory_order_release);
    if (!advanceRevision()) {
        s_coverageState.store(CoverageState::Unavailable,
                              std::memory_order_release);
        releaseRegistrationReservation();
        return std::unexpected(
            NativeSessionChangeWatchError::RevisionExhausted);
    }

    registrationEpoch_ = s_revision.load(std::memory_order_acquire);
    callbacks_ = callbacks;
    s_registrationEpoch.store(registrationEpoch_, std::memory_order_release);

    if (!callbacks_.install(callbacks_.context, registrationEpoch_,
                            &NativeSessionChangeWatch::recordSessionChange)) {
        s_registrationEpoch.store(0, std::memory_order_release);
        s_coverageState.store(CoverageState::Unavailable,
                              std::memory_order_release);
        const bool revisionAvailable = advanceRevision();
        // A failed install may be partial: retirement must succeed before the
        // sole process registration reservation can be released.
        if (!callbacks_.remove(callbacks_.context)) {
            registered_ = true;
            return std::unexpected(
                NativeSessionChangeWatchError::RemovalFailed);
        }
        callbacks_ = {};
        registrationEpoch_ = 0;
        releaseRegistrationReservation();
        return std::unexpected(
            revisionAvailable
                ? NativeSessionChangeWatchError::RegistrationFailed
                : NativeSessionChangeWatchError::RevisionExhausted);
    }

    // An event delivered during installation is valid and already advanced
    // the revision. Exhaustion in that interval is terminal.
    if (s_revision.load(std::memory_order_acquire) == 0) {
        s_registrationEpoch.store(0, std::memory_order_release);
        s_coverageState.store(CoverageState::Unavailable,
                              std::memory_order_release);
        if (!callbacks_.remove(callbacks_.context)) {
            registered_ = true;
            return std::unexpected(
                NativeSessionChangeWatchError::RemovalFailed);
        }
        callbacks_ = {};
        registrationEpoch_ = 0;
        releaseRegistrationReservation();
        return std::unexpected(
            NativeSessionChangeWatchError::RevisionExhausted);
    }

    registered_ = true;
    s_coverageState.store(CoverageState::Active,
                          std::memory_order_release);
    return {};
}

std::expected<void, NativeSessionChangeWatchError>
NativeSessionChangeWatch::stop() noexcept {
    if (!registered_) {
        return {};
    }

    // Close coverage before removal. A callback already in flight can only
    // conservatively advance the revision; it cannot resurrect coverage.
    s_coverageState.store(CoverageState::Retiring,
                          std::memory_order_release);
    s_registrationEpoch.store(0, std::memory_order_release);
    const bool revisionAvailable = advanceRevision();
    s_coverageState.store(CoverageState::Unavailable,
                          std::memory_order_release);

    if (!callbacks_.remove(callbacks_.context)) {
        // Keep the reservation held while observer retirement is ambiguous.
        return std::unexpected(
            NativeSessionChangeWatchError::RemovalFailed);
    }

    registered_ = false;
    callbacks_ = {};
    registrationEpoch_ = 0;
    releaseRegistrationReservation();
    if (!revisionAvailable) {
        return std::unexpected(
            NativeSessionChangeWatchError::RevisionExhausted);
    }
    return {};
}

} // namespace rdp::macos
