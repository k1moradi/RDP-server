// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "windows_dxgi_capture_cycle.h"

#include <cstdint>

namespace rdp_server::windows
{

class WindowsInputController;

// Read-only facts about one caller-selected Windows session. A target ID is
// merely a selector supplied by the future R2/R3 authorization owner; these
// fields never constitute authentication, authorization or a capability.
struct WindowsCaptureSessionObservation final
{
    std::uint32_t targetSessionId{};
    std::uint32_t processSessionId{};
    bool targetActive{};
};

struct WindowsCaptureSessionReadCallbacks final
{
    void *context{};
    bool (*read)(void *context, std::uint32_t targetSessionId,
                 WindowsCaptureSessionObservation &observation) noexcept{};
};

enum class WindowsCaptureSessionChangeResult
{
    ignored,
    revoked,
    alreadyClosed,
    invalidSession,
};

// Composes the EXISTING capture generation source with a synchronous Windows
// session-state precondition. This class never creates a token, switches
// desktops, opens DXGI, or decides OS admission. It only revokes.
//
// Once any observation is unavailable, mismatched, inactive, reentrant or
// reports a zero epoch, this guard is terminal; construct a fresh guard only
// after R2/R3 independently reauthorizes/rebinds the native session.
class WindowsCaptureSessionGenerationGuard final
{
public:
    WindowsCaptureSessionGenerationGuard(
        std::uint32_t targetSessionId,
        WindowsCaptureSessionReadCallbacks sessionReader,
        WindowsCaptureGenerationReader generationReader) noexcept;

    WindowsCaptureSessionGenerationGuard(
        const WindowsCaptureSessionGenerationGuard &) = delete;
    WindowsCaptureSessionGenerationGuard &operator=(
        const WindowsCaptureSessionGenerationGuard &) = delete;

    [[nodiscard]] WindowsCaptureGenerationReader reader() noexcept;
    // Called only on the same serialized capture-owner thread as reader().
    // Any valid change for the selected target is revocation-only: unlock or
    // reconnect never reopens this guard without fresh R2/R3 authorization.
    [[nodiscard]] WindowsCaptureSessionChangeResult notifySessionChange(
        std::uint32_t sessionId) noexcept;
    [[nodiscard]] bool closed() const noexcept { return closed_; }

private:
    static bool readGeneration(
        void *context, WindowsCaptureGeneration &current) noexcept;

    std::uint32_t targetSessionId_{};
    WindowsCaptureSessionReadCallbacks sessionReader_{};
    WindowsCaptureGenerationReader generationReader_{};
    bool readInProgress_{};
    bool closed_{};
};

// Stateless, revocation-only composition for an already-authorized native
// lifetime. Calls must stay on the same serialized R6 owner thread as the
// guard, capture cycle and input controller. The guard is revoked first so a
// terminal event can never emit held-input cleanup into another generation;
// capture cancellation then reuses the existing map/frame owners.
//
// This retires the supplied capture cycle only. If that cycle is owned by a
// WindowsDxgiDuplicationOwner, its caller must still close that outer owner to
// release the parent duplication/device/output resources child-before-parent.
[[nodiscard]] WindowsCaptureSessionChangeResult
retireWindowsNativeConsumersOnSessionChange(
    WindowsCaptureSessionGenerationGuard &guard,
    WindowsDxgiCaptureCycle &captureCycle,
    WindowsInputController &inputController,
    std::uint32_t sessionId) noexcept;

#ifdef _WIN32
// Production read-only WTS observer. It checks the calling process's actual
// session and the selected target's WTS connection state. It does NOT query
// credentials, obtain a user token or prove that a locked desktop is usable.
[[nodiscard]] WindowsCaptureSessionReadCallbacks
windowsCaptureSessionReadCallbacks() noexcept;
#endif

} // namespace rdp_server::windows
