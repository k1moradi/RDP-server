// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "windows_desktop_geometry.h"
#include "windows_dxgi_capture_cycle.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <variant>

namespace rdp_server::windows
{

class WindowsNativeDesktopOwner;

inline constexpr std::int32_t kMaximumWindowsInputWheelDelta = 16 * 120;
inline constexpr std::size_t kMaximumWindowsNativeInputBatch = 517;

enum class WindowsPointerButton : std::uint8_t
{
    left,
    right,
    middle,
    x1,
    x2,
};

enum class WindowsScrollAxis : std::uint8_t
{
    vertical,
    horizontal,
};

struct WindowsKeyInput final
{
    std::uint16_t scanCode{};
    bool extended{};
    bool pressed{};
};

struct WindowsPointerMoveInput final
{
    WindowsDesktopPoint position{};
};

struct WindowsPointerButtonInput final
{
    WindowsDesktopPoint position{};
    WindowsPointerButton button{WindowsPointerButton::left};
    bool pressed{};
};

struct WindowsScrollInput final
{
    WindowsDesktopPoint position{};
    std::int32_t delta{};
    WindowsScrollAxis axis{WindowsScrollAxis::vertical};
};

using WindowsInputEvent = std::variant<WindowsKeyInput, WindowsPointerMoveInput,
                                      WindowsPointerButtonInput,
                                      WindowsScrollInput>;

enum class WindowsNativeInputKind : std::uint8_t
{
    keyDown,
    keyUp,
    pointerMoveAbsolute,
    buttonDown,
    buttonUp,
    verticalWheel,
    horizontalWheel,
};

// Platform-neutral representation of one SendInput element. Absolute pointer
// coordinates are already normalized to the Win32 0..65535 virtual-desktop
// range. These commands grant no access and are never exposed to RDP parsing.
struct WindowsNativeInputCommand final
{
    WindowsNativeInputKind kind{WindowsNativeInputKind::pointerMoveAbsolute};
    std::uint16_t scanCode{};
    bool extended{};
    std::uint16_t normalizedX{};
    std::uint16_t normalizedY{};
    WindowsPointerButton button{WindowsPointerButton::left};
    std::int32_t wheelDelta{};
};

struct WindowsInputCallbacks final
{
    void *context{};
    // Return the number of leading commands inserted into the native input
    // stream. Production maps this directly to SendInput's return value.
    std::size_t (*send)(void *, std::span<const WindowsNativeInputCommand>) noexcept{};
};

// Single-thread-affine native input state owner. This is NOT authorization.
// R2/R3 must authenticate and authorize the Windows desktop before creating
// or invoking this object. The generation reader is revocation-only and can
// never turn an untrusted caller into an authorized one. The runtime does not
// construct this controller until that genuine Windows admission path exists.
class WindowsInputController final
{
public:
    WindowsInputController(WindowsDesktopLayout layout,
                           WindowsInputCallbacks callbacks,
                           WindowsCaptureGenerationReader generationReader,
                           WindowsCaptureGeneration pinnedGeneration) noexcept;
    ~WindowsInputController() noexcept;

    WindowsInputController(const WindowsInputController &) = delete;
    WindowsInputController &operator=(const WindowsInputController &) = delete;
    WindowsInputController(WindowsInputController &&) = delete;
    WindowsInputController &operator=(WindowsInputController &&) = delete;

    [[nodiscard]] bool handle(const WindowsInputEvent &event) noexcept;

    // Terminal retirement for upstream R2 admission revocation or R3
    // Share/input-authority loss. Held state is discarded without invoking
    // the native callback, even when retirement is requested reentrantly from
    // an in-flight callback. An already accepted native event cannot be
    // retracted, but no cleanup/release event may be posted afterward.
    void retireWithoutNativeInput() noexcept;

    // Best-effort release of keys/buttons only while both upstream input
    // authority and the pinned native generation remain current, then
    // terminally invalidate this controller. Authority loss must use
    // retireWithoutNativeInput().
    void cancel() noexcept;

    [[nodiscard]] bool closed() const noexcept { return closed_; }

private:
    friend class WindowsNativeDesktopOwner;

#ifdef _WIN32
    // Real SendInput is a private capability of the one R6 aggregate owner.
    // Native evidence/generation values alone cannot obtain this callback.
    [[nodiscard]] static WindowsInputCallbacks windowsNativeCallbacks() noexcept;
#endif

    static constexpr std::size_t kScanCodeSlots = 512;
    static constexpr std::size_t kButtonCount = 5;
    static_assert(kScanCodeSlots + kButtonCount ==
                  kMaximumWindowsNativeInputBatch);

    [[nodiscard]] bool generationUnchanged() noexcept;
    [[nodiscard]] bool normalizePosition(WindowsDesktopPoint position,
                                         std::uint16_t &x,
                                         std::uint16_t &y) const noexcept;
    [[nodiscard]] bool sendCommands(
        std::span<const WindowsNativeInputCommand> commands) noexcept;
    [[nodiscard]] bool handleKey(const WindowsKeyInput &input) noexcept;
    [[nodiscard]] bool handleMove(const WindowsPointerMoveInput &input) noexcept;
    [[nodiscard]] bool handleButton(const WindowsPointerButtonInput &input) noexcept;
    [[nodiscard]] bool handleScroll(const WindowsScrollInput &input) noexcept;
    void releaseHeldInput() noexcept;
    void finishDeferredCancellation() noexcept;
    void invalidateWithoutNativeInput() noexcept;

    [[nodiscard]] static std::size_t keySlot(std::uint16_t scanCode,
                                             bool extended) noexcept;
    [[nodiscard]] static std::size_t buttonSlot(WindowsPointerButton button) noexcept;

    WindowsDesktopLayout layout_{};
    WindowsInputCallbacks callbacks_{};
    WindowsCaptureGenerationReader generationReader_{};
    WindowsCaptureGeneration pinnedGeneration_{};
    std::array<bool, kScanCodeSlots> pressedKeys_{};
    std::array<bool, kButtonCount> pressedButtons_{};
    bool generationReadInProgress_{};
    bool operationInProgress_{};
    bool cancellationRequested_{};
    bool retirementWithoutNativeInputRequested_{};
    bool closed_{};
};

// The Win32 SendInput translation is deliberately NOT public. Only the one
// WindowsNativeDesktopOwner can obtain it after fresh R2 authorization; R3
// input authority remains an additional upstream per-event gate. Generation
// numbers alone are revocation facts.

} // namespace rdp_server::windows
