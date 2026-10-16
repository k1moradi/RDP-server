// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows_input_controller.h"

#include <algorithm>
#include <array>
#include <limits>
#include <type_traits>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace rdp_server::windows
{
namespace
{
constexpr std::uint32_t kNormalizedPointerMaximum = 65535U;

[[nodiscard]] bool validLayout(const WindowsDesktopLayout &layout) noexcept
{
    return layout.monitorCount != 0 &&
           layout.monitorCount <= kMaximumWindowsDesktopMonitors &&
           layout.virtualBounds.widthPixels != 0 &&
           layout.virtualBounds.heightPixels != 0;
}

[[nodiscard]] std::uint16_t normalizeAxis(std::uint32_t coordinate,
                                          std::uint32_t extent) noexcept
{
    if (extent <= 1U)
    {
        return 0;
    }
    const std::uint64_t denominator = static_cast<std::uint64_t>(extent - 1U);
    const std::uint64_t numerator =
        static_cast<std::uint64_t>(coordinate) * kNormalizedPointerMaximum +
        denominator / 2U;
    return static_cast<std::uint16_t>(numerator / denominator);
}
} // namespace

WindowsInputController::WindowsInputController(
    WindowsDesktopLayout layout, WindowsInputCallbacks callbacks,
    WindowsCaptureGenerationReader generationReader,
    WindowsCaptureGeneration pinnedGeneration) noexcept
    : layout_(layout), callbacks_(callbacks), generationReader_(generationReader),
      pinnedGeneration_(pinnedGeneration),
      closed_(callbacks_.context == nullptr || callbacks_.send == nullptr ||
              generationReader_.context == nullptr ||
              generationReader_.read == nullptr || pinnedGeneration_.session == 0 ||
              pinnedGeneration_.device == 0)
{
    WindowsDesktopLayout validated{};
    if (!closed_ &&
        (!validLayout(layout_) ||
         !makeWindowsDesktopLayout(
             std::span<const PortableRectangle>{layout_.monitors.data(),
                                                 layout_.monitorCount},
             validated) ||
         validated != layout_))
    {
        closed_ = true;
    }
}

WindowsInputController::~WindowsInputController() noexcept
{
    cancel();
}

std::size_t WindowsInputController::keySlot(std::uint16_t scanCode,
                                            bool extended) noexcept
{
    return static_cast<std::size_t>(scanCode) +
           (extended ? 256U : 0U);
}

std::size_t WindowsInputController::buttonSlot(WindowsPointerButton button) noexcept
{
    return static_cast<std::size_t>(button);
}

bool WindowsInputController::generationUnchanged() noexcept
{
    if (closed_ || generationReadInProgress_)
    {
        return false;
    }
    WindowsCaptureGeneration current{};
    generationReadInProgress_ = true;
    const bool observed =
        generationReader_.read(generationReader_.context, current);
    generationReadInProgress_ = false;
    if (!observed || current != pinnedGeneration_ ||
        current.session == 0 || current.device == 0)
    {
        // Never inject cleanup into a different/revoked desktop generation.
        invalidateWithoutNativeInput();
        return false;
    }
    return true;
}

bool WindowsInputController::normalizePosition(WindowsDesktopPoint position,
                                               std::uint16_t &x,
                                               std::uint16_t &y) const noexcept
{
    if (!desktopToNativePoint(layout_, position).has_value() ||
        position.x >= layout_.virtualBounds.widthPixels ||
        position.y >= layout_.virtualBounds.heightPixels)
    {
        return false;
    }
    x = normalizeAxis(position.x, layout_.virtualBounds.widthPixels);
    y = normalizeAxis(position.y, layout_.virtualBounds.heightPixels);
    return true;
}

bool WindowsInputController::sendCommands(
    std::span<const WindowsNativeInputCommand> commands) noexcept
{
    if (commands.empty())
    {
        return true;
    }
    operationInProgress_ = true;
    const std::size_t inserted = callbacks_.send(callbacks_.context, commands);
    operationInProgress_ = false;
    return inserted == commands.size();
}

bool WindowsInputController::handle(const WindowsInputEvent &event) noexcept
{
    if (closed_ || generationReadInProgress_ || operationInProgress_ ||
        cancellationRequested_ || !generationUnchanged())
    {
        return false;
    }
    if (cancellationRequested_)
    {
        finishDeferredCancellation();
        return false;
    }

    const bool handled = std::visit(
        [this](const auto &input) noexcept -> bool {
            using Input = std::decay_t<decltype(input)>;
            if constexpr (std::is_same_v<Input, WindowsKeyInput>)
            {
                return handleKey(input);
            }
            else if constexpr (std::is_same_v<Input, WindowsPointerMoveInput>)
            {
                return handleMove(input);
            }
            else if constexpr (std::is_same_v<Input, WindowsPointerButtonInput>)
            {
                return handleButton(input);
            }
            else
            {
                static_assert(std::is_same_v<Input, WindowsScrollInput>);
                return handleScroll(input);
            }
        },
        event);

    if (!handled)
    {
        if (!closed_)
        {
            cancellationRequested_ = true;
        }
        finishDeferredCancellation();
        return false;
    }

    if (!closed_ && !generationUnchanged())
    {
        return false;
    }
    finishDeferredCancellation();
    return !closed_;
}

bool WindowsInputController::handleKey(const WindowsKeyInput &input) noexcept
{
    if (input.scanCode == 0 || input.scanCode > 0xffU)
    {
        return false;
    }
    const std::size_t slot = keySlot(input.scanCode, input.extended);
    if (pressedKeys_[slot] == input.pressed)
    {
        return true;
    }

    const WindowsNativeInputCommand command{
        input.pressed ? WindowsNativeInputKind::keyDown
                      : WindowsNativeInputKind::keyUp,
        input.scanCode, input.extended};
    if (!sendCommands(std::span{&command, 1U}))
    {
        return false;
    }
    pressedKeys_[slot] = input.pressed;
    return true;
}

bool WindowsInputController::handleMove(const WindowsPointerMoveInput &input) noexcept
{
    std::uint16_t x{};
    std::uint16_t y{};
    if (!normalizePosition(input.position, x, y))
    {
        return false;
    }
    const WindowsNativeInputCommand command{
        WindowsNativeInputKind::pointerMoveAbsolute, 0, false, x, y};
    return sendCommands(std::span{&command, 1U});
}

bool WindowsInputController::handleButton(const WindowsPointerButtonInput &input) noexcept
{
    const std::size_t slot = buttonSlot(input.button);
    if (slot >= pressedButtons_.size())
    {
        return false;
    }
    if (pressedButtons_[slot] == input.pressed)
    {
        return true;
    }
    std::uint16_t x{};
    std::uint16_t y{};
    if (!normalizePosition(input.position, x, y))
    {
        return false;
    }
    const std::array commands{
        WindowsNativeInputCommand{WindowsNativeInputKind::pointerMoveAbsolute,
                                  0, false, x, y},
        WindowsNativeInputCommand{
            input.pressed ? WindowsNativeInputKind::buttonDown
                          : WindowsNativeInputKind::buttonUp,
            0, false, 0, 0, input.button},
    };
    if (!sendCommands(commands))
    {
        return false;
    }
    pressedButtons_[slot] = input.pressed;
    return true;
}

bool WindowsInputController::handleScroll(const WindowsScrollInput &input) noexcept
{
    if (input.axis != WindowsScrollAxis::vertical &&
        input.axis != WindowsScrollAxis::horizontal)
    {
        return false;
    }
    if (input.delta == 0)
    {
        return true;
    }
    if (input.delta < -kMaximumWindowsInputWheelDelta ||
        input.delta > kMaximumWindowsInputWheelDelta)
    {
        return false;
    }
    std::uint16_t x{};
    std::uint16_t y{};
    if (!normalizePosition(input.position, x, y))
    {
        return false;
    }
    const std::array commands{
        WindowsNativeInputCommand{WindowsNativeInputKind::pointerMoveAbsolute,
                                  0, false, x, y},
        WindowsNativeInputCommand{
            input.axis == WindowsScrollAxis::vertical
                ? WindowsNativeInputKind::verticalWheel
                : WindowsNativeInputKind::horizontalWheel,
            0, false, 0, 0, WindowsPointerButton::left, input.delta},
    };
    return sendCommands(commands);
}

void WindowsInputController::releaseHeldInput() noexcept
{
    std::array<WindowsNativeInputCommand, kMaximumWindowsNativeInputBatch> commands{};
    std::size_t count = 0;
    for (std::size_t slot = 0; slot < pressedKeys_.size(); ++slot)
    {
        if (!pressedKeys_[slot])
        {
            continue;
        }
        const bool extended = slot >= 256U;
        const auto scanCode = static_cast<std::uint16_t>(slot % 256U);
        commands[count++] = {WindowsNativeInputKind::keyUp, scanCode, extended};
    }
    for (std::size_t slot = 0; slot < pressedButtons_.size(); ++slot)
    {
        if (!pressedButtons_[slot])
        {
            continue;
        }
        commands[count++] = {
            WindowsNativeInputKind::buttonUp, 0, false, 0, 0,
            static_cast<WindowsPointerButton>(slot)};
    }

    pressedKeys_.fill(false);
    pressedButtons_.fill(false);
    if (count != 0)
    {
        (void)sendCommands(std::span{commands.data(), count});
    }
}

void WindowsInputController::invalidateWithoutNativeInput() noexcept
{
    closed_ = true;
    cancellationRequested_ = false;
    pressedKeys_.fill(false);
    pressedButtons_.fill(false);
}

void WindowsInputController::finishDeferredCancellation() noexcept
{
    if (!cancellationRequested_ || operationInProgress_)
    {
        return;
    }
    cancellationRequested_ = false;
    if (!closed_ && generationUnchanged())
    {
        releaseHeldInput();
    }
    closed_ = true;
    pressedKeys_.fill(false);
    pressedButtons_.fill(false);
}

void WindowsInputController::cancel() noexcept
{
    if (closed_)
    {
        return;
    }
    if (operationInProgress_ || generationReadInProgress_)
    {
        cancellationRequested_ = true;
        return;
    }
    if (generationUnchanged())
    {
        releaseHeldInput();
    }
    closed_ = true;
    cancellationRequested_ = false;
    pressedKeys_.fill(false);
    pressedButtons_.fill(false);
}

#ifdef _WIN32
namespace
{
[[nodiscard]] DWORD mouseButtonFlags(WindowsPointerButton button,
                                     bool pressed) noexcept
{
    switch (button)
    {
    case WindowsPointerButton::left:
        return pressed ? MOUSEEVENTF_LEFTDOWN : MOUSEEVENTF_LEFTUP;
    case WindowsPointerButton::right:
        return pressed ? MOUSEEVENTF_RIGHTDOWN : MOUSEEVENTF_RIGHTUP;
    case WindowsPointerButton::middle:
        return pressed ? MOUSEEVENTF_MIDDLEDOWN : MOUSEEVENTF_MIDDLEUP;
    case WindowsPointerButton::x1:
    case WindowsPointerButton::x2:
        return pressed ? MOUSEEVENTF_XDOWN : MOUSEEVENTF_XUP;
    }
    return 0;
}

std::size_t sendNativeInput(
    void *, std::span<const WindowsNativeInputCommand> commands) noexcept
{
    if (commands.empty() || commands.size() > kMaximumWindowsNativeInputBatch ||
        commands.size() > std::numeric_limits<UINT>::max())
    {
        return 0;
    }
    std::array<INPUT, kMaximumWindowsNativeInputBatch> native{};
    for (std::size_t index = 0; index < commands.size(); ++index)
    {
        const auto &command = commands[index];
        INPUT &input = native[index];
        switch (command.kind)
        {
        case WindowsNativeInputKind::keyDown:
        case WindowsNativeInputKind::keyUp:
            input.type = INPUT_KEYBOARD;
            input.ki.wVk = 0;
            input.ki.wScan = command.scanCode;
            input.ki.dwFlags = KEYEVENTF_SCANCODE |
                (command.extended ? KEYEVENTF_EXTENDEDKEY : 0U) |
                (command.kind == WindowsNativeInputKind::keyUp
                     ? KEYEVENTF_KEYUP : 0U);
            break;
        case WindowsNativeInputKind::pointerMoveAbsolute:
            input.type = INPUT_MOUSE;
            input.mi.dx = command.normalizedX;
            input.mi.dy = command.normalizedY;
            input.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE |
                               MOUSEEVENTF_VIRTUALDESK;
            break;
        case WindowsNativeInputKind::buttonDown:
        case WindowsNativeInputKind::buttonUp:
            input.type = INPUT_MOUSE;
            input.mi.dwFlags = mouseButtonFlags(
                command.button,
                command.kind == WindowsNativeInputKind::buttonDown);
            if (command.button == WindowsPointerButton::x1 ||
                command.button == WindowsPointerButton::x2)
            {
                input.mi.mouseData = command.button == WindowsPointerButton::x1
                                         ? XBUTTON1 : XBUTTON2;
            }
            break;
        case WindowsNativeInputKind::verticalWheel:
        case WindowsNativeInputKind::horizontalWheel:
            input.type = INPUT_MOUSE;
            input.mi.mouseData = static_cast<DWORD>(command.wheelDelta);
            input.mi.dwFlags = command.kind == WindowsNativeInputKind::verticalWheel
                                   ? MOUSEEVENTF_WHEEL : MOUSEEVENTF_HWHEEL;
            break;
        }
    }
    const UINT requested = static_cast<UINT>(commands.size());
    return static_cast<std::size_t>(
        ::SendInput(requested, native.data(), static_cast<int>(sizeof(INPUT))));
}
[[maybe_unused]] WindowsInputCallbacks dormantWindowsSendInputCallbacks() noexcept
{
    static int callbackContext{};
    return {&callbackContext, &sendNativeInput};
}
} // namespace
#endif

} // namespace rdp_server::windows
