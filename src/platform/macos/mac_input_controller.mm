// SPDX-License-Identifier: GPL-3.0-or-later
#include "mac_input_controller.h"

#include <ApplicationServices/ApplicationServices.h>
#include <CoreGraphics/CoreGraphics.h>

#include <memory>
#include <type_traits>

namespace rdp::macos {
namespace {

struct CfReleaser final {
    template <typename T>
    void operator()(T* value) const noexcept {
        if (value != nullptr) {
            CFRelease(value);
        }
    }
};

using EventSourceOwner = std::unique_ptr<
    std::remove_pointer_t<CGEventSourceRef>, CfReleaser>;
using EventOwner =
    std::unique_ptr<std::remove_pointer_t<CGEventRef>, CfReleaser>;

[[nodiscard]] bool nativeMouseButton(
    const MacPointerButton button, CGMouseButton& native) noexcept {
    switch (button) {
    case MacPointerButton::Left:
        native = kCGMouseButtonLeft;
        return true;
    case MacPointerButton::Right:
        native = kCGMouseButtonRight;
        return true;
    case MacPointerButton::Middle:
        native = kCGMouseButtonCenter;
        return true;
    case MacPointerButton::X1:
        native = static_cast<CGMouseButton>(3);
        return true;
    case MacPointerButton::X2:
        native = static_cast<CGMouseButton>(4);
        return true;
    }
    return false;
}

[[nodiscard]] bool buttonEventType(
    const MacPointerButton button, const bool pressed,
    CGEventType& type) noexcept {
    switch (button) {
    case MacPointerButton::Left:
        type = pressed ? kCGEventLeftMouseDown : kCGEventLeftMouseUp;
        return true;
    case MacPointerButton::Right:
        type = pressed ? kCGEventRightMouseDown : kCGEventRightMouseUp;
        return true;
    case MacPointerButton::Middle:
    case MacPointerButton::X1:
    case MacPointerButton::X2:
        type = pressed ? kCGEventOtherMouseDown : kCGEventOtherMouseUp;
        return true;
    }
    return false;
}

[[nodiscard]] bool moveEventType(
    const MacNativeInputCommand& command, CGEventType& type,
    CGMouseButton& button) noexcept {
    if (!command.dragging) {
        type = kCGEventMouseMoved;
        button = kCGMouseButtonLeft;
        return true;
    }
    if (!nativeMouseButton(command.dragButton, button)) {
        return false;
    }
    switch (command.dragButton) {
    case MacPointerButton::Left:
        type = kCGEventLeftMouseDragged;
        return true;
    case MacPointerButton::Right:
        type = kCGEventRightMouseDragged;
        return true;
    case MacPointerButton::Middle:
    case MacPointerButton::X1:
    case MacPointerButton::X2:
        type = kCGEventOtherMouseDragged;
        return true;
    }
    return false;
}

[[nodiscard]] EventOwner makeEvent(
    CGEventSourceRef source,
    const MacNativeInputCommand& command) noexcept {
    switch (command.kind) {
    case MacNativeInputKind::KeyDown:
    case MacNativeInputKind::KeyUp:
        return EventOwner(CGEventCreateKeyboardEvent(
            source, static_cast<CGKeyCode>(command.virtualKeyCode),
            command.kind == MacNativeInputKind::KeyDown));
    case MacNativeInputKind::PointerMove: {
        CGEventType type{};
        CGMouseButton button{};
        if (!moveEventType(command, type, button)) {
            return {};
        }
        return EventOwner(CGEventCreateMouseEvent(
            source, type, CGPointMake(command.xPoints, command.yPoints),
            button));
    }
    case MacNativeInputKind::ButtonDown:
    case MacNativeInputKind::ButtonUp: {
        CGMouseButton button{};
        CGEventType type{};
        if (!nativeMouseButton(command.button, button) ||
            !buttonEventType(command.button,
                             command.kind == MacNativeInputKind::ButtonDown,
                             type)) {
            return {};
        }
        return EventOwner(CGEventCreateMouseEvent(
            source, type, CGPointMake(command.xPoints, command.yPoints),
            button));
    }
    case MacNativeInputKind::VerticalScroll:
    case MacNativeInputKind::HorizontalScroll: {
        const std::int32_t vertical =
            command.kind == MacNativeInputKind::VerticalScroll
                ? command.scrollSteps
                : 0;
        const std::int32_t horizontal =
            command.kind == MacNativeInputKind::HorizontalScroll
                ? command.scrollSteps
                : 0;
        EventOwner event(CGEventCreateScrollWheelEvent2(
            source, kCGScrollEventUnitLine, 2, vertical, horizontal, 0));
        if (event) {
            CGEventSetLocation(
                event.get(),
                CGPointMake(command.xPoints, command.yPoints));
        }
        return event;
    }
    }
    return {};
}

std::size_t postQuartzInput(
    void*, const std::span<const MacNativeInputCommand> commands) noexcept {
    if (commands.empty() ||
        queryNativeMacInputPermissionStatus() !=
            MacInputPermissionStatus::Trusted) {
        return 0;
    }
    EventSourceOwner source(
        CGEventSourceCreate(kCGEventSourceStateHIDSystemState));
    if (!source) {
        return 0;
    }
    for (std::size_t index = 0; index < commands.size(); ++index) {
        EventOwner event = makeEvent(source.get(), commands[index]);
        if (!event) {
            return index;
        }
        CGEventPost(kCGHIDEventTap, event.get());
    }
    return commands.size();
}

[[maybe_unused]] MacInputCallbacks dormantMacQuartzInputCallbacks() noexcept {
    static int callbackContext{};
    return {&callbackContext, &postQuartzInput};
}

} // namespace

MacInputPermissionStatus queryNativeMacInputPermissionStatus() noexcept {
    const bool accessibilityTrusted = AXIsProcessTrustedWithOptions(nullptr);
    const bool inputMonitoringTrusted = CGPreflightListenEventAccess();
    return accessibilityTrusted && inputMonitoringTrusted
        ? MacInputPermissionStatus::Trusted
        : MacInputPermissionStatus::NotTrusted;
}

MacInputCallbacks MacInputController::nativeCallbacksForAuthorizedOwner() noexcept {
    return dormantMacQuartzInputCallbacks();
}

} // namespace rdp::macos
