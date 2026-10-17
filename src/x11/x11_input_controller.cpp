// SPDX-License-Identifier: GPL-3.0-or-later

#include "x11_input_controller.h"

#include <algorithm>
#include <cstdlib>
#include <limits>
#include <type_traits>

#include <xcb/xtest.h>

namespace
{

constexpr std::size_t kLockCaps = 0;
constexpr std::size_t kLockNum = 1;
constexpr std::size_t kLockScroll = 2;
constexpr std::uint8_t kMaximumButton = 9;
constexpr std::int64_t kScrollUnitsPerClick = 120;
constexpr std::int64_t kMaximumScrollBurst = 16;

// Core X11 keysyms; keeping the numeric protocol values here avoids a
// libX11 dependency for an otherwise XCB-only adapter.
constexpr xcb_keysym_t kCapsLockKeySymbol = 0x0000ffe5U;
constexpr xcb_keysym_t kNumLockKeySymbol = 0x0000ff7fU;
constexpr xcb_keysym_t kScrollLockKeySymbol = 0x0000ff14U;

} // namespace

X11InputController::X11InputController(xcb_connection_t &connection,
                                       xcb_window_t rootWindow,
                                       PixelSize bounds) noexcept
    : connection_(&connection), rootWindow_(rootWindow), bounds_(bounds)
{
    if (xcb_connection_has_error(connection_) != 0)
    {
        connection_ = nullptr;
        fail("X11 connection is already failed");
        return;
    }
    if (rootWindow_ == XCB_WINDOW_NONE || bounds_.widthPixels == 0 ||
        bounds_.heightPixels == 0)
    {
        fail("XTEST input geometry is invalid");
        return;
    }

    const xcb_query_extension_reply_t *extension =
        xcb_get_extension_data(connection_, &xcb_test_id);
    if (extension == nullptr || !extension->present)
    {
        fail("XTEST extension is unavailable");
        return;
    }

    const auto versionCookie = xcb_test_get_version(
        connection_, XCB_TEST_MAJOR_VERSION, XCB_TEST_MINOR_VERSION);
    xcb_generic_error_t *versionError = nullptr;
    xcb_test_get_version_reply_t *version =
        xcb_test_get_version_reply(connection_, versionCookie, &versionError);
    if (versionError != nullptr || version == nullptr)
    {
        std::free(versionError);
        std::free(version);
        fail("XTEST version negotiation failed");
        return;
    }
    std::free(version);

    const xcb_setup_t *setup = xcb_get_setup(connection_);
    if (setup == nullptr || setup->max_keycode < setup->min_keycode)
    {
        fail("X11 keyboard setup is invalid");
        return;
    }

    const unsigned int keycodeCount =
        static_cast<unsigned int>(setup->max_keycode) -
        static_cast<unsigned int>(setup->min_keycode) + 1U;
    if (keycodeCount > std::numeric_limits<std::uint8_t>::max())
    {
        fail("X11 keyboard mapping range is too large");
        return;
    }
    const auto keyboardCookie = xcb_get_keyboard_mapping(
        connection_, setup->min_keycode,
        static_cast<std::uint8_t>(keycodeCount));
    xcb_generic_error_t *keyboardError = nullptr;
    xcb_get_keyboard_mapping_reply_t *keyboard =
        xcb_get_keyboard_mapping_reply(connection_, keyboardCookie,
                                       &keyboardError);
    if (keyboardError != nullptr || keyboard == nullptr ||
        keyboard->keysyms_per_keycode == 0)
    {
        std::free(keyboardError);
        std::free(keyboard);
        fail("X11 keyboard mapping query failed");
        return;
    }

    const int symbolCount = xcb_get_keyboard_mapping_keysyms_length(keyboard);
    const xcb_keysym_t *symbols = xcb_get_keyboard_mapping_keysyms(keyboard);
    if (symbolCount <= 0 || symbols == nullptr)
    {
        std::free(keyboard);
        std::free(keyboardError);
        fail("X11 keyboard mapping reply is empty");
        return;
    }

    bool haveKeyMapping = false;
    try
    {
        keyMappings_.reserve(static_cast<std::size_t>(symbolCount));
        for (xcb_keycode_t keycode = setup->min_keycode;
             keycode <= setup->max_keycode; ++keycode)
        {
            const int keycodeOffset = keycode - setup->min_keycode;
            for (std::uint8_t level = 0; level < keyboard->keysyms_per_keycode;
                 ++level)
            {
                const int symbolIndex =
                    keycodeOffset * keyboard->keysyms_per_keycode + level;
                if (symbolIndex >= symbolCount)
                {
                    continue;
                }
                const xcb_keysym_t keysym = symbols[symbolIndex];
                if (keysym == XCB_NO_SYMBOL)
                {
                    continue;
                }
                haveKeyMapping = true;
                if (keysym <= 0xffU)
                {
                    xcb_keycode_t &direct =
                        latin1Keycodes_[static_cast<std::size_t>(keysym)];
                    if (direct == XCB_NO_SYMBOL)
                    {
                        direct = keycode;
                    }
                    hasDirectKeycodes_ = true;
                }
                else if ((keysym & 0xffffff00U) == 0xff00U)
                {
                    xcb_keycode_t &direct = functionKeycodes_[
                        static_cast<std::size_t>(keysym & 0xffU)];
                    if (direct == XCB_NO_SYMBOL)
                    {
                        direct = keycode;
                    }
                    hasDirectKeycodes_ = true;
                }
                else
                {
                    keyMappings_.push_back({keysym, keycode});
                }
            }
            if (keycode == setup->max_keycode)
            {
                break;
            }
        }
    }
    catch (...)
    {
        std::free(keyboard);
        std::free(keyboardError);
        fail("X11 keyboard mapping allocation failed");
        return;
    }
    std::free(keyboard);
    std::free(keyboardError);

    lockKeycodes_[kLockCaps] = keycodeFor(kCapsLockKeySymbol);
    lockKeycodes_[kLockNum] = keycodeFor(kNumLockKeySymbol);
    lockKeycodes_[kLockScroll] = keycodeFor(kScrollLockKeySymbol);

    const auto modifierCookie = xcb_get_modifier_mapping(connection_);
    xcb_generic_error_t *modifierError = nullptr;
    xcb_get_modifier_mapping_reply_t *modifierMapping =
        xcb_get_modifier_mapping_reply(connection_, modifierCookie,
                                       &modifierError);
    if (modifierError == nullptr && modifierMapping != nullptr)
    {
        const xcb_keycode_t *modifierKeycodes =
            xcb_get_modifier_mapping_keycodes(modifierMapping);
        if (modifierMapping->keycodes_per_modifier == 0 ||
            modifierKeycodes != nullptr)
        {
            for (std::size_t modifier = 0; modifier < 8; ++modifier)
            {
                for (std::size_t index = 0;
                     index < modifierMapping->keycodes_per_modifier; ++index)
                {
                    const xcb_keycode_t keycode =
                        modifierKeycodes[modifier *
                                         modifierMapping->keycodes_per_modifier +
                                         index];
                    for (std::size_t lock = 0; lock < lockKeycodes_.size(); ++lock)
                    {
                        if (keycode != XCB_NO_SYMBOL &&
                            keycode == lockKeycodes_[lock])
                        {
                            lockMasks_[lock] |= static_cast<std::uint16_t>(
                                1U << modifier);
                        }
                    }
                }
            }
        }
    }
    std::free(modifierError);
    std::free(modifierMapping);

    if (!haveKeyMapping || xcb_connection_has_error(connection_) != 0 ||
        xcb_flush(connection_) <= 0)
    {
        fail("X11 keyboard input setup failed");
        return;
    }

    failureReason_ = nullptr;
}

X11InputController::~X11InputController() noexcept
{
    disconnect();
}

bool
X11InputController::valid() const noexcept
{
    return failureReason_ == nullptr && connection_ != nullptr &&
           rootWindow_ != XCB_WINDOW_NONE &&
           xcb_connection_has_error(connection_) == 0;
}

const char *
X11InputController::failureReason() const noexcept
{
    return failureReason_;
}

bool
X11InputController::handle(const X11InputEvent &event) noexcept
{
    if (!valid())
    {
        return false;
    }

    return std::visit(
        [this](const auto &input) noexcept -> bool {
            using Input = std::decay_t<decltype(input)>;
            if constexpr (std::is_same_v<Input, X11KeyInput>)
            {
                return handleKey(input);
            }
            else if constexpr (std::is_same_v<Input, X11LockStateInput>)
            {
                return synchronizeLocks(input);
            }
            else if constexpr (std::is_same_v<Input, X11PointerMoveInput>)
            {
                return fakePointer(input.x, input.y);
            }
            else if constexpr (std::is_same_v<Input, X11PointerButtonInput>)
            {
                return handlePointerButton(input);
            }
            else
            {
                static_assert(std::is_same_v<Input, X11ScrollInput>);
                return handleScroll(input);
            }
        },
        event);
}

void
X11InputController::disconnect() noexcept
{
    releaseAll();
    retireState(failureReason_ == nullptr
                    ? "XTEST input controller is disconnected"
                    : failureReason_);
}

void
X11InputController::retireWithoutNativeInput() noexcept
{
    retireState(failureReason_ == nullptr
                    ? "XTEST input controller retired after authorization loss"
                    : failureReason_);
}

void
X11InputController::retireState(const char *reason) noexcept
{
    connection_ = nullptr;
    rootWindow_ = XCB_WINDOW_NONE;
    bounds_ = {};
    keyMappings_.clear();
    latin1Keycodes_.fill(XCB_NO_SYMBOL);
    functionKeycodes_.fill(XCB_NO_SYMBOL);
    hasDirectKeycodes_ = false;
    activeKeycodes_.fill(XCB_NO_SYMBOL);
    pressedButtons_.fill(false);
    lockKeycodes_.fill(XCB_NO_SYMBOL);
    lockMasks_.fill(0);
    verticalScrollRemainder_ = 0;
    horizontalScrollRemainder_ = 0;
    failureReason_ = reason;
}

void
X11InputController::fail(const char *reason) noexcept
{
    failureReason_ = reason;
}

void
X11InputController::releaseAll() noexcept
{
    verticalScrollRemainder_ = 0;
    horizontalScrollRemainder_ = 0;
    if (connection_ == nullptr || rootWindow_ == XCB_WINDOW_NONE ||
        xcb_connection_has_error(connection_) != 0)
    {
        activeKeycodes_.fill(XCB_NO_SYMBOL);
        pressedButtons_.fill(false);
        return;
    }

    bool sent = false;
    for (xcb_keycode_t &keycode : activeKeycodes_)
    {
        if (keycode == XCB_NO_SYMBOL)
        {
            continue;
        }
        xcb_test_fake_input(connection_, XCB_KEY_RELEASE, keycode,
                            XCB_CURRENT_TIME, rootWindow_, 0, 0, 0);
        keycode = XCB_NO_SYMBOL;
        sent = true;
    }

    for (std::uint8_t button = 1; button <= kMaximumButton; ++button)
    {
        if (!pressedButtons_[static_cast<std::size_t>(button)])
        {
            continue;
        }
        xcb_test_fake_input(connection_, XCB_BUTTON_RELEASE, button,
                            XCB_CURRENT_TIME, rootWindow_, 0, 0, 0);
        pressedButtons_[static_cast<std::size_t>(button)] = false;
        sent = true;
    }

    if (sent && xcb_flush(connection_) <= 0)
    {
        fail("XTEST input release failed");
    }
}

xcb_keycode_t
X11InputController::keycodeFor(xcb_keysym_t keysym) const noexcept
{
    if (hasDirectKeycodes_)
    {
        if (keysym <= 0xffU)
        {
            return latin1Keycodes_[static_cast<std::size_t>(keysym)];
        }
        if ((keysym & 0xffffff00U) == 0xff00U)
        {
            return functionKeycodes_[
                static_cast<std::size_t>(keysym & 0xffU)];
        }
    }

    for (const KeyMapping &mapping : keyMappings_)
    {
        if (mapping.keysym == keysym)
        {
            return mapping.keycode;
        }
    }
    return XCB_NO_SYMBOL;
}

bool
X11InputController::handleKey(const X11KeyInput &input) noexcept
{
    const std::size_t slot = keySlot(input.scanCode, input.extended);
    xcb_keycode_t keycode = activeKeycodes_[slot];
    if (input.pressed)
    {
        // RDP clients may send repeated make events while a key is held.
        // XTest makes the key logically down on the first event; forwarding
        // every duplicate can synthesize extra KeyPress events in addition
        // to the X server's own autorepeat stream.
        if (keycode != XCB_NO_SYMBOL)
        {
            return true;
        }
        keycode = keycodeFor(static_cast<xcb_keysym_t>(input.keySymbol));
    }
    else if (keycode == XCB_NO_SYMBOL)
    {
        // Ignore an unmatched break instead of failing the whole RDP input
        // event. There is no X11 state transition to perform.
        return true;
    }
    if (keycode == XCB_NO_SYMBOL)
    {
        return false;
    }

    if (!fakeKey(keycode, input.pressed))
    {
        return false;
    }
    activeKeycodes_[slot] = input.pressed ? keycode : XCB_NO_SYMBOL;
    return true;
}

bool
X11InputController::synchronizeLocks(const X11LockStateInput &input) noexcept
{
    const auto pointerCookie = xcb_query_pointer(connection_, rootWindow_);
    xcb_generic_error_t *pointerError = nullptr;
    xcb_query_pointer_reply_t *pointer =
        xcb_query_pointer_reply(connection_, pointerCookie, &pointerError);
    if (pointerError != nullptr || pointer == nullptr)
    {
        std::free(pointerError);
        std::free(pointer);
        fail("X11 lock-state query failed");
        return false;
    }

    std::uint16_t state = pointer->mask;
    std::free(pointer);
    std::free(pointerError);

    const std::array<bool, 3> desired{
        input.capsLock,
        input.numLock,
        input.scrollLock,
    };
    for (std::size_t lock = 0; lock < desired.size(); ++lock)
    {
        if (lockKeycodes_[lock] == XCB_NO_SYMBOL || lockMasks_[lock] == 0)
        {
            continue;
        }
        const bool current = (state & lockMasks_[lock]) != 0;
        if (current == desired[lock])
        {
            continue;
        }
        if (!fakeKey(lockKeycodes_[lock], true) ||
            !fakeKey(lockKeycodes_[lock], false))
        {
            return false;
        }
        state ^= lockMasks_[lock];
    }
    return true;
}

bool
X11InputController::handlePointerButton(
    const X11PointerButtonInput &input) noexcept
{
    if (input.button == 0 || input.button > kMaximumButton)
    {
        return false;
    }
    const std::uint8_t type = input.pressed ? XCB_BUTTON_PRESS
                                            : XCB_BUTTON_RELEASE;
    if (!fakeButton(type, input.button, input.x, input.y))
    {
        return false;
    }
    pressedButtons_[static_cast<std::size_t>(input.button)] = input.pressed;
    return true;
}

bool
X11InputController::handleScroll(const X11ScrollInput &input) noexcept
{
    switch (input.axis)
    {
        case X11ScrollAxis::Vertical:
            return emitScrollClicks(input.x, input.y, input.delta,
                                    verticalScrollRemainder_,
                                    /*positiveButton=*/4,
                                    /*negativeButton=*/5);
        case X11ScrollAxis::Horizontal:
            return emitScrollClicks(input.x, input.y, input.delta,
                                    horizontalScrollRemainder_,
                                    /*positiveButton=*/7,
                                    /*negativeButton=*/6);
        default:
            return false;
    }
}

bool
X11InputController::emitScrollClicks(std::int32_t x, std::int32_t y,
                                      std::int32_t delta,
                                      std::int64_t &accumulator,
                                      std::uint8_t positiveButton,
                                      std::uint8_t negativeButton) noexcept
{
    const std::int64_t boundedDelta = std::clamp<std::int64_t>(
        static_cast<std::int64_t>(delta),
        -kMaximumScrollBurst * kScrollUnitsPerClick,
        kMaximumScrollBurst * kScrollUnitsPerClick);
    accumulator = std::clamp(
        accumulator + boundedDelta, -kMaximumScrollBurst * kScrollUnitsPerClick,
        kMaximumScrollBurst * kScrollUnitsPerClick);

    bool emitted = false;
    while (accumulator >= kScrollUnitsPerClick)
    {
        if (!fakeButton(XCB_BUTTON_PRESS, positiveButton, x, y, false) ||
            !fakeButton(XCB_BUTTON_RELEASE, positiveButton, x, y, false))
        {
            (void)flushInput();
            return false;
        }
        accumulator -= kScrollUnitsPerClick;
        emitted = true;
    }
    while (accumulator <= -kScrollUnitsPerClick)
    {
        if (!fakeButton(XCB_BUTTON_PRESS, negativeButton, x, y, false) ||
            !fakeButton(XCB_BUTTON_RELEASE, negativeButton, x, y, false))
        {
            (void)flushInput();
            return false;
        }
        accumulator += kScrollUnitsPerClick;
        emitted = true;
    }
    return !emitted || flushInput();
}

bool
X11InputController::fakeKey(xcb_keycode_t keycode, bool pressed) noexcept
{
    return fakeInput(pressed ? XCB_KEY_PRESS : XCB_KEY_RELEASE, keycode, 0, 0);
}

bool
X11InputController::fakePointer(std::int32_t x, std::int32_t y) noexcept
{
    return fakeInput(XCB_MOTION_NOTIFY, 0, coordinate(x, bounds_.widthPixels),
                     coordinate(y, bounds_.heightPixels));
}

bool
X11InputController::fakeButton(std::uint8_t type, std::uint8_t button,
                               std::int32_t x, std::int32_t y,
                               bool flush) noexcept
{
    if (button == 0 || button > kMaximumButton)
    {
        return false;
    }
    return fakeInput(type, button, coordinate(x, bounds_.widthPixels),
                     coordinate(y, bounds_.heightPixels), flush);
}

bool
X11InputController::fakeInput(std::uint8_t type, std::uint8_t detail,
                              std::int16_t x, std::int16_t y,
                              bool flush) noexcept
{
    if (!valid())
    {
        return false;
    }
    xcb_test_fake_input(connection_, type, detail, XCB_CURRENT_TIME,
                        rootWindow_, x, y, 0);
    if (xcb_connection_has_error(connection_) != 0)
    {
        fail("XTEST input request failed");
        return false;
    }
    return !flush || flushInput();
}

bool
X11InputController::flushInput() noexcept
{
    if (!valid() || xcb_flush(connection_) <= 0)
    {
        fail("XTEST input flush failed");
        return false;
    }
    return true;
}

std::int16_t
X11InputController::coordinate(std::int32_t value,
                               std::uint32_t bound) const noexcept
{
    if (value <= 0 || bound == 0)
    {
        return 0;
    }
    const std::uint32_t maximum = std::min<std::uint32_t>(
        bound - 1U,
        static_cast<std::uint32_t>(std::numeric_limits<std::int16_t>::max()));
    const auto clipped = std::min(static_cast<std::uint32_t>(value), maximum);
    return static_cast<std::int16_t>(clipped);
}

std::size_t
X11InputController::keySlot(std::uint8_t scanCode, bool extended) const noexcept
{
    const std::size_t extendedOffset = extended ? 256U : 0U;
    return extendedOffset + static_cast<std::size_t>(scanCode);
}
