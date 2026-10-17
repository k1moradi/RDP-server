// SPDX-License-Identifier: GPL-3.0-or-later

#include "x11/x11_input_controller.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string_view>

#include <xcb/xcb.h>

namespace
{

struct XcbConnectionDeleter
{
    void operator()(xcb_connection_t *connection) const noexcept
    {
        if (connection != nullptr)
        {
            xcb_disconnect(connection);
        }
    }
};

using XcbConnection = std::unique_ptr<xcb_connection_t, XcbConnectionDeleter>;

XcbConnection
connectDisplay(const char *display, int &screenNumber)
{
    XcbConnection connection(xcb_connect(display, &screenNumber));
    assert(connection != nullptr);
    assert(screenNumber >= 0);
    assert(xcb_connection_has_error(connection.get()) == 0);
    return connection;
}

xcb_screen_t *
screenFor(xcb_connection_t &connection, int screenNumber)
{
    const xcb_setup_t *setup = xcb_get_setup(&connection);
    assert(setup != nullptr);
    xcb_screen_iterator_t iterator = xcb_setup_roots_iterator(setup);
    for (int index = 0; index < screenNumber && iterator.rem > 0; ++index)
    {
        xcb_screen_next(&iterator);
    }
    assert(iterator.rem > 0 && iterator.data != nullptr);
    return iterator.data;
}

std::array<std::uint8_t, 32>
keymapSnapshot(xcb_connection_t &connection)
{
    xcb_generic_error_t *error = nullptr;
    const xcb_query_keymap_cookie_t cookie = xcb_query_keymap(&connection);
    xcb_query_keymap_reply_t *reply =
        xcb_query_keymap_reply(&connection, cookie, &error);
    assert(error == nullptr);
    assert(reply != nullptr);

    std::array<std::uint8_t, 32> keys{};
    std::memcpy(keys.data(), reply->keys, keys.size());
    std::free(error);
    std::free(reply);
    return keys;
}

std::uint16_t
pointerMask(xcb_connection_t &connection, xcb_window_t rootWindow)
{
    xcb_generic_error_t *error = nullptr;
    const xcb_query_pointer_cookie_t cookie =
        xcb_query_pointer(&connection, rootWindow);
    xcb_query_pointer_reply_t *reply =
        xcb_query_pointer_reply(&connection, cookie, &error);
    assert(error == nullptr);
    assert(reply != nullptr);
    assert(reply->same_screen != 0);

    const std::uint16_t mask = reply->mask;
    std::free(error);
    std::free(reply);
    return mask;
}

void
connectionDenialsAndCancellation()
{
    xcb_connection_t *connection = xcb_connect_to_fd(-1, nullptr);
    assert(connection != nullptr);
    assert(xcb_connection_has_error(connection) != 0);

    {
        X11InputController input(*connection, 1, {1920, 1080});
        assert(!input.valid());
        assert(input.failureReason() != nullptr);
        assert(std::strcmp(input.failureReason(),
                           "X11 connection is already failed") == 0);

        assert(!input.handle(X11KeyInput{0x61U, 0x1eU, false, true}));
        assert(!input.handle(X11LockStateInput{true, true, false}));
        assert(!input.handle(X11PointerMoveInput{100, 200}));
        assert(!input.handle(X11PointerButtonInput{100, 200, 1, true}));
        assert(!input.handle(
            X11ScrollInput{100, 200, 120, X11ScrollAxis::Vertical}));

        input.disconnect();
        assert(!input.valid());
        input.disconnect();
        assert(!input.valid());

        // The explicit cancellation barrier must clear the borrowed pointer
        // before the owning XCB connection is destroyed.
        xcb_disconnect(connection);
        connection = nullptr;

        assert(!input.handle(X11PointerMoveInput{1, 1}));
        input.disconnect();
    }
}

void
destructorHeldInputRelease()
{
    const char *display = std::getenv("DISPLAY");
    assert(display != nullptr && display[0] != '\0');

    int screenNumber = -1;
    XcbConnection connection = connectDisplay(display, screenNumber);
    xcb_screen_t *screen = screenFor(*connection, screenNumber);

    const std::array<std::uint8_t, 32> baselineKeys =
        keymapSnapshot(*connection);
    const std::uint16_t baselinePointerMask =
        pointerMask(*connection, screen->root);

    {
        X11InputController input(
            *connection, screen->root,
            {screen->width_in_pixels, screen->height_in_pixels});
        assert(input.valid());

        // Use only the ephemeral Xvfb server. The controller must remember
        // both held states so its destructor can release them before the
        // borrowed XCB owner is destroyed.
        assert(input.handle(X11KeyInput{
            /*keySymbol=*/0x61U,
            /*scanCode=*/0x1eU,
            /*extended=*/false,
            /*pressed=*/true}));
        assert(input.handle(X11PointerButtonInput{
            /*x=*/100,
            /*y=*/100,
            /*button=*/1,
            /*pressed=*/true}));

        assert(keymapSnapshot(*connection) != baselineKeys);
        assert((pointerMask(*connection, screen->root) &
                XCB_BUTTON_MASK_1) != 0);
    }

    assert(xcb_connection_has_error(connection.get()) == 0);
    assert(keymapSnapshot(*connection) == baselineKeys);
    assert((pointerMask(*connection, screen->root) &
            XCB_BUTTON_MASK_1) ==
           (baselinePointerMask & XCB_BUTTON_MASK_1));

    // Reuse the same owner to prove explicit cancellation has the same
    // release semantics and leaves the borrowed connection healthy.
    X11InputController replacement(
        *connection, screen->root,
        {screen->width_in_pixels, screen->height_in_pixels});
    assert(replacement.valid());
    assert(replacement.handle(X11PointerButtonInput{
        /*x=*/120,
        /*y=*/120,
        /*button=*/1,
        /*pressed=*/true}));
    assert((pointerMask(*connection, screen->root) &
            XCB_BUTTON_MASK_1) != 0);
    replacement.disconnect();
    assert((pointerMask(*connection, screen->root) &
            XCB_BUTTON_MASK_1) ==
           (baselinePointerMask & XCB_BUTTON_MASK_1));
    assert(xcb_connection_has_error(connection.get()) == 0);
}

void
authorityRetirementNoNativePost()
{
    const char *display = std::getenv("DISPLAY");
    assert(display != nullptr && display[0] != '\0');

    int screenNumber = -1;
    XcbConnection connection = connectDisplay(display, screenNumber);
    xcb_screen_t *screen = screenFor(*connection, screenNumber);

    const std::array<std::uint8_t, 32> baselineKeys =
        keymapSnapshot(*connection);
    const std::uint16_t baselinePointerMask =
        pointerMask(*connection, screen->root);

    X11InputController input(
        *connection, screen->root,
        {screen->width_in_pixels, screen->height_in_pixels});
    assert(input.valid());
    assert(input.handle(X11KeyInput{
        /*keySymbol=*/0x61U,
        /*scanCode=*/0x1eU,
        /*extended=*/false,
        /*pressed=*/true}));
    assert(input.handle(X11PointerButtonInput{
        /*x=*/140,
        /*y=*/140,
        /*button=*/1,
        /*pressed=*/true}));

    const std::array<std::uint8_t, 32> heldKeys =
        keymapSnapshot(*connection);
    const std::uint16_t heldPointerMask =
        pointerMask(*connection, screen->root);
    assert(heldKeys != baselineKeys);
    assert((heldPointerMask & XCB_BUTTON_MASK_1) != 0);
    assert((baselinePointerMask & XCB_BUTTON_MASK_1) == 0);

    // Once R2/R3 authority is gone, retirement may clear only local tracking.
    // Remaining held Xvfb state proves no cleanup XTEST release was posted.
    input.retireWithoutNativeInput();
    assert(!input.valid());
    assert(keymapSnapshot(*connection) == heldKeys);
    assert(pointerMask(*connection, screen->root) == heldPointerMask);

    // Repeated retirement and later generic disconnect stay no-post because the
    // native endpoint and held-state bookkeeping are already retired.
    input.retireWithoutNativeInput();
    input.disconnect();
    assert(keymapSnapshot(*connection) == heldKeys);
    assert(pointerMask(*connection, screen->root) == heldPointerMask);
    assert(xcb_connection_has_error(connection.get()) == 0);
}

} // namespace

int
main(int argc, char **argv)
{
    if (argc == 1)
    {
        connectionDenialsAndCancellation();
        return 0;
    }

    assert(argc == 2);
    const std::string_view behavior(argv[1]);
    if (behavior == "destructor-held-input-release")
    {
        destructorHeldInputRelease();
        return 0;
    }
    if (behavior == "authority-retirement-no-native-post")
    {
        authorityRetirementNoNativePost();
        return 0;
    }

    assert(false && "unknown XTEST input controller behavior");
    return 1;
}
