// SPDX-License-Identifier: GPL-3.0-or-later

#include "x11/x11_input_controller.h"

#include <cassert>
#include <cstring>

#include <xcb/xcb.h>

int
main()
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

    return 0;
}
