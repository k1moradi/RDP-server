// SPDX-License-Identifier: GPL-3.0-or-later

#include "../src/x11/x11_cursor_tracker.h"

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string_view>

#include <xcb/xcb.h>
#include <xcb/xfixes.h>

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

void
checkedRequest(xcb_connection_t &connection, xcb_void_cookie_t cookie)
{
    xcb_generic_error_t *error = xcb_request_check(&connection, cookie);
    assert(error == nullptr);
    std::free(error);
}

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

void
roundTrip(xcb_connection_t &connection)
{
    xcb_generic_error_t *error = nullptr;
    const xcb_get_input_focus_cookie_t cookie =
        xcb_get_input_focus(&connection);
    xcb_get_input_focus_reply_t *reply =
        xcb_get_input_focus_reply(&connection, cookie, &error);
    assert(error == nullptr);
    assert(reply != nullptr);
    std::free(error);
    std::free(reply);
}

bool
consumeCursorNotification(xcb_connection_t &connection,
                          std::uint8_t firstEvent,
                          xcb_window_t rootWindow)
{
    roundTrip(connection);

    bool found = false;
    while (xcb_generic_event_t *event = xcb_poll_for_event(&connection))
    {
        const std::uint8_t responseType =
            static_cast<std::uint8_t>(event->response_type & 0x7fU);
        if (responseType ==
            static_cast<std::uint8_t>(
                firstEvent + XCB_XFIXES_CURSOR_NOTIFY))
        {
            const auto &notification =
                reinterpret_cast<const xcb_xfixes_cursor_notify_event_t &>(
                    *event);
            if (notification.window == rootWindow &&
                notification.subtype ==
                    XCB_XFIXES_CURSOR_NOTIFY_DISPLAY_CURSOR)
            {
                found = true;
            }
        }
        std::free(event);
    }
    return found;
}

xcb_cursor_t
createCursor(xcb_connection_t &connection, xcb_window_t rootWindow,
             bool foregroundPixel)
{
    const xcb_pixmap_t sourcePixmap = xcb_generate_id(&connection);
    const xcb_pixmap_t maskPixmap = xcb_generate_id(&connection);
    const xcb_gcontext_t graphicsContext = xcb_generate_id(&connection);
    const xcb_cursor_t cursor = xcb_generate_id(&connection);
    assert(sourcePixmap != XCB_NONE);
    assert(maskPixmap != XCB_NONE);
    assert(graphicsContext != XCB_NONE);
    assert(cursor != XCB_NONE);

    checkedRequest(
        connection,
        xcb_create_pixmap_checked(
            &connection, 1, sourcePixmap, rootWindow, 1, 1));
    checkedRequest(
        connection,
        xcb_create_pixmap_checked(
            &connection, 1, maskPixmap, rootWindow, 1, 1));

    const std::uint32_t sourceForeground = foregroundPixel ? 1U : 0U;
    checkedRequest(
        connection,
        xcb_create_gc_checked(
            &connection, graphicsContext, sourcePixmap,
            XCB_GC_FOREGROUND, &sourceForeground));
    const xcb_rectangle_t pixel{0, 0, 1, 1};
    checkedRequest(
        connection,
        xcb_poly_fill_rectangle_checked(
            &connection, sourcePixmap, graphicsContext, 1, &pixel));

    const std::uint32_t maskForeground = 1U;
    checkedRequest(
        connection,
        xcb_change_gc_checked(
            &connection, graphicsContext, XCB_GC_FOREGROUND,
            &maskForeground));
    checkedRequest(
        connection,
        xcb_poly_fill_rectangle_checked(
            &connection, maskPixmap, graphicsContext, 1, &pixel));

    checkedRequest(
        connection,
        xcb_create_cursor_checked(
            &connection, cursor, sourcePixmap, maskPixmap,
            /*fore_red=*/0xffffU, /*fore_green=*/0xffffU,
            /*fore_blue=*/0xffffU, /*back_red=*/0U,
            /*back_green=*/0U, /*back_blue=*/0U,
            /*x=*/0, /*y=*/0));

    checkedRequest(
        connection, xcb_free_gc_checked(&connection, graphicsContext));
    checkedRequest(
        connection, xcb_free_pixmap_checked(&connection, sourcePixmap));
    checkedRequest(
        connection, xcb_free_pixmap_checked(&connection, maskPixmap));
    return cursor;
}

void
displayCursor(xcb_connection_t &connection, xcb_window_t rootWindow,
              xcb_cursor_t cursor)
{
    const std::uint32_t value = cursor;
    checkedRequest(
        connection,
        xcb_change_window_attributes_checked(
            &connection, rootWindow, XCB_CW_CURSOR, &value));
}

void
connectionDenialsAndCancellation()
{
    // An invalid native FD produces a failed XCB object, not a live X
    // connection. No DISPLAY lookup, remote input, or cursor image read.
    xcb_connection_t *connection = xcb_connect_to_fd(-1, nullptr);
    assert(connection != nullptr);
    assert(xcb_connection_has_error(connection) != 0);

    X11CursorTracker cursor(*connection, XCB_WINDOW_NONE);
    assert(!cursor.valid());
    assert(std::string_view(cursor.failureReason()) ==
           "XFixes cursor connection is already failed");
    assert(!cursor.hasImage());
    assert(!cursor.refresh());

    // Cancellation must clear the borrowed connection before the
    // XCB owner destroys it; all later access stays independent of XCB.
    cursor.disconnect();
    xcb_disconnect(connection);
    cursor.disconnect();
    assert(!cursor.valid());
    assert(std::string_view(cursor.failureReason()) ==
           "XFixes cursor tracker is disconnected");
    assert(!cursor.pending());
    assert(!cursor.hasImage());
    assert(cursor.pixels().empty());
    assert(cursor.mask().empty());
    assert(cursor.widthPixels() == 0 && cursor.heightPixels() == 0);
    assert(cursor.hotspotX() == 0 && cursor.hotspotY() == 0);
    assert(cursor.refreshFailureReason() == nullptr);
    assert(cursor.refreshErrorCode() == 0);
    assert(cursor.refreshConnectionError() == 0);
    assert(!cursor.takeUnsupportedCursorWarning());
    assert(!cursor.takeRefreshFailureWarning());

    xcb_generic_event_t event{};
    event.response_type = 1;
    cursor.handle(event);
    assert(!cursor.handles(event));
    assert(!cursor.pending());
    assert(!cursor.refresh());
    assert(cursor.pixels().empty());
    cursor.acknowledge();
    assert(!cursor.pending());
}

void
destructorRetirement()
{
    const char *display = std::getenv("DISPLAY");
    assert(display != nullptr && display[0] != '\0');

    int ownerScreenNumber = -1;
    XcbConnection owner = connectDisplay(display, ownerScreenNumber);
    xcb_screen_t *ownerScreen =
        screenFor(*owner, ownerScreenNumber);

    int helperScreenNumber = -1;
    XcbConnection helper = connectDisplay(display, helperScreenNumber);
    xcb_screen_t *helperScreen =
        screenFor(*helper, helperScreenNumber);
    assert(helperScreen->root == ownerScreen->root);

    const xcb_query_extension_reply_t *extension =
        xcb_get_extension_data(owner.get(), &xcb_xfixes_id);
    assert(extension != nullptr && extension->present);
    const std::uint8_t firstEvent = extension->first_event;

    const xcb_cursor_t firstCursor =
        createCursor(*helper, helperScreen->root, true);
    const xcb_cursor_t secondCursor =
        createCursor(*helper, helperScreen->root, false);

    // Establish and consume one real notification so the test proves the
    // production subscription is active before exercising retirement.
    {
        X11CursorTracker cursor(*owner, ownerScreen->root);
        assert(cursor.valid());
        cursor.acknowledge();
        displayCursor(*helper, helperScreen->root, firstCursor);
        assert(consumeCursorNotification(
            *owner, firstEvent, ownerScreen->root));
    }

    // Destructor-driven cancellation must deselect the XFixes event mask while
    // the borrowed owner remains healthy. A later cursor change must therefore
    // produce no notification for this client.
    assert(xcb_connection_has_error(owner.get()) == 0);
    displayCursor(*helper, helperScreen->root, secondCursor);
    assert(!consumeCursorNotification(
        *owner, firstEvent, ownerScreen->root));

    // Replacement subscription proves the owner remains reusable, and
    // explicit disconnect must retire the same server-side registration.
    X11CursorTracker replacement(*owner, ownerScreen->root);
    assert(replacement.valid());
    displayCursor(*helper, helperScreen->root, firstCursor);
    assert(consumeCursorNotification(
        *owner, firstEvent, ownerScreen->root));
    replacement.disconnect();

    displayCursor(*helper, helperScreen->root, secondCursor);
    assert(!consumeCursorNotification(
        *owner, firstEvent, ownerScreen->root));
    assert(xcb_connection_has_error(owner.get()) == 0);

    checkedRequest(
        *helper, xcb_free_cursor_checked(helper.get(), firstCursor));
    checkedRequest(
        *helper, xcb_free_cursor_checked(helper.get(), secondCursor));
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
    if (behavior == "destructor-retirement")
    {
        destructorRetirement();
        return 0;
    }

    assert(false && "unknown XFixes cursor tracker behavior");
    return 1;
}
