// SPDX-License-Identifier: GPL-3.0-or-later

#include "../src/x11/x11_damage_tracker.h"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string_view>

#include <xcb/damage.h>
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

void
clearSyntheticRoot(xcb_connection_t &connection, xcb_window_t rootWindow)
{
    const xcb_void_cookie_t cookie =
        xcb_clear_area_checked(&connection, 0, rootWindow, 0, 0, 32, 32);
    xcb_generic_error_t *error = xcb_request_check(&connection, cookie);
    assert(error == nullptr);
    std::free(error);
    assert(xcb_connection_has_error(&connection) == 0);
}

bool
consumeDamageNotification(xcb_connection_t &connection,
                          std::uint8_t firstEvent,
                          xcb_window_t drawable)
{
    roundTrip(connection);

    bool found = false;
    while (xcb_generic_event_t *event = xcb_poll_for_event(&connection))
    {
        const std::uint8_t responseType =
            static_cast<std::uint8_t>(event->response_type & 0x7fU);
        if (responseType == firstEvent)
        {
            const auto &notification =
                reinterpret_cast<const xcb_damage_notify_event_t &>(*event);
            if (notification.drawable == drawable)
            {
                found = true;
            }
        }
        std::free(event);
    }
    return found;
}

void
connectionDenialsAndCancellation()
{
    // Deliberately invalid XCB fd: no display lookup, window inspection,
    // desktop capture, credentials, or server-side Damage installation.
    xcb_connection_t *connection = xcb_connect_to_fd(-1, nullptr);
    assert(connection != nullptr);
    assert(xcb_connection_has_error(connection) != 0);

    X11DamageTracker damage(*connection, XCB_WINDOW_NONE, {1920, 1080});
    assert(!damage.valid());
    assert(std::string_view(damage.failureReason()) ==
           "XDamage connection is already failed");
    assert(!damage.hasPendingDamage());
    assert(damage.notificationCount() == 0);
    assert(damage.damagedPixelCount() == 0);

    // Invalid connection cannot arm observation or acknowledge regions.
    damage.beginInteractionObservation(0);
    std::array<InteractionDamageNotification, 2> notifications{};
    assert(damage.copyInteractionNotifications(notifications) == 0);
    assert(damage.interactionNotificationOverflowCount() == 0);
    DamageRegion output;
    assert(!damage.snapshot(output));
    assert(output.rectangles().empty());
    assert(!damage.pendingDamageIntersects({0, 0, 16, 16}));

    // Explicit cancellation must precede the borrowed XCB owner's death.
    // Repeated cancellation, event delivery, and destructor must thereafter
    // be independent of the destroyed native connection.
    damage.disconnect();
    xcb_disconnect(connection);
    damage.disconnect();
    assert(!damage.valid());
    assert(std::string_view(damage.failureReason()) ==
           "XDamage tracker is disconnected");
    assert(!damage.hasPendingDamage());
    assert(damage.notificationCount() == 0);
    assert(damage.damagedPixelCount() == 0);
    assert(damage.snapshotRectangleCount() == 0);
    assert(damage.snapshotPixelCount() == 0);

    xcb_generic_event_t ignored{};
    ignored.response_type = 1;
    assert(!damage.handles(ignored));
    damage.handle(ignored);
    damage.beginInteractionObservation(1);
    assert(damage.copyInteractionNotifications(notifications) == 0);
    assert(damage.interactionNotificationOverflowCount() == 0);
    assert(!damage.pendingDamageIntersects({0, 0, 16, 16}));
    assert(!damage.snapshot(output));
    assert(output.rectangles().empty());
    damage.endInteractionObservation();
}

void
destructorRetirement()
{
    const char *display = std::getenv("DISPLAY");
    assert(display != nullptr && display[0] != '\0');

    int ownerScreenNumber = -1;
    XcbConnection owner = connectDisplay(display, ownerScreenNumber);
    xcb_screen_t *ownerScreen = screenFor(*owner, ownerScreenNumber);
    const PixelSize geometry{
        ownerScreen->width_in_pixels, ownerScreen->height_in_pixels};
    assert(geometry.widthPixels != 0 && geometry.heightPixels != 0);

    int helperScreenNumber = -1;
    XcbConnection helper = connectDisplay(display, helperScreenNumber);
    xcb_screen_t *helperScreen = screenFor(*helper, helperScreenNumber);
    assert(helperScreen->root == ownerScreen->root);

    const xcb_query_extension_reply_t *extension =
        xcb_get_extension_data(owner.get(), &xcb_damage_id);
    assert(extension != nullptr && extension->present);
    const std::uint8_t firstEvent = extension->first_event;

    {
        X11DamageTracker damage(
            *owner, ownerScreen->root, geometry);
        assert(damage.valid());

        clearSyntheticRoot(*helper, helperScreen->root);
        assert(consumeDamageNotification(
            *owner, firstEvent, ownerScreen->root));
    }

    // Scope exit must destroy the server-side Damage resource while the
    // borrowed owner remains healthy. Later root rendering must not enqueue a
    // stale notification for the dead observer.
    assert(xcb_connection_has_error(owner.get()) == 0);
    clearSyntheticRoot(*helper, helperScreen->root);
    assert(!consumeDamageNotification(
        *owner, firstEvent, ownerScreen->root));

    // A replacement resource must work on the same owner, and explicit
    // disconnect must retire the same native registration.
    X11DamageTracker replacement(
        *owner, ownerScreen->root, geometry);
    assert(replacement.valid());
    clearSyntheticRoot(*helper, helperScreen->root);
    assert(consumeDamageNotification(
        *owner, firstEvent, ownerScreen->root));

    replacement.disconnect();
    clearSyntheticRoot(*helper, helperScreen->root);
    assert(!consumeDamageNotification(
        *owner, firstEvent, ownerScreen->root));
    assert(xcb_connection_has_error(owner.get()) == 0);
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

    assert(false && "unknown XDamage tracker behavior");
    return 1;
}
