// SPDX-License-Identifier: GPL-3.0-or-later

#include "../src/x11/x11_damage_tracker.h"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include <xcb/xcb.h>

int main()
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
    return 0;
}
