// SPDX-License-Identifier: GPL-3.0-or-later

#include "x11_display_connection.h"

#include <cstdlib>
#include <string>

#include <xcb/randr.h>

namespace
{

struct XcbPollContext
{
    X11DisplayConnection *owner;
    bool socketReadable;
};

xcb_generic_event_t *
poll_xcb_event(void *context) noexcept
{
    const auto &state = *static_cast<XcbPollContext *>(context);
    // Recheck after each callback: a sink may cancel/disconnect the owner.
    xcb_connection_t *connection = state.owner->nativeConnection();
    if (connection == nullptr)
    {
        return nullptr;
    }

    // First drain XCB's already buffered events without reading the socket.
    if (xcb_generic_event_t *event = xcb_poll_for_queued_event(connection))
    {
        return event;
    }
    // Polling the socket is nonblocking, but only legal after readiness.
    return state.socketReadable ? xcb_poll_for_event(connection) : nullptr;
}

struct RandrObservation
{
    X11DisplayConnection *owner;
    std::uint8_t firstEvent;
    xcb_window_t rootWindow;
    PixelSize *geometry;
};

void
observe_randr(const xcb_generic_event_t &event, void *context) noexcept
{
    const auto &state = *static_cast<RandrObservation *>(context);
    if (!state.owner->valid() || state.firstEvent == 0 ||
        (event.response_type & 0x7f) !=
            static_cast<std::uint8_t>(
                state.firstEvent + XCB_RANDR_SCREEN_CHANGE_NOTIFY))
    {
        return;
    }
    const auto &resize =
        reinterpret_cast<const xcb_randr_screen_change_notify_event_t &>(
            event);
    if (resize.root == state.rootWindow &&
        resize.width != 0 && resize.height != 0)
    {
        *state.geometry = {resize.width, resize.height};
    }
}

} // namespace

X11DisplayConnection::X11DisplayConnection(std::string_view displayName) noexcept
{
    std::string ownedDisplayName;
    try
    {
        if (!displayName.empty())
        {
            ownedDisplayName.assign(displayName.data(), displayName.size());
        }
    }
    catch (...)
    {
        failed_ = true;
        return;
    }

    const char *requestedDisplay =
        displayName.empty() ? nullptr : ownedDisplayName.c_str();
    int requestedScreen = -1;
    connection_ = xcb_connect(requestedDisplay, &requestedScreen);
    if (connection_ == nullptr || xcb_connection_has_error(connection_) != 0)
    {
        failed_ = true;
        close();
        return;
    }
    screenNumber_ = requestedScreen;

    const xcb_setup_t *setup = xcb_get_setup(connection_);
    if (setup == nullptr || screenNumber_ < 0)
    {
        failed_ = true;
        close();
        return;
    }

    xcb_screen_iterator_t screens = xcb_setup_roots_iterator(setup);
    for (int index = 0; index < screenNumber_ && screens.rem > 0; ++index)
    {
        xcb_screen_next(&screens);
    }
    if (screens.rem <= 0 || screens.data == nullptr)
    {
        failed_ = true;
        close();
        return;
    }

    const xcb_screen_t *screen = screens.data;
    rootWindow_ = screen->root;
    rootVisual_ = screen->root_visual;
    rootDepth_ = screen->root_depth;
    sourceGeometry_.widthPixels = screen->width_in_pixels;
    sourceGeometry_.heightPixels = screen->height_in_pixels;
    if (rootWindow_ == XCB_WINDOW_NONE || rootVisual_ == XCB_NONE ||
        rootDepth_ == 0 || sourceGeometry_.widthPixels == 0 ||
        sourceGeometry_.heightPixels == 0)
    {
        failed_ = true;
        close();
        return;
    }

    const xcb_query_extension_reply_t *randrExtension =
        xcb_get_extension_data(connection_, &xcb_randr_id);
    if (randrExtension != nullptr && randrExtension->present)
    {
        const xcb_void_cookie_t selectCookie = xcb_randr_select_input_checked(
            connection_, rootWindow_, XCB_RANDR_NOTIFY_MASK_SCREEN_CHANGE);
        xcb_generic_error_t *selectError =
            xcb_request_check(connection_, selectCookie);
        if (selectError == nullptr)
        {
            randrFirstEvent_ = randrExtension->first_event;
        }
        std::free(selectError);
    }

    connectionFileDescriptor_ = xcb_get_file_descriptor(connection_);
    if (connectionFileDescriptor_ < 0)
    {
        failed_ = true;
        close();
        return;
    }
}

X11DisplayConnection::~X11DisplayConnection() noexcept
{
    close();
}

void
X11DisplayConnection::markFailedForOwnerTeardown() noexcept
{
    failed_ = true;
    connectionFileDescriptor_ = -1;
}

void
X11DisplayConnection::close() noexcept
{
    // XCB alone owns and closes the socket. Never duplicate/close its fd.
    connectionFileDescriptor_ = -1;
    if (connection_ != nullptr)
    {
        xcb_disconnect(connection_);
        connection_ = nullptr;
    }
    failed_ = true;
    screenNumber_ = -1;
    rootWindow_ = XCB_WINDOW_NONE;
    rootVisual_ = XCB_NONE;
    rootDepth_ = 0;
    randrFirstEvent_ = 0;
    sourceGeometry_ = {};
}

bool
X11DisplayConnection::valid() const noexcept
{
    return !failed_ && connection_ != nullptr &&
           xcb_connection_has_error(connection_) == 0 &&
           connectionFileDescriptor_ >= 0 && screenNumber_ >= 0 &&
           rootWindow_ != XCB_WINDOW_NONE &&
           rootVisual_ != XCB_NONE && rootDepth_ != 0 &&
           sourceGeometry_.widthPixels > 0 &&
           sourceGeometry_.heightPixels > 0;
}

bool
X11DisplayConnection::randrAvailable() const noexcept
{
    return valid() && randrFirstEvent_ != 0;
}

xcb_connection_t *
X11DisplayConnection::nativeConnection() const noexcept
{
    return valid() ? connection_ : nullptr;
}

PixelSize
X11DisplayConnection::sourceGeometry() const noexcept
{
    return valid() ? sourceGeometry_ : PixelSize{};
}

int
X11DisplayConnection::screenNumber() const noexcept
{
    return valid() ? screenNumber_ : -1;
}

xcb_window_t
X11DisplayConnection::rootWindow() const noexcept
{
    return valid() ? rootWindow_ : xcb_window_t{};
}

xcb_visualid_t
X11DisplayConnection::rootVisual() const noexcept
{
    return valid() ? rootVisual_ : xcb_visualid_t{};
}

std::uint8_t
X11DisplayConnection::rootDepth() const noexcept
{
    return valid() ? rootDepth_ : 0;
}

int
X11DisplayConnection::fileDescriptor() const noexcept
{
    return valid() ? connectionFileDescriptor_ : -1;
}

void
X11DisplayConnection::disconnect() noexcept
{
    close();
}

ConnectionStatus
X11DisplayConnection::processEvents(X11EventSink &eventSink,
                                    std::size_t eventBudget,
                                    bool *workMayRemain,
                                    bool socketReadable) noexcept
{
    if (workMayRemain != nullptr)
    {
        *workMayRemain = false;
    }
    if (!valid())
    {
        markFailedForOwnerTeardown();
        return ConnectionStatus::Failed;
    }

    XcbPollContext poll{this, socketReadable};
    RandrObservation randr{this, randrFirstEvent_, rootWindow_,
                           &sourceGeometry_};
    const auto result = processX11EventBatch(
        eventSink, poll_xcb_event, &poll, eventBudget,
        observe_randr, &randr);
    if (result.status == ConnectionStatus::Failed || !valid())
    {
        markFailedForOwnerTeardown();
        return ConnectionStatus::Failed;
    }
    if (workMayRemain != nullptr)
    {
        *workMayRemain = result.workMayRemain;
    }
    return ConnectionStatus::Ok;
}
