// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include <xcb/xcb.h>

enum class ConnectionStatus
{
    Ok,
    Failed,
};

/** Borrowed XCB event: valid only until handle returns. */
class X11EventSink
{
public:
    virtual ~X11EventSink() = default;
    virtual void handle(const xcb_generic_event_t &event) noexcept = 0;
};

struct X11EventDispatchResult
{
    ConnectionStatus status{ConnectionStatus::Ok};
    std::size_t eventsDispatched{0};
    // A full budget means buffered work MAY remain: the caller should
    // schedule another nonblocking iteration rather than wait for a new edge.
    bool workMayRemain{false};
};

using X11PollEvent = xcb_generic_event_t *(*)(void *) noexcept;
using X11EventObserver = void (*)(const xcb_generic_event_t &, void *) noexcept;

/**
 * Bounded, nonblocking XCB event drain. The poller returns an XCB-owned
 * malloc-compatible event, or nullptr when no work can be serviced.
 * Production supplies XCB's queued/readable poll functions; tests inject
 * synthetic events without connecting to a display. Protocol errors are
 * never forwarded to the event sink. No event memory escapes this call.
 */
[[nodiscard]] inline X11EventDispatchResult
processX11EventBatch(X11EventSink &sink, X11PollEvent pollEvent,
                     void *pollContext, std::size_t eventBudget,
                     X11EventObserver observer = nullptr,
                     void *observerContext = nullptr) noexcept
{
    if (pollEvent == nullptr)
    {
        return {ConnectionStatus::Failed, 0, false};
    }
    if (eventBudget == 0)
    {
        eventBudget = 1;
    }

    std::size_t count = 0;
    while (count < eventBudget)
    {
        xcb_generic_event_t *event = pollEvent(pollContext);
        if (event == nullptr)
        {
            break;
        }
        if (event->response_type == 0)
        {
            std::free(event);
            return {ConnectionStatus::Failed, count, false};
        }
        sink.handle(*event);
        if (observer != nullptr)
        {
            observer(*event, observerContext);
        }
        std::free(event);
        ++count;
    }
    return {ConnectionStatus::Ok, count, count == eventBudget};
}
