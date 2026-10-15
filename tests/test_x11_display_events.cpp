// SPDX-License-Identifier: GPL-3.0-or-later

#include "../src/x11/x11_event_dispatch.h"
#if defined(RDP_TEST_NATIVE_X11_CONNECTION)
#include "../src/x11/x11_display_connection.h"
#endif

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

namespace
{
struct EventQueue
{
    std::array<std::uint8_t, 6> types{2, 3, 4, 5, 6, 7};
    std::size_t next{0};
    std::size_t available{0};
    std::size_t polls{0};
    bool failedAllocation{false};
};

xcb_generic_event_t *pollEvent(void *context) noexcept
{
    auto &queue = *static_cast<EventQueue *>(context);
    ++queue.polls;
    if (queue.next == queue.available)
    {
        return nullptr;
    }
    auto *event = static_cast<xcb_generic_event_t *>(
        std::calloc(1, sizeof(xcb_generic_event_t)));
    if (event == nullptr)
    {
        queue.failedAllocation = true;
        return nullptr;
    }
    event->response_type = queue.types[queue.next++];
    return event;
}

struct Sink final : X11EventSink
{
    std::array<std::uint8_t, 8> seen{};
    std::size_t count{0};
    void handle(const xcb_generic_event_t &event) noexcept override
    {
        seen[count++] = event.response_type;
    }
};

struct Observer
{
    std::size_t callbacks{0};
    std::uint8_t lastType{0};
};

void observe(const xcb_generic_event_t &event, void *context) noexcept
{
    auto &observer = *static_cast<Observer *>(context);
    ++observer.callbacks;
    observer.lastType = event.response_type;
}
} // namespace

int main()
{
    EventQueue queue;
    Sink sink;
    Observer observer;

    // No readable/queued work must return promptly and without callbacks.
    const auto empty = processX11EventBatch(
        sink, pollEvent, &queue, 128, observe, &observer);
    assert(empty.status == ConnectionStatus::Ok);
    assert(empty.eventsDispatched == 0 && !empty.workMayRemain);
    assert(sink.count == 0 && observer.callbacks == 0);

    // A budget enforces fairness, and tells the caller to drain again.
    queue.available = 5;
    const auto first = processX11EventBatch(
        sink, pollEvent, &queue, 2, observe, &observer);
    assert(first.status == ConnectionStatus::Ok);
    assert(first.eventsDispatched == 2 && first.workMayRemain);
    assert(queue.next == 2 && sink.count == 2 && observer.callbacks == 2);
    assert(observer.lastType == 3);
    const auto second = processX11EventBatch(
        sink, pollEvent, &queue, 10, observe, &observer);
    assert(second.status == ConnectionStatus::Ok);
    assert(second.eventsDispatched == 3 && !second.workMayRemain);
    assert(queue.next == 5 && sink.count == 5 && observer.callbacks == 5);
    assert(sink.seen[4] == 6 && observer.lastType == 6);

    // Budget zero still makes bounded progress; never silently spins.
    queue.available = 6;
    const auto one = processX11EventBatch(sink, pollEvent, &queue, 0);
    assert(one.status == ConnectionStatus::Ok);
    assert(one.eventsDispatched == 1 && one.workMayRemain);
    assert(sink.count == 6 && observer.callbacks == 5);

    // Protocol errors fail closed, without invoking sink or observer.
    EventQueue failing;
    failing.types[0] = 0;
    failing.available = 2;
    Sink failedSink;
    const auto error = processX11EventBatch(
        failedSink, pollEvent, &failing, 8, observe, &observer);
    assert(error.status == ConnectionStatus::Failed);
    assert(error.eventsDispatched == 0 && !error.workMayRemain);
    assert(failing.next == 1 && failedSink.count == 0);
    assert(observer.callbacks == 5);

    const auto missingPoller = processX11EventBatch(sink, nullptr, nullptr, 3);
    assert(missingPoller.status == ConnectionStatus::Failed);
    assert(missingPoller.eventsDispatched == 0 && !missingPoller.workMayRemain);
    assert(!queue.failedAllocation && !failing.failedAllocation);

#if defined(RDP_TEST_NATIVE_X11_CONNECTION)
    // Invalid syntax cannot connect to a desktop. Cleanup must be idempotent.
    X11DisplayConnection disconnected(":not-a-display-number");
    assert(!disconnected.valid());
    assert(disconnected.fileDescriptor() == -1);
    assert(disconnected.nativeConnection() == nullptr);
    assert(disconnected.rootWindow() == XCB_WINDOW_NONE);
    assert(disconnected.sourceGeometry() == PixelSize{});
    assert(disconnected.processEvents(sink, 3, nullptr, true) ==
           ConnectionStatus::Failed);
    disconnected.disconnect();
    disconnected.disconnect();
    assert(!disconnected.valid() && disconnected.fileDescriptor() == -1);
#endif
    return 0;
}
