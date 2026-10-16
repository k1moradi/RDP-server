// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows/windows_input_controller.h"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>

using namespace rdp_server::windows;

namespace
{
struct FakeGeneration final
{
    WindowsCaptureGeneration current{11, 23};
    unsigned reads{};
    bool fail{};

    static bool read(void *context, WindowsCaptureGeneration &output) noexcept
    {
        auto &self = *static_cast<FakeGeneration *>(context);
        ++self.reads;
        if (self.fail)
        {
            return false;
        }
        output = self.current;
        return true;
    }

    [[nodiscard]] WindowsCaptureGenerationReader reader() noexcept
    {
        return {this, &read};
    }
};

struct FakeInputBackend final
{
    std::array<WindowsNativeInputCommand, 64> commands{};
    std::array<std::size_t, 32> batchSizes{};
    std::size_t commandCount{};
    std::size_t batchCount{};
    std::size_t forcedInsertedCount{static_cast<std::size_t>(-1)};
    WindowsInputController *controller{};
    WindowsInputEvent reentrantEvent{WindowsKeyInput{0x20, false, true}};
    bool cancelDuringSend{};
    bool reenterDuringSend{};
    bool changeGenerationDuringSend{};
    FakeGeneration *generation{};
    bool reentrantResult{true};

    static std::size_t send(
        void *context,
        std::span<const WindowsNativeInputCommand> input) noexcept
    {
        auto &self = *static_cast<FakeInputBackend *>(context);
        assert(self.batchCount < self.batchSizes.size());
        assert(self.commandCount + input.size() <= self.commands.size());
        self.batchSizes[self.batchCount++] = input.size();
        for (const auto &command : input)
        {
            self.commands[self.commandCount++] = command;
        }
        if (self.reenterDuringSend && self.controller != nullptr)
        {
            self.reentrantResult = self.controller->handle(self.reentrantEvent);
        }
        if (self.cancelDuringSend && self.controller != nullptr)
        {
            self.cancelDuringSend = false;
            self.controller->cancel();
        }
        if (self.changeGenerationDuringSend && self.generation != nullptr)
        {
            ++self.generation->current.device;
        }
        return self.forcedInsertedCount == static_cast<std::size_t>(-1)
                   ? input.size()
                   : self.forcedInsertedCount;
    }

    [[nodiscard]] WindowsInputCallbacks callbacks() noexcept
    {
        return {this, &send};
    }
};

[[nodiscard]] WindowsDesktopLayout sampleInputLayout()
{
    constexpr std::array monitors{
        PortableRectangle{-100, 0, 100, 100},
        PortableRectangle{0, 20, 200, 80},
    };
    WindowsDesktopLayout layout{};
    assert(makeWindowsDesktopLayout(monitors, layout));
    assert((layout.virtualBounds == PortableRectangle{-100, 0, 300, 100}));
    return layout;
}

void assertCommand(const WindowsNativeInputCommand &command,
                   WindowsNativeInputKind kind) noexcept
{
    assert(command.kind == kind);
}
} // namespace

void windowsInputSendInputLifecycle()
{
    FakeGeneration generation{};
    FakeInputBackend backend{};
    WindowsInputController controller(sampleInputLayout(), backend.callbacks(),
                                      generation.reader(), {11, 23});
    backend.controller = &controller;
    assert(!controller.closed());

    assert(controller.handle(WindowsKeyInput{0x1e, false, true}));
    assert(backend.commandCount == 1 && backend.batchSizes[0] == 1);
    assertCommand(backend.commands[0], WindowsNativeInputKind::keyDown);
    assert(backend.commands[0].scanCode == 0x1e && !backend.commands[0].extended);

    // Duplicate make is idempotent and never emits a second native press.
    assert(controller.handle(WindowsKeyInput{0x1e, false, true}));
    assert(backend.commandCount == 1);

    // Virtual-desktop endpoints normalize exactly to Win32's documented range.
    assert(controller.handle(WindowsPointerMoveInput{{0, 0}}));
    assertCommand(backend.commands[1], WindowsNativeInputKind::pointerMoveAbsolute);
    assert(backend.commands[1].normalizedX == 0 &&
           backend.commands[1].normalizedY == 0);

    assert(controller.handle(WindowsPointerButtonInput{
        {299, 99}, WindowsPointerButton::x2, true}));
    assert(backend.batchSizes[2] == 2);
    assertCommand(backend.commands[2], WindowsNativeInputKind::pointerMoveAbsolute);
    assert(backend.commands[2].normalizedX == 65535 &&
           backend.commands[2].normalizedY == 65535);
    assertCommand(backend.commands[3], WindowsNativeInputKind::buttonDown);
    assert(backend.commands[3].button == WindowsPointerButton::x2);

    assert(controller.handle(WindowsScrollInput{
        {100, 50}, -120, WindowsScrollAxis::horizontal}));
    assertCommand(backend.commands[4], WindowsNativeInputKind::pointerMoveAbsolute);
    assertCommand(backend.commands[5], WindowsNativeInputKind::horizontalWheel);
    assert(backend.commands[5].wheelDelta == -120);

    assert(controller.handle(WindowsKeyInput{0x1e, false, false}));
    assertCommand(backend.commands[6], WindowsNativeInputKind::keyUp);

    // Cancellation releases held mouse state before becoming terminal.
    controller.cancel();
    assert(controller.closed());
    assertCommand(backend.commands[7], WindowsNativeInputKind::buttonUp);
    assert(backend.commands[7].button == WindowsPointerButton::x2);
    assert(!controller.handle(WindowsPointerMoveInput{{1, 1}}));
    const auto commandCount = backend.commandCount;
    controller.cancel();
    assert(backend.commandCount == commandCount);
}

void windowsInputSendInputRevocationDenials()
{
    // Monitor-gap coordinates never reach the native callback.
    {
        FakeGeneration generation{};
        FakeInputBackend backend{};
        WindowsInputController controller(sampleInputLayout(), backend.callbacks(),
                                          generation.reader(), {11, 23});
        assert(!controller.handle(WindowsPointerMoveInput{{150, 10}}));
        assert(controller.closed() && backend.commandCount == 0);
    }

    // Malformed scan code and oversized wheel input fail closed.
    for (const auto &event : std::array<WindowsInputEvent, 3>{
             WindowsKeyInput{0, false, true},
             WindowsKeyInput{0x100, false, true},
             WindowsScrollInput{{100, 50},
                                kMaximumWindowsInputWheelDelta + 1,
                                WindowsScrollAxis::vertical}})
    {
        FakeGeneration generation{};
        FakeInputBackend backend{};
        WindowsInputController controller(sampleInputLayout(), backend.callbacks(),
                                          generation.reader(), {11, 23});
        assert(!controller.handle(event));
        assert(controller.closed() && backend.commandCount == 0);
    }

    // An invalid enum value is rejected instead of silently becoming horizontal.
    {
        FakeGeneration generation{};
        FakeInputBackend backend{};
        WindowsInputController controller(sampleInputLayout(), backend.callbacks(),
                                          generation.reader(), {11, 23});
        assert(!controller.handle(WindowsScrollInput{
            {100, 50}, 120, static_cast<WindowsScrollAxis>(99)}));
        assert(controller.closed() && backend.commandCount == 0);
    }

    // Stale generation denies all native input and does not emit cleanup into
    // a different desktop generation.
    {
        FakeGeneration generation{};
        FakeInputBackend backend{};
        WindowsInputController controller(sampleInputLayout(), backend.callbacks(),
                                          generation.reader(), {11, 23});
        generation.current.device = 24;
        assert(!controller.handle(WindowsKeyInput{0x1e, false, true}));
        assert(controller.closed() && backend.commandCount == 0);
    }

    // Short native insertion is terminal; previously held input gets one
    // best-effort release while the pinned generation remains current.
    {
        FakeGeneration generation{};
        FakeInputBackend backend{};
        WindowsInputController controller(sampleInputLayout(), backend.callbacks(),
                                          generation.reader(), {11, 23});
        assert(controller.handle(WindowsKeyInput{0x1e, true, true}));
        backend.forcedInsertedCount = 1; // move inserted, button not inserted
        assert(!controller.handle(WindowsPointerButtonInput{
            {100, 50}, WindowsPointerButton::left, true}));
        assert(controller.closed());
        assert(backend.batchCount == 3);
        assert(backend.batchSizes[1] == 2 && backend.batchSizes[2] == 1);
        assertCommand(backend.commands[3], WindowsNativeInputKind::keyUp);
        assert(backend.commands[3].scanCode == 0x1e &&
               backend.commands[3].extended);
    }

    // Reentry is denied, while cancellation during SendInput is deferred until
    // the successful key-down callback returns, then releases the key once.
    {
        FakeGeneration generation{};
        FakeInputBackend backend{};
        WindowsInputController controller(sampleInputLayout(), backend.callbacks(),
                                          generation.reader(), {11, 23});
        backend.controller = &controller;
        backend.cancelDuringSend = true;
        backend.reenterDuringSend = true;
        assert(!controller.handle(WindowsKeyInput{0x20, false, true}));
        assert(!backend.reentrantResult && controller.closed());
        assert(backend.commandCount == 2);
        assertCommand(backend.commands[0], WindowsNativeInputKind::keyDown);
        assertCommand(backend.commands[1], WindowsNativeInputKind::keyUp);
    }

    // A generation change observed after a synthetic send terminally revokes
    // without sending a release into the newly observed desktop generation.
    {
        FakeGeneration generation{};
        FakeInputBackend backend{};
        WindowsInputController controller(sampleInputLayout(), backend.callbacks(),
                                          generation.reader(), {11, 23});
        backend.generation = &generation;
        backend.changeGenerationDuringSend = true;
        assert(!controller.handle(WindowsKeyInput{0x30, false, true}));
        assert(controller.closed() && backend.commandCount == 1);
        assertCommand(backend.commands[0], WindowsNativeInputKind::keyDown);
    }

    // Missing callbacks, zero generation and noncanonical layout are inert.
    {
        FakeGeneration generation{};
        WindowsInputController missing(sampleInputLayout(), {}, generation.reader(),
                                       {11, 23});
        assert(missing.closed());
        FakeInputBackend backend{};
        WindowsInputController zero(sampleInputLayout(), backend.callbacks(),
                                    generation.reader(), {});
        assert(zero.closed());
        auto invalidLayout = sampleInputLayout();
        invalidLayout.virtualBounds.widthPixels = 299;
        WindowsInputController invalid(invalidLayout, backend.callbacks(),
                                       generation.reader(), {11, 23});
        assert(invalid.closed());
    }
}
