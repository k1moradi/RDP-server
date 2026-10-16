// SPDX-License-Identifier: GPL-3.0-or-later
#include "mac_input_controller.h"

#include <array>
#include <type_traits>

namespace rdp::macos {
namespace {

[[nodiscard]] constexpr std::int64_t maximumScrollDelta() noexcept {
    return static_cast<std::int64_t>(kMacInputScrollUnitsPerStep) *
           kMaximumMacInputScrollSteps;
}

} // namespace

MacInputController::MacInputController(
    const NativeDisplayGeometryRefresh& geometry, MacInputCallbacks callbacks,
    const std::uint64_t pinnedGeneration) noexcept
    : geometry_(&geometry), callbacks_(callbacks),
      pinnedGeneration_(pinnedGeneration) {
    const auto revision = geometry.topologyRevision(pinnedGeneration);
    const auto sessionWatchRevision = NativeSessionChangeWatch::coveredRevision();
    if (callbacks_.context == nullptr || callbacks_.send == nullptr ||
        pinnedGeneration_ == 0 || !revision || *revision == 0 ||
        !sessionWatchRevision || *sessionWatchRevision == 0) {
        closed_ = true;
        geometry_ = nullptr;
        pinnedGeneration_ = 0;
        return;
    }
    pinnedTopologyRevision_ = *revision;
    pinnedSessionWatchRevision_ = *sessionWatchRevision;
}

MacInputController::~MacInputController() noexcept {
    cancel();
}

std::size_t MacInputController::keySlot(const std::uint8_t scanCode,
                                        const bool extended) noexcept {
    return static_cast<std::size_t>(scanCode) + (extended ? 256U : 0U);
}

std::size_t MacInputController::buttonSlot(const MacPointerButton button) noexcept {
    return static_cast<std::size_t>(button);
}

void MacInputController::clearHeldState() noexcept {
    activeKeys_.fill(false);
    activeKeyCodes_.fill(0);
    pressedButtons_.fill(false);
    verticalScrollRemainder_ = 0;
    horizontalScrollRemainder_ = 0;
    havePointerPosition_ = false;
    lastXPoints_ = 0.0;
    lastYPoints_ = 0.0;
}

void MacInputController::invalidateWithoutNativeInput() noexcept {
    closed_ = true;
    cancellationRequested_ = false;
    geometry_ = nullptr;
    pinnedGeneration_ = 0;
    pinnedTopologyRevision_ = 0;
    pinnedSessionWatchRevision_ = 0;
    clearHeldState();
}

bool MacInputController::lifetimeCurrent() noexcept {
    if (closed_ || geometry_ == nullptr || pinnedGeneration_ == 0 ||
        pinnedTopologyRevision_ == 0 || pinnedSessionWatchRevision_ == 0) {
        return false;
    }
    const auto revision = geometry_->topologyRevision(pinnedGeneration_);
    if (!revision || *revision != pinnedTopologyRevision_ ||
        !NativeSessionChangeWatch::current(pinnedSessionWatchRevision_)) {
        // Session loss is terminal and deliberately clears held state without
        // synthesizing releases into a potentially different GUI session.
        invalidateWithoutNativeInput();
        return false;
    }
    return true;
}

bool MacInputController::translatePosition(
    const std::uint32_t x, const std::uint32_t y, double& xPoints,
    double& yPoints) const noexcept {
    if (geometry_ == nullptr || pinnedGeneration_ == 0) {
        return false;
    }
    const auto translated =
        geometry_->logicalAtVirtualPixel(x, y, pinnedGeneration_);
    if (!translated) {
        return false;
    }
    xPoints = translated->point.xPoints;
    yPoints = translated->point.yPoints;
    return true;
}

bool MacInputController::sendCommands(
    const std::span<const MacNativeInputCommand> commands) noexcept {
    if (commands.empty()) {
        return true;
    }
    // Re-check immediately before entering the injected/native posting
    // callback. A watch event racing the callback is fenced again by handle().
    if (!lifetimeCurrent()) {
        return false;
    }
    operationInProgress_ = true;
    const std::size_t accepted = callbacks_.send(callbacks_.context, commands);
    operationInProgress_ = false;
    return accepted == commands.size();
}

bool MacInputController::activeDragButton(MacPointerButton& button) const noexcept {
    for (std::size_t index = 0; index < pressedButtons_.size(); ++index) {
        if (pressedButtons_[index]) {
            button = static_cast<MacPointerButton>(index);
            return true;
        }
    }
    return false;
}

bool MacInputController::handleKey(const MacKeyInput& input) noexcept {
    if (input.scanCode == 0) {
        return false;
    }
    const std::size_t slot = keySlot(input.scanCode, input.extended);
    if (activeKeys_[slot] == input.pressed) {
        if (!input.pressed) {
            return true;
        }
        return activeKeyCodes_[slot] == input.virtualKeyCode;
    }

    const std::uint16_t nativeCode =
        input.pressed ? input.virtualKeyCode : activeKeyCodes_[slot];
    const MacNativeInputCommand command{
        input.pressed ? MacNativeInputKind::KeyDown : MacNativeInputKind::KeyUp,
        nativeCode};
    if (!sendCommands(std::span{&command, 1U})) {
        return false;
    }
    activeKeys_[slot] = input.pressed;
    activeKeyCodes_[slot] = input.pressed ? nativeCode : 0;
    return true;
}

bool MacInputController::handleMove(const MacPointerMoveInput& input) noexcept {
    double xPoints{};
    double yPoints{};
    if (!translatePosition(input.x, input.y, xPoints, yPoints)) {
        return false;
    }
    MacPointerButton dragButton{};
    const bool dragging = activeDragButton(dragButton);
    const MacNativeInputCommand command{
        MacNativeInputKind::PointerMove, 0, xPoints, yPoints,
        MacPointerButton::Left, 0, dragging, dragButton};
    if (!sendCommands(std::span{&command, 1U})) {
        return false;
    }
    lastXPoints_ = xPoints;
    lastYPoints_ = yPoints;
    havePointerPosition_ = true;
    return true;
}

bool MacInputController::handleButton(
    const MacPointerButtonInput& input) noexcept {
    const std::size_t slot = buttonSlot(input.button);
    if (slot >= pressedButtons_.size()) {
        return false;
    }
    if (pressedButtons_[slot] == input.pressed) {
        return true;
    }

    double xPoints{};
    double yPoints{};
    if (!translatePosition(input.x, input.y, xPoints, yPoints)) {
        return false;
    }
    MacPointerButton dragButton{};
    const bool dragging = activeDragButton(dragButton);
    const std::array commands{
        MacNativeInputCommand{MacNativeInputKind::PointerMove, 0, xPoints,
                              yPoints, MacPointerButton::Left, 0, dragging,
                              dragButton},
        MacNativeInputCommand{
            input.pressed ? MacNativeInputKind::ButtonDown
                          : MacNativeInputKind::ButtonUp,
            0, xPoints, yPoints, input.button},
    };
    if (!sendCommands(commands)) {
        return false;
    }
    pressedButtons_[slot] = input.pressed;
    lastXPoints_ = xPoints;
    lastYPoints_ = yPoints;
    havePointerPosition_ = true;
    return true;
}

bool MacInputController::handleScroll(const MacScrollInput& input) noexcept {
    if (input.axis != MacScrollAxis::Vertical &&
        input.axis != MacScrollAxis::Horizontal) {
        return false;
    }
    if (input.delta == 0) {
        return true;
    }
    if (static_cast<std::int64_t>(input.delta) < -maximumScrollDelta() ||
        static_cast<std::int64_t>(input.delta) > maximumScrollDelta()) {
        return false;
    }

    std::int64_t& remainder = input.axis == MacScrollAxis::Vertical
        ? verticalScrollRemainder_ : horizontalScrollRemainder_;
    const std::int64_t combined = remainder + input.delta;
    const auto steps = static_cast<std::int32_t>(
        combined / kMacInputScrollUnitsPerStep);
    const std::int64_t nextRemainder =
        combined % kMacInputScrollUnitsPerStep;
    if (steps == 0) {
        remainder = nextRemainder;
        return true;
    }

    double xPoints{};
    double yPoints{};
    if (!translatePosition(input.x, input.y, xPoints, yPoints)) {
        return false;
    }
    const MacNativeInputCommand command{
        input.axis == MacScrollAxis::Vertical
            ? MacNativeInputKind::VerticalScroll
            : MacNativeInputKind::HorizontalScroll,
        0, xPoints, yPoints, MacPointerButton::Left, steps};
    if (!sendCommands(std::span{&command, 1U})) {
        return false;
    }
    remainder = nextRemainder;
    lastXPoints_ = xPoints;
    lastYPoints_ = yPoints;
    havePointerPosition_ = true;
    return true;
}

bool MacInputController::handle(const MacInputEvent& event) noexcept {
    if (closed_ || operationInProgress_ || cancellationRequested_ ||
        !lifetimeCurrent()) {
        return false;
    }

    const bool handled = std::visit(
        [this](const auto& input) noexcept -> bool {
            using Input = std::decay_t<decltype(input)>;
            if constexpr (std::is_same_v<Input, MacKeyInput>) {
                return handleKey(input);
            } else if constexpr (std::is_same_v<Input, MacPointerMoveInput>) {
                return handleMove(input);
            } else if constexpr (std::is_same_v<Input, MacPointerButtonInput>) {
                return handleButton(input);
            } else {
                static_assert(std::is_same_v<Input, MacScrollInput>);
                return handleScroll(input);
            }
        },
        event);

    if (!handled) {
        if (!closed_) {
            cancellationRequested_ = true;
        }
        finishDeferredCancellation();
        return false;
    }
    if (cancellationRequested_) {
        finishDeferredCancellation();
        return false;
    }
    if (!lifetimeCurrent()) {
        return false;
    }
    return !closed_;
}

void MacInputController::releaseHeldInput() noexcept {
    std::array<MacNativeInputCommand, kMaximumMacNativeInputBatch> commands{};
    std::size_t count{};
    for (std::size_t slot = 0; slot < activeKeys_.size(); ++slot) {
        if (!activeKeys_[slot]) {
            continue;
        }
        commands[count++] = {MacNativeInputKind::KeyUp, activeKeyCodes_[slot]};
    }
    if (havePointerPosition_) {
        for (std::size_t slot = 0; slot < pressedButtons_.size(); ++slot) {
            if (!pressedButtons_[slot]) {
                continue;
            }
            commands[count++] = {
                MacNativeInputKind::ButtonUp, 0, lastXPoints_, lastYPoints_,
                static_cast<MacPointerButton>(slot)};
        }
    }

    clearHeldState();
    if (count != 0) {
        (void)sendCommands(std::span{commands.data(), count});
    }
}

void MacInputController::finishDeferredCancellation() noexcept {
    if (!cancellationRequested_ || operationInProgress_) {
        return;
    }
    cancellationRequested_ = false;
    if (!closed_ && lifetimeCurrent()) {
        releaseHeldInput();
    }
    closed_ = true;
    geometry_ = nullptr;
    pinnedGeneration_ = 0;
    pinnedTopologyRevision_ = 0;
    pinnedSessionWatchRevision_ = 0;
    clearHeldState();
}

void MacInputController::cancel() noexcept {
    if (closed_) {
        return;
    }
    if (operationInProgress_) {
        cancellationRequested_ = true;
        return;
    }
    if (lifetimeCurrent()) {
        releaseHeldInput();
    }
    closed_ = true;
    cancellationRequested_ = false;
    geometry_ = nullptr;
    pinnedGeneration_ = 0;
    pinnedTopologyRevision_ = 0;
    pinnedSessionWatchRevision_ = 0;
    clearHeldState();
}

} // namespace rdp::macos
