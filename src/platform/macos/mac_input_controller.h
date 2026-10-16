// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "platform/macos/native_display_refresh.h"
#include "platform/macos/native_session_change_watch.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <variant>

namespace rdp::macos {

inline constexpr std::int32_t kMacInputScrollUnitsPerStep = 120;
inline constexpr std::int32_t kMaximumMacInputScrollSteps = 16;
inline constexpr std::size_t kMaximumMacNativeInputBatch = 517;

enum class MacPointerButton : std::uint8_t {
    Left,
    Right,
    Middle,
    X1,
    X2,
};

enum class MacScrollAxis : std::uint8_t {
    Vertical,
    Horizontal,
};

struct MacKeyInput final {
    std::uint16_t virtualKeyCode{};
    std::uint8_t scanCode{};
    bool extended{};
    bool pressed{};
};

struct MacPointerMoveInput final {
    std::uint32_t x{};
    std::uint32_t y{};
};

struct MacPointerButtonInput final {
    std::uint32_t x{};
    std::uint32_t y{};
    MacPointerButton button{MacPointerButton::Left};
    bool pressed{};
};

struct MacScrollInput final {
    std::uint32_t x{};
    std::uint32_t y{};
    std::int32_t delta{};
    MacScrollAxis axis{MacScrollAxis::Vertical};
};

using MacInputEvent = std::variant<MacKeyInput, MacPointerMoveInput,
                                   MacPointerButtonInput, MacScrollInput>;

enum class MacNativeInputKind : std::uint8_t {
    KeyDown,
    KeyUp,
    PointerMove,
    ButtonDown,
    ButtonUp,
    VerticalScroll,
    HorizontalScroll,
};

struct MacNativeInputCommand final {
    MacNativeInputKind kind{MacNativeInputKind::PointerMove};
    std::uint16_t virtualKeyCode{};
    double xPoints{};
    double yPoints{};
    MacPointerButton button{MacPointerButton::Left};
    std::int32_t scrollSteps{};
    bool dragging{};
    MacPointerButton dragButton{MacPointerButton::Left};
};

struct MacInputCallbacks final {
    void* context{};
    // Return the number of leading commands accepted for native posting.
    std::size_t (*send)(void*, std::span<const MacNativeInputCommand>) noexcept{};
};

enum class MacInputPermissionStatus : std::uint8_t {
    Trusted,
    NotTrusted,
};

// Single-thread-affine R7 input state owner. The geometry generation,
// topology revision and native GUI-session watch revision are revocation facts
// only, never authorization. A future R2/R3 macOS route must authorize the
// concrete desktop before constructing or invoking this object. The geometry
// owner and process-scoped session watch must remain valid for the controller
// lifetime, and all access to this object and geometry must remain serialized
// by that route.
class MacInputController final {
public:
    MacInputController(const NativeDisplayGeometryRefresh& geometry,
                       MacInputCallbacks callbacks,
                       std::uint64_t pinnedGeneration) noexcept;
    ~MacInputController() noexcept;

    MacInputController(const MacInputController&) = delete;
    MacInputController& operator=(const MacInputController&) = delete;
    MacInputController(MacInputController&&) = delete;
    MacInputController& operator=(MacInputController&&) = delete;

    [[nodiscard]] bool handle(const MacInputEvent& event) noexcept;
    // Best-effort release of held keys/buttons only while the pinned display
    // epoch remains current, then terminally invalidate this controller.
    void cancel() noexcept;

    [[nodiscard]] bool closed() const noexcept { return closed_; }
    [[nodiscard]] std::uint64_t generation() const noexcept {
        return closed_ ? 0 : pinnedGeneration_;
    }

private:
    static constexpr std::size_t kScanCodeSlots = 512;
    static constexpr std::size_t kButtonCount = 5;
    static_assert(kScanCodeSlots + kButtonCount == kMaximumMacNativeInputBatch);

    [[nodiscard]] bool lifetimeCurrent() noexcept;
    [[nodiscard]] bool translatePosition(std::uint32_t x, std::uint32_t y,
                                         double& xPoints,
                                         double& yPoints) const noexcept;
    [[nodiscard]] bool sendCommands(
        std::span<const MacNativeInputCommand> commands) noexcept;
    [[nodiscard]] bool handleKey(const MacKeyInput& input) noexcept;
    [[nodiscard]] bool handleMove(const MacPointerMoveInput& input) noexcept;
    [[nodiscard]] bool handleButton(const MacPointerButtonInput& input) noexcept;
    [[nodiscard]] bool handleScroll(const MacScrollInput& input) noexcept;
    [[nodiscard]] bool activeDragButton(MacPointerButton& button) const noexcept;
    void releaseHeldInput() noexcept;
    void finishDeferredCancellation() noexcept;
    void invalidateWithoutNativeInput() noexcept;
    void clearHeldState() noexcept;

    [[nodiscard]] static std::size_t keySlot(std::uint8_t scanCode,
                                             bool extended) noexcept;
    [[nodiscard]] static std::size_t buttonSlot(MacPointerButton button) noexcept;

    const NativeDisplayGeometryRefresh* geometry_{};
    MacInputCallbacks callbacks_{};
    std::uint64_t pinnedGeneration_{};
    std::uint64_t pinnedTopologyRevision_{};
    std::uint64_t pinnedSessionWatchRevision_{};
    std::array<std::uint16_t, kScanCodeSlots> activeKeyCodes_{};
    std::array<bool, kScanCodeSlots> activeKeys_{};
    std::array<bool, kButtonCount> pressedButtons_{};
    std::int64_t verticalScrollRemainder_{};
    std::int64_t horizontalScrollRemainder_{};
    double lastXPoints_{};
    double lastYPoints_{};
    bool havePointerPosition_{};
    bool operationInProgress_{};
    bool cancellationRequested_{};
    bool closed_{};
};

#if defined(__APPLE__)
// Read-only Accessibility trust query. Passing no options never requests a
// prompt. This is OS permission evidence only and never substitutes for R2/R3
// authentication/session authorization.
[[nodiscard]] MacInputPermissionStatus queryNativeMacInputPermissionStatus() noexcept;
#endif

// The Quartz event-posting callback is deliberately not exposed. A future
// concrete R2/R3-authorized macOS route must own the capability that makes
// native input posting callable; a generation number alone is insufficient.

} // namespace rdp::macos
