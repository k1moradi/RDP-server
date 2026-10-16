// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "platform/macos/capture_pixel_buffer.h"
#include "platform/macos/native_display_refresh.h"
#include "platform/macos/screen_capture_preflight.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <optional>

namespace rdp::macos {

struct MacScreenCaptureBinding {
    std::uint32_t displayId{};
    std::size_t widthPixels{};
    std::size_t heightPixels{};
    std::uint64_t geometryGeneration{};
    std::uint64_t topologyRevision{};
};

enum class MacScreenCaptureError : std::uint8_t {
    InvalidBinding,
    MissingDisplay,
    StaleGeometryGeneration,
    StaleTopology,
    PermissionUnavailable,
    PermissionNotGranted,
    IllegalTransition,
    SetupFailed,
    OutputRegistrationFailed,
    StartRequestFailed,
    StartFailed,
    StopRequestFailed,
    StopFailed,
    NativeStreamFailed,
};

enum class MacScreenCaptureLifecycleState : std::uint8_t {
    Idle,
    Preparing,
    Ready,
    Starting,
    Capturing,
    Stopping,
    Closed,
    Failed,
};

enum class MacScreenCaptureFrameStatus : std::uint8_t {
    Complete,
    Idle,
    Blank,
    Started,
    Suspended,
    Stopped,
    Invalid,
};

enum class MacScreenCaptureFrameDrop : std::uint8_t {
    None,
    NotCapturing,
    InvalidStatus,
    MissingBuffer,
    UnsupportedFormat,
    InvalidDimensions,
    LockFailed,
    InvalidFramebuffer,
    StaleTopology,
};

enum class MacScreenCaptureFrameDisposition : std::uint8_t {
    Published,
    Dropped,
    RetireStream,
};

// Synchronous R7 -> R4 boundary using the same portable FramebufferView
// contract as Windows/X11. The view borrows the locked CoreVideo storage only
// for consume(); consumers needing asynchronous work must copy into their own
// explicitly bounded storage before returning. R7 owns no frame ID, damage
// schedule, encoder queue, presentation state, or transport authority here.
class MacCaptureFrameConsumer {
public:
    virtual ~MacCaptureFrameConsumer() = default;
    virtual void consume(const FramebufferView& frame,
                         std::uint64_t generation) noexcept = 0;
};

// Build one capture binding from the already validated native display snapshot.
// The existing compositor geometry validator is reused; mixed-scale and other
// unsupported layouts therefore keep failing closed before ScreenCaptureKit.
[[nodiscard]] std::expected<MacScreenCaptureBinding, MacScreenCaptureError>
makeMacScreenCaptureBinding(const NativeDisplayGeometryRefresh& geometry,
                            std::uint32_t selectedDisplayId,
                            std::uint64_t geometryGeneration) noexcept;

namespace detail {

// Shared callback state intentionally outlives MacScreenCaptureStream when a
// native completion or output callback is already queued. It owns no native
// ScreenCaptureKit object and never borrows the stream owner's `this` pointer.
class MacScreenCaptureState final {
public:
    MacScreenCaptureState(MacScreenCaptureBinding binding,
                          std::shared_ptr<MacCaptureFrameConsumer> consumer) noexcept;

    [[nodiscard]] std::expected<void, MacScreenCaptureError> beginPrepare() noexcept;
    [[nodiscard]] std::expected<void, MacScreenCaptureError> beginStart() noexcept;
    [[nodiscard]] std::expected<void, MacScreenCaptureError> beginStop() noexcept;

    void prepared() noexcept;
    void prepareFailed(MacScreenCaptureError error) noexcept;
    void startCompleted(bool succeeded) noexcept;
    void stopCompleted(bool succeeded) noexcept;
    void nativeFailed() noexcept;
    void fail(MacScreenCaptureError error) noexcept;
    void close() noexcept;
    void invalidateTopology() noexcept;

    [[nodiscard]] MacScreenCaptureFrameDisposition
    consumeFrame(CVPixelBufferRef pixelBuffer,
                 MacScreenCaptureFrameStatus frameStatus) noexcept;

    [[nodiscard]] MacScreenCaptureLifecycleState lifecycleState() const noexcept;
    [[nodiscard]] std::optional<MacScreenCaptureError> lastError() const noexcept;
    [[nodiscard]] MacScreenCaptureFrameDrop lastFrameDrop() const noexcept;
    [[nodiscard]] const MacScreenCaptureBinding& binding() const noexcept { return binding_; }

private:
    void failLocked(MacScreenCaptureError error) noexcept;
    [[nodiscard]] bool topologyCurrentLocked() const noexcept;

    const MacScreenCaptureBinding binding_;
    mutable std::mutex mutex_;
    MacScreenCaptureLifecycleState lifecycleState_{MacScreenCaptureLifecycleState::Idle};
    std::optional<MacScreenCaptureError> lastError_{};
    MacScreenCaptureFrameDrop lastFrameDrop_{MacScreenCaptureFrameDrop::None};
    std::shared_ptr<MacCaptureFrameConsumer> consumer_;
};

// Apple implementation is private Objective-C++; tests inject this C++ seam.
// Methods submit asynchronous native operations and report only synchronous
// submission failures. Completion results arrive through MacScreenCaptureState.
class MacScreenCaptureBackend {
public:
    virtual ~MacScreenCaptureBackend() = default;
    [[nodiscard]] virtual ScreenCapturePreflightStatus preflight() noexcept = 0;
    [[nodiscard]] virtual std::expected<void, MacScreenCaptureError>
    prepare(const MacScreenCaptureBinding& binding,
            const std::shared_ptr<MacScreenCaptureState>& state) noexcept = 0;
    [[nodiscard]] virtual std::expected<void, MacScreenCaptureError>
    start(const std::shared_ptr<MacScreenCaptureState>& state) noexcept = 0;
    [[nodiscard]] virtual std::expected<void, MacScreenCaptureError>
    stop(const std::shared_ptr<MacScreenCaptureState>& state) noexcept = 0;
    virtual void close(const std::shared_ptr<MacScreenCaptureState>& state) noexcept = 0;
};

} // namespace detail

// One-shot ScreenCaptureKit owner. There is deliberately no restart path:
// stop, topology invalidation, native failure, or close retires this instance.
// A fresh validated geometry generation and fresh authorized session binding
// are required before constructing any replacement stream.
class MacScreenCaptureStream final {
public:
    MacScreenCaptureStream(const MacScreenCaptureStream&) = delete;
    MacScreenCaptureStream& operator=(const MacScreenCaptureStream&) = delete;
    MacScreenCaptureStream(MacScreenCaptureStream&&) = delete;
    MacScreenCaptureStream& operator=(MacScreenCaptureStream&&) = delete;
    ~MacScreenCaptureStream() noexcept;

    // Deterministic production state-machine seam used by permission-free
    // CTests. The repository intentionally exposes no native ScreenCaptureKit
    // backend/factory until a concrete R2/R3 macOS authorization capability
    // exists; callers cannot turn a display binding or TCC grant into capture.
    [[nodiscard]] static std::expected<std::unique_ptr<MacScreenCaptureStream>,
                                       MacScreenCaptureError>
    createForTesting(MacScreenCaptureBinding binding,
                     std::shared_ptr<MacCaptureFrameConsumer> consumer,
                     std::unique_ptr<detail::MacScreenCaptureBackend> backend);

    [[nodiscard]] std::expected<void, MacScreenCaptureError> prepare() noexcept;
    [[nodiscard]] std::expected<void, MacScreenCaptureError> start() noexcept;
    [[nodiscard]] std::expected<void, MacScreenCaptureError> stop() noexcept;
    void invalidateTopology() noexcept;
    void close() noexcept;

    [[nodiscard]] MacScreenCaptureLifecycleState state() const noexcept;
    [[nodiscard]] std::optional<MacScreenCaptureError> lastError() const noexcept;
    [[nodiscard]] MacScreenCaptureFrameDrop lastFrameDrop() const noexcept;
    [[nodiscard]] std::uint64_t generation() const noexcept;

private:
    MacScreenCaptureStream(MacScreenCaptureBinding binding,
                           std::shared_ptr<MacCaptureFrameConsumer> consumer,
                           std::unique_ptr<detail::MacScreenCaptureBackend> backend);

    std::shared_ptr<detail::MacScreenCaptureState> state_;
    std::unique_ptr<detail::MacScreenCaptureBackend> backend_;
    mutable std::mutex ownerMutex_;
    bool backendClosed_{};
};

} // namespace rdp::macos
