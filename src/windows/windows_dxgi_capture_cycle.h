// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "windows_dxgi_damage.h"
#include "windows_d3d11_staging_map.h"
#include "windows_desktop_geometry.h"
#include "windows_dxgi_frame_owner.h"
#include "windows_dxgi_pointer_shape.h"

#include <span>
#include <cstdint>

namespace rdp_server::windows
{

enum class WindowsCaptureCycleResult
{
    mapped,
    timeout,
    notReady,
    invalidWait,
    accessLost,
    failed,
    busy,
    closed,
};

// Only consumed synchronously while the existing capture cycle still holds
// its DXGI lease and mapped staging resource. The sink must copy into owned
// storage before returning if R4 will encode on another thread.
struct WindowsCaptureFrameConsumer
{
    void *context{};
    bool (*consume)(void *context, const FramebufferView &frame) noexcept{};
};

enum class WindowsCaptureDamageResult
{
    ready, noFrame, unavailable, invalid, accessLost, failed, busy, closed,
};

enum class WindowsCaptureConsumeResult
{
    consumed,
    noFrame,
    invalidConsumer,
    rejected,
    busy,
    closed,
    releaseFailed,
};

enum class WindowsCapturePointerResult
{
    ready,
    noUpdate,
    noFrame,
    unavailable,
    invalid,
    accessLost,
    failed,
    busy,
    closed,
};

// A REVOCATION-ONLY source of session and graphics-device generations.
// R2/R3 must independently authenticate and authorize the interactive
// session. Matching numbers, or a callback returning true, grant NO access.
// The observation is sampled synchronously on the capture owner thread.
struct WindowsCaptureGeneration
{
    std::uint64_t session{};
    std::uint64_t device{};

    friend bool operator==(const WindowsCaptureGeneration &,
                           const WindowsCaptureGeneration &) = default;
};

struct WindowsCaptureGenerationReader
{
    void *context{};
    bool (*read)(void *context, WindowsCaptureGeneration &current) noexcept{};
};

// Independently owned pointer update for the currently acquired DXGI frame.
// nativeTopLeft is the top-left of the DXGI shape in Win32 virtual-screen
// coordinates and is meaningful only when positionChanged && visible.
// Shape and position updates are independent; a position-only update
// leaves shapeChanged false so R4 retains its prior same-generation shape.
// When shapeChanged is true, shape owns every byte needed after ReleaseFrame.
struct WindowsCapturePointerUpdate final
{
    WindowsCaptureGeneration generation{};
    bool positionChanged{};
    bool visible{};
    WindowsNativePoint nativeTopLeft{};
    bool shapeChanged{};
    WindowsDxgiPointerShape shape{};

    WindowsCapturePointerUpdate() noexcept = default;
    WindowsCapturePointerUpdate(const WindowsCapturePointerUpdate &) = delete;
    WindowsCapturePointerUpdate &operator=(const WindowsCapturePointerUpdate &) = delete;
    WindowsCapturePointerUpdate(WindowsCapturePointerUpdate &&) noexcept = default;
    WindowsCapturePointerUpdate &operator=(WindowsCapturePointerUpdate &&) noexcept = default;
};

// Coordinates the two existing native RAII owners, NOT the R4 graphics
// scheduler or the R2/R3 authorization decision. The caller must already
// own an authorized duplication + D3D11 context, and must serialize calls
// to this nonmoving object on the same thread as the native callbacks.
// Returned pixel views are borrowed, synchronous and valid only until
// releaseFrame, cancel, a topology change, or destruction.
class WindowsDxgiCaptureCycle final
{
public:
    WindowsDxgiCaptureCycle(
        WindowsDesktopLayout layout, WindowsDxgiFrameCallbacks frameCallbacks,
        WindowsD3D11StagingCallbacks stagingCallbacks,
        WindowsDxgiDamageReadCallbacks damageCallbacks = {},
        WindowsCaptureGenerationReader generationReader = {},
        WindowsCaptureGeneration pinnedGeneration = {},
        WindowsDxgiPointerShapeReadCallbacks pointerShapeCallbacks = {},
        PortableRectangle capturedOutputBounds = {}) noexcept;
    ~WindowsDxgiCaptureCycle() noexcept;

    WindowsDxgiCaptureCycle(const WindowsDxgiCaptureCycle &) = delete;
    WindowsDxgiCaptureCycle &operator=(const WindowsDxgiCaptureCycle &) = delete;
    WindowsDxgiCaptureCycle(WindowsDxgiCaptureCycle &&) = delete;
    WindowsDxgiCaptureCycle &operator=(WindowsDxgiCaptureCycle &&) = delete;

    [[nodiscard]] WindowsCaptureCycleResult captureFrame(
        std::uint32_t timeoutMilliseconds) noexcept;
    // Consume the currently mapped frame, then unmap and release its DXGI
    // lease before returning, including sink rejection and cancellation.
    // The synchronous sink cannot retain the borrowed view or call native
    // capture APIs on another thread. This does not authorize a session.
    [[nodiscard]] WindowsCaptureConsumeResult consumeFrame(
        WindowsCaptureFrameConsumer consumer) noexcept;
    // Produce a tightly packed BGRA8 snapshot into caller-owned storage.
    // Does not allocate, retain pixels, or schedule an R4 frame. The mapped
    // staging texture is unmapped and the DXGI lease released on every path.
    // A consumed result alone publishes the independent caller-owned view.
    // Rejected/cancelled/failed requests clear the output view.
    [[nodiscard]] WindowsCaptureConsumeResult copyFrameTo(
        std::span<std::byte> destination, FramebufferView &ownedOutput) noexcept;
    // Sample validated metadata only while this cycle owns the matching
    // frame. Malformed/stale reads revoke the cycle without partial output.
    [[nodiscard]] WindowsCaptureDamageResult readFrameDamage(
        std::span<PortableRectangle> destination,
        std::size_t &writtenCount) noexcept;
    // Consume the latest independently owned pointer state captured from
    // AcquireNextFrame. Shape bytes are copied while that native lease is held,
    // so this remains available even if staging was GPU-not-ready or the frame
    // has since been released. Generation changes leave output unchanged.
    [[nodiscard]] WindowsCapturePointerResult readFramePointerUpdate(
        WindowsCapturePointerUpdate &output) noexcept;
    [[nodiscard]] bool releaseFrame() noexcept;
    // Compare caller-sampled, validated geometry with the pinned snapshot.
    // A changed topology revokes the cycle; no Win32 enumeration is done.
    [[nodiscard]] bool topologyUnchanged(
        const WindowsDesktopLayout &latest) noexcept;
    void cancel() noexcept;

    [[nodiscard]] FramebufferView frame() const noexcept;
    [[nodiscard]] bool closed() const noexcept;

private:
    enum class FrameReleaseOutcome
    {
        released,
        failed,
        closed,
    };

    // Release the currently mapped frame while operationInProgress_ is set.
    // Distinguish native ReleaseFrame failure from successful retirement that
    // synchronously revoked this cycle.
    [[nodiscard]] FrameReleaseOutcome releaseHeldFrame() noexcept;

    // In-flight native callbacks can call cancel() synchronously. Deferring
    // actual teardown until the outer method returns prevents a release
    // while a staging callback still uses the acquired DXGI resource.
    // Called only with operationInProgress_ set; false terminally revokes.
    [[nodiscard]] bool generationUnchanged() noexcept;
    [[nodiscard]] WindowsCapturePointerResult capturePointerUpdate() noexcept;
    void finishCancellation() noexcept;

    WindowsDesktopLayout layout_{};
    WindowsDxgiFrameOwner duplication_;
    WindowsD3D11StagingMap staging_;
    WindowsDxgiDamageReadCallbacks damage_{};
    WindowsCaptureGenerationReader generationReader_{};
    WindowsCaptureGeneration pinnedGeneration_{};
    WindowsDxgiPointerShapeReadCallbacks pointerShape_{};
    PortableRectangle capturedOutputBounds_{};
    WindowsCapturePointerUpdate pendingPointerUpdate_{};
    bool pointerUpdatePending_{};
    bool operationInProgress_{};
    bool closed_{};
};

} // namespace rdp_server::windows
