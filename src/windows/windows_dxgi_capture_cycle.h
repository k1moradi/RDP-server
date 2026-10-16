// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "windows_d3d11_staging_map.h"
#include "windows_desktop_geometry.h"
#include "windows_dxgi_frame_owner.h"

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
        WindowsD3D11StagingCallbacks stagingCallbacks) noexcept;
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
    [[nodiscard]] bool releaseFrame() noexcept;
    // Compare caller-sampled, validated geometry with the pinned snapshot.
    // A changed topology revokes the cycle; no Win32 enumeration is done.
    [[nodiscard]] bool topologyUnchanged(
        const WindowsDesktopLayout &latest) noexcept;
    void cancel() noexcept;

    [[nodiscard]] FramebufferView frame() const noexcept;
    [[nodiscard]] bool closed() const noexcept;

private:
    // In-flight native callbacks can call cancel() synchronously. Deferring
    // actual teardown until the outer method returns prevents a release
    // while a staging callback still uses the acquired DXGI resource.
    void finishCancellation() noexcept;

    WindowsDesktopLayout layout_{};
    WindowsDxgiFrameOwner duplication_;
    WindowsD3D11StagingMap staging_;
    bool operationInProgress_{};
    bool closed_{};
};

} // namespace rdp_server::windows
