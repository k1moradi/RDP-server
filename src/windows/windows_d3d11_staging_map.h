// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "core/framebuffer_view.h"
#include "core/geometry.h"

#include <cstddef>

#ifdef _WIN32
struct ID3D11Device;
struct ID3D11DeviceContext;
struct ID3D11Texture2D;
#endif

namespace rdp_server::windows
{

enum class WindowsD3D11MapResult
{
    mapped,
    notReady,
    invalidFrame,
    failed,
    busy,
    closed,
};

// Callbacks are owned by the future authorized R2/R3 capture context. The
// successful mappingHandle owns its CPU-visible staging texture and must be
// released exactly once before the matching DXGI frame lease is released.
struct WindowsD3D11MappedData
{
    const std::byte *pixels{};
    std::size_t availableBytes{};
    PixelSize dimensions{};
    std::size_t rowPitchBytes{};
    void *mappingHandle{};
};

struct WindowsD3D11StagingCallbacks
{
    void *context{};
    WindowsD3D11MapResult (*stageAndMap)(
        void *context, void *acquiredResource,
        WindowsD3D11MappedData &output) noexcept{};
    void (*unmapAndRelease)(void *context, void *mappingHandle) noexcept{};
};

// At most one synchronous mapped BGRA view per native owner; no allocations
// or frame copies are made by this state machine. R4 must own its frame data
// before it can enqueue work asynchronously. All callbacks and the owner's
// methods are single-thread affine and must not be used after cancellation.
class WindowsD3D11StagingMap final
{
public:
    explicit WindowsD3D11StagingMap(
        WindowsD3D11StagingCallbacks callbacks) noexcept;
    ~WindowsD3D11StagingMap() noexcept;

    WindowsD3D11StagingMap(const WindowsD3D11StagingMap &) = delete;
    WindowsD3D11StagingMap &operator=(const WindowsD3D11StagingMap &) = delete;
    WindowsD3D11StagingMap(WindowsD3D11StagingMap &&) = delete;
    WindowsD3D11StagingMap &operator=(WindowsD3D11StagingMap &&) = delete;

    [[nodiscard]] WindowsD3D11MapResult mapFrame(
        void *acquiredResource) noexcept;
    void unmap() noexcept;
    void cancel() noexcept;

    // The returned view must never escape this owner's mapped lifetime.
    [[nodiscard]] FramebufferView frame() const noexcept;
    [[nodiscard]] bool mapped() const noexcept;
    [[nodiscard]] bool closed() const noexcept;

private:
    WindowsD3D11StagingCallbacks callbacks_{};
    FramebufferView frame_{};
    void *mappingHandle_{};
    bool callbackInProgress_{};
    bool closed_{};
};

#ifdef _WIN32
// Native context borrows an already-authorized D3D11 device and IMMEDIATE
// context; it does not create a device, output duplication or desktop. The
// context must outlive the staging owner using its callbacks. All calls to
// the immediate context must be serialized by the caller.
class WindowsD3D11NativeStagingContext final
{
public:
    WindowsD3D11NativeStagingContext(
        ID3D11Device &device, ID3D11DeviceContext &immediateContext) noexcept;
    ~WindowsD3D11NativeStagingContext() noexcept;
    WindowsD3D11NativeStagingContext(const WindowsD3D11NativeStagingContext &) = delete;
    WindowsD3D11NativeStagingContext &operator=(
        const WindowsD3D11NativeStagingContext &) = delete;
    WindowsD3D11NativeStagingContext(WindowsD3D11NativeStagingContext &&) = delete;
    WindowsD3D11NativeStagingContext &operator=(
        WindowsD3D11NativeStagingContext &&) = delete;

    [[nodiscard]] WindowsD3D11StagingCallbacks callbacks() noexcept;

    // Implementation detail for non-owning native callback functions.
    [[nodiscard]] ID3D11Device &device() const noexcept;
    [[nodiscard]] ID3D11DeviceContext &immediateContext() const noexcept;
    [[nodiscard]] bool hasMapping() const noexcept;
    void setMapping(ID3D11Texture2D &texture) noexcept;
    void releaseMapping() noexcept;

private:
    ID3D11Device *device_{};
    ID3D11DeviceContext *context_{};
    ID3D11Texture2D *staging_{};
};
#endif

} // namespace rdp_server::windows
