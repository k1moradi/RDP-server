// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows_dxgi_frame_owner.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <dxgi1_2.h>
#endif

namespace rdp_server::windows
{

WindowsDxgiFrameOwner::WindowsDxgiFrameOwner(
    WindowsDxgiFrameCallbacks callbacks) noexcept
    : callbacks_(callbacks),
      closed_(callbacks.context == nullptr || callbacks.acquire == nullptr ||
              callbacks.release == nullptr)
{
}

WindowsDxgiFrameOwner::~WindowsDxgiFrameOwner() noexcept
{
    cancel();
}

WindowsDxgiAcquireResult WindowsDxgiFrameOwner::acquireFrame(
    std::uint32_t timeoutMilliseconds) noexcept
{
    if (closed_)
    {
        return WindowsDxgiAcquireResult::closed;
    }
    if (resource_ != nullptr || acquireInProgress_ || releaseInProgress_)
    {
        return WindowsDxgiAcquireResult::busy;
    }
    if (timeoutMilliseconds > kMaximumWindowsDxgiFrameWaitMilliseconds)
    {
        return WindowsDxgiAcquireResult::invalidWait;
    }

    void *acquiredResource = nullptr;
    WindowsDxgiFrameInfo acquiredFrameInfo{};
    acquireInProgress_ = true;
    const auto result = callbacks_.acquire(
        callbacks_.context, timeoutMilliseconds,
        acquiredResource, acquiredFrameInfo);
    acquireInProgress_ = false;

    // A synchronous acquire callback may request terminal cancellation. Do not
    // publish a lease into the now-closed owner; return any resource produced
    // by the callback through the ordinary single-release path first.
    if (closed_)
    {
        if (acquiredResource != nullptr)
        {
            resource_ = acquiredResource;
            frameInfo_ = acquiredFrameInfo;
            (void)releaseFrame();
        }
        return WindowsDxgiAcquireResult::closed;
    }

    if (result == WindowsDxgiAcquireResult::acquired &&
        acquiredResource != nullptr)
    {
        resource_ = acquiredResource;
        frameInfo_ = acquiredFrameInfo;
        return result;
    }

    // A broken callback must not leak a successfully acquired native lease.
    // Even a claimed timeout or error with a returned resource is terminal.
    if (acquiredResource != nullptr)
    {
        (void)callbacks_.release(callbacks_.context, acquiredResource);
        closed_ = true;
        return WindowsDxgiAcquireResult::failed;
    }
    if (result == WindowsDxgiAcquireResult::timeout)
    {
        return result;
    }
    closed_ = true;
    if (result == WindowsDxgiAcquireResult::accessLost)
    {
        return result;
    }
    return WindowsDxgiAcquireResult::failed;
}

WindowsDxgiReleaseResult WindowsDxgiFrameOwner::releaseFrame() noexcept
{
    if (resource_ == nullptr)
    {
        return WindowsDxgiReleaseResult::notHeld;
    }
    // Invalidate the borrowed pointer and per-frame metadata before calling
    // the potentially re-entrant native release hook. No second release or
    // pointer-shape read can observe the old lease after this point.
    void *const resourceToRelease = resource_;
    resource_ = nullptr;
    frameInfo_ = {};
    releaseInProgress_ = true;
    const auto outcome = callbacks_.release(callbacks_.context,
                                            resourceToRelease);
    releaseInProgress_ = false;
    if (outcome != WindowsDxgiReleaseResult::released)
    {
        closed_ = true;
    }
    return outcome;
}

void WindowsDxgiFrameOwner::cancel() noexcept
{
    closed_ = true;
    (void)releaseFrame();
}

void *WindowsDxgiFrameOwner::resource() const noexcept
{
    return resource_;
}

WindowsDxgiFrameInfo WindowsDxgiFrameOwner::frameInfo() const noexcept
{
    return resource_ != nullptr ? frameInfo_ : WindowsDxgiFrameInfo{};
}

bool WindowsDxgiFrameOwner::closed() const noexcept
{
    return closed_;
}

#ifdef _WIN32
namespace
{

WindowsDxgiAcquireResult acquireNativeFrame(
    void *context, std::uint32_t timeoutMilliseconds,
    void *&resource, WindowsDxgiFrameInfo &portableFrameInfo) noexcept
{
    auto &duplication = *static_cast<IDXGIOutputDuplication *>(context);
    DXGI_OUTDUPL_FRAME_INFO frameInfo{};
    IDXGIResource *nativeResource = nullptr;
    const HRESULT result = duplication.AcquireNextFrame(
        timeoutMilliseconds, &frameInfo, &nativeResource);
    if (FAILED(result))
    {
        // COM pointers returned on failure must never leak even if a
        // broken driver violates the ordinary output-parameter contract.
        if (nativeResource != nullptr)
        {
            nativeResource->Release();
        }
        if (result == DXGI_ERROR_WAIT_TIMEOUT)
        {
            return WindowsDxgiAcquireResult::timeout;
        }
        if (result == DXGI_ERROR_ACCESS_LOST)
        {
            return WindowsDxgiAcquireResult::accessLost;
        }
        return WindowsDxgiAcquireResult::failed;
    }
    if (nativeResource == nullptr)
    {
        // S_OK creates an outstanding frame even if a faulty driver
        // neglected its resource output. Restore the DXGI protocol state.
        (void)duplication.ReleaseFrame();
        return WindowsDxgiAcquireResult::failed;
    }

    const bool pointerPositionUpdated =
        frameInfo.LastMouseUpdateTime.QuadPart != 0;
    const bool pointerVisible =
        pointerPositionUpdated && frameInfo.PointerPosition.Visible != FALSE;
    portableFrameInfo = {
        pointerPositionUpdated,
        pointerVisible,
        pointerVisible
            ? static_cast<std::int32_t>(frameInfo.PointerPosition.Position.x)
            : 0,
        pointerVisible
            ? static_cast<std::int32_t>(frameInfo.PointerPosition.Position.y)
            : 0,
        frameInfo.PointerShapeBufferSize};
    resource = nativeResource;
    return WindowsDxgiAcquireResult::acquired;
}

WindowsDxgiReleaseResult releaseNativeFrame(
    void *context, void *resource) noexcept
{
    auto &duplication = *static_cast<IDXGIOutputDuplication *>(context);
    static_cast<IDXGIResource *>(resource)->Release();
    const HRESULT result = duplication.ReleaseFrame();
    if (result == S_OK)
    {
        return WindowsDxgiReleaseResult::released;
    }
    if (result == DXGI_ERROR_ACCESS_LOST)
    {
        return WindowsDxgiReleaseResult::accessLost;
    }
    return WindowsDxgiReleaseResult::failed;
}

} // namespace

WindowsDxgiFrameCallbacks windowsDxgiFrameCallbacks(
    IDXGIOutputDuplication &duplication) noexcept
{
    return {&duplication, &acquireNativeFrame, &releaseNativeFrame};
}
#endif

} // namespace rdp_server::windows
