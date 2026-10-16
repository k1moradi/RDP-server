// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows_dxgi_capture_cycle.h"

namespace rdp_server::windows
{

WindowsDxgiCaptureCycle::WindowsDxgiCaptureCycle(
    WindowsDesktopLayout layout, WindowsDxgiFrameCallbacks frameCallbacks,
    WindowsD3D11StagingCallbacks stagingCallbacks) noexcept
    : layout_(layout), duplication_(frameCallbacks), staging_(stagingCallbacks),
      closed_(layout.monitorCount == 0 ||
              layout.monitorCount > kMaximumWindowsDesktopMonitors ||
              layout.virtualBounds.widthPixels == 0 ||
              layout.virtualBounds.heightPixels == 0 ||
              duplication_.closed() || staging_.closed())
{
}

WindowsDxgiCaptureCycle::~WindowsDxgiCaptureCycle() noexcept
{
    cancel();
}

WindowsCaptureCycleResult WindowsDxgiCaptureCycle::captureFrame(
    std::uint32_t timeoutMilliseconds) noexcept
{
    if (closed_)
    {
        return WindowsCaptureCycleResult::closed;
    }
    if (operationInProgress_ || staging_.mapped() ||
        duplication_.resource() != nullptr)
    {
        return WindowsCaptureCycleResult::busy;
    }

    operationInProgress_ = true;
    const auto acquired = duplication_.acquireFrame(timeoutMilliseconds);
    WindowsCaptureCycleResult outcome = WindowsCaptureCycleResult::failed;
    if (closed_)
    {
        outcome = WindowsCaptureCycleResult::closed;
    }
    else if (acquired == WindowsDxgiAcquireResult::timeout)
    {
        outcome = WindowsCaptureCycleResult::timeout;
    }
    else if (acquired == WindowsDxgiAcquireResult::invalidWait)
    {
        outcome = WindowsCaptureCycleResult::invalidWait;
    }
    else if (acquired == WindowsDxgiAcquireResult::accessLost)
    {
        closed_ = true;
        outcome = WindowsCaptureCycleResult::accessLost;
    }
    else if (acquired == WindowsDxgiAcquireResult::acquired)
    {
        const auto mapped = staging_.mapFrame(duplication_.resource());
        if (closed_)
        {
            outcome = WindowsCaptureCycleResult::closed;
        }
        else if (mapped == WindowsD3D11MapResult::mapped)
        {
            outcome = WindowsCaptureCycleResult::mapped;
        }
        else
        {
            if (mapped == WindowsD3D11MapResult::notReady)
            {
                outcome = WindowsCaptureCycleResult::notReady;
            }
            else
            {
                closed_ = true;
            }
            // Even a GPU-not-ready result must not retain the duplication
            // lease while the caller waits for the next capture attempt.
            staging_.unmap();
            if (duplication_.releaseFrame() != WindowsDxgiReleaseResult::released)
            {
                closed_ = true;
                outcome = WindowsCaptureCycleResult::failed;
            }
        }
    }
    else
    {
        closed_ = true;
    }

    if (duplication_.closed() || staging_.closed())
    {
        closed_ = true;
    }
    if (closed_)
    {
        finishCancellation();
    }
    operationInProgress_ = false;
    return outcome;
}

bool WindowsDxgiCaptureCycle::releaseFrame() noexcept
{
    if (operationInProgress_ || !staging_.mapped())
    {
        return false;
    }
    operationInProgress_ = true;
    // The frame view must be invalid before DXGI ReleaseFrame. The
    // staging native hook unmaps and drops its staging texture first.
    staging_.unmap();
    const bool success =
        duplication_.releaseFrame() == WindowsDxgiReleaseResult::released;
    if (!success || duplication_.closed() || staging_.closed())
    {
        closed_ = true;
    }
    if (closed_)
    {
        finishCancellation();
    }
    operationInProgress_ = false;
    return success && !closed_;
}

bool WindowsDxgiCaptureCycle::topologyUnchanged(
    const WindowsDesktopLayout &latest) noexcept
{
    if (closed_)
    {
        return false;
    }
    if (layout_ != latest)
    {
        cancel();
        return false;
    }
    return true;
}

void WindowsDxgiCaptureCycle::cancel() noexcept
{
    closed_ = true;
    if (!operationInProgress_)
    {
        finishCancellation();
    }
}

void WindowsDxgiCaptureCycle::finishCancellation() noexcept
{
    staging_.cancel();
    duplication_.cancel();
}

FramebufferView WindowsDxgiCaptureCycle::frame() const noexcept
{
    if (closed_ || operationInProgress_ || !staging_.mapped())
    {
        return {};
    }
    return staging_.frame();
}

bool WindowsDxgiCaptureCycle::closed() const noexcept
{
    return closed_;
}

} // namespace rdp_server::windows
