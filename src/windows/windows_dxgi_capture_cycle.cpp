// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows_bgra_frame.h"

#include <cstring>
#include <functional>
#include <span>
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

namespace
{

struct WindowsPackedBgraCopy
{
    std::span<std::byte> destination{};
    FramebufferView candidate{};

    static bool consume(void *raw, const FramebufferView &source) noexcept
    {
        auto &copy = *static_cast<WindowsPackedBgraCopy *>(raw);
        const std::uint64_t rowBytes =
            static_cast<std::uint64_t>(source.widthPixels) *
            kWindowsBgraBytesPerPixel;
        if (!source.valid() || rowBytes == 0 ||
            rowBytes > source.strideBytes ||
            rowBytes > kMaximumWindowsCaptureFrameBytes ||
            source.heightPixels > kMaximumWindowsCaptureFrameBytes / rowBytes)
        {
            return false;
        }

        const std::size_t pitch = static_cast<std::size_t>(rowBytes);
        const std::size_t required = pitch * source.heightPixels;
        if (copy.destination.size() < required)
        {
            return false;
        }

        // A view into the mapped texture is never an owned R4 snapshot.
        // Reject overlapping spans, including any source pitch padding.
        const auto less = std::less<const std::byte *>{};
        const auto *const sourceBegin = source.pixels.data();
        const auto *const sourceEnd = sourceBegin + source.pixels.size();
        const auto *const destinationBegin = copy.destination.data();
        const auto *const destinationEnd = destinationBegin + required;
        if (less(sourceBegin, destinationEnd) &&
            less(destinationBegin, sourceEnd))
        {
            return false;
        }

        for (std::size_t y = 0; y < source.heightPixels; ++y)
        {
            std::memcpy(copy.destination.data() + y * pitch,
                        sourceBegin + y * source.strideBytes, pitch);
        }
        copy.candidate = {
            std::span<const std::byte>(copy.destination.data(), required),
            source.widthPixels, source.heightPixels, pitch};
        return true;
    }
};

} // namespace

WindowsCaptureConsumeResult WindowsDxgiCaptureCycle::copyFrameTo(
    std::span<std::byte> destination, FramebufferView &ownedOutput) noexcept
{
    ownedOutput = {};
    WindowsPackedBgraCopy copy{destination};
    const auto result = consumeFrame(
        {&copy, &WindowsPackedBgraCopy::consume});
    // A failed DXGI ReleaseFrame or revoked session cannot publish pixels,
    // even when copying into the destination buffer itself succeeded.
    if (result == WindowsCaptureConsumeResult::consumed)
    {
        ownedOutput = copy.candidate;
    }
    return result;
}

WindowsCaptureConsumeResult WindowsDxgiCaptureCycle::consumeFrame(
    WindowsCaptureFrameConsumer consumer) noexcept
{
    if (closed_)
    {
        return WindowsCaptureConsumeResult::closed;
    }
    if (operationInProgress_)
    {
        return WindowsCaptureConsumeResult::busy;
    }
    if (!staging_.mapped() || duplication_.resource() == nullptr)
    {
        return WindowsCaptureConsumeResult::noFrame;
    }
    if (consumer.context == nullptr || consumer.consume == nullptr)
    {
        // Reject the sink but do not strand an acquired desktop frame.
        return releaseFrame() ? WindowsCaptureConsumeResult::invalidConsumer
                              : WindowsCaptureConsumeResult::releaseFailed;
    }

    operationInProgress_ = true;
    // The sink can call cancel() or topologyUnchanged(), but both defer
    // native teardown until it returns; nested release/capture is denied.
    const bool accepted = consumer.consume(consumer.context, staging_.frame());
    const bool revoked = closed_;
    staging_.unmap();
    const bool released =
        duplication_.releaseFrame() == WindowsDxgiReleaseResult::released;
    if (!released || duplication_.closed() || staging_.closed())
    {
        closed_ = true;
    }
    if (closed_)
    {
        finishCancellation();
    }
    operationInProgress_ = false;

    if (!released)
    {
        return WindowsCaptureConsumeResult::releaseFailed;
    }
    if (revoked || closed_)
    {
        return WindowsCaptureConsumeResult::closed;
    }
    return accepted ? WindowsCaptureConsumeResult::consumed
                    : WindowsCaptureConsumeResult::rejected;
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
