// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows_bgra_frame.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <functional>
#include <limits>
#include <span>
#include <utility>
#include "windows_dxgi_capture_cycle.h"

namespace rdp_server::windows
{

WindowsDxgiCaptureCycle::WindowsDxgiCaptureCycle(
    WindowsDesktopLayout layout, WindowsDxgiFrameCallbacks frameCallbacks,
    WindowsD3D11StagingCallbacks stagingCallbacks,
    WindowsDxgiDamageReadCallbacks damageCallbacks,
    WindowsCaptureGenerationReader generationReader,
    WindowsCaptureGeneration pinnedGeneration,
    WindowsDxgiPointerShapeReadCallbacks pointerShapeCallbacks,
    PortableRectangle capturedOutputBounds) noexcept
    : layout_(layout), duplication_(frameCallbacks), staging_(stagingCallbacks),
      damage_(damageCallbacks), generationReader_(generationReader),
      pinnedGeneration_(pinnedGeneration), pointerShape_(pointerShapeCallbacks),
      capturedOutputBounds_(capturedOutputBounds),
      closed_(layout.monitorCount == 0 ||
              layout.monitorCount > kMaximumWindowsDesktopMonitors ||
              layout.virtualBounds.widthPixels == 0 ||
              layout.virtualBounds.heightPixels == 0 ||
              duplication_.closed() || staging_.closed() ||
              // Incomplete revocation sources are terminal, never opt-out.
              ((generationReader.context != nullptr ||
                generationReader.read != nullptr ||
                pinnedGeneration.session != 0 ||
                pinnedGeneration.device != 0) &&
               (generationReader.context == nullptr ||
                generationReader.read == nullptr ||
                pinnedGeneration.session == 0 ||
                pinnedGeneration.device == 0)))
{
    const bool pointerIntegrationRequested =
        pointerShape_.context != nullptr || pointerShape_.read != nullptr ||
        capturedOutputBounds_.widthPixels != 0 ||
        capturedOutputBounds_.heightPixels != 0;
    if (closed_ || !pointerIntegrationRequested)
    {
        return;
    }

    // Pointer updates become asynchronously retainable R4 data, so this path
    // is available only with the same nonzero revocation generation already
    // used for pixels/damage and an exact selected monitor rectangle.
    if (pointerShape_.context == nullptr || pointerShape_.read == nullptr ||
        capturedOutputBounds_.widthPixels == 0 ||
        capturedOutputBounds_.heightPixels == 0 ||
        generationReader_.context == nullptr || generationReader_.read == nullptr ||
        pinnedGeneration_.session == 0 || pinnedGeneration_.device == 0)
    {
        closed_ = true;
        return;
    }

    std::size_t matchingOutputs = 0;
    for (std::size_t index = 0; index < layout_.monitorCount; ++index)
    {
        if (layout_.monitors[index] == capturedOutputBounds_)
        {
            ++matchingOutputs;
        }
    }
    if (matchingOutputs != 1)
    {
        closed_ = true;
    }
}

WindowsDxgiCaptureCycle::~WindowsDxgiCaptureCycle() noexcept
{
    cancel();
}

bool WindowsDxgiCaptureCycle::generationUnchanged() noexcept
{
    if (generationReader_.read == nullptr)
    {
        // Legacy fixture/no generation source: NOT production authorization.
        return true;
    }
    WindowsCaptureGeneration current{};
    if (!generationReader_.read(generationReader_.context, current) ||
        closed_ || current != pinnedGeneration_)
    {
        closed_ = true;
        return false;
    }
    return true;
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
    if (!generationUnchanged())
    {
        finishCancellation();
        operationInProgress_ = false;
        return WindowsCaptureCycleResult::closed;
    }
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
    else if (acquired == WindowsDxgiAcquireResult::acquired &&
             !generationUnchanged())
    {
        // DXGI acquired a lease but the session/output switched before
        // mapping: cancellation releases that resource exactly once.
        outcome = WindowsCaptureCycleResult::closed;
    }
    else if (acquired == WindowsDxgiAcquireResult::acquired)
    {
        // Copy pointer position/shape before staging can return notReady and
        // force this native frame lease to be released. Pointer bytes are
        // independently owned and remain pending until R4 consumes them.
        const auto pointerResult = capturePointerUpdate();
        if (pointerResult == WindowsCapturePointerResult::accessLost)
        {
            closed_ = true;
            outcome = WindowsCaptureCycleResult::accessLost;
        }
        else if (pointerResult == WindowsCapturePointerResult::invalid ||
                 pointerResult == WindowsCapturePointerResult::failed ||
                 pointerResult == WindowsCapturePointerResult::closed)
        {
            closed_ = true;
            outcome = pointerResult == WindowsCapturePointerResult::closed
                          ? WindowsCaptureCycleResult::closed
                          : WindowsCaptureCycleResult::failed;
        }
        else
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
                // Any cursor update is already independently owned above.
                staging_.unmap();
                const auto releaseResult = duplication_.releaseFrame();
                if (releaseResult != WindowsDxgiReleaseResult::released)
                {
                    closed_ = true;
                    outcome = WindowsCaptureCycleResult::failed;
                }
                else if (outcome == WindowsCaptureCycleResult::notReady &&
                         closed_)
                {
                    // A synchronous ReleaseFrame callback may revoke this
                    // cycle. Only override the retryable GPU-not-ready result;
                    // earlier terminal map errors keep their failed outcome.
                    outcome = WindowsCaptureCycleResult::closed;
                }
            }
        }
    }
    else
    {
        closed_ = true;
    }

    if (!closed_ && !generationUnchanged())
    {
        outcome = WindowsCaptureCycleResult::closed;
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
    if (!generationUnchanged())
    {
        finishCancellation();
        operationInProgress_ = false;
        return WindowsCaptureConsumeResult::closed;
    }
    // The sink can call cancel() or topologyUnchanged(), but both defer
    // native teardown until it returns; nested release/capture is denied.
    const bool accepted = consumer.consume(consumer.context, staging_.frame());
    // Catch a session/output switch during synchronous pixel consumption.
    if (!closed_)
    {
        (void)generationUnchanged();
    }
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

WindowsCaptureDamageResult WindowsDxgiCaptureCycle::readFrameDamage(
    std::span<PortableRectangle> destination,
    std::size_t &writtenCount) noexcept
{
    if (closed_)
        return WindowsCaptureDamageResult::closed;
    if (operationInProgress_)
        return WindowsCaptureDamageResult::busy;
    if (!staging_.mapped() || duplication_.resource() == nullptr)
        return WindowsCaptureDamageResult::noFrame;
    if (damage_.context == nullptr || damage_.read == nullptr)
    {
        cancel();
        return WindowsCaptureDamageResult::unavailable;
    }

    operationInProgress_ = true;
    if (!generationUnchanged())
    {
        finishCancellation();
        operationInProgress_ = false;
        return WindowsCaptureDamageResult::closed;
    }
    std::array<PortableRectangle,kMaximumWindowsDxgiDamageRectangles> normalized{};
    std::size_t count = 0;
    const auto view = staging_.frame();
    const auto status = readWindowsDxgiFrameDamage(
        damage_,{view.widthPixels,view.heightPixels},normalized,count);
    // Never publish damage from a generation that changed during read.
    if (!closed_)
    {
        (void)generationUnchanged();
    }
    const bool cancelled = closed_;
    if (status != WindowsDxgiDamageReadResult::ready ||
        count > destination.size())
        closed_ = true;
    if (closed_)
    {
        // If a callback cancelled the frame, unmap/release AFTER its return.
        finishCancellation();
        operationInProgress_ = false;
        if (cancelled)
            return WindowsCaptureDamageResult::closed;
        if (status == WindowsDxgiDamageReadResult::accessLost)
            return WindowsCaptureDamageResult::accessLost;
        if (status == WindowsDxgiDamageReadResult::failed)
            return WindowsCaptureDamageResult::failed;
        return WindowsCaptureDamageResult::invalid;
    }
    std::copy_n(normalized.begin(),count,destination.begin());
    writtenCount=count;
    operationInProgress_=false;
    return WindowsCaptureDamageResult::ready;
}

WindowsCapturePointerResult WindowsDxgiCaptureCycle::capturePointerUpdate() noexcept
{
    if (pointerShape_.context == nullptr || pointerShape_.read == nullptr)
    {
        return WindowsCapturePointerResult::unavailable;
    }
    if (!generationUnchanged())
    {
        return WindowsCapturePointerResult::closed;
    }

    const WindowsDxgiFrameInfo frameInfo = duplication_.frameInfo();
    if (!frameInfo.pointerPositionUpdated &&
        frameInfo.pointerShapeBufferSize == 0)
    {
        return WindowsCapturePointerResult::noUpdate;
    }

    WindowsCapturePointerUpdate candidate{};
    candidate.generation = pinnedGeneration_;
    candidate.positionChanged = frameInfo.pointerPositionUpdated;
    candidate.visible =
        candidate.positionChanged && frameInfo.pointerVisible;
    if (candidate.positionChanged && candidate.visible)
    {
        const std::int64_t nativeX =
            static_cast<std::int64_t>(capturedOutputBounds_.x) +
            frameInfo.pointerX;
        const std::int64_t nativeY =
            static_cast<std::int64_t>(capturedOutputBounds_.y) +
            frameInfo.pointerY;
        if (nativeX < std::numeric_limits<std::int32_t>::min() ||
            nativeX > std::numeric_limits<std::int32_t>::max() ||
            nativeY < std::numeric_limits<std::int32_t>::min() ||
            nativeY > std::numeric_limits<std::int32_t>::max())
        {
            return WindowsCapturePointerResult::invalid;
        }
        candidate.nativeTopLeft = {
            static_cast<std::int32_t>(nativeX),
            static_cast<std::int32_t>(nativeY)};
    }

    if (frameInfo.pointerShapeBufferSize != 0)
    {
        const auto shapeResult = readWindowsDxgiPointerShape(
            pointerShape_, frameInfo.pointerShapeBufferSize, candidate.shape);
        if (closed_)
        {
            return WindowsCapturePointerResult::closed;
        }
        if (shapeResult != WindowsDxgiPointerShapeReadResult::ready)
        {
            if (shapeResult == WindowsDxgiPointerShapeReadResult::accessLost)
                return WindowsCapturePointerResult::accessLost;
            if (shapeResult == WindowsDxgiPointerShapeReadResult::invalid ||
                shapeResult == WindowsDxgiPointerShapeReadResult::moreData)
                return WindowsCapturePointerResult::invalid;
            return WindowsCapturePointerResult::failed;
        }
        candidate.shapeChanged = true;
    }

    if (pointerUpdatePending_)
    {
        // Shape and position timestamps are independent. Merge any unread
        // half of the prior state only when this frame has no newer value for
        // that half, so shape-only and position-only frames cannot erase one
        // another before R4 consumes the owned update.
        if (!candidate.positionChanged &&
            pendingPointerUpdate_.positionChanged)
        {
            candidate.positionChanged = true;
            candidate.visible = pendingPointerUpdate_.visible;
            candidate.nativeTopLeft = pendingPointerUpdate_.nativeTopLeft;
        }
        if (!candidate.shapeChanged && pendingPointerUpdate_.shapeChanged)
        {
            candidate.shapeChanged = true;
            candidate.shape = std::move(pendingPointerUpdate_.shape);
        }
    }

    // A session/device change during GetFramePointerShape invalidates both
    // metadata and independently copied bytes before they can become pending.
    if (!generationUnchanged())
    {
        return WindowsCapturePointerResult::closed;
    }

    pendingPointerUpdate_ = std::move(candidate);
    pointerUpdatePending_ = true;
    return WindowsCapturePointerResult::ready;
}

WindowsCapturePointerResult WindowsDxgiCaptureCycle::readFramePointerUpdate(
    WindowsCapturePointerUpdate &output) noexcept
{
    if (closed_)
        return WindowsCapturePointerResult::closed;
    if (operationInProgress_)
        return WindowsCapturePointerResult::busy;
    if (pointerShape_.context == nullptr || pointerShape_.read == nullptr ||
        capturedOutputBounds_.widthPixels == 0 ||
        capturedOutputBounds_.heightPixels == 0 ||
        generationReader_.context == nullptr || generationReader_.read == nullptr)
    {
        return WindowsCapturePointerResult::unavailable;
    }
    if (!pointerUpdatePending_)
        return WindowsCapturePointerResult::noUpdate;

    operationInProgress_ = true;
    if (!generationUnchanged())
    {
        finishCancellation();
        operationInProgress_ = false;
        return WindowsCapturePointerResult::closed;
    }

    output = std::move(pendingPointerUpdate_);
    pendingPointerUpdate_ = {};
    pointerUpdatePending_ = false;
    operationInProgress_ = false;
    return WindowsCapturePointerResult::ready;
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
    // A generation/device/session revocation invalidates even independently
    // copied but not-yet-published cursor state.
    pendingPointerUpdate_ = {};
    pointerUpdatePending_ = false;
    staging_.cancel();
    duplication_.cancel();
}

FramebufferView WindowsDxgiCaptureCycle::frame() const noexcept
{
    // A raw borrowed view cannot be revalidated once returned; guarded
    // cycles expose frames only through consumeFrame/copyFrameTo.
    if (closed_ || operationInProgress_ || !staging_.mapped() ||
        generationReader_.read != nullptr)
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
