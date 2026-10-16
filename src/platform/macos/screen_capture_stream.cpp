// SPDX-License-Identifier: GPL-3.0-or-later
#include "platform/macos/screen_capture_stream.h"

#include "platform/macos/native_display_reconfiguration.h"

#include <CoreVideo/CoreVideo.h>

#include <utility>

namespace rdp::macos {

std::expected<MacScreenCaptureBinding, MacScreenCaptureError>
makeMacScreenCaptureBinding(const NativeDisplayGeometryRefresh& geometry,
                            const std::uint32_t selectedDisplayId,
                            const std::uint64_t geometryGeneration) noexcept {
    if (selectedDisplayId == 0 || geometryGeneration == 0) {
        return std::unexpected(MacScreenCaptureError::InvalidBinding);
    }
    if (geometry.generation() != geometryGeneration) {
        return std::unexpected(MacScreenCaptureError::StaleGeometryGeneration);
    }
    if (!geometry.usable(geometryGeneration)) {
        return std::unexpected(MacScreenCaptureError::StaleTopology);
    }
    const auto display = geometry.displayMapping(selectedDisplayId, geometryGeneration);
    if (!display) {
        return std::unexpected(MacScreenCaptureError::MissingDisplay);
    }
    const auto topologyRevision = geometry.topologyRevision(geometryGeneration);
    if (!topologyRevision) {
        return std::unexpected(MacScreenCaptureError::StaleTopology);
    }
    return MacScreenCaptureBinding{display->displayId,
                                   display->physicalPixels.widthPixels,
                                   display->physicalPixels.heightPixels,
                                   geometryGeneration,
                                   *topologyRevision};
}

namespace detail {

MacScreenCaptureState::MacScreenCaptureState(
    const MacScreenCaptureBinding binding,
    std::shared_ptr<MacCaptureFrameConsumer> consumer) noexcept
    : binding_(binding), consumer_(std::move(consumer)) {}

std::expected<void, MacScreenCaptureError>
MacScreenCaptureState::beginPrepare() noexcept {
    std::scoped_lock lock(mutex_);
    if (lifecycleState_ != MacScreenCaptureLifecycleState::Idle) {
        return std::unexpected(MacScreenCaptureError::IllegalTransition);
    }
    if (!topologyCurrentLocked()) {
        failLocked(MacScreenCaptureError::StaleTopology);
        return std::unexpected(MacScreenCaptureError::StaleTopology);
    }
    lifecycleState_ = MacScreenCaptureLifecycleState::Preparing;
    return {};
}

std::expected<void, MacScreenCaptureError>
MacScreenCaptureState::beginStart() noexcept {
    std::scoped_lock lock(mutex_);
    if (lifecycleState_ != MacScreenCaptureLifecycleState::Ready) {
        return std::unexpected(MacScreenCaptureError::IllegalTransition);
    }
    if (!topologyCurrentLocked()) {
        failLocked(MacScreenCaptureError::StaleTopology);
        return std::unexpected(MacScreenCaptureError::StaleTopology);
    }
    lifecycleState_ = MacScreenCaptureLifecycleState::Starting;
    return {};
}

std::expected<void, MacScreenCaptureError>
MacScreenCaptureState::beginStop() noexcept {
    std::scoped_lock lock(mutex_);
    if (lifecycleState_ != MacScreenCaptureLifecycleState::Capturing) {
        return std::unexpected(MacScreenCaptureError::IllegalTransition);
    }
    lifecycleState_ = MacScreenCaptureLifecycleState::Stopping;
    return {};
}

void MacScreenCaptureState::prepared() noexcept {
    std::scoped_lock lock(mutex_);
    if (lifecycleState_ != MacScreenCaptureLifecycleState::Preparing) return;
    if (!topologyCurrentLocked()) {
        failLocked(MacScreenCaptureError::StaleTopology);
        return;
    }
    lifecycleState_ = MacScreenCaptureLifecycleState::Ready;
}

void MacScreenCaptureState::prepareFailed(const MacScreenCaptureError error) noexcept {
    std::scoped_lock lock(mutex_);
    if (lifecycleState_ == MacScreenCaptureLifecycleState::Preparing) {
        failLocked(error);
    }
}

void MacScreenCaptureState::startCompleted(const bool succeeded) noexcept {
    std::scoped_lock lock(mutex_);
    if (lifecycleState_ != MacScreenCaptureLifecycleState::Starting) return;
    if (!succeeded) {
        failLocked(MacScreenCaptureError::StartFailed);
        return;
    }
    if (!topologyCurrentLocked()) {
        failLocked(MacScreenCaptureError::StaleTopology);
        return;
    }
    lifecycleState_ = MacScreenCaptureLifecycleState::Capturing;
}

void MacScreenCaptureState::stopCompleted(const bool succeeded) noexcept {
    std::scoped_lock lock(mutex_);
    if (lifecycleState_ != MacScreenCaptureLifecycleState::Stopping) return;
    if (!succeeded) {
        failLocked(MacScreenCaptureError::StopFailed);
        return;
    }
    lifecycleState_ = MacScreenCaptureLifecycleState::Closed;
    consumer_.reset();
}

void MacScreenCaptureState::nativeFailed() noexcept {
    fail(MacScreenCaptureError::NativeStreamFailed);
}

void MacScreenCaptureState::fail(const MacScreenCaptureError error) noexcept {
    std::scoped_lock lock(mutex_);
    if (lifecycleState_ != MacScreenCaptureLifecycleState::Closed &&
        lifecycleState_ != MacScreenCaptureLifecycleState::Failed) {
        failLocked(error);
    }
}

void MacScreenCaptureState::close() noexcept {
    std::scoped_lock lock(mutex_);
    if (lifecycleState_ != MacScreenCaptureLifecycleState::Failed) {
        lifecycleState_ = MacScreenCaptureLifecycleState::Closed;
    }
    consumer_.reset();
}

void MacScreenCaptureState::invalidateTopology() noexcept {
    std::scoped_lock lock(mutex_);
    if (lifecycleState_ != MacScreenCaptureLifecycleState::Closed &&
        lifecycleState_ != MacScreenCaptureLifecycleState::Failed) {
        failLocked(MacScreenCaptureError::StaleTopology);
    }
}

MacScreenCaptureFrameDisposition MacScreenCaptureState::consumeFrame(
    CVPixelBufferRef const pixelBuffer,
    const MacScreenCaptureFrameStatus frameStatus) noexcept {
    std::shared_ptr<MacCaptureFrameConsumer> consumer;
    {
        std::scoped_lock lock(mutex_);
        if (lifecycleState_ != MacScreenCaptureLifecycleState::Capturing) {
            lastFrameDrop_ = MacScreenCaptureFrameDrop::NotCapturing;
            return MacScreenCaptureFrameDisposition::Dropped;
        }
        if (!topologyCurrentLocked()) {
            lastFrameDrop_ = MacScreenCaptureFrameDrop::StaleTopology;
            failLocked(MacScreenCaptureError::StaleTopology);
            return MacScreenCaptureFrameDisposition::RetireStream;
        }
        if (frameStatus != MacScreenCaptureFrameStatus::Complete) {
            lastFrameDrop_ = MacScreenCaptureFrameDrop::InvalidStatus;
            return MacScreenCaptureFrameDisposition::Dropped;
        }
        if (pixelBuffer == nullptr) {
            lastFrameDrop_ = MacScreenCaptureFrameDrop::MissingBuffer;
            return MacScreenCaptureFrameDisposition::Dropped;
        }
        if (CVPixelBufferGetWidth(pixelBuffer) != binding_.widthPixels ||
            CVPixelBufferGetHeight(pixelBuffer) != binding_.heightPixels) {
            lastFrameDrop_ = MacScreenCaptureFrameDrop::InvalidDimensions;
            return MacScreenCaptureFrameDisposition::Dropped;
        }
        consumer = consumer_;
        if (!consumer) {
            lastFrameDrop_ = MacScreenCaptureFrameDrop::NotCapturing;
            return MacScreenCaptureFrameDisposition::Dropped;
        }
    }

    auto frame = LockedBgraPixelBuffer::lock(pixelBuffer);
    if (!frame) {
        std::scoped_lock lock(mutex_);
        lastFrameDrop_ = frame.error() == BgraBufferError::unsupported_format
                             ? MacScreenCaptureFrameDrop::UnsupportedFormat
                             : MacScreenCaptureFrameDrop::LockFailed;
        return MacScreenCaptureFrameDisposition::Dropped;
    }

    {
        std::scoped_lock lock(mutex_);
        if (lifecycleState_ != MacScreenCaptureLifecycleState::Capturing) {
            lastFrameDrop_ = MacScreenCaptureFrameDrop::NotCapturing;
            return MacScreenCaptureFrameDisposition::Dropped;
        }
        if (!topologyCurrentLocked()) {
            lastFrameDrop_ = MacScreenCaptureFrameDrop::StaleTopology;
            failLocked(MacScreenCaptureError::StaleTopology);
            return MacScreenCaptureFrameDisposition::RetireStream;
        }
    }

    consumer->consume(*frame, binding_.geometryGeneration);

    std::scoped_lock lock(mutex_);
    if (!topologyCurrentLocked()) {
        lastFrameDrop_ = MacScreenCaptureFrameDrop::StaleTopology;
        failLocked(MacScreenCaptureError::StaleTopology);
        return MacScreenCaptureFrameDisposition::RetireStream;
    }
    if (lifecycleState_ != MacScreenCaptureLifecycleState::Capturing) {
        lastFrameDrop_ = MacScreenCaptureFrameDrop::NotCapturing;
        return MacScreenCaptureFrameDisposition::RetireStream;
    }
    lastFrameDrop_ = MacScreenCaptureFrameDrop::None;
    return MacScreenCaptureFrameDisposition::Published;
}

MacScreenCaptureLifecycleState MacScreenCaptureState::lifecycleState() const noexcept {
    std::scoped_lock lock(mutex_);
    return lifecycleState_;
}

std::optional<MacScreenCaptureError> MacScreenCaptureState::lastError() const noexcept {
    std::scoped_lock lock(mutex_);
    return lastError_;
}

MacScreenCaptureFrameDrop MacScreenCaptureState::lastFrameDrop() const noexcept {
    std::scoped_lock lock(mutex_);
    return lastFrameDrop_;
}

void MacScreenCaptureState::failLocked(const MacScreenCaptureError error) noexcept {
    lastError_ = error;
    lifecycleState_ = MacScreenCaptureLifecycleState::Failed;
    consumer_.reset();
}

bool MacScreenCaptureState::topologyCurrentLocked() const noexcept {
    return !NativeDisplayReconfigurationWatch::changedSince(binding_.topologyRevision);
}

} // namespace detail

MacScreenCaptureStream::MacScreenCaptureStream(
    const MacScreenCaptureBinding binding,
    std::shared_ptr<MacCaptureFrameConsumer> consumer,
    std::unique_ptr<detail::MacScreenCaptureBackend> backend)
    : state_(std::make_shared<detail::MacScreenCaptureState>(binding, std::move(consumer))),
      backend_(std::move(backend)) {}

MacScreenCaptureStream::~MacScreenCaptureStream() noexcept {
    close();
}

std::expected<std::unique_ptr<MacScreenCaptureStream>, MacScreenCaptureError>
MacScreenCaptureStream::createNative(
    const MacScreenCaptureBinding binding,
    std::shared_ptr<MacCaptureFrameConsumer> consumer) {
    return createForTesting(binding, std::move(consumer),
                            detail::makeNativeMacScreenCaptureBackend());
}

std::expected<std::unique_ptr<MacScreenCaptureStream>, MacScreenCaptureError>
MacScreenCaptureStream::createForTesting(
    const MacScreenCaptureBinding binding,
    std::shared_ptr<MacCaptureFrameConsumer> consumer,
    std::unique_ptr<detail::MacScreenCaptureBackend> backend) {
    if (binding.displayId == 0 || binding.widthPixels == 0 ||
        binding.heightPixels == 0 || binding.geometryGeneration == 0 ||
        binding.topologyRevision == 0 || !consumer || !backend) {
        return std::unexpected(MacScreenCaptureError::InvalidBinding);
    }
    return std::unique_ptr<MacScreenCaptureStream>(
        new MacScreenCaptureStream(binding, std::move(consumer), std::move(backend)));
}

std::expected<void, MacScreenCaptureError> MacScreenCaptureStream::prepare() noexcept {
    std::scoped_lock ownerLock(ownerMutex_);
    if (backendClosed_) {
        return std::unexpected(MacScreenCaptureError::IllegalTransition);
    }
    if (auto began = state_->beginPrepare(); !began) {
        return began;
    }
    const auto preflight = backend_->preflight();
    if (preflight != ScreenCapturePreflightStatus::Granted) {
        const auto error = preflight == ScreenCapturePreflightStatus::NotGranted
                               ? MacScreenCaptureError::PermissionNotGranted
                               : MacScreenCaptureError::PermissionUnavailable;
        state_->prepareFailed(error);
        return std::unexpected(error);
    }
    auto submitted = backend_->prepare(state_->binding(), state_);
    if (!submitted) {
        state_->prepareFailed(submitted.error());
    }
    return submitted;
}

std::expected<void, MacScreenCaptureError> MacScreenCaptureStream::start() noexcept {
    std::scoped_lock ownerLock(ownerMutex_);
    if (backendClosed_) {
        return std::unexpected(MacScreenCaptureError::IllegalTransition);
    }
    if (auto began = state_->beginStart(); !began) {
        return began;
    }
    auto submitted = backend_->start(state_);
    if (!submitted) {
        state_->fail(submitted.error());
        return submitted;
    }
    return {};
}

std::expected<void, MacScreenCaptureError> MacScreenCaptureStream::stop() noexcept {
    std::scoped_lock ownerLock(ownerMutex_);
    if (backendClosed_) {
        return std::unexpected(MacScreenCaptureError::IllegalTransition);
    }
    if (auto began = state_->beginStop(); !began) {
        return began;
    }
    auto submitted = backend_->stop(state_);
    if (!submitted) {
        state_->fail(submitted.error());
        return submitted;
    }
    return {};
}

void MacScreenCaptureStream::invalidateTopology() noexcept {
    std::scoped_lock ownerLock(ownerMutex_);
    state_->invalidateTopology();
    if (!backendClosed_) {
        backend_->close(state_);
        backendClosed_ = true;
    }
}

void MacScreenCaptureStream::close() noexcept {
    std::scoped_lock ownerLock(ownerMutex_);
    if (!state_ || !backend_) return;
    state_->close();
    if (!backendClosed_) {
        backend_->close(state_);
        backendClosed_ = true;
    }
}

MacScreenCaptureLifecycleState MacScreenCaptureStream::state() const noexcept {
    return state_->lifecycleState();
}

std::optional<MacScreenCaptureError> MacScreenCaptureStream::lastError() const noexcept {
    return state_->lastError();
}

MacScreenCaptureFrameDrop MacScreenCaptureStream::lastFrameDrop() const noexcept {
    return state_->lastFrameDrop();
}

std::uint64_t MacScreenCaptureStream::generation() const noexcept {
    return state_->binding().geometryGeneration;
}

} // namespace rdp::macos
