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
    const auto generationFence = geometry.generationFence(geometryGeneration);
    if (!generationFence) {
        return std::unexpected(MacScreenCaptureError::StaleGeometryGeneration);
    }
    const auto topologyRevision = geometry.topologyRevision(geometryGeneration);
    if (!topologyRevision) {
        return std::unexpected(MacScreenCaptureError::StaleTopology);
    }
    const auto sessionWatchRevision = NativeSessionChangeWatch::coveredRevision();
    if (!sessionWatchRevision || *sessionWatchRevision == 0) {
        return std::unexpected(MacScreenCaptureError::StaleSession);
    }
    return MacScreenCaptureBinding{display->displayId,
                                   display->physicalPixels.widthPixels,
                                   display->physicalPixels.heightPixels,
                                   geometryGeneration,
                                   *generationFence,
                                   *topologyRevision,
                                   *sessionWatchRevision};
}

namespace detail {

MacScreenCaptureState::MacScreenCaptureState(
    MacScreenCaptureBinding binding,
    std::shared_ptr<MacCaptureFrameConsumer> consumer) noexcept
    : binding_(std::move(binding)), consumer_(std::move(consumer)) {}

std::expected<void, MacScreenCaptureError>
MacScreenCaptureState::beginPrepare() noexcept {
    std::scoped_lock lock(mutex_);
    if (lifecycleState_ != MacScreenCaptureLifecycleState::Idle) {
        return std::unexpected(MacScreenCaptureError::IllegalTransition);
    }
    if (const auto stale = staleLifetimeErrorLocked()) {
        failLocked(*stale);
        return std::unexpected(*stale);
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
    if (const auto stale = staleLifetimeErrorLocked()) {
        failLocked(*stale);
        return std::unexpected(*stale);
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
    if (const auto stale = staleLifetimeErrorLocked()) {
        failLocked(*stale);
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
    // Completion may arrive after close. Still record successful native start
    // so that the completion can retire a stream started after owner teardown.
    if (succeeded) {
        nativeStartSucceeded_ = true;
    }
    if (lifecycleState_ != MacScreenCaptureLifecycleState::Starting) return;
    if (!succeeded) {
        failLocked(MacScreenCaptureError::StartFailed);
        return;
    }
    if (const auto stale = staleLifetimeErrorLocked()) {
        failLocked(*stale);
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

bool MacScreenCaptureState::claimNativeStopRequest() noexcept {
    std::scoped_lock lock(mutex_);
    if (nativeStopRequested_) {
        return false;
    }
    nativeStopRequested_ = true;
    return true;
}

bool MacScreenCaptureState::claimNativeStopAfterStarted() noexcept {
    std::scoped_lock lock(mutex_);
    if (!nativeStartSucceeded_ || nativeStopRequested_) {
        return false;
    }
    nativeStopRequested_ = true;
    return true;
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
        if (const auto stale = staleLifetimeErrorLocked()) {
            failStaleFrameLocked(*stale);
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
    const FramebufferView framebuffer = frame->framebufferView();
    if (!framebuffer.valid()) {
        std::scoped_lock lock(mutex_);
        lastFrameDrop_ = MacScreenCaptureFrameDrop::InvalidFramebuffer;
        return MacScreenCaptureFrameDisposition::Dropped;
    }

    {
        std::scoped_lock lock(mutex_);
        if (lifecycleState_ != MacScreenCaptureLifecycleState::Capturing) {
            lastFrameDrop_ = MacScreenCaptureFrameDrop::NotCapturing;
            return MacScreenCaptureFrameDisposition::Dropped;
        }
        if (const auto stale = staleLifetimeErrorLocked()) {
            failStaleFrameLocked(*stale);
            return MacScreenCaptureFrameDisposition::RetireStream;
        }
    }

    // The LockedBgraPixelBuffer remains alive across this synchronous call,
    // so FramebufferView cannot outlive its retained/read-locked CoreVideo bytes.
    consumer->consume(framebuffer, binding_.geometryGeneration);

    std::scoped_lock lock(mutex_);
    if (const auto stale = staleLifetimeErrorLocked()) {
        // Bytes already observed by the synchronous consumer cannot be
        // retracted, but a revoked generation/topology/session lifetime must
        // not report successful publication.
        failStaleFrameLocked(*stale);
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

std::optional<MacScreenCaptureError>
MacScreenCaptureState::staleLifetimeError() const noexcept {
    std::scoped_lock lock(mutex_);
    return staleLifetimeErrorLocked();
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

void MacScreenCaptureState::failStaleFrameLocked(
    const MacScreenCaptureError error) noexcept {
    switch (error) {
    case MacScreenCaptureError::StaleGeometryGeneration:
        lastFrameDrop_ = MacScreenCaptureFrameDrop::StaleGeometryGeneration;
        break;
    case MacScreenCaptureError::StaleTopology:
        lastFrameDrop_ = MacScreenCaptureFrameDrop::StaleTopology;
        break;
    case MacScreenCaptureError::StaleSession:
        lastFrameDrop_ = MacScreenCaptureFrameDrop::StaleSession;
        break;
    default:
        lastFrameDrop_ = MacScreenCaptureFrameDrop::NotCapturing;
        break;
    }
    failLocked(error);
}

bool MacScreenCaptureState::generationCurrentLocked() const noexcept {
    return binding_.generationFence.generation() == binding_.geometryGeneration &&
           binding_.generationFence.current();
}

bool MacScreenCaptureState::topologyCurrentLocked() const noexcept {
    return !NativeDisplayReconfigurationWatch::changedSince(binding_.topologyRevision);
}

bool MacScreenCaptureState::sessionCurrentLocked() const noexcept {
    return NativeSessionChangeWatch::current(binding_.sessionWatchRevision);
}

std::optional<MacScreenCaptureError>
MacScreenCaptureState::staleLifetimeErrorLocked() const noexcept {
    if (!generationCurrentLocked()) {
        return MacScreenCaptureError::StaleGeometryGeneration;
    }
    if (!topologyCurrentLocked()) {
        return MacScreenCaptureError::StaleTopology;
    }
    if (!sessionCurrentLocked()) {
        return MacScreenCaptureError::StaleSession;
    }
    return std::nullopt;
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
MacScreenCaptureStream::createForTesting(
    const MacScreenCaptureBinding binding,
    std::shared_ptr<MacCaptureFrameConsumer> consumer,
    std::unique_ptr<detail::MacScreenCaptureBackend> backend) {
    if (binding.displayId == 0 || binding.widthPixels == 0 ||
        binding.heightPixels == 0 || binding.geometryGeneration == 0 ||
        binding.generationFence.generation() != binding.geometryGeneration ||
        binding.topologyRevision == 0 || binding.sessionWatchRevision == 0 ||
        !consumer || !backend) {
        return std::unexpected(MacScreenCaptureError::InvalidBinding);
    }
    if (!binding.generationFence.current()) {
        return std::unexpected(MacScreenCaptureError::StaleGeometryGeneration);
    }
    if (NativeDisplayReconfigurationWatch::changedSince(
            binding.topologyRevision)) {
        return std::unexpected(MacScreenCaptureError::StaleTopology);
    }
    if (!NativeSessionChangeWatch::current(binding.sessionWatchRevision)) {
        return std::unexpected(MacScreenCaptureError::StaleSession);
    }
    return std::unique_ptr<MacScreenCaptureStream>(
        new MacScreenCaptureStream(binding, std::move(consumer), std::move(backend)));
}

void MacScreenCaptureStream::retireBackend(
    std::unique_lock<std::mutex>& ownerLock) noexcept {
    if (backendClosed_) {
        return;
    }
    if (backendOperationInProgress_) {
        backendRetirementPending_ = true;
        return;
    }

    backendClosed_ = true;
    backendRetirementPending_ = false;
    // A backend close callback may reenter the owner; the closed flag prevents
    // duplicate retirement while the backend object stays owned by this stream.
    ownerLock.unlock();
    backend_->close(state_);
}

void MacScreenCaptureStream::finishBackendOperation(
    std::unique_lock<std::mutex>& ownerLock) noexcept {
    backendOperationInProgress_ = false;
    if (backendRetirementPending_) {
        retireBackend(ownerLock);
    }
}

std::expected<void, MacScreenCaptureError> MacScreenCaptureStream::prepare() noexcept {
    std::unique_lock ownerLock(ownerMutex_);
    if (backendClosed_ || backendOperationInProgress_) {
        return std::unexpected(MacScreenCaptureError::IllegalTransition);
    }
    if (auto began = state_->beginPrepare(); !began) {
        if (state_->lifecycleState() == MacScreenCaptureLifecycleState::Failed) {
            retireBackend(ownerLock);
        }
        return began;
    }

    backendOperationInProgress_ = true;
    ownerLock.unlock();
    const auto preflight = backend_->preflight();
    ownerLock.lock();
    if (backendRetirementPending_) {
        finishBackendOperation(ownerLock);
        return std::unexpected(MacScreenCaptureError::IllegalTransition);
    }
    if (preflight != ScreenCapturePreflightStatus::Granted) {
        const auto error = preflight == ScreenCapturePreflightStatus::NotGranted
                               ? MacScreenCaptureError::PermissionNotGranted
                               : MacScreenCaptureError::PermissionUnavailable;
        state_->prepareFailed(error);
        finishBackendOperation(ownerLock);
        return std::unexpected(error);
    }
    // A native failure reported by a synchronous preflight callback cannot
    // be followed by fresh ScreenCaptureKit preparation.
    if (state_->lifecycleState() != MacScreenCaptureLifecycleState::Preparing) {
        finishBackendOperation(ownerLock);
        return std::unexpected(MacScreenCaptureError::IllegalTransition);
    }
    if (const auto stale = state_->staleLifetimeError()) {
        state_->fail(*stale);
        backendRetirementPending_ = true;
        finishBackendOperation(ownerLock);
        return std::unexpected(*stale);
    }

    ownerLock.unlock();
    auto submitted = backend_->prepare(state_->binding(), state_);
    ownerLock.lock();
    const bool revoked = backendRetirementPending_;
    const auto stale = revoked ? std::optional<MacScreenCaptureError>{}
                               : state_->staleLifetimeError();
    if (stale) {
        state_->fail(*stale);
        backendRetirementPending_ = true;
    } else if (!submitted && !revoked) {
        state_->prepareFailed(submitted.error());
    }
    finishBackendOperation(ownerLock);
    if (revoked) {
        return std::unexpected(MacScreenCaptureError::IllegalTransition);
    }
    if (stale) {
        return std::unexpected(*stale);
    }
    return submitted;
}

std::expected<void, MacScreenCaptureError> MacScreenCaptureStream::start() noexcept {
    std::unique_lock ownerLock(ownerMutex_);
    if (backendClosed_ || backendOperationInProgress_) {
        return std::unexpected(MacScreenCaptureError::IllegalTransition);
    }
    if (auto began = state_->beginStart(); !began) {
        if (state_->lifecycleState() == MacScreenCaptureLifecycleState::Failed) {
            retireBackend(ownerLock);
        }
        return began;
    }

    backendOperationInProgress_ = true;
    ownerLock.unlock();
    auto submitted = backend_->start(state_);
    ownerLock.lock();
    const bool revoked = backendRetirementPending_;
    const auto stale = revoked ? std::optional<MacScreenCaptureError>{}
                               : state_->staleLifetimeError();
    if (stale) {
        state_->fail(*stale);
        backendRetirementPending_ = true;
    } else if (!submitted && !revoked) {
        state_->fail(submitted.error());
    }
    finishBackendOperation(ownerLock);
    if (revoked) {
        return std::unexpected(MacScreenCaptureError::IllegalTransition);
    }
    if (stale) {
        return std::unexpected(*stale);
    }
    return submitted;
}

std::expected<void, MacScreenCaptureError> MacScreenCaptureStream::stop() noexcept {
    std::unique_lock ownerLock(ownerMutex_);
    if (backendClosed_ || backendOperationInProgress_) {
        return std::unexpected(MacScreenCaptureError::IllegalTransition);
    }
    if (auto began = state_->beginStop(); !began) {
        return began;
    }

    backendOperationInProgress_ = true;
    ownerLock.unlock();
    auto submitted = backend_->stop(state_);
    ownerLock.lock();
    const bool revoked = backendRetirementPending_;
    if (!submitted && !revoked) {
        state_->fail(submitted.error());
    }
    finishBackendOperation(ownerLock);
    if (revoked) {
        return std::unexpected(MacScreenCaptureError::IllegalTransition);
    }
    return submitted;
}

void MacScreenCaptureStream::invalidateTopology() noexcept {
    std::unique_lock ownerLock(ownerMutex_);
    state_->invalidateTopology();
    retireBackend(ownerLock);
}

void MacScreenCaptureStream::close() noexcept {
    std::unique_lock ownerLock(ownerMutex_);
    if (!state_ || !backend_) {
        return;
    }
    state_->close();
    retireBackend(ownerLock);
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
