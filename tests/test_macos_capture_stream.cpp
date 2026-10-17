// SPDX-License-Identifier: GPL-3.0-or-later
#include "platform/macos/native_display_reconfiguration.h"
#include "platform/macos/native_session_change_watch.h"
#include "platform/macos/screen_capture_stream.h"

#include <CoreFoundation/CoreFoundation.h>
#include <CoreVideo/CoreVideo.h>

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string_view>

namespace {

using namespace rdp::macos;
using rdp::macos::detail::MacScreenCaptureBackend;
using rdp::macos::detail::MacScreenCaptureState;

template <typename Stream>
concept ExposesNativeCaptureFactory =
    requires(MacScreenCaptureBinding binding,
             std::shared_ptr<MacCaptureFrameConsumer> consumer) {
        Stream::createNative(binding, consumer);
    };

static_assert(!ExposesNativeCaptureFactory<MacScreenCaptureStream>,
              "native ScreenCaptureKit factory must remain quarantined");

struct SessionWatchFixture final {
    NativeSessionChangeRecorder recorder{};
    std::uint64_t registrationEpoch{};
    std::size_t removeCalls{};

    static bool install(void* const context, const std::uint64_t epoch,
                        const NativeSessionChangeRecorder callback) noexcept {
        auto& self = *static_cast<SessionWatchFixture*>(context);
        self.registrationEpoch = epoch;
        self.recorder = callback;
        return callback != nullptr && epoch != 0;
    }

    static bool remove(void* const context) noexcept {
        auto& self = *static_cast<SessionWatchFixture*>(context);
        ++self.removeCalls;
        self.recorder = nullptr;
        self.registrationEpoch = 0;
        return true;
    }

    [[nodiscard]] NativeSessionChangeWatchCallbacks callbacks() noexcept {
        return {this, &install, &remove};
    }

    void recordChange() const noexcept {
        assert(recorder != nullptr && registrationEpoch != 0);
        recorder(registrationEpoch);
    }
};

SessionWatchFixture* gSessionWatchFixture{};

struct SnapshotFixture {
    NativeDisplayObservation display{100, 0, 0, 2, 2, 2, 2, 0, 0};
    std::size_t calls{};
};

[[nodiscard]] NativeDisplayReadStatus readDisplay(
    void* const context, std::span<NativeDisplayObservation> destination,
    std::size_t& reportedCount) noexcept {
    auto& fixture = *static_cast<SnapshotFixture*>(context);
    ++fixture.calls;
    if (destination.empty()) {
        return NativeDisplayReadStatus::Unavailable;
    }
    destination[0] = fixture.display;
    reportedCount = 1;
    return NativeDisplayReadStatus::Ok;
}

struct GeometryFixture {
    SnapshotFixture snapshotFixture{};
    NativeDisplayGeometryRefresh geometry{};

    [[nodiscard]] std::uint64_t refresh() {
        snapshotFixture.calls = 0;
        auto generation = geometry.refresh(&readDisplay, &snapshotFixture);
        assert(generation && snapshotFixture.calls == 2);
        return *generation;
    }

    [[nodiscard]] MacScreenCaptureBinding bindingFor(
        const std::uint32_t displayId, const std::uint64_t generation) const {
        auto result = makeMacScreenCaptureBinding(geometry, displayId, generation);
        assert(result);
        return *result;
    }
};

struct PixelBufferOwner {
    CVPixelBufferRef value{};
    PixelBufferOwner(const PixelBufferOwner&) = delete;
    PixelBufferOwner& operator=(const PixelBufferOwner&) = delete;
    PixelBufferOwner() = default;
    PixelBufferOwner(PixelBufferOwner&& other) noexcept : value(other.value) {
        other.value = nullptr;
    }
    PixelBufferOwner& operator=(PixelBufferOwner&& other) noexcept {
        if (this != &other) {
            if (value != nullptr) CVPixelBufferRelease(value);
            value = other.value;
            other.value = nullptr;
        }
        return *this;
    }
    ~PixelBufferOwner() {
        if (value != nullptr) CVPixelBufferRelease(value);
    }
};

[[nodiscard]] PixelBufferOwner makePixelBuffer(
    std::span<std::byte> bytes, const std::size_t width, const std::size_t height,
    const OSType format, const std::size_t bytesPerRow) {
    PixelBufferOwner owner;
    const auto status = CVPixelBufferCreateWithBytes(
        kCFAllocatorDefault, width, height, format, bytes.data(), bytesPerRow,
        nullptr, nullptr, nullptr, &owner.value);
    assert(status == kCVReturnSuccess && owner.value != nullptr);
    return owner;
}

class RecordingConsumer final : public MacCaptureFrameConsumer {
public:
    void consume(const FramebufferView& frame,
                 const std::uint64_t generation) noexcept override {
        ++calls;
        assert(frame.valid());
        lastGeneration = generation;
        lastWidth = frame.widthPixels;
        lastHeight = frame.heightPixels;
        lastStride = frame.strideBytes;
        lastByteCount = frame.pixels.size();
        lastPixels = frame.pixels.data();
        assert(lastStride >= lastWidth * 4U);
        if (expectedPixels != nullptr) {
            assert(lastPixels == expectedPixels);
        }
        if (changeTopologyDuringConsume) {
            NativeDisplayReconfigurationWatch::recordTopologyChange();
        }
        if (changeSessionDuringConsume) {
            assert(gSessionWatchFixture != nullptr);
            gSessionWatchFixture->recordChange();
        }
        if (refreshGeometryDuringConsume && geometryToRefresh != nullptr) {
            refreshGeometryDuringConsume = false;
            refreshedGeneration = geometryToRefresh->refresh();
        }
        if (stopDuringConsume && streamToStop != nullptr) {
            stopDuringConsume = false;
            stopSucceeded = streamToStop->stop().has_value();
        }
        if (closeDuringConsume && streamToClose != nullptr) {
            closeDuringConsume = false;
            streamToClose->close();
        }
    }

    std::size_t calls{};
    std::uint64_t lastGeneration{};
    std::size_t lastWidth{};
    std::size_t lastHeight{};
    std::size_t lastStride{};
    std::size_t lastByteCount{};
    const std::byte* lastPixels{};
    const std::byte* expectedPixels{};
    MacScreenCaptureStream* streamToStop{};
    MacScreenCaptureStream* streamToClose{};
    GeometryFixture* geometryToRefresh{};
    std::uint64_t refreshedGeneration{};
    bool changeTopologyDuringConsume{};
    bool changeSessionDuringConsume{};
    bool refreshGeometryDuringConsume{};
    bool stopDuringConsume{};
    bool stopSucceeded{};
    bool closeDuringConsume{};
};

class FakeBackend final : public MacScreenCaptureBackend {
public:
    enum class ReentryStage : std::uint8_t {
        None,
        Preflight,
        Prepare,
        Start,
        Stop,
        Close,
    };
    enum class ReentryAction : std::uint8_t { Close, InvalidateTopology };
    enum class GeometryRefreshStage : std::uint8_t {
        None,
        Preflight,
        Prepare,
        Start,
    };

    ScreenCapturePreflightStatus preflight() noexcept override {
        ++preflightCalls;
        reenterOwner(ReentryStage::Preflight);
        refreshGeometry(GeometryRefreshStage::Preflight);
        if (revokeSessionDuringPreflight) {
            revokeSessionDuringPreflight = false;
            assert(gSessionWatchFixture != nullptr);
            gSessionWatchFixture->recordChange();
        }
        return preflightStatus;
    }

    std::expected<void, MacScreenCaptureError>
    prepare(const MacScreenCaptureBinding& receivedBinding,
            const std::shared_ptr<MacScreenCaptureState>& receivedState) noexcept override {
        ++prepareCalls;
        lastBinding = receivedBinding;
        state = receivedState;
        reenterOwner(ReentryStage::Prepare);
        refreshGeometry(GeometryRefreshStage::Prepare);
        if (revokeSessionDuringPrepare) {
            revokeSessionDuringPrepare = false;
            assert(gSessionWatchFixture != nullptr);
            gSessionWatchFixture->recordChange();
        }
        if (prepareRequestError) return std::unexpected(*prepareRequestError);
        return {};
    }

    std::expected<void, MacScreenCaptureError>
    start(const std::shared_ptr<MacScreenCaptureState>& receivedState) noexcept override {
        ++startCalls;
        state = receivedState;
        reenterOwner(ReentryStage::Start);
        refreshGeometry(GeometryRefreshStage::Start);
        if (revokeSessionDuringStart) {
            revokeSessionDuringStart = false;
            assert(gSessionWatchFixture != nullptr);
            gSessionWatchFixture->recordChange();
        }
        if (startRequestError) return std::unexpected(*startRequestError);
        return {};
    }

    std::expected<void, MacScreenCaptureError>
    stop(const std::shared_ptr<MacScreenCaptureState>& receivedState) noexcept override {
        ++stopCalls;
        state = receivedState;
        reenterOwner(ReentryStage::Stop);
        if (stopRequestError) return std::unexpected(*stopRequestError);
        claimNativeStop(receivedState);
        return {};
    }

    void close(const std::shared_ptr<MacScreenCaptureState>& receivedState) noexcept override {
        ++closeCalls;
        state = receivedState;
        reenterOwner(ReentryStage::Close);
        claimNativeStop(receivedState);
    }

    ScreenCapturePreflightStatus preflightStatus{ScreenCapturePreflightStatus::Granted};
    std::optional<MacScreenCaptureError> prepareRequestError{};
    std::optional<MacScreenCaptureError> startRequestError{};
    std::optional<MacScreenCaptureError> stopRequestError{};
    std::shared_ptr<MacScreenCaptureState> state{};
    MacScreenCaptureBinding lastBinding{};
    bool claimNativeStopRequests{};
    bool revokeSessionDuringPreflight{};
    bool revokeSessionDuringPrepare{};
    bool revokeSessionDuringStart{};
    GeometryFixture* geometryToRefresh{};
    GeometryRefreshStage geometryRefreshStage{GeometryRefreshStage::None};
    std::uint64_t refreshedGeneration{};
    MacScreenCaptureStream* owner{};
    ReentryStage reentryStage{ReentryStage::None};
    ReentryAction reentryAction{ReentryAction::Close};
    bool backendRetirementDeferred{};
    bool nestedOperationDenied{};
    std::size_t preflightCalls{};
    std::size_t prepareCalls{};
    std::size_t startCalls{};
    std::size_t stopCalls{};
    std::size_t closeCalls{};
    std::size_t nativeStopClaimAttempts{};
    std::size_t nativeStopClaims{};

private:
    void refreshGeometry(const GeometryRefreshStage stage) noexcept {
        if (geometryToRefresh == nullptr || geometryRefreshStage != stage) {
            return;
        }
        geometryRefreshStage = GeometryRefreshStage::None;
        refreshedGeneration = geometryToRefresh->refresh();
    }

    void reenterOwner(const ReentryStage stage) noexcept {
        if (owner == nullptr || reentryStage != stage) {
            return;
        }
        reentryStage = ReentryStage::None;
        if (reentryAction == ReentryAction::Close) {
            owner->close();
        } else {
            owner->invalidateTopology();
        }
        if (stage != ReentryStage::Close) {
            backendRetirementDeferred = closeCalls == 0;
            const auto nested = owner->start();
            nestedOperationDenied =
                !nested && nested.error() == MacScreenCaptureError::IllegalTransition;
        }
    }

    void claimNativeStop(
        const std::shared_ptr<MacScreenCaptureState>& receivedState) noexcept {
        if (!claimNativeStopRequests || !receivedState) {
            return;
        }
        ++nativeStopClaimAttempts;
        if (receivedState->claimNativeStopRequest()) {
            ++nativeStopClaims;
        }
    }
};

struct StreamFixture {
    std::shared_ptr<RecordingConsumer> consumer =
        std::make_shared<RecordingConsumer>();
    FakeBackend* backend{};
    // The production binding carries an async revocation fence, not a borrowed
    // geometry pointer. This owner is only for makeStream() test convenience,
    // and precedes the stream so reverse destruction retires capture first.
    std::unique_ptr<GeometryFixture> ownedGeometry{};
    std::unique_ptr<MacScreenCaptureStream> stream;
};

[[nodiscard]] StreamFixture makeStream(const MacScreenCaptureBinding streamBinding) {
    auto fake = std::make_unique<FakeBackend>();
    auto* const fakePointer = fake.get();
    auto consumer = std::make_shared<RecordingConsumer>();
    auto created = MacScreenCaptureStream::createForTesting(
        streamBinding, consumer, std::move(fake));
    assert(created);
    return StreamFixture{
        std::move(consumer), fakePointer, {}, std::move(*created)};
}

[[nodiscard]] StreamFixture makeStream() {
    auto geometry = std::make_unique<GeometryFixture>();
    const auto generation = geometry->refresh();
    auto fixture = makeStream(geometry->bindingFor(100, generation));
    fixture.ownedGeometry = std::move(geometry);
    return fixture;
}

void prepareAndStart(StreamFixture& fixture) {
    assert(fixture.stream->prepare());
    assert(fixture.stream->state() == MacScreenCaptureLifecycleState::Preparing);
    fixture.backend->state->prepared();
    assert(fixture.stream->state() == MacScreenCaptureLifecycleState::Ready);
    assert(fixture.stream->start());
    assert(fixture.stream->state() == MacScreenCaptureLifecycleState::Starting);
    fixture.backend->state->startCompleted(true);
    assert(fixture.stream->state() == MacScreenCaptureLifecycleState::Capturing);
}

void testLifecycle() {
    GeometryFixture geometry;
    const auto generation = geometry.refresh();
    auto fixture = makeStream(geometry.bindingFor(100, generation));
    assert(!fixture.stream->start());
    assert(!fixture.stream->stop());
    prepareAndStart(fixture);
    assert(fixture.backend->preflightCalls == 1 && fixture.backend->prepareCalls == 1);
    assert(fixture.backend->lastBinding.displayId == 100);
    assert(fixture.backend->lastBinding.widthPixels == 2);
    assert(fixture.backend->lastBinding.heightPixels == 2);
    assert(fixture.stream->generation() == generation);

    alignas(64) std::array<std::byte, 16> bytes{};
    auto pixelBuffer = makePixelBuffer(bytes, 2, 2, kCVPixelFormatType_32BGRA, 8);
    assert(fixture.backend->state->consumeFrame(
               pixelBuffer.value, MacScreenCaptureFrameStatus::Complete) ==
           MacScreenCaptureFrameDisposition::Published);
    assert(fixture.consumer->calls == 1 && fixture.consumer->lastGeneration == generation);
    assert(fixture.consumer->lastWidth == 2 && fixture.consumer->lastHeight == 2);
    assert(fixture.consumer->lastStride == 8 && fixture.consumer->lastByteCount == 16);

    assert(fixture.backend->state->consumeFrame(
               pixelBuffer.value, MacScreenCaptureFrameStatus::Idle) ==
           MacScreenCaptureFrameDisposition::Dropped);
    assert(fixture.consumer->calls == 1);

    assert(fixture.stream->stop());
    assert(fixture.stream->state() == MacScreenCaptureLifecycleState::Stopping);
    assert(fixture.backend->state->consumeFrame(
               pixelBuffer.value, MacScreenCaptureFrameStatus::Complete) ==
           MacScreenCaptureFrameDisposition::Dropped);
    fixture.backend->state->stopCompleted(true);
    assert(fixture.stream->state() == MacScreenCaptureLifecycleState::Closed);
    assert(!fixture.stream->stop()); // no double stop/reuse
    assert(fixture.consumer->calls == 1);

    auto retiredState = fixture.backend->state;
    fixture.stream->close();
    fixture.stream->close();
    assert(fixture.backend->closeCalls == 1);
    fixture.stream.reset();
    assert(retiredState->consumeFrame(pixelBuffer.value,
                                      MacScreenCaptureFrameStatus::Complete) ==
           MacScreenCaptureFrameDisposition::Dropped);
    assert(fixture.consumer->calls == 1);
}

void testDenials() {
    GeometryFixture geometry;
    const auto generation = geometry.refresh();
    auto staleGeneration = makeMacScreenCaptureBinding(
        geometry.geometry, 100, generation + 1);
    assert(!staleGeneration &&
           staleGeneration.error() == MacScreenCaptureError::StaleGeometryGeneration);
    auto missingDisplay = makeMacScreenCaptureBinding(
        geometry.geometry, 999, generation);
    assert(!missingDisplay && missingDisplay.error() == MacScreenCaptureError::MissingDisplay);
    NativeDisplayReconfigurationWatch::recordTopologyChange();
    auto staleTopology = makeMacScreenCaptureBinding(
        geometry.geometry, 100, generation);
    assert(!staleTopology && staleTopology.error() == MacScreenCaptureError::StaleTopology);

    {
        auto fixture = makeStream();
        fixture.backend->preflightStatus = ScreenCapturePreflightStatus::NotGranted;
        auto result = fixture.stream->prepare();
        assert(!result && result.error() == MacScreenCaptureError::PermissionNotGranted);
        assert(fixture.stream->state() == MacScreenCaptureLifecycleState::Failed);
        assert(fixture.backend->prepareCalls == 0);
    }
    {
        auto fixture = makeStream();
        fixture.backend->preflightStatus = ScreenCapturePreflightStatus::Unavailable;
        auto result = fixture.stream->prepare();
        assert(!result && result.error() == MacScreenCaptureError::PermissionUnavailable);
        assert(fixture.stream->state() == MacScreenCaptureLifecycleState::Failed);
        assert(fixture.backend->prepareCalls == 0);
    }
    {
        auto fixture = makeStream();
        fixture.backend->prepareRequestError = MacScreenCaptureError::SetupFailed;
        auto result = fixture.stream->prepare();
        assert(!result && result.error() == MacScreenCaptureError::SetupFailed);
        assert(fixture.stream->state() == MacScreenCaptureLifecycleState::Failed);
    }
    {
        auto fixture = makeStream();
        assert(fixture.stream->prepare());
        assert(!fixture.stream->prepare()); // no duplicate native output setup
        assert(fixture.backend->state->consumeFrame(
                   nullptr, MacScreenCaptureFrameStatus::Complete) ==
               MacScreenCaptureFrameDisposition::Dropped);
        assert(fixture.stream->lastFrameDrop() == MacScreenCaptureFrameDrop::NotCapturing);
        fixture.backend->state->prepareFailed(MacScreenCaptureError::OutputRegistrationFailed);
        assert(fixture.stream->state() == MacScreenCaptureLifecycleState::Failed);
        assert(!fixture.stream->start());
    }
    {
        auto fixture = makeStream();
        assert(fixture.stream->prepare());
        fixture.backend->state->prepared();
        assert(!fixture.stream->stop()); // stop before a successful start
        assert(fixture.stream->start());
        assert(!fixture.stream->start());
        fixture.backend->state->startCompleted(false);
        assert(fixture.stream->state() == MacScreenCaptureLifecycleState::Failed);
        assert(fixture.stream->lastError() == MacScreenCaptureError::StartFailed);
    }
    {
        auto fixture = makeStream();
        assert(fixture.stream->prepare());
        fixture.backend->state->prepared();
        fixture.backend->startRequestError = MacScreenCaptureError::StartRequestFailed;
        auto started = fixture.stream->start();
        assert(!started && started.error() == MacScreenCaptureError::StartRequestFailed);
        assert(fixture.stream->state() == MacScreenCaptureLifecycleState::Failed);
    }
    {
        auto fixture = makeStream();
        assert(fixture.stream->prepare());
        fixture.backend->state->prepared();
        fixture.backend->state->nativeFailed();
        assert(fixture.stream->state() == MacScreenCaptureLifecycleState::Failed);
        assert(!fixture.stream->start());
    }
    {
        auto fixture = makeStream();
        prepareAndStart(fixture);
        alignas(64) std::array<std::byte, 16> bytes{};
        assert(fixture.backend->state->consumeFrame(
                   nullptr, MacScreenCaptureFrameStatus::Complete) ==
               MacScreenCaptureFrameDisposition::Dropped);
        assert(fixture.stream->lastFrameDrop() == MacScreenCaptureFrameDrop::MissingBuffer);

        auto unsupported = makePixelBuffer(bytes, 2, 2, kCVPixelFormatType_32ARGB, 8);
        assert(fixture.backend->state->consumeFrame(
                   unsupported.value, MacScreenCaptureFrameStatus::Complete) ==
               MacScreenCaptureFrameDisposition::Dropped);
        assert(fixture.stream->lastFrameDrop() == MacScreenCaptureFrameDrop::UnsupportedFormat);

        std::array<std::byte, 8> smallBytes{};
        auto wrongDimensions = makePixelBuffer(
            smallBytes, 1, 2, kCVPixelFormatType_32BGRA, 4);
        assert(fixture.backend->state->consumeFrame(
                   wrongDimensions.value, MacScreenCaptureFrameStatus::Complete) ==
               MacScreenCaptureFrameDisposition::Dropped);
        assert(fixture.stream->lastFrameDrop() == MacScreenCaptureFrameDrop::InvalidDimensions);

        fixture.backend->stopRequestError = MacScreenCaptureError::StopRequestFailed;
        auto stopped = fixture.stream->stop();
        assert(!stopped && stopped.error() == MacScreenCaptureError::StopRequestFailed);
        assert(fixture.stream->state() == MacScreenCaptureLifecycleState::Failed);
        assert(!fixture.stream->start());
    }
    {
        auto fixture = makeStream();
        prepareAndStart(fixture);
        assert(fixture.stream->stop());
        fixture.backend->state->stopCompleted(false);
        assert(fixture.stream->state() == MacScreenCaptureLifecycleState::Failed);
        assert(fixture.stream->lastError() == MacScreenCaptureError::StopFailed);
    }
    {
        auto fixture = makeStream();
        assert(fixture.stream->prepare());
        fixture.stream->close();
        fixture.stream.reset();
    }
}

void testNativeFactoryQuarantine() {
    // The compile-time assertion above is the behavior under test. Runtime
    // execution keeps the case visible in CTest and proves no native setup is
    // attempted while exercising this policy boundary.
    assert(!ExposesNativeCaptureFactory<MacScreenCaptureStream>);
}

void testFramebufferContract() {
    GeometryFixture geometry;
    const auto generation = geometry.refresh();
    auto fixture = makeStream(geometry.bindingFor(100, generation));
    prepareAndStart(fixture);

    alignas(64) std::array<std::byte, 32> bytes{};
    fixture.consumer->expectedPixels = bytes.data();
    auto pixelBuffer = makePixelBuffer(
        bytes, 2, 2, kCVPixelFormatType_32BGRA, 16);

    assert(fixture.backend->state->consumeFrame(
               pixelBuffer.value, MacScreenCaptureFrameStatus::Complete) ==
           MacScreenCaptureFrameDisposition::Published);
    assert(fixture.consumer->calls == 1);
    assert(fixture.consumer->lastGeneration == generation);
    assert(fixture.consumer->lastPixels == bytes.data());
    assert(fixture.consumer->lastWidth == 2 &&
           fixture.consumer->lastHeight == 2);
    assert(fixture.consumer->lastStride == 16);
    assert(fixture.consumer->lastByteCount == bytes.size());
    assert(fixture.stream->lastFrameDrop() == MacScreenCaptureFrameDrop::None);
}

void testConsumerCancellation() {
    GeometryFixture geometry;
    const auto generation = geometry.refresh();
    auto fixture = makeStream(geometry.bindingFor(100, generation));
    prepareAndStart(fixture);

    alignas(64) std::array<std::byte, 16> bytes{};
    auto pixelBuffer = makePixelBuffer(
        bytes, 2, 2, kCVPixelFormatType_32BGRA, 8);
    auto callbackState = fixture.backend->state;
    fixture.consumer->streamToClose = fixture.stream.get();
    fixture.consumer->closeDuringConsume = true;

    // close() is allowed from the synchronous consumer callback. The local
    // shared consumer/state ownership must survive consumer_.reset(), and the
    // in-flight frame must retire rather than publish after cancellation.
    assert(callbackState->consumeFrame(
               pixelBuffer.value, MacScreenCaptureFrameStatus::Complete) ==
           MacScreenCaptureFrameDisposition::RetireStream);
    assert(fixture.consumer->calls == 1);
    assert(fixture.stream->state() == MacScreenCaptureLifecycleState::Closed);
    assert(fixture.stream->lastFrameDrop() ==
           MacScreenCaptureFrameDrop::NotCapturing);
    assert(fixture.backend->closeCalls == 1);

    // A retained native callback state cannot revive the closed consumer.
    assert(callbackState->consumeFrame(
               pixelBuffer.value, MacScreenCaptureFrameStatus::Complete) ==
           MacScreenCaptureFrameDisposition::Dropped);
    assert(fixture.consumer->calls == 1);
    fixture.stream->close();
    assert(fixture.backend->closeCalls == 1);
}

void testNativeStopSingleOwnership() {
    GeometryFixture geometry;
    const auto generation = geometry.refresh();
    auto fixture = makeStream(geometry.bindingFor(100, generation));
    prepareAndStart(fixture);
    fixture.backend->claimNativeStopRequests = true;

    alignas(64) std::array<std::byte, 16> bytes{};
    auto pixelBuffer = makePixelBuffer(
        bytes, 2, 2, kCVPixelFormatType_32BGRA, 8);
    auto callbackState = fixture.backend->state;
    fixture.consumer->streamToStop = fixture.stream.get();
    fixture.consumer->stopDuringConsume = true;

    // The owner submits the graceful native stop from inside consume(). The
    // callback then asks to retire its in-flight frame, but must not win a
    // second ScreenCaptureKit stop submission.
    assert(callbackState->consumeFrame(
               pixelBuffer.value, MacScreenCaptureFrameStatus::Complete) ==
           MacScreenCaptureFrameDisposition::RetireStream);
    assert(fixture.consumer->calls == 1);
    assert(fixture.consumer->stopSucceeded);
    assert(fixture.stream->state() == MacScreenCaptureLifecycleState::Stopping);
    assert(fixture.backend->stopCalls == 1);
    assert(fixture.backend->nativeStopClaimAttempts == 1);
    assert(fixture.backend->nativeStopClaims == 1);
    assert(!callbackState->claimNativeStopRequest());

    // Whichever native path owns the one request also owns the completion.
    // Closing the already-stopped one-shot stream must not claim another.
    callbackState->stopCompleted(true);
    assert(fixture.stream->state() == MacScreenCaptureLifecycleState::Closed);
    fixture.stream->close();
    assert(fixture.backend->closeCalls == 1);
    assert(fixture.backend->nativeStopClaimAttempts == 2);
    assert(fixture.backend->nativeStopClaims == 1);
    assert(callbackState->consumeFrame(
               pixelBuffer.value, MacScreenCaptureFrameStatus::Complete) ==
           MacScreenCaptureFrameDisposition::Dropped);
    assert(fixture.consumer->calls == 1);
}

void testBackendCallbackReentryRetirement() {
    using ReentryStage = FakeBackend::ReentryStage;
    using ReentryAction = FakeBackend::ReentryAction;

    auto assertRetired = [](const StreamFixture& fixture,
                            const MacScreenCaptureLifecycleState expectedState) {
        assert(fixture.backend->backendRetirementDeferred);
        assert(fixture.backend->nestedOperationDenied);
        assert(fixture.backend->closeCalls == 1);
        assert(fixture.stream->state() == expectedState);
        assert(!fixture.stream->start());
        fixture.stream->close();
        assert(fixture.backend->closeCalls == 1);
    };

    // A synchronous preflight callback can request close. Preparation must
    // not be submitted after that callback and backend retirement is deferred.
    {
        auto fixture = makeStream();
        fixture.backend->owner = fixture.stream.get();
        fixture.backend->reentryStage = ReentryStage::Preflight;
        const auto prepared = fixture.stream->prepare();
        assert(!prepared &&
               prepared.error() == MacScreenCaptureError::IllegalTransition);
        assert(fixture.backend->prepareCalls == 0);
        assertRetired(fixture, MacScreenCaptureLifecycleState::Closed);
    }
    {
        auto fixture = makeStream();
        fixture.backend->owner = fixture.stream.get();
        fixture.backend->reentryStage = ReentryStage::Prepare;
        const auto prepared = fixture.stream->prepare();
        assert(!prepared &&
               prepared.error() == MacScreenCaptureError::IllegalTransition);
        assert(fixture.backend->prepareCalls == 1);
        assertRetired(fixture, MacScreenCaptureLifecycleState::Closed);
    }
    {
        auto fixture = makeStream();
        assert(fixture.stream->prepare());
        fixture.backend->state->prepared();
        fixture.backend->owner = fixture.stream.get();
        fixture.backend->reentryStage = ReentryStage::Start;
        fixture.backend->reentryAction = ReentryAction::InvalidateTopology;
        const auto started = fixture.stream->start();
        assert(!started &&
               started.error() == MacScreenCaptureError::IllegalTransition);
        assert(fixture.backend->startCalls == 1);
        assert(fixture.stream->lastError() == MacScreenCaptureError::StaleTopology);
        assertRetired(fixture, MacScreenCaptureLifecycleState::Failed);
    }
    {
        auto fixture = makeStream();
        prepareAndStart(fixture);
        fixture.backend->owner = fixture.stream.get();
        fixture.backend->reentryStage = ReentryStage::Stop;
        const auto stopped = fixture.stream->stop();
        assert(!stopped &&
               stopped.error() == MacScreenCaptureError::IllegalTransition);
        assert(fixture.backend->stopCalls == 1);
        assertRetired(fixture, MacScreenCaptureLifecycleState::Closed);
    }
    // Backend close itself can reenter close without a recursive lock or a
    // second backend retirement request.
    {
        auto fixture = makeStream();
        fixture.backend->owner = fixture.stream.get();
        fixture.backend->reentryStage = ReentryStage::Close;
        fixture.stream->close();
        assert(fixture.backend->closeCalls == 1);
        assert(fixture.stream->state() == MacScreenCaptureLifecycleState::Closed);
        fixture.stream->close();
        assert(fixture.backend->closeCalls == 1);
    }
}


void testStartRetirementAfterCompletion() {
    // A close before asynchronous start success must not spend the native
    // stop claim. The later successful completion must retain one stop.
    {
        auto fixture = makeStream();
        assert(fixture.stream->prepare());
        fixture.backend->state->prepared();
        assert(fixture.stream->start());
        const auto state = fixture.backend->state;
        fixture.stream->close();
        assert(fixture.stream->state() == MacScreenCaptureLifecycleState::Closed);
        assert(!state->claimNativeStopAfterStarted());
        state->startCompleted(true);
        assert(state->lifecycleState() == MacScreenCaptureLifecycleState::Closed);
        assert(state->claimNativeStopAfterStarted());
        assert(!state->claimNativeStopRequest());
        assert(!state->claimNativeStopAfterStarted());
        assert(fixture.backend->closeCalls == 1);
    }
    // An asynchronous start failure is not a live native capture: do not
    // request a speculative stop after owner close.
    {
        auto fixture = makeStream();
        assert(fixture.stream->prepare());
        fixture.backend->state->prepared();
        assert(fixture.stream->start());
        const auto state = fixture.backend->state;
        fixture.stream->close();
        state->startCompleted(false);
        assert(!state->claimNativeStopAfterStarted());
        assert(fixture.backend->closeCalls == 1);
    }
    // After a normal completed start, close can claim exactly one stop.
    {
        auto fixture = makeStream();
        prepareAndStart(fixture);
        const auto state = fixture.backend->state;
        fixture.stream->close();
        assert(state->claimNativeStopAfterStarted());
        assert(!state->claimNativeStopAfterStarted());
    }
}

void testGeometryGenerationRetirement() {
    using GeometryRefreshStage = FakeBackend::GeometryRefreshStage;

    auto expectStaleGeneration = [](const auto& result) {
        assert(!result &&
               result.error() ==
                   MacScreenCaptureError::StaleGeometryGeneration);
    };

    // Same-display/same-topology refresh before prepare invalidates the stream
    // without relying on a Quartz topology notification.
    {
        GeometryFixture geometry;
        const auto oldGeneration = geometry.refresh();
        const auto oldBinding = geometry.bindingFor(100, oldGeneration);
        auto fixture = makeStream(oldBinding);
        const auto replacementGeneration = geometry.refresh();
        const auto replacementBinding =
            geometry.bindingFor(100, replacementGeneration);
        assert(replacementGeneration > oldGeneration);
        assert(replacementBinding.widthPixels == oldBinding.widthPixels);
        assert(replacementBinding.heightPixels == oldBinding.heightPixels);
        assert(replacementBinding.topologyRevision ==
               oldBinding.topologyRevision);

        const auto prepared = fixture.stream->prepare();
        expectStaleGeneration(prepared);
        assert(fixture.backend->preflightCalls == 0);
        assert(fixture.backend->prepareCalls == 0);
        assert(fixture.backend->closeCalls == 1);
    }

    // Refresh during preflight: no native prepare may be submitted.
    {
        GeometryFixture geometry;
        const auto generation = geometry.refresh();
        auto fixture = makeStream(geometry.bindingFor(100, generation));
        fixture.backend->geometryToRefresh = &geometry;
        fixture.backend->geometryRefreshStage =
            GeometryRefreshStage::Preflight;
        const auto prepared = fixture.stream->prepare();
        expectStaleGeneration(prepared);
        assert(fixture.backend->refreshedGeneration > generation);
        assert(fixture.backend->preflightCalls == 1);
        assert(fixture.backend->prepareCalls == 0);
        assert(fixture.backend->closeCalls == 1);
    }

    // Refresh during an already-entered native prepare submission: the call
    // cannot be retracted, but success cannot escape the stale lifetime.
    {
        GeometryFixture geometry;
        const auto generation = geometry.refresh();
        auto fixture = makeStream(geometry.bindingFor(100, generation));
        fixture.backend->geometryToRefresh = &geometry;
        fixture.backend->geometryRefreshStage =
            GeometryRefreshStage::Prepare;
        const auto prepared = fixture.stream->prepare();
        expectStaleGeneration(prepared);
        assert(fixture.backend->prepareCalls == 1);
        assert(fixture.backend->refreshedGeneration > generation);
        assert(fixture.backend->closeCalls == 1);
    }

    // Refresh after asynchronous preparation completion but before start.
    {
        GeometryFixture geometry;
        const auto generation = geometry.refresh();
        auto fixture = makeStream(geometry.bindingFor(100, generation));
        assert(fixture.stream->prepare());
        fixture.backend->state->prepared();
        assert(fixture.stream->state() ==
               MacScreenCaptureLifecycleState::Ready);
        const auto replacementGeneration = geometry.refresh();
        assert(replacementGeneration > generation);
        const auto started = fixture.stream->start();
        expectStaleGeneration(started);
        assert(fixture.backend->startCalls == 0);
        assert(fixture.backend->closeCalls == 1);
    }

    // Refresh during an already-entered start submission.
    {
        GeometryFixture geometry;
        const auto generation = geometry.refresh();
        auto fixture = makeStream(geometry.bindingFor(100, generation));
        assert(fixture.stream->prepare());
        fixture.backend->state->prepared();
        fixture.backend->geometryToRefresh = &geometry;
        fixture.backend->geometryRefreshStage = GeometryRefreshStage::Start;
        const auto started = fixture.stream->start();
        expectStaleGeneration(started);
        assert(fixture.backend->startCalls == 1);
        assert(fixture.backend->refreshedGeneration > generation);
        assert(fixture.backend->closeCalls == 1);
    }

    // Successful native start completion after replacement is terminal and
    // leaves exactly one deferred stop claim for the late native start.
    {
        GeometryFixture geometry;
        const auto generation = geometry.refresh();
        auto fixture = makeStream(geometry.bindingFor(100, generation));
        assert(fixture.stream->prepare());
        fixture.backend->state->prepared();
        assert(fixture.stream->start());
        const auto state = fixture.backend->state;
        const auto replacementGeneration = geometry.refresh();
        assert(replacementGeneration > generation);
        state->startCompleted(true);
        assert(state->lifecycleState() ==
               MacScreenCaptureLifecycleState::Failed);
        assert(state->lastError() ==
               MacScreenCaptureError::StaleGeometryGeneration);
        assert(state->claimNativeStopAfterStarted());
        assert(!state->claimNativeStopAfterStarted());
    }

    alignas(64) std::array<std::byte, 16> bytes{};
    auto pixelBuffer = makePixelBuffer(
        bytes, 2, 2, kCVPixelFormatType_32BGRA, 8);

    // A refresh before the callback reaches its consumer suppresses all old
    // frame bytes and retires the callback state.
    {
        GeometryFixture geometry;
        const auto generation = geometry.refresh();
        auto fixture = makeStream(geometry.bindingFor(100, generation));
        prepareAndStart(fixture);
        const auto state = fixture.backend->state;
        const auto replacementGeneration = geometry.refresh();
        assert(replacementGeneration > generation);
        assert(state->consumeFrame(pixelBuffer.value,
                                   MacScreenCaptureFrameStatus::Complete) ==
               MacScreenCaptureFrameDisposition::RetireStream);
        assert(fixture.consumer->calls == 0);
        assert(state->lastError() ==
               MacScreenCaptureError::StaleGeometryGeneration);
        assert(state->lastFrameDrop() ==
               MacScreenCaptureFrameDrop::StaleGeometryGeneration);
    }

    // A replacement racing inside the synchronous consumer cannot retract
    // bytes already observed there, but cannot report Published or revive old
    // callback state. A fresh current-generation stream still publishes.
    {
        GeometryFixture geometry;
        const auto generation = geometry.refresh();
        auto oldFixture = makeStream(geometry.bindingFor(100, generation));
        prepareAndStart(oldFixture);
        const auto oldState = oldFixture.backend->state;
        oldFixture.consumer->geometryToRefresh = &geometry;
        oldFixture.consumer->refreshGeometryDuringConsume = true;
        assert(oldState->consumeFrame(pixelBuffer.value,
                                      MacScreenCaptureFrameStatus::Complete) ==
               MacScreenCaptureFrameDisposition::RetireStream);
        assert(oldFixture.consumer->calls == 1);
        assert(oldFixture.consumer->refreshedGeneration > generation);
        assert(oldState->lastError() ==
               MacScreenCaptureError::StaleGeometryGeneration);
        assert(oldState->lastFrameDrop() ==
               MacScreenCaptureFrameDrop::StaleGeometryGeneration);

        const auto currentGeneration =
            oldFixture.consumer->refreshedGeneration;
        auto freshFixture =
            makeStream(geometry.bindingFor(100, currentGeneration));
        prepareAndStart(freshFixture);
        assert(freshFixture.backend->state->consumeFrame(
                   pixelBuffer.value, MacScreenCaptureFrameStatus::Complete) ==
               MacScreenCaptureFrameDisposition::Published);
        assert(freshFixture.consumer->calls == 1);
        assert(freshFixture.consumer->lastGeneration == currentGeneration);
        assert(oldState->consumeFrame(pixelBuffer.value,
                                      MacScreenCaptureFrameStatus::Complete) ==
               MacScreenCaptureFrameDisposition::Dropped);
        assert(oldFixture.consumer->calls == 1);
    }
}

void testCallbackRetirement() {
    GeometryFixture geometry;
    const auto oldGeneration = geometry.refresh();
    auto oldFixture = makeStream(geometry.bindingFor(100, oldGeneration));
    prepareAndStart(oldFixture);
    oldFixture.consumer->changeTopologyDuringConsume = true;
    alignas(64) std::array<std::byte, 16> bytes{};
    auto pixelBuffer = makePixelBuffer(bytes, 2, 2, kCVPixelFormatType_32BGRA, 8);
    auto oldState = oldFixture.backend->state;
    assert(oldState->consumeFrame(pixelBuffer.value,
                                  MacScreenCaptureFrameStatus::Complete) ==
           MacScreenCaptureFrameDisposition::RetireStream);
    assert(oldFixture.consumer->calls == 1);
    assert(oldFixture.stream->state() == MacScreenCaptureLifecycleState::Failed);
    assert(oldFixture.stream->lastError() == MacScreenCaptureError::StaleTopology);
    assert(oldState->consumeFrame(pixelBuffer.value,
                                  MacScreenCaptureFrameStatus::Complete) ==
           MacScreenCaptureFrameDisposition::Dropped);
    assert(oldFixture.consumer->calls == 1);

    const auto newGeneration = geometry.refresh();
    assert(newGeneration != oldGeneration);
    auto newFixture = makeStream(geometry.bindingFor(100, newGeneration));
    prepareAndStart(newFixture);
    assert(newFixture.backend->state->consumeFrame(
               pixelBuffer.value, MacScreenCaptureFrameStatus::Complete) ==
           MacScreenCaptureFrameDisposition::Published);
    assert(newFixture.consumer->calls == 1 &&
           newFixture.consumer->lastGeneration == newGeneration);

    oldFixture.stream->close();
    oldFixture.stream.reset();
    assert(oldState->consumeFrame(pixelBuffer.value,
                                  MacScreenCaptureFrameStatus::Complete) ==
           MacScreenCaptureFrameDisposition::Dropped);
    assert(newFixture.consumer->calls == 1);

    newFixture.stream->invalidateTopology();
    assert(newFixture.stream->state() == MacScreenCaptureLifecycleState::Failed);
    assert(newFixture.backend->closeCalls == 1);
    newFixture.stream->close();
    assert(newFixture.backend->closeCalls == 1);
}

void testSessionWatchFrameRetirement() {
    assert(gSessionWatchFixture != nullptr);

    // Change before prepare: no backend operation is allowed to start.
    {
        GeometryFixture geometry;
        const auto generation = geometry.refresh();
        auto fixture = makeStream(geometry.bindingFor(100, generation));
        gSessionWatchFixture->recordChange();
        const auto prepared = fixture.stream->prepare();
        assert(!prepared && prepared.error() == MacScreenCaptureError::StaleSession);
        assert(fixture.stream->state() == MacScreenCaptureLifecycleState::Failed);
        assert(fixture.backend->preflightCalls == 0);
        assert(fixture.backend->prepareCalls == 0);
        assert(fixture.backend->closeCalls == 1);
    }

    // Change during synchronous preflight: once the callback returns, the
    // stale lifetime retires before native preparation can be submitted.
    {
        auto fixture = makeStream();
        fixture.backend->revokeSessionDuringPreflight = true;
        const auto prepared = fixture.stream->prepare();
        assert(!prepared &&
               prepared.error() == MacScreenCaptureError::StaleSession);
        assert(fixture.backend->preflightCalls == 1);
        assert(fixture.backend->prepareCalls == 0);
        assert(fixture.backend->closeCalls == 1);
        assert(fixture.stream->state() ==
               MacScreenCaptureLifecycleState::Failed);
    }

    // Change during an already-entered preparation submission: the submission
    // cannot be retracted, but prepare() must retire before reporting success.
    {
        auto fixture = makeStream();
        fixture.backend->revokeSessionDuringPrepare = true;
        const auto prepared = fixture.stream->prepare();
        assert(!prepared &&
               prepared.error() == MacScreenCaptureError::StaleSession);
        assert(fixture.backend->prepareCalls == 1);
        assert(fixture.backend->closeCalls == 1);
        assert(fixture.stream->state() ==
               MacScreenCaptureLifecycleState::Failed);
    }

    // Change after preparation but before start: prepared native resources are
    // retired and no start request is submitted.
    {
        auto fixture = makeStream();
        assert(fixture.stream->prepare());
        fixture.backend->state->prepared();
        assert(fixture.stream->state() == MacScreenCaptureLifecycleState::Ready);
        gSessionWatchFixture->recordChange();
        const auto started = fixture.stream->start();
        assert(!started && started.error() == MacScreenCaptureError::StaleSession);
        assert(fixture.backend->startCalls == 0);
        assert(fixture.backend->closeCalls == 1);
    }

    // Change during an already-entered start submission: start() cannot
    // report success, and close remains safe for any later native completion.
    {
        auto fixture = makeStream();
        assert(fixture.stream->prepare());
        fixture.backend->state->prepared();
        fixture.backend->revokeSessionDuringStart = true;
        const auto started = fixture.stream->start();
        assert(!started &&
               started.error() == MacScreenCaptureError::StaleSession);
        assert(fixture.backend->startCalls == 1);
        assert(fixture.backend->closeCalls == 1);
        assert(fixture.stream->state() ==
               MacScreenCaptureLifecycleState::Failed);
    }

    // A successful asynchronous native start completing after session loss is
    // terminal and leaves exactly one deferred native-stop claim available.
    {
        auto fixture = makeStream();
        assert(fixture.stream->prepare());
        fixture.backend->state->prepared();
        assert(fixture.stream->start());
        const auto state = fixture.backend->state;
        gSessionWatchFixture->recordChange();
        state->startCompleted(true);
        assert(state->lifecycleState() == MacScreenCaptureLifecycleState::Failed);
        assert(state->lastError() == MacScreenCaptureError::StaleSession);
        assert(state->claimNativeStopAfterStarted());
        assert(!state->claimNativeStopAfterStarted());
    }

    // Topology and pixels remain unchanged. The first frame publishes, the
    // session event retires the old lifetime, and all later callbacks stay inert.
    {
        GeometryFixture geometry;
        const auto generation = geometry.refresh();
        auto fixture = makeStream(geometry.bindingFor(100, generation));
        prepareAndStart(fixture);
        alignas(64) std::array<std::byte, 16> bytes{};
        auto pixelBuffer = makePixelBuffer(
            bytes, 2, 2, kCVPixelFormatType_32BGRA, 8);
        const auto state = fixture.backend->state;
        assert(state->consumeFrame(pixelBuffer.value,
                                   MacScreenCaptureFrameStatus::Complete) ==
               MacScreenCaptureFrameDisposition::Published);
        assert(fixture.consumer->calls == 1);

        gSessionWatchFixture->recordChange();
        assert(state->consumeFrame(pixelBuffer.value,
                                   MacScreenCaptureFrameStatus::Complete) ==
               MacScreenCaptureFrameDisposition::RetireStream);
        assert(fixture.consumer->calls == 1);
        assert(state->lifecycleState() == MacScreenCaptureLifecycleState::Failed);
        assert(state->lastError() == MacScreenCaptureError::StaleSession);
        assert(state->lastFrameDrop() == MacScreenCaptureFrameDrop::StaleSession);
        assert(state->claimNativeStopRequest());
        assert(!state->claimNativeStopRequest());

        gSessionWatchFixture->recordChange();
        assert(state->consumeFrame(pixelBuffer.value,
                                   MacScreenCaptureFrameStatus::Complete) ==
               MacScreenCaptureFrameDisposition::Dropped);
        assert(fixture.consumer->calls == 1);
        fixture.stream->close();
        fixture.stream->close();
        assert(fixture.backend->closeCalls == 1);
    }
}

void testSessionWatchConsumerRace() {
    assert(gSessionWatchFixture != nullptr);
    GeometryFixture geometry;
    const auto generation = geometry.refresh();
    auto fixture = makeStream(geometry.bindingFor(100, generation));
    prepareAndStart(fixture);

    alignas(64) std::array<std::byte, 16> bytes{};
    auto pixelBuffer = makePixelBuffer(
        bytes, 2, 2, kCVPixelFormatType_32BGRA, 8);
    const auto state = fixture.backend->state;
    fixture.consumer->changeSessionDuringConsume = true;

    // The already-entered synchronous consumer observes its borrowed bytes,
    // but the post-callback watch fence forbids a successful publication
    // disposition and terminally retires the old session-bound state.
    assert(state->consumeFrame(pixelBuffer.value,
                               MacScreenCaptureFrameStatus::Complete) ==
           MacScreenCaptureFrameDisposition::RetireStream);
    assert(fixture.consumer->calls == 1);
    assert(state->lifecycleState() == MacScreenCaptureLifecycleState::Failed);
    assert(state->lastError() == MacScreenCaptureError::StaleSession);
    assert(state->lastFrameDrop() == MacScreenCaptureFrameDrop::StaleSession);
    assert(state->claimNativeStopRequest());
    assert(!state->claimNativeStopRequest());
    assert(state->consumeFrame(pixelBuffer.value,
                               MacScreenCaptureFrameStatus::Complete) ==
           MacScreenCaptureFrameDisposition::Dropped);
    assert(fixture.consumer->calls == 1);
    fixture.stream->close();
    assert(fixture.backend->closeCalls == 1);
}

} // namespace

int main(const int argumentCount, const char* const arguments[]) {
    if (argumentCount != 2) return 2;
    SessionWatchFixture sessionWatchFixture;
    NativeSessionChangeWatch sessionWatch;
    gSessionWatchFixture = &sessionWatchFixture;
    assert(sessionWatch.startWithCallbacks(sessionWatchFixture.callbacks()));
    const std::string_view testCase = arguments[1];
    if (testCase == "lifecycle") {
        testLifecycle();
    } else if (testCase == "stale-generation-denials") {
        testDenials();
    } else if (testCase == "geometry-generation-retirement") {
        testGeometryGenerationRetirement();
    } else if (testCase == "callback-retirement") {
        testCallbackRetirement();
    } else if (testCase == "consumer-cancellation") {
        testConsumerCancellation();
    } else if (testCase == "native-stop-single-ownership") {
        testNativeStopSingleOwnership();
    } else if (testCase == "backend-callback-reentry-retirement") {
        testBackendCallbackReentryRetirement();
    } else if (testCase == "start-retirement-after-completion") {
        testStartRetirementAfterCompletion();
    } else if (testCase == "native-factory-quarantine") {
        testNativeFactoryQuarantine();
    } else if (testCase == "framebuffer-contract") {
        testFramebufferContract();
    } else if (testCase == "session-watch-frame-retirement") {
        testSessionWatchFrameRetirement();
    } else if (testCase == "session-watch-consumer-race") {
        testSessionWatchConsumerRace();
    } else {
        return 2;
    }
    assert(sessionWatch.stop());
    assert(sessionWatchFixture.removeCalls == 1);
    gSessionWatchFixture = nullptr;
    return 0;
}
