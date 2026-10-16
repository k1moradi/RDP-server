// SPDX-License-Identifier: GPL-3.0-or-later
#include "platform/macos/native_display_reconfiguration.h"
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
    MacScreenCaptureStream* streamToClose{};
    bool changeTopologyDuringConsume{};
    bool closeDuringConsume{};
};

class FakeBackend final : public MacScreenCaptureBackend {
public:
    ScreenCapturePreflightStatus preflight() noexcept override {
        ++preflightCalls;
        return preflightStatus;
    }

    std::expected<void, MacScreenCaptureError>
    prepare(const MacScreenCaptureBinding& receivedBinding,
            const std::shared_ptr<MacScreenCaptureState>& receivedState) noexcept override {
        ++prepareCalls;
        lastBinding = receivedBinding;
        state = receivedState;
        if (prepareRequestError) return std::unexpected(*prepareRequestError);
        return {};
    }

    std::expected<void, MacScreenCaptureError>
    start(const std::shared_ptr<MacScreenCaptureState>& receivedState) noexcept override {
        ++startCalls;
        state = receivedState;
        if (startRequestError) return std::unexpected(*startRequestError);
        return {};
    }

    std::expected<void, MacScreenCaptureError>
    stop(const std::shared_ptr<MacScreenCaptureState>& receivedState) noexcept override {
        ++stopCalls;
        state = receivedState;
        if (stopRequestError) return std::unexpected(*stopRequestError);
        return {};
    }

    void close(const std::shared_ptr<MacScreenCaptureState>& receivedState) noexcept override {
        ++closeCalls;
        state = receivedState;
    }

    ScreenCapturePreflightStatus preflightStatus{ScreenCapturePreflightStatus::Granted};
    std::optional<MacScreenCaptureError> prepareRequestError{};
    std::optional<MacScreenCaptureError> startRequestError{};
    std::optional<MacScreenCaptureError> stopRequestError{};
    std::shared_ptr<MacScreenCaptureState> state{};
    MacScreenCaptureBinding lastBinding{};
    std::size_t preflightCalls{};
    std::size_t prepareCalls{};
    std::size_t startCalls{};
    std::size_t stopCalls{};
    std::size_t closeCalls{};
};

struct StreamFixture {
    std::shared_ptr<RecordingConsumer> consumer = std::make_shared<RecordingConsumer>();
    FakeBackend* backend{};
    std::unique_ptr<MacScreenCaptureStream> stream;
};

[[nodiscard]] StreamFixture makeStream(const MacScreenCaptureBinding streamBinding) {
    auto fake = std::make_unique<FakeBackend>();
    auto* const fakePointer = fake.get();
    auto consumer = std::make_shared<RecordingConsumer>();
    auto created = MacScreenCaptureStream::createForTesting(
        streamBinding, consumer, std::move(fake));
    assert(created);
    return StreamFixture{std::move(consumer), fakePointer, std::move(*created)};
}

[[nodiscard]] StreamFixture makeStream() {
    GeometryFixture geometry;
    const auto generation = geometry.refresh();
    return makeStream(geometry.bindingFor(100, generation));
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

} // namespace

int main(const int argumentCount, const char* const arguments[]) {
    if (argumentCount != 2) return 2;
    const std::string_view testCase = arguments[1];
    if (testCase == "lifecycle") {
        testLifecycle();
    } else if (testCase == "stale-generation-denials") {
        testDenials();
    } else if (testCase == "callback-retirement") {
        testCallbackRetirement();
    } else if (testCase == "consumer-cancellation") {
        testConsumerCancellation();
    } else if (testCase == "native-factory-quarantine") {
        testNativeFactoryQuarantine();
    } else if (testCase == "framebuffer-contract") {
        testFramebufferContract();
    } else {
        return 2;
    }
    return 0;
}
