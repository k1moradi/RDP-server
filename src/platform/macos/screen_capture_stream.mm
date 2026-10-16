// SPDX-License-Identifier: GPL-3.0-or-later
#include "platform/macos/screen_capture_stream.h"

#include <CoreMedia/CoreMedia.h>
#include <Foundation/Foundation.h>
#include <ScreenCaptureKit/ScreenCaptureKit.h>

#include <dispatch/dispatch.h>

#include <memory>
#include <mutex>
#include <utility>

namespace rdp::macos::detail {
namespace {

[[nodiscard]] MacScreenCaptureFrameStatus frameStatus(CMSampleBufferRef sampleBuffer) noexcept {
    if (sampleBuffer == nullptr || !CMSampleBufferIsValid(sampleBuffer) ||
        !CMSampleBufferDataIsReady(sampleBuffer)) {
        return MacScreenCaptureFrameStatus::Invalid;
    }
    CFArrayRef const attachments = CMSampleBufferGetSampleAttachmentsArray(sampleBuffer, false);
    if (attachments == nullptr || CFArrayGetCount(attachments) == 0) {
        return MacScreenCaptureFrameStatus::Invalid;
    }
    const auto dictionary = static_cast<CFDictionaryRef>(
        CFArrayGetValueAtIndex(attachments, 0));
    if (dictionary == nullptr) {
        return MacScreenCaptureFrameStatus::Invalid;
    }
    CFTypeRef const statusValue = CFDictionaryGetValue(
        dictionary, (__bridge CFStringRef)SCStreamFrameInfoStatus);
    if (statusValue == nullptr || CFGetTypeID(statusValue) != CFNumberGetTypeID()) {
        return MacScreenCaptureFrameStatus::Invalid;
    }
    NSInteger rawStatus = 0;
    if (!CFNumberGetValue(static_cast<CFNumberRef>(statusValue),
                          kCFNumberNSIntegerType, &rawStatus)) {
        return MacScreenCaptureFrameStatus::Invalid;
    }
    switch (static_cast<SCFrameStatus>(rawStatus)) {
    case SCFrameStatusComplete:
        return MacScreenCaptureFrameStatus::Complete;
    case SCFrameStatusIdle:
        return MacScreenCaptureFrameStatus::Idle;
    case SCFrameStatusBlank:
        return MacScreenCaptureFrameStatus::Blank;
    case SCFrameStatusStarted:
        return MacScreenCaptureFrameStatus::Started;
    case SCFrameStatusSuspended:
        return MacScreenCaptureFrameStatus::Suspended;
    case SCFrameStatusStopped:
        return MacScreenCaptureFrameStatus::Stopped;
    default:
        return MacScreenCaptureFrameStatus::Invalid;
    }
}

} // namespace
} // namespace rdp::macos::detail

using RdpMacCaptureState = rdp::macos::detail::MacScreenCaptureState;
using RdpMacCaptureDisposition = rdp::macos::MacScreenCaptureFrameDisposition;

@interface RdpScreenCaptureOutput : NSObject <SCStreamOutput, SCStreamDelegate>
- (instancetype)initWithState:(std::shared_ptr<RdpMacCaptureState>)state;
@end

@implementation RdpScreenCaptureOutput {
    std::shared_ptr<RdpMacCaptureState> _state;
}

- (instancetype)initWithState:(std::shared_ptr<RdpMacCaptureState>)state {
    self = [super init];
    if (self != nil) {
        _state = std::move(state);
    }
    return self;
}

- (void)stream:(SCStream*)stream
    didOutputSampleBuffer:(CMSampleBufferRef)sampleBuffer
                   ofType:(SCStreamOutputType)type {
    if (type != SCStreamOutputTypeScreen || !_state) {
        return;
    }
    CVPixelBufferRef const pixelBuffer = CMSampleBufferGetImageBuffer(sampleBuffer);
    const auto disposition = _state->consumeFrame(
        pixelBuffer, rdp::macos::detail::frameStatus(sampleBuffer));
    if (disposition == RdpMacCaptureDisposition::RetireStream && stream != nil) {
        auto state = _state;
        [stream stopCaptureWithCompletionHandler:^(NSError* error) {
            if (error != nil) {
                state->nativeFailed();
            }
        }];
    }
}

- (void)stream:(SCStream*)stream didStopWithError:(NSError*)error {
    (void)stream;
    (void)error;
    if (_state) {
        _state->nativeFailed();
    }
}

@end

@interface RdpScreenCaptureBridge : NSObject
- (instancetype)initWithBinding:(rdp::macos::MacScreenCaptureBinding)binding
                           state:(std::shared_ptr<RdpMacCaptureState>)state;
- (BOOL)beginPrepare;
- (BOOL)beginStart;
- (BOOL)beginStop;
- (void)close;
@end

@implementation RdpScreenCaptureBridge {
    rdp::macos::MacScreenCaptureBinding _binding;
    std::shared_ptr<RdpMacCaptureState> _state;
    SCStream* _stream;
    RdpScreenCaptureOutput* _output;
    dispatch_queue_t _outputQueue;
    BOOL _closed;
    BOOL _prepared;
    BOOL _startSubmitted;
    std::mutex _mutex;
}

- (instancetype)initWithBinding:(rdp::macos::MacScreenCaptureBinding)binding
                           state:(std::shared_ptr<RdpMacCaptureState>)state {
    self = [super init];
    if (self != nil) {
        _binding = binding;
        _state = std::move(state);
        _stream = nil;
        _output = nil;
        _outputQueue = nullptr;
        _closed = NO;
        _prepared = NO;
        _startSubmitted = NO;
    }
    return self;
}

- (BOOL)beginPrepare {
    {
        std::scoped_lock lock(_mutex);
        if (_closed || _prepared || !_state) {
            return NO;
        }
    }
    if (@available(macOS 12.3, *)) {
        RdpScreenCaptureBridge* bridge = self;
        [SCShareableContent
            getShareableContentExcludingDesktopWindows:YES
                                    onScreenWindowsOnly:YES
                                      completionHandler:^(SCShareableContent* content,
                                                          NSError* error) {
            std::shared_ptr<RdpMacCaptureState> state;
            rdp::macos::MacScreenCaptureBinding binding;
            {
                std::scoped_lock lock(bridge->_mutex);
                state = bridge->_state;
                binding = bridge->_binding;
                if (bridge->_closed || bridge->_prepared || !state) {
                    return;
                }
            }
            if (error != nil || content == nil) {
                state->prepareFailed(rdp::macos::MacScreenCaptureError::SetupFailed);
                return;
            }

            SCDisplay* selectedDisplay = nil;
            for (SCDisplay* display in content.displays) {
                if (display.displayID == binding.displayId) {
                    selectedDisplay = display;
                    break;
                }
            }
            if (selectedDisplay == nil) {
                state->prepareFailed(rdp::macos::MacScreenCaptureError::MissingDisplay);
                return;
            }

            SCContentFilter* filter =
                [[SCContentFilter alloc] initWithDisplay:selectedDisplay excludingWindows:@[]];
            SCStreamConfiguration* configuration = [[SCStreamConfiguration alloc] init];
            configuration.width = binding.widthPixels;
            configuration.height = binding.heightPixels;
            configuration.pixelFormat = kCVPixelFormatType_32BGRA;
            // ScreenCaptureKit's documented minimum/default of three keeps
            // latency bounded without adding any R7-side frame queue.
            configuration.queueDepth = 3;
            configuration.showsCursor = NO;

            RdpScreenCaptureOutput* output =
                [[RdpScreenCaptureOutput alloc] initWithState:state];
            SCStream* stream = [[SCStream alloc] initWithFilter:filter
                                                  configuration:configuration
                                                       delegate:output];
            if (stream == nil || output == nil) {
                state->prepareFailed(rdp::macos::MacScreenCaptureError::SetupFailed);
                return;
            }
            dispatch_queue_t outputQueue = dispatch_queue_create(
                "org.rdp-server.macos.capture", DISPATCH_QUEUE_SERIAL);
            if (outputQueue == nullptr) {
                state->prepareFailed(rdp::macos::MacScreenCaptureError::SetupFailed);
                return;
            }
            NSError* addOutputError = nil;
            if (![stream addStreamOutput:output
                                    type:SCStreamOutputTypeScreen
                      sampleHandlerQueue:outputQueue
                                   error:&addOutputError]) {
                (void)addOutputError;
                state->prepareFailed(
                    rdp::macos::MacScreenCaptureError::OutputRegistrationFailed);
                return;
            }
            {
                std::scoped_lock lock(bridge->_mutex);
                if (bridge->_closed || bridge->_prepared) {
                    return;
                }
                bridge->_stream = stream;
                bridge->_output = output;
                bridge->_outputQueue = outputQueue;
                bridge->_prepared = YES;
            }
            state->prepared();
            if (state->lifecycleState() !=
                rdp::macos::MacScreenCaptureLifecycleState::Ready) {
                [bridge close];
            }
        }];
        return YES;
    }
    return NO;
}

- (BOOL)beginStart {
    SCStream* stream = nil;
    std::shared_ptr<RdpMacCaptureState> state;
    {
        std::scoped_lock lock(_mutex);
        if (_closed || !_prepared || _startSubmitted || _stream == nil || !_state) {
            return NO;
        }
        _startSubmitted = YES;
        stream = _stream;
        state = _state;
    }
    if (@available(macOS 12.3, *)) {
        [stream startCaptureWithCompletionHandler:^(NSError* error) {
            state->startCompleted(error == nil);
            if (error == nil &&
                state->lifecycleState() !=
                    rdp::macos::MacScreenCaptureLifecycleState::Capturing) {
                [stream stopCaptureWithCompletionHandler:^(NSError* stopError) {
                    if (stopError != nil) {
                        state->nativeFailed();
                    }
                }];
            }
        }];
        return YES;
    }
    return NO;
}

- (BOOL)beginStop {
    SCStream* stream = nil;
    std::shared_ptr<RdpMacCaptureState> state;
    {
        std::scoped_lock lock(_mutex);
        if (_closed || !_startSubmitted || _stream == nil || !_state) {
            return NO;
        }
        stream = _stream;
        state = _state;
    }
    if (@available(macOS 12.3, *)) {
        [stream stopCaptureWithCompletionHandler:^(NSError* error) {
            state->stopCompleted(error == nil);
        }];
        return YES;
    }
    return NO;
}

- (void)close {
    SCStream* stream = nil;
    std::shared_ptr<RdpMacCaptureState> state;
    BOOL stopSubmitted = NO;
    {
        std::scoped_lock lock(_mutex);
        if (_closed) {
            return;
        }
        _closed = YES;
        stream = _stream;
        state = _state;
        stopSubmitted = _startSubmitted;
        _stream = nil;
        _output = nil;
        _outputQueue = nullptr;
        _state.reset();
    }
    if (@available(macOS 12.3, *)) {
        if (stream != nil && stopSubmitted) {
            [stream stopCaptureWithCompletionHandler:^(NSError* error) {
                if (error != nil && state) {
                    state->nativeFailed();
                }
            }];
        }
    }
}

@end

namespace rdp::macos::detail {
namespace {

class ScreenCaptureKitBackend final : public MacScreenCaptureBackend {
public:
    ScreenCaptureKitBackend() noexcept = default;
    ~ScreenCaptureKitBackend() override { close(lastState_); }

    ScreenCapturePreflightStatus preflight() noexcept override {
        if (@available(macOS 12.3, *)) {
            return queryNativeScreenCapturePreflight();
        }
        return ScreenCapturePreflightStatus::Unavailable;
    }

    std::expected<void, MacScreenCaptureError>
    prepare(const MacScreenCaptureBinding& binding,
            const std::shared_ptr<MacScreenCaptureState>& state) noexcept override {
        if (!state) {
            return std::unexpected(MacScreenCaptureError::SetupFailed);
        }
        RdpScreenCaptureBridge* bridge = nil;
        {
            std::scoped_lock lock(mutex_);
            if (bridge_ != nil) {
                return std::unexpected(MacScreenCaptureError::SetupFailed);
            }
            lastState_ = state;
            bridge_ = [[RdpScreenCaptureBridge alloc] initWithBinding:binding state:state];
            bridge = bridge_;
        }
        if (bridge == nil || ![bridge beginPrepare]) {
            close(state);
            return std::unexpected(MacScreenCaptureError::SetupFailed);
        }
        return {};
    }

    std::expected<void, MacScreenCaptureError>
    start(const std::shared_ptr<MacScreenCaptureState>& state) noexcept override {
        RdpScreenCaptureBridge* bridge = nil;
        {
            std::scoped_lock lock(mutex_);
            lastState_ = state;
            bridge = bridge_;
        }
        if (bridge == nil || ![bridge beginStart]) {
            return std::unexpected(MacScreenCaptureError::StartRequestFailed);
        }
        return {};
    }

    std::expected<void, MacScreenCaptureError>
    stop(const std::shared_ptr<MacScreenCaptureState>& state) noexcept override {
        RdpScreenCaptureBridge* bridge = nil;
        {
            std::scoped_lock lock(mutex_);
            lastState_ = state;
            bridge = bridge_;
        }
        if (bridge == nil || ![bridge beginStop]) {
            return std::unexpected(MacScreenCaptureError::StopRequestFailed);
        }
        return {};
    }

    void close(const std::shared_ptr<MacScreenCaptureState>& state) noexcept override {
        RdpScreenCaptureBridge* bridge = nil;
        {
            std::scoped_lock lock(mutex_);
            if (state) {
                lastState_ = state;
            }
            bridge = bridge_;
            bridge_ = nil;
            lastState_.reset();
        }
        if (bridge != nil) {
            [bridge close];
        }
    }

private:
    std::mutex mutex_;
    __strong RdpScreenCaptureBridge* bridge_ = nil;
    std::shared_ptr<MacScreenCaptureState> lastState_{};
};

} // namespace

std::unique_ptr<MacScreenCaptureBackend> makeNativeMacScreenCaptureBackend() {
    return std::make_unique<ScreenCaptureKitBackend>();
}

} // namespace rdp::macos::detail
