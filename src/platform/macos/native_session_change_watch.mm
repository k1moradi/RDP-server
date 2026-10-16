// SPDX-License-Identifier: GPL-3.0-or-later
#include "platform/macos/native_session_change_watch.h"

#if defined(__APPLE__)
#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>

namespace rdp::macos {
namespace {

NSNotificationCenter* s_nativeNotificationCenter = nil;
id<NSObject> s_resignActiveObserver = nil;
id<NSObject> s_becomeActiveObserver = nil;

[[nodiscard]] bool nativeDeliveryContextAvailable() noexcept {
    // Observer creation alone does not prove that a headless/stalled process
    // will dispatch every session transition.
    return [NSThread isMainThread] && NSApp != nil &&
           [NSRunLoop mainRunLoop].currentMode != nil;
}

[[nodiscard]] bool installNativeSessionObservers(
    void*, const std::uint64_t registrationEpoch,
    const NativeSessionChangeRecorder recorder) noexcept {
    @autoreleasepool {
        if (recorder == nullptr || s_nativeNotificationCenter != nil ||
            s_resignActiveObserver != nil || s_becomeActiveObserver != nil) {
            return false;
        }

        NSWorkspace* const workspace = [NSWorkspace sharedWorkspace];
        NSNotificationCenter* const center = workspace.notificationCenter;
        if (workspace == nil || center == nil) {
            return false;
        }

        id<NSObject> const resignObserver = [center
            addObserverForName:NSWorkspaceSessionDidResignActiveNotification
                        object:workspace
                         queue:nil
                    usingBlock:^(__unused NSNotification* notification) {
                        recorder(registrationEpoch);
                    }];
        if (resignObserver == nil) {
            return false;
        }

        id<NSObject> const becomeObserver = [center
            addObserverForName:NSWorkspaceSessionDidBecomeActiveNotification
                        object:workspace
                         queue:nil
                    usingBlock:^(__unused NSNotification* notification) {
                        recorder(registrationEpoch);
                    }];
        if (becomeObserver == nil) {
            [center removeObserver:resignObserver];
            return false;
        }

        s_nativeNotificationCenter = center;
        s_resignActiveObserver = resignObserver;
        s_becomeActiveObserver = becomeObserver;
        return true;
    }
}

[[nodiscard]] bool removeNativeSessionObservers(void*) noexcept {
    @autoreleasepool {
        if (s_nativeNotificationCenter == nil) {
            return s_resignActiveObserver == nil &&
                   s_becomeActiveObserver == nil;
        }
        if (s_resignActiveObserver != nil) {
            [s_nativeNotificationCenter
                removeObserver:s_resignActiveObserver];
        }
        if (s_becomeActiveObserver != nil) {
            [s_nativeNotificationCenter
                removeObserver:s_becomeActiveObserver];
        }
        s_resignActiveObserver = nil;
        s_becomeActiveObserver = nil;
        s_nativeNotificationCenter = nil;
        return true;
    }
}

} // namespace

std::expected<void, NativeSessionChangeWatchError>
NativeSessionChangeWatch::startNative() noexcept {
    if (!nativeDeliveryContextAvailable()) {
        return std::unexpected(
            NativeSessionChangeWatchError::DeliveryUnavailable);
    }
    return startWithCallbacks(
        {nullptr, &installNativeSessionObservers,
         &removeNativeSessionObservers});
}

} // namespace rdp::macos
#endif
