// SPDX-License-Identifier: GPL-3.0-or-later
#include "platform/macos/mac_native_desktop_owner.h"

#if defined(__APPLE__)
#include <CoreGraphics/CoreGraphics.h>
#endif

#include <cstring>
#include <limits>
#include <mutex>
#include <new>
#include <optional>
#include <span>
#include <utility>

namespace rdp::macos {
namespace {

using rdp_server::server::security::kConsoleInputPermission;
using rdp_server::server::security::kConsoleViewPermission;
using rdp_server::server::security::MacNativeDesktopAuthorizationView;

#if defined(__APPLE__)
struct InitializationVisitContext final {
    MacNativeDesktopOwner* owner{};
    MacNativeDesktopTestConfiguration* testConfiguration{};
    std::optional<MacNativeDesktopOwnerError> error{};
    bool callbackReached{};
};

struct BorrowVisitContext final {
    MacNativeDesktopOwner* owner{};
    std::uint64_t expectedFrameSequence{};
    MacNativeDesktopFrameConsumer consumer{};
    bool result{};
};

struct InputVisitContext final {
    MacNativeDesktopOwner* owner{};
    const MacInputEvent* event{};
    bool result{};
};
#endif

} // namespace

class MacNativeDesktopOwner::FrameMailbox final : public MacCaptureFrameConsumer {
public:
    FrameMailbox(const std::size_t maximumBytes,
                 const std::uint64_t geometryGeneration) noexcept
        : maximumBytes_(maximumBytes), geometryGeneration_(geometryGeneration) {}

    void consume(const FramebufferView& frame,
                 const std::uint64_t generation) noexcept override {
        const std::size_t widthPixels =
            static_cast<std::size_t>(frame.widthPixels);
        if (!frame.valid() || generation == 0 ||
            generation != geometryGeneration_ || frame.widthPixels == 0 ||
            frame.heightPixels == 0 ||
            widthPixels >
                (std::numeric_limits<std::size_t>::max)() / 4U) {
            return;
        }

        const std::size_t rowBytes = widthPixels * 4U;
        if (frame.strideBytes < rowBytes ||
            frame.heightPixels >
                (std::numeric_limits<std::size_t>::max)() / rowBytes) {
            return;
        }
        const std::size_t byteCount =
            rowBytes * static_cast<std::size_t>(frame.heightPixels);
        if (byteCount == 0 || byteCount > maximumBytes_) {
            return;
        }

        std::scoped_lock lock(mutex_);
        if (retired_) {
            return;
        }
        if (latestFrameSequence_ ==
            (std::numeric_limits<std::uint64_t>::max)()) {
            retireLocked();
            return;
        }

        if (storageCapacity_ < byteCount) {
            std::unique_ptr<std::byte[]> replacement;
            try {
                replacement =
                    std::make_unique_for_overwrite<std::byte[]>(byteCount);
            } catch (const std::bad_alloc&) {
                retireLocked();
                return;
            }
            storage_ = std::move(replacement);
            storageCapacity_ = byteCount;
        }

        const auto source = frame.pixels;
        for (std::size_t row = 0; row < frame.heightPixels; ++row) {
            const std::size_t sourceOffset = row * frame.strideBytes;
            const std::size_t destinationOffset = row * rowBytes;
            std::memcpy(storage_.get() + destinationOffset,
                        source.data() + sourceOffset, rowBytes);
        }

        widthPixels_ = frame.widthPixels;
        heightPixels_ = frame.heightPixels;
        strideBytes_ = rowBytes;
        byteCount_ = byteCount;
        ++latestFrameSequence_;
    }

    [[nodiscard]] bool borrow(
        const std::uint64_t expectedFrameSequence,
        const std::uint64_t admittedSessionGeneration,
        const MacNativeDesktopFrameConsumer consumer) noexcept {
        if (expectedFrameSequence == 0 || admittedSessionGeneration == 0 ||
            consumer.context == nullptr || consumer.consume == nullptr) {
            return false;
        }

        std::scoped_lock lock(mutex_);
        if (retired_ || latestFrameSequence_ != expectedFrameSequence ||
            storage_ == nullptr || byteCount_ == 0 || widthPixels_ == 0 ||
            heightPixels_ == 0 || strideBytes_ == 0) {
            return false;
        }
        const FramebufferView frame{
            std::span<const std::byte>{storage_.get(), byteCount_},
            widthPixels_, heightPixels_, strideBytes_};
        return frame.valid() && consumer.consume(
            consumer.context, frame, geometryGeneration_,
            admittedSessionGeneration, latestFrameSequence_);
    }

    [[nodiscard]] std::uint64_t latestFrameSequence() const noexcept {
        std::scoped_lock lock(mutex_);
        return retired_ ? 0U : latestFrameSequence_;
    }

    [[nodiscard]] bool frameAvailable() const noexcept {
        std::scoped_lock lock(mutex_);
        return !retired_ && latestFrameSequence_ != 0 && storage_ != nullptr &&
               byteCount_ != 0;
    }

    [[nodiscard]] bool retired() const noexcept {
        std::scoped_lock lock(mutex_);
        return retired_;
    }

    void retire() noexcept {
        std::scoped_lock lock(mutex_);
        retireLocked();
    }

private:
    void retireLocked() noexcept {
        retired_ = true;
        storage_.reset();
        storageCapacity_ = 0;
        byteCount_ = 0;
        widthPixels_ = 0;
        heightPixels_ = 0;
        strideBytes_ = 0;
        latestFrameSequence_ = 0;
    }

    const std::size_t maximumBytes_{};
    const std::uint64_t geometryGeneration_{};
    mutable std::mutex mutex_{};
    std::unique_ptr<std::byte[]> storage_{};
    std::size_t storageCapacity_{};
    std::size_t byteCount_{};
    std::uint32_t widthPixels_{};
    std::uint32_t heightPixels_{};
    std::size_t strideBytes_{};
    std::uint64_t latestFrameSequence_{};
    bool retired_{};
};

MacNativeDesktopOwner::~MacNativeDesktopOwner() noexcept {
    revoke();
}

#if defined(__APPLE__)
MacNativeDesktopOwner::MacNativeDesktopOwner(
    const rdp_server::server::security::MacNativeDesktopAuthorization& authorization,
    const std::uint64_t expectedAuthorizationGeneration) noexcept
    : authorization_(&authorization),
      authorizationGeneration_(expectedAuthorizationGeneration) {}

std::expected<std::unique_ptr<MacNativeDesktopOwner>,
              MacNativeDesktopOwnerError>
MacNativeDesktopOwner::createAuthorized(
    const rdp_server::server::security::MacNativeDesktopAuthorization& authorization,
    const std::uint64_t expectedAuthorizationGeneration) noexcept {
    if (expectedAuthorizationGeneration == 0) {
        return std::unexpected(
            MacNativeDesktopOwnerError::AuthorizationUnavailable);
    }
    auto owner = std::unique_ptr<MacNativeDesktopOwner>(
        new (std::nothrow) MacNativeDesktopOwner(
            authorization, expectedAuthorizationGeneration));
    if (!owner) {
        return std::unexpected(
            MacNativeDesktopOwnerError::AllocationUnavailable);
    }

    InitializationVisitContext context{owner.get(), nullptr, std::nullopt, false};
    const bool authorized = authorization.visit(
        expectedAuthorizationGeneration, kConsoleViewPermission,
        &MacNativeDesktopOwner::initializeAuthorizationVisit, &context);
    if (!authorized || !context.callbackReached) {
        owner->revoke();
        return std::unexpected(
            MacNativeDesktopOwnerError::AuthorizationUnavailable);
    }
    if (context.error) {
        const auto error = *context.error;
        owner->revoke();
        return std::unexpected(error);
    }
    return owner;
}

std::expected<std::unique_ptr<MacNativeDesktopOwner>,
              MacNativeDesktopOwnerError>
MacNativeDesktopOwner::createForTesting(
    const rdp_server::server::security::MacNativeDesktopAuthorization& authorization,
    const std::uint64_t expectedAuthorizationGeneration,
    MacNativeDesktopTestConfiguration configuration) noexcept {
    if (expectedAuthorizationGeneration == 0) {
        return std::unexpected(
            MacNativeDesktopOwnerError::AuthorizationUnavailable);
    }
    if (configuration.selectedDisplayId == 0 ||
        configuration.maximumFramebufferBytes == 0 ||
        configuration.maximumFramebufferBytes >
            kMaximumMacNativeDesktopFramebufferBytes ||
        configuration.displayWatchCallbacks.install == nullptr ||
        configuration.displayWatchCallbacks.remove == nullptr ||
        configuration.sessionWatchCallbacks.install == nullptr ||
        configuration.sessionWatchCallbacks.remove == nullptr ||
        configuration.displayReader == nullptr ||
        configuration.sessionReader.read == nullptr ||
        configuration.permissionReader.capture == nullptr ||
        configuration.permissionReader.input == nullptr ||
        !configuration.captureBackend) {
        return std::unexpected(
            MacNativeDesktopOwnerError::InvalidConfiguration);
    }

    auto owner = std::unique_ptr<MacNativeDesktopOwner>(
        new (std::nothrow) MacNativeDesktopOwner(
            authorization, expectedAuthorizationGeneration));
    if (!owner) {
        return std::unexpected(
            MacNativeDesktopOwnerError::AllocationUnavailable);
    }

    InitializationVisitContext context{
        owner.get(), &configuration, std::nullopt, false};
    const bool authorized = authorization.visit(
        expectedAuthorizationGeneration, kConsoleViewPermission,
        &MacNativeDesktopOwner::initializeAuthorizationVisit, &context);
    if (!authorized || !context.callbackReached) {
        owner->revoke();
        return std::unexpected(
            MacNativeDesktopOwnerError::AuthorizationUnavailable);
    }
    if (context.error) {
        const auto error = *context.error;
        owner->revoke();
        return std::unexpected(error);
    }
    return owner;
}

bool MacNativeDesktopOwner::initializeAuthorizationVisit(
    const MacNativeDesktopAuthorizationView& authorization,
    void* const contextValue) noexcept {
    auto& context = *static_cast<InitializationVisitContext*>(contextValue);
    context.callbackReached = true;
    if (context.testConfiguration == nullptr) {
        const auto initialized = context.owner->initializeNativeAuthorized(
            authorization);
        if (!initialized) {
            context.error = initialized.error();
        }
        return true;
    }

    const auto initialized = context.owner->initializeTestingAuthorized(
        authorization, std::move(*context.testConfiguration));
    if (!initialized) {
        context.error = initialized.error();
    }
    return true;
}

std::expected<void, MacNativeDesktopOwnerError>
MacNativeDesktopOwner::initializeNativeAuthorized(
    const MacNativeDesktopAuthorizationView& authorization) noexcept {
    if (authorization.authorizationGeneration() != authorizationGeneration_ ||
        authorization.authenticatedUserId() == 0 ||
        (authorization.permissionMask() & kConsoleViewPermission) == 0) {
        return std::unexpected(
            MacNativeDesktopOwnerError::AuthorizationUnavailable);
    }
    targetUserId_ = authorization.authenticatedUserId();
    permissionMask_ = authorization.permissionMask();
    authenticationGeneration_ = authorization.authenticationGeneration();

    if (!displayWatch_.startNative()) {
        return std::unexpected(
            MacNativeDesktopOwnerError::DisplayWatchUnavailable);
    }
    if (!sessionWatch_.startNative()) {
        return std::unexpected(
            MacNativeDesktopOwnerError::SessionWatchUnavailable);
    }

    const auto generation = geometry_.refreshNative();
    if (!generation || *generation == 0) {
        return std::unexpected(
            MacNativeDesktopOwnerError::DisplayUnavailable);
    }
    geometryGeneration_ = *generation;

    const std::uint32_t selectedDisplayId = CGMainDisplayID();
    const auto display = geometry_.displayMapping(
        selectedDisplayId, geometryGeneration_);
    if (selectedDisplayId == 0 || !display) {
        return std::unexpected(
            MacNativeDesktopOwnerError::DisplayUnavailable);
    }
    pixelGeometry_ = {
        display->physicalPixels.widthPixels,
        display->physicalPixels.heightPixels};
    const auto virtualPixelGeometry =
        geometry_.virtualPixelSize(geometryGeneration_);
    // One ScreenCaptureKit stream currently publishes one display. Refuse a
    // wider multi-display virtual canvas so capture pixels and RDP input
    // coordinates cannot silently describe different desktop spaces.
    if (!virtualPixelGeometry || *virtualPixelGeometry != pixelGeometry_) {
        return std::unexpected(
            MacNativeDesktopOwnerError::DisplayUnavailable);
    }

    const std::uint64_t minimumBytes =
        static_cast<std::uint64_t>(pixelGeometry_.widthPixels) *
        static_cast<std::uint64_t>(pixelGeometry_.heightPixels) * 4U;
    if (minimumBytes == 0 ||
        minimumBytes > kMaximumMacNativeDesktopFramebufferBytes) {
        return std::unexpected(
            MacNativeDesktopOwnerError::FramebufferUnavailable);
    }

    try {
        sessionGuard_ = std::make_unique<MacDesktopSessionGuard>(
            geometry_, geometryGeneration_, targetUserId_,
            macDesktopSessionReadCallbacks(), macDesktopPermissionReadCallbacks());
        if (sessionGuard_->closed() ||
            !sessionGuard_->allows(MacDesktopAccessKind::Capture)) {
            return std::unexpected(
                MacNativeDesktopOwnerError::SessionUnavailable);
        }

        if ((permissionMask_ & kConsoleInputPermission) != 0) {
            if (!sessionGuard_->allows(MacDesktopAccessKind::Input)) {
                return std::unexpected(
                    MacNativeDesktopOwnerError::InputUnavailable);
            }
            input_ = std::make_unique<MacInputController>(
                geometry_, MacInputController::nativeCallbacksForAuthorizedOwner(),
                geometryGeneration_);
            if (input_->closed()) {
                return std::unexpected(
                    MacNativeDesktopOwnerError::InputUnavailable);
            }
        }

        const auto binding = makeMacScreenCaptureBinding(
            geometry_, selectedDisplayId, geometryGeneration_);
        if (!binding) {
            return std::unexpected(
                MacNativeDesktopOwnerError::CaptureUnavailable);
        }
        frameMailbox_ = std::make_shared<FrameMailbox>(
            kMaximumMacNativeDesktopFramebufferBytes, geometryGeneration_);
        auto capture = MacScreenCaptureStream::createNativeForAuthorizedOwner(
            *binding, frameMailbox_);
        if (!capture) {
            return std::unexpected(
                MacNativeDesktopOwnerError::CaptureUnavailable);
        }
        capture_ = std::move(*capture);
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            MacNativeDesktopOwnerError::AllocationUnavailable);
    }

    state_ = MacNativeDesktopOwnerState::CapturePreparing;
    return {};
}

std::expected<void, MacNativeDesktopOwnerError>
MacNativeDesktopOwner::initializeTestingAuthorized(
    const MacNativeDesktopAuthorizationView& authorization,
    MacNativeDesktopTestConfiguration&& configuration) noexcept {
    if (authorization.authorizationGeneration() != authorizationGeneration_ ||
        authorization.authenticatedUserId() == 0 ||
        (authorization.permissionMask() & kConsoleViewPermission) == 0) {
        return std::unexpected(
            MacNativeDesktopOwnerError::AuthorizationUnavailable);
    }
    targetUserId_ = authorization.authenticatedUserId();
    permissionMask_ = authorization.permissionMask();
    authenticationGeneration_ = authorization.authenticationGeneration();

    if (!displayWatch_.startWithCallbacks(
            configuration.displayWatchCallbacks)) {
        return std::unexpected(
            MacNativeDesktopOwnerError::DisplayWatchUnavailable);
    }
    if (!sessionWatch_.startWithCallbacks(
            configuration.sessionWatchCallbacks)) {
        return std::unexpected(
            MacNativeDesktopOwnerError::SessionWatchUnavailable);
    }

    const auto generation = geometry_.refresh(
        configuration.displayReader, configuration.displayReaderContext);
    if (!generation || *generation == 0) {
        return std::unexpected(
            MacNativeDesktopOwnerError::DisplayUnavailable);
    }
    geometryGeneration_ = *generation;

    const auto display = geometry_.displayMapping(
        configuration.selectedDisplayId, geometryGeneration_);
    if (!display) {
        return std::unexpected(
            MacNativeDesktopOwnerError::DisplayUnavailable);
    }
    pixelGeometry_ = {
        display->physicalPixels.widthPixels,
        display->physicalPixels.heightPixels};
    const auto virtualPixelGeometry =
        geometry_.virtualPixelSize(geometryGeneration_);
    // One ScreenCaptureKit stream currently publishes one display. Refuse a
    // wider multi-display virtual canvas so capture pixels and RDP input
    // coordinates cannot silently describe different desktop spaces.
    if (!virtualPixelGeometry || *virtualPixelGeometry != pixelGeometry_) {
        return std::unexpected(
            MacNativeDesktopOwnerError::DisplayUnavailable);
    }

    const std::uint64_t minimumBytes =
        static_cast<std::uint64_t>(pixelGeometry_.widthPixels) *
        static_cast<std::uint64_t>(pixelGeometry_.heightPixels) * 4U;
    if (minimumBytes == 0 ||
        minimumBytes > configuration.maximumFramebufferBytes) {
        return std::unexpected(
            MacNativeDesktopOwnerError::FramebufferUnavailable);
    }

    try {
        sessionGuard_ = std::make_unique<MacDesktopSessionGuard>(
            geometry_, geometryGeneration_, targetUserId_,
            configuration.sessionReader, configuration.permissionReader);
        if (sessionGuard_->closed() ||
            !sessionGuard_->allows(MacDesktopAccessKind::Capture)) {
            return std::unexpected(
                MacNativeDesktopOwnerError::SessionUnavailable);
        }

        if ((permissionMask_ & kConsoleInputPermission) != 0) {
            if (configuration.inputCallbacks.context == nullptr ||
                configuration.inputCallbacks.send == nullptr ||
                !sessionGuard_->allows(MacDesktopAccessKind::Input)) {
                return std::unexpected(
                    MacNativeDesktopOwnerError::InputUnavailable);
            }
            input_ = std::make_unique<MacInputController>(
                geometry_, configuration.inputCallbacks, geometryGeneration_);
            if (input_->closed()) {
                return std::unexpected(
                    MacNativeDesktopOwnerError::InputUnavailable);
            }
        }

        const auto binding = makeMacScreenCaptureBinding(
            geometry_, configuration.selectedDisplayId, geometryGeneration_);
        if (!binding) {
            return std::unexpected(
                MacNativeDesktopOwnerError::CaptureUnavailable);
        }
        frameMailbox_ = std::make_shared<FrameMailbox>(
            configuration.maximumFramebufferBytes, geometryGeneration_);
        auto capture = MacScreenCaptureStream::createForTesting(
            *binding, frameMailbox_, std::move(configuration.captureBackend));
        if (!capture) {
            return std::unexpected(
                MacNativeDesktopOwnerError::CaptureUnavailable);
        }
        capture_ = std::move(*capture);
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            MacNativeDesktopOwnerError::AllocationUnavailable);
    }

    state_ = MacNativeDesktopOwnerState::CapturePreparing;
    return {};
}
#endif

bool MacNativeDesktopOwner::authorizationViewMatches(
    const MacNativeDesktopAuthorizationView& authorization,
    const std::uint32_t requiredPermissions) const noexcept {
    return state_ != MacNativeDesktopOwnerState::Revoked &&
           authorization_ != nullptr && authorizationGeneration_ != 0 &&
           targetUserId_ != 0 && authenticationGeneration_ != 0 &&
           authorization.authorizationGeneration() == authorizationGeneration_ &&
           authorization.authenticationGeneration() == authenticationGeneration_ &&
           authorization.authenticatedUserId() == targetUserId_ &&
           authorization.permissionMask() == permissionMask_ &&
           (permissionMask_ & requiredPermissions) == requiredPermissions;
}

bool MacNativeDesktopOwner::captureLifetimeCurrent() noexcept {
    if (state_ == MacNativeDesktopOwnerState::Revoked ||
        capture_ == nullptr || sessionGuard_ == nullptr ||
        frameMailbox_ == nullptr || frameMailbox_->retired() ||
        !sessionGuard_->allows(MacDesktopAccessKind::Capture) ||
        (input_ != nullptr &&
         !sessionGuard_->allows(MacDesktopAccessKind::Input))) {
        revoke();
        return false;
    }
    return true;
}

void MacNativeDesktopOwner::serviceAuthorized() noexcept {
    if (!captureLifetimeCurrent()) {
        return;
    }

    switch (capture_->state()) {
    case MacScreenCaptureLifecycleState::Idle:
        if (!capture_->prepare()) {
            revoke();
            return;
        }
        state_ = MacNativeDesktopOwnerState::CapturePreparing;
        break;
    case MacScreenCaptureLifecycleState::Preparing:
        state_ = MacNativeDesktopOwnerState::CapturePreparing;
        break;
    case MacScreenCaptureLifecycleState::Ready:
        if (!capture_->start()) {
            revoke();
            return;
        }
        state_ = MacNativeDesktopOwnerState::CaptureStarting;
        break;
    case MacScreenCaptureLifecycleState::Starting:
        state_ = MacNativeDesktopOwnerState::CaptureStarting;
        break;
    case MacScreenCaptureLifecycleState::Capturing:
        state_ = MacNativeDesktopOwnerState::Ready;
        break;
    case MacScreenCaptureLifecycleState::Stopping:
    case MacScreenCaptureLifecycleState::Closed:
    case MacScreenCaptureLifecycleState::Failed:
        revoke();
        break;
    }
}

#if defined(__APPLE__)
bool MacNativeDesktopOwner::serviceAuthorizationVisit(
    const MacNativeDesktopAuthorizationView& authorization,
    void* const context) noexcept {
    auto& owner = *static_cast<MacNativeDesktopOwner*>(context);
    if (!owner.authorizationViewMatches(authorization, kConsoleViewPermission)) {
        owner.revoke();
        return true;
    }
    owner.serviceAuthorized();
    return true;
}
#endif

MacNativeDesktopServiceObservation
MacNativeDesktopOwner::observation() const noexcept {
    MacNativeDesktopServiceObservation current{};
    current.state = state_;
    if (state_ == MacNativeDesktopOwnerState::Revoked) {
        return current;
    }
    current.pixelGeometry = pixelGeometry_;
    current.geometryGeneration = geometryGeneration_;
    current.admittedSessionGeneration = authorizationGeneration_;
    if (frameMailbox_) {
        current.latestFrameSequence = frameMailbox_->latestFrameSequence();
        current.frameAvailable = frameMailbox_->frameAvailable();
    }
    current.inputReady = input_ != nullptr && !input_->closed();
    return current;
}

MacNativeDesktopServiceObservation
MacNativeDesktopOwner::serviceOnce() noexcept {
#if defined(__APPLE__)
    if (state_ == MacNativeDesktopOwnerState::Revoked ||
        authorization_ == nullptr || authorizationGeneration_ == 0) {
        revoke();
        return observation();
    }
    if (!authorization_->visit(
            authorizationGeneration_, kConsoleViewPermission,
            &MacNativeDesktopOwner::serviceAuthorizationVisit, this)) {
        revoke();
    }
#else
    revoke();
#endif
    return observation();
}

bool MacNativeDesktopOwner::borrowAuthorized(
    const std::uint64_t expectedFrameSequence,
    const MacNativeDesktopFrameConsumer consumer) noexcept {
    if (state_ != MacNativeDesktopOwnerState::Ready ||
        !captureLifetimeCurrent() ||
        capture_->state() != MacScreenCaptureLifecycleState::Capturing) {
        return false;
    }
    return frameMailbox_->borrow(
        expectedFrameSequence, authorizationGeneration_, consumer);
}

#if defined(__APPLE__)
bool MacNativeDesktopOwner::borrowAuthorizationVisit(
    const MacNativeDesktopAuthorizationView& authorization,
    void* const contextValue) noexcept {
    auto& context = *static_cast<BorrowVisitContext*>(contextValue);
    if (!context.owner->authorizationViewMatches(
            authorization, kConsoleViewPermission)) {
        context.owner->revoke();
        return true;
    }
    context.result = context.owner->borrowAuthorized(
        context.expectedFrameSequence, context.consumer);
    return true;
}
#endif

bool MacNativeDesktopOwner::borrowFramebuffer(
    const std::uint64_t expectedFrameSequence,
    const MacNativeDesktopFrameConsumer consumer) noexcept {
#if defined(__APPLE__)
    if (state_ == MacNativeDesktopOwnerState::Revoked ||
        authorization_ == nullptr || authorizationGeneration_ == 0) {
        return false;
    }
    BorrowVisitContext context{this, expectedFrameSequence, consumer, false};
    if (!authorization_->visit(
            authorizationGeneration_, kConsoleViewPermission,
            &MacNativeDesktopOwner::borrowAuthorizationVisit, &context)) {
        revoke();
        return false;
    }
    return context.result;
#else
    (void)expectedFrameSequence;
    (void)consumer;
    return false;
#endif
}

bool MacNativeDesktopOwner::inputAuthorized(const MacInputEvent& event) noexcept {
    if (state_ != MacNativeDesktopOwnerState::Ready || input_ == nullptr ||
        sessionGuard_ == nullptr ||
        !sessionGuard_->allows(MacDesktopAccessKind::Input) ||
        !input_->handle(event)) {
        if (input_ != nullptr) {
            revoke();
        }
        return false;
    }
    return true;
}

#if defined(__APPLE__)
bool MacNativeDesktopOwner::inputAuthorizationVisit(
    const MacNativeDesktopAuthorizationView& authorization,
    void* const contextValue) noexcept {
    auto& context = *static_cast<InputVisitContext*>(contextValue);
    constexpr std::uint32_t requiredPermissions =
        kConsoleViewPermission | kConsoleInputPermission;
    if (!context.owner->authorizationViewMatches(
            authorization, requiredPermissions)) {
        context.owner->revoke();
        return true;
    }
    context.result = context.owner->inputAuthorized(*context.event);
    return true;
}
#endif

bool MacNativeDesktopOwner::handleInput(const MacInputEvent& event) noexcept {
#if defined(__APPLE__)
    constexpr std::uint32_t requiredPermissions =
        kConsoleViewPermission | kConsoleInputPermission;
    if (state_ == MacNativeDesktopOwnerState::Revoked ||
        authorization_ == nullptr || authorizationGeneration_ == 0 ||
        (permissionMask_ & requiredPermissions) != requiredPermissions) {
        return false;
    }
    InputVisitContext context{this, &event, false};
    if (!authorization_->visit(
            authorizationGeneration_, requiredPermissions,
            &MacNativeDesktopOwner::inputAuthorizationVisit, &context)) {
        revoke();
        return false;
    }
    return context.result;
#else
    (void)event;
    return false;
#endif
}

void MacNativeDesktopOwner::revoke() noexcept {
    if (state_ == MacNativeDesktopOwnerState::Revoked) {
        return;
    }
    state_ = MacNativeDesktopOwnerState::Revoked;
    authorization_ = nullptr;
    authorizationGeneration_ = 0;
    authenticationGeneration_ = 0;
    permissionMask_ = 0;
    targetUserId_ = 0;
    pixelGeometry_ = {};
    geometryGeneration_ = 0;

    if (input_) {
        input_->retireWithoutNativeInput();
    }
    if (frameMailbox_) {
        frameMailbox_->retire();
    }
    if (capture_) {
        capture_->close();
    }
    if (sessionGuard_) {
        sessionGuard_->close();
    }
    geometry_.invalidate();

    input_.reset();
    capture_.reset();
    sessionGuard_.reset();
    frameMailbox_.reset();
    (void)sessionWatch_.stop();
#if defined(__APPLE__)
    (void)displayWatch_.stopWithCallbacks();
#endif
}

} // namespace rdp::macos
