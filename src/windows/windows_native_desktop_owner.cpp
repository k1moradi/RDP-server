// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows_native_desktop_owner.h"

#include <new>
#include <span>
#include <utility>

namespace rdp_server::windows
{
namespace
{
using rdp_server::server::security::WindowsNativeDesktopAuthorization;
using rdp_server::server::security::WindowsNativeDesktopAuthorizationView;
using rdp_server::server::security::kConsoleInputPermission;
using rdp_server::server::security::kConsoleViewPermission;

[[nodiscard]] bool acceptAuthorization(
    const WindowsNativeDesktopAuthorizationView &authorization,
    void *context) noexcept
{
    auto &visited = *static_cast<bool *>(context);
    visited = authorization.authorizationGeneration() != 0 &&
              authorization.wtsSessionId() != 0;
    return visited;
}

[[nodiscard]] bool revalidatesAuthorization(
    const WindowsNativeDesktopAuthorization &authorization,
    std::uint64_t expectedAuthorizationGeneration,
    std::uint32_t requiredPermissions) noexcept
{
    if (expectedAuthorizationGeneration == 0)
        return false;
    bool visited = false;
    return authorization.visit(
               expectedAuthorizationGeneration, requiredPermissions,
               &acceptAuthorization, &visited) &&
           visited;
}

#if defined(_WIN32)
[[nodiscard]] bool validAuthorizedConfiguration(
    const WindowsNativeDesktopTestConfiguration &configuration,
    std::uint32_t permissionMask,
    bool requireInjectedCapture) noexcept
{
    if (configuration.layout.monitorCount != 1 ||
        configuration.target.monitor == 0 ||
        configuration.layout.virtualBounds != configuration.target.expectedBounds ||
        configuration.layout.monitors[0] != configuration.target.expectedBounds ||
        configuration.sessionReader.read == nullptr ||
        configuration.cursorReader.read == nullptr)
        return false;

    if ((permissionMask & kConsoleInputPermission) != 0 &&
        (configuration.inputCallbacks.context == nullptr ||
         configuration.inputCallbacks.send == nullptr))
        return false;

    WindowsDesktopLayout validated{};
    if (!makeWindowsDesktopLayout(
            std::span<const PortableRectangle>{
                configuration.layout.monitors.data(),
                configuration.layout.monitorCount},
            validated) ||
        validated != configuration.layout)
        return false;

    const auto &dxgi = configuration.dxgiCallbacks;
    if (dxgi.context == nullptr || dxgi.createFactory == nullptr ||
        dxgi.adapterAt == nullptr || dxgi.outputAt == nullptr ||
        dxgi.describeOutput == nullptr || dxgi.createDevice == nullptr ||
        dxgi.queryOutput1 == nullptr || dxgi.duplicate == nullptr ||
        dxgi.release == nullptr)
        return false;

    if (!requireInjectedCapture)
        return true;

    const auto &capture = configuration.captureCallbacks;
    return capture.frame.context != nullptr &&
           capture.frame.acquire != nullptr &&
           capture.frame.release != nullptr &&
           capture.staging.context != nullptr &&
           capture.staging.stageAndMap != nullptr &&
           capture.staging.unmapAndRelease != nullptr;
}
#endif
} // namespace

struct WindowsNativeDesktopOwner::State final
{
    const WindowsNativeDesktopAuthorization *authorization{};
    std::uint64_t authenticationGeneration{};
    std::uint64_t authorizationGeneration{};
    std::uint32_t permissionMask{};
    std::uint32_t targetSessionId{};
    WindowsDesktopLayout layout{};
    std::unique_ptr<WindowsCaptureSessionGenerationGuard> sessionGuard{};
    std::unique_ptr<WindowsDxgiDuplicationOwner> duplicationOwner{};
    std::unique_ptr<WindowsInputController> inputController{};
    WindowsCursorReadCallbacks cursorReader{};
    WindowsCaptureGeneration pinnedGeneration{};

    static bool readGeneration(
        void *context, WindowsCaptureGeneration &current) noexcept
    {
        auto &state = *static_cast<State *>(context);
        if (state.authorizationGeneration == 0 ||
            state.duplicationOwner == nullptr ||
            !state.duplicationOwner->ready())
            return false;
        const std::uint64_t deviceEpoch = state.duplicationOwner->deviceEpoch();
        if (deviceEpoch == 0)
            return false;
        current = {state.authorizationGeneration, deviceEpoch};
        return true;
    }

    [[nodiscard]] bool generationCurrent() noexcept
    {
        if (sessionGuard == nullptr || sessionGuard->closed() ||
            pinnedGeneration.session == 0 || pinnedGeneration.device == 0)
            return false;
        const WindowsCaptureGenerationReader reader = sessionGuard->reader();
        WindowsCaptureGeneration current{};
        return reader.context != nullptr && reader.read != nullptr &&
               reader.read(reader.context, current) &&
               current == pinnedGeneration;
    }
};

#if defined(_WIN32)
struct WindowsNativeDesktopOwner::InitializationVisitContext final
{
    WindowsNativeDesktopOwner *owner{};
    const WindowsNativeDesktopAuthorization *authorization{};
    WindowsNativeDesktopTestConfiguration *configuration{};
    bool nativeConstruction{};
    WindowsNativeDesktopOpenResult result{
        WindowsNativeDesktopOpenResult::nativeCompositionUnavailable};
    bool callbackReached{};
};
#endif
struct WindowsNativeDesktopOwner::ServiceVisitContext final
{
    WindowsNativeDesktopOwner *owner{};
    WindowsR4BgraFrameConsumer frameConsumer{};
    WindowsNativeDesktopServiceResult result{
        WindowsNativeDesktopServiceResult::failed};
    bool callbackReached{};
    bool retire{};
};
struct WindowsNativeDesktopOwner::InputVisitContext final
{
    WindowsNativeDesktopOwner *owner{};
    const WindowsInputEvent *event{};
    bool callbackReached{};
    bool handled{};
    bool retire{};
};
struct WindowsNativeDesktopOwner::CursorVisitContext final
{
    WindowsNativeDesktopOwner *owner{};
    WindowsCursorSnapshot *output{};
    WindowsCursorReadResult result{WindowsCursorReadResult::failed};
    bool callbackReached{};
    bool retire{};
};

WindowsNativeDesktopOwner::WindowsNativeDesktopOwner() noexcept = default;
WindowsNativeDesktopOwner::~WindowsNativeDesktopOwner() noexcept
{
    retireAfterAuthorizationLoss();
}

WindowsNativeDesktopOpenResult WindowsNativeDesktopOwner::open(
    const WindowsNativeDesktopAuthorization &authorization,
    std::uint64_t expectedAuthorizationGeneration) noexcept
{
    if (retired_)
        return WindowsNativeDesktopOpenResult::closed;
    if (state_ != nullptr)
        return WindowsNativeDesktopOpenResult::closed;
    if (!revalidatesAuthorization(
            authorization, expectedAuthorizationGeneration,
            kConsoleViewPermission))
        return WindowsNativeDesktopOpenResult::authorizationDenied;

    if (!kWindowsNativeDesktopPositiveActivationApproved)
        return WindowsNativeDesktopOpenResult::nativeCompositionUnavailable;

#if defined(_WIN32)
    InitializationVisitContext context{
        this, &authorization, nullptr, true,
        WindowsNativeDesktopOpenResult::nativeCompositionUnavailable, false};
    const bool authorized = authorization.visit(
        expectedAuthorizationGeneration, kConsoleViewPermission,
        &WindowsNativeDesktopOwner::initializeAuthorizationVisit, &context);
    if (!authorized || !context.callbackReached)
    {
        if (state_ != nullptr)
            retireAfterAuthorizationLoss();
        return WindowsNativeDesktopOpenResult::authorizationDenied;
    }
    return context.result;
#else
    return WindowsNativeDesktopOpenResult::nativeCompositionUnavailable;
#endif
}

#if defined(_WIN32)
WindowsNativeDesktopOpenResult WindowsNativeDesktopOwner::openForTesting(
    const WindowsNativeDesktopAuthorization &authorization,
    std::uint64_t expectedAuthorizationGeneration,
    WindowsNativeDesktopTestConfiguration configuration) noexcept
{
    if (retired_)
        return WindowsNativeDesktopOpenResult::closed;
    if (state_ != nullptr)
        return WindowsNativeDesktopOpenResult::closed;
    if (expectedAuthorizationGeneration == 0)
        return WindowsNativeDesktopOpenResult::authorizationDenied;

    InitializationVisitContext context{
        this, &authorization, &configuration, false,
        WindowsNativeDesktopOpenResult::nativeCompositionUnavailable, false};
    const bool authorized = authorization.visit(
        expectedAuthorizationGeneration, kConsoleViewPermission,
        &WindowsNativeDesktopOwner::initializeAuthorizationVisit, &context);
    if (!authorized || !context.callbackReached)
    {
        if (state_ != nullptr)
            retireAfterAuthorizationLoss();
        return WindowsNativeDesktopOpenResult::authorizationDenied;
    }
    return context.result;
}

bool WindowsNativeDesktopOwner::initializeAuthorizationVisit(
    const WindowsNativeDesktopAuthorizationView &authorizationView,
    void *contextValue) noexcept
{
    auto &context = *static_cast<InitializationVisitContext *>(contextValue);
    context.callbackReached = true;
    if (context.owner == nullptr || context.authorization == nullptr)
        return true;

    if (context.nativeConstruction)
    {
        context.result = context.owner->initializeNativeAuthorized(
            *context.authorization, authorizationView);
        return true;
    }
    if (context.configuration == nullptr)
        return true;

    context.result = context.owner->initializeForTestingAuthorized(
        *context.authorization, authorizationView,
        std::move(*context.configuration));
    return true;
}

WindowsNativeDesktopOpenResult
WindowsNativeDesktopOwner::initializeNativeAuthorized(
    const WindowsNativeDesktopAuthorization &authorization,
    const WindowsNativeDesktopAuthorizationView &authorizationView) noexcept
{
    WindowsSingleMonitorDesktopTarget target{};
    if (!readWindowsSingleMonitorDesktopTarget(target))
        return WindowsNativeDesktopOpenResult::nativeCompositionUnavailable;

    WindowsNativeDesktopTestConfiguration configuration{};
    configuration.layout = target.layout;
    configuration.target = {target.monitor, target.layout.monitors[0]};
    configuration.sessionReader = windowsCaptureSessionReadCallbacks();
    configuration.dxgiCallbacks = windowsNativeDxgiDuplicationCallbacks();
    configuration.cursorReader = windowsCursorReadCallbacks();
    if ((authorizationView.permissionMask() & kConsoleInputPermission) != 0)
        configuration.inputCallbacks =
            WindowsInputController::windowsNativeCallbacks();

    return initializeAuthorized(
        authorization, authorizationView, std::move(configuration), false);
}

WindowsNativeDesktopOpenResult
WindowsNativeDesktopOwner::initializeForTestingAuthorized(
    const WindowsNativeDesktopAuthorization &authorization,
    const WindowsNativeDesktopAuthorizationView &authorizationView,
    WindowsNativeDesktopTestConfiguration &&configuration) noexcept
{
    return initializeAuthorized(
        authorization, authorizationView, std::move(configuration), true);
}

WindowsNativeDesktopOpenResult
WindowsNativeDesktopOwner::initializeAuthorized(
    const WindowsNativeDesktopAuthorization &authorization,
    const WindowsNativeDesktopAuthorizationView &authorizationView,
    WindowsNativeDesktopTestConfiguration &&configuration,
    bool requireInjectedCapture) noexcept
{
    if (state_ != nullptr || authorizationView.authenticationGeneration() == 0 ||
        authorizationView.authorizationGeneration() == 0 ||
        authorizationView.wtsSessionId() == 0 ||
        (authorizationView.permissionMask() & kConsoleViewPermission) == 0 ||
        !validAuthorizedConfiguration(
            configuration, authorizationView.permissionMask(),
            requireInjectedCapture))
        return WindowsNativeDesktopOpenResult::nativeCompositionUnavailable;

    auto candidate = std::unique_ptr<State>{new (std::nothrow) State{}};
    if (candidate == nullptr)
        return WindowsNativeDesktopOpenResult::nativeCompositionUnavailable;
    candidate->authorization = &authorization;
    candidate->authenticationGeneration =
        authorizationView.authenticationGeneration();
    candidate->authorizationGeneration =
        authorizationView.authorizationGeneration();
    candidate->permissionMask = authorizationView.permissionMask();
    candidate->targetSessionId = authorizationView.wtsSessionId();
    candidate->layout = configuration.layout;
    candidate->cursorReader = configuration.cursorReader;

    candidate->duplicationOwner =
        std::unique_ptr<WindowsDxgiDuplicationOwner>{
            new (std::nothrow) WindowsDxgiDuplicationOwner(
                configuration.dxgiCallbacks, configuration.captureCallbacks)};
    if (candidate->duplicationOwner == nullptr ||
        candidate->duplicationOwner->open(configuration.target) !=
            WindowsDxgiDuplicationResult::ready)
        return WindowsNativeDesktopOpenResult::nativeCompositionUnavailable;

    candidate->sessionGuard =
        std::unique_ptr<WindowsCaptureSessionGenerationGuard>{
            new (std::nothrow) WindowsCaptureSessionGenerationGuard(
                candidate->targetSessionId, configuration.sessionReader,
                WindowsCaptureGenerationReader{candidate.get(), &State::readGeneration})};
    if (candidate->sessionGuard == nullptr || candidate->sessionGuard->closed())
        return WindowsNativeDesktopOpenResult::nativeCompositionUnavailable;

    const WindowsCaptureGenerationReader generationReader =
        candidate->sessionGuard->reader();
    WindowsCaptureGeneration pinned{};
    if (generationReader.context == nullptr ||
        generationReader.read == nullptr ||
        !generationReader.read(generationReader.context, pinned) ||
        pinned.session != candidate->authorizationGeneration ||
        pinned.device != candidate->duplicationOwner->deviceEpoch())
        return WindowsNativeDesktopOpenResult::nativeCompositionUnavailable;
    candidate->pinnedGeneration = pinned;

    bool attached = false;
    try
    {
        attached = candidate->duplicationOwner->attachCaptureCycle(
            candidate->layout, candidate->sessionGuard->reader(),
            pinned.session);
    }
    catch (const std::bad_alloc &)
    {
        attached = false;
    }
    if (!attached)
        return WindowsNativeDesktopOpenResult::nativeCompositionUnavailable;

    if ((candidate->permissionMask & kConsoleInputPermission) != 0)
    {
        candidate->inputController =
            std::unique_ptr<WindowsInputController>{
                new (std::nothrow) WindowsInputController(
                    candidate->layout, configuration.inputCallbacks,
                    candidate->sessionGuard->reader(), pinned)};
        if (candidate->inputController == nullptr ||
            candidate->inputController->closed())
            return WindowsNativeDesktopOpenResult::nativeCompositionUnavailable;
    }

    state_ = std::move(candidate);
    return ready() ? WindowsNativeDesktopOpenResult::ready
                   : WindowsNativeDesktopOpenResult::nativeCompositionUnavailable;
}
#endif

bool WindowsNativeDesktopOwner::authorizationViewMatches(
    const WindowsNativeDesktopAuthorizationView &authorizationView,
    std::uint32_t requiredPermissions) const noexcept
{
    return state_ != nullptr &&
           state_->authenticationGeneration != 0 &&
           state_->authenticationGeneration ==
               authorizationView.authenticationGeneration() &&
           state_->authorizationGeneration ==
               authorizationView.authorizationGeneration() &&
           state_->permissionMask == authorizationView.permissionMask() &&
           state_->targetSessionId == authorizationView.wtsSessionId() &&
           (state_->permissionMask & requiredPermissions) ==
               requiredPermissions;
}

bool WindowsNativeDesktopOwner::serviceAuthorizationVisit(
    const WindowsNativeDesktopAuthorizationView &authorizationView,
    void *contextValue) noexcept
{
    auto &context = *static_cast<ServiceVisitContext *>(contextValue);
    context.callbackReached = true;
    if (context.owner == nullptr ||
        !context.owner->authorizationViewMatches(
            authorizationView, kConsoleViewPermission))
    {
        context.result = WindowsNativeDesktopServiceResult::authorizationRequired;
        context.retire = true;
        return true;
    }
#if defined(_WIN32)
    State &state = *context.owner->state_;
    if (!state.generationCurrent() || state.duplicationOwner == nullptr)
    {
        context.result = WindowsNativeDesktopServiceResult::failed;
        context.retire = true;
        return true;
    }
    WindowsDxgiCaptureCycle *const captureCycle =
        state.duplicationOwner->captureCycle();
    if (captureCycle == nullptr || captureCycle->closed())
    {
        context.result = WindowsNativeDesktopServiceResult::closed;
        context.retire = true;
        return true;
    }
    switch (captureCycle->captureFrame(0))
    {
    case WindowsCaptureCycleResult::timeout:
    case WindowsCaptureCycleResult::notReady:
        context.result = WindowsNativeDesktopServiceResult::idle;
        return true;
    case WindowsCaptureCycleResult::mapped:
        break;
    case WindowsCaptureCycleResult::closed:
        context.result = WindowsNativeDesktopServiceResult::closed;
        context.retire = true;
        return true;
    default:
        context.result = WindowsNativeDesktopServiceResult::failed;
        context.retire = true;
        return true;
    }
    switch (captureCycle->consumeR4Frame(context.frameConsumer))
    {
    case WindowsCaptureConsumeResult::consumed:
        context.result = WindowsNativeDesktopServiceResult::frameConsumed;
        return true;
    case WindowsCaptureConsumeResult::noFrame:
        context.result = WindowsNativeDesktopServiceResult::idle;
        return true;
    case WindowsCaptureConsumeResult::closed:
        context.result = WindowsNativeDesktopServiceResult::closed;
        context.retire = true;
        return true;
    default:
        context.result = WindowsNativeDesktopServiceResult::failed;
        context.retire = true;
        return true;
    }
#else
    context.result = WindowsNativeDesktopServiceResult::nativeCompositionUnavailable;
    return true;
#endif
}

WindowsNativeDesktopServiceResult WindowsNativeDesktopOwner::serviceOnce(
    const WindowsNativeDesktopAuthorization &authorization,
    std::uint64_t expectedAuthorizationGeneration,
    WindowsR4BgraFrameConsumer frameConsumer) noexcept
{
    if (retired_)
        return WindowsNativeDesktopServiceResult::closed;
    if (state_ == nullptr)
    {
        if (!revalidatesAuthorization(
                authorization, expectedAuthorizationGeneration,
                kConsoleViewPermission))
            return WindowsNativeDesktopServiceResult::authorizationRequired;
        return WindowsNativeDesktopServiceResult::nativeCompositionUnavailable;
    }
    if (state_->authorization != &authorization ||
        state_->authorizationGeneration != expectedAuthorizationGeneration)
    {
        retireAfterAuthorizationLoss();
        return WindowsNativeDesktopServiceResult::authorizationRequired;
    }
    ServiceVisitContext context{this, frameConsumer};
    const bool authorized = authorization.visit(
        expectedAuthorizationGeneration, kConsoleViewPermission,
        &WindowsNativeDesktopOwner::serviceAuthorizationVisit, &context);
    if (!authorized || !context.callbackReached)
    {
        retireAfterAuthorizationLoss();
        return WindowsNativeDesktopServiceResult::authorizationRequired;
    }
    const auto result = context.result;
    if (context.retire)
        retireAfterAuthorizationLoss();
    return result;
}

bool WindowsNativeDesktopOwner::inputAuthorizationVisit(
    const WindowsNativeDesktopAuthorizationView &authorizationView,
    void *contextValue) noexcept
{
    auto &context = *static_cast<InputVisitContext *>(contextValue);
    context.callbackReached = true;
    if (context.owner == nullptr || context.event == nullptr ||
        !context.owner->authorizationViewMatches(
            authorizationView, kConsoleInputPermission))
    {
        context.retire = true;
        return true;
    }
    State &state = *context.owner->state_;
    if (state.inputController == nullptr || state.inputController->closed())
    {
        context.retire = true;
        return true;
    }
    context.handled = state.inputController->handle(*context.event);
    context.retire = state.inputController->closed() ||
                     state.sessionGuard == nullptr ||
                     state.sessionGuard->closed() ||
                     state.duplicationOwner == nullptr ||
                     !state.duplicationOwner->ready();
    return true;
}

bool WindowsNativeDesktopOwner::handleInput(
    const WindowsNativeDesktopAuthorization &authorization,
    std::uint64_t expectedAuthorizationGeneration,
    const WindowsInputEvent &event) noexcept
{
    if (retired_)
        return false;
    if (state_ == nullptr)
    {
        (void)revalidatesAuthorization(
            authorization, expectedAuthorizationGeneration,
            kConsoleInputPermission);
        return false;
    }
    if (state_->authorization != &authorization ||
        state_->authorizationGeneration != expectedAuthorizationGeneration)
    {
        retireAfterAuthorizationLoss();
        return false;
    }
    InputVisitContext context{this, &event};
    const bool authorized = authorization.visit(
        expectedAuthorizationGeneration, kConsoleInputPermission,
        &WindowsNativeDesktopOwner::inputAuthorizationVisit, &context);
    if (!authorized || !context.callbackReached)
    {
        retireAfterAuthorizationLoss();
        return false;
    }
    const bool handled = context.handled;
    if (context.retire)
        retireAfterAuthorizationLoss();
    return handled;
}

bool WindowsNativeDesktopOwner::cursorAuthorizationVisit(
    const WindowsNativeDesktopAuthorizationView &authorizationView,
    void *contextValue) noexcept
{
    auto &context = *static_cast<CursorVisitContext *>(contextValue);
    context.callbackReached = true;
    if (context.owner == nullptr || context.output == nullptr ||
        !context.owner->authorizationViewMatches(
            authorizationView, kConsoleViewPermission))
    {
        context.retire = true;
        return true;
    }
    State &state = *context.owner->state_;
    if (!state.generationCurrent())
    {
        context.retire = true;
        return true;
    }
    context.result = readWindowsCursorSnapshot(
        state.layout, state.cursorReader, *context.output);
    if (!state.generationCurrent())
    {
        context.result = WindowsCursorReadResult::failed;
        context.retire = true;
    }
    return true;
}

WindowsCursorReadResult WindowsNativeDesktopOwner::readCursorSnapshot(
    const WindowsNativeDesktopAuthorization &authorization,
    std::uint64_t expectedAuthorizationGeneration,
    WindowsCursorSnapshot &output) noexcept
{
    if (retired_)
        return WindowsCursorReadResult::failed;
    if (state_ == nullptr)
    {
        (void)revalidatesAuthorization(
            authorization, expectedAuthorizationGeneration,
            kConsoleViewPermission);
        return WindowsCursorReadResult::failed;
    }
    if (state_->authorization != &authorization ||
        state_->authorizationGeneration != expectedAuthorizationGeneration)
    {
        retireAfterAuthorizationLoss();
        return WindowsCursorReadResult::failed;
    }
    CursorVisitContext context{this, &output};
    const bool authorized = authorization.visit(
        expectedAuthorizationGeneration, kConsoleViewPermission,
        &WindowsNativeDesktopOwner::cursorAuthorizationVisit, &context);
    if (!authorized || !context.callbackReached)
    {
        retireAfterAuthorizationLoss();
        return WindowsCursorReadResult::failed;
    }
    const auto result = context.result;
    if (context.retire)
        retireAfterAuthorizationLoss();
    return result;
}

WindowsCaptureSessionChangeResult
WindowsNativeDesktopOwner::notifySessionChange(std::uint32_t sessionId) noexcept
{
    if (state_ == nullptr || state_->sessionGuard == nullptr)
        return WindowsCaptureSessionChangeResult::alreadyClosed;
    const auto result = state_->sessionGuard->notifySessionChange(sessionId);
    if (result != WindowsCaptureSessionChangeResult::ignored ||
        state_->sessionGuard->closed())
        retireAfterAuthorizationLoss();
    return result;
}

void WindowsNativeDesktopOwner::retireAfterAuthorizationLoss() noexcept
{
    retired_ = true;
    if (state_ == nullptr)
        return;
    if (state_->sessionGuard != nullptr && !state_->sessionGuard->closed())
        (void)state_->sessionGuard->notifySessionChange(state_->targetSessionId);
    if (state_->inputController != nullptr)
        state_->inputController->retireWithoutNativeInput();
    if (state_->duplicationOwner != nullptr)
    {
        state_->duplicationOwner->close();
        state_->duplicationOwner->completeDeferredClose();
    }
    state_->inputController.reset();
    state_->duplicationOwner.reset();
    state_->sessionGuard.reset();
    state_.reset();
}

bool WindowsNativeDesktopOwner::ready() const noexcept
{
    return !retired_ && state_ != nullptr &&
           state_->authorization != nullptr &&
           state_->authenticationGeneration != 0 &&
           state_->authorizationGeneration != 0 &&
           (state_->permissionMask & kConsoleViewPermission) != 0 &&
           state_->targetSessionId != 0 &&
           state_->sessionGuard != nullptr &&
           !state_->sessionGuard->closed() &&
           state_->duplicationOwner != nullptr &&
           state_->duplicationOwner->ready() &&
           ((state_->permissionMask & kConsoleInputPermission) == 0 ||
            (state_->inputController != nullptr &&
             !state_->inputController->closed())) &&
           state_->cursorReader.read != nullptr &&
           state_->pinnedGeneration.session != 0 &&
           state_->pinnedGeneration.device != 0;
}

} // namespace rdp_server::windows
