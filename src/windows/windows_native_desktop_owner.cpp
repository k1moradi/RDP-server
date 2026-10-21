// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows_native_desktop_owner.h"

#include "windows_dxgi_duplication_owner.h"

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

} // namespace

// The state shape establishes one aggregate lifetime without introducing a
// synthetic grant. R10 integration may populate it only inside a successful R2
// authorization visit and must keep the authorization owner alive longer than
// this R6 owner.
struct WindowsNativeDesktopOwner::State final
{
    const WindowsNativeDesktopAuthorization *authorization{};
    std::uint64_t authorizationGeneration{};
    std::uint32_t targetSessionId{};
    WindowsDesktopLayout layout{};
    std::unique_ptr<WindowsCaptureSessionGenerationGuard> sessionGuard{};
    std::unique_ptr<WindowsDxgiDuplicationOwner> duplicationOwner{};
    std::unique_ptr<WindowsInputController> inputController{};
    WindowsCursorReadCallbacks cursorReader{};
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
    {
        return WindowsNativeDesktopOpenResult::authorizationDenied;
    }

    // R2 is now wired into the R6 boundary, but R10 has not yet supplied the
    // single-owner native composition that may create WTS/DXGI/input state.
    // Do not sample layout, open DXGI, read a cursor or obtain SendInput here.
    static_assert(!kWindowsNativeDesktopPositiveActivationApproved);
    return WindowsNativeDesktopOpenResult::nativeCompositionUnavailable;
}

WindowsNativeDesktopServiceResult WindowsNativeDesktopOwner::serviceOnce(
    const WindowsNativeDesktopAuthorization &authorization,
    std::uint64_t expectedAuthorizationGeneration,
    WindowsR4BgraFrameConsumer frameConsumer) noexcept
{
    (void)frameConsumer;
    if (retired_)
        return WindowsNativeDesktopServiceResult::closed;
    if (!revalidatesAuthorization(
            authorization, expectedAuthorizationGeneration,
            kConsoleViewPermission))
    {
        if (state_ != nullptr)
            retireAfterAuthorizationLoss();
        return WindowsNativeDesktopServiceResult::authorizationRequired;
    }
    if (state_ == nullptr)
        return WindowsNativeDesktopServiceResult::nativeCompositionUnavailable;

    // Positive state cannot yet be populated; retain a fail-closed result if a
    // future partial integration reaches this branch without the service body.
    return WindowsNativeDesktopServiceResult::failed;
}

bool WindowsNativeDesktopOwner::handleInput(
    const WindowsNativeDesktopAuthorization &authorization,
    std::uint64_t expectedAuthorizationGeneration,
    const WindowsInputEvent &event) noexcept
{
    (void)event;
    if (retired_ ||
        !revalidatesAuthorization(
            authorization, expectedAuthorizationGeneration,
            kConsoleInputPermission))
    {
        if (state_ != nullptr)
            retireAfterAuthorizationLoss();
        return false;
    }

    // The real SendInput callbacks are private to this class through
    // WindowsInputController friendship, but R10 composition is not yet live.
    // Never call them merely because an R2 visit succeeded.
    return false;
}

WindowsCursorReadResult WindowsNativeDesktopOwner::readCursorSnapshot(
    const WindowsNativeDesktopAuthorization &authorization,
    std::uint64_t expectedAuthorizationGeneration,
    WindowsCursorSnapshot &output) noexcept
{
    (void)output;
    if (retired_ ||
        !revalidatesAuthorization(
            authorization, expectedAuthorizationGeneration,
            kConsoleViewPermission))
    {
        if (state_ != nullptr)
            retireAfterAuthorizationLoss();
        return WindowsCursorReadResult::failed;
    }

    // Cursor access stays disabled with the rest of positive composition.
    return WindowsCursorReadResult::failed;
}

WindowsCaptureSessionChangeResult
WindowsNativeDesktopOwner::notifySessionChange(
    std::uint32_t sessionId) noexcept
{
    if (state_ == nullptr || state_->sessionGuard == nullptr)
        return WindowsCaptureSessionChangeResult::alreadyClosed;

    const auto result = state_->sessionGuard->notifySessionChange(sessionId);
    if (result != WindowsCaptureSessionChangeResult::ignored ||
        state_->sessionGuard->closed())
    {
        retireAfterAuthorizationLoss();
    }
    return result;
}

void WindowsNativeDesktopOwner::retireAfterAuthorizationLoss() noexcept
{
    retired_ = true;
    if (state_ == nullptr)
        return;

    // Close revocation-only WTS generation first. Upstream R2/R3 authority is
    // already gone, so held input must be discarded without key/button posts.
    if (state_->sessionGuard != nullptr && !state_->sessionGuard->closed())
    {
        (void)state_->sessionGuard->notifySessionChange(
            state_->targetSessionId);
    }
    if (state_->inputController != nullptr)
        state_->inputController->retireWithoutNativeInput();

    if (state_->duplicationOwner != nullptr)
    {
        state_->duplicationOwner->close();
        state_->duplicationOwner->completeDeferredClose();
    }

    // Explicit reset order documents security-significant teardown.
    state_->inputController.reset();
    state_->duplicationOwner.reset();
    state_->sessionGuard.reset();
    state_.reset();
}

bool WindowsNativeDesktopOwner::ready() const noexcept
{
    return !retired_ && state_ != nullptr &&
           state_->authorization != nullptr &&
           state_->authorizationGeneration != 0 &&
           state_->sessionGuard != nullptr &&
           !state_->sessionGuard->closed() &&
           state_->duplicationOwner != nullptr &&
           state_->duplicationOwner->ready() &&
           state_->inputController != nullptr;
}

} // namespace rdp_server::windows
