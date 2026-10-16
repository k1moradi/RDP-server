// SPDX-License-Identifier: GPL-3.0-or-later

#include "x11_desktop_resources.h"

namespace
{

class X11DesktopResourceEventSink final : public X11EventSink
{
public:
    X11DesktopResourceEventSink(X11CursorTracker &cursor,
                                X11DamageTracker &damage,
                                X11EventSink *additionalEventSink) noexcept
        : cursor_(cursor),
          damage_(damage),
          additionalEventSink_(additionalEventSink)
    {
    }

    void handle(const xcb_generic_event_t &event) noexcept override
    {
        cursor_.handle(event);
        damage_.handle(event);
        if (additionalEventSink_ != nullptr)
        {
            additionalEventSink_->handle(event);
        }
    }

private:
    X11CursorTracker &cursor_;
    X11DamageTracker &damage_;
    X11EventSink *additionalEventSink_{};
};

} // namespace

X11DesktopResources::X11DesktopResources(
    std::string_view displayName,
    std::uint64_t maximumCapturePixels) noexcept
    : display_(displayName), maximumCapturePixels_(maximumCapturePixels)
{
    if (!display_.valid())
    {
        fail("X11 desktop display connection failed");
        cancelNativeResources();
        return;
    }

    xcb_connection_t *connection = display_.nativeConnection();
    const PixelSize geometry = display_.sourceGeometry();
    if (connection == nullptr || geometry.widthPixels == 0 ||
        geometry.heightPixels == 0)
    {
        fail("X11 desktop display geometry is invalid");
        cancelNativeResources();
        return;
    }

    capture_.emplace(*connection, display_.rootWindow(), display_.rootVisual(),
                     display_.rootDepth(), geometry, maximumCapturePixels_);
    if (!capture_->valid())
    {
        fail(capture_->failureReason());
        cancelNativeResources();
        return;
    }

    cursor_.emplace(*connection, display_.rootWindow());
    if (!cursor_->valid())
    {
        fail(cursor_->failureReason());
        cancelNativeResources();
        return;
    }

    damage_.emplace(*connection, display_.rootWindow(), geometry);
    if (!damage_->valid())
    {
        fail(damage_->failureReason());
        cancelNativeResources();
        return;
    }

    input_.emplace(*connection, display_.rootWindow(), geometry);
    if (!input_->valid())
    {
        fail(input_->failureReason());
        cancelNativeResources();
        return;
    }

    resourceGeometry_ = geometry;
    failureReason_ = nullptr;
}

X11DesktopResources::~X11DesktopResources() noexcept
{
    disconnect();
}

bool
X11DesktopResources::valid() const noexcept
{
    return failureReason_ == nullptr && display_.valid() &&
           childrenValid() && resourceGeometry_ == display_.sourceGeometry();
}

const char *
X11DesktopResources::failureReason() const noexcept
{
    return failureReason_;
}

int
X11DesktopResources::fileDescriptor() const noexcept
{
    return valid() ? display_.fileDescriptor() : -1;
}

xcb_connection_t *
X11DesktopResources::nativeConnection() const noexcept
{
    return valid() ? display_.nativeConnection() : nullptr;
}

xcb_window_t
X11DesktopResources::rootWindow() const noexcept
{
    return valid() ? display_.rootWindow() : xcb_window_t{};
}

PixelSize
X11DesktopResources::sourceGeometry() const noexcept
{
    return valid() ? resourceGeometry_ : PixelSize{};
}

bool
X11DesktopResources::randrAvailable() const noexcept
{
    return valid() && display_.randrAvailable();
}

bool
X11DesktopResources::damagePending() const noexcept
{
    return valid() && damage_->hasPendingDamage();
}

std::uint64_t
X11DesktopResources::damageNotificationCount() const noexcept
{
    return valid() ? damage_->notificationCount() : 0;
}

ConnectionStatus
X11DesktopResources::processEvents(std::size_t eventBudget,
                                  bool *workMayRemain,
                                  bool socketReadable,
                                  X11EventSink *additionalEventSink) noexcept
{
    if (workMayRemain != nullptr)
    {
        *workMayRemain = false;
    }
    if (failureReason_ != nullptr || !display_.valid() || !childrenValid() ||
        resourceGeometry_ != display_.sourceGeometry())
    {
        if (failureReason_ == nullptr)
        {
            fail("X11 desktop resources became invalid before event dispatch");
        }
        cancelNativeResources();
        return ConnectionStatus::Failed;
    }

    X11DesktopResourceEventSink eventSink(
        *cursor_, *damage_, additionalEventSink);
    const ConnectionStatus status = display_.processEvents(
        eventSink, eventBudget, workMayRemain, socketReadable);
    if (status == ConnectionStatus::Failed)
    {
        if (workMayRemain != nullptr)
        {
            *workMayRemain = false;
        }
        fail("X11 desktop event dispatch failed");
        cancelNativeResources();
        return ConnectionStatus::Failed;
    }

    const PixelSize observedGeometry = display_.sourceGeometry();
    if (observedGeometry != resourceGeometry_)
    {
        if (!rebuildGeometryBoundResources(observedGeometry))
        {
            if (workMayRemain != nullptr)
            {
                *workMayRemain = false;
            }
            return ConnectionStatus::Failed;
        }

        // The display drain stops immediately after a valid RandR screen
        // change. Service any events queued behind it only after the new
        // geometry-bound generation is fully committed.
        if (workMayRemain != nullptr)
        {
            *workMayRemain = true;
        }
    }
    if (!childrenValid())
    {
        if (workMayRemain != nullptr)
        {
            *workMayRemain = false;
        }
        fail("X11 desktop child resource failed during event dispatch");
        cancelNativeResources();
        return ConnectionStatus::Failed;
    }

    return ConnectionStatus::Ok;
}

void
X11DesktopResources::disconnect() noexcept
{
    const bool wasHealthy = failureReason_ == nullptr;
    cancelNativeResources();
    if (wasHealthy)
    {
        failureReason_ = "X11 desktop resources are disconnected";
    }
}

void
X11DesktopResources::fail(const char *reason) noexcept
{
    failureReason_ = reason != nullptr ? reason : "X11 desktop resource failure";
}

void
X11DesktopResources::cancelGeometryBoundResources() noexcept
{
    // Input can retain pressed native state and must release it before any
    // other geometry-bound resource is replaced or the connection is closed.
    if (input_)
    {
        input_->disconnect();
        input_.reset();
    }
    if (damage_)
    {
        damage_->disconnect();
        damage_.reset();
    }
    if (capture_)
    {
        capture_->disconnect();
        capture_.reset();
    }
    resourceGeometry_ = {};
}

bool
X11DesktopResources::rebuildGeometryBoundResources(
    PixelSize geometry) noexcept
{
    xcb_connection_t *connection = display_.nativeConnection();
    if (connection == nullptr || geometry.widthPixels == 0 ||
        geometry.heightPixels == 0)
    {
        fail("X11 desktop resize geometry is invalid");
        cancelNativeResources();
        return false;
    }

    // Commit-or-revoke transaction: no public call can observe the interval
    // between old-generation cancellation and complete new construction.
    cancelGeometryBoundResources();

    capture_.emplace(*connection, display_.rootWindow(), display_.rootVisual(),
                     display_.rootDepth(), geometry, maximumCapturePixels_);
    if (!capture_->valid())
    {
        fail(capture_->failureReason());
        cancelNativeResources();
        return false;
    }

    damage_.emplace(*connection, display_.rootWindow(), geometry);
    if (!damage_->valid())
    {
        fail(damage_->failureReason());
        cancelNativeResources();
        return false;
    }

    input_.emplace(*connection, display_.rootWindow(), geometry);
    if (!input_->valid())
    {
        fail(input_->failureReason());
        cancelNativeResources();
        return false;
    }

    resourceGeometry_ = geometry;
    return true;
}

void
X11DesktopResources::cancelNativeResources() noexcept
{
    cancelGeometryBoundResources();

    // Cursor is not geometry-bound, but it still borrows the same connection.
    if (cursor_)
    {
        cursor_->disconnect();
        cursor_.reset();
    }

    display_.disconnect();
}

bool
X11DesktopResources::childrenValid() const noexcept
{
    return capture_.has_value() && capture_->valid() &&
           cursor_.has_value() && cursor_->valid() &&
           damage_.has_value() && damage_->valid() &&
           input_.has_value() && input_->valid();
}
