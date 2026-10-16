// SPDX-License-Identifier: GPL-3.0-or-later

#include "x11_desktop_resources.h"

X11DesktopResources::X11DesktopResources(
    std::string_view displayName,
    std::uint64_t maximumCapturePixels) noexcept
    : display_(displayName)
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
                     display_.rootDepth(), geometry, maximumCapturePixels);
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
X11DesktopResources::cancelNativeResources() noexcept
{
    // Input may own pressed native state, so release it first. Cursor, Damage
    // and XShm all borrow the same XCB connection and must be cancelled before
    // X11DisplayConnection closes that sole connection.
    if (input_)
    {
        input_->disconnect();
        input_.reset();
    }
    if (cursor_)
    {
        cursor_->disconnect();
        cursor_.reset();
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
