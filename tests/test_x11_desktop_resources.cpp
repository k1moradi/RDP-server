// SPDX-License-Identifier: GPL-3.0-or-later

#include "x11/x11_desktop_resources.h"

#include <cassert>
#include <cstdlib>
#include <cstring>
#include <string_view>

namespace
{

void
connectionDenial()
{
    X11DesktopResources resources("not-a-valid-x11-display", 4096);
    assert(!resources.valid());
    assert(resources.failureReason() != nullptr);
    assert(resources.fileDescriptor() == -1);
    assert((resources.sourceGeometry() == PixelSize{}));
    assert(!resources.randrAvailable());

    resources.disconnect();
    assert(!resources.valid());
    resources.disconnect();
    assert(!resources.valid());
}

void
syntheticXvfbLifecycle()
{
    const char *display = std::getenv("DISPLAY");
    assert(display != nullptr && display[0] != '\0');

    // A failed child construction must cancel the already-open display before
    // another resource owner is created on the same synthetic X server.
    {
        X11DesktopResources rejected(display, 0);
        assert(!rejected.valid());
        assert(rejected.failureReason() != nullptr);
        assert(rejected.fileDescriptor() == -1);
    }

    constexpr std::uint64_t kCaptureArenaPixels = 256U * 1024U;
    {
        X11DesktopResources resources(display, kCaptureArenaPixels);
        assert(resources.valid());
        assert(resources.failureReason() == nullptr);
        assert(resources.fileDescriptor() >= 0);
        const PixelSize geometry = resources.sourceGeometry();
        assert(geometry.widthPixels == 1280);
        assert(geometry.heightPixels == 720);

        resources.disconnect();
        assert(!resources.valid());
        assert(resources.fileDescriptor() == -1);
        assert((resources.sourceGeometry() == PixelSize{}));
        resources.disconnect();
    }

    // Exercise destructor-driven ordered cancellation after a second complete
    // resource construction. No real desktop or user input is involved.
    X11DesktopResources resources(display, kCaptureArenaPixels);
    assert(resources.valid());
}

} // namespace

int
main(int argc, char **argv)
{
    if (argc == 1)
    {
        connectionDenial();
        return 0;
    }
    assert(argc == 2);
    const std::string_view behavior(argv[1]);
    if (behavior == "lifecycle")
    {
        syntheticXvfbLifecycle();
        return 0;
    }

    assert(false && "unknown X11 desktop resource behavior");
    return 1;
}
