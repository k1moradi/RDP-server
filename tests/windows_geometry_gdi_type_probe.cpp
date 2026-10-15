// SPDX-License-Identifier: GPL-3.0-or-later
// Include WinGDI before the R6 adapter to catch the native Rectangle
// function / portable Rectangle struct name collision at compile time.
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
extern "C" int Rectangle(void *, int, int, int, int);
#endif

#include "windows/windows_desktop_geometry.h"
#include "windows/windows_dxgi_damage.h"

#include <array>

namespace rdp_server::windows
{

bool windowsGdiRectangleTypeProbe() noexcept
{
    const std::array<PortableRectangle, 2> native{
        PortableRectangle{-800, 0, 800, 600},
        PortableRectangle{0, 0, 1280, 720},
    };
    WindowsDesktopLayout layout{};
    if (!makeWindowsDesktopLayout(native, layout) ||
        layout.virtualBounds != PortableRectangle{-800, 0, 2080, 720} ||
        layout.monitorCount != 2)
    {
        return false;
    }
    const std::array dirty{WindowsDxgiRectangle{0, 0, 20, 10}};
    std::array<PortableRectangle, 1> normalized{};
    std::size_t count = 0;
    return normalizeWindowsDxgiDamage({1280, 720}, {}, dirty, normalized,
                                      count) &&
           count == 1 &&
           normalized[0] == PortableRectangle{0, 0, 20, 10};
}

} // namespace rdp_server::windows
