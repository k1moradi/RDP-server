// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows_cursor_snapshot.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace rdp_server::windows
{

WindowsCursorReadResult readWindowsCursorSnapshot(
    const WindowsDesktopLayout &layout, WindowsCursorReadCallbacks callbacks,
    WindowsCursorSnapshot &output) noexcept
{
    if (callbacks.read == nullptr)
    {
        return WindowsCursorReadResult::failed;
    }

    WindowsNativeCursorObservation native{};
    const WindowsCursorReadResult result =
        callbacks.read(callbacks.context, native);
    if (result == WindowsCursorReadResult::hidden)
    {
        output = {};
        return result;
    }
    if (result != WindowsCursorReadResult::ready)
    {
        return result;
    }

    if (native.widthPixels == 0 || native.heightPixels == 0 ||
        native.widthPixels > kMaximumWindowsCursorDimension ||
        native.heightPixels > kMaximumWindowsCursorDimension ||
        native.hotspotX >= native.widthPixels ||
        native.hotspotY >= native.heightPixels)
    {
        return WindowsCursorReadResult::invalid;
    }
    const auto position = nativeToDesktopPoint(layout, native.position);
    if (!position.has_value())
    {
        return WindowsCursorReadResult::invalid;
    }

    output = {true, *position, native.widthPixels, native.heightPixels,
              native.hotspotX, native.hotspotY};
    return WindowsCursorReadResult::ready;
}

#ifdef _WIN32
namespace
{

class NativeBitmapOwner final
{
public:
    explicit NativeBitmapOwner(HBITMAP bitmap = nullptr) noexcept
        : bitmap_(bitmap)
    {
    }

    ~NativeBitmapOwner() noexcept
    {
        if (bitmap_ != nullptr)
        {
            (void)DeleteObject(bitmap_);
        }
    }

    NativeBitmapOwner(const NativeBitmapOwner &) = delete;
    NativeBitmapOwner &operator=(const NativeBitmapOwner &) = delete;

private:
    HBITMAP bitmap_{};
};

WindowsCursorReadResult readNativeCursor(
    void *, WindowsNativeCursorObservation &observation) noexcept
{
    CURSORINFO cursor{};
    cursor.cbSize = static_cast<DWORD>(sizeof(cursor));
    if (!GetCursorInfo(&cursor))
    {
        return WindowsCursorReadResult::failed;
    }
    if ((cursor.flags & CURSOR_SUPPRESSED) != 0 ||
        (cursor.flags & CURSOR_SHOWING) == 0)
    {
        return WindowsCursorReadResult::hidden;
    }
    if (cursor.hCursor == nullptr)
    {
        return WindowsCursorReadResult::invalid;
    }

    ICONINFO icon{};
    if (!GetIconInfo(cursor.hCursor, &icon))
    {
        return WindowsCursorReadResult::failed;
    }
    NativeBitmapOwner maskOwner(icon.hbmMask);
    NativeBitmapOwner colorOwner(icon.hbmColor);
    if (icon.fIcon != FALSE || icon.hbmMask == nullptr)
    {
        return WindowsCursorReadResult::invalid;
    }

    BITMAP mask{};
    if (GetObjectW(icon.hbmMask, static_cast<int>(sizeof(mask)), &mask) !=
            static_cast<int>(sizeof(mask)) ||
        mask.bmWidth <= 0 || mask.bmHeight <= 0)
    {
        return WindowsCursorReadResult::invalid;
    }

    LONG nativeHeight = mask.bmHeight;
    if (icon.hbmColor != nullptr)
    {
        BITMAP color{};
        if (GetObjectW(icon.hbmColor, static_cast<int>(sizeof(color)), &color) !=
                static_cast<int>(sizeof(color)) ||
            color.bmWidth != mask.bmWidth ||
            color.bmHeight != mask.bmHeight)
        {
            return WindowsCursorReadResult::invalid;
        }
    }
    else
    {
        if ((nativeHeight % 2) != 0)
        {
            return WindowsCursorReadResult::invalid;
        }
        nativeHeight /= 2;
        if (nativeHeight <= 0)
        {
            return WindowsCursorReadResult::invalid;
        }
    }

    const auto width = static_cast<std::uint32_t>(mask.bmWidth);
    const auto height = static_cast<std::uint32_t>(nativeHeight);
    if (width > kMaximumWindowsCursorDimension ||
        height > kMaximumWindowsCursorDimension ||
        icon.xHotspot >= width || icon.yHotspot >= height)
    {
        return WindowsCursorReadResult::invalid;
    }

    observation = {
        {static_cast<std::int32_t>(cursor.ptScreenPos.x),
         static_cast<std::int32_t>(cursor.ptScreenPos.y)},
        width, height, icon.xHotspot, icon.yHotspot};
    return WindowsCursorReadResult::ready;
}

} // namespace

WindowsCursorReadCallbacks windowsCursorReadCallbacks() noexcept
{
    return {nullptr, &readNativeCursor};
}
#endif

} // namespace rdp_server::windows
