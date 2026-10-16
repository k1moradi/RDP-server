// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows/windows_cursor_snapshot.h"

#include <array>
#include <cassert>

using namespace rdp_server::windows;

namespace
{

struct FakeCursorSource final
{
    WindowsCursorReadResult result{WindowsCursorReadResult::ready};
    WindowsNativeCursorObservation observation{{-25, 20}, 32, 24, 4, 5};
    unsigned reads{};

    static WindowsCursorReadResult read(
        void *context, WindowsNativeCursorObservation &output) noexcept
    {
        auto &self = *static_cast<FakeCursorSource *>(context);
        ++self.reads;
        output = self.observation;
        return self.result;
    }

    [[nodiscard]] WindowsCursorReadCallbacks callbacks() noexcept
    {
        return {this, &read};
    }
};

[[nodiscard]] WindowsDesktopLayout cursorLayout() noexcept
{
    constexpr std::array<PortableRectangle, 2> monitors{{
        {-100, 0, 100, 100},
        {100, 0, 100, 100},
    }};
    WindowsDesktopLayout layout{};
    assert(makeWindowsDesktopLayout(monitors, layout));
    return layout;
}

} // namespace

void windowsCursorSnapshotVisibleAndHidden()
{
    const WindowsDesktopLayout layout = cursorLayout();
    FakeCursorSource source{};
    WindowsCursorSnapshot output{};

    assert(readWindowsCursorSnapshot(layout, source.callbacks(), output) ==
           WindowsCursorReadResult::ready);
    assert(output.visible);
    assert((output.position == WindowsDesktopPoint{75, 20}));
    assert(output.widthPixels == 32 && output.heightPixels == 24);
    assert(output.hotspotX == 4 && output.hotspotY == 5);
    assert(source.reads == 1);

    source.result = WindowsCursorReadResult::hidden;
    assert(readWindowsCursorSnapshot(layout, source.callbacks(), output) ==
           WindowsCursorReadResult::hidden);
    assert((output == WindowsCursorSnapshot{}));
    assert(source.reads == 2);

#ifdef _WIN32
    const auto nativeCallbacks = windowsCursorReadCallbacks();
    assert(nativeCallbacks.read != nullptr);
#endif
}

void windowsCursorSnapshotRejections()
{
    const WindowsDesktopLayout layout = cursorLayout();
    const WindowsCursorSnapshot seed{true, {1, 2}, 3, 4, 1, 1};

    auto rejected = [&](FakeCursorSource &source,
                        WindowsCursorReadResult expected) noexcept {
        WindowsCursorSnapshot output = seed;
        assert(readWindowsCursorSnapshot(
                   layout, source.callbacks(), output) == expected);
        assert(output == seed);
    };

    FakeCursorSource zeroWidth{};
    zeroWidth.observation.widthPixels = 0;
    rejected(zeroWidth, WindowsCursorReadResult::invalid);

    FakeCursorSource zeroHeight{};
    zeroHeight.observation.heightPixels = 0;
    rejected(zeroHeight, WindowsCursorReadResult::invalid);

    FakeCursorSource oversized{};
    oversized.observation.widthPixels = kMaximumWindowsCursorDimension + 1;
    rejected(oversized, WindowsCursorReadResult::invalid);

    FakeCursorSource invalidHotspot{};
    invalidHotspot.observation.hotspotX =
        invalidHotspot.observation.widthPixels;
    rejected(invalidHotspot, WindowsCursorReadResult::invalid);

    FakeCursorSource monitorGap{};
    monitorGap.observation.position = {50, 20};
    rejected(monitorGap, WindowsCursorReadResult::invalid);

    FakeCursorSource invalidNative{};
    invalidNative.result = WindowsCursorReadResult::invalid;
    rejected(invalidNative, WindowsCursorReadResult::invalid);

    FakeCursorSource failedNative{};
    failedNative.result = WindowsCursorReadResult::failed;
    rejected(failedNative, WindowsCursorReadResult::failed);

    WindowsCursorSnapshot missingCallbackOutput = seed;
    assert(readWindowsCursorSnapshot(
               layout, {}, missingCallbackOutput) ==
           WindowsCursorReadResult::failed);
    assert(missingCallbackOutput == seed);
}
