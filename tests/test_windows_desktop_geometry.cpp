// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows/windows_desktop_geometry.h"
#include "windows/windows_bgra_frame.h"
#include "windows/windows_dxgi_damage.h"
#include "windows/windows_dxgi_frame_owner.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <limits>
#include <span>
#include <string_view>

namespace rdp_server::windows
{
[[nodiscard]] bool windowsGdiRectangleTypeProbe() noexcept;
}

using namespace rdp_server::windows;

namespace
{

void bgraFramePitchAndPixelOrder()
{
    // Two BGRA pixels and four bytes of DXGI row padding on each row.
    std::array<std::byte, 27> mapped{};
    mapped[0] = std::byte{0x12}; // Blue
    mapped[1] = std::byte{0x34}; // Green
    mapped[2] = std::byte{0x56}; // Red
    mapped[3] = std::byte{0xff}; // Alpha
    mapped[8] = std::byte{0x77}; // Padding is not part of a BGRA pixel.
    mapped[12] = std::byte{0x9a}; // First pixel of second row
    mapped[13] = std::byte{0xbc};
    mapped[14] = std::byte{0xde};
    mapped[15] = std::byte{0x80};

    FramebufferView frame{};
    assert(makeWindowsBgraFrameView(mapped, {2, 2}, 12, frame));
    assert(frame.valid());
    assert(frame.widthPixels == 2 && frame.heightPixels == 2);
    assert(frame.strideBytes == 12);
    assert(frame.pixels.size() == 24); // Excess bytes not exposed.
    assert(frame.pixels.data() == mapped.data()); // No allocation/copy.
    assert(frame.pixels[0] == std::byte{0x12});
    assert(frame.pixels[1] == std::byte{0x34});
    assert(frame.pixels[2] == std::byte{0x56});
    assert(frame.pixels[3] == std::byte{0xff});
    assert(frame.pixels[8] == std::byte{0x77}); // Pitch, not packed width.
    assert(frame.pixels[12] == std::byte{0x9a});
    assert(frame.pixels[13] == std::byte{0xbc});
    assert(frame.pixels[14] == std::byte{0xde});
    assert(frame.pixels[15] == std::byte{0x80});
    assert(mapped[24] == std::byte{});

    // Tight row pitch and a single row are valid, without a copy.
    FramebufferView tight{};
    assert(makeWindowsBgraFrameView(mapped, {2, 1}, 8, tight));
    assert(tight.valid() && tight.pixels.size() == 8);
    assert(kWindowsBgraBytesPerPixel == 4);
}

void bgraFrameInvalidBufferDenials()
{
    std::array<std::byte, 24> mapped{};
    FramebufferView view{};
    assert(makeWindowsBgraFrameView(mapped, {2, 2}, 12, view));
    const FramebufferView original = view;

    assert(!makeWindowsBgraFrameView(mapped, {0, 2}, 12, view));
    assert(!makeWindowsBgraFrameView(mapped, {2, 0}, 12, view));
    assert(!makeWindowsBgraFrameView(mapped, {2, 2}, 7, view));
    assert(!makeWindowsBgraFrameView(mapped, {2, 2}, 0, view));
    assert(!makeWindowsBgraFrameView(mapped, {2, 2}, 13, view));
    assert(!makeWindowsBgraFrameView({}, {2, 2}, 12, view));
    assert(!makeWindowsBgraFrameView(mapped, {1, 2},
                                     kMaximumWindowsCaptureFrameBytes + 1,
                                     view));
    assert(!makeWindowsBgraFrameView(mapped,
                                     {std::numeric_limits<std::uint32_t>::max(), 1},
                                     4, view));
    assert(!makeWindowsBgraFrameView(mapped,
                                     {1, std::numeric_limits<std::uint32_t>::max()},
                                     4, view));
    assert(!makeWindowsBgraFrameView(mapped, {1, 2},
                                     std::numeric_limits<std::size_t>::max(),
                                     view));
    assert(view.pixels.data() == original.pixels.data());
    assert(view.pixels.size() == original.pixels.size());
    assert(view.widthPixels == original.widthPixels);
    assert(view.heightPixels == original.heightPixels);
    assert(view.strideBytes == original.strideBytes);
}

void dxgiDirtyAndMoveRegions()
{
    constexpr PixelSize outputDimensions{1920, 1080};
    constexpr std::array moved{
        WindowsDxgiMoveRectangle{{100, 50}, {400, 300, 500, 360}},
        WindowsDxgiMoveRectangle{{0, 0}, {10, 20, 50, 40}},
    };
    constexpr std::array dirty{
        WindowsDxgiRectangle{430, 300, 440, 305},
        WindowsDxgiRectangle{0, 1000, 1920, 1080},
    };
    std::array<Rectangle, 6> regions{
        Rectangle{-1, -1, 1, 1}, Rectangle{-1, -1, 1, 1},
        Rectangle{-1, -1, 1, 1}, Rectangle{-1, -1, 1, 1},
        Rectangle{-1, -1, 1, 1}, Rectangle{-1, -1, 1, 1}};
    std::size_t count = 999;
    assert(normalizeWindowsDxgiDamage(outputDimensions, moved, dirty,
                                      regions, count));
    assert(count == 4);
    // DXGI mandates moved regions first. The current frame already holds
    // the destination pixels; the source is validated, not transmitted.
    assert((regions[0] == Rectangle{400, 300, 100, 60}));
    assert((regions[1] == Rectangle{10, 20, 40, 20}));
    assert((regions[2] == Rectangle{430, 300, 10, 5}));
    assert((regions[3] == Rectangle{0, 1000, 1920, 80}));
    assert((regions[4] == Rectangle{-1, -1, 1, 1}));
    assert(count == 4);

    // Pointer-only DXGI frames contain no image damage; clear the count
    // without rewriting the caller's unrelated output buffer.
    assert(normalizeWindowsDxgiDamage(outputDimensions, {}, {},
                                      regions, count));
    assert(count == 0);
    assert((regions[0] == Rectangle{400, 300, 100, 60}));

    // Exact-right/bottom rectangles and overlapping dirty/move regions
    // remain lossless: R4 alone decides how to coalesce or transmit them.
    constexpr std::array edgeDirty{
        WindowsDxgiRectangle{1919, 1079, 1920, 1080}};
    assert(normalizeWindowsDxgiDamage(outputDimensions, {}, edgeDirty,
                                      regions, count));
    assert(count == 1);
    assert((regions[0] == Rectangle{1919, 1079, 1, 1}));
}

void dxgiMetadataDenials()
{
    constexpr PixelSize dimensions{100, 70};
    constexpr std::array validMove{
        WindowsDxgiMoveRectangle{{0, 0}, {50, 20, 60, 30}}};
    constexpr std::array validDirty{
        WindowsDxgiRectangle{0, 0, 100, 70}};
    std::array<Rectangle, 2> output{
        Rectangle{-7, -9, 2, 3}, Rectangle{-1, -2, 3, 4}};
    const auto original = output;
    std::size_t count = 77;

    auto rejects = [&](PixelSize bounds,
                       std::span<const WindowsDxgiMoveRectangle> moves,
                       std::span<const WindowsDxgiRectangle> dirties,
                       std::span<Rectangle> destination) {
        assert(!normalizeWindowsDxgiDamage(bounds, moves, dirties,
                                           destination, count));
        assert(output == original && count == 77);
    };
    rejects({0, 70}, validMove, validDirty, output);
    rejects({100, 0}, validMove, validDirty, output);
    rejects({std::numeric_limits<std::uint32_t>::max(), 70},
            validMove, validDirty, output);
    rejects(dimensions, validMove, validDirty, std::span(output).first(1));
    constexpr std::array zeroWidth{WindowsDxgiRectangle{0, 0, 0, 1}};
    constexpr std::array negative{WindowsDxgiRectangle{-1, 0, 1, 1}};
    constexpr std::array inverted{WindowsDxgiRectangle{10, 0, 1, 2}};
    constexpr std::array tooWide{WindowsDxgiRectangle{0, 0, 101, 1}};
    constexpr std::array tooTall{WindowsDxgiRectangle{0, 0, 1, 71}};
    rejects(dimensions, {}, zeroWidth, output);
    rejects(dimensions, {}, negative, output);
    rejects(dimensions, {}, inverted, output);
    rejects(dimensions, {}, tooWide, output);
    rejects(dimensions, {}, tooTall, output);

    constexpr std::array negativeSource{
        WindowsDxgiMoveRectangle{{-1, 0}, {50, 20, 60, 30}}};
    constexpr std::array sourceOverflow{
        WindowsDxgiMoveRectangle{{95, 0}, {50, 20, 60, 30}}};
    constexpr std::array verticalSourceOverflow{
        WindowsDxgiMoveRectangle{{0, 65}, {50, 20, 60, 30}}};
    rejects(dimensions, negativeSource, {}, output);
    rejects(dimensions, sourceOverflow, {}, output);
    rejects(dimensions, verticalSourceOverflow, {}, output);

    // Late invalid entries must not publish earlier valid rectangles.
    constexpr std::array lateBadDirty{
        WindowsDxgiRectangle{0, 0, 20, 20},
        WindowsDxgiRectangle{0, 0, 200, 20}};
    rejects(dimensions, {}, lateBadDirty, output);
    rejects(dimensions, validMove, tooTall, output);
    constexpr std::array<WindowsDxgiRectangle,
                         kMaximumWindowsDxgiDamageRectangles + 1> tooMany{};
    rejects(dimensions, {}, tooMany, output);
}

void negativeOriginAndMonitorGaps()
{
    constexpr std::array monitors{
        Rectangle{-1920, 0, 1920, 1080},
        Rectangle{0, 0, 2560, 1440},
        Rectangle{2560, -320, 1280, 1024},
    };
    WindowsDesktopLayout layout{};
    assert(makeWindowsDesktopLayout(monitors, layout));
    assert(layout.monitorCount == monitors.size());
    assert((layout.virtualBounds == Rectangle{-1920, -320, 5760, 1760}));
    for (std::size_t index = 0; index < monitors.size(); ++index)
    {
        assert(layout.monitors[index] == monitors[index]);
    }
    const auto left = nativeToDesktopPoint(layout, {-1920, 0});
    assert(left.has_value() &&
           (*left == WindowsDesktopPoint{0, 320}));
    const auto topRight = nativeToDesktopPoint(layout, {3839, -320});
    assert(topRight.has_value() &&
           (*topRight == WindowsDesktopPoint{5759, 0}));
    const auto nativeLeft = desktopToNativePoint(layout, {0, 320});
    assert(nativeLeft.has_value() &&
           (*nativeLeft == WindowsNativePoint{-1920, 0}));
    const auto nativeRight = desktopToNativePoint(layout, {5759, 0});
    assert(nativeRight.has_value() &&
           (*nativeRight == WindowsNativePoint{3839, -320}));
    // Bounding-box pixels in a gap are NOT valid injection destinations.
    assert(!nativeToDesktopPoint(layout, {-1000, -200}));
    assert(!desktopToNativePoint(layout, {920, 120}));
    assert(!nativeToDesktopPoint(layout, {3840, 0}));
    assert(!desktopToNativePoint(layout, {5760, 0}));
    assert(!nativeToDesktopPoint(layout, {-1921, 0}));
    assert(!desktopToNativePoint(layout, {0, 1760}));
    assert(!nativeToDesktopPoint(layout, {2560, 704}));
    assert(!desktopToNativePoint(layout, {4480, 1024}));
}

void stableEnumerationOrderAndResize()
{
    constexpr std::array original{
        Rectangle{1920, -300, 1024, 768},
        Rectangle{-1600, 0, 1600, 900},
        Rectangle{0, 0, 1920, 1080},
    };
    constexpr std::array reordered{
        Rectangle{0, 0, 1920, 1080},
        Rectangle{1920, -300, 1024, 768},
        Rectangle{-1600, 0, 1600, 900},
    };
    WindowsDesktopLayout first{};
    WindowsDesktopLayout second{};
    assert(makeWindowsDesktopLayout(original, first));
    assert(makeWindowsDesktopLayout(reordered, second));
    assert(first == second);
    assert(first.monitorCount == original.size());
    assert((first.virtualBounds == Rectangle{-1600, -300, 4544, 1380}));
    assert((first.monitors[0] == Rectangle{-1600, 0, 1600, 900}));
    assert((first.monitors[1] == Rectangle{0, 0, 1920, 1080}));
    assert((first.monitors[2] == Rectangle{1920, -300, 1024, 768}));

    // A real geometry change must still invalidate the cached snapshot,
    // including a change that leaves the virtual bounding box identical.
    constexpr std::array resized{
        Rectangle{-1600, 0, 1600, 900},
        Rectangle{0, 0, 1920, 1080},
        Rectangle{1920, -300, 1024, 700},
    };
    WindowsDesktopLayout changed{};
    assert(makeWindowsDesktopLayout(resized, changed));
    assert(!(first == changed));
    assert(first.virtualBounds == changed.virtualBounds);

    // Empty/corrupted snapshots are not silently considered valid geometry.
    assert(!nativeToDesktopPoint(WindowsDesktopLayout{}, {0, 0}));
    assert(!desktopToNativePoint(WindowsDesktopLayout{}, {0, 0}));
}

void invalidLayoutRejections()
{
    constexpr std::array valid{Rectangle{-100, -200, 200, 400}};
    WindowsDesktopLayout layout{};
    assert(makeWindowsDesktopLayout(valid, layout));
    const auto originalVirtualBounds = layout.virtualBounds;
    const auto originalMonitor = layout.monitors[0];
    const auto originalCount = layout.monitorCount;

    assert(!makeWindowsDesktopLayout({}, layout));
    constexpr std::array zeroWidth{Rectangle{0, 0, 0, 100}};
    constexpr std::array zeroHeight{Rectangle{0, 0, 100, 0}};
    constexpr std::array invalidRight{
        Rectangle{std::numeric_limits<std::int32_t>::max(), 0, 2, 1}};
    constexpr std::array invalidBottom{
        Rectangle{0, std::numeric_limits<std::int32_t>::max(), 1, 2}};
    constexpr std::array tooMany = [] {
        std::array<Rectangle, kMaximumWindowsDesktopMonitors + 1> values{};
        for (Rectangle &rectangle : values)
        {
            rectangle = {0, 0, 1, 1};
        }
        return values;
    }();
    assert(!makeWindowsDesktopLayout(zeroWidth, layout));
    assert(!makeWindowsDesktopLayout(zeroHeight, layout));
    assert(!makeWindowsDesktopLayout(invalidRight, layout));
    assert(!makeWindowsDesktopLayout(invalidBottom, layout));
    assert(!makeWindowsDesktopLayout(tooMany, layout));
    // Every rejected update preserves the previous usable display snapshot.
    assert(layout.virtualBounds == originalVirtualBounds);
    assert(layout.monitors[0] == originalMonitor);
    assert(layout.monitorCount == originalCount);

    // Complete signed Win32 coordinate range still fits a 32-bit
    // unsigned virtual width without wrap or a framebuffer allocation.
    constexpr std::array maximumSpan{
        Rectangle{std::numeric_limits<std::int32_t>::min(), 0, 1, 1},
        Rectangle{std::numeric_limits<std::int32_t>::max() - 1, 0, 1, 1}};
    WindowsDesktopLayout maximumLayout{};
    assert(makeWindowsDesktopLayout(maximumSpan, maximumLayout));
    assert(maximumLayout.virtualBounds.widthPixels ==
           std::numeric_limits<std::uint32_t>::max());
    assert((nativeToDesktopPoint(
        maximumLayout, {std::numeric_limits<std::int32_t>::max() - 1, 0}) ==
        WindowsDesktopPoint{std::numeric_limits<std::uint32_t>::max() - 1, 0}));

    assert(!nativeToDesktopPoint(layout, {101, 0}));
    assert(!desktopToNativePoint(layout, {200, 200}));
    layout.monitorCount = kMaximumWindowsDesktopMonitors + 1;
    assert(!nativeToDesktopPoint(layout, {-100, -200}));
    assert(!desktopToNativePoint(layout, {0, 0}));
}

struct FakeDxgiFrameSource
{
    WindowsDxgiAcquireResult nextAcquire{WindowsDxgiAcquireResult::acquired};
    WindowsDxgiReleaseResult nextRelease{WindowsDxgiReleaseResult::released};
    unsigned acquisitions{};
    unsigned releases{};
    std::uint32_t lastWait{};
    std::byte token{};
    bool returnNull{};
    bool returnUnexpectedResource{};
    WindowsDxgiFrameOwner *reentrantOwner{};
    WindowsDxgiAcquireResult reentrantAcquire{WindowsDxgiAcquireResult::failed};

    static WindowsDxgiAcquireResult acquire(
        void *context, std::uint32_t timeoutMilliseconds,
        void *&resource) noexcept
    {
        auto &source = *static_cast<FakeDxgiFrameSource *>(context);
        ++source.acquisitions;
        source.lastWait = timeoutMilliseconds;
        if ((source.nextAcquire == WindowsDxgiAcquireResult::acquired &&
             !source.returnNull) || source.returnUnexpectedResource)
        {
            resource = &source.token;
        }
        return source.nextAcquire;
    }

    static WindowsDxgiReleaseResult release(
        void *context, void *resource) noexcept
    {
        auto &source = *static_cast<FakeDxgiFrameSource *>(context);
        assert(resource == &source.token);
        ++source.releases;
        if (source.reentrantOwner != nullptr)
        {
            source.reentrantAcquire = source.reentrantOwner->acquireFrame(0);
        }
        return source.nextRelease;
    }

    [[nodiscard]] WindowsDxgiFrameCallbacks callbacks() noexcept
    {
        return {this, &FakeDxgiFrameSource::acquire,
                &FakeDxgiFrameSource::release};
    }
};

void dxgiFrameLeaseLifecycle()
{
    FakeDxgiFrameSource source{};
    {
        WindowsDxgiFrameOwner owner(source.callbacks());
        assert(!owner.closed() && owner.resource() == nullptr);
        source.nextAcquire = WindowsDxgiAcquireResult::timeout;
        assert(owner.acquireFrame(5) == WindowsDxgiAcquireResult::timeout);
        assert(!owner.closed() && owner.resource() == nullptr);
        assert(source.acquisitions == 1 && source.lastWait == 5);

        source.nextAcquire = WindowsDxgiAcquireResult::acquired;
        assert(owner.acquireFrame(0) == WindowsDxgiAcquireResult::acquired);
        assert(owner.resource() == &source.token && source.acquisitions == 2);
        assert(owner.acquireFrame(0) == WindowsDxgiAcquireResult::busy);
        assert(source.acquisitions == 2);
        source.reentrantOwner = &owner;
        assert(owner.releaseFrame() == WindowsDxgiReleaseResult::released);
        assert(source.reentrantAcquire == WindowsDxgiAcquireResult::busy);
        source.reentrantOwner = nullptr;
        assert(source.releases == 1 && owner.resource() == nullptr);
        assert(owner.releaseFrame() == WindowsDxgiReleaseResult::notHeld);
        assert(!owner.closed());

        assert(owner.acquireFrame(11) == WindowsDxgiAcquireResult::acquired);
        assert(owner.resource() == &source.token && source.acquisitions == 3);
        owner.cancel();
        assert(source.releases == 2 && owner.closed());
        assert(owner.resource() == nullptr);
        assert(owner.acquireFrame(0) == WindowsDxgiAcquireResult::closed);
        owner.cancel();
        assert(source.releases == 2);
    }
    assert(source.releases == 2); // Destructor after cancel is idempotent.

    FakeDxgiFrameSource destructorSource{};
    {
        WindowsDxgiFrameOwner owner(destructorSource.callbacks());
        assert(owner.acquireFrame(0) == WindowsDxgiAcquireResult::acquired);
        assert(destructorSource.releases == 0);
    }
    assert(destructorSource.releases == 1);
}

void dxgiFrameLeaseDenials()
{
    FakeDxgiFrameSource source{};
    WindowsDxgiFrameOwner owner(source.callbacks());
    assert(owner.acquireFrame(
               kMaximumWindowsDxgiFrameWaitMilliseconds + 1) ==
           WindowsDxgiAcquireResult::invalidWait);
    assert(source.acquisitions == 0 && !owner.closed());
    assert(owner.acquireFrame(kMaximumWindowsDxgiFrameWaitMilliseconds) ==
           WindowsDxgiAcquireResult::acquired);
    assert(source.lastWait == kMaximumWindowsDxgiFrameWaitMilliseconds);
    source.nextRelease = WindowsDxgiReleaseResult::accessLost;
    assert(owner.releaseFrame() == WindowsDxgiReleaseResult::accessLost);
    assert(owner.closed() && owner.resource() == nullptr);
    assert(owner.acquireFrame(0) == WindowsDxgiAcquireResult::closed);
    assert(source.acquisitions == 1 && source.releases == 1);

    FakeDxgiFrameSource lost{};
    lost.nextAcquire = WindowsDxgiAcquireResult::accessLost;
    WindowsDxgiFrameOwner lostOwner(lost.callbacks());
    assert(lostOwner.acquireFrame(0) == WindowsDxgiAcquireResult::accessLost);
    assert(lostOwner.closed() && lost.releases == 0);
    assert(lostOwner.acquireFrame(0) == WindowsDxgiAcquireResult::closed);
    assert(lost.acquisitions == 1);

    FakeDxgiFrameSource failed{};
    failed.nextAcquire = WindowsDxgiAcquireResult::failed;
    WindowsDxgiFrameOwner failedOwner(failed.callbacks());
    assert(failedOwner.acquireFrame(0) == WindowsDxgiAcquireResult::failed);
    assert(failedOwner.closed() && failed.releases == 0);

    FakeDxgiFrameSource inconsistent{};
    inconsistent.nextAcquire = WindowsDxgiAcquireResult::timeout;
    inconsistent.returnUnexpectedResource = true;
    WindowsDxgiFrameOwner inconsistentOwner(inconsistent.callbacks());
    assert(inconsistentOwner.acquireFrame(0) == WindowsDxgiAcquireResult::failed);
    assert(inconsistentOwner.closed() && inconsistent.releases == 1);
    assert(inconsistentOwner.resource() == nullptr);

    FakeDxgiFrameSource missing{};
    missing.returnNull = true;
    WindowsDxgiFrameOwner missingOwner(missing.callbacks());
    assert(missingOwner.acquireFrame(0) == WindowsDxgiAcquireResult::failed);
    assert(missingOwner.closed() && missing.releases == 0);

    FakeDxgiFrameSource releaseFailed{};
    releaseFailed.nextRelease = WindowsDxgiReleaseResult::failed;
    WindowsDxgiFrameOwner releaseFailedOwner(releaseFailed.callbacks());
    assert(releaseFailedOwner.acquireFrame(0) ==
           WindowsDxgiAcquireResult::acquired);
    assert(releaseFailedOwner.releaseFrame() == WindowsDxgiReleaseResult::failed);
    assert(releaseFailedOwner.closed() && releaseFailed.releases == 1);

    WindowsDxgiFrameOwner invalid({});
    assert(invalid.closed());
    assert(invalid.acquireFrame(0) == WindowsDxgiAcquireResult::closed);
    assert(invalid.releaseFrame() == WindowsDxgiReleaseResult::notHeld);
}

} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        return 2;
    }
    const std::string_view behavior{argv[1]};
    if (behavior == "negative-origin-and-monitor-gaps")
    {
        negativeOriginAndMonitorGaps();
    }
    else if (behavior == "order-stable-reconfiguration")
    {
        stableEnumerationOrderAndResize();
    }
    else if (behavior == "capture-bgra-stride-and-pixel-order")
    {
        bgraFramePitchAndPixelOrder();
    }
    else if (behavior == "capture-bgra-invalid-frame-denials")
    {
        bgraFrameInvalidBufferDenials();
    }
    else if (behavior == "dxgi-dirty-and-move-regions")
    {
        dxgiDirtyAndMoveRegions();
    }
    else if (behavior == "dxgi-metadata-denials")
    {
        dxgiMetadataDenials();
    }
    else if (behavior == "dxgi-frame-lease-lifecycle")
    {
        dxgiFrameLeaseLifecycle();
    }
    else if (behavior == "dxgi-frame-lease-rejections")
    {
        dxgiFrameLeaseDenials();
    }
    else if (behavior == "win32-gdi-rectangle-name-resolution")
    {
        assert(windowsGdiRectangleTypeProbe());
    }
    else if (behavior == "invalid-layout-rejections")
    {
        invalidLayoutRejections();
    }
    else
    {
        return 2;
    }
    return 0;
}
