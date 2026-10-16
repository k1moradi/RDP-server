// SPDX-License-Identifier: GPL-3.0-or-later

#include "../src/x11/x11_capture_layout.h"
#include "../src/core/framebuffer_view.h"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <limits>

int main()
{
    constexpr PixelSize desktop{1920, 1080};
    constexpr Rectangle dirtyRectangle{31, 43, 17, 9};
    constexpr auto accepted = validatedX11CaptureLayout(
        dirtyRectangle, desktop, 17U * 9U * 4U);
    static_assert(accepted.has_value());
    static_assert(accepted->strideBytes == 68);
    static_assert(accepted->bufferBytes == 612);
    static_assert(accepted->matchesReplySize(612));
    static_assert(!accepted->matchesReplySize(611));
    static_assert(!accepted->matchesReplySize(613));

    // A short arena cannot be reported as a valid captured framebuffer.
    assert(!validatedX11CaptureLayout(dirtyRectangle, desktop, 611));
    assert(!validatedX11CaptureLayout(dirtyRectangle, desktop, 0));
    const auto packedLayout = validatedX11CaptureLayout({0, 0, 3, 2},
                                                         desktop, 24);
    assert(packedLayout && packedLayout->strideBytes == 12);
    assert(packedLayout->bufferBytes == 24);
    assert(packedLayout->matchesReplySize(24));
    assert(!packedLayout->matchesReplySize(23));
    assert(!packedLayout->matchesReplySize(25));
    const std::array<std::byte, 24> pixelStorage{};
    const FramebufferView completeFrame{pixelStorage, 3, 2,
                                        packedLayout->strideBytes};
    const FramebufferView truncatedFrame{
        std::span<const std::byte>{pixelStorage}.first(23), 3, 2,
        packedLayout->strideBytes};
    assert(completeFrame.valid());
    assert(!truncatedFrame.valid());

    // Reject empty rectangles, missing geometry and out-of-range coordinates.
    constexpr auto maximumArena = std::numeric_limits<std::size_t>::max();
    assert(!validatedX11CaptureLayout({0, 0, 0, 1}, desktop, maximumArena));
    assert(!validatedX11CaptureLayout({0, 0, 1, 0}, desktop, maximumArena));
    assert(!validatedX11CaptureLayout({0, 0, 1, 1}, {0, 1}, maximumArena));
    assert(!validatedX11CaptureLayout({-1, 0, 1, 1}, desktop, maximumArena));
    assert(!validatedX11CaptureLayout({0, -1, 1, 1}, desktop, maximumArena));
    assert(!validatedX11CaptureLayout({32768, 0, 1, 1},
                                      {65535, 65535}, maximumArena));
    assert(!validatedX11CaptureLayout({0, 32768, 1, 1},
                                      {65535, 65535}, maximumArena));
    assert(!validatedX11CaptureLayout({1919, 0, 2, 1}, desktop, maximumArena));
    assert(!validatedX11CaptureLayout({0, 1079, 1, 2}, desktop, maximumArena));
    assert(!validatedX11CaptureLayout({0, 0, 1, 1},
                                      {65536, 1}, maximumArena));
    assert(!validatedX11CaptureLayout({0, 0, 65536, 1},
                                      {65536, 1}, maximumArena));

    // No uint32 reply-length truncation, even if a 64-bit arena is huge.
    constexpr PixelSize largestDesktop{65535, 65535};
    // A large uint32-sized reply is accepted without allocating it; one
    // more row exceeds the limit.
    constexpr auto largeFrame = validatedX11CaptureLayout(
        {0, 0, 65535, 16384}, largestDesktop, maximumArena);
    static_assert(largeFrame.has_value());
    static_assert(largeFrame->strideBytes == 262140U);
    static_assert(largeFrame->bufferBytes == 4294901760ULL);
    static_assert(largeFrame->matchesReplySize(4294901760U));
    static_assert(!validatedX11CaptureLayout(
        {0, 0, 65535, 16385}, largestDesktop, maximumArena));
    assert(!validatedX11CaptureLayout({0, 0, 65535, 65535},
                                      largestDesktop, maximumArena));
    constexpr auto lastValidCoordinate = validatedX11CaptureLayout(
        {32767, 32767, 1, 1}, largestDesktop, 4);
    static_assert(lastValidCoordinate.has_value());
    static_assert(lastValidCoordinate->strideBytes == 4);
    return 0;
}
