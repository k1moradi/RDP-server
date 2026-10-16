// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>

#include "../core/geometry.h"
#include "../core/rectangle.h"

// This layout describes one tightly packed 32-bit XShm ZPixmap response.
// It owns no framebuffer bytes. The caller retains the XShm arena and must
// keep its bytes alive until the consumer has finished using the view.
struct X11CaptureLayout
{
    std::size_t strideBytes{};
    std::size_t bufferBytes{};

    // Reply length must describe exactly the packed pixel view published
    // to the portable consumer. A short or oversized XShm image is not a
    // valid framebuffer even when its geometry and arena were accepted.
    [[nodiscard]] constexpr bool matchesReplySize(
        std::uint32_t reportedBytes) const noexcept
    {
        return reportedBytes == bufferBytes;
    }
};

// MIT-SHM arena sizing remains bounded to the display and retains
// at least one complete row for each capture.
[[nodiscard]] constexpr std::uint64_t
captureArenaPixels(PixelSize bounds,
                   std::uint64_t maximumCapturePixels) noexcept
{
    if (bounds.widthPixels == 0 || bounds.heightPixels == 0 ||
        maximumCapturePixels == 0)
    {
        return 0;
    }

    const std::uint64_t framebufferPixels =
        static_cast<std::uint64_t>(bounds.widthPixels) *
        bounds.heightPixels;
    const std::uint64_t minimumProgressPixels = bounds.widthPixels;
    const std::uint64_t requestedPixels =
        maximumCapturePixels > minimumProgressPixels
            ? maximumCapturePixels
            : minimumProgressPixels;

    return framebufferPixels < requestedPixels ? framebufferPixels
                                                : requestedPixels;
}

// Pure geometry validation: safe to call before native X requests and from
// headless CTests. GetImage uses signed 16-bit coordinates, unsigned 16-bit
// dimensions and a 32-bit reply byte count; reject any unrepresentable size.
[[nodiscard]] constexpr std::optional<X11CaptureLayout>
validatedX11CaptureLayout(Rectangle rectangle, PixelSize bounds,
                          std::size_t arenaBytes) noexcept
{
    constexpr std::uint64_t kBytesPerPixel = 4;
    constexpr auto kMaximumCoordinate =
        std::numeric_limits<std::int16_t>::max();
    constexpr auto kMaximumDimension =
        std::numeric_limits<std::uint16_t>::max();

    if (rectangle.x < 0 || rectangle.y < 0 ||
        rectangle.x > kMaximumCoordinate ||
        rectangle.y > kMaximumCoordinate ||
        rectangle.widthPixels == 0 || rectangle.heightPixels == 0 ||
        rectangle.widthPixels > kMaximumDimension ||
        rectangle.heightPixels > kMaximumDimension ||
        bounds.widthPixels == 0 || bounds.heightPixels == 0 ||
        bounds.widthPixels > kMaximumDimension ||
        bounds.heightPixels > kMaximumDimension)
    {
        return std::nullopt;
    }

    const std::uint64_t rightEdge =
        static_cast<std::uint64_t>(rectangle.x) + rectangle.widthPixels;
    const std::uint64_t bottomEdge =
        static_cast<std::uint64_t>(rectangle.y) + rectangle.heightPixels;
    if (rightEdge > bounds.widthPixels || bottomEdge > bounds.heightPixels)
    {
        return std::nullopt;
    }

    // The bounds above make both multiplications safe in uint64_t, including
    // for a 32-bit build where size_t cannot represent large framebuffers.
    const std::uint64_t strideBytes =
        static_cast<std::uint64_t>(rectangle.widthPixels) * kBytesPerPixel;
    const std::uint64_t bufferBytes =
        strideBytes * rectangle.heightPixels;
    if (bufferBytes > std::numeric_limits<std::uint32_t>::max() ||
        bufferBytes > std::numeric_limits<std::size_t>::max() ||
        bufferBytes > arenaBytes)
    {
        return std::nullopt;
    }

    return X11CaptureLayout{
        static_cast<std::size_t>(strideBytes),
        static_cast<std::size_t>(bufferBytes),
    };
}
