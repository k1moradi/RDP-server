// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "core/geometry.h"
#include "core/rectangle.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace rdp::macos {

// Coordinates are normalized by the future native adapter into ONE top-left
// global logical-point system. No CoreGraphics/ScreenCaptureKit coordinate
// convention is inferred here. Pixel bounds are physical, not logical.
struct LogicalDesktopRectangle {
    double xPoints{};
    double yPoints{};
    double widthPoints{};
    double heightPoints{};
};

struct DesktopDisplayMapping {
    std::uint32_t displayId{};
    LogicalDesktopRectangle logicalPoints{};
    Rectangle physicalPixels{};
};

struct DesktopLogicalPoint {
    double xPoints{};
    double yPoints{};
};

struct DesktopPixelPosition {
    std::uint32_t displayId{};
    std::int32_t absoluteX{};
    std::int32_t absoluteY{};
    std::uint32_t virtualX{};
    std::uint32_t virtualY{};
};

struct DisplayLogicalPosition {
    std::uint32_t displayId{};
    DesktopLogicalPoint point{};
};

// An immutable, allocation-free, owning display snapshot. Build a new object
// when displays or scale factors change; R3/R4 must coordinate publication
// with their existing authorized session/graphics lifecycle. A generation
// mismatch refuses coordinates from an obsolete configuration. This class
// neither confers OS authorization nor owns a session or capture callback.
class DesktopDisplayGeometry final {
public:
    static constexpr std::size_t kMaximumDisplays = 16;

    [[nodiscard]] static std::optional<DesktopDisplayGeometry> create(
        std::span<const DesktopDisplayMapping> displays,
        std::uint64_t configurationGeneration) noexcept;

    [[nodiscard]] std::optional<DesktopPixelPosition> pixelAtLogicalPoint(
        DesktopLogicalPoint point,
        std::uint64_t configurationGeneration) const noexcept;

    // The reverse transform samples pixel centers, not the pixel's outer edge.
    [[nodiscard]] std::optional<DisplayLogicalPosition> logicalAtPhysicalPixel(
        std::int32_t absoluteX,
        std::int32_t absoluteY,
        std::uint64_t configurationGeneration) const noexcept;

    // RDP pointer locations are expressed relative to the top-left pixel
    // of the entire virtual desktop, not the native signed display origin.
    // Reject monitor gaps, stale generations and coordinates off the canvas.
    // This is geometry only: callers must enforce R2/R3 session admission.
    [[nodiscard]] std::optional<DisplayLogicalPosition> logicalAtVirtualPixel(
        std::uint32_t virtualX,
        std::uint32_t virtualY,
        std::uint64_t configurationGeneration) const noexcept;

    [[nodiscard]] PixelSize virtualPixelSize() const noexcept { return virtualSize_; }
    [[nodiscard]] std::int32_t physicalOriginX() const noexcept { return originX_; }
    [[nodiscard]] std::int32_t physicalOriginY() const noexcept { return originY_; }
    [[nodiscard]] std::uint64_t generation() const noexcept { return generation_; }
    [[nodiscard]] std::size_t displayCount() const noexcept { return displayCount_; }

private:
    struct CachedDisplay {
        DesktopDisplayMapping mapping{};
        double rightPoints{};
        double bottomPoints{};
        std::int64_t rightPixels{};
        std::int64_t bottomPixels{};
        double pixelsPerPointX{};
        double pixelsPerPointY{};
        double pointsPerPixelX{};
        double pointsPerPixelY{};
    };

    std::array<CachedDisplay, kMaximumDisplays> displays_{};
    std::size_t displayCount_{};
    std::int32_t originX_{};
    std::int32_t originY_{};
    PixelSize virtualSize_{};
    std::uint64_t generation_{};
};

} // namespace rdp::macos
