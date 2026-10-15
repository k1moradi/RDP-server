// SPDX-License-Identifier: GPL-3.0-or-later
#include "platform/macos/desktop_display_geometry.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>

namespace rdp::macos {
namespace {

struct CheckedRectangle {
    double rightPoints{};
    double bottomPoints{};
    std::int64_t rightPixels{};
    std::int64_t bottomPixels{};
};

[[nodiscard]] std::optional<CheckedRectangle> checkedBounds(
    const DesktopDisplayMapping& display) noexcept {
    const auto& logical = display.logicalPoints;
    const auto& physical = display.physicalPixels;
    if (display.displayId == 0 ||
        !std::isfinite(logical.xPoints) || !std::isfinite(logical.yPoints) ||
        !std::isfinite(logical.widthPoints) || !std::isfinite(logical.heightPoints) ||
        logical.widthPoints <= 0.0 || logical.heightPoints <= 0.0 ||
        physical.widthPixels == 0 || physical.heightPixels == 0) {
        return std::nullopt;
    }

    const double rightPoints = logical.xPoints + logical.widthPoints;
    const double bottomPoints = logical.yPoints + logical.heightPoints;
    // Reject input too coarse to represent a positive logical extent.
    if (!std::isfinite(rightPoints) || !std::isfinite(bottomPoints) ||
        rightPoints <= logical.xPoints || bottomPoints <= logical.yPoints) {
        return std::nullopt;
    }

    const std::int64_t rightPixels =
        static_cast<std::int64_t>(physical.x) + physical.widthPixels;
    const std::int64_t bottomPixels =
        static_cast<std::int64_t>(physical.y) + physical.heightPixels;
    constexpr auto kMaximumExclusivePixel =
        static_cast<std::int64_t>(std::numeric_limits<std::int32_t>::max()) + 1;
    if (rightPixels > kMaximumExclusivePixel ||
        bottomPixels > kMaximumExclusivePixel) {
        return std::nullopt;
    }
    return CheckedRectangle{rightPoints, bottomPoints, rightPixels, bottomPixels};
}

[[nodiscard]] bool overlaps(const DesktopDisplayMapping& first,
                            const CheckedRectangle& firstBounds,
                            const DesktopDisplayMapping& second,
                            const CheckedRectangle& secondBounds) noexcept {
    const auto& firstLogical = first.logicalPoints;
    const auto& secondLogical = second.logicalPoints;
    const bool logicalOverlap =
        (std::max)(firstLogical.xPoints, secondLogical.xPoints) <
            (std::min)(firstBounds.rightPoints, secondBounds.rightPoints) &&
        (std::max)(firstLogical.yPoints, secondLogical.yPoints) <
            (std::min)(firstBounds.bottomPoints, secondBounds.bottomPoints);
    const bool physicalOverlap =
        (std::max)(static_cast<std::int64_t>(first.physicalPixels.x),
                   static_cast<std::int64_t>(second.physicalPixels.x)) <
            (std::min)(firstBounds.rightPixels, secondBounds.rightPixels) &&
        (std::max)(static_cast<std::int64_t>(first.physicalPixels.y),
                   static_cast<std::int64_t>(second.physicalPixels.y)) <
            (std::min)(firstBounds.bottomPixels, secondBounds.bottomPixels);
    return logicalOverlap || physicalOverlap;
}

} // namespace

std::optional<DesktopDisplayGeometry> DesktopDisplayGeometry::create(
    const std::span<const DesktopDisplayMapping> displays,
    const std::uint64_t configurationGeneration) noexcept {
    if (configurationGeneration == 0 || displays.empty() ||
        displays.size() > kMaximumDisplays) {
        return std::nullopt;
    }

    DesktopDisplayGeometry geometry;
    std::int64_t minimumX = std::numeric_limits<std::int32_t>::max();
    std::int64_t minimumY = std::numeric_limits<std::int32_t>::max();
    std::int64_t maximumX = std::numeric_limits<std::int32_t>::min();
    std::int64_t maximumY = std::numeric_limits<std::int32_t>::min();

    // Retain the caller's order, but never retain caller-owned storage.
    for (std::size_t displayIndex = 0; displayIndex < displays.size(); ++displayIndex) {
        const auto& display = displays[displayIndex];
        const auto bounds = checkedBounds(display);
        if (!bounds) {
            return std::nullopt;
        }
        const double pixelsPerPointX =
            static_cast<double>(display.physicalPixels.widthPixels) /
            display.logicalPoints.widthPoints;
        const double pixelsPerPointY =
            static_cast<double>(display.physicalPixels.heightPixels) /
            display.logicalPoints.heightPoints;
        const double pointsPerPixelX =
            display.logicalPoints.widthPoints / display.physicalPixels.widthPixels;
        const double pointsPerPixelY =
            display.logicalPoints.heightPoints / display.physicalPixels.heightPixels;
        // Catch unrepresentable scales before they reach event dispatch.
        if (!std::isfinite(pixelsPerPointX) || pixelsPerPointX <= 0.0 ||
            !std::isfinite(pixelsPerPointY) || pixelsPerPointY <= 0.0 ||
            !std::isfinite(pointsPerPixelX) || pointsPerPixelX <= 0.0 ||
            !std::isfinite(pointsPerPixelY) || pointsPerPixelY <= 0.0) {
            return std::nullopt;
        }
        for (std::size_t previousIndex = 0; previousIndex < displayIndex;
             ++previousIndex) {
            const auto& previous = geometry.displays_[previousIndex];
            if (previous.mapping.displayId == display.displayId ||
                overlaps(previous.mapping,
                         CheckedRectangle{previous.rightPoints, previous.bottomPoints,
                                          previous.rightPixels, previous.bottomPixels},
                         display, *bounds)) {
                return std::nullopt;
            }
        }
        minimumX = (std::min)(minimumX, static_cast<std::int64_t>(display.physicalPixels.x));
        minimumY = (std::min)(minimumY, static_cast<std::int64_t>(display.physicalPixels.y));
        maximumX = (std::max)(maximumX, bounds->rightPixels);
        maximumY = (std::max)(maximumY, bounds->bottomPixels);
        geometry.displays_[displayIndex] = {
            display, bounds->rightPoints, bounds->bottomPoints,
            bounds->rightPixels, bounds->bottomPixels,
            pixelsPerPointX, pixelsPerPointY,
            pointsPerPixelX, pointsPerPixelY};
    }

    const std::int64_t width = maximumX - minimumX;
    const std::int64_t height = maximumY - minimumY;
    if (width <= 0 || height <= 0 ||
        width > std::numeric_limits<std::uint32_t>::max() ||
        height > std::numeric_limits<std::uint32_t>::max()) {
        return std::nullopt;
    }

    geometry.displayCount_ = displays.size();
    geometry.originX_ = static_cast<std::int32_t>(minimumX);
    geometry.originY_ = static_cast<std::int32_t>(minimumY);
    geometry.virtualSize_ = {static_cast<std::uint32_t>(width),
                             static_cast<std::uint32_t>(height)};
    geometry.generation_ = configurationGeneration;
    return geometry;
}

std::optional<DesktopPixelPosition> DesktopDisplayGeometry::pixelAtLogicalPoint(
    const DesktopLogicalPoint point,
    const std::uint64_t configurationGeneration) const noexcept {
    if (configurationGeneration != generation_ ||
        !std::isfinite(point.xPoints) || !std::isfinite(point.yPoints)) {
        return std::nullopt;
    }

    for (std::size_t displayIndex = 0; displayIndex < displayCount_; ++displayIndex) {
        const auto& entry = displays_[displayIndex];
        const auto& display = entry.mapping;
        if (point.xPoints < display.logicalPoints.xPoints ||
            point.xPoints >= entry.rightPoints ||
            point.yPoints < display.logicalPoints.yPoints ||
            point.yPoints >= entry.bottomPoints) {
            continue;
        }
        const double scaledX =
            (point.xPoints - display.logicalPoints.xPoints) * entry.pixelsPerPointX;
        const double scaledY =
            (point.yPoints - display.logicalPoints.yPoints) * entry.pixelsPerPointY;
        // The point is inside the half-open logical display bounds. Clamp
        // only a rounded-to-one endpoint; do not let it select a neighbour.
        const std::uint32_t localX = static_cast<std::uint32_t>(
            (std::min)(std::floor(scaledX),
                       static_cast<double>(display.physicalPixels.widthPixels - 1)));
        const std::uint32_t localY = static_cast<std::uint32_t>(
            (std::min)(std::floor(scaledY),
                       static_cast<double>(display.physicalPixels.heightPixels - 1)));
        const std::int64_t absoluteX = static_cast<std::int64_t>(display.physicalPixels.x) + localX;
        const std::int64_t absoluteY = static_cast<std::int64_t>(display.physicalPixels.y) + localY;
        return DesktopPixelPosition{
            display.displayId, static_cast<std::int32_t>(absoluteX),
            static_cast<std::int32_t>(absoluteY),
            static_cast<std::uint32_t>(absoluteX - originX_),
            static_cast<std::uint32_t>(absoluteY - originY_)};
    }
    return std::nullopt;
}

std::optional<DisplayLogicalPosition> DesktopDisplayGeometry::logicalAtPhysicalPixel(
    const std::int32_t absoluteX, const std::int32_t absoluteY,
    const std::uint64_t configurationGeneration) const noexcept {
    if (configurationGeneration != generation_) {
        return std::nullopt;
    }
    for (std::size_t displayIndex = 0; displayIndex < displayCount_; ++displayIndex) {
        const auto& entry = displays_[displayIndex];
        const auto& display = entry.mapping;
        const auto& physical = display.physicalPixels;
        if (static_cast<std::int64_t>(absoluteX) < physical.x ||
            static_cast<std::int64_t>(absoluteX) >= entry.rightPixels ||
            static_cast<std::int64_t>(absoluteY) < physical.y ||
            static_cast<std::int64_t>(absoluteY) >= entry.bottomPixels) {
            continue;
        }
        const double localX = static_cast<double>(
            static_cast<std::int64_t>(absoluteX) - physical.x) + 0.5;
        const double localY = static_cast<double>(
            static_cast<std::int64_t>(absoluteY) - physical.y) + 0.5;
        // Center sampling keeps motion and cursor hit-testing consistent.
        // nextafter protects the exclusive upper edge from FP rounding.
        const double logicalX = (std::min)(
            display.logicalPoints.xPoints + localX * entry.pointsPerPixelX,
            std::nextafter(entry.rightPoints, display.logicalPoints.xPoints));
        const double logicalY = (std::min)(
            display.logicalPoints.yPoints + localY * entry.pointsPerPixelY,
            std::nextafter(entry.bottomPoints, display.logicalPoints.yPoints));
        return DisplayLogicalPosition{display.displayId, {logicalX, logicalY}};
    }
    return std::nullopt;
}

std::optional<DisplayLogicalPosition> DesktopDisplayGeometry::logicalAtVirtualPixel(
    const std::uint32_t virtualX, const std::uint32_t virtualY,
    const std::uint64_t configurationGeneration) const noexcept {
    if (configurationGeneration == 0 || configurationGeneration != generation_ ||
        virtualX >= virtualSize_.widthPixels ||
        virtualY >= virtualSize_.heightPixels) {
        return std::nullopt;
    }

    // The subtraction-free 64-bit addition is bounded even when the canvas
    // begins at INT32_MIN. A position inside a virtual monitor gap may not
    // be representable as a native signed pixel; reject it before narrowing.
    const std::int64_t absoluteX = static_cast<std::int64_t>(originX_) + virtualX;
    const std::int64_t absoluteY = static_cast<std::int64_t>(originY_) + virtualY;
    if (absoluteX > std::numeric_limits<std::int32_t>::max() ||
        absoluteY > std::numeric_limits<std::int32_t>::max()) {
        return std::nullopt;
    }
    return logicalAtPhysicalPixel(static_cast<std::int32_t>(absoluteX),
                                  static_cast<std::int32_t>(absoluteY),
                                  configurationGeneration);
}

} // namespace rdp::macos
