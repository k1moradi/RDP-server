// SPDX-License-Identifier: GPL-3.0-or-later
#include "platform/macos/native_display_geometry.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <limits>

namespace rdp::macos {
namespace {

// Native dimensions are bounded by NativeDisplaySnapshot::read. The pixel
// origin is an R4-compositor-relative offset, not a Quartz framebuffer point.
[[nodiscard]] bool closeScale(const long double first,
                              const long double second) noexcept {
    return std::isfinite(first) && std::isfinite(second) && first > 0.0L &&
           second > 0.0L &&
           std::fabs(first - second) <=
               1e-10L * (std::max)(first, second);
}

[[nodiscard]] bool pixelOrigin(const long double logicalOffset,
                               const long double scale,
                               const std::size_t extent,
                               std::int32_t& out) noexcept {
    const long double position = logicalOffset * scale;
    if (!std::isfinite(position) || position < 0.0L) return false;
    const long double nearest = std::round(position);
    // Only permit exact-enough pixel alignment; no silent fractional
    // displacement that can spoil hit testing or framebuffer stitching.
    if (std::fabs(nearest - position) > 1e-9L ||
        nearest > static_cast<long double>(std::numeric_limits<std::int32_t>::max()) -
                      static_cast<long double>(extent)) return false;
    out = static_cast<std::int32_t>(nearest);
    return true;
}

} // namespace

std::expected<DesktopDisplayGeometry, NativeDisplayGeometryError>
makeDesktopGeometry(const NativeDisplaySnapshot& native) noexcept {
    const auto displays = native.displays();
    if (native.generation() == 0 || displays.empty() ||
        displays.size() > DesktopDisplayGeometry::kMaximumDisplays) {
        return std::unexpected(NativeDisplayGeometryError::InvalidSnapshot);
    }

    // Normalize every display against one global Quartz logical origin;
    // never multiply a different scale by each absolute origin.
    long double minX = std::numeric_limits<long double>::infinity();
    long double minY = std::numeric_limits<long double>::infinity();
    for (const auto& d : displays) {
        if (d.rotationDegrees != 0.0 || !std::isfinite(d.rotationDegrees)) {
            return std::unexpected(NativeDisplayGeometryError::UnsupportedRotation);
        }
        if (d.displayId == 0 || d.mirrorsDisplayId != 0 ||
            !std::isfinite(d.xPoints) || !std::isfinite(d.yPoints) ||
            !std::isfinite(d.widthPoints) || !std::isfinite(d.heightPoints) ||
            d.widthPoints <= 0.0 || d.heightPoints <= 0.0 ||
            d.backingWidthPixels == 0 || d.backingHeightPixels == 0 ||
            d.backingWidthPixels > 32768 || d.backingHeightPixels > 32768 ||
            d.backingWidthPixels > (512ULL * 1024ULL * 1024ULL / 4ULL) /
                                    d.backingHeightPixels) {
            return std::unexpected(NativeDisplayGeometryError::InvalidSnapshot);
        }
        minX = (std::min)(minX, static_cast<long double>(d.xPoints));
        minY = (std::min)(minY, static_cast<long double>(d.yPoints));
    }

    const auto& first = displays.front();
    const long double scaleX = static_cast<long double>(first.backingWidthPixels) /
                               static_cast<long double>(first.widthPoints);
    const long double scaleY = static_cast<long double>(first.backingHeightPixels) /
                               static_cast<long double>(first.heightPoints);
    if (!closeScale(scaleX, scaleY)) {
        return std::unexpected(NativeDisplayGeometryError::UnsupportedMixedScale);
    }
    std::array<DesktopDisplayMapping, DesktopDisplayGeometry::kMaximumDisplays> mappings{};
    for (std::size_t i = 0; i < displays.size(); ++i) {
        const auto& d = displays[i];
        const long double sx = static_cast<long double>(d.backingWidthPixels) /
                               static_cast<long double>(d.widthPoints);
        const long double sy = static_cast<long double>(d.backingHeightPixels) /
                               static_cast<long double>(d.heightPoints);
        if (!closeScale(sx, scaleX) || !closeScale(sy, scaleY)) {
            return std::unexpected(NativeDisplayGeometryError::UnsupportedMixedScale);
        }
        std::int32_t x{};
        std::int32_t y{};
        if (!pixelOrigin(static_cast<long double>(d.xPoints) - minX, scaleX,
                         d.backingWidthPixels, x) ||
            !pixelOrigin(static_cast<long double>(d.yPoints) - minY, scaleY,
                         d.backingHeightPixels, y)) {
            return std::unexpected(NativeDisplayGeometryError::UnrepresentablePlacement);
        }
        mappings[i] = {d.displayId,
                       {d.xPoints, d.yPoints, d.widthPoints, d.heightPoints},
                       {x, y, static_cast<std::uint32_t>(d.backingWidthPixels),
                        static_cast<std::uint32_t>(d.backingHeightPixels)}};
    }
    const auto result = DesktopDisplayGeometry::create(
        {mappings.data(), displays.size()}, native.generation());
    if (!result) {
        return std::unexpected(NativeDisplayGeometryError::UnrepresentablePlacement);
    }
    return *result;
}

#if defined(__APPLE__)
std::expected<DesktopDisplayGeometry, NativeDisplayGeometryError>
queryNativeDesktopGeometry(const std::uint64_t generation) noexcept {
    const auto native = queryNativeDisplaySnapshot(generation);
    if (!native) return std::unexpected(NativeDisplayGeometryError::InvalidSnapshot);
    return makeDesktopGeometry(*native);
}
#endif

} // namespace rdp::macos
