// SPDX-License-Identifier: GPL-3.0-or-later
#include "platform/macos/native_display_refresh.h"

#include "platform/macos/native_display_geometry.h"

#include <limits>
#include <utility>

namespace rdp::macos {

void NativeDisplayGeometryRefresh::invalidate() noexcept {
    active_.reset();
    if (generation_ != std::numeric_limits<std::uint64_t>::max()) {
        ++generation_;
    }
}

bool NativeDisplayGeometryRefresh::advance() noexcept {
    if (generation_ == std::numeric_limits<std::uint64_t>::max()) {
        active_.reset();
        return false;
    }
    invalidate();
    return true;
}

std::expected<std::uint64_t, NativeDisplayRefreshError>
NativeDisplayGeometryRefresh::install(
    const std::expected<NativeDisplaySnapshot, NativeDisplaySnapshotError>& observed) noexcept {
    if (!observed) {
        return std::unexpected(NativeDisplayRefreshError::DisplayUnavailable);
    }
    auto geometry = makeDesktopGeometry(*observed);
    if (!geometry) {
        return std::unexpected(NativeDisplayRefreshError::GeometryUnsupported);
    }
    active_.emplace(std::move(*geometry));
    return generation_;
}

std::expected<std::uint64_t, NativeDisplayRefreshError>
NativeDisplayGeometryRefresh::refresh(const NativeDisplayReadFunction reader,
                                       void* const context) noexcept {
    if (!advance()) {
        return std::unexpected(NativeDisplayRefreshError::GenerationExhausted);
    }
    return install(NativeDisplaySnapshot::read(reader, context, generation_));
}

#if defined(__APPLE__)
std::expected<std::uint64_t, NativeDisplayRefreshError>
NativeDisplayGeometryRefresh::refreshNative() noexcept {
    if (!advance()) {
        return std::unexpected(NativeDisplayRefreshError::GenerationExhausted);
    }
    return install(queryNativeDisplaySnapshot(generation_));
}
#endif

bool NativeDisplayGeometryRefresh::usable(const std::uint64_t generation) const noexcept {
    return generation != 0 && generation == generation_ && active_.has_value();
}

std::optional<PixelSize> NativeDisplayGeometryRefresh::virtualPixelSize(
    const std::uint64_t generation) const noexcept {
    if (!usable(generation)) return std::nullopt;
    return active_->virtualPixelSize();
}

std::optional<DesktopPixelPosition> NativeDisplayGeometryRefresh::pixelAtLogicalPoint(
    const DesktopLogicalPoint point, const std::uint64_t generation) const noexcept {
    if (!usable(generation)) return std::nullopt;
    return active_->pixelAtLogicalPoint(point, generation);
}

std::optional<DisplayLogicalPosition> NativeDisplayGeometryRefresh::logicalAtVirtualPixel(
    const std::uint32_t x, const std::uint32_t y,
    const std::uint64_t generation) const noexcept {
    if (!usable(generation)) return std::nullopt;
    return active_->logicalAtVirtualPixel(x, y, generation);
}

} // namespace rdp::macos
