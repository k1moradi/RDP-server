// SPDX-License-Identifier: GPL-3.0-or-later
#include "platform/macos/native_display_refresh.h"

#include "platform/macos/native_display_geometry.h"
#include "platform/macos/native_display_reconfiguration.h"

#include <limits>
#include <utility>

namespace rdp::macos {

void NativeDisplayGeometryRefresh::invalidate() noexcept {
    active_.reset();
    topologyRevision_ = 0;
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
    const std::expected<NativeDisplaySnapshot, NativeDisplaySnapshotError>& observed,
    const std::uint64_t topologyRevision) noexcept {
    if (!observed) {
        return std::unexpected(NativeDisplayRefreshError::DisplayUnavailable);
    }
    auto geometry = makeDesktopGeometry(*observed);
    if (!geometry) {
        return std::unexpected(NativeDisplayRefreshError::GeometryUnsupported);
    }
    if (NativeDisplayReconfigurationWatch::changedSince(topologyRevision)) {
        return std::unexpected(NativeDisplayRefreshError::TopologyChanged);
    }
    active_.emplace(std::move(*geometry));
    topologyRevision_ = topologyRevision;
    return generation_;
}

std::expected<std::uint64_t, NativeDisplayRefreshError>
NativeDisplayGeometryRefresh::refresh(const NativeDisplayReadFunction reader,
                                       void* const context) noexcept {
    if (!advance()) {
        return std::unexpected(NativeDisplayRefreshError::GenerationExhausted);
    }
    const auto revision = NativeDisplayReconfigurationWatch::revision();
    return install(NativeDisplaySnapshot::read(reader, context, generation_), revision);
}

#if defined(__APPLE__)
std::expected<std::uint64_t, NativeDisplayRefreshError>
NativeDisplayGeometryRefresh::refreshNative() noexcept {
    if (!advance()) {
        return std::unexpected(NativeDisplayRefreshError::GenerationExhausted);
    }
    const auto revision = NativeDisplayReconfigurationWatch::revision();
    return install(queryNativeDisplaySnapshot(generation_), revision);
}
#endif

bool NativeDisplayGeometryRefresh::usable(const std::uint64_t generation) const noexcept {
    return generation != 0 && generation == generation_ && active_.has_value() &&
           !NativeDisplayReconfigurationWatch::changedSince(topologyRevision_);
}

std::optional<PixelSize> NativeDisplayGeometryRefresh::virtualPixelSize(
    const std::uint64_t generation) const noexcept {
    if (!usable(generation)) return std::nullopt;
    return active_->virtualPixelSize();
}

std::optional<DesktopDisplayMapping> NativeDisplayGeometryRefresh::displayMapping(
    const std::uint32_t displayId, const std::uint64_t generation) const noexcept {
    if (!usable(generation)) return std::nullopt;
    return active_->displayMapping(displayId, generation);
}

std::optional<std::uint64_t> NativeDisplayGeometryRefresh::topologyRevision(
    const std::uint64_t generation) const noexcept {
    if (!usable(generation)) return std::nullopt;
    return topologyRevision_;
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
