// SPDX-License-Identifier: GPL-3.0-or-later
#include "platform/macos/native_display_refresh.h"

#include "platform/macos/native_display_geometry.h"
#include "platform/macos/native_display_reconfiguration.h"

#include <atomic>
#include <limits>
#include <memory>
#include <utility>

namespace rdp::macos {
namespace detail {

struct NativeDisplayGenerationFenceState final {
    std::atomic<std::uint64_t> activeGeneration{};
};

} // namespace detail

NativeDisplayGenerationFence::NativeDisplayGenerationFence(
    std::shared_ptr<const detail::NativeDisplayGenerationFenceState> state,
    const std::uint64_t generation) noexcept
    : state_(std::move(state)), generation_(generation) {}

bool NativeDisplayGenerationFence::current() const noexcept {
    return state_ != nullptr && generation_ != 0 &&
           state_->activeGeneration.load(std::memory_order_acquire) ==
               generation_;
}

NativeDisplayGeometryRefresh::NativeDisplayGeometryRefresh()
    : generationFenceState_(
          std::make_shared<detail::NativeDisplayGenerationFenceState>()) {}

NativeDisplayGeometryRefresh::~NativeDisplayGeometryRefresh() noexcept {
    generationFenceState_->activeGeneration.store(0, std::memory_order_release);
}

void NativeDisplayGeometryRefresh::invalidate() noexcept {
    // Revoke asynchronous users before mutating the serialized geometry owner.
    generationFenceState_->activeGeneration.store(0, std::memory_order_release);
    active_.reset();
    topologyRevision_ = 0;
    if (generation_ != std::numeric_limits<std::uint64_t>::max()) {
        ++generation_;
    }
}

bool NativeDisplayGeometryRefresh::advance() noexcept {
    if (generation_ == std::numeric_limits<std::uint64_t>::max()) {
        generationFenceState_->activeGeneration.store(
            0, std::memory_order_release);
        active_.reset();
        topologyRevision_ = 0;
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
    // Publish the async-visible generation only after the complete geometry
    // and its topology revision have been installed.
    generationFenceState_->activeGeneration.store(
        generation_, std::memory_order_release);
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
    if (!NativeDisplayReconfigurationWatch::nativeCoverageActive()) {
        return std::unexpected(
            NativeDisplayRefreshError::TopologyCoverageUnavailable);
    }
    const auto revision = NativeDisplayReconfigurationWatch::revision();
    return install(queryNativeDisplaySnapshot(generation_), revision);
}
#endif

bool NativeDisplayGeometryRefresh::usable(const std::uint64_t generation) const noexcept {
    return generation != 0 && generation == generation_ && active_.has_value() &&
           !NativeDisplayReconfigurationWatch::changedSince(topologyRevision_);
}

std::optional<NativeDisplayGenerationFence>
NativeDisplayGeometryRefresh::generationFence(
    const std::uint64_t generation) const noexcept {
    if (!usable(generation)) {
        return std::nullopt;
    }
    return NativeDisplayGenerationFence{generationFenceState_, generation};
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
