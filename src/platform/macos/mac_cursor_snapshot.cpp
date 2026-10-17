// SPDX-License-Identifier: GPL-3.0-or-later
#include "mac_cursor_snapshot.h"

#include <utility>

namespace rdp::macos {
namespace {

[[nodiscard]] bool validVisibleObservation(
    const MacNativeCursorObservation& observation,
    const std::unique_ptr<std::byte[]>& storage,
    const std::size_t byteCount) noexcept {
    if (!observation.visible || observation.widthPixels == 0 ||
        observation.heightPixels == 0 ||
        observation.widthPixels > kMaximumMacCursorDimension ||
        observation.heightPixels > kMaximumMacCursorDimension ||
        observation.hotspotX >= observation.widthPixels ||
        observation.hotspotY >= observation.heightPixels || storage == nullptr) {
        return false;
    }

    const std::size_t expectedBytesPerRow =
        static_cast<std::size_t>(observation.widthPixels) * 4U;
    const std::size_t expectedByteCount =
        expectedBytesPerRow * observation.heightPixels;
    return observation.bytesPerRow == expectedBytesPerRow &&
           byteCount == expectedByteCount &&
           byteCount <= kMaximumMacCursorBytes;
}

[[nodiscard]] bool validHiddenObservation(
    const MacNativeCursorObservation& observation,
    const std::unique_ptr<std::byte[]>& storage,
    const std::size_t byteCount) noexcept {
    return !observation.visible && observation.widthPixels == 0 &&
           observation.heightPixels == 0 && observation.hotspotX == 0 &&
           observation.hotspotY == 0 && observation.bytesPerRow == 0 &&
           storage == nullptr && byteCount == 0;
}

} // namespace

bool MacCursorSnapshot::valid() const noexcept {
    if (geometryGeneration == 0 || topologyRevision == 0 ||
        sessionWatchRevision == 0 ||
        !NativeSessionChangeWatch::current(sessionWatchRevision)) {
        return false;
    }
    if (!visible) {
        return position.displayId == 0 && widthPixels == 0 &&
               heightPixels == 0 && hotspotX == 0 && hotspotY == 0 &&
               bytesPerRow == 0 && storage == nullptr && byteCount == 0;
    }
    if (position.displayId == 0 || widthPixels == 0 || heightPixels == 0 ||
        widthPixels > kMaximumMacCursorDimension ||
        heightPixels > kMaximumMacCursorDimension || hotspotX >= widthPixels ||
        hotspotY >= heightPixels || storage == nullptr) {
        return false;
    }
    const std::size_t expectedBytesPerRow =
        static_cast<std::size_t>(widthPixels) * 4U;
    const std::size_t expectedByteCount =
        expectedBytesPerRow * heightPixels;
    return bytesPerRow == expectedBytesPerRow &&
           byteCount == expectedByteCount &&
           byteCount <= kMaximumMacCursorBytes;
}

bool MacCursorSnapshot::validFor(
    const NativeDisplayGeometryRefresh& geometry) const noexcept {
    if (!valid() || !geometry.usable(geometryGeneration)) {
        return false;
    }

    const auto currentTopologyRevision =
        geometry.topologyRevision(geometryGeneration);
    if (!currentTopologyRevision ||
        *currentTopologyRevision != topologyRevision) {
        return false;
    }

    // Hidden is a current no-shape observation and intentionally has no
    // display identity. Visible state must still name a display in this exact
    // current geometry generation before its owned bytes are consumable.
    return !visible ||
           geometry.displayMapping(position.displayId, geometryGeneration)
               .has_value();
}

std::expected<MacCursorSnapshot, MacCursorSnapshotError>
makeMacCursorSnapshot(const NativeDisplayGeometryRefresh& geometry,
                      const std::uint64_t geometryGeneration,
                      const std::uint64_t sessionWatchRevision,
                      const MacNativeCursorObservation observation,
                      std::unique_ptr<std::byte[]> storage,
                      const std::size_t byteCount) noexcept {
    if (geometryGeneration == 0) {
        return std::unexpected(MacCursorSnapshotError::InvalidGeneration);
    }
    if (geometry.generation() != geometryGeneration) {
        return std::unexpected(MacCursorSnapshotError::StaleGeometryGeneration);
    }

    const auto topologyRevision = geometry.topologyRevision(geometryGeneration);
    if (!topologyRevision || *topologyRevision == 0) {
        return std::unexpected(MacCursorSnapshotError::StaleTopology);
    }
    if (sessionWatchRevision == 0 ||
        !NativeSessionChangeWatch::current(sessionWatchRevision)) {
        return std::unexpected(MacCursorSnapshotError::StaleSession);
    }

    if (!observation.visible) {
        if (!validHiddenObservation(observation, storage, byteCount)) {
            return std::unexpected(MacCursorSnapshotError::InvalidObservation);
        }
        const auto finalRevision = geometry.topologyRevision(geometryGeneration);
        if (!finalRevision || *finalRevision != *topologyRevision) {
            return std::unexpected(MacCursorSnapshotError::StaleTopology);
        }
        if (!NativeSessionChangeWatch::current(sessionWatchRevision)) {
            return std::unexpected(MacCursorSnapshotError::StaleSession);
        }
        MacCursorSnapshot snapshot;
        snapshot.geometryGeneration = geometryGeneration;
        snapshot.topologyRevision = *topologyRevision;
        snapshot.sessionWatchRevision = sessionWatchRevision;
        return snapshot;
    }

    if (!validVisibleObservation(observation, storage, byteCount)) {
        return std::unexpected(MacCursorSnapshotError::InvalidObservation);
    }
    const auto position = geometry.pixelAtLogicalPoint(
        observation.position, geometryGeneration);
    if (!position) {
        const auto finalRevision = geometry.topologyRevision(geometryGeneration);
        if (!finalRevision || *finalRevision != *topologyRevision) {
            return std::unexpected(MacCursorSnapshotError::StaleTopology);
        }
        if (!NativeSessionChangeWatch::current(sessionWatchRevision)) {
            return std::unexpected(MacCursorSnapshotError::StaleSession);
        }
        return std::unexpected(MacCursorSnapshotError::PositionOutsideDesktop);
    }
    const auto finalRevision = geometry.topologyRevision(geometryGeneration);
    if (!finalRevision || *finalRevision != *topologyRevision) {
        return std::unexpected(MacCursorSnapshotError::StaleTopology);
    }
    if (!NativeSessionChangeWatch::current(sessionWatchRevision)) {
        return std::unexpected(MacCursorSnapshotError::StaleSession);
    }

    MacCursorSnapshot snapshot;
    snapshot.visible = true;
    snapshot.position = *position;
    snapshot.widthPixels = observation.widthPixels;
    snapshot.heightPixels = observation.heightPixels;
    snapshot.hotspotX = observation.hotspotX;
    snapshot.hotspotY = observation.hotspotY;
    snapshot.bytesPerRow = observation.bytesPerRow;
    snapshot.storage = std::move(storage);
    snapshot.byteCount = byteCount;
    snapshot.geometryGeneration = geometryGeneration;
    snapshot.topologyRevision = *topologyRevision;
    snapshot.sessionWatchRevision = sessionWatchRevision;
    return snapshot;
}

} // namespace rdp::macos
