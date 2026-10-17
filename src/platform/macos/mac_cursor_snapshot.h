// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "platform/macos/native_display_refresh.h"
#include "platform/macos/native_session_change_watch.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>

namespace rdp::macos {

inline constexpr std::uint32_t kMaximumMacCursorDimension = 256;
inline constexpr std::size_t kMaximumMacCursorBytes =
    static_cast<std::size_t>(kMaximumMacCursorDimension) *
    kMaximumMacCursorDimension * 4U;

enum class MacCursorSnapshotError : std::uint8_t {
    InvalidGeneration,
    StaleGeometryGeneration,
    StaleTopology,
    StaleSession,
    PositionOutsideDesktop,
    InvalidObservation,
    NativeCursorUnavailable,
    ImageUnavailable,
    AllocationFailed,
    RenderingFailed,
};

// Native cursor facts before desktop-coordinate normalization. Shape pixels are
// supplied separately as owned top-left BGRA storage. A hidden observation must
// not carry stale shape metadata.
struct MacNativeCursorObservation final {
    bool visible{};
    DesktopLogicalPoint position{};
    std::uint32_t widthPixels{};
    std::uint32_t heightPixels{};
    std::uint32_t hotspotX{};
    std::uint32_t hotspotY{};
    std::size_t bytesPerRow{};
};

// Move-only, independently owned R7 cursor snapshot. Cursor position is the
// hotspot position in RDP virtual-desktop pixels. Visible pixels are tightly
// packed premultiplied BGRA, top row first. Hidden snapshots deliberately own
// no shape bytes so stale cursor images cannot leak across a hide transition.
struct MacCursorSnapshot final {
    bool visible{};
    DesktopPixelPosition position{};
    std::uint32_t widthPixels{};
    std::uint32_t heightPixels{};
    std::uint32_t hotspotX{};
    std::uint32_t hotspotY{};
    std::size_t bytesPerRow{};
    std::unique_ptr<std::byte[]> storage{};
    std::size_t byteCount{};
    std::uint64_t geometryGeneration{};
    std::uint64_t topologyRevision{};
    std::uint64_t sessionWatchRevision{};

    MacCursorSnapshot() noexcept = default;
    MacCursorSnapshot(const MacCursorSnapshot&) = delete;
    MacCursorSnapshot& operator=(const MacCursorSnapshot&) = delete;
    MacCursorSnapshot(MacCursorSnapshot&&) noexcept = default;
    MacCursorSnapshot& operator=(MacCursorSnapshot&&) noexcept = default;

    // Owned-storage/session inspection only. These accessors do not establish
    // that this snapshot still belongs to the caller's current display
    // geometry and must not be used as a cursor-publication gate.
    [[nodiscard]] std::span<const std::byte> pixels() const noexcept {
        if (!valid() || storage == nullptr) {
            return {};
        }
        return {storage.get(), byteCount};
    }

    [[nodiscard]] bool valid() const noexcept;

    // Current-desktop consumption is a separate synchronous check. The caller
    // owns and serializes geometry lifetime; no borrowed geometry pointer is
    // retained by the snapshot. These checks grant no R2/R3 authorization and
    // perform no native sampling or R4 protocol publication.
    [[nodiscard]] bool
    validFor(const NativeDisplayGeometryRefresh& geometry) const noexcept;
    [[nodiscard]] std::span<const std::byte>
    pixelsFor(const NativeDisplayGeometryRefresh& geometry) const noexcept {
        if (!validFor(geometry) || storage == nullptr) {
            return {};
        }
        return {storage.get(), byteCount};
    }
};

// Validates one synthetic/native observation against a caller-pinned display
// and GUI-session epoch, then transactionally adopts the caller-owned pixel
// storage. The session revision must be captured before native observation
// begins so a switch cannot relabel stale cursor state. No native handle,
// borrowed span or authorization capability survives this call.
[[nodiscard]] std::expected<MacCursorSnapshot, MacCursorSnapshotError>
makeMacCursorSnapshot(const NativeDisplayGeometryRefresh& geometry,
                      std::uint64_t geometryGeneration,
                      std::uint64_t sessionWatchRevision,
                      MacNativeCursorObservation observation,
                      std::unique_ptr<std::byte[]> storage,
                      std::size_t byteCount) noexcept;

// Native AppKit cursor sampling stays translation-unit-private until a future
// R2/R3 macOS authorization owner and R4 cursor consumer can invoke it through
// one capability-bound route. Geometry alone must not expose live cursor state.

} // namespace rdp::macos
