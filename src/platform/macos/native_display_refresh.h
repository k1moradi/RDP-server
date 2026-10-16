// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "platform/macos/desktop_display_geometry.h"
#include "platform/macos/native_display_snapshot.h"

#include <cstdint>
#include <expected>
#include <optional>

namespace rdp::macos {

enum class NativeDisplayRefreshError : std::uint8_t {
    GenerationExhausted,
    DisplayUnavailable,
    GeometryUnsupported,
    TopologyChanged,
};

// A synchronous R7 geometry epoch guard, NOT an RDP session, capture stream,
// authorization capability, or graphics scheduler. Caller serializes refresh,
// invalidation and translations, and signals native topology changes promptly.
// Every attempted refresh first invalidates the previous geometry. No borrowed
// provider or native handle is retained; a failed read never leaves old pixel
// mapping usable for a new input/capture operation.
class NativeDisplayGeometryRefresh final {
public:
    NativeDisplayGeometryRefresh() noexcept = default;
    NativeDisplayGeometryRefresh(const NativeDisplayGeometryRefresh&) = delete;
    NativeDisplayGeometryRefresh& operator=(const NativeDisplayGeometryRefresh&) = delete;
    NativeDisplayGeometryRefresh(NativeDisplayGeometryRefresh&&) = delete;
    NativeDisplayGeometryRefresh& operator=(NativeDisplayGeometryRefresh&&) = delete;
    void invalidate() noexcept;

    [[nodiscard]] std::expected<std::uint64_t, NativeDisplayRefreshError>
    refresh(NativeDisplayReadFunction reader, void* context) noexcept;

#if defined(__APPLE__)
    // Caller-approved read-only CoreGraphics enumeration, not screen capture.
    [[nodiscard]] std::expected<std::uint64_t, NativeDisplayRefreshError>
    refreshNative() noexcept;
#endif

    [[nodiscard]] std::uint64_t generation() const noexcept { return generation_; }
    [[nodiscard]] bool usable(std::uint64_t generation) const noexcept;
    [[nodiscard]] std::optional<PixelSize>
    virtualPixelSize(std::uint64_t generation) const noexcept;
    [[nodiscard]] std::optional<DesktopDisplayMapping>
    displayMapping(std::uint32_t displayId, std::uint64_t generation) const noexcept;
    [[nodiscard]] std::optional<std::uint64_t>
    topologyRevision(std::uint64_t generation) const noexcept;
    [[nodiscard]] std::optional<DesktopPixelPosition>
    pixelAtLogicalPoint(DesktopLogicalPoint point,
                        std::uint64_t generation) const noexcept;
    [[nodiscard]] std::optional<DisplayLogicalPosition>
    logicalAtVirtualPixel(std::uint32_t x, std::uint32_t y,
                          std::uint64_t generation) const noexcept;

private:
    [[nodiscard]] bool advance() noexcept;
    [[nodiscard]] std::expected<std::uint64_t, NativeDisplayRefreshError>
    install(const std::expected<NativeDisplaySnapshot,
                                NativeDisplaySnapshotError>& observed,
            std::uint64_t topologyRevision) noexcept;

    std::uint64_t generation_{};
    std::uint64_t topologyRevision_{};
    std::optional<DesktopDisplayGeometry> active_{};
};

} // namespace rdp::macos
