// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "platform/macos/desktop_display_geometry.h"
#include "platform/macos/native_display_snapshot.h"

#include <cstdint>
#include <expected>
#include <memory>
#include <optional>

namespace rdp::macos {

enum class NativeDisplayRefreshError : std::uint8_t {
    GenerationExhausted,
    DisplayUnavailable,
    GeometryUnsupported,
    TopologyChanged,
    TopologyCoverageUnavailable,
};

namespace detail {
struct NativeDisplayGenerationFenceState;
}

// Copyable, asynchronous-safe R7 revocation fact for one geometry generation.
// It retains only a small shared atomic state, never the mutable geometry owner,
// native display objects, permission state, or authorization. Late native
// callbacks may use current() after the geometry owner refreshes or is destroyed.
class NativeDisplayGenerationFence final {
public:
    NativeDisplayGenerationFence() noexcept = default;

    [[nodiscard]] bool current() const noexcept;
    [[nodiscard]] std::uint64_t generation() const noexcept {
        return generation_;
    }

private:
    friend class NativeDisplayGeometryRefresh;

    NativeDisplayGenerationFence(
        std::shared_ptr<const detail::NativeDisplayGenerationFenceState> state,
        std::uint64_t generation) noexcept;

    std::shared_ptr<const detail::NativeDisplayGenerationFenceState> state_{};
    std::uint64_t generation_{};
};

// A synchronous R7 geometry epoch guard, NOT an RDP session, capture stream,
// authorization capability, or graphics scheduler. Caller serializes refresh,
// invalidation and translations, and signals native topology changes promptly.
// Every attempted refresh first invalidates the previous geometry. No borrowed
// provider or native handle is retained; a failed read never leaves old pixel
// mapping usable for a new input/capture operation.
class NativeDisplayGeometryRefresh final {
public:
    NativeDisplayGeometryRefresh();
    ~NativeDisplayGeometryRefresh() noexcept;

    NativeDisplayGeometryRefresh(const NativeDisplayGeometryRefresh&) = delete;
    NativeDisplayGeometryRefresh& operator=(const NativeDisplayGeometryRefresh&) = delete;
    NativeDisplayGeometryRefresh(NativeDisplayGeometryRefresh&&) = delete;
    NativeDisplayGeometryRefresh& operator=(NativeDisplayGeometryRefresh&&) = delete;
    void invalidate() noexcept;

    [[nodiscard]] std::expected<std::uint64_t, NativeDisplayRefreshError>
    refresh(NativeDisplayReadFunction reader, void* context) noexcept;

#if defined(__APPLE__)
    // Caller-approved read-only CoreGraphics enumeration, not screen capture.
    // Native Quartz reconfiguration coverage must already be active; unlike
    // the injected refresh seam this path cannot publish an uncovered epoch.
    [[nodiscard]] std::expected<std::uint64_t, NativeDisplayRefreshError>
    refreshNative() noexcept;
#endif

    [[nodiscard]] std::uint64_t generation() const noexcept { return generation_; }
    [[nodiscard]] bool usable(std::uint64_t generation) const noexcept;
    // This fence is for asynchronous retirement only. It is issued only for
    // the exact currently usable generation and never grants capture authority.
    [[nodiscard]] std::optional<NativeDisplayGenerationFence>
    generationFence(std::uint64_t generation) const noexcept;
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

    std::shared_ptr<detail::NativeDisplayGenerationFenceState>
        generationFenceState_;
    std::uint64_t generation_{};
    std::uint64_t topologyRevision_{};
    std::optional<DesktopDisplayGeometry> active_{};
};

} // namespace rdp::macos
