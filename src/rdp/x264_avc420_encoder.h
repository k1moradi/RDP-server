// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "core/geometry.h"

namespace rdp_server::rdp
{

struct X264Nv12PictureView final
{
    PixelSize codedGeometry{};
    std::span<const std::byte> yPlane{};
    std::span<const std::byte> uvPlane{};
    std::size_t yStrideBytes{};
    std::size_t uvStrideBytes{};

    // Opaque caller presentation label for the current fixed-CFR encoder.
    // R4 forwards it to x264 verbatim; it is not a scheduling/ACK authority.
    std::int64_t pts{};
};

struct X264EncodedPicture final
{
    std::vector<std::byte> annexB{};
    bool keyFrame{};

    // x264's output PTS. With the current zero-delay/no-B-frame CFR
    // configuration this preserves the caller-provided input label exactly.
    std::int64_t pts{};
};

// Owns one low-latency 8-bit 4:2:0 x264 encoder context. Input planes are
// borrowed only for encode() and are never retained by this wrapper. Each
// successful output is copied into caller-owned storage, so it remains valid
// across later encode() calls and reset().
//
// Not thread-safe: the single R4 presentation owner serializes one encoder
// instance for one active surface/generation.
class X264Avc420Encoder final
{
public:
    static constexpr std::size_t kMaximumEncodedPictureBytes =
        16U * 1024U * 1024U;

    X264Avc420Encoder() noexcept;
    ~X264Avc420Encoder();

    X264Avc420Encoder(const X264Avc420Encoder &) = delete;
    X264Avc420Encoder &operator=(const X264Avc420Encoder &) = delete;
    X264Avc420Encoder(X264Avc420Encoder &&) = delete;
    X264Avc420Encoder &operator=(X264Avc420Encoder &&) = delete;

    [[nodiscard]] bool open(PixelSize codedGeometry,
                            PixelSize visibleGeometry) noexcept;
    void reset() noexcept;

    [[nodiscard]] bool valid() const noexcept;
    [[nodiscard]] PixelSize codedGeometry() const noexcept;
    [[nodiscard]] PixelSize visibleGeometry() const noexcept;

    // Check all deterministic NV12 plane extents/strides without touching
    // x264 reference state. The producer uses this before stateful encode;
    // encode() enforces the same predicate for direct callers.
    [[nodiscard]] bool canEncodePicture(
        const X264Nv12PictureView &picture) const noexcept;

    [[nodiscard]] bool encode(const X264Nv12PictureView &picture,
                              X264EncodedPicture &output) noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_{};
};

} // namespace rdp_server::rdp
