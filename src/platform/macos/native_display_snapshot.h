// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

namespace rdp::macos {

// One read-only CoreGraphics observation. Global top-left display bounds
// are logical points. Backing width/height are per-display physical pixels,
// NOT a global pixel origin. Never multiply a global point origin by a
// local backing scale to fabricate an RDP virtual desktop pixel origin.
struct NativeDisplayObservation {
    std::uint32_t displayId{};
    double xPoints{};
    double yPoints{};
    double widthPoints{};
    double heightPoints{};
    std::size_t backingWidthPixels{};
    std::size_t backingHeightPixels{};
    std::uint32_t mirrorsDisplayId{};
    friend bool operator==(const NativeDisplayObservation&,
                           const NativeDisplayObservation&) = default;
};

enum class NativeDisplayReadStatus : std::uint8_t { Ok, Unavailable };

enum class NativeDisplaySnapshotError : std::uint8_t {
    Unavailable,
    InvalidGeneration,
    InvalidGeometry,
    TooManyDisplays,
    ChangedDuringRead,
};

// A synchronous borrowed reader: it must not retain destination/context and
// must write at most destination.size() items. Caller serializes shared state.
using NativeDisplayReadFunction = NativeDisplayReadStatus (*)(
    void* context, std::span<NativeDisplayObservation> destination,
    std::size_t& reportedCount) noexcept;

// Allocation-free owning snapshot. No permission grant or live OS admission,
// callback registration, screen capture, input event, or session lifecycle.
class NativeDisplaySnapshot final {
public:
    static constexpr std::size_t kMaximumDisplays = 16;

    [[nodiscard]] static std::expected<NativeDisplaySnapshot, NativeDisplaySnapshotError>
    read(NativeDisplayReadFunction readFunction, void* context,
         std::uint64_t configurationGeneration) noexcept;

    [[nodiscard]] std::span<const NativeDisplayObservation> displays() const noexcept {
        return {displays_.data(), displayCount_};
    }
    [[nodiscard]] std::uint64_t generation() const noexcept { return generation_; }

private:
    std::array<NativeDisplayObservation, kMaximumDisplays> displays_{};
    std::size_t displayCount_{};
    std::uint64_t generation_{};
};

#if defined(__APPLE__)
// Read-only Quartz Display Services. No TCC prompt, screen frame or input.
[[nodiscard]] std::expected<NativeDisplaySnapshot, NativeDisplaySnapshotError>
queryNativeDisplaySnapshot(std::uint64_t configurationGeneration) noexcept;
#endif

} // namespace rdp::macos
