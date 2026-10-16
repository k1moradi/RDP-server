// SPDX-License-Identifier: GPL-3.0-or-later
#include "platform/macos/native_display_snapshot.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>

#if defined(__APPLE__)
#include <CoreGraphics/CoreGraphics.h>
#endif

namespace rdp::macos {
namespace {

constexpr std::uint64_t kMaximumDisplayPixels = 512ULL * 1024ULL * 1024ULL / 4ULL;
constexpr std::size_t kMaximumDimensionPixels = 32768;

[[nodiscard]] bool valid(const NativeDisplayObservation& display) noexcept {
    if (display.displayId == 0 || display.mirrorsDisplayId != 0 ||
        !std::isfinite(display.xPoints) || !std::isfinite(display.yPoints) ||
        !std::isfinite(display.widthPoints) || !std::isfinite(display.heightPoints) ||
        display.widthPoints <= 0.0 || display.heightPoints <= 0.0 ||
        display.backingWidthPixels == 0 || display.backingHeightPixels == 0 ||
        display.backingWidthPixels > kMaximumDimensionPixels ||
        display.backingHeightPixels > kMaximumDimensionPixels ||
        display.backingWidthPixels >
            kMaximumDisplayPixels / display.backingHeightPixels) {
        return false;
    }
    const double right = display.xPoints + display.widthPoints;
    const double bottom = display.yPoints + display.heightPoints;
    return std::isfinite(right) && std::isfinite(bottom) &&
           right > display.xPoints && bottom > display.yPoints;
}

[[nodiscard]] bool overlaps(const NativeDisplayObservation& first,
                            const NativeDisplayObservation& second) noexcept {
    return (std::max)(first.xPoints, second.xPoints) <
               (std::min)(first.xPoints + first.widthPoints,
                          second.xPoints + second.widthPoints) &&
           (std::max)(first.yPoints, second.yPoints) <
               (std::min)(first.yPoints + first.heightPoints,
                          second.yPoints + second.heightPoints);
}

using SampleBuffer = std::array<NativeDisplayObservation,
                                NativeDisplaySnapshot::kMaximumDisplays + 1>;

[[nodiscard]] std::expected<std::size_t, NativeDisplaySnapshotError>
readChecked(NativeDisplayReadFunction reader, void* context,
            SampleBuffer& samples) noexcept {
    std::size_t count{};
    if (reader(context, samples, count) != NativeDisplayReadStatus::Ok) {
        return std::unexpected(NativeDisplaySnapshotError::Unavailable);
    }
    if (count > NativeDisplaySnapshot::kMaximumDisplays) {
        return std::unexpected(NativeDisplaySnapshotError::TooManyDisplays);
    }
    if (count == 0) {
        return std::unexpected(NativeDisplaySnapshotError::Unavailable);
    }
    for (std::size_t index = 0; index < count; ++index) {
        if (!valid(samples[index])) {
            return std::unexpected(NativeDisplaySnapshotError::InvalidGeometry);
        }
        for (std::size_t previous = 0; previous < index; ++previous) {
            if (samples[previous].displayId == samples[index].displayId ||
                overlaps(samples[previous], samples[index])) {
                return std::unexpected(NativeDisplaySnapshotError::InvalidGeometry);
            }
        }
    }
    // OS enumeration order is not a display identity or lifecycle signal.
    std::sort(samples.begin(), samples.begin() + static_cast<std::ptrdiff_t>(count),
              [](const auto& first, const auto& second) noexcept {
                  return first.displayId < second.displayId;
              });
    return count;
}

#if defined(__APPLE__)
[[nodiscard]] NativeDisplayReadStatus readCoreGraphicsDisplays(
    void*, std::span<NativeDisplayObservation> destination,
    std::size_t& reportedCount) noexcept {
    std::array<CGDirectDisplayID, NativeDisplaySnapshot::kMaximumDisplays + 1>
        nativeIds{};
    std::uint32_t nativeCount{};
    if (CGGetActiveDisplayList(static_cast<std::uint32_t>(nativeIds.size()),
                               nativeIds.data(), &nativeCount) != kCGErrorSuccess) {
        return NativeDisplayReadStatus::Unavailable;
    }
    reportedCount = nativeCount;
    if (nativeCount > destination.size()) {
        return NativeDisplayReadStatus::Unavailable;
    }
    for (std::size_t index = 0; index < nativeCount; ++index) {
        const CGDirectDisplayID displayId = nativeIds[index];
        const CGRect bounds = CGDisplayBounds(displayId);
        destination[index] = {
            displayId, bounds.origin.x, bounds.origin.y,
            bounds.size.width, bounds.size.height,
            CGDisplayPixelsWide(displayId), CGDisplayPixelsHigh(displayId),
            CGDisplayMirrorsDisplay(displayId)};
    }
    return NativeDisplayReadStatus::Ok;
}
#endif

} // namespace

std::expected<NativeDisplaySnapshot, NativeDisplaySnapshotError>
NativeDisplaySnapshot::read(const NativeDisplayReadFunction reader,
                            void* const context,
                            const std::uint64_t configurationGeneration) noexcept {
    if (configurationGeneration == 0) {
        return std::unexpected(NativeDisplaySnapshotError::InvalidGeneration);
    }
    if (reader == nullptr) {
        return std::unexpected(NativeDisplaySnapshotError::Unavailable);
    }
    SampleBuffer first{};
    SampleBuffer second{};
    const auto firstCount = readChecked(reader, context, first);
    if (!firstCount) {
        return std::unexpected(firstCount.error());
    }
    const auto secondCount = readChecked(reader, context, second);
    if (!secondCount) {
        return std::unexpected(secondCount.error());
    }
    if (*firstCount != *secondCount ||
        !std::equal(first.begin(), first.begin() + static_cast<std::ptrdiff_t>(*firstCount),
                    second.begin())) {
        return std::unexpected(NativeDisplaySnapshotError::ChangedDuringRead);
    }
    NativeDisplaySnapshot snapshot;
    std::copy_n(first.begin(), *firstCount, snapshot.displays_.begin());
    snapshot.displayCount_ = *firstCount;
    snapshot.generation_ = configurationGeneration;
    return snapshot;
}

#if defined(__APPLE__)
std::expected<NativeDisplaySnapshot, NativeDisplaySnapshotError>
queryNativeDisplaySnapshot(const std::uint64_t configurationGeneration) noexcept {
    return NativeDisplaySnapshot::read(&readCoreGraphicsDisplays, nullptr,
                                       configurationGeneration);
}
#endif

} // namespace rdp::macos
