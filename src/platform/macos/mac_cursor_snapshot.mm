// SPDX-License-Identifier: GPL-3.0-or-later
#include "mac_cursor_snapshot.h"

#include <AppKit/AppKit.h>
#include <CoreGraphics/CoreGraphics.h>

#include <cmath>
#include <cstdint>
#include <memory>
#include <new>
#include <type_traits>
#include <utility>

namespace rdp::macos {
namespace {

struct EventReleaser final {
    void operator()(CGEventRef value) const noexcept {
        if (value != nullptr) CFRelease(value);
    }
};
using EventOwner = std::unique_ptr<std::remove_pointer_t<CGEventRef>, EventReleaser>;

struct ColorSpaceReleaser final {
    void operator()(CGColorSpaceRef value) const noexcept {
        if (value != nullptr) CGColorSpaceRelease(value);
    }
};
using ColorSpaceOwner =
    std::unique_ptr<std::remove_pointer_t<CGColorSpaceRef>, ColorSpaceReleaser>;

struct ContextReleaser final {
    void operator()(CGContextRef value) const noexcept {
        if (value != nullptr) CGContextRelease(value);
    }
};
using ContextOwner =
    std::unique_ptr<std::remove_pointer_t<CGContextRef>, ContextReleaser>;

[[nodiscard]] std::expected<std::size_t, MacCursorSnapshotError>
scaledDimension(const double pointDimension, const double pixelsPerPoint) noexcept {
    if (!std::isfinite(pointDimension) || pointDimension <= 0.0 ||
        !std::isfinite(pixelsPerPoint) || pixelsPerPoint <= 0.0) {
        return std::unexpected(MacCursorSnapshotError::InvalidObservation);
    }
    const double scaled = pointDimension * pixelsPerPoint;
    if (!std::isfinite(scaled) || scaled < 1.0 ||
        scaled > static_cast<double>(kMaximumMacCursorDimension)) {
        return std::unexpected(MacCursorSnapshotError::InvalidObservation);
    }
    const auto rounded = static_cast<std::size_t>(std::lround(scaled));
    if (rounded == 0 || rounded > kMaximumMacCursorDimension) {
        return std::unexpected(MacCursorSnapshotError::InvalidObservation);
    }
    return rounded;
}

[[nodiscard]] std::expected<std::uint32_t, MacCursorSnapshotError>
scaledHotspot(const double hotspotPoints, const double imagePoints,
              const std::size_t imagePixels) noexcept {
    if (!std::isfinite(hotspotPoints) || hotspotPoints < 0.0 ||
        !std::isfinite(imagePoints) || imagePoints <= 0.0 || imagePixels == 0) {
        return std::unexpected(MacCursorSnapshotError::InvalidObservation);
    }
    const double scaled = hotspotPoints *
        (static_cast<double>(imagePixels) / imagePoints);
    if (!std::isfinite(scaled) || scaled < 0.0 ||
        scaled >= static_cast<double>(imagePixels)) {
        return std::unexpected(MacCursorSnapshotError::InvalidObservation);
    }
    return static_cast<std::uint32_t>(std::floor(scaled));
}

} // namespace

namespace {

[[maybe_unused]] std::expected<MacCursorSnapshot, MacCursorSnapshotError>
queryNativeMacCursorSnapshot(const NativeDisplayGeometryRefresh& geometry,
                             const std::uint64_t geometryGeneration) noexcept {
    if (geometryGeneration == 0) {
        return std::unexpected(MacCursorSnapshotError::InvalidGeneration);
    }
    if (geometry.generation() != geometryGeneration) {
        return std::unexpected(MacCursorSnapshotError::StaleGeometryGeneration);
    }
    if (!geometry.topologyRevision(geometryGeneration)) {
        return std::unexpected(MacCursorSnapshotError::StaleTopology);
    }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    const bool visible = CGCursorIsVisible() != 0;
#pragma clang diagnostic pop
    if (!visible) {
        return makeMacCursorSnapshot(
            geometry, geometryGeneration, MacNativeCursorObservation{}, {}, 0);
    }

    EventOwner event(CGEventCreate(nullptr));
    if (!event) {
        return std::unexpected(MacCursorSnapshotError::NativeCursorUnavailable);
    }
    const CGPoint nativePosition = CGEventGetLocation(event.get());
    const DesktopLogicalPoint logicalPosition{
        static_cast<double>(nativePosition.x),
        static_cast<double>(nativePosition.y)};
    const auto pixelPosition =
        geometry.pixelAtLogicalPoint(logicalPosition, geometryGeneration);
    if (!pixelPosition) {
        return std::unexpected(geometry.topologyRevision(geometryGeneration)
                                   ? MacCursorSnapshotError::PositionOutsideDesktop
                                   : MacCursorSnapshotError::StaleTopology);
    }
    const auto display =
        geometry.displayMapping(pixelPosition->displayId, geometryGeneration);
    if (!display) {
        return std::unexpected(MacCursorSnapshotError::StaleTopology);
    }

    const double pixelsPerPointX =
        static_cast<double>(display->physicalPixels.widthPixels) /
        display->logicalPoints.widthPoints;
    const double pixelsPerPointY =
        static_cast<double>(display->physicalPixels.heightPixels) /
        display->logicalPoints.heightPoints;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    NSCursor* const cursor = [NSCursor currentSystemCursor];
#pragma clang diagnostic pop
    if (cursor == nil) {
        return std::unexpected(MacCursorSnapshotError::NativeCursorUnavailable);
    }
    NSImage* const image = cursor.image;
    if (image == nil) {
        return std::unexpected(MacCursorSnapshotError::ImageUnavailable);
    }
    const NSSize pointSize = image.size;
    const auto requestedWidth = scaledDimension(
        static_cast<double>(pointSize.width), pixelsPerPointX);
    const auto requestedHeight = scaledDimension(
        static_cast<double>(pointSize.height), pixelsPerPointY);
    if (!requestedWidth) return std::unexpected(requestedWidth.error());
    if (!requestedHeight) return std::unexpected(requestedHeight.error());

    NSRect proposedRect = NSMakeRect(
        0.0, 0.0, static_cast<CGFloat>(*requestedWidth),
        static_cast<CGFloat>(*requestedHeight));
    CGImageRef const imageReference =
        [image CGImageForProposedRect:&proposedRect context:nil hints:nil];
    if (imageReference == nullptr) {
        return std::unexpected(MacCursorSnapshotError::ImageUnavailable);
    }
    const std::size_t widthPixels = CGImageGetWidth(imageReference);
    const std::size_t heightPixels = CGImageGetHeight(imageReference);
    if (widthPixels == 0 || heightPixels == 0 ||
        widthPixels > kMaximumMacCursorDimension ||
        heightPixels > kMaximumMacCursorDimension) {
        return std::unexpected(MacCursorSnapshotError::InvalidObservation);
    }

    const NSPoint hotspot = cursor.hotSpot;
    const auto hotspotX = scaledHotspot(
        static_cast<double>(hotspot.x), static_cast<double>(pointSize.width),
        widthPixels);
    const auto hotspotY = scaledHotspot(
        static_cast<double>(hotspot.y), static_cast<double>(pointSize.height),
        heightPixels);
    if (!hotspotX) return std::unexpected(hotspotX.error());
    if (!hotspotY) return std::unexpected(hotspotY.error());

    const std::size_t bytesPerRow = widthPixels * 4U;
    const std::size_t byteCount = bytesPerRow * heightPixels;
    std::unique_ptr<std::byte[]> pixels;
    try {
        pixels = std::make_unique_for_overwrite<std::byte[]>(byteCount);
    } catch (const std::bad_alloc&) {
        return std::unexpected(MacCursorSnapshotError::AllocationFailed);
    }

    ColorSpaceOwner colorSpace(CGColorSpaceCreateDeviceRGB());
    if (!colorSpace) {
        return std::unexpected(MacCursorSnapshotError::RenderingFailed);
    }
    constexpr CGBitmapInfo bitmapInfo = static_cast<CGBitmapInfo>(
        static_cast<std::uint32_t>(kCGBitmapByteOrder32Little) |
        static_cast<std::uint32_t>(kCGImageAlphaPremultipliedFirst));
    ContextOwner context(CGBitmapContextCreate(
        pixels.get(), widthPixels, heightPixels, 8, bytesPerRow,
        colorSpace.get(), bitmapInfo));
    if (!context) {
        return std::unexpected(MacCursorSnapshotError::RenderingFailed);
    }

    // CGBitmapContext's first row is y=0. Flip the draw so storage row zero is
    // the cursor's visual top row, matching R7's frame/shape contract.
    CGContextTranslateCTM(context.get(), 0.0, static_cast<CGFloat>(heightPixels));
    CGContextScaleCTM(context.get(), 1.0, -1.0);
    CGContextSetBlendMode(context.get(), kCGBlendModeCopy);
    CGContextDrawImage(
        context.get(),
        CGRectMake(0.0, 0.0, static_cast<CGFloat>(widthPixels),
                   static_cast<CGFloat>(heightPixels)),
        imageReference);

    MacNativeCursorObservation observation{
        true,
        logicalPosition,
        static_cast<std::uint32_t>(widthPixels),
        static_cast<std::uint32_t>(heightPixels),
        *hotspotX,
        *hotspotY,
        bytesPerRow};
    return makeMacCursorSnapshot(
        geometry, geometryGeneration, observation, std::move(pixels), byteCount);
}

} // namespace

} // namespace rdp::macos
