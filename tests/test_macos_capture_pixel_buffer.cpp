// SPDX-License-Identifier: GPL-3.0-or-later
#include "platform/macos/capture_pixel_layout.h"
#include "platform/macos/desktop_display_geometry.h"
#include "platform/macos/native_display_snapshot.h"
#include "platform/macos/screen_capture_preflight.h"

#if defined(__APPLE__)
#include "platform/macos/capture_pixel_buffer.h"
#endif

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cmath>
#include <limits>
#include <string_view>
#include <utility>

namespace {

#if defined(__APPLE__)
void onPixelBufferReleased(void* const context, const void* const base_address) {
    assert(context != nullptr);
    assert(base_address != nullptr);
    ++*static_cast<int*>(context);
}

// Exercise replacement destruction, self-move, and exactly-once release
// without capturing a screen or obtaining TCC authorization.
void testMoveAssignmentReleasesOldBuffer() {
    alignas(64) std::array<std::byte, 32> original_pixels{};
    alignas(64) std::array<std::byte, 32> replacement_pixels{};
    original_pixels[0] = std::byte{0x11};
    replacement_pixels[0] = std::byte{0x22};
    int original_release_count = 0;
    int replacement_release_count = 0;
    CVPixelBufferRef original_buffer = nullptr;
    CVPixelBufferRef replacement_buffer = nullptr;
    assert(CVPixelBufferCreateWithBytes(kCFAllocatorDefault, 2, 2,
        kCVPixelFormatType_32BGRA, original_pixels.data(), 16,
        &onPixelBufferReleased, &original_release_count, nullptr,
        &original_buffer) == kCVReturnSuccess);
    assert(CVPixelBufferCreateWithBytes(kCFAllocatorDefault, 2, 2,
        kCVPixelFormatType_32BGRA, replacement_pixels.data(), 16,
        &onPixelBufferReleased, &replacement_release_count, nullptr,
        &replacement_buffer) == kCVReturnSuccess);
    assert(original_buffer != nullptr && replacement_buffer != nullptr);
    {
        auto original = rdp::macos::LockedBgraPixelBuffer::lock(original_buffer);
        auto replacement = rdp::macos::LockedBgraPixelBuffer::lock(replacement_buffer);
        assert(original && replacement);
        CVPixelBufferRelease(original_buffer);
        CVPixelBufferRelease(replacement_buffer);
        assert(original_release_count == 0 && replacement_release_count == 0);
        *original = std::move(*replacement);
        assert(original_release_count == 1);
        assert(replacement_release_count == 0);
        assert(replacement->pixels().empty());
        assert(original->pixelRow(0).front() == std::byte{0x22});
        auto* const aliased_owner = &*original;
        *original = std::move(*aliased_owner);
        assert(original->pixelRow(0).front() == std::byte{0x22});
    }
    assert(original_release_count == 1);
    assert(replacement_release_count == 1);
}

void testRetainedPaddedBufferLifetime() {
    alignas(64) std::array<std::byte, 32> test_pixels{};
    test_pixels[0] = std::byte{0x4a};
    test_pixels[16] = std::byte{0x7b};
    int released_count = 0;
    CVPixelBufferRef original_buffer = nullptr;
    const auto status = CVPixelBufferCreateWithBytes(
        kCFAllocatorDefault, 3, 2, kCVPixelFormatType_32BGRA,
        test_pixels.data(), 16, &onPixelBufferReleased, &released_count,
        nullptr, &original_buffer);
    assert(status == kCVReturnSuccess);
    assert(original_buffer != nullptr);

    {
        auto result = rdp::macos::LockedBgraPixelBuffer::lock(original_buffer);
        assert(result.has_value());
        assert(result->layout().width_pixels == 3);
        assert(result->layout().height_pixels == 2);
        assert(result->layout().bytes_per_row == 16);
        assert(result->pixels().size() == 32);
        assert(result->pixels().front() == std::byte{0x4a});
        assert(result->pixelRow(0).size() == 12);
        assert(result->pixelRow(0).front() == std::byte{0x4a});
        assert(result->pixelRow(1).size() == 12);
        assert(result->pixelRow(1).front() == std::byte{0x7b});
        assert(result->pixelRow(2).empty());
        assert(result->pixelRow(std::numeric_limits<std::size_t>::max()).empty());
        CVPixelBufferRelease(original_buffer);
        assert(released_count == 0); // Locked view retained the original.

        auto moved = std::move(*result);
        assert(result->pixels().empty());
        assert(result->pixelRow(0).empty());
        assert(moved.pixels().size() == 32);
        auto again = std::move(moved);
        assert(moved.pixels().empty());
        assert(again.pixels().size() == 32);
        assert(again.pixelRow(1).front() == std::byte{0x7b});
    }
    assert(released_count == 1);
}

#endif

// Pure R7 geometry fixtures: all coordinates are pre-normalized to one
// top-left logical desktop, without CoreGraphics, permissions, or native input.
void testRetinaPointToPhysicalPixel() {
    using namespace rdp::macos;
    constexpr DesktopDisplayMapping retina{
        101, {0.0, 0.0, 1512.0, 982.0}, {0, 0, 3024, 1964}};
    const auto geometry = DesktopDisplayGeometry::create(
        std::array{retina}, 7);
    assert(geometry && geometry->displayCount() == 1);
    assert((geometry->virtualPixelSize() == PixelSize{3024, 1964}));
    assert(geometry->physicalOriginX() == 0);
    const auto origin = geometry->pixelAtLogicalPoint({0.0, 0.0}, 7);
    assert(origin && origin->absoluteX == 0 && origin->absoluteY == 0);
    assert(origin->virtualX == 0 && origin->virtualY == 0);
    const auto fractional = geometry->pixelAtLogicalPoint({0.5, 0.5}, 7);
    assert(fractional && fractional->absoluteX == 1 && fractional->absoluteY == 1);
    const auto final_pixel = geometry->pixelAtLogicalPoint({1511.999, 981.999}, 7);
    assert(final_pixel && final_pixel->absoluteX == 3023 &&
           final_pixel->absoluteY == 1963);
    assert(!geometry->pixelAtLogicalPoint({1512.0, 0.0}, 7));
    assert(!geometry->pixelAtLogicalPoint({0.0, 982.0}, 7));
    assert(!geometry->pixelAtLogicalPoint({-0.01, 0.0}, 7));
    const auto sample = geometry->logicalAtPhysicalPixel(3023, 1963, 7);
    assert(sample && sample->displayId == 101);
    assert(sample->point.xPoints > 1511.0 && sample->point.xPoints < 1512.0);
    const auto recovered = geometry->pixelAtLogicalPoint(sample->point, 7);
    assert(recovered && recovered->absoluteX == 3023 &&
           recovered->absoluteY == 1963);

    // The same production transform supports nonintegral 1.5x Retina scale.
    constexpr DesktopDisplayMapping one_and_half{
        102, {0.0, 0.0, 1280.0, 800.0}, {0, 0, 1920, 1200}};
    const auto fractional_scale = DesktopDisplayGeometry::create(
        std::array{one_and_half}, 8);
    assert(fractional_scale);
    const auto first = fractional_scale->pixelAtLogicalPoint({1.0, 1.0}, 8);
    assert(first && first->absoluteX == 1 && first->absoluteY == 1);
    const auto second = fractional_scale->pixelAtLogicalPoint({2.0, 2.0}, 8);
    assert(second && second->absoluteX == 3 && second->absoluteY == 3);

    // Exhaustive small integer scale matrix catches half-pixel rounding
    // mistakes and validates pixel-center reverse mapping at every X pixel.
    for (std::uint32_t logicalWidth = 1; logicalWidth <= 33; ++logicalWidth) {
        for (std::uint32_t physicalWidth = 1; physicalWidth <= 37; ++physicalWidth) {
            const DesktopDisplayMapping fixture{
                99, {0.0, 0.0, static_cast<double>(logicalWidth), 1.0},
                {0, 0, physicalWidth, 1}};
            const auto layout = DesktopDisplayGeometry::create(std::array{fixture}, 9);
            assert(layout);
            for (std::uint32_t pixel = 0; pixel < physicalWidth; ++pixel) {
                const auto point = layout->logicalAtPhysicalPixel(
                    static_cast<std::int32_t>(pixel), 0, 9);
                assert(point && point->point.xPoints >= 0.0 &&
                       point->point.xPoints < logicalWidth);
                const auto converted = layout->pixelAtLogicalPoint(point->point, 9);
                assert(converted && converted->virtualX == pixel);
            }
        }
    }
}

void testMultiDisplayBoundsAndDenials() {
    using namespace rdp::macos;
    constexpr DesktopDisplayMapping primary{
        100, {0.0, 0.0, 1512.0, 982.0}, {0, 0, 3024, 1964}};
    constexpr DesktopDisplayMapping left{
        200, {-1920.0, -100.0, 1920.0, 1080.0}, {-1920, -100, 1920, 1080}};
    const std::array displays{primary, left};
    const auto geometry = DesktopDisplayGeometry::create(displays, 42);
    assert(geometry && geometry->displayCount() == 2);
    assert((geometry->virtualPixelSize() == PixelSize{4944, 2064}));
    assert(geometry->physicalOriginX() == -1920 && geometry->physicalOriginY() == -100);
    const auto primary_origin = geometry->pixelAtLogicalPoint({0.0, 0.0}, 42);
    assert(primary_origin && primary_origin->displayId == 100 &&
           primary_origin->virtualX == 1920 && primary_origin->virtualY == 100);
    const auto secondary_origin = geometry->pixelAtLogicalPoint({-1920.0, -100.0}, 42);
    assert(secondary_origin && secondary_origin->displayId == 200 &&
           secondary_origin->absoluteX == -1920 && secondary_origin->virtualX == 0);
    const auto physical_corner = geometry->logicalAtPhysicalPixel(-1920, -100, 42);
    assert(physical_corner && physical_corner->displayId == 200 &&
           physical_corner->point.xPoints > -1920.0 &&
           physical_corner->point.xPoints < -1919.0);
    assert(!geometry->pixelAtLogicalPoint({-0.5, 990.0}, 42)); // gap
    assert(!geometry->logicalAtPhysicalPixel(-1, 1500, 42)); // pixel gap
    assert(!geometry->pixelAtLogicalPoint({std::numeric_limits<double>::quiet_NaN(), 0.0}, 42));
    assert(!geometry->pixelAtLogicalPoint({std::numeric_limits<double>::infinity(), 0.0}, 42));

    assert(!DesktopDisplayGeometry::create({}, 42));
    assert(!DesktopDisplayGeometry::create(displays, 0));
    constexpr DesktopDisplayMapping missing_id{
        0, {0.0, 0.0, 1.0, 1.0}, {0, 0, 1, 1}};
    assert(!DesktopDisplayGeometry::create(std::array{missing_id}, 1));
    constexpr DesktopDisplayMapping zero_physical{
        300, {10.0, 0.0, 1.0, 1.0}, {5000, 0, 0, 1}};
    assert(!DesktopDisplayGeometry::create(std::array{zero_physical}, 1));
    const DesktopDisplayMapping nonfinite{
        300, {0.0, 0.0, std::numeric_limits<double>::infinity(), 1.0}, {4000, 0, 5, 5}};
    assert(!DesktopDisplayGeometry::create(std::array{nonfinite}, 1));
    const DesktopDisplayMapping precision_loss{
        300, {1e300, 0.0, 1.0, 1.0}, {4000, 0, 5, 5}};
    assert(!DesktopDisplayGeometry::create(std::array{precision_loss}, 1));
    constexpr DesktopDisplayMapping duplicate_id{
        100, {4000.0, 0.0, 1.0, 1.0}, {4000, 0, 5, 5}};
    assert(!DesktopDisplayGeometry::create(std::array{primary, duplicate_id}, 1));
    constexpr DesktopDisplayMapping logical_overlap{
        300, {1511.0, 100.0, 20.0, 20.0}, {4000, 0, 20, 20}};
    assert(!DesktopDisplayGeometry::create(std::array{primary, logical_overlap}, 1));
    constexpr DesktopDisplayMapping physical_overlap{
        300, {4000.0, 0.0, 1.0, 1.0}, {3023, 100, 20, 20}};
    assert(!DesktopDisplayGeometry::create(std::array{primary, physical_overlap}, 1));
    constexpr DesktopDisplayMapping physical_overflow{
        300, {4000.0, 0.0, 1.0, 1.0},
        {std::numeric_limits<std::int32_t>::max(), 0, 2, 1}};
    assert(!DesktopDisplayGeometry::create(std::array{physical_overflow}, 1));
    constexpr DesktopDisplayMapping virtual_overflow_left{
        301, {-10.0, 0.0, 1.0, 1.0},
        {std::numeric_limits<std::int32_t>::min(), 0, 1, 1}};
    constexpr DesktopDisplayMapping virtual_overflow_right{
        302, {10.0, 0.0, 1.0, 1.0},
        {std::numeric_limits<std::int32_t>::max(), 0, 1, 1}};
    assert(!DesktopDisplayGeometry::create(
        std::array{virtual_overflow_left, virtual_overflow_right}, 1));
    std::array<DesktopDisplayMapping, DesktopDisplayGeometry::kMaximumDisplays + 1> too_many{};
    assert(!DesktopDisplayGeometry::create(too_many, 1));

    // Adjacent logical/physical bounds share a seam without overlapping.
    constexpr DesktopDisplayMapping adjacent{
        300, {1512.0, 0.0, 200.0, 200.0}, {3024, 0, 200, 200}};
    const auto adjoining = DesktopDisplayGeometry::create(std::array{primary, adjacent}, 1);
    assert(adjoining);
    const auto seam = adjoining->pixelAtLogicalPoint({1512.0, 0.0}, 1);
    assert(seam && seam->displayId == 300 && seam->virtualX == 3024);
}

void testDisplayReconfigurationRejectsStaleEvents() {
    using namespace rdp::macos;
    constexpr DesktopDisplayMapping old_scale{
        1, {0.0, 0.0, 100.0, 100.0}, {0, 0, 100, 100}};
    constexpr DesktopDisplayMapping new_scale{
        1, {0.0, 0.0, 100.0, 100.0}, {0, 0, 200, 200}};
    const auto before = DesktopDisplayGeometry::create(std::array{old_scale}, 50);
    const auto after = DesktopDisplayGeometry::create(std::array{new_scale}, 51);
    assert(before && after);
    assert(before->pixelAtLogicalPoint({25.0, 25.0}, 50)->virtualX == 25);
    assert(after->pixelAtLogicalPoint({25.0, 25.0}, 51)->virtualX == 50);
    assert(!after->pixelAtLogicalPoint({25.0, 25.0}, 50));
    assert(!after->logicalAtPhysicalPixel(25, 25, 50));
    assert(!before->pixelAtLogicalPoint({25.0, 25.0}, 51));
    assert(!after->pixelAtLogicalPoint({100.0, 50.0}, 51));
    assert(!after->logicalAtPhysicalPixel(200, 1, 51));
    assert(!after->logicalAtPhysicalPixel(-1, 1, 51));
}

void testVirtualDesktopPointerCoordinates() {
    using namespace rdp::macos;
    constexpr DesktopDisplayMapping primary{
        100, {0.0, 0.0, 1512.0, 982.0}, {0, 0, 3024, 1964}};
    constexpr DesktopDisplayMapping left{
        200, {-1920.0, -100.0, 1920.0, 1080.0}, {-1920, -100, 1920, 1080}};
    const auto geometry = DesktopDisplayGeometry::create(
        std::array{primary, left}, 91);
    assert(geometry);
    assert((geometry->virtualPixelSize() == PixelSize{4944, 2064}));

    const auto secondaryOrigin = geometry->logicalAtVirtualPixel(0, 0, 91);
    assert(secondaryOrigin && secondaryOrigin->displayId == 200);
    assert(secondaryOrigin->point.xPoints == -1919.5);
    assert(secondaryOrigin->point.yPoints == -99.5);

    const auto primaryOrigin = geometry->logicalAtVirtualPixel(1920, 100, 91);
    assert(primaryOrigin && primaryOrigin->displayId == 100);
    assert(primaryOrigin->point.xPoints == 0.25);
    assert(primaryOrigin->point.yPoints == 0.25);
    const auto normalizedAgain = geometry->pixelAtLogicalPoint(primaryOrigin->point, 91);
    assert(normalizedAgain && normalizedAgain->virtualX == 1920 &&
           normalizedAgain->virtualY == 100);

    const auto lastPixel = geometry->logicalAtVirtualPixel(4943, 2063, 91);
    assert(lastPixel && lastPixel->displayId == 100);
    assert(lastPixel->point.xPoints == 1511.75);
    assert(lastPixel->point.yPoints == 981.75);
    assert(!geometry->logicalAtVirtualPixel(1919, 1600, 91)); // monitor gap
    assert(!geometry->logicalAtVirtualPixel(0, 1080, 91)); // outside left monitor
    assert(!geometry->logicalAtVirtualPixel(4944, 100, 91)); // exclusive canvas edge
    assert(!geometry->logicalAtVirtualPixel(2000, 2064, 91));
    assert(!geometry->logicalAtVirtualPixel(1920, 100, 90)); // stale display generation
    assert(!geometry->logicalAtVirtualPixel(1920, 100, 0));

    // The widest legal virtual canvas may span almost all of uint32_t.
    // Crossing a gap near INT32_MAX must fail before narrowing a 64-bit sum.
    constexpr DesktopDisplayMapping minimumDisplay{
        1, {-1000.0, 0.0, 1.0, 1.0},
        {std::numeric_limits<std::int32_t>::min(), 0, 1, 1}};
    constexpr DesktopDisplayMapping maximumDisplay{
        2, {1000.0, 0.0, 1.0, 1.0},
        {std::numeric_limits<std::int32_t>::max() - 1, 0, 1, 1}};
    const auto wide = DesktopDisplayGeometry::create(
        std::array{minimumDisplay, maximumDisplay}, 92);
    assert(wide);
    assert(wide->virtualPixelSize().widthPixels ==
           std::numeric_limits<std::uint32_t>::max());
    const auto first = wide->logicalAtVirtualPixel(0, 0, 92);
    assert(first && first->displayId == 1);
    const auto last = wide->logicalAtVirtualPixel(
        std::numeric_limits<std::uint32_t>::max() - 1, 0, 92);
    assert(last && last->displayId == 2);
    assert(!wide->logicalAtVirtualPixel(
        std::numeric_limits<std::uint32_t>::max(), 0, 92));
    assert(!wide->logicalAtVirtualPixel(
        std::numeric_limits<std::uint32_t>::max() - 2, 0, 92));
}

// Fake TCC evidence only; no CGPreflightScreenCaptureAccess invocation.
[[nodiscard]] bool fakeScreenCapturePreflight(void* const context) noexcept {
    return *static_cast<const bool*>(context);
}

void testScreenCapturePermissionPreflightRevocation() {
    using namespace rdp::macos;
    bool permission_is_granted = false;
    assert(evaluateScreenCapturePreflight(nullptr, &permission_is_granted) ==
           ScreenCapturePreflightStatus::Unavailable);
    assert(evaluateScreenCapturePreflight(&fakeScreenCapturePreflight,
                                           &permission_is_granted) ==
           ScreenCapturePreflightStatus::NotGranted);
    permission_is_granted = true;
    assert(evaluateScreenCapturePreflight(&fakeScreenCapturePreflight,
                                           &permission_is_granted) ==
           ScreenCapturePreflightStatus::Granted);
    // Revocation must be observed immediately rather than using a cached grant.
    permission_is_granted = false;
    assert(evaluateScreenCapturePreflight(&fakeScreenCapturePreflight,
                                           &permission_is_granted) ==
           ScreenCapturePreflightStatus::NotGranted);
    permission_is_granted = true;
    assert(evaluateScreenCapturePreflight(&fakeScreenCapturePreflight,
                                           &permission_is_granted) ==
           ScreenCapturePreflightStatus::Granted);
}

void testLayoutBounds() {
    using rdp::macos::validateBgraPixelLayout;
    constexpr std::size_t huge = std::numeric_limits<std::size_t>::max();
    assert(!validateBgraPixelLayout(0, 1, 4, 4));
    assert(!validateBgraPixelLayout(1, 0, 4, 4));
    assert(!validateBgraPixelLayout(3, 2, 11, 32));
    assert(!validateBgraPixelLayout(3, 2, 16, 31));
    assert(!validateBgraPixelLayout(huge, 2, huge, huge));
    assert(!validateBgraPixelLayout(1, huge, huge, huge));
    assert(!validateBgraPixelLayout(32769, 1, 131076, 131076));
    assert(!validateBgraPixelLayout(32768, 32768, 131072, huge));
    assert(!validateBgraPixelLayout(1, 2, huge, huge));
    const auto padded = validateBgraPixelLayout(3, 2, 16, 4096);
    assert(padded && padded->byte_count == 32);
    assert(padded->width_pixels == 3);
    constexpr std::size_t maximum_frame_bytes = 512U * 1024U * 1024U;
    const auto maximum_frame = validateBgraPixelLayout(
        8192, 16384, 32768, maximum_frame_bytes);
    assert(maximum_frame && maximum_frame->byte_count == maximum_frame_bytes);
    assert(!validateBgraPixelLayout(8192, 16384, 32769, maximum_frame_bytes));
}

#if defined(__APPLE__)
void testNativeDenials() {
    const auto null_buffer = rdp::macos::LockedBgraPixelBuffer::lock(nullptr);
    assert(!null_buffer);
    assert(null_buffer.error() == rdp::macos::BgraBufferError::missing_buffer);

    alignas(64) std::array<std::byte, 32> test_pixels{};
    CVPixelBufferRef unsupported_buffer = nullptr;
    const auto status = CVPixelBufferCreateWithBytes(
        kCFAllocatorDefault, 2, 2, kCVPixelFormatType_32ARGB,
        test_pixels.data(), 16, nullptr, nullptr, nullptr, &unsupported_buffer);
    assert(status == kCVReturnSuccess);
    assert(unsupported_buffer != nullptr);
    const auto unsupported = rdp::macos::LockedBgraPixelBuffer::lock(unsupported_buffer);
    assert(!unsupported);
    assert(unsupported.error() == rdp::macos::BgraBufferError::unsupported_format);
    CVPixelBufferRelease(unsupported_buffer);
}
#endif


using rdp::macos::NativeDisplayObservation;
using rdp::macos::NativeDisplaySnapshot;
using rdp::macos::NativeDisplaySnapshotError;
using rdp::macos::NativeDisplayReadStatus;

constexpr NativeDisplayObservation kNativePrimary{
    100, 0, 0, 1512, 982, 3024, 1964, 0};
constexpr NativeDisplayObservation kNativeLeft{
    200, -1920, -100, 1920, 1080, 1920, 1080, 0};

struct NativeDisplayFixture {
    std::array<NativeDisplayObservation, 17> first{};
    std::array<NativeDisplayObservation, 17> second{};
    std::size_t firstCount{1};
    std::size_t secondCount{1};
    std::size_t calls{};
    std::size_t failingCall{};
};

[[nodiscard]] NativeDisplayReadStatus readSyntheticNativeDisplays(
    void* const context, std::span<NativeDisplayObservation> destination,
    std::size_t& count) noexcept {
    auto& fixture = *static_cast<NativeDisplayFixture*>(context);
    ++fixture.calls;
    if (fixture.calls == fixture.failingCall) {
        return NativeDisplayReadStatus::Unavailable;
    }
    count = fixture.calls == 1 ? fixture.firstCount : fixture.secondCount;
    const auto& sample = fixture.calls == 1 ? fixture.first : fixture.second;
    for (std::size_t index = 0;
         index < (std::min)(count, destination.size()); ++index) {
        destination[index] = sample[index];
    }
    return NativeDisplayReadStatus::Ok;
}

[[nodiscard]] NativeDisplayFixture nativeDisplayFixture() noexcept {
    NativeDisplayFixture fixture;
    fixture.first[0] = kNativePrimary;
    fixture.second[0] = kNativePrimary;
    return fixture;
}

void testNativeDisplayStableMultiRetina() {
    auto fixture = nativeDisplayFixture();
    fixture.firstCount = fixture.secondCount = 2;
    fixture.first[0] = kNativeLeft;
    fixture.first[1] = kNativePrimary;
    fixture.second[0] = kNativePrimary; // Reordered enumeration is stable.
    fixture.second[1] = kNativeLeft;
    const auto observed = NativeDisplaySnapshot::read(
        &readSyntheticNativeDisplays, &fixture, 9);
    assert(observed && fixture.calls == 2 && observed->generation() == 9);
    assert(observed->displays().size() == 2);
    assert(observed->displays()[0] == kNativePrimary);
    assert(observed->displays()[1] == kNativeLeft);
    assert(observed->displays()[0].backingWidthPixels == 3024);
    assert(observed->displays()[0].widthPoints == 1512);
}

void testNativeDisplaySnapshotDenials() {
    auto fixture = nativeDisplayFixture();
    assert(NativeDisplaySnapshot::read(nullptr, nullptr, 1).error() ==
           NativeDisplaySnapshotError::Unavailable);
    assert(NativeDisplaySnapshot::read(
        &readSyntheticNativeDisplays, &fixture, 0).error() ==
           NativeDisplaySnapshotError::InvalidGeneration);
    assert(fixture.calls == 0);
    fixture.firstCount = 0;
    assert(NativeDisplaySnapshot::read(
        &readSyntheticNativeDisplays, &fixture, 1).error() ==
           NativeDisplaySnapshotError::Unavailable);
    fixture = nativeDisplayFixture();
    fixture.firstCount = 17;
    assert(NativeDisplaySnapshot::read(
        &readSyntheticNativeDisplays, &fixture, 1).error() ==
           NativeDisplaySnapshotError::TooManyDisplays);
    fixture = nativeDisplayFixture();
    fixture.first[0].widthPoints = std::numeric_limits<double>::infinity();
    assert(NativeDisplaySnapshot::read(
        &readSyntheticNativeDisplays, &fixture, 1).error() ==
           NativeDisplaySnapshotError::InvalidGeometry);
    fixture = nativeDisplayFixture();
    fixture.first[0].backingHeightPixels = 0;
    assert(NativeDisplaySnapshot::read(
        &readSyntheticNativeDisplays, &fixture, 1).error() ==
           NativeDisplaySnapshotError::InvalidGeometry);
    fixture = nativeDisplayFixture();
    fixture.first[0].mirrorsDisplayId = 100;
    assert(NativeDisplaySnapshot::read(
        &readSyntheticNativeDisplays, &fixture, 1).error() ==
           NativeDisplaySnapshotError::InvalidGeometry);
    fixture = nativeDisplayFixture();
    fixture.firstCount = 2;
    fixture.first[1] = fixture.first[0];
    assert(NativeDisplaySnapshot::read(
        &readSyntheticNativeDisplays, &fixture, 1).error() ==
           NativeDisplaySnapshotError::InvalidGeometry);
    fixture = nativeDisplayFixture();
    fixture.first[0].backingWidthPixels = 32769;
    assert(NativeDisplaySnapshot::read(
        &readSyntheticNativeDisplays, &fixture, 1).error() ==
           NativeDisplaySnapshotError::InvalidGeometry);
    fixture = nativeDisplayFixture();
    fixture.first[0].widthPoints = 1e308;
    fixture.first[0].xPoints = 1e308; // Positive extent overflows.
    assert(NativeDisplaySnapshot::read(
        &readSyntheticNativeDisplays, &fixture, 1).error() ==
           NativeDisplaySnapshotError::InvalidGeometry);
    fixture = nativeDisplayFixture();
    fixture.first[0].widthPoints = 1;
    fixture.first[0].xPoints = 1e300; // Positive extent loses precision.
    assert(NativeDisplaySnapshot::read(
        &readSyntheticNativeDisplays, &fixture, 1).error() ==
           NativeDisplaySnapshotError::InvalidGeometry);
    fixture = nativeDisplayFixture();
    fixture.failingCall = 1;
    assert(NativeDisplaySnapshot::read(
        &readSyntheticNativeDisplays, &fixture, 1).error() ==
           NativeDisplaySnapshotError::Unavailable);
}

void testNativeDisplayChangedDuringRead() {
    auto fixture = nativeDisplayFixture();
    fixture.second[0].backingWidthPixels = 2880;
    assert(NativeDisplaySnapshot::read(
        &readSyntheticNativeDisplays, &fixture, 7).error() ==
           NativeDisplaySnapshotError::ChangedDuringRead);
    assert(fixture.calls == 2);
    fixture = nativeDisplayFixture();
    fixture.second[0].xPoints = 1;
    assert(NativeDisplaySnapshot::read(
        &readSyntheticNativeDisplays, &fixture, 7).error() ==
           NativeDisplaySnapshotError::ChangedDuringRead);
    fixture = nativeDisplayFixture();
    fixture.secondCount = 0;
    assert(NativeDisplaySnapshot::read(
        &readSyntheticNativeDisplays, &fixture, 7).error() ==
           NativeDisplaySnapshotError::Unavailable);
    fixture = nativeDisplayFixture();
    fixture.failingCall = 2;
    assert(NativeDisplaySnapshot::read(
        &readSyntheticNativeDisplays, &fixture, 7).error() ==
           NativeDisplaySnapshotError::Unavailable);
}

} // namespace

int main(const int argument_count, const char* const arguments[]) {
    if (argument_count != 2) {
        return 2;
    }
    const std::string_view test_case = arguments[1];
    if (test_case == "layout") {
        testLayoutBounds();
    } else if (test_case == "retina-points") {
        testRetinaPointToPhysicalPixel();
    } else if (test_case == "multi-display-invalid") {
        testMultiDisplayBoundsAndDenials();
    } else if (test_case == "reconfiguration") {
        testDisplayReconfigurationRejectsStaleEvents();
    } else if (test_case == "virtual-input-coordinates") {
        testVirtualDesktopPointerCoordinates();
    } else if (test_case == "permission-preflight") {
        testScreenCapturePermissionPreflightRevocation();
    } else if (test_case == "display-snapshot-stable-multi-retina") {
        testNativeDisplayStableMultiRetina();
    } else if (test_case == "display-snapshot-geometry-denials") {
        testNativeDisplaySnapshotDenials();
    } else if (test_case == "display-snapshot-changed-during-read") {
        testNativeDisplayChangedDuringRead();
#if defined(__APPLE__)
    } else if (test_case == "ownership") {
        testRetainedPaddedBufferLifetime();
    } else if (test_case == "native-denials") {
        testNativeDenials();
    } else if (test_case == "native-move-replacement") {
        testMoveAssignmentReleasesOldBuffer();
#endif
    } else {
        return 2;
    }
    return 0;
}
