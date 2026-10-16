// SPDX-License-Identifier: GPL-3.0-or-later
#include "platform/macos/capture_pixel_layout.h"
#include "platform/macos/desktop_display_geometry.h"
#include "platform/macos/native_display_snapshot.h"
#include "platform/macos/native_display_refresh.h"
#include "platform/macos/native_display_reconfiguration.h"
#include "platform/macos/native_display_geometry.h"
#include "platform/macos/mac_cursor_snapshot.h"
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
#include <memory>
#include <string_view>
#include <type_traits>
#include <utility>

namespace {

template <typename Geometry>
concept ExposesNativeCursorSampler =
    requires(const Geometry& geometry) {
        queryNativeMacCursorSnapshot(geometry, std::uint64_t{1});
    };

static_assert(
    !ExposesNativeCursorSampler<rdp::macos::NativeDisplayGeometryRefresh>,
    "native AppKit cursor sampler must remain authorization-quarantined");

// A geometry epoch is singular within its native caller context.
static_assert(!std::is_copy_constructible_v<rdp::macos::NativeDisplayGeometryRefresh>);
static_assert(!std::is_move_constructible_v<rdp::macos::NativeDisplayGeometryRefresh>);

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


// Conversion tests exercise the SAME production native -> portable geometry
// boundary used by queryNativeDesktopGeometry; the provider is synthetic,
// without CoreGraphics enumeration, desktop capture, TCC or input injection.
[[nodiscard]] rdp::macos::NativeDisplaySnapshot nativeGeometrySnapshot(
    NativeDisplayFixture& fixture, const std::uint64_t generation) {
    const auto read = NativeDisplaySnapshot::read(
        &readSyntheticNativeDisplays, &fixture, generation);
    assert(read);
    return *read;
}

void testNativeGeometrySingleRetina() {
    using namespace rdp::macos;
    auto fixture = nativeDisplayFixture();
    auto geometry = makeDesktopGeometry(nativeGeometrySnapshot(fixture, 15));
    assert(geometry && geometry->generation() == 15);
    assert((geometry->virtualPixelSize() == PixelSize{3024, 1964}));
    const auto origin = geometry->pixelAtLogicalPoint({0.0, 0.0}, 15);
    assert(origin && origin->displayId == 100 && origin->virtualX == 0);
    assert(!geometry->logicalAtVirtualPixel(0, 0, 16));
    fixture = nativeDisplayFixture();
    fixture.first[0].xPoints = -100.0;
    fixture.second[0].xPoints = -100.0;
    fixture.first[0].yPoints = 200.0;
    fixture.second[0].yPoints = 200.0;
    geometry = makeDesktopGeometry(nativeGeometrySnapshot(fixture, 16));
    assert(geometry);
    const auto native = geometry->logicalAtVirtualPixel(0, 0, 16);
    assert(native && native->displayId == 100);
    assert(native->point.xPoints > -100.0 && native->point.xPoints < -99.0);
}

void testNativeGeometryUniformMultiDisplay() {
    using namespace rdp::macos;
    auto fixture = nativeDisplayFixture();
    constexpr NativeDisplayObservation one{
        101, 0, 0, 1280, 800, 1920, 1200, 0};
    constexpr NativeDisplayObservation upperLeft{
        203, -960, -600, 960, 600, 1440, 900, 0};
    fixture.firstCount = fixture.secondCount = 2;
    fixture.first[0] = one;
    fixture.first[1] = upperLeft;
    fixture.second[0] = upperLeft; // reordered sample, stable IDs
    fixture.second[1] = one;
    const auto geometry = makeDesktopGeometry(nativeGeometrySnapshot(fixture, 17));
    assert(geometry);
    assert((geometry->virtualPixelSize() == PixelSize{3360, 2100}));
    const auto upper = geometry->pixelAtLogicalPoint({-960, -600}, 17);
    assert(upper && upper->displayId == 203 &&
           upper->virtualX == 0 && upper->virtualY == 0);
    const auto primary = geometry->pixelAtLogicalPoint({0, 0}, 17);
    assert(primary && primary->displayId == 101 &&
           primary->virtualX == 1440 && primary->virtualY == 900);
    assert(!geometry->logicalAtVirtualPixel(1440, 0, 17)); // monitor gap
    assert(!geometry->logicalAtVirtualPixel(0, 901, 17)); // monitor gap
    const auto native = geometry->logicalAtVirtualPixel(1440, 900, 17);
    assert(native && native->displayId == 101);
    const auto roundtrip = geometry->pixelAtLogicalPoint(native->point, 17);
    assert(roundtrip && roundtrip->virtualX == 1440 &&
           roundtrip->virtualY == 900);
}

void testNativeGeometryFailClosed() {
    using namespace rdp::macos;
    auto fixture = nativeDisplayFixture();
    fixture.firstCount = fixture.secondCount = 2;
    fixture.first[1] = fixture.second[1] = kNativeLeft;
    auto geometry = makeDesktopGeometry(nativeGeometrySnapshot(fixture, 30));
    assert(!geometry &&
           geometry.error() == NativeDisplayGeometryError::UnsupportedMixedScale);
    fixture = nativeDisplayFixture();
    fixture.firstCount = fixture.secondCount = 2;
    fixture.first[0] = fixture.second[0] =
        NativeDisplayObservation{101, 0, 0, 1280, 800, 1920, 1200, 0};
    fixture.first[1] = fixture.second[1] =
        NativeDisplayObservation{203, -960.25, -600, 960, 600, 1440, 900, 0};
    geometry = makeDesktopGeometry(nativeGeometrySnapshot(fixture, 30));
    assert(!geometry &&
           geometry.error() == NativeDisplayGeometryError::UnrepresentablePlacement);
    fixture = nativeDisplayFixture();
    fixture.first[0].rotationDegrees = fixture.second[0].rotationDegrees = 90;
    geometry = makeDesktopGeometry(nativeGeometrySnapshot(fixture, 30));
    assert(!geometry &&
           geometry.error() == NativeDisplayGeometryError::UnsupportedRotation);
    fixture = nativeDisplayFixture();
    fixture.first[0].backingWidthPixels =
        fixture.second[0].backingWidthPixels = 3000;
    geometry = makeDesktopGeometry(nativeGeometrySnapshot(fixture, 30));
    assert(!geometry &&
           geometry.error() == NativeDisplayGeometryError::UnsupportedMixedScale);
    fixture = nativeDisplayFixture();
    fixture.first[0].rotationDegrees = fixture.second[0].rotationDegrees =
        std::numeric_limits<double>::infinity();
    assert(!NativeDisplaySnapshot::read(
        &readSyntheticNativeDisplays, &fixture, 30));
}

void testNativeGeometryGenerationRefresh() {
    using namespace rdp::macos;
    auto fixture = nativeDisplayFixture();
    const auto before = makeDesktopGeometry(nativeGeometrySnapshot(fixture, 90));
    assert(before);
    fixture.first[0].backingWidthPixels =
        fixture.second[0].backingWidthPixels = 2268;
    fixture.first[0].backingHeightPixels =
        fixture.second[0].backingHeightPixels = 1473;
    // Change the backing scale from 2x to 1.5x, preserving logical bounds.
    fixture.first[0].widthPoints = fixture.second[0].widthPoints = 1512;
    fixture.first[0].heightPoints = fixture.second[0].heightPoints = 982;
    const auto after = makeDesktopGeometry(nativeGeometrySnapshot(fixture, 91));
    assert(after);
    assert(before->pixelAtLogicalPoint({10, 10}, 90)->virtualX == 20);
    assert(after->pixelAtLogicalPoint({10, 10}, 91)->virtualX == 15);
    assert(!before->pixelAtLogicalPoint({10, 10}, 91));
    assert(!after->logicalAtVirtualPixel(20, 20, 90));
}

void testNativeDisplayRefreshEpoch() {
    using namespace rdp::macos;
    auto fixture = nativeDisplayFixture();
    NativeDisplayGeometryRefresh tracker;
    assert(tracker.generation() == 0 && !tracker.usable(0));
    const auto first = tracker.refresh(&readSyntheticNativeDisplays, &fixture);
    assert(first && *first == 1 && fixture.calls == 2);
    const auto initial = tracker.pixelAtLogicalPoint({10, 10}, *first);
    assert(initial && initial->virtualX == 20);
    assert(tracker.virtualPixelSize(*first)->widthPixels == 3024);
    fixture.first[0].backingWidthPixels =
        fixture.second[0].backingWidthPixels = 2268;
    fixture.first[0].backingHeightPixels =
        fixture.second[0].backingHeightPixels = 1473;
    const auto updated = tracker.refresh(&readSyntheticNativeDisplays, &fixture);
    assert(updated && *updated == 2 && fixture.calls == 4);
    assert(!tracker.usable(*first));
    assert(!tracker.pixelAtLogicalPoint({10, 10}, *first));
    assert(!tracker.logicalAtVirtualPixel(20, 20, *first));
    const auto transformed = tracker.pixelAtLogicalPoint({10, 10}, *updated);
    assert(transformed && transformed->virtualX == 15);
    assert(tracker.logicalAtVirtualPixel(15, 15, *updated));
}

void testNativeDisplayTopologyInvalidation() {
    using namespace rdp::macos;
    auto fixture = nativeDisplayFixture();
    NativeDisplayGeometryRefresh tracker;
    const auto oldEpoch = tracker.refresh(&readSyntheticNativeDisplays, &fixture);
    assert(oldEpoch && tracker.usable(*oldEpoch));
    tracker.invalidate(); // A future CG display-change observer will call this.
    assert(tracker.generation() == 2);
    assert(!tracker.usable(*oldEpoch) && !tracker.usable(2));
    assert(!tracker.pixelAtLogicalPoint({0, 0}, *oldEpoch));
    assert(!tracker.logicalAtVirtualPixel(0, 0, *oldEpoch));
    assert(!tracker.virtualPixelSize(*oldEpoch));
    fixture = nativeDisplayFixture();
    const auto newEpoch = tracker.refresh(&readSyntheticNativeDisplays, &fixture);
    assert(newEpoch && *newEpoch == 3 && tracker.usable(*newEpoch));
    assert(!tracker.usable(1) && !tracker.usable(2));
    const auto p = tracker.pixelAtLogicalPoint({0, 0}, *newEpoch);
    assert(p && p->displayId == 100 && p->virtualX == 0);
}

void testNativeDisplayFailedRefreshClearsGeometry() {
    using namespace rdp::macos;
    auto fixture = nativeDisplayFixture();
    NativeDisplayGeometryRefresh tracker;
    const auto first = tracker.refresh(&readSyntheticNativeDisplays, &fixture);
    assert(first && *first == 1);
    fixture.failingCall = 4; // second sample of the next refresh.
    const auto unavailable = tracker.refresh(&readSyntheticNativeDisplays, &fixture);
    assert(!unavailable &&
           unavailable.error() == NativeDisplayRefreshError::DisplayUnavailable);
    assert(tracker.generation() == 2 && !tracker.usable(1) && !tracker.usable(2));
    assert(!tracker.logicalAtVirtualPixel(0, 0, 1));
    fixture = nativeDisplayFixture();
    fixture.firstCount = fixture.secondCount = 2;
    fixture.first[1] = fixture.second[1] = kNativeLeft; // mixed 2x/1x
    const auto unsupported = tracker.refresh(&readSyntheticNativeDisplays, &fixture);
    assert(!unsupported &&
           unsupported.error() == NativeDisplayRefreshError::GeometryUnsupported);
    assert(!tracker.usable(3));
    const auto nullReader = tracker.refresh(nullptr, nullptr);
    assert(!nullReader &&
           nullReader.error() == NativeDisplayRefreshError::DisplayUnavailable);
    assert(tracker.generation() == 4 && !tracker.usable(4));
    fixture = nativeDisplayFixture();
    const auto recovered = tracker.refresh(&readSyntheticNativeDisplays, &fixture);
    assert(recovered && *recovered == 5 && tracker.usable(5));
    tracker.invalidate();
    assert(!tracker.usable(5));
}

[[nodiscard]] NativeDisplayReadStatus readSyntheticWithConcurrentChange(
    void* const context, std::span<NativeDisplayObservation> destination,
    std::size_t& count) noexcept {
    const auto status = readSyntheticNativeDisplays(context, destination, count);
    const auto& fixture = *static_cast<const NativeDisplayFixture*>(context);
    if (fixture.calls == 2) {
        // Simulates Quartz begin/end notification on another thread. The
        // callback never needs to read the actual machine's display state.
        rdp::macos::NativeDisplayReconfigurationWatch::recordTopologyChange();
    }
    return status;
}

void testNativeReconfigurationStaleDenial() {
    using namespace rdp::macos;
    NativeDisplayGeometryRefresh geometry;
    auto fixture = nativeDisplayFixture();
    const auto epoch = geometry.refresh(&readSyntheticNativeDisplays, &fixture);
    assert(epoch && geometry.usable(*epoch));
    const auto revision = NativeDisplayReconfigurationWatch::revision();
    assert(revision != 0 && !NativeDisplayReconfigurationWatch::changedSince(revision));
    assert(geometry.pixelAtLogicalPoint({10, 10}, *epoch));
    NativeDisplayReconfigurationWatch::recordTopologyChange();
    assert(NativeDisplayReconfigurationWatch::changedSince(revision));
    assert(!geometry.usable(*epoch));
    assert(!geometry.pixelAtLogicalPoint({10, 10}, *epoch));
    assert(!geometry.logicalAtVirtualPixel(20, 20, *epoch));
    assert(!geometry.virtualPixelSize(*epoch));
    fixture = nativeDisplayFixture();
    const auto fresh = geometry.refresh(&readSyntheticNativeDisplays, &fixture);
    assert(fresh && *fresh > *epoch && geometry.usable(*fresh));
    assert(!geometry.usable(*epoch));
}

void testNativeReconfigurationDuringRead() {
    using namespace rdp::macos;
    NativeDisplayGeometryRefresh geometry;
    auto fixture = nativeDisplayFixture();
    const auto midRead = geometry.refresh(&readSyntheticWithConcurrentChange, &fixture);
    assert(!midRead && midRead.error() == NativeDisplayRefreshError::TopologyChanged);
    assert(geometry.generation() == 1 && !geometry.usable(1));
    assert(!geometry.pixelAtLogicalPoint({0, 0}, 1));
    fixture = nativeDisplayFixture();
    const auto clean = geometry.refresh(&readSyntheticNativeDisplays, &fixture);
    assert(clean && *clean == 2 && geometry.usable(*clean));
    // Explicitly cancelling again must also reject the old revision.
    geometry.invalidate();
    assert(!geometry.usable(*clean));
}

void testNativeReconfigurationSignalRevision() {
    using namespace rdp::macos;
    static_assert(!std::is_copy_constructible_v<NativeDisplayReconfigurationWatch>);
    static_assert(!std::is_move_constructible_v<NativeDisplayReconfigurationWatch>);
    const auto revision = NativeDisplayReconfigurationWatch::revision();
    assert(revision != 0);
    assert(!NativeDisplayReconfigurationWatch::changedSince(revision));
    assert(NativeDisplayReconfigurationWatch::changedSince(0));
    NativeDisplayReconfigurationWatch::recordTopologyChange();
    assert(NativeDisplayReconfigurationWatch::changedSince(revision));
    const auto secondRevision = NativeDisplayReconfigurationWatch::revision();
    assert(secondRevision != 0 && secondRevision != revision);
    assert(!NativeDisplayReconfigurationWatch::changedSince(secondRevision));
    NativeDisplayReconfigurationWatch::recordTopologyChange();
    assert(NativeDisplayReconfigurationWatch::changedSince(secondRevision));
}


void testMacCursorNativeSamplerQuarantine() {
    assert(!ExposesNativeCursorSampler<
           rdp::macos::NativeDisplayGeometryRefresh>);
}

void testMacCursorOwnedShape() {
    using namespace rdp::macos;
    NativeDisplayGeometryRefresh geometry;
    auto fixture = nativeDisplayFixture();
    const auto generation = geometry.refresh(&readSyntheticNativeDisplays, &fixture);
    assert(generation && geometry.usable(*generation));

    auto storage = std::make_unique_for_overwrite<std::byte[]>(16);
    for (std::size_t index = 0; index < 16; ++index) {
        storage[index] = static_cast<std::byte>(index);
    }
    auto* const ownedAddress = storage.get();
    MacNativeCursorObservation observation{
        true, {0.5, 0.5}, 2, 2, 1, 1, 8};
    auto snapshot = makeMacCursorSnapshot(
        geometry, *generation, observation, std::move(storage), 16);
    assert(snapshot && snapshot->valid());
    assert(storage == nullptr);
    assert(snapshot->visible);
    assert(snapshot->position.displayId == 100);
    assert(snapshot->position.absoluteX == 1 &&
           snapshot->position.absoluteY == 1);
    assert(snapshot->position.virtualX == 1 &&
           snapshot->position.virtualY == 1);
    assert(snapshot->widthPixels == 2 && snapshot->heightPixels == 2);
    assert(snapshot->hotspotX == 1 && snapshot->hotspotY == 1);
    assert(snapshot->bytesPerRow == 8 && snapshot->pixels().size() == 16);
    assert(snapshot->pixels().data() == ownedAddress);
    assert(snapshot->geometryGeneration == *generation);
    assert(snapshot->topologyRevision != 0);

    auto moved = std::move(*snapshot);
    assert(moved.valid() && moved.pixels().data() == ownedAddress);
    assert(snapshot->pixels().empty());
}

void testMacCursorValidationDenials() {
    using namespace rdp::macos;
    NativeDisplayGeometryRefresh geometry;
    auto fixture = nativeDisplayFixture();
    const auto generation = geometry.refresh(&readSyntheticNativeDisplays, &fixture);
    assert(generation);

    auto hidden = makeMacCursorSnapshot(
        geometry, *generation, MacNativeCursorObservation{}, {}, 0);
    assert(hidden && hidden->valid() && !hidden->visible);
    assert(hidden->pixels().empty());

    MacNativeCursorObservation hiddenWithShape{};
    hiddenWithShape.widthPixels = 1;
    const auto invalidHidden = makeMacCursorSnapshot(
        geometry, *generation, hiddenWithShape, {}, 0);
    assert(!invalidHidden &&
           invalidHidden.error() == MacCursorSnapshotError::InvalidObservation);

    const MacNativeCursorObservation visible{
        true, {1.0, 1.0}, 2, 2, 1, 1, 8};
    const auto missingStorage = makeMacCursorSnapshot(
        geometry, *generation, visible, {}, 16);
    assert(!missingStorage &&
           missingStorage.error() == MacCursorSnapshotError::InvalidObservation);

    auto oversized = visible;
    oversized.widthPixels = kMaximumMacCursorDimension + 1;
    const auto oversizedResult = makeMacCursorSnapshot(
        geometry, *generation, oversized,
        std::make_unique_for_overwrite<std::byte[]>(16), 16);
    assert(!oversizedResult &&
           oversizedResult.error() == MacCursorSnapshotError::InvalidObservation);

    auto invalidHotspot = visible;
    invalidHotspot.hotspotX = invalidHotspot.widthPixels;
    const auto hotspotResult = makeMacCursorSnapshot(
        geometry, *generation, invalidHotspot,
        std::make_unique_for_overwrite<std::byte[]>(16), 16);
    assert(!hotspotResult &&
           hotspotResult.error() == MacCursorSnapshotError::InvalidObservation);

    auto invalidStride = visible;
    invalidStride.bytesPerRow = 9;
    const auto strideResult = makeMacCursorSnapshot(
        geometry, *generation, invalidStride,
        std::make_unique_for_overwrite<std::byte[]>(16), 16);
    assert(!strideResult &&
           strideResult.error() == MacCursorSnapshotError::InvalidObservation);

    const auto shortBuffer = makeMacCursorSnapshot(
        geometry, *generation, visible,
        std::make_unique_for_overwrite<std::byte[]>(15), 15);
    assert(!shortBuffer &&
           shortBuffer.error() == MacCursorSnapshotError::InvalidObservation);

    auto outside = visible;
    outside.position = {1512.0, 0.0};
    const auto outsideResult = makeMacCursorSnapshot(
        geometry, *generation, outside,
        std::make_unique_for_overwrite<std::byte[]>(16), 16);
    assert(!outsideResult &&
           outsideResult.error() == MacCursorSnapshotError::PositionOutsideDesktop);

    const auto zeroGeneration = makeMacCursorSnapshot(
        geometry, 0, MacNativeCursorObservation{}, {}, 0);
    assert(!zeroGeneration &&
           zeroGeneration.error() == MacCursorSnapshotError::InvalidGeneration);
    const auto staleGeneration = makeMacCursorSnapshot(
        geometry, *generation + 1, MacNativeCursorObservation{}, {}, 0);
    assert(!staleGeneration &&
           staleGeneration.error() ==
               MacCursorSnapshotError::StaleGeometryGeneration);
}

void testMacCursorTopologyRevocation() {
    using namespace rdp::macos;
    NativeDisplayGeometryRefresh geometry;
    auto fixture = nativeDisplayFixture();
    const auto oldGeneration =
        geometry.refresh(&readSyntheticNativeDisplays, &fixture);
    assert(oldGeneration && geometry.usable(*oldGeneration));
    const auto oldRevision = geometry.topologyRevision(*oldGeneration);
    assert(oldRevision && *oldRevision != 0);

    NativeDisplayReconfigurationWatch::recordTopologyChange();
    const auto staleTopology = makeMacCursorSnapshot(
        geometry, *oldGeneration, MacNativeCursorObservation{}, {}, 0);
    assert(!staleTopology &&
           staleTopology.error() == MacCursorSnapshotError::StaleTopology);

    fixture = nativeDisplayFixture();
    const auto newGeneration =
        geometry.refresh(&readSyntheticNativeDisplays, &fixture);
    assert(newGeneration && *newGeneration > *oldGeneration);
    const auto staleGeneration = makeMacCursorSnapshot(
        geometry, *oldGeneration, MacNativeCursorObservation{}, {}, 0);
    assert(!staleGeneration &&
           staleGeneration.error() ==
               MacCursorSnapshotError::StaleGeometryGeneration);
    const auto freshHidden = makeMacCursorSnapshot(
        geometry, *newGeneration, MacNativeCursorObservation{}, {}, 0);
    assert(freshHidden && freshHidden->valid() && !freshHidden->visible);
    assert(freshHidden->topologyRevision != *oldRevision);
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
    } else if (test_case == "geometry-epoch-refresh") {
        testNativeDisplayRefreshEpoch();
    } else if (test_case == "geometry-epoch-invalidate") {
        testNativeDisplayTopologyInvalidation();
    } else if (test_case == "geometry-epoch-failed-refresh") {
        testNativeDisplayFailedRefreshClearsGeometry();
    } else if (test_case == "native-reconfiguration-stale-denial") {
        testNativeReconfigurationStaleDenial();
    } else if (test_case == "native-reconfiguration-during-read") {
        testNativeReconfigurationDuringRead();
    } else if (test_case == "native-reconfiguration-revision-sequence") {
        testNativeReconfigurationSignalRevision();
    } else if (test_case == "cursor-native-sampler-quarantine") {
        testMacCursorNativeSamplerQuarantine();
    } else if (test_case == "cursor-owned-shape") {
        testMacCursorOwnedShape();
    } else if (test_case == "cursor-validation-denials") {
        testMacCursorValidationDenials();
    } else if (test_case == "cursor-topology-revocation") {
        testMacCursorTopologyRevocation();
    } else if (test_case == "geometry-native-single-retina") {
        testNativeGeometrySingleRetina();
    } else if (test_case == "geometry-native-uniform-multi-display") {
        testNativeGeometryUniformMultiDisplay();
    } else if (test_case == "geometry-native-mixed-scale-denials") {
        testNativeGeometryFailClosed();
    } else if (test_case == "geometry-native-generation-refresh") {
        testNativeGeometryGenerationRefresh();
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
