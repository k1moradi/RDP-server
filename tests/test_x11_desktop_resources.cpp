// SPDX-License-Identifier: GPL-3.0-or-later

#include "x11/x11_desktop_resources.h"
#include "rdp/x264_avc420_segmented_frame_producer.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

#include <xcb/randr.h>
#include <xcb/xcb.h>

using namespace rdp_server::rdp;

namespace
{

struct XcbConnectionDeleter
{
    void operator()(xcb_connection_t *connection) const noexcept
    {
        if (connection != nullptr)
        {
            xcb_disconnect(connection);
        }
    }
};

using XcbConnection = std::unique_ptr<xcb_connection_t, XcbConnectionDeleter>;

constexpr std::uint64_t kCaptureArenaPixels = 256U * 1024U;

void
requireValidResources(const X11DesktopResources &resources,
                      const char *constructionPhase) noexcept
{
    const bool isValid = resources.valid();
    if (!isValid)
    {
        const char *reason = resources.failureReason();
        std::fprintf(
            stderr,
            "X11 desktop resource construction failed during %s: %s\n",
            constructionPhase,
            reason != nullptr ? reason : "no failure reason");
    }
    assert(isValid);
}

XcbConnection
connectHelper(const char *display, int &screenNumber)
{
    XcbConnection connection(xcb_connect(display, &screenNumber));
    assert(connection != nullptr);
    assert(screenNumber >= 0);
    assert(xcb_connection_has_error(connection.get()) == 0);
    return connection;
}

const char *
syntheticDisplay()
{
    const char *display = std::getenv("DISPLAY");
    assert(display != nullptr && display[0] != '\0');
    return display;
}

xcb_screen_t *
screenFor(xcb_connection_t &connection, int screenNumber)
{
    const xcb_setup_t *setup = xcb_get_setup(&connection);
    assert(setup != nullptr);
    xcb_screen_iterator_t iterator = xcb_setup_roots_iterator(setup);
    for (int index = 0; index < screenNumber && iterator.rem > 0; ++index)
    {
        xcb_screen_next(&iterator);
    }
    assert(iterator.rem > 0 && iterator.data != nullptr);
    return iterator.data;
}

void
disableRandrCrtcsAndResize(xcb_connection_t &connection,
                           xcb_window_t root,
                           PixelSize geometry) noexcept
{
    xcb_generic_error_t *resourcesError = nullptr;
    const auto resourcesCookie =
        xcb_randr_get_screen_resources_current(&connection, root);
    xcb_randr_get_screen_resources_current_reply_t *resources =
        xcb_randr_get_screen_resources_current_reply(
            &connection, resourcesCookie, &resourcesError);
    assert(resourcesError == nullptr);
    std::free(resourcesError);
    assert(resources != nullptr);

    const int crtcCount =
        xcb_randr_get_screen_resources_current_crtcs_length(resources);
    xcb_randr_crtc_t *crtcs =
        xcb_randr_get_screen_resources_current_crtcs(resources);
    assert(crtcCount >= 0);
    for (int index = 0; index < crtcCount; ++index)
    {
        xcb_generic_error_t *configError = nullptr;
        const auto configCookie = xcb_randr_set_crtc_config(
            &connection, crtcs[index], resources->timestamp,
            resources->config_timestamp, 0, 0, XCB_NONE,
            XCB_RANDR_ROTATION_ROTATE_0, 0, nullptr);
        xcb_randr_set_crtc_config_reply_t *config =
            xcb_randr_set_crtc_config_reply(
                &connection, configCookie, &configError);
        assert(configError == nullptr);
        std::free(configError);
        assert(config != nullptr);
        assert(config->status == XCB_RANDR_SET_CONFIG_SUCCESS);
        std::free(config);
    }
    std::free(resources);

    const xcb_void_cookie_t resizeCookie =
        xcb_randr_set_screen_size_checked(
            &connection, root,
            static_cast<std::uint16_t>(geometry.widthPixels),
            static_cast<std::uint16_t>(geometry.heightPixels),
            geometry.widthPixels / 4, geometry.heightPixels / 4);
    xcb_generic_error_t *resizeError =
        xcb_request_check(&connection, resizeCookie);
    assert(resizeError == nullptr);
    std::free(resizeError);
    assert(xcb_flush(&connection) > 0);
}

void
clearSyntheticRoot(xcb_connection_t &connection, xcb_window_t root) noexcept
{
    const xcb_void_cookie_t clearCookie = xcb_clear_area_checked(
        &connection, 0, root, 0, 0, 32, 32);
    xcb_generic_error_t *clearError =
        xcb_request_check(&connection, clearCookie);
    assert(clearError == nullptr);
    std::free(clearError);
    assert(xcb_flush(&connection) > 0);
}

struct SyntheticBgrColor final
{
    std::uint8_t red{};
    std::uint8_t green{};
    std::uint8_t blue{};

    [[nodiscard]] constexpr std::uint32_t nativePixel() const noexcept
    {
        return (static_cast<std::uint32_t>(red) << 16U) |
               (static_cast<std::uint32_t>(green) << 8U) |
               static_cast<std::uint32_t>(blue);
    }
};

struct SyntheticPixelPattern final
{
    SyntheticBgrColor base{};
    SyntheticBgrColor topLeft{};
    SyntheticBgrColor topRight{};
    SyntheticBgrColor bottomLeft{};
    SyntheticBgrColor bottomRight{};
    SyntheticBgrColor center{};
};

constexpr SyntheticPixelPattern kFirstPixelPattern{
    {0x12U, 0x34U, 0x56U},
    {0xa1U, 0x22U, 0x33U},
    {0x44U, 0xb2U, 0x55U},
    {0x66U, 0x77U, 0xc3U},
    {0xd4U, 0x88U, 0x99U},
    {0xabU, 0xcdU, 0xefU},
};

constexpr SyntheticPixelPattern kSecondPixelPattern{
    {0xe1U, 0xd2U, 0xc3U},
    {0x14U, 0x25U, 0x36U},
    {0x47U, 0x58U, 0x69U},
    {0x7aU, 0x8bU, 0x9cU},
    {0xadU, 0xbeU, 0xcfU},
    {0x20U, 0x40U, 0x60U},
};

void
requireCheckedRequest(xcb_connection_t &connection,
                      xcb_void_cookie_t cookie) noexcept
{
    xcb_generic_error_t *error = xcb_request_check(&connection, cookie);
    assert(error == nullptr);
    std::free(error);
}

void
synchronizeXcbConnection(xcb_connection_t &connection) noexcept
{
    xcb_generic_error_t *error = nullptr;
    const auto cookie = xcb_get_input_focus(&connection);
    xcb_get_input_focus_reply_t *reply =
        xcb_get_input_focus_reply(&connection, cookie, &error);
    assert(error == nullptr);
    std::free(error);
    assert(reply != nullptr);
    std::free(reply);
    assert(xcb_connection_has_error(&connection) == 0);
}

void
drawSyntheticPattern(xcb_connection_t &connection, xcb_drawable_t drawable,
                     Rectangle bounds,
                     const SyntheticPixelPattern &pattern) noexcept
{
    assert(bounds.widthPixels >= 3U);
    assert(bounds.heightPixels >= 3U);

    const xcb_gcontext_t graphicsContext = xcb_generate_id(&connection);
    assert(graphicsContext != XCB_NONE);
    std::uint32_t foreground = pattern.base.nativePixel();
    requireCheckedRequest(
        connection,
        xcb_create_gc_checked(
            &connection, graphicsContext, drawable, XCB_GC_FOREGROUND,
            &foreground));

    const auto fill =
        [&](Rectangle rectangle, SyntheticBgrColor color) noexcept
        {
            foreground = color.nativePixel();
            requireCheckedRequest(
                connection,
                xcb_change_gc_checked(
                    &connection, graphicsContext, XCB_GC_FOREGROUND,
                    &foreground));
            const xcb_rectangle_t nativeRectangle{
                static_cast<std::int16_t>(rectangle.x),
                static_cast<std::int16_t>(rectangle.y),
                static_cast<std::uint16_t>(rectangle.widthPixels),
                static_cast<std::uint16_t>(rectangle.heightPixels),
            };
            requireCheckedRequest(
                connection,
                xcb_poly_fill_rectangle_checked(
                    &connection, drawable, graphicsContext, 1,
                    &nativeRectangle));
        };

    fill(bounds, pattern.base);
    fill({bounds.x, bounds.y, 1, 1}, pattern.topLeft);
    fill({bounds.x + static_cast<std::int32_t>(bounds.widthPixels - 1U),
          bounds.y, 1, 1},
         pattern.topRight);
    fill({bounds.x,
          bounds.y + static_cast<std::int32_t>(bounds.heightPixels - 1U),
          1, 1},
         pattern.bottomLeft);
    fill({bounds.x + static_cast<std::int32_t>(bounds.widthPixels - 1U),
          bounds.y + static_cast<std::int32_t>(bounds.heightPixels - 1U),
          1, 1},
         pattern.bottomRight);
    fill({bounds.x + static_cast<std::int32_t>(bounds.widthPixels / 2U),
          bounds.y + static_cast<std::int32_t>(bounds.heightPixels / 2U),
          1, 1},
         pattern.center);

    requireCheckedRequest(
        connection, xcb_free_gc_checked(&connection, graphicsContext));
    assert(xcb_connection_has_error(&connection) == 0);
}

[[nodiscard]] SyntheticBgrColor
expectedSyntheticColor(Rectangle patternBounds,
                       const SyntheticPixelPattern &pattern,
                       std::int32_t globalX, std::int32_t globalY) noexcept
{
    assert(globalX >= patternBounds.x);
    assert(globalY >= patternBounds.y);
    const std::uint32_t localX =
        static_cast<std::uint32_t>(globalX - patternBounds.x);
    const std::uint32_t localY =
        static_cast<std::uint32_t>(globalY - patternBounds.y);
    assert(localX < patternBounds.widthPixels);
    assert(localY < patternBounds.heightPixels);

    if (localX == 0U && localY == 0U)
        return pattern.topLeft;
    if (localX + 1U == patternBounds.widthPixels && localY == 0U)
        return pattern.topRight;
    if (localX == 0U && localY + 1U == patternBounds.heightPixels)
        return pattern.bottomLeft;
    if (localX + 1U == patternBounds.widthPixels &&
        localY + 1U == patternBounds.heightPixels)
    {
        return pattern.bottomRight;
    }
    if (localX == patternBounds.widthPixels / 2U &&
        localY == patternBounds.heightPixels / 2U)
    {
        return pattern.center;
    }
    return pattern.base;
}

void
requireCapturedPattern(const FramebufferView &frame,
                       Rectangle capturedRectangle,
                       Rectangle patternBounds,
                       const SyntheticPixelPattern &pattern) noexcept
{
    assert(frame.valid());
    assert(frame.widthPixels == capturedRectangle.widthPixels);
    assert(frame.heightPixels == capturedRectangle.heightPixels);
    assert(frame.strideBytes ==
           static_cast<std::size_t>(capturedRectangle.widthPixels) * 4U);
    assert(frame.pixels.size() == frame.strideBytes * frame.heightPixels);

    const std::size_t strideBytes = frame.strideBytes;
    for (std::uint32_t y = 0; y < frame.heightPixels; ++y)
    {
        for (std::uint32_t x = 0; x < frame.widthPixels; ++x)
        {
            const auto expected = expectedSyntheticColor(
                patternBounds, pattern,
                capturedRectangle.x + static_cast<std::int32_t>(x),
                capturedRectangle.y + static_cast<std::int32_t>(y));
            const std::size_t pixelOffset =
                static_cast<std::size_t>(y) * strideBytes +
                static_cast<std::size_t>(x) * 4U;
            // The supported Xvfb visual is 24-bit TrueColor stored in 32-bit
            // little-endian BGRX memory. The padding byte is not alpha.
            assert(std::to_integer<std::uint8_t>(
                       frame.pixels[pixelOffset]) == expected.blue);
            assert(std::to_integer<std::uint8_t>(
                       frame.pixels[pixelOffset + 1U]) == expected.green);
            assert(std::to_integer<std::uint8_t>(
                       frame.pixels[pixelOffset + 2U]) == expected.red);
        }
    }
}

void
requireEveryBgrPixelChanged(std::span<const std::byte> previousPixels,
                            const FramebufferView &currentFrame) noexcept
{
    assert(currentFrame.valid());
    assert(previousPixels.size() == currentFrame.pixels.size());
    for (std::uint32_t y = 0; y < currentFrame.heightPixels; ++y)
    {
        for (std::uint32_t x = 0; x < currentFrame.widthPixels; ++x)
        {
            const std::size_t pixelOffset =
                static_cast<std::size_t>(y) * currentFrame.strideBytes +
                static_cast<std::size_t>(x) * 4U;
            const bool bgrChanged =
                previousPixels[pixelOffset] !=
                    currentFrame.pixels[pixelOffset] ||
                previousPixels[pixelOffset + 1U] !=
                    currentFrame.pixels[pixelOffset + 1U] ||
                previousPixels[pixelOffset + 2U] !=
                    currentFrame.pixels[pixelOffset + 2U];
            assert(bgrChanged);
        }
    }
}

void
requireSyntheticDamage(X11DesktopResources &resources,
                       std::uint64_t notificationCountBefore,
                       Rectangle expectedRectangle) noexcept
{
    xcb_connection_t *connection = resources.nativeConnection();
    assert(connection != nullptr);

    // A round trip on the production connection deterministically moves any
    // already-generated Damage events into XCB's local queue; event routing
    // itself still goes through X11DesktopResources.
    synchronizeXcbConnection(*connection);

    bool observed = false;
    for (std::size_t attempt = 0; attempt < 8U; ++attempt)
    {
        bool workMayRemain = false;
        assert(resources.processEvents(32, &workMayRemain, false) ==
               ConnectionStatus::Ok);
        if (resources.damageNotificationCount() > notificationCountBefore)
        {
            observed = true;
            break;
        }
    }
    assert(observed);
    assert(resources.damagePending());

    DamageRegion damage;
    assert(resources.snapshotDamage(damage));
    assert(!damage.rectangles().empty());
    assert(damage.intersects(expectedRectangle));
    assert(!resources.damagePending());

    // snapshotDamage() flushes XDamageSubtract. Complete that production
    // request before a helper client creates the next image generation.
    synchronizeXcbConnection(*connection);
}

std::uint64_t
requireSyntheticDamageGeneration(X11DesktopResources &resources,
                                 std::uint64_t notificationCountBefore,
                                 Rectangle expectedRectangle) noexcept
{
    xcb_connection_t *connection = resources.nativeConnection();
    assert(connection != nullptr);
    synchronizeXcbConnection(*connection);

    bool observed = false;
    for (std::size_t attempt = 0; attempt < 8U; ++attempt)
    {
        bool workMayRemain = false;
        assert(resources.processEvents(32, &workMayRemain, false) ==
               ConnectionStatus::Ok);
        if (resources.damageNotificationCount() > notificationCountBefore)
        {
            observed = true;
            break;
        }
    }
    assert(observed);
    assert(resources.damagePending());

    DamageRegion damage;
    std::uint64_t captureGeneration = 0;
    assert(resources.snapshotDamage(damage, captureGeneration));
    assert(captureGeneration != 0);
    assert(!damage.rectangles().empty());
    assert(damage.intersects(expectedRectangle));
    assert(!resources.damagePending());
    synchronizeXcbConnection(*connection);
    return captureGeneration;
}

void
requireSyntheticRandrRebuild(X11DesktopResources &resources,
                             xcb_connection_t &helper,
                             xcb_window_t root,
                             PixelSize resizedGeometry) noexcept
{
    disableRandrCrtcsAndResize(helper, root, resizedGeometry);
    xcb_connection_t *connection = resources.nativeConnection();
    assert(connection != nullptr);
    synchronizeXcbConnection(*connection);

    bool rebuilt = false;
    for (std::size_t attempt = 0; attempt < 8U; ++attempt)
    {
        bool workMayRemain = false;
        assert(resources.processEvents(64, &workMayRemain, false) ==
               ConnectionStatus::Ok);
        if (resources.sourceGeometry() == resizedGeometry)
        {
            assert(workMayRemain);
            rebuilt = true;
            break;
        }
    }
    assert(rebuilt);

    // Drain only after the RandR event committed the new generation. Any
    // event queued behind the transition is therefore offered to new
    // geometry-bound trackers, never the retired generation.
    bool workMayRemain = false;
    assert(resources.processEvents(64, &workMayRemain, false) ==
           ConnectionStatus::Ok);
    assert(resources.valid());
}

void
warpSyntheticPointer(xcb_connection_t &connection, xcb_window_t root,
                     X11PointerPosition position) noexcept
{
    const xcb_void_cookie_t warpCookie = xcb_warp_pointer_checked(
        &connection, XCB_NONE, root, 0, 0, 0, 0,
        static_cast<std::int16_t>(position.x),
        static_cast<std::int16_t>(position.y));
    xcb_generic_error_t *warpError =
        xcb_request_check(&connection, warpCookie);
    assert(warpError == nullptr);
    std::free(warpError);
    assert(xcb_flush(&connection) > 0);
}

std::array<std::byte, 22>
r4Advertisement()
{
    return {std::byte{0x12}, {}, {}, {}, std::byte{22}, {}, {}, {},
            std::byte{1}, {}, std::byte{5}, std::byte{1}, std::byte{8}, {},
            std::byte{4}, {}, {}, {}, std::byte{0x10}, {}, {}, {}};
}

GfxPresentationReceipt
emitR4Command(GfxPresentationLifecycle &lifecycle,
              std::uint64_t generation)
{
    std::array<std::byte, 24> bytes{};
    GfxPresentationReceipt receipt{};
    assert(lifecycle.prepareCommand(generation, bytes, receipt));
    return receipt;
}

void
mapR4Surface(GfxPresentationLifecycle &lifecycle,
             std::uint64_t generation,
             PixelSize geometry) noexcept
{
    assert(lifecycle.open(generation));
    assert(lifecycle.acceptCapabilities(generation, r4Advertisement()));
    auto receipt = emitR4Command(lifecycle, generation);
    assert(lifecycle.completeCommand(receipt, receipt.bytes));
    assert(lifecycle.configureSurface(generation, 7, geometry));
    receipt = emitR4Command(lifecycle, generation);
    assert(lifecycle.completeCommand(receipt, receipt.bytes));
    receipt = emitR4Command(lifecycle, generation);
    assert(lifecycle.completeCommand(receipt, receipt.bytes));
    assert(lifecycle.stage() == GfxPresentationStage::Mapped);
}

void
openR4Producer(X264Avc420SegmentedFrameProducer &producer,
               std::uint64_t generation,
               PixelSize geometry) noexcept
{
    const PixelSize coded = gfxAvc420CodedGeometry(geometry);
    assert(coded.widthPixels != 0 && coded.heightPixels != 0);
    assert(producer.open(generation, coded, geometry));
}

bool
prepareR4Bgra(GfxPresentationLifecycle &lifecycle,
              X264Avc420SegmentedFrameProducer &producer,
              std::uint64_t generation,
              std::uint32_t frameId,
              const FramebufferView &framebuffer,
              GfxAvc420SegmentedFrame &output,
              std::int64_t pts = 0) noexcept
{
    const std::array<Rectangle, 1> regions{{
        {0, 0, framebuffer.widthPixels, framebuffer.heightPixels}}};
    const std::array<GfxAvc420QuantQuality, 1> qualities{{{23, 80}}};
    const X264BgraFrameRequest request{
        7, frameId, framebuffer, pts, regions, qualities};
    return producer.prepareBgra(lifecycle, generation, request, output);
}

std::vector<std::byte>
packedSyntheticPixels(Rectangle bounds,
                      const SyntheticPixelPattern &pattern)
{
    const std::size_t stride =
        static_cast<std::size_t>(bounds.widthPixels) * 4U;
    std::vector<std::byte> pixels(
        stride * static_cast<std::size_t>(bounds.heightPixels));
    for (std::uint32_t y = 0; y < bounds.heightPixels; ++y)
    {
        for (std::uint32_t x = 0; x < bounds.widthPixels; ++x)
        {
            const auto color = expectedSyntheticColor(
                bounds, pattern,
                bounds.x + static_cast<std::int32_t>(x),
                bounds.y + static_cast<std::int32_t>(y));
            const std::size_t at =
                static_cast<std::size_t>(y) * stride +
                static_cast<std::size_t>(x) * 4U;
            pixels[at] = static_cast<std::byte>(color.blue);
            pixels[at + 1U] = static_cast<std::byte>(color.green);
            pixels[at + 2U] = static_cast<std::byte>(color.red);
            pixels[at + 3U] = std::byte{};
        }
    }
    return pixels;
}

struct R4IngressConsumer final
{
    GfxPresentationLifecycle *lifecycle{};
    X264Avc420SegmentedFrameProducer *producer{};
    GfxAvc420SegmentedFrame *output{};
    std::uint64_t presentationGeneration{};
    std::uint64_t expectedCaptureGeneration{};
    std::uint32_t frameId{};
    std::int64_t pts{};
    unsigned calls{};

    static bool consume(void *raw, const FramebufferView &framebuffer,
                        std::uint64_t captureGeneration) noexcept
    {
        auto &self = *static_cast<R4IngressConsumer *>(raw);
        ++self.calls;
        assert(framebuffer.valid());
        assert(framebuffer.strideBytes ==
               static_cast<std::size_t>(framebuffer.widthPixels) * 4U);
        if (captureGeneration != self.expectedCaptureGeneration)
        {
            return false;
        }
        return prepareR4Bgra(
            *self.lifecycle, *self.producer, self.presentationGeneration,
            self.frameId, framebuffer, *self.output, self.pts);
    }

    [[nodiscard]] X11R4BgraFrameConsumer callbacks() noexcept
    {
        return {this, &consume};
    }
};

class PointerRoutingObservationSink final : public X11EventSink
{
public:
    PointerRoutingObservationSink(X11DesktopResources &resources,
                                  X11PointerPosition expected) noexcept
        : resources_(resources), expected_(expected)
    {
    }

    void handle(const xcb_generic_event_t &) noexcept override
    {
        X11PointerPosition observed{};
        if (resources_.pendingPointerPosition(observed) &&
            observed == expected_)
        {
            observedAfterPointerRoute_ = true;
        }
    }

    [[nodiscard]] bool observedAfterPointerRoute() const noexcept
    {
        return observedAfterPointerRoute_;
    }

private:
    X11DesktopResources &resources_;
    X11PointerPosition expected_{};
    bool observedAfterPointerRoute_{false};
};

bool
waitForPointerPosition(X11DesktopResources &resources,
                       X11PointerPosition expected,
                       X11EventSink *additionalEventSink = nullptr) noexcept
{
    xcb_connection_t *connection = resources.nativeConnection();
    assert(connection != nullptr);
    synchronizeXcbConnection(*connection);

    for (std::size_t attempt = 0; attempt < 8U; ++attempt)
    {
        bool workMayRemain = false;
        assert(resources.processEvents(
                   16, &workMayRemain, false, additionalEventSink) ==
               ConnectionStatus::Ok);
        X11PointerPosition observed{};
        if (resources.pendingPointerPosition(observed) &&
            observed == expected)
        {
            return true;
        }
        if (!workMayRemain)
        {
            break;
        }
    }
    return false;
}

void
connectionDenial()
{
    X11DesktopResources resources("not-a-valid-x11-display", 4096);
    assert(!resources.valid());
    assert(resources.failureReason() != nullptr);
    assert(resources.fileDescriptor() == -1);
    assert((resources.sourceGeometry() == PixelSize{}));
    assert(!resources.randrAvailable());
    assert(!resources.damagePending());
    assert(resources.damageNotificationCount() == 0);
    assert(!resources.pointerPositionAvailable());
    assert(resources.pointerPositionFailureReason() != nullptr);
    X11PointerPosition position{};
    assert(!resources.pendingPointerPosition(position));
    assert(!resources.shouldForwardPointerPosition(position));
    resources.acknowledgePointerPosition(position, true);

    bool workMayRemain = true;
    assert(resources.processEvents(8, &workMayRemain, true) ==
           ConnectionStatus::Failed);
    assert(!workMayRemain);

    resources.disconnect();
    assert(!resources.valid());
    resources.disconnect();
    assert(!resources.valid());
}

void
syntheticXvfbLifecycle()
{
    const char *display = syntheticDisplay();

    // A failed child construction must cancel the already-open display before
    // another resource owner is created on the same synthetic X server.
    {
        X11DesktopResources rejected(display, 0);
        assert(!rejected.valid());
        assert(rejected.failureReason() != nullptr);
        assert(std::string_view(rejected.failureReason()) ==
               "XShm capture arena size is invalid");
        assert(rejected.fileDescriptor() == -1);
    }

    {
        X11DesktopResources resources(display, kCaptureArenaPixels);
        requireValidResources(resources, "failed-owner recovery");
        assert(resources.failureReason() == nullptr);
        assert(resources.fileDescriptor() >= 0);
        const PixelSize geometry = resources.sourceGeometry();
        assert(geometry.widthPixels == 1280);
        assert(geometry.heightPixels == 720);

        bool workMayRemain = true;
        assert(resources.processEvents(8, &workMayRemain, false) ==
               ConnectionStatus::Ok);
        assert(!workMayRemain);

        resources.disconnect();
        assert(!resources.valid());
        assert(resources.fileDescriptor() == -1);
        assert((resources.sourceGeometry() == PixelSize{}));
        resources.disconnect();
    }

    // Exercise destructor-driven ordered cancellation after a second complete
    // resource construction. No real desktop or user input is involved.
    X11DesktopResources resources(display, kCaptureArenaPixels);
    requireValidResources(resources, "post-disconnect recovery");
}

void
syntheticXvfbEventRouting()
{
    const char *display = syntheticDisplay();
    X11DesktopResources resources(display, kCaptureArenaPixels);
    assert(resources.valid());

    int helperScreenNumber = -1;
    XcbConnection helper = connectHelper(display, helperScreenNumber);
    xcb_screen_t *helperScreen = screenFor(*helper, helperScreenNumber);
    const std::uint64_t notificationCountBefore =
        resources.damageNotificationCount();

    clearSyntheticRoot(*helper, helperScreen->root);
    xcb_connection_t *connection = resources.nativeConnection();
    assert(connection != nullptr);
    synchronizeXcbConnection(*connection);

    bool routedDamage = false;
    for (std::size_t attempt = 0; attempt < 8U; ++attempt)
    {
        bool workMayRemain = false;
        assert(resources.processEvents(8, &workMayRemain, false) ==
               ConnectionStatus::Ok);
        if (resources.damageNotificationCount() > notificationCountBefore)
        {
            routedDamage = true;
            break;
        }
        if (!workMayRemain)
        {
            break;
        }
    }

    assert(routedDamage);
    assert(resources.damagePending());
    assert(resources.valid());
    resources.disconnect();
}

void
syntheticXvfbR4ReadBoundary()
{
    const char *display = syntheticDisplay();
    X11DesktopResources resources(display, kCaptureArenaPixels);
    assert(resources.valid());

    // R4 may synchronously borrow one bounded BGRX capture from the existing
    // XShm arena; no frame scheduler or persistent framebuffer owner is added.
    const FramebufferView frame = resources.capture({0, 0, 32, 16});
    assert(frame.valid());
    assert(frame.widthPixels == 32);
    assert(frame.heightPixels == 16);
    assert(frame.strideBytes == 32U * 4U);
    assert(frame.pixels.size() == frame.strideBytes * frame.heightPixels);
    assert(resources.valid());

    int helperScreenNumber = -1;
    XcbConnection helper = connectHelper(display, helperScreenNumber);
    xcb_screen_t *helperScreen = screenFor(*helper, helperScreenNumber);
    clearSyntheticRoot(*helper, helperScreen->root);
    xcb_connection_t *connection = resources.nativeConnection();
    assert(connection != nullptr);
    synchronizeXcbConnection(*connection);

    bool routedDamage = false;
    for (std::size_t attempt = 0; attempt < 8U; ++attempt)
    {
        bool workMayRemain = false;
        assert(resources.processEvents(8, &workMayRemain, false) ==
               ConnectionStatus::Ok);
        if (resources.damagePending())
        {
            routedDamage = true;
            break;
        }
        if (!workMayRemain)
        {
            break;
        }
    }
    assert(routedDamage);

    DamageRegion damage;
    assert(resources.snapshotDamage(damage));
    assert(!damage.rectangles().empty());
    assert(damage.intersects({0, 0, 32, 32}));
    assert(!resources.damagePending());
    DamageRegion emptyDamage;
    assert(resources.snapshotDamage(emptyDamage));
    assert(emptyDamage.rectangles().empty());

    // XFixes starts pending so R4 can fetch the initial cursor exactly once.
    assert(resources.cursorPending());
    assert(resources.refreshCursor());
    assert(resources.cursorRefreshFailureReason() == nullptr);
    assert(resources.cursorRefreshErrorCode() == 0);
    assert(!resources.takeCursorRefreshFailureWarning());
    assert(!resources.takeUnsupportedCursorWarning());

    const X11CursorImageView cursor = resources.cursorImage();
    assert(cursor.valid());
    assert(cursor.widthPixels == 32);
    assert(cursor.heightPixels == 32);
    assert(cursor.pixels.size() >= 32U * 32U * 4U);
    assert(cursor.mask.size() >= 32U * 32U / 8U);
    resources.acknowledgeCursor();
    assert(!resources.cursorPending());

    // Borrowed views must be consumed before owner teardown.
    resources.disconnect();
    assert(!resources.valid());
    assert(!resources.snapshotDamage(damage));
    assert(!resources.capture({0, 0, 1, 1}).valid());
    assert(!resources.refreshCursor());
    assert(!resources.cursorImage().valid());
}

void
syntheticXvfbCapturePixelParity()
{
    const char *display = syntheticDisplay();
    X11DesktopResources resources(display, kCaptureArenaPixels);
    requireValidResources(resources, "capture pixel parity");

    int helperScreenNumber = -1;
    XcbConnection helper = connectHelper(display, helperScreenNumber);
    xcb_screen_t *helperScreen = screenFor(*helper, helperScreenNumber);
    assert(helperScreen->root_depth == 24U);

    constexpr Rectangle patternBounds{73, 91, 8, 6};
    constexpr Rectangle subrectangle{75, 92, 4, 3};

    const std::uint64_t firstNotificationCount =
        resources.damageNotificationCount();
    drawSyntheticPattern(
        *helper, helperScreen->root, patternBounds, kFirstPixelPattern);
    requireSyntheticDamage(
        resources, firstNotificationCount, patternBounds);

    std::vector<std::byte> firstGenerationPixels;
    {
        const FramebufferView frame = resources.capture(patternBounds);
        requireCapturedPattern(
            frame, patternBounds, patternBounds, kFirstPixelPattern);
        firstGenerationPixels.assign(
            frame.pixels.begin(), frame.pixels.end());
    }

    {
        const FramebufferView subframe = resources.capture(subrectangle);
        requireCapturedPattern(
            subframe, subrectangle, patternBounds, kFirstPixelPattern);
    }

    const std::uint64_t secondNotificationCount =
        resources.damageNotificationCount();
    drawSyntheticPattern(
        *helper, helperScreen->root, patternBounds, kSecondPixelPattern);
    requireSyntheticDamage(
        resources, secondNotificationCount, patternBounds);

    {
        const FramebufferView frame = resources.capture(patternBounds);
        requireCapturedPattern(
            frame, patternBounds, patternBounds, kSecondPixelPattern);
        requireEveryBgrPixelChanged(firstGenerationPixels, frame);
    }

    assert(resources.valid());
    resources.disconnect();
}

void
syntheticXvfbRandrCaptureGeneration()
{
    const char *display = syntheticDisplay();
    X11DesktopResources resources(display, kCaptureArenaPixels);
    requireValidResources(resources, "RandR capture generation");
    assert(resources.randrAvailable());

    const int originalDescriptor = resources.fileDescriptor();
    xcb_connection_t *const originalConnection = resources.nativeConnection();
    assert(originalDescriptor >= 0);
    assert(originalConnection != nullptr);
    assert((resources.sourceGeometry() == PixelSize{1280, 720}));

    int helperScreenNumber = -1;
    XcbConnection helper = connectHelper(display, helperScreenNumber);
    xcb_screen_t *helperScreen = screenFor(*helper, helperScreenNumber);
    assert(helperScreen->root_depth == 24U);

    constexpr Rectangle generationRectangle{1016, 594, 8, 6};
    constexpr PixelSize resizedGeometry{1024, 600};
    static_assert(
        generationRectangle.x +
            static_cast<std::int32_t>(generationRectangle.widthPixels) ==
        static_cast<std::int32_t>(resizedGeometry.widthPixels));
    static_assert(
        generationRectangle.y +
            static_cast<std::int32_t>(generationRectangle.heightPixels) ==
        static_cast<std::int32_t>(resizedGeometry.heightPixels));

    const std::uint64_t oldNotificationCount =
        resources.damageNotificationCount();
    drawSyntheticPattern(
        *helper, helperScreen->root, generationRectangle, kFirstPixelPattern);
    requireSyntheticDamage(
        resources, oldNotificationCount, generationRectangle);

    std::vector<std::byte> oldGenerationPixels;
    {
        const FramebufferView oldFrame =
            resources.capture(generationRectangle);
        requireCapturedPattern(
            oldFrame, generationRectangle, generationRectangle,
            kFirstPixelPattern);
        oldGenerationPixels.assign(
            oldFrame.pixels.begin(), oldFrame.pixels.end());
    }

    requireSyntheticRandrRebuild(
        resources, *helper, helperScreen->root, resizedGeometry);
    assert(resources.valid());
    assert(resources.fileDescriptor() == originalDescriptor);
    assert(resources.nativeConnection() == originalConnection);
    assert(resources.sourceGeometry() == resizedGeometry);

    const std::uint64_t newNotificationCount =
        resources.damageNotificationCount();
    drawSyntheticPattern(
        *helper, helperScreen->root, generationRectangle, kSecondPixelPattern);
    requireSyntheticDamage(
        resources, newNotificationCount, generationRectangle);

    {
        const FramebufferView newFrame =
            resources.capture(generationRectangle);
        requireCapturedPattern(
            newFrame, generationRectangle, generationRectangle,
            kSecondPixelPattern);
        requireEveryBgrPixelChanged(oldGenerationPixels, newFrame);
    }

    assert(resources.valid());
    resources.disconnect();
    assert(!resources.valid());
    assert(resources.fileDescriptor() == -1);
    assert(resources.nativeConnection() == nullptr);
    assert(resources.rootWindow() == XCB_WINDOW_NONE);
}

void
syntheticXvfbRandrStaleDamageIsolation()
{
    const char *display = syntheticDisplay();
    X11DesktopResources resources(display, kCaptureArenaPixels);
    requireValidResources(resources, "RandR stale-damage isolation");
    assert(resources.randrAvailable());

    const int originalDescriptor = resources.fileDescriptor();
    xcb_connection_t *const originalConnection = resources.nativeConnection();
    assert(originalDescriptor >= 0);
    assert(originalConnection != nullptr);
    assert((resources.sourceGeometry() == PixelSize{1280, 720}));

    int helperScreenNumber = -1;
    XcbConnection helper = connectHelper(display, helperScreenNumber);
    xcb_screen_t *helperScreen = screenFor(*helper, helperScreenNumber);
    assert(helperScreen->root_depth == 24U);

    constexpr PixelSize resizedGeometry{1024, 600};
    constexpr Rectangle patternRectangle{0, 0, 8, 6};

    // Complete the server-side resize first, then draw while the production
    // aggregate still owns its old geometry-bound Damage resource. This queues
    // an old-generation DamageNotify behind the RandR transition on the one
    // production XCB connection.
    disableRandrCrtcsAndResize(
        *helper, helperScreen->root, resizedGeometry);
    drawSyntheticPattern(
        *helper, helperScreen->root, patternRectangle, kFirstPixelPattern);
    synchronizeXcbConnection(*originalConnection);

    bool rebuilt = false;
    bool queuedEventsDrained = false;
    for (std::size_t attempt = 0; attempt < 16U; ++attempt)
    {
        bool workMayRemain = false;
        assert(resources.processEvents(64, &workMayRemain, false) ==
               ConnectionStatus::Ok);

        if (resources.sourceGeometry() == resizedGeometry)
        {
            if (!rebuilt)
            {
                // The display owner stops at the geometry transition. The
                // aggregate must publish a complete replacement generation
                // before any later queued event can be routed.
                assert(workMayRemain);
                rebuilt = true;
            }
            assert(resources.fileDescriptor() == originalDescriptor);
            assert(resources.nativeConnection() == originalConnection);
            assert(resources.damageNotificationCount() == 0U);
            assert(!resources.damagePending());

            if (!workMayRemain)
            {
                queuedEventsDrained = true;
                break;
            }
        }
    }

    assert(rebuilt);
    assert(queuedEventsDrained);
    assert(resources.valid());

    DamageRegion staleDamage;
    assert(resources.snapshotDamage(staleDamage));
    assert(staleDamage.rectangles().empty());

    // The first pattern was drawn before R5 consumed the RandR transition, but
    // current pixels remain capturable through the rebuilt XShm generation.
    {
        const FramebufferView frame = resources.capture(patternRectangle);
        requireCapturedPattern(
            frame, patternRectangle, patternRectangle, kFirstPixelPattern);
    }

    // A genuinely new post-rebuild draw must be observed by the replacement
    // Damage owner and captured with its exact new-generation source pixels.
    const std::uint64_t notificationCountBefore =
        resources.damageNotificationCount();
    drawSyntheticPattern(
        *helper, helperScreen->root, patternRectangle, kSecondPixelPattern);
    requireSyntheticDamage(
        resources, notificationCountBefore, patternRectangle);
    {
        const FramebufferView frame = resources.capture(patternRectangle);
        requireCapturedPattern(
            frame, patternRectangle, patternRectangle, kSecondPixelPattern);
    }

    assert(resources.valid());
    resources.disconnect();
    assert(!resources.valid());
}

void
syntheticXvfbCaptureTerminalDenial()
{
    X11DesktopResources resources(syntheticDisplay(), kCaptureArenaPixels);
    requireValidResources(resources, "capture terminal denial");
    assert(resources.fileDescriptor() >= 0);
    assert(resources.nativeConnection() != nullptr);

    {
        const FramebufferView initialFrame =
            resources.capture({0, 0, 4, 4});
        assert(initialFrame.valid());
    }

    // 1280x300 is inside the Xvfb root but exceeds the bounded 256K-pixel
    // arena. The production XShm child treats this as terminal, so the
    // aggregate must revoke every native capability rather than republish a
    // partial or stale arena view.
    const FramebufferView rejected =
        resources.capture({0, 0, 1280, 300});
    assert(!rejected.valid());
    assert(!resources.valid());
    assert(resources.failureReason() != nullptr);
    assert(std::string_view(resources.failureReason()) ==
           "XShm capture rectangle or arena is outside supported limits");
    assert(resources.fileDescriptor() == -1);
    assert(resources.nativeConnection() == nullptr);
    assert(resources.rootWindow() == XCB_WINDOW_NONE);
    assert((resources.sourceGeometry() == PixelSize{}));
    assert(!resources.randrAvailable());
    assert(!resources.damagePending());
    assert(resources.damageNotificationCount() == 0U);

    DamageRegion damage;
    assert(!resources.snapshotDamage(damage));
    assert(damage.rectangles().empty());
    assert(!resources.capture({0, 0, 1, 1}).valid());
    assert(!resources.refreshCursor());
    assert(!resources.cursorImage().valid());

    bool workMayRemain = true;
    assert(resources.processEvents(8, &workMayRemain, true) ==
           ConnectionStatus::Failed);
    assert(!workMayRemain);

    resources.disconnect();
    assert(!resources.valid());
    resources.disconnect();
    assert(!resources.valid());
}

void
syntheticXvfbPointerCapabilityDenials()
{
    X11DesktopResources rejected("not-a-valid-x11-display", 4096);
    assert(!rejected.pointerPositionAvailable());
    assert(rejected.pointerPositionFailureReason() != nullptr);
    X11PointerPosition rejectedPosition{10, 20};
    assert(!rejected.pendingPointerPosition(rejectedPosition));
    assert(!rejected.shouldForwardPointerPosition(rejectedPosition));
    rejected.acknowledgePointerPosition(rejectedPosition, true);

    X11DesktopResources resources(syntheticDisplay(), kCaptureArenaPixels);
    requireValidResources(resources, "pointer capability");
#if defined(RDP_TEST_XINPUT_POINTER)
    assert(resources.pointerPositionAvailable());
    assert(resources.pointerPositionFailureReason() == nullptr);

    X11PointerPosition first{};
    if (resources.pendingPointerPosition(first))
    {
        X11PointerPosition repeated{};
        assert(resources.pendingPointerPosition(repeated));
        assert(repeated == first);
        resources.acknowledgePointerPosition(first, false);
        assert(!resources.pendingPointerPosition(repeated));
    }
#else
    assert(!resources.pointerPositionAvailable());
    assert(resources.pointerPositionFailureReason() != nullptr);
#endif

    resources.disconnect();
    assert(!resources.pointerPositionAvailable());
    assert(resources.pointerPositionFailureReason() != nullptr);
    X11PointerPosition stale{5, 5};
    assert(!resources.pendingPointerPosition(stale));
    assert(!resources.shouldForwardPointerPosition(stale));
    resources.acknowledgePointerPosition(stale, true);
}

#if defined(RDP_TEST_XINPUT_POINTER)
void
syntheticXvfbPointerEventRouting()
{
    const char *display = syntheticDisplay();
    X11DesktopResources resources(display, kCaptureArenaPixels);
    requireValidResources(resources, "pointer event routing");
    assert(resources.pointerPositionAvailable());

    X11PointerPosition initial{};
    if (resources.pendingPointerPosition(initial))
    {
        resources.acknowledgePointerPosition(initial, false);
    }

    int helperScreenNumber = -1;
    XcbConnection helper = connectHelper(display, helperScreenNumber);
    xcb_screen_t *helperScreen = screenFor(*helper, helperScreenNumber);

    constexpr X11PointerPosition target{321, 222};
    PointerRoutingObservationSink observation(resources, target);
    warpSyntheticPointer(*helper, helperScreen->root, target);

    assert(waitForPointerPosition(resources, target, &observation));
    assert(observation.observedAfterPointerRoute());
    assert(resources.shouldForwardPointerPosition(target));

    X11PointerPosition repeated{};
    assert(resources.pendingPointerPosition(repeated));
    assert(repeated == target);
    resources.acknowledgePointerPosition(target, false);
    assert(!resources.pendingPointerPosition(repeated));
    resources.disconnect();
}

void
syntheticXvfbPointerRandrRebuild()
{
    const char *display = syntheticDisplay();
    X11DesktopResources resources(display, kCaptureArenaPixels);
    requireValidResources(resources, "pointer RandR rebuild");
    assert(resources.pointerPositionAvailable());
    assert(resources.randrAvailable());
    const int originalDescriptor = resources.fileDescriptor();

    X11PointerPosition initial{};
    if (resources.pendingPointerPosition(initial))
    {
        resources.acknowledgePointerPosition(initial, false);
    }

    int helperScreenNumber = -1;
    XcbConnection helper = connectHelper(display, helperScreenNumber);
    xcb_screen_t *helperScreen = screenFor(*helper, helperScreenNumber);

    constexpr X11PointerPosition forwardedLocal{400, 300};
    warpSyntheticPointer(*helper, helperScreen->root, forwardedLocal);
    assert(waitForPointerPosition(resources, forwardedLocal));
    assert(resources.shouldForwardPointerPosition(forwardedLocal));
    resources.acknowledgePointerPosition(forwardedLocal, true);

    constexpr X11PointerPosition staleGeneration{1200, 700};
    warpSyntheticPointer(*helper, helperScreen->root, staleGeneration);
    assert(waitForPointerPosition(resources, staleGeneration));

    constexpr PixelSize resizedGeometry{1024, 600};
    disableRandrCrtcsAndResize(
        *helper, helperScreen->root, resizedGeometry);
    xcb_connection_t *connection = resources.nativeConnection();
    assert(connection != nullptr);
    synchronizeXcbConnection(*connection);

    bool rebuilt = false;
    for (std::size_t attempt = 0; attempt < 8U; ++attempt)
    {
        bool workMayRemain = false;
        assert(resources.processEvents(16, &workMayRemain, false) ==
               ConnectionStatus::Ok);
        if (resources.sourceGeometry() == resizedGeometry)
        {
            rebuilt = true;
            assert(workMayRemain);
            break;
        }
        if (!workMayRemain)
        {
            break;
        }
    }

    assert(rebuilt);
    assert(resources.valid());
    assert(resources.pointerPositionAvailable());
    assert(resources.fileDescriptor() == originalDescriptor);

    X11PointerPosition current{};
    if (resources.pendingPointerPosition(current))
    {
        assert(current != staleGeneration);
        assert(current.x >= 0);
        assert(current.y >= 0);
        assert(static_cast<std::uint32_t>(current.x) <
               resizedGeometry.widthPixels);
        assert(static_cast<std::uint32_t>(current.y) <
               resizedGeometry.heightPixels);
        assert(resources.shouldForwardPointerPosition(current));
        resources.acknowledgePointerPosition(current, false);
    }
    resources.disconnect();
}
#endif

#if defined(RDP_TEST_XINPUT_POINTER)
void
syntheticXvfbPointerRandrStaleMotionIsolation()
{
    const char *display = syntheticDisplay();
    X11DesktopResources resources(display, kCaptureArenaPixels);
    requireValidResources(resources, "pointer RandR stale-motion isolation");
    assert(resources.pointerPositionAvailable());
    assert(resources.randrAvailable());

    const int originalDescriptor = resources.fileDescriptor();
    xcb_connection_t *const originalConnection = resources.nativeConnection();
    assert(originalDescriptor >= 0);
    assert(originalConnection != nullptr);

    X11PointerPosition initial{};
    if (resources.pendingPointerPosition(initial))
    {
        resources.acknowledgePointerPosition(initial, false);
    }

    int helperScreenNumber = -1;
    XcbConnection helper = connectHelper(display, helperScreenNumber);
    xcb_screen_t *helperScreen = screenFor(*helper, helperScreenNumber);

    constexpr PixelSize resizedGeometry{1024, 600};
    constexpr X11PointerPosition staleGeneration{800, 500};

    // Resize first, then move the pointer through the independent helper while
    // the production aggregate still owns the old XI2 generation. The helper
    // request ordering places this motion behind the RandR transition.
    disableRandrCrtcsAndResize(
        *helper, helperScreen->root, resizedGeometry);
    warpSyntheticPointer(*helper, helperScreen->root, staleGeneration);
    synchronizeXcbConnection(*originalConnection);

    bool rebuilt = false;
    for (std::size_t attempt = 0; attempt < 8U; ++attempt)
    {
        bool workMayRemain = false;
        assert(resources.processEvents(64, &workMayRemain, false) ==
               ConnectionStatus::Ok);
        if (resources.sourceGeometry() == resizedGeometry)
        {
            assert(workMayRemain);
            rebuilt = true;
            break;
        }
    }
    assert(rebuilt);
    assert(resources.valid());
    assert(resources.pointerPositionAvailable());
    assert(resources.fileDescriptor() == originalDescriptor);
    assert(resources.nativeConnection() == originalConnection);

    // A replacement tracker snapshots the current root pointer during
    // construction. Consume only that synchronous snapshot before testing the
    // queued old-generation XI2 event.
    X11PointerPosition replacementSnapshot{};
    if (resources.pendingPointerPosition(replacementSnapshot))
    {
        assert(replacementSnapshot.x >= 0);
        assert(replacementSnapshot.y >= 0);
        assert(static_cast<std::uint32_t>(replacementSnapshot.x) <
               resizedGeometry.widthPixels);
        assert(static_cast<std::uint32_t>(replacementSnapshot.y) <
               resizedGeometry.heightPixels);
        resources.acknowledgePointerPosition(replacementSnapshot, false);
    }

    bool queuedEventsDrained = false;
    for (std::size_t attempt = 0; attempt < 8U; ++attempt)
    {
        bool workMayRemain = false;
        assert(resources.processEvents(64, &workMayRemain, false) ==
               ConnectionStatus::Ok);
        X11PointerPosition stale{};
        assert(!resources.pendingPointerPosition(stale));
        if (!workMayRemain)
        {
            queuedEventsDrained = true;
            break;
        }
    }
    assert(queuedEventsDrained);

    // A genuinely new motion after the replacement subscription must still
    // publish normally through that generation.
    constexpr X11PointerPosition freshGeneration{123, 234};
    warpSyntheticPointer(*helper, helperScreen->root, freshGeneration);
    synchronizeXcbConnection(*originalConnection);

    bool observedFreshMotion = false;
    for (std::size_t attempt = 0; attempt < 8U; ++attempt)
    {
        bool workMayRemain = false;
        assert(resources.processEvents(16, &workMayRemain, false) ==
               ConnectionStatus::Ok);
        X11PointerPosition observed{};
        if (resources.pendingPointerPosition(observed))
        {
            assert(observed == freshGeneration);
            observedFreshMotion = true;
            break;
        }
    }

    assert(observedFreshMotion);
    assert(resources.shouldForwardPointerPosition(freshGeneration));
    resources.acknowledgePointerPosition(freshGeneration, false);
    assert(resources.valid());
    resources.disconnect();
}
#endif

void
syntheticXvfbCaptureR4BgraIngress()
{
    const char *display = syntheticDisplay();
    X11DesktopResources resources(display, kCaptureArenaPixels);
    requireValidResources(resources, "R4 BGRA ingress");
    assert((resources.sourceGeometry() == PixelSize{320, 240}));

    int helperScreenNumber = -1;
    XcbConnection helper = connectHelper(display, helperScreenNumber);
    xcb_screen_t *screen = screenFor(*helper, helperScreenNumber);
    const Rectangle full{0, 0, 320, 240};
    const auto before = resources.damageNotificationCount();
    drawSyntheticPattern(*helper, screen->root, full, kFirstPixelPattern);
    const std::uint64_t captureGeneration =
        requireSyntheticDamageGeneration(resources, before, full);

    constexpr std::uint64_t presentationGeneration = 9101;
    GfxPresentationLifecycle controlLifecycle;
    GfxPresentationLifecycle ingressLifecycle;
    mapR4Surface(controlLifecycle, presentationGeneration, {320, 240});
    mapR4Surface(ingressLifecycle, presentationGeneration, {320, 240});
    X264Avc420SegmentedFrameProducer controlProducer;
    X264Avc420SegmentedFrameProducer ingressProducer;
    openR4Producer(controlProducer, presentationGeneration, {320, 240});
    openR4Producer(ingressProducer, presentationGeneration, {320, 240});

    std::vector<std::byte> controlPixels =
        packedSyntheticPixels(full, kFirstPixelPattern);
    const FramebufferView controlView{
        controlPixels, 320, 240, 320U * 4U};
    GfxAvc420SegmentedFrame controlFrame;
    GfxAvc420SegmentedFrame ingressFrame;
    assert(prepareR4Bgra(
        controlLifecycle, controlProducer, presentationGeneration,
        1U, controlView, controlFrame, 17));

    R4IngressConsumer consumer{
        &ingressLifecycle, &ingressProducer, &ingressFrame,
        presentationGeneration, captureGeneration, 1U, 17};
    assert(resources.consumeR4Frame(
        captureGeneration, consumer.callbacks()));
    assert(consumer.calls == 1U);
    assert(controlFrame.wireBytes().size() ==
           ingressFrame.wireBytes().size());
    assert(std::equal(
        controlFrame.wireBytes().begin(), controlFrame.wireBytes().end(),
        ingressFrame.wireBytes().begin()));

    resources.disconnect();
    assert(resources.captureGeneration() == 0);
    assert(ingressFrame.valid());
    assert(controlProducer.cancelUnwrittenDelivery(
        controlLifecycle, controlFrame));
    assert(ingressProducer.cancelUnwrittenDelivery(
        ingressLifecycle, ingressFrame));
}

void
syntheticXvfbCaptureR4StrideLayoutDenials()
{
    constexpr PixelSize visible{16, 16};
    GfxPresentationLifecycle lifecycle;
    constexpr std::uint64_t presentationGeneration = 9200;
    mapR4Surface(lifecycle, presentationGeneration, visible);
    X264Avc420SegmentedFrameProducer producer;
    openR4Producer(producer, presentationGeneration, visible);

    std::vector<std::byte> exact(16U * 16U * 4U);
    GfxAvc420SegmentedFrame denied;
    const FramebufferView shortStride{exact, 16, 16, 63};
    assert(!prepareR4Bgra(
        lifecycle, producer, presentationGeneration, 1U,
        shortStride, denied));
    const FramebufferView shortBuffer{
        std::span<const std::byte>(exact).first(exact.size() - 1U),
        16, 16, 64};
    assert(!prepareR4Bgra(
        lifecycle, producer, presentationGeneration, 1U,
        shortBuffer, denied));
    FramebufferView wrongGeometry{exact, 16, 16, 64};
    wrongGeometry.widthPixels =
        std::numeric_limits<std::uint32_t>::max();
    assert(!prepareR4Bgra(
        lifecycle, producer, presentationGeneration, 1U,
        wrongGeometry, denied));
    assert(!denied.valid());

    X11DesktopResources bounded(syntheticDisplay(), 320U);
    requireValidResources(bounded, "R4 bounded arena");
    assert((bounded.sourceGeometry() == PixelSize{320, 240}));
    GfxPresentationLifecycle boundedLifecycle;
    mapR4Surface(
        boundedLifecycle, presentationGeneration + 1U, {320, 240});
    X264Avc420SegmentedFrameProducer boundedProducer;
    openR4Producer(
        boundedProducer, presentationGeneration + 1U, {320, 240});
    GfxAvc420SegmentedFrame boundedFrame;
    const std::uint64_t generation = bounded.captureGeneration();
    R4IngressConsumer consumer{
        &boundedLifecycle, &boundedProducer, &boundedFrame,
        presentationGeneration + 1U, generation, 2U, 0};
    assert(!bounded.consumeR4Frame(generation, consumer.callbacks()));
    assert(consumer.calls == 0U);
    assert(!boundedFrame.valid());
    assert(!bounded.valid());
}

void
syntheticXvfbCaptureR4GenerationRetirement()
{
    const char *display = syntheticDisplay();
    X11DesktopResources resources(display, kCaptureArenaPixels);
    requireValidResources(resources, "R4 generation retirement");
    assert((resources.sourceGeometry() == PixelSize{320, 240}));

    int helperScreenNumber = -1;
    XcbConnection helper = connectHelper(display, helperScreenNumber);
    xcb_screen_t *screen = screenFor(*helper, helperScreenNumber);
    const Rectangle firstFull{0, 0, 320, 240};
    const auto before = resources.damageNotificationCount();
    drawSyntheticPattern(
        *helper, screen->root, firstFull, kFirstPixelPattern);
    const std::uint64_t firstGeneration =
        requireSyntheticDamageGeneration(resources, before, firstFull);

    constexpr std::uint64_t oldPresentationGeneration = 9301;
    GfxPresentationLifecycle oldLifecycle;
    mapR4Surface(oldLifecycle, oldPresentationGeneration, {320, 240});
    X264Avc420SegmentedFrameProducer oldProducer;
    openR4Producer(oldProducer, oldPresentationGeneration, {320, 240});
    GfxAvc420SegmentedFrame firstFrame;
    R4IngressConsumer firstConsumer{
        &oldLifecycle, &oldProducer, &firstFrame,
        oldPresentationGeneration, firstGeneration, 10U, 0};
    assert(resources.consumeR4Frame(
        firstGeneration, firstConsumer.callbacks()));
    assert(oldProducer.cancelUnwrittenDelivery(
        oldLifecycle, firstFrame));

    constexpr PixelSize resized{256, 192};
    requireSyntheticRandrRebuild(
        resources, *helper, screen->root, resized);
    const std::uint64_t replacementGeneration =
        resources.captureGeneration();
    assert(replacementGeneration == firstGeneration + 1U);

    GfxAvc420SegmentedFrame staleFrame;
    R4IngressConsumer staleConsumer{
        &oldLifecycle, &oldProducer, &staleFrame,
        oldPresentationGeneration, firstGeneration, 11U, 0};
    assert(!resources.consumeR4Frame(
        firstGeneration, staleConsumer.callbacks()));
    assert(staleConsumer.calls == 0U);
    assert(!resources.capture(
        firstGeneration, {0, 0, 256, 192}).valid());
    assert(resources.valid());

    R4IngressConsumer wrongGeometryConsumer{
        &oldLifecycle, &oldProducer, &staleFrame,
        oldPresentationGeneration, replacementGeneration, 11U, 0};
    assert(!resources.consumeR4Frame(
        replacementGeneration, wrongGeometryConsumer.callbacks()));
    assert(wrongGeometryConsumer.calls == 1U);
    assert(!staleFrame.valid());

    const Rectangle freshFull{0, 0, 256, 192};
    const auto freshBefore = resources.damageNotificationCount();
    drawSyntheticPattern(
        *helper, screen->root, freshFull, kSecondPixelPattern);
    const std::uint64_t freshGeneration =
        requireSyntheticDamageGeneration(
            resources, freshBefore, freshFull);
    assert(freshGeneration == replacementGeneration);

    constexpr std::uint64_t freshPresentationGeneration = 9302;
    GfxPresentationLifecycle freshLifecycle;
    mapR4Surface(freshLifecycle, freshPresentationGeneration, resized);
    X264Avc420SegmentedFrameProducer freshProducer;
    openR4Producer(freshProducer, freshPresentationGeneration, resized);
    GfxAvc420SegmentedFrame freshFrame;
    R4IngressConsumer freshConsumer{
        &freshLifecycle, &freshProducer, &freshFrame,
        freshPresentationGeneration, freshGeneration, 12U, 0};
    assert(resources.consumeR4Frame(
        freshGeneration, freshConsumer.callbacks()));
    assert(freshFrame.valid());
    assert(freshProducer.cancelUnwrittenDelivery(
        freshLifecycle, freshFrame));

    resources.disconnect();
    assert(resources.captureGeneration() == 0);
    DamageRegion disconnectedDamage;
    std::uint64_t disconnectedGeneration = 99;
    assert(!resources.snapshotDamage(
        disconnectedDamage, disconnectedGeneration));
    assert(disconnectedGeneration == 0);
    GfxAvc420SegmentedFrame postDisconnect;
    R4IngressConsumer postDisconnectConsumer{
        &freshLifecycle, &freshProducer, &postDisconnect,
        freshPresentationGeneration, replacementGeneration, 13U, 0};
    assert(!resources.consumeR4Frame(
        replacementGeneration, postDisconnectConsumer.callbacks()));
    assert(postDisconnectConsumer.calls == 0U);
}

void
syntheticXvfbRandrRebuild()
{
    const char *display = syntheticDisplay();
    X11DesktopResources resources(display, kCaptureArenaPixels);
    assert(resources.valid());
    assert(resources.randrAvailable());
    const int originalDescriptor = resources.fileDescriptor();
    assert(originalDescriptor >= 0);
    assert((resources.sourceGeometry() == PixelSize{1280, 720}));

    int helperScreenNumber = -1;
    XcbConnection helper = connectHelper(display, helperScreenNumber);
    xcb_screen_t *helperScreen = screenFor(*helper, helperScreenNumber);
    constexpr PixelSize resizedGeometry{1024, 600};
    disableRandrCrtcsAndResize(
        *helper, helperScreen->root, resizedGeometry);
    xcb_connection_t *connection = resources.nativeConnection();
    assert(connection != nullptr);
    synchronizeXcbConnection(*connection);

    bool rebuilt = false;
    for (std::size_t attempt = 0; attempt < 8U; ++attempt)
    {
        bool workMayRemain = false;
        assert(resources.processEvents(8, &workMayRemain, false) ==
               ConnectionStatus::Ok);
        if (resources.sourceGeometry() == resizedGeometry)
        {
            rebuilt = true;
            assert(workMayRemain);
            break;
        }
        if (!workMayRemain)
        {
            break;
        }
    }

    assert(rebuilt);
    assert(resources.valid());
    assert(resources.fileDescriptor() == originalDescriptor);

    const std::uint64_t notificationsAfterResize =
        resources.damageNotificationCount();
    clearSyntheticRoot(*helper, helperScreen->root);
    synchronizeXcbConnection(*connection);

    bool routedPostResizeDamage = false;
    for (std::size_t attempt = 0; attempt < 8U; ++attempt)
    {
        bool workMayRemain = false;
        assert(resources.processEvents(8, &workMayRemain, false) ==
               ConnectionStatus::Ok);
        if (resources.damageNotificationCount() > notificationsAfterResize)
        {
            routedPostResizeDamage = true;
            break;
        }
        if (!workMayRemain)
        {
            break;
        }
    }

    assert(routedPostResizeDamage);
    assert(resources.damagePending());
    assert(resources.valid());
    assert(resources.fileDescriptor() == originalDescriptor);
    resources.disconnect();
}

} // namespace

int
main(int argc, char **argv)
{
    if (argc == 1)
    {
        connectionDenial();
        return 0;
    }
    assert(argc == 2);
    const std::string_view behavior(argv[1]);
    if (behavior == "lifecycle")
    {
        syntheticXvfbLifecycle();
        return 0;
    }
    if (behavior == "event-routing")
    {
        syntheticXvfbEventRouting();
        return 0;
    }
    if (behavior == "randr-rebuild")
    {
        syntheticXvfbRandrRebuild();
        return 0;
    }
    if (behavior == "pointer-capability-denials")
    {
        syntheticXvfbPointerCapabilityDenials();
        return 0;
    }
#if defined(RDP_TEST_XINPUT_POINTER)
    if (behavior == "pointer-event-routing")
    {
        syntheticXvfbPointerEventRouting();
        return 0;
    }
    if (behavior == "pointer-randr-rebuild")
    {
        syntheticXvfbPointerRandrRebuild();
        return 0;
    }
    if (behavior == "pointer-randr-stale-motion-isolation")
    {
        syntheticXvfbPointerRandrStaleMotionIsolation();
        return 0;
    }
#endif
    if (behavior == "r4-read-boundary")
    {
        syntheticXvfbR4ReadBoundary();
        return 0;
    }
    if (behavior == "capture-r4-bgra-ingress")
    {
        syntheticXvfbCaptureR4BgraIngress();
        return 0;
    }
    if (behavior == "capture-r4-stride-layout-denials")
    {
        syntheticXvfbCaptureR4StrideLayoutDenials();
        return 0;
    }
    if (behavior == "capture-r4-generation-retirement")
    {
        syntheticXvfbCaptureR4GenerationRetirement();
        return 0;
    }
    if (behavior == "capture-pixel-parity")
    {
        syntheticXvfbCapturePixelParity();
        return 0;
    }
    if (behavior == "randr-capture-generation")
    {
        syntheticXvfbRandrCaptureGeneration();
        return 0;
    }
    if (behavior == "randr-stale-damage-isolation")
    {
        syntheticXvfbRandrStaleDamageIsolation();
        return 0;
    }
    if (behavior == "capture-terminal-denial")
    {
        syntheticXvfbCaptureTerminalDenial();
        return 0;
    }

    assert(false && "unknown X11 desktop resource behavior");
    return 1;
}
