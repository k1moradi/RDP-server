// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows/windows_dxgi_capture_cycle.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>

using namespace rdp_server::windows;

namespace
{

struct FakePointerCapture final
{
    std::array<std::byte, 4> framePixels{
        std::byte{0x10}, std::byte{0x20},
        std::byte{0x30}, std::byte{0xff}};
    std::array<std::byte, 64> shapePixels{};
    std::byte frameToken{};
    WindowsDxgiFrameInfo frameInfo{};
    WindowsDxgiPointerShapeDescription shapeDescription{
        WindowsDxgiPointerShapeType::color, 2, 2, 8, 1, 1};
    WindowsDxgiPointerShapeReadResult shapeResult{
        WindowsDxgiPointerShapeReadResult::ready};
    WindowsD3D11MapResult mapResult{WindowsD3D11MapResult::mapped};
    std::size_t requiredShapeBytes{16};
    std::uint64_t sessionGeneration{11};
    std::uint64_t deviceGeneration{23};
    unsigned acquisitions{};
    unsigned releases{};
    unsigned maps{};
    unsigned unmaps{};
    unsigned shapeReads{};
    unsigned generationReads{};
    bool failGenerationRead{};
    bool rotateGenerationDuringShape{};
    bool cancelDuringShape{};
    bool reenterDuringShape{};
    bool teardownDeferredDuringShape{};
    WindowsCapturePointerResult reentrantResult{
        WindowsCapturePointerResult::failed};
    WindowsDxgiCaptureCycle *cycle{};

    static WindowsDxgiAcquireResult acquire(
        void *context, std::uint32_t, void *&resource,
        WindowsDxgiFrameInfo &frameInfo) noexcept
    {
        auto &self = *static_cast<FakePointerCapture *>(context);
        ++self.acquisitions;
        resource = &self.frameToken;
        frameInfo = self.frameInfo;
        return WindowsDxgiAcquireResult::acquired;
    }

    static WindowsDxgiReleaseResult release(
        void *context, void *resource) noexcept
    {
        auto &self = *static_cast<FakePointerCapture *>(context);
        assert(resource == &self.frameToken);
        ++self.releases;
        return WindowsDxgiReleaseResult::released;
    }

    static WindowsD3D11MapResult map(
        void *context, void *resource,
        WindowsD3D11MappedData &output) noexcept
    {
        auto &self = *static_cast<FakePointerCapture *>(context);
        assert(resource == &self.frameToken);
        ++self.maps;
        if (self.mapResult == WindowsD3D11MapResult::mapped)
        {
            output = {self.framePixels.data(), self.framePixels.size(),
                      {1, 1}, 4, &self.frameToken};
        }
        return self.mapResult;
    }

    static void unmap(void *context, void *handle) noexcept
    {
        auto &self = *static_cast<FakePointerCapture *>(context);
        assert(handle == &self.frameToken);
        ++self.unmaps;
    }

    static bool readGeneration(
        void *context, WindowsCaptureGeneration &generation) noexcept
    {
        auto &self = *static_cast<FakePointerCapture *>(context);
        ++self.generationReads;
        if (self.failGenerationRead)
        {
            return false;
        }
        generation = {self.sessionGeneration, self.deviceGeneration};
        return true;
    }

    static WindowsDxgiPointerShapeReadResult readShape(
        void *context, std::span<std::byte> destination,
        std::size_t &requiredBytes,
        WindowsDxgiPointerShapeDescription &description) noexcept
    {
        auto &self = *static_cast<FakePointerCapture *>(context);
        ++self.shapeReads;

        if (self.reenterDuringShape && self.cycle != nullptr)
        {
            WindowsCapturePointerUpdate nested{};
            self.reentrantResult =
                self.cycle->readFramePointerUpdate(nested);
        }
        if (self.cancelDuringShape && self.cycle != nullptr)
        {
            self.cycle->cancel();
            self.teardownDeferredDuringShape =
                self.unmaps == 0 && self.releases == 0;
        }
        if (self.rotateGenerationDuringShape)
        {
            ++self.deviceGeneration;
        }

        requiredBytes = self.requiredShapeBytes;
        description = self.shapeDescription;
        if (self.shapeResult != WindowsDxgiPointerShapeReadResult::ready)
        {
            return self.shapeResult;
        }
        if (requiredBytes > destination.size() ||
            requiredBytes > self.shapePixels.size())
        {
            return WindowsDxgiPointerShapeReadResult::moreData;
        }
        std::copy_n(self.shapePixels.begin(), requiredBytes,
                    destination.begin());
        return WindowsDxgiPointerShapeReadResult::ready;
    }

    [[nodiscard]] WindowsDxgiFrameCallbacks frames() noexcept
    {
        return {this, &acquire, &release};
    }

    [[nodiscard]] WindowsD3D11StagingCallbacks staging() noexcept
    {
        return {this, &map, &unmap};
    }

    [[nodiscard]] WindowsCaptureGenerationReader generations() noexcept
    {
        return {this, &readGeneration};
    }

    [[nodiscard]] WindowsDxgiPointerShapeReadCallbacks pointerShapes() noexcept
    {
        return {this, &readShape};
    }
};

[[nodiscard]] WindowsDesktopLayout pointerLayout() noexcept
{
    WindowsDesktopLayout layout{};
    layout.monitorCount = 1;
    layout.virtualBounds = {-100, 50, 800, 600};
    layout.monitors[0] = layout.virtualBounds;
    return layout;
}

constexpr WindowsCaptureGeneration kPinnedGeneration{11, 23};

void seedColorShape(FakePointerCapture &backend) noexcept
{
    backend.requiredShapeBytes = 16;
    backend.shapeDescription = {
        WindowsDxgiPointerShapeType::color, 2, 2, 8, 1, 1};
    for (std::size_t index = 0; index < backend.requiredShapeBytes; ++index)
    {
        backend.shapePixels[index] =
            static_cast<std::byte>(0x20U + static_cast<unsigned>(index));
    }
}

void assertTerminalRelease(const FakePointerCapture &backend) noexcept
{
    assert(backend.unmaps == 1);
    assert(backend.releases == 1);
}

} // namespace

void windowsDxgiPointerShapeOwnedLifetime()
{
    FakePointerCapture backend{};
    seedColorShape(backend);
    backend.frameInfo = {true, true, 10, 20, 16};
    backend.reenterDuringShape = true;

    WindowsDxgiCaptureCycle cycle(
        pointerLayout(), backend.frames(), backend.staging(), {},
        backend.generations(), kPinnedGeneration,
        backend.pointerShapes(), pointerLayout().monitors[0]);
    backend.cycle = &cycle;

    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    WindowsCapturePointerUpdate update{};
    assert(cycle.readFramePointerUpdate(update) ==
           WindowsCapturePointerResult::ready);
    assert(backend.reentrantResult == WindowsCapturePointerResult::busy);
    assert(update.generation == kPinnedGeneration);
    assert(update.positionChanged && update.visible);
    assert((update.nativeTopLeft == WindowsNativePoint{-90, 70}));
    assert(update.shapeChanged && update.shape.valid());
    assert(update.shape.type == WindowsDxgiPointerShapeType::color);
    assert(update.shape.widthPixels == 2 && update.shape.heightPixels == 2);
    assert(update.shape.pitchBytes == 8);
    assert(update.shape.hotspotX == 1 && update.shape.hotspotY == 1);
    assert(update.shape.pixels().size() == 16);
    const std::byte ownedFirstPixel = update.shape.pixels().front();
    backend.shapePixels[0] = std::byte{0xee};
    assert(update.shape.pixels().front() == ownedFirstPixel);
    assert(cycle.readFramePointerUpdate(update) ==
           WindowsCapturePointerResult::noUpdate);
    assert(backend.shapeReads == 1);
    assert(cycle.releaseFrame());
    assert(update.shape.valid() &&
           update.shape.pixels().front() == ownedFirstPixel);

    // Visibility/position updates do not force a duplicate shape read.
    backend.frameInfo = {true, false, 777, 888, 0};
    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    WindowsCapturePointerUpdate hidden{};
    assert(cycle.readFramePointerUpdate(hidden) ==
           WindowsCapturePointerResult::ready);
    assert(hidden.positionChanged && !hidden.visible && !hidden.shapeChanged);
    assert((hidden.nativeTopLeft == WindowsNativePoint{}));
    assert(hidden.generation == kPinnedGeneration);
    assert(backend.shapeReads == 1);
    assert(cycle.releaseFrame());

    // A shape can change without a mouse-position timestamp. Preserve it as
    // shape-only state instead of fabricating a visibility/position update.
    seedColorShape(backend);
    backend.frameInfo = {false, false, 0, 0, 16};
    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    WindowsCapturePointerUpdate shapeOnly{};
    assert(cycle.readFramePointerUpdate(shapeOnly) ==
           WindowsCapturePointerResult::ready);
    assert(!shapeOnly.positionChanged);
    assert(shapeOnly.shapeChanged && shapeOnly.shape.valid());
    assert(backend.shapeReads == 2);
    assert(cycle.releaseFrame());

    // Monochrome Height contains two equally-sized AND/XOR planes; the
    // independently owned logical shape height is half the scanline count.
    backend.frameInfo = {true, true, -1, -2, 4};
    backend.requiredShapeBytes = 4;
    backend.shapeDescription = {
        WindowsDxgiPointerShapeType::monochrome, 8, 4, 1, 0, 1};
    backend.shapePixels[0] = std::byte{0xff};
    backend.shapePixels[1] = std::byte{0x00};
    backend.shapePixels[2] = std::byte{0x55};
    backend.shapePixels[3] = std::byte{0xaa};
    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    WindowsCapturePointerUpdate monochrome{};
    assert(cycle.readFramePointerUpdate(monochrome) ==
           WindowsCapturePointerResult::ready);
    assert(monochrome.shapeChanged && monochrome.shape.valid());
    assert(monochrome.shape.type ==
           WindowsDxgiPointerShapeType::monochrome);
    assert(monochrome.shape.widthPixels == 8);
    assert(monochrome.shape.heightPixels == 2);
    assert(monochrome.shape.pitchBytes == 1);
    assert((monochrome.nativeTopLeft == WindowsNativePoint{-101, 48}));
    assert(cycle.releaseFrame());

    // Masked color accepts only the DXGI-defined binary alpha mask.
    backend.frameInfo = {true, true, 0, 0, 4};
    backend.requiredShapeBytes = 4;
    backend.shapeDescription = {
        WindowsDxgiPointerShapeType::maskedColor, 1, 1, 4, 0, 0};
    backend.shapePixels[0] = std::byte{0x01};
    backend.shapePixels[1] = std::byte{0x02};
    backend.shapePixels[2] = std::byte{0x03};
    backend.shapePixels[3] = std::byte{0xff};
    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    WindowsCapturePointerUpdate masked{};
    assert(cycle.readFramePointerUpdate(masked) ==
           WindowsCapturePointerResult::ready);
    assert(masked.shapeChanged && masked.shape.valid());
    assert(masked.shape.type ==
           WindowsDxgiPointerShapeType::maskedColor);
    assert(cycle.releaseFrame());

    // A cursor shape cannot be lost when the GPU staging map is not ready:
    // it is copied before the lease is released and remains consumable.
    backend.mapResult = WindowsD3D11MapResult::notReady;
    seedColorShape(backend);
    backend.frameInfo = {true, true, 3, 4, 16};
    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::notReady);
    assert(backend.releases == 6);
    WindowsCapturePointerUpdate deferred{};
    assert(cycle.readFramePointerUpdate(deferred) ==
           WindowsCapturePointerResult::ready);
    assert(deferred.shapeChanged && deferred.shape.valid());
    assert((deferred.nativeTopLeft == WindowsNativePoint{-97, 54}));
    backend.mapResult = WindowsD3D11MapResult::mapped;

    // If R4 has not consumed a shape yet, a newer position-only frame must
    // merge with (not discard) that independently owned pending shape.
    backend.frameInfo = {true, true, 5, 6, 16};
    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    assert(cycle.releaseFrame());
    backend.frameInfo = {true, true, 7, 8, 0};
    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    assert(cycle.releaseFrame());
    WindowsCapturePointerUpdate merged{};
    assert(cycle.readFramePointerUpdate(merged) ==
           WindowsCapturePointerResult::ready);
    assert(merged.positionChanged && merged.shapeChanged && merged.shape.valid());
    assert((merged.nativeTopLeft == WindowsNativePoint{-93, 58}));

    // No mouse update means no cursor publication and no native shape call.
    backend.frameInfo = {};
    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    WindowsCapturePointerUpdate noUpdate{};
    assert(cycle.readFramePointerUpdate(noUpdate) ==
           WindowsCapturePointerResult::noUpdate);
    assert(cycle.readFramePointerUpdate(noUpdate) ==
           WindowsCapturePointerResult::noUpdate);
    assert(backend.shapeReads == 6);
    assert(cycle.releaseFrame());
    assert(!cycle.closed());
}

void windowsDxgiPointerShapeGenerationDenials()
{
    // A shape larger than the independent cursor budget revokes the frame
    // before allocation or callback and leaves prior caller state unchanged.
    {
        FakePointerCapture backend{};
        backend.frameInfo = {
            true, true, 0, 0,
            static_cast<std::uint32_t>(
                kMaximumWindowsDxgiPointerShapeBytes + 1U)};
        WindowsDxgiCaptureCycle cycle(
            pointerLayout(), backend.frames(), backend.staging(), {},
            backend.generations(), kPinnedGeneration,
            backend.pointerShapes(), pointerLayout().monitors[0]);
        backend.cycle = &cycle;
        WindowsCapturePointerUpdate output{};
        output.generation = {91, 92};
        output.visible = true;
        output.nativeTopLeft = {7, 9};
        assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::failed);
        assert(cycle.readFramePointerUpdate(output) ==
               WindowsCapturePointerResult::closed);
        assert(cycle.closed());
        assert(output.generation == (WindowsCaptureGeneration{91, 92}));
        assert((output.nativeTopLeft == WindowsNativePoint{7, 9}));
        assert(backend.shapeReads == 0);
        assertTerminalRelease(backend);
    }

    // Malformed shape metadata and unsupported type are terminal.
    for (int denial = 0; denial < 5; ++denial)
    {
        FakePointerCapture backend{};
        seedColorShape(backend);
        backend.frameInfo = {true, true, 0, 0, 16};
        if (denial == 0)
            backend.shapeDescription.hotspotX = -1;
        else if (denial == 1)
            backend.shapeDescription.pitchBytes = 7;
        else if (denial == 2)
            backend.requiredShapeBytes = 15;
        else if (denial == 3)
            backend.shapeDescription.type =
                static_cast<WindowsDxgiPointerShapeType>(99);
        else
        {
            backend.shapeDescription = {
                WindowsDxgiPointerShapeType::monochrome, 8, 3, 1, 0, 0};
            backend.requiredShapeBytes = 3;
            backend.frameInfo.pointerShapeBufferSize = 3;
        }

        WindowsDxgiCaptureCycle cycle(
            pointerLayout(), backend.frames(), backend.staging(), {},
            backend.generations(), kPinnedGeneration,
            backend.pointerShapes(), pointerLayout().monitors[0]);
        backend.cycle = &cycle;
        assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::failed);
        assert(cycle.closed());
        assertTerminalRelease(backend);
    }

    // Masked-color alpha has binary replace/XOR semantics only.
    {
        FakePointerCapture backend{};
        backend.frameInfo = {true, true, 0, 0, 4};
        backend.requiredShapeBytes = 4;
        backend.shapeDescription = {
            WindowsDxgiPointerShapeType::maskedColor, 1, 1, 4, 0, 0};
        backend.shapePixels[3] = std::byte{0x7f};
        WindowsDxgiCaptureCycle cycle(
            pointerLayout(), backend.frames(), backend.staging(), {},
            backend.generations(), kPinnedGeneration,
            backend.pointerShapes(), pointerLayout().monitors[0]);
        backend.cycle = &cycle;
        assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::failed);
        assert(cycle.closed());
        assertTerminalRelease(backend);
    }

    for (const auto result : {
             WindowsDxgiPointerShapeReadResult::moreData,
             WindowsDxgiPointerShapeReadResult::accessLost,
             WindowsDxgiPointerShapeReadResult::failed})
    {
        FakePointerCapture backend{};
        seedColorShape(backend);
        backend.frameInfo = {true, true, 0, 0, 16};
        backend.shapeResult = result;
        WindowsDxgiCaptureCycle cycle(
            pointerLayout(), backend.frames(), backend.staging(), {},
            backend.generations(), kPinnedGeneration,
            backend.pointerShapes(), pointerLayout().monitors[0]);
        backend.cycle = &cycle;
        const auto observed = cycle.captureFrame(0);
        if (result == WindowsDxgiPointerShapeReadResult::accessLost)
            assert(observed == WindowsCaptureCycleResult::accessLost);
        else
            assert(observed == WindowsCaptureCycleResult::failed);
        assert(cycle.closed());
        assertTerminalRelease(backend);
    }

    // A device epoch switch during the native read discards copied bytes.
    {
        FakePointerCapture backend{};
        seedColorShape(backend);
        backend.frameInfo = {true, true, 0, 0, 16};
        backend.rotateGenerationDuringShape = true;
        WindowsDxgiCaptureCycle cycle(
            pointerLayout(), backend.frames(), backend.staging(), {},
            backend.generations(), kPinnedGeneration,
            backend.pointerShapes(), pointerLayout().monitors[0]);
        backend.cycle = &cycle;
        assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::closed);
        assert(cycle.closed());
        assertTerminalRelease(backend);
    }

    // An independently copied update still cannot cross a later generation
    // revocation while waiting for R4 to consume it.
    {
        FakePointerCapture backend{};
        seedColorShape(backend);
        backend.frameInfo = {true, true, 0, 0, 16};
        WindowsDxgiCaptureCycle cycle(
            pointerLayout(), backend.frames(), backend.staging(), {},
            backend.generations(), kPinnedGeneration,
            backend.pointerShapes(), pointerLayout().monitors[0]);
        backend.cycle = &cycle;
        assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
        assert(cycle.releaseFrame());
        ++backend.deviceGeneration;
        WindowsCapturePointerUpdate output{};
        output.generation = {77, 88};
        assert(cycle.readFramePointerUpdate(output) ==
               WindowsCapturePointerResult::closed);
        assert(output.generation == (WindowsCaptureGeneration{77, 88}));
        assert(cycle.closed());
    }

    // Cancellation inside GetFramePointerShape is deferred until the callback
    // returns; it never tears down the duplication under the callback.
    {
        FakePointerCapture backend{};
        seedColorShape(backend);
        backend.frameInfo = {true, true, 0, 0, 16};
        backend.cancelDuringShape = true;
        WindowsDxgiCaptureCycle cycle(
            pointerLayout(), backend.frames(), backend.staging(), {},
            backend.generations(), kPinnedGeneration,
            backend.pointerShapes(), pointerLayout().monitors[0]);
        backend.cycle = &cycle;
        assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::closed);
        assert(backend.teardownDeferredDuringShape);
        assertTerminalRelease(backend);
    }

    // Pointer integration cannot opt out of the existing nonzero generation
    // reader or target-output identity.
    {
        FakePointerCapture backend{};
        WindowsDxgiCaptureCycle noGeneration(
            pointerLayout(), backend.frames(), backend.staging(), {},
            {}, {}, backend.pointerShapes(), pointerLayout().monitors[0]);
        assert(noGeneration.closed());

        auto wrongLayout = pointerLayout();
        PortableRectangle wrongOutput{0, 0, 1, 1};
        WindowsDxgiCaptureCycle wrongTarget(
            wrongLayout, backend.frames(), backend.staging(), {},
            backend.generations(), kPinnedGeneration,
            backend.pointerShapes(), wrongOutput);
        assert(wrongTarget.closed());
    }

    // Legacy cycles without the pointer callback stay usable for existing
    // frame tests, but cannot publish generation-safe cursor updates.
    {
        FakePointerCapture backend{};
        backend.frameInfo = {true, true, 0, 0, 0};
        WindowsDxgiCaptureCycle legacy(
            pointerLayout(), backend.frames(), backend.staging(), {},
            backend.generations(), kPinnedGeneration);
        assert(legacy.captureFrame(0) == WindowsCaptureCycleResult::mapped);
        WindowsCapturePointerUpdate output{};
        assert(legacy.readFramePointerUpdate(output) ==
               WindowsCapturePointerResult::unavailable);
        assert(legacy.releaseFrame());
    }

    // A visible DXGI position is output-relative. Checked translation must
    // reject signed overflow rather than wrap virtual-screen coordinates.
    {
        FakePointerCapture backend{};
        WindowsDesktopLayout edge{};
        edge.monitorCount = 1;
        edge.virtualBounds = {
            std::numeric_limits<std::int32_t>::max() - 1, 0, 1, 1};
        edge.monitors[0] = edge.virtualBounds;
        backend.frameInfo = {true, true, 10, 0, 0};
        WindowsDxgiCaptureCycle cycle(
            edge, backend.frames(), backend.staging(), {},
            backend.generations(), kPinnedGeneration,
            backend.pointerShapes(), edge.monitors[0]);
        backend.cycle = &cycle;
        assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::failed);
        assert(cycle.closed());
        assertTerminalRelease(backend);
    }
}
