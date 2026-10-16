// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "windows_cursor_snapshot.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

#ifdef _WIN32
struct IDXGIOutputDuplication;
#endif

namespace rdp_server::windows
{

// Cursor shape data is tiny relative to a desktop frame, but remains bounded
// independently so a corrupt/driver-supplied size cannot trigger unbounded
// allocation. 256x256x4 is 256 KiB; allow another factor of two for pitch
// padding and the paired monochrome AND/XOR planes.
inline constexpr std::size_t kMaximumWindowsDxgiPointerShapeBytes =
    512U * 1024U;

enum class WindowsDxgiPointerShapeType
{
    monochrome,
    color,
    maskedColor,
};

enum class WindowsDxgiPointerShapeReadResult
{
    ready,
    moreData,
    accessLost,
    invalid,
    failed,
};

// Portable mirror of DXGI_OUTDUPL_POINTER_SHAPE_INFO. For monochrome shapes,
// heightScanlines includes the AND plane followed by the same-height XOR
// plane. For color/masked-color shapes it is the logical pixel height.
struct WindowsDxgiPointerShapeDescription final
{
    WindowsDxgiPointerShapeType type{WindowsDxgiPointerShapeType::color};
    std::uint32_t widthPixels{};
    std::uint32_t heightScanlines{};
    std::uint32_t pitchBytes{};
    std::int32_t hotspotX{};
    std::int32_t hotspotY{};
};

// Callback seam for GetFramePointerShape. It is legal only while the SAME
// IDXGIOutputDuplication frame is held. The callback writes at most
// destination.size() bytes and reports the actual required byte count.
struct WindowsDxgiPointerShapeReadCallbacks final
{
    void *context{};
    WindowsDxgiPointerShapeReadResult (*read)(
        void *context, std::span<std::byte> destination,
        std::size_t &requiredBytes,
        WindowsDxgiPointerShapeDescription &description) noexcept{};
};

// Move-only independently owned DXGI cursor shape. R4 may retain/move this
// after the acquired frame is released. pixels() exposes only initialized
// bytes; no borrowed DXGI memory escapes.
struct WindowsDxgiPointerShape final
{
    WindowsDxgiPointerShapeType type{WindowsDxgiPointerShapeType::color};
    std::uint32_t widthPixels{};
    std::uint32_t heightPixels{};
    std::uint32_t pitchBytes{};
    std::uint32_t hotspotX{};
    std::uint32_t hotspotY{};
    std::unique_ptr<std::byte[]> storage{};
    std::size_t byteCount{};

    WindowsDxgiPointerShape() noexcept = default;
    WindowsDxgiPointerShape(const WindowsDxgiPointerShape &) = delete;
    WindowsDxgiPointerShape &operator=(const WindowsDxgiPointerShape &) = delete;
    WindowsDxgiPointerShape(WindowsDxgiPointerShape &&) noexcept = default;
    WindowsDxgiPointerShape &operator=(WindowsDxgiPointerShape &&) noexcept = default;

    [[nodiscard]] std::span<const std::byte> pixels() const noexcept
    {
        return {storage.get(), byteCount};
    }

    [[nodiscard]] bool valid() const noexcept
    {
        return storage != nullptr && byteCount != 0 &&
               widthPixels != 0 && heightPixels != 0 &&
               pitchBytes != 0 && hotspotX < widthPixels &&
               hotspotY < heightPixels;
    }
};

// Allocate exactly the bounded frame-advertised size, read the native shape,
// validate type/dimensions/pitch/hotspot/byte count, and transactionally move
// independent bytes into output. On failure output is unchanged.
[[nodiscard]] WindowsDxgiPointerShapeReadResult readWindowsDxgiPointerShape(
    WindowsDxgiPointerShapeReadCallbacks callbacks,
    std::size_t advertisedBytes,
    WindowsDxgiPointerShape &output) noexcept;

#ifdef _WIN32
// Borrows a duplication already owned by the authorized native capture owner.
// Calling the returned callback without an outstanding AcquireNextFrame lease
// is a DXGI invalid-call failure; this function grants no desktop access.
[[nodiscard]] WindowsDxgiPointerShapeReadCallbacks
windowsDxgiPointerShapeReadCallbacks(
    IDXGIOutputDuplication &duplication) noexcept;
#endif

} // namespace rdp_server::windows
