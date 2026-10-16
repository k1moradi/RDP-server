// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows_dxgi_pointer_shape.h"

#include <limits>
#include <new>
#include <utility>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <dxgi1_2.h>
#endif

namespace rdp_server::windows
{
namespace
{

[[nodiscard]] bool validateShape(
    const WindowsDxgiPointerShapeDescription &description,
    std::size_t requiredBytes,
    const std::byte *pixels,
    std::uint32_t &logicalHeight) noexcept
{
    if (description.widthPixels == 0 ||
        description.heightScanlines == 0 ||
        description.widthPixels > kMaximumWindowsCursorDimension ||
        description.pitchBytes == 0 ||
        description.hotspotX < 0 || description.hotspotY < 0)
    {
        return false;
    }

    if (description.type != WindowsDxgiPointerShapeType::monochrome &&
        description.type != WindowsDxgiPointerShapeType::color &&
        description.type != WindowsDxgiPointerShapeType::maskedColor)
    {
        return false;
    }

    std::uint32_t scanlineCount = description.heightScanlines;
    if (description.type == WindowsDxgiPointerShapeType::monochrome)
    {
        // DXGI monochrome data is an AND plane followed by an equally-sized
        // XOR plane. The reported scanline count therefore has two halves.
        if ((scanlineCount % 2U) != 0)
        {
            return false;
        }
        logicalHeight = scanlineCount / 2U;
        if (logicalHeight == 0 ||
            logicalHeight > kMaximumWindowsCursorDimension)
        {
            return false;
        }
    }
    else
    {
        logicalHeight = scanlineCount;
        if (logicalHeight > kMaximumWindowsCursorDimension)
        {
            return false;
        }
    }

    const auto hotspotX = static_cast<std::uint32_t>(description.hotspotX);
    const auto hotspotY = static_cast<std::uint32_t>(description.hotspotY);
    if (hotspotX >= description.widthPixels || hotspotY >= logicalHeight)
    {
        return false;
    }

    const std::uint64_t minimumPitch =
        description.type == WindowsDxgiPointerShapeType::monochrome
            ? (static_cast<std::uint64_t>(description.widthPixels) + 7U) / 8U
            : static_cast<std::uint64_t>(description.widthPixels) * 4U;
    const std::uint64_t byteCount =
        static_cast<std::uint64_t>(description.pitchBytes) * scanlineCount;
    if (description.pitchBytes < minimumPitch ||
        byteCount == 0 ||
        byteCount > kMaximumWindowsDxgiPointerShapeBytes ||
        byteCount != requiredBytes)
    {
        return false;
    }

    // DXGI masked-color alpha is a binary mask: 0 replaces the underlying
    // desktop pixel and 0xff XORs RGB with it. Reject any other alpha value
    // rather than silently inventing blend semantics.
    if (description.type == WindowsDxgiPointerShapeType::maskedColor)
    {
        if (pixels == nullptr)
        {
            return false;
        }
        for (std::uint32_t y = 0; y < logicalHeight; ++y)
        {
            const std::size_t rowOffset =
                static_cast<std::size_t>(y) * description.pitchBytes;
            for (std::uint32_t x = 0; x < description.widthPixels; ++x)
            {
                const std::size_t alphaOffset =
                    rowOffset + static_cast<std::size_t>(x) * 4U + 3U;
                const unsigned alpha =
                    std::to_integer<unsigned>(pixels[alphaOffset]);
                if (alpha != 0U && alpha != 0xffU)
                {
                    return false;
                }
            }
        }
    }

    return true;
}

} // namespace

WindowsDxgiPointerShapeReadResult readWindowsDxgiPointerShape(
    WindowsDxgiPointerShapeReadCallbacks callbacks,
    std::size_t advertisedBytes,
    WindowsDxgiPointerShape &output) noexcept
{
    if (callbacks.context == nullptr || callbacks.read == nullptr)
    {
        return WindowsDxgiPointerShapeReadResult::failed;
    }
    if (advertisedBytes == 0 ||
        advertisedBytes > kMaximumWindowsDxgiPointerShapeBytes)
    {
        return WindowsDxgiPointerShapeReadResult::invalid;
    }

    std::unique_ptr<std::byte[]> storage;
    try
    {
        storage = std::make_unique_for_overwrite<std::byte[]>(advertisedBytes);
    }
    catch (const std::bad_alloc &)
    {
        return WindowsDxgiPointerShapeReadResult::failed;
    }

    std::size_t requiredBytes = 0;
    WindowsDxgiPointerShapeDescription description{};
    const auto result = callbacks.read(
        callbacks.context,
        std::span<std::byte>(storage.get(), advertisedBytes),
        requiredBytes, description);
    if (result != WindowsDxgiPointerShapeReadResult::ready)
    {
        return result;
    }
    if (requiredBytes == 0 || requiredBytes > advertisedBytes)
    {
        return WindowsDxgiPointerShapeReadResult::invalid;
    }

    std::uint32_t logicalHeight = 0;
    if (!validateShape(description, requiredBytes, storage.get(),
                       logicalHeight))
    {
        return WindowsDxgiPointerShapeReadResult::invalid;
    }

    WindowsDxgiPointerShape candidate{};
    candidate.type = description.type;
    candidate.widthPixels = description.widthPixels;
    candidate.heightPixels = logicalHeight;
    candidate.pitchBytes = description.pitchBytes;
    candidate.hotspotX = static_cast<std::uint32_t>(description.hotspotX);
    candidate.hotspotY = static_cast<std::uint32_t>(description.hotspotY);
    candidate.storage = std::move(storage);
    candidate.byteCount = requiredBytes;
    output = std::move(candidate);
    return WindowsDxgiPointerShapeReadResult::ready;
}

#ifdef _WIN32
namespace
{

WindowsDxgiPointerShapeReadResult readNativePointerShape(
    void *context, std::span<std::byte> destination,
    std::size_t &requiredBytes,
    WindowsDxgiPointerShapeDescription &description) noexcept
{
    if (destination.size() >
        static_cast<std::size_t>(std::numeric_limits<UINT>::max()))
    {
        return WindowsDxgiPointerShapeReadResult::invalid;
    }

    auto &duplication = *static_cast<IDXGIOutputDuplication *>(context);
    UINT nativeRequiredBytes = 0;
    DXGI_OUTDUPL_POINTER_SHAPE_INFO nativeInfo{};
    const HRESULT result = duplication.GetFramePointerShape(
        static_cast<UINT>(destination.size()), destination.data(),
        &nativeRequiredBytes, &nativeInfo);
    requiredBytes = nativeRequiredBytes;

    if (result == DXGI_ERROR_MORE_DATA)
    {
        return WindowsDxgiPointerShapeReadResult::moreData;
    }
    if (result == DXGI_ERROR_ACCESS_LOST)
    {
        return WindowsDxgiPointerShapeReadResult::accessLost;
    }
    if (FAILED(result))
    {
        return WindowsDxgiPointerShapeReadResult::failed;
    }

    WindowsDxgiPointerShapeType type{};
    switch (nativeInfo.Type)
    {
    case DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MONOCHROME:
        type = WindowsDxgiPointerShapeType::monochrome;
        break;
    case DXGI_OUTDUPL_POINTER_SHAPE_TYPE_COLOR:
        type = WindowsDxgiPointerShapeType::color;
        break;
    case DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MASKED_COLOR:
        type = WindowsDxgiPointerShapeType::maskedColor;
        break;
    default:
        return WindowsDxgiPointerShapeReadResult::invalid;
    }

    description = {
        type,
        nativeInfo.Width,
        nativeInfo.Height,
        nativeInfo.Pitch,
        static_cast<std::int32_t>(nativeInfo.HotSpot.x),
        static_cast<std::int32_t>(nativeInfo.HotSpot.y)};
    return WindowsDxgiPointerShapeReadResult::ready;
}

} // namespace

WindowsDxgiPointerShapeReadCallbacks windowsDxgiPointerShapeReadCallbacks(
    IDXGIOutputDuplication &duplication) noexcept
{
    return {&duplication, &readNativePointerShape};
}
#endif

} // namespace rdp_server::windows
