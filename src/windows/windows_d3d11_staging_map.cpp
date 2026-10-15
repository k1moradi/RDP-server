// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows_d3d11_staging_map.h"

#include "windows_bgra_frame.h"

#include <span>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <d3d11.h>
#include <dxgi1_2.h>
#include <cstdint>
#endif

namespace rdp_server::windows
{

WindowsD3D11StagingMap::WindowsD3D11StagingMap(
    WindowsD3D11StagingCallbacks callbacks) noexcept
    : callbacks_(callbacks),
      closed_(callbacks.context == nullptr ||
              callbacks.stageAndMap == nullptr ||
              callbacks.unmapAndRelease == nullptr)
{
}

WindowsD3D11StagingMap::~WindowsD3D11StagingMap() noexcept
{
    cancel();
}

WindowsD3D11MapResult WindowsD3D11StagingMap::mapFrame(
    void *acquiredResource) noexcept
{
    if (closed_)
    {
        return WindowsD3D11MapResult::closed;
    }
    if (mappingHandle_ != nullptr || callbackInProgress_)
    {
        return WindowsD3D11MapResult::busy;
    }
    if (acquiredResource == nullptr)
    {
        return WindowsD3D11MapResult::invalidFrame;
    }

    WindowsD3D11MappedData mapped{};
    callbackInProgress_ = true;
    const auto result = callbacks_.stageAndMap(
        callbacks_.context, acquiredResource, mapped);
    callbackInProgress_ = false;
    if (!closed_ && result == WindowsD3D11MapResult::notReady &&
        mapped.mappingHandle == nullptr)
    {
        return result;
    }
    if (closed_ || result != WindowsD3D11MapResult::mapped ||
        mapped.mappingHandle == nullptr || mapped.pixels == nullptr)
    {
        if (mapped.mappingHandle != nullptr)
        {
            callbackInProgress_ = true;
            callbacks_.unmapAndRelease(callbacks_.context,
                                       mapped.mappingHandle);
            callbackInProgress_ = false;
        }
        closed_ = true;
        return WindowsD3D11MapResult::failed;
    }

    FramebufferView validated{};
    if (!makeWindowsBgraFrameView(
            std::span<const std::byte>(mapped.pixels, mapped.availableBytes),
            mapped.dimensions, mapped.rowPitchBytes, validated))
    {
        callbackInProgress_ = true;
        callbacks_.unmapAndRelease(callbacks_.context,
                                   mapped.mappingHandle);
        callbackInProgress_ = false;
        closed_ = true;
        return WindowsD3D11MapResult::invalidFrame;
    }

    mappingHandle_ = mapped.mappingHandle;
    frame_ = validated;
    return WindowsD3D11MapResult::mapped;
}

void WindowsD3D11StagingMap::unmap() noexcept
{
    if (mappingHandle_ == nullptr)
    {
        return;
    }
    void *const handle = mappingHandle_;
    // Invalidate the borrowed view before any native callback/reentry.
    mappingHandle_ = nullptr;
    frame_ = {};
    callbackInProgress_ = true;
    callbacks_.unmapAndRelease(callbacks_.context, handle);
    callbackInProgress_ = false;
}

void WindowsD3D11StagingMap::cancel() noexcept
{
    closed_ = true;
    unmap();
}

FramebufferView WindowsD3D11StagingMap::frame() const noexcept
{
    return frame_;
}

bool WindowsD3D11StagingMap::mapped() const noexcept
{
    return mappingHandle_ != nullptr;
}

bool WindowsD3D11StagingMap::closed() const noexcept
{
    return closed_;
}

#ifdef _WIN32
WindowsD3D11NativeStagingContext::WindowsD3D11NativeStagingContext(
    ID3D11Device &device, ID3D11DeviceContext &immediateContext) noexcept
    : device_(&device), context_(&immediateContext)
{
}

WindowsD3D11NativeStagingContext::~WindowsD3D11NativeStagingContext() noexcept
{
    releaseMapping();
}

ID3D11Device &WindowsD3D11NativeStagingContext::device() const noexcept
{
    return *device_;
}

ID3D11DeviceContext &
WindowsD3D11NativeStagingContext::immediateContext() const noexcept
{
    return *context_;
}

bool WindowsD3D11NativeStagingContext::hasMapping() const noexcept
{
    return staging_ != nullptr;
}

void WindowsD3D11NativeStagingContext::setMapping(
    ID3D11Texture2D &texture) noexcept
{
    staging_ = &texture;
}

void WindowsD3D11NativeStagingContext::releaseMapping() noexcept
{
    if (staging_ != nullptr)
    {
        context_->Unmap(staging_, 0);
        staging_->Release();
        staging_ = nullptr;
    }
}

namespace
{

WindowsD3D11MapResult stageAndMapNative(
    void *rawContext, void *acquiredResource,
    WindowsD3D11MappedData &output) noexcept
{
    auto &context = *static_cast<WindowsD3D11NativeStagingContext *>(
        rawContext);
    if (context.hasMapping() || acquiredResource == nullptr ||
        context.immediateContext().GetType() != D3D11_DEVICE_CONTEXT_IMMEDIATE)
    {
        return WindowsD3D11MapResult::failed;
    }

    ID3D11Texture2D *sourceTexture = nullptr;
    const HRESULT queryResult =
        static_cast<IDXGIResource *>(acquiredResource)->QueryInterface(
            __uuidof(ID3D11Texture2D),
            reinterpret_cast<void **>(&sourceTexture));
    if (FAILED(queryResult) || sourceTexture == nullptr)
    {
        if (sourceTexture != nullptr)
        {
            sourceTexture->Release();
        }
        return WindowsD3D11MapResult::invalidFrame;
    }
    D3D11_TEXTURE2D_DESC sourceDesc{};
    sourceTexture->GetDesc(&sourceDesc);
    const std::uint64_t minimumRowBytes =
        static_cast<std::uint64_t>(sourceDesc.Width) *
        kWindowsBgraBytesPerPixel;
    if (sourceDesc.Width == 0 || sourceDesc.Height == 0 ||
        sourceDesc.Format != DXGI_FORMAT_B8G8R8A8_UNORM ||
        sourceDesc.ArraySize != 1 || sourceDesc.MipLevels != 1 ||
        sourceDesc.SampleDesc.Count != 1 ||
        minimumRowBytes == 0 ||
        minimumRowBytes > kMaximumWindowsCaptureFrameBytes ||
        sourceDesc.Height >
            kMaximumWindowsCaptureFrameBytes / minimumRowBytes)
    {
        sourceTexture->Release();
        return WindowsD3D11MapResult::invalidFrame;
    }

    D3D11_TEXTURE2D_DESC stagingDesc = sourceDesc;
    stagingDesc.Usage = D3D11_USAGE_STAGING;
    stagingDesc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    stagingDesc.BindFlags = 0;
    stagingDesc.MiscFlags = 0;
    ID3D11Texture2D *staging = nullptr;
    const HRESULT createResult = context.device().CreateTexture2D(
        &stagingDesc, nullptr, &staging);
    if (FAILED(createResult) || staging == nullptr)
    {
        if (staging != nullptr)
        {
            staging->Release();
        }
        sourceTexture->Release();
        return WindowsD3D11MapResult::failed;
    }
    context.immediateContext().CopyResource(staging, sourceTexture);
    sourceTexture->Release();

    D3D11_MAPPED_SUBRESOURCE mapped{};
    const HRESULT result = context.immediateContext().Map(
        staging, 0, D3D11_MAP_READ, D3D11_MAP_FLAG_DO_NOT_WAIT, &mapped);
    if (FAILED(result))
    {
        staging->Release();
        if (result == DXGI_ERROR_WAS_STILL_DRAWING)
        {
            return WindowsD3D11MapResult::notReady;
        }
        return WindowsD3D11MapResult::failed;
    }
    const std::size_t rowPitch = mapped.RowPitch;
    const std::uint64_t height = sourceDesc.Height;
    if (mapped.pData == nullptr ||
        rowPitch < minimumRowBytes ||
        rowPitch > kMaximumWindowsCaptureFrameBytes / height)
    {
        context.immediateContext().Unmap(staging, 0);
        staging->Release();
        return WindowsD3D11MapResult::invalidFrame;
    }

    // Staging resource and mapping are now owned by this fixed native
    // context; no heap allocation or duplicate frame copy is needed.
    context.setMapping(*staging);
    output = {static_cast<const std::byte *>(mapped.pData),
              rowPitch * static_cast<std::size_t>(height),
              {sourceDesc.Width, sourceDesc.Height}, rowPitch, &context};
    return WindowsD3D11MapResult::mapped;
}

void unmapAndReleaseNative(void *rawContext, void *handle) noexcept
{
    auto &context = *static_cast<WindowsD3D11NativeStagingContext *>(
        rawContext);
    if (handle == &context)
    {
        context.releaseMapping();
    }
}

} // namespace

WindowsD3D11StagingCallbacks
WindowsD3D11NativeStagingContext::callbacks() noexcept
{
    return {this, &stageAndMapNative, &unmapAndReleaseNative};
}
#endif

} // namespace rdp_server::windows
