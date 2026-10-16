// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows_dxgi_duplication_owner.h"

#include <atomic>
#include <limits>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <d3d11.h>
#include <dxgi1_2.h>
#include <new>
#endif

namespace rdp_server::windows
{
namespace
{
constexpr std::uint32_t kMaximumAdapters = 32;
constexpr std::uint32_t kMaximumOutputsPerAdapter = 32;
std::atomic<std::uint64_t> nextDeviceEpoch{1};

bool matches(const WindowsDxgiOutputDescription &description,
             const WindowsDxgiTarget &target) noexcept
{
    return description.attached && description.identityRotation &&
           description.monitor == target.monitor &&
           description.bounds == target.expectedBounds &&
           description.bounds.widthPixels != 0 &&
           description.bounds.heightPixels != 0;
}
} // namespace

WindowsDxgiDuplicationOwner::WindowsDxgiDuplicationOwner(
    WindowsDxgiNativeCallbacks callbacks) noexcept
    : callbacks_(callbacks), closed_(!hasCallbacks())
{
}

WindowsDxgiDuplicationOwner::~WindowsDxgiDuplicationOwner() noexcept
{
    close();
}

bool WindowsDxgiDuplicationOwner::hasCallbacks() const noexcept
{
    return callbacks_.context != nullptr && callbacks_.createFactory &&
           callbacks_.adapterAt && callbacks_.outputAt &&
           callbacks_.describeOutput && callbacks_.createDevice &&
           callbacks_.queryOutput1 && callbacks_.duplicate &&
           callbacks_.release;
}

void WindowsDxgiDuplicationOwner::releaseResource(
    WindowsDxgiNativeResource kind, void *&resource) noexcept
{
    if (resource != nullptr)
    {
        callbacks_.release(callbacks_.context, kind, resource);
        resource = nullptr;
    }
}

WindowsDxgiDuplicationResult WindowsDxgiDuplicationOwner::open(
    WindowsDxgiTarget target) noexcept
{
    if (closed_ || factory_ != nullptr || duplication_ != nullptr)
        return WindowsDxgiDuplicationResult::closed;
    if (target.monitor == 0 || target.expectedBounds.widthPixels == 0 ||
        target.expectedBounds.heightPixels == 0)
        return WindowsDxgiDuplicationResult::invalidTarget;

    auto fail = [this](WindowsDxgiDuplicationResult result) noexcept {
        close();
        return result;
    };
    if (!callbacks_.createFactory(callbacks_.context, factory_) ||
        factory_ == nullptr)
        return fail(WindowsDxgiDuplicationResult::failed);

    bool enumerationEnded = false;
    for (std::uint32_t adapterIndex = 0; adapterIndex < kMaximumAdapters;
         ++adapterIndex)
    {
        void *candidateAdapter = nullptr;
        const auto enumeration = callbacks_.adapterAt(
            callbacks_.context, factory_, adapterIndex, candidateAdapter);
        if (enumeration != WindowsDxgiEnumerationResult::item ||
            candidateAdapter == nullptr)
        {
            releaseResource(WindowsDxgiNativeResource::adapter, candidateAdapter);
            if (enumeration == WindowsDxgiEnumerationResult::end)
            {
                enumerationEnded = true;
                break;
            }
            return fail(WindowsDxgiDuplicationResult::failed);
        }

        bool outputEnumerationEnded = false;
        for (std::uint32_t outputIndex = 0;
             outputIndex < kMaximumOutputsPerAdapter; ++outputIndex)
        {
            void *candidateOutput = nullptr;
            const auto outputEnumeration = callbacks_.outputAt(
                callbacks_.context, candidateAdapter, outputIndex,
                candidateOutput);
            if (outputEnumeration != WindowsDxgiEnumerationResult::item ||
                candidateOutput == nullptr)
            {
                releaseResource(WindowsDxgiNativeResource::output,
                                candidateOutput);
                if (outputEnumeration == WindowsDxgiEnumerationResult::end)
                {
                    outputEnumerationEnded = true;
                    break;
                }
                if (candidateAdapter != adapter_)
                    releaseResource(WindowsDxgiNativeResource::adapter,
                                    candidateAdapter);
                return fail(WindowsDxgiDuplicationResult::failed);
            }
            WindowsDxgiOutputDescription description{};
            if (!callbacks_.describeOutput(callbacks_.context,
                                            candidateOutput, description))
            {
                releaseResource(WindowsDxgiNativeResource::output,
                                candidateOutput);
                if (candidateAdapter != adapter_)
                    releaseResource(WindowsDxgiNativeResource::adapter,
                                    candidateAdapter);
                return fail(WindowsDxgiDuplicationResult::failed);
            }
            const bool sameMonitor = description.monitor == target.monitor;
            if (sameMonitor && !matches(description, target))
            {
                // A stale/detached/rotated selected monitor is not replaced
                // with a different physical output.
                releaseResource(WindowsDxgiNativeResource::output,
                                candidateOutput);
                if (candidateAdapter != adapter_)
                    releaseResource(WindowsDxgiNativeResource::adapter,
                                    candidateAdapter);
                return fail(WindowsDxgiDuplicationResult::unavailable);
            }
            if (matches(description, target))
            {
                if (output_ != nullptr)
                {
                    releaseResource(WindowsDxgiNativeResource::output,
                                    candidateOutput);
                    // candidateAdapter can alias the adapter retained by the
                    // first matching output. That retained reference belongs
                    // to adapter_ and close() must release it exactly once.
                    if (candidateAdapter != adapter_)
                    {
                        releaseResource(WindowsDxgiNativeResource::adapter,
                                        candidateAdapter);
                    }
                    return fail(WindowsDxgiDuplicationResult::ambiguous);
                }
                output_ = candidateOutput;
                // Retain the sole adapter owning the matching output.
                adapter_ = candidateAdapter;
            }
            else
            {
                releaseResource(WindowsDxgiNativeResource::output,
                                candidateOutput);
            }
        }
        if (!outputEnumerationEnded)
        {
            if (candidateAdapter != adapter_)
                releaseResource(WindowsDxgiNativeResource::adapter,
                                candidateAdapter);
            return fail(WindowsDxgiDuplicationResult::failed);
        }
        if (candidateAdapter != adapter_)
            releaseResource(WindowsDxgiNativeResource::adapter,
                            candidateAdapter);
    }
    if (!enumerationEnded)
        return fail(WindowsDxgiDuplicationResult::failed);
    if (output_ == nullptr)
        return fail(WindowsDxgiDuplicationResult::unavailable);

    if (!callbacks_.createDevice(callbacks_.context, adapter_,
                                 device_, context_) ||
        device_ == nullptr || context_ == nullptr)
        return fail(WindowsDxgiDuplicationResult::unsupported);
    if (!callbacks_.queryOutput1(callbacks_.context, output_, output1_) ||
        output1_ == nullptr)
        return fail(WindowsDxgiDuplicationResult::unsupported);

    WindowsDxgiOutputDescription refreshed{};
    if (!callbacks_.describeOutput(callbacks_.context, output_, refreshed) ||
        !matches(refreshed, target))
        return fail(WindowsDxgiDuplicationResult::accessLost);

    const auto outcome = callbacks_.duplicate(
        callbacks_.context, output1_, device_, duplication_);
    if (outcome != WindowsDxgiDuplicationResult::ready ||
        duplication_ == nullptr)
        return fail(outcome == WindowsDxgiDuplicationResult::ready
                        ? WindowsDxgiDuplicationResult::failed : outcome);

    selected_ = target;
    const auto epoch = nextDeviceEpoch.fetch_add(1, std::memory_order_relaxed);
    if (epoch == 0 || epoch == std::numeric_limits<std::uint64_t>::max())
        return fail(WindowsDxgiDuplicationResult::failed);
    deviceEpoch_ = epoch;
    return WindowsDxgiDuplicationResult::ready;
}

void WindowsDxgiDuplicationOwner::close() noexcept
{
    closed_ = true;
    deviceEpoch_ = 0;
#ifdef _WIN32
    if (captureCycle_)
    {
        captureCycle_->cancel();
        captureCycle_.reset();
    }
    stagingContext_.reset();
#endif
    releaseResource(WindowsDxgiNativeResource::duplication, duplication_);
    releaseResource(WindowsDxgiNativeResource::output1, output1_);
    releaseResource(WindowsDxgiNativeResource::context, context_);
    releaseResource(WindowsDxgiNativeResource::device, device_);
    releaseResource(WindowsDxgiNativeResource::output, output_);
    releaseResource(WindowsDxgiNativeResource::adapter, adapter_);
    releaseResource(WindowsDxgiNativeResource::factory, factory_);
}

bool WindowsDxgiDuplicationOwner::ready() const noexcept
{
    return !closed_ && duplication_ != nullptr && deviceEpoch_ != 0;
}

std::uint64_t WindowsDxgiDuplicationOwner::deviceEpoch() const noexcept
{
    return ready() ? deviceEpoch_ : 0;
}

WindowsDxgiFrameCallbacks WindowsDxgiDuplicationOwner::frameCallbacks() const noexcept
{
#ifdef _WIN32
    if (ready())
        return windowsDxgiFrameCallbacks(
            *static_cast<IDXGIOutputDuplication *>(duplication_));
#endif
    return {};
}

bool WindowsDxgiDuplicationOwner::observeGeneration(
    void *context, WindowsCaptureGeneration &current) noexcept
{
    auto &owner = *static_cast<WindowsDxgiDuplicationOwner *>(context);
    if (!owner.ready() || owner.sessionReader_.context == nullptr ||
        owner.sessionReader_.read == nullptr)
        return false;
    WindowsCaptureGeneration observed{};
    if (!owner.sessionReader_.read(owner.sessionReader_.context, observed) ||
        observed.session != owner.pinnedSessionEpoch_ ||
        observed.session == 0)
        return false;
    current = {observed.session, owner.deviceEpoch_};
    return true;
}

#ifdef _WIN32
bool WindowsDxgiDuplicationOwner::attachCaptureCycle(
    WindowsDesktopLayout layout,
    WindowsCaptureGenerationReader sessionReader,
    std::uint64_t pinnedSessionEpoch)
{
    if (!ready() || captureCycle_ || sessionReader.context == nullptr ||
        sessionReader.read == nullptr || pinnedSessionEpoch == 0)
        return false;
    bool found = false;
    for (std::size_t index = 0; index < layout.monitorCount; ++index)
        found = found || layout.monitors[index] == selected_.expectedBounds;
    if (!found)
        return false;
    sessionReader_ = sessionReader;
    pinnedSessionEpoch_ = pinnedSessionEpoch;
    stagingContext_ = std::make_unique<WindowsD3D11NativeStagingContext>(
        *static_cast<ID3D11Device *>(device_),
        *static_cast<ID3D11DeviceContext *>(context_));
    captureCycle_ = std::make_unique<WindowsDxgiCaptureCycle>(
        layout, frameCallbacks(), stagingContext_->callbacks(),
        WindowsDxgiDamageReadCallbacks{},
        WindowsCaptureGenerationReader{this, &observeGeneration},
        WindowsCaptureGeneration{pinnedSessionEpoch, deviceEpoch_},
        windowsDxgiPointerShapeReadCallbacks(
            *static_cast<IDXGIOutputDuplication *>(duplication_)),
        selected_.expectedBounds);
    return !captureCycle_->closed();
}

WindowsDxgiCaptureCycle *WindowsDxgiDuplicationOwner::captureCycle() noexcept
{
    return captureCycle_.get();
}
#endif

#ifdef _WIN32
namespace
{
bool createFactory(void *, void *&factory) noexcept
{
    IDXGIFactory1 *nativeFactory = nullptr;
    const HRESULT result = CreateDXGIFactory1(
        __uuidof(IDXGIFactory1),
        reinterpret_cast<void **>(&nativeFactory));
    factory = nativeFactory;
    return SUCCEEDED(result);
}

WindowsDxgiEnumerationResult adapterAt(
    void *, void *factory, std::uint32_t index, void *&adapter) noexcept
{
    IDXGIAdapter1 *nativeAdapter = nullptr;
    const HRESULT result = static_cast<IDXGIFactory1 *>(factory)->EnumAdapters1(
        index, &nativeAdapter);
    adapter = nativeAdapter;
    if (result == DXGI_ERROR_NOT_FOUND)
        return WindowsDxgiEnumerationResult::end;
    return SUCCEEDED(result) ? WindowsDxgiEnumerationResult::item
                             : WindowsDxgiEnumerationResult::failed;
}

WindowsDxgiEnumerationResult outputAt(
    void *, void *adapter, std::uint32_t index, void *&output) noexcept
{
    IDXGIOutput *nativeOutput = nullptr;
    const HRESULT result = static_cast<IDXGIAdapter1 *>(adapter)->EnumOutputs(
        index, &nativeOutput);
    output = nativeOutput;
    if (result == DXGI_ERROR_NOT_FOUND)
        return WindowsDxgiEnumerationResult::end;
    return SUCCEEDED(result) ? WindowsDxgiEnumerationResult::item
                             : WindowsDxgiEnumerationResult::failed;
}

bool describeOutput(
    void *, void *output, WindowsDxgiOutputDescription &description) noexcept
{
    DXGI_OUTPUT_DESC desc{};
    if (FAILED(static_cast<IDXGIOutput *>(output)->GetDesc(&desc)))
        return false;
    const auto width = static_cast<std::int64_t>(desc.DesktopCoordinates.right) -
                       desc.DesktopCoordinates.left;
    const auto height = static_cast<std::int64_t>(desc.DesktopCoordinates.bottom) -
                        desc.DesktopCoordinates.top;
    if (width <= 0 || height <= 0 ||
        width > std::numeric_limits<std::uint32_t>::max() ||
        height > std::numeric_limits<std::uint32_t>::max())
        return false;
    description = {
        reinterpret_cast<std::uintptr_t>(desc.Monitor),
        {desc.DesktopCoordinates.left, desc.DesktopCoordinates.top,
         static_cast<std::uint32_t>(width),
         static_cast<std::uint32_t>(height)},
        desc.AttachedToDesktop != FALSE,
        desc.Rotation == DXGI_MODE_ROTATION_IDENTITY};
    return true;
}

bool createDevice(void *, void *adapter, void *&device,
                  void *&context) noexcept
{
    ID3D11Device *nativeDevice = nullptr;
    ID3D11DeviceContext *nativeContext = nullptr;
    D3D_FEATURE_LEVEL actual{};
    constexpr D3D_FEATURE_LEVEL levels[]{D3D_FEATURE_LEVEL_11_0};
    const HRESULT result = D3D11CreateDevice(
        static_cast<IDXGIAdapter1 *>(adapter), D3D_DRIVER_TYPE_UNKNOWN,
        nullptr, D3D11_CREATE_DEVICE_BGRA_SUPPORT, levels, 1,
        D3D11_SDK_VERSION, &nativeDevice, &actual, &nativeContext);
    device = nativeDevice;
    context = nativeContext;
    return SUCCEEDED(result) && actual == D3D_FEATURE_LEVEL_11_0;
}

bool queryOutput1(void *, void *output, void *&output1) noexcept
{
    IDXGIOutput1 *nativeOutput = nullptr;
    const HRESULT result = static_cast<IDXGIOutput *>(output)->QueryInterface(
        __uuidof(IDXGIOutput1),
        reinterpret_cast<void **>(&nativeOutput));
    output1 = nativeOutput;
    return SUCCEEDED(result);
}

WindowsDxgiDuplicationResult duplicate(
    void *, void *output, void *device, void *&duplication) noexcept
{
    IDXGIOutputDuplication *nativeDuplication = nullptr;
    const HRESULT result = static_cast<IDXGIOutput1 *>(output)->DuplicateOutput(
        static_cast<ID3D11Device *>(device), &nativeDuplication);
    duplication = nativeDuplication;
    if (SUCCEEDED(result))
        return WindowsDxgiDuplicationResult::ready;
    if (result == E_ACCESSDENIED)
        return WindowsDxgiDuplicationResult::accessDenied;
    if (result == DXGI_ERROR_ACCESS_LOST ||
        result == DXGI_ERROR_SESSION_DISCONNECTED)
        return WindowsDxgiDuplicationResult::accessLost;
    if (result == DXGI_ERROR_NOT_CURRENTLY_AVAILABLE)
        return WindowsDxgiDuplicationResult::resourcePressure;
    if (result == DXGI_ERROR_UNSUPPORTED)
        return WindowsDxgiDuplicationResult::unsupported;
    if (result == DXGI_ERROR_DEVICE_REMOVED ||
        result == DXGI_ERROR_DEVICE_RESET)
        return WindowsDxgiDuplicationResult::accessLost;
    return WindowsDxgiDuplicationResult::failed;
}

void release(void *, WindowsDxgiNativeResource kind, void *resource) noexcept
{
    switch (kind)
    {
    case WindowsDxgiNativeResource::factory:
        static_cast<IDXGIFactory1 *>(resource)->Release(); break;
    case WindowsDxgiNativeResource::adapter:
        static_cast<IDXGIAdapter1 *>(resource)->Release(); break;
    case WindowsDxgiNativeResource::output:
        static_cast<IDXGIOutput *>(resource)->Release(); break;
    case WindowsDxgiNativeResource::output1:
        static_cast<IDXGIOutput1 *>(resource)->Release(); break;
    case WindowsDxgiNativeResource::device:
        static_cast<ID3D11Device *>(resource)->Release(); break;
    case WindowsDxgiNativeResource::context:
        static_cast<ID3D11DeviceContext *>(resource)->Release(); break;
    case WindowsDxgiNativeResource::duplication:
        static_cast<IDXGIOutputDuplication *>(resource)->Release(); break;
    }
}
} // namespace
#endif

WindowsDxgiNativeCallbacks windowsNativeDxgiDuplicationCallbacks() noexcept
{
#ifdef _WIN32
    static int nativeContext{};
    return {&nativeContext, &createFactory, &adapterAt, &outputAt,
            &describeOutput, &createDevice, &queryOutput1,
            &duplicate, &release};
#else
    return {};
#endif
}

} // namespace rdp_server::windows
