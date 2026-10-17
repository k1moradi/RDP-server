// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows_dxgi_duplication_owner.h"

#include <atomic>
#include <limits>
#include <utility>

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

std::uint64_t allocateDeviceEpoch() noexcept
{
    auto epoch = nextDeviceEpoch.load(std::memory_order_relaxed);
    const auto exhausted = std::numeric_limits<std::uint64_t>::max();
    while (epoch != 0 && epoch != exhausted)
    {
        if (nextDeviceEpoch.compare_exchange_weak(
                epoch, epoch + 1, std::memory_order_relaxed,
                std::memory_order_relaxed))
            return epoch;
    }
    return 0;
}

bool matches(const WindowsDxgiOutputDescription &description,
             const WindowsDxgiTarget &target) noexcept
{
    return description.attached && description.identityRotation &&
           description.monitor == target.monitor &&
           description.bounds == target.expectedBounds &&
           description.bounds.widthPixels != 0 &&
           description.bounds.heightPixels != 0;
}

bool hasAnyCaptureCallback(
    const WindowsDxgiOwnedCaptureCallbacks &callbacks) noexcept
{
    return callbacks.frame.context != nullptr ||
           callbacks.frame.acquire != nullptr ||
           callbacks.frame.release != nullptr ||
           callbacks.staging.context != nullptr ||
           callbacks.staging.stageAndMap != nullptr ||
           callbacks.staging.unmapAndRelease != nullptr ||
           callbacks.damage.context != nullptr ||
           callbacks.damage.read != nullptr ||
           callbacks.pointerShape.context != nullptr ||
           callbacks.pointerShape.read != nullptr;
}

bool hasValidCaptureCallbacks(
    const WindowsDxgiOwnedCaptureCallbacks &callbacks) noexcept
{
    const bool damageValid =
        (callbacks.damage.context == nullptr) ==
        (callbacks.damage.read == nullptr);
    const bool pointerValid =
        (callbacks.pointerShape.context == nullptr) ==
        (callbacks.pointerShape.read == nullptr);
    return callbacks.frame.context != nullptr &&
           callbacks.frame.acquire != nullptr &&
           callbacks.frame.release != nullptr &&
           callbacks.staging.context != nullptr &&
           callbacks.staging.stageAndMap != nullptr &&
           callbacks.staging.unmapAndRelease != nullptr &&
           damageValid && pointerValid;
}
} // namespace

WindowsDxgiDuplicationOwner::WindowsDxgiDuplicationOwner(
    WindowsDxgiNativeCallbacks callbacks,
    WindowsDxgiOwnedCaptureCallbacks captureCallbacks) noexcept
    : callbacks_(callbacks),
      captureCallbacks_(captureCallbacks),
      closed_(!hasCallbacks())
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
    void *const owned = std::exchange(resource, nullptr);
    if (owned != nullptr)
        callbacks_.release(callbacks_.context, kind, owned);
}

void WindowsDxgiDuplicationOwner::releaseOwnedResources() noexcept
{
    if (operationInProgress_ || teardownInProgress_)
        return;
#ifdef _WIN32
    if (captureCycle_ != nullptr && captureCycle_->operationInProgress_)
        return;
#endif

    teardownInProgress_ = true;
#ifdef _WIN32
    if (captureCycle_)
    {
        captureCycle_->cancel();
        captureCycle_.reset();
    }
    stagingContext_.reset();
#endif
    sessionReader_ = {};
    pinnedSessionEpoch_ = 0;
    selected_ = {};
    releaseResource(WindowsDxgiNativeResource::duplication, duplication_);
    releaseResource(WindowsDxgiNativeResource::output1, output1_);
    releaseResource(WindowsDxgiNativeResource::context, context_);
    releaseResource(WindowsDxgiNativeResource::device, device_);
    releaseResource(WindowsDxgiNativeResource::output, output_);
    releaseResource(WindowsDxgiNativeResource::adapter, adapter_);
    releaseResource(WindowsDxgiNativeResource::factory, factory_);
    teardownInProgress_ = false;
}

WindowsDxgiDuplicationResult WindowsDxgiDuplicationOwner::open(
    WindowsDxgiTarget target) noexcept
{
    if (closed_ || operationInProgress_ || teardownInProgress_ ||
        factory_ != nullptr || duplication_ != nullptr)
        return WindowsDxgiDuplicationResult::closed;
    if (target.monitor == 0 || target.expectedBounds.widthPixels == 0 ||
        target.expectedBounds.heightPixels == 0)
        return WindowsDxgiDuplicationResult::invalidTarget;

    operationInProgress_ = true;
    auto finish = [this](WindowsDxgiDuplicationResult result) noexcept {
        operationInProgress_ = false;
        if (closed_)
            releaseOwnedResources();
        return result;
    };
    auto fail = [this, &finish](
                    WindowsDxgiDuplicationResult result) noexcept {
        closed_ = true;
        deviceEpoch_ = 0;
        return finish(result);
    };
    auto cancelled = [&finish]() noexcept {
        return finish(WindowsDxgiDuplicationResult::closed);
    };

    const bool factoryCreated =
        callbacks_.createFactory(callbacks_.context, factory_);
    if (closed_)
        return cancelled();
    if (!factoryCreated || factory_ == nullptr)
        return fail(WindowsDxgiDuplicationResult::failed);

    bool enumerationEnded = false;
    for (std::uint32_t adapterIndex = 0; adapterIndex < kMaximumAdapters;
         ++adapterIndex)
    {
        void *candidateAdapter = nullptr;
        const auto enumeration = callbacks_.adapterAt(
            callbacks_.context, factory_, adapterIndex, candidateAdapter);
        if (closed_)
        {
            releaseResource(WindowsDxgiNativeResource::adapter,
                            candidateAdapter);
            return cancelled();
        }
        if (enumeration != WindowsDxgiEnumerationResult::item ||
            candidateAdapter == nullptr)
        {
            releaseResource(WindowsDxgiNativeResource::adapter,
                            candidateAdapter);
            if (closed_)
                return cancelled();
            if (enumeration == WindowsDxgiEnumerationResult::end)
            {
                enumerationEnded = true;
                break;
            }
            return fail(WindowsDxgiDuplicationResult::failed);
        }

        // Ownership follows the reference returned by this adapterAt call,
        // not the interface address. COM may return the same address for a
        // later call while still transferring another reference.
        bool candidateAdapterTransferred = false;
        bool outputEnumerationEnded = false;
        for (std::uint32_t outputIndex = 0;
             outputIndex < kMaximumOutputsPerAdapter; ++outputIndex)
        {
            void *candidateOutput = nullptr;
            const auto outputEnumeration = callbacks_.outputAt(
                callbacks_.context, candidateAdapter, outputIndex,
                candidateOutput);
            if (closed_)
            {
                releaseResource(WindowsDxgiNativeResource::output,
                                candidateOutput);
                if (!candidateAdapterTransferred)
                    releaseResource(WindowsDxgiNativeResource::adapter,
                                    candidateAdapter);
                return cancelled();
            }
            if (outputEnumeration != WindowsDxgiEnumerationResult::item ||
                candidateOutput == nullptr)
            {
                releaseResource(WindowsDxgiNativeResource::output,
                                candidateOutput);
                if (closed_)
                {
                    if (!candidateAdapterTransferred)
                        releaseResource(WindowsDxgiNativeResource::adapter,
                                        candidateAdapter);
                    return cancelled();
                }
                if (outputEnumeration == WindowsDxgiEnumerationResult::end)
                {
                    outputEnumerationEnded = true;
                    break;
                }
                if (!candidateAdapterTransferred)
                    releaseResource(WindowsDxgiNativeResource::adapter,
                                    candidateAdapter);
                if (closed_)
                    return cancelled();
                return fail(WindowsDxgiDuplicationResult::failed);
            }

            WindowsDxgiOutputDescription description{};
            const bool described = callbacks_.describeOutput(
                callbacks_.context, candidateOutput, description);
            if (closed_)
            {
                releaseResource(WindowsDxgiNativeResource::output,
                                candidateOutput);
                if (!candidateAdapterTransferred)
                    releaseResource(WindowsDxgiNativeResource::adapter,
                                    candidateAdapter);
                return cancelled();
            }
            if (!described)
            {
                releaseResource(WindowsDxgiNativeResource::output,
                                candidateOutput);
                if (!candidateAdapterTransferred)
                    releaseResource(WindowsDxgiNativeResource::adapter,
                                    candidateAdapter);
                if (closed_)
                    return cancelled();
                return fail(WindowsDxgiDuplicationResult::failed);
            }

            const bool sameMonitor = description.monitor == target.monitor;
            if (sameMonitor && !matches(description, target))
            {
                // A stale/detached/rotated selected monitor is not replaced
                // with a different physical output.
                releaseResource(WindowsDxgiNativeResource::output,
                                candidateOutput);
                if (!candidateAdapterTransferred)
                    releaseResource(WindowsDxgiNativeResource::adapter,
                                    candidateAdapter);
                if (closed_)
                    return cancelled();
                return fail(WindowsDxgiDuplicationResult::unavailable);
            }
            if (matches(description, target))
            {
                if (output_ != nullptr)
                {
                    releaseResource(WindowsDxgiNativeResource::output,
                                    candidateOutput);
                    // A second match within this same adapter scan shares
                    // the one adapterAt reference already transferred to
                    // adapter_. A reference from a later adapterAt call must
                    // still be released even if its interface address matches.
                    if (!candidateAdapterTransferred)
                    {
                        releaseResource(WindowsDxgiNativeResource::adapter,
                                        candidateAdapter);
                    }
                    if (closed_)
                        return cancelled();
                    return fail(WindowsDxgiDuplicationResult::ambiguous);
                }
                output_ = candidateOutput;
                adapter_ = candidateAdapter;
                candidateAdapterTransferred = true;
            }
            else
            {
                releaseResource(WindowsDxgiNativeResource::output,
                                candidateOutput);
                if (closed_)
                {
                    if (!candidateAdapterTransferred)
                        releaseResource(WindowsDxgiNativeResource::adapter,
                                        candidateAdapter);
                    return cancelled();
                }
            }
        }

        if (!outputEnumerationEnded)
        {
            if (!candidateAdapterTransferred)
                releaseResource(WindowsDxgiNativeResource::adapter,
                                candidateAdapter);
            if (closed_)
                return cancelled();
            return fail(WindowsDxgiDuplicationResult::failed);
        }
        if (!candidateAdapterTransferred)
            releaseResource(WindowsDxgiNativeResource::adapter,
                            candidateAdapter);
        if (closed_)
            return cancelled();
    }

    if (!enumerationEnded)
        return fail(WindowsDxgiDuplicationResult::failed);
    if (output_ == nullptr)
        return fail(WindowsDxgiDuplicationResult::unavailable);

    const bool deviceCreated = callbacks_.createDevice(
        callbacks_.context, adapter_, device_, context_);
    if (closed_)
        return cancelled();
    if (!deviceCreated || device_ == nullptr || context_ == nullptr)
        return fail(WindowsDxgiDuplicationResult::unsupported);

    const bool output1Created =
        callbacks_.queryOutput1(callbacks_.context, output_, output1_);
    if (closed_)
        return cancelled();
    if (!output1Created || output1_ == nullptr)
        return fail(WindowsDxgiDuplicationResult::unsupported);

    WindowsDxgiOutputDescription refreshed{};
    const bool refreshedDescription = callbacks_.describeOutput(
        callbacks_.context, output_, refreshed);
    if (closed_)
        return cancelled();
    if (!refreshedDescription || !matches(refreshed, target))
        return fail(WindowsDxgiDuplicationResult::accessLost);

    const auto outcome = callbacks_.duplicate(
        callbacks_.context, output1_, device_, duplication_);
    if (closed_)
        return cancelled();
    if (outcome != WindowsDxgiDuplicationResult::ready ||
        duplication_ == nullptr)
        return fail(outcome == WindowsDxgiDuplicationResult::ready
                        ? WindowsDxgiDuplicationResult::failed : outcome);

    selected_ = target;
    const auto epoch = allocateDeviceEpoch();
    if (epoch == 0)
        return fail(WindowsDxgiDuplicationResult::failed);
    deviceEpoch_ = epoch;
    return finish(WindowsDxgiDuplicationResult::ready);
}

void WindowsDxgiDuplicationOwner::close() noexcept
{
    closed_ = true;
    deviceEpoch_ = 0;
    if (operationInProgress_ || teardownInProgress_)
        return;
#ifdef _WIN32
    if (captureCycle_ != nullptr && captureCycle_->operationInProgress_)
    {
        // Cancellation makes the child unusable immediately, but its
        // unique_ptr must survive until the active member function returns.
        captureCycle_->cancel();
        return;
    }
#endif
    releaseOwnedResources();
}

void WindowsDxgiDuplicationOwner::completeDeferredClose() noexcept
{
    if (!closed_ || operationInProgress_ || teardownInProgress_)
        return;
    releaseOwnedResources();
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
        sessionReader.read == nullptr || pinnedSessionEpoch == 0 ||
        layout.monitorCount == 0 ||
        layout.monitorCount > layout.monitors.size())
        return false;

    // Validate the bounded fixed-array payload before iterating it or
    // constructing native wrappers. A stale/corrupt count must never index
    // beyond monitors, and a non-canonical virtual desktop is not attachable.
    WindowsDesktopLayout validatedLayout{};
    if (!makeWindowsDesktopLayout(
            std::span<const PortableRectangle>{
                layout.monitors.data(), layout.monitorCount},
            validatedLayout) ||
        validatedLayout != layout)
        return false;

    std::size_t matchingOutputs = 0;
    for (std::size_t index = 0; index < layout.monitorCount; ++index)
        matchingOutputs += layout.monitors[index] == selected_.expectedBounds;
    if (matchingOutputs != 1)
        return false;

    const bool injectedCapture = hasAnyCaptureCallback(captureCallbacks_);
    if (injectedCapture && !hasValidCaptureCallbacks(captureCallbacks_))
        return false;

    WindowsDxgiFrameCallbacks frame{};
    WindowsD3D11StagingCallbacks staging{};
    WindowsDxgiDamageReadCallbacks damage{};
    WindowsDxgiPointerShapeReadCallbacks pointerShape{};
    PortableRectangle pointerBounds{};
    std::unique_ptr<WindowsD3D11NativeStagingContext> stagingContext{};

    if (injectedCapture)
    {
        frame = captureCallbacks_.frame;
        staging = captureCallbacks_.staging;
        damage = captureCallbacks_.damage;
        pointerShape = captureCallbacks_.pointerShape;
        if (pointerShape.read != nullptr)
            pointerBounds = selected_.expectedBounds;
    }
    else
    {
        stagingContext = std::make_unique<WindowsD3D11NativeStagingContext>(
            *static_cast<ID3D11Device *>(device_),
            *static_cast<ID3D11DeviceContext *>(context_));
        frame = frameCallbacks();
        staging = stagingContext->callbacks();
        pointerShape = windowsDxgiPointerShapeReadCallbacks(
            *static_cast<IDXGIOutputDuplication *>(duplication_));
        pointerBounds = selected_.expectedBounds;
    }

    auto captureCycle = std::make_unique<WindowsDxgiCaptureCycle>(
        layout, frame, staging, damage,
        WindowsCaptureGenerationReader{this, &observeGeneration},
        WindowsCaptureGeneration{pinnedSessionEpoch, deviceEpoch_},
        pointerShape, pointerBounds);
    if (captureCycle->closed())
        return false;

    sessionReader_ = sessionReader;
    pinnedSessionEpoch_ = pinnedSessionEpoch;
    stagingContext_ = std::move(stagingContext);
    captureCycle_ = std::move(captureCycle);
    return true;
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
