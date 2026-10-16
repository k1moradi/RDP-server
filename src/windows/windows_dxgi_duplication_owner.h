// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "windows_dxgi_capture_cycle.h"

#include <cstdint>
#include <memory>

namespace rdp_server::windows
{

// Distinct results prevent access/session/device failures being treated as
// frame timeouts. Native HRESULTs are never interpreted as authorization.
enum class WindowsDxgiDuplicationResult
{
    ready, invalidTarget, unavailable, ambiguous, unsupported,
    accessDenied, accessLost, resourcePressure, failed, closed,
};

enum class WindowsDxgiEnumerationResult { item, end, failed };
enum class WindowsDxgiNativeResource
{
    factory, adapter, output, output1, device, context, duplication,
};

// Monitor identity is native HMONITOR (encoded without ownership), sampled
// from the SAME authorized desktop generation as expectedBounds.
// A rectangle alone is insufficient when outputs are ambiguous.
struct WindowsDxgiTarget
{
    std::uintptr_t monitor{};
    PortableRectangle expectedBounds{};
};

struct WindowsDxgiOutputDescription
{
    std::uintptr_t monitor{};
    PortableRectangle bounds{};
    bool attached{};
    bool identityRotation{};
};

// Injection seam executes the production enumeration/ownership algorithm in
// offline CTests. Each returned pointer owns exactly ONE reference. It must be
// released using release, including partial successes on failing callbacks.
struct WindowsDxgiNativeCallbacks
{
    void *context{};
    bool (*createFactory)(void *, void *&) noexcept{};
    WindowsDxgiEnumerationResult (*adapterAt)(
        void *, void *, std::uint32_t, void *&) noexcept{};
    WindowsDxgiEnumerationResult (*outputAt)(
        void *, void *, std::uint32_t, void *&) noexcept{};
    bool (*describeOutput)(
        void *, void *, WindowsDxgiOutputDescription &) noexcept{};
    bool (*createDevice)(void *, void *, void *&, void *&) noexcept{};
    bool (*queryOutput1)(void *, void *, void *&) noexcept{};
    WindowsDxgiDuplicationResult (*duplicate)(
        void *, void *, void *, void *&) noexcept{};
    void (*release)(void *, WindowsDxgiNativeResource, void *) noexcept{};
};

// Nonmoving, single-thread-affine RAII owner. No implicit authentication,
// desktop access, device recreation or R4 scheduler. Only call open AFTER
// R2/R3 independently bind an authorized target, never as an admission test.
// Close/cancel must execute on the serialized capture thread and never during
// an in-flight synchronous capture callback.
class WindowsDxgiDuplicationOwner final
{
public:
    explicit WindowsDxgiDuplicationOwner(
        WindowsDxgiNativeCallbacks callbacks) noexcept;
    ~WindowsDxgiDuplicationOwner() noexcept;
    WindowsDxgiDuplicationOwner(const WindowsDxgiDuplicationOwner &) = delete;
    WindowsDxgiDuplicationOwner &operator=(const WindowsDxgiDuplicationOwner &) = delete;
    WindowsDxgiDuplicationOwner(WindowsDxgiDuplicationOwner &&) = delete;
    WindowsDxgiDuplicationOwner &operator=(WindowsDxgiDuplicationOwner &&) = delete;

    [[nodiscard]] WindowsDxgiDuplicationResult open(
        WindowsDxgiTarget target) noexcept;
    // Closing is terminal: fresh R2/R3 authorization and a NEW owner are
    // required for any device/output/duplication reconstruction.
    void close() noexcept;
    [[nodiscard]] bool ready() const noexcept;
    [[nodiscard]] std::uint64_t deviceEpoch() const noexcept;
    [[nodiscard]] WindowsDxgiFrameCallbacks frameCallbacks() const noexcept;

#ifdef _WIN32
    // Optional owned composition for the existing capture cycle. The reader
    // is a revocation-only R2/R3 session source and must outlive this owner.
    // On close: cycle cancellation -> staging unmap -> frame release ->
    // native staging context -> duplication -> output -> device/adapter.
    [[nodiscard]] bool attachCaptureCycle(
        WindowsDesktopLayout layout,
        WindowsCaptureGenerationReader sessionReader,
        std::uint64_t pinnedSessionEpoch);
    [[nodiscard]] WindowsDxgiCaptureCycle *captureCycle() noexcept;
#endif

private:
    void releaseResource(WindowsDxgiNativeResource kind, void *&resource) noexcept;
    [[nodiscard]] bool hasCallbacks() const noexcept;
    [[nodiscard]] static bool observeGeneration(
        void *, WindowsCaptureGeneration &) noexcept;

    WindowsDxgiNativeCallbacks callbacks_{};
    void *factory_{};
    void *adapter_{};
    void *output_{};
    void *output1_{};
    void *device_{};
    void *context_{};
    void *duplication_{};
    WindowsDxgiTarget selected_{};
    WindowsCaptureGenerationReader sessionReader_{};
    std::uint64_t pinnedSessionEpoch_{};
    std::uint64_t deviceEpoch_{};
    bool closed_{};
#ifdef _WIN32
    std::unique_ptr<WindowsD3D11NativeStagingContext> stagingContext_{};
    std::unique_ptr<WindowsDxgiCaptureCycle> captureCycle_{};
#endif
};

// Real Windows SDK implementation. Produces no desktop capture on creation:
// open() must be invoked explicitly by the authorized R2/R3 caller.
[[nodiscard]] WindowsDxgiNativeCallbacks
windowsNativeDxgiDuplicationCallbacks() noexcept;

} // namespace rdp_server::windows
