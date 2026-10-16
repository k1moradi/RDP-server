// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows/windows_dxgi_duplication_owner.h"

#include <array>
#include <cassert>
#include <cstdint>

using namespace rdp_server::windows;

namespace
{
struct FakeDxgiBackend
{
    enum class Failure
    {
        none, factory, adapters, outputs, description, device,
        missingContext, output1, duplicate, changedOutput
    };
    enum class ReentryPhase
    {
        none, factory, adapter, output, description, device, output1,
        duplicate, selectedAdapterEnd
    };
    struct Token
    {
        unsigned outstanding{};
        unsigned releases{};
    };

    Token factory{}, adapters[2]{}, outputs[2][2]{};
    Token device{}, context{}, output1{}, duplication{};
    Failure failure{Failure::none};
    ReentryPhase reentryPhase{ReentryPhase::none};
    WindowsDxgiDuplicationResult duplicateResult{
        WindowsDxgiDuplicationResult::ready};
    WindowsDxgiDuplicationResult nestedOpenResult{
        WindowsDxgiDuplicationResult::invalidTarget};
    WindowsDxgiDuplicationOwner *owner{};
    Token *closeOnRelease{};
    bool detached{}, empty{}, rotated{}, wrongMonitor{}, ambiguous{};
    bool sameAdapterAmbiguous{};
    bool repeatSelectedAdapterReference{};
    bool enumeratingRepeatedAdapter{};
    bool assignFailureResource{};
    bool reenterOpen{};
    bool closeOnEveryRelease{};
    bool releaseReentryIssued{};
    bool requireChildRetiredBeforeRelease{};
    unsigned adapterCount{2};
    unsigned outputCount{2};
    unsigned factoryCalls{};
    unsigned adapterCalls{};
    unsigned outputCalls{};
    unsigned descriptions{};
    unsigned createDeviceCalls{};
    unsigned output1Calls{};
    unsigned duplicateCalls{};
    unsigned releaseSequence{};
    unsigned duplicationReleasedAt{};
    unsigned output1ReleasedAt{};
    unsigned contextReleasedAt{};
    unsigned deviceReleasedAt{};
    unsigned outputReleasedAt{};
    unsigned adapterReleasedAt{};
    unsigned factoryReleasedAt{};

    static FakeDxgiBackend &backend(void *context) noexcept
    {
        return *static_cast<FakeDxgiBackend *>(context);
    }
    static void assign(void *&out, Token &token) noexcept
    {
        assert(token.outstanding == 0);
        token.outstanding = 1;
        out = &token;
    }
    static void retain(void *&out, Token &token) noexcept
    {
        assert(token.outstanding != 0);
        ++token.outstanding;
        out = &token;
    }
    void closeOwner() noexcept
    {
        assert(owner != nullptr);
        owner->close();
    }
    void closeIf(ReentryPhase phase) noexcept
    {
        if (reentryPhase == phase)
            closeOwner();
    }
    static bool createFactory(void *context, void *&out) noexcept
    {
        auto &self = backend(context);
        ++self.factoryCalls;
        if (self.failure == Failure::factory)
        {
            if (self.assignFailureResource)
                assign(out, self.factory);
            return false;
        }
        assign(out, self.factory);
        if (self.reenterOpen)
        {
            self.reenterOpen = false;
            assert(self.owner != nullptr);
            self.nestedOpenResult = self.owner->open(
                {1234U, {-1920, 0, 1920, 1080}});
        }
        self.closeIf(ReentryPhase::factory);
        return true;
    }
    static WindowsDxgiEnumerationResult adapterAt(
        void *context, void *, std::uint32_t index, void *&out) noexcept
    {
        auto &self = backend(context);
        ++self.adapterCalls;
        if (self.failure == Failure::adapters)
        {
            if (self.assignFailureResource)
                assign(out, self.adapters[0]);
            return WindowsDxgiEnumerationResult::failed;
        }
        self.enumeratingRepeatedAdapter = false;
        if (self.repeatSelectedAdapterReference && index == 2)
        {
            assert(self.adapterCount == 3);
            self.enumeratingRepeatedAdapter = true;
            retain(out, self.adapters[1]);
            return WindowsDxgiEnumerationResult::item;
        }
        if (index >= self.adapterCount)
            return WindowsDxgiEnumerationResult::end;
        assert(index < std::size(self.adapters));
        assign(out, self.adapters[index]);
        self.closeIf(ReentryPhase::adapter);
        return WindowsDxgiEnumerationResult::item;
    }
    static WindowsDxgiEnumerationResult outputAt(
        void *context, void *adapter, std::uint32_t index,
        void *&out) noexcept
    {
        auto &self = backend(context);
        ++self.outputCalls;
        const unsigned adapterIndex =
            adapter == &self.adapters[0] ? 0U : 1U;
        if (self.failure == Failure::outputs)
        {
            if (self.assignFailureResource)
                assign(out, self.outputs[adapterIndex][0]);
            return WindowsDxgiEnumerationResult::failed;
        }
        if (self.enumeratingRepeatedAdapter &&
            adapter == &self.adapters[1])
        {
            return WindowsDxgiEnumerationResult::end;
        }
        if (self.reentryPhase == ReentryPhase::selectedAdapterEnd &&
            adapter == &self.adapters[1] && index >= self.outputCount)
        {
            self.closeOwner();
        }
        if (index >= self.outputCount)
            return WindowsDxgiEnumerationResult::end;
        assign(out, self.outputs[adapterIndex][index]);
        self.closeIf(ReentryPhase::output);
        return WindowsDxgiEnumerationResult::item;
    }
    static bool describe(
        void *context, void *output,
        WindowsDxgiOutputDescription &description) noexcept
    {
        auto &self = backend(context);
        ++self.descriptions;
        if (self.failure == Failure::description)
            return false;
        const bool matching = output == &self.outputs[1][1] ||
            (self.ambiguous && output == &self.outputs[0][0]) ||
            (self.sameAdapterAmbiguous && output == &self.outputs[1][0]);
        description = {
            matching && !self.wrongMonitor ? 1234U : 5678U,
            {matching ? -1920 : 0, 0,
             self.empty && matching ? 0U : 1920U, 1080},
            !(self.detached && matching),
            !(self.rotated && matching)};
        if (self.failure == Failure::changedOutput &&
            self.descriptions > 4 && matching)
            description.bounds.widthPixels = 1800;
        self.closeIf(ReentryPhase::description);
        return true;
    }
    static bool createDevice(
        void *context, void *, void *&outDevice, void *&outContext) noexcept
    {
        auto &self = backend(context);
        ++self.createDeviceCalls;
        if (self.failure == Failure::device)
        {
            if (self.assignFailureResource)
            {
                assign(outDevice, self.device);
                assign(outContext, self.context);
            }
            return false;
        }
        assign(outDevice, self.device);
        if (self.failure != Failure::missingContext)
            assign(outContext, self.context);
        self.closeIf(ReentryPhase::device);
        return true;
    }
    static bool queryOutput1(
        void *context, void *, void *&out) noexcept
    {
        auto &self = backend(context);
        ++self.output1Calls;
        if (self.failure == Failure::output1)
        {
            if (self.assignFailureResource)
                assign(out, self.output1);
            return false;
        }
        assign(out, self.output1);
        self.closeIf(ReentryPhase::output1);
        return true;
    }
    static WindowsDxgiDuplicationResult duplicate(
        void *context, void *, void *, void *&out) noexcept
    {
        auto &self = backend(context);
        ++self.duplicateCalls;
        if (self.failure == Failure::duplicate)
        {
            if (self.assignFailureResource)
                assign(out, self.duplication);
            return self.duplicateResult;
        }
        assign(out, self.duplication);
        self.closeIf(ReentryPhase::duplicate);
        return WindowsDxgiDuplicationResult::ready;
    }
    static void release(
        void *context, WindowsDxgiNativeResource kind,
        void *resource) noexcept
    {
        auto &self = backend(context);
        auto &token = *static_cast<Token *>(resource);
        if (self.requireChildRetiredBeforeRelease)
        {
            assert(self.owner != nullptr);
            assert(self.owner->captureCycle() == nullptr);
        }
        const bool shouldReenter =
            self.owner != nullptr && !self.releaseReentryIssued &&
            (self.closeOnEveryRelease || self.closeOnRelease == &token);
        if (shouldReenter)
        {
            self.releaseReentryIssued = true;
            self.owner->close();
        }
        assert(token.outstanding != 0);
        --token.outstanding;
        ++token.releases;
        ++self.releaseSequence;
        switch (kind)
        {
        case WindowsDxgiNativeResource::factory:
            self.factoryReleasedAt = self.releaseSequence; break;
        case WindowsDxgiNativeResource::adapter:
            self.adapterReleasedAt = self.releaseSequence; break;
        case WindowsDxgiNativeResource::output:
            self.outputReleasedAt = self.releaseSequence; break;
        case WindowsDxgiNativeResource::output1:
            self.output1ReleasedAt = self.releaseSequence; break;
        case WindowsDxgiNativeResource::device:
            self.deviceReleasedAt = self.releaseSequence; break;
        case WindowsDxgiNativeResource::context:
            self.contextReleasedAt = self.releaseSequence; break;
        case WindowsDxgiNativeResource::duplication:
            self.duplicationReleasedAt = self.releaseSequence; break;
        }
    }
    [[nodiscard]] WindowsDxgiNativeCallbacks callbacks() noexcept
    {
        return {this, &createFactory, &adapterAt, &outputAt, &describe,
                &createDevice, &queryOutput1, &duplicate, &release};
    }
    void assertReleased() const noexcept
    {
        assert(factory.outstanding == 0);
        for (const auto &adapter : adapters)
            assert(adapter.outstanding == 0);
        for (const auto &row : outputs)
            for (const auto &output : row)
                assert(output.outstanding == 0);
        assert(device.outstanding == 0 && context.outstanding == 0);
        assert(output1.outstanding == 0 && duplication.outstanding == 0);
    }
};
constexpr WindowsDxgiTarget selectedTarget{
    1234, {-1920, 0, 1920, 1080}};

bool readGeneration(
    void *, WindowsCaptureGeneration &generation) noexcept
{
    generation = {41, 73};
    return true;
}

[[nodiscard]] WindowsDesktopLayout selectedLayout() noexcept
{
    constexpr std::array monitors{selectedTarget.expectedBounds};
    WindowsDesktopLayout layout{};
    assert(makeWindowsDesktopLayout(monitors, layout));
    return layout;
}
} // namespace

void windowsDxgiDuplicationOwnerLifecycle()
{
    FakeDxgiBackend backend{};
    {
        WindowsDxgiDuplicationOwner owner(backend.callbacks());
        assert(owner.open(selectedTarget) == WindowsDxgiDuplicationResult::ready);
        assert(owner.ready() && owner.deviceEpoch() != 0);
        assert(owner.open(selectedTarget) == WindowsDxgiDuplicationResult::closed);
        assert(backend.duplication.outstanding == 1 &&
               backend.device.outstanding == 1 &&
               backend.context.outstanding == 1 &&
               backend.adapters[1].outstanding == 1 &&
               backend.outputs[1][1].outstanding == 1);
        owner.close();
        assert(!owner.ready() && owner.deviceEpoch() == 0);
        assert(backend.duplicationReleasedAt != 0);
        assert(backend.duplicationReleasedAt < backend.contextReleasedAt);
        assert(backend.contextReleasedAt < backend.deviceReleasedAt);
        assert(backend.deviceReleasedAt < backend.outputReleasedAt);
        assert(backend.outputReleasedAt < backend.adapterReleasedAt);
        assert(backend.adapterReleasedAt < backend.factoryReleasedAt);
        owner.close();
        assert(owner.open(selectedTarget) == WindowsDxgiDuplicationResult::closed);
    }
    backend.assertReleased();
    assert(backend.duplication.releases == 1 &&
           backend.device.releases == 1 && backend.context.releases == 1 &&
           backend.output1.releases == 1 &&
           backend.outputs[1][1].releases == 1);
}

void windowsDxgiDuplicationOwnerSelectionDenials()
{
    auto denied = [](FakeDxgiBackend backend,
                     WindowsDxgiDuplicationResult expected) {
        WindowsDxgiDuplicationOwner owner(backend.callbacks());
        assert(owner.open(selectedTarget) == expected);
        assert(!owner.ready() && owner.deviceEpoch() == 0);
        owner.close();
        backend.assertReleased();
    };
    FakeDxgiBackend noAdapters{};
    noAdapters.adapterCount = 0;
    denied(noAdapters, WindowsDxgiDuplicationResult::unavailable);
    FakeDxgiBackend noOutputs{};
    noOutputs.outputCount = 0;
    denied(noOutputs, WindowsDxgiDuplicationResult::unavailable);
    FakeDxgiBackend detached{};
    detached.detached = true;
    denied(detached, WindowsDxgiDuplicationResult::unavailable);
    FakeDxgiBackend empty{};
    empty.empty = true;
    denied(empty, WindowsDxgiDuplicationResult::unavailable);
    FakeDxgiBackend rotated{};
    rotated.rotated = true;
    denied(rotated, WindowsDxgiDuplicationResult::unavailable);
    FakeDxgiBackend wrong{};
    wrong.wrongMonitor = true;
    denied(wrong, WindowsDxgiDuplicationResult::unavailable);
    FakeDxgiBackend ambiguous{};
    ambiguous.ambiguous = true;
    denied(ambiguous, WindowsDxgiDuplicationResult::ambiguous);
    for (auto failure : {
             FakeDxgiBackend::Failure::factory,
             FakeDxgiBackend::Failure::adapters,
             FakeDxgiBackend::Failure::outputs,
             FakeDxgiBackend::Failure::description})
    {
        FakeDxgiBackend backend{};
        backend.failure = failure;
        denied(backend, WindowsDxgiDuplicationResult::failed);
    }
    for (auto failure : {
             FakeDxgiBackend::Failure::device,
             FakeDxgiBackend::Failure::missingContext,
             FakeDxgiBackend::Failure::output1})
    {
        FakeDxgiBackend backend{};
        backend.failure = failure;
        denied(backend, WindowsDxgiDuplicationResult::unsupported);
    }
    FakeDxgiBackend failedDuplication{};
    failedDuplication.failure = FakeDxgiBackend::Failure::duplicate;
    failedDuplication.duplicateResult =
        WindowsDxgiDuplicationResult::accessDenied;
    denied(failedDuplication, WindowsDxgiDuplicationResult::accessDenied);
    FakeDxgiBackend changed{};
    changed.failure = FakeDxgiBackend::Failure::changedOutput;
    denied(changed, WindowsDxgiDuplicationResult::accessLost);
    FakeDxgiBackend backend{};
    WindowsDxgiDuplicationOwner invalid(backend.callbacks());
    assert(invalid.open({}) == WindowsDxgiDuplicationResult::invalidTarget);
    assert(!invalid.ready());
    invalid.close();
    backend.assertReleased();
}

void windowsDxgiDuplicationOwnerSameAdapterAmbiguity()
{
    FakeDxgiBackend backend{};
    backend.sameAdapterAmbiguous = true;
    {
        WindowsDxgiDuplicationOwner owner(backend.callbacks());
        assert(owner.open(selectedTarget) ==
               WindowsDxgiDuplicationResult::ambiguous);
        assert(!owner.ready() && owner.deviceEpoch() == 0);
        owner.close();
    }
    backend.assertReleased();
    // Both matching outputs belong to adapter 1. The outputs are distinct
    // owned references, but the retained adapter is one reference and must
    // be released exactly once even though candidateAdapter aliases adapter_.
    assert(backend.outputs[1][0].releases == 1);
    assert(backend.outputs[1][1].releases == 1);
    assert(backend.adapters[1].releases == 1);
}

void windowsDxgiDuplicationOwnerRepeatedAdapterReference()
{
    FakeDxgiBackend backend{};
    backend.repeatSelectedAdapterReference = true;
    backend.adapterCount = 3;
    {
        WindowsDxgiDuplicationOwner owner(backend.callbacks());
        assert(owner.open(selectedTarget) ==
               WindowsDxgiDuplicationResult::ready);
        assert(owner.ready());

        // adapterAt returned adapter 1 twice. The interface address is the
        // same, but the second callback return owns a separate reference and
        // must already have been released after its empty output scan.
        assert(backend.adapters[1].outstanding == 1);
        assert(backend.adapters[1].releases == 1);

        owner.close();
    }
    backend.assertReleased();
    assert(backend.adapters[1].releases == 2);
}

void windowsDxgiDuplicationOwnerCaptureCycleSingleAttach()
{
    FakeDxgiBackend backend{};
    WindowsDxgiDuplicationOwner owner(backend.callbacks());
    assert(owner.open(selectedTarget) == WindowsDxgiDuplicationResult::ready);

    int readerContext = 0;
    const WindowsCaptureGenerationReader reader{&readerContext, &readGeneration};
    assert(owner.attachCaptureCycle(selectedLayout(), reader, 41));
    auto *const attached = owner.captureCycle();
    assert(attached != nullptr && !attached->closed());
    assert(owner.ready());

    // One duplication owner has exactly one capture-cycle subordinate. A
    // second attach cannot replace the already-live cycle or mutate readiness.
    assert(!owner.attachCaptureCycle(selectedLayout(), reader, 41));
    assert(owner.captureCycle() == attached);
    assert(owner.ready());

    owner.close();
    assert(owner.captureCycle() == nullptr);
    assert(!owner.ready());
    owner.close();
    backend.assertReleased();
    assert(backend.duplication.releases == 1);
    assert(backend.context.releases == 1);
    assert(backend.device.releases == 1);
}

void windowsDxgiDuplicationOwnerCaptureCycleLayoutDenials()
{
    FakeDxgiBackend backend{};
    WindowsDxgiDuplicationOwner owner(backend.callbacks());
    assert(owner.open(selectedTarget) == WindowsDxgiDuplicationResult::ready);

    int readerContext = 0;
    const WindowsCaptureGenerationReader reader{&readerContext, &readGeneration};

    // The fixed monitor array must be bounded before any iteration.
    WindowsDesktopLayout oversized{};
    oversized.monitorCount = kMaximumWindowsDesktopMonitors + 1;
    assert(!owner.attachCaptureCycle(oversized, reader, 41));
    assert(owner.captureCycle() == nullptr && owner.ready());

    // A matching monitor inside a non-canonical virtual desktop must fail
    // before native wrappers are installed, leaving the owner retryable.
    WindowsDesktopLayout nonCanonical{};
    nonCanonical.monitorCount = 1;
    nonCanonical.monitors[0] = selectedTarget.expectedBounds;
    nonCanonical.virtualBounds = {-1920, 0, 1919, 1080};
    assert(!owner.attachCaptureCycle(nonCanonical, reader, 41));
    assert(owner.captureCycle() == nullptr && owner.ready());

    owner.close();
    backend.assertReleased();
}

void windowsDxgiDuplicationOwnerEpochRevocation()
{
    FakeDxgiBackend first{};
    FakeDxgiBackend second{};
    WindowsDxgiDuplicationOwner owner(first.callbacks());
    WindowsDxgiDuplicationOwner later(second.callbacks());
    assert(owner.open(selectedTarget) == WindowsDxgiDuplicationResult::ready);
    const auto oldEpoch = owner.deviceEpoch();
    owner.close();
    assert(owner.deviceEpoch() == 0);
    assert(later.open(selectedTarget) == WindowsDxgiDuplicationResult::ready);
    assert(later.deviceEpoch() != 0 && later.deviceEpoch() != oldEpoch);
    later.close();
    first.assertReleased();
    second.assertReleased();
}


void windowsDxgiDuplicationOwnerReleaseReentry()
{
    FakeDxgiBackend backend{};
    WindowsDxgiDuplicationOwner owner(backend.callbacks());
    backend.owner = &owner;
    assert(owner.open(selectedTarget) == WindowsDxgiDuplicationResult::ready);

    backend.closeOnEveryRelease = true;
    owner.close();
    assert(backend.releaseReentryIssued);
    assert(!owner.ready() && owner.deviceEpoch() == 0);
    assert(backend.duplicationReleasedAt != 0);
    assert(backend.duplicationReleasedAt < backend.output1ReleasedAt);
    assert(backend.output1ReleasedAt < backend.contextReleasedAt);
    assert(backend.contextReleasedAt < backend.deviceReleasedAt);
    assert(backend.deviceReleasedAt < backend.outputReleasedAt);
    assert(backend.outputReleasedAt < backend.adapterReleasedAt);
    assert(backend.adapterReleasedAt < backend.factoryReleasedAt);
    owner.close();
    backend.assertReleased();
    assert(backend.duplication.releases == 1);
    assert(backend.output1.releases == 1);
    assert(backend.context.releases == 1);
    assert(backend.device.releases == 1);
    assert(backend.outputs[1][1].releases == 1);
    assert(backend.adapters[1].releases == 1);
    assert(backend.factory.releases == 1);
}

void windowsDxgiDuplicationOwnerOpenCancelReentry()
{
    {
        FakeDxgiBackend backend{};
        backend.reenterOpen = true;
        WindowsDxgiDuplicationOwner owner(backend.callbacks());
        backend.owner = &owner;
        assert(owner.open(selectedTarget) ==
               WindowsDxgiDuplicationResult::ready);
        assert(backend.nestedOpenResult ==
               WindowsDxgiDuplicationResult::closed);
        assert(owner.ready() && owner.deviceEpoch() != 0);
        owner.close();
        backend.assertReleased();
    }

    constexpr std::array phases{
        FakeDxgiBackend::ReentryPhase::factory,
        FakeDxgiBackend::ReentryPhase::adapter,
        FakeDxgiBackend::ReentryPhase::output,
        FakeDxgiBackend::ReentryPhase::description,
        FakeDxgiBackend::ReentryPhase::device,
        FakeDxgiBackend::ReentryPhase::output1,
        FakeDxgiBackend::ReentryPhase::duplicate,
        FakeDxgiBackend::ReentryPhase::selectedAdapterEnd};
    for (const auto phase : phases)
    {
        FakeDxgiBackend backend{};
        backend.reentryPhase = phase;
        WindowsDxgiDuplicationOwner owner(backend.callbacks());
        backend.owner = &owner;
        assert(owner.open(selectedTarget) ==
               WindowsDxgiDuplicationResult::closed);
        assert(!owner.ready() && owner.deviceEpoch() == 0);
        assert(owner.open(selectedTarget) ==
               WindowsDxgiDuplicationResult::closed);
        backend.assertReleased();

        if (phase == FakeDxgiBackend::ReentryPhase::factory)
            assert(backend.adapterCalls == 0);
        if (phase == FakeDxgiBackend::ReentryPhase::adapter)
            assert(backend.outputCalls == 0);
        if (phase == FakeDxgiBackend::ReentryPhase::output)
            assert(backend.descriptions == 0);
        if (phase == FakeDxgiBackend::ReentryPhase::description)
            assert(backend.createDeviceCalls == 0);
        if (phase == FakeDxgiBackend::ReentryPhase::device)
            assert(backend.output1Calls == 0);
        if (phase == FakeDxgiBackend::ReentryPhase::output1)
        {
            assert(backend.descriptions == 4);
            assert(backend.duplicateCalls == 0);
        }
        if (phase == FakeDxgiBackend::ReentryPhase::duplicate)
            assert(backend.duplicateCalls == 1);
        if (phase == FakeDxgiBackend::ReentryPhase::selectedAdapterEnd)
            assert(backend.createDeviceCalls == 0);
    }
}

void windowsDxgiDuplicationOwnerPartialResultCleanup()
{
    auto partial = [](FakeDxgiBackend::Failure failure,
                      WindowsDxgiDuplicationResult expected,
                      auto verify) {
        FakeDxgiBackend backend{};
        backend.failure = failure;
        backend.assignFailureResource = true;
        if (failure == FakeDxgiBackend::Failure::duplicate)
            backend.duplicateResult =
                WindowsDxgiDuplicationResult::accessDenied;
        WindowsDxgiDuplicationOwner owner(backend.callbacks());
        backend.owner = &owner;
        assert(owner.open(selectedTarget) == expected);
        assert(!owner.ready() && owner.deviceEpoch() == 0);
        owner.close();
        backend.assertReleased();
        verify(backend);
    };

    partial(FakeDxgiBackend::Failure::factory,
            WindowsDxgiDuplicationResult::failed,
            [](const auto &backend) {
                assert(backend.factory.releases == 1);
            });
    partial(FakeDxgiBackend::Failure::adapters,
            WindowsDxgiDuplicationResult::failed,
            [](const auto &backend) {
                assert(backend.adapters[0].releases == 1);
            });
    partial(FakeDxgiBackend::Failure::outputs,
            WindowsDxgiDuplicationResult::failed,
            [](const auto &backend) {
                assert(backend.outputs[0][0].releases == 1);
            });
    partial(FakeDxgiBackend::Failure::device,
            WindowsDxgiDuplicationResult::unsupported,
            [](const auto &backend) {
                assert(backend.device.releases == 1);
                assert(backend.context.releases == 1);
            });
    partial(FakeDxgiBackend::Failure::output1,
            WindowsDxgiDuplicationResult::unsupported,
            [](const auto &backend) {
                assert(backend.output1.releases == 1);
            });
    partial(FakeDxgiBackend::Failure::duplicate,
            WindowsDxgiDuplicationResult::accessDenied,
            [](const auto &backend) {
                assert(backend.duplication.releases == 1);
            });
}

void windowsDxgiDuplicationOwnerAmbiguousReentry()
{
    auto exercise = [](bool sameAdapter) {
        FakeDxgiBackend backend{};
        backend.sameAdapterAmbiguous = sameAdapter;
        backend.ambiguous = !sameAdapter;
        WindowsDxgiDuplicationOwner owner(backend.callbacks());
        backend.owner = &owner;
        backend.closeOnRelease = &backend.outputs[1][1];

        assert(owner.open(selectedTarget) ==
               WindowsDxgiDuplicationResult::closed);
        assert(backend.releaseReentryIssued);
        assert(!owner.ready() && owner.deviceEpoch() == 0);
        owner.close();
        backend.assertReleased();
        assert(backend.outputs[1][1].releases == 1);
        assert(backend.adapters[0].releases == 1);
        assert(backend.adapters[1].releases == 1);
        if (sameAdapter)
            assert(backend.outputs[1][0].releases == 1);
        else
            assert(backend.outputs[0][0].releases == 1);
    };

    exercise(true);
    exercise(false);
}

void windowsDxgiDuplicationOwnerChildCloseOrder()
{
    FakeDxgiBackend backend{};
    WindowsDxgiDuplicationOwner owner(backend.callbacks());
    backend.owner = &owner;
    assert(owner.open(selectedTarget) == WindowsDxgiDuplicationResult::ready);

    int readerContext = 0;
    const WindowsCaptureGenerationReader reader{&readerContext, &readGeneration};
    assert(owner.attachCaptureCycle(selectedLayout(), reader, 41));
    assert(owner.captureCycle() != nullptr);

    backend.requireChildRetiredBeforeRelease = true;
    backend.closeOnEveryRelease = true;
    owner.close();
    assert(backend.releaseReentryIssued);
    assert(owner.captureCycle() == nullptr);
    assert(!owner.ready() && owner.deviceEpoch() == 0);
    owner.close();
    backend.assertReleased();
}
