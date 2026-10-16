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
    struct Token
    {
        unsigned outstanding{};
        unsigned releases{};
    };
    Token factory{}, adapters[2]{}, outputs[2][2]{};
    Token device{}, context{}, output1{}, duplication{};
    Failure failure{Failure::none};
    WindowsDxgiDuplicationResult duplicateResult{
        WindowsDxgiDuplicationResult::ready};
    bool detached{}, empty{}, rotated{}, wrongMonitor{}, ambiguous{};
    bool sameAdapterAmbiguous{};
    unsigned adapterCount{2};
    unsigned outputCount{2};
    unsigned descriptions{};
    unsigned releaseSequence{};
    unsigned duplicationReleasedAt{};
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
    static bool createFactory(void *context, void *&out) noexcept
    {
        auto &self = backend(context);
        if (self.failure == Failure::factory)
            return false;
        assign(out, self.factory);
        return true;
    }
    static WindowsDxgiEnumerationResult adapterAt(
        void *context, void *, std::uint32_t index, void *&out) noexcept
    {
        auto &self = backend(context);
        if (self.failure == Failure::adapters)
            return WindowsDxgiEnumerationResult::failed;
        if (index >= self.adapterCount)
            return WindowsDxgiEnumerationResult::end;
        assign(out, self.adapters[index]);
        return WindowsDxgiEnumerationResult::item;
    }
    static WindowsDxgiEnumerationResult outputAt(
        void *context, void *adapter, std::uint32_t index,
        void *&out) noexcept
    {
        auto &self = backend(context);
        if (self.failure == Failure::outputs)
            return WindowsDxgiEnumerationResult::failed;
        if (index >= self.outputCount)
            return WindowsDxgiEnumerationResult::end;
        const unsigned adapterIndex = adapter == &self.adapters[0] ? 0U : 1U;
        assign(out, self.outputs[adapterIndex][index]);
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
        return true;
    }
    static bool createDevice(
        void *context, void *, void *&outDevice, void *&outContext) noexcept
    {
        auto &self = backend(context);
        if (self.failure == Failure::device)
            return false;
        assign(outDevice, self.device);
        if (self.failure != Failure::missingContext)
            assign(outContext, self.context);
        return true;
    }
    static bool queryOutput1(
        void *context, void *, void *&out) noexcept
    {
        auto &self = backend(context);
        if (self.failure == Failure::output1)
            return false;
        assign(out, self.output1);
        return true;
    }
    static WindowsDxgiDuplicationResult duplicate(
        void *context, void *, void *, void *&out) noexcept
    {
        auto &self = backend(context);
        if (self.failure == Failure::duplicate)
            return self.duplicateResult;
        assign(out, self.duplication);
        return WindowsDxgiDuplicationResult::ready;
    }
    static void release(
        void *context, WindowsDxgiNativeResource kind,
        void *resource) noexcept
    {
        auto &self = backend(context);
        auto &token = *static_cast<Token *>(resource);
        assert(token.outstanding == 1);
        token.outstanding = 0;
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
        case WindowsDxgiNativeResource::device:
            self.deviceReleasedAt = self.releaseSequence; break;
        case WindowsDxgiNativeResource::context:
            self.contextReleasedAt = self.releaseSequence; break;
        case WindowsDxgiNativeResource::duplication:
            self.duplicationReleasedAt = self.releaseSequence; break;
        case WindowsDxgiNativeResource::output1: break;
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
