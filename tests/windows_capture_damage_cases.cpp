// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows/windows_dxgi_capture_cycle.h"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>

using namespace rdp_server::windows;

namespace
{
struct FakeDamageReader
{
    std::byte token{};
    std::array<std::byte, 24> pixels{};
    std::array<char, 20> order{};
    std::size_t orderCount{};
    unsigned acquisitions{}, releases{}, maps{}, unmaps{}, reads{};
    WindowsDxgiCaptureCycle *cycle{};
    WindowsDxgiDamageReadResult nextResult{WindowsDxgiDamageReadResult::ready};
    std::size_t moveCount{1}, dirtyCount{1};
    bool malformedDirty{}, cancelInside{}, reenter{};
    WindowsCaptureDamageResult reentrantResult{WindowsCaptureDamageResult::ready};

    void record(char value) noexcept
    {
        assert(orderCount < order.size());
        order[orderCount++] = value;
    }
    static WindowsDxgiAcquireResult acquire(
        void *raw, std::uint32_t, void *&resource,
        WindowsDxgiFrameInfo &) noexcept
    {
        auto &f = *static_cast<FakeDamageReader *>(raw);
        f.record('A');
        ++f.acquisitions;
        resource = &f.token;
        return WindowsDxgiAcquireResult::acquired;
    }
    static WindowsDxgiReleaseResult release(
        void *raw, void *resource) noexcept
    {
        auto &f = *static_cast<FakeDamageReader *>(raw);
        assert(resource == &f.token);
        f.record('R');
        ++f.releases;
        return WindowsDxgiReleaseResult::released;
    }
    static WindowsD3D11MapResult map(
        void *raw, void *resource, WindowsD3D11MappedData &output) noexcept
    {
        auto &f = *static_cast<FakeDamageReader *>(raw);
        assert(resource == &f.token);
        f.record('S');
        ++f.maps;
        output = {f.pixels.data(), 24, {2, 2}, 12, &f.token};
        return WindowsD3D11MapResult::mapped;
    }
    static void unmap(void *raw, void *handle) noexcept
    {
        auto &f = *static_cast<FakeDamageReader *>(raw);
        assert(handle == &f.token);
        f.record('U');
        ++f.unmaps;
        if (f.cycle)
            assert(f.cycle->frame().pixels.empty());
    }
    static WindowsDxgiDamageReadResult read(
        void *raw, std::span<WindowsDxgiMoveRectangle> moves,
        std::span<WindowsDxgiRectangle> dirties,
        std::size_t &moveCount, std::size_t &dirtyCount) noexcept
    {
        auto &f = *static_cast<FakeDamageReader *>(raw);
        f.record('D');
        ++f.reads;
        assert(f.cycle->frame().pixels.empty());
        if (f.reenter)
        {
            std::array<PortableRectangle, 4> scratch{};
            std::size_t n = 0;
            f.reentrantResult = f.cycle->readFrameDamage(scratch, n);
        }
        if (f.cancelInside)
            f.cycle->cancel();
        if (f.nextResult != WindowsDxgiDamageReadResult::ready)
            return f.nextResult;
        if (f.moveCount != 0 && !moves.empty())
            moves[0] = {{0, 0}, {1, 1, 2, 2}};
        if (f.dirtyCount != 0 && !dirties.empty())
            dirties[0] = f.malformedDirty ?
                WindowsDxgiRectangle{0, 0, 3, 1} :
                WindowsDxgiRectangle{0, 0, 1, 1};
        moveCount = f.moveCount;
        dirtyCount = f.dirtyCount;
        return WindowsDxgiDamageReadResult::ready;
    }
    [[nodiscard]] WindowsDxgiFrameCallbacks frames() noexcept
    {
        return {this, &acquire, &release};
    }
    [[nodiscard]] WindowsD3D11StagingCallbacks staging() noexcept
    {
        return {this, &map, &unmap};
    }
    [[nodiscard]] WindowsDxgiDamageReadCallbacks damage() noexcept
    {
        return {this, &read};
    }
    [[nodiscard]] static WindowsDesktopLayout layout() noexcept
    {
        WindowsDesktopLayout l{};
        l.monitorCount = 1;
        l.virtualBounds = {0, 0, 2, 2};
        l.monitors[0] = l.virtualBounds;
        return l;
    }
};
} // namespace

void windowsCaptureNativeDamageReadLifetime()
{
    FakeDamageReader f{};
    WindowsDxgiCaptureCycle cycle(
        FakeDamageReader::layout(), f.frames(), f.staging(), f.damage());
    f.cycle = &cycle;

    std::array<PortableRectangle, 4> output{};
    output[2] = {7, 8, 9, 10};
    std::size_t written = 999;
    assert(cycle.readFrameDamage(output, written) ==
           WindowsCaptureDamageResult::noFrame);
    assert(written == 999 && f.reads == 0);

    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    f.reenter = true;
    assert(cycle.readFrameDamage(output, written) ==
           WindowsCaptureDamageResult::ready);
    assert(f.reentrantResult == WindowsCaptureDamageResult::busy);
    assert(written == 2);
    assert((output[0] == PortableRectangle{1, 1, 1, 1}));
    assert((output[1] == PortableRectangle{0, 0, 1, 1}));
    assert((output[2] == PortableRectangle{7, 8, 9, 10}));
    assert(f.unmaps == 0 && f.releases == 0);
    assert(f.orderCount == 3 && f.order[2] == 'D');
    assert(cycle.releaseFrame());
    assert(f.unmaps == 1 && f.releases == 1);
    assert(f.order[3] == 'U' && f.order[4] == 'R');

    assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
    f.moveCount = 0;
    f.dirtyCount = 0;
    written = 99;
    assert(cycle.readFrameDamage(output, written) ==
           WindowsCaptureDamageResult::ready);
    assert(written == 0 && !cycle.closed());
    assert(cycle.releaseFrame());
}

void windowsCaptureNativeDamageReadDenials()
{
    for (int scenario = 0; scenario < 6; ++scenario)
    {
        FakeDamageReader f{};
        WindowsDxgiCaptureCycle cycle(
            FakeDamageReader::layout(), f.frames(), f.staging(),
            scenario == 5 ? WindowsDxgiDamageReadCallbacks{} : f.damage());
        f.cycle = &cycle;
        std::array<PortableRectangle, 3> output{};
        output[0] = {7, 8, 9, 10};
        std::size_t written = 77;

        assert(cycle.captureFrame(0) == WindowsCaptureCycleResult::mapped);
        if (scenario == 0) f.moveCount = 1025;
        if (scenario == 1) f.malformedDirty = true;
        if (scenario == 2) f.nextResult = WindowsDxgiDamageReadResult::accessLost;
        if (scenario == 3) f.cancelInside = true;
        if (scenario == 4) { f.dirtyCount = 3; f.moveCount = 1; }

        const auto result = cycle.readFrameDamage(output, written);
        if (scenario == 0 || scenario == 1 || scenario == 4)
            assert(result == WindowsCaptureDamageResult::invalid);
        else if (scenario == 2)
            assert(result == WindowsCaptureDamageResult::accessLost);
        else if (scenario == 3)
            assert(result == WindowsCaptureDamageResult::closed);
        else
            assert(result == WindowsCaptureDamageResult::unavailable);

        assert(cycle.closed() && f.unmaps == 1 && f.releases == 1);
        assert(written == 77 &&
               (output[0] == PortableRectangle{7, 8, 9, 10}));
        assert(f.order[f.orderCount - 2] == 'U' &&
               f.order[f.orderCount - 1] == 'R');
        assert(cycle.readFrameDamage(output, written) ==
               WindowsCaptureDamageResult::closed);
    }
}
