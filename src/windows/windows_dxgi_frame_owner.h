// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

#ifdef _WIN32
struct IDXGIOutputDuplication;
#endif

namespace rdp_server::windows
{

// Desktop Duplication cannot interrupt an infinite wait; callers must poll
// with a bounded interval to observe disconnect, cancellation or OS changes.
inline constexpr std::uint32_t kMaximumWindowsDxgiFrameWaitMilliseconds = 100;

enum class WindowsDxgiAcquireResult
{
    acquired,
    timeout,
    accessLost,
    failed,
    busy,
    closed,
    invalidWait,
};

enum class WindowsDxgiReleaseResult
{
    released,
    accessLost,
    failed,
    notHeld,
};

// Callback seam used by the real IDXGIOutputDuplication adapter and by
// deterministic CTests. An acquired token represents one IDXGIResource COM
// reference AND the outstanding duplication-frame lease. release must drop
// the reference and call ReleaseFrame once, in that order. The context and
// callbacks must outlive this owner; calls are confined to the same thread.
struct WindowsDxgiFrameCallbacks
{
    void *context{};
    WindowsDxgiAcquireResult (*acquire)(void *context,
                                        std::uint32_t timeoutMilliseconds,
                                        void *&resource) noexcept{};
    WindowsDxgiReleaseResult (*release)(void *context,
                                        void *resource) noexcept{};
};

// Nonmoving, single-frame RAII owner. R2/R3 must authorize the native
// session BEFORE this owner is created; creating this object itself does
// not authorize or access a desktop. The borrowed resource() pointer is
// valid only until releaseFrame/cancel/destruction. Never hand it to R4
// asynchronously: copy/map into independently owned bytes first.
class WindowsDxgiFrameOwner final
{
public:
    explicit WindowsDxgiFrameOwner(WindowsDxgiFrameCallbacks callbacks) noexcept;
    ~WindowsDxgiFrameOwner() noexcept;

    WindowsDxgiFrameOwner(const WindowsDxgiFrameOwner &) = delete;
    WindowsDxgiFrameOwner &operator=(const WindowsDxgiFrameOwner &) = delete;
    WindowsDxgiFrameOwner(WindowsDxgiFrameOwner &&) = delete;
    WindowsDxgiFrameOwner &operator=(WindowsDxgiFrameOwner &&) = delete;

    [[nodiscard]] WindowsDxgiAcquireResult acquireFrame(
        std::uint32_t timeoutMilliseconds) noexcept;
    [[nodiscard]] WindowsDxgiReleaseResult releaseFrame() noexcept;
    void cancel() noexcept;

    [[nodiscard]] void *resource() const noexcept;
    [[nodiscard]] bool closed() const noexcept;

private:
    WindowsDxgiFrameCallbacks callbacks_{};
    void *resource_{};
    bool releaseInProgress_{};
    bool closed_{};
};

#ifdef _WIN32
// Borrows an already-created duplication from an authorized Windows session.
// Does not create one, trigger UAC, bind a session or capture a frame.
// The caller must retain the duplication until after owner destruction.
[[nodiscard]] WindowsDxgiFrameCallbacks windowsDxgiFrameCallbacks(
    IDXGIOutputDuplication &duplication) noexcept;
#endif

} // namespace rdp_server::windows
