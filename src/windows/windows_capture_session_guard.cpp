// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows_capture_session_guard.h"

#include <cstring>
#include <limits>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wtsapi32.h>
#endif

namespace rdp_server::windows
{

WindowsCaptureSessionGenerationGuard::WindowsCaptureSessionGenerationGuard(
    std::uint32_t targetSessionId,
    WindowsCaptureSessionReadCallbacks sessionReader,
    WindowsCaptureGenerationReader generationReader) noexcept
    : targetSessionId_(targetSessionId),
      sessionReader_(sessionReader),
      generationReader_(generationReader),
      closed_(targetSessionId == 0 ||
              targetSessionId == std::numeric_limits<std::uint32_t>::max() ||
              sessionReader.read == nullptr ||
              generationReader.read == nullptr)
{
}

WindowsCaptureGenerationReader
WindowsCaptureSessionGenerationGuard::reader() noexcept
{
    if (closed_)
    {
        return {};
    }
    return {this, &WindowsCaptureSessionGenerationGuard::readGeneration};
}

bool WindowsCaptureSessionGenerationGuard::readGeneration(
    void *context, WindowsCaptureGeneration &current) noexcept
{
    auto &guard =
        *static_cast<WindowsCaptureSessionGenerationGuard *>(context);
    if (guard.closed_)
    {
        return false;
    }
    if (guard.readInProgress_)
    {
        guard.closed_ = true;
        return false;
    }

    guard.readInProgress_ = true;
    WindowsCaptureSessionObservation session{};
    WindowsCaptureGeneration candidate{};
    bool valid = guard.sessionReader_.read(
        guard.sessionReader_.context, guard.targetSessionId_, session);
    if (valid)
    {
        valid = !guard.closed_ &&
                session.targetSessionId == guard.targetSessionId_ &&
                session.processSessionId == guard.targetSessionId_ &&
                session.targetActive;
    }
    if (valid)
    {
        valid = guard.generationReader_.read(
            guard.generationReader_.context, candidate);
    }
    if (valid)
    {
        valid = !guard.closed_ &&
                candidate.session != 0 && candidate.device != 0;
    }

    guard.readInProgress_ = false;
    if (!valid)
    {
        guard.closed_ = true;
        return false;
    }
    current = candidate;
    return true;
}

#ifdef _WIN32
namespace
{

bool readNativeCaptureSession(
    void *, std::uint32_t targetSessionId,
    WindowsCaptureSessionObservation &observation) noexcept
{
    if (targetSessionId == 0 ||
        targetSessionId == std::numeric_limits<std::uint32_t>::max())
    {
        return false;
    }

    DWORD processSessionId = 0;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &processSessionId))
    {
        return false;
    }

    LPWSTR rawState = nullptr;
    DWORD returnedBytes = 0;
    if (!WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE, static_cast<DWORD>(targetSessionId),
            WTSConnectState, &rawState, &returnedBytes))
    {
        return false;
    }

    WTS_CONNECTSTATE_CLASS state{};
    const bool validBuffer =
        rawState != nullptr && returnedBytes == sizeof(state);
    if (validBuffer)
    {
        std::memcpy(&state, rawState, sizeof(state));
    }
    if (rawState != nullptr)
    {
        WTSFreeMemory(rawState);
    }
    if (!validBuffer)
    {
        return false;
    }

    observation = {
        targetSessionId,
        static_cast<std::uint32_t>(processSessionId),
        state == WTSActive,
    };
    return true;
}

} // namespace

WindowsCaptureSessionReadCallbacks
windowsCaptureSessionReadCallbacks() noexcept
{
    return {nullptr, &readNativeCaptureSession};
}
#endif

} // namespace rdp_server::windows
