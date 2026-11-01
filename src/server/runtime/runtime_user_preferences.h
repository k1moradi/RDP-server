// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "server/runtime/runtime_application_bootstrap.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace rdp_server::server::runtime
{

// Convenience only. None of these fields is an R2 admission, current native
// permission, R1 endpoint choice, or authorization to turn Sharing on.
// Passwords, credential material, and live generations have no representation.
struct RuntimeUserPreferences final
{
    std::string lastExplicitUsername;
    std::string preferredStableLanInterfaceId;
    std::uint16_t port{kRuntimeDefaultListenPort};
    bool preferRemoteInput{true};
    std::uint8_t permissionLifetimeMinutes{15U};
};

enum class RuntimeUserPreferencesStorageStatus : std::uint8_t
{
    Loaded,
    Stored,
    Missing,
    Invalid,
    Unavailable,
};

// Fixed versioned record (not the expert --config grammar). Output is changed
// only after complete validation; callers must not treat parse success as
// evidence of OS identity, owner consent, endpoint validity, or session scope.
[[nodiscard]] bool encodeRuntimeUserPreferences(
    const RuntimeUserPreferences& preferences,
    std::vector<std::byte>& encoded);

[[nodiscard]] bool decodeRuntimeUserPreferences(
    std::span<const std::byte> encoded,
    RuntimeUserPreferences& preferences);

// Only these entry points resolve the effective user's native configuration
// directory. They never consult the executable or current working directory.
// Missing/invalid/unavailable reads leave safe default preferences in output.
[[nodiscard]] RuntimeUserPreferencesStorageStatus loadRuntimeUserPreferences(
    RuntimeUserPreferences& preferences) noexcept;
[[nodiscard]] RuntimeUserPreferencesStorageStatus saveRuntimeUserPreferences(
    const RuntimeUserPreferences& preferences) noexcept;

} // namespace rdp_server::server::runtime
