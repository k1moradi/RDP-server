// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "server/runtime/runtime_user_preferences.h"

#include <cstdint>
#include <filesystem>

namespace rdp_server::server::runtime
{
namespace detail
{
#if defined(_WIN32)
// Production status classifier reused by the Windows error-code CTest;
// no caller-supplied path reaches the public preferences entry points.
[[nodiscard]] RuntimeUserPreferencesStorageStatus
classifyWindowsApplicationDirectoryOpenFailure(
    bool create, std::uint32_t errorCode) noexcept;

// Production LocalAppData ancestor-walk predicate, exposed only to the
// isolated offline Windows test. The public API still accepts no paths.
[[nodiscard]] bool windowsDirectoryHasNoReparseAncestorsForTesting(
    const std::filesystem::path& directory) noexcept;
#else
// POSIX-only resolver seam for the focused unsafe-ancestor CTest. It uses the
// same no-follow ownership/mode checks as production but starts from an
// isolated owner-private fake home. Production never accepts a caller path.
[[nodiscard]] RuntimeUserPreferencesStorageStatus
loadRuntimeUserPreferencesFromHomeDirectoryForTesting(
    const std::filesystem::path& homeDirectory,
    RuntimeUserPreferences& preferences) noexcept;
#endif

// Storage-engine seam for isolated offline tests. The caller must provide an
// already-created, owner-private app directory; production must use the
// no-path public entry points above. No R2/R10 control is reachable here.
[[nodiscard]] RuntimeUserPreferencesStorageStatus
loadRuntimeUserPreferencesFromDirectory(
    const std::filesystem::path& directory,
    RuntimeUserPreferences& preferences) noexcept;
[[nodiscard]] RuntimeUserPreferencesStorageStatus
saveRuntimeUserPreferencesToDirectory(
    const std::filesystem::path& directory,
    const RuntimeUserPreferences& preferences) noexcept;

// Offline fault seam for the existing storage CTest. It follows the real
// temporary-file write/flush path and fails immediately before atomic
// replacement. Production and R7 must use only the public no-path entry points.
[[nodiscard]] RuntimeUserPreferencesStorageStatus
saveRuntimeUserPreferencesToDirectoryWithAtomicReplaceFailureForTesting(
    const std::filesystem::path& directory,
    const RuntimeUserPreferences& preferences) noexcept;
} // namespace detail


} // namespace rdp_server::server::runtime
