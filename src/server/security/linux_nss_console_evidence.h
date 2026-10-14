// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "console_os_evidence.h"

namespace rdp_server::server::security
{

// Read-only Linux/NSS account observation using the system's getpwnam_r.
// NSS configuration and its backends are external trust dependencies:
// a successful lookup does NOT authenticate a Kerberos user or prove who
// owns an active physical console. No service is started or configured.
//
// Threading: no mutable or cached state; simultaneous calls use separate
// stack buffers and libc's reentrant API. An NSS backend may still block.
// The returned account view borrows the input argument for the duration
// of its caller's synchronous inspection; never retain that view.
//
// NO logind/X11/session adapter is present in this milestone. Console
// evidence is ALWAYS Unavailable and consequently inspection always
// denies even when NSS resolves a legitimate local account.
class LinuxNssReadOnlyEvidenceSource final : public ConsoleOsEvidenceSource
{
public:
    [[nodiscard]] ConsoleAccountObservation readUnixAccount(
        std::string_view account) noexcept override;

    [[nodiscard]] ConsoleSessionObservation readActiveConsole() noexcept override;

    [[nodiscard]] std::optional<std::uint64_t>
    readMonotonicMilliseconds() noexcept override;
};

} // namespace rdp_server::server::security
