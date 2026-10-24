// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "console_os_evidence.h"
#include "macos_native_session_evidence.h"

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

namespace rdp_server::server::security
{

// Concrete macOS console OS evidence source implementing ConsoleOsEvidenceSource
// for CurrentOwnerSharingAuthority. It samples the live caller console session
// using MacNativeSessionEvidenceReader and WindowServer (CGSessionCopyCurrentDictionary).
class MacConsoleOsEvidenceSource final : public ConsoleOsEvidenceSource
{
public:
    MacConsoleOsEvidenceSource() noexcept;
    explicit MacConsoleOsEvidenceSource(
        MacNativeSessionEvidenceSource& nativeEvidence) noexcept;
    ~MacConsoleOsEvidenceSource() override = default;

    MacConsoleOsEvidenceSource(const MacConsoleOsEvidenceSource&) = delete;
    MacConsoleOsEvidenceSource& operator=(const MacConsoleOsEvidenceSource&) = delete;
    MacConsoleOsEvidenceSource(MacConsoleOsEvidenceSource&&) = delete;
    MacConsoleOsEvidenceSource& operator=(MacConsoleOsEvidenceSource&&) = delete;

    [[nodiscard]] ConsoleAccountObservation readUnixAccount(
        std::string_view account) noexcept override;

    [[nodiscard]] ConsoleSessionObservation readActiveConsole() noexcept override;

    [[nodiscard]] std::optional<std::uint64_t>
    readMonotonicMilliseconds() noexcept override;

private:
    MacNativeSessionEvidenceReader defaultNativeEvidence_{};
    MacNativeSessionEvidenceSource* nativeEvidence_{};
    mutable std::array<char, 64> sessionIdBuffer_{};
    mutable std::array<char, 256> accountBuffer_{};
};

} // namespace rdp_server::server::security
