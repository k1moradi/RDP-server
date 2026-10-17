// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "credssp_credentials.h"

#include <cstdint>
#include <span>
#include <string_view>

namespace rdp_server::server::security
{

// Internal-only synchronous access to validated password credential fields.
// The account view borrows a fixed stack copy and passwordUtf16Le borrows the
// caller-owned plaintext. Neither view may be retained after the callback
// returns. This helper is deliberately excluded from the installed SDK.
enum class CredSspPasswordFieldVisitStatus : std::uint8_t
{
    Visited,
    InvalidCredential,
    UnsupportedCredentialType,
    NonEmptyDomain,
    InvalidUnixAccount,
    InvalidVisitor,
};

using CredSspPasswordFieldVisitor = void (*)(
    std::string_view unixAccount,
    std::span<const std::uint8_t> passwordUtf16Le,
    void *context) noexcept;

[[nodiscard]] CredSspPasswordFieldVisitStatus visitCredSspPasswordCredential(
    std::span<const std::uint8_t> plaintextDer,
    CredSspPasswordFieldVisitor visitor,
    void *context) noexcept;

} // namespace rdp_server::server::security
