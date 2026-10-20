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

// Standalone application-password verification needs the same canonical
// TSCredentials/TSPasswordCreds parser but must not reinterpret its username
// through the Unix-account policy. All three spans borrow the caller-owned
// decrypted buffer and are valid only during the synchronous callback.
using CredSspValidatedPasswordFieldsVisitor = void (*)(
    std::span<const std::uint8_t> domainUtf16Le,
    std::span<const std::uint8_t> userUtf16Le,
    std::span<const std::uint8_t> passwordUtf16Le,
    void *context) noexcept;

[[nodiscard]] CredSspPasswordFieldVisitStatus
visitCredSspValidatedPasswordFields(
    std::span<const std::uint8_t> plaintextDer,
    CredSspValidatedPasswordFieldsVisitor visitor,
    void *context) noexcept;

} // namespace rdp_server::server::security
