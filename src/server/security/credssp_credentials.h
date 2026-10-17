// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace rdp_server::server::security
{

// MS-CSSP TSCredentials / TSPasswordCreds. Parsing deliberately exports
// neither names nor passwords, and never grants a console session.
inline constexpr std::size_t kMaximumDecryptedCredentialsBytes = 8192;
inline constexpr std::size_t kMaximumDelegatedUnixAccountBytes = 32;

enum class CredSspCredentialKind : std::uint8_t
{
    None,
    Password,       // credType=1
    SmartCard,      // credType=2
    RemoteGuard,    // credType=6
};

enum class CredSspCredentialError : std::uint8_t
{
    None,
    InvalidDer,
    UnsupportedType,
    InvalidPasswordFields,
};

struct CredSspCredentialInspection
{
    CredSspCredentialKind kind{CredSspCredentialKind::None};
    CredSspCredentialError error{CredSspCredentialError::None};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == CredSspCredentialError::None &&
               kind != CredSspCredentialKind::None;
    }
};

// Validates a single minimal DER TSCredentials SEQUENCE and validates the
// nested TSPasswordCreds envelope for credType=1, including canonical field
// order plus bounded, well-formed UTF-16LE domain/user/password strings with
// no embedded NUL code units. For types 2 and 6 the encrypted credential
// structure is only classified, NOT interpreted;
// SmartCard/RemoteGuard support is explicitly deferred. No bytes, strings,
// views, pointers or secrets escape into the result.
[[nodiscard]] CredSspCredentialInspection inspectCredSspCredentials(
    std::span<const std::uint8_t> plaintextDer) noexcept;

enum class CredSspDelegatedAccountError : std::uint8_t
{
    None,
    InvalidCredential,
    UnsupportedCredentialType,
    NonEmptyDomain,
    InvalidUnixAccount,
};

// Syntax-only local-account candidate extracted through the same canonical
// TSCredentials/TSPasswordCreds parser used above. This result never proves
// TLS/GSS origin or authorization. Password bytes and borrowed plaintext views
// never leave the parser.
struct CredSspDelegatedAccountInspection
{
    std::array<char, kMaximumDelegatedUnixAccountBytes + 1U> account{};
    std::size_t accountLength{};
    CredSspDelegatedAccountError error{
        CredSspDelegatedAccountError::InvalidCredential};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == CredSspDelegatedAccountError::None &&
               accountLength != 0;
    }

    [[nodiscard]] std::string_view accountName() const noexcept
    {
        return *this
            ? std::string_view(account.data(), accountLength)
            : std::string_view{};
    }
};

[[nodiscard]] CredSspDelegatedAccountInspection
inspectCredSspDelegatedAccount(
    std::span<const std::uint8_t> plaintextDer) noexcept;

// A separate, testable sensitive-buffer ownership primitive.
// The underlying storage remains caller-owned and MUST outlive this guard.
// All bytes are erased using OpenSSL's non-elidable cleanse operation.
class SensitiveBytesGuard final
{
public:
    explicit SensitiveBytesGuard(
        std::span<std::uint8_t> sensitive) noexcept : bytes_(sensitive) {}
    SensitiveBytesGuard(const SensitiveBytesGuard &) = delete;
    SensitiveBytesGuard &operator=(const SensitiveBytesGuard &) = delete;
    SensitiveBytesGuard(SensitiveBytesGuard &&) = delete;
    SensitiveBytesGuard &operator=(SensitiveBytesGuard &&) = delete;
    ~SensitiveBytesGuard();

    void clear() noexcept;

private:
    std::span<std::uint8_t> bytes_{};
};

} // namespace rdp_server::server::security
