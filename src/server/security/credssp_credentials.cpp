// SPDX-License-Identifier: GPL-3.0-or-later
#include "credssp_credentials.h"
#include "credssp_credentials_internal.h"

#include <openssl/crypto.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace rdp_server::server::security
{
namespace
{

class Reader final
{
public:
    explicit Reader(std::span<const std::uint8_t> bytes) noexcept
        : bytes_(bytes) {}

    [[nodiscard]] bool read(
        std::uint8_t expectedTag,
        std::span<const std::uint8_t> &value) noexcept
    {
        if (position_ >= bytes_.size() ||
            bytes_[position_++] != expectedTag ||
            position_ >= bytes_.size())
        {
            return false;
        }
        const std::uint8_t first = bytes_[position_++];
        std::size_t length = 0;
        if ((first & 0x80U) == 0)
        {
            length = first;
        }
        else
        {
            const std::size_t count = first & 0x7fU;
            if (count == 0 || count > 2 ||
                count > bytes_.size() - position_ ||
                bytes_[position_] == 0)
            {
                return false;
            }
            for (std::size_t index = 0; index < count; ++index)
            {
                length = (length << 8U) | bytes_[position_++];
            }
            if ((count == 1 && length < 128) ||
                (count == 2 && length < 256))
            {
                return false;
            }
        }
        if (length > bytes_.size() - position_)
        {
            return false;
        }
        value = bytes_.subspan(position_, length);
        position_ += length;
        return true;
    }

    [[nodiscard]] bool empty() const noexcept
    {
        return position_ == bytes_.size();
    }

private:
    std::span<const std::uint8_t> bytes_{};
    std::size_t position_{};
};

[[nodiscard]] bool unwrap(
    std::span<const std::uint8_t> encoded,
    std::uint8_t tag,
    std::span<const std::uint8_t> &value) noexcept
{
    Reader reader(encoded);
    return reader.read(tag, value) && reader.empty();
}

[[nodiscard]] bool readCredentialType(
    std::span<const std::uint8_t> explicitValue,
    std::uint8_t &type) noexcept
{
    std::span<const std::uint8_t> integer;
    if (!unwrap(explicitValue, 0x02, integer) ||
        integer.size() != 1 || integer[0] == 0 ||
        (integer[0] & 0x80U) != 0)
    {
        return false;
    }
    type = integer[0];
    return true;
}

[[nodiscard]] bool validUtf16Le(
    std::span<const std::uint8_t> text,
    bool allowEmpty) noexcept
{
    if (text.size() > 4096 || (text.size() % 2U) != 0 ||
        (!allowEmpty && text.empty()))
    {
        return false;
    }

    for (std::size_t offset = 0; offset < text.size(); offset += 2U)
    {
        const std::uint16_t codeUnit =
            static_cast<std::uint16_t>(text[offset]) |
            (static_cast<std::uint16_t>(text[offset + 1U]) << 8U);
        if (codeUnit == 0)
        {
            return false;
        }
        if (codeUnit >= 0xd800U && codeUnit <= 0xdbffU)
        {
            if (offset + 3U >= text.size())
            {
                return false;
            }
            const std::uint16_t low =
                static_cast<std::uint16_t>(text[offset + 2U]) |
                (static_cast<std::uint16_t>(text[offset + 3U]) << 8U);
            if (low < 0xdc00U || low > 0xdfffU)
            {
                return false;
            }
            offset += 2U;
        }
        else if (codeUnit >= 0xdc00U && codeUnit <= 0xdfffU)
        {
            return false;
        }
    }
    return true;
}

struct CredentialEnvelope
{
    std::uint8_t type{};
    std::span<const std::uint8_t> credentials{};
};

[[nodiscard]] bool parseCredentialEnvelope(
    std::span<const std::uint8_t> plaintext,
    CredentialEnvelope &output) noexcept
{
    if (plaintext.empty() ||
        plaintext.size() > kMaximumDecryptedCredentialsBytes)
    {
        return false;
    }

    std::span<const std::uint8_t> sequence;
    if (!unwrap(plaintext, 0x30, sequence))
    {
        return false;
    }

    Reader outer(sequence);
    std::span<const std::uint8_t> typeValue;
    std::span<const std::uint8_t> credentialValue;
    if (!outer.read(0xa0, typeValue) ||
        !outer.read(0xa1, credentialValue) || !outer.empty() ||
        !readCredentialType(typeValue, output.type) ||
        !unwrap(credentialValue, 0x04, output.credentials) ||
        output.credentials.empty())
    {
        return false;
    }
    return true;
}

struct PasswordCredentialFields
{
    std::span<const std::uint8_t> domain{};
    std::span<const std::uint8_t> user{};
    std::span<const std::uint8_t> password{};
};

[[nodiscard]] bool parsePasswordFields(
    std::span<const std::uint8_t> credentials,
    PasswordCredentialFields &output) noexcept
{
    std::span<const std::uint8_t> passwordSequence;
    if (!unwrap(credentials, 0x30, passwordSequence))
    {
        return false;
    }

    Reader fields(passwordSequence);
    std::span<const std::uint8_t> domainExplicit;
    std::span<const std::uint8_t> userExplicit;
    std::span<const std::uint8_t> passwordExplicit;
    if (!fields.read(0xa0, domainExplicit) ||
        !fields.read(0xa1, userExplicit) ||
        !fields.read(0xa2, passwordExplicit) ||
        !fields.empty() ||
        !unwrap(domainExplicit, 0x04, output.domain) ||
        !unwrap(userExplicit, 0x04, output.user) ||
        !unwrap(passwordExplicit, 0x04, output.password))
    {
        return false;
    }

    // MS-CSSP defines these as OCTET STRING fields and Windows encodes text
    // from UNICODE_STRING values. Empty user/password strings are therefore
    // syntactically representable; authentication policy, not DER parsing,
    // decides whether they can match an actual credential.
    return validUtf16Le(output.domain, true) &&
           validUtf16Le(output.user, true) &&
           validUtf16Le(output.password, true);
}

[[nodiscard]] constexpr bool asciiLower(char value) noexcept
{
    return value >= 'a' && value <= 'z';
}

[[nodiscard]] constexpr bool asciiDigit(char value) noexcept
{
    return value >= '0' && value <= '9';
}

[[nodiscard]] bool copyUnixAccount(
    std::span<const std::uint8_t> userUtf16Le,
    CredSspDelegatedAccountInspection &output) noexcept
{
    const std::size_t characterCount = userUtf16Le.size() / 2U;
    if (characterCount == 0 ||
        characterCount > kMaximumDelegatedUnixAccountBytes)
    {
        return false;
    }

    for (std::size_t index = 0; index < characterCount; ++index)
    {
        const std::size_t offset = index * 2U;
        if (userUtf16Le[offset + 1U] != 0)
        {
            return false;
        }
        const char character = static_cast<char>(userUtf16Le[offset]);
        if ((index == 0 && !asciiLower(character) &&
             character != '_') ||
            (!asciiLower(character) && !asciiDigit(character) &&
             character != '_' && character != '-'))
        {
            return false;
        }
        output.account[index] = character;
    }

    output.accountLength = characterCount;
    output.account[characterCount] = '\0';
    if (std::string_view(
            output.account.data(), output.accountLength) == "root")
    {
        output.account.fill('\0');
        output.accountLength = 0;
        return false;
    }
    return true;
}

} // namespace

CredSspCredentialInspection inspectCredSspCredentials(
    std::span<const std::uint8_t> plaintext) noexcept
{
    CredentialEnvelope envelope;
    if (!parseCredentialEnvelope(plaintext, envelope))
    {
        return {CredSspCredentialKind::None,
                CredSspCredentialError::InvalidDer};
    }

    switch (envelope.type)
    {
    case 1:
    {
        PasswordCredentialFields fields;
        if (!parsePasswordFields(envelope.credentials, fields))
        {
            return {CredSspCredentialKind::None,
                    CredSspCredentialError::InvalidPasswordFields};
        }
        return {CredSspCredentialKind::Password,
                CredSspCredentialError::None};
    }
    case 2:
        return {CredSspCredentialKind::SmartCard,
                CredSspCredentialError::None};
    case 6:
        return {CredSspCredentialKind::RemoteGuard,
                CredSspCredentialError::None};
    default:
        return {CredSspCredentialKind::None,
                CredSspCredentialError::UnsupportedType};
    }
}

CredSspDelegatedAccountInspection inspectCredSspDelegatedAccount(
    std::span<const std::uint8_t> plaintext) noexcept
{
    CredSspDelegatedAccountInspection result;
    CredentialEnvelope envelope;
    if (!parseCredentialEnvelope(plaintext, envelope))
    {
        return result;
    }
    if (envelope.type != 1)
    {
        result.error =
            CredSspDelegatedAccountError::UnsupportedCredentialType;
        return result;
    }

    PasswordCredentialFields fields;
    if (!parsePasswordFields(envelope.credentials, fields))
    {
        return result;
    }
    if (!fields.domain.empty())
    {
        result.error = CredSspDelegatedAccountError::NonEmptyDomain;
        return result;
    }
    if (!copyUnixAccount(fields.user, result))
    {
        // A rejected account is not a candidate. copyUnixAccount() may have
        // examined and copied a valid prefix before finding a bad code unit;
        // retire that partial identity before returning a failure result.
        result.account.fill('\0');
        result.accountLength = 0;
        result.error = CredSspDelegatedAccountError::InvalidUnixAccount;
        return result;
    }

    result.error = CredSspDelegatedAccountError::None;
    return result;
}

CredSspPasswordFieldVisitStatus visitCredSspValidatedPasswordFields(
    std::span<const std::uint8_t> plaintext,
    CredSspValidatedPasswordFieldsVisitor visitor,
    void *context) noexcept
{
    if (visitor == nullptr)
        return CredSspPasswordFieldVisitStatus::InvalidVisitor;

    CredentialEnvelope envelope;
    if (!parseCredentialEnvelope(plaintext, envelope))
        return CredSspPasswordFieldVisitStatus::InvalidCredential;
    if (envelope.type != 1)
        return CredSspPasswordFieldVisitStatus::UnsupportedCredentialType;

    PasswordCredentialFields fields;
    if (!parsePasswordFields(envelope.credentials, fields))
        return CredSspPasswordFieldVisitStatus::InvalidCredential;

    visitor(fields.domain, fields.user, fields.password, context);
    return CredSspPasswordFieldVisitStatus::Visited;
}

CredSspPasswordFieldVisitStatus visitCredSspPasswordCredential(
    std::span<const std::uint8_t> plaintext,
    CredSspPasswordFieldVisitor visitor,
    void *context) noexcept
{
    if (visitor == nullptr)
    {
        return CredSspPasswordFieldVisitStatus::InvalidVisitor;
    }

    CredentialEnvelope envelope;
    if (!parseCredentialEnvelope(plaintext, envelope))
    {
        return CredSspPasswordFieldVisitStatus::InvalidCredential;
    }
    if (envelope.type != 1)
    {
        return CredSspPasswordFieldVisitStatus::UnsupportedCredentialType;
    }

    PasswordCredentialFields fields;
    if (!parsePasswordFields(envelope.credentials, fields))
    {
        return CredSspPasswordFieldVisitStatus::InvalidCredential;
    }
    if (!fields.domain.empty())
    {
        return CredSspPasswordFieldVisitStatus::NonEmptyDomain;
    }

    CredSspDelegatedAccountInspection account;
    if (!copyUnixAccount(fields.user, account))
    {
        OPENSSL_cleanse(account.account.data(), account.account.size());
        account.accountLength = 0;
        return CredSspPasswordFieldVisitStatus::InvalidUnixAccount;
    }

    visitor(std::string_view(account.account.data(), account.accountLength),
            fields.password, context);
    OPENSSL_cleanse(account.account.data(), account.account.size());
    account.accountLength = 0;
    return CredSspPasswordFieldVisitStatus::Visited;
}

SensitiveBytesGuard::~SensitiveBytesGuard()
{
    clear();
}

void SensitiveBytesGuard::clear() noexcept
{
    if (!bytes_.empty())
    {
        OPENSSL_cleanse(bytes_.data(), bytes_.size());
        bytes_ = {};
    }
}

} // namespace rdp_server::server::security
