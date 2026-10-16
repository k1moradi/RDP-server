// SPDX-License-Identifier: GPL-3.0-or-later
#include "credssp_credentials.h"

#include <openssl/crypto.h>

namespace rdp_server::server::security
{
namespace
{

struct Reader
{
    std::span<const std::uint8_t> bytes{};
    std::size_t pos{};

    [[nodiscard]] bool read(std::uint8_t tag,
                            std::span<const std::uint8_t> &value) noexcept
    {
        value = {};
        if (pos >= bytes.size() || bytes[pos++] != tag ||
            pos >= bytes.size())
        {
            return false;
        }
        const std::uint8_t first = bytes[pos++];
        std::size_t length = 0;
        if ((first & 0x80U) == 0)
        {
            length = first;
        }
        else
        {
            const std::size_t count = first & 0x7fU;
            if (count == 0 || count > 2 ||
                count > bytes.size() - pos || bytes[pos] == 0)
            {
                return false;
            }
            for (std::size_t index = 0; index < count; ++index)
            {
                length = (length << 8U) | bytes[pos++];
            }
            if ((count == 1 && length < 128) ||
                (count == 2 && length < 256))
            {
                return false;
            }
        }
        if (length > bytes.size() - pos)
        {
            return false;
        }
        value = bytes.subspan(pos, length);
        pos += length;
        return true;
    }

    [[nodiscard]] bool finished() const noexcept
    {
        return pos == bytes.size();
    }
};

[[nodiscard]] bool unwrap(
    std::span<const std::uint8_t> encoded,
    std::uint8_t tag,
    std::span<const std::uint8_t> &value) noexcept
{
    Reader reader{encoded};
    return reader.read(tag, value) && reader.finished();
}

[[nodiscard]] bool readCredentialType(
    std::span<const std::uint8_t> bytes,
    std::uint8_t &type) noexcept
{
    // Canonical DER positive single-byte INTEGER, no high bit or padding.
    if (bytes.size() != 1 || bytes[0] == 0 || bytes[0] >= 128)
    {
        return false;
    }
    type = bytes[0];
    return true;
}

[[nodiscard]] bool validUtf16Le(
    std::span<const std::uint8_t> text,
    bool allowEmpty) noexcept
{
    if (text.size() > 4096 || (text.size() % 2U) != 0U ||
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
            // Embedded NUL would make later native string conversion
            // ambiguous even though the surrounding OCTET STRING is bounded.
            return false;
        }
        if (codeUnit >= 0xd800U && codeUnit <= 0xdbffU)
        {
            if (offset + 3U >= text.size())
            {
                return false;
            }
            const std::uint16_t trailing =
                static_cast<std::uint16_t>(text[offset + 2U]) |
                (static_cast<std::uint16_t>(text[offset + 3U]) << 8U);
            if (trailing < 0xdc00U || trailing > 0xdfffU)
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

[[nodiscard]] bool parsePasswordFields(
    std::span<const std::uint8_t> credentials) noexcept
{
    std::span<const std::uint8_t> fields;
    if (!unwrap(credentials, 0x30, fields))
    {
        return false;
    }
    Reader reader{fields};
    for (std::uint8_t index = 0; index < 3; ++index)
    {
        std::span<const std::uint8_t> wrapped;
        std::span<const std::uint8_t> text;
        if (!reader.read(static_cast<std::uint8_t>(0xa0U + index),
                         wrapped) ||
            !unwrap(wrapped, 0x04, text) ||
            !validUtf16Le(text, index == 0))
        {
            // Unicode domainName may be empty; userName/password are
            // required nonempty. Every nonempty field must be well-formed
            // UTF-16LE without embedded NULs before any native conversion.
            return false;
        }
    }
    return reader.finished();
}

} // namespace

CredSspCredentialInspection inspectCredSspCredentials(
    std::span<const std::uint8_t> plaintextDer) noexcept
{
    if (plaintextDer.empty() ||
        plaintextDer.size() > kMaximumDecryptedCredentialsBytes)
    {
        return {{}, CredSspCredentialError::InvalidDer};
    }
    std::span<const std::uint8_t> sequence;
    if (!unwrap(plaintextDer, 0x30, sequence))
    {
        return {{}, CredSspCredentialError::InvalidDer};
    }
    Reader reader{sequence};
    std::span<const std::uint8_t> typeWrapper;
    std::span<const std::uint8_t> credentialWrapper;
    std::span<const std::uint8_t> integer;
    std::span<const std::uint8_t> bytes;
    if (!reader.read(0xa0, typeWrapper) ||
        !reader.read(0xa1, credentialWrapper) ||
        !reader.finished() ||
        !unwrap(typeWrapper, 0x02, integer) ||
        !unwrap(credentialWrapper, 0x04, bytes) ||
        bytes.empty())
    {
        return {{}, CredSspCredentialError::InvalidDer};
    }
    std::uint8_t type = 0;
    if (!readCredentialType(integer, type))
    {
        return {{}, CredSspCredentialError::InvalidDer};
    }
    switch (type)
    {
        case 1:
            if (!parsePasswordFields(bytes))
            {
                return {{}, CredSspCredentialError::InvalidPasswordFields};
            }
            return {CredSspCredentialKind::Password,
                    CredSspCredentialError::None};
        case 2:
            return {CredSspCredentialKind::SmartCard,
                    CredSspCredentialError::None};
        case 6:
            return {CredSspCredentialKind::RemoteGuard,
                    CredSspCredentialError::None};
        default:
            return {{}, CredSspCredentialError::UnsupportedType};
    }
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
