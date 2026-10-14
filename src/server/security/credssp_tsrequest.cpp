// SPDX-License-Identifier: GPL-3.0-or-later
#include "credssp_tsrequest.h"

namespace rdp_server::server::security
{
namespace
{

struct DerCursor
{
    std::span<const std::uint8_t> bytes{};
    std::size_t offset{};

    [[nodiscard]] bool read(std::uint8_t tag,
                            std::span<const std::uint8_t> &value) noexcept
    {
        value = {};
        if (offset >= bytes.size() || bytes[offset++] != tag ||
            offset >= bytes.size())
        {
            return false;
        }
        const std::uint8_t first = bytes[offset++];
        std::size_t length = 0;
        if ((first & 0x80U) == 0)
        {
            length = first;
        }
        else
        {
            const std::size_t count = first & 0x7fU;
            if (count == 0 || count > 2 || count > bytes.size() - offset ||
                bytes[offset] == 0)
            {
                return false;
            }
            for (std::size_t index = 0; index < count; ++index)
            {
                length = (length << 8U) | bytes[offset++];
            }
            if ((count == 1 && length < 128) ||
                (count == 2 && length < 256))
            {
                return false;
            }
        }
        if (length > bytes.size() - offset)
        {
            return false;
        }
        value = bytes.subspan(offset, length);
        offset += length;
        return true;
    }

    [[nodiscard]] bool empty() const noexcept
    {
        return offset == bytes.size();
    }
};

[[nodiscard]] bool explicitValue(
    std::span<const std::uint8_t> contextValue,
    std::uint8_t expectedTag,
    std::span<const std::uint8_t> &decoded) noexcept
{
    DerCursor field{contextValue};
    return field.read(expectedTag, decoded) && field.empty();
}

[[nodiscard]] bool readUnsignedInteger(
    std::span<const std::uint8_t> bytes,
    std::uint32_t &output) noexcept
{
    // Positive, minimal DER integer; avoid signed rollover and 5-byte
    // leading-zero cases which cannot fit the 32-bit version field.
    if (bytes.empty() || bytes.size() > 5 ||
        (bytes.front() & 0x80U) != 0 ||
        (bytes.size() > 1 && bytes.front() == 0 &&
         (bytes[1] & 0x80U) == 0) ||
        (bytes.size() == 5 && bytes.front() != 0))
    {
        return false;
    }
    std::uint64_t result = 0;
    for (const auto byte : bytes)
    {
        result = (result << 8U) | byte;
    }
    if (result > 0xffffffffULL)
    {
        return false;
    }
    output = static_cast<std::uint32_t>(result);
    return true;
}

// NTSTATUS codes are 32-bit bit patterns, often with the sign bit set.
// Accept their canonical DER signed integer form without treating error
// responses as authenticators or interpreting their semantic meaning.
[[nodiscard]] bool validNtStatusInteger(
    std::span<const std::uint8_t> bytes) noexcept
{
    if (bytes.empty() || bytes.size() > 5 ||
        (bytes.size() == 5 && bytes.front() != 0))
    {
        return false;
    }
    if (bytes.size() > 1 &&
        ((bytes.front() == 0 && (bytes[1] & 0x80U) == 0) ||
         (bytes.front() == 0xff && (bytes[1] & 0x80U) != 0)))
    {
        return false;
    }
    return true;
}

[[nodiscard]] bool parseNegoData(
    std::span<const std::uint8_t> explicitPayload,
    TsRequestInfo &result) noexcept
{
    std::span<const std::uint8_t> sequenceBytes;
    if (!explicitValue(explicitPayload, 0x30, sequenceBytes))
    {
        return false;
    }
    DerCursor sequence{sequenceBytes};
    while (!sequence.empty())
    {
        if (result.tokenCount >= kMaximumCredSspTokens)
        {
            return false;
        }
        std::span<const std::uint8_t> item;
        std::span<const std::uint8_t> wrapper;
        std::span<const std::uint8_t> token;
        if (!sequence.read(0x30, item))
        {
            return false;
        }
        DerCursor itemCursor{item};
        if (!itemCursor.read(0xa0, wrapper) || !itemCursor.empty() ||
            !explicitValue(wrapper, 0x04, token) || token.empty() ||
            token.size() > kMaximumCredSspTokenBytes)
        {
            return false;
        }
        result.tokens[result.tokenCount++] = token;
    }
    return result.tokenCount != 0;
}

[[nodiscard]] TsRequestResult failure(TsRequestError reason) noexcept
{
    return {{}, reason};
}

} // namespace

TsRequestResult parseCredSspTsRequest(
    std::span<const std::uint8_t> der) noexcept
{
    if (der.empty() || der.size() > kMaximumCredSspRequestBytes)
    {
        return failure(TsRequestError::InvalidDer);
    }
    std::span<const std::uint8_t> encodedSequence;
    DerCursor outer{der};
    if (!outer.read(0x30, encodedSequence) || !outer.empty())
    {
        return failure(TsRequestError::InvalidDer);
    }
    DerCursor fields{encodedSequence};
    TsRequestInfo info{};
    std::uint8_t previousTag = 0x9fU;
    while (!fields.empty())
    {
        const auto next = fields.bytes[fields.offset];
        if (next < 0xa0U || next > 0xa5U ||
            (previousTag != 0x9fU && next <= previousTag) ||
            (previousTag == 0x9fU && next != 0xa0U))
        {
            return failure(TsRequestError::InvalidFields);
        }
        previousTag = next;
        std::span<const std::uint8_t> content;
        if (!fields.read(next, content))
        {
            return failure(TsRequestError::InvalidDer);
        }
        std::span<const std::uint8_t> payload;
        switch (next)
        {
            case 0xa0: // [0] EXPLICIT INTEGER version
                if (!explicitValue(content, 0x02, payload) ||
                    !readUnsignedInteger(payload, info.version) ||
                    info.version < 2 || info.version > 6)
                {
                    // Unknown versions fail until the selected security
                    // mechanism explicitly supports their semantics.
                    return failure(TsRequestError::InvalidVersion);
                }
                break;
            case 0xa1: // [1] EXPLICIT NegoData
                if (!parseNegoData(content, info))
                {
                    return failure(TsRequestError::InvalidTokens);
                }
                break;
            case 0xa2: // [2] encrypted and signed authInfo, opaque
            case 0xa3: // [3] encrypted public key binding, opaque
                if (!explicitValue(content, 0x04, payload) || payload.empty())
                {
                    return failure(TsRequestError::InvalidFields);
                }
                if (next == 0xa2)
                {
                    info.hasAuthInfo = true;
                    info.encryptedAuthInfo = payload;
                }
                else
                {
                    info.hasPubKeyAuth = true;
                    info.encryptedPubKeyAuth = payload;
                }
                break;
            case 0xa4: // [4] NTSTATUS errorCode
            {
                if (!explicitValue(content, 0x02, payload) ||
                    !validNtStatusInteger(payload))
                {
                    return failure(TsRequestError::InvalidFields);
                }
                // Never interpret it as authentication or log secrets.
                info.hasErrorCode = true;
                break;
            }
            case 0xa5: // [5] clientNonce for TLS binding, version >= 5
                if (!explicitValue(content, 0x04, payload) ||
                    payload.size() != 32 || info.version < 5)
                {
                    return failure(TsRequestError::InvalidNonce);
                }
                info.hasClientNonce = true;
                info.clientNonce = payload;
                break;
            default:
                return failure(TsRequestError::InvalidFields);
        }
    }
    if (previousTag == 0x9fU)
    {
        return failure(TsRequestError::InvalidFields);
    }
    return {info, TsRequestError::None};
}

} // namespace rdp_server::server::security
