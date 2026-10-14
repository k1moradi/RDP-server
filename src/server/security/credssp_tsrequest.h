// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace rdp_server::server::security
{

// Strict DER framing only (MS-CSSP 2.2.1). This is NOT a CredSSP
// implementation: no SPNEGO, Kerberos, NTLM, TLS binding, user credentials,
// encryption/decryption or authentication is performed by this parser.
inline constexpr std::size_t kMaximumCredSspRequestBytes = 16 * 1024;
inline constexpr std::size_t kMaximumCredSspTokenBytes = 8192;
inline constexpr std::size_t kMaximumCredSspTokens = 4;

enum class TsRequestError : std::uint8_t
{
    None,
    InvalidDer,
    InvalidVersion,
    InvalidFields,
    InvalidTokens,
    InvalidNonce,
};

struct TsRequestInfo
{
    std::uint32_t version{};
    // Views belong ONLY to the caller's incoming TLS-decrypted byte buffer.
    // Never cache these spans beyond a synchronous parse/SSPI handoff.
    std::array<std::span<const std::uint8_t>, kMaximumCredSspTokens> tokens{};
    std::uint8_t tokenCount{};
    bool hasAuthInfo{};
    bool hasPubKeyAuth{};
    bool hasErrorCode{};
    bool hasClientNonce{};
    // Borrowed opaque DER OCTET STRING contents; valid only as long as
    // the original TLS-decrypted TSRequest byte buffer stays alive.
    // In particular, pubKeyAuth is encrypted GSS data, NOT a plaintext hash.
    std::span<const std::uint8_t> encryptedAuthInfo{};
    std::span<const std::uint8_t> encryptedPubKeyAuth{};
    std::span<const std::uint8_t> clientNonce{};

    // Eligible for a FUTURE SPNEGO implementation to inspect, not proof of
    // identity and never permission to issue an MCS Connect-Response.
    [[nodiscard]] bool initialNegoTokenOnly() const noexcept
    {
        return tokenCount != 0 && !hasAuthInfo && !hasPubKeyAuth &&
               !hasErrorCode && !hasClientNonce;
    }
};

struct TsRequestResult
{
    TsRequestInfo value{};
    TsRequestError error{TsRequestError::None};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == TsRequestError::None;
    }
};

// Exactly one minimal, definite-length ASN.1 DER TSRequest.
// Reject unknown/duplicate/out-of-order fields and nonminimal encodings.
// On failure returns no token views or client-controlled metadata.
[[nodiscard]] TsRequestResult parseCredSspTsRequest(
    std::span<const std::uint8_t> der) noexcept;

// Stream-only DER framing across arbitrarily split TLS plaintext.  This
// decoder does not drive TLS or keep SPNEGO/GSS state and is NOT an
// authentication/session authority. A complete DER view stays borrowed
// only until releaseFrame()/close()/destruction; a future trusted GSS
// provider must synchronously consume it before releasing the frame.
enum class TsRequestFrameStatus : std::uint8_t
{
    NeedMore,
    Complete,
    Invalid,
    Closed,
};

struct TsRequestFrameResult
{
    std::size_t bytesConsumed{};
    TsRequestFrameStatus status{TsRequestFrameStatus::NeedMore};
    TsRequestError error{TsRequestError::None};
};

class TsRequestFrameReader final
{
public:
    TsRequestFrameReader() noexcept = default;
    TsRequestFrameReader(const TsRequestFrameReader &) = delete;
    TsRequestFrameReader &operator=(const TsRequestFrameReader &) = delete;
    ~TsRequestFrameReader() { close(); }

    // Consume at most ONE DER SEQUENCE, preserving trailing/coalesced
    // plaintext for the caller. An untrusted malformed frame is terminal.
    [[nodiscard]] TsRequestFrameResult consume(
        std::span<const std::uint8_t> plaintext) noexcept;
    // Exact next receive target: the uncompleted tag/length header, then
    // the remaining DER content. Zero after Complete/Invalid/Closed.
    [[nodiscard]] std::size_t bytesNeeded() const noexcept;
    [[nodiscard]] std::span<const std::uint8_t> completeDer() const noexcept;
    [[nodiscard]] TsRequestFrameStatus status() const noexcept
    {
        return status_;
    }
    // Only after a synchronous GSS/DER handoff; wipes all buffered bytes.
    // This permits receiving the next CredSSP message but authorizes nothing.
    [[nodiscard]] bool releaseFrame() noexcept;
    void close() noexcept;

private:
    void clear() noexcept;
    [[nodiscard]] TsRequestFrameResult reject(
        std::size_t consumed, TsRequestError error) noexcept;
    std::array<std::uint8_t, kMaximumCredSspRequestBytes> buffer_{};
    std::size_t buffered_{};
    std::size_t expected_{};
    TsRequestFrameStatus status_{TsRequestFrameStatus::NeedMore};
};

} // namespace rdp_server::server::security
