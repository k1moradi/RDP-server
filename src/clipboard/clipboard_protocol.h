// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rdp_server::clipboard
{

constexpr std::size_t kMaximumPduBytes = 8U * 1024U * 1024U;
constexpr std::size_t kChannelChunkLength = 1600;

constexpr std::uint16_t kMonitorReady = 1;
constexpr std::uint16_t kFormatList = 2;
constexpr std::uint16_t kFormatListResponse = 3;
constexpr std::uint16_t kFormatDataRequest = 4;
constexpr std::uint16_t kFormatDataResponse = 5;
constexpr std::uint16_t kClipCaps = 7;
constexpr std::uint16_t kFileContentsRequest = 8;
constexpr std::uint16_t kFileContentsResponse = 9;
constexpr std::uint16_t kLockClipdata = 10;
constexpr std::uint16_t kUnlockClipdata = 11;

constexpr std::uint16_t kResponseOk = 0x0001;
constexpr std::uint16_t kResponseFail = 0x0002;
constexpr std::uint32_t kUseLongFormatNames = 0x00000002U;
constexpr std::uint32_t kStreamFileclipEnabled = 0x00000004U;
constexpr std::uint32_t kFileclipNoFilePaths = 0x00000008U;
constexpr std::uint32_t kCanLockClipdata = 0x00000010U;
constexpr std::uint32_t kHugeFileSupportEnabled = 0x00000020U;

constexpr std::uint32_t kFileContentsSize = 0x00000001U;
constexpr std::uint32_t kFileContentsRange = 0x00000002U;

constexpr std::uint16_t kFormatText = 1;
constexpr std::uint16_t kFormatUnicodeText = 13;

struct PduView
{
    std::uint16_t type{};
    std::uint16_t flags{};
    std::span<const std::uint8_t> payload{};
};

enum class PngValidationError : std::uint8_t
{
    None,
    TooShort,
    InvalidSignature,
    InvalidChunkBounds,
    InvalidChunkCrc,
    MissingIhdr,
    InvalidIhdr,
    InvalidChunkOrder,
    UnsupportedCriticalChunk,
    MissingIdat,
    MissingIend,
    TrailingData,
};

struct PngInfo
{
    std::uint32_t width{};
    std::uint32_t height{};
    std::size_t idatChunks{};
};

struct DibInfo
{
    std::uint32_t pixelOffset{};
    std::uint16_t bitCount{};
    std::uint32_t compression{};
};

[[nodiscard]] bool validatePng(std::span<const std::uint8_t> bytes,
                               PngInfo &info,
                               PngValidationError *error = nullptr) noexcept;

// Validate a complete packed DIB without allocating or copying its payload.
// Conversion helpers should reuse this boundary rather than reparsing input.
[[nodiscard]] bool validateDib(std::span<const std::uint8_t> dib) noexcept;

[[nodiscard]] bool wrapDibAsBmp(std::span<const std::uint8_t> dib,
                                std::vector<std::uint8_t> &bmp,
                                DibInfo *info = nullptr) noexcept;

[[nodiscard]] bool decodePdu(std::span<const std::uint8_t> bytes,
                             PduView &pdu) noexcept;

[[nodiscard]] bool encodePdu(std::uint16_t type, std::uint16_t flags,
                             std::span<const std::uint8_t> payload,
                             std::vector<std::uint8_t> &bytes) noexcept;

/**
 * Reassembles the chunks delivered by xrdp's virtual-channel ABI.
 *
 * The protocol's totalLength field is client-controlled, so this object has a
 * fixed upper bound and rejects malformed or out-of-order sequences instead
 * of allocating whatever size the peer requests.
 */
class ChunkReassembler final
{
public:
    [[nodiscard]] bool append(const std::uint8_t *data, std::size_t size,
                              std::size_t totalSize, bool first, bool last,
                              std::vector<std::uint8_t> &complete) noexcept;

    void reset() noexcept;

private:
    std::vector<std::uint8_t> buffer_{};
    std::size_t expectedSize_{0};
};

[[nodiscard]] std::string normalizeText(std::string_view text) noexcept;

[[nodiscard]] std::string decodeUtf16Le(
    std::span<const std::uint8_t> bytes) noexcept;

[[nodiscard]] std::vector<std::uint8_t> encodeUtf16Le(
    std::string_view text) noexcept;

} // namespace rdp_server::clipboard
