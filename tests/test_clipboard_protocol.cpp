// SPDX-License-Identifier: GPL-3.0-or-later

#include "clipboard/clipboard_protocol.h"

// The canonical build uses Release/NDEBUG. Keep test predicates (including
// side-effecting encode/decode calls) active in every build configuration.
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string>
#include <span>
#include <string_view>
#include <vector>

namespace
{

void test_pdu_round_trip()
{
    using namespace rdp_server::clipboard;
    const std::vector<std::uint8_t> payload{1, 2, 3, 4};
    std::vector<std::uint8_t> encoded;
    assert(encodePdu(kFormatList, kUseLongFormatNames, payload, encoded));
    PduView pdu;
    assert(decodePdu(encoded, pdu));
    assert(pdu.type == kFormatList);
    assert(pdu.flags == kUseLongFormatNames);
    assert(std::vector<std::uint8_t>(pdu.payload.begin(), pdu.payload.end()) ==
           payload);
    encoded.push_back(0);
    assert(!decodePdu(encoded, pdu));
}

void test_chunk_reassembly()
{
    using namespace rdp_server::clipboard;
    std::vector<std::uint8_t> source(4096);
    for (std::size_t index = 0; index < source.size(); ++index)
    {
        source[index] = static_cast<std::uint8_t>(index & 0xffU);
    }
    ChunkReassembler reassembler;
    std::vector<std::uint8_t> complete;
    assert(reassembler.append(source.data(), 1600, source.size(), true, false,
                              complete));
    assert(complete.empty());
    assert(reassembler.append(source.data() + 1600, 1600, source.size(), false,
                              false, complete));
    assert(reassembler.append(source.data() + 3200, 896, source.size(), false,
                              true, complete));
    assert(complete == source);
    assert(!reassembler.append(source.data(), 1, source.size(), false, true,
                               complete));
    assert(!reassembler.append(source.data(), 1, kMaximumPduBytes + 1, true,
                               true, complete));
}

void test_unicode_and_line_endings()
{
    using namespace rdp_server::clipboard;
    const std::string original = "one\r\ntwo \xF0\x9F\x8C\x8D";
    const std::vector<std::uint8_t> encoded = encodeUtf16Le(original);
    assert(!encoded.empty());
    assert(decodeUtf16Le(encoded) == "one\ntwo \xF0\x9F\x8C\x8D");
    assert(normalizeText("a\rb\r\nc\0ignored") == "a\nb\nc");
}

void test_png_validation()
{
    using namespace rdp_server::clipboard;
    const std::vector<std::uint8_t> png{
        0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a,
        0x00,0x00,0x00,0x0d,0x49,0x48,0x44,0x52,
        0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,
        0x08,0x06,0x00,0x00,0x00,0x1f,0x15,0xc4,0x89,
        0x00,0x00,0x00,0x0d,0x49,0x44,0x41,0x54,
        0x78,0x9c,0x63,0xf8,0xcf,0xc0,0xf0,0x1f,0x00,
        0x05,0x00,0x01,0xff,0x89,0x99,0x3d,0x1d,
        0x00,0x00,0x00,0x00,0x49,0x45,0x4e,0x44,
        0xae,0x42,0x60,0x82};
    PngInfo info;
    PngValidationError error = PngValidationError::TooShort;
    assert(validatePng(png, info, &error));
    assert(error == PngValidationError::None);
    assert(info.width == 1 && info.height == 1 && info.idatChunks == 1);

    auto corrupt = png;
    corrupt[48] ^= 0x01U;
    assert(!validatePng(corrupt, info, &error));
    assert(error == PngValidationError::InvalidChunkCrc);

    auto trailing = png;
    trailing.push_back(0);
    assert(!validatePng(trailing, info, &error));
    assert(error == PngValidationError::TrailingData);
}

void test_png_palette_rules()
{
    using namespace rdp_server::clipboard;

    // Fully decodable 1x1 indexed-color PNG: filter=0, palette index=0,
    // stored DEFLATE block, and correct PNG and Adler-32 checksums.
    const std::vector<std::uint8_t> indexed{
        0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a,
        0x00,0x00,0x00,0x0d,0x49,0x48,0x44,0x52,
        0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,
        0x01,0x03,0x00,0x00,0x00,0x25,0xdb,0x56,0xca,
        0x00,0x00,0x00,0x03,0x50,0x4c,0x54,0x45,
        0x00,0x00,0x00,0xa7,0x7a,0x3d,0xda,
        0x00,0x00,0x00,0x0d,0x49,0x44,0x41,0x54,
        0x78,0x01,0x01,0x02,0x00,0xfd,0xff,
        0x00,0x00,0x00,0x02,0x00,0x01,
        0x7e,0x05,0x0d,0xd2,
        0x00,0x00,0x00,0x00,0x49,0x45,0x4e,0x44,
        0xae,0x42,0x60,0x82
    };
    PngInfo info;
    PngValidationError error;
    assert(validatePng(indexed, info, &error));
    assert(info.width == 1 && info.height == 1);

    auto noPalette = indexed;
    noPalette.erase(noPalette.begin() + 33, noPalette.begin() + 48);
    assert(!validatePng(noPalette, info, &error));
    assert(error == PngValidationError::InvalidChunkOrder);

    auto duplicatePalette = indexed;
    duplicatePalette.insert(duplicatePalette.begin() + 48,
                            indexed.begin() + 33, indexed.begin() + 48);
    assert(!validatePng(duplicatePalette, info, &error));
    assert(error == PngValidationError::InvalidChunkOrder);

    // Move PLTE after the IDAT chunk, preserving both chunks' CRCs.
    auto latePalette = noPalette;
    latePalette.insert(latePalette.begin() + 58,
                       indexed.begin() + 33, indexed.begin() + 48);
    assert(!validatePng(latePalette, info, &error));

    // Three palette entries do not fit 1-bit palette indices (maximum 2).
    const std::vector<std::uint8_t> threeColorPalette{
        0x00,0x00,0x00,0x09,0x50,0x4c,0x54,0x45,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x83,0x63,0xe9,0xc0
    };
    auto overlargePalette = noPalette;
    overlargePalette.insert(overlargePalette.begin() + 33,
                            threeColorPalette.begin(), threeColorPalette.end());
    assert(!validatePng(overlargePalette, info, &error));
    assert(error == PngValidationError::InvalidChunkOrder);

    // A grayscale IHDR with a corrected CRC must not carry PLTE.
    auto grayscaleWithPalette = indexed;
    grayscaleWithPalette[25] = 0x00;
    grayscaleWithPalette[29] = 0x37;
    grayscaleWithPalette[30] = 0x6e;
    grayscaleWithPalette[31] = 0xf9;
    grayscaleWithPalette[32] = 0x24;
    assert(!validatePng(grayscaleWithPalette, info, &error));
    assert(error == PngValidationError::InvalidChunkOrder);
}

void test_dib_wrapping()
{
    using namespace rdp_server::clipboard;
    std::vector<std::uint8_t> dib(44, 0);
    dib[0] = 40;
    dib[4] = 1;
    dib[8] = 1;
    dib[12] = 1;
    dib[14] = 24;
    dib[20] = 4;
    dib[40] = 0x11;
    dib[41] = 0x22;
    dib[42] = 0x33;

    std::vector<std::uint8_t> bmp;
    DibInfo info;
    assert(wrapDibAsBmp(dib, bmp, &info));
    assert(bmp.size() == 58);
    assert(bmp[0] == 'B' && bmp[1] == 'M');
    assert(info.pixelOffset == 54);
    assert(info.bitCount == 24);
    assert(info.compression == 0);
    assert(bmp[54] == 0x11 && bmp[55] == 0x22 && bmp[56] == 0x33);

    dib[14] = 3;
    assert(!wrapDibAsBmp(dib, bmp));
    assert(bmp.empty());
}

void test_dib_pixel_payload_validation()
{
    using namespace rdp_server::clipboard;
    const auto put16 = [](std::vector<std::uint8_t> &bytes,
                          std::size_t offset, std::uint16_t value) {
        bytes[offset] = static_cast<std::uint8_t>(value);
        bytes[offset + 1] = static_cast<std::uint8_t>(value >> 8U);
    };
    const auto put32 = [](std::vector<std::uint8_t> &bytes,
                          std::size_t offset, std::uint32_t value) {
        for (unsigned shift = 0; shift < 32; shift += 8)
        {
            bytes[offset + shift / 8] =
                static_cast<std::uint8_t>(value >> shift);
        }
    };
    const auto make = [&](std::uint32_t width, std::uint32_t height,
                          std::uint16_t bpp, std::uint32_t compression,
                          std::size_t bytesAfterHeader) {
        std::vector<std::uint8_t> dib(40U + bytesAfterHeader);
        put32(dib, 0, 40);
        put32(dib, 4, width);
        put32(dib, 8, height);
        put16(dib, 12, 1);
        put16(dib, 14, bpp);
        put32(dib, 16, compression);
        return dib;
    };

    std::vector<std::uint8_t> bmp;
    DibInfo info;

    // A 3-pixel 24-bpp row requires twelve bytes, not nine.
    auto rgb = make(3, 1, 24, 0, 12);
    assert(wrapDibAsBmp(rgb, bmp, &info));
    assert(info.pixelOffset == 54);
    rgb.pop_back();
    assert(!wrapDibAsBmp(rgb, bmp));
    assert(bmp.empty());

    // The 4-byte-aligned row rule is applied once per scanline.
    auto twoRows = make(1, 2, 24, 0, 8);
    assert(wrapDibAsBmp(twoRows, bmp));
    twoRows.pop_back();
    assert(!wrapDibAsBmp(twoRows, bmp));

    auto invalid = make(1, 1, 24, 0, 4);
    put32(invalid, 4, 0); // Zero width
    assert(!wrapDibAsBmp(invalid, bmp));
    put32(invalid, 4, 1);
    put32(invalid, 8, 0); // Zero height
    assert(!wrapDibAsBmp(invalid, bmp));
    put32(invalid, 8, 1);
    put16(invalid, 12, 0); // biPlanes must equal one
    assert(!wrapDibAsBmp(invalid, bmp));
    put16(invalid, 12, 1);
    put32(invalid, 20, 100); // Declared image size exceeds payload
    assert(!wrapDibAsBmp(invalid, bmp));

    // Negative height is legal for uncompressed top-down bitmaps.
    auto topDown = make(2, 0xfffffffeU, 32, 0, 16);
    assert(wrapDibAsBmp(topDown, bmp, &info));
    assert(info.pixelOffset == 54);
    topDown.resize(55);
    assert(!wrapDibAsBmp(topDown, bmp));

    // The same negative height is invalid for compressed RLE8.
    auto rle = make(1, 0xffffffffU, 8, 1, 12);
    put32(rle, 32, 2); // Only two entries in the palette
    put32(rle, 20, 4);
    assert(!wrapDibAsBmp(rle, bmp));
    put32(rle, 8, 1);
    assert(wrapDibAsBmp(rle, bmp, &info));
    assert(info.pixelOffset == 62);
    put32(rle, 20, 5); // Only four RLE bytes remain
    assert(!wrapDibAsBmp(rle, bmp));

    // BI_BITFIELDS includes three masks after a 40-byte header.
    auto masked = make(1, 1, 16, 3, 16);
    assert(wrapDibAsBmp(masked, bmp, &info));
    assert(info.pixelOffset == 66);
    masked.pop_back();
    assert(!wrapDibAsBmp(masked, bmp));

    // Embedded BI_PNG can legitimately use biBitCount=0 with no palette.
    auto embeddedPng = make(1, 1, 0, 5, 8);
    put32(embeddedPng, 20, 8);
    assert(wrapDibAsBmp(embeddedPng, bmp, &info));
    assert(info.pixelOffset == 54);
    // Even a peer which fills in the decoded bit depth must not force a
    // bitmap palette into the embedded PNG payload.
    put16(embeddedPng, 14, 8);
    assert(wrapDibAsBmp(embeddedPng, bmp, &info));
    assert(info.pixelOffset == 54);
    embeddedPng.resize(47);
    assert(!wrapDibAsBmp(embeddedPng, bmp));
}


// Different TCP/virtual-channel fragment boundaries must reassemble the same
// wire bytes, and the completed buffer must remain owned by the caller after
// the coordinator is reset or reused. Malformed fragments must not carry
// partial bytes into the next message.
void test_chunk_reassembly_reset_and_bounds()
{
    using namespace rdp_server::clipboard;
    std::array<std::uint8_t, 257> wireBytes{};
    for (std::size_t byteIndex = 0; byteIndex < wireBytes.size(); ++byteIndex)
    {
        wireBytes[byteIndex] = static_cast<std::uint8_t>(byteIndex);
    }
    const std::vector<std::uint8_t> expected(
        wireBytes.begin(), wireBytes.end());
    std::vector<std::uint8_t> complete;

    for (std::size_t firstChunkSize = 1;
         firstChunkSize < wireBytes.size(); ++firstChunkSize)
    {
        ChunkReassembler reassembler;
        complete.assign(1, 0xff);
        assert(reassembler.append(wireBytes.data(), firstChunkSize,
                                  wireBytes.size(), true, false, complete));
        assert(complete.empty());
        assert(reassembler.append(wireBytes.data() + firstChunkSize,
                                  wireBytes.size() - firstChunkSize,
                                  wireBytes.size(), false, true, complete));
        assert(complete == expected);
        reassembler.reset();
        assert(complete == expected); // The caller owns the moved result.
        assert(reassembler.append(wireBytes.data(), wireBytes.size(),
                                  wireBytes.size(), true, true, complete));
        assert(complete == expected);
    }

    ChunkReassembler reassembler;
    const auto checkCleanRecovery = [&]() {
        assert(reassembler.append(wireBytes.data(), wireBytes.size(),
                                  wireBytes.size(), true, true, complete));
        assert(complete == expected);
    };

    // Never accept an unannounced continuation, even if it ends a packet.
    complete.assign(3, 0xee);
    assert(!reassembler.append(wireBytes.data(), 1, wireBytes.size(),
                               false, true, complete));
    assert(complete.empty());
    checkCleanRecovery();

    // An early LAST, changed declared length, overrun or duplicate FIRST
    // invalidates the partial transfer. A later clean FIRST may recover.
    assert(reassembler.append(wireBytes.data(), 1, wireBytes.size(),
                              true, false, complete));
    assert(!reassembler.append(wireBytes.data() + 1, 1,
                               wireBytes.size(), false, true, complete));
    assert(complete.empty());
    checkCleanRecovery();

    assert(reassembler.append(wireBytes.data(), 1, wireBytes.size(),
                              true, false, complete));
    assert(!reassembler.append(wireBytes.data() + 1, 1,
                               wireBytes.size() - 1, false, false, complete));
    assert(complete.empty());
    checkCleanRecovery();

    assert(reassembler.append(wireBytes.data(), 1, wireBytes.size(),
                              true, false, complete));
    assert(!reassembler.append(wireBytes.data(), wireBytes.size(),
                               wireBytes.size(), false, true, complete));
    assert(complete.empty());
    checkCleanRecovery();

    assert(reassembler.append(wireBytes.data(), 1, wireBytes.size(),
                              true, false, complete));
    assert(!reassembler.append(wireBytes.data(), 1, wireBytes.size(),
                               true, false, complete));
    assert(complete.empty());
    checkCleanRecovery();

    // Upper limits and invalid pointers reject before reserving or reading
    // peer-controlled memory. A rejection does not preserve partial output.
    assert(!reassembler.append(wireBytes.data(), 1, kMaximumPduBytes + 1,
                               true, true, complete));
    assert(complete.empty());
    assert(!reassembler.append(nullptr, 1, wireBytes.size(),
                               true, true, complete));
    assert(complete.empty());
    assert(!reassembler.append(wireBytes.data(), 1, 0,
                               true, true, complete));
    assert(complete.empty());
    checkCleanRecovery();

    // Single-byte fragments, including a final one-byte chunk, stay bounded.
    for (std::size_t byteIndex = 0; byteIndex < wireBytes.size(); ++byteIndex)
    {
        assert(reassembler.append(wireBytes.data() + byteIndex, 1,
                                  wireBytes.size(), byteIndex == 0,
                                  byteIndex + 1 == wireBytes.size(), complete));
        if (byteIndex + 1 != wireBytes.size())
        {
            assert(complete.empty());
        }
    }
    assert(complete == expected);
}


void test_wire_codec_mutated_boundaries()
{
    using namespace rdp_server::clipboard;

    // The codec transports opaque type/flag bits. Ownership, exact framing
    // and the payload view must remain correct for every byte boundary.
    constexpr std::array<std::size_t, 10> lengths{
        0, 1, 2, 3, 7, 8, 31, 255, 1600, 4096};
    constexpr std::array<std::uint16_t, 4> values{
        0, 0x0001U, 0x7fffU, 0xffffU};
    for (const std::size_t length : lengths)
    {
        std::vector<std::uint8_t> payload(length);
        for (std::size_t index = 0; index < length; ++index)
        {
            payload[index] = static_cast<std::uint8_t>(
                (index * 29U + (index >> 2U) + 0x53U) & 0xffU);
        }
        for (const std::uint16_t value : values)
        {
            std::vector<std::uint8_t> encoded{0xee};
            assert(encodePdu(value, static_cast<std::uint16_t>(~value),
                             payload, encoded));
            assert(encoded.size() == length + 8U);
            PduView view;
            assert(decodePdu(encoded, view));
            assert(view.type == value);
            assert(view.flags == static_cast<std::uint16_t>(~value));
            assert(view.payload.size() == payload.size());
            assert(view.payload.data() == encoded.data() + 8U);
            assert(std::equal(view.payload.begin(), view.payload.end(),
                              payload.begin(), payload.end()));

            // Every strict prefix, including the 0..7-byte header prefixes,
            // and an otherwise valid packet with one extra byte fail closed.
            for (std::size_t prefix = 0; prefix < encoded.size(); ++prefix)
            {
                const std::span<const std::uint8_t> truncated{
                    encoded.data(), prefix};
                assert(!decodePdu(truncated, view));
            }
            auto trailing = encoded;
            trailing.push_back(0x7fU);
            assert(!decodePdu(trailing, view));
        }
    }

    // Mutate every bit in a frame, including all length-field bits.
    // The lower-level codec intentionally accepts unknown message types
    // and flags; only the exact little-endian declared length is structural.
    std::vector<std::uint8_t> payload(31);
    for (std::size_t index = 0; index < payload.size(); ++index)
        payload[index] = static_cast<std::uint8_t>(index * 13U);
    std::vector<std::uint8_t> frame;
    assert(encodePdu(kFormatList, kUseLongFormatNames, payload, frame));
    const auto read16 = [](const std::uint8_t *bytes) {
        return static_cast<std::uint16_t>(
            static_cast<std::uint16_t>(bytes[0]) |
            static_cast<std::uint16_t>(bytes[1]) << 8U);
    };
    const auto read32 = [](const std::uint8_t *bytes) {
        return static_cast<std::uint32_t>(bytes[0]) |
               static_cast<std::uint32_t>(bytes[1]) << 8U |
               static_cast<std::uint32_t>(bytes[2]) << 16U |
               static_cast<std::uint32_t>(bytes[3]) << 24U;
    };
    for (std::size_t offset = 0; offset < frame.size(); ++offset)
    {
        for (unsigned bit = 0; bit < 8U; ++bit)
        {
            auto mutated = frame;
            mutated[offset] ^= static_cast<std::uint8_t>(1U << bit);
            const auto beforeDecode = mutated;
            const bool structurallyValid =
                read32(mutated.data() + 4U) == mutated.size() - 8U;
            PduView view;
            assert(decodePdu(mutated, view) == structurallyValid);
            if (structurallyValid)
            {
                assert(view.type == read16(mutated.data()));
                assert(view.flags == read16(mutated.data() + 2U));
                assert(view.payload.data() == mutated.data() + 8U);
                assert(view.payload.size() == mutated.size() - 8U);
                assert(std::equal(view.payload.begin(), view.payload.end(),
                                  mutated.begin() + 8U, mutated.end()));
            }
            assert(mutated == beforeDecode); // Read-only parser contract.
        }
    }

    // The declared length is an untrusted uint32_t, not a reason to
    // allocate or read that many bytes from a short peer message.
    std::array<std::uint8_t, 8> hugeLength{
        0x02U, 0x00U, 0x02U, 0x00U, 0xffU, 0xffU, 0xffU, 0xffU};
    PduView ignored;
    assert(!decodePdu(hugeLength, ignored));
}

} // namespace

int main(int argumentCount, char **arguments)
{
    if (argumentCount == 2 &&
        std::string_view(arguments[1]) == "wire-codec-mutated-boundaries")
    {
        test_wire_codec_mutated_boundaries();
        return 0;
    }
    if (argumentCount == 2 &&
        std::string_view(arguments[1]) == "chunk-reassembly-reset-bounds")
    {
        test_chunk_reassembly_reset_and_bounds();
        return 0;
    }
    if (argumentCount != 1)
    {
        return 2; // Unknown test case names must not silently pass.
    }
    test_pdu_round_trip();
    test_chunk_reassembly();
    test_unicode_and_line_endings();
    test_png_validation();
    test_png_palette_rules();
    test_dib_wrapping();
    test_dib_pixel_payload_validation();
    return 0;
}
