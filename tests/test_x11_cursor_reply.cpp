// SPDX-License-Identifier: GPL-3.0-or-later

#include "../src/x11/cursor_image_conversion.h"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>

int main()
{
    using rdp_server::valid_xfixes_cursor_reply;

    // XFixes reports its payload size in 32-bit words, not bytes.
    static_assert(valid_xfixes_cursor_reply(1, 1, 0, 0, 1));
    static_assert(valid_xfixes_cursor_reply(32, 32, 31, 31, 1024));
    static_assert(valid_xfixes_cursor_reply(32, 32, 31, 31, 1025));
    static_assert(!valid_xfixes_cursor_reply(32, 32, 31, 31, 1023));
    static_assert(!valid_xfixes_cursor_reply(2, 2, 1, 1, 3));
    static_assert(!valid_xfixes_cursor_reply(0, 1, 0, 0, 1));
    static_assert(!valid_xfixes_cursor_reply(1, 0, 0, 0, 1));
    static_assert(!valid_xfixes_cursor_reply(33, 1, 0, 0, 33));
    static_assert(!valid_xfixes_cursor_reply(1, 33, 0, 0, 33));
    static_assert(!valid_xfixes_cursor_reply(1, 1, 1, 0, 1));
    static_assert(!valid_xfixes_cursor_reply(1, 1, 0, 1, 1));
    static_assert(!valid_xfixes_cursor_reply(1, 1, 0, 0, 0));

    // The existing production converter preserves BGRX ordering, bottom-up
    // row layout and alpha mask without needing an X connection.
    constexpr std::array<std::uint32_t, 2> argb{
        0xff123456U, 0x00112233U,
    };
    std::array<std::byte, 32U * 32U * 4U> pixels{};
    std::array<std::byte, (32U * 32U) / 8U> transparencyMask{};
    assert(rdp_server::convert_cursor_image(
        argb, 2, 1, pixels, transparencyMask));

    const std::size_t bottomLeftPixelOffset = 31U * 32U * 4U;
    assert(pixels[bottomLeftPixelOffset] == std::byte{0x56});
    assert(pixels[bottomLeftPixelOffset + 1U] == std::byte{0x34});
    assert(pixels[bottomLeftPixelOffset + 2U] == std::byte{0x12});
    assert(pixels[bottomLeftPixelOffset + 3U] == std::byte{0x00});
    assert(pixels[bottomLeftPixelOffset + 4U] == std::byte{0x00});
    assert(transparencyMask[31U * 32U / 8U] == std::byte{0x7f});
    assert(transparencyMask[0] == std::byte{0xff});

    // Invalid source and destination spans fail without modifying output.
    pixels.fill(std::byte{0x55});
    transparencyMask.fill(std::byte{0x55});
    assert(!rdp_server::convert_cursor_image(
        std::span<const std::uint32_t>{argb}.first(1), 2, 1,
        pixels, transparencyMask));
    assert(!rdp_server::convert_cursor_image(
        argb, 2, 1, std::span<std::byte>{pixels}.first(4095),
        transparencyMask));
    assert(!rdp_server::convert_cursor_image(
        argb, 2, 1, pixels,
        std::span<std::byte>{transparencyMask}.first(127)));
    assert(pixels[0] == std::byte{0x55});
    assert(transparencyMask[0] == std::byte{0x55});
    return 0;
}
