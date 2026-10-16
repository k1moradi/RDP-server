// SPDX-License-Identifier: GPL-3.0-or-later
#include "rdp/gfx_avc420_picture.h"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string_view>
#include <vector>

using namespace rdp_server::rdp;

namespace
{
constexpr std::array<std::byte, 7> kSyntheticAnnexB{
    std::byte{}, std::byte{}, std::byte{}, std::byte{1},
    std::byte{0x65}, std::byte{0xAA}, std::byte{0xBB}};
constexpr std::array<Rectangle, 2> kRegions{
    Rectangle{4, 2, 16, 12}, Rectangle{0, 0, 32, 16}};
constexpr std::array<GfxAvc420QuantQuality, 2> kQuality{{
    {22, 80}, {40, 100}
}};
using Bytes = std::array<std::byte, 128>;

GfxAvc420Picture picture() noexcept
{
    return {7, 0x11223344U, {32, 16}, kRegions, kQuality,
            kSyntheticAnnexB};
}
std::uint16_t u16(std::span<const std::byte> b, std::size_t p)
{
    return static_cast<std::uint16_t>(
        std::to_integer<unsigned>(b[p]) |
        (std::to_integer<unsigned>(b[p + 1]) << 8U));
}
std::uint32_t u32(std::span<const std::byte> b, std::size_t p)
{
    return static_cast<std::uint32_t>(u16(b, p)) |
           (static_cast<std::uint32_t>(u16(b, p + 2)) << 16U);
}
void wire()
{
    Bytes output{}; output.fill(std::byte{0xA5});
    const auto p = picture();
    const auto bytes = gfxAvc420PictureBytes(2, 7);
    assert(bytes == 84U);
    assert(buildGfxAvc420Picture(p, output) == bytes);
    assert(u16(output, 0) == 0x0B && u32(output, 4) == 16);
    assert(u32(output, 8) == 0 && u32(output, 12) == p.frameId);
    assert(u16(output, 16) == 0x0001 && u16(output, 18) == 0);
    assert(u32(output, 20) == 56); // 25 + 4 + 2*10 + 7
    assert(u16(output, 24) == 7 && u16(output, 26) == 0x000B);
    assert(output[28] == std::byte{0x20});
    assert(u16(output, 29) == 0 && u16(output, 31) == 0);
    assert(u16(output, 33) == 32 && u16(output, 35) == 16);
    assert(u32(output, 37) == 31); // Metablock 4+20, Annex B 7
    assert(u32(output, 41) == 2);
    // Region RECT16: left, top, right, bottom, not x,y,width,height.
    assert(u16(output, 45) == 4 && u16(output, 47) == 2);
    assert(u16(output, 49) == 20 && u16(output, 51) == 14);
    assert(u16(output, 53) == 0 && u16(output, 55) == 0);
    assert(u16(output, 57) == 32 && u16(output, 59) == 16);
    assert(output[61] == std::byte{22} && output[62] == std::byte{80});
    assert(output[63] == std::byte{40} && output[64] == std::byte{100});
    for (std::size_t i = 0; i < kSyntheticAnnexB.size(); ++i)
        assert(output[65 + i] == kSyntheticAnnexB[i]);
    assert(u16(output, 72) == 0x0C && u32(output, 76) == 12);
    assert(u32(output, 80) == p.frameId);
    for (std::size_t i = bytes; i < output.size(); ++i)
        assert(output[i] == std::byte{0xA5});
}
void rejections()
{
    Bytes output{}; output.fill(std::byte{0xA5});
    const auto fail = [&](const GfxAvc420Picture &p, std::size_t capacity) {
        output.fill(std::byte{0xA5});
        assert(buildGfxAvc420Picture(p,
               std::span<std::byte>{output}.first(capacity)) == 0);
        for (std::byte b : output) assert(b == std::byte{0xA5});
    };
    const auto valid = picture();
    for (std::size_t n = 0; n < gfxAvc420PictureBytes(2, 7); ++n)
        fail(valid, n);
    {auto p=valid;p.surfaceId=0;fail(p,output.size());}
    {auto p=valid;p.frameId=0;fail(p,output.size());}
    for(const PixelSize size : {PixelSize{0,16}, PixelSize{32,0},
                                PixelSize{31,16}, PixelSize{32,17},
                                PixelSize{65536,16}, PixelSize{32,65536}})
        {auto p=valid;p.codedGeometry=size;fail(p,output.size());}
    {auto p=valid;p.quantQualities={};fail(p,output.size());}
    {auto p=valid;p.annexBPicture={};fail(p,output.size());}
    std::array<std::byte,4> nonsense{
        std::byte{0},std::byte{0},std::byte{1},std::byte{0x80}};
    {auto p=valid;p.annexBPicture=nonsense;fail(p,output.size());}
    nonsense[3]=std::byte{0};
    {auto p=valid;p.annexBPicture=nonsense;fail(p,output.size());}
    std::array<GfxAvc420QuantQuality,2> bad=kQuality;
    bad[0].qp=52;
    {auto p=valid;p.quantQualities=bad;fail(p,output.size());}
    bad=kQuality;bad[0].quality=101;
    {auto p=valid;p.quantQualities=bad;fail(p,output.size());}
    std::array<Rectangle,2> rects=kRegions;
    rects[0].x=-1;
    {auto p=valid;p.regions=rects;fail(p,output.size());}
    rects=kRegions;rects[0].widthPixels=33;
    {auto p=valid;p.regions=rects;fail(p,output.size());}
    assert(gfxAvc420PictureBytes(0,7)==0);
    assert(gfxAvc420PictureBytes(4097,7)==0);
    assert(gfxAvc420PictureBytes(1,kGfxMaximumAnnexBPictureBytes+1)==0);
    assert(gfxAvc420PictureBytes(1,std::numeric_limits<std::size_t>::max())==0);
}
void overlap()
{
    // Precopy payload is overlap safe: it must preserve the input NAL
    // before inserting the surrounding graphics headers.
    std::array<std::byte,128> output{};
    std::copy(kSyntheticAnnexB.begin(), kSyntheticAnnexB.end(),
              output.begin()+45);
    auto p=picture();
    p.annexBPicture=std::span<const std::byte>(output).subspan(45,7);
    assert(buildGfxAvc420Picture(p,output)==84);
    for(std::size_t i=0;i<7;++i)assert(output[65+i]==kSyntheticAnnexB[i]);
}

void crop1080()
{
    assert(gfxAvc420CodedGeometry({1920,1080}) ==
           (PixelSize{1920,1088}));
    assert(gfxAvc420CodedGeometry({1366,768}) ==
           (PixelSize{1376,768}));
    std::array<Rectangle,1> regions{Rectangle{0,0,1920,1080}};
    std::array<GfxAvc420QuantQuality,1> quant{{{22,80}}};
    GfxAvc420Picture p{7,42,{1920,1088},regions,quant,
                       kSyntheticAnnexB,{1920,1080}};
    std::array<std::byte,96> out{};
    out.fill(std::byte{0xCC});
    assert(buildGfxAvc420Picture(p,out)==74);
    assert(u16(out,33)==1920 && u16(out,35)==1080);
    assert(u16(out,49)==1920 && u16(out,51)==1080);
    assert(u16(out,62)==0x000C && u32(out,70)==42);
    for(std::size_t i=74;i<out.size();++i)
        assert(out[i]==std::byte{0xCC});
}
void cropDenials()
{
    assert(gfxAvc420CodedGeometry({0,1080})==PixelSize{});
    assert(gfxAvc420CodedGeometry({65521,16})==PixelSize{});
    std::array<Rectangle,1> regions{Rectangle{0,0,1920,1080}};
    std::array<GfxAvc420QuantQuality,1> quant{{{22,80}}};
    GfxAvc420Picture p{7,42,{1920,1088},regions,quant,
                       kSyntheticAnnexB,{1920,1080}};
    std::array<std::byte,96> out{};
    auto denied=[&](const GfxAvc420Picture &bad){
        out.fill(std::byte{0xCC});
        assert(buildGfxAvc420Picture(bad,out)==0);
        for(auto b:out)assert(b==std::byte{0xCC});
    };
    {auto b=p;b.visibleGeometry={1920,0};denied(b);}
    {auto b=p;b.visibleGeometry={0,1080};denied(b);}
    {auto b=p;b.visibleGeometry={1936,1080};denied(b);}
    {auto b=p;b.visibleGeometry={1920,1104};denied(b);}
    {auto b=p;b.codedGeometry={1920,1080};denied(b);}
    {auto b=p;b.visibleGeometry={1920,1072};denied(b);}
    std::array<Rectangle,1> padded{Rectangle{0,1072,1920,16}};
    {auto b=p;b.regions=padded;denied(b);}
}
} // namespace

int main(int argc, char **argv)
{
    if(argc!=2) return 2;
    const std::string_view testName=argv[1];
    if(testName=="avc420-picture-wire") {wire();return 0;}
    if(testName=="avc420-picture-rejections") {rejections();return 0;}
    if(testName=="avc420-picture-overlap") {overlap();return 0;}
    if(testName=="avc420-visible-crop") {crop1080();return 0;}
    if(testName=="avc420-visible-crop-rejections") {cropDenials();return 0;}
    return 2;
}
