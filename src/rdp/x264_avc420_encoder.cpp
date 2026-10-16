// SPDX-License-Identifier: GPL-3.0-or-later
#include "x264_avc420_encoder.h"

#include "rdp/gfx_avc420_picture.h"

#include <climits>
#include <limits>
#include <new>
#include <utility>

extern "C"
{
#include "x264.h"
}

namespace rdp_server::rdp
{
namespace
{

[[nodiscard]] bool planeExtentValid(std::span<const std::byte> plane,
                                    std::size_t stride,
                                    std::uint32_t width,
                                    std::uint32_t rows) noexcept
{
    if (width == 0 || rows == 0 || stride < width || stride > INT_MAX)
        return false;
    const std::size_t rowCount = rows;
    if (rowCount - 1U >
        (std::numeric_limits<std::size_t>::max() - width) / stride)
        return false;
    return plane.size() >= (rowCount - 1U) * stride + width;
}

[[nodiscard]] bool hasAnnexBPrefix(std::span<const std::byte> bytes) noexcept
{
    return bytes.size() >= 4U && bytes[0] == std::byte{} &&
           bytes[1] == std::byte{} &&
           (bytes[2] == std::byte{1} ||
            (bytes[2] == std::byte{} && bytes[3] == std::byte{1}));
}

} // namespace

struct X264Avc420Encoder::Impl final
{
    x264_t *encoder{};
    PixelSize coded{};
    PixelSize visible{};

    ~Impl()
    {
        if (encoder != nullptr)
            x264_encoder_close(encoder);
    }
};

X264Avc420Encoder::X264Avc420Encoder() noexcept = default;
X264Avc420Encoder::~X264Avc420Encoder() = default;

bool X264Avc420Encoder::open(PixelSize codedGeometry,
                             PixelSize visibleGeometry) noexcept
{
    reset();
    if (codedGeometry.widthPixels == 0 || codedGeometry.heightPixels == 0 ||
        (codedGeometry.widthPixels & 15U) != 0 ||
        (codedGeometry.heightPixels & 15U) != 0 ||
        codedGeometry.widthPixels > static_cast<std::uint32_t>(INT_MAX) ||
        codedGeometry.heightPixels > static_cast<std::uint32_t>(INT_MAX) ||
        visibleGeometry.widthPixels == 0 || visibleGeometry.heightPixels == 0 ||
        visibleGeometry.widthPixels > codedGeometry.widthPixels ||
        visibleGeometry.heightPixels > codedGeometry.heightPixels ||
        (visibleGeometry.widthPixels & 1U) != 0 ||
        (visibleGeometry.heightPixels & 1U) != 0)
        return false;

    const std::uint64_t pixels =
        static_cast<std::uint64_t>(codedGeometry.widthPixels) *
        codedGeometry.heightPixels;
    constexpr std::uint64_t maximumInputBytes = 64U * 1024U * 1024U;
    if (pixels > maximumInputBytes * 2U / 3U)
        return false;

    x264_param_t parameters{};
    if (x264_param_default_preset(&parameters, "ultrafast", "zerolatency") < 0)
        return false;
    parameters.i_width = static_cast<int>(codedGeometry.widthPixels);
    parameters.i_height = static_cast<int>(codedGeometry.heightPixels);
    parameters.i_csp = X264_CSP_NV12;
    parameters.i_bitdepth = 8;
    parameters.i_threads = 1;
    parameters.b_sliced_threads = 0;
    parameters.i_sync_lookahead = 0;
    parameters.i_bframe = 0;
    parameters.rc.i_lookahead = 0;
    parameters.i_frame_reference = 1;
    parameters.i_keyint_max = 60;
    parameters.i_keyint_min = 1;
    parameters.i_scenecut_threshold = 0;
    parameters.b_repeat_headers = 1;
    parameters.b_annexb = 1;
    parameters.b_aud = 1;
    parameters.b_vfr_input = 0;
    parameters.i_fps_num = 60;
    parameters.i_fps_den = 1;
    parameters.i_timebase_num = 1;
    parameters.i_timebase_den = 60;
    parameters.i_log_level = X264_LOG_NONE;
    parameters.vui.b_fullrange = 1;
    parameters.vui.i_colorprim = 1; // ITU-R BT.709
    parameters.vui.i_transfer = 1;  // ITU-R BT.709
    parameters.vui.i_colmatrix = 1; // ITU-R BT.709
    parameters.crop_rect.i_right = static_cast<int>(
        codedGeometry.widthPixels - visibleGeometry.widthPixels);
    parameters.crop_rect.i_bottom = static_cast<int>(
        codedGeometry.heightPixels - visibleGeometry.heightPixels);
    if (x264_param_apply_profile(&parameters, "baseline") < 0)
        return false;

    x264_t *const encoder = x264_encoder_open(&parameters);
    if (encoder == nullptr)
        return false;

    try
    {
        auto candidate = std::make_unique<Impl>();
        candidate->encoder = encoder;
        candidate->coded = codedGeometry;
        candidate->visible = visibleGeometry;
        impl_ = std::move(candidate);
    }
    catch (...)
    {
        x264_encoder_close(encoder);
        return false;
    }
    return true;
}

void X264Avc420Encoder::reset() noexcept
{
    impl_.reset();
}

bool X264Avc420Encoder::valid() const noexcept
{
    return impl_ != nullptr && impl_->encoder != nullptr;
}

PixelSize X264Avc420Encoder::codedGeometry() const noexcept
{
    return valid() ? impl_->coded : PixelSize{};
}

PixelSize X264Avc420Encoder::visibleGeometry() const noexcept
{
    return valid() ? impl_->visible : PixelSize{};
}

bool X264Avc420Encoder::encode(const X264Nv12PictureView &picture,
                               X264EncodedPicture &output) noexcept
{
    if (!valid() || picture.codedGeometry != impl_->coded ||
        !planeExtentValid(picture.yPlane, picture.yStrideBytes,
                          picture.codedGeometry.widthPixels,
                          picture.codedGeometry.heightPixels) ||
        !planeExtentValid(picture.uvPlane, picture.uvStrideBytes,
                          picture.codedGeometry.widthPixels,
                          picture.codedGeometry.heightPixels / 2U))
        return false;

    x264_picture_t input{};
    x264_picture_t encoded{};
    x264_picture_init(&input);
    input.img.i_csp = X264_CSP_NV12;
    input.img.i_plane = 2;
    input.img.plane[0] = reinterpret_cast<std::uint8_t *>(
        const_cast<std::byte *>(picture.yPlane.data()));
    input.img.plane[1] = reinterpret_cast<std::uint8_t *>(
        const_cast<std::byte *>(picture.uvPlane.data()));
    input.img.i_stride[0] = static_cast<int>(picture.yStrideBytes);
    input.img.i_stride[1] = static_cast<int>(picture.uvStrideBytes);
    input.i_pts = picture.pts;

    x264_nal_t *nals = nullptr;
    int nalCount = 0;
    const int encodedBytes =
        x264_encoder_encode(impl_->encoder, &nals, &nalCount, &input, &encoded);
    if (encodedBytes <= 0 || nals == nullptr || nalCount <= 0 ||
        x264_encoder_delayed_frames(impl_->encoder) != 0)
        return false;

    std::size_t totalBytes = 0;
    for (int index = 0; index < nalCount; ++index)
    {
        if (nals[index].i_payload <= 0 || nals[index].p_payload == nullptr)
            return false;
        const auto bytes = static_cast<std::size_t>(nals[index].i_payload);
        if (bytes > kMaximumEncodedPictureBytes - totalBytes)
            return false;
        totalBytes += bytes;
    }
    if (totalBytes == 0 || totalBytes > kGfxMaximumAnnexBPictureBytes)
        return false;

    try
    {
        X264EncodedPicture candidate{};
        candidate.annexB.reserve(totalBytes);
        for (int index = 0; index < nalCount; ++index)
        {
            const auto *const begin = reinterpret_cast<const std::byte *>(
                nals[index].p_payload);
            candidate.annexB.insert(candidate.annexB.end(), begin,
                                    begin + nals[index].i_payload);
        }
        if (candidate.annexB.size() != totalBytes ||
            !hasAnnexBPrefix(candidate.annexB))
            return false;
        candidate.keyFrame = encoded.b_keyframe != 0;
        candidate.pts = encoded.i_pts;
        output = std::move(candidate);
    }
    catch (...)
    {
        return false;
    }
    return true;
}

} // namespace rdp_server::rdp
