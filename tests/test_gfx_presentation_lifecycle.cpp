// SPDX-License-Identifier: GPL-3.0-or-later
#include "rdp/gfx_presentation_lifecycle.h"
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

using namespace rdp_server::rdp;
namespace
{
using Receipt = GfxPresentationReceipt;
using Buffer = std::array<std::byte, 24>;

std::array<std::byte, 22> advertisement(std::byte flags = std::byte{0x10})
{
    return {std::byte{0x12}, {}, {}, {}, std::byte{22}, {}, {}, {},
            std::byte{1}, {}, std::byte{5}, std::byte{1}, std::byte{8}, {},
            std::byte{4}, {}, {}, {}, flags, {}, {}, {}};
}

std::array<std::byte, 20> ack(std::uint32_t id, std::uint32_t depth = 0)
{
    std::array<std::byte, 20> pdu{
        std::byte{13}, {}, {}, {}, std::byte{20}, {}, {}, {}};
    for (unsigned n = 0; n != 4; ++n)
    {
        pdu[8 + n] = static_cast<std::byte>(depth >> (8U * n));
        pdu[12 + n] = static_cast<std::byte>(id >> (8U * n));
    }
    return pdu;
}

Receipt emit(GfxPresentationLifecycle &lifecycle, std::uint64_t gen,
             std::byte command, std::size_t size)
{
    Buffer bytes{}; bytes.fill(std::byte{0xA5});
    Receipt receipt{};
    assert(lifecycle.prepareCommand(gen, bytes, receipt));
    assert(bytes[0] == command && receipt.bytes == size);
    for (std::size_t n = size; n != bytes.size(); ++n)
        assert(bytes[n] == std::byte{0xA5});
    return receipt;
}

void mapped(GfxPresentationLifecycle &lifecycle, std::uint64_t gen)
{
    assert(lifecycle.open(gen));
    assert(lifecycle.acceptCapabilities(gen, advertisement()));
    assert(lifecycle.completeCommand(emit(lifecycle, gen, std::byte{0x13}, 20), 20));
    assert(lifecycle.configureSurface(gen, 7, {640, 480}));
    assert(lifecycle.completeCommand(emit(lifecycle, gen, std::byte{9}, 15), 15));
    assert(lifecycle.completeCommand(emit(lifecycle, gen, std::byte{15}, 20), 20));
    assert(lifecycle.stage() == GfxPresentationStage::Mapped);
}

void delivered(GfxPresentationLifecycle &lifecycle, std::uint64_t gen,
               std::uint32_t id)
{
    GfxFrameDeliveryReceipt ticket{};
    assert(lifecycle.beginFrameDelivery(gen, id, 128, ticket));
    assert(lifecycle.completeFrameDelivery(ticket, 128));
}

void ordering()
{
    GfxPresentationLifecycle lifecycle;
    Buffer bytes{}; bytes.fill(std::byte{0xA5});
    Receipt ticket{999, 5, GfxPresentationCommand::Map, 123};
    assert(!lifecycle.canSubmitFrame(7));
    assert(lifecycle.open(7));
    assert(!lifecycle.prepareCommand(7, bytes, ticket));
    assert(!lifecycle.configureSurface(7, 1, {640, 480}));
    assert(lifecycle.acceptCapabilities(7, advertisement()));
    assert(!lifecycle.prepareCommand(7, std::span<std::byte>(bytes).first(19), ticket));
    for (std::byte b : bytes) assert(b == std::byte{0xA5});
    assert(ticket.serial == 5);
    const Receipt confirm = emit(lifecycle, 7, std::byte{19}, 20);
    assert(!lifecycle.prepareCommand(7, bytes, ticket));
    assert(!lifecycle.completeCommand(confirm, 19));
    assert(!lifecycle.configureSurface(7, 1, {640, 480}));
    assert(lifecycle.completeCommand(confirm, 20));
    assert(!lifecycle.completeCommand(confirm, 20));
    assert(lifecycle.configureSurface(7, 1, {640, 480}));
    const Receipt create = emit(lifecycle, 7, std::byte{9}, 15);
    { GfxFrameDeliveryReceipt denied{}; assert(!lifecycle.beginFrameDelivery(7, 1, 128, denied)); }
    assert(!lifecycle.completeCommand(create, 14));
    assert(lifecycle.completeCommand(create, 15));
    const Receipt map = emit(lifecycle, 7, std::byte{15}, 20);
    assert(!lifecycle.canSubmitFrame(7));
    assert(lifecycle.completeCommand(map, 20));
    assert(lifecycle.canSubmitFrame(7));
    delivered(lifecycle, 7, 1);
    GfxFrameAckWindowResult result{};
    assert(lifecycle.onFrameAcknowledge(7, ack(1), result));
    assert(result == GfxFrameAckWindowResult::Acknowledged);
}

void denials()
{
    GfxPresentationLifecycle lifecycle;
    assert(!lifecycle.open(0));
    assert(lifecycle.open(1));
    assert(!lifecycle.open(1));
    assert(!lifecycle.acceptCapabilities(2, advertisement()));
    auto malformed = advertisement(); malformed[4] = std::byte{21};
    assert(!lifecycle.acceptCapabilities(1, malformed));
    assert(lifecycle.stage() == GfxPresentationStage::Rejected);
    assert(!lifecycle.acceptCapabilities(1, advertisement()));
    assert(lifecycle.open(2));
    assert(!lifecycle.acceptCapabilities(2, advertisement(std::byte{0})));
    assert(lifecycle.open(3));
    assert(lifecycle.acceptCapabilities(3, advertisement()));
    assert(!lifecycle.acceptCapabilities(3, advertisement()));
    assert(lifecycle.completeCommand(emit(lifecycle, 3, std::byte{19}, 20), 20));
    for (const PixelSize size : {PixelSize{0, 480}, PixelSize{640, 0},
                                 PixelSize{641, 480}, PixelSize{640, 479},
                                 PixelSize{65536, 480}, PixelSize{640, 65536}})
        assert(!lifecycle.configureSurface(3, 1, size));
    assert(!lifecycle.configureSurface(3, 0, {640, 480}));
    assert(lifecycle.configureSurface(3, 1, {640, 480}));
    assert(!lifecycle.configureSurface(3, 1, {640, 480}));
    Buffer bytes{};bytes.fill(std::byte{0xA5});Receipt unused{};
    assert(!lifecycle.prepareCommand(3, std::span<std::byte>(bytes).first(14), unused));
    for (std::byte b : bytes) assert(b == std::byte{0xA5});
    assert(lifecycle.completeCommand(emit(lifecycle, 3, std::byte{9}, 15), 15));
    assert(lifecycle.completeCommand(emit(lifecycle, 3, std::byte{15}, 20), 20));
    auto invalid = ack(1); invalid[2] = std::byte{1};
    GfxFrameAckWindowResult result = GfxFrameAckWindowResult::Suspended;
    assert(!lifecycle.onFrameAcknowledge(3, invalid, result));
    assert(result == GfxFrameAckWindowResult::Suspended);
}

void revocation()
{
    GfxPresentationLifecycle lifecycle;
    mapped(lifecycle, 100);
    delivered(lifecycle, 100, 5);
    assert(lifecycle.requestSurfaceDelete(100));
    assert(!lifecycle.canSubmitFrame(100));
    assert(lifecycle.outstandingFrames() == 0);
    const Receipt del = emit(lifecycle, 100, std::byte{10}, 10);
    assert(!lifecycle.completeCommand(del, 9));
    assert(!lifecycle.configureSurface(100, 7, {800, 600}));
    assert(lifecycle.completeCommand(del, 10));
    assert(lifecycle.configureSurface(100, 7, {800, 600}));
    const Receipt old = emit(lifecycle, 100, std::byte{9}, 15);
    lifecycle.disconnect(); lifecycle.disconnect();
    assert(!lifecycle.completeCommand(old, 15));
    assert(!lifecycle.open(100));
    assert(lifecycle.open(101));
    assert(!lifecycle.acceptCapabilities(100, advertisement()));
    assert(lifecycle.acceptCapabilities(101, advertisement()));
    const Receipt confirm = emit(lifecycle, 101, std::byte{19}, 20);
    assert(confirm.serial > old.serial);
    assert(!lifecycle.completeCommand(old, 15));
    assert(lifecycle.completeCommand(confirm, 20));
    assert(lifecycle.configureSurface(101, 7, {800, 600}));
    assert(lifecycle.completeCommand(emit(lifecycle, 101, std::byte{9}, 15), 15));
    assert(lifecycle.completeCommand(emit(lifecycle, 101, std::byte{15}, 20), 20));
    delivered(lifecycle, 101, 5);
    GfxFrameAckWindowResult result{};
    assert(!lifecycle.onFrameAcknowledge(100, ack(5), result));
    assert(lifecycle.outstandingFrames() == 1);
    assert(lifecycle.onFrameAcknowledge(101, ack(5), result));
    assert(result == GfxFrameAckWindowResult::Acknowledged);
}

void backpressure()
{
    GfxPresentationLifecycle lifecycle;
    mapped(lifecycle, 501);
    for (std::uint32_t id = 1; id <= 64; ++id)
        delivered(lifecycle, 501, id);
    assert(lifecycle.outstandingFrames() == 64);
    assert(!lifecycle.canSubmitFrame(501));
    { GfxFrameDeliveryReceipt denied{}; assert(!lifecycle.beginFrameDelivery(501, 65, 128, denied)); }
    GfxFrameAckWindowResult result{};
    assert(lifecycle.onFrameAcknowledge(501, ack(32, 10), result));
    assert(result == GfxFrameAckWindowResult::Acknowledged);
    delivered(lifecycle, 501, 65);
    { GfxFrameDeliveryReceipt denied{}; assert(!lifecycle.beginFrameDelivery(501, 65, 128, denied)); }
    assert(lifecycle.outstandingFrames() == 64);
    assert(lifecycle.onFrameAcknowledge(501,
        ack(99, kGfxSuspendFrameAcknowledgement), result));
    assert(result == GfxFrameAckWindowResult::Suspended);
    assert(lifecycle.outstandingFrames() == 0);
    delivered(lifecycle, 501, 1000);
    assert(lifecycle.outstandingFrames() == 0);
    assert(lifecycle.onFrameAcknowledge(501, ack(1000, 1), result));
    delivered(lifecycle, 501, 1001);
    assert(lifecycle.outstandingFrames() == 1);
}

void frameReceipts()
{
    GfxPresentationLifecycle lifecycle;
    mapped(lifecycle, 801);
    GfxFrameDeliveryReceipt ticket{55, 66, 77, 88};
    const auto original = ticket;
    assert(!lifecycle.beginFrameDelivery(801, 4, 0, ticket));
    assert(!lifecycle.beginFrameDelivery(800, 4, 90, ticket));
    assert(ticket == original);
    assert(lifecycle.beginFrameDelivery(801, 4, 90, ticket));
    assert(ticket.generation == 801 && ticket.frameId == 4 &&
           ticket.bytes == 90 && ticket.serial != 0);
    assert(!lifecycle.canSubmitFrame(801));
    assert(lifecycle.outstandingFrames() == 0);
    assert(!lifecycle.requestSurfaceDelete(801));
    GfxFrameDeliveryReceipt other{};
    assert(!lifecycle.beginFrameDelivery(801, 5, 91, other));
    assert(!lifecycle.completeFrameDelivery(ticket, 89));
    auto forged = ticket; ++forged.serial;
    assert(!lifecycle.completeFrameDelivery(forged, 90));
    GfxFrameAckWindowResult result{};
    assert(lifecycle.onFrameAcknowledge(801, ack(4), result));
    assert(result == GfxFrameAckWindowResult::Unmatched);
    assert(lifecycle.completeFrameDelivery(ticket, 90));
    assert(!lifecycle.completeFrameDelivery(ticket, 90));
    assert(lifecycle.outstandingFrames() == 1);
    assert(!lifecycle.beginFrameDelivery(801, 4, 90, other));
    assert(lifecycle.beginFrameDelivery(801, 5, 91, other));
    assert(lifecycle.completeFrameDelivery(other, 91));
    assert(lifecycle.outstandingFrames() == 2);
    assert(lifecycle.onFrameAcknowledge(801, ack(4), result));
    assert(result == GfxFrameAckWindowResult::Acknowledged);
    assert(lifecycle.onFrameAcknowledge(801, ack(5), result));
    assert(result == GfxFrameAckWindowResult::Acknowledged);
}

void frameAbort()
{
    GfxPresentationLifecycle lifecycle;
    mapped(lifecycle, 901);
    GfxFrameDeliveryReceipt ticket{};
    assert(lifecycle.beginFrameDelivery(901, 7, 256, ticket));
    auto forged = ticket; ++forged.frameId;
    assert(!lifecycle.abortFrameDelivery(forged));
    assert(lifecycle.stage() == GfxPresentationStage::Mapped);
    assert(!lifecycle.completeFrameDelivery(ticket, 255));
    assert(lifecycle.abortFrameDelivery(ticket));
    assert(lifecycle.stage() == GfxPresentationStage::Inactive);
    assert(!lifecycle.abortFrameDelivery(ticket));
    assert(!lifecycle.completeFrameDelivery(ticket, 256));
    assert(!lifecycle.open(901));
    mapped(lifecycle, 902);
    assert(!lifecycle.completeFrameDelivery(ticket, 256));
    GfxFrameDeliveryReceipt fresh{};
    assert(lifecycle.beginFrameDelivery(902, 7, 256, fresh));
    assert(fresh.serial > ticket.serial);
    assert(!lifecycle.abortFrameDelivery(ticket));
    assert(lifecycle.completeFrameDelivery(fresh, 256));
    GfxFrameAckWindowResult result{};
    assert(!lifecycle.onFrameAcknowledge(901, ack(7), result));
    assert(lifecycle.onFrameAcknowledge(902, ack(7), result));
    assert(result == GfxFrameAckWindowResult::Acknowledged);
}
} // namespace

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    const std::string_view mode{argv[1]};
    if (mode == "channel-lifecycle-ordering") { ordering(); return 0; }
    if (mode == "channel-lifecycle-denials") { denials(); return 0; }
    if (mode == "surface-resize-revocation") { revocation(); return 0; }
    if (mode == "frame-publication-backpressure") { backpressure(); return 0; }
    if (mode == "frame-delivery-receipt-ordering") { frameReceipts(); return 0; }
    if (mode == "frame-delivery-abort-revocation") { frameAbort(); return 0; }
    return 2;
}
