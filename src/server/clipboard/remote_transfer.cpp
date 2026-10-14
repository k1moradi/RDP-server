// SPDX-License-Identifier: GPL-3.0-or-later
#include "remote_transfer.h"

#include "clipboard/clipboard_protocol.h"
#include "ms-rdpeclip.h" // Owned, attributed xrdp v0.10.6.1 definition source

#include <algorithm>
#include <array>
#include <limits>

namespace rdp_server::server::clipboard
{
// The native source-owned state machine must not drift from upstream's
// published CLIPRDR constants during the legacy chansrv migration.
static_assert(rdp_server::clipboard::kMonitorReady == CB_MONITOR_READY);
static_assert(rdp_server::clipboard::kFormatList == CB_FORMAT_LIST);
static_assert(rdp_server::clipboard::kFormatDataRequest ==
              CB_FORMAT_DATA_REQUEST);
static_assert(rdp_server::clipboard::kFormatDataResponse ==
              CB_FORMAT_DATA_RESPONSE);
static_assert(rdp_server::clipboard::kResponseOk == CB_RESPONSE_OK);
static_assert(rdp_server::clipboard::kResponseFail == CB_RESPONSE_FAIL);
static_assert(rdp_server::clipboard::kUseLongFormatNames ==
              CB_USE_LONG_FORMAT_NAMES);
namespace
{
constexpr std::uint16_t kAllowedResponseFlags =
    rdp_server::clipboard::kResponseOk |
    rdp_server::clipboard::kResponseFail;

} // namespace

bool RemoteTransfer::receiveFormatList(
    std::span<const std::uint32_t> advertisedFormatIds) noexcept
{
    if (poisoned_ || generation_ == std::numeric_limits<std::uint64_t>::max() ||
        advertisedFormatIds.size() > kMaximumFormats)
    {
        poisoned_ = true;
        return false;
    }

    // Small bounded lookup; reject malformed duplicates instead of creating
    // an ambiguous mapping between named and standard clipboard formats.
    for (std::size_t index = 0; index < advertisedFormatIds.size(); ++index)
    {
        const std::uint32_t formatId = advertisedFormatIds[index];
        if (formatId == 0 ||
            std::find(advertisedFormatIds.begin(),
                      advertisedFormatIds.begin() + index, formatId) !=
                advertisedFormatIds.begin() + index)
        {
            poisoned_ = true;
            return false;
        }
    }

    std::copy(advertisedFormatIds.begin(), advertisedFormatIds.end(),
              advertisedFormats_.begin());
    advertisedCount_ = advertisedFormatIds.size();
    ++generation_;
    // pending_ deliberately survives a new format list: CLIPRDR wire
    // responses carry no request generation. A stale response must be drained.
    return true;
}

bool RemoteTransfer::beginRequest(
    std::uint32_t formatId, std::vector<std::uint8_t> &output) noexcept
{
    output.clear();
    if (poisoned_ || generation_ == 0 || pendingValid_ ||
        !advertises(formatId))
    {
        return false;
    }
    const std::array<std::uint8_t, 4> payload{
        static_cast<std::uint8_t>(formatId),
        static_cast<std::uint8_t>(formatId >> 8U),
        static_cast<std::uint8_t>(formatId >> 16U),
        static_cast<std::uint8_t>(formatId >> 24U),
    };
    if (!rdp_server::clipboard::encodePdu(
            rdp_server::clipboard::kFormatDataRequest, 0, payload, output))
    {
        return false;
    }
    pending_ = PendingRequest{generation_, formatId};
    pendingValid_ = true;
    return true;
}

RemoteTransfer::Response RemoteTransfer::receiveResponse(
    std::span<const std::uint8_t> completePdu) noexcept
{
    using namespace rdp_server::clipboard;
    PduView pdu{};
    if (poisoned_ || !pendingValid_ || !decodePdu(completePdu, pdu) ||
        pdu.type != kFormatDataResponse ||
        (pdu.flags != kResponseOk && pdu.flags != kResponseFail) ||
        (pdu.flags & ~kAllowedResponseFlags) != 0 ||
        (pdu.flags == kResponseFail && !pdu.payload.empty()))
    {
        poisoned_ = true;
        return {};
    }

    const PendingRequest completed = pending_;
    pending_ = {};
    pendingValid_ = false;
    if (completed.generation != generation_)
    {
        return {ResponseStatus::DiscardedPreviousGeneration,
                completed.generation, completed.formatId, {}};
    }
    if (pdu.flags == kResponseFail)
    {
        return {ResponseStatus::RemoteFailure,
                completed.generation, completed.formatId, {}};
    }
    return {ResponseStatus::Received, completed.generation,
            completed.formatId, pdu.payload};
}

void RemoteTransfer::abandonRequest() noexcept
{
    if (pendingValid_)
    {
        poisoned_ = true;
    }
}

void RemoteTransfer::resetAfterDisconnect() noexcept
{
    advertisedFormats_.fill(0);
    advertisedCount_ = 0;
    generation_ = 0;
    pending_ = {};
    pendingValid_ = false;
    poisoned_ = false;
}

bool RemoteTransfer::synchronized() const noexcept
{
    return !poisoned_;
}

bool RemoteTransfer::hasOutstandingRequest() const noexcept
{
    return pendingValid_;
}

bool RemoteTransfer::waitingForObsoleteResponse() const noexcept
{
    return pendingValid_ && pending_.generation != generation_;
}

std::uint64_t RemoteTransfer::generation() const noexcept
{
    return generation_;
}

bool RemoteTransfer::advertises(std::uint32_t formatId) const noexcept
{
    return !poisoned_ && formatId != 0 &&
           std::find(advertisedFormats_.begin(),
                     advertisedFormats_.begin() + advertisedCount_,
                     formatId) !=
               advertisedFormats_.begin() + advertisedCount_;
}

} // namespace rdp_server::server::clipboard
