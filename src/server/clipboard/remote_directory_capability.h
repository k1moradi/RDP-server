// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "clipboard/remote_transfer.h"

#include <cstddef>
#include <cstdint>

namespace rdp_server::server::clipboard
{

// Opaque platform token for one caller-authorized, already-open directory
// capability. The numeric value has no authority until platform operations
// validate and duplicate it.
using RemoteDirectoryNativeToken = std::uintptr_t;

struct RemoteDirectoryNativeOperations final
{
    void *context{};
    // Duplicate one already-authorized directory capability into an
    // independently owned token. This operation MUST inspect the native object
    // itself; it must not reopen a pathname or derive one from remote metadata.
    bool (*duplicateDirectoryCapability)(
        void *, RemoteDirectoryNativeToken,
        RemoteDirectoryNativeToken &) noexcept{};
    void (*closeDirectoryCapability)(
        void *, RemoteDirectoryNativeToken) noexcept{};
};

// One-shot binding between a current planned remote directory association and
// a separately supplied native directory capability.
//
// This object does NOT create directories/files, expose a relative child-name
// API, or infer hierarchy from FILEDESCRIPTORW. It is the ownership/lifetime
// boundary required before any future handle-relative creation policy can be
// reviewed. The bound RemoteTransfer and RemoteFileDestinationPlan must outlive
// this object. All methods are event-loop/thread confined.
class RemoteDirectoryCapabilityBinding final
{
public:
    enum class Status : std::uint8_t
    {
        Idle,
        Bound,
        Cancelled,
        Closed,
        SourceRetired,
        AssociationRejected,
        NativeRejected,
    };

    RemoteDirectoryCapabilityBinding(
        RemoteTransfer &source,
        const RemoteFileDestinationPlan &plan,
        RemoteDirectoryNativeOperations nativeOperations) noexcept;
    ~RemoteDirectoryCapabilityBinding() noexcept;

    RemoteDirectoryCapabilityBinding(
        const RemoteDirectoryCapabilityBinding &) = delete;
    RemoteDirectoryCapabilityBinding &operator=(
        const RemoteDirectoryCapabilityBinding &) = delete;
    RemoteDirectoryCapabilityBinding(
        RemoteDirectoryCapabilityBinding &&) = delete;
    RemoteDirectoryCapabilityBinding &operator=(
        RemoteDirectoryCapabilityBinding &&) = delete;

    // Bind exactly one current Directory association to an independently
    // duplicated caller capability. localSelectionIdentity is metadata only
    // and is never interpreted as a native token by this class.
    [[nodiscard]] bool bind(
        std::size_t remoteFileIndex,
        RemoteDirectoryNativeToken callerDirectoryCapability) noexcept;

    // Revalidate the exact source generation and association. A stale source,
    // cancelled plan, or changed association terminally releases the duplicate.
    [[nodiscard]] bool current() noexcept;
    void onRemoteGenerationChanged() noexcept;

    // Terminal and idempotent. close() preserves an already-cancelled state.
    void cancel() noexcept;
    void close() noexcept;

    [[nodiscard]] bool valid() const noexcept
    {
        return nativeOperationsValid_;
    }
    [[nodiscard]] bool bound() const noexcept
    {
        return status_ == Status::Bound && nativeCapabilityHeld_;
    }
    [[nodiscard]] Status status() const noexcept
    {
        return status_;
    }
    [[nodiscard]] std::uint64_t generation() const noexcept
    {
        return generation_;
    }
    [[nodiscard]] std::size_t remoteFileIndex() const noexcept
    {
        return remoteFileIndex_;
    }
    [[nodiscard]] std::uint64_t localSelectionIdentity() const noexcept
    {
        return localSelectionIdentity_;
    }

private:
    [[nodiscard]] bool operationsValid() const noexcept;
    void releaseNativeCapability() noexcept;
    void retire(Status terminalStatus) noexcept;

    RemoteTransfer &source_;
    const RemoteFileDestinationPlan &plan_;
    RemoteDirectoryNativeOperations nativeOperations_{};
    RemoteDirectoryNativeToken nativeCapability_{};
    std::uint64_t generation_{};
    std::uint64_t localSelectionIdentity_{};
    std::size_t remoteFileIndex_{};
    Status status_{Status::Idle};
    bool nativeOperationsValid_{};
    bool nativeCapabilityHeld_{};
};

} // namespace rdp_server::server::clipboard
