// SPDX-License-Identifier: GPL-3.0-or-later
#include "remote_directory_capability.h"

namespace rdp_server::server::clipboard
{

RemoteDirectoryCapabilityBinding::RemoteDirectoryCapabilityBinding(
    RemoteTransfer &source,
    const RemoteFileDestinationPlan &plan,
    const RemoteDirectoryNativeOperations nativeOperations) noexcept
    : source_(source),
      plan_(plan),
      nativeOperations_(nativeOperations),
      nativeOperationsValid_(operationsValid())
{
    if (!nativeOperationsValid_)
    {
        status_ = Status::Closed;
    }
}

RemoteDirectoryCapabilityBinding::~RemoteDirectoryCapabilityBinding() noexcept
{
    releaseNativeCapability();
}

bool RemoteDirectoryCapabilityBinding::operationsValid() const noexcept
{
    return nativeOperations_.duplicateDirectoryCapability != nullptr &&
           nativeOperations_.closeDirectoryCapability != nullptr;
}

void RemoteDirectoryCapabilityBinding::releaseNativeCapability() noexcept
{
    if (!nativeCapabilityHeld_)
    {
        return;
    }
    nativeOperations_.closeDirectoryCapability(
        nativeOperations_.context, nativeCapability_);
    nativeCapability_ = {};
    nativeCapabilityHeld_ = false;
}

void RemoteDirectoryCapabilityBinding::retire(
    const Status terminalStatus) noexcept
{
    releaseNativeCapability();
    status_ = terminalStatus;
}

bool RemoteDirectoryCapabilityBinding::bind(
    const std::size_t remoteFileIndex,
    const RemoteDirectoryNativeToken callerDirectoryCapability) noexcept
{
    if (!nativeOperationsValid_ || status_ != Status::Idle)
    {
        return false;
    }
    if (!source_.synchronized() || !plan_.current(source_))
    {
        status_ = Status::SourceRetired;
        return false;
    }

    const auto association =
        plan_.association(source_, remoteFileIndex);
    if (!association ||
        association->remoteRole !=
            RemoteFileDestinationPlan::RemoteEntryRole::Directory)
    {
        status_ = Status::AssociationRejected;
        return false;
    }

    RemoteDirectoryNativeToken duplicate{};
    if (!nativeOperations_.duplicateDirectoryCapability(
            nativeOperations_.context,
            callerDirectoryCapability, duplicate))
    {
        status_ = Status::NativeRejected;
        return false;
    }

    nativeCapability_ = duplicate;
    nativeCapabilityHeld_ = true;
    generation_ = source_.generation();
    remoteFileIndex_ = remoteFileIndex;
    localSelectionIdentity_ = association->localSelectionIdentity;
    status_ = Status::Bound;
    return true;
}

bool RemoteDirectoryCapabilityBinding::current() noexcept
{
    if (!bound())
    {
        return false;
    }
    if (!source_.synchronized() ||
        source_.generation() != generation_ ||
        !plan_.current(source_))
    {
        retire(Status::SourceRetired);
        return false;
    }

    const auto association =
        plan_.association(source_, remoteFileIndex_);
    if (!association ||
        association->remoteRole !=
            RemoteFileDestinationPlan::RemoteEntryRole::Directory ||
        association->localSelectionIdentity != localSelectionIdentity_)
    {
        retire(Status::SourceRetired);
        return false;
    }
    return true;
}

void RemoteDirectoryCapabilityBinding::onRemoteGenerationChanged() noexcept
{
    if (bound())
    {
        (void)current();
    }
}

void RemoteDirectoryCapabilityBinding::cancel() noexcept
{
    if (status_ == Status::Cancelled ||
        status_ == Status::Closed)
    {
        return;
    }
    if (status_ == Status::Idle ||
        status_ == Status::Bound)
    {
        releaseNativeCapability();
        status_ = Status::Cancelled;
    }
}

void RemoteDirectoryCapabilityBinding::close() noexcept
{
    if (status_ == Status::Cancelled ||
        status_ == Status::Closed)
    {
        return;
    }
    releaseNativeCapability();
    status_ = Status::Closed;
}

} // namespace rdp_server::server::clipboard
