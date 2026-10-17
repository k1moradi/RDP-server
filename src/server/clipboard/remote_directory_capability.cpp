// SPDX-License-Identifier: GPL-3.0-or-later
#include "remote_directory_capability.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#elif defined(__APPLE__) || defined(__linux__)
#include <cerrno>
#include <climits>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

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


#if defined(_WIN32)
namespace
{

[[nodiscard]] HANDLE directoryHandle(
    const RemoteDirectoryNativeToken token) noexcept
{
    return reinterpret_cast<HANDLE>(token);
}

[[nodiscard]] bool duplicateWindowsDirectoryCapability(
    void *, const RemoteDirectoryNativeToken sourceToken,
    RemoteDirectoryNativeToken &duplicateToken) noexcept
{
    duplicateToken = {};
    HANDLE source = directoryHandle(sourceToken);
    if (source == nullptr || source == INVALID_HANDLE_VALUE ||
        ::GetFileType(source) != FILE_TYPE_DISK)
    {
        return false;
    }

    FILE_STANDARD_INFO standard{};
    if (!::GetFileInformationByHandleEx(
            source, FileStandardInfo,
            &standard, sizeof(standard)) ||
        !standard.Directory)
    {
        return false;
    }

    FILE_ATTRIBUTE_TAG_INFO attributes{};
    if (!::GetFileInformationByHandleEx(
            source, FileAttributeTagInfo,
            &attributes, sizeof(attributes)) ||
        (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U)
    {
        return false;
    }

    HANDLE duplicate = nullptr;
    if (!::DuplicateHandle(
            ::GetCurrentProcess(), source,
            ::GetCurrentProcess(), &duplicate,
            0, FALSE, DUPLICATE_SAME_ACCESS) ||
        duplicate == nullptr || duplicate == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    duplicateToken =
        reinterpret_cast<RemoteDirectoryNativeToken>(duplicate);
    return true;
}

void closeWindowsDirectoryCapability(
    void *, const RemoteDirectoryNativeToken token) noexcept
{
    HANDLE handle = directoryHandle(token);
    if (handle != nullptr && handle != INVALID_HANDLE_VALUE)
    {
        (void)::CloseHandle(handle);
    }
}

} // namespace

RemoteDirectoryNativeOperations
makeWindowsRemoteDirectoryNativeOperations() noexcept
{
    return {
        nullptr,
        &duplicateWindowsDirectoryCapability,
        &closeWindowsDirectoryCapability,
    };
}
#elif defined(__APPLE__) || defined(__linux__)
namespace
{

[[nodiscard]] bool posixDescriptor(
    const RemoteDirectoryNativeToken token,
    int &descriptor) noexcept
{
    if (token > static_cast<RemoteDirectoryNativeToken>(INT_MAX))
    {
        return false;
    }
    descriptor = static_cast<int>(token);
    return descriptor >= 0;
}

[[nodiscard]] bool duplicatePosixDirectoryCapability(
    void *, const RemoteDirectoryNativeToken sourceToken,
    RemoteDirectoryNativeToken &duplicateToken) noexcept
{
    duplicateToken = {};
    int source = -1;
    if (!posixDescriptor(sourceToken, source))
    {
        return false;
    }

    struct stat metadata{};
    if (::fstat(source, &metadata) != 0 ||
        !S_ISDIR(metadata.st_mode))
    {
        return false;
    }

    int duplicate = -1;
    do
    {
        duplicate = ::fcntl(source, F_DUPFD_CLOEXEC, 0);
    } while (duplicate < 0 && errno == EINTR);
    if (duplicate < 0)
    {
        return false;
    }

    duplicateToken =
        static_cast<RemoteDirectoryNativeToken>(duplicate);
    return true;
}

void closePosixDirectoryCapability(
    void *, const RemoteDirectoryNativeToken token) noexcept
{
    int descriptor = -1;
    if (posixDescriptor(token, descriptor))
    {
        // POSIX close releases the descriptor even if an implementation
        // reports EINTR. Never retry and risk closing a reused descriptor.
        (void)::close(descriptor);
    }
}

} // namespace

RemoteDirectoryNativeOperations
makePosixRemoteDirectoryNativeOperations() noexcept
{
    return {
        nullptr,
        &duplicatePosixDirectoryCapability,
        &closePosixDirectoryCapability,
    };
}
#endif

} // namespace rdp_server::server::clipboard
