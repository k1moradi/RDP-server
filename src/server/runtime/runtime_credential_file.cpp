// SPDX-License-Identifier: GPL-3.0-or-later
#include "runtime_credential_file_internal.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <new>
#include <utility>

#include <openssl/crypto.h>

#if defined(_WIN32)
#include <aclapi.h>
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace rdp_server::server::runtime::detail
{
namespace
{

[[nodiscard]] bool isAbsoluteCredentialPath(std::string_view path) noexcept
{
    if (path.empty() || path.size() > 1024U)
        return false;
#if defined(_WIN32)
    if (path.size() < 4U ||
        !((path[0] >= 'A' && path[0] <= 'Z') ||
          (path[0] >= 'a' && path[0] <= 'z')) ||
        path[1] != ':' || (path[2] != '/' && path[2] != '\\'))
        return false;
#else
    if (path.front() != '/')
        return false;
#endif

    std::size_t componentStart = 0U;
    for (std::size_t index = 0U; index <= path.size(); ++index)
    {
        const bool isSeparator = index == path.size() || path[index] == '/'
#if defined(_WIN32)
            || path[index] == '\\'
#endif
            ;
        if (!isSeparator)
            continue;
        const auto component =
            path.substr(componentStart, index - componentStart);
        if (component == "..")
            return false;
        componentStart = index + 1U;
    }
    return true;
}

#if defined(_WIN32)
[[nodiscard]] bool hasRestrictedCredentialDacl(
    HANDLE fileHandle, bool privateKey) noexcept
{
    PSID owner = nullptr;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR rawDescriptor = nullptr;
    if (::GetSecurityInfo(
            fileHandle, SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &owner, nullptr, &dacl, nullptr,
            &rawDescriptor) != ERROR_SUCCESS)
        return false;

    struct DescriptorCloser final
    {
        void operator()(void *pointer) const noexcept
        {
            (void)::LocalFree(pointer);
        }
    };
    std::unique_ptr<void, DescriptorCloser> descriptor{rawDescriptor};
    if (!descriptor || owner == nullptr || !::IsValidSid(owner) ||
        dacl == nullptr || !::IsValidAcl(dacl))
        return false;

    constexpr DWORD unsafeRights =
        FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
        FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER |
        GENERIC_WRITE | GENERIC_ALL;
    for (DWORD index = 0U; index < dacl->AceCount; ++index)
    {
        void *rawAce = nullptr;
        if (!::GetAce(dacl, index, &rawAce) || rawAce == nullptr)
            return false;

        const auto *header = static_cast<const ACE_HEADER *>(rawAce);
        if ((header->AceFlags & INHERIT_ONLY_ACE) != 0)
            continue;
        if (header->AceType == ACCESS_DENIED_ACE_TYPE)
            continue;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE ||
            header->AceSize < sizeof(ACCESS_ALLOWED_ACE))
            return false;

        auto *allow = static_cast<ACCESS_ALLOWED_ACE *>(rawAce);
        PSID principal = &allow->SidStart;
        if (!::IsValidSid(principal))
            return false;

        const bool broadPrincipal =
            ::IsWellKnownSid(principal, WinWorldSid) ||
            ::IsWellKnownSid(principal, WinAuthenticatedUserSid) ||
            ::IsWellKnownSid(principal, WinBuiltinUsersSid) ||
            ::IsWellKnownSid(principal, WinBuiltinGuestsSid) ||
            ::IsWellKnownSid(principal, WinAnonymousSid) ||
            ::IsWellKnownSid(principal, WinInteractiveSid) ||
            ::IsWellKnownSid(principal, WinNetworkSid);
        if (broadPrincipal && (allow->Mask & unsafeRights) != 0)
            return false;

        if (privateKey && !::EqualSid(principal, owner) &&
            !::IsWellKnownSid(principal, WinLocalSystemSid) &&
            !::IsWellKnownSid(principal, WinBuiltinAdministratorsSid))
            return false;
    }
    return true;
}
#else
[[nodiscard]] int openCredentialFileWithoutSymlinkParents(
    std::string_view path) noexcept
{
    if (path.size() < 2U || path.front() != '/')
        return -1;

    int parentDescriptor =
        ::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (parentDescriptor < 0)
        return -1;

    path.remove_prefix(1U);
    while (true)
    {
        const std::size_t separator = path.find('/');
        const std::string_view component = path.substr(0U, separator);
        if (component.empty() || component == "." || component == "..")
        {
            (void)::close(parentDescriptor);
            return -1;
        }

        std::array<char, 1025> terminatedComponent{};
        std::copy(
            component.begin(), component.end(), terminatedComponent.begin());
        const int flags =
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK |
            (separator == std::string_view::npos ? 0 : O_DIRECTORY);
        const int openedDescriptor =
            ::openat(parentDescriptor, terminatedComponent.data(), flags);
        (void)::close(parentDescriptor);
        if (openedDescriptor < 0)
            return -1;
        if (separator == std::string_view::npos)
            return openedDescriptor;

        parentDescriptor = openedDescriptor;
        path.remove_prefix(separator + 1U);
    }
}
#endif

struct FileCloser final
{
    void operator()(std::FILE *file) const noexcept
    {
        (void)std::fclose(file);
    }
};
using OwnedFile = std::unique_ptr<std::FILE, FileCloser>;

struct RuntimeCredentialFileIdentity final
{
#if defined(_WIN32)
    DWORD volume{};
    DWORD indexHigh{};
    DWORD indexLow{};
#else
    dev_t device{};
    ino_t inode{};
#endif
};

[[nodiscard]] bool sameCredentialFileIdentity(
    const RuntimeCredentialFileIdentity &left,
    const RuntimeCredentialFileIdentity &right) noexcept
{
#if defined(_WIN32)
    return left.volume == right.volume &&
           left.indexHigh == right.indexHigh &&
           left.indexLow == right.indexLow;
#else
    return left.device == right.device && left.inode == right.inode;
#endif
}

[[nodiscard]] OwnedFile openCredentialFile(
    std::string_view path,
    bool privateKey,
    std::size_t maximumBytes,
    RuntimeCredentialFileIdentity &identity,
    std::size_t &openedBytes) noexcept
{
    openedBytes = 0U;
    if (maximumBytes == 0U || !isAbsoluteCredentialPath(path))
        return {};

#if defined(_WIN32)
    std::array<char, 1025> terminatedPath{};
    std::copy(path.begin(), path.end(), terminatedPath.begin());
    const HANDLE handle = ::CreateFileA(
        terminatedPath.data(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE)
        return {};

    FILE_ATTRIBUTE_TAG_INFO attributes{};
    BY_HANDLE_FILE_INFORMATION information{};
    const bool haveAttributes = ::GetFileInformationByHandleEx(
        handle, FileAttributeTagInfo, &attributes, sizeof(attributes)) != FALSE;
    const bool haveInformation =
        ::GetFileInformationByHandle(handle, &information) != FALSE;
    const std::uint64_t fileBytes = haveInformation
        ? ((static_cast<std::uint64_t>(information.nFileSizeHigh) << 32U) |
           information.nFileSizeLow)
        : 0U;
    const bool safe =
        ::GetFileType(handle) == FILE_TYPE_DISK &&
        haveAttributes &&
        (attributes.FileAttributes &
         (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0 &&
        haveInformation &&
        fileBytes > 0U &&
        fileBytes <= maximumBytes &&
        hasRestrictedCredentialDacl(handle, privateKey);
    if (!safe)
    {
        (void)::CloseHandle(handle);
        return {};
    }

    identity.volume = information.dwVolumeSerialNumber;
    identity.indexHigh = information.nFileIndexHigh;
    identity.indexLow = information.nFileIndexLow;
    openedBytes = static_cast<std::size_t>(fileBytes);

    const int descriptor = ::_open_osfhandle(
        reinterpret_cast<std::intptr_t>(handle), _O_RDONLY | _O_BINARY);
    if (descriptor < 0)
    {
        (void)::CloseHandle(handle);
        openedBytes = 0U;
        return {};
    }

    OwnedFile file{::_fdopen(descriptor, "rb")};
    if (!file)
    {
        (void)::_close(descriptor);
        openedBytes = 0U;
        return {};
    }
    return file;
#else
    if (maximumBytes >
        static_cast<std::size_t>(std::numeric_limits<off_t>::max()))
        return {};

    const int descriptor = openCredentialFileWithoutSymlinkParents(path);
    if (descriptor < 0)
        return {};

    struct stat information {};
    const bool safe =
        ::fstat(descriptor, &information) == 0 &&
        S_ISREG(information.st_mode) &&
        information.st_size > 0 &&
        information.st_size <= static_cast<off_t>(maximumBytes) &&
        (information.st_mode & (S_IWGRP | S_IWOTH)) == 0 &&
        (!privateKey ||
         (information.st_uid == ::geteuid() &&
          (information.st_mode & (S_IRWXG | S_IRWXO)) == 0 &&
          (information.st_mode & S_IRUSR) != 0));
    if (!safe)
    {
        (void)::close(descriptor);
        return {};
    }

    identity.device = information.st_dev;
    identity.inode = information.st_ino;
    openedBytes = static_cast<std::size_t>(information.st_size);

    OwnedFile file{::fdopen(descriptor, "rb")};
    if (!file)
    {
        (void)::close(descriptor);
        openedBytes = 0U;
        return {};
    }
    return file;
#endif
}

[[nodiscard]] bool readOpenedFileExactly(
    std::FILE *file,
    std::size_t bytes,
    bool sensitive,
    std::unique_ptr<std::uint8_t[]> &output) noexcept
{
    if (file == nullptr || bytes == 0U)
        return false;

    std::unique_ptr<std::uint8_t[]> buffer{
        new (std::nothrow) std::uint8_t[bytes]};
    if (!buffer)
        return false;

    const bool success =
        std::fread(buffer.get(), 1U, bytes, file) == bytes &&
        std::ferror(file) == 0 &&
        std::fgetc(file) == EOF;
    if (!success)
    {
        if (sensitive)
            ::OPENSSL_cleanse(buffer.get(), bytes);
        return false;
    }

    output = std::move(buffer);
    return true;
}

} // namespace

RuntimeCredentialFilePairSnapshot::~RuntimeCredentialFilePairSnapshot()
{
    clear();
}

RuntimeCredentialFilePairSnapshot::RuntimeCredentialFilePairSnapshot(
    RuntimeCredentialFilePairSnapshot &&other) noexcept
{
    *this = std::move(other);
}

RuntimeCredentialFilePairSnapshot &
RuntimeCredentialFilePairSnapshot::operator=(
    RuntimeCredentialFilePairSnapshot &&other) noexcept
{
    if (this == &other)
        return *this;

    clear();
    publicBytes_ = std::move(other.publicBytes_);
    privateKeyBytes_ = std::move(other.privateKeyBytes_);
    publicSize_ = other.publicSize_;
    privateKeySize_ = other.privateKeySize_;
    other.publicSize_ = 0U;
    other.privateKeySize_ = 0U;
    return *this;
}

RuntimeCredentialFilePairSnapshot::operator bool() const noexcept
{
    return publicBytes_ != nullptr &&
           privateKeyBytes_ != nullptr &&
           publicSize_ != 0U &&
           privateKeySize_ != 0U;
}

std::span<const std::uint8_t>
RuntimeCredentialFilePairSnapshot::publicBytes() const noexcept
{
    return *this
        ? std::span<const std::uint8_t>{publicBytes_.get(), publicSize_}
        : std::span<const std::uint8_t>{};
}

std::span<const std::uint8_t>
RuntimeCredentialFilePairSnapshot::privateKeyBytes() const noexcept
{
    return *this
        ? std::span<const std::uint8_t>{
              privateKeyBytes_.get(), privateKeySize_}
        : std::span<const std::uint8_t>{};
}

void RuntimeCredentialFilePairSnapshot::clear() noexcept
{
    if (privateKeyBytes_ != nullptr && privateKeySize_ != 0U)
        ::OPENSSL_cleanse(privateKeyBytes_.get(), privateKeySize_);
    privateKeyBytes_.reset();
    publicBytes_.reset();
    privateKeySize_ = 0U;
    publicSize_ = 0U;
}

RuntimeCredentialFilePairSnapshot loadSecureRuntimeCredentialFilePair(
    std::string_view publicPath,
    std::string_view privateKeyPath,
    std::size_t maximumPublicBytes,
    std::size_t maximumPrivateKeyBytes) noexcept
{
    RuntimeCredentialFileIdentity publicIdentity{};
    RuntimeCredentialFileIdentity privateIdentity{};
    std::size_t publicBytes = 0U;
    std::size_t privateBytes = 0U;

    OwnedFile publicFile = openCredentialFile(
        publicPath, false, maximumPublicBytes, publicIdentity, publicBytes);
    OwnedFile privateFile = openCredentialFile(
        privateKeyPath, true, maximumPrivateKeyBytes,
        privateIdentity, privateBytes);
    if (!publicFile || !privateFile ||
        sameCredentialFileIdentity(publicIdentity, privateIdentity))
        return {};

    RuntimeCredentialFilePairSnapshot snapshot;
    if (!readOpenedFileExactly(
            publicFile.get(), publicBytes, false, snapshot.publicBytes_) ||
        !readOpenedFileExactly(
            privateFile.get(), privateBytes, true, snapshot.privateKeyBytes_))
        return {};

    snapshot.publicSize_ = publicBytes;
    snapshot.privateKeySize_ = privateBytes;
    return snapshot;
}

bool validateSecureRuntimeCredentialFilePairReferences(
    std::string_view publicPath,
    std::string_view privateKeyPath,
    std::size_t maximumPublicBytes,
    std::size_t maximumPrivateKeyBytes) noexcept
{
    RuntimeCredentialFileIdentity publicIdentity{};
    RuntimeCredentialFileIdentity privateIdentity{};
    std::size_t publicBytes = 0U;
    std::size_t privateBytes = 0U;

    OwnedFile publicFile = openCredentialFile(
        publicPath, false, maximumPublicBytes, publicIdentity, publicBytes);
    OwnedFile privateFile = openCredentialFile(
        privateKeyPath, true, maximumPrivateKeyBytes,
        privateIdentity, privateBytes);
    return publicFile && privateFile &&
           publicBytes != 0U && privateBytes != 0U &&
           !sameCredentialFileIdentity(publicIdentity, privateIdentity);
}

} // namespace rdp_server::server::runtime::detail
