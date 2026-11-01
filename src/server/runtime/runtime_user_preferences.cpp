// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/runtime_user_preferences_internal.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <limits>
#include <memory>
#include <string_view>
#include <utility>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#include <shlobj.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace rdp_server::server::runtime
{
namespace
{

constexpr std::array<char, 8> kMagic{'R', 'D', 'P', 'U', 'P', 'R', 'E', 'F'};
constexpr std::size_t kHeaderBytes{17U};
constexpr std::size_t kMaximumUsernameBytes{256U};
constexpr std::size_t kMaximumInterfaceBytes{128U};
constexpr std::size_t kMaximumRecordBytes{
    kHeaderBytes + kMaximumUsernameBytes + kMaximumInterfaceBytes};
std::atomic<std::uint64_t> nextTemporaryNumber{1U};

[[nodiscard]] constexpr unsigned octet(const std::byte value) noexcept
{
    return std::to_integer<unsigned>(value);
}

[[nodiscard]] bool validUtf8Username(std::string_view text) noexcept
{
    if (text.size() > kMaximumUsernameBytes)
        return false;
    for (std::size_t index = 0U; index < text.size();)
    {
        const auto first = static_cast<unsigned char>(text[index]);
        unsigned codePoint = 0U;
        unsigned remaining = 0U;
        if (first < 0x80U)
            codePoint = first;
        else if (first >= 0xc2U && first <= 0xdfU)
        {
            codePoint = first & 0x1fU;
            remaining = 1U;
        }
        else if (first >= 0xe0U && first <= 0xefU)
        {
            codePoint = first & 0x0fU;
            remaining = 2U;
        }
        else if (first >= 0xf0U && first <= 0xf4U)
        {
            codePoint = first & 0x07U;
            remaining = 3U;
        }
        else
            return false;
        if (remaining > text.size() - index - 1U)
            return false;
        for (unsigned continuation = 0U; continuation < remaining;
             ++continuation)
        {
            const auto next = static_cast<unsigned char>(
                text[index + 1U + continuation]);
            if ((next & 0xc0U) != 0x80U)
                return false;
            codePoint = (codePoint << 6U) | (next & 0x3fU);
        }
        if ((remaining == 1U && codePoint < 0x80U) ||
            (remaining == 2U && codePoint < 0x800U) ||
            (remaining == 3U && codePoint < 0x10000U) ||
            codePoint > 0x10ffffU ||
            (codePoint >= 0xd800U && codePoint <= 0xdfffU) ||
            codePoint < 0x20U ||
            (codePoint >= 0x7fU && codePoint <= 0x9fU) ||
            codePoint == '/' || codePoint == '\\')
            return false;
        index += remaining + 1U;
    }
    return true;
}

[[nodiscard]] bool validInterfaceId(std::string_view text) noexcept
{
    if (text.size() > kMaximumInterfaceBytes)
        return false;
    for (const unsigned char character : text)
    {
        const bool alphanumeric =
            (character >= 'a' && character <= 'z') ||
            (character >= 'A' && character <= 'Z') ||
            (character >= '0' && character <= '9');
        if (!alphanumeric && character != '-' && character != '_' &&
            character != '.' && character != ':' &&
            character != '{' && character != '}')
            return false;
    }
    return true;
}

[[nodiscard]] bool validPreferences(
    const RuntimeUserPreferences& preferences) noexcept
{
    return validUtf8Username(preferences.lastExplicitUsername) &&
           validInterfaceId(preferences.preferredStableLanInterfaceId) &&
           preferences.port != 0U &&
           preferences.permissionLifetimeMinutes >= 1U &&
           preferences.permissionLifetimeMinutes <= 60U;
}

#if !defined(_WIN32)
class FileDescriptor final
{
public:
    explicit FileDescriptor(int descriptor = -1) noexcept
        : descriptor_(descriptor) {}
    ~FileDescriptor()
    {
        if (descriptor_ >= 0)
            (void)::close(descriptor_);
    }
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    FileDescriptor(FileDescriptor&& other) noexcept
        : descriptor_(std::exchange(other.descriptor_, -1)) {}
    FileDescriptor& operator=(FileDescriptor&& other) noexcept
    {
        if (this != &other)
        {
            if (descriptor_ >= 0)
                (void)::close(descriptor_);
            descriptor_ = std::exchange(other.descriptor_, -1);
        }
        return *this;
    }
    [[nodiscard]] int get() const noexcept { return descriptor_; }
    [[nodiscard]] explicit operator bool() const noexcept
    {
        return descriptor_ >= 0;
    }

private:
    int descriptor_{-1};
};

[[nodiscard]] bool privateObject(
    int descriptor, bool directory, bool exactPrivateMode) noexcept
{
    struct stat metadata{};
    if (::fstat(descriptor, &metadata) != 0 ||
        metadata.st_uid != ::geteuid() ||
        (directory ? !S_ISDIR(metadata.st_mode) :
                     !S_ISREG(metadata.st_mode)))
        return false;

    const mode_t permissionBits = metadata.st_mode & 07777;
    if (exactPrivateMode)
    {
        const mode_t requiredMode = directory ? 0700 : 0600;
        if (permissionBits != requiredMode)
            return false;
    }
    else if ((permissionBits & 0022) != 0)
    {
        return false;
    }
    return directory || metadata.st_nlink == 1;
}

[[nodiscard]] FileDescriptor openDirectoryChild(
    int parent, const char* name, bool create,
    bool exactPrivateMode) noexcept
{
    if (create && ::mkdirat(parent, name, 0700) != 0 && errno != EEXIST)
        return FileDescriptor{};
    FileDescriptor child{
        ::openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
    if (child && privateObject(child.get(), true, exactPrivateMode))
        return child;
    if (child)
        errno = EPERM;
    return FileDescriptor{};
}

[[nodiscard]] RuntimeUserPreferencesStorageStatus openNativeDirectory(
    FileDescriptor& directory, bool create) noexcept
{
    std::array<char, 16384> recordBytes{};
    passwd account{};
    passwd* accountResult = nullptr;
    if (::getpwuid_r(::geteuid(), &account, recordBytes.data(),
                     recordBytes.size(), &accountResult) != 0 ||
        accountResult != &account || account.pw_dir == nullptr ||
        account.pw_dir[0] != '/')
        return RuntimeUserPreferencesStorageStatus::Unavailable;
    FileDescriptor home{
        ::open(account.pw_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
    if (!home || !privateObject(home.get(), true, false))
        return RuntimeUserPreferencesStorageStatus::Unavailable;

#if defined(__APPLE__)
    auto first = openDirectoryChild(home.get(), "Library", create, false);
    if (!first)
        return create ? RuntimeUserPreferencesStorageStatus::Unavailable
                      : (errno == ENOENT ? RuntimeUserPreferencesStorageStatus::Missing
                                         : RuntimeUserPreferencesStorageStatus::Invalid);
    auto second = openDirectoryChild(
        first.get(), "Application Support", create, false);
#else
    auto second = openDirectoryChild(home.get(), ".config", create, false);
#endif
    if (!second)
        return create ? RuntimeUserPreferencesStorageStatus::Unavailable
                      : RuntimeUserPreferencesStorageStatus::Missing;
    directory = openDirectoryChild(
        second.get(), "rdp-server", create, true);
    return directory ? RuntimeUserPreferencesStorageStatus::Loaded
                     : (create ? RuntimeUserPreferencesStorageStatus::Unavailable
                               : (errno == ENOENT ? RuntimeUserPreferencesStorageStatus::Missing
                                                  : RuntimeUserPreferencesStorageStatus::Invalid));
}

[[nodiscard]] RuntimeUserPreferencesStorageStatus loadFromNativeDirectory(
    int directory, RuntimeUserPreferences& preferences)
{
    FileDescriptor file{::openat(
        directory, "preferences.bin", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)};
    if (!file)
        return errno == ENOENT
            ? RuntimeUserPreferencesStorageStatus::Missing
            : RuntimeUserPreferencesStorageStatus::Invalid;
    if (!privateObject(file.get(), false, true))
        return RuntimeUserPreferencesStorageStatus::Invalid;

    std::array<std::byte, kMaximumRecordBytes + 1U> data{};
    std::size_t length = 0U;
    while (length < data.size())
    {
        const ssize_t received = ::read(
            file.get(), data.data() + length, data.size() - length);
        if (received == 0)
            break;
        if (received < 0)
        {
            if (errno == EINTR)
                continue;
            return RuntimeUserPreferencesStorageStatus::Unavailable;
        }
        length += static_cast<std::size_t>(received);
    }
    if (length > kMaximumRecordBytes ||
        !decodeRuntimeUserPreferences(std::span{data}.first(length), preferences))
        return RuntimeUserPreferencesStorageStatus::Invalid;
    return RuntimeUserPreferencesStorageStatus::Loaded;
}

[[nodiscard]] RuntimeUserPreferencesStorageStatus saveToNativeDirectory(
    int directory, const RuntimeUserPreferences& preferences)
{
    FileDescriptor existing{::openat(
        directory, "preferences.bin", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)};
    if (existing)
    {
        if (!privateObject(existing.get(), false, true))
            return RuntimeUserPreferencesStorageStatus::Invalid;
    }
    else if (errno != ENOENT)
        return RuntimeUserPreferencesStorageStatus::Invalid;

    std::vector<std::byte> encoded;
    if (!encodeRuntimeUserPreferences(preferences, encoded))
        return RuntimeUserPreferencesStorageStatus::Invalid;
    for (unsigned attempt = 0U; attempt < 8U; ++attempt)
    {
        const std::string temporaryName =
            ".preferences-" + std::to_string(::getpid()) + "-" +
            std::to_string(nextTemporaryNumber.fetch_add(1U));
        FileDescriptor temporary{::openat(
            directory, temporaryName.c_str(),
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600)};
        if (!temporary)
        {
            if (errno == EEXIST)
                continue;
            return RuntimeUserPreferencesStorageStatus::Unavailable;
        }
        // openat() applies umask to creation mode; normalize only this new
        // object, then revalidate exact owner/type/mode before publication.
        if (::fchmod(temporary.get(), 0600) != 0 ||
            !privateObject(temporary.get(), false, true))
        {
            (void)::unlinkat(directory, temporaryName.c_str(), 0);
            return RuntimeUserPreferencesStorageStatus::Unavailable;
        }
        std::size_t offset = 0U;
        bool written = true;
        while (offset < encoded.size())
        {
            const ssize_t count = ::write(
                temporary.get(), encoded.data() + offset,
                encoded.size() - offset);
            if (count < 0 && errno == EINTR)
                continue;
            if (count <= 0)
            {
                written = false;
                break;
            }
            offset += static_cast<std::size_t>(count);
        }
        if (!written || ::fsync(temporary.get()) != 0 ||
            ::renameat(directory, temporaryName.c_str(), directory,
                       "preferences.bin") != 0)
        {
            (void)::unlinkat(directory, temporaryName.c_str(), 0);
            return RuntimeUserPreferencesStorageStatus::Unavailable;
        }
        if (::fsync(directory) != 0)
            return RuntimeUserPreferencesStorageStatus::Unavailable;
        return RuntimeUserPreferencesStorageStatus::Stored;
    }
    return RuntimeUserPreferencesStorageStatus::Unavailable;
}

#else

class NativeHandle final
{
public:
    explicit NativeHandle(HANDLE value = INVALID_HANDLE_VALUE) noexcept
        : value_(value) {}
    ~NativeHandle()
    {
        if (value_ != INVALID_HANDLE_VALUE && value_ != nullptr)
            (void)::CloseHandle(value_);
    }
    NativeHandle(const NativeHandle&) = delete;
    NativeHandle& operator=(const NativeHandle&) = delete;
    NativeHandle(NativeHandle&& other) noexcept
        : value_(std::exchange(other.value_, INVALID_HANDLE_VALUE)) {}
    NativeHandle& operator=(NativeHandle&& other) noexcept
    {
        if (this != &other)
        {
            if (value_ != INVALID_HANDLE_VALUE && value_ != nullptr)
                (void)::CloseHandle(value_);
            value_ = std::exchange(other.value_, INVALID_HANDLE_VALUE);
        }
        return *this;
    }
    [[nodiscard]] HANDLE get() const noexcept { return value_; }
    [[nodiscard]] explicit operator bool() const noexcept
    {
        return value_ != INVALID_HANDLE_VALUE && value_ != nullptr;
    }

private:
    HANDLE value_{INVALID_HANDLE_VALUE};
};

struct LocalMemoryCloser final
{
    void operator()(void* pointer) const noexcept
    {
        if (pointer != nullptr)
            (void)::LocalFree(pointer);
    }
};

[[nodiscard]] bool currentUserSid(std::vector<std::byte>& storage,
                                   PSID& sid)
{
    NativeHandle token;
    HANDLE rawToken = INVALID_HANDLE_VALUE;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &rawToken))
        return false;
    token = NativeHandle{rawToken};
    DWORD required = 0U;
    (void)::GetTokenInformation(token.get(), TokenUser, nullptr, 0U, &required);
    if (required < sizeof(TOKEN_USER) || required > 16384U)
        return false;
    storage.resize(required);
    if (!::GetTokenInformation(token.get(), TokenUser, storage.data(),
                               required, &required))
        return false;
    sid = reinterpret_cast<TOKEN_USER*>(storage.data())->User.Sid;
    return sid != nullptr && ::IsValidSid(sid);
}

[[nodiscard]] bool restrictiveSecurity(
    PSID sid, SECURITY_DESCRIPTOR& descriptor, std::vector<std::byte>& aclStorage,
    SECURITY_ATTRIBUTES& attributes)
{
    const DWORD aclBytes = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) -
                           sizeof(DWORD) + ::GetLengthSid(sid);
    aclStorage.resize(aclBytes);
    auto* acl = reinterpret_cast<PACL>(aclStorage.data());
    if (!::InitializeAcl(acl, aclBytes, ACL_REVISION) ||
        !::AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, sid) ||
        !::InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
        !::SetSecurityDescriptorOwner(&descriptor, sid, FALSE) ||
        !::SetSecurityDescriptorDacl(&descriptor, TRUE, acl, FALSE) ||
        !::SetSecurityDescriptorControl(
            &descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED))
        return false;
    attributes = SECURITY_ATTRIBUTES{
        sizeof(SECURITY_ATTRIBUTES), &descriptor, FALSE};
    return true;
}

[[nodiscard]] bool isPrivateWindowsObject(
    HANDLE handle, PSID expectedOwner, bool directory) noexcept
{
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    if (::GetFileType(handle) != FILE_TYPE_DISK ||
        !::GetFileInformationByHandleEx(
            handle, FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
        (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U ||
        ((attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U) != directory)
        return false;

    PSID owner = nullptr;
    PACL acl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (::GetSecurityInfo(
            handle, SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &owner, nullptr, &acl, nullptr, &descriptor) != ERROR_SUCCESS)
        return false;
    std::unique_ptr<void, LocalMemoryCloser> descriptorOwner{descriptor};
    SECURITY_DESCRIPTOR_CONTROL descriptorControl{};
    DWORD descriptorRevision = 0U;
    if (!descriptorOwner ||
        !::GetSecurityDescriptorControl(
            descriptor, &descriptorControl, &descriptorRevision) ||
        (descriptorControl & SE_DACL_PROTECTED) == 0U ||
        !::IsValidSid(owner) || !::EqualSid(owner, expectedOwner) ||
        acl == nullptr || !::IsValidAcl(acl) || acl->AceCount == 0U)
        return false;
    for (DWORD index = 0U; index < acl->AceCount; ++index)
    {
        void* rawAce = nullptr;
        if (!::GetAce(acl, index, &rawAce) || rawAce == nullptr)
            return false;
        const auto* header = static_cast<const ACE_HEADER*>(rawAce);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE ||
            header->AceSize < sizeof(ACCESS_ALLOWED_ACE) ||
            (header->AceFlags & INHERITED_ACE) != 0U ||
            !::EqualSid(
                &static_cast<ACCESS_ALLOWED_ACE*>(rawAce)->SidStart,
                expectedOwner))
            return false;
    }
    return true;
}

[[nodiscard]] RuntimeUserPreferencesStorageStatus loadFromWindowsDirectory(
    const std::filesystem::path& directory,
    PSID sid, RuntimeUserPreferences& preferences)
{
    const auto filename = directory / L"preferences.bin";
    NativeHandle file{::CreateFileW(
        filename.c_str(), GENERIC_READ | READ_CONTROL, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
    if (!file)
        return ::GetLastError() == ERROR_FILE_NOT_FOUND
            ? RuntimeUserPreferencesStorageStatus::Missing
            : RuntimeUserPreferencesStorageStatus::Invalid;
    if (!isPrivateWindowsObject(file.get(), sid, false))
        return RuntimeUserPreferencesStorageStatus::Invalid;
    LARGE_INTEGER length{};
    if (!::GetFileSizeEx(file.get(), &length) || length.QuadPart <= 0 ||
        length.QuadPart > static_cast<LONGLONG>(kMaximumRecordBytes))
        return RuntimeUserPreferencesStorageStatus::Invalid;
    std::array<std::byte, kMaximumRecordBytes> data{};
    DWORD received = 0U;
    if (!::ReadFile(file.get(), data.data(), static_cast<DWORD>(length.QuadPart),
                    &received, nullptr) ||
        received != static_cast<DWORD>(length.QuadPart) ||
        !decodeRuntimeUserPreferences(
            std::span{data}.first(received), preferences))
        return RuntimeUserPreferencesStorageStatus::Invalid;
    return RuntimeUserPreferencesStorageStatus::Loaded;
}

[[nodiscard]] RuntimeUserPreferencesStorageStatus saveToWindowsDirectory(
    const std::filesystem::path& directory, PSID sid,
    const RuntimeUserPreferences& preferences)
{
    const auto target = directory / L"preferences.bin";
    NativeHandle existing{::CreateFileW(
        target.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
    if (existing)
    {
        if (!isPrivateWindowsObject(existing.get(), sid, false))
            return RuntimeUserPreferencesStorageStatus::Invalid;
    }
    else if (::GetLastError() != ERROR_FILE_NOT_FOUND)
        return RuntimeUserPreferencesStorageStatus::Invalid;
    // Do not hold a shared read handle across the atomic replacement.
    existing = NativeHandle{};

    std::vector<std::byte> encoded;
    if (!encodeRuntimeUserPreferences(preferences, encoded))
        return RuntimeUserPreferencesStorageStatus::Invalid;
    SECURITY_DESCRIPTOR descriptor{};
    std::vector<std::byte> aclStorage;
    SECURITY_ATTRIBUTES attributes{};
    if (!restrictiveSecurity(sid, descriptor, aclStorage, attributes))
        return RuntimeUserPreferencesStorageStatus::Unavailable;
    for (unsigned attempt = 0U; attempt < 8U; ++attempt)
    {
        const std::wstring temporaryName = L"preferences-" +
            std::to_wstring(::GetCurrentProcessId()) + L"-" +
            std::to_wstring(nextTemporaryNumber.fetch_add(1U)) + L".tmp";
        const auto temporaryPath = directory / temporaryName;
        NativeHandle temporary{::CreateFileW(
            temporaryPath.c_str(), GENERIC_WRITE | READ_CONTROL, 0U,
            &attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr)};
        if (!temporary)
        {
            if (::GetLastError() == ERROR_FILE_EXISTS)
                continue;
            return RuntimeUserPreferencesStorageStatus::Unavailable;
        }
        DWORD written = 0U;
        const bool complete =
            isPrivateWindowsObject(temporary.get(), sid, false) &&
            ::WriteFile(temporary.get(), encoded.data(),
                        static_cast<DWORD>(encoded.size()), &written, nullptr) &&
            written == encoded.size() &&
            ::FlushFileBuffers(temporary.get()) != 0;
        temporary = NativeHandle{};
        if (!complete || !::MoveFileExW(
                temporaryPath.c_str(), target.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            (void)::DeleteFileW(temporaryPath.c_str());
            return RuntimeUserPreferencesStorageStatus::Unavailable;
        }
        return RuntimeUserPreferencesStorageStatus::Stored;
    }
    return RuntimeUserPreferencesStorageStatus::Unavailable;
}

[[nodiscard]] RuntimeUserPreferencesStorageStatus openNativeDirectory(
    std::filesystem::path& directory, bool create)
{
    PWSTR rawPath = nullptr;
    if (FAILED(::SHGetKnownFolderPath(
            FOLDERID_LocalAppData, KF_FLAG_DEFAULT, nullptr, &rawPath)) ||
        rawPath == nullptr)
        return RuntimeUserPreferencesStorageStatus::Unavailable;
    const std::filesystem::path root{rawPath};
    ::CoTaskMemFree(rawPath);
    directory = root / L"RDP-server";
    std::vector<std::byte> userStorage;
    PSID userSid = nullptr;
    if (!currentUserSid(userStorage, userSid))
        return RuntimeUserPreferencesStorageStatus::Unavailable;
    SECURITY_DESCRIPTOR descriptor{};
    std::vector<std::byte> aclStorage;
    SECURITY_ATTRIBUTES attributes{};
    if (!restrictiveSecurity(userSid, descriptor, aclStorage, attributes))
        return RuntimeUserPreferencesStorageStatus::Unavailable;
    if (create && !::CreateDirectoryW(directory.c_str(), &attributes) &&
        ::GetLastError() != ERROR_ALREADY_EXISTS)
        return RuntimeUserPreferencesStorageStatus::Unavailable;
    NativeHandle opened{::CreateFileW(
        directory.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
    if (!opened)
        return create ? RuntimeUserPreferencesStorageStatus::Unavailable
                      : RuntimeUserPreferencesStorageStatus::Missing;
    return isPrivateWindowsObject(opened.get(), userSid, true)
        ? RuntimeUserPreferencesStorageStatus::Loaded
        : RuntimeUserPreferencesStorageStatus::Invalid;
}

#endif

} // namespace

bool encodeRuntimeUserPreferences(
    const RuntimeUserPreferences& preferences,
    std::vector<std::byte>& encoded)
{
    if (!validPreferences(preferences))
        return false;

    const std::size_t usernameBytes = preferences.lastExplicitUsername.size();
    const std::size_t interfaceBytes =
        preferences.preferredStableLanInterfaceId.size();
    const std::size_t encodedBytes =
        kHeaderBytes + usernameBytes + interfaceBytes;
    std::vector<std::byte> result(encodedBytes);

    std::size_t offset = 0U;
    for (const char character : kMagic)
        result[offset++] = static_cast<std::byte>(
            static_cast<unsigned char>(character));
    result[offset++] = std::byte{1U};
    result[offset++] =
        preferences.preferRemoteInput ? std::byte{1U} : std::byte{0U};
    result[offset++] = static_cast<std::byte>(preferences.port & 0xffU);
    result[offset++] = static_cast<std::byte>(preferences.port >> 8U);
    result[offset++] =
        static_cast<std::byte>(preferences.permissionLifetimeMinutes);
    const auto appendLength =
        [&result, &offset](const std::size_t size) noexcept {
            result[offset++] = static_cast<std::byte>(size & 0xffU);
            result[offset++] =
                static_cast<std::byte>((size >> 8U) & 0xffU);
        };
    appendLength(usernameBytes);
    appendLength(interfaceBytes);

    for (const unsigned char character : preferences.lastExplicitUsername)
        result[offset++] = static_cast<std::byte>(character);
    for (const unsigned char character :
         preferences.preferredStableLanInterfaceId)
        result[offset++] = static_cast<std::byte>(character);

    if (offset != encodedBytes)
        return false;
    encoded = std::move(result);
    return true;
}

bool decodeRuntimeUserPreferences(
    std::span<const std::byte> encoded,
    RuntimeUserPreferences& preferences)
{
    if (encoded.size() < kHeaderBytes || encoded.size() > kMaximumRecordBytes)
        return false;
    for (std::size_t index = 0U; index < kMagic.size(); ++index)
    {
        if (octet(encoded[index]) !=
            static_cast<unsigned char>(kMagic[index]))
            return false;
    }
    if (octet(encoded[8]) != 1U || octet(encoded[9]) > 1U)
        return false;
    const auto port = octet(encoded[10]) | (octet(encoded[11]) << 8U);
    const auto lifetime = octet(encoded[12]);
    const std::size_t usernameLength =
        octet(encoded[13]) | (octet(encoded[14]) << 8U);
    const std::size_t interfaceLength =
        octet(encoded[15]) | (octet(encoded[16]) << 8U);
    if (usernameLength > kMaximumUsernameBytes ||
        interfaceLength > kMaximumInterfaceBytes ||
        encoded.size() != kHeaderBytes + usernameLength + interfaceLength)
        return false;

    RuntimeUserPreferences candidate;
    candidate.port = static_cast<std::uint16_t>(port);
    candidate.preferRemoteInput = octet(encoded[9]) != 0U;
    candidate.permissionLifetimeMinutes = static_cast<std::uint8_t>(lifetime);
    const auto* characters =
        reinterpret_cast<const char*>(encoded.data() + kHeaderBytes);
    candidate.lastExplicitUsername.assign(characters, usernameLength);
    candidate.preferredStableLanInterfaceId.assign(
        characters + usernameLength, interfaceLength);
    if (!validPreferences(candidate))
        return false;
    preferences = std::move(candidate);
    return true;
}

namespace detail
{

RuntimeUserPreferencesStorageStatus loadRuntimeUserPreferencesFromDirectory(
    const std::filesystem::path& directory,
    RuntimeUserPreferences& preferences) noexcept
{
    preferences = RuntimeUserPreferences{};
    try
    {
#if defined(_WIN32)
        std::vector<std::byte> sidStorage;
        PSID sid = nullptr;
        if (!currentUserSid(sidStorage, sid))
            return RuntimeUserPreferencesStorageStatus::Unavailable;
        NativeHandle opened{::CreateFileW(
            directory.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
        if (!opened || !isPrivateWindowsObject(opened.get(), sid, true))
            return RuntimeUserPreferencesStorageStatus::Invalid;
        return loadFromWindowsDirectory(directory, sid, preferences);
#else
        FileDescriptor opened{::open(
            directory.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
        if (!opened || !privateObject(opened.get(), true, true))
            return RuntimeUserPreferencesStorageStatus::Invalid;
        return loadFromNativeDirectory(opened.get(), preferences);
#endif
    }
    catch (...)
    {
        preferences = RuntimeUserPreferences{};
        return RuntimeUserPreferencesStorageStatus::Unavailable;
    }
}

RuntimeUserPreferencesStorageStatus saveRuntimeUserPreferencesToDirectory(
    const std::filesystem::path& directory,
    const RuntimeUserPreferences& preferences) noexcept
{
    try
    {
        if (!validPreferences(preferences))
            return RuntimeUserPreferencesStorageStatus::Invalid;
#if defined(_WIN32)
        std::vector<std::byte> sidStorage;
        PSID sid = nullptr;
        if (!currentUserSid(sidStorage, sid))
            return RuntimeUserPreferencesStorageStatus::Unavailable;
        NativeHandle opened{::CreateFileW(
            directory.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
        if (!opened || !isPrivateWindowsObject(opened.get(), sid, true))
            return RuntimeUserPreferencesStorageStatus::Invalid;
        return saveToWindowsDirectory(directory, sid, preferences);
#else
        FileDescriptor opened{::open(
            directory.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
        if (!opened || !privateObject(opened.get(), true, true))
            return RuntimeUserPreferencesStorageStatus::Invalid;
        return saveToNativeDirectory(opened.get(), preferences);
#endif
    }
    catch (...)
    {
        return RuntimeUserPreferencesStorageStatus::Unavailable;
    }
}

} // namespace detail

RuntimeUserPreferencesStorageStatus loadRuntimeUserPreferences(
    RuntimeUserPreferences& preferences) noexcept
{
    preferences = RuntimeUserPreferences{};
    try
    {
#if defined(_WIN32)
        std::filesystem::path directory;
        const auto status = openNativeDirectory(directory, false);
        return status == RuntimeUserPreferencesStorageStatus::Loaded
            ? detail::loadRuntimeUserPreferencesFromDirectory(
                  directory, preferences) : status;
#else
        FileDescriptor directory;
        const auto status = openNativeDirectory(directory, false);
        return status == RuntimeUserPreferencesStorageStatus::Loaded
            ? loadFromNativeDirectory(directory.get(), preferences) : status;
#endif
    }
    catch (...)
    {
        return RuntimeUserPreferencesStorageStatus::Unavailable;
    }
}

RuntimeUserPreferencesStorageStatus saveRuntimeUserPreferences(
    const RuntimeUserPreferences& preferences) noexcept
{
    try
    {
        if (!validPreferences(preferences))
            return RuntimeUserPreferencesStorageStatus::Invalid;
#if defined(_WIN32)
        std::filesystem::path directory;
        const auto status = openNativeDirectory(directory, true);
        return status == RuntimeUserPreferencesStorageStatus::Loaded
            ? detail::saveRuntimeUserPreferencesToDirectory(
                  directory, preferences) : status;
#else
        FileDescriptor directory;
        const auto status = openNativeDirectory(directory, true);
        return status == RuntimeUserPreferencesStorageStatus::Loaded
            ? saveToNativeDirectory(directory.get(), preferences) : status;
#endif
    }
    catch (...)
    {
        return RuntimeUserPreferencesStorageStatus::Unavailable;
    }
}

} // namespace rdp_server::server::runtime
