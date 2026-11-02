// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/runtime_user_preferences_internal.h"
#include "server/runtime/runtime_host_control.h"

#include <array>
#include <cassert>
#include <memory>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

using namespace rdp_server::server::runtime;

namespace
{

#if defined(_WIN32)
struct WindowsHandleCloser final
{
    void operator()(void* handle) const noexcept
    {
        if (handle != nullptr && handle != INVALID_HANDLE_VALUE)
            (void)::CloseHandle(handle);
    }
};

using WindowsHandle = std::unique_ptr<void, WindowsHandleCloser>;

[[nodiscard]] WindowsHandle openSharedPreferenceReader(
    const std::filesystem::path& path) noexcept
{
    const HANDLE handle = ::CreateFileW(
        path.c_str(), GENERIC_READ | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    return handle == INVALID_HANDLE_VALUE
        ? WindowsHandle{} : WindowsHandle{handle};
}

[[nodiscard]] bool sameWindowsFileIdentity(
    HANDLE first, HANDLE second) noexcept
{
    BY_HANDLE_FILE_INFORMATION firstInformation{};
    BY_HANDLE_FILE_INFORMATION secondInformation{};
    if (!::GetFileInformationByHandle(first, &firstInformation) ||
        !::GetFileInformationByHandle(second, &secondInformation))
        return false;
    return firstInformation.dwVolumeSerialNumber ==
               secondInformation.dwVolumeSerialNumber &&
           firstInformation.nFileIndexHigh == secondInformation.nFileIndexHigh &&
           firstInformation.nFileIndexLow == secondInformation.nFileIndexLow;
}

[[nodiscard]] bool createPrivateDirectory(const std::filesystem::path& path)
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    DWORD bytes = 0U;
    (void)GetTokenInformation(token, TokenUser, nullptr, 0U, &bytes);
    std::vector<std::byte> storage(bytes);
    const bool obtained = bytes >= sizeof(TOKEN_USER) &&
        GetTokenInformation(token, TokenUser, storage.data(), bytes, &bytes) != 0;
    (void)CloseHandle(token);
    if (!obtained)
        return false;
    PSID sid = reinterpret_cast<TOKEN_USER*>(storage.data())->User.Sid;
    const DWORD aclSize = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) -
                          sizeof(DWORD) + GetLengthSid(sid);
    std::vector<std::byte> aclStorage(aclSize);
    auto* acl = reinterpret_cast<PACL>(aclStorage.data());
    SECURITY_DESCRIPTOR descriptor{};
    if (!InitializeAcl(acl, aclSize, ACL_REVISION) ||
        !AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, sid) ||
        !InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorOwner(&descriptor, sid, FALSE) ||
        !SetSecurityDescriptorDacl(&descriptor, TRUE, acl, FALSE) ||
        !SetSecurityDescriptorControl(
            &descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED))
        return false;
    SECURITY_ATTRIBUTES attributes{
        sizeof(SECURITY_ATTRIBUTES), &descriptor, FALSE};
    return CreateDirectoryW(path.c_str(), &attributes) != 0;
}
#else
[[nodiscard]] bool createPrivateDirectory(const std::filesystem::path& path)
{
    // The directory must never exist briefly with a permissive umask.
    return ::mkdir(path.c_str(), 0700) == 0;
}
#endif

void writeEncoded(const std::filesystem::path& path,
                  const std::vector<std::byte>& encoded)
{
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    assert(stream.is_open());
    stream.write(reinterpret_cast<const char*>(encoded.data()),
                 static_cast<std::streamsize>(encoded.size()));
    stream.close();
    assert(stream.good());
}

#if defined(_WIN32)
int runWindowsApplicationDirectoryAncestryDenialTest()
{
    const auto isUnreparsed =
        &detail::windowsDirectoryHasNoReparseAncestorsForTesting;
    assert(!isUnreparsed(std::filesystem::path{L"relative\\AppData"}));
    assert(!isUnreparsed(std::filesystem::path{L"C:\\Users\\..\\AppData"}));

    const auto unsafeAncestor = std::filesystem::current_path() /
        ("runtime-user-preferences-windows-ancestor-" +
         std::to_string(::GetCurrentProcessId()));
    {
        std::ofstream file(unsafeAncestor);
        assert(file.good());
    }
    // A non-directory intermediate component must not be traversed to
    // manufacture a per-user application root. No privileged link creation
    // or live OS profile mutation is needed for this offline denial.
    assert(!isUnreparsed(unsafeAncestor / L"RDP-server"));
    assert(std::filesystem::remove(unsafeAncestor));
    return 0;
}

int runWindowsApplicationDirectoryAccessDenialTest()
{
    using Status = RuntimeUserPreferencesStorageStatus;
    const auto classify =
        &detail::classifyWindowsApplicationDirectoryOpenFailure;
    assert(classify(false, ERROR_FILE_NOT_FOUND) == Status::Missing);
    assert(classify(false, ERROR_PATH_NOT_FOUND) == Status::Missing);
    // Security/capability errors cannot masquerade as first-run defaults.
    assert(classify(false, ERROR_ACCESS_DENIED) == Status::Invalid);
    assert(classify(false, ERROR_SHARING_VIOLATION) == Status::Invalid);
    assert(classify(false, ERROR_INVALID_NAME) == Status::Invalid);
    assert(classify(false, ERROR_CANT_ACCESS_FILE) == Status::Invalid);
    assert(classify(true, ERROR_FILE_NOT_FOUND) == Status::Unavailable);
    assert(classify(true, ERROR_ACCESS_DENIED) == Status::Unavailable);
    return 0;
}

int runWindowsPreferenceHardLinkDenialTest()
{
    using Status = RuntimeUserPreferencesStorageStatus;
    const auto directory = std::filesystem::current_path() /
        ("runtime-user-preferences-windows-hard-link-" +
         std::to_string(::GetCurrentProcessId()));
    assert(createPrivateDirectory(directory));

    RuntimeUserPreferences original;
    original.lastExplicitUsername = "hard-link-owner";
    original.preferredStableLanInterfaceId = "{ABC-123}_Ethernet";
    original.port = 3394U;
    original.preferRemoteInput = false;
    original.permissionLifetimeMinutes = 9U;
    assert(detail::saveRuntimeUserPreferencesToDirectory(
               directory, original) == Status::Stored);

    const auto file = directory / L"preferences.bin";
    const auto alias = directory / L"preferences-alias.bin";
    if (!::CreateHardLinkW(alias.c_str(), file.c_str(), nullptr))
    {
        const DWORD error = ::GetLastError();
        assert(std::filesystem::remove(file));
        assert(std::filesystem::remove(directory));
        return error == ERROR_NOT_SUPPORTED || error == ERROR_INVALID_FUNCTION
            ? 77 : 1;
    }

    // The alias has the same owner and protected DACL as the original file.
    // File identity, not access metadata alone, must reject the substitution.
    RuntimeUserPreferences loaded = original;
    assert(detail::loadRuntimeUserPreferencesFromDirectory(
               directory, loaded) == Status::Invalid);
    assert(loaded.lastExplicitUsername.empty());
    assert(detail::saveRuntimeUserPreferencesToDirectory(
               directory, original) == Status::Invalid);

    assert(::DeleteFileW(alias.c_str()) != 0);
    assert(detail::loadRuntimeUserPreferencesFromDirectory(
               directory, loaded) == Status::Loaded);
    assert(loaded.lastExplicitUsername == original.lastExplicitUsername);
    assert(std::filesystem::remove(file));
    assert(std::filesystem::remove(directory));
    return 0;
}

int runWindowsActiveReaderAtomicReplacementTest()
{
    using Status = RuntimeUserPreferencesStorageStatus;
    const auto directory = std::filesystem::current_path() /
        ("runtime-user-preferences-windows-reader-" +
         std::to_string(::GetCurrentProcessId()));
    assert(createPrivateDirectory(directory));
    RuntimeUserPreferences original;
    original.lastExplicitUsername = "original-owner";
    original.preferredStableLanInterfaceId = "{ABC-123}_Ethernet";
    original.port = 3394U;
    original.preferRemoteInput = false;
    assert(detail::saveRuntimeUserPreferencesToDirectory(
               directory, original) == Status::Stored);
    const auto file = directory / L"preferences.bin";

    // The old object remains readable with DELETE sharing, but no writer
    // may change it in place while the new pathname is atomically published.
    {
        const WindowsHandle pinnedReader = openSharedPreferenceReader(file);
        assert(pinnedReader);

        RuntimeUserPreferences replacement = original;
        replacement.lastExplicitUsername = "replacement-owner";
        replacement.port = 3395U;
        assert(detail::saveRuntimeUserPreferencesToDirectory(
                   directory, replacement) == Status::Stored);

        LARGE_INTEGER previousSize{};
        assert(::GetFileSizeEx(pinnedReader.get(), &previousSize) != 0);
        std::array<std::byte, 512U> previousBytes{};
        assert(previousSize.QuadPart > 0 &&
               previousSize.QuadPart <=
                   static_cast<LONGLONG>(previousBytes.size()));
        DWORD received = 0U;
        assert(::ReadFile(pinnedReader.get(), previousBytes.data(),
                          static_cast<DWORD>(previousSize.QuadPart),
                          &received, nullptr) != 0);
        assert(received == static_cast<DWORD>(previousSize.QuadPart));
        RuntimeUserPreferences previous;
        assert(decodeRuntimeUserPreferences(
            std::span{previousBytes}.first(received), previous));
        assert(previous.lastExplicitUsername ==
               original.lastExplicitUsername);
        assert(previous.port == original.port);

        RuntimeUserPreferences loaded;
        assert(detail::loadRuntimeUserPreferencesFromDirectory(
                   directory, loaded) == Status::Loaded);
        assert(loaded.lastExplicitUsername ==
               replacement.lastExplicitUsername);
        assert(loaded.port == replacement.port);
        assert(loaded.preferredStableLanInterfaceId ==
               replacement.preferredStableLanInterfaceId);
    }
    assert(std::filesystem::remove(file));
    assert(std::filesystem::remove(directory));
    return 0;
}

int runWindowsActiveReaderReplacementIdentityTest()
{
    using Status = RuntimeUserPreferencesStorageStatus;
    const auto directory = std::filesystem::current_path() /
        ("runtime-user-preferences-windows-reader-identity-" +
         std::to_string(::GetCurrentProcessId()));
    assert(createPrivateDirectory(directory));

    RuntimeUserPreferences original;
    original.lastExplicitUsername = "identity-original";
    original.preferredStableLanInterfaceId = "{ABC-123}_Ethernet";
    original.port = 3396U;
    original.preferRemoteInput = false;
    assert(detail::saveRuntimeUserPreferencesToDirectory(
               directory, original) == Status::Stored);
    const auto file = directory / L"preferences.bin";

    {
        const WindowsHandle previousReader = openSharedPreferenceReader(file);
        assert(previousReader);

        RuntimeUserPreferences replacement = original;
        replacement.lastExplicitUsername = "identity-replacement";
        replacement.port = 3397U;
        assert(detail::saveRuntimeUserPreferencesToDirectory(
                   directory, replacement) == Status::Stored);

        const WindowsHandle currentReader = openSharedPreferenceReader(file);
        assert(currentReader);
        assert(!sameWindowsFileIdentity(
            previousReader.get(), currentReader.get()));

        BY_HANDLE_FILE_INFORMATION currentInformation{};
        assert(::GetFileInformationByHandle(
                   currentReader.get(), &currentInformation) != 0);
        assert(currentInformation.nNumberOfLinks == 1U);

        RuntimeUserPreferences loaded;
        assert(detail::loadRuntimeUserPreferencesFromDirectory(
                   directory, loaded) == Status::Loaded);
        assert(loaded.lastExplicitUsername ==
               replacement.lastExplicitUsername);
        assert(loaded.port == replacement.port);
    }

    assert(std::filesystem::remove(file));
    assert(std::filesystem::remove(directory));
    return 0;
}
#endif

int runUnsafeConfigAncestorStatusTest()
{
#if defined(_WIN32)
    return 77;
#else
    const unsigned long processId = static_cast<unsigned long>(::getpid());
    const auto homeDirectory = std::filesystem::current_path() /
        ("runtime-user-preferences-home-" + std::to_string(processId));
    assert(createPrivateDirectory(homeDirectory));

#if defined(__APPLE__)
    const auto libraryDirectory = homeDirectory / "Library";
    assert(createPrivateDirectory(libraryDirectory));
    const auto configDirectory = libraryDirectory / "Application Support";
#else
    const auto configDirectory = homeDirectory / ".config";
#endif
    const auto appDirectory = configDirectory / "rdp-server";
    const RuntimeUserPreferences defaults{};

    const auto requireStatus =
        [&](const RuntimeUserPreferencesStorageStatus expected) {
            RuntimeUserPreferences loaded;
            loaded.lastExplicitUsername = "must-reset";
            loaded.port = 3399U;
            assert(detail::loadRuntimeUserPreferencesFromHomeDirectoryForTesting(
                       homeDirectory, loaded) == expected);
            assert(loaded.lastExplicitUsername.empty());
            assert(loaded.port == defaults.port);
            assert(loaded.preferRemoteInput == defaults.preferRemoteInput);
        };

    // A truly absent configuration parent is a normal first-run condition.
    requireStatus(RuntimeUserPreferencesStorageStatus::Missing);

    // An existing no-follow path that cannot be accepted as a private
    // directory is a security/capability failure, not an ordinary miss.
    assert(::symlink(homeDirectory.c_str(), configDirectory.c_str()) == 0);
    requireStatus(RuntimeUserPreferencesStorageStatus::Invalid);
    assert(::unlink(configDirectory.c_str()) == 0);

    assert(createPrivateDirectory(configDirectory));
    assert(::chmod(configDirectory.c_str(), 0777) == 0);
    requireStatus(RuntimeUserPreferencesStorageStatus::Invalid);
    assert(::chmod(configDirectory.c_str(), 0700) == 0);

    // A secure configuration parent with no application directory is still a
    // normal first-run miss.
    requireStatus(RuntimeUserPreferencesStorageStatus::Missing);

    // The private application directory itself must also reject path
    // substitution instead of being reported as absent.
    assert(::symlink(homeDirectory.c_str(), appDirectory.c_str()) == 0);
    requireStatus(RuntimeUserPreferencesStorageStatus::Invalid);
    assert(::unlink(appDirectory.c_str()) == 0);

    assert(createPrivateDirectory(appDirectory));
    requireStatus(RuntimeUserPreferencesStorageStatus::Missing);

    assert(std::filesystem::remove(appDirectory));
    assert(std::filesystem::remove(configDirectory));
#if defined(__APPLE__)
    assert(std::filesystem::remove(libraryDirectory));
#endif
    assert(std::filesystem::remove(homeDirectory));
    return 0;
#endif
}

int runUnsafeHomeAncestorStatusTest()
{
#if defined(_WIN32)
    return 77;
#else
    const unsigned long processId = static_cast<unsigned long>(::getpid());
    const auto baseName =
        "runtime-user-preferences-unsafe-home-" + std::to_string(processId);
    const auto homeDirectory = std::filesystem::current_path() / baseName;
    const auto symlinkHome = std::filesystem::current_path() /
        (baseName + "-link");
    const RuntimeUserPreferences defaults{};

    const auto requireStatus =
        [&](const std::filesystem::path& selectedHome,
            const RuntimeUserPreferencesStorageStatus expected) {
            RuntimeUserPreferences loaded;
            loaded.lastExplicitUsername = "must-reset";
            loaded.port = 3399U;
            assert(detail::loadRuntimeUserPreferencesFromHomeDirectoryForTesting(
                       selectedHome, loaded) == expected);
            assert(loaded.lastExplicitUsername.empty());
            assert(loaded.port == defaults.port);
            assert(loaded.preferRemoteInput == defaults.preferRemoteInput);
        };

    // A missing account home means storage is unavailable, not that the
    // preferences subtree is an ordinary first-run miss.
    requireStatus(
        homeDirectory, RuntimeUserPreferencesStorageStatus::Unavailable);

    assert(createPrivateDirectory(homeDirectory));
    assert(::symlink(homeDirectory.c_str(), symlinkHome.c_str()) == 0);
    requireStatus(
        symlinkHome, RuntimeUserPreferencesStorageStatus::Invalid);
    assert(::unlink(symlinkHome.c_str()) == 0);

    assert(::chmod(homeDirectory.c_str(), 0777) == 0);
    requireStatus(
        homeDirectory, RuntimeUserPreferencesStorageStatus::Invalid);
    assert(::chmod(homeDirectory.c_str(), 0700) == 0);

    // A secure real home with no configuration directory remains a normal
    // first-run preferences miss.
    requireStatus(
        homeDirectory, RuntimeUserPreferencesStorageStatus::Missing);

    assert(std::filesystem::remove(homeDirectory));
    return 0;
#endif
}

int runSymlinkedHomeParentStatusTest()
{
#if defined(_WIN32)
    return 77;
#else
    const unsigned long processId = static_cast<unsigned long>(::getpid());
    const auto baseDirectory = std::filesystem::current_path() /
        ("runtime-user-preferences-home-parent-" + std::to_string(processId));
    const auto realParent = baseDirectory / "real-parent";
    const auto realHome = realParent / "home";
    const auto linkedParent = baseDirectory / "linked-parent";
    const RuntimeUserPreferences defaults{};

    assert(createPrivateDirectory(baseDirectory));
    assert(createPrivateDirectory(realParent));
    assert(createPrivateDirectory(realHome));
    assert(::symlink(realParent.c_str(), linkedParent.c_str()) == 0);

    RuntimeUserPreferences loaded;
    loaded.lastExplicitUsername = "must-reset";
    loaded.port = 3399U;
    assert(detail::loadRuntimeUserPreferencesFromHomeDirectoryForTesting(
               linkedParent / "home", loaded) ==
           RuntimeUserPreferencesStorageStatus::Invalid);
    assert(loaded.lastExplicitUsername.empty());
    assert(loaded.port == defaults.port);
    assert(loaded.preferRemoteInput == defaults.preferRemoteInput);

    assert(::unlink(linkedParent.c_str()) == 0);
    assert(std::filesystem::remove(realHome));
    assert(std::filesystem::remove(realParent));
    assert(std::filesystem::remove(baseDirectory));
    return 0;
#endif
}

#if !defined(_WIN32)
int runPosixFifoTargetDenialTest()
{
    using Status = RuntimeUserPreferencesStorageStatus;
    const auto directory = std::filesystem::current_path() /
        ("runtime-user-preferences-fifo-" +
         std::to_string(static_cast<unsigned long>(::getpid())));
    assert(createPrivateDirectory(directory));
    const auto file = directory / "preferences.bin";

    // A private FIFO is not a regular preferences record. An attacker-created
    // nonregular target must not block on read, be decoded, or be replaced.
    assert(::mkfifo(file.c_str(), 0600) == 0);
    assert(::chmod(file.c_str(), 0600) == 0);
    RuntimeUserPreferences loaded;
    loaded.lastExplicitUsername = "must-reset";
    loaded.preferredStableLanInterfaceId = "stale-interface";
    loaded.port = 3399U;
    const RuntimeUserPreferences defaults{};
    assert(detail::loadRuntimeUserPreferencesFromDirectory(
               directory, loaded) == Status::Invalid);
    assert(loaded.lastExplicitUsername.empty());
    assert(loaded.preferredStableLanInterfaceId.empty());
    assert(loaded.port == defaults.port);
    assert(loaded.preferRemoteInput == defaults.preferRemoteInput);
    assert(loaded.permissionLifetimeMinutes ==
           defaults.permissionLifetimeMinutes);

    RuntimeUserPreferences replacement;
    replacement.lastExplicitUsername = "private-owner";
    assert(detail::saveRuntimeUserPreferencesToDirectory(
               directory, replacement) == Status::Invalid);
    struct stat metadata{};
    assert(::lstat(file.c_str(), &metadata) == 0);
    assert(S_ISFIFO(metadata.st_mode));
    assert((metadata.st_mode & 07777) == 0600);

    assert(::unlink(file.c_str()) == 0);
    assert(detail::loadRuntimeUserPreferencesFromDirectory(
               directory, loaded) == Status::Missing);
    assert(std::filesystem::remove(directory));
    return 0;
}
#endif

} // namespace

int main(int argc, char** argv)
{
#if defined(_WIN32)
    if (argc == 2 &&
        std::string_view{argv[1]} == "windows-directory-access-denial-status")
        return runWindowsApplicationDirectoryAccessDenialTest();
    if (argc == 2 &&
        std::string_view{argv[1]} == "windows-localappdata-ancestry-denial")
        return runWindowsApplicationDirectoryAncestryDenialTest();
    if (argc == 2 &&
        std::string_view{argv[1]} == "windows-file-hard-link-denial")
        return runWindowsPreferenceHardLinkDenialTest();
    if (argc == 2 &&
        std::string_view{argv[1]} == "windows-active-reader-atomic-replacement")
        return runWindowsActiveReaderAtomicReplacementTest();
    if (argc == 2 &&
        std::string_view{argv[1]} == "windows-active-reader-replacement-identity")
        return runWindowsActiveReaderReplacementIdentityTest();
#endif
#if !defined(_WIN32)
    if (argc == 2 &&
        std::string_view{argv[1]} == "posix-fifo-target-denial")
        return runPosixFifoTargetDenialTest();
#endif
    if (argc == 2 &&
        std::string_view{argv[1]} == "unsafe-config-ancestor-status")
        return runUnsafeConfigAncestorStatusTest();
    if (argc == 2 &&
        std::string_view{argv[1]} == "unsafe-home-ancestor-status")
        return runUnsafeHomeAncestorStatusTest();
    if (argc == 2 &&
        std::string_view{argv[1]} == "symlinked-home-parent-status")
        return runSymlinkedHomeParentStatusTest();
    assert(argc == 1);
    static_assert(!runtimeBootstrapMayPersist(
        RuntimeBootstrapMaterial::SessionPassword));
    static_assert(RuntimeApplicationBootstrapPolicy::automaticListenerStart == false);
    static_assert(RuntimeApplicationBootstrapPolicy::explicitSharingRequiredBeforeListen);

    const RuntimeUserPreferences defaults{};
    RuntimeUserPreferences original;
    original.lastExplicitUsername = "owner-\xc3\xa9";
    original.preferredStableLanInterfaceId = "{ABC-123}_en0";
    original.port = 3392U;
    original.preferRemoteInput = false;
    original.permissionLifetimeMinutes = 10U;

    std::vector<std::byte> encoded;
    assert(encodeRuntimeUserPreferences(original, encoded));
    RuntimeUserPreferences parsed;
    assert(decodeRuntimeUserPreferences(encoded, parsed));
    assert(parsed.lastExplicitUsername == original.lastExplicitUsername);
    assert(parsed.preferredStableLanInterfaceId ==
           original.preferredStableLanInterfaceId);
    assert(parsed.port == 3392U);
    assert(!parsed.preferRemoteInput);
    assert(parsed.permissionLifetimeMinutes == 10U);

    const auto reject = [&](std::vector<std::byte> damaged) {
        RuntimeUserPreferences unchanged = original;
        assert(!decodeRuntimeUserPreferences(damaged, unchanged));
        assert(unchanged.lastExplicitUsername == original.lastExplicitUsername);
        assert(unchanged.port == original.port);
    };
    {
        auto invalid = encoded;
        invalid[8] = std::byte{2U}; // Unknown version.
        reject(invalid);
        invalid = encoded;
        invalid[9] = std::byte{0x80U}; // Privilege/unknown flag injection.
        reject(invalid);
        invalid = encoded;
        invalid[10] = std::byte{0U};
        invalid[11] = std::byte{0U}; // Invalid numeric port.
        reject(invalid);
        invalid = encoded;
        invalid[12] = std::byte{61U}; // Invalid permission-lifetime number.
        reject(invalid);
        invalid = encoded;
        invalid[13] = std::byte{0xffU}; // Malformed string length.
        reject(invalid);
        invalid = encoded;
        invalid[17] = std::byte{0xffU}; // Invalid UTF-8.
        reject(invalid);
        invalid = encoded;
        invalid.push_back(std::byte{0x42U}); // No extensible/duplicate fields.
        reject(invalid);
        invalid = encoded;
        invalid.pop_back(); // Truncated/partial record.
        reject(invalid);
        invalid = encoded;
        invalid[0] = std::byte{0U}; // Unknown record family.
        reject(invalid);
    }
    {
        auto invalid = original;
        invalid.lastExplicitUsername = "owner/password";
        assert(!encodeRuntimeUserPreferences(invalid, encoded));
        invalid = original;
        invalid.preferredStableLanInterfaceId = "../fake";
        assert(!encodeRuntimeUserPreferences(invalid, encoded));
        invalid = original;
        invalid.permissionLifetimeMinutes = 0U;
        assert(!encodeRuntimeUserPreferences(invalid, encoded));
    }
    assert(encodeRuntimeUserPreferences(original, encoded));

    // CTest's working directory is the existing single build root.
#if defined(_WIN32)
    const unsigned long processId = GetCurrentProcessId();
#else
    const unsigned long processId = static_cast<unsigned long>(::getpid());
#endif
    const auto directory = std::filesystem::current_path() /
        ("runtime-user-preferences-" + std::to_string(processId));
    assert(createPrivateDirectory(directory));
    const auto file = directory / "preferences.bin";
#if !defined(_WIN32)
    struct stat directoryMetadata{};
    assert(::lstat(directory.c_str(), &directoryMetadata) == 0);
    assert(S_ISDIR(directoryMetadata.st_mode));
    assert(directoryMetadata.st_uid == ::geteuid());
    assert((directoryMetadata.st_mode & 07777) == 0700);
#endif

    RuntimeUserPreferences loaded = original;
    assert(detail::loadRuntimeUserPreferencesFromDirectory(
               directory, loaded) == RuntimeUserPreferencesStorageStatus::Missing);
    assert(loaded.lastExplicitUsername.empty());
    assert(loaded.port == defaults.port);
    assert(loaded.preferRemoteInput == defaults.preferRemoteInput);
    assert(detail::saveRuntimeUserPreferencesToDirectory(
               directory, original) == RuntimeUserPreferencesStorageStatus::Stored);
    assert(detail::loadRuntimeUserPreferencesFromDirectory(
               directory, loaded) == RuntimeUserPreferencesStorageStatus::Loaded);
    assert(loaded.lastExplicitUsername == original.lastExplicitUsername);
    assert(loaded.preferredStableLanInterfaceId ==
           original.preferredStableLanInterfaceId);
    assert(loaded.port == original.port);

    // Force a failure only after the secure temporary record has been written
    // and flushed. The old record must remain readable and no temporary path
    // may survive the failed atomic replacement.
    RuntimeUserPreferences replacement = original;
    replacement.lastExplicitUsername = "replacement-owner";
    replacement.port = 3393U;
    assert(detail::
               saveRuntimeUserPreferencesToDirectoryWithAtomicReplaceFailureForTesting(
                   directory, replacement) ==
           RuntimeUserPreferencesStorageStatus::Unavailable);
    RuntimeUserPreferences retainedAfterAtomicFailure;
    assert(detail::loadRuntimeUserPreferencesFromDirectory(
               directory, retainedAfterAtomicFailure) ==
           RuntimeUserPreferencesStorageStatus::Loaded);
    assert(retainedAfterAtomicFailure.lastExplicitUsername ==
           original.lastExplicitUsername);
    assert(retainedAfterAtomicFailure.preferredStableLanInterfaceId ==
           original.preferredStableLanInterfaceId);
    assert(retainedAfterAtomicFailure.port == original.port);
    assert(retainedAfterAtomicFailure.preferRemoteInput ==
           original.preferRemoteInput);
    assert(retainedAfterAtomicFailure.permissionLifetimeMinutes ==
           original.permissionLifetimeMinutes);
    std::size_t storedEntries = 0U;
    for (const auto& entry : std::filesystem::directory_iterator(directory))
    {
        assert(entry.path().filename() == "preferences.bin");
        ++storedEntries;
    }
    assert(storedEntries == 1U);
#if !defined(_WIN32)
    struct stat fileMetadata{};
    assert(::lstat(file.c_str(), &fileMetadata) == 0);
    assert(S_ISREG(fileMetadata.st_mode));
    assert(fileMetadata.st_uid == ::geteuid());
    assert(fileMetadata.st_nlink == 1);
    assert((fileMetadata.st_mode & 07777) == 0600);

    // A same-owner hard-link alias makes the target identity non-unique and
    // must be denied until the alias is removed.
    const auto hardLink = directory / "preferences-hard-link.bin";
    assert(::link(file.c_str(), hardLink.c_str()) == 0);
    loaded = original;
    assert(detail::loadRuntimeUserPreferencesFromDirectory(
               directory, loaded) == RuntimeUserPreferencesStorageStatus::Invalid);
    assert(loaded.lastExplicitUsername.empty());
    assert(detail::saveRuntimeUserPreferencesToDirectory(
               directory, original) == RuntimeUserPreferencesStorageStatus::Invalid);
    assert(::unlink(hardLink.c_str()) == 0);
    assert(detail::loadRuntimeUserPreferencesFromDirectory(
               directory, loaded) == RuntimeUserPreferencesStorageStatus::Loaded);

    // Exact private mode is part of the file contract; owner execute bits are
    // not accepted merely because group/world access remains absent.
    assert(::chmod(file.c_str(), 0700) == 0);
    loaded = original;
    assert(detail::loadRuntimeUserPreferencesFromDirectory(
               directory, loaded) == RuntimeUserPreferencesStorageStatus::Invalid);
    assert(detail::saveRuntimeUserPreferencesToDirectory(
               directory, original) == RuntimeUserPreferencesStorageStatus::Invalid);
    assert(::chmod(file.c_str(), 0600) == 0);
    assert(detail::loadRuntimeUserPreferencesFromDirectory(
               directory, loaded) == RuntimeUserPreferencesStorageStatus::Loaded);
#endif

    // Independent reload simulates restart. This path neither owns a secret
    // nor depends on HostControl; the deny-only runtime remains unchanged.
    UnavailableRuntimeHostControl runtime;
    const auto before = runtime.status();
    RuntimeUserPreferences restarted;
    assert(detail::loadRuntimeUserPreferencesFromDirectory(
               directory, restarted) == RuntimeUserPreferencesStorageStatus::Loaded);
    const auto after = runtime.status();
    assert(before.stage == RuntimeHostStage::Stopped);
    assert(after.stage == RuntimeHostStage::Stopped);
    assert(!after.graphicsReady);
    assert(!after.credentialsConfigured);
    assert(!after.listenerAvailable);
    assert(!after.product.ownerAuthorized);

    {
        auto invalid = encoded;
        invalid[9] = std::byte{0xffU};
        writeEncoded(file, invalid);
        loaded = original;
        assert(detail::loadRuntimeUserPreferencesFromDirectory(
                   directory, loaded) == RuntimeUserPreferencesStorageStatus::Invalid);
        assert(loaded.lastExplicitUsername.empty());
        assert(loaded.port == defaults.port);
    }
    writeEncoded(file, encoded);
#if !defined(_WIN32)
    // Existing file remains intact when an unsafe directory forbids saving.
    assert(::chmod(directory.c_str(), 0777) == 0);
    assert(detail::saveRuntimeUserPreferencesToDirectory(
               directory, original) == RuntimeUserPreferencesStorageStatus::Invalid);
    assert(detail::loadRuntimeUserPreferencesFromDirectory(
               directory, loaded) == RuntimeUserPreferencesStorageStatus::Invalid);
    assert(::chmod(directory.c_str(), 0700) == 0);
    assert(detail::loadRuntimeUserPreferencesFromDirectory(
               directory, loaded) == RuntimeUserPreferencesStorageStatus::Loaded);

    // Creation mode is umask-sensitive; the store must still publish a
    // canonical 0600 replacement or fail before replacing the target.
    assert(std::filesystem::remove(file));
    const mode_t previousUmask = ::umask(0777);
    const auto restrictiveSave = detail::saveRuntimeUserPreferencesToDirectory(
        directory, original);
    (void)::umask(previousUmask);
    assert(restrictiveSave == RuntimeUserPreferencesStorageStatus::Stored);
    struct stat restrictiveFileMetadata{};
    assert(::lstat(file.c_str(), &restrictiveFileMetadata) == 0);
    assert(S_ISREG(restrictiveFileMetadata.st_mode));
    assert(restrictiveFileMetadata.st_uid == ::geteuid());
    assert((restrictiveFileMetadata.st_mode & 07777) == 0600);
    assert(detail::loadRuntimeUserPreferencesFromDirectory(
               directory, loaded) == RuntimeUserPreferencesStorageStatus::Loaded);

    const auto alias = directory.string() + "-alias";
    assert(::symlink(directory.c_str(), alias.c_str()) == 0);
    assert(detail::loadRuntimeUserPreferencesFromDirectory(
               alias, loaded) == RuntimeUserPreferencesStorageStatus::Invalid);
    assert(::unlink(alias.c_str()) == 0);
    // A symlink target must never be followed or replaced.
    assert(std::filesystem::remove(file));
    assert(::symlink("/dev/null", file.c_str()) == 0);
    assert(detail::saveRuntimeUserPreferencesToDirectory(
               directory, original) == RuntimeUserPreferencesStorageStatus::Invalid);
    assert(std::filesystem::remove(file));
#else
    // An ordinary file masquerading as a directory is never a store.
    const auto unsafe = std::filesystem::current_path() /
        ("runtime-user-preferences-unsafe-" + std::to_string(processId));
    { std::ofstream stream(unsafe); assert(stream.good()); }
    assert(detail::saveRuntimeUserPreferencesToDirectory(
               unsafe, original) == RuntimeUserPreferencesStorageStatus::Invalid);
    assert(std::filesystem::remove(unsafe));
    assert(std::filesystem::remove(file));
#endif
    assert(std::filesystem::remove(directory));
    return 0;
}
