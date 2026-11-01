// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/runtime_user_preferences_internal.h"
#include "server/runtime/runtime_host_control.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
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

} // namespace

int main()
{
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
