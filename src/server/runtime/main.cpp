// SPDX-License-Identifier: GPL-3.0-or-later
// R10 process entry point. No listener, session controller or OS adapter is
// constructed until R2 admission and R3 authoritative live sessions exist.
// An explicit offline configuration check does not authenticate or start a user.
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string_view>
#if defined(_WIN32)
#include <windows.h>
#include <aclapi.h>
#include <fcntl.h>
#include <io.h>
#include <cstdint>
#endif

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#ifndef RDP_SERVER_VERSION
#error "The build system must provide the RDP server version"
#endif

namespace {
constexpr int kSecureStartupUnavailableExitCode = 2;
constexpr int kInvalidConfigurationExitCode = 3;
constexpr std::size_t kMaximumConfigurationBytes = 4096;

constexpr std::array<std::string_view, 7> kConfigurationFields{
    "listen_address", "listen_port", "tls_certificate", "tls_private_key",
    "authentication", "os_authorization", "max_connections"};

[[nodiscard]] constexpr std::string_view trimWhitespace(std::string_view value) noexcept {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.remove_prefix(1);
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
        value.remove_suffix(1);
    }
    return value;
}

[[nodiscard]] constexpr bool isDecimalWithin(std::string_view value,
                                              unsigned minimum,
                                              unsigned maximum) noexcept {
    if (value.empty()) {
        return false;
    }
    unsigned parsedValue = 0;
    for (const char digit : value) {
        if (digit < '0' || digit > '9') {
            return false;
        }
        const auto numericDigit = static_cast<unsigned>(digit - '0');
        if (parsedValue > (maximum - numericDigit) / 10U) {
            return false;
        }
        parsedValue = parsedValue * 10U + numericDigit;
    }
    return parsedValue >= minimum;
}

[[nodiscard]] bool isAbsoluteConfigurationPath(std::string_view path) noexcept {
    if (path.empty() || path.size() > 1024) {
        return false;
    }
#if defined(_WIN32)
    // Restrict the preliminary contract to fully qualified drive paths.
    // Relative, drive-relative and UNC paths require separate policy review.
    if (path.size() < 4 ||
        !((path[0] >= 'A' && path[0] <= 'Z') ||
          (path[0] >= 'a' && path[0] <= 'z')) ||
        path[1] != ':' || (path[2] != '/' && path[2] != '\\')) {
        return false;
    }
#else
    if (path.front() != '/') {
        return false;
    }
#endif
    // Check separators explicitly; no environment expansion or normalization.
    // This initial gate does not establish file permissions or certificate validity.
    std::size_t componentStart = 0;
    for (std::size_t index = 0; index <= path.size(); ++index) {
        const bool isSeparator = index == path.size() || path[index] == '/'
#if defined(_WIN32)
            || path[index] == '\\'
#endif
            ;
        if (!isSeparator) {
            continue;
        }
        const auto component = path.substr(componentStart, index - componentStart);
        if (component == "..") {
            return false;
        }
        componentStart = index + 1;
    }
    return true;
}

[[nodiscard]] bool isValidConfiguration(
    std::string_view text,
    std::array<std::string_view, kConfigurationFields.size()>* validatedFields = nullptr) noexcept {
    std::array<std::string_view, kConfigurationFields.size()> fieldValues{};
    std::array<bool, kConfigurationFields.size()> fieldSeen{};

    while (!text.empty()) {
        const auto lineEnd = text.find('\n');
        auto line = text.substr(0, lineEnd);
        text = lineEnd == std::string_view::npos
            ? std::string_view{} : text.substr(lineEnd + 1);
        if (!line.empty() && line.back() == '\r') {
            line.remove_suffix(1);
        }
        line = trimWhitespace(line);
        for (const char character : line) {
            const auto codePoint = static_cast<unsigned char>(character);
            if ((codePoint < 0x20U && codePoint != '\t') || codePoint == 0x7FU) {
                return false;
            }
        }
        if (line.empty() || line.front() == '#') {
            continue;
        }
        const auto separator = line.find('=');
        if (separator == std::string_view::npos) {
            return false;
        }
        const auto fieldName = trimWhitespace(line.substr(0, separator));
        const auto value = trimWhitespace(line.substr(separator + 1));
        bool recognized = false;
        for (std::size_t index = 0; index < kConfigurationFields.size(); ++index) {
            if (fieldName != kConfigurationFields[index]) {
                continue;
            }
            if (fieldSeen[index] || value.empty()) {
                return false;
            }
            fieldSeen[index] = true;
            fieldValues[index] = value;
            recognized = true;
            break;
        }
        if (!recognized) {
            return false;
        }
    }
    for (const bool seen : fieldSeen) {
        if (!seen) {
            return false;
        }
    }
    const bool valid =
        (fieldValues[0] == "127.0.0.1" || fieldValues[0] == "::1") &&
        isDecimalWithin(fieldValues[1], 1, 65535) &&
        isAbsoluteConfigurationPath(fieldValues[2]) &&
        isAbsoluteConfigurationPath(fieldValues[3]) &&
        fieldValues[2] != fieldValues[3] &&
        fieldValues[4] == "required" &&
        fieldValues[5] == "required" &&
        isDecimalWithin(fieldValues[6], 1, 64);
    if (valid && validatedFields != nullptr) {
        *validatedFields = fieldValues; // Borrowed only while config buffer lives.
    }
    return valid;
}

#if defined(_WIN32)
// Conservative file DACL gate: broad principals may read configuration,
// but must not be granted write, delete or permission-changing rights.
// Evaluate the opened HANDLE, not a second (racy) path lookup.
[[nodiscard]] bool hasRestrictedConfigurationDacl(
    HANDLE fileHandle, bool privateKey = false) noexcept {
    PSID owner = nullptr;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR rawDescriptor = nullptr;
    if (::GetSecurityInfo(fileHandle, SE_FILE_OBJECT,
                          OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                          &owner, nullptr, &dacl, nullptr,
                          &rawDescriptor) != ERROR_SUCCESS) {
        return false;
    }
    struct DescriptorCloser {
        void operator()(void* ptr) const noexcept {
            (void)::LocalFree(ptr);
        }
    };
    std::unique_ptr<void, DescriptorCloser> descriptor{rawDescriptor};
    if (!descriptor || owner == nullptr || !::IsValidSid(owner) ||
        dacl == nullptr || !::IsValidAcl(dacl)) {
        return false; // A null DACL grants unrestricted access.
    }
    constexpr DWORD unsafeRights =
        FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
        FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER |
        GENERIC_WRITE | GENERIC_ALL;
    for (DWORD index = 0; index < dacl->AceCount; ++index) {
        void* rawAce = nullptr;
        if (!::GetAce(dacl, index, &rawAce) || rawAce == nullptr) {
            return false;
        }
        const auto* header = static_cast<const ACE_HEADER*>(rawAce);
        if ((header->AceFlags & INHERIT_ONLY_ACE) != 0) {
            continue; // Does not authorize access to this file.
        }
        if (header->AceType == ACCESS_DENIED_ACE_TYPE) {
            continue;
        }
        // Do not silently accept unexamined callback/object allow ACEs.
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE ||
            header->AceSize < sizeof(ACCESS_ALLOWED_ACE)) {
            return false;
        }
        auto* allow = static_cast<ACCESS_ALLOWED_ACE*>(rawAce);
        PSID principal = &allow->SidStart;
        if (!::IsValidSid(principal)) {
            return false;
        }
        const bool broadPrincipal =
            ::IsWellKnownSid(principal, WinWorldSid) ||
            ::IsWellKnownSid(principal, WinAuthenticatedUserSid) ||
            ::IsWellKnownSid(principal, WinBuiltinUsersSid) ||
            ::IsWellKnownSid(principal, WinBuiltinGuestsSid) ||
            ::IsWellKnownSid(principal, WinAnonymousSid) ||
            ::IsWellKnownSid(principal, WinInteractiveSid) ||
            ::IsWellKnownSid(principal, WinNetworkSid);
        if (broadPrincipal && (allow->Mask & unsafeRights) != 0) {
            return false;
        }
        if (privateKey && !::EqualSid(principal, owner) &&
            !::IsWellKnownSid(principal, WinLocalSystemSid) &&
            !::IsWellKnownSid(principal, WinBuiltinAdministratorsSid)) {
            return false; // A readable private key must not be public.
        }
    }
    return true;
}
#endif


struct TlsFileIdentity {
#if defined(_WIN32)
    DWORD volume = 0;
    DWORD indexHigh = 0;
    DWORD indexLow = 0;
#else
    dev_t device = 0;
    ino_t inode = 0;
#endif
};

[[nodiscard]] bool inspectTlsFile(std::string_view path,
                                  bool privateKey,
                                  TlsFileIdentity& identity) noexcept {
    constexpr std::size_t kMaximumCertificateBytes = 1024U * 1024U;
    constexpr std::size_t kMaximumPrivateKeyBytes = 256U * 1024U;
    const std::size_t maximumBytes =
        privateKey ? kMaximumPrivateKeyBytes : kMaximumCertificateBytes;
    if (!isAbsoluteConfigurationPath(path)) {
        return false;
    }
    std::array<char, 1025> terminatedPath{};
    std::copy(path.begin(), path.end(), terminatedPath.begin());
#if defined(_WIN32)
    const HANDLE handle = ::CreateFileA(
        terminatedPath.data(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    BY_HANDLE_FILE_INFORMATION information{};
    const bool safe =
        ::GetFileType(handle) == FILE_TYPE_DISK &&
        ::GetFileInformationByHandleEx(
            handle, FileAttributeTagInfo, &attributes, sizeof(attributes)) &&
        (attributes.FileAttributes &
         (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0 &&
        ::GetFileInformationByHandle(handle, &information) &&
        (static_cast<std::uint64_t>(information.nFileSizeHigh) << 32U |
         information.nFileSizeLow) > 0 &&
        (static_cast<std::uint64_t>(information.nFileSizeHigh) << 32U |
         information.nFileSizeLow) <= maximumBytes &&
        hasRestrictedConfigurationDacl(handle, privateKey);
    (void)::CloseHandle(handle);
    if (!safe) {
        return false;
    }
    identity.volume = information.dwVolumeSerialNumber;
    identity.indexHigh = information.nFileIndexHigh;
    identity.indexLow = information.nFileIndexLow;
#else
    // Check identity/mode on the same descriptor without following the
    // final symlink, blocking on a FIFO or opening any TLS material content.
    const int fd = ::open(
        terminatedPath.data(), O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return false;
    }
    struct stat information {};
    const bool safe = ::fstat(fd, &information) == 0 &&
        S_ISREG(information.st_mode) &&
        information.st_size > 0 &&
        information.st_size <= static_cast<off_t>(maximumBytes) &&
        (information.st_mode & (S_IWGRP | S_IWOTH)) == 0 &&
        (!privateKey ||
         (information.st_uid == ::geteuid() &&
          (information.st_mode & (S_IRWXG | S_IRWXO)) == 0 &&
          (information.st_mode & S_IRUSR) != 0));
    (void)::close(fd);
    if (!safe) {
        return false;
    }
    identity.device = information.st_dev;
    identity.inode = information.st_ino;
#endif
    return true;
}

[[nodiscard]] bool checkTlsFileReferences(
    std::string_view certificatePath, std::string_view privateKeyPath) noexcept {
    TlsFileIdentity certificate{};
    TlsFileIdentity privateKey{};
    if (!inspectTlsFile(certificatePath, false, certificate) ||
        !inspectTlsFile(privateKeyPath, true, privateKey)) {
        return false;
    }
#if defined(_WIN32)
    return certificate.volume != privateKey.volume ||
           certificate.indexHigh != privateKey.indexHigh ||
           certificate.indexLow != privateKey.indexLow;
#else
    return certificate.device != privateKey.device ||
           certificate.inode != privateKey.inode;
#endif
}

// Offline metadata acceptance is not certificate parsing, key matching,
// expiry verification, an R2 admission decision or permission to listen.
[[nodiscard]] bool checkConfigurationFile(
    const char* path, bool checkTlsFiles = false) noexcept {
    if (path == nullptr || *path == '\0') {
        return false;
    }
    struct FileCloser {
        void operator()(std::FILE* file) const noexcept {
            (void)std::fclose(file);
        }
    };
    // On POSIX, open the *actual* file without following its final symlink.
    // Nonblocking open makes FIFOs/devices fail safely rather than hanging
    // the offline checker. The FILE stream exclusively owns this descriptor
    // after fdopen succeeds; otherwise close it on the failure path.
#if !defined(_WIN32)
    const int configurationDescriptor =
        ::open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (configurationDescriptor < 0) {
        return false;
    }
    std::unique_ptr<std::FILE, FileCloser> file{
        ::fdopen(configurationDescriptor, "rb")};
    if (!file) {
        (void)::close(configurationDescriptor);
        return false;
    }
    struct stat openedFileStatus {};
    if (::fstat(configurationDescriptor, &openedFileStatus) != 0 ||
        !S_ISREG(openedFileStatus.st_mode) ||
        (openedFileStatus.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return false;
    }
#else
    // Reject relative, UNC and device namespaces before native file opening.
    // The DACL and intermediate reparse components require separate review.
    if (!isAbsoluteConfigurationPath(path)) {
        return false;
    }
    struct NativeHandleCloser {
        void operator()(void* nativeHandle) const noexcept {
            (void)::CloseHandle(nativeHandle);
        }
    };
    const HANDLE openedHandle = ::CreateFileA(
        path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (openedHandle == INVALID_HANDLE_VALUE) {
        return false;
    }
    std::unique_ptr<void, NativeHandleCloser> nativeHandle{openedHandle};
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    if (::GetFileType(nativeHandle.get()) != FILE_TYPE_DISK ||
        !::GetFileInformationByHandleEx(nativeHandle.get(), FileAttributeTagInfo,
                                        &attributes, sizeof(attributes)) ||
        (attributes.FileAttributes &
         (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
        !hasRestrictedConfigurationDacl(nativeHandle.get())) {
        return false;
    }
    // Exactly one owner across HANDLE -> CRT descriptor -> FILE.
    const int descriptor = ::_open_osfhandle(
        reinterpret_cast<std::intptr_t>(nativeHandle.get()),
        _O_RDONLY | _O_BINARY);
    if (descriptor < 0) {
        return false;
    }
    (void)nativeHandle.release();
    std::unique_ptr<std::FILE, FileCloser> file{::_fdopen(descriptor, "rb")};
    if (!file) {
        (void)::_close(descriptor);
        return false;
    }
#endif
    std::array<char, kMaximumConfigurationBytes + 1> bytes{};
    const std::size_t bytesRead =
        std::fread(bytes.data(), sizeof(char), bytes.size(), file.get());
    if (std::ferror(file.get()) != 0 || bytesRead == 0 ||
        bytesRead > kMaximumConfigurationBytes) {
        return false;
    }
    std::array<std::string_view, kConfigurationFields.size()> validatedFields{};
    if (!isValidConfiguration(std::string_view{bytes.data(), bytesRead},
                              &validatedFields)) {
        return false;
    }
    return !checkTlsFiles ||
           checkTlsFileReferences(validatedFields[2], validatedFields[3]);
}

void printUsage() noexcept {
    std::fputs("Usage: rdp-server [--help | --version | --check-config FILE | --check-tls-files FILE]\n"
               "--check-config validates syntax only. --check-tls-files checks\n"
               "file metadata, not cryptographic contents or OS authorization.\n"
               "Secure desktop service startup is not implemented.\n", stdout);
}
} // namespace

int main(int argumentCount, char* argumentValues[]) noexcept {
    if (argumentCount >= 2 && argumentValues[1] != nullptr) {
        const std::string_view option{argumentValues[1]};
        if (argumentCount == 2 && option == "--help") {
            printUsage();
            return 0;
        }
        if (argumentCount == 2 && option == "--version") {
            std::printf("rdp-server %s\n", RDP_SERVER_VERSION);
            return 0;
        }
        if (argumentCount == 3 &&
            (option == "--check-config" || option == "--check-tls-files")) {
            const bool verifyTls = option == "--check-tls-files";
            if (checkConfigurationFile(argumentValues[2], verifyTls)) {
                if (verifyTls) {
                    std::fputs("rdp-server: TLS file metadata accepted; cryptographic contents "
                               "and OS authorization not verified; service remains disabled.\n",
                               stdout);
                } else {
                    std::fputs("rdp-server: configuration syntax accepted; credentials and "
                               "OS authorization not verified; service remains disabled.\n",
                               stdout);
                }
                return 0;
            }
            // Never reveal configuration contents, paths or secrets in logs.
            std::fputs("rdp-server: configuration check failed; "
                       "service remains disabled.\n", stderr);
            return kInvalidConfigurationExitCode;
        }
    }

    // Reject service startup, missing or chained arguments, and security-
    // weakening options. No sockets, credentials, or desktop are accessed.
    std::fputs("rdp-server: refusing to start: authenticated OS authorization "
               "and authoritative live RDP sessions are unavailable.\n", stderr);
    return kSecureStartupUnavailableExitCode;
}
