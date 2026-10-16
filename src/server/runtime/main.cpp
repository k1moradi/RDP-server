// SPDX-License-Identifier: GPL-3.0-or-later
// R10 process entry point. No listener, session controller or OS adapter is
// constructed until R2 admission and R3 authoritative live sessions exist.
// An explicit offline configuration check does not authenticate or start a user.
#include <array>
#include <cstdio>
#include <memory>
#include <string_view>
#if defined(_WIN32)
#include <windows.h>
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

[[nodiscard]] bool isValidConfiguration(std::string_view text) noexcept {
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
    return (fieldValues[0] == "127.0.0.1" || fieldValues[0] == "::1") &&
           isDecimalWithin(fieldValues[1], 1, 65535) &&
           isAbsoluteConfigurationPath(fieldValues[2]) &&
           isAbsoluteConfigurationPath(fieldValues[3]) &&
           fieldValues[2] != fieldValues[3] &&
           fieldValues[4] == "required" &&
           fieldValues[5] == "required" &&
           isDecimalWithin(fieldValues[6], 1, 64);
}

[[nodiscard]] bool checkConfigurationFile(const char* path) noexcept {
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
         (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
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
    return isValidConfiguration(std::string_view{bytes.data(), bytesRead});
}

void printUsage() noexcept {
    std::fputs("Usage: rdp-server [--help | --version | --check-config FILE]\n"
               "--check-config validates syntax only; it does not verify\n"
               "TLS credentials, OS authorization or start a service.\n"
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
        if (argumentCount == 3 && option == "--check-config") {
            if (checkConfigurationFile(argumentValues[2])) {
                std::fputs("rdp-server: configuration syntax accepted; credentials and "
                           "OS authorization not verified; service remains disabled.\n",
                           stdout);
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
