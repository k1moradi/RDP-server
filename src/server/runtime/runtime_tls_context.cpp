// SPDX-License-Identifier: GPL-3.0-or-later
#include "runtime_tls_context.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <new>
#include <string_view>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

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

namespace rdp_server::server::runtime
{
namespace
{

constexpr std::size_t kMaximumCertificateBytes = 1024U * 1024U;
constexpr std::size_t kMaximumPrivateKeyBytes = 256U * 1024U;
constexpr std::string_view kCertificateBeginMarker =
    "-----BEGIN CERTIFICATE-----";

[[nodiscard]] bool isAbsoluteCredentialPath(std::string_view path) noexcept
{
    if (path.empty() || path.size() > 1024) {
        return false;
    }
#if defined(_WIN32)
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

#if defined(_WIN32)
[[nodiscard]] bool hasRestrictedTlsDacl(
    HANDLE fileHandle, bool privateKey) noexcept
{
    PSID owner = nullptr;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR rawDescriptor = nullptr;
    if (::GetSecurityInfo(fileHandle, SE_FILE_OBJECT,
                          OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                          &owner, nullptr, &dacl, nullptr,
                          &rawDescriptor) != ERROR_SUCCESS) {
        return false;
    }
    struct DescriptorCloser
    {
        void operator()(void *pointer) const noexcept
        {
            (void)::LocalFree(pointer);
        }
    };
    std::unique_ptr<void, DescriptorCloser> descriptor{rawDescriptor};
    if (!descriptor || owner == nullptr || !::IsValidSid(owner) ||
        dacl == nullptr || !::IsValidAcl(dacl)) {
        return false;
    }

    constexpr DWORD unsafeRights =
        FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
        FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER |
        GENERIC_WRITE | GENERIC_ALL;
    for (DWORD index = 0; index < dacl->AceCount; ++index) {
        void *rawAce = nullptr;
        if (!::GetAce(dacl, index, &rawAce) || rawAce == nullptr) {
            return false;
        }
        const auto *header = static_cast<const ACE_HEADER *>(rawAce);
        if ((header->AceFlags & INHERIT_ONLY_ACE) != 0) {
            continue;
        }
        if (header->AceType == ACCESS_DENIED_ACE_TYPE) {
            continue;
        }
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE ||
            header->AceSize < sizeof(ACCESS_ALLOWED_ACE)) {
            return false;
        }
        auto *allow = static_cast<ACCESS_ALLOWED_ACE *>(rawAce);
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
            return false;
        }
    }
    return true;
}
#else
[[nodiscard]] int openTlsFileWithoutSymlinkParents(
    std::string_view path) noexcept
{
    if (path.size() < 2 || path.front() != '/') {
        return -1;
    }
    int parentDescriptor =
        ::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (parentDescriptor < 0) {
        return -1;
    }
    path.remove_prefix(1);
    while (true) {
        const std::size_t separator = path.find('/');
        const std::string_view component = path.substr(0, separator);
        if (component.empty() || component == "." || component == "..") {
            (void)::close(parentDescriptor);
            return -1;
        }
        std::array<char, 1025> terminatedComponent{};
        std::copy(component.begin(), component.end(), terminatedComponent.begin());
        const int flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK |
            (separator == std::string_view::npos ? 0 : O_DIRECTORY);
        const int openedDescriptor =
            ::openat(parentDescriptor, terminatedComponent.data(), flags);
        (void)::close(parentDescriptor);
        if (openedDescriptor < 0) {
            return -1;
        }
        if (separator == std::string_view::npos) {
            return openedDescriptor;
        }
        parentDescriptor = openedDescriptor;
        path.remove_prefix(separator + 1);
    }
}
#endif

struct FileCloser
{
    void operator()(std::FILE *file) const noexcept
    {
        (void)std::fclose(file);
    }
};
using OwnedFile = std::unique_ptr<std::FILE, FileCloser>;

struct TlsFileIdentity
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

[[nodiscard]] bool sameTlsFileIdentity(
    const TlsFileIdentity &left, const TlsFileIdentity &right) noexcept
{
#if defined(_WIN32)
    return left.volume == right.volume &&
           left.indexHigh == right.indexHigh &&
           left.indexLow == right.indexLow;
#else
    return left.device == right.device && left.inode == right.inode;
#endif
}

[[nodiscard]] OwnedFile openTlsFile(
    std::string_view path, bool privateKey,
    TlsFileIdentity &identity, std::size_t &openedBytes) noexcept
{
    openedBytes = 0;
    const std::size_t maximumBytes =
        privateKey ? kMaximumPrivateKeyBytes : kMaximumCertificateBytes;
    if (!isAbsoluteCredentialPath(path)) {
        return {};
    }
#if defined(_WIN32)
    std::array<char, 1025> terminatedPath{};
    std::copy(path.begin(), path.end(), terminatedPath.begin());
    const HANDLE handle = ::CreateFileA(
        terminatedPath.data(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return {};
    }
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
        ::GetFileType(handle) == FILE_TYPE_DISK && haveAttributes &&
        (attributes.FileAttributes &
         (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0 &&
        haveInformation && fileBytes > 0 && fileBytes <= maximumBytes &&
        hasRestrictedTlsDacl(handle, privateKey);
    if (!safe) {
        (void)::CloseHandle(handle);
        return {};
    }
    identity.volume = information.dwVolumeSerialNumber;
    identity.indexHigh = information.nFileIndexHigh;
    identity.indexLow = information.nFileIndexLow;
    openedBytes = static_cast<std::size_t>(fileBytes);
    const int descriptor = ::_open_osfhandle(
        reinterpret_cast<std::intptr_t>(handle), _O_RDONLY | _O_BINARY);
    if (descriptor < 0) {
        (void)::CloseHandle(handle);
        openedBytes = 0;
        return {};
    }
    OwnedFile file{::_fdopen(descriptor, "rb")};
    if (!file) {
        (void)::_close(descriptor);
        openedBytes = 0;
        return {};
    }
    return file;
#else
    const int descriptor = openTlsFileWithoutSymlinkParents(path);
    if (descriptor < 0) {
        return {};
    }
    struct stat information {};
    const bool safe = ::fstat(descriptor, &information) == 0 &&
        S_ISREG(information.st_mode) && information.st_size > 0 &&
        information.st_size <= static_cast<off_t>(maximumBytes) &&
        (information.st_mode & (S_IWGRP | S_IWOTH)) == 0 &&
        (!privateKey ||
         (information.st_uid == ::geteuid() &&
          (information.st_mode & (S_IRWXG | S_IRWXO)) == 0 &&
          (information.st_mode & S_IRUSR) != 0));
    if (!safe) {
        (void)::close(descriptor);
        return {};
    }
    identity.device = information.st_dev;
    identity.inode = information.st_ino;
    openedBytes = static_cast<std::size_t>(information.st_size);
    OwnedFile file{::fdopen(descriptor, "rb")};
    if (!file) {
        (void)::close(descriptor);
        openedBytes = 0;
        return {};
    }
    return file;
#endif
}

struct BioCloser
{
    void operator()(BIO *bio) const noexcept { ::BIO_free(bio); }
};
struct X509Closer
{
    void operator()(X509 *certificate) const noexcept { ::X509_free(certificate); }
};
struct PkeyCloser
{
    void operator()(EVP_PKEY *key) const noexcept { ::EVP_PKEY_free(key); }
};

using OwnedBio = std::unique_ptr<BIO, BioCloser>;
using OwnedCertificate = std::unique_ptr<X509, X509Closer>;
using OwnedPrivateKey = std::unique_ptr<EVP_PKEY, PkeyCloser>;

struct ValidatedTlsCredentials
{
    OwnedCertificate certificate{};
    OwnedPrivateKey privateKey{};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return certificate != nullptr && privateKey != nullptr;
    }
};

int rejectPrivateKeyPassword(char *, int, int, void *) noexcept
{
    return 0;
}

[[nodiscard]] bool readOpenedFileExactly(
    std::FILE *file, std::size_t bytes,
    std::unique_ptr<unsigned char[]> &output) noexcept
{
    if (file == nullptr || bytes == 0) {
        return false;
    }
    std::unique_ptr<unsigned char[]> buffer{
        new (std::nothrow) unsigned char[bytes]};
    if (!buffer) {
        return false;
    }
    if (std::fread(buffer.get(), 1, bytes, file) != bytes ||
        std::ferror(file) != 0 || std::fgetc(file) != EOF) {
        return false;
    }
    output = std::move(buffer);
    return true;
}

[[nodiscard]] bool isPemWhitespace(unsigned char value) noexcept
{
    return value == ' ' || value == '\t' || value == '\r' || value == '\n';
}

[[nodiscard]] bool beginsWithExpectedPemObject(
    const unsigned char *data, std::size_t bytes,
    std::string_view expectedMarker) noexcept
{
    if (data == nullptr || bytes < expectedMarker.size()) {
        return false;
    }
    std::size_t offset = 0;
    while (offset < bytes && isPemWhitespace(data[offset])) {
        ++offset;
    }
    if (bytes - offset < expectedMarker.size()) {
        return false;
    }
    return std::equal(expectedMarker.begin(), expectedMarker.end(),
                      reinterpret_cast<const char *>(data + offset));
}

[[nodiscard]] bool bioRemainderIsWhitespace(BIO *bio) noexcept
{
    if (bio == nullptr) {
        return false;
    }
    std::array<unsigned char, 256> buffer{};
    while (true) {
        std::size_t bytesRead = 0;
        const int result =
            ::BIO_read_ex(bio, buffer.data(), buffer.size(), &bytesRead);
        for (std::size_t index = 0; index < bytesRead; ++index) {
            if (!isPemWhitespace(buffer[index])) {
                return false;
            }
        }
        if (result != 1) {
            return bytesRead == 0 && !::BIO_should_retry(bio);
        }
        if (bytesRead == 0) {
            return true;
        }
    }
}

[[nodiscard]] bool hasCurrentCertificateValidity(
    const X509 *certificate) noexcept
{
    if (certificate == nullptr) {
        return false;
    }
#if OPENSSL_VERSION_NUMBER >= 0x40000000L
    return ::X509_check_certificate_times(nullptr, certificate, nullptr) == 1;
#else
    const int notBeforeComparison =
        ::X509_cmp_current_time(::X509_get0_notBefore(certificate));
    const int notAfterComparison =
        ::X509_cmp_current_time(::X509_get0_notAfter(certificate));
    return notBeforeComparison == -1 && notAfterComparison == 1;
#endif
}

[[nodiscard]] ValidatedTlsCredentials loadValidatedTlsCredentials(
    std::string_view certificatePath,
    std::string_view privateKeyPath) noexcept
{
    TlsFileIdentity certificateIdentity{};
    TlsFileIdentity privateKeyIdentity{};
    std::size_t certificateBytes = 0;
    std::size_t privateKeyBytes = 0;
    OwnedFile certificateFile = openTlsFile(
        certificatePath, false, certificateIdentity, certificateBytes);
    OwnedFile privateKeyFile = openTlsFile(
        privateKeyPath, true, privateKeyIdentity, privateKeyBytes);
    if (!certificateFile || !privateKeyFile ||
        sameTlsFileIdentity(certificateIdentity, privateKeyIdentity)) {
        return {};
    }

    std::unique_ptr<unsigned char[]> certificateData;
    std::unique_ptr<unsigned char[]> privateKeyData;
    if (!readOpenedFileExactly(
            certificateFile.get(), certificateBytes, certificateData) ||
        !readOpenedFileExactly(
            privateKeyFile.get(), privateKeyBytes, privateKeyData)) {
        return {};
    }

    if (!beginsWithExpectedPemObject(
            certificateData.get(), certificateBytes,
            kCertificateBeginMarker) ||
        !beginsWithExpectedPemObject(
            privateKeyData.get(), privateKeyBytes, "-----BEGIN ")) {
        return {};
    }

    OwnedBio certificateBio{::BIO_new_mem_buf(
        certificateData.get(), static_cast<int>(certificateBytes))};
    OwnedBio privateKeyBio{::BIO_new_mem_buf(
        privateKeyData.get(), static_cast<int>(privateKeyBytes))};
    if (!certificateBio || !privateKeyBio) {
        return {};
    }

    OwnedCertificate certificate{
        ::PEM_read_bio_X509(certificateBio.get(), nullptr, nullptr, nullptr)};
    OwnedPrivateKey privateKey{::PEM_read_bio_PrivateKey(
        privateKeyBio.get(), nullptr, rejectPrivateKeyPassword, nullptr)};
    if (!certificate || !privateKey ||
        !bioRemainderIsWhitespace(certificateBio.get()) ||
        !bioRemainderIsWhitespace(privateKeyBio.get()) ||
        !hasCurrentCertificateValidity(certificate.get()) ||
        ::X509_check_private_key(certificate.get(), privateKey.get()) != 1 ||
        ::X509_check_purpose(
            certificate.get(), X509_PURPOSE_SSL_SERVER, 0) != 1) {
        return {};
    }

    return {std::move(certificate), std::move(privateKey)};
}

} // namespace

bool validateTlsFileReferences(
    std::string_view certificatePath,
    std::string_view privateKeyPath) noexcept
{
    TlsFileIdentity certificateIdentity{};
    TlsFileIdentity privateKeyIdentity{};
    std::size_t certificateBytes = 0;
    std::size_t privateKeyBytes = 0;
    OwnedFile certificate = openTlsFile(
        certificatePath, false, certificateIdentity, certificateBytes);
    OwnedFile privateKey = openTlsFile(
        privateKeyPath, true, privateKeyIdentity, privateKeyBytes);
    return certificate && privateKey && certificateBytes > 0 &&
           privateKeyBytes > 0 &&
           !sameTlsFileIdentity(certificateIdentity, privateKeyIdentity);
}

bool validateTlsCredentialContents(
    std::string_view certificatePath,
    std::string_view privateKeyPath) noexcept
{
    return static_cast<bool>(
        loadValidatedTlsCredentials(certificatePath, privateKeyPath));
}

RuntimeServerTlsContext RuntimeServerTlsContext::fromCredentialFiles(
    std::string_view certificatePath,
    std::string_view privateKeyPath) noexcept
{
    ValidatedTlsCredentials credentials =
        loadValidatedTlsCredentials(certificatePath, privateKeyPath);
    if (!credentials) {
        return {};
    }

    OwnedContext context{::SSL_CTX_new(::TLS_server_method()), &::SSL_CTX_free};
    if (!context ||
        ::SSL_CTX_set_min_proto_version(context.get(), TLS1_2_VERSION) != 1) {
        return {};
    }

    std::uint64_t requiredOptions = SSL_OP_NO_COMPRESSION;
#if defined(SSL_OP_NO_RENEGOTIATION)
    requiredOptions |= SSL_OP_NO_RENEGOTIATION;
#endif
    const std::uint64_t configuredOptions =
        ::SSL_CTX_set_options(context.get(), requiredOptions);
    if ((configuredOptions & requiredOptions) != requiredOptions ||
        ::SSL_CTX_use_certificate(
            context.get(), credentials.certificate.get()) != 1 ||
        ::SSL_CTX_use_PrivateKey(
            context.get(), credentials.privateKey.get()) != 1 ||
        ::SSL_CTX_check_private_key(context.get()) != 1) {
        return {};
    }

    return RuntimeServerTlsContext{std::move(context)};
}

RuntimeServerTlsContext::ServerTls
RuntimeServerTlsContext::createServerTls() const noexcept
{
    ServerTls serverTls{context_ ? ::SSL_new(context_.get()) : nullptr,
                        &::SSL_free};
    if (serverTls) {
        ::SSL_set_accept_state(serverTls.get());
    }
    return serverTls;
}

int RuntimeServerTlsContext::minimumProtocolVersion() const noexcept
{
    return context_ ? ::SSL_CTX_get_min_proto_version(context_.get()) : 0;
}

std::uint64_t RuntimeServerTlsContext::options() const noexcept
{
    return context_ ? ::SSL_CTX_get_options(context_.get()) : 0U;
}

const X509 *RuntimeServerTlsContext::certificate() const noexcept
{
    return context_ ? ::SSL_CTX_get0_certificate(context_.get()) : nullptr;
}

} // namespace rdp_server::server::runtime
