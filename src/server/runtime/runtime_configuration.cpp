// SPDX-License-Identifier: GPL-3.0-or-later
#include "runtime_configuration.h"

#include "runtime_licensing_context.h"
#include "server/transport/rdp_licensing.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <memory>
#include <span>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#include <fcntl.h>
#include <io.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace rdp_server::server::runtime
{
namespace
{
constexpr std::size_t kMaximumConfigurationBytes = 4096U;
constexpr std::size_t kBaseConfigurationFieldCount = 7U;
constexpr std::size_t kLicensingFieldStart =
    static_cast<std::size_t>(RuntimeConfigurationField::LicensingCertificate);
constexpr std::size_t kAfterLicensingField =
    static_cast<std::size_t>(RuntimeConfigurationField::GssServicePrincipal);
constexpr std::size_t kLinuxSecurityFieldStart = kAfterLicensingField;
constexpr std::size_t kLinuxSecurityFieldEndWithoutPam =
    static_cast<std::size_t>(RuntimeConfigurationField::PamService);
constexpr std::size_t kLinuxSecurityFieldEndWithPam =
    kRuntimeConfigurationFieldCount;

constexpr std::array<std::string_view, kRuntimeConfigurationFieldCount>
    kConfigurationFields{
        "listen_address", "listen_port", "tls_certificate", "tls_private_key",
        "authentication", "os_authorization", "max_connections",
        "licensing_certificate", "licensing_private_key",
        "licensing_product_version", "licensing_company_name",
        "licensing_product_id", "licensing_scope",
        "gss_service_principal", "gss_keytab",
        "authorized_kerberos_principal", "authorized_unix_account",
        "authorized_seat", "authorized_display", "authorized_uid",
        "authorized_permissions", "pam_service"};

[[nodiscard]] constexpr std::string_view trimWhitespace(
    std::string_view value) noexcept
{
    while (!value.empty() &&
           (value.front() == ' ' || value.front() == '\t'))
        value.remove_prefix(1U);
    while (!value.empty() &&
           (value.back() == ' ' || value.back() == '\t'))
        value.remove_suffix(1U);
    return value;
}

[[nodiscard]] bool parseUnsigned32Decimal(
    std::string_view value,
    std::uint32_t& parsedValue) noexcept
{
    if (value.empty())
        return false;
    parsedValue = 0U;
    constexpr std::uint32_t maximumValue =
        (std::numeric_limits<std::uint32_t>::max)();
    for (const char digit : value)
    {
        if (digit < '0' || digit > '9')
            return false;
        const auto numericDigit =
            static_cast<std::uint32_t>(static_cast<unsigned>(digit - '0'));
        if (parsedValue > (maximumValue - numericDigit) / 10U)
            return false;
        parsedValue = parsedValue * 10U + numericDigit;
    }
    return parsedValue != 0U;
}

[[nodiscard]] bool isAbsoluteConfigurationPath(
    std::string_view path) noexcept
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
        const bool separator =
            index == path.size() || path[index] == '/'
#if defined(_WIN32)
            || path[index] == '\\'
#endif
            ;
        if (!separator)
            continue;
        const auto component =
            path.substr(componentStart, index - componentStart);
        if (component == "..")
            return false;
        componentStart = index + 1U;
    }
    return true;
}

constexpr std::size_t kMaximumLicensingIdentityBytes =
    rdp_server::server::transport::kMaximumRdpServerLicenseIdentityTextBytes;

struct ParsedLicensingIdentity final
{
    std::array<std::uint8_t, kMaximumLicensingIdentityBytes>
        companyNameUtf16{};
    std::array<std::uint8_t, kMaximumLicensingIdentityBytes>
        productIdUtf16{};
    std::array<std::uint8_t, kMaximumLicensingIdentityBytes> scopeAnsi{};
    std::size_t companyNameUtf16Bytes{};
    std::size_t productIdUtf16Bytes{};
    std::size_t scopeAnsiBytes{};
    std::uint32_t productVersion{};
};

[[nodiscard]] bool encodeLicensingUtf8AsUtf16Le(
    std::string_view value,
    std::span<std::uint8_t> output,
    std::size_t& bytesWritten) noexcept
{
    bytesWritten = 0U;
    if (value.empty() || output.size() < 4U)
        return false;

    std::size_t inputOffset = 0U;
    while (inputOffset < value.size())
    {
        const auto first =
            static_cast<std::uint8_t>(
                static_cast<unsigned char>(value[inputOffset]));
        std::uint32_t codePoint = 0U;
        std::size_t sequenceBytes = 0U;
        if (first <= 0x7fU)
        {
            codePoint = first;
            sequenceBytes = 1U;
        }
        else if (first >= 0xc2U && first <= 0xdfU)
        {
            if (inputOffset + 1U >= value.size())
                return false;
            const auto second = static_cast<std::uint8_t>(
                static_cast<unsigned char>(value[inputOffset + 1U]));
            if ((second & 0xc0U) != 0x80U)
                return false;
            codePoint =
                (static_cast<std::uint32_t>(first & 0x1fU) << 6U) |
                static_cast<std::uint32_t>(second & 0x3fU);
            sequenceBytes = 2U;
        }
        else if (first >= 0xe0U && first <= 0xefU)
        {
            if (inputOffset + 2U >= value.size())
                return false;
            const auto second = static_cast<std::uint8_t>(
                static_cast<unsigned char>(value[inputOffset + 1U]));
            const auto third = static_cast<std::uint8_t>(
                static_cast<unsigned char>(value[inputOffset + 2U]));
            if ((second & 0xc0U) != 0x80U ||
                (third & 0xc0U) != 0x80U ||
                (first == 0xe0U && second < 0xa0U) ||
                (first == 0xedU && second > 0x9fU))
                return false;
            codePoint =
                (static_cast<std::uint32_t>(first & 0x0fU) << 12U) |
                (static_cast<std::uint32_t>(second & 0x3fU) << 6U) |
                static_cast<std::uint32_t>(third & 0x3fU);
            sequenceBytes = 3U;
        }
        else if (first >= 0xf0U && first <= 0xf4U)
        {
            if (inputOffset + 3U >= value.size())
                return false;
            const auto second = static_cast<std::uint8_t>(
                static_cast<unsigned char>(value[inputOffset + 1U]));
            const auto third = static_cast<std::uint8_t>(
                static_cast<unsigned char>(value[inputOffset + 2U]));
            const auto fourth = static_cast<std::uint8_t>(
                static_cast<unsigned char>(value[inputOffset + 3U]));
            if ((second & 0xc0U) != 0x80U ||
                (third & 0xc0U) != 0x80U ||
                (fourth & 0xc0U) != 0x80U ||
                (first == 0xf0U && second < 0x90U) ||
                (first == 0xf4U && second > 0x8fU))
                return false;
            codePoint =
                (static_cast<std::uint32_t>(first & 0x07U) << 18U) |
                (static_cast<std::uint32_t>(second & 0x3fU) << 12U) |
                (static_cast<std::uint32_t>(third & 0x3fU) << 6U) |
                static_cast<std::uint32_t>(fourth & 0x3fU);
            sequenceBytes = 4U;
        }
        else
        {
            return false;
        }

        if (codePoint <= 0x1fU ||
            (codePoint >= 0x7fU && codePoint <= 0x9fU))
            return false;

        if (codePoint <= 0xffffU)
        {
            if (bytesWritten + 4U > output.size())
                return false;
            output[bytesWritten] =
                static_cast<std::uint8_t>(codePoint & 0xffU);
            output[bytesWritten + 1U] =
                static_cast<std::uint8_t>((codePoint >> 8U) & 0xffU);
            bytesWritten += 2U;
        }
        else
        {
            if (bytesWritten + 6U > output.size())
                return false;
            const std::uint32_t supplementary = codePoint - 0x10000U;
            const std::uint16_t high = static_cast<std::uint16_t>(
                0xd800U + (supplementary >> 10U));
            const std::uint16_t low = static_cast<std::uint16_t>(
                0xdc00U + (supplementary & 0x3ffU));
            output[bytesWritten] =
                static_cast<std::uint8_t>(high & 0xffU);
            output[bytesWritten + 1U] =
                static_cast<std::uint8_t>((high >> 8U) & 0xffU);
            output[bytesWritten + 2U] =
                static_cast<std::uint8_t>(low & 0xffU);
            output[bytesWritten + 3U] =
                static_cast<std::uint8_t>((low >> 8U) & 0xffU);
            bytesWritten += 4U;
        }
        inputOffset += sequenceBytes;
    }

    if (bytesWritten == 0U || bytesWritten + 2U > output.size())
        return false;
    output[bytesWritten++] = 0U;
    output[bytesWritten++] = 0U;
    return true;
}

[[nodiscard]] bool encodeLicensingScopeAnsi(
    std::string_view value,
    std::span<std::uint8_t> output,
    std::size_t& bytesWritten) noexcept
{
    bytesWritten = 0U;
    if (value.empty() || value.size() + 1U > output.size())
        return false;
    for (const char character : value)
    {
        const auto byte =
            static_cast<std::uint8_t>(
                static_cast<unsigned char>(character));
        if (byte < 0x20U || byte > 0x7eU)
            return false;
        output[bytesWritten++] = byte;
    }
    output[bytesWritten++] = 0U;
    return true;
}

[[nodiscard]] bool parseLicensingIdentity(
    const RuntimeConfigurationView& configuration,
    ParsedLicensingIdentity& identity) noexcept
{
    using Field = RuntimeConfigurationField;
    if (!parseUnsigned32Decimal(
            configuration.field(Field::LicensingProductVersion),
            identity.productVersion) ||
        !encodeLicensingUtf8AsUtf16Le(
            configuration.field(Field::LicensingCompanyName),
            identity.companyNameUtf16,
            identity.companyNameUtf16Bytes) ||
        !encodeLicensingUtf8AsUtf16Le(
            configuration.field(Field::LicensingProductId),
            identity.productIdUtf16,
            identity.productIdUtf16Bytes) ||
        !encodeLicensingScopeAnsi(
            configuration.field(Field::LicensingScope),
            identity.scopeAnsi,
            identity.scopeAnsiBytes))
        return false;

    const auto certificate =
        configuration.field(Field::LicensingCertificate);
    const auto privateKey =
        configuration.field(Field::LicensingPrivateKey);
    return isAbsoluteConfigurationPath(certificate) &&
           isAbsoluteConfigurationPath(privateKey) &&
           certificate != privateKey;
}

[[nodiscard]] bool hasCompleteOptionalGroup(
    const std::array<bool, kRuntimeConfigurationFieldCount>& fieldSeen,
    std::size_t begin,
    std::size_t end) noexcept
{
    bool any = false;
    bool all = true;
    for (std::size_t index = begin; index < end; ++index)
    {
        any = any || fieldSeen[index];
        all = all && fieldSeen[index];
    }
    return !any || all;
}

[[nodiscard]] bool parseConfiguration(
    std::string_view text,
    RuntimeConfigurationCapabilities capabilities,
    RuntimeConfigurationVisitor visitor,
    void* context) noexcept
{
    if (visitor == nullptr || (capabilities.linuxPam &&
                               !capabilities.linuxSecurity))
        return false;

    RuntimeConfigurationView::Fields fieldValues{};
    std::array<bool, kRuntimeConfigurationFieldCount> fieldSeen{};

    while (!text.empty())
    {
        const auto lineEnd = text.find('\n');
        auto line = text.substr(0U, lineEnd);
        text = lineEnd == std::string_view::npos
            ? std::string_view{} : text.substr(lineEnd + 1U);
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1U);
        line = trimWhitespace(line);

        for (const char character : line)
        {
            const auto codePoint =
                static_cast<unsigned char>(character);
            if ((codePoint < 0x20U && codePoint != '\t') ||
                codePoint == 0x7fU)
                return false;
        }
        if (line.empty() || line.front() == '#')
            continue;

        const auto separator = line.find('=');
        if (separator == std::string_view::npos)
            return false;
        const auto fieldName =
            trimWhitespace(line.substr(0U, separator));
        const auto value =
            trimWhitespace(line.substr(separator + 1U));

        std::size_t fieldIndex = kRuntimeConfigurationFieldCount;
        for (std::size_t index = 0U;
             index < kConfigurationFields.size(); ++index)
        {
            if (fieldName == kConfigurationFields[index])
            {
                fieldIndex = index;
                break;
            }
        }
        if (fieldIndex == kRuntimeConfigurationFieldCount ||
            fieldSeen[fieldIndex] || value.empty())
            return false;
        if (fieldIndex >= kLinuxSecurityFieldStart &&
            !capabilities.linuxSecurity)
            return false;
        if (fieldIndex ==
                static_cast<std::size_t>(
                    RuntimeConfigurationField::PamService) &&
            !capabilities.linuxPam)
            return false;

        fieldSeen[fieldIndex] = true;
        fieldValues[fieldIndex] = value;
    }

    for (std::size_t index = 0U;
         index < kBaseConfigurationFieldCount; ++index)
    {
        if (!fieldSeen[index])
            return false;
    }
    if (!hasCompleteOptionalGroup(
            fieldSeen, kLicensingFieldStart, kAfterLicensingField))
        return false;

    const std::size_t linuxSecurityEnd = capabilities.linuxPam
        ? kLinuxSecurityFieldEndWithPam
        : kLinuxSecurityFieldEndWithoutPam;
    if (capabilities.linuxSecurity &&
        !hasCompleteOptionalGroup(
            fieldSeen, kLinuxSecurityFieldStart, linuxSecurityEnd))
        return false;

    const RuntimeConfigurationView view{fieldValues};
    if (fieldSeen[kLicensingFieldStart])
    {
        ParsedLicensingIdentity identity{};
        if (!parseLicensingIdentity(view, identity))
            return false;
    }

    unsigned ignored = 0U;
    using Field = RuntimeConfigurationField;
    const bool valid =
        (view.field(Field::ListenAddress) == "127.0.0.1" ||
         view.field(Field::ListenAddress) == "::1") &&
        parseRuntimeConfigurationDecimal(
            view.field(Field::ListenPort), 1U, 65535U, ignored) &&
        isAbsoluteConfigurationPath(view.field(Field::TlsCertificate)) &&
        isAbsoluteConfigurationPath(view.field(Field::TlsPrivateKey)) &&
        view.field(Field::TlsCertificate) !=
            view.field(Field::TlsPrivateKey) &&
        view.field(Field::Authentication) == "required" &&
        view.field(Field::OsAuthorization) == "required" &&
        parseRuntimeConfigurationDecimal(
            view.field(Field::MaxConnections), 1U, 64U, ignored);
    return valid && visitor(view, context);
}

#if defined(_WIN32)
[[nodiscard]] bool hasRestrictedConfigurationDacl(
    HANDLE fileHandle) noexcept
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
        void operator()(void* pointer) const noexcept
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
        void* rawAce = nullptr;
        if (!::GetAce(dacl, index, &rawAce) || rawAce == nullptr)
            return false;
        const auto* header =
            static_cast<const ACE_HEADER*>(rawAce);
        if ((header->AceFlags & INHERIT_ONLY_ACE) != 0U)
            continue;
        if (header->AceType == ACCESS_DENIED_ACE_TYPE)
            continue;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE ||
            header->AceSize < sizeof(ACCESS_ALLOWED_ACE))
            return false;
        auto* allow =
            static_cast<ACCESS_ALLOWED_ACE*>(rawAce);
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
        if (broadPrincipal && (allow->Mask & unsafeRights) != 0U)
            return false;
    }
    return true;
}
#endif

struct FileCloser final
{
    void operator()(std::FILE* file) const noexcept
    {
        (void)std::fclose(file);
    }
};
} // namespace

bool parseRuntimeConfigurationDecimal(
    std::string_view value,
    unsigned minimum,
    unsigned maximum,
    unsigned& parsedValue) noexcept
{
    if (value.empty() || minimum > maximum)
        return false;
    parsedValue = 0U;
    for (const char digit : value)
    {
        if (digit < '0' || digit > '9')
            return false;
        const auto numericDigit =
            static_cast<unsigned>(digit - '0');
        if (parsedValue > (maximum - numericDigit) / 10U)
            return false;
        parsedValue = parsedValue * 10U + numericDigit;
    }
    return parsedValue >= minimum;
}

bool visitRuntimeConfigurationText(
    std::string_view text,
    RuntimeConfigurationCapabilities capabilities,
    RuntimeConfigurationVisitor visitor,
    void* context) noexcept
{
    if (text.empty() || text.size() > kMaximumConfigurationBytes)
        return false;
    return parseConfiguration(text, capabilities, visitor, context);
}

bool visitRuntimeConfigurationFile(
    const char* path,
    RuntimeConfigurationCapabilities capabilities,
    RuntimeConfigurationVisitor visitor,
    void* context) noexcept
{
    if (path == nullptr || *path == '\0' || visitor == nullptr)
        return false;
#if !defined(_WIN32)
    const int configurationDescriptor =
        ::open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (configurationDescriptor < 0)
        return false;
    std::unique_ptr<std::FILE, FileCloser> file{
        ::fdopen(configurationDescriptor, "rb")};
    if (!file)
    {
        (void)::close(configurationDescriptor);
        return false;
    }
    struct stat openedFileStatus {};
    if (::fstat(configurationDescriptor, &openedFileStatus) != 0 ||
        !S_ISREG(openedFileStatus.st_mode) ||
        (openedFileStatus.st_mode & (S_IWGRP | S_IWOTH)) != 0)
        return false;
#else
    if (!isAbsoluteConfigurationPath(path))
        return false;
    struct NativeHandleCloser final
    {
        void operator()(void* nativeHandle) const noexcept
        {
            (void)::CloseHandle(nativeHandle);
        }
    };
    const HANDLE openedHandle = ::CreateFileA(
        path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
        nullptr);
    if (openedHandle == INVALID_HANDLE_VALUE)
        return false;
    std::unique_ptr<void, NativeHandleCloser> nativeHandle{
        openedHandle};
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    if (::GetFileType(nativeHandle.get()) != FILE_TYPE_DISK ||
        !::GetFileInformationByHandleEx(
            nativeHandle.get(), FileAttributeTagInfo,
            &attributes, sizeof(attributes)) ||
        (attributes.FileAttributes &
         (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0U ||
        !hasRestrictedConfigurationDacl(
            static_cast<HANDLE>(nativeHandle.get())))
        return false;
    const int descriptor = ::_open_osfhandle(
        reinterpret_cast<std::intptr_t>(nativeHandle.get()),
        _O_RDONLY | _O_BINARY);
    if (descriptor < 0)
        return false;
    (void)nativeHandle.release();
    std::unique_ptr<std::FILE, FileCloser> file{
        ::_fdopen(descriptor, "rb")};
    if (!file)
    {
        (void)::_close(descriptor);
        return false;
    }
#endif

    std::array<char, kMaximumConfigurationBytes + 1U> bytes{};
    const std::size_t bytesRead =
        std::fread(bytes.data(), sizeof(char), bytes.size(), file.get());
    if (std::ferror(file.get()) != 0 || bytesRead == 0U ||
        bytesRead > kMaximumConfigurationBytes)
        return false;
    return visitRuntimeConfigurationText(
        std::string_view{bytes.data(), bytesRead},
        capabilities, visitor, context);
}

bool configureRuntimeLicensingContextFromConfiguration(
    const RuntimeConfigurationView& configuration,
    RuntimeLicensingContext& licensingContext) noexcept
{
    using Field = RuntimeConfigurationField;
    if (configuration.field(Field::LicensingCertificate).empty())
        return false;

    ParsedLicensingIdentity identity{};
    if (!parseLicensingIdentity(configuration, identity) ||
        !licensingContext.configureFromCredentialFiles(
            identity.productVersion,
            std::span{identity.companyNameUtf16}.first(
                identity.companyNameUtf16Bytes),
            std::span{identity.productIdUtf16}.first(
                identity.productIdUtf16Bytes),
            configuration.field(Field::LicensingCertificate),
            std::span{identity.scopeAnsi}.first(
                identity.scopeAnsiBytes),
            configuration.field(Field::LicensingPrivateKey)))
        return false;

    const auto* configuredIdentity = licensingContext.identity();
    const auto* credential = licensingContext.credential();
    return licensingContext.configured() &&
           configuredIdentity != nullptr && credential != nullptr &&
           configuredIdentity->productVersion() ==
               identity.productVersion &&
           credential->matches(*configuredIdentity);
}

} // namespace rdp_server::server::runtime
