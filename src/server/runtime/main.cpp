// SPDX-License-Identifier: GPL-3.0-or-later
// R10 process entry point. Listener startup is explicit and loopback-only.
// TCP accept alone is never admission: only the serialized R1 TLS/CredSSP
// owner plus genuine R2 native authorization can cross that boundary.
// Offline configuration checks still do not authenticate or start a user.
#include "runtime_tls_context.h"
#include "runtime_licensing_context.h"
#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
#include "linux_runtime_security.h"
#include "linux_runtime_connection.h"
#include "runtime_deployment_policy.h"
#include "server/transport/nonblocking_tcp_adapter.h"
#endif

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <memory>
#include <span>
#include <string_view>
#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
#include <chrono>
#include <cstring>
#endif

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

#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/resource.h>
#include <sys/socket.h>
#endif

#ifndef RDP_SERVER_VERSION
#error "The build system must provide the RDP server version"
#endif

namespace {
constexpr int kSecureStartupUnavailableExitCode = 2;
constexpr int kInvalidConfigurationExitCode = 3;
constexpr std::size_t kMaximumConfigurationBytes = 4096;
#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
constexpr std::chrono::seconds kLinuxSerializedConnectionDeadline{30};
#endif

constexpr std::size_t kBaseConfigurationFieldCount = 7;
constexpr std::size_t kLicensingConfigurationFieldCount = 6;
constexpr std::size_t kLicensingFieldStart = kBaseConfigurationFieldCount;
constexpr std::size_t kLicensingCertificateField = kLicensingFieldStart;
constexpr std::size_t kLicensingPrivateKeyField = kLicensingFieldStart + 1U;
constexpr std::size_t kLicensingProductVersionField = kLicensingFieldStart + 2U;
constexpr std::size_t kLicensingCompanyNameField = kLicensingFieldStart + 3U;
constexpr std::size_t kLicensingProductIdField = kLicensingFieldStart + 4U;
constexpr std::size_t kLicensingScopeField = kLicensingFieldStart + 5U;
constexpr std::size_t kAfterLicensingField =
    kLicensingFieldStart + kLicensingConfigurationFieldCount;
#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
#if defined(RDP_SERVER_HAVE_LINUX_PAM_PASSWORD_VERIFIER)
constexpr std::array<std::string_view, 22> kConfigurationFields{
    "listen_address", "listen_port", "tls_certificate", "tls_private_key",
    "authentication", "os_authorization", "max_connections",
    "licensing_certificate", "licensing_private_key",
    "licensing_product_version", "licensing_company_name",
    "licensing_product_id", "licensing_scope",
    "gss_service_principal", "gss_keytab",
    "authorized_kerberos_principal", "authorized_unix_account",
    "authorized_seat", "authorized_display", "authorized_uid",
    "authorized_permissions", "pam_service"};
#else
constexpr std::array<std::string_view, 21> kConfigurationFields{
    "listen_address", "listen_port", "tls_certificate", "tls_private_key",
    "authentication", "os_authorization", "max_connections",
    "licensing_certificate", "licensing_private_key",
    "licensing_product_version", "licensing_company_name",
    "licensing_product_id", "licensing_scope",
    "gss_service_principal", "gss_keytab",
    "authorized_kerberos_principal", "authorized_unix_account",
    "authorized_seat", "authorized_display", "authorized_uid",
    "authorized_permissions"};
#endif
constexpr std::size_t kLinuxSecurityFieldStart = kAfterLicensingField;
constexpr std::size_t kGssServicePrincipalField = kLinuxSecurityFieldStart;
constexpr std::size_t kGssKeytabField = kLinuxSecurityFieldStart + 1U;
constexpr std::size_t kAuthorizedKerberosPrincipalField =
    kLinuxSecurityFieldStart + 2U;
constexpr std::size_t kAuthorizedUnixAccountField =
    kLinuxSecurityFieldStart + 3U;
constexpr std::size_t kAuthorizedSeatField = kLinuxSecurityFieldStart + 4U;
constexpr std::size_t kAuthorizedDisplayField = kLinuxSecurityFieldStart + 5U;
constexpr std::size_t kAuthorizedUidField = kLinuxSecurityFieldStart + 6U;
constexpr std::size_t kAuthorizedPermissionsField =
    kLinuxSecurityFieldStart + 7U;
#if defined(RDP_SERVER_HAVE_LINUX_PAM_PASSWORD_VERIFIER)
constexpr std::size_t kPamServiceField = kLinuxSecurityFieldStart + 8U;
#endif
#else
constexpr std::array<std::string_view, 13> kConfigurationFields{
    "listen_address", "listen_port", "tls_certificate", "tls_private_key",
    "authentication", "os_authorization", "max_connections",
    "licensing_certificate", "licensing_private_key",
    "licensing_product_version", "licensing_company_name",
    "licensing_product_id", "licensing_scope"};
#endif

[[nodiscard]] constexpr std::string_view trimWhitespace(std::string_view value) noexcept {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.remove_prefix(1);
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
        value.remove_suffix(1);
    }
    return value;
}

[[nodiscard]] constexpr bool parseDecimalWithin(
    std::string_view value, unsigned minimum, unsigned maximum,
    unsigned& parsedValue) noexcept {
    if (value.empty()) {
        return false;
    }
    parsedValue = 0;
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

[[nodiscard]] constexpr bool isDecimalWithin(
    std::string_view value, unsigned minimum, unsigned maximum) noexcept {
    unsigned parsedValue = 0;
    return parseDecimalWithin(value, minimum, maximum, parsedValue);
}

[[nodiscard]] bool parseUnsigned32Decimal(
    std::string_view value, std::uint32_t& parsedValue) noexcept {
    if (value.empty()) {
        return false;
    }
    parsedValue = 0U;
    constexpr std::uint32_t maximumValue =
        (std::numeric_limits<std::uint32_t>::max)();
    for (const char digit : value) {
        if (digit < '0' || digit > '9') {
            return false;
        }
        const auto numericDigit =
            static_cast<std::uint32_t>(static_cast<unsigned>(digit - '0'));
        if (parsedValue >
            (maximumValue - numericDigit) / 10U) {
            return false;
        }
        parsedValue = parsedValue * 10U + numericDigit;
    }
    return parsedValue != 0U;
}

constexpr std::size_t kMaximumLicensingIdentityBytes =
    rdp_server::server::transport::kMaximumRdpServerLicenseIdentityTextBytes;

struct ParsedLicensingIdentity final {
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
    std::string_view value, std::span<std::uint8_t> output,
    std::size_t& bytesWritten) noexcept {
    bytesWritten = 0U;
    if (value.empty() || output.size() < 4U) {
        return false;
    }

    std::size_t inputOffset = 0U;
    while (inputOffset < value.size()) {
        const auto first =
            static_cast<std::uint8_t>(static_cast<unsigned char>(
                value[inputOffset]));
        std::uint32_t codePoint = 0U;
        std::size_t sequenceBytes = 0U;
        if (first <= 0x7fU) {
            codePoint = first;
            sequenceBytes = 1U;
        } else if (first >= 0xc2U && first <= 0xdfU) {
            if (inputOffset + 1U >= value.size()) {
                return false;
            }
            const auto second = static_cast<std::uint8_t>(
                static_cast<unsigned char>(value[inputOffset + 1U]));
            if ((second & 0xc0U) != 0x80U) {
                return false;
            }
            codePoint =
                (static_cast<std::uint32_t>(first & 0x1fU) << 6U) |
                static_cast<std::uint32_t>(second & 0x3fU);
            sequenceBytes = 2U;
        } else if (first >= 0xe0U && first <= 0xefU) {
            if (inputOffset + 2U >= value.size()) {
                return false;
            }
            const auto second = static_cast<std::uint8_t>(
                static_cast<unsigned char>(value[inputOffset + 1U]));
            const auto third = static_cast<std::uint8_t>(
                static_cast<unsigned char>(value[inputOffset + 2U]));
            if ((second & 0xc0U) != 0x80U ||
                (third & 0xc0U) != 0x80U ||
                (first == 0xe0U && second < 0xa0U) ||
                (first == 0xedU && second > 0x9fU)) {
                return false;
            }
            codePoint =
                (static_cast<std::uint32_t>(first & 0x0fU) << 12U) |
                (static_cast<std::uint32_t>(second & 0x3fU) << 6U) |
                static_cast<std::uint32_t>(third & 0x3fU);
            sequenceBytes = 3U;
        } else if (first >= 0xf0U && first <= 0xf4U) {
            if (inputOffset + 3U >= value.size()) {
                return false;
            }
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
                (first == 0xf4U && second > 0x8fU)) {
                return false;
            }
            codePoint =
                (static_cast<std::uint32_t>(first & 0x07U) << 18U) |
                (static_cast<std::uint32_t>(second & 0x3fU) << 12U) |
                (static_cast<std::uint32_t>(third & 0x3fU) << 6U) |
                static_cast<std::uint32_t>(fourth & 0x3fU);
            sequenceBytes = 4U;
        } else {
            return false;
        }

        if (codePoint <= 0x1fU ||
            (codePoint >= 0x7fU && codePoint <= 0x9fU)) {
            return false;
        }

        if (codePoint <= 0xffffU) {
            if (bytesWritten + 4U > output.size()) {
                return false;
            }
            output[bytesWritten] =
                static_cast<std::uint8_t>(codePoint & 0xffU);
            output[bytesWritten + 1U] =
                static_cast<std::uint8_t>((codePoint >> 8U) & 0xffU);
            bytesWritten += 2U;
        } else {
            if (bytesWritten + 6U > output.size()) {
                return false;
            }
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

    if (bytesWritten == 0U || bytesWritten + 2U > output.size()) {
        return false;
    }
    output[bytesWritten++] = 0U;
    output[bytesWritten++] = 0U;
    return true;
}

[[nodiscard]] bool encodeLicensingScopeAnsi(
    std::string_view value, std::span<std::uint8_t> output,
    std::size_t& bytesWritten) noexcept {
    bytesWritten = 0U;
    if (value.empty() || value.size() + 1U > output.size()) {
        return false;
    }
    for (const char character : value) {
        const auto byte =
            static_cast<std::uint8_t>(static_cast<unsigned char>(character));
        if (byte < 0x20U || byte > 0x7eU) {
            return false;
        }
        output[bytesWritten++] = byte;
    }
    output[bytesWritten++] = 0U;
    return true;
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

[[nodiscard]] bool parseLicensingIdentity(
    const std::array<std::string_view, kConfigurationFields.size()>& fields,
    ParsedLicensingIdentity& identity) noexcept {
    if (!parseUnsigned32Decimal(
            fields[kLicensingProductVersionField], identity.productVersion) ||
        !encodeLicensingUtf8AsUtf16Le(
            fields[kLicensingCompanyNameField], identity.companyNameUtf16,
            identity.companyNameUtf16Bytes) ||
        !encodeLicensingUtf8AsUtf16Le(
            fields[kLicensingProductIdField], identity.productIdUtf16,
            identity.productIdUtf16Bytes) ||
        !encodeLicensingScopeAnsi(
            fields[kLicensingScopeField], identity.scopeAnsi,
            identity.scopeAnsiBytes)) {
        return false;
    }
    return isAbsoluteConfigurationPath(fields[kLicensingCertificateField]) &&
           isAbsoluteConfigurationPath(fields[kLicensingPrivateKeyField]) &&
           fields[kLicensingCertificateField] !=
               fields[kLicensingPrivateKeyField];
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
    for (std::size_t index = 0;
         index < kBaseConfigurationFieldCount; ++index) {
        if (!fieldSeen[index]) {
            return false;
        }
    }
    bool anyLicensingField = false;
    bool allLicensingFields = true;
    for (std::size_t index = kLicensingFieldStart;
         index < kAfterLicensingField; ++index) {
        anyLicensingField = anyLicensingField || fieldSeen[index];
        allLicensingFields = allLicensingFields && fieldSeen[index];
    }
    if (anyLicensingField != allLicensingFields) {
        return false;
    }
    if (allLicensingFields) {
        ParsedLicensingIdentity licensingIdentity{};
        if (!parseLicensingIdentity(fieldValues, licensingIdentity)) {
            return false;
        }
    }
#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
    bool anyLinuxSecurityField = false;
    bool allLinuxSecurityFields = true;
    for (std::size_t index = kLinuxSecurityFieldStart;
         index < fieldSeen.size(); ++index) {
        anyLinuxSecurityField = anyLinuxSecurityField || fieldSeen[index];
        allLinuxSecurityFields = allLinuxSecurityFields && fieldSeen[index];
    }
    if (anyLinuxSecurityField && !allLinuxSecurityFields) {
        return false;
    }
#endif
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
[[nodiscard]] bool hasRestrictedConfigurationDacl(HANDLE fileHandle) noexcept {
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
    }
    return true;
}
#endif


struct FileCloser {
    void operator()(std::FILE* file) const noexcept {
        (void)std::fclose(file);
    }
};

#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
[[nodiscard]] bool configureLinuxRuntimeSecurity(
    const std::array<std::string_view, kConfigurationFields.size()>&
        validatedFields,
    rdp_server::server::runtime::LinuxRuntimeSecurityConfiguration&
        linuxSecurity) noexcept {
    for (std::size_t index = kLinuxSecurityFieldStart;
         index < validatedFields.size(); ++index) {
        if (validatedFields[index].empty()) {
            return false;
        }
    }

    unsigned localUid = 0;
    unsigned permissions = 0;
    if (!parseDecimalWithin(
            validatedFields[kAuthorizedUidField], 1U, 0xfffffffeU,
            localUid) ||
        !parseDecimalWithin(
            validatedFields[kAuthorizedPermissionsField], 1U,
            rdp_server::server::security::kConsoleAllowedPermissions,
            permissions)) {
        return false;
    }

    const rdp_server::server::security::ConsoleIdentityRuleInput rule{
        validatedFields[kAuthorizedKerberosPrincipalField],
        validatedFields[kAuthorizedUnixAccountField],
        validatedFields[kAuthorizedSeatField],
        validatedFields[kAuthorizedDisplayField],
        static_cast<std::uint32_t>(localUid),
        static_cast<std::uint32_t>(permissions)};

#if defined(RDP_SERVER_HAVE_LINUX_PAM_PASSWORD_VERIFIER)
    return linuxSecurity.configure(
        validatedFields[kGssServicePrincipalField],
        validatedFields[kGssKeytabField], rule,
        validatedFields[kPamServiceField]);
#else
    return linuxSecurity.configure(
        validatedFields[kGssServicePrincipalField],
        validatedFields[kGssKeytabField], rule);
#endif
}

[[nodiscard]] bool checkLinuxSecurityConfiguration(
    const std::array<std::string_view, kConfigurationFields.size()>&
        validatedFields) noexcept {
    rdp_server::server::runtime::LinuxRuntimeSecurityConfiguration
        linuxSecurity;
    if (!configureLinuxRuntimeSecurity(validatedFields, linuxSecurity)) {
        return false;
    }

    const auto tlsContext =
        rdp_server::server::runtime::RuntimeServerTlsContext::
            fromCredentialFiles(validatedFields[2], validatedFields[3]);
    return tlsContext && linuxSecurity.policy() != nullptr;
}

class LinuxListenerOwner final {
public:
    explicit LinuxListenerOwner(int descriptor) noexcept
        : descriptor_(descriptor) {}
    LinuxListenerOwner(const LinuxListenerOwner&) = delete;
    LinuxListenerOwner& operator=(const LinuxListenerOwner&) = delete;
    ~LinuxListenerOwner() {
        if (descriptor_ >= 0) {
            (void)::close(descriptor_);
        }
    }

    [[nodiscard]] int descriptor() const noexcept { return descriptor_; }
    [[nodiscard]] int release() noexcept {
        const int released = descriptor_;
        descriptor_ = -1;
        return released;
    }

private:
    int descriptor_{-1};
};

[[nodiscard]] bool hasLinuxServeDescriptorBudget(
    unsigned acceptBudget) noexcept {
    struct rlimit descriptorLimit {};
    if (::getrlimit(RLIMIT_NOFILE, &descriptorLimit) != 0) {
        return false;
    }

    // Keep fixed headroom for stdio, the retained R2 keytab snapshot,
    // listener, accepted connection, logind watcher and TLS/runtime handles.
    constexpr rlim_t kDescriptorReserve = 8U;
    const rlim_t required =
        kDescriptorReserve + static_cast<rlim_t>(acceptBudget);
    return descriptorLimit.rlim_cur == RLIM_INFINITY ||
           descriptorLimit.rlim_cur >= required;
}

[[nodiscard]] int openVerifiedLinuxLoopbackListener(
    std::string_view listenAddress, std::uint16_t listenPort) noexcept {
    const bool ipv4 = listenAddress == "127.0.0.1";
    const bool ipv6 = listenAddress == "::1";
    if ((!ipv4 && !ipv6) || listenPort == 0U) {
        return -1;
    }

    const int addressFamily = ipv4 ? AF_INET : AF_INET6;
    const int descriptor = ::socket(
        addressFamily, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
    if (descriptor < 0) {
        return -1;
    }

    LinuxListenerOwner failureOwner{descriptor};
    if (ipv6) {
        const int enabled = 1;
        if (::setsockopt(
                descriptor, IPPROTO_IPV6, IPV6_V6ONLY, &enabled,
                sizeof(enabled)) != 0) {
            return -1;
        }
    }

    if (ipv4) {
        struct sockaddr_in requested {};
        requested.sin_family = AF_INET;
        requested.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        requested.sin_port = htons(listenPort);
        if (::bind(
                descriptor, reinterpret_cast<const sockaddr*>(&requested),
                sizeof(requested)) != 0) {
            return -1;
        }
    } else {
        struct sockaddr_in6 requested {};
        requested.sin6_family = AF_INET6;
        requested.sin6_addr = in6addr_loopback;
        requested.sin6_port = htons(listenPort);
        if (::bind(
                descriptor, reinterpret_cast<const sockaddr*>(&requested),
                sizeof(requested)) != 0) {
            return -1;
        }
    }

    if (::listen(descriptor, 1) != 0) {
        return -1;
    }

    int socketType = 0;
    int accepting = 0;
    socklen_t optionLength = sizeof(socketType);
    if (::getsockopt(
            descriptor, SOL_SOCKET, SO_TYPE, &socketType, &optionLength) != 0 ||
        optionLength != sizeof(socketType) || socketType != SOCK_STREAM) {
        return -1;
    }
    optionLength = sizeof(accepting);
    if (::getsockopt(
            descriptor, SOL_SOCKET, SO_ACCEPTCONN, &accepting,
            &optionLength) != 0 ||
        optionLength != sizeof(accepting) || accepting != 1) {
        return -1;
    }

    struct sockaddr_storage actual {};
    socklen_t actualLength = sizeof(actual);
    if (::getsockname(
            descriptor, reinterpret_cast<sockaddr*>(&actual),
            &actualLength) != 0) {
        return -1;
    }

    bool endpointMatches = false;
    if (ipv4 && actual.ss_family == AF_INET &&
        actualLength >= sizeof(sockaddr_in)) {
        const auto* bound =
            reinterpret_cast<const sockaddr_in*>(&actual);
        endpointMatches =
            bound->sin_addr.s_addr == htonl(INADDR_LOOPBACK) &&
            ntohs(bound->sin_port) == listenPort;
    } else if (ipv6 && actual.ss_family == AF_INET6 &&
               actualLength >= sizeof(sockaddr_in6)) {
        const auto* bound =
            reinterpret_cast<const sockaddr_in6*>(&actual);
        endpointMatches =
            std::memcmp(
                &bound->sin6_addr, &in6addr_loopback,
                sizeof(in6addr_loopback)) == 0 &&
            bound->sin6_scope_id == 0U &&
            ntohs(bound->sin6_port) == listenPort;
    }
    if (!endpointMatches) {
        return -1;
    }

    // Transfer ownership to the caller only after every socket property and
    // effective bound endpoint has been verified.
    return failureOwner.release();
}

struct LinuxServeAcceptContext final {
    const rdp_server::server::runtime::RuntimeDeploymentPolicy* policy{};
    rdp_server::server::runtime::LinuxRuntimeSecurityConfiguration*
        securityConfiguration{};
    const rdp_server::server::runtime::RuntimeServerTlsContext* tlsContext{};
    const rdp_server::server::security::ConsoleEvidenceRequest*
        admissionRequest{};
    bool endpointViolation{};
};

[[nodiscard]] bool runSerializedLinuxCandidate(
    rdp_server::server::transport::OwnedNativeTcpSocket accepted,
    void* rawContext) noexcept {
    using PollStatus =
        rdp_server::server::runtime::LinuxRuntimeSocketPollStatus;
    using PreStep =
        rdp_server::server::runtime::LinuxPreAdmissionStepStatus;
    using McsStep =
        rdp_server::server::runtime::LinuxPostAdmissionMcsStepStatus;
    using ResponseStep =
        rdp_server::server::runtime::LinuxPostAdmissionMcsResponseStepStatus;
    using ErectStep =
        rdp_server::server::runtime::LinuxPostAdmissionMcsErectStepStatus;

    auto* context = static_cast<LinuxServeAcceptContext*>(rawContext);
    if (context == nullptr || context->policy == nullptr ||
        context->securityConfiguration == nullptr ||
        context->tlsContext == nullptr || context->admissionRequest == nullptr ||
        !accepted.valid()) {
        return false;
    }

    const auto peer = accepted.peerEndpoint();
    std::span<const std::uint8_t> peerAddress;
    if (peer.family ==
        rdp_server::server::transport::TcpPeerAddressFamily::Ipv4) {
        peerAddress = std::span<const std::uint8_t>{peer.address}.first(4U);
    } else if (
        peer.family ==
        rdp_server::server::transport::TcpPeerAddressFamily::Ipv6) {
        peerAddress = std::span<const std::uint8_t>{peer.address};
    } else {
        context->endpointViolation = true;
        return false;
    }

    if (!context->policy->permitsLoopbackTransportCandidate(peerAddress)) {
        context->endpointViolation = true;
        return false;
    }

    rdp_server::server::runtime::LinuxRuntimeConnection connection{
        *context->securityConfiguration, std::move(accepted)};
    if (!connection.ready()) {
        return true;
    }

    const auto deadline =
        std::chrono::steady_clock::now() +
        kLinuxSerializedConnectionDeadline;
    bool readable = false;
    bool writable = false;
    bool admitted = false;

    while (connection.ready() && !admitted) {
        const auto step = connection.advancePreAdmission(
            readable, writable, *context->tlsContext);
        readable = false;
        writable = false;

        switch (step.status) {
        case PreStep::Progress:
        case PreStep::TlsEstablished:
        case PreStep::BindingVerified:
            continue;
        case PreStep::CredentialsVerified:
            admitted = connection.issueAdmission(*context->admissionRequest);
            if (!admitted) {
                return true;
            }
            continue;
        case PreStep::NeedRead:
        case PreStep::NeedWrite: {
            const auto ready =
                connection.pollSocketReadinessOnce(deadline);
            switch (ready.status) {
            case PollStatus::Ready:
                readable = ready.readable;
                writable = ready.writable;
                continue;
            case PollStatus::NoEvent:
                continue;
            case PollStatus::Expired:
            case PollStatus::Closed:
            case PollStatus::Failure:
                return true;
            }
            return true;
        }
        case PreStep::UnsupportedFinalCredentials:
        case PreStep::Invalid:
        case PreStep::Closed:
            return true;
        }
    }

    if (!admitted || !connection.hasAdmissionLease()) {
        return true;
    }

    readable = false;
    writable = false;
    bool acceptedConnectInitial = false;
    while (connection.ready() && !acceptedConnectInitial) {
        const auto step =
            connection.advancePostAdmissionMcsConnectInitial(
                readable, writable);
        readable = false;
        writable = false;

        switch (step.status) {
        case McsStep::Progress:
            continue;
        case McsStep::NeedRead:
        case McsStep::NeedWrite: {
            const auto ready =
                connection.pollSocketReadinessOnce(deadline);
            switch (ready.status) {
            case PollStatus::Ready:
                readable = ready.readable;
                writable = ready.writable;
                continue;
            case PollStatus::NoEvent:
                continue;
            case PollStatus::Expired:
            case PollStatus::Closed:
            case PollStatus::Failure:
                return true;
            }
            return true;
        }
        case McsStep::AdmittedConnectInitial:
            acceptedConnectInitial = true;
            break;
        case McsStep::AdmissionDenied:
        case McsStep::Invalid:
        case McsStep::Closed:
            return true;
        }
    }
    if (!acceptedConnectInitial || !connection.hasAdmissionLease()) {
        return true;
    }

    // The R3 response writer owns all plaintext and reply/slice identities.
    // R1 alone performs SSL writes; R2 reauthorizes every accepted-byte
    // receipt before R3 commits progress.
    readable = false;
    writable = false;
    bool deliveredResponse = false;
    while (connection.ready() && !deliveredResponse) {
        const auto step =
            connection.advancePostAdmissionMcsConnectResponseWrite(
                readable, writable);
        readable = false;
        writable = false;

        switch (step.status) {
        case ResponseStep::Progress:
            continue;
        case ResponseStep::NeedRead:
        case ResponseStep::NeedWrite: {
            const auto ready =
                connection.pollSocketReadinessOnce(deadline);
            switch (ready.status) {
            case PollStatus::Ready:
                readable = ready.readable;
                writable = ready.writable;
                continue;
            case PollStatus::NoEvent:
                continue;
            case PollStatus::Expired:
            case PollStatus::Closed:
            case PollStatus::Failure:
                return true;
            }
            return true;
        }
        case ResponseStep::Delivered:
            deliveredResponse = true;
            break;
        case ResponseStep::AdmissionDenied:
        case ResponseStep::Invalid:
        case ResponseStep::Closed:
            return true;
        }
    }
    if (!deliveredResponse || !connection.hasAdmissionLease()) {
        return true;
    }

    // The next exact TLS TPKT is Erect Domain. No buffering of the following
    // Attach/User PDU is allowed, and only R2 can advance R3's phase.
    readable = false;
    writable = false;
    bool acceptedErectDomain = false;
    while (connection.ready() && !acceptedErectDomain) {
        const auto step =
            connection.advancePostAdmissionMcsErectDomain(
                readable, writable);
        readable = false;
        writable = false;

        switch (step.status) {
        case ErectStep::Progress:
            continue;
        case ErectStep::NeedRead:
        case ErectStep::NeedWrite: {
            const auto ready =
                connection.pollSocketReadinessOnce(deadline);
            switch (ready.status) {
            case PollStatus::Ready:
                readable = ready.readable;
                writable = ready.writable;
                continue;
            case PollStatus::NoEvent:
                continue;
            case PollStatus::Expired:
            case PollStatus::Closed:
            case PollStatus::Failure:
                return true;
            }
            return true;
        }
        case ErectStep::ErectDomainAccepted:
            acceptedErectDomain = true;
            break;
        case ErectStep::AdmissionDenied:
        case ErectStep::Invalid:
        case ErectStep::Closed:
            return true;
        }
    }
    if (!acceptedErectDomain || !connection.hasAdmissionLease()) {
        return true;
    }    using AttachStep =
        rdp_server::server::runtime::LinuxPostAdmissionMcsAttachStepStatus;
    {
    // Attach User: only current R2/R3 authority may advance this stage.
    readable = false;
    writable = false;
    bool stageAccepted = false;
    while (connection.ready() && !stageAccepted) {
        const auto step = connection.advancePostAdmissionMcsAttachUser(
            *context->policy, readable, writable);
        readable = false;
        writable = false;
        switch (step.status) {
        case AttachStep::Progress:
            continue;
        case AttachStep::NeedRead:
        case AttachStep::NeedWrite: {
            const auto ready = connection.pollSocketReadinessOnce(deadline);
            switch (ready.status) {
            case PollStatus::Ready:
                readable = ready.readable;
                writable = ready.writable;
                continue;
            case PollStatus::NoEvent:
                continue;
            case PollStatus::Expired:
            case PollStatus::Closed:
            case PollStatus::Failure:
                return true;
            }
            return true;
        }
        case AttachStep::AttachUserAccepted:
            stageAccepted = true;
            break;
        case AttachStep::AdmissionDenied:
        case AttachStep::Invalid:
        case AttachStep::Closed:
            return true;
        }
    }
    if (!stageAccepted || !connection.hasAdmissionLease()) {
        return true;
    }
    }
    using ConfirmStep =
        rdp_server::server::runtime::LinuxPostAdmissionMcsAttachConfirmStepStatus;
    // Attach User Confirm: only current R2/R3 authority may advance this stage.
    readable = false;
    writable = false;
    while (connection.ready()) {
        const auto step = connection.advancePostAdmissionMcsAttachConfirmWrite(
            *context->policy, readable, writable);
        readable = false;
        writable = false;
        switch (step.status) {
        case ConfirmStep::Progress:
            continue;
        case ConfirmStep::NeedRead:
        case ConfirmStep::NeedWrite: {
            const auto ready = connection.pollSocketReadinessOnce(deadline);
            switch (ready.status) {
            case PollStatus::Ready:
                readable = ready.readable;
                writable = ready.writable;
                continue;
            case PollStatus::NoEvent:
                continue;
            case PollStatus::Expired:
            case PollStatus::Closed:
            case PollStatus::Failure:
                return true;
            }
            return true;
        }
        case ConfirmStep::Delivered:
            // No joins are invented. The next increment begins here.
            connection.revoke();
            return true;
        case ConfirmStep::AdmissionDenied:
        case ConfirmStep::Invalid:
        case ConfirmStep::Closed:
            return true;
        }
    }
    return true;

}

[[nodiscard]] bool runLinuxPersonalDesktopServe(
    const std::array<std::string_view, kConfigurationFields.size()>&
        validatedFields) noexcept {
    unsigned parsedPort = 0U;
    unsigned maxConnections = 0U;
    unsigned permissions = 0U;
    if (!parseDecimalWithin(
            validatedFields[1], 1U, 65535U, parsedPort) ||
        !parseDecimalWithin(
            validatedFields[6], 1U, 64U, maxConnections) ||
        maxConnections != 1U ||
        !parseDecimalWithin(
            validatedFields[kAuthorizedPermissionsField], 1U,
            rdp_server::server::security::kConsoleAllowedPermissions,
            permissions)) {
        return false;
    }

    rdp_server::server::runtime::RuntimeDeploymentPolicy deploymentPolicy;
    if (!deploymentPolicy.configurePersonalDesktop(
            true, static_cast<std::uint16_t>(parsedPort))) {
        return false;
    }

    rdp_server::server::runtime::LinuxRuntimeSecurityConfiguration
        linuxSecurity;
    if (!configureLinuxRuntimeSecurity(validatedFields, linuxSecurity)) {
        return false;
    }

    const auto tlsContext =
        rdp_server::server::runtime::RuntimeServerTlsContext::
            fromCredentialFiles(validatedFields[2], validatedFields[3]);
    if (!tlsContext) {
        return false;
    }

    const rdp_server::server::security::ConsoleEvidenceRequest request{
        validatedFields[kAuthorizedKerberosPrincipalField],
        validatedFields[kAuthorizedUnixAccountField],
        validatedFields[kAuthorizedSeatField],
        validatedFields[kAuthorizedDisplayField],
        static_cast<std::uint32_t>(permissions)};
    const auto preflight =
        linuxSecurity.preflightPersonalDesktopAdmission(
            deploymentPolicy, request);
    if (!preflight.readyForAuthenticatedAdmissionAttempt() ||
        preflight.authenticatedAdmission ||
        !hasLinuxServeDescriptorBudget(maxConnections)) {
        return false;
    }

    const int listenerDescriptor = openVerifiedLinuxLoopbackListener(
        validatedFields[0], static_cast<std::uint16_t>(parsedPort));
    if (listenerDescriptor < 0) {
        return false;
    }
    LinuxListenerOwner listener{listenerDescriptor};

    LinuxServeAcceptContext acceptContext{
        &deploymentPolicy, &linuxSecurity, &tlsContext, &request, false};
    using Clock = std::chrono::steady_clock;
    using namespace std::chrono_literals;
    for (;;) {
        const auto result =
            rdp_server::server::transport::pollNonblockingTcpAcceptBatch(
                static_cast<std::uintptr_t>(listener.descriptor()), 1U,
                runSerializedLinuxCandidate, &acceptContext,
                Clock::now() + 25ms, 25ms);
        if (acceptContext.endpointViolation) {
            return false;
        }

        using Outcome =
            rdp_server::server::transport::TcpListenerPollOutcome;
        switch (result.outcome) {
        case Outcome::NoEvent:
        case Outcome::Expired:
            break;
        case Outcome::BatchCompleted: {
            using Batch =
                rdp_server::server::transport::TcpAcceptBatchOutcome;
            if (result.batch.outcome == Batch::Drained ||
                result.batch.outcome == Batch::BudgetReached ||
                result.batch.outcome == Batch::WouldBlock) {
                break;
            }
            return false;
        }
        case Outcome::InvalidInput:
        case Outcome::Failure:
            return false;
        }
    }
}
#endif

[[nodiscard]] bool checkLicensingConfiguration(
    const std::array<std::string_view, kConfigurationFields.size()>&
        validatedFields) noexcept {
    if (validatedFields[kLicensingCertificateField].empty()) {
        return false;
    }

    ParsedLicensingIdentity identity{};
    if (!parseLicensingIdentity(validatedFields, identity)) {
        return false;
    }

    rdp_server::server::runtime::RuntimeLicensingContext licensingContext;
    if (!licensingContext.configureFromCredentialFiles(
            identity.productVersion,
            std::span{identity.companyNameUtf16}.first(
                identity.companyNameUtf16Bytes),
            std::span{identity.productIdUtf16}.first(
                identity.productIdUtf16Bytes),
            validatedFields[kLicensingCertificateField],
            std::span{identity.scopeAnsi}.first(identity.scopeAnsiBytes),
            validatedFields[kLicensingPrivateKeyField])) {
        return false;
    }

    const auto* configuredIdentity = licensingContext.identity();
    const auto* credential = licensingContext.credential();
    return licensingContext.configured() &&
           configuredIdentity != nullptr && credential != nullptr &&
           configuredIdentity->productVersion() == identity.productVersion &&
           credential->matches(*configuredIdentity);
}

// Configuration checks do not establish certificate trust, hostname,
// revocation, R2 admission or an R3 session decision. LinuxServe is the sole
// mode below allowed to bind/listen, and only after the genuine R2 preflight.
enum class ConfigurationCheckMode {
    Syntax,
    TlsMetadata,
    TlsCredentials,
    LicensingCredentials,
#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
    LinuxSecurity,
    LinuxServe,
#endif
};

[[nodiscard]] bool checkConfigurationFile(
    const char* path, ConfigurationCheckMode mode) noexcept {
    if (path == nullptr || *path == '\0') {
        return false;
    }
    // On POSIX, open the *actual* file without following its final symlink.
    // Nonblocking open makes FIFOs/devices fail safely rather than hanging
    // the configuration reader. The FILE stream exclusively owns this descriptor
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
    switch (mode) {
    case ConfigurationCheckMode::Syntax:
        return true;
    case ConfigurationCheckMode::TlsMetadata:
        return rdp_server::server::runtime::validateTlsFileReferences(
            validatedFields[2], validatedFields[3]);
    case ConfigurationCheckMode::TlsCredentials:
        return rdp_server::server::runtime::validateTlsCredentialContents(
            validatedFields[2], validatedFields[3]);
    case ConfigurationCheckMode::LicensingCredentials:
        return checkLicensingConfiguration(validatedFields);
#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
    case ConfigurationCheckMode::LinuxSecurity:
        return checkLinuxSecurityConfiguration(validatedFields);
    case ConfigurationCheckMode::LinuxServe:
        return runLinuxPersonalDesktopServe(validatedFields);
#endif
    }
    return false;
}

void printUsage() noexcept {
#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
    std::fputs("Usage: rdp-server [--help | --version | --check-config FILE | --check-tls-files FILE | --check-tls-credentials FILE | --check-licensing-credentials FILE | --check-linux-security FILE | serve --config FILE]\n"
               "--check-config validates syntax. --check-tls-files checks file metadata.\n"
               "--check-tls-credentials verifies certificate validity, server purpose and private-key match.\n"
               "--check-licensing-credentials validates explicit RDP licensing identity plus its matching RSA private key.\n"
#if defined(RDP_SERVER_HAVE_LINUX_PAM_PASSWORD_VERIFIER)
               "--check-linux-security additionally acquires the explicit Linux GSS acceptor credential, provisions the configured PAM service and validates one native identity-policy rule.\n"
#else
               "--check-linux-security additionally acquires the explicit Linux GSS acceptor credential and validates one native identity-policy rule.\n"
#endif
               "serve opens only a verified loopback listener, serializes X.224/TLS/CredSSP through the sole R1 owner, and requires genuine R2 native admission before MCS Connect Initial/Response; desktop/input publication is not yet enabled.\n", stdout);
#else
    std::fputs("Usage: rdp-server [--help | --version | --check-config FILE | --check-tls-files FILE | --check-tls-credentials FILE | --check-licensing-credentials FILE]\n"
               "--check-config validates syntax. --check-tls-files checks file metadata.\n"
               "--check-tls-credentials additionally verifies the current certificate validity window and private-key match.\n"
               "--check-licensing-credentials validates explicit RDP licensing identity plus its matching RSA private key.\n"
               "Trust, Microsoft-client acceptance, licensing authority, OS authorization and server startup are not verified.\n", stdout);
#endif
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
#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
        if (argumentCount == 4 && option == "serve" &&
            argumentValues[2] != nullptr &&
            std::string_view{argumentValues[2]} == "--config" &&
            argumentValues[3] != nullptr) {
            if (checkConfigurationFile(
                    argumentValues[3], ConfigurationCheckMode::LinuxServe)) {
                return 0;
            }
            // Never reveal configuration contents, credential paths or
            // native-session details on secure-startup denial.
            std::fputs(
                "rdp-server: refusing to start: authenticated OS authorization "
                "and authoritative live RDP sessions are unavailable.\n",
                stderr);
            return kSecureStartupUnavailableExitCode;
        }
#endif
        bool configurationCheckOption =
            option == "--check-config" || option == "--check-tls-files" ||
            option == "--check-tls-credentials" ||
            option == "--check-licensing-credentials";
#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
        configurationCheckOption =
            configurationCheckOption || option == "--check-linux-security";
#endif
        if (argumentCount == 3 && configurationCheckOption) {
            ConfigurationCheckMode mode = ConfigurationCheckMode::Syntax;
            if (option == "--check-tls-files") {
                mode = ConfigurationCheckMode::TlsMetadata;
            } else if (option == "--check-tls-credentials") {
                mode = ConfigurationCheckMode::TlsCredentials;
            } else if (option == "--check-licensing-credentials") {
                mode = ConfigurationCheckMode::LicensingCredentials;
#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
            } else if (option == "--check-linux-security") {
                mode = ConfigurationCheckMode::LinuxSecurity;
#endif
            }
            if (checkConfigurationFile(argumentValues[2], mode)) {
                if (mode == ConfigurationCheckMode::LicensingCredentials) {
                    std::fputs(
                        "rdp-server: licensing certificate, matching RSA private key and product identity accepted by the offline R3 credential validator; Microsoft-client trust or acceptance, license issuance, user authentication, RDP session authorization and listener readiness not verified; service remains disabled.\n",
                        stdout);
#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)
                } else if (mode == ConfigurationCheckMode::LinuxSecurity) {
#if defined(RDP_SERVER_HAVE_LINUX_PAM_PASSWORD_VERIFIER)
                    std::fputs("rdp-server: TLS identity, explicit Linux GSS acceptor credential, PAM service configuration and native identity policy accepted; no user authenticated or session authorized; service remains disabled.\n",
                               stdout);
#else
                    std::fputs("rdp-server: TLS identity, explicit Linux GSS acceptor credential and native identity policy accepted; no user authenticated or session authorized; service remains disabled.\n",
                               stdout);
#endif
#endif
                } else if (mode == ConfigurationCheckMode::TlsCredentials) {
                    std::fputs("rdp-server: TLS certificate is currently valid and matches the private key; "
                               "trust, hostname, revocation and OS authorization not verified; service remains disabled.\n",
                               stdout);
                } else if (mode == ConfigurationCheckMode::TlsMetadata) {
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
