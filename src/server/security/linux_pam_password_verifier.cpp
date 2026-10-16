// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_pam_password_verifier.h"

#include <openssl/crypto.h>
#include <security/pam_appl.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <span>
#include <string_view>

namespace rdp_server::server::security
{
namespace
{

constexpr std::size_t kMaximumPasswordUtf16Bytes = 4096;
constexpr std::size_t kMaximumPasswordUtf8Bytes =
    kMaximumPasswordUtf16Bytes * 2U;

struct SensitiveUtf8Password final
{
    std::array<char, kMaximumPasswordUtf8Bytes + 1U> bytes{};
    std::size_t length{};

    ~SensitiveUtf8Password()
    {
        OPENSSL_cleanse(bytes.data(), bytes.size());
        length = 0;
    }

    SensitiveUtf8Password() = default;
    SensitiveUtf8Password(const SensitiveUtf8Password &) = delete;
    SensitiveUtf8Password &operator=(const SensitiveUtf8Password &) = delete;
};

[[nodiscard]] constexpr bool asciiAlphaNumeric(char value) noexcept
{
    return (value >= 'a' && value <= 'z') ||
           (value >= 'A' && value <= 'Z') ||
           (value >= '0' && value <= '9');
}

[[nodiscard]] bool validServiceName(std::string_view serviceName) noexcept
{
    if (serviceName.empty() || serviceName.size() > 64 ||
        !asciiAlphaNumeric(serviceName.front()))
    {
        return false;
    }
    return std::all_of(
        serviceName.begin(), serviceName.end(),
        [](char value) noexcept {
            return asciiAlphaNumeric(value) ||
                   value == '_' || value == '-' || value == '.';
        });
}

[[nodiscard]] bool validUnixAccount(std::string_view account) noexcept
{
    if (account.empty() || account.size() > 32 || account == "root" ||
        ((account.front() < 'a' || account.front() > 'z') &&
         account.front() != '_'))
    {
        return false;
    }
    return std::all_of(
        account.begin(), account.end(),
        [](char value) noexcept {
            return (value >= 'a' && value <= 'z') ||
                   (value >= '0' && value <= '9') ||
                   value == '_' || value == '-';
        });
}

[[nodiscard]] bool appendUtf8(
    SensitiveUtf8Password &output,
    std::uint32_t codePoint) noexcept
{
    std::array<char, 4> encoded{};
    std::size_t encodedLength = 0;
    if (codePoint <= 0x7fU)
    {
        encoded[0] = static_cast<char>(codePoint);
        encodedLength = 1;
    }
    else if (codePoint <= 0x7ffU)
    {
        encoded[0] = static_cast<char>(0xc0U | (codePoint >> 6U));
        encoded[1] = static_cast<char>(0x80U | (codePoint & 0x3fU));
        encodedLength = 2;
    }
    else if (codePoint <= 0xffffU)
    {
        encoded[0] = static_cast<char>(0xe0U | (codePoint >> 12U));
        encoded[1] = static_cast<char>(
            0x80U | ((codePoint >> 6U) & 0x3fU));
        encoded[2] = static_cast<char>(0x80U | (codePoint & 0x3fU));
        encodedLength = 3;
    }
    else if (codePoint <= 0x10ffffU)
    {
        encoded[0] = static_cast<char>(0xf0U | (codePoint >> 18U));
        encoded[1] = static_cast<char>(
            0x80U | ((codePoint >> 12U) & 0x3fU));
        encoded[2] = static_cast<char>(
            0x80U | ((codePoint >> 6U) & 0x3fU));
        encoded[3] = static_cast<char>(0x80U | (codePoint & 0x3fU));
        encodedLength = 4;
    }
    else
    {
        return false;
    }

    if (output.length + encodedLength >= output.bytes.size())
    {
        return false;
    }
    std::copy_n(
        encoded.begin(), encodedLength,
        output.bytes.begin() + static_cast<std::ptrdiff_t>(output.length));
    output.length += encodedLength;
    output.bytes[output.length] = '\0';
    return true;
}

[[nodiscard]] bool convertPasswordToUtf8(
    std::span<const std::uint8_t> passwordUtf16Le,
    SensitiveUtf8Password &output) noexcept
{
    if (passwordUtf16Le.empty() ||
        passwordUtf16Le.size() > kMaximumPasswordUtf16Bytes ||
        (passwordUtf16Le.size() % 2U) != 0U)
    {
        return false;
    }

    for (std::size_t offset = 0;
         offset < passwordUtf16Le.size(); offset += 2U)
    {
        const std::uint16_t first =
            static_cast<std::uint16_t>(passwordUtf16Le[offset]) |
            (static_cast<std::uint16_t>(passwordUtf16Le[offset + 1U]) << 8U);
        if (first == 0)
        {
            return false;
        }

        std::uint32_t codePoint = first;
        if (first >= 0xd800U && first <= 0xdbffU)
        {
            if (offset + 3U >= passwordUtf16Le.size())
            {
                return false;
            }
            const std::uint16_t second =
                static_cast<std::uint16_t>(passwordUtf16Le[offset + 2U]) |
                (static_cast<std::uint16_t>(
                     passwordUtf16Le[offset + 3U]) << 8U);
            if (second < 0xdc00U || second > 0xdfffU)
            {
                return false;
            }
            codePoint =
                0x10000U +
                ((static_cast<std::uint32_t>(first) - 0xd800U) << 10U) +
                (static_cast<std::uint32_t>(second) - 0xdc00U);
            offset += 2U;
        }
        else if (first >= 0xdc00U && first <= 0xdfffU)
        {
            return false;
        }

        if (!appendUtf8(output, codePoint))
        {
            return false;
        }
    }
    return output.length != 0;
}

struct PamConversationContext final
{
    const SensitiveUtf8Password *password{};
    bool passwordSupplied{};
};

void cleanseResponses(
    pam_response *responses,
    int responseCount) noexcept
{
    if (responses == nullptr)
    {
        return;
    }
    for (int index = 0; index < responseCount; ++index)
    {
        if (responses[index].resp != nullptr)
        {
            const std::size_t length = std::strlen(responses[index].resp);
            OPENSSL_cleanse(responses[index].resp, length);
            std::free(responses[index].resp);
            responses[index].resp = nullptr;
        }
    }
    std::free(responses);
}

[[nodiscard]] int pamPasswordConversation(
    int messageCount,
    const pam_message **messages,
    pam_response **responses,
    void *applicationData) noexcept
{
    if (messageCount <= 0 || messageCount > 8 ||
        messages == nullptr || responses == nullptr ||
        applicationData == nullptr)
    {
        return PAM_CONV_ERR;
    }

    auto *const context =
        static_cast<PamConversationContext *>(applicationData);
    if (context->password == nullptr)
    {
        return PAM_CONV_ERR;
    }

    auto *const answers = static_cast<pam_response *>(
        std::calloc(static_cast<std::size_t>(messageCount),
                    sizeof(pam_response)));
    if (answers == nullptr)
    {
        return PAM_BUF_ERR;
    }

    for (int index = 0; index < messageCount; ++index)
    {
        if (messages[index] == nullptr)
        {
            cleanseResponses(answers, messageCount);
            return PAM_CONV_ERR;
        }

        switch (messages[index]->msg_style)
        {
        case PAM_PROMPT_ECHO_OFF:
        {
            if (context->passwordSupplied)
            {
                cleanseResponses(answers, messageCount);
                return PAM_CONV_ERR;
            }
            const auto &password = *context->password;
            auto *const copy =
                static_cast<char *>(std::malloc(password.length + 1U));
            if (copy == nullptr)
            {
                cleanseResponses(answers, messageCount);
                return PAM_BUF_ERR;
            }
            std::memcpy(copy, password.bytes.data(), password.length);
            copy[password.length] = '\0';
            answers[index].resp = copy;
            answers[index].resp_retcode = 0;
            context->passwordSupplied = true;
            break;
        }
        case PAM_ERROR_MSG:
        case PAM_TEXT_INFO:
            answers[index].resp = nullptr;
            answers[index].resp_retcode = 0;
            break;
        case PAM_PROMPT_ECHO_ON:
        default:
            // pam_start() already pins the exact local account. Refuse any
            // module that tries to source another identity or extra secret.
            cleanseResponses(answers, messageCount);
            return PAM_CONV_ERR;
        }
    }

    *responses = answers;
    return PAM_SUCCESS;
}

} // namespace

bool LinuxPamPasswordVerifier::configure(
    std::string_view serviceName) noexcept
{
    if (attempted_)
    {
        return false;
    }
    attempted_ = true;

    if (!validServiceName(serviceName))
    {
        return false;
    }

    std::copy(
        serviceName.begin(), serviceName.end(), serviceName_.begin());
    serviceNameLength_ = serviceName.size();
    serviceName_[serviceNameLength_] = '\0';
    configured_ = true;
    return true;
}

LinuxPamPasswordVerificationStatus LinuxPamPasswordVerifier::verify(
    std::string_view unixAccount,
    std::span<const std::uint8_t> passwordUtf16Le) const noexcept
{
    if (!configured_ || !validUnixAccount(unixAccount))
    {
        return LinuxPamPasswordVerificationStatus::InvalidInput;
    }

    SensitiveUtf8Password password;
    if (!convertPasswordToUtf8(passwordUtf16Le, password))
    {
        return LinuxPamPasswordVerificationStatus::InvalidInput;
    }

    std::array<char, 33> accountBytes{};
    std::copy(
        unixAccount.begin(), unixAccount.end(), accountBytes.begin());
    accountBytes[unixAccount.size()] = '\0';

    PamConversationContext conversationContext{&password, false};
    const pam_conv conversation{
        &pamPasswordConversation, &conversationContext};
    pam_handle_t *handle = nullptr;
    const int startStatus = pam_start(
        serviceName_.data(), accountBytes.data(), &conversation, &handle);
    if (startStatus != PAM_SUCCESS || handle == nullptr)
    {
        if (handle != nullptr)
        {
            (void)pam_end(handle, startStatus);
        }
        return LinuxPamPasswordVerificationStatus::ProviderFailure;
    }

    const int authenticationStatus = pam_authenticate(
        handle, PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK);
    int finalStatus = authenticationStatus;
    if (authenticationStatus == PAM_SUCCESS)
    {
        finalStatus = pam_acct_mgmt(handle, PAM_SILENT);
    }

    const int endStatus = pam_end(handle, finalStatus);
    if (endStatus != PAM_SUCCESS)
    {
        return LinuxPamPasswordVerificationStatus::ProviderFailure;
    }
    return finalStatus == PAM_SUCCESS
        ? LinuxPamPasswordVerificationStatus::Authorized
        : LinuxPamPasswordVerificationStatus::Denied;
}

} // namespace rdp_server::server::security
