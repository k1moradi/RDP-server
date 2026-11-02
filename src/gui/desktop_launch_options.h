// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdio>
#include <span>
#include <string_view>

namespace rdp::gui
{
// Borrowed argv values; no argument value is copied into diagnostics.
struct DesktopLaunchOptions final
{
    std::string_view username;
    std::string_view configurationPath;
    bool usernameProvided{};
    bool passwordFromStdin{};
    bool requestSharingConfirmation{};
    bool help{};
};

enum class DesktopLaunchError
{
    None,
    InvalidOption,
    MissingPasswordInput,
    InvalidPasswordInput,
    PasswordTooLong,
};

inline constexpr std::size_t kDesktopMaximumArguments = 16;
inline constexpr std::size_t kDesktopMaximumUsernameBytes = 128;
inline constexpr std::size_t kDesktopMaximumPasswordBytes = 256;

// Reject UTF-8 truncation, overlong forms, surrogates, scalar overflow
// and all C0/DEL controls. Valid text is not proof of an authenticated user.
[[nodiscard]] inline bool validDesktopText(const std::string_view text) noexcept
{
    for (std::size_t offset = 0; offset < text.size();)
    {
        const auto first = static_cast<unsigned char>(text[offset]);
        if (first < 0x80U)
        {
            if (first < 0x20U || first == 0x7fU)
                return false;
            ++offset;
            continue;
        }
        const std::size_t continuationCount =
            first >= 0xc2U && first <= 0xdfU ? 1U :
            first >= 0xe0U && first <= 0xefU ? 2U :
            first >= 0xf0U && first <= 0xf4U ? 3U : 0U;
        if (continuationCount == 0U ||
            continuationCount >= text.size() - offset)
            return false;
        const auto second = static_cast<unsigned char>(text[offset + 1U]);
        if ((second & 0xc0U) != 0x80U ||
            (first == 0xc2U && second < 0xa0U) || // Reject C1 controls.
            (first == 0xe0U && second < 0xa0U) ||
            (first == 0xedU && second >= 0xa0U) ||
            (first == 0xf0U && second < 0x90U) ||
            (first == 0xf4U && second >= 0x90U))
            return false;
        for (std::size_t index = 2U; index <= continuationCount; ++index)
            if ((static_cast<unsigned char>(text[offset + index]) & 0xc0U) !=
                0x80U)
                return false;
        offset += continuationCount + 1U;
    }
    return true;
}

// R2-compatible non-secret Username: unlike Session Password, it cannot
// contain path separators. The caller still owns all authorization decisions.
[[nodiscard]] inline bool validDesktopUsername(
    const std::string_view username) noexcept
{
    return validDesktopText(username) &&
           username.find_first_of("/\\") == std::string_view::npos;
}

[[nodiscard]] inline DesktopLaunchError parseDesktopLaunchOptions(
    const std::span<const std::string_view> arguments,
    DesktopLaunchOptions& options) noexcept
{
    options = {};
    if (arguments.empty() ||
        arguments.size() > kDesktopMaximumArguments)
        return DesktopLaunchError::InvalidOption;
    for (std::size_t index = 1U; index < arguments.size(); ++index)
    {
        const std::string_view argument = arguments[index];
        if (argument == "--help")
        {
            if (options.help)
                return DesktopLaunchError::InvalidOption;
            options.help = true;
        }
        else if (argument == "--username" || argument == "--config")
        {
            if (index + 1U >= arguments.size())
                return DesktopLaunchError::InvalidOption;
            const std::string_view value = arguments[++index];
            if (value.empty() || value.front() == '-' ||
                value.size() > 4096U)
                return DesktopLaunchError::InvalidOption;
            if (argument == "--username")
            {
                if (options.usernameProvided ||
                    value.size() > kDesktopMaximumUsernameBytes ||
                    !validDesktopUsername(value))
                    return DesktopLaunchError::InvalidOption;
                options.username = value;
                options.usernameProvided = true;
            }
            else
            {
                if (!options.configurationPath.empty())
                    return DesktopLaunchError::InvalidOption;
                options.configurationPath = value;
            }
        }
        else if (argument == "--password-stdin")
        {
            if (options.passwordFromStdin)
                return DesktopLaunchError::InvalidOption;
            options.passwordFromStdin = true;
        }
        else if (argument == "--enable")
        {
            if (options.requestSharingConfirmation)
                return DesktopLaunchError::InvalidOption;
            options.requestSharingConfirmation = true;
        }
        else
        {
            // Includes every argv-password spelling and unknown option.
            return DesktopLaunchError::InvalidOption;
        }
    }
    if ((options.help && arguments.size() != 2U) ||
        (!options.configurationPath.empty() &&
         (options.usernameProvided || options.passwordFromStdin ||
          options.requestSharingConfirmation || options.help)))
        return DesktopLaunchError::InvalidOption;
    return DesktopLaunchError::None;
}

// Input must be a redirected non-terminal FILE*, checked by the caller.
// Only one bounded line is consumed; no echo, heap copy, or secret logging.
[[nodiscard]] inline DesktopLaunchError readDesktopPasswordLine(
    std::FILE* source,
    std::array<char, kDesktopMaximumPasswordBytes + 1U>& password,
    std::size_t& length) noexcept
{
    length = 0;
    password.fill('\0');
    if (source == nullptr)
        return DesktopLaunchError::MissingPasswordInput;
    for (;;)
    {
        const int next = std::fgetc(source);
        if (next == EOF)
        {
            if (std::ferror(source))
            {
                password.fill('\0');
                length = 0;
                return DesktopLaunchError::InvalidPasswordInput;
            }
            break;
        }
        if (next == '\n')
            break;
        if (length == kDesktopMaximumPasswordBytes)
        {
            password.fill('\0');
            length = 0;
            return DesktopLaunchError::PasswordTooLong;
        }
        password[length++] = static_cast<char>(next);
    }
    if (length != 0 && password[length - 1U] == '\r')
        password[--length] = '\0';
    if (length == 0 || !validDesktopText(
            std::string_view{password.data(), length}))
    {
        password.fill('\0');
        length = 0;
        return DesktopLaunchError::InvalidPasswordInput;
    }
    password[length] = '\0';
    return DesktopLaunchError::None;
}

// Volatile stores ensure retired temporary private input is not optimized away.
inline void wipeDesktopPassword(
    std::array<char, kDesktopMaximumPasswordBytes + 1U>& password) noexcept
{
    for (char& byte : password)
        *static_cast<volatile char*>(&byte) = '\0';
}
} // namespace rdp::gui
