// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>

namespace rdp_server::server::runtime::detail
{

// Runtime-internal exact snapshots of one public credential object and one
// private-key object. The loader opens each pathname exactly once, checks the
// native object identity/metadata, rejects aliasing, and then reads from those
// already-open handles. Private bytes are cleansed on every destruction path.
class RuntimeCredentialFilePairSnapshot final
{
public:
    RuntimeCredentialFilePairSnapshot() noexcept = default;
    ~RuntimeCredentialFilePairSnapshot();

    RuntimeCredentialFilePairSnapshot(
        const RuntimeCredentialFilePairSnapshot &) = delete;
    RuntimeCredentialFilePairSnapshot &operator=(
        const RuntimeCredentialFilePairSnapshot &) = delete;

    RuntimeCredentialFilePairSnapshot(
        RuntimeCredentialFilePairSnapshot &&other) noexcept;
    RuntimeCredentialFilePairSnapshot &operator=(
        RuntimeCredentialFilePairSnapshot &&other) noexcept;

    [[nodiscard]] explicit operator bool() const noexcept;
    [[nodiscard]] std::span<const std::uint8_t> publicBytes() const noexcept;
    [[nodiscard]] std::span<const std::uint8_t> privateKeyBytes() const noexcept;

private:
    friend RuntimeCredentialFilePairSnapshot
    loadSecureRuntimeCredentialFilePair(
        std::string_view publicPath,
        std::string_view privateKeyPath,
        std::size_t maximumPublicBytes,
        std::size_t maximumPrivateKeyBytes) noexcept;

    void clear() noexcept;

    std::unique_ptr<std::uint8_t[]> publicBytes_{};
    std::unique_ptr<std::uint8_t[]> privateKeyBytes_{};
    std::size_t publicSize_{};
    std::size_t privateKeySize_{};
};

[[nodiscard]] RuntimeCredentialFilePairSnapshot
loadSecureRuntimeCredentialFilePair(
    std::string_view publicPath,
    std::string_view privateKeyPath,
    std::size_t maximumPublicBytes,
    std::size_t maximumPrivateKeyBytes) noexcept;

[[nodiscard]] bool validateSecureRuntimeCredentialFilePairReferences(
    std::string_view publicPath,
    std::string_view privateKeyPath,
    std::size_t maximumPublicBytes,
    std::size_t maximumPrivateKeyBytes) noexcept;

} // namespace rdp_server::server::runtime::detail
