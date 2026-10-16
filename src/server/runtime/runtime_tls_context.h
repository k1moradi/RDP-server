// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <memory>
#include <string_view>

#include <openssl/ssl.h>

namespace rdp_server::server::runtime
{

// Runtime-only TLS server identity owner. A valid instance owns exactly one
// configured SSL_CTX. The runtime must keep this owner alive while connection
// SSL objects created from it remain active; R1 owns each returned SSL.
class RuntimeServerTlsContext final
{
public:
    using ServerTls = std::unique_ptr<SSL, decltype(&::SSL_free)>;

    RuntimeServerTlsContext() noexcept = default;
    RuntimeServerTlsContext(const RuntimeServerTlsContext &) = delete;
    RuntimeServerTlsContext &operator=(const RuntimeServerTlsContext &) = delete;
    RuntimeServerTlsContext(RuntimeServerTlsContext &&) noexcept = default;
    RuntimeServerTlsContext &operator=(RuntimeServerTlsContext &&) noexcept = default;
    ~RuntimeServerTlsContext() = default;

    [[nodiscard]] static RuntimeServerTlsContext fromCredentialFiles(
        std::string_view certificatePath,
        std::string_view privateKeyPath) noexcept;

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return context_ != nullptr;
    }

    [[nodiscard]] ServerTls createServerTls() const noexcept;
    [[nodiscard]] int minimumProtocolVersion() const noexcept;
    [[nodiscard]] std::uint64_t options() const noexcept;
    [[nodiscard]] const X509 *certificate() const noexcept;

private:
    using OwnedContext = std::unique_ptr<SSL_CTX, decltype(&::SSL_CTX_free)>;

    explicit RuntimeServerTlsContext(OwnedContext context) noexcept
        : context_(std::move(context)) {}

    OwnedContext context_{nullptr, &::SSL_CTX_free};
};

// Offline metadata and cryptographic checks share the exact secure native
// credential-open and snapshot loader used by RuntimeServerTlsContext.
[[nodiscard]] bool validateTlsFileReferences(
    std::string_view certificatePath,
    std::string_view privateKeyPath) noexcept;
[[nodiscard]] bool validateTlsCredentialContents(
    std::string_view certificatePath,
    std::string_view privateKeyPath) noexcept;

} // namespace rdp_server::server::runtime
