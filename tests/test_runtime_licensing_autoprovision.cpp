// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/runtime_licensing_context.h"
#include "server/runtime/runtime_tls_context.h"
#include "server/transport/rdp_licensing.h"

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>

using rdp_server::server::runtime::RuntimeLicensingContext;
using rdp_server::server::runtime::RuntimeServerTlsContext;
using namespace rdp_server::server::transport;

namespace
{
struct X509Closer
{
    void operator()(X509* value) const noexcept { ::X509_free(value); }
};
struct PkeyCloser
{
    void operator()(EVP_PKEY* value) const noexcept { ::EVP_PKEY_free(value); }
};
using OwnedX509 = std::unique_ptr<X509, X509Closer>;
using OwnedPkey = std::unique_ptr<EVP_PKEY, PkeyCloser>;

template <std::size_t N>
consteval std::array<std::uint8_t, N * 2U>
utf16Le(const char (&text)[N]) noexcept
{
    std::array<std::uint8_t, N * 2U> result{};
    for (std::size_t index = 0U; index < N; ++index)
        result[index * 2U] =
            static_cast<std::uint8_t>(static_cast<unsigned char>(text[index]));
    return result;
}

template <std::size_t N>
consteval std::array<std::uint8_t, N>
ansi(const char (&text)[N]) noexcept
{
    std::array<std::uint8_t, N> result{};
    for (std::size_t index = 0U; index < N; ++index)
        result[index] =
            static_cast<std::uint8_t>(static_cast<unsigned char>(text[index]));
    return result;
}

constexpr auto kCompany = utf16Le("RDP-server");
constexpr auto kProduct = utf16Le("RDP-server Personal Desktop");
constexpr auto kScope = ansi("RDP-server");

[[nodiscard]] std::uint32_t readLe32(
    std::span<const std::uint8_t> input, std::size_t offset) noexcept
{
    return static_cast<std::uint32_t>(input[offset]) |
        (static_cast<std::uint32_t>(input[offset + 1U]) << 8U) |
        (static_cast<std::uint32_t>(input[offset + 2U]) << 16U) |
        (static_cast<std::uint32_t>(input[offset + 3U]) << 24U);
}

struct ParsedChain final
{
    OwnedX509 root{};
    OwnedX509 leaf{};
    [[nodiscard]] explicit operator bool() const noexcept
    {
        return root != nullptr && leaf != nullptr;
    }
};

[[nodiscard]] ParsedChain parseGeneratedChain(
    std::span<const std::uint8_t> bytes) noexcept
{
    constexpr std::uint32_t kVersion = 2U;
    constexpr std::uint32_t kCount = 2U;
    constexpr std::size_t kPaddingBytes = 8U + 4U * kCount;
    if (bytes.size() < 8U || (readLe32(bytes, 0U) & 0x7fffffffU) != kVersion ||
        readLe32(bytes, 4U) != kCount)
        return {};

    std::array<OwnedX509, 2> certificates{};
    std::size_t offset = 8U;
    for (std::size_t index = 0U; index < certificates.size(); ++index)
    {
        if (bytes.size() - offset < 4U)
            return {};
        const std::size_t certificateBytes = readLe32(bytes, offset);
        offset += 4U;
        if (certificateBytes == 0U || certificateBytes > bytes.size() - offset)
            return {};
        const unsigned char* cursor = bytes.data() + offset;
        const unsigned char* const end = cursor + certificateBytes;
        certificates[index].reset(
            ::d2i_X509(nullptr, &cursor, static_cast<long>(certificateBytes)));
        if (!certificates[index] || cursor != end)
            return {};
        offset += certificateBytes;
    }

    if (bytes.size() - offset != kPaddingBytes ||
        !std::all_of(
            bytes.begin() + static_cast<std::ptrdiff_t>(offset), bytes.end(),
            [](std::uint8_t value) { return value == 0U; }))
        return {};

    return {
        std::move(certificates[0]),
        std::move(certificates[1])};
}

void testDeterministicProductIdentity()
{
    RuntimeLicensingContext first;
    RuntimeLicensingContext second;
    assert(first.configureGeneratedApplicationIdentity());
    assert(second.configureGeneratedApplicationIdentity());
    assert(first.configured() && second.configured());

    const auto* firstIdentity = first.identity();
    const auto* secondIdentity = second.identity();
    assert(firstIdentity != nullptr && secondIdentity != nullptr);
    assert(firstIdentity->productVersion() == 0x00010000U);
    assert(firstIdentity->companyNameUtf16().size() == kCompany.size());
    assert(std::equal(
        firstIdentity->companyNameUtf16().begin(),
        firstIdentity->companyNameUtf16().end(), kCompany.begin()));
    assert(firstIdentity->productIdUtf16().size() == kProduct.size());
    assert(std::equal(
        firstIdentity->productIdUtf16().begin(),
        firstIdentity->productIdUtf16().end(), kProduct.begin()));
    assert(firstIdentity->scopeAnsi().size() == kScope.size());
    assert(std::equal(
        firstIdentity->scopeAnsi().begin(),
        firstIdentity->scopeAnsi().end(), kScope.begin()));

    assert(secondIdentity->productVersion() == firstIdentity->productVersion());
    assert(secondIdentity->companyNameUtf16().size() ==
           firstIdentity->companyNameUtf16().size());
    assert(std::equal(
        secondIdentity->companyNameUtf16().begin(),
        secondIdentity->companyNameUtf16().end(),
        firstIdentity->companyNameUtf16().begin()));
    assert(secondIdentity->productIdUtf16().size() ==
           firstIdentity->productIdUtf16().size());
    assert(std::equal(
        secondIdentity->productIdUtf16().begin(),
        secondIdentity->productIdUtf16().end(),
        firstIdentity->productIdUtf16().begin()));
    assert(secondIdentity->scopeAnsi().size() == firstIdentity->scopeAnsi().size());
    assert(std::equal(
        secondIdentity->scopeAnsi().begin(), secondIdentity->scopeAnsi().end(),
        firstIdentity->scopeAnsi().begin()));

    // Product identity is deterministic, but fresh process-local RSA material
    // makes the advertised certificate chain installation/session specific.
    assert(firstIdentity->serverCertificate().size() ==
           secondIdentity->serverCertificate().size() ||
           firstIdentity->serverCertificate().size() != 0U);
    assert(!std::equal(
        firstIdentity->serverCertificate().begin(),
        firstIdentity->serverCertificate().end(),
        secondIdentity->serverCertificate().begin(),
        secondIdentity->serverCertificate().end()));
    assert(first.credential() != nullptr &&
           first.credential()->matches(*firstIdentity));
    assert(!first.configureGeneratedApplicationIdentity());
}

void testMicrosoftX509ChainShape()
{
    RuntimeLicensingContext context;
    assert(context.configureGeneratedApplicationIdentity());
    const auto* identity = context.identity();
    assert(identity != nullptr);

    ParsedChain chain = parseGeneratedChain(identity->serverCertificate());
    assert(chain);
    OwnedPkey rootKey{::X509_get_pubkey(chain.root.get())};
    OwnedPkey leafKey{::X509_get_pubkey(chain.leaf.get())};
    assert(rootKey && leafKey);
    assert(::X509_verify(chain.root.get(), rootKey.get()) == 1);
    assert(::X509_verify(chain.leaf.get(), rootKey.get()) == 1);
    assert(::X509_check_ca(chain.root.get()) > 0);
    assert(::X509_check_ca(chain.leaf.get()) == 0);
    assert(::EVP_PKEY_base_id(leafKey.get()) == EVP_PKEY_RSA);
    assert(::EVP_PKEY_get_bits(leafKey.get()) >= 2048);

    const auto* credential = context.credential();
    assert(credential != nullptr);
    assert(credential->configured());
    assert(credential->matches(*identity));
}


void testMicrosoftTemporaryCertificateMarker()
{
    RuntimeLicensingContext context;
    assert(context.configureGeneratedApplicationIdentity());
    const auto* identity = context.identity();
    assert(identity != nullptr);

    const auto bytes = identity->serverCertificate();
    assert(bytes.size() >= 8U);
    constexpr std::uint32_t kCertificateVersionMask = 0x7fffffffU;
    constexpr std::uint32_t kTemporaryCertificateFlag = 0x80000000U;
    const std::uint32_t rawVersion = readLe32(bytes, 0U);
    assert((rawVersion & kCertificateVersionMask) == 2U);
    assert((rawVersion & kTemporaryCertificateFlag) != 0U);
}

void testServerLicenseRequestConsumesGeneratedIdentity()
{
    RuntimeLicensingContext context;
    assert(context.configureGeneratedApplicationIdentity());
    const auto* identity = context.identity();
    assert(identity != nullptr);

    std::array<std::uint8_t, kRdpLicensingRandomBytes> random{};
    for (std::size_t index = 0U; index < random.size(); ++index)
        random[index] = static_cast<std::uint8_t>(index + 1U);

    const RdpServerLicenseRequestFields fields{
        random,
        identity->productVersion(),
        identity->companyNameUtf16(),
        identity->productIdUtf16(),
        identity->serverCertificate(),
        identity->scopeAnsi()};
    std::array<std::uint8_t, kMaximumRdpServerLicenseRequestBytes> output{};
    const auto encoded =
        encodeEnhancedSecurityServerLicenseRequest(fields, output);
    assert(encoded);
    assert(encoded.bytesWritten > identity->serverCertificate().size());
    assert(output[0] ==
           static_cast<std::uint8_t>(
               RdpLicensingMessageType::ServerLicenseRequest));

    const auto end = output.begin() +
        static_cast<std::ptrdiff_t>(encoded.bytesWritten);
    const auto found = std::search(
        output.begin(), end,
        identity->serverCertificate().begin(),
        identity->serverCertificate().end());
    assert(found != end);
}

void testLicensingIdentityIsDistinctFromR1Tls()
{
    RuntimeLicensingContext licensing;
    assert(licensing.configureGeneratedApplicationIdentity());
    ParsedChain chain =
        parseGeneratedChain(licensing.identity()->serverCertificate());
    assert(chain);

    RuntimeServerTlsContext tls =
        RuntimeServerTlsContext::fromGeneratedIpAddress("192.0.2.44");
    assert(tls);
    const X509* tlsCertificate = tls.certificate();
    assert(tlsCertificate != nullptr);

    // R1 owns one bare endpoint-bound TLS leaf. MS-RDPBCGR licensing requires
    // a SERVER_CERTIFICATE object containing a root-first X.509 chain, so the
    // TLS leaf is neither the right wire shape nor the licensing key owner.
    const auto licensingBytes = licensing.identity()->serverCertificate();
    assert(licensingBytes.size() > 8U);
    assert((readLe32(licensingBytes, 0U) & 0x7fffffffU) == 2U);
    assert(readLe32(licensingBytes, 4U) == 2U);
    assert(::X509_cmp(chain.leaf.get(), tlsCertificate) != 0);
}
} // namespace

int main(int argc, char** argv)
{
    if (argc != 2 || argv[1] == nullptr)
        return 2;
    const std::string_view testCase{argv[1]};
    if (testCase == "deterministic-product-identity")
        testDeterministicProductIdentity();
    else if (testCase == "microsoft-x509-chain-shape")
        testMicrosoftX509ChainShape();
    else if (testCase == "microsoft-temporary-certificate-marker")
        testMicrosoftTemporaryCertificateMarker();
    else if (testCase == "server-license-request-generated-identity")
        testServerLicenseRequestConsumesGeneratedIdentity();
    else if (testCase == "distinct-from-r1-tls")
        testLicensingIdentityIsDistinctFromR1Tls();
    else
        return 2;
    return 0;
}
