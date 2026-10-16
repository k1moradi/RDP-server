// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace rdp_server::server::transport
{

// MS-RDPBCGR 2.2.1.12.1.1 LICENSE_PREAMBLE uses a 16-bit total length.
// This first-party parser never allocates from peer-controlled lengths.
inline constexpr std::size_t kMaximumRdpLicensingPduBytes = 65535U;

enum class RdpLicensingMessageType : std::uint8_t
{
    ServerLicenseRequest = 0x01,
    ServerPlatformChallenge = 0x02,
    ServerNewLicense = 0x03,
    ServerUpgradeLicense = 0x04,
    ClientLicenseInfo = 0x12,
    ClientNewLicenseRequest = 0x13,
    ClientPlatformChallengeResponse = 0x15,
    ErrorAlert = 0xff,
};

enum class RdpLicensingParseError : std::uint8_t
{
    None,
    Truncated,
    Oversized,
    LengthMismatch,
    InvalidType,
    InvalidFlags,
};

struct RdpLicensingMessageView
{
    RdpLicensingMessageType type{RdpLicensingMessageType::ErrorAlert};
    std::uint8_t protocolVersion{};
    bool extendedErrorSupported{};
    // Borrowed from the caller's immutable completeMessage. The span remains
    // valid only while that input storage is alive and unchanged; the parser
    // and lifecycle never retain it beyond the current call.
    std::span<const std::uint8_t> body{};
};

struct RdpLicensingParseResult
{
    RdpLicensingMessageView value{};
    RdpLicensingParseError error{RdpLicensingParseError::Truncated};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == RdpLicensingParseError::None;
    }
};

// Parse exactly one already-isolated licensing PDU. Upstream R3 still must
// prove R2 admission, session generation, assigned MCS user/global channel,
// complete segmentation/reassembly, licensing phase and client direction.
// A successful parse never authenticates, licenses or activates a session.
[[nodiscard]] RdpLicensingParseResult parseRdpLicensingMessage(
    std::span<const std::uint8_t> completeMessage) noexcept;

inline constexpr std::size_t kRdpLicensingRandomBytes = 32U;
inline constexpr std::size_t kRdpLicensingPreMasterSecretBytes = 48U;
inline constexpr std::size_t kRdpLicensingKeyBytes = 16U;

// Borrowed cryptographic inputs from exactly one structurally valid initial
// client licensing message. These spans are valid only while completeMessage
// remains alive and unchanged; parsing them does not authorize or license.
struct RdpClientLicensingKeyExchangeView
{
    RdpLicensingMessageType type{RdpLicensingMessageType::ErrorAlert};
    std::span<const std::uint8_t> clientRandom{};
    std::span<const std::uint8_t> encryptedPreMasterSecret{};
};

enum class RdpClientLicensingKeyExchangeError : std::uint8_t
{
    None,
    InvalidLicensingMessage,
    UnexpectedMessage,
    MalformedBody,
};

struct RdpClientLicensingKeyExchangeParseResult
{
    RdpClientLicensingKeyExchangeView value{};
    RdpClientLicensingKeyExchangeError error{
        RdpClientLicensingKeyExchangeError::InvalidLicensingMessage};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == RdpClientLicensingKeyExchangeError::None;
    }
};

// MS-RDPELE 2.2.2.2/2.2.2.3 zero-copy extraction. It validates the same
// complete CLIENT_NEW_LICENSE_REQUEST / CLIENT_LICENSE_INFO structure used by
// the state machine, then returns only ClientRandom and encrypted premaster.
[[nodiscard]] RdpClientLicensingKeyExchangeParseResult
parseRdpClientLicensingKeyExchange(
    std::span<const std::uint8_t> completeMessage) noexcept;

struct RdpLicensingKeyMaterial
{
    std::array<std::uint8_t, kRdpLicensingKeyBytes> macSaltKey{};
    std::array<std::uint8_t, kRdpLicensingKeyBytes> encryptionKey{};
};

enum class RdpLicensingKeyDerivationError : std::uint8_t
{
    None,
    InvalidInput,
    DigestFailure,
};

struct RdpLicensingKeyDerivationResult
{
    RdpLicensingKeyMaterial value{};
    RdpLicensingKeyDerivationError error{
        RdpLicensingKeyDerivationError::InvalidInput};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == RdpLicensingKeyDerivationError::None;
    }
};

// MS-RDPELE 5.1.2. The caller must already have decrypted and validated the
// exact 48-byte premaster secret with the matching licensing private key.
// This helper derives keys only; it does not perform RSA, RC4, MAC validation,
// license validation, authorization or any session phase transition.
[[nodiscard]] RdpLicensingKeyDerivationResult deriveRdpLicensingKeys(
    std::span<const std::uint8_t> preMasterSecret,
    std::span<const std::uint8_t> clientRandom,
    std::span<const std::uint8_t> serverRandom) noexcept;

// Current credential processing deliberately supports the standards-defined
// X.509 certificate-chain form (CERT_CHAIN_VERSION_2). The private key input
// is one unencrypted PEM object supplied by the service configuration owner.
// Proprietary RDP certificates and encrypted PEM keys remain unsupported here.
inline constexpr std::size_t kMaximumRdpLicensingPrivateKeyPemBytes =
    16U * 1024U;
inline constexpr std::size_t kMaximumRdpLicensingRsaModulusBytes = 512U;

enum class RdpLicensingPreMasterDecryptError : std::uint8_t
{
    None,
    NotConfigured,
    InvalidEncryptedPreMasterSecret,
    DecryptFailure,
};

struct RdpLicensingPreMasterDecryptResult
{
    std::array<std::uint8_t, kRdpLicensingPreMasterSecretBytes> value{};
    RdpLicensingPreMasterDecryptError error{
        RdpLicensingPreMasterDecryptError::NotConfigured};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == RdpLicensingPreMasterDecryptError::None;
    }
};

class RdpServerLicenseIdentity;

// One service-owned licensing credential, configured before session
// publication and immutable thereafter. Configuration proves that the exact
// advertised CERT_CHAIN_VERSION_2 chain is internally signature-consistent,
// its terminal-server leaf has an RSA key, and the supplied unencrypted PEM
// private key matches that leaf. The private PEM is copied into bounded
// contiguous storage, cleansed on destruction, and is never exposed.
//
// configure() is one-shot and not thread-safe. After successful configuration,
// matches() and decryptPreMasterSecret() are read-only and may be called by
// separately serialized session owners. This object is credential material,
// NOT R2/native admission or a positive licensing decision.
class RdpLicensingServiceCredential final
{
public:
    RdpLicensingServiceCredential() noexcept = default;
    ~RdpLicensingServiceCredential();

    RdpLicensingServiceCredential(
        const RdpLicensingServiceCredential &) = delete;
    RdpLicensingServiceCredential &operator=(
        const RdpLicensingServiceCredential &) = delete;
    RdpLicensingServiceCredential(
        RdpLicensingServiceCredential &&) = delete;
    RdpLicensingServiceCredential &operator=(
        RdpLicensingServiceCredential &&) = delete;

    [[nodiscard]] bool configure(
        const RdpServerLicenseIdentity &identity,
        std::span<const std::uint8_t> privateKeyPem) noexcept;
    [[nodiscard]] bool configured() const noexcept { return configured_; }
    [[nodiscard]] bool matches(
        const RdpServerLicenseIdentity &identity) const noexcept;
    // Public, non-secret binding token for session continuity. Empty until
    // successful one-shot configuration; the private PEM is never exposed.
    [[nodiscard]] std::span<const std::uint8_t>
    certificateFingerprint() const noexcept
    {
        return configured_
            ? std::span<const std::uint8_t>{serverCertificateSha256_}
            : std::span<const std::uint8_t>{};
    }

    // MS-RDPELE uses the terminal server certificate's RSA key and the RDP
    // little-endian raw-RSA integer convention. The client BLOB must be
    // exactly the RSA modulus width plus eight trailing zero protocol bytes.
    // No RC4/MAC/license validation or lifecycle transition occurs here.
    [[nodiscard]] RdpLicensingPreMasterDecryptResult
    decryptPreMasterSecret(
        std::span<const std::uint8_t> encryptedPreMasterSecret) const noexcept;

private:
    std::array<std::uint8_t, kMaximumRdpLicensingPrivateKeyPemBytes>
        privateKeyPem_{};
    std::array<std::uint8_t, 32> serverCertificateSha256_{};
    std::size_t privateKeyPemLength_{};
    std::size_t rsaModulusBytes_{};
    bool attempted_{};
    bool configured_{};
};

// Under Enhanced RDP Security, SC_SECURITY carries no server certificate.
// SERVER_LICENSE_REQUEST therefore has to carry the explicitly provisioned
// licensing certificate needed by the client's RSA key exchange. Keep the
// complete owned request below R1's existing 18 KiB TLS application boundary.
inline constexpr std::size_t kMaximumRdpServerLicenseRequestBytes = 16U * 1024U;
inline constexpr std::size_t kMaximumRdpServerLicenseCertificateBytes =
    14U * 1024U;

enum class RdpServerLicenseRequestEncodeError : std::uint8_t
{
    None,
    InvalidRandom,
    InvalidProductInfo,
    InvalidServerCertificate,
    InvalidScope,
    Oversized,
    OutputTooSmall,
};

struct RdpServerLicenseRequestFields
{
    // Borrowed only by the deterministic offline serializer. Live R3 writers
    // do not accept this structure: they generate ServerRandom internally
    // from the CSPRNG-backed RdpServerLicenseIdentity path.
    std::span<const std::uint8_t> serverRandom{};
    std::uint32_t productVersion{};
    // Complete null-terminated UTF-16LE strings, terminators included.
    std::span<const std::uint8_t> companyNameUtf16{};
    std::span<const std::uint8_t> productIdUtf16{};
    // Opaque caller-provisioned BB_CERTIFICATE_BLOB payload. The serializer
    // bounds/copies it but cannot prove chain validity or private-key binding.
    std::span<const std::uint8_t> serverCertificate{};
    // Complete null-terminated ANSI issuer scope.
    std::span<const std::uint8_t> scopeAnsi{};
};

// One-shot, fixed-storage product/scope provisioning for live R3 licensing.
// It owns copies so configuration buffers cannot change beneath a session.
// This is protocol identity only, never authentication or license authority.
inline constexpr std::size_t kMaximumRdpServerLicenseIdentityTextBytes = 512U;

class RdpServerLicenseIdentity final
{
public:
    RdpServerLicenseIdentity() noexcept = default;
    RdpServerLicenseIdentity(const RdpServerLicenseIdentity &) = delete;
    RdpServerLicenseIdentity &operator=(const RdpServerLicenseIdentity &) = delete;
    RdpServerLicenseIdentity(RdpServerLicenseIdentity &&) = delete;
    RdpServerLicenseIdentity &operator=(RdpServerLicenseIdentity &&) = delete;

    // Configure exactly once. Each logical text value must be nonempty.
    // Failure is terminal for this object: malformed provisioning cannot be
    // replaced later while other owners may believe startup validation passed.
    [[nodiscard]] bool configure(
        std::uint32_t productVersion,
        std::span<const std::uint8_t> companyNameUtf16,
        std::span<const std::uint8_t> productIdUtf16,
        std::span<const std::uint8_t> serverCertificate,
        std::span<const std::uint8_t> scopeAnsi) noexcept;

    [[nodiscard]] bool configured() const noexcept { return configured_; }
    [[nodiscard]] std::uint32_t productVersion() const noexcept
    {
        return configured_ ? productVersion_ : 0U;
    }
    [[nodiscard]] std::span<const std::uint8_t>
    companyNameUtf16() const noexcept
    {
        return configured_
            ? std::span<const std::uint8_t>{
                  companyNameUtf16_.data(), companyNameUtf16Length_}
            : std::span<const std::uint8_t>{};
    }
    [[nodiscard]] std::span<const std::uint8_t>
    productIdUtf16() const noexcept
    {
        return configured_
            ? std::span<const std::uint8_t>{
                  productIdUtf16_.data(), productIdUtf16Length_}
            : std::span<const std::uint8_t>{};
    }
    [[nodiscard]] std::span<const std::uint8_t>
    serverCertificate() const noexcept
    {
        return configured_
            ? std::span<const std::uint8_t>{
                  serverCertificate_.data(), serverCertificateLength_}
            : std::span<const std::uint8_t>{};
    }
    [[nodiscard]] std::span<const std::uint8_t>
    scopeAnsi() const noexcept
    {
        return configured_
            ? std::span<const std::uint8_t>{
                  scopeAnsi_.data(), scopeAnsiLength_}
            : std::span<const std::uint8_t>{};
    }

private:
    std::array<std::uint8_t, kMaximumRdpServerLicenseIdentityTextBytes>
        companyNameUtf16_{};
    std::array<std::uint8_t, kMaximumRdpServerLicenseIdentityTextBytes>
        productIdUtf16_{};
    std::array<std::uint8_t, kMaximumRdpServerLicenseCertificateBytes>
        serverCertificate_{};
    std::array<std::uint8_t, kMaximumRdpServerLicenseIdentityTextBytes>
        scopeAnsi_{};
    std::uint32_t productVersion_{};
    std::size_t companyNameUtf16Length_{};
    std::size_t productIdUtf16Length_{};
    std::size_t serverCertificateLength_{};
    std::size_t scopeAnsiLength_{};
    bool attempted_{};
    bool configured_{};
};

struct RdpServerLicenseRequestEncodeResult
{
    std::size_t bytesWritten{};
    RdpServerLicenseRequestEncodeError error{
        RdpServerLicenseRequestEncodeError::InvalidRandom};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == RdpServerLicenseRequestEncodeError::None;
    }
};

// MS-RDPELE 2.2.2.1 SERVER_LICENSE_REQUEST for Enhanced RDP Security.
// Allocation-free; output is untouched on failure. The key-exchange BLOB is
// KEY_EXCHANGE_ALG_RSA and the nonempty BB_CERTIFICATE_BLOB is copied from
// explicit provisioning because Enhanced-Security SC_SECURITY contains no
// certificate fallback. Exactly one caller-provisioned scope is emitted.
// This function never invents random bytes, product/scope identity, certificate
// material, private-key binding, licensing authority, or authorization.
[[nodiscard]] RdpServerLicenseRequestEncodeResult
encodeEnhancedSecurityServerLicenseRequest(
    const RdpServerLicenseRequestFields &fields,
    std::span<std::uint8_t> output) noexcept;

enum class RdpLicensingPhase : std::uint8_t
{
    NotStarted,
    AwaitClientLicenseResponse,
    AwaitServerDecision,
    Failed,
    Closed,
};

enum class RdpLicensingIntake : std::uint8_t
{
    ClientLicenseInfoAccepted,
    ClientNewLicenseRequestAccepted,
    MalformedMessage,
    UnexpectedMessage,
    Failed,
    Closed,
};

// Stateful licensing phase owned by the sole R3 session. This component has
// no socket, SSL, thread, event loop, identity or authorization capability.
// Serialized event-loop use only. The initial transition means that a future
// authorized owner has fully delivered its Server License Request; encoding or
// queueing such a packet is not delivery. No transition to licensed/completed
// exists in this increment: accepted client syntax stops at AwaitServerDecision.
class RdpLicensingLifecycle final
{
public:
    RdpLicensingLifecycle() noexcept = default;
    RdpLicensingLifecycle(const RdpLicensingLifecycle &) = delete;
    RdpLicensingLifecycle &operator=(const RdpLicensingLifecycle &) = delete;
    RdpLicensingLifecycle(RdpLicensingLifecycle &&) = delete;
    RdpLicensingLifecycle &operator=(RdpLicensingLifecycle &&) = delete;

    [[nodiscard]] RdpLicensingPhase phase() const noexcept { return phase_; }
    // Public protocol random already sent on the wire, retained only while a
    // live licensing decision may still need MS-RDPELE 5.1.2 derivation.
    [[nodiscard]] std::span<const std::uint8_t> serverRandom() const noexcept
    {
        return serverRandomReady_
            ? std::span<const std::uint8_t>{serverRandom_}
            : std::span<const std::uint8_t>{};
    }

    // Accept exactly one complete client licensing message in the initial
    // response state. CLIENT_LICENSE_INFO and CLIENT_NEW_LICENSE_REQUEST are
    // structurally validated according to MS-RDPELE 2.2.2.3 and 2.2.2.2.
    // Cryptographic license validation/key derivation is deliberately not yet
    // performed, so success never means that licensing has completed.
    [[nodiscard]] RdpLicensingIntake onClientMessage(
        std::span<const std::uint8_t> completeMessage) noexcept;

    // Terminal for this object. Reconnect requires a fresh owning R3 session
    // and therefore a fresh RdpLicensingLifecycle instance.
    void close() noexcept
    {
        serverRandom_.fill(0U);
        serverRandomReady_ = false;
        phase_ = RdpLicensingPhase::Closed;
    }

private:
    friend class RdpServerLicenseRequestWriteGate;

    // Only the receipt gate may advance this transition after every byte of
    // its stable owned SERVER_LICENSE_REQUEST has been accepted.
    [[nodiscard]] bool onServerLicenseRequestWritten(
        std::span<const std::uint8_t> serverRandom) noexcept;
    void fail() noexcept
    {
        serverRandom_.fill(0U);
        serverRandomReady_ = false;
        phase_ = RdpLicensingPhase::Failed;
    }

    std::array<std::uint8_t, kRdpLicensingRandomBytes> serverRandom_{};
    RdpLicensingPhase phase_{RdpLicensingPhase::NotStarted};
    bool serverRandomReady_{};
};

struct RdpServerLicenseRequestWriteView
{
    std::span<const std::uint8_t> bytes{};
    std::uint64_t replySequence{};
    std::uint64_t writeSliceSequence{};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return !bytes.empty() && replySequence != 0U &&
               writeSliceSequence != 0U;
    }
};

enum class RdpServerLicenseRequestWriteOutcome : std::uint8_t
{
    Pending,
    Delivered,
    Rejected,
};

// Single-owner write accounting for one SERVER_LICENSE_REQUEST. Serialized
// event-loop use only. Stable contiguous bytes and two monotonic receipts bind
// every submitted suffix. Zero-byte backpressure preserves the slice; positive
// partial progress rotates only the slice receipt; only full accepted-byte
// delivery advances licensing. Any stale/duplicate receipt, overwrite,
// over-report, abandonment, or lifecycle mismatch closes both objects.
// This proves delivery only, not R2 admission or configuration provenance.
class RdpServerLicenseRequestWriteGate final
{
public:
    explicit RdpServerLicenseRequestWriteGate(
        RdpLicensingLifecycle &lifecycle) noexcept
        : lifecycle_(&lifecycle)
    {
    }
    RdpServerLicenseRequestWriteGate(
        const RdpServerLicenseRequestWriteGate &) = delete;
    RdpServerLicenseRequestWriteGate &operator=(
        const RdpServerLicenseRequestWriteGate &) = delete;
    RdpServerLicenseRequestWriteGate(
        RdpServerLicenseRequestWriteGate &&) = delete;
    RdpServerLicenseRequestWriteGate &operator=(
        RdpServerLicenseRequestWriteGate &&) = delete;

    // The live writer generates the required ServerRandom internally with
    // OpenSSL's private CSPRNG. Callers provide only immutable provisioning.
    [[nodiscard]] bool queue(
        const RdpServerLicenseIdentity &identity) noexcept;
    [[nodiscard]] RdpServerLicenseRequestWriteView
    pendingWrite() const noexcept;
    [[nodiscard]] RdpServerLicenseRequestWriteOutcome onBytesWritten(
        std::uint64_t replySequence,
        std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;
    void close() noexcept;

private:
    [[nodiscard]] bool advanceReplySequence() noexcept;
    [[nodiscard]] bool advanceWriteSliceSequence() noexcept;

    std::array<std::uint8_t, kMaximumRdpServerLicenseRequestBytes> pending_{};
    std::array<std::uint8_t, kRdpLicensingRandomBytes> serverRandom_{};
    RdpLicensingLifecycle *lifecycle_{};
    std::size_t pendingLength_{};
    std::size_t bytesWritten_{};
    std::uint64_t replySequence_{};
    std::uint64_t writeSliceSequence_{};
    bool delivered_{};
    bool closed_{};
};

} // namespace rdp_server::server::transport
