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

struct RdpLicensingKeyMaterial;

// MS-RDPELE 2.2.2.3.1 CLIENT_HARDWARE_ID and MACData have fixed wire sizes.
inline constexpr std::size_t kRdpLicensingHardwareIdBytes = 20U;
inline constexpr std::size_t kRdpLicensingMacBytes = 16U;

// Conservative R3-owned CAL inspection limits. CLIENT_LICENSE_INFO carries the
// opaque pbLicenseInfo returned by a license server; no peer length is used as
// an allocation size before this total bound is enforced.
inline constexpr std::size_t kMaximumRdpClientCalBytes = 16U * 1024U;
inline constexpr std::size_t kMaximumRdpClientCalCertificateBytes = 8U * 1024U;
inline constexpr std::size_t kMaximumRdpClientCalCertificateCount = 16U;

struct RdpClientLicenseInfoView
{
    std::span<const std::uint8_t> licenseInfo{};
    std::span<const std::uint8_t> encryptedHardwareId{};
    std::span<const std::uint8_t> macData{};
};

enum class RdpClientLicenseInfoParseError : std::uint8_t
{
    None,
    InvalidLicensingMessage,
    UnexpectedMessage,
    MalformedBody,
};

struct RdpClientLicenseInfoParseResult
{
    RdpClientLicenseInfoView value{};
    RdpClientLicenseInfoParseError error{
        RdpClientLicenseInfoParseError::InvalidLicensingMessage};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == RdpClientLicenseInfoParseError::None;
    }
};

[[nodiscard]] RdpClientLicenseInfoParseResult parseRdpClientLicenseInfo(
    std::span<const std::uint8_t> completeMessage) noexcept;

enum class RdpLicensingRc4Error : std::uint8_t
{
    None,
    InvalidKey,
    SizeMismatch,
};

struct RdpLicensingRc4Result
{
    RdpLicensingRc4Error error{RdpLicensingRc4Error::InvalidKey};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == RdpLicensingRc4Error::None;
    }
};

// MS-RDPELE 5.1.3/5.1.4 RC4 with the exact 128-bit licensing key.
// Equal-size input/output may overlap; no allocation or legacy provider is used.
[[nodiscard]] RdpLicensingRc4Result cryptRdpLicensingData(
    std::span<const std::uint8_t> encryptionKey,
    std::span<const std::uint8_t> input,
    std::span<std::uint8_t> output) noexcept;

enum class RdpLicensingMacError : std::uint8_t
{
    None,
    InvalidKey,
    OversizedData,
    DigestFailure,
};

struct RdpLicensingMacResult
{
    std::array<std::uint8_t, kRdpLicensingMacBytes> value{};
    RdpLicensingMacError error{RdpLicensingMacError::InvalidKey};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == RdpLicensingMacError::None;
    }
};

// MS-RDPELE 5.1.5 licensing MAC generation.
[[nodiscard]] RdpLicensingMacResult generateRdpLicensingMac(
    std::span<const std::uint8_t> macSaltKey,
    std::span<const std::uint8_t> data) noexcept;

enum class RdpClientLicenseInfoHardwareIdError : std::uint8_t
{
    None,
    InvalidMessage,
    DecryptFailure,
    MacFailure,
    MacMismatch,
};

struct RdpClientLicenseInfoHardwareIdResult
{
    RdpClientLicenseInfoHardwareIdError error{
        RdpClientLicenseInfoHardwareIdError::InvalidMessage};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == RdpClientLicenseInfoHardwareIdError::None;
    }
};

// Decrypt the 20-byte HWID and compare its MAC in constant time. This proves
// only HWID integrity; the CAL still requires trust/product/expiry validation.
[[nodiscard]] RdpClientLicenseInfoHardwareIdResult
verifyRdpClientLicenseInfoHardwareId(
    std::span<const std::uint8_t> completeMessage,
    const RdpLicensingKeyMaterial &keyMaterial) noexcept;

enum class RdpClientCalChainError : std::uint8_t
{
    None,
    Empty,
    Oversized,
    MalformedContainer,
    UnsupportedContainer,
    CertificateCountOutOfRange,
    OversizedCertificate,
    DuplicateCertificate,
    AmbiguousChain,
    MissingIssuer,
    UnsupportedCertificateVersion,
    UnsupportedSignatureAlgorithm,
    UnsupportedKeyType,
    SignatureVerificationFailure,
    MissingTrustAnchor,
    MalformedTrustAnchor,
    UntrustedTrustAnchor,
};

enum class RdpClientCalPolicyStatus : std::uint8_t
{
    NotEvaluated,
    MissingRequiredExtension,
    DuplicateRequiredExtension,
    UnsupportedCriticalExtension,
    RequiredExtensionsPresentButUnparsed,
};

enum class RdpClientCalLeafCertificateValidityStatus : std::uint8_t
{
    NotEvaluated,
    UnsupportedVerificationTime,
    MalformedWindow,
    NotYetValid,
    Valid,
    Expired,
};

struct RdpClientCalChainFacts
{
    std::size_t certificateCount{};
    bool signaturesVerified{};
    bool trustedIssuerMatched{};
    RdpClientCalPolicyStatus policyStatus{
        RdpClientCalPolicyStatus::NotEvaluated};
    RdpClientCalLeafCertificateValidityStatus leafCertificateValidity{
        RdpClientCalLeafCertificateValidityStatus::NotEvaluated};
};

struct RdpClientCalChainInspectionResult
{
    RdpClientCalChainFacts facts{};
    RdpClientCalChainError error{RdpClientCalChainError::MalformedContainer};
};

// Inspect one existing-client CAL candidate. The supported subset is canonical
// DER PKCS#7 SignedData carrying one unambiguous X.509 v3 chain. The peer root
// is never authority by itself: trustedRootDer must independently name the
// exact embedded root. Success reports only chain/signature/trust facts. The
// licensing extension payloads, product, expiry, HWID binding and CAL class are
// deliberately not accepted yet, so this API cannot license a session.
[[nodiscard]] RdpClientCalChainInspectionResult
inspectRdpClientCalCertificateChain(
    std::span<const std::uint8_t> licenseInfo,
    std::span<const std::uint8_t> trustedRootDer) noexcept;

// Evaluate the leaf certificate's RFC-defined validity interval at one
// caller-supplied Unix timestamp. This is a necessary X.509 chain fact only:
// it does not decode the RDP licensing extensions, classify CAL expiry, bind a
// CAL to the protected-message HWID or authorize a licensing transition.
[[nodiscard]] RdpClientCalChainInspectionResult
inspectRdpClientCalCertificateChainAtTime(
    std::span<const std::uint8_t> licenseInfo,
    std::span<const std::uint8_t> trustedRootDer,
    std::int64_t verificationUnixSeconds) noexcept;

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

// Wipe session-owned licensing keys with OpenSSL's non-optimizable cleanse.
// Safe on already-zero/default material and intended for terminal teardown.
void cleanseRdpLicensingKeyMaterial(
    RdpLicensingKeyMaterial &material) noexcept;

// MS-RDPELE 5.1.2. The caller must already have decrypted and validated the
// exact 48-byte premaster secret with the matching licensing private key.
// This helper derives keys only; it does not perform RSA, RC4, MAC validation,
// license validation, authorization or any session phase transition.
[[nodiscard]] RdpLicensingKeyDerivationResult deriveRdpLicensingKeys(
    std::span<const std::uint8_t> preMasterSecret,
    std::span<const std::uint8_t> clientRandom,
    std::span<const std::uint8_t> serverRandom) noexcept;

// R3's concrete Server Platform Challenge profile uses a fresh 128-bit
// CSPRNG seed rendered as 32 uppercase hexadecimal UTF-16LE characters plus
// the terminating null. The wire field is variable-length; this fixed profile
// preserves full seed entropy while preventing embedded terminators.
inline constexpr std::size_t kRdpPlatformChallengeSeedBytes = 16U;
inline constexpr std::size_t kRdpPlatformChallengePlaintextBytes = 66U;
inline constexpr std::size_t kRdpServerPlatformChallengeBytes =
    4U + 4U + 4U + kRdpPlatformChallengePlaintextBytes +
    kRdpLicensingMacBytes;

enum class RdpServerPlatformChallengeEncodeError : std::uint8_t
{
    None,
    InvalidChallenge,
    EncryptionFailure,
    MacFailure,
    OutputTooSmall,
};

struct RdpServerPlatformChallengeEncodeResult
{
    std::size_t bytesWritten{};
    RdpServerPlatformChallengeEncodeError error{
        RdpServerPlatformChallengeEncodeError::InvalidChallenge};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == RdpServerPlatformChallengeEncodeError::None;
    }
};

// MS-RDPELE 2.2.2.4 pure encoder. MACData is generated over the plaintext
// challenge and the challenge BLOB is RC4-encrypted with the exact derived
// session keys. No authorization or state transition occurs here, and caller
// output is unchanged on failure.
[[nodiscard]] RdpServerPlatformChallengeEncodeResult
encodeRdpServerPlatformChallenge(
    std::span<const std::uint8_t> plaintextChallenge,
    const RdpLicensingKeyMaterial &keyMaterial,
    std::span<std::uint8_t> output) noexcept;

inline constexpr std::size_t
    kRdpPlatformChallengeResponseHeaderBytes = 8U;
inline constexpr std::size_t
    kRdpPlatformChallengeResponseDataBytes =
        kRdpPlatformChallengeResponseHeaderBytes +
        kRdpPlatformChallengePlaintextBytes;

enum class RdpClientPlatformChallengeResponseError : std::uint8_t
{
    None,
    InvalidMessage,
    InvalidBlob,
    DecryptFailure,
    InvalidResponseData,
    ChallengeMismatch,
    MacFailure,
    MacMismatch,
};

struct RdpClientPlatformChallengeResponseResult
{
    std::uint16_t clientType{};
    std::uint16_t licenseDetailLevel{};
    RdpClientPlatformChallengeResponseError error{
        RdpClientPlatformChallengeResponseError::InvalidMessage};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == RdpClientPlatformChallengeResponseError::None;
    }
};

// MS-RDPELE 2.2.2.5 / 2.2.2.5.1. Decrypt both BB_ENCRYPTED_DATA_BLOB
// values with the already-derived licensing key, require version 0x0100,
// a normative client type/detail level, exact retained challenge equality,
// a 20-byte HWID, and MACData over plaintext response-data || HWID.
// No license is issued and no authorization is inferred.
[[nodiscard]] RdpClientPlatformChallengeResponseResult
verifyRdpClientPlatformChallengeResponse(
    std::span<const std::uint8_t> completeMessage,
    const RdpLicensingKeyMaterial &keyMaterial,
    std::span<const std::uint8_t> expectedChallenge) noexcept;

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

// Initial client-response cryptographic preparation. This does NOT validate a
// CAL, HWID or licensing MAC and does not change any session/lifecycle state.
// It only proves that the already-bounded initial response's encrypted
// premaster can be unwrapped by the exact configured credential and derives
// the two MS-RDPELE 5.1.2 keys using the request's exact ServerRandom.
enum class RdpInitialLicensingCryptoError : std::uint8_t
{
    None,
    InvalidServerRandom,
    InvalidClientMessage,
    PreMasterDecryptFailure,
    KeyDerivationFailure,
};

struct RdpInitialLicensingCryptoResult
{
    RdpLicensingKeyMaterial value{};
    RdpInitialLicensingCryptoError error{
        RdpInitialLicensingCryptoError::InvalidClientMessage};
    RdpLicensingMessageType messageType{
        RdpLicensingMessageType::ErrorAlert};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == RdpInitialLicensingCryptoError::None;
    }
};

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

// Parse the exact initial licensing message, unwrap its encrypted premaster
// through the configured credential, derive MAC/encryption keys, and cleanse
// the temporary 48-byte premaster before returning. The returned keys remain
// sensitive and must be cleansed by their owner on every terminal path.
[[nodiscard]] RdpInitialLicensingCryptoResult
prepareInitialRdpLicensingCrypto(
    const RdpLicensingServiceCredential &credential,
    std::span<const std::uint8_t> completeMessage,
    std::span<const std::uint8_t> serverRandom) noexcept;

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

// Local plaintext bound for NEW_LICENSE_INFO. Combined with the existing
// 512-byte scope/company/product bounds and later licensing wrapper overhead,
// this keeps a future encrypted grant below R1's 18 KiB application-write cap.
// CAL bytes are opaque here and MUST come from a real licensing authority.
inline constexpr std::size_t kMaximumRdpIssuedCalBytes =
    kMaximumRdpClientCalBytes;
inline constexpr std::size_t kRdpNewLicenseInfoFixedBytes = 20U;
inline constexpr std::size_t kMaximumRdpNewLicenseInfoBytes =
    kRdpNewLicenseInfoFixedBytes +
    3U * kMaximumRdpServerLicenseIdentityTextBytes +
    kMaximumRdpIssuedCalBytes;

// One unfragmented T.125 SendData userData field is limited to 14 bits.
// The eventual Enhanced-Security envelope consumes four of those bytes for
// TS_SECURITY_HEADER, so this pure licensing packet must stay <= 16,379
// bytes. With all three identity strings at their configured 512-byte maxima,
// the largest CAL that is always transportable without PER fragmentation is
// therefore 14,799 bytes. The complete future TPKT/X.224/MCS long-header
// application write is 16,398 bytes, below R1's 18 KiB plaintext ceiling.
inline constexpr std::size_t
    kMaximumRdpLicensingUnfragmentedMcsUserDataBytes = 16383U;
inline constexpr std::size_t kRdpLicensingBasicSecurityHeaderBytes = 4U;
inline constexpr std::size_t kRdpServerLicenseGrantFixedBytes =
    4U + 4U + kRdpLicensingMacBytes;
inline constexpr std::size_t kMaximumRdpServerLicenseGrantCalBytes =
    kMaximumRdpLicensingUnfragmentedMcsUserDataBytes -
    kRdpLicensingBasicSecurityHeaderBytes -
    kRdpServerLicenseGrantFixedBytes -
    kRdpNewLicenseInfoFixedBytes -
    3U * kMaximumRdpServerLicenseIdentityTextBytes;
inline constexpr std::size_t kMaximumRdpServerLicenseGrantPlaintextBytes =
    kRdpNewLicenseInfoFixedBytes +
    3U * kMaximumRdpServerLicenseIdentityTextBytes +
    kMaximumRdpServerLicenseGrantCalBytes;
inline constexpr std::size_t kMaximumRdpServerLicenseGrantBytes =
    kRdpServerLicenseGrantFixedBytes +
    kMaximumRdpServerLicenseGrantPlaintextBytes;
inline constexpr std::size_t kRdpServerLicenseGrantLongMcsHeaderBytes = 15U;
inline constexpr std::size_t
    kMaximumRdpServerLicenseGrantTlsApplicationBytes =
        kRdpServerLicenseGrantLongMcsHeaderBytes +
        kRdpLicensingBasicSecurityHeaderBytes +
        kMaximumRdpServerLicenseGrantBytes;

static_assert(kMaximumRdpServerLicenseGrantCalBytes == 14799U);
static_assert(
    kMaximumRdpServerLicenseGrantBytes +
        kRdpLicensingBasicSecurityHeaderBytes ==
    kMaximumRdpLicensingUnfragmentedMcsUserDataBytes);
static_assert(kMaximumRdpServerLicenseGrantBytes == 16379U);
static_assert(kMaximumRdpServerLicenseGrantTlsApplicationBytes == 16398U);

enum class RdpNewLicenseInfoEncodeError : std::uint8_t
{
    None,
    IdentityNotConfigured,
    InvalidLicense,
    Oversized,
    OutputTooSmall,
};

struct RdpNewLicenseInfoEncodeResult
{
    std::size_t bytesWritten{};
    RdpNewLicenseInfoEncodeError error{
        RdpNewLicenseInfoEncodeError::IdentityNotConfigured};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == RdpNewLicenseInfoEncodeError::None;
    }
};

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

// MS-RDPELE 2.2.2.6.1 NEW_LICENSE_INFO plaintext serializer. It reuses the
// immutable request identity for version/scope/company/product indexing and
// copies one caller-provided opaque CAL. It does NOT validate/sign/issue the
// CAL, encrypt the structure, generate MACData, mutate licensing state, or
// authorize publication. Output remains untouched on every rejected input.
[[nodiscard]] RdpNewLicenseInfoEncodeResult encodeRdpNewLicenseInformation(
    const RdpServerLicenseIdentity &identity,
    std::span<const std::uint8_t> issuedCal,
    std::span<std::uint8_t> output) noexcept;

enum class RdpServerLicenseGrantKind : std::uint8_t
{
    NewLicense = 0x03U,
    UpgradeLicense = 0x04U,
};

// Opaque correlation token for one service-owned licensing-authority result.
// R3 does not define the fingerprint's contents; the future authority owner
// must rotate both this token and its nonzero generation when issuance policy
// or material changes.
inline constexpr std::size_t kRdpLicensingAuthorityFingerprintBytes = 32U;

enum class RdpLicensingAuthorityGrantError : std::uint8_t
{
    None,
    AlreadyConfigured,
    InvalidAuthorityGeneration,
    InvalidAuthorityFingerprint,
    InvalidLicense,
    Oversized,
};

// Non-live, one-shot snapshot of a license-authority issuance result. The CAL
// is capped to the grant encoder's always-unfragmented limit rather than the
// larger offline NEW_LICENSE_INFO limit. This object owns no authority by
// itself: it cannot mutate R3 state, invoke R2, create a write receipt, or
// publish bytes. Future live publication must receive it from the actual
// service authority owner and freshly match generation/fingerprint first.
class RdpLicensingAuthorityGrant final
{
public:
    RdpLicensingAuthorityGrant() noexcept = default;
    RdpLicensingAuthorityGrant(const RdpLicensingAuthorityGrant &) = delete;
    RdpLicensingAuthorityGrant &operator=(
        const RdpLicensingAuthorityGrant &) = delete;
    RdpLicensingAuthorityGrant(RdpLicensingAuthorityGrant &&) = delete;
    RdpLicensingAuthorityGrant &operator=(
        RdpLicensingAuthorityGrant &&) = delete;

    [[nodiscard]] RdpLicensingAuthorityGrantError configure(
        RdpServerLicenseGrantKind kind,
        std::uint64_t authorityGeneration,
        std::span<const std::uint8_t> authorityFingerprint,
        std::span<const std::uint8_t> issuedCal) noexcept;

    [[nodiscard]] bool configured() const noexcept { return configured_; }
    [[nodiscard]] RdpServerLicenseGrantKind kind() const noexcept
    {
        return kind_;
    }
    [[nodiscard]] std::uint64_t authorityGeneration() const noexcept
    {
        return configured_ ? authorityGeneration_ : 0U;
    }
    [[nodiscard]] std::span<const std::uint8_t>
    authorityFingerprint() const noexcept
    {
        return configured_
            ? std::span<const std::uint8_t>{authorityFingerprint_}
            : std::span<const std::uint8_t>{};
    }
    [[nodiscard]] std::span<const std::uint8_t> issuedCal() const noexcept
    {
        return configured_
            ? std::span<const std::uint8_t>{issuedCal_}.first(issuedCalLength_)
            : std::span<const std::uint8_t>{};
    }

    // Constant-time fingerprint comparison plus exact generation correlation.
    // A match is continuity evidence only; it is not licensing authority.
    [[nodiscard]] bool matchesAuthority(
        std::uint64_t authorityGeneration,
        std::span<const std::uint8_t> authorityFingerprint) const noexcept;

private:
    std::array<std::uint8_t, kRdpLicensingAuthorityFingerprintBytes>
        authorityFingerprint_{};
    std::array<std::uint8_t, kMaximumRdpServerLicenseGrantCalBytes>
        issuedCal_{};
    RdpServerLicenseGrantKind kind_{RdpServerLicenseGrantKind::NewLicense};
    std::uint64_t authorityGeneration_{};
    std::size_t issuedCalLength_{};
    bool attempted_{};
    bool configured_{};
};

// Borrowed view over exactly one derived RdpLicensingKeyMaterial. The explicit
// span constructor exists so fail-closed tests can exercise truncated keys;
// no key bytes are copied, retained, logged, or interpreted as authority.
struct RdpLicensingKeyMaterialView
{
    std::span<const std::uint8_t> macSaltKey{};
    std::span<const std::uint8_t> encryptionKey{};

    RdpLicensingKeyMaterialView(
        const RdpLicensingKeyMaterial &material) noexcept
        : macSaltKey(material.macSaltKey),
          encryptionKey(material.encryptionKey)
    {
    }

    RdpLicensingKeyMaterialView(
        std::span<const std::uint8_t> macSaltKeyValue,
        std::span<const std::uint8_t> encryptionKeyValue) noexcept
        : macSaltKey(macSaltKeyValue),
          encryptionKey(encryptionKeyValue)
    {
    }
};

enum class RdpServerLicenseGrantEncodeError : std::uint8_t
{
    None,
    InvalidGrantKind,
    IdentityNotConfigured,
    InvalidLicense,
    InvalidKeyMaterial,
    Oversized,
    OutputTooSmall,
    PlaintextEncodingFailure,
    EncryptionFailure,
    MacFailure,
};

struct RdpServerLicenseGrantEncodeResult
{
    std::size_t bytesWritten{};
    RdpServerLicenseGrantEncodeError error{
        RdpServerLicenseGrantEncodeError::InvalidGrantKind};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == RdpServerLicenseGrantEncodeError::None;
    }
};

// MS-RDPELE 2.2.2.6 / 2.2.2.7 pure New/Upgrade License encoder. It reuses
// encodeRdpNewLicenseInformation, RC4 and the licensing MAC over the complete
// plaintext, then emits one BB_ENCRYPTED_DATA_BLOB followed by MACData.
// issuedCal is opaque authority output supplied by the caller; this helper
// does not validate/sign/issue it, mutate lifecycle state, create receipts,
// invoke R2, or publish bytes. Output is transactional on every failure.
[[nodiscard]] RdpServerLicenseGrantEncodeResult encodeRdpServerLicenseGrant(
    RdpServerLicenseGrantKind kind,
    const RdpServerLicenseIdentity &identity,
    std::span<const std::uint8_t> issuedCal,
    RdpLicensingKeyMaterialView keyMaterial,
    std::span<std::uint8_t> output) noexcept;

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

enum class RdpLicensingDecisionBranch : std::uint8_t
{
    None,
    ClientLicenseInfoValidation,
    PlatformChallengeRequired,
    AwaitPlatformChallengeResponse,
    NewLicenseIssuanceRequired,
};

enum class RdpLicensingPhase : std::uint8_t
{
    NotStarted,
    AwaitClientLicenseResponse,
    AwaitServerDecision,
    AwaitClientPlatformChallengeResponse,
    Licensed,
    Failed,
    Closed,
};

enum class RdpLicensingIntake : std::uint8_t
{
    ClientLicenseInfoAccepted,
    ClientNewLicenseRequestAccepted,
    ClientPlatformChallengeResponseAccepted,
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
    [[nodiscard]] RdpLicensingDecisionBranch decisionBranch() const noexcept
    {
        return decisionBranch_;
    }
    [[nodiscard]] std::span<const std::uint8_t>
    platformChallenge() const noexcept
    {
        return platformChallengeReady_
            ? std::span<const std::uint8_t>{platformChallenge_}
            : std::span<const std::uint8_t>{};
    }
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

    // Accept only the response to this lifecycle's fully delivered platform
    // challenge. Cryptographic integrity/challenge correlation are mandatory;
    // success stops at the next server-decision gate before license issuance.
    [[nodiscard]] RdpLicensingIntake onClientPlatformChallengeResponse(
        std::span<const std::uint8_t> completeMessage,
        const RdpLicensingKeyMaterial &keyMaterial) noexcept;

    // Terminal for this object. Reconnect requires a fresh owning R3 session
    // and therefore a fresh RdpLicensingLifecycle instance.
    void close() noexcept
    {
        serverRandom_.fill(0U);
        platformChallenge_.fill(0U);
        serverRandomReady_ = false;
        platformChallengeReady_ = false;
        decisionBranch_ = RdpLicensingDecisionBranch::None;
        phase_ = RdpLicensingPhase::Closed;
    }

private:
    friend class RdpServerLicenseRequestWriteGate;
    friend class RdpServerPlatformChallengeWriteGate;
    friend class RdpServerLicenseGrantWriteGate;

    // Only the receipt gate may advance this transition after every byte of
    // its stable owned SERVER_LICENSE_REQUEST has been accepted.
    [[nodiscard]] bool onServerLicenseRequestWritten(
        std::span<const std::uint8_t> serverRandom) noexcept;
    [[nodiscard]] bool onServerPlatformChallengeWritten(
        std::span<const std::uint8_t> plaintextChallenge) noexcept;
    [[nodiscard]] bool onServerLicenseGrantWritten(
        RdpServerLicenseGrantKind kind) noexcept;
    void fail() noexcept
    {
        serverRandom_.fill(0U);
        platformChallenge_.fill(0U);
        serverRandomReady_ = false;
        platformChallengeReady_ = false;
        decisionBranch_ = RdpLicensingDecisionBranch::None;
        phase_ = RdpLicensingPhase::Failed;
    }

    std::array<std::uint8_t, kRdpLicensingRandomBytes> serverRandom_{};
    std::array<std::uint8_t, kRdpPlatformChallengePlaintextBytes>
        platformChallenge_{};
    RdpLicensingPhase phase_{RdpLicensingPhase::NotStarted};
    RdpLicensingDecisionBranch decisionBranch_{
        RdpLicensingDecisionBranch::None};
    bool serverRandomReady_{};
    bool platformChallengeReady_{};
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

struct RdpServerPlatformChallengeWriteView
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

enum class RdpServerPlatformChallengeWriteOutcome : std::uint8_t
{
    Pending,
    Delivered,
    Rejected,
};

// Single-owner receipt accounting for the standards-required challenge after
// CLIENT_NEW_LICENSE_REQUEST. queue() generates fresh challenge material,
// encrypts/MACs one stable packet and exposes suffixes until exact delivery.
// Stale/duplicate/over-reported receipts are terminal.
class RdpServerPlatformChallengeWriteGate final
{
public:
    explicit RdpServerPlatformChallengeWriteGate(
        RdpLicensingLifecycle &lifecycle) noexcept
        : lifecycle_(&lifecycle)
    {
    }
    RdpServerPlatformChallengeWriteGate(
        const RdpServerPlatformChallengeWriteGate &) = delete;
    RdpServerPlatformChallengeWriteGate &operator=(
        const RdpServerPlatformChallengeWriteGate &) = delete;
    RdpServerPlatformChallengeWriteGate(
        RdpServerPlatformChallengeWriteGate &&) = delete;
    RdpServerPlatformChallengeWriteGate &operator=(
        RdpServerPlatformChallengeWriteGate &&) = delete;

    [[nodiscard]] bool queue(
        const RdpLicensingKeyMaterial &keyMaterial) noexcept;
    [[nodiscard]] RdpServerPlatformChallengeWriteView
    pendingWrite() const noexcept;
    [[nodiscard]] RdpServerPlatformChallengeWriteOutcome onBytesWritten(
        std::uint64_t replySequence,
        std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;
    void close() noexcept;

private:
    [[nodiscard]] bool advanceReplySequence() noexcept;
    [[nodiscard]] bool advanceWriteSliceSequence() noexcept;

    std::array<std::uint8_t, kRdpServerPlatformChallengeBytes> pending_{};
    std::array<std::uint8_t, kRdpPlatformChallengePlaintextBytes>
        plaintextChallenge_{};
    RdpLicensingLifecycle *lifecycle_{};
    std::size_t pendingLength_{};
    std::size_t bytesWritten_{};
    std::uint64_t replySequence_{};
    std::uint64_t writeSliceSequence_{};
    bool delivered_{};
    bool closed_{};
};

struct RdpServerLicenseGrantWriteView
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

enum class RdpServerLicenseGrantWriteOutcome : std::uint8_t
{
    Pending,
    Delivered,
    Rejected,
};

// Receipt owner for an already-authority-issued New License. This is still
// not a live publication capability: no R2 broker/session entry exposes it.
// queue() requires an exact authority generation/fingerprint match, the
// existing immutable product identity, and already-derived licensing keys.
// Upgrade License remains offline until CLIENT_LICENSE_INFO trust validation
// exists. Full accepted-byte delivery alone moves the licensing lifecycle to
// Licensed; stale/duplicate/over-reported receipts close it.
class RdpServerLicenseGrantWriteGate final
{
public:
    explicit RdpServerLicenseGrantWriteGate(
        RdpLicensingLifecycle &lifecycle) noexcept
        : lifecycle_(&lifecycle)
    {
    }
    RdpServerLicenseGrantWriteGate(
        const RdpServerLicenseGrantWriteGate &) = delete;
    RdpServerLicenseGrantWriteGate &operator=(
        const RdpServerLicenseGrantWriteGate &) = delete;
    RdpServerLicenseGrantWriteGate(
        RdpServerLicenseGrantWriteGate &&) = delete;
    RdpServerLicenseGrantWriteGate &operator=(
        RdpServerLicenseGrantWriteGate &&) = delete;

    [[nodiscard]] bool queue(
        const RdpLicensingAuthorityGrant &grant,
        const RdpServerLicenseIdentity &identity,
        const RdpLicensingKeyMaterial &keyMaterial,
        std::uint64_t authorityGeneration,
        std::span<const std::uint8_t> authorityFingerprint) noexcept;
    [[nodiscard]] RdpServerLicenseGrantWriteView pendingWrite() const noexcept;
    [[nodiscard]] RdpServerLicenseGrantWriteOutcome onBytesWritten(
        std::uint64_t replySequence,
        std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;
    void close() noexcept;

private:
    [[nodiscard]] bool advanceReplySequence() noexcept;
    [[nodiscard]] bool advanceWriteSliceSequence() noexcept;

    std::array<std::uint8_t, kMaximumRdpServerLicenseGrantBytes> pending_{};
    RdpLicensingLifecycle *lifecycle_{};
    std::size_t pendingLength_{};
    std::size_t bytesWritten_{};
    std::uint64_t replySequence_{};
    std::uint64_t writeSliceSequence_{};
    bool delivered_{};
    bool closed_{};
};

} // namespace rdp_server::server::transport
