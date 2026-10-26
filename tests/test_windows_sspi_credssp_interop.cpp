// SPDX-License-Identifier: GPL-3.0-or-later
#define SECURITY_WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <credssp.h>
#include <schannel.h>
#include <sspi.h>

#include "server/runtime/runtime_tls_context.h"
#include "server/security/credssp_tsrequest.h"
#include "server/security/standalone_credssp.h"
#include "server/security/standalone_ntlmssp.h"
#include "server/security/standalone_ntlmv2.h"

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

using namespace rdp_server::server::runtime;
using namespace rdp_server::server::security;

namespace
{

enum class TargetProfile : std::uint8_t
{
    PortableServerName,
    PhysicalIpv4,
};

[[nodiscard]] constexpr std::wstring_view targetName(
    TargetProfile profile) noexcept
{
    switch (profile)
    {
    case TargetProfile::PortableServerName:
        return L"TERMSRV/RDP-SERVER";
    case TargetProfile::PhysicalIpv4:
        return L"TERMSRV/192.168.1.5";
    }
    return {};
}

[[nodiscard]] constexpr const char *targetLabel(
    TargetProfile profile) noexcept
{
    switch (profile)
    {
    case TargetProfile::PortableServerName:
        return "TERMSRV/RDP-SERVER";
    case TargetProfile::PhysicalIpv4:
        return "TERMSRV/192.168.1.5";
    }
    return "unknown";
}

constexpr std::string_view kPhysicalEndpoint{"192.168.1.5"};
constexpr NtlmServerChallenge kServerChallenge{
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
constexpr ULONG kCredSspContextRequirements =
    ISC_REQ_ALLOCATE_MEMORY |
    ISC_REQ_CONNECTION |
    ISC_REQ_MANUAL_CRED_VALIDATION;
constexpr std::size_t kMaximumExchangeRounds = 128U;
constexpr std::size_t kMaximumRawTokenBytes = 256U * 1024U;

[[nodiscard]] bool securityStatusSucceeded(
    SECURITY_STATUS status) noexcept
{
    return status >= 0;
}

[[nodiscard]] std::uint64_t currentWindowsFileTime() noexcept
{
    FILETIME fileTime{};
    GetSystemTimeAsFileTime(&fileTime);
    return (static_cast<std::uint64_t>(fileTime.dwHighDateTime) << 32U) |
           static_cast<std::uint64_t>(fileTime.dwLowDateTime);
}

class AllocatedSspiToken final
{
public:
    AllocatedSspiToken() noexcept = default;
    ~AllocatedSspiToken() { reset(); }

    AllocatedSspiToken(const AllocatedSspiToken &) = delete;
    AllocatedSspiToken &operator=(const AllocatedSspiToken &) = delete;

    AllocatedSspiToken(AllocatedSspiToken &&other) noexcept
        : data_(std::exchange(other.data_, nullptr)),
          size_(std::exchange(other.size_, 0U))
    {
    }

    AllocatedSspiToken &operator=(AllocatedSspiToken &&other) noexcept
    {
        if (this == &other)
            return *this;
        reset();
        data_ = std::exchange(other.data_, nullptr);
        size_ = std::exchange(other.size_, 0U);
        return *this;
    }

    void adopt(void *data, unsigned long size) noexcept
    {
        reset();
        data_ = data;
        size_ = static_cast<std::size_t>(size);
    }

    [[nodiscard]] std::span<const std::uint8_t> view() const noexcept
    {
        if (data_ == nullptr)
            return {};
        return {
            static_cast<const std::uint8_t *>(data_),
            size_};
    }

    [[nodiscard]] bool empty() const noexcept
    {
        return data_ == nullptr || size_ == 0U;
    }

private:
    void reset() noexcept
    {
        if (data_ != nullptr)
            FreeContextBuffer(data_);
        data_ = nullptr;
        size_ = 0U;
    }

    void *data_{};
    std::size_t size_{};
};

struct CredSspClientStep final
{
    SECURITY_STATUS status{SEC_E_INTERNAL_ERROR};
    ULONG contextAttributes{};
    AllocatedSspiToken output{};
};

[[nodiscard]] SECURITY_STATUS completeOutputTokenIfNeeded(
    SECURITY_STATUS status,
    CtxtHandle &context,
    SecBufferDesc &outputDescriptor) noexcept
{
    if (status != SEC_I_COMPLETE_NEEDED &&
        status != SEC_I_COMPLETE_AND_CONTINUE)
    {
        return status;
    }

    const SECURITY_STATUS completeStatus =
        CompleteAuthToken(&context, &outputDescriptor);
    if (!securityStatusSucceeded(completeStatus))
        return completeStatus;

    return status == SEC_I_COMPLETE_AND_CONTINUE
        ? SEC_I_CONTINUE_NEEDED
        : SEC_E_OK;
}

class WindowsCredSspClient final
{
public:
    WindowsCredSspClient() noexcept
    {
        identity_.User = username_.data();
        identity_.UserLength =
            static_cast<unsigned long>(username_.size());
        identity_.Domain = domain_.data();
        identity_.DomainLength =
            static_cast<unsigned long>(domain_.size());
        identity_.Password = password_.data();
        identity_.PasswordLength =
            static_cast<unsigned long>(password_.size());
        identity_.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

        schannel_.dwVersion = SCHANNEL_CRED_VERSION;
        schannel_.dwFlags =
            SCH_CRED_MANUAL_CRED_VALIDATION |
            SCH_CRED_NO_DEFAULT_CREDS |
            SCH_USE_STRONG_CRYPTO;

        credSsp_.Type = CredsspSubmitBufferBoth;
        credSsp_.pSchannelCred = &schannel_;
        credSsp_.pSpnegoCred = &identity_;
    }

    ~WindowsCredSspClient()
    {
        if (contextValid_)
            DeleteSecurityContext(&context_);
        if (credentialValid_)
            FreeCredentialsHandle(&credential_);
        SecureZeroMemory(
            password_.data(), password_.size() * sizeof(password_[0]));
    }

    WindowsCredSspClient(const WindowsCredSspClient &) = delete;
    WindowsCredSspClient &operator=(const WindowsCredSspClient &) = delete;

    [[nodiscard]] SECURITY_STATUS acquire() noexcept
    {
        wchar_t packageName[] = L"CREDSSP";
        TimeStamp expiry{};
        const SECURITY_STATUS status = AcquireCredentialsHandleW(
            nullptr,
            packageName,
            SECPKG_CRED_OUTBOUND,
            nullptr,
            &credSsp_,
            nullptr,
            nullptr,
            &credential_,
            &expiry);
        credentialValid_ = securityStatusSucceeded(status);
        return status;
    }

    [[nodiscard]] CredSspClientStep step(
        TargetProfile profile,
        std::span<const std::uint8_t> serverToken) noexcept
    {
        CredSspClientStep result{};
        if (!credentialValid_)
        {
            result.status = SEC_E_INVALID_HANDLE;
            return result;
        }

        std::array<wchar_t, 64> mutableTarget{};
        const auto sourceTarget = targetName(profile);
        if (sourceTarget.empty() ||
            sourceTarget.size() + 1U > mutableTarget.size())
        {
            result.status = SEC_E_TARGET_UNKNOWN;
            return result;
        }
        std::copy(
            sourceTarget.begin(), sourceTarget.end(), mutableTarget.begin());

        std::vector<std::uint8_t> mutableInput;
        std::array<SecBuffer, 2> inputBuffers{};
        SecBufferDesc inputDescriptor{};
        SecBufferDesc *input = nullptr;
        if (contextValid_)
        {
            if (serverToken.empty() ||
                serverToken.size() >
                    static_cast<std::size_t>(
                        (std::numeric_limits<unsigned long>::max)()))
            {
                result.status = SEC_E_INCOMPLETE_MESSAGE;
                return result;
            }
            try
            {
                mutableInput.assign(serverToken.begin(), serverToken.end());
            }
            catch (...)
            {
                result.status = SEC_E_INSUFFICIENT_MEMORY;
                return result;
            }

            inputBuffers[0].BufferType = SECBUFFER_TOKEN;
            inputBuffers[0].cbBuffer =
                static_cast<unsigned long>(mutableInput.size());
            inputBuffers[0].pvBuffer = mutableInput.data();
            inputBuffers[1].BufferType = SECBUFFER_EMPTY;
            inputDescriptor.ulVersion = SECBUFFER_VERSION;
            inputDescriptor.cBuffers =
                static_cast<unsigned long>(inputBuffers.size());
            inputDescriptor.pBuffers = inputBuffers.data();
            input = &inputDescriptor;
        }

        SecBuffer outputBuffer{};
        outputBuffer.BufferType = SECBUFFER_TOKEN;
        SecBufferDesc outputDescriptor{
            SECBUFFER_VERSION, 1U, &outputBuffer};

        TimeStamp expiry{};
        CtxtHandle newContext{};
        CtxtHandle *const existingContext =
            contextValid_ ? &context_ : nullptr;
        CtxtHandle *const outputContext =
            contextValid_ ? &context_ : &newContext;

        result.status = InitializeSecurityContextW(
            &credential_,
            existingContext,
            mutableTarget.data(),
            kCredSspContextRequirements,
            0U,
            SECURITY_NATIVE_DREP,
            input,
            0U,
            outputContext,
            &outputDescriptor,
            &result.contextAttributes,
            &expiry);

        if (!contextValid_ && securityStatusSucceeded(result.status))
        {
            context_ = newContext;
            contextValid_ = true;
        }

        if (contextValid_)
        {
            result.status = completeOutputTokenIfNeeded(
                result.status, context_, outputDescriptor);
        }

        if (outputBuffer.pvBuffer != nullptr)
        {
            result.output.adopt(
                outputBuffer.pvBuffer, outputBuffer.cbBuffer);
            outputBuffer.pvBuffer = nullptr;
            outputBuffer.cbBuffer = 0U;
        }
        return result;
    }

private:
    std::array<unsigned short, 4> username_{
        static_cast<unsigned short>('U'),
        static_cast<unsigned short>('s'),
        static_cast<unsigned short>('e'),
        static_cast<unsigned short>('r')};
    std::array<unsigned short, 3> domain_{
        static_cast<unsigned short>('R'),
        static_cast<unsigned short>('D'),
        static_cast<unsigned short>('P')};
    std::array<unsigned short, 8> password_{
        static_cast<unsigned short>('P'),
        static_cast<unsigned short>('a'),
        static_cast<unsigned short>('s'),
        static_cast<unsigned short>('s'),
        static_cast<unsigned short>('w'),
        static_cast<unsigned short>('o'),
        static_cast<unsigned short>('r'),
        static_cast<unsigned short>('d')};
    SEC_WINNT_AUTH_IDENTITY_W identity_{};
    SCHANNEL_CRED schannel_{};
    CREDSSP_CRED credSsp_{};
    CredHandle credential_{};
    CtxtHandle context_{};
    bool credentialValid_{};
    bool contextValid_{};
};

enum class TlsAdvance : std::uint8_t
{
    NeedPeer,
    Ready,
    Failed,
};

enum class FrameAdvance : std::uint8_t
{
    NeedPeer,
    Complete,
    Failed,
};

class ProductionCredSspServer final
{
public:
    ProductionCredSspServer() noexcept
        : tls_(nullptr, &SSL_free)
    {
        tlsContext_ =
            RuntimeServerTlsContext::fromGeneratedIpAddress(
                kPhysicalEndpoint);
        if (!tlsContext_ ||
            tlsContext_.validateEndpointIdentity(kPhysicalEndpoint) !=
                RuntimeTlsEndpointIdentityStatus::Match)
        {
            return;
        }

        tls_ = tlsContext_.createServerTls();
        if (!tls_)
            return;

        BIO *inputBio = BIO_new(BIO_s_mem());
        BIO *outputBio = BIO_new(BIO_s_mem());
        if (inputBio == nullptr || outputBio == nullptr)
        {
            BIO_free(inputBio);
            BIO_free(outputBio);
            return;
        }
        BIO_set_mem_eof_return(inputBio, -1);
        BIO_set_mem_eof_return(outputBio, -1);
        SSL_set_bio(tls_.get(), inputBio, outputBio);
        inputBio_ = SSL_get_rbio(tls_.get());
        outputBio_ = SSL_get_wbio(tls_.get());

        std::array<char16_t, 8> password{
            u'P',u'a',u's',u's',u'w',u'o',u'r',u'd'};
        const bool credentialReady =
            credential_.configure(u"User", password);
        SecureZeroMemory(
            password.data(), password.size() * sizeof(password[0]));
        if (!credentialReady)
            return;

        const std::uint64_t timestamp = currentWindowsFileTime();
        if (timestamp == 0U)
            return;
        const StandaloneSpnegoChallengeConfiguration challenge{
            kServerChallenge,
            kStandaloneNtlmPortableDomainName,
            kStandaloneNtlmPortableServerName,
            timestamp};
        if (!acceptor_.configureChallenge(challenge))
            return;

        valid_ = inputBio_ != nullptr && outputBio_ != nullptr;
    }

    [[nodiscard]] bool valid() const noexcept { return valid_; }

    [[nodiscard]] bool feedRaw(
        std::span<const std::uint8_t> bytes) noexcept
    {
        if (!valid_ || bytes.empty() ||
            bytes.size() > kMaximumRawTokenBytes)
        {
            return false;
        }

        std::size_t offset = 0U;
        while (offset < bytes.size())
        {
            std::size_t written = 0U;
            if (BIO_write_ex(
                    inputBio_,
                    bytes.data() + offset,
                    bytes.size() - offset,
                    &written) != 1 ||
                written == 0U)
            {
                return false;
            }
            offset += written;
        }
        return true;
    }

    [[nodiscard]] std::vector<std::uint8_t> drainRaw()
    {
        std::vector<std::uint8_t> output;
        if (!valid_)
            return output;

        std::array<std::uint8_t, 16U * 1024U> buffer{};
        for (;;)
        {
            const std::size_t pending =
                static_cast<std::size_t>(BIO_ctrl_pending(outputBio_));
            if (pending == 0U)
                break;
            if (output.size() + pending > kMaximumRawTokenBytes)
            {
                output.clear();
                valid_ = false;
                break;
            }

            std::size_t read = 0U;
            const std::size_t requested =
                std::min(buffer.size(), pending);
            if (BIO_read_ex(
                    outputBio_, buffer.data(), requested, &read) != 1 ||
                read == 0U)
            {
                output.clear();
                valid_ = false;
                break;
            }
            output.insert(
                output.end(),
                buffer.begin(),
                buffer.begin() + static_cast<std::ptrdiff_t>(read));
        }
        return output;
    }

    [[nodiscard]] TlsAdvance advanceHandshake() noexcept
    {
        if (!valid_)
            return TlsAdvance::Failed;
        if (SSL_is_init_finished(tls_.get()) == 1)
            return TlsAdvance::Ready;

        for (std::size_t attempt = 0U; attempt < 64U; ++attempt)
        {
            const int handshakeResult = SSL_do_handshake(tls_.get());
            if (handshakeResult == 1)
                return TlsAdvance::Ready;
            const int error = SSL_get_error(tls_.get(), handshakeResult);
            if (error == SSL_ERROR_WANT_READ)
                return TlsAdvance::NeedPeer;
            if (error != SSL_ERROR_WANT_WRITE)
                return TlsAdvance::Failed;
        }
        return TlsAdvance::Failed;
    }

    [[nodiscard]] FrameAdvance advanceFrame() noexcept
    {
        if (!valid_ || SSL_is_init_finished(tls_.get()) != 1)
            return FrameAdvance::Failed;

        for (std::size_t attempt = 0U; attempt < 64U; ++attempt)
        {
            const auto result = reader_.readOneTlsStep(tls_.get());
            switch (result.status)
            {
            case TsRequestTlsReadStatus::Progress:
                continue;
            case TsRequestTlsReadStatus::NeedRead:
            case TsRequestTlsReadStatus::NeedWrite:
                return FrameAdvance::NeedPeer;
            case TsRequestTlsReadStatus::Complete:
                return FrameAdvance::Complete;
            case TsRequestTlsReadStatus::Invalid:
            case TsRequestTlsReadStatus::Closed:
                return FrameAdvance::Failed;
            }
        }
        return FrameAdvance::Failed;
    }

    [[nodiscard]] bool processInitialFrame() noexcept
    {
        if (reader_.status() != TsRequestFrameStatus::Complete)
            return false;
        const auto request = parseCredSspTsRequest(reader_.completeDer());
        if (!request || request.value.tokenCount != 1U ||
            !request.value.initialNegoTokenOnly())
        {
            return false;
        }

        const auto status = acceptor_.processCompleteFrame(
            reader_, writer_, credential_);
        return status == StandaloneCredSspFrameStatus::NegoReplyQueued &&
               acceptor_.lastNtlmMessageType() == 1U &&
               acceptor_.stage() == StandaloneCredSspStage::NegoContinue;
    }

    [[nodiscard]] std::vector<std::uint8_t> flushProductionReply()
    {
        for (std::size_t attempt = 0U; attempt < 64U; ++attempt)
        {
            const auto result = writer_.writeOneTlsStep(tls_.get());
            if (result.status == TsRequestTlsWriteStatus::Complete)
                break;
            if (result.status == TsRequestTlsWriteStatus::Progress ||
                result.status == TsRequestTlsWriteStatus::NeedWrite)
            {
                continue;
            }
            return {};
        }
        if (writer_.status() != TsRequestTlsWriteStatus::Complete)
            return {};

        auto raw = drainRaw();
        if (raw.empty() || !writer_.releaseReply())
            return {};
        return raw;
    }

    [[nodiscard]] bool processNextClientFrame(
        std::uint8_t &tokenCount,
        bool &hasPubKeyAuth) noexcept
    {
        tokenCount = 0U;
        hasPubKeyAuth = false;
        if (reader_.status() != TsRequestFrameStatus::Complete)
            return false;

        const auto request = parseCredSspTsRequest(reader_.completeDer());
        if (!request)
            return false;
        tokenCount = request.value.tokenCount;
        hasPubKeyAuth = request.value.hasPubKeyAuth;

        const auto status = acceptor_.processCompleteFrame(
            reader_, writer_, credential_);
        return acceptor_.lastNtlmMessageType() == 3U &&
               status ==
                   StandaloneCredSspFrameStatus::BindingReplyQueued &&
               acceptor_.stage() ==
                   StandaloneCredSspStage::ServerBindingReplyQueued;
    }

    [[nodiscard]] NtlmChallengeMessageObservation
    challengeObservation() const noexcept
    {
        return acceptor_.challengeObservation();
    }

private:
    RuntimeServerTlsContext tlsContext_{};
    RuntimeServerTlsContext::ServerTls tls_;
    BIO *inputBio_{};
    BIO *outputBio_{};
    TsRequestFrameReader reader_{};
    TsRequestTlsReplyWriter writer_{};
    StandaloneCredSspNtlmAcceptor acceptor_{};
    EphemeralNtlmV2Credential credential_{};
    bool valid_{};
};

struct FullCredSspAttempt final
{
    const char *stage{"not-started"};
    SECURITY_STATUS acquireStatus{SEC_E_INTERNAL_ERROR};
    SECURITY_STATUS lastClientStatus{SEC_E_INTERNAL_ERROR};
    std::uint32_t typeTwoFlags{};
    std::size_t typeTwoTargetNameCodeUnits{};
    bool tlsEstablished{};
    bool initialClientTsRequestReceived{};
    bool productionTypeTwoQueued{};
    bool microsoftNextTokenGenerated{};
    bool nextClientTsRequestReceived{};
    bool productionObservedTypeThree{};
    bool nextClientHasPubKeyAuth{};
};

[[nodiscard]] FullCredSspAttempt runFullCredSspAttempt(
    TargetProfile profile)
{
    FullCredSspAttempt result{};
    WindowsCredSspClient client;
    ProductionCredSspServer server;
    if (!server.valid())
    {
        result.stage = "production-server-setup";
        return result;
    }

    result.stage = "acquire-credssp";
    result.acquireStatus = client.acquire();
    if (!securityStatusSucceeded(result.acquireStatus))
        return result;

    result.stage = "credssp-client-initial";
    auto clientStep = client.step(profile, {});
    result.lastClientStatus = clientStep.status;
    if (!securityStatusSucceeded(clientStep.status) ||
        clientStep.output.empty())
    {
        return result;
    }

    bool initialFrameReady = false;
    for (std::size_t round = 0U;
         round < kMaximumExchangeRounds && !initialFrameReady;
         ++round)
    {
        result.stage = "client-to-server";
        if (!server.feedRaw(clientStep.output.view()))
            return result;

        result.stage = "server-tls";
        const TlsAdvance tls = server.advanceHandshake();
        if (tls == TlsAdvance::Failed)
            return result;
        result.tlsEstablished = tls == TlsAdvance::Ready;

        if (result.tlsEstablished)
        {
            result.stage = "server-initial-tsrequest";
            const FrameAdvance frame = server.advanceFrame();
            if (frame == FrameAdvance::Failed)
                return result;
            if (frame == FrameAdvance::Complete)
            {
                initialFrameReady = true;
                break;
            }
        }

        result.stage = "server-to-client";
        const auto serverToken = server.drainRaw();
        if (serverToken.empty())
            return result;

        result.stage = "credssp-client-continue";
        clientStep = client.step(profile, serverToken);
        result.lastClientStatus = clientStep.status;
        if (!securityStatusSucceeded(clientStep.status) ||
            clientStep.output.empty())
        {
            return result;
        }
    }

    if (!initialFrameReady)
    {
        result.stage = "initial-tsrequest-timeout";
        return result;
    }
    result.initialClientTsRequestReceived = true;

    result.stage = "production-type2";
    if (!server.processInitialFrame())
        return result;
    result.productionTypeTwoQueued = true;
    const auto challenge = server.challengeObservation();
    result.typeTwoFlags = challenge.negotiateFlags;
    result.typeTwoTargetNameCodeUnits =
        challenge.targetNameCodeUnits;

    const auto productionTypeTwo = server.flushProductionReply();
    if (productionTypeTwo.empty())
    {
        result.stage = "production-type2-tls-write";
        return result;
    }

    result.stage = "microsoft-credssp-after-type2";
    auto nextClientStep = client.step(profile, productionTypeTwo);
    result.lastClientStatus = nextClientStep.status;
    if (!securityStatusSucceeded(nextClientStep.status) ||
        nextClientStep.output.empty())
    {
        return result;
    }
    result.microsoftNextTokenGenerated = true;

    result.stage = "next-client-token-to-server";
    if (!server.feedRaw(nextClientStep.output.view()))
        return result;

    result.stage = "next-client-tsrequest";
    const FrameAdvance nextFrame = server.advanceFrame();
    if (nextFrame != FrameAdvance::Complete)
        return result;
    result.nextClientTsRequestReceived = true;

    std::uint8_t tokenCount = 0U;
    result.stage = "production-consume-next-client-token";
    if (!server.processNextClientFrame(
            tokenCount, result.nextClientHasPubKeyAuth))
    {
        return result;
    }
    result.productionObservedTypeThree = tokenCount == 1U;
    if (!result.productionObservedTypeThree)
        return result;

    result.stage = "none";
    return result;
}

void printStatus(const char *label, SECURITY_STATUS status) noexcept
{
    std::fprintf(
        stderr,
        "%s=0x%08lx\n",
        label,
        static_cast<unsigned long>(
            static_cast<std::uint32_t>(status)));
}

void printFailure(
    TargetProfile profile,
    const FullCredSspAttempt &result) noexcept
{
    std::fprintf(
        stderr,
        "microsoft-credssp target=%s stage=%s tls=%s "
        "initial-tsrequest=%s type2-queued=%s type2-flags=0x%08lx "
        "type2-target-code-units=%zu next-token=%s next-tsrequest=%s "
        "type3=%s pubkeyauth=%s\n",
        targetLabel(profile),
        result.stage,
        result.tlsEstablished ? "established" : "not-established",
        result.initialClientTsRequestReceived ? "yes" : "no",
        result.productionTypeTwoQueued ? "yes" : "no",
        static_cast<unsigned long>(result.typeTwoFlags),
        result.typeTwoTargetNameCodeUnits,
        result.microsoftNextTokenGenerated ? "yes" : "no",
        result.nextClientTsRequestReceived ? "yes" : "no",
        result.productionObservedTypeThree ? "yes" : "no",
        result.nextClientHasPubKeyAuth ? "yes" : "no");
    printStatus("microsoft-credssp-acquire-status", result.acquireStatus);
    printStatus(
        "microsoft-credssp-last-client-status",
        result.lastClientStatus);
}

} // namespace

int main(int argc, char **argv)
{
    if (argc != 2 || argv[1] == nullptr)
        return 2;

    const std::string_view mode{argv[1]};
    TargetProfile profile{};
    if (mode == "control-target")
        profile = TargetProfile::PortableServerName;
    else if (mode == "physical-ip-target")
        profile = TargetProfile::PhysicalIpv4;
    else
        return 2;

    const FullCredSspAttempt result = runFullCredSspAttempt(profile);
    if (std::string_view{result.stage} == "none" &&
        result.tlsEstablished &&
        result.initialClientTsRequestReceived &&
        result.productionTypeTwoQueued &&
        result.microsoftNextTokenGenerated &&
        result.nextClientTsRequestReceived &&
        result.productionObservedTypeThree &&
        result.nextClientHasPubKeyAuth)
    {
        std::fprintf(
            stderr,
            "microsoft-credssp target=%s production-type2=accepted "
            "next-client-token=yes type3=yes pubkeyauth=yes\n",
            targetLabel(profile));
        return 0;
    }

    printFailure(profile, result);
    return 1;
}
