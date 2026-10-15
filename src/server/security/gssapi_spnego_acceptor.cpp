// SPDX-License-Identifier: GPL-3.0-or-later
#include "gssapi_spnego_acceptor.h"

#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>

#include <openssl/crypto.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>

namespace rdp_server::server::security
{
namespace
{

// RFC 4178 SPNEGO OID 1.3.6.1.5.5.2, DER encoded.
constexpr std::array<std::uint8_t, 8> kSpnegoOid{
    0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02};
// Kerberos V5 mechanism OID 1.2.840.113554.1.2.2.
constexpr std::array<std::uint8_t, 9> kKerberosOid{
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02};

[[nodiscard]] bool allowedService(std::string_view service) noexcept
{
    // Require an explicit Kerberos principal, including realm. Using
    // GSS_C_NT_HOSTBASED_SERVICE would allow the GSS provider to change
    // the hostname/realm through DNS or host configuration.
    constexpr std::string_view prefix{"TERMSRV/"};
    if (!service.starts_with(prefix) ||
        service.size() <= prefix.size() || service.size() > 512)
    {
        return false;
    }
    const auto at = service.find('@', prefix.size());
    if (at == service.npos || at == prefix.size() ||
        at + 1 >= service.size() ||
        service.find('@', at + 1) != service.npos)
    {
        return false;
    }
    const auto host = service.substr(prefix.size(), at - prefix.size());
    const auto realm = service.substr(at + 1);
    if (host.size() > 253 || realm.size() > 253 ||
        host.front() == '.' || host.back() == '.' ||
        host.front() == '-' || host.back() == '-' ||
        realm.front() == '.' || realm.back() == '.')
    {
        return false;
    }
    for (const char character : host)
    {
        if (!((character >= 'a' && character <= 'z') ||
              (character >= 'A' && character <= 'Z') ||
              (character >= '0' && character <= '9') ||
              character == '-' || character == '.'))
        {
            return false;
        }
    }
    for (const char character : realm)
    {
        if (!((character >= 'A' && character <= 'Z') ||
              (character >= '0' && character <= '9') ||
              character == '-' || character == '.'))
        {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool allowedKeytab(std::string_view keytab) noexcept
{
    // No default keytab and no relative filesystem path. The caller
    // must provide an explicit file; no keytab content is logged.
    constexpr std::string_view prefix{"FILE:/"};
    if (!keytab.starts_with(prefix) || keytab.size() <= prefix.size() ||
        keytab.size() > 4096 || keytab.find('\0') != keytab.npos)
    {
        return false;
    }
    return true;
}

[[nodiscard]] bool isKerberosMech(gss_OID mechanism) noexcept
{
    return mechanism != GSS_C_NO_OID &&
           mechanism->length == kKerberosOid.size() &&
           mechanism->elements != nullptr &&
           std::memcmp(mechanism->elements, kKerberosOid.data(),
                       kKerberosOid.size()) == 0;
}

} // namespace

bool isInitialSpnegoToken(
    std::span<const std::uint8_t> token) noexcept
{
    if (token.size() < 2 + kSpnegoOid.size() ||
        token.size() > kMaximumSpnegoInputBytes ||
        token[0] != 0x60)
    {
        return false;
    }
    std::size_t position = 1;
    const std::uint8_t first = token[position++];
    std::size_t payloadLength = 0;
    if ((first & 0x80U) == 0)
    {
        payloadLength = first;
    }
    else
    {
        const std::size_t count = first & 0x7fU;
        if (count == 0 || count > 2 ||
            count > token.size() - position ||
            token[position] == 0)
        {
            return false;
        }
        for (std::size_t index = 0; index < count; ++index)
        {
            payloadLength = (payloadLength << 8U) | token[position++];
        }
        if ((count == 1 && payloadLength < 128) ||
            (count == 2 && payloadLength < 256))
        {
            return false;
        }
    }
    if (payloadLength != token.size() - position ||
        payloadLength <= kSpnegoOid.size())
    {
        return false;
    }
    for (std::size_t index = 0; index < kSpnegoOid.size(); ++index)
    {
        if (token[position + index] != kSpnegoOid[index])
        {
            return false;
        }
    }
    // Nonempty mechanism-specific NegotiationToken is delegated to GSSAPI.
    return true;
}

GssapiSpnegoAcceptor::~GssapiSpnegoAcceptor()
{
    reject();
}

void GssapiSpnegoAcceptor::deleteContext() noexcept
{
    if (context_ != GSS_C_NO_CONTEXT)
    {
        OM_uint32 minor = 0;
        (void)gss_delete_sec_context(&minor, &context_,
                                      GSS_C_NO_BUFFER);
        context_ = GSS_C_NO_CONTEXT;
    }
}

void GssapiSpnegoAcceptor::reject() noexcept
{
    deleteContext();
    if (credentials_ != GSS_C_NO_CREDENTIAL)
    {
        OM_uint32 minor = 0;
        (void)gss_release_cred(&minor, &credentials_);
        credentials_ = GSS_C_NO_CREDENTIAL;
    }
    principal_.clear();
    negotiatedServerTls_ = nullptr;
    OPENSSL_cleanse(negotiatedCertificate_.data(),
                    negotiatedCertificate_.size());
    hasNegotiatedCertificate_ = false;
    negotiatedVersion_ = 0;
    stage_ = SpnegoStage::Failed;
}

bool GssapiSpnegoAcceptor::matchesNegotiatedCertificate(
    const SSL *serverTls) const noexcept
{
    if (serverTls == nullptr || serverTls != negotiatedServerTls_ ||
        !hasNegotiatedCertificate_)
        return false;

    CredSspTlsCertificateFingerprint selected{};
    if (!fingerprintActiveCredSspServerTlsCertificate(serverTls, selected))
        return false;
    const bool unchanged =
        CRYPTO_memcmp(selected.data(), negotiatedCertificate_.data(),
                      selected.size()) == 0;
    OPENSSL_cleanse(selected.data(), selected.size());
    return unchanged;
}

bool GssapiSpnegoAcceptor::configure(
    std::string_view serviceName, std::string_view keytabFile) noexcept
{
    if (stage_ != SpnegoStage::Unconfigured ||
        !allowedService(serviceName) || !allowedKeytab(keytabFile))
    {
        configDiagnostics_.stage = GssConfigurationFailure::InvalidOptions;
        reject();
        return false;
    }
    try
    {
        // Both buffers must be NUL terminated for GSSAPI and the MIT
        // keytab cred-store extension. Never fall back to host defaults.
        const std::string service{serviceName};
        const std::string keytab{keytabFile};
        gss_buffer_desc serviceBuffer{
            service.size(), const_cast<char *>(service.data())};
        gss_name_t serviceIdentity = GSS_C_NO_NAME;
        OM_uint32 minor = 0;
        const OM_uint32 imported = gss_import_name(
            &minor, &serviceBuffer, GSS_KRB5_NT_PRINCIPAL_NAME,
            &serviceIdentity);
        if (imported != GSS_S_COMPLETE || serviceIdentity == GSS_C_NO_NAME)
        {
            configDiagnostics_ = {GssConfigurationFailure::ImportService,
                                  imported, minor};
            if (serviceIdentity != GSS_C_NO_NAME)
            {
                (void)gss_release_name(&minor, &serviceIdentity);
            }
            reject();
            return false;
        }
        gss_key_value_element_desc element{
            "keytab", keytab.c_str()};
        gss_key_value_set_desc store{1, &element};
        const OM_uint32 acquired = gss_acquire_cred_from(
            &minor, serviceIdentity, GSS_C_INDEFINITE,
            GSS_C_NO_OID_SET, GSS_C_ACCEPT, &store,
            &credentials_, nullptr, nullptr);
        // Release of the imported name also updates the minor variable.
        // Preserve the status originating at acquisition, not at cleanup.
        const OM_uint32 acquisitionMinor = minor;
        (void)gss_release_name(&minor, &serviceIdentity);
        if (acquired != GSS_S_COMPLETE ||
            credentials_ == GSS_C_NO_CREDENTIAL)
        {
            configDiagnostics_ = {GssConfigurationFailure::AcquireCredentials,
                                  acquired, acquisitionMinor};
            reject();
            return false;
        }
        stage_ = SpnegoStage::AwaitInitialToken;
        return true;
    }
    catch (...)
    {
        configDiagnostics_.stage = GssConfigurationFailure::Allocation;
        reject();
        return false;
    }
}

bool GssapiSpnegoAcceptor::keepAuthenticatedPrincipal(
    gss_name_t name) noexcept
{
    if (name == GSS_C_NO_NAME)
    {
        return false;
    }
    OM_uint32 minor = 0;
    gss_buffer_desc displayed = GSS_C_EMPTY_BUFFER;
    if (gss_display_name(&minor, name, &displayed, nullptr) !=
        GSS_S_COMPLETE)
    {
        (void)gss_release_buffer(&minor, &displayed);
        return false;
    }
    bool valid = displayed.value != nullptr && displayed.length != 0 &&
                 displayed.length <= 1024;
    if (valid)
    {
        const auto *data = static_cast<const char *>(displayed.value);
        valid = std::memchr(data, '\0', displayed.length) == nullptr;
        if (valid)
        {
            try
            {
                principal_.assign(data, displayed.length);
            }
            catch (...)
            {
                valid = false;
            }
        }
    }
    (void)gss_release_buffer(&minor, &displayed);
    return valid;
}

SpnegoStep GssapiSpnegoAcceptor::acceptInitialRequest(
    const TsRequestResult &request) noexcept
{
    if (!request || !request.value.initialNegoTokenOnly() ||
        request.value.tokenCount != 1)
    {
        reject();
        return {};
    }
    return accept(request.value.tokens[0]);
}

SpnegoStep GssapiSpnegoAcceptor::acceptFramedNegoRequest(
    TsRequestFrameReader &reader) noexcept
{
    const SSL *sourceTls = reader.completedFrameServerTls();
    // The TLS framer, not caller-supplied DER or a second SSL handle,
    // determines which server TLS connection supplies every GSS token.
    if (sourceTls == nullptr ||
        (negotiatedServerTls_ != nullptr &&
         !matchesNegotiatedCertificate(sourceTls)))
    {
        reader.close();
        reject();
        return {};
    }

    const auto parsed = parseCredSspTsRequest(reader.completeDer());
    if (!parsed || (parsed.value.version != 5 &&
                    parsed.value.version != 6) ||
        (negotiatedVersion_ != 0 &&
         negotiatedVersion_ != parsed.value.version) ||
        (negotiatedServerTls_ == nullptr &&
         stage_ != SpnegoStage::AwaitInitialToken))
    {
        reader.close();
        reject();
        return {};
    }
    // The GSS acceptor independently pins the same TLS selected cert
    // from the FIRST verified frame. A fresh reader per message must not
    // erase that transcript identity on an unchanged SSL pointer.
    if (negotiatedServerTls_ == nullptr)
    {
        CredSspTlsCertificateFingerprint selected{};
        if (!fingerprintActiveCredSspServerTlsCertificate(sourceTls, selected))
        {
            reader.close();
            reject();
            return {};
        }
        negotiatedCertificate_ = selected;
        hasNegotiatedCertificate_ = true;
        OPENSSL_cleanse(selected.data(), selected.size());
    }
    negotiatedServerTls_ = sourceTls;
    negotiatedVersion_ = parsed.value.version;
    auto step = acceptInitialRequest(parsed);
    if (!reader.releaseFrame())
    {
        reader.close();
        reject();
        return {};
    }
    if (step.status == SpnegoStatus::Rejected)
    {
        // Never retry credentials on a failed context using a new frame.
        reader.close();
    }
    return step;
}


SpnegoStatus GssapiSpnegoAcceptor::acceptFramedNegoAndQueueReply(
    TsRequestFrameReader &reader, TsRequestTlsReplyWriter &writer) noexcept
{
    const SSL *sourceTls = reader.completedFrameServerTls();
    // The previous server reply must be completely sent and released;
    // do not accept another peer token while outgoing TLS is pending.
    if (sourceTls == nullptr ||
        writer.status() != TsRequestTlsWriteStatus::Idle)
    {
        reader.close();
        writer.close();
        reject();
        return SpnegoStatus::Rejected;
    }

    auto result = acceptFramedNegoRequest(reader);
    const bool validContinuation =
        result.status == SpnegoStatus::Continue &&
        stage_ == SpnegoStage::ContinueNeeded &&
        negotiatedServerTls_ == sourceTls &&
        (negotiatedVersion_ == 5 || negotiatedVersion_ == 6) &&
        !result.outputToken.empty();

    bool queued = false;
    if (validContinuation)
    {
        // The only source of the outgoing token is a real
        // gss_accept_sec_context output in this exact TLS transcript.
        queued = writer.queueReply(
            const_cast<SSL *>(sourceTls),
            static_cast<std::uint8_t>(negotiatedVersion_),
            CredSspServerReplyField::NegoToken, result.outputToken);
    }
    if (!result.outputToken.empty())
    {
        // The writer owns its own DER snapshot; erase the transient
        // provider token on either successful queue or rejection.
        OPENSSL_cleanse(result.outputToken.data(), result.outputToken.size());
        result.outputToken.clear();
    }
    if (!queued)
    {
        reader.close();
        writer.close();
        reject();
        return SpnegoStatus::Rejected;
    }
    return SpnegoStatus::Continue;
}

SpnegoStep GssapiSpnegoAcceptor::accept(
    std::span<const std::uint8_t> token) noexcept
{
    const bool initial = stage_ == SpnegoStage::AwaitInitialToken;
    if ((!initial && stage_ != SpnegoStage::ContinueNeeded) ||
        credentials_ == GSS_C_NO_CREDENTIAL ||
        token.empty() || token.size() > kMaximumSpnegoInputBytes ||
        rounds_ >= kMaximumSpnegoRoundTrips ||
        (initial && !isInitialSpnegoToken(token)))
    {
        reject();
        return {};
    }
    ++rounds_;
    gss_buffer_desc incoming{
        token.size(), const_cast<std::uint8_t *>(token.data())};
    gss_buffer_desc outgoing = GSS_C_EMPTY_BUFFER;
    gss_name_t initiator = GSS_C_NO_NAME;
    gss_cred_id_t delegated = GSS_C_NO_CREDENTIAL;
    gss_OID mechanism = GSS_C_NO_OID;
    OM_uint32 flags = 0;
    OM_uint32 minor = 0;
    const OM_uint32 major = gss_accept_sec_context(
        &minor, &context_, credentials_, &incoming,
        GSS_C_NO_CHANNEL_BINDINGS, &initiator, &mechanism,
        &outgoing, &flags, nullptr, &delegated);

    // CredSSP delegation must not occur through SPNEGO accept: the
    // protected TSCredentials phase has its own identity policy.
    if (delegated != GSS_C_NO_CREDENTIAL)
    {
        (void)gss_release_cred(&minor, &delegated);
    }
    const bool completed = major == GSS_S_COMPLETE;
    const bool continuing = major == GSS_S_CONTINUE_NEEDED;
    constexpr OM_uint32 required =
        GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG |
        GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG;
    const bool secureContext =
        completed && initiator != GSS_C_NO_NAME &&
        isKerberosMech(mechanism) &&
        (flags & required) == required &&
        (flags & GSS_C_DELEG_FLAG) == 0 &&
        keepAuthenticatedPrincipal(initiator);

    // Copy any output token *before* releasing GSS's buffer, with a
    // strict size cap. Never include any output on a rejected step.
    SpnegoStep result{};
    bool copied = false;
    if ((continuing || secureContext) &&
        outgoing.length <= kMaximumSpnegoOutputBytes)
    {
        try
        {
            if (outgoing.length == 0)
            {
                copied = true;
            }
            else if (outgoing.value != nullptr)
            {
                const auto *data =
                    static_cast<const std::uint8_t *>(outgoing.value);
                result.outputToken.assign(data, data + outgoing.length);
                copied = true;
            }
        }
        catch (...)
        {
            copied = false;
        }
    }
    (void)gss_release_buffer(&minor, &outgoing);
    if (initiator != GSS_C_NO_NAME)
    {
        (void)gss_release_name(&minor, &initiator);
    }
    if (!copied)
    {
        reject();
        return {};
    }
    if (secureContext)
    {
        stage_ = SpnegoStage::MechanismVerified;
        result.status = SpnegoStatus::MechanismVerified;
        return result;
    }
    if (continuing)
    {
        stage_ = SpnegoStage::ContinueNeeded;
        result.status = SpnegoStatus::Continue;
        return result;
    }
    reject();
    return {};
}

} // namespace rdp_server::server::security
