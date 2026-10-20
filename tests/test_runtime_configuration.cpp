// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/runtime_configuration.h"

#include <cassert>
#include <string>
#include <string_view>

using namespace rdp_server::server::runtime;

namespace
{
#if defined(_WIN32)
constexpr std::string_view kTlsCertificate{"C:/private/server.crt"};
constexpr std::string_view kTlsPrivateKey{"C:/private/server.key"};
#else
constexpr std::string_view kTlsCertificate{"/private/server.crt"};
constexpr std::string_view kTlsPrivateKey{"/private/server.key"};
#endif

struct Observation final
{
    unsigned calls{};
};

[[nodiscard]] bool observe(
    const RuntimeConfigurationView& configuration,
    void* rawContext) noexcept
{
    auto* observation = static_cast<Observation*>(rawContext);
    assert(observation != nullptr);
    ++observation->calls;
    assert(configuration.field(RuntimeConfigurationField::ListenAddress) ==
           "127.0.0.1");
    assert(configuration.field(RuntimeConfigurationField::ListenPort) ==
           "3389");
    assert(configuration.field(RuntimeConfigurationField::TlsCertificate) ==
           kTlsCertificate);
    return true;
}

[[nodiscard]] std::string baseConfiguration()
{
    std::string text;
    text += "listen_address=127.0.0.1\n";
    text += "listen_port=3389\n";
    text += "tls_certificate=";
    text += kTlsCertificate;
    text += "\ntls_private_key=";
    text += kTlsPrivateKey;
    text += "\nauthentication=required\n";
    text += "os_authorization=required\n";
    text += "max_connections=1\n";
    return text;
}

[[nodiscard]] std::string linuxSecurityFields(bool includePam)
{
    std::string text;
    text += "gss_service_principal=TERMSRV/rdp.example.test@EXAMPLE.TEST\n";
    text += "gss_keytab=FILE:/private/service.keytab\n";
    text += "authorized_kerberos_principal=alice@EXAMPLE.TEST\n";
    text += "authorized_unix_account=alice\n";
    text += "authorized_seat=seat0\n";
    text += "authorized_display=:0\n";
    text += "authorized_uid=1001\n";
    text += "authorized_permissions=7\n";
    if (includePam)
        text += "pam_service=rdp-server\n";
    return text;
}
} // namespace

int main()
{
    Observation observation;
    const std::string base = baseConfiguration();
    assert(visitRuntimeConfigurationText(
        base, {}, &observe, &observation));
    assert(observation.calls == 1U);

    unsigned parsed = 0U;
    assert(parseRuntimeConfigurationDecimal(
        "3389", 1U, 65535U, parsed));
    assert(parsed == 3389U);
    assert(!parseRuntimeConfigurationDecimal(
        "65536", 1U, 65535U, parsed));
    assert(!parseRuntimeConfigurationDecimal(
        "0", 1U, 65535U, parsed));

    Observation linuxObservation;
    const std::string linuxWithoutPam =
        base + linuxSecurityFields(false);
    assert(visitRuntimeConfigurationText(
        linuxWithoutPam, {true, false},
        &observe, &linuxObservation));
    assert(linuxObservation.calls == 1U);
    assert(!visitRuntimeConfigurationText(
        linuxWithoutPam, {false, false},
        &observe, &linuxObservation));
    assert(!visitRuntimeConfigurationText(
        linuxWithoutPam, {true, true},
        &observe, &linuxObservation));

    Observation pamObservation;
    const std::string linuxWithPam =
        base + linuxSecurityFields(true);
    assert(visitRuntimeConfigurationText(
        linuxWithPam, {true, true},
        &observe, &pamObservation));
    assert(pamObservation.calls == 1U);
    assert(!visitRuntimeConfigurationText(
        linuxWithPam, {true, false},
        &observe, &pamObservation));

    std::string partial = base;
    partial += "gss_service_principal=TERMSRV/rdp.example.test@EXAMPLE.TEST\n";
    assert(!visitRuntimeConfigurationText(
        partial, {true, false}, &observe, &observation));

    std::string duplicate = base;
    duplicate += "listen_port=3390\n";
    assert(!visitRuntimeConfigurationText(
        duplicate, {}, &observe, &observation));

    std::string traversal = base;
#if defined(_WIN32)
    traversal.replace(
        traversal.find("C:/private/server.crt"),
        std::string_view{"C:/private/server.crt"}.size(),
        "C:/private/../server.crt");
#else
    traversal.replace(
        traversal.find("/private/server.crt"),
        std::string_view{"/private/server.crt"}.size(),
        "/private/../server.crt");
#endif
    assert(!visitRuntimeConfigurationText(
        traversal, {}, &observe, &observation));

    return 0;
}
