# SPDX-License-Identifier: GPL-3.0-or-later
# Reuse one registry and preserve test executable/source file identities.
# Build-policy regression: path spelling is lexical only after the caller has
# proved that the ~/rdp-server candidate exists. macOS/Windows may then compare
# the resolved spelling case-insensitively; Linux remains case-sensitive.
add_test(NAME project.local-checkout-path-comparison
    COMMAND "${CMAKE_COMMAND}" -P
        "${PROJECT_SOURCE_DIR}/tests/check_local_checkout_path.cmake")
set_tests_properties(project.local-checkout-path-comparison PROPERTIES
    LABELS "policy;build")

# CTest names are user/developer-facing behavior taxonomy. Internal R1-R10
# road identifiers may remain in fixture command modes, but never test names.
function(rdp_functional_ctest_name output_variable raw_name)
    set(functional_name "${raw_name}")
    set(previous_name "")
    while(NOT previous_name STREQUAL functional_name)
        set(previous_name "${functional_name}")
        string(REGEX REPLACE "(^|[._-])r(10|[1-9])([._-])" "\\1"
            functional_name "${functional_name}")
        string(REGEX REPLACE "(^|[._-])r(10|[1-9])$" ""
            functional_name "${functional_name}")
    endwhile()
    set(${output_variable} "${functional_name}" PARENT_SCOPE)
endfunction()

# R7 Windows launcher uses DesktopWindow directly instead of the shared
# desktop-ui archive, so every out-of-line widget implementation used by the
# dashboard must be present in this target's source list.
add_test(NAME windows.gui-dashboard-toggle-linkage-source-contract
    COMMAND "${CMAKE_COMMAND}"
        "-DRDP_ROOT_CMAKE=${PROJECT_SOURCE_DIR}/CMakeLists.txt"
        -P "${PROJECT_SOURCE_DIR}/tests/check_windows_gui_toggle_linkage.cmake")
set_tests_properties(windows.gui-dashboard-toggle-linkage-source-contract
    PROPERTIES LABELS "windows;gui;policy;offline")

# R6/R9 Windows hidden offline verification must allow Qt's internal
# QTabWidget stack while still rejecting a competing application-owned stack.
add_test(NAME windows.gui-round2-tab-offline-verifier-source-contract
    COMMAND "${CMAKE_COMMAND}"
        "-DRDP_WINDOWS_GUI_SOURCE=${PROJECT_SOURCE_DIR}/src/windows/windows_gui_main.cpp"
        -P "${PROJECT_SOURCE_DIR}/tests/check_windows_gui_round2_tabs.cmake")
set_tests_properties(windows.gui-round2-tab-offline-verifier-source-contract
    PROPERTIES LABELS "windows;gui;platform;assurance;round2;policy;offline")

# R7's imported switch intentionally has no Q_OBJECT macro. Object-name lookup
# in hidden launch checks and fixtures must therefore use a Qt meta-object base
# class rather than making the presentation widget depend on AUTOMOC.
add_test(NAME gui.toggle-object-name-base-lookup-source-contract
    COMMAND "${CMAKE_COMMAND}"
        "-DRDP_TOGGLE_HEADER=${PROJECT_SOURCE_DIR}/src/gui/toggle_switch.h"
        "-DRDP_WINDOWS_GUI_SOURCE=${PROJECT_SOURCE_DIR}/src/windows/windows_gui_main.cpp"
        "-DRDP_GUI_TEST_SOURCE=${PROJECT_SOURCE_DIR}/tests/test_desktop_gui_offline.cpp"
        -P "${PROJECT_SOURCE_DIR}/tests/check_gui_toggle_lookup_contract.cmake")
set_tests_properties(gui.toggle-object-name-base-lookup-source-contract
    PROPERTIES LABELS "gui;windows;macos;policy;build;offline")

# R7/R10 dashboard integration must consume the authoritative product lifecycle
# without retaining removed GUI command-intent flags or the retired raw-stage
# sharing helper. This source contract is platform-independent and catches
# cross-platform compile regressions before packaging lanes diverge.
add_test(NAME gui.product-status-integration-source-contract
    COMMAND "${CMAKE_COMMAND}"
        "-DRDP_DESKTOP_WINDOW_SOURCE=${PROJECT_SOURCE_DIR}/src/gui/desktop_window.cpp"
        "-DRDP_HOST_CONTROL_SOURCE=${PROJECT_SOURCE_DIR}/src/gui/host_control.cpp"
        -P "${PROJECT_SOURCE_DIR}/tests/check_gui_product_status_integration.cmake")
set_tests_properties(gui.product-status-integration-source-contract
    PROPERTIES LABELS "gui;host-control;policy;offline")

add_test(NAME gui.owner-acceptance-release-gate-and-production-path
    COMMAND "${CMAKE_COMMAND}"
        "-DRDP_DESKTOP_WINDOW_SOURCE=${PROJECT_SOURCE_DIR}/src/gui/desktop_window.cpp"
        "-DRDP_HOST_CONTROL_SOURCE=${PROJECT_SOURCE_DIR}/src/gui/host_control.cpp"
        "-DRDP_LINUX_HOST_CONTROL_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_host_control.cpp"
        "-DRDP_STANDALONE_CREDENTIAL_CONSENT_HEADER=${PROJECT_SOURCE_DIR}/src/server/security/standalone_credential_consent.h"
        "-DRDP_RUNTIME_HOST_CONTROL_HEADER=${PROJECT_SOURCE_DIR}/src/server/runtime/runtime_host_control.h"
        "-DRDP_DESKTOP_ENTRYPOINT_SOURCE=${PROJECT_SOURCE_DIR}/src/gui/main.cpp"
        "-DRDP_ROOT_CMAKE=${PROJECT_SOURCE_DIR}/CMakeLists.txt"
        "-DRDP_CI_WORKFLOW=${PROJECT_SOURCE_DIR}/.github/workflows/ci.yml"
        -P "${PROJECT_SOURCE_DIR}/tests/check_gui_owner_acceptance_gate.cmake")
set_tests_properties(gui.owner-acceptance-release-gate-and-production-path
    PROPERTIES LABELS "gui;admission;host-control;acceptance;security;offline")

# R9 GUI Round 2 exact-source contracts. These inspect source/CI text only:
# they do not launch Qt, read native color profiles or suppress diagnostics.
add_test(NAME gui.round2-tab-source-contract
    COMMAND "${CMAKE_COMMAND}"
        "-DRDP_DESKTOP_WINDOW_HEADER=${PROJECT_SOURCE_DIR}/src/gui/desktop_window.h"
        "-DRDP_DESKTOP_WINDOW_SOURCE=${PROJECT_SOURCE_DIR}/src/gui/desktop_window.cpp"
        -P "${PROJECT_SOURCE_DIR}/tests/check_gui_round2_tabs.cmake")
set_tests_properties(gui.round2-tab-source-contract PROPERTIES
    LABELS "gui;assurance;round2;policy;offline")

add_test(NAME gui.round2-refresh-tray-function-boundary
    COMMAND "${CMAKE_COMMAND}"
        "-DRDP_DESKTOP_WINDOW_SOURCE=${PROJECT_SOURCE_DIR}/src/gui/desktop_window.cpp"
        -P "${PROJECT_SOURCE_DIR}/tests/check_gui_refresh_tray_boundary.cmake")
set_tests_properties(gui.round2-refresh-tray-function-boundary PROPERTIES
    LABELS "gui;round2;runtime;policy;offline")

add_test(NAME gui.round2-qcolor-warning-classification
    COMMAND "${CMAKE_COMMAND}"
        "-DRDP_SOURCE_ROOT=${PROJECT_SOURCE_DIR}"
        "-DRDP_CI_WORKFLOW=${PROJECT_SOURCE_DIR}/.github/workflows/ci.yml"
        -P "${PROJECT_SOURCE_DIR}/tests/check_gui_qcolor_warning_policy.cmake")
set_tests_properties(gui.round2-qcolor-warning-classification PROPERTIES
    LABELS "gui;assurance;round2;qt;policy;offline")

# R2 production credential-choice boundary: no secrets, network, OS login or
# synthetic lease; unsupported GUI passwords cannot enable Share.
add_executable(test_standalone_credential_policy
    test_standalone_credential_policy.cpp)
target_link_libraries(test_standalone_credential_policy PRIVATE rdp-server-protocol)
add_test(NAME security.lan-credential-mode-denials
    COMMAND test_standalone_credential_policy lan-credential-mode-denials)
set_tests_properties(security.lan-credential-mode-denials PROPERTIES
    LABELS "security;credentials;offline")

# R2 standalone password cryptographic core. Microsoft MS-NLMP known-answer
# bytes are fixed independently in the fixture; this is not an interoperability
# or positive R2-admission test.
add_executable(test_standalone_ntlmv2 test_standalone_ntlmv2.cpp)
target_link_libraries(test_standalone_ntlmv2 PRIVATE
    rdp-server-standalone-ntlmv2)
if(MSVC)
    target_compile_options(test_standalone_ntlmv2 PRIVATE /W4 /UNDEBUG)
else()
    target_compile_options(test_standalone_ntlmv2 PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
foreach(ntlmv2_case IN ITEMS
        ntlmv2-microsoft-known-answer-and-session-keys
        ntlmv2-proof-blob-and-flag-denials
        ntlmv2-credential-owner-generation-revocation
        standalone-credential-unconfigured-consent-independence
        standalone-credential-replacement-revokes-owner-consent
        ntlmv2-ephemeral-secret-revocation)
    add_test(NAME "security.${ntlmv2_case}"
        COMMAND test_standalone_ntlmv2 "${ntlmv2_case}")
    set_tests_properties("security.${ntlmv2_case}" PROPERTIES
        LABELS "security;credentials;ntlmv2;credssp;offline")
endforeach()

# R2 standalone NTLMSSP framing bridge. These cases consume published MS-NLMP
# wire examples and bounded parser fixtures only; they do not open TLS/network
# state, grant R2 admission, or claim Microsoft-client interoperability.
add_executable(test_standalone_ntlmssp test_standalone_ntlmssp.cpp)
target_link_libraries(test_standalone_ntlmssp PRIVATE
    rdp-server-standalone-ntlmv2)
if(MSVC)
    target_compile_options(test_standalone_ntlmssp PRIVATE /W4 /UNDEBUG)
else()
    target_compile_options(test_standalone_ntlmssp PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
foreach(ntlmssp_case IN ITEMS
        ntlmssp-type1-structural-observation
        ntlmssp-negotiate-challenge-framing
        ntlmssp-challenge-portable-target-name
        ntlmssp-challenge-compatibility-profiles
        ntlmssp-challenge-target-name-conformance
        ntlmssp-microsoft-authenticate-bridge
        ntlmssp-security-buffer-mic-denials)
    add_test(NAME "security.${ntlmssp_case}"
        COMMAND test_standalone_ntlmssp "${ntlmssp_case}")
    set_tests_properties("security.${ntlmssp_case}" PROPERTIES
        LABELS "security;credentials;ntlmv2;ntlmssp;credssp;offline")
endforeach()

# Microsoft-native Windows SSPI is the independent client-side NTLM oracle.
# It uses explicit in-memory test credentials and performs no network/domain
# login. Production owns only Type 2 and final Type-3 parsing/verification.
if(WIN32)
    add_executable(test_windows_sspi_ntlm_interop
        test_windows_sspi_ntlm_interop.cpp)
    target_link_libraries(test_windows_sspi_ntlm_interop PRIVATE
        rdp-server-standalone-ntlmv2 secur32)
    if(MSVC)
        target_compile_options(test_windows_sspi_ntlm_interop PRIVATE
            /W4 /UNDEBUG)
    else()
        target_compile_options(test_windows_sspi_ntlm_interop PRIVATE
            -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    endif()
    add_test(NAME security.windows-sspi-production-type2-interop
        COMMAND test_windows_sspi_ntlm_interop control-target)
    add_test(NAME security.windows-sspi-production-type2-physical-ip-target
        COMMAND test_windows_sspi_ntlm_interop physical-ip-target)
    add_test(NAME security.windows-sspi-production-type2-oem-omission-differential
        COMMAND test_windows_sspi_ntlm_interop oem-omission-differential)
    set_tests_properties(
        security.windows-sspi-production-type2-interop
        security.windows-sspi-production-type2-physical-ip-target
        security.windows-sspi-production-type2-oem-omission-differential
        PROPERTIES
        LABELS "security;credentials;ntlmv2;ntlmssp;credssp;windows;interop;offline"
        TIMEOUT 30)

    # Microsoft CredSSP owns the client TLS/CredSSP context. Production owns
    # the server TLS identity and exact standalone CredSSP Type-2 response.
    add_executable(test_windows_sspi_credssp_interop
        test_windows_sspi_credssp_interop.cpp)
    target_link_libraries(test_windows_sspi_credssp_interop PRIVATE
        rdp-server-standalone-ntlmv2
        rdp-server-runtime-tls
        secur32)
    if(MSVC)
        target_compile_options(test_windows_sspi_credssp_interop PRIVATE
            /W4 /UNDEBUG)
    else()
        target_compile_options(test_windows_sspi_credssp_interop PRIVATE
            -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    endif()
    add_test(NAME security.windows-credssp-harness-stream-buffer-retention
        COMMAND test_windows_sspi_credssp_interop harness-stream-buffer-retention)
    add_test(NAME security.windows-credssp-harness-multi-turn-round-progression
        COMMAND test_windows_sspi_credssp_interop harness-multi-turn-round-progression)
    set_tests_properties(
        security.windows-credssp-harness-stream-buffer-retention
        security.windows-credssp-harness-multi-turn-round-progression
        PROPERTIES
        LABELS "security;credentials;credssp;tls;windows;harness;offline"
        TIMEOUT 15)

    add_test(NAME security.windows-credssp-tls-system-default
        COMMAND test_windows_sspi_credssp_interop tls-system-default)
    add_test(NAME security.windows-credssp-tls12-only-server
        COMMAND test_windows_sspi_credssp_interop tls12-only-server)
    add_test(NAME security.windows-credssp-tls13-only-server
        COMMAND test_windows_sspi_credssp_interop tls13-only-server)
    set_tests_properties(
        security.windows-credssp-tls-system-default
        security.windows-credssp-tls12-only-server
        security.windows-credssp-tls13-only-server
        PROPERTIES
        LABELS "security;credentials;credssp;tls;windows;interop;acceptance;offline"
        TIMEOUT 45)

    add_test(
        NAME security.windows-credssp-modern-schannel-system-defaults-full-boundary-probe
        COMMAND test_windows_sspi_credssp_interop
            modern-schannel-system-defaults-probe)
    set_tests_properties(
        security.windows-credssp-modern-schannel-system-defaults-full-boundary-probe
        PROPERTIES
        LABELS "security;credentials;credssp;tls;windows;interop;offline"
        TIMEOUT 45)

    add_test(NAME security.windows-credssp-credential-semantic-differential
        COMMAND "${CMAKE_COMMAND}"
            "-DTEST_EXECUTABLE=$<TARGET_FILE:test_windows_sspi_credssp_interop>"
            -P "${PROJECT_SOURCE_DIR}/tests/run_windows_credssp_credential_semantics.cmake")
    set_tests_properties(
        security.windows-credssp-credential-semantic-differential
        PROPERTIES
        LABELS "security;credentials;ntlmv2;credssp;tls;windows;interop;acceptance;offline"
        TIMEOUT 45)

    add_test(NAME security.windows-credssp-type2-required-av-negative-controls
        COMMAND "${CMAKE_COMMAND}"
            "-DTEST_EXECUTABLE=$<TARGET_FILE:test_windows_sspi_credssp_interop>"
            -P "${PROJECT_SOURCE_DIR}/tests/run_windows_credssp_type2_negative_controls.cmake")
    set_tests_properties(
        security.windows-credssp-type2-required-av-negative-controls
        PROPERTIES
        LABELS "security;credentials;ntlmv2;credssp;tls;windows;interop;acceptance;offline"
        TIMEOUT 45)

    add_test(NAME security.windows-credssp-production-full-exchange
        COMMAND test_windows_sspi_credssp_interop full-production-exchange)
    add_test(NAME security.windows-credssp-server-binding-mismatch-negative-control
        COMMAND test_windows_sspi_credssp_interop binding-negative-mismatch)
    set_tests_properties(
        security.windows-credssp-production-full-exchange
        security.windows-credssp-server-binding-mismatch-negative-control
        PROPERTIES
        LABELS "security;credentials;ntlmv2;credssp;tls;windows;interop;acceptance;offline"
        TIMEOUT 45)

    add_test(NAME security.windows-credssp-production-control-target-next-token
        COMMAND test_windows_sspi_credssp_interop control-target)
    add_test(NAME security.windows-credssp-production-physical-ip-target-next-token
        COMMAND test_windows_sspi_credssp_interop physical-ip-target)
    add_test(NAME security.windows-credssp-production-bare-ip-target-next-token
        COMMAND test_windows_sspi_credssp_interop bare-ip-target)
    set_tests_properties(
        security.windows-credssp-production-control-target-next-token
        security.windows-credssp-production-physical-ip-target-next-token
        security.windows-credssp-production-bare-ip-target-next-token
        PROPERTIES
        LABELS "security;credentials;ntlmv2;credssp;tls;windows;interop;acceptance;offline"
        TIMEOUT 45)

    # Test-only Windows certificate-policy oracle. The current production leaf
    # and endpoint-CN comparison leaf are trusted only by an exclusive in-memory
    # application store; no machine/user trust store is modified.
    add_executable(test_windows_certificate_policy
        test_windows_certificate_policy.cpp)
    target_link_libraries(test_windows_certificate_policy PRIVATE
        rdp-server-runtime-tls
        OpenSSL::Crypto
        crypt32)
    if(MSVC)
        target_compile_options(test_windows_certificate_policy PRIVATE
            /W4 /UNDEBUG)
    else()
        target_compile_options(test_windows_certificate_policy PRIVATE
            -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    endif()
    add_test(NAME security.windows-generated-tls-certificate-policy-profiles
        COMMAND test_windows_certificate_policy)
    set_tests_properties(
        security.windows-generated-tls-certificate-policy-profiles
        PROPERTIES
        LABELS "security;tls;certificate;windows;interop;offline"
        TIMEOUT 30)
endif()

# Test-only macOS Security.framework certificate-policy oracle. Custom anchors
# are scoped to each SecTrust object and network fetching is disabled; no
# Keychain, system trust-store or user prompt is used.
if(APPLE)
    add_executable(test_macos_certificate_policy
        test_macos_certificate_policy.cpp)
    target_link_libraries(test_macos_certificate_policy PRIVATE
        rdp-server-runtime-tls
        OpenSSL::Crypto
        "${RDP_SERVER_SECURITY_FRAMEWORK}"
        "${RDP_SERVER_COREFOUNDATION_FRAMEWORK}")
    target_compile_options(test_macos_certificate_policy PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    add_test(NAME security.macos-generated-tls-certificate-policy-profiles
        COMMAND test_macos_certificate_policy)
    set_tests_properties(
        security.macos-generated-tls-certificate-policy-profiles
        PROPERTIES
        LABELS "security;tls;certificate;macos;interop;offline"
        TIMEOUT 30)
endif()

# R2 standalone NTLM transcript MIC and connection-oriented SIGN/SEAL state.
add_executable(test_standalone_ntlm_security
    test_standalone_ntlm_security.cpp)
target_link_libraries(test_standalone_ntlm_security PRIVATE
    rdp-server-standalone-ntlmv2)
if(MSVC)
    target_compile_options(test_standalone_ntlm_security PRIVATE /W4 /UNDEBUG)
else()
    target_compile_options(test_standalone_ntlm_security PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
foreach(ntlm_security_case IN ITEMS
        ntlmv2-transcript-mic-verification
        ntlmv2-session-security-sign-seal-known-answer
        ntlmv2-session-security-tamper-revokes)
    add_test(NAME "security.${ntlm_security_case}"
        COMMAND test_standalone_ntlm_security "${ntlm_security_case}")
    set_tests_properties("security.${ntlm_security_case}" PROPERTIES
        LABELS "security;credentials;ntlmv2;ntlmssp;credssp;offline")
endforeach()

# R9 P0 rejection diagnostics preserve specific initial token categories.
add_test(NAME security.standalone-spnego-initial-rejection-categories
    COMMAND test_standalone_spnego
        r9-spnego-initial-rejection-categories)
set_tests_properties(security.standalone-spnego-initial-rejection-categories
    PROPERTIES LABELS "assurance;security;spnego;credssp;offline")

# R9 P0 Microsoft-compatible synthetic NegTokenInit2 path through
# NEGOEX/Kerberos-family-first mechanism selection into NTLM challenge. This
# does not claim
# that the unmodified owner client succeeded or that GSS fallback is enabled.
add_test(NAME security.standalone-credssp-spnego-microsoft-negotiation
    COMMAND test_standalone_spnego
        r9-microsoft-neginit2-ntlm-challenge)
set_tests_properties(security.standalone-credssp-spnego-microsoft-negotiation
    PROPERTIES LABELS "assurance;security;spnego;credssp;offline")

# R2 standalone SPNEGO/NTLM mechanism state. These are bounded offline wire
# and cryptographic tests only; no TSRequest/TLS, GUI secret or R2 admission.
add_executable(test_standalone_spnego test_standalone_spnego.cpp)
target_link_libraries(test_standalone_spnego PRIVATE
    rdp-server-standalone-ntlmv2)
if(MSVC)
    target_compile_options(test_standalone_spnego PRIVATE /W4 /UNDEBUG)
else()
    target_compile_options(test_standalone_spnego PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
add_test(NAME security.direct-ntlm-envelope-negotiate-authenticate
    COMMAND test_standalone_spnego
        direct-ntlm-envelope-negotiate-authenticate)
set_tests_properties(
    security.direct-ntlm-envelope-negotiate-authenticate
    PROPERTIES LABELS "security;credentials;ntlmv2;credssp;authentication-envelope;platform;offline")

add_test(NAME security.direct-ntlm-envelope-classification-denials
    COMMAND test_standalone_spnego
        direct-ntlm-envelope-classification-denials)
set_tests_properties(
    security.direct-ntlm-envelope-classification-denials
    PROPERTIES LABELS "security;credentials;ntlmv2;ntlmssp;credssp;authentication-envelope;platform;offline")

add_test(NAME security.direct-ntlm-wrong-password-stage
    COMMAND test_standalone_spnego
        direct-ntlm-wrong-password-stage)
set_tests_properties(
    security.direct-ntlm-wrong-password-stage
    PROPERTIES LABELS "security;credentials;ntlmv2;ntlmssp;credssp;authentication-envelope;platform;offline")

foreach(spnego_case IN ITEMS
        spnego-ntlm-first-negotiate-challenge
        spnego-ntlm-authenticate-known-answer
        spnego-fallback-mechlistmic-roundtrip
        spnego-fallback-integrity-and-der-denials)
    add_test(NAME "security.${spnego_case}"
        COMMAND test_standalone_spnego "${spnego_case}")
    set_tests_properties("security.${spnego_case}" PROPERTIES
        LABELS "security;credentials;spnego;ntlmv2;credssp;offline")
endforeach()

# R10 shared configuration grammar and bounded visitor lifetime.
add_executable(test_runtime_configuration
    test_runtime_configuration.cpp)
target_link_libraries(test_runtime_configuration PRIVATE
    rdp-server-runtime-configuration)
if(MSVC)
    target_compile_options(test_runtime_configuration PRIVATE /W4 /UNDEBUG)
else()
    target_compile_options(test_runtime_configuration PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
add_test(NAME runtime.shared-configuration-grammar
    COMMAND test_runtime_configuration)
set_tests_properties(runtime.shared-configuration-grammar PROPERTIES
    LABELS "runtime;configuration;security;offline")

add_test(NAME runtime.desktop-shared-configuration-feed
    COMMAND "${CMAKE_COMMAND}"
        "-DRDP_RUNTIME_CONFIGURATION_HEADER=${PROJECT_SOURCE_DIR}/src/server/runtime/runtime_configuration.h"
        "-DRDP_RUNTIME_CONFIGURATION_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/runtime_configuration.cpp"
        "-DRDP_RUNTIME_MAIN_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/main.cpp"
        "-DRDP_GUI_MAIN_SOURCE=${PROJECT_SOURCE_DIR}/src/gui/main.cpp"
        "-DRDP_ROOT_CMAKE=${PROJECT_SOURCE_DIR}/CMakeLists.txt"
        -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_desktop_configuration_feed.cmake")
set_tests_properties(runtime.desktop-shared-configuration-feed PROPERTIES
    LABELS "runtime;configuration;gui;host-control;offline")

# R6 portable automatic-bootstrap storage/lifetime policy. This pure
# cross-platform contract opens no listener and performs no filesystem I/O.
add_executable(test_runtime_bootstrap_contract
    test_runtime_bootstrap_contract.cpp)
target_include_directories(test_runtime_bootstrap_contract PRIVATE
    "${PROJECT_SOURCE_DIR}/src")
target_compile_features(test_runtime_bootstrap_contract PRIVATE cxx_std_23)
if(MSVC)
    target_compile_options(test_runtime_bootstrap_contract PRIVATE /W4 /WX /UNDEBUG)
else()
    target_compile_options(test_runtime_bootstrap_contract PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
add_test(NAME runtime.bootstrap-portable-storage-and-no-autostart-contract
    COMMAND test_runtime_bootstrap_contract)
set_tests_properties(runtime.bootstrap-portable-storage-and-no-autostart-contract
    PROPERTIES LABELS "runtime;bootstrap;platform;security;packaging;offline")

add_executable(test_runtime_bootstrap_generated_identity_lifetimes
    test_runtime_bootstrap_generated_identity_lifetimes.cpp)
target_include_directories(test_runtime_bootstrap_generated_identity_lifetimes PRIVATE
    "${PROJECT_SOURCE_DIR}/src")
target_compile_features(
    test_runtime_bootstrap_generated_identity_lifetimes PRIVATE cxx_std_23)
if(MSVC)
    target_compile_options(
        test_runtime_bootstrap_generated_identity_lifetimes PRIVATE
        /W4 /WX /UNDEBUG)
else()
    target_compile_options(
        test_runtime_bootstrap_generated_identity_lifetimes PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
add_test(NAME runtime.bootstrap-generated-identities-default-memory-only
    COMMAND test_runtime_bootstrap_generated_identity_lifetimes)
set_tests_properties(runtime.bootstrap-generated-identities-default-memory-only
    PROPERTIES LABELS "runtime;bootstrap;platform;security;offline")

# R9 P0 owned TLS-record TSRequest v5/v6 through standalone SPNEGO to
# NTLM Type 2 challenge. This is not a real X.224/listener/client receipt.
add_test(NAME security.standalone-credssp-tsrequest-v5-v6-challenge
    COMMAND test_standalone_credssp
        r9-standalone-credssp-tsrequest-v5-v6-ntlm-challenge)
set_tests_properties(security.standalone-credssp-tsrequest-v5-v6-challenge
    PROPERTIES LABELS "assurance;security;tls;credssp;spnego;offline")

# R2 standalone CredSSP TLS binding/authInfo bridge. In-memory TLS only:
# these tests cannot grant native admission or enable a listener.
add_executable(test_standalone_credssp test_standalone_credssp.cpp)
target_link_libraries(test_standalone_credssp PRIVATE
    rdp-server-standalone-ntlmv2)
if(MSVC)
    target_compile_options(test_standalone_credssp PRIVATE /W4 /WX /UNDEBUG)
else()
    target_compile_options(test_standalone_credssp PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
# R9 P0: production Type-2 TSRequest from the physical raw-Type-1 flags,
# decoded by a test-only DER oracle rather than the production TSRequest parser.
add_test(NAME security.credssp-direct-ntlm-physical-type1-tsrequest-conformance
    COMMAND test_standalone_credssp
        r9-credssp-direct-ntlm-physical-type1-tsrequest-conformance)
set_tests_properties(
    security.credssp-direct-ntlm-physical-type1-tsrequest-conformance
    PROPERTIES LABELS "assurance;security;credentials;ntlmv2;credssp;tls;protocol;offline")

add_test(NAME security.standalone-credssp-direct-ntlm-v6-full-flow
    COMMAND test_standalone_credssp
        r9-standalone-credssp-direct-ntlm-v6-full-flow)
set_tests_properties(
    security.standalone-credssp-direct-ntlm-v6-full-flow
    PROPERTIES LABELS "assurance;security;credentials;ntlmv2;credssp;tls;authentication-envelope;platform;offline")

add_test(NAME security.standalone-credssp-direct-ntlm-wrong-password-stage
    COMMAND test_standalone_credssp
        standalone-credssp-direct-ntlm-wrong-password-stage)
set_tests_properties(
    security.standalone-credssp-direct-ntlm-wrong-password-stage
    PROPERTIES LABELS "security;credentials;ntlmv2;ntlmssp;credssp;tls;authentication-envelope;platform;offline")

add_test(NAME security.standalone-credssp-portable-envelope-modes-converge
    COMMAND test_standalone_credssp
        standalone-credssp-portable-envelope-modes-converge)
set_tests_properties(
    security.standalone-credssp-portable-envelope-modes-converge
    PROPERTIES LABELS "security;credentials;ntlmv2;credssp;tls;authentication-envelope;platform;offline")

foreach(standalone_credssp_case IN ITEMS
        standalone-credssp-tls-bound-combined-pubkeyauth
        standalone-credssp-pubkeyauth-tamper-revokes
        standalone-credssp-authinfo-exact-credential-match
        standalone-credssp-direct-tls-cannot-bind-admission-proof
        standalone-credssp-authinfo-credential-mismatch-revokes
        standalone-credssp-authinfo-tamper-revokes
        standalone-credssp-authinfo-first-failure-classification
        standalone-credssp-authinfo-credential-structure-classification
        standalone-credssp-authinfo-post-binding-revocation
        standalone-credssp-authinfo-empty-fields-are-mismatch
        standalone-credssp-authinfo-empty-field-categories
        standalone-credssp-manual-frame-provenance-denial)
    add_test(NAME "security.${standalone_credssp_case}"
        COMMAND test_standalone_credssp "${standalone_credssp_case}")
    set_tests_properties("security.${standalone_credssp_case}" PROPERTIES
        LABELS "security;credentials;ntlmv2;spnego;credssp;tls;offline")
endforeach()

# Fixed-capacity R2 authentication-abuse policy: real listener peer/global
# guard and GSS-provider-verified account gate before PAM. Pure/offline.
add_executable(test_authentication_attempt_limiter
    test_authentication_attempt_limiter.cpp)
target_link_libraries(test_authentication_attempt_limiter PRIVATE rdp-server-protocol)
if(MSVC)
    target_compile_options(test_authentication_attempt_limiter PRIVATE /W4 /UNDEBUG)
else()
    target_compile_options(test_authentication_attempt_limiter PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
add_test(NAME security.bounded-peer-global-and-account-attempts
    COMMAND test_authentication_attempt_limiter
        bounded-peer-global-and-account-attempts)
set_tests_properties(security.bounded-peer-global-and-account-attempts
    PROPERTIES LABELS "security;credentials;offline")

# Dedicated same-owner account table exhaustion/expiry invariant. This
# reuses the exact production limiter and existing CTest executable.
add_test(NAME security.verified-account-table-exhaustion
    COMMAND test_authentication_attempt_limiter
        verified-account-table-exhaustion)
set_tests_properties(security.verified-account-table-exhaustion
    PROPERTIES LABELS "security;credentials;offline")

# One R2 peer quota must be shared by IPv4 and its IPv4-mapped IPv6 form,
# without merging arbitrary IPv6 addresses or bypassing global protection.
add_test(NAME security.ipv4-mapped-ipv6-peer-quota-identity
    COMMAND test_authentication_attempt_limiter
        ipv4-mapped-ipv6-peer-quota-identity)
set_tests_properties(security.ipv4-mapped-ipv6-peer-quota-identity
    PROPERTIES LABELS "security;credentials;offline")

# R10 shared Linux listener: executable-backed offline policy and move-only
# descriptor ownership. No positive bind, socket, GSS/OS lease or GUI Start.
if(TARGET rdp-server-linux-serve-listener)
    add_executable(test_linux_serve_listener test_linux_serve_listener.cpp)
    target_link_libraries(test_linux_serve_listener PRIVATE
        rdp-server-linux-serve-listener)
    target_compile_options(test_linux_serve_listener PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    add_test(NAME runtime.linux-serve-loopback-listener-exact-endpoint-denials
        COMMAND test_linux_serve_listener
            linux-serve-loopback-listener-exact-endpoint-denials)
    set_tests_properties(
        runtime.linux-serve-loopback-listener-exact-endpoint-denials
        PROPERTIES LABELS "runtime;security;listener;offline")
endif()

# Deterministic offline R10 HostControl lifetime/status regressions.
if(TARGET rdp-server-linux-host-control)
    add_executable(test_linux_runtime_host_control
        test_linux_runtime_host_control.cpp)
    target_link_libraries(test_linux_runtime_host_control PRIVATE
        rdp-server-linux-host-control OpenSSL::SSL)
    target_compile_options(test_linux_runtime_host_control PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)

    # R10 production-backed reconnect/lifetime integration. The peer drives the
    # real LAN listener, X.224 HYBRID/TLS and DirectNtlm CredSSP path through
    # CredentialsVerified. Hosted synthetic owner evidence cannot replace the
    # production broker's real logind evidence/change monitor, so the positive
    # peer is expected to stop at native Admission before MCS. R5/R8 consume
    # the same round trip only to pin native/clipboard dormancy across failure,
    # reconnect and Stop -> Start.
    add_executable(test_linux_runtime_direct_ntlm_lifecycle
        test_linux_runtime_direct_ntlm_lifecycle.cpp)
    target_link_libraries(test_linux_runtime_direct_ntlm_lifecycle PRIVATE
        rdp-server-linux-host-control OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(
        test_linux_runtime_direct_ntlm_lifecycle PRIVATE
        "RDP_R3_MICROSOFT_MCS_FIXTURE_PATH=\"${PROJECT_SOURCE_DIR}/tests/fixtures/ms_rdpbcgr_4_1_3_mcs_connect_initial.hex\"")
    target_compile_options(test_linux_runtime_direct_ntlm_lifecycle PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    add_test(
        NAME runtime.linux-host-control-direct-ntlm-reconnect-stop-start-lifecycle
        COMMAND test_linux_runtime_direct_ntlm_lifecycle
            direct-ntlm-reconnect-stop-start-lifecycle)
    set_tests_properties(
        runtime.linux-host-control-direct-ntlm-reconnect-stop-start-lifecycle
        PROPERTIES
            LABELS "clipboard;lifecycle;security;runtime;transport;tls;credssp;authentication;admission;ntlmv2;linux;native-environment"
            SKIP_RETURN_CODE 77)
    # R1 production-backed final CredSSP framing: a truncated final authInfo
    # must retire only its peer; fragmenting the complete final authInfo over
    # separate TLS writes must still verify credentials, fail native admission
    # and permit a fresh same-listener connection with new TLS/NTLM state.
    add_test(
        NAME runtime.linux-direct-ntlm-final-authinfo-tls-fragments-reconnect
        COMMAND test_linux_runtime_direct_ntlm_lifecycle
            direct-ntlm-final-authinfo-tls-fragments-reconnect)
    set_tests_properties(
        runtime.linux-direct-ntlm-final-authinfo-tls-fragments-reconnect
        PROPERTIES
            LABELS "runtime;security;transport;tls;credssp;authentication;admission;linux;native-environment"
            SKIP_RETURN_CODE 77)

    # R1/R3 delegated-credential handoff: a valid nonempty final authInfo
    # larger than the reader scratch chunk is fragmented across tag/length/body
    # writes. The final TLS application write appends the exact 416-byte
    # Microsoft Connect-Initial; it must remain outside CredSSP and be discarded
    # when independent native Admission denies the exact connection.
    add_test(
        NAME runtime.linux-direct-ntlm-final-authinfo-large-fragments-coalesced-tail-reconnect
        COMMAND test_linux_runtime_direct_ntlm_lifecycle
            direct-ntlm-final-authinfo-large-fragments-coalesced-tail-reconnect)
    set_tests_properties(
        runtime.linux-direct-ntlm-final-authinfo-large-fragments-coalesced-tail-reconnect
        PROPERTIES
            LABELS "runtime;security;transport;tls;credssp;authentication;admission;linux;native-environment"
            SKIP_RETURN_CODE 77)

    # Pending complete final authInfo must not survive R10 Stop or act on a
    # replacement accepted connection; use real R1 TLS/R2 CredSSP owners.
    add_test(NAME runtime.linux-host-control-stop-queued-authinfo-retirement
        COMMAND test_linux_runtime_direct_ntlm_lifecycle
            direct-ntlm-stop-queued-authinfo-retirement)
    set_tests_properties(runtime.linux-host-control-stop-queued-authinfo-retirement
        PROPERTIES
            LABELS "runtime;security;transport;tls;credssp;authentication;admission;lifecycle;linux;native-environment"
            SKIP_RETURN_CODE 77
            TIMEOUT 25)

    # R10 typed final-authInfo diagnostics remain one accepted-client lifetime.
    add_test(NAME runtime.linux-authinfo-diagnostic-replacement-fencing
        COMMAND test_linux_runtime_direct_ntlm_lifecycle
            direct-ntlm-authinfo-diagnostic-replacement-fencing)
    set_tests_properties(runtime.linux-authinfo-diagnostic-replacement-fencing
        PROPERTIES
            LABELS "runtime;security;transport;tls;credssp;authentication;diagnostics;admission;lifecycle;linux;native-environment"
            SKIP_RETURN_CODE 77
            TIMEOUT 30)

    # Two consecutive Type-2 deliveries followed by peer EOF before Type 3
    # remain pre-admission on one listener while current owner consent survives;
    # this gate grants no native, MCS, graphics or clipboard authority.
    add_test(
        NAME runtime.linux-direct-ntlm-type2-peer-eof-pre-admission-diagnostics
        COMMAND test_linux_runtime_direct_ntlm_lifecycle
            direct-ntlm-type2-peer-eof-pre-admission-diagnostics)
    set_tests_properties(
        runtime.linux-direct-ntlm-type2-peer-eof-pre-admission-diagnostics
        PROPERTIES
            LABELS "runtime;security;transport;tls;credssp;authentication;diagnostics;linux;native-environment"
            SKIP_RETURN_CODE 77)

    # R10 fail-only timing evidence is connection-local and monotonic. The
    # second peer must start with a fresh EOF timer while the same listener,
    # owner grant, Session Password and fixed target tuple remain current.
    add_test(
        NAME runtime.linux-direct-ntlm-type2-peer-eof-timing-diagnostics
        COMMAND test_linux_runtime_direct_ntlm_lifecycle
            direct-ntlm-type2-peer-eof-timing-diagnostics)
    set_tests_properties(
        runtime.linux-direct-ntlm-type2-peer-eof-timing-diagnostics
        PROPERTIES
            LABELS "runtime;security;transport;tls;credssp;authentication;diagnostics;timing;lifecycle;linux;native-environment"
            SKIP_RETURN_CODE 77)

    # R10 validates the new connection-local pre-Type-2 timing stages over
    # two accepted-client lifetimes without a second transport/auth owner.
    add_test(
        NAME runtime.linux-direct-ntlm-preauth-stage-timeline-lifecycle
        COMMAND test_linux_runtime_direct_ntlm_lifecycle
            direct-ntlm-preauth-stage-timeline-lifecycle)
    set_tests_properties(
        runtime.linux-direct-ntlm-preauth-stage-timeline-lifecycle
        PROPERTIES
            LABELS "runtime;security;transport;tls;credssp;authentication;diagnostics;timing;lifecycle;linux;native-environment"
            SKIP_RETURN_CODE 77)

    add_test(
        NAME runtime.linux-direct-ntlm-preauth-service-no-starvation
        COMMAND test_linux_runtime_direct_ntlm_lifecycle
            direct-ntlm-preauth-service-no-starvation)
    set_tests_properties(
        runtime.linux-direct-ntlm-preauth-service-no-starvation
        PROPERTIES
            LABELS "runtime;security;transport;tls;credssp;authentication;diagnostics;timing;scheduling;linux;native-environment"
            SKIP_RETURN_CODE 77
            TIMEOUT 20)

    # R1 zero-timeout scheduler attribution: reuse the same production-backed
    # two-peer lifecycle but pin Read/Write dwell versus poll/service subsets.
    add_test(
        NAME runtime.linux-direct-ntlm-preauth-zero-timeout-readiness-attribution
        COMMAND test_linux_runtime_direct_ntlm_lifecycle
            direct-ntlm-preauth-zero-timeout-readiness-attribution)
    set_tests_properties(
        runtime.linux-direct-ntlm-preauth-zero-timeout-readiness-attribution
        PROPERTIES
            LABELS "runtime;security;transport;tls;credssp;authentication;diagnostics;timing;lifecycle;linux;native-environment"
            SKIP_RETURN_CODE 77)

    # Distinguish a quiet post-Type-2 peer from raw TLS/plaintext progress
    # without parsing a second transport stream or changing authentication.
    add_test(
        NAME runtime.linux-direct-ntlm-post-type2-client-data-timeline-diagnostics
        COMMAND test_linux_runtime_direct_ntlm_lifecycle
            direct-ntlm-post-type2-client-data-timeline-diagnostics)
    set_tests_properties(
        runtime.linux-direct-ntlm-post-type2-client-data-timeline-diagnostics
        PROPERTIES
            LABELS "runtime;security;transport;tls;credssp;authentication;diagnostics;timing;lifecycle;linux;native-environment"
            SKIP_RETURN_CODE 77)

    # R5 independently proves that native owner/session loss during a real
    # production-backed Direct-NTLM Await-Type-3 lifetime retires the peer
    # before X11 capture/input/clipboard construction can become reachable.
    foreach(r5_preauth_owner_loss_case IN ITEMS
            owner-lock
            owner-logout
            owner-session-switch
            owner-permission-revoke)
        add_test(
            NAME "runtime.linux-direct-ntlm-preauth-${r5_preauth_owner_loss_case}-isolation"
            COMMAND test_linux_runtime_direct_ntlm_lifecycle
                "direct-ntlm-preauth-${r5_preauth_owner_loss_case}-isolation")
        set_tests_properties(
            "runtime.linux-direct-ntlm-preauth-${r5_preauth_owner_loss_case}-isolation"
            PROPERTIES
                LABELS "runtime;security;transport;tls;credssp;authentication;admission;lifecycle;linux;native-environment;native-isolation"
                SKIP_RETURN_CODE 77
                TIMEOUT 20)
    endforeach()

    # Agent 1 post-Type-2 wire observations reuse the exact production
    # listener, R1 TLS owner and CredSSP reader. No case changes wire policy.
    add_test(NAME runtime.linux-direct-ntlm-post-type2-silence
        COMMAND test_linux_runtime_direct_ntlm_lifecycle
            direct-ntlm-post-type2-silence)
    add_test(NAME runtime.linux-direct-ntlm-post-type2-partial-tls-record
        COMMAND test_linux_runtime_direct_ntlm_lifecycle
            direct-ntlm-post-type2-partial-tls-record)
    add_test(NAME runtime.linux-direct-ntlm-post-type2-partial-tsrequest-fin-drain
        COMMAND test_linux_runtime_direct_ntlm_lifecycle
            direct-ntlm-post-type2-partial-tsrequest-fin-drain)
    add_test(NAME runtime.linux-direct-ntlm-post-type2-non-type3-tsrequest
        COMMAND test_linux_runtime_direct_ntlm_lifecycle
            direct-ntlm-post-type2-non-type3-tsrequest)
    add_test(NAME runtime.linux-direct-ntlm-post-type2-tls-close-notify
        COMMAND test_linux_runtime_direct_ntlm_lifecycle
            direct-ntlm-post-type2-tls-close-notify)
    add_test(NAME runtime.linux-direct-ntlm-post-type2-orderly-fin
        COMMAND test_linux_runtime_direct_ntlm_lifecycle
            direct-ntlm-post-type2-orderly-fin)
    # RST classification was only checked negatively by the existing FIN cases.
    add_test(NAME runtime.linux-direct-ntlm-post-type2-abortive-reset-classification
        COMMAND test_linux_runtime_direct_ntlm_lifecycle
            direct-ntlm-post-type2-abortive-reset-classification)
    add_test(NAME runtime.linux-direct-ntlm-post-type2-immediate-retry
        COMMAND test_linux_runtime_direct_ntlm_lifecycle
            direct-ntlm-post-type2-immediate-retry)
    set_tests_properties(
        runtime.linux-direct-ntlm-post-type2-silence
        runtime.linux-direct-ntlm-post-type2-partial-tls-record
        runtime.linux-direct-ntlm-post-type2-partial-tsrequest-fin-drain
        runtime.linux-direct-ntlm-post-type2-non-type3-tsrequest
        runtime.linux-direct-ntlm-post-type2-tls-close-notify
        runtime.linux-direct-ntlm-post-type2-orderly-fin
        runtime.linux-direct-ntlm-post-type2-abortive-reset-classification
        runtime.linux-direct-ntlm-post-type2-immediate-retry
        PROPERTIES
            LABELS "runtime;security;transport;tls;credssp;authentication;diagnostics;lifecycle;linux;native-environment"
            SKIP_RETURN_CODE 77)

    # One Start-scoped endpoint/service identity must survive a rejected peer
    # and an immediate second attempt without changing the current fixed Type-2
    # server name or widening retirement to the listener/credential/owner grant.
    add_test(
        NAME runtime.linux-connection-target-identity-retained-across-peer-retry
        COMMAND test_linux_runtime_direct_ntlm_lifecycle
            connection-target-identity-retained-across-peer-retry)
    set_tests_properties(
        runtime.linux-connection-target-identity-retained-across-peer-retry
        PROPERTIES
            LABELS "runtime;security;transport;tls;credssp;authentication;identity;listener;lifecycle;linux;native-environment"
            SKIP_RETURN_CODE 77)

    # A valid Type-3 shape with an invalid NTLMv2 proof must surface only the
    # existing verifier's typed credential-rejection fact. No token bytes are
    # retained or projected into product diagnostics.
    add_test(
        NAME runtime.linux-direct-ntlm-invalid-credentials-diagnostic
        COMMAND test_linux_runtime_direct_ntlm_lifecycle
            direct-ntlm-invalid-credentials-diagnostic)
    set_tests_properties(
        runtime.linux-direct-ntlm-invalid-credentials-diagnostic
        PROPERTIES
            LABELS "runtime;security;transport;tls;credssp;authentication;credentials;diagnostics;linux;native-environment"
            SKIP_RETURN_CODE 77)

    # A delivered Type 2 followed by peer close is an incomplete exchange,
    # distinct from malformed Type 3 rejection and later native Admission denial.
    add_test(
        NAME runtime.linux-type2-peer-close-distinct-from-authentication-rejection
        COMMAND test_linux_runtime_direct_ntlm_lifecycle
            type2-peer-close-distinct-from-authentication-rejection)
    set_tests_properties(
        runtime.linux-type2-peer-close-distinct-from-authentication-rejection
        PROPERTIES
            LABELS "runtime;security;transport;tls;credssp;authentication;diagnostics;linux;native-environment"
            SKIP_RETURN_CODE 77)

    add_test(
        NAME runtime.linux-direct-ntlm-type2-waits-for-preauth-timeout
        COMMAND test_linux_runtime_direct_ntlm_lifecycle
            direct-ntlm-type2-waits-for-preauth-timeout)
    set_tests_properties(
        runtime.linux-direct-ntlm-type2-waits-for-preauth-timeout
        PROPERTIES
            LABELS "runtime;security;transport;tls;credssp;authentication;timeout;listener;linux;native-environment"
            SKIP_RETURN_CODE 77
            TIMEOUT 20)

    add_test(
        NAME runtime.linux-admission-denial-retains-listener-and-accepts-second-tls
        COMMAND test_linux_runtime_direct_ntlm_lifecycle
            admission-denial-retains-listener-and-accepts-second-tls)
    set_tests_properties(
        runtime.linux-admission-denial-retains-listener-and-accepts-second-tls
        PROPERTIES
            LABELS "runtime;security;transport;tls;credssp;authentication;admission;listener;linux;native-environment"
            SKIP_RETURN_CODE 77)
    add_test(
        NAME runtime.linux-admission-denial-exposes-bounded-reason-and-retries
        COMMAND test_linux_runtime_direct_ntlm_lifecycle
            admission-denial-exposes-bounded-reason-and-retries)
    set_tests_properties(
        runtime.linux-admission-denial-exposes-bounded-reason-and-retries
        PROPERTIES
            LABELS "runtime;security;transport;tls;credssp;authentication;admission;diagnostics;listener;linux;native-environment"
            SKIP_RETURN_CODE 77)

    foreach(host_control_case IN ITEMS
            linux-host-control-no-consent-start-denials
            linux-host-control-product-status-projection
            linux-host-control-preauth-diagnostic-projection
            linux-host-control-physical-client-environment-diagnostic-projection
            linux-host-control-sharing-permission-product-projection
            linux-host-control-injected-owner-evidence-permission-determinism
            linux-host-control-standalone-credential-native-admission-separation
            linux-host-control-retained-credential-lock-session-loss
            linux-host-control-first-live-graphics-trace-projection
            linux-host-control-route-aware-lan-recommendation
            linux-host-control-stop-revoke-retirement)
        add_test(NAME "runtime.${host_control_case}"
            COMMAND test_linux_runtime_host_control "${host_control_case}")
        set_tests_properties("runtime.${host_control_case}" PROPERTIES
            LABELS "runtime;security;host-control;offline"
            SKIP_RETURN_CODE 77)
    endforeach()

    add_test(
        NAME runtime.linux-host-control-credentials-admission-mcs-diagnostics
        COMMAND test_linux_runtime_host_control
            linux-host-control-credentials-admission-mcs-diagnostic-projection)
    set_tests_properties(
        runtime.linux-host-control-credentials-admission-mcs-diagnostics
        PROPERTIES
            LABELS "runtime;security;authentication;admission;protocol;mcs;diagnostics;offline"
            SKIP_RETURN_CODE 77)

    add_test(
        NAME runtime.linux-host-control-pre-admission-protocol-dormancy
        COMMAND test_linux_runtime_host_control
            linux-host-control-pre-admission-protocol-dormancy-projection)
    set_tests_properties(
        runtime.linux-host-control-pre-admission-protocol-dormancy
        PROPERTIES
            LABELS "runtime;security;authentication;protocol;mcs;share;diagnostics;offline"
            SKIP_RETURN_CODE 77)

    # These cases intentionally consume host interface/native identity, NSS
    # account state or a real listener prerequisite. Keep the existing names
    # for selectors, but do not classify their environment-dependent coverage
    # as deterministic offline behavior.
    foreach(native_host_control_case IN ITEMS
            linux-host-control-revalidated-interface-denials
            linux-host-control-automatic-tls-identity-lifecycle
            linux-host-control-rejected-selection-retires-previous
            linux-host-control-native-interface-id-verification
            linux-host-control-standalone-password-lifecycle
            linux-host-control-stop-start-retains-standalone-credential
            linux-host-control-fresh-native-authorization-every-start
            linux-portable-gui-bootstrap-listener-acceptance)
        add_test(NAME "runtime.${native_host_control_case}"
            COMMAND test_linux_runtime_host_control "${native_host_control_case}")
        set_tests_properties("runtime.${native_host_control_case}" PROPERTIES
            LABELS "runtime;security;host-control;linux;native-environment"
            SKIP_RETURN_CODE 77)
    endforeach()

    # Focused R1 native-environment proof: a real production standalone
    # credential and R2 owner grant remain pre-listener until the selected
    # endpoint is configured, then R1 must publish only the exact bound
    # listener plus same-generation matched TLS identity.
    add_test(
        NAME runtime.linux-host-control-standalone-owner-grant-authoritative-listener
        COMMAND test_linux_runtime_host_control
            linux-host-control-standalone-owner-grant-authoritative-listener)
    set_tests_properties(
        runtime.linux-host-control-standalone-owner-grant-authoritative-listener
        PROPERTIES
            LABELS "runtime;security;transport;tls;owner-consent;standalone;host-control;linux;native-environment"
            SKIP_RETURN_CODE 77)

    # R9 P0 exact-SHA pre-owner gate: same-port three-cycle credential and
    # consent lifecycle, plus a real X.224 HYBRID/SSL client against R1.
    # Native environment skip is not a PASS receipt for owner qualification.
    add_test(NAME runtime.start-stop-start-and-tls-interop
        COMMAND test_linux_runtime_host_control
            r9-start-stop-start-and-tls-interop)
    set_tests_properties(runtime.start-stop-start-and-tls-interop PROPERTIES
        LABELS "assurance;security;transport;tls;owner-consent;linux;native-environment"
        SKIP_RETURN_CODE 77)

    # Production/default native-evidence observation is intentionally separate
    # from the deterministic offline cases above. It skips on headless hosts
    # and never requests consent, opens a listener, captures or injects input.
    add_test(NAME runtime.linux-host-control-default-native-evidence-projection
        COMMAND test_linux_runtime_host_control
            linux-host-control-default-native-evidence-projection)
    set_tests_properties(
        runtime.linux-host-control-default-native-evidence-projection
        PROPERTIES
            LABELS "runtime;security;owner-consent;host-control;linux;native-observation"
            SKIP_RETURN_CODE 77)

    add_test(NAME runtime.linux-host-control-authority-lifetime-handoff
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_LINUX_HOST_CONTROL_HEADER=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_host_control.h"
            "-DRDP_LINUX_HOST_CONTROL_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_host_control.cpp"
            "-DRDP_LINUX_CONNECTION_HEADER=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_connection.h"
            "-DRDP_LINUX_CONNECTION_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_connection.cpp"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_host_owner_authority_handoff.cmake")
    set_tests_properties(
        runtime.linux-host-control-authority-lifetime-handoff PROPERTIES
        LABELS "runtime;security;owner-consent;host-control;offline")
    add_test(NAME runtime.linux-host-control-provisioned-listener-transaction
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_LINUX_HOST_CONTROL_HEADER=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_host_control.h"
            "-DRDP_LINUX_HOST_CONTROL_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_host_control.cpp"
            "-DRDP_GUI_HOST_CONTROL_SOURCE=${PROJECT_SOURCE_DIR}/src/gui/host_control.cpp"
            "-DRDP_GUI_WINDOW_SOURCE=${PROJECT_SOURCE_DIR}/src/gui/desktop_window.cpp"
            "-DRDP_ROOT_CMAKE=${PROJECT_SOURCE_DIR}/CMakeLists.txt"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_host_provisioned_listener_transaction.cmake")
    set_tests_properties(
        runtime.linux-host-control-provisioned-listener-transaction PROPERTIES
        LABELS "runtime;security;transport;tls;owner-consent;host-control;offline")

    add_test(NAME runtime.linux-host-control-bounded-accepted-client-scheduler
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_LINUX_HOST_CONTROL_HEADER=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_host_control.h"
            "-DRDP_LINUX_HOST_CONTROL_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_host_control.cpp"
            "-DRDP_GUI_MAIN_SOURCE=${PROJECT_SOURCE_DIR}/src/gui/main.cpp"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_host_accepted_client_scheduler.cmake")
    set_tests_properties(
        runtime.linux-host-control-bounded-accepted-client-scheduler PROPERTIES
        LABELS "runtime;security;transport;tls;admission;share;host-control;offline")

    add_test(NAME runtime.linux-host-control-standalone-authentication-selector
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_LINUX_HOST_CONTROL_HEADER=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_host_control.h"
            "-DRDP_LINUX_HOST_CONTROL_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_host_control.cpp"
            "-DRDP_LINUX_CONNECTION_HEADER=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_connection.h"
            "-DRDP_GUI_WINDOW_SOURCE=${PROJECT_SOURCE_DIR}/src/gui/desktop_window.cpp"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_host_standalone_authentication_selector.cmake")
    set_tests_properties(
        runtime.linux-host-control-standalone-authentication-selector PROPERTIES
        LABELS "runtime;security;standalone;host-control;offline")

    add_test(NAME runtime.linux-host-control-native-desktop-bounded-post-share
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_LINUX_HOST_CONTROL_HEADER=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_host_control.h"
            "-DRDP_LINUX_HOST_CONTROL_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_host_control.cpp"
            "-DRDP_X11_DESKTOP_SOURCE=${PROJECT_SOURCE_DIR}/src/x11/x11_desktop_resources.cpp"
            "-DRDP_ROOT_CMAKE=${PROJECT_SOURCE_DIR}/CMakeLists.txt"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_host_native_desktop_scheduler.cmake")
    set_tests_properties(
        runtime.linux-host-control-native-desktop-bounded-post-share PROPERTIES
        LABELS "runtime;security;transport;admission;graphics;frame;codec;native;host-control;x11;offline")

    add_test(NAME runtime.linux-auth-envelope-independent-native-owner
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_LINUX_HOST_CONTROL_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_host_control.cpp"
            "-DRDP_LINUX_CONNECTION_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_connection.cpp"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_r5_auth_envelope_independence.cmake")
    set_tests_properties(
        runtime.linux-auth-envelope-independent-native-owner PROPERTIES
        LABELS "runtime;security;admission;graphics;native;host-control;linux;x11;native-desktop;session;offline")

    add_test(NAME runtime.linux-host-control-dormant-unicode-clipboard-composition
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_LINUX_HOST_CONTROL_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_host_control.cpp"
            "-DRDP_RUNTIME_ENTRYPOINT_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/main.cpp"
            "-DRDP_DESKTOP_WINDOW_SOURCE=${PROJECT_SOURCE_DIR}/src/gui/desktop_window.cpp"
            "-DRDP_LINUX_PREPARED_CLIPBOARD_HEADER=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_prepared_clipboard_owner.h"
            "-DRDP_X11_CLIPBOARD_SOURCE=${PROJECT_SOURCE_DIR}/src/x11/x11_clipboard_adapter.cpp"
            "-DRDP_R8_R3_CLIPBOARD_BRIDGE_SOURCE=${PROJECT_SOURCE_DIR}/src/server/clipboard/r3_clipboard_transfer_bridge.cpp"
            "-DRDP_ROOT_CMAKE=${PROJECT_SOURCE_DIR}/CMakeLists.txt"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_host_clipboard_dormant_composition.cmake")
    set_tests_properties(
        runtime.linux-host-control-dormant-unicode-clipboard-composition PROPERTIES
        LABELS "runtime;clipboard;lifecycle;security;x11;offline")

    # R8 P2: automatic zero-argument GUI bootstrap may provision local runtime
    # prerequisites, but must not activate CLIPRDR or preserve stale clipboard
    # ownership across password replacement, Stop/restart, tray hide, or Quit.
    add_test(NAME runtime.linux-gui-bootstrap-clipboard-dormancy
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_DESKTOP_ENTRYPOINT_SOURCE=${PROJECT_SOURCE_DIR}/src/gui/main.cpp"
            "-DRDP_DESKTOP_WINDOW_HEADER=${PROJECT_SOURCE_DIR}/src/gui/desktop_window.h"
            "-DRDP_DESKTOP_WINDOW_SOURCE=${PROJECT_SOURCE_DIR}/src/gui/desktop_window.cpp"
            "-DRDP_LINUX_HOST_CONTROL_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_host_control.cpp"
            "-DRDP_LINUX_HOST_CONTROL_HEADER=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_host_control.h"
            "-DRDP_LINUX_PREPARED_CLIPBOARD_HEADER=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_prepared_clipboard_owner.h"
            "-DRDP_RUNTIME_BOOTSTRAP_HEADER=${PROJECT_SOURCE_DIR}/src/server/runtime/runtime_application_bootstrap.h"
            "-DRDP_RUNTIME_HOST_CONTROL_HEADER=${PROJECT_SOURCE_DIR}/src/server/runtime/runtime_host_control.h"
            "-DRDP_STANDALONE_CREDENTIAL_CONSENT_HEADER=${PROJECT_SOURCE_DIR}/src/server/security/standalone_credential_consent.h"
            "-DRDP_TESTS_CMAKE=${PROJECT_SOURCE_DIR}/tests/CMakeLists.txt"
            "-DRDP_WINDOWS_CREDSSP_HARNESS_SOURCE=${PROJECT_SOURCE_DIR}/tests/test_windows_sspi_credssp_interop.cpp"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_bootstrap_clipboard_dormancy.cmake")
    set_tests_properties(
        runtime.linux-gui-bootstrap-clipboard-dormancy PROPERTIES
        LABELS "runtime;clipboard;lifecycle;security;gui;offline")
endif()

if(TARGET rdp-server-macos-host-control)
    add_executable(test_macos_runtime_host_control
        test_macos_runtime_host_control.cpp)
    target_link_libraries(test_macos_runtime_host_control PRIVATE
        rdp-server-macos-host-control)
    target_compile_options(test_macos_runtime_host_control PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    foreach(mac_host_control_case IN ITEMS
            macos-host-control-initial-product-projection
            macos-host-control-standalone-password-lifecycle
            macos-host-control-sharing-permission-lifecycle
            macos-host-control-stop-revoke-retirement
            macos-portable-gui-bootstrap-readiness
            macos-host-control-lan-endpoint-recommendation
            macos-host-control-screen-recording-permission-denial
            macos-host-control-accessibility-permission-denial
            macos-host-control-permission-revocation-retires-sharing
            macos-host-control-no-prompt-on-app-launch)
        add_test(NAME "runtime.${mac_host_control_case}"
            COMMAND test_macos_runtime_host_control "${mac_host_control_case}")
        set_tests_properties("runtime.${mac_host_control_case}" PROPERTIES
            LABELS "runtime;security;macos;offline"
            SKIP_RETURN_CODE 77)
    endforeach()

    # R10 production macOS pre-admission path with a synthetic local TCP peer.
    # No real RDP client, R2 native admission, TCC, capture or input is used.
    # Network/interface unavailable is an explicit skip, not an offline pass.
    add_test(NAME runtime.macos-host-control-accepted-pre-admission-dormancy
        COMMAND test_macos_runtime_host_control
            macos-host-control-accepted-pre-admission-dormancy)
    set_tests_properties(
        runtime.macos-host-control-accepted-pre-admission-dormancy PROPERTIES
        LABELS "runtime;security;transport;tls;macos;native-environment"
        SKIP_RETURN_CODE 77)

    # R6 portable Stop/Start contract: exercise the production macOS listener
    # three times on one immediately reusable port. The injected owner evidence
    # avoids TCC prompts; interface/bind/TLS/listener state remains production.
    add_test(
        NAME runtime.macos-host-control-stop-start-retains-standalone-credential
        COMMAND test_macos_runtime_host_control
            macos-host-control-stop-start-retains-standalone-credential)
    set_tests_properties(
        runtime.macos-host-control-stop-start-retains-standalone-credential
        PROPERTIES
            LABELS "runtime;security;transport;tls;owner-consent;platform;macos;native-environment"
            SKIP_RETURN_CODE 77)

    # Production/default route/interface observation intentionally consumes the
    # machine environment and therefore has its own native integration gate.
    add_test(NAME runtime.macos-host-control-native-lan-endpoint-observation
        COMMAND test_macos_runtime_host_control
            macos-host-control-native-lan-endpoint-observation)
    set_tests_properties(
        runtime.macos-host-control-native-lan-endpoint-observation PROPERTIES
            LABELS "runtime;security;macos;native-environment"
            SKIP_RETURN_CODE 77)

    # R3 cross-platform application-host consumption: macOS must retain the
    # generated process-local licensing identity before Start without opening a
    # listener as a construction or idle-service side effect.
    add_test(NAME runtime.macos-host-control-automatic-licensing-prestart-no-listener
        COMMAND test_macos_runtime_host_control
            macos-host-control-automatic-licensing-prestart-no-listener)
    set_tests_properties(
        runtime.macos-host-control-automatic-licensing-prestart-no-listener
        PROPERTIES
            LABELS "runtime;security;licensing;protocol;macos;offline"
            SKIP_RETURN_CODE 77)
endif()

# R10's single-owner GUI control contract: offline, no TCP or R2 positive lease.
add_executable(test_runtime_host_control test_runtime_host_control.cpp)
target_link_libraries(test_runtime_host_control PRIVATE rdp-server-protocol)
if(MSVC)
    target_compile_options(test_runtime_host_control PRIVATE /W4 /UNDEBUG)
else()
    target_compile_options(test_runtime_host_control PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
foreach(host_control_case IN ITEMS
        host-control-unavailable-denials
        host-control-standalone-deny-fallback-cleanses
        host-control-windows-rpc-interface-macro-compatibility
        host-control-cross-platform-lan-recommendation-contract
        host-control-gui-round2-endpoint-recommendation
        host-control-product-status-projection
        host-control-incomplete-peer-product-state
        host-control-connection-target-identity-taxonomy
        host-control-product-target-tuple-construction
        host-control-credential-editing-lifecycle-policy
        host-control-route-aware-recommendation-non-authority
        host-control-clipboard-state-denials
        host-control-credential-setup-denials
        host-control-selected-lan-interface-denials
        host-control-authentication-outcome-denials)
    add_test(NAME "runtime.${host_control_case}"
        COMMAND test_runtime_host_control "${host_control_case}")
    set_tests_properties("runtime.${host_control_case}" PROPERTIES
        LABELS "runtime;security;host-control;offline")
endforeach()

# R1 remains the actual bind/security authority when R10 changes endpoint
# recommendation ranking. This source contract is fully offline: it opens no
# socket and requires no FIRST/native environment.
add_test(NAME runtime.lan-bind-revalidates-recommended-endpoint
    COMMAND "${CMAKE_COMMAND}"
        "-DRDP_RUNTIME_HOST_CONTROL_HEADER=${PROJECT_SOURCE_DIR}/src/server/runtime/runtime_host_control.h"
        "-DRDP_LINUX_HOST_CONTROL_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_host_control.cpp"
        "-DRDP_LAN_LISTENER_SOURCE=${PROJECT_SOURCE_DIR}/src/server/transport/lan_listener.cpp"
        -P "${PROJECT_SOURCE_DIR}/tests/check_r1_recommendation_bind_authority.cmake")
set_tests_properties(runtime.lan-bind-revalidates-recommended-endpoint
    PROPERTIES LABELS "runtime;security;transport;lan;host-control;offline")

# R2 M1 host consent is one noncopyable positive authority owned by R10.
# Deterministic injected evidence tests the capability state machine only;
# no socket, live seat or network peer can mint consent from these fixtures.
add_executable(test_current_owner_sharing_authority
    test_current_owner_sharing_authority.cpp)
target_include_directories(test_current_owner_sharing_authority PRIVATE
    "${PROJECT_SOURCE_DIR}/src")
target_compile_features(test_current_owner_sharing_authority PRIVATE cxx_std_23)
if(MSVC)
    target_compile_options(test_current_owner_sharing_authority PRIVATE
        /W4 /UNDEBUG)
else()
    target_compile_options(test_current_owner_sharing_authority PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
foreach(owner_consent_case IN ITEMS
        owner-consent-positive-seat0-unlocked-grant
        owner-consent-expiry-revokes
        owner-consent-read-only-grant-observation
        owner-consent-read-only-product-facts
        owner-consent-invalid-native-evidence-denials
        owner-consent-stop-lock-logout-switch-replacement-revocations
        owner-consent-start-admission-evidence-mismatch-diagnostics
        owner-consent-credential-expiry-native-loss-revocations
        standalone-credential-portable-stop-revoke-matrix)
    add_test(NAME "security.${owner_consent_case}"
        COMMAND test_current_owner_sharing_authority "${owner_consent_case}")
    set_tests_properties("security.${owner_consent_case}" PROPERTIES
        LABELS "security;owner-consent;offline" TIMEOUT 15)
endforeach()
set_tests_properties(
    security.owner-consent-start-admission-evidence-mismatch-diagnostics
    PROPERTIES
    LABELS "security;owner-consent;linux;x11;native-desktop;session;offline"
    TIMEOUT 15)

# R2 Track E Windows/macOS native authorization capability. These synthetic
# fixtures use fake authenticated identity + fake native evidence + the real
# CurrentOwnerSharingAuthority state machine. They never call WTS/LSA, Security,
# TCC, capture, input or a listener and cannot create a production admission.
add_executable(test_native_desktop_authorization
    test_native_desktop_authorization.cpp)
target_link_libraries(test_native_desktop_authorization PRIVATE
    rdp-server-native-desktop-authorization)
if(MSVC)
    target_compile_options(test_native_desktop_authorization PRIVATE
        /W4 /WX /UNDEBUG)
else()
    target_compile_options(test_native_desktop_authorization PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
foreach(native_authorization_case IN ITEMS
        windows-positive-construction
        windows-stale-denials
        macos-positive-construction
        macos-stale-denials)
    add_test(NAME "security.native-authorization-${native_authorization_case}"
        COMMAND test_native_desktop_authorization
            "${native_authorization_case}")
    set_tests_properties(
        "security.native-authorization-${native_authorization_case}" PROPERTIES
        LABELS "security;native-authorization;offline" TIMEOUT 15)
endforeach()

# R2 P0 portable authenticated-session native authorization. The standalone
# fixture intentionally supplies no SID/UID identity mapping and uses the real
# generation-fenced StandalonePasswordCredentialOwner. Native evidence and
# CurrentOwnerSharingAuthority remain required and no live native API is called.
add_executable(test_native_desktop_standalone_authorization
    test_native_desktop_standalone_authorization.cpp)
target_link_libraries(test_native_desktop_standalone_authorization PRIVATE
    rdp-server-native-desktop-authorization
    rdp-server-standalone-ntlmv2)
if(MSVC)
    target_compile_options(test_native_desktop_standalone_authorization PRIVATE
        /W4 /WX /UNDEBUG)
else()
    target_compile_options(test_native_desktop_standalone_authorization PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
foreach(standalone_native_authorization_case IN ITEMS
        standalone-current-owner-without-os-identity
        standalone-provenance-and-revocation-denials
        macos-standalone-reentrant-generation-denials
        macos-standalone-nested-visitor-denials)
    add_test(
        NAME "security.native-authorization-${standalone_native_authorization_case}"
        COMMAND test_native_desktop_standalone_authorization
            "${standalone_native_authorization_case}")
    set_tests_properties(
        "security.native-authorization-${standalone_native_authorization_case}"
        PROPERTIES
            LABELS "security;native-authorization;standalone;offline"
            TIMEOUT 15)
endforeach()

find_package(Python3 REQUIRED COMPONENTS Interpreter)

# Agent 5 read-only physical-client evidence helper. The synthetic fixture
# reads only a temporary .app Info.plist and temporary logs; it never launches
# Windows App, changes Keychain/trust state, touches preferences or uses network.
add_test(NAME macos.windows-app-owner-evidence-readonly-manifest
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/test_macos_windows_app_owner_evidence.py"
        --script "${PROJECT_SOURCE_DIR}/scripts/macos_windows_app_owner_evidence.py")
set_tests_properties(macos.windows-app-owner-evidence-readonly-manifest PROPERTIES
    LABELS "macos;offline;project-policy;evidence" TIMEOUT 15)

# Dedicated negative gate: contradictory R1/R10 timing subsets and private
# manifest extension fields must never pass validation or enter shared output.
add_test(NAME macos.windows-app-owner-evidence-timing-subset-denials
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/test_macos_windows_app_owner_evidence.py"
        --script "${PROJECT_SOURCE_DIR}/scripts/macos_windows_app_owner_evidence.py"
        -k timing_attribution_subset_denials_and_private_metadata_redaction)
set_tests_properties(macos.windows-app-owner-evidence-timing-subset-denials PROPERTIES
    LABELS "macos;offline;project-policy;evidence" TIMEOUT 15)

# R6 privacy-safe paired Microsoft client evidence; no client launch.
add_test(NAME interop.windows-client-ab-evidence-contradiction-denials
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/test_macos_windows_app_owner_evidence.py"
        --script "${PROJECT_SOURCE_DIR}/scripts/macos_windows_app_owner_evidence.py"
        -k paired_)
set_tests_properties(interop.windows-client-ab-evidence-contradiction-denials PROPERTIES
    LABELS "windows;macos;interop;offline;security;evidence" TIMEOUT 15)

# R5 owner-private Linux/X11 evidence validation is offline only. No listener,
# XTEST/XCB, credentials, native R2 lease or physical desktop is opened.
add_test(NAME linux.x11-owner-private-evidence-validation-denials
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/test_linux_x11_owner_evidence.py"
        --script "${PROJECT_SOURCE_DIR}/scripts/linux_x11_owner_evidence.py")
set_tests_properties(linux.x11-owner-private-evidence-validation-denials PROPERTIES
    LABELS "linux;x11;offline;project-policy;evidence;security" TIMEOUT 15)

# R9 cross-platform SERVER-TEST package contract. This synthetic archive test
# never executes a server, opens a socket, touches a service manager or uses a
# native desktop. Real executable CLI/ABI/dependency smoke runs in the matrix.
add_test(NAME packaging.server-test-cross-platform-offline-contract
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/test_server_test_bundle.py"
        --script "${PROJECT_SOURCE_DIR}/scripts/server_test_bundle.py")
set_tests_properties(packaging.server-test-cross-platform-offline-contract PROPERTIES
    LABELS "packaging;release;server-test;offline" TIMEOUT 30)

# R6 Windows SERVER-TEST packaging/lifecycle contract. Portable checks run on
# every host; native PowerShell install/verify/start/status/stop/uninstall
# assertions execute only on Windows and never invoke the server executable.
add_test(NAME windows.package-user-lifecycle-offline-contract
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/test_windows_server_bundle.py"
        --script "${PROJECT_SOURCE_DIR}/scripts/server_test_bundle.py"
        --lifecycle-script "${PROJECT_SOURCE_DIR}/packaging/windows/rdp-server-test.ps1")
set_tests_properties(windows.package-user-lifecycle-offline-contract PROPERTIES
    LABELS "windows;packaging;security;server-test;offline" TIMEOUT 90)

# Independent Windows evidence: the hosted runner must actually exercise a
# reparse-point parent, not silently skip inside the aggregate unittest.
if(WIN32)
    add_test(NAME windows.package-reparse-parent-denial
        COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tests/test_windows_server_bundle.py"
            --script "${PROJECT_SOURCE_DIR}/scripts/server_test_bundle.py"
            --lifecycle-script "${PROJECT_SOURCE_DIR}/packaging/windows/rdp-server-test.ps1"
            WindowsServerBundleTests.test_native_powershell_rejects_parent_directory_reparse_point)
    set_tests_properties(windows.package-reparse-parent-denial PROPERTIES
        LABELS "windows;packaging;security;server-test;offline" TIMEOUT 30)
endif()

# R7 offline test-bundle policy: no desktop, TCC, network or process activation.
add_test(NAME macos.package-offline-integrity-and-idempotence
    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/test_macos_test_bundle.py"
        --script "${PROJECT_SOURCE_DIR}/scripts/macos_test_bundle.py")
set_tests_properties(macos.package-offline-integrity-and-idempotence PROPERTIES
    LABELS "macos;packaging;security;offline")

# R7/R9 .app archive contract; fixtures never invoke AppKit, TCC, or networking.
add_test(NAME packaging.macos-portable-gui-app-integrity-denials
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/test_macos_gui_bundle.py")
set_tests_properties(packaging.macos-portable-gui-app-integrity-denials
    PROPERTIES LABELS "macos;packaging;gui;security;offline" TIMEOUT 30)
add_test(NAME packaging.macos-portable-gui-macdeployqt-symlink-resolution
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/test_macos_gui_bundle.py"
        MacGuiBundleTests.test_macdeployqt_symlink_resolution_requires_executable_target)
set_tests_properties(packaging.macos-portable-gui-macdeployqt-symlink-resolution
    PROPERTIES LABELS "macos;packaging;gui;security;offline" TIMEOUT 30)
add_test(NAME packaging.macos-portable-gui-minimal-cocoa-deployment
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/test_macos_gui_bundle.py"
        MacGuiBundleTests.test_macdeployqt_minimal_cocoa_deployment_command)
set_tests_properties(packaging.macos-portable-gui-minimal-cocoa-deployment
    PROPERTIES LABELS "macos;packaging;gui;security;offline" TIMEOUT 30)
add_test(NAME packaging.macos-portable-gui-install-id-normalization
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/test_macos_gui_bundle.py"
        MacGuiBundleTests.test_absolute_install_ids_normalized_before_adhoc_signing)
set_tests_properties(packaging.macos-portable-gui-install-id-normalization
    PROPERTIES LABELS "macos;packaging;gui;security;offline" TIMEOUT 30)

# Preserve only bounded in-framework version aliases through ZIP extraction,
# retaining the real signed Qt subcomponent Info.plist lookup paths.
add_test(NAME packaging.macos-portable-gui-framework-alias-integrity-denials
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/test_macos_gui_bundle.py"
        MacGuiBundleTests.test_signed_framework_version_aliases_survive_extraction
        MacGuiBundleTests.test_escaping_framework_alias_is_rejected)
set_tests_properties(packaging.macos-portable-gui-framework-alias-integrity-denials
    PROPERTIES LABELS "macos;packaging;gui;security;offline" TIMEOUT 30)
add_test(NAME packaging.portable-gui-macos-framework-link-verifier-denials
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/test_portable_gui_archive.py"
        PortableGuiArchiveTests.test_macos_framework_links_are_bounded_and_resolved)
set_tests_properties(packaging.portable-gui-macos-framework-link-verifier-denials
    PROPERTIES LABELS "macos;packaging;gui;security;offline" TIMEOUT 30)

# R7 optional per-user LaunchAgent contract. Rendering is offline and refuses
# implicit registration; tests never invoke a service manager or native APIs.
# Register only on Apple because the contract deliberately validates POSIX
# macOS home paths and file modes.
if(APPLE)
    add_test(NAME packaging.macos-user-launch-agent-offline-contract
        COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tests/test_macos_test_launch_agent.py"
            --script "${PROJECT_SOURCE_DIR}/scripts/macos_test_launch_agent.py")
    set_tests_properties(packaging.macos-user-launch-agent-offline-contract PROPERTIES
        LABELS "macos;packaging;security;offline" TIMEOUT 20)
endif()
# R9 canonical roadmap integrity and truncation regressions (offline).
add_test(NAME project.canonical-roadmap-integrity-and-truncation-denials
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/scripts/verify_canonical_roadmap.py"
        "${PROJECT_SOURCE_DIR}/docs/ROADMAP.md" --self-test)
set_tests_properties(project.canonical-roadmap-integrity-and-truncation-denials
    PROPERTIES LABELS "project-policy;documentation;offline" TIMEOUT 15)

add_test(NAME project.ci-workflow-structure-denials
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/scripts/validate_ci_workflow.py"
        --workflow "${PROJECT_SOURCE_DIR}/.github/workflows/ci.yml"
        --fixture-root "${PROJECT_SOURCE_DIR}/tests/fixtures/ci_workflow_structure"
        --self-test)
set_tests_properties(project.ci-workflow-structure-denials PROPERTIES
    LABELS "policy;ci")

# R9 Windows PORTABLE-GUI release barrier and socket query denial fixtures are
# platform-independent source checks: no Qt, desktop, sockets or services run.
# Keep these in ordinary full Debug CTest, not only the hosted CI structure job.
add_test(NAME packaging.windows-portable-gui-clean-release-structure-denials
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/test_r9_clean_windows_gate.py")
set_tests_properties(packaging.windows-portable-gui-clean-release-structure-denials
    PROPERTIES LABELS "windows;packaging;release;security;offline" TIMEOUT 20)
add_test(NAME packaging.windows-portable-gui-manual-clean-receipt-verifier-denials
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/test_r9_manual_clean_windows_receipt.py")
set_tests_properties(packaging.windows-portable-gui-manual-clean-receipt-verifier-denials
    PROPERTIES LABELS "windows;packaging;release;security;offline" TIMEOUT 20)

function(add_rdp_test source_file suite behavior)
    get_filename_component(test_target "${source_file}" NAME_WE)
    add_executable("${test_target}" "${source_file}")
    target_link_libraries("${test_target}" PRIVATE rdp-server-protocol)
    if(test_target MATCHES "mcs_connect_initial|gcc_conference_create|preauth_session")
        target_compile_definitions("${test_target}" PRIVATE
            "OWNED_MCS_FIXTURE_PATH=\"${PROJECT_SOURCE_DIR}/tests/fixtures/ms_rdpbcgr_4_1_3_mcs_connect_initial.hex\"")
    endif()
    if(MSVC)
        target_compile_options("${test_target}" PRIVATE /UNDEBUG)
    else()
        target_compile_options("${test_target}" PRIVATE -UNDEBUG)
    endif()
    if(test_target STREQUAL "test_owned_mcs_connect_initial")
        # Split four existing envelope behavior groups, plus two new
        # T.125 domain-negotiation groups, from the SAME executable.
        foreach(case_name IN ITEMS
                mcs-envelope-microsoft
                mcs-envelope-tpkt-errors
                mcs-envelope-ber-errors
                mcs-envelope-mutations
                mcs-domain-merge
                mcs-domain-rejections
                mcs-response-wire
                mcs-gcc-first-exchange-conformance
                mcs-response-security-replay
                mcs-response-session-allocation-plan
                mcs-static-channel-role-binding
                mcs-static-channel-role-denials
                mcs-client-info-protected-route
                mcs-client-info-protected-route-denials
                mcs-client-info-packet-structure
                mcs-client-info-packet-denials
                mcs-response-write-receipts
                mcs-response-write-denials
                mcs-response-rejections
                mcs-erect-request
                mcs-attach-request
                mcs-channel-join-request
                mcs-rdp-user-id-range-conformance
                mcs-attach-confirm-wire
                mcs-session-attach-confirm-write-receipts
                mcs-session-attach-confirm-denials
                mcs-channel-join-confirm
                mcs-session-join-confirm-receipts
                mcs-session-join-confirm-denials
                mcs-join-write-completion
                mcs-join-write-denials
                mcs-join-duplicate-ignored
                mcs-join-batched-requests
                mcs-send-data-joined-membership
                mcs-send-data-joined-denials
                mcs-join-stale-write-receipts
                mcs-join-stale-partial-write-slices
                mcs-send-indication-joined-wire
                mcs-send-indication-joined-denials
                mcs-session-unverified-connect
                mcs-session-unverified-ordering
                mcs-session-post-response-domain-ordering-denials
                mcs-session-first-envelope-size-bounds
                mcs-session-unadmitted-domain-size-bounds
                mcs-session-first-failure-boundaries
                mcs-session-domain-failure-boundaries
                licensing-personal-no-cal-valid-client-completion
                licensing-personal-presented-cal-valid-client-completion
                licensing-personal-mode-and-malformed-denials
                licensing-personal-valid-client-duplicate-and-partial-revocation
                licensing-server-request-wire
                licensing-server-identity-configuration
                licensing-server-request-certificate-required
                licensing-server-request-generated-random
                licensing-server-request-write-receipts
                licensing-server-request-write-denials
                licensing-client-response-before-request-delivery
                licensing-generated-request-cancellation-replay
                licensing-client-response-single-consumption
                licensing-client-envelope-wire
                licensing-client-envelope-denials
                licensing-key-exchange-wire
                licensing-key-exchange-denials
                licensing-key-derivation
                licensing-rc4-wire
                licensing-mac-wire
                licensing-client-license-info-hwid-proof
                licensing-client-license-info-hwid-denials
                licensing-client-license-info-hwid-fresh-verification
                licensing-existing-cal-authority-request-ownership
                licensing-existing-cal-live-visit-lifetime
                licensing-existing-cal-authority-request-hwid-proof-gate
                licensing-existing-cal-authority-request-product-and-correlation-denials
                licensing-existing-cal-authority-request-revocation-replay
                licensing-client-cal-chain-structure
                # PKCS#7 signed-content absent/empty acceptance and nonempty denial.
                licensing-client-cal-signed-content-empty-only
                licensing-client-cal-issuer-signature-denials
                licensing-client-cal-issuer-constraints
                licensing-client-cal-product-extension-denials
                licensing-client-cal-certificate-validity
                licensing-client-cal-expiry-hwid-denials
                licensing-client-cal-no-premature-completion
                licensing-client-cal-terminal-retirement
                licensing-server-platform-challenge-wire
                licensing-server-platform-challenge-write-receipts
                licensing-server-platform-challenge-write-denials
                licensing-client-platform-challenge-response-proof
                licensing-client-platform-challenge-response-denials
                licensing-authority-grant-boundary
                licensing-server-license-grant-write-receipts
                licensing-server-license-grant-write-denials
                licensing-new-license-info-wire
                licensing-new-license-info-denials
                licensing-server-new-license-wire
                licensing-server-upgrade-license-wire
                licensing-server-license-grant-encode-denials
                licensing-server-license-grant-transactional-output
                licensing-server-grant-no-live-publication
                licensing-premaster-rsa-decrypt
                licensing-premaster-rsa-denials
                licensing-runtime-context-ownership
                licensing-runtime-context-denials
                licensing-initial-crypto-preparation
                licensing-initial-crypto-denials
                licensing-key-material-terminal-replay
                licensing-preamble-and-state
                licensing-length-bounds
                licensing-ordering-denials
                mcs-disconnect-wire
                mcs-disconnect-rejections
                mcs-send-data-wire
                mcs-send-data-rejections
                mcs-send-indication-wire
                mcs-send-indication-rejections
                share-control-header-wire
                share-control-header-rejections
                share-data-header-wire
                share-data-header-rejections
                share-input-slow-path-wire
                share-input-slow-path-rejections
                share-sync-finalization-wire
                share-sync-finalization-rejections
                share-control-finalization-wire
                share-control-finalization-rejections
                share-active-capabilities-wire
                share-active-capabilities-rejections
                share-general-capability-wire
                share-general-capability-rejections
                share-bitmap-capability-wire
                share-bitmap-capability-rejections
                share-demand-active-encode-wire
                share-demand-active-encode-rejections
                share-server-finalization-encode-wire
                share-server-finalization-encode-rejections
                share-personal-activation-ordering
                share-confirm-active-client-capability-store
                share-finalization-early-input-ignore
                share-personal-activation-denials
                rdpgfx-client-core-capability-gate
                dvc-graphics-create-success
                dvc-graphics-caps-selection
                dvc-graphics-caps-unsupported-denial
                dvc-graphics-presentation-wire
                dvc-graphics-frame-ack-handoff-wire
                dvc-graphics-frame-ack-handoff-malformed
                dvc-graphics-frame-ack-handoff-stale
                dvc-graphics-frame-credit-preflight
                dvc-graphics-surface-remap
                dvc-graphics-first-client-acceptance-observability
                dvc-graphics-frame-acceptance-status-projection
                dvc-graphics-create-response-denials
                dvc-graphics-generation-cancellation
                dvc-graphics-pre-share-denial
                post-share-classifier-joined-routes
                post-share-classifier-malformed-and-wrong-role
                post-share-classifier-graphics-dynamic-id-phase
                post-share-classifier-generations-share-disconnect
                cliprdr-pre-share-denial
                dvc-graphics-frame-zero-publication
                dvc-graphics-frame-multifragment-delivery
                dvc-graphics-frame-header-partial-abort
                dvc-graphics-frame-payload-partial-abort
                dvc-graphics-frame-stale-receipt
                dvc-graphics-frame-share-loss-abort
                dvc-graphics-data-malformed-first
                dvc-graphics-data-wrong-channel
                dvc-graphics-data-fragment-ordering
                share-active-exchange-correlation
                share-active-exchange-denials
                share-finalization-exchange-correlation
                share-finalization-exchange-denials)
            rdp_functional_ctest_name(functional_transport_test_name "transport.${case_name}")
            add_test(NAME "${functional_transport_test_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("${functional_transport_test_name}" PROPERTIES
                LABELS "protocol;transport")
        endforeach()
    elseif(test_target STREQUAL "test_owned_preauth_session")
        # Behavior groups from ONE existing executable: no duplicate
        # compilation, executables, state controllers or fixture sources.
        foreach(case_name IN ITEMS
                preauth-session-lifecycle
                mcs-preauth-terminal-revocation
                mcs-preauth-first-envelope-size-bound
                x224-request-fragments
                x224-request-outcomes
                x224-confirm-write-order
                x224-confirm-partial-writes
                tcp-adapter-fragments
                tcp-adapter-backpressure
                tcp-bio-chunk-bounds
                tcp-native-chunk-bounds
                tcp-native-accept-ownership
                tcp-native-accepted-peer-endpoint
                tcp-native-accept-move-replacement
                tcp-native-accept-orderly-eof
                tcp-native-accept-batch-budget-handoff
                tcp-native-accept-batch-stops-denials
                tcp-native-listener-role-and-mode-denials
                tcp-native-wrong-socket-type-denials
                tcp-listener-poll-budget-handoff
                tcp-listener-poll-deadline-denials
                tcp-owned-connection-tls-lifecycle
                tcp-owned-connection-cancellation
                tcp-owned-readiness-dispatch
                tcp-owned-reply-interest-priority
                tcp-owned-deadline-cancellation
                tcp-owned-bounded-poll-loopback-tls
                tcp-owned-bounded-poll-timeout-eof
                tcp-owned-security-negotiation-provenance
                tcp-owned-hybrid-nla-negotiation
                tcp-owned-hybrid-credssp-first-record
                tcp-owned-hybrid-direct-ntlm-first-record
                credssp-owned-transport-generation
                tcp-owned-buffered-tls-credssp-mcs-readiness
                tcp-owned-hybrid-no-premature-mcs
                tcp-owned-hybrid-provenance-revocation
                tcp-owned-tls-application-io
                tcp-owned-tls-application-partial-write
                tcp-owned-r3-connect-response-slice
                tcp-owned-r3-graphics-frame-slice
                tcp-owned-r3-license-request-slice
                tcp-owned-r3-license-request-cancel-replay
                tcp-owned-r3-platform-challenge-slice
                tcp-owned-r3-platform-challenge-cancel-replay
                tcp-owned-r3-client-license-read
                tcp-owned-r3-platform-challenge-response-read
                tcp-owned-tls-terminal-readiness
                tcp-owned-tls-application-cancellation
                tls-nonblocking-handshake
                tls-nonblocking-failures
                tcp-native-loopback-tls
                tcp-native-loopback-close
                tcp-attached-tls-ownership-denials
                tcp-attached-mcs-order-denials
                tls-handshake-gate
                x224-length-and-close
                mcs-decrypted-fragments
                mcs-decrypted-rejections
                mcs-tls-record-fragments
                mcs-tls-record-rejections
                mcs-tls-selected-certificate-continuity
                mcs-tls-selected-certificate-substitution
                credssp-tls-fragments
                credssp-tls-coalesced
                credssp-tls-rejections
                credssp-tls-provenance
                credssp-owned-tls-framing
                credssp-owned-tls-reply
                credssp-tls-certificate-pinning
                credssp-tls-reply-wire
                credssp-tls-reply-backpressure
                credssp-tls-reply-rejections
                credssp-tls-reply-cert-pending
                credssp-tls-reply-cert-completion
                credssp-tls-reply-cert-backpressure
                credssp-tls-failure-reply-wire
                credssp-tls-failure-reply-rejections)
            rdp_functional_ctest_name(functional_transport_test_name "transport.${case_name}")
            add_test(NAME "${functional_transport_test_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("${functional_transport_test_name}" PROPERTIES
                LABELS "protocol;transport")
        endforeach()
        # R1 pre-TLS byte accounting is a focused diagnostic regression.
        # Keep it outside R9's fixed-count generic transport sanitizer
        # inventory until that lane explicitly enrolls this behavior.
        add_test(NAME transport.tcp-owned-pre-tls-transport-byte-accounting
            COMMAND "${test_target}" "tcp-owned-pre-tls-transport-byte-accounting")
        set_tests_properties(
            transport.tcp-owned-pre-tls-transport-byte-accounting
            PROPERTIES LABELS "transport;tls;security;diagnostics;offline"
                       TIMEOUT 20)

        # Dedicated real TLS reader→writer interleaving regression; keep
        # outside R9's fixed-count generic transport sanitizer inventory.
        add_test(NAME transport.tcp-owned-tls-read-want-interleaved-frame-write
            COMMAND "${test_target}" "tcp-owned-tls-read-want-interleaved-frame-write")
        set_tests_properties(
            transport.tcp-owned-tls-read-want-interleaved-frame-write
            PROPERTIES LABELS "transport;tls;security;offline" TIMEOUT 20)
        # Dedicated Direct-NTLM Type-2 delivery receipt regression. Keep it
        # outside R9's fixed-count generic transport sanitizer inventory until
        # that lane explicitly enrolls the new behavior.
        add_test(NAME transport.credssp-direct-ntlm-type2-delivery-receipts
            COMMAND "${test_target}" "credssp-direct-ntlm-type2-delivery-receipts")
        set_tests_properties(
            transport.credssp-direct-ntlm-type2-delivery-receipts
            PROPERTIES
                LABELS "transport;tls;security;credssp;authentication;offline"
                TIMEOUT 20)
        # Fail fast with a NAMED CTest TIMEOUT instead of tying up a
        # Windows worker forever if native connect/backlog handling stalls.
        # Keep both original production assertions intact.
        set_tests_properties(
            transport.tcp-native-accept-orderly-eof
            transport.tcp-native-accept-batch-budget-handoff
            transport.tcp-native-accept-batch-stops-denials
            transport.tcp-native-listener-role-and-mode-denials
            transport.tcp-native-wrong-socket-type-denials
            transport.tcp-listener-poll-budget-handoff
            transport.tcp-listener-poll-deadline-denials
            PROPERTIES TIMEOUT 20)
        # Live server-cert binding and release-time certificate continuity
        # belong to the existing real TLS fixture and remain explicit
        # security contracts rather than transport-only coverage.
        foreach(case_name IN ITEMS
                credssp-active-tls-public-key-length-portability
                credssp-active-tls-binding-positive
                credssp-active-tls-binding-rejections
                credssp-tls-release-certificate-denial)
            rdp_functional_ctest_name(functional_security_test_name "security.${case_name}")
            add_test(NAME "${functional_security_test_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("${functional_security_test_name}" PROPERTIES
                LABELS "protocol;security")
        endforeach()
        # Linux SO_LINGER abortive close exercises the native R1 SSL/BIO
        # connection owner. Do not impose RST delivery semantics on Darwin
        # or Winsock, and do not launch an external listener/service.
        if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
            add_test(NAME "transport.tcp-owned-tls-application-tcp-rst-terminal"
                COMMAND "${test_target}" "tcp-owned-tls-application-tcp-rst-terminal")
            set_tests_properties(
                transport.tcp-owned-tls-application-tcp-rst-terminal
                PROPERTIES LABELS "protocol;transport;native;security"
                           TIMEOUT 20)
        endif()
    elseif(test_target STREQUAL "test_linux_gssapi_spnego")
        foreach(case_name IN ITEMS
                gssapi-configuration-rejections
                gssapi-framed-handoff
                gssapi-console-provenance-before-os-read
                gssapi-native-os-admission-capability-denials
                console-evidence-standalone-native-account-candidate
                gssapi-native-admission-nla-transport-provenance-denials
                gssapi-credssp-delegated-account-origin-denials
                authenticated-principal-proof-gss-compatibility
                gssapi-r3-initial-nla-owner-fence
                gssapi-r3-mcs-admission-contract
                gssapi-r3-protected-transition-generation-fence
                gssapi-r3-connect-response-write-contract
                gssapi-r3-connect-response-completion-reauthorization
                gssapi-r3-erect-domain-contract
                gssapi-r3-attach-user-contract
                gssapi-r3-channel-join-contract
                gssapi-r3-channel-join-terminal-replay-fence
                gssapi-r3-joined-clipboard-role-contract
                gssapi-r3-client-info-route-contract
                gssapi-r3-server-license-request-write-contract
                gssapi-r3-client-licensing-route-contract
                gssapi-r3-server-platform-challenge-write-contract
                gssapi-r3-client-platform-challenge-response-route-contract
                gssapi-r3-attach-user-terminal-replay-fence
                gssapi-r3-protected-transition-terminal-replay-fence
                gssapi-r3-native-change-revocation
                gssapi-r3-mcs-disconnect-revocation-fence)
            rdp_functional_ctest_name(functional_security_test_name "security.${case_name}")
            add_test(NAME "${functional_security_test_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("${functional_security_test_name}" PROPERTIES
                LABELS "security;linux-provider")
        endforeach()
        add_test(NAME security.native-admission-reason-taxonomy-and-positive-fixture
            COMMAND "${test_target}"
                native-admission-reason-taxonomy-and-positive-fixture)
        set_tests_properties(
            security.native-admission-reason-taxonomy-and-positive-fixture
            PROPERTIES LABELS "authentication;admission;consent;security")
    elseif(test_target STREQUAL "test_owned_credssp_tsrequest")
        # Reuse the existing one binary: five previous semantic
        # groups and three new streaming/boundary behaviors.
        foreach(case_name IN ITEMS
                credssp-der-basic
                credssp-der-opaque
                credssp-der-rejections
                credssp-der-bounds
                credssp-der-mutations
                credssp-password-credential-strict-fields
                credssp-password-credential-nested-der-mutations
                credssp-password-credential-length-boundary-denials
                credssp-password-credential-utf16-mutation-boundaries
                credssp-password-field-synchronous-visitor
                credssp-delegated-account-extraction
                credssp-delegated-domain-identity-denials
                credssp-delegated-account-sensitive-retirement
                credssp-delegated-account-adversarial-boundaries
                credssp-stream-fragments
                credssp-stream-coalesced
                credssp-stream-rejections
                credssp-server-reply-wire
                credssp-server-reply-rejections
                credssp-server-failure-wire
                credssp-server-failure-rejections
                credssp-final-negotiation-binding
                credssp-final-binding-rejections)
            rdp_functional_ctest_name(functional_security_test_name "security.${case_name}")
            add_test(NAME "${functional_security_test_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("${functional_security_test_name}" PROPERTIES
                LABELS "protocol;security")
        endforeach()
    elseif(test_target STREQUAL "test_gfx_avc420_segmented_frame")
        foreach(case_name IN ITEMS
                avc420-segmented-frame-single
                avc420-segmented-frame-multipart
                avc420-segmented-frame-denials-reconnect
                avc420-segmented-frame-delivery-ack
                avc420-segmented-frame-unsent-cancellation
                avc420-segmented-frame-owned-output-reuse-denials
                avc420-segmented-frame-retirement-reuse)
            add_test(NAME "graphics.${case_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("graphics.${case_name}" PROPERTIES
                LABELS "protocol;graphics;offline")
        endforeach()
    elseif(test_target STREQUAL "test_gfx_clearcodec_fallback")
        foreach(case_name IN ITEMS
                clearcodec-residual-frame-wire
                clearcodec-capability-fallback
                clearcodec-owned-delivery-recovery
                clearcodec-denials)
            add_test(NAME "graphics.${case_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("graphics.${case_name}" PROPERTIES
                LABELS "protocol;graphics;offline")
        endforeach()
    elseif(test_target STREQUAL "test_gfx_segmented_data")
        foreach(case_name IN ITEMS
                segmented-data-single
                segmented-data-multipart
                segmented-data-denials-inplace
                segmented-data-u32-boundary-denial)
            add_test(NAME "graphics.${case_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("graphics.${case_name}" PROPERTIES
                LABELS "protocol;graphics;offline")
        endforeach()
    elseif(test_target STREQUAL "test_gfx_avc420_picture")
        foreach(case_name IN ITEMS
                avc420-picture-wire
                avc420-zero-frame-id-wire
                avc420-zero-surface-id-wire
                avc420-picture-rejections
                avc420-picture-overlap
                avc420-visible-crop
                avc420-visible-crop-rejections)
            add_test(NAME "graphics.${case_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("graphics.${case_name}" PROPERTIES
                LABELS "protocol;graphics;offline")
        endforeach()
    elseif(test_target STREQUAL "test_gfx_presentation_lifecycle")
        foreach(case_name IN ITEMS
                first-frame-compatibility-contract
                surface-remap-before-first-frame-wire
                channel-lifecycle-ordering
                channel-lifecycle-denials
                surface-resize-revocation
                frame-publication-backpressure
                frame-ack-deferred-revocation-generation-reset
                frame-ack-backpressure-observation
                frame-ack-decode-progress-observation
                frame-delivery-receipt-ordering
                frame-delivery-abort-revocation
                frame-delivery-unsent-cancellation
                frame-delivery-partial-send-remains-terminal
                avc420-mapped-frame-wire
                avc420-mapped-frame-denials
                avc420-mapped-frame-reconnect
                avc420-mapped-padded-picture)
            add_test(NAME "graphics.${case_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("graphics.${case_name}" PROPERTIES
                LABELS "protocol;graphics")
        endforeach()
    elseif(test_target STREQUAL "test_gfx_frame_acknowledge")
        # One production-backed graphics executable, seven behavior CTests.
        foreach(case_name IN ITEMS
                frame-ack-wire
                frame-ack-suspension
                frame-ack-rejections
                frame-ack-correlation
                frame-ack-bounded-backpressure
                frame-ack-decode-progress
                frame-ack-stale-generation)
            add_test(NAME "graphics.${case_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("graphics.${case_name}" PROPERTIES
                LABELS "protocol;graphics")
        endforeach()
    elseif(test_target STREQUAL "test_gfx_avc420_capabilities")
        # Same production-linked executable, four independent wire behaviors.
        foreach(case_name IN ITEMS
                avc420-capabilities-selection
                avc420-capabilities-highest-supported-selection
                avc420-capabilities-rejections
                avc420-capabilities-header-bounds)
            add_test(NAME "graphics.${case_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("graphics.${case_name}" PROPERTIES
                LABELS "protocol;graphics")
        endforeach()
    elseif(test_target STREQUAL "test_gfx_surface_lifecycle")
        foreach(case_name IN ITEMS
                surface-lifecycle-wire
                surface-zero-id-wire
                surface-lifecycle-rejections)
            add_test(NAME "graphics.${case_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("graphics.${case_name}" PROPERTIES
                LABELS "protocol;graphics")
        endforeach()
    elseif(test_target STREQUAL "test_owned_remote_transfer")
        # Preserve the default regression and register the R8 cases.
        add_test(NAME "clipboard.remote-transfer" COMMAND "${test_target}")
        set_tests_properties("clipboard.remote-transfer" PROPERTIES
            LABELS "protocol;clipboard")
        foreach(case_name IN ITEMS
                long-format-list-generation
                short-format-list-negotiation
                format-list-response-native-acceptance
                capabilities-negotiation-format-gating
                capability-format-request-interoperability-matrix
                format-list-response-joined-mcs-envelope
                joined-static-channel-inbound-gates
                r3-channel-retirement-revokes-state
                prefetch-unicode-png-dib-single-flight
                format-data-request-joined-mcs-envelope
                format-data-request-generation-cancellation
                file-descriptor-metadata-validation
                file-lock-unlock-wire-receipts
                file-lock-unlock-partial-send-denials
                file-lock-unlock-generation-retention
                file-contents-locked-stream-identity
                file-lock-capability-prerequisite-denials
                file-contents-size-range-streaming
                file-contents-response-rejections
                file-contents-joined-mcs-envelope
                verified-unicode-text-readiness
                verified-image-readiness
                nonblocking-paste-readiness)
            rdp_functional_ctest_name(functional_clipboard_test_name "clipboard.${case_name}")
            add_test(NAME "${functional_clipboard_test_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("${functional_clipboard_test_name}" PROPERTIES
                LABELS "protocol;clipboard")
        endforeach()
    else()
        add_test(NAME "${suite}.${behavior}" COMMAND "${test_target}")
        set_tests_properties("${suite}.${behavior}" PROPERTIES
            LABELS "protocol;${suite}")
    endif()
endfunction()

add_rdp_test(test_owned_rdp_x224.cpp transport x224)
add_rdp_test(test_owned_security_negotiation.cpp transport security-negotiation)
add_rdp_test(test_owned_mcs_connect_initial.cpp transport mcs-connect-initial)

# R3 canonical production Demand Active profile. These cases are pure offline
# protocol tests and mint no positive R2 admission lease.
add_executable(test_rdp_demand_active_profile
    test_rdp_demand_active_profile.cpp)
target_link_libraries(test_rdp_demand_active_profile PRIVATE
    rdp-server-protocol)
if(MSVC)
    target_compile_options(test_rdp_demand_active_profile PRIVATE /W4 /UNDEBUG)
else()
    target_compile_options(test_rdp_demand_active_profile PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
foreach(case_name IN ITEMS
        exact-wire
        field-consistency
        policy-variants
        count-length-agreement
        stale-unsupported-denials
        immutable-lifetime)
    add_test(NAME "transport.demand-active-profile-${case_name}"
        COMMAND test_rdp_demand_active_profile "${case_name}")
    set_tests_properties(
        "transport.demand-active-profile-${case_name}"
        PROPERTIES LABELS "protocol;demand-active;share;offline")
endforeach()
# R3 production static-VC framing exercised offline, with no R2 OS lease.
add_executable(test_r3_clipboard_static_channel
    test_r3_clipboard_static_channel.cpp)
target_link_libraries(test_r3_clipboard_static_channel PRIVATE
    rdp-server-protocol)
if(MSVC)
    target_compile_options(test_r3_clipboard_static_channel PRIVATE /UNDEBUG)
else()
    target_compile_options(test_r3_clipboard_static_channel PRIVATE -UNDEBUG)
endif()
foreach(case_name IN ITEMS
        fragment-reassembly
        generation-replacement
        wrong-role-compression
        fragment-abort-conditions
        ignored-client-flags
        outbound-write-receipts
        stale-receipt-abort
        terminal-partial-abort)
    add_test(NAME "transport.cliprdr-${case_name}"
        COMMAND test_r3_clipboard_static_channel "${case_name}")
    set_tests_properties("transport.cliprdr-${case_name}" PROPERTIES
        LABELS "protocol;transport;cliprdr;security;offline")
endforeach()

# R8 consumes only R3's authenticated route view, complete-PDU sink and
# receipt view. These cases are fully offline and mint no R2 admission.
add_executable(test_r8_r3_clipboard_bridge
    test_r8_r3_clipboard_bridge.cpp)
target_link_libraries(test_r8_r3_clipboard_bridge PRIVATE
    rdp-server-r8-r3-clipboard)
if(MSVC)
    target_compile_options(test_r8_r3_clipboard_bridge PRIVATE /UNDEBUG)
else()
    target_compile_options(test_r8_r3_clipboard_bridge PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
foreach(case_name IN ITEMS
        server-outbound-capabilities-format-lists
        server-initialization-ordering
        server-initialization-generation-replacement
        server-initialization-pending-write-retirement
        server-local-source-revocation-response-drain
        source-request-receipt
        missing-activated-route-denial
        old-route-generation-retirement
        partial-positive-receipt-retirement
        filecontents-request-receipt)
    add_test(NAME "clipboard.route-bridge-${case_name}"
        COMMAND test_r8_r3_clipboard_bridge "${case_name}")
    set_tests_properties("clipboard.route-bridge-${case_name}" PROPERTIES
        LABELS "protocol;clipboard;lifecycle;security;offline")
endforeach()

# Stable R2-committed scalars require no R3 borrowed span after mutation.
# This ordinary test is outside the fixed 87 clipboard sanitizer selection.
add_test(NAME runtime.clipboard-stable-scalar-write-receipt
    COMMAND test_r8_r3_clipboard_bridge
        stable-scalar-receipt-after-r3-mutation)
set_tests_properties(runtime.clipboard-stable-scalar-write-receipt
    PROPERTIES LABELS "runtime;clipboard;lifecycle;security;offline")

# A delayed old R3 positive receipt may not revoke a reconnected R8 route.
# This ordinary CTest is outside the fixed 87 clipboard sanitizer selection.
add_test(NAME runtime.clipboard-retired-route-positive-receipt-isolation
    COMMAND test_r8_r3_clipboard_bridge
        retired-route-positive-receipt-isolation)
set_tests_properties(runtime.clipboard-retired-route-positive-receipt-isolation
    PROPERTIES LABELS "runtime;clipboard;lifecycle;security;offline")

add_test(NAME runtime.clipboard-repeated-restart-receipt-isolation
    COMMAND test_r8_r3_clipboard_bridge
        repeated-restart-receipt-isolation)
set_tests_properties(runtime.clipboard-repeated-restart-receipt-isolation
    PROPERTIES LABELS "runtime;clipboard;lifecycle;security;offline")

# R3 portable licensing bootstrap: exercise the production no-file generator,
# the normative MS-RDPBCGR X.509 chain shape, and the existing MS-RDPELE
# Server License Request serializer. This target opens no listener and owns no
# R2/native authorization object.
add_executable(test_runtime_licensing_autoprovision
    test_runtime_licensing_autoprovision.cpp)
target_link_libraries(test_runtime_licensing_autoprovision PRIVATE
    rdp-server-runtime-licensing
    rdp-server-runtime-tls
    OpenSSL::Crypto)
if(MSVC)
    target_compile_options(test_runtime_licensing_autoprovision PRIVATE
        /W4 /WX /UNDEBUG)
else()
    target_compile_options(test_runtime_licensing_autoprovision PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
foreach(runtime_licensing_autoprovision_case IN ITEMS
        deterministic-product-identity
        microsoft-x509-chain-shape
        microsoft-temporary-certificate-marker
        server-license-request-generated-identity
        distinct-from-server-tls)
    rdp_functional_ctest_name(functional_licensing_test_name "runtime.licensing-autoprovision-${runtime_licensing_autoprovision_case}")
    add_test(
        NAME "${functional_licensing_test_name}"
        COMMAND test_runtime_licensing_autoprovision
            "${runtime_licensing_autoprovision_case}")
    set_tests_properties(
        "${functional_licensing_test_name}"
        PROPERTIES LABELS "runtime;security;licensing;protocol;offline")
endforeach()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND
   TARGET rdp-server-linux-host-control)
    add_executable(test_linux_runtime_licensing_autoprovision
        test_linux_runtime_licensing_autoprovision.cpp)
    target_link_libraries(test_linux_runtime_licensing_autoprovision PRIVATE
        rdp-server-linux-host-control)
    target_compile_options(test_linux_runtime_licensing_autoprovision PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    add_test(
        NAME runtime.linux-host-control-automatic-licensing-prestart-no-listener
        COMMAND test_linux_runtime_licensing_autoprovision)
    set_tests_properties(
        runtime.linux-host-control-automatic-licensing-prestart-no-listener
        PROPERTIES LABELS "runtime;security;licensing;protocol;linux;offline")
endif()

# R10/R3 test-only composition: reuse the existing ephemeral licensing crypto
# fixture to validate the noninstalled service-lifetime runtime owner.
target_link_libraries(test_owned_mcs_connect_initial PRIVATE
    rdp-server-runtime-licensing)
add_test(NAME runtime.licensing-context-secure-file-snapshots
    COMMAND "${CMAKE_COMMAND}"
        "-DRDP_RUNTIME_LICENSING_TEST=$<TARGET_FILE:test_owned_mcs_connect_initial>"
        "-DRDP_RUNTIME_LICENSING_CASE=licensing-runtime-context-secure-files"
        "-DRDP_RUNTIME_FIXTURE_DIRECTORY=${PROJECT_BINARY_DIR}/runtime-licensing-fixtures"
        -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_licensing_context.cmake")
set_tests_properties(runtime.licensing-context-secure-file-snapshots
    PROPERTIES LABELS "runtime;security;licensing;offline" TIMEOUT 30)
add_test(NAME runtime.licensing-context-replacement-freshness
    COMMAND "${CMAKE_COMMAND}"
        "-DRDP_RUNTIME_LICENSING_TEST=$<TARGET_FILE:test_owned_mcs_connect_initial>"
        "-DRDP_RUNTIME_LICENSING_CASE=licensing-runtime-context-replacement-freshness"
        "-DRDP_RUNTIME_FIXTURE_DIRECTORY=${PROJECT_BINARY_DIR}/runtime-licensing-freshness-fixtures"
        -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_licensing_context.cmake")
set_tests_properties(runtime.licensing-context-replacement-freshness
    PROPERTIES LABELS "runtime;security;licensing;offline" TIMEOUT 30)
add_test(NAME runtime.licensing-context-secure-file-denials
    COMMAND "${CMAKE_COMMAND}"
        "-DRDP_RUNTIME_LICENSING_TEST=$<TARGET_FILE:test_owned_mcs_connect_initial>"
        "-DRDP_RUNTIME_LICENSING_CASE=licensing-runtime-context-secure-file-denials"
        "-DRDP_RUNTIME_FIXTURE_DIRECTORY=${PROJECT_BINARY_DIR}/runtime-licensing-denial-fixtures"
        -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_licensing_context.cmake")
set_tests_properties(runtime.licensing-context-secure-file-denials
    PROPERTIES LABELS "runtime;security;licensing;offline" TIMEOUT 30)
add_rdp_test(test_owned_gcc_conference_create.cpp transport gcc-conference-create)
add_rdp_test(test_owned_preauth_session.cpp transport preauth-session)
# Test-only cross-road composition: R1 remains in the exported protocol target;
# this existing executable additionally consumes R10's noninstalled runtime TLS
# owner and the portable standalone NTLM implementation used by its Type-2
# delivery-receipt fixture. Link the producer directly on every platform rather
# than relying on Linux-only transitive runtime-security composition.
target_link_libraries(test_owned_preauth_session PRIVATE
    rdp-server-runtime-tls
    rdp-server-standalone-ntlmv2)
if(TARGET rdp-server-linux-gssapi)
    # Exercise real TLS -> actual MIT GSSAPI handoff using the existing
    # in-memory TLS fixture; no duplicate certificate/test implementation.
    target_link_libraries(test_owned_preauth_session PRIVATE
        rdp-server-linux-gssapi
        rdp-server-linux-runtime-security)
    target_compile_definitions(test_owned_preauth_session PRIVATE
        RDP_TEST_LINUX_GSSAPI=1)
    if(RDP_SERVER_TEST_REAL_KERBEROS)
        target_compile_definitions(test_owned_preauth_session PRIVATE
            RDP_TEST_REAL_KERBEROS=1)
        foreach(case_name IN ITEMS
                gssapi-real-kerberos-owned-binding
                gssapi-credssp-public-key-not-native-admission
                gssapi-real-kerberos-owned-authinfo-denial
                gssapi-real-kerberos-tls-mechanism
                gssapi-real-kerberos-tls-failure)
            rdp_functional_ctest_name(functional_security_test_name "security.${case_name}")
            add_test(NAME "${functional_security_test_name}"
                COMMAND test_owned_preauth_session "${case_name}")
            set_tests_properties("${functional_security_test_name}"
                PROPERTIES LABELS "security;linux-provider;opt-in-kerberos")
        endforeach()

        # R10 opt-in real-provider composition. Reuse the secure R10 TLS
        # fixture writer and the existing real MIT GSS initiator; no listener,
        # native admission or R3 session is created.
        foreach(runtime_real_kerberos_case IN ITEMS
                linux-connection-real-kerberos-binding
                linux-connection-real-kerberos-binding-not-native-admission
                linux-connection-real-kerberos-authinfo-denial)
            add_test(NAME "runtime.${runtime_real_kerberos_case}"
                COMMAND "${CMAKE_COMMAND}"
                    "-DRDP_RUNTIME_TLS_CONTEXT_TEST=$<TARGET_FILE:test_owned_preauth_session>"
                    "-DRDP_RUNTIME_TLS_CONTEXT_CASE=${runtime_real_kerberos_case}"
                    "-DRDP_RUNTIME_FIXTURE_DIRECTORY=${PROJECT_BINARY_DIR}/runtime-tls-context-fixtures"
                    -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_tls_context.cmake")
            set_tests_properties(
                "runtime.${runtime_real_kerberos_case}"
                PROPERTIES
                    LABELS "runtime;security;linux-provider;opt-in-kerberos"
                    TIMEOUT 30)
        endforeach()
    endif()
    foreach(case_name IN ITEMS
            gssapi-credssp-transport-provenance-fence
            gssapi-binding-delivery-transport-fence
            gssapi-credssp-authinfo-terminal-denials
            gssapi-credssp-transport-cancellation-fence
            gssapi-completed-frame-transport-cancellation-fence
            gssapi-tls-ownership
            gssapi-principal-tls-proof-gate
            gssapi-tls-framed-credential-denials
            gssapi-final-combined-denials
            gssapi-negotiation-reply-gates
            gssapi-failure-reply-denials
            gssapi-binding-reply-gates
            gssapi-reply-order-denials
            gssapi-framed-binding-only-denials
            gssapi-framed-binding-reply-order)
        rdp_functional_ctest_name(functional_security_test_name "security.${case_name}")
        add_test(NAME "${functional_security_test_name}"
            COMMAND test_owned_preauth_session "${case_name}")
        set_tests_properties("${functional_security_test_name}" PROPERTIES
            LABELS "security;linux-provider")
    endforeach()
endif()
add_rdp_test(test_owned_remote_transfer.cpp clipboard remote-transfer)
target_link_libraries(test_owned_remote_transfer PRIVATE
    rdp-server-clipboard-directory-capability)
# R9 bounded mutational wire negative corpus, reusing the production test.
add_test(NAME clipboard.mcs-cliprdr-length-mutation-denials
    COMMAND test_owned_remote_transfer mcs-cliprdr-length-mutation-denials)
set_tests_properties(clipboard.mcs-cliprdr-length-mutation-denials PROPERTIES
    LABELS "protocol;clipboard;security;offline")
# Offline MCS-joined membership/teardown integration, not TLS/OS admission.
add_test(NAME clipboard.mcs-joined-response-teardown
    COMMAND test_owned_remote_transfer mcs-joined-response-teardown)
set_tests_properties(clipboard.mcs-joined-response-teardown PROPERTIES
    LABELS "protocol;clipboard;security;offline")
# A separate fail-closed framing contract, dispatched by the same native test.
add_test(NAME clipboard.remote-transfer-framing-rejections
    COMMAND test_owned_remote_transfer framing-rejections)
set_tests_properties(clipboard.remote-transfer-framing-rejections PROPERTIES
    LABELS "protocol;clipboard;security")
# R8 fixed-capacity, generation-pinned local destination planning. These cases
# reuse the production RemoteTransfer and are centrally registered exactly once.
foreach(case_name IN ITEMS
        file-destination-plan-index-generation
        file-destination-plan-directory-traversal-denials
        file-hierarchy-relative-tree-provenance
        file-hierarchy-provenance-unsupported-denials
        file-hierarchy-parent-cycle-and-depth-denials
        file-hierarchy-generation-replacement
        file-hierarchy-no-path-authority
        file-destination-plan-transactional-commit
        file-destination-plan-cancel-replay
        directory-capability-binding-authority
        directory-capability-binding-retirement)
    rdp_functional_ctest_name(functional_clipboard_test_name "clipboard.${case_name}")
    add_test(NAME "${functional_clipboard_test_name}"
        COMMAND test_owned_remote_transfer "${case_name}")
    set_tests_properties("${functional_clipboard_test_name}" PROPERTIES
        LABELS "protocol;clipboard;security;offline")
endforeach()
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_test(NAME clipboard.linux-directory-capability-native
        COMMAND test_owned_remote_transfer linux-directory-capability-native)
    set_tests_properties(clipboard.linux-directory-capability-native PROPERTIES
        LABELS "protocol;clipboard;security;native;offline")
elseif(APPLE)
    add_test(NAME clipboard.macos-directory-capability-native
        COMMAND test_owned_remote_transfer macos-directory-capability-native)
    set_tests_properties(clipboard.macos-directory-capability-native PROPERTIES
        LABELS "protocol;clipboard;security;native;offline")
elseif(WIN32)
    add_test(NAME clipboard.windows-directory-capability-native
        COMMAND test_owned_remote_transfer windows-directory-capability-native)
    set_tests_properties(clipboard.windows-directory-capability-native PROPERTIES
        LABELS "protocol;clipboard;security;native;offline")
endif()
add_rdp_test(test_clipboard_protocol.cpp clipboard protocol)
# R9 bounded fragmentation, ownership and reset regression; reuse test binary.
add_test(NAME clipboard.chunk-reassembly-reset-bounds
    COMMAND test_clipboard_protocol chunk-reassembly-reset-bounds)
set_tests_properties(clipboard.chunk-reassembly-reset-bounds PROPERTIES
    LABELS "protocol;clipboard;security")
add_test(NAME clipboard.ms-rdpeclip-wire-conformance
    COMMAND test_clipboard_protocol ms-rdpeclip-wire-conformance)
set_tests_properties(clipboard.ms-rdpeclip-wire-conformance PROPERTIES
    LABELS "protocol;clipboard;offline")
add_test(NAME clipboard.wire-codec-mutated-boundaries
    COMMAND test_clipboard_protocol wire-codec-mutated-boundaries)
set_tests_properties(clipboard.wire-codec-mutated-boundaries PROPERTIES
    LABELS "protocol;clipboard;security;offline")
add_rdp_test(test_owned_credssp_binding.cpp security credssp-binding)
add_rdp_test(test_owned_credssp_tsrequest.cpp security credssp-tsrequest)
add_rdp_test(test_console_identity_policy.cpp security console-policy-candidate-matching)
target_link_libraries(test_console_identity_policy PRIVATE
    rdp-server-console-identity-policy)
add_test(NAME security.console-policy-delegated-account-binding
    COMMAND test_console_identity_policy console-policy-delegated-account-binding)
set_tests_properties(security.console-policy-delegated-account-binding
    PROPERTIES LABELS "protocol;security;offline")
add_test(NAME security.console-policy-replacement-revocation
    COMMAND test_console_identity_policy console-policy-replacement-revocation)
set_tests_properties(security.console-policy-replacement-revocation
    PROPERTIES LABELS "protocol;security;credentials;offline")
add_rdp_test(test_base64_codec.cpp security base64-codec)
add_rdp_test(test_gfx_surface_lifecycle.cpp graphics surface-lifecycle)
add_rdp_test(test_gfx_avc420_capabilities.cpp graphics avc420-capabilities)
add_rdp_test(test_gfx_frame_acknowledge.cpp graphics frame-ack-wire)
add_rdp_test(test_gfx_presentation_lifecycle.cpp graphics channel-lifecycle)
add_rdp_test(test_gfx_avc420_picture.cpp graphics avc420-picture)
add_rdp_test(test_gfx_clearcodec_fallback.cpp graphics clearcodec-fallback)
add_rdp_test(test_gfx_segmented_data.cpp graphics segmented-data)
add_rdp_test(test_gfx_avc420_segmented_frame.cpp graphics avc420-segmented-frame)
if(TARGET rdp-server-linux-gssapi)
    add_rdp_test(test_linux_gssapi_spnego.cpp security linux-gssapi)
    target_link_libraries(test_linux_gssapi_spnego PRIVATE
        rdp-server-linux-gssapi)
endif()

if(TARGET rdp-server-linux-pam-password-verifier)
    add_rdp_test(
        test_linux_pam_password_verifier.cpp
        security linux-pam-password-verifier-denials)
    target_link_libraries(test_linux_pam_password_verifier PRIVATE
        rdp-server-linux-pam-password-verifier
        rdp-server-linux-gssapi)
    set_tests_properties(
        security.linux-pam-password-verifier-denials
        PROPERTIES LABELS "security;linux-provider;pam;offline")
    foreach(case_name IN ITEMS
            credssp-pam-password-field-verifier-denials
            gssapi-pam-verifier-binding-denials)
        rdp_functional_ctest_name(functional_security_test_name "security.${case_name}")
        add_test(NAME "${functional_security_test_name}"
            COMMAND test_linux_pam_password_verifier "${case_name}")
        set_tests_properties("${functional_security_test_name}" PROPERTIES
            LABELS "security;linux-provider;pam;offline")
    endforeach()
endif()

if(TARGET rdp-server-linux-runtime-security)
    # Native logind session identity must remain consistent across repeat reads.
    # Pure production predicate test: no live desktop or R2 lease.
    add_executable(test_linux_logind_session_identity
        test_linux_logind_session_identity.cpp)
    target_compile_features(test_linux_logind_session_identity PRIVATE cxx_std_23)
    target_link_libraries(test_linux_logind_session_identity PRIVATE
        rdp-server-linux-runtime-security)
    target_compile_options(test_linux_logind_session_identity PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    add_test(NAME security.linux-seat0-session-identity-denials
        COMMAND test_linux_logind_session_identity seat0-session-identity-denials)
    add_test(NAME runtime.linux-no-config-standalone-current-x11-selection
        COMMAND test_linux_logind_session_identity
            no-config-standalone-current-x11-selection)
    add_test(NAME runtime.linux-logind-monitor-baseline-zero-poll
        COMMAND test_linux_logind_session_identity
            logind-monitor-baseline-zero-poll)
    set_tests_properties(
        security.linux-seat0-session-identity-denials
        runtime.linux-no-config-standalone-current-x11-selection PROPERTIES
        LABELS "security;linux-provider;offline;seat0-revocation;linux;x11;native-desktop;session")
    set_tests_properties(runtime.linux-logind-monitor-baseline-zero-poll PROPERTIES
        LABELS "linux;x11;native-desktop;session;native-environment"
        SKIP_RETURN_CODE 77
        TIMEOUT 15)

    # R2 final-credential security contract: check only GSS-verified account
    # reservation after R2 mapping and before PAM. No real OS admission.
    add_test(NAME security.linux-verified-account-pam-attempt-fence-source
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_R2_FINAL_CREDENTIAL_SOURCE=${PROJECT_SOURCE_DIR}/src/server/security/gssapi_credssp_credentials.cpp"
            "-DRDP_R2_GSS_ACCEPTOR_HEADER=${PROJECT_SOURCE_DIR}/src/server/security/gssapi_spnego_acceptor.h"
            "-DRDP_R2_GSS_ACCEPTOR_SOURCE=${PROJECT_SOURCE_DIR}/src/server/security/gssapi_spnego_acceptor.cpp"
            "-DRDP_R2_LINUX_CONNECTION_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_connection.cpp"
            "-DRDP_R2_LINUX_SERVER_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/main.cpp"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_verified_account_attempt_fence.cmake")
    set_tests_properties(
        security.linux-verified-account-pam-attempt-fence-source
        PROPERTIES LABELS "security;credentials;linux-provider;offline")
    add_executable(test_runtime_io_interest
        test_runtime_io_interest.cpp)
    target_compile_features(test_runtime_io_interest PRIVATE cxx_std_23)
    target_link_libraries(test_runtime_io_interest PRIVATE
        rdp-server-linux-runtime-security)
    target_compile_options(test_runtime_io_interest PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    foreach(runtime_io_interest_case IN ITEMS
            outbound-write-readiness
            outbound-tls-want-precedence
            outbound-cancellation-revocation
            buffered-tls-read-dispatch
            clipboard-outbound-want-precedence
            stalled-graphics-tls-write-bounded-poll
            resize-deadline-bounded-poll)
        add_test(NAME "runtime.linux-connection-${runtime_io_interest_case}"
            COMMAND test_runtime_io_interest "${runtime_io_interest_case}")
        set_tests_properties(
            "runtime.linux-connection-${runtime_io_interest_case}"
            PROPERTIES LABELS "runtime;security;linux-provider;offline")
    endforeach()

    find_path(RDP_SERVER_TEST_KRB5_INCLUDE_DIR NAMES krb5.h REQUIRED)
    find_library(RDP_SERVER_TEST_KRB5_LIBRARY NAMES krb5 REQUIRED)
    find_library(RDP_SERVER_TEST_K5CRYPTO_LIBRARY NAMES k5crypto REQUIRED)
    add_executable(test_runtime_linux_security
        test_runtime_linux_security.cpp)
    target_compile_features(test_runtime_linux_security PRIVATE cxx_std_23)
    target_compile_definitions(test_runtime_linux_security PRIVATE
        "RDP_R3_MICROSOFT_MCS_FIXTURE_PATH=\"${PROJECT_SOURCE_DIR}/tests/fixtures/ms_rdpbcgr_4_1_3_mcs_connect_initial.hex\"")
    target_include_directories(test_runtime_linux_security PRIVATE
        "${RDP_SERVER_TEST_KRB5_INCLUDE_DIR}")
    target_link_libraries(test_runtime_linux_security PRIVATE
        rdp-server-linux-runtime-security
        "${RDP_SERVER_TEST_KRB5_LIBRARY}"
        "${RDP_SERVER_TEST_K5CRYPTO_LIBRARY}")
    target_compile_options(test_runtime_linux_security PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    # R2 exact prepared-owner-epoch denial; exercises the production
    # admission predicate using only injected non-authorizing evidence.
    # No native lease, desktop access, R1 TLS or authenticated principal.
    add_test(NAME security.linux-native-admission-prepared-consent-epoch-denials
        COMMAND test_runtime_linux_security
            linux-native-admission-prepared-consent-epoch-denials
            "${PROJECT_BINARY_DIR}/runtime-linux-security-fixtures")
    set_tests_properties(
        security.linux-native-admission-prepared-consent-epoch-denials
        PROPERTIES LABELS
            "security;owner-consent;linux-provider;native-admission;offline"
            TIMEOUT 20)

    foreach(runtime_linux_security_case IN ITEMS
            linux-security-explicit-keytab-continuity
            linux-security-personal-desktop-preflight-denials
            linux-security-access-policy-replacement-revocation
            linux-security-keytab-snapshot-mutation-continuity
            linux-security-keytab-policy-denials
            linux-security-admission-request-owned-generation-fence
            linux-connection-standalone-authentication-selector-denials
            linux-connection-standalone-authentication-provenance-generation
            linux-connection-credssp-owner-framing
            linux-connection-credssp-progress-accounting
            linux-connection-tls-acceptance-diagnostics
            linux-connection-terminal-transport-classification
            linux-connection-pre-admission-dispatch
            linux-connection-pre-admission-native-poll
            linux-connection-native-poll-expiry-revocation
            linux-connection-pre-admission-mcs-split-tls-revocation-denials
            linux-connection-mcs-pre-admission-tls-coalesced-denials
            linux-connection-post-admission-mcs-framing-denials
            linux-connection-post-admission-mcs-response-denials
            linux-connection-post-admission-erect-domain-denials
            linux-connection-post-admission-attach-user-denials
            linux-connection-post-admission-attach-confirm-write-denials
            linux-connection-post-admission-channel-join-denials
            linux-connection-post-admission-client-info-denials
            linux-connection-client-info-bounded-tpkt-framing
            linux-connection-credssp-revocation-order
            linux-connection-credssp-authorization-denials
            linux-connection-final-credential-native-admission-denials
            linux-connection-aggregate-ordered-revocation
            linux-connection-aggregate-premature-admission-denial
            linux-connection-native-monitor-borrow-denials
            linux-connection-native-monitor-registration-denials
            linux-connection-native-desktop-selection-denials
            linux-connection-personal-licensing-sequence-denials
            linux-connection-personal-desktop-r3-authority-denials
            linux-connection-personal-desktop-slow-path-input-gateway-denials
            linux-connection-personal-desktop-clipboard-gateway-denials
            linux-connection-personal-desktop-policy-receipt-denials
            linux-connection-personal-desktop-graphics-dvc-authority-denials
            linux-connection-personal-license-request-tls-write-denials
            linux-connection-personal-client-licensing-tls-intake-denials
            linux-connection-personal-valid-client-tls-write-denials
            linux-connection-personal-share-tls-io-denials
            linux-connection-personal-graphics-dvc-tls-io-denials
            linux-connection-existing-cal-unadmitted-denial)
        rdp_functional_ctest_name(functional_runtime_security_test_name "runtime.${runtime_linux_security_case}")
        add_test(NAME "${functional_runtime_security_test_name}"
            COMMAND test_runtime_linux_security
                "${runtime_linux_security_case}"
                "${PROJECT_BINARY_DIR}/runtime-linux-security-fixtures")
        set_tests_properties("${functional_runtime_security_test_name}" PROPERTIES
            LABELS "runtime;security;linux-provider;offline")
    endforeach()

    add_test(NAME runtime.tls-attach-independent-of-diagnostic-projection
        COMMAND test_runtime_linux_security
            "tls-attach-independent-of-diagnostic-projection"
            "${PROJECT_BINARY_DIR}/runtime-linux-security-fixtures")
    set_tests_properties(
        runtime.tls-attach-independent-of-diagnostic-projection
        PROPERTIES LABELS "runtime;security;transport;tls;offline")

    # Dedicated production-runtime R2/R3 classifier gateway denial: the
    # existing Linux runtime executable receives no synthetic native lease.
    # Keep this outside R9's fixed 40-case legacy sanitizer selector.
    add_test(NAME runtime.linux-connection-personal-post-share-classifier-authority-denials
        COMMAND test_runtime_linux_security
            "linux-connection-personal-post-share-classifier-authority-denials"
            "${PROJECT_BINARY_DIR}/runtime-linux-security-fixtures")
    set_tests_properties(
        runtime.linux-connection-personal-post-share-classifier-authority-denials
        PROPERTIES LABELS "runtime;security;post-share;offline")

    # One R1 TLS reader plus the already-existing Graphics DVC framing owner;
    # a missing R2 lease prevents both packet dispatch and Graphics ACKs.
    add_test(NAME runtime.linux-connection-personal-post-share-single-reader-denials
        COMMAND test_runtime_linux_security
            "linux-connection-personal-post-share-single-reader-denials"
            "${PROJECT_BINARY_DIR}/runtime-linux-security-fixtures")
    set_tests_properties(
        runtime.linux-connection-personal-post-share-single-reader-denials
        PROPERTIES LABELS "runtime;security;post-share;offline")

    add_test(NAME runtime.linux-connection-graphics-credit-preflight-denials
        COMMAND test_runtime_linux_security
            "linux-connection-graphics-credit-preflight-denials"
            "${PROJECT_BINARY_DIR}/runtime-linux-security-fixtures")
    set_tests_properties(
        runtime.linux-connection-graphics-credit-preflight-denials
        PROPERTIES LABELS "runtime;security;graphics;offline")

    # R10 may request R3 remap only through a live R2 lease. This proves the
    # runtime wrapper cannot fabricate resize authority from geometry alone.
    add_test(NAME runtime.linux-connection-graphics-surface-remap-denials
        COMMAND test_runtime_linux_security
            "linux-connection-graphics-surface-remap-denials"
            "${PROJECT_BINARY_DIR}/runtime-linux-security-fixtures")
    set_tests_properties(
        runtime.linux-connection-graphics-surface-remap-denials
        PROPERTIES LABELS "runtime;security;resize;offline")

    # R8 outbound clipboard must borrow the current R3 write and complete
    # its accepted-byte receipt through the sole R1 TLS owner. An absent
    # R2 lease forbids either writable or delayed plaintext publication.
    # Keep this distinct from the fixed 87 clipboard sanitizer inventory.
    add_test(NAME runtime.linux-connection-personal-clipboard-tls-write-denials
        COMMAND test_runtime_linux_security
            "linux-connection-personal-clipboard-tls-write-denials"
            "${PROJECT_BINARY_DIR}/runtime-linux-security-fixtures")
    set_tests_properties(
        runtime.linux-connection-personal-clipboard-tls-write-denials
        PROPERTIES LABELS "runtime;clipboard;lifecycle;security;offline")

    # A Linux signal only requests Stop; R1/R2/R3/R5 teardown is serialized.
    # This inspects production code offline without signals or live admission.
    add_test(NAME runtime.linux-serve-cooperative-signal-stop-order
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_RUNTIME_ENTRYPOINT_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/main.cpp"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_linux_cooperative_stop.cmake")
    set_tests_properties(runtime.linux-serve-cooperative-signal-stop-order
        PROPERTIES LABELS "runtime;security;stop;offline")

    # R3 containment: no protocol bytes are changed. Pin the production
    # TLS -> CredSSP CredentialsVerified -> successful native R2 admission ->
    # first-MCS handoff, and prove Stop destroys the accepted connection/MCS
    # owner before R1 listener teardown. The already-qualified
    # Start->Stop->Start credential lifecycle remains independent of this R3
    # boundary gate.
    add_test(NAME runtime.linux-host-control-stop-retires-protocol-session-state
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_LINUX_HOST_CONTROL_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_host_control.cpp"
            "-DRDP_LINUX_CONNECTION_HEADER=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_connection.h"
            "-DRDP_LINUX_CONNECTION_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_connection.cpp"
            "-DRDP_MCS_SESSION_HEADER=${PROJECT_SOURCE_DIR}/src/server/transport/mcs_channel_connection.h"
            "-DRDP_MCS_SESSION_SOURCE=${PROJECT_SOURCE_DIR}/src/server/transport/mcs_channel_connection.cpp"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_r3_tls_gate_stop_freshness.cmake")
    set_tests_properties(
        runtime.linux-host-control-stop-retires-protocol-session-state PROPERTIES
        LABELS "runtime;security;mcs;stop;offline")

    # Real production runtime owner contract, with no synthetic positive R2
    # admission, physical X11 host or auto-start. Source guards complement
    # the executable-backed missing-lease and R1 I/O tests above.
    add_test(NAME runtime.linux-serve-persistent-post-share-single-owner
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_RUNTIME_ENTRYPOINT_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/main.cpp"
            "-DRDP_RUNTIME_CONNECTION_HEADER=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_connection.h"
            "-DRDP_RUNTIME_CONNECTION_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_connection.cpp"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_linux_post_share_persistent.cmake")
    set_tests_properties(runtime.linux-serve-persistent-post-share-single-owner
        PROPERTIES LABELS "runtime;security;post-share;offline")

    # R10 must compose the real post-STATUS_VALID_CLIENT Share owner without
    # fabricating a positive OS lease in ordinary CI. The production R3 profile
    # must derive admitted Client Core geometry and R10 may supply only feature
    # bits before the existing serialized Share state machine is driven.
    add_test(NAME runtime.linux-serve-share-activation-composition
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_RUNTIME_ENTRYPOINT_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/main.cpp"
            "-DRDP_MCS_SESSION_SOURCE=${PROJECT_SOURCE_DIR}/src/server/transport/mcs_channel_connection.cpp"
            "-DRDP_RUNTIME_CONNECTION_HEADER=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_connection.h"
            "-DRDP_RUNTIME_CONNECTION_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_connection.cpp"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_linux_share_activation.cmake")
    set_tests_properties(
        runtime.linux-serve-share-activation-composition PROPERTIES
        LABELS "runtime;security;share;offline")

    # R10 post-Share Graphics control composition is source-guarded offline:
    # ordinary CI must not fabricate a positive R2 lease, native desktop or
    # R4 frame merely to prove DRDYNVC CREATE/CAPS scheduling.
    add_test(NAME runtime.linux-serve-graphics-dvc-composition
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_RUNTIME_ENTRYPOINT_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/main.cpp"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_linux_graphics_dvc.cmake")
    set_tests_properties(
        runtime.linux-serve-graphics-dvc-composition PROPERTIES
        LABELS "runtime;security;graphics;offline")

    # R10's live native owner is reachable only behind genuine R2 admission,
    # so ordinary CI source-guards production composition rather than
    # fabricating a Kerberos/PAM/logind lease or touching a real X11 desktop.
    add_test(NAME runtime.linux-serve-authorized-x11-owner-composition
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_RUNTIME_ENTRYPOINT_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/main.cpp"
            "-DRDP_ROOT_CMAKE=${PROJECT_SOURCE_DIR}/CMakeLists.txt"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_linux_native_owner.cmake")
    set_tests_properties(
        runtime.linux-serve-authorized-x11-owner-composition PROPERTIES
        LABELS "runtime;security;native;linux;x11;native-desktop;session;offline")

    # The R5 aggregate's terminal XCB/XShm/input failure cleanup must not
    # post held-key/button releases; the Xvfb native controller fixture
    # separately exercises actual no-XTEST retirement.
    add_test(NAME x11.input-native-failure-terminal-retirement-no-xtest
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_R5_NATIVE_HEADER=${PROJECT_SOURCE_DIR}/src/x11/x11_desktop_resources.h"
            "-DRDP_R5_NATIVE_SOURCE=${PROJECT_SOURCE_DIR}/src/x11/x11_desktop_resources.cpp"
            -P "${PROJECT_SOURCE_DIR}/tests/check_x11_native_failure_no_input.cmake")
    set_tests_properties(
        x11.input-native-failure-terminal-retirement-no-xtest
        PROPERTIES LABELS "x11;linux-adapter;security;offline;terminal")

    # R5 follows the single R10 R2-selected XCB owner. The production
    # post-Share scheduler must retire its borrowed logind watch before
    # native drain, refresh R2 authority and borrow the first XShm frame
    # synchronously while R1 owns all TLS application reads.
    add_test(NAME runtime.linux-x11-authorized-event-service-denials
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_RUNTIME_ENTRYPOINT_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/main.cpp"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_linux_x11_event_service.cmake")
    add_test(NAME runtime.linux-persistent-x11-input-frame-borrow-order
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_RUNTIME_ENTRYPOINT_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/main.cpp"
            "-DRDP_R5_PERSISTENT_FRAME_GATE=ON"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_linux_x11_event_service.cmake")
    set_tests_properties(
        runtime.linux-x11-authorized-event-service-denials
        runtime.linux-persistent-x11-input-frame-borrow-order PROPERTIES
        LABELS "runtime;security;native;x11;offline")

    # R2 post-admission TLS reads must fence the current R3 admission/session
    # generations as well as the live lease/native evidence. This source-level
    # guard is intentionally offline because ordinary CI must not fabricate a
    # positive Kerberos/PAM/logind admission lease.
    add_test(NAME runtime.linux-connection-protected-read-generation-denials
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_RUNTIME_CONNECTION_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_connection.cpp"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_linux_protected_read_generation.cmake")
    set_tests_properties(
        runtime.linux-connection-protected-read-generation-denials PROPERTIES
        LABELS "runtime;security;linux-provider;offline")

    if(TARGET rdp-server-linux-pam-password-verifier)
        add_test(NAME runtime.linux-connection-verified-account-attempt-limiter-binding-denials
            COMMAND test_runtime_linux_security
                linux-connection-verified-account-attempt-limiter-binding-denials
                "${PROJECT_BINARY_DIR}/runtime-linux-security-fixtures")
        set_tests_properties(
            runtime.linux-connection-verified-account-attempt-limiter-binding-denials
            PROPERTIES LABELS "runtime;security;linux-provider;pam;offline")

        add_test(NAME runtime.linux-security-pam-verifier-provisioning
            COMMAND test_runtime_linux_security
                linux-security-pam-verifier-provisioning
                "${PROJECT_BINARY_DIR}/runtime-linux-security-fixtures")
        set_tests_properties(
            runtime.linux-security-pam-verifier-provisioning PROPERTIES
            LABELS "runtime;security;linux-provider;pam;offline")
    endif()

    set(runtime_linux_process_cases
        validates-linux-security-provisioning
        rejects-linux-security-missing-provisioning
        rejects-linux-serve-missing-security
        rejects-linux-serve-nonserialized-budget
        rejects-linux-serve-wildcard-address)
    set(runtime_linux_pam_process_argument)
    if(TARGET rdp-server-linux-pam-password-verifier)
        list(APPEND runtime_linux_process_cases
            rejects-linux-security-missing-pam-service
            rejects-linux-security-invalid-pam-service
            rejects-linux-security-password-config
            rejects-linux-security-authorization-result-config)
        set(runtime_linux_pam_process_argument
            "-DRDP_RUNTIME_HAVE_LINUX_PAM=ON")
    endif()
    foreach(runtime_linux_process_case IN LISTS runtime_linux_process_cases)
        add_test(NAME "runtime.${runtime_linux_process_case}"
            COMMAND "${CMAKE_COMMAND}"
                "-DRDP_RUNTIME_EXECUTABLE=$<TARGET_FILE:rdp-server>"
                "-DRDP_RUNTIME_VERSION=${PROJECT_VERSION}"
                "-DRDP_RUNTIME_TEST_CASE=${runtime_linux_process_case}"
                "-DRDP_RUNTIME_FIXTURE_DIRECTORY=${PROJECT_BINARY_DIR}/runtime-fixtures"
                "-DRDP_RUNTIME_LINUX_SECURITY_HELPER=$<TARGET_FILE:test_runtime_linux_security>"
                ${runtime_linux_pam_process_argument}
                -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_entrypoint.cmake")
        set_tests_properties(
            "runtime.${runtime_linux_process_case}"
            PROPERTIES LABELS "runtime;security;linux-provider;offline")
    endforeach()
endif()

# R10 administrator-facing licensing provisioning. These process-level cases
# execute the real non-listening rdp-server and reuse the existing R3 fixture
# generator; no separate licensing test executable or credential policy exists.
set(runtime_licensing_cli_arguments
    "-DRDP_RUNTIME_EXECUTABLE=$<TARGET_FILE:rdp-server>"
    "-DRDP_RUNTIME_VERSION=${PROJECT_VERSION}"
    "-DRDP_RUNTIME_LICENSING_HELPER=$<TARGET_FILE:test_owned_mcs_connect_initial>")
if(TARGET test_runtime_linux_security)
    list(APPEND runtime_licensing_cli_arguments
        "-DRDP_RUNTIME_LINUX_SECURITY_HELPER=$<TARGET_FILE:test_runtime_linux_security>")
    if(TARGET rdp-server-linux-pam-password-verifier)
        list(APPEND runtime_licensing_cli_arguments
            "-DRDP_RUNTIME_HAVE_LINUX_PAM=ON")
    endif()
endif()
foreach(runtime_licensing_cli_case IN ITEMS
        licensing-cli-valid-provisioning
        licensing-cli-incomplete-configuration
        licensing-cli-invalid-product-identity
        licensing-cli-credential-file-denials
        licensing-cli-existing-check-compatibility
        licensing-cli-service-still-disabled)
    add_test(NAME "runtime.${runtime_licensing_cli_case}"
        COMMAND "${CMAKE_COMMAND}"
            ${runtime_licensing_cli_arguments}
            "-DRDP_RUNTIME_TEST_CASE=${runtime_licensing_cli_case}"
            "-DRDP_RUNTIME_FIXTURE_DIRECTORY=${PROJECT_BINARY_DIR}/runtime-licensing-cli-fixtures/${runtime_licensing_cli_case}"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_entrypoint.cmake")
    set_tests_properties("runtime.${runtime_licensing_cli_case}"
        PROPERTIES LABELS "runtime;security;licensing;offline" TIMEOUT 60)
endforeach()

# Public-header lifetime regression: this consumer intentionally does not
# include runtime_licensing_authority_internal.h. Construction/destruction must
# remain valid while the provider implementation type is only forward-declared.
add_executable(test_runtime_licensing_authority_public_header
    test_runtime_licensing_authority_public_header.cpp)
target_link_libraries(test_runtime_licensing_authority_public_header PRIVATE
    rdp-server-runtime-licensing)
if(MSVC)
    target_compile_options(test_runtime_licensing_authority_public_header PRIVATE
        /W4 /UNDEBUG)
else()
    target_compile_options(test_runtime_licensing_authority_public_header PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
add_test(NAME runtime.licensing-authority-public-header-consumer-lifetime
    COMMAND test_runtime_licensing_authority_public_header)
set_tests_properties(
    runtime.licensing-authority-public-header-consumer-lifetime PROPERTIES
    LABELS "runtime;security;licensing;offline")

# R10 immutable product mode with explicit loopback/private-LAN candidate gates.
# These cases exercise production policy code only; no socket is opened and no
# R2/R3 positive authority is synthesized.
add_executable(test_runtime_deployment_policy
    test_runtime_deployment_policy.cpp)
target_link_libraries(test_runtime_deployment_policy PRIVATE
    rdp-server-runtime-licensing)
if(MSVC)
    target_compile_options(test_runtime_deployment_policy PRIVATE /W4 /UNDEBUG)
else()
    target_compile_options(test_runtime_deployment_policy PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
foreach(runtime_deployment_policy_case IN ITEMS
        personal-desktop-policy-immutable-denials
        personal-desktop-loopback-listener-denials
        personal-desktop-private-lan-candidate-denials)
    add_test(NAME "runtime.${runtime_deployment_policy_case}"
        COMMAND test_runtime_deployment_policy
            "${runtime_deployment_policy_case}")
    set_tests_properties(
        "runtime.${runtime_deployment_policy_case}" PROPERTIES
        LABELS "runtime;security;licensing;service-policy;offline")
endforeach()

# R10 service-owned licensing-authority lifecycle. The production runtime
# exposes no positive provider configuration; this executable owns the sole
# deterministic positive provider fixture and is never installed or linked
# into rdp-server.
add_executable(test_runtime_licensing_authority
    test_runtime_licensing_authority.cpp)
target_link_libraries(test_runtime_licensing_authority PRIVATE
    rdp-server-runtime-licensing)
if(MSVC)
    target_compile_options(test_runtime_licensing_authority PRIVATE
        /W4 /UNDEBUG)
else()
    target_compile_options(test_runtime_licensing_authority PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
foreach(runtime_licensing_authority_case IN ITEMS
        licensing-authority-unconfigured-denials
        licensing-authority-issuer-policy-correlation
        licensing-authority-generation-revocation
        licensing-authority-result-bounds-and-cancellation
        licensing-authority-sensitive-retirement)
    add_test(NAME "runtime.${runtime_licensing_authority_case}"
        COMMAND test_runtime_licensing_authority
            "${runtime_licensing_authority_case}")
    set_tests_properties(
        "runtime.${runtime_licensing_authority_case}" PROPERTIES
        LABELS "runtime;security;licensing;offline")
endforeach()

# Existing-client CAL validation is a separate R10 provider operation. Positive
# decisions in these cases come only from the noninstalled provider fixture in
# test_runtime_licensing_authority; production configureUnavailable() remains
# incapable of producing a positive decision.
foreach(runtime_existing_cal_case IN ITEMS
        licensing-existing-cal-provider-unavailable
        licensing-existing-cal-request-correlation
        licensing-existing-cal-policy-generation-revocation
        licensing-existing-cal-result-retirement
        licensing-existing-cal-connection-unavailable-denial
        licensing-existing-cal-connection-cross-generation-cancellation)
    add_test(NAME "runtime.${runtime_existing_cal_case}"
        COMMAND test_runtime_licensing_authority
            "${runtime_existing_cal_case}")
    set_tests_properties(
        "runtime.${runtime_existing_cal_case}" PROPERTIES
        LABELS "runtime;security;licensing;offline")
endforeach()

# Exercise the real process separately so the test-only provider cannot become
# a startup path. This meta-case reuses the existing process checker for every
# supported offline preflight plus normal/wrong-argument startup refusal.
add_test(NAME runtime.licensing-authority-no-startup-bypass
    COMMAND "${CMAKE_COMMAND}"
        ${runtime_licensing_cli_arguments}
        "-DRDP_RUNTIME_TEST_CASE=licensing-authority-no-startup-bypass"
        "-DRDP_RUNTIME_FIXTURE_DIRECTORY=${PROJECT_BINARY_DIR}/runtime-licensing-authority-startup-fixtures"
        -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_entrypoint.cmake")
set_tests_properties(runtime.licensing-authority-no-startup-bypass PROPERTIES
    LABELS "runtime;security;licensing;offline" TIMEOUT 60)

# R2 Windows native-session evidence. The production reader is exercised on
# the actual hosted Windows process/WTS/LSA context, but the test never treats
# an observed SID/session as authenticated RDP admission.
if(TARGET rdp-server-windows-native-session-evidence)
    add_executable(test_windows_native_session_evidence
        test_windows_native_session_evidence.cpp)
    target_link_libraries(test_windows_native_session_evidence PRIVATE
        rdp-server-windows-native-session-evidence)
    if(MSVC)
        target_compile_options(
            test_windows_native_session_evidence PRIVATE /W4 /UNDEBUG)
    else()
        target_compile_options(
            test_windows_native_session_evidence PRIVATE
            -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    endif()
    add_test(NAME security.windows-native-session-evidence-provider-denials
        COMMAND test_windows_native_session_evidence)
    set_tests_properties(
        security.windows-native-session-evidence-provider-denials PROPERTIES
        LABELS "security;native-admission;windows;offline")

    # R6/R2 negative-only candidate identity: a reused numeric WTS ID cannot
    # conceal a different LSA authentication LUID or logon time.
    add_test(NAME security.windows-native-session-reused-id-luid-logon-denials
        COMMAND test_windows_native_session_evidence reused-session-id-denials)
    set_tests_properties(
        security.windows-native-session-reused-id-luid-logon-denials PROPERTIES
        LABELS "security;native-admission;windows;offline")
endif()

# R2 accepted-SSPI authenticated identity proof. The positive offline case
# adopts only the current process token through a private test friend to test
# bounded SID extraction and generation/revocation; production can bind only
# through QuerySecurityContextToken on an accepted SSPI context.
if(TARGET rdp-server-windows-authenticated-identity)
    add_executable(test_windows_authenticated_identity
        test_windows_authenticated_identity.cpp)
    target_link_libraries(test_windows_authenticated_identity PRIVATE
        rdp-server-windows-authenticated-identity)
    if(MSVC)
        target_compile_options(
            test_windows_authenticated_identity PRIVATE /W4 /WX /UNDEBUG)
    else()
        target_compile_options(
            test_windows_authenticated_identity PRIVATE
            -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    endif()
    foreach(case_name IN ITEMS
            sspi-context-denials
            process-token-generation-lifecycle)
        add_test(NAME "security.windows-authenticated-identity-${case_name}"
            COMMAND test_windows_authenticated_identity "${case_name}")
        set_tests_properties(
            "security.windows-authenticated-identity-${case_name}" PROPERTIES
            LABELS "security;native-authorization;windows;sspi;offline"
            TIMEOUT 15)
    endforeach()
endif()

# R6 fixture-only checks: do not enumerate a real desktop, capture pixels,
# or inject input during an ordinary Windows CTest run.
if(TARGET rdp-server-windows-desktop)
    add_executable(test_windows_desktop_geometry
        test_windows_desktop_geometry.cpp
        windows_geometry_gdi_type_probe.cpp
        windows_capture_cycle_cases.cpp
        windows_capture_damage_cases.cpp
        windows_capture_session_guard_cases.cpp
        windows_native_desktop_owner_cases.cpp
        windows_r4_handoff_cases.cpp
        windows_dxgi_duplication_owner_cases.cpp
        windows_dxgi_pointer_shape_cases.cpp
        windows_input_controller_cases.cpp
        windows_cursor_snapshot_cases.cpp
        windows_rdp_conflict_cases.cpp)
    target_link_libraries(test_windows_desktop_geometry PRIVATE
        rdp-server-windows-desktop
        rdp-server-native-desktop-authorization
        rdp-server-graphics)
    if(MSVC)
        target_compile_options(test_windows_desktop_geometry PRIVATE /UNDEBUG)
    else()
        target_compile_options(test_windows_desktop_geometry PRIVATE -UNDEBUG)
    endif()
    foreach(case_name IN ITEMS
            single-monitor-native-target-selection
            negative-origin-and-monitor-gaps
            invalid-layout-rejections
            order-stable-reconfiguration
            capture-bgra-stride-and-pixel-order
            capture-bgra-invalid-frame-denials)
        add_test(NAME "windows.geometry-${case_name}"
            COMMAND test_windows_desktop_geometry "${case_name}")
        set_tests_properties("windows.geometry-${case_name}" PROPERTIES
            LABELS "windows;desktop-geometry;offline")
    endforeach()
    # Regression for the WinGDI Rectangle function hiding our portable type.
    add_test(NAME windows.geometry-gdi-rectangle-name-resolution
        COMMAND test_windows_desktop_geometry win32-gdi-rectangle-name-resolution)
    set_tests_properties(windows.geometry-gdi-rectangle-name-resolution
        PROPERTIES LABELS "windows;desktop-geometry;offline")
    # Native DXGI duplication owner, using synthetic COM references only.
    foreach(case_name IN ITEMS
            dxgi-duplication-owner-lifecycle
            dxgi-duplication-owner-selection-denials
            dxgi-duplication-owner-same-adapter-ambiguity
            dxgi-duplication-owner-repeated-adapter-reference
            dxgi-duplication-owner-repeated-output-reference
            dxgi-duplication-owner-capture-cycle-single-attach
            dxgi-duplication-owner-capture-cycle-layout-denials
            dxgi-duplication-owner-epoch-revocation
            dxgi-duplication-owner-release-reentry
            dxgi-duplication-owner-open-cancel-reentry
            dxgi-duplication-owner-partial-result-cleanup
            dxgi-duplication-owner-ambiguous-reentry
            dxgi-duplication-owner-child-close-order)
        add_test(NAME "windows.capture-${case_name}"
            COMMAND test_windows_desktop_geometry "${case_name}")
        set_tests_properties("windows.capture-${case_name}" PROPERTIES
            LABELS "windows;desktop-capture;security;offline")
    endforeach()
    # R6 native duplication frame-lease RAII: synthetic callbacks only, no
    # AcquireNextFrame on an actual Windows desktop during ordinary tests.
    foreach(case_name IN ITEMS
            dxgi-frame-lease-lifecycle
            dxgi-frame-lease-acquire-callback-revocation
            dxgi-frame-lease-rejections)
        add_test(NAME "windows.capture-${case_name}"
            COMMAND test_windows_desktop_geometry "${case_name}")
        set_tests_properties("windows.capture-${case_name}" PROPERTIES
            LABELS "windows;desktop-capture;offline")
    endforeach()
    # R6 D3D11 staging frame/map RAII, injected callbacks only.
    foreach(case_name IN ITEMS
            d3d11-staging-bgra-map-lifetime
            d3d11-staging-map-denials)
        add_test(NAME "windows.capture-${case_name}"
            COMMAND test_windows_desktop_geometry "${case_name}")
        set_tests_properties("windows.capture-${case_name}" PROPERTIES
            LABELS "windows;desktop-capture;offline")
    endforeach()
    # R6 capture-cycle ordering; synthetic callbacks, no desktop access.
    add_test(NAME windows.capture-frame-ordered-lifetime
        COMMAND test_windows_desktop_geometry capture-cycle-ordered-lifetime)
    add_test(NAME windows.capture-frame-cancel-and-topology-rejections
        COMMAND test_windows_desktop_geometry capture-cycle-cancel-and-topology-rejections)
    add_test(NAME windows.capture-frame-release-callback-revocation
        COMMAND test_windows_desktop_geometry capture-cycle-release-callback-revocation)
    set_tests_properties(
        windows.capture-frame-ordered-lifetime
        windows.capture-frame-cancel-and-topology-rejections
        windows.capture-frame-release-callback-revocation
        PROPERTIES LABELS "windows;desktop-capture;offline")
    # Scoped synchronous consumption never leaves a DXGI lease or staging map
    # live after returning, including cancellation and sink rejection.
    foreach(case_name IN ITEMS
            capture-cycle-synchronous-consume-lifetime
            capture-cycle-synchronous-consume-denials
            capture-cycle-invalid-consumer-release-revocation)
        add_test(NAME "windows.capture-${case_name}"
            COMMAND test_windows_desktop_geometry "${case_name}")
        set_tests_properties("windows.capture-${case_name}" PROPERTIES
            LABELS "windows;desktop-capture;offline")
    endforeach()
    # R6 independent caller-owned BGRA snapshot, using the existing cycle
    # and one synchronous copy before native unmap/duplication release.
    foreach(case_name IN ITEMS
            capture-packed-copy-lifetime
            capture-packed-copy-denials)
        add_test(NAME "windows.${case_name}"
            COMMAND test_windows_desktop_geometry "${case_name}")
        set_tests_properties("windows.${case_name}" PROPERTIES
            LABELS "windows;desktop-capture;offline")
    endforeach()
    # R6 -> R4 native BGRA borrow contract. The real R4 converter is linked
    # only into this existing fixture; production R6 retains no R4 dependency.
    foreach(case_name IN ITEMS
            bgra-layout-contract
            frame-lifetime-revocation
            monitor-replacement-denials)
        add_test(NAME "windows.capture-${case_name}"
            COMMAND test_windows_desktop_geometry "r4-${case_name}")
        set_tests_properties("windows.capture-${case_name}" PROPERTIES
            LABELS "windows;desktop-capture;graphics;security;offline")
    endforeach()
    # One bounded native frame metadata reader; synthetic tests never access DXGI.
    foreach(case_name IN ITEMS
            dxgi-native-damage-map-lifetime
            dxgi-native-damage-denials)
        add_test(NAME "windows.capture-${case_name}"
            COMMAND test_windows_desktop_geometry "${case_name}")
        set_tests_properties("windows.capture-${case_name}" PROPERTIES
            LABELS "windows;desktop-capture;offline")
    endforeach()
    # Revocation-only session/device generation observations. Synthetic
    # sources cannot grant R2/R3 OS admission or access a real desktop.
    foreach(case_name IN ITEMS
            capture-generation-pinned-frame-lifetime
            capture-generation-revocation-denials)
        add_test(NAME "windows.${case_name}"
            COMMAND test_windows_desktop_geometry "${case_name}")
        set_tests_properties("windows.${case_name}" PROPERTIES
            LABELS "windows;desktop-capture;offline")
    endforeach()
    # R6 target-session revocation guard and session-change event sink.
    # Synthetic observations only: no CTest queries or changes a real session.
    foreach(case_name IN ITEMS
            capture-session-generation-active-lifetime
            capture-session-revocation-denials
            capture-session-change-revocation
            capture-session-change-denials)
        add_test(NAME "windows.${case_name}"
            COMMAND test_windows_desktop_geometry "${case_name}")
        set_tests_properties("windows.${case_name}" PROPERTIES
            LABELS "windows;desktop-capture;security;offline")
    endforeach()
    # R6 cross-component native session retirement. These use the real guard,
    # capture cycle and input controller with injected callbacks only.
    add_test(NAME windows.capture-session-change-coordinated-input-revocation
        COMMAND test_windows_desktop_geometry
            capture-session-change-coordinated-input-revocation)
    add_test(NAME windows.capture-session-change-callback-revocation
        COMMAND test_windows_desktop_geometry
            capture-session-change-callback-revocation)
    add_test(NAME windows.input-session-change-held-state-retirement
        COMMAND test_windows_desktop_geometry
            input-session-change-held-state-retirement)
    set_tests_properties(
        windows.capture-session-change-coordinated-input-revocation
        windows.capture-session-change-callback-revocation
        windows.input-session-change-held-state-retirement
        PROPERTIES
            LABELS "windows;desktop-capture;desktop-input;security;offline"
            TIMEOUT 20)
    # Whole-owner R6 retirement: production parent/cycle/input/guard objects
    # with injected callbacks only; no live DXGI desktop or host SendInput.
    foreach(case_name IN ITEMS
            capture-session-change-duplication-owner-retirement
            capture-session-change-duplication-release-order
            capture-session-change-duplication-callback-retirement
            capture-session-change-duplication-prior-revocation)
        add_test(NAME "windows.${case_name}"
            COMMAND test_windows_desktop_geometry "${case_name}")
        set_tests_properties("windows.${case_name}" PROPERTIES
            LABELS "windows;desktop-capture;desktop-input;security;offline"
            TIMEOUT 20)
    endforeach()
    # R6 DXGI pointer position/shape ownership. Synthetic callbacks exercise
    # the same acquired-frame/generation path; no CTest captures a live cursor.
    foreach(case_name IN ITEMS
            cursor-dxgi-shape-owned-lifetime
            cursor-dxgi-shape-generation-denials)
        add_test(NAME "windows.${case_name}"
            COMMAND test_windows_desktop_geometry "${case_name}")
        set_tests_properties("windows.${case_name}" PROPERTIES
            LABELS "windows;desktop-cursor;desktop-capture;security;offline")
    endforeach()
    # Keep this deterministic denial suite bounded under the owner's plain
    # CTest command even if MSVC debug assertion handling waits interactively.
    set_tests_properties(windows.cursor-dxgi-shape-generation-denials
        PROPERTIES TIMEOUT 20)
    # R6 generation-pinned SendInput controller. Synthetic callbacks exercise
    # command/state logic only; ordinary CTest never injects host input.
    foreach(case_name IN ITEMS
            sendinput-lifecycle
            sendinput-revocation-denials
            sendinput-authority-retirement-no-native-post)
        add_test(NAME "windows.input-${case_name}"
            COMMAND test_windows_desktop_geometry "${case_name}")
        set_tests_properties("windows.input-${case_name}" PROPERTIES
            LABELS "windows;desktop-input;security;offline")
    endforeach()
    # R6 read-only RDP host-conflict preflight. Synthetic classifier cases
    # plus one production observation; no listener bind or OS mutation.
    foreach(case_name IN ITEMS
            rdp-termservice-active-conflict-denial
            rdp-requested-port-occupied-conflict-denial
            rdp-observation-unavailable-denial
            rdp-clear-when-service-stopped-port-free
            rdp-native-readonly-observation)
        add_test(NAME "windows.host-preflight-${case_name}"
            COMMAND test_windows_desktop_geometry "${case_name}")
        set_tests_properties("windows.host-preflight-${case_name}" PROPERTIES
            LABELS "windows;host-preflight;security;offline" TIMEOUT 20)
    endforeach()

    # R6 aggregate native-owner denial boundary. It uses the real R2
    # authorization object only in an unbound/deny-only state and performs no
    # live WTS/DXGI/cursor read or SendInput.
    add_test(NAME windows.native-owner-grant-and-lifetime-denials
        COMMAND test_windows_desktop_geometry native-owner-r2-grant-and-lifetime-denials)
    set_tests_properties(
        windows.native-owner-grant-and-lifetime-denials PROPERTIES
        LABELS "windows;native-owner;security;offline" TIMEOUT 20)

    add_test(NAME windows.native-owner-authorized-offline-lifecycle
        COMMAND test_windows_desktop_geometry
            native-owner-r2-authorized-offline-lifecycle)
    add_test(NAME windows.native-owner-authorized-view-only-offline-lifecycle
        COMMAND test_windows_desktop_geometry
            native-owner-r2-authorized-view-only-offline-lifecycle)
    add_test(NAME windows.native-owner-standalone-authenticated-session-lifecycle
        COMMAND test_windows_desktop_geometry
            native-owner-standalone-authenticated-session-lifecycle)
    set_tests_properties(
        windows.native-owner-authorized-offline-lifecycle
        windows.native-owner-authorized-view-only-offline-lifecycle
        windows.native-owner-standalone-authenticated-session-lifecycle
        PROPERTIES
            LABELS "windows;native-owner;security;offline"
            TIMEOUT 20)

    # R6 read-only cursor metadata snapshot. Synthetic callbacks only; the
    # production Win32 observer is compiled but no CTest reads the live cursor.
    foreach(case_name IN ITEMS
            cursor-snapshot-visible-and-hidden
            cursor-snapshot-rejections)
        add_test(NAME "windows.${case_name}"
            COMMAND test_windows_desktop_geometry "${case_name}")
        set_tests_properties("windows.${case_name}" PROPERTIES
            LABELS "windows;desktop-cursor;offline")
    endforeach()
    # R6 DXGI metadata converts native move/dirty descriptors only; tests
    # never acquire an output or call live native input/capture APIs.
    add_test(NAME windows.capture-dxgi-move-before-dirty
        COMMAND test_windows_desktop_geometry dxgi-dirty-and-move-regions)
    add_test(NAME windows.capture-dxgi-metadata-rejections
        COMMAND test_windows_desktop_geometry dxgi-metadata-denials)
    set_tests_properties(
        windows.capture-dxgi-move-before-dirty
        windows.capture-dxgi-metadata-rejections
        PROPERTIES LABELS "windows;capture;offline")
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_rdp_test(test_x11_capture_layout.cpp x11 capture-layout-bounds)
    set_tests_properties(x11.capture-layout-bounds PROPERTIES
        LABELS "x11;linux-adapter")
endif()

# R1/R10 live ownership integration. Reuse the existing preauth executable and
# the exact secure R10 credential fixture writer; only loopback is bound.
foreach(runtime_transport_case IN ITEMS
        tcp-owned-runtime-tls-handshake
        tcp-owned-runtime-tls-identity-continuity)
    add_test(NAME "transport.${runtime_transport_case}"
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_RUNTIME_TLS_CONTEXT_TEST=$<TARGET_FILE:test_owned_preauth_session>"
            "-DRDP_RUNTIME_TLS_CONTEXT_CASE=${runtime_transport_case}"
            "-DRDP_RUNTIME_FIXTURE_DIRECTORY=${PROJECT_BINARY_DIR}/runtime-tls-context-fixtures"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_tls_context.cmake")
    set_tests_properties("transport.${runtime_transport_case}" PROPERTIES
        LABELS "protocol;transport;runtime;security;offline"
        TIMEOUT 30)
endforeach()

add_test(NAME transport.tcp-owned-generated-ip-hybrid-tls-client-verification
    COMMAND test_owned_preauth_session
        tcp-owned-generated-ip-hybrid-tls-client-verification)
set_tests_properties(
    transport.tcp-owned-generated-ip-hybrid-tls-client-verification
    PROPERTIES LABELS "protocol;transport;runtime;security;offline" TIMEOUT 30)

# R10 production TLS-context ownership. These tests exercise the runtime-only
# component directly; they never bind/listen and use only synthetic credentials.
add_executable(test_runtime_tls_context test_runtime_tls_context.cpp)
target_link_libraries(test_runtime_tls_context PRIVATE
    rdp-server-runtime-tls
    rdp-server-protocol
    OpenSSL::Crypto
    OpenSSL::SSL)
if(MSVC)
    target_compile_options(test_runtime_tls_context PRIVATE /W4 /UNDEBUG)
else()
    target_compile_options(test_runtime_tls_context PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
foreach(runtime_tls_context_case IN ITEMS
        validates-live-tls-context-construction
        validates-lan-endpoint-certificate-identity
        tls-endpoint-san-only-openssl-compatibility
        tls-context-read-only-unbound-identity-status
        tls-identity-offline-lifecycle-denials
        tls-context-survives-credential-path-replacement
        rejects-live-tls-context-invalid-material
        rejects-live-tls-context-extra-certificate-material
        rejects-live-tls-context-private-key-mismatch)
    add_test(NAME "runtime.${runtime_tls_context_case}"
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_RUNTIME_TLS_CONTEXT_TEST=$<TARGET_FILE:test_runtime_tls_context>"
            "-DRDP_RUNTIME_TLS_CONTEXT_CASE=${runtime_tls_context_case}"
            "-DRDP_RUNTIME_FIXTURE_DIRECTORY=${PROJECT_BINARY_DIR}/runtime-tls-context-fixtures"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_tls_context.cmake")
    set_tests_properties("runtime.${runtime_tls_context_case}" PROPERTIES
        LABELS "runtime;security;offline")
endforeach()

# R1 automatic portable-GUI identity: direct in-memory generation has no
# credential-file fixture and must not attach or open any network socket.
foreach(generated_tls_context_case IN ITEMS
        generated-tls-identity-ipv4-san
        generated-tls-identity-ipv6-san
        generated-tls-identity-generic-subject-ip-san-authority
        generated-tls-identity-owner-ipv4-san-der
        generated-tls-test-only-cn-variants-retain-ip-san
        generated-tls-context-negotiates-tls13
        generated-tls-identity-wrong-endpoint-denial
        generated-tls-identity-stop-retirement
        generated-tls-identity-no-listener-side-effect)
    add_test(NAME "runtime.${generated_tls_context_case}"
        COMMAND test_runtime_tls_context "${generated_tls_context_case}")
    set_tests_properties("runtime.${generated_tls_context_case}" PROPERTIES
        LABELS "runtime;security;tls;offline")
endforeach()

# One R10 production executable, and one offline CMake-script checker,
# without opening a listener, reading real credentials or installing a service.
foreach(runtime_case IN ITEMS
        rejects-unconfigured-startup
        rejects-unrecognized-options
        rejects-help-option-smuggling
        rejects-version-option-smuggling
        rejects-sensitive-argument-output
        displays-help-without-startup
        reports-version-without-startup
        validates-configuration-syntax
        validates-configuration-comments-crlf
        rejects-configuration-public-listener
        rejects-configuration-missing-auth
        rejects-configuration-missing-os-policy
        rejects-configuration-disabled-auth
        rejects-configuration-disabled-os-policy
        rejects-configuration-duplicate-field
        rejects-configuration-invalid-port
        rejects-configuration-invalid-limit
        rejects-configuration-oversized-file
        rejects-configuration-unknown-field
        rejects-configuration-control-comment
        rejects-configuration-relative-key
        rejects-configuration-traversal-key
        rejects-configuration-identical-tls-paths
        rejects-configuration-missing-file
        rejects-config-option-smuggling
        validates-configuration-owner-only
        validates-configuration-mode-normalization
        rejects-configuration-symlink
        rejects-configuration-fifo
        rejects-configuration-group-writable
        rejects-configuration-directory
        validates-configuration-windows-regular
        rejects-configuration-windows-directory
        rejects-configuration-windows-relative-file
        rejects-windows-device-namespace
        validates-configuration-windows-private-dacl
        rejects-configuration-windows-everyone-write
        rejects-configuration-windows-authenticated-write
        rejects-configuration-windows-users-write
        validates-tls-files-private-regular
        rejects-tls-files-missing-certificate
        rejects-tls-files-missing-key
        rejects-tls-files-empty-key
        rejects-tls-files-oversized-key
        rejects-tls-files-aliased-identity
        rejects-tls-files-key-group-readable
        rejects-tls-files-certificate-group-writable
        rejects-tls-files-key-symlink
        rejects-tls-files-certificate-symlink
        rejects-tls-files-key-directory
        rejects-tls-files-windows-key-public-read
        rejects-tls-files-option-smuggling
        validates-tls-files-nested-real-parent
        rejects-tls-files-key-parent-symlink
        rejects-tls-files-certificate-parent-symlink
        validates-tls-credentials-matching-pair
        rejects-tls-credentials-client-only-certificate
        rejects-tls-credentials-mismatched-key
        rejects-tls-credentials-malformed-certificate
        rejects-tls-credentials-malformed-key
        rejects-tls-credentials-encrypted-key
        rejects-tls-credentials-expired-certificate
        rejects-tls-credentials-not-yet-valid-certificate
        rejects-tls-credentials-option-smuggling
        )
    # A real nested directory is valid; either parent symlink is rejected
    # by the production openat component walk on POSIX.
    if(NOT UNIX AND runtime_case MATCHES
       "^(validates-tls-files-nested-real-parent|rejects-tls-files-(key|certificate)-parent-symlink)$")
        continue()
    endif()
    if(NOT WIN32 AND runtime_case STREQUAL "rejects-tls-files-windows-key-public-read")
        continue()
    endif()
    if(NOT UNIX AND runtime_case MATCHES
       "^rejects-tls-files-(key-group-readable|certificate-group-writable|key-symlink|certificate-symlink|key-directory)$")
        continue()
    endif()
    if(NOT WIN32 AND runtime_case MATCHES
       "^(validates-configuration-windows-(regular|private-dacl)|rejects-configuration-windows-(directory|relative-file|everyone-write|authenticated-write|users-write)|rejects-windows-device-namespace)$")
        continue()
    endif()
    # POSIX descriptor-identity/permissions tests are not applicable to
    # Windows native file handles; retain the original Windows CTests.
    if(NOT UNIX AND runtime_case MATCHES
       "^(validates-configuration-(owner-only|mode-normalization)|rejects-configuration-(symlink|fifo|group-writable|directory))$")
        continue()
    endif()
    add_test(NAME "runtime.${runtime_case}"
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_RUNTIME_EXECUTABLE=$<TARGET_FILE:rdp-server>"
            "-DRDP_RUNTIME_VERSION=${PROJECT_VERSION}"
            "-DRDP_RUNTIME_TEST_CASE=${runtime_case}"
            "-DRDP_RUNTIME_FIXTURE_DIRECTORY=${PROJECT_BINARY_DIR}/runtime-fixtures"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_entrypoint.cmake")
    set_tests_properties("runtime.${runtime_case}" PROPERTIES
        LABELS "runtime;offline")
    if(runtime_case STREQUAL "rejects-configuration-fifo" OR
       runtime_case STREQUAL "rejects-tls-credentials-encrypted-key")
        set_tests_properties("runtime.${runtime_case}" PROPERTIES TIMEOUT 10)
    endif()
endforeach()

if(WIN32)
    foreach(windows_fixture_case IN ITEMS
            dacl-creation
            broad-access-denials
            owner-consistency)
        add_test(NAME "runtime.windows-private-fixture-${windows_fixture_case}"
            COMMAND "${CMAKE_COMMAND}"
                "-DRDP_RUNTIME_EXECUTABLE=$<TARGET_FILE:rdp-server>"
                "-DRDP_RUNTIME_VERSION=${PROJECT_VERSION}"
                "-DRDP_WINDOWS_FIXTURE_CASE=${windows_fixture_case}"
                "-DRDP_RUNTIME_FIXTURE_DIRECTORY=${PROJECT_BINARY_DIR}/windows-private-fixture-${windows_fixture_case}"
                -P "${PROJECT_SOURCE_DIR}/tests/check_windows_private_fixture_acl.cmake")
        set_tests_properties(
            "runtime.windows-private-fixture-${windows_fixture_case}" PROPERTIES
            LABELS "runtime;security;windows;offline"
            TIMEOUT 30)
    endforeach()
endif()
# The native cursor conversion is compiled into the isolated headless
# test without adding XCB dependencies to the portable protocol archive.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_rdp_test(test_x11_cursor_reply.cpp x11 cursor-reply-length-bounds)
    target_sources(test_x11_cursor_reply PRIVATE
        "${PROJECT_SOURCE_DIR}/src/x11/cursor_image_conversion.cpp")
    set_tests_properties(x11.cursor-reply-length-bounds PROPERTIES
        LABELS "x11;linux-adapter")
endif()

# Test arena sizing even without optional XCB-SHM development headers.
# Where found, compile/link the native capture adapter and fail it closed.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_rdp_test(test_x11_native_capture.cpp x11
        capture-arena-and-connection-denials)
    if(TARGET rdp-server-linux-xshm)
        target_link_libraries(test_x11_native_capture PRIVATE
            rdp-server-linux-xshm)
        target_compile_definitions(test_x11_native_capture PRIVATE
            RDP_SERVER_HAVE_NATIVE_XSHM=1)
    endif()
    set_tests_properties(x11.capture-arena-and-connection-denials
        PROPERTIES LABELS "x11;linux-adapter")
endif()

# R5 XShm shared-memory and borrowed XCB owner teardown. The ordinary case
# uses a failed fd. The optional Xvfb case exercises a real attached segment,
# destructor retirement and immediate replacement on the same borrowed owner.
if(TARGET rdp-server-linux-xshm)
    add_rdp_test(test_x11_capture_disconnect.cpp x11
        capture-native-disconnect-cancellation)
    target_link_libraries(test_x11_capture_disconnect PRIVATE
        rdp-server-linux-xshm)
    set_tests_properties(x11.capture-native-disconnect-cancellation
        PROPERTIES LABELS "x11;linux-adapter;native")

    find_program(RDP_SERVER_XVFB_RUN_EXECUTABLE NAMES xvfb-run)
    if(RDP_SERVER_XVFB_RUN_EXECUTABLE)
        add_test(NAME x11.capture-native-destructor-retirement
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 1280x720x24 -nolisten tcp"
                $<TARGET_FILE:test_x11_capture_disconnect>
                destructor-retirement)
        set_tests_properties(x11.capture-native-destructor-retirement
            PROPERTIES
                LABELS "x11;linux-adapter;native;synthetic-display"
                TIMEOUT 20)
    endif()
endif()

# R7 standard CTests are synthetic and permission-safe on every OS.
# The Apple cases retain CoreVideo buffers only; no live ScreenCaptureKit
# stream, real TCC query or keyboard/mouse event is exercised here.
add_executable(test_macos_capture_pixel_buffer
    test_macos_capture_pixel_buffer.cpp)
target_include_directories(test_macos_capture_pixel_buffer PRIVATE
    "${PROJECT_SOURCE_DIR}/src")
if(APPLE)
    # The CoreVideo fixture directly references kCFAllocatorDefault.
    # Keep CoreFoundation on this Apple-only TEST executable.
    find_library(RDP_SERVER_COREFOUNDATION_FRAMEWORK CoreFoundation REQUIRED)
    target_link_libraries(test_macos_capture_pixel_buffer PRIVATE
        rdp-server-macos-capture
        "${RDP_SERVER_COREFOUNDATION_FRAMEWORK}")
else()
    target_sources(test_macos_capture_pixel_buffer PRIVATE
        "${PROJECT_SOURCE_DIR}/src/platform/macos/capture_pixel_layout.cpp"
        "${PROJECT_SOURCE_DIR}/src/platform/macos/capture_framebuffer_view.cpp"
        "${PROJECT_SOURCE_DIR}/src/platform/macos/desktop_display_geometry.cpp"
        "${PROJECT_SOURCE_DIR}/src/platform/macos/screen_capture_preflight.cpp"
        "${PROJECT_SOURCE_DIR}/src/platform/macos/native_display_snapshot.cpp"
        "${PROJECT_SOURCE_DIR}/src/platform/macos/native_display_geometry.cpp"
        "${PROJECT_SOURCE_DIR}/src/platform/macos/native_display_refresh.cpp"
        "${PROJECT_SOURCE_DIR}/src/platform/macos/native_display_reconfiguration.cpp"
        "${PROJECT_SOURCE_DIR}/src/platform/macos/native_session_change_watch.cpp"
        "${PROJECT_SOURCE_DIR}/src/platform/macos/mac_cursor_snapshot.cpp")
endif()
if(MSVC)
    target_compile_options(test_macos_capture_pixel_buffer PRIVATE /W4 /UNDEBUG)
else()
    target_compile_options(test_macos_capture_pixel_buffer PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
add_test(NAME macos.capture-bgra-layout-bounds
    COMMAND test_macos_capture_pixel_buffer layout)
add_test(NAME macos.capture-framebuffer-view-contract
    COMMAND test_macos_capture_pixel_buffer framebuffer-view-contract)
add_test(NAME macos.capture-permission-preflight-revocation
    COMMAND test_macos_capture_pixel_buffer permission-preflight)
set_tests_properties(
    macos.capture-bgra-layout-bounds
    macos.capture-framebuffer-view-contract
    macos.capture-permission-preflight-revocation
    PROPERTIES LABELS "macos;capture;offline")
foreach(case_name IN ITEMS
        retina-points multi-display-invalid reconfiguration
        virtual-input-coordinates)
    add_test(NAME "macos.desktop-${case_name}"
        COMMAND test_macos_capture_pixel_buffer "${case_name}")
    set_tests_properties("macos.desktop-${case_name}"
        PROPERTIES LABELS "macos;geometry;offline")
endforeach()
# CoreGraphics display enumeration is exercised only through synthetic
# injected observations here: no real display read or privacy interaction.
foreach(case_name IN ITEMS
        stable-multi-retina geometry-denials changed-during-read)
    add_test(NAME "macos.display-snapshot-${case_name}"
        COMMAND test_macos_capture_pixel_buffer "display-snapshot-${case_name}")
    set_tests_properties("macos.display-snapshot-${case_name}" PROPERTIES
        LABELS "macos;geometry;offline")
endforeach()
# R7 native snapshot -> portable geometry uses synthetic metadata only.
foreach(case_name IN ITEMS
        single-retina uniform-multi-display mixed-scale-denials generation-refresh)
    add_test(NAME "macos.geometry-native-${case_name}"
        COMMAND test_macos_capture_pixel_buffer "geometry-native-${case_name}")
    set_tests_properties("macos.geometry-native-${case_name}" PROPERTIES
        LABELS "macos;geometry;offline")
endforeach()
# R7 topology-epoch guard: synthetic reads, no CoreGraphics display,
# screen-capture stream, TCC prompt, native input or service activation.
foreach(case_name IN ITEMS
        refresh generation-fence-revocation invalidate failed-refresh)
    add_test(NAME "macos.desktop-geometry-epoch-${case_name}"
        COMMAND test_macos_capture_pixel_buffer "geometry-epoch-${case_name}")
    set_tests_properties("macos.desktop-geometry-epoch-${case_name}"
        PROPERTIES LABELS "macos;geometry;offline")
endforeach()
# R7 CoreGraphics reconfiguration callback revision fence; ordinary tests
# inject notifications and NEVER register the native callback or access TCC.
foreach(case_name IN ITEMS
        stale-denial during-read revision-sequence)
    add_test(NAME "macos.desktop-native-reconfiguration-${case_name}"
        COMMAND test_macos_capture_pixel_buffer "native-reconfiguration-${case_name}")
    set_tests_properties("macos.desktop-native-reconfiguration-${case_name}"
        PROPERTIES LABELS "macos;geometry;offline")
endforeach()
# R7 cursor snapshots are synthetic on every OS. The Apple sampler remains
# translation-unit-private until authorized R2/R3 + R4 composition; its source
# is compile/link checked but ordinary CTest cannot invoke live AppKit state.
foreach(case_name IN ITEMS
        native-sampler-quarantine owned-shape validation-denials
        topology-revocation topology-publication-revocation
        geometry-generation-publication-denials session-watch-revocation)
    add_test(NAME "macos.cursor-${case_name}"
        COMMAND test_macos_capture_pixel_buffer "cursor-${case_name}")
    set_tests_properties("macos.cursor-${case_name}" PROPERTIES
        LABELS "macos;cursor;offline")
endforeach()
set_tests_properties(
    macos.cursor-topology-publication-revocation
    macos.cursor-geometry-generation-publication-denials
    PROPERTIES LABELS "macos;cursor;geometry;security;offline")

# R7 macOS input state/translation tests are permission-free on every OS.
# Apple compile/links the dormant Quartz emitter, but ordinary CTest reaches
# only the injected callback seam and synthetic display geometry.
add_executable(test_macos_input_controller
    test_macos_input_controller.cpp)
target_include_directories(test_macos_input_controller PRIVATE
    "${PROJECT_SOURCE_DIR}/src")
if(APPLE)
    target_link_libraries(test_macos_input_controller PRIVATE
        rdp-server-macos-capture)
else()
    target_sources(test_macos_input_controller PRIVATE
        "${PROJECT_SOURCE_DIR}/src/platform/macos/desktop_display_geometry.cpp"
        "${PROJECT_SOURCE_DIR}/src/platform/macos/native_display_snapshot.cpp"
        "${PROJECT_SOURCE_DIR}/src/platform/macos/native_display_geometry.cpp"
        "${PROJECT_SOURCE_DIR}/src/platform/macos/native_display_refresh.cpp"
        "${PROJECT_SOURCE_DIR}/src/platform/macos/native_display_reconfiguration.cpp"
        "${PROJECT_SOURCE_DIR}/src/platform/macos/native_session_change_watch.cpp"
        "${PROJECT_SOURCE_DIR}/src/platform/macos/mac_input_controller.cpp")
endif()
if(MSVC)
    target_compile_options(test_macos_input_controller PRIVATE /W4 /UNDEBUG)
else()
    target_compile_options(test_macos_input_controller PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
foreach(case_name IN ITEMS lifecycle validation-denials revocation-cleanup
        authority-retirement-no-native-post session-watch-revocation)
    add_test(NAME "macos.input-controller-${case_name}"
        COMMAND test_macos_input_controller "${case_name}")
    set_tests_properties("macos.input-controller-${case_name}" PROPERTIES
        LABELS "macos;input;offline")
endforeach()

# R2 macOS native-session evidence. This calls only read-only production
# console/audit/Security-session APIs; it requests no TCC permission and never
# promotes the observed UID/session to authenticated RDP admission.
if(TARGET rdp-server-macos-native-session-evidence)
    add_executable(test_macos_native_session_evidence
        test_macos_native_session_evidence.cpp)
    target_link_libraries(test_macos_native_session_evidence PRIVATE
        rdp-server-macos-native-session-evidence)
    target_compile_options(test_macos_native_session_evidence PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    add_test(NAME security.macos-native-session-evidence-provider-denials
        COMMAND test_macos_native_session_evidence)
    set_tests_properties(
        security.macos-native-session-evidence-provider-denials PROPERTIES
        LABELS "security;native-admission;macos;offline")
endif()

# R7 macOS desktop session/permission guard. Ordinary tests use synthetic
# session observations and permission probes; Apple compile/links the native
# read-only Quartz session reader through rdp-server-macos-capture.
add_executable(test_macos_desktop_session_guard
    test_macos_desktop_session_guard.cpp)
target_include_directories(test_macos_desktop_session_guard PRIVATE
    "${PROJECT_SOURCE_DIR}/src")
if(APPLE)
    target_link_libraries(test_macos_desktop_session_guard PRIVATE
        rdp-server-macos-capture)
else()
    target_sources(test_macos_desktop_session_guard PRIVATE
        "${PROJECT_SOURCE_DIR}/src/platform/macos/desktop_display_geometry.cpp"
        "${PROJECT_SOURCE_DIR}/src/platform/macos/native_display_snapshot.cpp"
        "${PROJECT_SOURCE_DIR}/src/platform/macos/native_display_geometry.cpp"
        "${PROJECT_SOURCE_DIR}/src/platform/macos/native_display_refresh.cpp"
        "${PROJECT_SOURCE_DIR}/src/platform/macos/native_display_reconfiguration.cpp"
        "${PROJECT_SOURCE_DIR}/src/platform/macos/native_session_change_watch.cpp"
        "${PROJECT_SOURCE_DIR}/src/platform/macos/mac_desktop_session_guard.cpp")
endif()
if(MSVC)
    target_compile_options(test_macos_desktop_session_guard PRIVATE /W4 /UNDEBUG)
else()
    target_compile_options(test_macos_desktop_session_guard PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
foreach(case_name IN ITEMS
        lifecycle validation-denials revocation-reentry
        switch-away-back-revocation mid-operation-epoch-change
        watch-registration-retirement watch-retirement-callback-race
        watch-partial-install-retirement watch-destructor-retirement
        watch-unavailable-denial)
    add_test(NAME "macos.desktop-session-${case_name}"
        COMMAND test_macos_desktop_session_guard "${case_name}")
    set_tests_properties("macos.desktop-session-${case_name}" PROPERTIES
        LABELS "macos;session;security;offline")
endforeach()

if(APPLE)
    add_test(NAME "macos.desktop-native-reconfiguration-registration-retirement"
        COMMAND test_macos_capture_pixel_buffer
                "native-reconfiguration-registration-retirement")
    set_tests_properties(
        "macos.desktop-native-reconfiguration-registration-retirement"
        PROPERTIES LABELS "macos;geometry;security;offline")

    add_test(NAME "macos.desktop-native-refresh-requires-topology-coverage"
        COMMAND test_macos_capture_pixel_buffer
                "native-refresh-requires-topology-coverage")
    set_tests_properties(
        "macos.desktop-native-refresh-requires-topology-coverage"
        PROPERTIES LABELS "macos;geometry;security;offline")

    foreach(case_name IN ITEMS ownership native-denials native-move-replacement)
        add_test(NAME "macos.capture-bgra-buffer-${case_name}"
            COMMAND test_macos_capture_pixel_buffer "${case_name}")
        set_tests_properties("macos.capture-bgra-buffer-${case_name}"
            PROPERTIES LABELS "macos;capture;offline")
    endforeach()
endif()

# The ScreenCaptureKit lifecycle CTests use the production C++ state owner with
# an injected backend and synthetic CoreVideo buffers. The production native
# factory remains private to the R2-authorized aggregate owner; ordinary tests
# never enumerate SCShareableContent, start SCStream, or request TCC.
if(APPLE)
    add_executable(test_macos_capture_stream test_macos_capture_stream.cpp)
    target_include_directories(test_macos_capture_stream PRIVATE
        "${PROJECT_SOURCE_DIR}/src")
    target_link_libraries(test_macos_capture_stream PRIVATE
        rdp-server-macos-capture
        rdp-server-graphics
        "${RDP_SERVER_COREFOUNDATION_FRAMEWORK}")
    if(MSVC)
        target_compile_options(test_macos_capture_stream PRIVATE /W4 /UNDEBUG)
    else()
        target_compile_options(test_macos_capture_stream PRIVATE
            -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    endif()
    foreach(case_name IN ITEMS
            lifecycle stale-generation-denials
            geometry-generation-retirement callback-retirement
            consumer-cancellation native-stop-single-ownership
            backend-callback-reentry-retirement
            start-retirement-after-completion
            native-factory-quarantine framebuffer-contract
            session-watch-frame-retirement session-watch-consumer-race)
        add_test(NAME "macos.capture-stream-${case_name}"
            COMMAND test_macos_capture_stream "${case_name}")
        set_tests_properties("macos.capture-stream-${case_name}" PROPERTIES
            LABELS "macos;capture;offline;native")
    endforeach()
    # R7 -> R4 synchronous BGRA compatibility. Production macOS capture keeps
    # no R4/x264 dependency; only this existing Apple fixture links graphics.
    foreach(case_name IN ITEMS
            bgra-layout-contract
            pixel-lifetime-retirement
            display-generation-denials)
        add_test(NAME "macos.capture-${case_name}"
            COMMAND test_macos_capture_stream "r4-${case_name}")
        set_tests_properties("macos.capture-${case_name}" PROPERTIES
            LABELS "macos;capture;graphics;x264;security;offline;native")
    endforeach()
endif()

# R5 macOS aggregate owner: real R2 authorization state with injected display,
# GUI-session, TCC, capture and input seams. These tests never enumerate a live
# desktop, start ScreenCaptureKit or post Quartz events.
add_test(NAME macos.native-desktop-owner-framebuffer-row-size-bounds
    COMMAND "${CMAKE_COMMAND}"
        "-DRDP_MAC_NATIVE_OWNER_SOURCE=${PROJECT_SOURCE_DIR}/src/platform/macos/mac_native_desktop_owner.cpp"
        -P "${PROJECT_SOURCE_DIR}/tests/check_macos_native_desktop_framebuffer_sizing.cmake")
set_tests_properties(
    macos.native-desktop-owner-framebuffer-row-size-bounds PROPERTIES
    LABELS "macos;desktop;capture;security;policy;offline;native")

add_test(NAME macos.native-input-permission-readiness-contract
    COMMAND "${CMAKE_COMMAND}"
        "-DRDP_MAC_INPUT_CONTROLLER_SOURCE=${PROJECT_SOURCE_DIR}/src/platform/macos/mac_input_controller.mm"
        -P "${PROJECT_SOURCE_DIR}/tests/check_macos_native_input_permission_readiness.cmake")
set_tests_properties(
    macos.native-input-permission-readiness-contract PROPERTIES
    LABELS "macos;desktop;input;security;policy;offline;native")

if(APPLE)
    add_executable(test_macos_native_desktop_owner
        test_macos_native_desktop_owner.cpp)
    target_include_directories(test_macos_native_desktop_owner PRIVATE
        "${PROJECT_SOURCE_DIR}/src")
    target_link_libraries(test_macos_native_desktop_owner PRIVATE
        rdp-server-macos-capture
        rdp-server-native-desktop-authorization)
    if(MSVC)
        target_compile_options(test_macos_native_desktop_owner PRIVATE
            /W4 /UNDEBUG)
    else()
        target_compile_options(test_macos_native_desktop_owner PRIVATE
            -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    endif()
    foreach(case_name IN ITEMS
            fail-closed-construction
            frame-input-lifecycle
            borrow-callback-retirement
            input-permission-retirement
            standalone-authenticated-session-lifecycle
            display-session-retirement)
        add_test(NAME "macos.native-desktop-owner-${case_name}"
            COMMAND test_macos_native_desktop_owner "${case_name}")
        set_tests_properties(
            "macos.native-desktop-owner-${case_name}" PROPERTIES
            LABELS "macos;desktop;capture;input;security;offline;native")
    endforeach()
endif()

# R10 production process linkage for the platform-native owner. This source
# guard is platform-independent; hosted Windows/macOS compilation additionally
# proves the real static/native dependency closure. Startup remains unattached.
add_test(NAME runtime.platform-native-production-single-owner-linkage
    COMMAND "${CMAKE_COMMAND}"
        "-DRDP_ROOT_CMAKE=${PROJECT_SOURCE_DIR}/CMakeLists.txt"
        "-DRDP_RUNTIME_ENTRYPOINT_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/main.cpp"
        -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_platform_native_production_linkage.cmake")
set_tests_properties(
    runtime.platform-native-production-single-owner-linkage PROPERTIES
    LABELS "runtime;host-control;native;security;offline")

# R10 one-owner Windows/macOS platform-native composition seam. The ordinary
# regression uses an unbound real R2 authorization object, so it executes no
# WTS/DXGI/SendInput, TCC/ScreenCaptureKit/Quartz, listener or protocol action.
if(TARGET rdp-server-runtime-platform-native-desktop)
    add_executable(test_runtime_platform_native_desktop
        test_runtime_platform_native_desktop.cpp)
    target_include_directories(test_runtime_platform_native_desktop PRIVATE
        "${PROJECT_SOURCE_DIR}/src")
    target_link_libraries(test_runtime_platform_native_desktop PRIVATE
        rdp-server-runtime-platform-native-desktop
        rdp-server-native-desktop-authorization)
    if(MSVC)
        target_compile_options(test_runtime_platform_native_desktop PRIVATE
            /W4 /WX /UNDEBUG)
    else()
        target_compile_options(test_runtime_platform_native_desktop PRIVATE
            -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    endif()
    if(WIN32)
        add_test(
            NAME runtime.platform-native-desktop-windows-gated-composition
            COMMAND test_runtime_platform_native_desktop)
        add_test(
            NAME runtime.platform-native-desktop-windows-authenticated-session-denials
            COMMAND test_runtime_platform_native_desktop
                authenticated-session-denials)
        set_tests_properties(
            runtime.platform-native-desktop-windows-gated-composition
            runtime.platform-native-desktop-windows-authenticated-session-denials
            PROPERTIES
            LABELS "runtime;host-control;native;security;windows;offline")
    elseif(APPLE)
        add_test(
            NAME runtime.platform-native-desktop-macos-gated-composition
            COMMAND test_runtime_platform_native_desktop)
        add_test(
            NAME runtime.platform-native-desktop-macos-authenticated-session-denials
            COMMAND test_runtime_platform_native_desktop
                authenticated-session-denials)
        set_tests_properties(
            runtime.platform-native-desktop-macos-gated-composition
            runtime.platform-native-desktop-macos-authenticated-session-denials
            PROPERTIES
            LABELS "runtime;host-control;native;security;macos;offline")
    endif()
endif()

# R5 native XCB connection: headless deterministic event draining and
# invalid-display descriptor ownership, no live desktop/X server.
if(TARGET rdp-server-x11-connection)
    add_rdp_test(test_x11_display_events.cpp x11
        display-event-budget-and-readiness)
    target_link_libraries(test_x11_display_events PRIVATE
        rdp-server-x11-connection)
    target_compile_definitions(test_x11_display_events PRIVATE
        RDP_TEST_NATIVE_X11_CONNECTION=1)
    add_test(NAME x11.display-event-disconnect-cleanup
        COMMAND test_x11_display_events disconnect-cleanup)
    set_tests_properties(
        x11.display-event-budget-and-readiness
        x11.display-event-disconnect-cleanup
        PROPERTIES LABELS "x11;linux-adapter;native")

    find_program(RDP_SERVER_XVFB_RUN_EXECUTABLE NAMES xvfb-run)
    if(RDP_SERVER_XVFB_RUN_EXECUTABLE)
        add_test(NAME x11.display-event-failure-defers-owner-teardown
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 1280x720x24 -nolisten tcp"
                $<TARGET_FILE:test_x11_display_events>
                failure-defers-owner-teardown)
        set_tests_properties(
            x11.display-event-failure-defers-owner-teardown
            PROPERTIES LABELS "x11;linux-adapter;native;synthetic-display"
                       TIMEOUT 20)
    endif()
endif()

# Existing first-party XI2 pointer tracker: real XInput2 negotiation and
# subscription use only ephemeral Xvfb; synthetic wire records exercise the
# production parser/coalescer without XTEST or a logged-in desktop.
if(TARGET rdp-server-linux-xinput-pointer)
    add_executable(test_x11_pointer_position_tracker
        test_x11_pointer_position_tracker.cpp)
    target_link_libraries(test_x11_pointer_position_tracker PRIVATE
        rdp-server-linux-xinput-pointer)
    target_compile_options(test_x11_pointer_position_tracker PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)

    find_program(RDP_SERVER_XVFB_RUN_EXECUTABLE NAMES xvfb-run)
    if(RDP_SERVER_XVFB_RUN_EXECUTABLE)
        foreach(case_name IN ITEMS
                motion-coalescing remote-echo-suppression
                disconnect-cancellation destructor-retirement
                malformed-event-bounds)
            add_test(NAME "x11.pointer-xi2-${case_name}"
                COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                    "-screen 0 1280x720x24 -nolisten tcp -noreset"
                    $<TARGET_FILE:test_x11_pointer_position_tracker>
                    "${case_name}")
            set_tests_properties("x11.pointer-xi2-${case_name}"
                PROPERTIES LABELS "x11;linux-adapter;native;synthetic-display"
                           TIMEOUT 20)
        endforeach()
    else()
        add_test(NAME x11.pointer-xi2-disconnect-cancellation
            COMMAND test_x11_pointer_position_tracker disconnect-cancellation)
        set_tests_properties(x11.pointer-xi2-disconnect-cancellation
            PROPERTIES LABELS "x11;linux-adapter;native")
    endif()
endif()

# First-party native XFixes cursor source: exercise failure and borrowed
# connection cancellation without an X server or desktop access.
if(TARGET rdp-server-linux-xfixes-cursor)
    add_rdp_test(test_x11_native_cursor.cpp x11
        cursor-native-connection-denials-and-cancellation)
    target_link_libraries(test_x11_native_cursor PRIVATE
        rdp-server-linux-xfixes-cursor)
    set_tests_properties(
        x11.cursor-native-connection-denials-and-cancellation
        PROPERTIES LABELS "x11;linux-adapter;native")

    find_program(RDP_SERVER_XVFB_RUN_EXECUTABLE NAMES xvfb-run)
    if(RDP_SERVER_XVFB_RUN_EXECUTABLE)
        add_test(NAME x11.cursor-native-destructor-retirement
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 1280x720x24 -nolisten tcp -noreset"
                $<TARGET_FILE:test_x11_native_cursor>
                destructor-retirement)
        set_tests_properties(
            x11.cursor-native-destructor-retirement
            PROPERTIES LABELS "x11;linux-adapter;native;synthetic-display"
                       TIMEOUT 20)
    endif()
endif()

# R5 native XDamage lifetime: invalid connection and deterministic
# cancellation before XCB owner teardown, without a running display.
if(TARGET rdp-server-linux-xdamage)
    add_rdp_test(test_x11_native_damage.cpp x11
        damage-native-connection-denials-and-cancellation)
    target_link_libraries(test_x11_native_damage PRIVATE
        rdp-server-linux-xdamage)
    set_tests_properties(
        x11.damage-native-connection-denials-and-cancellation
        PROPERTIES LABELS "x11;linux-adapter;native")

    find_program(RDP_SERVER_XVFB_RUN_EXECUTABLE NAMES xvfb-run)
    if(RDP_SERVER_XVFB_RUN_EXECUTABLE)
        add_test(NAME x11.damage-native-destructor-retirement
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 1280x720x24 -nolisten tcp -noreset"
                $<TARGET_FILE:test_x11_native_damage>
                destructor-retirement)
        set_tests_properties(
            x11.damage-native-destructor-retirement
            PROPERTIES LABELS "x11;linux-adapter;native;synthetic-display"
                       TIMEOUT 20)
    endif()
endif()

# R5 native XTEST input lifetime: the test uses an already-failed XCB
# descriptor so no live input can be injected. It verifies production
# constructor denial plus repeated cancellation before parent teardown.
if(TARGET rdp-server-linux-xtest-input)
    add_rdp_test(test_x11_native_input.cpp x11
        input-native-connection-denials-and-cancellation)
    target_link_libraries(test_x11_native_input PRIVATE
        rdp-server-linux-xtest-input)
    set_tests_properties(
        x11.input-native-connection-denials-and-cancellation
        PROPERTIES LABELS "x11;linux-adapter;native")

    find_program(RDP_SERVER_XVFB_RUN_EXECUTABLE NAMES xvfb-run)
    if(RDP_SERVER_XVFB_RUN_EXECUTABLE)
        add_test(NAME x11.input-native-destructor-held-input-release
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 1280x720x24 -nolisten tcp -noreset"
                $<TARGET_FILE:test_x11_native_input>
                destructor-held-input-release)
        add_test(NAME x11.input-native-keyboard-sequence-and-reconnect
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 1280x720x24 -nolisten tcp -noreset"
                $<TARGET_FILE:test_x11_native_input>
                keyboard-sequence-and-reconnect)
        add_test(NAME x11.input-native-keyboard-logout-no-native-post
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 1280x720x24 -nolisten tcp -noreset"
                $<TARGET_FILE:test_x11_native_input>
                keyboard-logout-no-native-post)
        add_test(NAME x11.input-native-authority-retirement-no-native-post
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 1280x720x24 -nolisten tcp -noreset"
                $<TARGET_FILE:test_x11_native_input>
                authority-retirement-no-native-post)
        add_test(NAME x11.input-native-pointer-button-owner-held-break-denials
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 1280x720x24 -nolisten tcp -noreset"
                $<TARGET_FILE:test_x11_native_input>
                pointer-button-owner-held-transitions)
        set_tests_properties(
            x11.input-native-destructor-held-input-release
            x11.input-native-authority-retirement-no-native-post
            x11.input-native-keyboard-sequence-and-reconnect
            x11.input-native-keyboard-logout-no-native-post
            x11.input-native-pointer-button-owner-held-break-denials
            PROPERTIES LABELS "x11;linux-adapter;native;security;synthetic-display"
                       TIMEOUT 20)
    endif()
endif()

# R5 one-XCB-owner lifecycle. The denial case needs no X server; the
# positive case runs only under an ephemeral Xvfb server and never touches a
# logged-in desktop, credentials, or the server runtime.
if(TARGET rdp-server-linux-x11-desktop)
    add_rdp_test(test_x11_desktop_resources.cpp x11
        desktop-resource-owner-connection-denial)
    target_link_libraries(test_x11_desktop_resources PRIVATE
        rdp-server-linux-x11-desktop
        rdp-server-graphics)
    target_compile_options(test_x11_desktop_resources PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    if(TARGET rdp-server-linux-xinput-pointer)
        target_compile_definitions(test_x11_desktop_resources PRIVATE
            RDP_TEST_XINPUT_POINTER=1)
    endif()
    set_tests_properties(
        x11.desktop-resource-owner-connection-denial
        PROPERTIES LABELS "x11;linux-adapter;native")

    if(RDP_SERVER_XVFB_RUN_EXECUTABLE)
        # This case intentionally reaches zero X clients between independent
        # owner generations. Keep Xvfb from resetting so the test isolates R5
        # teardown/recovery rather than racing the server's last-client reset.
        add_test(NAME x11.desktop-resource-owner-lifecycle
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 1280x720x24 -nolisten tcp -noreset"
                $<TARGET_FILE:test_x11_desktop_resources> lifecycle)
        add_test(NAME x11.desktop-resource-event-routing
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 1280x720x24 -nolisten tcp"
                $<TARGET_FILE:test_x11_desktop_resources> event-routing)
        add_test(NAME x11.desktop-resource-randr-rebuild
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 1280x720x24 -nolisten tcp"
                $<TARGET_FILE:test_x11_desktop_resources> randr-rebuild)
        add_test(NAME x11.input-native-keyboard-layout-change-revokes-owner
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 1280x720x24 -nolisten tcp -noreset"
                $<TARGET_FILE:test_x11_desktop_resources>
                keyboard-layout-change-revokes-owner)
        set_tests_properties(
            x11.input-native-keyboard-layout-change-revokes-owner PROPERTIES
            LABELS "x11;linux-adapter;native;security;synthetic-display"
            TIMEOUT 20)
        add_test(NAME x11.desktop-resource-frame-read-boundary
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 1280x720x24 -nolisten tcp"
                $<TARGET_FILE:test_x11_desktop_resources> r4-read-boundary)
        add_test(NAME x11.capture-bgra-ingress
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 320x240x24 -nolisten tcp -noreset"
                $<TARGET_FILE:test_x11_desktop_resources>
                capture-r4-bgra-ingress)
        add_test(NAME x11.capture-stride-layout-denials
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 320x240x24 -nolisten tcp -noreset"
                $<TARGET_FILE:test_x11_desktop_resources>
                capture-r4-stride-layout-denials)
        add_test(NAME x11.capture-generation-retirement
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 320x240x24 -nolisten tcp -noreset"
                $<TARGET_FILE:test_x11_desktop_resources>
                capture-r4-generation-retirement)
        set_tests_properties(
            x11.capture-bgra-ingress
            x11.capture-stride-layout-denials
            x11.capture-generation-retirement
            PROPERTIES
                LABELS "x11;linux-adapter;native;synthetic-display;graphics"
                TIMEOUT 20)

        add_test(NAME x11.desktop-resource-capture-pixel-parity
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 1280x720x24 -nolisten tcp"
                $<TARGET_FILE:test_x11_desktop_resources>
                capture-pixel-parity)
        # A new R5 X11 owner must never reuse a retired capture epoch, even
        # with identical screen size and native-session generation.
        add_test(NAME x11.native-capture-owner-replacement-aba-denial
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 1280x720x24 -nolisten tcp -noreset"
                $<TARGET_FILE:test_x11_desktop_resources>
                native-capture-owner-replacement-aba-denial)
        set_tests_properties(
            x11.native-capture-owner-replacement-aba-denial
            PROPERTIES LABELS "x11;linux-adapter;native;synthetic-display;graphics;generation;security"
                       TIMEOUT 20)
        # R5 snapshot/borrow generation fence; no R2 lease, listener or seat0.
        add_test(NAME x11.native-geometry-observation-generation-retirement
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 1280x720x24 -nolisten tcp -noreset"
                $<TARGET_FILE:test_x11_desktop_resources>
                native-geometry-observation-retirement)
        set_tests_properties(
            x11.native-geometry-observation-generation-retirement
            PROPERTIES LABELS "x11;linux-adapter;native;synthetic-display;graphics;generation"
                       TIMEOUT 30)
        # R5 same-root-pixel RandR invalidation, isolated from seat0.
        add_test(NAME x11.same-pixel-randr-capture-retirement
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 1280x720x24 -nolisten tcp -noreset"
                $<TARGET_FILE:test_x11_desktop_resources>
                same-pixel-randr-capture-retirement)
        add_test(NAME x11.randr-burst-generation-retirement-recovery
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 1280x720x24 -nolisten tcp -noreset"
                $<TARGET_FILE:test_x11_desktop_resources>
                randr-burst-generation-retirement-recovery)
        set_tests_properties(
            x11.same-pixel-randr-capture-retirement
            x11.randr-burst-generation-retirement-recovery
            PROPERTIES LABELS "x11;linux-adapter;native;synthetic-display;graphics;generation"
                       TIMEOUT 20)
        add_test(NAME x11.desktop-resource-randr-capture-generation
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 1280x720x24 -nolisten tcp"
                $<TARGET_FILE:test_x11_desktop_resources>
                randr-capture-generation)
        add_test(NAME x11.desktop-resource-randr-stale-damage-isolation
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 1280x720x24 -nolisten tcp"
                $<TARGET_FILE:test_x11_desktop_resources>
                randr-stale-damage-isolation)
        add_test(NAME x11.desktop-resource-authority-retirement-queued-damage-isolation
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 1280x720x24 -nolisten tcp -noreset"
                $<TARGET_FILE:test_x11_desktop_resources>
                authority-retirement-queued-damage-isolation)
        set_tests_properties(
            x11.desktop-resource-authority-retirement-queued-damage-isolation
            PROPERTIES
                LABELS "x11;linux-adapter;native;synthetic-display;security;generation"
                TIMEOUT 20)
        # Authority loss during a queued XDamage callback stops the event
        # batch before it can touch a replacement native owner.
        add_test(NAME x11.desktop-resource-reentrant-authority-loss-damage-dispatch
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 1280x720x24 -nolisten tcp -noreset"
                $<TARGET_FILE:test_x11_desktop_resources>
                reentrant-authority-loss-damage-dispatch)
        set_tests_properties(
            x11.desktop-resource-reentrant-authority-loss-damage-dispatch
            PROPERTIES
                LABELS "x11;linux-adapter;native;synthetic-display;security;generation"
                TIMEOUT 20)
        # A synchronous R4 pixel borrow cannot publish after native R2
        # retirement, even when the callback completed its read successfully.
        add_test(NAME x11.desktop-resource-inflight-frame-borrow-authority-retirement
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 1280x720x24 -nolisten tcp -noreset"
                $<TARGET_FILE:test_x11_desktop_resources>
                inflight-frame-borrow-authority-retirement)
        set_tests_properties(
            x11.desktop-resource-inflight-frame-borrow-authority-retirement
            PROPERTIES
                LABELS "x11;linux-adapter;native;synthetic-display;security;generation"
                TIMEOUT 20)
        add_test(NAME x11.desktop-resource-capture-terminal-denial
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 1280x720x24 -nolisten tcp"
                $<TARGET_FILE:test_x11_desktop_resources>
                capture-terminal-denial)
        add_test(NAME x11.desktop-resource-pointer-capability-denials
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 1280x720x24 -nolisten tcp"
                $<TARGET_FILE:test_x11_desktop_resources>
                pointer-capability-denials)
        set_tests_properties(
            x11.desktop-resource-owner-lifecycle
            x11.desktop-resource-event-routing
            x11.desktop-resource-randr-rebuild
            x11.desktop-resource-frame-read-boundary
            x11.desktop-resource-capture-pixel-parity
            x11.desktop-resource-randr-capture-generation
            x11.desktop-resource-randr-stale-damage-isolation
            x11.desktop-resource-capture-terminal-denial
            x11.desktop-resource-pointer-capability-denials
            PROPERTIES LABELS "x11;linux-adapter;native;synthetic-display"
                       TIMEOUT 20)

        if(TARGET rdp-server-linux-xinput-pointer)
            add_test(NAME x11.desktop-resource-pointer-event-routing
                COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                    "-screen 0 1280x720x24 -nolisten tcp"
                    $<TARGET_FILE:test_x11_desktop_resources>
                    pointer-event-routing)
            add_test(NAME x11.desktop-resource-pointer-randr-rebuild
                COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                    "-screen 0 1280x720x24 -nolisten tcp"
                    $<TARGET_FILE:test_x11_desktop_resources>
                    pointer-randr-rebuild)
            add_test(NAME x11.desktop-resource-pointer-randr-stale-motion-isolation
                COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                    "-screen 0 1280x720x24 -nolisten tcp"
                    $<TARGET_FILE:test_x11_desktop_resources>
                    pointer-randr-stale-motion-isolation)
            set_tests_properties(
                x11.desktop-resource-pointer-event-routing
                x11.desktop-resource-pointer-randr-rebuild
                x11.desktop-resource-pointer-randr-stale-motion-isolation
                PROPERTIES
                    LABELS "x11;linux-adapter;native;synthetic-display"
                    TIMEOUT 20)
        endif()
    else()
        message(STATUS "R5 xvfb-run unavailable: synthetic X11 owner lifecycle/event/resize CTests not built")
    endif()
endif()

# R5 production R2-gated decoded slow-path native event mapping, fully
# offline. Only deterministic X11 pointer buttons/motion and lock-sync map;
# unknown, Unicode, relative and unsupported negotiated variants deny natively.
if(TARGET rdp-server-linux-x11-authorized-input)
    add_executable(test_x11_rdp_slow_path_input
        test_x11_rdp_slow_path_input.cpp)
    target_link_libraries(test_x11_rdp_slow_path_input PRIVATE
        rdp-server-linux-x11-authorized-input)
    target_compile_options(test_x11_rdp_slow_path_input PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    add_test(NAME x11.input-authorized-slow-path-native-mapping-denials
        COMMAND test_x11_rdp_slow_path_input)
    set_tests_properties(
        x11.input-authorized-slow-path-native-mapping-denials PROPERTIES
        LABELS "x11;linux-adapter;security;input;offline"
        TIMEOUT 20)
    # Offline scancode/extended-key coverage through R3's decoded event
    # type; each positive native post still requires a real R2 lease.
    add_executable(test_x11_rdp_scancode test_x11_rdp_scancode.cpp)
    target_link_libraries(test_x11_rdp_scancode PRIVATE
        rdp-server-linux-x11-authorized-input)
    target_compile_options(test_x11_rdp_scancode PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    add_test(NAME x11.input-scancode-make-release-modifier-extended-denials
        COMMAND test_x11_rdp_scancode)
    set_tests_properties(
        x11.input-scancode-make-release-modifier-extended-denials PROPERTIES
        LABELS "x11;linux-adapter;security;input;offline"
        TIMEOUT 20)
    add_executable(test_x11_rdp_extended_mouse
        test_x11_rdp_extended_mouse.cpp)
    target_link_libraries(test_x11_rdp_extended_mouse PRIVATE
        rdp-server-linux-x11-authorized-input)
    target_compile_options(test_x11_rdp_extended_mouse PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    add_test(NAME x11.input-rdp-mousex-side-button-bounds-and-flag-denials
        COMMAND test_x11_rdp_extended_mouse)
    set_tests_properties(
        x11.input-rdp-mousex-side-button-bounds-and-flag-denials PROPERTIES
        LABELS "x11;linux-adapter;security;input;offline"
        TIMEOUT 20)
    # R3-decoded signed 9-bit wheel units, vertical precedence, ignored
    # client coordinates and strict no-XTEST/offline mapping regression.
    add_executable(test_x11_rdp_wheel
        test_x11_rdp_wheel.cpp)
    target_link_libraries(test_x11_rdp_wheel PRIVATE
        rdp-server-linux-x11-authorized-input)
    target_compile_options(test_x11_rdp_wheel PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    add_test(NAME x11.input-rdp-wheel-sign-extension-axis-and-coordinate-denials
        COMMAND test_x11_rdp_wheel)
    set_tests_properties(
        x11.input-rdp-wheel-sign-extension-axis-and-coordinate-denials PROPERTIES
        LABELS "x11;linux-adapter;security;input;offline"
        TIMEOUT 20)
endif()

# R5's direct legacy route must match the active R10-owned protected
# slow-path callback: terminal injection failure never sends cleanup XTEST.
# No native session, GSS/PAM/logind lease or Xvfb is needed for this guard.
add_test(NAME x11.input-direct-route-native-failure-no-xtest
    COMMAND "${CMAKE_COMMAND}"
        "-DRDP_R5_AUTHORIZED_INPUT_SOURCE=${PROJECT_SOURCE_DIR}/src/x11/x11_authorized_input_route.cpp"
        -P "${PROJECT_SOURCE_DIR}/tests/check_x11_authorized_input_terminal_route.cmake")
set_tests_properties(
    x11.input-direct-route-native-failure-no-xtest PROPERTIES
    LABELS "x11;linux-adapter;security;input;offline;terminal")

# R10 production dependency handoff for R5's landed protected input bridge.
# This is source/build-graph evidence only: main must still not dispatch native
# input before the single post-Share R1 TPKT router is composed.
add_test(NAME runtime.linux-x11-authorized-input-production-linkage
    COMMAND "${CMAKE_COMMAND}"
        "-DRDP_ROOT_CMAKE=${PROJECT_SOURCE_DIR}/CMakeLists.txt"
        "-DRDP_RUNTIME_ENTRYPOINT_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/main.cpp"
        -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_linux_x11_authorized_input_linkage.cmake")
set_tests_properties(
    runtime.linux-x11-authorized-input-production-linkage PROPERTIES
    LABELS "runtime;security;native;x11;input;offline")

# R8 production dependency readiness plus dormant-route policy guard. The
# persistent R10 router/native lifetime now exists, so require the compiled
# composition while pinning its explicit production activation gate to false
# and keeping the first future acceptance Unicode-text-only.
add_test(NAME runtime.linux-x11-clipboard-production-linkage
    COMMAND "${CMAKE_COMMAND}"
        "-DRDP_ROOT_CMAKE=${PROJECT_SOURCE_DIR}/CMakeLists.txt"
        "-DRDP_RUNTIME_ENTRYPOINT_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/main.cpp"
        "-DRDP_LINUX_PREPARED_CLIPBOARD_HEADER=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_prepared_clipboard_owner.h"
        -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_linux_x11_clipboard_linkage.cmake")
set_tests_properties(
    runtime.linux-x11-clipboard-production-linkage PROPERTIES
    LABELS "runtime;clipboard;lifecycle;security;x11;offline;native-linkage")

# R5 R2/R3-authorized XTEST route. These cases use only ephemeral Xvfb and
# deliberately supply no admission lease. They prove both that native desktop
# freshness cannot authorize XTEST and that a mismatched geometry generation
# is terminal before input can cross into a replacement native owner.
if(TARGET rdp-server-linux-x11-authorized-input AND
   RDP_SERVER_XVFB_RUN_EXECUTABLE)
    add_executable(test_x11_authorized_input_route
        test_x11_authorized_input_route.cpp)
    target_link_libraries(test_x11_authorized_input_route PRIVATE
        rdp-server-linux-x11-authorized-input)
    target_compile_options(test_x11_authorized_input_route PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    add_test(NAME x11.input-admission-route-denials-and-revocation
        COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
            "-screen 0 1280x720x24 -nolisten tcp"
            $<TARGET_FILE:test_x11_authorized_input_route>)
    add_test(NAME x11.input-native-generation-mismatch-denial
        COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
            "-screen 0 1280x720x24 -nolisten tcp"
            $<TARGET_FILE:test_x11_authorized_input_route>
            generation-mismatch)
    add_test(NAME x11.input-policy-replacement-keyboard-denial
        COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
            "-screen 0 1280x720x24 -nolisten tcp"
            $<TARGET_FILE:test_x11_authorized_input_route>
            policy-replacement-keyboard)
    set_tests_properties(
        x11.input-admission-route-denials-and-revocation
        x11.input-native-generation-mismatch-denial
        x11.input-policy-replacement-keyboard-denial
        PROPERTIES LABELS "x11;linux-adapter;native;security;synthetic-display"
                   TIMEOUT 20)
endif()

# R8 Linux file-descriptor destination. These tests use ordinary files created
# only in CTest's build-root working directory; they never access a live
# clipboard or a user's file-manager destination.
if(TARGET rdp-server-linux-clipboard-file-destination)
    add_executable(test_linux_clipboard_file_destination
        test_linux_clipboard_file_destination.cpp)
    target_link_libraries(test_linux_clipboard_file_destination PRIVATE
        rdp-server-linux-clipboard-file-destination)
    target_compile_options(test_linux_clipboard_file_destination PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    foreach(case_name IN ITEMS
            linux-file-destination-streaming
            linux-file-destination-size-cancel
            linux-file-destination-denials)
        rdp_functional_ctest_name(functional_clipboard_test_name "clipboard.${case_name}")
        add_test(NAME "${functional_clipboard_test_name}"
            COMMAND test_linux_clipboard_file_destination "${case_name}")
        set_tests_properties("${functional_clipboard_test_name}" PROPERTIES
            LABELS "protocol;clipboard;linux-file-destination;native;offline")
    endforeach()
endif()

# R8 macOS file destination. Portable state runs through an injected native
# seam on every hosted OS; Apple additionally exercises the production POSIX
# descriptor callbacks against a build-root temporary file.
add_executable(test_macos_clipboard_file_destination
    test_macos_clipboard_file_destination.cpp)
target_link_libraries(test_macos_clipboard_file_destination PRIVATE
    rdp-server-macos-clipboard)
if(MSVC)
    target_compile_options(test_macos_clipboard_file_destination PRIVATE
        /W4 /UNDEBUG)
else()
    target_compile_options(test_macos_clipboard_file_destination PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
foreach(case_name IN ITEMS
        macos-file-destination-streaming
        macos-file-destination-size-cancel
        macos-file-destination-destructor-retirement
        macos-file-destination-write-generation-replacement
        macos-file-destination-finalization-generation-replacement
        macos-file-destination-denials
        macos-completed-file-url-handoff
        macos-completed-multi-file-url-handoff)
    rdp_functional_ctest_name(functional_clipboard_test_name "clipboard.${case_name}")
    add_test(NAME "${functional_clipboard_test_name}"
        COMMAND test_macos_clipboard_file_destination "${case_name}")
    set_tests_properties("${functional_clipboard_test_name}" PROPERTIES
        LABELS "protocol;clipboard;apple-file-destination;offline")
endforeach()
if(APPLE)
    add_test(NAME clipboard.macos-file-destination-native-descriptor
        COMMAND test_macos_clipboard_file_destination
            macos-file-destination-native-descriptor)
    set_tests_properties(
        clipboard.macos-file-destination-native-descriptor
        PROPERTIES LABELS "protocol;clipboard;apple-file-destination;native;offline")
endif()

# R8 macOS pasteboard presentation. Every case uses deterministic injected
# native operations on every CI OS; ordinary CTest never reads or mutates the
# host pasteboard. Apple additionally compile/links the dormant AppKit bridge.
add_executable(test_macos_clipboard_adapter
    test_macos_clipboard_adapter.cpp)
target_link_libraries(test_macos_clipboard_adapter PRIVATE
    rdp-server-macos-clipboard)
if(MSVC)
    target_compile_options(test_macos_clipboard_adapter PRIVATE /W4 /UNDEBUG)
else()
    target_compile_options(test_macos_clipboard_adapter PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
foreach(case_name IN ITEMS
        macos-clipboard-remote-ready-publication
        macos-clipboard-generation-owner-loss
        macos-clipboard-r3-retirement-source-epoch
        macos-clipboard-png-routing
        macos-clipboard-disconnect-owner-fence
        macos-clipboard-failure-reentry-denials)
    rdp_functional_ctest_name(functional_clipboard_test_name "clipboard.${case_name}")
    add_test(NAME "${functional_clipboard_test_name}"
        COMMAND test_macos_clipboard_adapter "${case_name}")
    # Keep native-adapter labeling narrower than broad platform preflights.
    set_tests_properties("${functional_clipboard_test_name}" PROPERTIES
        LABELS "protocol;clipboard;apple-clipboard-adapter;offline")
endforeach()

# R8 Windows file destination. The state machine uses injected native
# operations on every CI OS; Windows additionally runs one real HANDLE-backed
# build-root file case. No case derives a local path from remote metadata.
add_executable(test_windows_clipboard_file_destination
    test_windows_clipboard_file_destination.cpp)
target_link_libraries(test_windows_clipboard_file_destination PRIVATE
    rdp-server-windows-clipboard)
if(MSVC)
    target_compile_options(
        test_windows_clipboard_file_destination PRIVATE /W4 /UNDEBUG)
else()
    target_compile_options(
        test_windows_clipboard_file_destination PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
foreach(case_name IN ITEMS
        windows-file-destination-streaming
        windows-file-destination-size-cancel
        windows-file-destination-destructor-retirement
        windows-file-destination-write-generation-replacement
        windows-file-destination-finalization-generation-replacement
        windows-file-destination-denials
        windows-completed-file-hdrop-handoff
        windows-completed-multi-file-hdrop-handoff
        file-destination-plan-native-capability-integration
        windows-file-destination-source-epoch-revocation)
    rdp_functional_ctest_name(functional_clipboard_test_name "clipboard.${case_name}")
    add_test(NAME "${functional_clipboard_test_name}"
        COMMAND test_windows_clipboard_file_destination "${case_name}")
    set_tests_properties("${functional_clipboard_test_name}" PROPERTIES
        LABELS "protocol;clipboard;win32-file-destination;offline")
endforeach()
if(WIN32)
    add_test(NAME clipboard.windows-file-destination-native-handle
        COMMAND test_windows_clipboard_file_destination
            windows-file-destination-native-handle)
    set_tests_properties(
        clipboard.windows-file-destination-native-handle
        PROPERTIES LABELS "protocol;clipboard;win32-file-destination;native;offline")
endif()

# R8 Windows clipboard presentation. Every case uses deterministic injected
# native operations; no ordinary CTest opens or mutates the host clipboard.
# The same production source compiles the dormant Win32 bridge on Windows.
add_executable(test_windows_clipboard_adapter
    test_windows_clipboard_adapter.cpp)
target_link_libraries(test_windows_clipboard_adapter PRIVATE
    rdp-server-windows-clipboard)
if(MSVC)
    target_compile_options(test_windows_clipboard_adapter PRIVATE /W4 /UNDEBUG)
else()
    target_compile_options(test_windows_clipboard_adapter PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
foreach(case_name IN ITEMS
        windows-clipboard-remote-ready-publication
        windows-clipboard-generation-owner-loss
        windows-clipboard-r3-retirement-source-epoch
        windows-clipboard-png-dib-routing
        windows-clipboard-render-all-disconnect
        windows-clipboard-publication-midcallback-retirement
        windows-clipboard-failure-reentry-denials)
    rdp_functional_ctest_name(functional_clipboard_test_name "clipboard.${case_name}")
    add_test(NAME "${functional_clipboard_test_name}"
        COMMAND test_windows_clipboard_adapter "${case_name}")
    # Do not add the broad "windows" label: R6's target-only native
    # preflight intentionally runs -L windows before this executable is built.
    set_tests_properties("${functional_clipboard_test_name}" PROPERTIES
        LABELS "protocol;clipboard;win32-adapter;offline")
endforeach()

# R8 native X11 CLIPBOARD selection adapter. All cases use a deterministic
# native operation seam; they compile the real adapter without DISPLAY/Xvfb.
if(TARGET rdp-server-linux-x11-clipboard)
    add_rdp_test(test_x11_clipboard_adapter.cpp clipboard
        x11-selection-ownership-generation)
    target_link_libraries(test_x11_clipboard_adapter PRIVATE
        rdp-server-linux-x11-clipboard)
    target_compile_options(test_x11_clipboard_adapter PRIVATE
        -Wall -Wextra -Wpedantic -Werror)

    foreach(case_name IN ITEMS
            x11-targets-publication
            x11-selection-request-nonblocking
            x11-unicode-text-only-presentation
            x11-completed-file-uri-handoff
            x11-completed-multi-file-uri-handoff
            x11-selection-owner-loss
            x11-disconnect-late-paste-fence
            x11-incr-large-text-progression
            x11-incr-png-progression
            x11-incr-cancellation
            x11-incr-error-property-cleanup
            x11-r3-retirement-stale-incr-fence)
        rdp_functional_ctest_name(functional_clipboard_test_name "clipboard.${case_name}")
        add_test(NAME "${functional_clipboard_test_name}"
            COMMAND $<TARGET_FILE:test_x11_clipboard_adapter> "${case_name}")
        set_tests_properties("${functional_clipboard_test_name}" PROPERTIES
            LABELS "protocol;clipboard;x11;linux-adapter;native;offline")
    endforeach()
    set_tests_properties(
        clipboard.x11-selection-ownership-generation
        PROPERTIES LABELS "protocol;clipboard;x11;linux-adapter;native;offline")

    add_test(NAME runtime.clipboard-x11-restart-incr-isolation
        COMMAND $<TARGET_FILE:test_x11_clipboard_adapter>
            x11-disconnect-restart-stale-incr-isolation)
    set_tests_properties(runtime.clipboard-x11-restart-incr-isolation PROPERTIES
        LABELS "runtime;clipboard;lifecycle;security;x11;native;offline")
endif()

# R9 opt-in bounded coverage-guided wire fuzzing. This is deliberately
# absent from normal owner builds and uses only first-party production APIs.
if(RDP_SERVER_BUILD_FUZZERS)
    add_executable(fuzz_mcs_cliprdr fuzz_mcs_cliprdr.cpp)
    target_link_libraries(fuzz_mcs_cliprdr PRIVATE rdp-server-protocol)
    target_compile_options(fuzz_mcs_cliprdr PRIVATE
        -Wall -Wextra -Wpedantic -Werror
        -fsanitize=fuzzer,address,undefined
        -fno-omit-frame-pointer -fno-sanitize-recover=all)
    target_link_options(fuzz_mcs_cliprdr PRIVATE
        -fsanitize=fuzzer,address,undefined)
    set(rdp_fuzz_corpus_dir
        "${CMAKE_BINARY_DIR}/fuzz-corpus-mcs-cliprdr")
    set(rdp_fuzz_artifact_dir
        "${CMAKE_BINARY_DIR}/fuzz-artifacts-mcs-cliprdr")
    file(MAKE_DIRECTORY "${rdp_fuzz_corpus_dir}" "${rdp_fuzz_artifact_dir}")
    file(COPY "${PROJECT_SOURCE_DIR}/tests/fixtures/fuzz_mcs_cliprdr/"
        DESTINATION "${rdp_fuzz_corpus_dir}")
    add_test(NAME fuzz.mcs-cliprdr-bounded
        COMMAND fuzz_mcs_cliprdr
            "${rdp_fuzz_corpus_dir}"
            -runs=5000 -seed=12648430 -max_len=4096
            -rss_limit_mb=512 -malloc_limit_mb=64
            -timeout=2 -print_final_stats=1
            "-artifact_prefix=${rdp_fuzz_artifact_dir}/")
    set_tests_properties(fuzz.mcs-cliprdr-bounded PROPERTIES
        LABELS "fuzz;protocol;security;offline"
        TIMEOUT 30
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}")

    # R9 CredSSP parser/framing fuzzing stays separate from MCS/CLIPRDR so
    # either reproducer remains attributable and independently observable.
    add_executable(fuzz_credssp fuzz_credssp.cpp)
    target_link_libraries(fuzz_credssp PRIVATE rdp-server-protocol)
    target_compile_options(fuzz_credssp PRIVATE
        -Wall -Wextra -Wpedantic -Werror
        -fsanitize=fuzzer,address,undefined
        -fno-omit-frame-pointer -fno-sanitize-recover=all)
    target_link_options(fuzz_credssp PRIVATE
        -fsanitize=fuzzer,address,undefined)
    set(rdp_credssp_fuzz_corpus_dir
        "${CMAKE_BINARY_DIR}/fuzz-corpus-credssp")
    set(rdp_credssp_fuzz_artifact_dir
        "${CMAKE_BINARY_DIR}/fuzz-artifacts-credssp")
    file(MAKE_DIRECTORY
        "${rdp_credssp_fuzz_corpus_dir}"
        "${rdp_credssp_fuzz_artifact_dir}")
    file(COPY "${PROJECT_SOURCE_DIR}/tests/fixtures/fuzz_credssp/"
        DESTINATION "${rdp_credssp_fuzz_corpus_dir}")
    add_test(NAME fuzz.credssp-bounded
        COMMAND fuzz_credssp
            "${rdp_credssp_fuzz_corpus_dir}"
            -runs=5000 -seed=1592594996 -max_len=16384
            -rss_limit_mb=512 -malloc_limit_mb=64
            -timeout=2 -print_final_stats=1
            "-artifact_prefix=${rdp_credssp_fuzz_artifact_dir}/")
    set_tests_properties(fuzz.credssp-bounded PROPERTIES
        LABELS "fuzz;protocol;security;offline"
        TIMEOUT 30
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}")
endif()

add_test(NAME project.policy
    COMMAND "${CMAKE_COMMAND}"
        "-DRDP_SERVER_SOURCE_ROOT=${PROJECT_SOURCE_DIR}"
        -P "${PROJECT_SOURCE_DIR}/cmake/verify_project_policy.cmake")
set_tests_properties(project.policy PROPERTIES LABELS "project-policy")


# R4 genuine x264 producer tests. This executable links the noninstalled
# graphics target; portable protocol test binaries remain x264-free.
add_executable(test_x264_avc420_encoder test_x264_avc420_encoder.cpp)
target_link_libraries(test_x264_avc420_encoder PRIVATE rdp-server-graphics)
if(MSVC)
    target_compile_options(test_x264_avc420_encoder PRIVATE /W4 /UNDEBUG)
else()
    target_compile_options(test_x264_avc420_encoder PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
foreach(case_name IN ITEMS
        x264-nv12-annexb-picture
        x264-input-rejections
        x264-visible-crop-sequence
        x264-reset-reference-lifecycle
        x264-cfr-pts-passthrough)
    add_test(NAME "graphics.${case_name}"
        COMMAND test_x264_avc420_encoder "${case_name}")
    set_tests_properties("graphics.${case_name}" PROPERTIES
        LABELS "protocol;graphics;x264;offline")
endforeach()

# R4 production codec -> packetizer -> segmented-frame convergence. This
# remains noninstalled and links the native graphics target, not the SDK.
add_executable(test_x264_avc420_segmented_frame_producer
    test_x264_avc420_segmented_frame_producer.cpp)
target_link_libraries(test_x264_avc420_segmented_frame_producer PRIVATE
    rdp-server-graphics)
if(MSVC)
    target_compile_options(test_x264_avc420_segmented_frame_producer PRIVATE
        /W4 /UNDEBUG)
else()
    target_compile_options(test_x264_avc420_segmented_frame_producer PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
foreach(case_name IN ITEMS
        x264-segmented-delivery-continuity
        x264-segmented-surface-remap-idr
        x264-segmented-backpressure-preflight
        x264-segmented-metadata-preflight
        x264-segmented-owned-output-reuse-preflight
        x264-segmented-retirement-reuse
        x264-segmented-malformed-nv12-reference-continuity
        x264-segmented-duplicate-id-reference-continuity
        x264-segmented-abort-generation-reset
        x264-segmented-unsent-cancel-idr
        x264-segmented-external-cancel-idr
        x264-segmented-zero-frame-id-delivery
        x264-segmented-zero-surface-id-delivery
        x264-segmented-cfr-pts-reference-continuity
        bgra-nv12-bt709-pixel-oracle
        bgra-nv12-stride-padding-lifetime
        bgra-nv12-invalid-frame-denials
        bgra-nv12-reset-scratch-reuse
        x264-bgra-segmented-production-chain
        x264-bgra-backpressure-reference-denials
        x264-bgra-unsent-cancel-idr
        x264-native-bgra-frame-ingress
        x264-native-bgra-resize-recovery
        avc420-capture-generation-denials)
    add_test(NAME "graphics.${case_name}"
        COMMAND test_x264_avc420_segmented_frame_producer "${case_name}")
    set_tests_properties("graphics.${case_name}" PROPERTIES
        LABELS "protocol;graphics;x264;offline")
endforeach()

# R5 Linux server bundle install/verify/remove does not execute the payload
# or invoke service management, capture, XTEST or a TCP listener.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_Interpreter_FOUND)
        add_test(NAME packaging.linux-user-bundle-offline-lifecycle
            COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/tests/test_linux_server_bundle.py"
                "${PROJECT_SOURCE_DIR}/packaging/linux/server_test_bundle.py")
        set_tests_properties(packaging.linux-user-bundle-offline-lifecycle
            PROPERTIES LABELS "packaging;linux;security;offline" TIMEOUT 30)
    endif()
endif()

# R5 offline real-Qt packaging contracts tested using synthetic ELF fixtures.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND Python3_Interpreter_FOUND)
    add_test(NAME packaging.linux-gui-zip-offline-closure-and-modes
        COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/tests/test_linux_gui_bundle.py")
    set_tests_properties(packaging.linux-gui-zip-offline-closure-and-modes
        PROPERTIES LABELS "packaging;linux;gui;offline;security" TIMEOUT 30)
endif()

# R1 opt-in LAN listener: production socket/interface validation without
# creating a daemon, a second acceptor, SSL owner, or an OS admission lease.
add_executable(test_lan_listener test_lan_listener.cpp)
target_link_libraries(test_lan_listener PRIVATE rdp-server-protocol)
if(MSVC)
    target_compile_options(test_lan_listener PRIVATE /UNDEBUG)
else()
    target_compile_options(test_lan_listener PRIVATE -UNDEBUG)
endif()
add_test(NAME transport.lan-listener-native-bind-denials
    COMMAND test_lan_listener)
set_tests_properties(transport.lan-listener-native-bind-denials PROPERTIES
    LABELS "protocol;transport;native;security" TIMEOUT 20)
if(NOT WIN32)
    add_test(NAME transport.lan-listener-same-port-rebind-after-server-close
        COMMAND test_lan_listener same-port-rebind-after-server-close)
    set_tests_properties(
        transport.lan-listener-same-port-rebind-after-server-close PROPERTIES
        LABELS "protocol;transport;native;security;tls;listener;lifecycle"
        TIMEOUT 20
        SKIP_RETURN_CODE 77)
endif()

# R7 per-peer authentication failure is not host teardown. Pin the production
# Linux retirement boundary so a rejected remote client cannot revoke the
# configured Session Password or close the listener.
add_test(NAME runtime.linux-authentication-failure-retains-listener-and-credential-source
    COMMAND "${CMAKE_COMMAND}"
        "-DRDP_LINUX_HOST_CONTROL_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_host_control.cpp"
        "-DRDP_LINUX_CONNECTION_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_connection.cpp"
        -P "${PROJECT_SOURCE_DIR}/tests/check_linux_auth_failure_retention.cmake")
set_tests_properties(
    runtime.linux-authentication-failure-retains-listener-and-credential-source
    PROPERTIES LABELS "runtime;linux;admission;gui;credentials;authentication;security;offline")

# R7 layout/state tests run offscreen and never authorize real host start.
if(RDP_SERVER_BUILD_DESKTOP_GUI)
    add_executable(test_desktop_gui_offline test_desktop_gui_offline.cpp)
    target_link_libraries(test_desktop_gui_offline PRIVATE rdp-server-desktop-ui)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        # Verify real R10 denial/retirement through the shared R7 Qt view.
        target_link_libraries(test_desktop_gui_offline PRIVATE
            rdp-server-linux-host-control)
    elseif(APPLE)
        target_link_libraries(test_desktop_gui_offline PRIVATE
            rdp-server-macos-host-control)
    endif()
    if(MSVC)
        target_compile_options(test_desktop_gui_offline PRIVATE /W4 /UNDEBUG)
    else()
        target_compile_options(test_desktop_gui_offline PRIVATE
            -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    endif()
    # The test executable intentionally undefines NDEBUG so assertions remain
    # active in Release. Carry the UI build's actual acceptance-surface state
    # separately so Release tests do not mistake -UNDEBUG for a Debug UI.
    target_compile_definitions(test_desktop_gui_offline PRIVATE
        "$<$<OR:$<CONFIG:Debug>,$<BOOL:${RDP_SERVER_ENABLE_OWNER_ACCEPTANCE_UI}>>:RDP_SERVER_OWNER_ACCEPTANCE_TEST_UI=1>")

    # R5 owner-situation integration: production Linux HostControl plus
    # deterministic physical-X11 evidence, with the machine's real LAN
    # recommendation. It never authenticates, binds, captures or injects input.
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND
       TARGET rdp-server-linux-host-control)
        add_executable(test_linux_gui_physical_x11_precredential_readiness
            test_linux_gui_physical_x11_precredential_readiness.cpp)
        target_link_libraries(
            test_linux_gui_physical_x11_precredential_readiness PRIVATE
            rdp-server-desktop-ui rdp-server-linux-host-control)
        target_compile_options(
            test_linux_gui_physical_x11_precredential_readiness PRIVATE
            -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
        target_compile_definitions(
            test_linux_gui_physical_x11_precredential_readiness PRIVATE
            "$<$<OR:$<CONFIG:Debug>,$<BOOL:${RDP_SERVER_ENABLE_OWNER_ACCEPTANCE_UI}>>:RDP_SERVER_OWNER_ACCEPTANCE_TEST_UI=1>")
        add_test(
            NAME runtime.linux-gui-physical-x11-precredential-readiness
            COMMAND test_linux_gui_physical_x11_precredential_readiness)
        set_tests_properties(
            runtime.linux-gui-physical-x11-precredential-readiness PROPERTIES
            ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
            LABELS "runtime;gui;linux;native-desktop;acceptance;native-environment"
            SKIP_RETURN_CODE 77
            TIMEOUT 30)
    endif()

    add_test(NAME gui.offscreen-first-run-authorization-revocation
        COMMAND test_desktop_gui_offline)
    set_tests_properties(gui.offscreen-first-run-authorization-revocation PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security" TIMEOUT 30)
    # Window hiding is presentation-only; a future tray hide must not Stop
    # the one active R10/clipboard lifetime.
    add_test(NAME gui.offscreen-hide-preserves-active-sharing
        COMMAND test_desktop_gui_offline hide-preserves-sharing)
    set_tests_properties(gui.offscreen-hide-preserves-active-sharing
        PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security;runtime;clipboard;lifecycle" TIMEOUT 30)
    # R9 GUI Round 2: one standard Main/Advanced tab container, no wizard
    # or disclosure panel, and no implementation/diagnostic controls on Main.
    add_test(NAME gui.offscreen-round2-tabs-and-main-simplicity
        COMMAND test_desktop_gui_offline round2-tabs)
    set_tests_properties(gui.offscreen-round2-tabs-and-main-simplicity
        PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;product;round2;tabs" TIMEOUT 30)
    add_test(NAME gui.offscreen-round2-endpoint-refresh-fail-closed
        COMMAND test_desktop_gui_offline round2-endpoint-refresh)
    set_tests_properties(gui.offscreen-round2-endpoint-refresh-fail-closed
        PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;product;round2;lan" TIMEOUT 30)
    add_test(NAME gui.offscreen-round2-advanced-groups-scrollable
        COMMAND test_desktop_gui_offline round2-advanced-scroll)
    set_tests_properties(gui.offscreen-round2-advanced-groups-scrollable
        PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;product;round2;layout" TIMEOUT 30)
    # R7 post-qualification polish: the R10-recommended address is the primary
    # selectable connection value, and unsupported builds show one concise
    # default-page explanation instead of repeating the same denial.
    add_test(NAME gui.offscreen-recommended-address-prominence-and-unavailable-summary
        COMMAND test_desktop_gui_offline dashboard-polish)
    set_tests_properties(
        gui.offscreen-recommended-address-prominence-and-unavailable-summary
        PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;product;dashboard;accessibility" TIMEOUT 30)
    # Start/Stop intent never outranks the runtime's authoritative lifecycle.
    add_test(NAME gui.offscreen-authoritative-sharing-toggle
        COMMAND test_desktop_gui_offline toggle-authority)
    set_tests_properties(gui.offscreen-authoritative-sharing-toggle
        PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;product;runtime;lifecycle" TIMEOUT 30)
    add_test(NAME gui.offscreen-product-status-authority
        COMMAND test_desktop_gui_offline product-status-authority)
    set_tests_properties(gui.offscreen-product-status-authority
        PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;product;runtime;lifecycle;lan" TIMEOUT 30)
    # Closing while active hides only presentation; explicit Quit enters
    # Stop/Revoke first and cannot complete before authoritative retirement.
    add_test(NAME gui.offscreen-tray-close-hide-and-explicit-quit
        COMMAND test_desktop_gui_offline tray-lifecycle)
    set_tests_properties(gui.offscreen-tray-close-hide-and-explicit-quit
        PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;product;tray;lifecycle" TIMEOUT 30)
    add_test(NAME gui.offscreen-automatic-tls-preparation-order
        COMMAND test_desktop_gui_offline automatic-tls-preparation-order)
    set_tests_properties(gui.offscreen-automatic-tls-preparation-order
        PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security;runtime;tls" TIMEOUT 30)
    add_test(NAME gui.offscreen-control-adapter-denials
        COMMAND test_desktop_gui_offline runtime)
    set_tests_properties(gui.offscreen-control-adapter-denials PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security;runtime" TIMEOUT 30)
    add_test(NAME gui.offscreen-os-account-request-status-gate
        COMMAND test_desktop_gui_offline access)
    set_tests_properties(gui.offscreen-os-account-request-status-gate PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security;credentials" TIMEOUT 30)
    add_test(NAME gui.offscreen-owner-permission-scope-lifetime-forwarding
        COMMAND test_desktop_gui_offline access)
    set_tests_properties(
        gui.offscreen-owner-permission-scope-lifetime-forwarding PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security;runtime;consent" TIMEOUT 30)
    add_test(NAME gui.offscreen-owner-grant-observation
        COMMAND test_desktop_gui_offline owner-grant-observation)
    set_tests_properties(gui.offscreen-owner-grant-observation PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security;runtime;consent" TIMEOUT 30)
    add_test(NAME gui.offscreen-sharing-permission-product-language
        COMMAND test_desktop_gui_offline permission-product-language)
    set_tests_properties(gui.offscreen-sharing-permission-product-language
        PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;product;runtime;consent" TIMEOUT 30)
    add_test(NAME gui.offscreen-sharing-permission-requestability-gates-start
        COMMAND test_desktop_gui_offline permission-requestability-gates-sharing)
    set_tests_properties(
        gui.offscreen-sharing-permission-requestability-gates-start PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;product;runtime;consent;security" TIMEOUT 30)

    add_test(NAME gui.offscreen-positive-owner-workflow-presentation
        COMMAND test_desktop_gui_offline positive-workflow)
    set_tests_properties(gui.offscreen-positive-owner-workflow-presentation PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;presentation;runtime;consent" TIMEOUT 30)
    # The actual LAN endpoint and opaque clients must come from R10 status.
    # All interactions remain offscreen without socket/native side effects.
    add_test(NAME gui.offscreen-interface-endpoint-client-disconnect-denials
        COMMAND test_desktop_gui_offline lan-client)
    set_tests_properties(gui.offscreen-interface-endpoint-client-disconnect-denials
        PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security;runtime" TIMEOUT 30)
    # R10 peer, endpoint and interface data must remain literal Qt text.
    add_test(NAME gui.offscreen-runtime-peer-and-endpoint-plain-text
        COMMAND test_desktop_gui_offline plain-runtime-text)
    set_tests_properties(gui.offscreen-runtime-peer-and-endpoint-plain-text
        PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security;runtime" TIMEOUT 30)
    # R10's unique stable-ID/real-address policy also gates GUI choices.
    add_test(NAME gui.offscreen-selected-lan-endpoint-preflight-denials
        COMMAND test_desktop_gui_offline r10-lan-selector)
    set_tests_properties(gui.offscreen-selected-lan-endpoint-preflight-denials
        PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security;runtime;lan" TIMEOUT 30)
    # R1's typed identity evidence must never be mistaken for client
    # trust, host consent or an authenticated listener.
    add_test(NAME gui.offscreen-tls-fingerprint-rotation-and-denials
        COMMAND test_desktop_gui_offline tls-identity)
    set_tests_properties(gui.offscreen-tls-fingerprint-rotation-and-denials
        PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security;runtime;tls" TIMEOUT 30)
    # Terminal R2 authority loss must suppress stale listener readiness.
    add_test(NAME gui.offscreen-terminal-listener-readiness-denials
        COMMAND test_desktop_gui_offline terminal-listener)
    set_tests_properties(gui.offscreen-terminal-listener-readiness-denials
        PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security;runtime;status" TIMEOUT 30)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        # Real R10 shell; no fake consent, native desktop or socket.
        add_test(NAME gui.offscreen-linux-concrete-host-control-denials
            COMMAND test_desktop_gui_offline linux-real-host-control)
        set_tests_properties(gui.offscreen-linux-concrete-host-control-denials
            PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
            LABELS "gui;linux;offline;security;runtime" TIMEOUT 30)
    elseif(APPLE)
        add_test(NAME gui.offscreen-macos-gui-parity-and-widget-properties
            COMMAND test_desktop_gui_offline macos-gui-parity)
        set_tests_properties(gui.offscreen-macos-gui-parity-and-widget-properties
            PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
            LABELS "gui;macos;offline;acceptance;round2"
            SKIP_RETURN_CODE 77 TIMEOUT 30)

        add_test(NAME gui.offscreen-macos-concrete-host-control-acceptance
            COMMAND test_desktop_gui_offline macos-real-host-control)
        set_tests_properties(gui.offscreen-macos-concrete-host-control-acceptance
            PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
            LABELS "gui;macos;offline;security;runtime"
            SKIP_RETURN_CODE 77 TIMEOUT 30)
    endif()
    # R2 terminal session loss must not bypass the R10 raw-stage Stop guard.
    add_test(NAME gui.offscreen-lifecycle-and-terminal-close-denials
        COMMAND test_desktop_gui_offline lifecycle-stages)
    set_tests_properties(gui.offscreen-lifecycle-and-terminal-close-denials
        PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security;runtime;status" TIMEOUT 30)
    # Public Release capability remains false, while Debug/explicit owner
    # acceptance builds expose the exact production standalone path.
    # The standalone credential relationship must be explicit on Main without
    # retaining or exposing the Session Password after runtime handoff.
    add_test(NAME gui.offscreen-rdp-client-credential-guidance
        COMMAND test_desktop_gui_offline rdp-client-credential-guidance)
    set_tests_properties(gui.offscreen-rdp-client-credential-guidance
        PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;product;credentials;authentication;security"
        TIMEOUT 30)


    # With an already-configured memory-only credential, editing the
    # non-secret Username must require an explicit password replacement,
    # never silently present a different configured client identifier.
    add_test(NAME gui.offscreen-configured-username-change-requires-password
        COMMAND test_desktop_gui_offline configured-username-replacement)
    set_tests_properties(
        gui.offscreen-configured-username-change-requires-password PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;product;credentials;authentication;security;lifecycle"
        TIMEOUT 30)

    add_test(NAME gui.offscreen-independent-password-workflow-unavailable
        COMMAND test_desktop_gui_offline unsupported-password)
    set_tests_properties(gui.offscreen-independent-password-workflow-unavailable
        PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security;credentials;acceptance" TIMEOUT 30)

    add_test(NAME gui.offscreen-owner-acceptance-editor-properties
        COMMAND test_desktop_gui_offline owner-acceptance-editor-properties)
    set_tests_properties(
        gui.offscreen-owner-acceptance-editor-properties PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;product;credentials;acceptance;editability;parity"
        SKIP_RETURN_CODE 77
        TIMEOUT 30)

    # R9 owner-reported usability regression. Unlike the property-only case,
    # this drives real Qt key events and the listener-authoritative UI flow.
    add_test(NAME gui.offscreen-owner-acceptance-credential-editor-parity
        COMMAND test_desktop_gui_offline owner-gui-credential-parity)
    set_tests_properties(
        gui.offscreen-owner-acceptance-credential-editor-parity PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;product;credentials;acceptance;editability;parity;assurance;lifecycle"
        SKIP_RETURN_CODE 77
        TIMEOUT 30)

    add_test(NAME gui.offscreen-debug-owner-acceptance-keeps-release-gate-closed
        COMMAND test_desktop_gui_offline debug-owner-acceptance-release-gate)
    set_tests_properties(
        gui.offscreen-debug-owner-acceptance-keeps-release-gate-closed PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;product;credentials;acceptance;release-gate;security"
        SKIP_RETURN_CODE 77
        TIMEOUT 30)

    add_test(NAME gui.offscreen-owner-acceptance-consumer-start-orchestration
        COMMAND test_desktop_gui_offline consumer-workflow)
    set_tests_properties(
        gui.offscreen-owner-acceptance-consumer-start-orchestration PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;product;credentials;acceptance;lifecycle"
        SKIP_RETURN_CODE 77
        TIMEOUT 30)

    add_test(NAME gui.offscreen-owner-acceptance-password-stop-restart-reuses-memory-credential
        COMMAND test_desktop_gui_offline consumer-password-stop-restart)
    set_tests_properties(
        gui.offscreen-owner-acceptance-password-stop-restart-reuses-memory-credential
        PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;product;credentials;acceptance;lifecycle;consent"
        SKIP_RETURN_CODE 77
        TIMEOUT 30)

    add_test(NAME gui.offscreen-admission-failure-reason-product-diagnostic
        COMMAND test_desktop_gui_offline admission-failure-reason-product-diagnostic)
    set_tests_properties(
        gui.offscreen-admission-failure-reason-product-diagnostic PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;authentication;admission;diagnostics;runtime"
        TIMEOUT 30)

    # R7 consumes only R10's lifetime-fenced final-authInfo reason.
    # Main/Activity stay generic; Advanced/export are bounded and redacted.
    add_test(NAME gui.offscreen-authinfo-typed-advanced-only-and-generation-retirement
        COMMAND test_desktop_gui_offline
            authinfo-typed-advanced-only-and-generation-retirement)
    set_tests_properties(
        gui.offscreen-authinfo-typed-advanced-only-and-generation-retirement
        PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;authentication;diagnostics;security;lifecycle"
        TIMEOUT 30)

    # Advanced connection-security details are display-only and may use only
    # bounded facts supplied by R10/R1, never inference or bypass controls.
    add_test(NAME gui.offscreen-advanced-runtime-security-diagnostics
        COMMAND test_desktop_gui_offline
            advanced-runtime-security-diagnostics)
    set_tests_properties(gui.offscreen-advanced-runtime-security-diagnostics
        PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security;tls;diagnostics" TIMEOUT 30)

    # R7 may render only the redacted Type-1 VERSION structure already
    # projected by R10. It must remain Advanced-only and non-authorizing.
    add_test(NAME gui.offscreen-advanced-runtime-type1-structural-profile
        COMMAND test_desktop_gui_offline
            advanced-runtime-type1-structural-profile)
    set_tests_properties(
        gui.offscreen-advanced-runtime-type1-structural-profile
        PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security;authentication;diagnostics"
        TIMEOUT 30)

    add_test(NAME gui.offscreen-configured-username-runtime-projection
        COMMAND test_desktop_gui_offline
            configured-username-runtime-projection)
    add_test(NAME gui.offscreen-advanced-authentication-diagnostics-export-redaction
        COMMAND test_desktop_gui_offline
            advanced-authentication-diagnostics-export-redaction)
    add_test(NAME gui.offscreen-authentication-first-failure-classification
        COMMAND test_desktop_gui_offline
            authentication-first-failure-classification)
    add_test(NAME gui.offscreen-authentication-diagnostics-connection-replacement
        COMMAND test_desktop_gui_offline
            authentication-diagnostics-connection-replacement)
    # A post-Type-3 authInfo failure cannot contaminate another client.
    add_test(NAME gui.offscreen-authinfo-failure-connection-replacement-redaction
        COMMAND test_desktop_gui_offline
            authinfo-failure-connection-replacement-redaction)
    set_tests_properties(
        gui.offscreen-configured-username-runtime-projection
        gui.offscreen-advanced-authentication-diagnostics-export-redaction
        gui.offscreen-authentication-first-failure-classification
        gui.offscreen-authentication-diagnostics-connection-replacement
        gui.offscreen-authinfo-failure-connection-replacement-redaction
        PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security;authentication;diagnostics;lifecycle"
        TIMEOUT 30)

    add_test(NAME gui.offscreen-authentication-incomplete-before-native-admission
        COMMAND test_desktop_gui_offline
            authentication-incomplete-before-native-admission)
    set_tests_properties(
        gui.offscreen-authentication-incomplete-before-native-admission
        PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;product;credentials;authentication;diagnostics;lifecycle"
        TIMEOUT 30)

    add_test(NAME gui.offscreen-authentication-challenge-disconnect-product-language
        COMMAND test_desktop_gui_offline
            authentication-incomplete-before-native-admission)
    set_tests_properties(
        gui.offscreen-authentication-challenge-disconnect-product-language
        PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;product;authentication;diagnostics;lifecycle"
        TIMEOUT 30)

    add_test(NAME gui.offscreen-owner-authentication-failure-product-language-and-retention
        COMMAND test_desktop_gui_offline authentication-failure-product-language)
    set_tests_properties(
        gui.offscreen-owner-authentication-failure-product-language-and-retention
        PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;product;credentials;authentication;diagnostics;lifecycle"
        SKIP_RETURN_CODE 77
        TIMEOUT 30)

    add_test(NAME gui.offscreen-owner-acceptance-password-change-rerequests-owner-permission
        COMMAND test_desktop_gui_offline consumer-password-change-rerequests-permission)
    set_tests_properties(
        gui.offscreen-owner-acceptance-password-change-rerequests-owner-permission
        PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;product;credentials;acceptance;consent;lifecycle;security"
        SKIP_RETURN_CODE 77
        TIMEOUT 30)

    add_test(NAME gui.offscreen-owner-acceptance-start-failure-rolls-back
        COMMAND test_desktop_gui_offline consumer-workflow-failure)
    set_tests_properties(
        gui.offscreen-owner-acceptance-start-failure-rolls-back PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;product;credentials;acceptance;failure"
        SKIP_RETURN_CODE 77
        TIMEOUT 30)

    add_test(NAME gui.offscreen-owner-acceptance-listener-start-failure-keeps-clipboard-dormant
        COMMAND test_desktop_gui_offline
            consumer-listener-start-failure-clipboard-dormant)
    set_tests_properties(
        gui.offscreen-owner-acceptance-listener-start-failure-keeps-clipboard-dormant
        PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;product;credentials;acceptance;failure;clipboard;lifecycle;security"
        SKIP_RETURN_CODE 77
        TIMEOUT 30)
    # Public Release keeps the prequalification surface disabled. Debug uses
    # !NDEBUG; an explicit owner-acceptance Release build uses the CMake option
    # and must execute the same behavior suite rather than silently skipping it.
    if(NOT RDP_SERVER_ENABLE_OWNER_ACCEPTANCE_UI)
        set_tests_properties(
            gui.offscreen-owner-acceptance-editor-properties
            gui.offscreen-owner-acceptance-credential-editor-parity
            gui.offscreen-debug-owner-acceptance-keeps-release-gate-closed
            gui.offscreen-owner-acceptance-consumer-start-orchestration
            gui.offscreen-owner-acceptance-password-stop-restart-reuses-memory-credential
            gui.offscreen-owner-authentication-failure-product-language-and-retention
            gui.offscreen-owner-acceptance-password-change-rerequests-owner-permission
            gui.offscreen-owner-acceptance-start-failure-rolls-back
            gui.offscreen-owner-acceptance-listener-start-failure-keeps-clipboard-dormant
            PROPERTIES CONFIGURATIONS Debug)
    endif()

    # R10 client authentication cannot be presented as a connected desktop.
    # Stale endpoint/peer fields are cleared by the Qt projection on Stop.
    add_test(NAME gui.offscreen-client-stage-and-retirement-status-denials
        COMMAND test_desktop_gui_offline client-stage)
    set_tests_properties(gui.offscreen-client-stage-and-retirement-status-denials
        PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security;runtime;clients" TIMEOUT 30)
    # R7 must not project Graphics control as a visible native desktop.
    add_test(NAME gui.offscreen-graphics-native-desktop-projection
        COMMAND test_desktop_gui_offline graphics-native-status)
    set_tests_properties(gui.offscreen-graphics-native-desktop-projection
        PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security;runtime;clients;graphics" TIMEOUT 30)
    add_test(NAME gui.offscreen-local-username-default-keeps-session-password-empty
        COMMAND test_desktop_gui_offline local-username-default-no-password-prefill)
    set_tests_properties(
        gui.offscreen-local-username-default-keeps-session-password-empty
        PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;credentials;security;portability;product;offline"
        TIMEOUT 30)

    add_test(NAME gui.offscreen-product-hosting-listener-readiness
        COMMAND test_desktop_gui_offline product-hosting-listener-readiness)
    set_tests_properties(gui.offscreen-product-hosting-listener-readiness
        PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;product;runtime;lifecycle" TIMEOUT 30)
    # The runtime-label fixture also needs to prohibit transient rich-text
    # parsing before QLabel receives its explicit PlainText mode.
    add_test(NAME gui.runtime-label-plain-before-text-assignment
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_GUI_SOURCE=${PROJECT_SOURCE_DIR}/src/gui/desktop_window.cpp"
            -P "${PROJECT_SOURCE_DIR}/tests/check_gui_plain_text_factory.cmake")
    set_tests_properties(gui.runtime-label-plain-before-text-assignment
        PROPERTIES LABELS "gui;offline;security;runtime" TIMEOUT 30)
endif()

# R9 separate PORTABLE-GUI archive integrity contract; no listener, auth,
# native desktop, or GUI process is started by these synthetic ZIP fixtures.
add_test(NAME packaging.portable-gui-archive-integrity-denials
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/test_portable_gui_archive.py")
set_tests_properties(packaging.portable-gui-archive-integrity-denials
    PROPERTIES LABELS "packaging;gui;security;offline" TIMEOUT 30)

# R6 synthetic native PATH sanitizer check; real exact-ZIP Windows smoke is CI.
if(WIN32)
    find_program(RDP_SERVER_WINDOWS_POWERSHELL NAMES powershell.exe)
    if(NOT RDP_SERVER_WINDOWS_POWERSHELL)
        message(FATAL_ERROR "Windows PowerShell required for GUI path check")
    endif()
    add_test(NAME windows.gui-portable-clean-loader-environment-denials
        COMMAND "${RDP_SERVER_WINDOWS_POWERSHELL}" -NoProfile -NonInteractive
            -ExecutionPolicy Bypass -File
            "${PROJECT_SOURCE_DIR}/scripts/smoke_windows_portable_gui_clean.ps1"
            -EnvironmentSelfTest)
    set_tests_properties(windows.gui-portable-clean-loader-environment-denials
        PROPERTIES LABELS "windows;gui;packaging;security;offline" TIMEOUT 20)
endif()

# R6 Windows PORTABLE-GUI builder contract. Synthetic PE fixtures run on
# every host; native windeployqt/launch/PE-import closure remains Windows CI.
add_test(NAME windows.gui-portable-zip-integrity-path-uninstall-denials
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/test_windows_gui_bundle.py")
set_tests_properties(windows.gui-portable-zip-integrity-path-uninstall-denials
    PROPERTIES LABELS "windows;packaging;gui;security;offline" TIMEOUT 30)

# Canonical runtime spellings must fail closed independently of host
# filesystem case semantics.
add_test(NAME windows.gui-portable-canonical-runtime-name-denials
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/test_windows_gui_bundle.py"
        WindowsGuiBundleTests.test_case_alias_and_wrong_output_name_are_rejected)
set_tests_properties(windows.gui-portable-canonical-runtime-name-denials
    PROPERTIES LABELS "windows;packaging;gui;security;offline" TIMEOUT 15)

# R6 stages the recursive non-system DLL closure after windeployqt. The
# synthetic resolver proves package inclusion without executing host PE tools.
add_test(NAME windows.gui-portable-runtime-dependency-staging
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/test_windows_gui_bundle.py"
        WindowsGuiBundleTests.test_resolved_non_system_runtime_dlls_are_staged)
set_tests_properties(windows.gui-portable-runtime-dependency-staging
    PROPERTIES LABELS "windows;packaging;gui;security;offline" TIMEOUT 15)

# R6 native offline state comparison is exercised without a GUI, network,
# service change or administrative privilege. The packaged GUI smoke uses
# the same production comparison against read-only Windows snapshots.
if(WIN32)
    add_test(NAME windows.gui-offline-system-state-mutation-denials
        COMMAND powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass
            -File "${PROJECT_SOURCE_DIR}/scripts/smoke_windows_portable_gui.ps1"
            -SnapshotContractTest)
    set_tests_properties(windows.gui-offline-system-state-mutation-denials
        PROPERTIES LABELS "windows;packaging;gui;security;offline" TIMEOUT 20)
endif()

# R9 portable recursive PE-import closure is pure Python on every host; native
# llvm-objdump execution is performed by the Windows CLANG64 CI lane.
add_test(NAME windows.gui-native-pe-closure-contract
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/tests/test_windows_pe_closure.py")
set_tests_properties(windows.gui-native-pe-closure-contract
    PROPERTIES LABELS "windows;packaging;gui;security;offline" TIMEOUT 20)

# R5 read-only Linux GUI preflight has no R2 lease/selection or X11 owner.
# The production parser is linked to the optional Qt desktop shell.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND RDP_SERVER_BUILD_DESKTOP_GUI)
    add_executable(test_linux_gui_prerequisites
        test_linux_gui_prerequisites.cpp)
    target_link_libraries(test_linux_gui_prerequisites PRIVATE
        rdp-server-desktop-ui)
    target_compile_options(test_linux_gui_prerequisites PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    add_test(NAME gui.linux-readonly-seat0-prerequisite-denials
        COMMAND test_linux_gui_prerequisites)
    add_test(NAME gui.linux-readonly-prerequisite-structured-projection
        COMMAND test_linux_gui_prerequisites structured-projection)
    add_test(NAME gui.linux-prerequisite-probe-readonly-boundary
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_LINUX_PREREQUISITE_SOURCE=${PROJECT_SOURCE_DIR}/src/gui/linux_prerequisites.cpp"
            -P "${PROJECT_SOURCE_DIR}/tests/check_linux_gui_prerequisite_readonly.cmake")
    set_tests_properties(
        gui.linux-readonly-seat0-prerequisite-denials
        gui.linux-readonly-prerequisite-structured-projection
        gui.linux-prerequisite-probe-readonly-boundary PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;linux;native-preflight;security;offline" TIMEOUT 20)
endif()


# Agent/road ownership names are internal coordination only, not CTest labels.
add_test(NAME project.ctest-durable-label-taxonomy
    COMMAND "${CMAKE_COMMAND}"
        "-DRDP_TEST_REGISTRY=${PROJECT_SOURCE_DIR}/tests/CMakeLists.txt"
        -P "${PROJECT_SOURCE_DIR}/tests/check_ctest_label_taxonomy.cmake")
set_tests_properties(project.ctest-durable-label-taxonomy PROPERTIES
    LABELS "project-policy;testing;offline")

# Source-level policy catches literal names/labels; this resolved registry check
# also catches names assembled from behavior case variables.
get_property(rdp_registered_test_names DIRECTORY PROPERTY TESTS)
foreach(rdp_registered_test_name IN LISTS rdp_registered_test_names)
    if(rdp_registered_test_name MATCHES "(^|[._-])r(10|[1-9])([._-]|$)")
        message(FATAL_ERROR
            "CTest name contains internal agent ownership taxonomy: "
            "${rdp_registered_test_name}")
    endif()
    get_property(rdp_registered_test_labels
        TEST "${rdp_registered_test_name}" PROPERTY LABELS)
    foreach(rdp_registered_test_label IN LISTS rdp_registered_test_labels)
        if(rdp_registered_test_label MATCHES "^r(10|[1-9])($|[-_.])")
            message(FATAL_ERROR
                "CTest label contains internal agent ownership taxonomy: "
                "${rdp_registered_test_name}: ${rdp_registered_test_label}")
        endif()
    endforeach()
endforeach()
