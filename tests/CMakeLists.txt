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
        ntlmssp-negotiate-challenge-framing
        ntlmssp-microsoft-authenticate-bridge
        ntlmssp-security-buffer-mic-denials)
    add_test(NAME "security.${ntlmssp_case}"
        COMMAND test_standalone_ntlmssp "${ntlmssp_case}")
    set_tests_properties("security.${ntlmssp_case}" PROPERTIES
        LABELS "security;credentials;ntlmv2;ntlmssp;credssp;offline")
endforeach()

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
        -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_desktop_configuration_feed.cmake")
set_tests_properties(runtime.desktop-shared-configuration-feed PROPERTIES
    LABELS "runtime;configuration;gui;r10-host-control;offline")

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
        PROPERTIES LABELS "runtime;security;r10-listener;offline")
endif()

# Three offline native R10 HostControl lifetime/denial regressions.
if(TARGET rdp-server-linux-host-control)
    add_executable(test_linux_runtime_host_control
        test_linux_runtime_host_control.cpp)
    target_link_libraries(test_linux_runtime_host_control PRIVATE
        rdp-server-linux-host-control)
    target_compile_options(test_linux_runtime_host_control PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    foreach(host_control_case IN ITEMS
            linux-host-control-no-consent-start-denials
            linux-host-control-revalidated-interface-denials
            linux-host-control-rejected-selection-retires-previous
            linux-host-control-native-interface-id-verification
            linux-host-control-stop-revoke-retirement)
        add_test(NAME "runtime.${host_control_case}"
            COMMAND test_linux_runtime_host_control "${host_control_case}")
        set_tests_properties("runtime.${host_control_case}" PROPERTIES
            LABELS "runtime;security;r10-host-control;offline"
            SKIP_RETURN_CODE 77)
    endforeach()
    add_test(NAME runtime.linux-host-control-r2-authority-lifetime-handoff
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_LINUX_HOST_CONTROL_HEADER=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_host_control.h"
            "-DRDP_LINUX_HOST_CONTROL_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_host_control.cpp"
            "-DRDP_LINUX_CONNECTION_HEADER=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_connection.h"
            "-DRDP_LINUX_CONNECTION_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/linux_runtime_connection.cpp"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_host_owner_authority_handoff.cmake")
    set_tests_properties(
        runtime.linux-host-control-r2-authority-lifetime-handoff PROPERTIES
        LABELS "runtime;security;r2-owner-consent;r10-host-control;offline")
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
        LABELS "runtime;security;r1-tls;r2-owner-consent;r10-host-control;offline")
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
        host-control-clipboard-state-denials
        host-control-credential-setup-denials
        host-control-selected-lan-interface-denials
        host-control-authentication-outcome-denials)
    add_test(NAME "runtime.${host_control_case}"
        COMMAND test_runtime_host_control "${host_control_case}")
    set_tests_properties("runtime.${host_control_case}" PROPERTIES
        LABELS "runtime;security;host-control;offline")
endforeach()

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
        owner-consent-invalid-native-evidence-denials
        owner-consent-stop-lock-logout-switch-replacement-revocations
        owner-consent-credential-expiry-native-loss-revocations)
    add_test(NAME "security.${owner_consent_case}"
        COMMAND test_current_owner_sharing_authority "${owner_consent_case}")
    set_tests_properties("security.${owner_consent_case}" PROPERTIES
        LABELS "security;r2-owner-consent;offline" TIMEOUT 15)
endforeach()

find_package(Python3 REQUIRED COMPONENTS Interpreter)

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
            add_test(NAME "transport.${case_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("transport.${case_name}" PROPERTIES
                LABELS "protocol;transport")
        endforeach()
    elseif(test_target STREQUAL "test_owned_preauth_session")
        # Seventeen behavior groups from ONE existing executable: no duplicate
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
                credssp-r1-owned-framing
                credssp-r1-owned-reply
                credssp-tls-certificate-pinning
                credssp-tls-reply-wire
                credssp-tls-reply-backpressure
                credssp-tls-reply-rejections
                credssp-tls-reply-cert-pending
                credssp-tls-reply-cert-completion
                credssp-tls-reply-cert-backpressure
                credssp-tls-failure-reply-wire
                credssp-tls-failure-reply-rejections)
            add_test(NAME "transport.${case_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("transport.${case_name}" PROPERTIES
                LABELS "protocol;transport")
        endforeach()
        # Dedicated real TLS reader→writer interleaving regression; keep
        # outside R9's fixed-count generic transport sanitizer inventory.
        add_test(NAME transport.tcp-owned-tls-read-want-interleaved-frame-write
            COMMAND "${test_target}" "tcp-owned-tls-read-want-interleaved-frame-write")
        set_tests_properties(
            transport.tcp-owned-tls-read-want-interleaved-frame-write
            PROPERTIES LABELS "r1-tls-interleave;security;offline" TIMEOUT 20)
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
                credssp-active-tls-binding-positive
                credssp-active-tls-binding-rejections
                credssp-tls-release-certificate-denial)
            add_test(NAME "security.${case_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("security.${case_name}" PROPERTIES
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
                gssapi-native-admission-r1-nla-provenance-denials
                gssapi-credssp-delegated-account-origin-denials
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
            add_test(NAME "security.${case_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("security.${case_name}" PROPERTIES
                LABELS "security;linux-provider")
        endforeach()
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
            add_test(NAME "security.${case_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("security.${case_name}" PROPERTIES
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
                channel-lifecycle-ordering
                channel-lifecycle-denials
                surface-resize-revocation
                frame-publication-backpressure
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
            add_test(NAME "clipboard.${case_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("clipboard.${case_name}" PROPERTIES
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
        PROPERTIES LABELS "protocol;r3-demand-active;offline")
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
        LABELS "protocol;transport;r3-cliprdr;security;offline")
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
        source-request-receipt
        missing-activated-route-denial
        old-route-generation-retirement
        partial-positive-receipt-retirement
        filecontents-request-receipt)
    add_test(NAME "clipboard.r3-bridge-${case_name}"
        COMMAND test_r8_r3_clipboard_bridge "${case_name}")
    set_tests_properties("clipboard.r3-bridge-${case_name}" PROPERTIES
        LABELS "protocol;clipboard;r8-r3;security;offline")
endforeach()

# Stable R2-committed scalars require no R3 borrowed span after mutation.
# This ordinary test is outside the fixed 87 clipboard sanitizer selection.
add_test(NAME runtime.r8-r3-stable-scalar-write-receipt
    COMMAND test_r8_r3_clipboard_bridge
        stable-scalar-receipt-after-r3-mutation)
set_tests_properties(runtime.r8-r3-stable-scalar-write-receipt
    PROPERTIES LABELS "runtime;security;r8-receipt;offline")

# A delayed old R3 positive receipt may not revoke a reconnected R8 route.
# This ordinary CTest is outside the fixed 87 clipboard sanitizer selection.
add_test(NAME runtime.r8-r3-retired-route-positive-receipt-isolation
    COMMAND test_r8_r3_clipboard_bridge
        retired-route-positive-receipt-isolation)
set_tests_properties(runtime.r8-r3-retired-route-positive-receipt-isolation
    PROPERTIES LABELS "runtime;security;r8-receipt;offline")

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
# only this existing executable links R10's noninstalled runtime TLS owner.
target_link_libraries(test_owned_preauth_session PRIVATE
    rdp-server-runtime-tls)
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
            add_test(NAME "security.${case_name}"
                COMMAND test_owned_preauth_session "${case_name}")
            set_tests_properties("security.${case_name}"
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
            gssapi-r1-owned-credssp-provenance-fence
            gssapi-r1-owned-binding-delivery-fence
            gssapi-credssp-authinfo-terminal-denials
            gssapi-r1-owned-credssp-cancellation-fence
            gssapi-r1-owned-completed-frame-cancellation-fence
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
        add_test(NAME "security.${case_name}"
            COMMAND test_owned_preauth_session "${case_name}")
        set_tests_properties("security.${case_name}" PROPERTIES
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
    add_test(NAME "clipboard.${case_name}"
        COMMAND test_owned_remote_transfer "${case_name}")
    set_tests_properties("clipboard.${case_name}" PROPERTIES
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
        add_test(NAME "security.${case_name}"
            COMMAND test_linux_pam_password_verifier "${case_name}")
        set_tests_properties("security.${case_name}" PROPERTIES
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
    set_tests_properties(security.linux-seat0-session-identity-denials PROPERTIES
        LABELS "security;linux-provider;offline;seat0-revocation")

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
    target_include_directories(test_runtime_linux_security PRIVATE
        "${RDP_SERVER_TEST_KRB5_INCLUDE_DIR}")
    target_link_libraries(test_runtime_linux_security PRIVATE
        rdp-server-linux-runtime-security
        "${RDP_SERVER_TEST_KRB5_LIBRARY}"
        "${RDP_SERVER_TEST_K5CRYPTO_LIBRARY}")
    target_compile_options(test_runtime_linux_security PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    foreach(runtime_linux_security_case IN ITEMS
            linux-security-explicit-keytab-continuity
            linux-security-personal-desktop-preflight-denials
            linux-security-access-policy-replacement-revocation
            linux-security-keytab-snapshot-mutation-continuity
            linux-security-keytab-policy-denials
            linux-connection-credssp-owner-framing
            linux-connection-credssp-progress-accounting
            linux-connection-r1-acceptance-diagnostics
            linux-connection-pre-admission-dispatch
            linux-connection-pre-admission-native-poll
            linux-connection-native-poll-expiry-revocation
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
            linux-connection-personal-license-request-r1-write-denials
            linux-connection-personal-client-licensing-r1-intake-denials
            linux-connection-personal-valid-client-r1-write-denials
            linux-connection-personal-share-r1-io-denials
            linux-connection-personal-graphics-dvc-r1-io-denials
            linux-connection-existing-cal-unadmitted-denial)
        add_test(NAME "runtime.${runtime_linux_security_case}"
            COMMAND test_runtime_linux_security
                "${runtime_linux_security_case}"
                "${PROJECT_BINARY_DIR}/runtime-linux-security-fixtures")
        set_tests_properties("runtime.${runtime_linux_security_case}" PROPERTIES
            LABELS "runtime;security;linux-provider;offline")
    endforeach()

    # Dedicated production-runtime R2/R3 classifier gateway denial: the
    # existing Linux runtime executable receives no synthetic native lease.
    # Keep this outside R9's fixed 40-case legacy sanitizer selector.
    add_test(NAME runtime.linux-connection-personal-post-share-classifier-authority-denials
        COMMAND test_runtime_linux_security
            "linux-connection-personal-post-share-classifier-authority-denials"
            "${PROJECT_BINARY_DIR}/runtime-linux-security-fixtures")
    set_tests_properties(
        runtime.linux-connection-personal-post-share-classifier-authority-denials
        PROPERTIES LABELS "runtime;security;r10-post-share;offline")

    # One R1 TLS reader plus the already-existing Graphics DVC framing owner;
    # a missing R2 lease prevents both packet dispatch and Graphics ACKs.
    add_test(NAME runtime.linux-connection-personal-post-share-single-reader-denials
        COMMAND test_runtime_linux_security
            "linux-connection-personal-post-share-single-reader-denials"
            "${PROJECT_BINARY_DIR}/runtime-linux-security-fixtures")
    set_tests_properties(
        runtime.linux-connection-personal-post-share-single-reader-denials
        PROPERTIES LABELS "runtime;security;r10-post-share;offline")

    add_test(NAME runtime.linux-connection-graphics-credit-preflight-denials
        COMMAND test_runtime_linux_security
            "linux-connection-graphics-credit-preflight-denials"
            "${PROJECT_BINARY_DIR}/runtime-linux-security-fixtures")
    set_tests_properties(
        runtime.linux-connection-graphics-credit-preflight-denials
        PROPERTIES LABELS "runtime;security;r10-graphics;offline")

    # R10 may request R3 remap only through a live R2 lease. This proves the
    # runtime wrapper cannot fabricate resize authority from geometry alone.
    add_test(NAME runtime.linux-connection-graphics-surface-remap-denials
        COMMAND test_runtime_linux_security
            "linux-connection-graphics-surface-remap-denials"
            "${PROJECT_BINARY_DIR}/runtime-linux-security-fixtures")
    set_tests_properties(
        runtime.linux-connection-graphics-surface-remap-denials
        PROPERTIES LABELS "runtime;security;r10-resize;offline")

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
        PROPERTIES LABELS "runtime;security;r8-r3;offline")

    # A Linux signal only requests Stop; R1/R2/R3/R5 teardown is serialized.
    # This inspects production code offline without signals or live admission.
    add_test(NAME runtime.linux-serve-cooperative-signal-stop-order
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_RUNTIME_ENTRYPOINT_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/main.cpp"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_linux_cooperative_stop.cmake")
    set_tests_properties(runtime.linux-serve-cooperative-signal-stop-order
        PROPERTIES LABELS "runtime;security;r10-stop;offline")

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
        PROPERTIES LABELS "runtime;security;r10-post-share;offline")

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
        LABELS "runtime;security;r10-share;offline")

    # R10 post-Share Graphics control composition is source-guarded offline:
    # ordinary CI must not fabricate a positive R2 lease, native desktop or
    # R4 frame merely to prove DRDYNVC CREATE/CAPS scheduling.
    add_test(NAME runtime.linux-serve-graphics-dvc-composition
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_RUNTIME_ENTRYPOINT_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/main.cpp"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_linux_graphics_dvc.cmake")
    set_tests_properties(
        runtime.linux-serve-graphics-dvc-composition PROPERTIES
        LABELS "runtime;security;r10-graphics;offline")

    # R10's live native owner is reachable only behind genuine R2 admission,
    # so ordinary CI source-guards production composition rather than
    # fabricating a Kerberos/PAM/logind lease or touching a real X11 desktop.
    add_test(NAME runtime.linux-serve-r2-selected-x11-owner-composition
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_RUNTIME_ENTRYPOINT_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/main.cpp"
            "-DRDP_ROOT_CMAKE=${PROJECT_SOURCE_DIR}/CMakeLists.txt"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_linux_native_owner.cmake")
    set_tests_properties(
        runtime.linux-serve-r2-selected-x11-owner-composition PROPERTIES
        LABELS "runtime;security;r10-native;x11;offline")

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
        PROPERTIES LABELS "x11;linux-adapter;security;offline;r5-terminal")

    # R5 follows the single R10 R2-selected XCB owner. The production
    # post-Share scheduler must retire its borrowed logind watch before
    # native drain, refresh R2 authority and borrow the first XShm frame
    # synchronously while R1 owns all TLS application reads.
    add_test(NAME runtime.linux-r5-x11-authorized-event-service-denials
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_RUNTIME_ENTRYPOINT_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/main.cpp"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_linux_x11_event_service.cmake")
    add_test(NAME runtime.linux-r5-persistent-x11-input-frame-borrow-order
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_RUNTIME_ENTRYPOINT_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/main.cpp"
            "-DRDP_R5_PERSISTENT_FRAME_GATE=ON"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_linux_x11_event_service.cmake")
    set_tests_properties(
        runtime.linux-r5-x11-authorized-event-service-denials
        runtime.linux-r5-persistent-x11-input-frame-borrow-order PROPERTIES
        LABELS "runtime;security;r5-native;x11;offline")

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

# R10 immutable product mode and future loopback-only listener candidate gate.
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
        personal-desktop-loopback-listener-denials)
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

# R6 fixture-only checks: do not enumerate a real desktop, capture pixels,
# or inject input during an ordinary Windows CTest run.
if(TARGET rdp-server-windows-desktop)
    add_executable(test_windows_desktop_geometry
        test_windows_desktop_geometry.cpp
        windows_geometry_gdi_type_probe.cpp
        windows_capture_cycle_cases.cpp
        windows_capture_damage_cases.cpp
        windows_capture_session_guard_cases.cpp
        windows_r4_handoff_cases.cpp
        windows_dxgi_duplication_owner_cases.cpp
        windows_dxgi_pointer_shape_cases.cpp
        windows_input_controller_cases.cpp
        windows_cursor_snapshot_cases.cpp
        windows_rdp_conflict_cases.cpp)
    target_link_libraries(test_windows_desktop_geometry PRIVATE
        rdp-server-windows-desktop
        rdp-server-graphics)
    if(MSVC)
        target_compile_options(test_windows_desktop_geometry PRIVATE /UNDEBUG)
    else()
        target_compile_options(test_windows_desktop_geometry PRIVATE -UNDEBUG)
    endif()
    foreach(case_name IN ITEMS
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
            r4-bgra-layout-contract
            r4-frame-lifetime-revocation
            r4-monitor-replacement-denials)
        add_test(NAME "windows.capture-${case_name}"
            COMMAND test_windows_desktop_geometry "${case_name}")
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
        tls-context-read-only-unbound-identity-status
        tls-identity-offline-lifecycle-denials
        tls-context-survives-credential-path-replacement
        rejects-live-tls-context-invalid-material
        rejects-live-tls-context-extra-certificate-material)
    add_test(NAME "runtime.${runtime_tls_context_case}"
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_RUNTIME_TLS_CONTEXT_TEST=$<TARGET_FILE:test_runtime_tls_context>"
            "-DRDP_RUNTIME_TLS_CONTEXT_CASE=${runtime_tls_context_case}"
            "-DRDP_RUNTIME_FIXTURE_DIRECTORY=${PROJECT_BINARY_DIR}/runtime-tls-context-fixtures"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_tls_context.cmake")
    set_tests_properties("runtime.${runtime_tls_context_case}" PROPERTIES
        LABELS "runtime;security;offline")
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
# an injected backend and synthetic CoreVideo buffers. The public header exposes
# no native backend/factory before real R2/R3 macOS authorization; ordinary
# tests never enumerate SCShareableContent, start SCStream, or request TCC.
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
            r4-bgra-layout-contract
            r4-pixel-lifetime-retirement
            r4-display-generation-denials)
        add_test(NAME "macos.capture-${case_name}"
            COMMAND test_macos_capture_stream "${case_name}")
        set_tests_properties("macos.capture-${case_name}" PROPERTIES
            LABELS "macos;capture;graphics;x264;security;offline;native")
    endforeach()
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
        add_test(NAME x11.desktop-resource-r4-read-boundary
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 1280x720x24 -nolisten tcp"
                $<TARGET_FILE:test_x11_desktop_resources> r4-read-boundary)
        add_test(NAME x11.capture-r4-bgra-ingress
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 320x240x24 -nolisten tcp -noreset"
                $<TARGET_FILE:test_x11_desktop_resources>
                capture-r4-bgra-ingress)
        add_test(NAME x11.capture-r4-stride-layout-denials
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 320x240x24 -nolisten tcp -noreset"
                $<TARGET_FILE:test_x11_desktop_resources>
                capture-r4-stride-layout-denials)
        add_test(NAME x11.capture-r4-generation-retirement
            COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
                "-screen 0 320x240x24 -nolisten tcp -noreset"
                $<TARGET_FILE:test_x11_desktop_resources>
                capture-r4-generation-retirement)
        set_tests_properties(
            x11.capture-r4-bgra-ingress
            x11.capture-r4-stride-layout-denials
            x11.capture-r4-generation-retirement
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
            x11.desktop-resource-r4-read-boundary
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
    add_test(NAME x11.input-r2-authorized-slow-path-native-mapping-denials
        COMMAND test_x11_rdp_slow_path_input)
    set_tests_properties(
        x11.input-r2-authorized-slow-path-native-mapping-denials PROPERTIES
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
    LABELS "x11;linux-adapter;security;input;offline;r5-terminal")

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
    LABELS "runtime;security;r10-native;x11;input;offline")

# R8 production dependency readiness plus dormant-route policy guard. The
# persistent R10 router/native lifetime now exists, so require the compiled
# composition while pinning its explicit production activation gate to false
# and keeping the first future acceptance Unicode-text-only.
add_test(NAME runtime.linux-x11-clipboard-production-linkage
    COMMAND "${CMAKE_COMMAND}"
        "-DRDP_ROOT_CMAKE=${PROJECT_SOURCE_DIR}/CMakeLists.txt"
        "-DRDP_RUNTIME_ENTRYPOINT_SOURCE=${PROJECT_SOURCE_DIR}/src/server/runtime/main.cpp"
        -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_linux_x11_clipboard_linkage.cmake")
set_tests_properties(
    runtime.linux-x11-clipboard-production-linkage PROPERTIES
    LABELS "runtime;security;r8-r3;x11;offline;native-linkage")

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
    add_test(NAME x11.input-r3-admission-route-denials-and-revocation
        COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
            "-screen 0 1280x720x24 -nolisten tcp"
            $<TARGET_FILE:test_x11_authorized_input_route>)
    add_test(NAME x11.input-native-generation-mismatch-denial
        COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
            "-screen 0 1280x720x24 -nolisten tcp"
            $<TARGET_FILE:test_x11_authorized_input_route>
            generation-mismatch)
    add_test(NAME x11.input-r2-policy-replacement-keyboard-denial
        COMMAND "${RDP_SERVER_XVFB_RUN_EXECUTABLE}" -a -s
            "-screen 0 1280x720x24 -nolisten tcp"
            $<TARGET_FILE:test_x11_authorized_input_route>
            policy-replacement-keyboard)
    set_tests_properties(
        x11.input-r3-admission-route-denials-and-revocation
        x11.input-native-generation-mismatch-denial
        x11.input-r2-policy-replacement-keyboard-denial
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
        add_test(NAME "clipboard.${case_name}"
            COMMAND test_linux_clipboard_file_destination "${case_name}")
        set_tests_properties("clipboard.${case_name}" PROPERTIES
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
        macos-file-destination-denials
        macos-completed-file-url-handoff
        macos-completed-multi-file-url-handoff)
    add_test(NAME "clipboard.${case_name}"
        COMMAND test_macos_clipboard_file_destination "${case_name}")
    set_tests_properties("clipboard.${case_name}" PROPERTIES
        LABELS "protocol;clipboard;apple-file-destination;offline")
endforeach()
if(APPLE)
    add_test(NAME clipboard.macos-file-destination-native-descriptor
        COMMAND test_macos_clipboard_file_destination
            macos-file-destination-native-descriptor)
    set_tests_properties(
        clipboard.macos-file-destination-native-descriptor
        PROPERTIES LABELS
            "protocol;clipboard;apple-file-destination;native;offline")
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
    add_test(NAME "clipboard.${case_name}"
        COMMAND test_macos_clipboard_adapter "${case_name}")
    # Keep native-adapter labeling narrower than broad platform preflights.
    set_tests_properties("clipboard.${case_name}" PROPERTIES
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
        windows-file-destination-denials
        windows-completed-file-hdrop-handoff
        windows-completed-multi-file-hdrop-handoff
        file-destination-plan-native-capability-integration
        windows-file-destination-source-epoch-revocation)
    add_test(NAME "clipboard.${case_name}"
        COMMAND test_windows_clipboard_file_destination "${case_name}")
    set_tests_properties("clipboard.${case_name}" PROPERTIES
        LABELS "protocol;clipboard;win32-file-destination;offline")
endforeach()
if(WIN32)
    add_test(NAME clipboard.windows-file-destination-native-handle
        COMMAND test_windows_clipboard_file_destination
            windows-file-destination-native-handle)
    set_tests_properties(
        clipboard.windows-file-destination-native-handle
        PROPERTIES LABELS
            "protocol;clipboard;win32-file-destination;native;offline")
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
    add_test(NAME "clipboard.${case_name}"
        COMMAND test_windows_clipboard_adapter "${case_name}")
    # Do not add the broad "windows" label: R6's target-only native
    # preflight intentionally runs -L windows before this executable is built.
    set_tests_properties("clipboard.${case_name}" PROPERTIES
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
            x11-r3-retirement-stale-incr-fence)
        add_test(NAME "clipboard.${case_name}"
            COMMAND $<TARGET_FILE:test_x11_clipboard_adapter> "${case_name}")
        set_tests_properties("clipboard.${case_name}" PROPERTIES
            LABELS "protocol;clipboard;x11;linux-adapter;native;offline")
    endforeach()
    set_tests_properties(
        clipboard.x11-selection-ownership-generation
        PROPERTIES LABELS "protocol;clipboard;x11;linux-adapter;native;offline")
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

# R7 layout/state tests run offscreen and never authorize real host start.
if(RDP_SERVER_BUILD_DESKTOP_GUI)
    add_executable(test_desktop_gui_offline test_desktop_gui_offline.cpp)
    target_link_libraries(test_desktop_gui_offline PRIVATE rdp-server-desktop-ui)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        # Verify real R10 denial/retirement through the shared R7 Qt view.
        target_link_libraries(test_desktop_gui_offline PRIVATE
            rdp-server-linux-host-control)
    endif()
    if(MSVC)
        target_compile_options(test_desktop_gui_offline PRIVATE /W4 /UNDEBUG)
    else()
        target_compile_options(test_desktop_gui_offline PRIVATE
            -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
    endif()
    add_test(NAME gui.offscreen-first-run-authorization-revocation
        COMMAND test_desktop_gui_offline)
    set_tests_properties(gui.offscreen-first-run-authorization-revocation PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security" TIMEOUT 30)
    add_test(NAME gui.offscreen-close-revokes-pending-host
        COMMAND test_desktop_gui_offline close)
    set_tests_properties(gui.offscreen-close-revokes-pending-host PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security" TIMEOUT 30)
    # A live/pending window close must require explicit host-owner Stop.
    add_test(NAME gui.offscreen-close-requires-explicit-owner-stop
        COMMAND test_desktop_gui_offline close-consent)
    set_tests_properties(gui.offscreen-close-requires-explicit-owner-stop
        PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security;runtime;consent" TIMEOUT 30)
    add_test(NAME gui.offscreen-r10-control-adapter-denials
        COMMAND test_desktop_gui_offline runtime)
    set_tests_properties(gui.offscreen-r10-control-adapter-denials PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security;runtime" TIMEOUT 30)
    add_test(NAME gui.offscreen-r2-os-account-request-status-gate
        COMMAND test_desktop_gui_offline access)
    set_tests_properties(gui.offscreen-r2-os-account-request-status-gate PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security;credentials" TIMEOUT 30)
    add_test(NAME gui.offscreen-owner-permission-scope-lifetime-forwarding
        COMMAND test_desktop_gui_offline access)
    set_tests_properties(
        gui.offscreen-owner-permission-scope-lifetime-forwarding PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security;runtime;consent" TIMEOUT 30)

    add_test(NAME gui.offscreen-positive-owner-workflow-presentation
        COMMAND test_desktop_gui_offline positive-workflow)
    set_tests_properties(gui.offscreen-positive-owner-workflow-presentation PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;presentation;runtime;consent" TIMEOUT 30)
    # The actual LAN endpoint and opaque clients must come from R10 status.
    # All interactions remain offscreen without socket/native side effects.
    add_test(NAME gui.offscreen-r10-interface-endpoint-client-disconnect-denials
        COMMAND test_desktop_gui_offline lan-client)
    set_tests_properties(gui.offscreen-r10-interface-endpoint-client-disconnect-denials
        PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security;runtime" TIMEOUT 30)
    # R10 peer, endpoint and interface data must remain literal Qt text.
    add_test(NAME gui.offscreen-runtime-peer-and-endpoint-plain-text
        COMMAND test_desktop_gui_offline plain-runtime-text)
    set_tests_properties(gui.offscreen-runtime-peer-and-endpoint-plain-text
        PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security;runtime" TIMEOUT 30)
    # R10's unique stable-ID/real-address policy also gates GUI choices.
    add_test(NAME gui.offscreen-r10-selected-lan-endpoint-preflight-denials
        COMMAND test_desktop_gui_offline r10-lan-selector)
    set_tests_properties(gui.offscreen-r10-selected-lan-endpoint-preflight-denials
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
    endif()
    # R2 terminal session loss must not bypass the R10 raw-stage Stop guard.
    add_test(NAME gui.offscreen-r10-lifecycle-and-terminal-close-denials
        COMMAND test_desktop_gui_offline lifecycle-stages)
    set_tests_properties(gui.offscreen-r10-lifecycle-and-terminal-close-denials
        PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security;runtime;status" TIMEOUT 30)
    # Until R2 proves interoperable independent-password NLA, the GUI must
    # contain no application-password entry fields or actionable workflow.
    add_test(NAME gui.offscreen-independent-password-workflow-unavailable
        COMMAND test_desktop_gui_offline unsupported-password)
    set_tests_properties(gui.offscreen-independent-password-workflow-unavailable
        PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security;credentials" TIMEOUT 30)
    # R10 client authentication cannot be presented as a connected desktop.
    # Stale endpoint/peer fields are cleared by the Qt projection on Stop.
    add_test(NAME gui.offscreen-r10-client-stage-and-retirement-status-denials
        COMMAND test_desktop_gui_offline client-stage)
    set_tests_properties(gui.offscreen-r10-client-stage-and-retirement-status-denials
        PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;offline;security;runtime;clients" TIMEOUT 30)
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
    set_tests_properties(
        gui.linux-readonly-seat0-prerequisite-denials PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        LABELS "gui;linux;native-preflight;security;offline" TIMEOUT 20)
endif()
