# SPDX-License-Identifier: GPL-3.0-or-later
# Reuse one registry and preserve test executable/source file identities.
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
                mcs-response-rejections
                mcs-erect-request
                mcs-attach-request
                mcs-channel-join-request
                mcs-attach-confirm-wire
                mcs-channel-join-confirm
                mcs-join-write-completion
                mcs-join-write-denials
                mcs-join-duplicate-ignored
                mcs-join-batched-requests
                mcs-send-data-joined-membership
                mcs-send-data-joined-denials
                mcs-join-stale-write-receipts
                mcs-join-stale-partial-write-slices
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
                x224-request-fragments
                x224-request-outcomes
                x224-confirm-write-order
                x224-confirm-partial-writes
                tcp-adapter-fragments
                tcp-adapter-backpressure
                tcp-bio-chunk-bounds
                tcp-native-chunk-bounds
                tcp-native-accept-ownership
                tcp-native-accept-move-replacement
                tcp-native-accept-orderly-eof
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
        # Live server-cert binding belongs to the existing real TLS
        # fixture, but exposes separate positive and negative security
        # contracts rather than hiding them under transport CTest.
        foreach(case_name IN ITEMS
                credssp-active-tls-binding-positive
                credssp-active-tls-binding-rejections)
            add_test(NAME "security.${case_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("security.${case_name}" PROPERTIES
                LABELS "protocol;security")
        endforeach()
    elseif(test_target STREQUAL "test_linux_gssapi_spnego")
        foreach(case_name IN ITEMS
                gssapi-configuration-rejections
                gssapi-framed-handoff)
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
    elseif(test_target STREQUAL "test_gfx_avc420_capabilities")
        # Same production-linked executable, three independent wire behaviors.
        foreach(case_name IN ITEMS
                avc420-capabilities-selection
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
                surface-lifecycle-rejections)
            add_test(NAME "graphics.${case_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("graphics.${case_name}" PROPERTIES
                LABELS "protocol;graphics")
        endforeach()
    elseif(test_target STREQUAL "test_owned_remote_transfer")
        # Preserve the default regression and register the three R8 cases.
        add_test(NAME "clipboard.remote-transfer" COMMAND "${test_target}")
        set_tests_properties("clipboard.remote-transfer" PROPERTIES
            LABELS "protocol;clipboard")
        foreach(case_name IN ITEMS
                long-format-list-generation
                short-format-list-negotiation
                format-list-response-native-acceptance)
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
add_rdp_test(test_owned_gcc_conference_create.cpp transport gcc-conference-create)
add_rdp_test(test_owned_preauth_session.cpp transport preauth-session)
if(TARGET rdp-server-linux-gssapi)
    # Exercise real TLS -> actual MIT GSSAPI handoff using the existing
    # in-memory TLS fixture; no duplicate certificate/test implementation.
    target_link_libraries(test_owned_preauth_session PRIVATE
        rdp-server-linux-gssapi)
    target_compile_definitions(test_owned_preauth_session PRIVATE
        RDP_TEST_LINUX_GSSAPI=1)
    if(RDP_SERVER_TEST_REAL_KERBEROS)
        target_compile_definitions(test_owned_preauth_session PRIVATE
            RDP_TEST_REAL_KERBEROS=1)
        foreach(case_name IN ITEMS
                gssapi-real-kerberos-tls-mechanism
                gssapi-real-kerberos-tls-failure)
            add_test(NAME "security.${case_name}"
                COMMAND test_owned_preauth_session "${case_name}")
            set_tests_properties("security.${case_name}"
                PROPERTIES LABELS "security;linux-provider;opt-in-kerberos")
        endforeach()
    endif()
    foreach(case_name IN ITEMS
            gssapi-tls-ownership
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
# A separate fail-closed framing contract, dispatched by the same native test.
add_test(NAME clipboard.remote-transfer-framing-rejections
    COMMAND test_owned_remote_transfer framing-rejections)
set_tests_properties(clipboard.remote-transfer-framing-rejections PROPERTIES
    LABELS "protocol;clipboard;security")
add_rdp_test(test_clipboard_protocol.cpp clipboard protocol)
add_rdp_test(test_owned_credssp_binding.cpp security credssp-binding)
add_rdp_test(test_owned_credssp_tsrequest.cpp security credssp-tsrequest)
add_rdp_test(test_base64_codec.cpp security base64-codec)
add_rdp_test(test_gfx_surface_lifecycle.cpp graphics surface-lifecycle)
add_rdp_test(test_gfx_avc420_capabilities.cpp graphics avc420-capabilities)
if(TARGET rdp-server-linux-gssapi)
    add_rdp_test(test_linux_gssapi_spnego.cpp security linux-gssapi)
    target_link_libraries(test_linux_gssapi_spnego PRIVATE
        rdp-server-linux-gssapi)
endif()

# R6 fixture-only checks: do not enumerate a real desktop, capture pixels,
# or inject input during an ordinary Windows CTest run.
if(TARGET rdp-server-windows-desktop)
    add_executable(test_windows_desktop_geometry
        test_windows_desktop_geometry.cpp
        windows_geometry_gdi_type_probe.cpp)
    target_link_libraries(test_windows_desktop_geometry PRIVATE
        rdp-server-windows-desktop)
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

add_test(NAME project.policy
    COMMAND "${CMAKE_COMMAND}"
        "-DRDP_SERVER_SOURCE_ROOT=${PROJECT_SOURCE_DIR}"
        -P "${PROJECT_SOURCE_DIR}/cmake/verify_project_policy.cmake")
set_tests_properties(project.policy PROPERTIES LABELS "project-policy")
