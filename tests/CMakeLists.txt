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
                mcs-channel-join-confirm)
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
                tls-nonblocking-handshake
                tls-nonblocking-failures
                tcp-native-loopback-tls
                tcp-native-loopback-close
                tls-handshake-gate
                x224-length-and-close
                mcs-decrypted-fragments
                mcs-decrypted-rejections
                mcs-tls-record-fragments
                mcs-tls-record-rejections
                credssp-tls-fragments
                credssp-tls-coalesced
                credssp-tls-rejections
                credssp-tls-provenance
                credssp-tls-certificate-pinning
                credssp-tls-reply-wire
                credssp-tls-reply-backpressure
                credssp-tls-reply-rejections)
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
                credssp-final-negotiation-binding
                credssp-final-binding-rejections)
            add_test(NAME "security.${case_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("security.${case_name}" PROPERTIES
                LABELS "protocol;security")
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
    foreach(case_name IN ITEMS
            gssapi-tls-ownership
            gssapi-final-combined-denials
            gssapi-negotiation-reply-gates
            gssapi-binding-reply-gates
            gssapi-reply-order-denials)
        add_test(NAME "security.${case_name}"
            COMMAND test_owned_preauth_session "${case_name}")
        set_tests_properties("security.${case_name}" PROPERTIES
            LABELS "security;linux-provider")
    endforeach()
endif()
add_rdp_test(test_owned_remote_transfer.cpp clipboard remote-transfer)
add_rdp_test(test_clipboard_protocol.cpp clipboard protocol)
add_rdp_test(test_owned_credssp_binding.cpp security credssp-binding)
add_rdp_test(test_owned_credssp_tsrequest.cpp security credssp-tsrequest)
add_rdp_test(test_base64_codec.cpp security base64-codec)
if(TARGET rdp-server-linux-gssapi)
    add_rdp_test(test_linux_gssapi_spnego.cpp security linux-gssapi)
    target_link_libraries(test_linux_gssapi_spnego PRIVATE
        rdp-server-linux-gssapi)
endif()

add_test(NAME project.policy
    COMMAND "${CMAKE_COMMAND}"
        "-DRDP_SERVER_SOURCE_ROOT=${PROJECT_SOURCE_DIR}"
        -P "${PROJECT_SOURCE_DIR}/cmake/verify_project_policy.cmake")
set_tests_properties(project.policy PROPERTIES LABELS "project-policy")
