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
                mcs-tls-record-rejections)
            add_test(NAME "transport.${case_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("transport.${case_name}" PROPERTIES
                LABELS "protocol;transport")
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
add_rdp_test(test_owned_remote_transfer.cpp clipboard remote-transfer)
add_rdp_test(test_clipboard_protocol.cpp clipboard protocol)
add_rdp_test(test_owned_credssp_binding.cpp security credssp-binding)
add_rdp_test(test_owned_credssp_tsrequest.cpp security credssp-tsrequest)
add_rdp_test(test_base64_codec.cpp security base64-codec)

add_test(NAME project.policy
    COMMAND "${CMAKE_COMMAND}"
        "-DRDP_SERVER_SOURCE_ROOT=${PROJECT_SOURCE_DIR}"
        -P "${PROJECT_SOURCE_DIR}/cmake/verify_project_policy.cmake")
set_tests_properties(project.policy PROPERTIES LABELS "project-policy")
