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
    add_test(NAME "${suite}.${behavior}" COMMAND "${test_target}")
    set_tests_properties("${suite}.${behavior}" PROPERTIES
        LABELS "protocol;${suite}")
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
