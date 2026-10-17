# SPDX-License-Identifier: GPL-3.0-or-later
foreach(required_argument IN ITEMS
        RDP_RUNTIME_EXECUTABLE RDP_RUNTIME_VERSION
        RDP_WINDOWS_FIXTURE_CASE RDP_RUNTIME_FIXTURE_DIRECTORY)
    if(NOT DEFINED ${required_argument} OR "${${required_argument}}" STREQUAL "")
        message(FATAL_ERROR "Missing ${required_argument}")
    endif()
endforeach()
if(NOT WIN32)
    message(FATAL_ERROR "Windows fixture ACL CTest requires WIN32")
endif()
include("${CMAKE_CURRENT_LIST_DIR}/windows_private_fixture_acl.cmake")
file(MAKE_DIRECTORY "${RDP_RUNTIME_FIXTURE_DIRECTORY}")

function(run_runtime_entrypoint_case case_name)
    execute_process(
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_RUNTIME_EXECUTABLE=${RDP_RUNTIME_EXECUTABLE}"
            "-DRDP_RUNTIME_VERSION=${RDP_RUNTIME_VERSION}"
            "-DRDP_RUNTIME_TEST_CASE=${case_name}"
            "-DRDP_RUNTIME_FIXTURE_DIRECTORY=${RDP_RUNTIME_FIXTURE_DIRECTORY}/${case_name}"
            -P "${CMAKE_CURRENT_LIST_DIR}/check_runtime_entrypoint.cmake"
        RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
    if(NOT result STREQUAL "0")
        message(FATAL_ERROR
            "Windows fixture production-backed case '${case_name}' failed "
            "(${result})\n${output}${error}")
    endif()
endfunction()

if(RDP_WINDOWS_FIXTURE_CASE STREQUAL "dacl-creation")
    run_runtime_entrypoint_case("validates-configuration-windows-private-dacl")
    run_runtime_entrypoint_case("validates-tls-files-private-regular")
elseif(RDP_WINDOWS_FIXTURE_CASE STREQUAL "broad-access-denials")
    foreach(case_name IN ITEMS
            rejects-configuration-windows-everyone-write
            rejects-configuration-windows-authenticated-write
            rejects-configuration-windows-users-write
            rejects-tls-files-windows-key-public-read)
        run_runtime_entrypoint_case("${case_name}")
    endforeach()
elseif(RDP_WINDOWS_FIXTURE_CASE STREQUAL "owner-consistency")
    set(owner_fixture "${RDP_RUNTIME_FIXTURE_DIRECTORY}/owner-consistency.key")
    file(REMOVE "${owner_fixture}")
    file(WRITE "${owner_fixture}" "synthetic-private-key-material\n")
    rdp_windows_make_private_fixture_acl("${owner_fixture}")
    rdp_windows_fixture_get_identity(current_account current_sid)
    rdp_windows_fixture_get_owner_sid("${owner_fixture}" owner_sid)
    if(NOT owner_sid STREQUAL current_sid)
        message(FATAL_ERROR
            "Windows fixture owner mismatch after preparation: "
            "account='${current_account}' current_sid='${current_sid}' "
            "owner_sid='${owner_sid}'")
    endif()
else()
    message(FATAL_ERROR "Unknown Windows fixture ACL case '${RDP_WINDOWS_FIXTURE_CASE}'")
endif()
