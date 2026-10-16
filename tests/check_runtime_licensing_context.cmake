# SPDX-License-Identifier: GPL-3.0-or-later
foreach(required_argument IN ITEMS
        RDP_RUNTIME_LICENSING_TEST
        RDP_RUNTIME_FIXTURE_DIRECTORY)
    if(NOT DEFINED ${required_argument} OR "${${required_argument}}" STREQUAL "")
        message(FATAL_ERROR "Missing ${required_argument}")
    endif()
endforeach()

file(MAKE_DIRECTORY "${RDP_RUNTIME_FIXTURE_DIRECTORY}")
set(certificate_file
    "${RDP_RUNTIME_FIXTURE_DIRECTORY}/runtime-licensing.bin")
set(private_key_file
    "${RDP_RUNTIME_FIXTURE_DIRECTORY}/runtime-licensing.key")
set(encrypted_premaster_file
    "${RDP_RUNTIME_FIXTURE_DIRECTORY}/runtime-licensing-premaster.bin")
file(REMOVE
    "${certificate_file}" "${private_key_file}"
    "${encrypted_premaster_file}")

execute_process(
    COMMAND "${RDP_RUNTIME_LICENSING_TEST}"
        emit-runtime-licensing-fixture
        "${certificate_file}" "${private_key_file}"
        "${encrypted_premaster_file}"
    RESULT_VARIABLE emit_result
    OUTPUT_VARIABLE emit_output
    ERROR_VARIABLE emit_error)
if(NOT emit_result STREQUAL "0")
    message(FATAL_ERROR
        "Runtime licensing fixture generation failed (${emit_result})\n${emit_output}${emit_error}")
endif()

if(UNIX)
    file(CHMOD "${certificate_file}" PERMISSIONS
        OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
    file(CHMOD "${private_key_file}" PERMISSIONS
        OWNER_READ OWNER_WRITE)
    file(CHMOD "${encrypted_premaster_file}" PERMISSIONS
        OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
elseif(WIN32)
    execute_process(COMMAND whoami.exe
        RESULT_VARIABLE whoami_result
        OUTPUT_VARIABLE runtime_account
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(NOT whoami_result STREQUAL "0" OR runtime_account STREQUAL "")
        message(FATAL_ERROR "Cannot discover synthetic fixture owner")
    endif()
    foreach(material IN ITEMS "${certificate_file}" "${private_key_file}")
        execute_process(COMMAND icacls.exe "${material}"
            /inheritance:r /grant:r "${runtime_account}:(F)"
            RESULT_VARIABLE acl_result OUTPUT_QUIET ERROR_QUIET)
        if(NOT acl_result STREQUAL "0")
            message(FATAL_ERROR "Cannot set licensing fixture DACL")
        endif()
        execute_process(COMMAND icacls.exe "${material}"
            /setowner "${runtime_account}"
            RESULT_VARIABLE owner_result OUTPUT_QUIET ERROR_QUIET)
        if(NOT owner_result STREQUAL "0")
            message(FATAL_ERROR "Cannot set licensing fixture owner")
        endif()
    endforeach()
endif()

execute_process(
    COMMAND "${RDP_RUNTIME_LICENSING_TEST}"
        licensing-runtime-context-secure-files
        "${certificate_file}" "${private_key_file}"
        "${encrypted_premaster_file}"
    RESULT_VARIABLE test_result
    OUTPUT_VARIABLE test_output
    ERROR_VARIABLE test_error)
if(NOT test_result STREQUAL "0")
    message(FATAL_ERROR
        "Runtime licensing secure-file test failed (${test_result})\n${test_output}${test_error}")
endif()
