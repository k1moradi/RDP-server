# SPDX-License-Identifier: GPL-3.0-or-later
foreach(required_argument IN ITEMS
        RDP_RUNTIME_LICENSING_TEST
        RDP_RUNTIME_LICENSING_CASE
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

if(RDP_RUNTIME_LICENSING_CASE STREQUAL
   "licensing-runtime-context-secure-file-denials")
    function(expect_runtime_licensing_denial public_path private_path)
        execute_process(
            COMMAND "${RDP_RUNTIME_LICENSING_TEST}"
                licensing-runtime-context-secure-file-denial
                "${public_path}" "${private_path}"
                "${encrypted_premaster_file}"
            RESULT_VARIABLE denial_result
            OUTPUT_VARIABLE denial_output
            ERROR_VARIABLE denial_error)
        if(NOT denial_result STREQUAL "0")
            message(FATAL_ERROR
                "Runtime licensing denial subcase failed (${denial_result})\n${denial_output}${denial_error}")
        endif()
    endfunction()

    expect_runtime_licensing_denial(
        "${certificate_file}" "${certificate_file}")
    expect_runtime_licensing_denial(
        "${certificate_file}" "${private_key_file}.missing")
    expect_runtime_licensing_denial(
        "${certificate_file}" "relative-runtime-licensing.key")

    set(restricted_key "${private_key_file}.restricted")
    file(COPY_FILE "${private_key_file}" "${restricted_key}")
    if(UNIX)
        file(CHMOD "${restricted_key}" PERMISSIONS
            OWNER_READ OWNER_WRITE GROUP_READ)
        expect_runtime_licensing_denial(
            "${certificate_file}" "${restricted_key}")
        set(key_link "${private_key_file}.symlink")
        file(REMOVE "${key_link}")
        file(CREATE_LINK "${private_key_file}" "${key_link}" SYMBOLIC)
        expect_runtime_licensing_denial(
            "${certificate_file}" "${key_link}")
    elseif(WIN32)
        execute_process(COMMAND icacls.exe "${restricted_key}"
            /inheritance:r /grant:r "${runtime_account}:(F)"
            RESULT_VARIABLE restricted_acl_result
            OUTPUT_QUIET ERROR_QUIET)
        if(NOT restricted_acl_result STREQUAL "0")
            message(FATAL_ERROR
                "Cannot set restricted licensing-key baseline DACL")
        endif()
        execute_process(COMMAND icacls.exe "${restricted_key}"
            /setowner "${runtime_account}"
            RESULT_VARIABLE restricted_owner_result
            OUTPUT_QUIET ERROR_QUIET)
        if(NOT restricted_owner_result STREQUAL "0")
            message(FATAL_ERROR
                "Cannot set restricted licensing-key owner")
        endif()
        execute_process(COMMAND icacls.exe "${restricted_key}"
            /grant "*S-1-1-0:(R)"
            RESULT_VARIABLE public_read_result
            OUTPUT_QUIET ERROR_QUIET)
        if(NOT public_read_result STREQUAL "0")
            message(FATAL_ERROR
                "Cannot grant synthetic public licensing-key read ACE")
        endif()
        expect_runtime_licensing_denial(
            "${certificate_file}" "${restricted_key}")
    endif()
else()
    execute_process(
        COMMAND "${RDP_RUNTIME_LICENSING_TEST}"
            "${RDP_RUNTIME_LICENSING_CASE}"
            "${certificate_file}" "${private_key_file}"
            "${encrypted_premaster_file}"
        RESULT_VARIABLE test_result
        OUTPUT_VARIABLE test_output
        ERROR_VARIABLE test_error)
    if(NOT test_result STREQUAL "0")
        message(FATAL_ERROR
            "Runtime licensing secure-file test failed (${test_result})\n${test_output}${test_error}")
    endif()
endif()
