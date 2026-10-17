# SPDX-License-Identifier: GPL-3.0-or-later
# Shared Windows-only preparation for disposable synthetic credential fixtures.

if(NOT WIN32)
    message(FATAL_ERROR "Windows fixture ACL helper requires WIN32")
endif()

function(_rdp_windows_fixture_resolve_system_executable relative_path program_name output_variable)
    set(candidate "")
    if(DEFINED ENV{SystemRoot} AND NOT "$ENV{SystemRoot}" STREQUAL "")
        file(TO_CMAKE_PATH "$ENV{SystemRoot}/${relative_path}" candidate)
    endif()
    if(candidate AND EXISTS "${candidate}")
        set(resolved "${candidate}")
    else()
        unset(resolved)
        unset(resolved CACHE)
        find_program(resolved NAMES "${program_name}")
    endif()
    if(NOT resolved)
        message(FATAL_ERROR
            "Windows fixture ACL helper cannot resolve ${program_name}; "
            "SystemRoot='$ENV{SystemRoot}' PATH='$ENV{PATH}'")
    endif()
    set("${output_variable}" "${resolved}" PARENT_SCOPE)
endfunction()

_rdp_windows_fixture_resolve_system_executable(
    "System32/icacls.exe" "icacls.exe" RDP_WINDOWS_FIXTURE_ICACLS)
_rdp_windows_fixture_resolve_system_executable(
    "System32/whoami.exe" "whoami.exe" RDP_WINDOWS_FIXTURE_WHOAMI)
_rdp_windows_fixture_resolve_system_executable(
    "System32/WindowsPowerShell/v1.0/powershell.exe"
    "powershell.exe" RDP_WINDOWS_FIXTURE_POWERSHELL)

function(_rdp_windows_fixture_native_regular_path path output_variable)
    if(NOT EXISTS "${path}")
        message(FATAL_ERROR "Windows fixture ACL target does not exist: '${path}'")
    endif()
    if(IS_DIRECTORY "${path}" OR IS_SYMLINK "${path}")
        message(FATAL_ERROR
            "Windows fixture ACL target is not a regular non-aliased file: '${path}'")
    endif()
    get_filename_component(absolute_path "${path}" ABSOLUTE)
    file(TO_NATIVE_PATH "${absolute_path}" native_path)
    set("${output_variable}" "${native_path}" PARENT_SCOPE)
endfunction()

function(_rdp_windows_fixture_run_icacls path operation)
    _rdp_windows_fixture_native_regular_path("${path}" native_path)
    execute_process(
        COMMAND "${RDP_WINDOWS_FIXTURE_ICACLS}" "${native_path}" ${ARGN}
        RESULT_VARIABLE result
        OUTPUT_VARIABLE output
        ERROR_VARIABLE error)
    string(REPLACE "\r\n" "\n" output "${output}")
    string(REPLACE "\r\n" "\n" error "${error}")
    if(NOT result STREQUAL "0")
        message(FATAL_ERROR
            "Windows fixture ACL operation '${operation}' failed\n"
            "  executable: ${RDP_WINDOWS_FIXTURE_ICACLS}\n"
            "  native path: ${native_path}\n"
            "  exit code: ${result}\n"
            "  stdout: ${output}\n"
            "  stderr: ${error}")
    endif()
endfunction()

function(rdp_windows_fixture_get_identity account_output sid_output)
    execute_process(
        COMMAND "${RDP_WINDOWS_FIXTURE_WHOAMI}"
        RESULT_VARIABLE account_result
        OUTPUT_VARIABLE account
        ERROR_VARIABLE account_error
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(NOT account_result STREQUAL "0" OR account STREQUAL "")
        message(FATAL_ERROR
            "Windows fixture account lookup failed via "
            "'${RDP_WINDOWS_FIXTURE_WHOAMI}' (exit ${account_result})\n"
            "stderr: ${account_error}")
    endif()
    execute_process(
        COMMAND "${RDP_WINDOWS_FIXTURE_WHOAMI}" /user /fo csv /nh
        RESULT_VARIABLE sid_result
        OUTPUT_VARIABLE sid_record
        ERROR_VARIABLE sid_error
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    string(REGEX MATCH "S-[0-9-]+" current_sid "${sid_record}")
    if(NOT sid_result STREQUAL "0" OR NOT current_sid MATCHES "^S-[0-9-]+$")
        message(FATAL_ERROR
            "Windows fixture SID lookup failed for account '${account}' "
            "via '${RDP_WINDOWS_FIXTURE_WHOAMI}' (exit ${sid_result})\n"
            "stdout: ${sid_record}\n"
            "stderr: ${sid_error}")
    endif()
    set("${account_output}" "${account}" PARENT_SCOPE)
    set("${sid_output}" "${current_sid}" PARENT_SCOPE)
endfunction()

function(rdp_windows_fixture_get_owner_sid path output_variable)
    _rdp_windows_fixture_native_regular_path("${path}" native_path)
    string(REPLACE "'" "''" powershell_path "${native_path}")
    set(owner_command
        "$ErrorActionPreference = 'Stop'; "
        "$acl = [System.IO.File]::GetAccessControl('${powershell_path}'); "
        "$acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value")
    execute_process(
        COMMAND "${RDP_WINDOWS_FIXTURE_POWERSHELL}"
            -NoLogo -NoProfile -NonInteractive -Command "${owner_command}"
        RESULT_VARIABLE owner_result
        OUTPUT_VARIABLE owner_sid
        ERROR_VARIABLE owner_error
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(NOT owner_result STREQUAL "0" OR NOT owner_sid MATCHES "^S-[0-9-]+$")
        message(FATAL_ERROR
            "Windows fixture owner-SID query failed\n"
            "  executable: ${RDP_WINDOWS_FIXTURE_POWERSHELL}\n"
            "  native path: ${native_path}\n"
            "  exit code: ${owner_result}\n"
            "  stdout: ${owner_sid}\n"
            "  stderr: ${owner_error}")
    endif()
    set("${output_variable}" "${owner_sid}" PARENT_SCOPE)
endfunction()

function(_rdp_windows_fixture_verify_private_descriptor path expected_sid)
    _rdp_windows_fixture_native_regular_path("${path}" native_path)
    string(REPLACE "'" "''" powershell_path "${native_path}")
    set(verify_command [=[
$ErrorActionPreference = 'Stop'
$acl = [System.IO.File]::GetAccessControl('@PATH@')
$expected = '@SID@'
$owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
if ($owner -ne $expected) { throw "owner SID $owner does not match current SID $expected" }
if (-not $acl.AreAccessRulesProtected) { throw 'DACL inheritance remains enabled' }
$allowed = @($expected, 'S-1-5-18', 'S-1-5-32-544')
$ownerFull = $false
foreach ($rule in $acl.Access) {
    if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
    $ruleSid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    if ($allowed -notcontains $ruleSid) { throw "unexpected allow ACE for SID $ruleSid" }
    if ($ruleSid -eq $expected) {
        $mask = [int64]$rule.FileSystemRights
        $full = [int64][System.Security.AccessControl.FileSystemRights]::FullControl
        if (($mask -band $full) -eq $full) { $ownerFull = $true }
    }
}
if (-not $ownerFull) { throw 'current owner lacks an explicit FullControl allow ACE' }
Write-Output "owner=$owner; inheritanceProtected=True; ownerFullControl=True"
]=])
    string(REPLACE "@PATH@" "${powershell_path}" verify_command "${verify_command}")
    string(REPLACE "@SID@" "${expected_sid}" verify_command "${verify_command}")
    execute_process(
        COMMAND "${RDP_WINDOWS_FIXTURE_POWERSHELL}"
            -NoLogo -NoProfile -NonInteractive -Command "${verify_command}"
        RESULT_VARIABLE verify_result
        OUTPUT_VARIABLE verify_output
        ERROR_VARIABLE verify_error)
    if(NOT verify_result STREQUAL "0")
        message(FATAL_ERROR
            "Windows fixture private-DACL verification failed\n"
            "  executable: ${RDP_WINDOWS_FIXTURE_POWERSHELL}\n"
            "  native path: ${native_path}\n"
            "  expected owner SID: ${expected_sid}\n"
            "  exit code: ${verify_result}\n"
            "  stdout: ${verify_output}\n"
            "  stderr: ${verify_error}")
    endif()
endfunction()

function(rdp_windows_make_private_fixture_acl path)
    rdp_windows_fixture_get_identity(current_account current_sid)
    rdp_windows_fixture_get_owner_sid("${path}" owner_sid)
    if(NOT owner_sid STREQUAL current_sid)
        _rdp_windows_fixture_run_icacls(
            "${path}" "set owner to current SID" /setowner "*${current_sid}")
        rdp_windows_fixture_get_owner_sid("${path}" owner_sid)
        if(NOT owner_sid STREQUAL current_sid)
            message(FATAL_ERROR
                "Windows fixture owner correction did not take effect: "
                "account='${current_account}' current_sid='${current_sid}' "
                "owner_sid='${owner_sid}'")
        endif()
    endif()
    _rdp_windows_fixture_run_icacls(
        "${path}" "remove inherited ACEs" /inheritance:r)
    _rdp_windows_fixture_run_icacls(
        "${path}" "replace current-owner grant" /grant:r "*${current_sid}:F")
    _rdp_windows_fixture_verify_private_descriptor("${path}" "${current_sid}")
endfunction()

function(rdp_windows_fixture_add_insecure_test_ace path principal_sid rights operation)
    if(NOT principal_sid MATCHES "^(S-1-1-0|S-1-5-11|S-1-5-32-545)$")
        message(FATAL_ERROR "Unsupported synthetic broad-principal SID '${principal_sid}'")
    endif()
    if(NOT rights MATCHES "^(R|M)$")
        message(FATAL_ERROR "Unsupported synthetic broad-principal rights '${rights}'")
    endif()
    _rdp_windows_fixture_run_icacls(
        "${path}" "${operation}" /grant "*${principal_sid}:${rights}")
endfunction()
