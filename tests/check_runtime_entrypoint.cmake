# SPDX-License-Identifier: GPL-3.0-or-later
# Inspect both process status and output without opening a network listener.
foreach(required_argument IN ITEMS RDP_RUNTIME_EXECUTABLE RDP_RUNTIME_VERSION RDP_RUNTIME_TEST_CASE)
    if(NOT DEFINED ${required_argument} OR "${${required_argument}}" STREQUAL "")
        message(FATAL_ERROR "Missing ${required_argument}")
    endif()
endforeach()

set(runtime_arguments)
set(runtime_working_directory "${CMAKE_CURRENT_BINARY_DIR}")
if(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-unconfigured-startup")
    set(expected_exit_code 2)
elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-unrecognized-options")
    set(runtime_arguments "--listen=0.0.0.0:3389" "--no-authentication")
    set(expected_exit_code 2)
elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-help-option-smuggling")
    set(runtime_arguments "--help" "--listen=0.0.0.0:3389")
    set(expected_exit_code 2)
elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-version-option-smuggling")
    set(runtime_arguments "--version" "--disable-nla")
    set(expected_exit_code 2)
elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-sensitive-argument-output")
    set(runtime_arguments "--auth-password=R10_SENTINEL_MUST_NOT_APPEAR")
    set(expected_exit_code 2)
elseif(RDP_RUNTIME_TEST_CASE STREQUAL "displays-help-without-startup")
    set(runtime_arguments "--help")
    set(expected_exit_code 0)
elseif(RDP_RUNTIME_TEST_CASE STREQUAL "reports-version-without-startup")
    set(runtime_arguments "--version")
    set(expected_exit_code 0)
elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-tls-files-option-smuggling")
    set(runtime_arguments "--check-tls-files" "R10_SENTINEL_MUST_NOT_APPEAR" "--help")
    set(expected_exit_code 2)
elseif(RDP_RUNTIME_TEST_CASE MATCHES "^(validates|rejects)-(configuration|tls-files)-")
    if(NOT DEFINED RDP_RUNTIME_FIXTURE_DIRECTORY OR
       RDP_RUNTIME_FIXTURE_DIRECTORY STREQUAL "")
        message(FATAL_ERROR "Missing RDP_RUNTIME_FIXTURE_DIRECTORY")
    endif()
    file(MAKE_DIRECTORY "${RDP_RUNTIME_FIXTURE_DIRECTORY}")
    set(config_file "${RDP_RUNTIME_FIXTURE_DIRECTORY}/${RDP_RUNTIME_TEST_CASE}.conf")
    set(check_tls_metadata FALSE)
    if(RDP_RUNTIME_TEST_CASE MATCHES "-tls-files-")
        set(check_tls_metadata TRUE)
    endif()
    # Absolute path syntax is host-specific; no real credentials are accessed.
    if(check_tls_metadata)
        set(certificate_file "${RDP_RUNTIME_FIXTURE_DIRECTORY}/${RDP_RUNTIME_TEST_CASE}.crt")
        set(private_key_file "${RDP_RUNTIME_FIXTURE_DIRECTORY}/${RDP_RUNTIME_TEST_CASE}.key")
    elseif(WIN32)
        set(certificate_file "C:/synthetic-r10/test.crt")
        set(private_key_file "C:/synthetic-r10/test.key")
    else()
        set(certificate_file "/synthetic-r10/test.crt")
        set(private_key_file "/synthetic-r10/test.key")
    endif()
    set(config_text
        "listen_address=127.0.0.1\nlisten_port=3389\n"
        "tls_certificate=${certificate_file}\n"
        "tls_private_key=${private_key_file}\n"
        "authentication=required\nos_authorization=required\n"
        "max_connections=4\n")
    string(JOIN "" config_text ${config_text})
    if(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-public-listener")
        string(REPLACE "127.0.0.1" "0.0.0.0" config_text "${config_text}")
    elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-missing-auth")
        string(REPLACE "authentication=required\n" "" config_text "${config_text}")
    elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-missing-os-policy")
        string(REPLACE "os_authorization=required\n" "" config_text "${config_text}")
    elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-disabled-auth")
        string(REPLACE "authentication=required" "authentication=disabled" config_text "${config_text}")
    elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-disabled-os-policy")
        string(REPLACE "os_authorization=required" "os_authorization=disabled" config_text "${config_text}")
    elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-duplicate-field")
        string(APPEND config_text "listen_port=3390\n")
    elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-invalid-port")
        string(REPLACE "listen_port=3389" "listen_port=65536" config_text "${config_text}")
    elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-invalid-limit")
        string(REPLACE "max_connections=4" "max_connections=65" config_text "${config_text}")
    elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-oversized-file")
        string(REPEAT "#" 4100 config_text)
    elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-unknown-field")
        string(APPEND config_text "disable_nla=true\n")
    elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-control-comment")
        string(ASCII 1 forbidden_character)
        string(APPEND config_text "#comment${forbidden_character}\n")
    elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-relative-key")
        string(REPLACE "${private_key_file}" "secrets/test.key" config_text "${config_text}")
    elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-traversal-key")
        string(REPLACE "${private_key_file}" "${private_key_file}/../key" config_text "${config_text}")
    elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-identical-tls-paths")
        string(REPLACE "${private_key_file}" "${certificate_file}" config_text "${config_text}")
    elseif(RDP_RUNTIME_TEST_CASE STREQUAL "validates-configuration-comments-crlf")
        string(PREPEND config_text "  # Valid non-secret settings\n\n")
        # On Windows, CMake file(WRITE) converts LF to CRLF; supplying
        # CRLF explicitly would create CRCRLF. On POSIX write CRLF bytes.
        string(REPLACE "\r" "" config_text "${config_text}")
        if(NOT WIN32)
            string(REPLACE "\n" "\r\n" config_text "${config_text}")
        endif()
    elseif(check_tls_metadata)
        # TLS-file cases modify only synthetic fixture paths or permissions.
    elseif(RDP_RUNTIME_TEST_CASE STREQUAL "validates-configuration-windows-private-dacl")
        # A private DACL remains readable by its owner.
    elseif(RDP_RUNTIME_TEST_CASE MATCHES "^rejects-configuration-windows-(everyone|authenticated|users)-write$")
        # Add a broad write grant to the otherwise private test DACL.
    elseif(RDP_RUNTIME_TEST_CASE STREQUAL "validates-configuration-windows-regular")
        # Existing disk-backed synthetic fixture must be accepted.
    elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-windows-directory")
        # Replace the fixture with a directory before invocation.
    elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-windows-relative-file")
        # A real existing file must be rejected when opened relatively.
    elseif(RDP_RUNTIME_TEST_CASE STREQUAL "validates-configuration-owner-only")
        # A private regular file must remain valid on POSIX hosts.
    elseif(RDP_RUNTIME_TEST_CASE STREQUAL "validates-configuration-mode-normalization")
        # Exercise a previously permissive file even if the test host's
        # umask would otherwise create all its fixtures as private.
    elseif(RDP_RUNTIME_TEST_CASE MATCHES "^rejects-configuration-(symlink|fifo|group-writable|directory)$")
        # Substitute a synthetic local file-system object after writing the
        # ordinary configuration, without accessing any user's credentials.
    elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-missing-file")
        # Do not write a fixture in this case.
    elseif(NOT RDP_RUNTIME_TEST_CASE STREQUAL "validates-configuration-syntax")
        message(FATAL_ERROR "Unknown configuration test case")
    endif()
    # Fixture paths are unique to each case; remove only the files/directories
    # created by this script so repeat CTest runs cannot block on stale FIFOs.
    if(IS_DIRECTORY "${config_file}")
        file(REMOVE_RECURSE "${config_file}")
    else()
        file(REMOVE "${config_file}")
    endif()
    if(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-missing-file")
        # This case deliberately leaves the generated fixture absent.
    else()
        if(UNIX AND RDP_RUNTIME_TEST_CASE STREQUAL "validates-configuration-mode-normalization")
            # Model a CTest build tree created under a permissive umask.
            # CMake file(WRITE) preserves permissions on an existing file.
            file(WRITE "${config_file}" "${config_text}")
            file(CHMOD "${config_file}" PERMISSIONS
                OWNER_READ OWNER_WRITE GROUP_WRITE WORLD_WRITE)
        endif()
        file(WRITE "${config_file}" "${config_text}")
        if(UNIX)
            # The production POSIX reader rejects group/world writable
            # config files. Fixtures must not depend on the owner's umask.
            # Explicit negative permission tests override this baseline.
            file(CHMOD "${config_file}" PERMISSIONS OWNER_READ OWNER_WRITE)
        endif()
        if(WIN32 AND NOT RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-windows-directory")
            # Ensure every Windows config fixture has an explicit private
            # baseline DACL, independent of CI checkout inheritance.
            execute_process(COMMAND whoami.exe
                RESULT_VARIABLE whoami_result
                OUTPUT_VARIABLE runtime_account
                OUTPUT_STRIP_TRAILING_WHITESPACE)
            if(NOT whoami_result STREQUAL "0" OR runtime_account STREQUAL "")
                message(FATAL_ERROR "Cannot discover synthetic fixture owner")
            endif()
            execute_process(COMMAND icacls.exe "${config_file}"
                /inheritance:r /grant:r "${runtime_account}:(F)"
                RESULT_VARIABLE private_acl_result
                OUTPUT_QUIET ERROR_VARIABLE private_acl_error)
            if(NOT private_acl_result STREQUAL "0")
                message(FATAL_ERROR "Cannot set private synthetic config DACL")
            endif()
            if(RDP_RUNTIME_TEST_CASE MATCHES "^rejects-configuration-windows-(everyone|authenticated|users)-write$")
                if(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-windows-everyone-write")
                    set(broad_sid "*S-1-1-0")
                elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-windows-authenticated-write")
                    set(broad_sid "*S-1-5-11")
                else()
                    set(broad_sid "*S-1-5-32-545")
                endif()
                execute_process(COMMAND icacls.exe "${config_file}"
                    /grant "${broad_sid}:(M)"
                    RESULT_VARIABLE grant_result OUTPUT_QUIET ERROR_QUIET)
                if(NOT grant_result STREQUAL "0")
                    message(FATAL_ERROR "Cannot grant synthetic broad write ACE")
                endif()
            endif()
        endif()
        if(WIN32 AND RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-windows-directory")
            file(REMOVE "${config_file}")
            file(MAKE_DIRECTORY "${config_file}")
        elseif(UNIX AND RDP_RUNTIME_TEST_CASE STREQUAL "validates-configuration-owner-only")
            file(CHMOD "${config_file}" PERMISSIONS OWNER_READ OWNER_WRITE)
        elseif(UNIX AND RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-group-writable")
            file(CHMOD "${config_file}" PERMISSIONS OWNER_READ OWNER_WRITE GROUP_WRITE)
        elseif(UNIX AND RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-symlink")
            set(target_file "${config_file}.target")
            file(WRITE "${target_file}" "${config_text}")
            file(REMOVE "${config_file}")
            file(CREATE_LINK "${target_file}" "${config_file}" SYMBOLIC)
        elseif(UNIX AND RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-fifo")
            file(REMOVE "${config_file}")
            execute_process(COMMAND mkfifo "${config_file}"
                RESULT_VARIABLE fifo_create_result)
            if(NOT fifo_create_result STREQUAL "0")
                message(FATAL_ERROR "Cannot create synthetic FIFO")
            endif()
        elseif(UNIX AND RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-directory")
            file(REMOVE "${config_file}")
            file(MAKE_DIRECTORY "${config_file}")
        endif()
        if(check_tls_metadata)
            foreach(material IN ITEMS "${certificate_file}" "${private_key_file}")
                if(IS_DIRECTORY "${material}")
                    file(REMOVE_RECURSE "${material}")
                else()
                    file(REMOVE "${material}")
                endif()
            endforeach()
            file(WRITE "${certificate_file}" "SYNTHETIC_CERTIFICATE_METADATA_ONLY")
            file(WRITE "${private_key_file}" "SYNTHETIC_KEY_METADATA_ONLY")
            if(UNIX)
                file(CHMOD "${certificate_file}" PERMISSIONS
                    OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
                file(CHMOD "${private_key_file}" PERMISSIONS
                    OWNER_READ OWNER_WRITE)
            else()
                foreach(material IN ITEMS "${certificate_file}" "${private_key_file}")
                    execute_process(COMMAND icacls.exe "${material}"
                        /inheritance:r /grant:r "${runtime_account}:(F)"
                        RESULT_VARIABLE acl_result OUTPUT_QUIET ERROR_QUIET)
                    if(NOT acl_result STREQUAL "0")
                        message(FATAL_ERROR "Cannot set synthetic TLS-file ACL")
                    endif()
                endforeach()
            endif()
            if(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-tls-files-missing-certificate")
                file(REMOVE "${certificate_file}")
            elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-tls-files-missing-key")
                file(REMOVE "${private_key_file}")
            elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-tls-files-empty-key")
                file(WRITE "${private_key_file}" "")
            elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-tls-files-oversized-key")
                string(REPEAT "K" 262145 oversized_key)
                file(WRITE "${private_key_file}" "${oversized_key}")
            elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-tls-files-aliased-identity")
                file(REMOVE "${private_key_file}")
                file(CREATE_LINK "${certificate_file}" "${private_key_file}")
            elseif(UNIX AND RDP_RUNTIME_TEST_CASE STREQUAL "rejects-tls-files-key-group-readable")
                file(CHMOD "${private_key_file}" PERMISSIONS
                    OWNER_READ OWNER_WRITE GROUP_READ)
            elseif(UNIX AND RDP_RUNTIME_TEST_CASE STREQUAL "rejects-tls-files-certificate-group-writable")
                file(CHMOD "${certificate_file}" PERMISSIONS
                    OWNER_READ OWNER_WRITE GROUP_WRITE)
            elseif(UNIX AND RDP_RUNTIME_TEST_CASE STREQUAL "rejects-tls-files-key-symlink")
                file(REMOVE "${private_key_file}")
                file(CREATE_LINK "${certificate_file}" "${private_key_file}" SYMBOLIC)
            elseif(UNIX AND RDP_RUNTIME_TEST_CASE STREQUAL "rejects-tls-files-certificate-symlink")
                file(REMOVE "${certificate_file}")
                file(CREATE_LINK "${private_key_file}" "${certificate_file}" SYMBOLIC)
            elseif(UNIX AND RDP_RUNTIME_TEST_CASE STREQUAL "rejects-tls-files-key-directory")
                file(REMOVE "${private_key_file}")
                file(MAKE_DIRECTORY "${private_key_file}")
            elseif(WIN32 AND RDP_RUNTIME_TEST_CASE STREQUAL "rejects-tls-files-windows-key-public-read")
                execute_process(COMMAND icacls.exe "${private_key_file}"
                    /grant "*S-1-1-0:(R)"
                    RESULT_VARIABLE grant_result OUTPUT_QUIET ERROR_QUIET)
                if(NOT grant_result STREQUAL "0")
                    message(FATAL_ERROR "Cannot grant synthetic TLS key public read ACE")
                endif()
            endif()
        endif()
        if(RDP_RUNTIME_TEST_CASE STREQUAL "validates-configuration-comments-crlf")
            # Ordinary CMake file(READ) normalizes CRLF to LF. HEX reads
            # verify actual fixture bytes without that transformation.
            file(READ "${config_file}" written_config_hex HEX)
            set(expected_config_text "${config_text}")
            if(WIN32)
                string(REPLACE "\n" "\r\n" expected_config_text "${expected_config_text}")
            endif()
            string(HEX "${expected_config_text}" expected_config_hex)
            if(NOT written_config_hex STREQUAL expected_config_hex)
                message(FATAL_ERROR "CRLF fixture bytes changed during write")
            endif()
        endif()
    endif()
    if(check_tls_metadata)
        set(runtime_arguments "--check-tls-files" "${config_file}")
    else()
        set(runtime_arguments "--check-config" "${config_file}")
    endif()
    if(WIN32 AND RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-windows-relative-file")
        set(runtime_working_directory "${RDP_RUNTIME_FIXTURE_DIRECTORY}")
        get_filename_component(relative_config_file "${config_file}" NAME)
        set(runtime_arguments "--check-config" "${relative_config_file}")
    endif()
    if(RDP_RUNTIME_TEST_CASE MATCHES "^validates-(configuration|tls-files)-")
        set(expected_exit_code 0)
    else()
        set(expected_exit_code 3)
    endif()
elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-windows-device-namespace")
    set(runtime_arguments "--check-config" "//./NUL")
    set(expected_exit_code 3)
elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-config-option-smuggling")
    set(runtime_arguments "--check-config" "R10_SENTINEL_MUST_NOT_APPEAR" "--help")
    set(expected_exit_code 2)
else()
    message(FATAL_ERROR "Unknown runtime test case")
endif()

execute_process(
    COMMAND "${RDP_RUNTIME_EXECUTABLE}" ${runtime_arguments}
    WORKING_DIRECTORY "${runtime_working_directory}"
    RESULT_VARIABLE runtime_exit_code
    OUTPUT_VARIABLE runtime_stdout
    ERROR_VARIABLE runtime_stderr)

# Windows text-mode standard streams can use CRLF; compare normalized text.
string(REPLACE "\r\n" "\n" runtime_stdout "${runtime_stdout}")
string(REPLACE "\r\n" "\n" runtime_stderr "${runtime_stderr}")

if(NOT "${runtime_exit_code}" STREQUAL "${expected_exit_code}")
    message(FATAL_ERROR "Unexpected runtime exit status: ${runtime_exit_code}")
endif()

if(expected_exit_code EQUAL 2)
    set(expected_rejection_output
        "rdp-server: refusing to start: authenticated OS authorization and authoritative live RDP sessions are unavailable.\n")
    if(NOT runtime_stdout STREQUAL "" OR
       NOT runtime_stderr STREQUAL expected_rejection_output)
        message(FATAL_ERROR "Secure startup refusal must be generic and not disclose arguments")
    endif()
elseif(RDP_RUNTIME_TEST_CASE STREQUAL "displays-help-without-startup")
    if(NOT runtime_stderr STREQUAL "" OR
       NOT runtime_stdout MATCHES "^Usage: rdp-server ")
        message(FATAL_ERROR "Runtime help must not attempt startup")
    endif()
elseif(RDP_RUNTIME_TEST_CASE STREQUAL "reports-version-without-startup")
    if(NOT runtime_stderr STREQUAL "" OR
       NOT runtime_stdout STREQUAL "rdp-server ${RDP_RUNTIME_VERSION}\n")
        message(FATAL_ERROR "Runtime version does not match PROJECT_VERSION")
    endif()
endif()

if(expected_exit_code EQUAL 3)
    if(NOT runtime_stdout STREQUAL "" OR NOT runtime_stderr STREQUAL
        "rdp-server: configuration check failed; service remains disabled.\n")
        message(FATAL_ERROR "Configuration errors must not disclose input")
    endif()
elseif(RDP_RUNTIME_TEST_CASE MATCHES "^validates-configuration-")
    if(NOT runtime_stderr STREQUAL "" OR NOT runtime_stdout STREQUAL
        "rdp-server: configuration syntax accepted; credentials and OS authorization not verified; service remains disabled.\n")
        message(FATAL_ERROR "Offline configuration success must not imply authenticated service")
    endif()
elseif(RDP_RUNTIME_TEST_CASE MATCHES "^validates-tls-files-")
    if(NOT runtime_stderr STREQUAL "" OR NOT runtime_stdout STREQUAL
        "rdp-server: TLS file metadata accepted; cryptographic contents and OS authorization not verified; service remains disabled.\n")
        message(FATAL_ERROR "Offline TLS metadata success must not imply authenticated service")
    endif()
endif()
