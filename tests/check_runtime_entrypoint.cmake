# SPDX-License-Identifier: GPL-3.0-or-later
# Inspect both process status and output without opening a network listener.
foreach(required_argument IN ITEMS RDP_RUNTIME_EXECUTABLE RDP_RUNTIME_VERSION RDP_RUNTIME_TEST_CASE)
    if(NOT DEFINED ${required_argument} OR "${${required_argument}}" STREQUAL "")
        message(FATAL_ERROR "Missing ${required_argument}")
    endif()
endforeach()

if(WIN32)
    include("${CMAKE_CURRENT_LIST_DIR}/windows_private_fixture_acl.cmake")
endif()

# R10 licensing-authority startup isolation. Reuse the existing process
# expectations rather than creating a second CLI oracle. The positive provider
# fixture is not linked into rdp-server and no case below can configure one.
if(RDP_RUNTIME_TEST_CASE STREQUAL
   "licensing-authority-no-startup-bypass")
    if(NOT DEFINED RDP_RUNTIME_FIXTURE_DIRECTORY OR
       RDP_RUNTIME_FIXTURE_DIRECTORY STREQUAL "")
        message(FATAL_ERROR "Missing RDP_RUNTIME_FIXTURE_DIRECTORY")
    endif()
    set(authority_startup_cases
        rejects-unconfigured-startup
        rejects-unrecognized-options
        validates-configuration-syntax
        validates-tls-files-private-regular
        validates-tls-credentials-matching-pair
        licensing-cli-valid-provisioning
        licensing-cli-service-still-disabled)
    if(DEFINED RDP_RUNTIME_LINUX_SECURITY_HELPER AND
       NOT RDP_RUNTIME_LINUX_SECURITY_HELPER STREQUAL "")
        list(APPEND authority_startup_cases
            validates-linux-security-provisioning)
    endif()

    foreach(authority_startup_case IN LISTS authority_startup_cases)
        set(authority_startup_arguments
            "-DRDP_RUNTIME_EXECUTABLE=${RDP_RUNTIME_EXECUTABLE}"
            "-DRDP_RUNTIME_VERSION=${RDP_RUNTIME_VERSION}"
            "-DRDP_RUNTIME_TEST_CASE=${authority_startup_case}"
            "-DRDP_RUNTIME_FIXTURE_DIRECTORY=${RDP_RUNTIME_FIXTURE_DIRECTORY}/${authority_startup_case}")
        if(DEFINED RDP_RUNTIME_LICENSING_HELPER AND
           NOT RDP_RUNTIME_LICENSING_HELPER STREQUAL "")
            list(APPEND authority_startup_arguments
                "-DRDP_RUNTIME_LICENSING_HELPER=${RDP_RUNTIME_LICENSING_HELPER}")
        endif()
        if(DEFINED RDP_RUNTIME_LINUX_SECURITY_HELPER AND
           NOT RDP_RUNTIME_LINUX_SECURITY_HELPER STREQUAL "")
            list(APPEND authority_startup_arguments
                "-DRDP_RUNTIME_LINUX_SECURITY_HELPER=${RDP_RUNTIME_LINUX_SECURITY_HELPER}")
            if(RDP_RUNTIME_HAVE_LINUX_PAM)
                list(APPEND authority_startup_arguments
                    "-DRDP_RUNTIME_HAVE_LINUX_PAM=ON")
            endif()
        endif()
        execute_process(
            COMMAND "${CMAKE_COMMAND}"
                ${authority_startup_arguments}
                -P "${CMAKE_CURRENT_LIST_FILE}"
            RESULT_VARIABLE authority_startup_result
            OUTPUT_VARIABLE authority_startup_output
            ERROR_VARIABLE authority_startup_error)
        if(NOT authority_startup_result STREQUAL "0")
            message(FATAL_ERROR
                "Licensing-authority startup isolation case ${authority_startup_case} failed (${authority_startup_result})\n${authority_startup_output}${authority_startup_error}")
        endif()
    endforeach()
    return()
endif()

# R10 administrator licensing provisioning uses the real process entry point,
# the existing R3 RSA/X.509-chain fixture generator and production secure-file
# loader. These cases return before the legacy process checker below.
if(RDP_RUNTIME_TEST_CASE MATCHES "^licensing-cli-")
    if(NOT DEFINED RDP_RUNTIME_FIXTURE_DIRECTORY OR
       RDP_RUNTIME_FIXTURE_DIRECTORY STREQUAL "")
        message(FATAL_ERROR "Missing RDP_RUNTIME_FIXTURE_DIRECTORY")
    endif()
    file(MAKE_DIRECTORY "${RDP_RUNTIME_FIXTURE_DIRECTORY}")

    # Compatibility is deliberately evaluated through the pre-existing cases
    # so this dedicated CTest cannot drift from their process expectations.
    if(RDP_RUNTIME_TEST_CASE STREQUAL
       "licensing-cli-existing-check-compatibility")
        set(compatibility_cases
            validates-configuration-syntax
            validates-tls-files-private-regular
            validates-tls-credentials-matching-pair)
        if(DEFINED RDP_RUNTIME_LINUX_SECURITY_HELPER AND
           NOT RDP_RUNTIME_LINUX_SECURITY_HELPER STREQUAL "")
            list(APPEND compatibility_cases
                validates-linux-security-provisioning)
        endif()
        foreach(compatibility_case IN LISTS compatibility_cases)
            set(compatibility_arguments
                "-DRDP_RUNTIME_EXECUTABLE=${RDP_RUNTIME_EXECUTABLE}"
                "-DRDP_RUNTIME_VERSION=${RDP_RUNTIME_VERSION}"
                "-DRDP_RUNTIME_TEST_CASE=${compatibility_case}"
                "-DRDP_RUNTIME_FIXTURE_DIRECTORY=${RDP_RUNTIME_FIXTURE_DIRECTORY}/${compatibility_case}")
            if(compatibility_case STREQUAL
               "validates-linux-security-provisioning")
                list(APPEND compatibility_arguments
                    "-DRDP_RUNTIME_LINUX_SECURITY_HELPER=${RDP_RUNTIME_LINUX_SECURITY_HELPER}")
                if(RDP_RUNTIME_HAVE_LINUX_PAM)
                    list(APPEND compatibility_arguments
                        "-DRDP_RUNTIME_HAVE_LINUX_PAM=ON")
                endif()
            endif()
            execute_process(
                COMMAND "${CMAKE_COMMAND}"
                    ${compatibility_arguments}
                    -P "${CMAKE_CURRENT_LIST_FILE}"
                RESULT_VARIABLE compatibility_result
                OUTPUT_VARIABLE compatibility_output
                ERROR_VARIABLE compatibility_error)
            if(NOT compatibility_result STREQUAL "0")
                message(FATAL_ERROR
                    "Legacy runtime compatibility case ${compatibility_case} failed (${compatibility_result})\n${compatibility_output}${compatibility_error}")
            endif()
        endforeach()
        return()
    endif()

    if(NOT DEFINED RDP_RUNTIME_LICENSING_HELPER OR
       RDP_RUNTIME_LICENSING_HELPER STREQUAL "")
        message(FATAL_ERROR "Missing RDP_RUNTIME_LICENSING_HELPER")
    endif()

    set(licensing_certificate
        "${RDP_RUNTIME_FIXTURE_DIRECTORY}/licensing-certificate.bin")
    set(licensing_private_key
        "${RDP_RUNTIME_FIXTURE_DIRECTORY}/licensing-private-key.pem")
    set(licensing_premaster
        "${RDP_RUNTIME_FIXTURE_DIRECTORY}/licensing-premaster.bin")
    set(pristine_certificate
        "${RDP_RUNTIME_FIXTURE_DIRECTORY}/licensing-certificate.pristine")
    set(pristine_private_key
        "${RDP_RUNTIME_FIXTURE_DIRECTORY}/licensing-private-key.pristine")
    set(alternate_certificate
        "${RDP_RUNTIME_FIXTURE_DIRECTORY}/alternate-certificate.bin")
    set(alternate_private_key
        "${RDP_RUNTIME_FIXTURE_DIRECTORY}/alternate-private-key.pem")
    set(alternate_premaster
        "${RDP_RUNTIME_FIXTURE_DIRECTORY}/alternate-premaster.bin")
    set(config_file
        "${RDP_RUNTIME_FIXTURE_DIRECTORY}/${RDP_RUNTIME_TEST_CASE}.conf")

    function(set_private_runtime_file_metadata path)
        if(UNIX)
            file(CHMOD "${path}" PERMISSIONS OWNER_READ OWNER_WRITE)
        elseif(WIN32)
            rdp_windows_make_private_fixture_acl("${path}")
        endif()
    endfunction()

    function(set_public_certificate_metadata path)
        if(UNIX)
            file(CHMOD "${path}" PERMISSIONS
                OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
        elseif(WIN32)
            set_private_runtime_file_metadata("${path}")
        endif()
    endfunction()

    function(write_private_runtime_config config_text)
        if(IS_DIRECTORY "${config_file}")
            file(REMOVE_RECURSE "${config_file}")
        else()
            file(REMOVE "${config_file}")
        endif()
        file(WRITE "${config_file}" "${config_text}")
        set_private_runtime_file_metadata("${config_file}")
    endfunction()

    set(empty_output "")
    set(configuration_failure_output
        "rdp-server: configuration check failed; service remains disabled.\n")
    set(licensing_success_output
        "rdp-server: licensing certificate, matching RSA private key and product identity accepted by the offline R3 credential validator; Microsoft-client trust or acceptance, license issuance, user authentication, RDP session authorization and listener readiness not verified; service remains disabled.\n")

    function(run_runtime_cli option config_text expected_exit
             expected_stdout_variable expected_stderr_variable)
        write_private_runtime_config("${config_text}")
        execute_process(
            COMMAND "${RDP_RUNTIME_EXECUTABLE}" "${option}" "${config_file}"
            RESULT_VARIABLE runtime_exit_code
            OUTPUT_VARIABLE runtime_stdout
            ERROR_VARIABLE runtime_stderr)
        string(REPLACE "\r\n" "\n" runtime_stdout "${runtime_stdout}")
        string(REPLACE "\r\n" "\n" runtime_stderr "${runtime_stderr}")
        if(NOT "${runtime_exit_code}" STREQUAL "${expected_exit}")
            message(FATAL_ERROR
                "Unexpected licensing CLI exit status: ${runtime_exit_code}")
        endif()
        if(NOT runtime_stdout STREQUAL
               "${${expected_stdout_variable}}" OR
           NOT runtime_stderr STREQUAL
               "${${expected_stderr_variable}}")
            message(FATAL_ERROR
                "Licensing CLI output crossed its documented trust boundary")
        endif()
    endfunction()

    file(REMOVE
        "${licensing_certificate}" "${licensing_private_key}"
        "${licensing_premaster}" "${pristine_certificate}"
        "${pristine_private_key}" "${alternate_certificate}"
        "${alternate_private_key}" "${alternate_premaster}")
    execute_process(
        COMMAND "${RDP_RUNTIME_LICENSING_HELPER}"
            emit-runtime-licensing-fixture
            "${licensing_certificate}" "${licensing_private_key}"
            "${licensing_premaster}"
        RESULT_VARIABLE fixture_result
        OUTPUT_VARIABLE fixture_output
        ERROR_VARIABLE fixture_error)
    if(NOT fixture_result STREQUAL "0")
        message(FATAL_ERROR
            "Cannot generate licensing fixture (${fixture_result})\n${fixture_output}${fixture_error}")
    endif()
    set_public_certificate_metadata("${licensing_certificate}")
    set_private_runtime_file_metadata("${licensing_private_key}")
    file(COPY_FILE "${licensing_certificate}" "${pristine_certificate}")
    file(COPY_FILE "${licensing_private_key}" "${pristine_private_key}")
    set_public_certificate_metadata("${pristine_certificate}")
    set_private_runtime_file_metadata("${pristine_private_key}")

    function(restore_licensing_fixture)
        file(REMOVE "${licensing_certificate}" "${licensing_private_key}")
        file(COPY_FILE "${pristine_certificate}" "${licensing_certificate}")
        file(COPY_FILE "${pristine_private_key}" "${licensing_private_key}")
        set_public_certificate_metadata("${licensing_certificate}")
        set_private_runtime_file_metadata("${licensing_private_key}")
    endfunction()

    set(tls_certificate
        "${RDP_RUNTIME_FIXTURE_DIRECTORY}/synthetic-unused-tls.crt")
    set(tls_private_key
        "${RDP_RUNTIME_FIXTURE_DIRECTORY}/synthetic-unused-tls.key")
    set(base_config
        "listen_address=127.0.0.1\nlisten_port=3389\n"
        "tls_certificate=${tls_certificate}\n"
        "tls_private_key=${tls_private_key}\n"
        "authentication=required\nos_authorization=required\n"
        "max_connections=4\n")
    string(JOIN "" base_config ${base_config})
    set(licensing_config
        "licensing_certificate=${licensing_certificate}\n"
        "licensing_private_key=${licensing_private_key}\n"
        "licensing_product_version=393217\n"
        "licensing_company_name=RDP\n"
        "licensing_product_id=A02\n"
        "licensing_scope=scope\n")
    string(JOIN "" licensing_config ${licensing_config})
    set(full_config "${base_config}${licensing_config}")

    if(RDP_RUNTIME_TEST_CASE STREQUAL
       "licensing-cli-valid-provisioning")
        run_runtime_cli(
            "--check-licensing-credentials" "${full_config}" 0
            licensing_success_output empty_output)

    elseif(RDP_RUNTIME_TEST_CASE STREQUAL
           "licensing-cli-incomplete-configuration")
        set(partial_config
            "${base_config}licensing_certificate=${licensing_certificate}\n")
        run_runtime_cli(
            "--check-licensing-credentials" "${partial_config}" 3
            empty_output configuration_failure_output)

        string(REPLACE
            "licensing_scope=scope\n" ""
            missing_scope_config "${full_config}")
        run_runtime_cli(
            "--check-licensing-credentials" "${missing_scope_config}" 3
            empty_output configuration_failure_output)

        string(REPLACE
            "licensing_product_version=393217\n" ""
            missing_version_config "${full_config}")
        run_runtime_cli(
            "--check-licensing-credentials" "${missing_version_config}" 3
            empty_output configuration_failure_output)

        set(duplicate_field_config
            "${full_config}licensing_scope=other\n")
        run_runtime_cli(
            "--check-licensing-credentials" "${duplicate_field_config}" 3
            empty_output configuration_failure_output)

        string(REPLACE
            "licensing_company_name=RDP"
            "licensing_company_name="
            empty_identity_config "${full_config}")
        run_runtime_cli(
            "--check-licensing-credentials" "${empty_identity_config}" 3
            empty_output configuration_failure_output)

    elseif(RDP_RUNTIME_TEST_CASE STREQUAL
           "licensing-cli-invalid-product-identity")
        string(REPLACE
            "licensing_product_version=393217"
            "licensing_product_version=0"
            invalid_config "${full_config}")
        run_runtime_cli(
            "--check-licensing-credentials" "${invalid_config}" 3
            empty_output configuration_failure_output)

        string(REPLACE
            "licensing_product_version=393217"
            "licensing_product_version=4294967296"
            invalid_config "${full_config}")
        run_runtime_cli(
            "--check-licensing-credentials" "${invalid_config}" 3
            empty_output configuration_failure_output)

        string(REPEAT "A" 256 oversized_identity)
        string(REPLACE
            "licensing_company_name=RDP"
            "licensing_company_name=${oversized_identity}"
            invalid_config "${full_config}")
        run_runtime_cli(
            "--check-licensing-credentials" "${invalid_config}" 3
            empty_output configuration_failure_output)

        string(ASCII 195 malformed_utf8_lead)
        string(REPLACE
            "licensing_company_name=RDP"
            "licensing_company_name=R${malformed_utf8_lead}"
            invalid_config "${full_config}")
        run_runtime_cli(
            "--check-licensing-credentials" "${invalid_config}" 3
            empty_output configuration_failure_output)

        string(REPLACE
            "licensing_company_name=RDP"
            "licensing_company_name=R\tDP"
            invalid_config "${full_config}")
        run_runtime_cli(
            "--check-licensing-credentials" "${invalid_config}" 3
            empty_output configuration_failure_output)

        string(ASCII 194 169 unsupported_scope)
        string(REPLACE
            "licensing_scope=scope"
            "licensing_scope=${unsupported_scope}"
            invalid_config "${full_config}")
        run_runtime_cli(
            "--check-licensing-credentials" "${invalid_config}" 3
            empty_output configuration_failure_output)

        string(REPEAT "s" 512 oversized_scope)
        string(REPLACE
            "licensing_scope=scope"
            "licensing_scope=${oversized_scope}"
            invalid_config "${full_config}")
        run_runtime_cli(
            "--check-licensing-credentials" "${invalid_config}" 3
            empty_output configuration_failure_output)

    elseif(RDP_RUNTIME_TEST_CASE STREQUAL
           "licensing-cli-credential-file-denials")
        restore_licensing_fixture()
        file(REMOVE "${licensing_certificate}")
        run_runtime_cli(
            "--check-licensing-credentials" "${full_config}" 3
            empty_output configuration_failure_output)

        restore_licensing_fixture()
        file(REMOVE "${licensing_private_key}")
        run_runtime_cli(
            "--check-licensing-credentials" "${full_config}" 3
            empty_output configuration_failure_output)

        restore_licensing_fixture()
        string(REPLACE
            "${licensing_private_key}" "relative-licensing.key"
            invalid_path_config "${full_config}")
        run_runtime_cli(
            "--check-licensing-credentials" "${invalid_path_config}" 3
            empty_output configuration_failure_output)

        restore_licensing_fixture()
        if(UNIX)
            file(CHMOD "${licensing_certificate}" PERMISSIONS
                OWNER_READ OWNER_WRITE)
        endif()
        file(REMOVE "${licensing_private_key}")
        file(CREATE_LINK
            "${licensing_certificate}" "${licensing_private_key}")
        run_runtime_cli(
            "--check-licensing-credentials" "${full_config}" 3
            empty_output configuration_failure_output)

        restore_licensing_fixture()
        if(UNIX)
            file(CHMOD "${licensing_private_key}" PERMISSIONS
                OWNER_READ OWNER_WRITE GROUP_READ)
        elseif(WIN32)
            rdp_windows_fixture_add_insecure_test_ace(
                "${licensing_private_key}" "S-1-1-0" "R"
                "grant synthetic public licensing-key read ACE")
        endif()
        run_runtime_cli(
            "--check-licensing-credentials" "${full_config}" 3
            empty_output configuration_failure_output)

        restore_licensing_fixture()
        file(WRITE "${licensing_certificate}"
            "NOT_A_LICENSING_CERTIFICATE")
        run_runtime_cli(
            "--check-licensing-credentials" "${full_config}" 3
            empty_output configuration_failure_output)

        restore_licensing_fixture()
        file(WRITE "${licensing_private_key}" "NOT_A_PRIVATE_KEY")
        run_runtime_cli(
            "--check-licensing-credentials" "${full_config}" 3
            empty_output configuration_failure_output)

        execute_process(
            COMMAND "${RDP_RUNTIME_LICENSING_HELPER}"
                emit-runtime-licensing-fixture
                "${alternate_certificate}" "${alternate_private_key}"
                "${alternate_premaster}"
            RESULT_VARIABLE alternate_result
            OUTPUT_VARIABLE alternate_output
            ERROR_VARIABLE alternate_error)
        if(NOT alternate_result STREQUAL "0")
            message(FATAL_ERROR
                "Cannot generate mismatched licensing fixture")
        endif()
        set_private_runtime_file_metadata("${alternate_private_key}")
        restore_licensing_fixture()
        file(REMOVE "${licensing_private_key}")
        file(COPY_FILE
            "${alternate_private_key}" "${licensing_private_key}")
        set_private_runtime_file_metadata("${licensing_private_key}")
        run_runtime_cli(
            "--check-licensing-credentials" "${full_config}" 3
            empty_output configuration_failure_output)

    elseif(RDP_RUNTIME_TEST_CASE STREQUAL
           "licensing-cli-service-still-disabled")
        run_runtime_cli(
            "--check-licensing-credentials" "${full_config}" 0
            licensing_success_output empty_output)
        execute_process(
            COMMAND "${RDP_RUNTIME_EXECUTABLE}"
            RESULT_VARIABLE startup_exit_code
            OUTPUT_VARIABLE startup_stdout
            ERROR_VARIABLE startup_stderr)
        string(REPLACE "\r\n" "\n" startup_stdout "${startup_stdout}")
        string(REPLACE "\r\n" "\n" startup_stderr "${startup_stderr}")
        set(expected_startup_error
            "rdp-server: refusing to start: authenticated OS authorization and authoritative live RDP sessions are unavailable.\n")
        if(NOT startup_exit_code STREQUAL "2" OR
           NOT startup_stdout STREQUAL "" OR
           NOT startup_stderr STREQUAL expected_startup_error)
            message(FATAL_ERROR
                "Successful licensing preflight must not enable service startup")
        endif()
    else()
        message(FATAL_ERROR "Unknown licensing CLI test case")
    endif()
    return()
endif()

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
elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-tls-credentials-option-smuggling")
    set(runtime_arguments "--check-tls-credentials" "R10_SENTINEL_MUST_NOT_APPEAR" "--help")
    set(expected_exit_code 2)
elseif(RDP_RUNTIME_TEST_CASE MATCHES
       "^rejects-linux-serve-(missing-security|nonserialized-budget|wildcard-address)$")
    if(NOT DEFINED RDP_RUNTIME_FIXTURE_DIRECTORY OR
       RDP_RUNTIME_FIXTURE_DIRECTORY STREQUAL "")
        message(FATAL_ERROR "Missing RDP_RUNTIME_FIXTURE_DIRECTORY")
    endif()
    file(MAKE_DIRECTORY "${RDP_RUNTIME_FIXTURE_DIRECTORY}")
    set(config_file
        "${RDP_RUNTIME_FIXTURE_DIRECTORY}/${RDP_RUNTIME_TEST_CASE}.conf")
    set(listen_address "127.0.0.1")
    set(max_connections "1")
    if(RDP_RUNTIME_TEST_CASE STREQUAL
       "rejects-linux-serve-nonserialized-budget")
        set(max_connections "2")
    elseif(RDP_RUNTIME_TEST_CASE STREQUAL
           "rejects-linux-serve-wildcard-address")
        set(listen_address "0.0.0.0")
    endif()
    file(WRITE "${config_file}"
        "listen_address=${listen_address}\nlisten_port=3389\n"
        "tls_certificate=/synthetic-r10/test.crt\n"
        "tls_private_key=/synthetic-r10/test.key\n"
        "authentication=required\nos_authorization=required\n"
        "max_connections=${max_connections}\n")
    if(UNIX)
        file(CHMOD "${config_file}" PERMISSIONS OWNER_READ OWNER_WRITE)
    endif()
    set(runtime_arguments "serve" "--config" "${config_file}")
    set(expected_exit_code 2)
elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-linux-security-missing-provisioning")
    if(NOT DEFINED RDP_RUNTIME_FIXTURE_DIRECTORY OR
       RDP_RUNTIME_FIXTURE_DIRECTORY STREQUAL "")
        message(FATAL_ERROR "Missing RDP_RUNTIME_FIXTURE_DIRECTORY")
    endif()
    file(MAKE_DIRECTORY "${RDP_RUNTIME_FIXTURE_DIRECTORY}")
    set(config_file
        "${RDP_RUNTIME_FIXTURE_DIRECTORY}/${RDP_RUNTIME_TEST_CASE}.conf")
    file(WRITE "${config_file}"
        "listen_address=127.0.0.1\nlisten_port=3389\n"
        "tls_certificate=/synthetic-r10/test.crt\n"
        "tls_private_key=/synthetic-r10/test.key\n"
        "authentication=required\nos_authorization=required\n"
        "max_connections=4\n")
    if(UNIX)
        file(CHMOD "${config_file}" PERMISSIONS OWNER_READ OWNER_WRITE)
    endif()
    set(runtime_arguments "--check-linux-security" "${config_file}")
    set(expected_exit_code 3)
elseif(RDP_RUNTIME_TEST_CASE MATCHES "^(validates|rejects)-(configuration|tls-files|tls-credentials|linux-security)-")
    if(NOT DEFINED RDP_RUNTIME_FIXTURE_DIRECTORY OR
       RDP_RUNTIME_FIXTURE_DIRECTORY STREQUAL "")
        message(FATAL_ERROR "Missing RDP_RUNTIME_FIXTURE_DIRECTORY")
    endif()
    file(MAKE_DIRECTORY "${RDP_RUNTIME_FIXTURE_DIRECTORY}")
    set(config_file "${RDP_RUNTIME_FIXTURE_DIRECTORY}/${RDP_RUNTIME_TEST_CASE}.conf")
    set(check_tls_metadata FALSE)
    set(check_tls_credentials FALSE)
    set(check_linux_security FALSE)
    if(RDP_RUNTIME_TEST_CASE MATCHES "-tls-(files|credentials)-")
        set(check_tls_metadata TRUE)
    endif()
    if(RDP_RUNTIME_TEST_CASE MATCHES "-tls-credentials-")
        set(check_tls_credentials TRUE)
    endif()
    if(RDP_RUNTIME_TEST_CASE MATCHES "-linux-security-")
        set(check_linux_security TRUE)
        set(check_tls_metadata TRUE)
        set(check_tls_credentials TRUE)
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
    if(check_linux_security)
        set(keytab_file
            "${RDP_RUNTIME_FIXTURE_DIRECTORY}/${RDP_RUNTIME_TEST_CASE}.keytab")
        string(APPEND config_text
            "gss_service_principal=TERMSRV/rdp.example.test@EXAMPLE.TEST\n"
            "gss_keytab=FILE:${keytab_file}\n"
            "authorized_kerberos_principal=alice@EXAMPLE.TEST\n"
            "authorized_unix_account=alice\n"
            "authorized_seat=seat0\n"
            "authorized_display=:0\n"
            "authorized_uid=1001\n"
            "authorized_permissions=7\n")
        if(RDP_RUNTIME_HAVE_LINUX_PAM)
            string(APPEND config_text "pam_service=rdp-server-r2-ci\n")
        endif()
    endif()
    if(check_tls_credentials)
        set(valid_certificate [=[-----BEGIN CERTIFICATE-----
MIIBRTCB7aADAgECAgESMAoGCCqGSM49BAMCMCMxITAfBgNVBAMMGHJkcC1zZXJ2
ZXItcjEwLXRpbWUtdGVzdDAgFw0yMDAxMDEwMDAwMDBaGA8yMTIwMDEwMTAwMDAw
MFowIzEhMB8GA1UEAwwYcmRwLXNlcnZlci1yMTAtdGltZS10ZXN0MFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAER5U11inycMqKve0b0RMF2PqDUVQPhR4CWECHQbY2
7+rFi5pncKOkTxKltblZKm/HdcMGdh1pG47kX2rmEIDpg6MQMA4wDAYDVR0TAQH/
BAIwADAKBggqhkjOPQQDAgNHADBEAiBfHoR/od+48kUfNa1TnJvzMd5K55V4xs5f
xEyf+2a6QwIgQuZ6iUBOIXPlG7GX932Ob4XuiIEQk8DK/LooextAsT8=
-----END CERTIFICATE-----
]=])
        set(client_only_certificate [=[-----BEGIN CERTIFICATE-----
MIIBzDCCAXGgAwIBAgIUZkGs/yO3vX3ivI9fsKdqTftOtXMwCgYIKoZIzj0EAwIw
KTEnMCUGA1UEAwwecmRwLXNlcnZlci1yMTAtY2xpZW50b25seS10ZXN0MCAXDTI2
MTAxNjA4MzAyNFoYDzIxMjYwOTIyMDgzMDI0WjApMScwJQYDVQQDDB5yZHAtc2Vy
dmVyLXIxMC1jbGllbnRvbmx5LXRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AARHlTXWKfJwyoq97RvREwXY+oNRVA+FHgJYQIdBtjbv6sWLmmdwo6RPEqW1uVkq
b8d1wwZ2HWkbjuRfauYQgOmDo3UwczAdBgNVHQ4EFgQUtaVxIkarAzc4CC4Ul+SK
p8thI9AwHwYDVR0jBBgwFoAUtaVxIkarAzc4CC4Ul+SKp8thI9AwDAYDVR0TAQH/
BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIwCgYIKoZI
zj0EAwIDSQAwRgIhAL1dSTI0uGnRneUqFzw/ymVNrKrwNLEVK3zncmoTmsqqAiEA
zM3gSCjIAUy6rUxrKsETblErkrn0muJUxG+amk7YRV0=
-----END CERTIFICATE-----
]=])
        set(expired_certificate [=[-----BEGIN CERTIFICATE-----
MIIBRDCB66ADAgECAgEQMAoGCCqGSM49BAMCMCMxITAfBgNVBAMMGHJkcC1zZXJ2
ZXItcjEwLXRpbWUtdGVzdDAeFw0xMDAxMDEwMDAwMDBaFw0yMDAxMDEwMDAwMDBa
MCMxITAfBgNVBAMMGHJkcC1zZXJ2ZXItcjEwLXRpbWUtdGVzdDBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABEeVNdYp8nDKir3tG9ETBdj6g1FUD4UeAlhAh0G2Nu/q
xYuaZ3CjpE8SpbW5WSpvx3XDBnYdaRuO5F9q5hCA6YOjEDAOMAwGA1UdEwEB/wQC
MAAwCgYIKoZIzj0EAwIDSAAwRQIhAIiqy4myNYnYX46VxwOrvow3/6TC3tOWpuAv
gF7I7+vNAiBh3e1PZZ08TwF66SlQJFJF92tDlpHVskeBXGpeP5RIBA==
-----END CERTIFICATE-----
]=])
        set(not_yet_valid_certificate [=[-----BEGIN CERTIFICATE-----
MIIBRzCB76ADAgECAgERMAoGCCqGSM49BAMCMCMxITAfBgNVBAMMGHJkcC1zZXJ2
ZXItcjEwLXRpbWUtdGVzdDAiGA8yMTIwMDEwMTAwMDAwMFoYDzIxMzAwMTAxMDAw
MDAwWjAjMSEwHwYDVQQDDBhyZHAtc2VydmVyLXIxMC10aW1lLXRlc3QwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAARHlTXWKfJwyoq97RvREwXY+oNRVA+FHgJYQIdB
tjbv6sWLmmdwo6RPEqW1uVkqb8d1wwZ2HWkbjuRfauYQgOmDoxAwDjAMBgNVHRMB
Af8EAjAAMAoGCCqGSM49BAMCA0cAMEQCIFeNWwLLZhjQDTzrfgc5+7uJyrAO/ik3
G6OEMig3yNUnAiBnIZ1Y2Xc4Oe5QowWd00pOtE1Mq/34zc7rpmRBxLJmaw==
-----END CERTIFICATE-----
]=])
        set(valid_private_key [=[-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILZ+dgVxkAWBXTPZaP7sTQWMDNkkzFDB89nbT9jsSb/joAoGCCqGSM49
AwEHoUQDQgAER5U11inycMqKve0b0RMF2PqDUVQPhR4CWECHQbY27+rFi5pncKOk
TxKltblZKm/HdcMGdh1pG47kX2rmEIDpgw==
-----END EC PRIVATE KEY-----
]=])
        set(other_private_key [=[-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIQWmj/2/ggsRmYIjESBt/O9Qq/dPpl3dlZr5RUQLwUfoAoGCCqGSM49
AwEHoUQDQgAE1hlUpXLs0O3Y5+S6y7a17EIFMQk8UqNmwiaOiV3HI+nFS2KK6hA/
ufkKgFPh5YDLhRJU8AW202oUdLHcAJjy6g==
-----END EC PRIVATE KEY-----
]=])
        set(encrypted_private_key [=[-----BEGIN ENCRYPTED PRIVATE KEY-----
MIH0MF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBAya3YSvnZsZQjIcn5z
VcltAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQAR5zW2DLx2NbFRgy
rXiNtQSBkJueSanmNwrcL+X4rQrUAi7hY6kLZcnkVFaWGlKY9drPnJSrQhCFsWJ3
gR9TgiOjFmEaQeWZ+Z7vJHaBKwa3IlHieq2rGoUrGYR7DE0Et1FzFpMvNgaC2Px6
bbojipfqEY16R35hsd2MROgBIQ3NaPHt0Lnlp3r2TFPAvJ0kgKikZxduf24WleuP
E0U+IoGqDg==
-----END ENCRYPTED PRIVATE KEY-----
]=])
    endif()
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
    elseif(RDP_RUNTIME_TEST_CASE STREQUAL "validates-linux-security-provisioning")
        # Positive Linux provisioning composes the existing TLS fixture with
        # a generated explicit service keytab, optional explicit PAM service
        # and one native identity rule.
    elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-linux-security-missing-pam-service")
        string(REPLACE "pam_service=rdp-server-r2-ci\n" "" config_text
            "${config_text}")
    elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-linux-security-invalid-pam-service")
        string(REPLACE "pam_service=rdp-server-r2-ci"
            "pam_service=../login" config_text "${config_text}")
    elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-linux-security-password-config")
        string(APPEND config_text "pam_password=R2_PASSWORD_MUST_NOT_BE_CONFIGURED\n")
    elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-linux-security-authorization-result-config")
        string(APPEND config_text "pam_authorized=true\n")
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
            rdp_windows_make_private_fixture_acl("${config_file}")
            if(RDP_RUNTIME_TEST_CASE MATCHES "^rejects-configuration-windows-(everyone|authenticated|users)-write$")
                if(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-windows-everyone-write")
                    set(broad_sid "S-1-1-0")
                elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-windows-authenticated-write")
                    set(broad_sid "S-1-5-11")
                else()
                    set(broad_sid "S-1-5-32-545")
                endif()
                rdp_windows_fixture_add_insecure_test_ace(
                    "${config_file}" "${broad_sid}" "M"
                    "grant synthetic broad write ACE")
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
            if(check_tls_credentials)
                file(WRITE "${certificate_file}" "${valid_certificate}")
                file(WRITE "${private_key_file}" "${valid_private_key}")
            else()
                file(WRITE "${certificate_file}" "SYNTHETIC_CERTIFICATE_METADATA_ONLY")
                file(WRITE "${private_key_file}" "SYNTHETIC_KEY_METADATA_ONLY")
            endif()
            if(UNIX)
                file(CHMOD "${certificate_file}" PERMISSIONS
                    OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
                file(CHMOD "${private_key_file}" PERMISSIONS
                    OWNER_READ OWNER_WRITE)
            elseif(WIN32)
                foreach(material IN ITEMS "${certificate_file}" "${private_key_file}")
                    rdp_windows_make_private_fixture_acl("${material}")
                endforeach()
            endif()
            if(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-tls-credentials-client-only-certificate")
                file(WRITE "${certificate_file}" "${client_only_certificate}")
            elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-tls-credentials-mismatched-key")
                file(WRITE "${private_key_file}" "${other_private_key}")
            elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-tls-credentials-malformed-certificate")
                file(WRITE "${certificate_file}" "NOT_A_PEM_CERTIFICATE")
            elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-tls-credentials-malformed-key")
                file(WRITE "${private_key_file}" "NOT_A_PEM_PRIVATE_KEY")
            elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-tls-credentials-encrypted-key")
                file(WRITE "${private_key_file}" "${encrypted_private_key}")
            elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-tls-credentials-expired-certificate")
                file(WRITE "${certificate_file}" "${expired_certificate}")
            elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-tls-credentials-not-yet-valid-certificate")
                file(WRITE "${certificate_file}" "${not_yet_valid_certificate}")
            elseif(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-tls-files-missing-certificate")
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
            elseif(UNIX AND RDP_RUNTIME_TEST_CASE MATCHES
                   "^(validates-tls-files-nested-real-parent|rejects-tls-files-(key|certificate)-parent-symlink)$")
                # Move a real fixture into a nested directory; only the
                # intended alias path includes a parent-directory symlink.
                set(real_parent "${RDP_RUNTIME_FIXTURE_DIRECTORY}/${RDP_RUNTIME_TEST_CASE}.real-parent")
                set(alias_parent "${RDP_RUNTIME_FIXTURE_DIRECTORY}/${RDP_RUNTIME_TEST_CASE}.link-parent")
                file(MAKE_DIRECTORY "${real_parent}")
                if(RDP_RUNTIME_TEST_CASE STREQUAL "rejects-tls-files-certificate-parent-symlink")
                    set(original_material "${certificate_file}")
                    set(nested_filename "certificate.pem")
                else()
                    set(original_material "${private_key_file}")
                    set(nested_filename "private-key.pem")
                endif()
                set(real_material "${real_parent}/${nested_filename}")
                file(REMOVE "${real_material}")
                file(RENAME "${original_material}" "${real_material}")
                if(RDP_RUNTIME_TEST_CASE MATCHES "-parent-symlink$")
                    file(REMOVE "${alias_parent}")
                    file(CREATE_LINK "${real_parent}" "${alias_parent}" SYMBOLIC)
                    set(referenced_material "${alias_parent}/${nested_filename}")
                else()
                    set(referenced_material "${real_material}")
                endif()
                string(REPLACE "${original_material}" "${referenced_material}"
                    config_text "${config_text}")
                file(WRITE "${config_file}" "${config_text}")
                file(CHMOD "${config_file}" PERMISSIONS OWNER_READ OWNER_WRITE)
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
                rdp_windows_fixture_add_insecure_test_ace(
                    "${private_key_file}" "S-1-1-0" "R"
                    "grant synthetic TLS key public read ACE")
            endif()
            if(check_linux_security)
                if(NOT DEFINED RDP_RUNTIME_LINUX_SECURITY_HELPER OR
                   RDP_RUNTIME_LINUX_SECURITY_HELPER STREQUAL "")
                    message(FATAL_ERROR
                        "Missing RDP_RUNTIME_LINUX_SECURITY_HELPER")
                endif()
                file(REMOVE "${keytab_file}")
                execute_process(
                    COMMAND "${RDP_RUNTIME_LINUX_SECURITY_HELPER}"
                        write-synthetic-keytab "${keytab_file}"
                    RESULT_VARIABLE keytab_result
                    OUTPUT_QUIET ERROR_QUIET)
                if(NOT keytab_result STREQUAL "0" OR
                   NOT EXISTS "${keytab_file}")
                    message(FATAL_ERROR
                        "Cannot create synthetic Linux service keytab")
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
    if(check_linux_security)
        set(runtime_arguments "--check-linux-security" "${config_file}")
    elseif(check_tls_credentials)
        set(runtime_arguments "--check-tls-credentials" "${config_file}")
    elseif(check_tls_metadata)
        set(runtime_arguments "--check-tls-files" "${config_file}")
    else()
        set(runtime_arguments "--check-config" "${config_file}")
    endif()
    if(WIN32 AND RDP_RUNTIME_TEST_CASE STREQUAL "rejects-configuration-windows-relative-file")
        set(runtime_working_directory "${RDP_RUNTIME_FIXTURE_DIRECTORY}")
        get_filename_component(relative_config_file "${config_file}" NAME)
        set(runtime_arguments "--check-config" "${relative_config_file}")
    endif()
    if(RDP_RUNTIME_TEST_CASE MATCHES "^validates-(configuration|tls-files|tls-credentials|linux-security)-")
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
elseif(RDP_RUNTIME_TEST_CASE MATCHES "^validates-tls-credentials-")
    if(NOT runtime_stderr STREQUAL "" OR NOT runtime_stdout STREQUAL
        "rdp-server: TLS certificate is currently valid and matches the private key; trust, hostname, revocation and OS authorization not verified; service remains disabled.\n")
        message(FATAL_ERROR "Offline TLS credential success must not imply trusted service")
    endif()
elseif(RDP_RUNTIME_TEST_CASE STREQUAL "validates-linux-security-provisioning")
    if(RDP_RUNTIME_HAVE_LINUX_PAM)
        set(expected_linux_security_output
            "rdp-server: TLS identity, explicit Linux GSS acceptor credential, PAM service configuration and native identity policy accepted; no user authenticated or session authorized; service remains disabled.\n")
    else()
        set(expected_linux_security_output
            "rdp-server: TLS identity, explicit Linux GSS acceptor credential and native identity policy accepted; no user authenticated or session authorized; service remains disabled.\n")
    endif()
    if(NOT runtime_stderr STREQUAL "" OR
       NOT runtime_stdout STREQUAL expected_linux_security_output)
        message(FATAL_ERROR
            "Linux security preflight must not imply authenticated service")
    endif()
endif()
