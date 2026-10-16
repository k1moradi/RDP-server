# SPDX-License-Identifier: GPL-3.0-or-later
# Exercise the production R10 TLS-context owner without opening a listener.
foreach(required_argument IN ITEMS
        RDP_RUNTIME_TLS_CONTEXT_TEST
        RDP_RUNTIME_TLS_CONTEXT_CASE
        RDP_RUNTIME_FIXTURE_DIRECTORY)
    if(NOT DEFINED ${required_argument} OR "${${required_argument}}" STREQUAL "")
        message(FATAL_ERROR "Missing ${required_argument}")
    endif()
endforeach()

file(MAKE_DIRECTORY "${RDP_RUNTIME_FIXTURE_DIRECTORY}")
set(certificate_file
    "${RDP_RUNTIME_FIXTURE_DIRECTORY}/${RDP_RUNTIME_TLS_CONTEXT_CASE}.crt")
set(private_key_file
    "${RDP_RUNTIME_FIXTURE_DIRECTORY}/${RDP_RUNTIME_TLS_CONTEXT_CASE}.key")
set(replacement_certificate_file
    "${RDP_RUNTIME_FIXTURE_DIRECTORY}/${RDP_RUNTIME_TLS_CONTEXT_CASE}.replacement.crt")
set(replacement_private_key_file
    "${RDP_RUNTIME_FIXTURE_DIRECTORY}/${RDP_RUNTIME_TLS_CONTEXT_CASE}.replacement.key")

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
set(valid_private_key [=[-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILZ+dgVxkAWBXTPZaP7sTQWMDNkkzFDB89nbT9jsSb/joAoGCCqGSM49
AwEHoUQDQgAER5U11inycMqKve0b0RMF2PqDUVQPhR4CWECHQbY27+rFi5pncKOk
TxKltblZKm/HdcMGdh1pG47kX2rmEIDpgw==
-----END EC PRIVATE KEY-----
]=])

file(REMOVE
    "${certificate_file}" "${private_key_file}"
    "${replacement_certificate_file}" "${replacement_private_key_file}")
if(RDP_RUNTIME_TLS_CONTEXT_CASE STREQUAL
   "rejects-live-tls-context-invalid-material")
    file(WRITE "${certificate_file}" "NOT_A_PEM_CERTIFICATE\n")
elseif(RDP_RUNTIME_TLS_CONTEXT_CASE STREQUAL
       "rejects-live-tls-context-extra-certificate-material")
    file(WRITE "${certificate_file}"
        "${valid_certificate}${valid_certificate}")
else()
    file(WRITE "${certificate_file}" "${valid_certificate}")
endif()
file(WRITE "${private_key_file}" "${valid_private_key}")

if(UNIX)
    file(CHMOD "${certificate_file}" PERMISSIONS
        OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
    file(CHMOD "${private_key_file}" PERMISSIONS OWNER_READ OWNER_WRITE)
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
            message(FATAL_ERROR "Cannot set synthetic TLS fixture DACL")
        endif()
        execute_process(COMMAND icacls.exe "${material}"
            /setowner "${runtime_account}"
            RESULT_VARIABLE owner_result OUTPUT_QUIET ERROR_QUIET)
        if(NOT owner_result STREQUAL "0")
            message(FATAL_ERROR "Cannot set synthetic TLS fixture owner")
        endif()
    endforeach()
endif()

set(test_arguments
    "${RDP_RUNTIME_TLS_CONTEXT_CASE}"
    "${certificate_file}"
    "${private_key_file}")
if(RDP_RUNTIME_TLS_CONTEXT_CASE STREQUAL
   "tls-context-survives-credential-path-replacement")
    file(WRITE "${replacement_certificate_file}" "REPLACED_CERTIFICATE\n")
    file(WRITE "${replacement_private_key_file}" "REPLACED_PRIVATE_KEY\n")
    if(UNIX)
        file(CHMOD "${replacement_certificate_file}" PERMISSIONS
            OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
        file(CHMOD "${replacement_private_key_file}" PERMISSIONS
            OWNER_READ OWNER_WRITE)
    endif()
    list(APPEND test_arguments
        "${replacement_certificate_file}" "${replacement_private_key_file}")
endif()

execute_process(
    COMMAND "${RDP_RUNTIME_TLS_CONTEXT_TEST}" ${test_arguments}
    RESULT_VARIABLE test_result
    OUTPUT_VARIABLE test_output
    ERROR_VARIABLE test_error)
if(NOT test_result STREQUAL "0")
    message(FATAL_ERROR
        "Runtime TLS context test failed (${test_result})\n${test_output}${test_error}")
endif()
