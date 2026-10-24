# SPDX-License-Identifier: GPL-3.0-or-later
# Provision the secure production R10 TLS fixture. Direct R10 cases do not
# listen; R1/R10 integration cases bind only an ephemeral loopback listener.
foreach(required_argument IN ITEMS
        RDP_RUNTIME_TLS_CONTEXT_TEST
        RDP_RUNTIME_TLS_CONTEXT_CASE
        RDP_RUNTIME_FIXTURE_DIRECTORY)
    if(NOT DEFINED ${required_argument} OR "${${required_argument}}" STREQUAL "")
        message(FATAL_ERROR "Missing ${required_argument}")
    endif()
endforeach()

if(WIN32)
    include("${CMAKE_CURRENT_LIST_DIR}/windows_private_fixture_acl.cmake")
endif()

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

set(lan_identity_certificate [=[-----BEGIN CERTIFICATE-----
MIIBlzCCAT6gAwIBAgIIASNFZ4mrze8wCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwM
cmRwLWxhbi50ZXN0MCAXDTIwMDEwMTAwMDAwMFoYDzIxMjAwMTAxMDAwMDAwWjAX
MRUwEwYDVQQDDAxyZHAtbGFuLnRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AAQUmxwjmsJBOyaDOY20350MJSfTBv38B8eNhd10TDJVdn1gfFYNvxL1xKI9X7S4
MFWsh8/UH0SdFwFKc/dbJig2o3IwcDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQE
AwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATA7BgNVHREENDAyggxyZHAtbGFuLnRl
c3SCCmhvc3QubG9jYWyHBMCoMgqHEP0AAAAAAAAAAAAAAAAAEjQwCgYIKoZIzj0E
AwIDRwAwRAIgEuSrHpJ45vaeIIkMmx73cbcFTh0PKYySbuCGBD+fLyoCIG6LlAPS
zx/SlE1wYWR9fIhl3H2DELlJ31/5kncUyjg0
-----END CERTIFICATE-----
]=])
set(lan_identity_private_key [=[-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUz+QK4kd4IbYRo/N
IeqFb1yc+RbUly6LUZ1GU8gJKo2hRANCAAQUmxwjmsJBOyaDOY20350MJSfTBv38
B8eNhd10TDJVdn1gfFYNvxL1xKI9X7S4MFWsh8/UH0SdFwFKc/dbJig2
-----END PRIVATE KEY-----
]=])

file(REMOVE
    "${certificate_file}" "${private_key_file}"
    "${replacement_certificate_file}" "${replacement_private_key_file}")
if(RDP_RUNTIME_TLS_CONTEXT_CASE STREQUAL
   "validates-lan-endpoint-certificate-identity")
    file(WRITE "${certificate_file}" "${lan_identity_certificate}")
    file(WRITE "${private_key_file}" "${lan_identity_private_key}")
elseif(RDP_RUNTIME_TLS_CONTEXT_CASE STREQUAL
   "rejects-live-tls-context-invalid-material")
    file(WRITE "${certificate_file}" "NOT_A_PEM_CERTIFICATE\n")
elseif(RDP_RUNTIME_TLS_CONTEXT_CASE STREQUAL
       "rejects-live-tls-context-extra-certificate-material")
    file(WRITE "${certificate_file}"
        "${valid_certificate}${valid_certificate}")
else()
    file(WRITE "${certificate_file}" "${valid_certificate}")
endif()
if(RDP_RUNTIME_TLS_CONTEXT_CASE STREQUAL
   "rejects-live-tls-context-private-key-mismatch")
    file(WRITE "${private_key_file}" "${lan_identity_private_key}")
elseif(NOT RDP_RUNTIME_TLS_CONTEXT_CASE STREQUAL
       "validates-lan-endpoint-certificate-identity")
    file(WRITE "${private_key_file}" "${valid_private_key}")
endif()

if(UNIX)
    file(CHMOD "${certificate_file}" PERMISSIONS
        OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
    file(CHMOD "${private_key_file}" PERMISSIONS OWNER_READ OWNER_WRITE)
elseif(WIN32)
    foreach(material IN ITEMS "${certificate_file}" "${private_key_file}")
        rdp_windows_make_private_fixture_acl("${material}")
    endforeach()
endif()

set(test_arguments
    "${RDP_RUNTIME_TLS_CONTEXT_CASE}"
    "${certificate_file}"
    "${private_key_file}")
if(RDP_RUNTIME_TLS_CONTEXT_CASE STREQUAL
       "tls-context-survives-credential-path-replacement"
   OR RDP_RUNTIME_TLS_CONTEXT_CASE STREQUAL
       "tcp-owned-runtime-tls-identity-continuity"
   OR RDP_RUNTIME_TLS_CONTEXT_CASE STREQUAL
       "tls-identity-offline-lifecycle-denials")
    if(RDP_RUNTIME_TLS_CONTEXT_CASE STREQUAL
       "tls-identity-offline-lifecycle-denials")
        file(WRITE "${replacement_certificate_file}"
            "${lan_identity_certificate}")
        file(WRITE "${replacement_private_key_file}"
            "${lan_identity_private_key}")
    else()
        file(WRITE "${replacement_certificate_file}" "REPLACED_CERTIFICATE\n")
        file(WRITE "${replacement_private_key_file}" "REPLACED_PRIVATE_KEY\n")
    endif()
    if(UNIX)
        file(CHMOD "${replacement_certificate_file}" PERMISSIONS
            OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
        file(CHMOD "${replacement_private_key_file}" PERMISSIONS
            OWNER_READ OWNER_WRITE)
    elseif(WIN32 AND RDP_RUNTIME_TLS_CONTEXT_CASE STREQUAL
           "tls-identity-offline-lifecycle-denials")
        foreach(material IN ITEMS
                "${replacement_certificate_file}"
                "${replacement_private_key_file}")
            rdp_windows_make_private_fixture_acl("${material}")
        endforeach()
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
