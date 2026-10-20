# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.22)

foreach(required_var IN ITEMS
        RDP_RUNTIME_CONFIGURATION_HEADER
        RDP_RUNTIME_CONFIGURATION_SOURCE
        RDP_RUNTIME_MAIN_SOURCE
        RDP_GUI_MAIN_SOURCE)
    if(NOT DEFINED ${required_var})
        message(FATAL_ERROR "missing ${required_var}")
    endif()
endforeach()

file(READ "${RDP_RUNTIME_CONFIGURATION_HEADER}" configuration_header)
file(READ "${RDP_RUNTIME_CONFIGURATION_SOURCE}" configuration_source)
file(READ "${RDP_RUNTIME_MAIN_SOURCE}" runtime_main)
file(READ "${RDP_GUI_MAIN_SOURCE}" gui_main)

foreach(required_text IN ITEMS
        "RuntimeConfigurationView"
        "visitRuntimeConfigurationFile"
        "RuntimeConfigurationCapabilities")
    string(FIND "${configuration_header}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR "shared configuration API missing: ${required_text}")
    endif()
endforeach()

foreach(required_text IN ITEMS
        "O_NOFOLLOW"
        "kMaximumConfigurationBytes = 4096U"
        "hasRestrictedConfigurationDacl")
    string(FIND "${configuration_source}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR "secure configuration policy missing: ${required_text}")
    endif()
endforeach()

foreach(required_text IN ITEMS
        "visitRuntimeConfigurationFile("
        "configureLinuxRuntimeSecurityFromConfiguration("
        "configureRuntimeLicensingContextFromConfiguration(")
    string(FIND "${runtime_main}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR "CLI no longer consumes shared configuration: ${required_text}")
    endif()
endforeach()

foreach(forbidden_text IN ITEMS
        "kConfigurationFields"
        "isValidConfiguration("
        "gss_keytab=")
    string(FIND "${runtime_main}" "${forbidden_text}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR "CLI retained duplicate configuration grammar: ${forbidden_text}")
    endif()
endforeach()

foreach(required_text IN ITEMS
        "--config"
        "visitRuntimeConfigurationFile("
        "configureLinuxRuntimeSecurityFromConfiguration("
        "RuntimeServerTlsContext::"
        "configureRuntimeLicensingContextFromConfiguration("
        "LinuxRuntimeHostControl runtime{")
    string(FIND "${gui_main}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR "desktop configuration feed missing: ${required_text}")
    endif()
endforeach()

foreach(forbidden_text IN ITEMS
        "gss_keytab="
        "tls_certificate="
        "authorized_unix_account=")
    string(FIND "${gui_main}" "${forbidden_text}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR "desktop duplicated configuration grammar: ${forbidden_text}")
    endif()
endforeach()
