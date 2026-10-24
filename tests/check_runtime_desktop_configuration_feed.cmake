# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.22)

foreach(required_var IN ITEMS
        RDP_RUNTIME_CONFIGURATION_HEADER
        RDP_RUNTIME_CONFIGURATION_SOURCE
        RDP_RUNTIME_MAIN_SOURCE
        RDP_GUI_MAIN_SOURCE
        RDP_ROOT_CMAKE)
    if(NOT DEFINED ${required_var})
        message(FATAL_ERROR "missing ${required_var}")
    endif()
endforeach()

file(READ "${RDP_RUNTIME_CONFIGURATION_HEADER}" configuration_header)
file(READ "${RDP_RUNTIME_CONFIGURATION_SOURCE}" configuration_source)
file(READ "${RDP_RUNTIME_MAIN_SOURCE}" runtime_main)
file(READ "${RDP_GUI_MAIN_SOURCE}" gui_main)
file(READ "${RDP_ROOT_CMAKE}" root_cmake)

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
        "configureLinuxRuntimeAdmissionFromConfiguration("
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
        "configureLinuxRuntimeAdmissionFromConfiguration("
        "RuntimeServerTlsContext::"
        "configureRuntimeLicensingContextFromConfiguration("
        "LinuxRuntimeHostControl runtime{"
        "LinuxPortableDesktopRuntime applicationRuntime"
        "applicationRuntime.hostControl()")
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


# The CLI's Linux-only serialized service aggregate must remain entirely inside
# the production Linux runtime-security guard. This prevents non-Linux builds
# from seeing Linux-only types and catches a dropped opening #if before CI.
string(FIND "${runtime_main}"
    "#if defined(RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY)\n// R10's verified listener"
    linux_service_guard)
string(FIND "${runtime_main}"
    "struct LinuxServeAcceptContext final" linux_service_context)
string(FIND "${runtime_main}"
    "[[nodiscard]] bool runLinuxPersonalDesktopServe(" linux_service_entry)
if(linux_service_guard LESS 0 OR linux_service_context LESS linux_service_guard
   OR linux_service_entry LESS linux_service_context)
    message(FATAL_ERROR
        "serialized Linux serve block escaped its runtime-security guard")
endif()


# Expert --config remains supported, but ordinary startup must own the
# automatic application runtime rather than a bare unprovisioned controller.
string(FIND "${gui_main}"
    "LinuxPortableDesktopRuntime applicationRuntime" portable_runtime)
string(FIND "${gui_main}"
    "auto& runtime = applicationRuntime.hostControl()" portable_control)
string(FIND "${gui_main}"
    "LinuxRuntimeHostControl runtime;" bare_unprovisioned_runtime)
if(portable_runtime LESS 0 OR portable_control LESS 0)
    message(FATAL_ERROR
        "zero-argument desktop startup lost automatic application runtime")
endif()
if(NOT bare_unprovisioned_runtime EQUAL -1)
    message(FATAL_ERROR
        "zero-argument desktop startup regressed to unprovisioned HostControl")
endif()


# Product builds must not require a user to discover the production-security
# CMake switch. A normal Linux desktop build composes that graph automatically;
# headless SDK/protocol jobs remain able to opt out by disabling the GUI.
foreach(required_text IN ITEMS
        "option(RDP_SERVER_BUILD_DESKTOP_GUI"
        "if(CMAKE_SYSTEM_NAME STREQUAL \"Linux\" AND RDP_SERVER_BUILD_DESKTOP_GUI)"
        "set(RDP_SERVER_ENABLE_LINUX_RUNTIME_SECURITY ON)")
    string(FIND "${root_cmake}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR
            "Linux desktop product lost automatic runtime-security composition: ${required_text}")
    endif()
endforeach()
