# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.22)

foreach(required_variable IN ITEMS RDP_ROOT_CMAKE RDP_RUNTIME_ENTRYPOINT_SOURCE)
    if(NOT DEFINED ${required_variable})
        message(FATAL_ERROR "${required_variable} is required")
    endif()
endforeach()

file(READ "${RDP_ROOT_CMAKE}" root_cmake)
file(READ "${RDP_RUNTIME_ENTRYPOINT_SOURCE}" runtime_entrypoint)

foreach(required_fragment IN ITEMS
        "target_link_libraries(rdp-server PRIVATE\n        rdp-server-runtime-platform-native-desktop)"
        "rdp-server-windows-desktop\n            rdp-server-windows-native-session-evidence"
        "rdp-server-macos-capture\n            rdp-server-macos-native-session-evidence"
        "target_compile_definitions(rdp-server PRIVATE\n        RDP_SERVER_HAVE_PLATFORM_NATIVE_DESKTOP=1)")
    string(FIND "${root_cmake}" "${required_fragment}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR
            "production runtime is missing platform-native linkage fragment: ${required_fragment}")
    endif()
endforeach()

foreach(required_fragment IN ITEMS
        "#include \"runtime_platform_native_desktop.h\""
        "RDP_SERVER_HAVE_PLATFORM_NATIVE_DESKTOP"
        "platformNativeDesktopLifetime;")
    string(FIND "${runtime_entrypoint}" "${required_fragment}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR
            "production entry point is missing R10 platform lifetime fragment: ${required_fragment}")
    endif()
endforeach()

string(REGEX MATCHALL
    "RuntimePlatformNativeDesktop[ \t\r\n]+platformNativeDesktopLifetime"
    owner_declarations "${runtime_entrypoint}")
list(LENGTH owner_declarations owner_count)
if(NOT owner_count EQUAL 1)
    message(FATAL_ERROR
        "production entry point must own exactly one R10 platform-native lifetime")
endif()

string(FIND "${runtime_entrypoint}" "platformNativeDesktopLifetime.attach(" attach_call)
if(NOT attach_call EQUAL -1)
    message(FATAL_ERROR
        "startup must not attach platform-native authority without the serialized authenticated serve path")
endif()
