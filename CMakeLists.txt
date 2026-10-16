# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.22)
project(RDP_server VERSION 0.1.0
    DESCRIPTION "Portable standards-first C++23 Remote Desktop Protocol server"
    LANGUAGES CXX)
include(CTest)

# The only build root is <checkout>/build; local checkout: ~/rdp-server.
# Each ephemeral CI job uses one checkout-local build root.
if(NOT CMAKE_BINARY_DIR STREQUAL "${PROJECT_SOURCE_DIR}/build")
    message(FATAL_ERROR "Reuse only ${PROJECT_SOURCE_DIR}/build; local path: ~/rdp-server/build")
endif()

# Hosted CI has an isolated ephemeral checkout; ordinary local builds must
# also use the specified home checkout, not merely a same-named build subdir.
if(NOT "$ENV{GITHUB_ACTIONS}" STREQUAL "true")
    if(WIN32)
        set(rdp_home_directory "$ENV{USERPROFILE}")
    else()
        set(rdp_home_directory "$ENV{HOME}")
    endif()
    if(rdp_home_directory STREQUAL "")
        message(FATAL_ERROR "Cannot determine home directory for ~/rdp-server")
    endif()
    file(TO_CMAKE_PATH "${rdp_home_directory}" normalized_rdp_home)
    set(required_rdp_source_directory "${normalized_rdp_home}/rdp-server")
    cmake_path(NORMAL_PATH required_rdp_source_directory)
    cmake_path(NORMAL_PATH PROJECT_SOURCE_DIR OUTPUT_VARIABLE actual_rdp_source_directory)
    if(NOT actual_rdp_source_directory STREQUAL required_rdp_source_directory)
        message(FATAL_ERROR
            "Local checkout must be ~/rdp-server (actual: ${PROJECT_SOURCE_DIR}). "
            "Only ~/rdp-server/build may contain local build output.")
    endif()
endif()
include(GNUInstallDirs)
option(RDP_SERVER_BUILD_TESTING "Build protocol regression tests" ON)
# Explicit Linux-only developer gate; no GSS dependency in the portable
# protocol SDK, macOS/Windows builds or default downstream consumers.
option(RDP_SERVER_TEST_LINUX_GSSAPI
       "Compile/test the first-party Linux GSSAPI provider (no admission)" OFF)
option(RDP_SERVER_TEST_REAL_KERBEROS
       "Opt-in REAL external FILE: keytab+ticket SPNEGO validation (no OS admission)" OFF)
if(RDP_SERVER_TEST_REAL_KERBEROS)
    if(NOT RDP_SERVER_TEST_LINUX_GSSAPI OR
       NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" OR
       NOT BUILD_TESTING)
        message(FATAL_ERROR "Real Kerberos probe requires Linux GSSAPI test mode")
    endif()
    foreach(required_var IN ITEMS RDP_TEST_KRB5_SERVICE
                                  RDP_TEST_KRB5_KEYTAB
                                  RDP_TEST_KRB5_CCACHE)
        if(NOT DEFINED ENV{${required_var}} OR "$ENV{${required_var}}" STREQUAL "")
            message(FATAL_ERROR "Real Kerberos probe requires explicit ${required_var}")
        endif()
    endforeach()
    if(NOT "$ENV{RDP_TEST_KRB5_SERVICE}" MATCHES "^TERMSRV/.+@.+$" OR
       NOT "$ENV{RDP_TEST_KRB5_KEYTAB}" MATCHES "^FILE:/.+" OR
       NOT "$ENV{RDP_TEST_KRB5_CCACHE}" MATCHES "^FILE:/.+")
        message(FATAL_ERROR "Real Kerberos probe requires explicit TERMSRV/...@REALM and FILE:/ keytab/cache")
    endif()
endif()
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)

# No xrdp, VNC, patched upstream C runtime, or network-listening daemon.
# Additional imported first-party algorithms remain in src/ but are not
# linked until their OS-independent contracts and acceptance tests are ready.
add_library(rdp-server-protocol STATIC
    src/server/transport/tpkt_x224.cpp
    src/server/transport/mcs_connect_initial.cpp
    src/server/transport/mcs_channel_connection.cpp
    src/server/transport/mcs_connect_response.cpp
    src/server/transport/gcc_conference_create.cpp
    src/server/transport/security_negotiation.cpp
    src/server/transport/preauth_session.cpp
    src/server/transport/nonblocking_tcp_adapter.cpp
    src/server/security/base64_codec.cpp
    src/server/security/credssp_tsrequest.cpp
    src/server/security/credssp_credentials.cpp
    src/server/security/credssp_binding.cpp
    src/server/security/credssp_tls_certificate.cpp
    src/server/clipboard/remote_transfer.cpp
    src/clipboard/clipboard_protocol.cpp
    src/core/generation_tile_map.cpp
    src/rdp/gfx_surface_lifecycle.cpp
    src/rdp/gfx_avc420_capabilities.cpp
    src/rdp/gfx_frame_acknowledge.cpp
    src/rdp/gfx_presentation_lifecycle.cpp
    src/rdp/verified_bitmap_cache16.cpp)
target_compile_features(rdp-server-protocol PUBLIC cxx_std_23)
# These are the same public include prefixes in both the checkout and
# the installed protocol SDK; experimental OS adapters are not linked.
add_library(RDPServer::protocol ALIAS rdp-server-protocol)
set_target_properties(rdp-server-protocol PROPERTIES EXPORT_NAME protocol)
target_include_directories(rdp-server-protocol PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>"
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/server>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/rdp-server>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/rdp-server/server>")
target_link_libraries(rdp-server-protocol PUBLIC
    OpenSSL::Crypto OpenSSL::SSL)
# Native nonblocking TCP is a thin platform adapter. The portable RDP
# connection owner and its protocol/authorization semantics stay shared.
if(WIN32)
    target_link_libraries(rdp-server-protocol PUBLIC ws2_32)
endif()

# First native XShm translation-unit target. Optional Linux XCB developer
# packages keep the portable protocol library and owner one-liner working.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND BUILD_TESTING AND
   RDP_SERVER_BUILD_TESTING)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(RDP_SERVER_XCB_SHM QUIET IMPORTED_TARGET
            xcb xcb-shm)
    endif()
    if(TARGET PkgConfig::RDP_SERVER_XCB_SHM)
        add_library(rdp-server-linux-xshm STATIC
            src/x11/x11_shared_memory_capture.cpp)
        target_compile_features(rdp-server-linux-xshm PUBLIC cxx_std_23)
        target_include_directories(rdp-server-linux-xshm PUBLIC
            "${PROJECT_SOURCE_DIR}/src")
        target_link_libraries(rdp-server-linux-xshm PUBLIC
            PkgConfig::RDP_SERVER_XCB_SHM)
        target_compile_options(rdp-server-linux-xshm PRIVATE
            -Wall -Wextra -Wpedantic -Werror)
    endif()
endif()

# R6 native monitor geometry is a separate, noninstalled Windows adapter:
# it does not pull user32/Win32 headers into the portable protocol archive.
if(WIN32)
    add_library(rdp-server-windows-desktop STATIC
        src/windows/windows_desktop_geometry.cpp
        src/windows/windows_bgra_frame.cpp
        src/windows/windows_dxgi_damage.cpp
        src/windows/windows_dxgi_frame_owner.cpp
        src/windows/windows_d3d11_staging_map.cpp
        src/windows/windows_dxgi_capture_cycle.cpp)
    target_compile_features(rdp-server-windows-desktop PUBLIC cxx_std_23)
    target_include_directories(rdp-server-windows-desktop PUBLIC
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>")
    target_link_libraries(rdp-server-windows-desktop PRIVATE user32)
    if(MSVC)
        target_compile_options(rdp-server-windows-desktop PRIVATE /W4)
    else()
        target_compile_options(rdp-server-windows-desktop PRIVATE
            -Wall -Wextra -Wpedantic -Werror)
    endif()
endif()

# R5 first-party native XCB/RandR connection; the portable RDP SDK
# never links XCB. The native target is built when the development
# packages exist; CI provisions them on Linux for exact-SHA coverage.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(RDP_SERVER_XCB_RANDR QUIET IMPORTED_TARGET
            xcb xcb-randr)
    endif()
    if(RDP_SERVER_XCB_RANDR_FOUND)
        add_library(rdp-server-x11-connection STATIC
            src/x11/x11_display_connection.cpp)
        target_compile_features(rdp-server-x11-connection PUBLIC cxx_std_23)
        target_include_directories(rdp-server-x11-connection PUBLIC
            "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>")
        target_link_libraries(rdp-server-x11-connection PUBLIC
            PkgConfig::RDP_SERVER_XCB_RANDR)
        target_compile_options(rdp-server-x11-connection PRIVATE
            -Wall -Wextra -Wpedantic -Werror)
    else()
        message(STATUS "R5 xcb/xcb-randr headers unavailable: native X11 connection CTest not built")
    endif()
endif()

# Native XFixes cursor owner remains separate from the portable engine
# and is testable without a live X server. No xrdp libraries are used.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(RDP_SERVER_XCB_XFIXES QUIET IMPORTED_TARGET
            xcb xcb-xfixes)
    endif()
    if(TARGET PkgConfig::RDP_SERVER_XCB_XFIXES)
        add_library(rdp-server-linux-xfixes-cursor STATIC
            src/x11/x11_cursor_tracker.cpp
            src/x11/cursor_image_conversion.cpp)
        target_compile_features(rdp-server-linux-xfixes-cursor PUBLIC cxx_std_23)
        target_include_directories(rdp-server-linux-xfixes-cursor PUBLIC
            "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>")
        target_link_libraries(rdp-server-linux-xfixes-cursor PUBLIC
            PkgConfig::RDP_SERVER_XCB_XFIXES)
        target_compile_options(rdp-server-linux-xfixes-cursor PRIVATE
            -Wall -Wextra -Wpedantic -Werror)
    else()
        message(STATUS "R5 xcb-xfixes development files unavailable: native XFixes cursor CTest not built")
    endif()
endif()

# R5 native XDamage adapter compiles the real Damage tracker against
# XCB-Damage. Keep it noninstalled and separate from the portable SDK.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(RDP_SERVER_XCB_DAMAGE QUIET IMPORTED_TARGET
            xcb xcb-damage)
    endif()
    if(TARGET PkgConfig::RDP_SERVER_XCB_DAMAGE)
        add_library(rdp-server-linux-xdamage STATIC
            src/x11/x11_damage_tracker.cpp
            src/core/damage_region.cpp)
        target_compile_features(rdp-server-linux-xdamage PUBLIC cxx_std_23)
        target_include_directories(rdp-server-linux-xdamage PUBLIC
            "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>")
        target_link_libraries(rdp-server-linux-xdamage PUBLIC
            PkgConfig::RDP_SERVER_XCB_DAMAGE)
        target_compile_options(rdp-server-linux-xdamage PRIVATE
            -Wall -Wextra -Wpedantic -Werror)
    else()
        message(STATUS "R5 xcb-damage development files unavailable: native XDamage CTest not built")
    endif()
endif()

if(MSVC)
    target_compile_options(rdp-server-protocol PRIVATE /W4)
else()
    target_compile_options(rdp-server-protocol PRIVATE
        -Wall -Wextra -Wpedantic -Werror)
endif()

# R10 process entry point: compile and test it, but do not install/package
# an RDP service before authenticating and OS-authorizing live sessions.
add_executable(rdp-server src/server/runtime/main.cpp)
target_compile_features(rdp-server PRIVATE cxx_std_23)
target_compile_definitions(rdp-server PRIVATE
    "RDP_SERVER_VERSION=\"${PROJECT_VERSION}\"")
target_link_libraries(rdp-server PRIVATE rdp-server-protocol)
if(MSVC)
    target_compile_options(rdp-server PRIVATE /W4)
else()
    target_compile_options(rdp-server PRIVATE
        -Wall -Wextra -Wpedantic -Werror)
endif()

if(RDP_SERVER_TEST_LINUX_GSSAPI)
    if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" OR
       NOT BUILD_TESTING OR NOT RDP_SERVER_BUILD_TESTING)
        message(FATAL_ERROR "Linux GSSAPI validation requires Linux with tests enabled")
    endif()
    find_path(RDP_SERVER_GSSAPI_INCLUDE_DIR NAMES gssapi/gssapi.h REQUIRED)
    find_library(RDP_SERVER_GSSAPI_LIBRARY NAMES gssapi_krb5 REQUIRED)
    add_library(rdp-server-linux-gssapi STATIC
        src/server/security/gssapi_spnego_acceptor.cpp
        src/server/security/gssapi_credssp_binding.cpp
        src/server/security/gssapi_credssp_credentials.cpp)
    target_compile_features(rdp-server-linux-gssapi PUBLIC cxx_std_23)
    target_include_directories(rdp-server-linux-gssapi PRIVATE
        "${RDP_SERVER_GSSAPI_INCLUDE_DIR}")
    target_link_libraries(rdp-server-linux-gssapi PUBLIC
        rdp-server-protocol "${RDP_SERVER_GSSAPI_LIBRARY}")
    if(MSVC)
        target_compile_options(rdp-server-linux-gssapi PRIVATE /W4)
    else()
        target_compile_options(rdp-server-linux-gssapi PRIVATE
            -Wall -Wextra -Wpedantic -Werror)
    endif()
    # Not installed or exported; requires an actual Linux Kerberos provider
    # and independently authorized OS admission in a future service.
endif()

# R7 native capture ingestion only: retain CoreVideo buffers and preflight
# Screen Recording permission without activating a capture stream or service.
# No Apple frameworks are linked into the portable protocol library.
if(APPLE)
    find_library(RDP_SERVER_COREVIDEO_FRAMEWORK CoreVideo REQUIRED)
    find_library(RDP_SERVER_COREGRAPHICS_FRAMEWORK CoreGraphics REQUIRED)
    add_library(rdp-server-macos-capture STATIC
        src/platform/macos/capture_pixel_layout.cpp
        src/platform/macos/capture_pixel_buffer.cpp
        src/platform/macos/desktop_display_geometry.cpp
        src/platform/macos/screen_capture_preflight.cpp
        src/platform/macos/native_display_snapshot.cpp
        src/platform/macos/native_display_geometry.cpp)
    target_compile_features(rdp-server-macos-capture PUBLIC cxx_std_23)
    target_include_directories(rdp-server-macos-capture PUBLIC
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>")
    target_link_libraries(rdp-server-macos-capture PUBLIC
        "${RDP_SERVER_COREVIDEO_FRAMEWORK}"
        "${RDP_SERVER_COREGRAPHICS_FRAMEWORK}")
    target_compile_options(rdp-server-macos-capture PRIVATE
        -Wall -Wextra -Wpedantic -Werror)
endif()

if(BUILD_TESTING AND RDP_SERVER_BUILD_TESTING)
    add_subdirectory(tests)
endif()

# Installable protocol SDK, not a service or an installable RDP daemon.
# Preserve the existing include tree to avoid breaking first-party APIs.
include(CMakePackageConfigHelpers)
set(rdp_package_cmake_dir "${CMAKE_INSTALL_LIBDIR}/cmake/RDPServerProtocol")
configure_package_config_file(
    "${PROJECT_SOURCE_DIR}/cmake/RDPServerProtocolConfig.cmake.in"
    "${PROJECT_BINARY_DIR}/RDPServerProtocolConfig.cmake"
    INSTALL_DESTINATION "${rdp_package_cmake_dir}")
write_basic_package_version_file(
    "${PROJECT_BINARY_DIR}/RDPServerProtocolConfigVersion.cmake"
    VERSION "${PROJECT_VERSION}"
    COMPATIBILITY SameMajorVersion)

install(TARGETS rdp-server-protocol EXPORT RDPServerProtocolTargets
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(DIRECTORY src/ DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/rdp-server"
    FILES_MATCHING PATTERN "*.h"
    PATTERN "windows" EXCLUDE
    PATTERN "macos" EXCLUDE
    PATTERN "x11" EXCLUDE)
install(EXPORT RDPServerProtocolTargets
    FILE RDPServerProtocolTargets.cmake
    NAMESPACE RDPServer::
    DESTINATION "${rdp_package_cmake_dir}")
install(FILES
    "${PROJECT_BINARY_DIR}/RDPServerProtocolConfig.cmake"
    "${PROJECT_BINARY_DIR}/RDPServerProtocolConfigVersion.cmake"
    DESTINATION "${rdp_package_cmake_dir}")
install(FILES
    "${PROJECT_SOURCE_DIR}/LICENSE"
    "${PROJECT_SOURCE_DIR}/NOTICE"
    "${PROJECT_SOURCE_DIR}/docs/THIRD_PARTY.md"
    DESTINATION "${CMAKE_INSTALL_DATADIR}/rdp-server")

# Cross-platform ZIP packages are SDK artifacts only; they do not contain
# a desktop server, daemon, service unit, account admission or installer.
set(CPACK_GENERATOR ZIP)
set(CPACK_PACKAGE_NAME "rdp-server-protocol")
set(CPACK_PACKAGE_VENDOR "RDP-server")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "Development-only C++23 RDP protocol library; NOT a working RDP server")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_FILE_NAME
    "rdp-server-protocol-${PROJECT_VERSION}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE")
include(CPack)
# A server executable will only be shipped after real-client acceptance.
