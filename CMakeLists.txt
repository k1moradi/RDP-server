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
if(MSVC)
    target_compile_options(rdp-server-protocol PRIVATE /W4)
else()
    target_compile_options(rdp-server-protocol PRIVATE
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
    FILES_MATCHING PATTERN "*.h")
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
