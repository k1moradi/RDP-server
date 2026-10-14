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
    src/server/transport/gcc_conference_create.cpp
    src/server/transport/security_negotiation.cpp
    src/server/transport/preauth_session.cpp
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
target_include_directories(rdp-server-protocol PUBLIC
    "${PROJECT_SOURCE_DIR}/src"
    "${PROJECT_SOURCE_DIR}/src/server")
target_link_libraries(rdp-server-protocol PUBLIC
    OpenSSL::Crypto OpenSSL::SSL)
if(MSVC)
    target_compile_options(rdp-server-protocol PRIVATE /W4)
else()
    target_compile_options(rdp-server-protocol PRIVATE
        -Wall -Wextra -Wpedantic -Werror)
endif()

if(BUILD_TESTING AND RDP_SERVER_BUILD_TESTING)
    add_subdirectory(tests)
endif()

install(TARGETS rdp-server-protocol ARCHIVE
    DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(DIRECTORY src/ DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/rdp-server"
    FILES_MATCHING PATTERN "*.h")
# A server executable will only be shipped after real-client acceptance.
