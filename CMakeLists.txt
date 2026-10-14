# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.22)
project(RDP_server VERSION 0.1.0
    DESCRIPTION "Portable standards-first C++23 Remote Desktop Protocol server"
    LANGUAGES CXX)
include(CTest)
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
    set(_rdp_tests
        test_owned_rdp_x224
        test_owned_security_negotiation
        test_owned_mcs_connect_initial
        test_owned_gcc_conference_create
        test_owned_preauth_session
        test_owned_remote_transfer
        test_clipboard_protocol
        test_owned_credssp_binding
        test_owned_credssp_tsrequest
        test_base64_codec)
    foreach(name IN LISTS _rdp_tests)
        add_executable(${name} "tests/${name}.cpp")
        target_link_libraries(${name} PRIVATE rdp-server-protocol)
        if(name MATCHES "mcs_connect_initial|gcc_conference_create|preauth_session")
            target_compile_definitions(${name} PRIVATE
                "OWNED_MCS_FIXTURE_PATH=\"${CMAKE_SOURCE_DIR}/tests/fixtures/ms_rdpbcgr_4_1_3_mcs_connect_initial.hex\"")
        endif()
        if(MSVC)
            target_compile_options(${name} PRIVATE /UNDEBUG)
        else()
            target_compile_options(${name} PRIVATE -UNDEBUG)
        endif()
        add_test(NAME ${name} COMMAND ${name})
    endforeach()
endif()

install(TARGETS rdp-server-protocol ARCHIVE
    DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(DIRECTORY src/ DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/rdp-server"
    FILES_MATCHING PATTERN "*.h")
# A server executable will only be shipped after real-client acceptance.
