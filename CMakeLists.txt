# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.22)
project(RDP_server VERSION 0.1.0
    DESCRIPTION "Portable standards-first C++23 Remote Desktop Protocol server"
    LANGUAGES C CXX)
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
option(RDP_SERVER_BUILD_FUZZERS
       "Build bounded Linux/Clang libFuzzer protocol targets" OFF)
if(RDP_SERVER_BUILD_FUZZERS)
    if(NOT BUILD_TESTING OR NOT RDP_SERVER_BUILD_TESTING)
        message(FATAL_ERROR "Fuzz targets require the existing CTest build")
    endif()
    if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" OR
       NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR
            "RDP_SERVER_BUILD_FUZZERS requires Linux with Clang/libFuzzer")
    endif()
endif()
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
    src/server/transport/rdp_licensing.cpp
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
    src/rdp/gfx_avc420_picture.cpp
    src/rdp/gfx_segmented_data.cpp
    src/rdp/gfx_avc420_segmented_frame.cpp
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
        src/windows/windows_dxgi_pointer_shape.cpp
        src/windows/windows_dxgi_frame_owner.cpp
        src/windows/windows_dxgi_duplication_owner.cpp
        src/windows/windows_d3d11_staging_map.cpp
        src/windows/windows_dxgi_capture_cycle.cpp
        src/windows/windows_capture_session_guard.cpp
        src/windows/windows_input_controller.cpp
        src/windows/windows_cursor_snapshot.cpp)
    target_compile_features(rdp-server-windows-desktop PUBLIC cxx_std_23)
    target_include_directories(rdp-server-windows-desktop PUBLIC
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>")
    target_link_libraries(rdp-server-windows-desktop PRIVATE
        user32 gdi32 d3d11 dxgi wtsapi32)
    if(MSVC)
        target_compile_options(rdp-server-windows-desktop PRIVATE /W4)
    else()
        target_compile_options(rdp-server-windows-desktop PRIVATE
            -Wall -Wextra -Wpedantic -Werror)
    endif()
endif()

# R8 Windows clipboard presentation is noninstalled and never owns CLIPRDR.
# The state machine is compiled on every CI platform through an injected native
# call seam; only Windows includes the dormant User32/GlobalAlloc bridge.
add_library(rdp-server-windows-clipboard STATIC
    src/windows/windows_clipboard_adapter.cpp)
target_compile_features(rdp-server-windows-clipboard PUBLIC cxx_std_23)
target_include_directories(rdp-server-windows-clipboard PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>")
target_link_libraries(rdp-server-windows-clipboard PUBLIC
    rdp-server-protocol)
if(WIN32)
    target_link_libraries(rdp-server-windows-clipboard PRIVATE user32)
endif()
if(MSVC)
    target_compile_options(rdp-server-windows-clipboard PRIVATE /W4)
else()
    target_compile_options(rdp-server-windows-clipboard PRIVATE
        -Wall -Wextra -Wpedantic -Werror)
endif()

# R8 macOS pasteboard presentation is noninstalled and never owns CLIPRDR.
# The portable state owner compiles on every CI platform through an injected
# native seam; only Apple adds the dormant AppKit implementation below.
add_library(rdp-server-macos-clipboard STATIC
    src/platform/macos/mac_clipboard_adapter.cpp)
target_compile_features(rdp-server-macos-clipboard PUBLIC cxx_std_23)
target_include_directories(rdp-server-macos-clipboard PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>")
target_link_libraries(rdp-server-macos-clipboard PUBLIC
    rdp-server-protocol)
if(MSVC)
    target_compile_options(rdp-server-macos-clipboard PRIVATE /W4)
else()
    target_compile_options(rdp-server-macos-clipboard PRIVATE
        -Wall -Wextra -Wpedantic -Werror)
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

# R5 native XInput2 pointer observer. Keep the optional XI2 dependency
# noninstalled and outside the portable protocol SDK; the desktop aggregate
# may still provide capture/cursor/damage/input when xcb-xinput is absent.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(RDP_SERVER_XCB_XINPUT QUIET IMPORTED_TARGET
            xcb xcb-xinput)
    endif()
    if(TARGET PkgConfig::RDP_SERVER_XCB_XINPUT)
        add_library(rdp-server-linux-xinput-pointer STATIC
            src/x11/x11_pointer_position_tracker.cpp)
        target_compile_features(rdp-server-linux-xinput-pointer PUBLIC cxx_std_23)
        target_include_directories(rdp-server-linux-xinput-pointer PUBLIC
            "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>")
        target_link_libraries(rdp-server-linux-xinput-pointer PUBLIC
            PkgConfig::RDP_SERVER_XCB_XINPUT)
        target_compile_options(rdp-server-linux-xinput-pointer PRIVATE
            -Wall -Wextra -Wpedantic -Werror)
    else()
        message(STATUS "R5 xcb-xinput development files unavailable: native pointer observation disabled")
    endif()
endif()

# R5 native XTEST input adapter. Keep it noninstalled and separate from the
# runtime until R2/R3 supply an authorized input-routing boundary.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(RDP_SERVER_XCB_XTEST QUIET IMPORTED_TARGET
            xcb xcb-xtest)
    endif()
    if(TARGET PkgConfig::RDP_SERVER_XCB_XTEST)
        add_library(rdp-server-linux-xtest-input STATIC
            src/x11/x11_input_controller.cpp)
        target_compile_features(rdp-server-linux-xtest-input PUBLIC cxx_std_23)
        target_include_directories(rdp-server-linux-xtest-input PUBLIC
            "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>")
        target_link_libraries(rdp-server-linux-xtest-input PUBLIC
            PkgConfig::RDP_SERVER_XCB_XTEST)
        target_compile_options(rdp-server-linux-xtest-input PRIVATE
            -Wall -Wextra -Wpedantic -Werror)
    else()
        message(STATUS "R5 xcb-xtest development files unavailable: native XTEST input CTest not built")
    endif()
endif()

# R8 Linux clipboard file destination: stream already-validated FileContents
# ranges directly into one caller-selected writable regular-file descriptor.
# It is noninstalled, owns no CLIPRDR writer, and needs no FUSE/portal package.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_library(rdp-server-linux-clipboard-file-destination STATIC
        src/platform/linux/linux_clipboard_file_destination.cpp)
    target_compile_features(
        rdp-server-linux-clipboard-file-destination PUBLIC cxx_std_23)
    target_include_directories(
        rdp-server-linux-clipboard-file-destination PUBLIC
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>")
    target_link_libraries(
        rdp-server-linux-clipboard-file-destination PUBLIC
        rdp-server-protocol)
    target_compile_options(
        rdp-server-linux-clipboard-file-destination PRIVATE
        -Wall -Wextra -Wpedantic -Werror)
endif()

# R8 X11 CLIPBOARD presentation borrows R5's one XCB connection at runtime.
# Keep it noninstalled and separate from the portable protocol archive.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(RDP_SERVER_XCB_CLIPBOARD QUIET IMPORTED_TARGET xcb)
    endif()
    if(TARGET PkgConfig::RDP_SERVER_XCB_CLIPBOARD)
        add_library(rdp-server-linux-x11-clipboard STATIC
            src/x11/x11_clipboard_adapter.cpp)
        target_compile_features(rdp-server-linux-x11-clipboard PUBLIC cxx_std_23)
        target_include_directories(rdp-server-linux-x11-clipboard PUBLIC
            "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>")
        target_link_libraries(rdp-server-linux-x11-clipboard PUBLIC
            rdp-server-protocol
            PkgConfig::RDP_SERVER_XCB_CLIPBOARD
            rdp-server-linux-clipboard-file-destination)
        target_compile_options(rdp-server-linux-x11-clipboard PRIVATE
            -Wall -Wextra -Wpedantic -Werror)
    else()
        message(STATUS "R8 xcb development files unavailable: native X11 clipboard CTests not built")
    endif()
endif()

# One R5 native desktop resource aggregate owns the existing XCB connection
# plus capture/cursor/damage/input children. It remains noninstalled and is
# not linked into the runtime before genuine R2/R3 desktop admission.
if(TARGET rdp-server-x11-connection AND
   TARGET rdp-server-linux-xshm AND
   TARGET rdp-server-linux-xfixes-cursor AND
   TARGET rdp-server-linux-xdamage AND
   TARGET rdp-server-linux-xtest-input)
    add_library(rdp-server-linux-x11-desktop STATIC
        src/x11/x11_desktop_resources.cpp)
    target_compile_features(rdp-server-linux-x11-desktop PUBLIC cxx_std_23)
    target_include_directories(rdp-server-linux-x11-desktop PUBLIC
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>")
    target_link_libraries(rdp-server-linux-x11-desktop PUBLIC
        rdp-server-x11-connection
        rdp-server-linux-xshm
        rdp-server-linux-xfixes-cursor
        rdp-server-linux-xdamage
        rdp-server-linux-xtest-input)
    if(TARGET rdp-server-linux-xinput-pointer)
        target_link_libraries(rdp-server-linux-x11-desktop PUBLIC
            rdp-server-linux-xinput-pointer)
        target_compile_definitions(rdp-server-linux-x11-desktop PRIVATE
            RDP_SERVER_X11_XINPUT_POINTER=1)
    endif()
    target_compile_options(rdp-server-linux-x11-desktop PRIVATE
        -Wall -Wextra -Wpedantic -Werror)
endif()

if(MSVC)
    target_compile_options(rdp-server-protocol PRIVATE /W4)
else()
    target_compile_options(rdp-server-protocol PRIVATE
        -Wall -Wextra -Wpedantic -Werror)
endif()

# R4 real AVC420 producer. x264 is a pinned, vendored, library-only static
# dependency and never enters the installed/exported portable protocol SDK.
set(RDP_SERVER_X264_SOURCE_DIR "${PROJECT_SOURCE_DIR}/third_party/x264")
add_library(rdp-server-x264 STATIC
    ${RDP_SERVER_X264_SOURCE_DIR}/common/osdep.c
    ${RDP_SERVER_X264_SOURCE_DIR}/common/base.c
    ${RDP_SERVER_X264_SOURCE_DIR}/common/cpu.c
    ${RDP_SERVER_X264_SOURCE_DIR}/common/tables.c
    ${RDP_SERVER_X264_SOURCE_DIR}/encoder/api.c
    ${RDP_SERVER_X264_SOURCE_DIR}/common/mc.c
    ${RDP_SERVER_X264_SOURCE_DIR}/common/predict.c
    ${RDP_SERVER_X264_SOURCE_DIR}/common/pixel.c
    ${RDP_SERVER_X264_SOURCE_DIR}/common/macroblock.c
    ${RDP_SERVER_X264_SOURCE_DIR}/common/frame.c
    ${RDP_SERVER_X264_SOURCE_DIR}/common/dct.c
    ${RDP_SERVER_X264_SOURCE_DIR}/common/cabac.c
    ${RDP_SERVER_X264_SOURCE_DIR}/common/common.c
    ${RDP_SERVER_X264_SOURCE_DIR}/common/rectangle.c
    ${RDP_SERVER_X264_SOURCE_DIR}/common/set.c
    ${RDP_SERVER_X264_SOURCE_DIR}/common/quant.c
    ${RDP_SERVER_X264_SOURCE_DIR}/common/deblock.c
    ${RDP_SERVER_X264_SOURCE_DIR}/common/vlc.c
    ${RDP_SERVER_X264_SOURCE_DIR}/common/mvpred.c
    ${RDP_SERVER_X264_SOURCE_DIR}/common/bitstream.c
    ${RDP_SERVER_X264_SOURCE_DIR}/encoder/analyse.c
    ${RDP_SERVER_X264_SOURCE_DIR}/encoder/me.c
    ${RDP_SERVER_X264_SOURCE_DIR}/encoder/ratecontrol.c
    ${RDP_SERVER_X264_SOURCE_DIR}/encoder/set.c
    ${RDP_SERVER_X264_SOURCE_DIR}/encoder/macroblock.c
    ${RDP_SERVER_X264_SOURCE_DIR}/encoder/cabac.c
    ${RDP_SERVER_X264_SOURCE_DIR}/encoder/cavlc.c
    ${RDP_SERVER_X264_SOURCE_DIR}/encoder/encoder.c
    ${RDP_SERVER_X264_SOURCE_DIR}/encoder/lookahead.c)
set_target_properties(rdp-server-x264 PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS YES)
target_include_directories(rdp-server-x264 PUBLIC
    "${RDP_SERVER_X264_SOURCE_DIR}")
target_compile_definitions(rdp-server-x264 PRIVATE
    BIT_DEPTH=8
    HIGH_BIT_DEPTH=0)
if(MSVC)
    target_compile_definitions(rdp-server-x264 PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_options(rdp-server-x264 PRIVATE /w)
else()
    target_compile_options(rdp-server-x264 PRIVATE -w)
endif()
if(NOT WIN32)
    target_link_libraries(rdp-server-x264 PRIVATE m)
endif()

add_library(rdp-server-graphics STATIC
    src/rdp/bgra_nv12_converter.cpp
    src/rdp/x264_avc420_encoder.cpp
    src/rdp/x264_avc420_segmented_frame_producer.cpp)
target_compile_features(rdp-server-graphics PUBLIC cxx_std_23)
target_include_directories(rdp-server-graphics PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>")
target_link_libraries(rdp-server-graphics
    PUBLIC rdp-server-protocol
    PRIVATE rdp-server-x264)
if(MSVC)
    target_compile_options(rdp-server-graphics PRIVATE /W4)
else()
    target_compile_options(rdp-server-graphics PRIVATE
        -Wall -Wextra -Wpedantic -Werror)
endif()

# R10 runtime-only TLS owner: it securely validates one credential snapshot,
# constructs one reusable server SSL_CTX, and creates per-connection SSL owners.
# It is deliberately not installed/exported and never binds or listens.
add_library(rdp-server-runtime-tls STATIC
    src/server/runtime/runtime_tls_context.cpp)
target_compile_features(rdp-server-runtime-tls PUBLIC cxx_std_23)
target_include_directories(rdp-server-runtime-tls PUBLIC
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>")
target_link_libraries(rdp-server-runtime-tls PUBLIC
    OpenSSL::Crypto OpenSSL::SSL)
if(WIN32)
    target_link_libraries(rdp-server-runtime-tls PRIVATE Advapi32)
endif()
if(MSVC)
    target_compile_options(rdp-server-runtime-tls PRIVATE /W4)
else()
    target_compile_options(rdp-server-runtime-tls PRIVATE
        -Wall -Wextra -Wpedantic -Werror)
endif()

# R10 process entry point: compile and test it, but do not install/package
# an RDP service before authenticating and OS-authorizing live sessions.
add_executable(rdp-server src/server/runtime/main.cpp)
target_compile_features(rdp-server PRIVATE cxx_std_23)
target_compile_definitions(rdp-server PRIVATE
    "RDP_SERVER_VERSION=\"${PROJECT_VERSION}\"")
target_link_libraries(rdp-server PRIVATE
    rdp-server-protocol
    rdp-server-runtime-tls)
if(WIN32)
    # GetSecurityInfo on the *opened* file handle requires Advapi32.
    target_link_libraries(rdp-server PRIVATE Advapi32)
endif()
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
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(RDP_SERVER_SYSTEMD_LOGIN QUIET IMPORTED_TARGET
            libsystemd)
    endif()
    add_library(rdp-server-linux-gssapi STATIC
        src/server/security/gssapi_spnego_acceptor.cpp
        src/server/security/gssapi_credssp_binding.cpp
        src/server/security/gssapi_credssp_credentials.cpp
        # Keep the generic injected-evidence bridge deny-only. Positive
        # admission below owns concrete native NSS/logind/watch provenance.
        src/server/security/gssapi_console_gate.cpp
        src/server/security/console_identity_policy.cpp
        src/server/security/console_os_evidence.cpp
        src/server/security/linux_nss_console_evidence.cpp
        src/server/security/linux_logind_console_evidence.cpp
        src/server/security/linux_logind_session_change_watch.cpp
        src/server/security/linux_console_admission.cpp)
    target_compile_features(rdp-server-linux-gssapi PUBLIC cxx_std_23)
    target_include_directories(rdp-server-linux-gssapi PRIVATE
        "${RDP_SERVER_GSSAPI_INCLUDE_DIR}")
    target_link_libraries(rdp-server-linux-gssapi PUBLIC
        rdp-server-protocol "${RDP_SERVER_GSSAPI_LIBRARY}")
    if(TARGET PkgConfig::RDP_SERVER_SYSTEMD_LOGIN)
        target_link_libraries(rdp-server-linux-gssapi PRIVATE
            PkgConfig::RDP_SERVER_SYSTEMD_LOGIN)
        target_compile_definitions(rdp-server-linux-gssapi PRIVATE
            XRDP_CONSOLE_HAVE_SYSTEMD_LOGIN=1)
    endif()
    if(MSVC)
        target_compile_options(rdp-server-linux-gssapi PRIVATE /W4)
    else()
        target_compile_options(rdp-server-linux-gssapi PRIVATE
            -Wall -Wextra -Wpedantic -Werror)
    endif()
    # Not installed or exported; requires an actual Linux Kerberos provider
    # and independently authorized OS admission in a future service.

    # R10 Linux pre-listener security provisioning. It retains one securely
    # opened keytab object and one immutable native identity policy, then
    # configures the existing R2 acceptor from that exact descriptor. No
    # listener, client ticket, user authentication or R3 session is created.
    add_library(rdp-server-linux-runtime-security STATIC
        src/server/runtime/linux_runtime_security.cpp
        src/server/runtime/linux_runtime_connection.cpp)
    target_compile_features(rdp-server-linux-runtime-security PUBLIC cxx_std_23)
    target_include_directories(rdp-server-linux-runtime-security PUBLIC
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>"
        "${RDP_SERVER_GSSAPI_INCLUDE_DIR}")
    target_link_libraries(rdp-server-linux-runtime-security PUBLIC
        rdp-server-linux-gssapi
        rdp-server-runtime-tls)
    target_link_libraries(rdp-server PRIVATE
        rdp-server-linux-runtime-security)
    target_compile_definitions(rdp-server PRIVATE
        RDP_SERVER_HAVE_LINUX_RUNTIME_SECURITY=1)
    target_compile_options(rdp-server-linux-runtime-security PRIVATE
        -Wall -Wextra -Wpedantic -Werror)
endif()

# R5 stateless authorized-input route. Build only where the concrete native
# Linux R2/R3 broker and the one-XCB desktop owner are both present. This
# target owns no session/input state and is never installed or linked runtime.
if(TARGET rdp-server-linux-gssapi AND
   TARGET rdp-server-linux-x11-desktop)
    add_library(rdp-server-linux-x11-authorized-input STATIC
        src/x11/x11_authorized_input_route.cpp)
    target_compile_features(rdp-server-linux-x11-authorized-input PUBLIC cxx_std_23)
    target_include_directories(rdp-server-linux-x11-authorized-input PUBLIC
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>")
    target_link_libraries(rdp-server-linux-x11-authorized-input PUBLIC
        rdp-server-linux-gssapi
        rdp-server-linux-x11-desktop)
    target_compile_options(rdp-server-linux-x11-authorized-input PRIVATE
        -Wall -Wextra -Wpedantic -Werror)
endif()

# R7 native macOS capture remains isolated from the portable protocol target.
# Objective-C++ is enabled only on Apple for the ScreenCaptureKit bridge; the
# owner is not wired into runtime startup before independent R2/R3 admission.
if(APPLE)
    enable_language(OBJCXX)
    find_library(RDP_SERVER_COREVIDEO_FRAMEWORK CoreVideo REQUIRED)
    find_library(RDP_SERVER_COREGRAPHICS_FRAMEWORK CoreGraphics REQUIRED)
    find_library(RDP_SERVER_COREFOUNDATION_FRAMEWORK CoreFoundation REQUIRED)
    find_library(RDP_SERVER_FOUNDATION_FRAMEWORK Foundation REQUIRED)
    find_library(RDP_SERVER_APPKIT_FRAMEWORK AppKit REQUIRED)
    find_library(RDP_SERVER_APPLICATIONSERVICES_FRAMEWORK ApplicationServices REQUIRED)
    find_library(RDP_SERVER_COREMEDIA_FRAMEWORK CoreMedia REQUIRED)
    find_library(RDP_SERVER_SCREENCAPTUREKIT_FRAMEWORK ScreenCaptureKit REQUIRED)

    # R8 native pasteboard callbacks stay separate from R7 capture/input and
    # are never linked into the installed portable protocol SDK.
    target_sources(rdp-server-macos-clipboard PRIVATE
        src/platform/macos/mac_clipboard_adapter.mm)
    set_source_files_properties(
        src/platform/macos/mac_clipboard_adapter.mm
        PROPERTIES COMPILE_OPTIONS "-fobjc-arc")
    set_target_properties(rdp-server-macos-clipboard PROPERTIES
        OBJCXX_STANDARD 23
        OBJCXX_STANDARD_REQUIRED YES
        OBJCXX_EXTENSIONS NO)
    target_link_libraries(rdp-server-macos-clipboard PRIVATE
        "${RDP_SERVER_FOUNDATION_FRAMEWORK}"
        "${RDP_SERVER_APPKIT_FRAMEWORK}")

    add_library(rdp-server-macos-capture STATIC
        src/platform/macos/capture_pixel_layout.cpp
        src/platform/macos/capture_framebuffer_view.cpp
        src/platform/macos/capture_pixel_buffer.cpp
        src/platform/macos/desktop_display_geometry.cpp
        src/platform/macos/screen_capture_preflight.cpp
        src/platform/macos/native_display_snapshot.cpp
        src/platform/macos/native_display_geometry.cpp
        src/platform/macos/native_display_refresh.cpp
        src/platform/macos/native_display_reconfiguration.cpp
        src/platform/macos/native_session_change_watch.cpp
        src/platform/macos/native_session_change_watch.mm
        src/platform/macos/mac_cursor_snapshot.cpp
        src/platform/macos/mac_cursor_snapshot.mm
        src/platform/macos/mac_input_controller.cpp
        src/platform/macos/mac_input_controller.mm
        src/platform/macos/mac_desktop_session_guard.cpp
        src/platform/macos/screen_capture_stream.cpp
        src/platform/macos/screen_capture_stream.mm)
    set_source_files_properties(
        src/platform/macos/mac_cursor_snapshot.mm
        src/platform/macos/native_session_change_watch.mm
        src/platform/macos/screen_capture_stream.mm
        PROPERTIES COMPILE_OPTIONS "-fobjc-arc")
    set_target_properties(rdp-server-macos-capture PROPERTIES
        OBJCXX_STANDARD 23
        OBJCXX_STANDARD_REQUIRED YES
        OBJCXX_EXTENSIONS NO)
    target_compile_features(rdp-server-macos-capture PUBLIC cxx_std_23)
    target_include_directories(rdp-server-macos-capture PUBLIC
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>")
    target_link_libraries(rdp-server-macos-capture PUBLIC
        "${RDP_SERVER_COREVIDEO_FRAMEWORK}"
        "${RDP_SERVER_COREGRAPHICS_FRAMEWORK}"
        "${RDP_SERVER_COREFOUNDATION_FRAMEWORK}"
        "${RDP_SERVER_FOUNDATION_FRAMEWORK}"
        "${RDP_SERVER_APPKIT_FRAMEWORK}"
        "${RDP_SERVER_APPLICATIONSERVICES_FRAMEWORK}"
        "${RDP_SERVER_COREMEDIA_FRAMEWORK}"
        "${RDP_SERVER_SCREENCAPTUREKIT_FRAMEWORK}")
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
    PATTERN "linux" EXCLUDE
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
