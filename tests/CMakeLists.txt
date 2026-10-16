# SPDX-License-Identifier: GPL-3.0-or-later
# Reuse one registry and preserve test executable/source file identities.
function(add_rdp_test source_file suite behavior)
    get_filename_component(test_target "${source_file}" NAME_WE)
    add_executable("${test_target}" "${source_file}")
    target_link_libraries("${test_target}" PRIVATE rdp-server-protocol)
    if(test_target MATCHES "mcs_connect_initial|gcc_conference_create|preauth_session")
        target_compile_definitions("${test_target}" PRIVATE
            "OWNED_MCS_FIXTURE_PATH=\"${PROJECT_SOURCE_DIR}/tests/fixtures/ms_rdpbcgr_4_1_3_mcs_connect_initial.hex\"")
    endif()
    if(MSVC)
        target_compile_options("${test_target}" PRIVATE /UNDEBUG)
    else()
        target_compile_options("${test_target}" PRIVATE -UNDEBUG)
    endif()
    if(test_target STREQUAL "test_owned_mcs_connect_initial")
        # Split four existing envelope behavior groups, plus two new
        # T.125 domain-negotiation groups, from the SAME executable.
        foreach(case_name IN ITEMS
                mcs-envelope-microsoft
                mcs-envelope-tpkt-errors
                mcs-envelope-ber-errors
                mcs-envelope-mutations
                mcs-domain-merge
                mcs-domain-rejections
                mcs-response-wire
                mcs-response-rejections
                mcs-erect-request
                mcs-attach-request
                mcs-channel-join-request
                mcs-attach-confirm-wire
                mcs-channel-join-confirm
                mcs-join-write-completion
                mcs-join-write-denials
                mcs-join-duplicate-ignored
                mcs-join-batched-requests
                mcs-send-data-joined-membership
                mcs-send-data-joined-denials
                mcs-join-stale-write-receipts
                mcs-join-stale-partial-write-slices
                mcs-send-indication-joined-wire
                mcs-send-indication-joined-denials
                mcs-session-unverified-connect
                mcs-session-unverified-ordering
                mcs-session-first-envelope-size-bounds
                mcs-session-unadmitted-domain-size-bounds
                mcs-session-first-failure-boundaries
                mcs-disconnect-wire
                mcs-disconnect-rejections
                mcs-send-data-wire
                mcs-send-data-rejections
                mcs-send-indication-wire
                mcs-send-indication-rejections
                share-control-header-wire
                share-control-header-rejections
                share-data-header-wire
                share-data-header-rejections
                share-sync-finalization-wire
                share-sync-finalization-rejections
                share-control-finalization-wire
                share-control-finalization-rejections
                share-active-capabilities-wire
                share-active-capabilities-rejections
                share-general-capability-wire
                share-general-capability-rejections
                share-bitmap-capability-wire
                share-bitmap-capability-rejections
                share-demand-active-encode-wire
                share-demand-active-encode-rejections
                share-server-finalization-encode-wire
                share-server-finalization-encode-rejections
                share-active-exchange-correlation
                share-active-exchange-denials
                share-finalization-exchange-correlation
                share-finalization-exchange-denials)
            add_test(NAME "transport.${case_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("transport.${case_name}" PROPERTIES
                LABELS "protocol;transport")
        endforeach()
    elseif(test_target STREQUAL "test_owned_preauth_session")
        # Seventeen behavior groups from ONE existing executable: no duplicate
        # compilation, executables, state controllers or fixture sources.
        foreach(case_name IN ITEMS
                preauth-session-lifecycle
                mcs-preauth-terminal-revocation
                mcs-preauth-first-envelope-size-bound
                x224-request-fragments
                x224-request-outcomes
                x224-confirm-write-order
                x224-confirm-partial-writes
                tcp-adapter-fragments
                tcp-adapter-backpressure
                tcp-bio-chunk-bounds
                tcp-native-chunk-bounds
                tcp-native-accept-ownership
                tcp-native-accept-move-replacement
                tcp-native-accept-orderly-eof
                tcp-native-accept-batch-budget-handoff
                tcp-native-accept-batch-stops-denials
                tcp-listener-poll-budget-handoff
                tcp-listener-poll-deadline-denials
                tcp-owned-connection-tls-lifecycle
                tcp-owned-connection-cancellation
                tcp-owned-readiness-dispatch
                tcp-owned-reply-interest-priority
                tcp-owned-deadline-cancellation
                tcp-owned-bounded-poll-loopback-tls
                tcp-owned-bounded-poll-timeout-eof
                tls-nonblocking-handshake
                tls-nonblocking-failures
                tcp-native-loopback-tls
                tcp-native-loopback-close
                tcp-attached-tls-ownership-denials
                tcp-attached-mcs-order-denials
                tls-handshake-gate
                x224-length-and-close
                mcs-decrypted-fragments
                mcs-decrypted-rejections
                mcs-tls-record-fragments
                mcs-tls-record-rejections
                mcs-tls-selected-certificate-continuity
                mcs-tls-selected-certificate-substitution
                credssp-tls-fragments
                credssp-tls-coalesced
                credssp-tls-rejections
                credssp-tls-provenance
                credssp-tls-certificate-pinning
                credssp-tls-reply-wire
                credssp-tls-reply-backpressure
                credssp-tls-reply-rejections
                credssp-tls-reply-cert-pending
                credssp-tls-reply-cert-completion
                credssp-tls-reply-cert-backpressure
                credssp-tls-failure-reply-wire
                credssp-tls-failure-reply-rejections)
            add_test(NAME "transport.${case_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("transport.${case_name}" PROPERTIES
                LABELS "protocol;transport")
        endforeach()
        # Fail fast with a NAMED CTest TIMEOUT instead of tying up a
        # Windows worker forever if native connect/backlog handling stalls.
        # Keep both original production assertions intact.
        set_tests_properties(
            transport.tcp-native-accept-batch-budget-handoff
            transport.tcp-native-accept-batch-stops-denials
            transport.tcp-listener-poll-budget-handoff
            transport.tcp-listener-poll-deadline-denials
            PROPERTIES TIMEOUT 20)
        # Live server-cert binding belongs to the existing real TLS
        # fixture, but exposes separate positive and negative security
        # contracts rather than hiding them under transport CTest.
        foreach(case_name IN ITEMS
                credssp-active-tls-binding-positive
                credssp-active-tls-binding-rejections)
            add_test(NAME "security.${case_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("security.${case_name}" PROPERTIES
                LABELS "protocol;security")
        endforeach()
    elseif(test_target STREQUAL "test_linux_gssapi_spnego")
        foreach(case_name IN ITEMS
                gssapi-configuration-rejections
                gssapi-framed-handoff
                gssapi-console-provenance-before-os-read)
            add_test(NAME "security.${case_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("security.${case_name}" PROPERTIES
                LABELS "security;linux-provider")
        endforeach()
    elseif(test_target STREQUAL "test_owned_credssp_tsrequest")
        # Reuse the existing one binary: five previous semantic
        # groups and three new streaming/boundary behaviors.
        foreach(case_name IN ITEMS
                credssp-der-basic
                credssp-der-opaque
                credssp-der-rejections
                credssp-der-bounds
                credssp-der-mutations
                credssp-stream-fragments
                credssp-stream-coalesced
                credssp-stream-rejections
                credssp-server-reply-wire
                credssp-server-reply-rejections
                credssp-server-failure-wire
                credssp-server-failure-rejections
                credssp-final-negotiation-binding
                credssp-final-binding-rejections)
            add_test(NAME "security.${case_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("security.${case_name}" PROPERTIES
                LABELS "protocol;security")
        endforeach()
    elseif(test_target STREQUAL "test_gfx_presentation_lifecycle")
        foreach(case_name IN ITEMS
                channel-lifecycle-ordering
                channel-lifecycle-denials
                surface-resize-revocation
                frame-publication-backpressure
                frame-delivery-receipt-ordering
                frame-delivery-abort-revocation)
            add_test(NAME "graphics.${case_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("graphics.${case_name}" PROPERTIES
                LABELS "protocol;graphics")
        endforeach()
    elseif(test_target STREQUAL "test_gfx_frame_acknowledge")
        # One production-backed graphics executable, six behavior CTests.
        foreach(case_name IN ITEMS
                frame-ack-wire
                frame-ack-suspension
                frame-ack-rejections
                frame-ack-correlation
                frame-ack-bounded-backpressure
                frame-ack-stale-generation)
            add_test(NAME "graphics.${case_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("graphics.${case_name}" PROPERTIES
                LABELS "protocol;graphics")
        endforeach()
    elseif(test_target STREQUAL "test_gfx_avc420_capabilities")
        # Same production-linked executable, three independent wire behaviors.
        foreach(case_name IN ITEMS
                avc420-capabilities-selection
                avc420-capabilities-rejections
                avc420-capabilities-header-bounds)
            add_test(NAME "graphics.${case_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("graphics.${case_name}" PROPERTIES
                LABELS "protocol;graphics")
        endforeach()
    elseif(test_target STREQUAL "test_gfx_surface_lifecycle")
        foreach(case_name IN ITEMS
                surface-lifecycle-wire
                surface-lifecycle-rejections)
            add_test(NAME "graphics.${case_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("graphics.${case_name}" PROPERTIES
                LABELS "protocol;graphics")
        endforeach()
    elseif(test_target STREQUAL "test_owned_remote_transfer")
        # Preserve the default regression and register the three R8 cases.
        add_test(NAME "clipboard.remote-transfer" COMMAND "${test_target}")
        set_tests_properties("clipboard.remote-transfer" PROPERTIES
            LABELS "protocol;clipboard")
        foreach(case_name IN ITEMS
                long-format-list-generation
                short-format-list-negotiation
                format-list-response-native-acceptance
                capabilities-negotiation-format-gating
                format-list-response-joined-mcs-envelope
                joined-static-channel-inbound-gates
                prefetch-unicode-png-dib-single-flight
                format-data-request-joined-mcs-envelope
                format-data-request-generation-cancellation)
            add_test(NAME "clipboard.${case_name}"
                COMMAND "${test_target}" "${case_name}")
            set_tests_properties("clipboard.${case_name}" PROPERTIES
                LABELS "protocol;clipboard")
        endforeach()
    else()
        add_test(NAME "${suite}.${behavior}" COMMAND "${test_target}")
        set_tests_properties("${suite}.${behavior}" PROPERTIES
            LABELS "protocol;${suite}")
    endif()
endfunction()

add_rdp_test(test_owned_rdp_x224.cpp transport x224)
add_rdp_test(test_owned_security_negotiation.cpp transport security-negotiation)
add_rdp_test(test_owned_mcs_connect_initial.cpp transport mcs-connect-initial)
add_rdp_test(test_owned_gcc_conference_create.cpp transport gcc-conference-create)
add_rdp_test(test_owned_preauth_session.cpp transport preauth-session)
if(TARGET rdp-server-linux-gssapi)
    # Exercise real TLS -> actual MIT GSSAPI handoff using the existing
    # in-memory TLS fixture; no duplicate certificate/test implementation.
    target_link_libraries(test_owned_preauth_session PRIVATE
        rdp-server-linux-gssapi)
    target_compile_definitions(test_owned_preauth_session PRIVATE
        RDP_TEST_LINUX_GSSAPI=1)
    if(RDP_SERVER_TEST_REAL_KERBEROS)
        target_compile_definitions(test_owned_preauth_session PRIVATE
            RDP_TEST_REAL_KERBEROS=1)
        foreach(case_name IN ITEMS
                gssapi-real-kerberos-tls-mechanism
                gssapi-real-kerberos-tls-failure)
            add_test(NAME "security.${case_name}"
                COMMAND test_owned_preauth_session "${case_name}")
            set_tests_properties("security.${case_name}"
                PROPERTIES LABELS "security;linux-provider;opt-in-kerberos")
        endforeach()
    endif()
    foreach(case_name IN ITEMS
            gssapi-tls-ownership
            gssapi-principal-tls-proof-gate
            gssapi-tls-framed-credential-denials
            gssapi-final-combined-denials
            gssapi-negotiation-reply-gates
            gssapi-failure-reply-denials
            gssapi-binding-reply-gates
            gssapi-reply-order-denials
            gssapi-framed-binding-only-denials
            gssapi-framed-binding-reply-order)
        add_test(NAME "security.${case_name}"
            COMMAND test_owned_preauth_session "${case_name}")
        set_tests_properties("security.${case_name}" PROPERTIES
            LABELS "security;linux-provider")
    endforeach()
endif()
add_rdp_test(test_owned_remote_transfer.cpp clipboard remote-transfer)
# R9 bounded mutational wire negative corpus, reusing the production test.
add_test(NAME clipboard.mcs-cliprdr-length-mutation-denials
    COMMAND test_owned_remote_transfer mcs-cliprdr-length-mutation-denials)
set_tests_properties(clipboard.mcs-cliprdr-length-mutation-denials PROPERTIES
    LABELS "protocol;clipboard;security;offline")
# Offline MCS-joined membership/teardown integration, not TLS/OS admission.
add_test(NAME clipboard.mcs-joined-response-teardown
    COMMAND test_owned_remote_transfer mcs-joined-response-teardown)
set_tests_properties(clipboard.mcs-joined-response-teardown PROPERTIES
    LABELS "protocol;clipboard;security;offline")
# A separate fail-closed framing contract, dispatched by the same native test.
add_test(NAME clipboard.remote-transfer-framing-rejections
    COMMAND test_owned_remote_transfer framing-rejections)
set_tests_properties(clipboard.remote-transfer-framing-rejections PROPERTIES
    LABELS "protocol;clipboard;security")
add_rdp_test(test_clipboard_protocol.cpp clipboard protocol)
# R9 bounded fragmentation, ownership and reset regression; reuse test binary.
add_test(NAME clipboard.chunk-reassembly-reset-bounds
    COMMAND test_clipboard_protocol chunk-reassembly-reset-bounds)
set_tests_properties(clipboard.chunk-reassembly-reset-bounds PROPERTIES
    LABELS "protocol;clipboard;security")
add_rdp_test(test_owned_credssp_binding.cpp security credssp-binding)
add_rdp_test(test_owned_credssp_tsrequest.cpp security credssp-tsrequest)
add_rdp_test(test_base64_codec.cpp security base64-codec)
add_rdp_test(test_gfx_surface_lifecycle.cpp graphics surface-lifecycle)
add_rdp_test(test_gfx_avc420_capabilities.cpp graphics avc420-capabilities)
add_rdp_test(test_gfx_frame_acknowledge.cpp graphics frame-ack-wire)
add_rdp_test(test_gfx_presentation_lifecycle.cpp graphics channel-lifecycle)
if(TARGET rdp-server-linux-gssapi)
    add_rdp_test(test_linux_gssapi_spnego.cpp security linux-gssapi)
    target_link_libraries(test_linux_gssapi_spnego PRIVATE
        rdp-server-linux-gssapi)
endif()

# R6 fixture-only checks: do not enumerate a real desktop, capture pixels,
# or inject input during an ordinary Windows CTest run.
if(TARGET rdp-server-windows-desktop)
    add_executable(test_windows_desktop_geometry
        test_windows_desktop_geometry.cpp
        windows_geometry_gdi_type_probe.cpp
        windows_capture_cycle_cases.cpp
        windows_capture_damage_cases.cpp)
    target_link_libraries(test_windows_desktop_geometry PRIVATE
        rdp-server-windows-desktop)
    if(MSVC)
        target_compile_options(test_windows_desktop_geometry PRIVATE /UNDEBUG)
    else()
        target_compile_options(test_windows_desktop_geometry PRIVATE -UNDEBUG)
    endif()
    foreach(case_name IN ITEMS
            negative-origin-and-monitor-gaps
            invalid-layout-rejections
            order-stable-reconfiguration
            capture-bgra-stride-and-pixel-order
            capture-bgra-invalid-frame-denials)
        add_test(NAME "windows.geometry-${case_name}"
            COMMAND test_windows_desktop_geometry "${case_name}")
        set_tests_properties("windows.geometry-${case_name}" PROPERTIES
            LABELS "windows;desktop-geometry;offline")
    endforeach()
    # Regression for the WinGDI Rectangle function hiding our portable type.
    add_test(NAME windows.geometry-gdi-rectangle-name-resolution
        COMMAND test_windows_desktop_geometry win32-gdi-rectangle-name-resolution)
    set_tests_properties(windows.geometry-gdi-rectangle-name-resolution
        PROPERTIES LABELS "windows;desktop-geometry;offline")
    # R6 native duplication frame-lease RAII: synthetic callbacks only, no
    # AcquireNextFrame on an actual Windows desktop during ordinary tests.
    foreach(case_name IN ITEMS
            dxgi-frame-lease-lifecycle
            dxgi-frame-lease-rejections)
        add_test(NAME "windows.capture-${case_name}"
            COMMAND test_windows_desktop_geometry "${case_name}")
        set_tests_properties("windows.capture-${case_name}" PROPERTIES
            LABELS "windows;desktop-capture;offline")
    endforeach()
    # R6 D3D11 staging frame/map RAII, injected callbacks only.
    foreach(case_name IN ITEMS
            d3d11-staging-bgra-map-lifetime
            d3d11-staging-map-denials)
        add_test(NAME "windows.capture-${case_name}"
            COMMAND test_windows_desktop_geometry "${case_name}")
        set_tests_properties("windows.capture-${case_name}" PROPERTIES
            LABELS "windows;desktop-capture;offline")
    endforeach()
    # R6 capture-cycle ordering; synthetic callbacks, no desktop access.
    add_test(NAME windows.capture-frame-ordered-lifetime
        COMMAND test_windows_desktop_geometry capture-cycle-ordered-lifetime)
    add_test(NAME windows.capture-frame-cancel-and-topology-rejections
        COMMAND test_windows_desktop_geometry capture-cycle-cancel-and-topology-rejections)
    set_tests_properties(
        windows.capture-frame-ordered-lifetime
        windows.capture-frame-cancel-and-topology-rejections
        PROPERTIES LABELS "windows;desktop-capture;offline")
    # Scoped synchronous consumption never leaves a DXGI lease or staging map
    # live after returning, including cancellation and sink rejection.
    foreach(case_name IN ITEMS
            capture-cycle-synchronous-consume-lifetime
            capture-cycle-synchronous-consume-denials)
        add_test(NAME "windows.capture-${case_name}"
            COMMAND test_windows_desktop_geometry "${case_name}")
        set_tests_properties("windows.capture-${case_name}" PROPERTIES
            LABELS "windows;desktop-capture;offline")
    endforeach()
    # R6 independent caller-owned BGRA snapshot, using the existing cycle
    # and one synchronous copy before native unmap/duplication release.
    foreach(case_name IN ITEMS
            capture-packed-copy-lifetime
            capture-packed-copy-denials)
        add_test(NAME "windows.${case_name}"
            COMMAND test_windows_desktop_geometry "${case_name}")
        set_tests_properties("windows.${case_name}" PROPERTIES
            LABELS "windows;desktop-capture;offline")
    endforeach()
    # One bounded native frame metadata reader; synthetic tests never access DXGI.
    foreach(case_name IN ITEMS
            dxgi-native-damage-map-lifetime
            dxgi-native-damage-denials)
        add_test(NAME "windows.capture-${case_name}"
            COMMAND test_windows_desktop_geometry "${case_name}")
        set_tests_properties("windows.capture-${case_name}" PROPERTIES
            LABELS "windows;desktop-capture;offline")
    endforeach()
    # R6 DXGI metadata converts native move/dirty descriptors only; tests
    # never acquire an output or call live native input/capture APIs.
    add_test(NAME windows.capture-dxgi-move-before-dirty
        COMMAND test_windows_desktop_geometry dxgi-dirty-and-move-regions)
    add_test(NAME windows.capture-dxgi-metadata-rejections
        COMMAND test_windows_desktop_geometry dxgi-metadata-denials)
    set_tests_properties(
        windows.capture-dxgi-move-before-dirty
        windows.capture-dxgi-metadata-rejections
        PROPERTIES LABELS "windows;capture;offline")
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_rdp_test(test_x11_capture_layout.cpp x11 capture-layout-bounds)
    set_tests_properties(x11.capture-layout-bounds PROPERTIES
        LABELS "x11;linux-adapter")
endif()

# One R10 production executable, and one offline CMake-script checker,
# without opening a listener, reading real credentials or installing a service.
foreach(runtime_case IN ITEMS
        rejects-unconfigured-startup
        rejects-unrecognized-options
        rejects-help-option-smuggling
        rejects-version-option-smuggling
        rejects-sensitive-argument-output
        displays-help-without-startup
        reports-version-without-startup
        validates-configuration-syntax
        validates-configuration-comments-crlf
        rejects-configuration-public-listener
        rejects-configuration-missing-auth
        rejects-configuration-missing-os-policy
        rejects-configuration-disabled-auth
        rejects-configuration-disabled-os-policy
        rejects-configuration-duplicate-field
        rejects-configuration-invalid-port
        rejects-configuration-invalid-limit
        rejects-configuration-oversized-file
        rejects-configuration-unknown-field
        rejects-configuration-control-comment
        rejects-configuration-relative-key
        rejects-configuration-traversal-key
        rejects-configuration-identical-tls-paths
        rejects-configuration-missing-file
        rejects-config-option-smuggling
        validates-configuration-owner-only
        validates-configuration-mode-normalization
        rejects-configuration-symlink
        rejects-configuration-fifo
        rejects-configuration-group-writable
        rejects-configuration-directory
        validates-configuration-windows-regular
        rejects-configuration-windows-directory
        rejects-configuration-windows-relative-file
        rejects-windows-device-namespace
        validates-configuration-windows-private-dacl
        rejects-configuration-windows-everyone-write
        rejects-configuration-windows-authenticated-write
        rejects-configuration-windows-users-write
        )
    if(NOT WIN32 AND runtime_case MATCHES
       "^(validates-configuration-windows-(regular|private-dacl)|rejects-configuration-windows-(directory|relative-file|everyone-write|authenticated-write|users-write)|rejects-windows-device-namespace)$")
        continue()
    endif()
    # POSIX descriptor-identity/permissions tests are not applicable to
    # Windows native file handles; retain the original Windows CTests.
    if(NOT UNIX AND runtime_case MATCHES
       "^(validates-configuration-(owner-only|mode-normalization)|rejects-configuration-(symlink|fifo|group-writable|directory))$")
        continue()
    endif()
    add_test(NAME "runtime.${runtime_case}"
        COMMAND "${CMAKE_COMMAND}"
            "-DRDP_RUNTIME_EXECUTABLE=$<TARGET_FILE:rdp-server>"
            "-DRDP_RUNTIME_VERSION=${PROJECT_VERSION}"
            "-DRDP_RUNTIME_TEST_CASE=${runtime_case}"
            "-DRDP_RUNTIME_FIXTURE_DIRECTORY=${PROJECT_BINARY_DIR}/runtime-fixtures"
            -P "${PROJECT_SOURCE_DIR}/tests/check_runtime_entrypoint.cmake")
    set_tests_properties("runtime.${runtime_case}" PROPERTIES
        LABELS "runtime;offline")
    if(runtime_case STREQUAL "rejects-configuration-fifo")
        set_tests_properties("runtime.${runtime_case}" PROPERTIES TIMEOUT 10)
    endif()
endforeach()
# The native cursor conversion is compiled into the isolated headless
# test without adding XCB dependencies to the portable protocol archive.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_rdp_test(test_x11_cursor_reply.cpp x11 cursor-reply-length-bounds)
    target_sources(test_x11_cursor_reply PRIVATE
        "${PROJECT_SOURCE_DIR}/src/x11/cursor_image_conversion.cpp")
    set_tests_properties(x11.cursor-reply-length-bounds PROPERTIES
        LABELS "x11;linux-adapter")
endif()

# Test arena sizing even without optional XCB-SHM development headers.
# Where found, compile/link the native capture adapter and fail it closed.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_rdp_test(test_x11_native_capture.cpp x11
        capture-arena-and-connection-denials)
    if(TARGET rdp-server-linux-xshm)
        target_link_libraries(test_x11_native_capture PRIVATE
            rdp-server-linux-xshm)
        target_compile_definitions(test_x11_native_capture PRIVATE
            RDP_SERVER_HAVE_NATIVE_XSHM=1)
    endif()
    set_tests_properties(x11.capture-arena-and-connection-denials
        PROPERTIES LABELS "x11;linux-adapter")
endif()

# R5 XShm shared-memory and borrowed XCB owner teardown. The native test
# intentionally starts with a failed fd and never touches a live desktop.
if(TARGET rdp-server-linux-xshm)
    add_rdp_test(test_x11_capture_disconnect.cpp x11
        capture-native-disconnect-cancellation)
    target_link_libraries(test_x11_capture_disconnect PRIVATE
        rdp-server-linux-xshm)
    set_tests_properties(x11.capture-native-disconnect-cancellation
        PROPERTIES LABELS "x11;linux-adapter;native")
endif()

# R7 standard CTests are synthetic and permission-safe on every OS.
# The Apple cases retain CoreVideo buffers only; no live ScreenCaptureKit
# stream, real TCC query or keyboard/mouse event is exercised here.
add_executable(test_macos_capture_pixel_buffer
    test_macos_capture_pixel_buffer.cpp)
target_include_directories(test_macos_capture_pixel_buffer PRIVATE
    "${PROJECT_SOURCE_DIR}/src")
if(APPLE)
    # The CoreVideo fixture directly references kCFAllocatorDefault.
    # Keep CoreFoundation on this Apple-only TEST executable.
    find_library(RDP_SERVER_COREFOUNDATION_FRAMEWORK CoreFoundation REQUIRED)
    target_link_libraries(test_macos_capture_pixel_buffer PRIVATE
        rdp-server-macos-capture
        "${RDP_SERVER_COREFOUNDATION_FRAMEWORK}")
else()
    target_sources(test_macos_capture_pixel_buffer PRIVATE
        "${PROJECT_SOURCE_DIR}/src/platform/macos/capture_pixel_layout.cpp"
        "${PROJECT_SOURCE_DIR}/src/platform/macos/desktop_display_geometry.cpp"
        "${PROJECT_SOURCE_DIR}/src/platform/macos/screen_capture_preflight.cpp"
        "${PROJECT_SOURCE_DIR}/src/platform/macos/native_display_snapshot.cpp"
        "${PROJECT_SOURCE_DIR}/src/platform/macos/native_display_geometry.cpp"
        "${PROJECT_SOURCE_DIR}/src/platform/macos/native_display_refresh.cpp")
endif()
if(MSVC)
    target_compile_options(test_macos_capture_pixel_buffer PRIVATE /W4 /UNDEBUG)
else()
    target_compile_options(test_macos_capture_pixel_buffer PRIVATE
        -Wall -Wextra -Wpedantic -Werror -UNDEBUG)
endif()
add_test(NAME macos.capture-bgra-layout-bounds
    COMMAND test_macos_capture_pixel_buffer layout)
add_test(NAME macos.capture-permission-preflight-revocation
    COMMAND test_macos_capture_pixel_buffer permission-preflight)
set_tests_properties(
    macos.capture-bgra-layout-bounds
    macos.capture-permission-preflight-revocation
    PROPERTIES LABELS "macos;capture;offline")
foreach(case_name IN ITEMS
        retina-points multi-display-invalid reconfiguration
        virtual-input-coordinates)
    add_test(NAME "macos.desktop-${case_name}"
        COMMAND test_macos_capture_pixel_buffer "${case_name}")
    set_tests_properties("macos.desktop-${case_name}"
        PROPERTIES LABELS "macos;geometry;offline")
endforeach()
# CoreGraphics display enumeration is exercised only through synthetic
# injected observations here: no real display read or privacy interaction.
foreach(case_name IN ITEMS
        stable-multi-retina geometry-denials changed-during-read)
    add_test(NAME "macos.display-snapshot-${case_name}"
        COMMAND test_macos_capture_pixel_buffer "display-snapshot-${case_name}")
    set_tests_properties("macos.display-snapshot-${case_name}" PROPERTIES
        LABELS "macos;geometry;offline")
endforeach()
# R7 native snapshot -> portable geometry uses synthetic metadata only.
foreach(case_name IN ITEMS
        single-retina uniform-multi-display mixed-scale-denials generation-refresh)
    add_test(NAME "macos.geometry-native-${case_name}"
        COMMAND test_macos_capture_pixel_buffer "geometry-native-${case_name}")
    set_tests_properties("macos.geometry-native-${case_name}" PROPERTIES
        LABELS "macos;geometry;offline")
endforeach()
# R7 topology-epoch guard: synthetic reads, no CoreGraphics display,
# screen-capture stream, TCC prompt, native input or service activation.
foreach(case_name IN ITEMS refresh invalidate failed-refresh)
    add_test(NAME "macos.desktop-geometry-epoch-${case_name}"
        COMMAND test_macos_capture_pixel_buffer "geometry-epoch-${case_name}")
    set_tests_properties("macos.desktop-geometry-epoch-${case_name}"
        PROPERTIES LABELS "macos;geometry;offline")
endforeach()
if(APPLE)
    foreach(case_name IN ITEMS ownership native-denials native-move-replacement)
        add_test(NAME "macos.capture-bgra-buffer-${case_name}"
            COMMAND test_macos_capture_pixel_buffer "${case_name}")
        set_tests_properties("macos.capture-bgra-buffer-${case_name}"
            PROPERTIES LABELS "macos;capture;offline")
    endforeach()
endif()

# R5 native XCB connection: headless deterministic event draining and
# invalid-display descriptor ownership, no live desktop/X server.
if(TARGET rdp-server-x11-connection)
    add_rdp_test(test_x11_display_events.cpp x11
        display-event-budget-and-readiness)
    target_link_libraries(test_x11_display_events PRIVATE
        rdp-server-x11-connection)
    target_compile_definitions(test_x11_display_events PRIVATE
        RDP_TEST_NATIVE_X11_CONNECTION=1)
    add_test(NAME x11.display-event-disconnect-cleanup
        COMMAND test_x11_display_events disconnect-cleanup)
    set_tests_properties(
        x11.display-event-budget-and-readiness
        x11.display-event-disconnect-cleanup
        PROPERTIES LABELS "x11;linux-adapter;native")
endif()

# First-party native XFixes cursor source: exercise failure and borrowed
# connection cancellation without an X server or desktop access.
if(TARGET rdp-server-linux-xfixes-cursor)
    add_rdp_test(test_x11_native_cursor.cpp x11
        cursor-native-connection-denials-and-cancellation)
    target_link_libraries(test_x11_native_cursor PRIVATE
        rdp-server-linux-xfixes-cursor)
    set_tests_properties(
        x11.cursor-native-connection-denials-and-cancellation
        PROPERTIES LABELS "x11;linux-adapter;native")
endif()

# R5 native XDamage lifetime: invalid connection and deterministic
# cancellation before XCB owner teardown, without a running display.
if(TARGET rdp-server-linux-xdamage)
    add_rdp_test(test_x11_native_damage.cpp x11
        damage-native-connection-denials-and-cancellation)
    target_link_libraries(test_x11_native_damage PRIVATE
        rdp-server-linux-xdamage)
    set_tests_properties(
        x11.damage-native-connection-denials-and-cancellation
        PROPERTIES LABELS "x11;linux-adapter;native")
endif()

add_test(NAME project.policy
    COMMAND "${CMAKE_COMMAND}"
        "-DRDP_SERVER_SOURCE_ROOT=${PROJECT_SOURCE_DIR}"
        -P "${PROJECT_SOURCE_DIR}/cmake/verify_project_policy.cmake")
set_tests_properties(project.policy PROPERTIES LABELS "project-policy")
