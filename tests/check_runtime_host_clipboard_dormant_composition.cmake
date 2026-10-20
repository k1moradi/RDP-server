# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.22)

foreach(required_var IN ITEMS
        RDP_LINUX_HOST_CONTROL_SOURCE
        RDP_RUNTIME_ENTRYPOINT_SOURCE
        RDP_LINUX_PREPARED_CLIPBOARD_HEADER
        RDP_ROOT_CMAKE)
    if(NOT DEFINED ${required_var})
        message(FATAL_ERROR "missing ${required_var}")
    endif()
endforeach()

file(READ "${RDP_LINUX_HOST_CONTROL_SOURCE}" host_source)
file(READ "${RDP_RUNTIME_ENTRYPOINT_SOURCE}" runtime_source)
file(READ "${RDP_LINUX_PREPARED_CLIPBOARD_HEADER}" owner_header)
file(READ "${RDP_ROOT_CMAKE}" root_cmake)

foreach(required_text IN ITEMS
        "inline constexpr bool kLinuxProductionClipboardActivationApproved = false"
        "class LinuxPreparedClipboardOwner final"
        "PresentationScope::UnicodeTextOnly"
        "visitPersonalDesktopClipboardChannel("
        "dispatchPersonalDesktopClipboardTpkt("
        "queuePersonalDesktopClipboardPdu("
        "advancePersonalDesktopClipboardTlsWrite("
        "recordAcceptedWriteReceipt("
        "adapter_->disconnect()"
        "bridge_->retireR3ChannelState()")
    string(FIND "${owner_header}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR
            "shared dormant R8 owner contract missing: ${required_text}")
    endif()
endforeach()

foreach(forbidden_text IN ITEMS
        "publishCompletedFile("
        "publishCompletedFiles("
        "beginFileSizeRequest("
        "beginFileRangeRequest("
        "PasteKind::Png"
        "xcb_connect("
        "SSL_write"
        "std::thread")
    string(FIND "${owner_header}" "${forbidden_text}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR
            "dormant GUI R8 owner exceeded its single-owner text-only boundary: ${forbidden_text}")
    endif()
endforeach()

foreach(required_text IN ITEMS
        "#include \"linux_prepared_clipboard_owner.h\""
        "LinuxPreparedClipboardOwner clipboard{}"
        "candidate->clipboard.prepare("
        "candidate->admissionGeneration"
        "candidate->sessionGeneration"
        "clipboard.generationsMatch("
        "clipboard.eventSink()"
        "clipboard.serviceNative("
        "clipboard.writePending()"
        "clipboard.advanceTlsWrite("
        "clipboard.serviceAfterNetworkDispatch("
        "clipboard.dispatchAuthenticatedTpkt(")
    string(FIND "${host_source}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR
            "HostControl dormant R8 composition missing: ${required_text}")
    endif()
endforeach()

string(FIND "${host_source}"
    "void LinuxRuntimeHostControl::retireNativeDesktop() noexcept"
    retire_native_begin)
string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::initializeNativeDesktop() noexcept"
    retire_native_end)
if(retire_native_begin LESS 0 OR retire_native_end LESS_EQUAL retire_native_begin)
    message(FATAL_ERROR "unable to isolate HostControl native retirement")
endif()
math(EXPR retire_native_length "${retire_native_end} - ${retire_native_begin}")
string(SUBSTRING "${host_source}" ${retire_native_begin}
    ${retire_native_length} retire_native_source)
string(FIND "${retire_native_source}" "clipboard.retire()" clipboard_retire)
string(FIND "${retire_native_source}"
    "desktop->retireAfterAuthorizationLoss()" desktop_retire)
if(clipboard_retire LESS 0 OR desktop_retire LESS 0 OR
   NOT clipboard_retire LESS desktop_retire)
    message(FATAL_ERROR
        "HostControl must retire R8 selection/INCR state before the R5 X11 owner")
endif()

string(FIND "${host_source}"
    "void LinuxRuntimeHostControl::retireAcceptedClient(" retire_client_begin)
string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::pollAcceptedClientReadiness()"
    retire_client_end)
if(retire_client_begin LESS 0 OR retire_client_end LESS_EQUAL retire_client_begin)
    message(FATAL_ERROR "unable to isolate accepted-client retirement")
endif()
math(EXPR retire_client_length "${retire_client_end} - ${retire_client_begin}")
string(SUBSTRING "${host_source}" ${retire_client_begin}
    ${retire_client_length} retire_client_source)
string(FIND "${retire_client_source}" "retireNativeDesktop()" native_retire)
string(FIND "${retire_client_source}" "acceptedClient_->revoke()" connection_revoke)
if(native_retire LESS 0 OR connection_revoke LESS 0 OR
   NOT native_retire LESS connection_revoke)
    message(FATAL_ERROR
        "HostControl must retire R8/R5 before the accepted R3/R2/R1 aggregate")
endif()

string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::serviceNativeDesktopOnce() noexcept"
    service_begin)
string(FIND "${host_source}"
    "void LinuxRuntimeHostControl::clearAcceptedClient() noexcept"
    service_end)
if(service_begin LESS 0 OR service_end LESS_EQUAL service_begin)
    message(FATAL_ERROR "unable to isolate HostControl post-Share service")
endif()
math(EXPR service_length "${service_end} - ${service_begin}")
string(SUBSTRING "${host_source}" ${service_begin}
    ${service_length} service_source)
string(FIND "${service_source}"
    "if (nativeDesktop_->clipboard.writePending())" clipboard_write)
string(FIND "${service_source}"
    "if (nativeDesktop_->graphicsWritePending)" graphics_write)
string(FIND "${service_source}"
    "advancePersonalDesktopPostShareApplicationRead(" application_read)
string(FIND "${service_source}"
    "if (nativeDesktop_->clipboard.writePending())" capture_clipboard_gate REVERSE)
string(FIND "${service_source}"
    "preflightPersonalDesktopGraphicsFramePublication(" capture_preflight)
if(clipboard_write LESS 0 OR graphics_write LESS 0 OR application_read LESS 0 OR
   capture_clipboard_gate LESS 0 OR capture_preflight LESS 0 OR
   NOT clipboard_write LESS graphics_write OR
   NOT graphics_write LESS application_read OR
   NOT capture_clipboard_gate LESS capture_preflight)
    message(FATAL_ERROR
        "clipboard write ownership must precede Graphics/read/capture scheduling")
endif()

string(FIND "${root_cmake}"
    "# R8 production dependency readiness only." r8_link_begin)
string(FIND "${root_cmake}"
    "# R7 native macOS capture remains isolated" r8_link_end)
if(r8_link_begin LESS 0 OR r8_link_end LESS_EQUAL r8_link_begin)
    message(FATAL_ERROR "unable to isolate R8 production link block")
endif()
math(EXPR r8_link_length "${r8_link_end} - ${r8_link_begin}")
string(SUBSTRING "${root_cmake}" ${r8_link_begin}
    ${r8_link_length} r8_link_block)
foreach(required_text IN ITEMS
        "target_link_libraries(rdp-server-linux-host-control PUBLIC"
        "rdp-server-r8-r3-clipboard"
        "rdp-server-linux-x11-clipboard"
        "RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD=1")
    string(FIND "${r8_link_block}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR
            "HostControl R8 build composition missing: ${required_text}")
    endif()
endforeach()

string(FIND "${runtime_source}"
    "class LinuxPreparedClipboardOwner final" duplicate_owner)
if(NOT duplicate_owner EQUAL -1)
    message(FATAL_ERROR
        "CLI must reuse the shared dormant R8 owner instead of duplicating it")
endif()

message(STATUS
    "HostControl shares one generation-fenced Unicode-text-only R8 owner; activation remains false")
