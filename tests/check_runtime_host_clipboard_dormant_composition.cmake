# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.22)

foreach(required_var IN ITEMS
        RDP_LINUX_HOST_CONTROL_SOURCE
        RDP_RUNTIME_ENTRYPOINT_SOURCE
        RDP_LINUX_PREPARED_CLIPBOARD_HEADER
        RDP_X11_CLIPBOARD_SOURCE
        RDP_R8_R3_CLIPBOARD_BRIDGE_SOURCE
        RDP_ROOT_CMAKE)
    if(NOT DEFINED ${required_var})
        message(FATAL_ERROR "missing ${required_var}")
    endif()
endforeach()

file(READ "${RDP_LINUX_HOST_CONTROL_SOURCE}" host_source)
file(READ "${RDP_RUNTIME_ENTRYPOINT_SOURCE}" runtime_source)
file(READ "${RDP_LINUX_PREPARED_CLIPBOARD_HEADER}" owner_header)
file(READ "${RDP_X11_CLIPBOARD_SOURCE}" x11_clipboard_source)
file(READ "${RDP_R8_R3_CLIPBOARD_BRIDGE_SOURCE}" bridge_source)
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
        "bridge_->retireR3ChannelState()"
        "writePending_ = false"
        "admissionGeneration_ = 0U"
        "sessionGeneration_ = 0U")
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
        "context->clipboard->dispatchAuthenticatedTpkt(")
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

# Every accepted-client replacement must allocate a fresh native/R8 owner.
string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::initializeNativeDesktop() noexcept"
    initialize_begin)
string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::serviceNativeDesktopOnce() noexcept"
    initialize_end)
if(initialize_begin LESS 0 OR initialize_end LESS_EQUAL initialize_begin)
    message(FATAL_ERROR "unable to isolate HostControl native initialization")
endif()
math(EXPR initialize_length "${initialize_end} - ${initialize_begin}")
string(SUBSTRING "${host_source}" ${initialize_begin}
    ${initialize_length} initialize_source)
string(FIND "${initialize_source}"
    "auto candidate = std::make_unique<LinuxHostNativeDesktopState>()"
    fresh_native_owner)
string(FIND "${initialize_source}"
    "candidate->clipboard.prepare(" fresh_clipboard_prepare)
string(FIND "${initialize_source}"
    "nativeDesktop_ = std::move(candidate)" fresh_native_install)
if(fresh_native_owner LESS 0 OR fresh_clipboard_prepare LESS 0 OR
   fresh_native_install LESS 0 OR
   NOT fresh_native_owner LESS fresh_clipboard_prepare OR
   NOT fresh_clipboard_prepare LESS fresh_native_install)
    message(FATAL_ERROR
        "reconnect must install a freshly prepared native/R8 clipboard owner")
endif()

# Stop/Revoke share this helper, and process Quit falls back to the same helper.
# R8/R5 retirement must precede the accepted connection and listener.
string(FIND "${host_source}"
    "void LinuxRuntimeHostControl::retireStoppedRuntime(" retire_stopped_begin)
string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::stopSharing()" retire_stopped_end)
if(retire_stopped_begin LESS 0 OR
   retire_stopped_end LESS_EQUAL retire_stopped_begin)
    message(FATAL_ERROR "unable to isolate stopped-runtime retirement")
endif()
math(EXPR retire_stopped_length
    "${retire_stopped_end} - ${retire_stopped_begin}")
string(SUBSTRING "${host_source}" ${retire_stopped_begin}
    ${retire_stopped_length} retire_stopped_source)
string(FIND "${retire_stopped_source}"
    "ownerSharingAuthority_.revoke(" stopped_authority_revoke)
string(FIND "${retire_stopped_source}"
    "retireNativeDesktop()" stopped_native_retire)
string(FIND "${retire_stopped_source}"
    "acceptedClient_->revoke()" stopped_connection_revoke)
string(FIND "${retire_stopped_source}"
    "listener_.close()" stopped_listener_close)
if(stopped_authority_revoke LESS 0 OR stopped_native_retire LESS 0 OR
   stopped_connection_revoke LESS 0 OR stopped_listener_close LESS 0 OR
   NOT stopped_authority_revoke LESS stopped_native_retire OR
   NOT stopped_native_retire LESS stopped_connection_revoke OR
   NOT stopped_connection_revoke LESS stopped_listener_close)
    message(FATAL_ERROR
        "Stop/Revoke must retire authority then R8/R5 before connection/listener")
endif()

string(FIND "${host_source}"
    "LinuxRuntimeHostControl::~LinuxRuntimeHostControl()" destructor_begin)
string(FIND "${host_source}"
    "bool LinuxRuntimeHostControl::onOwnerThread() const noexcept" destructor_end)
if(destructor_begin LESS 0 OR destructor_end LESS_EQUAL destructor_begin)
    message(FATAL_ERROR "unable to isolate HostControl destructor")
endif()
math(EXPR destructor_length "${destructor_end} - ${destructor_begin}")
string(SUBSTRING "${host_source}" ${destructor_begin}
    ${destructor_length} destructor_source)
string(FIND "${destructor_source}" "retireStoppedRuntime(" quit_retire)
if(quit_retire LESS 0)
    message(FATAL_ERROR
        "process Quit/destruction must enter the common clipboard-first teardown")
endif()

# X11 selection/paste/INCR state is dead before the borrowed R5 XCB owner.
string(FIND "${x11_clipboard_source}"
    "void\nX11ClipboardAdapter::disconnect() noexcept" x11_disconnect_begin)
if(x11_disconnect_begin LESS 0)
    message(FATAL_ERROR "unable to isolate X11 clipboard disconnect")
endif()
string(SUBSTRING "${x11_clipboard_source}" ${x11_disconnect_begin}
    -1 x11_disconnect_source)
foreach(required_text IN ITEMS
        "releaseNativeOwnership()"
        "pending_ = {}"
        "incr_ = {}"
        "ownerWindow_ = XCB_WINDOW_NONE"
        "valid_ = false")
    string(FIND "${x11_disconnect_source}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR
            "X11 clipboard disconnect leaves stale native state: ${required_text}")
    endif()
endforeach()

# R8 bridge retirement removes the route plus any queued TLS-write identity.
string(FIND "${bridge_source}"
    "void R3ClipboardTransferBridge::retireR3ChannelState() noexcept"
    bridge_retire_begin)
if(bridge_retire_begin LESS 0)
    message(FATAL_ERROR "unable to isolate R8/R3 bridge retirement")
endif()
string(SUBSTRING "${bridge_source}" ${bridge_retire_begin}
    -1 bridge_retire_source)
foreach(required_text IN ITEMS
        "channelId_ = 0U"
        "routeGeneration_ = 0U"
        "routeObservationAvailable_ = false"
        "clearOutbound()"
        "transfer_.retireR3ChannelState()")
    string(FIND "${bridge_retire_source}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR
            "R8/R3 bridge retirement leaves stale route/TLS receipt state: ${required_text}")
    endif()
endforeach()

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
