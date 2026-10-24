# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.22)

foreach(required_var IN ITEMS
        RDP_DESKTOP_ENTRYPOINT_SOURCE
        RDP_DESKTOP_WINDOW_HEADER
        RDP_DESKTOP_WINDOW_SOURCE
        RDP_LINUX_HOST_CONTROL_SOURCE
        RDP_LINUX_PREPARED_CLIPBOARD_HEADER
        RDP_RUNTIME_BOOTSTRAP_HEADER)
    if(NOT DEFINED ${required_var})
        message(FATAL_ERROR "missing ${required_var}")
    endif()
endforeach()

file(READ "${RDP_DESKTOP_ENTRYPOINT_SOURCE}" desktop_entrypoint_source)
file(READ "${RDP_DESKTOP_WINDOW_HEADER}" desktop_window_header)
file(READ "${RDP_DESKTOP_WINDOW_SOURCE}" desktop_window_source)
file(READ "${RDP_LINUX_HOST_CONTROL_SOURCE}" host_source)
file(READ "${RDP_LINUX_PREPARED_CLIPBOARD_HEADER}" owner_header)
file(READ "${RDP_RUNTIME_BOOTSTRAP_HEADER}" bootstrap_header)
set(gui_source "${desktop_window_header}\n${desktop_window_source}")

# R6 may define where automatic bootstrap state lives, but that policy cannot
# make clipboard a bootstrap material or relax the explicit-Sharing boundary.
foreach(required_text IN ITEMS
        "configurationFileRequired{false}"
        "explicitSharingRequiredBeforeListen{true}"
        "automaticListenerStart{false}"
        "sessionPasswordPersisted{false}"
        "RuntimeBootstrapMaterial::SessionPassword")
    string(FIND "${bootstrap_header}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR
            "portable bootstrap policy lost R8-safe lifecycle fact: ${required_text}")
    endif()
endforeach()
foreach(forbidden_text IN ITEMS
        "RuntimeBootstrapMaterial::Clipboard"
        "automaticListenerStart{true}"
        "explicitSharingRequiredBeforeListen{false}")
    string(FIND "${bootstrap_header}" "${forbidden_text}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR
            "portable bootstrap policy must not manufacture clipboard/listener authority: ${forbidden_text}")
    endif()
endforeach()

# R3 normal HostControl construction now owns an automatically generated
# process-local licensing identity. That service-lifetime bootstrap material is
# allowed before Start, but construction must remain preparation-only: it cannot
# open the listener or create/grant/dispatch any R8 state.
string(FIND "${host_source}"
    "LinuxRuntimeHostControl::LinuxRuntimeHostControl() noexcept"
    licensing_constructor_begin)
string(FIND "${host_source}"
    "LinuxRuntimeHostControl::~LinuxRuntimeHostControl()"
    licensing_constructor_end)
if(licensing_constructor_begin LESS 0 OR
   licensing_constructor_end LESS_EQUAL licensing_constructor_begin)
    message(FATAL_ERROR
        "unable to isolate automatic licensing HostControl construction")
endif()
math(EXPR licensing_constructor_length
    "${licensing_constructor_end} - ${licensing_constructor_begin}")
string(SUBSTRING "${host_source}" ${licensing_constructor_begin}
    ${licensing_constructor_length} licensing_constructor_source)
string(FIND "${licensing_constructor_source}"
    "configureGeneratedApplicationIdentity()" generated_licensing_prepare)
if(generated_licensing_prepare LESS 0)
    message(FATAL_ERROR
        "R8 audit expects the landed R3 automatic licensing preparation seam")
endif()
foreach(forbidden_text IN ITEMS
        "listener_."
        "startSharing("
        "clipboard.prepare("
        "nativeDesktop_"
        "kConsoleClipboardPermission"
        "visitPersonalDesktopClipboardChannel("
        "dispatchPersonalDesktopClipboardTpkt("
        "queuePersonalDesktopClipboardPdu("
        "advancePersonalDesktopClipboardTlsWrite(")
    string(FIND "${licensing_constructor_source}" "${forbidden_text}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR
            "automatic licensing construction must stay outside listener/R8 authority: ${forbidden_text}")
    endif()
endforeach()

# Automatic GUI bootstrap may provision local TLS/licensing/authentication
# prerequisites, but it is not an R8 authority boundary and must not activate
# CLIPRDR or construct/dispatch the prepared clipboard owner.
foreach(forbidden_text IN ITEMS
        "kLinuxProductionClipboardActivationApproved"
        "LinuxPreparedClipboardOwner"
        "visitPersonalDesktopClipboardChannel("
        "dispatchPersonalDesktopClipboardTpkt("
        "queuePersonalDesktopClipboardPdu("
        "advancePersonalDesktopClipboardTlsWrite("
        "kConsoleClipboardPermission"
        "allowClipboard = true"
        "allowClipboard=true")
    string(FIND "${desktop_entrypoint_source}" "${forbidden_text}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR
            "automatic GUI bootstrap must not activate R8/CLIPRDR: ${forbidden_text}")
    endif()
endforeach()

string(FIND "${owner_header}"
    "inline constexpr bool kLinuxProductionClipboardActivationApproved = false"
    activation_gate)
if(activation_gate LESS 0)
    message(FATAL_ERROR
        "R8 production activation gate must remain literal false before FIRST")
endif()

# Main may gain Session Password/bootstrap controls, but no clipboard checkbox
# or writable clipboard preference while production activation remains false.
foreach(forbidden_text IN ITEMS
        "QCheckBox* clipboard"
        "QCheckBox *clipboard"
        "QCheckBox* allowClipboard"
        "QCheckBox *allowClipboard"
        "clipboardToggle_"
        "clipboardCheckBox_"
        "allowClipboard_")
    string(FIND "${gui_source}" "${forbidden_text}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR
            "Main/GUI must not expose a clipboard checkbox while dormant: ${forbidden_text}")
    endif()
endforeach()
string(FIND "${desktop_window_source}"
    "request.allowClipboard = false" gui_clipboard_denial)
if(gui_clipboard_denial LESS 0)
    message(FATAL_ERROR
        "GUI owner-permission request must keep clipboard disabled")
endif()

# R1 endpoint-bound TLS preparation is now part of R10 configure(). That newly
# resolved bootstrap edge must stay independent of R8: preparing an identity
# before explicit Sharing cannot prepare/dispatch native clipboard state.
string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::configure("
    configure_begin)
string(FIND "${host_source}"
    "bool LinuxRuntimeHostControl::configureStandaloneApplicationPassword("
    configure_end)
if(configure_begin LESS 0 OR configure_end LESS_EQUAL configure_begin)
    message(FATAL_ERROR "unable to isolate automatic endpoint preparation")
endif()
math(EXPR configure_length "${configure_end} - ${configure_begin}")
string(SUBSTRING "${host_source}" ${configure_begin}
    ${configure_length} configure_source)
string(FIND "${configure_source}"
    "prepareTlsIdentityForSelection(options.localAddress)" generated_tls_prepare)
if(generated_tls_prepare LESS 0)
    message(FATAL_ERROR
        "R8 audit expects the landed R1 endpoint-bound TLS preparation seam")
endif()
foreach(forbidden_text IN ITEMS
        "clipboard.prepare("
        "nativeDesktop_->clipboard"
        "kConsoleClipboardPermission"
        "dispatchPersonalDesktopClipboardTpkt("
        "queuePersonalDesktopClipboardPdu(")
    string(FIND "${configure_source}" "${forbidden_text}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR
            "automatic endpoint preparation must stay outside R8: ${forbidden_text}")
    endif()
endforeach()

# Session-password replacement cannot carry a live native/R8 generation across
# the credential boundary. The current implementation rejects replacement while
# a listener is live; a future implementation may instead enter the common
# stopped-runtime retirement before installing the replacement.
string(FIND "${host_source}"
    "bool LinuxRuntimeHostControl::configureStandaloneApplicationPassword("
    password_begin)
string(FIND "${host_source}"
    "LinuxRuntimeHostControl::standaloneApplicationPasswordObservation()"
    password_end)
if(password_begin LESS 0 OR password_end LESS_EQUAL password_begin)
    message(FATAL_ERROR
        "unable to isolate standalone Session Password replacement")
endif()
math(EXPR password_length "${password_end} - ${password_begin}")
string(SUBSTRING "${host_source}" ${password_begin}
    ${password_length} password_source)
string(FIND "${password_source}" "listener_.valid()" password_live_listener_denial)
string(FIND "${password_source}" "retireStoppedRuntime(" password_live_retirement)
if(password_live_listener_denial LESS 0 AND password_live_retirement LESS 0)
    message(FATAL_ERROR
        "Session Password replacement must reject a live host or retire it first")
endif()
string(FIND "${password_source}"
    "standaloneCredentialGeneration_ = 0U" password_generation_clear)
string(FIND "${password_source}"
    "standalonePasswordCredential_.configure(" password_configure)
string(FIND "${password_source}"
    "standaloneCredentialGeneration_ = observation.generation"
    password_generation_install)
if(password_generation_clear LESS 0 OR password_configure LESS 0 OR
   password_generation_install LESS 0 OR
   NOT password_generation_clear LESS password_configure OR
   NOT password_configure LESS password_generation_install)
    message(FATAL_ERROR
        "Session Password replacement must invalidate and replace its generation")
endif()
foreach(forbidden_text IN ITEMS
        "clipboard.prepare("
        "nativeDesktop_->clipboard"
        "kConsoleClipboardPermission")
    string(FIND "${password_source}" "${forbidden_text}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR
            "Session Password replacement must not manipulate R8 state: ${forbidden_text}")
    endif()
endforeach()

# Stop/Revoke retires dormant/prepared R8 state before R5 native destruction,
# the accepted connection, and the listener.
string(FIND "${host_source}"
    "void LinuxRuntimeHostControl::retireNativeDesktop() noexcept"
    retire_native_begin)
string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::initializeNativeDesktop() noexcept"
    retire_native_end)
if(retire_native_begin LESS 0 OR retire_native_end LESS_EQUAL retire_native_begin)
    message(FATAL_ERROR "unable to isolate native desktop retirement")
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
        "Stop must retire dormant/prepared R8 before native desktop destruction")
endif()

string(FIND "${host_source}"
    "void LinuxRuntimeHostControl::retireStoppedRuntime("
    retire_stopped_begin)
string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::stopSharing()"
    retire_stopped_end)
if(retire_stopped_begin LESS 0 OR retire_stopped_end LESS_EQUAL retire_stopped_begin)
    message(FATAL_ERROR "unable to isolate stopped-runtime retirement")
endif()
math(EXPR retire_stopped_length
    "${retire_stopped_end} - ${retire_stopped_begin}")
string(SUBSTRING "${host_source}" ${retire_stopped_begin}
    ${retire_stopped_length} retire_stopped_source)
string(FIND "${retire_stopped_source}" "retireNativeDesktop()" stop_native)
string(FIND "${retire_stopped_source}" "acceptedClient_->revoke()" stop_client)
string(FIND "${retire_stopped_source}" "listener_.close()" stop_listener)
string(FIND "${retire_stopped_source}"
    "retireGeneratedTlsIdentity()" stop_generated_tls)
if(stop_native LESS 0 OR stop_client LESS 0 OR stop_listener LESS 0 OR
   stop_generated_tls LESS 0 OR
   NOT stop_native LESS stop_client OR NOT stop_client LESS stop_listener OR
   NOT stop_listener LESS stop_generated_tls)
    message(FATAL_ERROR
        "Stop/Revoke must retire R8/R5 before connection/listener and generated TLS")
endif()

# Every post-Stop/reconnect native lifetime creates a new aggregate and prepares
# the (still inactive) R8 owner from the replacement admission/session pair.
string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::initializeNativeDesktop() noexcept"
    initialize_begin)
string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::serviceNativeDesktopOnce() noexcept"
    initialize_end)
if(initialize_begin LESS 0 OR initialize_end LESS_EQUAL initialize_begin)
    message(FATAL_ERROR "unable to isolate native desktop initialization")
endif()
math(EXPR initialize_length "${initialize_end} - ${initialize_begin}")
string(SUBSTRING "${host_source}" ${initialize_begin}
    ${initialize_length} initialize_source)
string(FIND "${initialize_source}"
    "auto candidate = std::make_unique<LinuxHostNativeDesktopState>()"
    fresh_owner)
string(FIND "${initialize_source}"
    "candidate->clipboard.prepare(" fresh_clipboard)
string(FIND "${initialize_source}"
    "candidate->admissionGeneration" fresh_admission_generation)
string(FIND "${initialize_source}"
    "candidate->sessionGeneration" fresh_session_generation)
string(FIND "${initialize_source}"
    "nativeDesktop_ = std::move(candidate)" fresh_install)
if(fresh_owner LESS 0 OR fresh_clipboard LESS 0 OR
   fresh_admission_generation LESS 0 OR fresh_session_generation LESS 0 OR
   fresh_install LESS 0 OR
   NOT fresh_owner LESS fresh_clipboard OR
   NOT fresh_clipboard LESS fresh_install)
    message(FATAL_ERROR
        "restart/reconnect must install a fresh generation-bound dormant R8 owner")
endif()

# Hide-to-tray is presentation-only. Explicit Quit enters Stop/Revoke before
# process exit and therefore reaches the clipboard-first runtime teardown.
string(FIND "${desktop_window_source}"
    "void DesktopWindow::closeEvent(QCloseEvent* event)" close_begin)
if(close_begin LESS 0)
    message(FATAL_ERROR "unable to isolate close/hide path")
endif()
string(SUBSTRING "${desktop_window_source}" ${close_begin} -1 close_source)
foreach(required_text IN ITEMS
        "if (mayStillBeHosting(host_.status()))"
        "hide()"
        "event->ignore()")
    string(FIND "${close_source}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR
            "hide-to-tray must remain nonterminal: ${required_text}")
    endif()
endforeach()
string(FIND "${close_source}" "host_.stopAndRevoke()" close_stop)
if(NOT close_stop EQUAL -1)
    message(FATAL_ERROR "hide-to-tray must not Stop/Revoke")
endif()

string(FIND "${desktop_window_source}"
    "void DesktopWindow::requestQuit()" quit_begin)
string(FIND "${desktop_window_source}"
    "void DesktopWindow::updateTray(" quit_end)
if(quit_begin LESS 0 OR quit_end LESS_EQUAL quit_begin)
    message(FATAL_ERROR "unable to isolate explicit Quit path")
endif()
math(EXPR quit_length "${quit_end} - ${quit_begin}")
string(SUBSTRING "${desktop_window_source}" ${quit_begin}
    ${quit_length} quit_source)
string(FIND "${quit_source}" "host_.stopAndRevoke()" quit_stop)
string(FIND "${quit_source}" "QApplication::quit()" quit_exit)
if(quit_stop LESS 0 OR quit_exit LESS 0 OR NOT quit_stop LESS quit_exit)
    message(FATAL_ERROR "explicit Quit must Stop/Revoke before exit")
endif()

# The dormant production owner remains text-only. No file/image/directory
# activation may sneak in with bootstrap lifecycle work.
foreach(forbidden_text IN ITEMS
        "publishCompletedFile("
        "publishCompletedFiles("
        "beginFileSizeRequest("
        "beginFileRangeRequest("
        "PasteKind::Png"
        "PresentationScope::TextAndImages"
        "RemoteDirectoryCapability")
    string(FIND "${owner_header}" "${forbidden_text}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR
            "bootstrap audit found forbidden R8 file/image/directory scope: ${forbidden_text}")
    endif()
endforeach()

message(STATUS
    "Automatic GUI bootstrap is clipboard-dormant; Stop/restart/tray lifetime remains generation-safe")
