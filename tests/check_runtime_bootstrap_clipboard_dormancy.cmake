# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.22)

foreach(required_var IN ITEMS
        RDP_DESKTOP_ENTRYPOINT_SOURCE
        RDP_DESKTOP_WINDOW_HEADER
        RDP_DESKTOP_WINDOW_SOURCE
        RDP_LINUX_HOST_CONTROL_SOURCE
        RDP_LINUX_HOST_CONTROL_HEADER
        RDP_LINUX_PREPARED_CLIPBOARD_HEADER
        RDP_RUNTIME_BOOTSTRAP_HEADER
        RDP_RUNTIME_HOST_CONTROL_HEADER
        RDP_STANDALONE_CREDENTIAL_CONSENT_HEADER)
    if(NOT DEFINED ${required_var})
        message(FATAL_ERROR "missing ${required_var}")
    endif()
endforeach()

file(READ "${RDP_DESKTOP_ENTRYPOINT_SOURCE}" desktop_entrypoint_source)
file(READ "${RDP_DESKTOP_WINDOW_HEADER}" desktop_window_header)
file(READ "${RDP_DESKTOP_WINDOW_SOURCE}" desktop_window_source)
file(READ "${RDP_LINUX_HOST_CONTROL_SOURCE}" host_source)
file(READ "${RDP_LINUX_HOST_CONTROL_HEADER}" host_header)
file(READ "${RDP_LINUX_PREPARED_CLIPBOARD_HEADER}" owner_header)
file(READ "${RDP_RUNTIME_BOOTSTRAP_HEADER}" bootstrap_header)
file(READ "${RDP_RUNTIME_HOST_CONTROL_HEADER}" runtime_host_header)
file(READ "${RDP_STANDALONE_CREDENTIAL_CONSENT_HEADER}" credential_consent_header)
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

# R7 restored the public standalone-password Release gate after R10 briefly
# promoted it without the required real Microsoft-client receipt. R8 must keep
# that product qualification boundary separate from clipboard authority:
# Release stays closed, while Debug/explicit owner-acceptance builds may expose
# the exact production Session Password path for physical qualification.
string(FIND "${runtime_host_header}"
    "kStandalonePasswordProductCapabilityApproved = false"
    standalone_release_gate)
if(standalone_release_gate LESS 0)
    message(FATAL_ERROR
        "public standalone-password capability must remain false before Microsoft-client qualification")
endif()
string(FIND "${runtime_host_header}"
    "kStandalonePasswordProductCapabilityApproved = true"
    premature_standalone_release_gate)
if(NOT premature_standalone_release_gate EQUAL -1)
    message(FATAL_ERROR
        "owner-acceptance readiness must not silently promote standalone Release capability")
endif()
foreach(required_text IN ITEMS
        "ownerAcceptancePasswordUiEnabled()"
        "!defined(NDEBUG) || defined(RDP_SERVER_ENABLE_OWNER_ACCEPTANCE_UI)")
    string(FIND "${desktop_window_source}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR
            "owner-acceptance Session Password surface lost compile-time qualification gate: ${required_text}")
    endif()
endforeach()

# R10 now makes the normal zero-argument product own one
# LinuxPortableDesktopRuntime aggregate instead of a bare HostControl. Keep
# that application-lifetime wrapper composition-only: it may serialize the
# existing R10 owner/service loop, but it must not introduce a second R8 owner
# or direct clipboard/CLIPRDR authority.
foreach(required_text IN ITEMS
        "LinuxPortableDesktopRuntime applicationRuntime"
        "auto& runtime = applicationRuntime.hostControl()"
        "applicationRuntime.serviceOnce()")
    string(FIND "${desktop_entrypoint_source}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR
            "zero-argument application runtime lost required R10 seam: ${required_text}")
    endif()
endforeach()
string(FIND "${desktop_entrypoint_source}"
    "LinuxRuntimeHostControl runtime;" bare_unprovisioned_runtime)
if(NOT bare_unprovisioned_runtime EQUAL -1)
    message(FATAL_ERROR
        "zero-argument desktop regressed to a bare unprovisioned HostControl")
endif()

string(FIND "${host_header}"
    "class LinuxPortableDesktopRuntime final" portable_runtime_begin)
string(FIND "${host_header}"
    "} // namespace rdp_server::server::runtime" portable_runtime_end)
if(portable_runtime_begin LESS 0 OR
   portable_runtime_end LESS_EQUAL portable_runtime_begin)
    message(FATAL_ERROR "unable to isolate LinuxPortableDesktopRuntime")
endif()
math(EXPR portable_runtime_length
    "${portable_runtime_end} - ${portable_runtime_begin}")
string(SUBSTRING "${host_header}" ${portable_runtime_begin}
    ${portable_runtime_length} portable_runtime_source)
string(FIND "${portable_runtime_source}"
    "LinuxRuntimeHostControl hostControl_{}" portable_host_owner)
if(portable_host_owner LESS 0)
    message(FATAL_ERROR
        "portable desktop runtime must retain the single R10 HostControl owner")
endif()
foreach(forbidden_text IN ITEMS
        "LinuxPreparedClipboardOwner"
        "clipboard.prepare("
        "clipboard.retire("
        "kConsoleClipboardPermission"
        "visitPersonalDesktopClipboardChannel("
        "dispatchPersonalDesktopClipboardTpkt("
        "queuePersonalDesktopClipboardPdu("
        "advancePersonalDesktopClipboardTlsWrite(")
    string(FIND "${portable_runtime_source}" "${forbidden_text}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR
            "portable desktop aggregate must not own or authorize R8: ${forbidden_text}")
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

# R5/R2 no-config standalone preparation now derives one native-target policy
# from trusted physical X11 evidence before the standalone credential is
# installed. That preparation may replace security/admission configuration, but
# it must remain pre-listener and completely outside R8/native clipboard state.
string(FIND "${host_source}"
    "bool LinuxRuntimeHostControl::prepareAutomaticStandaloneAdmission() noexcept"
    standalone_admission_begin)
string(FIND "${host_source}"
    "bool LinuxRuntimeHostControl::connectionTargetIdentityMatchesActiveListener()"
    standalone_admission_end)
if(standalone_admission_begin LESS 0 OR
   standalone_admission_end LESS_EQUAL standalone_admission_begin)
    message(FATAL_ERROR
        "unable to isolate automatic standalone admission preparation")
endif()
math(EXPR standalone_admission_length
    "${standalone_admission_end} - ${standalone_admission_begin}")
string(SUBSTRING "${host_source}" ${standalone_admission_begin}
    ${standalone_admission_length} standalone_admission_source)
foreach(required_text IN ITEMS
        "selectCurrentPhysicalX11Desktop("
        "configureStandalonePersonalDesktop(rule)"
        "configureStandalonePersonalDesktop(rule, *security)"
        "generatedAdmissionConfiguration_ = std::move(admission)"
        "generatedSecurityConfiguration_ = std::move(security)")
    string(FIND "${standalone_admission_source}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR
            "automatic standalone admission lost required no-config seam: ${required_text}")
    endif()
endforeach()
foreach(forbidden_text IN ITEMS
        "listener_."
        "startSharing("
        "nativeDesktop_"
        "clipboard.prepare("
        "kConsoleClipboardPermission"
        "visitPersonalDesktopClipboardChannel("
        "dispatchPersonalDesktopClipboardTpkt("
        "queuePersonalDesktopClipboardPdu("
        "advancePersonalDesktopClipboardTlsWrite(")
    string(FIND "${standalone_admission_source}" "${forbidden_text}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR
            "automatic standalone admission must stay outside listener/R8 authority: ${forbidden_text}")
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

# R7's owner-acceptance Session Password surface now drives the exact
# production credential -> View/Input permission -> endpoint/listener
# transaction. Clipboard remains explicitly denied in that transaction, and
# password presentation storage is cleared before any later network step.
string(FIND "${desktop_window_source}"
    "void DesktopWindow::requestStart()" gui_start_begin)
string(FIND "${desktop_window_source}"
    "void DesktopWindow::requestStop()" gui_start_end)
if(gui_start_begin LESS 0 OR gui_start_end LESS_EQUAL gui_start_begin)
    message(FATAL_ERROR "unable to isolate Session Password Sharing transaction")
endif()
math(EXPR gui_start_length "${gui_start_end} - ${gui_start_begin}")
string(SUBSTRING "${desktop_window_source}" ${gui_start_begin}
    ${gui_start_length} gui_start_source)
string(FIND "${gui_start_source}"
    "host_.configureStandalonePassword(" gui_credential)
string(FIND "${gui_start_source}"
    "sessionPassword_->clear()" gui_password_clear)
string(FIND "${gui_start_source}"
    "sessionPasswordConfirm_->clear()" gui_confirmation_clear)
string(FIND "${gui_start_source}"
    "permission.allowClipboard = false" gui_permission_clipboard_denial)
string(FIND "${gui_start_source}"
    "host_.requestHostPermission(permission)" gui_permission)
string(FIND "${gui_start_source}"
    "host_.start(currentHostRequest())" gui_start)
if(gui_credential LESS 0 OR gui_password_clear LESS 0 OR
   gui_confirmation_clear LESS 0 OR gui_permission_clipboard_denial LESS 0 OR
   gui_permission LESS 0 OR gui_start LESS 0 OR
   NOT gui_credential LESS gui_password_clear OR
   NOT gui_password_clear LESS gui_permission OR
   NOT gui_confirmation_clear LESS gui_permission OR
   NOT gui_permission_clipboard_denial LESS gui_permission OR
   NOT gui_permission LESS gui_start)
    message(FATAL_ERROR
        "Session Password Sharing must clear secrets and keep clipboard denied before Start")
endif()
foreach(forbidden_text IN ITEMS
        "allowClipboard = true"
        "kConsoleClipboardPermission"
        "clipboard.prepare("
        "visitPersonalDesktopClipboardChannel("
        "dispatchPersonalDesktopClipboardTpkt("
        "queuePersonalDesktopClipboardPdu("
        "advancePersonalDesktopClipboardTlsWrite(")
    string(FIND "${gui_start_source}" "${forbidden_text}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR
            "Session Password Sharing transaction must not activate R8: ${forbidden_text}")
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
    "replaceStandaloneApplicationCredential(" password_replace_transaction)
string(FIND "${password_source}"
    "standaloneCredentialGeneration_ = observation.generation"
    password_generation_install)
if(password_generation_clear LESS 0 OR password_replace_transaction LESS 0 OR
   password_generation_install LESS 0 OR
   NOT password_generation_clear LESS password_replace_transaction OR
   NOT password_replace_transaction LESS password_generation_install)
    message(FATAL_ERROR
        "Session Password replacement must clear, replace and install its generation")
endif()

# R2 owns consent invalidation and production credential consumption in one
# shared transaction. Inspect that helper rather than requiring the old direct
# HostControl implementation spelling.
string(FIND "${credential_consent_header}"
    "OwnerConsentRevocationReason::CredentialChange"
    credential_owner_generation_revoke)
string(FIND "${credential_consent_header}"
    "credentialOwner.configure(username, password)"
    credential_owner_configure)
if(credential_owner_generation_revoke LESS 0 OR
   credential_owner_configure LESS 0 OR
   NOT credential_owner_generation_revoke LESS credential_owner_configure)
    message(FATAL_ERROR
        "shared R2 credential replacement must revoke owner consent before configuring")
endif()

set(password_replacement_sources
    "${password_source}\n${credential_consent_header}")
foreach(forbidden_text IN ITEMS
        "clipboard.prepare("
        "nativeDesktop_->clipboard"
        "kConsoleClipboardPermission")
    string(FIND "${password_replacement_sources}" "${forbidden_text}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR
            "Session Password replacement must not manipulate R8 state: ${forbidden_text}")
    endif()
endforeach()

# Listener Start remains an R1/R2 boundary only. In particular, a failed
# Start after credential replacement, consent and endpoint preparation must not
# construct or retain a native/R8 owner; native/R8 construction begins only
# later for an accepted client at GraphicsReady.
string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::startSharing()"
    start_sharing_begin)
string(FIND "${host_source}"
    "void LinuxRuntimeHostControl::retireNativeDesktop() noexcept"
    start_sharing_end)
if(start_sharing_begin LESS 0 OR
   start_sharing_end LESS_EQUAL start_sharing_begin)
    message(FATAL_ERROR "unable to isolate listener Start")
endif()
math(EXPR start_sharing_length
    "${start_sharing_end} - ${start_sharing_begin}")
string(SUBSTRING "${host_source}" ${start_sharing_begin}
    ${start_sharing_length} start_sharing_source)
string(FIND "${start_sharing_source}" "openLanListener(" start_listener_open)
if(start_listener_open LESS 0)
    message(FATAL_ERROR "R8 audit expects Start to own only the R1 listener boundary")
endif()
foreach(forbidden_text IN ITEMS
        "nativeDesktop_"
        "initializeNativeDesktop("
        "LinuxPreparedClipboardOwner"
        "clipboard.prepare("
        "kConsoleClipboardPermission"
        "visitPersonalDesktopClipboardChannel("
        "dispatchPersonalDesktopClipboardTpkt("
        "queuePersonalDesktopClipboardPdu("
        "advancePersonalDesktopClipboardTlsWrite(")
    string(FIND "${start_sharing_source}" "${forbidden_text}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR
            "listener Start must not construct or retain R8 state: ${forbidden_text}")
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
