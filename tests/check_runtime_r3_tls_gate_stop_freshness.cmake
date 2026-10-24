# SPDX-License-Identifier: GPL-3.0-or-later
# R3 source contract: TLS establishment is prerequisite evidence only.
# Require CredSSP CredentialsVerified AND a successful native R2 admission
# lease before R3/MCS ownership, classify earlier negotiation rejection as
# pre-R3, and prove Stop destroys the accepted R3/MCS owner before R1.
if(NOT DEFINED RDP_LINUX_HOST_CONTROL_SOURCE OR
   "${RDP_LINUX_HOST_CONTROL_SOURCE}" STREQUAL "" OR
   NOT DEFINED RDP_LINUX_CONNECTION_HEADER OR
   "${RDP_LINUX_CONNECTION_HEADER}" STREQUAL "" OR
   NOT DEFINED RDP_LINUX_CONNECTION_SOURCE OR
   "${RDP_LINUX_CONNECTION_SOURCE}" STREQUAL "" OR
   NOT DEFINED RDP_MCS_SESSION_HEADER OR
   "${RDP_MCS_SESSION_HEADER}" STREQUAL "" OR
   NOT DEFINED RDP_MCS_SESSION_SOURCE OR
   "${RDP_MCS_SESSION_SOURCE}" STREQUAL "")
    message(FATAL_ERROR "Missing R3 TLS-gate/Stop source inputs")
endif()

file(READ "${RDP_LINUX_HOST_CONTROL_SOURCE}" host_source)
file(READ "${RDP_LINUX_CONNECTION_HEADER}" connection_header)
file(READ "${RDP_LINUX_CONNECTION_SOURCE}" connection_source)
file(READ "${RDP_MCS_SESSION_HEADER}" mcs_header)
file(READ "${RDP_MCS_SESSION_SOURCE}" mcs_source)

function(require_token variable_name needle description)
    string(FIND "${${variable_name}}" "${needle}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR "${description}: missing ${needle}")
    endif()
endfunction()

function(require_order variable_name description)
    set(previous_position -1)
    foreach(needle IN LISTS ARGN)
        string(FIND "${${variable_name}}" "${needle}" position)
        if(position EQUAL -1 OR position LESS_EQUAL previous_position)
            message(FATAL_ERROR
                "${description}: missing/out-of-order ${needle}")
        endif()
        set(previous_position ${position})
    endforeach()
endfunction()

# R1 must establish TLS before R2/CredSSP can progress, but TLS is never R3
# authority. TlsEstablished and BindingVerified deliberately remain in
# PreAdmission; only verified credentials plus successful native admission may
# move the host toward the first R3/MCS phase.
string(FIND "${host_source}"
    "case AcceptedClientPhase::PreAdmission:" preauth_begin)
string(FIND "${host_source}"
    "case AcceptedClientPhase::McsConnectInitial:" mcs_initial_begin)
if(preauth_begin EQUAL -1 OR mcs_initial_begin EQUAL -1 OR
   NOT preauth_begin LESS mcs_initial_begin)
    message(FATAL_ERROR "Cannot isolate R10 PreAdmission boundary")
endif()
math(EXPR preauth_length "${mcs_initial_begin} - ${preauth_begin}")
string(SUBSTRING "${host_source}" ${preauth_begin}
    ${preauth_length} preauth_source)
require_token(preauth_source
    "case Step::TlsEstablished:"
    "TLS-established diagnostic boundary")
require_token(preauth_source
    "case Step::CredentialsVerified:"
    "CredentialsVerified diagnostic boundary")
require_token(preauth_source
    "case Step::Progress:
        case Step::TlsEstablished:
        case Step::BindingVerified:
            return {RuntimeHostError::None, false}"
    "TLS/Binding must not advance R3")
require_order(preauth_source
    "CredentialsVerified plus successful native admission must own the first R3 handoff"
    "case Step::CredentialsVerified:"
    "acceptedClient_->issueAdmission(*request)"
    "acceptedClientPhase_ = AcceptedClientPhase::McsConnectInitial")

# Pin the connection-side admission transaction as well. The independent
# Session Password mechanism must already be CredentialsVerified, then the
# native admission broker must issue a live lease. TLS readiness, a completed
# binding, a configured credential or a candidate native identity is not enough.
string(FIND "${connection_source}"
    "bool LinuxRuntimeConnection::issueAdmission(" admission_begin)
string(FIND "${connection_source}"
    "LinuxRuntimeConnection::authorizeMcsConnectInitial(" admission_end)
if(admission_begin EQUAL -1 OR admission_end EQUAL -1 OR
   NOT admission_begin LESS admission_end)
    message(FATAL_ERROR "Cannot isolate R2 native admission transaction")
endif()
math(EXPR admission_length "${admission_end} - ${admission_begin}")
string(SUBSTRING "${connection_source}" ${admission_begin}
    ${admission_length} admission_source)
require_order(admission_source
    "Standalone CredentialsVerified must precede native admission lease"
    "CredentialsVerified"
    "auto issued = broker_->issue(*proof, connection_, request)"
    "lease_.emplace(std::move(*issued))")

# Owner evidence now reaches an owned CredSSP TSRequest v6 whose first
# negotiation token is a 40-byte direct-NTLM form and is rejected by the current
# SPNEGO-only envelope rule. That is decisive R2 evidence, but it remains
# pre-CredentialsVerified and therefore pre-R3.
string(FIND "${connection_source}"
    "LinuxCredSspStepResult LinuxRuntimeConnection::advanceStandaloneCredSsp() noexcept"
    standalone_begin)
string(FIND "${connection_source}"
    "LinuxCredSspStepResult LinuxRuntimeConnection::onCredSspIoReady() noexcept"
    standalone_end)
if(standalone_begin EQUAL -1 OR standalone_end EQUAL -1 OR
   NOT standalone_begin LESS standalone_end)
    message(FATAL_ERROR "Cannot isolate standalone CredSSP owner")
endif()
math(EXPR standalone_length "${standalone_end} - ${standalone_begin}")
string(SUBSTRING "${connection_source}" ${standalone_begin}
    ${standalone_length} standalone_source)
require_order(standalone_source
    "Owned TLS TSRequest must reach standalone processing before any R3 handoff"
    "credSspFrameReader_.readOneTlsStep(connection_)"
    "case ReadStatus::Complete:"
    "processCompleteOwnedFrame(")
require_order(standalone_source
    "CredentialsVerified is the only standalone promotion boundary"
    "case FrameStatus::CredentialsVerified:"
    "standalonePrincipalProof_.bind("
    "LinuxRuntimeCredSspDiagnosticTransition::CredentialsVerified")
require_token(connection_source
    "case Stage::Spnego: return \"spnego\""
    "Standalone SPNEGO diagnostic classification")
require_token(connection_source
    "credssp=spnego-initial"
    "Standalone SPNEGO CredSSP diagnostic boundary")
require_token(connection_source
    "credssp=direct-ntlm"
    "Standalone direct-NTLM CredSSP diagnostic boundary")
require_token(connection_source
    "direct-ntlm-type1="
    "Standalone direct-NTLM Type-1 diagnostic checkpoint")
require_token(connection_source
    "os-gss-fallback=disabled"
    "Standalone product must keep OS GSS fallback disabled")
string(FIND "${standalone_source}"
    "acceptor_.advanceOwnedCredSspHandshake" os_gss_fallback)
if(NOT os_gss_fallback EQUAL -1)
    message(FATAL_ERROR
        "Standalone password path must not fall back to OS GSS authentication")
endif()

# The first R3 transition after CredentialsVerified is Connect-Initial;
# Connect-Response is owned only after that exact intake is admitted.
string(FIND "${host_source}"
    "case AcceptedClientPhase::McsConnectResponse:" mcs_response_begin)
string(FIND "${host_source}"
    "case AcceptedClientPhase::McsErectDomain:" mcs_erect_begin)
if(mcs_response_begin EQUAL -1 OR mcs_erect_begin EQUAL -1 OR
   NOT mcs_initial_begin LESS mcs_response_begin OR
   NOT mcs_response_begin LESS mcs_erect_begin)
    message(FATAL_ERROR "Cannot isolate first R3 MCS transitions")
endif()
math(EXPR mcs_initial_length
    "${mcs_response_begin} - ${mcs_initial_begin}")
string(SUBSTRING "${host_source}" ${mcs_initial_begin}
    ${mcs_initial_length} mcs_initial_source)
math(EXPR mcs_response_length
    "${mcs_erect_begin} - ${mcs_response_begin}")
string(SUBSTRING "${host_source}" ${mcs_response_begin}
    ${mcs_response_length} mcs_response_source)
require_order(mcs_initial_source
    "MCS Connect-Initial classification"
    "advancePostAdmissionMcsConnectInitial("
    "case Step::AdmittedConnectInitial:"
    "acceptedClientPhase_ = AcceptedClientPhase::McsConnectResponse")
require_order(mcs_response_source
    "MCS Connect-Response classification"
    "advancePostAdmissionMcsConnectResponseWrite("
    "case Step::Delivered:"
    "acceptedClientPhase_ = AcceptedClientPhase::McsErectDomain")

# The first connection-side MCS read must also retain the concrete R2 admission
# lease and revalidate it. A transport parser being ready for MCS after TLS is
# not permission to diagnose or consume R3 traffic.
string(FIND "${connection_source}"
    "LinuxRuntimeConnection::advancePostAdmissionMcsConnectInitial("
    connection_mcs_begin)
string(FIND "${connection_source}"
    "LinuxRuntimeConnection::advancePostAdmissionMcsConnectResponseWrite("
    connection_mcs_end)
if(connection_mcs_begin EQUAL -1 OR connection_mcs_end EQUAL -1 OR
   NOT connection_mcs_begin LESS connection_mcs_end)
    message(FATAL_ERROR "Cannot isolate connection-side first R3 transition")
endif()
math(EXPR connection_mcs_length
    "${connection_mcs_end} - ${connection_mcs_begin}")
string(SUBSTRING "${connection_source}" ${connection_mcs_begin}
    ${connection_mcs_length} connection_mcs_source)
foreach(needle IN ITEMS
    "if (!broker_ || !lease_ || lease_->isRevoked() ||"
    "AwaitVerifiedR2Admission"
    "broker_->revalidate(*lease_, *principalProof_, connection_)")
    require_token(connection_mcs_source "${needle}"
        "First R3 transition must retain verified R2 admission")
endforeach()

# Stop must retire the accepted connection before R1 listener teardown.
string(FIND "${host_source}"
    "void LinuxRuntimeHostControl::retireStoppedRuntime(" stop_begin)
string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::stopSharing()" stop_end)
if(stop_begin EQUAL -1 OR stop_end EQUAL -1 OR NOT stop_begin LESS stop_end)
    message(FATAL_ERROR "Cannot isolate HostControl Stop retirement")
endif()
math(EXPR stop_length "${stop_end} - ${stop_begin}")
string(SUBSTRING "${host_source}" ${stop_begin}
    ${stop_length} stop_source)
require_order(stop_source
    "Stop must retire R3 before R1 listener"
    "if (acceptedClient_ != nullptr)"
    "acceptedClient_->revoke()"
    "clearAcceptedClient()"
    "listener_.close()")

# clearAcceptedClient destroys the old aggregate and resets every HostControl
# accepted-client phase/readiness field; no old MCS phase can be resumed.
string(FIND "${host_source}"
    "void LinuxRuntimeHostControl::clearAcceptedClient()" clear_begin)
string(FIND "${host_source}"
    "void LinuxRuntimeHostControl::retireAcceptedClient(" clear_end)
if(clear_begin EQUAL -1 OR clear_end EQUAL -1 OR
   NOT clear_begin LESS clear_end)
    message(FATAL_ERROR "Cannot isolate accepted-client clear")
endif()
math(EXPR clear_length "${clear_end} - ${clear_begin}")
string(SUBSTRING "${host_source}" ${clear_begin}
    ${clear_length} clear_source)
foreach(needle IN ITEMS
    "acceptedClient_.reset()"
    "acceptedClientPhase_ = AcceptedClientPhase::None"
    "acceptedClientId_ = 0U"
    "acceptedClientPeer_.clear()"
    "acceptedClientReadable_ = false"
    "acceptedClientWritable_ = false")
    require_token(clear_source "${needle}" "Accepted-client reset")
endforeach()

# Every later accept constructs a new LinuxRuntimeConnection. Its embedded R3
# McsSessionLifecycle is value-owned, so it cannot borrow the retired session.
string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::acceptClientOnce(" accept_begin)
string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::advanceAcceptedClientOnce()"
    accept_end)
if(accept_begin EQUAL -1 OR accept_end EQUAL -1 OR
   NOT accept_begin LESS accept_end)
    message(FATAL_ERROR "Cannot isolate fresh accepted-client construction")
endif()
math(EXPR accept_length "${accept_end} - ${accept_begin}")
string(SUBSTRING "${host_source}" ${accept_begin}
    ${accept_length} accept_source)
require_order(accept_source
    "New accept must own a fresh connection aggregate"
    "auto connection = std::make_unique<LinuxRuntimeConnection>("
    "acceptedClient_ = std::move(connection)"
    "acceptedClientPhase_ = AcceptedClientPhase::PreAdmission")
require_token(connection_header
    "rdp_server::server::transport::McsSessionLifecycle session_{}"
    "LinuxRuntimeConnection must value-own one R3 session")

# LinuxRuntimeConnection::revoke() closes all first-MCS framing and the R3
# session/lease before cancelling the sole R1 transport owner.
string(FIND "${connection_source}"
    "void LinuxRuntimeConnection::revoke() noexcept" revoke_begin)
string(FIND "${connection_source}"
    "LinuxRuntimeConnection::admissionState() const noexcept" revoke_end)
if(revoke_begin EQUAL -1 OR revoke_end EQUAL -1 OR
   NOT revoke_begin LESS revoke_end)
    message(FATAL_ERROR "Cannot isolate connection revocation")
endif()
math(EXPR revoke_length "${revoke_end} - ${revoke_begin}")
string(SUBSTRING "${connection_source}" ${revoke_begin}
    ${revoke_length} revoke_source)
require_order(revoke_source
    "R3 framing must close before R1 cancellation"
    "mcsConnectInitialFrameReader_.close()"
    "connection_.cancel()")
require_token(revoke_source
    "broker_->revokeR3Session(*principalProof_, session_)"
    "R2-backed R3 revoke")
require_token(revoke_source
    "session_.close()"
    "Fallback R3 revoke")
require_order(revoke_source
    "R2-backed R3 revoke must precede R1 cancellation"
    "broker_->revokeR3Session(*principalProof_, session_)"
    "connection_.cancel()")
require_order(revoke_source
    "Fallback R3 revoke must precede R1 cancellation"
    "session_.close()"
    "connection_.cancel()")

# McsSessionLifecycle::close() scrubs connection-specific MCS/Share/channel
# state. A newly constructed R3 owner receives a distinct reconnect generation.
foreach(needle IN ITEMS
    "admissionGeneration_ = 0"
    "sessionGeneration_ = 0"
    "connectResponseDomain_ = {}"
    "connectResponseClientSettings_ = {}"
    "connectResponseAllocation_ = {}"
    "allocatedUserId_ = 0"
    "connectResponseWrite_.close()"
    "shareActivation_.close()"
    "clipboardStaticChannel_.close()"
    "graphicsDynamicVirtualChannel_.close()"
    "dynamicVirtualChannels_.close()"
    "joins_.close()"
    "phase_ = McsSessionPhase::Closed")
    require_token(mcs_header "${needle}" "MCS terminal scrub")
endforeach()
require_token(mcs_source
    "McsSessionLifecycle::McsSessionLifecycle() noexcept"
    "R3 fresh-session constructor")
require_token(mcs_source
    "allocateFirstClientAcceptanceReconnectGeneration()"
    "R3 fresh reconnect generation allocator")
