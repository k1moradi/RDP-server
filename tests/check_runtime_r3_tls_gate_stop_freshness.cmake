# SPDX-License-Identifier: GPL-3.0-or-later
# R3 source contract: classify the first post-TLS boundary without changing
# wire behavior, and prove Stop destroys the accepted R3/MCS owner before R1.
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

# R1 must establish TLS before R2/CredSSP can move R10 toward any R3 phase.
# TlsEstablished and BindingVerified deliberately remain in PreAdmission.
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
    "CredentialsVerified must own the first R3 handoff"
    "case Step::CredentialsVerified:"
    "acceptedClient_->issueAdmission(*request)"
    "acceptedClientPhase_ = AcceptedClientPhase::McsConnectInitial")

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
    "acceptedClient_ = std::move(connection);"
    "acceptedClientPhase_ = AcceptedClientPhase::PreAdmission;")
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
