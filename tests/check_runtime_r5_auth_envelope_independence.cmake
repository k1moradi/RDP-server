# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.20)

foreach(required_variable IN ITEMS
        RDP_LINUX_HOST_CONTROL_SOURCE
        RDP_LINUX_CONNECTION_SOURCE)
    if(NOT DEFINED ${required_variable} OR
       "${${required_variable}}" STREQUAL "")
        message(FATAL_ERROR "missing required input: ${required_variable}")
    endif()
endforeach()

file(READ "${RDP_LINUX_HOST_CONTROL_SOURCE}" host_source)
file(READ "${RDP_LINUX_CONNECTION_SOURCE}" connection_source)

function(require_text source_text required_text failure_message)
    string(FIND "${source_text}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR "${failure_message}: ${required_text}")
    endif()
endfunction()

function(forbid_text source_text forbidden_text failure_message)
    string(FIND "${source_text}" "${forbidden_text}" found)
    if(NOT found LESS 0)
        message(FATAL_ERROR "${failure_message}: ${forbidden_text}")
    endif()
endfunction()

function(extract_between source_text begin_marker end_marker output_variable)
    string(FIND "${source_text}" "${begin_marker}" begin_position)
    string(FIND "${source_text}" "${end_marker}" end_position)
    if(begin_position LESS 0 OR end_position LESS_EQUAL begin_position)
        message(FATAL_ERROR
            "unable to isolate source region: ${begin_marker} -> ${end_marker}")
    endif()
    math(EXPR region_length "${end_position} - ${begin_position}")
    string(SUBSTRING "${source_text}" ${begin_position}
        ${region_length} region_source)
    set(${output_variable} "${region_source}" PARENT_SCOPE)
endfunction()

set(envelope_terms
    "StandaloneNtlmNegotiationEnvelope"
    "DirectNtlm"
    "negotiationEnvelope"
    "NTLMSSP"
    "acceptInitialToken"
    "acceptContinuationToken")

extract_between(
    "${host_source}"
    "constructHostAuthorizedX11Desktop("
    "struct LinuxHostPostShareDispatchContext"
    native_constructor_source)
foreach(forbidden_term IN LISTS envelope_terms)
    forbid_text(
        "${native_constructor_source}" "${forbidden_term}"
        "R5 native construction must not inspect the authentication envelope")
endforeach()

extract_between(
    "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::initializeNativeDesktop() noexcept"
    "RuntimeHostResult LinuxRuntimeHostControl::serviceNativeDesktopOnce() noexcept"
    initialize_native_source)
foreach(required_text IN ITEMS
        "acceptedClientPhase_ != AcceptedClientPhase::GraphicsReady"
        "visitNativeDesktopSelection("
        "candidate->admissionGeneration == 0U"
        "candidate->sessionGeneration == 0U"
        "nativeDesktop_ = std::move(candidate)")
    require_text(
        "${initialize_native_source}" "${required_text}"
        "R5 fresh admitted-owner gate missing")
endforeach()
foreach(forbidden_term IN LISTS envelope_terms)
    forbid_text(
        "${initialize_native_source}" "${forbidden_term}"
        "R5 initialization must consume only the admitted R2 capability")
endforeach()

extract_between(
    "${host_source}"
    "case AcceptedClientPhase::PreAdmission:"
    "case AcceptedClientPhase::McsConnectInitial:"
    preadmission_source)
foreach(required_text IN ITEMS
        "case Step::CredentialsVerified:"
        "acceptedClient_->issueAdmission(*request)"
        "case Step::Invalid:"
        "case Step::Closed:"
        "peerFailure(RuntimeHostError::AuthenticationRejected)")
    require_text(
        "${preadmission_source}" "${required_text}"
        "R2 pre-admission failure/lease gate missing")
endforeach()
string(FIND "${preadmission_source}"
    "case Step::CredentialsVerified:" credentials_verified_case)
string(FIND "${preadmission_source}"
    "acceptedClient_->issueAdmission(*request)" issue_admission_call)
if(credentials_verified_case LESS 0 OR issue_admission_call LESS 0 OR
   NOT credentials_verified_case LESS issue_admission_call)
    message(FATAL_ERROR
        "native admission sampling must remain after CredentialsVerified")
endif()

# PreAdmission must not enter any native or graphics state owner. The
# production-backed Type-2/EOF lifecycle separately proves the observable
# framebuffer/ClearCodec/write/ACK trace remains zero while awaiting Type 3 and
# after peer retirement. Hidden surface, frame-scheduler, AVC and FRAME_ACK
# state is pinned here by forbidding every production seam that could create or
# advance it from this isolated branch.
foreach(forbidden_text IN ITEMS
        "selectCurrentPhysicalX11Desktop("
        "initializeNativeDesktop("
        "serviceNativeDesktopOnce("
        "constructHostAuthorizedX11Desktop("
        "visitNativeDesktopSelection("
        "registerNativeChange("
        "X11DesktopResources"
        "X11AuthorizedInputRoute"
        "LinuxHostNativeDesktopState"
        "RdpGraphicsSurfaceReconfiguration"
        "RdpGraphicsFramePublicationReadiness"
        "nextFrameId"
        "graphicsWritePending"
        "framePublicationPending"
        "nextCapture"
        "Avc420"
        "AVC420"
        "X264"
        "RdpGraphicsFrameAcknowledge"
        "consumeR3PersonalDesktopGraphicsFrameAcknowledge("
        "startPersonalDesktopGraphicsDynamicVirtualChannel("
        "advancePersonalDesktopGraphicsDynamicVirtualChannel("
        "beginPersonalDesktopGraphicsSurfaceReconfiguration("
        "preflightPersonalDesktopGraphicsFramePublication("
        "startPersonalDesktopClearCodecFramePublication("
        "cancelUnwrittenPersonalDesktopGraphicsFrame("
        "advancePersonalDesktopPostShareApplicationRead("
        "dispatchPersonalDesktopPostShareGraphicsTpkt("
        "AcceptedClientPhase::GraphicsControl"
        "AcceptedClientPhase::GraphicsReady"
        "publishHostCapturedFrame("
        "processEvents("
        "consumeR4Frame("
        "nativeDesktop_ =")
    forbid_text(
        "${preadmission_source}" "${forbidden_text}"
        "pre-admission authentication failure must not touch native/graphics state")
endforeach()

extract_between(
    "${host_source}"
    "case AcceptedClientPhase::GraphicsControl:"
    "case AcceptedClientPhase::GraphicsReady:"
    graphics_control_source)
foreach(required_text IN ITEMS
        "case Step::Ready:"
        "authorizePersonalDesktopApplicationTraffic("
        "acceptedClientPhase_ = AcceptedClientPhase::GraphicsReady")
    require_text(
        "${graphics_control_source}" "${required_text}"
        "GraphicsReady transition gate missing")
endforeach()
forbid_text(
    "${graphics_control_source}" "initializeNativeDesktop("
    "R5 X11 ownership must not precede GraphicsReady")

extract_between(
    "${host_source}"
    "case AcceptedClientPhase::GraphicsReady:"
    "return peerFailure(RuntimeHostError::InternalFailure);"
    graphics_ready_source)
foreach(required_text IN ITEMS
        "authorizePersonalDesktopApplicationTraffic("
        "if (nativeDesktop_ == nullptr)"
        "return initializeNativeDesktop()")
    require_text(
        "${graphics_ready_source}" "${required_text}"
        "R5 GraphicsReady owner creation gate missing")
endforeach()
foreach(forbidden_term IN LISTS envelope_terms)
    forbid_text(
        "${graphics_ready_source}" "${forbidden_term}"
        "R5 GraphicsReady service must remain authentication-envelope agnostic")
endforeach()

extract_between(
    "${connection_source}"
    "bool LinuxRuntimeConnection::visitNativeDesktopSelection("
    "bool LinuxRuntimeConnection::nativeChangeRegistrationMatches("
    visit_selection_source)
foreach(required_text IN ITEMS
        "!ready()"
        "!broker_"
        "!lease_"
        "lease_->isRevoked()"
        "broker_->visitNativeDesktopSelection("
        "*lease_"
        "*principalProof_")
    require_text(
        "${visit_selection_source}" "${required_text}"
        "R5 must consume a live admitted R2 capability")
endforeach()
foreach(forbidden_term IN LISTS envelope_terms)
    forbid_text(
        "${visit_selection_source}" "${forbidden_term}"
        "native selection must not depend on the CredSSP envelope")
endforeach()

message(STATUS
    "R5/R4 pre-admission dormancy: no X11 owner or surface/scheduler/codec/ACK path; live R2 lease + GraphicsReady gate construction")
