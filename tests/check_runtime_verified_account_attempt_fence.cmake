# SPDX-License-Identifier: GPL-3.0-or-later
# Production-source R2 account attempt order and single-owner policy.
# This never fabricates credentials, provider success, or native admission.
foreach(argument IN ITEMS
        RDP_R2_FINAL_CREDENTIAL_SOURCE
        RDP_R2_GSS_ACCEPTOR_HEADER
        RDP_R2_GSS_ACCEPTOR_SOURCE
        RDP_R2_LINUX_CONNECTION_SOURCE
        RDP_R2_LINUX_SERVER_SOURCE)
    if(NOT DEFINED ${argument} OR "${${argument}}" STREQUAL "")
        message(FATAL_ERROR "Missing ${argument}")
    endif()
endforeach()

file(READ "${RDP_R2_FINAL_CREDENTIAL_SOURCE}" credential_source)
file(READ "${RDP_R2_GSS_ACCEPTOR_HEADER}" acceptor_header)
file(READ "${RDP_R2_GSS_ACCEPTOR_SOURCE}" acceptor_source)
file(READ "${RDP_R2_LINUX_CONNECTION_SOURCE}" connection_source)
file(READ "${RDP_R2_LINUX_SERVER_SOURCE}" server_source)

# Scope the order assertion to the actual decrypted final-credential visitor.
# It must match a policy principal/account BEFORE charging the genuine
# GSS-derived principal, and must charge BEFORE invoking the PAM provider.
string(FIND "${credential_source}"
    "void verifyDelegatedPasswordCandidate(" visitor_begin)
string(FIND "${credential_source}"
    "bool permittedCredentialMessage(" visitor_end)
if(visitor_begin EQUAL -1 OR visitor_end EQUAL -1 OR
   visitor_end LESS_EQUAL visitor_begin)
    message(FATAL_ERROR "Missing R2 final credential visitor")
endif()
math(EXPR visitor_length "${visitor_end} - ${visitor_begin}")
string(SUBSTRING "${credential_source}" ${visitor_begin}
    ${visitor_length} visitor)
string(FIND "${visitor}" "matchPrincipalAccountCandidate(" candidate_match)
string(FIND "${visitor}" "if (!context.exactCandidate)" candidate_deny)
string(FIND "${visitor}" "context.attemptLimiter != nullptr" budget_guard)
string(FIND "${visitor}" "reserveVerifiedAccountAttempt(" account_reserve)
string(FIND "${visitor}" "context.authenticatedPrincipal" verified_principal)
string(FIND "${visitor}" "context.passwordVerifier->verify(" pam_verify)
if(candidate_match EQUAL -1 OR candidate_deny EQUAL -1 OR
   budget_guard EQUAL -1 OR account_reserve EQUAL -1 OR
   verified_principal EQUAL -1 OR pam_verify EQUAL -1 OR
   candidate_match GREATER_EQUAL candidate_deny OR
   candidate_deny GREATER_EQUAL budget_guard OR
   budget_guard GREATER_EQUAL account_reserve OR
   account_reserve GREATER_EQUAL pam_verify)
    message(FATAL_ERROR
        "GSS-verified account attempt must follow policy match and precede PAM")
endif()
string(FIND "${visitor}" "context.authenticatedPrincipal," reserve_key)
if(reserve_key EQUAL -1 OR reserve_key LESS account_reserve OR
   reserve_key GREATER pam_verify)
    message(FATAL_ERROR "PAM limiter must charge the actual GSS principal")
endif()
# The credential visitor must use the bound per-acceptor service budget.
string(FIND "${credential_source}"
    "verification.attemptLimiter = verifiedAccountAttemptLimiter_" bound_budget)
if(bound_budget EQUAL -1)
    message(FATAL_ERROR "Final authInfo visitor lost GSS acceptor budget")

# Exact one-shot R2 binding and terminal pointer retirement.
foreach(text_needed IN ITEMS
        "bindVerifiedAccountAttemptLimiter("
        "AuthenticationAttemptLimiter *verifiedAccountAttemptLimiter_")
    string(FIND "${acceptor_header}" "${text_needed}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "Missing private GSS attempt authority: ${text_needed}")
    endif()
endforeach()
foreach(text_needed IN ITEMS
        "stage_ != SpnegoStage::AwaitInitialToken"
        "passwordVerifier_ == nullptr"
        "verifiedAccountAttemptLimiter_ != nullptr"
        "verifiedAccountAttemptLimiter_ = &limiter"
        "verifiedAccountAttemptLimiter_ = nullptr")
    string(FIND "${acceptor_source}" "${text_needed}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "Missing terminal GSS budget binding: ${text_needed}")
    endif()
endforeach()

# The one serialized Linux service, not the client or separate provider,
# owns both peer/global and GSS/PAM account windows.
string(FIND "${server_source}" "reservePeerAuthenticationAttempt(" peer_gate)
string(FIND "${server_source}" "LinuxRuntimeConnection connection{" connection_owner)
string(FIND "${server_source}" "&context->authAttempts" service_budget)
if(peer_gate EQUAL -1 OR connection_owner EQUAL -1 OR
   service_budget EQUAL -1 OR peer_gate GREATER connection_owner OR
   connection_owner GREATER service_budget)
    message(FATAL_ERROR "Linux serve does not share one pre-NLA attempt budget")
endif()
string(FIND "${connection_source}"
    "securityConfiguration_.configureAcceptor(acceptor_)" security_provider)
string(FIND "${connection_source}"
    "acceptor_.bindVerifiedAccountAttemptLimiter(" bind_budget)
string(FIND "${connection_source}" "broker_.emplace(*policy)" broker_owner)
if(security_provider EQUAL -1 OR bind_budget EQUAL -1 OR
   broker_owner EQUAL -1 OR security_provider GREATER bind_budget OR
   bind_budget GREATER broker_owner)
    message(FATAL_ERROR "Budget must bind between configured GSS and R2 broker")
endif()
