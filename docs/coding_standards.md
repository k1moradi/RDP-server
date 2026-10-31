## R10 macOS accepted-client pre-admission ownership (2026-10-30)

The macOS HostControl service tick owns only the existing accepted R1 socket,
one R2 standalone CredSSP framer/writer/acceptor, and the memory-only
credential-generation selector. X.224 Confirm must finish before the sole R1
TLS/BIO owner starts; one zero-wait readiness check may drive at most one
bounded R1 or TSRequest step. Do not clone LinuxRuntimeConnection, add a Qt
worker or 25 ms polling loop. Readiness is not authorization.

The active listener generation and R1 selected TLS certificate are validated
on each step. Pin the exact R10 owner-consent grant/revocation epoch at accept
and revalidate before I/O, even when a later grant has identical permissions.
Credential replacement, Stop, expiry, listener replacement or consent loss
first retires R2 proof/TSRequest frames and replies, then R1 SSL/BIO/socket.
A successfully bound standalone proof is retained only for future R2, and
cannot grant native macOS admission, protected R3 MCS/Share or R7 attachment.
No cached UID, TCC flag, diagnostic state or booleans may supply that authority.

## R8 native FileContents terminalization callback authority (2026-10-30)

After the existing post-write generation/epoch fence, the macOS and Windows
file destinations must revalidate the same exact synchronized RemoteTransfer
authority after final resize, flush and close callbacks before publishing
Complete. Fail closed as SourceReplaced, even when an injected finalization
callback synchronously calls onRemoteGenerationChanged(). Terminal cleanup
marks status before callback entry, and close detaches its owned duplicate
before invoking the native closer, preventing recursive cleanup and double
close. If revocation occurs inside close, the duplicate may already be closed:
never reopen an owner-selected path or claim rollback after close; suppress
completed local URL/path handoff instead. No change to Linux thread-affine
direct pwrite/fsync, R2/R3 authorization, file path provenance or live R8
activation. The offline fake-native tests cover success and resize/flush/close
replacement without host file or clipboard access.

## R5 Linux/X11 private acceptance evidence never grants authority (2026-10-30)

The owner-private Linux X11 manifest is a closed schema of copied scalar
observations, not an R2 admission controller, X11 owner or GUI entry point.
Both initial and reconnect positive native Admission must independently
record an R2-bound owner-consent generation equal to the explicit owner grant;
a matching scalar alone does not prove genuine R2 authority. Admit a valid
pre-graphics record without inventing native capture. Reject missing/extra
fields, source-SHA failures, stale/replaced epochs, input after revocation,
frame before Share, unmatched ACK and reconnect-generation reuse. The
public projection must never contain UID, Username, endpoint/address,
credentials, audit session or native IDs, XIDs, pixels or key/button payloads.
No duplicated R2/R10 control or 46th native X11 test is permitted.

## R2 macOS authorization visitor reentrancy and original-grant lifetime (2026-10-30)

The existing `MacNativeDesktopAuthorization` is R2's single grant owner, not
an R3 admission token. `visit(expectedAuthorizationGeneration, permissions, ...)`
must retain the original grant generation across native evidence sampling,
the synchronous visitor and post-visitor revalidation. Native evidence exposed
through `MacNativeDesktopAuthorizationView` is a callback-local snapshot,
never a pointer to mutable grant storage that can be cleared or rebound inside
the callback. A reentrant replacement may install a newer generation, but the
older visit must return denial without revoking that newer grant. Reinspect
the exact `CurrentOwnerSharingAuthority` epoch after native evidence reads,
which can synchronously revoke consent. Generations, UIDs, TCC status and GUI
Sharing are never standalone authority.

The real `StandalonePasswordAuthenticatedPrincipalProof` derives its private
authentication generation from the verified CredSSP acceptor, exact accepted
`OwnedPreauthTcpConnection`/TLS owner and configured credential generation.
No caller-supplied principal, credential bytes, generation or raw `SSL*`
can replace it. Credential change, Stop, lock, logout, native session/owner
replacement or listener/connection retirement must invalidate the R2 visit.
Do not treat this narrower visitor hardening as macOS native Admission or R3
integration: an Agent-3-reviewed private R3 gate and a concrete R10 owner for
the accepted connection, independently verified native session/lock evidence
and terminal revocation are still required.

A nested `MacNativeDesktopAuthorization::visit` is denied before another
native evidence reader or protected consumer can run. The owner-thread
reentrancy guard spans initial native evidence revalidation, the callback and
final grant-generation/consent revalidation; its stack-scoped retirement must
occur on every return. A reentrant `revoke()/bindAuthenticatedSession()` from
the callback remains allowed to produce a separate, higher generation, and
the earlier visit denies without revoking that newer grant. Nested-visit denial
alone must not revoke a still-current outer grant. No R3 private entry or
positive macOS OS admission is introduced.

## R1 OpenSSL typed-stack macro qualification (2026-10-30)

OpenSSL's typed STACK_OF accessors such as `sk_GENERAL_NAME_num`,
`sk_GENERAL_NAME_value` and `sk_GENERAL_NAME_push` are generated macros,
not namespace-scope C++ functions. Do not prefix them with `::`: OpenSSL
4.1's macro expansion makes that form ill-formed C++ under warnings-as-errors.
This is a source-compatibility rule only and does not change SAN matching,
certificate trust, TLS policy, socket ownership or R2 admission.

## R6 paired physical Windows client evidence is non-authorizing (2026-10-30)

Preserve the single R5 macOS owner-evidence collector and its private
schema-v2 manifest. Consume it read-only; accept a separate closed-schema
Windows mstsc record and only the macOS facts missing from R5. Require
independent stage facts, credential source and intention to re-enter
rather than inferring them from an EOF or generic UI error. Reject
unapproved authentication fields and emit only allowlisted redacted
diagnostics. No raw credentials, NTLM bytes, tokens, logs, endpoint,
exact UI text or connection identifiers enter shared summaries.
Neither A/B success nor hosted SSPI success grants native Admission.

## R7 borrowed macOS framebuffer callbacks may revoke their native owner (2026-10-30)

The macOS FrameMailbox must never invoke its R4 frame consumer while holding
the mailbox mutex. A consumer may synchronously revoke the owning native
desktop, whose retirement calls back into the same mailbox. Keep the borrowed
BGRA arena alive until the callback returns, including when owner retirement
resets the shared mailbox pointer; invalidate its generation immediately.
While one borrow is in flight, discard concurrent capture updates rather than
mutate borrowed pixels. A callback that caused retirement must return denial,
not successful publication. Do not add per-frame allocation/copy, a second
capture owner, an OS permission prompt or an R10 admission shortcut.

## R1 OpenSSL 4.1 identity-only SAN matching portability (2026-10-30)

`RuntimeServerTlsContext::validateEndpointIdentity()` is only selected-leaf
identity coverage, not X.509 trust, TLS permission, native Admission or listener
authority. OpenSSL 4.1 deprecates `X509_check_ip_asc` and `X509_check_host`;
its recommended `X509_VERIFY_PARAM_set1_host/set1_ip_asc` plus
`X509_verify_cert` would additionally invoke chain verification and must not
replace this helper. On OpenSSL 4.1+, inspect the selected certificate's
bounded decoded subjectAltName entries directly: binary iPAddress (4/16 bytes)
for valid numeric endpoints, case-insensitive dNSName for DNS endpoints,
full-label leftmost wildcard only (no partial/multi-label match), and never
consult Subject Common Name. Handle borrowed ASN.1 buffers within the
GENERAL_NAMES RAII lifetime; use `ASN1_STRING_get_length` with 4.1+ headers,
not the deprecated signed-length accessor. Older OpenSSL/LibreSSL retain the
existing `X509_check_*` branch and flags; keep `-Werror`. Empty/overlong/NUL
endpoints remain InvalidEndpoint; malformed numeric-looking text retains its
former DNS mismatch classification. A positive self-signed SAN match is
not a trust-chain PASS and must never publish R2/Share/desktop authority.
No Type-2 or socket/TLS I/O behavior changes.

## R8 native file destination write callbacks must revalidate source ownership (2026-10-30)

The macOS and Windows clipboard file destinations may call an injected native
write boundary while a FileContents RANGE result is being consumed. A successful
native write is not permission to advance destination state: before incrementing
`bytesWritten_` or completing the file, revalidate that `RemoteTransfer` is
still synchronized and that both the exact clipboard generation and monotonic
source epoch match the destination. If source ownership changes during the
callback, truncate and close the owned duplicate and terminalize the destination
as `SourceReplaced`. Remote FILEDESCRIPTORW names remain bounded metadata only;
they never authorize or construct a local path. Linux's production destination
uses direct thread-affine `pwrite` rather than an injected reentrant write
callback and retains its existing pre-write generation fence.

## R6 CredSSP selected-certificate ASN.1 length portability (2026-10-30)

CredSSP selected-certificate public-key extraction follows the same OpenSSL
version boundary as CAL SignedData inspection: use the size_t-returning
`ASN1_STRING_get_length` only with OpenSSL 4.1+ headers, retain
`ASN1_STRING_length` for older OpenSSL and LibreSSL, and keep the existing
strict nonzero / `kMaximumCredSspPublicKeyBytes` bound before forming a
borrowed span. This is compile/API portability only; it must not alter the
selected certificate, TLS policy, CredSSP binding bytes, target identity or
authentication/native-admission decisions. Keep `-Werror`; do not suppress
the deprecation warning.

## R5 borrowed framebuffer callback may retire its native owner (2026-10-30)

The R4 framebuffer callback owns a temporary `std::span<const std::byte>` into the current XShm arena. The callback may synchronously trigger terminal native authority revocation, so callers must check aggregate health, capture generation and geometry **after** callback return before reporting a successful publication. Never inspect or retain the borrowed pixels after the callback destroys the old arena. Avoid a second buffer owner or a speculative XShm copy on the hot path. The native owner thread serializes callback delivery and resource retirement. Graceful disconnect under valid R2 authority may emit held-key/button releases; terminal authorization loss and fatal display failure must clear local input state without any XTEST request. R10 consumes the broker's authoritative consent/lease revalidation, not a duplicated owner-consent epoch.

## R2 native lease must retain its prepared owner-consent epoch (2026-10-30)

The Linux R2 broker captures `CurrentOwnerSharingAuthority::authorizationEpoch(requestedPermissions)` during Admission preparation, after freshly checking grant/native session. The scalar pair is a freshness fence, not permission or identity. After NSS/logind evidence and change-monitor sampling and before finishing proof/R1 CredSSP admission, require `authorizesAtEpoch()` with the same exact permissions; repeat immediately after synchronous completion and before publishing the lease. Store the epoch in the existing private lease control and require the same epoch on every protected broker authorization/revalidation, so a same-permission replacement grant cannot reuse an older lease. Failure is terminal `OwnerConsentMissing`, not a retry or a CredSSP/password-policy exception. Broker and mutable grant methods are owner-thread serialized; atomic revocation can also publish terminal loss. An `isRevoked()` scalar observation is not a substitute for protected R2 broker revalidation before MCS, Share, graphics, input or clipboard. No owner-consent state or privileged proof is exposed to R10.

## R8 local source destruction revokes publication authority (2026-10-30)

Native clipboard ownership may end without a new generation. Revoke only
the exact current server source in the existing bridge; invalidate old
Accepted receipts and borrowed route observations, retaining monotonic
generation high-water. Drain a Delivered server Format List response as
Superseded. Only unbound staged R8 bytes can be discarded; once R3 owns
the queued write, retire R8 and require R2/R3 to cancel its sole route/
writer without fabricating write offsets or receipts. Stale native
callbacks never revoke a later generation. Serialized event-loop only.

## R3 PKCS#7 signed-content length accessor across OpenSSL versions (2026-10-30)

For CAL SignedData inspection, preserve the exact optional-content policy:
an absent `contents->d.data` is allowed, a present zero-length OCTET STRING
is allowed, and any nonempty content is `UnsupportedContainer` before chain
trust evaluation. OpenSSL 4.1 introduces the `size_t`-returning
`ASN1_STRING_get_length` and deprecates `ASN1_STRING_length`; use the new
accessor only with OpenSSL 4.1+ headers, otherwise retain the old accessor,
including on LibreSSL. The zero/nonzero comparison needs no cast or warning
suppression. Keep `-Werror` and licensing enabled; this is header/API
compatibility only, not a CAL policy or RDP wire change.

## R3 successful CredentialsVerified does not admit buffered MCS (2026-10-30)

A successful CredSSP `CredentialsVerified` transition is authentication
evidence, not native-session authority. R1/OpenSSL may already hold a complete
416-byte Microsoft Connect-Initial in the same TLS application write as final
`authInfo`; R2 must consume only the bounded CredSSP DER and the connection
must still obtain a fresh, independent native R2 lease before R3 reads any of
those bytes. If native Admission denies, retire the accepted connection and all
buffered post-auth plaintext with no MCS/GCC semantic dispatch, Share
transition, or static/dynamic virtual-channel construction. A caller Boolean,
valid TPKT/GCC profile, Username, credential generation or cached epoch never
substitutes for that lease.

R8 dormant CLIPRDR initialization may consume only one current protected R3
route observation after `ShareActivated`: the exact joined `cliprdr` static
channel ID and route generation, the R3-assigned user ID used by that route,
the current Share state and fresh R2 authority. R3 remains the sole owner of
MCS/static-channel framing, queued write slices and the exact
`(routeGeneration, replySequence, writeSliceSequence, acceptedBytes)` receipt.
`R3ClipboardTransferBridge` consumes those prerequisites and retains
server-originated `CB_CLIP_CAPS` / `CB_FORMAT_LIST` application
serialization; do not add an R3 serializer or second route/receipt owner.

## R5 callback-time XCB authority retirement (2026-10-30)

An owner-thread native X11 event sink may revoke its aggregate while a malloc-backed XCB event is still borrowed by the active event batch. After terminal authority loss, discard held XTEST state without release requests; retire event registrations, XDamage/XShm and the sole XCB owner before another poll. The batch frees only its current event, must not invoke later callbacks on the retired owner and never forwards borrowed pixels/events into a replacement generation. R2's protected synchronous visitor remains the only native authorization gate; geometry or event observations grant none. Preserve serialized event-loop affinity and explicit RAII child-before-XCB destruction.

## R8 local clipboard generation invalidates earlier route observations (2026-10-30)

A local/native clipboard generation change must clear any previously borrowed
fresh-route observation before that generation can be advertised. The local
owner can change independently of R2, so only an R2/R3 protected route visit
performed after the new generation exists may authorize staging its server
Format List. Keep the monotonic local-generation high-water mark; do not retire
the route merely because the native generation advanced. Response draining and
the one R1 writer remain unchanged.

## R8 dormant CLIPRDR initialization and local-publication ownership (2026-10-30)

Keep server initialization in the existing `R3ClipboardTransferBridge`; do
not add a second clipboard controller, writer, channel framer or generation
owner. Server `CB_CLIP_CAPS` precedes `CB_MONITOR_READY`, and each outbound
stage advances only from the exact R3/R2 accepted-byte `Delivered` receipt.
A fresh protected R3 route observation is required before each newly staged
application PDU. Serialization, a joined channel ID, or an initialization enum
is never R2/Share/native authority.

After Monitor Ready, accept the client's initial Format List even if the first
client capabilities and Temporary Directory have not arrived yet. A first late
capability PDU may update feature negotiation for subsequent Format Lists;
missing capabilities mean zero negotiated flags. Do not reinterpret an already
parsed short Format List after capabilities arrive. Temporary Directory remains
optional for base initialization but mandatory wherever the existing file-lock
prerequisite requires it. Duplicate capability/temp-directory PDUs stay
terminal.

Treat server-local clipboard ownership as a lifetime-monotonic generation
separate from the remote `RemoteTransfer` source generation. A server Format
List may be staged only after base initialization is Ready, for the exact
current local generation, with no incompatible PDU/request or undrained prior
Format List response. If ownership changes before the response arrives, drain
the old response as superseded and never apply it to the replacement generation.
Preserve local-generation high-water marks across R3 route retirement so a
reused numeric channel ID cannot revive old ownership. Route-local stage,
pending response and receipt state must retire on R2/Share/channel loss.

Do not couple this ordering state to ordinary Format Data single-flight,
FileContents stream IDs, lock/`clipDataId` state, X11 INCR ownership or native
adapter callbacks. Those owners retain their existing generation and
retirement contracts. `kLinuxProductionClipboardActivationApproved` remains
false until the separately authorized R10 product handoff is satisfied.

## R5 queued X11 events remain owner-generation local (2026-10-30)

An XCB event is valid only for the aggregate connection/generation that received it. Authorization-loss teardown must destroy geometry-bound children and the sole XCB owner before any replacement aggregate is exposed; do not copy, cache or replay XDamage/XFixes/RandR/input events across owners. Replacement construction must allocate fresh capture/native resource generations even when display name, root geometry and R2 session generation are unchanged. Terminal authority loss uses suppressing input retirement; only a still-authorized graceful disconnect may emit held-input cleanup.

## R3 first-MCS buffered plaintext is never admission authority (2026-10-30)

R1/OpenSSL may hold decrypted bytes beyond the current CredSSP frame, including
a partial or complete MCS Connect-Initial. Those bytes are transport state only.
R3 must not consume the first MCS byte until the connection owns a current,
non-revoked native R2 lease and R2 revalidates the exact authenticated proof,
TLS owner and native generations. Completion of a bounded TPKT requires a
second authorization at semantic dispatch through
`authorizeR3McsConnectInitial`; cached readiness, protocol validity, username,
Connect-Initial content or diagnostic epochs never promote authority. Any
failure closes the R3 owner before R2/R1 teardown.

Later reads and writes keep the same rule: protected transitions are freshly
authorized before each bounded read or write plan, and accepted-byte write
receipts are reauthorized before they can advance state. PersonalDesktop
changes only the licensing decision. Static-channel serialization remains R8
application ownership, while R3 retains the joined route generation and
accepted-byte ledger.

## R2/R6 fail-only empty delegated-field observability (2026-10-30)

After the actual production CredSSP verifier's canonical parser validates password fields, its borrowed visitor may retain at most a bounded enum describing empty delegated username/password *only when authentication fails*. Never retain the borrowed `std::span` buffers, their sizes, actual UTF-16 values, credentials or raw SSPI tokens; reset the enum with challenge owner reset and successful authentication. The classifier has no effect on the existing comparison, signature/seal, session provenance, credential-generation or R2 native-admission predicate. Windows oracle logging must distinguish an SSPI input empty-domain request from any observed delegated fields; neither is proof of a valid login or a policy exception.

## R8 server-originated CLIPRDR serialization ownership (2026-10-30)

Server-originated clipboard capabilities and format offers belong to the
existing `R3ClipboardTransferBridge` outbound owner; do not add a second
clipboard controller, static-channel serializer, write-offset ledger or socket
reader. A serializer may run only after the exact R3 route generation has been
observed, copies any caller-borrowed format-name views before return, and stages
the resulting complete CLIPRDR application PDU into the bridge's existing owned
contiguous buffer. R3/R2 remain the sole static-channel/MCS queue and
accepted-byte receipt owner.

Advertise one MS-RDPECLIP General Capability Set v2 and mask configured flags
to `RemoteTransfer::kSupportedGeneralFlags`; a configuration bit unsupported
by the production state machine must never appear on the wire. General
capability version is informational. Select a long `CB_FORMAT_LIST` only from
the mutually negotiated `CB_USE_LONG_FORMAT_NAMES` bit. Long entries are
LE32 format ID plus a null-terminated UTF-16LE name. Without the negotiated
long-name bit, use fixed 36-byte entries: `CB_ASCII_NAMES` only if every name
fits the 32-byte ASCII field, otherwise the 16-code-unit Unicode field. Reject
rather than silently truncate an outbound registered name that cannot be
represented. Require nonzero unique format IDs, valid bounded UTF-16 and at
most `RemoteTransfer::kMaximumFormats` entries.

Serialization and an R3 route observation are not activation authority. The
live owner still must implement the normative initialization/order policy,
fresh R2 authorization, joined `cliprdr` role and one R1 TLS writer.
Keep `kLinuxProductionClipboardActivationApproved = false`; offline
capability/format bytes must not flip it or construct native clipboard state.

## R2/R6 credential-parser failure-only reinspection (2026-10-30)

Final CredSSP diagnostic refinement may call the existing bounded credential inspection a second time **only after** the canonical delegated-password visitor has already failed. Keep this off the successful authentication path, reuse the same parser contract, and project only an enum distinguishing outer credential-envelope DER, nested password-field structure, unsupported type or generic invalid input. Never expose decrypted buffer contents or lengths to logs/UI, and never make the diagnostic result influence credential acceptance, retry, fallback, challenge construction or native admission. This preserves one R2 verifier owner while giving R6 an interoperability boundary precise enough for a Microsoft differential.

## R2/R6 final CredSSP authInfo first-failure ownership (2026-10-30)

The single production CredSSP acceptor may retain one small enum through
terminal final-authInfo rejection, using its existing parser and sign/seal
verifier. The enum is observation only: no decrypted credential buffers,
identity, password, domain string, access capability or fallback authority may
escape. Test fixtures may report an SSPI empty-domain *request* separately
from the verified decrypted-field category; zero `DomainLength` is not proof
of delegated-domain emptiness. Distinguish invalid protected length,
cryptographic unwrapping, invalid DER/type, nonempty domain and combined
identity/password mismatch without changing the verifier's acceptance
predicate or fail-closed teardown. An empty TSPasswordCreds userName or
password OCTET STRING is syntactically representable and must not be mislabeled
as malformed DER; standalone matching, Unix-account selection and PAM remain
responsible for rejecting empty credentials before any authority is granted. Clear observations on fresh challenge,
reset and successful verification. Agent 2 owns future verifier-policy changes;
Agent 6's Windows oracle remains diagnostic and `native-admission=no`.

## R3 Microsoft RDP User Channel ID profile (2026-10-29)

For RDP interoperability, follow **MS-RDPBCGR** as the project-primary wire
authority when it conflicts with the referenced generic MCS/GCC ASN.1 text.
MS-RDPBCGR explicitly defines both the RDP User Channel ID store and GCC
Conference Create Response nodeID as **1001..65536 inclusive**. The generic
T.124/T.125 formal modules instead define DynamicChannelID/UserId as
1001..65535. Do not silently tighten the RDP implementation to the generic
upper bound.

In the RDP profile, the aligned-PER initiator remains encoded as an offset from
1001, so `0xFC17` represents RDP User Channel ID 65536 and is accepted;
`0xFC18` represents 65537 and is rejected. Keep this RDP-profile UserId rule
separate from ordinary 16-bit ChannelId fields and from Share Control fields
that have their own encodings and bounds. Any future change to this exception
requires direct Microsoft-client evidence plus an explicit MS-RDPBCGR
reconciliation; lower-level ASN.1 alone is insufficient.

## R7 configured Username and first-failure wording are runtime-authoritative (2026-10-29)

The configured standalone Username is non-secret but still belongs to R10's
selected credential generation. Retain it only as bounded generation-fenced
configuration metadata in the same serialized R10 owner; do not reach into the
password/hash-bearing credential object and do not treat a successful GUI
handoff as an independent credential-state cache. Ordinary Stop preserves the
receipt together with the credential; credential replacement, mode change,
terminal revoke and Quit retire it.

R7 may remember only the last Username projected by R10 to preserve an
in-progress owner edit. Startup and unchanged Stop -> Start synchronize from
R10. Diagnostic export remains Username-free even though Main may display the
configured non-secret Username.

First-failure product wording follows typed runtime state. Only
`AuthenticationIncompletePeerClosed` plus the bounded peer-close observation
may produce `Client disconnected before completing authentication.`.
`AuthenticationRejected` must not be reshaped into that wording from a legacy
stage pattern; absent a typed credential rejection or native-admission reason it
remains generic remote authentication failure.

## R10 pre-auth service fairness stays serialized and readiness-led (2026-10-29)

The Linux GUI may drain a bounded burst of already-actionable R10 work, but it
must retain exactly one socket/TLS/CredSSP owner and one Qt owner thread. A
successful service result with retryable=false is immediately actionable; Qt
may run at most eight such calls before yielding through a zero-delay timer.
The existing 25 ms cadence is reserved for retryable=true. Never add a second
transport reader, authentication controller, worker socket loop, sleep, larger
timeout or repeated TLS handshake spin.

Accepted TCP and early X.224/TLS/CredSSP progress must not sit behind blocking
native evidence. Try nonblocking accept before owner/interface maintenance and
retry once afterward. For a live PreAdmission peer, R1 always advances first.
Full logind/X11/interface owner maintenance is absent from Accepted-to-TLS and
TLS-to-Type-1. It resumes at Direct-NTLM Await-Type-3/later when R1 is waiting,
then R1 is polled once more. Existing lock/logout/session-replacement tests at
Await-Type-3 remain mandatory; fresh R2 admission still gates every MCS entry.

GUI status is projection, not reauthorization. While a peer is PreAdmission it
may use only the existing non-authorizing owner-grant projection and must not
synchronously sample logind/X11 owner state or listener interface identity.

R1's new pre-TLS socket-poll and ready-to-service fields remain the transport
owner's precise subsets. R10 complements them with stage-local service-call
count, application-reschedule wait, peer-readiness wait upper bound, total
service execution, native-maintenance execution and maximum application gap.
These observations never change readiness, timeout or authority.

## R4 first-frame graphics capability ownership (2026-10-29)

RDPGFX may be opened only after the parsed Client Core Data explicitly advertises
`RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL` (0x0100), in addition to the existing
R2 admission, Share and joined-`drdynvc` gates. The Client Core bit is structural
capability evidence only; it never creates authentication, native admission,
Share, a DVC or a graphics surface. If it is absent, the current PersonalDesktop
runtime fails graphics startup closed because no legacy bitmap-update publication
path is implemented.

RDPGFX codec choice belongs exclusively to the selected RDPGFX capability set.
The current server supports only VERSION8 and VERSION81, always retains
ClearCodec as the implemented fallback, and permits AVC420 only when the
selected VERSION81 set carries AVC420_ENABLED. Do not infer RDPGFX codec support
from the MS-RDPBCGR Bitmap Codecs capability and do not confirm VERSION10+
until their additional protocol requirements, including QoE frame ACK intake,
are implemented.

The first-frame lifecycle stays single-owner and bounded: CREATE_SURFACE and
MAP_SURFACE_TO_OUTPUT must complete for the current generation before a frame;
framebuffer geometry must equal the mapped surface; exact delivery creates one
ACK-window entry; duplicate/stale IDs and generations are rejected. The ACK
window is capped at 64 frames. Credit exhaustion is a side-effect-free defer,
not a reason to capture more pixels or spin: R10 schedules a bounded later
capture and keeps servicing the sole R1 read path for FRAME_ACKNOWLEDGE. A
suspend ACK clears outstanding credit and must never cause the server to wait
for further ACKs. Session revocation retires the generation before later frame
or ACK callbacks can publish state.

## R7 first-failure desktop diagnostics remain projection-only (2026-10-29)

The desktop GUI may present and export only the bounded read-only facts already
owned by R1/R2/R10 for the accepted connection: selected endpoint, R10's opaque
accepted-client ID, TLS version/cipher, current certificate fingerprint,
redacted NTLM Type-1 structure, Type-2 local-write state, Type-3 stage
progression, typed termination category and the existing monotonic stage
durations/counters. R7 must not add a socket/BIO reader, TLS/NTLM/CredSSP
parser, timer, packet cache or competing connection-generation owner.

"Invalid credentials" is permitted only when the existing standalone NTLM
verifier reports its typed credential-rejection result and the connection is
still pre-Admission. A peer close before Type 3 is instead "Client disconnected
before completing authentication"; verified credentials followed by a concrete
R2 admission reason is "Native desktop admission denied". Generic client error
0x204 is never proof that the server was unreachable. Missing facts remain
unavailable rather than being reconstructed from UI state or log text.

Diagnostic export is explicit user action and serializes the same bounded
snapshot rendered in Advanced. Never export Session Passwords, NTLM
challenge/response bytes, MICs, protected authInfo, TLS/session keys, delegated
credentials or raw protocol records. The export action must not change
firewall, TermService, OS RDP policy, networking, trust, listener or credential
state. Ordinary GUI launch remains read-only until explicit Sharing ON.

The configured Username remains the existing non-secret GUI handoff receipt:
after a successful standalone credential transaction it must continue to match
the credential that R10 owns. Ordinary Sharing OFF preserves the runtime
credential under the established security rule, and Stop -> Start may reuse it
only while that displayed Username is unchanged. A Username replacement still
requires a new matching Session Password/Confirm handoff.

## R2 challenge evidence and mutation ownership (2026-10-29)

A physical NTLM reference fixture must distinguish captured bytes from
normalized test bytes. Never turn an uncaptured SECURITY_BUFFER offset,
descriptor or payload byte into asserted wire evidence merely because a
zero-filled synthetic message parses. When the physical receipt retains a
VERSION structure, preserve that known structure in the reference while
marking genuinely uncaptured fields explicitly unknown.

For a standalone CredSSP NTLMv2 challenge with negotiated integrity and
confidentiality, keep the Type-2 flag relation explicit: return negotiated
SIGN/SEAL/EXTENDED_SESSIONSECURITY/128 and any selected KEY_EXCH/56 properties;
server-only target-type/TargetInfo flags may be added, and VERSION may be
omitted only with an all-zero Version field. The selected TargetInfo must keep
the required NetBIOS domain and computer AV pairs and a terminal EOL; the
production writer's timestamp remains bounded wire state, not authentication
authority.

Compatibility experiments that deliberately remove a required flag or AV pair
are test-only protocol mutations. Derive them from the actual production
challenge, label them as invalid controls, and do not pass them back through a
production writer/validator in a way that makes the oracle self-confirming.
Run independent Microsoft-provider controls in fresh processes when practical
so provider state from one invalid case cannot classify another. No such
experiment authorizes production wire changes unless a supported external
Microsoft client first demonstrates the corresponding failure on the
unmodified production path.

## R1 pre-TLS transport attribution stays inside the existing owners (2026-10-29)

The accepted-to-established-TLS diagnostic may be decomposed only by reusing
R10's existing accepted-connection `std::chrono::steady_clock` and R1's sole
native socket/BIO owner. R1 may expose cumulative received and sent byte
scalars; R10 may latch first observed X.224/TLS byte progress and existing
stage transitions. These are observation points, not packet timestamps or
peer-receipt claims.

Do not equate time spent inside the existing socket-readiness poll with the
full time a nonblocking connection waits for readiness: GUI/service schedulers
may intentionally issue zero-timeout polls. Preserve Read versus Write
direction by accounting wall-clock dwell while that existing R1 interest is
authoritative between bounded service calls. Keep actual native-poll duration
as a separate non-additive subset.

When the existing poller observes matching readiness, it may latch that
connection-local steady-clock observation until the next matching
`advancePreAdmission` call. The readiness-to-service age is a subset of the
corresponding Read/Write dwell and diagnoses runtime scheduling after readiness
was already observed. TLS handshake active work is a subset of R1 active work
and may be identified only when the existing handshake-step counter advances.
Residual accepted-to-TLS time is reserved for non-Read/Write phases rather
than guessed as peer or scheduler delay.

Do not add a socket reader, TLS record parser, timer thread, timeout, flush
loop or repeated `SSL_do_handshake` spin. X.224 still drains before TLS;
`SSL_ERROR_WANT_READ` / `SSL_ERROR_WANT_WRITE` remain authoritative.
Cumulative send progress proves only that the local kernel accepted bytes.
It cannot prove peer receipt or authorize TLS/CredSSP, Admission, MCS, Share,
graphics, input or clipboard changes.

## R5 physical-client evidence is private; redacted summaries are typed (2026-10-29)

The R5 private manifest may carry the bounded R1/R10 timing-attribution scalars
that already exist in the production diagnostic owner. Preserve their exact
measurement semantics: socket-poll and ready-to-service values are non-additive
subsets, R10 peer-wait is an upper bound, and app-reschedule/service/native
maintenance fields are scheduler observations rather than authentication
authority. Never infer a client cause from those numbers. Missing/contradictory
timing invalidates a current physical evidence row; nonzero early native
maintenance is a separate qualification finding, not a reason to relabel valid
evidence as malformed.

Keep the owner-selected Windows App Core/UI files and exact client text in the
private evidence bundle. A reusable validator may read that bundle but must
emit only bounded non-secret facts: exact server SHA/certificate identity,
client version/build, redacted endpoint correlation, credential-control state,
typed server stages and normalized first-client-error category/source. Do not
copy raw log lines, usernames, exact UI messages, log paths/hashes or connection
identifiers into shared diagnostics. A bare UI code such as `0x204` remains
`unknown` until the same-attempt private Core/UI evidence provides an explicit
provider category/code. Missing logs, excessive timestamp delta, inconsistent
certificate decisions and invalid A/B controls are evidence failures, never
inputs to a guessed protocol diagnosis.

The Linux runtime must remain native-dormant while an accepted peer is still
pre-admission. R10 may refresh the read-only seat0/session/owner evidence and
current owner-consent generation before advancing R1/R2, but X11 desktop
construction, capture, XTEST input dispatch, clipboard preparation and native
event polling are unreachable until the same peer has genuine R2 Admission,
Share activation and Graphics readiness. Lock/logout/session replacement or
owner revocation during Await-Type-3 retires the accepted connection/listener
before any native aggregate can be created. Consent bits are not native input
authority.

## R8 offline CLIPRDR conformance and X11 INCR abort cleanup (2026-10-29)

MS-RDPECLIP capability negotiation remains feature-bit driven: General
Capability `version` is informational, missing General capabilities mean zero
flags, long Format List names require mutual `CB_USE_LONG_FORMAT_NAMES`, and
streamed file requests require mutual `CB_STREAM_FILECLIP_ENABLED`. Standard
text/Unicode/DIB IDs and registered `PNG`/`FileGroupDescriptorW` names remain
format-list state, never capability or native-admission authority. Format Data
requests stay single-flight because their responses have no wire request ID;
FileContents uses its own monotonic `streamId` and exact response correlation.

An X11 INCR transfer that has already announced its requestor property must not
leave the INCR marker or a partial chunk behind when timeout, publication
replacement, native owner loss, or a property-write failure aborts the transfer.
Retire the in-memory INCR state first, restore the borrowed requestor event mask,
and delete the transfer property on abort. Preserve the zero-length property on
a successful INCR completion, and touch neither property nor event mask after a
requestor DestroyNotify. This cleanup is native presentation only; it creates no
CLIPRDR, R2, R3, Share, or production activation authority.

## R3 post-authentication MCS/GCC handoff contract (2026-10-29)

For the HYBRID/NLA product path, R1 owns X.224 negotiation, TLS and the complete
CredSSP transport. The first Basic Settings packet eligible for R3 after
successful credential verification **and** the project's independent revocable
R2 native-session admission is one complete TLS-protected TPKT/X.224 Data TPDU
containing the BER MCS Connect-Initial and PER GCC Conference Create Request.
A pre-Type-3 packet, a syntactically valid Connect-Initial, a caller Boolean or
a copied generation can never create this authority. R10 may assemble exactly
one TPKT boundary; R3 alone parses MCS/GCC after the concrete R2 broker
reauthorizes the exact R1 owner.

MS-RDPBCGR 3.3.5.3.3 requires the GCC Client Security Data
`encryptionMethods` and `extEncryptionMethods` fields, taken together, to
contain at least one recognized encryption-method flag. Reject zero or
unknown-only masks even though Standard RDP Security is not selected; accepting
the fields is protocol validation, not permission to downgrade from Enhanced
Security. French-locale placement in `extEncryptionMethods` remains valid.
Client Data Blocks are type-tagged and may be reordered; duplicate known blocks,
inconsistent lengths, invalid H.221 keys, over-limit GCC data, invalid channel
counts/arrays and security-selection replay mismatches fail closed before
Connect-Response publication.

A successful protocol-only decode may merge T.125 domain parameters and plan
the positional server channel IDs, but these values are still non-authorizing.
The server response preserves requested static-channel order, and no
Erect/Attach/Join, licensing, Share, graphics, input or clipboard transition
may occur until the same revocable R2 lease is freshly revalidated. Personal
desktop mode changes only the later licensing branch; it does not weaken the
CredSSP/native-admission or MCS/Share gates.

## R10 pre-authentication stage-clock ownership (2026-10-27)

R10 borrows only R1's established-TLS fact and R2's parsed Type-1 and queued
Type-2 facts. The sole accepted-connection owner latches each first transition
using `std::chrono::steady_clock`, caching bounded microsecond durations
with explicit availability flags. Existing Type-2 delivery and peer-EOF
clocks remain in that owner. Neither a new transport reader, an independent
authentication parser, remote-receipt assumptions, timeout policy nor
admission capability is created. The fail-only terminal scalar snapshot
survives the accepted connection's revocation, and a fresh peer resets it.

## R7 configured Username presentation follows the GUI credential handoff (2026-10-27)

After the production standalone credential owner accepts a GUI handoff, remember
only the non-secret Username displayed at that handoff for presentation
consistency. This is not a second credential verifier or an R2/R10 authority.
Ordinary Sharing OFF preserves the memory-only runtime password, so a later
Username edit with cleared Password/Confirm must not silently reuse the old
credential identifier or instruct the remote client to use the changed name.
Require an explicit new, matching Session Password/Confirm transaction on
Sharing ON before the changed Username becomes the configured display name.
Restoring the previous name permits ordinary no-password Stop/Start reuse.
The Main guidance must reflect a pending change without exposing a secret or
implying any automatic client synchronization. Never infer the physical
pre-Type-3 disconnect's cause from this presentation state.

## Agent 1 completes post-Type-2 wire-silence ownership (2026-10-27)

Extend Agent-10's existing timeline rather than creating a second TLS/CredSSP
observer. R1's sole native receive path owns cumulative encrypted bytes;
snapshot that count at exact Type-2 TLS-write completion and report only its
delta. The existing TSRequest reader owns decrypted bytes, complete-frame count
and its bounded current partial-frame byte count. R1's typed terminal path
remains authoritative for TLS close_notify/peer alert and TCP EOF/reset.

Count only TLS alerts surfaced by that existing R1 terminal path; do not add a
record parser or message callback. All fields are connection-local,
non-authorizing scalars. Zero encrypted bytes plus zero plaintext, frame and
alert activity is an explicit wire-silence observation.

Never log packet contents, TLS records, TSRequest bytes, NTLM response material,
passwords, keys or delegated data. These observations cannot change TLS or
certificate policy, Type-2 bytes, the pre-auth timeout, authentication,
Admission, MCS, Share, graphics, input or clipboard.

## Agent 9 owner-candidate qualification cannot reopen ruled-out wire hypotheses (2026-10-27)

The manual physical-candidate gate is stricter than an individual diagnostic
oracle. Because independent Microsoft evidence already reaches Type 3 over TLS
1.3 / `TLS_AES_256_GCM_SHA384`, Agent 9 requires the TLS-1.3 full-CREDSSP row
to be PASS with Type 3 before nominating another owner attempt. A future
test-only `ORACLE_LIMITATION` may remain useful diagnostic evidence, but it is
not sufficient for this physical candidate and must not reactivate a TLS-1.2
production cap or physical A/B workaround.

Consume the existing credential-source differential, owner-private Windows
App evidence and post-Type-2 timeline; do not add a second credential,
transport or parser owner. Only the explicit-valid row has a prescribed
Type-3 outcome. Wrong-password, empty-password and unavailable/no-SPNEGO
states remain observational. If wrong password emits Type 3 that is useful
negative evidence; if any state naturally consumes production Type 2 and then
emits no Type 3, that row becomes a leading physical comparison. No outcome
grants authentication, Admission, MCS, Share, graphics, input or clipboard
authority.

The next owner receipt must preserve secrets by recording only Saved-credential
selection, username, and the yes/no fact that its password matched the server
Session Password. Never record the password. Require same-attempt Core/UI logs
and exact client-visible error before interpreting peer EOF. Production remains
`fixed-name / RDP-SERVER`.

## R7 remote-client credential guidance is presentation-only (2026-10-27)

The standalone GUI may explain that its Username and Session Password are the
credentials the owner must enter in the remote RDP client. Keep that instruction
as plain presentation text beside the existing credential editors; it must not
become a second credential cache, a client-account selector or authentication
authority. Do not imply that Windows App automatically receives or discovers
the Session Password.

Preserve the existing secret lifetime: the operating-system password is never
retrieved or auto-filled, Session Password and confirmation remain masked, and
both GUI secret editors are cleared immediately after the existing runtime
credential handoff. Never add a post-handoff Copy Password or reveal action.
The non-secret Username may remain visible through its existing presentation
lifetime. Agent-5's owner-evidence procedure may require that same Username in
Windows App, but the two password ends remain manually entered and independently
owned.

A delivered Direct-NTLM Type 2 followed by peer EOF remains
`AuthenticationIncompletePeerClosed`. Main continues to say
`Remote client authentication did not complete.` and Advanced continues to
say `Client disconnected after authentication challenge.`. Do not render
wrong-password, certificate, native-admission or target-identity conclusions
from that boundary. Agent-2's credential-semantic oracle remains independent
test evidence and cannot be inferred from GUI state before its native result is
available.

Agent-10's typed post-Type-2 timeline may support a separate waiting
presentation when the exact accepted connection proves no post-Type-2 client
data. Do not infer that fact from absence of Type 3 or from the older physical
receipt. This Agent-7 increment intentionally leaves the optional waiting text
unchanged.

## Agent 6 credential-source differentials are test-only, observational and non-secret (2026-10-27)

Vary only test-supplied outbound Microsoft credential source while reusing the
production generated certificate, TLS/TSRequest path, Direct-NTLM acceptor and
unchanged production Type 2. Every executed row owns a fresh Microsoft CREDSSP
context. Valid, wrong-password and empty-password rows use fixed test material.
Unavailable/no-SPNEGO uses Schannel-only `CREDSSP_CRED` with
`pSpnegoCred == nullptr`; it must not silently borrow process credentials.

Hosted default/process credentials must not run when doing so could consume the
runner account's real credential material. Record `NOT_RUN_POLICY` and
`hosted-runner-credentials-used=no` instead.

Do not prescribe wrong/empty/unavailable outcomes. Record
AcquireCredentialsHandle, first InitializeSecurityContext, first TSRequest,
Type 1, production Type-2 consumption, next client output, Type 3, terminal
status and monotonic elapsed time. A natural Type-1 -> Type-2-consumed ->
no-Type-3 outcome is diagnostic evidence, not authority. Never log credential
bytes, NTLM responses, keys or delegated credentials. Production remains
`fixed-name / RDP-SERVER`.

## Agent 5 physical Windows App credential evidence is private and non-authorizing (2026-10-27)

The macOS Windows App owner-evidence path may record only the bounded client facts
needed to classify the pre-Type-3 boundary: Saved credential state, exact saved
Username when one exists, whether that saved credential was newly created for
the attempt, whether the Windows App credential and RDP-server standalone
credential were intentionally matched, Core/UI logging lifecycle, exact
user-visible error, certificate-warning state and the correlated Linux
connection ID/timestamp. These are owner-private diagnostics, not authentication
or native-admission authority.

The helper must have no password input or output. The independent Session
Password remains owned by the RDP-server standalone credential owner, and the
Windows App saved password remains entered only through Windows App. Never copy
either secret into a manifest, command line, repository document or test
fixture. Do not substitute the Linux account password unless the owner
intentionally made it identical to the standalone Session Password; record only
the yes/no fact that the two application credential ends were intentionally
matched.

Do not access Keychain, mutate trust, change Windows App preferences or invent
a private client-log path. A committed Type 2 followed by peer EOF before Type
3 cannot be classified as wrong-password, certificate-rejection or
credential-rejection without matching client-side evidence. Saved-credential
state and client logs may narrow the external policy boundary, but they never
authorize Type-2, TLS, certificate, target-identity, Admission, MCS, Share,
graphics, input or clipboard changes.
## R8 long pre-Type-3 stalls remain clipboard-free (2026-10-27)

Elapsed time while a delivered Direct NTLM Type 2 is waiting for Type 3 does
not create clipboard authority. The accepted connection remains
`PreAdmission` for its entire lifetime: service ticks, idle duration,
diagnostic timing, retained listener state, owner consent and retained Session
Password must not initialize CLIPRDR, a native clipboard owner, X11 CLIPBOARD
selection/INCR state or admission/session clipboard generations.

Peer EOF at that boundary retires only the accepted connection. An immediate
same-listener retry is a fresh accepted-client lifetime and cannot inherit an
R8/R3 route, pending transfer, X11 selection/INCR state or clipboard
generation. Prove this without adding production clipboard observability: the
production-backed lifecycle may hold the live peer for a bounded interval,
while the existing `PreAdmission` source contract keeps native/R8
construction unreachable and the independent X11 restart regression fences
stale INCR/generation state. Production clipboard activation remains false.

## Agent 4 pre-Type-3 elapsed time cannot create graphics authority (2026-10-27)

Owner physical evidence on assignment parent `985709b9f8b4c23c32da7297cb088b1ace2920fb` remains
PreAdmission for approximately 7.6 seconds after the production Type 2 is fully
committed, then ends in peer EOF without Type 3. The measured
`type2-creation-to-delivery-us=23619` and
`preauth-peer-eof-elapsed-us=7586602` are diagnostics only. Elapsed time,
TLS readiness and a delivered challenge never create native or graphics
authority.

While Type 3, pubKeyAuth, authInfo, `CredentialsVerified`, native Admission,
MCS and Share are absent, the serialized HostControl path must not construct
the X11/native desktop owner or enter its post-Share service loop. Consequently
it must not create or advance framebuffer, surface-remap, frame-scheduler,
ClearCodec, AVC/x264 or FRAME_ACK state. Keep the existing production
`fixed-name / RDP-SERVER` authentication behavior unchanged; this P2 rule is
an assurance boundary, not a compatibility workaround.

Do not add production observability just to prove hidden graphics state is
absent. Runtime status may continue exposing the existing bounded first-live
frame trace; source-contract tests pin the otherwise hidden surface/scheduler/
AVC/ACK entry points behind GraphicsReady.

## Agent 1 explicit server TLS-version profiles remain test-only (2026-10-27)

Exact-SHA hosted evidence at `94c4fdab233a59417f1d0f3eaad053e21e2e49ad`
already proves Microsoft full CREDSSP can reach Type 3 over TLS 1.3 /
`TLS_AES_256_GCM_SHA384` with the existing modern
`SCH_CREDENTIALS` system-default client profile. The explicit Agent-1 matrix
therefore does not create a new TLS owner or imply that TLS 1.3 is still the
leading physical-failure hypothesis. It adds an independent **server-policy**
control around the same production TLS/CredSSP path: system/default,
TLS-1.2-only and TLS-1.3-only.

Version restriction belongs only to the test-created per-connection `SSL *`
after `RuntimeServerTlsContext::createServerTls()`. Keep the production
generated exact-IP certificate, production TSRequest reader/writer, production
standalone NTLM/CredSSP acceptor and production context maximum unchanged.
System/default and TLS-1.2-only retain the legacy `SCHANNEL_CRED` client
control; TLS-1.3-only reuses the existing modern
`SCH_CREDENTIALS` system-default client profile.

A TLS-1.3-only `ORACLE_LIMITATION` is valid only before TLS establishment
and before any TSRequest/NTLM wire state, for a typed Microsoft credential
rejection or typed TLS negotiation failure. No-progress/round-limit remains
FAIL, and any failure after TLS 1.3 establishes remains FAIL. Pair any
limitation with the independent production-context TLS-1.3 CTest. Never cap
production at TLS 1.2, alter certificate CN/SAN or mutate Type-2 identity to
make a test profile green.

## R10 post-Type-2 timeline diagnostics are monotonic and non-authorizing (2026-10-27)

The exact accepted Linux runtime connection owns one `std::chrono::steady_clock`
pre-auth origin. For Direct NTLM, R10 latches the Type-2 creation observation
only when the existing R2 CredSSP owner returns the newly created challenge as
`NegoReplyQueued`; it latches delivery only when the existing R1 TLS writer
reports complete accepted plaintext and releases that reply. The
creation-to-delivery age is recorded once in microseconds and never recomputed
from status polling.

At that exact delivery boundary, R10 snapshots the read-only cumulative native
receive-byte count exposed by the sole R1 socket/BIO owner. The existing
CredSSP reader may later compare that monotonically increasing count with the
snapshot to latch the first post-Type-2 client TLS-byte age once. Do not peek
the socket, add another recv/BIO/TLS reader, parse TLS records, or retain packet
contents. The same existing TSRequest reader supplies its already-bounded
decrypted plaintext byte count and increments a complete-TSRequest scalar only
when one whole DER frame completes. These observations are diagnostic evidence
only; raw TLS activity alone does not imply a complete CredSSP request.

On terminal R1 `PeerEof` during pre-auth, the same connection latches both
total pre-auth elapsed time and, when Type 2 was delivered, Type-2-delivery to
peer-EOF elapsed time exactly once. Missing observations and a valid
sub-microsecond zero are distinguished by explicit availability flags. The
event-loop owner is serialized; do not add atomics, wall-clock timestamps, a
second timer owner or a parallel authentication state machine. Bounded counters
must saturate rather than wrap.

Fail-only output may print only the bounded scalar durations, availability,
post-Type-2 plaintext-byte count and complete-TSRequest count. Never log TLS
record contents, TSRequest bytes, challenge bytes, passwords, Type-3 response
material, session keys or delegated data. A peer EOF after delivered Type 2
remains `AuthenticationIncompletePeerClosed`, never wrong-password or native
Admission failure. Every immediate retry starts a fresh connection-local
timeline while retaining only the independently owned listener, target tuple,
owner grant and Session Password. Production remains `fixed-name / RDP-SERVER`;
these diagnostics cannot authorize a TLS, certificate, TargetName, TargetInfo,
MsvAvTargetName or credential-policy change.

## Test-only Microsoft NTLM response-bit differentials preserve the exact challenge payload (2026-10-27)

When a native Microsoft SSPI oracle isolates one CHALLENGE_MESSAGE capability
bit, derive the candidate from the exact production Type 2 for that same
Microsoft-generated Type 1. Never rewrite the client's Type 1, and never turn a
diagnostic variant into a production profile. For the OEM differential, the
candidate may clear only `NTLM_NEGOTIATE_OEM`; all bytes outside
NegotiateFlags, including ServerChallenge, zero/omitted VERSION, TargetName,
TargetInfo and MsvAvTimestamp, remain byte-identical to production. Validate
both messages through the existing production Type-2 validator before giving
the candidate to SSPI.

Timestamp-age diagnostics are non-authorizing and non-secret. Capture a
`steady_clock` creation point when the FILETIME timestamp is created and
report only elapsed milliseconds immediately before Type-2 delivery. Never log
the FILETIME value, server challenge, NTLM response, password, session key or
delegated credential. Microsoft Type-3 emission from a test-only variant is an
interop differential only; it cannot authorize a production flag, identity,
Admission, MCS, Share, graphics, input or clipboard change.

## R7 Advanced Type-1 client profile is structural only (2026-10-27)

R7 may render the already-redacted R10 NTLM Type-1 VERSION observation in
Advanced diagnostics as a client-profile fact. It must consume
`RuntimeAcceptedClientNtlmTypeOneDiagnostics` through the existing HostControl
snapshot and must not parse NTLM, retain token bytes or add a second
authentication cache. VERSION is descriptive interoperability metadata, not a
credential, client identity, authentication result or native-admission signal.

Keep opaque negotiate flags and domain/workstation details out of the owner GUI
unless a later product need makes them both understandable and necessary; never
reconstruct omitted fields from logs or constants. Missing Type-1/VERSION
observations stay missing. This presentation cannot change Type-2 flags,
TargetName, TargetInfo, MsvAvTargetName, certificate identity, target-profile
selection or any downstream authority. Main and Advanced authentication wording
remain independently owned by the existing typed failure boundary.

## Agent 6 Microsoft CredSSP modern-Schannel TLS 1.3 evidence is test-only (2026-10-27)

Exact-SHA hosted Windows evidence at `94c4fdab233a59417f1d0f3eaad053e21e2e49ad` (workflow
`40505738277`, Windows protocol job `122194521687`) demonstrates that
Microsoft CREDSSP accepts a `SCH_CREDENTIALS` object supplied through the
opaque `CREDSSP_CRED::pSchannelCred` field in this harness. The mandatory
legacy `SCHANNEL_CRED` control negotiated TLS 1.2 /
`ECDHE-RSA-AES256-GCM-SHA384` and reached the next client TSRequest with
NTLM Type 3. The modern system-default profile negotiated TLS 1.3 /
`TLS_AES_256_GCM_SHA384`, consumed the production Type 2 and independently
reached the same Type-3 boundary.

Keep the modern profile test-only: `SCH_CREDENTIALS_VERSION`, the same manual
server-certificate validation / no-default-client-certificate / strong-crypto
flags, and zero `TLS_PARAMETERS` entries so Schannel uses system defaults.
The result largely rules out TLS 1.3 *by itself* as the physical Windows
App/macOS peer-EOF cause. It does not prove that Windows App uses this exact
provider/configuration path and does not authorize a production TLS cap,
certificate/TargetName/TargetInfo/MsvAvTargetName change, native Admission,
MCS, graphics or clipboard change.

## R10 retained physical-client environment diagnostics (2026-10-26)

R10 consumes the existing R1 established-TLS observer and R2 Type-1 parser; it
must not create a second TLS, NTLM or CredSSP state machine. The retained
accepted-client fail-only snapshot may carry only bounded, non-secret facts:
negotiated TLS version, selected cipher protocol identifier plus bounded cipher
name, SNI class, NTLM Type-1 VERSION presence and major/minor/build/revision,
and the current generated-certificate profile with its exact live listener
generation. Never retain the SNI hostname, NTLM domain/workstation contents,
tokens, challenge/response material, passwords, keys or delegated data.

R2 may reset its live CredSSP mechanism on terminal peer closure. Preserve only
the already-redacted Type-1 structural parser result immediately before that
reset, beside the existing cached negotiation-envelope and Type-2 shape
observations. The cache is connection-local, is never reparsed, and cannot be
consulted for authentication, Admission, MCS, Share, graphics, input or
clipboard authority.

The existing R10 target tuple remains independently authoritative: numeric
endpoint, TERMSRV service class, IP target class, `fixed-name / RDP-SERVER`,
and Start/listener generation. TLS/SNI/VERSION/certificate diagnostics must not
activate endpoint-bound identity or change Type-2 flags, TargetName, TargetInfo
or MsvAvTargetName. The generated certificate profile remains the existing
self-signed exact-IP-SAN profile; its diagnostic generation is obtained from
the same live TLS-context/listener binding and is zero when that binding is not
current.

## Agent 9 physical-client candidate observations remain non-authorizing (2026-10-27)

Native certificate-policy qualification must consume the production-generated leaf or an explicitly test-only comparison profile and must never install, delete or persist trust in a Keychain or user/machine certificate store. macOS custom anchors remain scoped to the individual `SecTrust`; Windows comparison trust remains confined to the existing exclusive in-memory store/chain engine. Endpoint policy, purpose, time and trust observations grant no CredSSP, native Admission, MCS, Share, graphics, input or clipboard authority.

Type-1 comparability is structural evidence only. Reuse the bounded production parser for byte count, negotiate flags, VERSION and supplied-field metadata, and pair the measured physical profile with Agent 2's native Microsoft OEM-omission result. Never log domain/workstation contents, credentials, challenge/response material, session keys or delegated data. A Microsoft SSPI PASS for an OEM-only Type-2 delta rules out that isolated response-bit difference; it does not make the whole hosted Type-1 profile equal to the physical profile or authorize a production Type-2 mutation.

Reuse the established Linux TLS diagnostic owner for physical evidence and Agent 6's existing full-CREDSSP oracle for the external TLS-version comparison. A physical TLS 1.3 versus hosted TLS 1.2 difference is evidence, not permission to change production TLS. If Microsoft full CredSSP reaches Type 3 over TLS 1.3, keep production TLS unchanged and do not run a TLS-1.2 A/B merely to force a match. If TLS 1.3 remains unqualified or fails before Type 3, a TLS-1.2-only physical A/B may be selected only by the owner-candidate evidence gate as a one-property, standards-compliant, reversible diagnostic. Never expose that experiment as a permanent user setting, silently cap production TLS, or treat it as product acceptance.

Do not add a parallel TLS owner or change production Type-2 TargetName, TargetInfo, MsvAvTargetName, target-profile selection, certificate identity, native Admission, MCS, graphics or clipboard to force a hosted/physical match.

## R7 Advanced TLS/environment presentation is evidence-only (2026-10-26)

R7 may display negotiated TLS version/cipher, SHA-256 certificate fingerprint,
selected endpoint and a certificate-profile summary only from existing runtime
owners. Reuse R1's bounded established-SSL metadata; do not inspect TLS records,
certificate extensions, TargetName/TargetInfo or authentication tokens in Qt,
and do not add a second TLS/certificate parser or cache.

R10 may classify its normal automatically generated numeric-LAN certificate as
`Self-signed, exact-IP SAN` from the provisioning path it owns. Expert or
otherwise unclassified identities remain profile-unavailable rather than being
guessed from certificate text. Fingerprint/profile/endpoint/version/cipher are
descriptive facts: none reveal the client's trust decision, prove certificate
or target rejection, grant authentication/native authority or justify a bypass
control. Native certificate-policy oracle results remain test evidence until a
typed runtime/client boundary proves relevance.

Keep Main authentication wording at
`Remote client authentication did not complete.` for the proven
Type-2-delivered/pre-Type-3 peer close. Advanced may retain
`Client disconnected after authentication challenge.`. The new environment
facts must not be rewritten as wrong-password, target-identity-rejection,
certificate-rejection or local-desktop-authorization claims without matching
typed authority.

## Agent 5/6 certificate-policy and hosted-client observations are non-authorizing (2026-10-26)

Native certificate-policy comparisons belong to test code. The current profile
must obtain its leaf from `RuntimeServerTlsContext::fromGeneratedIpAddress`;
an endpoint-CN comparison certificate may exist only in test fixtures. Neither
result by itself authorizes a production Common Name, SAN, TLS identity,
Type-2 TargetName/TargetInfo/MsvAvTargetName or target-profile change.

On macOS, scope custom anchors to the individual `SecTrust`, exclude built-in
anchors for the oracle and disable network fetching. On Windows, use a
nondefault chain engine with an exclusive in-memory trusted-people store and
disable network/AIA retrieval. Never modify a Keychain, user/machine
certificate store or system trust policy. Report trust separately from endpoint
name/policy; on Windows also keep purpose and time/chain failures distinct.

The existing production Type-1 observer remains the single parser for hosted
CREDSSP diagnostics. Test output may additionally identify the non-secret raw
token class/message type, compare total Type-1 bytes with the physical trace,
and report negotiated TLS version/cipher, target string and generated
certificate profile. Do not log domain/workstation contents or any credential,
challenge-response, session-key or delegated data.

Pre-Type-3 Linux native dormancy is a construction-boundary invariant as well
as a status invariant. The production-backed two-peer Type-2/EOF test must
remain without native/graphics/framebuffer readiness, and source checks must
keep X11 capture, XTEST/input and capture-generation creation behind the
existing `GraphicsReady` native-owner gate. Do not add a pre-admission native
probe merely to prove absence.

## Physical TLS diagnostics are bounded, public and non-authorizing (2026-10-26)

Capture negotiated TLS presentation metadata only from the already-established R1 `SSL*`, never from a parallel TLS owner. Cipher/CN text is fixed-capacity; certificate CN is logged only when printable ASCII and otherwise reports `redacted`. Client SNI is reduced to presence plus IP/DNS/none class rather than retaining the name. IP/DNS SAN observations, certificate fingerprint and exact-endpoint self-check are diagnostics only and cannot create CredSSP, native Admission, MCS, Share, graphics, input or clipboard authority.

Generated-certificate identity experiments remain test-only. Production keeps the generic `RDP Server` CN and exact numeric `iPAddress` SAN until external client/policy evidence selects a different profile. A test may vary the CN while preserving the same IP SAN, but must not expose that choice through runtime configuration, add a textual-IP `dNSName` SAN, weaken certificate validation or cap production at TLS 1.2 merely to match one oracle.

## R2 Type-1 client profile observation is structural only (2026-10-26)

Parse each accepted NTLM NEGOTIATE_MESSAGE once through the production bounded
Type-1 parser and retain only non-secret structure needed for interoperability:
NegotiateFlags, VERSION presence and major/minor/build/revision, the OEM domain
and workstation supplied bits, and their security-buffer byte counts. Never
retain or log domain/workstation payload bytes. The same observation may be
projected into fail-only physical diagnostics and Windows SSPI qualification,
but it is evidence only and grants no authentication, native or session
authority.

MS-NLMP VERSION is debugging metadata and does not affect normal NTLM message
processing. A client offering VERSION is therefore not a reason to set VERSION
in the server Type 2. Keep the fixed-name `RDP-SERVER` Type-2 profile and its
TargetName/TargetInfo/MsvAvTargetName behavior unchanged unless independent
Microsoft/client evidence selects a wire change. Preserve the exact received
Type 1 and emitted Type 2 byte sequences for later Type-3 MIC/NTLMv2
verification; structural observation must never normalize that transcript.

## Pre-Type-3 retry cannot create a clipboard lifetime (2026-10-26)

A Direct NTLM connection with Type 2 fully delivered but no Type 3 remains
`PreAdmission`. Peer EOF at that boundary retires only the accepted
connection. A same-listener retry must start with no CLIPRDR route/state, no
native clipboard owner, no X11 CLIPBOARD selection ownership, no pending or
INCR transfer, and no admission/session clipboard generation inherited from
the retired peer.

Do not add production clipboard observability solely to prove this absence.
Keep native/R8 construction exclusive to the existing post-admission
`GraphicsReady` path. The production-backed Type-2/EOF lifecycle proves both
peers remain pre-MCS/pre-Share with clipboard unavailable and no native desktop;
the source contract proves `PreAdmission` cannot call clipboard
initialization/service/dispatch/write paths. Existing owner retirement must
continue to disconnect X11 before bridge retirement, clear pending/INCR and
selection state, zero clipboard generations, and reject stale route receipts.

## Pre-Type-3 authentication cannot initialize graphics state (2026-10-26)

A connection waiting for Direct NTLM Type 3 remains `PreAdmission`. The
pre-admission control-flow region must not start or advance the Graphics DVC,
construct the native graphics owner, reconfigure a surface, preflight/reserve
frame credit, prepare ClearCodec/AVC state, dispatch post-Share graphics/ACK
traffic, borrow a framebuffer or publish a frame. Peer EOF at that boundary
must retire only the accepted connection and leave all of those graphics
owners/states absent.

Prove the boundary without adding production diagnostic state merely for a
test. Pair the existing production-backed Type-2/EOF status assertions
(framebuffer/ClearCodec/write/ACK observations remain zero) with a source
contract that forbids the hidden state-transition calls from the isolated
`AcceptedClientPhase::PreAdmission` branch. Surface, codec and frame-credit
state may become reachable only through the already ordered post-admission
MCS/Share/GraphicsReady path.

## R9 CredSSP harness-integrity seam remains test-only (2026-10-26)

Keep the R1 memory-BIO pump as the single round-progression implementation and
preserve Agent 6's per-call evidence fields. Harness-integrity fixtures may
parameterize that pump with scripted test providers, but must not fork its
scheduling rules or reproduce production TLS/DER/NTLM encoders. The Microsoft
client keeps one bounded contiguous server-input owner: append within the
existing cap, retain the complete input on `SEC_E_INCOMPLETE_MESSAGE`, retain
only trailing `SECBUFFER_EXTRA` bytes after a consuming call, and clear
consumed input otherwise.

The scripted provider seam is qualification only. It can expose bounded
statuses, byte counts and state transitions needed to prove zero-output
continuation, local/peer pump sequencing and coalesced buffered work, but it
cannot mint an SSPI identity, authentication result, native Admission, MCS,
Share, graphics, input or clipboard authority. Production Type-2/TLS/SPNEGO
behavior remains outside this seam.

## R1 full-CredSSP memory-BIO tests mirror production TLS event semantics (2026-10-26)

The Windows Microsoft `CREDSSP` oracle is test transport, not a second R1
state machine. Feed every complete SSPI output token into the server memory BIO
without assuming one TLS record, and drain all pending server BIO bytes without
assuming one record or one response per provider call. Perform at most one
`SSL_do_handshake`, bounded TLS application read, or bounded TLS application
write per pump iteration, preserving WANT_READ/WANT_WRITE as continuation
states exactly as the production R1 owner does.

TLS handshake completion is not a buffer boundary. A call that changes the SSL
state to Ready may leave encrypted client application records in the input BIO;
the existing CredSSP reader may consume them immediately. Likewise TLS 1.3 may
leave post-handshake server output in the write BIO. Track both BIO pending
counts and `SSL_pending()`; do not discard, reorder or fabricate bytes.
Production permits TLS 1.2 and leaves the maximum at the provider default, so
the test pump must be version-agnostic and report the actually negotiated TLS
version rather than special-case TLS 1.2 or TLS 1.3.

Microsoft SSPI continuation is also not a wire-output guarantee. Preserve
`SECBUFFER_EXTRA` for the next TOKEN+EMPTY call, retain the complete input on
`SEC_E_INCOMPLETE_MESSAGE`, and allow an empty-output
`SEC_I_CONTINUE_NEEDED` to make a bounded subsequent call only when the SSPI
owner has retained input or explicitly exposed a no-wire continuation. A round
is deadlocked only when wire movement, TLS/application buffered state, server
frame progress and SSPI state all make no progress. None of these test-only
observations grants authentication, native Admission, MCS, Share, graphics,
input or clipboard authority.

## R10 shared product target-tuple construction remains non-authorizing (2026-10-26)

Use `prepareRuntimeConnectionTargetIdentity()` as the single portable constructor
for the product's pre-commit numeric-IP / `TERMSRV` target tuple. Production and
test oracles may supply the deliberately selected profile and protocol identity,
but the helper itself grants no authority and deliberately leaves
`startGeneration == 0`. The real R10 Start transaction remains responsible for
opening the selected endpoint, verifying that the TLS identity is bound to the
same listener generation, rechecking owner consent/policy, and only then
committing that exact generation into the tuple.

`runtimeConnectionTargetServicePrincipal()` is a non-secret rendering helper for
tests and diagnostics that need the service target represented by the tuple. It
may produce `TERMSRV/RDP-SERVER` for the current fixed-name profile or an
endpoint-form principal for a test-only endpoint-bound tuple. It does not select
a profile, prove Microsoft acceptance, or authorize a production identity
change. Current standalone production remains `fixed-name / RDP-SERVER` until
the full Microsoft CREDSSP control reaches Type 3 and the subsequent IP-target
matrix supplies typed evidence.

## CredSSP target-principal identity experiments are test-only (2026-10-25)

The demonstrated physical boundary is a completely committed production Type 2
followed by Await-Type-3 and peer EOF, while Microsoft native NTLM SSPI already
accepts that exact Type 2. Do not change production Type-2 flags, TargetName,
TargetInfo, TLS, SPNEGO or CredSSP framing without full-context Microsoft
CredSSP evidence.

TargetName and MsvAvTargetName are separate diagnostic wire properties for this
investigation. The first experiment changes only the CHALLENGE_MESSAGE
TargetName to the endpoint identity. The second leaves TargetName untouched and
adds only MsvAvTargetName (AV ID 9) with the endpoint service principal. The
third combines those two deliberate changes. Each candidate is rebuilt from the
exact production challenge, remains bounded, and must pass the production
challenge validator before SSPI consumes it.

These variants are internal test diagnostics only. They never become runtime
switches, never make a failing production oracle green, never weaken server
authentication/security requirements, and never authorize native Admission,
MCS, Share, graphics, input or clipboard.

## Start-scoped connection target/service identity ownership (2026-10-25)

R10 owns one non-secret connection target identity for each successful Start:
the freshly selected numeric endpoint, service class `TERMSRV`, an optional
protocol/server identity, a typed service-identity profile, and the exact
listener/Start generation. GUI text is never authority, and R2 native admission
must not derive or reconstruct this tuple from globals.

Standalone authentication consumes the R10-owned protocol/server identity only
after the tuple matches the active listener generation. Current production
remains deliberately `fixed-name`: the protocol identity is still the exact
existing `RDP-SERVER` value. The `endpoint-bound` profile is vocabulary and
ownership plumbing only; do not select it or change Type-2 bytes until a full
Microsoft CredSSP IP-target oracle proves the fixed profile fails and identifies
a passing replacement.

Build the target tuple before listener publication, then commit its generation
only from the verified listener that also binds the selected numeric endpoint
and TLS identity. Reconfiguration and Stop retire the target identity. Retiring
one failed/interrupted peer does not: the listener, target identity, current
owner consent and configured memory-only Session Password remain available for
the immediate next attempt while those host authorities are still current.

Fail-only diagnostics may expose only safe structural fields: target class
(`ip`/`dns`), service class, service-identity profile, Start generation and
the existing authentication progress. Never add username/password, NTLM
challenge/response, keys, delegated credentials or native account/session
identifiers to this projection.

## Pre-Type-3 peer close never creates MCS authority (2026-10-25)

A Direct NTLM connection that has fully committed production Type 2 through TLS
and is waiting for Type 3 remains pre-admission. Peer EOF at that point must
retain `protocolStage=PreAdmission`, no native-admission failure reason, no
MCS session advancement and no Share activation. Closing the transport may
retire the connection-local protocol owner; it must never reinterpret the
retained snapshot as having reached Admission or MCS.

The diagnostic boundary for the next successful physical progression is narrow:
after CredSSP reports `CredentialsVerified`, a native Admission rejection is
reported as `admission`; successful Admission is observable as
`native-admission-verified`; only acceptance of a real client MCS
Connect-Initial is observable as `mcs-connect-initial-received`. These are
diagnostic observations only and grant no authority. Do not add or advance
Connect-Response, Share, RDPGFX, graphics, input or clipboard behavior merely
to make hosted diagnostics exercise later stages.

Microsoft SSPI acceptance of the unmodified production Type 2 plus the
independent outer TSRequest DER oracle rule out random Type-2-format churn as
an R3 response. A physical target-principal/identity mismatch hypothesis belongs
to the CredSSP/security boundary until a real Type 3 arrives.

## R10 peer interruption is not authentication rejection (2026-10-25)

A peer-driven close after a completely delivered Direct NTLM Type 2 and before
Type 3 is an incomplete authentication exchange, not a rejected credential,
failed NTLM proof or native Admission denial. R10 may project
`AuthenticationIncompletePeerClosed` only from the existing authoritative
connection snapshot when all of these are true: DirectNtlm is selected, Type 2
has the exact delivered receipt, the retained stage is `NtlmChallenge`,
protocol is `PreAdmission`, admission reason is `None`, and R1 reports a
peer-driven EOF/reset/TLS close. Local cancellation, timeout, TLS/protocol
failure, malformed Type 3 and post-CredentialsVerified Admission denial are not
eligible for this reclassification. The derived host error is diagnostic only
and grants no retry, identity, consent, native or protocol authority.

Do not add a second authentication state machine to spell every human-readable
phase. The exact runtime progression is the composition of the existing
single-owner facts: CredSSP awaiting-token before the first negotiation token;
DirectNtlm plus the Type-2 queued receipt; `NtlmChallenge` plus delivered
receipt while awaiting Type 3; `NtlmAuthenticate` once Type 3 is observed;
`CredSspBinding` while the combined Type-3/pubKeyAuth result is verified and
the server binding reply is pending; `CredentialDelegation` after that reply
is delivered while authInfo is awaited; `Authenticated` only after exact
credentials verification; and the independent protocol stage for native
Admission/post-admission. MS-CSSP permits Type 3 and pubKeyAuth in one final
TSRequest, so do not fabricate a transient authority boundary that the owning
CredSSP implementation cannot independently observe.

Retiring only the failed/interrupted accepted connection must leave a valid
listener, current owner-sharing grant and configured memory-only Session
Password intact. Ordinary Stop still revokes the owner grant and listener/native
connection state while retaining that credential generation; the next Start
requires fresh local sharing authorization and preserves the existing same-port
restart contract.

## R1 committed Type-2 pre-Type-3 transport ownership (2026-10-25)

For Direct NTLM, keep one monotonic diagnostic progression on the existing
R1/R2 connection owner: a valid Type 1 is received, the canonical Type-2
TSRequest is queued, the exact R1 TLS application writer commits every Type-2
plaintext byte and releases the reply, the connection awaits Type 3, and then
either Type 3 is observed or the transport terminates. These are diagnostic
milestones only; they do not form another authentication state machine or
grant native/session authority.

A queued Type 2 is not sufficient terminal evidence. Project
`peer-eof-before-type3`, `peer-reset-before-type3`,
`tls-close-notify-before-type3`, `tls-alert-before-type3` or
`local-close-before-type3` only after the complete Type-2 TLS write receipt
has been committed. Keep raw TCP FIN/EOF, TCP reset, orderly TLS
`close_notify`, fatal peer TLS alert and local owner close distinct wherever
R1 can observe them. A normal pre-auth deadline remains the accepted-client
deadline established at accept; Type-2 completion must not arm a shorter
failure timer.

Deadline expiry must first set R1's `Timeout` termination before aggregate
revocation. Retiring a peer before Type 3 remains accepted-connection scoped:
when listener, local owner grant and generation-fenced Session Password are
still current, they survive that peer. This transport work must not change TLS
certificate identity, NTLM Type-2 wire shape, native admission, MCS, graphics
or clipboard.

## R3 pre-Type-3 diagnostics expose current R3 dormancy (2026-10-25)

The last-positive protocol diagnostic and the current R3 lifecycle observation
are distinct facts. Keep `protocolStage` as historical fail-only evidence, but
project the current connection-owned R3 state separately: `mcsSessionAdvanced`
is false while `McsSessionPhase` is `AwaitVerifiedR2Admission` and after it
is terminally `Closed`; `shareActivated` is true only when the existing R3
owner itself reports current Share activation. These scalars are descriptive
only and can never authorize MCS, Share, graphics, native input or clipboard.

A Direct NTLM peer that receives Type 2 and closes before Type 3 must therefore
remain `NtlmChallenge / PreAdmission`, with no current R3 session advancement,
no Share activation and no GraphicsReady/native state. Preserve the sole
promotion chain: Type 3 -> pubKeyAuth -> authInfo -> `CredentialsVerified` ->
successful native admission lease -> first R3/MCS transition. Do not repair a
pre-Type-3 interoperability failure in native admission, MCS, Share, RDPGFX or
clipboard code.

## NTLM Type-2 compatibility changes are evidence-gated (2026-10-25)

For connection-oriented CHALLENGE_MESSAGE negotiation, keep client capability
flags as an explicit intersection and server-only flags as an explicit,
documented addition. SIGN and SEAL offered by the client are returned;
ALWAYS_SIGN, 56 and 128 retain their MS-NLMP dependency rules; KEY_EXCH is
never introduced when the client did not offer it. TARGET_TYPE_SERVER and
TARGET_INFO may be server-selected only when their corresponding bounded fields
are actually emitted.

NEGOTIATE_VERSION is debugging-only protocol metadata. Do not enable or disable
it to imitate a Microsoft packet capture. A production change requires
Microsoft-native SSPI evidence. If enabled for interoperability, return it only
when offered and emit a bounded VERSION structure with portable semantics; do
not claim a particular Windows release merely to match an example.

Do not fabricate DNS computer/domain names, MsvAvFlags or MsvAvTargetName in
TargetInfo. Add an AV pair only when the protocol scenario requires it or a
Microsoft-native interoperability oracle proves it necessary. In particular,
MsvAvFlags can alter MIC semantics, and channel-binding/target-name checks
belong to the authenticated response/application binding boundary.

NTLM MIC verification is over the exact wire transcript. Retain the received
Type 1 and the single emitted Type 2 byte-for-byte and feed those exact buffers
to MIC verification. Never reconstruct, normalize or re-encode either message
for transcript verification.

## R2 Type-2 structural validation and safe diagnostics (2026-10-25)

R2 consumes the portable server-TargetName correction and independent test
oracle already on main, and adds a production CHALLENGE_MESSAGE validator that
runs before every encoded Type 2 is published. Validate NTLMSSP signature and
MessageType, TargetName/TargetInfo security-buffer ranges and nonoverlap,
UTF-16LE TargetName/text AV values, server/domain target consistency,
terminated TargetInfo AV framing, zero Reserved bytes, nonzero
ServerChallenge, Version shape when negotiated, and client-capability response
flags against the exact Type 1. Security-buffer MaximumLength is advisory on
receipt per MS-NLMP; the writer continues to emit MaximumLength equal to
Length.

When TARGET_TYPE_SERVER is selected, TargetName is non-empty and is the already
bounded portable computer identity. Never use the remote Username as
TargetName. The alternative no-target-type/no-request-target/empty-TargetName
shape may be structurally parsed for comparison, but it is not the standalone
production profile unless later Microsoft evidence requires a different
standards-compatible form.

Only non-secret structural challenge metadata may survive into fail-only
connection diagnostics: Type-1 flags, selected Type-2 flags, TargetName code
units, TargetInfo bytes, total Type-2 bytes, bounded AV IDs, and target/name
presence booleans. Never retain or print ServerChallenge bytes, NTLM responses,
MIC/session keys, passwords or password-derived material.

Owner evidence base `5a21694f8aaaf446d2b345c8fef89b94ac4542f3`
remains Linux full CTest 975/975 PASS followed by real Windows App peer EOF
after Type 2 with no Type 3. Preserve the current phase-owned pre-admission
classification and same-listener retry coverage. Do not modify native
admission, MCS, graphics or clipboard for this boundary.

## R9 independent Type-2 oracle and terminal authentication taxonomy (2026-10-25)

A production NTLM Type-2 encoder must not qualify itself solely through a byte
array derived from the same implementation assumptions. Keep an independent
test-only parser that validates CHALLENGE_MESSAGE signature/type, legal selected
flags, TargetName and TargetInfo security-buffer bounds, non-overlap,
non-empty valid UTF-16LE server TargetName, TargetInfo AV structure, and
TargetName/MsvAvNbComputerName consistency. Negative mutations must fail
without changing production parsing or authentication authority.

The existing connection-owned diagnostic scalars are sufficient to distinguish
the required phases without creating a second state machine:
CredSspDirectNtlm = ntlm-negotiate; NtlmChallenge + live transport =
awaiting-type3; NtlmChallenge + peer termination = peer-closed-after-type2;
NtlmAuthenticate = ntlm-authenticate; CredSspBinding = pubkeyAuth;
CredentialDelegation = authInfo; and only the genuine post-CredentialsVerified
native broker may report admission. Fail-only terminal logging must preserve
that exact redacted boundary; these names grant no authority.

## Portable NTLM Type-2 server TargetName is wire state (2026-10-25)

MS-NLMP CHALLENGE_MESSAGE naming is portable protocol state. When
`NTLMSSP_TARGET_TYPE_SERVER` is set, emit a non-empty server TargetName and
set `NTLMSSP_REQUEST_TARGET`; the normal standalone server identity is the
bounded UTF-16 value `RDP-SERVER`. Encode it directly as UTF-16LE from
`char16_t` code units. Do not use locale conversion, host-name lookup,
filesystem/environment names or the GUI's local Username suggestion to
manufacture this wire identity.

Keep the server TargetName and `MsvAvNbComputerName` on the same deliberately
selected portable computer identity. The normal standalone domain/computer
constants live in the portable security layer so Linux, macOS protocol tests
and future Windows hosting consume the same wire identity. A deliberate future
override must still pass the same non-empty, valid-UTF-16,
maximum-code-unit and total-message bounds before any output byte is mutated.

A peer EOF after a successfully written Type 2 but before Type 3 is an
authentication/negotiation boundary, not native Admission. Runtime/GUI
diagnostic corrections already on main preserve that distinction; this wire
correction must not reopen logind/native admission, MCS, graphics or clipboard.

## R7 pre-admission authentication presentation follows typed evidence (2026-10-25)

R7 must not classify an `AuthenticationRejected` peer as local-desktop
authorization failure merely because a retained authentication-stage scalar
says `Admission`. Product-visible local-desktop authorization failure requires
all three facts: CredSSP credentials were verified, the retained stage is
Admission, and the typed native-admission reason is non-`None`.

A Direct NTLM peer that terminates with `PeerEof` after the server challenge
but before Type 3 remains authentication-level. The current runtime snapshot is
`NtlmChallenge + CredSSP Closed + standalone failure NtlmNegotiation +
admission None + PeerEof`; R7 may also accept the immediately preceding
standalone-failure-`None` snapshot only for safe presentation compatibility.
Main shows `Remote client authentication did not complete.`. Advanced
Diagnostics may state `Client disconnected after authentication challenge.`
only when the retained R1 `directNtlmTypeTwoDelivered` receipt is true. A
queued-only or legacy snapshot uses a less-specific redacted authentication
diagnostic; never infer delivery from `NtlmChallenge` alone. Do not infer a
target-identity mismatch from the destination address, TargetName or other
presentation data. A future `Remote target identity was not accepted.`
diagnostic requires an explicit typed runtime diagnosis.

R7 must also fail safely for an older contradictory retained tuple such as
`Admission + CredSSP Failed + standalone failure Admission + admission None +
PeerEof`: it remains authentication-level and must not produce
`Could not authorize access to the local desktop.`. Use a less-specific
redacted authentication diagnostic for that legacy tuple rather than inventing
native authority or an exact wire milestone.

This presentation rule changes no listener, credential, native-admission, MCS,
graphics or clipboard authority. Main never exposes NTLM flags, tokens, parser
strings or internal protocol taxonomy.

## Direct NTLM Type-2 delivery and pre-Type-3 close evidence (2026-10-25)

A transport close after Direct NTLM Type 2 but before any Type 3 is observed is
not native Admission. If no more-specific parser failure exists, the current
CredSSP stage and authentication-progress owner classify the interrupted
authentication phase (`NtlmNegotiation` while awaiting Type 3). Preserve the
last positive boundary `NtlmChallenge`, protocol `PreAdmission`, admission
reason `None`, CredSSP close transition and R1's exact transport termination.

Keep queue ownership distinct from transport delivery. Report
`direct-ntlm-type2-queued` only after the canonical Type-2-bearing TSRequest is
owned by the existing CredSSP TLS writer. Report
`direct-ntlm-type2-delivered` only after the writer reaches `Complete` through
the exact R1 accepted-byte accounting and `releaseReply()` revalidates the same
transport generation, SSL identity and selected certificate. A queued reply is
never reported as delivered. Delivery is an R1 plaintext-write receipt, not
proof that the peer parsed or accepted Type 2.

For a Direct-NTLM connection with Type 2 queued/delivered and no Type 3, project
only bounded terminal categories when transport evidence supports them:
`peer-eof-before-type3`, `peer-reset-before-type3`,
`tls-alert-before-type3`, or `local-close-before-type3`. Keep the underlying R1
termination separately intact. R9's higher-level `awaiting-type3` /
`peer-closed-after-type2` names remain authentication-phase diagnostics; the
R1 subtype records the specific terminal transport fact. Neither grants
authority.

`AwaitBinding` still maps to `PubKeyAuth`; `ServerBindingReplyQueued` maps to
`AuthInfo`. Only completed credentials followed by the actual native-admission
call may produce Admission. The portable TargetName correction, independent R9
oracle and R2 production Type-2 validator/shape observation are separate
wire/security responsibilities and remain untouched by this R1 evidence rule.

## Local username suggestion is convenience, never authentication (2026-10-24)

The standalone Username field may default to a safely observed current local
interactive account name. That value is presentation convenience only: it does
not mint native admission, select an OS identity for a remote peer, or imply
that the remote credential is an OS-account credential. The field remains
editable; if a trustworthy interactive username is unavailable, use an empty
default rather than a guessed or system identity.

Read only the platform's current-account name boundary: the effective local
account on Linux, the console user on macOS, and the current interactive
process WTS session on Windows. Reject root/system/service-style identities.
Never read `/etc/shadow`, scrape credential stores, use PAM to recover
plaintext, cache a login password, or silently substitute OS authentication.

Session Password is independent application state. It and its confirmation
start empty and become populated only from explicit user input. A future
Existing OS Account mode remains a separate authenticated provider path.

## Native-admission reasons are diagnostics, never capabilities (2026-10-24)

After credentials are verified, preserve the first failed native-admission
predicate as a bounded non-secret enum. Evidence inspection may distinguish
account lookup/identity, console availability/activity/physicality, session
identity, seat/display, console-owner UID, freshness and policy. The admission
owner may additionally distinguish local owner consent, exact HYBRID/TLS
provenance, authenticated-proof continuity, request validity, session-change
monitor state, policy-generation replacement, native-proof completion and the
final CredSSP admission handoff.

Detailed classification must not widen authority. `CandidateOnly` remains
non-authorizing, broker denial remains terminal, and only a successfully minted
lease authorizes downstream work. Never bypass logind, trust process
`DISPLAY`, accept a mismatched UID, map a remote standalone username into a
Unix identity, or enable OS-GSS fallback to make an admission reason disappear.

Standalone application username and local native owner are independent facts.
The existing GUI local-account Username hint is presentation-only. Never
retrieve or auto-fill the OS account password; Session Password remains a
separate user-entered application credential.

## Start-versus-admission evidence is observable but never cached (2026-10-24)

The physical Microsoft-client boundary is native `stage=admission`; do not
reopen TLS/SPNEGO/NTLM without contradictory evidence. Start-time owner
consent and admission-time native authorization are intentionally fresh,
independent samples. When admission rejects an apparently unchanged desktop,
report the exact bounded structural mismatch rather than reusing the earlier
grant.

Linux fail-only diagnostics may expose logind/systemd availability, graphical
seat presence, active-session presence, session type/class/seat/display,
active/remote/lock state, process-owner UID equality, session-generation
stability and monitor state. They must not print account names, raw session
identifiers, credentials, token bytes, clipboard content or desktop data.

A newly created logind monitor establishes a pre-candidate baseline with its
published fd/events, zero-time poll and one flush of accumulated readiness.
Every wake after that baseline remains revocation authority. This baseline is
not an authorization cache and must not make a changed session acceptable.

The GUI may derive only the local Username convenience default from the OS.
Never retrieve or auto-fill an OS account password. Session Password remains
a separate user-entered application credential.

## Post-authentication diagnostics never manufacture protocol authority (2026-10-24)

The demonstrated physical Microsoft-client boundary is native admission:
TLS and Direct NTLM/CredSSP have progressed far enough for production to report
`stage=admission`, but no positive native admission lease exists. Keep a
separate bounded last-positive protocol diagnostic scalar. It remains
`PreAdmission` until the genuine native lease is issued, then may advance only
after existing production owners report successful Connect-Initial,
Connect-Response, ErectDomain, AttachUser, ChannelJoin/MCS establishment and
Share activation transitions. The diagnostic is read-only, contains no packet,
credential or native-identity material, and never authorizes protocol work.

Externally emitted diagnostics and CTest classification use durable functional
terms such as `transport`, `tls`, `admission`, `mcs`, `share`,
`graphics` and `clipboard`. Agent/road ownership names remain internal
coordination metadata and do not belong in new user-facing diagnostics or CTest
labels.

## Native-admission denial is accepted-peer scoped (2026-10-24)

Owner physical evidence on assignment baseline
`9fd1db518076713f30b41af2aff023308f95a925` reached established TLS,
selected Direct NTLM, accepted Type 1, sent Type 2 and progressed CredSSP
before production reported `stage=admission`. Treat native admission as the
first demonstrated failure boundary. Do not redesign the exact-IP certificate,
TLS handshake, SPNEGO/DirectNtlm envelope or NTLM Type 1/2/3 path without
newer evidence showing an earlier failure.

A native-admission denial is connection-scoped. Retire the accepted connection
and its children, but keep the still-current listener, local owner grant and
configured generation-fenced memory-only Session Password. A later peer must
be able to establish a fresh TLS/NTLM connection on the same listener without
toggling Sharing. The new peer receives fresh transport and NTLM state; nothing
from the denied peer is reused.

Transport termination remains independent diagnostic truth. Snapshot it before
owner cancellation. `PeerEof` remains `peer-eof`; it must never be rewritten
as `tls-failure` merely because the connection was later rejected at native
admission. Keep peer EOF/reset/alert, local TLS failure and owner cancellation
distinct.

CTest names, labels and user-visible test summaries use functional domains such
as `transport`, `tls`, `security`, `authentication`, `admission` and
`listener`. Internal road/agent ownership identifiers do not belong in those
visible taxonomies.

## POSIX LAN listener restart preserves exact-endpoint exclusivity (2026-10-24)

The opt-in LAN listener may set `SO_REUSEADDR` before a POSIX exact-address
bind so ordinary Stop -> Start can promptly reclaim the same configured port
after a process-owned accepted connection was actively closed and remains in
TCP `TIME_WAIT`. Do not use `SO_REUSEPORT` for this purpose.

This restart allowance must not weaken listener ownership: binding is still to
the exact validated private interface address, wildcard/public selection stays
denied, and a second concurrently live listener on the same exact address/port
must still fail as occupied. Keep a native regression that proves both the
server-active-close rebind and the simultaneous-live-listener denial.

## Direct NTLM envelope classification is parser-gated, not prefix-gated (2026-10-24)

For standalone CredSSP, never classify a peer token as `DirectNtlm` merely
because byte zero is `0x4e` or because an `NTLMSSP\0` prefix is present.
The first token selects `DirectNtlm` only after both the complete signature
and the existing Type-1 `parseNtlmNegotiateMessage()` succeed. Otherwise feed
the unchanged bytes to the strict SPNEGO initial-token parser. Once a valid
envelope is selected it is immutable for that accepted connection.

Do not create a second raw-NTLM parser or crypto path. Raw Type 1/2/3 must reuse
the same transcript buffers, challenge encoder, NTLMv2 proof verification, MIC,
exported session key and directional SIGN/SEAL context used by the SPNEGO NTLM
path. A diagnostic-only MessageType observation may inspect the exact NTLM
signature and four-byte MessageType after the envelope is already DirectNtlm,
but it must never make malformed bytes acceptable.

Keep one authoritative retained authentication-progress owner. R2 parser state
may expose bounded, non-secret facts to R10, but it must not introduce a
parallel lifecycle controller. Fail-only diagnostics may report envelope,
MessageType, token length and named stage; never log token contents or
credential/key material.

## R10 peer-failure and authentication-status ownership (2026-10-24)

Treat remote authentication failure as an accepted-connection terminal event,
not a service-credential or Sharing terminal event. If the listener and local
owner grant remain current, retire only the failed connection and its native/R3
children; never revoke the configured standalone credential generation, close
the listener or revoke owner consent because a peer sent a malformed/rejected
CredSSP/NTLM token.

Each accepted connection must construct a fresh CredSSP/NTLM owner and fresh
random NTLM challenge. NTLM transcript bytes, derived keys, RC4/sign/seal
sequence state and security context are connection-owned and must be cleansed
before socket/TLS destruction; they must never be cached in R10 service state
or reused by a reconnect. The service may borrow only the current
generation-fenced standalone credential owner.

Diagnostic state must preserve protocol truth without becoming authority. Cache
only bounded redacted scalars needed after mechanism cleanup: immutable
SPNEGO/DirectNtlm envelope, last reached authentication boundary and credential
generation. Keep transport termination separate. Never rewrite a DirectNtlm
failure as SPNEGO, and never retain/log raw tokens, hashes, session keys or
delegated credentials to improve presentation.

## Authentication failure presentation is product-safe (2026-10-24)

R7 must never project protocol parser strings or wire observations onto Main.
A remote authentication failure is presented there only as
`Remote client authentication failed.`. Advanced Diagnostics may classify the
failure from redacted R10 enums, for example
`Authentication: CredSSP — Direct NTLM — negotiation failed`.

Keep the diagnostic data model scalar and closed: negotiation envelope enum,
CredSSP transition enum and authentication failure-stage enum only. Do not pass
token bytes, NTLMSSP signatures, DER tags, token lengths, usernames, passwords,
hashes, keys or parser rejection strings into Qt.

Per-peer failure is not credential or listener lifetime authority. The accepted
connection may be revoked while the configured memory-only Session Password and
listener remain active. Only explicit Stop/revoke or an existing security-policy
terminal condition may widen teardown. R7 must not require password re-entry
after an ordinary failed client attempt.

R10 product state remains authoritative for lifecycle labels. In particular,
`CredentialsVerified` is an R2 milestone while product state may still be
`Authenticating`; R7 may show Connected only after R10 publishes Connected.

## R8 authentication-envelope changes must have zero clipboard authority (2026-10-24)

R2 authentication envelope selection is not R8 authority. A failed SPNEGO or
DirectNtlm attempt must terminate before any native clipboard owner is created,
before any CLIPRDR route/dispatch/write operation is reachable, and before any
R8 admission/session generation can become nonzero. Do not add clipboard cleanup
as a substitute for this ordering; the preferred invariant is that failed
authentication never constructs the R8 owner in the first place.

Successful authentication alone is also insufficient. Clipboard remains a child
of the separately admitted/authorized native desktop lifetime and the existing
R3 clipboard permission/channel gates. Keep
`kLinuxProductionClipboardActivationApproved = false` until the independent
R8 physical acceptance gate is satisfied. Authentication work must not flip the
gate, expose clipboard UI, enable OS/GSS fallback or translate a standalone
username into clipboard/native authority.

While R8 remains P2/BLOCKED, work is limited to stale-lifetime containment and
regression coverage. Preserve clipboard-first teardown, zero retired
admission/session generations, and reject late X11/INCR callbacks and R3/TLS
receipts from retired lifetimes.

## R1 established TLS provenance is envelope-independent (2026-10-24)

Once X.224 HYBRID has selected the accepted connection and TLS is established,
R2 negotiation must remain on that exact R1 transport. SPNEGO and DirectNtlm
share the same `OwnedPreauthTcpConnection`, the same established server
`SSL*`, and the same selected-certificate SHA-256 pin. A valid raw NTLM
Type-1 token changes only the R2 negotiation envelope; it must never create,
reattach, or replace TLS.

Bind every production TSRequest reader/writer to the tuple
`(R1 owner, transport generation, SSL identity, certificate fingerprint)`.
The accepted transport generation is nonzero and process-lifetime monotonic;
zero is invalid and exhaustion fails closed. Preserve the tuple across
`releaseFrame()` and `releaseReply()` so Type 1, Type 2, Type 3,
`pubKeyAuth`, and `authInfo` cannot cross a reconnect boundary. Owner
substitution, SSL substitution, certificate substitution, or same-address stale
owner reuse is terminal.

Established TLS application data is decisive R1 success evidence. Do not treat
a Microsoft client certificate-warning UI as the first failing boundary when
the same connection reaches CredSSP application data. Do not change generated
certificate shape, SAN policy, or fingerprint behavior without independent
evidence requiring such a change.

## R5 native authority is independent of the R2 authentication envelope (2026-10-24)

R5 must never branch on, store, or interpret CredSSP negotiation-envelope state.
Whether StandalonePassword reached R2 through SPNEGO-wrapped NTLM or
`DirectNtlm` is an R2 implementation detail. R5 consumes only the resulting
live admitted native-desktop capability.

Authentication failure of either envelope must terminate before any X11 owner
can be constructed. Successful credentials are still insufficient: R2 must
issue a fresh non-revoked admission lease from current owner/native evidence,
R3 must reach `GraphicsReady`, and only then may HostControl obtain the native
selection through `visitNativeDesktopSelection()` and construct the one X11
owner. Native construction and service code must contain no NTLM/SPNEGO
envelope knowledge.

Ordinary Stop continues to revoke the current owner grant and destroy the X11
aggregate while retaining only the permitted memory-only Session Password.
Every later Start requires fresh owner authorization/native evidence exactly as
before; authentication-envelope support must not weaken that lifecycle.

## CredSSP negotiation envelope is connection-scoped and immutable (2026-10-24)

MS-CSSP `TSRequest.negoTokens` can carry SPNEGO tokens or direct
Kerberos/NTLM messages. Do not infer SPNEGO solely from CredSSP. For the
standalone Session Password path, select exactly one negotiation envelope from
the first **valid** token: `Spnego` for a valid GSS/SPNEGO initial token or
`DirectNtlm` for a valid raw NTLMSSP Type-1 NEGOTIATE_MESSAGE. Preserve that
choice for the complete accepted connection; never trial-parse a later token
under the other envelope. Never select from host OS, client product, adapter
type or a rule such as "macOS Windows App uses direct NTLM."

Both envelopes must reuse the single existing NTLM transcript/security owner.
Direct NTLM is raw Type 1 -> raw Type 2 -> raw Type 3; do not add a second
NTLM parser, verifier, challenge generator or SIGN/SEAL context. SPNEGO keeps
its existing mechanism-list and mechListMIC rules. The final raw Type 3 carries
no fabricated SPNEGO completion wrapper and, per MS-CSSP, is accepted only in
the final TSRequest that also carries `pubKeyAuth`.

This compatibility path changes neither authentication authority nor native
desktop identity. Keep the selector and NTLM implementation in the portable
security target with no GSS link/runtime dependency. Keep OS/GSS fallback
disabled for StandalonePassword; never map the remote application username
into a host OS identity. After either
envelope verifies the same NTLM security context, continue through the existing
pubKeyAuth/TLS binding, authInfo and Session Password verification boundaries.

## R3 authority requires verified credentials and native admission (2026-10-24)

Treat established TLS as an R1 transport fact, never as R3 authority. A
connection may have an established HYBRID/TLS transport and a parser positioned
for later application data while R2 is still negotiating CredSSP. Do not infer
MCS ownership, diagnose an R3 failure, or advance a HostControl R3 phase from
TLS readiness, certificate continuity, `BindingVerified`, configured
credentials or candidate native-session evidence.

For the standalone Session Password path, the only promotion sequence is
`CredentialsVerified` -> successful `LinuxConsoleAdmissionBroker::issue()`
-> live admission lease -> first R3/MCS transition. The first-MCS path must keep
requiring and revalidating that exact lease. Direct-NTLM support in R2 must
converge on the same existing credential proof and native-admission authority;
it must not create a shortcut into R3, enable OS/GSS fallback or translate the
remote username into a host identity.

## Diagnostic projection must never become TLS authority (2026-10-24)

R1 diagnostic setup is descriptive only. A valid accepted TLS owner must not
require a prior logging/projection call in order to attach its SSL object.
Certificate continuity is enforced directly between the fresh accepted SSL leaf
and the exact service-owned TLS context. When an earlier public fingerprint
snapshot exists, it is an additional continuity cross-check, never the source
of transport authority. Keep endpoint-name/IP self-check logging independent
from handshake liveness.

## R5 fresh native authorization on every Start (2026-10-24)

Ordinary Stop may retain the generation-fenced memory-only standalone Session
Password, but it must retain no native desktop authority. Stop revokes the
current owner grant first, terminally retires the R5 X11 aggregate with
no-XTEST cleanup, destroys its input/capture/damage/framebuffer resources,
retires the accepted R3/R2/R1 owner and listener, and leaves no native
generation usable by a later Start.

The retained standalone credential is bound to the exact unlocked native
session fingerprint: session ID, owner UID, X11 DISPLAY and native session
generation. A lock/unknown state, local-user switch, DISPLAY replacement,
logout/session-generation replacement or unavailable/stale bound evidence is
credential-terminal. Ordinary Stop by itself is not: an unchanged unlocked
physical session may request a fresh owner grant and restart without Session
Password re-entry.

Every Start must re-read current native/logind/X11 evidence and rebuild the
standalone native admission policy from that observation. A prior grant A1
cannot authorize Start #2 after Stop; a new explicit local grant A2 is required.
Even after A2, native X11 ownership is created only for a later authenticated
client that has reached the existing GraphicsReady/R2 native-selection gate.

## Portable HostControl Stop versus terminal credential lifetime (2026-10-24)

Linux, macOS and future Windows HostControl implementations share one
credential-lifetime matrix through
`shouldRetireStandaloneApplicationCredential()`. Ordinary `Stop` is the only
retaining event: it revokes current-owner consent and retires accepted client,
native desktop/input, listener and endpoint-bound TLS state while preserving the
configured generation-fenced Session Password in secure process memory.
Lock/unknown state, logout, local-user switch, native-session replacement,
credential replacement, consent expiry/security loss, explicit Revoke, Quit and
object destruction are terminal and must retire the credential.

A later Start may reuse only that retained credential. It must obtain fresh
local-owner authorization, prepare fresh selection-bound TLS state and bind a
new listener generation. Retained credential possession is never permission,
listener authority or native desktop authority. Platform implementations must
use the shared matrix rather than inventing a Windows/macOS-specific Stop rule.

## R1 Microsoft-client TLS failure diagnostics (2026-10-24)

When a real client reaches X.224 Enhanced Security but TLS does not establish,
R1 is the first failing boundary. The sole preauth/TLS owner records one
non-secret handshake-step counter, immediate `SSL_get_error()`, numeric OpenSSL
top error/reason, configured certificate fingerprint, exact numeric-IP identity
self-check, selected-SSL certificate continuity and terminal transport class.
Keep peer EOF, peer reset, peer TLS alert, local TLS failure, timeout and owner
cancellation distinct; do not rewrite those transport facts as an R2/R3
authentication diagnosis. Never log passwords, NT hashes/responses, TLS key
material or CredSSP token bytes.

The generated endpoint certificate remains exact-IP SAN authority. Do not
change its subject for client compatibility without real-client evidence that
a standards-compliant IP-SAN client succeeds and the isolated Microsoft
variant changes the observed result.

## R2 retained Session Password and standalone SPNEGO structural diagnostics (2026-10-24)

Ordinary user-requested Stop is a nonterminal credential boundary. It revokes the
current owner View/Input grant, retires every accepted client/admission/native
desktop lifetime, closes the listener, retires generated/connection-bound TLS
state and deployment policy, and prevents all remote access. It may retain only
the existing generation-fenced memory-only standalone credential plus a bounded
non-secret native-session fingerprint. No prior owner grant, admission lease,
native owner, listener, TLS binding or R3 state may survive Stop.

The retained credential is session-fenced. Any observed lock/unknown lock state,
logout, local-user switch, native-session generation replacement, stale or
unavailable bound-session evidence is credential-terminal. The standalone
credential and its non-secret fingerprint are erased and unlock requires
Session Password re-entry. Password replacement, full `revokeSharing()`,
explicit Quit, native authorization loss and object/process destruction are also
terminal. Ordinary restart may reuse G1 only while the same unlocked native
session remains current, and it must obtain a fresh owner grant before Start.

The independent Session Password path must never authenticate through the
ExistingOsAccount/OS-GSS owner as fallback. `os-gss-fallback=disabled` is the
required product state.

For the first incoming standalone CredSSP nego token, fail-only diagnostics may
record only bounded structural metadata: TSRequest version/token count/token
length, top ASN.1 tag, GSS InitialContextToken presence, offered mechanism OIDs
and count, NTLM presence/index, optimistic token presence/length,
NegTokenInit/NegTokenInit2 field presence, reqFlags, negHints, mechListMIC and a
stable structural rejection reason. Never log raw SPNEGO or NTLM token bodies,
usernames/passwords, hashes, challenges/responses, MIC bytes, session keys or
authInfo. Unknown OIDs may be represented only by a bounded DER-OID prefix; this
diagnostic must never broaden authentication authority or ASN.1 acceptance.

## R10 explicit Stop credential policy and diagnostic preservation (2026-10-24)

Do not derive standalone credential lifetime from an owner-consent revocation
reason. Linux R10 teardown takes an explicit credential policy. Ordinary
`stopSharing()` is the sole keep-credentials caller; terminal loss,
`revokeSharing()` and destruction use the fail-closed default that clears the
credential generation, StandalonePassword mode and configured state.

A stopped configured standalone host may restart without password re-entry, but
never without fresh local-owner consent and fresh endpoint/TLS preparation.
R7's cleared-editor reuse remains valid only while R10 authoritatively reports
the production standalone credential configured; newly typed password text is
always replacement.

Preserve accepted-client diagnostic categories exactly. R10 may mirror bounded
R1/R2 enums, but must not collapse TLS failure, transport/protocol close,
standalone SPNEGO rejection, NTLM negotiation/credential rejection, MIC,
sign/seal, pubKeyAuth, authInfo or admission into one another. The generic
product `AuthenticationRejected` code is presentation summary only. Never
enable OS GSS fallback as a standalone Session Password workaround.

## R9 precise SPNEGO parser categories (2026-10-24)

At the parser's initial-token boundary, distinguish outer GSS/SPNEGO DER,
mechanism list, negotiation field, initial mechListMIC, and embedded NTLM
Type 1/challenge failures. Preserve only a small enum across terminal
mechanism cleanup, not a token or ASN.1 buffer. Map it to stable fail-only
runtime strings; do not change authentication acceptance or retry another
mechanism because of diagnostic classification. Tests must cover valid
NTLM-first and Microsoft-style Kerberos-first NegTokenInit2 forms and
negative malformed-envelope/mechanism inputs.

## R7 cleared Session Password fields are presentation, not credential state (2026-10-24)

After a successful production credential transfer, R7 clears Password and
Confirm but must not interpret those empty editors as an unconfigured
credential. When the standalone-password surface is selected,
`credentialsConfigured` from R10 is the reuse authority. Ordinary Sharing OFF
therefore returns to an editable Stopped UI that can Start again with the same
memory-only credential after fresh owner authorization.

Any new Password or Confirm input is replacement intent, not reuse. Require a
non-empty password and matching Confirm, and invoke the production replacement
only after explicit Sharing ON. Never cache or redisplay the transferred secret
in R7. The toggle remains a projection of authoritative listener/Stop state.

## R9 standalone SPNEGO diagnostics (2026-10-24)

In the independent Session Password authentication mode, propagate only
a bounded `StandaloneSpnegoStatus` from the mechanism through CredSSP
before the mechanism resets on failure. Redacted runtime diagnostics
may classify invalid state/token, mechanism-integrity mismatch, NTLM
credential rejection or bounded reply exhaustion. They must not log peer
token material, username, password, session key or hash, alter fallback
selection, or grant admission. The current invalid-token category can
cover both ASN.1 DER and embedded NTLM framing and is not yet a byte-level
root-cause diagnosis.

## Ordinary Stop versus terminal credential revoke (2026-10-24)

Linux HostControl ordinary Stop invalidates current-owner authorization first,
retires native input/desktop, accepted R3/R2/R1 connection, listener and
selection-scoped generated TLS identity, but retains the validated generation
in its sole memory-only `StandalonePasswordCredentialOwner`. Subsequent
Start must obtain fresh local owner consent; credential possession never grants
authority. Explicit/full revoke, credential replacement, native-session loss,
Quit and destruction securely retire the credential and generation. Do not
store the password in GUI fields, persistent storage or a second cache.

## R8 clipboard lifetime never follows retained credentials (2026-10-24)

Credential ownership and clipboard ownership have different lifetimes. Whether
ordinary Stop retains or retires the memory-only standalone credential, every
Stop/Revoke retires the current R8/native lifetime: cancel native paste/INCR,
retire the R8/R3 route and queued/accepted delivery-receipt identity, clear
write-pending state, zero R8 admission/session generations, retire R5, and
destroy the old native owner before a later Start constructs a replacement.

A retained credential generation is never permission to keep or revive a
clipboard owner. A later Start must obtain fresh owner/native/session authority
and create a fresh R8 owner. Stale X11 callbacks, native generations and old
R1/R2/R3 delivery receipts remain non-authorizing. This rule does not activate
clipboard and does not change the literal production activation gate.

## Credential editability is R10 lifecycle authority (2026-10-24)

Credential configuration, native admission, owner consent and credential-editor
mutation are separate facts. R10 product status owns whether the local
credential editor may mutate the production standalone credential. Never derive
editor enablement from `credentialsConfigured`: configured credentials remain
replaceable while the host is stopped, and replacement revokes the prior R2
consent generation.

Stopped, PackageInstalled and CredentialsConfigured raw host stages are editable
when HostControl is available and the selected product/acceptance credential
surface is backed by a configurable production credential owner. Starting,
Listening, Authenticating, DesktopInitializing, Connected and Stopping product
states are locked; raw Revoked is locked even when its redacted product state is
Stopped. A recoverable product Error does not by itself lock a raw stopped host.

Linux and macOS HostControl implementations must project the same lifecycle
fact. R7 may combine it with the existing public-qualification / explicit
owner-acceptance surface gate, including R2's descriptive
`standalonePasswordConfigurationAvailable`, but must not infer editability
from permission requestability, endpoint/TLS readiness, configured state or
other unrelated flags. The editability fact grants neither consent,
authentication, endpoint authority nor listener authority.

## Keep standalone credential, native admission and consent as separate owners (2026-10-24)

Do not make production standalone credential configuration depend on current
native desktop/admission-policy readiness. The credential owner validates and
generation-fences the username/password; platform-native admission is rebuilt
from fresh evidence at the protected Start boundary. Likewise,
`credentialsConfigured` means the selected production credential generation
is current and valid, not that owner consent, native admission, endpoint/TLS or
listener readiness has already succeeded.

Credential replacement must revoke the prior current-owner consent generation
before consuming the replacement password, and the mutable password must be
scrubbed on success and failure. Keep the public Release qualification bit
separate from the internal production configuration-availability fact; neither
bit is authorization.

## R7 permission requestability is not owner authorization (2026-10-24)

R7 may use R10's redacted `sharingPermission.canRequest` fact only to decide
whether the explicit local Sharing/permission action is available. It is never
an owner grant and must not be converted into `desktopAuthorized`, listener
authority or automatic Start. When no current owner grant exists and permission
cannot be requested, the GUI keeps both main and tray Sharing actions disabled
and presents the bounded product denial. When permission is requestable, the GUI
may enable the explicit local action, but that action must still call R10's
permission command and obtain a fresh grant before endpoint/listener Start.

## Keep qualification gates independent (2026-10-23)

Do not use `kStandalonePasswordProductCapabilityApproved` as a proxy for
clipboard readiness. Before real Microsoft-client qualification it must remain
false while Debug/explicit acceptance builds still exercise the production
standalone path. Likewise, later promotion of that flag must not alter
`kLinuxProductionClipboardActivationApproved` or manufacture clipboard
permission. Keep both gates literal, reviewable, and backed by their own
acceptance evidence.

## Keep the portable desktop wrapper composition-only (2026-10-23)

Do not add clipboard state or protected CLIPRDR operations directly to
`LinuxPortableDesktopRuntime`. The wrapper may own the one serialized
`LinuxRuntimeHostControl` and delegate `serviceOnce()`; all native/R8 state
must remain inside the existing generation-fenced HostControl/native-desktop
lifetime. A product capability flag, hosted bootstrap PASS or listener-ready
projection is not clipboard authority and must never be used to bypass the
literal production activation gate.

## Standalone bootstrap/Sharing must remain clipboard-free (2026-10-23)

When no-config standalone security/admission policy is regenerated from current
physical-X11 evidence, keep that helper limited to R2 policy ownership. It must
not open the listener, create the native desktop, grant clipboard permission or
touch CLIPRDR/prepared clipboard APIs. In the GUI's explicit Sharing
transaction, configure the production Session Password first, immediately clear
both password widgets, request only View/Input with `allowClipboard = false`,
then prepare/start the endpoint. Do not infer clipboard freshness from the
credential, policy, TLS or licensing generation.

## Portable host-control deny fallbacks must be backend-link independent (2026-10-23)

A cross-platform `RuntimeHostControl` default denial path must not introduce a
link dependency on an optional authentication provider merely to erase caller
input. Keep the base fallback self-contained, bounded, allocation-free and
non-elidably cleansing; concrete production providers remain responsible for
their stronger mechanism-specific secret lifecycle. A cleanup fallback is not
an authentication implementation and must never mint credentials, authority or
listener state.

## R7 owner-acceptance Session Password surface (2026-10-23)

Before StandalonePassword is publicly qualified, its product capability must
remain false in Release. A qualification UI may exist only behind compile-time
Debug/acceptance gating; do not add a runtime preference, hidden command,
environment variable or second authentication implementation that bypasses the
product capability. The acceptance UI must invoke the exact production
generation-fenced standalone credential owner and clear presentation password
fields immediately after the production configure call.

Normal no-argument Linux standalone provisioning must not fabricate a
Kerberos/GSS identity or map the application username to an OS account. Reuse
R5's current physical X11 selector for the native target, resolve that target's
current non-root NSS account, retain an empty Kerberos principal through the
dedicated standalone policy producer, and continue requiring exact standalone
authentication plus fresh owner authority before native admission.

A recommended address is descriptive before Start, not proof of a listener.
Presentation must call it a local address and keep Copy disabled until R10
reports a current bound listener. Only then may the GUI call the value
connectable. Startup/provisioning code must never call listener Start; the
explicit Sharing action is the local intent boundary.

## Generated licensing bootstrap is not clipboard authority (2026-10-23)

Keep automatic R3 licensing construction side-effect-free with respect to R1
listen, R2 admission, native desktop creation and R8. Do not call clipboard
permission, prepared-owner, CLIPRDR route/dispatch/queue/write or native
clipboard APIs from the HostControl constructor or licensing generator.
Service-lifetime licensing material may outlive Stop; dormant/live clipboard
state may not. Clipboard freshness continues to come only from the current
admission/session generations and common native-desktop retirement.

## OpenSSL generated-certificate mutable-object portability (2026-10-23)

Do not assume an accessor returning an X509-owned subobject remains mutable
across supported OpenSSL versions. In particular, generated-certificate code
must not acquire a subject with `X509_get_subject_name()` and mutate it in
place. Construct a fresh RAII-owned mutable `X509_NAME`, populate it, then
copy it into the certificate through `X509_set_subject_name()` and
`X509_set_issuer_name()`. Read-only observations should use const accessors.

This rule does not change identity semantics: a generic certificate Common Name
is descriptive only. Numeric R1 endpoints remain authorized exclusively by
their exact `iPAddress` SAN and must never fall back to the Common Name.

## Portable automatic bootstrap state is outside the extracted app (2026-10-23)

Normal desktop startup has no required arguments. Prefer the shortest safe
lifetime: the current R1 generated TLS identity and R3 generated licensing
identity are process-memory-only; Session Password is always memory-only by
default. If TLS identity or licensing identity is explicitly persisted, it
belongs in the OS per-user private application-data root. Non-secret preferences belong in the per-user configuration root. Never
derive a writable secret path from `argv[0]`, the current working directory or
the ZIP extraction directory; read-only extraction is a supported condition.

Persistent private creation/replacement must be atomic and fail closed across
symlinks, reparse points and parent/final path substitution, using restrictive
POSIX modes or Windows ACLs before material becomes authoritative. Reuse the
existing R1/R3 secure credential readers after generation instead of adding a
weaker parallel loader. Bootstrap may run before the GUI appears, but it owns
no listener, service, firewall/system-RDP mutation, R2 admission, R3 Share or
native permission. Explicit Sharing remains the only product route to
listening. The expert `--config` route may select supplied material but must
not become the normal consumer dependency.

## R1 generated TLS identity and secret lifetime (2026-10-23)

The portable GUI may prepare an R1 server identity in memory from an exact
numeric LAN endpoint. Generate keys with reviewed OpenSSL APIs and keep the key
inside RAII-owned OpenSSL objects; do not serialize generated private-key bytes
to argv, environment, logs, status/error strings, CMake cache, temporary PEM
files or the extracted application directory. Numeric addresses require an
`iPAddress` SAN containing the parsed address bytes. Never use CN/DNS fallback
for an IP literal.

Generated identity preparation is not bind authority. R10 may own the move-only
R1 context for lifecycle composition, but R1 remains the sole listener/bind/TLS
boundary and must revalidate the current native interface/address and the
certificate against the actual bound listener before publication. Reconfigure
must retire a stale generated identity; Stop must retire accepted/native and
listener state before the generated TLS context. File-backed TLS remains an
expert/legacy input only and must satisfy the same purpose/key/SAN checks.
Do not share TLS key material with R3 licensing merely to reduce key count.

## R8 bootstrap must not manufacture clipboard authority (2026-10-23)

Automatic GUI bootstrap may create local runtime prerequisites and Session
Password state, but it must not set clipboard permission, flip the production
clipboard activation gate, construct the prepared clipboard owner, or call
CLIPRDR routing/write APIs. Keep bootstrap state and R8 state separate.
Credential replacement must not carry a live native/R8 generation across the
boundary: reject replacement while hosting or retire the host first, invalidate
the old credential generation, and let any later native lifetime allocate a
fresh generation-bound clipboard owner. Stop/Revoke remains clipboard-before-R5
teardown; hide-to-tray remains nonterminal; Quit must Stop/Revoke before exit.

## Product permission status must be projected above R2 (2026-10-22)

Do not make Qt decode owner-consent enums, native-session evidence or
`kConsole*Permission` bitmasks. R2 owns fresh evidence validation and may
expose a read-only non-authorizing observation; R10 translates it once into
redacted product facts: requestability, active View/Input scope, remaining
lifetime and a bounded denial category. GUI text and button state consume only
that R10 product projection.

A status observation never substitutes for
`CurrentOwnerSharingAuthority::authorizes()`, never refreshes/revokes a grant,
and never turns a cached GUI Boolean into authority. Keep lock, desktop
replacement, expiry and explicit revocation fail-closed. Dormant clipboard
capability must not be added to the product permission projection before its
separate activation gate.

## Linux prerequisite projection stays read-only and product-facing (2026-10-22)

R5's Linux GUI prerequisite probe may expose only compact product-facing
session/runtime facts. Keep Session type, Display, Active local session,
Unlocked, Physical session and Input support separate from raw diagnostic
evidence, and do not expose roadmap names, authorization generations, local UID
internals or capture implementation details in user-visible text.

The probe is observation only: environment reads, client-library presence and a
bounded `loginctl show-session` query are allowed. It must not connect to the
X server, construct native desktop/capture/input owners, synthesize input, bind
a listener, or request/mint sharing permission. A positive prerequisite field
never creates authority.

## Cross-platform preferred-LAN recommendation semantics (2026-10-22)

Keep preferred-LAN recommendation inputs semantic and platform-neutral.
A platform collector supplies an opaque stable interface identity, numeric
address, explicit IPv4/IPv6 family, private-LAN eligibility, whether the route
is preferred/default, and route metric/priority when the platform can provide
one. Native interface names, friendly labels and API structure layouts stay
inside the platform adapter.

Never rank candidates by strings such as `eth0`, `wlan0`, `en0`, adapter
friendly names, stable-ID lexical order or address lexical order. Preferred
route ownership is meaningful cross-platform evidence. Compare route metrics
only when every remaining contender exposes one; otherwise distinct contenders
are ambiguous. Address family is explicit metadata, not a portable tie breaker.

Windows may later derive these facts from its native interface/routing APIs and
Linux/macOS from their own native sources, but those API-specific records must
not leak into `runtime_host_control.h`. Recommendation never authorizes a
bind, R2 admission or native desktop activation; R1 must still revalidate the
exact selected interface/address at Start.

## Authentication kind is part of the R2 native-authorization proof (2026-10-22)

Do not make local SID/UID equality a universal native-desktop admission rule.
`ExistingOsAccount` must continue to prove exact authenticated SID/UID
identity equality with the current native owner. `StandalonePassword` must
instead prove the exact authenticated application session: owner-bound
`CredentialsVerified`, exact R1/TLS connection provenance and exact current
standalone credential generation. Never fabricate a SID, UID or GSS/Kerberos
principal, and never map the standalone application username to an OS account
just to satisfy an older interface.

Keep one R2 authenticated-session proof generation distinct from the service
credential generation. Rebinding a proof to another accepted connection must
advance that proof generation even if the configured password generation is
unchanged. Native authorizations pin both the proof generation and their own
authorization generation and revalidate the proof, owner epoch and native
session before and after each synchronous visitor callback.

Downstream R5/R6/R10 code may consume only the const, noncopyable authorization
visitor. Native-session SID/UID values exposed to platform owners identify the
local desktop target for standalone mode; they are evidence/freshness fields,
not a remote authenticated identity.

## macOS native input readiness requires both non-prompting privacy gates (2026-10-21)

Treat Accessibility trust and Input Monitoring readiness as one fail-closed
native-input precondition for the R5 Quartz route. Production checks must use
`AXIsProcessTrustedWithOptions(nullptr)` plus
`CGPreflightListenEventAccess()`; do not call prompt/request APIs from native
owner construction, service or input dispatch. The combined observation is
revocation evidence only: R2 View+Input authorization remains mandatory and
TCC booleans never create authority.

Recheck this combined readiness through the existing serialized session guard.
If either observation is lost, terminally retire the aggregate and discard
held input with no native cleanup posts into the changed desktop.

## Normalize bounded pixel dimensions before size_t overflow guards (2026-10-21)

When a fixed-width framebuffer dimension participates in `size_t` allocation
or stride arithmetic, convert it once to a cached `std::size_t` value before
comparing against `size_t` limits. Do not compare a narrower unsigned type
directly with a platform-wider constant such as `size_t::max()/bytesPerPixel`;
Clang may correctly diagnose that comparison as tautological under `-Werror`.
Keep the overflow check before multiplication and reuse the converted value for
the hot-path row calculation.

## R10 platform-native composition is one owner, never a platform server (2026-10-21)

For Windows/macOS native hosting, keep exactly one R10 owner-thread composition
surface above R5/R6. Do not create separate RuntimeHostControl state machines,
listeners, protocol loops, worker threads or native schedulers per platform.
Linux's existing R10 HostControl remains its already-serialized lifetime.

The platform composition may consume only a const already-bound R2 native
authorization and must derive the exact current authorization generation from
that object during attach. Never accept a generation, SID/UID, WTS/session ID,
TCC status or permission Boolean from GUI/caller code as construction
authority. At most one native aggregate may be active; a new authorization
requires retirement and a fresh attach.

All native operations stay bounded and owner-thread-affine. R2/R3 routing is
closed before terminal native retirement. Delegate retirement to R5/R6 so held
input is discarded without native cleanup posts before capture/session
resources are destroyed. Do not bypass a platform's fail-closed positive
activation gate merely because the R10 composition seam exists.

## R5 macOS native desktop operations stay inside the R2 visitor (2026-10-21)

Do not expose a macOS native desktop constructor from UID, display ID, geometry
generation, TCC state or any other scalar/evidence tuple. Production
ScreenCaptureKit and Quartz callbacks remain private to
`MacNativeDesktopOwner`, and that aggregate may obtain them only while being
constructed inside a fresh `MacNativeDesktopAuthorization::visit()`.

Every protected R5 operation must execute synchronously inside the exact R2
authorization-generation visitor with the minimum required scope: View for
capture service/frame borrow and View+Input for Quartz dispatch. Do not sample
R2 from ScreenCaptureKit's asynchronous callback queue; copy at most one newest
frame into bounded aggregate-owned storage and re-enter R2 only when the
owner-thread consumer borrows it.

Treat display/session/TCC changes as terminal retirement. On upstream authority
loss, call `MacInputController::retireWithoutNativeInput()` before destroying
native children; never synthesize key/button releases into an identity or
desktop that may have changed. Reconnect means fresh R2 authorization plus a
fresh one-shot aggregate.

Until a reviewed multi-display compositor/multi-stream policy exists, reject a
layout whose virtual pixel size differs from the selected ScreenCaptureKit
display. Capture pixels and input coordinates must never silently refer to
different desktop spaces.

## R2 Windows/macOS native grants require identity + evidence + owner epoch (2026-10-21)

## R6 Windows aggregate consumes R2 authority; native evidence never substitutes (2026-10-21)

Keep the real Win32 `SendInput` callback private to
`WindowsNativeDesktopOwner`; do not re-expose a general native-input callback
helper. Positive owner construction and every protected capture/cursor/input
operation must name the expected
`WindowsNativeDesktopAuthorization::authorizationGeneration()` and re-enter
the const R2 `visit()` surface with the exact required View/Input permission.
A matching SID, WTS session number, LSA LUID/logon time, active-console state,
desktop layout, DXGI output or generation scalar is observation/revocation
evidence only and must never create or refresh authority. R3 Share/input
authority remains an additional runtime gate.

R10 owns the serialized scheduler and at most one aggregate Windows native
owner. `WindowsNativeDesktopOwner::serviceOnce` is a bounded unit of native
work, never permission to add another listener, server loop or worker. On
R2/R3 authority loss retire routing first, close the native guard, discard held
input with `retireWithoutNativeInput()`, then retire DXGI children/COM state.
Do not synthesize cleanup SendInput after authority loss and do not add
TermService, firewall, RDP-policy, Session-0 or service-management behavior.

Native platform evidence is never authentication and never authority. The R2
Windows/macOS authorization objects may bind only after an authenticated
identity proof matches a fresh native observation and
`CurrentOwnerSharingAuthority::authorizationEpoch()` freshly authorizes the
requested scope. Positive native scope is limited to View or View+Input;
Clipboard and any unknown bit are rejected.

Bind and every synchronous visit must pin the authenticated-identity
generation, a monotonically increasing R2 authorization generation, and the
exact owner grant + revocation epoch. Replacing owner consent must invalidate
the old platform grant even when the revocation counter itself did not change.
A visit must require the caller's expected R2 generation, then re-read native
evidence and revalidate identity/owner state before and after its callback.
Generation mismatch is a denial without destroying a newer current grant;
identity, native-session or owner-epoch loss is terminal for the bound grant.

Windows binds exact SID bytes, local physical WTS session ID, LSA
authentication LUID, logon time/type and requested permissions. macOS binds
authenticated UID, bounded console-user UTF-8 name, console/audit UID, audit
session ID, SecuritySession ID/attributes and requested permissions. Downstream
R10/R5/R6 code receives only const noncopyable visitor views and may copy
generation/session selectors only for freshness; those scalars never recreate
authorization. Keep bind/revoke/visit serialized on the R2/R10 owner thread.
Native evidence readers remain read-only and platform-specific.

## R7 Qt findChild type must own a meta-object (2026-10-21)

Qt 6.11+ statically requires the concrete type supplied to
`QObject::findChild<T*>()` to have `Q_OBJECT`. A custom widget can validly
inherit `QAbstractButton` without declaring its own meta-object when it adds
no signals, slots or properties. For object-name-only discovery of such a
widget, query through the nearest suitable Qt base class that already owns a
meta-object and consume only that base API. Do not add `Q_OBJECT` or enable
AUTOMOC solely to make a test or hidden launcher lookup compile.

Keep direct construction/ownership concretely typed where useful; this rule is
only about meta-object discovery. The R7 sharing-toggle checks therefore use
`QAbstractButton*` by object name and validate checkability/enabled/checked
state without casting back to the imported concrete widget.

## R2 standalone interoperability diagnostics are redacted and fail-only (2026-10-21)

For the standalone Microsoft-client gate, report the first terminal R2 boundary
only: NTLM negotiation, MIC, SIGN/SEAL, SPNEGO, pubKeyAuth, authInfo or
admission. Keep that value as a bounded enum/scalar; never retain or log
TSRequest/NTLM bytes, responses, session keys, delegated credentials, usernames,
passwords, native identities or authorization objects.

When `StandalonePassword` is selected, a failure log may state the fixed stage
and that OS/GSS fallback is disabled. It must be fail-only. Do not initialize,
retry or consult the GSS acceptor from the standalone path merely to improve
diagnostics. Offline tests must continue to assert the GSS stage is
`Unconfigured` for the selected standalone connection.

Do not solve the physical acceptance password-entry problem by adding a public
or hidden product switch, config key, argv/environment secret, or Qt field.
Until an unmodified Windows App or Windows 11 `mstsc.exe` succeeds, the only
permitted preparation is an owner-local non-product harness that freshly fills
mutable password memory and immediately calls the existing internal
generation-fenced credential seam. No such harness or password value is
product capability evidence.

## R8 tray hiding is presentation-only; terminal commands own retirement (2026-10-21)

Do not couple Qt visibility to R8 lifetime. A hide/minimize/tray-hide operation
must not call Stop/Revoke or retire the current clipboard while R10 continues
sharing. Clipboard lifetime follows the accepted-client/native owner, not the
visibility of `DesktopWindow`.

Stop, Revoke and process Quit must enter the common R10 retirement path so R8
selection/paste/INCR plus bridge receipt state dies before R5, the accepted
connection and the listener. Client disconnect must retire the same R8/R5
state before the accepted connection while permitting a fresh replacement
client. Reconnect must allocate a new `LinuxHostNativeDesktopState` and
prepare a new `LinuxPreparedClipboardOwner` from that replacement's exact R2
admission/session generations; never carry an adapter, bridge, pending write or
native selection across the boundary.

Keep `kLinuxProductionClipboardActivationApproved = false` until the recorded
FIRST visible-desktop + mouse + keyboard + Stop pass. The first later activation
remains Unicode text only. Images and files are separate later milestones.

## R10 HostControl must never default a selected standalone client to GSS (2026-10-20)

Treat the HostControl credential mode as part of the accepted-connection
security provenance. Existing-OS-account and standalone modes must map
explicitly to `LinuxRuntimeAuthenticationSelection`; do not call the default
four-argument `LinuxRuntimeConnection` constructor after a product mode has
been selected.

For standalone mode, capture one exact credential generation when the
service-lifetime password is configured. Before listener readiness and again
before accepted-client construction, require that exact generation and a
successful synchronous credential visitor. Generate a fresh cryptographically
random NTLM ServerChallenge per connection and a current FILETIME; never reuse a
fixed challenge across clients. Selection/challenge failure is terminal for the
current host runtime and must not fall back to OS-account authentication.

Use the same selected mode when requesting R2 native evidence. Standalone must
request the principal-free standalone identity kind; ExistingOsAccount keeps
the Kerberos-principal request. Keep the public
`IndependentApplicationPassword` UI unavailable until the explicit production
selector has succeeded with an unmodified Microsoft client.

## R8 GUI/CLI prepared clipboard owner stays single-owner (2026-10-20)

Do not duplicate the prepared Linux clipboard composition between CLI and Qt.
Both lifetimes must use `LinuxPreparedClipboardOwner`, borrow the one R5 XCB
connection, pin the exact R2 admission/session generations and re-enter the R2
clipboard gateway for every protected transition. Build availability is never
clipboard authorization.

Keep `kLinuxProductionClipboardActivationApproved = false` until the recorded
FIRST REAL DESKTOP video/input/Stop PASS. The first activation surface is
`PresentationScope::UnicodeTextOnly`; production code must not call PNG,
FileContents, completed-file or directory-transfer entry points.

In the bounded Qt service loop, a pending clipboard R1/R3 write owns effective
WANT_READ/WANT_WRITE before Graphics writes, application reads and capture.
Advance an already-pending clipboard write at most once per service tick; a
freshly staged response may only prime the existing writer with no readiness
flags. On every terminal path retire R8 X11/INCR and bridge receipt state before
R5, then the accepted connection.

## Native bridges must not re-specialize the R2 proof (2026-10-20)

After R2 selects a `LinuxAuthenticatedPrincipalProof`, native bridges such as
the X11 input route must consume that common proof rather than naming a concrete
GSS or standalone mechanism. Re-adding a mechanism-specific include to repair a
compile failure is not acceptable because it fragments authorization and can
silently exclude another authenticated mode.

## R2/R10 authentication selection is explicit per accepted connection (2026-10-20)

Do not infer standalone-password mode from the mere presence of a configured
credential. R10 must explicitly select existing-OS-account or standalone mode
when constructing the sole `LinuxRuntimeConnection`. Standalone selection
must name the exact credential owner/generation and bounded NTLM challenge
identity; consume challenge views synchronously.

After selection, keep exactly one `LinuxAuthenticatedPrincipalProof*` for all
broker/R3 calls. GSS-only operations remain confined to existing-account mode;
standalone TSRequest processing uses the exact R1 connection and synchronous
credential visitor. Never add parallel brokers, leases, post-admission mode
controllers or fake Kerberos principals.

## R2 standalone proof requires owner-bound TSRequest I/O (2026-10-20)

A standalone `CredentialsVerified` result is production-eligible only when
every TSRequest was read through the exact R1 `OwnedPreauthTcpConnection` and
every CredSSP reply was queued through that same owner. Keep direct-SSL
memory-BIO/provider paths test-only and incapable of binding an R2 proof.

The standalone authenticated-principal proof must also retain and recheck the
exact `StandalonePasswordCredentialOwner` generation on initial admission,
completion and every protected-operation revalidation. Connection failure
retires connection-scoped proof/CredSSP state, not the service-lifetime
credential.

## R2 authentication mechanisms converge before native authorization (2026-10-20)

Authentication mechanisms must implement the one
`LinuxAuthenticatedPrincipalProof` contract instead of adding
mechanism-specific broker/R3 gateways. The proof may validate only its own
exact authentication/TLS/generation provenance. Current-owner consent, native
NSS/logind evidence, permissions, lease lifetime and R3 protected-operation
authorization remain in the sole `LinuxConsoleAdmissionBroker`. Mechanism
revocation must flow through the proof contract on every broker denial.

## R10X post-Share Qt ticks own exactly one native desktop (2026-10-20)

After Graphics control readiness, construct the Linux native desktop only
through the current R2 `visitNativeDesktopSelection(...)` callback and retain
exactly one X11 owner beside the accepted connection. The callback may copy only
the admission/session generations; the DISPLAY view is consumed synchronously.
Never fall back to configured/environment DISPLAY or create another XCB owner.

A Qt service tick is a bounded work budget, not a blocking loop: use zero-timeout
readiness, retire the borrowed logind registration before callbacks, cap X11
events, advance at most one existing application-read/Graphics-write operation,
then use the existing resize scheduler, frame-credit preflight and synchronous
typed framebuffer borrow. Reauthorize after native changes and after the X11
drain. A socket `POLLERR/POLLHUP` is readiness for the sole R1 operation, not
a HostControl cancellation; only `POLLNVAL` is scheduler-terminal. Clipboard
remains out of this increment.

Stop/Revoke must order current-owner authority -> native no-XTEST retirement ->
accepted R3/R2/R1 aggregate -> listener. Explicit client disconnect retires
native -> accepted aggregate and preserves the current authorized listener.

## R2 standalone native identity must not synthesize Kerberos (2026-10-20)

When independent-password authentication targets an existing OS desktop, carry
an explicit standalone authentication kind and an empty Kerberos principal.
Match the already configured exact Unix account, seat/display, native UID and
permissions instead of manufacturing a principal string. Keep Kerberos
principal matching unchanged for GSS. The identity-kind selector itself is
untrusted metadata and must never authorize native access; only the one R2
authenticated-proof/broker path may consume the resulting candidate evidence.

## R2 owner-grant observations stay non-authorizing (2026-10-20)

When R10/R7 need to display current local-owner consent, expose only a read-only
projection from the one `CurrentOwnerSharingAuthority`: effective permission
mask while active plus remaining/expiry state. Do not expose native session
identity, credential material or an authorization token. Observation must not
renew, revoke or otherwise mutate the grant, and callers must still use the
existing fresh `authorizes()` path before every protected operation.

## R1 native poll errors remain transport-owned (2026-10-20)

Do not revoke an accepted connection merely because the external POSIX poller
reports `POLLERR` or `POLLHUP`. Surface one readiness event in R1's exact
currently requested direction so the sole recv/send/OpenSSL owner observes the
EOF/reset and records the terminal transport classification. Only
`POLLNVAL` is an invalid-descriptor scheduler failure. This avoids rewriting
peer resets as Stop/cancellation and preserves one socket/BIO/SSL authority.

After terminal R1 teardown, never act on the retired numeric descriptor again.
A later kernel reuse of that fd number belongs to a different owner; stale
poll/advance calls must remain closed and must not close or mutate the reused
descriptor.

## R7 authoritative lifecycle facts stay read-only (2026-10-20)

Do not create a GUI-side connection state machine. Project R10's typed stage
plus its explicit read-only `graphicsReady`, `nativeDesktopInitializing`,
`nativeDesktopReady` and `clientDisconnected` observations. A visible or
connected desktop requires `nativeDesktopReady`; Share activation, RDPGFX
control readiness and stale per-client flags are insufficient.

Requested owner-permission scope/lifetime remains intent. R2's typed read-only
grant observation is now the only GUI source for effective permission scope
and remaining lifetime. Never copy requested checkbox/lifetime values into a
grant field or label them as granted. Present an active observation as current
only when the same R10 snapshot independently confirms view authorization;
expiry or terminal host-session loss must expose no effective scope.

R10X native readiness likewise stays authoritative for Desktop Visible; do not
infer visibility from Share/Graphics stages or GUI state. Session Password
inputs remain absent until a production capability is backed by composed R2
admission and accepted Microsoft-client interoperability; do not add a
developer/user switch that can bypass that product gate.

## R10 GUI service ticks stay bounded and single-owner (2026-10-20)

Do not call the CLI's serialized blocking candidate loop from Qt and do not add
a worker thread or second poller. Accept directly from the exact R1 listener
only when no client is owned, apply private-LAN and authentication-attempt gates
before constructing `LinuxRuntimeConnection`, and pass the existing const
owner-sharing authority into that connection.

Each GUI service tick may advance one existing runtime phase and perform only a
zero-wait readiness observation. Preserve the pre-Share deadline but do not
invent a post-Share idle timeout. On Stop/Revoke, host-owner authority retires
before the accepted connection, and the connection retires before the listener.

## R2 standalone password ownership is generation-fenced and non-public (2026-10-20)

Keep one service-lifetime owner around the existing memory-only standalone
credential. Configuration must consume a mutable UTF-16 password buffer and
non-elidably cleanse it on every return path; retain only the existing bounded
username/NT hash. Replacing credentials invalidates the old credential first
and advances a monotonic generation. Never expose a durable raw
`EphemeralNtlmV2Credential` pointer/reference across generations; use an exact
generation plus a synchronous visitor.

Credential replacement is an R2 authorization event: revoke current-owner
consent as `CredentialChange`. Ordinary Stop revokes current-owner consent and
retires per-Share runtime state but preserves the current valid standalone
credential generation. Explicit/full revoke, native-session or local-user loss,
Quit, owner destruction and credential-mode replacement must cleanse standalone
credential material; terminal teardown must do so before the listener retires.
Switching to another credential mode must revoke the alternate standalone
credential even if the requested replacement later fails.

Do not project this internal owner as product credential readiness. Until a real
unmodified Windows App/mstsc CredSSP exchange succeeds through the production
accepted-socket path, keep `IndependentApplicationPassword` unsupported and
construct no Qt password field.

## R10 configuration snapshots and LAN policy are lifetime owners (2026-10-20)

Never retain a `RuntimeConfigurationView` or any of its field string_views
past the visitor callback. Any identity needed for later R2 admission must be
copied into bounded service-owned storage and fenced to the exact current
identity-policy generation. Reconfiguration/revocation invalidates the old
snapshot rather than updating it in place.

Do not reuse the CLI loopback transport decision for GUI LAN acceptance.
PersonalDesktop loopback and private-LAN scopes are explicit immutable policy
modes. Private-LAN candidate classification is network location only; it must
not replace TLS/CredSSP, current-owner authority, NSS/logind evidence or
per-operation R2 reauthorization.

## R2 standalone authInfo credentials remain borrowed and non-authorizing (2026-10-20)

Final standalone CredSSP authInfo must be accepted only after verified
TLS-bound pubKeyAuth and only from the same pinned TLS-derived TSRequest owner.
Require one NTLM signature followed by bounded ciphertext, unwrap through the
existing connection security context, and cleanse the entire decrypted buffer
on every return path.

Reuse the canonical TSCredentials/TSPasswordCreds parser. When the standalone
application credential needs validated password fields, expose them only as
synchronous borrowed UTF-16LE spans; do not route its username through the
Unix-account naming policy and do not copy or cache the delegated password.
Require an empty domain, bind the username to the configured standalone
identity using the same ASCII case rule as NTLM, derive only an ephemeral NT
hash from the delegated password, compare password-equivalent material in
constant time, then cleanse it.

A successful authInfo comparison is credential-mechanism evidence, not desktop
authorization. Retire the CredSSP message-security keys after final credential
verification, but keep R2 current-owner consent/session authority as a separate
mandatory gate. Never enable IndependentApplicationPassword merely because an
offline authInfo fixture succeeds.

## R2 standalone CredSSP must reuse TLS-derived TSRequest provenance (2026-10-20)

Do not create a standalone-password-specific DER parser, TLS reader/writer, or
certificate identity cache. Feed only complete frames produced by the existing
`TsRequestFrameReader`, pin the exact established server TLS object and
selected-certificate fingerprint on the first frame, and queue replies only
through the existing one-reply `TsRequestTlsReplyWriter`. A manually consumed
DER frame has no TLS provenance and must fail terminally even when its syntax
and NTLM token are otherwise valid.

For NTLM CredSSP protected fields, require exactly one 16-byte NTLM message
signature followed by the sealed plaintext. Use the already-established
directional NTLM sequence/RC4 state; never derive a second set of keys or reset
sequence numbers at the TLS binding boundary. After stream consumption, any
signature, certificate, nonce, version, reader/writer, or TLS mismatch retires
the entire standalone mechanism.

When the final client SPNEGO token shares a TSRequest with `pubKeyAuth`,
suppress a mechanism response only if it is the exact empty
accept-completed envelope required to transition to the server binding reply.
Never discard an outstanding response token or mechListMIC merely because the
CredSSP server-binding shape omits `negoTokens`.

## R2 SPNEGO mechListMIC uses exact mechanism-list bytes and NTLM state (2026-10-20)

When SPNEGO selects NTLM after another initiator-preferred mechanism, retain the
exact DER-encoded MechTypeList and require the RFC 4178 mechanism-list MIC
exchange before authentication can complete. Verify/sign that exact list with
the already-established NTLM message-integrity service; do not re-encode OIDs,
reset sequence numbers, clone RC4 state, or treat a successfully parsed MIC as
authorization.

NTLM SIGN-only and SEAL must consume the same per-direction sequence and
KEY_EXCH RC4 checksum stream. A mechListMIC therefore advances the state later
used by CredSSP pubKeyAuth/authInfo. On mismatch after RC4 consumption, retire
the entire context rather than attempting rollback.

Distinguish Microsoft NegTokenInit2 from the older RFC layout: context [3] is
NegHints when it contains the NegHints SEQUENCE, context [4] is the Microsoft
mechListMIC, while RFC 4178 may use [3] directly for mechListMIC. Hints are
bounded syntax only and never trusted as server identity or policy.

## R2 standalone SPNEGO parsing and fallback integrity (2026-10-20)

First-party SPNEGO must have one bounded connection owner; do not split
mechanism selection, NTLM transcript retention and message-security sequence
state across helpers with independent lifetimes. Parse canonical definite DER
with exact context tags and OIDs, cap mechanism counts/tokens, and retain exact
wire Type 1/server Type 2 bytes rather than reconstructing an authentication
transcript.

Selecting NTLM after a different initiator-preferred mechanism does not permit
final authentication by itself. Until mechListMIC is verified with the
negotiated mechanism integrity service, fail closed before a fallback exchange
can become authenticated. A Type 3 password proof must also bind the presented
username to the configured standalone username; password knowledge alone may
not authorize an arbitrary claimed username.

## R2 stateful NTLM message security stays single-owner (2026-10-20)

Connection-oriented NTLM SIGN/SEAL state is not a reusable stateless helper.
Keep client/server RC4 permutations and sequence counters inside the same
noncopyable security context that owns the derived keys. Compute the ESS HMAC
over the plaintext and sequence number before sealing; when KEY_EXCH is active,
encrypt the eight-byte checksum by continuing the same directional RC4 stream.
If verification fails after stream consumption, cleanse output and retire the
entire context instead of attempting rollback or stream reconstruction.

Transcript MIC checks must consume exact wire bytes and logically zero only the
MIC field for HMAC. Do not rebuild Type 1/2/3 messages from parsed structures
for authentication, and never cache a successful parser Boolean as identity or
admission evidence.

## R2 NTLMSSP security buffers are borrowed, bounded wire views (2026-10-20)

For standalone NTLMSSP, treat each MS-NLMP SECURITY_BUFFER MaxLen as
non-authoritative and validate only the transmitted Len plus BufferOffset
against the exact caller-owned token. Nonempty Type 3 payload ranges must begin
after the fixed 72-byte header (including its always-present Version field) and
the required MIC region and must not overlap one another. Decode negotiated Unicode identities byte-by-byte into
bounded aligned char16_t storage; never reinterpret an untrusted byte pointer as
char16_t. Keep NTLMv2 response/key bytes borrowed synchronously and do not cache
a parser success Boolean as authentication. Exact transcript/MIC verification
and stateful SIGN/SEAL remain responsibilities of the future single mechanism
owner.

## R8 dormant activation composition rules (2026-10-19)

When preparing clipboard before live authorization, compile the complete route
but keep one explicit production gate false. Do not replace that gate with a
GUI preference, build-option default, cached permission Boolean or synthetic R2
lease. The serialized runtime owner must re-enter the existing R2 clipboard
gateway for every R3 route observation and native paste request.

Use the already-owned R5 XCB connection and event loop. The R8 adapter must
retire before its `RemoteTransfer` owner because INCR and delayed-selection
state may borrow verified payload storage. On Stop/revoke/reconnect, disconnect
the X11 adapter first, retire the R8 bridge/source/response state second, then
retire R5 and the R1/R2/R3 connection. Generation values are anti-stale
provenance only and never authorization.

While an R3 clipboard write is queued, the sole R1 TLS writer owns the effective
WANT direction. Prime that existing writer without I/O after a newly staged
response so the next poll projects the correct direction; do not add another
socket writer or infer completion from writability. Defer capture/application
reads until the exact R2/R3 accepted-byte receipt clears the clipboard write.

The first production scope is Unicode text only. Use the adapter's explicit
`PresentationScope::UnicodeTextOnly`; never rely on callers merely promising
not to request PNG/files. Production `main.cpp` must not call completed-file,
FileContents, PNG-paste or directory-transfer entry points until a separately
reviewed post-acceptance change authorizes them.

## R2 current-owner consent does not follow identity automatically (2026-10-19)

R2 owns one sharing authority distinct from R1 CredSSP/GSS identity, NSS,
PAM, logind physical-seat evidence and R10 GUI status. The cross-platform
`CurrentOwnerSharingAuthority` accepts only untrusted, bounded intent;
until real human confirmation and trustworthy unlocked-state evidence exist,
every positive check denies. The production Linux admission broker must
enforce this before lease issuance and again at every protected operation.
Its default no-authority constructor must remain fail-closed. Never add a
test-only grant constructor, expose capabilities to Qt/network peers or
interpret a synthetic session fingerprint, bool, cached setting or advisory
lock hint as owner authorization. R2-owned authority must outlive its
borrowers; revocation epochs are atomic, while request/UI scheduling is
serialized by R10. Positive future implementations must bind actual UID,
seat0/session generation, exact permission scope and owner-selected deadline.

## R1 live-context certificate identity publication (2026-10-19)

Derive TLS status only from the loaded SSL_CTX leaf; use the one R1
getsockname-verified OwnedLanListener for effective address/IP-SAN matching,
not R7-selected text. An unopened listener is not ready. A fingerprint is
server identity metadata, not peer trust or R2 admission. Re-observe after
rotation/Stop/interface change; R10 alone owns status and listener lifetimes,
and must verify the actually selected certificate for each accepted SSL.
Never add another TLS transport or GUI-owned socket.

## R7 unsupported credentials must have no secret input surface (2026-10-18)

Do not construct even disabled secret text fields for an independent
application-password mechanism that R2 cannot consume. Until interoperable
NLA is proven, expose only inert explanatory text and a visibly disabled
unsupported action. Supported OS-account setup remains a separate R10/R2
request. Never store, compare, log or gate Start on a password the server
cannot authenticate.

## R7 raw R10 stage cannot bypass Qt close consent (2026-10-18)

Project R10 RuntimeHostStage and listenerAvailable in the existing thin
Qt snapshot adapter. These values are descriptive, not new ownership
or authorization. Stage text must remain Qt PlainText and distinguish
authenticating, Share activated, desktop visible and real connected peers.
When R2 terminal host-session errors suppress current projected sharing,
the raw R10 stage still demands explicit Stop/close consent and confirmed
retirement. Never add a second R10 controller, listener or TLS fingerprint
generator.

## R7 Qt close authorization is explicit (2026-10-18)

Never interpret QWidget closeEvent as implicit authorization to Stop/Revoke
R10 hosting or permission to hide an unattended sharing GUI. For an active
or pending state, display a plain-text modal with a safe Keep Window Open
default; only an explicit user choice may request Stop through the existing
thin adapter. Re-read authoritative R10 state and keep the window visible
if retirement cannot be confirmed. Do not add a second listener or status
owner.

## R10 one Linux runtime listener owner across CLI and future GUI (2026-10-18)

Keep verified Linux native `socket`/`bind`/`listen` plus
`SO_ACCEPTCONN`/`getsockname` validation in **one** noninstalled
R10 component, with the sole noncopyable/nonmovable RAII descriptor
owner. The CLI remains loopback-only and obtains the descriptor only
*after* R2 pre-listener provisioning; moving the functions into a shared
library does not confer GUI bind permission or enable LAN serving. A
future GUI HostControl must reuse this owner rather than make a
parallel listener or bypass R1 accepted-socket transfer.

## Qt status QLabel creation order (R7, 2026-10-18)

Never supply R10-projected peer/interface/endpoint text to the
`QLabel` constructor before disabling AutoText. Construct an empty
QLabel, set `Qt::PlainText`, then call `setText`; setting PlainText
after construction is insufficient because Qt may already have parsed
a rich-text resource. Keep these values inert, including malformed
or untrusted peer text.

## R7 Qt runtime-status rendering (2026-10-18)

Qt Widgets `QLabel::AutoText` may interpret HTML-looking text.
Labels showing R10-projected client peer strings, LAN interface names,
bound endpoint and status/error detail must set `Qt::PlainText`
explicitly. Preserve supplied text as inert information; do not turn
network/credential state into links, rich text, permissions, TLS
identity or R2 admission. Keep the shared existing Qt shell and
fail-closed runtime adapter; no second GUI owner.

## R1/R8 clipboard outbound TLS interest projection (2026-10-18)

Once the R2/R3-authorized CLIPRDR writer has begun, the existing Linux
runtime readiness selector projects the current R8 writer-in-progress
into Write interest, including after positive partial plaintext acceptance.
When SSL_write_ex returns WANT_READ/WANT_WRITE, R1's pending-write retry
direction overrides that outbound preference. Do not poll Read for
buffered unrelated plaintext during a CLIPRDR write, and let terminal
revocation always win. Project readiness only: never duplicate R3
static-VC bytes, route IDs, write offsets, accepted-byte receipts or SSL.

## R1 nonblocking TLS read-WANT to write interleaving (2026-10-18)

OpenSSL permits SSL_write_ex after an incomplete SSL_read_ex (WANT_READ or
WANT_WRITE). Because the blocked read accepted zero application bytes,
the single R1 SSL owner may drop the pending read retry when submitting an
outbound Graphics or Share record; it must not invent a second reader or
reassemble a second packet. Conversely, an SSL_write_ex returning WANT_READ
or WANT_WRITE must retain its exact write length until that write completes.
Never advance R3 receipts from attempted rather than accepted plaintext.

## Windows SDK ordinary-name collisions require explicit portable type disambiguation (2026-10-17)

WinGDI declares a global `Rectangle(...)` function, while the portable core
also exposes a global `struct Rectangle`. A header that can be parsed after
`<windows.h>` must not rely on the bare ordinary name when the SDK function can
hide the class name. Use an elaborated type specifier at that boundary (for
example `struct Rectangle`) or a project-owned alias; do not suppress GDI or
reorder includes to hide the collision. Keep the Windows compile probe including
the affected public/shared header after `<windows.h>` so MSVC and CLANG64 both
exercise the real include order.

## R10 outbound event interest follows protocol slices, except during R1 WANT (2026-10-17)

A complete R3-owned outbound slice must make the runtime poller request
`Write` even when R1's generic post-handshake fallback is `Read`. Derive
that fact from the existing authoritative protocol phase and R10 next-I/O
action; do not copy packet bytes/offsets or add another scheduler state machine.

After R1 `writeTlsApplicationData()` returns WANT_READ or WANT_WRITE, R1's
pending application operation owns the retry direction until it completes.
Reauthorize and reborrow the current R3 suffix on retry. Terminal/revoked
runtime state always wins over stale outbound indicators.

## R2 production Linux startup-security preflight (2026-10-17)

Production Linux GSS/PAM/logind support must not be selected by a TEST_* option
or depend on BUILD_TESTING. The explicit production build gate must fail CMake
configuration when required GSSAPI/Kerberos, PAM or libsystemd dependencies are
missing. Runtime credentials remain separately provisioned restricted files;
build options, environment variables and command-line arguments never carry
private keys, keytabs, passwords or admission generations.

R2 preflight is non-authorizing. It may report that the sealed GSS acceptor
credential is usable, an explicit PAM service is configured, the immutable
deployment object is PersonalDesktop, and fresh NSS/logind evidence matches the
configured physical X11 seat policy. It must still report authenticated
admission as false. Only a live TLS-bound CredSSP/GSS exchange followed by
PAM/NSS/logind validation can mint the private revocable admission lease.

## R10 Graphics control composition stops at R3 CAPS readiness (2026-10-17)

Post-Share DRDYNVC/Graphics control follows the same single-owner rule as Share:
R10 retains only next-I/O and R1 WANT retry direction. R3 owns the dynamic
channel ID/generation, capabilities, CREATE lifecycle and CAPS negotiation; R2
reauthorizes every borrow, receipt and complete client TPKT. Do not copy those
identities or infer readiness from a previous Boolean.

A fully accepted server CAPS_CONFIRM may let the control scheduler report
Ready, but this does not authorize or define graphics application DATA
publication. R10 must not synthesize DYNVC DATA_FIRST/DATA fragmentation,
static-channel chunking or an R4-payload-to-outer-record map. Those mappings
belong to R3 because it owns the DVC/static-VC/MCS/TPKT envelopes and their
receipt identities. Until R3 exposes that sender, R4 frame bytes are
non-publishable even when CREATE/CAPS mechanics are ready.

## R10 multi-packet Share composition keeps only next-I/O state (2026-10-17)

R3 remains the sole Share activation phase and packet owner. R10 may retain only
the scheduler fact that the next operation is a read or write, plus R1's pending
WANT direction. Determine that next operation exclusively from R3's protected
write kind / completion and client-intake outcomes; do not mirror Confirm
Active, Synchronize, Control or Font stages in a second runtime state machine.

A fixed-capacity TPKT framing owner may be reused for a multi-packet transcript
only after its complete packet was synchronously consumed through R2/R3. Reset
must clear the prior bytes/length and return to NeedMore; Invalid and Closed
states are terminal and cannot be revived. Every real client read is freshly R2
reauthorized immediately before R1 I/O and is capped at the exact remaining
TPKT boundary. Every server write follows the R10 outbound rule: freshly
reauthorize/borrow through R2, submit only the borrowed R3 span through R1, and
commit only R1's exact positive plaintext accepted-byte receipt.

## R10 outbound TLS writers never accept caller progress (2026-10-17)

For a serialized post-admission outbound protocol record, R10 may accept only
event-loop readiness plus immutable policy/configuration inputs. Borrow the
current wire slice through the freshly reauthorized R2 wrapper, submit that exact
span to the sole R1 `writeTlsApplicationData()` owner, and commit only R1's
returned positive plaintext accepted-byte count through the R2 receipt wrapper.
Never expose a runtime scheduler API that accepts a caller-provided completion
count.

A TLS WANT_READ/WANT_WRITE result retains only retry-direction state, not a
second copy of the packet or its offset. On retry, reauthorize and reborrow the
R3-owned current slice. A short positive write is durable only after R2 accepts
the exact receipt; zero/oversized progress, stale slices, policy/lease
replacement, R2 rejection or transport uncertainty are terminal. This keeps R3
as the sole protocol writer-state owner and R1 as the sole TLS progress owner.

## R2 post-Share Graphics DVC transitions are policy-bound (2026-10-17)

R3 owns the Graphics DVC protocol lifecycle. R2 does not duplicate that state or
create a second channel authority. Once R3 reaches `ShareActivated`, R10 may
access the existing private Graphics begin, pending-write, write-receipt and
client-TPKT transitions only through R2's PersonalDesktop broker wrappers.
Each wrapper first rechecks the exact immutable deployment-policy object and the
same protected transition used by licensing/Share: current R1 HYBRID TLS owner,
TLS-bound GSS principal, active lease/control and identity-policy generation,
fresh NSS/logind session evidence, and exact R3 admission/session generations.

The accepted-byte receipt uses the nullable current lease because R1 plaintext
may have progressed before logout, disconnect, policy replacement or native
session revocation becomes visible. A missing/stale lease closes R3 and revokes
GSS before the byte count can reach the Graphics DVC owner. Pending writes and
client TPKTs must be reauthorized independently; a prior application-ready
Boolean or DVC generation is freshness evidence only and cannot authorize a
later operation.

## R10 post-admission TLS intake is exact-frame and authority-bound (2026-10-17)

For a post-admission RDP packet consumed from the connection SSL owner, retain
one bounded frame owner in the serialized connection aggregate. Check the exact
protocol phase and immutable product-policy identity before reading, preserve
R1's WANT_READ/WANT_WRITE direction, and allow already-processed TLS plaintext
to satisfy read readiness. Immediately before every real TLS application read,
freshly revalidate the current R2 lease and original R1/GSS/native-session
owner.

Request no more than the frame owner's exact remaining byte count, so one
scheduler step cannot consume bytes belonging to the following TPKT. Dispatch a
completed packet synchronously through the policy-bound R2 wrapper into the
existing R3 parser/state owner; do not retain a borrowed packet span afterward
or introduce another licensing queue/parser. Close the frame owner before
authority/transport teardown so truncated input, revocation and replay cannot
cross a connection lifetime.

## PersonalDesktop licensing transitions stay policy-bound inside R2 (2026-10-17)

R10 retaining the exact service-lifetime PersonalDesktop policy pointer is not
sufficient authorization by itself. R2 must recheck that same object identity
inside the broker before every personal Server License Request slice, every
accepted-byte receipt, every client licensing intake, Valid Client slice and
receipt, every Share intake/slice/receipt and the post-Share application gate.
Those checks are in addition to the existing protected-transition proof of the
exact R1 TLS owner, TLS-bound GSS principal, live lease, PAM/NSS identity,
logind session/watch and admission/session generations.

A separately configured but value-equivalent RuntimeDeploymentPolicy is a
replacement and must fail closed. Positive R1 plaintext progress is not durable
R3 progress until the receipt crosses the same policy-bound R2 gate. Logout,
logind change/provider failure, policy replacement, disconnect or generation
replacement closes R3 before a late receipt can advance licensing or Share.
Generic app-server licensing broker methods remain available only for their
issuer-backed mode; R10 personal composition uses the policy-bound methods.

## Native input authority loss never synthesizes cleanup (R6/R7, 2026-10-17)

Native lifetime freshness and upstream R2/R3 authority are separate facts.
When R2 admission or R3 Share/input authority is lost, stop routing first and
terminally retire native input without invoking `SendInput` or Quartz cleanup,
even if a key/button is held and the native generation is still current. A
native call already entered before revocation cannot be retracted, but no
release/cleanup event may be posted afterward.

Graceful cancellation may best-effort release held state only while upstream
input authority remains current. R6 uses
`WindowsInputController::retireWithoutNativeInput()` for upstream authority
loss; its existing guard-first WTS retirement remains revocation-only and makes
ordinary `cancel()` unable to post into a revoked session. Neither a WTS
notification nor a native generation scalar grants authority.

## R3-authorized CLIPRDR stays R3-owned and generation-correlated (R8 P1, 2026-10-17)

Live CLIPRDR ingress and egress require one authoritative R3 route that is
already authenticated through current R2 authority, genuinely licensed and
Share-activated. A joined MCS channel ID, an admission Boolean, or
`RemoteTransfer::generation()` is not that authority. The live composition
boundary must correlate the current R2 admission/session generations, R3's
exact session lifetime and exact CLIPRDR-channel generation, and the negotiated
CLIPRDR channel ID/role.

R3 must revalidate that exact binding before every inbound clipboard dispatch,
outbound prepare/write slice and accepted-byte receipt, FileContents
request/response, and native publish/render callback. R8's clipboard generation
remains a separate remote-offer identity. On R2 revocation, R3 channel/session
replacement, disconnect, or either R3 generation changing, stop routing first
and call `RemoteTransfer::retireR3ChannelState()` before any replacement can
use R8 state. That revocation-only hook grants no authority; it reuses the
disconnect cleanup while monotonic receipt, stream and source identities prevent
ABA. Any native publication, delayed callback or completed destination that can
survive that call must bind `RemoteTransfer::sourceEpoch()` in addition to the
resettable clipboard generation; generation equality alone is not replacement
provenance. The owning native adapter must retire its publication/handoff state
in the same serialized lifecycle before a replacement can publish.

Caller-authorized native destinations remain independent capabilities. Verified
relative File List hierarchy is structural metadata only and never participates
in the R3 authority tuple or becomes a local path. Directory-tree creation
remains unsupported until separately reviewed native directory capabilities and
race-safe handle-relative creation exist.

## Relative CLIPRDR hierarchy is metadata, never path authority (R8 P2, 2026-10-17)

MS-RDPECLIP File List names can carry bounded relative components even when
`CB_FILECLIP_NO_FILE_PATHS` forbids disclosure of the source path. Treat those
components only as protocol structure. Keep native-facing file names leaf-only;
never return the relative string as a filesystem path, concatenate it with a
local directory, or reopen anything by name.

A hierarchy proof is valid only for one exact clipboard generation when every
node name is unique, every non-root immediate prefix names an explicit
directory descriptor, depth/count bounds hold and the parent graph is acyclic.
Failure is transactional for the hierarchy proof: no partial parent mapping is
visible. Flat descriptor-index streaming may remain usable independently.
Caller-selected local placement and verified remote parentage are separate
facts and may differ.

## R4 native framebuffer ingress is generation-fenced before dereference (2026-10-17)

Keep `FramebufferView` as the single shared platform/R4 framebuffer
representation. Native BGRA/BGRX ingress is a synchronous borrowed read:
top-left row-major bytes are B, G, R, ignored alpha; width and height exactly
match visible geometry; stride covers at least four bytes per visible pixel;
and the span covers every pitched row with checked arithmetic.

Platform capture owners retain their richer native generation/revocation rules.
A serialized composition owner may additionally bind a nonzero R4 capture epoch
with `openBgraCapture()`; advance it whenever the validated native capture
lifetime is replaced. Reject an epoch mismatch before reading source bytes.
Rebinding resets x264 reference history, so replacement/resize starts IDR.
Generic `open()` remains epoch zero for already generation-fenced synchronous
owners such as the current R6/R7 callbacks.

Conversion/x264/segmented ownership completes synchronously, so native mappings
may retire after successful preparation. Capture epochs are freshness
correlation only, never R2 authorization, R3 Graphics-DVC authority, scheduling
or publication receipts.

## Proof-bearing protected plaintext must not degrade to a Boolean (R3 P0, 2026-10-17)

When protected protocol plaintext is allowed to cross an ownership boundary
only after cryptographic verification, represent that fact with a type that
callers cannot synthesize. For CLIENT_LICENSE_INFO HWID, the production
decrypt+MAC routine alone may construct the move-only proof; raw bytes and a
`verified=true` parameter are not an API.

Consume the proof into one bounded non-overwriteable request owner. Copy exact
immutable protocol identity and correlation inputs transactionally, cleanse
sensitive plaintext/correlation on retirement, and make generation replacement,
disconnect and cancellation terminal. The request object carries provenance;
it does not inherit or manufacture the external policy authority that will
decide the request.

## Receipt-bearing move-only owners are not overwriteable (R4, 2026-10-17)

When a move-only object carries an unresolved receipt owned by another state
machine and does not itself own the authority needed to retire that receipt,
do not provide move assignment. Permit move construction into a fresh owner,
and require explicit completion/cancellation/abort before a caller reuses an
output slot. A failed prepare into an occupied slot must leave both the existing
owner and the target state machine unchanged.

## Completed multi-file presentation is metadata, not a transfer scheduler

Group only independently completed native file destinations. Do not add a
second FileContents scheduler or prefetch a whole set: the one
`RemoteTransfer` owner remains single-flight and files materialize
sequentially. A presentation set may retain bounded caller-selected local URI
metadata only after every member proves exact completion and current
generation.

Reject null/partial/stale members, duplicate local URIs, aggregate metadata
overflow and attempts to mutate the set behind one native clipboard ownership
transition. Derive native list formats from one canonical bounded representation
instead of retaining duplicate per-format lists. Never reconstruct directory
hierarchy or a local path from FILEDESCRIPTORW leaf names; absent an explicit
trusted destination mapping, hierarchy is unknown.

## Geometry-bound XI2 events need explicit generation provenance (2026-10-16)

A rebuilt XI2 observer must not accept an already-queued motion merely because
its extension opcode, event type and root window match the replacement
subscription. Record the successful subscription request sequence and reject
older XCB `full_sequence` values with bounded serial arithmetic. Keep a
synchronous replacement-time pointer query separate from queued event
provenance: it is a current-state snapshot, not an old motion notification.

## Native X11 resource IDs are not generation provenance (2026-10-16)

When an X11 child resource is retired and replaced on the same XCB connection,
do not use extension event type plus XID as the sole generation test for
already-queued events. Record a request-sequence floor after replacement
initialization and compare XCB's reconstructed `full_sequence` with bounded
32-bit serial arithmetic before accepting the event. This is especially
important across RandR geometry rebuilds where old native events may already be
in XCB's local queue when the new resource becomes valid.

## Windows standard-library limit calls must be macro-safe

A translation unit that includes `windows.h` may inherit function-like
`min` / `max` macros. Do not write unguarded
`std::numeric_limits<T>::max()` or `min()` there. Use
`(std::numeric_limits<T>::max)()` / `(std::numeric_limits<T>::min)()`,
preferably cached in a descriptive `constexpr` when reused. Do not change
global Windows-header macro policy merely to fix one call site.

## Windows completed files publish as CF_HDROP, never remote paths

When a fully materialized R8 Windows destination is handed to Explorer, bind the caller-selected fully qualified local UTF-16 path to the same destination capability at begin time. Never derive, append or resolve a local path from the remote FILEDESCRIPTORW name. Keep that local path hidden until exact-size materialization, final resize, flush and duplicate close have completed.

For one existing local file, use predefined `CF_HDROP`: encode a `DROPFILES` header with `pFiles` pointing at a double-NUL-terminated fully qualified Unicode file list and `fWide=TRUE`. Build the complete bounded payload before opening/emptying the clipboard. Transfer GMEM_MOVEABLE ownership only through successful `SetClipboardData`; free it on failure through the existing native seam. Do not use delayed rendering to trigger FileContents network work.

A local clipboard takeover wins. Use the existing WM_DESTROYCLIPBOARD/self-replacement fence and verify native ownership before replacing an R8-owned publication. Refuse stale destination generations. CF_HDROP publication is native presentation only and never creates CLIPRDR/R3 authority.

## Completed native file handoff must consume a completion capability

Do not let a caller publish an arbitrary local path/URL by passing a Boolean
that says a transfer finished. Native file-manager/pasteboard publication must
consume the concrete completed destination object that owns the materialization
lifecycle and verify its source generation still matches the one
`RemoteTransfer` owner.

Caller-selected local URL/path metadata must be bound to the native destination
capability before transfer and must never be derived from remote
FILEDESCRIPTORW names. Hide and erase that metadata while materialization is
partial or failed. Only exact-size, flushed, closed completion may expose it.

On macOS, write completed file URLs as `NSURL` objects through
`NSPasteboard.writeObjects:`; do not resurrect deprecated URL pasteboard
types or copy the file body into pasteboard memory. Reuse the existing
`MacClipboardAdapter` change-count ownership fence so file handoff cannot
become a second clipboard controller or steal a generation back after local
takeover.

## macOS clipboard file destinations are explicit descriptor capabilities

For R8 macOS file materialization, never derive a local filesystem path from a
remote FILEDESCRIPTORW leaf name. The native destination must be selected and
authorized by the caller as a writable regular file descriptor. Reject
`O_APPEND`; positional FileContents offsets must remain authoritative.

Duplicate the descriptor with `F_DUPFD_CLOEXEC` and own only that duplicate.
Write each already-validated RANGE synchronously with positional `pwrite`,
bounded by the existing 64-KiB FileContents request ceiling. Retain only fixed
metadata, receipt identity and progress; do not add a whole-file buffer or
secondary chunk queue. Unknown lengths continue to use the existing SIZE
request/result path.

Treat exact completion as a native publication fence: only after the expected
byte count is present, the file is truncated to that exact size, `fsync`
succeeds and the duplicate is closed may a higher native layer expose the file.
Generation replacement, cancellation, remote/protocol failure or native I/O
failure invalidates the partial destination and should truncate it before close
where possible. The native sink exposes request intents only and must never
serialize CLIPRDR or bypass R3 authorization.

## Windows clipboard file destinations are handle capabilities

For R8 Windows file materialization, never create a local path from a remote
FILEDESCRIPTORW name. The caller must supply a destination HANDLE selected by
the native UI/shell layer. Validate it as a disk, non-directory object and own
only a duplicate with the same access.

Keep `RemoteTransfer` authoritative for generation, FileContents stream IDs
and response receipts. A native destination may expose bounded SIZE/RANGE
intents and bind the exact receipt, but it must not serialize or send CLIPRDR.
Consume borrowed RANGE bytes synchronously and write directly to the native
destination; do not add a whole-file cache or second queue.

On Windows, duplicated handles share the underlying file object's position.
Confine the destination to one serialized thread and require the caller not to
perform concurrent file-position-sensitive I/O through the original HANDLE.
Use handle-based truncate/write/flush operations; never reopen by a remote name.
Until exact-size completion plus flush and duplicate close, the file is partial
and must not be published to a consumer.

## Native pointer identity is not ownership provenance

For COM and other reference-counted native APIs, decide cleanup from the
ownership event that produced a reference, not from pointer-value equality.
Two callback/API returns can own distinct references while exposing the same
interface address. Conversely, one reference transferred into an owner may be
reused under multiple local names without creating another release obligation.

Track transfer state explicitly for each returned reference. Release a candidate
unless that exact reference was transferred to the authoritative owner; do not
infer transfer from `candidate == retained`. Native fixtures should be able to
represent multiple outstanding references to one address and require the final
reference count to return to zero.

## Completed X11 file handoff never derives a path from remote metadata

For R8 X11 file-manager handoff, bind any local file URI at the same native
destination-capability boundary that receives the caller-selected descriptor.
The URI is caller metadata, never a conversion of FILEDESCRIPTORW names.
Accept only a bounded local `file:///...` URI, require percent-encoding for
spaces/non-ASCII bytes, reject controls/backslashes/query/fragment syntax and
remote authorities, and erase the URI on partial-transfer failure or cancel.

Do not advertise file-manager clipboard targets until the materializer has
reached exact-size `Complete` after final truncate, sync and duplicate close.
At that point the existing X11 clipboard owner may copy the URI into bounded
publication state. Publish `text/uri-list` with CRLF line termination (RFC
2483), GNOME/Nautilus `x-special/gnome-copied-files` as
`copy\n<uri>` without a trailing empty line, and KDE's supplemental
`application/x-kde-cutselection` value `0` for copy. These native formats
must never trigger CLIPRDR I/O.

File URI publication follows the same X11 ownership epoch as text/image. Local
owner takeover yields the remote generation and clears the file handoff; an
old completed file cannot reclaim CLIPBOARD for that same generation. Remote
generation replacement invalidates the URI even if the local file remains.
PRIMARY stays untouched.

Do not emulate XDG Desktop Portal FileTransfer with an X11 MIME payload. A
Wayland portal integration must use the real portal session and
`application/vnd.portal.filetransfer` contract when that runtime boundary
exists.

## Linux clipboard destinations are descriptor capabilities

For R8 Linux file materialization, a native destination descriptor is a
caller-selected capability, not a path derived from remote clipboard metadata.
Never concatenate or resolve a FILEDESCRIPTORW name into a local path. Accept
only writable regular files and reject `O_APPEND`: Linux append semantics can
defeat positional-write offsets even when `pwrite` is used.

Duplicate the caller descriptor with CLOEXEC and own only that duplicate.
Stream each already-validated FileContents RANGE directly with checked
positional writes; retain only fixed metadata and progress, never a whole-file
buffer or second range queue. Unknown sizes use the existing SIZE request.
Do not expose the destination to a consumer until the exact declared byte count
has been written, final size fixed, data synchronized and the duplicate closed.

Generation replacement, cancel, remote failure, local I/O failure or receipt
mismatch invalidates the partial destination. Best-effort truncate it before
closing, while leaving any already-submitted R8 request to the one
`RemoteTransfer` owner for cancellation/drain. A native destination exposes
request intents only; it never owns CLIPRDR serialization, R3 authorization or
TLS output.

## macOS pasteboard ownership is change-count fenced

For R8 macOS ready-data publication, keep `RemoteTransfer` as the only RDP
clipboard-generation/data owner. Publish only verified current-generation
representations; UTF-8 text may become the native string type, and only a
validated registered PNG may become `NSPasteboardTypePNG`. Never label
CF_DIB/CF_DIBV5 bytes as PNG merely because a native image consumer wants PNG.

Record the AppKit pasteboard change count after replacement and compare it
before any later clear/republication. A mismatch is local-owner takeover:
yield that remote generation and do not steal it back. On RDP generation
replacement, clear old immediate data only while the recorded change count
still proves ownership. If the count cannot be read, fail closed without
clearing somebody else's pasteboard. Native publication remains presentation
state, never R3 channel authority, and must not perform a synchronous network
fetch or wait.

## Win32 delayed clipboard rendering is never a network wait

For R8 Windows publication, do not use `WM_RENDERFORMAT` as the trigger for a
CLIPRDR fetch. Win32 delivers that message while the requesting application
holds the clipboard open, and the owner is expected to place the requested
format immediately without reopening the clipboard. Announce a delayed native
format only after the current `RemoteTransfer` generation already owns
validated bytes. Keep generation checks immediately before the synchronous
native copy; stale generations fail without publishing data.

For `WM_RENDERALLFORMATS`, open the clipboard, verify the configured owner
window still owns it, render only already-ready formats, then close. Transfer
`GMEM_MOVEABLE` ownership to Win32 only after successful
`SetClipboardData`; free it on failure. A local clipboard takeover suppresses
republication of the same remote generation. Native clipboard ownership is
presentation state, never R3 channel authority.

## R1-owned TLS application framing rule (2026-10-16)

When a higher protocol layer needs decrypted/encrypted application bytes from
an R1-owned accepted connection, it MUST call
`OwnedPreauthTcpConnection::readTlsApplicationData` /
`writeTlsApplicationData`. The `establishedTls()` borrow is
inspection-only and MUST NOT be used to invoke `SSL_read_ex`,
`SSL_write_ex` or handshake advancement outside R1.

A higher-layer framer may pin that borrowed SSL together with the exact
nonmoving R1 owner for synchronous certificate/provenance checks. Once
owner-bound, fail closed on owner substitution, direct-SSL I/O downgrade,
cancellation or selected-certificate change. Check owner validity before
dereferencing a retained SSL borrow after any possible teardown. Pending WANT
retries retain only operation identity and the same logical byte count inside
R1; higher layers retain their own stable bytes and never hand R1 a stored
caller span.

Native socket readability is not sufficient once OpenSSL has consumed a TLS
record. R1 alone may query its owned SSL for already-decrypted application
bytes and expose only a non-authorizing readiness fact. A scheduler may
perform one normal bounded application read without a new POLLIN only when
that R1 fact is true. Never use buffered plaintext to change a pending write
retry, bypass a WANT_WRITE direction, retain an SSL/BIO borrow, or advance
MCS before genuine R2 admission.

## Runtime connection aggregate teardown

When R10 composes a live connection from existing road owners, do not transfer
or duplicate their authority into a second session controller. A connection
aggregate may own the objects solely to enforce lifetime: R1 socket/BIO/SSL,
R2 GSS/native admission capability, and the one R3 session lifecycle.

Terminal teardown order is security-significant. Close/revoke R3 first while
R2 and R1 are still alive, then revoke/destroy R2 GSS and admission leases,
then release R1 TLS/BIO/socket last. Make this path idempotent and use it from
the destructor. Service-lifetime keytab/policy/SSL_CTX owners must outlive every
connection aggregate that borrows them.

## Credential object identity is not credential-content immutability

When a provider will reload security-sensitive bytes later, retaining a
validated read-only descriptor closes pathname TOCTOU but does **not** freeze
the inode contents. Do not treat descriptor identity as an immutable credential
snapshot. On Linux, copy the validated bounded credential into a private
anonymous file, verify the source did not change during the copy, seal the
snapshot against write/grow/shrink, and close the mutable source before later
provider loads. Fail closed when immutable snapshot support is unavailable;
never silently fall back to the original pathname or mutable descriptor.

Keep the immutable owner alive for every provider object that references its
procfd. Cleanse temporary credential-copy buffers. This rule is distinct from
authentication: loading an immutable server credential does not prove a remote
user or authorize an OS session.

## Reference-coded graphics publication continuity

For stateful video codecs, successful encode is itself a state transition:
the codec may reference that picture from later frames even before transport
accepts it. The single graphics owner must therefore check every deterministic
backpressure/generation/surface and packet-metadata denial before encode,
reusing the packetizer's canonical metadata validator rather than duplicating
its geometry/quant rules. If encode succeeds but
the corresponding frame cannot be transactionally reserved for publication,
discard/reinitialize codec reference history so the next accepted frame is an
independent refresh/IDR. Never continue a P-frame chain through an unsent or
ambiguously delivered reference. A terminal/partial transport abort likewise
invalidates codec history for that presentation generation.

A same-Graphics-generation R3 surface replacement is also a codec-reference
boundary. R3 remains the sole surface-ID owner; the stateful R4 encoder may
only observe the current mapped ID after all deterministic denials. When that
otherwise-valid ID differs from the last successfully prepared surface, rebuild
reference history before encode so the first accepted picture is independently
decodable (SPS/PPS/IDR for AVC420). Do not use this observation to mint a
surface, bypass R3's post-remap AVC420 gate, or create another ACK membership
owner.

A conclusively zero-byte withdrawal is a narrower transition than abort. Only
the exact pending delivery receipt may be canceled, and only after the
transport owner has independently proved cumulative accepted bytes are zero
and retired every borrow of the owned publication bytes. Successful
cancellation must invalidate that publication object and rebuild codec
reference history before another encode; if rebuild fails, revoke the
presentation rather than expose a mapped lifecycle through an unusable codec.
Do not accept a caller Boolean as transport proof, and do not apply this path
to positive or uncertain progress.

Keep this logic inside the one graphics owner/subordinate codec boundary, not
in a second scheduler or transport queue.

## Linux provider credential-file continuity

When a native provider API accepts a filename but R10 has already security-
validated a concrete credential file object, do not validate by pathname and
later let the provider reopen that mutable pathname. On Linux, retain the
opened descriptor and, where the provider supports ordinary FILE semantics,
hand it a `FILE:/proc/self/fd/<n>` reference while the descriptor remains
alive. The runtime owner must outlive every provider object configured through
that reference. Keep the original path only as configuration input, not as the
post-validation authority.

This continuity mechanism does not upgrade provider credential acquisition
into user authentication: acquiring a service keytab only proves the server
can load that acceptor identity. User identity and authorization still require
their existing TLS/GSS transcript and native OS policy owners.

# Coding standards — native C++23 RDP server

**Mandatory on every agent prompt:** [AGENTS.md](../AGENTS.md),
[VISION.md](VISION.md), the [living TODO](ROADMAP.md), and the
other three domain standards. Record new verified coding and protocol
lessons in this file; do not create a parallel coding-policy document.

## Standards-first protocol design

Microsoft's published RDP protocol definitions are the primary behavior
authority. For each wire change identify the specification, negotiation
capability, message ordering, bounds and negative test. Reject unsupported
or ambiguous inputs rather than inventing private protocol behavior or
copying xrdp-specific workarounds. A documented, version-identified client
exception requires failing evidence and a targeted regression.

Maintain explicit bounded transport, authentication, session, virtual
channel, graphics, input and clipboard state transitions. Keep wire/core
source independent of OS libraries and place capture/input/clipboard
integration behind distinct adapters. One authoritative owner per
connection/session and clipboard generation; no competing state machine.

## C++23 implementation and memory layout

- RAII for sockets, crypto, memory, files, handles, locks and callbacks.
  Prefer `std::unique_ptr` and deterministic lifetime; use shared
  ownership only when justified, no raw owning `new`/`delete`.
- Prefer contiguous `std::vector`, `std::array`, `std::span` over
  pointer-chasing node containers. Borrowed views may never outlive
  their buffer. Use allocation-free `std::string_view` format routing.
  `std::make_unique_for_overwrite<std::byte[]>` is suitable only when
  every allocated byte is written before use.
- Specify lengths, allocation limits, offsets, byte order, index and
  stride invariants. Check all overflow/conversions before arithmetic
  or buffer access, including untrusted PDU and image metadata.
- Cache fixed strides and lengths outside hot loops. Use `reserve`,
  moves, `emplace`, SIMD and `std::fma`/`std::fmaf` only when the
  result is correct and measurements justify it. Scalar paths remain
  the interoperability and numerical reference.
- Use human-readable names, narrow scopes, `constexpr`, `[[nodiscard]]`
  and documented invariants. Do not erase existing comments, rename
  public APIs or perform broad refactors without an explicit need.

## Concurrency, failure paths and security

Document session event-loop affinity, lock order and ownership.
Bound pending work, queue sizes, response payloads and timers.
Cancel and quarantine late responses on timeout, generation replacement,
disconnect or owner loss; stale data cannot be published in a new
session. Reject malformed DER/Unicode/frames; do not confuse successful
TLS/CredSSP parsing with OS session authorization.
Use fail-only logging, never credentials or user clipboard bytes.

GCC/Clang `-Wall -Wextra -Wpedantic -Werror`, MSVC `/W4`,
standard C++23, portable library first; no xrdp/VNC runtime.
Extend native tests for positive and negative cases and use sanitizers
where supported. See [testing_standards.md](testing_standards.md).

## Preserved lessons

CLIPRDR format response does not provide a universal wire request ID:
retain single-flight ambiguous requests and generation-aware bookkeeping.
X11 PNG delivery to a generic consumer does not prove Firefox obtained
a non-null synchronous image `File`. CLIPRDR file streaming is distinct
from RDPDR drive browsing; neither protocol intrinsically requires FUSE.
Record new facts here and update the same existing TODO.

## R8 capability-boundary lesson (2026-10-15; focused harness PASS)

MS-RDPECLIP 2.2.2.1 says Clipboard Capabilities is optional. Missing
General sets select zero flags (short-format names); General capability
`version` is informational and MUST NOT gate features. Parse bounded
sets, skip unknown length-valid types, reject duplicate/malformed known
sets, and enable features only when both endpoints explicitly advertise
the corresponding generalFlags. This state belongs in the one clipboard
generation owner and is reset on channel disconnect. R3 retains the
actual authorized channel and locally advertised capability authority.

## R8 static-channel envelope handoff (2026-10-15)

MS-RDPBCGR 2.2.6.1.1 requires an eight-byte `CHANNEL_PDU_HEADER`
before opaque static-channel clipboard data; the four-byte `length`
excludes that header. One uncompressed clipboard acknowledgment is
FIRST|LAST (0x3), not a bare CLIPRDR_HEADER sent directly as MCS
userData. Reuse R3's MCS joined-channel encoder and preserve
`RemoteTransfer` as sole clipboard generation owner. An MCS channel
join confirmation, even when fully written, is necessary but **not
sufficient** for authenticated, independently OS-authorized CLIPRDR
routing. Keep ownership of TLS send progress and cancellation in
R3's existing connection writer; never fabricate channel permission.

## R8 per-generation native clipboard prefetch candidates (2026-10-15)

MS-RDPECLIP Format Data Requests carry a format ID advertised
by the peer; ordinary responses have no request ID. Background
text/image selection MUST reuse the single pending request owner,
avoid unbounded repeat attempts, and drain an older generation's
pending response before fetching a new offer. Favor CF_UNICODETEXT
(13), named PNG, CF_DIBV5 (17), and CF_DIB (8) respectively.
A completed fetch is not ready for OS paste until bounded media
validation, conversion and native lifetime/ownership checks succeed.
An actual paste must not be starved by speculative background work.

## R8 outbound clipboard write lifecycle (2026-10-16)

MS-RDPECLIP 2.2.5.1 requests one actually advertised format ID,
and MS-RDPBCGR 2.2.6.1.1 requires an eight-byte static-VC header
before it is sent in a T.125 MCS SendDataIndication. Prepare
the full envelope transactionally before committing the
single-outstanding CLIPRDR request state. Serialization success
is neither R2/R3 admission nor TLS acceptance. The sole authorized
writer owns output until a complete send receipt is observed;
a zero-byte never-submitted request may be revoked, but any partial
or uncertain send must fail closed because the response has no
wire request ID. Keep delivery sequence receipts monotonic
across reconnect to reject stale callbacks, and drain old
generation's replies without handing them to a newer format.
No second clipboard controller, writer, or packet queue.

## R8 nonblocking paste receipt lifecycle (2026-10-16)

Keep native paste waiting state in the same generation-owning
`RemoteTransfer`, not in a second clipboard state machine. Use a monotonic
caller-supplied deadline and receipt sequence that remains monotonic across
disconnect. Event-loop code must never sleep, wait on a condition variable or
poll an OS clipboard. A live paste blocks *new* speculative prefetch, but an
already-sent ordinary Format Data Request cannot be cancelled or overtaken
after ambiguous delivery because its response carries no request ID. Drain it
first, then service the live request. Preserve the exact native receipt across
ready, timeout, replacement, owner loss, disconnect and channel-error outcomes;
reject stale native callbacks by sequence. Terminal native outcomes do not by
themselves grant R3 channel authority or poison sound CLIPRDR state.

## Native clipboard implementation rules (2026-10-14; design, NOT RUN)

Use [MS-RDPECLIP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeclip/8bb14d95-fcfa-45e9-b822-f97b129ff208)
(CLIPRDR) for text, image format data and copied-file streams.
[MS-RDPEFS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/)
(RDPDR) is separate optional redirected-file-system access, not the
prerequisite for clipboard file paste. Preserve one first-party portable
clipboard session owner and OS-specific adapters; extend the existing
`RemoteTransfer` generation/format-request coordinator rather than duplicating
it. No xrdp/FreeRDP runtime, FUSE mount or file-cache daemon is required.

- **Announcement is not data:** a client's Format List is only an offer.
  Client focus or OS clipboard privacy rules may delay an offer (observed
  with Windows App on macOS); the server must not assume an unadvertised copy
  exists or bypass client permission. For each advertised generation retain
  separate offered/requested/receiving/ready/failed state. Registered formats
  such as `PNG` and `FileGroupDescriptorW` map by *name*, not globally
  stable numeric IDs. The ordinary Format Data Response has no request ID:
  serialize requests; drain old-generation replies before advancing; if a
  timeout makes matching ambiguous, fail closed/reset the channel instead of
  assigning stale data to a new generation.
- **Prefetch policy:** after a legitimate offer, boundedly prefetch
  `CF_UNICODETEXT` and preferably PNG for images; if needed, request
  `CF_DIBV5` or `CF_DIB` and convert using checked dimensions. Prioritize
  an actual paste over speculative requests. Store only validated,
  compressed image content (and limited text) per current generation;
  lazily decode/convert to consumer formats and cap decoded pixel memory,
  CPU time and queued work. Never serve partial/stale payloads. Prefetch
  may move clipboard contents before paste: expose an explicit session
  clipboard-sharing policy and avoid secret-bearing logs.
- **Waiting must make progress:** X11 `SelectionRequest`/INCR, CLIPRDR
  channel I/O and worker completion are asynchronous. Retain each waiting
  paste request with a deadline; advance unrelated desktop/session events
  while fetching/converting, then complete it or report failure.
  `std::this_thread::sleep_for` or blocking condition-variable waits on the
  event thread can deadlock the very transfer being awaited. A dedicated
  worker may wait on a condition variable with cancellation and timeout.
- **Selection ownership:** on X11 monitor `CLIPBOARD` with XFixes,
  selection timestamps and owner identity; do not seize `PRIMARY`.
  Publish an actual remote generation once and relinquish to local
  applications or clipboard managers without timer-driven reclaiming.
  Ignore self-origin changes, suppress loops using origin/generation
  and handle owner loss while an INCR transfer is in flight. Wayland,
  macOS and Windows use their own native data-offer/clipboard APIs.
- **File transfers:** CLIPRDR `FileGroupDescriptorW` metadata and
  `CB_FILECONTENTS_REQUEST/RESPONSE` ranges use a distinct `streamId`;
  validate indices, 64-bit sizes/offsets, path traversal, cancellation
  and chunk limits. Negotiate file locks where supported; release on
  completion/disconnect. Cache metadata and bounded buffers only, not
  whole files. A desktop file manager may still require a usable local
  file URI, file descriptor or portal adapter; do not claim wire-level
  streaming alone solves that OS integration.
- **Browser criterion:** a successful X11 `image/png` selection read
  is not proof of a Firefox `DataTransferItem` file. Require actual
  synchronous `paste` event inspection with non-null
  `getAsFile()`, MIME `image/png` and matching screenshot contents.

## TCP intake implementation decision (2026-10-14)

RFC 1006 treats TCP as a byte stream, **not** as a sequence of complete
TPKTs. `PreauthConnectionStream` therefore buffers no more than the
initial 260-byte X.224 CR, validates the four-byte length before copying
the rest, returns the exact consumed prefix and leaves any coalesced
TLS data to the caller. Invalid framing terminates the diagnostic;
unsupported proposals use the existing protocol-defined negotiation
failure before closing. The caller must send the whole X.224 Confirm
**before** handing the stream to TLS; no app-data authorization occurs.
Avoid a second transport/session state owner or speculative network
listener until a real TLS and session admission boundary exists.

## X.224 send-before-TLS invariant (2026-10-14)

An X.224 Connection Confirm must be fully transmitted **before** the
external security provider begins TLS (MS-RDPBCGR 3.3.5.3.2).
The single `PreauthConnectionStream` state owner now requires exactly
one `onConnectionReplySent(true)` acknowledgment before allowing
`onTlsHandshake`. Transport adapters must report success only after
the full response was written; partial send, false completion and
duplicate acknowledgment fail closed. A caller-provided bool is still
only an internal test signal and does **not** establish real TLS,
CredSSP or session authorization.

## TLS-record independent MCS framing (2026-10-14)

The decrypted stream from a TLS provider has **no RDP TPKT message
boundaries**. Feed it to the existing single-owner preauth stream
rather than assuming one TLS read equals one Basic Settings Exchange
PDU. MS-RDPBCGR 2.2.1.3 encodes the initial MCS/GCC request inside
a 4-byte TPKT plus a 3-byte X.224 Data TPDU. Validate TPKT
version/reserved/length (bounded to 8,192 bytes), then X.224 before
buffering BER; consume only the first envelope. Reuse the preauth
storage and zero its occupied bytes after close. No parser evidence
alone implies authenticated session admission.

## OpenSSL server TLS evidence boundary (2026-10-14)

Per MS-RDPBCGR 5.4 Enhanced RDP Security and 3.3.5.3.2,
the X.224 Confirm must be **fully sent** before entering the
external TLS provider. An arbitrary `bool completed` from a future
socket adapter is not sufficient evidence that a TLS server handshake
happened. The single `PreauthConnectionStream` owner now checks a
borrowed OpenSSL `SSL*` for **server role**, completed handshake,
TLS version 1.2+, negotiated cipher, and selected certificate before
advancing to the diagnostic MCS parser. Only a *borrowed* `SSL*`
is accepted; lifetime, encrypted network I/O, certificate provisioning
and cancellation remain caller-owned. A TLS handshake alone does not
authenticate OS accounts or approve an RDP desktop session.

## OpenSSL / Windows C++ header hygiene (2026-10-14)

Including OpenSSL's full `ssl.h` in a public portable C++ header
can transitively introduce platform macros such as `min` on MSVC.
Use only `openssl/types.h` in a public header when borrowing
`SSL*`, and include `openssl/ssl.h` privately in implementation
and actual TLS tests. Where a Windows compatibility macro can still
interfere, write `(std::min)(...)` to call the standard function
without macro expansion. The failure was at the compiled native
transport boundary; maintain `/W4` and do not skip Windows CI.

## First decrypted TLS application-record bridge (2026-10-14)

MS-RDPBCGR sections 5.4.2.1 and 3.3.5.3.2 place the MCS Connect
Initial in the established TLS channel. The existing preauth stream
now holds a borrowed pointer **identity** to the previously verified
server-side SSL session, preventing a caller from substituting an
unrelated TLS object on the new read path. Limit `SSL_read_ex` to
the next TPKT boundary; OpenSSL may internally decrypt coalesced TLS
application records, but the parser MUST NOT consume later RDP
PDUs. A retryable WANT_READ/WANT_WRITE requires transport event-loop
progress, not a busy loop. Missing SSL, wrong role/identity, EOF and
malformed framing always fail closed. The caller owns the TLS
provider, BIO/socket lifetime, encrypted network pump and cancellation;
no ownership of SSL or authenticated OS identity is transferred.

**Verified on hosted systems:** the borrowed-SSL read path and bounded
TPKT-preserving algorithm at `a226f15827e9da48ad7a91b7cfa53528c3498802`
passed [Actions run 38557465241](https://github.com/k1moradi/RDP-server/actions/runs/38557465241)
on Ubuntu, macOS and Windows. Keep network I/O cancellation and
user authorization separate from validated TLS record decoding.

## Real nonblocking X.224 send progression (2026-10-14)

MS-RDPBCGR 3.3.5.3.2 requires the server to send the X.224
Connection Confirm before invoking external TLS and to send
RDP Negotiation Failure before closing. The former boolean
`onConnectionReplySent(true)` could be misreported after a
partial socket write, violating that ordering. Use the sole
connection owner's `pendingConnectionReply()` suffix and
`onConnectionReplyBytesWritten(n)` event to account for exactly
the bytes accepted by the OS. Zero-byte progress does not advance;
over-count, replay, invalid state and hard I/O failure close
without TLS admission. The rejected-security path may drain
the error PDU while remaining terminal. No duplicated send
state, separate controller, socket listener or private protocol.

**Verified:** implementation commit `98f6fdc60d513d47a87a78fadf1aa6be387da28b`,
[Actions run 38561127854](https://github.com/k1moradi/RDP-server/actions/runs/38561127854)
passed GCC/Linux, Clang/macOS, MSVC/Windows, documentation-policy,
all Debug/Release CTests, SDK consumer and packaging checks. This
does not yet establish live network service or OS user admission.

## Borrowed platform socket transport boundary (2026-10-14)

Keep OS socket system headers inside the thin
`nonblocking_tcp_adapter.cpp` implementation. The portable interface
reports progress, would-block, EOF and hard failure explicitly;
byte counts larger than the exact span offered are invalid. A
preauth TCP read MUST request only the next needed TPKT header/body
bytes (4 then length-4, at most 260 total) to avoid accidentally
consuming a coalesced TLS ClientHello before the security reply
is fully sent. A send MUST use only the owner's pending reply
suffix and acknowledge exactly bytes written. On Windows the socket
owner initializes Winsock, on BSD/macOS protects against SIGPIPE,
and everywhere configures nonblocking mode, event readiness, lifecycle
and close. The portable static library does not open a listener or
authorize OS access.

**Verified cross-platform:** implementation SHA
`dd3a806f97b13e6db18affd689c6321bfa009813`,
[Actions run 38563789698](https://github.com/k1moradi/RDP-server/actions/runs/38563789698)
passed the Debug/Release portable protocol suite, downstream SDK
consumer and packaging gates on Linux/GCC, macOS/Clang and Windows/MSVC,
plus documentation-policy. Native socket syscalls were compiled but
actual connected native socket traffic is not covered by this test;
do not infer live server or user authentication.

## Synthetic certificate ownership on OpenSSL 3 and 4

Do not assume `X509_get_subject_name` yields writable storage:
OpenSSL 4.0.3 returns a const name. The native TLS test fixture
should own a separate mutable name via RAII `X509_NAME_new` and
install it through `X509_set_subject_name` and
`X509_set_issuer_name`, then sign. Do not use `const_cast`,
weaken assertions, silently pin OpenSSL to hide a compiler
error, or confuse test self-signed certificates with
trusted production credential management.

**Post-fix evidence:** `5c4f3ad7273d17948327b7d351ff9840de2b0395`,
[CI run 38564403002](https://github.com/k1moradi/RDP-server/actions/runs/38564403002)
passed Linux, macOS and Windows Debug/Release tests and SDK gates.
The successful macOS runner selected OpenSSL 3.6.4, so OpenSSL
4 compile compatibility after the RAII fixture change remains
unverified until an explicit 4.x compile is recorded.

## Nonblocking TLS readiness and borrowed SSL identity (2026-10-14)

Keep server-side TLS handshake progression on the **same**
`PreauthConnectionStream` that tracks X.224 Confirm output and
will parse the first MCS/GCC frame. `SSL_do_handshake` must be
invoked **once per ready event**, and its `SSL_get_error` checked
immediately on a failed result. WANT_READ and WANT_WRITE are
retryable without inventing a timer or spinning. The first
server SSL pointer is borrowed until success/cancellation,
so another OpenSSL handle cannot take over a partially
started handshake. Full reply-write acknowledgement remains
mandatory before the first TLS operation. Provider cancellation
clears the SSL pointer and buffers; neither cryptographic
transport completion nor a temporary self-signed test
certificate authorizes a real user or OS session.

**Verified cross-platform:** the one-owner nonblocking TLS
handshake API at `fcd05f8e903a459ca85f13807bd35f7091f3fd70`
passed [Actions run 38566584099](https://github.com/k1moradi/RDP-server/actions/runs/38566584099)
on Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy,
with **25** Debug/Release CTests and per-OS package verification.
Keep certificate trust, live sockets and identity authorization
independent of this in-memory protocol handshake evidence.

## Nonblocking OpenSSL BIO over native socket adapter (2026-10-14)

OpenSSL permits custom nonblocking `BIO_METHOD` operations through
`BIO_meth_set_read_ex`, `BIO_meth_set_write_ex` and retry flags.
Map the existing borrowed `TcpNonblockingIo` exactly: positive
counts no greater than the offered span progress; WouldBlock sets
the matching BIO read/write retry bit; FIN, errors, invalid counts
and zero-success never count as progress. Use `SSL_set_bio` once
to transfer the BIO into SSL; it MUST NOT transfer ownership of
the socket or adapter. Verify no previous BIO/handshake exists.
This avoids narrowing Windows SOCKET handles and keeps
platform-native headers out of the protocol core. Avoid
spin-polling inside production TLS callbacks; one handshake
operation is driven per event-loop readiness event. Test-only
port-zero IPv4 loopback connections must be short-lived, bound
to 127.0.0.1 only and must never authorize an OS desktop session.

**Verified native BIO loopback boundary:** the implementation
`7ce64737ccef439af2f0cfd383208181cc0e9513` passed
[CI run 38579350917](https://github.com/k1moradi/RDP-server/actions/runs/38579350917)
on GCC/Linux, Clang/macOS and MSVC/Windows, including
Debug/Release 27 registered CTests and SDK consumer/package gates.
Short-lived native TCP loopback traffic and encrypted OpenSSL
records were exercised; user authorization and real external
RDP client interoperability are NOT RUN.

## MS-RDPBCGR/T.125 MCS domain merge (2026-10-14)

For Connect-Initial processing, follow Microsoft's published
[MergeDomainParameters algorithm](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7617f746-95c9-4a6e-808d-e2f642471e86)
rather than assuming the target set can be copied to the server
response. Apply the precise minimums (four channels, three users,
one priority and one domain hierarchy level), bounds on
maxMCSPDUsize, and effective protocolVersion 2. The minimum and
maximum protocolVersion BER fields are individually legal without
being 2; reject when their range cannot negotiate 2. Reject any
merge failure **before** channel/domain allocation or a response;
return an empty value so callers cannot reuse partial negotiation
state. A successful merge does not authenticate credentials or
authorize an OS session. Never allocate according to client
advertised 32-bit quantities without a later independent budget
and real-user admission gate.

## T.125 BER / T.124 PER Connect-Response encoding (2026-10-14)

Use the canonical wire formats from
[MS-RDPBCGR 2.2.1.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/927de44c-7fe8-4206-a14f-e5517dc24b1c)
and its annotated 4.1.4 example: APPLICATION 102 `7F 66`,
BER ENUMERATED success `0A 01 00`, zero calledConnectId,
merged eight-field DomainParameters encoded as minimal
nonnegative BER INTEGERs (include sign-protecting zero octet),
and an OCTET STRING holding GCC ConferenceCreateResponse.
Use bounded nonfragmented PER length, legal GCC nodeID
1001..65536 offset and H.221 key `McDn`.
Only Enhanced TLS is currently supported; `SC_SECURITY`
encryption method/level must both be zero with NO legacy
server random or RC4 proprietary server certificate.
`SC_NET` channel IDs must match client-requested count,
be nonduplicated, and obey the merged channel limit; odd
counts need two padding bytes. The serializer must not
own channels, admit users, send to a live peer, or reuse
a partial packet after rejection.

## T.125 channel-connection PER syntax-only boundary (2026-10-14)

For MS-RDPBCGR sections
[2.2.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/04c60697-0d9a-4afd-a0cd-2cc133151a9c),
[2.2.1.6](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f5d6a541-9b36-4100-b78f-18710f39f247)
and
[2.2.1.8](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/64564639-3b2d-4d2c-ae77-1105b4cc011b),
reuse the existing `parseDataTpdu` validator for exactly one
complete TPKT. Recognize aligned PER DomainMCSPDU choice octets
0x04, 0x28 and 0x38; reject other directions/types and extra
data. For Erect, require both bounded, present PER INTEGER
values with canonical lengths. For Join, decode UserId as the
big-endian wire offset + 1001 with overflow protection, but
never infer that the user or requested channel has been
allocated or joined. Even a syntactically valid out-of-domain
channelId must be checked by the future authenticated domain
owner. Do not fork the MCS parser or create a competing
session or channel controller.

**Verified parser boundary:** the strict T.125 Erect, Attach and
ChannelJoin decoding increment at
`6effdb76229e2514511ebe5dd8cb404841403b1b` passed
[Actions run 38588538653](https://github.com/k1moradi/RDP-server/actions/runs/38588538653)
on GCC/Linux, Clang/macOS and MSVC/Windows, including full
Debug/Release **37 CTests** and SDK gates. An early incorrect
PER test-vector length was corrected without changing the
strict decoder; do not interpret this as authenticated domain
or channel admission.

## Offline MCS Attach/Channel success encoding (2026-10-14)

Follow T.125 BASIC aligned PER semantics and the exact server
wire samples of [MS-RDPBCGR 4.1.7](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3b3d850b-99b1-4a9a-852b-1eb2da5024e5)
and [4.1.8.2.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7443e65e-3482-4cec-823a-741eb1fe27b4):
`2e 00 [UserId offset:2]` and
`3e 00 [UserId offset:2] [requested:2] [channelId:2]`,
framed with exact TPKT and X.224 bytes. Never choose, reserve,
attach, or join identifiers in a serialization function.
Fail closed on assigned UserId outside 1001..65536, a
mismatched client initiator, wrong request variant, unallocated
or multiply listed requested channel, or empty/oversized
allocation list. The future authenticated domain controller
must perform an independently audited admission before using
any positive response on a socket. Synthetic tests and
caller-provided lists are not identity evidence.

**Cross-platform evidence:** offline Attach User Confirm and
Channel Join Confirm encoders at
`4eb3bff4f9fc15cb72da1b8e994ec89e7e9a96db`
passed [CI 38590263498](https://github.com/k1moradi/RDP-server/actions/runs/38590263498)
on GCC/Linux, Clang/macOS and MSVC/Windows, with
Debug/Release 39 named CTests, documentation-policy and
installed SDK consumer/package gates. This does not prove
any identity, host admission, channel allocation or
actual RDP client acceptance.

## MCS disconnect PER encoding and lifecycle ownership (2026-10-14)

Under [MS-RDPBCGR 2.2.2.3/4.2.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/19a238a5-0455-46f0-a96b-31320d9a70a1)
the complete Disconnect Provider Ultimatum is nine
TPKT/X.224/aligned-PER octets, and its two-bit reason
straddles the final octets. The pure server encoder may
emit only reasons 1 (provider initiated) or 3 (user requested);
all invalid enum values return no packet. The receiving
server must ignore all four two-bit reason values, while
rejecting invalid TPKT lengths, choice/extension bits,
and nonzero PER padding. No heap, second owner, new protocol
transport, or session policy in this primitive. Only
the one future authenticated TLS owner may transmit the
entire encrypted PDU and close after write completion.
Offline wire correctness is not an RDP disconnect acceptance.

## Bounded zero-copy MCS Send Data Request (2026-10-14)

Keep T.125 client SendDataRequest in the existing
`parseMcsChannelRequest`, reusing the canonical checked TPKT/X.224
envelope validator. Per MS-RDPBCGR 4.1.16, choice 25 (0x64)
has a PER initiator offset +1001, channelId, two-bit priority
and segmentation, four zero padding bits, and userData carried
as an aligned-PER OCTET STRING.

Check bounds for every field before reading. Accept both short
7-bit and long 14-bit PER length determinants (including long
form for a short payload, for real-client interoperability);
reject fragment determinants, inconsistent lengths, TPKT
surplus, invalid padding and initiator overflow. A single
PER userData field is at most 16383 bytes. Return a borrowed
`std::span<const std::uint8_t>` without copying, with lifetime
tied to the caller's unchanged complete packet. The owning TLS
read buffer must not be reused while that view is consumed.
No worker-thread handoff or cached span is safe without a
separate, explicit owned snapshot and bounded lifecycle.

These syntax fields do not indicate authentication, channel join,
complete fragmented messages or eligibility for clipboard,
graphics or OS input. Only the future single authenticated
session owner can verify transport, identity and channel rights
before dispatch; the parser never performs admission.

## Offline server MCS Send Data Indication (2026-10-15)

MS-RDPBCGR 1.3.1.1 and 2.2.6.1 require server-to-client
post-channel traffic to use T.125 `SendDataIndication`
(DomainMCSPDU choice 26, 0x68), never the client's
`SendDataRequest` choice 25 (0x64). Reuse the original
`mcs_channel_connection` module for this encoder; do
not create a parallel session controller. Emit one full
TPKT/X.224/aligned-PER frame into caller-provided
`std::span<std::uint8_t>`. Require valid UserId
1001..65536, nonzero caller-supplied channel, two-bit
priority and segmentation, and unfragmented PER userData
at most 16383 bytes. Use one short determinant below 128
and a two-octet determinant from 128; validate output
capacity BEFORE writing any byte. The caller can pass
input overlapping output: use a single `std::memmove`
for the opaque payload BEFORE writing its header, so no
source bytes are destroyed. Do not allocate or touch any
output suffix. Failure must leave the entire destination
unchanged. Only authenticated owner-supplied authorization,
TLS provenance and joined MCS state may allow actual
SSL transmission; this encoder never grants permission.

## Server Demand Active writer: validate before mutation (2026-10-15)

MS-RDPBCGR 2.2.1.13.1.1 and 3.3.5.3.13.1 require
the outbound server Demand Active Share Control PDU
with source pduSource=1002, type/version 0x0011,
LE16 totalLength/sourceDescriptorLength/combinedCaps,
caller-supplied shareID and sessionId, a counted
sequence of TS_CAPS_SET, and no Share Data header.
Reuse the original `mcs_channel_connection` module.
Use the SAME first-party helper to validate all
capabilitySetType/lengthCapability envelopes on
both inbound and outbound paths: each envelope is
at least four bytes; count and declared data sizes
must consume exactly the concatenated input.

Validate descriptor and combined lengths against
LE16 maxima, full packet <=65535, reject
`totalLength=0x8000` because that value means a
must-ignore FlowPDU, check output capacity and
input/output overlap BEFORE any destination mutation.
The two independent opaque input spans must not
overlap the destination region being written:
reject rather than risk corrupting yet-unread bytes.
Do not allocate internally; preserve unused suffix
and leave output completely unchanged on rejection.
Empty/unknown capabilities are accepted as framing
only, NEVER as a negotiated or supported server
graphics/clipboard/input feature. This offline
encoder does not perform TLS or MCS writes and
cannot bypass the genuine security/OS admission gate.

## Correlate activation transcript without granting authority (2026-10-15)

For the T.128 Demand Active -> Confirm Active exchange,
reuse the existing `parseRdpActivePdu` twice in the same
first-party transport translation unit. Confirm must be
type 3 with originatorID=0x03EA and sender pduSource
equal to the separately assigned 16-bit client user ID.
Demand must be type 1 with normative server
pduSource=0x03EA; the 32-bit share IDs MUST match.
Refuse user IDs below 1001 and beyond 65535 before
any narrowing conversion; a T.125 65536 initiator
cannot be represented by 16-bit Share Control source.
The complete input boundaries, opaque capability counts
and lengths remain the parser's responsibility. Do not
introduce a second parser, activation controller, cache,
heap allocation or TLS send. Return only
`ConsistentSyntaxOnly` or `Rejected`, never a
privileged, authenticated or session-admitted result.

A successful syntax correlation MUST NOT authorize
the OS account, prove client originator channel
membership, compare negotiated capability contents,
satisfy licensing, advance the live state machine,
or grant desktop graphics/input. The assigned-client-
user-ID argument is caller-supplied syntax, not
independently verified MCS identity. Only one later
genuinely Kerberos/TLS-bound, independently OS-approved
session owner may enforce those separate decisions.

## Checked Demand/Confirm Active capability envelopes (2026-10-15)

MS-RDPBCGR 2.2.1.13.1.1 (Demand Active) and 2.2.1.13.2.1
(Confirm Active) use distinct fixed prefixes after the shared
six-byte TS_SHARECONTROLHEADER. Demand has LE32 shareID,
LE16 source length, LE16 combined-capabilities length,
source bytes, LE16 count + ignored LE16 pad, N capability
sets and exact terminal LE32 sessionId. Confirm adds an LE16
originatorID=0x03EA after shareID but has no sessionId.
The combined length INCLUDES count + pad, NOT sourceDescriptor.
Every TS_CAPS_SET is at least 4 bytes, with LE16 type and
LE16 lengthCapability INCLUDING those four bytes. Validate
fixed prefix sizes, all source/combined/subcap boundaries
using remaining-span subtraction, reject cap counts that
cannot fit even four-byte headers, demand exact consumption,
and never accept truncated or surplus bytes. Avoid heap
allocation and return only caller-lifetime borrowed spans.

Unknown TS_CAPS_SET types MAY be preserved as opaque
envelopes; the published Microsoft Demand Active packet
contains a four-byte FONT set that is malformed against
its ideal typed schema but valid as a four-byte envelope.
Do not pretend envelope recognition negotiates font,
bitmap, AVC420 or any capability. Ignore pad2Octets.
A valid Confirm originatorID=1002, sourceID or shareID
is untrusted syntax, not MCS permission, authenticated
identity, share admission or license acceptance. Only
the single future owner may validate direction,
session-specific shareID, the *contents* and required
sets, active TLS-bound GSS, independent OS policy and
ordering before any real activation or input.

## Fail-closed server finalization serialization (2026-10-15)

MS-RDPBCGR 2.2.1.14.1, 2.2.1.15.1, 2.2.1.19,
2.2.1.20 and 2.2.1.21 govern server-side
Synchronize, Control Cooperate and Control Granted.
Implement these fixed-size uncompressed Share Control
and Share Data packets in the SAME existing C++23
`mcs_channel_connection` owner. Reuse one private,
allocation-free writer for the common 18-byte Share
Control/Data header with pduSource=1002, protocol
version/type=0x0017, caller shareID, explicit
uncompressedLength, canonical zero pad and compression
flags. Synchronize is 22 bytes, stream 0, type2 0x1f,
messageType=1 and an uninterpreted LE16 targetUser.
Microsoft's uninitialized Server Synchronize targetUser
example forbids assuming that a valid value proves
assigned membership. Control is 26 bytes, stream 2,
type2 0x14, valid server actions ONLY Cooperate (4)
and Granted Control (2). Cooperate requires zero
assignedClientUserId and writes grant/control IDs 0/0;
Granted requires 1001..65535, writes that user ID
and server channel 1002. Reject Request Control, Detach,
out-of-range user IDs, unknown actions, and short output
capacities BEFORE touching any output octet. Preserve
caller output suffix and perform no heap allocation.

Never interpret a valid emitted Granted Control packet
as an OS permission, MCS join result, successful GSS/TLS
authentication, licensing result or share activation.
Real message ordering, TLS output and resource access
belong only to a future separately authorized session
owner. These offline writers do not form an independent
state machine or encryption layer.

## Pure finalization PDU syntax is NOT an activation controller (2026-10-15)

MS-RDPBCGR 2.2.1.14.1 and 2.2.1.15.1 define small,
fixed-size T.128 finalization messages. Extend ONLY the
first-party `mcs_channel_connection` Share Data parser,
not a new state manager. `TS_SYNCHRONIZE_PDU` requires
exactly four body octets, type2 SYNCHRONIZE 0x1f and
little-endian messageType 1; its targetUser LE16 is
untrusted channel metadata. `TS_CONTROL_PDU` requires
exactly eight body octets, type2 CONTROL 0x14, and
LE16 action 1=Request, 2=Granted, 3=Detach or
4=Cooperate, followed by LE16 grantId and LE32
controlId. Reject truncated, coalesced, malformed,
wrong-type, unsupported compressed and invalid
action/message-type packets before returning any
success-shaped structure. Reuse existing nested
Share Control/Share Data strict framing, compression
denial and stream compatibility; no temporary
buffer, heap allocation, or parallel dispatcher.

This layer MUST NOT treat a syntactically valid
GrantedControl action or a targetUser/grantId/controlId
as proof of joined MCS ownership, actual sender
direction, negotiated active share or OS control.
Microsoft's Client Cooperate/Request Control requires
zero grantId/controlId; Server Granted Control uses
assigned UserId and the server channel, but those
directional/session-specific requirements must be
verified by the one authorized connection owner
AFTER genuine CredSSP TLS binding, OS admission,
security-header handling, licensing and capability
negotiation. Do not synthesize a server Granted
Control reply in a parser, emit TLS or admit input.

## Fail-closed T.128 Share Data Header decoding (2026-10-15)

MS-RDPBCGR 2.2.8.1.1.1.2 describes 12 data-header octets
following the canonical six-byte Share Control Header.
Reuse the existing exact-length Share Control parser, then
require kind=Data and at least 12 remaining header bytes
before reading LE32 shareID, ignored pad1, streamId,
LE16 reported uncompressedLength, type2, compression
flags and LE16 compressedLength. Permit the 24 documented
type2 values, streams 1/2/4 and stream 0 ONLY with
SYNCHRONIZE type2 (0x1f). Unknown values fail closed
with no borrowed body. Propagate FlowPDU ignored status,
rather than converting an ignored packet to a Data PDU.

The published Microsoft Client Font List sample contains
an uninitialized uncompressedLength. Keep that field as
metadata, NOT a length check or allocator. The enclosing
Share Control totalLength is the real validated frame
boundary. Likewise pad1 MUST be ignored (real packets
contain nonzero bytes), and in uncompressed mode the
compressedLength is metadata, never an allocation or
payload boundary. Until authenticated decompression and
history ownership exist, reject EVERY nonzero
compressedType (including compressed, flushed and at-front
flags). Never misroute compressed payload to an uncompressed
Data PDU handler. Return a zero-copy borrowed span only
for valid, explicitly isolated, uncompressed Data PDUs.

Actual MCS, TLS, license, security header, active share,
joined channel and independently authenticated OS identity
are mandatory, separately verified future admission gates;
none is inferred from pure Share Data syntax.

## Strict offline T.128 Share Control Header (2026-10-15)

Follow [MS-RDPBCGR 2.2.8.1.1.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/73d01865-2eae-407f-9b2c-87e31daac471):
the six bytes of `TS_SHARECONTROLHEADER` consist of LE16
totalLength, LE16 pduType (12-bit protocol version and 4-bit
type) and LE16 pduSource. The only five documented type values
are 1, 3, 6, 7, and 10; `TS_PROTOCOL_VERSION` must be 1.
Reject any incomplete, coalesced or size-inconsistent complete
input. Distinguish `totalLength=0x8000` as a *must-ignore*
T.128 FlowPDU, not as a request to allocate 32768 bytes and
not as an application message. Do not hand out a borrowed
body for ignored, malformed or unknown frames. Accept source
ID as uninterpreted; a parsed header never proves a negotiated
share, valid channel or account.

The caller must already identify the Share Control PDU after
MCS, optional Security Header, and any negotiated security/
licensing routing. Never assume unclassified MCS userData is a
Share Control PDU. No nested Share Data, compression, capability,
RDPGFX, virtual channel, clipboard or user input interpretation
belongs in this pure parser. Use one checked, borrowed `std::span`
into the full original input, no buffer copies or allocations;
the owning input must remain alive until all views are consumed.

## Strict bounded CredSSP DER framing ownership (2026-10-14)

MS-CSSP 2.2.1 specifies DER TSRequest messages on TLS;
use the existing parser rather than another DER validator.
The first-party `TsRequestFrameReader` is a *framer*,
not a duplicate session authority. Read exactly tag and
length (DER short, 0x81 or 0x82 canonical lengths), reject
indefinite/fragmented/nonminimal/oversized forms before
buffer allocation, and never consume bytes of a coalesced
following TSRequest. Hold sensitive, opaque token bytes
in at most the existing 16 KiB fixed array; borrow views
only until explicit release and cleanse on every cancel
or discard. A complete frame must not be overwritten by
unexpected new input, even when the next input is itself
syntactically valid. Reject an invalid first tag byte within the
same receive step, *before* returning NeedMore on input exhaustion,
even when it was the only byte received. This is a bounded
fail-fast parser invariant, not an authorization change.
No change to NLA flags or authentication
admission may be justified by framing correctness alone.

**Cross-platform validation:** incremental CredSSP DER framing
at `c7f0463a3e11c8bd9fb6e8dfb404c3f1057d40cd`
passed [CI run 38592588562](https://github.com/k1moradi/RDP-server/actions/runs/38592588562)
on Linux/GCC, macOS/Clang and Windows/MSVC,
including Debug/Release 46 CTests and installed SDK/package
gates. This is DER framing acceptance only; it does not
authenticate identity or authorize OS/RDP session access.

## Canonical offline CredSSP server response DER (2026-10-14)

MS-CSSP 2.2.1 requires a server TSRequest to contain only the
relevant response field for its current handshake phase. Encode
`negoTokens` with exactly one nested NegoDataItem or `pubKeyAuth`
as an opaque OCTET STRING; do not combine them, introduce
`authInfo`, or serialize a client nonce for server replies.
Use canonical short/0x81/0x82 definite lengths and a single
bounded output reservation with a verified final size.
Restrict the current helper to project-supported versions 5/6
and 8192-byte opaque provider outputs. DER serialization must
never be treated as GSS wrap, principal verification or
permission to advance TLS, MCS or a console session.

## Optional native Linux GSSAPI provider boundary (2026-10-14)

Keep the portable C++23 static SDK free of mandatory Kerberos
dependencies. The Linux-only, opt-in test target may link
MIT GSSAPI implementation files, but must never be installed
as a functioning RDP server or implicitly load a host keytab.
Only explicit TERMSRV/host@REALM and absolute FILE:/ keytab
configuration is permitted by the existing GSS acceptor.
Pass a complete v5/v6 `TsRequestFrameReader` into
`GssapiSpnegoAcceptor::acceptFramedNegoRequest` synchronously;
parse/borrow once, invoke the existing real GSS-API provider
without copying the inbound token, and erase/close on failure.
Keep OpenSSL TLS binding, delegated credentials and OS desktop
admission as independent, unverified gates; GSS syntax tests,
an absent-keytab failure or green builds never grant rights.

## TLS-bound CredSSP streaming and ownership (2026-10-14)

Reuse the first-party `TsRequestFrameReader` for both synthetic
DER fixtures and decrypted real TLS bytes. When reading TLS,
pin the same established server-role `SSL*` throughout all
frames, reject attempts to alternate SSL identities or inject
raw plaintext, and securely clear buffers at every terminal
failure. Keep a 512-byte stack chunk and read only up to
`bytesNeeded()` to avoid consuming the next coalesced frame.
If `SSL_read_ex` produced bytes without completing the
frame, return `Progress` to permit a follow-on call even
when no new socket readiness event occurs. Only on
`SSL_ERROR_WANT_READ` or `SSL_ERROR_WANT_WRITE` should
the event loop wait. Call `SSL_get_error` immediately after
the failed OpenSSL operation. Explicitly erase transient
decrypted stack bytes after copying into the sole owned DER
buffer. TLS provenance alone does not authorize NLA/GSS,
independent OS identity, or desktop.

## TLS provenance and version pinning for CredSSP GSSAPI (2026-10-14)

MS-CSSP 2.2.1 and 3.1.5 put all SPNEGO tokens and the
pubKeyAuth proof on the *same* TLS-encrypted CredSSP
exchange. A syntactically valid DER view is not evidence
it arrived over the selected TLS session. Carry a borrowed
completed-frame server SSL identity from the already-owned
framer into the existing Linux GSS acceptor and pin
it together with the supported 5/6 CredSSP version.
Reject a mixed parser/TLS handoff, changed SSL pointer,
changed version or pre-initial provider phase without
trying to use GSS credentials. Clear borrowed identity
on terminal rejection; guard protected-binding unwrap
with matching SSL and version before comparing the
selected TLS certificate's hash. No standalone account
capability, stored plaintext, extra controller or generic
SSPI emulation is created. Keep positive Kerberos,
combined final negotiation/binding, credentials and
independent OS authorization open until tested.

## Final combined CredSSP token + pubKeyAuth gate (2026-10-14)

MS-CSSP 2.2.1 and 3.1.5 specify that the last
client `negoTokens` item and protected `pubKeyAuth`
co-occur in one TSRequest. Keep exact one-token,
v5/v6, 32-byte nonce, no-delegated-credentials/no-error
checks in the existing borrowed-span type rather than
inventing a second ASN.1 parser. Accept this final
request only on the single pinned SSL transcript with
an already continuing Linux MIT GSSAPI context. Process
both phases synchronously before wiping/releasing the
existing frame: GSS accept with required mechanism
security flags, unwrap the encrypted binding with
confidentiality, compare against selected TLS certificate
hash and nonce, wrap server proof. If an extra provider
output token remains and the defined server binding
reply cannot carry it, fail closed rather than silently
discard it. The prior binding-only helper remains
independently gated and MUST NOT treat a token-containing
final message as a binding-only request. Do not claim
end-to-end authenticated session admission from
negative-only GSS tests; controlled positive Kerberos
and OS policy verification remain mandatory.

## Secure nonblocking CredSSP server reply transport (2026-10-14)

For MS-CSSP 2.2.1/3.1.5, keep server-side
`negoTokens` and encrypted `pubKeyAuth` replies
within the existing canonical encoder, never accept
arbitrary preframed DER or raw GSS bytes for direct
TLS transport. Queue exactly one bounded 16 KiB
reply with a pinned server `SSL*` after TLS 1.2+
handshake completion and selected certificate/cipher.
`SSL_write_ex` can partially write or return
WANT_READ/WANT_WRITE; a stable owned vector must
remain unchanged, with the *same pointer and remaining
length* across all retry calls when OpenSSL reports
WANT and offsets advanced **only** for successful
writes. Never reinterpret WANT as EOF, spin on
readiness, overwrite a pending reply, send twice
after Complete or permit SSL pointer substitution.
Cleanse the payload on release/cancel/error, preserve
SSL provenance only across explicit successful
release, and leave policy to the one future trusted
CredSSP/session owner. Green TLS wire tests alone
are not positive GSS or OS authorization evidence.

## Linux MIT GSSAPI -> TLS writer handoff (2026-10-14)

When forwarding real provider tokens per MS-CSSP
3.1.5, source the TLS pointer only from the
currently complete actual server-side
`TsRequestFrameReader` frame. Neither
caller-provided DER nor an unrelated `SSL*`
can impersonate that identity. During
SPNEGO, queue `negoTokens` ONLY for an
actual `GSS_S_CONTINUE_NEEDED` result with
nonempty opaque output; if context completes
on a negotiation-only frame without the
mandatory client final binding, reject rather
than accepting a wrong stage. Require any
previous TLS server response to be completely
sent AND explicitly released before consuming
a subsequent GSS client token. The final client
request must contain combined `negoTokens`
and confidential client `pubKeyAuth` in
the single same-TLS frame. Only a real GSS
context plus successful version-pinned TLS
binding may queue the confidentially wrapped
server proof. The producer's temporary
GSS token vector must be cleansed once its
bytes are snapshotted by the writer; clear
reader/writer/context on every failure.
The helper merely queues a response for a
future TLS readiness loop; it does NOT
create an authenticated OS session, perform
credential delegation, alter X.224 selection
or emit MCS domain/channel responses.

## Selected server certificate continuity for CredSSP (2026-10-14)

Per MS-CSSP 2.2.1/3.1.5, the v5/v6 client/server
proof uses the SubjectPublicKey from the server's
selected TLS certificate, with a direction-specific
NUL-terminated binding label and the client's
32-byte nonce. Do NOT hash the peer certificate,
a mutable SSL_CTX default before handshake, the
full SubjectPublicKeyInfo or raw TLS bytes.
Validate finished TLS >=1.2, server role, active
cipher and selected certificate in ONE existing
certificate module. SHA-256 fingerprint the selected
DER certificate on the FIRST authentic TLS read,
pin it alongside the existing `SSL*`, compare it
in constant time before every later read and
completed GSS handoff, and fail closed on same-SSL
certificate substitution/renegotiation.
Do NOT reset the pin merely because a successfully
parsed frame is released; wipe it on the reader's
terminal close. No GSS token, binding hash or
certificate fingerprint is a user-authorization
capability. Test with actual OpenSSL selected
certificates, never a fabricated OS identity.

## Frame-proven GSS pubKeyAuth only (2026-10-14)

The optional Linux MIT GSS binding implementation
must never accept a caller-provided
`std::span<DER>` paired with a seemingly valid
`SSL*` as proof of TLS record provenance.
Keep the legacy public method only as
deny-only for callers that might still
compile against it. The one trusted
`TsRequestFrameReader` must supply
`completedFrameServerTls()` and a
borrowed, bounded DER span until the
synchronous real GSS unwrap, selected
cert/nonce check and server GSS wrap end.
For the binding-only form require NO
negoTokens, EXACTLY encrypted pubKeyAuth
and a 32-byte nonce, no authInfo/errorCode,
matched negotiated 5/6 version, verified
GSS context and unchanged active TLS
certificate. For the combined final
message preserve its independent strict
shape and GSS completion requirement.
Reuse a single checked reply queue
implementation for both variants;
reject non-idle writers and erase
transient GSS-protected provider output
after snapshotting bytes into the
existing canonical TLS writer. Never
promote these components to OS or
MCS authorization authority.

## Outgoing CredSSP TLS selected-certificate continuity (2026-10-14)

The nonblocking server `TsRequestTlsReplyWriter`
must validate more than `SSL*` pointer
equality: a selected server certificate
may be reconfigured on the same SSL
object between responses or between
`SSL_write_ex` retries. Pin SHA-256
of the actual selected DER X.509
certificate on the first queued
canonical TSRequest v5/v6 reply.
Reuse the existing strict finished
TLS >=1.2 server-role/cipher/certificate
check and compare the pinned digest
with `CRYPTO_memcmp` at each step,
including Complete and release and
the next queue after release.
Keep the original digest across
successful reply release and cleanse
it on terminal close; cleanse the
transient fingerprint on ALL return
paths. Preserve the stable owned
DER pointer and size across WANT.
Reject a mismatch BEFORE any
additional `SSL_write_ex`, wiping
the pending reply and terminating
the writer. A previous successful
SSL write cannot be recalled.
Do not confuse transport continuity
with GSS provider authentication,
OS authorization or session admission.

## Cross-reader GSS transcript certificate identity (2026-10-14)

Even correct individual `TsRequestFrameReader`
certificate pinning is insufficient if application
code constructs a new reader per CredSSP round.
The existing Linux GSS acceptor MUST pin its own
selected server DER X.509 SHA-256 identity at
the first TLS-derived token, compare it
constant-time at all later same-SSL GSS/
pubKeyAuth/frame/writer handoffs, and cleanse
the pin during terminal `reject()`.
Neither the public raw-DER legacy deny-only
API nor a fresh reader may bypass this policy.
Do not elevate a verified Kerberos SPNEGO
context to authorization: the OS adapter
must still independently approve a session.

The opt-in real provider probe must use ONLY an
explicit `TERMSRV/host@REALM` service principal,
explicit `FILE:/` keytab and separately specified
`FILE:/` initiator credential cache. It must NOT
load a host default keytab/cache, fabricate
provider success, spin up an implicit KDC,
start an RDP listener or accept an OS account.
Use existing native GSS and OpenSSL TLS fixture
and one current connection owner; never log
or commit credentials.

## GSS provider-only CredSSP v6 negative reply dispatch (2026-10-15)

The existing first-party Linux MIT GSSAPI acceptor MAY queue
a terminal version-6 `TSRequest.errorCode` under Microsoft
MS-CSSP 2.2.1/3.1.5 ONLY after the configured, explicit-keytab
`gss_accept_sec_context` actually rejects a client token or
rejects its completed security/mechanism flags. Internal
`SpnegoStep.providerRejected` is the evidence carrier, not an
injected caller verdict or identity credential. A missing keytab,
bad TLS provenance, wrong/premature version, malformed DER,
invalid pre-GSS initial tag/OID, failed local memory copy
or incomplete GSS continuation MUST remain silent terminal
rejection. Do not disclose provider-specific major/minor codes
or emit any success-shaped token on failure.

Capture the active TLS `SSL*`, selected X509 fingerprint and
valid version-6 nego-only DER BEFORE the accepted provider
step; the existing fail-only GSS cleanup clears its own
credential/context and TLS pin on rejection. Recheck the
selected certificate before enqueuing the **fixed**
`STATUS_LOGON_FAILURE` (0xC000006D) to the existing single
`TsRequestTlsReplyWriter`; never introduce a parallel queue,
record cache or SSL writer. A new `FailureQueued` outcome
means the provider is already terminal and exactly one error
reply is waiting for caller-driven TLS writes; it is NOT a
successful SPNEGO result or OS authorization. Writer identity,
pending state, retry pointer, secure wipe and terminal release
remain unchanged. Do not interpret `FailureQueued` as license
to advance to CredSSP authInfo, MCS, console or desktop.

Opt-in genuine provider failure tests MUST use explicit
TERMSRV service, caller-provided FILE:/ keytab and separate
FILE:/ cache, and genuine TLS BIOs. They must not silently
read the host login/keytab, fabricate provider rejection or
claim successful Kerberos authentication from a negative
wire result. Keep the opt-in test inactive in default CI.

## Canonical and terminal CredSSP error replies (2026-10-14)

Per MS-CSSP 2.2.1/3.1.5, only v6 is
supported by the new server fail-only
serializer; the legacy 3/4 error cases
remain unsupported rather than silently
pretending v5 has errorCode semantics.
Represent negative NTSTATUS as exactly
four DER signed INTEGER octets. Permit
ONLY fixed `STATUS_LOGON_FAILURE` and
`STATUS_NOT_SUPPORTED`, not positive
success or provider-specific minor error
leaks. Never mix [4] with negoTokens,
pubKeyAuth, authInfo or nonce.
The original `TsRequestTlsReplyWriter`
must own BOTH success and failure
replies via the same PRIVATE encoded
queue, preserving pending-record
exclusivity, SSL identity, SHA256
selected-certificate continuity, exact
nonblocking write/retry ownership and
secure wipe even when a rejected
candidate reply was already encoded.
A fully delivered failure response
MUST terminate its writer at release;
neither failed nor completed failures
may be used as authenticated identity
or lead to MCS. No automatic provider
error mapping until the true NLA
failure/connection state is implemented.

## Offline finalization role check (2026-10-15; CI PASS)

MS-RDPBCGR 2.2.1.14–2.2.1.21 permits a pure finalization
cross-check using existing exact-length Share Data parsers.
It MUST NOT become a competing state machine, TLS sender
or OS authorization source. Validate role-specific client
channel, server source 1002, share ID, client action and
zero Control IDs, server Cooperate zero IDs, and Granted
user/server channel IDs. The server Synchronize targetUser
is opaque in the published example, not reliable identity.
The caller alone enforces actual wire order, per-message
sender provenance, MCS joins and independent OS admission.
All spans borrow complete input buffers for the call only.

**Exact implementation CI PASS (2026-10-15):**
`27996f24e5fbb497c0bee37756d34551d1a47e47`,
[Actions 38735353873](https://github.com/k1moradi/RDP-server/actions/runs/38735353873).
Linux/GCC **101/101** CTests and macOS/Clang,
Windows/MSVC **91/91** CTests in BOTH Debug and Release,
including the new finalization correlation/denial cases.
SDK consumer/install, ZIP/SHA256 uploads and documentation
policy also PASS; prerelease publishing SKIPPED (no tag).
Owner-local compile, real GSS/TLS positive Kerberos binding,
independent OS authorization and client/desktop remain
**NOT RUN**.

## OpenSSL X.509 continuity through MCS diagnostics (2026-10-15)

MS-RDPBCGR 5.4 and MS-CSSP 3.1.5 require TLS before the
CredSSP authentication/binding flow. The selected certificate
is security-relevant input, not interchangeable merely because
`SSL*` is unchanged. Reuse the existing selected-certificate
SHA-256 routine and compare its bytes with `CRYPTO_memcmp`
before each direct `SSL_read_ex` MCS callback. Do NOT include
OpenSSL's broad ssl.h transitively in portable public headers.
The sole connection owner stores a fixed 32-byte pin, wipes it
on close, and never owns the SSL/BIO or introduces a second
session or identity authority. Certificate continuity does
not authenticate a user or admit an OS account; only a future
trusted GSS and separately authorized OS path may do that.
Plaintext synthetic MCS intake has no live transport provenance.

## General capability semantics without false negotiation (2026-10-15)

For MS-RDPBCGR 2.2.7.1.1, use the existing exact-length,
counted TS_CAPS_SET envelope parser before interpreting
one fixed 24-byte General set. Keep a single zero-allocation
scan using checked offsets, no duplicate capability cache,
no pointer ownership, and no second activation controller.
Treat the protocolVersion field as required 0x0200;
reject duplicate General sets, undersized/oversized
layouts and non-Boolean refresh/suppress bytes. Ignore
pad2OctetsA even when nonzero. Preserve raw OS and
extraFlags advertisement including unfamiliar future
bits, and do not infer any graphics codec or authentication.
Do not strengthen the common generic decoder to reject
other capability lists: other unimplemented features
remain opaque until independently negotiated after
GSS/TLS and OS approval.

**Exact-head CI PASS (2026-10-15):**
`3625b0daadef1f470bc0b23b3b2aff9106750a6a`,
[Actions 38742975505](https://github.com/k1moradi/RDP-server/actions/runs/38742975505).
Linux/GCC **105/105** and macOS/Clang, Windows/MSVC
**95/95** CTests passed in BOTH Debug and Release,
including both new General capability cases. Installed
SDK consumer, ZIP/SHA256 package uploads and policy
PASS; no version tag, so prerelease SKIPPED.
**NOT RUN:** owner-local new-head build, genuine GSS/TLS
positive proof, independent OS authority, Microsoft
client or graphics/desktop.

## Strict Bitmap capability without inferred authority (2026-10-15)

MS-RDPBCGR 2.2.7.1.2 requires bitmapCompressionFlag
and multipleRectangleSupport to equal one for a
connection to proceed. Parse their LE16 values only
AFTER the existing exact Active/capability envelope
gate; require a single 28-byte Bitmap set, nonzero
desktop dimensions and valid Boolean resize flag.
Treat preferred color depth and drawing flags as raw
advertisements, not negotiated/OS-authorized output
settings. Ignore padding, legacy 1/4/8-bpp client
receive fields and highColorFlags, even if nonzero,
rather than rejecting valid Microsoft peers.
Do not use the advertised dimensions as a memory
allocation size. Preserve unknown siblings, make
no state copies and add no second session owner.

**Exact implementation CI PASS (2026-10-15):**
`89ffef98b4f27ad2947b4629c9eefa49b64152a7`,
[GitHub Actions 38746309146](https://github.com/k1moradi/RDP-server/actions/runs/38746309146).
Linux/GCC **107/107** and macOS/Clang,
Windows/MSVC **97/97** full CTests each in BOTH
Debug and Release. New
`transport.share-bitmap-capability-wire`
and `transport.share-bitmap-capability-rejections`
PASSED on each system; documentation-policy,
installed SDK consumer, ZIP/SHA256 packaging/upload
PASSED. Untagged prerelease SKIPPED.
**NOT RUN:** owner-local single-build-root compile,
real GSS/Kerberos/TLS binding, independently approved
OS session, licensed capabilities, graphics or desktop.

## Keep connected TCP/BIO provenance through MCS (2026-10-15)

A borrowed `SSL*` or a completed handshake alone
does not establish it is attached to the same TCP I/O
that received X.224. Pin both the selected `SSL*`
and its shared read/write BIO on a successful
`attachTlsTransport`. Reject duplicate attach,
swapped SSL, swapped BIO or `BIO_get_data` retargeting
before any `SSL_do_handshake` or `SSL_read_ex`
from the connection-oriented readiness callbacks.
Never dereference a stored old BIO before confirming
it is STILL the SSL's active read AND write BIO:
`SSL_set_bio` may free the original. Keep all socket
and SSL lifetimes borrowed, event-loop serialized
and non-owning; close the sole preauth diagnostic on
invalid/replayed transitions. Legacy synthetic
TLS fixtures stay available for tests but are not
authenticated/OS-authorized session admission.

**Exact implementation CI PASS (2026-10-15):**
`45f68c2c0fcaa163aaf242a99f5637726a023fe2`,
[Actions 38749371803](https://github.com/k1moradi/RDP-server/actions/runs/38749371803).
Linux/GCC **109/109**, macOS/Clang and
Windows/MSVC **99/99** full CTests each in BOTH
Debug and Release, including the strict connected
TLS ownership/MCS ordering denial cases and
the actual native loopback transport. Documentation
policy, installed SDK downstream consumers, ZIP/SHA256
package uploads PASS. Prerelease SKIPPED (no tag).
**NOT RUN:** owner-local exact-head CTest, real GSS/
CredSSP/TLS binding, independent OS authority,
live authenticated Microsoft RDP client and desktop.

## R1 exact per-call TCP/BIO bounds (2026-10-15)

One native nonblocking socket syscall or OpenSSL
BIO callback MUST cap its requested span to the
first 18 KiB before touching the OS or a borrowed
`TcpNonblockingIo`. RFC 5246 6.2.3 bounds the
TLS 1.2 ciphertext fragment to 2^14+2048 bytes;
RFC 8446 5.2 bounds TLS 1.3 ciphertext to
2^14+256 bytes. This is an I/O quantum, not a
hard cap on the caller's total message: preserve
correct short reads/writes and caller-managed
retries without hidden accumulation, buffers or
socket ownership. Compare a provider's returned
byte count against the **capped** span, never just
the original oversized caller span. Limit Winsock
recv/send length before converting to `int`;
do not silently narrow arbitrary `size_t`.
Use `(std::min)` to avoid the Windows min macro.
Do not interpret a successful TCP or TLS byte
transfer as GSS/OS admission.

**Exact-code acceptance (2026-10-15):**
`8ce08611d5d7b093c9d69f4b7eee5d23cd096359`
passed [GitHub Actions 38752789202](https://github.com/k1moradi/RDP-server/actions/runs/38752789202):
Linux/GCC **111/111**, macOS/Clang and Windows/MSVC
**101/101** registered CTests in EACH Debug and
Release, including BIO and real loopback chunk-bound
cases. Project documentation policy, installed
SDK downstream consumer, ZIP/SHA256 artifacts
and package uploads PASS. Prerelease publishing
SKIPPED (no version tag). Owner-local current-head,
MSYS2 CLANG64 Clang23, macOS27, real GSS/CredSSP
and OS account authorization, Microsoft client and
desktop remain **NOT RUN**.

## Accepted TCP handle ownership (R1, 2026-10-15)

Separate the borrowed listening descriptor from move-only ownership of
one accepted socket. Configure nonblocking and non-inheritable flags
before returning it to the event loop. On Linux use atomic `accept4`
flags where available; on macOS/BSD also disable socket SIGPIPE.
Failure must close the newly accepted descriptor, never its listener.
Free SSL/BIO/connection callbacks before socket close or move; never
reuse borrowed socket I/O after cancellation. Move assignment closes the
previous descriptor exactly once; an aliased self-move preserves ownership.
Peer FIN must deliver buffered bytes before explicit EOF, with the listener
still borrowed and intact after local cancellation.

## R1 attached native socket/TLS lifetime (2026-10-15)

An active OpenSSL BIO borrows `NativeTcpIo`: keep the enclosing
accepted-connection owner nonmoving. Transfer ownership of the
already-configured server `SSL` only after full X.224 Confirm output.
On cancellation, EOF, fatal TLS or terminal MCS diagnostic, clear
preauthentication, destroy SSL/BIO and THEN close the native accepted
socket. Never invoke readiness after close. The listener is borrowed
and remains independent of the accepted socket lifetime.

## R1 readiness contract and monotonic deadlines (2026-10-15)

Do not introduce a second phase enum/cache when existing preauth reply
bytes and `SSL_want_write` identify the required readiness direction.
A complete X.224 request can advance the diagnostic stage before the
Confirm/failure suffix is written. Inspect pending reply bytes FIRST;
select writable readiness and the existing reply writer ahead of TLS
configuration or terminal close until its entire suffix is sent.
Gate native callbacks on the matching supplied bit, and advance at
most one of the existing bounded X.224/TLS/MCS callbacks per event.
An external `steady_clock` time point and policy deadline trigger
idempotent cancellation; do not allocate timers or read the wall clock
from the transport owner. A read-only completed SSL borrow must not
outlive its owner or substitute for R2 authenticated identity.

**One bounded native poll step (R1):** Do not place a blocking
socket recv/send or unbounded poll/retry into a readiness callback.
A connection-scoped POSIX poll/WSAPoll wait is capped to 25ms,
uses only the owner's socket and previous `ioInterest`, handles
EINTR without hidden retry and fails closed on native errors.
Check a monotonic deadline before and after polling, pass only the
matching ready direction to one existing bounded callback, and keep
listener policy, process runtime and OS authorization outside R1.

## R1 bounded listener intake and one accepted owner (2026-10-15)

The native accept batch MUST be bounded to 1..16 successful
accepts, perform no blocking waits or implicit retry, and call
only the existing nonblocking one-shot acceptor for platform
socket flags and failure closure. Transfer each accepted socket
to one no-throw, move-only RAII callback; a callback that declines
further intake must not leak or drop the listener. Keep explicit
outcomes for would-block, budget reached, post-progress drain,
invalid input and failure. Caller/R10 owns listener policy and
fairness; R1 must not add any new queue, authentication or RDP
state controller.

## R1 one-step borrowed-listener readiness (2026-10-15)

Treat listener polling and per-connection polling as separate
borrowed versus owned resources, without allocating another
controller. Bound each listener readiness step to a single
POSIX poll or Winsock select with at most 25ms wait; reuse the
same 1..16 nonblocking batch acceptor only after a real readable
result. Validate callback/budget first, check a monotonic
deadline before socket operations, and do not silently retry
interrupts. Never close a borrowed listener on poll error or
deadline; neither the presence of a pending connection nor a
successful X.224/TLS diagnostic implies R2/R3 authorization.

## R1 listener role/nonblocking fail-closed guard (2026-10-15)

Only `SO_ACCEPTCONN`-verified listening sockets may enter a
native accept callback. On POSIX reject listeners missing
`O_NONBLOCK` before calling `accept`, using `F_GETFL`
without mutating flags. A caller still owns the listener,
its socket mode, fairness and lifetime; Windows callers MUST
configure `FIONBIO` explicitly. No new listening service,
session controller or identity authority.

## R1 native Darwin socket-option compatibility (2026-10-15)

Never infer getsockopt support from a defined option constant.
macOS SO_ACCEPTCONN returns ENOPROTOOPT: check SO_TYPE and peer
state on Darwin, retain read-only O_NONBLOCK and native accept
rejection. Do not configure borrowed listeners or add a controller.


## R7 one-shot ScreenCaptureKit stop ownership (2026-10-16)

A one-shot native capture stream can reach `SCStream::stopCapture` from several
concurrent retirement paths: explicit owner stop/close, startup cancellation,
or an output callback that detects an unowned revocation. These paths MUST share
one callback-state stop-submission claim before touching ScreenCaptureKit. The
first claimant owns the asynchronous native request; later claimants observe it
and do not submit a duplicate stop. A completion that races an owner transition
to `Stopping` must still complete that state, while completion after terminal
`Closed`/`Failed` retirement is inert except for fail-closed native errors.
The claim is lifecycle coordination only: it grants no capture permission,
identity, session admission, graphics scheduling or transport authority.

For asynchronous ScreenCaptureKit callbacks, do not retain a raw
`NativeDisplayGeometryRefresh*`: the serialized geometry owner may be
refreshed or destroyed while queued callbacks still hold state. Bind each
capture lifetime to a copyable generation-revocation fence backed by one
shared atomic state per geometry owner. Refresh/invalidate/destruction revokes
before replacing mutable geometry, and callbacks compare only the immutable
expected generation. Shared ownership is justified solely because callback
state can outlive the mutable owner; never allocate per frame or treat this
fence as R2/R3 admission.

## R2 cross-platform native desktop evidence and capability boundary (2026-10-17)

Keep one R2 authorization domain. Linux remains the only implemented positive
native-admission issuer: the existing broker binds exact HYBRID TLS/GSS final
credentials, real PAM account verification, NSS identity, logind physical
session ownership and the R2-owned change monitor. R10/R5 may obtain its
display/session selection only through the synchronous noncopyable
`LinuxNativeDesktopSelectionView` visitor. The broker revalidates before and
after that callback. The view must not escape it; configured `DISPLAY`,
principal/account strings, numeric UID values and copied generation numbers are
never authorization.

Windows and macOS native readers are **evidence adapters, not admission
controllers**. The Windows adapter proves only that the running process is in a
nonzero physical-console WTS session whose primary-token SID/session/logon LUID
agree with LSA logon-session data and whose WTS state is active. A future R2
SSPI/CredSSP provider must privately supply the authenticated SID; R10/R6 may
not supply or override it. Session 0/service execution fails closed in this
adapter and needs a separately reviewed privileged service-session design.

The macOS adapter proves only that the current primary-console UID equals the
process effective UID and audit UID, that the audit session is nonzero, and that
the caller Security session is local and has graphical access. A future genuine
R2 credential verifier must privately bind the authenticated local account to
that UID before capability issuance. TCC, `CGSessionCopyCurrentDictionary`,
AppKit notifications and `MacDesktopSessionGuard` are downstream
freshness/permission checks, never authentication. Any future R2 lease must
store the native session identity and revoke terminally on logout/switch,
evidence mismatch, policy change or connection teardown; there is no public
capability constructor or caller-supplied success flag.

## R2 personal-desktop broker boundary (2026-10-17)

Personal-desktop product mode is selected only through the concrete Linux R2
broker after the current move-only lease has been rebound to the exact R1
HYBRID/TLS/GSS owner and fresh NSS/logind session evidence. R10 supplies the
service-lifetime, nonmoving `RuntimeDeploymentPolicy` object by const reference.
R2 stores only that object's identity after successful one-shot selection and
requires the exact same object plus `PersonalDesktop`, native-session
revocation and one-console invariants on every later personal transition.

R2 never accepts admission/session generations from R10. Every wrapper invokes
the existing `revokeUnlessAdmissionBindingMatches()` path through
`authorizeR3ProtectedTransition()` before borrowing or mutating R3. R3 remains
the sole owner of Valid Client and Share bytes/receipt state; R1 remains the
sole TLS writer. Null/missing leases are permitted only on accepted-byte
completion paths so late callbacks can be rejected without inventing a
replacement capability. Any wrong policy, duplicate selection, stale
generation, missing TLS provenance, native-session failure, R3 rejection or
late receipt closes R3 before revoking R2/GSS.


## Confirm Active capabilities are R3-owned protocol state (2026-10-18)

Confirm Active is not only envelope syntax. Before a runtime framing buffer can
be recycled, the sole R3 Share owner must copy the exact validated capability
sequence into connection-owned bounded storage and derive only the feature
intersection that R3 actually consumes. Caller/GUI buffers, booleans and a
previous server advertisement are never substitutes for the client's
capability state.

Input that arrives after Confirm Active but before Share finalization is legal
RDP traffic. Validate its exact MCS/share identity and negotiated input format,
then discard it while no native owner is dispatchable. Do not advance the
Synchronize/Control/Font state machine, create a second queue, or treat the
discard as input authorization. After Share activation, each decoded event
still needs both negotiated protocol support and the existing fresh R2 native
authorization immediately before dispatch.


## R3 owns RDPGFX presentation identity (2026-10-18)

The authenticated Graphics DVC owner is the sole production owner of RDPGFX
presentation generation and surface identity. R10, GUI/native capture code and
R2 wrappers must not supply a `GfxPresentationLifecycle`, DVC generation or
surface ID. R3 opens the existing R4 presentation lifecycle on the current DVC
generation, derives initial geometry from the admitted Client Core settings and
does not expose the DVC as frame-ready until CAPS_CONFIRM, CREATE_SURFACE and
MAP_SURFACE_TO_OUTPUT have completed through accepted-byte receipts.

For the mandatory first-frame fallback, accept only a synchronous borrowed
framebuffer and frame ID, prepare ClearCodec against the embedded presentation,
and transfer the move-only R4 frame directly into the existing R3 record
publisher. Keep cancellation legal only at zero accepted outer bytes; any
positive or uncertain partial delivery remains terminal and must abort the
presentation receipt.
