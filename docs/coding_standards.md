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
