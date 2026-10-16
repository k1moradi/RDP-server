### R1 explicit TLS-vs-HYBRID negotiation policy (2026-10-16)

Security protocol selection is immutable per-connection configuration, not a
post-parse scalar. `DiagnosticTlsOnly` preserves the historical default.
`HybridNla` requires an actual HYBRID offer and returns
`PROTOCOL_HYBRID`; SSL-only receives `HYBRID_REQUIRED_BY_SERVER`.

The policy is threaded through the existing single R1 owner before any peer
bytes are consumed. The same parser, X.224 reply buffer, SSL/BIO and immutable
provenance remain authoritative. HYBRID selection is only protocol shape; it
does not prove GSS authentication, native OS authorization or R3 admission.
Unsupported Restricted Admin/Remote Credential Guard flags remain denied.
R10 must explicitly choose HybridNla for serving connections.

### R3 authenticated joined static-channel role observation (2026-10-16)

MS-RDPBCGR CS_NET `CHANNEL_DEF` positions correspond exactly to the
server SC_NET `channelIdArray` positions. The sole R3 MCS owner already
retains the parsed client settings and its checked allocation. The new
portable `resolveMcsStaticChannelRole` provides **syntax-only**,
constant-bounded positional identity for exact NUL-padded static
roles: CLIPRDR, RDPDR, RDPSND and DRDYNVC. It fails closed for
mismatched lengths, missing CS_NET, unknown/duplicated role,
malformed/ambiguous names or colliding allocations. It never
configures joins or produces an admission capability.

The new private `McsSessionLifecycle` resolver may report a CLIPRDR
static-channel ID only after the retained native admission generation
has passed the concrete R2 broker's immediate authorization on the
same R1-owned TLS/HYBRID connection, and the sole existing join gate
has completely accepted the UserId, I/O and CLIPRDR confirmations.
No borrowed GCC input is retained; the copied settings and allocation
are owned by R3. Cancellation clears both, all channel membership and
licensing before R2/GSS teardown. A not-yet-joined or absent role
produces no role ID.

`authorizeR3JoinedClipboardChannel` returns only a transient numeric
classification to the synchronous caller. No stand-alone bool,
channel ID, proposed clipboard name, GSS principal string or raw SSL
pointer grants OS/session access. Any subsequent message handling must
reauthorize R2, recheck R3 generations/role, enforce MCS reassembly,
VC framing, licensing, Share activation and R8's existing clipboard
generation before reading or writing any clipboard data. R1 alone
reads/writes TLS application bytes. This increment deliberately
does **not** install a clipboard dispatcher, license a client,
start a service or activate a desktop.

### R4 reset-stable NV12 scratch lifetime (2026-10-16)

`BgraNv12Converter::reset()` invalidates `picture()` via `ready_ = false`
and clears visible/coded metadata without destroying its initialized
contiguous scratch. Subsequent same-byte-size frames reuse the exact
allocation without a large default-initialization/heap transaction. Input
overlap validation continues to inspect the live vector extent even between
presentation generations; it must reject capture aliases of R4 scratch before
reading or writing. The old coded Y/UV pixels are never exposed as a valid
frame after reset or after a rejected conversion. The encoder remains the
sole x264 reference-history owner, and all methods remain serialized by R4's
event thread.

### R4 borrowed BGRA framebuffer to owned x264 NV12 input (2026-10-16)

The noninstalled `rdp-server-graphics` target now owns
`BgraNv12Converter`, a single-threaded synchronous bridge from a complete
first-party native `FramebufferView` to `X264Nv12PictureView`. R5/XShm,
R6/DXGI and R7/CoreVideo retain all platform resources. R4 never retains
capture pointers or carries a view across native unmap, callback, event or
resize. The producer embeds reusable contiguous scratch; the Y and
interleaved UV spans are valid only until the next conversion/reset and
are read synchronously by its existing x264 `prepare()` path.

Visible dimensions must be nonzero, even, exactly equal to capture width
and height and compatible with `gfxAvc420CodedGeometry()`. Source pitch
must be at least width * 4 with complete pitched rows, checked size arithmetic
and no overlap with scratch. Current coded dimensions remain 16-aligned
and both packed NV12 planes are limited to a total 64 MiB; input rows and
plane offsets are checked before reading or writing. The output uses
Y stride = UV stride = coded width; each plane is exactly sized, with
no exposed row padding. Scratch reallocates only when coded byte size
changes, never inside the pixel loop, and is logically invalid after any
failed conversion.

BGRA/XRGB bytes are interpreted B,G,R,ignored-alpha (neither blending nor
premultiplication). Reference scalar full-range BT.709 integer coefficients
are Q16: Y=(13933R+46871G+4732B)/65536,
Cb=128+(-7509R-25259G+32768B)/65536,
Cr=128+(32768R-29763G-3005B)/65536. Signed division rounds to the nearest
integer with ties away from zero; channels clamp to 0..255. Each NV12 2x2
chroma block averages its four edge-clamped RGB pixels first using
(sum+2)/4, then applies Cb/Cr. Right/bottom coded margins replicate the
nearest visible pixel before luma/chroma conversion. No resize, scaling
or multi-monitor composition occurs.

`X264Avc420SegmentedFrameProducer::prepareBgra()` preflights generation,
surface, AVC420 envelope and `GfxPresentationLifecycle::canSubmitFrame()`
before conversion, then borrows scratch only for the existing synchronous
`prepare()`. This preserves the single encoder reference chain and
transactional full-wire delivery receipt: pre-encode rejection does not
advance codec/ACK, post-encode publication denial rebuilds IDR, and terminal
partial abort invalidates generation and encoder history. A converter never
creates an authorized graphics channel or client-visible desktop.

### R1-owned CredSSP plaintext transport boundary (2026-10-16)

CredSSP framing may inspect the same established server SSL for immutable
role/version/cipher/certificate provenance, but production application I/O is
owned exclusively by `OwnedPreauthTcpConnection`. The owner-aware
`TsRequestFrameReader` and `TsRequestTlsReplyWriter` overloads therefore
translate R1's bounded Progress/NeedRead/NeedWrite/terminal results rather
than advancing OpenSSL directly.

The reader pins two correlated borrows: the exact established SSL and, for
the production path, the exact nonmoving R1 owner. A raw-SSL read cannot take
over an owner-bound frame, a second owner cannot substitute even with a valid
TLS session, and cancellation invalidates the owner-to-SSL relation before
certificate revalidation. The owner object must outlive the framer, matching
the existing event-loop lifetime rule.

Reply queueing remains R2/GSS-owned and may identify the established SSL
because queueing itself performs no provider I/O. A fresh raw-queued reply can
be adopted by the exact R1 owner on its first write; after that adoption,
direct `SSL_write_ex` progression is prohibited. Release rechecks the same
owner before selected-certificate validation, preventing a stale SSL
dereference after R1 cancellation.

This boundary proves transport continuity only. R2 still owns DER/GSS/CredSSP
semantics and native authorization, R3 remains the sole session state
machine, and R10 owns the future event loop/listener. No framed byte or
completed TLS handshake is an admission capability.

### R3 protected Channel Join receipts after Attach User (2026-10-16)

The existing `McsSessionLifecycle`, not a second join owner, handles
Channel Join after complete authorized 11-byte Attach User Confirm
delivery. Its `AwaitChannelJoin` phase retains the assigned UserId
1002 and checked GCC/IO/static channel allocation. A private
`onVerifiedR2ChannelJoin()` consumes exactly one already-decrypted
TPKT after `LinuxConsoleAdmissionBroker` reauthorizes the genuine
nonforgeable lease, GSS/selected TLS certificate, immutable R1
HYBRID/NLA provenance, NSS/logind watch, policy epoch, session
generation and view permission. Neither the public diagnostic
`onDomainPdu()` nor a Boolean/raw SSL/identifier can grant admission.

The already-configured `McsChannelJoinWriteGate` owns one fixed
15-byte Join Confirm and a bounded queued index for each distinct
requested assigned channel. A repeat pending/confirmed Join remains
idempotent; foreign/wrong initiator, invalid/early/late/wrong-order
PDU, cancellation and stale/overreported receipts are terminal.
One R3-owned output suffix, reply receipt and independent slice
receipt are borrowed only after fresh broker authorization.
`OwnedPreauthTcpConnection::writeTlsApplicationData()` remains
the sole TLS write boundary. WANT with no accepted bytes retains
the same suffix and receipt; positive partial acceptance advances
only the slice; full authorized acceptance confirms exactly the
corresponding channel and may publish the next pending Join reply.

The broker reauthorizes again before consuming each completion,
so R2 revocation or changed TLS provenance cannot turn old accepted
bytes into channel membership. Terminal failures revoke R3 join,
licensing and protocol state first, then R2/GSS; R1 releases TLS
afterward. Confirmed MCS membership is a prerequisite only: there
is still NO admitted Send Data, channel-role dispatch, licensing,
Share Control, graphics, input, clipboard or listener. R3 keeps
its existing single event-loop-affine writer and no extra thread,
scheduler or heap-based queue.

### R3 authorized Attach User and receipt-bound MCS UserId (2026-10-16)

The sole `McsSessionLifecycle` owns the allocated UserId, pending 11-byte
Attach User Confirm, receipt counters and existing channel-join gate.
After R2-authorized Connect Initial, fully accepted Connect Response and
R2-authorized Erect Domain, only
`LinuxConsoleAdmissionBroker::authorizeR3AttachUser` can consume the
single complete Attach User Request. R2 freshly checks the unforgeable
LinuxConsoleAdmissionLease, exact R1-owned established TLS connection,
HYBRID/NLA provenance, GSS/CredSSP certificate binding, view permission,
policy epoch, native NSS/logind watch and both admission generations.
The public DomainMCSPDU entry remains terminal denial-only.

The deterministic checked UserId is 1002; the negotiated Connect Response
reserves GCC node 1001, I/O channel 1003 and static channels 1004 onward.
The single R3 owner verifies channel/user capacities and uniqueness before
allocating once. Malformed, wrong-order, duplicate, oversized and disconnect
input closes the same owner. Cancellation clears the UserId, pending bytes
and join/licensing state before R2/GSS and finally R1 teardown.

The production `McsAttachUserConfirmWriteGate` stores the existing
`encodeMcsAttachUserConfirm` result in a fixed contiguous 15-byte capacity
with 11 active bytes. Separate nonzero reply and slice receipts bind exact
accepted-byte progress: WANT/zero-byte progress retains the identical suffix
and receipt; a positive partial write rotates the slice receipt; complete
progress retires the reply. Every write preparation and completion is a fresh
R2 authorization with the original R1 connection and bound negotiation
provenance. The event-loop writer uses R1
`OwnedPreauthTcpConnection::writeTlsApplicationData()` and must keep
borrowed suffix bytes stable over WANT retries. Accepted bytes alone are
not peer receipt evidence.

Only the complete authorized 11-byte write transitions
`AwaitAttachConfirm -> AwaitChannelJoin` and configures the existing
join gate once for user channel 1002, I/O 1003 and the checked static list.
This is NOT a joined channel or Send Data authorization. Actual protected
Channel Join Request intake, Channel Join Confirm delivery, licensing, Share
Control, virtual channels, graphics/input/clipboard and Microsoft-client
acceptance remain separate increments.

### R10 Linux connection aggregate and teardown order

`LinuxRuntimeConnection` is the non-listening composition owner between
service-lifetime R10 security/TLS configuration and one future accepted client.
It is noncopyable/nonmovable because R1's SSL/BIO callbacks borrow the embedded
TCP adapter and because R2/R3 authority must never fork.

Ownership remains layered rather than duplicated: R10 owns the sealed keytab
snapshot, immutable native identity policy and reusable `SSL_CTX`; the
aggregate owns one R1 accepted socket/BIO/SSL connection, one R2 GSS/native
admission broker with at most one lease, and exactly one R3
`McsSessionLifecycle`.

The aggregate does not parse SPNEGO, inspect NSS/logind itself or emulate R3.
Every positive transition delegates to its existing owner. R2 admission
consumes the exact R1 connection so established TLS and immutable HYBRID
negotiation provenance cannot be supplied independently.

Terminal destruction is a security boundary: close/revoke R3 first while R2
and R1 are alive, then revoke/destroy R2 GSS and admission leases, then cancel
R1 so SSL/BIO/socket disappear last. Explicit `revoke()` and the destructor
share this idempotent order. Service-lifetime keytab/policy/SSL_CTX owners must
outlive every aggregate that borrows them.

### R2 downstream protected-input owner seam (2026-10-16)

Native input routing does not receive an independent transport proof.
`X11AuthorizedInputRoute::dispatch` carries the exact borrowed
`OwnedPreauthTcpConnection` into R2 immediately before the protected R3
transition and XTEST injection. R2 alone derives TLS plus immutable HYBRID
provenance from that owner. The route cannot substitute a raw `SSL*`, cache
authorization or create a second transport/session authority; its existing
no-lease and native-failure teardown remains R3 → R2/GSS → native disconnect
within the established serialized ownership boundary.

### R2 R1-owned NLA provenance and R3 admission ownership (2026-10-16)

R1 remains the sole accepted-socket/TLS/X.224 negotiation owner. R2 may borrow
the active server TLS pointer and copy the immutable
`SecurityNegotiationProvenance` only synchronously from the exact live
`OwnedPreauthTcpConnection`; it retains neither pointer nor provenance past
that owner's validity. Positive Linux admission requires the client HYBRID bit
and exact server `PROTOCOL_HYBRID` selection from that snapshot before any
native authorization work. TLS handshake completion, a HYBRID offer by itself,
or caller-constructed negotiation fields are not authorization.

The same R1 owner is supplied again immediately before protected R3
transitions. R2 derives the current TLS/provenance pair, repeats its existing
GSS/TLS/certificate, permission, NSS/logind, native-session and generation
checks, then permits only the existing R3 owner to advance. On denial R3 is
closed first, R2/GSS is revoked second, and R1 transport lifetime remains with
its caller until that serialized denial returns. A raw `SSL*` positive R3
route no longer exists; the retained raw-SSL `issue` overload is explicitly
deny-only compatibility.

`hasHybridNlaNegotiationProvenance()` is intentionally a non-authorizing
value predicate used to centralize offered+selected HYBRID validation. It
cannot construct the private move-only `LinuxConsoleAdmissionLease`.
Current R1 diagnostic negotiation selects only `PROTOCOL_SSL`, so ordinary
composition remains fail-closed until R1 implements genuine HYBRID. R10 still
owns service TLS/keytab configuration and the future listener; R3 still owns
all MCS progression.

### R10 immutable service-keytab snapshot ownership (2026-10-16)

The R10 Linux security configuration owns a **sealed anonymous keytab
snapshot**, not the mutable configured source file. Secure path walking and
metadata checks first establish the intended source object. R10 then copies the
bounded contents through explicit-offset I/O into a `memfd`, rechecks source
identity/size/change timestamps and rejects short/growing/changed input before
requiring all write/grow/shrink/final seals. Temporary copy storage is
cleansed and the source descriptor is closed.

The snapshot descriptor is service-lifetime R10 state and must outlive every
R2 `GssapiSpnegoAcceptor` configured through its
`FILE:/proc/self/fd/<n>` URI. Neither path replacement nor later writes to
the original source inode can change the credential bytes seen by a future
connection. This is server credential immutability only: GSS/CredSSP still
proves the client identity, `LinuxConsoleAdmissionBroker` still owns native
authorization/revocation, and R3 remains the sole session owner. No listener
is activated by snapshot creation.

### R1/R10 live TLS ownership composition (2026-10-16)

R10 owns the reusable validated `SSL_CTX` and must outlive every
per-connection `SSL` created from it. R1 takes unique ownership of that
server-role SSL only after the same R1-owned accepted socket has completed the
plaintext X.224 exchange and fully written its Connection Confirm. R1 then
attaches its BIO to the already-owned nonblocking TCP object; there is no
second socket, SSL, BIO, TLS state machine or listener owner.

A successful handshake exposes only the short-lived read-only
`establishedTls()` borrow and value-form
`SecurityNegotiationProvenance`. Both are transport evidence, not R2
identity/OS admission or R3 session authority, and cancellation revokes them
with the immutable peer endpoint. R1 never rereads credential pathnames: SSLs
created after pathname replacement still use the certificate snapshot
retained by the live R10 context. The production contract is unchanged;
dedicated loopback integration tests now prove this composition.

### R4 deterministic metadata before stateful encode (2026-10-16)

AVC420 envelope metadata validation is shared between the packetizer and the
x264 producer through `gfxAvc420PictureMetadataValid()`. It intentionally
does not inspect Annex-B bytes: surface/frame IDs, coded/visible geometry,
region count/bounds and quant-quality entries are all knowable before encode
and must be rejected before x264 can change reference history.

This keeps ordinary malformed work cheap and reference-stable. Only failures
that can occur after x264 has genuinely accepted a picture—encoded-payload
validation, allocation/framing/reservation failure, or terminal delivery
failure—may require codec-history invalidation. R3 channel/session authority
and the existing R4 presentation lifecycle remain unchanged.

### R4 x264 publication/reference ownership (2026-10-16)

`X264Avc420SegmentedFrameProducer` is the native-codec subordinate of the
existing `GfxPresentationLifecycle`, not another graphics controller. One
producer instance is bound to one presentation generation and one coded/
visible geometry pair. Its synchronous input NV12 planes remain caller-owned;
its output is the existing move-only `GfxAvc420SegmentedFrame`, which owns
the complete RDP8 segmented wire bytes for a future R3 send.

The producer preflights lifecycle generation, mapped surface and backpressure
before encoding. Once x264 accepts a picture, that picture has entered codec
reference history. Therefore any later failure to reserve/packetize the same
frame invalidates that history: the producer immediately reconstructs x264 at
the same geometry so the next accepted frame is IDR. Conversely, ordinary
backpressure rejected before encode leaves the existing reference chain
untouched. Terminal frame-delivery abort closes the presentation through its
existing owner and resets codec history.

R3 remains solely authoritative for authenticated Graphics DVC ownership,
fragmentation and full transport completion. R2/native roads remain solely
authoritative for admitted desktop/capture ownership. This producer cannot
open a DVC, admit a peer, capture pixels, acknowledge delivery or create a
second scheduling queue.

### R4 stable segmented-frame handoff ownership (2026-10-16)

`GfxAvc420SegmentedFrame` owns exactly one complete R4 outbound frame after
RDP8 segmented-data framing. It is move-only and retains the contiguous wire
bytes plus the private `GfxFrameDeliveryReceipt` created by the existing
`GfxPresentationLifecycle`. Preparation composes, rather than replaces,
`prepareAvc420Picture()` and `buildGfxSegmentedData()`; exact in-place
expansion avoids a second large graphics copy.

R3 remains the sole future owner of authenticated Graphics DVC routing,
fragmentation, socket/TLS progress and the decision that all outer segmented
bytes were delivered. R3 may borrow `wireBytes()` only while retaining the
owning frame object. A successful full-send callback is translated back to
the lifecycle's inner graphics-byte receipt before ACK publication. Partial
or terminal send failure delegates to the existing lifecycle abort, revoking
the generation. Neither the object nor its helpers can open a DVC, authorize
capture, advance authentication or bypass R2/R3.

### R10 Linux runtime security provisioning ownership (2026-10-16)

`LinuxRuntimeSecurityConfiguration` is a service-lifetime R10 owner, not a
new authentication state machine. It owns one native keytab descriptor, the
exact `TERMSRV/host@REALM` service-principal text, and one existing
`ConsoleIdentityPolicy`. It is noncopyable/nonmovable and one-shot so a
running configuration cannot silently replace its keytab or policy.

Linux keytab resolution is object-first. R10 component-walks the configured
`FILE:/absolute/path` without following symlinks and accepts only a bounded
private regular file owned by the effective uid. It retains that descriptor,
then supplies `FILE:/proc/self/fd/<descriptor>` to the already-existing R2
`GssapiSpnegoAcceptor::configure`. The provider may open that procfd URI, but
it still names the retained kernel file object; changing the original pathname
does not change the service credential source. The configuration object must
outlive all R2 acceptors configured from it.

A temporary R2 acceptor is used during provisioning solely to prove that MIT
GSS can acquire the exact acceptor credential. `gss_acquire_cred_from`
success here is **service credential provisioning**, not client
authentication. Client identity still requires the existing TLS-bound
CredSSP/SPNEGO transcript; native authorization still requires
`LinuxConsoleAdmissionBroker` to revalidate concrete NSS/logind/session-watch
facts and mint its move-only lease. R3 remains the only session state owner.

The offline Linux preflight composes this owner with
`RuntimeServerTlsContext` and one immutable identity rule. It destroys all
temporary owners before returning and never binds a socket. A future serving
runtime must instead retain both R10 owners for the full connection population,
create one R1 SSL per connection, one R2 GSS acceptor/broker per connection,
and revoke R3→R2 before releasing R1/R10 ownership.

### R10 runtime TLS-context ownership (2026-10-16)

### R6 generation-pinned Windows SendInput controller

`WindowsInputController` is a native R6 state owner for keyboard/pointer
injection, not an authentication decision, RDP input parser, session router or
scheduler. The future sole R3 session owner may construct/invoke it only after
R2 independently authenticates and authorizes the exact Windows desktop. Its
`WindowsCaptureGenerationReader` is reused solely to revoke stale native
state; fabricated session/device numbers grant no capability.

The controller accepts scan-code make/break state, absolute pointer movement,
left/right/middle/X1/X2 buttons and bounded vertical/horizontal wheel deltas.
It validates a canonical existing `WindowsDesktopLayout`; points in monitor
gaps are rejected. Portable desktop coordinates are normalized to 0..65535
and production emits `MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK`.
Keyboard production packets use `KEYEVENTF_SCANCODE`, optional
`KEYEVENTF_EXTENDEDKEY`, and `KEYEVENTF_KEYUP`; no keyboard-layout virtual
key lookup is introduced. Pointer move+button and move+wheel are submitted as
one `SendInput` array so Windows inserts each pair serially.

The controller tracks at most 512 scan-code/extended slots and five mouse
buttons in contiguous fixed arrays. Duplicate transitions do not issue native
input. Any malformed request or short native insertion terminally cancels the
owner. Cancellation is deferred across a synchronous native callback and
best-effort releases held input only if the pinned generation still matches.
Once generation observation fails or changes, local held state is discarded
without sending key/button releases into the new desktop generation. The
Win32 translation to `SendInput` is compiled in the native translation unit,
but its callback factory is intentionally not exported while no genuine R2/R3
Windows admission capability exists. Thus generation numbers alone cannot make
the R6 API call native input. The runtime creates no such controller, so
ordinary builds/tests cannot inject host input. `SendInput` can be blocked by
UIPI and reports the count of inserted events; R6 treats a short return as
failure rather than retrying or claiming authorization. Generation-reader
callbacks are also reentry-guarded; cancellation requested inside a generation
observation completes before any new native input.


`RuntimeServerTlsContext` is the sole R10 owner of the reusable server
`SSL_CTX`. Construction is one continuous credential-snapshot pipeline:
secure native open → metadata/identity policy → exact bounded read → PEM parse
→ current validity/server-purpose/key-match checks → `TLS_server_method()`
context population. OpenSSL receives the already-parsed `X509` and
`EVP_PKEY` objects through `SSL_CTX_use_certificate` and
`SSL_CTX_use_PrivateKey`; no filename-loading API is used, so there is no
post-validation pathname replacement boundary. `SSL_CTX_check_private_key`
must also succeed before the owner becomes valid.

The context has a TLS 1.2 minimum and no TLS 1.3 cap. Compression is disabled,
and legacy renegotiation is disabled where the OpenSSL build provides that
option. Default OpenSSL cipher/security-level policy is otherwise retained.
The certificate-file contract currently accepts exactly one certificate PEM
object; a second certificate or other trailing non-whitespace material is
rejected. Therefore this increment does not yet present an intermediate chain
and does not claim CA trust, hostname acceptance, external revocation status or
client interoperability.

For each accepted connection, R10 may call `createServerTls()`, which creates
one server-role `SSL` with the exact unique-owner type expected by R1
`OwnedPreauthTcpConnection::attachServerTls`. The runtime context logically
outlives all of these connections; R1 remains the sole per-connection owner of
SSL/BIO/socket state. R2 may later borrow only R1's established `const SSL*`
and R3 owns session state; neither owns the context or transport objects.

Offline credential checks and live context construction share the same
validated-snapshot loader. Successful offline acceptance is still distinct
from a live `SSL_CTX`, and a live context is still distinct from listener
activation, R2 authorization, R3 session activation and external-client
acceptance. No listener or service lifecycle is introduced here.

# RDP-server architecture

### R6 acquired-frame DXGI pointer ownership

Pointer metadata stays inside the existing Desktop Duplication frame lifecycle.
`WindowsDxgiFrameOwner` copies the position timestamp/visibility/coordinates
and shape-buffer size from the same `DXGI_OUTDUPL_FRAME_INFO` returned by
`AcquireNextFrame`; it owns no second lease. Position change and shape change
are deliberately separate because DXGI can report a new shape without a mouse
move. The per-frame metadata is invalidated before `ReleaseFrame`.

`WindowsDxgiPointerShape` is a move-only, independently owned native-shape
record. `GetFramePointerShape` executes only while the duplication still owns
that acquired image. Reads are bounded to 512 KiB and 256x256 logical pixels
and validate exact pitch/byte layout, hotspot and the three DXGI shape types.
Monochrome data contains vertically paired AND then XOR planes, so the native
scanline height is even and the logical height is half. Color and masked-color
keep their native 32-bpp bytes; masked-color alpha is accepted only as the
DXGI-defined 0/0xff replace/XOR mask. This adapter does not convert shapes into
an RDP pointer PDU.

The existing `WindowsDxgiCaptureCycle` copies a new shape before attempting
the nonblocking D3D11 staging map. Therefore a GPU-not-ready frame can release
its DXGI lease without losing the cursor update. One pending owned update
coalesces independent position-only and shape-only changes without allocating
for position-only motion; a newer value replaces only its own half. A visible
DXGI output-relative top-left is checked and translated through the selected
output's signed desktop origin. The pending record carries the already-pinned
session/device generation. Generation failure before publication clears it;
cancellation during the native shape callback is deferred until callback
return. Terminal cleanup releases the acquired DXGI frame exactly once. If a
staging map exists it is unmapped before `ReleaseFrame`; a denial before
mapping correctly performs no D3D11 unmap callback.

`WindowsDxgiDuplicationOwner::attachCaptureCycle` supplies this borrowed
shape callback and exact selected-output rectangle to the same capture cycle it
already owns. R2/R3 must independently authorize and bind the Windows desktop;
an HMONITOR, WTS ID, successful duplication or cursor bytes are not admission.
R4 remains the sole scheduler and may retain only the independently owned
cursor update. Live desktop capture and input injection remain outside ordinary
CTest and outside this increment.





### R10 TLS server-certificate purpose gate (2026-10-16)

After native credential-file identity/permission checks, exact bounded reads,
PEM parsing, certificate time validation and certificate/private-key matching,
the offline credential preflight asks OpenSSL to validate the certificate for
`X509_PURPOSE_SSL_SERVER`. Certificates constrained to incompatible purposes,
such as clientAuth-only EKU, fail closed. The decision uses the same
handle-derived bytes and does not reopen either credential path. This remains
an offline prerequisite: certificate trust, hostname, revocation, R2 identity,
R3 authority, listener activation and service installation are not established.

### R6 native D3D11/DXGI duplication ownership (offline integration)

`WindowsDxgiDuplicationOwner` is the native R6 COM RAII boundary, not
an authorization capability or another capture scheduler. After R2/R3
authorizes one desktop target, the caller supplies an HMONITOR identity
and expected signed monitor rectangle from the same display generation.
The owner enumerates DXGI adapters and outputs (bounded to 32 each),
selecting exactly one attached, identity-rotation output with matching
HMONITOR and desktop coordinates. Detached, empty, mismatched, duplicated,
changed, or unsupported outputs fail closed without substituting the
primary adapter or first output. The selected adapter is passed to
`D3D11CreateDevice` with `D3D_DRIVER_TYPE_UNKNOWN`, BGRA support
and required feature level 11.0; no WARP fallback. `IDXGIOutput1`
`DuplicateOutput` creates one owned duplication per owner.

The owner holds one reference to the DXGI factory, selected adapter and
output, output1, D3D11 device and immediate context, and duplication. During
bounded enumeration a candidate adapter may alias the already-retained selected
adapter; such an alias is not a second owned reference and is never released
separately. Ambiguous duplicate-output denial releases each output reference
once and leaves terminal `close()` to release the retained adapter once.
All failed construction paths release returned partial native references.
`close` is terminal; destruction first cancels/destroys the existing
`WindowsDxgiCaptureCycle` (unmap before ReleaseFrame), then drops native
staging context, duplication, output1, context, device, output, adapter,
factory. A nonzero monotonic process-local device epoch is invalidated
before native teardown. Stale session epochs revoke through the existing
generation observer; R10 owns WTS event delivery and the session guard
remains revocation-only. There is no automatic recreation on unlock.

The optional `attachCaptureCycle` composes the already-existing frame
owner/staging map/capture cycle with borrowed callbacks and a revocation
reader. It does not expose owned D3D interfaces or pixel data to R4.
All native calls are serialized on the capture owner thread, with no
callback still in progress during destruction. R4 must synchronously
consume or copy into independently owned bytes. Ordinary Windows CTests
inject synthetic COM-like resources, never call live `DuplicateOutput`,
and do not prove real desktop capture or OS authorization.


**Armada:** RDP protocol first. Fast native C++23 implementation. No
workarounds when a standards-compliant RDP mechanism already solves the problem.

## Module boundaries

```text
Windows App / Microsoft Remote Desktop / FreeRDP / other RDP clients
                         │
           TLS + CredSSP/NLA + X.224/TPKT
                         │
               MCS/GCC and RDP session
                         │
              RDP virtual-channel router
                   ┌─────┼─────┐
             graphics  input  CLIPRDR and channels
                   └─────┼─────┘
                 platform abstractions
       ┌───────────────┼──────────────┐
     Linux           macOS         Windows/other OS
```

The diagram is the **target**, not an implemented daemon. Source-owned
foundation APIs currently reside in `src/server/transport`,
`src/server/security`, `src/server/clipboard`,
`src/clipboard`, `src/core` and `src/rdp`.
`src/x11` contains Linux/X11-specific adapter candidate code: it is not a
portable dependency of the protocol archive. A separate noninstalled
Linux `rdp-server-linux-xshm` target compiles the real native
XShm capture adapter when pkg-config finds `xcb` and `xcb-shm`.
Its headless CTest uses a deliberately invalid XCB fd to check
fail-closed construction without contacting a desktop. Neither this
target nor this test authorizes an OS session or delivers R4 frames.
Other imported algorithms not
listed in CMake are under porting review and are not silently shipped.

### R5 native XDamage cancellation boundary (Linux only)

`X11DamageTracker` borrows the existing XCB connection rather than
owning or closing it. The owner must invoke its idempotent
`disconnect()` before destroying the XCB connection. While the
transport is healthy, cancellation releases its XDamage server-side
resource; in every case it clears the borrowed pointer, pending
regions, observations and counters. The destructor reuses this path
and never needs to touch XCB after cancellation. A failed connection
is rejected before XDamage extension negotiation. The dedicated
noninstalled Linux `rdp-server-linux-xdamage` target links only
`xcb`, `xcb-damage` and the existing bounded `DamageRegion`;
the portable protocol engine, SDK and macOS/Windows builds remain
unaffected. The native CTest uses a deliberately failed XCB descriptor
and never authorizes or observes a real desktop. R2 and R3 must grant
independent access before any protected capture or input; R4 alone
schedules graphics transmission.

### R5 native XFixes cursor lifetime (Linux only)

The existing `X11CursorTracker` borrows a native `xcb_connection_t`
from the R5 XCB connection owner. Its `disconnect()` is an explicit,
repeatable cancellation barrier: it drops the borrowed pointer and
cached pixel/mask views, resets pending image state and warning flags,
and prevents further XFixes requests or event handling. The owner must
cancel the cursor before destroying its XCB connection, and no consumer
may retain cursor spans beyond cancellation or the next refresh.
Constructing the cursor against a failed XCB connection is rejected
before negotiating XFixes. The native `rdp-server-linux-xfixes-cursor`
CMake target compiles the existing native tracker and first-party pixel
converter against `xcb` and `xcb-xfixes` only on Linux, not into the
installed portable SDK. The headless native test uses only an invalid
XCB descriptor and never confers R2/R3 authorization. R4 alone owns
graphics scheduling and cursor delivery.

### R5 native XTEST input lifetime and typed boundary (Linux only)

`X11InputController` now consumes the R5-native, allocation-free
`X11InputEvent` variant rather than historical xrdp `WM_*` and
`KBD_FLAG_*` identifiers. The typed requests preserve the existing X11 keysym,
scan-code slot, pointer, button, lock and bounded scroll semantics without
pulling xrdp or libX11 into the adapter. This native type does **not** confer
authorization: R3 must translate and forward only already-authorized input
after R2 OS-session admission.

The controller borrows one live `xcb_connection_t` and never owns or closes
it. Failed XCB connections are rejected before XTEST negotiation.
`disconnect()` is the repeatable cancellation barrier: while the borrowed
owner is valid it releases held keys/buttons, then clears native state and the
borrowed pointer so destruction cannot touch a later-destroyed connection.
The noninstalled Linux `rdp-server-linux-xtest-input` target links only
`xcb` and `xcb-xtest`; it is not linked into the server runtime yet.
Its ordinary native CTest uses an already-failed XCB fd and therefore cannot
inject real keyboard or pointer input.

The stateless `X11AuthorizedInputRoute` is the only R5 boundary allowed to
invoke the aggregate's private XTEST child. It owns no session, permission
cache or input state. Every dispatch requires the concrete broker-issued
`LinuxConsoleAdmissionLease` plus the live GSS/TLS and sole R3
`McsSessionLifecycle`; immediately before XTEST it calls the existing R2
`authorizeR3ProtectedTransition(..., kConsoleInputPermission)`. Missing or
stale admission, generation mismatch, native-owner loss, or XTEST failure
closes the X11 owner and the R3/R2 path. A Boolean, policy match, desktop
handle or caller-supplied generation can never authorize input.

### R5 one-XCB desktop resource ownership (Linux only)

`X11DesktopResources` owns the existing `X11DisplayConnection` together
with the existing XShm capture, XFixes cursor, XDamage and XTEST input
adapters. It adds no second connection, graphics scheduler, authorization
state or protocol engine, and the runtime does not link it before R2/R3
admission. Child cancellation is ordered input, cursor, Damage, XShm, then
the sole XCB connection. Construction failures use that same path.

The aggregate now owns the bounded native event-routing call. Each serviced
event is offered directly to the owned cursor and Damage trackers on the same
serialized XCB thread; no event memory or child pointer escapes the callback.
After the display owner processes its internal RandR observation, the
aggregate compares the new source geometry with the generation that XShm,
Damage and input were constructed against. A valid size change stops the
display drain before any later queued event is serviced. The aggregate then
cancels the old input/Damage/XShm generation, reconstructs all three against
the new bounds on the **same** XCB connection, and commits the new geometry
only after every child is valid. Any reconstruction failure revokes the whole
native owner instead of exposing a mixed generation. XFixes cursor remains
connection-bound rather than geometry-bound and is retained across a
successful resize.

This is a synchronous commit-or-revoke transition on the serialized XCB owner
thread, not a second scheduler. The caller is told work may remain after a
screen-change boundary so queued events are drained only after the new
generation is complete. R4 still owns frame/cursor scheduling and R3 still
owns authorized input routing.

The aggregate also exposes the synchronous native read boundary that R4 can
consume without gaining ownership of any X11 object: `snapshotDamage()`
copies the current bounded XDamage rectangles into a caller-owned
`DamageRegion`, `capture()` returns one borrowed XShm `FramebufferView`,
and the cursor methods expose pending/refresh/image/ack state from the existing
XFixes tracker. Framebuffer bytes remain valid only until the next capture,
RandR rebuild or disconnect; cursor spans remain valid only until the next
cursor refresh or disconnect. Native child failure during capture, Damage
acknowledgement or cursor refresh revokes the aggregate instead of leaving R4
with a partially failed source. Retryable cursor-image query diagnostics remain
available through the same owner. These calls do not schedule frames, retain
borrowed views, authorize a desktop or inject input: R4 remains the sole
graphics scheduler and R2/R3 remain the admission/input authorities.

A dispatch/protocol failure invalidates `X11DisplayConnection` readiness but
does not immediately free its XCB allocation. The aggregate therefore gets a
deterministic child-before-parent cancellation window even when the event
stream fails. Public descriptor/native access is denied as soon as failure is
observed; explicit `disconnect()` or destruction performs the final close.

The noninstalled aggregate builds only when all five native adapter targets
exist. Headless denial tests need no X server. Ephemeral-Xvfb CTests exercise
complete resource lifetime, real XDamage notification routing, and a deliberate
protocol-error path proving connection destruction is deferred until ordered
owner teardown. They touch no logged-in desktop and inject no user input.

### R8 native X11 CLIPBOARD publication (Linux only)

`X11ClipboardAdapter` is an R8 presentation adapter, not another clipboard
session owner. `RemoteTransfer` remains the sole generation, verified-content
and pending-paste owner. The adapter borrows `X11DesktopResources`' sole XCB
connection and root window; R5 exposes those handles only while its aggregate
is valid and can fan the same bounded XCB event batch to one additional sink.
The clipboard adapter never calls `xcb_connect`, never closes the borrowed
connection and must be disconnected before the R5 owner.

Only `CLIPBOARD` is claimed; `PRIMARY` is never interned or modified.
Fixed native atoms are bounded to `CLIPBOARD`, `TARGETS`, `UTF8_STRING`,
`image/png` and `INCR`. A current remote generation advertises UTF-8 text when
CF_UNICODETEXT is offered and `image/png` only when that generation names a
registered PNG format. Verified PNG bytes remain compressed; DIB/DIBV5 are
never mislabeled as PNG. A 64-KiB direct-property ceiling keeps ordinary
ChangeProperty requests bounded. Larger verified text/PNG uses ICCCM INCR:
the request property first carries one 32-bit total byte count with type INCR,
then the adapter waits for PropertyDelete acknowledgement before each bounded
64-KiB target-typed chunk and ends with one zero-length chunk. The adapter
borrows the existing RemoteTransfer storage throughout; it does not duplicate
the whole transfer.

SelectionRequest handling is nonblocking with respect to CLIPRDR. Ready R8
views are borrowed only for the synchronous property write. Otherwise one
native request binds to one monotonic `RemoteTransfer` paste receipt and a
two-second monotonic deadline. The adapter exposes only the exact remote
format-fetch intent; R3 must still authorize and serialize any Format Data
Request through its one writer. `PasteKind::Png` prevents an already-ready
DIB fallback from satisfying an `image/png` request. Property success precedes one SelectionNotify. For INCR, that same notify is
the only SelectionNotify; later chunk failure cancels the incremental state
rather than sending a contradictory second terminal notify. Before native
bytes become ready, timeout, replacement, disconnect or owner loss still uses
the X11 failure form exactly once.

SelectionClear or an observed different owner yields immediately, cancels the
exact pending receipt by sequence and marks that remote generation as yielded.
The adapter ignores its own owner observation and has no timer or same-
generation reclaim path. Ownership tracks remote generation, native epoch and
source rather than content hashes. An active INCR additionally binds the exact
requestor window/property to that generation/epoch, restores the requestor's
previous event mask on normal completion/cancellation, skips restore after
requester destruction, and has a five-second monotonic acknowledgement
deadline. Runtime activation remains disabled until R2/R3 provide genuine
admitted CLIPRDR/session authority. DIB-to-PNG, Windows/macOS adapters and
native file-destination integration remain later R8 increments.

### R8 bounded FileContents metadata and range owner

The portable `RemoteTransfer` remains the single CLIPRDR generation owner for
file-copy state. File streaming activates only when the current remote offer
contains the registered `FileGroupDescriptorW` format and the negotiated
general capabilities include `CB_STREAM_FILECLIP_ENABLED`. The owner stores
no remote file body. It retains a fixed-capacity array of at most 64 parsed
FILEDESCRIPTORW records for the current clipboard generation.

Each descriptor is exactly 592 bytes: attributes and FILESIZE are consumed only
when their validity bits are present, and the 260-code-unit UTF-16LE name is
validated as a NUL-terminated leaf name with strict surrogate pairing and zero
padding. Source paths and Windows-reserved path/name characters are rejected
rather than being converted into local paths. Directory descriptors may be
observed as metadata but are not eligible for byte-range retrieval. A size
above 32 bits or a range with a nonzero high offset is accepted only after
`CB_HUGE_FILE_SUPPORT_ENABLED` was jointly negotiated.

FileContents requests are separate from ordinary Format Data requests because
their responses carry an explicit stream ID. R8 allocates one monotonic,
nonzero stream ID per request and never resets that counter across disconnect.
This first bounded owner permits one FileContents request at a time. SIZE uses
the protocol-mandated eight-byte request length; RANGE is limited to 64 KiB and
must fit the known file size. Responses must echo the pending stream ID. Range
bytes borrow the caller's complete PDU and are never copied into a whole-file
cache. Generation replacement clears descriptor metadata; a late response for
the old generation is consumed as obsolete instead of being attached to a new
file list.

For an outbound FileContents request, R8 can additionally wrap the same exact
32-byte CLIPRDR PDU in one 8-byte uncompressed static-VC header and delegate
MCS SendDataIndication serialization to the existing confirmed-join gate.
The resulting caller-owned packet has a sequence-bound cumulative write
receipt. Before any byte is submitted, generation replacement can revoke and
cancel it. Once any prefix may have reached the transport, abandonment is
ambiguous and poisons the clipboard coordinator until genuine disconnect.
Only a fully submitted frame may consume its FileContents response; a fully
submitted retired-generation response is drained as obsolete. This is an
offline membership/framing boundary only: the join gate is not evidence of
R2 admission, negotiated CLIPRDR role, valid session stage, security-header
policy or ownership of the one TLS writer.

The supported general capability mask intentionally omits
`CB_CAN_LOCK_CLIPDATA` until R8 owns lock/unlock transmission and completion
receipts. The FileContents state added here does not grant MCS membership,
CLIPRDR role authority, R2 admission, TLS write permission or a local file
destination. Those remain R3/R2/native-adapter responsibilities.

### R5 native XCB connection readiness and ownership

The existing `src/x11/x11_display_connection.{h,cpp}` is the only XCB
connection owner. It obtains its borrowed file descriptor via
`xcb_get_file_descriptor`; R10's eventual event loop owns polling, not
the socket, and must never close/duplicate that borrowed descriptor.
On the owning XCB thread it calls
`processEvents(sink, budget, workMayRemain, socketReadable)` after
readiness and to drain already queued events. It polls the XCB socket
only when externally reported readable; an exhausted event budget
signals that more buffered work MAY remain (another service iteration
is needed even without a new edge). Event callbacks only borrow event
memory until return. XCB protocol errors and connection failures
invalidate native access; `disconnect()` is idempotent and clears
descriptor, root/window/depth, screen number and geometry. RandR
screen-change root notifications update native geometry.

`rdp-server-x11-connection` is a separate Linux-only first-party target
requiring XCB and XCB/RandR development packages. It is not exported,
installed, or linked into the portable protocol SDK; `src/x11`
headers are excluded from the portable SDK installation. Ordinary
CTest runs use synthetic XCB events and invalid display syntax without
a desktop. The native connection alone grants no authenticated R2/R3
OS session permission and must not trigger protected capture or input.
R4 remains the sole frame scheduler.

### Windows monitor layout adapter (R6; not session-integrated)

The native adapter spells the existing portable `struct ::Rectangle` as
`PortableRectangle` inside `rdp_server::windows`. This avoids WinGDI's
unrelated global function `Rectangle` hiding the type when `windows.h`
precedes adapter headers; no new rectangle representation is introduced.

`src/windows/windows_desktop_geometry.{h,cpp}` is a separate Windows-only
native adapter target, not part of the portable protocol library or its
installed SDK. It samples the calling thread's Win32 monitor rectangles via
`EnumDisplayMonitors`/`GetMonitorInfoW`; the public header uses only the
existing portable `Rectangle` contract. A fixed 16-monitor owned snapshot
canonically sorts monitor rectangles to suppress false topology changes,
computes a checked signed-origin virtual desktop and allows coordinate
translation only inside actual monitor rectangles, not virtual gaps. A
fresh snapshot is required after topology changes. Enumeration of the
calling process's displays is not evidence of authenticated OS admission,
desktop/window-station authorization, capture or input permission. The
future R2/R3-controlled runtime must bind this snapshot to an independently
authorized interactive Windows session before using it for capture/input.
The R4 scheduler remains the sole owner of graphics lifecycle.

### Windows DXGI BGRA mapped-view boundary (R6; offline only)

The Windows-only `windows_bgra_frame` helper borrows pixels from an
externally owned mapped DXGI surface and produces the existing portable
`FramebufferView` without a copy. DXGI Desktop Duplication supplies
top-down `DXGI_FORMAT_B8G8R8A8_UNORM`; the contract retains BGRA byte order
and the native row pitch (which may exceed width * 4). It verifies the
full pitched allocation (including final-row padding) and limits one view
to 512 MiB before returning a bounded span. The consumer must finish
using the view before the producer unmaps/releases the native frame;
asynchronous R4 processing requires separately owned frame bytes.
No COM/DXGI object or Windows header enters portable protocol code.
R2/R3 admission must be enforced by the future native capture owner;
this helper itself neither accesses a desktop nor grants permission.

### Windows DXGI capture-cycle ordered lifetime (R6; offline only)

`WindowsDxgiCaptureCycle` only composes the existing duplication
lease owner and D3D11 staging-map owner; it does not control R4
scheduling or R2/R3 admission. Its inputs are borrowed callbacks
created for an independently authorized Windows session, plus
a validated desktop-layout snapshot. An explicit caller-sampled
layout mismatch, disconnect/cancel, access loss or release failure
revokes the cycle. Every frame completes its staging unmap before
the duplication lease's `ReleaseFrame`. Reentrant cancellation
is deferred until the in-progress acquire/map/unmap callback returns;
the view cannot be observed when the owner is revoked. R4 must copy
pixel bytes synchronously before enqueueing. No active Win32
enumeration, input injection, graphics queue, or live desktop
capture is performed by tests. DXGI requires releasing a frame
before the next acquisition; access loss requires recreating
duplication:
https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutputduplication-releaseframe

### R6 session/device capture generation invalidation (offline only)

`WindowsDxgiCaptureCycle` can optionally pin two nonzero lifecycle
epochs for a separately authorized Windows native interactive session
and D3D11 device/output. Its **revocation-only**
`WindowsCaptureGenerationReader` checks that neither epoch has
changed on either side of frame acquisition/mapping, synchronous
pixel consumption and native damage reads. Failed observations and
reentrant cancellation invalidate the cycle; one staging mapping is
unmapped before the original DXGI lease releases exactly once. A
guarded cycle does not expose an unchecked raw borrowed view through
`frame()`; consumers must use checked synchronous
`consumeFrame`/`copyFrameTo`. Independently owned output is
published only if its generation is still current on return.
An asynchronously side-effecting consumer cannot have its work
rolled back, so R4 must use the owned-copy path before enqueueing.
This guards reuse of stale capture resources but **does not grant
authentication, OS-session admission, ACL access or desktop
permissions**. Synthetic callback epochs are not trustworthy
authority. Live Windows capture remains disabled until R2/R3
supplies independently verified session/device lifecycle and
R4 owns asynchronous frame scheduling.

### R6 active Windows session revocation guard

`WindowsCaptureSessionGenerationGuard` is a Windows-adapter safety
boundary layered in front of the existing capture generation reader.
The future R2/R3 owner supplies a target session identifier and the
existing nonzero session/device epochs. The native observer verifies
that the current process belongs to that exact session with
`ProcessIdToSessionId` and queries its WTS connection state with
`WTSQuerySessionInformationW(WTSConnectState)`; only `WTSActive`
allows the existing epoch observation to proceed. Read failure,
process/target mismatch, inactive state, zero generation or reentrant
observation terminally closes the guard. A new guard/capture cycle is
required after revocation.

The same guard also exposes `notifySessionChange(sessionId)` as a
same-capture-owner-thread revocation sink. Any valid event for the selected
session closes the guard, so lock/unlock, connect/disconnect and
logon/logoff cannot silently preserve an old capture generation once the
runtime routes those native WTS changes. Unrelated session IDs are ignored;
malformed zero/sentinel IDs fail closed. A notification delivered
reentrantly during a session observation prevents that observation from
publishing its generation. Unlock/reconnect does not reopen the guard.

This layer grants no rights: a caller can fabricate the target ID and
synthetic callbacks, so R2/R3 must independently authenticate the user,
authorize the native session and own its lifetime. The guard deliberately
does not register a window, service control handler or WTS notification
source. R10/R3 must marshal `WM_WTSSESSION_CHANGE` or
`SERVICE_CONTROL_SESSIONCHANGE` delivery onto the serialized R6 capture
owner and promptly cancel an active cycle after target revocation. Ordinary
CTests execute synthetic callbacks only.

### R6 read-only Win32 cursor metadata snapshot

`WindowsCursorSnapshot` is a small owned metadata record, not a cursor
bitmap or R4 graphics packet. `readWindowsCursorSnapshot` samples one
injected/native observation synchronously, then translates the native
virtual-screen position through the existing validated
`WindowsDesktopLayout`. Visible cursors require nonzero dimensions no
larger than 256x256, an in-bounds hotspot, and a position on an actual
monitor rather than a virtual-desktop gap. Invalid/unavailable reads leave
the previous snapshot unchanged; hidden or touch/pen-suppressed state
successfully clears stale visible metadata.

The Windows callback uses `GetCursorInfo` for global cursor state and
screen position, then `GetIconInfo` plus `GetObjectW` only while the
cursor is visible. `GetIconInfo` creates mask/color bitmaps, so the adapter
owns those temporary `HBITMAP` values through stack RAII and calls
`DeleteObject` on every exit path. Color mask/color sizes must agree.
For a monochrome cursor, the mask bitmap contains AND and XOR halves, so
its height must be even and the logical cursor height is half the bitmap
height. The observer retains no HCURSOR/HBITMAP after return and extracts
no shape pixels yet.

Reading global cursor state is not authorization. R2/R3 must first bind the
correct interactive Windows session/desktop and its lifecycle; R4 remains
the sole cursor/graphics delivery owner. Ordinary CTests use synthetic
callbacks and never inspect a live cursor. Cursor shape conversion and
generation-safe R4 handoff remain subsequent work.

### R6 bounded native DXGI move/dirty metadata on active lease

`WindowsDxgiCaptureCycle::readFrameDamage` samples metadata only
while the EXISTING DXGI lease and D3D11 staging map are held. The caller
must bind the borrowed `WindowsDxgiDamageReadCallbacks` to that same
duplication after independent R2/R3 OS authorization. Native
`GetFrameMoveRects`/`GetFrameDirtyRects` result byte counts must be
multiples of SDK descriptor sizes and together fit 1,024 rectangles.
The existing normalized portable damage format and move-before-dirty
ordering are reused. Invalid/cancelled/access-lost reads terminally
revoke the cycle, with no partially published damage; cancellation
inside callbacks defers unmap and DXGI frame release until return.
No second acquisition owner, R4 scheduler or live desktop access.

### Caller-owned packed BGRA handoff (R6; offline tested)

`WindowsDxgiCaptureCycle::copyFrameTo` reuses the existing
synchronous `consumeFrame` callback to copy a mapped DXGI BGRA8
texture into caller-provided storage as tightly packed rows. It
validates dimensions, full pitched source layout, destination size,
512 MiB per-frame bounds and complete disjointness from GPU mapping
(including source row padding). No allocation, new frame owner, cache,
R4 queue or Windows framebuffer type is created. Only a successful
consume/unmap/`ReleaseFrame` result publishes a portable
`FramebufferView` over the caller's independent bytes. Every denial
still releases the acquired frame in map-before-lease order.
The caller controls the output storage lifetime; R4 must agree on
generation/queue ownership before retaining frames asynchronously.
This helper does not authorize or acquire a native desktop.

### Scoped DXGI mapped-frame consumption (R6; synthetic tests only)

`WindowsDxgiCaptureCycle::consumeFrame` is the synchronous R6 handoff
for an already-acquired/mapped frame. It borrows the existing portable
`FramebufferView` only for the duration of the consumer callback, defers
session/topology cancellation inside that callback, rejects reentrant
release/capture, then unmaps its one D3D11 staging resource BEFORE the
existing DXGI lease owner releases the resource and calls `ReleaseFrame`.
Missing/rejecting consumers still release the lease. R4 must copy or
otherwise independently own pixels before returning if enqueueing work
asynchronously. No new capture owner, graphics scheduler, admission
token, Windows service or live desktop access is introduced.

### Windows D3D11 staging map/copy lifetime (R6; fixture-only admission)

`WindowsD3D11StagingMap` extends the existing BGRA pitch/bounds view
and `WindowsDxgiFrameOwner` acquisition lease without creating a
second frame scheduler. A caller-owned, authorized D3D11 device and
immediate context provide an `IDXGIResource` already acquired from
Desktop Duplication. Native callbacks query its BGRA8 texture,
check dimension/array/mip/sample limits and 512 MiB cap, create
a CPU-read `D3D11_USAGE_STAGING` texture, `CopyResource`, then
`Map(D3D11_MAP_READ, D3D11_MAP_FLAG_DO_NOT_WAIT)`. A GPU-busy
outcome leaves the staging map retryable; other invalid states
invalidate the native owner. An owned mapping lives in one fixed
native context, which unmaps before releasing its texture. The
portable `FramebufferView` borrows mapped memory and is invalidated
before unmap or cancel; the DXGI duplication-frame lease must be
released only after unmapping. Callbacks are single-thread affine;
reentrancy and cancellation during staging cannot publish pixels.
Real device/context construction, session admission, asynchronous
R4 owned-frame transfer, encoder queues, and desktop input remain
outside this adapter. Windows COM/D3D11 headers stay out of the
portable protocol SDK. Offline CTests never call a native GPU.
Microsoft documents these mechanics in
[CopyResource](https://learn.microsoft.com/en-us/windows/win32/api/d3d11/nf-d3d11-id3d11devicecontext-copyresource)
and [Map](https://learn.microsoft.com/en-us/windows/win32/api/d3d11/nf-d3d11-id3d11devicecontext-map).

### Windows DXGI acquired-frame ownership (R6; offline acceptance only)

`WindowsDxgiFrameOwner` is the Windows-only single-lease RAII owner
behind an `IDXGIOutputDuplication` callback seam. Its production
callbacks call `AcquireNextFrame` and hold the returned `IDXGIResource`
until exactly one ordered resource release + `ReleaseFrame`; the
duplication interface is **borrowed** from the future R2/R3-authorized
native capture/session owner. Duplicate acquisition is rejected;
timeouts (bounded 100 ms polling) do not close the lease; access loss,
invalid native returns and release failures terminate the owner and
require a new independently authorized duplication. Acquire and release
callbacks are both reentry-guarded. Cancellation during acquisition is
terminal but deferred with respect to callback-owned outputs: if the callback
returns a new lease after cancellation, the owner releases it exactly once
before returning `closed` and never publishes its resource or metadata.
A malformed timeout/error that nevertheless returns a resource is likewise
cleaned through the owner's guarded `releaseFrame` path after the owner is
terminal, so release-callback reentry cannot start a new acquisition.
Cancellation and destruction release any already-held frame once. The
underlying frame resource is only
borrowed by synchronous consumers while the lease exists, never
scheduled or retained by R4. No active desktop, OS authorization,
GPU staging texture, frame queue or new R4 scheduler is implemented.

### Windows DXGI dirty/move metadata boundary (R6; offline only)

`windows_dxgi_damage` is a pure Windows-only per-output metadata bridge:
it validates native-equivalent `RECT` dirty regions and `POINT` source /
`RECT` destination move regions, and publishes caller-owned `Rectangle`
spans in **move destination, then dirty** order. Frame pixels already
include the completed moves; R4 decides how to coalesce and transmit
damage. An empty list (such as pointer-only updates) returns count zero;
invalid counts, source/destination coordinates, short capacity and
unrepresentable dimensions fail transactionally rather than clipping.
The 1024-rectangle maximum is an intentional bounded handoff; capture
must treat an overflow as a failed incremental update and request a
full-frame recovery after validation rather than silently dropping pixels.
Input metadata must come from the same acquired, R2/R3-authorized frame;
the native producer validates DXGI metadata byte lengths and releases
the frame before changing the session. This increment owns no COM
objects, authorization, queue, capture polling or graphics scheduler.

### R4 RDPGFX server segmented-data envelope

MS-RDPEGFX requires every server-to-client Graphics DVC message to be
encapsulated in one `RDP_SEGMENTED_DATA`. The portable
`gfx_segmented_data.{h,cpp}` layer wraps one or more already-complete
RDPGFX messages without owning them. Payloads up to 65,535 bytes emit
SINGLE (0xE0) with an uncompressed RDP8 bulk-data header
(`PACKET_COMPR_TYPE_RDP8=0x04`, compressed flag clear). Larger payloads
emit MULTIPART (0xE1) with segment count/uncompressed size and 32-bit
per-segment encoded sizes. Reverse copies permit exact in-place
expansion without allocations; other overlap is rejected atomically.
This deliberately does not implement the RDP8 compressor yet.

R3 alone owns the reliable `Microsoft::Windows::RDS::Graphics` dynamic
virtual channel, DRDYNVC framing/fragmentation and actual full-send
completion. R4 segmentation cannot authorize a session and cannot mark
a frame delivered. Graphics PDUs must not span separate
`RDP_SEGMENTED_DATA` structures. Normative: MS-RDPEGFX 2.1 and
2.2.5.1–3; Microsoft's sample decompressor verifies that a bulk header
without `PACKET_COMPRESSED` carries raw bytes.

### R4 AVC420 visible-surface crop and coded macroblocks

MS-RDPEGFX AVC420 requires an H.264 bitstream with 16-pixel
macroblock-aligned dimensions but crops display pixels using regionRects.
The optional trailing GfxAvc420Picture::visibleGeometry separates the
mapped RDPGFX destRect and mask from codedGeometry. Both zero defaults
to codedGeometry for existing callers. The checked
gfxAvc420CodedGeometry rounds surfaces up to 16 without u16 overflow.
R4's single GfxPresentationLifecycle compares the *visible* extent
to the mapped surface, then uses the same full-delivery receipt and
bounded ACK accounting. E.g. coded 1920x1088 maps visible 1920x1080.
A genuine x264 encoder must supply correctly cropped SPS/bitstream;
R4 does not validate actual H.264, authorize R3 or show a live desktop.
Normative: MS-RDPEGFX 2.2.2.1, 2.2.4.4, 2.2.4.4.1.
### R4 mapped AVC420 picture composition and receipt boundary

The existing `GfxPresentationLifecycle` now composes
`gfx_avc420_picture` with the same R4 capabilities, mapped surface,
and fixed ACK window. `prepareAvc420Picture` verifies the R3-provided
generation, negotiated/mapped stage, surface ID, matching coded frame
geometry and preflight frame-ID/backpressure before encoding caller
provided Annex-B bytes and atomically reserving the one full-send
receipt. The R3 sender retains the full output until transport
completion; successful serialization is NOT permission to dispatch
graphics and does not mark frame delivered. A denied call leaves
receipt/output/ACK state unchanged. Old-generation callbacks cannot
publish frames after reconnect; terminal partial sends revoke the
channel using the existing abort path. The previously lost picture
module/three CTests are restored to the canonical build registry.
This offline boundary is neither a real x264 encoder nor an authorized
graphics DVC or a real Microsoft-client display.

### R4 graphics presentation lifecycle and wire delivery receipts

`rdp/gfx_presentation_lifecycle.{h,cpp}` is the R4-side
sequencing contract combining the existing AVC420 CAPSET,
CREATE/MAP/DELETE and `GfxFrameAckWindow` implementations.
R3 alone must authorize/open the actual graphics DVC and own
outbound bytes/fragmentation. The R4 `open()` method is
**not** authentication or channel admission; its trusted
generation must come from R3's real session owner.
The R3 sender reports full-PDU delivery using unique receipts
tied to command, generation and serial. Serialization alone
never activates a client surface. Only completed CAPS_CONFIRM
allows CREATE, completed CREATE allows MAP, and completed MAP
allows frame delivery and acknowledgement. The R4 owner additionally reserves an exact generation/serial/frame-ID
receipt when a complete encoded logical frame enters R3's authorized
outbound writer. Only R3's complete START_FRAME..END_FRAME send callback
adds the frame ID to the existing ACK window. Preflight checks the same
ACK set for duplicates/full capacity; a partially delivered frame
cannot be followed by another frame or surface command and revokes the
channel on abort. Surface deletion cannot race an in-flight frame.
Exact outgoing frame completion triggers the existing ACK window;
no second scheduler
or frame store is introduced. DELETE completion gates surface ID
reuse; disconnect and generation changes revoke old callbacks.
Live graphics, H.264/x264 and real-client acceptance remain
separate unimplemented integration gates.

### R4 graphics frame acknowledgement accounting

`rdp/gfx_frame_acknowledge.h` parses a complete already-authorized
20-byte RDPGFX FRAME_ACKNOWLEDGE command, without allocations, and
exposes one fixed-size (64 frame IDs) ACK window to be **embedded in
the single R4 graphics owner**. Only exact frame IDs are retired,
including out-of-order acknowledgements; unmatched IDs retire none.
The 0xFFFFFFFF suspend signal clears pending IDs and disables waiting;
finite-depth replies resume. Queue depth is buffered client bytes
(0 means unknown). The 64-ID bound is an internal resource policy.
A nonreused generation supplied by R3 on the authorized channel
rejects stale ACKs after resize/reconnect, and generation zero
deactivates the owner on disconnect. R3 remains sole DVC router;
this implementation does not itself send frames or admit sessions.

### R4 portable AVC420 capability-exchange boundary

`rdp/gfx_avc420_capabilities.h` parses one complete, already-reassembled
MS-RDPEGFX CAPS_ADVERTISE PDU and builds one 20-byte CAPS_CONFIRM for
the explicitly advertised 8.1 AVC420 profile only. It checks the common
graphics header, count, every variable-size capability set and exact
PDU length without allocation. Unsupported or malformed offers produce
no confirmation. R3 retains admission, dynamic-virtual-channel framing,
send ownership and channel lifecycle. R4's single graphics owner must
record successful confirmation and prevent surface/frame delivery before
the confirmation is sent; this stateless helper is not a session,
scheduler or negotiated transport by itself.

### R4 portable graphics surface wire boundary

`rdp/gfx_surface_lifecycle.h` builds exact CREATE_SURFACE (15-byte),
MAP_SURFACE_TO_OUTPUT (20-byte) and DELETE_SURFACE (10-byte) PDUs.
The first H.264 path uses XRGB8888, checked nonzero 16-bit surface
dimensions, caller-owned output spans, and failure without partial
writes. The helpers are stateless and allocate no graphics objects:
R3 must first authorize the dynamic graphics channel, while R4's one
graphics owner manages capability negotiation, surface IDs, command
ordering, resize and disconnect/reconnect. A caller synchronizes
access to any shared output buffer. Tested wire encoders do not
constitute a live, authenticated desktop.

### Portable CLIPRDR Format List boundary (R8; offline)

The existing portable `RemoteTransfer` owner remains the sole clipboard
generation and ambiguous Format Data Request coordinator. Long and short
CLIPRDR Format List PDU intake checks bounded names, format IDs and wire
framing, resolving registered `PNG` and `FileGroupDescriptorW` by name
for the current generation without copying strings. Format List responses
carry an exact eight-byte OK or FAIL status after native adapter acceptance.
A declined native offer invalidates advertised IDs and retains the retired
outstanding request only for stale-response draining. R3 must establish
both peers' General Capability flags and authorized CLIPRDR channel
admission before invoking this offline parser or transmitting a response.
The coordinator also receives a complete optional `CB_CLIP_CAPS` once
per authorized channel, tracks at most 16 length-bounded capability sets
and the intersection of the peer's general flags with the caller-supplied
server-advertised flags. Absent General capabilities select the default
zero flags; version is informational, unknown bounded extension sets are
skipped. The new negotiated-format-list intake uses this state rather
than a caller-selected name mode. Disconnect clears capabilities and
offers. The caller owns native offer completion, outbound queueing, and
channel reassembly. No additional clipboard controller, OS API dependency
or live clipboard access is introduced by this increment.

### R8 outbound clipboard Format Data Request write receipts (offline)

The existing single `RemoteTransfer` state owner prepares a
CLIPRDR Format Data Request for an advertised current-generation
numeric format, wraps the 12-byte PDU with a single uncompressed
`CHANNEL_PDU_HEADER` (length 12, FIRST|LAST), and delegates only
the MCS SendDataIndication serialization to R3's confirmed-join
`McsChannelJoinWriteGate`. The format-data request slot is reserved
**only after** successful checked serialization into a caller-owned
buffer. R3 retains all genuine authenticated CLIPRDR channel role,
TLS/NLA/R2 session admission, security headers, and outbound writer
ownership; an offline checked MCS join is not authorization.

A monotonic receipt distinguishes request preparations across actual
disconnect/reconnect. The R3 writer must check current generation and
receipt before submitting the stored buffer, then report cumulative
bytes actually written to the same event-loop owner. Zero submitted
bytes can be cancelled without reserving an ambiguous response.
A partially delivered request cannot be rolled back; abort or
unknown delivery poisons the coordinator until a genuine disconnect.
Only a fully written request can consume a Format Data Response,
which has no wire request ID. If the clipboard generation changes
after full delivery, its late response is drained as obsolete.
This offline API does not enqueue TLS bytes or cache OS clipboard data.

### R8 owned verified Unicode clipboard readiness (offline)

The existing generation-owning `RemoteTransfer` can validate a
successfully consumed CF_UNICODETEXT Format Data Response and copy
only a strict, 1-MiB-bounded UTF-16LE payload into owned UTF-8.
Exactly one terminator is required, invalid surrogate pairs fail,
CRLF normalizes to LF, and UTF-8 expansion stays below 2 MiB.
Content failure is not confused with a malformed CLIPRDR PDU:
it fails readiness without poisoning a sound channel. New offers
and disconnect clear the snapshot; channel poison hides it.
Raw `Response.payload` remains borrowed, unvalidated wire data.
R3 authentication and native OS clipboard publication are not
supplied by this offline readiness boundary.

### R8 owned verified image clipboard readiness (offline)

The same generation-owning `RemoteTransfer` can validate and retain a
successful current-generation registered PNG, CF_DIBV5 or CF_DIB response.
Registered PNG is resolved by the current Format List name before numeric
17/8 fallbacks, because registered format IDs are generation-local. CF_DIBV5
requires a 124-byte BITMAPV5HEADER. PNG chunk/CRC/order checks and packed-DIB
layout checks reuse `clipboard_protocol`; DIB validation is allocation-free
and BMP wrapping consumes that same checked layout rather than copying just
to validate. Stored wire content stays compressed PNG or packed DIB and is
bounded below the 8-MiB CLIPRDR PDU ceiling. Dimensions must additionally fit
a 256-MiB prospective 32-bpp decoded working set before readiness. New offers
and disconnect clear owned image state, channel poison hides it, and obsolete
responses never become current image data. This boundary does not decode an
image, perform native clipboard publication, schedule background work or
authorize a channel.

### R8 nonblocking native paste receipt boundary (offline)

`RemoteTransfer` remains event-loop confined and owns at most one pending
native paste receipt. The adapter supplies `std::chrono::steady_clock`
timestamps and a future deadline; the core never sleeps, waits on a condition
variable, starts a worker or polls an OS clipboard. Receipt sequence numbers
stay monotonic across disconnect so stale native callbacks cannot complete a
later request. Polling returns Pending until current-generation verified text
or image exists, or produces one terminal result: timeout, clipboard
replacement, explicit native owner loss, disconnect or channel error. A
terminal result is consumed once. A valid replacement marks the old receipt
before advancing generation; a malformed replacement poisons the channel and
therefore resolves as channel error instead. Disconnect preserves the terminal
receipt long enough for the adapter to observe it while clearing clipboard
wire/readiness state.

A pending live paste prevents `beginNextPrefetch` from launching another
speculative Format Data Request. It does not cancel a request that may already
have reached the peer: because ordinary Format Data Responses have no request
ID, that reply must still complete or drain before the live paste reuses the
single-flight slot. The native adapter may then use the existing
`beginRequest`/joined-writer lifecycle for the demanded format. This boundary
does not itself choose an R3 channel, send bytes, convert images, publish X11/
Windows/macOS clipboard ownership, implement X11 INCR, or prove a real paste.

### Independence test

The top-level CMake project enables **CXX only**, targets C++23, and links
only the maintained first-party protocol sources, C++ runtime and
OpenSSL. Its build must not discover or compile upstream xrdp or VNC.
The protocol static archive must not open a listening socket or claim
to be a complete server.

### R7 internal macOS frame and geometry boundary (2026-10-15)

`rdp-server-macos-capture` is a macOS-only, noninstalled C++23 static
adapter linked against CoreVideo and CoreGraphics, separate from
`RDPServer::protocol`. CoreVideo's C API requires no Objective-C++ here.
Its move-only `LockedBgraPixelBuffer` retains and read-locks an explicit
borrowed BGRA pixel buffer, validates physical dimensions, padded stride and
bounded size, and exposes pixel-only read rows; destruction/move replacement
unlock and release the native object exactly once. Ownership and locked
span lifetime remain with the capture adapter, not R4's graphics scheduler.

`DesktopDisplayGeometry` holds at most 16 explicitly normalized displays.
It maps logical points to physical pixels, and RDP virtual pixels back
to display-local logical points, rejecting gaps, stale configuration
generations, overlapping rectangles, malformed scaling and overflow.
No CoreGraphics coordinate-space convention is assumed: a future native
display sampler must normalize inputs explicitly. Neither the geometry
snapshot nor the CoreGraphics `CGPreflightScreenCaptureAccess` read-only
status grants R2 OS admission. Preflight is re-evaluated, cannot request
screen permission, and does not guarantee ScreenCaptureKit stream access.
Ordinary native CTests construct synthetic pixel buffers; no test creates a
desktop capture stream, performs native input or prompts for TCC consent.
Live graphics, cursor, input and independent OS session binding are still
unimplemented and must respect the R2/R3/R4/R8 ownership boundaries.

### R7 native CoreGraphics display sampling (2026-10-15)

The macOS-only `native_display_snapshot` translation unit calls read-only
`CGGetActiveDisplayList`, `CGDisplayBounds`, `CGDisplayPixelsWide/High` and
`CGDisplayMirrorsDisplay`. It returns at most 16 bounded, owning
observations (32,768 pixel dimension and 512 MiB equivalent BGRA cap per
display). Native display bounds use Quartz's main-display-relative top-left
global logical points; per-display backing size is in *physical pixels*.
No fabricated global physical origins are emitted: mixed Retina scales
require a separately agreed R4 composition/layout policy. A synchronous
borrowed provider is sampled twice, validates format, uniqueness, logical
intersection, capacity and ordering, and rejects differing observations;
this best-effort consistency check is NOT a display configuration lock.
Regular CTests inject samples and never query an actual user display.
Physical availability, authorized graphical session identity and screen
privacy permissions remain independent R2/R3 and native TCC concerns.

### R7 native snapshot -> portable geometry normalization (2026-10-16)

`native_display_geometry` takes the existing owned `NativeDisplaySnapshot`
and produces the existing `DesktopDisplayGeometry`. It establishes ONE
RDP-compositor-relative pixel origin at the minimum global Quartz logical
point; it never claims these pixel coordinates represent Apple's native
physical framebuffer origins. Native backing widths/heights and a shared
uniform isotropic scale determine integer-aligned virtual placements.
Mixed scale, rotated, mirrored and non-aligned layouts are rejected until
R4 supplies an explicit compositor mapping. The snapshot now carries
`CGDisplayRotation` metadata, and generation changes must be passed by
R2/R3 session owners before new input/capture. No callbacks, permission
prompts, capture session, login or input injection are added.

### R7 fail-closed display refresh epochs (2026-10-16)

The allocation-free `NativeDisplayGeometryRefresh` retains only an owned
`DesktopDisplayGeometry` and monotonically advancing topology generation.
It belongs to R7's native geometry adapter, **not** to R3's authoritative
session or R4's graphics scheduler. A synchronous native or injected refresh
first invalidates the previously published geometry, then performs the
existing bounded double display observation and checked translation. A
failed observation, unsupported placement, explicit display-change signal,
or generation mismatch refuses all pointer/size queries; callers must
serialize notifications and translations. Generation exhaustion never wraps
to zero or permits reuse. A provider/context is borrowed only during the
refresh call, never retained. Default CTests use a deterministic provider;
`refreshNative()` is Apple-only and read-only, with NO implicit capture,
privacy prompt, input permission or authenticated OS admission. Native
CoreGraphics callback registration and actual StreamCaptureKit integration
remain future authorized R7 work.

### R7 Quartz reconfiguration revision fence (2026-10-16)

`NativeDisplayReconfigurationWatch` is an optional, noncopyable native
CoreGraphics callback registration for a future per-user authorized process.
It registers via `CGDisplayRegisterReconfigurationCallback` and unregisters
via the matching CoreGraphics API; ordinary CTests do neither. Callback
`userInfo` is always null and touches **only process-lifetime atomics**,
so an already executing callback during removal never dereferences a
retired session/geometry object. Only one Quartz registration is permitted
per process; registration failure releases its reservation, while removal
failure retains it to avoid duplicate observers. Both start and stop retire
previous revision tokens. The signal saturates to an invalid zero on
uint64 exhaustion rather than reuse generations.

The existing `NativeDisplayGeometryRefresh` now records a topology signal
revision around each synchronous two-read sample and geometry conversion.
A notification during sampling rejects publication; later begin/complete
notifications cause `usable`, pointer conversion, and virtual-canvas
queries to fail until a fresh refresh. The CoreGraphics callback NEVER
calls into the mutable geometry owner; the future R2/R3 session owner must
serialize start/stop/refresh and check generation immediately before
native input/capture, including any later R4 scheduling. This is NOT an
authorization capability, a ScreenCaptureKit stream, or a replacement for
R3's sole session lifecycle. Consent prompts, input and frame capture
remain disabled.

### Implementation principles

- Portable wire parsers reject malformed lengths/flags and ambiguous states.
- No trusted-client assumptions for inputs from RDP channels.
- Generation-aware clipboard request/response serialization; no unsolicited
  image forwarding, no fake file objects.
- OS adapters handle session selection and desktop capture without contaminating
  RDP protocol state.
- Strict tests, sanitizers and real-client gates before release.

### Current connection intake boundary

The portable `PreauthConnectionStream` extends the existing
`PreauthSession` and X.224 parser with bounded TCP byte-stream intake.
It consumes **only** the initial plaintext Connection Request, returns
the exact consumed bytes, and produces the existing TLS-negotiation
Confirm or failure decision. A transport adapter must send the entire
response before starting TLS and leave already-received TLS bytes
unconsumed. This is **not** an active TCP listener, a TLS provider,
an authenticated RDP session or a connection to a desktop.

The stream owner additionally enforces send-before-TLS ordering:
an adapter must report a **single successful full X.224 response
write** before the diagnostic TLS transition is permitted. Failed,
premature or duplicate completion closes it. This guards the future
transport adapter contract but does not implement that adapter.

### Incremental decrypted Basic Settings Exchange intake

The **same** `PreauthConnectionStream` now reuses one fixed-size
8,192-byte buffer for the initial CR (at most 260 bytes) and for
decrypted MCS Connect Initial after the diagnostic TLS transition.
The TPKT length is checked before accumulating the body and the
X.224 Data TPDU is checked before buffering BER. The parser receives
exactly one complete bounded frame; extra decrypted bytes remain
unconsumed. After validating or rejecting its GCC content, the
diagnostic closes. The API neither negotiates genuine TLS/NLA nor
emits an MCS response or authorizes an OS session.

### Build/install/release boundary

The protocol static library has an installable CMake target
`RDPServer::protocol`, an OpenSSL-aware package config, and
cross-platform CPack ZIP archives. GitHub Actions builds both
configurations and checks a separate downstream consumer before
uploading CI artifacts. An authorized matching version tag can
publish a GitHub **protocol SDK prerelease**. This is an artifact
delivery mechanism only: it does not introduce an RDP listener,
service installation, authentication or desktop deployment.

### R10 opened Windows HANDLE DACL protection (2026-10-15)

The offline runtime queries `GetSecurityInfo(SE_FILE_OBJECT)` with
the already-opened HANDLE and rejects null/unreadable ACLs and broad
write/delete/permission-change grants to common untrusted built-in
principals; only ordinary allow ACEs are evaluated. The query
requires `Advapi32`, linked on the runtime executable only.
Native handle ownership, path classification and POSIX descriptor
policies are otherwise unchanged. This conservative common-principal
screen is *not* comprehensive Windows effective-access enforcement:
arbitrary domain groups, intermediate directory reparse points and
TLS key permissions still require explicit native auditing. No
network/desktop access or R2/R3 session is created.

### R10 Windows-safe PEM parsing buffer boundary (2026-10-15)

Credential metadata and file identity are established on one native
open object. For cryptographic parsing, the runtime reads exactly
the bounded size from that same `FILE*` using its own C runtime,
then parses an OpenSSL memory BIO. It does not pass the application's
`FILE*` across the OpenSSL library/CRT boundary on Windows and
does not reopen the path. Short reads or content growth past the
validated size fail closed. Memory allocation is bounded by the
existing 1 MiB certificate and 256 KiB key limits and uses
nothrow ownership. The trust/expiry/admission limitations below
remain unchanged.

### R10 offline TLS PEM parse/key-match preflight (2026-10-15)

A third explicit diagnostic, `--check-tls-credentials`, first applies
the established syntax and native credential-file metadata/identity
policy. It retains the opened certificate and private-key file
objects, then parses PEM directly from those same handles with
OpenSSL. The private key must be unencrypted and match the
certificate public key through `X509_check_private_key`. The
certificate's `notBefore` and `notAfter` fields must also contain
the current system time; malformed time encodings, expired
certificates and not-yet-valid certificates fail closed. OpenSSL 4+
uses its certificate-level temporal checker, while OpenSSL 3.x retains
the equivalent strict individual-time comparison. The password
callback is noninteractive and always rejects encrypted keys. This
eliminates a path reopen between metadata validation and content
parsing. It does not validate a trust chain, hostname, revocation,
NLA, R2 admission, R3 authority or permit server startup.

### R10 offline TLS file metadata preflight (2026-10-15)

A separate `--check-tls-files FILE` command retains the existing
syntax-only `--check-config` contract. It borrows validated certificate
and key path views while the bounded configuration input buffer lives,
opens each actual path without following its final symlink, checks
native file identity, regular/disk type, finite size, and permissions,
and rejects hard-linked aliases. POSIX requires a private same-eUID
key and no world/group-writable certificate. Windows permits key
read grants only to the file owner, SYSTEM and Administrators based
on the opened HANDLE DACL; the general config-file DACL gate remains
separate. This is FILE METADATA only: no PEM parsing, private key
loading, certificate matching, NLA, listener or desktop activation.
Intermediate directory reparse/ACL analysis remains open.

### R10 POSIX TLS credential ancestor-path descriptor walk (2026-10-15)

R10's offline `--check-tls-files` metadata preflight now refuses
certificate and key paths that traverse intermediate POSIX symbolic
links. It opens each component relative to the previous opened
directory descriptor using `openat` and `O_NOFOLLOW`; no separate
path `stat` is used for the decision. The already-established
`fstat`, effective UID, file mode, size, alias-identity and
resource-lifetime checks are preserved. The handle is closed after
offline verification; TLS material is **not parsed or retained**.
This does not grant future live-session permission or protect a
separate subsequent file reopen. Windows is unchanged and needs
separate parent-junction review.

### R10 Windows native configuration-file descriptor guard (2026-10-15)

The non-installable runtime uses Win32 `CreateFileA`,
`FILE_FLAG_OPEN_REPARSE_POINT`, `GetFileType` and
`GetFileInformationByHandleEx(FileAttributeTagInfo)` to reject
non-disk, directory and final-component reparse handles. Drive
absolute paths are required. Ownership moves from HANDLE to CRT
descriptor and then RAII FILE without overlapping owners. This
does not verify Windows DACL, intermediate directory junctions,
private key permissions, NLA or native OS admission. The service
remains disabled.

### R10 POSIX configuration-descriptor guard (2026-10-15)

The non-installable `rdp-server --check-config` syntax checker now
opens POSIX configuration files through `open(O_NOFOLLOW | O_NONBLOCK |
O_CLOEXEC)`; the same opened handle must pass `fstat` as a regular
file without group/world write permissions. `fdopen` transfers
descriptor ownership to RAII-managed `FILE`; its failed conversion
closes the descriptor. This prevents blocking on synthetic FIFOs and
disallows final-component symlink substitution without a separate
pathname-stat race. Parent-directory links and platform file ACLs are
not yet independently accepted. Windows retains its existing
syntax-only file handling until native handle/reparse/ACL checks are
implemented. No credentials/certificates, listener, OS session,
clipboard or desktop are read/activated.

### R10 native process and offline configuration boundary

The **non-installable** `rdp-server` C++23 executable links the existing
first-party protocol library. It constructs no TCP listener, TLS context,
session controller, worker thread, desktop adapter or service. `--help`
and `--version` succeed as informational commands. Default startup,
unknown flags and chained options always fail closed (exit 2), without
echoing potentially sensitive arguments.

An explicit `--check-config FILE` mode reads at most 4,097 bytes into
one stack buffer, refusing files larger than 4,096 bytes. It validates
seven unique required key/value settings using bounded `string_view`
lookups, numeric limits, loopback address restriction, absolute distinct
certificate/private-key path syntax and explicit required authentication
and OS authorization flags. Control bytes, missing/duplicate/unknown keys,
unbounded integers, public listeners and relative/traversal paths fail.
The local file handle has RAII ownership, and parser views never escape
the buffer lifetime. The CLI reports generic failures without printing
contents or filenames. A *syntactically valid* configuration prints an
explicit disclaimer that credentials, private key, OS authorization,
provider availability and file permissions have **not** been checked;
no service is started. Invalid configuration exits 3. No persistent
configuration state or second session owner is introduced. The SDK
install/export/CPack rules are unchanged.

The real runtime must later couple verified R2 admission and R3 session
authority to the R1 transport before any listener can be enabled.
### Real TLS handshake evidence boundary

Before the one-owner preauth stream progresses from X.224 to decrypted
MCS, it now requires a **completed OpenSSL server SSL session**
(TLS 1.2+, negotiated cipher and selected server certificate), not
merely a Boolean callback. Test transport uses an in-memory BIO
pair and a temporary self-signed test certificate. A future
socket adapter must retain the live SSL object and handle all
encrypted I/O, send acknowledgments, shutdown and cancellation.
No network listener, CredSSP/OS identity, real desktop or
MCS Connect-Response is created by this offline increment.

### Bounded TLS application-data intake (2026-10-14)

After the complete X.224 Confirm write and a verified live server TLS
handshake, the existing preauth owner retains only the **identity of a
borrowed SSL** handle, cleared on terminal close. The new
`consumeMcsConnectInitialFromTls` reads at most 8,192 bytes through
OpenSSL `SSL_read_ex`, requesting only the remainder of the
4-byte TPKT header, 3-byte X.224 Data TPDU, or declared MCS frame
at a time. OpenSSL retains coalesced plaintext for a later consumer;
the diagnostic does not accept that extra packet. WANT_READ/WRITE are
retryable; close_notify, provider errors, wrong SSL identity and
invalid framing terminate. No extra session state authority,
network listener, MCS response or OS admission exists.

### Byte-accurate X.224 Confirm/Failure output (2026-10-14)

The existing preauthentication stream now owns precisely one 19-byte
X.224 negotiation response and exposes only the unsent suffix.
A nonblocking transport must report the **actual** positive number
of bytes accepted from that suffix; zero means retry on writable
readiness. A short write cannot advance the TLS handshake. On
`RDP_NEG_FAILURE` the same stream permits the entire failure
response to drain, then closes; on `RDP_NEG_RSP` it permits TLS
only after every byte has been acknowledged. Hard socket failures
abort the stream. This is a portable I/O boundary, not an
active network listener, TLS credential verifier or OS admission.

### Nonblocking native X.224 socket boundary (2026-10-14)

`PreauthTcpAdapter` contains one preauthentication owner and a
borrowed `TcpNonblockingIo` adapter. The platform-native
`NativeTcpIo` delegates to recv/send (Winsock or POSIX) without
binding, listening, owning a socket or activating any service.
The caller must create an already-connected nonblocking socket,
drive readable/writable readiness on a single event loop,
and configure SIGPIPE handling where required. The adapter reads
exactly the missing TPKT header/body bytes, leaving any early TLS
ClientHello record in the native TCP buffer. It drains the existing
19-byte RDP_NEG_RSP/RDP_NEG_FAILURE on writability, then signals
ready-for-TLS or terminal close. It cannot establish a TLS session,
authenticate an OS identity or construct an MCS domain.

### One-owner nonblocking OpenSSL handshake progression (2026-10-14)

Once X.224 Confirm has been fully sent, the existing
`PreauthConnectionStream` can drive one server-side
`SSL_do_handshake` per event-loop readiness callback.
WANT_READ and WANT_WRITE return independently; the stream
binds the borrowed SSL identity on the first attempt and
refuses swapping it during a partially complete handshake.
A successful provider handshake passes the existing TLS 1.2+,
certificate, cipher and server-role gate; the SAME SSL then
decrypts the initial bounded MCS/GCC PDU. Fatal TLS errors and
cancellation close the sole preauth owner. `PreauthTcpAdapter`
forwards this readiness call without a second state machine.
The socket/BIO still belongs to the caller; no socket listener,
certificate enrollment, CredSSP, MCS response or OS admission
is added in this increment.

### Borrowed nonblocking native socket BIO and TLS loopback (2026-10-14)

The native `PreauthTcpAdapter` and the same protocol owner now
cross the previously synthetic TLS/network boundary. An OpenSSL
custom `BIO_METHOD` delegates encrypted record read/write to the
existing `TcpNonblockingIo` rather than using platform-specific
`SSL_set_fd` integer casts. It reports SSL WANT_READ/WANT_WRITE on
would-block, and ordinary EOF/error on closed/failed I/O; `SSL`
owns/free the BIO, while the external caller owns the already
connected nonblocking socket and its IO object. The BIO neither
copies/owns the socket nor creates a second RDP state controller.
Attaching on the server adapter requires completion of X.224
Confirm output. The same SSL then drives server handshake and the
existing bounded MCS/GCC diagnostic. A test-only listener binds
to 127.0.0.1 port 0, accepts one peer and closes the listener
before TLS; no installed daemon or persistent listening service.
Credential verification, OS identity and MCS server response remain
unimplemented.

### T.125 Connect-Initial domain parameter negotiation (2026-10-14)

The existing MCS/GCC parser and **same** preauthentication diagnostic
now apply the eight-field `MergeDomainParameters` rules from
[MS-RDPBCGR 3.3.5.3.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7617f746-95c9-4a6e-808d-e2f642471e86)
after a complete decrypted Connect-Initial and before treating
the envelope as validated. Channel/user counts, token IDs,
priorities, throughput, height, max PDU size and protocol version
are merged from client target/min/max sets; the result is a
**value only** and neither allocates channels nor creates
an MCS domain. BER decoding accepts syntactically valid minimum
and maximum protocol-version integers, while negotiation still
requires effective version 2. On merge failure the existing
preauth owner closes as before. No Connect-Response, CredSSP
account identity, OS authorization or desktop is produced.

### Offline MCS Connect-Response/GCC serializer (2026-10-14)

After a checked MCS Connect-Initial, the portable first-party
`encodeMcsConnectResponse` independently revalidates the client's
GCC settings and T.125 merged DomainParameters, then builds
a complete bounded wire PDU: RFC 1006 TPKT, Class 0 X.224 Data,
BER APPLICATION 102 Connect-Response with success result and
calledConnectId 0, followed by a T.124 GCC ConferenceCreateResponse
with the H.221 server key `McDn`. The response holds the server
Core block (RDP 5 compatible version, offered SSL), Network block
(I/O channel 1003 and explicitly supplied, nonduplicated channel IDs
with the correct odd-channel pad) and Enhanced Security block
(encryption method and level zero, no legacy RC4 key or certificate).
All BER/PER lengths are derived from the actual payload, and
failure produces an empty packet. The published Microsoft example
[MS-RDPBCGR 4.1.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d23f7725-876c-48d4-9e41-8288896a19d3)
provides the independent wire oracle for the common layout.

**Crucial authority boundary:** this is an OFFLINE encoder, not a
preauthentication state transition and not permission to send
rt-successful on a live connection. The existing owner still
closes after diagnostic MCS intake. No TLS record emission,
CredSSP, OS session or MCS domain/channel lifecycle was enabled.

### Pure PER MCS Channel Connection request decoding (2026-10-14)

The first-party `mcs_channel_connection.{h,cpp}` adds a pure,
non-allocating request decoder for MS-RDPBCGR 2.2.1.5 (Erect Domain),
2.2.1.6 (Attach User) and 2.2.1.8 (Channel Join). It reuses the
existing exact TPKT/X.224 Data TPDU validator and decodes the T.125
aligned BASIC-PER discriminator and fields into a *value only*.
Erect accepts canonical 1..4 octet nonnegative subHeight and
subInterval. Attach has no payload beyond its one-byte type.
Join extracts the PER UserId offset (wire value plus 1001) and
channelId without treating that as evidence of allocation.

This does not change `PreauthConnectionStream`'s existing terminal
diagnostic behavior after Connect-Initial. It does not accept a
user identity, mutate an MCS domain, join a channel, decrypt
additional PDUs, send replies or create a server listener.
Those transitions require a separately verified authentication
and OS session authority, which remains unimplemented.

### Offline T.125 server Attach User/Channel Join confirmations (2026-10-14)

The existing first-party `mcs_channel_connection` portable module
now encodes the T.125 aligned-PER **server** responses specified
in [MS-RDPBCGR 2.2.1.7](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3b3d850b-99b1-4a9a-852b-1eb2da5024e5)
and [4.1.8.2.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7443e65e-3482-4cec-823a-741eb1fe27b4).
For an externally provided assigned user, the 11-byte Attach
User Confirm carries its PER UserId offset. The 15-byte Channel
Join Confirm is conditional on a decoded Join Request with the
same assigned user and requested channel that occurs once in
a bounded external allocation list; it repeats the confirmed
channelId. Both return fixed-size values only, with no retained
pointers, domain mutations or SSL writes. These are *offline*
wire primitives, NOT a server acceptance gate. The existing
preauthentication stream still closes after the Connect-Initial
diagnostic; an actual OS authentication/authorization provider
and one authoritative MCS owner remain essential before any
success packet may be transmitted.

### Offline T.125 MCS Disconnect Provider Ultimatum (2026-10-14)

The existing `mcs_channel_connection` module now provides an
allocation-free, fixed-nine-byte TPKT/X.224/T.125 PER
Disconnect Provider Ultimatum encoder matching
[MS-RDPBCGR 4.2.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/19a238a5-0455-46f0-a96b-31320d9a70a1).
Per [3.1.5.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3efcb3f7-8fa5-488b-8388-bf4d32004b8c),
only provider-initiated (1) and user-requested (3) can be
serialized by the server. The existing bounded parser recognizes
a complete Disconnect Provider Ultimatum and rejects invalid
TPKT/X.224 and PER padding, but ignores even reserved inbound
reasons as mandated by
[3.1.5.1.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f10e972d-7b77-4fa5-999f-08406fe86284).

These pure helpers do not grant session/OS admission, encrypt,
send data, close a transport, or duplicate lifecycle ownership.
A future authenticated connection owner must send the entire PDU
via its negotiated TLS/security transport and then close.
Offline tests cannot establish live client disconnect semantics.

### Offline T.125 client MCS Send Data Request (2026-10-14)

The existing `mcs_channel_connection` module now parses T.125
SendDataRequest (DomainMCSPDU choice 25) after exact TPKT/X.224
envelope validation. As specified in MS-RDPBCGR 4.1.16,
the request contains an initiator UserId offset from 1001,
a 16-bit channel ID, two-bit priority and segmentation values,
zero padding, and an aligned-PER OCTET STRING userData field.

The decoder accepts 7-bit and 14-bit PER length encodings, including
two-octet lengths for small payloads as emitted by real RDP stacks.
Fragmented PER length determinants are rejected; userData is
limited to 16383 bytes in a single complete TPKT. Returned userData
is a borrowed read-only span into the caller-owned input: the caller
must retain its backing bytes until synchronous use completes.
No copies, heap allocations or competing connection controllers.

The result is a syntax-only building block. It does NOT establish
TLS provenance, authentication, joined channel membership, complete
segmented application data, virtual channel routing or remote desktop
admission. Existing preauthentication diagnostics still close before
any live post-channel MCS traffic. A future authorized single session
owner must independently validate the assigned user and joined channel
before consuming the borrowed payload.

### Offline server MCS Send Data Indication encoder (2026-10-15)

The current first-party `mcs_channel_connection` module now writes
T.125 server-to-client `SendDataIndication` (DomainMCSPDU choice 26,
0x68), per
[MS-RDPBCGR 1.3.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/023f1e69-cfe8-4ee6-9ee0-7e759fb4e4ee)
and
[2.2.6.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/6c074267-1b32-4ceb-9496-2eb941a23e6b).
A caller-owned `std::span<std::uint8_t>` receives one exact
TPKT/X.224/aligned-PER server frame. The fixed fields are
initiator UserId offset by 1001, channelId, dataPriority,
segmentation, 7-bit or 14-bit PER userData length and
caller-provided opaque bytes (up to 16383). All bounds,
UserId range, nonzero channel, priority and segmentation
are checked before ANY output mutation. Short length is
chosen for 0..127 bytes, long length for 128..16383.
The packet is written with one overlap-safe payload move
followed by header stores, without internal heap allocation;
unwritten output suffix is unchanged.

This is an OFFLINE serializer, not an authorized server
data path: the future single authenticated domain owner must
prove the assigned user and joined channel, supply a valid
inner RDP/licensing/virtual-channel PDU and complete TLS
encryption/transmission. The encoder itself performs no SSL
I/O, session admission, OS operation, reassembly or graphics.

### Offline server Demand Active Share Control serializer (2026-10-15)

The original first-party `mcs_channel_connection` owner now
also emits one full Demand Active *Share Control* PDU into a
caller-owned contiguous span, per
[MS-RDPBCGR 2.2.1.13.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/bd612af5-cb54-43a2-9646-438bc3ecf5db)
and the send procedure
[3.3.5.3.13.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/4aed639a-9ac3-411d-add9-c5253308aa85).
It writes the exact LE16 totalLength, version/type 0x0011,
normative server MCS pduSource 1002, caller shareID,
source-descriptor length, combined capability length
(count + pad + envelope bytes), the opaque descriptor,
count and zero pad, validated capability envelopes, and
terminal LE32 sessionId. It shares the single
`validCapabilitySetEnvelopes` validator with the existing
Demand/Confirm decoder, preventing divergent inbound and
outbound length/count interpretation.

The entire destination capacity, LE16 field limits,
reserved legacy FlowPDU size 0x8000, and every
capability-set header/length/count are checked BEFORE
writing anything; failure leaves destination unchanged.
Both input spans must be disjoint from the written output
region; overlap is explicitly rejected to avoid corruption
between two source copies. Success performs a direct
contiguous copy of each source span, no heap allocation,
and preserves the unused output suffix. Unknown capability
types remain opaque: a syntactically valid emission is NOT
a valid negotiated server capability set.

This is an OFFLINE Share Control serializer, not a complete
MCS SendDataIndication/TLS record. The future single owner
must independently verify a genuine CredSSP/TLS-bound
Kerberos principal, OS session permission, licensing,
channel membership, capability set contents and
activation order BEFORE writing it to an authenticated
client. No live send, user input, graphics, OS session
or share activation is enabled.

### Offline Demand/Confirm Active transcript correlation (2026-10-15)

The existing `mcs_channel_connection` module now performs
*stateless*, allocation-free correlation of one isolated server
Demand Active and one client Confirm Active Share Control PDU.
Per [MS-RDPBCGR 2.2.1.13.2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/4e9722c3-ad83-43f5-af5a-529f73d88b48),
Confirm Active carries the server originatorID 0x03EA,
while [2.2.1.13.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/bd612af5-cb54-43a2-9646-438bc3ecf5db)
defines the server Demand layout and shareID. The new
`correlateRdpActiveExchange` first uses the existing exact-
length, counted-capability parsers, then requires Demand
pduSource=1002, Confirm pduSource equal to the separately
supplied expected client MCS user-channel ID (1001..65535),
the mandatory Confirm originatorID=1002, and identical
32-bit shareID on both messages. A client user ID of 65536
cannot fit the Share Control 16-bit pduSource and is
rejected rather than truncated.

The sole positive result is intentionally named
`ConsistentSyntaxOnly`, NOT an admission or activated
share. Capabilities remain opaque; even disjoint capability
sets or an untrusted descriptor can produce matching
syntax. It does not establish actual MCS joins, client
sender provenance, TLS/GSS authentication, independent OS
account/session authorization, required negotiated
capability contents, licensing, packet order, or permission
to send an activation/finalization packet. No connection
state, TLS writer, OS adapter or new lifecycle owner
is created. Only a later genuine authenticated single
session owner may use these correlated fields as inputs
to independently authorized activation decisions.

### Offline Demand/Confirm Active capability-envelope validation (2026-10-15)

The original C++23 `mcs_channel_connection` parser now also
recognizes the two capability-exchange Share Control PDUs:
[MS-RDPBCGR 2.2.1.13.1.1 Demand Active](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/bd612af5-cb54-43a2-9646-438bc3ecf5db)
and
[2.2.1.13.2.1 Confirm Active](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/4e9722c3-ad83-43f5-af5a-529f73d88b48).
It first reuses the one exact-size/version Share Control parser,
then validates shareID, source descriptor length, combined
capability-set length (including numberCapabilities and pad),
and one bounded, fully consumed sequence of
[TS_CAPS_SET envelopes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d705c3b6-a392-4b32-9610-391f6af62323).
Each LE16 `lengthCapability` MUST be >=4 and fit completely
within the combined region. The number of sets MUST equal
`numberCapabilities`, without a dangling fragment or trailing
octet. Demand Active additionally requires exactly one LE32
sessionId after capabilities; Confirm Active instead requires
LE16 originatorID=1002 (MCS server channel) before the source
descriptor and has no sessionId. Pad2Octets is intentionally
ignored. An unknown capability type remains opaque; the
Microsoft Server Demand Active example has a nonconforming
four-byte FONT set, which is accepted as *envelope syntax*
without claiming functional font support.

The API returns borrowed read-only `sourceDescriptor` and
`capabilitySets` spans plus IDs/count; no heap, copy, session
state transition, TLS I/O, admission or application negotiation.
It does NOT validate nested capability semantics, H.264/AVC420,
licensing, channel membership, OS identity, packet direction,
sender trust, or MCS segmentation. The future single authenticated
session owner must separately verify TLS-bound CredSSP,
independent OS session policy, prior Demand Active shareID,
required capability types/contents, and transcript ordering
BEFORE any share activation or input acceptance.

### Offline server Synchronize / Control finalization writers (2026-10-15)

The same `mcs_channel_connection` translation unit now writes
one complete plaintext Share Control + Share Data packet directly
into a caller-owned span, with no intermediate buffers, MCS
SendDataIndication, TLS or desktop activation. Following
[MS-RDPBCGR 2.2.1.14.1](https://learn.microsoft.com/fr-ch/openspecs/windows_protocols/ms-rdpbcgr/3fb4c95e-ad2d-43d1-a46f-5bd49418da49),
`encodeRdpServerSynchronizePdu` emits 22 bytes: pduSource
1002, version/type 0x0017, caller shareID, uncompressed stream
0, type2 0x1f, SYNCMSGTYPE_SYNC=1 and caller-provided LE16
targetUser. This is intentional: Microsoft's Server Synchronize
packet example has a historically uninitialized targetUser,
so the offline encoder treats it as raw syntax, NOT channel
admission.

Per [MS-RDPBCGR 2.2.1.15.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/0448f397-aa11-455d-81b1-f1265085239d),
`encodeRdpServerControlPdu` emits a fixed 26-byte uncompressed
Share Data packet with stream=2, type2=0x14, and exactly
two server-side action forms: Cooperate action=4 requires
assignedClientUserId=0 and emits grantId/controlId 0/0;
Granted Control action=2 requires a client user-channel ID
1001..65535, emits grantId=that ID and controlId=1002.
Client-only Request Control and Detach, unknown actions,
invalid user-channel IDs and insufficient caller capacity
are rejected BEFORE any output mutation. Both packets
write ignored padding as zero, provide exact packet lengths,
and preserve the untouched output suffix.

All fixed Share Control/Data metadata is written by one
private helper to avoid different framing between the two
server-side writers; the existing independent decoders
round-trip the results. **Neither a successful serializer
nor an encoded Granted Control action grants any rights.**
Only a future authenticated CredSSP/Kerberos TLS owner with
independent OS session policy, joined MCS channels, a
licensed/activated share, exact message direction and
ordering may actually send such finalization records.
No live socket, TLS writer, graphics, input or console
access is introduced.

### Offline RDP connection-finalization Control and Synchronize PDUs (2026-10-15)

The original `mcs_channel_connection` module now reuses its checked
Share Control and Share Data decoders to parse two *finalization*
payloads. Per
[MS-RDPBCGR 2.2.1.14.1](https://learn.microsoft.com/fr-ch/openspecs/windows_protocols/ms-rdpbcgr/3fb4c95e-ad2d-43d1-a46f-5bd49418da49),
`TS_SYNCHRONIZE_PDU` is exactly 22 bytes including
the 18-byte enclosing headers, type2 `0x1f`, little-endian
`messageType=SYNCMSGTYPE_SYNC (1)` and an uninterpreted
`targetUser` channel ID. Windows Server's documented
`STREAM_UNDEFINED=0` exception remains supported by the
underlying Share Data decoder. Per
[MS-RDPBCGR 2.2.1.15.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/0448f397-aa11-455d-81b1-f1265085239d),
`TS_CONTROL_PDU` has exactly 26 bytes including headers,
type2 `0x14`, little-endian `action` 1..4 (Request,
Granted, Detach, Cooperate), `grantId` LE16 and
`controlId` LE32. Source/share IDs are carried from
the checked enclosing frame. Wrong kind, total length,
nested length, unknown action, invalid messageType,
and unsupported compressed payload fail without
exposing or applying any action. Pure C++23, no copies,
allocations, state machine or extra decoder owner.

Microsoft's decrypted Client Synchronize, Client
Cooperate, Client Request and Server Granted Control
fixtures are independently checked in the existing
MCS behavior registry. The **real** finalization protocol
imposes DIRECTIONAL rules that pure syntax cannot
prove: Client Request/Cooperate have zero grant/control
IDs, while Server Granted uses a previously assigned
user-channel ID and server channel ID. The parser
intentionally preserves raw IDs and actions, including
a potentially forged client-side Granted enum, WITHOUT
calling any state transition. Only one future *genuinely
CredSSP/Kerberos TLS-bound and independently OS-authorized*
session owner may validate direction, assigned channel,
share ownership, ordering, licensing and capability
negotiation before advancing or granting control.
This still does not enable live TLS, input or desktop.

### Offline uncompressed Share Data Header decoding (2026-10-15)

The original first-party `mcs_channel_connection` module now exposes
`parseRdpShareDataHeader`, layered on its *existing*, exact-length
`parseRdpShareControlHeader`. Under
[MS-RDPBCGR 2.2.8.1.1.1.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/4b5d4c0d-a657-41e9-9c69-d58632f46d31),
a Data PDU contains a further 12-byte Share Data Header: LE32
shareID; ignored pad1; streamID; LE16 uncompressedLength;
pduType2; compressedType; and LE16 compressedLength.
Only the 24 documented pduType2 values are recognized.
STREAM_UNDEFINED (0) is permitted ONLY for Synchronize
because the Microsoft specification identifies a known
server compatibility exception; streams 1/2/4 are standard.

Some real Client Font List packets carry uninitialized
`uncompressedLength`. Keep it as reported metadata, NEVER
allocate from it or equate it to the already-validated Share
Control `totalLength`. Ignore pad1 even if nonzero. Keep
`compressedLength` as reported metadata when uncompressed.
Every nonzero `compressedType` is explicitly UNSUPPORTED:
no compressed payload is exposed to downstream application
processing until an authenticated owner has a correctly
negotiated and bounded bulk decompressor/history.
The returned body is an allocation-free, read-only borrowed
`std::span` into caller-owned complete input, beginning
after the full 18-byte Share Control + Share Data header.

This is OFFLINE syntax, not an MCS/OS admission decision,
security-header detector, capability negotiation, nested
Share Control/INPUT/COLOR decoder, licensed session,
graphics pipeline or live RDP server. Microsoft Control,
Font List and Font Map examples provide independent wire
oracles; real-client acceptance remains separately gated.

### Offline RDP Share Control Header decoding (2026-10-15)

The existing portable `mcs_channel_connection` translation unit now
decodes an explicitly isolated six-byte T.128 `TS_SHARECONTROLHEADER`
per [MS-RDPBCGR 2.2.8.1.1.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/73d01865-2eae-407f-9b2c-87e31daac471).
Its little-endian `totalLength` must match the entire supplied Share
Control PDU, its 12-bit protocol version must be `TS_PROTOCOL_VERSION`
(1), and the low four bits must designate Demand Active (1),
Confirm Active (3), Deactivate All (6), Data (7), or Server
Redirection (10). The server must ignore `totalLength=0x8000`
(T.128 FlowPDU); it is returned as a distinct ignored status
without a body or ordinary PDU success.

The decoded source ID is syntax only, not verified channel ownership.
The remaining PDU bytes form a read-only `std::span` borrowed
from the unchanged caller-owned complete Share PDU. No allocation,
data copy, nested PDU processing, decompression, or TLS/socket I/O.
The existing MCS parser can supply a borrowed `userData` span,
but **not every MCS userData payload is a Share Control PDU**.
The sole future authenticated owner must first validate MCS channel
membership, actual security-header presence/meaning, licensing
or client-info phases, segmentation/reassembly, and the Share
Control message boundary before using this parser. In particular,
this change does not admit share activation, client keyboard/input,
graphics, OS accounts or remote desktop sessions. The published
26-byte Microsoft Server Control example provides an independent
header oracle; tests do not claim end-to-end server interoperability.

### Bounded decrypted CredSSP TSRequest framing (2026-10-14)

The existing first-party CredSSP DER parser gains
`TsRequestFrameReader`, a fixed-capacity framing helper,
**not** an RDP session, GSS mechanism, login controller or
TLS event loop. Following the MS-CSSP 2.2.1 TSRequest DER
SEQUENCE length, it takes at most one complete decrypted
TSRequest per call and counts exactly how many bytes of the
supplied plaintext were consumed. It handles callbacks split
at any header or payload boundary without swallowing the
next coalesced frame. It validates canonical short/long DER
lengths before accepting the body, enforces the existing
16 KiB ceiling and invokes `parseCredSspTsRequest` at
completion. The borrowed full-frame view exists only until
explicit `releaseFrame`, terminal rejection, close or
destruction, which zeroes the stored ciphertext.

This component does not change the diagnostic's
`PROTOCOL_SSL` security selection; no CredSSP packets are
accepted over a live connection and no session is admitted.
Future GSS authentication must consume this DER synchronously,
verify binding and independently validate OS account/console
authorization before an MCS state transition can occur.

### Offline CredSSP server TSRequest DER serializer (2026-10-14)

The existing portable CredSSP parser/framer also exports a bounded,
single-reply DER serializer for MS-CSSP 2.2.1 `negoTokens` and
already-encrypted `pubKeyAuth` (versions 5/6 only). It writes one
minimal definite-length SEQUENCE and validates size before any
one-shot vector allocation; empty or over-limit provider output
fails without bytes. The payload is opaque and remains the provider's
responsibility; this library cannot determine Kerberos success,
encrypt its own public-key hash, authorize OS identity, send a
TLS record or transition to MCS. Test vectors are synthetic and
no authentication grant exists.

### Linux GSSAPI provider compilation and framed-token handoff (2026-10-14)

The optional `rdp-server-linux-gssapi` build target links the
first-party GSS SPNEGO acceptor, protected-binding and
deny-only credentials source to the platform GSSAPI library.
It is NOT part of the installed portable protocol SDK or
a service; it is compiled only with the explicit Linux
validation flag. The existing per-connection GSS acceptor
synchronously consumes a completed `TsRequestFrameReader`
frame through `acceptFramedNegoRequest`. The provider
receives borrowed tokens only before `releaseFrame` wipes
the fixed DER storage. Unsupported CredSSP versions, early
incomplete handoff, invalid frames or provider rejection
permanently fail the GSS state and close the framer.

This development gate is deliberately rejection-focused
without a real Kerberos keytab, TLS binding or OS-authorized
session. It grants no admission capability and does not
modify the existing PROTOCOL_SSL diagnostic transport.

### CredSSP decrypted-TLS frame boundary (2026-10-14)

`TsRequestFrameReader` now optionally owns the per-connection
TLS read association: `readOneTlsStep(SSL*)` accepts ONLY a
finished server-role OpenSSL session using TLS 1.2+ and a selected
server certificate/cipher, and pins the SSL pointer across frames.
It issues exactly one capped `SSL_read_ex` call per invocation,
reading at most the next TSRequest DER bytes-needed boundary.
`Progress` means OpenSSL may already have additional decrypted
bytes and the connection owner should call again without waiting
for kernel socket readiness. `NeedRead`/`NeedWrite` require
readiness; a complete DER frame blocks all future reads until
explicit secure `releaseFrame()`. No secondary buffer or new
RDP connection/session owner is introduced.
Manual plaintext injection into a TLS-bound reader, or attaching
an SSL stream to a partially manually filled reader, is terminal.
This does not enable CredSSP selection, GSS identity, protected
bindings or OS admission; the current diagnostic still closes.

### CredSSP-to-GSS TLS transcript ownership (2026-10-14)

The single existing `TsRequestFrameReader` owns the TLS
provenance of its currently complete DER frame. A borrowed
`SSL*` can be observed only when that exact frame came
from completed server TLS, never from parser-only DER or a
partially received or released frame. The Linux GSS
acceptor pins that pointer and v5/v6 version on its first
framed negotiation request; subsequent frames cannot
switch certificate/TLS connection or version. The protected
binding handler demands the *same pointer and version*
before GSS unwrap and TLS certificate hash comparison.
Rejection clears the borrowed association; no second
buffer, session owner, or token cache is introduced.
The portable SDK remains independent of GSSAPI; no real
Kerberos authentication, OS session admission or live RDP
listener is enabled.

### Linux native R2 admission lease boundary (2026-10-16)

The positive Linux authorization path is intentionally separate from the
generic candidate-inspection interfaces. `LinuxConsoleAdmissionBroker` is
one-shot and owns the concrete `LinuxLogindReadOnlyEvidenceSource` and
`LinuxLogindSessionChangeSource`; it exposes no
`ConsoleOsEvidenceSource` injection point. It may mint the private-
constructor, move-only `LinuxConsoleAdmissionLease` only after the real
GSS acceptor re-proves the exact active TLS identity and selected X.509,
the policy epoch is stable, the native change monitor is established and
quiet, and fresh NSS/logind facts match the requested account, physical
seat/display, UID and session generation.

The capability carries no password, ticket, keytab or delegated credential:
only bounded principal/account/session identity, UID, session generation,
permission mask and admission generation. Its shared revocation epoch is
invalidated by lease destruction, explicit broker revocation, policy epoch
change or a one-second revalidation deadline. Before protected R3 use,
`authorizes()` rechecks permission scope, live GSS/TLS certificate
continuity, policy, NSS/logind session identity and the native change watch.
The broker owns neither SSL nor GSS; the connection owner must keep them
alive during checks and invoke revoke before teardown.

This does not make logind polling atomic authorization. The double-poll
brackets each native evidence sample, but a seat/session event can occur
immediately after the final poll and before R3 performs an action. R3 must
monitor the returned native change fd, validate immediately before each
protected transition and revoke on disconnect/session teardown. A future
platform primitive that offers an atomic use lease should replace this
residual check/use gap rather than pretending polling eliminates it.
Synthetic evidence remains CandidateOnly and cannot construct the production
lease.

### Linux GSS-to-OS candidate inspection without authorization (2026-10-15)

The optional Linux GSS library now compiles the existing
`ConsoleAdmissionGate`, `ConsoleIdentityPolicy` and
`ConsoleOsEvidenceInspector` into one provider-side
authentication-to-OS *candidate inspection* boundary.
`requestWithOsEvidence()` first borrows the sole real GSS
acceptor's `verifiedPrincipal()`, which requires a completed
v5/v6 CredSSP TLS public-key proof on the unchanged selected
server certificate. It rejects empty or mismatched principal
claims without even sampling NSS/logind evidence. Only an
exact match can trigger the existing inspector to read
account, physical seat, display, session generation and
monotonic freshness for a CandidateOnly comparison.

The result is intentionally discarded and cannot grant
OS authorization, desktop access, clipboard/input permissions,
MCS or a session capability; fabricated OS sources can also
report matching candidates. Both success and failure
terminally reject the provider and leave the gate Denied.
The historical caller-attested snapshot method never matches
policy and is strictly terminal deny-only. Never issue
blocking OS provider reads from an event-loop thread; the
existing isolation/quarantine and revocation contracts
remain separate. Positive real GSS plus an audited,
privileged OS authority still must be validated before
R2 Gate A and R3 admission.

### Provider-derived Kerberos identity visibility gate (2026-10-15)

The optional Linux `GssapiSpnegoAcceptor` owns the only authenticated
GSS principal. Its `verifiedPrincipal()` borrow is now empty during
`MechanismVerified`: real GSS completion alone is insufficient before
the CredSSP v5/v6 GSS-protected public-key hash has been compared to
the active pinned TLS server X.509. Only `ServerBindingPrepared` with
an existing GSS context, a bounded provider name, a pinned TLS version
and the currently unchanged certificate permits the borrowed principal.
Replacing the certificate on the same `SSL*` invalidates this view
without having to wait for a subsequent GSS request. Destroying or
rejecting the provider clears its stored principal and TLS identity.

This is the first provider-to-OS *identity visibility* prerequisite,
not an OS admission capability: the Linux `ConsoleAdmissionGate` still
terminally denies requests, `ConsoleOsEvidenceInspector` yields
candidate observations only, and the R3 MCS/session owner has no
admitted authenticated desktop. An audited native account/session
authority, credential provenance and revocable admission decision
remain necessary. Normal CTests never load default host keytabs.

### CredSSP completed-frame release certificate continuity (2026-10-16)

A completed `TsRequestFrameReader` frame that originated from
`readOneTlsStep()` remains bound to both the exact borrowed server
`SSL*` and the selected server X.509 fingerprint through the release
boundary. `releaseFrame()` reuses `completedFrameServerTls()` immediately
before success; a missing or changed selected certificate on the same SSL
closes the reader, cleanses retained DER, clears TLS/certificate provenance
and prevents later release/read/replay from reactivating it. With unchanged
TLS identity, release wipes only the previous frame and permits the next
CredSSP frame on that same connection. A reader populated only by manual
offline `consume()` has no TLS provenance and retains its existing release
semantics. This framing guarantee does not authenticate GSS or authorize an
OS/R3 session.

### TLS-owned delegated credential denial boundary (2026-10-15)

After the server has verified GSS/SPNEGO and an active CredSSP v5/v6
TLS public-key binding, the client may send a final TLS-protected
`TSRequest.authInfo` containing GSS-encrypted `TSCredentials`
([MS-CSSP 2.2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685),
[3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c)).
The existing Linux `GssapiSpnegoAcceptor` remains its sole GSS
context owner. `consumeFramedAndDenyDelegatedCredentials()` requires
the completed existing `TsRequestFrameReader` and independently
checks BOTH the frame's TLS identity and the acceptor's pinned
original selected X.509, TLS pointer, protocol version, authenticated
principal visibility and GSS context before parsing an authInfo-only
envelope. Only then may the provider attempt confidential
`gss_unwrap`; its plaintext is inspected in-place for metadata
only and securely cleansed before provider buffer release.

**All paths are terminal deny-only.** The reader's encrypted frame
is wiped and closed, and the GSS acceptor's context, credentials and
principal are rejected; no delegated password, token, OS capability
or MCS authorization result is emitted. The legacy
`consumeAndDenyDelegatedCredentials(std::span)` cannot establish
TLS read provenance and is therefore retained solely as a
nondecrypting terminal denial. This prevents synthetic/caller
ciphertext from becoming a future privileged identity source while
OS user and console-session authorization remains unimplemented.

### Combined final CredSSP SPNEGO and TLS binding (2026-10-14)

Per [MS-CSSP 3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c),
the client's last GSS token is accompanied by the encrypted
`pubKeyAuth` value (and v5/v6 nonce) in the *same*
TLS-protected TSRequest. The portable parser retains
borrowed spans and performs only field-shape validation.
A Linux GSSAPI method receives the existing completed
TLS-owned frame, requires `ContinueNeeded` and the
pinned SSL/version, accepts the final GSS token and
requires full GSS completion with no extra output token
that a binding-only server reply could not carry.
It then GSS-unwraps/validates the client's hash of
the selected active TLS certificate and nonce, produces
a confidentially GSS-wrapped server hash and releases
the one bounded DER frame. Any failure closes reader
and acceptor; no credentials or OS authorization result
is exposed. Positive live Kerberos and Microsoft-client
acceptance still require separately verified credentials
and independently authorized OS admission.

### Bounded TLS writing of CredSSP server replies (2026-10-14)

MS-CSSP 2.2.1/3.1.5 requires all server negoTokens and
protected pubKeyAuth replies as canonical DER TSRequest
application plaintext inside established TLS. The
existing `credssp_tsrequest` module now provides
`TsRequestTlsReplyWriter`: only the already
tested offline server encoder can produce the one
pending DER frame, with at most the existing 16-KiB
limit. The transport writer borrows/pins the same
completed server-role SSL pointer for its entire
lifetime, owns the stable encrypted-by-TLS plaintext
until `SSL_write_ex` fully succeeds, returns readiness
requirements on real OpenSSL WANT states, and never
replaces or interleaves an outstanding reply. Explicit
release wipes the one pending buffer and keeps the TLS
association for the next provider reply. Terminal
failure and close erase bytes and invalidate identity.
This is transport serialization only, *not* a
second connection/session authority, GSS provider,
proof of Kerberos trust or permission to enable
PROTOCOL_HYBRID, send an MCS domain reply or
admit a desktop session.

### GSS provider-originated server CredSSP replies (2026-10-14)

MS-CSSP 3.1.5 distinguishes server SPNEGO
`negoTokens` responses while a real authenticated
GSS context is CONTINUING, and a server
`pubKeyAuth` response after the final combined
client token and binding has been verified.
The optional Linux `GssapiSpnegoAcceptor`
provides two additional synchronous orchestration
methods using the existing TLS-derived
`TsRequestFrameReader` and bounded
`TsRequestTlsReplyWriter`. It pins the SAME
actual server SSL and v5/v6 version already held
by the provider, verifies that the writer is
idle before consuming another client message,
then calls the REAL MIT GSSAPI context for
provider-originated tokens. The last combined
message requires verified GSS completion,
confidential GSS unwrap, active TLS certificate
binding comparison and server gss_wrap.
Each method queues only a single canonical
server DER response on matching SSL and
erases transient provider vectors immediately.
Invalid stage, missing credentials, synthetic
frame, outstanding reply, GSS provider failure
or mismatch is a terminal close of all three
components. No extra session controller or
portable GSS dependency was added. TLS
queuing alone is not a trusted client, account
authorization or permission to respond to MCS.

### Pin selected TLS certificate across the CredSSP handshake (2026-10-14)

MS-CSSP 3.1.5 requires the client and server to derive their
direction-specific binding hashes from the actual TLS-selected
server certificate SubjectPublicKey and client nonce. An SSL pointer
alone is not a sufficient long-lived certificate identity if
credentials change within the same TLS connection. The existing
first-party `credssp_tls_certificate` module now hashes the
selected, finished TLS 1.2+ server X.509 DER certificate to a
fixed SHA-256 fingerprint, sharing selected-certificate role,
cipher and handshake checks with the SubjectPublicKey binding
computation. The original single bounded
`TsRequestFrameReader` retains this one fingerprint from its
first real TLS read, tests it before every subsequent step,
and hides completed SSL provenance from the GSS provider
if that selected certificate changes even between frame
completion and the synchronous handoff. Secure close
clears the fingerprint; `releaseFrame()` cleanses only
that one DER frame, retaining the transcript identity
for the next request. The fingerprint proves transport
continuity, NOT genuine Kerberos, client OS identity,
account admission or executable desktop availability.

### TLS-owned CredSSP pubKeyAuth binding-only handoff (2026-10-14)

Microsoft MS-CSSP 2.2.1/3.1.5 carries
all client pubKeyAuth ciphertext inside the
same established TLS transcript as SPNEGO.
Previously the optional Linux GSS acceptor's
`processProtectedBinding(SSL*, rawDer)`
could receive caller-injected DER without
proving that those bytes originated from
that SSL stream, notwithstanding its
required verified GSS context. That entry
point is now permanently deny-only.
The existing `TsRequestFrameReader` is the
single TLS provenance + DER lifetime owner
for BOTH the combined-final and binding-only
forms. `processFramedProtectedBinding`
requires its completed server TLS pointer
(and verified selected X509 fingerprint),
the accepted original TLS and v5/v6 version,
exact binding-only DER fields, and the
real Kerberos-secured GSS context before
calling shared confidential GSS unwrap,
active nonce/public-key comparison and
GSS wrap. On success it wipes/releases
the single received DER frame, retaining
the original TLS pin for the next frame.
The new framed reply queue reuses the
existing `queueFramedProtectedReply`
and `TsRequestTlsReplyWriter` rather than
creating another connection state owner.
All failures terminally close and cleanse
frame, writer and GSS context. No evidence
of positive authenticated Kerberos,
OS session authorization, actual RDP
MCS admission or usable desktop is implied.

### CredSSP server TLS outgoing certificate continuity (2026-10-14)

In addition to the existing inbound
`TsRequestFrameReader` TLS certificate
fingerprint pin, the same first-party
`TsRequestTlsReplyWriter` now remembers a
single SHA-256 fingerprint of the
selected, finished server SSL X.509
certificate when it queues its FIRST
canonical v5/v6 TSRequest response.
It validates the identical original
`SSL*` and same selected certificate
at every nonblocking `SSL_write_ex`
attempt (including WANT retry and
already Complete), at explicit
`releaseReply`, and before accepting
any subsequent reply on the same writer.
It reuses the original
`fingerprintActiveCredSspServerTlsCertificate`
instead of maintaining a competing
certificate selection implementation.
Any changed or unhandshaken server
certificate closes and cleanses the
outgoing DER, TLS identity and digest
terminally. Once TLS has accepted a
write, ciphertext may already be on
the wire; rejection cannot retroactively
retract that record and does not count
any future successful write. This
transport boundary does not create
authenticated GSS identity,
independent OS permission or an
RDP server connection controller.

### GSS acceptor transcript-wide X.509 identity (2026-10-14)

The optional Linux real MIT GSS provider is part of the same
TLS/CredSSP transcript but is NOT a second session controller.
Its original pinned `SSL*` and MS-CSSP version are now
accompanied by one independently pinned SHA-256 fingerprint
of the FIRST selected TLS server DER X.509 certificate.
That pin is checked with `CRYPTO_memcmp` on every
subsequent SPNEGO request, protected binding-only or
combined-final proof, before confidential GSS proof
verification, and before queuing a server TLS response.
Recreating the `TsRequestFrameReader` on an unchanged
SSL pointer cannot evade the GSS acceptor's old
certificate identity; terminal reject releases MIT
GSS context and explicit acceptor credential, erases
principal, and cleanses the digest.

An optional Linux-only external-credential test exercises a real
`gss_init_sec_context` initiator using an EXPLICIT
`gss_acquire_cred_from` FILE: credential cache, and the
existing production `GssapiSpnegoAcceptor` using its
independently specified service FILE: keytab.
The real mechanism steps travel inside completed
in-memory OpenSSL TLS application records and canonical
TSRequest DER. Once both sides truly complete, the
test checks confidentially wrapped client-to-server
and server-to-client v5/v6 binding-only public-key
proofs, and a same-SSL certificate replacement
between TWO distinct TLS frame readers. The
binding-only path tests the existing provider seam,
not the REQUIRED combined-last-token MS-CSSP
interoperability with Microsoft Windows App.
No daemon, KDC, OS user admission or desktop
is activated by the test option.

### Explicit GSS provider-rejection to CredSSP v6 error queue (2026-10-15)

The Linux MIT GSSAPI acceptor now distinguishes an actual
`gss_accept_sec_context` provider/policy rejection from a local
frame, version, provenance, keytab, allocation, or TLS pin
failure. Per [MS-CSSP 2.2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685)
and [3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c),
the server SHOULD provide a negative NTSTATUS when SPNEGO fails
under supported error-code versions. This SDK supports **only v6**
and emits a fixed `STATUS_LOGON_FAILURE` (0xC000006D) via the
*existing* canonical 15-byte `TSRequest.errorCode` serializer
and `TsRequestTlsReplyWriter`.

The new `SpnegoStep.providerRejected` evidence is set only
when the real configured MIT GSS backend has actually processed
a candidate token and rejected its mechanism/security policy.
`acceptFramedNegoAndQueueReply` records the complete v6 TLS-
derived TSRequest, current selected X.509 fingerprint and
continuity of the original SSL before handing it to GSS;
on provider rejection, after provider credentials/context/
principal have already been destroyed, it verifies the
same fingerprint again and queues the canonical negative
reply. It returns `SpnegoStatus::FailureQueued`: **queued, not
written**, and emphatically **not authenticated**. The single
connection owner must drive the existing nonblocking writer's
SSL_write_ex/retry/release path before closing the TLS session.
A completed terminal error does not allow success reply reuse.

Absent explicit keytab credentials, fake caller-supplied DER,
wrong version (v5), changed SSL/certificate, malformed tokens,
failed local copies and pending/wrong writer states still cause
SILENT terminal closure with no errorCode or GSS identity.
The normal CI tests exercise those fail-closed paths, not a
positive credential. The new separate opt-in real-GSS failure
delivery probe requires caller-authorized dedicated keytab
and ticket-cache configuration; it does NOT run in default CI.
Neither the server nor the probe opens an RDP listener, admits
an OS session, or sends desktop data. A genuine full Windows
CredSSP combined-last-token acceptance remains NOT RUN.

### Version-6 CredSSP failure reply transport boundary (2026-10-14)

Microsoft MS-CSSP 2.2.1 and 3.1.5 support a
server `TSRequest.errorCode` on a failed
SPNEGO negotiation at versions 3, 4 and 6.
The existing library currently accepts
only v5/v6 server-reply wire shapes, so
it adds an EXPLICIT, v6-only canonical
15-byte DER failure serializer with
two unsuccessful NTSTATUS codes:
`STATUS_LOGON_FAILURE=0xC000006D`
and `STATUS_NOT_SUPPORTED=0xC00000BB`.
ASN.1 INTEGER must retain its signed
32-bit four-byte representation and
the only populated fields are [0]
version and [4] errorCode. No token,
nonce, credentials or pubKeyAuth is
included. The same single
`TsRequestTlsReplyWriter` now exposes
`queueFailureReply`; both its success-
shaped and fail-only serializer pass
through ONE private guarded queue and
the existing stable OpenSSL retry buffer
and pinned TLS selected certificate.
Only a fully written failure can be
released, after which the writer is
terminally closed; callers cannot queue
a later success. The primitive deliberately
does not auto-generate failure from
a GSS exception: the future session
orchestration must select the correct
stage and sanitized NTSTATUS explicitly,
then reject the session separately.
No new GSS, OS admission, service,
or RDP client acceptance is implied.

## Offline client/server finalization PDU correlation (2026-10-15; CI PASS)

Per MS-RDPBCGR 2.2.1.14–2.2.1.21, a pure, borrow-only
`RdpFinalizationTranscript` compares complete decrypted
Share Control PDUs for client Synchronize, Control Cooperate,
Control Request and server Synchronize, Control Cooperate,
Control Granted. It reuses one set of existing syntax decoders,
compares externally provided share and MCS user IDs, and
never sends packets or stores state. The uninitialized
server Synchronize targetUser is NOT client identity.
The named fields do not establish arrival order or peer
provenance; the future single authenticated session owner
must enforce the actual dependencies, Kerberos/CredSSP/TLS,
independent OS admission and licensing before activation.

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

## TLS-selected-certificate continuity from preauth to MCS (2026-10-15)

The sole `PreauthConnectionStream` binds one completed server
`SSL*` after all X.224 Confirm bytes are sent. It now also
pins the selected local X.509 SHA-256 via the existing
`fingerprintActiveCredSspServerTlsCertificate` helper,
rather than using a borrowed pointer as complete identity.
A later MCS TLS read, including a resumed WANT_READ/WRITE
or partially buffered RFC1006 TPKT, rejects a different
certificate selected on the SAME SSL object before it reads
additional plaintext. `close()` wipes the pin. No new
crypto provider or session controller; borrowed SSL/BIO
remain externally owned and event-loop-affine. Pinning does
NOT establish TLS CA trust, GSS/CredSSP authentication,
the MCS sender, OS authorization or a usable desktop.
Real positive Kerberos and independent OS admission remain
mandatory for any production MCS reply.

## Offline General Capability Set structure intake (2026-10-15)

Per MS-RDPBCGR 2.2.7.1.1, a 24-byte
`TS_GENERAL_CAPABILITYSET` includes capability type/length,
OS major/minor IDs, protocol version 0x0200, ignored pad,
compression metadata, extra flags and byte-sized refresh/
suppress support. The single existing strict Active PDU
parser first proves complete framing and count/envelope
bounds. A new pure helper scans for exactly one General
set and copies primitive fields only, with no new allocations
or borrowed results. Unknown sibling capabilities and
ignored pad values are NOT interpreted. A duplicate or
malformed mandatory General set is rejected by this
specialized helper, leaving generic envelope decoding
unchanged. This extraction does not prove client MCS
sender provenance, authenticate an account, select graphics,
enable FASTPATH, authorize the console or activate the share.

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

## Offline Bitmap Capability extraction (2026-10-15; CI NOT RUN)

MS-RDPBCGR 2.2.7.1.2 defines a 28-byte Bitmap
Capability Set in both client Confirm and server
Demand Active. The existing complete Share Control
Active decoder provides exact framing and validated
capability-set envelopes. The new allocation-free
`parseRdpBitmapCapabilityFromActive` walks those
already-bounded envelopes for exactly one type 2
and reads its advertised depth, dimensions, resize
and drawing flags. It requires nonzero dimensions,
0/1 resize and the two mandatory bitmapCompression
and multipleRectangleSupport flags equal to 1.
Legacy receive1/4/8 bit fields, highColorFlags and
both pad2octets fields are ignored per specification.
Unknown drawing bits and sibling capability types
are tolerated, not enabled. No framebuffer allocation,
channel/session owner, TLS binding, licensing, graphics,
OS approval or real-client admission is introduced.

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

## Gate A borrowed TCP/TLS/MCS owner continuity (2026-10-15)

The existing `PreauthTcpAdapter` has one borrowed
`TcpNonblockingIo`, one `PreauthConnectionStream` and
a real nonblocking X.224 Confirm path. A newly exposed
`onAttachedTlsIoReady()` and `onAttachedMcsIoReady()`
readiness pair now draws its SSL identity ONLY from
one successful `attachTlsTransport`, with the shared
custom OpenSSL BIO pointer and its borrowed TCP I/O
identity rechecked before provider calls. The network
loopback fixture covers real connected TCP, completed
X.224 Confirm, OpenSSL handshake and exact first MCS
record via this strict path. No new thread, session
controller, listener, socket/SSL lifetime ownership,
TLS certificate policy or direct desktop authorization
is added. The historical argument-bearing method
remains a memory-BIO diagnostic; after network attach
it must also enforce the pinned TLS/BIO owner.
Validated MCS envelope still TERMINATES the diagnostic;
it is NOT an admitted authenticated MCS connection.

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

## R1 native socket and OpenSSL BIO chunk bound (2026-10-15)

The same connected `NativeTcpIo` and borrowed BIO
serving X.224 -> TLS -> diagnostic MCS now accept
at most `kMaximumTcpIoChunkBytes = 18 KiB`
for each `recv`/`send` or synchronous OpenSSL
BIO read/write callback, while returning the actual
short byte count and preserving nonblocking retry
signals. This bounds event-loop work per call and
prevents unchecked `size_t` -> `int` conversion
in Windows Winsock calls. It does NOT buffer partial
data, change TLS record semantics, allocate memory,
add a second session/queue, launch a listener,
authenticate CredSSP/GSS, authorize an OS account
or emit MCS/graphics traffic. Higher-level SSL and
the sole connection owner retain state across
short I/O as before.

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

**R3 MCS Channel Join delivery bookkeeping (offline-only; no admission):**
`McsChannelJoinWriteGate` lives in the existing transport MCS header for
event-loop composition by the one future authenticated R3 session owner.
It copies up to 33 assigned channel IDs, buffers bounded distinct join
requests, serializes one 15-byte Join Confirm at a time through the
owner's existing outbound writer and marks channels joined only after
full accepted-byte completion. Already joined/pending requests do not
produce a second reply. Wrong IDs, malformed order, invalid/late
writer callbacks and disconnect revoke all memberships. Pending byte
spans are borrowed and never outlive a mutating call. Monotonically
increasing reply and write-slice receipts reject replay of stale
completions across confirmations and within partial writes.

Parsed inbound SendDataRequest membership requires the bound UserId and
confirmed channel; it never grants TLS/CredSSP authentication, independent
OS session authorization, licensing, capability agreement or application
data routing. The sole R3 controller must enforce those separately and
bound the upstream TPKT intake. No second writer, session owner or
live desktop service is introduced.

**R3 preauth terminal-state synchronization (denial-only):**
The one R1 preauthentication owner now revokes its embedded, sole
`McsSessionLifecycle` on an invalid/repeated X.224 request or failed/
premature TLS handshake through the same `close()` used by cancellation.
A read-only lifecycle-phase query provides diagnostic visibility only;
it cannot authenticate an identity or configure a join. Valid TLS still
means only diagnostic progress to an MCS envelope, not R2 authorization.
No new transport, admission capability or session state machine exists.


**R3 first-failure MCS negotiation classification (2026-10-15):**
The existing single deny-only `McsSessionLifecycle` distinguishes
an invalid MCS Connect-Initial envelope from a syntactically valid
packet with failed T.125 domain-parameter merging or failed GCC
Conference Create parsing. It checks these in protocol order using
the first-party decoders; no exception, parser fork, borrowed
userdata retention, negotiated channel or TLS output is introduced.
Each outcome revokes pending join bookkeeping. Valid decoding
remains a syntax diagnostic, never R2 OS-authorized admission.

**R3 unadmitted-domain PDU budget (2026-10-15):**
The same R3 `McsSessionLifecycle` now applies the project's shared
8192-byte first-MCS pre-admission budget to unsolicited T.125 domain
PDUs before invoking the existing parser. Oversized input closes the
single noncopyable owner and invalidates channel membership without
transmitting any reply. The cap applies to deny-only pre-admission
diagnostics, not to any future authenticated session's negotiated
maxMCSPDUsize or virtual-channel fragmentation. A valid peer
Disconnect remains a terminal close, never an admission shortcut.

**R3 domain-PDU first-failure diagnostics (2026-10-15):**
The one `McsSessionLifecycle` maps the existing domain parser's
`InvalidTransport`, `InvalidDomainPdu` and `InvalidPerValue`
outcomes to distinct appended session-intake diagnostics before
terminal teardown. These values are observability only: they do not
retain borrowed spans, send a response, allocate a domain, authenticate
a principal or grant channel permission. Oversize pre-admission input
continues to take precedence before parser invocation.

**R3 first-MCS byte-budget ownership (2026-10-15):**
The project's existing 8192-byte cap on the first decrypted MCS
Connect-Initial TPKT now lives in the common MCS header, shared by
R1's fixed-capacity TLS intake and the sole R3 `McsSessionLifecycle`.
R3 applies the cap before parsing and terminates oversize envelopes;
R1's diagnostic callback forwards all sizes to the one R3 checker
while retaining its R1 TLS intake bound. This defense-in-depth bound
is independent of the negotiated 1024/4096-byte GCC user-data limits.
An oversized diagnostic does not admit, send, or configure anything
and can never be retried on a closed connection.

**R3 first R1/R2 session integration boundary (deny-only):** The
noncopyable `McsSessionLifecycle` owns the R3 Channel Join bookkeeping
and receives the already-decrypted first MCS Connect-Initial from the
existing R1 preauthentication diagnostic. It reuses the strict MCS
parser, domain-parameter negotiation and GCC parser, then closes
without emitting Connect Response because no R2-issued OS-authorized
admission exists. It also denies any pre-admission Erect/Attach/Join or
SendData and accepts peer Disconnect only for terminal teardown.
Each instance is terminal on rejection, disconnection or malformed input.
No fake principal, Boolean authentication flag, test-issued capability,
live TLS writer or second session controller can advance the state.
The R1 syntax-diagnostic Boolean remains true for a *validly decoded*
Connect-Initial even though the R3 session is never admitted. R2 must
supply genuine OS-authorized TLS-bound evidence before protected
transitions can be implemented; offline tests cannot grant it.


**R3 outbound joined-channel MCS envelope:** The existing Channel Join
gate also offers `encodeJoinedSendDataIndication`, a membership-only
wrapper around the first-party server-to-client T.125 encoder.
It refuses queued, partially joined, foreign or disconnected channels,
preserving output on failure. The single future session owner must still
independently authorize R2 TLS identity/OS access, license, phase and
negotiated channel permissions before any TLS write.

## R1 accepted TCP-to-TLS lifetime boundary (2026-10-15)

`OwnedPreauthTcpConnection` nonmovably owns exactly one accepted socket,
the existing `NativeTcpIo` and `PreauthTcpAdapter`, and a unique
server `SSL` attached only after the entire X.224 Confirm is sent.
The custom BIO borrows the embedded I/O object. All cancellation paths
close the diagnostic, free SSL/BIO and then close the socket, retaining
the caller-owned listener. It reuses the current protocol stages and
cannot grant authentication, authorize a desktop or emit an MCS reply.
An external event loop supplies readiness and timeout decisions.

**R1 one-connection OS polling step:** `pollSocketOnce` uses POSIX
`poll` or Winsock `WSAPoll` for precisely the currently owned
accepted socket, with a 25ms per-call wait cap and caller-owned
monotonic deadline. Only the matching existing socket readiness
callback runs, once; timeout and hard OS error close the TLS/BIO and
socket in the original order, with the borrowed listener untouched.
This is a reusable event-loop building block, NOT a new daemon,
background thread or authenticated session controller.

### R1 bounded readiness and connection deadline (2026-10-15)

The same `OwnedPreauthTcpConnection` now advertises `Read`, `Write`,
`ConfigureTls` or `Closed` from the existing preauthentication stage,
unsent X.224 Confirm bytes and OpenSSL's WANT direction. An event loop
supplies readiness bits to `onSocketReady`, which executes at most one
existing bounded callback only when the correct bit is present.
**Critical ordering:** X.224 Confirm/NEG_FAILURE bytes can remain queued
after the parser advances to `AwaitTls` or closes. Writable interest
and the original bounded reply-sender must take precedence over the
resulting stage until the response is fully transmitted.
`ConfigureTls` cannot read TLS bytes without the caller transferring
a configured server SSL. `cancelIfExpired` takes caller-owned monotonic
clock instants, frees borrowed BIO/SSL before socket closure, and makes
subsequent callbacks inert; R10 retains polling, deadline policy and
listener configuration. `establishedTls` is a short-lived read-only
borrow after an actual TLS handshake for future R2 inspection, NOT a
verified client identity, authenticated OS session or R3 admission.

## R1 bounded borrowed-listener accept batch (2026-10-15)

`acceptNonblockingTcpBatch` consumes at most 16 incoming sockets per
caller-selected iteration on an already-configured nonblocking,
borrowed listener. It invokes the SAME single nonblocking acceptor
used for prior RAII tests and hands an `OwnedNativeTcpSocket` by
value to a no-throw callback. That callback can create the existing
nonmoving `OwnedPreauthTcpConnection`, or allow its socket to be
closed by RAII; it may stop further intake. Budget exhaustion does
NOT assert that the OS backlog is empty. Native would-block and
post-progress native failures are explicit. R10 still owns listener
configuration, scheduling, connection limits and admission routing;
this does not activate a listener or authorize an RDP session.

## R1 borrowed listener readiness before bounded accept (2026-10-15)

`pollNonblockingTcpAcceptBatch` is a one-step **borrowed** native
listener readiness helper: POSIX `poll` or Winsock `select` for
the read side of a listening socket, bounded to 25ms and a caller-owned
steady-clock deadline. It never configures a port or creates a
listener, blocks indefinitely, or accepts while idle/expired.
When ready it delegates exactly one 1..16 budgeted batch to the
existing first-party nonblocking acceptor; the only accepted socket
owner remains `OwnedNativeTcpSocket` and then (if adopted by
the callback) `OwnedPreauthTcpConnection`. It never closes the
borrowed listener even on poll error. R10 owns process/listener
policy, fairness and timeout selection; R2/R3 still own
authenticated session authorization and activation.

## R1 fail-closed borrowed-listener configuration (2026-10-15)

`SO_ACCEPTCONN` must report an actual listening socket before the
native one-shot accept or borrowed listener readiness wait. POSIX
additionally checks `O_NONBLOCK` through read-only `F_GETFL`
before any accept. These checks do NOT configure, bind, duplicate,
close or otherwise own the listener. Windows runtime must set
`FIONBIO` itself because the existing mode is not safely queryable.
The already sole accepted-socket owner and authenticated R2/R3
session boundaries remain unchanged.

## R1 Darwin listener-role fallback (2026-10-15)

Apple does not support `getsockopt(SO_ACCEPTCONN)`; use supported
`SO_TYPE` and `getpeername` to reject datagram/connected sockets.
The existing native nonblocking accept rejects remaining nonlisteners.
Windows/Linux continue SO_ACCEPTCONN, all POSIX continues O_NONBLOCK.
No listener ownership or authenticated session activation.


## R1 post-handshake encrypted byte-stream ownership (2026-10-15)

The accepted connection remains one lifetime:
`OwnedNativeTcpSocket -> NativeTcpIo -> OpenSSL BIO -> SSL ->
OwnedPreauthTcpConnection application I/O`. R1 never exports mutable
`SSL*`, BIO ownership or a duplicate descriptor. R2 may continue to borrow
the established `const SSL*` only for immutable TLS/certificate inspection;
R3 receives plaintext byte counts through the bounded transport methods and
retains all packet/framing/session state itself.

Each application call is synchronous and one-step. The span is valid only
for that call. WANT_READ/WANT_WRITE stores no pointer: only Read/Write
operation identity, retry byte count and actual OpenSSL readiness direction
survive. Therefore `onSocketReady`/one-shot polling report readiness but
cannot silently retry application TLS I/O. A short successful write is
returned immediately so the higher owner advances its own stable logical
buffer. Once this byte-stream mode is selected, the older diagnostic MCS
reader cannot consume from the same TLS stream.

Terminal teardown remains application buffers stop -> OpenSSL operations stop
-> SSL/owned BIO release -> `NativeTcpIo` borrow ends -> accepted socket
close. No worker thread, second event loop, listener owner, authentication
decision or second RDP session controller is introduced.


## R1 immutable accepted peer identity metadata (2026-10-16)

The native accept boundary now snapshots the remote TCP endpoint in the same
OS accept operation that transfers descriptor ownership. The normalized
`TcpPeerEndpoint` is allocation-free and platform-neutral: address family,
16 network-order address bytes, host-order port, and IPv6 scope ID. IPv4 uses
the first four bytes and zeroes the remaining twelve. An unsupported
address-family result is rejected before the connected descriptor is exposed.

Ownership remains singular:
`borrowed listener -> OwnedNativeTcpSocket{socket, peer endpoint} ->
NativeTcpIo -> owned BIO/SSL -> OwnedPreauthTcpConnection`.
Moving the socket owner moves the endpoint snapshot; close/cancel clears it.
The nonmoving connection owner returns the snapshot by value, so consumers
cannot mutate native sockaddr storage or perform an address lookup through a
borrowed descriptor.

This endpoint is only network transport provenance. It MUST NOT be treated as
an authenticated client identity, Kerberos/CredSSP principal, OS-authorized
session, channel permission or anti-spoofing proof. R2 still owns identity and
admission; R3 still owns session/channel state. No reverse DNS lookup,
listener policy, connection scheduler, second event loop or service
activation is introduced.


## R3 licensing ownership and authorization boundary (2026-10-16)

The sole `McsSessionLifecycle` now embeds the bounded
`RdpLicensingLifecycle` and closes it on every session teardown. The
licensing object owns only protocol phase; it owns no SSL/socket, identity,
authorization token, event loop, thread or application channel. A reconnect
constructs a fresh session/licensing object rather than resetting terminal
state in place.

Its first reachable standalone phase transition is deliberately tied to a
*fully written* future Server License Request:
`NotStarted -> AwaitClientLicenseResponse -> AwaitServerDecision`.
The latter means only that one initial client licensing response is
structurally valid; it is not a `licensed=true` state and cannot enable
Demand Active. Wrong-order, duplicate, malformed or late messages fail
terminally. The production `McsSessionLifecycle` still has no positive path
past `AwaitVerifiedR2Admission` because R2 has not published a genuine
revocable native-OS admission capability.

Licensing dispatch must eventually occur only after R1 TLS decryption and R3
checks for the same admitted generation, assigned user, global/static channel,
segmentation/reassembly, direction and licensing phase. The common licensing
parser returns only an immutable borrowed body span whose lifetime is the
caller's unchanged input. It never allocates from `wMsgSize` or nested BLOB
lengths and never logs opaque licensing material.


## R3 native R2 admission handoff into MCS Basic Settings (2026-10-16)

R2 now has a concrete Linux-only admission lease, so R3 no longer treats
"admission unavailable" as a permanent architectural condition. The public
`McsSessionLifecycle::onConnectInitial` remains deliberately denial-only.
The only current positive entry is
`LinuxConsoleAdmissionBroker::authorizeR3McsConnectInitial`: the concrete
broker first calls its existing native `authorizes` path with
`kConsoleViewPermission`, rechecking exact TLS/GSS identity, policy epoch,
NSS/logind session identity, native change watch and lease freshness, then
immediately invokes a private friend transition on the sole R3 owner.

No caller-visible bool, scalar token, principal string, user ID or synthetic
evidence object can invoke that private transition. On success, R3 validates
the complete bounded MCS Connect Initial, T.125 DomainParameters and GCC Client
Data while the input span is live, stores only the R2 admission/session
generation numbers, and advances to `AwaitConnectResponse`. It emits no
bytes and does not yet allocate user/static channel IDs. Malformed or
wrong-order admitted input closes R3 and revokes the same broker/GSS admission
so it cannot be replayed on a fresh protocol owner.

Disconnect ordering is explicit through
`LinuxConsoleAdmissionBroker::revokeR3Session`: close R3 protocol/licensing/
channel state first, revoke R2/GSS second, and only then may the caller release
R1 TLS/socket ownership. The method is idempotent. A valid peer Disconnect
Provider Ultimatum is recognized as teardown while R3 waits for Connect
Response; every other DomainMCSPDU in that phase is terminal ordering failure.
The native logind check/use race documented by R2 remains: the service must
monitor the broker's native change fd and repeat broker authorization
immediately before every later protected R3 transition.

Native session-change readiness has an explicit R2-to-R3 teardown edge:
`LinuxConsoleAdmissionBroker::onNativeSessionChangeReady()` re-polls the
broker-owned logind monitor. `Changed` or `Unavailable` closes R3
protocol/licensing/join state first and then revokes the admission
generation/GSS context. A missing watch is terminal too. `None` is only a
spurious wake and does not authorize anything; the caller must still invoke
`authorizes()` immediately before the next protected R3 transition. This
keeps prompt revocation separate from positive authorization and preserves
the documented non-atomic logind check/use limitation.

Later R3 transitions now have a generation-bound R2 authorization contract
even though no runtime Connect Response writer exists yet.
`McsSessionLifecycle::revokeUnlessAdmissionBindingMatches` is deliberately
revocation-only: caller-provided generation scalars can never create or
advance admission. It retains state only when the owner is already in its
private R2-admitted `AwaitConnectResponse` phase and both stored generations
match the exact lease. `LinuxConsoleAdmissionBroker::authorizeR3ProtectedTransition`
then repeats permission, GSS/TLS certificate continuity, policy, NSS/logind
fingerprint, freshness and native-watch validation. Failure closes R3 and
revokes R2/GSS synchronously; success changes no R3 phase and emits no bytes.
R3 must call this gate immediately before every protected state/write
transition and must call it again before the next one.

The existing MCS Connect Response encoder remains offline because it currently
accepts only its diagnostic PROTOCOL_SSL input and caller-supplied channel IDs.
The live CredSSP/Hybrid path therefore stops at `AwaitConnectResponse` rather
than emitting a response with invented or mismatched protocol/allocation
semantics.


## R3 Basic Settings enhanced-security replay parsing (2026-10-16)

The bounded GCC Client Core parser now treats its optional tail as the strict
ordered prefix defined by MS-RDPBCGR instead of accepting every length at or
above the 128-byte fixed body. Only complete optional-field boundaries are
accepted. R3 retains the non-sensitive `earlyCapabilityFlags` and Client
Core `serverSelectedProtocol` together with explicit presence bits; no
borrowed Core view or identity string survives parsing.

For Enhanced RDP Security, Client Core `serverSelectedProtocol` is the
client's replay of the server's earlier RDP Negotiation Response. The pure
`matchesMcsSecurityNegotiationReplay` helper checks that replay against
externally proven X.224 request/selection values, verifies the selected SSL or
HYBRID bit was actually offered, and grants no admission or write authority.

Server Core has a different replay rule: `clientRequestedProtocols` carries
the client's complete original request mask. The offline Connect Response
encoder therefore no longer hardcodes PROTOCOL_SSL. It accepts only the
currently implemented Enhanced Security bits PROTOCOL_SSL and
PROTOCOL_HYBRID, separately or combined, and serializes that exact mask.
Unsupported RDSTLS/HYBRID_EX/RDS-AAD/unknown bits remain fail-closed.

No runtime response publication is enabled. R1 still selects its diagnostic
PROTOCOL_SSL path, but the sole accepted/TLS owner now exposes immutable
`SecurityNegotiationProvenance` by value only after the exact attached TLS
has established. The snapshot contains the complete parsed
`requestedProtocols` mask from the original X.224 request and the exact
server-selected protocol produced by that same R1 negotiation. It is revoked
with connection teardown. A caller-supplied scalar is still not authority.
R3 therefore remains in `AwaitConnectResponse` until it consumes this R1
provenance and R2 freshly revalidates the bound admission/session generations
immediately before writer ownership.


## R7 ScreenCaptureKit stream lifecycle and CoreVideo handoff (2026-10-16)

The native capture boundary is split intentionally. `MacScreenCaptureStream` and its state machine are C++23. `screen_capture_stream.mm` is the only ScreenCaptureKit Objective-C++ bridge and is built with ARC. Objective-C objects stay private to that translation unit. The bridge retains a shared C++ callback-state object, never a borrowed `MacScreenCaptureStream::this`; therefore queued delegate/output/completion callbacks can observe a retired state without dereferencing a destroyed owner.

A binding comes from the existing `NativeDisplayGeometryRefresh` epoch and carries `displayId`, physical width/height, geometry generation and topology revision. ScreenCaptureKit content enumeration must find an `SCDisplay.displayID` equal to that CoreGraphics identity. No coordinate-derived identity and no fallback display are accepted. The global native reconfiguration revision fences prepare/start/frame publication, and the owner exposes explicit topology invalidation so the topology coordinator can immediately close the native stream. Late old-generation callbacks retain only old state and cannot publish into a replacement generation.

The output queue is a private serial dispatch queue and ScreenCaptureKit queue depth is three; R7 creates no additional frame queue. A complete screen sample is converted only to its `CVPixelBufferRef`, then passed through the existing `LockedBgraPixelBuffer` RAII lock. The consumer receives that locked BGRA frame synchronously and must copy into explicitly bounded owned storage before returning if asynchronous R4 work is needed. Neither x264/RDPGFX scheduling nor RDP session admission moves into R7.

Screen Recording preflight remains macOS TCC evidence only. Successful preflight, shareable-content enumeration, or stream start never substitutes for R2 authentication or R3 session admission. Live runtime wiring remains intentionally absent until those contracts are genuine.


## R1 immutable X.224 security negotiation provenance (2026-10-16)

The one preauthentication stream retains only two fixed-size scalars from its
successful Enhanced Security exchange: the client's complete parsed
`requestedProtocols` mask and the protocol actually selected by
`negotiateDiagnosticTls`. `SecurityReply::selectedProtocol` is explicit so
the selection is never reconstructed from the response packet; in a
NEG_FAILURE the same wire DWORD is a failure code, not a selected protocol.

`OwnedPreauthTcpConnection::securityNegotiationProvenance()` returns this
pair by value only while the exact attached SSL/BIO/socket has completed TLS
and the underlying stream is in `AwaitMcsConnectInitial`. The snapshot is
unavailable while X.224 response bytes are pending, while TLS is incomplete,
for rejected negotiation, or after cancellation/close. No original packet
buffer, caller span, mutable SSL/BIO, native descriptor, principal, admission
lease or R3 state is exposed.

This is the R1 transport half of R3's Enhanced Security replay correlation.
R3 still owns GCC/MCS replay validation and response state; R2 still owns
identity and independent OS authorization. The existence of the snapshot
cannot publish a Connect Response by itself.


## R3 Connect Response R1/R2/R3 composition (2026-10-16)

The first protected outbound MCS transition has one ownership chain: R1
`OwnedPreauthTcpConnection` owns SSL/socket and immutable X.224 provenance;
R2 `LinuxConsoleAdmissionBroker` owns the revocable OS-admission lease and
fresh reauthorization; R3 `McsSessionLifecycle` owns negotiated MCS state,
identifier allocation, response bytes and write receipts.

R2 reads both the established TLS pointer and
`SecurityNegotiationProvenance` from the same R1 owner rather than accepting
protocol scalars from a caller. R3 independently correlates its stored Client
Core replay before encoding. Each next write slice passes through R2 again.
Completion uses only the previously issued monotonic reply/slice receipt;
wrong or late completion fails closed. Full response delivery changes only
R3's phase to `AwaitErectDomain`; later DomainMCSPDU transitions remain
separately protected.


## R4 x264 AVC420 encoder ownership (2026-10-16)

The first real H.264 producer is the noninstalled `rdp-server-graphics`
target. `X264Avc420Encoder` owns exactly one `x264_t` context; no protocol,
platform-capture, scheduler, authorization, or runtime owner manipulates that
handle directly. The exported `rdp-server-protocol` target retains the
RDPGFX packetizer/lifecycle and has no x264 dependency.

The wrapper accepts one validated NV12 picture with independent Y/UV strides
and extents. Input is borrowed only for the synchronous
`x264_encoder_encode` call and is never retained, which is compatible with
short-lived XShm, mapped D3D11 and locked CoreVideo views. Every successful
access unit is copied out of x264's next-call-invalidated NAL storage into a
bounded caller-owned `std::vector<std::byte>`.

The initial correctness profile is 8-bit 4:2:0 H.264 Baseline, Annex-B,
repeat SPS/PPS on IDR, no B frames, no lookahead, one encoder thread and one
reference frame. Reference history is preserved only across successive
pictures with the same coded/visible geometry. `reset()` destroys that
history; geometry or generation changes must reset/recreate the encoder.
x264 SPS crop fields describe the visible dimensions inside the 16-aligned
coded frame; RDPGFX regions independently constrain the presented surface.
R3 remains the sole future Graphics DVC authority.


## R2 Connect Response completion authorization fence (2026-10-16)

Connect Response write completion is a protected state-publication boundary,
not merely receipt bookkeeping. R2 requires the same nonforgeable lease and
exact R1 connection used for preparation, confirms live established TLS and
R1 negotiation provenance, and reruns generation-bound native authorization
before R3 consumes any accepted-byte receipt. Thus policy/native-session
revocation, GSS/TLS loss, stale generation, missing provenance or bad receipt
cannot advance R3 writer state or transition to `AwaitErectDomain`.

The fence cannot undo bytes already accepted by TLS in the interval after the
pre-write authorization. The serialized runtime must therefore continue
servicing native-change readiness promptly and authorize every write slice;
the completion fence prevents stale authorization from becoming durable R3
state after that unavoidable external check/use interval.

## R3 protected Erect Domain boundary (2026-10-16)

After full Connect Response delivery, R3 owns `AwaitErectDomain`. Erect is
input-only: the protocol sequence sends Attach User next, so a successful Erect
moves directly to `AwaitAttachUser` and creates no outbound write state.

Only `LinuxConsoleAdmissionBroker::authorizeR3ErectDomain` can invoke that
positive transition. R2 derives the active TLS pointer from the same
`OwnedPreauthTcpConnection`, checks the bound admission/session generations
and repeats native view authorization before R3 parses the complete decrypted
TPKT. Borrowed packet bytes do not survive the synchronous call. Wrong order,
malformed transport/PER, oversized input, unexpected PDU, disconnect, stale
lease or native reauthorization failure closes R3 and revokes R2/GSS. Erect
allocates no UserId/channel and grants no licensing/share/application authority.


## R7 generation-safe macOS cursor snapshot boundary (2026-10-16)

`MacCursorSnapshot` is independent of the ScreenCaptureKit frame callback and owns its BGRA shape bytes outright. Its position is the cursor hotspot expressed in the existing RDP virtual-desktop coordinate system; no AppKit/CoreGraphics coordinate convention escapes the macOS adapter. A hidden snapshot clears width/height/hotspot/position/storage, while a visible snapshot must be structurally valid, no larger than 256x256 and no larger than 256 KiB. The constructor rechecks the same geometry generation and topology revision before publishing the snapshot, so a display reconfiguration cannot silently relabel old cursor state.

`mac_cursor_snapshot.mm` is the sole AppKit cursor bridge. It uses a read-only Quartz event for global pointer location, the existing display mapping for backing scale, and the current system cursor image/hotspot for shape acquisition. Deprecated system-wide cursor introspection is isolated here; no deprecated cursor API crosses a header or portable target. Shape pixels are rendered once into tightly packed premultiplied BGRA using CoreGraphics and transferred by `std::unique_ptr<std::byte[]>`.

The sampler does not start a capture stream, request Screen Recording or Accessibility permission, install an event tap, move the cursor or inject input. It must only be called by a future independently authorized per-user desktop owner. R4 remains the sole owner of cursor scheduling/deduplication and protocol encoding.


## R7 generation-pinned macOS input controller (2026-10-16)

`MacInputController` is a single-thread-affine R7 native-state owner pinned to one current `NativeDisplayGeometryRefresh` generation and Quartz topology revision. These values are revocation facts only: they do not authenticate a user or authorize a desktop. A future concrete macOS R2/R3 route must own the geometry lifetime, serialize access, and authorize the exact interactive desktop before it may construct or invoke this controller.

The controller consumes macOS-native virtual-key codes plus RDP scan identity, virtual-desktop pointer coordinates, five buttons and bounded vertical/horizontal wheel deltas. Pointer coordinates pass through the existing Retina/multi-display geometry transform; monitor gaps and stale epochs fail closed. Held key/button state is fixed-capacity and allocation-free. Duplicate make/button transitions are idempotent, scroll units accumulate in bounded 120-unit steps, callback reentry is denied, cancellation during a native callback is deferred, and a short native batch is terminal. Cleanup releases held state only while the pinned generation/revision is still current; after a display-generation/topology change it clears local state without injecting releases into a replacement desktop.

`mac_input_controller.mm` contains a dormant Quartz event translator for keyboard, pointer, drag, button and line-scroll commands. It checks non-prompting Accessibility trust immediately before posting and uses `CGEventPost` at the HID event tap, but no public callback factory exposes this capability. The only public native function is the read-only Accessibility trust preflight. Therefore generation numbers, a positive Accessibility result, or test callbacks cannot independently create a runtime input path.


## R7 synchronous macOS desktop session/permission guard (2026-10-16)

`MacDesktopSessionGuard` is a revocation-only precondition between future R2/R3 macOS authorization and the existing R7 capture/input children. It pins one caller-selected nonzero user ID, one `NativeDisplayGeometryRefresh` generation, and its Quartz topology revision. None of those values is authority: the guard can only deny or remain current.

Before each requested capture or input operation, the guard checks the pinned geometry/revision, reads the caller's Quartz GUI-session facts, checks the relevant no-prompt OS permission, reads the session a second time, and rechecks geometry. The two session samples must be identical and both must report the selected user as the WindowServer session user and the process effective UID, with console/login-complete state. Capture uses the existing Screen Recording preflight; input uses the existing Accessibility trust query. Any denial, malformed read, reentry, mid-check session change, permission loss, geometry refresh, or topology change permanently closes the guard.

The native reader uses `CGSessionCopyCurrentDictionary` and documented Window Server session properties only; no username string is retained, no token is opened, no login session is switched, and no prompt is requested. The guard deliberately exposes no ScreenCaptureKit object and no Quartz event-posting callback. A future concrete macOS R2/R3 route must still provide the independently authorized target UID and invoke this guard immediately before the native child operation. Synchronous double-read cannot prove an unobserved user switch-away-and-back between separate calls; a native session-change revision/watch remains a later lifecycle hardening step.


## R7 monotonic macOS GUI-session revocation epoch (2026-10-16)

`NativeSessionChangeWatch` is a process-scoped revocation source separate from
`NativeDisplayReconfigurationWatch`; display and Retina topology remain owned
by `NativeDisplayGeometryRefresh`. The session watch has one process
registration owner and a process-lifetime 64-bit revision initialized nonzero.
Release/acquire atomic transitions are monotonic; zero is terminal exhaustion
and is never reused. Explicit start and stop advance the revision so guards
cannot span notification-coverage lifetimes.

The Apple Objective-C++ bridge registers the resign-active and become-active
session notifications only on the shared `NSWorkspace` notification center.
Observer blocks capture a static recorder and scalar registration epoch. The
recorder performs one atomic revision transition and no allocation, identity
lookup, TCC query, capture, input action or watch-object dereference. Observer
retirement clears the active scalar epoch before removal. A callback already in
flight may conservatively add a revision but cannot restore coverage; delayed
callbacks carrying older epochs are ignored. Removal failure retains the
process reservation so a second observer authority cannot appear.

Native coverage is accepted only from an already-running AppKit main-loop
context. Successful observer creation alone is not treated as proof that a
headless or indefinitely stalled process observes every fast-user-switch
transition; such a context returns `DeliveryUnavailable`. Real delivery
remains an owner macOS 27 validation gate.

`MacDesktopSessionGuard` remains R7's revocation-only precondition. It now
pins the session-watch revision alongside target UID, display generation and
topology revision. `allows()` requires unchanged active watch coverage before
the first Quartz session observation and again as its final success gate. The
existing two identical Quartz observations and selected capture/input
permission check remain mandatory. Any watch event, coverage stop/failure,
UID/session mismatch, topology change, permission denial, reentry or callback
cancellation closes the guard permanently. The revision never constitutes
authentication, R2/R3 admission, ScreenCaptureKit authority, Quartz input
authority or R4 scheduling permission.
