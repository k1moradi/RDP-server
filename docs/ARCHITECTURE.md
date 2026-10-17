## R5 XI2 pointer generation fence across RandR (2026-10-16)

The geometry-bound XI2 pointer observer uses the same single XCB owner as
capture/damage/input. A RandR transition can leave a motion event generated for
the retiring observer queued after the aggregate has already subscribed a
replacement tracker. Extension opcode, XI2 event type and root window are not
sufficient generation provenance.

Each `X11PointerPositionTracker` records the request sequence of the successful
`XISelectEvents` subscription that creates its generation. `handles()`
accepts motion only when XCB's reconstructed `full_sequence` is at or after
that floor using bounded 32-bit serial arithmetic. The replacement tracker's
synchronous `QueryPointer` snapshot remains valid current-state observation;
the sequence fence only rejects older queued XI2 events.

## R5 XDamage event generation fence (2026-10-16)

## R2 Linux PAM verifier boundary (2026-10-16)

The Linux PAM verifier is a subordinate OS-authentication primitive, not an R2 capability. It owns only an explicit PAM service name and one synchronous verification call; it has no socket/TLS/GSS/session/logind state and cannot construct a `LinuxConsoleAdmissionLease`.

Password conversion stays inside this boundary: bounded UTF-16LE is revalidated, converted into fixed-capacity UTF-8 stack storage, and cleansed on every return path. The PAM conversation may transfer one password response into PAM's C-API ownership; R2 retains no heap/plaintext copy. Username prompts and additional secret prompts are refused.

A future positive path must first parse the TLS-derived confidential `TSPasswordCreds`, match the delegated username to the immutable `ConsoleIdentityPolicy` rule for the exact provider-derived Kerberos principal, then invoke PAM. PAM success plus `pam_acct_mgmt` is necessary but insufficient; only the authenticated GSS owner may set the private completion proof, and `LinuxConsoleAdmissionBroker` must still independently revalidate exact R1 HYBRID/TLS provenance, NSS/logind foreground-session facts, permissions, freshness, generation and change-watch state.


A geometry rebuild may occur while XCB still holds events generated for the
retiring XDamage resource. Resource ID plus extension event type are not treated
as sufficient generation provenance. Each `X11DamageTracker` records the full
request sequence of the successful initial `XDamageSubtract` that completes
its generation initialization. `handles()` accepts a Damage notification only
when XCB's reconstructed `full_sequence` is at or after that floor using
bounded 32-bit serial arithmetic.

This fence is local to the existing tracker and one XCB owner. It does not add
an event queue, display connection or graphics scheduler. RandR still stops the
bounded display batch at the geometry transition, the aggregate still cancels
old geometry-bound children before constructing replacements, and later queued
events are then offered to the replacement objects with their own generation
floor.

## R10 administrator licensing provisioning boundary (2026-10-16)

R10 owns the administrator-facing configuration boundary for the existing R3
licensing identity and private-key credential. The optional six-field group is
`licensing_certificate`, `licensing_private_key`,
`licensing_product_version`, `licensing_company_name`,
`licensing_product_id`, and `licensing_scope`; partial groups fail. Legacy
syntax/TLS/Linux-security checks accept the group being absent and do not open
licensing credential files.

Product version is nonzero decimal `uint32_t`. Company/product are canonical
UTF-8 converted allocation-free to null-terminated UTF-16LE within R3's
512-byte bound; malformed/overlong UTF-8, surrogate encodings, embedded
NUL/control characters and overflow fail. Scope is printable ASCII converted
to R3's null-terminated ANSI form within the same bound.

`--check-licensing-credentials` uses production `RuntimeLicensingContext`
and `configureFromCredentialFiles()`, reusing the exact-opened-object secure
snapshot policy and native-object alias rejection. The certificate is the RDP
`SERVER_CERTIFICATE` v2 root-first X.509-chain binary structure (at least two
DER certificates with RDP framing/padding), not arbitrary DER or TLS PEM. R3
checks chain signatures and requires an unencrypted PEM RSA private key matching
the terminal leaf. This proves cryptographic continuity only, not Microsoft
licensing trust.

Success creates no listener/socket, R2 lease, authenticated user, R3 licensing
transition or Share activation and makes no CAL/real-client acceptance claim.
The temporary context is destroyed before exit and R3 cleanses retained key
bytes. Normal startup remains fail-closed.

## R8 Windows completed-file CF_HDROP presentation boundary (2026-10-16)

`WindowsClipboardFileDestination` remains a native materialization child of `RemoteTransfer`; it now may retain one caller-supplied fully qualified local path alongside the caller-selected HANDLE capability. That path is local metadata only, never synthesized from the remote FILEDESCRIPTORW leaf name, and is observable only after the existing exact-size resize/flush/close completion transition. Partial, cancelled, failed or replaced-generation destinations expose no path.

`WindowsClipboardAdapter` remains the only Win32 clipboard presentation owner. Completed local files use predefined `CF_HDROP`, not the remote CLIPRDR FileGroupDescriptorW/FileContents protocol. R8 serializes a `DROPFILES` payload with a 20-byte little-endian header (`pFiles=20`, zero point, `fNC=FALSE`, `fWide=TRUE`) followed by one UTF-16 fully qualified path, its terminator, and the list terminator. The existing native byte setter owns the GMEM_MOVEABLE allocation until successful `SetClipboardData`; then Win32 owns the memory.

This boundary is immediate-data-only: it does not open the destination file, fetch more FileContents bytes, serialize CLIPRDR, or grant R2/R3/session/TLS authority. Clipboard self-replacement uses the existing `selfReplacingPublication_` fence, while a real local takeover yields the current generation through the existing WM_DESTROYCLIPBOARD path. Missed owner notifications are additionally caught by querying the current clipboard owner before replacement. Stale completed destinations are rejected by exact RemoteTransfer generation comparison.

The first handoff supports one completed regular file. Directory trees, multiple-file CF_HDROP publication, local directory creation and authenticated real-client Explorer acceptance remain later R8 gates.

## R8 macOS completed-file pasteboard handoff (2026-10-16)

## R2 final password-credential parsing boundary (2026-10-16)

The first supported *candidate* final CredSSP credential shape is
`TSCredentials.credType=1` / `TSPasswordCreds`. This does not itself create
authentication authority. R2 accepts syntax only after the existing genuine
R1-owned HYBRID/TLS, Kerberos/GSS and CredSSP public-key proof chain, and the
current production path remains terminal deny-only after final authInfo.

The portable credential inspector is deliberately metadata-only. It requires
canonical DER and exact domainName/userName/password field ordering, bounds
each UTF-16LE OCTET STRING, rejects embedded NUL code units, rejects odd byte
lengths and malformed surrogate sequences, and requires nonempty userName and
password. No plaintext name/password view escapes the parser. SmartCard and
RemoteGuard are identified only so later policy can reject them explicitly;
they have no native verifier.

A future positive Linux implementation must keep secret extraction and
conversion inside R2's authenticated provider boundary, compare the delegated
account against the exact GSS principal and immutable
`ConsoleIdentityPolicy`, invoke a real explicitly configured OS verifier
(PAM authentication plus applicable account checks is the current intended
provider), cleanse every R2-owned secret buffer, then set the private completion
proof only on genuine success. The existing `LinuxConsoleAdmissionBroker`
still performs independent NSS/logind active-session, permission, generation,
freshness and change-watch validation before it alone can mint a lease.


The existing `MacClipboardFileDestination` now optionally binds one
caller-selected strict local `file:///` URL to the same descriptor capability
used for materialization. This local URL is fixed-capacity metadata, never a
path derived from remote FILEDESCRIPTORW. It is erased on partial failure or
cancellation and is observable only after the destination reaches `Complete`.

`MacClipboardAdapter` remains the only macOS pasteboard presentation owner.
Its completed-file publication accepts a `MacClipboardFileDestination`, not an
arbitrary "complete" Boolean or raw URL. It requires destination
`Status::Complete`, a bound completed URL, current synchronized
`RemoteTransfer`, and exact generation equality before entering the native
seam. Thus a partial or stale file cannot be made visible merely by caller
assertion.

The AppKit callback converts the bounded UTF-8 `file:///` string to an
`NSURL`, requires `isFileURL`, clears the currently owned pasteboard and
writes the URL object via `writeObjects:`. Apple documents `NSURL` as
implementing `NSPasteboardWriting` and recommends object-based URL writes in
place of the deprecated URL pasteboard type. No file bytes are recopied into
the pasteboard.

File URLs share the existing pasteboard `changeCount` owner fence with text
and PNG. A detected local takeover yields the generation before any replacement
can occur; same-generation reclaim is refused. Remote generation replacement
and disconnect clear only while the recorded count still proves R8 owns the
pasteboard. There is still one clipboard owner and one FileContents owner.

## R8 macOS file-descriptor destination boundary (2026-10-16)

`MacClipboardFileDestination` mirrors the validated Linux/Windows native sink
boundary while keeping `RemoteTransfer` as the single clipboard generation,
descriptor, stream-ID, response and receipt owner. The macOS child owns only
one duplicated local file descriptor and monotonically increasing sequential
materialization progress for one current-generation file.

The destination descriptor is an explicit capability supplied by the caller;
R8 never converts the validated remote FILEDESCRIPTORW leaf name into a local
path. Apple production callbacks accept only writable regular descriptors and
reject `O_APPEND`, then duplicate with `F_DUPFD_CLOEXEC`. The caller's
original descriptor remains caller-owned. The duplicated descriptor is
truncated before use, written with offset-specific `pwrite`, synchronized
with `fsync` only after the exact expected byte count is present, and closed
by the child.

The child emits request intents only. The authoritative caller creates the
actual `RemoteTransfer` SIZE/RANGE request and supplies the exact receipt back
to the child before any parsed result is accepted. No method owns static-VC/MCS
framing, transport output, session authorization or TLS. RANGE bytes remain
borrowed from the complete CLIPRDR response PDU and are copied directly to the
native descriptor during the synchronous acceptance call; there is no
whole-file memory cache or second payload queue.

A changed clipboard generation, explicit cancellation, remote failure,
receipt/result mismatch or native I/O failure invalidates the partial
materialization and attempts to truncate it before closing the duplicate.
Completion is visible only after exact-size materialization, final truncate,
`fsync` and duplicate close. The current implementation is intentionally
unlocked/current-generation only and performs no Finder/file-promise or other
file-manager publication. Those handoff APIs may consume only a future
already-complete destination.

## R8 Windows file-handle destination boundary (2026-10-16)

The Windows file destination is a native materialization child of `RemoteTransfer`, not a second clipboard controller. It retains only one duplicated native destination handle, a copied remote leaf name for metadata, and sequential byte progress. The portable clipboard owner keeps all remote generation, descriptor, streamId, response and writer-receipt authority.

A caller supplies the destination HANDLE as a local capability. Production Win32 operations require a disk, non-directory handle and duplicate it with `DUPLICATE_SAME_ACCESS`; no remote name is opened or converted to a local path. Each existing FileContents receipt must exactly match the destination's current intent before a response may be consumed. Parsed range bytes are written synchronously and are not retained after return.

The production bridge truncates through `SetFileInformationByHandle(FileEndOfFileInfo)`, positions the duplicate for each sequential bounded range, writes with `WriteFile`, then requires exact final size plus `FlushFileBuffers` before marking completion. The original caller handle remains owned by its caller. Because duplicated Win32 handles alias the same underlying file object's position, the caller must avoid concurrent file-position-sensitive I/O until the destination reaches a terminal state.

Cancellation, generation replacement and errors best-effort truncate partial content before duplicate close. No shell data object, File Explorer handoff, directory-tree materializer, whole-file cache, CLIPRDR writer or session authorization is created here.

## R2 boundary for CLIENT_LICENSE_INFO HWID verification (2026-10-16)

A successful `verifyRdpClientLicenseInfoHardwareId` result proves only the
protocol-defined HWID integrity check performed with the already-derived
licensing keys. It is not an R2 admission capability and does not certify CAL
trust, product identity, expiry, native console ownership or desktop
authorization.

The protected first-client-licensing route therefore continues to accept only
the concrete move-only `LinuxConsoleAdmissionLease` in its authority slot,
with the licensing service credential separately supplied as protocol
continuity input. Parsed `RdpClientLicenseInfoView`, HWID verifier results,
key-exchange views and derived key material cannot substitute for that lease.
R2 adds no speculative server-decision API while R3 remains stopped at
`AwaitServerLicenseDecision`.

## R2 boundary for licensing service credentials (2026-10-16)

`RdpLicensingServiceCredential` is cryptographic continuity material, not an
R2 admission capability. Its validated certificate chain, matching private key
and non-secret certificate fingerprint may be consumed only after the concrete
`LinuxConsoleAdmissionLease` and exact R1 owner have passed the normal
protected-transition gate.

The existing protected Server License Request and first client licensing
methods retain the lease as the authority-bearing argument and the credential
as a separate protocol input. Compile-time contracts explicitly reject placing
the credential in the lease slot. R2 therefore does not infer native
authorization from licensing key possession, certificate validity, premaster
capability or derived key material.

## R2 boundary for licensing key material (2026-10-16)

R3's licensing parsers and `deriveRdpLicensingKeys` are protocol/cryptographic
helpers, not authorization capabilities. A structurally valid
`CLIENT_NEW_LICENSE_REQUEST`, borrowed ClientRandom, encrypted-premaster BLOB,
or successfully derived MAC/encryption key pair cannot enter protected R3
session progression.

The only positive first-client-licensing transition remains
`LinuxConsoleAdmissionBroker::authorizeR3ClientLicensingMessage`, which
requires the concrete move-only native admission lease, exact R1
`OwnedPreauthTcpConnection`, GSS acceptor and sole R3 lifecycle before the
packet reaches private licensing state. Key-exchange views, derived key
material, raw SSL pointers, principal strings, generation integers and nullable
lease substitutes are not alternative authority forms. Pure decoding and key
derivation therefore remain reusable below the authorization boundary without
weakening the R2 lease/provenance contract.

## R8 completed Linux file URI handoff through X11 (2026-10-16)

The Linux file-descriptor materializer and X11 clipboard adapter remain
subordinates of the one `RemoteTransfer` clipboard generation. The
materializer may bind a caller-provided local `file:///...` URI to the same
destination descriptor capability at `begin()`; it never creates that URI
from remote metadata. The URI is fixed-capacity and unavailable until the
materializer reaches `Complete` after exact byte count, final truncate,
`fsync`, and duplicate-fd close. Cancellation/failure clears it.

`X11ClipboardAdapter::publishCompletedFile` accepts the destination object
itself, not a caller Boolean or forgeable completion scalar. It requires
`Status::Complete`, matching nonzero current RDP generation and a retained
local URI before it can claim CLIPBOARD. The adapter copies the URI into its
own 4096-byte bounded publication state, so the destination object need not
outlive later X11 SelectionRequests.

For X11 file-manager interoperability the owner advertises
`text/uri-list`, `x-special/gnome-copied-files`, and
`application/x-kde-cutselection`. The standard URI-list payload is the one
URI plus CRLF. GNOME/Nautilus receives `copy\n<uri>` without a trailing
empty line; KDE's supplemental cut-selection marker is `0` for copy. These
are local presentation formats only: no FileContents request, MCS envelope,
TLS output or R2/R3 authorization occurs while servicing the X11 request.

File targets participate in the existing X11 ownership epoch and source model.
A local owner takeover clears the URI publication and records the yielded
remote generation, preventing timer/same-generation reclaim. A remote
generation change invalidates the previous URI even if the completed local
file still exists. PRIMARY remains isolated.

The XDG Desktop Portal FileTransfer contract is intentionally not approximated
here. A future Wayland integration must use its real session/D-Bus lifecycle
and `application/vnd.portal.filetransfer` key rather than treating an X11 URI
payload as portal authorization.

### R1 bounded client-licensing intake compatibility (2026-10-16)

R1's post-handshake application seam deliberately remains a bounded byte
stream, not an RDP PDU owner. The current R3 protected client-licensing route
requires a complete TPKT no larger than 8 KiB, while one R1 application read
accepts up to 18 KiB. Therefore the caller can retain one bounded R3 envelope
buffer and resubmit only its remaining suffix after each explicit R1 progress
receipt; no larger TLS buffer, hidden read loop or second framing controller is
required.

R1 does not infer licensing boundaries from TLS records. Multiple TLS records
may contribute to one caller-owned 8-KiB TPKT, and bytes following that span
remain in OpenSSL until a later explicit application read. R2 still owns fresh
native/GSS authorization and R3 still owns MCS membership, segmentation,
`SEC_LICENSE_PKT`, licensing order and session transitions.

## R1/R3 licensing transport compatibility boundary (2026-10-16)

R3's `RdpServerLicenseRequestWriteGate` owns licensing serialization and
monotonic delivery receipts; R1 owns only the accepted socket/BIO/SSL and exact
plaintext progress. Since a complete server licensing request is at most 2 KiB,
one pending R3 slice always fits within R1's existing 18 KiB application-write
boundary. Positive short R1 progress is fed back to R3 as the accepted-byte
count, while OpenSSL WANT produces a zero-byte receipt and preserves the same
logical pending suffix. Neither layer retries the other's state internally.

The composition does not change authority. R2 remains responsible for fresh
lease/R1-owner reauthorization before exposing a slice or consuming its
completion receipt, and R3 alone decides licensing phase progression. R1
never interprets licensing bytes and gains no licensing/session state.

## R2 first client licensing intake authority boundary (2026-10-16)

The first client licensing response is not a public R3 capability. Only
`LinuxConsoleAdmissionBroker::authorizeR3ClientLicensingMessage` may enter the
private R3 licensing intake, after the common protected-transition gate proves
the stored R3 admission/session generations still match the concrete move-only
lease and freshly revalidates exact R1 HYBRID/TLS/GSS identity, permission,
policy, NSS/logind fingerprint, freshness and native-change watch state.

A syntactically valid MCS SendDataRequest, `SEC_LICENSE_PKT` header or
licensing preamble is never authority by itself. The public
`McsSessionLifecycle::onDomainPdu` path remains denial-only before admission
and closes the owner even for licensing-shaped traffic. The R2 API accepts
neither raw `SSL *`, principal strings, generation scalars nor a nullable
lease substitute. Positive licensing parsing remains behind the exact
lease/R1-owner boundary and stops at the R3 server-decision phase; no Share,
graphics, input, clipboard or desktop authority follows from structural
licensing intake.

## R8 Linux file-descriptor destination boundary (2026-10-16)

`LinuxClipboardFileDestination` is a native materialization child of
`RemoteTransfer`, not another clipboard/FileContents controller.
`RemoteTransfer` still owns generation, metadata, stream IDs, pending replies
and wire receipts. The Linux child owns only one CLOEXEC-duplicated destination
fd and sequential local progress.

The caller supplies the destination capability; remote names never become local
paths. Only writable regular files without `O_APPEND` are accepted. The child
exposes request intents, binds the exact `FileContentsRequestReceipt`, and
writes each borrowed validated RANGE directly with positional I/O. It never
serializes or sends CLIPRDR, retains a whole-file buffer, or grants R2/R3/TLS
authority.

Unknown sizes use the existing SIZE result. RANGE requests remain bounded by
the existing 64-KiB limit. Exact completion requires final size, `fsync` and
closing the duplicate; cancellation, replacement, remote failure or native I/O
failure invalidates and truncates partial materialization where possible.
This first boundary is current-generation/unlocked and does not enable lock
capability, portals, URIs, directories or file-manager publication.

## R2/R3 licensing publication authorization boundary (2026-10-16)

The R3 `RdpServerLicenseRequestWriteGate` is a child of the one
`McsSessionLifecycle` for production session progression. It owns stable
serialized licensing bytes and monotonic delivery receipts, but those facts are
not authority. R2 is the only component that can expose a pending licensing
slice or consume its accepted-byte receipt: both operations require a fresh
`LinuxConsoleAdmissionBroker` revalidation of the exact move-only admission
lease and original R1 HYBRID/TLS/GSS/native-session owner.

The server-random, product and scope fields remain caller-provisioned R3
serialization inputs. R2 does not certify entropy or licensing provenance, R1
alone performs transport writes, and receipt completion advances only the
nested licensing lifecycle. A detached licensing writer, copied receipt
integers, a raw SSL pointer, principal string or Boolean cannot advance the
session. Any mismatch follows the established ordered teardown:
R3/licensing first, then R2/GSS, then the caller releases R1.

## R8 macOS pasteboard presentation boundary (2026-10-16)

`MacClipboardAdapter` is a native presentation child of the existing
`RemoteTransfer`; it is not another clipboard controller. The portable C++
state machine borrows one native operation table, retains no duplicate RDP
payload, and stays confined to the caller's serialized clipboard/native event
context. `RemoteTransfer` continues to own generation, verified UTF-8 text,
validated image bytes, request receipts and disconnect semantics.

macOS publication is ready-data-only. The adapter can copy verified UTF-8 text
and verified named PNG bytes into one native pasteboard item. DIB/DIBV5 bytes
are deliberately not advertised as PNG. The AppKit bridge uses
`clearContents` followed by `writeObjects:`; it does not initiate an RDP
request, wait for network data, create a clipboard channel or confer R2/R3
session authority.

The native ownership fence is the pasteboard change count recorded immediately
after publication. A changed count means another native owner won and causes
the current remote generation to be yielded. R8 then refuses to reclaim that
same generation. Conversely, when `RemoteTransfer` advances generations,
old immediate pasteboard bytes are cleared only if the recorded count still
matches. An unreadable ownership count fails closed without clearing, because
native ownership is ambiguous. Disconnect uses the same fence.

The Objective-C++ callback implementation is Apple-only and dormant until a
future authorized macOS desktop aggregate chooses to construct it. Ordinary
CTests use injected callbacks on every platform and never call
`NSPasteboard generalPasteboard`, read user clipboard data or mutate a host
pasteboard. Native file destinations and authenticated CLIPRDR payload
dispatch remain separate R8/R3 gates.

## R2 binding identity versus completed CredSSP admission (2026-10-16)

MS-CSSP public-key proof is not the final client credential step. R2 therefore
keeps two distinct internal facts. A fully delivered server binding reply may
expose the provider-derived principal through the existing diagnostic
`verifiedPrincipal*()` APIs. Native OS admission, however, requires a
separate private R2 final-credential authorization completion proof. No public
Boolean, principal string, TLS pointer or caller-supplied receipt can set that
proof. The current delegated-credential implementation is intentionally
deny-only, so the proof remains false and the native lease path is
unreachable.

The one production provider state machine remains
`GssapiSpnegoAcceptor::advanceOwnedCredSspHandshake()`. After it returns
`BindingVerified` for the fully written/released server public-key reply, a
later call may read exactly one final `authInfo` frame only through the same
R1 owner. The frame must retain actual HYBRID selection, the pinned TLS
certificate, CredSSP version, reader/writer identity and an idle reply writer.
A bounded exact `finalAuthInfoOnly()` request is handed to the existing GSS
credential denial path, which wipes provider plaintext and the source frame
and destroys the GSS context. The result `UnsupportedFinalCredentials` is
terminal policy denial; it never means authenticated desktop access. Invalid
field mixtures, oversized data, owner or certificate substitution and replay
remain `Rejected`.

R10 owns scheduling and maps that terminal result into aggregate revocation.
R1 remains the sole TLS application I/O owner; R2 does not call production
`SSL_read_ex`/`SSL_write_ex` independently. R3 sees no lease or session
capability from either binding completion or final-credential denial.

## R1 post-TLS HYBRID phase ownership (2026-10-16)

R1's transport state now records the actual protocol selected by its one X.224
exchange. A completed TLS handshake transitions an exact `PROTOCOL_HYBRID`
selection to `AwaitCredSsp`; an SSL-only `DiagnosticTlsOnly` selection keeps
the historical `AwaitMcsConnectInitial` diagnostic. The new state is not an
authentication result and has no API for callers to mark NLA complete.

While `AwaitCredSsp`, `OwnedPreauthTcpConnection::ioInterest()` reports the
same R1-owned nonblocking SSL application's required readiness, and
`onSocketReady()` only surfaces that readiness. It never dispatches
`onMcsIoReady()`. R2 synchronously supplies its current bounded buffer to
`readTlsApplicationData()` / `writeTlsApplicationData()`; R1 still retains no
caller buffer pointer and performs one OpenSSL application operation per call.
An explicit diagnostic MCS call in this phase closes the owner with zero MCS
plaintext consumed. R1 deliberately provides no authenticated-R2-to-R3 phase
transition; that integration remains R2/R3-owned.

The immutable negotiation provenance lookup accepts both established
post-TLS phases but revalidates the originally pinned selected-certificate
fingerprint before returning the offered/selected snapshot. Wrong owner/BIO,
unfinished or closed TLS, certificate substitution, cancellation and terminal
transport failure therefore cannot supply live provenance.

### R3 bounded Client Info structure and pre-licensing state (2026-10-16)

Client Info is consumed exactly once by the existing R3 session owner. The
outer route remains responsible for genuine R2 authorization, immutable R1
HYBRID/TLS provenance, joined assigned user/I/O/static channels, exact I/O
channel identity and complete MCS segmentation. The new inner parser treats
TS_INFO_PACKET contents as sensitive untrusted structure, not authentication.

The parser retains no credential/string view. It validates the fixed lengths,
Unicode/ANSI terminators and bounded optional TS_EXTENDED_INFO_PACKET chain
using only caller-owned bytes. Extended fields are structural metadata only:
client address/directory, time-zone bytes, performance/session fields,
Auto-Reconnect cookie length, reserved fields and Dynamic DST values do not
authorize an OS session, alter R2 identity or become policy inputs.

A successful protected acceptance changes only
`McsSessionPhase::AwaitChannelJoin` to
`McsSessionPhase::AwaitServerLicenseRequest`. The embedded
`RdpLicensingLifecycle` remains `NotStarted`; the transition does not imply
that a Server License Request was encoded, queued or delivered. The next
outbound licensing message must therefore use the existing R3/R2/R1 pattern:
one R3-owned bounded byte buffer, monotonic reply/slice receipts, fresh R2
authorization before each publication and completion, and R1 as the only TLS
writer. Only full accepted-byte completion may call
`RdpLicensingLifecycle::onServerLicenseRequestWritten()`.

### R2 real-provider owner-driven CredSSP acceptance test

The authentication boundary has an opt-in test for the transition between
Kerberos/CredSSP proof and native authorization. It reuses the real MIT GSS
initiator, the existing native loopback `OwnedPreauthTcpConnection`, R1
HYBRID negotiation and
`GssapiSpnegoAcceptor::advanceOwnedCredSspHandshake()`; no second TLS or
CredSSP state machine is introduced.

The same `TsRequestFrameReader` and `TsRequestTlsReplyWriter` stay pinned to
one R1 owner for the entire exchange. Token-only continuation messages may
advance only while the provider is continuing. The final provider token is
carried in the same TSRequest as `pubKeyAuth` and the client nonce.
`ServerBindingPrepared` alone exposes no owner-authorizing principal. Only
completion and release of the provider-generated server binding reply through
that exact owner may produce `BindingVerified`, after which
`verifiedPrincipalForOwnedConnection()` can expose the provider name. The
client independently GSS-unwraps that server proof. NSS/logind admission
remains a separate subsequent R2 authority boundary.

## R8 Windows clipboard presentation boundary (2026-10-16)

`WindowsClipboardAdapter` is a native presentation child of the existing
`RemoteTransfer`; it is not a second clipboard controller. It borrows one
caller-owned window token and a small native operation table, retains no RDP
payload copy, and is confined to the same serialized native/event-loop
context. `RemoteTransfer` owns generation, verified UTF-8 text, validated
PNG/DIB bytes, request correlation and disconnect semantics.

Windows publication is ready-data-only. The adapter may advertise
CF_UNICODETEXT, CF_DIB, CF_DIBV5, or the process-registered `PNG` format only
when the matching `RemoteTransfer` snapshot is already verified for the
current generation. Delayed rendering never waits on network I/O. A generation
change invalidates publication before native render can copy stale bytes.
`WM_DESTROYCLIPBOARD` yields the published generation so a local application
can take ownership without R8 immediately reclaiming it.

The Win32 bridge is quarantined behind injected callbacks. Its
`SetClipboardData` path uses `GMEM_MOVEABLE`, copies bounded verified bytes,
and transfers ownership to the OS only on success. `WM_RENDERFORMAT` does not
call `OpenClipboard`; `WM_RENDERALLFORMATS` opens and verifies owner identity
first. No constructor or callback grants R2/R3 admission, creates an RDP
channel, or performs CLIPRDR transmission.

### R2 owner-completed CredSSP binding proof

Native admission distinguishes a prepared server binding from a binding reply actually completed through R1. Only `advanceOwnedCredSspHandshake()` may set the private completion latch after exact owner-backed write completion and reply release. `verifiedPrincipalForOwnedConnection()` additionally requires the same live HYBRID owner, established TLS and selected-certificate continuity. Legacy framed helpers remain protocol-test surfaces and cannot satisfy native admission; rejection clears the latch before GSS/TLS teardown.

### R3 protected Enhanced-Security Client Info route (2026-10-16)

After complete Attach User and Channel Join confirmation, the single R3
owner may identify the first post-join client message without creating a
second dispatcher. For the current HYBRID/NLA path, Microsoft requires
Client Info after all requested Channel Join confirms when no Standard
Security Exchange PDU is used. The MCS SendDataRequest originates from
the assigned client UserId and targets the server-selected I/O channel.
Although R1 has already decrypted and integrity-checked the complete PDU
with the external security protocol, Client Info still begins with the
4-byte Basic Security Header and carries `SEC_INFO_PKT`.

`parseEnhancedSecurityClientInfoEnvelope` is a pure, allocation-free
envelope check. It accepts only SEC_INFO_PKT plus the sequence-number bits
which receivers must ignore and optional FLAGSHI_VALID; flagsHi itself is
opaque/ignored. Standard-Security `SEC_ENCRYPT`, secure-checksum,
licensing, exchange, transport, redirection, auto-detect and heartbeat
packet-kind flags cannot be reinterpreted as Client Info. At least the
fixed 18-byte TS_INFO prefix must be present, but its internal lengths,
strings and extraInfo are intentionally not validated by this increment.

The private `McsSessionLifecycle::routeVerifiedR2ClientInfoEnvelope`
requires immutable HYBRID provenance, all configured user/I/O/static MCS
joins completely delivered, joined membership, assigned initiator, exact
I/O channel and begin|end segmentation. It returns only a borrowed view
into the current caller-owned packet and does not mutate licensing phase.
A malformed, early, static-channel, partially segmented or wrong-owner
request closes R3. The Linux R2 broker reauthorizes the native lease,
GSS/TLS binding, generations and view permission immediately before the
route. The separately exposed CLIPRDR role now requires clipboard
permission. Neither route is a reusable authority token.

No TS_INFO credential is trusted, copied or logged here. No Client Info
state transition, Server License Request, Demand Active, Share Control,
MCS application dispatch, clipboard, graphics or input is activated.
The next R3 state change must accompany a bounded TS_INFO parser and
receipt-bound licensing output so that a valid outer header alone can
never skip connection-sequence validation.

### R2 owner-driven CredSSP/GSS progression ownership (2026-10-16)

R2 owns CredSSP/GSS semantics but never R1 application I/O.
`GssapiSpnegoAcceptor::advanceOwnedCredSspHandshake` binds one exact
`OwnedPreauthTcpConnection`, `TsRequestFrameReader`, and
`TsRequestTlsReplyWriter` for the handshake. Before any application read or
write it requires the immutable R1 negotiation snapshot to show both a client
HYBRID offer and exact server `PROTOCOL_HYBRID` selection. The established
SSL remains inspection-only to R2; all plaintext progress goes through R1's
bounded application-I/O methods.

Each progression call performs at most one R1 TLS application read or write.
It may synchronously parse DER, call the existing MIT GSS acceptor, verify the
existing certificate/nonce public-key binding, queue provider output, or
release a fully transmitted reply. Only a reply produced by that progression
may be emitted; externally prequeued canonical DER is not an authority input.
A genuine provider v6 rejection may still flush the existing canonical
terminal failure reply, after which the exchange is rejected.

The final `BindingVerified` state is deliberately narrower than admission:
it proves the provider-derived Kerberos principal and CredSSP public-key proof
on the exact R1 TLS transcript, after full server-binding delivery. R2 native
NSS/logind policy and its move-only lease remain independent, R3 remains the
sole session owner, and R10 remains the future serving event-loop/listener
owner. R10 already constructs its non-listening R1 connection with
`HybridNla` and performs owner-aware frame intake; that earlier aggregate
must now replace its complete-frame denial with this R2 progression and retain
the matching reply writer before any serving path can reach native admission.

### R8 bounded locked-generation clipboard stream ownership (2026-10-16)

`RemoteTransfer` remains the sole clipboard generation and remote file-stream
metadata owner. One fully delivered `CB_LOCK_CLIPDATA` snapshots only the
existing fixed-capacity 64-entry FILEDESCRIPTORW metadata for its exact
generation and assigns a monotonic nonzero `clipDataId`; no file payload is
retained. The live clipboard may advance independently, and locked
FileContents lookups use only the retained metadata/ID so an old file index
cannot borrow a new offer's descriptor.

Lock and Unlock are complete 12-byte CLIPRDR PDUs (8-byte header plus
4-byte `clipDataId`, `msgFlags=0`) wrapped by the existing R3-owned
static-VC/MCS framing path. Full cumulative writer acceptance makes an
operation locally delivered; it does not fabricate peer acknowledgement.
Completely unwritten frames can be cancelled. Partial/uncertain abandonment
poisons the owner until disconnect. Disconnect revokes retained metadata while
monotonic receipt and `clipDataId` identities continue, preventing stale
callback ABA/reuse.

A locked `CB_FILECONTENTS_REQUEST` carries the optional trailing
`clipDataId`, growing from a 24-byte to 28-byte payload and from a 32-byte
to 36-byte complete CLIPRDR PDU. Current requests remain the original 32-byte
form. Both preserve one-outstanding-stream ownership, SIZE/RANGE and huge-file
validation, stream-ID response correlation and partial-send poison behavior.

Temporary Directory is accepted only after capabilities and before the first
Format List; its fixed 520-byte UTF-16 field is validated for a nonempty,
well-formed NUL-terminated value and is never retained or dereferenced.
Raw peer/local lock offers are retained only for deterministic offline
prerequisite tests. `kSupportedGeneralFlags` remains `0x2e`.

R3's `authorizeR3JoinedClipboardChannel` gives a transient protected
R2-revalidated role observation, not clipboard payload dispatch, licensing or
Share authority. The portable R8 owner therefore does not depend on the
Linux-only security broker or treat a joined channel/Boolean as authorization.
A production caller must revalidate the authoritative R2/R3 session/channel
state before invoking R8 and before each R3 write. Until that protected
dispatcher and the complete Clipboard Initialization Sequence exist,
`CB_CAN_LOCK_CLIPDATA` stays disabled.

### R4 ACK-pending frame-ID reservation before stateful encode (2026-10-16)

The single `GfxPresentationLifecycle` exposes
`canReserveFrame(generation, frameId)` as a non-mutating, event-thread-only
read of its own mapped-surface state, full-wire send receipt status,
bounded serial and authoritative `GfxFrameAckWindow::canRecordFrame()`.
The `beginFrameDelivery()` and `prepareAvc420Picture()` reservation
sites use the identical gate. R4's `X264Avc420SegmentedFrameProducer`
calls it before stateful x264 encoding, and its borrowed BGRA path also
calls it before Y/UV conversion. A duplicate ID already delivered but
not ACKed is therefore an ordinary pre-encode denial, not a
post-encode packetizer rejection. Neither x264 reference history nor
outstanding ACK bookkeeping advances. The existing conservative encoder
rebuild remains necessary if a post-encode publication failure nevertheless
occurs. This is not R3 channel authorization, does not cache client ACKs
and introduces no new scheduler/transport authority.

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
output, output1, D3D11 device and immediate context, and duplication. Adapter
ownership follows the reference returned by each enumeration call, not the raw
COM interface address. Within one adapter scan, transferring the candidate into
`adapter_` moves that single owned reference to the owner; later outputs in
the same scan reuse it without another release. A later `adapterAt` result is
a distinct owned reference and must be released independently unless that
specific result is transferred, even if COM returns the same interface address.
The same rule applies to `outputAt`: a later output enumeration can return the
same interface address with another owned reference, so ambiguity cleanup
releases that later candidate separately from the already-retained selected
output. Ambiguous duplicate-output denial releases each output reference once
and leaves terminal `close()` to release the retained selected-adapter reference.
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
reader. It validates the fixed monitor-array count and canonical desktop layout
before any iteration/native wrapper construction, requires exactly one selected
output rectangle, and commits staging/capture subordinates transactionally only
after the cycle is open. A failed attach therefore leaves no partial
`captureCycle()` installed. It does not expose owned D3D interfaces or pixel
data to R4.
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
fail-closed construction without contacting a desktop. An additional
ephemeral-Xvfb lifecycle case drives a real MIT-SHM attach and GetImage,
then lets the production destructor retire the child while its borrowed XCB
owner remains alive. A fresh XShm child must attach and capture immediately on
that exact owner; the same case also exercises successful explicit disconnect
and repeated cancellation before a second replacement generation. Borrowed
`FramebufferView` spans are consumed before every retirement boundary.
Neither this target nor these tests authorize an OS session or deliver R4
frames.
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
unaffected. The headless native CTest uses a deliberately failed XCB
descriptor. A second production-linked lifecycle case runs only under
ephemeral Xvfb: it proves one real root Damage notification while the tracker
is alive, destroys the tracker while the borrowed owner stays healthy, then
proves later synthetic root rendering produces no stale notification and a
replacement Damage resource can register normally. Neither case authorizes or
observes a real desktop. R2 and R3 must grant independent access before any
protected capture or input; R4 alone schedules graphics transmission.

### R5 native XFixes cursor lifetime (Linux only)

The existing `X11CursorTracker` borrows a native `xcb_connection_t`
from the R5 XCB connection owner. Its `disconnect()` is an explicit,
repeatable cancellation barrier: while the borrowed owner remains healthy it
first clears this client's XFixes display-cursor notification mask, then drops
the borrowed pointer and cached pixel/mask views, resets pending image state
and warning flags, and prevents further XFixes requests or event handling.
The destructor reuses the same barrier, so native cursor notifications cannot
outlive ordinary tracker scope exit. The owner must cancel the cursor before
destroying its XCB connection, and no consumer may retain cursor spans beyond
cancellation or the next refresh.
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
The destructor reuses that barrier. Ephemeral-Xvfb lifecycle coverage verifies
that a real held key and button are both released on ordinary scope exit while
the same borrowed XCB owner remains healthy and reusable.
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
`consumeFrame`/`copyFrameTo`. Mapped-frame teardown preserves
native release failure separately from successful lease retirement that
synchronously revokes the enclosing cycle; invalid-consumer cleanup therefore
returns terminal `closed` rather than fabricating a release failure.
Independently owned output is published only if its generation is still current
on return.
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
source.

`retireWindowsNativeConsumersOnSessionChange` is the stateless R6
cross-component retirement boundary for an already-composed guard, capture
cycle and input controller. R10/R3 must marshal `WM_WTSSESSION_CHANGE` or
`SERVICE_CONTROL_SESSIONCHANGE` delivery onto the serialized R6 owner and
call this function. It first notifies the guard. A valid unrelated session
event returns without touching healthy consumers; a target event, malformed
session identifier, or already-invalid guard is terminal. Terminal retirement
then cancels input before capture. Because the guard is already closed, the
existing input controller discards held key/button state without synthesizing
cleanup into a potentially different desktop generation. The existing capture
cycle invalidates its borrowed view, unmaps D3D11 staging and releases the DXGI
frame exactly once. When the notification arrives inside a native capture
callback, logical closure is immediate while the cycle's established callback
guard defers physical unmap/release until the callback returns.

The coordinator owns nothing, starts no watcher and grants no admission. If
the supplied cycle is a child of `WindowsDxgiDuplicationOwner`, the caller
must still invoke that outer owner's terminal `close()` when retiring its
duplication/device/output resources; its existing child-before-parent cleanup
remains authoritative. Ordinary CTests execute synthetic callbacks only.

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
CoreGraphics callback registration is explicit and coverage-gated through the
process-scoped watch below; actual ScreenCaptureKit integration remains future
authorized R7 work.

### R7 Quartz reconfiguration revision fence (2026-10-16)

`NativeDisplayReconfigurationWatch` is an optional, noncopyable native
CoreGraphics callback registration for a future per-user authorized process.
It registers via `CGDisplayRegisterReconfigurationCallback` and unregisters
via the matching CoreGraphics API; ordinary CTests do neither. Callback
`userInfo` is always null and touches **only process-lifetime atomics**,
so an already executing callback during removal never dereferences a
retired session/geometry object. Only one Quartz registration is permitted
per process; registration failure releases its reservation, while removal
failure retains it to avoid duplicate observers. Active notification coverage
is tracked separately from that reservation and becomes unavailable before
removal is attempted, so ambiguous teardown cannot authorize a fresh native
geometry sample. The Apple-only lifecycle seam used by CTest injects only
register/remove functions; the real `startNative()` path still exclusively
binds those operations to CoreGraphics. Both start and stop retire previous
revision tokens. The signal
saturates to an invalid zero on uint64 exhaustion rather than reuse generations.

The existing `NativeDisplayGeometryRefresh` records a topology signal revision
around each synchronous two-read sample and geometry conversion. The injected
reader seam remains authorization-neutral for deterministic tests, but
`refreshNative()` now requires already-active Quartz notification coverage and
fails before CoreGraphics enumeration when coverage is absent. A notification
during sampling rejects publication; later begin/complete notifications cause
`usable`, pointer conversion, and virtual-canvas queries to fail until a fresh
covered refresh. The CoreGraphics callback NEVER
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

The native capture boundary is split intentionally. `MacScreenCaptureStream` and its state machine are C++23. `screen_capture_stream.mm` is the only ScreenCaptureKit Objective-C++ bridge and is built with ARC. Objective-C objects stay private to that translation unit. The bridge retains a shared C++ callback-state object, never a borrowed `MacScreenCaptureStream::this`; therefore queued delegate/output/completion callbacks can observe a retired state without dereferencing a destroyed owner. The stream owner releases its mutex around synchronous backend preflight/prepare/start/stop/close calls. An in-flight operation flag denies recursive owner operations; a callback requesting close or topology invalidation revokes state immediately but defers the one backend retirement until the synchronous call returns. The backend remains owned throughout its callback; native close is marked before invocation so close-callback reentry cannot submit a duplicate retirement. Stream destruction itself still requires the caller to have ended all synchronous methods and pinned the owner lifetime.

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

The native reader uses `CGSessionCopyCurrentDictionary` and documented Window Server session properties only; no username string is retained, no token is opened, no login session is switched, and no prompt is requested. The guard deliberately exposes no ScreenCaptureKit object and no Quartz event-posting callback. A future concrete macOS R2/R3 route must still provide the independently authorized target UID and invoke this guard immediately before the native child operation. Synchronous double-read alone cannot prove an unobserved user switch-away-and-back between separate calls; the process-scoped session-change revision below closes that offline lifecycle gap when native notification coverage is active, while owner macOS 27 still owns the real delivery gate.


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
callbacks carrying older epochs are ignored. A failed install is treated as
potentially partial: cleanup removal must succeed before the sole process
reservation is released. Removal failure retains that reservation so a second
observer authority cannot appear.

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


## R7 native capture capability quarantine (2026-10-16)

The ScreenCaptureKit implementation is deliberately compiled but no longer
constructible through the public R7 C++ surface. Until R2/R3 provides a
non-forgeable macOS per-user authorization capability, neither a validated
display binding nor a positive Screen Recording preflight may create a native
capture owner. `MacScreenCaptureStream` therefore exposes only the injected
backend constructor used by deterministic lifecycle tests; the native backend
factory is absent from headers and has no exported construction function.

This is symmetric with native input: the Quartz posting translator may compile,
but its callback factory is private. Future authorized composition must add one
single capability-consuming entry point rather than reviving independent
capture/input factories. Geometry, TCC state and the R7 session-watch revision
remain revocation/precondition facts, never authorization tokens.

## R10 owner-aware CredSSP non-listening frame boundary (2026-10-16; CI pending)

The existing Linux connection now creates its only R1 socket owner with the
R1 `HybridNla` negotiation policy, and exposes a bounded
`onCredSspIoReady()` step. The step requires genuine R1-selected HYBRID
provenance on established server TLS, then invokes the genuine R2
`TsRequestFrameReader::readOneTlsStep(OwnedPreauthTcpConnection&)`.
`Progress` advances on a later call; `NeedRead` and `NeedWrite` require
the matching owner readiness. Malformed/closed input is terminal. Since
the genuine R2 GSS/CredSSP token-processing and reply issuance contract
is not yet aggregate-callable, even complete DER is denied with ordered
R3 close -> R2 lease/GSS/broker -> R2 framing retirement -> R1 cancel.

The new centrally registered
`runtime.linux-connection-credssp-authorization-denials` test covers
no-TLS/no-HYBRID and stale-revoked-event denials using real accepted
loopback socket ownership. Positive owner-framing TLS/DER, reply-write,
native logind/Kerberos admission and real client validation are **BLOCKED**
on an R1/R2 fixture with genuinely selected HYBRID and the R2 provider
handoff; no synthetic authenticated session is claimed. Canonical owner
checkout build and CTest are **NOT RUN** (checkout absent in this
environment); hosted exact-SHA CI is **NOT RUN** at authoring.
No listener, system service, fabricated lease or alternate owner was
introduced. M2/M3 remain **OPEN**. Next R10 gate is verified genuine
HYBRID TLS/fragmented DER -> R2 GSS processing and owner-aware reply
receipt, followed by native console admission before listener work.


## R7 live macOS desktop-read quarantine (2026-10-16)

R7 distinguishes portable state construction from live desktop access. The
owned `MacCursorSnapshot` value and `makeMacCursorSnapshot` remain portable
and authorization-neutral. The AppKit sampler that obtains the current system
cursor, global pointer location and rendered shape is translation-unit-private;
it has no header declaration and no externally callable symbol. Its body is
kept compiled for Apple SDK/deprecation/rendering checks, but an R7 caller
cannot acquire live cursor data from geometry alone.

Together with the preceding ScreenCaptureKit factory quarantine and already
private Quartz input-posting factory, all native macOS desktop data/action
entry points now require future explicit composition work. TCC permission,
display generation, topology revision, session-watch revision and portable
cursor/capture objects remain revocation or data facts only. A future R2/R3
macOS capability must be the single authority-bearing route that can invoke
these native implementations and must still revalidate the R7 session guard.


## R7 macOS portable framebuffer boundary (2026-10-16)

The macOS adapter now ends platform-specific pixel ownership at
`FramebufferView`. The helper performs no allocation or color conversion;
it validates exact pitched storage and publishes a borrow-only view. During
the synchronous consumer callback, `LockedBgraPixelBuffer` keeps CoreVideo
retained/read-locked. The envelope contains only pixels, dimensions and stride,
not presentation generation, frame ID, damage, scheduler, codec, ACK, channel
or authorization state. Those remain R4/R3 responsibilities.


## R10 framed GSS handoff and provider-failure reply orchestration (2026-10-16; exact-SHA CI pending)

Starting shared `main` for this increment: `b30a0ba2fc1d5ba55fe3afb19a329ba9bde4c5c7`. Follow-up source review
supersedes the prior R10 note's blocker statement: R2 already exposes
`GssapiSpnegoAcceptor::acceptFramedNegoAndQueueReply`,
`processFinalFramedNegoAndQueueBindingReply` and
`processFramedProtectedBindingAndQueueReply`. R10 now consumes those genuine
R2 APIs instead of terminally rejecting every complete DER frame.

The single non-listening `LinuxRuntimeConnection::onCredSspIoReady()` remains
bounded to at most one R1 TLS application-I/O operation per call. R1 alone
executes application `SSL_read_ex`/`SSL_write_ex`; R2's
`TsRequestFrameReader` retains split DER bytes, the existing R2 GSS acceptor
synchronously consumes each complete borrowed frame, and
`TsRequestTlsReplyWriter::writeOneTlsStep(OwnedPreauthTcpConnection&)`
advances only provider-generated continuation/binding/failure replies.
`Progress` permits immediate bounded re-entry; `NeedRead`/`NeedWrite`
defer to socket readiness. No queued byte is counted as written until the
R1-owned write reports actual plaintext progress.

A genuine version-6 backend GSS rejection may queue R2's canonical
STATUS_LOGON_FAILURE. On that path R10 closes R3 and retires native
lease/broker/GSS authority first, closes the completed frame, retains only the
R2 failure writer plus exact R1 transport long enough to flush that reply, then
retires writer/reader before R1 SSL/BIO/socket cancellation. Explicit revoke
while a frame or reply is pending remains terminal and idempotent.

New centrally registered CTests are
`runtime.linux-connection-credssp-owner-framing` and
`runtime.linux-connection-credssp-revocation-order`. They use a real accepted
loopback socket, R1 `HybridNla` X.224 selection, the production R10 TLS
context, real OpenSSL handshake, a synthetic service keytab and a
syntactically initial but provider-rejected SPNEGO token. The framing test
splits one TSRequest across two encrypted client writes, proves exact retained
plaintext progress, exercises real R2 provider rejection, verifies the
canonical 15-byte v6 failure reply through the same R1 owner, and never creates
an admission lease. The revocation test covers cancellation with incomplete
DER and with a provider-generated reply still pending, plus repeated revoke and
late callbacks.

A dedicated aggregate short-write success-reply test is still **BLOCKED**:
ordinary deterministic CTest cannot manufacture a legitimate GSS continuation
output, and the 15-byte provider-failure reply is too small to guarantee a
portable short write/WANT. Existing lower-level
`transport.credssp-r1-owned-reply` and R2 reply-order tests retain that
transport coverage. Genuine positive Kerberos continuation, TLS public-key
binding, current NSS/logind admission and R3 progression remain **NOT RUN** in
ordinary CTest and require the explicit real-KDC/native acceptance gates.

Canonical owner-local `~/rdp-server/build` configure/build/full CTest is
**NOT RUN** in this connector environment because that checkout is unavailable.
Exact-final-SHA hosted CI is **PENDING** after publication; no platform PASS is
claimed here. No listener, service, daemon, fabricated principal, synthetic
lease or alternate TLS/GSS/R3 owner was added. M2/M3 remain **OPEN**. Next R10
gate after hosted compilation is the opt-in genuine Kerberos path through this
same aggregate to a provider-generated continuation/final binding reply, then
independent native console admission before any listener work.



## R10 delegates owned CredSSP progression to the R2 authority (2026-10-16; exact-SHA CI pending)

R2's validated owner-driven API landed concurrently with the first R10
provider/reply composition. R10 now removes its temporary stage-by-stage GSS
dispatch and calls exactly
`GssapiSpnegoAcceptor::advanceOwnedCredSspHandshake(connection, reader, writer)`.
This restores the intended authority split: R1 alone owns TLS application I/O,
R2 alone owns DER/GSS/binding/reply sequencing, and R10 owns only event-loop
status mapping plus aggregate lifetimes.

`LinuxCredSspStepStatus` adds `BindingVerified` to surface R2's explicit
boundary without converting it into authorization. Native lease issuance still
requires the existing R2 broker, the exact R1 HYBRID/TLS owner and
`SpnegoStage::ServerBindingPrepared`; no caller Boolean or raw TLS pointer can
substitute. A provider-generated terminal v6 failure remains entirely inside
R2 until its reply is actually written/released; only then does R10 perform
ordered R3 -> R2 -> framer/writer -> R1 teardown. Explicit cancellation while
that reply is pending performs the same terminal ordering immediately.

The existing R10 loopback tests continue to cover split DER retention,
provider rejection/failure reply delivery, pending-frame cancellation,
pending-reply cancellation, stale callbacks and absence of any admission
lease. Their pre-flush assertions now distinguish failed GSS from aggregate
teardown: native admission/R3 are unreachable, while R2 retains only the
terminal reply state until it is flushed or the caller revokes.

Validation immediately before this authority-consolidation commit: correction
SHA `06e4793eb7a78ea86bfb7f072b8642f1ec90d1d7`, Actions
`38899285708`, Ubuntu/GCC full Debug **395/395 PASS** and Release
**395/395 PASS**, including
`runtime.linux-connection-credssp-owner-framing`,
`runtime.linux-connection-credssp-revocation-order` and
`runtime.linux-connection-credssp-authorization-denials`; R9 sanitizer job
**PASS** and documentation policy **PASS**. macOS Debug compiled but failed
only the unrelated R1
`transport.tcp-native-listener-role-and-mode-denials`; macOS Release and its
package stages were therefore **NOT RUN**. Windows was still running when this
follow-up was authored. Canonical owner-local `~/rdp-server/build` remains
**NOT RUN** in this connector environment.

No listener/service, synthetic positive GSS result, fabricated native lease or
second TLS/session owner is introduced. M2/M3 remain **OPEN**. The next R10
acceptance gate is an opt-in real client Kerberos exchange reaching R2
`BindingVerified`, followed independently by current NSS/logind admission
through the existing broker; delegated TSCredentials remain denial-only until
R2 defines an audited positive credential contract.


## R10 CredSSP owner-framing scheduling-independent oracle (2026-10-16; CI pending)

Starting reconciled shared `main`: `487e26c49b4709c031c6ef71342c5b3f202d5fb4`. Repeated hosted Linux runs
exposed a test-only timing assumption in
`runtime.linux-connection-credssp-owner-framing`: the fixture asserted zero
reply bytes throughout its second request-drain loop. R2's production
`advanceOwnedCredSspHandshake` contract instead permits the next bounded
callback to advance an already-pending provider reply; the security invariant
is that one callback performs at most one R1 application read **or** write,
and no reply bytes are accepted before the entire DER request has been
consumed.

The test now records request and reply progress continuously, asserts read/write
mutual exclusion per step, bounds both counters, requires every nonzero reply
write to occur only after the exact complete request and genuine provider
failure, and still requires the exact canonical 15-byte v6 failure reply,
terminal aggregate revocation and zero admission lease. Production R1/R2/R3
code is unchanged; provenance, GSS failure, reply contents, teardown and
authority checks remain intact.

Canonical owner-local `~/rdp-server/build` configure/build/full CTest is
**NOT RUN** because the checkout is unavailable in this connector environment.
Exact-publication-SHA hosted Linux Debug/Release, R9 sanitizer,
documentation-policy and cross-platform matrix are required before PASS is
claimed. No listener, service, fabricated GSS success or native lease is added.
M2/M3 remain **OPEN**.


## R10 CredSSP readiness progress accounting correction (2026-10-16; CI pending)

Starting reconciled shared `main`: `3bcdb4ad2911de916aae465305f58b9f8c770918`. Exact R10 workflow
`38902051095` at `255b532b85456dff228912541bb25dfc3a73eea3`
compiled the production aggregate and exposed the accounting defect behind the
prior timing-sensitive oracle: R2 may return `NeedWrite` in the same bounded
call that consumed final TLS plaintext and queued its genuine provider failure,
but R10 mapped `NeedRead` and `NeedWrite` to zero byte counts. That discarded
progress already accepted by the exact R1 owner.

`LinuxRuntimeConnection::onCredSspIoReady()` now preserves R2's
`plaintextBytesRead` and `plaintextBytesWritten` for readiness statuses as
well as Progress/terminal statuses. R10 still performs no TLS application I/O
itself and readiness/framing remains non-authorizing. The existing owner-framing
test retains exact request/reply accounting and the canonical 15-byte v6
failure check. New dedicated CTest
`runtime.linux-connection-credssp-progress-accounting` requires the
provider-failure `NeedWrite` transition to report the final accepted R1 read
progress while GSS is failed, no native lease exists, R3 remains pre-admission,
and explicit revocation is terminal.

Workflow `38902051095` also contained concurrent R8 clipboard failures; those
are not attributed to this R10 defect. Canonical owner-local
`~/rdp-server/build` configure/build/full CTest is **NOT RUN** because the
checkout is unavailable in this connector environment. Exact-publication-SHA
hosted Linux Debug/Release, R9 sanitizer, documentation-policy and
cross-platform regression evidence are required before PASS is claimed. No
listener, service, synthetic GSS success or fabricated native lease is added.
M2/M3 remain **OPEN**.


## R4 fixed-CFR x264 PTS ownership contract (2026-10-16)

R4's pinned x264 revision remains configured for fixed 60 fps CFR
(`b_vfr_input=0`, fps 60/1, effective timebase 1/60), one encoder thread,
zero B frames, zero lookahead and one reference frame. The vendored x264
header states that timestamps participate in rate control only for VFR input;
the encoder's non-strict-monotonic warning and timestamp-derived frame
durations are likewise guarded by `b_vfr_input`. With B frames disabled,
the input PTS is copied to reordered PTS/output PTS without a reorder delay.

Accordingly, R4 does **not** create a second timestamp scheduler or monotonic
PTS gate. `X264Nv12PictureView::pts` and `X264BgraFrameRequest::pts` are
opaque signed 64-bit caller labels forwarded through the synchronous encoder.
Duplicate, decreasing, skipped and `INT64_MIN`/`INT64_MAX` values are
valid under the current configuration. Presentation generation, frame ID,
ACK/backpressure, wire publication and full-send ownership remain authoritative
and independent. No PTS baseline, sentinel or incrementing counter exists, so
ordinary preflight/backpressure denial cannot advance timestamp state and
generation abort/reset has no separate timestamp history to retire.

This contract must be re-audited before enabling x264 VFR input, B-frame
reordering/lookahead, timestamp-derived rate control, or any transport/scheduler
consumer of encoded PTS. Those changes would be the point at which a
generation-bound ordering policy could become a correctness requirement.


## R10 CredSSP progress-accounting hosted receipt + sanitizer selection (2026-10-16; sanitizer-extension CI pending)

Starting reconciled shared `main`: `914b2c5b0c97476f37243a59c7ceee2f6752e22d`. Exact R10 implementation
`0a07d096626cad58576d14de72ff52c6d333439c`, Actions `38903827001`,
completed **SUCCESS**. Ubuntu/GCC full CTest passed **402/402 Debug** and
**402/402 Release**; the four R10 aggregate cases
`runtime.linux-connection-credssp-owner-framing`,
`runtime.linux-connection-credssp-progress-accounting`,
`runtime.linux-connection-credssp-revocation-order`, and
`runtime.linux-connection-credssp-authorization-denials` all passed in both
configurations. macOS/Clang passed **343/343 Debug + Release**. Windows/MSVC
passed focused native preflight **39/39 Debug + Release** and full CTest
**368/368 Debug + Release**. Installed SDK consumer/package validation and
documentation policy passed. The existing R9 sanitizer job also passed its
credential-free groups: **41/41 clipboard**, **25/25 bounded R1/R3
transport/security**, **23/23 native R2/R3 GSS**, **16/16 R5 X11**, and
**1/1 bounded fuzzer**.

That exact sanitizer job did not build or execute
`test_runtime_linux_security`, so it is regression evidence but not direct
sanitizer coverage for the corrected R10 status mapping. The shared sanitizer
job is therefore extended additively: it now builds the existing
`test_runtime_linux_security` target and runs exactly the four R10 CredSSP
aggregate CTests under ASan/UBSan, with the existing MIT-krb5 provider leak
suppression scoped to that Linux GSS-backed step. No existing R9 selection is
removed or renamed, and no parallel sanitizer harness/build root is created.

Canonical owner-local `~/rdp-server/build`, owner Linux/X11, Windows MSYS2
CLANG64/Clang23, macOS 27, the opt-in R2
`security.gssapi-real-kerberos-owned-binding`, positive NSS/logind admission
and Microsoft-client acceptance remain **NOT RUN** here. R2 exact-SHA hosted
validation confirms the new real-Kerberos body compiles but the positive case
itself remains disabled without explicit credentials. R10 still requires an
opt-in aggregate-level real Kerberos run reaching `BindingVerified` before
positive native admission or listener work. No listener/service, fabricated
principal, synthetic lease or authentication bypass is added. M2/M3 remain
**OPEN**.


## R10 sanitizer workflow syntax correction (2026-10-16; exact-SHA CI pending)

Sanitizer-selection commit `75631de64ac8375d02e2b7a29d7d656402088825`,
Actions `38905072552`, is **FAIL** before job creation: the generated workflow
text truncated the new R10 `ctest -R` command and swallowed the following R5
step header, so GitHub created **0 jobs**. No build or test result can be
inferred from that run.

The correction restores the complete R10 regex and the unchanged R5 step name,
condition, environment and command. The intended sanitizer scope remains
additive only: compile `test_runtime_linux_security` and execute the four
existing R10 CredSSP aggregate CTests under ASan/UBSan while retaining every
pre-existing R9 clipboard, R1/R3, native R2/R3, X11 and fuzzer selection.
Production source, CTest semantics, admission authority and listener state are
unchanged. Exact correction-SHA CI is required before sanitizer PASS is claimed.


## R10 CredSSP progress-accounting sanitizer validation receipt (2026-10-16)

Production fix `0a07d096626cad58576d14de72ff52c6d333439c`,
Actions `38903827001`, remains the exact R10 behavior validation: Ubuntu/GCC
full CTest **402/402 PASS Debug + Release**, macOS/Clang **343/343 PASS
Debug + Release**, Windows/MSVC **368/368 PASS Debug + Release** with focused
native preflight **39/39 PASS** in both configurations, documentation policy
and installed SDK consumer/package validation all **PASS**. The dedicated
`runtime.linux-connection-credssp-progress-accounting` case and the three
neighboring R10 CredSSP aggregate cases pass in both Linux configurations.

The attempted sanitizer-extension commits
`75631de64ac8375d02e2b7a29d7d656402088825` (Actions `38905072552`) and
`3b7a32e120a6e4e537b07701d1ce74ed41db3fa9` (Actions `38905403688`)
created **zero jobs** due malformed generated workflow text. They are retained
as historical FAIL receipts and provide no test evidence.

Shared workflow repair `0abf1e5de12517817a70973be3740ac56ff1d522`,
Actions `38906102171`, completed **SUCCESS** and directly closes the R10
sanitizer gap. Its Clang ASan/UBSan job builds
`test_runtime_linux_security` and runs the four aggregate cases:
`runtime.linux-connection-credssp-owner-framing`,
`runtime.linux-connection-credssp-progress-accounting`,
`runtime.linux-connection-credssp-revocation-order`, and
`runtime.linux-connection-credssp-authorization-denials`: **4/4 PASS**.
The same sanitizer job also passes **41/41 clipboard**, **18/18 R4 x264**,
**25/25 bounded R1/R3 transport/security**, **23/23 native R2/R3 GSS**,
**16/16 R5 X11**, and **1/1 bounded fuzzer**. Normal hosted validation on the
same repair SHA is Ubuntu/GCC **407/407 Debug + Release**, macOS/Clang
**349/349 Debug + Release**, and Windows/MSVC **373/373 Debug + Release** plus
**39/39 focused native preflight** in both configurations; downstream SDK
consumer/package and documentation policy also pass.

This validates the R10 owned CredSSP framing/reply, progress accounting,
denial and revocation paths under normal hosted Debug/Release and direct
ASan/UBSan coverage. It does **not** establish positive Kerberos, NSS/logind
admission, an authenticated R3 session or Microsoft-client interoperability.
R2's opt-in `security.gssapi-real-kerberos-owned-binding` compiles in hosted
CI but remains **NOT RUN** without explicit credentials. Canonical owner
`~/rdp-server/build`, owner Linux/X11, Windows MSYS2 CLANG64/Clang23 and
macOS 27 remain **NOT RUN**. No listener or service is enabled; M2/M3 remain
**OPEN**. The next R10 gate is an opt-in real-Kerberos exchange through
`LinuxRuntimeConnection` reaching R2 `BindingVerified`, followed separately
by current NSS/logind native admission on the same exact R1 owner.


## R5 XI2 pointer observation under the single XCB owner (2026-10-16)

The existing `X11PointerPositionTracker` is a subordinate observer of
`X11DesktopResources`, never a second display owner. When Linux
`xcb-xinput` development support is present, the desktop aggregate links the
noninstalled XI2 tracker target and routes each borrowed XCB event in the fixed
order **XFixes cursor -> XDamage -> XI2 pointer -> optional external sink**.
No event pointer is retained and the existing display owner remains responsible
for the bounded poll budget, readiness and RandR stop/rebuild boundary.

XI2 is deliberately feature-local. Missing extension/version/subscription
support disables only synchronous pointer-position observation; capture,
damage, cursor image and authorized XTEST children retain their existing
lifetime. A transport error on the shared XCB connection is fatal to the whole
aggregate. The installed portable SDK contains no XInput2 headers or link
dependency.

The pointer observer owns one current-generation pending coordinate. Native
16.16 fixed-point root coordinates are converted to integer pixels and clamped
to the current source geometry. Queries are read-only; R4 must explicitly
acknowledge whether a position was actually forwarded. The tracker's existing
last-forwarded/remote/local-authority state suppresses XTEST echo loops without
permitting R5 to parse RDP input. Only the already authenticated
`X11AuthorizedInputRoute` can reach `X11DesktopResources::handleAuthorizedInput`;
a matching local-authority motion is consumed there, while a distinct remote
move transfers authority and proceeds through the existing clamping XTEST
controller.

The tracker is geometry-bound because its clipping and pending position belong
to one desktop generation. RandR rebuild disconnects it before replacement;
disconnect clears the XI2 mask while the borrowed connection is live,
invalidates the XCB/root identity and clears every pending/echo field. The
tracker destructor invokes the same idempotent barrier, so ordinary scope exit
also retires native observation before the borrowed owner is released. The
connection-bound XFixes cursor child remains unchanged.

## R3 Server License Request serializer and receipt fence (2026-10-16; hosted CI pending)

**Reconciled shared-main parent:** `27ba58477a0c730c32e2bd65d2c2f66deee8572c`.

The next R3 boundary is implemented without fabricating licensing authority.
The portable licensing layer now has one bounded, allocation-free
Enhanced-Security `SERVER_LICENSE_REQUEST` serializer. It writes the
MS-RDPELE preamble, caller-provided 32-byte server random, PRODUCT_INFO, the
required RSA key-exchange BLOB, the empty certificate BLOB permitted when
Enhanced RDP Security already protects the connection, and exactly one
caller-provisioned scope. Company/product strings are complete terminated
UTF-16LE, scope is complete terminated ANSI, all size arithmetic is bounded by
a 2048-byte local cap, and validation failure leaves output untouched.

Entropy/provisioning remains outside this structural serializer. It cannot
prove CSPRNG provenance and does not invent a company, product ID, issuer
scope, certificate, or license authority. The sole `McsSessionLifecycle`
therefore still stops at `AwaitServerLicenseRequest`; no production session
API queues licensing bytes until legitimate random/product/scope material has
an authoritative owner.

The lifecycle shortcut is closed. `onServerLicenseRequestWritten()` is
private and callable only by `RdpServerLicenseRequestWriteGate`. That gate
owns stable contiguous bytes, nonzero monotonic reply/write-slice receipts,
exact accepted-byte accounting, zero-byte backpressure stability,
partial-write slice rollover, and full-delivery-only lifecycle advancement.
Stale/duplicate receipts, overwrite, over-report, or abandonment close the
licensing owner rather than advancing it.

Dedicated production-linked central-registry CTests:
`transport.licensing-server-request-wire`,
`transport.licensing-server-request-write-receipts`, and
`transport.licensing-server-request-write-denials`. Existing licensing
state/length/ordering tests now enter the client-response phase only by fully
delivering the production serializer through this receipt gate.

Canonical owner-local `~/rdp-server/build/` configure/build/full CTest is
**NOT RUN** because this connector environment exposes no owner checkout; no
alternate build root was created. Exact-publication-SHA hosted Linux/GCC,
macOS/Clang, Windows/MSVC Debug/Release, R9 sanitizers, documentation policy,
and downstream SDK/package evidence are pending. Genuine CSPRNG/product/scope
provisioning into the R2-authorized R3 owner, client-license cryptography,
Share activation, and Microsoft-client acceptance remain **OPEN / NOT RUN**.
**M2/M3 remain OPEN / NOT ACCEPTED.**

## R6 DXGI duplication-owner callback boundary (2026-10-16)

`WindowsDxgiDuplicationOwner` remains the sole outer owner for its factory,
selected adapter/output, D3D11 device/context, output interface and duplication
reference. Native callbacks execute synchronously on the documented serialized
capture-owner thread; they may request terminal `close()`, but cannot start a
second teardown while `open()` or resource release is active.

`closed_` is the terminal revocation bit and invalidates readiness/device epoch
immediately. During `open()`, `operationInProgress_` defers physical teardown
until the callback returns; the caller then stops before issuing another native
operation and releases every acquired local/owned reference. During final
teardown, `teardownInProgress_` makes nested `close()` idempotent while the
outer pass continues through every remaining resource. Each owned slot is
cleared before its external release callback, preventing that callback from
seeing the same owner reference twice.

Parent teardown order remains: terminal owner/generation invalidation, capture
cycle cancellation/destruction, native staging context destruction, duplication,
output1, D3D11 context/device, selected output/adapter, then factory. Temporary
enumeration references remain local and distinct from the retained selected
adapter/output contract; a same-address selected-adapter alias is not released
as a second local reference. Failure callbacks that publish a pointer still
transfer one owned reference and are cleaned exactly once. No callback result
can revive a terminal owner, and device-epoch allocation saturates permanently
at exhaustion rather than wrapping.

## R10 opt-in real Kerberos aggregate binding gate (2026-10-16; execution pending)

Starting reconciled shared `main`: `172564bbae431f09e118652d4124d4727a8c1d01`. The existing R2 opt-in
Kerberos fixture already proves genuine MIT GSS/CredSSP binding through the R1
owner. R10 now reuses that client/provider machinery in a dedicated
`runtime.linux-connection-real-kerberos-binding` CTest whose server side is
the production `LinuxRuntimeConnection` aggregate.

The test body is compiled with the ordinary Linux GSS test executable but the
CTest is registered only when `RDP_SERVER_TEST_REAL_KERBEROS=ON`. It requires
the existing explicit `RDP_TEST_KRB5_SERVICE=TERMSRV/...@REALM`,
`RDP_TEST_KRB5_KEYTAB=FILE:/...` and `RDP_TEST_KRB5_CCACHE=FILE:/...`
inputs. For CredSSP versions 5 and 6 it drives the aggregate's R1
`HybridNla` X.224 selection, production R10 TLS context, real MIT SPNEGO
rounds, final combined GSS token plus protected client public-key binding, and
the R2 provider-generated protected server binding reply. Success is only the
aggregate's explicit `BindingVerified` transport/GSS receipt.

The case additionally requires that no native admission lease exists and R3
remains at `AwaitVerifiedR2Admission` before explicit ordered revocation.
It does not send final delegated credentials, sample NSS/logind, authorize a
desktop, invoke MCS progression, bind a production listener or install a
service. Current R2 policy still denies final `authInfo`; therefore
`BindingVerified` is deliberately not native admission authority.

Canonical owner-local build and the opt-in Kerberos CTest are **NOT RUN** in
this connector environment because `~/rdp-server` and explicit KDC
credentials are unavailable. Ordinary exact-SHA hosted CI can compile the test
body and provide regression evidence, but it cannot promote this opt-in case
to PASS. M2/M3 remain **OPEN**. The next R10 gate after an owner real-Kerberos
PASS is to drive the existing R2 final-`authInfo`
`UnsupportedFinalCredentials` denial through this same aggregate, then keep
native NSS/logind admission blocked until R2 defines a reviewed positive final
credential authorization contract.

## R10 real-Kerberos aggregate final-authInfo denial gate (2026-10-16; execution pending)

Starting reconciled shared `main`: `6b45368b57ec0213212f3e3f42ff9a1ec5ee3d10`. The newly added R10
real-Kerberos aggregate fixture is extended with a second dedicated opt-in CTest,
`runtime.linux-connection-real-kerberos-authinfo-denial`. It reuses the same
production `LinuxRuntimeConnection`, R1 HYBRID/TLS owner, R2 MIT-GSS
handshake and verified public-key binding, then GSS-wraps one bounded valid
TSPasswordCreds envelope and submits it as the final CredSSP `authInfo`.

The expected result is the existing R2 policy outcome
`UnsupportedFinalCredentials`. R10 must preserve the exact plaintext-read
receipt, emit no reply bytes, surface that distinct terminal denial, close R3,
revoke R2 state/lease authority, retire the framing objects, then cancel R1.
The case also proves the aggregate cannot resume on a late CredSSP callback.
It never turns decrypted credentials into a native identity, never creates a
lease, never invokes MCS progression and never enables a listener/service.

Both real-Kerberos aggregate cases compile in the ordinary Linux GSS test
binary, but are registered only with
`RDP_SERVER_TEST_REAL_KERBEROS=ON` and explicit external service keytab and
client cache. Credentialed execution is **NOT RUN** in this connector
environment. Exact-SHA ordinary hosted CI remains regression/compile evidence
only, not a real-Kerberos PASS. M2/M3 remain **OPEN**. With final credentials
still policy-denied by R2, positive NSS/logind admission is correctly
**BLOCKED** rather than synthesized; the next R10 production gate depends on a
reviewed R2 positive final-credential authorization contract.


## R4 RDPGFX frame-ID domain (2026-10-16)

RDPGFX START_FRAME and END_FRAME carry a 32-bit unsigned `frameId`.
R4 treats the full wire domain, including zero, as valid. A frame ID is not an
object-validity sentinel: `GfxFrameDeliveryReceipt::serial`, presentation
generation/stage and the ACK window provide delivery identity/liveness.
Pending duplicate IDs remain rejected by the one authoritative ACK window
before x264 runs; accepting zero therefore does not weaken correlation or
create a second frame scheduler. The same ID is serialized unchanged into
START_FRAME and END_FRAME and is matched unchanged by FRAME_ACKNOWLEDGE.

## R10 real-Kerberos aggregate gate hosted validation receipt (2026-10-16)

Validated implementation SHA
`d57f3df6d8543e327165adf0f547aca5e54ebe74`, GitHub Actions
`38912836625`, completed **SUCCESS**. The descendant contains both R10 opt-in
real-provider aggregate cases:
`runtime.linux-connection-real-kerberos-binding` and
`runtime.linux-connection-real-kerberos-authinfo-denial`.

Hosted credential-free regression evidence at that exact SHA is
Ubuntu/GCC **430/430 Debug PASS** and **430/430 Release PASS**,
macOS/Clang **362/362 Debug PASS** and **362/362 Release PASS**, and
Windows/MSVC native preflight **44/44 Debug PASS** plus **44/44 Release PASS**
with full **391/391 Debug PASS** and **391/391 Release PASS**. Linux, macOS
and Windows installed-SDK consumer checks and package generation passed.
Documentation policy passed. The R9 Clang ASan/UBSan job passed all configured
groups: **46/46 clipboard**, **18/18 R4 x264**, **33/33 bounded R1/R3
transport/security**, **25/25 native R2/R3 GSS**, **4/4 R10 Linux runtime
CredSSP**, **24/24 R5 X11**, and **1/1 bounded fuzzer**. The sanitizer build
compiled the R10 real-Kerberos aggregate test body through the production-linked
Linux GSS/runtime target.

The two new `opt-in-kerberos` CTests themselves are **NOT RUN** in hosted CI:
the workflow deliberately configures
`RDP_SERVER_TEST_REAL_KERBEROS=OFF` and has no external service keytab/client
ticket cache. Therefore no real Kerberos `BindingVerified` or final
`UnsupportedFinalCredentials` runtime result is claimed yet. Owner canonical
`~/rdp-server/build`, Linux/X11, Windows MSYS2 CLANG64/Clang23, macOS 27,
real KDC/keytab/cache execution, NSS/logind positive admission and Microsoft
RDP client acceptance remain **NOT RUN**.

The implementation does not enable a listener or service and never fabricates
a principal, final credential authorization, native lease or R3 admission.
Current R2 intentionally treats final CredSSP `authInfo` as terminal
`UnsupportedFinalCredentials`, so positive native NSS/logind admission is
**BLOCKED on R2** until a reviewed positive final-credential authorization
contract exists. M2/M3 remain **OPEN**. R10's next safe production integration
gate is that R2 contract; after it lands, R10 must require the genuine
owner-completed credential proof and independent current native-session
evidence before any listener work.

## R3 CSPRNG licensing identity and session completion phase (2026-10-16; hosted CI pending)

**Reconciled shared-main parent:** `2bea27c667816b3e876fc392bd6b94820634bea1`.

R2's immediately preceding protected-publication increment embedded the existing
Server License Request receipt gate in the sole R3 session and required fresh
lease/R1-owner authorization before each exposed slice and accepted-byte
receipt. R3 now closes the remaining serialization-provenance gap without
duplicating that R2 boundary.

`RdpServerLicenseIdentity` is a one-shot, noncopyable, fixed-storage
product/scope snapshot. It owns bounded nonempty terminated UTF-16LE
company/product strings and one bounded terminated ANSI issuer scope, so
configuration buffers cannot be changed beneath active sessions. It is
protocol provisioning only and conveys no authentication or licensing
authority.

The live `RdpServerLicenseRequestWriteGate` no longer accepts raw
`RdpServerLicenseRequestFields`. On first queue it generates the mandatory
32-byte ServerRandom internally with OpenSSL `RAND_priv_bytes`, combines it
with the immutable identity, and preserves the resulting request bytes across
backpressure and partial-write receipts. The raw fields serializer remains an
offline deterministic wire-codec API for specification-derived tests; it is no
longer a production session writer input.

R3 and the concrete R2 broker now accept only the immutable identity at request
preparation. Full accepted-byte completion advances the nested licensing
lifecycle to `AwaitClientLicenseResponse` and the owning
`McsSessionLifecycle` to the matching explicit phase. Partial or zero-byte
progress cannot change the phase, and duplicate/stale completion remains
terminal. The already-landed R2 contract continues to require the move-only
lease and exact R1 HYBRID/TLS owner; its sanitizer-selected test now also proves
raw request fields cannot substitute for the identity API.

New ordinary production-linked CTests are
`transport.licensing-server-identity-configuration` and
`transport.licensing-server-request-generated-random`. Existing
`security.gssapi-r3-server-license-request-write-contract` is strengthened
in place and remains selected by the R9 native-GSS sanitizer group. No R10
listener/config-file ownership, second TLS writer, scheduler, positive native
admission or synthetic license result is added.

Canonical owner-local `~/rdp-server/build/` configure/build/full CTest is
**NOT RUN** in this connector environment. Exact-publication-SHA Linux/GCC,
macOS/Clang, Windows/MSVC Debug/Release, R9 sanitizer, documentation-policy and
SDK/package evidence are pending. R10 still has to provision the immutable
identity from real service configuration and drive the existing R1 application
writer after genuine positive admission. Microsoft-client licensing, client
license cryptography, Share activation and desktop acceptance remain
**NOT RUN/OPEN**.

**Next R3:** after full request delivery, add protected global-I/O-channel
intake for exactly one `CLIENT_LICENSE_INFO` or
`CLIENT_NEW_LICENSE_REQUEST` through the existing bounded licensing
lifecycle, preserving security-header/segmentation ordering and stopping at
`AwaitServerDecision` until real cryptographic licensing logic exists.
**M2/M3 remain OPEN / NOT ACCEPTED.**

## R3 CSPRNG licensing identity exact-SHA validation receipt (2026-10-16)

**Implementation:** `e9042e3d3e2910f3d34fc3a75f60ae9d1261df45`.
**Actions:** `38914000119` — **SUCCESS**.

Ubuntu/GCC full CTest is **438/438 PASS Debug** and **438/438 PASS
Release**; macOS/Clang is **366/366 PASS Debug** and **366/366 PASS
Release**; Windows/MSVC is **395/395 PASS Debug** and **395/395 PASS
Release**, with the focused Windows native preflight **44/44 PASS** in both
configurations. The new
`transport.licensing-server-identity-configuration` and
`transport.licensing-server-request-generated-random` cases pass in all six
hosted Debug/Release configurations. The strengthened
`security.gssapi-r3-server-license-request-write-contract` also passes in
Linux Debug/Release.

R9 Clang ASan/UBSan is **PASS**: clipboard **49/49**, R4 x264/BGRA **19/19**,
bounded R1/R3 transport/security/licensing **33/33**, native R2/R3 GSS
**26/26**, R10 Linux CredSSP **4/4**, native R5 X11 **24/24**, and bounded
fuzzer **1/1**. The strengthened GSS licensing contract ran under sanitizers.
The two newly added portable identity/CSPRNG tests were not selected by the
then-current bounded transport regex, so sanitizer-specific execution of those
two is **NOT RUN** and is not claimed.

Documentation policy, installed SDK downstream consumer and package
creation/upload all **PASS** on Linux, macOS and Windows. Canonical owner-local
`~/rdp-server/build/`, owner Linux/X11, Windows MSYS2 CLANG64/Clang 23,
macOS 27, genuine positive Kerberos/logind admission and Microsoft-client
licensing/Share/desktop acceptance remain **NOT RUN**. M2/M3 remain
**OPEN / NOT ACCEPTED**.

## R3 protected first client licensing response intake (2026-10-16; hosted CI pending)

**Reconciled shared-main parent:** `dd5786fe60d823668056892671aaa98270ef2e45`.

After complete Server License Request delivery, R3 now recognizes only the
Enhanced-Security licensing envelope that Microsoft requires: a 4-byte Basic
Security Header containing `SEC_LICENSE_PKT`, followed by one complete
licensing message. `SEC_RESET_SEQNO`, `SEC_IGNORE_SEQNO` and
`SEC_FLAGSHI_VALID` are tolerated as the specification requires; competing
packet-kind flags, Standard-Security `SEC_ENCRYPT`/exchange paths and
licensing-encryption capability bits are rejected before any licensing body is
exposed. The syntax parser is allocation-free and returns only a borrowed
licensing span.

The sole `McsSessionLifecycle` accepts this response only from
`AwaitClientLicenseResponse`, with the same bound HYBRID provenance,
allocated user, complete joined-channel state, exact client initiator, global
I/O channel and begin|end MCS segmentation. Only then is the existing bounded
`RdpLicensingLifecycle::onClientMessage` invoked. Exactly one structurally
valid `CLIENT_LICENSE_INFO` or `CLIENT_NEW_LICENSE_REQUEST` can advance
both owners to their explicit server-decision state. Malformed, duplicated,
wrong-channel, wrong-security-header or wrong-order traffic closes the R3
owner; no client payload is retained.

Positive intake remains private to
`LinuxConsoleAdmissionBroker::authorizeR3ClientLicensingMessage`, which
freshly reauthorizes the same move-only native lease and exact R1
HYBRID/TLS/GSS owner before the packet reaches R3. Ordinary CI does not
fabricate a positive NSS/logind lease; the Linux contract therefore proves
the unforgeable method signature and denial boundary rather than synthetic
admission.

New production-linked CTests:
`transport.licensing-client-envelope-wire`,
`transport.licensing-client-envelope-denials`, and Linux-only
`security.gssapi-r3-client-licensing-route-contract`. The R9 bounded
transport and native-GSS selectors are extended to run all three under
ASan/UBSan.

This increment performs **no cryptographic license validation or issuance**.
A structurally accepted client response stops at
`RdpLicensingPhase::AwaitServerDecision` /
`McsSessionPhase::AwaitServerLicenseDecision`. It grants no Share, graphics,
input, clipboard or desktop authority. R10 still owns eventual service
configuration/listener composition and R1 remains the only TLS/application
I/O owner.

Canonical owner-local `~/rdp-server/build/` configure/build/full CTest is
**NOT RUN** in this connector environment. Exact-publication-SHA hosted
Linux/GCC, macOS/Clang, Windows/MSVC Debug/Release, R9 sanitizer,
documentation-policy and SDK/package evidence are pending.

**Next R3:** implement a real, standards-correct server licensing decision
with cryptographic verification/key handling before any License Error
(valid-client), New License, Platform Challenge or Demand Active path can
advance. Until that exists, **M2/M3 remain OPEN / NOT ACCEPTED**.



## R10 real-Kerberos binding-is-not-native-admission aggregate gate (2026-10-16; execution pending)

Starting reconciled shared `main`: `39f4b0de15f2b3ea3d60884ed53e95c0ba80df7a`. R2 remains deliberately
deny-only for final CredSSP credentials, so this increment does not invent a
positive native-admission path. Instead, the existing R10 real-Kerberos
aggregate fixture now discovers the exact client principal from the explicitly
provided GSS FILE: credential cache and uses that real principal in the
immutable runtime identity policy.

A third opt-in CTest,
`runtime.linux-connection-real-kerberos-binding-not-native-admission`, drives
the production `LinuxRuntimeConnection` through R1 HYBRID/TLS, real MIT
SPNEGO and delivered CredSSP public-key binding, verifies the protected server
proof, then calls R10 `issueAdmission()` with the exact cache principal and
matching configured account/seat/display request. The required result is
terminal denial: R2's private native-admission principal remains empty because
final credential authorization has not completed.

The R2 broker checks that private proof before constructing its logind change
monitor or sampling NSS/logind, so this gate specifically demonstrates that
`BindingVerified` cannot be promoted into native evidence. R10 must end with
GSS failed, broker revoked, no lease, R3 closed and stale CredSSP callbacks
closed. No listener/service, synthetic authenticated principal, native session
sampling or R3 admission is added.

The test body compiles with the ordinary Linux GSS test executable and is
registered only under `RDP_SERVER_TEST_REAL_KERBEROS=ON` with the existing
explicit external service principal/keytab/client-cache requirements.
Credentialed execution is **NOT RUN** in this connector environment. Canonical
owner `~/rdp-server/build` is also **NOT RUN** because no checkout is mounted.
M2/M3 remain **OPEN** and positive native admission remains **BLOCKED on R2**
until a reviewed positive final-credential authorization contract exists.

## R3 Enhanced-Security licensing certificate source correction (2026-10-16; hosted CI pending)

**Reconciled shared-main parent:** `8e9040f198982e1e7b52c8597dbbb9b47730ba2e`.

The next cryptographic licensing step exposed a prerequisite interoperability
bug in the earlier Server License Request authoring. This server negotiates
Enhanced RDP Security, so MS-RDPBCGR 2.2.1.4.3 requires SC_SECURITY
`encryptionMethod=0` and `encryptionLevel=0`; the existing MCS response
correctly emits no `serverRandom` or `serverCertificate` fields there.
MS-RDPELE 2.2.2.1 permits an empty `ServerCertificate` BLOB only when the
client can use the public key from Server Security Data. That fallback does not
exist on this Enhanced-Security path. The prior empty licensing-certificate
encoding is therefore superseded for live R3 sessions.

`RdpServerLicenseIdentity` now requires and owns a nonempty explicitly
provisioned `BB_CERTIFICATE_BLOB` payload in addition to product/scope
identity. The protocol layer treats those bytes as bounded opaque credential
material: it does not invent a certificate, parse or bless a certificate
chain, or claim that a matching private key is available. Missing or oversized
certificate material fails the one-shot identity configuration and live request
writer closed.

The complete `SERVER_LICENSE_REQUEST` owner grows from a 2 KiB ceiling to a
16 KiB ceiling, still below R1's existing 18 KiB TLS application-I/O boundary.
The certificate itself is capped at 14 KiB, leaving bounded room for the fixed
licensing fields and the existing three 512-byte identity strings. The
deterministic serializer now writes the nonzero certificate BLOB length and
bytes and reports `InvalidServerCertificate` without modifying caller output
when the certificate is absent. CSPRNG ServerRandom generation and receipt
accounting are unchanged.

Portable production-linked coverage strengthens
`transport.licensing-server-request-wire` and
`transport.licensing-server-identity-configuration`, and adds
`transport.licensing-server-request-certificate-required`. The R1
`transport.tcp-owned-r3-license-request-slice` fixture is updated only with
opaque certificate bytes so its short-write/receipt invariant remains the same.
R9's bounded sanitizer selector now directly includes the identity,
certificate-required and generated-random cases in addition to the existing
request wire/receipt/denial coverage.

This is a standards prerequisite, **not** a licensing decision. The test
certificate bytes are explicitly opaque serializer fixtures, not a fabricated
valid credential. No private key is introduced, no client premaster secret is
decrypted, no licensing keys or MAC are derived or verified, and no
`STATUS_VALID_CLIENT`, Platform Challenge, New License, Demand Active, Share,
graphics, input, clipboard or desktop authority can advance.

Canonical owner-local `~/rdp-server/build/` configure/build/full CTest is
**NOT RUN** in this connector environment. Exact-publication-SHA Linux/GCC,
macOS/Clang, Windows/MSVC Debug/Release, R9 sanitizer, documentation-policy and
SDK/package evidence are pending.

**Next R3:** add a bounded credential/key-processing boundary for the accepted
client licensing response: retain/extract the exact 32-byte ClientRandom and
encrypted premaster BLOB, require an explicitly provisioned private key that
matches the advertised licensing certificate, perform the specified RSA
premaster decryption and MS-RDPELE 5.1.2 licensing-key derivation, and still
stop before any positive client decision until the relevant MAC/license
material is cryptographically verified. R10 remains responsible for real
service credential provisioning. **M2/M3 remain OPEN / NOT ACCEPTED.**

## R6 capture-cycle release callback result boundary (2026-10-16)

A successful native DXGI `ReleaseFrame` only proves that the current lease was
retired; it does not prove that the enclosing `WindowsDxgiCaptureCycle` is
still usable. Release callbacks are synchronous and may request terminal
cancellation while `captureFrame()` owns the operation guard. Such
cancellation remains deferred until the callback returns, preventing recursive
teardown or duplicate release.

When staging reports GPU-not-ready, the cycle still releases the frame before
returning. If that release fails, the cycle reports `failed`. If release
succeeds but its callback has terminally revoked the cycle, terminal `closed`
dominates the otherwise retryable `notReady` result. Only a still-live cycle
may report `notReady` and be retried. The existing staging-before-DXGI release
order, single lease owner, generation reader, and authorization boundary are
unchanged.

## R10 binding-is-not-native-admission exact-SHA hosted validation receipt (2026-10-16)

Implementation `bdf9c5a95f8567ad5e3d2f77eb8c64a7a234ef87`,
GitHub Actions `38919442800`, completed **SUCCESS**. This validates the
third R10 opt-in real-provider aggregate case,
`runtime.linux-connection-real-kerberos-binding-not-native-admission`, at
compile/regression level while preserving its explicit external-credential
execution gate.

The exact SHA passed Ubuntu/GCC **444/444 Debug** and **444/444 Release**,
macOS/Clang **371/371 Debug** and **371/371 Release**, Windows/MSVC native
preflight **44/44 Debug** and **44/44 Release**, and full Windows
**400/400 Debug** and **400/400 Release**. Installed SDK consumer checks and
package generation passed on Linux, macOS and Windows. Documentation policy
passed.

The Clang ASan/UBSan job also completed **SUCCESS**: **49/49 clipboard**,
**19/19 R4 x264/BGRA**, **36/36 bounded R1/R3 transport/security/licensing**,
**27/27 native R2/R3 GSS**, **4/4 R10 Linux runtime CredSSP**,
**24/24 R5 X11**, and **1/1 bounded fuzzer**. The production-linked Linux GSS
test target containing all three R10 real-Kerberos aggregate cases compiled
under sanitizers.

The three `opt-in-kerberos` aggregate CTests themselves remain **NOT RUN** in
hosted CI because the workflow intentionally configures
`RDP_SERVER_TEST_REAL_KERBEROS=OFF` and supplies no external service keytab
or client credential cache. Therefore no credentialed claim is made for
`BindingVerified`, final `UnsupportedFinalCredentials`, or the
binding-not-native-admission call to `issueAdmission()`.

Current R2 source still makes positive native admission unreachable by design:
final CredSSP `authInfo` is consumed only by the reviewed deny-only path,
`ownedCredSspCredentialAuthorizationComplete_` remains false with no public
setter, and `LinuxConsoleAdmissionBroker::issue()` requires the corresponding
private native-admission principal before constructing a logind monitor or
sampling NSS/logind. R10 therefore remains **BLOCKED on R2** for positive
native admission and must not synthesize that proof.

Canonical owner-local `~/rdp-server/build`, owner Linux/X11, Windows MSYS2
CLANG64/Clang23, macOS 27, explicit real KDC/keytab/cache execution, positive
NSS/logind admission and Microsoft-client acceptance remain **NOT RUN**.
R3's emerging licensing identity/configuration work does not remove this
authentication blocker and is not sufficient reason to enable a listener.
M2/M3 remain **OPEN / NOT ACCEPTED**.


## R4 RDPGFX surface identifier domain (2026-10-16)

R4 treats `surfaceId` as the full MS-RDPEGFX uint16 wire domain, including
zero. `GfxPresentationLifecycle::stage()` is the configuredness authority;
the stored `surfaceId_` value is meaningful only in the surface-command /
mapped stages and is not a validity sentinel. A mapped surface with ID zero
therefore passes through CREATE, MAP, WIRE_TO_SURFACE_1, frame delivery/ACK
and DELETE exactly like any other ID. R3 remains responsible for the future
authenticated Graphics DVC; this rule adds no surface allocator or transport
ownership.


## R7 native capture start-completion stop ordering (2026-10-16)

A ScreenCaptureKit stream may report successful asynchronous start after its
C++ owner has already closed or invalidated the topology. A speculative
`stopCaptureWithCompletionHandler` submitted before start completion does not
guarantee that the later successful start is retired; if it consumes the
one-shot stop claim, the later start callback cannot submit a second stop.
The shared C++ callback state therefore records a *successful native start
completion* even when its lifecycle was already closed. Only an already
successful start permits owner `close()` to claim a native stop. Otherwise the
late successful start completion uses the existing one-shot claim and submits
retirement. Failed starts never cause speculative stop. This keeps all stop
paths on the same per-stream claim without changing frame delivery,
authorization, capture construction, or R3/R4 ownership.



## R10 unified pre-admission readiness dispatcher (2026-10-16; hosted CI pending)

Starting reconciled shared `main`: `394a17d930044fcbbd247747c05b7a9174997d22`. Review of the existing
non-listening aggregate found a scheduler seam rather than an authentication
gap: after R1 completes a genuine HYBRID TLS handshake,
`LinuxRuntimeConnection::ioInterest()` correctly exposes application read or
write readiness, while the legacy phase-specific `onReadable()` /
`onWritable()` methods still target the plaintext X.224 adapter. A future
event loop that mechanically paired those APIs could repeatedly receive
`ReadyForTls` without advancing R2 CredSSP.

R10 now exposes one bounded `advancePreAdmission(readable, writable,
tlsContext)` dispatcher. It derives all phase from the existing R1 owner and
all pending CredSSP write direction from the existing R2 writer; it adds no
parallel state machine. Wrong-direction readiness returns `NeedRead` or
`NeedWrite` with zero plaintext progress and touches no socket. R1's own
bounded readiness dispatcher drains X.224 reply bytes and advances TLS. Only
after the complete X.224 response may R10 transfer one fresh SSL from the
service-owned TLS context into R1. Once R1 reaches `AwaitCredSsp`, the same
R10 call delegates exactly one step to R2's owner-driven CredSSP/GSS path and
preserves its exact read/write accounting.

The dispatcher is deliberately pre-admission only. If R1 ever exposes its
legacy `AwaitMcsConnectInitial` diagnostic on this HYBRID aggregate, R10
revokes instead of invoking that reader. Positive MCS remains reachable only
through the existing R2 lease/broker path. The old phase-specific methods
remain for focused tests/compatibility but are documented as unsuitable for a
general pre-admission scheduler.

New production-backed CTest
`runtime.linux-connection-pre-admission-dispatch` drives one accepted loopback
connection through wrong-direction X.224 readiness, HYBRID negotiation, the
production R10 TLS context, nonblocking TLS, wrong-direction post-TLS
readiness, and a real R2-owned rejected CredSSP token. It requires read/write
mutual exclusion, exact request/reply byte accounting, the canonical v6
provider failure reply, terminal ordered revocation and inert stale callbacks.
The R9 Clang ASan/UBSan R10 selector is expanded to include this fifth
aggregate case.

Canonical owner-local `~/rdp-server/build` configure/build/full CTest is
**NOT RUN** because the checkout is unavailable in this connector environment.
Exact-publication-SHA hosted Linux/GCC, macOS/Clang, Windows/MSVC,
documentation-policy, SDK/package and sanitizer evidence are required before
PASS is claimed. Positive native admission remains **BLOCKED on R2** because
final CredSSP credentials are still deny-only. R3 licensing credential
provisioning is not invented here because its reviewed certificate/private-key
service contract is not yet defined. No listener/service is enabled and M2/M3
remain **OPEN**.

## R10 unified pre-admission dispatcher hosted validation receipt (2026-10-16)

Implementation `3e135ad6fe0d7d0720e79369e925f815e75a4826` introduced the
bounded R10 `advancePreAdmission()` readiness dispatcher and
`runtime.linux-connection-pre-admission-dispatch`. Its first workflow,
Actions `38934560964`, failed before any job was created because the
publication script accidentally duplicated the tail of `.github/workflows/ci.yml`
while editing the sanitizer regex. That run is workflow-authoring failure only,
not C++/CTest evidence.

Shared-main correction `93ab919dc2a3de53d551471599c04310dd25f35e`
restored the workflow structure and retained the intended five-case R10
sanitizer selector. Clean validated descendant
`aa6f55dfc5f399e995ca0ba922567c0d1d99e211`, Actions
`38934985250`, completed **SUCCESS**. The R10 runtime header/source,
`test_runtime_linux_security.cpp` and central CTest registration have
identical Git blobs at the implementation and validated descendant SHAs.

Hosted evidence on that clean descendant is Ubuntu/GCC **459/459 Debug PASS**
and **459/459 Release PASS**; the new dispatcher is test 287 and passes in both.
macOS/AppleClang is **385/385 Debug PASS** and **385/385 Release PASS**.
Windows/MSVC native preflight is **46/46 Debug PASS** and **46/46 Release
PASS**, with the full suite **414/414 Debug PASS** and **414/414 Release PASS**.
Installed SDK consumer **1/1**, packaging, digest and artifact upload pass on
all hosted platforms. Documentation policy passes; untagged prerelease
publication is correctly skipped.

The Clang ASan/UBSan job also completes **SUCCESS**: clipboard **50/50**,
R4 x264/BGRA **20/20**, bounded R1/R3 transport/security/licensing **49/49**,
native R2/R3 GSS **27/27**, R10 pre-admission **5/5**, native R5 X11 **25/25**,
and bounded fuzzer **1/1**. The new dispatcher test passes directly under
ASan/UBSan.

Validated invariant: one R10 call now maps external readiness across X.224,
TLS and R2 CredSSP without redispatching the legacy plaintext callback after
HYBRID TLS. Wrong-direction readiness performs zero plaintext I/O, X.224 reply
delivery precedes SSL ownership transfer, and the pre-admission API never
invokes the legacy R1 MCS reader. Existing R2/R3 admission remains the only
positive MCS route.

Canonical owner-local `~/rdp-server/build`, owner Linux/X11, Windows MSYS2
CLANG64/Clang23, macOS 27, explicit real-Kerberos credentialed aggregate tests,
positive NSS/logind admission and Microsoft-client acceptance remain **NOT
RUN**. Positive native admission remains **BLOCKED on R2** because final
CredSSP credential authorization is deny-only. R3 licensing still lacks the
reviewed service certificate/private-key provisioning contract needed for R10
configuration; no schema is invented. No listener/service is enabled and
M2/M3 remain **OPEN / NOT ACCEPTED**.

## R3 licensing service credential and RSA premaster primitive (2026-10-16; hosted CI pending)

**Reconciled shared-main parent:** `8199ba9a6b7af6ea574711da163d410bd75009b5`.

R3 now has the bounded asymmetric-credential prerequisite for the existing
initial licensing key-exchange parser and MS-RDPELE key derivation. A new
noncopyable `RdpLicensingServiceCredential` is configured exactly once from
one already-provisioned `RdpServerLicenseIdentity` plus one unencrypted PEM
private key. Failed configuration retains no caller key bytes; successful
configuration owns one bounded contiguous PEM snapshot and cleanses that
storage on destruction.

The credential accepts the standards-defined
`CERT_CHAIN_VERSION_2` X.509 licensing-certificate form only. It checks the
2..200 root-first certificate layout and exact protocol padding, parses every
DER certificate, verifies each child certificate signature against the
immediately preceding issuer, selects the terminal-server leaf, requires an
RSA private key of at least the legacy 512-bit size and at most 4096 bits, and
requires that private key to match the exact terminal leaf. This proves
internal chain coherence and leaf/private-key binding only; it deliberately
does not claim that the chain root is externally trusted by licensing policy.
Proprietary RDP certificates and encrypted PEM private keys remain unsupported
and fail closed.

A SHA-256 fingerprint binds the credential to the exact advertised
`SERVER_CERTIFICATE` bytes, including the chain padding. After configuration,
`matches(identity)` can prove that a later identity is byte-for-byte the
credential's advertised certificate without exposing private material.

`decryptPreMasterSecret` implements only the RSA unwrap prerequisite. It
requires the client BLOB to be exactly the configured RSA modulus width plus
the protocol's eight trailing zero bytes, converts the RDP unsigned
little-endian RSA integer to OpenSSL big-endian form, performs raw RSA private
operation, converts the result back, requires all bytes above the exact
48-byte premaster secret to be zero, returns the exact 48-byte value without
inventing an entropy/nonzero predicate, returns a zero-initialized result on
failure, and cleanses all temporary ciphertext and plaintext buffers. The successful 48-byte output can feed the already-tested
`deriveRdpLicensingKeys` helper; neither operation mutates licensing/session
state.

New production-linked ordinary CTests are
`transport.licensing-premaster-rsa-decrypt` and
`transport.licensing-premaster-rsa-denials`. The fixture creates ephemeral
in-memory RSA keys and a two-certificate X.509 chain only for offline
cryptographic verification; it is never service provisioning or an
authentication/license authority. Denials cover wrong private key,
unsupported/non-RSA key, malformed/unsupported certificate form, broken chain
signature, key-file trailing garbage/oversize, malformed protocol padding,
truncated ciphertext and all-zero decrypted premaster. Both cases are added
to the bounded R1/R3 ASan/UBSan selector and its registry preflight.

This increment deliberately does **not** make
`RdpServerLicenseRequestWriteGate` require the credential yet, does not pass
private-key material through R2, and does not perform a server licensing
decision. Therefore an opaque structurally accepted
`RdpServerLicenseIdentity` still cannot be treated as a usable live
credential merely because serialization succeeds. R10 remains responsible for
real service credential provisioning, and R2 remains the sole native
admission/reauthorization owner.

Canonical owner-local `~/rdp-server/build/` configure/build/full CTest is
**NOT RUN** in this connector environment; no alternate persistent checkout or
build root is created. Exact-publication-SHA Linux/GCC, macOS/Clang,
Windows/MSVC Debug/Release, R9 sanitizer, documentation-policy and
SDK/package evidence are pending. Genuine Kerberos/NSS/logind positive
admission, real licensing credential provisioning, Microsoft-client licensing,
Share activation and desktop acceptance remain **NOT RUN/OPEN**.

**Next R3:** require the configured credential to match the identity before
the protected Server License Request can be published; then, after the first
client licensing response is freshly R2-reauthorized, decrypt its exact
encrypted premaster with that same credential, derive the licensing keys, and
stop at `AwaitServerDecision` until CAL/HWID/MAC validation is implemented.
No `STATUS_VALID_CLIENT`, Platform Challenge, New License or Demand Active
path may advance before those cryptographic checks. **M2/M3 remain OPEN / NOT
ACCEPTED.**

## R3 licensing service credential RSA exact-SHA validation (2026-10-16)

**Implementation:** `10ff27cdd93a9c0226a024f40e6e9fe1f90bd1f0`.
**Premaster-value correction:** `1268b81fcf315d8521a1282f1dabf11508852398`.
**Authoritative Actions:** `38937314411` — **SUCCESS**.

The corrected exact SHA is green across every hosted gate. Ubuntu/GCC full
CTest is **461/461 PASS Debug** and **461/461 PASS Release**. macOS/Clang is
**387/387 PASS Debug** and **387/387 PASS Release**. Windows/MSVC native
preflight is **46/46 PASS Debug** and **46/46 PASS Release**, and the full
suite is **416/416 PASS Debug** plus **416/416 PASS Release**. The new
`transport.licensing-premaster-rsa-decrypt` and
`transport.licensing-premaster-rsa-denials` cases pass in all six hosted
Debug/Release platform configurations.

R9 Clang ASan/UBSan is **PASS**: clipboard **50/50**, R4 x264/BGRA **20/20**,
bounded R1/R3 transport/security/licensing **51/51**, native R2/R3 GSS
**27/27**, R10 Linux runtime CredSSP **5/5**, native R5 X11 **25/25**, and
bounded fuzzer **1/1**. Both new RSA credential cases are explicitly selected
by the bounded R1/R3 registry preflight and pass under ASan/UBSan.
Documentation policy and the independent R7 macOS sanitizer side gate pass.
Installed SDK downstream consumer is **1/1 PASS** and package/artifact upload
passes on Linux, macOS and Windows.

An earlier intermediate run of `10ff27c...` had one unrelated macOS failure
in `transport.tcp-native-accept-orderly-eof`; both new RSA licensing tests
passed there in Debug and Release. The corrected `1268b81...` rerun is fully
green and is the authoritative result.

Canonical owner-local `~/rdp-server/build/`, owner Linux/X11, Windows MSYS2
CLANG64/Clang23, macOS 27, genuine Kerberos/NSS/logind positive admission,
real service licensing credentials, Microsoft-client licensing/Share/desktop
acceptance remain **NOT RUN / OPEN**. **M2/M3 remain OPEN / NOT ACCEPTED.**

## R3 bound licensing credential continuity (2026-10-16; hosted CI pending)

**Reconciled shared-main parent:** `1268b81fcf315d8521a1282f1dabf11508852398`.

The live protected licensing path now requires the cryptographically validated
`RdpLicensingServiceCredential`; a structurally configured
`RdpServerLicenseIdentity` alone can no longer reach R2-authorized request
publication or first client licensing intake. This changes ownership/provenance
only and does not alter the Server License Request wire bytes.

`RdpLicensingServiceCredential::certificateFingerprint()` exposes only the
non-secret SHA-256 binding of the exact advertised `SERVER_CERTIFICATE`.
On the first authorized Server License Request preparation,
`McsSessionLifecycle` requires `credential.matches(identity)`, copies that
32-byte fingerprint into session-owned fixed storage and queues the existing
stable request. Every later partial-write resubmission must present a
credential whose fingerprint exactly matches the one already bound; a second
otherwise-valid credential/identity pair cannot silently replace the key
identity for an in-flight request. Teardown clears the fingerprint and binding
flag.

The concrete Linux R2 broker method
`authorizeR3ServerLicenseRequestWrite` now requires both the immutable
identity and the service credential after the same fresh lease/R1
reauthorization used previously. The existing
`security.gssapi-r3-server-license-request-write-contract` compile-time
contract is strengthened so identity without credential, raw request fields,
Boolean authorization and other substitutes cannot satisfy that protected
signature.

The first client licensing response also requires the same bound credential
before any MCS/security-envelope parsing can advance licensing state.
`authorizeR3ClientLicensingMessage` and its private R3 intake now take the
service credential and compare its fingerprint with the one pinned when the
server request was prepared. This is continuity only: the client premaster is
not yet decrypted in the session, no derived key is stored, no CAL/HWID/MAC is
validated, and no positive licensing result or activation is emitted. The
existing Linux client-licensing route contract is strengthened in place and
remains selected by R9.

No private key bytes are copied into `McsSessionLifecycle`; the sole
credential object remains the bounded service credential owner. R1 remains the
only TLS/application writer and R2 remains the only native admission/
reauthorization owner. No listener, scheduler, synthetic positive lease,
license authority or second transport owner is introduced.

Canonical owner-local `~/rdp-server/build/` configure/build/full CTest is
**NOT RUN** in this connector environment. Exact-publication-SHA Linux/GCC,
macOS/Clang, Windows/MSVC Debug/Release, R9 sanitizer, documentation-policy and
SDK/package evidence are pending.

**Next R3:** inside the freshly R2-reauthorized first-client-response
transition, parse the already bounded key-exchange view, decrypt its exact
encrypted premaster through the session-bound credential, derive the licensing
MAC/encryption keys from the retained request ServerRandom, securely erase
temporary premaster material, and stop at `AwaitServerDecision`. Do not emit
`STATUS_VALID_CLIENT`, Platform Challenge, New License or Demand Active
until the required CAL/HWID/MAC validation is implemented. **M2/M3 remain
OPEN / NOT ACCEPTED.**

## R3 bound client-premaster decryption and licensing-key preparation (2026-10-16; hosted CI pending)

**Reconciled shared-main parent:** `5dd55a2e84faf883510929ab3a99393085156390`.

The protected first-client-licensing transition now performs the cryptographic
preparation required by the preceding roadmap while still stopping before any
positive licensing decision. A new bounded
`prepareInitialRdpLicensingCrypto` helper composes the existing structural
key-exchange parser, the session-bound `RdpLicensingServiceCredential` RSA
premaster unwrap, and the existing MS-RDPELE 5.1.2 key derivation. It accepts
one complete supported initial client licensing message plus the exact
32-byte ServerRandom retained from the fully delivered Server License Request.

The helper returns only the 16-byte MAC salt key and 16-byte licensing
encryption key. The temporary 48-byte premaster is cleansed immediately after
derivation. A shared `cleanseRdpLicensingKeyMaterial` boundary uses
OpenSSL's non-optimizable cleanse for terminal erasure; no premaster, client
payload, private key, username or machine name is retained.

`McsSessionLifecycle::acceptVerifiedR2ClientLicensingMessage` invokes this
crypto preparation only after the existing concrete R2 lease/exact-R1-owner
reauthorization, credential-fingerprint continuity check, joined global-I/O
routing, complete segmentation and `SEC_LICENSE_PKT` validation. Crypto
failure closes the R3 owner before the structural licensing lifecycle can
advance. On success the sole R3 session owns one fixed
`RdpLicensingKeyMaterial`, immediately cleanses the temporary returned copy,
then consumes the licensing message exactly once and stops at
`AwaitServerLicenseDecision`. Session close and destruction both cleanse the
owned keys.

This is **not** a valid-client decision. No CAL, HWID or MAC verification is
implemented; no RC4 licensing payload is trusted; no `STATUS_VALID_CLIENT`,
Platform Challenge, New/Upgrade License, Demand Active, Share, graphics,
input, clipboard or desktop authority is emitted. R2 admission authority and
R1 TLS/application-I/O ownership are unchanged, and R10 still owns real
service credential/configuration composition.

New ordinary production-linked CTests are
`transport.licensing-initial-crypto-preparation` and
`transport.licensing-initial-crypto-denials`. The positive case uses only an
ephemeral in-memory RSA/X.509 fixture and independently compares the composed
result with the already-tested key-derivation oracle. Denials cover invalid
ServerRandom size, truncated client message, unconfigured credential, malformed
encrypted-premaster padding and an unexpected licensing message. Both cases are
added to the bounded R1/R3 ASan/UBSan selector and its registry preflight.

Canonical owner-local `~/rdp-server/build/` configure/build/full CTest is
**NOT RUN** in this connector environment. Exact-publication-SHA Linux/GCC,
macOS/Clang, Windows/MSVC Debug/Release, R9 sanitizer, documentation-policy and
SDK/package evidence are pending. Genuine Kerberos/NSS/logind positive
admission, real service licensing credentials and Microsoft-client licensing/
Share/desktop acceptance remain **NOT RUN/OPEN**.

**Next R3:** parse and cryptographically validate the relevant
`CLIENT_LICENSE_INFO` CAL/HWID/MAC material using these bound derived keys,
or implement the standards-required New License / Platform Challenge branch
for `CLIENT_NEW_LICENSE_REQUEST`, with every outbound decision protected by
fresh R2 authorization and receipt-bound R1 delivery. Do not emit
`STATUS_VALID_CLIENT` or activation before those checks. **M2/M3 remain
OPEN / NOT ACCEPTED.**

## R3 CLIENT_LICENSE_INFO HWID integrity boundary (2026-10-16; hosted CI pending)

**Reconciled shared-main parent:** `06d2e08eeea0c224c949b68ae46ffb5b9bd7175a`.

R3 now implements the next cryptographic prerequisite for an existing-license
client without claiming that the presented CAL is valid. The licensing layer
exposes the exact borrowed `CLIENT_LICENSE_INFO` fields needed by later
license validation: the opaque CAL BLOB, encrypted hardware identification and
16-byte MACData. The encrypted hardware identifier is structurally required to
be exactly the 20-byte `CLIENT_HARDWARE_ID` defined by MS-RDPELE 2.2.2.3.1.

A bounded first-party `cryptRdpLicensingData` implements the RC4 transform
specified by MS-RDPELE 5.1.3/5.1.4 using only the exact 16-byte licensing
encryption key. It uses fixed 256-byte stack state, supports overlapping
input/output through memmove staging, allocates nothing and cleanses the RC4
state after use. It deliberately avoids dependence on OpenSSL's optional legacy
RC4 provider.

`generateRdpLicensingMac` implements MS-RDPELE 5.1.5 exactly:
`MD5(macKey || pad2 || SHA1(macKey || pad1 || LE32(dataLength) || data))`.
SHA-1/MD5 are invoked only for this protocol-defined compatibility checksum via
the existing OpenSSL digest boundary.

`verifyRdpClientLicenseInfoHardwareId` decrypts the 20-byte HWID with the
derived licensing encryption key, regenerates MACData over the plaintext HWID
and compares it with `CRYPTO_memcmp`. Plaintext HWID and temporary MAC bytes
are cleansed before return and are never exposed or retained.

The protected first-client-response transition now invokes that verifier when
the already-bound response is `CLIENT_LICENSE_INFO`. HWID integrity failure
closes the sole R3 owner before the licensing lifecycle can remain in the
server-decision state. Success still advances only to
`AwaitServerLicenseDecision`; the session retains the branch enum and the
already-derived two 16-byte keys, not CAL or HWID payload.
`CLIENT_NEW_LICENSE_REQUEST` remains on its separate Platform Challenge
decision branch.

New production-linked CTests:
`transport.licensing-rc4-wire`,
`transport.licensing-mac-wire`,
`transport.licensing-client-license-info-hwid-proof`, and
`transport.licensing-client-license-info-hwid-denials`. The RC4/MAC oracles
are fixed independent specification vectors. Denials cover key/size errors,
MAC mismatch, ciphertext corruption, wrong key, wrong message type and malformed
encrypted-HWID length. All four are selected by the bounded R1/R3 ASan/UBSan
registry preflight.

This increment deliberately does **not** validate the CAL certificate/signature,
product identity, expiration state or CAL-to-HWID binding and therefore cannot
emit `STATUS_VALID_CLIENT`. It creates no Platform Challenge, New/Upgrade
License, Demand Active, Share, graphics, input, clipboard or desktop authority.
R1 remains the only TLS/application-I/O owner, R2 the native
admission/reauthorization owner, and R10 the real service/license-authority
configuration owner.

Canonical owner-local `~/rdp-server/build/` configure/build/full CTest is
**NOT RUN** in this connector environment. Exact-publication-SHA Linux/GCC,
macOS/Clang, Windows/MSVC Debug/Release, R9 sanitizer, documentation-policy and
SDK/package evidence are pending. Genuine Kerberos/NSS/logind positive
admission, real licensing authority material and Microsoft-client
licensing/Share/desktop acceptance remain **NOT RUN / OPEN**.

**Next R3:** either add bounded CAL parsing plus provisioned trust/product/
expiration/HWID validation for the now-MAC-verified
`CLIENT_LICENSE_INFO`, or implement the standards-required receipt-bound
Server Platform Challenge branch for `CLIENT_NEW_LICENSE_REQUEST`.
Only after the full relevant branch is cryptographically valid may a protected
server licensing result be serialized. **M2/M3 remain OPEN / NOT ACCEPTED.**



## R10 service-owned licensing credential context (2026-10-16; hosted CI pending)

Starting reconciled shared `main`: `7732d83f4b1ffcb2f1a579043303ec777071b271`. R3 now has a reviewed,
cryptographically bound `RdpLicensingServiceCredential` contract: the exact
advertised `CERT_CHAIN_VERSION_2` identity must match one RSA private key,
and protected licensing publication/intake requires that credential separately
from the concrete R2 admission lease. This removes the earlier R10 blocker that
the service credential ownership contract itself was undefined.

R10 now adds a narrow, noninstalled `RuntimeLicensingContext`. It is
noncopyable/nonmovable and one-shot. `configure()` synchronously composes the
existing R3 `RdpServerLicenseIdentity` and
`RdpLicensingServiceCredential`; success exposes only const borrows to those
two already-reviewed owners. Both R3 objects own their required snapshots, so
the caller may overwrite or release the input certificate/private-key buffers
after configuration. The private-key snapshot remains inside R3's bounded
credential storage and is cleansed by that owner on destruction.

This increment deliberately does **not** define a configuration-file schema or
read a licensing key pathname. It does not connect the credential to
`LinuxRuntimeConnection`, because positive final CredSSP authorization and
therefore a genuine native R2 lease remain unreachable. It also does not bind a
listener, create R3 session authority, publish a Server License Request, make a
licensing decision, or enable Share activation. The next filesystem/config
increment must reuse an independently reviewed secure R10 file-snapshot
boundary rather than accepting a pathname reopen.

Two production-backed cases reuse the existing ephemeral RSA/X.509 licensing
fixture instead of creating a second cryptographic fixture:
`transport.licensing-runtime-context-ownership` proves successful snapshot
ownership survives caller certificate/private-key mutation and can still
decrypt the fixture premaster; `transport.licensing-runtime-context-denials`
proves mismatched-key and invalid-identity failures are terminal and expose no
partial identity/credential. Both are added to the bounded Clang ASan/UBSan
licensing selection.

Canonical owner-local `~/rdp-server/build` configure/build/full CTest is
**NOT RUN** in this connector environment because no synchronized checkout is
available. Exact-publication-SHA Linux/GCC, macOS/Clang, Windows/MSVC,
documentation-policy, SDK/package and sanitizer evidence are required before
PASS is claimed. Positive Kerberos/final-CredSSP authorization, NSS/logind
admission, real licensing credential files, Microsoft-client licensing/Share
activation and any listener/service remain **NOT RUN / BLOCKED**. M2/M3 remain
**OPEN / NOT ACCEPTED**.



## R10 service-owned licensing context exact-SHA validation (2026-10-16)

Implementation `85f12cdd9386b9d606697048e99ff5c42ac50f8a`,
GitHub Actions `38966505059`, completed **SUCCESS**. The implementation adds
the noninstalled one-shot `RuntimeLicensingContext` and the dedicated
`transport.licensing-runtime-context-ownership` plus
`transport.licensing-runtime-context-denials` regressions.

Hosted exact-SHA evidence is Ubuntu/GCC **471/471 Debug PASS** and
**471/471 Release PASS**; macOS/AppleClang **397/397 Debug PASS** and
**397/397 Release PASS**; Windows/MSVC native preflight **47/47 Debug PASS**
and **47/47 Release PASS**, with the full suite **426/426 Debug PASS** and
**426/426 Release PASS**. Both new runtime licensing cases pass in every full
platform configuration. Installed SDK consumer **1/1**, package generation,
digest/artifact upload and documentation policy pass on all applicable hosted
platforms; untagged prerelease publication is correctly skipped.

The Clang ASan/UBSan job is also **PASS**. Its bounded R1/R3 licensing selector
registered and directly executed both new R10 cases; that selection is
**61/61 PASS**. The other configured sanitizer groups remain green:
clipboard **50/50**, R4 x264/BGRA **20/20**, R4 RDPGFX capability **4/4**,
native R2/R3 GSSAPI **27/27**, R10 pre-admission **5/5**, native R5 X11
**26/26**, and bounded fuzzer **1/1**. The independent R7 macOS session
sanitizer side gate also passes.

Validated invariant: R10 can own one immutable service-lifetime R3 licensing
identity/private-key credential pair without exposing partial state, and the
successful context remains independent of caller certificate/private-key
buffer lifetime. The credential remains protocol cryptographic continuity
material, not an R2 admission capability or licensing decision.

Canonical owner-local `~/rdp-server/build`, owner Linux/X11, Windows MSYS2
CLANG64/Clang23, macOS 27, genuine Kerberos/final-CredSSP positive
authorization, NSS/logind admission, real licensing credential files and
Microsoft-client licensing/Share/desktop acceptance remain **NOT RUN**.
Positive live R10 composition is still **BLOCKED on R2** because final
CredSSP credential authorization remains deny-only. No listener/service is
enabled; M2/M3 remain **OPEN / NOT ACCEPTED**.

**Next R10:** add a secure licensing credential file-snapshot/provisioning
boundary by reusing the already-reviewed R10 opened-file ownership rules rather
than reopening caller pathnames, while keeping the resulting context offline
and non-authorizing. Do not connect licensing into the per-connection aggregate
or enable a listener until genuine R2 positive admission exists.



## R10 shared secure credential snapshot + licensing file provisioning (2026-10-16; hosted CI pending)

Starting reconciled shared `main`: `4b49f34b883d4377c51597b7df4ab5d76ff426dd`. R10 now factors the existing
TLS credential opened-file rules into one runtime-internal exact snapshot owner
and reuses it for licensing provisioning. Each absolute path is opened once;
the native object identity is retained from that handle, certificate/key
aliasing is rejected, the existing POSIX no-symlink/regular-file/mode rules or
Windows opened-HANDLE reparse/DACL rules are applied, and exact bounded bytes
are read from those already-open objects. Private-key bytes are explicitly
cleansed on failed reads and snapshot destruction.

`RuntimeServerTlsContext` and TLS metadata preflight are refactored onto this
shared owner without changing PEM, validity, server-purpose or key-match
semantics. `RuntimeLicensingContext::configureFromCredentialFiles` uses the
same opened-file snapshot with R3's licensing-specific size ceilings and then
synchronously transfers those exact bytes into the reviewed R3
identity/credential owners. There is no validate-then-reopen pathname window.

New cross-platform CTest
`runtime.licensing-context-secure-file-snapshots` reuses the existing
ephemeral R3 RSA/X.509 generator, applies deterministic owner-private
permissions/DACLs, configures the production file-backed context, replaces both
pathname contents with garbage, and still requires the retained private key to
decrypt the original premaster and the retained certificate identity to remain
unchanged. The case is included in the bounded Clang ASan/UBSan licensing
selection. Existing TLS credential tests regression-test the shared opener.

The internal helper header is excluded from the SDK. No configuration schema,
listener, authentication, R2 lease, per-connection licensing transition,
licensing decision or Share activation is added. Positive live composition
remains blocked on R2's deny-only final CredSSP credential authorization.

Canonical owner-local `~/rdp-server/build` and real credential/client gates
are **NOT RUN** here. Exact-publication-SHA hosted Linux/GCC, macOS/Clang,
Windows/MSVC, sanitizer, documentation-policy and SDK/package evidence are
required before PASS is claimed. M2/M3 remain **OPEN / NOT ACCEPTED**.

## R10 secure credential snapshot exact-SHA hosted validation (2026-10-16)

**Implementation:** `df67d3012440a59cd67dd2e53b85aea8f4355c39`.
Its own Actions run `38968057232` is retained as **FAIL / zero jobs**:
the implementation publication accidentally left the shared sanitizer
`licensing_selection` shell regex unterminated and duplicated the following
workflow tail. GitHub therefore created no jobs, so that run supplies no C++
or CTest evidence.

The first clean validated descendant used for R10 implementation evidence is
`0d333f3d4baabd12417878baea5f5741e08d899c`, Actions
`38968793787`, completed **SUCCESS**. Every R10 implementation/test blob from
the original publication is byte-identical on that descendant:
`CMakeLists.txt`,
`src/server/runtime/runtime_credential_file.cpp`,
`src/server/runtime/runtime_credential_file_internal.h`,
`src/server/runtime/runtime_licensing_context.cpp/.h`,
`src/server/runtime/runtime_tls_context.cpp`,
`tests/CMakeLists.txt`,
`tests/check_runtime_licensing_context.cmake`, and
`tests/test_owned_mcs_connect_initial.cpp`.

Hosted validation on that clean descendant is Ubuntu/GCC **472/472 Debug
PASS** and **472/472 Release PASS**, macOS/AppleClang **398/398 Debug PASS**
and **398/398 Release PASS**, and Windows/MSVC native preflight **47/47 Debug
PASS** plus **47/47 Release PASS** with full **427/427 Debug PASS** and
**427/427 Release PASS**. The dedicated
`runtime.licensing-context-secure-file-snapshots` case passes in all six full
platform configurations. Installed SDK consumer **1/1**, package generation
and artifact upload pass on Linux, macOS and Windows; documentation policy
passes.

The Clang ASan/UBSan job is also **PASS**. The bounded
R1/R3 transport/security/licensing selector is **62/62 PASS** and explicitly
registers and executes
`runtime.licensing-context-secure-file-snapshots` under sanitizers. The other
configured groups remain green: clipboard **50/50**, R4 x264/BGRA **20/20**,
R4 capability **4/4**, native R2/R3 GSSAPI **27/27**, R10 Linux
pre-admission **5/5**, native R5 X11 **26/26**, and bounded fuzzer **1/1**.
The independent R7 sanitizer side gate also passes.

Validated invariant: R10 reads TLS/licensing credential paths through one
opened-object identity, applies the platform security checks before exact
bounded reads, retains immutable snapshots independent of later pathname
replacement, and keeps private-key bytes inside noninstalled runtime/R3 owners.
No validate-then-reopen pathname window, listener, authentication proof, native
lease, licensing decision or Share activation is introduced.

Later shared-main R9 work adds
`runtime.licensing-context-replacement-freshness`; that is additional
freshness coverage and does not alter this receipt's implementation identity.
Positive live composition remains **BLOCKED on R2** because final CredSSP
credential authorization remains deny-only. Canonical owner-local
`~/rdp-server/build`, owner Linux/X11, Windows MSYS2 CLANG64/Clang23,
macOS 27, genuine Kerberos/NSS/logind positive admission, real production
licensing credential files and Microsoft-client licensing/Share/desktop
acceptance remain **NOT RUN / OPEN**. No listener/service is enabled.
**M2/M3 remain OPEN / NOT ACCEPTED.**

## R3 receipt-bound Server Platform Challenge branch (2026-10-16; hosted CI pending)

**Reconciled shared-main parent:** `c3b12e213ce63e42c13e54508d7c3d18a0b2b21c`.

R3 now implements the standards-required outbound branch after an accepted
`CLIENT_NEW_LICENSE_REQUEST`, without weakening the separate
`CLIENT_LICENSE_INFO` CAL-validation gate. The licensing lifecycle records
which server-decision branch is pending: a new-license request requires a
Platform Challenge, while a license-info response remains blocked on
CAL trust/product/expiration/HWID authorization and cannot produce
`STATUS_VALID_CLIENT`.

The pure `SERVER_PLATFORM_CHALLENGE` encoder follows MS-RDPELE 2.2.2.4:
the preamble is version 3, ConnectFlags is the reserved `0xffffffff` value,
the challenge BLOB type is the specification-unused zero value, the challenge
is RC4-encrypted with the already-derived licensing encryption key, and
MACData is generated over the plaintext challenge with the already-derived
MAC salt key. Encoding is allocation-free and transactional: malformed input
or insufficient output never exposes partial bytes.

The production challenge profile generates a fresh 128-bit seed with
OpenSSL `RAND_priv_bytes`, renders all 32 uppercase hexadecimal characters
as UTF-16LE plus one terminating null, and therefore owns a fixed 66-byte
plaintext challenge without embedded terminators. The seed and temporary
plaintext are cleansed after construction/delivery; the sole licensing
lifecycle retains the plaintext only while the matching client challenge
response is expected.

`RdpServerPlatformChallengeWriteGate` owns one stable encrypted packet and
uses the same nonzero reply/write-slice receipt discipline as the preceding
Server License Request writer. Zero-byte backpressure preserves the exact
slice, positive partial progress rotates only the slice receipt, and full
accepted-byte delivery alone advances
`RdpLicensingPhase::AwaitServerDecision ->
AwaitClientPlatformChallengeResponse`. Stale, duplicate, over-reported,
wrong-branch or early receipts close the licensing owner.

The sole `McsSessionLifecycle` accepts this writer only when its initial
response was `CLIENT_NEW_LICENSE_REQUEST`, the derived licensing keys are
present, the exact bound HYBRID provenance still matches, and the session is
still `AwaitServerLicenseDecision`. Full delivery advances only to
`McsSessionPhase::AwaitClientPlatformChallengeResponse`. The
`CLIENT_LICENSE_INFO` branch cannot enter this writer.

Positive prepare/resume and accepted-byte completion are private to
`LinuxConsoleAdmissionBroker`. The broker freshly revalidates the concrete
move-only native lease and exact R1 HYBRID/TLS/GSS owner before every exposed
slice and every completion receipt. Challenge bytes and licensing keys are not
caller inputs. A raw SSL pointer, Boolean, derived key material, guessed
receipt or configuration value cannot replace the admission capability.

New production-linked CTests:
`transport.licensing-server-platform-challenge-wire`,
`transport.licensing-server-platform-challenge-write-receipts`,
`transport.licensing-server-platform-challenge-write-denials`, and
Linux-only
`security.gssapi-r3-server-platform-challenge-write-contract`.
The wire case uses a fixed independent RC4/MAC oracle. All four are selected
by the existing bounded ASan/UBSan R1/R3 and native-GSS registry gates.

This increment does **not** accept `CLIENT_PLATFORM_CHALLENGE_RESPONSE`,
issue New/Upgrade License, validate CAL trust/product/expiration, emit
`STATUS_VALID_CLIENT`, send Demand Active, activate Share, or grant graphics,
input, clipboard or desktop authority. R1 remains the sole TLS/application-I/O
owner, R2 remains native admission/reauthorization owner, and R10 remains
service/licensing credential configuration owner.

Canonical owner-local `~/rdp-server/build/` configure/build/full CTest is
**NOT RUN** in this connector environment. Exact-publication-SHA Linux/GCC,
macOS/Clang, Windows/MSVC Debug/Release, bounded ASan/UBSan,
documentation-policy and SDK/package evidence are pending.

**Next R3:** add bounded protected
`CLIENT_PLATFORM_CHALLENGE_RESPONSE` intake. Decrypt the challenge response
and HWID with the existing session encryption key, require the plaintext
challenge to match this exact retained server challenge and the normative
client type/version/detail layout, verify MACData over the plaintext response
data plus HWID, and stop before New License issuance until real
license-authority issuance material/policy is available. The parallel
`CLIENT_LICENSE_INFO` path still requires CAL trust/product/expiration/HWID
authorization. **M2/M3 remain OPEN / NOT ACCEPTED.**

## R3 Server Platform Challenge exact-SHA validation receipt (2026-10-16)

**Implementation:** `06ebfa7897b305b2b65eba85b29e0610779f6c00`.
**Actions:** `38971624372` — **SUCCESS**.

The exact implementation SHA passes the complete hosted matrix. Ubuntu/GCC
full CTest is **478/478 PASS Debug** and **478/478 PASS Release**.
macOS/Clang is **403/403 PASS Debug** and **403/403 PASS Release**.
Windows/MSVC focused native preflight is **48/48 PASS Debug** and
**48/48 PASS Release**, with full CTest **432/432 PASS Debug** and
**432/432 PASS Release**. Installed SDK downstream consumer is **1/1 PASS**
on Linux, macOS and Windows, and package/digest/artifact publication checks
pass.

All new R3 cases pass in every applicable hosted configuration:
`transport.licensing-server-platform-challenge-wire`,
`transport.licensing-server-platform-challenge-write-receipts`,
`transport.licensing-server-platform-challenge-write-denials`, and Linux
`security.gssapi-r3-server-platform-challenge-write-contract`.

R9 Clang ASan/UBSan is **PASS**. The bounded R1/R3
transport/CredSSP/licensing selection is **66/66 PASS**, including all three
new portable Platform Challenge cases. The native R2/R3 GSS selection is
**28/28 PASS**, including the new challenge publication authority contract.
Other configured R9 groups also pass, and the bounded fuzzer is **1/1 PASS**.
Documentation policy and the separate R7 macOS-session sanitizer job are
**PASS**. Untagged protocol prerelease publication is correctly **SKIPPED**.

The validated boundary is deliberately incomplete: the server can now publish
one cryptographically protected, receipt-bound Platform Challenge only after a
real `CLIENT_NEW_LICENSE_REQUEST` branch and fresh R2 reauthorization, but
R3 still does **not** accept/verify the client's Platform Challenge Response,
issue a CAL/New License, validate an existing CAL's trust/product/expiration,
emit `STATUS_VALID_CLIENT`, or enter Share activation. Canonical owner-local
`~/rdp-server/build/`, owner Linux/X11, Windows MSYS2 CLANG64/Clang 23,
macOS 27 and Microsoft-client end-to-end M2 remain **NOT RUN / OPEN**.

**Next R3:** implement the bounded protected
`CLIENT_PLATFORM_CHALLENGE_RESPONSE` verifier against the exact retained
challenge and current licensing keys, including decrypted response/HWID and
MAC verification, then stop before license issuance until authoritative
license-issuance policy/material exists. **M2/M3 remain OPEN / NOT ACCEPTED.**

## R3 protected Client Platform Challenge Response intake (2026-10-16; hosted CI pending)

**Reconciled shared-main parent:** `d78deb63f756ee902c57c4571be789e13e320260`.

R3 now implements the bounded inbound half of the standards-required platform
challenge exchange. After the receipt-bound `SERVER_PLATFORM_CHALLENGE` has
fully delivered, only one `CLIENT_PLATFORM_CHALLENGE_RESPONSE` can be
accepted. The pure verifier requires two
`BB_ENCRYPTED_DATA_BLOB (0x0009)` fields, decrypts each independently with
the already-derived licensing encryption key, requires the first plaintext to
be exactly the fixed R3 response-data size, and requires the HWID plaintext to
be exactly 20 bytes.

The decrypted Platform Challenge Response Data is checked before any state
advance: `wVersion == 0x0100`, client type is one of the four normative
values (Win32/Win16/WinCE/Other), license detail level is Simple/Moderate/Detail
(1..3), `cbChallenge` equals the retained challenge length, and
`pbChallenge` matches the exact challenge retained from the fully delivered
server packet using constant-time comparison. MACData is then verified in
constant time over the concatenation of the plaintext response-data and
decrypted HWID, as required by MS-RDPELE 2.2.2.5/2.2.2.5.1. Temporary
plaintext response, HWID, MAC input and digest buffers are cleansed before
return.

The licensing lifecycle exposes a dedicated
`onClientPlatformChallengeResponse` transition only from
`AwaitClientPlatformChallengeResponse /
AwaitPlatformChallengeResponse`. Success consumes the retained challenge and
public ServerRandom, returns the lifecycle to `AwaitServerDecision`, and
sets the explicit branch `NewLicenseIssuanceRequired`. Duplicate, wrong-order,
malformed, mismatched-challenge or bad-MAC input is terminal. Success is **not**
a license decision and creates no New/Upgrade License bytes.

The sole `McsSessionLifecycle` accepts the response only from its matching
`AwaitClientPlatformChallengeResponse` phase, with the exact bound HYBRID
provenance, fully joined global-I/O channel, begin|end MCS segmentation,
`SEC_LICENSE_PKT` envelope, retained derived keys, and the same provisioned
licensing credential fingerprint. Positive entry remains private to
`LinuxConsoleAdmissionBroker::authorizeR3ClientPlatformChallengeResponse`,
which freshly reauthorizes the concrete move-only native lease and exact R1
owner before the packet reaches R3.

New central-registry production-linked CTests:
`transport.licensing-client-platform-challenge-response-proof`,
`transport.licensing-client-platform-challenge-response-denials`, and
Linux-only
`security.gssapi-r3-client-platform-challenge-response-route-contract`.
All three are added to the existing bounded ASan/UBSan selectors; no new test
executable or duplicated state controller is introduced.

Canonical owner-local `~/rdp-server/build/` configure/build/full CTest is
**NOT RUN** in this connector environment. Exact-publication-SHA Linux/GCC,
macOS/Clang, Windows/MSVC Debug/Release, bounded sanitizer,
documentation-policy and SDK/package evidence are pending.

**Next R3:** implement a real New License / Upgrade License issuance decision
only when legitimate license-authority material and policy are available.
Until then do not emit a synthetic CAL, `STATUS_VALID_CLIENT`, Demand Active,
Share activation, graphics, input, clipboard or desktop authority. The
parallel `CLIENT_LICENSE_INFO` branch still requires CAL
trust/signature/product/expiration/HWID validation. **M2/M3 remain OPEN / NOT
ACCEPTED.**



## R10 licensing credential-file denial coverage (2026-10-16; exact-SHA CI pending)

Starting reconciled shared `main`: `4b72268e3e050a6855f28683ebe0b489aa79b385`. Review of the current
`RuntimeLicensingContext::configureFromCredentialFiles` boundary found that
the shared opened-file snapshot owner already enforces absolute paths, distinct
native file identities, owner-private key metadata and symlink/reparse
rejection, but licensing-specific coverage only exercised successful snapshot
retention and post-replacement freshness.

R10 now adds one production-backed
`runtime.licensing-context-secure-file-denials` CTest. It drives the actual
licensing context through the shared secure opener and requires terminal
one-shot failure with null identity/credential publication for the same native
object supplied as certificate and private key, a missing private key, a
relative private-key path, and a private key whose metadata violates the
platform policy. POSIX additionally exercises a final-component key symlink and
group-readable key; Windows grants Everyone read access to an otherwise
owner-controlled copied key and requires rejection through the opened-HANDLE
DACL check. No test uses real user credentials.

The test reuses the existing ephemeral R3 licensing RSA/X.509 fixture and
existing CMake driver; production credential ownership code is unchanged.
The bounded Clang ASan/UBSan licensing registry now explicitly requires and
runs the new case. This closes a licensing-call-site evidence gap without
adding a configuration schema, listener, R2 lease, licensing decision, Share
activation or alternate file owner.

Canonical owner-local `~/rdp-server/build` and owner platform commands are
**NOT RUN** in this connector environment. Exact-publication-SHA Linux/GCC,
macOS/AppleClang, Windows/MSVC, sanitizer, documentation-policy and SDK/package
evidence are required before PASS is claimed. Positive live composition
remains **BLOCKED on R2** while final CredSSP credential authorization is
deny-only; R10 must not connect licensing or a listener around a fabricated
lease. M2/M3 remain **OPEN / NOT ACCEPTED**.


## R1 Client Platform Challenge Response owned-TLS compatibility (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared `main`:** `12fafaa866bef4f4d2258ecf39a6f96a8e72a815`.

R3 now exposes the protected `CLIENT_PLATFORM_CHALLENGE_RESPONSE` intake
that the preceding R1 roadmap explicitly awaited. The complete production
boundary remains comfortably inside the existing transport contract: the
licensing PDU is 122 bytes, Enhanced-Security MCS user data is 126 bytes, and
the complete TPKT is 140 bytes, all below R1's existing 18 KiB
`kMaximumTlsApplicationIoBytes` ceiling. No R1 production API or buffer-size
change is required.

New default CTest
`transport.tcp-owned-r3-platform-challenge-response-read` reuses the sole
`OwnedPreauthTcpConnection` over a real ephemeral loopback TLS session. It
advances the production licensing lifecycle through a fully delivered Server
Platform Challenge, builds a cryptographically valid response for that exact
retained challenge and key material, then sends the complete protected TPKT in
two explicit TLS application writes. After the first 61 plaintext bytes R1
must return a zero-byte `NeedRead`; the same caller-owned suffix is then
resubmitted after bounded monotonic readiness polling. The completed plaintext
is parsed through the existing MCS and Enhanced-Security licensing envelope and
accepted by `onClientPlatformChallengeResponse`, which reaches only
`AwaitServerDecision / NewLicenseIssuanceRequired`.

A separate trailing TLS application record is sent before the second half is
drained and must remain untouched until a subsequent explicit R1 application
read. This proves exact caller-buffer boundaries as well as WANT retry
semantics without a second TLS reader, hidden retry loop, sleep, queue,
listener, authorization token or session owner. R9's bounded R1/R3
ASan/UBSan selector explicitly names and fail-closed checks the new case.

Canonical owner-local `~/rdp-server/build/` configure/build/full CTest is
**NOT RUN** in this connector environment; no alternate persistent build root
or branch was created. Exact publication-SHA Linux/GCC, macOS/AppleClang,
Windows/MSVC Debug/Release, bounded sanitizer, documentation-policy and
SDK/package evidence are pending. Owner Linux/X11, Windows MSYS2
CLANG64/Clang23, macOS 27, real license issuance and Microsoft-client
acceptance remain **NOT RUN**. **M2/M3 remain OPEN / NOT ACCEPTED.**

**Next R1:** add no transport surface unless R3's eventual protected New
License / Upgrade License publication or later Share activation demonstrates
a concrete bounded TCP/TLS mismatch.

## R3 Client Platform Challenge Response exact-SHA validation receipt (2026-10-16)

**Implementation:** `cd10f34e10c8676543adbeecd4b52a848a03c1ce`.
**Actions:** `38972322799` — **SUCCESS**.

Ubuntu/GCC full CTest is **485/485 PASS Debug** and **485/485 PASS Release**;
macOS/Clang is **409/409 PASS Debug** and **409/409 PASS Release**; Windows/MSVC
focused native preflight is **48/48 PASS Debug** and **48/48 PASS Release**,
with full CTest **439/439 PASS Debug** and **439/439 PASS Release**. The two
new portable challenge-response cases pass in all six hosted configurations;
Linux `security.gssapi-r3-client-platform-challenge-response-route-contract`
also passes in Debug/Release. R9 bounded R1/R3 is **69/69 PASS** and native
R2/R3 GSS is **29/29 PASS**, including all new R3 cases. Documentation policy,
SDK consumer/package checks and the R7 macOS-session sanitizer job pass.

This proves the protected challenge-response proof only. It adds no CAL
issuance authority, `STATUS_VALID_CLIENT`, Share activation or desktop
authority. Owner-local/native-client gates remain **NOT RUN / OPEN**.

## R3 bounded NEW_LICENSE_INFO plaintext serializer (2026-10-16; hosted CI pending)

**Reconciled shared-main parent:** `d0116485e53118c5312cd0a9f0d72a928510a7f6`.

The live New/Upgrade License decision remains blocked on legitimate
license-server issuance material and policy. The terminal-server licensing
certificate/private key remains only the RSA key-exchange credential and is
not repurposed as a CAL issuer.

R3 adds allocation-free `encodeRdpNewLicenseInformation` for MS-RDPELE
2.2.2.6.1. It serializes the immutable licensing identity's version, issuer
scope, company and product indexing values plus one opaque caller-provided CAL.
The CAL is capped at **16 KiB**; together with the existing 512-byte indexing
bounds and later wrapper overhead, a future encrypted grant remains below R1's
existing 18 KiB TLS application-write ceiling. All validation occurs before the
first write, so unconfigured identity, empty/oversized CAL and short output fail
without modifying caller storage.

This helper does not parse, trust, sign, issue, encrypt or MAC the CAL; it
does not mutate licensing state, create a receipt, invoke R2 or publish network
bytes. The byte-exact test CAL is explicitly synthetic opaque serialization
data, not a claimed valid license.

New central CTests:
`transport.licensing-new-license-info-wire` and
`transport.licensing-new-license-info-denials`. Both are selected by R9's
bounded R1/R3 ASan/UBSan gate.

Canonical owner-local `~/rdp-server/build/` validation is **NOT RUN** in
this connector environment. Exact-publication-SHA hosted Debug/Release,
sanitizer, documentation-policy and SDK/package evidence are pending.

**Next R3:** add a pure SERVER_NEW_LICENSE / SERVER_UPGRADE_LICENSE
encryption+MAC wrapper around caller-supplied authority-produced
NEW_LICENSE_INFO, still with no live transition. A receipt-bound live grant
must remain blocked until an explicit service owner supplies real
license-server issuance material/policy. Existing CLIENT_LICENSE_INFO remains
blocked on CAL signature/trust, product/version/expiration and HWID validation
before `STATUS_VALID_CLIENT`. **M2/M3 remain OPEN / NOT ACCEPTED.**



## R1 Client Platform Challenge Response exact-SHA validation (2026-10-16)

**Implementation:** `d98f96afc69ab6fadc0776db46731dddc4f52ee0`.  
**Actions:** [38972700952](https://github.com/k1moradi/RDP-server/actions/runs/38972700952) — **SUCCESS**.

The exact R1 transport-regression SHA is green across the hosted matrix. Linux/GCC
passes **487/487 Debug** and **487/487 Release** CTests; the new
`transport.tcp-owned-r3-platform-challenge-response-read` case runs as test
151 and passes in both configurations. macOS/AppleClang passes **411/411
Debug** and **411/411 Release**, again with the new case as test 151. Windows
native preflight passes **48/48** in both configurations and the full suite
passes **441/441 Debug** plus **441/441 Release**; the new R1 case passes as
test 151 in both.

R9 Clang ASan+UBSan is also **PASS**. The bounded R1/R3 MCS, CredSSP and
licensing selection passes **71/71**, explicitly discovers
`transport.tcp-owned-r3-platform-challenge-response-read`, and executes it as
selected test 151 with sanitizer instrumentation. The other bounded sanitizer
groups pass as well: clipboard **53/53**, portable R4 lifecycle **33/33**, R4
x264/BGRA **20/20**, R4 capability **4/4**, native R2/R3 GSSAPI **29/29**,
direct R10 runtime security **10/10**, native R5 X11 **27/27**, and the bounded
fuzzer **1/1**. The independent R7 macOS sanitizer job and documentation-policy
job pass.

Staged SDK install, downstream consumer **1/1**, package generation,
reproducible digest and artifact upload pass on Linux, macOS and Windows. The
run is untagged, so prerelease publication is correctly skipped.

This closes the R1 compatibility increment without changing production R1
source. The complete protected Client Platform Challenge Response remains a
140-byte TPKT inside the existing 18 KiB application-I/O boundary; the test
proves split TLS plaintext progress, zero-byte WANT retry with the same pending
span, exact R3 verification after reassembly, and preservation of a following
TLS application record. No second TLS reader, listener, authentication result,
licensing issuance, Share activation, session authority or Microsoft-client
acceptance is added.

Canonical owner-local `~/rdp-server/build/`, owner Linux/X11, Windows MSYS2
CLANG64/Clang23, macOS 27, real license-authority issuance and Microsoft-client
acceptance remain **NOT RUN**. **M2/M3 remain OPEN / NOT ACCEPTED.**

**Next R1:** add no transport surface unless R3's eventual protected New
License / Upgrade License publication or later Share activation demonstrates a
concrete bounded TCP/TLS mismatch.

### R7 macOS GUI-session revocation reaches native consumers

The process-scoped `NativeSessionChangeWatch` remains a monotonic revocation
signal, not an admission capability. `MacInputController` and
`MacScreenCaptureState` now pin the covered watch revision alongside their
existing display generation/topology facts. A changed or unavailable watch
revision terminally invalidates the old native lifetime even if user ID,
display bounds, topology and TCC evidence later look identical.

Input retirement deliberately distinguishes orderly shutdown from session
loss: held keys/buttons may be best-effort released only while both display and
GUI-session continuity are still current; after session loss they are discarded
without synthetic key/button-up posting. Capture rechecks continuity after
each synchronous preflight/prepare/start backend return before allowing a
subsequent native step or successful submission result, and checks it before
frame publication and after the synchronous R4 consumer returns. The latter fence
cannot undo bytes already observed inside an entered callback, but it prevents
a successful publication disposition, rejects later callbacks and reuses the
existing exact-once ScreenCaptureKit stop/deferred-close path. No new watcher,
thread, scheduler, capture owner or authorization object is introduced.


## R1 owned-TLS licensing write readiness hardening (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared `main`:** `47cb1a6e496ff5c62a2a27612e9cdbd9666ca76e`.

R1's two production-backed R3 licensing write regressions no longer use a
fixed 1 ms scheduler sleep after zero-byte TLS WANT. Both
`transport.tcp-owned-r3-license-request-slice` and
`transport.tcp-owned-r3-platform-challenge-slice` now preserve the exact
R3 reply/write-slice receipt and stable pending span, then call the existing
R1 `OwnedPreauthTcpConnection::pollSocketOnce` with a finite monotonic
deadline and `kMaximumTcpPollWait`.

The poller waits only for the exact `ioInterest()` direction recorded by the
failed SSL application write. In application mode it intentionally cannot
retry SSL I/O because R1 never retains caller memory; after matching readiness
the test explicitly resubmits the same logical R3 slice. `Dispatched` and
`NoEvent` are the only nonterminal poll results accepted, the returned
interest must remain the recorded WANT direction, and expiration is a hard
test failure rather than a hidden retry.

This is test-harness reliability only. No production transport API, TLS owner,
buffer bound, listener, queue, authorization result or licensing state changes.
Both named CTests are already in the bounded R9 R1/R3 ASan/UBSan selector.

Canonical owner-local `~/rdp-server/build/` configure/build/full CTest is
**NOT RUN** in this connector environment; no alternate persistent build root
or branch was created. Exact publication-SHA hosted Linux/GCC,
macOS/AppleClang, Windows/MSVC Debug/Release, sanitizer,
documentation-policy and SDK/package evidence are pending. Owner native
platform tests and Microsoft-client acceptance remain **NOT RUN**.
**M2/M3 remain OPEN / NOT ACCEPTED.**

**Next R1:** add no transport surface unless R3 lands a protected receipt-bound
New/Upgrade License publication or later Share activation that demonstrates a
concrete bounded TCP/TLS mismatch.

## R3 encrypted/MACed Server New/Upgrade License wrapper (2026-10-16; hosted CI pending)

**Reconciled shared-main parent:** `11009883c7adc33b9c2fc3c479ac7712e49b7f8b`.

R3 adds the roadmap's pure allocation-free grant wrapper:
`encodeRdpServerLicenseGrant` packages already-authority-produced
`NEW_LICENSE_INFO` as `SERVER_NEW_LICENSE` or
`SERVER_UPGRADE_LICENSE`, RC4-encrypts the exact plaintext with the derived
licensing key, and appends MS-RDPELE MACData over that plaintext.

The 16 KiB CAL cap plus bounded scope/company/product fields yields a maximum
17,940-byte plaintext and 17,964-byte wrapped grant, below R1's existing
18 KiB TLS application-write ceiling. A fixed contiguous scratch packet keeps
all rejection paths transactional.

This remains offline: no CAL validation/signing/issuance, policy decision,
lifecycle mutation, receipt owner, R2 authorization or network publication is
added. The terminal-server RSA key-exchange credential is not a CAL issuer.

New central CTests:
`transport.licensing-server-license-grant-wire` and
`transport.licensing-server-license-grant-denials`, both selected by the
bounded R1/R3 ASan/UBSan gate.

Canonical owner-local `~/rdp-server/build/` is **NOT RUN** here.
Exact-publication-SHA hosted Debug/Release, sanitizer, documentation-policy and
SDK/package evidence are pending.

**Next R3:** define the real licensing-authority result boundary and only then
add receipt-bound live New/Upgrade License publication behind fresh R2
authorization. `CLIENT_LICENSE_INFO` still requires CAL trust/signature,
product/version/expiration and HWID validation before
`STATUS_VALID_CLIENT`. **M2/M3 remain OPEN / NOT ACCEPTED.**



## R1 owned-TLS licensing write readiness exact validation (2026-10-16)

**Implementation:** `3404d1d5b239682265f6c3ac059c7f4328d62b98`.  
**Clean validating descendant:** `d60fd8c15ef9ff33a64a6ad004a985a285d3e24e`.  
**Actions:** `38974469401` — **SUCCESS**.

The implementation SHA itself could not start jobs because its reconciled parent
`47cb1a6e496ff5c62a2a27612e9cdbd9666ca76e` had already published malformed
R7 workflow YAML. Immediate R7 repairs restored workflow structure; the next
attempt then exposed an unrelated R2 test-header compile error inherited from
`a5651588b1b8b2697c63305515bc58807917c519`. R2 corrected that declaration
visibility and added its documentation receipt before the clean descendant run
above. Those failed runs are not treated as R1 validation evidence.

The R1 source under test is unchanged between the implementation and clean
validating descendant: subsequent changes touch CI/docs and other road-owned
tests, not `tests/test_owned_preauth_session.cpp`.

Hosted evidence on the clean descendant:
- Linux/GCC: **499/499 PASS Debug** and **499/499 PASS Release**.
  `transport.tcp-owned-r3-license-request-slice` and
  `transport.tcp-owned-r3-platform-challenge-slice` pass as tests 150/151 in
  both configurations.
- macOS/AppleClang: **423/423 PASS Debug** and **423/423 PASS Release**; the
  same two R1 cases pass as tests 150/151 in both configurations.
- Windows/MSVC: native preflight **51/51 PASS** in Debug and Release; full
  CTest **453/453 PASS Debug** and **453/453 PASS Release**, with the two R1
  cases passing as tests 150/151.
- R9 Clang ASan+UBSan bounded R1/R3 MCS, CredSSP and licensing selection:
  **74/74 PASS**. The two hardened write cases are explicitly selected and
  pass as selected tests 61/62 (central test IDs 150/151).
- Other sanitizer groups also pass: clipboard **58/58**, portable R4
  lifecycle **33/33**, R4 x264/BGRA **20/20**, R4 capability **4/4**,
  native R2/R3 GSS **29/29**, direct R10 runtime security **10/10**, native
  R5 X11 **30/30**, and bounded fuzzer **1/1**.
- Documentation policy, the R7 macOS-session sanitizer job, staged SDK,
  downstream consumer **1/1**, package generation, reproducible digest and
  artifact upload all pass. Untagged prerelease publication is correctly
  skipped.

This validates the test-harness change: zero-byte TLS WANT in the existing R3
license-request and platform-challenge writers now waits through R1's bounded
monotonic socket poller and explicitly resubmits the stable caller-owned slice;
no fixed scheduler sleep or fabricated both-directions readiness remains in
those paths. No production R1 source or transport surface changed.

Contemporaneous R3 `d2bb7f073ba796fa3eebc5352834ba0c5cf63d94` adds only the
offline encrypted/MACed New/Upgrade License wrapper. Its maximum wrapped grant
is **17,964 bytes**, below R1's existing 18 KiB application-write ceiling, and
it adds no receipt owner, R2 authorization or network publication. Therefore
it does not trigger another R1 transport increment yet.

Canonical owner-local `~/rdp-server/build/`, owner native platform tests,
real license-authority issuance and Microsoft-client acceptance remain
**NOT RUN**. **M2/M3 remain OPEN / NOT ACCEPTED.**

**Next R1:** when R3 adds receipt-bound live New/Upgrade License publication
behind real authority/R2 authorization, verify the final production slice
through the sole owned TLS writer. Otherwise wait for a live Share activation
boundary that demonstrates a concrete bounded transport mismatch.


## R1 owned-TLS application readiness hardening (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared `main`:** `77a03edcaf796268b35d567c64414cde65ffaaff`.

R1 removes the remaining fixed-sleep/fabricated-readiness pattern from two
production-backed owned-TLS application-I/O regressions. In
`transport.tcp-owned-tls-application-partial-write`, zero-byte
`SSL_ERROR_WANT_READ/WRITE` during the forced-fragment server write now waits
through `OwnedPreauthTcpConnection::pollSocketOnce` with a finite monotonic
deadline and asserts the exact `ioInterest()` direction before retrying. The
pending application read uses an independent finite deadline and the same
direction-preserving poll path instead of a 1 ms scheduler sleep.

`transport.tcp-owned-r3-connect-response-slice` now applies the same rule to
the existing R3 Connect Response receipt compatibility test. A zero-byte TLS
WANT preserves the exact reply sequence, write-slice sequence, data pointer and
remaining byte count; R1 then polls only the recorded readiness direction and
the caller explicitly resubmits the same stable pending slice. The test no
longer fabricates simultaneous readable+writable readiness with
`onSocketReady(true, true)` and no longer sleeps between retries.

This is test-harness determinism only. No production R1 transport source,
application-I/O bound, TLS owner, R2 authorization, MCS lifecycle or network
publication behavior changes. The existing
`transport.tcp-owned-r3-connect-response-slice` remains in R9's bounded
R1/R3 sanitizer selector; `transport.tcp-owned-tls-application-partial-write`
is now explicitly added and both names are fail-closed selector checks.

Canonical owner-local `~/rdp-server/build/` configure/build/full CTest is
**NOT RUN** in this connector environment; no alternate persistent build root
or branch is created. Exact publication-SHA Linux/GCC, macOS/AppleClang,
Windows/MSVC Debug/Release, bounded sanitizer, documentation-policy and
SDK/package evidence are pending. Owner native platform runs, real
license-authority issuance and Microsoft-client acceptance remain **NOT RUN**.
**M2/M3 remain OPEN / NOT ACCEPTED.**

**Next R1:** when R3 adds receipt-bound live New/Upgrade License publication
behind legitimate authority and fresh R2 authorization, verify that final
production slice through the sole owned TLS writer. Otherwise wait for a live
Share-activation boundary that demonstrates a concrete bounded transport
mismatch.

## R3 encrypted New/Upgrade License transport-bound correction (2026-10-16; exact-SHA CI pending)

**Reconciled shared-main parent:** `0a376216a88733082926c49b3932f70d80af2133`.

The earlier pure grant wrapper at
`d2bb7f073ba796fa3eebc5352834ba0c5cf63d94` established the correct
SERVER_NEW_LICENSE / SERVER_UPGRADE_LICENSE cryptographic wire skeleton, but
follow-up audit against the current R3 assignment found two material boundary
gaps. It accepted already-serialized plaintext instead of reusing
`encodeRdpNewLicenseInformation` from the supplied identity/CAL, and its
17,964-byte worst-case packet proof considered only R1's 18 KiB TLS
application-write ceiling. A single unfragmented T.125 SendData userData field
is limited to 16,383 bytes, of which Enhanced Security consumes four bytes for
the Basic Security Header.

The corrected standalone encoder now receives an explicit
`RdpServerLicenseGrantKind`, configured `RdpServerLicenseIdentity`, opaque
caller-supplied CAL, and borrowed `RdpLicensingKeyMaterialView`. It invokes
the existing NEW_LICENSE_INFO serializer internally, MACs the complete
plaintext with the existing licensing MAC, RC4-encrypts exactly that plaintext
with the existing licensing cipher, and emits one BB_ENCRYPTED_DATA_BLOB
(0x0009) followed by exactly 16 bytes of MACData. Unsupported enum values,
unconfigured identity, empty/oversized CAL, non-16-byte key spans and short
output fail before caller output changes. Temporary plaintext, ciphertext
scratch and MAC storage are explicitly cleansed; caller CAL/key spans are never
retained.

The existing standalone NEW_LICENSE_INFO CAL ceiling remains 16 KiB. For this
eventual wire wrapper, the conservative always-transportable CAL ceiling is
**14,799 bytes** with all three identity strings at their 512-byte configured
maxima. The corresponding maximum NEW_LICENSE_INFO plaintext is **16,355
bytes**, the complete licensing packet is **16,379 bytes**, and adding the
four-byte Basic Security Header reaches exactly the T.125 unfragmented userData
limit of **16,383 bytes**. The existing 15-byte long TPKT/X.224/MCS
SendDataIndication header gives a maximum R1 TLS plaintext application write of
**16,398 bytes**, safely below `kMaximumTlsApplicationIoBytes` (**18,432
bytes**). A compile-time assertion binds that proof to R1's actual constant;
R1 is not enlarged.

Five dedicated central CTests replace the earlier coarse pair:
`transport.licensing-server-new-license-wire`,
`transport.licensing-server-upgrade-license-wire`,
`transport.licensing-server-license-grant-encode-denials`,
`transport.licensing-server-license-grant-transactional-output`, and
`transport.licensing-server-grant-no-live-publication`. The New/Upgrade
cases use an independently fixed 71-byte encrypted/MACed oracle and decrypt it
back to the exact 47-byte NEW_LICENSE_INFO plaintext; the denial matrix covers
invalid grant kind, unconfigured identity, empty/oversized CAL, truncated or
missing key material, output bounds and the exact maximum envelope. The
transactional case proves failures leave a sentinel buffer untouched and
success does not modify excess capacity. The no-publication case proves a
synthetic opaque CAL cannot mutate licensing/session state or bypass the public
MCS admission boundary. All five are fail-closed entries in the bounded R1/R3
ASan/UBSan selector.

This remains a pure offline protocol encoder. It does **not** validate, sign or
issue a CAL; confer issuer trust; create a licensing decision; create a write
receipt; invoke R2; publish network bytes; mark a client licensed; enter Share
activation; or use the terminal-server key-exchange private key as a CAL issuer.
A future live grant still requires an audited licensing authority/result,
legitimate CAL material and fresh R2 authorization.

Canonical owner-local `~/rdp-server/build/` configure/build/full CTest is
**NOT RUN** in this connector environment because the synchronized owner
checkout is unavailable and no alternate persistent build root was created.
Exact-publication-SHA Linux/GCC, macOS/Clang, Windows/MSVC Debug/Release,
bounded R9 sanitizer, documentation-policy and SDK/package evidence are
pending.

**Next R3:** audit the real CAL validation/issuance authority boundary before
any receipt-bound live New/Upgrade publication or STATUS_VALID_CLIENT.
CLIENT_LICENSE_INFO still requires issuer trust/signature, product/version,
expiration/upgrade policy and CAL-to-client hardware authorization. M1
owner-machine evidence and M2/M3 remain **OPEN / NOT ACCEPTED**.

## R3 licensing-authority grant snapshot boundary (2026-10-16; hosted CI pending)

**Reconciled shared-main parent:** `74b5fb33484e961479a652204d35864ecfc77fd8`.

R3 now defines the roadmap's next non-live licensing-authority result boundary
without treating arbitrary CAL bytes as a session decision.
`RdpLicensingAuthorityGrant` is a one-shot, noncopyable, fixed-storage
snapshot containing one New/Upgrade grant kind, one bounded CAL, a nonzero
authority generation, and one fixed 32-byte opaque authority fingerprint.
Caller storage is copied into contiguous owned memory and cannot replace a
result after the first configure attempt.

The CAL bound is the corrected live-safe grant limit of **14,799 bytes**, not
the larger 16 KiB standalone `NEW_LICENSE_INFO` test/serializer ceiling. It
therefore remains compatible with the existing one-PER-fragment proof:
complete licensing PDU **16,379 bytes**, plus the four-byte Basic Security
Header **16,383 bytes**, with the full long MCS/TLS plaintext still below R1's
existing 18 KiB write bound.

The generation/fingerprint pair is correlation only, not proof that a caller
is a licensing authority. `matchesAuthority` requires the exact nonzero
generation and compares the fixed fingerprint in constant time, allowing a
future service authority owner to reject stale results after policy/material
rotation. Zero generation, wrong-sized or all-zero fingerprint, empty CAL,
invalid grant kind, and a CAL beyond 14,799 bytes fail closed.

This boundary intentionally has **no** lifecycle mutation, receipt owner, R2
entry point, or network publication. A captured CAL can feed the existing pure
New/Upgrade License encoder, but the snapshot itself cannot license a client or
advance `RdpLicensingLifecycle`. Live New/Upgrade publication remains blocked
until R10 owns a real issuance provider and R2 freshly authorizes both
publication and accepted-byte completion against current authority correlation.

New central production-linked CTest:
`transport.licensing-authority-grant-boundary`. It proves fixed ownership,
one-shot replacement denial, stale authority correlation denial, invalid
generation/fingerprint/kind/CAL rejection, composition with the corrected
offline grant encoder, and zero licensing-state advance. The bounded R1/R3
ASan/UBSan selector explicitly requires this case.

Canonical owner-local `~/rdp-server/build/` configure/build/full CTest is
**NOT RUN** in this connector environment. Exact-publication-SHA Linux/GCC,
macOS/Clang, Windows/MSVC Debug/Release, bounded sanitizers,
documentation-policy, and SDK/package evidence are pending.

**Next R3:** once a concrete R10 licensing-authority owner can supply this
snapshot with a freshly verifiable generation/fingerprint, add a receipt-bound
live New/Upgrade License writer behind fresh R2 authorization. The parallel
`CLIENT_LICENSE_INFO` path still requires real CAL signature/trust,
product/version/expiration and HWID validation before any
`STATUS_VALID_CLIENT` or Share activation. **M2/M3 remain OPEN / NOT
ACCEPTED.**



## R4 client decode-backlog observation boundary (2026-10-16)

`GfxFrameAckWindow` remains the sole RDPGFX ACK-state owner.
`GfxPresentationLifecycle` exposes read-only
`expectingFrameAcknowledgements()`, `clientQueueDepthAvailable()` and
`clientQueueDepthBytes()`. The value is the most recent valid finite client
`queueDepth`; zero explicitly means unavailable, while suspension clears the
value and disables ACK expectation. These are facts for R4's one future frame
scheduler, not a second scheduler or a throttle policy.

## R3 authority-correlated New License receipt gate (2026-10-16; hosted CI pending)

**Reconciled shared-main parent:** `4ec2b8c5ece830e28427c8501b98ff943465372b`.

R3 now has the receipt owner needed for a future live authority-issued New
License without prematurely treating a caller-provided snapshot as licensing
authority. `RdpServerLicenseGrantWriteGate` is intentionally **not** embedded
in `McsSessionLifecycle` and has no R2 broker entry point in this increment.
It can therefore exercise the production packet/receipt/lifecycle boundary
without creating a live publication capability before R10 owns a real licensing
authority.

The gate accepts only an already-configured
`RdpLicensingAuthorityGrant` whose nonzero generation and fixed 32-byte
fingerprint exactly match the caller's current authority correlation. It also
requires the immutable server-license identity, already-derived licensing keys,
and a lifecycle that has cryptographically reached
`NewLicenseIssuanceRequired`. The current live-eligible branch is
`NewLicense` only; `UpgradeLicense` remains offline because the parallel
`CLIENT_LICENSE_INFO` trust/signature/product/expiration decision is still
unimplemented.

One stable contiguous encrypted/MACed SERVER_NEW_LICENSE packet is retained
through zero-byte backpressure and positive partial writes. Reply and
write-slice receipts remain nonzero and monotonic; positive partial progress
rotates only the slice receipt. Stale/duplicate receipts, over-report, wrong
phase, wrong grant kind, stale authority correlation or invalid encoding close
the lifecycle. Only exact full accepted-byte delivery invokes the private
lifecycle transition and moves `RdpLicensingPhase` to `Licensed`; merely
queueing or partially sending a grant never licenses the connection.

Dedicated central CTests:
`transport.licensing-server-license-grant-write-receipts` and
`transport.licensing-server-license-grant-write-denials`. Both are selected
by the bounded R1/R3 ASan/UBSan licensing gate. They cover stable WANT
resubmission, partial-slice rollover, exact completion, stale authority
fingerprint, Upgrade-on-New branch denial, wrong phase, stale receipt,
over-report and duplicate completion.

This is still **not live publication**. R10 currently provides administrator
licensing credential/product preflight but not a CAL-issuing authority owner;
R2 therefore receives no new API and cannot publish this gate. The existing
authority snapshot is correlation evidence only and remains insufficient by
itself to mint a licensed session.

Canonical owner-local `~/rdp-server/build/` configure/build/full CTest is
**NOT RUN** in this connector environment. Exact-publication-SHA Linux/GCC,
macOS/AppleClang, Windows/MSVC Debug/Release, R9 sanitizer,
documentation-policy and SDK/package evidence are pending.

**Next R3:** once R10 exposes a concrete licensing-authority owner that returns
the snapshot together with freshly verifiable generation/fingerprint, embed
this gate in the sole R3 session and let R2 freshly authorize every grant slice
and accepted-byte completion. Separately, `CLIENT_LICENSE_INFO` still needs
real CAL trust/signature, product/version/expiration and HWID validation before
any STATUS_VALID_CLIENT path. Share activation remains blocked until one of
those standards-correct licensing completions is live. **M2/M3 remain OPEN /
NOT ACCEPTED.**

## R3 grant receipt-gate compile-order correction (2026-10-16)

The authority-correlated New License receipt-gate implementation remains
unchanged from `525e235e1cc86ae978cf910020511bfcba4f4338`. Its first exact-SHA
hosted run exposed a macOS/AppleClang test compilation error only: the new
`advanceToNewLicenseIssuance` helper referenced the existing
`makeClientPlatformChallengeResponse` fixture before that fixture's later
definition in the same translation unit.

Correction `83d05e8076982545e57b75b78f5f5b212ddde865` adds the explicit
forward declaration and passes all five arguments at the earlier call site.
There is no production source, packet encoding, authority correlation,
receipt-accounting or lifecycle behavior change.

The correction's first hosted workflow correctly failed documentation policy
because that implementation-fix commit lacked a Markdown co-change; this
section supplies the required policy receipt for the corrected-source
descendant. Platform, sanitizer and full CTest results for the corrected source
remain pending and must be recorded only after their exact workflow completes.

