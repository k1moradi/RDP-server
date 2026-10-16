## R8 Linux bounded file-descriptor destination (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared main:** `dd59f8a71ee921261b1a6346404676abb1c28750`. The existing `RemoteTransfer`
FileGroupDescriptorW/FileContents/Lock owner remains authoritative. This
increment adds only a Linux native destination child; it does not add an RDP
writer or authorization path.

The child duplicates one caller-selected writable regular-file descriptor with
`F_DUPFD_CLOEXEC` and streams already-parsed current-generation FileContents
RANGE results directly with bounded `pwrite`. Remote FILEDESCRIPTORW names
are metadata only and are never resolved into local paths. Read-only,
non-regular and `O_APPEND` descriptors are rejected. No whole-file cache or
second range queue is introduced.

It exposes SIZE/RANGE request intents and binds the exact existing
`FileContentsRequestReceipt`; it serializes/sends no CLIPRDR. Unknown size is
resolved with the existing SIZE request, range intents stay at or below 64 KiB,
and borrowed response bytes are consumed synchronously. Completion requires the
exact byte count, final `ftruncate`, `fsync`, and closure of only the
duplicated fd. Until then the destination must not be published to a consumer.
Generation replacement, cancellation, remote failure and native I/O failure
truncate the partial file before closing where possible.

This first destination is current-generation/unlocked only. Directory-tree
materialization, URI/portal/file-manager handoff, authenticated Microsoft-client
file copy, Windows/macOS file destinations and performance remain OPEN/NOT RUN.

Dedicated Linux CTests are
`clipboard.linux-file-destination-streaming`,
`clipboard.linux-file-destination-size-cancel`, and
`clipboard.linux-file-destination-denials`. Canonical owner-local
`~/rdp-server/build` execution is NOT RUN in this connector environment;
exact-SHA hosted CI and sanitizer evidence are pending.

**Next R8:** validate this descriptor sink under hosted CI, then add a real
Linux file-manager/portal or equivalent completed-file handoff without exposing
partial files or bypassing R3's sole authorized CLIPRDR writer.

## R2 reauthorized Server License Request publication (2026-10-16; exact-SHA CI pending)

**Reconciled shared-main parent:** `d57f3df6d8543e327165adf0f547aca5e54ebe74`.

R3 now owns a bounded receipt-tracked `SERVER_LICENSE_REQUEST` serializer,
which creates the next protected publication boundary after accepted Client
Info. R2 binds that writer into the sole `McsSessionLifecycle`: the licensing
write gate is no longer an independently supplied lifecycle for production
session progression. `LinuxConsoleAdmissionBroker` revalidates the concrete
move-only lease, exact R1 HYBRID/TLS owner, GSS identity, policy generation,
NSS/logind fingerprint and native session watch immediately before exposing
each pending licensing slice and again before accepting every write receipt.

Caller-provisioned server random/product/scope fields remain serialization
inputs only. R2 does not infer CSPRNG provenance or licensing authority from
their syntax, and the current deny-only final CredSSP credential policy still
cannot mint a native admission lease. Receipt sequence numbers, slice numbers,
accepted-byte counts or a separately completed production licensing writer
cannot substitute for that lease.

Dedicated production-linked CTest
`security.gssapi-r3-server-license-request-write-contract` uses a real
`RdpServerLicenseRequestWriteGate` to obtain genuine monotonic receipt values,
then proves those values cannot advance a fresh R3 owner through the R2
completion API without the unforgeable lease/original R1 owner. Denial closes
R3 licensing first and then revokes R2/GSS; replay remains terminal. The case
is included in R9's native GSS ASan/UBSan selection.

Canonical owner-local `~/rdp-server/build/` configure/build/full CTest is
**NOT RUN** because this connector environment exposes no synchronized owner
checkout; no alternate build root was created. Exact-publication-SHA hosted
Linux/GCC, macOS/Clang, Windows/MSVC Debug/Release, R9 sanitizer,
documentation policy and SDK/package evidence are **PENDING**.

Genuine positive Kerberos/final-CredSSP authorization, NSS/logind lease
issuance, legitimate licensing provisioning/cryptography and Microsoft-client
acceptance remain **NOT RUN / OPEN**. **M2/M3 remain OPEN / NOT ACCEPTED.**

**Next R2:** apply the same fresh protected-transition authorization to R3's
future client licensing intake and subsequent licensing/activation writers as
those production transitions become available; never treat licensing syntax
or delivery receipts as authentication capability.

## R9 CredSSP completed-frame cancellation and licensing sanitizer exact-SHA validation (2026-10-16)

**Implementation:** `9c4888a088bb71ad30e04cfeeaf09d159c38550f`  
**GitHub Actions:** `38911169939` — **SUCCESS**  
**Validation-receipt parent:** `a158d9ce12504fc9efbdd7feb9ab31dabee3effb`

Exact implementation-SHA hosted results:

- Linux/GCC Debug: **429/429 PASS**.
- Linux/GCC Release: **429/429 PASS**.
- macOS/Clang Debug: **362/362 PASS**.
- macOS/Clang Release: **362/362 PASS**.
- Windows/MSVC focused native-adapter Debug: **39/39 PASS**.
- Windows/MSVC focused native-adapter Release: **39/39 PASS**.
- Windows/MSVC full Debug: **386/386 PASS**.
- Windows/MSVC full Release: **386/386 PASS**.
- Documentation policy: **PASS**.
- R9 ASan/UBSan sanitizer selections: clipboard **46/46**, x264 **18/18**,
  bounded R1/R3 transport/CredSSP/licensing **33/33**, native GSS/R2/R3
  **25/25**, R10 Linux runtime CredSSP **4/4**, native X11 **23/23**, bounded
  MCS/CLIPRDR fuzzer **1/1**.
- The new
  `security.gssapi-r1-owned-completed-frame-cancellation-fence` executed from
  the production-linked `test_owned_preauth_session` binary and passed under
  ASan/UBSan/LSan.
- R3's newly landed
  `transport.licensing-server-request-wire`,
  `transport.licensing-server-request-write-receipts`, and
  `transport.licensing-server-request-write-denials` all executed in the
  bounded sanitizer group and passed.
- Linux, macOS and Windows installable SDK staging, downstream CMake
  package/link/execution, ZIP packaging, reproducible digest generation and
  artifact upload all **PASS**; each downstream consumer CTest is **1/1 PASS**.
- `publish-protocol-prerelease` is **SKIPPED**, not a passing Release stage.

The cancellation regression proves a completed owner-bound TSRequest cannot
retain usable TLS provenance after the exact R1 owner is cancelled:
`completedFrameServerTls()` returns null before stale SSL use, R2 returns
`TransportClosed`, retained DER/reader/writer/GSS state is wiped/failed, and
replay remains terminal. No positive GSS identity, final-credential
authorization, native admission lease, logind authorization or R3 capability
is fabricated.

Canonical owner-local `~/rdp-server/build/` execution remains **NOT RUN** in
this connector environment because no synchronized owner checkout is exposed.
Owner Linux/X11, Windows MSYS2 CLANG64/Clang 23, macOS 27, real
Kerberos/logind admission and Microsoft-client acceptance remain separately
required **NOT RUN/OPEN** gates. **M2/M3 remain OPEN.**

## R9 post-landing CredSSP cancellation and licensing sanitizer fence (2026-10-16; exact-SHA CI pending)

**Starting/reconciled main:** `5316531a451be9d5454cf43621b83089e18f0aaa`. The latest completed combined-state
hosted baseline inspected before authoring is `fb265c38abcd020e233b6202b0ff0d7f6c7fd5c2`,
Actions `38909145581`: R9 sanitizer groups pass clipboard **46/46**, x264
**18/18**, bounded R1/R3 transport/CredSSP/licensing **30/30**, native
GSS/R2/R3 **24/24**, R10 Linux runtime CredSSP **4/4**, native X11 **23/23**
and the bounded fuzzer **1/1**.

R9 re-audited the completed Channel Join terminal replay work and the newer R1
HYBRID/R2 final-CredSSP seam. The existing R1 cancellation fence cancels before
R2 holds a completed owner-bound TSRequest. A distinct lifetime boundary
remained unnamed: R1 may be cancelled after `TsRequestFrameReader` has already
completed a TLS-derived frame and retained its borrowed SSL identity. New
production-backed CTest
`security.gssapi-r1-owned-completed-frame-cancellation-fence` reuses
`test_owned_preauth_session`, a real loopback HYBRID/TLS
`OwnedPreauthTcpConnection`, `TsRequestFrameReader`,
`TsRequestTlsReplyWriter` and `GssapiSpnegoAcceptor`.

After `OwnedPreauthTcpConnection::cancel()`, the live SSL and immutable
negotiation provenance are gone. The completed reader must report no
`completedFrameServerTls()` rather than dereference the retired SSL; the next
R2 owner-driven advance must return `TransportClosed`, close/wipe the retained
DER, reader, writer and GSS acceptor, and repeated advance remains terminal.
No GSS success, public-key binding, delegated credential, native admission
lease, logind authorization or R3 capability is fabricated.

R3 commit `c80febfbb0a46327d637b541bb10abf96cf77837` also landed three
production-linked `SERVER_LICENSE_REQUEST` cases after the last R9 sanitizer
receipt: `transport.licensing-server-request-wire`,
`transport.licensing-server-request-write-receipts`, and
`transport.licensing-server-request-write-denials`. They were centrally
registered but absent from the bounded R1/R3 licensing sanitizer regex. R9 adds
all three to that existing selector without changing R3 production behavior.
Relative to the completed baseline, the bounded transport selection is expected
to grow from **30 to 33** and the native GSS selection from **24 to 25**; these
counts are registration expectations until exact-SHA execution confirms them.

The existing ASan/UBSan settings, 60-second CTest cap, and GSS-only MIT krb5
LSan suppression are unchanged. Canonical owner-local `~/rdp-server/build/`
configure/build/full CTest is **NOT RUN** in this connector environment because
no synchronized checkout is available; exact-publication-SHA hosted validation
is required before recording a pass. Owner Linux/X11, Windows MSYS2
CLANG64/Clang 23, macOS 27, real Kerberos/logind admission and Microsoft-client
acceptance remain separate **NOT RUN/OPEN** gates. **M2/M3 remain OPEN.**

## R8 macOS ready-data pasteboard exact-SHA hosted validation (2026-10-16)

**Implementation:** `4da8d0deab5e3d7a251fdd4c180a6380c1e4e978`.
**Actions:** [38908531302](https://github.com/k1moradi/RDP-server/actions/runs/38908531302) — **SUCCESS**.

The complete hosted matrix is green. Ubuntu/GCC full CTest is **416/416
PASS** in Debug and **416/416 PASS** in Release. macOS/Clang is **357/357
PASS** in Debug and Release, compile/linking the Apple-only Objective-C++
AppKit bridge in both configurations. Windows/MSVC focused native preflight is
**39/39 PASS** in both configurations and full CTest is **381/381 PASS** in
Debug and Release. The downstream installed-SDK consumer, package/artifact
steps and documentation-policy job all pass.

All five new production-linked R8 cases pass on Linux, macOS and Windows:
`clipboard.macos-clipboard-remote-ready-publication`,
`clipboard.macos-clipboard-generation-owner-loss`,
`clipboard.macos-clipboard-png-routing`,
`clipboard.macos-clipboard-disconnect-owner-fence`, and
`clipboard.macos-clipboard-failure-reentry-denials`. R9 Clang ASan/UBSan
clipboard coverage is **46/46 PASS**, including those five cases. The same
sanitizer job also passes its bounded transport/security **18/18**, native
GSS/R2/R3 **30/30**, runtime **24/24**, native X11 **16/16**, auxiliary
selected group **4/4**, and bounded CLIPRDR fuzzer **1/1**.

This evidence validates deterministic ready-data state, cross-platform C++23
builds and Apple SDK compile/link coverage only. Canonical owner-local
`~/rdp-server/build`, owner macOS 27 live pasteboard use, Windows
MSYS2 CLANG64/Clang23, authenticated Microsoft-client CLIPRDR, native
file-manager destinations and clipboard performance remain **NOT RUN/OPEN**.
No live user pasteboard was read or modified by ordinary CTest. R3 remains the
sole future post-admission CLIPRDR payload writer.

**Next R8:** bounded native file-destination integration, without introducing
a second transfer owner, whole-file cache, transport writer or authentication
shortcut.

## R8 macOS ready-data pasteboard presentation (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared main:** `1cbb068c4dd7b0b9b2b8065244ba650b71676005`. The bounded
FILEDESCRIPTORW/FileContents Lock/Unlock owner and the hosted-validated Windows
ready-data adapter remain unchanged. The live roadmap's next R8 native
presentation increment is implemented as a separate noninstalled
`MacClipboardAdapter` while `RemoteTransfer` remains the sole clipboard
generation, verified-content and request-correlation owner.

The adapter publishes only current-generation data that R8 already validated:
normalized UTF-8 text as the native string representation and a genuinely
registered/validated PNG as `NSPasteboardTypePNG`. CF_DIB/CF_DIBV5 are not
relabelled as PNG and no image decode/conversion or file-body cache is added.
Publication is immediate-data-only and performs no CLIPRDR request or wait.

Native ownership is fenced by AppKit's monotonic pasteboard `changeCount`.
After a successful replacement R8 records the observed count; any later
mismatch yields that remote generation and prevents same-generation reclaim.
Generation replacement clears stale remote data only when the recorded count
still proves R8 owns the pasteboard. Disconnect follows the same rule and
therefore cannot erase a newer local application's clipboard. Failed ownership
observation is terminal and does not speculate by clearing native contents.

Dedicated production-linked CTests are
`clipboard.macos-clipboard-remote-ready-publication`,
`clipboard.macos-clipboard-generation-owner-loss`,
`clipboard.macos-clipboard-png-routing`,
`clipboard.macos-clipboard-disconnect-owner-fence`, and
`clipboard.macos-clipboard-failure-reentry-denials`. They inject the native
operation seam on every hosted OS and never access the host pasteboard. Apple
builds additionally compile/link the dormant AppKit implementation. The R9
clipboard sanitizer target list explicitly builds this executable before the
existing all-`clipboard` selection.

Canonical owner-local `~/rdp-server/build` configure/build/full CTest is
**NOT RUN** because this connector environment does not expose that checkout;
no alternate build root was created. Exact-publication-SHA Linux/GCC,
macOS/Clang, Windows/MSVC Debug/Release, R9 ASan/UBSan clipboard coverage,
documentation policy and downstream package/consumer evidence are **PENDING**.
No live macOS pasteboard, Windows App/Microsoft client, authenticated R3
CLIPRDR writer, file-manager destination, owner macOS 27 or performance test
is claimed.

**Next R8 after hosted validation:** continue bounded native file-destination
integration while R3 completes the authoritative post-admission CLIPRDR
payload writer. Native fetch intents must not bypass that authority.

## R1 HYBRID CredSSP-before-MCS exact-SHA hosted validation (2026-10-16)

Validated R1 implementation/fix SHA
`010d3b6e34bb36a01cd24424a2a6474b9d279e0a`, Actions `38907600714`,
overall **SUCCESS**. The preceding implementation SHA
`8b80bc7d2916e80bc11af9be71070f544795c0ef` reached the R1 production
sources on macOS but its new test translation unit failed only because the
existing test-only `substituteCredSspReplyCertificate` helper was defined
below its first new call. The follow-up added the matching forward declaration;
production transport behavior was unchanged.

Hosted protocol matrix on the corrected exact SHA:

- Linux/GCC: **410/410 Debug PASS**, **410/410 Release PASS**; configured SDK
  consumer, package and artifact steps PASS.
- Windows/MSVC: native R6 preflight **39/39 PASS** before each configuration,
  then **376/376 Debug PASS** and **376/376 Release PASS**; configured downstream
  SDK/package steps PASS.
- macOS/AppleClang: **352/352 Debug PASS**, **352/352 Release PASS**; configured
  downstream SDK/package steps PASS.
- The three new R1 cases
  `transport.tcp-owned-hybrid-credssp-first-record`,
  `transport.tcp-owned-hybrid-no-premature-mcs`, and
  `transport.tcp-owned-hybrid-provenance-revocation` PASS in every hosted
  Debug/Release matrix leg.
- R9 sanitizer job: clipboard **41/41 PASS**, R4 x264/BGRA **18/18 PASS**,
  bounded R1/R3 MCS/CredSSP/licensing **30/30 PASS** (including all three new
  HYBRID cases), native R2/R3 GSSAPI **23/23 PASS**, R10 Linux runtime CredSSP
  **4/4 PASS**, R5 X11 **16/16 PASS**, bounded fuzzer **1/1 PASS**.
- Documentation policy PASS.

The earlier P0 fixture repair remains separately validated at
`8dc5cfd962f9432d4aaf3ac3c552ddb8fed172d7` / Actions `38897048825`.
A subsequent R2 descendant may add stricter final-CredSSP admission denial, but
R1 still does not expose an authenticated-to-MCS transition API or claim R2/R3
authority.

The connector environment has no owner `~/rdp-server` checkout, so the
canonical owner-local build command was **NOT RUN** here. Owner Linux/X11,
Windows MSYS2 CLANG64/Clang23, macOS 27, genuine Kerberos/logind admission and
a current Microsoft RDP client remain separate **NOT RUN** acceptance gates.
HYBRID/TLS/DER success is not authentication evidence. **M2 remains OPEN /
NOT ACCEPTED.**

## R2 final-CredSSP admission fence and owned authInfo denial (2026-10-16; exact-SHA CI pending)

**Reconciled publication parent:** `010d3b6e34bb36a01cd24424a2a6474b9d279e0a`.

The MS-CSSP sequence audit found a real completion-boundary gap in the
otherwise owner-bound R2 path. `BindingVerified` is emitted only after the
real Kerberos mechanism, client public-key proof and the full R1-owned server
binding reply have completed, but the protocol still requires the client final
encrypted `authInfo` afterward. `LinuxConsoleAdmissionBroker::issue()` was
using that binding-level principal as its positive identity prerequisite, so a
matching native NSS/logind policy could make binding completion look stronger
than the currently supported CredSSP credential policy.

R2 now preserves `verifiedPrincipal()` and
`verifiedPrincipalForOwnedConnection()` as narrow binding-level diagnostics,
but native issuance/revalidation uses a private R2 completion proof instead.
That proof has no caller-facing setter and the current deny-only delegated
credential policy never sets it. Positive `LinuxConsoleAdmissionLease`
issuance is therefore deliberately unreachable until a separately reviewed
final-credential authorization policy exists.

The existing `advanceOwnedCredSspHandshake()` is also the sole post-binding
provider handoff. `BindingVerified` is one-shot: the next frame must come
through the same R1 `OwnedPreauthTcpConnection`, reader and writer, with the
same HYBRID provenance, TLS certificate and CredSSP version. Only a bounded
`finalAuthInfoOnly()` shape is routed to
`consumeFramedAndDenyDelegatedCredentials()`; that existing path performs
the real GSS confidential unwrap attempt, bounded metadata inspection, secure
plaintext/frame cleanup and terminal provider teardown. R2 then returns
`UnsupportedFinalCredentials`; this is an explicit deny-only policy outcome,
not proof that credential plaintext was valid or authorized. Malformed,
mixed, oversized, stale or wrong-version frames remain terminal
`Rejected`. R10 maps the unsupported outcome and revokes the aggregate; no
listener or R3 capability is added.

Dedicated default Linux CTest
`security.gssapi-credssp-authinfo-terminal-denials` exercises genuine
R1-owned HYBRID/TLS intake and early final-authInfo rejection without
fabricating GSS success. The opt-in real-provider suite gains
`security.gssapi-credssp-public-key-not-native-admission` and
`security.gssapi-real-kerberos-owned-authinfo-denial`; they require the
existing externally provisioned service keytab and client FILE cache and are
not enabled in ordinary hosted CI. The new default denial case is added to
R9's bounded native GSS ASan/UBSan selection.

Canonical owner-local `~/rdp-server/build/` configure/build/CTest is
**NOT RUN** here because this execution environment has no usable synchronized
checkout and shell GitHub DNS resolution fails; no alternate build root was
created. Hosted exact-publication-SHA validation is pending. Real Kerberos
positive execution, positive NSS/logind admission, owner Linux/X11,
MSYS2 CLANG64/Clang23, macOS 27 and Microsoft-client acceptance remain
**NOT RUN**. **M2/M3 remain OPEN.**

## R1 HYBRID phase compile follow-up (2026-10-16; hosted CI pending)

Exact implementation SHA `8b80bc7d2916e80bc11af9be71070f544795c0ef`, Actions
`38907356523`, reached the production R1 sources successfully on macOS but the
new test translation unit failed because
`substituteCredSspReplyCertificate` was defined later in the file without a
prior declaration. This is test declaration order only; no production transport
behavior changes. The follow-up adds the matching test-only forward declaration
and retains all HYBRID/CredSSP assertions unchanged. Exact follow-up-SHA hosted
Debug/Release and sanitizer validation is pending. M2 remains **OPEN**.

## R1 HYBRID CredSSP-before-MCS transport phase (2026-10-16; hosted CI pending)

Authoring parent: `e9acfa52007247488f5088af0a66161e1e9d735a`. P0's deferred loopback TLS-read repair is already
validated at `8dc5cfd962f9432d4aaf3ac3c552ddb8fed172d7` / Actions
`38897048825`: Windows/MSVC 351/351 Debug+Release, macOS/AppleClang 326/326
Debug+Release, Linux/GCC full Debug+Release, R9 sanitizer, documentation,
SDK consumer and package jobs PASS. The confirmed failure was fixture-only:
a legitimate zero-byte `NeedRead` could arrive after client `SSL_write_ex`
accepted the eight-byte prefix but before that TLS record was server-readable.
The strengthened fixture waits for both exact plaintext progress and its
requested framing status using the bounded R1 poll/deadline path.

P1 now distinguishes the exact X.224-selected `PROTOCOL_HYBRID` path from the
historical `DiagnosticTlsOnly` path. Successful HYBRID TLS enters
`PreauthStage::AwaitCredSsp`; diagnostic TLS continues to
`AwaitMcsConnectInitial`. HYBRID socket readiness is surfaced to the external
R2 consumer without invoking the diagnostic MCS reader. Explicit MCS intake in
this phase fails closed before an application read. The established R1
application-I/O seam remains the only SSL/BIO byte path; no authentication,
lease, MCS admission, listener or authenticated-transition API is added.

Negotiation provenance remains a value snapshot of the original offered mask
and selected HYBRID protocol while the same R1 SSL/BIO/certificate is live.
Cancellation, SSL-owner replacement, selected-certificate replacement and
terminal denial revoke that provenance. Dedicated production-linked CTests are
`transport.tcp-owned-hybrid-credssp-first-record`,
`transport.tcp-owned-hybrid-no-premature-mcs`, and
`transport.tcp-owned-hybrid-provenance-revocation`; the R9 bounded sanitizer
selector includes all three. The existing `transport.credssp-r1-owned-framing`
retains the P0 delayed-readiness regression, so no duplicate timing test is
introduced.

The canonical owner-local `~/rdp-server/build` command is **NOT RUN** in this
connector environment because the owner checkout is unavailable. Exact
publication-SHA hosted Linux/GCC, Windows/MSVC, macOS/AppleClang, R9 sanitizer,
documentation, SDK consumer and package outcomes are pending. Owner Linux/X11,
Windows MSYS2 CLANG64/Clang23, macOS 27, real Kerberos/logind admission and a
current Microsoft-client NLA session remain separate **NOT RUN** gates.
**M2 remains OPEN / NOT ACCEPTED.**

## R9 TS_INFO_PACKET sanitizer exact-SHA receipt (2026-10-16)

**Implementation:** `d2df45e136fb7668212d7566bcd95cd96da67587`,
Actions `38906316309` — **SUCCESS**.

The two R3 packet-boundary cases now execute under the existing R9 Clang
ASan/UBSan job: `transport.mcs-client-info-packet-structure` and
`transport.mcs-client-info-packet-denials` both **PASS** in **0.01 s**.
The bounded R1/R3 transport/security selection is therefore **27/27 PASS**.
The same sanitizer run also passes clipboard **41/41**, R4 x264/BGRA
**18/18**, native GSS/R2/R3 **23/23**, R10 Linux runtime CredSSP **4/4**,
R5 X11 **16/16**, and the bounded fuzzer **1/1**. The MIT-krb5 LSan
suppression remains scoped to native GSS and reports only the same two known
`krb5_copy_principal` provider-failure cases at **216 bytes / 10 allocations**
each.

Cross-platform exact-SHA evidence is fully green: Linux/GCC **407/407 PASS**
in Debug and Release; macOS/Clang **349/349 PASS** in Debug and Release;
Windows/MSVC focused native preflight **39/39 PASS** in Debug and Release and
full CTest **373/373 PASS** in Debug and Release. Downstream installed SDK
consumer/package checks and documentation policy pass. Non-tag prerelease
publication is correctly skipped.

This closes the sanitizer-specific gap called out by the R3 TS_INFO receipt;
it does not change R3 state ownership or establish real Client Info semantics,
positive Kerberos/logind admission, Server License Request delivery, Share
activation or Microsoft-client acceptance. Canonical owner-local
`~/rdp-server/build/` and owner platform commands remain **NOT RUN** here.
**M2/M3 remain OPEN.**

## R9 TS_INFO_PACKET sanitizer coverage handoff (2026-10-16; exact-SHA CI pending)

**Reconciled publication parent:** `0abf1e5de12517817a70973be3740ac56ff1d522`.
R3 implementation `6d15aa6f1e564e389224e4b54d44b62b7d2920de` added
`transport.mcs-client-info-packet-structure` and
`transport.mcs-client-info-packet-denials`. Exact Actions `38904425329` is
fully green across Linux/GCC, macOS/Clang and Windows/MSVC Debug/Release,
but the R3 receipt correctly records those two packet-structure cases as
**NOT RUN under R9 sanitizers**.

R9 closes only that selector gap. Both cases already reuse the production
`parseRdpClientInfoPacket` path inside `test_owned_mcs_connect_initial` and
the central CTest registry; no parser, R3 lifecycle, test semantics, build
target or credential/admission behavior changes. The existing bounded
R1/R3 transport/security sanitizer selection grows from **25 to 27** cases.
Clipboard, R4 x264, native GSS/R2/R3, R10 runtime, R5 X11 and fuzzer groups
remain unchanged, as do ASan/UBSan options and the GSS-only MIT-krb5 LSan
suppression.

Canonical owner-local `~/rdp-server/build/` configure/build/full CTest and
local sanitizer execution remain **NOT RUN** in this connector environment.
Exact-publication-SHA hosted evidence is required. Real Client Info from a
Microsoft client, positive Kerberos/logind admission, licensing/Share and
M2/M3 remain **NOT RUN/OPEN**.

### R3 TS_INFO_PACKET exact-SHA hosted validation receipt (2026-10-16)

Implementation `6d15aa6f1e564e389224e4b54d44b62b7d2920de`,
[Actions 38904425329](https://github.com/k1moradi/RDP-server/actions/runs/38904425329):
**SUCCESS** across every mandatory job. Linux/GCC full CTest is
**407/407 PASS** in Debug and **407/407 PASS** in Release; macOS/Clang is
**348/348 PASS** in Debug and Release; Windows/MSVC native preflight is
**39/39 PASS** in both configurations and full CTest is **373/373 PASS**
in Debug and Release. Documentation-policy and downstream SDK/package gates
PASS; non-tag prerelease publication is correctly skipped.

The new `transport.mcs-client-info-packet-structure` and
`transport.mcs-client-info-packet-denials` cases PASS in all six hosted
Debug/Release configurations. Existing protected Client Info route tests PASS
alongside them; Linux-only `security.gssapi-r3-client-info-route-contract`
PASSes in Debug and Release. R9 ASan/UBSan selected groups are all PASS:
clipboard **41/41**, bounded R1/R3 transport/security **25/25**, native
GSS/R2/R3 **23/23**, native R5 X11 **16/16**, and fuzzer **1/1**. The R9
bounded selector still contains the two earlier route tests but does not yet
select the two newly added packet-structure cases; their sanitizer-specific
execution is therefore **NOT RUN**, while full hosted CTest evidence is green.

Canonical owner-local `~/rdp-server/build`, owner Linux/X11, Windows MSYS2
CLANG64/Clang23, macOS27, genuine positive Kerberos/logind admission,
Microsoft-client Client Info, licensing/Share and desktop acceptance remain
**NOT RUN/OPEN**. **M2 NOT ACCEPTED.** The next R3 implementation must not
invent licensing identity or randomness: Server License Request needs an
owned CSPRNG server random plus product/scope identity before its receipt-bound
writer can become a positive R2-authorized path.

## R2 owner-driven real Kerberos test exact-SHA hosted validation (2026-10-16)

**Test commit:** `1d218f285049b12460ccd9da844b57d7c70e3b9c`.
**Actions:** `38904205829` — **SUCCESS**.

Credential-free hosted validation is clean across the complete matrix:
Ubuntu/GCC full CTest **405/405 PASS Debug** and **405/405 PASS Release**;
macOS/Clang **346/346 PASS Debug** and **346/346 PASS Release**;
Windows/MSVC **371/371 PASS Debug** and **371/371 PASS Release**, with the
focused Windows native preflight **39/39 PASS** in both configurations.
Installable SDK consumer/package validation also passed on all hosted
platforms. Documentation-policy **PASS**.

The R9 Clang ASan/UBSan job **PASS**. Its production-linked preauth/GSS build
compiled the new real-provider owner-driven test body, and the selected native
R2/R3 GSS group completed **23/23 PASS**; the remaining selected protocol,
clipboard, X11 and fuzzer groups also passed.

This does **not** claim the new
`security.gssapi-real-kerberos-owned-binding` CTest executed. Hosted CI keeps
`RDP_SERVER_TEST_REAL_KERBEROS=OFF` and has no explicit service keytab/client
credential cache. The exact-SHA result proves ordinary compilation with GCC and
Clang plus no credential-free regressions. Positive MIT Kerberos execution,
positive NSS/logind lease issuance, Microsoft-client M2, canonical
`~/rdp-server/build/`, owner Linux/X11, Windows MSYS2 CLANG64/Clang23 and
macOS27 remain **NOT RUN**.

**Next R2 acceptance gate:** provision an explicit test service keytab and
client `FILE:` cache, enable `RDP_SERVER_TEST_REAL_KERBEROS`, and require
`security.gssapi-real-kerberos-owned-binding` to reach the exact
owner-driven `BindingVerified` receipt. Only then proceed to positive native
NSS/logind admission on that same principal and R1 owner.

## R3 bounded TS_INFO_PACKET acceptance boundary (2026-10-16; hosted CI pending)

**Authoring base:** `3bcdb4ad2911de916aae465305f58b9f8c770918`;
**reconciled shared main:** `f032e4c434642dc788a56e48616e1e72d429935c`.
The protected Enhanced-Security Client Info envelope already proves one
fresh R2-authorized, complete begin|end MCS SendDataRequest from the assigned
client UserId on the joined I/O channel. This increment validates the borrowed
TS_INFO_PACKET before any connection-sequence state advances.

`parseRdpClientInfoPacket` is allocation-free and never returns Domain,
UserName, Password, AlternateShell or WorkingDir bytes. It checks the fixed
18-byte header, Unicode/ANSI string byte counts, mandatory terminators and the
current 512-byte per-string bound. Optional TS_EXTENDED_INFO_PACKET is checked
in strict suffix order: AF_INET/AF_INET6, bounded terminated clientAddress and
clientDir, optional 172-byte time-zone block, session/performance fields,
zero-or-28-byte Auto-Reconnect cookie, reserved2=0, bounded even Dynamic DST
key and 0/1 daylight-disabled value. Truncation, malformed optional ordering,
odd Unicode sizes, missing terminators and trailing bytes fail closed.

After a freshly reauthorized broker call validates both the existing
MCS/security envelope and the full TS_INFO structure, the sole
`McsSessionLifecycle` consumes Client Info once and transitions
`AwaitChannelJoin -> AwaitServerLicenseRequest`. Its embedded licensing
lifecycle deliberately remains `NotStarted`: no Server License Request bytes
exist in this increment, and therefore no licensing state can advance without
a later receipt-bound writer. Duplicate Client Info and late Channel Join are
no longer valid after this state change. Joined static-channel identity remains
owned by the same R3 session; CLIPRDR still requires the separate clipboard
permission and is not payload authority.

Dedicated portable CTests:
`transport.mcs-client-info-packet-structure` and
`transport.mcs-client-info-packet-denials`. The existing Linux
`security.gssapi-r3-client-info-route-contract` is updated to require the
stateful packet-acceptance broker signature while ordinary CI continues to
avoid fabricating a positive Kerberos/logind lease.

Canonical owner-local `~/rdp-server/build` configure/build/full CTest is
**NOT RUN** in this connector environment. Exact-SHA hosted Linux/GCC,
macOS/Clang, Windows/MSVC Debug/Release, R9 sanitizers and documentation-policy
are **PENDING after publication**. Real TS_INFO semantics, credentials,
Microsoft-client admission, Server License Request construction/delivery,
license completion, Share activation and desktop acceptance remain **NOT
RUN/OPEN**. **Next R3:** add the one bounded Server License Request encoder and
receipt owner, then call the existing licensing lifecycle only after full
accepted-byte completion. **M2 NOT ACCEPTED.**

## R2 opt-in owner-driven real Kerberos binding receipt (2026-10-16; exact-SHA CI pending)

R2 implementation `5400566af551b6b5715a23d76569a3e838bcd8bd` plus
warning-clean correction `f2c363b27f20e047b31611861e585a63b3076703`
compiled on hosted Linux, macOS and Windows. Exact correction workflow
`38901685430` passed documentation policy, macOS Debug/Release, Windows
Debug/Release and the R9 ASan/UBSan job. Ubuntu/GCC Debug compiled and reached
**395/396 PASS**; its sole failure was R10
`runtime.linux-connection-credssp-owner-framing`, not an R2 GSS case. Linux
Release was therefore not run at that SHA. R9 later selected
`security.gssapi-r1-owned-binding-delivery-fence` explicitly.

This increment adds opt-in
`security.gssapi-real-kerberos-owned-binding` to the existing preauth/GSS
test binary. With caller-provisioned explicit `FILE:` service keytab and
client credential cache, it uses MIT `gss_init_sec_context` and the production
R2 `advanceOwnedCredSspHandshake()` over one genuine R1
`SecurityNegotiationPolicy::HybridNla` loopback connection. Continuation
tokens and replies cross the exact owner-backed TLS path. The final real GSS
client token is combined with the CredSSP public-key binding and nonce; the
test requires the provider principal to remain non-authorizing while the server
binding reply is merely queued, then requires the explicit
`BindingVerified` result and `verifiedPrincipalForOwnedConnection()` only
after that reply is fully written and released through the same R1 owner.
The real initiator GSS-unwraps the server proof and compares it with the
expected server-to-client TLS binding.

This remains authentication-proof coverage, **not** native desktop admission:
no NSS/logind lease, R3 capability, delegated credential, listener or desktop
is created. Default hosted CI remains credential-free and compiles this code
through `RDP_TEST_LINUX_GSSAPI`, but does not register/run the case unless
`RDP_SERVER_TEST_REAL_KERBEROS=ON` with explicit credentials. Therefore
positive real-Kerberos execution, positive native admission, Microsoft-client
M2 acceptance, owner Linux/X11, Windows MSYS2 CLANG64/Clang23, macOS27 and
canonical `~/rdp-server/build/` remain **NOT RUN** here.

**Next R2 gate after clean compilation:** execute the opt-in case with a real
client cache/service keytab. Only after that exact owner-driven
`BindingVerified` receipt is demonstrated should R2 exercise positive
NSS/logind lease issuance on the same principal and R1 owner.

## R6 capture-cycle single-ownership + focused-selector hosted receipt (2026-10-16)

R6 test commit `2918bbfda7db4b47afb3ee82a22d1d7bbe2b859f` added
`windows.capture-dxgi-duplication-owner-capture-cycle-single-attach`. Its first
exact run proved the case itself **PASS** in Windows Debug, but exposed the
focused preflight's overly broad `-L windows` regex matching five R8
`windows-adapter` registrations whose separate executable was not built.

Selector correction `53312ec4f07f59d603982f1a20a625bc92df081d`,
Actions `38902761330`, anchors the focused selection to
`^windows\.(geometry|capture|cursor|input)-`. Windows/MSVC R6 preflight is
**39/39 PASS Debug** and **39/39 PASS Release**; the new single-attach case
passed in **0.01 s** in both. Full Windows CTest is **368/368 PASS Debug** and
**368/368 PASS Release**, with the same test again **0.01 s** in both.
Windows install/downstream consumer, macOS/Clang, documentation-policy and the
selected R9 sanitizer job also **PASS**.

The exact workflow remains overall **FAIL** only because Ubuntu/GCC Debug aborts
in unrelated R10 `runtime.linux-connection-credssp-owner-framing` at
`tests/test_runtime_linux_security.cpp:670` on
`totalRead == request.size()`; Ubuntu Release did not run.

Validated R6 invariant: one ready duplication owner owns at most one
capture-cycle subordinate; a second attach cannot replace it or change
readiness; terminal close clears the subordinate and is idempotent with native
references released once. Full-suite coverage remains authoritative; the
focused selector no longer crosses road/executable boundaries.

Owner-local CMake/CTest and Windows MSYS2 CLANG64/Clang23 remain **NOT RUN**.
Genuine Windows R2/R3 admission is still absent, so runtime DXGI capture and
SendInput remain **BLOCKED**. M4 remains OPEN.

## R1 HYBRID + owner-aware CredSSP hosted acceptance receipt (2026-10-16)

R1 fixture correction `8dc5cfd962f9432d4aaf3ac3c552ddb8fed172d7`
completed [Actions 38897048825](https://github.com/k1moradi/RDP-server/actions/runs/38897048825)
with **SUCCESS** across every hosted job. Linux/GCC full Debug and Release
CTest passed, macOS/AppleClang full **326/326 Debug and 326/326 Release**
passed, and Windows/MSVC full **351/351 Debug and 351/351 Release** passed.
Documentation policy, R9 ASan/UBSan selection, installed SDK consumer and
package publication checks also passed.

The R1-specific production-backed cases all pass on the same source:
`transport.tcp-owned-hybrid-nla-negotiation`,
`transport.credssp-r1-owned-framing`,
`transport.credssp-r1-owned-reply`,
`transport.tcp-owned-runtime-tls-handshake`, and
`transport.tcp-owned-runtime-tls-identity-continuity`. The immediately
following R2 owner-driven CredSSP integration
`0f5fcd6f55e0a674671927609a78bd841d58405c` likewise completed
[Actions 38898173843](https://github.com/k1moradi/RDP-server/actions/runs/38898173843)
with all hosted protocol, sanitizer and documentation jobs passing. This
closes the previously missing hosted evidence for R1's genuine HYBRID
selection and R1-owned CredSSP application-I/O seam; it does **not** prove
real Kerberos/native admission or M2.

A later descendant `e028aa5652636e82218eed85a49e675be5d322d3`,
[Actions 38902568449](https://github.com/k1moradi/RDP-server/actions/runs/38902568449),
again passes the R9 bounded R1/R3 selection **25/25**, including HYBRID,
both owner-aware CredSSP cases and both R10→R1 TLS cases; Windows and macOS
full jobs pass. Its sole Ubuntu failure is
`runtime.linux-connection-credssp-owner-framing`, outside R1 transport:
R2 can return `NeedWrite` with nonzero `plaintextBytesRead` after consuming
the final DER bytes and queueing provider output, while R10
`LinuxRuntimeConnection::onCredSspIoReady()` currently drops those byte
receipts when mapping `NeedWrite`/ `NeedRead`. The resulting accounting
assertion is tracked on R10 issue #19. R1 transport code is unchanged.

Owner Linux/X11, Windows MSYS2 CLANG64/Clang23 and macOS 27 exact-source
commands, genuine Kerberos/logind admission, a current Microsoft-client NLA
session and full M2 remain **NOT RUN / NOT ACCEPTED**. The next production
listener/event-loop composition remains R10-owned; R1 must not introduce a
second listener/session controller merely to advance that gate.

## R8 Windows ready-data clipboard hosted validation receipt (2026-10-16)

Repair commit `e028aa5652636e82218eed85a49e675be5d322d3`, Actions
`38902568449`, validates the Windows ready-data clipboard boundary after the
borrowed-PDU fixture and focused-label corrections. macOS/Clang completed
**343/343 PASS** in both Debug and Release, including all five R8 cases.
Windows/MSVC completed the isolated R6 preflight **39/39 PASS** in both
configurations, then full project CTest **368/368 PASS** in Debug and Release;
all five R8 Win32-adapter cases passed in both configurations. The R9
ASan/UBSan job passed **41/41 clipboard CTests**, including all five R8 cases,
then passed its remaining bounded protocol/native groups and fuzzer.
Documentation-policy also passed.

Ubuntu/GCC compiled the production/test targets and all five R8 cases passed in
full Debug CTest. The job finished **400/401 PASS** because the unrelated
`runtime.linux-connection-credssp-owner-framing` R10 case still asserted
`totalRead == request.size()`; Release was therefore skipped by workflow
fail-fast. This is not counted as an R8 failure. Owner-local
`~/rdp-server/build`, Windows MSYS2 CLANG64/Clang23, live Win32 clipboard,
Microsoft-client interoperability and performance remain **NOT RUN**.

**Next R8:** proceed with the equivalent ready-data macOS clipboard adapter
and native file-destination integration while R3 completes the authoritative
post-admission CLIPRDR payload writer.

## R9 sanitizer-group independence exact-SHA receipt (2026-10-16)

**Implementation:** `87d529d7d64721187e3ae873da33a48f6d24c809`,
Actions `38902378901`. The workflow is correctly **FAIL** overall, but the
R9 CI-control objective is validated: after a successful shared sanitizer
compile, a failing earlier owner group no longer suppresses later bounded
sanitizer evidence.

The clipboard sanitizer group ran **41 cases** and finished **36/41** because
all five concurrent R8 Windows clipboard adapter fixtures still reproduced the
known heap-use-after-free at this exact SHA. Despite that failure, the new
`always() && compile-success` gates caused every later R9 group to execute:
bounded R1/R3 transport/CredSSP/licensing **25/25 PASS**; native GSS/R2/R3
**23/23 PASS**; native R5 X11 **16/16 PASS**; bounded MCS/CLIPRDR fuzzer
**1/1 PASS**. The newly selected
`security.gssapi-r1-owned-binding-delivery-fence` ran as CTest 143 and
**PASS**ed under ASan/UBSan in **0.04 s**. The MIT-krb5 LSan suppression
remained scoped to native GSS and appeared only in the same two known
`krb5_copy_principal` failure paths, each **216 bytes / 10 allocations**.

Cross-platform Debug jobs remain red for independently owned fixtures at this
SHA. Linux/GCC ran **401** tests with six failures: the concurrent R10
`runtime.linux-connection-credssp-owner-framing` plus the five R8 clipboard
cases; the R2 binding-delivery fence itself passed as test 143. macOS/Clang
ran **343** tests with only the five R8 clipboard cases failing. Windows/MSVC
stopped in its focused native preflight because the same five R8 cases were
selected by the broad `windows-adapter` label before their executable was
built. Release/downstream stages blocked by those Debug/preflight failures are
not claimed. Documentation policy **PASS**; non-tag prerelease publication
was correctly **SKIPPED**.

Concurrent R8 commit `e028aa5652636e82218eed85a49e675be5d322d3` now repairs
both the borrowed-response fixture lifetime and the preflight label collision;
that descendant fix is separate evidence and does not rewrite the exact
`87d529d...` receipt above.

Canonical owner-local `~/rdp-server/build/` configure/build/full CTest and
local sanitizers remain **NOT RUN** in this connector environment. Real
Kerberos binding completion, NSS/logind admission, Microsoft-client
authentication and M2/M3 remain **NOT RUN/OPEN**.

## R6 focused Windows preflight selector isolation (2026-10-16; exact-SHA CI pending)

Exact-SHA Actions `38902316637` for test-only R6 commit
`2918bbfda7db4b47afb3ee82a22d1d7bbe2b859f` compiled the Windows desktop
target successfully. Its new
`windows.capture-dxgi-duplication-owner-capture-cycle-single-attach` test
**PASS** in Debug in **0.01 s**. The focused preflight then failed because
`ctest -L windows` regex-matched five R8 clipboard cases labeled
`windows-adapter`; their separate executable was intentionally not built by
the R6-only step. All 39 selected R6/native-desktop tests themselves passed.

The preflight now uses anchored behavior names
`^windows\.(geometry|capture|cursor|input)-`, matching only the existing
`test_windows_desktop_geometry` target. The ordinary complete build and full
CTest remain unchanged and authoritative, so R8 and other-road tests are still
required there. No production source/native behavior changes.

Canonical owner-local CMake/CTest is **NOT RUN** here. Exact-SHA hosted
Windows/MSVC Debug+Release preflight/full matrix is required after publication.
Owner Windows MSYS2 CLANG64/Clang23 and genuine Windows R2/R3 admission remain
**NOT RUN/BLOCKED**; M4 remains OPEN.

## R8 Windows clipboard fixture-lifetime and preflight-label repair (2026-10-16; CI pending)

Implementation `b1cd3e30b5b2a708831c55c4cc857b103a46f246`, Actions
`38901871912`, exposed two R8 test-integration defects without invalidating the
production ownership design. Linux/GCC and macOS/Clang compiled the new
Windows clipboard adapter/test target, but the five R8 cases dereferenced
`RemoteTransfer::Response::payload` after a temporary response vector had
already been destroyed. R9 ASan/UBSan independently diagnosed the same helper
bug as heap-use-after-free. Production `RemoteTransfer` documents that payload
as borrowed, so the fixture now retains each complete PDU through synchronous
`storeVerifiedUnicodeText` / `storeVerifiedImage`.

Windows/MSVC failed earlier in the existing R6 native preflight: R8 had labeled
its cases `windows-adapter`, and CTest's `-L windows` regex selected them
even though that target-only preflight intentionally builds only
`test_windows_desktop_geometry`. The R8 cases now use
`win32-adapter` plus the existing `clipboard;protocol;offline` labels, keeping
R6's isolated preflight intact while full Windows CTest and the R9 clipboard
sanitizer suite still select R8 normally.

The same Linux full CTest also retained one unrelated concurrent R10 failure,
`runtime.linux-connection-credssp-owner-framing`; R10 has since published its
own scheduling-independent fixture repair. Documentation-policy passed on the
R8 implementation commit. Canonical owner-local `~/rdp-server/build` remains
**NOT RUN** in this connector environment. Exact-SHA hosted validation of this
repair is the next R8 gate.

## R9 sanitizer-group execution independence (2026-10-16; exact-SHA CI pending)

**Reconciled publication parent:** `2918bbfda7db4b47afb3ee82a22d1d7bbe2b859f`.
R9 exact implementation `487e26c49b4709c031c6ef71342c5b3f202d5fb4`,
Actions `38901941233`, proved the selected-target sanitizer build itself
succeeds but exposed a cross-road CI suppression hazard. The first clipboard
group executed **41 cases** and the five newly landed R8 Windows clipboard
adapter cases all failed under ASan with heap-use-after-free reports rooted
through the R8 fixture's borrowed `RemoteTransfer::Response` payload lifetime.
Because that clipboard step failed, GitHub skipped the later bounded
transport/security, native GSS/R2/R3, R5 X11 and fuzzer steps. Therefore the
new `security.gssapi-r1-owned-binding-delivery-fence` was **NOT RUN** at that
SHA despite being correctly present in the regex. This is not recorded as an
R2/R9 behavioral pass.

R9 now makes the existing sanitizer groups execution-independent after one
successful selected-target compile. The compile step receives a stable ID;
each later non-clipboard group uses `always()` gated by that compile outcome.
A failure in clipboard or any intermediate CTest group still makes the one
sanitizer job fail overall, but it no longer suppresses evidence from later
owners. A compile failure still prevents all test groups that depend on the
missing binaries, avoiding misleading secondary failures. The single checkout
and single `build/` root, sanitizer flags, target list, CTest regexes, leak
suppression scope and bounded test semantics are otherwise unchanged.

The same `487e26c...` workflow also had concurrent R8 full-matrix failures;
Windows reported all five new clipboard adapter CTests **Not Run** because
`test_windows_clipboard_adapter.exe` was absent from the ordinary full-build
output. Those R8 build/test integration defects remain owned by R8 and are not
fixed by this R9 CI-control change.

Canonical owner-local build/full CTest and sanitizer commands remain **NOT
RUN** in this connector runtime. Exact-publication-SHA hosted execution is
required to prove that the R8 failure remains visible while the later R9
groups, especially the 23-case native GSS/R2/R3 selection, still execute.
Real Kerberos/logind and Microsoft-client acceptance remain **NOT RUN/OPEN**.

## R6 capture-cycle single-attachment ownership coverage (2026-10-16; exact-SHA CI pending)

With native runtime binding still blocked on genuine Windows R2/R3 admission and
owner CLANG64/Clang23 evidence, the next R6 maintenance increment strengthens
the newest transactional attachment contract without changing production code.
Dedicated CTest
`windows.capture-dxgi-duplication-owner-capture-cycle-single-attach` opens the
existing production `WindowsDxgiDuplicationOwner`, attaches one capture-cycle
subordinate with a canonical selected-output layout, then requires a second
attach attempt to fail without replacing the live subordinate or revoking owner
readiness. Terminal `close()` must clear the subordinate, invalidate readiness
and remain idempotent while synthetic duplication/context/device references are
released exactly once.

The test constructs the existing native staging/capture wrappers but performs
no frame acquisition, GPU mapping, live desktop access or SendInput. No
authorization surface, production callback, scheduler or runtime route changes.

Canonical owner-local CMake/CTest is **NOT RUN** in this connector environment.
Exact-SHA hosted Windows/MSVC Debug+Release preflight/full matrix is required
after publication. Owner Windows MSYS2 CLANG64/Clang23 and genuine Windows
R2/R3 admission remain **NOT RUN/BLOCKED**; M4 remains OPEN.

## R9 owner-completed CredSSP binding sanitizer handoff (2026-10-16; exact-SHA CI pending)

**Reconciled publication parent:** `b1cd3e30b5b2a708831c55c4cc857b103a46f246`.
R2 added `security.gssapi-r1-owned-binding-delivery-fence` beside the two
owner-driven CredSSP provenance/cancellation fences already selected by R9.
The new test uses the real R1 loopback HYBRID/TLS owner and the production
`GssapiSpnegoAcceptor::advanceOwnedCredSspHandshake` path, but ordinary CI
still has no configured Kerberos credentials, so it proves fail-closed
delivery/admission behavior without fabricating a principal, native logind
lease or successful R3 session.

R9 adds exactly this registered case to the existing native GSS/R2/R3
ASan+UBSan regex. No production source, CTest registration, fixture semantics,
build target, sanitizer option, LSan scope, X11/clipboard selection or fuzzer
changes. The native GSS/R2/R3 selected count is expected to rise from
**22 to 23**; all other R9 groups remain unchanged.

R2 implementation `5400566af551b6b5715a23d76569a3e838bcd8bd`,
Actions `38901455596`, is preserved as a compile-failure receipt rather than
a test result: the R9 sanitizer build and Ubuntu/GCC stopped in
`src/server/security/linux_console_admission.cpp:359` because the R2 admission
switch left an unused `activeServerTls` local and the Linux GSS target uses
`-Werror`. No new binding-delivery CTest executed in those failed jobs.
The direct follow-up `f2c363b27f20e047b31611861e585a63b3076703` removes
only that obsolete local; authorization semantics are unchanged. Its hosted
workflow is independent evidence and was still in progress when this R9
selection was authored.

Canonical owner `~/rdp-server/build/` configure/build/full CTest and local
sanitizers remain **NOT RUN** in this connector environment; no alternate
build root/worktree/branch is created. Exact-publication-SHA hosted R9
sanitizer, Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy
evidence is required. Positive real-Kerberos binding delivery, NSS/logind
admission and Microsoft-client M2 remain **NOT RUN/OPEN**.

## R8 Windows ready-data clipboard presentation (2026-10-16; exact-SHA CI pending)

**Starting shared main:** `f2c363b27f20e047b31611861e585a63b3076703`. R8 P0/P1 remain intact: the
FILEDESCRIPTORW fixture correction and bounded Lock/Unlock plus locked
FileContents lifecycle are already hosted-validated. The protected R3 session
still does not expose a complete licensing/Share-activated CLIPRDR
payload-writer contract, so this increment does not fabricate channel
authority or transmit any RDP bytes.

A new noninstalled `WindowsClipboardAdapter` adds the next independent native
R8 boundary. `RemoteTransfer` remains the sole clipboard generation and data
owner. The adapter announces only **already verified current-generation**
CF_UNICODETEXT, CF_DIB/CF_DIBV5, or registered `PNG` data. Win32 delayed
rendering is therefore a local copy operation only: `WM_RENDERFORMAT` never
starts a network request or blocks waiting for CLIPRDR. Text is bounded and
re-expanded to Windows CRLF UTF-16LE at render time; image bytes remain in the
validated packed/compressed representation. A native takeover yields the same
remote generation instead of timer-driven reclaiming, and generation
replacement prevents stale delayed rendering.

The native seam follows Win32 ownership rules: publication opens and empties
the clipboard before declaring delayed formats; `WM_RENDERFORMAT` rendering
must not reopen it; `WM_RENDERALLFORMATS` opens it, verifies the HWND still
owns the clipboard, renders ready formats, then closes it. Disconnect clears
our delayed publication only while that HWND is still owner. The real
User32/GlobalAlloc callbacks compile only on Windows; ordinary tests inject
callbacks and never touch the host clipboard.

Dedicated registered CTests:
`clipboard.windows-clipboard-remote-ready-publication`,
`clipboard.windows-clipboard-generation-owner-loss`,
`clipboard.windows-clipboard-png-dib-routing`,
`clipboard.windows-clipboard-render-all-disconnect`, and
`clipboard.windows-clipboard-failure-reentry-denials`. The existing R9
sanitizer build list now compiles this target before its all-clipboard label
run.

**Authoring validation:** source/ownership/documentation review **PASS**.
Canonical owner-local `~/rdp-server/build` configure/build/full CTest is
**NOT RUN** because this connector environment does not expose that checkout;
no alternate build root was created. Exact-SHA Linux/GCC, macOS/Clang,
Windows/MSVC Debug/Release, R9 ASan/UBSan and documentation-policy are
**PENDING after publication**. No live Windows clipboard, Microsoft client,
R3-authorized CLIPRDR payload dispatch, file-manager destination integration,
Windows MSYS2 CLANG64/Clang23 owner run or performance acceptance was executed.

**Next R8:** add the equivalent ready-data macOS clipboard adapter and continue
native file-destination integration while R3 completes the authoritative
post-admission clipboard payload writer; only then wire native fetch intents
to actual CLIPRDR transmission.

## R2 binding-fence warning-clean correction (2026-10-16)

Post-publication review of `5400566af551b6b5715a23d76569a3e838bcd8bd` found an obsolete local `activeServerTls` left in `LinuxConsoleAdmissionBroker::issue` after native issuance switched to `verifiedPrincipalForOwnedConnection()`. The Linux GSS target uses `-Werror`; this correction removes only that unused raw-TLS local. Authorization and teardown semantics are unchanged.

## R6 capture-cycle attach bounds exact-SHA hosted validation (2026-10-16)

R6 implementation `82655aee07a404bf553faf3273fce37daec51f09`,
Actions `38901068473`, validates the bounded/transactional
`WindowsDxgiDuplicationOwner::attachCaptureCycle` correction on hosted
Windows/MSVC. The focused native-adapter preflight passed **38/38 Debug** and
**38/38 Release**. The new
`windows.capture-dxgi-duplication-owner-capture-cycle-layout-denials` case
passed in **0.01 s** in both configurations, confirming oversized and
non-canonical layouts fail before partial capture-cycle attachment.

The authoritative full Windows suite then passed **362/362 Debug** and
**362/362 Release**; the new R6 case again passed in **0.01 s** in both full
runs. Windows install/downstream consumer validation passed. macOS/Clang,
documentation-policy and the selected R9 sanitizer job also **PASS**.

The exact workflow is overall **FAIL** only because Ubuntu/GCC Debug failed the
unrelated R10 runtime test
`runtime.linux-connection-credssp-owner-framing` at
`tests/test_runtime_linux_security.cpp:648`
(`step.plaintextBytesWritten == 0`). Ubuntu Release therefore did not run.
No R6 test or Windows native-adapter build failed.

Canonical owner-local CMake/CTest and owner Windows MSYS2 CLANG64/Clang23
remain **NOT RUN** in this connector environment. Current source still exposes
no genuine Windows R2/R3 native-admission capability, so runtime DXGI capture
and SendInput remain **BLOCKED**. M4 remains OPEN.

**Next R6 production gate:** owner Windows MSYS2 CLANG64/Clang23 evidence plus
a concrete Windows R2/R3 authorization capability. Until both exist, continue
only bounded R6 ownership/error-path maintenance and do not introduce a runtime
desktop/input route.

## R2 owner-completed CredSSP binding admission fence (2026-10-16; exact-SHA CI pending)

Starting inspected shared `main`: `19655e23fa992cdf7b57cd2c9f84b51971d38706`. `ServerBindingPrepared` is only a semantic GSS/CredSSP state; it does not prove the server binding reply completed through R1. R2 now sets a private completion latch only after `advanceOwnedCredSspHandshake` fully writes and releases that reply through its pinned `OwnedPreauthTcpConnection`. An idle prepared state without that receipt is rejected rather than synthesized into `BindingVerified`.

New `verifiedPrincipalForOwnedConnection()` requires that completion receipt plus the same live HYBRID-selected R1 owner, TLS object and certificate continuity. Native lease issuance and its issuance-time continuity checks use this stricter predicate. R10 delegates CredSSP progression to the same R2 API, so its surfaced `BindingVerified` receipt—not `ServerBindingPrepared` alone—is the prerequisite for native admission.

Dedicated existing-binary CTest `security.gssapi-r1-owned-binding-delivery-fence` checks the owner-only API and genuine HYBRID loopback denial path without fabricating credentials. Positive real-Kerberos binding completion, NSS/logind lease, Microsoft-client M2, owner platform commands and canonical local `~/rdp-server/build/` remain **NOT RUN** here.

## R4 malformed NV12 preflight exact-SHA hosted CI (2026-10-16)

**Implementation SHA:** [`3c8baa7a02b61879d541bd845fdbecbf26ff6d76`](https://github.com/k1moradi/RDP-server/commit/3c8baa7a02b61879d541bd845fdbecbf26ff6d76).
[Exact-SHA GitHub Actions 38900695904](https://github.com/k1moradi/RDP-server/actions/runs/38900695904)
completed **overall FAILURE**, solely from one R10-owned Linux Debug
runtime assertion, not an R4 test failure:

- **Linux/GCC Debug:** **395/396 PASS**. The newly registered
  `graphics.x264-segmented-malformed-nv12-reference-continuity`
  (test 388) **PASS**. Only
  `runtime.linux-connection-credssp-owner-framing` (test 254)
  fails in `tests/test_runtime_linux_security.cpp:648` at
  `step.plaintextBytesWritten == 0`; R10 CredSSP owner/framing semantics
  are unaffected by the R4 change. Linux Release and downstream SDK
  package/consumer **NOT RUN** at this SHA after the Debug stop.
- **macOS/Clang:** Debug **338/338 PASS**, Release **338/338 PASS**,
  including the new R4 test (test 330) in both builds; installed
  portable SDK consumer and package verification **PASS**.
- **Windows/MSVC:** Debug **362/362 PASS**, Release **362/362 PASS**,
  including the new R4 test (test 354) in both builds; native R6
  preflight and downstream portable SDK consumer/package checks **PASS**.
- **R9 selected ASan/UBSan job:** **PASS** in its configured scope.
  This does not prove the R4 x264/BGRA executable itself ran under
  sanitizers. **Documentation-policy:** **PASS**. Prerelease
  publication correctly **SKIPPED** for an ordinary development commit.
- **Owner machine:** canonical `~/rdp-server/build` configure/build/full
  CTest, Linux/X11, Windows MSYS2 CLANG64/Clang23, macOS27, external
  Microsoft/FreeRDP graphics client and performance gates **NOT RUN**.

The R4 producer now preflights all deterministic caller-owned NV12
plane/stride errors before invoking x264; an IDR followed by malformed
inputs and the next valid P-slice is production-tested on all three
hosted platforms. Actual x264/post-publication failures still require
recovery IDR. No R3 graphics-channel authority or desktop listener was
introduced. **Next R4:** take final-SHA hosted Linux Release after the
R10 owner fixes its failing test; run owner three-OS commands; integrate
only with genuinely admitted R3 Graphics DVC/full-send provenance.
**Gate B / M3 / M4 / M5 remain OPEN.**

## R6 capture-cycle layout bounds and transactional attach (2026-10-16; exact-SHA CI pending)

Continuing the allowed R6 ownership/error-path audit while genuine Windows
R2/R3 admission remains absent found an unchecked fixed-array boundary in
`WindowsDxgiDuplicationOwner::attachCaptureCycle`. The method iterated
`layout.monitorCount` before proving it was at most
`kMaximumWindowsDesktopMonitors`; a stale/corrupt count could therefore read
past `WindowsDesktopLayout::monitors` before the subordinate capture-cycle
constructor rejected the layout. A non-canonical layout could also construct
and retain a closed staging/capture subordinate before returning `false`,
making a failed attach non-transactional.

Attachment now rejects zero/oversized monitor counts before forming a span or
iterating, rebuilds and compares the canonical desktop layout, requires exactly
one selected output rectangle, and constructs staging/capture subordinates in
local RAII owners. Session-reader state and subordinate ownership are committed
only after the new capture cycle is open. Failed attachment therefore leaves
the already-open duplication owner ready and retryable with no partial
`captureCycle()`.

New dedicated Windows CTest
`windows.capture-dxgi-duplication-owner-capture-cycle-layout-denials` reuses
the existing production duplication owner and synthetic COM-reference fixture.
It rejects an oversized monitor count and a matching-output/non-canonical
virtual desktop, requires no partial capture cycle to remain, then verifies
ordinary owner teardown releases every synthetic native reference once.

Canonical owner-local CMake/CTest is **NOT RUN** in this connector environment.
Exact-SHA hosted Windows/MSVC Debug+Release preflight/full matrix is required
after publication. Owner Windows MSYS2 CLANG64/Clang23 and genuine Windows
R2/R3 admission remain **NOT RUN/BLOCKED**. No live Desktop Duplication or
SendInput is exercised; M4 remains OPEN.

## R9 Client Info / NLA sanitizer exact-SHA hosted receipt (2026-10-16)

**Validated implementation:** `f59f3e89b02925d6d91a5ce35c312830918c0fe8`,
Actions `38900361619`. The workflow completed **FAIL** overall, but the
R9-owned sanitizer job completed **SUCCESS** with the intended expanded
registry coverage. The conditional prerelease publisher was **SKIPPED** because
this was not a version tag.

R9 sanitizer results are: clipboard **36/36 PASS**; bounded R1/R3
transport/CredSSP/licensing **25/25 PASS**; native GSS/R2/R3 **22/22 PASS**;
the concurrently expanded R5 native X11 selection **16/16 PASS**; bounded
MCS/CLIPRDR fuzzer **1/1 PASS**. The newly selected
`transport.mcs-client-info-protected-route` and
`transport.mcs-client-info-protected-route-denials` passed under
ASan/UBSan. The newly selected Linux cases
`security.gssapi-native-admission-r1-nla-provenance-denials`,
`security.gssapi-r3-initial-nla-owner-fence`, and
`security.gssapi-r3-client-info-route-contract` also passed. The
MIT-krb5 LSan suppression remained scoped only to native GSS and appeared in
the same two known provider-failure cases, each reporting **216 bytes / 10
`krb5_copy_principal` allocations**; no unsuppressed sanitizer failure was
reported.

macOS/Clang full CTest is **337/337 PASS** in Debug and **337/337 PASS** in
Release, followed by downstream SDK consumer/package success. Windows/MSVC
native preflight is **37/37 PASS** in Debug and Release; full CTest is
**361/361 PASS** in Debug and **361/361 PASS** in Release, followed by SDK
consumer/package success. Both portable Client Info route cases pass in all
four of those full configurations.

Ubuntu/GCC Debug reached **394/395 PASS**. All five R9 target cases passed,
including the three Linux-only security contracts, before the sole failure:
concurrent R10 test
`runtime.linux-connection-credssp-owner-framing` asserted
`step.plaintextBytesWritten == 0` at
`tests/test_runtime_linux_security.cpp:648`. The R9 implementation changes
only CI regex selection and documentation, so this is not attributed to R9 or
R3 Client Info. Linux Release, SDK consumer and package stages were **NOT RUN**
because the Debug full-suite step failed. Documentation policy **PASS**.

Canonical owner-local `~/rdp-server/build/` configure/build/focused/full
CTest and local sanitizers remain **NOT RUN** in this connector environment.
Owner Linux/X11, Windows MSYS2 CLANG64/Clang23, macOS27, genuine
Kerberos/client-ticket plus native logind admission, Microsoft-client
authentication and live desktop acceptance remain **NOT RUN/OPEN**. M2/M3 are
not accepted by this CI-only coverage expansion.

## R5 complete native X11 sanitizer exact-SHA hosted receipt (2026-10-16)

**Implementation:** `f220436f0da88e6b02f2bd58f1da164826929ac6`.
**Actions:** `38900083125`, overall **SUCCESS**.

The existing R9 Clang ASan/UBSan job compiled every production-linked R5 X11
test executable and the exact 16-case selection completed **16/16 PASS** with
no reported ASan/UBSan finding. Coverage is the complete current R5 native X11
registry: capture layout bounds, cursor reply bounds, XShm arena/connection and
disconnect cancellation, display event budget/readiness/disconnect/deferred
owner teardown, XFixes cursor cancellation, XDamage cancellation, XTEST input
cancellation, the five one-XCB aggregate ownership/event/RandR/R4-read cases,
and the concrete R3-admission input denial. The separate R8 clipboard
sanitizer selection remained **36/36 PASS**.

The same exact SHA passed the full hosted matrix: Ubuntu/GCC **395/395 PASS**
in Debug and **395/395 PASS** in Release; macOS/Clang **337/337 PASS** in
Debug and **337/337 PASS** in Release; Windows/MSVC **361/361 PASS** in Debug
and **361/361 PASS** in Release, with its focused native preflight **37/37
PASS** in both configurations. Documentation policy, installed SDK consumer,
package/digest/upload and the bounded fuzzer all passed. Prerelease publication
was correctly skipped because the commit is not a protocol release tag.

No production R5 source or CTest semantics changed in this increment. Current
shared main still contains no R3 Share/Input or Fast-Path Input PDU event
surface; R3 has advanced through protected Channel Join and Client Info, but
not input parsing. Therefore the roadmap's next R5 production translation
remains **BLOCKED BY R3** and R5 must not introduce another parser/session/input
authority.

Canonical owner-local `~/rdp-server/build`, owner Linux/X11, Windows MSYS2
CLANG64/Clang23, macOS27, genuine positive Kerberos/logind admission, live
XTEST injection, Microsoft-client M3 acceptance and R5 performance benchmarks
remain **NOT RUN**. **Next R5:** preserve the fully sanitized native boundary
and resume production input translation only when R3 exports the authoritative
bounded input event contract. M3 remains OPEN.

## R4 deterministic malformed-NV12 preflight before x264 references (2026-10-16; hosted CI pending)

Starting inspected shared `main`: `06e4793eb7a78ea86bfb7f072b8642f1ec90d1d7`.
Previous R4 ACK-pending frame-ID gate landed at
[`f5e19b8d997ba31501f856e68ec90e61c7c01535`](https://github.com/k1moradi/RDP-server/commit/f5e19b8d997ba31501f856e68ec90e61c7c01535);
[exact-SHA Actions 38897649670](https://github.com/k1moradi/RDP-server/actions/runs/38897649670)
completed **SUCCESS**: Linux/GCC Debug+Release 387/387 each,
macOS/Clang Debug+Release 333/333 each, Windows/MSVC Debug+Release
358/358 each. The new duplicate-ID regression **PASS** on all six
hosted configurations; documentation policy and R9 selected sanitizers
**PASS**. Hosted SDK downstream checks **PASS**. Owner Linux/X11,
Windows MSYS2 CLANG64/Clang23, macOS27 and real client acceptance
remain **NOT RUN**.

The subsequent R4 maintenance audit found a distinct, deterministic
pre-encode source denial. `X264Avc420Encoder::encode()` already refuses
incorrect coded geometry, truncated Y/UV rows, too-short or out-of-range
strides and arithmetic overflow **before invoking x264**. However, the
existing `X264Avc420SegmentedFrameProducer::prepare()` treated every
`encode()` failure as uncertain codec state and rebuilt x264, forcing
an unnecessary IDR on the next valid frame. Invalid caller-owned
NV12 bytes cannot corrupt a codec that was never called.

The existing noninstalled x264 encoder now exposes an allocation-free
`canEncodePicture()` predicate, sharing exactly the same plane/stride
validation with `encode()` (no duplicated validator). The one R4 producer
preflights NV12 geometry and storage using this predicate before stateful
encode, without resetting the encoder on deterministic denial. All
post-x264 failures still conservatively rebuild the reference chain;
presentation generation, RDPGFX metadata/ACK authority, BGRA scratch,
transport full-send and R2/R3 authorization remain unchanged.

New production-linked ordinary CTest
`graphics.x264-segmented-malformed-nv12-reference-continuity`
establishes a genuinely encoded/delivered/ACKed IDR, rejects truncated
Y/UV planes, under-width Y pitch, oversized UV pitch, mismatched coded
geometry and empty Y plane while keeping the existing ACK state unchanged,
then requires the next valid picture to remain a non-IDR P-slice.
It runs in the existing segmented producer executable and centralized
CTest registry; no new runner or graphics owner.

**Authoring gate:** source/tests/central registry/docs written; canonical
owner-local `~/rdp-server/build` configure/build/full CTest **NOT RUN**
because this connector session lacks the home checkout. New exact-final-SHA
hosted Linux/GCC, macOS/Clang, Windows/MSVC Debug/Release, R9 selected
sanitizers, documentation-policy and SDK consumer must be inspected after
publication. Owner three-OS, actual authenticated Graphics DVC, live
desktop/native capture, Microsoft-client rendering and performance
remain **NOT RUN/BLOCKED**. Gate B, M3/M4/M5 remain **OPEN**.

## R9 Client Info / NLA sanitizer coverage reconciliation (2026-10-16; exact-SHA CI pending)

**Publication parent after concurrent reconciliation:** `92a0820d88312de8f7a0a1ae7e733cfc0c2532f8`.
R9 audited the central CTest registry against the single Clang ASan/UBSan
workflow after R2 owner-driven CredSSP and R3 protected Client Info landed.
No production state machine, parser, admission owner, CTest registration or
fixture changes in this increment.

Five existing production-backed behaviors run in ordinary full CTest but were
absent from the bounded R9 sanitizer selections:
`transport.mcs-client-info-protected-route`,
`transport.mcs-client-info-protected-route-denials`,
`security.gssapi-native-admission-r1-nla-provenance-denials`,
`security.gssapi-r3-initial-nla-owner-fence`, and
`security.gssapi-r3-client-info-route-contract`. The first two exercise the
real Enhanced-Security Client Info envelope/parser route and all-join,
I/O-channel, initiator, segmentation and Basic Security Header denials. The
three Linux cases cover real R1 HYBRID provenance refusal, the R2 native
admission boundary, the initial R3 owner fence and the protected Client Info
broker contract. They remain denial/ownership tests: no fake Kerberos
principal, native logind lease or successful R3 admission is introduced.

The existing sanitizer job changes only its CTest selection. The already
compiled `test_owned_mcs_connect_initial` and
`test_linux_gssapi_spnego` targets are reused. One checkout-local
`build/`, ASan/UBSan halt-on-error, leak detection, the MIT-krb5 LSan
suppression scoped only to native GSS, clipboard, the concurrently expanded
R5 X11 group and the bounded fuzzer remain unchanged. Expected selected counts
rise from bounded R1/R3 transport/security **23 to 25** and native
GSS/R2/R3 **19 to 22**.

Pre-change exact-head Actions `38899285708` for
`06e4793eb7a78ea86bfb7f072b8642f1ec90d1d7` is the latest completed
baseline before this R9 selection change. Its R9 sanitizer passed
**36/36 + 23/23 + 19/19 + 7/7 + 1/1**. Linux/GCC full CTest passed
**395/395 Debug and 395/395 Release**, directly running all five cases.
Windows/MSVC passed **361/361 Debug and 361/361 Release**, including both
portable Client Info cases. macOS/Clang Debug passed those portable cases but
ended **336/337** because unrelated
`transport.tcp-native-listener-role-and-mode-denials` asserted
`Batch::BudgetReached` at `tests/test_owned_preauth_session.cpp:4377`;
macOS Release/downstream were **NOT RUN**. Documentation policy passed. Later
concurrent commits do not change these five registry entries or the R9
transport/GSS sanitizer regexes being corrected here.

**Authoring execution:** canonical owner `~/rdp-server/build/` configure,
build, focused/full CTest and local sanitizer execution are **NOT RUN** because
this connector runtime has no mounted owner checkout; no alternate build root,
worktree or side branch is created. Exact-publication-SHA Linux/GCC,
Windows/MSVC, macOS/Clang, R9 sanitizer and documentation-policy evidence is
required after publication. Owner Linux/X11, Windows MSYS2 CLANG64/Clang23,
macOS27, configured KDC/client ticket, positive NSS/logind admission and
Microsoft-client M2/M3 acceptance remain **NOT RUN/OPEN**.

## R5 complete native X11 sanitizer selection (2026-10-16; exact-SHA CI pending)

The prior R5 sanitizer expansion `3b57baa31cd2533d29a00d92d1606f27cb476af8`,
Actions `38894949531`, is **PASS for R5**: its Clang ASan/UBSan job compiled the
real native X11 aggregate and ran **7/7 PASS** for deferred XCB teardown,
aggregate connection denial/lifecycle recovery, event routing, transactional
RandR rebuild, synchronous R4 reads and the R3-admission input denial. Ubuntu/GCC
full CTest on the same SHA is **369/369 PASS** in both Debug and Release,
including all 24 X11-labeled tests. The workflow's overall FAIL is unrelated:
macOS/Clang Debug failed only concurrent R1
`transport.credssp-r1-owned-framing`, while Windows/MSVC Debug failed only
the two known R10 OpenSSL `no OPENSSL_Applink` live-TLS tests. Documentation
policy passed.

Current R3 work has progressed through protected Channel Join and Client Info,
but still exports no Share/Input or Fast-Path Input PDU event surface. R5
therefore does not add protocol parsing or another input/session owner.

This increment completes sanitizer selection for the existing R5 native X11
registry without touching R8 clipboard tests. The same ASan/UBSan job now
builds the remaining production-linked R5 executables and runs exactly **16**
R5 X11 behaviors: capture layout; cursor reply bounds; XShm arena/connection
and disconnect cancellation; display event budget/readiness, disconnect and
deferred-owner teardown; XFixes, XDamage and XTEST child cancellation; the five
one-XCB aggregate ownership/read/resize cases; and the concrete R3-admission
input denial. No CTest is duplicated, no production source changes, and the
ephemeral Xvfb cases still perform no positive admission or live keyboard/
pointer injection.

**Authoring status:** current-main source/CTest/CI mapping inspection PASS.
Canonical owner-local `~/rdp-server/build` compile/CTest is **NOT RUN** in
this connector environment. Exact-SHA hosted ASan/UBSan is **PENDING**. Owner
Linux/X11, Windows MSYS2 CLANG64/Clang23, macOS27, genuine Kerberos/logind
admission, live XTEST and Microsoft-client M3 remain **NOT RUN**. **Next R5:**
after this complete sanitizer selection is green, retain the tested native
boundary and wait for R3's authoritative input PDU/event contract before
production translation. M3 remains OPEN.

### R3 Client Info exact-SHA compile correction (2026-10-16)

Implementation `3819cdaab6b787c037b0aed93e6c6626b9f5b8e2`,
[Actions 38898593347](https://github.com/k1moradi/RDP-server/actions/runs/38898593347),
passed documentation policy but Linux/GCC Debug, macOS/Clang Debug and
the R9 sanitizer build stopped before CTest in the new portable R3 test:
`tests/test_owned_mcs_connect_initial.cpp:581` called the existing
`frameDomainPdu` helper before its later definition and had no prior
declaration. GCC reported “not declared in this scope”; Clang reported
“use of undeclared identifier”. This is an R3 test-ordering compile
failure, not a production parser failure. Windows/MSVC remained in
progress when classified and is not used to infer a result.

The correction is test-only: add the existing helper's exact forward
declaration in the same anonymous namespace before any new Client Info
test uses it. No production code, wire bytes, security flags, admission,
permissions or state transitions change. The corrected exact SHA must
rerun the full hosted Debug/Release matrix and R9 sanitizer selections;
no PASS is carried forward from the failed implementation SHA.
Owner three-OS and real-client admission remain NOT RUN. M2 NOT ACCEPTED.

## R2 owner-driven CredSSP/GSS exact-SHA hosted receipt (2026-10-16)

**Implementation:** `0f5fcd6f55e0a674671927609a78bd841d58405c`,
Actions `38898173843`, completed **SUCCESS**. Documentation-policy,
Ubuntu/GCC, macOS/Clang, Windows/MSVC and the R9 Clang ASan/UBSan job all
completed successfully. All three hosted protocol jobs compiled and ran both
Debug and Release CTests, then staged the installed SDK, ran the downstream
consumer and generated/uploaded the ZIP/SHA-256 package. The conditional
prerelease publication was correctly **SKIPPED** because this was not a
protocol version tag.

The sanitizer job compiled the production-linked Linux GSS target and its
expanded native R2/R3 selection, including
`security.gssapi-r1-owned-credssp-provenance-fence` and
`security.gssapi-r1-owned-credssp-cancellation-fence`; that GSS step and the
entire sanitizer job passed with no reported unsuppressed ASan/UBSan failure.
Ubuntu/GCC full Debug and Release CTest both passed, directly executing the two
new Linux-only cases through the ordinary central registry.

This receipt also corrects one stale authoring sentence. R10 commit
`6ff071954f6d46ade4a41ace3a7ce7b4524a3af4` had already changed the
non-listening Linux aggregate to R1 `HybridNla` and owner-aware CredSSP frame
intake before this R2 implementation published. R10 currently stops at a
complete DER frame because the R2 provider/reply progression was not callable
when that aggregate was written. The remaining composition dependency is
therefore narrower: R10 must invoke
`GssapiSpnegoAcceptor::advanceOwnedCredSspHandshake` with its exact R1 owner
and persistent R2 reader/writer, then proceed to existing native admission only
after `BindingVerified`. R2 does not modify that R10 owner here.

**Still NOT RUN:** canonical owner `~/rdp-server/build/` commands in this
connector environment, owner Linux/X11, Windows MSYS2 CLANG64/Clang23,
macOS27, a configured service keytab plus real client Kerberos ticket through
the new owner-driven exchange, positive NSS/logind admission, Microsoft-client
authentication/desktop acceptance and a production listener/service. M2
remains **NOT ACCEPTED**.

## R3 protected post-join Client Info routing boundary (2026-10-16; hosted CI pending)

Previous R3 joined-role implementation `b31d910a7c5f17f16676469bee7e7c8ba1bd69fe`
has exact-SHA Actions receipt
[38896370927](https://github.com/k1moradi/RDP-server/actions/runs/38896370927):
Linux/GCC **377/377 PASS** in Debug and Release; macOS/Clang
**324/324 Debug PASS** and **323/324 Release**, with sole R1-owned
`transport.tcp-native-accept-ownership` failure at
`tests/test_owned_preauth_session.cpp:1616`; Windows/MSVC stopped in
the R6 preflight compile at `tests/test_windows_desktop_geometry.cpp:491`
because the then-current frame-info test used unavailable equality.
R9 sanitizer selections and documentation policy PASS. The three R3
joined-role tests PASS in all applicable executed configurations.
Those other-road failures do not turn the exact SHA into a full-matrix pass.

This increment follows MS-RDPBCGR 2.2.1.11, 2.2.8.1.1.2.1 and the
Enhanced RDP Security sequence: when Standard Security Exchange is not
used, Client Info follows receipt of the requested MCS Channel Join
Confirm PDUs; the client SendDataRequest uses the assigned UserId and
I/O channel, and Client Info still contains a Basic Security Header with
`SEC_INFO_PKT` even though R1 has already decrypted/authenticated the
outer PDU through the selected external HYBRID security protocol.

R3 adds a syntax-only `parseEnhancedSecurityClientInfoEnvelope` and
a private `routeVerifiedR2ClientInfoEnvelope`. Routing requires the
sole R3 owner in post-Attach Channel Join state, exact bound
PROTOCOL_HYBRID provenance, all configured user/I/O/static joins fully
confirmed, one complete joined SendDataRequest from UserId 1002 on I/O
1003, begin|end MCS segmentation, and an unambiguous Basic Security
Header. `SEC_INFO_PKT` is mandatory; competing packet-kind,
Standard-Security encryption/checksum and heartbeat/transport flags fail
closed. RESET/IGNORE sequence flags and flagsHi are ignored as required.
Only the caller-owned bytes after the 4-byte header are returned; R3 does
**not** parse TS_INFO_PACKET, retain its sensitive strings, advance
licensing, activate Share Control, or dispatch input/clipboard.

The concrete Linux R2 broker is the only positive entry and revalidates
the genuine native lease, original GSS acceptor, exact R1-owned
established TLS/HYBRID connection, policy/session generations and view
permission before this routing step. Invalid routing closes R3 before
R2/GSS teardown. The existing joined CLIPRDR observation is also tightened
to require `kConsoleClipboardPermission`, not generic view permission;
the numeric role remains a transient observation rather than a capability.

Dedicated central-registry CTests:
`transport.mcs-client-info-protected-route`,
`transport.mcs-client-info-protected-route-denials`, and Linux-only
`security.gssapi-r3-client-info-route-contract`. They exercise the
production security-header parser, all-join completion predicate, exact
I/O/initiator/segmentation conditions, conflicting flags, truncation,
static-channel non-equivalence, unforgeable R2/R1 method signatures and
pre-admission terminal denial. No positive Kerberos/logind lease is
fabricated.

**Authoring local build/CTest BLOCKED / NOT RUN:** this environment still
has no `~/rdp-server` checkout and shell GitHub DNS is unavailable.
Exact-SHA hosted Linux/GCC, macOS/Clang, Windows/MSVC Debug/Release,
R9 sanitizer and docs-policy are **PENDING after publication**. Owner
Linux/X11, Windows MSYS2 CLANG64/Clang23, macOS27, real client/KDC/native
session, TS_INFO semantics, licensing and Share/desktop acceptance remain
**NOT RUN**. Next R3: add a bounded TS_INFO_PACKET structural validator
and only then advance the sole session into the server licensing-request
writer/receipt phase. **M2 NOT ACCEPTED.**

## R4 ACK-pending frame-ID preflight exact-SHA hosted CI (2026-10-16)

**Source commit:** [`f5e19b8d997ba31501f856e68ec90e61c7c01535`](https://github.com/k1moradi/RDP-server/commit/f5e19b8d997ba31501f856e68ec90e61c7c01535).
[Exact-SHA Actions 38897649670](https://github.com/k1moradi/RDP-server/actions/runs/38897649670)
has **PASS** for all five mandatory build/test jobs (Linux/GCC,
macOS/Clang, Windows/MSVC, R9 selected ASan/UBSan and documentation-policy).
Protocol prerelease publication was **SKIPPED**; that is not a test failure.

- **Linux/GCC:** full Debug **387/387 PASS**, Release **387/387 PASS**.
  `graphics.x264-segmented-duplicate-id-reference-continuity` **PASS**
  in both configurations (CTest #380). Installed SDK downstream
  configure/link/consumer **PASS**.
- **macOS/Clang:** full Debug **333/333 PASS**, Release **333/333 PASS**.
  The new R4 test **PASS** in both configurations (CTest #326), and
  SDK downstream consumer **PASS**.
- **Windows/MSVC:** native R6 preflight Debug **37/37 PASS** and
  Release **37/37 PASS**; full Debug **358/358 PASS**, Release
  **358/358 PASS**. The new R4 test **PASS** in both configurations
  (CTest #351), and SDK downstream consumer **PASS**.
- **R9 selected sanitizer gate:** **PASS** for its configured suite;
  converter-/x264-specific ASan/UBSan execution is **NOT RUN** unless
  explicitly selected. **Documentation-policy:** **PASS**.
- **Exact hosted full-test commands:** `cmake --build build --config
  Debug --parallel 2` then `ctest --test-dir build --build-config
  Debug --timeout 60 --output-on-failure`, followed by the same
  Release commands; Windows additionally runs `-L windows` preflight
  with `--timeout 20`. Each hosted job uses its single checkout-local
  `build/` root.

The dedicated new offline CTest uses genuine x264 and both NV12 and BGRA
input paths: after one fully delivered initial IDR picture remains
ACK-pending, a duplicate frame ID must be denied without altering ACK
count or encoder reference history, and a fresh ID produces a P slice
rather than an avoidable IDR. This confirms *offline* graphics
publication invariants only, not admission or a rendered desktop.

**Owner-local canonical build/full CTest:** **NOT RUN** in the
connector-only environment (`~/rdp-server` unavailable). Linux/X11,
Windows MSYS2 CLANG64/Clang23, macOS27, real authenticated R3 Graphics
DVC/full-send integration, R5/R6/R7 native capture-driven rendering,
Microsoft-client acceptance and graphics benchmarking **NOT RUN**.
**Gate B / M3/M4/M5 remain OPEN.** Next R4 gate is actual admitted
R3 graphics-channel authority and owner native-client validation;
no independent scheduler or synthetic positive authorization should
be introduced.

## R2 owner-driven CredSSP/GSS handshake boundary (2026-10-16; exact-SHA CI pending)

Starting inspected shared `main`: `35df03319d0a1cf4ac667f1715e7408958b78d74`. R1 now has explicit
`SecurityNegotiationPolicy::HybridNla`, so R2 can consume genuine immutable
HYBRID selection instead of a caller-supplied protocol scalar. This increment
completes the R2 half of issue #17 without taking R1 socket/TLS ownership or
adding a second authentication/session controller.

`GssapiSpnegoAcceptor::advanceOwnedCredSspHandshake` is the single bounded
production progression call. It consumes the exact nonmoving R1
`OwnedPreauthTcpConnection` plus the existing R2 frame reader/reply writer,
requires immutable client-offered + server-selected `PROTOCOL_HYBRID` before
any TLS application byte is read or written, and performs at most one bounded
R1 application read or write per invocation. Existing GSS provider, CredSSP
DER, selected-certificate, nonce/public-key binding, failure-reply and
round-trip rules remain authoritative. Provider-generated replies are queued
against the same R1 owner; caller-prequeued output cannot enter this production
progression path.

The progression pins the exact connection/reader/writer tuple for its lifetime.
Owner/object substitution, raw-SSL API substitution, missing/SSL-only
negotiation provenance, R1 cancellation, stale reply state and malformed/order
errors are terminal. `BindingVerified` means only that genuine Kerberos GSS
and the CredSSP public-key proof have completed and the server binding reply was
fully sent; it is not native OS admission and grants no R3 capability.

Dedicated existing-binary Linux GSS CTests:
`security.gssapi-r1-owned-credssp-provenance-fence` and
`security.gssapi-r1-owned-credssp-cancellation-fence`. The provenance test
uses real loopback R1 TLS for SSL-only, HYBRID-offered/SSL-selected and genuine
HYBRID-selected connections. Invalid provenance consumes/emits zero application
bytes and leaves the client TSRequest byte-for-byte pending in R1. Genuine
HYBRID selection drives that frame through owner-backed R1 reads and then
reaches the existing semantic rejection because ordinary CI supplies no
configured service keytab. The same test proves caller-prequeued output cannot
be written even with valid HYBRID provenance. The cancellation case destroys
R1 TLS before a queued write and requires terminal callbacks without stale SSL
dereference. Compile-time coverage rejects a raw `SSL*` substitute. Both
cases join the existing R9 sanitizer GSS selection.

R1 now supplies the required positive transport provenance. The existing R10
non-listening aggregate already selects `HybridNla` and performs owner-aware
CredSSP frame intake, but it predates this callable R2 provider/reply
progression and still rejects a completed frame instead of advancing GSS.
Ordinary CI also has no real client Kerberos ticket in this fixture, so this
increment does **not** claim Kerberos login, NSS/logind admission or M2
acceptance. The next integration dependency is R10 invoking this exact R2
progression with its persistent reader/writer and existing R1 owner; genuine
client-ticket/native-admission acceptance remains separate.

**Authoring validation:** canonical `~/rdp-server/build/` configure/build/full
CTest is **NOT RUN** in this connector environment because the owner checkout
is unavailable; no alternate build root/worktree was created. Exact-SHA hosted
Linux/GCC, macOS/Clang, Windows/MSVC, R9 ASan/UBSan and documentation-policy
evidence is required after publication. Owner Linux/X11, Windows MSYS2
CLANG64/Clang23, macOS27, genuine KDC/client-ticket + NSS/logind admission and
Microsoft-client acceptance remain **NOT RUN**. M2 remains **NOT ACCEPTED**.

## R9 Channel Join terminal replay exact-SHA hosted receipt (2026-10-16)

**Validated implementation:** `d5a129f2d28e0100cb5d173463a081a83a8a133b`, Actions `38897266092`.
**Validation-receipt publication parent after concurrent reconciliation:** `68cfd7eff0bc42381ff71c6347a937e56e1c2a3f`.
The exact implementation workflow completed **SUCCESS**. The conditional
prerelease job was **SKIPPED** because this was not a tagged prerelease; it is
not reported as a passing Release stage.

The single `r9-security-protocol-sanitizers` job completed **SUCCESS** with
production-linked coverage: clipboard **36/36 PASS**; bounded R1/R3 transport,
CredSSP and licensing **23/23 PASS**; native R2/R3 GSS **17/17 PASS**;
authorized X11/input **7/7 PASS**; bounded MCS/CLIPRDR fuzzer **1/1 PASS**.
The job built both `test_owned_preauth_session` and
`test_linux_gssapi_spnego`. It actually executed
`transport.credssp-r1-owned-framing` and
`transport.credssp-r1-owned-reply` as tests 126/127 and the new
`security.gssapi-r3-channel-join-terminal-replay-fence` plus
`security.gssapi-r3-joined-clipboard-role-contract` as tests 240/241; all
four passed. The MIT-krb5 LSan suppression remained scoped only to the native
GSS step and was used in the same two known provider failure cases, each
**216 bytes / 10 `krb5_copy_principal` allocations**. No unsuppressed
ASan/UBSan/LSan failure occurred.

Hosted full-suite evidence on the same SHA is: Linux/GCC **385/385 PASS**
Debug and **385/385 PASS** Release; macOS/Clang **331/331 PASS** Debug and
**331/331 PASS** Release; Windows/MSVC focused native-adapter **37/37 PASS**
in both Debug and Release, then full **356/356 PASS** Debug and **356/356
PASS** Release. The two historical R10 Windows TLS-context tests,
`runtime.validates-live-tls-context-construction` and
`runtime.tls-context-survives-credential-path-replacement`, both pass on
this descendant SHA; their earlier `f1a6dc...` OpenSSL/Applink failure
evidence remains preserved in the historical R9 receipt rather than being
weakened or removed.

Installed SDK consumer **1/1 PASS** and package generation/upload completed
successfully on Linux, macOS and Windows. Documentation policy **PASS**. The
R1 CredSSP owner tests that had exposed the earlier macOS Release timing
fixture issue pass in both Debug and Release on all three hosted platforms at
this exact SHA.

Canonical owner-local `~/rdp-server/build/` configure/build/focused/full
CTest and local sanitizer execution remain **NOT RUN** in this agent runtime
because the owner checkout is not mounted and shell GitHub DNS is unavailable;
no alternate build root, branch, worktree, patch or quarantine was created.
Hosted runners do not substitute for owner Linux/X11, Windows MSYS2
CLANG64/Clang 23 or macOS 27 validation. Genuine Kerberos/TLS plus native
logind admission, positive authenticated Channel Join, Microsoft-client
authentication and live desktop acceptance remain **NOT RUN/OPEN**. M2/M3
acceptance remains **OPEN**.

## R8 bounded file-stream Lock/Unlock lifecycle (2026-10-16)

P0 is integrated at `2bdc77344862ee589ae3adbdbe167b4d5947bbc7`.
The two exposed macOS R8 failures shared one fixture root cause:
FILEDESCRIPTORW stores `nFileSizeHigh` at descriptor offset 64 and
`nFileSizeLow` at 68, while the generic `put64()` helper correctly writes
ordinary little-endian FileContents SIZE integers low-DWORD first. The
descriptor fixtures now use a dedicated high-then-low helper. Production
FILEDESCRIPTORW decoding was not weakened.

P1 is published at `9938faf3a54682b76e2d925e354f728a32981b65`.
The existing `RemoteTransfer` remains the only clipboard/file-stream owner.
A completely delivered Lock assigns a monotonic nonzero `clipDataId` and
retains at most one exact clipboard generation's existing 64-entry descriptor
metadata. No file body is cached. Matching Unlock releases only that
generation. Receipt and lock-ID counters never reset; completely unwritten
frames may be cancelled, while partial/ambiguous Lock or Unlock delivery
poisons the owner until genuine disconnect.

Lock/Unlock are 12-byte CLIPRDR PDUs: eight-byte header, zero `msgFlags`,
four-byte payload length and one four-byte `clipDataId`. Locked
FileContents requests append that optional ID, producing a 28-byte payload /
36-byte complete CLIPRDR PDU; unlocked requests remain 24/32 bytes.
SIZE/RANGE bounds, huge-file gates, one-outstanding-stream correlation and
joined-MCS writer receipts resolve against the exact current or retained
descriptor generation.

The client Temporary Directory PDU is structurally validated after
capabilities and before the first Format List. `CB_CAN_LOCK_CLIPDATA`
remains deliberately absent from `kSupportedGeneralFlags` (`0x2e`).
R3's protected joined-CLIPRDR role observation from
`b31d910a7c5f17f16676469bee7e7c8ba1bd69fe` is preserved, but it is not
licensing, Share activation or clipboard payload-dispatch permission.
R8 does not duplicate or bypass R2/R3 authority, so capability advertisement
remains disabled until the complete protected initialization/dispatch path
exists.

Dedicated CTests:
`clipboard.file-lock-unlock-wire-receipts`,
`clipboard.file-lock-unlock-partial-send-denials`,
`clipboard.file-lock-unlock-generation-retention`,
`clipboard.file-contents-locked-stream-identity`, and
`clipboard.file-lock-capability-prerequisite-denials`.

Exact-SHA hosted run
https://github.com/k1moradi/RDP-server/actions/runs/38897188955 validated
`9938faf3`: Linux/GCC Debug and Release **PASS** (384/384 each),
macOS/Clang Debug and Release **PASS** (331/331 each), Windows/MSVC Debug and
Release **PASS** (356/356 each), R9 ASan/UBSan clipboard coverage **PASS**
(36/36, including all five new R8 cases), and downstream SDK/package consumer
checks **PASS**. The run's documentation-policy job alone **FAIL**ed because
the production commit intentionally omitted Markdown while concurrent roads
were editing the same documents; this documentation receipt supplies that
required co-change without overwriting those concurrent receipts.

Local owner build/CTest remains **NOT RUN** because this connector environment
does not expose the synchronized `~/rdp-server` checkout and project policy
forbids creating a second build root. Authenticated CLIPRDR, live
Microsoft-client file copy and native Windows/macOS clipboard acceptance
remain **OPEN**.

## R4 duplicate ACK-pending frame-ID pre-encode gate (2026-10-16; exact-SHA CI pending)

Starting inspected `main`: `7a83947d7876574f573ac393d3e1311d40eea80f`.
R4's existing `GfxFrameAckWindow::canRecordFrame()` rejects a frame ID
already outstanding on the same generation. Previously, the stateful
`X264Avc420SegmentedFrameProducer::prepare()` and `prepareBgra()`
preflight only called `GfxPresentationLifecycle::canSubmitFrame()`, which
checks stage, pending send and ACK-window size but not an individual
ACK-pending ID. Consequently, a duplicate ID could be encoded before
`prepareAvc420Picture()` refused the reservation; R4 would then rebuild
x264 history and force an unnecessary IDR for the next valid frame.

The one existing lifecycle now exposes read-only
`canReserveFrame(generation, frameId)`, which combines its original
`canSubmitFrame()` test with the shared serial-overflow bound and *the
same authoritative ACK window's* `canRecordFrame()`. Both full-frame
reservation sites reuse this predicate. Both x264 NV12 and BGRA producers
preflight the specific frame ID before encoding/conversion, retaining the
existing post-encode recovery path for any truly unexpected reservation
failure. No duplicate ACK owner, queue, transport or permission authority
is created. The common event thread continues to serialize preflight and
publication.

New ordinary offline CTest
`graphics.x264-segmented-duplicate-id-reference-continuity` uses the
real vendored x264, RDPGFX packetizer and lifecycle twice: with NV12
input and with borrowed BGRA input. Each case delivers one initial
SPS/PPS/IDR picture, intentionally leaves its ID ACK-pending, denies
a duplicate frame ID before encode, then verifies that a different valid
ID produces a P-slice without recovery IDR. It verifies no rejected
output, no ACK count change and the producer remains valid.

**Authoring status:** production, centralized CTest and docs prepared;
canonical owner `~/rdp-server/build` compile/full CTest **NOT RUN** in
the GitHub-connector environment. Exact-final-SHA hosted
Linux/GCC, Windows/MSVC, macOS/Clang, selected sanitizer and policy
evidence required after publication, including the new named CTest.
Owner Linux/X11, Windows MSYS2 CLANG64/Clang23 and macOS27, real R3
admitted Graphics DVC/full-send, capture-to-client rendering and graphics
benchmark remain **NOT RUN**. Gate B, M3/M4/M5 **OPEN**.
**Next R4 gate:** verify the new exact-SHA CI and any concurrent R1/R3/R6
failures, then integrate graphics only when R3 exposes actual authorized
channel/full-send provenance.

## R6 frame-owner callback lifecycle exact-SHA validation (2026-10-16)

Production/frame-fixture descendant
`1f6240c8d2a4e1a900edd133bfd0be94cd13b9ae`, Actions
`38896793718`, validates the R6 acquire-callback reentry/cancellation guard,
the field-wise fixture correction, and malformed-resource guarded cleanup.

Windows/MSVC focused R6 preflight: **37/37 PASS Debug** and **37/37 PASS
Release**. Both
`windows.capture-dxgi-frame-lease-acquire-callback-revocation` and
`windows.capture-dxgi-duplication-owner-same-adapter-ambiguity` passed in
**0.01 s** in both configurations; the historical
`windows.cursor-dxgi-shape-generation-denials` also remained **0.01 s**.
The authoritative full Windows matrix then passed **351/351 Debug** and
**351/351 Release**.

Ubuntu/GCC passed **378/378 Debug** and **378/378 Release**. The R9 sanitizer
job and documentation-policy both passed. The workflow's overall conclusion is
still **FAIL** solely because macOS/Clang failed the unrelated R1
`transport.credssp-r1-owned-framing` assertion; no R6 test failed.

Canonical owner-local build/CTest and owner Windows MSYS2 CLANG64/Clang23 remain
**NOT RUN** in this connector environment. The repository still lacks a
concrete Windows R2/R3 native admission capability, so no runtime DXGI/Input
binding is authorized. **Next R6 production gate remains owner CLANG64/Clang23
plus genuine Windows R2/R3 authorization; M4 remains OPEN.**

## R9 Channel Join terminal replay fence + cross-road CI verification (2026-10-16; exact-SHA CI pending)

**Initial inspected main:** `e4b0df9c3a2e9e466b3a24cb7dc2f563d2160533`.
**Publication parent after concurrent reconciliation:** `9938faf3a54682b76e2d925e354f728a32981b65`.
R9 independently rechecked the R3 protected Channel Join boundary, the
production `McsChannelJoinWriteGate`, the central CTest registry, the single
R9 sanitizer workflow and the R1-owned CredSSP transport seam. No R2 lease,
successful GSS identity, HYBRID/NLA admission or logind authorization is
fabricated.

The existing transport regressions already cover zero-byte WANT retention,
positive partial delivery with write-slice rotation, stable pending suffixes,
duplicate/stale receipt rejection, overreported byte counts, pending-reply
disconnect/replacement, no membership before complete confirmation, bounded
single-writer queuing and old-receipt rejection on later joins. Therefore R9
adds no redundant transport CTest.

The distinct new Linux production-backed CTest is
`security.gssapi-r3-channel-join-terminal-replay-fence`, dispatched by the
existing `test_linux_gssapi_spnego` executable. It drives the real
`LinuxConsoleAdmissionBroker::completeR3ChannelJoinConfirmWrite`,
`GssapiSpnegoAcceptor`, `OwnedPreauthTcpConnection` and sole
`McsSessionLifecycle`. Null-lease completion attempts with zero, stale,
changed reply/slice and impossible byte counts close R3, licensing, R2 and
GSS; repeated completion, late valid/repeated/malformed/unassigned/changed
Join input, explicit disconnect, R3-only replacement and a completely fresh
owner set cannot revive membership. A standalone production
`McsChannelJoinWriteGate` supplies real pending receipt values only as
non-authoritative bookkeeping and is explicitly retired before replay.

Exact-SHA baseline `f1a6dc4c45030daa7fdc47ad4935a6dd46319d3e`,
Actions `38894157254`, remains overall **FAIL** only because Windows full
Debug is **332/334** on the two R10 TLS-context/OpenSSL tests; Linux/GCC is
**362/362 PASS** Debug and Release, macOS/Clang **310/310 PASS** Debug and
Release, documentation policy PASS, Windows focused native-adapter Debug and
Release **35/35 PASS**, and the R9 sanitizer groups PASS at clipboard 31,
R1/R3 transport/security 20, native GSS/R2/R3 15, authorized X11 input 1 and
bounded fuzzer 1.

R1-owned CredSSP exact commit
`e476ab5b2dd96a6595d3bfe3ac597ffe14965141`, Actions `38894475826`,
proves both `transport.credssp-r1-owned-framing` and
`transport.credssp-r1-owned-reply` are centrally registered, built through
`test_owned_preauth_session`, matched by the sanitizer regex and actually
executed there as tests 123/124 in a **22/22 PASS** selected group. Linux ran
both in Debug and Release within **364/364 PASS**. macOS Debug ran and passed
both within **312/312 PASS**; Release reran both, with only the framing case
failing at that SHA while reply passed. Windows Debug ran and passed both,
then the two R10 runtime TLS-context tests failed, so Windows Release and SDK
downstream stages were **NOT RUN**. Source inspection confirms owner
substitution, direct/raw SSL downgrade and post-cancel stale SSL/certificate
use are denied; no synthetic successful GSS/native admission is introduced.

The existing R9 sanitizer job now also selects this new replay fence and the
current R3 `security.gssapi-r3-joined-clipboard-role-contract`, which was
registered after the prior 15-test native GSS selection but omitted by its
regex. ASan+UBSan halt-on-error, leak detection, the MIT-krb5 LSan suppression
scoped only to the native GSS step, Xvfb behavior, deterministic fixtures and
the one build root remain unchanged.

**Authoring validation:** canonical `~/rdp-server/build/` configure/build,
focused CTest, full CTest and local sanitizer execution are **NOT RUN** because
this execution environment has no mounted owner checkout and shell GitHub DNS
is unavailable; no second build root was created. Exact-publication-SHA
Linux/GCC, Windows/MSVC, macOS/Clang, R9 sanitizer, documentation-policy and
SDK consumer/package jobs are **PENDING**. Owner Linux/X11, Windows MSYS2
CLANG64/Clang23 and macOS27, real Kerberos/logind admission, Microsoft-client
authentication and desktop acceptance remain **NOT RUN**. M2/M3 remain
**OPEN**.

## R1 HYBRID exact-SHA hosted receipt and CredSSP fixture follow-up (2026-10-16)

R1 HYBRID implementation `611c10b6973b077aeb515c75485ca39384159aa0`,
Actions `38896489005`: documentation policy **PASS**; Linux/GCC full Debug
and Release, SDK consumer/package **PASS**; R9 ASan/UBSan selection **PASS**,
including `transport.tcp-owned-hybrid-nla-negotiation`; macOS/AppleClang
Debug **325/325 PASS**. On macOS Release, both new HYBRID cases also **PASS**:
`transport.security-negotiation` and
`transport.tcp-owned-hybrid-nla-negotiation`. The sole macOS Release failure
is the older R1 `transport.credssp-r1-owned-framing` fixture: after the client
accepted an 8-byte TLS application write, the helper returned on the first
legitimate socket-level `NeedRead` before those bytes became readable.

This follow-up changes no production code. The existing owner-backed CredSSP
test drain helper now accepts `NeedRead` as its requested boundary only after
the caller-specified minimum plaintext prefix has actually been consumed.
That preserves one production TLS operation per callback and exercises the
same readiness polling rather than assuming immediate loopback delivery.

Windows on the HYBRID exact SHA did not build R1: the new R6 preflight failed
first at `test_windows_desktop_geometry.cpp:491` because
`WindowsDxgiFrameInfo` lacked the asserted equality operator. That is
R6-owned and Windows R1 remains **NOT RUN** for the HYBRID SHA.

## R6 malformed-acquire guarded cleanup (2026-10-16; exact-SHA CI pending)

Exact-SHA validation of `c31c07f87152f8bd8c536c77abb7f5511871a6e8`,
Actions `38895979261`, did not reach the new Windows CTest because MSVC
rejected its fixture assertion: `WindowsDxgiFrameInfo` intentionally has no
equality operator. Ubuntu/GCC, documentation-policy and the R9 sanitizer job
passed; macOS/Clang again hit the unrelated R1
`transport.credssp-r1-owned-framing` assertion.

The fixture now checks empty frame metadata field-by-field rather than
expanding the production API solely for testing. The same lifecycle audit also
found that a malformed acquire callback returning a native resource together
with `timeout`/error bypassed `WindowsDxgiFrameOwner::releaseFrame` and
invoked the release callback directly. That skipped the owner's release
reentrancy guard.

Malformed returned resources now enter the owner's normal single-release path:
the resource is installed only for cleanup, metadata is zeroed, the owner is
marked terminal before release, and `releaseFrame()` invalidates the borrowed
pointer before invoking the callback. The existing dedicated
`windows.capture-dxgi-frame-lease-acquire-callback-revocation` CTest is
strengthened so release-callback reentry must observe `closed`, with one
backend acquisition, one release, no retained resource and idempotent cancel.

Canonical owner-local CMake/CTest is **NOT RUN** in this connector environment.
Exact-SHA hosted Windows/MSVC Debug+Release preflight/full matrix is required
after publication. Owner Windows MSYS2 CLANG64/Clang23 and genuine Windows
R2/R3 admission remain **NOT RUN/BLOCKED**. Native runtime capture/input binding
remains blocked and M4 remains OPEN.

## R4 reset-stable NV12 scratch exact-SHA hosted CI (2026-10-16)

**Source commit:** [`39443e93b45bdf5b01575a9066f0232f48b8bcdb`](https://github.com/k1moradi/RDP-server/commit/39443e93b45bdf5b01575a9066f0232f48b8bcdb).
[Exact-SHA workflow 38896116551](https://github.com/k1moradi/RDP-server/actions/runs/38896116551)
completed with **overall FAILURE** from separate R1/R3 and R6 regressions,
not from a demonstrated R4 regression:

- **Linux/GCC Debug:** **374/374 PASS**, including new
  `graphics.bgra-nv12-reset-scratch-reuse` and five previous BGRA tests.
  **Linux/GCC Release:** **374/374 PASS**, including the same R4 coverage.
  Downstream installed portable SDK consumer/package checks **PASS**.
- **macOS/Clang Debug:** **321/322 PASS**. The only failing case is
  R1/R3 `transport.credssp-r1-owned-framing` at
  `tests/test_owned_preauth_session.cpp:5708`, unchanged from the preceding
  BGRA CI; new `graphics.bgra-nv12-reset-scratch-reuse` **PASS** at test 320.
  macOS Release and downstream packaging **NOT RUN** because the job stopped
  after the failed Debug CTest.
- **Windows/MSVC:** **FAIL before complete Debug build/full CTest** in the
  independent R6 native preflight: `test_windows_desktop_geometry.cpp:491`
  errors C2676 because `WindowsDxgiFrameInfo` has no equality operator.
  No claim of R4 Windows compile/CTest or Windows Release on this SHA;
  these are **NOT RUN** after that preflight.
- **R9 selected ASan/UBSan job:** **PASS** for its configured scope; the
  converter tests were not among the explicitly reported sanitizer CTests.
  **Documentation-policy:** **PASS**.
- **Owner-local canonical one-root build/full CTest:** **NOT RUN** in this
  connector environment, which has no `~/rdp-server` checkout. Owner
  Linux/X11, Windows MSYS2 CLANG64/Clang23, macOS 27, native capture, and
  Microsoft-client rendering remain **NOT RUN**.

This validates scratch reuse/reset behavior on hosted Linux and macOS while
preserving R4 generation, surface, backpressure, codec reference and full-send
receipt semantics. Next R4 evidence requires clean Windows/MSVC after the
R6 owner fixes preflight and macOS/Clang after the R1/R3 owner fixes framing,
plus independent owner-native matrix runs. Authenticated R3 Graphics DVC and
real client-visible desktop remain dependencies. **Gate B, M3/M4/M5 OPEN.**

## R1 explicit genuine HYBRID/NLA negotiation policy (2026-10-16; exact-SHA CI pending)

Starting reconciled shared `main`: `b31d910a7c5f17f16676469bee7e7c8ba1bd69fe`. R2 already requires immutable
R1 provenance showing both a client HYBRID offer and an actual server
`PROTOCOL_HYBRID` selection before native OS admission. R1 previously had
only the diagnostic TLS selection, which made that positive path impossible.

R1 now exposes one immutable per-connection
`SecurityNegotiationPolicy`. The source-compatible default remains
`DiagnosticTlsOnly`; existing callers keep selecting `PROTOCOL_SSL`.
An explicitly configured `HybridNla` connection selects
`PROTOCOL_HYBRID` only when HYBRID was offered, emits
`HYBRID_REQUIRED_BY_SERVER` for SSL-only/downgrade attempts, and rejects
Restricted Admin, Remote Credential Guard and unknown flags that this
implementation does not support. Standard RDP security remains unsupported.

The policy is fixed before peer bytes enter the existing
`PreauthSession -> PreauthConnectionStream -> PreauthTcpAdapter ->
OwnedPreauthTcpConnection` ownership chain. No second transport/session
controller is added. Provenance remains unavailable until the exact attached
SSL completes TLS and is revoked by terminal cancellation.

Dedicated loopback CTest `transport.tcp-owned-hybrid-nla-negotiation`
proves downgrade denial, exact HYBRID Confirm bytes, real nonblocking TLS on
the same accepted socket/BIO, immutable offered+selected provenance, caller
buffer mutation isolation and revocation. `transport.security-negotiation`
covers combined/HYBRID-only offers, HYBRID_REQUIRED encoding, correlation
acceptance and unsupported-flag denials. R9 sanitizer selection includes the
new owner case.

R1 does not switch R10's non-listening aggregate from its diagnostic default.
R10 owns serving configuration and must opt a genuine serving connection into
`HybridNla` when its CredSSP/GSS/native-admission event loop is composed.
R2 remains the sole identity/OS-admission authority and R3 the sole session
owner. M2 is not accepted by this transport change alone.

## R3 protected joined-CLIPRDR role identity boundary (2026-10-16; exact-SHA CI pending)

**Authoring base:** `e4b0df9c3a2e9e466b3a24cb7dc2f563d2160533`;
**concurrent main reconciled:** `c31c07f87152f8bd8c536c77abb7f5511871a6e8`.
This incremental R3 boundary adds a first-party bounded, allocation-free,
**syntax-only** `resolveMcsStaticChannelRole` mapping between the existing
parsed CS_NET CHANNEL_DEF names and the same owned SC_NET positional static
ID array, per MS-RDPBCGR 2.2.1.3.4 and 2.2.1.4.4. Exact 8-byte
NUL-padded name matching, original positional correspondence, matching
counts, unique nonzero IDs, no GCC/IO collision and ambiguous duplicate
role rejection are required. Recognized roles are cliprdr, rdpdr,
rdpsnd and drdynvc. This pure function never admits a session or channel.

The only positive R3 joined-clipboard role observation remains private to
the noncopyable `McsSessionLifecycle` and reachable solely through
`LinuxConsoleAdmissionBroker::authorizeR3JoinedClipboardChannel`.
R2 must revalidate the genuine native revocable lease, original GSS
acceptor and R1-owned established TLS/HYBRID provenance, view permission,
policy/session generations and native NSS/logind watch for every call.
R3 requires its own `AwaitChannelJoin` phase, bound Connect Response
provenance, allocated UserId, unique negotiated CLIPRDR name/ID and **fully
confirmed joins** on the user channel, I/O channel and CLIPRDR channel.
Before any of those conditions the result exposes no CLIPRDR ID. No
caller-supplied boolean, raw SSL pointer, string or static channel ID can
replace the concrete broker admission. The result is a synchronous
non-capability role observation: caching it never grants clipboard,
MCS Send Data, licensing, Share Control, OS data or input authorization.
R8 and R9 still own their existing bounded clipboard/framing semantics.

Dedicated behavior CTests reuse the central registry and existing binaries:
`transport.mcs-static-channel-role-binding`,
`transport.mcs-static-channel-role-denials`, and Linux-only
`security.gssapi-r3-joined-clipboard-role-contract`.
The portable cases use the real Microsoft 4.1.3 fixture and production
CS_NET/SC_NET allocation to cover the 1004/1005/1006 positional mapping,
reordered IDs, missing/duplicated/unterminated roles, malformed counts,
overflows and collisions. Linux checks concrete native-lease/R1 owner
method signatures and terminal revocation without fabricating positive
native admission.

**Authoring compile/full CTest NOT RUN locally**: no `~/rdp-server`
checkout and GitHub is unreachable by shell DNS. New exact-SHA
Linux/GCC, macOS/Clang, Windows/MSVC Debug/Release, R9 sanitizer and
project policy jobs are **NOT RUN at authoring**, to be checked through
hosted Actions after publication. R10 listener/runtime integration,
real Kerberos client ticket/logind positive admission, MS-RDPBCGR
license/Share activation, R8 CLIPRDR payload dispatch and three owner
OS validation reports are **NOT RUN**. Next R3 increment must add
genuinely protected channel message/role routing with bounded
segmentation, licensing/Share ordering and specific permission checks;
a mere numeric role snapshot is not dispatch permission. M2 **NOT
ACCEPTED**.

## R4 BGRA converter reset reuse + exact-SHA matrix (2026-10-16; new CI pending)

The production BGRA-to-NV12 implementation landed directly on `main` at
[`6749f43fff489eb9d9a8ee27a122bd1004b0c314`](https://github.com/k1moradi/RDP-server/commit/6749f43fff489eb9d9a8ee27a122bd1004b0c314).
Its [exact-SHA Actions 38894864302](https://github.com/k1moradi/RDP-server/actions/runs/38894864302)
completed **overall FAIL** (other-road regressions), with the following
precise evidence:

- **R4:** all five newly registered `graphics.bgra-nv12-*` /
  `graphics.x264-bgra-*` CTests **PASS** in Linux/GCC Debug and Release,
  macOS/Clang Debug, and Windows/MSVC Debug. The eight existing
  `graphics.x264-*` CTests also **PASS** in those Debug jobs.
- **Linux/GCC:** complete Debug **369/369 PASS** and Release **369/369 PASS**;
  downstream portable SDK package/consumer **PASS**.
- **macOS/Clang:** Debug **316/317 PASS**, one unrelated
  `transport.credssp-r1-owned-framing` assertion at
  `tests/test_owned_preauth_session.cpp:5708` (R1/R3); Release and SDK
  downstream **NOT RUN** because Debug CTest stopped the job.
- **Windows/MSVC:** Debug **339/341 PASS**; unrelated R10
  `runtime.validates-live-tls-context-construction` and
  `runtime.tls-context-survives-credential-path-replacement` fail with
  `OPENSSL_Uplink(...): no OPENSSL_Applink`. Release/downstream **NOT RUN**
  at this SHA because Debug CTest stopped the job.
- **R9 selected sanitizer job:** **PASS**, but BGRA converter-specific
  sanitizer instrumentation **NOT RUN** unless explicitly selected.
  Documentation-policy job **PASS**.
- **Owner local:** Linux/X11, Windows MSYS2 CLANG64/Clang 23, macOS 27,
  native capture integration and Microsoft-client graphics **NOT RUN**.

A focused subsequent R4 correction preserves the converter's initialized
scratch **size as well as capacity** on `reset()`. The old `clear()`
invalidated output correctly but caused a new large allocation on the next
same-geometry conversion despite retained capacity; it could also skip the
active-overlap check while size was zero. `ready_` continues to invalidate
published planes, and the entire allocation stays R4-owned. New dedicated
`graphics.bgra-nv12-reset-scratch-reuse` CTest checks publication
invalidation, retained capacity, overlap denial immediately after reset,
same-address reuse on a fresh frame, and correct BT.709 output. This change
does not alter the codec owner, capture authority or ACK accounting.

**Validation for the reset refinement:** code, CTest and docs authored;
canonical owner-local compile/full CTest **NOT RUN** (no `~/rdp-server`
checkout in this environment). Exact-final-SHA hosted CI is required before
claiming this new regression **PASS**. No listener or synthetic R2/R3 channel
is enabled. **Next R4:** confirm exact-SHA CI and owner platform checks,
then integrate only with genuinely admitted R3 Graphics DVC/full-send and
native R5/R6/R7 synchronous capture seams. Gate B, M3/M4/M5 and live
Microsoft-client rendering remain **OPEN**.

## R6 frame-lease acquire callback revocation (2026-10-16; exact-SHA CI pending)

Exact validation of the preceding same-adapter ambiguity fix
`91423a68f6af1569029cc2016b9cfa9663ea1b18`, Actions
`38895053035`, proved the Windows R6 preflight in both MSVC configurations:
**36/36 Debug PASS** and **36/36 Release PASS**. The new
`windows.capture-dxgi-duplication-owner-same-adapter-ambiguity` passed in
**0.01 s** in each preflight and again in the ordinary full Windows Debug
CTest. Ubuntu/GCC, documentation-policy and the R9 sanitizer job also passed.
The exact workflow remained overall **FAIL** only because the full Windows
Debug suite hit the already-owned R10 OpenSSL Applink pair and macOS/Clang hit
the unrelated R1 `transport.credssp-r1-owned-framing` assertion. A later R10
commit addresses its test oracle independently.

Continuing the allowed R6 ownership audit found a second callback-lifecycle
gap in `WindowsDxgiFrameOwner`. Release-callback reentry was already denied,
but acquire-callback reentry was not: while the callback was active,
`resource_` was still null, so a nested `acquireFrame` could enter a second
acquisition. In addition, a synchronous callback could call `cancel()`, set
the owner terminal, then return a newly acquired resource; the old outer path
would commit and return that lease from the already-closed owner.

The frame owner now marks acquisition callbacks in progress. Nested acquisition
returns `busy` without invoking the backend. If cancellation occurs inside
the acquire callback, any resource returned by that callback is routed through
the ordinary single-release path and `acquireFrame` returns `closed`; the
resource and frame metadata are never published. Dedicated CTest
`windows.capture-dxgi-frame-lease-acquire-callback-revocation` covers both
reentry and cancel-with-returned-lease cleanup, including idempotent later
cancel/destruction.

Canonical owner-local CMake/CTest is **NOT RUN** in this connector environment.
Exact-SHA Windows/MSVC Debug+Release preflight and full matrix are required
after publication. Owner Windows MSYS2 CLANG64/Clang23 remains **NOT RUN**.
No live Desktop Duplication or R2/R3 authorization is fabricated.

**Next R6 production gate remains unchanged:** concrete Windows R2/R3
authorization plus the owner CLANG64/Clang23 receipt. Native runtime
capture/input binding remains **BLOCKED** and M4 remains OPEN.

## R10 Windows live-TLS test-oracle cross-CRT correction (2026-10-16; exact-SHA CI pending)

Validated descendant `2bdc77344862ee589ae3adbdbe167b4d5947bbc7`,
Actions `38893987860`, exercises unchanged R10 Linux provisioning/aggregate
sources from `be99fb50d0f1c7ae981a8e706ec44794a309eadc`: Ubuntu/GCC full
CTest is **362/362 PASS** in Debug and Release, macOS/Clang is **310/310
PASS** in Debug and Release, and the R9 sanitizer job passes its selected
scope. Earlier exact R10 workflows remain historical pre-R10-test failures.

Windows/MSVC Debug on the same descendant is **332/334**; only
`runtime.validates-live-tls-context-construction` and
`runtime.tls-context-survives-credential-path-replacement` fail with
`OPENSSL_Uplink(...): no OPENSSL_Applink`. The neighboring production
R1/R10 live handshake and identity-continuity tests PASS, as do all offline
TLS credential parsing cases.

Root cause is test-only: `test_runtime_tls_context.cpp::readCertificate()`
passed the application CRT's `FILE*` to `PEM_read_X509`. Production R10
already uses a memory-BIO boundary. The oracle now bounds the fixture to 1 MiB,
reads exact bytes with the application CRT into
`std::make_unique_for_overwrite<unsigned char[]>`, rejects short/growing
input, and parses with `BIO_new_mem_buf` / `PEM_read_bio_X509`. No Applink
shim or production TLS behavior changes.

The R1 half of issue #17 landed at
`e476ab5b2dd96a6595d3bfe3ac597ffe14965141`: owner-aware CredSSP framing
routes application I/O through the exact `OwnedPreauthTcpConnection`.
R10/R2 still must consume that seam with the genuine GSS/CredSSP owner, and
genuine production HYBRID negotiation remains an R1 dependency. No listener
is permitted yet.

**Authoring status:** source/log/doc review only. Canonical owner-local
configure/build/CTest is **NOT RUN** because this connector environment has no
owner checkout; no alternate build root was created. Exact-SHA hosted
Windows/MSVC Debug+Release and the ordinary Linux/macOS matrix are required
after publication. Owner Windows MSYS2 CLANG64/Clang23, Linux/X11, macOS27,
real KDC/client ticket, positive logind admission, external RDP client and
listener/service remain **NOT RUN**.

**Next R10 gate:** Windows/MSVC PASS for the two live TLS-context cases and
full matrix, then compose R2 genuine CredSSP/GSS state with the new R1
owner-aware framing seam before any listener.

## R6 DXGI same-adapter ambiguity ownership fix (2026-10-16; exact-SHA CI pending)

Maintenance review of the existing `WindowsDxgiDuplicationOwner` found one
terminal enumeration alias bug without changing the admission boundary. When a
second output on the **same adapter** matched the selected HMONITOR/bounds, the
ambiguous-output branch released `candidateAdapter` unconditionally even
though it was the same retained reference already stored in `adapter_`.
Terminal `close()` then released `adapter_` again. Real DXGI enumeration
normally exposes one output per monitor, but the owner contract already treats
duplicate matches as hostile/ambiguous and must remain correct on that path.

The ambiguity branch now releases a candidate adapter only when it is distinct
from the retained `adapter_`; terminal `close()` remains the sole releaser
of the retained reference. Existing cross-adapter ambiguity behavior is
unchanged. New dedicated CTest
`windows.capture-dxgi-duplication-owner-same-adapter-ambiguity` reuses the
existing production owner and synthetic COM-reference fixture, presents two
matching outputs from one adapter, and requires both output references plus the
single adapter reference to be released exactly once. The fixture's release
callback asserts on any double release.

Canonical owner-local CMake/CTest is **NOT RUN** in this connector environment.
Exact-SHA hosted Windows/MSVC Debug+Release preflight/full-matrix validation is
required after publication; non-Windows jobs remain regression evidence only.
No live desktop, `DuplicateOutput`, capture, input, or fabricated R2/R3
authorization is used.

**Next R6 production gate remains unchanged:** owner Windows MSYS2
CLANG64/Clang23 and a concrete R2/R3 Windows authorization capability. Native
runtime capture/input binding remains **BLOCKED** and M4 remains OPEN.

## R5 one-XCB ownership sanitizer expansion (2026-10-16; exact-SHA CI pending)

Starting shared `main`: `6749f43fff489eb9d9a8ee27a122bd1004b0c314`. R3 still exposes no authoritative
Share/Input or Fast-Path Input PDU event surface, so the roadmap's next R5
production translation remains dependency-blocked and no competing parser,
session owner or input controller is introduced.

R5 instead extends the existing bounded ASan/UBSan job across the already
registered deterministic native ownership boundaries. The sanitizer build now
also compiles `test_x11_display_events` and
`test_x11_desktop_resources`; the X11 sanitizer step runs the existing
`x11.display-event-failure-defers-owner-teardown`,
`x11.desktop-resource-owner-connection-denial`,
`x11.desktop-resource-owner-lifecycle`,
`x11.desktop-resource-event-routing`,
`x11.desktop-resource-randr-rebuild`,
`x11.desktop-resource-r4-read-boundary`, and
`x11.input-r3-admission-route-denials-and-revocation` CTests. The synthetic
Xvfb cases exercise real XCB/XShm/XFixes/XDamage/XTEST construction and
ordered teardown but still perform no positive R2 admission or live keyboard/
pointer injection.

No production source or CTest registry is changed. This is deliberately the
same one-root sanitizer job and existing behavior tests, not a parallel test
harness. **Authoring status:** source/CMake/CI contract review PASS; canonical
owner-local build/CTest **NOT RUN** in this connector environment; exact-SHA
hosted CI **PENDING**. Owner Linux/X11, Windows MSYS2 CLANG64/Clang23,
macOS27, genuine Kerberos/logind admission, live XTEST and Microsoft-client M3
remain **NOT RUN**. **Next R5:** if this sanitizer expansion passes, retain the
validated native boundary and wait for R3's real input PDU/event contract
before adding production translation. M3 remains OPEN.

## R4 bounded desktop BGRA to AVC420 NV12 boundary (2026-10-16; CI NOT RUN)

Starting inspected shared `main`: `b348e2708a9870b69c7e099302357a4a65cef0e5`.
The next missing R4 format boundary is implemented under the existing noninstalled
`rdp-server-graphics` target as `BgraNv12Converter` and
`X264Avc420SegmentedFrameProducer::prepareBgra()`. No R1 transport,
R2 admission, R3 DVC, R5/R6/R7 capture owner, scheduler, listener or
second encoder is introduced. The capture view is borrowed only during the
synchronous call; R4 retains reusable, contiguous, bounded NV12 bytes.

**Input/codec policy:** exact complete visible BGRA/XRGB frame, even nonzero
visible geometry, checked 4-byte pixels, full row stride and full row bytes,
no source/scratch overlap; reject any mismatch to
`gfxAvc420CodedGeometry()` or the x264 64 MiB NV12 limit before touching
output. RGB ignores alpha. Scalar Q16 full-range BT.709 Y/Cb/Cr uses signed
nearest-integer rounding, ties away from zero, and 8-bit clamp. Averages each
2x2 RGB block before chroma conversion and edge-replicates right/bottom
pixels into aligned 16x16 coded margins. Y and UV strides equal coded width,
with no uninitialized padding and no resize/compositing.

**Publication/continuity:** one same-generation coded/visible and surface
preflight checks `gfxAvc420PictureMetadataValid()` and
`canSubmitFrame()` before conversion. The current producer is still the
only x264 reference owner; invalid BGRA and ordinary backpressure leave
references untouched, successful full delivery permits P slices, failed
post-encode publication rebuilds IDR state, and terminal abort drops
generation and encoder history. Only R3's genuine complete wire-delivery
receipt advances the existing ACK owner.

**Dedicated offline behavior CTests (added to existing x264 segmented
producer executable):**
`graphics.bgra-nv12-bt709-pixel-oracle`,
`graphics.bgra-nv12-stride-padding-lifetime`,
`graphics.bgra-nv12-invalid-frame-denials`,
`graphics.x264-bgra-segmented-production-chain`, and
`graphics.x264-bgra-backpressure-reference-denials`.

**Validation:** source and centralized CTest registration authored;
owner's canonical `~/rdp-server/build` configure/build/full CTest **NOT RUN**
because this session cannot access that checkout or execute hosted tooling
directly. Initial exact-SHA R4 historical Actions
[38881366561](https://github.com/k1moradi/RDP-server/actions/runs/38881366561),
[38882596797](https://github.com/k1moradi/RDP-server/actions/runs/38882596797)
and [38883477072](https://github.com/k1moradi/RDP-server/actions/runs/38883477072)
all concluded **FAIL** due to R6/R10 Windows tests or R8 clipboard
assert-macro compilation, rather than a confirmed R4 regression. The new
change requires *its own* exact-final-SHA Linux/GCC, Windows/MSVC, macOS/Clang,
sanitizer, documentation-policy and downstream SDK checks after publication.

**Next gate:** run/reconcile final-SHA hosted CI and owner's Linux/X11,
Windows MSYS2 CLANG64/Clang23, and macOS 27 validations. Real authenticated
R3 Graphics DVC/full-send integration, native capture-driven scheduling,
Microsoft-client display, Gate B and M3/M4/M5 acceptance remain **OPEN**.

## R2 HYBRID provenance descendant validation receipt (2026-10-16)

R2 implementation `2fb5ed5a832c97241d236813599b6d1e8efef985` and its downstream
R1-owner call-site repair `461077c612ec4370d8f943e1a2502172e4649ee3` remain present in
current `main`. Their exact-SHA workflows both failed before authoritative R2
CTest completion while shared-branch compile blockers were still present, so
neither red workflow is reported as an R2 behavior failure.

A later exact descendant, `2bdc77344862ee589ae3adbdbe167b4d5947bbc7`
(Actions `38893987860`), provides the first clean hosted evidence after those
shared blockers were repaired. Linux/GCC configured and compiled Debug and
Release and passed the full registered CTest suite in both configurations;
the Ubuntu Clang ASan/UBSan job also compiled the production-linked Linux GSS
binary and passed its selected R2/R3 GSS and X11 authorized-input denial sets.
macOS/Clang likewise compiled and passed the full Debug and Release suites.
Windows/MSVC compiled Debug successfully, then its full CTest run failed only
at the two R10 live-TLS-context tests reporting OpenSSL Applink; Windows
Release/package stages were therefore not run. The first listed failing CTest,
`runtime.validates-live-tls-context-construction`, belongs to R10, not R2.
Documentation-policy passed.

The two R2 behavior-named regressions remain centrally registered:
`security.gssapi-native-admission-r1-nla-provenance-denials` and
`security.gssapi-r3-initial-nla-owner-fence`. Current R1 still selects
diagnostic `PROTOCOL_SSL`, so the hosted evidence proves the fail-closed
boundary only; genuine HYBRID/Kerberos/logind admission remains unavailable.
Canonical owner `~/rdp-server/build/`, owner Linux/X11, Windows MSYS2
CLANG64/Clang23, macOS27, genuine Kerberos/logind and Microsoft-client M2
acceptance remain **NOT RUN**. R10 live serving composition also remains a
separate dependency.

## R1-owned CredSSP framed application I/O seam (2026-10-16; exact-SHA CI pending)

Starting reconciled shared `main`: `5d07e0881f8494878d7b92ace5a3ef9da64c371e`. This increment addresses
cross-road issue #17 without adding a second TLS, authentication, or session
owner. R2's existing `TsRequestFrameReader` and
`TsRequestTlsReplyWriter` retain DER framing, selected-certificate pinning
and GSS-facing semantics, while new production overloads consume the exact
live R1 `OwnedPreauthTcpConnection`. TLS application plaintext is read and
written only through `readTlsApplicationData()` /
`writeTlsApplicationData()`; an owner-backed frame/reply never advances its
borrowed SSL directly.

The reader pins the exact established SSL plus the nonmoving R1 owner on its
first owner-backed read. Owner substitution, switching to the raw-SSL read
path, selected-certificate substitution, inactive transport, malformed DER
and terminal R1 I/O fail closed. `completedFrameServerTls()` first checks
that the owner still exposes the same established SSL before certificate
revalidation, so R1 cancellation cannot leave a stale SSL dereference.

The reply writer maps R1 Progress/NeedRead/NeedWrite/terminal results with no
hidden retry and preserves stable queued bytes across WANT. Existing GSS
queueing may still supply the established SSL to `queueReply` because
queueing performs no TLS I/O; a fresh queued writer may be adopted by that
exact R1 owner on its first write. Once owner-bound, raw
`SSL_write_ex` progression is terminally denied. `releaseReply()` also
rechecks the owner-to-SSL relation before touching certificate state.

Dedicated production-backed loopback CTests are
`transport.credssp-r1-owned-framing` and
`transport.credssp-r1-owned-reply`. They cover initial WANT, split DER
progress, exact TLS/certificate provenance, raw-path downgrade denial, owner
substitution, R1 cancellation, forced 1 KiB short writes, exact
client-visible DER, raw GSS-style queue adoption and cancellation between
final write progress and release. They create no Kerberos success, native OS
admission, R3 advancement or externally reachable listener.

The prior R1/R10 test publication `b41269ed75628285767dc3a59d7bedacfc3dcc8b`
ran as Actions `38883617565`: documentation-policy **PASS**, while all
three protocol jobs and R9 sanitizer compilation were blocked before R1
execution by the unrelated R8 assert-macro fixture error in
`test_owned_remote_transfer.cpp`. Shared main has since fixed that compile
blocker (`fa79a916fbdda240a8df9601858989ede5e4ca92`) and its follow-up
FILEDESCRIPTORW fixture sizes
(`2bdc77344862ee589ae3adbdbe167b4d5947bbc7`). No result from the blocked
run is counted as R1 behavioral evidence.

This closes the R1 transport half of issue #17. R2/R10 still need to drive
their genuine CredSSP/GSS state machine through these owner-aware calls, and
R1 still selects diagnostic `PROTOCOL_SSL`; genuine production
`PROTOCOL_HYBRID` negotiation remains the next independent R1 dependency
before positive M2 admission. M2 remains **NOT ACCEPTED**.

## R5 X11 lifecycle/input-boundary descendant hosted validation (2026-10-16)

Validated descendant: `2bdc77344862ee589ae3adbdbe167b4d5947bbc7`,
Actions `38893987860`. The R5 lifecycle correction from
`f1718fa601c12e9ff10f9be3bba281acd0a57e90` remains present unchanged while
the descendant also contains later R2/R3/R8/R9 work.

**R5/Linux PASS:** Ubuntu/GCC full CTest is **362/362 PASS** in both Debug and
Release. The production-backed R5 cases all pass in both configurations:
`x11.desktop-resource-owner-connection-denial`,
`x11.desktop-resource-owner-lifecycle`,
`x11.desktop-resource-event-routing`,
`x11.desktop-resource-randr-rebuild`,
`x11.desktop-resource-r4-read-boundary`, and
`x11.input-r3-admission-route-denials-and-revocation`. The corrected
lifecycle case completed in about **0.03 s** in both Debug and Release. The
Linux registry reports **24 x11-labeled tests** total.

**Sanitizer PASS:** the R9 ASan/UBSan job passed its full selected scope,
including **31/31** clipboard tests, **20/20** bounded R1/R3 MCS/CredSSP/
licensing tests, **14/14** native R2/R3 GSS tests,
`x11.input-r3-admission-route-denials-and-revocation` **1/1 PASS** under
ASan/UBSan, and the bounded fuzzer **1/1 PASS**.

**Cross-platform context:** macOS/Clang full CTest is **310/310 PASS** in both
Debug and Release. Windows/MSVC native R6 preflight is **35/35 PASS** twice,
but the full Windows Debug registry is **332/334** because unrelated R10
`runtime.validates-live-tls-context-construction` and
`runtime.tls-context-survives-credential-path-replacement` fail with
`OPENSSL_Uplink ... no OPENSSL_Applink`; Windows Release/package therefore
did not run. Documentation-policy passes. The overall workflow conclusion is
**FAIL solely at that Windows R10 boundary**, not an R5 failure.

The shared FILEDESCRIPTORW fixtures repaired on this SHA also pass in Linux,
macOS and the sanitizer scope. Canonical owner-local Linux/X11, Windows MSYS2
CLANG64/Clang23 and macOS27 remain **NOT RUN**, as do genuine positive
Kerberos/logind admission, live XTEST injection and Microsoft-client M3.

**Next R5 remains BLOCKED on R3 protocol ownership:** there is still no
authoritative R3 Share/Input or Fast-Path Input PDU event surface to translate
into the existing typed `X11InputEvent`. R5 must not introduce a competing
parser/session/input controller. Resume production input translation only when
R3 exposes that boundary; M3 remains OPEN.

## R5 descendant FILEDESCRIPTORW fixture unblock (2026-10-16; CI pending)

R5 validation descendant `fa79a916fbdda240a8df9601858989ede5e4ca92`, Actions
`38893052784`, compiled past the prior clipboard assert-macro error. macOS
then ran Debug CTest and failed only
`clipboard.file-descriptor-metadata-validation` and
`clipboard.file-contents-response-rejections`. Production
`RemoteTransfer::storeFileGroupDescriptors` reads FILEDESCRIPTORW
`nFileSizeHigh` at byte 64 and `nFileSizeLow` at byte 68; the fixtures had
incorrectly reused the generic low-first little-endian `put64`.

This shared test-only repair adds `putDescriptorFileSize`, writing high then
low DWORD, at the four FILEDESCRIPTORW fixture sites. Generic `put64` remains
unchanged for true contiguous 64-bit FILECONTENTS payloads. No R8 production
behavior or R5 X11 production code changes. Linux/sanitizer on that descendant
were separately blocked by a stale R3 test accessor; R9 repaired its own
fixture before this change, and concurrent R3 Channel Join work on current
`main` is preserved unchanged.

**R5 remains dependency-blocked for new production input work:** the repository
still has no authoritative R3 Share/Input or Fast-Path Input PDU event surface
to translate into the existing typed `X11InputEvent`. Do not add a second
parser/session/input owner. Exact descendant hosted CI is the next automated
gate for the existing R5 matrix; owner Linux/X11, Windows MSYS2
CLANG64/Clang23, macOS27 and live Microsoft-client acceptance remain **NOT
RUN**.

## R3 protected Channel Join intake and confirmation (2026-10-16; exact-SHA CI pending)

Starting inspected main for this increment:
`9131611a110aa7bbe6746c341607c8667ddfad4a`;
latest reconciled shared main:
`07f53d3aef9162a55943cefe6c6bd513a757cc12`.
The previous R3 Attach User implementation
`f5fd24e2e6a5c41409f38746c5adaa8fd56504e5`
compiled the portable R3 test target on Linux in Actions
[38885550643](https://github.com/k1moradi/RDP-server/actions/runs/38885550643),
but its full Debug/Release matrix FAILED at unrelated R8
`tests/test_owned_remote_transfer.cpp` assert macro parsing
(lines 1634-1655), also blocking R9 sanitizer execution. The
documentation-policy job PASSED. Those are not R3 CTest PASS receipts;
the source owner of the first failure is R8. Later main includes a
separate R8 test correction, but no success is inferred before hosted CI.

The sole `McsSessionLifecycle` now exposes *private* protected
post-Attach Channel Join intake and confirmation progress. The only
positive entry is the concrete LinuxConsoleAdmissionBroker with the
nonforgeable R2 lease, original GSS acceptor, exact R1-owned established
HYBRID/NLA TLS connection, bounded already-decrypted complete TPKT, and
`kConsoleViewPermission`. R2 rechecks GSS/CredSSP certificate, native
NSS/logind watch, policy epoch and stored session/admission generations
before each Join intake, writer suffix and accepted-byte completion.
Every denial tears down R3 protocol, licensing and channel state before
R2/GSS; R1 TLS/socket teardown remains under its original owner.

After a fully completed Attach User Confirm, R3 validates each Channel
Join Request through the existing single T.125 parser and
`McsChannelJoinWriteGate`. Only UserId 1002 and the assigned user,
I/O 1003 and static channels may be joined. Correctly repeated joins
are idempotent. Distinct client-batched joins are bounded by fixed
allocation; the same existing gate serializes each 15-byte confirm
with nonzero reply and write-slice receipts, stable backpressure bytes,
one-completion-at-a-time membership, and terminal stale/overreported
receipt denial. No second writer, scheduler, socket owner or borrowed
packet state is introduced. The public `onDomainPdu()` remains
denial-only. Channel membership alone does not authorize Send Data,
licensing, Share Control, graphics, input or clipboard.

New central-registry CTests in the existing executables:
`transport.mcs-session-join-confirm-receipts`,
`transport.mcs-session-join-confirm-denials` and
`security.gssapi-r3-channel-join-contract` (Linux GSSAPI).
Offline tests cover real production join gate wire/receipt behavior
and compile-time protected authority signatures plus genuine null-lease,
missing R1 TLS and terminal replay denials. No test invents an R2
positive lease. **Owner local full build/CTest NOT RUN** because
`~/rdp-server` is absent and shell GitHub DNS fails. **Hosted exact-SHA
Linux/GCC, macOS/Clang, Windows/MSVC Debug/Release, R9 sanitizers and
owner Linux/X11, Windows MSYS2 CLANG64/Clang 23 and macOS 27 remain
NOT RUN for this increment at authoring.** Next R3 requires
R2-authorized channel-role dispatch/licensing/Share progression and
real-client positive native-admission integration. **M2 NOT ACCEPTED.**

## R6 hosted Windows native-adapter stabilization receipt (2026-10-16)

R6 CI-preflight commit `d965eb8e15c9dbffd30ed497020f7d0560384eef`
was published directly to `main`; Actions
`38892908446` proved the new Windows preflight works before the unrelated
full-build blocker. MSVC Debug built the existing
`test_windows_desktop_geometry` production-backed fixture and its **35/35**
`windows`-labeled CTests passed. The same target then built under MSVC
Release with assertions retained and **35/35** passed. In both configurations
`windows.cursor-dxgi-shape-generation-denials` passed promptly, confirming the
pre-map invariant fix instead of the historical 1,500-second stall. The later
full Debug compile on that SHA still failed on unrelated R8 assertion-macro
source and therefore did not reach the ordinary full CTest.

Descendant `fa79a916fbdda240a8df9601858989ede5e4ca92`, Actions
`38893052784`, repaired that shared compile blocker and repeated the same R6
preflight: **35/35 Debug PASS, 35/35 Release PASS**. Windows full Debug compile
also passed and ordinary CTest ran the R6 cases again; both
`windows.cursor-dxgi-shape-owned-lifetime` and
`windows.cursor-dxgi-shape-generation-denials` passed in **0.01 s**, as did
the generation/session, duplication/frame-lease/staging, metadata, cursor
snapshot and SendInput-controller fixtures. The repository-wide Windows Debug
CTest still failed on unrelated R8
`clipboard.file-descriptor-metadata-validation` and
`clipboard.file-contents-response-rejections` plus the R10
`runtime.validates-live-tls-context-construction` and
`runtime.tls-context-survives-credential-path-replacement` OpenSSL Applink
failures. Full Windows Release was skipped after that authoritative Debug
failure even though the focused R6 Release suite had already passed.

On the same descendant, documentation-policy **PASS**. Linux/GCC and the R9
sanitizer job failed while compiling an R3/R9 GSS fixture that referenced the
removed `McsSessionLifecycle::pendingConnectResponse` API; macOS/Clang reached
CTest and failed only the two R8 clipboard cases above. These are cross-road
blockers and are not R6 ownership changes.

**R6 status:** hosted MSVC native-adapter Debug/Release focused validation is
**PASS**; the original DXGI pointer regression is stabilized. Canonical
owner-local CMake/CTest and owner Windows MSYS2 CLANG64/Clang23 remain
**NOT RUN** here. Source still exposes no genuine Windows R2/R3 admission
capability, so native DXGI/Input runtime binding remains **BLOCKED** and no
`SendInput` callback is exposed. M4 remains OPEN.

**Next R6 production gate:** owner Windows MSYS2 CLANG64/Clang23 receipt and a
concrete R2/R3 Windows authorization capability. Until both exist, do not add a
runtime capture/input route; continue only validation/maintenance of the
existing single R6 owners.

## R5 lifecycle validation update and shared CI unblock (2026-10-16; descendant CI pending)

Historical lifecycle workflow `38873727660` attempt 2 completed **SUCCESS**
at unchanged SHA `45dc57878bcc741a87bd2ba8b9b9edf15588f062`. Linux/GCC Debug and
Release each passed **289/289** CTests; the previously intermittent
`x11.desktop-resource-owner-lifecycle` passed in both (**0.07 s** each).
This confirms the old fixture could pass unchanged and is consistent with the
last-client Xvfb reset race already reproduced by the R5 bounded probe; it does
not invalidate the deterministic `-noreset` correction.

Exact R5 implementation `f1718fa601c12e9ff10f9be3bba281acd0a57e90`, Actions
`38885619241`, concluded **FAIL** before any R5 CTest could run. Linux/GCC,
macOS/Clang, Windows/MSVC and the R9 sanitizer job all stopped while compiling
unrelated R8 test source `tests/test_owned_remote_transfer.cpp`: two
`assert` invocations contained a braced `std::u16string_view{ptr, size}`
initializer whose comma was parsed as a second macro argument. Documentation
policy passed. The failure is therefore a shared test-build blocker, not an R5
runtime/lifecycle failure.

This descendant repair changes only those two R8 test assertions by wrapping
the complete Boolean expressions in an extra pair of parentheses. Production
clipboard behavior, R5 X11 production code and ownership are unchanged; the
existing `clipboard.file-descriptor-metadata-validation` CTest remains the
behavior-named coverage. No duplicate test is added.

**R5 next production gate remains BLOCKED by R3:** current source contains no
RDP Share/Input or Fast-Path Input PDU parser/event surface. The only R5 native
entry remains the existing `X11AuthorizedInputRoute`, which already requires
the concrete R2 lease, exact R1 owner/GSS provenance and sole R3 session before
XTEST. Do not invent a second parser/session/input authority. After this shared
compile repair, exact descendant hosted CI must compile and run the existing R5
native matrix; owner Linux/X11, Windows MSYS2 CLANG64/Clang23, macOS27 and live
Microsoft-client acceptance remain **NOT RUN**.

## R6 Windows native-adapter CI preflight (2026-10-16; exact-SHA CI pending)

Post-publication validation of R6 implementation
`527977bfe3fbb167dc14d6273006f1b802edc170` completed as Actions
`38885699857` with overall **FAIL**, but the failure occurred before any
CTest ran. Windows/MSVC Debug successfully compiled
`windows_dxgi_capture_cycle.cpp`, `windows_input_controller.cpp`,
`rdp-server-windows-desktop.lib`, and linked
`test_windows_desktop_geometry.exe`. The full build then stopped on the
unrelated R8 `tests/test_owned_remote_transfer.cpp` braced
`std::u16string_view` expression being split by the C `assert` macro.
Linux/GCC, macOS/Clang and the R9 sanitizer job stopped on the same R8 test
source. Documentation-policy **PASS**. Release compilation/CTest and all R6
CTest execution were therefore **NOT RUN**.

To keep R6 validation observable without weakening the authoritative full
matrix, Windows CI now performs one focused preflight immediately after
configuration: build the existing `test_windows_desktop_geometry` target in
Debug, run every test carrying the `windows` label, then build the same target
in Release and run the same labeled tests. Both use the existing checkout-local
`build/` and a 20-second per-test cap. The ordinary full Debug/Release builds
and CTests remain unchanged afterward, so unrelated repository failures still
fail CI rather than being hidden.

No production R6 behavior, native desktop access, admission, or input exposure
changes in this increment. The preflight executes only the existing synthetic
production-backed R6 fixture; no new test runner or branch is introduced.

**Next gate:** exact-SHA Windows preflight PASS for Debug and Release, then
record the still-authoritative full-matrix outcome and obtain the owner Windows
MSYS2 CLANG64/Clang23 receipt. M4 remains OPEN; genuine R2/R3 Windows admission
is still required before any native runtime binding.

## R6 DXGI denial publication receipt (2026-10-16; exact-SHA workflow queued)

Implementation commit: `527977bfe3fbb167dc14d6273006f1b802edc170`
(`fix(r6): verify DXGI pre-map cancellation lifecycle`), published directly
to `main` from reconciled parent
`f1718fa601c12e9ff10f9be3bba281acd0a57e90` by expected-head non-force
update. Exact workflow: Actions `38885699857`, currently **QUEUED** for
implementation SHA `527977bfe3fbb167dc14d6273006f1b802edc170`.

All five hosted jobs are **NOT RUN yet**: Windows/MSVC, Linux/GCC,
macOS/Clang, documentation-policy, and R9 sanitizer coverage are queued.
Accordingly there is no exact-SHA Debug/Release PASS claim yet. The owner
Windows MSYS2 CLANG64/Clang23 acceptance check is separately **NOT RUN** in
this environment.

The implementation changes only the existing R6 pointer-shape denial fixture,
its CTest timeout, and lifecycle documentation. It confirms pre-map terminal
paths acquire one DXGI frame, perform zero D3D11 maps/unmaps, and release the
frame once; mapped teardown remains unmap-before-`ReleaseFrame`. Native
Windows input remains unreachable without genuine R2/R3 admission and M4
remains OPEN.

**Next gate:** complete Actions `38885699857` and record exact failing test
names/logs if any, then obtain the owner CLANG64/Clang23 receipt before the next
R6 production increment.

## R5 X11 lifecycle fixture publication receipt (2026-10-16; exact-SHA workflow queued)

Implementation commit: `f1718fa601c12e9ff10f9be3bba281acd0a57e90`
(`fix(r5): stabilize X11 desktop lifecycle fixture`), published directly to
`main` with an expected-head fast-forward update. Exact implementation
workflow: Actions `38885619241`, currently **QUEUED**;
no hosted Debug/Release result is claimed yet.

Reliability probe environment: Debian GNU/Linux 13 (trixie), x86-64, Xvfb/
Xserver `2:21.1.16-1.3+deb13u1`. Across **25** independent property-set/read
cycles with the lifecycle fixture's prior
`-screen 0 1280x720x24 -nolisten tcp` arguments, the last-client reset was
observed **25/25** times. With only `-noreset` added, continuity was retained
**25/25** times. The two bounded 25-cycle groups completed together in about
**1.19 s**. This is fixture-mechanism evidence, not a substitute for the real
production-backed CTest.

The implementation changes no production X11 source and adds no new CTest:
`x11.desktop-resource-owner-lifecycle` remains the behavior-named regression,
now with deterministic same-server continuity plus fail-only aggregate
construction diagnostics. Canonical owner-local CMake/build/full CTest remains
**NOT RUN** in this connector environment. Historical Actions `38873727660`
attempt 2 also remains queued. R5 acceptance stays open until exact-SHA hosted
Linux/GCC Debug+Release and the existing native/R8 regression matrix actually
run; owner-platform and Microsoft-client gates remain **NOT RUN**.

## R6 DXGI pre-map cursor denial lifecycle regression (2026-10-16; exact-SHA CI pending)

Initial inspected `main`: `0ecfc2e5f54a38c1605c04bf32bd0d09a65d10d9`;
concurrent work advanced the shared branch, and this fix is reconciled onto
publication parent `f1718fa601c12e9ff10f9be3bba281acd0a57e90` immediately before the expected-head update.

Windows Actions runs `38879555520` at
`e51d69ac5b66e622bb1992a858ee463b25309d0f` and `38879607776` at
`8bc97f5b8f5d64008c039e57304a17467c404849` both reached
`windows.cursor-dxgi-shape-generation-denials`, then waited exactly the
historical CTest default before reporting `***Timeout 1500.01 sec` and
`Assertion failed: backend.unmaps == 1`. Source tracing confirms the affected
oversize/malformed/native-shape-error/generation-change/callback-cancel and
coordinate-overflow paths all terminate after `AcquireNextFrame` pointer
processing and before `WindowsD3D11StagingMap::mapFrame`. Cleanup therefore
releases the acquired DXGI frame exactly once with zero staging maps and zero
unmap callbacks. Adding a production unmap would violate the existing owner
contract; the regression is a fixture-only expectation error.

The existing dedicated denial CTest now names and checks that pre-map contract
(`acquisitions == 1`, `maps == 0`, `unmaps == 0`, `releases == 1`).
Its first oversize case additionally proves repeated terminal cancellation and
destruction do not release twice. No R6 production owner changes. The same test
has explicit `TIMEOUT 20` so the owner's plain canonical CTest command cannot
wait 25 minutes if a future MSVC debug assertion leaves the process pending;
current hosted CI separately uses `ctest --timeout 60`.

**Authoring validation:** production/test/doc source trace PASS. Canonical local
configure/build/CTest is **NOT RUN** because this execution environment has no
owner checkout and cannot resolve github.com to create one; no alternate build
root was created. Exact-SHA hosted Windows/MSVC Debug+Release, Linux/GCC
Debug+Release, macOS/Clang Debug+Release, documentation-policy and relevant
sanitizer results remain pending publication. The two Windows runtime TLS
context failures seen in the historical runs are R10-owned and are not changed
by R6.

**Next R6 gate:** exact-SHA hosted CI plus the owner Windows MSYS2
CLANG64/Clang23 check. Native `WindowsInputController` remains unreachable
without genuine R2/R3 Windows admission; generation numbers are revocation-only.
M4 remains OPEN. After stabilization, the next R6 increment is only the
smallest authorized Windows session/capture binding exposed by R2/R3, not broad
runtime integration.

## R5 X11 desktop lifecycle fixture reliability (2026-10-16; exact-SHA CI pending)

**Starting shared main:** `ce23e7dd73a0c943c42a8257149111fe5a66baf7`. This P0 investigation preserves the
existing production X11 resource aggregate and fixes the deterministic test
environment instead of weakening native initialization.

**Historical failure and reproduction evidence:** exact source SHA
`45dc57878bcc741a87bd2ba8b9b9edf15588f062`, Actions `38873727660`, passed
Linux/GCC Debug **289/289** and then failed Linux/GCC Release **288/289**.
The sole failure was `x11.desktop-resource-owner-lifecycle` at the third
`X11DesktopResources` construction, line 115's `assert(resources.valid())`:
a deliberately failed partial owner had already been destroyed, one complete
owner had initialized successfully and been explicitly disconnected twice, and
the next independent owner failed to become valid. The following separately
spawned `x11.desktop-resource-event-routing` Xvfb case passed. The historical
binary printed no `failureReason()`, so the exact child diagnostic for that
one failed run is unavailable and is not inferred.

**Root cause:** the lifecycle fixture intentionally reaches a zero-X-client
interval but launched Xvfb without `-noreset`. A bounded local fixture probe
using the same `-screen 0 1280x720x24 -nolisten tcp` arguments demonstrated
that a root property written by one X client disappears after that last client
disconnects, while adding `-noreset` preserves it for the next independent
client. The Release-only failure therefore raced Xvfb's last-client server
reset, not R5's one-XCB ownership or child teardown ordering. The dedicated
lifecycle CTest now adds `-noreset`; no sleep, retry, privilege widening or
second XCB owner is introduced.

The existing lifecycle behavior remains the dedicated regression rather than
adding a duplicate case: it requires the deliberate XShm construction failure
to preserve `XShm capture arena size is invalid`, recovery by a complete owner,
idempotent explicit disconnect, and a subsequent independent complete owner.
Unexpected valid-owner construction failures now emit only the bounded phase
and existing aggregate `failureReason()` before the assertion. No production
X11 source or ownership rule changes; architecture remains unchanged.

**Authoring validation:** the standalone exact-argument Xvfb reset probe is
**PASS**. The canonical `~/rdp-server/build/` configure/build/full CTest is
**NOT RUN** in this connector environment because the owner checkout is not
mounted; no alternate build root was created. Historical Actions
`38873727660` attempt 2 was requested as a bounded same-SHA reliability rerun
and was still queued at authoring. Exact-SHA hosted Debug/Release CI is required
after publication. Owner Linux/X11, Windows MSYS2 CLANG64/Clang23, macOS27,
genuine positive R2/R3 admission, live XTEST, Microsoft-client M3 acceptance
and performance remain **NOT RUN**. The existing next R5 integration boundary
remains real R3 input-PDU translation only after R3 exposes that authoritative
parser/session route; M3 remains **OPEN**.

## R3 protected Attach User / confirmation receipt increment (2026-10-16; hosted validation pending)

Starting inspected main: `db5bcbd4a6415779dab713424c0c7c0e17ce6fb2`;
reconciled with the stronger R2 NLA-provenance and concurrent main updates
through `0ecfc2e5f54a38c1605c04bf32bd0d09a65d10d9`.
The sole R3 `McsSessionLifecycle` extends
`AwaitAttachUser -> AwaitAttachConfirm -> AwaitChannelJoin` exclusively
through the concrete Linux R2 broker, after current native lease/GSS/CredSSP
and exact R1-owned established TLS/HYBRID authorization with view permission.
The admission and native-session generation fence runs again before every
Attach User intake, confirmation write slice and accepted-byte completion.
The public DomainMCSPDU method remains denial-only.

R3 selects the checked UserId 1002 only after valid, admitted Attach User
intake. It is distinct from GCC node 1001, I/O channel 1003 and allocated
static channels starting at 1004. Negotiated maximum channels/users,
allocated identifiers, and duplicates are checked before reservation.
The existing Attach User Confirm serializer produces the exact fixed 11-byte
response. A one-shot R3-owned bounded writer retains immutable suffix bytes,
a nonzero reply receipt and a separately rotating write-slice receipt across
OpenSSL zero-byte WANT and partial accepted progress. Stale/overreported,
unsolicited, wrong-generation or post-cancellation completion closes R3.
Only fully accepted confirmation configures the existing join gate once with
the user channel, I/O channel and static channels; no Channel Join traffic,
licensing, Share, graphics, clipboard or input becomes authorized here.
R3 -> R2/GSS -> R1 teardown remains mandatory.

Dedicated offline CTests:
`transport.mcs-session-attach-confirm-write-receipts`,
`transport.mcs-session-attach-confirm-denials` and (with Linux GSSAPI)
`security.gssapi-r3-attach-user-contract`.
They exercise the production serializer/receipt writer, every first-slice
split, backpressure, cancellation, and genuine denial/compile-time R2
authority signatures; they do NOT mint an authenticated native lease.
Authoring environment has no synchronized `~/rdp-server` checkout and cannot
resolve GitHub by shell: canonical local configure/build/full CTest and
owner Linux/X11, Windows MSYS2 CLANG64/Clang 23, macOS 27 are **NOT RUN**.
Exact-SHA hosted Debug/Release Linux/GCC, macOS/Clang and Windows/MSVC,
R9 sanitizers and real Kerberos/logind admission remain next verification
gates. **M2 NOT ACCEPTED.** The next R3 step is protected Join Request,
Join Confirm receipts and channel activation (not a runtime listener).

## R10 connection-aggregate publication receipt and CredSSP I/O blocker (2026-10-16)

Implementation commit: `be99fb50d0f1c7ae981a8e706ec44794a309eadc`
(`feat(r10): own Linux connection teardown aggregate`), published directly to
`main` from `461077c612ec4370d8f943e1a2502172e4649ee3` by expected-head,
non-force update. Exact workflow: Actions `38885191523`, currently
**QUEUED**; hosted compile/CTest is therefore **NOT RUN yet** for this SHA.
The prerequisite sealed-keytab seal-query correction workflow
`38884685461` is also still **QUEUED**.

Post-publication integration review confirms the aggregate itself does not yet
make a production listener permissible. R1 now explicitly owns bounded
post-handshake TLS application I/O through
`OwnedPreauthTcpConnection::readTlsApplicationData` /
`writeTlsApplicationData`, while the current R2
`TsRequestFrameReader::readOneTlsStep(SSL*)` and
`TsRequestTlsReplyWriter::writeOneTlsStep(SSL*)` still advance OpenSSL
directly. R1's `establishedTls()` borrow explicitly forbids advancing SSL
outside R1. Exposing the aggregate's private acceptor or bypassing R1 would
violate sole-owner architecture.

This cross-road seam is tracked as issue #17,
**R1/R2: route CredSSP framing through the owned TLS application-I/O
boundary**. R10 will keep the aggregate non-listening until R1/R2 supply a
bounded framed path through the owned application-I/O seam and both pending
R10 exact-SHA Linux gates pass.

Descendant `main` inspected at `5d7f4cef992436091c97c49d514ea7bff0fa2279` changes clipboard/docs/test
registration only relative to the R10 aggregate commit; the new
`linux_runtime_connection.{h,cpp}`, R10 CMake source registration and
aggregate tests remain unchanged.

## R10 non-listening Linux R1→R2→R3 connection aggregate (2026-10-16; exact-SHA CI pending)

Starting shared `main`: `0ecfc2e5f54a38c1605c04bf32bd0d09a65d10d9`;
shared files were reconciled through publication candidate `461077c612ec4370d8f943e1a2502172e4649ee3`. The
sealed-keytab provisioning gate remains unpromoted and correction workflow
`38884685461` is still pending, so this increment does **not** add or activate
a listener. Instead R10 adds the ownership boundary required before listener
work: `LinuxRuntimeConnection`.

One nonmoving aggregate owns the transferred R1
`OwnedPreauthTcpConnection`, one existing R2 `GssapiSpnegoAcceptor`, one
`LinuxConsoleAdmissionBroker`, an optional move-only
`LinuxConsoleAdmissionLease`, and the sole R3 `McsSessionLifecycle`.
It borrows the service-lifetime `LinuxRuntimeSecurityConfiguration` and
`RuntimeServerTlsContext`; it creates no competing protocol/authentication
state. Construction configures a fresh R2 acceptor from the already sealed R10
keytab snapshot and cancels an accepted socket immediately if service
provisioning is absent.

The terminal `revoke()` is idempotent and enforces R3 → R2/GSS → R1:
`LinuxConsoleAdmissionBroker::revokeR3Session` closes R3 first, then the
lease/broker/GSS authority is destroyed, and only then R1 releases SSL/BIO/
socket ownership. A fresh per-connection SSL can be created only through the
existing R10 TLS context and transferred into R1. Positive admission remains
the existing R2 `issue(acceptor, exact-R1-owner, request)` path, including its
genuine HYBRID negotiation-provenance requirement; the lease never escapes
this aggregate. R3 Connect Initial remains reachable only through R2.

Two new Linux production-backed CTests are registered in the existing
`test_runtime_linux_security` executable:
`runtime.linux-connection-aggregate-ordered-revocation` and
`runtime.linux-connection-aggregate-premature-admission-denial`. They reuse
the build-root-only synthetic MIT service keytab and a test-only ephemeral
loopback accepted socket. Coverage includes unprovisioned-constructor socket
cancellation, one transferred R1 socket with a fresh R2 acceptor/broker and
untouched R3 owner, idempotent ordered teardown, and terminal denial when a
policy-shaped request is submitted before any CredSSP/GSS identity or R1
HYBRID proof. No positive admission capability is fabricated.

**Authoring status:** source/test/doc review only. Canonical repository
build/CTest is **NOT RUN** here because the owner checkout is unavailable; no
alternate build root was created. Exact-SHA hosted Linux compilation and both
new CTests are required after publication. Owner Linux/X11, MSYS2
CLANG64/Clang23, macOS27, real KDC/client ticket, positive logind admission,
external RDP client and listener/service are **NOT RUN**.

**Next R10 gate:** obtain exact-SHA Linux PASS for the sealed-keytab correction
and this aggregate. Only then may R10 promote Linux runtime provisioning and
design the minimal loopback listener/event loop around this exact aggregate.

## R2 downstream R1-owner seam repair (2026-10-16; exact-SHA CI pending)

Post-publication call-site audit of R2 commit
`2fb5ed5a832c97241d236813599b6d1e8efef985` found the existing Linux X11
input route still forwarding a caller-selected `SSL*` into the now
owner-bound protected-transition gate. The route now carries the same
read-only `const OwnedPreauthTcpConnection&` from R1 into
`LinuxConsoleAdmissionBroker::authorizeR3ProtectedTransition`; no XTEST,
R3, native-input, policy or permission semantics changed.

The existing
`x11.input-r3-admission-route-denials-and-revocation` regression now has a
compile-time owner-only signature assertion and rejects a raw `SSL*`
invocation. Its no-lease runtime case still proves that a native X11 desktop
cannot reach XTEST and that denial closes R3/R2/native state. Targeted review
of the admission/runtime/input-route surfaces found no additional positive
broker caller needing conversion. Positive authorization remains impossible
under current diagnostic R1 `PROTOCOL_SSL` negotiation.

The first R2 implementation was ultimately published from parent
`db5bcbd4a6415779dab713424c0c7c0e17ce6fb2`. Actions run
`38884206732` for that intermediate exact SHA was still queued when this
downstream compile-surface defect was found and is superseded for R2
acceptance by the repaired exact SHA. Canonical owner-local build/CTest and
genuine Kerberos/logind/client acceptance remain **NOT RUN**.

## R10 seal-query correction publication receipt (2026-10-16; exact-SHA workflow queued)

Correction commit: `110479f382dfcbbd28343f472ba126e6c5fbef09`
(`fix(r10): fail closed on keytab seal query`), published directly to
`main` from parent `f9704cacd236f2d2344fa20508570c44e2a2bbdd` by
expected-head non-force update. Exact workflow: Actions `38884685461`,
currently **QUEUED**; hosted compile/CTest is therefore **NOT RUN yet** for
this correction SHA.

Authoring verification under `~/rdp-server/build/r10-probe/`:
`seal_verify_probe.cpp` compiled with GCC C++23
`-Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion` and
Clang with the same warnings plus ASan+UBSan. Both executions report
`verified=1 seals=0xf pwrite=-1 errno=1`, demonstrating successful explicit
seal verification and kernel-enforced `EPERM` on a post-seal write. The
existing MIT-GSS sealed-keytab provider probe remains PASS.

This correction adds no listener, authentication success or native admission.
All existing R10 Linux-security CTests remain registered, including
`runtime.validates-linux-security-provisioning` and
`runtime.linux-security-keytab-snapshot-mutation-continuity`.
**Next gate:** exact-SHA Linux compile/CTest. Runtime promotion and listener
work remain blocked until that gate passes.

## R10 sealed-keytab seal-query fail-closed correction (2026-10-16; exact-SHA CI pending)

Starting shared `main`: `f9704cacd236f2d2344fa20508570c44e2a2bbdd`. Post-publication review of
`14ba20d89ec784241ec451eaeb1fdc371f751fba` found one error-path bug in
the immutable keytab snapshot verification: `fcntl(F_GET_SEALS)` returns
`-1` on failure, and masking that value directly makes every required seal
bit appear set. The snapshot creation itself still required successful
`F_ADD_SEALS`, but the verification expression was not fail-closed.

Production now records the `F_GET_SEALS` result and requires it to be
nonnegative before comparing `F_SEAL_WRITE | F_SEAL_GROW |
F_SEAL_SHRINK | F_SEAL_SEAL`. A seal-query error therefore closes the
snapshot and rejects configuration. The one-byte source-growth probe now
reuses the existing cleansed copy buffer rather than a separate stack byte.

The dedicated
`runtime.linux-security-keytab-snapshot-mutation-continuity` CTest and all
prior R10 Linux provisioning/process tests remain registered; no listener,
authentication success or R3 path is added.

**Authoring PASS:** exact seal-verification probe under
`~/rdp-server/build/r10-probe/` compiled with GCC C++23
`-Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion` and with
Clang ASan+UBSan using the same warning set. Both runs report
`verified=1 seals=0xf pwrite=-1 errno=1`; post-seal writes fail with
`EPERM` and no sanitizer finding is reported.

**Next gate remains unchanged:** exact-SHA Linux compilation and all R10
Linux-security CTests before provisioning promotion or any listener.

## R2 R1-owned HYBRID provenance gate (2026-10-16; exact-SHA CI pending)

Initial inspected shared `main`:
`23ae82fe9f8f5f93dccd91ea2c8e8e5b045f9334`; implementation was reconciled
through concurrent work onto final publication parent
`db5bcbd4a6415779dab713424c0c7c0e17ce6fb2`.

R2 positive Linux console admission no longer accepts a caller-selected TLS
object as sufficient connection provenance. The positive
`LinuxConsoleAdmissionBroker::issue` overload now consumes the exact
R1-owned `OwnedPreauthTcpConnection`, synchronously derives
`establishedTls()` plus immutable `securityNegotiationProvenance()`, and
requires both a genuine client `PROTOCOL_HYBRID` offer and an actual server
`PROTOCOL_HYBRID` selection before any logind monitor, NSS/logind sampling or
lease creation. The existing GSS provider principal/TLS pointer, selected
certificate, native policy/session fingerprint, permissions, one-shot broker
state and generation/expiry checks remain unchanged. The historical raw
`SSL*` issuance overload remains only for source compatibility and is now
terminal deny-only.

The same owner fence now applies to R2 revalidation and every positive
protected R3 handoff, including the first MCS Connect Initial. R3 generation
matching is still revocation-only, R3 remains the sole MCS state owner, and
protected denial closes R3 before revoking R2/GSS. No caller-supplied protocol
mask, selected-protocol scalar, authenticated flag or standalone SSL pointer
can substitute for R1's stored negotiation snapshot.

A small `hasHybridNlaNegotiationProvenance()` predicate exists only to test
the protocol shape. It cannot mint a lease or authorize R3 and is positive
only for offered+selected HYBRID. Dedicated Linux CTests reuse the existing
GSS executable:
`security.gssapi-native-admission-r1-nla-provenance-denials` and
`security.gssapi-r3-initial-nla-owner-fence`. The first drives genuine R1
loopback X.224/TCP/OpenSSL ownership and covers inactive ownership, incomplete
TLS, established diagnostic SSL, HYBRID offered while SSL is selected,
cancelled ownership, legacy raw-SSL denial and terminal replay. The second
enforces compile-time owner-only initial/protected R3 APIs and terminal
R3→R2/GSS cleanup without fabricating a lease.

Current R1 production negotiation still intentionally selects diagnostic
`PROTOCOL_SSL`, including when the client offers HYBRID. Therefore this R2
increment strengthens the denial boundary and does **not** create a positive
authenticated session. The required dependency remains:

**R1 genuine PROTOCOL_HYBRID negotiation → R2 TLS-bound GSS/CredSSP and
independent native OS admission → R3 sole authenticated session.**

This gate does not complete the first item. R1 must add genuine production
HYBRID negotiation under the appropriate serving configuration, and R10 must
later compose the live listener/service ownership, before M2 can become
positive.

**Authoring validation:** source/test/docs review completed against the
reconciled shared head. The canonical owner command in
`~/rdp-server/build/` is **NOT RUN** in this execution environment because
the owner checkout is not available locally; no alternate build root was
created. Exact-SHA hosted Linux/GCC, macOS/Clang, Windows/MSVC,
documentation-policy and focused/full CTest evidence is required after
publication. Genuine Kerberos client-ticket exchange, logind-positive
admission, Microsoft-client M2 acceptance, owner Linux/X11, owner Windows
MSYS2 CLANG64/Clang23 and owner macOS27 are **NOT RUN**.

## R10 sealed-keytab publication receipt (2026-10-16; exact-SHA workflow queued)

Implementation commit: `14ba20d89ec784241ec451eaeb1fdc371f751fba`
(`security(r10): seal Linux keytab snapshot`), published directly to
`main` from `b41269ed75628285767dc3a59d7bedacfc3dcc8b` using an
expected-head non-force update. Exact workflow: Actions `38883815450`,
currently **QUEUED**, therefore hosted compile/CTest is **NOT RUN yet** for
this SHA.

Authoring commands/evidence under the mandatory
`~/rdp-server/build/r10-probe/` root:
- `./keytab_probe` prepares the synthetic explicit service keytab.
- `./mutable_fd_probe` rewrites that same inode and confirms an ordinary
  retained-source procfd no longer yields a complete GSS acquisition.
- `./sealed_keytab_probe` performs the sealed snapshot and reports
  `acquire=0 minor=0 seals=0xf` after the same source rewrite.
- `clang++ -std=c++23 -O1 -g -Wall -Wextra -Wpedantic -Werror
  -fno-omit-frame-pointer -fsanitize=address,undefined
  -fno-sanitize-recover=all sealed_keytab_probe.cpp
  -o sealed_keytab_probe_san -lgssapi_krb5`, followed by
  `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1
  UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
  ./sealed_keytab_probe_san`: **PASS**, same complete acquisition and seals,
  no sanitizer finding.

The new registered production-backed CTest is
`runtime.linux-security-keytab-snapshot-mutation-continuity`; the previously
added positive `runtime.validates-linux-security-provisioning`, pathname
replacement, policy denials and missing-provisioning denial remain registered.
Full repository build/CTest on this execution host is **NOT RUN** because the
checkout cannot be materialized through local GitHub DNS. Owner-platform,
KDC/client-ticket, positive native R2 admission, R3, external client and
listener/service evidence remain **NOT RUN**.

**Gate remains:** wait for exact-SHA Linux compile/CTest evidence before
promoting R10 Linux provisioning or adding a listener. This receipt records
publication and authoring evidence only; it is not milestone acceptance.

## R10 sealed immutable Linux keytab snapshot (2026-10-16; exact-SHA CI pending)

Starting shared `main`: `b41269ed75628285767dc3a59d7bedacfc3dcc8b`. Review of the new explicit-keytab owner
found a narrower TOCTOU gap before listener promotion: retaining the securely
opened source descriptor prevents pathname substitution, but it does **not**
freeze bytes in that inode. A same-owner writer could truncate or rewrite the
configured keytab and a later per-connection `gss_acquire_cred_from` through
`/proc/self/fd/<source>` would observe the changed contents.

R10 now converts the validated source into an immutable anonymous snapshot
before exposing it to GSS. After the existing component-by-component
`openat(... O_NOFOLLOW ...)`, owner/mode/type and 1 MiB bounds, production
copies the exact source bytes into `memfd_create(... MFD_ALLOW_SEALING)`.
The copy uses bounded stack storage that is cleansed on scope exit, explicit
`pread`/`pwrite` offsets with EINTR/partial-write handling, rejects source
growth/short reads, and rechecks device/inode/size/mtime/ctime after copying.
The anonymous descriptor is owner-read-only and must accept all of
`F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL`; otherwise
configuration fails closed. The mutable source descriptor is then closed.
The existing R2 acceptor continues to receive only
`FILE:/proc/self/fd/<n>`, now naming the sealed snapshot.

New dedicated CTest
`runtime.linux-security-keytab-snapshot-mutation-continuity` overwrites the
**same configured source inode in place** after R10 configuration, then
requires a fresh real `GssapiSpnegoAcceptor` to acquire the originally
provisioned service identity. The earlier pathname-replacement continuity,
keytab/policy denials, process-level missing-provisioning denial, and positive
`runtime.validates-linux-security-provisioning` are retained.

**Authoring PASS:** under `~/rdp-server/build/r10-probe/`, a control
`mutable_fd_probe` demonstrates the previous model is content-mutable:
after an in-place source rewrite, real MIT GSS returns non-complete credential
acquisition. The replacement `sealed_keytab_probe` reports
`acquire=0 minor=0 seals=0xf` after the same source rewrite. Recompiled with
Clang C++23 `-Wall -Wextra -Wpedantic -Werror` plus ASan+UBSan and
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1`; the sealed probe PASSes with
the same GSS result and no sanitizer finding. These are provider/API probes,
not a full repository build.

Full repository configure/build/CTest remains **NOT RUN** on this execution
host because local GitHub DNS cannot materialize the checkout. The earlier
implementation workflow `38881106173` remains queued and is superseded for
R10 acceptance by the hardened SHA after publication. Owner Linux/X11,
MSYS2 CLANG64/Clang23, macOS27, real KDC/client ticket, positive native R2
admission, R3, external clients and listener/service remain **NOT RUN**.

**Next R10 gate:** exact-SHA hosted Linux compile and all Linux-security CTests
for the sealed-snapshot implementation, including positive production preflight,
same-inode mutation continuity and pathname replacement. Do not promote the
provisioning boundary or add a listener before that evidence.

## R1 production R10 TLS through owned transport (2026-10-16; exact-SHA CI pending)

Starting inspected shared `main`: `20dd5e7de5b90ec4a5ae52a43144549203d88459`. This R1 increment adds no
production transport surface. The existing R1 owner already enforces complete
X.224 Confirm delivery before TLS attachment, sole accepted-socket/BIO/SSL
ownership, one-step nonblocking handshake progress, bounded application I/O
and terminal snapshot revocation.

Dedicated CTests `transport.tcp-owned-runtime-tls-handshake` and
`transport.tcp-owned-runtime-tls-identity-continuity` now compose R10's real
`RuntimeServerTlsContext` factory with R1's production ephemeral-loopback
accept/X.224/BIO/TLS path, reusing the secure R10 credential fixture. They
prove client-observed certificate identity, immutable negotiation provenance,
bounded encrypted byte accounting and short progress; fail-closed premature
attach/incomplete handshake; orderly and abrupt peer teardown; cancellation
revocation; and caller listener survival.

The continuity case replaces both validated credential pathnames with invalid
fixture material before creating a fresh SSL, then completes a new R1-owned
network handshake. The client still observes the original retained
certificate, so R1 performs no second pathname read. An independent R3
lifecycle remains at `AwaitVerifiedR2Admission`; TLS grants neither R2
admission nor R3 authority.

No demonstrable R1 production defect was found, so
`src/server/transport/*` is unchanged. Only the existing preauth test
executable gains a test-only link to the noninstalled R10 TLS library; the
exported protocol library gains no runtime dependency. R9 sanitizer selection
includes both cases. Canonical local build/CTest is **NOT RUN at authoring**
because no synchronized owner checkout is available and shell GitHub DNS
resolution fails. Exact-SHA hosted Linux/GCC, macOS/Clang and Windows/MSVC
Debug/Release plus sanitizer evidence is required after publication. Owner
Linux/X11, Windows MSYS2 CLANG64/Clang 23, macOS 27, real Kerberos/native
admission and Microsoft-client validation remain **NOT RUN**. M2 remains
**NOT ACCEPTED**.

## R4 deterministic AVC420 metadata pre-encode gate (2026-10-16; exact-SHA CI pending)

Starting shared `main`: `95a3c3d1da9aa440a94d8275d61560ceda00bd3b`;
publication is reconciled onto the current shared `main`. R3 still has no
authenticated Graphics DVC authority, so R4 continues only inside its existing
codec/presentation ownership boundary.

The AVC420 packetizer now exposes
`gfxAvc420PictureMetadataValid()`, one allocation-free validator for the
deterministic surface/frame/coded-visible geometry/region/quant metadata
already enforced by `buildGfxAvc420Picture()`. The x264 segmented-frame
producer uses that same validator before calling x264. Invalid QP/quality,
out-of-visible regions and other deterministic envelope errors therefore do
not advance codec references and do not force an avoidable encoder rebuild.
The packetizer still validates Annex-B only after encode; any genuine
post-encode publication failure remains fail-closed and rebuilds codec history.

The producer regression is now
`graphics.x264-segmented-metadata-preflight`: after one delivered/ACKed IDR,
bad quant metadata and an out-of-bounds region are rejected while lifecycle
submission remains available, and the next valid frame must remain a P slice,
proving x264 history was not touched. Existing AVC420 packetizer rejection
coverage also checks the shared metadata validator for representative surface,
frame, quant and rectangle denials.

**Authoring validation:** source/CMake/test construction complete. Canonical
one-root repository build/full CTest is **NOT RUN** on this host; the exact
prior R4 workflow `38882596797` for
`23ae82fe9f8f5f93dccd91ea2c8e8e5b045f9334` was still **QUEUED** when
rechecked. Exact-SHA hosted CI for this increment is required after
publication. Owner Linux/X11, Windows MSYS2 CLANG64/Clang23, macOS27, real R3
Graphics DVC, Microsoft-client rendering and graphics performance are
**NOT RUN**. Gate B / M3 remains **OPEN**. **Next R4:** integrate only when R3
exports its authenticated Graphics DVC/full-send authority; otherwise continue
hardening the existing single-owner graphics path without a synthetic channel.

## R10 positive Linux security preflight coverage (2026-10-16; exact-SHA CI pending)

Starting shared `main`: `23ae82fe9f8f5f93dccd91ea2c8e8e5b045f9334`. This is a testing-only R10 increment;
production serving behavior is unchanged and the listener remains disabled.
The existing Linux provisioning boundary already has direct keytab-owner tests
and a process-level missing-provisioning denial, but it did not exercise the
production executable's complete positive `--check-linux-security FILE`
path.

The existing `test_runtime_linux_security` fixture now exposes one test-only
`write-synthetic-keytab` mode. `check_runtime_entrypoint.cmake` reuses its
existing valid TLS certificate/private-key fixture, asks that helper to create
a private build-root-only MIT service keytab, appends the eight existing Linux
security fields, and invokes the real `rdp-server --check-linux-security`
entrypoint. New dedicated CTest:
`runtime.validates-linux-security-provisioning`. It requires exit 0 and the
existing explicit message that TLS identity, GSS acceptor credential and
native identity policy are accepted while **no user is authenticated, no
session is authorized and service remains disabled**. The prior
`runtime.rejects-linux-security-missing-provisioning` case remains registered.

No KDC, client ticket, live GSS user authentication, NSS/logind admission,
R3 session or socket is created. The synthetic keytab contains a random test
service key only and remains under the one build root.

**Authoring validation:** MIT GSSAPI provider probes in
`~/rdp-server/build/r10-probe/` rerun PASS:
`./keytab_probe` -> `GSS_S_COMPLETE`; `./procfd_probe` ->
`GSS_S_COMPLETE` after pathname removal through retained
`FILE:/proc/self/fd/3`. Candidate CMake/test registration static assertions
also PASS. Full repository build/CTest is **NOT RUN** in this execution host
because the repository checkout cannot be obtained through local GitHub DNS.
The earlier implementation workflow `38881106173` for
`d6efca9f14e8b5bd675016f0c7962f4f98a6da6d` remains **QUEUED** at this
authoring snapshot.

**Next R10 gate:** exact-SHA hosted Linux compile plus all direct and process
Linux-security CTests, including the new positive preflight. Do not promote the
provisioning boundary or add a listener until that evidence is available.

## R4 x264 -> segmented AVC420 publication owner (2026-10-16; exact-SHA CI pending)

Starting inspected shared `main`: `be0a0322117742da5a2cdd8be97b972289d4cce0`;
publication is reconciled onto the current shared `main`. R3 still exposes no
authenticated `Microsoft::Windows::RDS::Graphics` DVC authority, so this
increment does not fabricate a channel contract. Instead it closes the next
R4-internal correctness gap between the already-landed x264 encoder and the
already-landed stable segmented-frame handoff.

New noninstalled `X264Avc420SegmentedFrameProducer` is subordinate to the
existing single `GfxPresentationLifecycle`. It binds one x264 context to one
nonzero presentation generation plus coded/visible geometry, accepts one
validated NV12 picture request, produces genuine x264 Annex-B, composes the
existing AVC420 packetizer and RDP8 segmented-data handoff, and returns the
existing move-only `GfxAvc420SegmentedFrame`. It owns no graphics DVC,
capture source, scheduler, transport queue, ACK window or authorization state.

Reference continuity is fail-closed. Deterministic lifecycle/backpressure
denials are checked before x264 runs. If x264 accepts a picture but the exact
frame cannot subsequently be reserved/packetized, the producer immediately
reopens the same encoder configuration so the next accepted picture starts
with SPS/PPS/IDR instead of referencing an unsent frame. A terminal/partial
delivery abort delegates to the existing presentation abort and drops codec
history. Reconfiguration to a new generation creates fresh codec history.
Successful full delivery preserves x264 references for later P slices.

Dedicated production-backed CTests:
`graphics.x264-segmented-delivery-continuity`,
`graphics.x264-segmented-backpressure-preflight`,
`graphics.x264-segmented-publication-idr-recovery`, and
`graphics.x264-segmented-abort-generation-reset`. They encode real NV12 with
the vendored x264 target and assert IDR/SPS/PPS on first/recovered frames,
reference-continuous P slices after successful delivery, no codec advancement
under R4 backpressure, and generation-safe abort/reset semantics.

**Authoring validation:** source/CMake/test construction complete; canonical
repository build/full CTest is **NOT RUN** in this tool environment because no
owner `~/rdp-server/build/` checkout is available. Exact-SHA hosted CI is the
next automated gate. Owner Linux/X11, Windows MSYS2 CLANG64/Clang23, macOS27,
real R3 Graphics DVC, Microsoft-client rendering and graphics performance are
**NOT RUN**. Gate B / M3 remains **OPEN**. **Next R4:** consume the future
R3-authenticated Graphics DVC with this exact stable owned frame/full-send
boundary; do not add another scheduler or synthetic authorization token.

## R10 Linux runtime-security publication receipt (2026-10-16; exact-SHA workflow queued)

Implementation commit: `d6efca9f14e8b5bd675016f0c7962f4f98a6da6d`
(`feat(r10): provision explicit Linux runtime security`), published directly
to `main` from parent `b009c43bc6913513937b89c9de16a0abbc5a6a50`
with an expected-head, non-force ref update. Exact implementation workflow:
Actions `38881106173`, currently **QUEUED** in the shared runner backlog, so
hosted compile/CTest is **NOT RUN yet** for this exact SHA.

Authoring PASS remains the two provider probes in
`~/rdp-server/build/r10-probe/`: `./keytab_probe` acquired the explicit
synthetic keytab with `GSS_S_COMPLETE`; `./procfd_probe` acquired the same
credential through the retained `FILE:/proc/self/fd/3` after pathname
replacement. Full local repository build/CTest remains **NOT RUN** because the
workspace has no GitHub-resolvable checkout.

Descendant `main` inspected at `6cdfab6e45126baa67cc277339443b8a223b42a2` retains the R10 runtime source,
process entrypoint, CMake registration and three new CTests unchanged; its
intervening changes are other-road graphics/Windows/docs/test additions.
Therefore no R10 behavior was silently replaced while its exact workflow is
queued. **Next gate:** obtain exact-SHA Linux compile and all three dedicated
R10 CTest results before promoting the provisioning boundary or adding any
listener.

## R4 owned AVC420 segmented-frame handoff (2026-10-16; exact-SHA CI pending)

Starting shared `main` for this convergence increment:
`0adc4682a85f6c1c888fdd03e7ecd72efd3ffe97`; publication is reconciled
onto the current shared `main`. A concurrent R4 publication already supplied
the pinned static x264 producer, so this increment follows the roadmap's
non-duplication fallback rather than adding a second encoder.

New `GfxAvc420SegmentedFrame` is the single stable R4-owned handoff object
between the existing mapped presentation lifecycle and future R3 Graphics DVC
delivery. `prepareGfxAvc420SegmentedFrame()` first uses
`GfxPresentationLifecycle::prepareAvc420Picture()` to serialize and reserve
exactly one START_FRAME / AVC420 WIRE_TO_SURFACE / END_FRAME sequence, then
expands that same contiguous buffer in place through
`buildGfxSegmentedData()`. The object owns the resulting SINGLE or MULTIPART
RDP8 segmented payload and keeps it stable across an asynchronous future R3
write. It owns no encoder, channel, transport, scheduler or authorization
state.

The lifecycle receipt remains private inside the move-only object.
`completeGfxAvc420SegmentedFrameDelivery()` accepts the actual outer
segmented byte count reported by R3, requires exact full delivery, and only
then translates to the existing inner graphics receipt so frame-ACK admission
occurs at the established lifecycle boundary. Partial/fatal transport failure
uses `abortGfxAvc420SegmentedFrameDelivery()`, which delegates to the
existing terminal generation revocation. Stale generation objects cannot
complete a newer presentation.

Dedicated offline CTests:
`graphics.avc420-segmented-frame-single`,
`graphics.avc420-segmented-frame-multipart`,
`graphics.avc420-segmented-frame-denials-reconnect`, and
`graphics.avc420-segmented-frame-delivery-ack`. They cover stable owned
SINGLE/MULTIPART payloads, outer/inner delivery-byte translation, ACK
publication only after full delivery, ordinary rejection without reservation,
reconnect staleness and terminal abort.

**Authoring validation:** source-level construction complete; canonical
repository build/CTest is **NOT RUN** in this tool environment because no
owner checkout/build root is available. Exact-SHA hosted CI is required after
publication. Real R3 authorized Graphics DVC, Microsoft-client rendering,
owner Linux/X11, Windows MSYS2 CLANG64/Clang23, macOS27 and performance remain
**NOT RUN**. M3/Gate B remains **OPEN**. Next R4 step is R3 integration of
this exact owned payload/full-send receipt boundary once R3 exposes the
authenticated Graphics DVC authority; do not introduce another scheduler or
authorization shortcut.

## R10 Linux explicit GSS/keytab and native identity-policy provisioning (2026-10-16; exact-SHA CI pending)

Starting inspected `main`: `1818324f3095069fe2597d9dd9469590fd47ab9b`;
shared files were reconciled through publication candidate
`b009c43bc6913513937b89c9de16a0abbc5a6a50`. This R10 increment remains strictly pre-listener. On Linux under
the existing `RDP_SERVER_TEST_LINUX_GSSAPI=ON` build gate, new
`LinuxRuntimeSecurityConfiguration` owns one securely opened service keytab
descriptor and one immutable `ConsoleIdentityPolicy`. The configured keytab
must be an explicit `FILE:/` absolute path, is component-walked with
`openat` + `O_NOFOLLOW`, and must resolve to a nonempty regular file owned
by the effective service uid, owner-readable, and inaccessible to group/other.
The runtime retains that descriptor for the configuration lifetime and gives
the existing R2 `GssapiSpnegoAcceptor` the provider URI
`FILE:/proc/self/fd/<n>`. Therefore a later pathname replacement cannot
redirect GSS credential acquisition to a different keytab object.

Configuration is one-shot and fail-closed. R10 first validates the existing
R2 `ConsoleIdentityPolicy` rule, then uses a temporary real MIT-GSS acceptor
to prove that the requested exact `TERMSRV/host@REALM` credential can be
acquired from the retained keytab. Future per-connection R2 acceptors are
configured through the same retained descriptor. R10 does not duplicate
SPNEGO, CredSSP, NSS/logind authorization or R3 state ownership.

The Linux-enabled executable recognizes an offline
`--check-linux-security FILE` preflight. Eight all-or-none settings extend
the original seven-field syntax:
`gss_service_principal`, `gss_keytab`,
`authorized_kerberos_principal`, `authorized_unix_account`,
`authorized_seat`, `authorized_display`, `authorized_uid`, and
`authorized_permissions`. The preflight additionally constructs the existing
live `RuntimeServerTlsContext`, acquires the explicit GSS acceptor credential,
and validates the native identity rule. Success still authenticates **no**
client, issues **no** `LinuxConsoleAdmissionLease`, opens **no** listener and
starts **no** R3 session.

Dedicated Linux CTests use a generated, build-root-only MIT keytab with a
random synthetic service key (no KDC/client ticket):
`runtime.linux-security-explicit-keytab-continuity`,
`runtime.linux-security-keytab-policy-denials`, and
`runtime.rejects-linux-security-missing-provisioning`. The continuity case
configures R10, replaces the original configured keytab pathname with invalid
bytes, and then requires a fresh real R2 GSS acceptor to acquire the original
service credential through the retained descriptor. Denials cover group-readable
keytabs, symlink final components, wrong service class, root policy mapping,
relative keytab URI and missing keytab.

**Authoring validation:** within the mandatory
`~/rdp-server/build/r10-probe/` root, MIT Kerberos/GSSAPI 1.21.3 standalone
provider probes PASS: explicit synthetic keytab acquisition returned
`GSS_S_COMPLETE`, and after unlink/path replacement
`FILE:/proc/self/fd/3` acquisition also returned `GSS_S_COMPLETE`.
Commands: `./keytab_probe` and `./procfd_probe`. Full repository
CMake/build/CTest is **NOT RUN at authoring** because this environment has no
GitHub-resolvable checkout. Exact-SHA hosted Linux compilation/CTest is the
next gate; owner Linux/X11, MSYS2 CLANG64/Clang23, macOS27, real client
tickets/KDC, genuine R2 positive admission and external RDP clients are
**NOT RUN**.

**Next R10 gate:** after exact-SHA Linux validation, promote this provisioning
boundary out of the developer GSS build gate into the eventual Linux runtime
composition and add only the minimal loopback listener/event loop once one
connection can retain R10 TLS/keytab/policy ownership, R1 transport, genuine
R2 admission and the sole R3 session with ordered revocation. No listener is
permitted before that aggregate exists.

## R10 reusable live TLS context owner (2026-10-16; R10 hosted tests PASS, unrelated full-suite blocker)

## R6 generation-pinned native Windows input adapter (2026-10-16; exact-SHA CI pending)

Starting main inspected before authoring: `132b1d5e7ed81809f163cce108acf79c93e53fc6`;
publication is rebased onto the current shared `main`. New
`windows_input_controller.{h,cpp}` adds the focused native R6 input boundary
after DXGI cursor ownership. It accepts Windows-native scan-code, absolute
pointer, five-button and vertical/horizontal wheel events only after the caller
supplies an already-pinned nonzero Windows session/device generation. The
generation reader is **revocation-only** and is not authentication or OS
admission. The Win32 command-to-`SendInput` translation is compiled but
deliberately has no exported callback factory while genuine Windows R2/R3
admission is unavailable. The runtime therefore cannot turn forgeable
generation numbers into a native input capability.

Pointer coordinates reuse the canonical `WindowsDesktopLayout`, reject
virtual-desktop gaps, and normalize the complete virtual desktop to Win32's
0..65535 absolute range with `MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK`.
Keyboard input uses scan codes and the extended-key bit rather than
layout-dependent virtual keys. Duplicate make/button transitions are
idempotent. Wheel input is bounded to 16 detents per event. Button+position
and wheel+position pairs are submitted in one callback batch. A short native
insertion, malformed event, reentry or callback cancellation closes the
controller. Explicit cancellation best-effort releases held keys/buttons only
while the pinned generation is still current; a stale generation clears local
state without injecting cleanup into a different desktop.

**Dedicated Windows offline CTests:** `windows.input-sendinput-lifecycle`
and `windows.input-sendinput-revocation-denials`. They exercise exact
coordinate endpoints, scan-code/extended-key state, X buttons, horizontal
wheel, duplicate suppression, monitor-gap rejection, invalid scan/wheel/enum
values, short insertion, native-callback and generation-reader reentry,
deferred cancellation, generation changes, and inert invalid construction. Ordinary CTest uses injected callbacks and
never calls real `SendInput`.

**Authoring validation:** isolated GCC C++23 high-warning fixture PASS;
isolated Clang C++23 high-warning ASan+UBSan fixture PASS. Full repository
Windows/MSVC, owner Windows MSYS2 CLANG64/Clang23, live input injection,
genuine R2/R3 Windows authorization, Microsoft-client M4 and performance are
**NOT RUN** before publication. `SendInput` remains subject to Windows UIPI,
and a short return is terminal rather than retried. **Next:** exact-SHA hosted
Windows validation and owner CLANG64; then bind this adapter only to the sole
R3 input route after R2 exposes genuine Windows OS-session admission. M4 OPEN.


Starting `main`: `9331ec040819b7156a24ea24ab9cc5973a8d891f`. R10 now has a runtime-only
`RuntimeServerTlsContext` that owns exactly one RAII `SSL_CTX`. Its
production factory performs the existing secure native certificate/private-key
open, metadata and distinct-file identity checks, exact bounded reads, PEM
parse, certificate time and `X509_PURPOSE_SSL_SERVER` checks, and key match,
then installs those already-parsed objects directly into
`SSL_CTX_new(TLS_server_method())`. No certificate/key pathname is reopened
between validation and context population; the source file handles and parsed
temporary objects are released only after OpenSSL has retained the server
identity. The offline `--check-tls-files` and `--check-tls-credentials`
paths reuse this same runtime component instead of maintaining a second TLS
credential policy.

The context explicitly requires TLS 1.2 or newer, leaves TLS 1.3 enabled,
disables compression, and disables legacy renegotiation when OpenSSL exposes
`SSL_OP_NO_RENEGOTIATION`; it does not lower OpenSSL's security level or
invent a cipher list. This increment deliberately supports exactly one X.509
certificate object in the configured certificate PEM: additional certificates
or other trailing non-whitespace PEM material are rejected rather than
silently ignored. This is server identity loading, not CA-chain/trust,
hostname, revocation or external-client acceptance.

`createServerTls()` returns the same
`std::unique_ptr<SSL, decltype(&SSL_free)>` ownership type consumed by R1's
`OwnedPreauthTcpConnection::attachServerTls`; each SSL is put in server
accept state. R10 keeps the context owner alive while its per-connection SSLs
are active, and ownership of each SSL/BIO/socket remains solely with R1.
Neither R2 nor R3 owns OpenSSL transport objects.

Dedicated CTests:
`runtime.validates-live-tls-context-construction`,
`runtime.tls-context-survives-credential-path-replacement`,
`runtime.rejects-live-tls-context-invalid-material`, and
`runtime.rejects-live-tls-context-extra-certificate-material`. The
replacement regression constructs the context first, replaces both credential
paths deterministically, then creates a fresh server SSL and verifies that its
certificate is still the originally validated identity.

**First hosted integration result:** implementation commit
`22d6641f0fbf5f92ce4d1327c1dbcd4fc0a1e11b`, Actions
`38877885057`, failed during Debug compilation on Linux and macOS because
the new test translation unit used a same-directory runtime-header include
from `tests/`. The production runtime TLS target itself compiled before that
test failure. The test now includes
`server/runtime/runtime_tls_context.h` through the target's existing
`src/` include root; this is an integration-path correction only, with no
TLS ownership or policy change. Exact-SHA CI for the correction is pending.

**Corrected exact-SHA hosted evidence:** correction commit
`d2b81dd06e70b9ab06dd14e899db514919644956`, Actions
`38878109138`. Linux/GCC found OpenSSL **3.0.13**, compiled Debug and ran
**307** registered CTests: **306 PASS / 1 FAIL**. macOS/Clang found Homebrew
OpenSSL **4.0.3**, compiled Debug and ran **275** registered CTests:
**274 PASS / 1 FAIL**. On both hosts all four new R10 tests PASS:
`runtime.validates-live-tls-context-construction`,
`runtime.tls-context-survives-credential-path-replacement`,
`runtime.rejects-live-tls-context-invalid-material`, and
`runtime.rejects-live-tls-context-extra-certificate-material`; the sole
full-suite failure is `transport.gcc-conference-create`. Pre-R10 parent
`c09e581ac965e79ce700ef4617a0af6d2b04adba`, Actions
`38877612047`, already fails that same transport test on Linux and macOS,
so R10 does not modify or mask it. R9 sanitizer and documentation-policy jobs
PASS. Windows/MSVC Debug configure and compile PASS; its full Debug CTest is
still **IN PROGRESS** at this evidence snapshot. Linux/macOS Release,
Windows Release, SDK/package steps and the exact Windows CTest result are
therefore **NOT RUN/NOT COMPLETE** for this SHA.

**Authoring validation:** OpenSSL 3.5.5 / GCC 14.2 C++23
`-Wall -Wextra -Wpedantic -Werror` compile of the production TLS component:
**PASS**. A focused synthetic fixture harness covering context construction,
TLS policy, per-connection server SSL, path replacement, malformed material
and duplicate certificate material: **4/4 PASS**. The complete repository
checkout/full CTest, Windows/MSVC, macOS/Clang, owner Linux/X11, owner MSYS2
CLANG64/Clang23, owner macOS27, external RDP clients and service installation
are **NOT RUN at authoring**; exact-SHA hosted CI is the next gate.

The executable remains fail-closed and **does not activate a listener**.
R2's genuine admission capability and R3's authoritative session lifecycle
remain separate and are not invoked by this new TLS owner. Packaging/install
remain protocol-SDK-only. **Next R10 step:** secure Linux runtime provisioning
for explicit GSS service principal/keytab and native identity policy, then a
minimal loopback listener/event loop only once the complete R1→R2→R3
connection aggregate can be constructed and revoked coherently.

# RDP-server protocol roadmap and acceptance gates

## R6 generation-safe DXGI pointer shape ownership (2026-10-16; exact-SHA CI pending)

Starting main inspected: `b8c04fe1242d0d7b1a52009311df876b6f6f4739`;
shared files are reconciled against the current publication parent immediately
before commit. The existing `WindowsDxgiFrameOwner` now retains only the
pointer facts returned atomically by its existing `AcquireNextFrame` lease:
independent position-change state, output-relative position/visibility, and
`PointerShapeBufferSize`. It still owns exactly one frame lease and clears
that metadata before `ReleaseFrame`.

New `windows_dxgi_pointer_shape.{h,cpp}` provides the bounded native
`GetFramePointerShape` seam and move-only owned shape bytes. A shape is
limited to 256x256 logical pixels and 512 KiB, with checked pitch, byte count,
hotspot and type. Monochrome data preserves the DXGI AND/XOR planes and halves
the reported scanline count to its logical height; color retains native BGRA
bytes; masked-color requires the documented binary alpha mask (0 or 0xff).
No borrowed DXGI buffer escapes the callback.

The existing `WindowsDxgiCaptureCycle`, not a second cursor scheduler, copies
shape data immediately after acquisition and before D3D11 staging can return
GPU-not-ready. Position and shape timestamps are independent: shape-only and
position-only frames are merged with any unread same-generation state so
neither can erase the other. Output-relative visible positions are converted
to checked Win32 virtual-screen coordinates using the already-selected output
rectangle. The owned update carries the existing pinned session/device
generation and is revalidated immediately before publication; revocation
clears unpublished cursor state and releases the native frame through the
existing unmap-before-`ReleaseFrame` teardown. The duplication owner supplies
the shape callback only to its already-owned capture cycle. R4 may move the
owned bytes but remains the sole graphics/cursor scheduler.

**Dedicated Windows offline CTests:**
`windows.cursor-dxgi-shape-owned-lifetime` and
`windows.cursor-dxgi-shape-generation-denials`. Coverage includes color,
monochrome and masked-color shape ownership, shape-only/position-only merging,
GPU-map deferral, source-buffer independence, same-frame reentry denial,
oversize/malformed pitch/hotspot/type/alpha rejection, `MORE_DATA`,
access loss, cancellation deferral, signed position overflow, stale generation
discard and required generation/output binding. Tests use synthetic callbacks;
ordinary CTest never calls a live `AcquireNextFrame` or captures the desktop.

**Authoring validation:** source/test review against the current C++23
high-warning contracts; full hosted build/CTest is **NOT RUN before
publication** and must be taken from exact-SHA Actions. Owner Windows MSYS2
CLANG64/Clang23, live Desktop Duplication, genuine Windows R2/R3 admission,
R4 runtime cursor delivery, Microsoft-client M4 and performance are **NOT RUN**.
No authentication, service event registrar, input injection or second R4
schedule is added. **Next:** exact-SHA Windows/MSVC + owner CLANG64 validation,
then a focused native Windows input increment only behind genuine R2/R3
authorization; M4 remains OPEN.







## R10 TLS server-certificate purpose gate (2026-10-16; exact-SHA CI pending)

Starting `main`: `d4669a0a612bf916c6f406d42f26d1174d7130c8`. The two owner-reported configuration-positive
CTest failures are not reproducible in the latest recorded hosted matrix:
Windows/MSVC Debug and Release both passed 285/285 registered CTests, including
`runtime.validates-configuration-syntax` and
`runtime.validates-configuration-comments-crlf`. Owner MSYS2 CLANG64/Clang
23 remains **NOT RUN**, so owner-local closure is not claimed.

The existing nonactivating `--check-tls-credentials` preflight now requires
the already-opened, currently-valid, certificate/private-key-matched X.509
certificate to be suitable for TLS server use according to OpenSSL's
`X509_PURPOSE_SSL_SERVER` purpose check. A clientAuth-only certificate is
rejected without reopening paths or weakening native file policy. New dedicated
CTest: `runtime.rejects-tls-credentials-client-only-certificate`. Trust-chain,
hostname, revocation, live credential-handle continuity into a future listener,
R2/R3 admission, service lifecycle and release packaging remain OPEN.

**Authoring validation:** OpenSSL 3.5.5 C++23 high-warning API probe for
`X509_check_purpose(..., X509_PURPOSE_SSL_SERVER, ...)` PASS. Full repository
build/CTest and owner platform tests are **NOT RUN** in this network-isolated
workspace; exact-SHA GitHub Actions is required after publication.

## R6 native DXGI owner increment (2026-10-16; exact-SHA hosted CI PASS)

The Windows-only `WindowsDxgiDuplicationOwner` now provides an explicit
factory/adapter/output/ID3D11Device/immediate-context/IDXGIOutput1/
IDXGIOutputDuplication lifecycle, with SDK-backed enumeration and an
injected deterministic offline seam. Output selection requires the selected
native monitor handle **and** exact signed desktop rectangle, attached state,
nonempty bounds and identity rotation. A second matching output, a stale
descriptor, unsupported device/output, or missing COM reference fails closed;
there is no output-zero fallback or software rendering fallback. Creation
uses the selected adapter with `D3D_DRIVER_TYPE_UNKNOWN`, BGRA support,
and D3D feature level 11.0. Duplication failures distinguish access denial,
access loss, unsupported configuration, and duplication-client pressure.

`close()` terminally revokes the nonzero native device epoch and cancels
any attached existing capture cycle before dropping its staging context,
duplication, output1, immediate context, device, output, adapter, and factory.
The optional capture-cycle binding uses the original frame-owner and native
staging-map callbacks, with revocation-only session generation observation.
No new scheduler, capture admission, automatic reconstruction, service
notification registration, cursor bitmap, or input injection is introduced.
R2/R3 must independently authorize/bind a Windows interactive desktop
before calling `open` or `attachCaptureCycle`; native monitor IDs and WTS
session IDs do **not** authorize a user. The runtime is NOT wired for capture.

**Dedicated Windows offline CTests:** `windows.capture-dxgi-duplication-owner-lifecycle`,
`windows.capture-dxgi-duplication-owner-selection-denials`, and
`windows.capture-dxgi-duplication-owner-epoch-revocation`.
Their injected callbacks do not enumerate or capture a real desktop.
**Exact-SHA hosted CI:** implementation `f42145a44c041510013d9da07a5d27652137db7f`,
Actions 38873520825 completed **SUCCESS**. Windows/MSVC passed **288/288**
registered CTests in Debug and Release, including all three new owner cases;
Linux/GCC passed **289/289** and macOS/Clang **265/265** in both configurations.
Documentation policy and sanitizer jobs passed. **NOT RUN:** owner MSYS2
CLANG64/Clang23, live `DuplicateOutput`, genuine R2/R3 Windows admission,
R4 real-time graphics and Microsoft-client M4. The next R6 increment is the
generation-safe pointer ownership described above; M4 remains OPEN.


## Target

Develop an independently maintained, secure, standards-compliant C++23 RDP
server protocol stack, portable across OSes via system adapters. Use native
RDP capabilities, not VNC, xrdp, clipboard injection helpers, or nonstandard
screen-sharing workarounds.

## Status: foundation, not release

Current code includes X.224/TPKT, selected MCS/GCC parsers, negotiation,
CredSSP/DER and CLIPRDR helpers, verified graphics algorithms and portable
testable core. It does **not** yet operate a complete authenticated RDP
server session. The library has no shipping daemon/installer.

## Parallel delivery plan — 10 agent roads, 6 convergence milestones

**Parallel implementation, synchronized acceptance.** Ten GPT-6-High
engineering agents/workstreams may design and implement independent code
in parallel, but they contribute to **one portable C++23 RDP server** with
one authoritative connection/session owner. The human project owner is
**not** an eleventh engineering road: the owner runs the agreed build +
CTest one-liner independently on Linux/X11, Windows MSYS2 CLANG64 with
Clang 23, and macOS 27, and reports results. Platform development and
automated testing run **in parallel from the beginning**; *human desktop
acceptance* runs in order Linux/X11 -> Windows -> macOS. This order does
not delay Windows/macOS implementation or portable test coverage.

### Ten independent engineering workstreams (R1–R10)

Each row owns a bounded implementation area and its **own new, dedicated
behavior-named CTest case(s)** registered in the existing single
`tests/CMakeLists.txt` registry, normally reusing existing test
executables and fixtures. A test must execute the changed production
behavior, with meaningful positive, negative, bounds and teardown
assertions where applicable. Building the static library or passing
someone else's previous tests is **not** evidence for new code. Platform
specific tests may be registered conditionally; report them NOT RUN on
other platforms, never silently call a skip a PASS. Do not create
parallel test registries, duplicate state controllers or one executable
per tiny behavior.

| Road | Agent-owned scope and first deliverable | Interface/dependency to converge |
| --- | --- | --- |
| **R1 Transport** | Bounded native TCP accept/read/write, pinned OpenSSL TLS socket, nonblocking partial-I/O, cancellation and disconnect; test live loopback lifecycle/failures without unauthorized admission. | Supply immutable active TLS/peer identity and reliable bounded I/O to R2/R3. |
| **R2 Identity/security** | Real, opt-in Kerberos/GSS CredSSP/NLA positive path, active TLS binding, independent native OS identity/session authorization and fail-closed denials. | Provide a verified admission decision to R3; request OS-policy adapter facts from R5/R6/R7 without granting sessions by synthetic tokens. |
| **R3 RDP session/router** | **Sole** authoritative server session state, MCS/GCC attach/join, licensing, capabilities, Demand/Confirm Active, finalization and virtual-channel routing. | Consume R1 I/O + R2 admission; export bounded authorized graphics/input/clipboard channel contracts to R4/R8 and OS adapter lifecycle to R5–R7. |
| **R4 Graphics** | Static license-reviewed x264 C++23 RAII integration; negotiated RDPGFX AVC420, DVC framing, surfaces, ACK/backpressure, dirty-region frames, resize and reconnect. | Consume abstract captured-frame/cursor data from R5–R7 and channel access from R3; own the **one** frame schedule. |
| **R5 Linux/X11 adapter** | X11 capture, pointer/keyboard/cursor, display/session lifecycle and OS authorization adapter; deterministic native tests. | Implement portable frame/input/identity interfaces; first authorized desktop-acceptance target (M3). |
| **R6 Windows adapter** | Native Windows desktop capture, pointer/keyboard/cursor, identity/session policy and lifecycle; validate in **MSYS2 CLANG64, Clang 23**. | Implement the **same** interfaces as R5, not a second RDP engine; develop now, human acceptance at M4. |
| **R7 macOS adapter** | Native macOS capture, input, cursor, permissions, identity/session and lifecycle for **macOS 27**. Initial internal CoreVideo/Retina/TCC-preflight adapter compiled with dedicated offline CTests; full macOS 27 verification and live capture remain NOT RUN. | Implement the **same** interfaces as R5; develop now, human acceptance at M5. |
| **R8 Clipboard/files** | One native CLIPRDR lifecycle; text, PNG/DIB/DIBV5, generation-safe X11/Windows/macOS ownership and bounded on-demand file transfer. | Use R3's virtual-channel router and OS clipboard adapters; not a blocker for first visible Linux desktop, but required for declared full-feature release. |
| **R9 Quality/interoperability** | Independently authored dedicated CTests for new integration boundaries, fuzz/sanitizer negatives, CI triage, Microsoft-client matrix, performance/reliability regression and verification receipts. | Validate every road; maintain **one test registry** and integrate cross-road fixtures rather than duplicate behavior owners. |
| **R10 Runtime/release** | Standalone first-party server executable, secure startup/configuration, packaging, service/termination, installation, upgrades, rollback, release evidence and commit integration coordination. | Consume R1–R9 verified interfaces; SDK ZIPs alone never count as deployable server artifacts. |

**R10 secure offline runtime configuration boundary (2026-10-15;
implementation pending exact-SHA CI):** The non-installable `rdp-server` executable
links the existing portable protocol library. `--help` and `--version`
remain informational. New `--check-config FILE` validates a *syntax-only*
4,096-byte maximum configuration with required unique settings:
`listen_address`, `listen_port`, `tls_certificate`, `tls_private_key`,
`authentication`, `os_authorization`, and `max_connections`. The
preliminary policy accepts only loopback, port 1–65535, absolute and
different cert/key path strings, `authentication=required`,
`os_authorization=required`, and 1–64 connections. Malformed, unknown,
duplicate, missing, oversize, control-byte and unsafe values are
rejected. Even syntactically accepted configuration **cannot start** a
listener, authenticate a user or authorize a desktop. Real TLS key
contents, permissions, Kerberos/OS policy, and runtime service gates
have NOT been verified or implemented.

**Local isolated PASS:** Linux GCC 14.2 and Clang 17 strict C++23 builds,
25/25 direct CMake-script behavior checks each, then the same 25/25
with each compiler under ASan+UBSan. A scratch offline harness using
the *same CTest registration text* passed 25/25 tests in both Debug
and Release (GCC 14.2); it does not link/build the whole repository.
Files and executables stayed inside `~/rdp-server/build/`.
No full repository CMake/CTest, owner
three-platform checkpoints or CI ran for this pending patch; M1–M6
remain unaccepted. Parent `main`:
`2ee2d1371a98b237c68cee061eea13811278d8f6`.
**Publication:** the containing main commit delivers code, tests and
documentation atomically using non-force, expected-HEAD update.
Exact-SHA CI and owner results are NOT RUN at authoring.
**Next:** full Debug/Release CTests and SDK/package regression,
then independent same-SHA owner acceptance.
**R10 POSIX configuration-descriptor validation (2026-10-15; exact-SHA CI NOT RUN at authoring):**
The existing non-installable, fail-closed `rdp-server --check-config FILE`
now opens POSIX configuration paths with `O_NOFOLLOW | O_NONBLOCK |
O_CLOEXEC`, then checks the same open descriptor with `fstat` before
reading. Reject symlink final components, directories, FIFOs/other
nonregular objects and group/world-writable config files; descriptor
ownership passes to `fdopen`/RAII, with explicit close if `fdopen`
fails. The file remains limited to 4,096 bytes and every startup
attempt still refuses service activation. Five new **POSIX-only**
dedicated runtime CTests cover private regular-file acceptance and
symlink, FIFO, group-writable and directory rejection. Existing 25
runtime CTests are preserved. Synthetic fixture cleanup is safe across
repeat CTest runs. **PASS (isolated local only):** GCC 14.2 strict
C++23 focused CTest 30/30, repeat 30/30; Clang 17 ASan/UBSan focused
CTest 30/30 with leak detection. **NOT RUN:** full repository CMake/
CTest (no full local Git checkout; GitHub DNS unavailable), Windows/
macOS exact-code CI at authoring, owner's three-platform one-root
command, TLS private-key ACL/permission checks, actual R2 authorization,
R3 live session, external Microsoft client and desktop. On Windows,
existing syntax-only `fopen` remains in use; Windows native ACL/reparse
point hardening is still required. Parent main is resolved by the atomic
commit; milestone acceptance M1–M6 remains open. **Next:** exact-SHA
CI and owner baseline, then Windows-native safe config-file opening
and independent certificate/key permission checks, without starting
a service.

**R10 POSIX file-policy exact-commit CI result (2026-10-15):**
Production commit `25e751b8b0c0e09905355c71e9abaf7bf20fc64c` is published on `main`.
[GitHub Actions 38800655859](https://github.com/k1moradi/RDP-server/actions/runs/38800655859)
**FAILED overall**, but **R10 runtime behavior PASS**: macOS/Clang
five new `runtime.*configuration*` POSIX cases all PASS (30/30 R10
cases), Windows/MSVC **180/180** total registered CTests in BOTH
Debug and Release, plus downstream SDK consumer 1/1, ZIP/digest
artifacts and documentation-policy PASS. Linux/GCC configure PASS,
Debug build FAIL before CTest on R5-owned
`src/x11/x11_display_connection.cpp:222` (enum/non-enum conditional,
`-Werror=extra`), reported to
[R5 issue #4](https://github.com/k1moradi/RDP-server/issues/4).
macOS/Clang Debug **177/178** PASS; the sole failure is R1-owned
`transport.tcp-owned-reply-interest-priority` at
`tests/test_owned_preauth_session.cpp:2112`, reported to
[R1 issue #2](https://github.com/k1moradi/RDP-server/issues/2).
Linux full CTest, macOS Release and associated packaging NOT RUN;
untagged prerelease SKIPPED. Local GCC 14.2 ASan/UBSan focused R10
CTest additionally **30/30 PASS**, but remains an isolated harness.
Owner Linux/X11, Windows MSYS2 CLANG64/Clang23 and macOS27 one-root
CTest and real-client authorization/desktop remain NOT RUN.
M1–M6 acceptance remains OPEN. **Next integration step:** R5/R1
owners correct their failures and verify new exact-SHA CI; R10 follows
with Windows native file-handle/ACL checks.

**R10 Windows-native offline file-handle gate (2026-10-15; CI NOT RUN at authoring):**
`rdp-server --check-config` now requires drive-absolute Windows
configuration file paths and opens via `CreateFileA` with
`FILE_FLAG_OPEN_REPARSE_POINT`. An opened handle must be disk-backed,
not a directory or a final-component reparse point; handle ownership
transfers exactly once via `_open_osfhandle`, `_fdopen` and RAII.
Four new Windows-only `runtime.*` CTests exercise ordinary file
acceptance, directory and existing-relative-file denials, and device
namespace rejection using synthetic data. No listener, credentials,
OS session or desktop are activated. The existing Windows and POSIX
test cases are retained. **NOT RUN at authoring:** native Windows
compiler/full CTest, current exact-SHA GitHub Actions, owner's
Linux/X11, MSYS2 CLANG64 Clang23 and macOS27 checkpoints, and live
client. This gate does NOT inspect the Windows DACL, intermediate
junctions, or real TLS key/certificate permissions; those remain
separate blockers and the server still refuses startup.
**Next:** validate exact-SHA hosted Windows Debug/Release plus
cross-platform CI and implement DACL policy with its own CTest.
M1–M6 remain open.

**R10 Windows handle exact-SHA CI PASS (2026-10-15):**
Implementation [`c7676520bb2c360d156004d458d5ed946575297b`](https://github.com/k1moradi/RDP-server/commit/c7676520bb2c360d156004d458d5ed946575297b)
passed [Actions 38844859211](https://github.com/k1moradi/RDP-server/actions/runs/38844859211)
with Linux/GCC **205/205**, macOS/Clang **191/191**, and Windows/MSVC
**199/199** full registered CTests in EACH Debug and Release.
All four newly registered Windows-only native config-handle CTests
explicitly PASS in both Windows configurations. Each OS's installed
downstream SDK consumer **1/1 PASS**; protocol-only ZIP/SHA256
packaging and uploads PASS, documentation-policy PASS.
Automatic protocol prerelease SKIPPED (no tag).
This is hosted CI evidence, NOT the owner's Linux/X11,
Windows MSYS2 CLANG64 Clang23 and macOS27 same-SHA command.
Native ACL/reparse ancestors and actual TLS private-key/OS
authorization remain unverified, so M1–M6 remain OPEN.
**Next R10:** Windows DACL/write-access gate and dedicated CTests.

**R10 Windows opened-HANDLE DACL write-grant gate (2026-10-15; CI NOT RUN at authoring):**
The offline, non-installable `rdp-server --check-config` reads
`OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION` from the
already-open Win32 file handle with `GetSecurityInfo` (Advapi32),
not from a second pathname lookup. Null/invalid owner or DACL,
unexpected allow-ACE representations, and write/append/delete/ACL
modification grants to Everyone, Authenticated Users, BUILTIN Users/
Guests, Anonymous, Interactive or Network principals fail closed.
Deny ACEs and inherit-only entries are not misread as live grants.
The native file-handle and 4,096-byte syntax checks remain intact;
the server refuses to start. Four new Windows-only dedicated CTests
check owner-private acceptance and synthetically granted Everyone,
Authenticated Users and BUILTIN Users modification rights. All
Windows configuration test fixtures receive a private DACL before
running, independent of checkout ACL inheritance; the tests use
the OS-provided `whoami.exe` and `icacls.exe`, not privileged
service activation. **NOT RUN at authoring:** Windows/MSVC or
MSYS2 CLANG64/Clang23 build, exact-SHA Actions, owner three-platform
same-SHA CTest and real Microsoft RDP client. Inherited parent
junctions, unknown domain-specific trustees, full Windows effective-
access evaluation, TLS private-key file protection and OS admission
remain unverified; M1–M6 remain open. **Next:** exact-commit CI,
then comprehensive ACL policy and credentials-file permissions.

**R10 Windows DACL security exact-SHA CI PASS (2026-10-15):**
Code commit [`9dedd0b6608ec826e850dc8d8706f0af46d2b287`](https://github.com/k1moradi/RDP-server/commit/9dedd0b6608ec826e850dc8d8706f0af46d2b287)
passed [Actions 38849455579](https://github.com/k1moradi/RDP-server/actions/runs/38849455579).
Hosted Linux/GCC **217/217**, macOS/Clang **201/201**, and
Windows/MSVC **219/219** CTests all PASS in **each Debug and Release**
configuration. The new four DACL-positive/negative Windows runtime
CTests explicitly PASS in both configurations. Installed downstream
SDK consumer **1/1 PASS** per OS, artifact ZIP/SHA256 and
documentation-policy checks PASS; R9 clipboard sanitizer job PASS.
Protocol prerelease publication SKIPPED (no release tag).
These results prove only the hosted native/offline build and test
boundary. Owner's separate Linux/X11, Windows MSYS2 CLANG64/Clang23
and macOS27 same-SHA one-liner, full Windows effective DACL rights,
intermediate reparse paths, TLS certificate/private-key ACLs,
actual R2/R3 admission, Microsoft-client desktop and M1–M6
convergence are **NOT RUN / NOT ACCEPTED**.
**Next R10:** audit real certificate/private-key file identities,
permissions and lifecycle, with dedicated security-negative CTests,
without activating any listener.

**R10 deterministic POSIX configuration fixture correction (2026-10-15; exact-SHA CI NOT RUN at authoring):**
Owner-reported full CTest showed failures at
`runtime.validates-configuration-syntax` (#164) and
`runtime.validates-configuration-comments-crlf` (#165).
The full failure diagnostics and platform were not included; the
specific root cause remains unconfirmed. Both success fixtures
previously inherited the local filesystem creation `umask`; on
POSIX a permissive umask can create group/world-writable files,
which the production R10 security gate correctly rejects.
The shared CMake fixture writer now explicitly applies owner-only
read/write permissions to each POSIX file before case-specific
negative overrides; it does NOT weaken the production file-policy
check. New dedicated behavior-named POSIX CTest
`runtime.validates-configuration-mode-normalization` starts from
a deliberately world/group-writable synthetic file and verifies
the existing production `--check-config` accepts it only after
fixture permissions are normalized. Existing
`runtime.rejects-configuration-group-writable` still asserts
the restrictive production behavior. **PASS:** isolated Linux
CMake 3.31.6 under `umask 000` creates mode 666 and explicit
`file(CHMOD OWNER_READ OWNER_WRITE)` produces mode 600.
**NOT RUN at authoring:** actual owner failure command/output,
full-repository CTest and Windows/macOS CI. No service activation,
TLS private keys or real client. M1–M6 remain open. Next: exact-SHA
hosted CTests and rerun the owner's two previously failing tests.

**R10 integration recovery — workflow YAML duplicate jobs (2026-10-15):**
The owner-reported POSIX config CTest failures led to R10 test-only
fixture normalization at
[`875033cdfb0b7b13d7842de711b54ba3d867ec8f`](https://github.com/k1moradi/RDP-server/commit/875033cdfb0b7b13d7842de711b54ba3d867ec8f).
Its exact-SHA [Actions 38850361038](https://github.com/k1moradi/RDP-server/actions/runs/38850361038)
failed at workflow admission with **zero jobs**, not at R10 CTest.
The updated workflow had duplicate `documentation-policy` and
`publish-protocol-prerelease` job identifiers plus an outdented
stray shell line after a release command. R10 now removes the
duplicate tail, preserving R9's legitimate separate sanitizer job,
the first documentation-policy gate, and the original guarded SDK
prerelease job. This is a CI configuration repair only: no production
runtime or security check is loosened. **PASS:** exact static
invariant inspection (one of each job, sanitizer retained).
**NOT RUN at authoring:** restored exact-commit hosted GitHub
Actions/CTest, owner's platform test; original two owner test
failure diagnostics have not been supplied. M1–M6 remain OPEN.
Next: verify the restored exact-SHA workflow and the fixture regression.

**R10 macOS fixture mode normalization correction (2026-10-15):**
[CI 38850617229](https://github.com/k1moradi/RDP-server/actions/runs/38850617229)
started correctly after the restored workflow and macOS/Clang Debug
reported **PASS** for both owner-reported runtime regressions:
`runtime.validates-configuration-syntax` and
`runtime.validates-configuration-comments-crlf`.
The new `runtime.validates-configuration-mode-normalization` itself
**FAILED before invocation** because its synthetic fixture used invalid
CMake `OTHERS_WRITE` instead of supported `WORLD_WRITE`.
This follow-up corrects the test keyword only. Local CMake 3.31.6
probe **PASS**: explicit group/world writable mode 622, then
normalized owner-only mode 600; previously established production
group-writable denial is unchanged. Exact-SHA CI for this correction
**NOT RUN at authoring**; owner's original terminal outcome after
pull remains NOT RUN. No RDP runtime production code changed.

**R10 POSIX fixture normalization exact-SHA CI PASS (2026-10-15):**
Corrected test/script commit [`a0c39e4a612c740949c05e4a9699f711061c21d0`](https://github.com/k1moradi/RDP-server/commit/a0c39e4a612c740949c05e4a9699f711061c21d0)
passed [Actions 38850747646](https://github.com/k1moradi/RDP-server/actions/runs/38850747646).
Hosted Linux/GCC **226/226**, macOS/Clang **209/209**, and
Windows/MSVC **228/228** full CTests all PASS in **both Debug and
Release**. `runtime.validates-configuration-syntax` and
`runtime.validates-configuration-comments-crlf` explicitly PASS
on every hosted OS, and the added
`runtime.validates-configuration-mode-normalization` explicitly
PASSes on Linux/macOS. R9 sanitizer job, hosted documentation
policy and per-OS downstream SDK consumer **1/1** PASS; protocol
ZIP/SHA256 packaging succeeds. The CI workflow is again valid,
with one sanitizer, documentation and prerelease job.
No production security policy was relaxed. **NOT RUN:** owner
Linux/X11, Windows MSYS2 CLANG64/Clang23, macOS27 original
terminal after latest pull; failure root cause on owner's host
remains provisional until original `ctest --output-on-failure`
diagnostics are provided. Real TLS private-key permissions,
R2/R3 admission, Microsoft client and M1–M6 acceptance OPEN.

**R10 offline TLS credential-file identity and permission preflight (2026-10-15; exact-SHA CI NOT RUN at authoring):**
The noninstallable `rdp-server` gains explicit
`--check-tls-files FILE` independent from the existing syntax-only
`--check-config`. After the same seven-setting syntax validation,
a bounded metadata-only preflight opens the configured certificate
and private-key paths without following the final symlink, rejecting
missing, empty, nonregular, oversized or aliased (same file identity)
objects. Limits: certificate ≤1 MiB, private key ≤256 KiB.
POSIX checks the opened descriptor with `fstat`, rejects group/world
write on the certificate and all group/world access to a key, and
requires the key owner to match the effective UID. Windows uses
the existing `CreateFileA` no-final-reparse/handle identity gates,
and the opened HANDLE's DACL; private-key read grants are restricted
to the actual owner, SYSTEM and Administrators. Existing config-file
size/DACL/syntax checks continue unchanged. Paths and secrets are not
logged. **New behavior CTests:** ordinary private metadata success;
missing cert/key, empty/oversized key, hard-link identity alias,
POSIX group-readable key, group-writable certificate, final-component
symlinks, nonregular directory key, and Windows public-read key; plus
CLI smuggling rejection. All are deterministic synthetic files
under the existing build fixture root. No real certificate or private
key is read or cryptographically parsed; key/cert correspondence,
expiry, OS admission, TLS/NLA, desktop and listener **NOT VERIFIED**.
**NOT RUN at authoring:** exact-SHA hosted CI, owner's three-platform
same-SHA command, external Microsoft client. M1–M6 remain open.
Next R10: exact CI, full owner CTests, native parent-path/reparse
and genuine private-key provisioning checks before any service.

**R10 TLS-file initial CI owner-fixture correction (2026-10-15):**
[Implementation 8a4f466c3bab9af155da623a54dba91b7cb7529d](https://github.com/k1moradi/RDP-server/commit/8a4f466c3bab9af155da623a54dba91b7cb7529d),
[Actions 38857433495](https://github.com/k1moradi/RDP-server/actions/runs/38857433495):
Linux full matrix PASS; macOS Debug 15 unrelated R1 TCP accept
cases FAIL but every R10 TLS-file CTest PASS. Windows Debug
246/247 PASS; the one failing R10 test is
`runtime.validates-tls-files-private-regular` (exit 3). This
test-only change explicitly sets each synthetic Windows TLS file's
owner to the granted test-account SID via `icacls /setowner`.
The precise Windows SID mismatch remains a hypothesis until verified
by a passing exact-SHA run; production DACL restrictions are not
weakened. R1 separately published a native accept correction.
Owner 3-platform one-root CTest, real credentials and M1–M6
acceptance remain NOT RUN / OPEN.

**R10 TLS metadata exact-SHA integrated CI PASS (2026-10-15):**
Corrected fixture commit [`2ccc1a384306359fc01a35ddfbefd89d3cbbc13b`](https://github.com/k1moradi/RDP-server/commit/2ccc1a384306359fc01a35ddfbefd89d3cbbc13b)
passed [Actions 38857862786](https://github.com/k1moradi/RDP-server/actions/runs/38857862786)
across ALL hosted platforms: Linux/GCC **252/252**, macOS/Clang
**234/234**, Windows/MSVC **251/251** full registered CTests
in EACH Debug and Release. Windows positive private-file fixture
and public-read private-key denial explicitly PASS in both modes,
as do the POSIX identity, permission, size and symlink cases.
R1 native TCP accept regressions no longer fail in this tested SHA.
R9 sanitizer job and documentation-policy PASS; downstream installed
protocol SDK consumer **1/1 PASS** per OS; SDK ZIP/digest packaging
and artifact upload PASS. Protocol prerelease SKIPPED (no tag).
**Security and acceptance limits:** metadata/ACL snapshots only,
no cryptographic PEM parsing, X.509 expiry/key match, directory
ancestor reparse/ACL checks, OS admission, NLA, listener, or live
desktop. Owner's Linux/X11, Windows MSYS2 CLANG64 Clang23,
macOS27 same-SHA terminal commands NOT RUN. M1–M6 OPEN.
Next R10: credentials' parent-path confinement and real
certificate/key cryptographic provisioning checks behind a
separate offline, non-activating gate.

**R10 POSIX TLS file parent-symlink component walk (2026-10-15; CI NOT RUN at authoring):**
The already implemented independent, nonactivating
`rdp-server --check-tls-files FILE` previously rejected a symlink at
the final cert/key path component but could follow an ancestor
directory symlink during pathname opening. For POSIX TLS certificate
and private-key preflight, R10 now walks absolute path components from
an opened root directory with bounded stack buffers and
`openat(O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK)`, using
`O_DIRECTORY` at each intermediate step. It then performs the
**existing** opened-descriptor regular-file, owner, mode, size and
cert/key identity tests. Failures close the current descriptor; no
path content, key material or credential is logged or parsed.
Three dedicated **POSIX-only** CTests exercise a real nested parent
(accept) and symlinked parent directories for key and certificate
(reject), invoking the existing real executable and CMake fixture.
Windows's previously validated native HANDLE/reparse/DACL path is
unchanged. The ordinary `--check-config` remains syntax-only;
normal startup, listener, R2 admission and R3 desktop remain
disabled. **PASS isolated Linux:** GCC 14.2 and Clang 17 strict
C++23 production-like focused source with genuine nested/symlink
file handles, success 0 and rejection 3. **NOT RUN at authoring:**
full repository CI on this increment, owner Linux/X11,
Windows MSYS2 CLANG64 Clang23, macOS27 exact-SHA one-liner and
live-client checks. This does not prevent replacement **after**
offline validation; live TLS loader must re-open and re-validate
credential handles. M1–M6 remain unaccepted. Next: hosted CI
Debug/Release and owner full CTests, then actual cryptographic
certificate/private-key parsing and matching without service
activation.

**R10 POSIX TLS ancestor symlink exact-SHA CI PASS (2026-10-15):**
Implementation [`88ba20c5d4581765475e9337b366469a0d9bf089`](https://github.com/k1moradi/RDP-server/commit/88ba20c5d4581765475e9337b366469a0d9bf089)
passed [GitHub Actions 38858338819](https://github.com/k1moradi/RDP-server/actions/runs/38858338819)
with Linux/GCC **258/258**, macOS/Clang **240/240**, and
Windows/MSVC **254/254** full CTests in EACH Debug and Release.
Three new R10 POSIX parent-path cases (nested real directory,
symlinked key ancestor, symlinked certificate ancestor) explicitly
PASS on Linux and macOS, while Windows's runtime syntax/CRLF,
DACL and native TLS metadata CTests remain passing. R9 sanitizer,
documentation-policy and all three downstream SDK consumer jobs
**PASS**; protocol SDK ZIP/digests and uploads PASS.
Untagged prerelease skipped as intended.
This is hosted exact-SHA evidence; owner's Linux/X11,
Windows MSYS2 CLANG64 Clang23 and macOS27 single-root command
still **NOT RUN** here, and M1–M6 remain OPEN. Offline acceptance
cannot authorize live RDP sessions or guarantee a later separately
opened TLS file's identity.

**R10 offline PEM certificate/private-key parse and match gate (2026-10-15; exact-SHA CI NOT RUN at authoring):**
A new explicit `rdp-server --check-tls-credentials FILE` layers on
the existing syntax and TLS-file metadata gates without changing
either command's contract. Certificate/key files are opened once
through the existing native secure-path/type/size/permission policy,
kept open, parsed directly from those same `FILE*` objects using
OpenSSL PEM APIs, and required to satisfy `X509_check_private_key`.
There is no second pathname reopen after metadata acceptance.
Encrypted private keys fail noninteractively through a password
callback that always returns zero; the checker never prompts or
accepts a passphrase. Certificate trust, hostname, chain, revocation
and validity time are NOT evaluated. Six new cross-platform dedicated
runtime CTests use fixed synthetic test-only EC material: matching
pair success; mismatched key, malformed cert, malformed key,
encrypted key and option-smuggling rejection. Encrypted-key CTest has
a 10-second timeout to prove no prompt/hang. Existing metadata tests
and unconditional startup refusal remain. **NOT RUN at authoring:**
full exact-SHA hosted matrix, owner Linux/X11 / Windows MSYS2
CLANG64 Clang23 / macOS27 one-root tests, real provisioned TLS
credentials, R2/R3 authorization and Microsoft-client desktop.
M1–M6 remain OPEN. **Next:** hosted CI and owner full CTest, then
certificate trust/expiry policy and live-loader handle continuity
without enabling a listener prematurely.

**R10 Windows PEM parser CRT-boundary correction (2026-10-15; exact-SHA CI NOT RUN at authoring):**
Initial crypto implementation
[`0a673075a3532249cf1a53439994537e165631fa`](https://github.com/k1moradi/RDP-server/commit/0a673075a3532249cf1a53439994537e165631fa),
[Actions 38864141629](https://github.com/k1moradi/RDP-server/actions/runs/38864141629):
all six new TLS-credential CTests PASS on Linux and macOS; those two
full jobs fail only a parent-SHA-reproduced R3
`transport.mcs-session-unverified-ordering` assertion. Windows
compiles, but five content-parsing cases return process status 1
while option-smuggling PASSes. A later descendant Windows run
reproduces the same R10 pattern. The cross-platform parser had
passed the application CRT's `FILE*` directly into OpenSSL.
This follow-up keeps the security-validated file object open,
reads exactly its already-bounded native file size into a
nothrow-owned buffer, rejects short/growing reads, then gives
OpenSSL a memory BIO. OpenSSL no longer consumes a foreign CRT
`FILE*` on Windows; there is still no pathname reopen between
metadata and content checks. Metadata/DACL/mode/identity policy
and all CLI semantics remain unchanged. **NOT RUN at authoring:**
corrected hosted CI and owner three-platform command. R3 blocker
was reported on issue #5 with exact parent evidence. M1–M6 OPEN.

**R10 PEM/key-match corrected cross-platform CI evidence (2026-10-15):**
Corrected implementation [`caa767fe0550958aebd215f19fa83dae0fb7fee5`](https://github.com/k1moradi/RDP-server/commit/caa767fe0550958aebd215f19fa83dae0fb7fee5),
[Actions 38864834658](https://github.com/k1moradi/RDP-server/actions/runs/38864834658).
The Windows memory-BIO correction is verified: Windows/MSVC
**269/269 PASS** in both Debug and Release, including all six new
TLS-credential parse/match cases. Linux/GCC **271/271 PASS** in both
Debug and Release. macOS/Clang Debug **253/253 PASS**; macOS Release
**252/253**, with the sole failure R1-owned
`transport.tcp-owned-reply-interest-priority` at
`test_owned_preauth_session.cpp:2112`. Every R10 TLS-credential
case PASSes in macOS Release too. R1 issue #2 received the exact
failure. R9 sanitizer and documentation-policy PASS. Linux/Windows
downstream SDK consumer **1/1**, protocol ZIP/digest packaging and
artifact upload PASS; macOS downstream/package are NOT RUN because
its Release CTest step failed first. Overall workflow therefore
reports FAIL despite cross-platform R10 success. Owner Linux/X11,
Windows MSYS2 CLANG64/Clang23 and macOS27 same-SHA tests, real
certificate trust/expiry/revocation, R2/R3 live authorization and
Microsoft-client desktop remain NOT RUN. M1–M6 OPEN.
**Next R10:** certificate validity/trust policy and future live-loader
handle continuity, still behind nonactivating offline checks.

**R10 offline certificate validity-time gate (2026-10-16; exact-SHA CI NOT RUN at authoring):**
The existing nonactivating `--check-tls-credentials` path now rejects
a parsed certificate unless its `notBefore` and `notAfter` fields
contain the current system time. Invalid time encodings fail closed
through OpenSSL's certificate-time comparison. This check is performed
on the same securely opened, bounded certificate bytes already used for
PEM parsing; no path reopen, listener, TLS session or service activation
is added. The fixed matching-pair fixture is extended through 2120 so
the positive regression is not tied to the original 2036 certificate.
Dedicated cross-platform CTests
`runtime.rejects-tls-credentials-expired-certificate` and
`runtime.rejects-tls-credentials-not-yet-valid-certificate` use
certificates with the same matching private key, isolating the temporal
denial from key mismatch. Local GCC 14.2/OpenSSL 3.5.5 strict C++23 API
probe **PASS**: current+matching accepted; expired+matching and
not-yet-valid+matching rejected. Full repository CTest and exact-SHA
hosted CI are **NOT RUN at authoring**. Certificate chain trust,
hostname and revocation, live-loader handle continuity, R2/R3
authorization, listener/service startup and M1-M6 remain OPEN.
Starting `main`: `46b1ca77c4c2c00bbd66e02de71896999f8c71fd`.

**R10 validity-time first exact-SHA fixture correction (2026-10-16):**
Implementation `8dfa00a8aef833e24f6a7ad3867a16c0a37a9351`,
[Actions 38871662501](https://github.com/k1moradi/RDP-server/actions/runs/38871662501)
compiled the production change on all hosted platforms. The two new
temporal denials explicitly **PASS** on Linux/GCC, macOS/Clang and
Windows/MSVC, and the owner-reported configuration syntax/CRLF cases
also **PASS** on all three. Full Debug CTest is Linux **285/286**,
macOS **264/265** and Windows **284/285**: the sole failure everywhere
is the pre-existing `runtime.validates-tls-credentials-matching-pair`
fixture comparing stdout to the old success text after production
truthfully stopped saying expiry was unverified. R9 sanitizer and
documentation-policy **PASS**; Release/downstream steps are not credited
because Debug failed. This follow-up changes only that CMake fixture
expectation. Production validity, key-match, file-security and startup
denials are unchanged. Owner MSYS2 CLANG64/Clang23 remains **NOT RUN**.

**R10 certificate validity-time corrected exact-SHA CI PASS (2026-10-16):**
Fixture correction `7f6d74b4ef9b03c86ecabc7c56af6f1de071ad07`,
[Actions 38871903394](https://github.com/k1moradi/RDP-server/actions/runs/38871903394)
is **PASS**. Linux/GCC **286/286**, macOS/Clang **265/265**, and
Windows/MSVC **285/285** full CTests PASS in each Debug and Release
configuration. On every hosted OS/configuration,
`runtime.validates-configuration-syntax`,
`runtime.validates-configuration-comments-crlf`,
`runtime.validates-tls-credentials-matching-pair`,
`runtime.rejects-tls-credentials-expired-certificate`, and
`runtime.rejects-tls-credentials-not-yet-valid-certificate` explicitly
PASS. R9 sanitizer, documentation-policy, downstream installed SDK
consumer **1/1**, protocol ZIP/SHA256 packaging and artifact upload all
PASS; untagged prerelease publication is skipped as intended. Owner
Linux/X11, Windows MSYS2 CLANG64/Clang23 and macOS27 same-SHA commands
remain **NOT RUN**. Certificate chain trust, hostname/revocation,
live-loader handle continuity, R2/R3 authorization, listener/service
startup and M1-M6 remain OPEN.

**R10 OpenSSL 4 temporal-check API correction (2026-10-16; corrected exact-SHA CI pending):**
Documentation receipt `f249acf6d06269d895daa10db219d8c12a087e8b`,
[Actions 38872238533](https://github.com/k1moradi/RDP-server/actions/runs/38872238533)
exposed a new R10 compile boundary after the macOS runner installed
OpenSSL **4.0.3**: `X509_cmp_current_time` is deprecated there and the
project's `-Werror` gate correctly rejected both calls before CTest.
Linux and R9 sanitizer/documentation-policy PASS on that run; Windows
was still executing when the correction was authored. The runtime now
selects OpenSSL 4+'s nondeprecated certificate-level temporal checker
and retains the prior strict comparison only for OpenSSL 3.x. Local
GCC 14.2/OpenSSL 3.5.5 `-Wall -Wextra -Wpedantic -Werror` probe
**PASS**. Temporal semantics, key matching, secure handle ownership and
startup refusal are unchanged. Corrected hosted OpenSSL 4 compilation,
owner MSYS2 CLANG64/Clang23 and macOS27 remain to be verified.

**R10 OpenSSL 4 temporal-check corrected exact-SHA CI PASS (2026-10-16):**
Compatibility fix `e540be81f297c7f880c6b03db6ffc1a3ad8998ad`,
[Actions 38872488081](https://github.com/k1moradi/RDP-server/actions/runs/38872488081)
is **PASS**. Linux/GCC **287/287**, macOS/Clang with Homebrew
OpenSSL **4.0.3** **265/265**, and Windows/MSVC **285/285** full CTests
PASS in each Debug and Release configuration. The owner-reported
configuration syntax/CRLF positives, validity-aware matching-pair
success, expired-certificate denial and not-yet-valid-certificate denial
all explicitly PASS on every hosted OS/configuration. R9 sanitizer,
documentation-policy, downstream installed SDK **1/1**, ZIP/SHA256
packaging and artifact upload PASS; untagged prerelease is skipped.
This closes the hosted OpenSSL 4 compile regression without changing
temporal policy. Owner Linux/X11, Windows MSYS2 CLANG64/Clang23 and
macOS27 same-SHA validation remain **NOT RUN**; chain trust, hostname,
revocation, live-loader continuity and service activation remain OPEN.

**R10 Windows CRLF fixture regression (2026-10-15):** The first
published R10 increment `a7234f40c4e2188b1170daf363136a6ac159c025`
passed the Ubuntu/GCC and macOS/Clang CI jobs, but Windows/MSVC Debug
failed `runtime.validates-configuration-comments-crlf` (test 137 of 154)
with exit 3; the other 24 R10 runtime cases passed there. This follow-up
normalizes existing CR bytes before generating CRLF and verifies the
synthetic fixture's written bytes using `file(READ HEX)`. Isolated Linux
focused CTest **25/25 PASS**; corrected exact-SHA Windows CI is
**NOT RUN at authoring**. No production policy is relaxed, and M1–M6
remain unaccepted. Next: full Debug/Release CI and owner one-root tests.

**R10 follow-up Windows newline compatibility (2026-10-15):**
The first correction `b90baa6d76d769fce18a216d055c081375cd9b89`
passed Linux/GCC and macOS/Clang in
[Actions 38797088304](https://github.com/k1moradi/RDP-server/actions/runs/38797088304),
but Windows/MSVC Debug failed the same CRLF case with a raw fixture-byte
mismatch (164/165 CTests passed). CMake `file(WRITE)` on that host
converts LF to CRLF; this test-only correction supplies LF to Windows
and explicit CRLF on POSIX, then verifies exact canonical CRLF bytes
with `file(READ HEX)`. Local Linux Debug/Release isolated harness
**25/25 PASS** each. Corrected Windows CI **NOT RUN at authoring**;
M1–M6 remain open, no production runtime security change.

**R10 exact-SHA cross-platform CI acceptance (2026-10-15):**
Corrected runtime test commit `853e572dafdeab18161afa3926db2f29d2ec3a34` passed
[Actions 38797522248](https://github.com/k1moradi/RDP-server/actions/runs/38797522248). Linux/GCC **170/170**,
Windows/MSVC **166/166**, and macOS/Clang **158/158** registered
CTests in EACH Debug and Release configuration. Downstream SDK
consumer **1/1** on all three platforms; install, ZIP/SHA256
packaging/artifact uploads and documentation-policy PASS. Protocol
SDK prerelease publication SKIPPED (no version tag). Windows CRLF
configuration fixture now passes in both configurations. This is
HOSTED CI evidence only: owner Linux/X11, Windows MSYS2 CLANG64
Clang 23 and macOS 27 independent CTests are NOT RUN; live RDP
identity, desktop, service, installer and M1–M6 milestone acceptance
remain OPEN. The executable remains non-installable and fail closed.

**Ownership discipline:** R3 alone owns the session and channel lifecycle;
R4 alone owns graphics scheduling; R8 alone owns clipboard generation;
R1 owns encrypted socket I/O; R2 owns admission decisions. R5/R6/R7
implement native OS adapters behind the same portable contracts.
Road-specific development may be offline and fixture-driven before
upstream dependencies exist, but an offline PASS cannot promote a live
end-to-end dependency to ACCEPTED. All cross-road API changes must have
an agreed owner and a minimal consumer-facing test.

### Six mandatory convergence milestones (M1–M6)

These are **integration checkpoints, not ten independent product
releases**. Existing detailed P0/P1 checkboxes and historical evidence
below remain the sole living implementation TODO; the roads specify
ownership and convergence, not a second checklist. For each milestone
record the exact same tested SHA, real environment, new CTest names,
PASS/FAIL/BLOCKED/NOT RUN and first failed boundary. Never claim a
Microsoft-client or live-OS acceptance from offline fixtures.

| Milestone | Required roads at convergence | Objective acceptance / exit criterion |
| --- | --- | --- |
| **M1 — Portable contracts and CI baseline** | R1–R10 contracts; R9 verification | All new code has its dedicated registered CTest; shared C++23 core + implemented native adapter test targets compile where supported. Same integration SHA has Linux, Windows CLANG64/Clang 23 and macOS 27 Debug/CTest owner results; existing GCC/MSVC/macOS Actions remain additional, **not substitute** coverage. Open external-client gates remain NOT RUN. |
| **M2 — Authenticated RDP activation** | R1 + R2 + R3 + R9 | A current real Microsoft client completes authorized TLS/NLA, OS identity admission, live MCS/channel joins, licensing/share activation and clean disconnect on the first isolated Linux test target. Reject bad identities/certs, downgrade, premature messages and unauthorized channels. No desktop claim yet. Windows/macOS code and CTests continue simultaneously. |
| **M3 — Linux/X11 human desktop** | M2 + R4 + R5 + R9 + minimal R10 launcher | Separately authorized human connects with a Microsoft client and sees real X11 desktop; mouse, keyboard, terminal typing/scrolling, menus, AVC420 surface updates, resize and disconnect/reconnect work. Unsupported AVC fails cleanly. R6/R7 do not wait for M3 to start coding or CTests. |
| **M4 — Windows human desktop** | Accepted shared core + R4 + R6 + R9 + R10 test launcher | Real authorized Microsoft-client interaction with the **Windows server** built/tested using MSYS2 CLANG64/Clang 23: identity/session, visible desktop, input, resize, reconnect and negative cases. Keep Linux regression coverage green. |
| **M5 — macOS human desktop and feature beta** | Accepted shared core + R4 + R7 + R8 + R9 | Real authorized Microsoft-client interaction with the **macOS 27 server**: identity, screen permissions/capture, input, resize/reconnect and negative cases; integrate and accept release-scope CLIPRDR text/image/file semantics on **each applicable OS** before calling feature beta complete. Linux/Windows automated regression stays green. |
| **M6 — Cross-platform production release** | R1–R10 accepted; R9 security + R10 operations signoff | Same release candidate passes all three specified platform CTest runs, each supported platform's human desktop/declared clipboard scope, realistic load/reconnect/soak, fuzz and supported sanitizers, security negatives, installation/upgrade/rollback, resource and performance budgets. Deploy only after explicit approval; no claim of all-platform readiness from SDK ZIPs or one OS's result. |

**Mapping of older acceptance terminology:** existing P0 annotations
labeled *Gate A* feed M2; *Gate B* feeds M3–M5; *Gate C* feeds the
human desktop acceptance in M3–M5; *Gate D* feeds M6; earlier
*Gate E* expansion is covered by R8 and M5/M6 as applicable. These
labels are historical references, **not additional milestones**.
Linux/X11 is merely the first human trial; Windows and macOS OS-server
implementation, dedicated CTests and toolchain validation begin now.
Codec expansion, Wayland and further OS support remain separately scoped,
not prerequisites for the defined three-platform release.

### Agent integration and the owner's independent platform test

**GitHub main-only development — publish working code, not patches:**
**All development and commits must occur on existing `main`; creating
ANY other Git branch (local, remote, temporary, feature, hotfix, release,
experimental, agent-specific or branch-backed worktree) is prohibited.**
Each of R1–R10 is expected to **complete and directly commit its own
implementation, newly registered dedicated CTest(s), and updated existing
roadmap/documentation together to GitHub `main`**. No agent should
conclude ordinary work by handing over a patch or asking R10 to push on
its behalf. R10 handles cross-road integration and CI triage, not
gatekeeping the publication of independent, safely prepared changes.

**Concurrency control uses GitHub's current HEAD, not manual waiting
for an exclusive publication slot.** Immediately before publishing,
fetch `main` HEAD and the actual versions of affected source, CMake,
test registry and roadmap files. Construct one complete atomic commit on
the latest HEAD and publish it through a **non-force fast-forward update
that checks the expected old HEAD SHA**. Only one concurrent update can
succeed against a given expected HEAD. If another agent won the race,
re-read `main`, reconcile/merge the intended changes into the newer
files (especially `tests/CMakeLists.txt` and `docs/ROADMAP.md`),
repeat relevant validation if available, and retry. Never force-update
a ref, blind-reset, lose another road's edits, publish stale whole-file
replacements, create a branch or split code/test/docs across separate
misleading commits. Do not mark work complete until its direct-to-main
commit SHA is verified. Report BLOCKED only for an actual non-resolvable
conflict, lack of write permissions or comparable technical obstruction,
and report exact evidence. The absence of an R10 publication slot is
**not** such a blocker. Each isolated local checkout retains its one
`build/` root; the owner's three computers each maintain their own.

**Dedicated test contract:** every source/header/runtime/build behavior
change is paired with at least one **new distinct behavior-named CTest**
registered in the central registry, normally as a case of an existing
executable. Cover new functionality with positive and fail-closed
cases, and preserve all prior registered cases. Documentation-only
planning edits do not assert execution or require a new production-code
CTest. GitHub Actions compiles/tests every published integration; report
the actual jobs and exact SHA, not an assumed pass. The owner's terminal
runs are separate authoritative environment evidence; agents must not
record them as PASS until the owner reports the results.

**Owner's normal platform test — direct from current `main`:**
On each platform, the owner opens a terminal in the required compiler
environment and runs the **exact unchanged one-liner** below after an
agent's commit reaches GitHub. This is the required everyday
development-feedback workflow; agents must publish testable code and
registered dedicated CTests before asking for owner verification.
No patch application, cherry-pick, manual integration, alternate branch,
special test flags, additional build root or live service is required.

```sh
cd ~/rdp-server && git switch main && git pull --ff-only origin main && cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON && cmake --build build --config Debug --parallel 2 && ctest --test-dir build -C Debug --output-on-failure
```

**Agents are responsible for making this command pass** on supported
platforms, including adding their dedicated, deterministic and
noninteractive CTests to the existing registry. Failures reported by
the owner must be diagnosed and corrected with another direct-to-main
code+CTest+docs commit. This procedure tests the locally checked-out
`main` commit even if GitHub `main` advances subsequently. For a
same-SHA three-platform milestone, record `git rev-parse HEAD` for each
Linux/X11, Windows MSYS2 CLANG64/Clang 23 and macOS 27 test report;
if the SHAs differ, repeat affected platform runs against a common
nominated HEAD before declaring the convergence gate. Do **not**
automatically block everyday development commits pending human reports
or a coordinator-managed freeze. If the owner explicitly requests a
temporary same-SHA checkpoint freeze, honor it while in effect.
Report CMake-selected compiler and CTest counts, not assumed platform
success; a cached Windows CMake configuration may select a compiler
other than the expected Clang 23. Native-only tests are conditional, and
skipped/unavailable tests are NOT RUN rather than PASS.

The terminal one-liner authorizes ordinary compilation and noninteractive
CTest only; genuine RDP client login, native desktop capture/input,
real clipboard transfers and service modifications remain separately
authorized acceptance tests. The owner is responsible only for running
the three commands and reporting PASS/FAIL, not writing CTests, resolving
agents' Git conflicts, applying patches or doing integration.

## Acceptance policy

- Every production-code increment has at least one **new dedicated,
  behavior-named CTest** exercising the changed functionality and
  registered in the **one** existing `tests/CMakeLists.txt` registry.
  Reuse shared executables/fixtures; preserve previous tests. Tests for
  OS-specific code run on the applicable native platform and report
  NOT RUN elsewhere. Owner reports from the same exact integration SHA
  are needed for the three-platform test checkpoint.
- Offline CTest and static library compilation are foundation gates.
- Native protocol integration, TLS/NLA security, external clients, graphics,
  input, clipboard, session admission, OS backends and real desktop access
  are **not yet accepted**; never infer them from a green unit test.
- **All development and commits must target existing `main`. Creating
  any new Git branch is prohibited for everyone, including agents,
  contributors and automation.** No feature, hotfix, release, temporary,
  local/remote or branch-backed worktree branches; no exceptions under the
  current project policy. Publish to `main` only with a verified
  single-writer slot and non-force fast-forward update; never during
  the owner's exact-SHA platform-validation freeze.
- Preserve attributions and third-party licenses for upstream-inspired code,
  but do not depend on an xrdp daemon, patched chansrv or VNC runtime.
- Target **practical interoperability with current Microsoft RDP clients**,
  not an official Microsoft certification claim. The first graphics milestone
  deliberately supports only negotiated H.264 for encoded bitmaps; it does
  not claim full MS-RDPEGFX implementation conformance, which specifies
  ClearCodec support. Reject sessions lacking compatible AVC capabilities
  cleanly instead of sending an unnegotiated format or claiming success.

## Living TODO — authoritative project checklist

This is the **single current TODO list**, required context on **every
prompt**. Update the *same* item when implementation, blocker or evidence
changes; don't create another milestone list. Apply [VISION](VISION.md)
and the four mandatory [coding](coding_standards.md),
[testing](testing_standards.md), [build](compile.md) and
[benchmark](benchmark.md) standards. Checkboxes require measured
acceptance evidence; no synthetic completion claims.

**Execution priority (2026-10-15; parallelized):** maintain the existing
P0/P1 implementation checkboxes as **one authoritative TODO**, but
assign their implementation to R1–R10 above. A/B/C protocol
dependencies converge at M2 while R4/R5/R6/R7/R8 develop and register
their dedicated CTests concurrently. Linux/X11, Windows MSYS2 CLANG64
(Clang 23) and macOS 27 all receive parallel development/automated
verification; their separately authorized *human* acceptance is staged
at M3/M4/M5. Road R10 serializes main commits and freezes nominated
test SHAs while the owner runs three terminal checks. Keep prior
per-commit evidence intact and add real-client transcripts only when
actually run; another parser CTest alone is not a complete session.

### P0 — Preserve work and implement a native RDP server

- [x] Independently compile/test C++23 static protocol foundation;
  historical Actions run 38516048776 succeeded at 77c94c75b467.
  This **is not** a working RDP desktop server.
- [x] Retire the obsolete legacy-source migration guide and both import
  scripts by owner request. The original project was **not fully
  imported**; only the maintained, checked-in first-party code is in
  scope for ongoing development. Additional historical source requires
  a separately authorized and reviewed integration, not an automatic
  import. This is a cleanup gate, not a functional RDP milestone.
- [ ] Implement bounded X.224/TPKT/MCS/GCC network listener and complete
  standards-compliant server connection state machine with external-client
  handshake and malformed-packet evidence.
  **Gate A integration acceptance (NOT RUN):** bind the existing
  preauthentication parser and TLS transport to a real first-party
  listener and one connection owner. Prove a current Microsoft client
  receives correct live MCS/GCC responses and advances through the
  authenticated channel/share lifecycle; the loopback TLS intake
  diagnostic by itself remains insufficient.

  **R1 native accepted-socket implementation (2026-10-15; new-code CI pending):**
  Extend the ONLY existing native TCP adapter with a one-shot nonblocking
  accept operation returning a move-only, RAII-owned connection handle;
  the caller retains its listening socket. Linux uses atomic
  `accept4(SOCK_NONBLOCK | SOCK_CLOEXEC)`; macOS/BSD apply checked
  nonblocking/close-on-exec/SO_NOSIGPIPE configuration; Winsock applies
  nonblocking and non-inheritable handle setup. Failed configuration
  closes only the just-accepted socket. No new TLS/session controller,
  daemon, bound/listening production port, admission, or MCS response.
  Three dedicated CTests: `transport.tcp-native-accept-ownership`,
  `transport.tcp-native-accept-move-replacement` and
  `transport.tcp-native-accept-orderly-eof` reuse real loopback fixtures
  for X.224 negotiation, invalid listeners, would-block, move replacement,
  FIN after queued data, EOF, and idempotent cancellation without closing
  the borrowed listener. Expected registry: 104 portable / 114 Linux GSS
  (prior 101/111).
  Owner separately reports 101/101 existing tests PASS; exact local SHA
  and platform were not supplied, and this new CTest was not included.
  Integration parent main: `96dbdc660cc9814d086cfb3c7772850474b8f2fd`.
  **PASS:** isolated Linux GCC 14.2 / Clang 17 C++23 warning-clean,
  ASan+UBSan accept/ownership/EOF smoke (native `accept4` and simulated
  portable POSIX fallback). **NOT RUN:** full checkout build, registered
  dedicated CTests, owner Windows CLANG64/macOS27 and new-code CI at
  authoring time. Commit directly to `main` under optimistic HEAD check. First boundary remains a
  production listener/event loop feeding this accept into the one
  owned TCP/TLS session, followed by R2/R3 authenticated activation.


  **R1 accepted-socket TLS/BIO lifetime increment (2026-10-15;
  integration parent `a7234f40c4e2188b1170daf363136a6ac159c025`; exact new-code CI pending):**
  `OwnedPreauthTcpConnection` is one nonmoving, single-event-loop owner
  of the accepted native socket, existing `NativeTcpIo` /
  `PreauthTcpAdapter` and transferred server `SSL` and its borrowed BIO.
  It forwards X.224/TLS/MCS diagnostic readiness to the existing
  protocol stages; on cancellation, errors or diagnostic completion it
  clears preauth, frees SSL/BIO and only then closes the accepted socket.
  The listener is never owned. Two new registered CTests:
  `transport.tcp-owned-connection-tls-lifecycle` drives native
  loopback through X.224 Confirm, negotiated TLS and encrypted first
  MCS/GCC intake; `transport.tcp-owned-connection-cancellation`
  covers invalid handles, partial X.224, cancel before ClientHello,
  idempotence and listener preservation. No new session state controller,
  production listener, authentication or OS session access.
  **NOT RUN at authoring:** dedicated/full repository CTest, hosted
  new-code CI and owner's three platform toolchains; isolated previous
  R1 socket accept/EOF sanitizer checks PASS. Next: bounded readiness
  polling/cancellation and R2/R3 authorized lifecycle integration.

  **R1 published exact-SHA CI receipt (2026-10-15):**
  [implementation `50a53e6d1ab07ab787c0ef5e62c91e068ba3ffcb`](https://github.com/k1moradi/RDP-server/commit/50a53e6d1ab07ab787c0ef5e62c91e068ba3ffcb)
  and [Actions run 38796272916](https://github.com/k1moradi/RDP-server/actions/runs/38796272916).
  **PASS:** both dedicated R1 CTests in hosted Linux/GCC Debug+Release
  (**159/159** each), macOS/Clang Debug+Release (**148/148** each), and
  Windows/MSVC Debug (**both R1 cases passed**). Documentation-policy PASS.
  **FAIL:** hosted Windows full Debug CTest **155/156**; ONLY unrelated
  R10 `runtime.validates-configuration-comments-crlf` returns exit
  3 instead of 0, tracked in
  [R10 Issue #9](https://github.com/k1moradi/RDP-server/issues/9).
  Windows Release **NOT RUN** due to failing Debug. Owner Linux/X11,
  Windows MSYS2 CLANG64/Clang23 and macOS27 exact-SHA tests **NOT RUN**;
  R2 credential authorization and R3 authenticated activation NOT ACCEPTED.
  Next R1 boundary: bounded readiness scheduling and deterministic timeout
  release around the owned native TCP/TLS connection.


  **R1 bounded readiness dispatch and monotonic cancellation increment
  (2026-10-15; parent `db62ec72f84c5b83adbedd72a2606b4db9470ec7`; exact new-code CI pending):**
  Extend the EXISTING nonmoving `OwnedPreauthTcpConnection` with
  `ioInterest()` and `onSocketReady(readable,writable)` that derive the
  next read/write event from its one `PreauthConnectionStream` stage,
  pending X.224 response and active OpenSSL `SSL_want_write` (including
  post-handshake MCS reads). Dispatch at most ONE previously bounded
  native preauth, TLS or diagnostic-MCS callback per matching event,
  and ignore empty, wrong-direction, pre-TLS and stale events without
  opening a socket or spinning. A caller-provided steady-clock
  `cancelIfExpired(now,deadline)` releases SSL/BIO before native socket;
  a short-lived `const SSL*` borrow is available only after actual TLS
  establishment, NOT an authenticated identity decision.
  New dedicated behavior CTests
  `transport.tcp-owned-readiness-dispatch` and
  `transport.tcp-owned-deadline-cancellation` reuse the existing test
  executable and native 127.0.0.1:0 loopback; exercise split plaintext,
  no premature TLS, full Confirm/failure-response delivery, real TLS
  and encrypted MCS, wrong/stale readiness, deterministic deadline
  expiration and listener preservation. No new poller, protocol state
  authority, listener manager, TLS credential policy, R2 admission or
  R3 session. **NOT RUN at authorship:** new code CMake/full CTest,
  new exact-commit GitHub Actions and owner's Linux/X11, Windows
  CLANG64 Clang23 or macOS27 toolchains (clone DNS unavailable in
  worker). Previous R1 integration Linux GCC/macOS Clang suites and
  Windows R1-specific cases PASS at `50a53e6d1ab07ab787c0ef5e62c91e068ba3ffcb`.
  The current Windows full CTest still reports a separate R10 CRLF
  configuration test FAIL (Issue #9). Next R1: hand readiness and a
  bounded listener accept budget to R10's already authorized runtime
  without bypassing the R2/R3 security gates.

  **R1 direct-to-main readiness repair (2026-10-15; parent
  `d556c2f7ce93b5f46a52fce8ddfd2cf4b2e25eb4`):** Initial new-code [Actions run
  38798562218](https://github.com/k1moradi/RDP-server/actions/runs/38798562218)
  exposed two R1 CTest failures on Linux: dispatcher picked
  `ConfigureTls` after the Connection Request advanced to `AwaitTls`
  but its 19-byte Confirm was still queued. The same precedence applies
  to a permitted failure reply after rejection. Fix `ioInterest` and
  `onSocketReady` to prioritize any pending X.224 reply suffix
  regardless of diagnostic stage, then dispatch through the existing
  bounded `onWritable` until fully sent before TLS or terminal close.
  Add dedicated `transport.tcp-owned-reply-interest-priority` CTest
  for both successful Confirm and rejected NEG_FAILURE, wrong-direction
  wakeups, exact bytes and listener preservation. **FAIL** initial
  new-code Linux focused/full CTest; corrected code exact-SHA CI
  **NOT RUN** at authoring. This is a test-detected R1 production fix,
  not an authentication success. No second stage owner or event loop.

  **R1 portable nonblocking readiness-fixture repair (2026-10-15;
  parent `3b22e8fa018d093339f4d1f5e7c44fe90ef7b4f3`):** Exact repair-SHA [Actions
  38799213949](https://github.com/k1moradi/RDP-server/actions/runs/38799213949)
  verified **PASS Linux 176/176 Debug+Release** and
  **PASS Windows full Debug+Release**, including all three new R1
  behavior CTests. macOS Debug **164/164 PASS**; macOS Release
  **163/164 FAIL** only
  `transport.tcp-owned-deadline-cancellation`: its new test fixture
  incorrectly assumed one nonblocking receive always collects a full
  X.224 request immediately after the client's send. The actual
  transport can validly return `Read` for partial bytes on any OS.
  Repair test-only synchronization with a bounded 2,048-step retry,
  never a production poller or relaxed protocol assertion; reuse this
  helper in readiness/denial/deadline tests. Corrected exact-SHA CI
  **NOT RUN** at authoring. Owner Windows CLANG64/macOS27 tests
  **NOT RUN**. No production behavior, privilege or admission change.

  **R1 exact-SHA readiness/reply/expiration CI receipt (2026-10-15)**:
  [production increment `209ebb6fa714b4bba61478539976719506b9b96d`](https://github.com/k1moradi/RDP-server/commit/209ebb6fa714b4bba61478539976719506b9b96d),
  [reply-priority production repair `0dfc33871c8b140e07e9028d7c4fc4cb12e83fb0`](https://github.com/k1moradi/RDP-server/commit/0dfc33871c8b140e07e9028d7c4fc4cb12e83fb0),
  and [bounded nonblocking fixture repair `9f3bcd369d0544c2f85aaf0964b31f912aba7bf5`](https://github.com/k1moradi/RDP-server/commit/9f3bcd369d0544c2f85aaf0964b31f912aba7bf5).
  [Exact final R1 CTest run 38799804260](https://github.com/k1moradi/RDP-server/actions/runs/38799804260):
  **PASS** Linux/GCC **183/183 Debug and 183/183 Release**,
  Windows/MSVC **180/180 Debug and 180/180 Release**, three R1
  readiness/reply/deadline dedicated cases on both platforms in both
  configurations, documentation-policy and installed SDK consumers.
  **BLOCKED/FAIL** macOS AppleClang Debug CTest not reached:
  unrelated R7 `test_macos_capture_pixel_buffer` link has missing
  `_kCFAllocatorDefault` (CoreFoundation), reported at
  [R7 Issue #7](https://github.com/k1moradi/RDP-server/issues/7).
  macOS Debug CTest and Release build/CTest **NOT RUN** for this SHA.
  Owner Linux/X11, Windows CLANG64 Clang23 and macOS27 exact-SHA
  checks **NOT RUN**; R2 admission/R3 session/client desktop gates
  **NOT ACCEPTED**. Next R1: bounded actual readiness polling/listener
  budget integration with R10 under authenticated R2/R3 interfaces.


  **R1 bounded one-connection native polling integration
  (2026-10-15; integration parent `84d55d00f4c49772ddaad524d078ade198cf5f03`; exact new-code CI pending):**
  Extend the ONLY `OwnedPreauthTcpConnection` with one
  `pollSocketOnce(deadline,maxWait)` using platform POSIX `poll` or
  Winsock `WSAPoll`. Each call polls precisely one owned accepted socket
  for the existing `ioInterest` direction, for at most **25ms**, then
  forwards a single bounded `onSocketReady` callback. Unready, EINTR,
  pending TLS configuration, expired deadlines, socket error/hangup
  and already-closed owners are explicit; no hidden OS blocking I/O
  loops, socket duplicate, poll thread, service port, listener manager,
  TLS certificate policy or new RDP authority. Deadline cancellations
  continue to free SSL/BIO before the accepted socket; the separately
  borrowed listener remains unaffected. Two new dedicated portable
  CTests `transport.tcp-owned-bounded-poll-loopback-tls` and
  `transport.tcp-owned-bounded-poll-timeout-eof` use real ephemeral
  loopback acceptance, partial X.224, exact Confirm, actual selected
  SSL/TLS handshake and encrypted MCS termination, zero/oversized wait,
  expired time and mid-request peer EOF. Expected +2 registered tests
  relative to current main; **NOT RUN** new focused/full CTest at
  authoring (worker has no GitHub-clonable checkout).
  **PASS** earlier main CI baseline Linux/Windows/macOS and documentation
  at `991320318e681fba99ca85adf1d29039c3e3137c`
  ([Actions 38801211658](https://github.com/k1moradi/RDP-server/actions/runs/38801211658)).
  **NOT RUN:** exact new-SHA CI, owner Linux/X11, Windows MSYS2 CLANG64
  Clang23 and macOS27, live Microsoft client and R2/R3 authenticated
  session. Next gate: R10 runtime callback wiring to bounded listener
  acceptance with R2 identity/R3 session trust decisions preserved.

  **R1 exact-commit native polling acceptance receipt (2026-10-15):**
  [commit `fb63d6c41734e3d8a5d14f35237bacee90fd72ba`](https://github.com/k1moradi/RDP-server/commit/fb63d6c41734e3d8a5d14f35237bacee90fd72ba);
  [GitHub Actions 38844140123](https://github.com/k1moradi/RDP-server/actions/runs/38844140123)
  completed **SUCCESS** at that exact source SHA.
  **PASS:** Linux/GCC **194/194** Debug and **194/194** Release;
  macOS/AppleClang **181/181** Debug and **181/181** Release;
  Windows/MSVC **185/185** Debug and **185/185** Release.
  Both new ordinary transport CTests
  `transport.tcp-owned-bounded-poll-loopback-tls` and
  `transport.tcp-owned-bounded-poll-timeout-eof` PASS on all three
  hosted platforms in both configurations. Project documentation,
  installed SDK downstream consumer CTest, and SDK ZIP artifacts PASS;
  prerelease SKIPPED without a release tag.
  **NOT RUN:** owner's exact-SHA Linux/X11, Windows MSYS2
  CLANG64/Clang23, macOS 27 tests; real client, live OS authorization,
  R2 credential acceptance, R3 session and graphical desktop.
  Next: R10 single listener/poller activation remains outside R1 and
  requires independent authorization; no full M2 acceptance is implied.


  **R1 bounded listener-accept budget and sole owner handoff
  (2026-10-15; parent `0914dba9cab11eb6bee928915cad1d7da5435fef`, exact-code CI pending):**
  Add `acceptNonblockingTcpBatch` to the EXISTING first-party native
  transport module. It borrows a caller-owned already-listening and
  nonblocking native descriptor; a caller-selected batch budget must
  be in **1..16** and is strictly enforced. The function reuses ONLY
  `acceptNonblockingTcpConnection` and transfers each RAII-owned
  nonblocking socket exactly once to a no-throw callback that may
  immediately wrap it in `OwnedPreauthTcpConnection`. Callback
  refusal stops after transfer; even unadopted sockets close by RAII.
  Distinguish malformed arguments, initial would-block, drained
  backlog, exhausted budget, callback-stop and hard native failures.
  No socket array allocation, extra event loop, bind/listen call,
  idle blocking, producer queue, session owner or OS privilege.
  Dedicated `transport.tcp-native-accept-batch-budget-handoff`
  verifies three sequential real loopback clients (no platform
  backlog-depth assumption), exact one/two-accept budget-limited
  delivery, true X.224 Confirm using the sole accepted owner, and
  intact listener. `transport.tcp-native-accept-batch-stops-denials`
  covers zero/excessive budget, null sink, invalid descriptor,
  non-listener socket, callback refusal/RAII closure and partial
  drain after progress. Both reuse the original preauth executable
  and central CTest list. **NOT RUN at authorship:** fresh source
  compilation/new CTest/full suite because this worker lacks a
  network-clonable checkout; new exact SHA hosted CI pending.
  **Prior current-main baseline PASS:** run
  [38801211658](https://github.com/k1moradi/RDP-server/actions/runs/38801211658)
  and later concurrent runs. Owner Linux/X11, Windows CLANG64 Clang23
  and macOS27 **NOT RUN**. Next R1: R10 runtime selects event-loop
  fairness and process-owned listener policy; never let an offline
  X.224/TLS diagnostic bypass R2 authentication and R3 session gates.

  **R1 Windows bounded native batch CTest watchdog (2026-10-15; parent
  `927b34591d7cac9506d132ad844c2185fa419efa`):** New batch-accept R1 cases PASS on Linux/macOS
  hosted CI at `c3b10eecf9f76d550d09f6601c3095130ff94b95`
  (Linux 210/210, macOS 195/195 Debug+Release). Windows Debug
  remains IN PROGRESS on initial and backlog-independent fixture
  runs, with no named test result yet; do not claim WIN PASS/FAIL.
  Add per-test CTest `TIMEOUT 20` for the two new R1 batch cases to
  expose platform-dependent stalls with a named failure, without
  changing implementation, test expectations or socket ownership.
  The corrected fixture commit `16ec8326ef2be45d56f2e87e49f907635a314eb8`
  has its two new R1 cases PASS Linux/macOS Debug, but full Linux
  215/216 and macOS 200/201 FAIL the separately owned R7
  `macos.geometry-native-mixed-scale-denials` assertion at line 552,
  tracked in [Issue #12](https://github.com/k1moradi/RDP-server/issues/12).
  Corrected watchdog CI **NOT RUN** at authorship. Owner-local
  Linux/X11, MSYS2 CLANG64 Clang23 and macOS27 **NOT RUN**.

  **R1 bounded accept-batch cross-platform full CI receipt (2026-10-15)**:
  [production commit `c3b10eecf9f76d550d09f6601c3095130ff94b95`](https://github.com/k1moradi/RDP-server/commit/c3b10eecf9f76d550d09f6601c3095130ff94b95),
  [backlog-independent fixture `16ec8326ef2be45d56f2e87e49f907635a314eb8`](https://github.com/k1moradi/RDP-server/commit/16ec8326ef2be45d56f2e87e49f907635a314eb8),
  and [bounded test watchdog `2d03a9bd0bebf7697231322c07d0fa594ef6b0d1`](https://github.com/k1moradi/RDP-server/commit/2d03a9bd0bebf7697231322c07d0fa594ef6b0d1).
  The [exact source CI run 38849575634](https://github.com/k1moradi/RDP-server/actions/runs/38849575634)
  completed **SUCCESS**, with hosted Linux/GCC full
  **218/218 Debug and 218/218 Release**, macOS/AppleClang full
  **202/202 Debug and 202/202 Release**, and Windows/MSVC full
  **220/220 Debug and 220/220 Release** CTests.
  BOTH new R1 native batch CTests PASS in every platform/build type.
  Documentation-policy, R9 clipboard-sanitizer, installed SDK
  consumer and ZIP/SHA-256 artifact jobs PASS; prerelease SKIPPED
  without a tag. All listener bind/service activation, R2 identity
  and OS authorization, R3 admitted session, live Microsoft RDP
  client/desktop and owner's Linux/X11, MSYS2 CLANG64 Clang23,
  macOS27 exact-SHA commands remain **NOT RUN**.
  Next R1: integrate the bounded accept callback into R10's
  eventual production listener fairness without introducing a
  second session controller or bypassing authenticated gates.

  **R1 borrowed native listener readiness gate (2026-10-15;
  integration parent `a0c39e4a612c740949c05e4a9699f711061c21d0`; exact new-code hosted CI pending at authoring; restored
  baseline CI PASS):**
  `pollNonblockingTcpAcceptBatch` performs exactly ONE bounded
  0..25ms readiness wait on the caller's existing nonblocking listener
  (POSIX `poll(POLLIN)`; Windows Winsock `select(readfds)` for
  compatible listening-socket semantics), then delegates at most ONE
  caller-budgeted batch to the already sole `acceptNonblockingTcpBatch`.
  It validates the 1..16 budget and callback BEFORE touching any socket;
  honors a caller-owned monotonic deadline; never consumes pending
  clients when expired, never owns/closes the listener, never retries
  silently on EINTR, and never creates another connection queue,
  background thread, listener or RDP state authority.
  New `transport.tcp-listener-poll-budget-handoff` CTest validates
  real ephemeral loopback listener readiness, exact X.224 Confirm via
  `OwnedPreauthTcpConnection`, no-event idle, and one-connection
  post-progress drain without a two-deep backlog assumption.
  `transport.tcp-listener-poll-deadline-denials` verifies input
  rejection, expired pending connection preservation, callback
  refusal/RAII close, clamped excessive wait and error from a closed
  borrowed listener. Both in existing central CTest registry, with
  20s per-case timeout; no live server/admission.
  **PASS (prior implementation):** `2d03a9bd0bebf7697231322c07d0fa594ef6b0d1`
  hosted Linux/GCC 218/218, macOS/Clang 202/202 and Windows/MSVC
  220/220 Debug+Release CTests (Actions 38849575634).
  **NOT RUN:** new-code CTest/full suite in this agent environment
  (no local GitHub-clonable checkout), exact new-SHA CI (prior workflow parse issue #13
  corrected before this publication; baseline Actions 38850747646
  at `a0c39e4a612c740949c05e4a9699f711061c21d0` SUCCESS), owner's Linux/X11/Windows CLANG64/macOS27 commands,
  authenticated R2/R3 handoff and live Microsoft client.
  **Next:** R10 integrate listener readiness into its process scheduler,
  keeping R2 identity and independent OS authorization and R3
  authoritative channel/session progression separate.

  **R1 native listener readiness exact-commit CI receipt (2026-10-15)**:
  [implementation `1fb4d48e3f9a1133587d634d08ec69c5d5c19e03`](https://github.com/k1moradi/RDP-server/commit/1fb4d48e3f9a1133587d634d08ec69c5d5c19e03),
  [Actions run 38851057291](https://github.com/k1moradi/RDP-server/actions/runs/38851057291)
  **SUCCESS at that exact source SHA**. Linux/GCC **228/228**
  Debug and **228/228** Release CTests; macOS/AppleClang
  **211/211** Debug and **211/211** Release; Windows/MSVC
  **230/230** Debug and **230/230** Release. BOTH new
  `transport.tcp-listener-poll-budget-handoff` and
  `transport.tcp-listener-poll-deadline-denials` CTests
  **PASS in all six hosted builds**. Documentation-policy,
  R9 protocol-sanitizer and installed SDK consumer jobs
  PASS; tagged prerelease SKIPPED because no tag.
  **Owner-local Linux/X11, MSYS2 CLANG64 Clang23, macOS27,
  live Microsoft RDP client, R2 authentication, independent
  OS authorization and R3 MCS/share/session remain NOT RUN**.
  Runtime port binding and listener scheduling remain R10-owned.

  **R1 older accept-batch test nonblocking readiness repair
  (2026-10-15; integration parent `464211b1da48ce80e09e27904addce7bb40137b2`):**
  The source-only implementation `1fb4d48e3f9a1133587d634d08ec69c5d5c19e03`
  [Actions 38851057291](https://github.com/k1moradi/RDP-server/actions/runs/38851057291)
  **PASS Linux 228/228, macOS 211/211, Windows 230/230**
  Debug+Release. Its documentation-only follow-up
  `464211b1da48ce80e09e27904addce7bb40137b2`
  [Actions 38851395036](https://github.com/k1moradi/RDP-server/actions/runs/38851395036)
  exposed an intermittent **FAIL macOS Debug** in the older
  `transport.tcp-native-accept-batch-stops-denials` CTest:
  `drained.outcome == Drained` at the fixture's test line 2582.
  That test assumed a just-connected loopback client was already
  visible to the nonblocking listener. It now uses a bounded
  128-step/25ms listener-ready wait through the new R1 API before
  asserting the same **Drained**, exactly one accepted handle,
  callback execution and untouched listener. Production code is
  unchanged; no negative assertion is suppressed. **NOT RUN at
  authoring:** corrected fixture exact-SHA full CI and the owner's
  three platform toolchains. Next: confirm the full hosted matrix
  including the previously intermittent macOS Debug case.

  **R1 listener-readiness corrected full-CI receipt (2026-10-15)**:
  Initial native listener-poll implementation
  [`1fb4d48e3f9a1133587d634d08ec69c5d5c19e03`](https://github.com/k1moradi/RDP-server/commit/1fb4d48e3f9a1133587d634d08ec69c5d5c19e03)
  PASS full hosted Debug+Release. Its documentation-only follow-up
  exposed one sporadic macOS Debug failure in an older R1 batch
  test that assumed an immediate native accept after client connect.
  The test-only [`66077dd20222f6f50466b2937f90e25d500a13f1`](https://github.com/k1moradi/RDP-server/commit/66077dd20222f6f50466b2937f90e25d500a13f1)
  waits boundedly for the same borrowed listener to become readable
  through the new R1 polling API; `Drained`, one accepted connection,
  callback and independent listener assertions are unchanged.
  [Exact corrected commit Actions 38851653835](https://github.com/k1moradi/RDP-server/actions/runs/38851653835)
  **SUCCESS**: Linux/GCC **228/228 Debug+Release**,
  macOS/AppleClang **211/211 Debug+Release**, Windows/MSVC
  **230/230 Debug+Release**. All new R1 poll tests AND the
  previously intermittent accept-batch test PASS in all six
  configurations; documentation-policy, security-protocol
  sanitizers and installed SDK downstream checks PASS.
  **NOT RUN** owner's Linux/X11, Windows MSYS2 CLANG64
  Clang23, macOS27 exact-SHA commands or live Microsoft client,
  R2 authenticated OS identity/admission, and R3 channel/desktop
  activation. Next: R10 bounded runtime listener integration
  after the independent security and session gates.


  **R1 listener role/nonblocking configuration guard (2026-10-15;
  parent `ea1cf468986b15bcc4ee0b43b70082cfc0862e82`; corrected exact-code CI pending):**
  Fail closed on an actual native TCP socket that is NOT listening
  using POSIX/Winsock `getsockopt(SO_ACCEPTCONN)` in the one-shot
  acceptor and pre-poll borrowed listener gate. POSIX additionally
  rejects a listener without `fcntl(F_GETFL) & O_NONBLOCK`
  BEFORE a possibly blocking `accept`. The batch inherits the
  single acceptor's validation. Winsock cannot query `FIONBIO`
  non-mutatingly, so R10/runtime MUST still set nonblocking mode.
  No changes to caller-owned listener flags, queue, service or
  user admission. New registered 20s-watchdog CTest
  `transport.tcp-native-listener-role-and-mode-denials`: all-platform
  connected non-listener denials in one-shot/batch/poll; POSIX
  queued-peer blocking-listener fail-closed and restored modes;
  exactly one successful existing-owner handoff afterward.
  **NOT RUN at authoring:** new full CTest/exact source-SHA CI,
  owner Linux/X11, MSYS2 CLANG64/Clang23 and macOS27 tests,
  live RDP service/R2/R3 authorized session or Microsoft client.
  Next: R10's gated live listener scheduling using the sole
  R1 transport owner without creating competing state authority.

  **R1 Darwin listener socket-option compatibility correction (2026-10-15):
  Initial production commit `6d5422f82dc9e644e8fa058e30e22deedb76bd84`
  [Actions 38857085837](https://github.com/k1moradi/RDP-server/actions/runs/38857085837)
  **PASS** Linux/GCC and Windows/MSVC hosted CI, docs and R9 sanitizers,
  but **FAIL macOS Debug** with 15 native transport tests rejecting
  configured listeners. macOS defines `SO_ACCEPTCONN` but does not
  support its use with `getsockopt` (`ENOPROTOOPT`). Instead check
  supported `SO_TYPE=SOCK_STREAM`, exclude already-connected sockets
  through `getpeername`, and let the existing NONBLOCKING native
  accept reject other unlistening streams. Retain Linux/Windows
  `SO_ACCEPTCONN` and all POSIX `O_NONBLOCK` checks; no mutation
  of borrowed listener state. Add dedicated 20s-watchdog
  `transport.tcp-native-wrong-socket-type-denials` CTest for
  UDP rejection by one-shot/batch/poll and positive queued TCP
  recovery, with the same single owner. **NOT RUN at authorship:**
  corrected exact-SHA CI, owner Linux/X11, Windows CLANG64/Clang23,
  macOS27, real R2/R3 identity/session/desktop acceptance.
  Next: verify all hosted Debug+Release platforms before R10
  runtime listener integration.**

  **R1 Darwin listener-role corrected exact-SHA CI receipt (2026-10-15):**
  Original guard [`6d5422f82dc9e644e8fa058e30e22deedb76bd84`](https://github.com/k1moradi/RDP-server/commit/6d5422f82dc9e644e8fa058e30e22deedb76bd84)
  exposed **FAIL** macOS Debug (15 accepted-socket tests) because Darwin
  rejects `getsockopt(SO_ACCEPTCONN)` even though the macro is defined.
  [Corrected implementation `c78a745aaa5180007a00a35a2858072974c2ad17`](https://github.com/k1moradi/RDP-server/commit/c78a745aaa5180007a00a35a2858072974c2ad17)
  in [exact Actions 38857769789](https://github.com/k1moradi/RDP-server/actions/runs/38857769789):
  **PASS Linux/GCC 252/252 Debug and Release**,
  **PASS macOS/AppleClang 234/234 Debug and Release**;
  both new `transport.tcp-native-listener-role-and-mode-denials` and
  `transport.tcp-native-wrong-socket-type-denials` CTests PASS in
  Windows/MSVC Debug as well. **FAIL Windows full Debug 250/251**:
  only R10-owned `runtime.validates-tls-files-private-regular`
  returned exit 3 instead of 0, tracked in
  [R10 Issue #14](https://github.com/k1moradi/RDP-server/issues/14);
  **Windows Release NOT RUN** due Debug failure.
  Documentation-policy, R9 protocol sanitizers and installed SDK
  consumer checks PASS where run. Owner-local Linux/X11,
  Windows MSYS2 CLANG64 Clang23, macOS27 and live Microsoft
  client, R2 authenticated identity/OS admission and R3 session
  gates **NOT RUN**. Continue R10 listener/runtime integration
  separately without duplicating R1 connection state authority.

  **R1 Darwin listener guard final all-host CI receipt (2026-10-15):**
  Darwin compatibility repair [`c78a745aaa5180007a00a35a2858072974c2ad17`](https://github.com/k1moradi/RDP-server/commit/c78a745aaa5180007a00a35a2858072974c2ad17),
  carried into docs/report SHA [`01a9dd001dc8111668635511208a0a6a93bff622`](https://github.com/k1moradi/RDP-server/commit/01a9dd001dc8111668635511208a0a6a93bff622).
  [Exact source GitHub Actions 38858078854](https://github.com/k1moradi/RDP-server/actions/runs/38858078854)
  **SUCCESS**: Linux/GCC **252/252 Debug + 252/252 Release**,
  macOS/AppleClang **234/234 Debug + 234/234 Release**,
  Windows/MSVC **251/251 Debug + 251/251 Release**.
  Both new R1 `transport.tcp-native-listener-role-and-mode-denials`
  and `transport.tcp-native-wrong-socket-type-denials` PASS on
  ALL hosted platforms in both configurations; documentation-policy,
  R9 security-protocol sanitizers, per-platform SDK consumer and ZIP
  packaging PASS. Previous unrelated Windows private-TLS-file
  runtime failure corrected independently by R10, and [Issue #14](https://github.com/k1moradi/RDP-server/issues/14)
  closed with both Windows modes PASS.
  **NOT RUN:** owner Linux/X11, Windows MSYS2 CLANG64 Clang23,
  macOS27 on this exact SHA; real RDP client, TLS/NLA
  authentication and independent OS identity/authorization,
  R3 channel/session and desktop. Runtime listener activation
  remains R10-owned and requires separate approval.

  **Verified R1 bounded TCP/BIO syscall integration increment
  (2026-10-15; exact-head CI PASS):** Reuse the
  ONLY existing `NativeTcpIo` and custom OpenSSL
  `TcpNonblockingIo` BIO, without adding a listener or
  controller. Enforce an 18 KiB maximum **per native
  recv/send and BIO callback** (RFC 5246 TLS 1.2
  ciphertext maximum 2^14+2048; compatible with
  RFC 8446 TLS 1.3 maximum 2^14+256). Return actual
  short progress to OpenSSL, preserve WANT_READ/
  WANT_WRITE retry flags on would-block only, reject
  provider misreported lengths even if <= the caller's
  originally larger buffer, and avoid Windows size_t-
  to-int socket-length wrap/negative conversion. No
  payload allocation or staging; the caller/event loop
  retains all packet assembly and cancellation.
  Two new dedicated portable CTests, registered under
  the original preauth executable and single registry:
  `transport.tcp-bio-chunk-bounds` exercises real
  OpenSSL BIO read/write callbacks with overlength
  spans, 18KiB/18KiB/tail progression, would-block,
  spoofed overreported lengths and complete byte
  parity; `transport.tcp-native-chunk-bounds`
  exercises connected native loopback sockets on
  Linux/macOS/Windows with checked bounded partial
  send/read and complete byte parity.
  Expected **101 portable / 111 Linux GSS** full
  CTests, up from the independently reported 99/109.
  Parent `7e9b2881f66cea2b0354242b4e7ae39cb89170bc`
  is docs-only ten-workstream R1–R10 convergence
  policy; prior actual transport code
  `45f68c2c0fcaa163aaf242a99f5637726a023fe2`
  passed [CI 38749371803](https://github.com/k1moradi/RDP-server/actions/runs/38749371803)
  Linux **109/109** and macOS/Windows **99/99**
  CTests in both Debug and Release. Owner reports
  **99/99** local PASS on preceding code without
  a matching local SHA or terminal log.
  **NOT RUN:** exact new-head hosted CI, owner's
  new-code single-build-root tests, Windows MSYS2
  Clang 23/macOS 27 owner-target toolchains,
  real Kerberos/CredSSP identity, OS admission,
  licensing, live Microsoft-client MCS handshake,
  H.264/X11 desktop or human test. This work
  exercises R1 I/O only and CANNOT accept a user.
  **PASS:** exact implementation
  `8ce08611d5d7b093c9d69f4b7eee5d23cd096359`,
  [GitHub Actions 38752789202](https://github.com/k1moradi/RDP-server/actions/runs/38752789202):
  Linux/GCC **111/111** and macOS/Clang,
  Windows/MSVC **101/101** registered CTests in BOTH
  Debug and Release, including both new R1 chunk
  bounds cases; documentation-policy, installed
  downstream SDK consumer, ZIP/SHA256 packaging and
  artifact uploads PASS. Untagged prerelease SKIPPED.
  Earlier NOT RUN-at-authoring status is now superseded
  for hosted CI only. **NOT RUN:** owner-local current
  SHA single-root CTest, MSYS2 CLANG64 Clang23 and
  macOS27 owner environment, positive real CredSSP/
  Kerberos+TLS binding, independent OS account/session
  admission, real Microsoft RDP client and desktop.
  **Next:** owner performs exact-head local CTest
  with his one reused build root; R1/R2/R3 converge
  only after externally authorized GSS/OS session
  and actual client acceptance evidence.
  **Verified partial Gate A single-owner TCP/TLS/MCS readiness integration
  (2026-10-15; exact-head CI PASS):** In the
  existing `PreauthTcpAdapter` alone, bind the completed
  X.224 Confirm's connected `TcpNonblockingIo` to exactly
  one attached server `SSL*` and its single shared
  OpenSSL BIO. Expose `onAttachedTlsIoReady` and
  `onAttachedMcsIoReady` so the event loop cannot supply
  a replacement SSL pointer on subsequent callbacks.
  The existing transport verifies the same borrowed BIO
  pointer and its `TcpNonblockingIo` data, and rejects
  a duplicated attach, changed BIO/socket target,
  premature TLS/MCS callbacks and replay. Existing
  synthetic memory-BIO `onTlsIoReady(SSL*)` remains
  available for offline diagnostics only; once attached,
  even that legacy callback routes through the strict
  connection identity gate. No new network listener,
  state controller, GSS identity, licensing or MCS reply.
  The existing true native nonblocking loopback test
  now drives BOTH handshake and bounded MCS/GCC intake
  through this single pinned TCP owner. Two new
  behavior CTests in the existing preauth executable
  prove premature calls, duplicate/wrong SSL and
  changed/retargeted BIO fail closed. Expected **99
  portable / 109 Linux GSS** CTests (prior 97/107).
  Baseline main `00c70a24568098b34bcd1485e8f82fd63d0bab9a`
  is the roadmap's Gate A/C real-client priority commit.
  Implementation `89ffef98b4f27ad2947b4629c9eefa49b64152a7`
  passed [CI 38746309146](https://github.com/k1moradi/RDP-server/actions/runs/38746309146):
  Linux 107/107 and macOS/Windows 97/97 Debug/Release.
  Owner reports **97/97 local PASS** on the preceding code
  without a full log or local SHA.
  **PASS:** implementation
  `45f68c2c0fcaa163aaf242a99f5637726a023fe2`,
  [Actions 38749371803](https://github.com/k1moradi/RDP-server/actions/runs/38749371803):
  Linux/GCC **109/109**, macOS/Clang and Windows/MSVC
  **99/99** CTests in BOTH Debug and Release,
  including both new TCP/TLS/MCS ownership/order denials
  and the real native socket loopback flow. Installed
  SDK consumer, ZIP/SHA256 packaging/artifact uploads
  and documentation-policy PASS. Prerelease SKIPPED
  (no protocol version tag).
  **NOT RUN:** owner-local new-code full CTest,
  human Microsoft-client authenticated negotiation,
  real GSS/CredSSP TLS public-key proof and independent
  OS account/session admission, live MCS Connect-Response,
  H.264 or X11 desktop.
  **Next:** owner-local reused single-root CTest,
  then explicitly authorized isolated Kerberos/TLS and
  OS approval before any live MCS response or
  postauth transition.
  **Completed partial increment at `988938a90f8adbae4e07714ac636af3eb0640011`:**
  bounded incremental plaintext Connection Request intake, exact TCP
  consumed-byte accounting, correct negotiation response/terminal failure,
  all request split points and malformed-length negative tests.
  **PASS:** [Actions run 38536987879](https://github.com/k1moradi/RDP-server/actions/runs/38536987879)
  on Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy;
  registered protocol and policy CTests passed.
  The *overall* milestone stays **open**: a real TCP listener, TLS provider,
  authenticated session, MCS response and external-client handshake
  remain **NOT RUN / unimplemented**.
  **Additional partial increment `18262c0e4bf9bc4ecec4c2d56b069d4fc723b1f1`:**
  the existing preauth owner requires exactly one completed X.224
  reply write before accepting a TLS transition. Premature TLS,
  failed/partial and repeated acknowledgments fail closed.
  **PASS:** [Actions run 38537586258](https://github.com/k1moradi/RDP-server/actions/runs/38537586258)
  on Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy.
  The overall listener/TLS/authentication milestone is still open;
  **no real socket, TLS provider or external client was tested**.
  **Verified increment at `49c6006d47476184f7448028cd332e377ec9bd0b`:** reuses the same preauth
  buffer to reassemble exactly one decrypted RFC 1006/X.224 Data TPDU
  carrying a BER MCS Connect Initial and GCC Conference Create Request.
  The native test exercises every split/truncation point, coalesced
  next-PDU bytes, invalid TPKT length/X.224 type, BER errors and
  replay/close. This is NOT a real TLS or admitted RDP session.
  **PASS:** [Actions run 38541509607](https://github.com/k1moradi/RDP-server/actions/runs/38541509607) on Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy. **NOT RUN:** live TLS/NLA, host listener and external client.
  **Next boundary:** real TLS provider plus authenticated session
  policy and complete MCS response handling.
  **Current partial security increment (CI pending):**
  `PreauthConnectionStream` requires a completed, server-role
  OpenSSL TLS 1.2+ session with selected certificate/cipher, instead of
  accepting a caller-supplied Boolean. The existing transport CTest
  now exercises an actual in-memory OpenSSL TLS handshake and negative
  wrong-role, pre-handshake, null, early and replay transitions.
  This does **not** implement socket TLS I/O, trusted OS session
  authorization, CredSSP/NLA or MCS Connect-Response.
  **First CI result:** macOS and documentation-policy PASS,
  Windows Compile Debug FAIL at `a25b5186398e4a5619baea2998a61596fa7b2887`
  ([Actions run 38551275680](https://github.com/k1moradi/RDP-server/actions/runs/38551275680))
  because OpenSSL's platform includes exposed a `min` macro
  affecting the existing `std::min(...)` intake calls.
  The follow-up fixes OpenSSL header isolation and call syntax.
  **PASS:** fixed OpenSSL include/Windows macro handling at
  `edfaf2e7ea684ab5adc77bf58441ff467288f818`, verified by
  [Actions run 38551496274](https://github.com/k1moradi/RDP-server/actions/runs/38551496274):
  Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy
  all passed Debug/Release full CTests, downstream SDK consumer
  and per-OS ZIP/checksum artifact uploads.
  **NOT RUN:** real socket TLS peer, trusted credentials/NLA,
  OS desktop admission, external RDP clients or owner's local
  build of this new commit. **Next:** integrate an authenticated
  TLS transport/session lifecycle without permitting OS admission
  before CredSSP/identity authorization.
  **Verified TLS application-record increment `a226f15827e9da48ad7a91b7cfa53528c3498802`:** the existing
  preauth stream now associates the completed OpenSSL server `SSL*`
  with the connection and uses `SSL_read_ex` to decrypt and parse
  precisely one bounded MCS/GCC TPKT. WANT_READ/WANT_WRITE do not
  close the connection; EOF, malformed data, swapped SSL handles
  and replay fail closed. The memory-BIO test drives actual encrypted
  TLS application records at every split boundary, coalesced trailing
  PDU, invalid header and early close. Neither a socket listener
  nor CredSSP/OS admission is implemented.
  **PASS:** [Actions run 38557465241](https://github.com/k1moradi/RDP-server/actions/runs/38557465241),
  Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy; all
  Debug/Release protocol and project-policy CTests, staged SDK install,
  downstream consumer and platform ZIP/checksum uploads passed.
  **NOT RUN:** user's local build of this exact head, external client,
  TCP TLS listener, OS identity admission and desktop interaction.
  **Next:** nonblocking socket adapter and authenticated session policy,
  without equating a TLS handshake with user authentication.
  **Verified partial-send protocol increment at `98f6fdc60d513d47a87a78fadf1aa6be387da28b`:**
  `PreauthConnectionStream` now owns the 19-byte X.224
  Confirm/Failure response and tracks byte-accurate nonblocking
  write progress. Zero-byte output is retryable; overrun, premature
  TLS and replay fail closed; a rejected negotiation's response
  drains before transport closure. The existing preauth executable
  has an independent `transport.x224-confirm-partial-writes` CTest
  covering all 20 split boundaries, bytewise writes, cancellation,
  malformed accounting and both negotiation outcomes. Expected
  CTest total: **21**, up from 20 for a substantive new behavior.
  **PASS:** [CI run 38561127854](https://github.com/k1moradi/RDP-server/actions/runs/38561127854)
  for Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy;
  all Debug/Release CTests, installed SDK consumer, ZIP and SHA-256
  artifacts. Ubuntu logs explicitly show **21/21 PASS** in both
  configurations. **NOT RUN:** owner-local new build, real TCP listener,
  external clients, NLA, OS admission, desktop interaction.
  **Next:** nonblocking network adapter and authenticated RDP session.
  **Verified native TCP adapter increment `dd3a806f97b13e6db18affd689c6321bfa009813`:**
  `PreauthTcpAdapter` wraps the existing sole preauth owner and drives
  exact-prefix 4-byte TPKT/declared request `recv`, followed by the
  byte-accurate pending X.224 Confirm/Failure `send`. A thin native
  socket adapter maps Linux/macOS/BSD and Windows recv/send errors to
  nonblocking outcomes. No extra encrypted TLS records can be read
  prematurely, even if coalesced on TCP. Scripted event-loop regressions
  exercise all 20 CR split positions, one-byte reads/writes, would-block,
  corrupted headers, EOF, short output, overreported counts, complete
  NEG_FAILURE and cancellation.
  **PASS:** [Actions run 38563789698](https://github.com/k1moradi/RDP-server/actions/runs/38563789698)
  passed Ubuntu/GCC, macOS/Clang, Windows/MSVC and documentation-policy,
  all Debug/Release CTests, SDK installation, downstream consumer
  and three ZIP/SHA-256 artifacts. Ubuntu explicitly reports
  **23/23 PASS** in Debug and Release.
  **NOT RUN:** owner-local new build, actual connected native
  socket runtime, listening server, live TLS network handshake,
  CredSSP/NLA, MCS Connect-Response and authenticated desktop.
  **CI compatibility note:** the documentation-evidence rerun
  [38564061700](https://github.com/k1moradi/RDP-server/actions/runs/38564061700)
  encountered a macOS Debug compile **FAIL** with OpenSSL 4.0.3:
  `X509_get_subject_name` now returns `const X509_NAME*`,
  invalidating the synthetic certificate fixture's mutable cast.
  A follow-up constructs its own `X509_NAME` and assigns it
  through `X509_set_subject_name`, avoiding reliance on
  the changed mutable return type.
  **PASS:** corrected `5c4f3ad7273d17948327b7d351ff9840de2b0395`
  in [CI run 38564403002](https://github.com/k1moradi/RDP-server/actions/runs/38564403002):
  Ubuntu/GCC, macOS/Clang, Windows/MSVC, documentation-policy,
  Debug/Release **23 CTests**, installed consumer and three SDK ZIPs.
  macOS selected OpenSSL **3.6.4** on the passing run;
  the corrected fixture's OpenSSL 4 runtime/compiler gate remains
  **NOT RUN**. **Next:** verify OpenSSL 4 explicitly, complete
  actual live TLS/socket I/O, authentication and MCS response.
  **Verified nonblocking TLS handshake increment at
  `fcd05f8e903a459ca85f13807bd35f7091f3fd70` (25 CTests):** the sole `PreauthConnectionStream` now drives one
  `SSL_do_handshake` attempt per readiness event, returns OpenSSL
  WANT_READ/WANT_WRITE distinctly, and binds the borrowed SSL pointer
  through retries. Complete X.224 Confirm output and server-role SSL
  are mandatory. Provider errors, null/client-role/wrong-pointer
  handles and cancellation fail closed; successful handshake reuses
  the same SSL for bounded encrypted MCS/GCC intake. The existing
  event-driven TCP adapter forwards `onTlsIoReady`, without
  installing a server listener. Two named test groups cover real
  in-memory TLS handshake progress through MCS and negative/replay
  gates. **NOT RUN:** exact-head CI, owner-local build, real connected
  socket TLS I/O, NLA/identity authentication, MCS Connect-Response
  and OS desktop admission.
  **PASS:** [Actions run 38566584099](https://github.com/k1moradi/RDP-server/actions/runs/38566584099)
  on Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy:
  both Debug/Release CTests, staged SDK installation, downstream
  consumer and three platform ZIP/SHA-256 artifacts. Ubuntu logs
  show **25/25 PASS** in Debug and Release.
  **NOT RUN:** owner's local post-change build, connected native
  TLS socket, independent credential/CredSSP/OS authorization,
  MCS Connect-Response or external RDP client/desktop.
  **Next:** drive the same TLS handshake over real connected
  nonblocking sockets in a safe loopback test, then authenticated
  RDP session establishment.
  **Verified native nonblocking loopback/TLS increment
  `7ce64737ccef439af2f0cfd383208181cc0e9513`
  (27 CTests):** a first-party OpenSSL custom BIO now borrows the
  existing `TcpNonblockingIo` and translates partial send/recv,
  would-block, EOF and I/O failure to OpenSSL readiness semantics
  without narrowing 64-bit Windows SOCKET handles. The existing
  `PreauthTcpAdapter` attaches this BIO only after the full X.224
  Confirm is sent; the same connection owner then drives
  `SSL_do_handshake` and bounded TLS MCS/GCC intake. Two new
  behavior-named CTests open ephemeral **127.0.0.1:0-only** TCP pairs,
  immediately close the temporary listener and verify native X.224,
  real TLS records carrying the Microsoft 416-byte MCS fixture,
  terminal EOF on a truncated CR and delivery of RDP_NEG_FAILURE.
  This is an isolated CI test, NOT installation/activation of a
  daemon or an externally reachable RDP server.
  **First CI FAIL:** [run 38578878083](https://github.com/k1moradi/RDP-server/actions/runs/38578878083)
  passed Ubuntu/GCC, Windows/MSVC and documentation-policy; on
  macOS/Clang two native loopback tests failed because the test
  assumed immediate recv readiness and immediate observation of TCP
  FIN. Corrected the **test driver only** to tolerate would-block
  and wait with bounded 1ms sleeps while retaining exact framing
  and terminal assertions.
  **PASS:** corrected [Actions run 38579350917](https://github.com/k1moradi/RDP-server/actions/runs/38579350917)
  on Ubuntu/GCC, macOS/Clang, Windows/MSVC and documentation-policy;
  both Debug/Release full **27/27 CTests** (confirmed in Ubuntu logs),
  installed SDK consumer and three ZIP/SHA-256 platform packages.
  **NOT RUN:** user's local build of the new code, external RDP
  clients, production certificate trust/enrollment, CredSSP/NLA,
  MCS Connect-Response, OS authorization and desktop.
  **Next:** authenticated session policy and the standards-compliant
  MCS server response.
  **Next protocol increment — T.125 MCS domain negotiation
  (pending exact-head CI):** the first-party
  `mergeMcsDomainParameters` implements Microsoft's
  [MS-RDPBCGR 3.3.5.3.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7617f746-95c9-4a6e-808d-e2f642471e86)
  eight-field target/minimum/maximum negotiation. The BER parser now
  allows min/max protocol versions other than 2 if they can negotiate
  version 2; the existing preauth diagnostic requires a successful
  merge, otherwise closes without MCS admission. Two NEW domain
  behavior tests cover the published Microsoft client fixture,
  each required fallback, unsupported version and all rejection
  branches. The four existing Connect-Initial test groups are
  individually registered without duplicating the executable:
  expected CTest total **32** (previously 27; two new behaviors,
  three additional registrations of existing behaviors).
  **PASS:** implementation `865c56c548526f4514207a4af1b192f3b3637c9a`
  in [CI 38582674975](https://github.com/k1moradi/RDP-server/actions/runs/38582674975):
  Linux/GCC, macOS/Clang, Windows/MSVC, documentation-policy,
  Debug/Release 32 CTests, installed downstream consumer and SDK
  ZIP/checksum gates. Owner-provided Linux Debug build and
  **32/32 CTest PASS** at the same code commit in the reused
  `~/rdp-server/build/` directory.
  **NOT RUN:** real external RDP client, CredSSP/NLA, authenticated
  OS admission or MCS Connect-Response emission.
  **Offline MCS Connect-Response encoder increment (CI pending;
  expected 34 CTests):** first-party
  `encodeMcsConnectResponse` constructs a bounded TPKT/X.224 Data TPDU,
  T.125 BER Connect-Response (APPLICATION 102), and T.124 GCC
  Conference Create Response with H.221 `McDn`. It emits
  `SC_CORE`, `SC_NET` with caller-provided, validated channel IDs,
  and `SC_SECURITY` with Enhanced TLS security values (0, 0)
  rather than a legacy RC4 certificate/random. DomainParameters
  come from the existing checked `mergeMcsDomainParameters` result.
  The encoder validates the actual client GCC settings, checks
  nodeID range 1001..65536, channel cardinality and uniqueness,
  requires the currently supported SSL offer (1), uses minimal BER
  and nonfragmented PER lengths, and returns no bytes on failure.
  **Offline only:** it does NOT send to a peer, register a domain,
  authorize credentials, or allocate a desktop or channel session.
  New `transport.mcs-response-wire` compares the whole 108-byte
  TLS-only response to an independently assembled oracle derived
  from [MS-RDPBCGR 4.1.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d23f7725-876c-48d4-9e41-8288896a19d3);
  `transport.mcs-response-rejections` covers malformed or
  contradictory inputs and BER integer sign padding.
  **PASS:** implementation `e25cd3a05f46b7eaa2a259eb2da8ddb3b7459a87`
  passed Linux/GCC Debug/Release **34 CTests**, Windows/MSVC
  Debug/Release CTests, SDK consumer and packaging, and
  documentation-policy in [CI run 38586253181](https://github.com/k1moradi/RDP-server/actions/runs/38586253181).
  The owner's local Linux Debug `~/rdp-server/build/` run at
  `ddfc2d372285c397c52dca0197d30bf1c61c338e` confirmed
  **34/34 CTests PASS**; macOS status for that implementation is
  not independently asserted here.
  **NOT RUN:** production response emission, CredSSP/NLA user
  authentication, MCS domain lifecycle and desktop access.
  **Next:** implement bounded offline Erect/Attach/Join decoding,
  then authenticated connection admission and response ownership.
  **Offline MCS channel-connection request decoding (pending
  cross-platform CI; expected 37 CTests):** the portable
  `parseMcsChannelRequest` parses exactly one complete RFC1006
  TPKT/X.224 Data PDU holding T.125 aligned BASIC-PER
  ErectDomainRequest (subHeight/subInterval), AttachUserRequest or
  ChannelJoinRequest (initiator UserId and requested channel ID).
  It uses existing validated `parseDataTpdu` framing, bounded
  1..4-octet PER integers, canonical encodings and exact consumed
  lengths, and rejects wrong-direction PDU types, malformed padding,
  length mismatch, trailing bytes and UserId overflow. The
  initiator offset of 1001 is decoded **without** verifying that
  the account or channel exists. New CTests reuse the same MCS
  executable and Microsoft's 4.1.5/4.1.6/4.1.8 request examples:
  `transport.mcs-erect-request`,
  `transport.mcs-attach-request`,
  `transport.mcs-channel-join-request`.
  **Initial FAIL:** implementation `d5bc7d3b03906890da483dd1a480677a4fbaf73b`
  [CI run 38588334504](https://github.com/k1moradi/RDP-server/actions/runs/38588334504)
  failed Ubuntu Debug `transport.mcs-erect-request` at the
  *test-only* extended PER integer example: its octet length
  determinant claimed 4 bytes but the fixture provided 3.
  Other 36 CTests passed. The production parser correctly
  rejected the inconsistent packet. The test vector has been
  corrected from 0x04 to 0x03 without changing the decoder.
  **PASS:** corrected implementation
  `6effdb76229e2514511ebe5dd8cb404841403b1b`,
  [Actions run 38588538653](https://github.com/k1moradi/RDP-server/actions/runs/38588538653)
  on Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy:
  both Debug/Release **37 CTests**, installed downstream SDK
  consumer, and three SDK ZIP/SHA-256 uploads. Ubuntu logs
  explicitly show **37/37 PASS** in both configurations.
  **PASS (owner-local):** the user's reused
  `~/rdp-server/build/` Linux Debug configure/build/CTest
  at `3135d66e557ecc8144fba02a8a69b5054b62ede9`
  passed **37/37**. This predates the new reply encoders.
  **NOT RUN:** TLS-verified domain phase admission, CredSSP/NLA,
  live attach/channel replies, OS authorization and desktop.
  **Next:** independent authenticated session authority and
  its single-owner MCS Attach/ChannelJoin lifecycle.
  **Offline Attach User and Channel Join confirmation encoding
  (2026-10-14; 39 CTests verified):**
  the existing portable `mcs_channel_connection.{h,cpp}` now
  constructs complete bounded TPKT/X.224/T.125 aligned-PER
  `rt-successful` Server Attach User Confirm and Channel Join Confirm
  packets without mutating session/domain/channel state.
  The assigned UserId must be 1001..65536 and is serialized
  as the 16-bit PER offset. A Channel Join Confirm requires a
  previously parsed Join request, the same explicitly assigned
  UserId, a nonzero requested channel, exactly one matching
  entry in a bounded externally supplied channel list, and
  correct repeated requested/confirmed ChannelId.
  Complete Microsoft example packets in MS-RDPBCGR 4.1.7
  (11 bytes) and 4.1.8.2.2 (15 bytes) are bytewise test oracles.
  Two new behavior CTests test successful encoding, both extrema
  of UserId, mismatched/duplicate/unallocated channels, wrong
  request kind and invalid identifiers. The library **does NOT**
  use these encoders to send packets; the supplied channel list
  does not prove OS identity, credential approval or MCS admission.
  **PASS:** implementation
  `4eb3bff4f9fc15cb72da1b8e994ec89e7e9a96db`,
  [Actions run 38590263498](https://github.com/k1moradi/RDP-server/actions/runs/38590263498)
  passed Linux/GCC, macOS/Clang, Windows/MSVC and
  documentation-policy, full Debug/Release CTests, installed SDK
  consumer and three ZIP/SHA-256 artifacts. Ubuntu logs confirmed
  **39/39 CTests PASS** in Debug and Release.
  **NOT RUN:** owner's updated local build, real CredSSP/NLA
  and OS-authorized session, encrypted live reply emission,
  external Microsoft clients and OS desktop.
  **Next:** implement a genuine CredSSP/NLA and independent OS
  identity authority, then let the sole server connection owner
  enforce MCS ordering, allocations and reply transmission.
- [ ] Implement TLS, CredSSP/NLA and independently verified OS session
  authorization, including security downgrade and failure tests.
  **Gate A security acceptance (NOT RUN):** positive real Kerberos/GSS
  with the active TLS certificate/public-key binding plus separate OS
  user/console authorization on an explicitly approved isolated test
  host. Gate all channel/session output on both authorizations; cover
  invalid accounts, altered certificates, downgrade, expiry, denial,
  cleanup and replay. Fail closed rather than bypassing NLA or
  accepting synthetic credentials as proof of admission.
  **R2 CredSSP release-time certificate continuity (2026-10-16;
  parent main `a603976a07d5a525aee20f75ba74e40f77ec9314`):**
  `TsRequestFrameReader::releaseFrame()` now reuses the existing
  `completedFrameServerTls()` certificate check before releasing any
  TLS-derived complete frame. A same-`SSL*` selected-certificate
  substitution therefore terminally closes the reader, wipes retained
  DER and TLS/certificate provenance, and leaves release/read/replay inert.
  Unchanged TLS identity can release and receive the next frame; manual
  offline `consume()` framing keeps its prior release behavior.
  Dedicated default CTest
  `security.credssp-tls-release-certificate-denial` reuses the existing
  real memory-BIO TLS fixture for stable reuse, same-SSL substitution
  denial, terminal cleanup/replay denial and offline compatibility.
  **PASS at authoring:** current-main source/registry review.
  **NOT RUN at authoring:** local single-root focused/full CTest because
  this agent sandbox has no repository checkout and cannot resolve
  github.com; exact-SHA hosted CI until publication; real Kerberos,
  independent native OS admission and owner Linux/X11, Windows
  MSYS2 CLANG64/Clang23, macOS27 remain NOT RUN.
  **Exact-SHA hosted CI receipt:** implementation
  `ff72dbac77c881858279a2e7db753a1a5fac6c92`,
  [Actions 38865066667](https://github.com/k1moradi/RDP-server/actions/runs/38865066667)
  **PASS overall**. Full registered CTest passed in both Debug and Release:
  Linux/GCC **272/272**, macOS/Clang **254/254**, Windows/MSVC **270/270**.
  `security.credssp-tls-release-certificate-denial` passed in all six
  configurations. R9 ASan/UBSan and documentation-policy jobs passed;
  SDK downstream/package checks passed and prerelease publication was
  correctly skipped without a version tag. This does not substitute for
  owner Linux/X11, Windows MSYS2 CLANG64/Clang23 or macOS27 runs, genuine
  Kerberos, native OS admission, R3 activation or Microsoft-client evidence.
  **R2 Linux native admission lease boundary (2026-10-16;
  authoring parent `7f6d74b4ef9b03c86ecabc7c56af6f1de071ad07`; exact-SHA CI pending):**
  introduce a move-only, non-default-constructible
  `LinuxConsoleAdmissionLease` and one-shot
  `LinuxConsoleAdmissionBroker` in the existing optional Linux GSS target.
  Positive issuance has **no injectable evidence-source parameter**: only
  the broker-owned concrete `LinuxLogindReadOnlyEvidenceSource` plus
  `LinuxLogindSessionChangeSource` may reach issuance, and the native
  change monitor is established before NSS/logind sampling. The broker
  requires the provider-derived principal for the exact active pinned TLS,
  unchanged policy generation, current physical seat/display/UID/session
  generation, fresh monotonic evidence and a quiet native change watch.
  The lease carries only bounded principal/account/session ID, UID,
  session generation, permission mask and admission generation.
  Lease destruction, explicit revoke, policy epoch changes or a one-second
  missed-revalidation deadline invalidate the shared capability epoch.
  `authorizes()` rechecks permission scope, GSS/TLS certificate continuity,
  policy generation, NSS/logind identity and the change watch immediately
  before protected use. A logind event may still occur after the final
  post-sample poll and before R3 acts; this residual check/use race is
  unavoidable with these read-only APIs, so R3 must register the native
  watch fd, call the broker immediately before protected transitions, and
  revoke before TLS/R3 teardown.
  The existing generic `ConsoleAdmissionGate` remains deny-only and fake
  `ConsoleOsEvidenceSource` implementations remain structurally unable to
  mint this production lease. Dedicated Linux GSS CTest
  `security.gssapi-native-os-admission-capability-denials` checks the
  move-only/nonconstructible contract, absence of a generic evidence
  issuance overload, GSS-before-native denial, replay denial and policy
  generation fencing without a real login or Kerberos credential.
  **NOT RUN at authoring:** local checkout build/CTest, exact-SHA CI, real
  positive Kerberos+logind issuance, R3 consumption, owner Linux/X11,
  Windows CLANG64/Clang23, macOS27 or Microsoft-client desktop.
  **Exact-SHA hosted CI receipt:** implementation
  `03f2edbbfaa9049e7d6a22f22c11c94d9ad91213`,
  [Actions 38872022770](https://github.com/k1moradi/RDP-server/actions/runs/38872022770)
  finished overall **FAIL** only because a concurrent R10 macOS Debug build
  treats OpenSSL 3.6 deprecations of `X509_cmp_current_time` in
  `src/server/runtime/main.cpp` as errors. R2's Linux target compiled with
  strict warnings and full CTest passed **287/287** in BOTH Debug and
  Release; `security.gssapi-native-os-admission-capability-denials`
  passed in both. Windows/MSVC full CTest passed **285/285** in BOTH
  configurations. R9 ASan/UBSan and documentation-policy passed; Linux and
  Windows SDK downstream/package checks passed. macOS CTest/Release/package
  were **NOT RUN** after the unrelated R10 compile failure. No R2 failure is
  observed at this SHA.
  **Still NOT RUN:** real positive Kerberos+native-logind issuance, R3
  capability consumption, owner Linux/X11, Windows MSYS2 CLANG64/Clang23,
  macOS27 and Microsoft-client desktop.
  **Next:** wire this capability into R3's sole session owner and R1
  disconnect teardown before any protected MCS state.
  **R2 GSS-to-OS candidate-evidence provenance gate (2026-10-15;
  new implementation CI pending):** add the existing
  `ConsoleAdmissionGate`, `ConsoleIdentityPolicy`, and
  `ConsoleOsEvidenceInspector` to the optional Linux GSS
  target rather than leaving the bridge unlinked. Its new
  `requestWithOsEvidence` requires the GSS provider's live
  TLS/X.509-bound `verifiedPrincipal()` to equal the proposed
  Kerberos identity BEFORE it samples independently observed
  OS account/physical-console facts. Even CandidateOnly never
  yields a token or session; the acceptor is terminally rejected.
  The legacy caller-attested snapshot API is deny-only and
  no longer even evaluates a candidate policy match.
  Dedicated new default Linux provider CTest
  `security.gssapi-console-provenance-before-os-read` proves
  an artificial evidence source could match policy, yet the
  unverified, failed-keytab, replayed and raw-snapshot gate
  must not perform ANY account/session/time reads.
  **PASS:** source/CTest registration static review.
  **NOT RUN at authoring:** local single-root CTest (checkout
  unavailable), exact-SHA new CI, real Kerberos/TLS positive,
  independent audited native OS admission, R3 or owner platforms.
  **Next:** verify full hosted CTests and establish revocable
  genuine GSS+OS admission, without trusting fake candidates.
  **R2 TLS-provenant delegated-credential handoff (2026-10-15;
  CI pending):** optional Linux GSS now accepts protected authInfo
  only from the existing complete TLS-derived `TsRequestFrameReader`.
  It requires the same pinned server SSL/X.509, negotiated v5/v6,
  genuinely verified GSS identity and confidential public-key proof,
  and a credential-only TSRequest envelope before GSS unwrap.
  Provider plaintext is inspected only for bounded credential metadata
  then securely erased; both GSS and frame owners are terminally
  closed/rejected. The old raw-DER API never decrypts and only denies.
  **Dedicated new default Linux CTest:**
  `security.gssapi-tls-framed-credential-denials` checks real TLS
  framing with no GSS proof, v5/v6 authInfo DER, manual/incomplete
  frames, changed same-SSL certificate, no reply and replay denial.
  **PASS at authoring:** source-level review; **NOT RUN** local
  checkout CTest or new-head hosted CI until published; genuine
  Kerberos credentials, OS admission and R3 access remain NOT RUN.
  **Next:** validate exact-commit CI, then independently audit native
  OS identity/console authority without issuing synthetic capabilities.
  **R2 TLS-owned credentials full hosted-CI receipt (2026-10-15):**
  Source+CTest+docs `063bcaa1c3cb5b49fbb4be4b84230736fcd6bf7f`,
  [Actions 38844600869](https://github.com/k1moradi/RDP-server/actions/runs/38844600869)
  **PASS overall:** Linux/GCC **195/195**, Windows/MSVC
  **185/185**, macOS/Clang **181/181** CTests in BOTH Debug
  and Release; `security.gssapi-tls-framed-credential-denials`
  PASS on Linux in both. Docs policy and SDK consumer PASS.
  **NOT RUN:** owner Linux/X11, MSYS2 CLANG64/Clang23, macOS27,
  genuine Kerberos, independently authorized OS session and
  Microsoft-client desktop. Console admission stays deny-only.
  **R2 provider/TLS identity handoff (2026-10-15; CI pending):**
  `GssapiSpnegoAcceptor::verifiedPrincipal()` now requires genuine
  GSS completion AND the selected TLS X.509-bound CredSSP v5/v6
  public-key proof. It refuses a missing GSS context, early GSS-only
  identity, or a later changed selected certificate. The dedicated
  `security.gssapi-principal-tls-proof-gate` CTest exercises negative
  real-TLS handoffs; opt-in genuine Kerberos tests cover successful
  binding and certificate-change denial. **NOT RUN at authoring:**
  patched CTests, new-head CI, opt-in Kerberos, independent OS
  authorization and R3 admission. The console gate remains deny-only.
  **Hosted exact-R2 code CI and repaired cross-platform acceptance:**
  implementation `ec8291eb68069182d86034768618e67bb8ea3c73`
  PASS Linux/GCC 184/184 and Windows/MSVC 180/180 CTests in Debug
  and Release. The initial macOS native R7 linker failure was repaired
  on a later main commit. Inclusion SHA
  `19512d5fdbc0568fbd6c3333b32c770d76c6f8b4`
  [Actions 38800199864](https://github.com/k1moradi/RDP-server/actions/runs/38800199864)
  PASS Linux 184/184, Windows 180/180, macOS 173/173 full CTests in
  BOTH configurations, including the new R2 Linux GSS gate CTest.
  **NOT RUN:** owner local three-platform command, opt-in Kerberos
  credentials, independently authorized OS session or human desktop.
  **CredSSP TSRequest decrypted-message framing increment (2026-10-14,
  46 CTests; exact-head CI PASS):** extend the existing
  first-party `credssp_tsrequest.{h,cpp}` with a fixed 16 KiB
  `TsRequestFrameReader`, preserving DER SEQUENCE/length boundaries
  across fragmented TLS application bytes, rejecting nonminimal,
  indefinite, oversized and unsupported DER lengths *before*
  large buffering, and leaving coalesced following-message bytes
  unconsumed. Completed bytes and SPNEGO/credential fields remain
  borrowed until explicit `releaseFrame()`; cancellation,
  malformed input and destruction wipe owned ciphertext via
  OpenSSL cleanse and terminate invalid frames. A second frame
  cannot overwrite an unreleased first frame. Three new
  behavior groups test every split, coalesced messages, DER
  0x81/0x82 lengths (including large bounded frames), invalid
  headers, EOF/cancellation and replay. Register the five
  prior CredSSP behavior groups separately without creating
  another executable (39 old registered CTests -> 46 expected).
  **This is syntax-only:** no SPNEGO acceptor, Kerberos/NTLM
  user authentication, version-5/6 TLS public-key binding,
  nonce validation, credentials decryption, OS account/session
  authorization, NLA X.224 negotiation or MCS admission is enabled.
  The existing diagnostic still selects only PROTOCOL_SSL and
  closes after MCS intake.
  **PASS:** implementation
  `c7f0463a3e11c8bd9fb6e8dfb404c3f1057d40cd`,
  [CI run 38592588562](https://github.com/k1moradi/RDP-server/actions/runs/38592588562)
  on Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy:
  Debug/Release full CTests, installed downstream SDK consumer
  and all three ZIP/checksum package artifacts. Ubuntu logs
  explicitly show **46/46 CTests PASS** in each build mode.
  **NOT RUN:** owner's local build of updated code,
  live CredSSP TSRequest TLS exchange, GSS/SPNEGO and
  independently authenticated OS session, external client
  or desktop acceptance.
  **Next:** connect this bounded DER handoff to a real
  CredSSP/SPNEGO provider and verified OS authorization in
  the sole connection owner; never treat a syntactically
  valid token as an authentication capability.
  **Verified bounded server-reply serialization (2026-10-14;
  48 CTests PASS):** within the same `credssp_tsrequest` module, an
  offline, allocation-bounded, canonical DER encoder produces
  one MS-CSSP TSRequest server `negoTokens` response OR an
  already-GSS-protected `pubKeyAuth` response for versions
  5/6. No credential or nonce output, TLS send, SPNEGO trust
  assertion or OS identity authority is added. Two additional
  existing-executable behavior CTests exercise literal DER wire
  oracles, lengths, parsing/framing and rejection bounds (expected
  **48 CTests**). **PASS:** exact implementation `46e77ed65afdd9526ee1c63d39724668670cf047`,
  [Actions run 38596955778](https://github.com/k1moradi/RDP-server/actions/runs/38596955778): 48/48 Debug and Release
  CTests on Linux/GCC, macOS/Clang and Windows/MSVC, SDK
  installed downstream consumer, all three ZIP/checksum
  uploads and documentation-policy gate. No prerelease tag.
  **NOT RUN:** owner's local build, real GSS/Kerberos,
  TLS public-key binding, OS admission or desktop.
  **Next:** connect to a trusted GSS provider and independent
  OS authorization before allowing any reply on a socket.
  **Verified Linux GSSAPI framed-token provider increment
  (2026-10-14; CI PASS):** compile the already-staged first-party
  MIT GSSAPI SPNEGO, public-key binding and deny-only credential
  sources behind explicit Linux-only `RDP_SERVER_TEST_LINUX_GSSAPI`.
  The existing GSS acceptor accepts a completed v5/v6 frame from
  `TsRequestFrameReader` synchronously, borrows only within
  the provider call and wipes the frame on return. Early,
  downgraded, malformed or GSS-rejected frames terminate both
  owners; an absent explicit keytab must never fall back to
  host credentials. The portable SDK has no mandatory GSSAPI
  dependency or newly enabled authentication path.
  **PASS:** implementation `36989cebcc6a69b51d1c3f3d5d1f2660417a9865`,
  [CI 38603782133](https://github.com/k1moradi/RDP-server/actions/runs/38603782133):
  Linux/GCC **50/50**, macOS/Clang and Windows/MSVC **48/48**
  CTests in both Debug and Release, SDK downstream consumer,
  three ZIP/checksum packages and documentation-policy. The two
  new Linux-only native GSS rejection suites passed.
  **NOT RUN:** owner-local updated build, live keytab/Kerberos
  credentials, positive GSS/TLS binding, OS admission, external
  client or desktop. **Next:** independently verify real
  configured provider credentials and TLS certificate binding,
  then implement independently authorized OS session admission
  before permitting live MCS responses.
  **Verified TLS->CredSSP frame intake increment (2026-10-14;
  CI PASS):** extend the existing 16 KiB `TsRequestFrameReader`
  with exactly one bounded `SSL_read_ex` per method call,
  pinning a finished server TLS identity, selected certificate,
  cipher and TLS >= 1.2. `Progress` requires immediate caller
  continuation for bytes already buffered inside OpenSSL;
  NeedRead/NeedWrite require actual transport readiness.
  Subsequent coalesced TSRequests remain unread until the
  first is released; reject SSL substitution, manual/TLS
  mixing, malformed DER and EOF terminally and wipe buffers.
  Reuse the existing OpenSSL memory-BIO fixture and add
  **three new** CTests for all fragment splits, coalesced
  envelopes and negative transport/mixed-source boundaries.
  **PASS:** implementation `d2885363502e34e52c71c41342902908b781fd58`,
  [CI 38607049062](https://github.com/k1moradi/RDP-server/actions/runs/38607049062):
  Linux/GCC 53/53, macOS/Clang 51/51 and Windows/MSVC
  51/51 CTests in both Debug and Release; all three
  new cases passed on each platform. SDK downstream
  consumer, ZIP/SHA256 artifacts and docs-policy PASS.
  **NOT RUN:** owner-local build, real GSS credentials,
  TLS CredSSP pubKeyAuth, OS-authorized admission or
  Microsoft desktop connection. The diagnostic remains
  PROTOCOL_SSL and never grants identity. **Next:**
  authenticated GSS binding to the selected TLS
  certificate and independent OS authorization before
  any MCS response or remote desktop admission.
  **Verified TLS-owned GSS provider provenance increment
  (2026-10-14; CI PASS):** MS-CSSP 2.2.1/3.1.5
  requires SPNEGO and encrypted public-key validation
  in the same TLS session. The one `TsRequestFrameReader`
  now exposes server-SSL provenance only for a complete
  TLS-read frame, never synthetic/partial/released DER.
  The Linux `GssapiSpnegoAcceptor` requires this evidence,
  pins the SSL pointer and v5/v6 version across framed
  negotiation, rejects mismatched SSL/version, and
  checks the pinned identity and version again before
  protected-binding GSS unwrap. Rejection erases
  borrowed identity without creating extra buffers
  or granting account/session authority.
  **PASS:** implementation `6e11b25224e1a5e6c3f45778436afc3950a3e866`,
  [CI 38609620612](https://github.com/k1moradi/RDP-server/actions/runs/38609620612):
  Linux/GCC **55/55**, macOS/Clang and Windows/MSVC
  **52/52** CTests in BOTH Debug and Release. Two
  new behavior-named tests (portable TLS provenance
  and Linux-only real-provider fail-closed handoff)
  passed. SDK downstream consumer, three ZIP/checksum
  uploads and documentation-policy also PASS.
  **NOT RUN:** owner's local updated build, real keytab
  or Kerberos tickets, positive GSS context, TLS
  public-key proof, OS authorization, Microsoft client
  and desktop. **Next:** genuine positive Kerberos/GSS
  with selected TLS certificate and interoperable
  MS-CSSP final negoToken+pubKeyAuth phase, followed
  by independent OS authorization before MCS admission.
  **Verified MS-CSSP final combined token/binding processing
  (2026-10-14; CI PASS):** Microsoft's
  [MS-CSSP 3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c)
  requires the last client SPNEGO token and encrypted TLS
  public-key binding together in one TSRequest. The
  first-party v5/v6 framer validates exactly one token,
  encrypted pubKeyAuth, a 32-byte nonce and no authInfo
  or errorCode. The optional Linux GSSAPI provider requires
  a continuing context and pinned SSL/version, accepts
  the final token and demands fully verified Kerberos
  security flags; it rejects a GSS output token that
  cannot be sent in the binding-only server reply,
  then uses confidential GSS unwrap/wrap and the selected
  active TLS certificate to generate a protected reply
  before securely releasing the frame. This is NOT a
  successful Kerberos exchange or desktop admission.
  **PASS:** implementation
  `ad848646391eb7f2dce5c8e2a6238212e7f4e5ae`,
  [CI 38612269453](https://github.com/k1moradi/RDP-server/actions/runs/38612269453):
  Linux/GCC **58/58**, macOS/Clang and Windows/MSVC
  **54/54** CTests in both Debug and Release, including
  all THREE newly registered behavior-named cases.
  SDK install/downstream consumer, ZIP+SHA-256 artifact
  uploads and documentation policy PASS across all systems.
  **NOT RUN:** owner's local new build, positive real GSS
  credentials/keytab, actual TLS pubKeyAuth validation,
  external Microsoft clients, independent OS account
  authorization or real desktop. **Next:** controlled
  positive real GSS/Kerberos and binding interoperability,
  then independent OS authorization before any MCS
  domain replies or desktop activation.
  **Verified bounded TLS server TSRequest reply transport
  (2026-10-14; CI PASS):** per
  [MS-CSSP 2.2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685)
  and [3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c),
  the existing first-party `credssp_tsrequest` module
  now writes one bounded canonical server negoToken
  or GSS-protected pubKeyAuth DER reply over pinned
  finished server TLS. It retains a stable, owned
  byte buffer across OpenSSL WANT_READ/WANT_WRITE,
  never counts unsuccessful writes, prohibits
  conflicting TLS identities or overlapping records,
  and wipes sensitive contents on release/cancel.
  This is transport only: no SPNEGO provider success,
  trusted user identity, OS authorization, NLA
  activation, positive MCS reply or desktop.
  Three NEW behavior-named CTests use real OpenSSL
  memory BIO TLS, including exact wire, WANT_WRITE
  backpressure/retry and terminal error denial.
  **Initial FAIL:** implementation
  `915cd2bfac59d7e775b458b7deed3d94db17ad93`,
  [CI 38614500856](https://github.com/k1moradi/RDP-server/actions/runs/38614500856):
  the backpressure fixture attempted unsupported
  `BIO_set_write_buf_size` on an already paired
  memory BIO; this was test setup failure.
  **PASS:** corrected fixture implementation
  `afa7d737b4ee32c0f0e72bbedd32e6cb9066afd6`,
  [CI 38614808824](https://github.com/k1moradi/RDP-server/actions/runs/38614808824):
  Linux/GCC **61/61**, macOS/Clang and Windows/MSVC
  **57/57** CTests in BOTH Debug and Release,
  including all three new cases, SDK downstream
  consumers, three ZIP/SHA-256 artifact uploads
  and policy gate. Constrained server BIO capacity
  is now established before handshake with no
  weakened assertions. Preexisting Linux Release
  test fixture compiler warning remains nonfatal.
  **NOT RUN:** owner-local new build, real positive
  GSS/Kerberos ticket/keytab and public-key binding,
  OS identity authorization, external RDP client
  or desktop. **Next:** connect the verified transport
  to a real provider-generated GSS exchange, verify
  TLS pubKeyAuth end to end, and independently
  authorize OS session access before any MCS reply.
  **Verified Linux real-GSS-to-TLS server reply handoff
  (2026-10-14; CI PASS):** per Microsoft
  [MS-CSSP 3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c),
  the existing optional real MIT GSS provider
  can now queue its own SPNEGO continuation
  `negoTokens` or confidentially wrapped final
  server `pubKeyAuth` on the original server
  TLS, using the existing bounded nonblocking
  `TsRequestTlsReplyWriter`. The handshake
  requires a real provider output, correct
  stage/version, matching SSL frame provenance,
  idle outgoing writer, and successful final
  client GSS/TLS certificate-bound proof.
  Transient GSS output is cleansed immediately
  after queueing; reject closes all three
  owners. This helper does NOT itself send
  TLS, enable NLA, authorize an OS user,
  generate MCS responses or admit a desktop.
  **PASS:** implementation
  `27e8342aee0e475c3b0854330678e7c7596fc912`,
  [CI 38617602493](https://github.com/k1moradi/RDP-server/actions/runs/38617602493):
  Linux/GCC **64/64** CTests in BOTH Debug
  and Release (all **three NEW** GSS-TLS
  provider response-gate tests PASS),
  macOS/Clang and Windows/MSVC **57/57**
  each in Debug and Release, documentation
  policy PASS, three SDK downstream
  consumers, ZIP/SHA256 package uploads PASS.
  The new tests use actual TLS application
  records and real linked MIT GSSAPI, but
  deliberately assert negative results
  WITHOUT installed Kerberos credentials.
  A preexisting unrelated Linux Release
  `-Wstringop-overflow` in test fixture
  `tests/test_owned_preauth_session.cpp:589`
  remains nonfatal.
  **NOT RUN:** owner-local update build,
  genuine positive keytab/ticket mutual
  Kerberos exchange, live selected-TLS
  pubKeyAuth verification, independently
  authorized OS account/session, external
  Microsoft RDP clients or desktop.
  **Next:** controlled opt-in positive
  Kerberos/GSS+TLS public-key binding,
  then independently checked OS policy and
  single-owner live X.224/MCS transitions.
  **Verified active server TLS certificate identity pin and
  real TLS binding (2026-10-14; CI PASS):** Microsoft
  [MS-CSSP 2.2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685)
  and [3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c)
  bind the client/server proof to the selected TLS
  certificate SubjectPublicKey, 32-byte nonce and
  distinct direction labels. The existing one
  `TsRequestFrameReader` now pins the selected
  server X.509 SHA-256 fingerprint as well as
  `SSL*` on its FIRST real TLS read. It checks
  both before later TLS chunks, after frame
  completion and after release: even a different
  selected certificate on the SAME SSL pointer
  revokes handoff and closes/wipes the frame.
  The existing `credssp_tls_certificate`
  module owns finished TLS >=1.2 server-role/
  cipher/cert checks and active certificate
  SubjectPublicKey hashing, without GSS or
  OS session authority. Three new portable
  CTests use real in-memory OpenSSL TLS, comparing
  both direction-specific live-certificate hashes
  with independent SubjectPublicKey calculations;
  reject other certs, nonces, reflected/mutated
  hashes and invalid TLS roles; and reject
  completed/partial DER after same-SSL cert
  replacement while accepting unchanged identity.
  **Initial FAIL:** implementation
  `d0583c92eb6b6a3517d5e96ea5fd8adc07ee413d`,
  [CI 38619291326](https://github.com/k1moradi/RDP-server/actions/runs/38619291326):
  new test compile failed due to OpenSSL 4-compatible
  `const X509*` source passed to `SSL_use_certificate`.
  **PASS:** correction
  `340ce518d0e84ea94a4d24c295f8fa88e74ccf6d`
  duplicates the test-only certificate with
  `X509_dup` into existing RAII `CertificatePointer`
  and retains all assertions.
  [CI 38619544190](https://github.com/k1moradi/RDP-server/actions/runs/38619544190):
  Linux/GCC **67/67** and macOS/Clang,
  Windows/MSVC **60/60** CTests, BOTH Debug
  and Release; three new cases, installed
  SDK consumers, ZIP/SHA256 uploads,
  documentation-policy PASS. Prior Linux
  Release fixture warning remains nonfatal.
  **NOT RUN:** owner-local new build, positive
  actual Kerberos/GSS service keytab/tickets,
  true GSS unwrap/wrap TLS public-key proof,
  independent OS account authorization,
  Microsoft client or real desktop.
  **Next:** positive controlled Kerberos/GSS
  and TLS binding, then independent OS policy
  before admitting real MCS/desktop.
  **Verified TLS-framed GSS binding-only provenance boundary
  (2026-10-14; CI PASS):** Microsoft
  [MS-CSSP 2.2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685)
  and [3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c)
  require real SPNEGO and encrypted public-key
  proof inside the original established TLS
  transcript. The Linux acceptor's historical
  `processProtectedBinding(SSL*, rawDer)` is
  now permanently deny-only: raw caller-supplied
  bytes, even with an SSL pointer and an
  otherwise authenticated provider, never
  prove TLS record provenance.
  `processFramedProtectedBinding(reader)`
  requires exactly one complete TLS-derived
  v5/v6 binding-only DER frame, unchanged
  pinned SSL/selected X.509 certificate and
  negotiation version, with successful REAL
  GSS context and confidential unwrap before
  nonce/hash comparison and protected server
  response. The existing combined-final and
  new binding-only queue methods now share
  one guarded idle-writer handoff; terminal
  failure closes reader, provider and writer.
  **PASS:** implementation
  `340b25d2352314003053ec19d467b75d578c9dbf`,
  [CI 38623829568](https://github.com/k1moradi/RDP-server/actions/runs/38623829568):
  Linux/GCC **69/69** and macOS/Clang,
  Windows/MSVC **60/60** CTests in BOTH
  Debug and Release; TWO new Linux real
  TLS/GSS-linked denial and outgoing-order
  CTests passed, along with all previous
  regression groups, staged SDK/consumer,
  ZIP/SHA-256 uploads and documentation
  policy. The previously existing Linux
  Release test fixture warning remains
  nonfatal. These tests are **negative-only**
  for GSS authentication. No positive ticket,
  keytab, GSS unwrap success, independently
  authorized OS account, Windows App client
  or real desktop was run.
  **Next:** opt-in controlled genuine positive
  Kerberos/GSS exchange with explicit test
  keytab/client ticket and active TLS binding,
  then independent OS authorization before
  any live MCS/desktop admission.
  **Verified outgoing CredSSP TLS reply certificate continuity
  (2026-10-14; CI PASS):** per Microsoft's
  [MS-CSSP 3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c),
  every canonical v5/v6 `TSRequest` reply must
  remain tied to the actual server TLS-selected
  X.509 public key. The existing
  `TsRequestTlsReplyWriter` now pins one SHA-256
  fingerprint of the selected finished server
  certificate at its FIRST reply queue, in
  addition to its one `SSL*` identity.
  On EVERY subsequent SSL_write_ex readiness
  retry, idempotent Complete, reply release
  and next reply queue it rechecks the
  selected certificate in constant time
  with the existing first-party certificate
  helper. A changed selected certificate
  on the SAME SSL pointer fails terminally,
  closes and wipes pending DER/fingerprint
  BEFORE a new TLS write. Previously emitted
  TLS ciphertext cannot be retroactively
  recalled. No duplicate state controller
  or output encoder was added.
  Three NEW all-platform real TLS CTests
  cover v5/v6 SPNEGO and pubKeyAuth replies
  denied before write with zero delivered
  plaintext after certificate replacement;
  changed certificate after Complete,
  before release and after release, with
  unchanged positive multi-reply reuse;
  and a real 2048-byte memory-BIO
  SSL_ERROR_WANT_WRITE followed by same-SSL
  certificate mutation and no retry.
  **PASS:** implementation
  `53184c7e4fdfb1c01f287933ff4ca0a6fdf63c0a`,
  [CI 38674532102](https://github.com/k1moradi/RDP-server/actions/runs/38674532102):
  Linux/GCC **72/72**, macOS/Clang
  and Windows/MSVC **63/63** CTests
  in BOTH Debug and Release; all three
  new cases, documentation policy,
  installed SDK downstream consumer
  and all three ZIP/SHA256 package
  uploads PASSED. Previous unrelated
  nonfatal Ubuntu Release test fixture
  `-Wstringop-overflow` remains.
  **NOT RUN:** owner's local build,
  positive real service-keytab/client-ticket
  Kerberos/GSS and confidential
  active-TLS pubKeyAuth, independently
  authorized OS account/session,
  Windows App or actual desktop.
  **Next:** explicitly authorized
  controlled genuine Kerberos/SPNEGO
  and active TLS certificate binding,
  then independently audited OS policy
  before any MCS/session admission.
  **Verified Linux GSS acceptor transcript-wide TLS certificate pin,
  with unrun opt-in genuine Kerberos probe (2026-10-14):** per
  [MS-CSSP 3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c)
  and [RFC 4178](https://www.rfc-editor.org/rfc/rfc4178.html),
  the existing Linux MIT GSS provider now pins the first
  selected server TLS X.509 DER SHA-256 fingerprint inside
  the acceptor itself, IN ADDITION to its original SSL*
  and CredSSP v5/v6 version. Every later TLS-framed
  SPNEGO request, binding-only or combined-final proof,
  confidential GSS hash check and queued server
  binding response rechecks the exact selected certificate,
  even if the caller replaces the frame reader between
  rounds on the SAME SSL*. Terminal reject cleanses
  the fingerprint and authenticated principal and
  closes the GSS context and explicit credentials.
  No new session controller or OS account authority.

  One separately gated Linux-only acceptance probe
  is compiled into the original TLS fixture and
  registered ONLY under `RDP_SERVER_TEST_REAL_KERBEROS=ON`
  with an explicitly supplied `TERMSRV/host@REALM`,
  `FILE:/` service keytab and separate `FILE:/`
  client ticket cache. It invokes real MIT
  GSS initiator/acceptor through TLS application
  records, GSS-confidential v5/v6 binding-only
  verification, and a new-reader, SAME-SSL
  X.509 swap rejection. No KDC or desktop is started;
  no default host keytab/cache or client credential
  contents are imported into the project.
  Binding-only proof is an internal diagnostic,
  NOT normative combined-last-token MS-CSSP
  interoperability or independently authorized
  account/session acceptance.

  **PASS:** implementation
  `1f6740452f27332303ded71d4f5f23bb599b9726`,
  [CI 38678010820](https://github.com/k1moradi/RDP-server/actions/runs/38678010820):
  Linux/GCC **72/72** and macOS/Clang,
  Windows/MSVC **63/63** standard CTests,
  EACH Debug and Release, three installed SDK
  downstream consumers, ZIP/SHA256 package
  uploads and documentation-policy PASS.
  The Linux test executable compiles the new
  GSS probe code, but the opt-in case was
  NOT registered or executed with CI credentials.
  Existing Ubuntu Release nonfatal
  `-Wstringop-overflow` at TLS fixture
  line 594 remains.
  **NOT RUN:** actual positive keytab/client
  ticket authenticated GSS handshake,
  GSS-confidential pubKeyAuth probe,
  real Microsoft combined-final client,
  owner's local build, independent OS
  authorization, live RDP server or desktop.
  **Next:** with explicit authority and
  isolated real ticket/keytab, RUN the
  opt-in positive provider/TLS-binding probe
  and close any MS-CSSP combined-last-token
  interoperability gaps before independent
  OS session admission.
  **Partial real-provider CredSSP v6 SPNEGO failure dispatch
  (2026-10-15; CI PASS):** the existing
  Linux MIT GSS acceptor now marks a provider/policy
  rejection only when the configured, explicit-keytab
  `gss_accept_sec_context` was actually called on a
  TLS-derived and valid SPNEGO negotiation request.
  For version 6 ONLY, recheck the original SSL and
  selected X509 SHA256 fingerprint after GSS terminal
  cleanup; then enqueue fixed `STATUS_LOGON_FAILURE`
  using the existing single 15-byte DER error encoder
  and nonblocking `TsRequestTlsReplyWriter`.
  `SpnegoStatus::FailureQueued` means error queued,
  GSS credentials/principal already wiped, but NO
  SSL record written or authenticated session.
  Missing keytab, invalid DER/token, wrong/changed TLS,
  version 5, failed local memory or pending writer
  MUST silently terminate, not synthesize GSS denial.
  Extend original preauth TLS fixture with one default
  Linux GSS-only negative CTest, and a separately
  registered opt-in genuine MIT rejection + TLS
  15-byte error oracle (requires explicitly authorized
  service keytab and ticket cache). Default CTest
  counts: **77 portable / 87 Linux GSS** (prior 77/86);
  opt-in positive credentials and failure delivery
  still **NOT RUN** without owner authorization.
  Baseline `ebc794738552f5411ebe4d2222000f8ae94183f2`,
  [Actions 38708915869](https://github.com/k1moradi/RDP-server/actions/runs/38708915869)
  PASS; owner reports **77/77** local on prior main.
  **PASS:** implementation `b4c9f8eff73e701130cc8b92b6c1fda50aedcf11`,
  [Actions 38710937644](https://github.com/k1moradi/RDP-server/actions/runs/38710937644):
  Linux/GCC **87/87**, macOS/Clang and Windows/MSVC
  **77/77** full CTests in EACH Debug and Release,
  including new Linux GSS fail-closed behavior;
  installed SDK downstream consumer, ZIP/SHA256
  artifacts and documentation policy PASS.
  Prerelease publication SKIPPED (no release tag).
  **NOT RUN:** owner-local incremental compile/CTest,
  opt-in configured real GSS rejection/errorCode
  delivery, full Microsoft combined-last-token,
  OS admission, real RDP client or desktop.
  **Next:** owner explicitly provisions
  isolated real Kerberos keytab and client tickets
  before opt-in provider/TLS proof and independent
  OS authorization, then the one live CredSSP owner
  can govern a complete authenticated negotiation.
  **Verified version-6 CredSSP errorCode server reply transport
  (2026-10-14; CI PASS):** [MS-CSSP 2.2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685)
  and [3.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c)
  specify a server `TSRequest.errorCode`
  on failed SPNEGO at protocol versions
  3/4/6. The current v5/v6-only native
  reply codec now supports ONLY a
  version-**6** negative NTSTATUS
  failure record. It emits exact
  15-byte DER with [0] version and
  [4] signed 32-bit failure: the fixed
  `STATUS_LOGON_FAILURE` (0xC000006D)
  or `STATUS_NOT_SUPPORTED` (0xC00000BB).
  It rejects v5/legacy versions,
  unknown codes, mixed SPNEGO/pubKeyAuth/
  authInfo/nonce fields and any success
  status. The existing, single
  `TsRequestTlsReplyWriter` queues
  canonical negotiated tokens, sealed
  bindings, and failures through ONE
  private encoder-owned guarded queue.
  It retains TLS SSL*/selected X509
  fingerprint, nonblocking retry
  pointer, one-pending-response limit,
  and wipe-on-error. A completed
  failure is released to CLOSED,
  never followed by a success response.
  FOUR new portable behavior cases
  check exact independent DER oracles,
  rejected versions/fields/nonminimal
  signed integer, real TLS delivery
  and terminal failure behavior, and
  pending-reply/wrong-TLS/same-SSL
  certificate-swap rejection.
  **PASS:** implementation
  `6925ac11a49b3d71a6ffa120b688ca95a0a088af`,
  [CI 38683205424](https://github.com/k1moradi/RDP-server/actions/runs/38683205424):
  Linux/GCC **76/76**, macOS/Clang
  and Windows/MSVC **67/67** CTests
  in BOTH Debug and Release,
  ALL four new tests PASSED on
  all three OS, installed SDK
  consumer, ZIP/SHA256 packages
  uploaded and docs policy passed.
  The earlier unrelated nonfatal
  Ubuntu Release `-Wstringop-overflow`
  in `test_owned_preauth_session.cpp:594`
  persists.
  **NOT RUN:** owner's local build,
  opt-in successful real Kerberos
  service keytab and client ticket,
  automatic server GSS failure
  dispatch to this optional message,
  authenticated TLS public-key
  binding, independent OS session
  policy, Microsoft RDP client
  or usable desktop.
  **Next:** controlled opt-in
  real Kerberos/GSS and active-TLS
  binding proof; when authorized,
  wire terminal failure response
  to explicit GSS state without
  promoting it to authentication
  success; independent OS admission
  before real MCS or desktop.
  **Verified bounded DER intake hardening (CI PASS):**
  reorder the existing CredSSP first-tag check before the
  end-of-input NeedMore return so a single wrong tag byte
  immediately closes the frame owner; a valid single 0x30
  byte continues waiting for the length. The existing
  `security.credssp-stream-rejections` CTest exhausts
  all 255 invalid first tags, exact consumption, irreversible
  close and the valid-prefix control. Based on prior main
  `1cce799dc1aa7a55e3cb343dd09823052a1c23a6`.
  **PASS:** implementation `36926462d34726f355279367a2ba2f27e93d2095`,
  [CI 38684306429](https://github.com/k1moradi/RDP-server/actions/runs/38684306429)
  Linux/GCC, macOS/Clang, Windows/MSVC full Debug/Release,
  documentation-policy and SDK/package gates. The owner also
  provided a single-build-root Linux Debug **67/67 PASS** log
  on that exact commit. Real credentials, external clients and
  desktop acceptance remain NOT RUN.
  **Next:**
  continue explicit authenticated GSS/OS admission gates
  separately; no external-client/desktop acceptance claimed.
  **Verified partial OFFLINE connection-finalization fixed PDU decoding (2026-10-15;
  CI PASS):** after the existing canonical
  complete Share Control + uncompressed Share Data parsing,
  the first-party C++23 MCS module recognizes a strict
  22-byte `TS_SYNCHRONIZE_PDU` (type2 0x1f,
  messageType 1, raw targetUser) and 26-byte
  `TS_CONTROL_PDU` (type2 0x14, action
  Request/Granted/Detach/Cooperate, raw grantId and
  controlId). Reuse Microsoft decrypted Client Synchronize,
  Cooperate, Request Control and Server Granted Control
  wire examples. Reject malformed/truncated/extra bytes,
  unknown actions, wrong type/stream/version and
  compressed payloads. All are pure borrowed-input
  syntax without heap work, side effects, channel
  assignment or control activation. A forged
  client-shaped Granted action remains syntax only;
  an authenticated session owner must enforce direction,
  ordering, licensed share and assigned channel.
  Four behavior-named portable CTests added to the
  existing MCS registry; expected **81** portable,
  **91** Linux GSS-enabled (77/87 previously).
  Parent `1c4dc32ef2bb3d1bc86aeffa1bcc7d10f57ab8ed`
  passed [CI 38711285093](https://github.com/k1moradi/RDP-server/actions/runs/38711285093);
  owner confirms **77/77** locally on that parent.
  **PASS:** implementation `c14f47bcd63faaa37761b87ffab06388c1e1bfe7`,
  [CI run 38712823857](https://github.com/k1moradi/RDP-server/actions/runs/38712823857):
  Linux/GCC **91/91**, macOS/Clang and Windows/MSVC
  **81/81** full CTests in BOTH Debug and Release,
  including all four new Sync/Control behaviors;
  documentation policy, staged installed CMake SDK
  consumer and three ZIP/SHA256 package uploads
  PASS. Prerelease publication SKIPPED (no tag).
  **NOT RUN:** owner-local exact-code build/CTest,
  real credential-backed Kerberos/GSS/TLS,
  independently authorized OS session, actual
  Share Activation, channel state, external clients,
  DVC/H.264 graphics or usable desktop.
  **Next:** obtain
  explicitly authorized isolated Kerberos test keytab
  and client ticket cache, prove full GSS/TLS binding,
  add independent OS authorization, and only then
  transition the one session owner through finalization.
  **Partial OFFLINE Demand/Confirm Active capability envelope
  intake (2026-10-15; CI PASS):**
  Extend the first-party C++23 Share Control decoder with
  Demand Active / Confirm Active syntax per MS-RDPBCGR
  2.2.1.13.1.1, 2.2.1.13.2.1 and 2.2.1.13.1.1.1.
  Validate mandatory Confirm originatorID=1002,
  exact sourceDescriptor and combinedCapabilities
  lengths, counted TS_CAPS_SET envelopes (LE16
  size includes 4-byte type/length header), ignored
  pads and the exact trailing Demand sessionId.
  Borrow source/capability ranges from caller storage,
  never copy or allocate, reject incomplete, surplus,
  invalid size and count fields before exposing views.
  Unknown capability IDs remain opaque; four-byte
  FONT envelope mirrors a published Microsoft server
  compatibility quirk but is not typed negotiation.
  Two behavior-named portable CTests are added to
  the original MCS registry. Expected **83** portable
  and **93** Linux GSS-enabled (81/91 before).
  Baseline main `ea258bfcc4a8d8d759a9bc1a882c4f0121959296`
  passed [CI 38713180113](https://github.com/k1moradi/RDP-server/actions/runs/38713180113),
  and owner reports **81/81** local PASS for prior head.
  **PASS:** implementation `5125fcc68f7e3e9fdd496f8504a17a3a7a251953`,
  [Actions 38714673332](https://github.com/k1moradi/RDP-server/actions/runs/38714673332):
  Linux/GCC **93/93**, macOS/Clang and Windows/MSVC
  **83/83** full CTests in EACH Debug and Release;
  both new Demand/Confirm capability tests, project
  documentation-policy, SDK staged installed consumer,
  and ZIP/SHA256 package artifacts PASS. Prerelease
  publishing SKIPPED because this is not a tagged release.
  **NOT RUN:** owner-local new-head CTest, genuinely
  authorized Kerberos/TLS binding, independent OS
  session policy, live Share Active lifecycle, capability
  negotiation, H.264, input or external clients.
  **Next:** isolated explicitly
  authorized genuine Kerberos and independent OS admission
  before binding a negotiated capability set into the
  sole authenticated session owner.
  **Verified offline server Demand Active writer (2026-10-15;
  corrected CI PASS):** complement the existing bounded
  Demand/Confirm Active parser with one direct caller-buffer
  Demand Active Share Control serializer. Write server
  pduSource 1002, shareID, source descriptor, validated
  counted capability envelopes, and trailing sessionId.
  Reuse ONE validator for every nested TS_CAPS_SET on
  both inbound and outbound paths. Reject overlong
  lengths, malformed counts/envelopes, the reserved
  0x8000 FlowPDU length, insufficient output and
  input/output overlap BEFORE any mutation. No internal
  allocation; preserve unused output bytes and treat
  unknown capability IDs as opaque, not supported.
  Two behavior-named CTests in the original fixture
  verify exact 38-byte golden output, round-trip
  decoding, 32767/32769/65535 byte boundaries and
  fail-closed atomic rejection. Expected **85**
  portable, **95** Linux GSS (prior 83/93).
  **Initial CI failure:** implementation `5c0a790ba317f592da21f457842ba6a39a6bd553`,
  [Actions 38716458988](https://github.com/k1moradi/RDP-server/actions/runs/38716458988)
  failed `transport.share-demand-active-encode-wire`:
  the old decoder golden has deliberately nonzero
  ignored `pad2Octets`, while the server writer
  correctly emits zero padding. The new rejection
  suite PASS; fix the golden to canonical zero pad
  without altering production semantics. Corrected
  commit `ec7261e059e699f23511f9d17d0a77762bf5d337`
  [CI 38716746326](https://github.com/k1moradi/RDP-server/actions/runs/38716746326)
  **PASS**: Linux/GCC **95/95**, macOS/Clang and
  Windows/MSVC **85/85** full CTests in EACH Debug
  and Release, plus SDK installed downstream consumer,
  ZIP/SHA256 artifacts and documentation-policy.
  All new writer and rejection tests PASS; the
  canonical-pad test oracle was the only change.
  Baseline `659e0b816e8055f4bec7c87bda2816d8a614b9af`
  passed [CI 38715062876](https://github.com/k1moradi/RDP-server/actions/runs/38715062876);
  owner reports **83/83 local PASS** on the parent.
  **NOT RUN:** owner-local new-head build/CTest,
  authorized real Kerberos/TLS binding, independent
  OS admission, actual negotiated capabilities,
  share activation, licensing, MCS/TLS send,
  external client, H.264 graphics or desktop.
  **Next:** owner-local full CTest, then
  isolated owner-authorized Kerberos/TLS proof
  and separate OS session admission before ANY
  live capability negotiation or Demand Active send.
  **Verified partial OFFLINE server finalization output (2026-10-15;
  CI PASS):** reuse existing first-party
  C++23 Share Data/Control owner to serialize the 22-byte
  server Synchronize and 26-byte server Control Cooperate
  and Granted packets. One common private fixed header
  writer sets source 1002, Share Data type/stream,
  uncompressed lengths and canonical zero padding.
  Synchronize preserves raw targetUser, including the
  historically uninitialized Microsoft example, rather
  than trusting it as a joined MCS channel. Control
  prohibits client-only Request/Detach actions, requires
  zero ID for Cooperate and an assigned 1001..65535 user
  channel for Granted, with server controlId 1002.
  Preflight all output sizes and action/ID rules before
  any bytes change, and preserve suffix/no allocation.
  Two new behavior-named test groups compare byte-exact
  Microsoft-derived canonical oracles, round-trip the
  existing independent decoders, exercise boundary IDs
  and all insufficient output buffers/invalid actions.
  Expected **87 portable / 97 Linux GSS** CTests
  (previous 85/95). Parent main
  `f48332e4465b6915e1683e5ed4f3aae767d3c777`
  passed [CI 38717067457](https://github.com/k1moradi/RDP-server/actions/runs/38717067457);
  owner reports **85/85** local PASS on the parent.
  **PASS:** exact implementation `be87f4ba35289d881a161c0d03ac28c592f3a44f`,
  [Actions 38718197674](https://github.com/k1moradi/RDP-server/actions/runs/38718197674):
  Linux/GCC **97/97**, macOS/Clang and Windows/MSVC
  **87/87** full CTests in EACH Debug and Release;
  both new writer suites, installed SDK downstream
  consumer, ZIP/SHA256 packages, and documentation
  policy PASS. Prerelease publishing SKIPPED
  because no version tag was created.
  **NOT RUN:** owner-local new-code tests, real opt-in
  GSS/Kerberos/TLS binding, independently approved OS
  session, joined channels, licensing, live network,
  share activation, graphics or user input.
  **Next:** owner-local single-build-root CTest,
  followed by explicitly authorized isolated
  Kerberos/TLS positive acceptance and independent OS
  authorization before finalization can be dispatched
  from a single live session owner.
  **Partial OFFLINE Demand/Confirm Active transcript correlation
  (2026-10-15; CI PASS):** the existing
  first-party C++23 MCS/Share module now correlates one
  complete server Demand and one complete client Confirm
  after reusing the canonical exact-length Active parser.
  It checks server source 1002, the separately supplied
  1001..65535 client user source (65536 cannot fit
  Share Control pduSource), mandatory Confirm originator
  1002 and matching shareIDs. Success explicitly means
  `ConsistentSyntaxOnly`, NEVER that the client is the
  authenticated MCS sender, its capabilities negotiated,
  its OS account permitted, or the session activated.
  Two behavior-named portable test groups exercise
  fixture/serializer correlation, malformed transcripts,
  mismatched share and assigned user IDs, and opaque
  capability disagreement; expected **89 portable /
  99 Linux GSS-enabled** full CTests (prior 87/97).
  Baseline main `0e508cfad519d7f9f9f7cb0dd5e54b1c0118e465`
  passed [CI 38718555326](https://github.com/k1moradi/RDP-server/actions/runs/38718555326);
  owner reports **87/87 local PASS** on that head.
  **PASS:** exact implementation `d83549d489be2b8e49855429693d2c5d4b1a0a71`,
  [Actions 38719691636](https://github.com/k1moradi/RDP-server/actions/runs/38719691636):
  Linux/GCC **99/99**, macOS/Clang and Windows/MSVC
  **89/89** full CTests in EACH Debug and Release,
  including both new Active-correlation cases;
  docs policy, installed SDK consumer and all
  three ZIP/SHA256 artifacts PASS. Untagged
  prerelease publication SKIPPED.
  **NOT RUN:** owner-local new-head build/CTest,
  real Kerberos/TLS pubKeyAuth with isolated
  tickets/keytab, independently audited OS
  authorization, licensed capability negotiation,
  activated share or desktop.
  **Next:** owner-local single-build-root CTest,
  then controlled real GSS/TLS and independent OS identity
  before a single authenticated owner may enforce
  activation order and dispatch any channel traffic.

  **Verified partial OFFLINE finalization transcript correlation (2026-10-15;
  exact-head CI PASS):** The original first-party
  Share Data parsers now support zero-allocation
  `correlateRdpFinalizationExchange` for six complete PDUs:
  client Synchronize/Cooperate/Request and server
  Synchronize/Cooperate/Granted. Each must match a caller-provided
  expected share ID and role-specific 1002 server or assigned
  1001..65535 client user source; client Request/Cooperate IDs
  must be zero, server Cooperate IDs zero, and Granted must
  address the expected client channel and server control channel.
  The server Synchronize targetUser is deliberately opaque
  because Microsoft examples include an uninitialized value.
  The six named slots are **not evidence of temporal ordering,
  actual MCS sender provenance, CredSSP/TLS identity, independent
  OS permission, licensing, capability agreement or activation**.
  No second state owner, listener or transport output is added.
  Two behavior CTests cover Microsoft examples, independent
  encoder outputs, all six truncation boundaries, extra bytes,
  role spoofing, share mismatches, invalid actions/IDs and
  unsupported compression. Expected **91 portable / 101
  Linux GSS** CTests (prior verified 89/99). Baseline main
  `7777cc92a35cb94193eea4980285dd8153c49648`,
  prior implementation `d83549d489be2b8e49855429693d2c5d4b1a0a71`
  [CI 38719691636](https://github.com/k1moradi/RDP-server/actions/runs/38719691636)
  PASS on Linux, macOS, Windows and docs/SDK; owner reports
  **89/89 local PASS** on previous code, without full logs/SHA.
  **PASS:** exact implementation `27996f24e5fbb497c0bee37756d34551d1a47e47`,
  [Actions 38735353873](https://github.com/k1moradi/RDP-server/actions/runs/38735353873):
  Linux/GCC **101/101** and macOS/Clang, Windows/MSVC
  **91/91** registered CTests in EACH Debug and Release.
  Both new behavior suites, documentation-policy, SDK
  installed downstream consumer and ZIP/SHA256 packaging
  and uploads PASS; untagged prerelease SKIPPED.
  **NOT RUN:** owner-local updated build/CTest,
  real Kerberos/TLS binding, independently authorized OS user,
  live ordered encrypted finalization, licensed share,
  Microsoft client or desktop. **Next:** owner-local single-root CTest, then
  controlled real GSS/TLS and independent OS admission
  before any live PDU dispatch.

  **Partial TLS-selected-certificate continuity gate (2026-10-15;
  new-head CI NOT RUN at authoring):** The existing
  `PreauthConnectionStream` now pins the SHA-256 digest
  of the selected completed OpenSSL server X.509 certificate
  when the X.224 Confirm-to-TLS handshake is accepted,
  using the already maintained first-party CredSSP TLS
  certificate helper. Before every later direct TLS MCS/GCC
  receive callback, reject a changed certificate EVEN when
  the borrowed `SSL*` remains the same; do not read any more
  decrypted MCS bytes. Close/reset the pin and buffered state
  on all terminal paths. TLS provider/socket ownership and
  event-loop confinement remain unchanged. Direct synthetic
  plaintext parser methods remain diagnostics, not trusted
  TLS/authenticated admission. Reuse the existing real
  OpenSSL memory-BIO fixture to test WANT_READ, partial
  TPKT continuation, complete 416-byte Microsoft frame,
  and an in-place certificate substitution both before
  first read and after a partial TLS frame. Two additional
  behavior-named portable CTests: expected **93 portable /
  103 Linux GSS** (prior 91/101). The parent
  `6d5148a615e22d82d263437be8547a131cfe036e`
  retains the previous implementation
  `27996f24e5fbb497c0bee37756d34551d1a47e47`
  with [CI 38735353873](https://github.com/k1moradi/RDP-server/actions/runs/38735353873)
  PASS (91 portable, 101 Linux GSS in Debug/Release).
  Owner reports 91/91 local tests PASS on previous code,
  without a matching log or exact local SHA. **NOT RUN:**
  new-head CI, owner-local compile/CTest, externally
  provisioned real GSS/Kerberos TLS public-key binding,
  independent OS admission, authenticated MCS session,
  Microsoft client, licensed share or desktop. This is
  defense in depth ONLY; a fingerprint is not authentication.
  **First exact-head CI FAIL:** implementation
  `5b1c9790b772923a4a4437d4f4bef4ec7f404d88`,
  [Actions 38738637457](https://github.com/k1moradi/RDP-server/actions/runs/38738637457)
  failed Debug compilation on Linux, macOS and Windows:
  a new test-only forward declaration in an anonymous
  namespace did not refer to the existing file-scope
  `substituteCredSspReplyCertificate`, creating
  ambiguous function calls. The first error is
  `tests/test_owned_preauth_session.cpp` in the
  existing TLS reply tests; no production compile
  error was identified. Release/CTest/SDK NOT RUN.
  **Correction verified:** test-only fix
  `850a6e9b7f2bc0a25854d31e02d0ed25332989b3`,
  [CI 38738957048](https://github.com/k1moradi/RDP-server/actions/runs/38738957048),
  relocates the two new test bodies below the original
  helper definition and removes the ambiguous prototype.
  No production code or assertions were changed.
  **PASS:** Linux/GCC **103/103**, macOS/Clang and
  Windows/MSVC **93/93** CTests in EACH Debug and
  Release, both new certificate tests, documentation
  policy, staged SDK/downstream consumer, and ZIP/SHA256
  packages/uploads. Release publishing SKIPPED (no tag).
  **NOT RUN:** owner-local updated build/CTest, positive
  genuine Kerberos/TLS public-key binding, independent
  OS session authorization, external RDP client or desktop.
  **Next:** owner-local one-root CTest, then separately
  authorized real GSS/TLS and OS identity acceptance.
  **Verified partial OFFLINE General Capability Set decoding (2026-10-15;
  exact-head CI PASS):** Extend the existing
  Demand/Confirm Active Share Control decoder with one independent
  allocation-free semantic extraction of the 24-byte
  MS-RDPBCGR 2.2.7.1.1 `TS_GENERAL_CAPABILITYSET`. First reuse
  the canonical complete-PDU and counted-envelope validator;
  scan the borrowed capability list for exactly one General
  (type 1), reject absent/duplicate/incorrect size, invalid
  0x0200 protocolVersion and non-Boolean refresh/suppress
  support values. Preserve OS IDs, compression metadata
  and extraFlags without pretending they have been negotiated;
  ignore `pad2OctetsA` and skip unknown sibling capability
  types. The existing generic envelope parser remains
  permissive for artificial/opaque capabilities.
  Two new behavior-named CTests reuse the MCS executable
  and Microsoft published General capability bytes, covering
  exact server Demand output, independent client Confirm,
  ignored pad/unknown flags, all truncation boundaries,
  trailing bytes, invalid layouts, absent/duplicate
  General, version and Boolean errors. Expected **95
  portable / 105 Linux GSS** full CTests (previous 93/103).
  Previous code `850a6e9b7f2bc0a25854d31e02d0ed25332989b3`
  passed [CI 38738957048](https://github.com/k1moradi/RDP-server/actions/runs/38738957048):
  Linux 103/103; macOS/Windows 93/93 each Debug/Release;
  owner reports **93/93 local PASS** on preceding code
  (no exact local SHA/log supplied). Baseline main
  `911e4d3a4459f070588aadc6380d54cc2efda7f5`.
  **PASS:** implementation `3625b0daadef1f470bc0b23b3b2aff9106750a6a`,
  [Actions 38742975505](https://github.com/k1moradi/RDP-server/actions/runs/38742975505):
  Linux/GCC **105/105**, macOS/Clang and Windows/MSVC
  **95/95** registered CTests in EACH Debug and Release.
  Both new General capability wire/rejection cases passed
  on all platforms. Documentation-policy, staged SDK
  installation/downstream consumer, ZIP/SHA256 packages
  and uploaded artifacts PASS. Prerelease SKIPPED (no tag).
  **NOT RUN:** owner-local new compile/CTest,
  isolated positive genuine Kerberos/TLS, independent OS
  admission, licensed capability *agreement*, graphics codec,
  Microsoft client or desktop. The new parser makes no
  claim that extraFlags represent negotiation/permission.
  **Next:** owner single-root full CTest, then separately
  authorized real GSS/TLS and OS session identity before
  ANY live capability dispatch.

  **Verified partial OFFLINE Bitmap Capability Set parsing (2026-10-15;
  exact-head CI PASS):** Reuse the same existing
  MS-RDPBCGR 2.2.1.13.1.1 Demand/Confirm Active exact-PDU parser
  and counted TS_CAPS_SET envelopes to extract precisely one
  28-byte MS-RDPBCGR 2.2.7.1.2 Bitmap Capability Set
  (CAPSTYPE_BITMAP=2). Reject missing, duplicate, wrong-size,
  zero desktop dimension, invalid desktopResizeFlag (not 0/1),
  absent mandatory bitmap compression support (MUST=1)
  and absent multiple-rectangle support (MUST=1).
  Do not interpret pad2octets/pad2octetsB, legacy
  1/4/8-bpp receive flags or highColorFlags; preserve raw
  drawingFlags and preferredBitsPerPixel without selecting
  a graphics path. The helper is allocation-free and
  retains no source views, surface buffers or session state.
  Reuse the existing MCS native test binary and CTest registry
  for two new behavior suites exercising Microsoft's independent
  28-byte server Bitmap oracle, round-trip server writer, client
  Confirm, unknown sibling/pad/drawing flags, truncation/trailers,
  missing/duplicate/incorrect sizes, zero dimensions, resize
  and required-support failures. Expected **97 portable /
  107 Linux GSS** CTests (previous 95/105).
  Parent main `39480cb88de6b80277b9c2621ca8ddb41651dfee`
  follows confirmed implementation
  `3625b0daadef1f470bc0b23b3b2aff9106750a6a`:
  [CI 38742975505](https://github.com/k1moradi/RDP-server/actions/runs/38742975505)
  Linux **105/105**, macOS and Windows **95/95**
  Debug/Release PASS, SDK and docs-policy PASS. The owner
  reports **95/95 local PASS** on preceding code, without
  a matching complete log/local SHA.
  **PASS:** exact implementation
  `89ffef98b4f27ad2947b4629c9eefa49b64152a7`,
  [Actions 38746309146](https://github.com/k1moradi/RDP-server/actions/runs/38746309146):
  Linux/GCC **107/107**, macOS/Clang and Windows/MSVC
  **97/97** CTests in EACH Debug and Release;
  both new Bitmap wire/rejections cases, installed SDK
  consumer, ZIP/SHA256 packaging/uploads and docs-policy PASS.
  Prerelease SKIPPED (no version tag).
  **NOT RUN:** owner-local current-head compile/CTest; real
  Kerberos/CredSSP/TLS binding, MCS sender provenance,
  independent OS session admission, licensed capabilities,
  desktop/graphics and external RDP client.
  Even mandatory Bitmap support in one packet does NOT
  grant authority or bitmap/H.264 dispatch.
  **Next:** owner-local one-root full CTest, then
  independently authorized genuine GSS/TLS and OS
  identity before any live graphics or MCS traffic.
- [ ] Implement licensing, capabilities/share activation, virtual-channel
  routing, graphics delivery, keyboard/pointer and correct lifecycle.
  **Gate A session acceptance (NOT RUN):** integrate existing offline
  serializers/parsers into one live, authenticated MCS attach/join,
  licensing, capabilities, Demand/Confirm Active, finalization and
  disconnect path with outbound TLS write completion, membership
  checks and bounded cancellation. Record a real Microsoft-client
  post-auth share activation before treating this as functional.
  **R3 Channel Join delivery gate (2026-10-15; exact-SHA CI PASS):**
  In the existing MCS module, a single event-loop-affine, bounded component
  tracks up to 33 assigned Channel Join Requests in arrival order, while
  one existing outbound writer serializes each 15-byte confirmation.
  Confirmation membership becomes true only after exact accepted-byte
  completion. Duplicate pending/already-joined requests are ignored;
  malformed/foreign joins, excess callbacks and cancellation fail closed.
  Independent reply and partial-write slice receipts prevent stale callbacks
  from advancing another reply or re-counting previously accepted bytes.
  Joined inbound SendData membership requires the attached UserId and a
  fully confirmed allocated channel; it grants no TLS, R2 identity/OS
  authorization, license, capability, reassembly or application permission.
  Eight NEW dedicated cases in the existing MCS executable and shared
  CTest registry cover completion, denial, duplicates, batching, joined
  SendData, stale replies and stale partial-write slices.
  **PASS (limited):** local GCC 14.2 C++23 ASan/UBSan stand-in 8/8 and
  Clang 17 C++23 ASan/UBSan 8/8, using a reduced parser/encoder fixture.
  **PASS (exact implementation SHA):**
  `469f49e5d4621017016a06095a17ca7cbfc10182`,
  [Actions 38794591251](https://github.com/k1moradi/RDP-server/actions/runs/38794591251):
  Linux/GCC **124/124** and macOS/Clang, Windows/MSVC **114/114**
  full CTests in BOTH Debug and Release. All eight new R3 CTests,
  documentation-policy, installed SDK consumer, ZIP packaging and
  SHA256 artifact checks PASS. Prerelease SKIPPED (no version tag).
  **NOT RUN:** owner exact-SHA Linux/X11, MSYS2 CLANG64/Clang23
  and macOS27 CTests, real TLS/CredSSP/OS-admitted Microsoft-client
  activation, licensed session or desktop.
  **Next:** compose the existing R1 writer and genuine R2 OS-authorized
  TLS/CredSSP decision into one admission-gated R3 MCS domain dispatcher.
  **Gate A/M2 is NOT accepted** from this bookkeeping or synthetic tests.
  **R3 outbound joined-channel envelope (2026-10-15; partial CI PASS):**
  The same post-attach join gate now wraps the existing T.125 server
  SendDataIndication encoder to refuse unjoined, queued, partially joined
  or closed channel IDs without output modification. Existing checked
  PER size, priority, segmentation and buffer/overlap rules are reused.
  Two new central MCS CTests check byte-exact output and fail-closed
  denials. Full project CTest and exact-SHA Actions NOT RUN at authoring.
  Membership is NOT R2 OS admission, TLS security, licensing, capability
  negotiation or data dispatch. R3 Gate A/M2 remains open.
  **R3 exact-SHA hosted verification (2026-10-15):**
  [Actions 38796333656](https://github.com/k1moradi/RDP-server/actions/runs/38796333656)
  built this implementation SHA: Linux/GCC **161/161** and
  macOS/Clang **150/150** full CTests PASS in Debug and Release,
  including both new R3 cases; docs policy and downstream SDK PASS.
  Windows/MSVC compiled and both new R3 CTests PASS, but full Debug
  was **157/158 FAIL** at unrelated R10
  `runtime.validates-configuration-comments-crlf` (expected exit 0,
  observed 3); Windows Release **NOT RUN** because Debug failed.
  Tracked in [R10 CI bug #10](https://github.com/k1moradi/RDP-server/issues/10).
  Owner MSYS2 CLANG64/Clang23, macOS27 and Linux/X11 exact-SHA
  independent tests and real OS-authorized RDP remain **NOT RUN**.
  **R3 R1-to-R2 MCS session denial boundary (2026-10-15; CI NOT RUN at authoring):**
  R1's existing bounded first decrypted Connect-Initial diagnostic now
  passes one complete packet through the R3-owned `McsSessionLifecycle`.
  This noncopyable object embeds the sole bounded Channel Join gate and
  checks the production MCS/GCC/domain parser; absent genuine R2
  TLS-bound, independently OS-authorized evidence, it ALWAYS terminates
  with no Connect Response, Attach Confirm, Channel Join, licensing or
  SendData. Even a valid encrypted packet is **not** user admission.
  Subsequent domain PDUs (Erect/Attach/Join/SendData) are explicitly
  rejected before R2; a valid Disconnect closes without advancement.
  Every malformed input and late re-entry is terminal, with no output or
  inherited channel membership. Two new dedicated central CTests cover
  first Connect-Initial denial and premature domain/teardown ordering.
  **NOT RUN at authoring:** exact-SHA hosted CI, owner three-platform,
  real GSS plus OS authorization, Microsoft-client and desktop.
  **Next:** R2 must deliver an unforgeable, live, TLS-bound OS session
  authorization interface; then R3 extends THIS owner with ordered
  Connect Response/Erect/Attach/Join and outbound write completion.
  Gate A/M2 remains open.
  **R3 exact-SHA hosted CI follow-up (2026-10-15):**
  [Actions 38798696991](https://github.com/k1moradi/RDP-server/actions/runs/38798696991)
  compiled both R3 additions and their dedicated CTests PASS on
  Linux/GCC and macOS/Clang Debug. Their full Debug suites FAIL
  **172/174 Linux** and **160/162 macOS**, at the same two R1-owned
  accepted TCP/TLS readiness/deadline CTests already failing at parent
  `209ebb6fa714b4bba61478539976719506b9b96d`
  [Actions 38798562218](https://github.com/k1moradi/RDP-server/actions/runs/38798562218).
  [R1 bug #11](https://github.com/k1moradi/RDP-server/issues/11)
  tracks those pre-existing assertions. Both Release phases are NOT RUN
  because the Debug step fails; Windows was still running when this
  receipt was prepared. Documentation-policy PASS.
  This is a partial CI result, NOT an overall green commit, and M2
  remains unaccepted pending actual R2-backed OS admission and owner CTests.
  **R3 preauth-to-session terminal revocation (2026-10-15; exact-SHA CI PASS):**
  The existing R1 `PreauthSession` now calls its single close() path
  on rejected/duplicate X.224 negotiation and unsuccessful/premature
  TLS handshake, revoking the R3 `McsSessionLifecycle` in the same
  event-loop turn. A read-only lifecycle-phase diagnostic exposes no
  admission token and cannot advance MCS. The new dedicated CTest
  `transport.mcs-preauth-terminal-revocation` covers denial,
  repeated X.224, TLS failure/premature calls, explicit cancellation,
  late MCS reentry and a valid diagnostic envelope that still closes.
  **NOT RUN at authoring:** full repository CTest, new-SHA hosted CI,
  owner's Linux/X11, Windows CLANG64/Clang23 and macOS27 verification,
  genuine R2 admission, Microsoft client and live desktop.
  **Next:** R2 must issue verified, TLS-bound, independently OS-authorized
  session evidence before this sole R3 owner can send Connect Response
  or advance to Erect/Attach/Join. Gate A/M2 NOT ACCEPTED.
  **R3 exact-SHA CI verification (2026-10-15):**
  [Implementation 84d55d00f4c49772ddaad524d078ade198cf5f03](https://github.com/k1moradi/RDP-server/commit/84d55d00f4c49772ddaad524d078ade198cf5f03)
  [Actions 38844029977](https://github.com/k1moradi/RDP-server/actions/runs/38844029977)
  PASS: Linux/GCC **192/192**, macOS/Clang **179/179**,
  Windows/MSVC **183/183** full CTests in Debug AND Release.
  New R3 terminal-revocation CTest, SDK consumer, packaging and
  documentation-policy checks PASS; prerelease SKIPPED (no tag).
  Owner exact-SHA Linux/X11, Windows MSYS2 CLANG64/Clang23 and
  macOS27 validation, real R2 OS admission, Microsoft client and
  desktop remain NOT RUN. Gate A/M2 remains OPEN.
  **R3 shared bounded first-MCS admission-denial intake (2026-10-15; CI NOT RUN at authoring):**
  Moved the existing 8192-byte first decrypted Connect-Initial TPKT
  ceiling into the common first-party MCS header. The sole noncopyable
  R3 `McsSessionLifecycle` now enforces this bound BEFORE the BER/GCC
  parser, returning an explicit `OversizedEnvelope` terminal outcome.
  R1's incremental TLS reader still allocates/buffers no more than its
  original 8192 bytes, and the R1 syntax-only callback now delegates
  envelope validation and its size policy to R3 instead of duplicating
  a second check. Too-short/malformed/overlimit data closes both owners;
  a fresh session is required for any next packet. The 8192-byte bound
  is a local intake ceiling, NOT a replacement for MS-RDPBCGR's
  1024/4096-byte negotiated GCC Create Request field limits.
  Two new production-linked registered CTests cover direct R3
  oversize rejection and the actual R1-to-R3 denial callback.
  **NOT RUN at authoring:** exact new-SHA hosted full CTests, owner's
  exact-SHA Linux/X11, Windows MSYS2 CLANG64/Clang23 and macOS27 CTests,
  genuine R2 OS authorization, real Microsoft-client or desktop.
  **Next:** consume only a genuine R2-issued TLS-bound and independently
  OS-authorized session lease; then complete MCS Connect Response with
  R1's accepted-byte writer before admitting Erect/Attach/Join.
  Gate A/M2 remains NOT ACCEPTED.
  **R3 pre-admission domain-PDU byte budget (2026-10-15; exact-SHA CI PASS):**
  The one denial-only `McsSessionLifecycle::onDomainPdu` now enforces
  the same bounded 8192-byte pre-admission TPKT ceiling as its first
  Connect-Initial, BEFORE parsing client T.125 domain PDUs. This
  prevents a caller bypassing R1's bounded preauth intake from
  presenting unbounded, unauthenticated SendData payloads for parsing.
  This limit applies ONLY while R2 has issued no independently
  OS-authorized, TLS-bound session capability; the future admitted
  session's negotiated maxMCSPDUsize remains a distinct requirement.
  One NEW behavior-named CTest checks valid PER SendData Requests
  at 8191, 8192, 8193 and 16398 total bytes, exact boundary
  classification, 65536-byte invalid input, local teardown,
  stale reentry and 9-byte peer Disconnect. No application dispatch,
  MCS reply, writer or OS admission was added.
  **NOT RUN at authoring:** actual new-commit Actions and owner
  three-platform same-SHA CTests; real Kerberos/CredSSP and OS
  authorization, Microsoft client and desktop. Gate A/M2 remains OPEN.
  **Exact-SHA R3 hosted CI verified (2026-10-15):**
  [Implementation 7cb6ac36aa7b8355dd76cdc567f7e943acfe330b](https://github.com/k1moradi/RDP-server/commit/7cb6ac36aa7b8355dd76cdc567f7e943acfe330b),
  [GitHub Actions 38849842295, attempt 2](https://github.com/k1moradi/RDP-server/actions/runs/38849842295)
  PASS: Linux/GCC **219/219**, macOS/Clang **203/203**,
  Windows/MSVC **221/221** full CTests in BOTH Debug and Release.
  The new R3 domain-budget CTest, documentation-policy,
  installed SDK consumer, packaging and the R9 sanitizer job PASS.
  Initial macOS attempt 1 FAILED at a separate R1-owned
  `transport.tcp-native-accept-batch-budget-handoff` assertion
  (`test_owned_preauth_session.cpp:2494`); exact-SHA macOS rerun
  attempt 2 **203/203 PASS** in Debug and Release. This does not
  erase the initial failure or prove that R1's timing boundary
  is deterministic; its first failing owner remains R1.
  **NOT RUN:** owner's independent Linux/X11, Windows MSYS2
  CLANG64/Clang23 and macOS27 CTests at this SHA, genuine
  R2 TLS-bound OS authorization, Microsoft-client activation
  or desktop. R3 Gate A/M2 remains NOT ACCEPTED.
  **R3 first failing MCS negotiation boundary (2026-10-15; exact-SHA CI PASS):**
  The one deny-only `McsSessionLifecycle` now distinguishes
  invalid RFC1006/BER MCS Connect-Initial syntax,
  failed T.125 domain-parameter negotiation, and failed
  GCC Conference Create parsing using the existing first-party
  decoders. All outcomes synchronously revoke joined/pending
  state and close; a fully valid Microsoft fixture remains
  `ValidButNotAdmitted` without a Connect Response or user
  authorization. Existing outcome numeric values remain unchanged;
  new error-only outcomes are appended. One new central CTest
  mutates the verbatim Microsoft packet independently at each layer
  and proves first-failure classification, terminal cleanup,
  stale reentry rejection and oversize precedence.
  **NOT RUN at authoring:** new-SHA full hosted CI, owner
  independent Linux/X11, Windows MSYS2 CLANG64/Clang23
  and macOS27 tests, real R2 TLS-bound identity plus OS
  authorization, external client or desktop. Gate A/M2 OPEN.
  **R3 first-failure exact-SHA hosted CI (2026-10-15):**
  [Corrected implementation 4ddf21920fbd10c0185f2d4f8d405c13600426a0](https://github.com/k1moradi/RDP-server/commit/4ddf21920fbd10c0185f2d4f8d405c13600426a0),
  [Actions 38856886973, attempt 2](https://github.com/k1moradi/RDP-server/actions/runs/38856886973)
  PASS: Linux/GCC **229/229**, macOS/Clang **212/212**,
  Windows/MSVC **231/231** full CTests in Debug AND Release.
  The new R3 case, sanitizer job, documentation-policy, SDK
  consumer and packaging passed. First attempt macOS Release
  FAILED at existing unrelated R1 accept-batch test assertion
  `test_owned_preauth_session.cpp:2494`; the same-SHA rerun
  passed **212/212** in both configs. This failure remains
  recorded in R1 issue #11; it is not erased by the rerun.
  NOT RUN: independent owner Linux/X11, Windows CLANG64/Clang23,
  macOS27 exact-SHA command, real Kerberos/CredSSP and OS
  authorization, Microsoft client or desktop. Gate A/M2 OPEN.
  **R3 first-failure domain-PDU classification (2026-10-15; CI NOT RUN at authoring):**
  The sole deny-only `McsSessionLifecycle::onDomainPdu` now preserves
  the existing parser's first failing boundary: RFC1006/X.224 transport,
  T.125 DomainMCSPDU choice/shape, or aligned-PER value. Three new
  appended `McsSessionIntake` error-only outcomes report those
  distinctions while keeping all existing numeric values unchanged.
  Every outcome still closes the same R3 owner, clears joined/pending
  channel state, emits no response and grants no R2/OS/session authority.
  A new central CTest independently proves valid-but-not-admitted Join,
  invalid transport, invalid domain shape, invalid PER UserId,
  oversize precedence, terminal stale reentry and peer Disconnect.
  **NOT RUN at authoring:** exact new-SHA hosted full CTests, owner
  independent Linux/X11, Windows MSYS2 CLANG64/Clang23, macOS27,
  genuine R2 TLS-bound OS admission, Microsoft client or desktop.
  Gate A/M2 remains OPEN.
  **Initial exact-SHA CI FAIL / test-oracle correction:**
  implementation `1f82be913b2ad7ae09134d939542ec22b3656d63`,
  [Actions 38864030223](https://github.com/k1moradi/RDP-server/actions/runs/38864030223)
  compiled the new domain classification and its new CTest passed on
  Linux/macOS Debug. Full Debug stopped because the older
  `transport.mcs-session-unverified-ordering` still expected generic
  `InvalidEnvelope` for a six-byte truncated TPKT. The parser reports
  `InvalidTransport`, so R3 now returns `InvalidDomainTransport`.
  Correct only that stale test oracle; production behavior is unchanged.
  **Verified partial offline MCS lifecycle boundary (CI PASS):**
  the existing `mcs_channel_connection` parser now recognizes
  strictly framed Disconnect Provider Ultimatum with ignored
  inbound reason; the allocation-free server serializer emits
  only provider-initiated (1) or user-requested (3) as required
  by MS-RDPBCGR 2.2.2.3 / 3.1.5.1.1. Two additional portable
  CTests exercise the published nine-byte example and exhaustive
  invalid reason/truncation/transport cases. Baseline main
  `36926462d34726f355279367a2ba2f27e93d2095`
  had owner's Linux Debug **67/67 PASS** and
  [CI 38684306429](https://github.com/k1moradi/RDP-server/actions/runs/38684306429)
  PASS. **PASS:** implementation `ed4b0c0a05981f573bc6b8369893f33d1e71549d`,
  [CI 38685111404](https://github.com/k1moradi/RDP-server/actions/runs/38685111404):
  Linux/GCC **78/78** and macOS/Clang, Windows/MSVC **69/69**
  in EACH Debug and Release, including both new disconnect cases,
  installed SDK consumers, three ZIP/SHA-256 archives and
  documentation-policy. The prerelease publishing job was SKIPPED
  (no version tag). Owner-local tests of this **new** commit are
  NOT RUN. This is NOT an authenticated server or live teardown.
  **Next:** build the one authenticated session state machine
  with controlled GSS/Kerberos and independent OS admission;
  only then verify TLS-encrypted disconnect send completion
  followed by socket close.
  **Partial offline client SendDataRequest framing (CI NOT RUN):**
  the existing `mcs_channel_connection` parser recognizes T.125
  client DomainMCSPDU choice 25 (0x64), initiator offset from
  1001, channel, priority, segmentation and bounded 7-bit/14-bit
  PER OCTET STRING length. It returns a borrowed caller-buffer
  span without heap copies; malformed lengths, unsupported
  PER fragmentation, invalid padding, bad TPKT and initiator
  overflow fail closed. Two extra portable behavior CTests
  reuse the original MCS executable (71 portable / 80 with
  Linux GSSAPI expected). Baseline main
  `05f2708cc8b326983c406b643bee1d47e5e166d0`
  passed [CI 38685374294](https://github.com/k1moradi/RDP-server/actions/runs/38685374294)
  and the owner reports 69/69 local CTests PASS.
  **First CI FAIL** for implementation
  `c1f9e5458132c40b149e8ec5f0e6083addff8715`:
  [run 38696231297](https://github.com/k1moradi/RDP-server/actions/runs/38696231297)
  found an invalid *test* lifetime: parsing a temporary
  `frameDomainPdu` and reading its borrowed `userData`
  after the vector was destroyed. Linux Debug **79/80**
  and macOS Debug **70/71** passed; the sole failed case
  was `transport.mcs-send-data-wire`. Follow-up keeps
  that frame alive through all view assertions without
  changing the production parser, and adds an offset check.
  **PASS:** correction
  `72af29fddc2424fcc7f4edbd579e2b313ef25f48`,
  [CI 38696503496](https://github.com/k1moradi/RDP-server/actions/runs/38696503496):
  Linux/GCC **80/80**, macOS/Clang and Windows/MSVC
  **71/71** CTests in BOTH Debug and Release; both new
  SendData wire/negative cases, documentation-policy,
  installed SDK consumer and three ZIP/SHA256 packages
  PASS. Prerelease publication SKIPPED (no release tag).
  Owner-local test of the corrected exact commit NOT RUN.
  This does not enable live TLS MCS intake, authorized channel
  membership, reassembly or desktop session admission.
  **Next:** run exact-head full CI; then controlled real
  Kerberos/GSS transcript, verified OS identity/session
  policy, and one owner for all post-auth channel states
  before delivering any client Send Data payload.
  **Partial offline server SendDataIndication encoding (2026-10-15;
  CI NOT RUN at authoring):** the existing first-party MCS
  module can now serialize server-to-client T.125 DomainMCSPDU
  choice 26 to a caller-owned contiguous buffer, with checked
  UserId/channel, priority, segmentation and canonical
  unfragmented PER payload length up to 16383 bytes.
  The result is fixed-header plus one overlap-safe memory
  move, no internal allocation; reject invalid parameters
  or insufficient capacity without mutating output.
  Two additional tests (73 portable / 82 Linux GSS-enabled
  expected) cover byte-exact wire, length boundaries,
  aliasing, bounds and fail-closed output.
  Baseline parent `cd50346be4df281b7fc207c5126072555a3eba63`
  passed [CI 38696744690](https://github.com/k1moradi/RDP-server/actions/runs/38696744690);
  owner reports local **71/71 PASS** on prior code.
  **PASS:** implementation `8c9fabeb02fce7ede13abfb42631d3b7f35a4fc1`,
  [Actions run 38701524465](https://github.com/k1moradi/RDP-server/actions/runs/38701524465):
  Linux/GCC **82/82**, macOS/Clang and Windows/MSVC
  **73/73** CTests in BOTH Debug and Release, including
  both new cases; SDK install/downstream consumer,
  ZIP+SHA256 uploads and documentation policy PASS.
  Prerelease publishing SKIPPED (no release tag).
  **NOT RUN:** owner's local build of this new commit,
  independent OS admission, joined-channel enforcement,
  actual TLS sends, real client, licensing, graphics or desktop.
  **Next:** exact-head cross-platform CI; then controlled
  true GSS/Kerberos/TLS identity and separate OS policy
  before wiring any SendData indication into the one
  authorized session owner.
  **Verified partial offline Share Control Header decoder (2026-10-15;
  CI PASS):** extend the original C++23
  MCS module with a strict, zero-copy T.128
  `TS_SHARECONTROLHEADER` decoder per MS-RDPBCGR
  2.2.8.1.1.1.1. It checks six-byte LE framing,
  complete declared length, version 1 and all five
  documented PDU types, but no nested data message.
  Recognize `totalLength=0x8000` as a MUST-IGNORE
  FlowPDU without exposing body or accepting it as
  activation. Reuse the existing test executable for
  Microsoft 26-byte Control PDU and malformed/ignored
  cases; expected **75** portable and **84** Linux
  GSS-enabled CTests (73 and 82 prior). Baseline main
  `424a35a8ceeb2a32fc553f334cfdcdfeebf5e2a6`
  passed [Actions 38701851845](https://github.com/k1moradi/RDP-server/actions/runs/38701851845);
  owner reports **73/73 local PASS** on that prior code.
  **PASS:** implementation `77fd1be92c0f4dcff60962d645a39af9b23c96de`,
  [Actions 38705203733](https://github.com/k1moradi/RDP-server/actions/runs/38705203733):
  Linux/GCC **84/84**, macOS/Clang and Windows/MSVC
  **75/75** full CTests in BOTH Debug and Release;
  new Share Control cases, documentation-policy,
  installed SDK consumer and all three ZIP/SHA256
  artifacts PASS. Prerelease publishing SKIPPED
  without a version tag.
  **NOT RUN:** owner-local new compile, actual Share
  Control/Share Data dispatch, optional security-header
  handling, licensing, independent MCS/OS authorization,
  external Windows App or desktop session.
  **Next:** genuine authorized GSS
  with active TLS proof, independent OS session policy,
  and the sole authenticated owner for licensing/share
  activation and nested PDU processing.
  **Verified offline T.128 Share Data Header decoding (2026-10-15;
  CI PASS):** reuse the existing MCS/Share
  Control module to decode the 12-byte Share Data Header only
  after an explicitly isolated, complete Data PDU. Accept the
  24 normative type2 values, stream priorities 1/2/4, and
  stream 0 ONLY with Synchronize for known server behavior;
  ignore pad1; preserve uncompressedLength and compressedLength
  as metadata, never allocation or trust boundaries.
  Reject any compressedType != 0 pending real negotiated
  decompression, or any truncated/unknown/FlowPDU input,
  without exposing a borrowed application payload.
  Two behavior-named regression tests reuse the original
  MCS executable with 3 real Microsoft sample layouts;
  **77** portable and **86** Linux GSS-enabled CTests
  expected (75 and 84 prior).
  Baseline `8aea09a101fe1394c6c60145fef42fa002514315`
  passed [CI 38705731398](https://github.com/k1moradi/RDP-server/actions/runs/38705731398);
  owner reports **75/75 local PASS** on that prior main.
  **PASS:** exact implementation `9bc9e041419b4a932dc988a51f1f3e920ac82ba3`,
  [CI 38708579033](https://github.com/k1moradi/RDP-server/actions/runs/38708579033):
  Linux/GCC **86/86**, macOS/Clang and Windows/MSVC
  **77/77** full CTests in EACH Debug and Release;
  both new Share Data groups, project policy, staged
  installed SDK consumer and three ZIP/SHA256 artifacts
  PASS. Prerelease publication SKIPPED (no version tag).
  **NOT RUN:** owner-local NEW compile/CTest, independently
  authenticated OS/session, live TLS/ShareData routing,
  negotiated decompression, licensing, client activation,
  input or desktop.
  **Next:** authorized
  opt-in genuine GSS/Kerberos + TLS certificate binding,
  independent OS session admission, and only afterward
  single-owner Share Control/Share Data lifecycle.
- [ ] Deliver the **first usable, H.264-only Microsoft-compatible RDP server**:
  **Gate B minimum vertical slice (NOT RUN):** ship the first tested
  native server executable with Linux/X11 capture, pointer/keyboard
  input and cursor, after Gate A authorization. Complete negotiated
  RDPGFX AVC420 delivery and robust resize/frame ACK/reconnect before
  adding clipboard, other OS backends or optional codecs.
  **R5 XShm capture-layout bounds increment (based on main
  `d9a46e5cb871b8a81d8a6d057d0f60b568957f45`; exact implementation CI pending):**
  Validate XCB signed-16 coordinates, nonzero unsigned-16 rectangle and
  display dimensions, on-screen geometry, packed 32-bit BGRX stride,
  size_t/uint32 byte limits and shared-memory capacity before GetImage.
  Reject mismatched short/oversized reply byte counts without publishing
  an invalid borrowed FramebufferView; preserve existing arena ownership.
  Linux-only dedicated CTest: `x11.capture-layout-bounds`; headless
  positive/negative and near-4-GiB geometry assertions (no allocation).
  **PASS:** isolated R5 fixture 2/2; GCC 14 and Clang 17 strict-warning
  C++23 capture tests; GCC ASan/UBSan capture test. These results are not
  full-project CI or authorized desktop acceptance.
  **NOT RUN:** complete project CTest, native XCB source compile (missing
  xcb/shm.h), owner Linux/Windows CLANG64/macOS27, benchmarks and live
  Microsoft-client desktop. Current container cannot clone GitHub.
  **Next R5:** native XCB capture compilation/lifecycle CTest followed by
  R2/R3-authorized backend ownership and R4 frame consumer. M3 stays open.
  **R5 XFixes cursor reply-length safety (2026-10-15; implementation
  based on `d7946e2e74bf9ca7cdce66f02080b37085812be6`; exact-head CI pending):**
  `X11CursorTracker::refresh` checks XFixes GetCursorImage reply
  `length` in 32-bit words against the cursor's width-by-height area
  before reading its ARGB pixels. Invalid dimensions and hotspots also
  fail closed; unsupported cursors retain the existing fallback.
  New Linux-only CTest `x11.cursor-reply-length-bounds` checks exact,
  truncated and padded reply lengths, hotspot/dimension rejection,
  BGRX/mask conversion and unmodified output on short spans, without
  an X server. **PASS:** isolated R5 headless CTest 2/2, strict GCC 14
  and Clang 17 C++23 cursor builds, and GCC ASan+UBSan cursor test.
  **NOT RUN:** native XCB tracker compile (xcb/xfixes.h unavailable),
  full-project CTest, owner three-platform tests, human desktop and
  performance benchmarks. **Next R5:** compile and test actual native
  XCB cursor lifecycle with controlled replies; integrate only after
  R2/R3 admission and R4 graphics routing. M3 stays NOT RUN.
  **R5 first-party XCB event readiness (based on main
  `5c885088775bcbb74b3a9083bd165b4fd17d8bf7`; exact-SHA CI pending):** replace xrdp config, os_calls
  and tbus wait-object dependencies in `X11DisplayConnection` with
  XCB-owned borrowed descriptor, external readable-socket indication,
  bounded queued events, continuation hint, RandR root resize handling
  and deterministic disconnection (no socket dup/close). On Linux the
  ordinary CMake build compiles the real native XCB/RandR source when
  pkg-config finds xcb and xcb-randr; hosted Linux CI installs headers.
  New dedicated native Linux CTest `x11.display-event-budget-and-readiness`
  exercises the production event-drain, injected synthetic events and
  invalid-display teardown without a real X server. **PASS:** isolated
  strict GCC 14/Clang 17 C++23 dispatch fixture and GCC ASan+UBSan.
  **NOT RUN locally:** actual RandR translation unit (missing dev
  xcb/randr.h), canonical full CTest (no clone), owner Linux/X11,
  Windows CLANG64/Clang23, macOS 27, benchmarks and authorized desktop.
  **Next R5:** native capture/cursor/damage resource lifecycle, then
  R2/R3-authorized desktop operation feeding R4 frame consumer.
  M3 remains NOT RUN.
  **R5 native strict-compile correction (2026-10-15, base
  `7dc34b69831a9122fda752434d5c9bfb8ee121ef`):** Linux hosted build on published R5 commit
  `4d4d97ec78a63e963c1bed8d7fa6513141a4f9fa`
  found GCC `-Werror=extra` for enum/integer conditional getter
  fallbacks in `x11_display_connection.cpp`. Return explicitly
  typed zero XCB identifiers and split a dedicated native-only
  `x11.display-event-disconnect-cleanup` CTest from the existing
  bounded event-budget case. Both cases run without an X server.
  **FAIL:** initial exact-SHA native Linux Debug compilation;
  **PASS:** isolated headless event helper GCC/Clang/ASan tests.
  **NOT RUN:** corrected exact-SHA CI and native owner-local test
  until the follow-up commit completes. M3 remains NOT RUN.
  **R5 native XFixes cursor cancellation and lifecycle (2026-10-15;
  based on main `991320318e681fba99ca85adf1d29039c3e3137c`, exact-SHA CI pending):**
  Compiles the real `X11CursorTracker` and existing production cursor
  converter in a Linux-only, noninstalled `rdp-server-linux-xfixes-cursor`
  target when pkg-config finds `xcb` and `xcb-xfixes`. Reject already
  failed XCB connections before requesting extensions; add idempotent
  cursor `disconnect()` that invalidates the borrowed XCB pointer,
  discards cached images and flags and forbids stale refresh/event use
  after its parent is destroyed. Dedicated Linux-native headless CTest
  `x11.cursor-native-connection-denials-and-cancellation` exercises the
  real cursor translation unit with a deliberately invalid fd, failure
  handling, cancellation before XCB teardown and safe subsequent calls.
  It does not open a real display or inject input. Existing
  `x11.cursor-reply-length-bounds` tests remain unchanged.
  **PASS prior SHA:** Linux/GCC full suite for published R5 readiness
  `f46a9a47751aafbf30419851f4df40213d1e3f52` (191/191).
  **NOT RUN at authoring:** new native XFixes build/CTest locally
  (missing `xcb/xfixes.h`); new-SHA CI, owner three-platform tests,
  authorized X11 desktop, R4 graphics integration and benchmarks.
  **Next R5:** native damage, capture/cursor connection teardown
  ordering and R2/R3-approved frame/cursor delivery; M3 NOT ACCEPTED.
  **R5 native XFixes cursor exact-SHA CI PASS (2026-10-15):**
  published production commit `c4aedf8d4dbc2e0732b43bd7df273dea47e94d85`;
  [Actions 38845314257](https://github.com/k1moradi/RDP-server/actions/runs/38845314257)
  completed SUCCESS. Linux/GCC built the actual native XFixes
  tracker and production converter in Debug/Release; full Linux
  CTests **208/208** PASS each, including new
  `x11.cursor-native-connection-denials-and-cancellation` PASS in
  both. Hosted macOS/Clang **193/193** and Windows/MSVC
  **203/203** full CTests PASS in each config; Linux-only native
  XFixes test was NOT RUN on macOS/Windows. Docs policy,
  install/consumer SDK and package/digests PASS.
  **NOT RUN:** owner's independent Linux/X11, Windows CLANG64/
  Clang23 and macOS27 exact-SHA tests; real R2/R3 authorization,
  Microsoft-client desktop, R4 cursor delivery and benchmarks.
  M1/M3 remain unaccepted.
  **R5 native XDamage ownership and cancellation (2026-10-15;
  based on `4d091d3d41ac74e1bf7692721c425f52317c5373`, exact new-SHA CI pending):** Add the
  real `X11DamageTracker` and first-party bounded `DamageRegion`
  to a Linux-only noninstalled `rdp-server-linux-xdamage` target
  when pkg-config finds `xcb` and `xcb-damage`; Ubuntu CI installs
  `libxcb-damage0-dev`. Reject failed XCB connections before native
  extension negotiations. Explicit idempotent `disconnect()` releases
  the Damage resource when connected and clears its borrowed native
  pointer, pending regions, interaction history, and counters before
  the display owner is destroyed. Existing destructor calls the same
  teardown. New Linux-native headless CTest
  `x11.damage-native-connection-denials-and-cancellation` exercises
  actual tracker behavior with an invalid XCB fd, snapshot rejection,
  observation reset, repeated disconnect, and post-owner-destruction
  denials. No live DISPLAY or desktop is accessed.
  **NOT RUN locally:** native XDamage compilation/CTest (this authoring
  environment lacks xcb/damage.h and full project checkout), new exact
  hosted CI, owner three-platform acceptance, authorized client
  desktop and benchmarks. **Next R5:** coordinate one XCB owner with
  capture/damage/cursor teardown and resize, then R2/R3 admission
  and R4 frame/cursor consumption. M3 remains NOT ACCEPTED.
  **R5 native XDamage exact-SHA hosted CI PASS (2026-10-15):**
  production `2f3b0ea12d7324cfd501ec25665fc02e030b0469`;
  [Actions 38849416185](https://github.com/k1moradi/RDP-server/actions/runs/38849416185)
  completed SUCCESS. Real Linux XCB-Damage tracker and DamageRegion
  compiled and linked in Debug/Release. **217/217** Linux CTests
  PASS in both, including dedicated
  `x11.damage-native-connection-denials-and-cancellation`.
  Hosted macOS **201/201** and Windows **215/215** full CTests PASS
  in Debug and Release; Linux-only XDamage test not run elsewhere.
  Docs policy, SDK stage/consumer/package and R9 clipboard
  sanitizers PASS. **NOT RUN:** owner's independent Linux/X11,
  Windows CLANG64/Clang23, macOS27, real R2/R3-authorized
  desktop/client, native teardown/resize integration with R4
  and reproducible benchmarks. M1/M3 remain unaccepted.
  **R5 Linux XCB-SHM native compile increment (2026-10-15;
  base `aa15209c67d74814cac8c859997e623cd096691c`, exact-SHA CI pending):**
  Add separate, noninstalled `rdp-server-linux-xshm` native Linux
  target compiling the actual XShm capture translation unit where
  pkg-config finds `xcb` and `xcb-shm` development headers. The
  portable protocol archive does not link XCB. Move the unchanged
  `captureArenaPixels` algorithm into the existing XCB-free layout
  header so ordinary headless CTests can verify bounds without an
  X server. New Linux-only `x11.capture-arena-and-connection-denials`
  CTest checks zero dimensions, minimum row and capped arenas;
  when XCB-SHM is available it also instantiates native capture
  with an intentionally failed fd -1 connection and verifies
  constructor/capture refusal and safe teardown. Ubuntu CI installs
  developer packages for this compile/test without contacting DISPLAY.
  **PASS:** isolated 3/3 R5 CTests, GCC 14 and Clang 17 strict C++23
  arena test, GCC ASan/UBSan. **NOT RUN at authoring:** actual
  xcb-shm native compile locally (headers unavailable), full repo
  CTest, owner three-platform tests, live desktop, benchmarking.
  **Next R5:** controlled native XShm response/resource lifecycle
  and admitted R2/R3 backend frame access for R4. M3 not accepted.
  **R5 native XShm borrowed-owner cancellation (2026-10-16;
  base main `4ddf21920fbd10c0185f2d4f8d405c13600426a0`):**
  Add explicit idempotent `X11SharedMemoryCapture::disconnect()`.
  Detach the XShm server resource and release the local arena while the
  caller still owns the XCB connection; clear its borrowed XCB pointer,
  drawable, layout and size before the parent can be destroyed. Repeated
  cancellation, destructor and capture attempts no longer access the
  former connection or overwrite the disconnected diagnostic.
  New native Linux headless CTest
  `x11.capture-native-disconnect-cancellation` creates a deliberately
  invalid-fd XCB connection, cancels capture, destroys the connection,
  then checks repeated cancellation, failed post-disconnect capture and
  destructor safety. Native CTest conditionally registers when xcb-shm
  development headers are available. No live X server or session is used.
  **NOT RUN at authoring:** local native XCB-SHM compile (headers absent),
  complete local repository/CTest (no checkout), new exact-SHA hosted CI,
  independent owner Linux/X11, Windows CLANG64/Clang23 and macOS27,
  real authorized desktop, and performance benchmarks.
  **Next R5:** combine parent display, cursor, damage and XShm teardown
  under one R2/R3-authorized owner; coordinate resized capture bounds and
  R4 frame consumption. M3 remains NOT ACCEPTED.
  **R5 XShm cancellation exact-SHA hosted CI PASS (2026-10-16):**
  production implementation `ea1cf468986b15bcc4ee0b43b70082cfc0862e82`,
  [Actions 38856920824](https://github.com/k1moradi/RDP-server/actions/runs/38856920824)
  completed SUCCESS. The real native XCB-SHM source compiled under
  Ubuntu GCC in Debug and Release and the new
  `x11.capture-native-disconnect-cancellation` CTest passed.
  Hosted Linux **230/230**, macOS **212/212**, and Windows **231/231**
  full registered CTests PASS separately in Debug and Release.
  Protocol sanitizer, docs policy, SDK install/consumer and ZIP package
  checks PASS; prerelease publishing intentionally SKIPPED.
  **NOT RUN:** owner's independent Linux/X11, Windows MSYS2 CLANG64/
  Clang23 and macOS27 one-root tests; genuine R2 OS admission,
  R3-authorized desktop, R4 frame delivery, live Microsoft client,
  native resize integration, benchmarks. Gate B/M3 remain OPEN.

  **R5 native XTEST typed input boundary (2026-10-16; based on main
  `e6504314c87fadbb9fcf1cde7f09f9fa5b9de010`, exact-SHA hosted CI pending):** Remove the remaining
  `xrdp_constants.h` and `ms-rdpbcgr.h` dependency from
  `X11InputController`. The controller now consumes a first-party
  R5-native typed event variant for keys, lock state, pointer movement,
  buttons and bounded scrolling; it rejects failed XCB connections before
  XTEST negotiation and catches keyboard-map allocation failure inside its
  `noexcept` constructor. Add an explicit idempotent `disconnect()`
  barrier that releases held keys/buttons while the XCB owner is alive,
  then invalidates the borrowed connection before parent teardown.
  A Linux-only noninstalled `rdp-server-linux-xtest-input` target builds
  the real production source when pkg-config finds `xcb`/`xcb-xtest`;
  hosted CI installs `libxcb-xtest0-dev`. Dedicated headless CTest
  `x11.input-native-connection-denials-and-cancellation` uses only an
  already-failed fd, exercises all typed request categories as fail-closed,
  repeated cancellation and destructor-after-owner-teardown safety, and
  cannot inject live input. The target is not linked into the runtime, and
  the typed R5 event is not an authorization token: R2/R3 admission and
  R3's authoritative input routing remain required before protected input.
  **PASS locally:** GCC 14.2 strict C++23 compile/run of the allocation-free
  typed event contract. **NOT RUN locally:** actual XTEST translation unit
  and native CTest because `xcb/xtest.h` is absent; full canonical CTest,
  owner platform trio, authorized desktop, Microsoft client and benchmarks.
  **Next R5:** compose display/capture/cursor/damage/input cancellation under
  one admitted XCB owner, then bind R3-authorized input and R4 frame/cursor
  consumption without creating a second scheduler. M3 remains OPEN.

  **R5 native XTEST hosted Linux receipt (2026-10-16):**
  implementation `987b4736c001edeb3cd4c2a4675080b583ca134c`.
  Exact-SHA Actions run 38866079679 installed `libxcb-xtest0-dev` and
  compiled/linked the real native XTEST target before the shared build hit
  the pre-existing R1 OpenSSL constness failure also reproduced by parent
  `e6504314c87fadbb9fcf1cde7f09f9fa5b9de010` on all three hosted OSes.
  R1 descendant `1260eb659073d5269724a4436e3a8bbfda322725` changes only
  R1 test/docs after the R5 implementation; Actions run 38866320385 builds
  unchanged R5 source and runs
  `x11.input-native-connection-denials-and-cancellation` **PASS** in
  Ubuntu Debug and Release, with full **277/277 PASS** in each configuration
  plus SDK install/consumer/package stages PASS. No DISPLAY, live input,
  R2/R3 authorization, Microsoft client or M3 acceptance was exercised.

  **R5 one-XCB desktop resource owner (2026-10-16; based on main
  `0ee521f2802bb2f2fd3fd6fa1ebfb834f4d47287`; exact-SHA CI pending):** Repair the concurrent R9 CMake
  overwrite that left typed XTEST source/test present but dropped its native
  target and CI package, then add `X11DesktopResources`. This noninstalled
  Linux aggregate owns the existing display connection plus XShm capture,
  XFixes cursor, XDamage and XTEST input under one XCB owner. It grants no
  R2/R3 admission and is not linked into the runtime. Failure/destruction
  cancels input, cursor, Damage and XShm before closing XCB. Dedicated
  `x11.desktop-resource-owner-connection-denial` needs no X server;
  `x11.desktop-resource-owner-lifecycle` runs under ephemeral Xvfb when
  available and constructs/tears down all real native resources without
  user input or real desktop capture consumption.
  **NOT RUN at authoring:** native composite compile/CTest here, owner
  platform trio, real admission, RandR reconstruction, R4/R3 consumers,
  Microsoft client and benchmarks.
  **Next R5:** route bounded XCB events through this owner and revoke or
  reconstruct geometry-bound children on RandR change before authorized
  input/frame/cursor integration. M3 remains OPEN.

  **R5 one-XCB owner exact-SHA hosted CI PASS (2026-10-16):**
  implementation `754e681a503a11c06ea60082103c3d95eb834919`,
  [Actions 38871605559](https://github.com/k1moradi/RDP-server/actions/runs/38871605559)
  completed **SUCCESS**. Ubuntu/GCC built the restored XTEST target and
  `rdp-server-linux-x11-desktop`; Debug/Release CTests were **284/284
  PASS** each, including restored XTEST denial plus both new resource-owner
  cases (ephemeral Xvfb lifecycle included). macOS/Clang was **263/263
  PASS** twice; Windows/MSVC **283/283 PASS** twice. Documentation-policy,
  R9 sanitizer, SDK consumer/package stages PASS. **NOT RUN:** owner
  Linux/X11, Windows MSYS2 CLANG64/Clang23, macOS27, genuine R2/R3 desktop
  admission/routing, live input, RandR reconstruction, R4 consumption,
  Microsoft client and benchmarks. M3 remains OPEN.

  **R5 bounded owner event routing and resize revocation (2026-10-16;
  based on main `ae4f2501a1e7c42b83fafe769f6fcd049d2685e6`; exact-SHA CI pending):** Add
  `X11DesktopResources::processEvents` as the single native event-routing
  entry point. It reuses the display owner's bounded nonblocking drain and
  forwards borrowed events to the existing XFixes cursor and XDamage
  trackers on the same serialized XCB thread. If RandR changes source
  geometry, revoke input/cursor/Damage/XShm and then the XCB owner before
  stale geometry can reach capture or input; resource reconstruction remains
  a later admitted-session step. Also change display event failure semantics:
  public readiness/native access is invalidated immediately, but the owned
  XCB allocation stays alive until explicit owner teardown so children cannot
  retain dangling connection pointers.
  New Xvfb CTests:
  `x11.desktop-resource-event-routing` generates a real synthetic-root
  XDamage operation and verifies it reaches the owned tracker;
  `x11.display-event-failure-defers-owner-teardown` queues a deliberate
  unchecked protocol error and proves the borrowed XCB pointer remains alive
  until explicit disconnect. Existing denial/lifecycle CTests remain.
  **NOT RUN at authoring:** synchronized local native compile/CTest, owner
  Linux/X11, Windows CLANG64/Clang23, macOS27, a real RandR resize event,
  R2/R3 admitted desktop, R4 frame/cursor consumption, Microsoft client and
  benchmarks. **Next R5:** rebuild geometry-bound XShm/Damage/input children
  transactionally after an admitted RandR resize, preserving the one XCB
  owner; then expose synchronous R4 capture/damage/cursor reads and
  R3-authorized typed input. M3 remains OPEN.

  **R5 bounded event routing exact-SHA hosted CI PASS (2026-10-16):**
  implementation `ba59c94c7ab07c688d6b19ee8d440ddcd98acee8`,
  [Actions 38873077390](https://github.com/k1moradi/RDP-server/actions/runs/38873077390)
  completed **SUCCESS**. Ubuntu/GCC full CTest was **289/289 PASS** in
  Debug and **289/289 PASS** in Release. Both new native Xvfb cases,
  `x11.desktop-resource-event-routing` and
  `x11.display-event-failure-defers-owner-teardown`, passed in both
  configurations, together with the existing XTEST and one-XCB owner cases.
  macOS/Clang full CTest was **265/265 PASS** Debug/Release; Windows/MSVC
  **285/285 PASS** Debug/Release. Documentation-policy, R9 sanitizers,
  installed-SDK consumer, package/digest/upload stages all PASS; prerelease
  publication was skipped without a release tag.
  **NOT RUN:** owner's Linux/X11, Windows MSYS2 CLANG64/Clang23 and macOS27
  one-root commands; a real RandR geometry-change notification; genuine
  R2/R3 admitted desktop routing; live XTEST input; R4 frame/cursor
  consumption; Microsoft-client M3 acceptance; performance benchmarks.
  The runtime still does not link the native X11 aggregate. M3 remains OPEN.

  **R5 transactional RandR geometry rebuild (2026-10-16; based on main
  `f99a2ad3efefb03b2316cc940cc625f77d3699eb`; exact-SHA CI pending):** Replace resize revocation with a
  synchronous commit-or-revoke rebuild under the existing
  `X11DesktopResources` owner. A valid RandR screen-change notification now
  stops the bounded display drain before later queued events; the aggregate
  cancels old XTEST/Damage/XShm geometry-bound state, reconstructs all three
  against the new bounds on the same XCB connection, and publishes the new
  geometry only after every child is valid. XFixes cursor remains live across
  a successful geometry-only transition. Rebuild failure closes the entire
  native owner rather than exposing partial generations. Add ordinary
  Linux/Xvfb CTest `x11.desktop-resource-randr-rebuild`: disable only the
  ephemeral Xvfb CRTC, resize its root 1280x720 -> 1024x600 via XCB/RandR,
  verify owner validity and unchanged XCB descriptor, then generate another
  root change and verify the newly constructed XDamage tracker receives it.
  No live desktop, credentials or input injection are involved.
  **NOT RUN at authoring:** synchronized local native build/full CTest,
  exact-SHA hosted CI, owner Linux/X11, Windows CLANG64/Clang23, macOS27,
  admitted R2/R3 desktop routing, R4 frame/cursor consumption, Microsoft
  client and benchmarks. **Next R5:** expose synchronous bounded capture,
  Damage snapshot and cursor refresh/ack reads from this admitted native
  owner for R4, then bind only R3-authorized typed input; do not create a
  second graphics scheduler. M3 remains OPEN.

  **R5 transactional RandR rebuild exact-SHA hosted receipt (2026-10-16):**
  implementation `4fb615a7f5e726d278c9a7793d16103dc109ac37`,
  [Actions 38874824167](https://github.com/k1moradi/RDP-server/actions/runs/38874824167).
  Linux/GCC compiled the real native X11 aggregate in Debug and Release and
  full CTest was **294/294 PASS** in both. New
  `x11.desktop-resource-randr-rebuild` passed in both configurations,
  proving an actual ephemeral-Xvfb RandR resize 1280x720 -> 1024x600 rebuilt
  XShm/XDamage/XTEST while retaining the same XCB descriptor, followed by
  successful post-resize XDamage delivery. macOS/Clang full CTest was
  **266/266 PASS** Debug/Release; Windows/MSVC **289/289 PASS**
  Debug/Release. Documentation policy and installed-SDK consumer/package
  stages passed.
  The workflow conclusion is **FAIL**, solely because the concurrent parent
  R9 sanitizer expansion fails strict Clang compile on unused private
  logind-evidence fields; parent `f99a2ad3efefb03b2316cc940cc625f77d3699eb`
  [Actions 38874696875](https://github.com/k1moradi/RDP-server/actions/runs/38874696875)
  reproduces the same sanitizer compile errors before this R5 change.
  **NOT RUN:** owner Linux/X11, Windows MSYS2 CLANG64/Clang23 and macOS27
  one-root commands; genuine R2/R3 admitted desktop routing; live XTEST
  input; R4 capture/cursor consumption; Microsoft-client M3 acceptance;
  performance benchmarks. M3 remains OPEN.

  **R5 synchronous R4 native read boundary (2026-10-16; based on main
  `c09e581ac965e79ce700ef4617a0af6d2b04adba`; exact-SHA CI pending):** Keep `X11DesktopResources` as the
  sole native lifetime/event owner and expose synchronous pass-through reads
  for the existing R4 scheduler: bounded XShm rectangle capture, XDamage
  snapshot/acknowledgement, and XFixes cursor pending/refresh/image/ack state.
  Returned frame and cursor spans remain borrowed from the aggregate and may
  not survive another capture/refresh, RandR generation replacement or
  disconnect. Capture/Damage/hard cursor child failure revokes the whole
  native owner rather than letting R4 consume a degraded partial source;
  retryable cursor diagnostics remain queryable without a second controller.
  Add ordinary Xvfb CTest `x11.desktop-resource-r4-read-boundary` that uses
  the real production aggregate to capture a bounded synthetic-root rectangle,
  routes and snapshots XDamage, refreshes/reads/acknowledges the initial
  XFixes cursor, then verifies all reads fail closed after disconnect.
  No scheduling, R2/R3 authorization decision, protected desktop access or
  input injection is added.
  **NOT RUN at authoring:** synchronized local native build/full CTest,
  exact-SHA hosted CI, owner Linux/X11, Windows CLANG64/Clang23, macOS27,
  genuine admitted desktop/R4 delivery, live input, Microsoft client and
  benchmarks. **Next R5:** bind the existing typed XTEST adapter only behind
  the concrete R3-authorized admitted-session boundary and invalidate that
  path on admission-generation/session revocation; do not create another
  input or session controller. M3 remains OPEN.

  **R5 synchronous native graphics-read hosted receipt (2026-10-16):**
  implementation `9331ec040819b7156a24ea24ab9cc5973a8d891f`,
  [Actions 38877739759](https://github.com/k1moradi/RDP-server/actions/runs/38877739759).
  Ubuntu/GCC compiled the real `rdp-server-linux-x11-desktop` target and
  `x11.desktop-resource-r4-read-boundary` **PASS** under ephemeral Xvfb,
  together with all other R5 X11 cases. Full Debug CTest was **302/303**
  because unrelated `transport.gcc-conference-create` aborted at
  `earlyCapabilityFlags == 0x0001U`; the immediate parent
  `c09e581ac965e79ce700ef4617a0af6d2b04adba`,
  [Actions 38877612047](https://github.com/k1moradi/RDP-server/actions/runs/38877612047),
  reproduces that same Linux failure before the R5 change. Release/package
  therefore did not run on the exact Linux SHA. macOS/Clang Debug likewise
  reached **270/271**, with the same inherited conference-create failure
  reproduced by the parent; Release did not run. Documentation-policy and
  R9 sanitizer jobs **PASS**. The exact Windows/MSVC job was **IN PROGRESS**
  when this receipt was recorded and is not claimed as PASS/FAIL.
  **NOT RUN:** owner Linux/X11, Windows MSYS2 CLANG64/Clang23 and macOS27
  one-root commands; genuine R2/R3 admitted desktop/R4 delivery; live XTEST
  input; Microsoft-client M3 acceptance; performance benchmarks. M3 remains
  OPEN.

  **R5 concrete R3-authorized XTEST route (2026-10-16; based on main
  `8f86a5a25ebbdece40b3d97beb569c860d235c87`; exact-SHA CI pending):** Add a stateless
  `X11AuthorizedInputRoute` as the sole friend allowed to reach the private
  XTEST child in `X11DesktopResources`. Each dispatch requires the concrete
  broker-issued `LinuxConsoleAdmissionLease`, live GSS/TLS acceptor and sole
  `McsSessionLifecycle`, then synchronously calls existing
  `authorizeR3ProtectedTransition(..., kConsoleInputPermission)` immediately
  before the typed X11 event. Missing/stale admission, generation mismatch,
  dead native ownership or XTEST failure revokes the native owner and R3/R2
  path; no Boolean, policy match, native handle or scalar generation can grant
  input. Add ordinary ephemeral-Xvfb CTest
  `x11.input-r3-admission-route-denials-and-revocation`: construct a real
  native desktop and an input-capable policy but deliberately provide no
  lease, verify no XTEST path is reached, and require native/R3/R2 terminal
  revocation plus replay denial. The positive Kerberos/logind/XTEST path stays
  NOT RUN in ordinary CTest.
  **NOT RUN at authoring:** local one-root native build/full CTest, exact-SHA
  hosted CI, genuine positive Kerberos/TLS + physical logind admission, live
  XTEST injection, owner Linux/X11, Windows CLANG64/Clang23, macOS27,
  Microsoft-client M3 and benchmarks. **Next R5:** consume real R3 input PDUs
  into the existing typed X11 event form only after R3 share/input protocol
  parsing exposes that authoritative boundary; keep translation and native
  dispatch separate and do not create another session/input controller. M3
  remains OPEN.

  implement RDPGFX/DVC lifecycle, AVC420 capability selection, surface mapping,
  changed-region encoding, reference-frame correctness, frame ACK flow control,
  resizing and reconnects together with authorized desktop capture/input.
  Reuse existing first-party C++23 dirty-tile/fingerprint/NV12 scheduling;
  permit native RDPGFX fills, copies and cache reuse (not additional codecs).
  **Use x264 as the sole initial software H.264 encoder:** build a pinned,
  license-reviewed static x264 library (without its CLI/FFmpeg) within the one
  reused build root and link it into the future server executable through a
  small C++23 RAII wrapper. Verify static-link feasibility on Linux/GCC,
  macOS/Clang and Windows/MSVC; keep the current standalone protocol SDK
  independent of encoder dependencies until the runtime is implemented.
  Give one owner exclusive encoder access and lifetime, validate NV12 strides
  and dimensions, and preserve NAL output until packetization. x264 encodes
  complete H.264 pictures even when capture/conversion and RDPGFX updates
  are dirty-region-aware; preserve reference continuity across submissions.
  Defer ClearCodec, Planar and RemoteFX compression entirely; AVC444/v2 is a
  later H.264-only option **only if client negotiation or text fidelity requires
  it**. Never advertise an unsupported mode or silently fall back when AVC420
  is unavailable. **Status: NOT RUN / not a working RDP server.**
  **R4 single-owner graphics presentation ordering (2026-10-15):**
  A new C++23 `GfxPresentationLifecycle` composes the existing
  AVC420 CAPS_ADVERTISE/CONFIRM, CREATE/MAP/DELETE encoders and
  64-entry ACK window. Only future R3-authenticated, admitted graphics
  DVC callbacks may supply its trusted monotonic channel generation;
  it does not authenticate or transmit graphics independently.
  Full-send receipts with unique serial, command and generation
  gates must match before subsequent commands are allowed:
  CAPS_CONFIRM completion precedes CREATE, CREATE completion precedes
  MAP, and MAP completion precedes frame/ACK admission. DELETE
  completion precedes same-channel surface reuse. Invalid caps,
  premature frames, stale completion callbacks and old-generation
  ACKs are denied, disconnect cancels outstanding state.
  Dedicated registered CTests: `graphics.channel-lifecycle-ordering`,
  `graphics.channel-lifecycle-denials`,
  `graphics.surface-resize-revocation`,
  `graphics.frame-publication-backpressure`. **PASS:** GCC 14.2 and
  Clang 17 strict C++23 ASan/UBSan 4/4 cases each; isolated CTest
  4/4. **NOT RUN:** full repository local CTest, exact new commit
  hosted CI, owner Linux/X11, Windows CLANG64 Clang23, macOS27,
  authorized R3 DVC, real x264, client and benchmarks.
  **Next R4:** actual authorized R3 DVC full-send callback then
  integrate the existing H.264 frame owner/x264. Gate B NOT ACCEPTED.
  **R4 RDPGFX segmented-data envelope (2026-10-15; focused source
  validated before integration):** Portable `RDP_SEGMENTED_DATA`
  server framing wraps complete graphics-message sequences without
  allocation. <=65,535 bytes uses SINGLE (0xE0) plus uncompressed
  RDP8 header 0x04; larger payloads use MULTIPART (0xE1), uint16
  segment count, uint32 uncompressed size and bounded
  RDP_DATA_SEGMENT entries. Exact in-place expansion is supported;
  other overlap, empty/oversized input and short output fail before
  mutation. R3 still owns `Microsoft::Windows::RDS::Graphics`
  DRDYNVC creation, fragmentation and full-send completion.
  Dedicated CTests: `graphics.segmented-data-single`,
  `graphics.segmented-data-multipart`,
  `graphics.segmented-data-denials-inplace`.
  **Focused PASS:** GCC 14.2 and Clang 17 strict C++23 ASan/UBSan
  3/3 each under `~/rdp-server/build/r4_segment_stage`.
  **NOT RUN at authoring:** full local CTest, owner Linux/X11,
  Windows CLANG64/Clang23, macOS27, live R3 DVC/client/x264/benchmarks.
  **Next R4:** compose mapped AVC420 output with this envelope at
  the R3 full-send boundary; then integrate reviewed static x264.
  **R4 RDPGFX segmented-data exact-SHA CI (2026-10-16):**
  source `88e4c3faaff6559dea8139583890c2ef6b7694cb`,
  [Actions 38864509039](https://github.com/k1moradi/RDP-server/actions/runs/38864509039)
  **FAIL overall** only because Windows/MSVC Debug has five
  pre-existing R10 TLS credential tests failing. R4's three
  `graphics.segmented-data-*` tests PASS on every hosted OS that
  reached CTest. Linux/GCC **271/271 Debug + Release PASS**;
  macOS/AppleClang **253/253 Debug + Release PASS**; Windows/MSVC
  Debug **264/269 PASS**, segmentation tests PASS, Release NOT RUN.
  Parent `6369d8622057aa3f315af55011b52c1d74325d5b`,
  [Actions 38864378401](https://github.com/k1moradi/RDP-server/actions/runs/38864378401),
  already failed the same five Windows runtime TLS cases, proving
  they predate R4. R10 Issue #15 owns that blocker. Docs policy
  and R9 security sanitizer jobs PASS. Owner Linux/X11, Windows
  CLANG64/Clang23, macOS27, live R3 Graphics DVC, x264 and
  Microsoft-client graphics remain NOT RUN. Gate B remains OPEN.
  **R4 AVC420 visible/coded picture crop (2026-10-15, source parent a604ab9ab1aa77caeb5fb74feb8fbeac0afde94a):**
  distinguish 16-aligned H.264 codedGeometry from actual mapped
  RDPGFX visibleGeometry and region mask, preserving zero/zero
  default for previous callers. 1920x1088 coded may target a
  1920x1080 surface; RECT16 destRect and region mask crop to 1080.
  Add bounded gfxAvc420CodedGeometry() alignment helper; reject
  zero/partial visible geometry, padded mask regions and u16 overflow.
  The ONE R4 owner now verifies visible versus mapped surface size.
  Dedicated CTests graphics.avc420-visible-crop,
  graphics.avc420-visible-crop-rejections and
  graphics.avc420-mapped-padded-picture cover valid PDU bytes,
  invalid geometry/output atomicity and full-send receipt.
  **NOT RUN at authoring:** local whole-project build, owner's
  Linux/X11, CLANG64 Clang23 and macOS27 test, x264 output SPS crop,
  authenticated R3 channel, real-client desktop or benchmark.
  Gate B remains OPEN. **Next R4:** pinned license-reviewed static
  x264 producing decodable H.264 SPS/picture and R3 full-send DVC.
  **R4 mapped AVC420 delivery preparation + CMake recovery (2026-10-15;
  parent `6d5422f82dc9e644e8fa058e30e22deedb76bd84`):** Restore the previously committed picture
  packetizer and three existing AVC420 picture CTests to the normal
  protocol build/test registry after their registrations were dropped.
  `GfxPresentationLifecycle::prepareAvc420Picture` composes the one
  mapped-surface lifecycle, production Annex-B packetizer and exact
  frame-delivery receipt. Only matching R3 generation, mapped surface,
  coded dimensions and unblocked ACK/frame-ID state permit encoding.
  Rejection never publishes a receipt or ACK; R3 still must transmit
  the entire frame and call `completeFrameDelivery`, or terminally
  abort partial delivery. Three new registered behavior CTests are
  `graphics.avc420-mapped-frame-wire`,
  `graphics.avc420-mapped-frame-denials` and
  `graphics.avc420-mapped-frame-reconnect`.
  **NOT RUN at authoring:** owner Linux/X11, Windows MSYS2 CLANG64/
  Clang 23 and macOS 27, local full checkout CTest, real R2/R3
  graphics channel, pinned static x264, real H.264 desktop or
  benchmarks. Synthetic Annex-B fixture proves framing only.
  **Next R4:** integrate reviewed static x264 producing decodable
  pictures and R3's authorized DVC full-send writer. Gate B OPEN.
  **R4 AVC420 Annex-B picture transport frame (2026-10-15):**
  The compiled portable graphics protocol SDK now has the first
  correctly sized START_FRAME, WIRE_TO_SURFACE_1 with AVC420
  METABLOCK/region mask/quant-quality entries and borrowed Annex-B
  bitstream, and matching END_FRAME serializer. It reuses R4's
  mapped-surface and full-delivery receipt contracts; this is an
  offline wire boundary, not a second graphics schedule or x264
  encoder. The legacy uncompiled gfx_avc420_frame.cpp builder
  lacked any encoded H.264 bytes and must NOT be used for live
  graphics. New central CTests `graphics.avc420-picture-wire`,
  `graphics.avc420-picture-rejections`,
  `graphics.avc420-picture-overlap` cover full wire lengths and
  endianness, region clipping, quant values, Annex-B presence,
  buffer failure atomicity and overlap-safe bitstream copying.
  Actual x264 Annex-B picture generation and profile validation,
  R3 authorized DVC fragmentation/write completion, human
  Microsoft-client rendering, owner three-platform tests and
  benchmarks remain NOT RUN. Gate B/M3 remain OPEN.
  **Next R4:** connect this production picture builder to the
  single R4 frame delivery receipt via the R3-authorized writer;
  source and statically link a reviewed pinned x264 encoder.
  **R4 frame delivery receipt and lifecycle-build recovery
  (2026-10-15):** Restore first-party R4 presentation lifecycle source
  and its four existing graphics CTests to the central CMake registry
  after a concurrent integration dropped those registrations. Extend
  that one graphics lifecycle with a single in-flight complete-frame
  receipt (R3 generation, monotonic serial, frame ID, byte count);
  ACK tracking starts ONLY when R3 attests the full logical
  START_FRAME..END_FRAME was delivered. Reject duplicate or full
  outstanding IDs before delivery using the existing ACK authority.
  Partial, forged and stale delivery receipts cannot publish a frame.
  Abort on terminal transport failure revokes the channel; block
  surface deletion while a logical frame is being sent.
  Two new behavior CTests are `graphics.frame-delivery-receipt-ordering`
  and `graphics.frame-delivery-abort-revocation`, reusing the four
  existing lifecycle cases and executable. Full project and owner
  three-platform exact-SHA validation **NOT RUN at authoring**.
  Real R3-admitted DVC, static x264 and Microsoft-client graphics
  remain **NOT IMPLEMENTED / NOT RUN**. Next: R3 owner supplies a
  genuinely authorized graphics-channel writer and full-send receipt.
  **R4 bounded frame ACK/window (2026-10-15, implemented):**
  parse one reassembled MS-RDPEGFX FRAME_ACKNOWLEDGE command and
  maintain at most 64 exact outstanding frame IDs in the R4 owner.
  Out-of-order matches retire only that ID; duplicate/full-window
  submissions fail closed. The 0xFFFFFFFF queue-depth sentinel
  suspends ACK waiting and clears pending IDs; finite depths resume.
  The R3-authorized channel owner must supply nonreused generations
  to prevent late ACKs releasing frames after resize or reconnect;
  zero generation deactivates the window on disconnect. The client
  queue depth is buffered bytes, not a frame count. No second
  scheduler or R3 dynamic-virtual-channel router was introduced.
  Dedicated CTests: `graphics.frame-ack-wire`,
  `graphics.frame-ack-suspension`, `graphics.frame-ack-rejections`,
  `graphics.frame-ack-correlation`,
  `graphics.frame-ack-bounded-backpressure`, and
  `graphics.frame-ack-stale-generation`. **PASS:** GCC 14.2
  and Clang 17 C++23 ASan/UBSan, all 6 cases each; isolated
  CTest 6/6. **NOT RUN at authoring:** full project CTest,
  owner Linux/Windows CLANG64/macOS27, exact-SHA CI, authorized
  DVC or real Microsoft-client H.264 desktop. **Next R4:**
  integrate this window into the one graphics owner after R3's
  authorized DVC lifecycle and test resize/scheduling/backpressure.
  **R4 bounded AVC420 capability exchange (2026-10-15, implemented):**
  portable MS-RDPEGFX CAPS_ADVERTISE parsing and exact CAPS_CONFIRM
  serialization accept only advertised version 8.1 with its explicit
  AVC420_ENABLED flag. The parser checks every variable-length CAPSET
  header and data length, rejects duplicates, malformed/trailing data,
  unsupported flags and unknown-only offers. It neither opens a channel
  nor enables a session or x264 encoder. The dedicated CTests
  `graphics.avc420-capabilities-selection`,
  `graphics.avc420-capabilities-rejections`, and
  `graphics.avc420-capabilities-header-bounds` cover exact confirmation,
  truncation, overflow, unsupported features and the successive-header
  bounds regression. **PASS:** GCC 14.2 and Clang 17 strict C++23
  ASan/UBSan (3/3 each); isolated staging CTest (3/3).
  **NOT RUN at authoring:** full checkout CTest, exact-commit GitHub CI,
  owner Linux/X11, Windows CLANG64/Clang23, macOS27, authorized R3 DVC,
  real-client H.264 and performance. Gate B remains unaccepted.
  **Next R4 gate:** bind the confirmed profile to R3's authorized DVC
  lifecycle and surface creation, then validate client frame scheduling.
  **R4 surface lifecycle wire increment (2026-10-15, implemented):**
  portable allocation-free CREATE_SURFACE, MAP_SURFACE_TO_OUTPUT and
  DELETE_SURFACE encoders now implement MS-RDPEGFX 2.2.2.9/.10/.15.
  XRGB8888 creation checks nonzero dimensions and 16-bit wire bounds;
  each output buffer is validated before any byte is written.
  Dedicated registered CTests `graphics.surface-lifecycle-wire` and
  `graphics.surface-lifecycle-rejections` exercise exact golden
  bytes, capacity/geometry rejections and atomic failure.
  **PASS:** GCC 14.2 and Clang 17 strict C++23 ASan/UBSan,
  2/2 behaviors per compiler; isolated staged CTest 2/2.
  **NOT RUN:** full repository CTest, exact-commit Actions and
  owner Linux/Windows CLANG64/macOS27 tests, R3 authorized DVC,
  real-client desktop, x264 and graphics benchmarks.
  **Next R4 gate:** connect the negotiated RDPGFX channel to
  CREATE/MAP/DELETE ordering, resize and cleanup under the
  existing single graphics owner; keep Gate B open.
- [ ] Confirm H.264 capability negotiation and a genuinely interactive,
  authenticated desktop with current Windows App on Windows/macOS and
  Windows 11 Remote Desktop Connection. Record actual versions, advertised
  capability sets and failures (including AVC disabled/missing), then verify
  text/input, scrolling, menus, images, clipboard, display resize, frame
  ordering and reconnect. **Status: NOT RUN; no real-client acceptance yet.**
  **Gate C first human acceptance (NOT RUN):** with explicit permission,
  a human must authenticate using a real Microsoft client, see the
  Linux/X11 desktop, move the pointer, type and scroll in a terminal,
  open menus, resize and reconnect without stale updates. Record exact
  client/version, server SHA, negotiation/first failure and separate
  negative tests for invalid credentials and missing AVC. Clipboard,
  screenshot, file transfer and additional OS acceptance remain under
  existing P1 items, not blockers to this first desktop trial.

### P1 — Real client features and performance

**Parallel development; staged feature acceptance:** R6/R7 Windows and
macOS server adapters start immediately, not after Linux testing.
R8 CLIPRDR/file work starts independently and converges for the
declared full-feature beta at M5. Preserve these TODO items and their
real-client acceptance criteria, but do not block the first Linux/X11
interactive desktop (M3) on clipboard, file transfer, Wayland or
optional codecs. Human acceptance remains Linux, then Windows, then
macOS; all platform Debug/CTest work proceeds in parallel.

- [ ] **One native CLIPRDR clipboard session owner** (MS-RDPECLIP): reuse
  `src/server/clipboard/remote_transfer.*`, existing first-party PDU/PNG/DIB
  helpers and tests. Implement channel/capability negotiation, long/short
  named format mapping, Format List acknowledgment, Unicode text, PNG and
  DIBV5/DIB requests/responses, bounded reassembly and cancellation.
  Ordinary Format Data Responses have **no request ID**: permit only one
  outstanding format-data request, associate it with the advertised generation,
  drain obsolete replies, and fail closed on irrecoverably ambiguous timeout.
  File-content replies have separate `streamId` correlation. Do not create
  competing session controllers or depend on xrdp/FreeRDP at runtime.
  **Status: PARTIAL — R8 portable Format List wire intake added on
  2026-10-15; native channel/desktop integration NOT RUN.** The existing
  `RemoteTransfer` owner validates bounded long UTF-16LE or 36-byte short
  ASCII/UTF-16LE Format Lists using R3-negotiated capabilities. Registered
  `PNG` and `FileGroupDescriptorW` IDs are generation-scoped. Malformed
  names/headers/duplicates fail closed; an exact eight-byte
  `CB_FORMAT_LIST_RESPONSE` signals success only after explicit native
  offer acceptance. Declined offers clear advertised IDs while retaining
  stale-response quarantine. Dedicated CTests:
  `clipboard.long-format-list-generation`,
  `clipboard.short-format-list-negotiation`,
  `clipboard.format-list-response-native-acceptance`. GCC 14.2,
  Clang 17 and GCC ASan+UBSan isolated fixture checks PASS; full repo
  CTest, CI, owner platforms and live clipboard NOT RUN at authoring.
  **R8 capability negotiation (2026-10-15):** the same `RemoteTransfer`
  now parses optional bounded `CB_CLIP_CAPS`: at most 16 sets, a single
  exact 12-byte General set, checked lengths, unknown-set skip, mandatory
  short-name fallback when flags are absent, and fail-closed malformed or
  repeated advertisements. General version is informational; negotiated
  flags are the intersection of the peer flags and R3-supplied actual
  server-advertised flags. The new format-list entry point derives long
  versus short names from those flags, preserving native-offer acknowledgment
  and stale-generation isolation. Dedicated
  `clipboard.capabilities-negotiation-format-gating` CTest covers Microsoft's
  capability example, fallback, unknown versions/flags/sets, bounds,
  duplicates and disconnect. Focused GCC/Clang/ASan tests PASS; exact-SHA
  CI and owner three-platform suite NOT RUN at authoring.
  **R8 joined-MCS acknowledgment envelope (2026-10-15):** added
  `RemoteTransfer::encodeJoinedFormatListResponse` using R3's existing
  `McsChannelJoinWriteGate::encodeJoinedSendDataIndication`. The
  8-byte generated OK/FAIL response is enclosed in the 8-byte
  `CHANNEL_PDU_HEADER` (length 8, FIRST|LAST) and the T.125 server
  SendDataIndication only after the gate confirms that MCS channel join
  was fully written. An old/forged response, malformed response header,
  unknown/unjoined channel, insufficient output or disconnect fails
  without output mutation. This offline bridge does **not** assert
  NLA/OS admission, actually send TLS bytes, or grant a channel ID as
  CLIPRDR. New dedicated `clipboard.format-list-response-joined-mcs-envelope`
  CTest covers exact 30-byte framing, invalid responses and join state.
  Full CI and owner OS tests: NOT RUN at authoring. **Next:** R3's sole
  authenticated session owner must bind verified `cliprdr` channel IDs,
  permissions, outbound writer completion/cancellation and inbound
  reassembly to this existing R8 owner; R5/R6/R7 adapters remain required.
  **R8 inbound joined-static-channel dispatch (2026-10-15):**
  the same `RemoteTransfer` owner now checks R3's confirmed
  MCS join predicate, exact expected CLIPRDR channel ID, external
  authenticated/OS-session admission and unsegmented T.125 request
  BEFORE parsing a single complete uncompressed static VC chunk.
  The MS-RDPBCGR 8-byte CHANNEL_PDU_HEADER total length, FIRST|LAST
  flags, compression and PDU framing are checked before routing
  `CB_CLIP_CAPS`, `CB_FORMAT_LIST` and `CB_FORMAT_DATA_RESPONSE`
  to their existing generation-safe handlers. Unexpected types are
  ignored; invalid inbound framing poisons the clipboard coordinator.
  Borrowed received-data spans never outlive the caller's MCS input.
  Dedicated `clipboard.joined-static-channel-inbound-gates` CTest
  covers membership, admission, name negotiation, offers, data,
  malformed headers, stale responses and teardown; restore existing
  `clipboard.format-list-response-joined-mcs-envelope` registration.
  **At authoring:** full hosted CI and owner's local three-platform
  CTest NOT RUN. This offline adapter does not authenticate, allocate
  CLIPRDR role permissions, own a TLS writer, reassemble multi-chunk
  MCS/VC payloads, or access a live clipboard.
  **Next:** R3 actual authenticated channel-role admission and
  R9 bounded fragmented-channel reassembly, then R5/R6/R7 native
  integration and real-client acceptance.
  **Verified hosted CI for R8 inbound dispatch:** exact implementation
  commit `288f10ebd7c51616f16098c39c3fae9d7a9c090b`,
  [Actions 38845220243](https://github.com/k1moradi/RDP-server/actions/runs/38845220243)
  **PASS** documentation policy, Linux/GCC **207/207**,
  macOS/Clang **193/193**, and Windows/MSVC **203/203**
  in BOTH Debug and Release. Both R8 joined-channel CTests
  PASS on all three hosted platforms. Owner-operated Linux/X11,
  Windows MSYS2 CLANG64 Clang23, macOS27, authenticated desktop,
  real-client clipboard, Firefox PNG File paste and performance
  **NOT RUN**.
  **R8 transactional outbound Format Data Request (2026-10-16):**
  `RemoteTransfer::prepareJoinedFormatDataRequest` now builds a
  complete 12-byte CLIPRDR request inside the uncompressed FIRST|LAST
  static VC header, then delegates the MCS SendDataIndication to R3's
  confirmed-join encoder. It rejects unadvertised/stale formats,
  wrong or unjoined channel IDs and short output capacity without
  reserving a phantom pending response or mutating output. The new
  monotonic joined-request receipt lets R3's sole writer report
  cumulative byte progress; pre-write cancellation is safe, whereas
  partial/uncertain delivery poisons the transfer until disconnect.
  Complete delivery is required before accepting any data response;
  an old-generation completed response is discarded, never relabeled.
  Dedicated `clipboard.format-data-request-joined-mcs-envelope`
  and `clipboard.format-data-request-generation-cancellation`
  CTests cover golden bytes, failures, partial writes, reconnects
  and stale response quarantine. This remains an OFFLINE R8 wire
  boundary: genuine R2/R3 TLS/NLA/OS admission, CLIPRDR role and
  one TLS writer remain external, and media/OS paste acceptance
  is NOT RUN. At authoring full exact-SHA CI and owner-machine CTests
  NOT RUN; next bridge the R3 authorized writer and verify bytes.
  **R8 outbound request exact-code validation (2026-10-16):**
  implementation `22915cee335df7d82149728543866f45db7bc8aa`
  is an ancestor of verified [Actions run 38850747646](https://github.com/k1moradi/RDP-server/actions/runs/38850747646)
  on `a0c39e4a612c740949c05e4a9699f711061c21d0`.
  The initial implementation-SHA CI run 38850425244 had **zero jobs**
  because a concurrent shared workflow edit duplicated YAML jobs; R10
  repaired that in `4d24b8b3b9857370fef8608cf7d7782f644df3ea`.
  A further unrelated R10 test fixture used an unsupported CMake
  permission token, fixed in `a0c39e4a612c740949c05e4a9699f711061c21d0`.
  On the corrected descendant SHA: **PASS** Linux/GCC 226/226,
  macOS/Clang 209/209 and Windows/MSVC 228/228 CTests in both
  Debug and Release, both new R8 joined-request tests on every
  platform, 15/15 sanitizer clipboard tests, and docs policy.
  Owner-operated Linux/X11, Windows MSYS2 CLANG64/Clang23,
  macOS27 and live authenticated clipboard/Firefox PNG File paste
  remain **NOT RUN**. Next: R3's genuinely authorized single TLS
  writer and receipt handoff, then validated media byte readiness.
- [ ] **Bounded eager text/image retrieval, with delayed OS presentation**:
  after a *legitimate client Format List* for generation N, prioritize
  `CF_UNICODETEXT` and registered `PNG` (look up names, not fixed IDs),
  falling back to `CF_DIBV5`/`CF_DIB` when PNG is unavailable. Serialize
  prefetch over the one-at-a-time format-data channel without starving an
  actual paste. Maintain advertised/requested/receiving/ready/failed state;
  cache only verified, size-limited UTF-8 text and compressed image bytes
  for the current generation. Decode/convert on demand with checked image
  dimensions and bounded worker resources; avoid unconditional expanded
  bitmap copies. Never publish incomplete, corrupt or superseded content.
  Client OS focus/privacy policy may delay or suppress an announcement:
  do not poll, infer unseen copies or bypass the client's policy.
  **R8 bounded prefetch selection (2026-10-15): PARTIAL.**
  The existing `RemoteTransfer::beginNextPrefetch` selects
  CF_UNICODETEXT for text, or registered PNG then CF_DIBV5 (17)
  and CF_DIB (8) for image. Only formats from the current offer
  qualify, with one attempted request per numeric ID/generation,
  no concurrent outstanding request, and stale-response draining
  before reuse. Reoffer/disconnect reset attempts. This method
  does not validate media, cache bytes, claim OS clipboard ownership
  or block the event loop; a caller tries fallback only on failed
  or rejected data. New dedicated CTest
  `clipboard.prefetch-unicode-png-dib-single-flight`.
  Full CI and owner three-platform validation NOT RUN at authoring.
  **R8 bounded Unicode text readiness (2026-10-16):** the existing
  `RemoteTransfer` now validates current-generation CF_UNICODETEXT
  UTF-16LE Format Data Response bytes, then owns a UTF-8 snapshot.
  Exactly one trailing UTF-16 NUL is required; odd lengths, embedded
  NUL, invalid surrogate pairs and wire data over 1 MiB fail without
  exposing partial text; CRLF normalizes to LF. A malformed content
  payload leaves sound PDU framing usable but never becomes paste-ready.
  New offers, disconnect and coordinator poison invalidate readiness.
  Dedicated `clipboard.verified-unicode-text-readiness` CTest.
  Exact-code [Actions run 38857378176](https://github.com/k1moradi/RDP-server/actions/runs/38857378176):
  Linux/GCC Debug+Release 238/238 each and Windows/MSVC
  Debug+Release 239/239 each PASS, as do new R8 and sanitizer tests.
  macOS R8 CTest PASS but full Debug suite FAIL 15/220
  `transport.tcp-*` CTests (first: native accept ownership);
  macOS Release NOT RUN. Owner machines and live paste NOT RUN.
  **R8 validated image readiness (2026-10-16):** `RemoteTransfer` now
  accepts only a current-generation successful response for the advertised
  registered PNG ID, CF_DIBV5 (17) or CF_DIB (8), validates it through the
  existing first-party PNG/DIB rules, and owns the original wire bytes.
  Registered PNG name resolution wins over numeric fallback IDs. CF_DIBV5
  requires a 124-byte BITMAPV5HEADER. Retained payload is bounded by the
  existing 8-MiB CLIPRDR PDU limit, while width/height must also fit a
  256-MiB prospective 32-bpp decoded working set. PNG remains compressed
  and DIB remains packed; there is no eager bitmap expansion. A new offer,
  disconnect or poisoned channel makes cached image readiness unavailable,
  and an obsolete-generation response cannot repopulate it. DIB structural
  validation is now allocation-free and reused by BMP wrapping. Dedicated
  `clipboard.verified-image-readiness` CTest. Exact implementation
  `015217fc304dd7b4beea73a09e1f02bbe44b038f`,
  [Actions 38865310807](https://github.com/k1moradi/RDP-server/actions/runs/38865310807)
  **PASS**: Linux/GCC Debug+Release **273/273** each, macOS/Clang
  Debug+Release **255/255** each, Windows/MSVC Debug+Release **271/271**
  each; the dedicated R8 test passes all six configurations. R9
  ASan/UBSan **18/18 clipboard + 10/10 MCS/CredSSP PASS**,
  documentation-policy PASS, and each installed-package consumer
  **1/1 PASS**. Owner Linux/X11, Windows MSYS2 CLANG64/Clang23,
  macOS27, native publication and real-client Firefox paste are NOT RUN.
  **Remaining:** native prefetch scheduling/conversion and actual OS paste
  acceptance; R3 authenticated writer authority remains external.
- [ ] **Nonblocking clipboard paste readiness**: register a pending OS paste
  request and deadline; process RDP/desktop events while remote transfer or
  image conversion completes, then satisfy the *same* request or reject on
  timeout, disconnect, clipboard replacement or owner loss. Do not call
  `sleep_for` or wait on a condition variable in the event loop. Support
  X11 asynchronous SelectionRequest/SelectionNotify and INCR for large data;
  use native asynchronous data offers on Wayland/macOS/Windows adapters.
  Never return a success or an empty image before required bytes are ready.
  **R8 portable pending-paste receipt (2026-10-16): PARTIAL.**
  The existing `RemoteTransfer` event-loop owner now registers one native
  text/image paste receipt with a monotonic caller-supplied deadline and a
  sequence that never resets across disconnect. Polling is nonblocking:
  current verified text/image completes the same receipt; exact-deadline
  expiry rejects it; a valid new Format List records `ClipboardReplaced`;
  disconnect records `Disconnected`; native owner loss is an explicit
  stale-sequence-checked cancellation; channel poison records
  `ChannelError`. Terminal outcomes are delivered once. While a paste is
  pending, `beginNextPrefetch` cannot start further speculative work, but
  an already-sent request still drains before the live paste can reuse the
  one ordinary Format Data Response slot. This portable boundary does not
  block, sleep, start threads, publish an OS clipboard, convert image bytes
  or grant R3 channel authority. Dedicated
  `clipboard.nonblocking-paste-readiness` CTest. Exact implementation
  `cc8e0a9cbfbbf6891720eab03f1e94b926a30285`,
  [Actions 38870845839](https://github.com/k1moradi/RDP-server/actions/runs/38870845839)
  **PASS**: Linux/GCC Debug+Release **277/277** each, macOS/Clang
  Debug+Release **259/259** each, Windows/MSVC Debug+Release **277/277**
  each; the dedicated R8 test passes all six configurations. R9 Clang
  ASan/UBSan **19/19 clipboard + 10/10 MCS/CredSSP PASS** and the bounded
  MCS/CLIPRDR fuzzer **1/1 PASS**; documentation-policy PASS; each staged
  installed-package consumer **1/1 PASS**. Owner Linux/X11, Windows MSYS2
  CLANG64/Clang23, macOS27 and live native paste remain NOT RUN.
  **R8 Linux/X11 binding (2026-10-16): PARTIAL.** The first native
  `X11ClipboardAdapter` now binds this same receipt to X11 SelectionRequest
  handling for `UTF8_STRING` and registered `image/png`, while exposing only
  an exact remote-format fetch intent for R3's future authorized writer.
  `PasteKind::Png` prevents a ready DIB/DIBV5 fallback from satisfying PNG.
  **Remaining:** genuine R3-authorized request transmission, Windows/macOS
  adapters and real-client paste acceptance.
- [ ] **OS clipboard ownership without competition**: one native adapter per
  OS; on X11 use the `CLIPBOARD` selection (not `PRIMARY`), XFixes owner-change
  events, timestamps, TARGETS and selection-clear rules. Claim ownership on
  a genuine new remote offer, ignore own changes, suppress echo loops with
  source/generation, and yield when a local app or clipboard manager (for
  example Qlipper) becomes owner. Do not repeatedly reclaim selection from
  a timer or mistake a manager's reoffer for fresh remote content. Test
  ownership handoff, INCR, local copies and races with disconnect/reconnect.
  **Status: PARTIAL — R8 native X11 CLIPBOARD increment (2026-10-16).**
  A Linux-only `X11ClipboardAdapter` borrows R5's sole XCB connection/root
  and optional event fanout; it never creates a second XCB connection or
  clipboard generation owner. It claims only `CLIPBOARD`, publishes bounded
  `TARGETS`, serves verified `UTF8_STRING` and registered compressed
  `image/png`, and never advertises DIB bytes as PNG. One delayed native
  request maps to one monotonic R8 paste receipt; a second delayed request
  fails deterministically. SelectionClear/local takeover yields immediately,
  exact-sequence owner-loss cancellation prevents stale callbacks, own owner
  observations are ignored, and the yielded generation is never reclaimed by
  timer. Direct properties remain capped at 64 KiB. Larger verified UTF-8 text
  and registered PNG use ICCCM INCR without another whole-payload copy: one
  active transfer advertises its total byte count, then advances in bounded
  64-KiB property chunks only after the exact requestor/property emits
  PropertyDelete. The transfer finishes with the required zero-length chunk.
  A five-second monotonic acknowledgement deadline, clipboard generation or
  ownership-epoch change, local takeover, requester destruction and stale
  property events cancel safely; requestor event masks are restored when that
  window still exists. Dedicated headless CTests:
  `clipboard.x11-selection-ownership-generation`,
  `clipboard.x11-targets-publication`,
  `clipboard.x11-selection-request-nonblocking`,
  `clipboard.x11-selection-owner-loss`,
  `clipboard.x11-disconnect-late-paste-fence`,
  `clipboard.x11-incr-large-text-progression`,
  `clipboard.x11-incr-png-progression`, and
  `clipboard.x11-incr-cancellation`.
  Isolated GCC 14.2 and Clang 17 strict C++23 native-source compilation PASS;
  deterministic fake-XCB behavior 4/4 PASS and Clang ASan+UBSan+LSan 4/4
  PASS. Initial implementation `047e4ffc9ce93faeee1a05ecc9eb6e75079f84cc`
  Actions **38876114364** passed docs policy and compiled the new clipboard
  target, but Linux stopped before CTest on a GCC 13.3 `-Werror=extra`
  enum/integral conditional in R5's new borrowed `rootWindow()` fallback.
  Correction `24193f2548cfe847749f34dd62c32287819673e5`, Actions
  **38876427741**, builds the Linux native targets; three new R8 CTests PASS.
  The ownership-generation CTest initially aborted before its assertions
  because the shared helper invokes its default registration without a case
  argument. Test-driver correction
  `9d6fc40ec78a33e4a558f61b9f6e9f36a96110cd`, Actions **38876792846**,
  then builds the real Linux adapter and passes **23/23** clipboard-labelled
  CTests, including all four new X11 behaviors. R9 sanitizer clipboard
  **19/19 PASS**, bounded CLIPRDR fuzzer **1/1 PASS**, and documentation
  policy PASS. The workflow is still red from the unrelated concurrent
  `transport.gcc-conference-create` assertion on Linux/macOS, not from R8.
  Owner Linux/X11, Windows CLANG64/Clang23, macOS27, live clipboard,
  Microsoft client/Firefox and performance are NOT RUN. Genuine
  R3 CLIPRDR-role activation remains external. **Bounded X11 INCR is now
  implemented in the R8 adapter; authoring parent main `95c79fbb610c007431b1227bc5a5cc05816dea45`, exact-SHA
  hosted CI and owner/live desktop tests are NOT RUN at authoring. Next R8:
  genuine R3-authorized CLIPRDR request transmission, then native Windows/macOS
  adapters and native file-destination integration.**
- [ ] **Native clipboard file streaming, never whole-file prefetch**:
  negotiate `CB_STREAM_FILECLIP_ENABLED`, `FileGroupDescriptorW` and
  FileContents size/range requests; use `streamId` per file-content request,
  check 64-bit sizes, offsets, bounds and filenames, and support
  `CB_LOCK_CLIPDATA`/`CB_UNLOCK_CLIPDATA` when negotiated. Retain bounded
  metadata and chunk buffers, not entire file bodies; cancel and release
  locks cleanly. CLIPRDR copies files; RDPDR is optional drive redirection.
  For Linux file managers, independently validate a usable destination
  integration (URI/file-descriptor/portal or another native adapter) since
  RDP file streaming alone does not make remote files locally openable.
  Do not require FUSE or `~/thinclient_drives` by default.
  **Status: PARTIAL — bounded R8 FileContents owner (2026-10-16).**
  The existing `RemoteTransfer` now accepts `FileGroupDescriptorW` only
  when `CB_STREAM_FILECLIP_ENABLED` is jointly negotiated. It retains at
  most 64 exact 592-byte FILEDESCRIPTORW metadata records, never file bodies.
  UTF-16 file names must be terminated, scalar-valid leaf names with zero
  padding; path separators, drive separators, control characters and Windows
  reserved filename characters are rejected. File attributes and optional
  64-bit sizes are generation scoped; directories are represented as metadata
  but cannot start byte-range reads. Sizes above 4 GiB and nonzero high offset
  DWORDs require `CB_HUGE_FILE_SUPPORT_ENABLED`.

  File size/range requests use one monotonic 32-bit `streamId` at a time,
  never reused across disconnect, with a 64-KiB maximum range. Responses must
  echo that exact stream ID. Size replies are exact 64-bit little-endian
  values; range replies are borrowed bounded spans rather than retained file
  copies. A valid new Format List invalidates metadata while an already-issued
  old-generation response is drained as obsolete. Wrong stream IDs,
  malformed size replies and oversized/out-of-file range replies fail closed.
  Because lock/unlock write receipts are not implemented yet,
  `CB_CAN_LOCK_CLIPDATA` is no longer included in R8's supported-general-flags
  mask; the owner now advertises at most long names, stream file copy,
  no-file-paths and huge-file support.

  The same stream receipt can now be prepared as one complete uncompressed
  static-VC/MCS SendDataIndication only after the expected CLIPRDR channel is
  confirmed in the existing R3 join gate. The caller-owned framed bytes have
  exact cumulative-write accounting: zero submitted bytes may be cancelled,
  partial/uncertain delivery poisons the coordinator until disconnect, and a
  fully delivered old-generation stream drains its response as obsolete.
  Joined membership remains necessary but explicitly does not grant R2
  admission, CLIPRDR role authority, session-stage permission or TLS-writer
  ownership.

  Dedicated CTests:
  `clipboard.file-descriptor-metadata-validation`,
  `clipboard.file-contents-size-range-streaming`,
  `clipboard.file-contents-response-rejections`, and
  `clipboard.file-contents-joined-mcs-envelope`.
  The original FileContents owner authoring parent was
  `23d9f362283d27bee7fc7cd4646b402512934575`; the joined-envelope increment
  authoring parent is `be99fb50d0f1c7ae981a8e706ec44794a309eadc`.
  Exact-SHA CI and owner machine tests for the joined-envelope increment are
  NOT RUN at authoring. Genuine R3-authorized TLS emission,
  `CB_LOCK_CLIPDATA`/`CB_UNLOCK_CLIPDATA` receipts, native destination
  integration, directory-tree materialization and real-client file copy remain
  NOT IMPLEMENTED / NOT RUN. **Next R8:** add lock/unlock lifetime receipts and
  continue Windows/macOS native clipboard work while R3 completes the
  authoritative post-admission virtual-channel writer contract.
- [ ] **Real Microsoft-client clipboard acceptance**: macOS screenshot
  taken while Windows App is unfocused, delayed Format List after refocus,
  then remote paste on Linux/X11 into Firefox. Inspect the *synchronous*
  paste event: `clipboardData.items[].getAsFile()` must be non-null with
  MIME `image/png` and the correct screenshot bytes. Exercise immediate
  paste before prefetch completes, repeated paste, local text/image copy
  in both directions, Qlipper competition, PNG/DIB fallback, large INCR
  payloads, file-copy interoperability and clipboard changes mid-transfer.
  An X11 PNG read alone is NOT proof of Firefox file-item acceptance.
  Record client version and capabilities; live host experiments require
  separate authorization. **Status: NOT RUN.**
- [ ] Integrate isolated Linux/X11/Wayland, Windows and macOS desktop,
  clipboard and input adapters; test real Microsoft/FreeRDP clients.
  **R7 M1 increment (2026-10-15):** New, noninstalled macOS-only
  `rdp-server-macos-capture` CoreVideo BGRA read-lock owner and CoreGraphics
  read-only screen-permission preflight; portable, fixed-capacity physical/
  logical display mapping (Retina fractional scales, negative origins,
  monitor gaps, RDP virtual pointer coordinates and display generations).
  No authorization, screen permission request, capture stream, input
  injection, H.264 encoder or clipboard controller is created.
  Dedicated offline CTests: `macos.capture-bgra-layout-bounds`,
  `macos.capture-permission-preflight-revocation`,
  `macos.desktop-retina-points`,
  `macos.desktop-multi-display-invalid`,
  `macos.desktop-reconfiguration`,
  `macos.desktop-virtual-input-coordinates` (portable) and Apple-only
  `macos.capture-bgra-buffer-ownership`,
  `macos.capture-bgra-buffer-native-denials`,
  `macos.capture-bgra-buffer-native-move-replacement`.
  Isolated Linux CMake/CTest **9/9 PASS** including synthetic CoreVideo
  simulation; Clang 17 ASan/UBSan portable **6/6 PASS** and GCC 14.2
  -O2 portable **6/6 PASS**. These are not canonical repository or Apple
  SDK tests. **NOT RUN:** full exact-commit CI at authoring, owner macOS 27,
  MSYS2 CLANG64 23 and Linux exact-SHA tests, permission-dependent live
  desktop, RDP client acceptance and performance. **Next:** native
  CoreGraphics geometry sampler and authorized per-user ScreenCaptureKit
  lifecycle only after R2/R3/R4 interface convergence. M1/M5 remain open.
  **R7 exact-head macOS compile failure and fix (2026-10-15):**
  Initial R7 commit `e13e473bf901524ff53c6e0e01b42dfef2ad041c`,
  [Actions 38799661046](https://github.com/k1moradi/RDP-server/actions/runs/38799661046):
  Ubuntu/GCC and documentation-policy PASS; macOS arm64 FAIL at Debug
  linking the synthetic CoreVideo test due to missing
  `_kCFAllocatorDefault`. Explicit CoreFoundation linkage is now limited
  to the native TEST target. Production R7 and portable RDP library
  linkage are unchanged. Corrected-SHA CI and macOS27 owner tests NOT RUN
  at authoring; M1/M5 acceptance remains open.
  **R7 refresh-owner hardening and CI startup (2026-10-16):**
  The R7 geometry-epoch guard is explicitly noncopyable/nonmovable;
  compile-time assertions in the existing test runner prevent duplicate
  independent epoch owners. Sparse local GCC14.2 CMake CTest **7/7 PASS**
  after this correction. The initial implementation SHA
  `19dd0e781bd558a2f9ebf4f3f76b5561d2e33e00` triggered
  [Actions 38850284552](https://github.com/k1moradi/RDP-server/actions/runs/38850284552)
  **FAIL before any job was scheduled**, because the shared CI workflow
  already defined `publish-protocol-prerelease` twice at the same YAML
  job-map level on its parent (unchanged workflow blob). R9 tracking
  [issue #13](https://github.com/k1moradi/RDP-server/issues/13).
  **NOT RUN:** full repo hosted CTest on that exact SHA, owner macOS27,
  Windows CLANG64 Clang23, Linux/X11, live desktop and benchmarks.
  **R7 Quartz exact-source hosted CI PASS (2026-10-16):**
  Implementation `3849c8e3073822984c185aad1c996f87e448031e`,
  [Actions 38858255530](https://github.com/k1moradi/RDP-server/actions/runs/38858255530)
  completed Ubuntu/GCC **255/255**, macOS/Apple Clang **237/237**,
  Windows/MSVC **254/254** registered CTests **in both Debug and Release**.
  All three new `macos.desktop-native-reconfiguration-*` offline
  CTests passed on all hosted OSes. Documentation-policy, R9 security
  sanitizer, installed SDK consumer, and ZIP/checksum packaging PASS.
  Native CoreGraphics callback code COMPILED/LINKED on hosted macOS;
  tests emitted synthetic events only and NEVER registered the actual
  Quartz callback or accessed TCC. **NOT RUN:** owner macOS27, Windows
  CLANG64 Clang23 and Linux/X11 common-SHA one-root test, actual display
  callbacks, authorized client, live ScreenCaptureKit/input, benchmarks.
  M1/M5 open; next R2/R3-bound event subscription and R4 frame ownership.
  **R7 Quartz display notifications (2026-10-16):**
  Added explicit opt-in CoreGraphics `CGDisplayRegisterReconfigurationCallback`
  and paired removal, with a process-lifetime atomic revision signal and
  single-registration guard. Quartz's begin/end/topology callbacks only
  increment the revision: no frame access, allocations, permission prompt,
  or borrowed C++ callback object is touched. `NativeDisplayGeometryRefresh`
  binds the revision before double-sample enumeration and refuses any
  publish/coordinate lookup following a concurrent notification, including
  a mid-refresh event. Removal invalidates old observations; a failed
  removal leaves registration reserved rather than risk a second owner.
  Three new dedicated offline CTests:
  `macos.desktop-native-reconfiguration-stale-denial`,
  `macos.desktop-native-reconfiguration-during-read`,
  `macos.desktop-native-reconfiguration-revision-sequence`.
  **PASS:** partial local Linux GCC14.2 CMake/CTest 8/8 (two focused
  signal smoke cases and six previous fixture cases); Clang17 ASan/UBSan
  signal smoke 2/2; GCC14.2 -O2 strict signal smoke 2/2. Full new
  production refresh integration and native Quartz callback registration
  require the exact-source GitHub CI and macOS owner validation.
  **NOT RUN at authoring:** canonical full CTest, owner macOS27,
  Windows CLANG64 Clang23, real user session, any TCC/capture, client
  input or latency benchmarks. **Next:** connect this native signal to
  R2/R3-authorized session lifetime and native capture cancellation;
  R4 physical composition remains authoritative; M1/M5 OPEN.
  **R7 topology epoch invalidation (2026-10-16):**
  `NativeDisplayGeometryRefresh` extends existing CoreGraphics read-only
  discovery plus `DesktopDisplayGeometry` with an explicit, bounded
  generation-controlled refresh guard. It invalidates the prior geometry
  before every read/conversion; failed enumeration, unstable observation
  or unsupported mixed-scale layout never permits old pointer positions.
  Explicit `invalidate()` retires geometry synchronously on a future
  R3/native display-change notification; only a complete two-sample
  fresh geometry can restore translations. Generation wrap is terminal.
  No new scheduler, session owner, callback subscription, capture stream,
  TCC prompt, input injection or OS admission is introduced. Three
  new central headless CTests: `macos.desktop-geometry-epoch-refresh`,
  `macos.desktop-geometry-epoch-invalidate`,
  `macos.desktop-geometry-epoch-failed-refresh`. Isolated GCC14.2 CMake
  CTest **7/7 PASS** (3 new + 4 preceding fixture behaviors), optimized
  strict GCC14.2 **3/3 PASS**, Clang17 ASan+UBSan **3/3 PASS**.
  **NOT RUN at authoring:** full canonical CTest/hosted exact-SHA CI,
  owner's macOS27 and Windows CLANG64 Clang23, native live desktop/TCC,
  Microsoft client or benchmarks. **Next:** actual native display-change
  callback registration scoped to a R2/R3-authorized user session;
  coordinate R4 mixed-Retina compositor mapping before capture.
  **R7 exact-source hosted CI verified (2026-10-16):** Corrected
  implementation `8083958d617daff00bf68f02848a11eab416bd7d`,
  [Actions 38849245902](https://github.com/k1moradi/RDP-server/actions/runs/38849245902)
  PASS on Ubuntu/GCC **216/216**, macOS/Apple Clang **201/201**,
  Windows/MSVC **215/215** full registered CTests EACH in both Debug and
  Release; all four new R7 geometry-native CTests passed on every OS.
  Documentation policy, staged SDK consumer and ZIP/hash artifacts PASS.
  Initial implementation `2427cdea0f0aa866e1b8fe8caa53f119317225bf`
  had a synthetic mixed-scale fixture failure in
  [Actions 38849090483](https://github.com/k1moradi/RDP-server/actions/runs/38849090483),
  corrected without weakening assertions.
  **NOT RUN:** owner macOS27, Windows MSYS2 CLANG64 Clang23, Linux/X11
  exact-SHA terminal runs, real TCC/capture/input/Microsoft-client M5
  acceptance and benchmarks. M1/M5 still OPEN.
  **R7 conversion hardening (2026-10-16):** Corrected the
  mixed-scale rejection test so its second display has complete native
  identity/dimensions, and tightened common-scale comparison to relative
  tolerance. This preserves rejection for extremely small but different
  scales. New behavior-named CTests remain registered unchanged;
  isolated GCC14 CTest 4/4 and Clang17 ASan/UBSan 4/4 PASS.
  Corrected-source hosted CI and owner macOS27 remain NOT RUN at
  authoring; M1/M5 still open.
  **R7 native-to-portable compositor geometry (2026-10-16):**
  Native CoreGraphics display observations now feed the existing
  generation-safe `DesktopDisplayGeometry` via `makeDesktopGeometry`.
  A shared minimum Quartz logical origin defines explicit RDP compositor
  pixel placement, supporting single Retina and uniform, isotropic
  scale multi-monitor layouts (negative origins, gaps, stable IDs).
  Reject mixed scale, rotated/mirrored displays and non-integer or
  unrepresentable physical offsets; do not infer native global physical
  origins by multiplying each display by its own Retina scale.
  Preserve previous geometry on failed conversion only under explicit
  caller-side invalidation, not as permission for new input.
  Added native `CGDisplayRotation` observation; no TCC/capture/input.
  New existing-runner CTests: `macos.geometry-native-single-retina`,
  `macos.geometry-native-uniform-multi-display`,
  `macos.geometry-native-mixed-scale-denials`,
  `macos.geometry-native-generation-refresh`.
  **PASS** isolated GCC14.2 Debug CTest 4/4, -O2 strict 4/4,
  Clang17 ASan/UBSan 4/4. **NOT RUN** canonical exact-SHA CI at
  authoring, owner macOS27/CLANG64 Clang23/Linux one-root, genuine
  ScreenCaptureKit, authorized Microsoft client, pointer/cursor or
  benchmarks. **Next:** R4 mixed-Retina physical compositor placement
  and R2/R3-authorized native capture lifecycle; M1/M5 open.
  **R7 exact-commit hosted display-snapshot CTest PASS (2026-10-15):**
  Implementation `3274b39c85b817ef2a56215390bf19cc8aa0e5b4`,
  [Actions 38844757901](https://github.com/k1moradi/RDP-server/actions/runs/38844757901)
  completed full registered Debug and Release CTest on
  Ubuntu/GCC **205/205**, hosted macOS/Apple Clang **191/191** and
  Windows/MSVC **195/195** in EACH configuration. All three new R7
  `macos.display-snapshot-*` fixture-driven cases passed on all OSes.
  Documentation-policy, staged SDK consumer and package/artifact checks
  also PASS. **NOT RUN:** owner macOS 27 terminal, Windows MSYS2 CLANG64
  Clang23 and Linux/X11 exact-SHA one-root validation, real macOS
  CoreGraphics enumeration/ScreenCaptureKit authorization/desktop input,
  Microsoft RDP client acceptance, memory/latency benchmarks. M1/M5
  remain OPEN.
  **R7 native display enumeration (2026-10-15):** Added an allocation-free
  CoreGraphics active-display read-only snapshot (at most 16 displays),
  preserving global top-left logical-point bounds separately from backing
  physical-pixel dimensions. A paired synthetic read rejects changed
  displays mid-sample, unavailable displays, duplicate/overlapping IDs,
  mirrored outputs, malformed extents and oversize backing images; any
  app/session admission remains R2/R3-owned. Added three behavior-named
  portable CTests `macos.display-snapshot-stable-multi-retina`,
  `macos.display-snapshot-geometry-denials`,
  `macos.display-snapshot-changed-during-read` using the existing R7
  executable. **PASS:** Linux GCC14.2 isolated CTest 3/3, GCC14.2 -O2
  3/3 and Clang17 ASan/UBSan 3/3. **NOT RUN at authoring:** complete
  canonical full repository CTest, exact-SHA GitHub Actions, macOS27
  owner/Windows CLANG64 Clang23, live TCC/screens/keyboard/cursor/client
  and native latency benchmarks. **Next:** integrate approved per-user
  ScreenCaptureKit lifecycle and safely choose R4 physical-frame placement;
  do not infer a multi-monitor pixel origin from per-display Retina scale.
  **R7 corrected exact-commit hosted CI PASS:** Code
  `0b248c67f8c62ac31d2f94ff4c091bb527f10766`,
  [Actions 38800167816](https://github.com/k1moradi/RDP-server/actions/runs/38800167816):
  Ubuntu/GCC **184/184**, macOS/Apple Clang **173/173** and
  Windows/MSVC **180/180** full registered CTests EACH in Debug and
  Release. Nine Apple-only/portable R7 tests PASS on macOS, six portable
  tests PASS on Linux/Windows. SDK downstream consumer, ZIP/SHA256 and
  documentation-policy PASS. **NOT RUN:** owner's macOS27/CLANG64 Clang23
  exact-SHA validation, approved live desktop/TCC, authenticated RDP
  client and benchmark. M1/M5 remain open.
  **R6 exact-SHA hosted CI verification:** implementation commit
  `bd56f3a8ebcf4fa72d3419fb417d5a01f1678961`,
  [Actions 38797799194](https://github.com/k1moradi/RDP-server/actions/runs/38797799194):
  Linux Ubuntu Debug/Release CTest **170/170 PASS** each,
  Windows MSVC Debug/Release **168/168 PASS** each, macOS
  Debug/Release **158/158 PASS** each; documentation-policy,
  SDK install/consumer and packaging also PASS. **NOT RUN:**
  owner Windows MSYS2 CLANG64 Clang 23, owner Linux/X11/macOS 27,
  native live DXGI and Microsoft-client desktop acceptance.
  **R6 D3D11 exact-commit CI evidence:** Implementation SHA
  `ecce84689b2aa4801fc28348182d8e4183e6308e`,
  [GitHub Actions 38800686222](https://github.com/k1moradi/RDP-server/actions/runs/38800686222)
  overall **FAIL** on Ubuntu/GCC Debug Compile at
  `src/x11/x11_display_connection.cpp:222` (R5 X11
  `-Werror=extra`: conditional mixes enum/integer `XCB_WINDOW_NONE`);
  R5 issue #4 notified, no R5 source modified by R6. R6
  Windows/MSVC Debug and Release CTests **182/182 PASS** each,
  including both new D3D11 cases; macOS Debug and Release
  **178/178 PASS** each; documentation policy and Windows/macOS
  downstream SDK consumers PASS. Ubuntu CTest was not executed
  due to the unrelated build failure. Owner-local Windows
  MSYS2 CLANG64/Clang 23 and live M4 remain NOT RUN.
  **R6 capture-cycle exact-SHA hosted CI evidence:** Commit
  `fd08bd8b5ef07b3a5b8499b1f917eeadc57ca284`, [Actions 38844961028](https://github.com/k1moradi/RDP-server/actions/runs/38844961028)
  SUCCESS: Ubuntu Linux CTests 205/205 Debug and Release;
  Windows/MSVC 201/201 Debug and Release (both new R6 cases PASS);
  macOS 191/191 Debug and Release; documentation policy,
  installed SDK consumer tests and ZIP packaging PASS. Owner
  Windows MSYS2 CLANG64/Clang 23, Linux/X11, macOS 27, native
  authorized DXGI capture and Microsoft-client acceptance NOT RUN.
  **R6 capture-cycle ordered ownership (2026-10-16; parent
  `643d62ae3758ba17494767603141a98abc3dc7b6`):** The nonmoving Windows-only
  `windows_dxgi_capture_cycle.{h,cpp}` composes the existing
  `WindowsDxgiFrameOwner` and `WindowsD3D11StagingMap` without
  introducing a second R4 graphics scheduler or making an R2/R3
  authorization decision. It enforces one active mapped frame;
  releases staging map **before** `IDXGIOutputDuplication::ReleaseFrame`;
  releases an acquired frame on GPU-not-ready; rejects reentrant
  acquisition; and revokes the cycle on cancellation, disconnect,
  access loss or a changed validated monitor layout. Native callback
  cancellation is deferred until the callback exits, so a mapped
  view is never published after revocation. The view remains
  borrowed and cannot be queued asynchronously by R4.
  **Two dedicated Windows CTests in the existing R6 binary:**
  `windows.capture-frame-ordered-lifetime` and
  `windows.capture-frame-cancel-and-topology-rejections`.
  **PASS (offline sparse fixture):** GCC 14.2 and Clang 17 C++23
  `-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Werror`
  2/2 each, Clang ASan/UBSan 2/2, CMake staging CTest 2/2.
  **NOT RUN at authoring:** full canonical CMake/CTest (GitHub
  clone DNS unavailable locally), Windows MSYS2 CLANG64/Clang 23,
  real authorized Desktop Duplication, owner's three platforms,
  R4 graphics presentation and M4 Microsoft-client desktop acceptance.
  **Next:** consume an R2/R3 authorization-bound native capture
  lifecycle, then hand synchronous frame bytes to the sole R4 owner.
  **R6 active-session revocation exact-SHA hosted CI receipt (2026-10-15):**
  Implementation [`6369d8622057aa3f315af55011b52c1d74325d5b`](https://github.com/k1moradi/RDP-server/commit/6369d8622057aa3f315af55011b52c1d74325d5b),
  [Actions 38864378401](https://github.com/k1moradi/RDP-server/actions/runs/38864378401)
  finished overall **FAIL** because five later R10 Windows runtime
  TLS-credential CTests failed; no R6 test or build failure occurred.
  Linux/GCC full CTest **268/268 PASS** in Debug and Release; macOS/Clang
  **250/250 PASS** in Debug and Release. Windows/MSVC compiled and linked
  the native WTS adapter and both new R6 CTests
  `windows.capture-session-generation-active-lifetime` and
  `windows.capture-session-revocation-denials` **PASS**; full Windows
  Debug was **261/266 PASS**, with only R10 tests 241-245 failing.
  Windows Release was **NOT RUN** because Debug CTest returned nonzero.
  Documentation-policy and R9 security/protocol sanitizer jobs PASS.
  Owner MSYS2 CLANG64/Clang23, live R2/R3 admission, WTS lock/unlock,
  real DXGI capture, Microsoft client and performance remain NOT RUN.
  **R6 native active-session revocation guard (2026-10-15; authored
  against parent `43953fd5aa05b9bb913430825313caf41e2ebdd5`; exact-SHA CI pending):**
  Add Windows-only `WindowsCaptureSessionGenerationGuard`, which
  composes a caller-selected target WTS session with the EXISTING
  `WindowsCaptureGenerationReader`. The native read path uses
  `ProcessIdToSessionId(GetCurrentProcessId())` plus
  `WTSQuerySessionInformationW(..., WTSConnectState, ...)` and
  permits the epoch observation only while the process is in the exact
  target session and that target reports `WTSActive`. Any mismatch,
  inactive/disconnected state, query failure, zero epoch or reentrant
  observation terminally revokes the guard; a fresh R2/R3 binding is
  required. **This is revocation only:** the target session ID remains
  caller-supplied and matching WTS state is NOT authentication,
  authorization, an OS capability, or proof that the desktop is
  unlocked. No token acquisition, desktop switching, service mutation,
  capture, or input occurs.
  **Dedicated Windows-only CTests:** `windows.capture-session-generation-active-lifetime`
  and `windows.capture-session-revocation-denials`, reusing the
  existing R6 executable with fully synthetic session/epoch sources.
  Native WTS calls are compiled but never executed by ordinary CTest.
  **NOT RUN at authoring:** exact-SHA hosted matrix, owner MSYS2
  CLANG64/Clang23, Linux/X11/macOS27 owner checks, live WTS/session,
  lock/unlock notification, Desktop Duplication, Microsoft client and
  performance. **Next:** bind this revocation guard only after R2/R3
  issues real OS-authorized Windows session evidence; add explicit
  lock/unlock/session-change notification invalidation before live M4.
  **R6 target-session change revocation (2026-10-16; authored against
  parent `5510d09b31bb1aaa0697a9086edeb317e3c12b42`; exact-SHA CI PASS):** Extend the existing
  `WindowsCaptureSessionGenerationGuard` with a same-owner-thread
  `notifySessionChange(sessionId)` sink. Any valid notification for the
  selected target terminally revokes the guard; this conservatively covers
  lock/unlock, connect/disconnect and logon/logoff when the runtime routes
  those native WTS changes. Unrelated valid session IDs are ignored;
  zero/sentinel IDs fail closed, repeated target revocation is idempotent,
  and a target change delivered reentrantly during session observation
  prevents the old generation from being published. An already mapped
  guarded frame is then rejected by the existing generation check, which
  unmaps D3D11 staging before releasing the DXGI frame and publishes no
  caller-owned pixels. The guard still registers no window/service callback,
  switches no desktop, creates no token and grants no R2/R3 authorization.
  The future runtime/session owner must marshal native session changes onto
  the serialized R6 capture owner and cancel active capture promptly; a
  reconnect/unlock requires fresh independent authorization and a new guard.
  **Dedicated Windows-only CTests:** `windows.capture-session-change-revocation`
  and `windows.capture-session-change-denials`, in the existing R6
  executable/registry with synthetic callbacks only.
  **PASS (isolated portable seam):** Clang 17 C++23 strict-warning fixture
  and Clang 17 ASan/UBSan fixture.
  **Hosted exact-SHA PASS:** implementation
  `1efd3688872cc38e7c932efc661c793edfd4c4b7`,
  Actions 38865710309: Linux/GCC **273/273**, Windows/MSVC **273/273**
  and macOS/Clang **255/255** registered CTests passed in both Debug and
  Release; both new R6 cases passed on Windows; documentation policy,
  sanitizer, installed SDK consumer and package checks also passed.
  **NOT RUN at authoring:** full canonical
  repository CMake/CTest, native Windows SDK/MSVC, owner MSYS2 CLANG64
  Clang23/Linux X11/macOS27, live WTS notifications, R2/R3 admission,
  Desktop Duplication, Microsoft client and performance.
  **Next:** after genuine R2/R3 Windows authorization exists, route native
  service/window session-change events into this sink and bind authorized
  device/output duplication lifetime; then proceed to cursor/input in
  focused increments.
  **R6 Win32 cursor metadata snapshot (2026-10-16; authored against
  parent `10fff1ab437b74f7065bdd4c87dd9a5095f1f050`; exact-SHA CI PASS):**
  Add `windows_cursor_snapshot.{h,cpp}` to the existing noninstalled R6
  adapter. A synthetic/native callback reports cursor visibility, screen
  position, dimensions and hotspot; the shared validation path translates
  visible cursor position through the EXISTING validated monitor layout,
  rejects monitor gaps, zero/oversized dimensions and out-of-range hotspots,
  and preserves the prior snapshot on malformed/unavailable reads. Hidden
  or touch/pen-suppressed state is a successful snapshot that clears stale
  cursor metadata. The native observer uses read-only `GetCursorInfo`,
  `GetIconInfo` and `GetObjectW`; the two `HBITMAP` objects created by
  `GetIconInfo` are released through stack RAII on every path. Color cursor
  mask/color dimensions must match; monochrome mask height must be even and
  is halved per Win32 cursor semantics. Metadata is bounded to 256x256.
  No cursor pixel extraction, pointer cache, R4 scheduling, input injection,
  desktop switching or R2/R3 admission is added.
  **Dedicated Windows-only CTests:** `windows.cursor-snapshot-visible-and-hidden`
  and `windows.cursor-snapshot-rejections`, using synthetic callbacks while
  compiling the native Win32 path on Windows. **PASS (isolated portable
  seam):** GCC 14.2 and Clang 17 strict C++23, plus Clang 17 ASan/UBSan.
  **Hosted exact-SHA PASS:** implementation
  `0ee521f2802bb2f2fd3fd6fa1ebfb834f4d47287`,
  [Actions 38871393796](https://github.com/k1moradi/RDP-server/actions/runs/38871393796):
  Windows/MSVC **283/283** registered CTests passed in both Debug and Release,
  including both new cursor cases; Linux/GCC **281/281** and macOS/Clang
  **263/263** passed in both configurations. Documentation policy, R9
  ASan/UBSan protocol tests, bounded MCS/CLIPRDR fuzzer, installed SDK
  consumers and package/artifact checks also passed.
  **NOT RUN:** owner MSYS2 CLANG64 Clang23, live authorized cursor/session,
  Microsoft client and performance. **Next:** add bounded cursor shape-pixel extraction
  with explicit alpha/AND/XOR semantics and generation-safe R4 ownership;
  input injection remains separately gated on real R2/R3 authorization.
  **R6 capture session/device generation revocation (2026-10-15;
  authored against parent `ea1cf468986b15bcc4ee0b43b70082cfc0862e82`; exact-SHA CI pending):**
  The existing `WindowsDxgiCaptureCycle` accepts an OPTIONAL,
  revocation-only `WindowsCaptureGenerationReader` plus independently
  pinned nonzero native session/device epochs. A bound reader is
  sampled before DXGI acquisition, between acquisition and mapping,
  after mapping, before/after synchronous R4-owned pixel copy or
  consumer execution, and before/after reading native damage. Missing,
  partial, zero, stale or unavailable bound observations fail closed.
  Revocation unmaps the staging buffer and then releases the one
  existing DXGI frame; it never publishes pixels or damage from
  the replaced generation. Guarded cycles expose raw borrowed
  frames ONLY via checked synchronous consumption, not `frame()`.
  Legacy unbound cycles remain available for isolated offline fixtures;
  **these numbers are NOT R2/R3 authorization, a token, or permission
  to open a desktop**. Native R2/R3 authenticated admission and audited
  Windows-session evidence are required separately before real use.
  **Dedicated offline Windows CTests:**
  `windows.capture-generation-pinned-frame-lifetime` and
  `windows.capture-generation-revocation-denials`; reused the
  existing R6 executable and registry. **NOT RUN at authoring:**
  full canonical checkout CMake/CTest, owner Windows MSYS2 CLANG64
  Clang23/Linux X11/macOS27, real authenticated session, desktop
  capture and Microsoft client, or performance. Hosted exact-SHA CI
  to be checked after direct-main publication. **Next:** connect
  the revocation reader to audited R2/R3 native session/device
  lifecycle, then agree on generation-safe R4 graphics ownership.
  **R6 native DXGI move/dirty metadata read (2026-10-15,
  authored against latest main `3c09e0763d019d0423919f17d880375167bb7be7`; CI pending):** Extend the
  existing `WindowsDxgiCaptureCycle` to read
  `IDXGIOutputDuplication::GetFrameMoveRects/GetFrameDirtyRects` only
  while its existing frame lease and staging map remain held. The native
  byte lengths and combined 1,024-descriptor budget are checked before
  using existing move-before-dirty portable damage normalization.
  Missing callbacks, malformed metadata, short output capacity,
  access loss and cancellation fail closed and unmap staging BEFORE
  DXGI ReleaseFrame, without exposing partial rectangles. No second
  capture owner, protocol engine, R4 frame schedule, or R2/R3 admission.
  **New dedicated registered Windows CTests:**
  `windows.capture-dxgi-native-damage-map-lifetime` and
  `windows.capture-dxgi-native-damage-denials` in the existing test
  executable. **PASS (isolated headless fixture only):**
  GCC 14.2 and Clang 17 C++23 strict warnings ASan/UBSan 2/2,
  sparse R6 CTest 8/8. **NOT RUN at authoring:** full repository CTest,
  Windows SDK/MSVC exact-SHA CI, owner Windows CLANG64/Clang23,
  Linux/X11/macOS27, authorized live DXGI, real RDP client,
  M4 acceptance and performance. **Next:** R2/R3 independently
  authorized interactive Windows session/output and R4 frame lifecycle.
  **R6 caller-owned packed BGRA snapshot (2026-10-15; implementation
  against inspected main `b127398873a810d50957ad94537d56a4c0eb8b55`; hosted CI pending):** Existing
  `WindowsDxgiCaptureCycle::copyFrameTo` now accepts bounded caller
  storage and, via the existing synchronous consume callback, copies
  ONLY visible BGRA pixels into a packed buffer (no D3D11 padding).
  A `FramebufferView` over the caller's independent bytes is published
  only after successful D3D11 unmap and DXGI frame release. Undersized
  and source-overlapping buffers are rejected without publishing a view,
  while still releasing the one native lease. The destination is
  caller-owned; no new frame queue, scheduler or Windows framebuffer
  representation was added. **Dedicated registered CTests:**
  `windows.capture-packed-copy-lifetime` and
  `windows.capture-packed-copy-denials`.
  **PASS (headless sparse fixture, not full checkout):** GCC 14.2
  `-std=c++23 -O2 -Wall -Wextra -Wpedantic -Werror -UNDEBUG` 2/2;
  Clang 17 ASan/UBSan 2/2; reused sparse `~/rdp-server/build`
  CMake/CTest 6/6 including all previous focused fixture cases.
  **NOT RUN at authoring:** complete repository CTest, Windows MSYS2
  CLANG64 Clang23, owner Linux/X11/macOS27, live authenticated
  desktop, real RDP client and performance. Exact-commit CI must
  be checked after publication. **Next:** R2/R3 independently
  authorized Windows session generation, native device/duplication
  selection, and agreed R4 frame scheduling/pixel-copy contract.
  **R6 scoped capture-cycle frame consumption (2026-10-15; authored
  against remote main `d3a7137dcb8b4c0d2e4a036068dca04af4617de9`; integration CI pending):** Extend
  the EXISTING `WindowsDxgiCaptureCycle` with `consumeFrame`, a
  synchronous consumer callback that receives only the borrowed
  `FramebufferView` while staging is mapped. Reentrant capture/
  consumption/release is rejected; in-callback cancellation and topology
  revocation defer cleanup until the callback returns. Even rejection or
  missing consumer unmaps staging BEFORE releasing the existing DXGI
  lease. Device/access-loss release errors close the cycle. R4 must
  independently own pixels before any asynchronous encoding; real
  R2/R3 Windows session authorization is still missing.
  **Dedicated Windows CTests:**
  `windows.capture-capture-cycle-synchronous-consume-lifetime` and
  `windows.capture-capture-cycle-synchronous-consume-denials`.
  **PASS (focused synthetic CMake fixture only):** Clang 17 C++23
  ASan/UBSan **2/2** and strict-warning compilation; hosted CI and
  owner Windows CLANG64/Clang 23 **NOT RUN at authoring**.
  Full checkout local CTest, native desktop, real Microsoft client
  and performance **NOT RUN**. Next: R2/R3 native Windows admission,
  independently owned R4 frame snapshot/queue contract and
  device/duplication generation invalidation.
  **R6 D3D11 staging-copy/map RAII (2026-10-15; parent
  `19512d5fdbc0568fbd6c3333b32c770d76c6f8b4`):** `src/windows/windows_d3d11_staging_map.{h,cpp}`
  now consumes a borrowed `IDXGIResource` from the existing R6
  frame owner, validates BGRA8 2D geometry, creates a CPU-readable
  D3D11 staging texture, copies on the caller-supplied immediate
  context, and maps with `D3D11_MAP_FLAG_DO_NOT_WAIT`. The fixed
  native context owns mapping/unmapping and GPU COM resource release;
  the reusable nonmoving state owner exposes the existing
  `FramebufferView` only while its mapping is held. Nonready GPU
  responses remain retryable; invalid pitch, short mapping, device
  failure, cancellation during callbacks, duplicate/reentrant map
  and teardown fail closed with exactly-once cleanup. R4 must copy
  into owned frame memory before async handoff, and R3/R2 must
  independently authorize the native session before any real use.
  **New dedicated Windows CTests:** `windows.capture-d3d11-staging-bgra-map-lifetime`
  and `windows.capture-d3d11-staging-map-denials`, same existing R6
  executable and central registry. **PASS:** local sparse source
  Clang 17 and GCC 14.2 strict C++23 12/12 selectors each,
  Clang ASan/UBSan 12/12, local sparse staging CTest 12/12
  and new cases 2/2. **NOT RUN at authoring:** full canonical
  checkout CMake/CTest (GitHub Git DNS unavailable locally),
  Windows MSYS2 CLANG64/Clang 23, native SDK/hardware frame,
  owner Linux/X11/macOS 27, and Microsoft-client desktop
  acceptance. CI at resulting SHA must be evaluated. Next: bind
  a single R3-authorized native frame lifecycle to R4's one
  graphics owner without admitting desktop input.
  **R6 DXGI acquired-frame RAII (2026-10-15, authored on parent
  `853e572dafdeab18161afa3926db2f29d2ec3a34`):** `src/windows/windows_dxgi_frame_owner.{h,cpp}`
  owns one native `IDXGIOutputDuplication::AcquireNextFrame` lease,
  releases the COM `IDXGIResource` then calls `ReleaseFrame` exactly
  once on normal completion, cancellation or destruction. Timeout
  remains retryable, bounded to at most 100 ms per poll; access loss,
  release failure and inconsistent native callbacks close the owner
  until a newly authorized duplication/session is constructed. One
  borrowed resource is never reused after release. The native
  duplication pointer is caller-owned and must outlive the frame
  owner. Dedicated conditional CTests, in the existing R6 binary:
  `windows.capture-dxgi-frame-lease-lifecycle` and
  `windows.capture-dxgi-frame-lease-rejections`. **PASS:** Linux
  Clang 17 and GCC 14.2 strict C++23 10/10 R6 case selectors;
  Clang ASan/UBSan 10/10; sparse-only staging CTest 10/10
  (`ctest --test-dir build -C Debug --output-on-failure`).
  **NOT RUN:** complete project CMake/CTest from a synchronized
  checkout (GitHub DNS unavailable here), Windows native SDK
  MSYS2 CLANG64 Clang 23, owner's platform trio, real DXGI desktop,
  R2/R3 session admission and R4 asynchronous graphics consumption.
  Hosted CI result must be checked at the resulting commit SHA.
  **Next:** bind acquired frame resource to a session-authorized D3D11
  staging-map owner and validate row pitch/cleanup without live capture.
  **R6 WinGDI type-name correction (2026-10-15):** At published
  `467bf6bcf4624399e4e24667d214afd738b359d6`, Windows/MSVC
  Debug CI build FAIL at `windows_desktop_geometry.cpp:33`: WinGDI's
  function named `Rectangle` hid the portable C++ type after inclusion
  of `windows.h`. R6 now binds the core `struct ::Rectangle` through
  `PortableRectangle` in its Windows namespace and adds
  `windows.geometry-gdi-rectangle-name-resolution` to the existing
  Windows-only CTest executable. **PASS:** Clang 17 and GCC 14.2 C++23
  strict warnings 8/8 direct cases, Clang ASan/UBSan 8/8; synthetic
  WinGDI-function-first header inclusion 1/1. **NOT RUN:** native
  Windows/MSYS2 CLANG64 Clang 23, owner workstation CTest and human
  desktop; GitHub Actions for the correction pending at publication.
  Next: validated DXGI acquire/release after R2/R3 and R4 contract.
  **R6 direct-main integration (2026-10-15; parent `455b8b631957d2f3f9631393f2a3833e19c2c07a`):**
  7/7 fixture selectors PASS under Clang 17 and GCC 14.2 C++23
  warnings-as-errors; Clang ASan/UBSan 7/7 PASS; sparse CTest
  7/7 PASS. Full repository/Windows CLANG64 CTests remain NOT RUN.
  Native session admission and real desktop acceptance NOT RUN.
  **R6 Windows monitor geometry increment (2026-10-15; integrated on main; native validation pending):**
  `src/windows/windows_desktop_geometry.{h,cpp}` provides read-only
  `EnumDisplayMonitors`/`GetMonitorInfoW` sampling into owned, bounded
  portable `Rectangle` layouts plus signed-native/unsigned-desktop
  coordinate translation that rejects monitor gaps. Canonical ordering
  makes equivalent monitor enumerations equal for resize detection. The adapter
  remains separate from the protocol archive and cannot grant OS/RDP
  admission. New conditional CTests:
  `windows.geometry-negative-origin-and-monitor-gaps` and
  `windows.geometry-invalid-layout-rejections`, and
  `windows.geometry-order-stable-reconfiguration` (fixture-only).
  **PASS (sparse staging, 2026-10-15):** Linux Clang 17/GCC 14.2
  C++23 `-Wall -Wextra -Wpedantic -Werror` each compiled/executed all
  three fixture behaviors; Clang ASan+UBSan also PASS 3/3 under the
  sole `~/rdp-server/build/` directory. A sparse staging-only
  CTest registry PASS 3/3; synthetic Win32 callback stub also PASS.
  **NOT RUN:** actual Windows/MSYS2 CLANG64 Clang 23 compile,
  dedicated Windows CTest registration, full project CTest, Windows
  capture/input/identity integration, and human desktop acceptance.
  **NOT RUN:** full repository CTest and native Win32 SDK compilation;
  sparse fixture success does not establish M1/M4 acceptance.
  **R6 DXGI BGRA mapped-view validation (2026-10-15; integrated on main; native validation pending):**
  `src/windows/windows_bgra_frame.{h,cpp}` extends the same Windows-only
  adapter target with a borrowing, zero-copy conversion of a validated
  top-down BGRA8 mapped frame into existing `FramebufferView`. The helper
  requires four bytes per pixel, sufficient mapped row pitch and complete
  backing storage, and caps one frame at 512 MiB. It preserves the previous
  output on failure and does not acquire a live DXGI image. Added dedicated
  Windows CTests `windows.geometry-capture-bgra-stride-and-pixel-order` and
  `windows.geometry-capture-bgra-invalid-frame-denials`, reusing the same
  existing R6 fixture executable and single CTest registry.
  **PASS (sparse staging, 2026-10-15):** focused source/test compilation
  and all **5/5** fixtures with Clang 17 and GCC 14.2 C++23, strict
  warnings-as-errors; Clang ASan+UBSan **5/5**. Sparse staging-only
  `ctest --test-dir build -C Debug --output-on-failure` **5/5 PASS**;
  its new-case `-R '^windows\.geometry-capture-'` **2/2 PASS**.
  **NOT RUN:** native
  Windows toolchain, real desktop capture, full repository CTest and
  R2/R3/R4 authorized end-to-end integration. No Windows user session,
  input or graphics is activated by the helper.
  **R6 DXGI damage metadata normalization (2026-10-15; integrated on main;
  native validation pending):** `src/windows/windows_dxgi_damage.{h,cpp}` emits bounded
  portable `Rectangle` spans from per-output Desktop Duplication move and
  dirty descriptors, in normative move-destination-before-dirty order.
  Validates non-stretched move source and destination bounds, exclusive
  edges, nonempty pixels, 1024-rectangle cap, 32-bit geometry and output
  capacity before committing; malformed late metadata leaves the prior
  output/count intact. Empty pointer-only frames emit zero rectangles.
  The helper neither accumulates damage nor owns an R4 graphics lifecycle.
  **Dedicated CTests:** `windows.capture-dxgi-move-before-dirty` and
  `windows.capture-dxgi-metadata-rejections` (Windows registration, same
  R6 fixture executable). **PASS (sparse offline fixture, Linux):** Clang
  17, GCC 14.2 and Clang ASan/UBSan compiled and executed **7/7** R6
  selectors; sparse local `ctest --test-dir build -C Debug
  --output-on-failure` **7/7 PASS** and focused
  `ctest --test-dir build -C Debug -R '^windows\.capture-dxgi-'
  --output-on-failure` **2/2 PASS**. Full canonical checkout/CTest,
  Windows Clang 23, native SDK and real capture NOT RUN.
  **NOT RUN:** native Windows toolchain and full repository CTest;
  no desktop or injected input was used. Next: native
  DXGI frame acquisition/release/cancellation with R2/R3-approved session
  and R4 borrowed/owned frame lifetime contract, tested offline first.
  **R6 exact-SHA hosted CI verification:** implementation commit
  `bd56f3a8ebcf4fa72d3419fb417d5a01f1678961`,
  [Actions 38797799194](https://github.com/k1moradi/RDP-server/actions/runs/38797799194):
  Linux Ubuntu Debug/Release CTest **170/170 PASS** each,
  Windows MSVC Debug/Release **168/168 PASS** each, macOS
  Debug/Release **158/158 PASS** each; documentation-policy,
  SDK install/consumer and packaging also PASS. **NOT RUN:**
  owner Windows MSYS2 CLANG64 Clang 23, owner Linux/X11/macOS 27,
  native live DXGI and Microsoft-client desktop acceptance.
  **R6 DXGI acquired-frame RAII (2026-10-15, authored on parent
  `853e572dafdeab18161afa3926db2f29d2ec3a34`):** `src/windows/windows_dxgi_frame_owner.{h,cpp}`
  owns one native `IDXGIOutputDuplication::AcquireNextFrame` lease,
  releases the COM `IDXGIResource` then calls `ReleaseFrame` exactly
  once on normal completion, cancellation or destruction. Timeout
  remains retryable, bounded to at most 100 ms per poll; access loss,
  release failure and inconsistent native callbacks close the owner
  until a newly authorized duplication/session is constructed. One
  borrowed resource is never reused after release. The native
  duplication pointer is caller-owned and must outlive the frame
  owner. Dedicated conditional CTests, in the existing R6 binary:
  `windows.capture-dxgi-frame-lease-lifecycle` and
  `windows.capture-dxgi-frame-lease-rejections`. **PASS:** Linux
  Clang 17 and GCC 14.2 strict C++23 10/10 R6 case selectors;
  Clang ASan/UBSan 10/10; sparse-only staging CTest 10/10
  (`ctest --test-dir build -C Debug --output-on-failure`).
  **NOT RUN:** complete project CMake/CTest from a synchronized
  checkout (GitHub DNS unavailable here), Windows native SDK
  MSYS2 CLANG64 Clang 23, owner's platform trio, real DXGI desktop,
  R2/R3 session admission and R4 asynchronous graphics consumption.
  Hosted CI result must be checked at the resulting commit SHA.
  **Next:** bind acquired frame resource to a session-authorized D3D11
  staging-map owner and validate row pitch/cleanup without live capture.
  **R6 WinGDI type-name correction (2026-10-15):** At published
  `467bf6bcf4624399e4e24667d214afd738b359d6`, Windows/MSVC
  Debug CI build FAIL at `windows_desktop_geometry.cpp:33`: WinGDI's
  function named `Rectangle` hid the portable C++ type after inclusion
  of `windows.h`. R6 now binds the core `struct ::Rectangle` through
  `PortableRectangle` in its Windows namespace and adds
  `windows.geometry-gdi-rectangle-name-resolution` to the existing
  Windows-only CTest executable. **PASS:** Clang 17 and GCC 14.2 C++23
  strict warnings 8/8 direct cases, Clang ASan/UBSan 8/8; synthetic
  WinGDI-function-first header inclusion 1/1. **NOT RUN:** native
  Windows/MSYS2 CLANG64 Clang 23, owner workstation CTest and human
  desktop; GitHub Actions for the correction pending at publication.
  Next: validated DXGI acquire/release after R2/R3 and R4 contract.
  **R6 direct-main integration (2026-10-15; parent `455b8b631957d2f3f9631393f2a3833e19c2c07a`):**
  7/7 fixture selectors PASS under Clang 17 and GCC 14.2 C++23
  warnings-as-errors; Clang ASan/UBSan 7/7 PASS; sparse CTest
  7/7 PASS. Full repository/Windows CLANG64 CTests remain NOT RUN.
  Native session admission and real desktop acceptance NOT RUN.
  **R6 Windows monitor geometry increment (2026-10-15; integrated on main; native validation pending):**
  `src/windows/windows_desktop_geometry.{h,cpp}` provides read-only
  `EnumDisplayMonitors`/`GetMonitorInfoW` sampling into owned, bounded
  portable `Rectangle` layouts plus signed-native/unsigned-desktop
  coordinate translation that rejects monitor gaps. Canonical ordering
  makes equivalent monitor enumerations equal for resize detection. The adapter
  remains separate from the protocol archive and cannot grant OS/RDP
  admission. New conditional CTests:
  `windows.geometry-negative-origin-and-monitor-gaps` and
  `windows.geometry-invalid-layout-rejections`, and
  `windows.geometry-order-stable-reconfiguration` (fixture-only).
  **PASS (sparse staging, 2026-10-15):** Linux Clang 17/GCC 14.2
  C++23 `-Wall -Wextra -Wpedantic -Werror` each compiled/executed all
  three fixture behaviors; Clang ASan+UBSan also PASS 3/3 under the
  sole `~/rdp-server/build/` directory. A sparse staging-only
  CTest registry PASS 3/3; synthetic Win32 callback stub also PASS.
  **NOT RUN:** actual Windows/MSYS2 CLANG64 Clang 23 compile,
  dedicated Windows CTest registration, full project CTest, Windows
  capture/input/identity integration, and human desktop acceptance.
  **NOT RUN:** full repository CTest and native Win32 SDK compilation;
  sparse fixture success does not establish M1/M4 acceptance.
  **R6 DXGI BGRA mapped-view validation (2026-10-15; integrated on main; native validation pending):**
  `src/windows/windows_bgra_frame.{h,cpp}` extends the same Windows-only
  adapter target with a borrowing, zero-copy conversion of a validated
  top-down BGRA8 mapped frame into existing `FramebufferView`. The helper
  requires four bytes per pixel, sufficient mapped row pitch and complete
  backing storage, and caps one frame at 512 MiB. It preserves the previous
  output on failure and does not acquire a live DXGI image. Added dedicated
  Windows CTests `windows.geometry-capture-bgra-stride-and-pixel-order` and
  `windows.geometry-capture-bgra-invalid-frame-denials`, reusing the same
  existing R6 fixture executable and single CTest registry.
  **PASS (sparse staging, 2026-10-15):** focused source/test compilation
  and all **5/5** fixtures with Clang 17 and GCC 14.2 C++23, strict
  warnings-as-errors; Clang ASan+UBSan **5/5**. Sparse staging-only
  `ctest --test-dir build -C Debug --output-on-failure` **5/5 PASS**;
  its new-case `-R '^windows\.geometry-capture-'` **2/2 PASS**.
  **NOT RUN:** native
  Windows toolchain, real desktop capture, full repository CTest and
  R2/R3/R4 authorized end-to-end integration. No Windows user session,
  input or graphics is activated by the helper.
  **R6 DXGI damage metadata normalization (2026-10-15; integrated on main;
  native validation pending):** `src/windows/windows_dxgi_damage.{h,cpp}` emits bounded
  portable `Rectangle` spans from per-output Desktop Duplication move and
  dirty descriptors, in normative move-destination-before-dirty order.
  Validates non-stretched move source and destination bounds, exclusive
  edges, nonempty pixels, 1024-rectangle cap, 32-bit geometry and output
  capacity before committing; malformed late metadata leaves the prior
  output/count intact. Empty pointer-only frames emit zero rectangles.
  The helper neither accumulates damage nor owns an R4 graphics lifecycle.
  **Dedicated CTests:** `windows.capture-dxgi-move-before-dirty` and
  `windows.capture-dxgi-metadata-rejections` (Windows registration, same
  R6 fixture executable). **PASS (sparse offline fixture, Linux):** Clang
  17, GCC 14.2 and Clang ASan/UBSan compiled and executed **7/7** R6
  selectors; sparse local `ctest --test-dir build -C Debug
  --output-on-failure` **7/7 PASS** and focused
  `ctest --test-dir build -C Debug -R '^windows\.capture-dxgi-'
  --output-on-failure` **2/2 PASS**. Full canonical checkout/CTest,
  Windows Clang 23, native SDK and real capture NOT RUN.
  **NOT RUN:** native Windows toolchain and full repository CTest;
  no desktop or injected input was used. Next: native
  DXGI frame acquisition/release/cancellation with R2/R3-approved session
  and R4 borrowed/owned frame lifetime contract, tested offline first.
  **R6 exact-SHA hosted CI verification:** implementation commit
  `bd56f3a8ebcf4fa72d3419fb417d5a01f1678961`,
  [Actions 38797799194](https://github.com/k1moradi/RDP-server/actions/runs/38797799194):
  Linux Ubuntu Debug/Release CTest **170/170 PASS** each,
  Windows MSVC Debug/Release **168/168 PASS** each, macOS
  Debug/Release **158/158 PASS** each; documentation-policy,
  SDK install/consumer and packaging also PASS. **NOT RUN:**
  owner Windows MSYS2 CLANG64 Clang 23, owner Linux/X11/macOS 27,
  native live DXGI and Microsoft-client desktop acceptance.
  **R6 DXGI acquired-frame RAII (2026-10-15, authored on parent
  `853e572dafdeab18161afa3926db2f29d2ec3a34`):** `src/windows/windows_dxgi_frame_owner.{h,cpp}`
  owns one native `IDXGIOutputDuplication::AcquireNextFrame` lease,
  releases the COM `IDXGIResource` then calls `ReleaseFrame` exactly
  once on normal completion, cancellation or destruction. Timeout
  remains retryable, bounded to at most 100 ms per poll; access loss,
  release failure and inconsistent native callbacks close the owner
  until a newly authorized duplication/session is constructed. One
  borrowed resource is never reused after release. The native
  duplication pointer is caller-owned and must outlive the frame
  owner. Dedicated conditional CTests, in the existing R6 binary:
  `windows.capture-dxgi-frame-lease-lifecycle` and
  `windows.capture-dxgi-frame-lease-rejections`. **PASS:** Linux
  Clang 17 and GCC 14.2 strict C++23 10/10 R6 case selectors;
  Clang ASan/UBSan 10/10; sparse-only staging CTest 10/10
  (`ctest --test-dir build -C Debug --output-on-failure`).
  **NOT RUN:** complete project CMake/CTest from a synchronized
  checkout (GitHub DNS unavailable here), Windows native SDK
  MSYS2 CLANG64 Clang 23, owner's platform trio, real DXGI desktop,
  R2/R3 session admission and R4 asynchronous graphics consumption.
  Hosted CI result must be checked at the resulting commit SHA.
  **Next:** bind acquired frame resource to a session-authorized D3D11
  staging-map owner and validate row pitch/cleanup without live capture.
  **R6 WinGDI type-name correction (2026-10-15):** At published
  `467bf6bcf4624399e4e24667d214afd738b359d6`, Windows/MSVC
  Debug CI build FAIL at `windows_desktop_geometry.cpp:33`: WinGDI's
  function named `Rectangle` hid the portable C++ type after inclusion
  of `windows.h`. R6 now binds the core `struct ::Rectangle` through
  `PortableRectangle` in its Windows namespace and adds
  `windows.geometry-gdi-rectangle-name-resolution` to the existing
  Windows-only CTest executable. **PASS:** Clang 17 and GCC 14.2 C++23
  strict warnings 8/8 direct cases, Clang ASan/UBSan 8/8; synthetic
  WinGDI-function-first header inclusion 1/1. **NOT RUN:** native
  Windows/MSYS2 CLANG64 Clang 23, owner workstation CTest and human
  desktop; GitHub Actions for the correction pending at publication.
  Next: validated DXGI acquire/release after R2/R3 and R4 contract.
  **R6 direct-main integration (2026-10-15; parent `455b8b631957d2f3f9631393f2a3833e19c2c07a`):**
  7/7 fixture selectors PASS under Clang 17 and GCC 14.2 C++23
  warnings-as-errors; Clang ASan/UBSan 7/7 PASS; sparse CTest
  7/7 PASS. Full repository/Windows CLANG64 CTests remain NOT RUN.
  Native session admission and real desktop acceptance NOT RUN.
  **R6 Windows monitor geometry increment (2026-10-15; integrated on main; native validation pending):**
  `src/windows/windows_desktop_geometry.{h,cpp}` provides read-only
  `EnumDisplayMonitors`/`GetMonitorInfoW` sampling into owned, bounded
  portable `Rectangle` layouts plus signed-native/unsigned-desktop
  coordinate translation that rejects monitor gaps. Canonical ordering
  makes equivalent monitor enumerations equal for resize detection. The adapter
  remains separate from the protocol archive and cannot grant OS/RDP
  admission. New conditional CTests:
  `windows.geometry-negative-origin-and-monitor-gaps` and
  `windows.geometry-invalid-layout-rejections`, and
  `windows.geometry-order-stable-reconfiguration` (fixture-only).
  **PASS (sparse staging, 2026-10-15):** Linux Clang 17/GCC 14.2
  C++23 `-Wall -Wextra -Wpedantic -Werror` each compiled/executed all
  three fixture behaviors; Clang ASan+UBSan also PASS 3/3 under the
  sole `~/rdp-server/build/` directory. A sparse staging-only
  CTest registry PASS 3/3; synthetic Win32 callback stub also PASS.
  **NOT RUN:** actual Windows/MSYS2 CLANG64 Clang 23 compile,
  dedicated Windows CTest registration, full project CTest, Windows
  capture/input/identity integration, and human desktop acceptance.
  **NOT RUN:** full repository CTest and native Win32 SDK compilation;
  sparse fixture success does not establish M1/M4 acceptance.
  **R6 DXGI BGRA mapped-view validation (2026-10-15; integrated on main; native validation pending):**
  `src/windows/windows_bgra_frame.{h,cpp}` extends the same Windows-only
  adapter target with a borrowing, zero-copy conversion of a validated
  top-down BGRA8 mapped frame into existing `FramebufferView`. The helper
  requires four bytes per pixel, sufficient mapped row pitch and complete
  backing storage, and caps one frame at 512 MiB. It preserves the previous
  output on failure and does not acquire a live DXGI image. Added dedicated
  Windows CTests `windows.geometry-capture-bgra-stride-and-pixel-order` and
  `windows.geometry-capture-bgra-invalid-frame-denials`, reusing the same
  existing R6 fixture executable and single CTest registry.
  **PASS (sparse staging, 2026-10-15):** focused source/test compilation
  and all **5/5** fixtures with Clang 17 and GCC 14.2 C++23, strict
  warnings-as-errors; Clang ASan+UBSan **5/5**. Sparse staging-only
  `ctest --test-dir build -C Debug --output-on-failure` **5/5 PASS**;
  its new-case `-R '^windows\.geometry-capture-'` **2/2 PASS**.
  **NOT RUN:** native
  Windows toolchain, real desktop capture, full repository CTest and
  R2/R3/R4 authorized end-to-end integration. No Windows user session,
  input or graphics is activated by the helper.
  **R6 DXGI damage metadata normalization (2026-10-15; integrated on main;
  native validation pending):** `src/windows/windows_dxgi_damage.{h,cpp}` emits bounded
  portable `Rectangle` spans from per-output Desktop Duplication move and
  dirty descriptors, in normative move-destination-before-dirty order.
  Validates non-stretched move source and destination bounds, exclusive
  edges, nonempty pixels, 1024-rectangle cap, 32-bit geometry and output
  capacity before committing; malformed late metadata leaves the prior
  output/count intact. Empty pointer-only frames emit zero rectangles.
  The helper neither accumulates damage nor owns an R4 graphics lifecycle.
  **Dedicated CTests:** `windows.capture-dxgi-move-before-dirty` and
  `windows.capture-dxgi-metadata-rejections` (Windows registration, same
  R6 fixture executable). **PASS (sparse offline fixture, Linux):** Clang
  17, GCC 14.2 and Clang ASan/UBSan compiled and executed **7/7** R6
  selectors; sparse local `ctest --test-dir build -C Debug
  --output-on-failure` **7/7 PASS** and focused
  `ctest --test-dir build -C Debug -R '^windows\.capture-dxgi-'
  --output-on-failure` **2/2 PASS**. Full canonical checkout/CTest,
  Windows Clang 23, native SDK and real capture NOT RUN.
  **NOT RUN:** native Windows toolchain and full repository CTest;
  no desktop or injected input was used. Next: native
  DXGI frame acquisition/release/cancellation with R2/R3-approved session
  and R4 borrowed/owned frame lifetime contract, tested offline first.
- [ ] Measure native server CPU/RAM, bandwidth, graphics and clipboard
  p50/p95/p99; only then claim performance improvements.
- [ ] **H.264-only interactive desktop baseline first.** Under the existing
  [benchmark standards](benchmark.md), exercise terminal typing/scrolling,
  code editing with syntax highlighting, text-heavy browser scrolling,
  file-manager navigation, menus/dialogs, and mixed text/images/video.
  These are **text-dominant graphical desktop workloads**, not a terminal-only
  protocol or an assumption that pixels have a known content type. Record
  p50/p95/p99 input-to-visible-update latency where measurable; distinguish
  RDPGFX frame ACK from actual presentation. Also record capture/encode/queue
  timings, CPU on older scalar/dual-core hardware, client decode cost,
  network bytes, RSS/allocations, text fidelity and frame drops at fixed
  resolution, load and network conditions. **Tune x264, not competing H.264
  libraries:** start with `superfast` and `zerolatency`, no B-frames/lookahead,
  persistent NV12 input and bounded in-flight work. Compare x264's
  `ultrafast`/`superfast`/`veryfast`, single-frame-thread versus low-latency
  slice threading, and `X264_MBINFO_CONSTANT` unchanged-16x16-macroblock hints
  enabled/disabled. Only set hints verified against the encoder's reference
  history; test frame skips, refresh, resize and reconnect. Compare matched
  visual quality on LAN and bandwidth-limited WAN, prioritizing end-to-end
  latency over encode-only throughput. **Exclude OpenH264 benchmarking and
  generic alternative-encoder evaluations** from this roadmap.
  **Status: NOT RUN.**
- [ ] **Only after H.264 usability is verified, evaluate ClearCodec** as an
  optional optimization, not a prerequisite. Research and test existing
  [IronRDP ClearCodecEncoder](https://docs.rs/ironrdp-graphics/0.9.0/ironrdp_graphics/clearcodec/struct.ClearCodecEncoder.html)
  (Rust, MIT OR Apache-2.0; implemented residual/RLE and small glyph cache,
  but **not** full bands/V-Bar encoding), and the
  [FreeRDP ClearCodec code](https://github.com/FreeRDP/FreeRDP/blob/master/libfreerdp/codec/clear.c)
  (decoder/reference; `clear_compress()` is unimplemented as of this review).
  First benchmark the candidate offline against the **same dirty rectangles**
  and H.264 settings; assess missing encoder features, output validity,
  client interoperability and licensing before choosing a reusable reference
  or writing a native C++23 encoder. Avoid a Rust runtime dependency in the
  production protocol library. A residual-only prototype does **not** measure
  the full ClearCodec V-Bar cache benefit. **Status: RESEARCH ONLY;
  encode/decode benchmarks and real-client tests NOT RUN.**
- [ ] **ClearCodec go/no-go after measured comparison.** If an interoperable
  implementation provides repeatable improvements in text-dominant GUI
  p95/p99 latency, total CPU/bandwidth or exact text fidelity **without
  unacceptable regressions** in mixed content, memory, security or frame
  correctness, consider an opt-in ClearCodec path and mixed-codec RDPGFX
  synchronization with H.264. Otherwise retain H.264-only graphics and do
  not add a codec for speculative benefit. Preserve the first-party C++23
  architecture and collect reproducible real-Microsoft-client evidence.
  **Status: NOT RUN; decision deferred.**

### P0 — Standards and repeatable automation

**Deployment hardening gate (NOT RUN):** after an authorized human
desktop trial, record supported sanitizer/fuzzer coverage, concurrent
connections, long-session/leak/race/timeout testing, real-client
latency/CPU/RAM/bandwidth, private-network binding, certificate/account
configuration, service packaging, upgrade and rollback evidence.
Protocol SDK ZIPs are developer packages, not server deployment.

- [x] The canonical agent policy, four mandatory domain standards,
  behavior-named CTest suites, documentation co-change checker and
  local-home-checkout/single-build-root CMake guards passed
  [Actions run 38535723210](https://github.com/k1moradi/RDP-server/actions/runs/38535723210)
  at `e1843b07c8772588f29e45a9b8e328e51c59e2ff`.
  Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy
  jobs all succeeded. This proves the **CI's isolated checkout
  exception** and offline protocol/policy gates only; the owner's
  persistent `~/rdp-server/build/` and real clients were NOT RUN.
- [x] Automate Debug/Release C++23 builds and full offline CTest,
  staged SDK installation, downstream package consumer verification,
  per-OS ZIP archives and SHA-256 manifests. **PASS:** commit
  `1aa025960288d40f476e85c5a9c5f97b06bebf20`,
  [Actions run 38543429777](https://github.com/k1moradi/RDP-server/actions/runs/38543429777):
  Linux/GCC, macOS/Clang, Windows/MSVC and documentation-policy;
  **three uploaded protocol SDK packages verified**.
- [ ] Exercise automatic tagged GitHub **prerelease publication**
  (`protocol-vX.Y.Z` corresponding to CMake project version, from `main`).
  Release job is configured and gated on successful matrix/maintenance
  checks, but was **SKIPPED / NOT RUN** because no release tag was
  created. Publishing an SDK is **not** installation, activation or
  authenticated end-to-end deployment of an RDP server.
- [x] Consolidate all seven non-entrypoint root Markdown documents
  under `docs/` while retaining `README.md`, `AGENTS.md`,
  `CLAUDE.md`, `CODEX.md`, `agent.md`, `LICENSE` and `NOTICE`
  at repository root. Rebase 47 links, fix attribution package
  install path and enforce the layout using the canonical policy CTest.
  **Initial FAIL:** [run 38544805819](https://github.com/k1moradi/RDP-server/actions/runs/38544805819)
  at `e3e6a7576f530280a1095f8e15f058d7da07f52d` uncovered
  missing CMP0057 in standalone `cmake -P` policy script (10 native
  protocol tests still passed on Ubuntu).
  **PASS:** corrected `list(FIND)` at
  `f68d1d417424823eed7856761ff95f0ebe1eabb2` in
  [Actions run 38544988535](https://github.com/k1moradi/RDP-server/actions/runs/38544988535):
  Ubuntu/GCC, macOS/Clang, Windows/MSVC and documentation-policy
  passed full Debug/Release CTests, SDK installation, downstream
  consumer and package upload.
  **NOT RUN:** owner-local builds, real clients and service deployment.
- [ ] Expand reusable sanitizer, parser-fuzz, security-negative and real
  client acceptance suites as native runtime code becomes available.
  **Verified CTest reporting increment at `1e11327f2b74ff7e676fbb3bb7200491718a779f`:** Register the existing
  preauth test executable as ten independent behavior-named CTests
  (initial state, request fragmentation/outcomes, reply ordering,
  real TLS handshake, malformed X.224, decrypted MCS fragmentation
  and rejection, encrypted TLS record fragmentation and rejection).
  Keep one shared binary and all preexisting assertions. This changes
  the displayed CTest total from **11 to 20**; it does not mean nine
  newly invented protocol features or that the server can accept users.
  **PASS:** [Actions run 38559221423](https://github.com/k1moradi/RDP-server/actions/runs/38559221423):
  Ubuntu/GCC, macOS/Clang, Windows/MSVC and documentation-policy
  succeeded, including Debug/Release full CTests, installed
  downstream consumer, ZIP and SHA-256 artifacts. Ubuntu logs
  explicitly confirmed **20/20 passed** in each configuration.
  **NOT RUN:** owner's local CTest after this change, external RDP
  client, authenticated session or desktop. Next development boundary:
  actual nonblocking TLS socket adapter and CredSSP/NLA admission.


  **R9 bounded CLIPRDR wire-codec mutation gate (2026-10-15; new):**
  Register default-on `clipboard.wire-codec-mutated-boundaries` in the
  one existing test registry, dispatched by `test_clipboard_protocol`.
  The native C++23 codec is exercised for ten payload lengths (including
  zero, 1, 1600 and 4096 bytes), four opaque type/flag combinations,
  every strict prefix and trailing byte, and each one-bit mutation of
  a 39-byte complete PDU (312 cases). Verify precise advertised length,
  read-only decoding and payload span pointing into the caller buffer.
  Unknown type/flag bits remain structurally valid in the low-level
  codec; policy rejection belongs in the higher CLIPRDR state machine.
  **Parent main:** `8a4f466c3bab9af155da623a54dba91b7cb7529d`.
  **PASS (isolated production-wire excerpt only):** GCC 14.2 strict
  C++23 Debug and Release; Clang 17 ASan/UBSan with leak detection.
  Mutant with disabled declared-length check aborts at the trailing
  byte assertion (expected negative). **NOT RUN:** full repository CMake
  and CTest (GitHub transport DNS unavailable to local shell), new
  exact-commit CI, owner Linux/X11, Windows CLANG64 Clang23, macOS27
  and Microsoft-client authorization/desktop. **Next:** verify hosted
  exact-SHA CTests and repeat owner's three-platform same-SHA command.

  **R9 exact-commit CLIPRDR codec CI receipt (2026-10-15):**
  Source commit `ab78ed83f59b64463123382da34b8b13b832c0e1`,
  [Actions run 38857546859](https://github.com/k1moradi/RDP-server/actions/runs/38857546859):
  dedicated `clipboard.wire-codec-mutated-boundaries` **PASS** hosted
  Linux/GCC, macOS/AppleClang and Windows/MSVC Debug, plus Ubuntu
  Clang 18 ASan/UBSan. Ubuntu Debug/Release full CTest **251/251
  PASS** each; R9 sanitizer job **17/17 clipboard + 10/10 MCS/
  CredSSP PASS**; documentation-policy **PASS**.
  **OVERALL RUN FAIL (unrelated cross-road gates):** macOS
  **218/233 Debug**, with 15 TCP accept/listener tests aborting
  after unsuccessful acceptance (first at
  `test_owned_preauth_session.cpp:1564`); Windows
  **247/248 Debug**, failing only
  `runtime.validates-tls-files-private-regular`
  at `tests/check_runtime_entrypoint.cmake:317` with
  unexpected process exit 3. R1 subsequently published listener
  guard correction `c78a745aaa5180007a00a35a2858072974c2ad17`,
  but its exact-SHA rerun is a separate gate; Windows R10
  fixture likewise remains unverified at the R9 source SHA.
  macOS/Windows Release, owner Linux/X11, MSYS2 CLANG64/Clang23,
  macOS27 and real clients remain **NOT RUN**.
  **Next:** obtain full green cross-road Debug/Release and
  owner-same-SHA platform receipts before milestone acceptance.

  **R9 CLIPRDR Format Data Response fail-closed regression (2026-10-15):**
  A new distinct default-enabled `clipboard.remote-transfer-framing-rejections`
  CTest invokes the production `RemoteTransfer::receiveResponse` and CLIPRDR
  wire decoder in the existing test executable. It rejects all truncated
  response prefixes, malformed/hostile lengths, wrong types/flags, and
  duplicate unsolicited replies; verifies poisoned state, no stale payload
  exposure and fresh data only after an actual disconnect/reset. The
  original `clipboard.remote-transfer` test remains unchanged.
  **Implementation parent main:** `469f49e5d4621017016a06095a17ca7cbfc10182`.
  **PASS (isolated only):** GCC 14.2 Debug and Release and Clang 17
  ASan/UBSan with leak detection using byte-identical production
  `RemoteTransfer` and first-party wire decoder excerpts.
  Deliberately breaking the length check causes expected failure.
  **NOT RUN:** full project build/official CTest (repository Git DNS
  unavailable locally), exact-commit GitHub CI, owner's Linux/X11,
  Windows CLANG64/Clang23 and macOS27 tests or Microsoft RDP client.
  **Next:** exact-SHA CI, canonical one-root owner CTest, then separate
  CLIPRDR fragmentation and R3→R8 authorization regression.

  **Exact implementation CI PASS:** `455b8b631957d2f3f9631393f2a3833e19c2c07a`,
  [Actions 38794861230](https://github.com/k1moradi/RDP-server/actions/runs/38794861230).
  Linux/GCC **125/125**, macOS/Clang and Windows/MSVC **115/115**
  full CTests in **each Debug and Release**. New
  `clipboard.remote-transfer-framing-rejections` and previous
  `clipboard.remote-transfer` both PASS across the hosted matrix.
  The documentation-policy, SDK install/downstream consumer, ZIP
  packaging and artifact upload jobs PASS. Hosted CI uses Windows/MSVC,
  NOT MSYS2 CLANG64/Clang23; owner three-platform exact-SHA
  terminal runs, authentication, Microsoft-client and desktop remain
  **NOT RUN**. Next R9: separate bounded CLIPRDR chunk/recovery test,
  then R3/R8 authorized channel integration.

  **R9 CLIPRDR chunk reassembly reset/bounds regression (2026-10-15):**
  Added default-enabled `clipboard.chunk-reassembly-reset-bounds`,
  independently dispatched in the existing `test_clipboard_protocol`
  executable against first-party `ChunkReassembler::append/reset`.
  Covers all 256 split offsets of a 257-byte synthetic message,
  byte-at-a-time delivery, caller-owned completed output after reset
  and reuse; rejects premature LAST, changed advertised total,
  overrun, duplicate FIRST, continuation without FIRST, null data
  with nonzero length, zero and 8 MiB+1 advertised totals; then
  accepts a clean new first fragment without stale data.
  Existing `clipboard.protocol` assertions run unchanged.
  **Integration parent main:** `54e107bef8670c8ae3b739c442a3e6147a9b1069`. **PASS isolated:** GCC
  14.2 C++23 Debug/Release, Clang 17 ASan/UBSan plus leak detector on
  first-party `clipboard_protocol.h` and byte-identical production
  reassembler methods under `~/rdp-server/build/`. A deliberately
  removed early-LAST size check caused expected assertion exit 134.
  **NOT RUN at authoring:** complete source CMake/official CTest (Git
  clone DNS unavailable in this environment), exact-SHA hosted Actions
  and the owner's Linux/X11, MSYS2 CLANG64/Clang23 and macOS27
  checkpoint; real OS clipboard, Microsoft client and desktop.
  **Next:** verify the exact committed SHA's hosted CTests, obtain
  owner's unchanged one-root platform reports, then test
  authorization/disconnect propagation from R3 to R8.

  **R9 exact-SHA CI receipt — clipboard fragments (2026-10-15):**
  Implementation `d7946e2e74bf9ca7cdce66f02080b37085812be6`, [Actions 38796420558](https://github.com/k1moradi/RDP-server/actions/runs/38796420558).
  **PASS** Linux/GCC **162/162** and macOS/Clang **151/151**
  in EACH Debug and Release full CTest; documentation-policy PASS.
  New `clipboard.chunk-reassembly-reset-bounds` CTest PASS
  in both configurations, as did existing clipboard behavior tests.
  Windows/MSVC Debug compile PASS, **158/159 Debug CTests PASS**,
  including the new R9 regression, but full job **FAIL** at
  `runtime.validates-configuration-comments-crlf`: R10's
  `tests/check_runtime_entrypoint.cmake:118` observed offline
  configuration check exit **3** versus expected **0**. This
  R10-owned Windows failure was reproduced on earlier SHAs and
  is tracked in [issue #9](https://github.com/k1moradi/RDP-server/issues/9).
  Windows Release NOT RUN because Debug CTest stopped the CI job.
  **NOT RUN:** owner Linux/X11, Windows MSYS2 CLANG64 Clang23
  and macOS 27 on the same SHA, live OS admission/client/desktop.
  **Next:** R10 fix of the offline Windows CRLF fixture/parser and
  full Windows Debug+Release revalidation; then R9 R3→R8
  authorized-channel/teardown integration negatives.

  **R9 offline MCS joined clipboard response/teardown contract (2026-10-15):**
  Introduced `clipboard.mcs-joined-response-teardown` in the existing
  `test_owned_remote_transfer` executable. Its synthetic complete
  MS-RDPBCGR TPKT/X.224/MCS SendDataRequest contains a genuine
  CLIPRDR Format Data Response processed by R8's production
  `RemoteTransfer`, but ONLY after R3's production
  `McsChannelJoinWriteGate` confirms completion of the last
  JoinConfirm write. The test preserves a pending clipboard request
  across pre-join denial, partial-write denial, wrong user/channel
  IDs, invalid TPKT/PER framing, then checks exactly one successful
  payload, close/reset invalidation and independent new-session
  membership. No extra controller or fixture owner was created.
  **Strict limit:** membership is necessary, NOT sufficient for R2
  TLS/OS authorization, channel role, licensing, MCS fragmentation
  or live RDP delivery; currently no authenticated R3→R8 router.
  **Integration parent main:** `46ef1d2282c6c78b67e37b373be77c624bf529b7`. New test is C++23 portable,
  noninteractive and runs in ordinary full CTest. **NOT RUN at
  authoring:** full checkout local CMake/CTest (git clone DNS unavailable)
  and exact-SHA CI/owner platform runs; prior R9 chunk test has hosted
  Linux/macOS PASS but R10 Windows CRLF test remains independently
  tracked. **Next:** evaluate exact published SHA hosted Actions,
  owner Linux/X11, CLANG64/Clang23 and macOS27, then test actual
  R3 admitted channel routing when R2/R3 integration exists.

  **R9 CI syntax correction (2026-10-15):**
  First implementation SHA `d556c2f7ce93b5f46a52fce8ddfd2cf4b2e25eb4`
  failed hosted Linux/GCC **Compile Debug** because an R9 source
  insertion duplicated the `int main(int argumentCount` prefix at
  `tests/test_owned_remote_transfer.cpp:828`. No CTests on that SHA
  completed; do not credit the integration regression with a PASS.
  Restored the single original main declaration without changing
  existing assertions, the dedicated new CTest or production logic.
  **Parent main:** `d556c2f7ce93b5f46a52fce8ddfd2cf4b2e25eb4`. Exact correction-SHA hosted CI
  required before any R9 cross-boundary PASS claim; owner three-platform
  and real R3/R8 authorization remain NOT RUN.

  **R9 MCS→CLIPRDR cross-boundary exact-SHA CI (2026-10-15):**
  Fix SHA `396c81513363d99bb1de60c46f9b2e4bf504c8cf`,
  [Actions 38798952942](https://github.com/k1moradi/RDP-server/actions/runs/38798952942):
  `clipboard.mcs-joined-response-teardown` **PASS** Linux/GCC
  and macOS/Clang **Debug** compiled/native CTest, and project
  documentation policy **PASS**. **FAIL** Linux full Debug
  173/175, macOS full Debug 161/163, precisely two R1
  `test_owned_preauth_session` assertions expecting
  `onSocketReady(true, false) == Interest::Write` at lines
  1967 and 2130. These failed at earlier R1/R3 parents
  too, tracked in [issue #11](https://github.com/k1moradi/RDP-server/issues/11);
  they are not new R9 clipboard failures. Linux/macOS
  Release on this exact SHA **NOT RUN** because Debug
  full-suite failure stopped their jobs. Windows/MSVC
  compiled Debug but hosted Debug CTest **IN PROGRESS**
  at receipt authoring, so no Windows test PASS claimed.
  The initial R9 SHA `d556c2f7ce93b5f46a52fce8ddfd2cf4b2e25eb4`
  had a self-introduced malformed `main` declaration (GCC
  Compile Debug FAIL) and is superseded by the fix SHA.
  **NOT RUN:** owner's specified Linux/X11, Windows
  CLANG64/Clang23, macOS27 and live Microsoft client.
  **Next R9:** after cross-road CI returns to green,
  test authenticated R3-to-R8 routing and stale session
  teardown using the real, once-available authorized router.

  **R9 bounded MCS/CLIPRDR nested-length mutation gate (2026-10-15):**
  Added dedicated default-on `clipboard.mcs-cliprdr-length-mutation-denials` to the existing
  production-linked clipboard executable and sole CTest registry.
  It sweeps 25 strict prefixes and each mismatched byte value of
  the outer TPKT length, T.125/PER userData length and inner
  CLIPRDR Format Data Response payload length (0..255),
  rejecting unauthorized or malformed interpretation before
  clipboard delivery. It also checks assigned UserId/static
  channel membership and invalid PER padding, persistent R8
  fail-closed poison until actual disconnect/reset, recovered
  clean offers, and 256 valid opaque one-byte payload variants
  with zero-copy borrowed-result lifetime. A completed R3 join
  confirmation is a *necessary*, not sufficient, authorization
  precondition; no synthetic TLS/R2/OS admission is granted.
  **Parent main:** `3130fc9f5b57c7d57719ffaf86e9dcc252bfe6bd`. Production implementations
  unchanged; test is deterministic, finite and headless.
  **NOT RUN at authoring:** full local CMake/CTest because direct
  GitHub clone still fails DNS on this worker; exact-commit
  hosted Debug/Release CI and owner platform trio are pending.
  **Next R9:** inspect exact-SHA hosted full CTests, triage
  unrelated cross-road failures explicitly and verify R3
  authenticated ingress only when its production router exists.

  **R9 exact-commit MCS/CLIPRDR mutation CI PASS (2026-10-15):**
  Exact implementation `4eb24cd9312e1d3e133811a8c3a9151cebab4501`,
  [Actions 38844672159](https://github.com/k1moradi/RDP-server/actions/runs/38844672159) completed **SUCCESS**.
  Linux/GCC **202/202**, macOS/Clang **188/188**, Windows/MSVC
  **192/192** registered CTests EACH in Debug and Release,
  including new `clipboard.mcs-cliprdr-length-mutation-denials`
  PASS on all six hosted builds. Documentation-policy,
  staged installed SDK and downstream consumer, ZIP/SHA256
  packaging and artifact uploads PASS; prerelease SKIPPED
  (no version tag). No R9 compiler/CTest defect was confirmed.
  **NOT RUN:** author's local full checkout/ASan/UBSan (GitHub DNS
  unavailable to runner), owner's Linux/X11, Windows MSYS2
  CLANG64/Clang23, macOS27 same-SHA command; real TLS/NLA,
  OS authorization, Microsoft client/desktop/clipboard.
  **Next:** introduce native bounded ASan/fuzzer execution
  receipts, and test *actual* R3-admitted R8 ingress only when
  a production authorized routing owner has been integrated.

  **R9 first-party CLIPRDR sanitizer CI (2026-10-15):**
  Add GitHub Actions `r9-clipboard-sanitizers`, a separate Ubuntu
  C++23 Clang AddressSanitizer+UndefinedBehaviorSanitizer job running
  on every `main` push and PR. Configure from the real source
  into the SAME ephemeral checkout's `build/` directory with
  `-fsanitize=address,undefined -fno-omit-frame-pointer`;
  compile the existing `test_owned_remote_transfer` and
  `test_clipboard_protocol` against production translation units;
  run the sole CTest registry's `-L clipboard` set with ASan leak
  detection and UBSan abort-on-error. No second test registry,
  protocol owner, separate build root, credential, desktop or
  live clipboard. The normal three-OS Debug+Release matrix stays.
  **Integration parent main:** `8083958d617daff00bf68f02848a11eab416bd7d`. **NOT RUN at
  authoring:** new exact-SHA sanitizer job (pending GitHub Actions).
  Earlier R9 normal hosted `4eb24cd9312e1d3e133811a8c3a9151cebab4501`
  passed the Linux/macOS/Windows full Debug+Release suites.
  **Next:** inspect sanitizer exit statuses and real first failure,
  repair any introduced CI defect without relaxing assertions;
  obtain owner Linux/X11, MSYS2 CLANG64 Clang23, macOS27
  separately and eventually real R3/R8 admitted-channel tests.

  **R9 exact-SHA Clang sanitizer CI receipt (2026-10-15):** Implementation `9e4d33b60ca87606cd66625c4212b326d98b5204`,
  [Actions 38849272774](https://github.com/k1moradi/RDP-server/actions/runs/38849272774)
  completed SUCCESS: Ubuntu/Clang ASan+UBSan+leak detection clipboard
  **12/12 CTests PASS**, Linux/GCC **216/216**, macOS/Clang
  **201/201**, Windows/MSVC **215/215** full CTests in Debug
  AND Release, with policy and SDK packaging PASS. Owner three-platform,
  live client and authenticated desktop NOT RUN. Next: R3's real
  session-authorized clipboard router and expanded fuzzing.

  **R9 security/MCS sanitizer coverage expansion (2026-10-15):**
  Extend the existing first-party Ubuntu/Clang ASan+UBSan
  `r9-clipboard-sanitizers` job into the SAME single bounded CI
  job `r9-security-protocol-sanitizers` (not a second workflow).
  Under one ephemeral checkout-local `build/`, compile the five
  production-linked clipboard, MCS Connect-Initial, CredSSP DER
  and CredSSP binding test binaries with Debug symbols,
  `-fsanitize=address,undefined` and preserved frame pointers.
  Preserve the entire existing `ctest -L clipboard` suite,
  and add exactly ten *existing* named CTests covering hostile MCS
  envelope lengths/BER, joined membership/stale receipts, and
  CredSSP DER rejection/bounds/mutations and public-key binding.
  Leak and UB detection halt the job; no live TLS session,
  native desktop, credentials or alternate test registry/build root.
  Existing Linux/GCC, macOS/Clang and Windows/MSVC Debug/Release
  matrices and SDK packaging remain unchanged.
  **Parent main SHA:** `90c17fc19fe17ddc6e87ed712d8b22f5484eb4d6`. **NOT RUN at authoring:**
  new expanded sanitizer CI and owner three-platform commands;
  preceding clipboard-only ASan/UBSan job **12/12 PASS**
  at `9e4d33b60ca87606cd66625c4212b326d98b5204`.
  **Next:** inspect new exact-SHA job for first real sanitizer
  error, record compiler and CTest evidence, then validate
  R3→R8 genuine authorized channel routing when available.

  **R9 workflow syntax repair (2026-10-15):**
  `2cca0ed17d8c98b5f38d5d34079f90d66ce389d4`,
  [Actions 38850195312](https://github.com/k1moradi/RDP-server/actions/runs/38850195312),
  **FAIL** before scheduling tests (zero jobs): R9's quoted
  `ctest -R` expression was truncated into the subsequent
  `documentation-policy` YAML header. This is an R9 CI edit
  defect, NOT a sanitizer finding. Correct the single broken
  workflow line, reinstate `--output-on-failure` and the
  independent documentation-policy job header, retain all
  twenty-two selected clipboard and MCS/CredSSP cases,
  existing full CI matrix and strict sanitizer settings.
  **Parent:** `22915cee335df7d82149728543866f45db7bc8aa`. **NOT RUN at authoring:**
  corrected workflow hosted CI/owner commands. **Next:**
  verify new SHA job scheduling and real sanitizer output.

  **R9 extended native sanitizer verification PASS (2026-10-15):**
  On exact R10-corrected `main` SHA
  `a0c39e4a612c740949c05e4a9699f711061c21d0`,
  [Actions 38850747646](https://github.com/k1moradi/RDP-server/actions/runs/38850747646)
  **SUCCESS**: the single Ubuntu Clang 18.1.3 R9 CI job
  built five production-linked targets under ASan/UBSan
  and leak detection, with 15/15 clipboard and ten MCS/
  CredSSP security CTests PASS (25/25 total), no diagnostics.
  Full hosted Linux/GCC 226/226, macOS/Clang 209/209
  and Windows/MSVC 228/228 CTests PASS in each Debug and
  Release; documentation policy, SDK consumer and
  packaging PASS. First R9 workflow SHAs
  `2cca0ed17d8c98b5f38d5d34079f90d66ce389d4`
  and `a2a85d0e4eb551572e56df8d01df07958c5f3782`
  failed before scheduling jobs due duplicated YAML
  from JavaScript `String.replace` interpreting
  the regex dollar-sign/apostrophe. Concurrent repair
  `4d24b8b3b9857370fef8608cf7d7782f644df3ea`
  restored the workflow; [Actions 38850617229](https://github.com/k1moradi/RDP-server/actions/runs/38850617229)
  then had sanitizer PASS but a sole R10 POSIX fixture
  failure (`file(CHMOD OTHERS_WRITE)`) on Linux/macOS.
  R10 fixed that separately in the passing SHA above.
  **NOT RUN:** owner Linux/X11, MSYS2 CLANG64 Clang 23
  and macOS27 exact-SHA, sustained coverage-guided
  fuzzing, Microsoft-client NLA/OS-authorized desktop.
  **Next:** independently test real R3-admitted R8
  channel dispatch/cancellation when implemented.

  **R9 bounded native coverage-guided MCS/CLIPRDR fuzz gate (2026-10-16):**
  Add opt-in `RDP_SERVER_BUILD_FUZZERS` for Linux/Clang only;
  normal owner builds remain unchanged. New first-party
  `fuzz_mcs_cliprdr` links the actual protocol library and
  drives raw T.125/MCS parsing, CLIPRDR PDU/capability/format
  list/response parsing, nested SendDataRequest payloads and
  bounded chunk-reassembly/reset. Inputs larger than 4096 bytes
  are ignored. Two checked-in binary seeds reach a valid
  Format Data Response and complete TPKT/MCS envelope.
  Conditional CTest `fuzz.mcs-cliprdr-bounded` uses 5000 runs,
  fixed seed 12648430, max_len 4096, 512 MiB RSS, two-second
  per-input and 30-second CTest timeouts; mutable corpus/crash
  files stay under the existing CI `build/`. Existing R9
  Clang ASan/UBSan CI enables it after the 25 deterministic
  sanitizer CTests. No socket, credential, R3 admission or
  desktop is created. **Parent main:** `1260eb659073d5269724a4436e3a8bbfda322725`.
  **NOT RUN at authoring:** exact-SHA libFuzzer/CI and owner
  platform commands. **Next:** inspect any crash artifact and
  first sanitizer stack; otherwise retain bounded seeds and
  await genuine R3-admitted R8 dispatch.

  **R9 bounded libFuzzer exact-SHA CI PASS (2026-10-16):**
  Implementation `f3cde6d231b4f396746f3cd40628e660af5c3a3a`,
  [Actions 38866538809](https://github.com/k1moradi/RDP-server/actions/runs/38866538809)
  completed **SUCCESS**. Ubuntu Clang **18.1.3** built the
  opt-in `fuzz_mcs_cliprdr` target with libFuzzer+ASan+UBSan.
  Existing sanitizer stages passed **18/18 clipboard** and
  **10/10 MCS/CredSSP** CTests, then
  `fuzz.mcs-cliprdr-bounded` **1/1 PASS**. The registered
  CTest invokes libFuzzer with `-runs=5000`, fixed seed
  12648430, `-max_len=4096`, RSS/allocation/time bounds and
  the two checked-in seed inputs. No ASan/UBSan/LSan diagnostic
  appeared. Same-SHA full hosted suites PASS in BOTH Debug and
  Release: Linux/GCC **276/276**, macOS/Clang **258/258**,
  Windows/MSVC **276/276**; docs policy, SDK consumer and
  package jobs PASS. This bounded sample is not exhaustive and
  proves neither R2/R3 admission nor Microsoft-client desktop
  interoperability. **NOT RUN:** owner Linux/X11, Windows
  MSYS2 CLANG64/Clang23, macOS27, sustained multi-corpus
  fuzzing and live authenticated desktop/clipboard.
  **Next:** preserve crashing artifacts if future runs fail;
  otherwise test the real R3-admitted R8 dispatcher when that
  production authority exists.

Each implementation updates the relevant item with exact SHA, test
PASS/FAIL/BLOCKED/NOT RUN, first failing boundary and next smallest step.
Put detailed lessons into the appropriate domain standard, not new files.


## R1 bounded post-handshake TLS application byte stream (2026-10-15)

**Starting main:** `1efd3688872cc38e7c932efc661c793edfd4c4b7`.
R1 now extends the existing nonmoving `OwnedPreauthTcpConnection` instead
of exposing mutable OpenSSL ownership. `readTlsApplicationData` and
`writeTlsApplicationData` accept only 1..18 KiB caller spans and perform
exactly one `SSL_read_ex` / `SSL_write_ex` step on the same accepted
socket -> `NativeTcpIo` -> owned BIO -> owned `SSL` chain. Results expose
exact plaintext progress, provider-derived WANT_READ/WANT_WRITE, orderly
TLS close, transport close, fatal TLS failure and invalid state. OpenSSL
partial-write mode keeps short writes visible; no caller span is retained.

Application mode starts only after a valid established-TLS call, leaving
the legacy first-MCS diagnostic unchanged until an R2/R3 consumer opts in.
A WANT remembers only operation kind, exact retry length and actual
readiness direction; readiness callbacks never replay stale caller memory.
Cancellation/deadline/TLS close/fatal transport errors clear that interest,
destroy SSL/BIO before the accepted socket and remain terminal/idempotent.
The legacy MCS diagnostic is terminally denied once application mode owns
TLS plaintext, preventing a second reader.

Dedicated central CTests:
`transport.tcp-owned-tls-application-io`,
`transport.tcp-owned-tls-application-partial-write`, and
`transport.tcp-owned-tls-application-cancellation`. They use only a real
ephemeral loopback connection and real OpenSSL handshake; cover pre-TLS and
span-bound denials, WANT/readiness without hidden retry, exact bidirectional
byte parity, deterministic short progress, retry-shape denial, deadline
cancellation, close_notify, abrupt FIN and fatal malformed TLS input.

Local one-root CTest is **NOT RUN** in this agent sandbox because no repository
checkout is available and outbound GitHub DNS is blocked; exact-SHA hosted CI
is required after publication. No R2 identity/OS admission, R3 protocol
activation, production listener or R10 scheduler was added. M2 remains
**NOT ACCEPTED**. **Next R1 dependency:** consume concrete R2/R3 integration
feedback; add no further transport abstraction unless their sole owners
demonstrate a missing bounded hook.


**Initial exact-SHA CI / const-safe test correction:** implementation
`e6504314c87fadbb9fcf1cde7f09f9fa5b9de010`,
[Actions 38865843371](https://github.com/k1moradi/RDP-server/actions/runs/38865843371)
compiled the production protocol library successfully on Linux and macOS,
and its sanitizer plus documentation-policy jobs passed. The ordinary
protocol jobs then stopped while compiling the new partial-write CTest
because `establishedTls()` intentionally returns `const SSL*`, whereas
OpenSSL 4's `SSL_get_mode` macro takes mutable `SSL*`. The correction
removes only those two test-introspection assertions; it does not cast away
constness, broaden SSL ownership, or alter production behavior. The existing
1 KiB test send fragment and required short-progress assertion remain the
behavioral proof of `SSL_MODE_ENABLE_PARTIAL_WRITE`.


**Second exact-SHA CI / nonblocking fixture timing correction:**
`68ef1e4a81284df029a4fd00a17db6d1aafdc86f`,
[Actions 38866114504](https://github.com/k1moradi/RDP-server/actions/runs/38866114504),
compiled Debug successfully on Linux and macOS; sanitizer and documentation
policy passed. The new cancellation CTest passed on both hosts and the main
application-I/O CTest passed on macOS. Linux exposed test-fixture timing:
the nonblocking client helper exhausted a yield-only retry loop before all
TLS ciphertext became readable. macOS also showed that a same-size explicit
application read retry may legitimately return WANT again before the full
record arrives. The correction keeps production one-step semantics intact:
fixture WANT loops now wait 1 ms between explicit retries, and the partial
write test resubmits the same 7-byte caller span until Progress instead of
assuming one retry is sufficient. No hidden R1 retry or retained span is
introduced.


**Final hosted verification:** `1260eb659073d5269724a4436e3a8bbfda322725`,
[Actions 38866320385](https://github.com/k1moradi/RDP-server/actions/runs/38866320385)
**PASS**. Linux/GCC Debug and Release each passed **277/277** CTests;
macOS/AppleClang Debug and Release each passed **258/258**; Windows/MSVC
Debug and Release each passed **276/276**. The three dedicated R1
application-I/O CTests passed in those full suites. R9 sanitizer and
documentation-policy jobs also passed; downstream installed-SDK smoke tests
passed **1/1** on each platform and the workflow concluded success. This
hosted matrix is separate from the owner's Linux/X11, Windows MSYS2
CLANG64/Clang 23 and macOS 27 environments, which remain **NOT RUN** here.
M2 remains **NOT ACCEPTED** pending genuine R2 admission, R3 activation and
real Microsoft-client evidence.


## R1 immutable accepted peer endpoint (2026-10-16)

**Starting main:** `cc8e0a9cbfbbf6891720eab03f1e94b926a30285`.
R1 now completes the transport-side half of the roadmap's
"immutable active TLS/peer identity" contract without exposing the native
socket to R2/R3 for address discovery. The SAME successful
`accept`/`accept4` call that creates `OwnedNativeTcpSocket` captures the
IPv4/IPv6 peer endpoint into a fixed-size `TcpPeerEndpoint`: 16 address
bytes in network order, host-order port, and host-order IPv6 scope ID.
Unsupported/non-IP peer address shapes fail closed before an accepted
connection is exposed.

The endpoint moves atomically with the sole accepted-socket owner and is
cleared on close/cancellation. `OwnedPreauthTcpConnection::peerEndpoint()`
returns a value snapshot only; there is no pointer to sockaddr storage,
mutable descriptor capability, reverse DNS, heap allocation, thread, listener
ownership, admission decision, or new state machine. This value is transport
metadata only: it is NOT a verified CredSSP/Kerberos principal, OS identity,
or authorization capability.

New central CTest
`transport.tcp-native-accepted-peer-endpoint` uses a real ephemeral
127.0.0.1 listener/client, independently queries the client's local endpoint,
checks exact accepted peer address/port parity, verifies move continuity into
`OwnedPreauthTcpConnection`, then verifies cancellation revokes the snapshot
while preserving the borrowed listener.

**Authoring validation:** local one-root build/CTest is **NOT RUN** in this
agent sandbox because no repository checkout is mounted and direct GitHub
clone DNS is unavailable. Exact-SHA hosted Debug/Release CI is **PENDING**
after publication. Owner Linux/X11, Windows MSYS2 CLANG64/Clang 23 and
macOS 27 remain **NOT RUN**. No R2 admission, R3 activation, listener service
or Microsoft-client acceptance is implied; M2 remains **NOT ACCEPTED**.
**Next R1 dependency:** let R2/R3 consume this immutable endpoint alongside
the existing read-only established TLS object and bounded application I/O;
add no further transport surface unless integration demonstrates a concrete
missing hook.


## R3 bounded licensing lifecycle foundation (2026-10-16)

**Starting main inspected:** `46b1ca77c4c2c00bbd66e02de71896999f8c71fd`. **Publication parent after
concurrent-agent reconciliation:** `d4682e71e76d55dd923a8ae1e7b970e558e02f6d`. R2 still exposes no
genuine nonforgeable, revocable, TLS-bound native OS admission capability, so
the existing `McsSessionLifecycle` remains denial-only at
`AwaitVerifiedR2Admission -> Closed`; no Boolean, principal string, fake
token or test backdoor can enter the post-auth MCS path.

R3 now contains a first-party allocation-free `RdpLicensingLifecycle`
owned by that same sole session object for teardown. It implements the first
licensing state transition independently of authentication: `NotStarted ->
AwaitClientLicenseResponse` only after a future owner reports a fully written
Server License Request, then accepts exactly one structurally valid initial
client `CLIENT_LICENSE_INFO (0x12)` or
`CLIENT_NEW_LICENSE_REQUEST (0x13)` and stops at
`AwaitServerDecision`. There is intentionally no licensed/completed
transition and no server licensing output yet.

The common MS-RDPBCGR 2.2.1.12.1.1 preamble is exact-length checked with a
65,535-byte hard maximum, current protocol versions 2/3 and only the defined
extended-error flag. Initial client bodies follow MS-RDPELE 2.2.2.2/2.2.2.3:
RSA key-exchange selector, fixed 32-byte ClientRandom, bounded
LICENSE_BINARY_BLOB headers/data, required BLOB types, null-terminated ANSI
user/machine names for new requests, and exact 16-byte MAC tail for stored
license information. Peer lengths never allocate memory; returned body spans
borrow the caller input only for that call. Truncation, overflow, surplus,
wrong type/order, duplicate messages and post-failure data are terminal.

Before production dispatch the eventual owner must additionally prove genuine
R2 admission, matching session generation/TLS provenance, assigned MCS user,
global/static channel, complete segmentation/reassembly, direction and current
licensing phase. Parsing never grants authentication, OS authorization,
licensing success, share activation or application-channel access.

**Dedicated CTests:** `transport.licensing-preamble-and-state`,
`transport.licensing-length-bounds`, and
`transport.licensing-ordering-denials`. A focused standalone GCC C++23
strict-warning build/run of the production licensing translation unit passed
during authoring. Full synchronized repository CMake/CTest and owner
Linux/X11, Windows MSYS2 CLANG64/Clang23 and macOS27 are **NOT RUN** in the
authoring environment because Git network cloning is unavailable; exact-SHA
hosted Actions is to be inspected after direct-to-main publication.
M2 remains **NOT ACCEPTED**.

**Next R3:** keep the same owner and add the smallest spec-backed server
licensing output/write-receipt step needed to drive the accepted initial client
response toward the required challenge/license decision. Do not integrate a
positive Connect Response or licensing path until R2 publishes a real
revocable admission capability.


**Initial exact-SHA compile correction:** implementation
`d4682e71e76d55dd923a8ae1e7b970e558e02f6d`,
[Actions 38870971854](https://github.com/k1moradi/RDP-server/actions/runs/38870971854)
passed documentation policy but the sanitizer job stopped while compiling
`nonblocking_tcp_adapter.cpp`. The new peer parser used POSIX
`sockaddr_in`/`sockaddr_in6` without including `<netinet/in.h>`, Windows
needs `<ws2tcpip.h>` for the IPv6 socket types, and the POSIX accept branch
redeclared the shared `sockaddr_storage`. The correction is compile-only:
add the platform socket-address headers and keep one shared peer-address
storage object. Endpoint capture, ownership, fail-closed address-family
handling and the dedicated CTest semantics are unchanged.


### R3 bounded licensing hosted validation receipt (2026-10-16)

**Atomic R3 implementation:** `05b3814dc93360513c6c0077afa1006c1ad669a4`,
[Actions 38871063598](https://github.com/k1moradi/RDP-server/actions/runs/38871063598).
That exact-SHA workflow **FAILED at an inherited R1 compile boundary** before
the R3 CTests could link: the immediately preceding peer-endpoint change in
`nonblocking_tcp_adapter.cpp` lacked portable IPv4/IPv6 address declarations
and redeclared POSIX peer storage. Documentation policy passed, and
`rdp_licensing.cpp` itself compiled in Linux sanitizer, Linux/GCC,
macOS/Clang and Windows/MSVC builds. The three R3 licensing CTests are therefore
**NOT RUN on the implementation SHA**, not falsely counted as PASS.

R1 corrected only that compile boundary in descendant
`10fff1ab437b74f7065bdd4c87dd9a5095f1f050`,
[Actions 38871271985](https://github.com/k1moradi/RDP-server/actions/runs/38871271985).
With the R3 sources unchanged, Linux/GCC Debug and Release passed **281/281**
CTests each and Windows/MSVC Debug and Release passed **281/281** each.
`transport.licensing-preamble-and-state`,
`transport.licensing-length-bounds`, and
`transport.licensing-ordering-denials` passed in all four suites.
macOS/Clang Debug also passed all three R3 licensing tests; its full suite was
**262/263** because the unrelated R1
`transport.tcp-owned-tls-application-partial-write` aborted, so macOS Release
did not run. The descendant sanitizer job passed its configured suites; an
independent local Clang 17 ASan+UBSan+LeakSanitizer focused run of
`rdp_licensing.cpp` also passed.

Owner Linux/X11, Windows MSYS2 CLANG64/Clang23 and macOS27 remain **NOT RUN**.
No real credentials, OS admission, Microsoft RDP client or desktop were used.
M2 remains **NOT ACCEPTED**.


## R1 loopback accept visibility fixture correction (2026-10-16)

**Starting main:** `9cf14768fbdda1a053c80aee5d34285f63f8a0c2`.
The immutable accepted-peer endpoint implementation itself is verified at
`10fff1ab437b74f7065bdd4c87dd9a5095f1f050`,
[Actions 38871271985](https://github.com/k1moradi/RDP-server/actions/runs/38871271985):
`transport.tcp-native-accepted-peer-endpoint` **PASS** on Linux, macOS and
Windows Debug. Linux/GCC and Windows/MSVC full Debug+Release suites each
passed **281/281**. macOS Debug passed **262/263**; its sole failure was the
R1 `transport.tcp-owned-tls-application-partial-write` fixture at
`test_owned_preauth_session.cpp:2242`, where a just-connected loopback peer
was assumed to be immediately visible to nonblocking `accept`. macOS Release
did not run because Debug failed first. Sanitizer and documentation-policy
jobs passed.

This correction changes TEST fixtures only. A shared
`waitForAcceptedLoopbackConnection` retries the existing one-step
`acceptNonblockingTcpConnection` for at most 2048 one-millisecond attempts,
accepting only `WouldBlock` until the queued peer becomes observable. It is
used by the newly added peer-endpoint test and all post-TLS application-I/O
fixtures. Production listener/accept behavior, ownership, deadlines, TLS,
R2/R3 authority and byte-stream semantics are unchanged. The bounded helper
exists solely to remove scheduler timing from the loopback oracle.


## R3 concrete R2 admission -> MCS Connect Initial handoff (2026-10-16)

**Implementation SHA:** `70897645ed1f822c081747024a847a0928e18f15`.
**Starting main inspected:** `e540be81f297c7f880c6b03db6ffc1a3ad8998ad`;
the implementation was reconciled over concurrent R10/R5 work and published
directly to main without force. A later stale-base R6 shared-file rewrite
preserved the R3 production sources but accidentally dropped this roadmap text
and the Linux CTest registration; this follow-up restores those shared entries
without reverting R6 or subsequent R1 work.

R2 implementation `03f2edbbfaa9049e7d6a22f22c11c94d9ad91213`
introduced the concrete, move-only Linux native admission lease. The sole
`McsSessionLifecycle` now has a private positive transition that only
`LinuxConsoleAdmissionBroker` can invoke. The broker's
`authorizeR3McsConnectInitial` requires current
`kConsoleViewPermission` and runs the existing native `authorizes()`
revalidation immediately before R3 sees the complete Connect Initial. R3
validates its existing parser/domain/GCC boundaries, binds the nonzero R2
admission and native session generations, and advances exactly to
`AwaitConnectResponse`. Public `onConnectInitial` remains denial-only.
No public admission bool/token, fake evidence source, user ID, channel
allocation, TLS writer or response bytes were added.

Any authorization failure closes R3. Any malformed/wrong-order admitted MCS
input closes R3 and revokes the broker/GSS capability, preventing replay.
A valid Disconnect Provider Ultimatum remains legal teardown while waiting for
Connect Response; other DomainMCSPDUs are terminal ordering failures.
`revokeR3Session` provides the ordered cancellation barrier:
R3 state -> R2/GSS revocation -> caller-owned R1 TLS/socket teardown.

**Exact-SHA hosted CI:** [Actions 38873422752](https://github.com/k1moradi/RDP-server/actions/runs/38873422752)
for `70897645ed1f822c081747024a847a0928e18f15` completed **SUCCESS**.
Linux/GCC passed **290/290** CTests in Debug and **290/290** in Release;
the Linux-only dedicated
`security.gssapi-r3-mcs-admission-contract` passed in both configurations.
macOS/Clang passed **265/265** Debug and **265/265** Release, and
Windows/MSVC passed **285/285** Debug and **285/285** Release. Those two
platforms compile the portable R3 protocol changes but do not build the
Linux-GSS-specific contract CTest. R9 sanitizer CI passed **19/19 clipboard**,
**10/10 MCS/CredSSP**, and the bounded fuzzer **1/1**; documentation policy
passed. Installed SDK consumers passed **1/1** per platform, with packaging
and artifact upload successful; untagged prerelease publication was skipped.

**Positive native admission remains NOT RUN in ordinary CI:** no test-only
path can mint `LinuxConsoleAdmissionLease`; genuine Kerberos/TLS plus a real
active physical logind session is required. Owner Linux/X11, Windows MSYS2
CLANG64/Clang23, macOS27 and Microsoft-client desktop remain **NOT RUN**.
M2 remains **NOT ACCEPTED**.

**R2 native-session-change revocation callback (2026-10-16; authoring
parent `aac9c86a17f7489a0523dc1ae4f0591b39b44817`):** add `onNativeSessionChangeReady()` to the concrete
Linux admission broker for event-loop readiness on the broker-owned logind
monitor. A real session change or monitor failure closes the sole R3
lifecycle first and then revokes R2/GSS; missing/unissued watch state is also
terminal. A spurious wake leaves state unchanged but grants no authority:
every later protected transition still requires fresh `authorizes()`.
Dedicated Linux provider CTest
`security.gssapi-r3-native-change-revocation` covers missing-watch
fail-closed behavior, R3/licensing cleanup, GSS rejection and replay denial
without fabricating a positive native lease.
**NOT RUN at authoring:** local full CTest, exact-SHA hosted CI, genuine
Kerberos/TLS admission followed by a real logind switch/logout, live R1
disconnect composition, owner platform trio and Microsoft client.
**Exact-SHA hosted CI:** implementation
`3a350fa386563182872600d55769a4314c0e9b78`,
[Actions 38874417036](https://github.com/k1moradi/RDP-server/actions/runs/38874417036)
completed **SUCCESS**. Linux/GCC full CTest passed **292/292** in Debug and
**292/292** in Release; both
`security.gssapi-r3-mcs-admission-contract` and
`security.gssapi-r3-native-change-revocation` passed in both
configurations. macOS/Clang passed **266/266** Debug and Release;
Windows/MSVC passed **289/289** Debug and Release. R9 sanitizer,
documentation-policy, installed SDK consumer, package/digest and artifact
upload stages passed; prerelease publication was correctly skipped without
a tag. The two R2/R3 GSS tests are Linux-provider-only; macOS/Windows cover
the portable R3 surfaces.
**Still NOT RUN:** genuine positive Kerberos/TLS/native-logind admission
followed by a real switch/logout, live R1 disconnect composition, owner
Linux/X11, Windows MSYS2 CLANG64/Clang23, macOS27 and Microsoft-client
desktop. Gate A/M2 remain **OPEN/NOT ACCEPTED**.
**R2 generation-bound protected-transition authorization (2026-10-16;
authoring parent `9d6fc40ec78a33e4a558f61b9f6e9f36a96110cd`):** add
`LinuxConsoleAdmissionBroker::authorizeR3ProtectedTransition` as the
reusable post-handoff gate for the sole R3 owner. Before any live native
evidence read, R3's revocation-only
`revokeUnlessAdmissionBindingMatches` requires its stored nonzero
admission/native-session generations to equal the exact lease generations.
Caller-supplied scalars can only close an unadmitted/mismatched owner and can
never advance a phase. Only after that fence does R2 repeat permission scope,
exact TLS/GSS identity, policy epoch, NSS/logind fingerprint, freshness and
native-change-watch checks. Any denial closes R3 in the same call and revokes
R2/GSS; success changes no R3 state and writes no bytes.
Dedicated Linux provider CTest
`security.gssapi-r3-protected-transition-generation-fence` checks the
exact nonforgeable-lease API, rejects a Boolean substitute, and executes
zero/nonzero scalar guesses plus replay on a never-admitted R3 owner; every
case is terminal and clears licensing/join state without fabricating a
positive lease.
**NOT RUN at authoring:** local project build/CTest (no checkout), exact-SHA
hosted CI, genuine positive Kerberos/TLS/logind admission, actual Connect
Response publication, owner platform trio or Microsoft client. The current
R3 implementation still stops at `AwaitConnectResponse`; this increment
does not invent writer ownership or protocol progression.
**Exact-SHA hosted validation:** implementation
`3a0500077b6eedc30c656825daaf3fd7545d5d5d`,
[Actions 38877137287](https://github.com/k1moradi/RDP-server/actions/runs/38877137287).
The new Linux provider CTest
`security.gssapi-r3-protected-transition-generation-fence` **PASS** in
Ubuntu/GCC Debug after the production Linux GSS/logind target compiled.
Documentation-policy and the R9 ASan/UBSan/LSan job **PASS**. The sanitizer
selection on this exact SHA predates R9's later regex expansion, so no
sanitizer PASS is claimed for this new CTest itself.

The full Ubuntu Debug suite is **299/300** and macOS Debug **269/270**,
both failing only the inherited R3
`transport.gcc-conference-create` assertion
`earlyCapabilityFlags == 0x0001U`. Parent
`9d6fc40ec78a33e4a558f61b9f6e9f36a96110cd`,
[Actions 38876792846](https://github.com/k1moradi/RDP-server/actions/runs/38876792846),
reproduces the same failure before this R2 change. Release did not run on
those two jobs after Debug failure. Windows/MSVC Debug remained **IN
PROGRESS** at receipt authoring. Therefore whole-workflow PASS is not
claimed, but no R2-introduced failure is observed.

**Still NOT RUN:** genuine positive Kerberos/TLS/logind admission, live use
of this gate before Connect Response/Attach/Join/licensing, owner Linux/X11,
Windows MSYS2 CLANG64/Clang23, macOS27 and Microsoft client. Gate A/M2
remain **OPEN/NOT ACCEPTED**.

**Next R2:** require R3's eventual Connect Response, Attach/Join, licensing,
activation, clipboard/input and desktop transitions to invoke this gate with
their required permission immediately before state/write publication, while
preserving R3 -> R2/GSS -> R1 teardown ordering.

**Next R3:** extend `AwaitConnectResponse` only after updating the existing
Connect Response encoder for the real CredSSP/PROTOCOL_HYBRID settings replay
and moving static-channel/node allocation into this same R3 owner. Require a
fresh broker authorization matching the stored admission/session generations
immediately before response publication, and bind partial TLS writes to stable
monotonic receipts. Then proceed in order to Erect/Attach/Join.


### R1 loopback accept visibility final hosted result (2026-10-16)

Correction SHA `45dc57878bcc741a87bd2ba8b9b9edf15588f062`,
[Actions 38873727660](https://github.com/k1moradi/RDP-server/actions/runs/38873727660).
The bounded accept fixture correction is verified across the exact R1 cases:
macOS/AppleClang **265/265 Debug and 265/265 Release PASS**;
Windows/MSVC **288/288 Debug and 288/288 Release PASS**;
Linux/GCC **289/289 Debug PASS**. Linux Release compiled successfully and
every R1 transport test passed, including
`transport.tcp-native-accepted-peer-endpoint`,
`transport.tcp-owned-tls-application-io`,
`transport.tcp-owned-tls-application-partial-write`, and
`transport.tcp-owned-tls-application-cancellation`, but the full suite was
**288/289** because unrelated
`x11.desktop-resource-owner-lifecycle` failed at
`tests/test_x11_desktop_resources.cpp:115` on
`assert(resources.valid())`. That X11 failure is outside R1 and is not
modified here. R9 sanitizer and documentation-policy jobs **PASS**; the
overall workflow conclusion is therefore **FAIL** solely because of the
Linux Release X11 failure.

No production R1 source changed in this correction. The immutable accepted
peer endpoint, bounded post-TLS application I/O, sole socket/BIO/SSL
ownership, R2/R3 authorization separation and R10 listener ownership remain
unchanged. Owner Linux/X11, Windows MSYS2 CLANG64/Clang 23, macOS 27 and
real Microsoft-client validation remain **NOT RUN**; M2 remains
**NOT ACCEPTED**. **Next R1 dependency:** consume concrete R2/R3 integration
feedback; do not add another transport surface without a demonstrated
missing hook.


## R9 integrated admission/revocation sanitizer gate (2026-10-16; CI pending)

**Starting HEAD:** `45dc57878bcc741a87bd2ba8b9b9edf15588f062`. **Reconciled authoring base:**
`3a350fa386563182872600d55769a4314c0e9b78`. R3 now consumes the genuine move-only R2
`LinuxConsoleAdmissionLease` through
`LinuxConsoleAdmissionBroker::authorizeR3McsConnectInitial`, and R2 also
provides the production native-session-change revocation callback. R9 therefore
targets this real R2->R3 boundary instead of building a synthetic positive
authorization path.

One independent production-backed regression is added to the existing
`test_linux_gssapi_spnego` executable:
`security.gssapi-r3-mcs-disconnect-revocation-fence`. It invokes the real
`revokeR3Session` R3->R2/GSS cancellation barrier, then submits independently
validated late Channel Join and Disconnect Provider PDUs to the sole
`McsSessionLifecycle`. Both remain terminal `Closed`; licensing stays
closed and no join confirmation/channel membership survives. This is distinct
from the existing admission-contract and native-change tests and uses no fake
lease, injected positive evidence, authorization Boolean or second session
owner.

The existing single `r9-security-protocol-sanitizers` job is expanded in the
same checkout-local `build/`. It installs only `libkrb5-dev` and
`pkg-config`, configures `RDP_SERVER_TEST_LINUX_GSSAPI=ON` and
`RDP_SERVER_TEST_REAL_KERBEROS=OFF`, and adds
`test_linux_gssapi_spnego` to the production-linked targets. The bounded
selection preserves the prior 10 MCS/CredSSP cases and adds four R2 admission
cases, the R3 admission contract, R2 native-change/R3 revocation, the new R9
disconnect fence, and all three R3 licensing cases (**20 selected
security/protocol CTests**). Clipboard label coverage and the 5,000-run
`fuzz.mcs-cliprdr-bounded` remain unchanged. ASan leak detection,
`halt_on_error`, UBSan stack traces, frame pointers and
`-fno-sanitize-recover=all` remain enabled.

**Authoring validation:** local configure/build/CTest is **NOT RUN** because
this agent container cannot obtain a synchronized checkout (direct
`github.com` DNS resolution failed). Exact-SHA hosted sanitizer and full
Linux/macOS/Windows Debug+Release outcomes are **PENDING** publication. Real
Kerberos and a genuine positive native admission remain **NOT RUN**; authorized
R3->R8 routing remains **BLOCKED**. Owner Linux/X11, Windows MSYS2
CLANG64/Clang23, macOS27, Microsoft-client interoperability and
performance/reliability acceptance are **NOT RUN**. No temporary patch/diff
file was created. M1-M6 remain unaccepted pending their full evidence.


### R9 first hosted sanitizer boundary and dependency correction (2026-10-16)

Implementation SHA `f99a2ad3efefb03b2316cc940cc625f77d3699eb`,
Actions **38874696875**, reached Ubuntu Clang **18.1.3** with
`RDP_SERVER_TEST_LINUX_GSSAPI=ON`, real Kerberos OFF and the unchanged
ASan/UBSan/LSan settings. Configuration succeeded, but compilation of the real
Linux native-admission target stopped before CTest: without libsystemd
development metadata, the optional no-systemd compilation left native logind
storage fields unused under Clang's `-Werror`
(`sessionIdBytes_`, `displayBytes_`, and `monitor_`). This is the first
R9 failing boundary; no sanitizer diagnostic or test failure occurred because
the target did not finish compiling.

The correction keeps production code, warnings and sanitizer settings intact
and adds only `libsystemd-dev` to the existing sanitizer job's Linux build
dependencies. This compiles the actual systemd/logind integration that the
native R2 admission broker depends on rather than suppressing Clang warnings
or weakening the gate. Exact-SHA rerun is **PENDING**.

In the same `f99a2ad3...` workflow, Linux/GCC full Debug+Release completed
successfully. macOS Debug failed independently in the R1 fixture
`transport.tcp-owned-connection-cancellation` at
`test_owned_preauth_session.cpp:1964` because a loopback accept was assumed
immediately visible; R9 does not modify that R1 boundary. Windows was still
running when this correction was authored.


### R9 MIT GSS failure-path leak isolation (2026-10-16; rerun pending)

Correction SHA `08a6cb30349441db2adc0505965fedf9402ab722`,
Actions **38874962952**, compiled the full native Linux GSSAPI/logind target
under Ubuntu Clang **18.1.3** after adding `libsystemd-dev`. The job then
proved the R9 expansion itself is reachable: clipboard **19/19 PASS** and
**18/20** selected MCS/CredSSP/R2/R3/licensing CTests passed. The three R3
licensing cases, R2 native capability denial, R3 admission contract,
native-session-change revocation and new
`security.gssapi-r3-mcs-disconnect-revocation-fence` all passed. The two
failures were existing
`security.gssapi-configuration-rejections` and
`security.gssapi-console-provenance-before-os-read`; each reached MIT
`gss_acquire_cred_from` with the deliberately unavailable explicit keytab and
LSan reported **216 bytes in 10 allocations**, rooted at
`krb5_copy_principal`.

R9 independently reproduced that exact **216-byte / 10-allocation** signature
in a standalone ASan/LSan program containing no RDP-server code, linked only
to MIT GSSAPI/Kerberos **1.21.3**. The probe released the imported GSS name and
released any returned credential handle; the failed provider call returned
`GSS_C_NO_CREDENTIAL`, leaving no caller-owned object capable of freeing the
reported principal copies. The same external leak reproduced for both a
nonexistent keytab and a syntactically valid empty keytab. This establishes an
MIT provider failure-path leak rather than RDP-server ownership loss.

The gate therefore keeps
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` unchanged and adds one narrow
LSan suppression, `leak:krb5_copy_principal`, **only** to the seven GSSAPI
boundary CTests. The 19 clipboard tests, 13 MCS/CredSSP/licensing CTests and
bounded fuzzer run with no LSan suppression. The GSS CTest step is verbose so
the provider suppression use is auditable. Any unsuppressed ASan/UBSan/LSan
finding still fails the job. Exact-SHA hosted rerun is **PENDING**.


## R3 Enhanced Security Basic Settings replay foundation (2026-10-16)

**Authoring parent:** `799280df6ed88099614ac6a1ddcda2a9aefcb01b`. This increment follows the successful native
R2-admission -> R3 Connect Initial handoff but deliberately does not publish a
Connect Response. Basic Settings has two distinct replay checks: Client Core
replays the server's one earlier `selectedProtocol`, while Server Core
replays the client's entire earlier `requestedProtocols` mask.

Production remains allocation-free. `GccClientSettings` now records optional
`earlyCapabilityFlags` and `serverSelectedProtocol` plus presence bits.
The parser accepts only the 16 legal Client Core body prefix endpoints from
128 through 230 bytes, preventing partial optional fields. The pure
`matchesMcsSecurityNegotiationReplay` correlation accepts only the current
SSL/HYBRID subset, requires the selected bit to have been offered, requires
the Client Core replay field, and compares it exactly.
`encodeMcsConnectResponse` now writes supported request masks 1, 2 or 3
exactly instead of hardcoding 1; zero and unsupported/unknown bits fail closed.

Dedicated central CTest `transport.mcs-response-security-replay` rewrites
only the published Microsoft Client Core replay field, verifies SSL/HYBRID
request-selection correlation, checks exact Server Core mask bytes for 1/2/3,
and proves no other response byte changes. Existing GCC coverage additionally
checks optional-field presence and rejects a split Client Core optional field.
No channel allocation, user allocation, writer, TLS write or new authority is
introduced.

**BLOCKED next positive R3 step:** R1 does not yet preserve/export immutable
selected-protocol provenance from the X.224 negotiation. Connect Response
publication must not accept a forgeable caller scalar. Once R1 provides that
provenance, R3 must freshly revalidate the same R2 admission/session
generations, allocate identifiers in the same owner, and bind partial writes
to stable monotonic receipts. M2 remains **NOT ACCEPTED**.


### R9 integrated native admission/licensing sanitizer exact-SHA receipt (2026-10-16)

Final R9 implementation SHA `799280df6ed88099614ac6a1ddcda2a9aefcb01b`,
[Actions 38875589060](https://github.com/k1moradi/RDP-server/actions/runs/38875589060)
completed **SUCCESS**. This verifies the focused R9 Path-B increment against
the real R2->R3 production boundary without a synthetic positive lease.

The single Ubuntu sanitizer job used Clang **18.1.3 (1ubuntu1)** and one
checkout-local `build/` with
`RDP_SERVER_TEST_LINUX_GSSAPI=ON`,
`RDP_SERVER_TEST_REAL_KERBEROS=OFF`,
`RDP_SERVER_BUILD_FUZZERS=ON`,
`-fsanitize=address,undefined -fno-omit-frame-pointer
-fno-sanitize-recover=all`,
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1`, and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`.
Built production-linked targets were
`test_owned_remote_transfer`, `test_clipboard_protocol`,
`test_owned_mcs_connect_initial`, `test_owned_credssp_tsrequest`,
`test_owned_credssp_binding`, `test_linux_gssapi_spnego`, and
`fuzz_mcs_cliprdr`.

Sanitizer results: clipboard **19/19 PASS**; unsuppressed MCS/CredSSP/licensing
**13/13 PASS**; native R2/R3 GSSAPI **7/7 PASS**; bounded
`fuzz.mcs-cliprdr-bounded` **1/1 PASS**. The fuzzer retains 5,000 runs,
seed 12648430, max input 4096 bytes, 512 MiB RSS, 64 MiB allocation,
2-second per-input timeout and 30-second CTest bound. The three R3 licensing
cases all passed. The four requested credential-free R2 cases all passed, as
did `security.gssapi-r3-mcs-admission-contract`,
`security.gssapi-r3-native-change-revocation`, and R9's independent
`security.gssapi-r3-mcs-disconnect-revocation-fence`.

The two provider-acquisition denial cases used the documented GSS-only
`leak:krb5_copy_principal` LSan suppression. Verbose output reported the
suppression exactly twice, each **216 bytes / 10 allocations**. No suppression
is active for clipboard, MCS, CredSSP, licensing or the fuzzer. This signature
was independently reproduced outside RDP-server with MIT Kerberos 1.21.3 and
no returned credential handle, while hosted Ubuntu uses MIT Kerberos 1.20.1.
No RDP-server ASan/UBSan/unsuppressed LSan diagnostic occurred in the final
job.

Full same-SHA hosted matrix also passed: Linux/GCC **294/294 Debug** and
**294/294 Release**; macOS/Clang **266/266 Debug** and **266/266 Release**;
Windows/MSVC **289/289 Debug** and **289/289 Release**. Installed SDK consumer
tests passed **1/1** per platform; packaging/digest/upload stages completed in
the successful protocol jobs; documentation-policy passed. The earlier
`f99a2ad3...` sanitizer compile failure was R9 CI dependency coverage
(`libsystemd-dev` absent) and was corrected without weakening warnings. Its
concurrent macOS R1 loopback-fixture failure did not reproduce on this final
R9 SHA.

**NOT RUN/BLOCKED:** genuine positive Kerberos/TLS + active physical logind
lease issuance is **NOT RUN**; therefore real positive R3 admission is
**NOT RUN**. Authenticated/authorized R3->R8 clipboard routing remains
**BLOCKED**. Owner Linux/X11, Windows MSYS2 CLANG64/Clang23, macOS27,
Microsoft-client interoperability, and performance/reliability acceptance are
**NOT RUN**. No temporary patch/diff files remain. M1-M6 are not accepted from
this offline/hosted QA increment alone. **Next R9:** when explicit native
authorization is available, independently exercise positive lease issuance,
revocation across reconnect/session generations, and then the genuine
authorized R3->R8 route.


## R7 ScreenCaptureKit stream lifecycle and CoreVideo handoff (2026-10-16)

R7 now contains an opt-in, Apple-only one-display ScreenCaptureKit stream owner. A capture binding is created only from a current `NativeDisplayGeometryRefresh` generation; it preserves the validated CoreGraphics display ID, that display's physical backing dimensions, and the Quartz reconfiguration revision. The Objective-C++ bridge enumerates `SCShareableContent` and selects only the `SCDisplay` whose `displayID` matches that validated identity. Missing or stale displays fail closed; there is no first-display or primary-display fallback.

The owner has explicit idle/preparing/ready/starting/capturing/stopping/closed/failed states. Native delegate, completion and output callbacks retain shared callback state rather than a C++ owner pointer. Stop, close, native failure and topology revocation retire the one-shot stream; a replacement requires a fresh validated geometry generation and a fresh independently authorized R2/R3 binding. R7 does not create an authorization token and the stream is not started automatically by R10.

ScreenCaptureKit is configured for `kCVPixelFormatType_32BGRA`, exact validated display backing dimensions, cursor exclusion for this increment, and `queueDepth = 3`. Only complete, ready video samples with an image buffer and exact dimensions are admitted; the existing `LockedBgraPixelBuffer::lock()` performs the CoreVideo format/stride/storage validation. The frame is synchronously borrowed by `MacCaptureFrameConsumer::consume()` only for the callback duration. R7 adds no unbounded graphics/frame queue; R4 remains responsible for any later owned copy, scheduling, conversion, encode and backpressure.

Dedicated Apple CTests are `macos.capture-stream-lifecycle`, `macos.capture-stream-stale-generation-denials`, and `macos.capture-stream-callback-retirement`. They inject the production lifecycle backend seam and use synthetic CoreVideo buffers; they do not enumerate live shareable content, start a real stream, request Screen Recording permission, inject input or exercise cursor delivery. Cursor metadata remains the preferred next isolated R7 increment after hosted stream-lifetime evidence is stable. M5 remains **OPEN** pending genuine R2/R3 authorization, live macOS capture/input, R4 delivery, and Microsoft-client evidence.


## R9 X11 clipboard teardown sanitizer coverage (2026-10-16; CI pending)

**Starting inspection head:** `9d6fc40ec78a33e4a558f61b9f6e9f36a96110cd`.
**Reconciled authoring base:** `e0a05f8b35df3575984c9de0b022f4af298a13a0`. Genuine positive Kerberos/TLS plus
active physical logind admission is still unavailable, so the next R9
increment stays on credential-free production boundaries rather than
inventing an authorization fixture.

R8 now has a real Linux `X11ClipboardAdapter` that borrows R5's XCB owner and
the sole `RemoteTransfer`; its own exact-SHA hosted run passes all four native
X11 clipboard behaviors, but the dedicated R9 sanitizer job still builds only
the portable clipboard targets. R9 therefore adds `libxcb1-dev`, builds
`test_x11_clipboard_adapter` against the real
`rdp-server-linux-x11-clipboard` production target, and relies on the
existing `-L clipboard` sanitizer step to execute all registered native X11
clipboard behaviors. These tests use the existing deterministic native
operation seam and require no DISPLAY, Xvfb, live clipboard manager or desktop
authorization.

One independent R9 behavior,
`clipboard.x11-disconnect-late-paste-fence`, starts a real
`RemoteTransfer` paste receipt and matching remote format request, marks the
native fetch as started, then disconnects the adapter before the remote
response arrives. Teardown must consume the exact paste receipt and send one
native failure notification before destroying the borrowed-owner window. A
subsequently valid late CLIPRDR response may still be verified by
`RemoteTransfer`, but the disconnected adapter must issue no property write,
no duplicate notification, no stale fetch intent and no republish. Repeated
disconnect remains idempotent. The existing fake-XCB operation seam is reused;
no new harness, session owner or authorization bypass is introduced.

The concurrent R2 generation-bound protected-transition gate is also added to
the existing R9 GSS sanitizer selection as
`security.gssapi-r3-protected-transition-generation-fence`. Its production
contract is denial/revalidation only; R9 does not synthesize a positive lease.

**Expected hosted scope:** the previous 19 portable clipboard CTests plus the
four existing R8 X11 cases and this new R9 teardown case (**24 clipboard
cases**); the GSS selection increases from seven to eight with the new R2
generation fence. Existing MCS/CredSSP/licensing and bounded libFuzzer
selections remain unchanged. Canonical local build/CTest is **NOT RUN** in
this tool environment; exact-SHA hosted CI is required after publication.

A separate shared-branch defect remains outside R9:
`transport.gcc-conference-create` expects the published Microsoft Client Core
`earlyCapabilityFlags` to be `0x0001`, while the checked-in fixture bytes at
the documented offset decode as `0x0018`. R9 does not modify that R3
contract. Genuine positive R2/R3 admission, authorized R3->R8 runtime routing,
owner Linux/X11, Windows MSYS2 CLANG64/Clang23, macOS27, Microsoft-client
interoperability and performance remain **NOT RUN/BLOCKED** as applicable.
M1-M6 remain unaccepted.


## R1 immutable X.224 security negotiation provenance (2026-10-16)

**Starting main:** `a00454ab30e4c3d7708befaee2d7f452901163eb`.
Concrete R3 integration feedback identified the next bounded R1 hook:
`matchesMcsSecurityNegotiationReplay` requires the client's complete original
X.224 `requestedProtocols` mask and the server-selected protocol from that
same exchange; a later caller-supplied scalar is not sufficient provenance.

R1 now records those two values in fixed-size
`SecurityNegotiationProvenance` owned by the existing
`PreauthConnectionStream`. `SecurityReply` carries its selected protocol
explicitly on successful RDP_NEG_RSP, avoiding any confusion with the
NEG_FAILURE failure-code DWORD. The sole
`OwnedPreauthTcpConnection` returns a copy only after the exact attached
SSL/BIO/socket has completed TLS. Provenance is absent before the full X.224
reply, during TLS handshake, on rejected negotiation, and after every
terminal close/cancellation. No raw request bytes, caller views, mutable SSL,
descriptor, authentication result, OS admission capability or R3 state are
exported.

New central CTest
`transport.tcp-owned-security-negotiation-provenance` uses a real ephemeral
loopback socket and real OpenSSL handshake. It proves a TLS+HYBRID client
offer is preserved exactly while R1 selects PROTOCOL_SSL, caller-copy
mutation cannot change the stored snapshot, premature/rejected access is
empty, and cancellation revokes it. The underlying security-negotiation unit
test also distinguishes successful `selectedProtocol` from the failure
packet's unrelated failure code.

The same R1 test change applies the already documented bounded loopback-accept
fixture to the older owned TLS lifecycle/cancellation cases. Cross-road hosted
CI had again reproduced the immediate-accept assumption on macOS in
`transport.tcp-owned-connection-cancellation`; production accept semantics
are unchanged.

**Authoring validation:** local one-root build/CTest is **NOT RUN** in this
agent sandbox because there is no mounted clonable repository. Exact-SHA
hosted Debug/Release CI is **PENDING** after publication. Owner Linux/X11,
Windows MSYS2 CLANG64/Clang 23, macOS 27 and real Microsoft-client validation
remain **NOT RUN**. M2 remains **NOT ACCEPTED**.
**Next R1 dependency:** R3 may consume this immutable replay provenance
together with fresh R2 authorization; add no further R1 transport surface
unless that integration demonstrates another concrete missing hook.


### R9 X11 clipboard teardown sanitizer exact-SHA receipt (2026-10-16)

Implementation `b532c91492b4e6705a0786a5afe6348ec13b79c4`,
[Actions 38877445677](https://github.com/k1moradi/RDP-server/actions/runs/38877445677).
The dedicated `r9-security-protocol-sanitizers` job completed **SUCCESS**
with Ubuntu Clang **18.1.3 (1ubuntu1)** after discovering and compiling the
real X11 clipboard production target through `libxcb1-dev`.

Sanitizer results are **24/24 clipboard PASS**: the prior 19 portable cases,
all four R8 X11 cases, and the independently authored
`clipboard.x11-disconnect-late-paste-fence`. The new case proves that
disconnect cancels/consumes the exact pending paste receipt and sends one
failure notify before native-window destruction; a later valid CLIPRDR response
may remain owned by `RemoteTransfer` but cannot produce an X11 property,
duplicate notify, stale fetch or republish. Repeated disconnect remains
idempotent.

The unsuppressed MCS/CredSSP/licensing selection is **13/13 PASS**. The native
R2/R3 GSS selection is **8/8 PASS**, including the concurrently added
`security.gssapi-r3-protected-transition-generation-fence` plus the prior
admission/revocation fences. The GSS-only MIT provider suppression was used
exactly twice, each **216 bytes / 10 `krb5_copy_principal` allocations**,
matching the already documented external failure-path signature. No
X11/clipboard, MCS, CredSSP, licensing or fuzzer test uses that suppression.
The bounded `fuzz.mcs-cliprdr-bounded` case is **1/1 PASS** with its existing
5,000-run/seed/length/resource/time limits. No unsuppressed ASan/UBSan/LSan
diagnostic occurred in the R9 job.

Documentation policy is **PASS**. The ordinary hosted matrix is not a green R9
claim because it consumes unrelated road changes: Linux Debug reached
**300/301** and macOS Debug **269/270**, each failing only
`transport.gcc-conference-create` at the pre-existing R3 assertion
`earlyCapabilityFlags == 0x0001U`. The checked-in Microsoft fixture's bytes
at that Client Core field are `18 00` = `0x0018`. Release/package stages on
those two platforms were skipped after Debug failure. The Windows job remained
**IN PROGRESS** when this receipt was authored; do not infer a pass or failure
for it from R9.

Positive Kerberos/TLS + active physical logind admission is still **NOT RUN**,
so positive R3 protected-transition authorization and genuine authorized
R3->R8 runtime clipboard routing remain **BLOCKED/NOT RUN**. Live X11
clipboard-manager behavior, owner Linux/X11, Windows MSYS2 CLANG64/Clang23,
macOS27, Microsoft-client interoperability and performance/reliability
acceptance remain **NOT RUN**. M1-M6 remain unaccepted. The next R9 step is to
consume the now-landed immutable R1 negotiation provenance plus R2
generation-bound reauthorization once R3 exposes a real protected transition;
until then, continue independent sanitizer/regression coverage of reachable
production boundaries without synthetic admission.


## R3 protected Connect Response writer boundary (2026-10-16)

**Starting implementation base:** `22d6641f0fbf5f92ce4d1327c1dbcd4fc0a1e11b`.
**Publication parent after concurrent reconciliation:** `abb285087cf500a85090d823fe1ce60881363d4f`.
R1 now exposes immutable `SecurityNegotiationProvenance` only from the exact
established `OwnedPreauthTcpConnection`, and R2 already provides
generation-bound live reauthorization. R3 consumes both without accepting
caller protocol scalars.

The admitted Connect Initial copies only fixed response state: negotiated
DomainParameters, parsed GCC settings, deterministic GCC nodeID 1001, I/O
channel 1003, and ordered static channel IDs from 1004. Borrowed Connect
Initial/GCC bytes do not survive the call. The User Channel ID remains
unallocated until Attach User.

`LinuxConsoleAdmissionBroker::authorizeR3ConnectResponseWrite` borrows the
sole R1 connection, obtains its established TLS pointer and same-connection
negotiation provenance, invokes the existing protected-transition
reauthorization for view permission, correlates Client Core's replayed selected
protocol, and returns exactly one stable R3 write slice with monotonic
reply/slice receipts. The gate is called again before every next partial-write
slice/resubmission. There is no positive API accepting a Boolean or raw
requested/selected protocol scalar.

`completeR3ConnectResponseWrite` accepts only the exact issued reply/slice
receipt. Zero-byte backpressure keeps the slice receipt; positive partial
progress rotates it; stale/duplicate/overreported completion is terminal and
revokes R3 then R2/GSS. Exact full delivery advances only to
`AwaitErectDomain`. The ordinary DomainMCSPDU path still cannot consume
Erect without a later protected R2 wrapper.

Dedicated CTests:
`transport.mcs-response-session-allocation-plan`,
`transport.mcs-response-write-receipts`,
`transport.mcs-response-write-denials`, and
`security.gssapi-r3-connect-response-write-contract`. The Linux contract
test cannot fabricate a positive lease; it proves the broker API requires the
nonforgeable lease plus the R1 connection and guessed completion receipts are
terminal. **Next R3:** add protected Erect Domain progression, then Attach User
allocation/confirmation, each with fresh R2 authorization and the same
single-owner receipt discipline. M2 remains **NOT ACCEPTED** pending genuine
positive native admission and Microsoft-client evidence.


### R1 X.224 negotiation provenance hosted validation (2026-10-16)

**Production/test SHA:** `a00454ab30e4c3d7708befaee2d7f452901163eb`.
**Documentation descendant:** `c09e581ac965e79ce700ef4617a0af6d2b04adba`.
**Owner-fixture normalization:** `ae50773088356ef3d3d281656c0d6e09e432d82d`.

The immutable X.224 request/selection provenance compiles on hosted GCC,
AppleClang and MSVC. On
[Actions 38877612047](https://github.com/k1moradi/RDP-server/actions/runs/38877612047),
`transport.tcp-owned-security-negotiation-provenance` **PASS** on Linux/GCC
Debug and macOS/AppleClang Debug. The surrounding R1 owner block also passes:
connection TLS lifecycle, cancellation, readiness dispatch, reply-interest
priority, deadline cancellation, both bounded-poll cases and all three
post-TLS application-I/O cases. Linux Debug is **301/302** and macOS Debug
**270/271**; each has exactly one unrelated inherited failure,
`transport.gcc-conference-create`, at
`test_owned_gcc_conference_create.cpp:109`
(`settings.earlyCapabilityFlags == 0x0001U`). Release is skipped after that
Debug failure. Documentation-policy and the R9 sanitizer job **PASS** on the
documentation descendant.

The test-only normalization
`ae50773088356ef3d3d281656c0d6e09e432d82d`,
[Actions 38878305211](https://github.com/k1moradi/RDP-server/actions/runs/38878305211),
again passes the complete R1 owner block on Linux and macOS after moving the
remaining owner/readiness setup paths onto the shared bounded accept fixture.
Linux Debug is **306/307** and macOS Debug **274/275**, with the same sole
inherited GCC failure. Documentation-policy and sanitizer again **PASS**.

Windows/MSVC Debug **COMPILE PASS** on both R1 runs, but full CTest remains
**IN PROGRESS**; no Windows CTest PASS/FAIL is claimed. This is inherited:
pre-R1 parent `9d6fc40ec78a33e4a558f61b9f6e9f36a96110cd`,
[Actions 38876792846](https://github.com/k1moradi/RDP-server/actions/runs/38876792846),
is still in the same Windows full-Debug CTest step while its Linux/macOS jobs
fail the same GCC assertion. R1 does not add a watchdog or weaken transport
assertions to mask that suite-level stall.

R3 has since consumed the new R1 surface in production:
`LinuxConsoleAdmissionBroker::authorizeR3ConnectResponseWrite` obtains both
`establishedTls()` and `securityNegotiationProvenance()` from the same
`OwnedPreauthTcpConnection`, freshly reauthorizes through R2, and supplies
R3's receipt-bound Connect Response writer. No caller protocol scalar is
accepted. This satisfies the concrete integration gap that motivated the R1
increment; the existing bounded R1 application writer remains sufficient for
the eventual TLS write step.

The source SHA's standalone documentation-policy job failed only because the
connector transaction ceiling forced source/tests and Markdown into two
consecutive direct-to-main commits. The immediate documentation descendant
passes policy; history is retained rather than force-rewritten.

**NOT RUN:** owner Linux/X11, Windows MSYS2 CLANG64/Clang 23 and macOS 27
same-SHA commands; genuine positive Kerberos/TLS/native-session admission;
real Microsoft RDP client. M2 remains **NOT ACCEPTED**.
**Next R1:** no new transport surface is justified. Support R3's protected
Erect/Attach/Join progression only if integration demonstrates a concrete
missing bounded TCP/TLS hook.


## R4 real x264 AVC420 producer increment (2026-10-16)

R4 now owns a first production H.264 boundary behind the existing RDPGFX
AVC420 packetizer: validated NV12 -> one RAII x264 encoder -> bounded owned
Annex-B access unit -> existing `GfxAvc420Picture`. The x264 source is pinned
and statically vendored, while `rdp-server-protocol` stays independently
buildable/installable without it. The initial encoder is synchronous,
single-threaded, Baseline 8-bit 4:2:0, Annex-B, no B-frame reordering or
lookahead, with explicit SPS coded-to-visible cropping and reset-driven
reference invalidation.

Dedicated production-backed cases are
`graphics.x264-nv12-annexb-picture`,
`graphics.x264-input-rejections`,
`graphics.x264-visible-crop-sequence`, and
`graphics.x264-reset-reference-lifecycle`. They require bytes produced by
x264, inspect SPS/PPS/IDR structure and SPS cropping, feed the result into the
existing AVC420 packetizer, reject malformed plane/stride/lifetime inputs,
and preserve frame-N output storage across frame N+1.

This increment does not create R3 Graphics DVC authorization, a second
presentation scheduler, native capture, or runtime service activation.
Microsoft-client rendering and authorized native-desktop delivery therefore
remain NOT RUN/BLOCKED. M3 / Gate B remains OPEN.


### R3 Microsoft Client Core fixture expectation correction (2026-10-16)

The central GCC regression had a stale test-only expectation for
`earlyCapabilityFlags`: it asserted `0x0001`, while the checked-in
Microsoft 4.1.3 wire fixture contains little-endian `18 00` at the parser's
validated Client Core field and therefore decodes to `0x0018`. Multiple
hosted Linux/macOS runs before the protected Connect Response change reproduced
this same sole assertion failure.

The production parser is unchanged: it continues to read the exact optional
field only when the complete legal Client Core prefix is present. The CTest now
asserts the fixture's actual `0x0018` value. This is a regression-fixture
correction, not a capability negotiation or admission policy change. Exact-SHA
hosted validation is required on the descendant commit.


### R3 borrowed-fixture lifetime correction (2026-10-16)

The first protected Connect Response SHA exposed a macOS-only failure in the
three new transport cases because the tests passed a temporary
`publishedFixture()` vector directly to `parseMcsConnectInitial`. The
returned `McsConnectInitial::gccUserData` is intentionally a borrowed
`std::span`, so the temporary vector was destroyed at the end of that
expression. Linux happened to observe unchanged freed storage; macOS aborted
the assertions. Production parsing/lifetime rules are unchanged.

The correction keeps the fixture vector alive for the complete parse/plan/
encode assertion scope in both new helpers. No parser, allocator, writer,
authorization, or wire behavior changes. The original SHA's Linux/GCC new R3
tests and sanitizer coverage passed; the corrected descendant must provide
cross-platform confirmation.


## R2 Connect Response completion reauthorization (2026-10-16; authoring parent `132b1d5e7ed81809f163cce108acf79c93e53fc6`)

The first protected outbound MCS step already reauthorizes the concrete native
lease before each write slice, but its completion callback previously accepted
only public reply/slice receipts. R2 now requires the same lease plus the exact
`OwnedPreauthTcpConnection` again before R3 may consume accepted-byte
completion. It verifies that R1 still exposes established TLS and immutable
negotiation provenance, then reruns the generation-bound native
`authorizeR3ProtectedTransition(kConsoleViewPermission)`. Missing lease,
TLS/provenance loss, policy/session expiry or change, stale GSS/TLS identity,
native-watch failure, or a bad receipt closes R3 and revokes R2/GSS.

This cannot retract bytes already accepted by R1/TLS after the pre-write
authorization; it closes the narrower state-publication gap so stale
authorization cannot advance durable R3 write state or the next phase.
Dedicated Linux provider CTest
`security.gssapi-r3-connect-response-completion-reauthorization` executes
the real null-lease denial and replay paths without fabricating positive
admission, and compile-time checks prove the old scalar-only completion call
is no longer invocable. **NOT RUN at authoring:** local full CTest,
exact-SHA hosted CI, genuine Kerberos/logind mid-write revocation, owner
platform trio or Microsoft client. Gate A/M2 remain OPEN.

## R1 R3 Connect Response slice compatibility (2026-10-16)

**Starting main:** `372ad95ebe4d93c8c4c476eae10e6064209577aa`.
R2/R3 now consume R1's immutable X.224 negotiation provenance for the
protected Connect Response contract. No new R1 transport surface is required:
R3's current `kMaximumMcsResponseBytes` is 2048 bytes, strictly below R1's
18 KiB `kMaximumTlsApplicationIoBytes` one-step write ceiling.

A new independently registered
`transport.tcp-owned-r3-connect-response-slice` regression proves that
contract through the existing production types. It queues a maximum-sized
`McsConnectResponse` in R3's receipt-owning
`McsConnectResponseWriteGate`, establishes a real OpenSSL TLS session over
an ephemeral loopback socket owned by `OwnedPreauthTcpConnection`, and feeds
each borrowed R3 write view directly to
`OwnedPreauthTcpConnection::writeTlsApplicationData`. A forced 1 KiB TLS
record fragment proves caller-visible short progress; positive progress rotates
the R3 slice receipt, while zero-byte OpenSSL WANT preserves the exact receipt
and borrowed span until explicit retry. The peer receives exact byte parity.

This is transport-compatibility coverage only. The synthetic response is not
authorized for publication and creates no R2 lease, OS admission, R3 phase
advance, listener, session controller or authentication success. Production
R1/R2/R3 code is unchanged. Local repository CMake/CTest is **NOT RUN** in
this agent environment; exact-SHA hosted Debug/Release CI is required after
publication. Owner Linux/X11, Windows MSYS2 CLANG64/Clang 23, macOS 27 and
real Microsoft-client validation remain **NOT RUN**; M2 remains
**NOT ACCEPTED**. **Next R1:** no new surface unless protected
Erect/Attach/Join integration demonstrates a concrete bounded TCP/TLS gap.


## R3 protected Erect Domain progression (2026-10-16)

**Authoring base:** `86b5c32aa0318ab96a3e5e30ddda57a84f54b3b3`; reconciled onto
`e51d69ac5b66e622bb1992a858ee463b25309d0f` without overwriting the concurrent R3 fixture-lifetime correction.
The existing R1 connection owner, R2 generation-bound native admission lease
and R3 Connect Response receipt path remain unchanged. This increment adds only
the next Channel Connection state: after a completely delivered Connect
Response, the sole R3 owner can consume one Erect Domain Request only through
`LinuxConsoleAdmissionBroker::authorizeR3ErectDomain`.

The broker requires the nonforgeable `LinuxConsoleAdmissionLease`, GSS
acceptor, exact `OwnedPreauthTcpConnection`, sole `McsSessionLifecycle`,
and one complete decrypted TPKT. It derives TLS from the R1 owner and repeats
the existing generation fence plus fresh view/native authorization before
calling R3's private Erect transition. No Boolean, raw TLS pointer, identity
string or generation scalar can invoke the positive API.

R3 accepts Erect only from `AwaitErectDomain`. The existing bounded T.125
parser must establish a complete TPKT/X.224 Data TPDU and both PER INTEGER
fields. Success advances exactly to `AwaitAttachUser`; no UserId/channel is
allocated and no reply bytes exist for this step. Nonzero subHeight/subInterval
remain syntactically accepted because Microsoft recommends zero at the client
while server processing requires field presence rather than zero values.
Malformed, oversized, wrong-kind/order, disconnect, stale-generation or
reauthorization failure is terminal and revokes R3 then R2/GSS.

Dedicated CTest: `security.gssapi-r3-erect-domain-contract`. It proves the
broker signature requires the concrete lease plus R1 owner and that public R3
Domain intake cannot manufacture positive progression. Genuine positive
execution still requires real R2 native admission; no fake lease/test backdoor
is added. **Next R3:** Attach User allocation plus receipt-bound Attach User
Confirm, with fresh R2 authorization before request consumption and every
outbound write slice. M2 remains **NOT ACCEPTED**.


### R1 R3 Connect Response slice exact-SHA partial hosted receipt (2026-10-16)

**Code/test SHA:** `372ad95ebe4d93c8c4c476eae10e6064209577aa`.
**Actions:** [38879623066](https://github.com/k1moradi/RDP-server/actions/runs/38879623066).

Hosted macOS/AppleClang has completed **SUCCESS**: the new
`transport.tcp-owned-r3-connect-response-slice` case **PASS** in both Debug
and Release, the full suite is **283/283 PASS** in each configuration, and the
installed-SDK smoke is **1/1 PASS**. This proves the maximum 2048-byte R3
write view traverses the existing bounded R1 OpenSSL application writer with
the intended short-progress/receipt behavior on that host.

At this receipt, the exact-SHA Linux/GCC, Windows/MSVC, R9 sanitizer and
documentation-policy jobs remain **QUEUED**, not PASS or FAIL. The queue is
behind older shared-branch workflows whose Windows jobs remain in the full
Debug CTest step; no R1 assertion failure is currently available from those
queued jobs. Do not infer Linux/Windows success from the macOS result or from
newer descendants.

Concurrent R3 protected Erect Domain integration has also landed and uses the
existing R1 owner only for its established TLS identity; the decrypted complete
TPKT and authorization remain R2/R3 responsibilities. Inspection therefore
shows no new bounded R1 TCP/TLS hook is required for Erect. Owner Linux/X11,
Windows MSYS2 CLANG64/Clang 23, macOS 27, genuine positive native admission
and Microsoft-client evidence remain **NOT RUN**. M2 remains **NOT ACCEPTED**.


## R9 protected-transition/native-input sanitizer integration (2026-10-16; CI pending)

**Starting inspection:** `86b5c32aa0318ab96a3e5e30ddda57a84f54b3b3`.
**Reconciled authoring base:** `08797bea5447fbadabf306ff216fcdb72a7d81c2`. R3 now protects Connect Response
preparation, accepted-byte completion, and Erect Domain progression using the
concrete R2 lease plus exact R1 transport/provenance. R5 also exposes one
stateless X11 input route that requires the same concrete R2/R3 authority and
input permission immediately before XTEST. R8 has additionally landed bounded
X11 INCR clipboard transfer tests. Genuine positive native admission remains
unavailable in hosted CI, so R9 adds no synthetic lease or bypass.

The existing single Linux sanitizer job is expanded in place. It installs the
same XCB/Xvfb development dependencies used by the normal Ubuntu matrix,
builds `test_owned_preauth_session` and
`test_x11_authorized_input_route`, and preserves all prior sanitizer
coverage. Unsuppressed transport coverage adds
`transport.tcp-owned-security-negotiation-provenance`,
`transport.tcp-owned-r3-connect-response-slice`,
`transport.mcs-response-security-replay`,
`transport.mcs-response-write-receipts`, and
`transport.mcs-response-write-denials`.

The native GSS/R2/R3 sanitizer set now includes the previously omitted
`security.gssapi-r3-connect-response-write-contract`, plus
`security.gssapi-r3-connect-response-completion-reauthorization` and
`security.gssapi-r3-erect-domain-contract`. R9 independently adds
`security.gssapi-r3-protected-transition-terminal-replay-fence`: with no
positive lease or established R1 transport, a guessed Connect Response
completion must close R3 and revoke R2/GSS; late Erect input, changed/zero
receipts, public generation guesses, an R3-only replacement, and a completely
fresh owner set must never turn receipt values into authority.

The production-backed
`x11.input-r3-admission-route-denials-and-revocation` Xvfb case is also run
under ASan/UBSan without the MIT GSS leak suppression. It deliberately passes
no admission lease, so a real native desktop plus an input-capable policy must
still fail closed before XTEST and terminally revoke native/R3/R2 state.

Because the sanitizer job executes the full `clipboard` label, all eight
X11 clipboard cases are included, including R8's new bounded INCR progression
and cancellation cases plus R9's disconnect/late-paste fence.

Expected exact-SHA sanitizer scope is clipboard **27**, unsuppressed R1/R3 MCS
+ CredSSP + licensing **18**, native R2/R3 GSS **12**, authorized-input denial
**1**, and bounded fuzzer **1**. The scoped `krb5_copy_principal` LSan
suppression remains GSS-only. Local synchronized build/CTest is **NOT RUN** in
this connector-only environment; exact-SHA GitHub Actions is required after
publication. Positive Kerberos/logind admission, actual protected
writes/completion/Erect/input injection, Attach/Join, authorized R3->R8
runtime routing, owner-platform commands, Microsoft-client interoperability
and performance remain **NOT RUN/BLOCKED**. M1-M6 remain unaccepted.


## R7 generation-safe macOS cursor snapshot boundary (2026-10-16)

R7 now has a separate move-only cursor snapshot beside ScreenCaptureKit frames. A visible snapshot owns at most 256x256 premultiplied BGRA pixels, a checked hotspot, the hotspot position in RDP virtual-desktop pixels, the geometry generation and the Quartz topology revision. Shape storage is tightly packed and capped at 256 KiB. Hidden snapshots deliberately contain no shape bytes or stale position metadata. The portable constructor adopts caller-owned contiguous storage transactionally and rejects stale generations/topology, cursor points outside the validated desktop, invalid dimensions/hotspots/stride and mismatched byte counts.

The Apple-only read-only sampler uses the existing normalized display epoch and maps the Quartz pointer location through `NativeDisplayGeometryRefresh`. It scales the current system cursor image/hotspot to the backing scale of the display under the pointer and renders into owned BGRA storage. Deprecated public system-wide cursor introspection is quarantined in `mac_cursor_snapshot.mm` with local warning suppression. ScreenCaptureKit's `showsCursor` remains disabled, so R7 does not double-composite the pointer into frame pixels.

Dedicated permission-free CTests are `macos.cursor-owned-shape`, `macos.cursor-validation-denials`, and `macos.cursor-topology-revocation`. They never invoke the Apple sampler or inspect a live desktop. Implementation commit `be0a0322117742da5a2cdd8be97b972289d4cce0` is on `main`; exact-SHA hosted Actions run `38881746797` is **QUEUED**, not yet PASS/FAIL. Local strict Clang/GCC and Clang ASan+UBSan+LSan harnesses pass; owner macOS 27 and live cursor sampling remain **NOT RUN**.

This increment still grants no R2/R3 authorization, performs no input injection, and does not publish cursor updates into R4. **Next R7:** define the smallest generation-safe cursor publication/deduplication boundary that consumes this owned snapshot once R4's portable cursor consumer contract is available; otherwise continue native macOS input/session groundwork without duplicating R4 ownership. M5 remains **OPEN**.


## R9 hosted CTest timeout bound (2026-10-16; CI pending)

R9 implementation `b009c43bc6913513937b89c9de16a0abbc5a6a50`,
Actions **38880965403**, is queued behind older workflows. R9 traced the queue
amplifier to completed Windows job `116892480222` in run **38876427741**:
`transport.gcc-conference-create` emitted the now-corrected
`earlyCapabilityFlags == 0x0001U` assertion, but CTest held the test for its
default **1500.01-second** timeout before continuing. Adjacent successful tests
completed normally in fractions of a second. This is bounded-CI infrastructure
evidence, not a DXGI or current-R3 failure claim.

Every hosted CTest invocation now supplies `--timeout 60` as the default
per-test limit: Debug, Release, installed-package consumer, R9 clipboard,
transport, GSS, X11-input and fuzzer runs. Explicit tighter per-test
`TIMEOUT` properties remain intact. No test is skipped or weakened and no
production code changes. `docs/testing_standards.md` records the same rule:
surface and fix slow/deadlocked failures rather than increasing the bound.

The protected-transition R9 exact-SHA run remains **QUEUED**, not PASS/FAIL,
at authoring time. Positive native admission and live/owner/client acceptance
remain **NOT RUN/BLOCKED** as previously recorded.


## R7 generation-pinned macOS input controller (2026-10-16)

R7 now has a generation-pinned, single-thread-affine macOS input state owner. `MacInputController` is bound to one current `NativeDisplayGeometryRefresh` generation and Quartz topology revision; these are revocation facts only and are never authentication or desktop authorization. The controller accepts macOS-native virtual-key codes plus RDP scan identity, virtual-desktop pointer coordinates, five buttons, and bounded vertical/horizontal wheel deltas. Pointer coordinates reuse the existing Retina/multi-display transform, so monitor gaps, stale generations, and topology revocation fail closed.

Held key/button state is fixed-capacity and allocation-free. Duplicate make/button transitions are idempotent, wheel input accumulates in bounded 120-unit steps, callback reentry is denied, cancellation during a callback is deferred, and short native acceptance is terminal. Cleanup releases held native state only while the exact pinned generation/revision remains current; after display refresh/reconfiguration R7 clears local state without injecting releases into a replacement desktop epoch.

The Apple-only bridge compiles a dormant Quartz translator for keyboard, pointer, drag, button, and line-scroll events. It uses the non-prompting Accessibility trust query immediately before native posting, but the callback factory is intentionally private and no runtime path can obtain it. A positive Accessibility result, generation number, or synthetic test callback therefore cannot bypass future macOS R2/R3 authorization.

Dedicated permission-free CTests are `macos.input-controller-lifecycle`, `macos.input-controller-validation-denials`, and `macos.input-controller-revocation-cleanup`. Implementation commit `003f455148fa72f6ee82bd5fbdf6016e3df4fab8` is on `main`; exact-SHA Actions run `38884345628` is **QUEUED**. Local strict Clang/GCC and Clang ASan+UBSan+LSan harnesses pass, and Objective-C++ syntax against stub CoreGraphics/ApplicationServices declarations passes. Owner macOS 27, real Accessibility trust, live Quartz input posting, genuine R2/R3 macOS admission, Microsoft-client input, and performance remain **NOT RUN**.

**Next R7:** do not export the native input callback until a concrete macOS R2/R3 authorization/session route exists. If that cross-road authority remains unavailable, continue isolated macOS session/permission lifecycle groundwork; if R4 publishes a portable cursor-consumer contract first, add generation-safe cursor dedup/publication without creating another graphics scheduler. M5 remains **OPEN**.


## R7 synchronous macOS desktop session/permission guard (2026-10-16)

R7 now has a revocation-only desktop precondition between future macOS R2/R3 admission and the existing capture/input children. `MacDesktopSessionGuard` pins one caller-selected nonzero user ID plus one `NativeDisplayGeometryRefresh` generation/topology revision. Those values are selectors/revocation facts only; they never create authentication, OS admission, capture authority, or input authority.

Each `allows(Capture)` / `allows(Input)` call checks the pinned geometry, reads the caller's Quartz GUI-session facts, samples the relevant no-prompt OS permission, reads the GUI session again, and rechecks geometry. Both session samples must match and report the selected user as both WindowServer session UID and process effective UID, with console/login-complete state. Screen capture uses the existing preflight path; input uses the existing non-prompting Accessibility trust path. Any read failure, UID/session mismatch, permission denial, reentry, mid-check session mutation, geometry refresh, or display-topology change closes the guard permanently.

Implementation `ce23e7dd73a0c943c42a8257149111fe5a66baf7` is on `main`; exact-SHA Actions `38885564347` is **QUEUED**, not PASS/FAIL. Focused strict GCC/Clang C++23 behavior tests and Clang ASan+UBSan+LSan passed locally; the Apple CoreFoundation/CoreGraphics path passed strict syntax against stubs. Real Apple SDK compile/link, owner macOS 27, live GUI-session reads, actual Screen Recording/Accessibility state, positive macOS R2/R3 admission, capture/input use, and Microsoft-client acceptance remain **NOT RUN**.

**Next R7:** add a monotonic native console/session-change revision/watch so a switch-away-and-back entirely between synchronous checks cannot be missed; keep it revocation-only and keep native capture/input capabilities inaccessible until concrete R2/R3 authorization exists. If R4 exposes a portable cursor consumer first, cursor publication/deduplication may proceed instead without creating another scheduler. M5 remains **OPEN**.


## R9 Attach User terminal replay sanitizer coverage (2026-10-16; CI pending)

**Starting main:** `fa79a916fbdda240a8df9601858989ede5e4ca92`. R3 now owns protected Erect Domain and Attach
User confirmation boundaries, while genuine positive Kerberos/TLS plus native
OS admission remains unavailable in hosted CI. R9 therefore extends the real
denial/replay surface rather than fabricating a lease.

New independent CTest
`security.gssapi-r3-attach-user-terminal-replay-fence` exercises the
production `completeR3AttachUserConfirmWrite` rejection path with no lease,
then proves late Attach/Erect PDUs, changed receipt scalars, replacement of only
the R3 lifecycle, and a full reconnect with fresh R2/R3/R1 owners cannot revive
authority or allocate a user ID. It reuses the existing Linux GSS executable
and central registry; no second owner, positive fixture, or test-only admission
seam is added.

The existing single R9 GSS sanitizer selection now includes both
`gssapi-r3-attach-user-contract` and this R9 replay fence, in addition to the
previous Connect Response/Erect/generation/revocation cases. The scoped MIT
`krb5_copy_principal` suppression remains confined to the GSS step.

Canonical local build/CTest is **NOT RUN** in this connector environment.
Exact-SHA hosted ASan/UBSan/LSan and ordinary matrix evidence is required after
publication. Positive Attach User/Join progression, genuine Kerberos/logind
admission, authorized R3 virtual-channel/desktop routes, owner platform checks,
Microsoft-client interoperability and performance remain **NOT RUN/BLOCKED**.


### R9 sanitizer compile-blocker correction (2026-10-16; CI pending)

The immediately preceding shared sanitizer run on `fa79a916fbdda240a8df9601858989ede5e4ca92`
failed while compiling the Linux GSS test executable because an older R2/R3
fixture still called removed diagnostic
`McsSessionLifecycle::pendingConnectResponse()`. Production R3 intentionally
no longer exposes that writer state publicly. R9 does not restore the API.

The fixture now verifies the same terminal-close intent only through supported
public state: phase is `Closed`, GCC node and I/O channel allocation are zero,
and the static-channel allocation span is empty. This is test-only and does not
weaken the existing R2/R3 revocation or writer contract. Exact-SHA hosted
sanitizer evidence is required before the new Attach User replay result is
claimed.


### R9 protected Channel Join sanitizer expansion (2026-10-16; CI pending)

R3 now exposes the protected Channel Join intake/confirmation contract through
the same nonforgeable R2 lease and exact R1 owner. R9 adds the registered
`security.gssapi-r3-channel-join-contract` to the existing native R2/R3 GSS
sanitizer selection. This sits alongside the independently authored
`security.gssapi-r3-attach-user-terminal-replay-fence`; no positive native
lease or synthetic admission is introduced.

The preceding R9 exact-SHA run compiled the GSS executable after the stale
writer-accessor fixture correction, then stopped in two R8 FILEDESCRIPTORW
tests before reaching GSS. Shared commit
`2bdc77344862ee589ae3adbdbe167b4d5947bbc7` corrects those test-only
high/low DWORD fixtures without changing production. R9 consumes that shared
repair rather than duplicating it.

Exact-SHA hosted CI must now demonstrate the complete clipboard label stage,
the expanded GSS selection including Attach User and Channel Join, the existing
R1/R3 MCS/CredSSP/licensing selection, X11 authorized-input denial, and bounded
fuzzer. Positive Kerberos/logind admission, real Join progression, authorized
channel roles, owner platform checks, Microsoft-client interoperability and
performance remain **NOT RUN/BLOCKED**.


### R9 Attach/Join protected-transition sanitizer receipt (2026-10-16)

R9 QA implementation lineage:
`07f53d3aef9162a55943cefe6c6bd513a757cc12`
(`test(r9): fence Attach User terminal replay`),
`b348e2708a9870b69c7e099302357a4a65cef0e5`
(test fixture update after R3 removed the public pending-writer diagnostic),
and final sanitizer expansion
`f1a6dc4c45030daa7fdc47ad4935a6dd46319d3e`
(`ci(r9): sanitize protected Channel Join contract`). The final exact workflow
is Actions `38894157254`.

The dedicated `r9-security-protocol-sanitizers` job completed **SUCCESS**
with Ubuntu Clang **18.1.3 (1ubuntu1)**. Production-linked selected coverage:
clipboard **31/31 PASS**; bounded R1/R3 MCS, CredSSP and licensing
**20/20 PASS**; native R2/R3 GSS **15/15 PASS**; authorized X11 input denial
**1/1 PASS**; bounded MCS/CLIPRDR fuzzer **1/1 PASS**.

The GSS set now includes the R3 owner
`security.gssapi-r3-attach-user-contract`,
`security.gssapi-r3-channel-join-contract`, and R9's independently authored
`security.gssapi-r3-attach-user-terminal-replay-fence`. The R9 replay case
proves that a rejected Attach User confirmation completion closes the sole R3
owner, clears allocated UserId/licensing/join state, revokes R2/GSS, rejects
late Attach/Erect work, survives changed receipt scalars, and cannot be revived
by replacing only R3 or by a fresh reconnect that still lacks a genuine lease
and established R1 authority.

The scoped MIT GSS LSan suppression was used exactly twice, each
**216 bytes / 10 `krb5_copy_principal` allocations**, in the same two
previously isolated provider acquisition failure cases. No clipboard,
MCS/CredSSP/licensing, X11 input or fuzzer test uses that suppression. No
unsuppressed ASan/UBSan/LSan diagnostic occurred in the R9 job.

The shared FILEDESCRIPTORW fixture repair
`2bdc77344862ee589ae3adbdbe167b4d5947bbc7` was consumed rather than
duplicated. It corrected only test encoding of the documented high-DWORD then
low-DWORD size fields; on the final R9 SHA both formerly failing R8 file
metadata/response cases pass under sanitizers.

Same-SHA hosted matrix evidence: Linux/GCC **362/362 Debug PASS** and
**362/362 Release PASS**, installed consumer **1/1 PASS**; macOS/Clang
**310/310 Debug PASS** and **310/310 Release PASS**, installed consumer
**1/1 PASS**. Documentation policy **PASS**. Windows/MSVC full Debug is
**332/334**: only R10
`runtime.validates-live-tls-context-construction` and
`runtime.tls-context-survives-credential-path-replacement` fail with
`OPENSSL_Uplink(...): no OPENSSL_Applink`; Windows Release/package stages are
skipped after that unrelated Debug failure. This is not an R9 sanitizer
failure and whole-workflow PASS is not claimed.

Genuine positive Kerberos/TLS plus active native OS admission remains
**NOT RUN**, so positive Attach User/Channel Join progression and later
authorized channel-role/licensing/desktop routing are still **NOT RUN/BLOCKED**.
Owner Linux/X11, Windows MSYS2 CLANG64/Clang23, macOS27, Microsoft-client
interoperability and performance/reliability acceptance remain **NOT RUN**.
M1-M6 are not promoted by this hosted QA evidence. **Next R9:** independently
exercise terminal replay/reconnect behavior around protected Channel Join
confirmation and then extend sanitizer coverage to the next real R3
channel-role/licensing transition as it lands; continue to avoid synthetic
positive admission.


## R7 monotonic macOS session-change revocation watch (2026-10-16; exact-SHA CI pending)

R7 closes the documented switch-away-and-back gap with a distinct process-scoped
`NativeSessionChangeWatch`, separate from display-topology ownership. Its
process-lifetime nonzero revision uses release/acquire atomics, advances on each
accepted resign-active/become-active event and on coverage start/stop, and fails
closed on numeric exhaustion instead of wrapping. Only one registration owner
may exist; ambiguous observer removal keeps that reservation held. Native
callbacks carry only a scalar registration epoch and static recorder, so late
callbacks cannot dereference a destroyed watch or revive a retired epoch.

The Apple bridge observes
`NSWorkspaceSessionDidResignActiveNotification` and
`NSWorkspaceSessionDidBecomeActiveNotification` through the shared
`NSWorkspace` notification center. `startNative()` accepts coverage only
from an already-running AppKit main event-loop context; successful observer
creation alone is not treated as proof that a headless/stalled process observes
every fast-user-switch transition. Unavailable delivery context therefore fails
closed. Owner macOS 27 notification-delivery validation remains **NOT RUN**.

`MacDesktopSessionGuard` now pins the active session-watch revision alongside
target UID, display generation and topology revision. Every capture/input check
requires that revision before the first Quartz session read and again
immediately before success, in addition to the existing two identical session
observations and permission preflight. Any session-watch event, coverage loss,
session mismatch, permission denial, display change, reentry or callback
cancellation permanently closes the guard; a later become-active event cannot
revive it even if the same UID returns.

Dedicated ordinary CTests retain the existing three session cases and add
`macos.desktop-session-switch-away-back-revocation`,
`macos.desktop-session-mid-operation-epoch-change`,
`macos.desktop-session-watch-registration-retirement`, and
`macos.desktop-session-watch-unavailable-denial`. Focused authoring coverage
passed **7/7** with strict GCC 14.2 C++23 and **7/7** with Clang 17
ASan+UBSan+LSan. Ordinary tests use the production atomic recorder with a
synthetic registration backend and never install AppKit observers.

Historical CI was rechecked before this increment. Cursor
`be0a0322117742da5a2cdd8be97b972289d4cce0` passed hosted macOS
Debug/Release **290/290** CTests. Input/session-guard workflows were blocked by
the unrelated R8 braced-`assert` compile error. Descendant
`2bdc77344862ee589ae3adbdbe167b4d5947bbc7`, Actions `38893987860`,
cleared that blocker with Linux **362/362** and macOS **310/310** full CTests
plus documentation policy and R9 sanitizer PASS; Windows reached full CTest and
failed only then-existing R10 live TLS-context cases.

Exact-SHA hosted validation for this increment, owner macOS 27, genuine R2/R3
per-user macOS admission, live capture/input, R4 publication and Microsoft-client
acceptance remain **NOT RUN**. Next R7 is the R2/R3 binding of the existing
children to a genuinely authorized per-user desktop, not publication of native
authority from revocation metadata. **M5 remains OPEN.**


## R7 macOS session-change watch exact-SHA hosted receipt (2026-10-16)

R7 implementation is the net tree at
`e4b0df9c3a2e9e466b3a24cb7dc2f563d2160533`; relative to pre-R7 parent
`3d3d5c758e0e4216132f73e0cc2506ac45e87d75` it changes exactly the intended
12 R7 source/test/CMake/documentation files. A transient sparse-tree publication
at `0f974721035491e21c084f861f7daad37be6e521` was immediately corrected by
the forward repair commit; no force push or history rewrite was used.

Exact workflow Actions `38895679498`: documentation-policy **PASS**; R9
ASan/UBSan/fuzzer security job **PASS**; Linux/GCC full **373/373 Debug and
373/373 Release PASS**; Windows/MSVC full **346/346 Debug and 346/346 Release
PASS**. All seven `macos.desktop-session-*` tests pass in both configurations
on Linux and Windows. SDK stage/consumer/package steps pass on both platforms.

macOS/AppleClang compiles and links the real ARC Objective-C++ NSWorkspace
observer in both configurations. Debug full **321/321 PASS**. Release executes
all seven R7 session tests successfully but finishes **320/321** because
unrelated R1 test `transport.credssp-r1-owned-framing` aborts at
`tests/test_owned_preauth_session.cpp:5708`; R7 source/test compile and
behavior are not implicated. The macOS package steps are skipped only because
the full Release CTest job stops after that R1 failure.

Owner macOS 27 real fast-user-switch notification delivery, genuine R2/R3
per-user macOS authorization, live ScreenCaptureKit/Quartz input, R4
publication, Microsoft-client M5 acceptance and performance remain **NOT RUN**.
R7's next production dependency is the concrete R2/R3 authorized per-user
desktop binding; the new revision remains revocation-only and cannot mint
capture/input authority.


## R7 native ScreenCaptureKit factory quarantine (2026-10-16; CI pending)

The R2/R3 macOS authorization dependency remains unresolved: current positive
native admission is Linux-specific and there is no macOS lease/capability that
can legitimately mint desktop capture authority. R4 still has no portable
cursor-consumer contract. R7 therefore hardens the existing boundary instead
of fabricating either dependency.

`MacScreenCaptureStream::createNative()` and the declared
`detail::makeNativeMacScreenCaptureBackend()` escape hatch are removed from
the macOS header; the backend factory definition is removed as well. The
ScreenCaptureKit backend implementation remains compiled in the private
Objective-C++ translation unit so its SDK/lifetime code continues to receive
Apple compiler coverage, but no repository API can instantiate it before a
future concrete R2/R3 macOS authorization route. The existing
`createForTesting()` seam remains for deterministic injected backends only and
does not expose ScreenCaptureKit capability.

Apple CTest `macos.capture-stream-native-factory-quarantine` carries a
compile-time concept assertion that the stream type has no `createNative`
member and executes no native setup. Existing capture lifecycle tests continue
using synthetic CoreVideo buffers and injected backends. This matches the input
side, where the Quartz posting callback was already intentionally private.

Exact-SHA AppleClang Debug/Release compile and full matrix validation are
required after publication. Genuine macOS R2/R3 per-user authorization, owner
macOS 27 notification delivery/live capture, R4 cursor publication and
Microsoft-client M5 acceptance remain **NOT RUN/BLOCKED**. **Next R7:** consume
a non-forgeable macOS authorization capability if R2 publishes one; otherwise
do not restore the native capture factory or export native input posting.

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


## R7 native capture quarantine receipt and cursor-sampler quarantine (2026-10-16; new CI pending)

Capture-factory hardening commit `7a83947d7876574f573ac393d3e1311d40eea80f`,
Actions `38896898244`, is validated as follows: documentation policy and the
R9 sanitizer/fuzzer job **PASS**; Linux/GCC full **378/378 Debug and 378/378
Release PASS** with SDK consumer/package PASS; Windows/MSVC full **351/351
Debug and 351/351 Release PASS** with SDK consumer/package PASS. macOS
AppleClang successfully compiles the private ScreenCaptureKit backend with no
public native factory, and
`macos.capture-stream-native-factory-quarantine` **PASS**. The macOS full
Debug suite is **325/326** only because unrelated R1
`transport.credssp-r1-owned-framing` aborts in the concurrently changing
owned-TLS fixture; Release/package are skipped after that failure. No R7
capture test failed.

The same authorization invariant is now extended to cursor state. The portable,
owned `MacCursorSnapshot` constructor remains public for synthetic/native data
that an authorized owner may eventually provide, but
`queryNativeMacCursorSnapshot` is removed from the header. The AppKit sampler
stays compiled as a translation-unit-private, `[[maybe_unused]]` function so
deprecated cursor API containment, Retina scaling and BGRA rendering continue
to receive Apple compiler coverage without exposing a live desktop read path.
No R4 cursor scheduler/encoder is introduced.

Portable CTest `macos.cursor-native-sampler-quarantine` uses a dependent
`requires` expression plus `static_assert` to prove the public header cannot
resolve the native sampler through ADL; it performs no AppKit call. Existing
owned-shape/validation/topology cursor tests are unchanged.

Exact-SHA Linux/Windows/macOS and policy/sanitizer validation for this cursor
quarantine is pending publication. Genuine macOS R2/R3 per-user authorization,
owner macOS 27 live notification/cursor/capture validation, R4 cursor
publication and Microsoft-client M5 acceptance remain **NOT RUN/BLOCKED**.
**Next R7:** expose neither live cursor sampling nor native capture/input until a
non-forgeable macOS R2/R3 capability exists; consume R4's cursor contract only
if R4 publishes one.


## R7 portable macOS BGRA framebuffer handoff (2026-10-16; exact-SHA CI pending)

R7 now converges ScreenCaptureKit callback data with R4's existing
`FramebufferView` contract, matching Windows/X11. Allocation-free
`makeMacBgraFramebufferView()` revalidates `BgraPixelLayout`, requires exact
pitched storage and transactional publication. `LockedBgraPixelBuffer`
continues to retain/read-lock CoreVideo while a synchronous
`MacCaptureFrameConsumer` receives only the borrowed portable view.

No frame IDs, damage inference, queues, scheduling, encoding, ACKs, R3 channel
authority or native authorization are added. The native ScreenCaptureKit
factory, AppKit cursor sampler and Quartz input route remain quarantined while
R2 positive admission is Linux-specific.

New CTests: `macos.capture-framebuffer-view-contract` and
`macos.capture-stream-framebuffer-contract`. Focused helper checks pass strict
GCC 14.2 C++23 and Clang 17 ASan+UBSan+LSan. Exact-SHA hosted Apple/full matrix
is pending. Next R7 remains a genuine non-forgeable macOS R2/R3 capability;
M5 remains open.


## R7 macOS portable framebuffer exact-SHA hosted receipt (2026-10-16)

Implementation `35df03319d0a1cf4ac667f1715e7408958b78d74`,
Actions `38897985255`, completed the full hosted matrix successfully.
Linux/GCC full CTest is **388/388 PASS** in both Debug and Release;
Windows/MSVC is **359/359 PASS** in both Debug and Release; macOS/AppleClang is
**335/335 PASS** in both Debug and Release. Documentation policy and the R9
ASan/UBSan/fuzzer job also PASS, and each platform's installed SDK consumer is
**1/1 PASS**.

The new portable `macos.capture-framebuffer-view-contract` passes in both
configurations on Linux, Windows and macOS. Apple-only
`macos.capture-stream-framebuffer-contract` passes in both macOS
configurations using the synthetic padded CoreVideo buffer. The same Apple
runs also pass `macos.capture-stream-native-factory-quarantine` and
`macos.cursor-native-sampler-quarantine`, so the portable handoff did not
reopen either live native desktop-read path.

AppleClang compiles and links the production CoreVideo lock owner and
ScreenCaptureKit callback with the new `FramebufferView` consumer signature.
No frame queue, scheduling, codec, transport or authorization owner was added.
Current R2 work has advanced R1-owned HYBRID CredSSP progression but still
provides no non-forgeable macOS native-admission lease/capability. R7 therefore
does not expose ScreenCaptureKit construction, cursor sampling or Quartz input.
Owner macOS 27 live capture/cursor/input, real per-user R2/R3 admission,
Microsoft-client M5 acceptance and performance remain **NOT RUN/BLOCKED**.


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


### R10 CredSSP aggregate test-enum compile correction (2026-10-16)

Exact implementation SHA `b2d1122f6ad9bd063688c0466cc30ae434806485`,
Actions `38898862902`, reached the R10 Linux production target successfully:
`rdp-server-linux-runtime-security` compiled and linked. Ubuntu, macOS and the
R9 sanitizer build were initially blocked by an unrelated R3
`frameDomainPdu` declaration error; descendant R3 commit
`23c3703cd562f596622fd8840c36a1a9d0439443` fixed that shared compile
boundary. The descendant Ubuntu build then exposed one R10 test-only stale
enum comparison in `testConnectionCredSspAuthorizationDenials`: the final
post-revoke assertion still named `TsRequestTlsReadStatus::Closed` after
`onCredSspIoReady()` moved to `LinuxCredSspStepStatus`.

This correction changes only that assertion to
`LinuxCredSspStepStatus::Closed`; production CredSSP/GSS orchestration,
ownership and teardown are unchanged. The failing descendant compile therefore
records the R10 test as **NOT RUN**, not FAIL behavior. Exact correction-SHA
hosted CI is required before claiming the new aggregate CTests PASS. Owner-local
canonical `~/rdp-server/build` remains **NOT RUN** in this connector
environment.



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


## R7 ScreenCaptureKit consumer-cancellation regression (2026-10-16; CI pending)

The macOS native-authorization dependency remains unchanged: R2 still has no
non-forgeable macOS admission lease/capability, and R4 still exposes no cursor
consumer contract. R7 therefore adds lifecycle coverage only, without exposing
native ScreenCaptureKit, cursor sampling or Quartz input.

New Apple-only CTest `macos.capture-stream-consumer-cancellation` closes the
existing `MacScreenCaptureStream` synchronously from inside its borrowed
`MacCaptureFrameConsumer::consume()` callback. It verifies that callback-local
shared ownership survives `consumer_.reset()`, the in-flight frame returns
`RetireStream` instead of `Published`, the backend closes exactly once, a
retained callback-state handle cannot deliver another frame, and repeated
owner close is idempotent. The fixture uses a synthetic CoreVideo buffer and
the injected backend; it does not enumerate or start ScreenCaptureKit or query
TCC.

No production source is changed by this increment. Canonical owner-local
`~/rdp-server/build` remains unavailable in this connector environment, so
the new Apple test is **NOT RUN** at authoring; exact-SHA hosted AppleClang
Debug/Release plus the full cross-platform matrix are required after
publication. **Next R7** remains a genuine R2/R3 macOS authorization
capability; M5 remains open.


## R7 capture consumer-cancellation exact-SHA hosted receipt (2026-10-16)

Test-only implementation `93f9e5980b4cbadc9309dc676c45be558dcbda17`,
Actions `38900557422`, validates the synchronous close-from-consumer lifetime
boundary without changing production code or native authorization reachability.

macOS/AppleClang full CTest is **338/338 PASS** in both Debug and Release.
The new `macos.capture-stream-consumer-cancellation` case passes in both
configurations and proves that closing the stream from inside
`MacCaptureFrameConsumer::consume()` makes the in-flight callback return
`RetireStream`, closes the injected backend exactly once, rejects a later
callback through retained `MacScreenCaptureState`, and keeps repeated close
idempotent. The macOS installed SDK consumer is **1/1 PASS** and packaging
completes.

Windows/MSVC full CTest is **361/361 PASS** in both Debug and Release, with
the installed SDK consumer **1/1 PASS** and packaging complete. Documentation
policy and the R9 ASan/UBSan/fuzzer job **PASS**.

Ubuntu/GCC Debug runs **394/395**: the only failure is unrelated R10
`runtime.linux-connection-credssp-owner-framing`, which aborts at
`tests/test_runtime_linux_security.cpp:648` on
`step.plaintextBytesWritten == 0`. Release/package steps are skipped after
that Debug failure. No R7 source or test is implicated, and the new case is
Apple-only.

The roadmap dependency remains unchanged: no non-forgeable macOS R2/R3
admission capability and no R4 cursor-consumer contract exist. Native
ScreenCaptureKit construction, AppKit cursor sampling and Quartz input remain
quarantined. Owner macOS 27 live desktop evidence and M5 remain
**NOT RUN/BLOCKED**.


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


## R4 fixed-CFR PTS contract + recovered reference CTest (2026-10-16; hosted CI pending)

**Starting reconciled shared `main`:** `0a07d096626cad58576d14de72ff52c6d333439c`.

Source review of pinned x264 `4613ac3c15fd75cebc4b9f65b7fb95e70a3acce1`
found that R4's fixed-CFR configuration does not use caller PTS for rate
control or frame duration: `b_vfr_input=0`, fps/timebase are 60/1 and 1/60,
and B frames/lookahead are disabled. R4's AVC420 framing, presentation
lifecycle, ACK window, latest-frame state and interaction scheduler do not
consume PTS. A strict duplicate/backward-PTS preflight would therefore add an
unsupported second ordering authority and reject inputs that are valid for the
current encoder. R4 keeps PTS as opaque signed 64-bit pass-through metadata;
gaps, duplicates, decreases and extreme values are allowed, with no internal
counter/sentinel arithmetic.

Two production-backed cases are added:
`graphics.x264-cfr-pts-passthrough` verifies real x264 returns duplicate,
backward, gapped and `INT64_MIN`/`INT64_MAX` PTS labels unchanged while
maintaining the IDR -> P reference chain; and
`graphics.x264-segmented-cfr-pts-reference-continuity` verifies the real
NV12 and BGRA producer paths fully deliver/ACK fresh frame IDs across those
PTS patterns without an avoidable IDR. Existing backpressure cases already
retry the same PTS after a pre-encode denial, confirming denied work does not
need timestamp bookkeeping.

Reconciliation also found that current `main` still contained the production
body and command dispatcher for
`x264-segmented-malformed-nv12-reference-continuity` but had lost its
central `tests/CMakeLists.txt` registration. This increment restores that
previously validated R4 CTest rather than allowing reference-denial coverage
to silently disappear.

The canonical owner-local `~/rdp-server/build` configure/build/full CTest is
**NOT RUN** in this connector environment because the checkout is unavailable.
Exact-SHA Linux/GCC, macOS/Clang, Windows/MSVC Debug/Release, R9 sanitizer
scope, documentation policy and SDK/package consumer evidence must be
inspected after publication. Real authenticated R3 Graphics DVC/full-send
integration, owner Linux/X11, Windows MSYS2 CLANG64/Clang 23, macOS 27,
native capture performance and Microsoft-client rendering remain
**NOT RUN/BLOCKED**. Gate B and M3/M4/M5 remain **OPEN**.


## R4 fixed-CFR x264 PTS exact-SHA hosted CI (2026-10-16)

**Implementation:** `f032e4c434642dc788a56e48616e1e72d429935c`.
**Actions:** `38903954802` — **SUCCESS**.

- **Linux/GCC:** Debug **405/405 PASS**, Release **405/405 PASS**.
  `graphics.x264-cfr-pts-passthrough` (#392),
  restored `graphics.x264-segmented-malformed-nv12-reference-continuity`
  (#396), and `graphics.x264-segmented-cfr-pts-reference-continuity`
  (#399) pass in both configurations. Installed SDK consumer/package gates
  also pass.
- **macOS/Clang:** Debug **346/346 PASS**, Release **346/346 PASS**.
  The same three R4 cases pass as #333, #337 and #340 in both configurations;
  SDK consumer/package gates pass.
- **Windows/MSVC:** native R6 preflight **39/39 PASS** in Debug and Release;
  full Debug **371/371 PASS**, Release **371/371 PASS**. The three R4 cases
  pass as #358, #362 and #365 in both configurations; SDK consumer/package
  gates pass.
- **R9 selected ASan/UBSan job:** **PASS** for its configured scope, but the
  workflow target list still excludes `test_x264_avc420_encoder` and
  `test_x264_avc420_segmented_frame_producer`; real x264/BGRA execution
  under sanitizers remains **NOT RUN**, not PASS.
- **Documentation policy:** **PASS**. Prerelease publication correctly
  **SKIPPED** for an ordinary development commit.

This exact-SHA matrix also proves the earlier R10-owned
`runtime.linux-connection-credssp-owner-framing` failure is no longer a
blocker for this R4 implementation: the complete Linux Debug/Release suites
pass at `f032e4c...`. The fixed-CFR PTS decision remains unchanged: no
monotonic timestamp gate, counter, clock or second scheduler is introduced;
caller PTS is opaque pass-through metadata under the current x264 CFR/no-B
configuration.

**Still NOT RUN/BLOCKED:** owner `~/rdp-server/build` command on Linux/X11,
Windows MSYS2 CLANG64/Clang 23 and macOS 27; real R4 x264/BGRA sanitizer
execution; genuine authenticated R3 Graphics DVC/full-send integration;
native capture performance; and Microsoft-client graphics rendering.
Gate B and M3/M4/M5 remain **OPEN**.


## R7 ScreenCaptureKit single-stop ownership (2026-10-16; CI pending)

Starting shared-main base: `695dd90b80cf105d7bdeb90576168801ffaf011b`. R7 found a native lifecycle ownership
race in the quarantined ScreenCaptureKit backend. An in-flight output callback
can return `RetireStream` after its synchronous consumer has already invoked
owner `stop()` or `close()`. The owner path can therefore submit
`stopCaptureWithCompletionHandler` and the output delegate can immediately
submit the same native stop a second time; startup retirement and later close
have the same duplicate-submission risk.

The shared `MacScreenCaptureState` now carries a one-shot native-stop claim.
Every native ScreenCaptureKit stop site must win that claim before submitting
`stopCapture`: output retirement, start-completion retirement, explicit stop,
and close. The winner's completion also completes a concurrently entered
`Stopping` state when applicable. No restart path is added and the claim never
resets for the one-shot stream.

New Apple-only CTest `macos.capture-stream-native-stop-single-ownership`
uses the injected backend and synthetic CoreVideo frame. Its consumer calls
owner `stop()` synchronously while the borrowed framebuffer is live, then it
verifies exactly one native-stop claim, rejects the output-callback's second
claim, completes the graceful stop, rejects a later close claim, and prevents a
retained callback state from publishing again. No ScreenCaptureKit stream is
enumerated or started, no TCC prompt is requested, and no desktop pixels leave
the synthetic fixture.

Canonical owner-local `~/rdp-server/build` configure/build/CTest is **NOT RUN**
because that checkout is unavailable in this connector environment. Hosted
exact-SHA AppleClang Debug/Release plus the ordinary cross-platform matrix are
required after publication. The authorization dependency is unchanged: there
is still no non-forgeable macOS R2/R3 admission capability and no R4 cursor
consumer contract, so native construction/input/cursor publication remain
quarantined and M5 remains **OPEN/BLOCKED** on those dependencies.


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


## R7 native capture single-stop exact-SHA hosted receipt (2026-10-16)

Implementation `94e2a450c31346a3eaee94143fd4f73e49fd4d1c`, Actions
`38904721033`, completed **SUCCESS**. The production change serializes all
ScreenCaptureKit stop submissions through the one-shot
`MacScreenCaptureState::claimNativeStopRequest()` fence, preventing explicit
owner stop/close, start-completion retirement and output-callback retirement
from submitting duplicate native stop requests.

macOS/AppleClang full CTest is **349/349 PASS** in Debug and **349/349 PASS**
in Release. New
`macos.capture-stream-native-stop-single-ownership` is test #323 and passes in
both configurations, proving owner `stop()` from inside the synchronous
frame consumer wins the one native-stop claim, the returning output callback
cannot claim another, later close cannot claim another, and retained callback
state cannot publish after stop completion. The modified Objective-C++
ScreenCaptureKit source compiles in this job. Installed SDK consumer is
**1/1 PASS** and packaging succeeds.

Ubuntu/GCC full CTest is **407/407 PASS** in both Debug and Release, including
`runtime.linux-connection-credssp-owner-framing`; installed SDK consumer is
**1/1 PASS** and packaging succeeds. Windows/MSVC focused native preflight is
**39/39 PASS** in both configurations, full CTest is **373/373 PASS** in Debug
and Release, and installed SDK consumer is **1/1 PASS**. R9
security/protocol sanitizers and documentation policy both **PASS**.
Untagged prerelease publication is correctly **SKIPPED**.

Canonical owner-local `~/rdp-server/build` and owner macOS 27 live desktop
fast-user-switch/capture/cursor/input acceptance remain **NOT RUN** in this
connector environment. The roadmap blocker is unchanged: R7 still requires a
genuine non-forgeable macOS R2/R3 admission capability before exposing native
capture/input/cursor construction, and R4 still has no portable cursor-consumer
contract. M5 remains **OPEN/BLOCKED** on those dependencies.


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


## R4 full x264/BGRA ASan+UBSan gate (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared `main`:** `9d37c0da57553fadc105669cd65e5ae566cf9b03`.

The previous R4 exact-SHA matrix left one explicit validation hole: the shared
R9 sanitizer job passed its configured scope but did not build or execute
`test_x264_avc420_encoder` or
`test_x264_avc420_segmented_frame_producer`. Source/build review also found
that every C translation unit in this repository belongs to the pinned x264
library, while the sanitizer job configured only C++ sanitizer flags. Merely
adding the R4 executables would therefore exercise a sanitized wrapper around
an uninstrumented codec.

This increment closes that gap without changing production graphics behavior.
The existing sanitizer job now verifies both `clang` and `clang++`,
configures both C and C++ with ASan+UBSan/fail-on-UB flags, builds the two
existing R4 production-linked test executables, and runs the complete
`x264` CTest label as an independent `always() && compile-success` group.
The current label contains **18** cases and covers real instrumented x264 C,
the C++ encoder wrapper, BGRA-to-NV12 conversion, segmented AVC420/RDP8
publication, reference recovery, ACK/backpressure and fixed-CFR PTS behavior.
No x264 suppression is added.

No R3 DVC/channel authority, scheduler, capture owner, codec state or wire
format changes. Canonical owner `~/rdp-server/build` configure/build/full
CTest is **NOT RUN** in this connector environment. Exact-SHA hosted
Linux/Clang sanitizer execution plus the normal Linux/GCC, macOS/Clang and
Windows/MSVC Debug/Release matrix, documentation policy and SDK/package gates
are required after publication. Genuine authenticated R3 Graphics
DVC/full-send integration, owner Linux/X11, Windows MSYS2 CLANG64/Clang 23,
macOS 27, native capture performance and Microsoft-client rendering remain
**NOT RUN/BLOCKED**. Gate B and M3/M4/M5 remain **OPEN**.


## R4 sanitizer workflow shared-YAML repair (2026-10-16; exact-SHA CI pending)

R4 sanitizer implementation `27d472baee4eabf3593757c2a749e72d33595cd0`
triggered Actions `38905806962`, which failed with **0 jobs**. The same
zero-job failure is present on its parent `9d37c0da...` (Actions
`38905605037`) and preceding R10 syntax-fix `3b7a32e...` (Actions
`38905403688`), proving the failure predates the R4 sanitizer additions.

Inspection found duplicate top-level `documentation-policy` and
`publish-protocol-prerelease` keys plus a duplicated sanitizer tail left by
the earlier malformed R10 workflow edit. The R10 follow-up repaired its
truncated regex/header but did not remove that duplicated YAML, so GitHub
continued rejecting the workflow before job creation.

This correction reconstructs only `.github/workflows/ci.yml` from the last
known-good exact workflow at `695dd90b80cf105d7bdeb90576168801ffaf011b`,
then reapplies the intended additive R10 sanitizer target/group and R4's
additive Clang-C/x264 sanitizer target/group. The resulting workflow contains
one sanitizer job, one documentation-policy job and one prerelease job. No
production source, CTest registration, authorization or graphics behavior is
changed.

Canonical owner-local testing remains **NOT RUN**. The repaired exact SHA must
first prove GitHub creates jobs, then the R4 `x264` sanitizer label must run
all **18** cases with the vendored x264 C sources compiler-instrumented.
Normal three-OS Debug/Release, SDK/package and documentation gates remain
required. Genuine R3 Graphics DVC/full-send integration and Microsoft-client
rendering remain **BLOCKED/NOT RUN**; Gate B and M3/M4/M5 remain **OPEN**.


## R4 fully instrumented x264/BGRA sanitizer exact-SHA receipt (2026-10-16)

**Implementation/repair SHA:** `0abf1e5de12517817a70973be3740ac56ff1d522`.
**Actions:** `38906102171` — **SUCCESS**.

The first R4 sanitizer publication `27d472baee4eabf3593757c2a749e72d33595cd0`
correctly added Clang C instrumentation and the R4 test group, but inherited a
pre-existing malformed workflow: its run `38905806962` created **0 jobs**.
The repair rebuilt `.github/workflows/ci.yml` from the last known-good
workflow and reapplied only the intended R10 and R4 additive sanitizer changes.
GitHub then created and completed the full matrix successfully.

- **Clang ASan+UBSan R4 graphics gate:** **18/18 PASS**. Both
  `test_x264_avc420_encoder` and
  `test_x264_avc420_segmented_frame_producer` compile and execute with
  `clang++`; all vendored x264 C translation units compile with `clang`
  under the same address/undefined sanitizer flags. Leak detection,
  halt-on-error and fail-on-UB remain enabled with **no x264 suppression**.
  Coverage includes NV12 validation, Annex-B/crop/reference lifecycle,
  metadata and malformed-input preflight, duplicate-ID/backpressure recovery,
  abort/generation reset, fixed-CFR PTS, BGRA BT.709 conversion/scratch
  lifetime, and BGRA -> x264 -> AVC420 -> segmented RDP8 publication.
- **Linux/GCC:** Debug **407/407 PASS**, Release **407/407 PASS**; installed
  SDK consumer and package gates PASS.
- **macOS/Clang:** Debug **349/349 PASS**, Release **349/349 PASS**; installed
  SDK consumer and package gates PASS.
- **Windows/MSVC:** native preflight **39/39 PASS** in Debug and Release;
  full Debug **373/373 PASS**, Release **373/373 PASS**; SDK consumer/package
  gates PASS.
- The same sanitizer job also preserves all previously configured clipboard,
  bounded R1/R3, native R2/R3 GSSAPI, R10 runtime CredSSP, complete R5 X11 and
  bounded fuzzer groups; they all PASS. **Documentation policy PASS** and
  untagged prerelease publication is correctly **SKIPPED**.

This closes the roadmap's prior **NOT RUN** item for real R4 x264/BGRA
ASan+UBSan execution. No production graphics code, CTest semantics, channel
authority, scheduler, capture owner or wire format changed.

**Still NOT RUN/BLOCKED:** canonical owner `~/rdp-server/build` command on
Linux/X11, Windows MSYS2 CLANG64/Clang 23 and macOS 27; genuine authenticated
R3 `Microsoft::Windows::RDS::Graphics` DVC/full-send integration; native
capture performance; and Microsoft-client visible graphics acceptance.
There is still no R3 graphics authority to consume without fabricating a
second owner, so R4's next production integration gate remains that dependency.
Gate B and M3/M4/M5 remain **OPEN**.


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


## R5 XInput2 pointer observation integration (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared `main`:** `4da8d0deab5e3d7a251fdd4c180a6380c1e4e978`.

R5 now reuses the existing first-party `X11PointerPositionTracker` as an
optional geometry-bound child of the sole `X11DesktopResources` owner.
`xcb-xinput` is discovered only for Linux and builds the noninstalled
`rdp-server-linux-xinput-pointer` target when available; it is not added to
the portable protocol SDK. Missing XI2 build/runtime capability is reported by
the synchronous pointer capability API while XShm/XDamage/XFixes/XTEST remain
usable. A failed shared XCB transport still revokes the complete aggregate.

The existing bounded event route remains one XCB poll: cursor image tracker,
Damage tracker, XI2 pointer tracker when available, then the caller's optional
event sink. The pointer tracker now rejects short GenericEvent records before
accessing XI2 motion fields, filters the owned root, coalesces into one latest
clamped position, and provides idempotent cancellation that clears pending,
forwarded and local/remote echo authority state. Cancellation clears the root
motion mask only while the original borrowed connection remains valid and
never creates another connection/thread/event queue.

R4-facing reads expose capability, pending position, should-forward and
explicit acknowledgement without allocation. Querying never acknowledges.
A `forwarded=false` acknowledgement leaves the coordinate eligible for later
publication, while a successful local publication activates the existing
remote-XTEST echo fence. The existing concrete R2/R3-authorized
`X11AuthorizedInputRoute` remains the only native injection entrance:
same-position remote motion echoes are suppressed there and a distinct remote
move immediately regains authority. No RDP pointer PDU, DVC write, frame ACK,
listener or session-admission path is introduced.

RandR replacement now disconnects and reconstructs the XI2 tracker with the
other geometry-bound children, so old pending/echo state cannot cross a
desktop generation while the sole XCB descriptor remains unchanged. Dedicated
production-linked CTests are
`x11.pointer-xi2-motion-coalescing`,
`x11.pointer-xi2-remote-echo-suppression`,
`x11.pointer-xi2-disconnect-cancellation`,
`x11.pointer-xi2-malformed-event-bounds`,
`x11.desktop-resource-pointer-event-routing`,
`x11.desktop-resource-pointer-randr-rebuild`, and
`x11.desktop-resource-pointer-capability-denials`. The shared R9
ASan/UBSan selector is extended from 16 to 23 R5 X11 behaviors and hosted
Linux installs `libxcb-xinput-dev`.

**Validation status at authoring:** source/ownership/test registration review
PASS. The connector environment does not expose the mandatory
`~/rdp-server/build/` checkout and has no XInput2 development header, so the
canonical owner configure/build/full CTest and all new native executions are
**NOT RUN** locally. Last fully green hosted R5 baseline remains
`f220436f0da88e6b02f2bd58f1da164826929ac6`, Actions
`38900083125`, including R5 ASan/UBSan 16/16 and the documented full
Linux/macOS/Windows matrix. Exact implementation-SHA hosted CI is the next
gate. Owner Linux/X11, Windows MSYS2 CLANG64/Clang 23, macOS 27 and real
Microsoft-client desktop acceptance remain **NOT RUN**. R3 still owns real
RDP Input parsing/authorization and R4 still owns client cursor scheduling and
delivery. **M3 remains OPEN / NOT ACCEPTED.**


## R5 XInput2 pointer observation exact-SHA hosted validation (2026-10-16)

**Implementation:** `50b171d5fb0b818d1029153b953e4c374ba62caa`.
**Actions:** `38908798693`, overall **SUCCESS**.

The exact implementation SHA compiled the real optional
`rdp-server-linux-xinput-pointer` target against hosted
`libxcb-xinput-dev` and linked it into the sole
`rdp-server-linux-x11-desktop` aggregate. Ubuntu/GCC full CTest is
**423/423 PASS** in Debug and **423/423 PASS** in Release. All seven new
production-linked R5 behaviors passed in both configurations:
`x11.pointer-xi2-motion-coalescing`,
`x11.pointer-xi2-remote-echo-suppression`,
`x11.pointer-xi2-disconnect-cancellation`,
`x11.pointer-xi2-malformed-event-bounds`,
`x11.desktop-resource-pointer-capability-denials`,
`x11.desktop-resource-pointer-event-routing`, and
`x11.desktop-resource-pointer-randr-rebuild`.

The shared Clang ASan/UBSan job completed **SUCCESS** and the expanded R5
native X11 selection passed **23/23**, including each new XI2 tracker and
aggregate case. The same sanitizer job also passed the R10 Linux CredSSP
selection **4/4**; the previously tracked
`runtime.linux-connection-credssp-owner-framing` failure is therefore not
present on this SHA.

Cross-platform portability remained green: macOS/Clang full CTest
**357/357 PASS** in Debug and Release; Windows/MSVC full CTest
**381/381 PASS** in Debug and Release. Documentation policy, downstream
installed-SDK consumer **1/1**, package creation/digest/upload, the other
sanitizer groups and the bounded fuzzer all passed. The prerelease publisher
was correctly skipped because this was not a protocol release tag.

Canonical owner-local `~/rdp-server/build/` execution remains **NOT RUN**
in this connector environment. Owner Linux/X11, Windows MSYS2
CLANG64/Clang 23, macOS 27, real authenticated R3 Input/Graphics DVC
integration and Microsoft-client M3 desktop acceptance remain
**NOT RUN/OPEN**. R5 introduces no second XCB connection, listener, scheduler,
RDP pointer parser or client cursor publication owner. **M3 remains OPEN /
NOT ACCEPTED.**


### R5 remote-pointer clamp/echo correction (2026-10-16; exact-SHA CI pending)

Post-validation review found one bounded echo edge: XTEST clamps remote root
coordinates to both the current source geometry and its signed 16-bit native
coordinate range, while the XI2 tracker had retained the original untrusted
remote request for echo comparison. An out-of-range remote move could therefore
reappear as a different, clamped XI2 coordinate and be incorrectly eligible
for publication back to the client.

The existing tracker now normalizes remote authority through the same geometry
and int16 bounds before comparison/storage. The existing
`x11.pointer-xi2-remote-echo-suppression` production-linked CTest is
strengthened with a wide synthetic geometry to prove both same-authority
rejection and native-echo suppression at the actual injected coordinate. No
new queue, XTEST path, RDP parser or capability is added; the R5 sanitizer
selection remains **23** behavior-named cases. Exact correction-SHA hosted CI
is pending.


## R7 session-watch destructor retirement regression (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared `main`:** `973ad903e77206c8ab6592ccc56829f992783078`.

The process-scoped macOS session-change watch already retires native coverage
from its destructor, but the dedicated regression previously exercised only
explicit `stop()`. New offline CTest
`macos.desktop-session-watch-destructor-retirement` invokes the production
destructor path with the existing injected registration backend. Successful
destruction must remove the observer once, make coverage unavailable, keep a
queued scalar-epoch callback inert after the C++ owner is gone, and allow a
fresh replacement watch to register and retire normally.

The same subprocess then exercises the terminal ambiguous-retirement path:
observer removal fails during destruction, coverage remains unavailable, and
the process registration reservation remains held so a replacement registration
is denied. The case deliberately ends with that reservation held; callbacks
carry no watch-object pointer, so this is a fail-closed lifetime assertion
rather than a recoverable restart path.

Production source and native reachability are unchanged. Ordinary CTest still
installs no AppKit observer, requests no TCC permission, reads no live desktop
and performs no capture/input action. Source/registry/documentation review is
**PASS**. Canonical owner-local `~/rdp-server/build/` execution is **NOT RUN**
in this connector environment; exact-SHA hosted Linux/GCC, macOS/AppleClang,
Windows/MSVC, R9 sanitizer and documentation-policy results are **PENDING**
after publication.

The roadmap blocker is unchanged: R7 still requires a genuine non-forgeable
macOS R2/R3 admission capability before exposing native capture/input/cursor
construction, while R4 still owns any future cursor publication contract.
Owner macOS 27 live fast-user-switch delivery and Microsoft-client M5
acceptance remain **NOT RUN**. **M5 remains OPEN/BLOCKED**.


## R4 RDPGFX highest-supported capability regression (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared `main`:** `6a9bf3f67c09cdf1c10f4de252411579efe5eec8`.

The May 2026 MS-RDPEGFX revision changed server behavior around preventing
selection of unsupported graphics capability sets. R4's production parser is
already fail-closed for this rule: the only implemented profile is Version 8.1
with explicit AVC420, while newer/unknown capability sets are parsed only for
their bounded declared length and are never reflected into CAPS_CONFIRM.

A new dedicated production-linked CTest,
`graphics.avc420-capabilities-highest-supported-selection`, locks that
contract. It advertises the currently published Version 10.7 and an unknown
future capability before/after a valid Version 8.1 AVC420 set and requires the
exact Version 8.1 confirmation regardless of list order. Advertisements
containing only Version 10.7/unknown sets must return
`UnsupportedCapability` with zero confirmation bytes. Existing malformed,
header-bounds and generic selection cases remain unchanged.

No production parser change is needed, no higher graphics profile is claimed,
and no R3 DVC/channel authority is fabricated. Canonical owner
`~/rdp-server/build` configure/build/full CTest is **NOT RUN** in this
connector environment. Exact-SHA Linux/GCC, macOS/Clang, Windows/MSVC
Debug/Release, the existing sanitizer matrix, documentation policy and
SDK/package checks are required after publication. Genuine authenticated R3
Graphics DVC/full-send integration, owner three-OS commands, native capture
performance and Microsoft-client rendering remain **NOT RUN/BLOCKED**.
Gate B and M3/M4/M5 remain **OPEN**.

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



## R5 pointer echo-authority rollover correction (2026-10-16; CI pending)

Continuation review after the XI2 integration found a second bounded echo-state
edge. A newly accepted remote move changes the pointer position already known
to the peer, so the prior locally forwarded coordinate must no longer remain a
duplicate-publication sentinel. Conversely, once a later native position is
successfully published, any older remote-echo coordinate is stale and must not
suppress a genuine future native return to that coordinate.

The existing `x11.pointer-xi2-remote-echo-suppression` production-linked CTest
now proves both rollover directions. This remains one latest-position observer
under the sole XCB owner; it adds no timeout, queue, XTEST path, RDP parser,
scheduler, or client-publication owner. Exact-SHA hosted CI is pending.


## R4 RDPGFX highest-supported capability exact-SHA hosted receipt (2026-10-16)

**Implementation:** `27ba58477a0c730c32e2bd65d2c2f66deee8572c`.
**Actions:** `38910472878` — **SUCCESS**.

The production capability selector required no correction: it continues to
confirm only the Version 8.1 AVC420 capability set R4 actually implements,
regardless of newer advertised capability versions. New dedicated CTest
`graphics.avc420-capabilities-highest-supported-selection` proves a
published Version 10.7 set and an unknown future set cannot displace Version
8.1 when ordered before or after it, and that unsupported-only advertisements
produce no CAPS_CONFIRM.

- **Linux/GCC:** Debug **425/425 PASS**, Release **425/425 PASS**; the new
  capability case is test **#208** in both configurations. Installed SDK
  consumer/package gates PASS.
- **macOS/Clang:** Debug **359/359 PASS**, Release **359/359 PASS**; the new
  case is test **#194** in both configurations. SDK consumer/package gates
  PASS.
- **Windows/MSVC:** focused native preflight **39/39 PASS** in Debug and
  Release; full Debug **383/383 PASS**, Release **383/383 PASS**; the new case
  is test **#194** in both full suites. SDK consumer/package gates PASS.
- **Configured Clang ASan/UBSan groups:** **PASS**, including the existing
  fully instrumented R4 x264/BGRA group **18/18 PASS**. The new capability
  regression itself is not selected by that bounded sanitizer job, so this
  receipt does **not** claim direct sanitizer execution for the new case.
  **Documentation policy PASS**; untagged prerelease publication is correctly
  **SKIPPED**.

This is a standards-conformance regression only; no production parser, codec,
scheduler, channel authority or wire-format behavior changed. The owner-local
`~/rdp-server/build` command and owner Linux/X11, Windows MSYS2
CLANG64/Clang 23 and macOS 27 runs remain **NOT RUN** here. Genuine
authenticated R3 `Microsoft::Windows::RDS::Graphics` DVC/full-send
integration, native capture performance and Microsoft-client visible graphics
acceptance remain **BLOCKED/NOT RUN**. R4 must not fabricate a parallel channel
or authorization owner; Gate B and M3/M4/M5 remain **OPEN**.


## R7 session-watch destructor retirement exact-SHA hosted receipt (2026-10-16)

Implementation `6a9bf3f67c09cdf1c10f4de252411579efe5eec8`, Actions
`38910289341`, completed **SUCCESS**. The new production-backed
`macos.desktop-session-watch-destructor-retirement` CTest passed in both
Debug and Release on every hosted compiler: Linux/GCC full CTest is
**424/424 PASS** in each configuration, macOS/AppleClang is **358/358 PASS**
in each configuration, and Windows/MSVC is **382/382 PASS** in each
configuration. Windows focused native preflight is also **39/39 PASS** in
Debug and Release.

The regression proves successful destructor-driven observer retirement,
inert delayed scalar-epoch delivery after the C++ watch owner is gone,
replacement registration after clean retirement, and fail-closed process
reservation when removal is ambiguous during destruction. It installs no real
AppKit observer and performs no live desktop, TCC, capture or input operation.
The Apple job still compile/links the real AppKit session-watch implementation,
which remains SDK evidence rather than proof of real fast-user-switch delivery.

Documentation policy and the shared R9 sanitizer job both **PASS**. Installed
SDK consumers are **1/1 PASS** on Linux, macOS and Windows and package steps
complete; untagged prerelease publication is correctly **SKIPPED**.

Canonical owner-local `~/rdp-server/build/`, owner macOS 27 live
fast-user-switch notification delivery, genuine non-forgeable macOS R2/R3
admission, live capture/input/cursor publication and Microsoft-client M5
acceptance remain **NOT RUN/OPEN**. The R7 authority blocker is unchanged and
**M5 remains OPEN/BLOCKED**.

## R3 Server License Request receipt-fence exact-SHA validation (2026-10-16)

**Implementation:** `c80febfbb0a46327d637b541bb10abf96cf77837`. **Actions:** `38910597009` — **SUCCESS**.

The exact implementation SHA passed the complete hosted protocol matrix.
Ubuntu/GCC full CTest is **428/428 PASS Debug** and **428/428 PASS Release**;
macOS/Clang is **362/362 PASS Debug** and **362/362 PASS Release**;
Windows/MSVC is **386/386 PASS Debug** and **386/386 PASS Release**, with
the focused Windows native preflight **39/39 PASS** in both configurations.
The three new production-linked R3 cases
`transport.licensing-server-request-wire`,
`transport.licensing-server-request-write-receipts`, and
`transport.licensing-server-request-write-denials` each PASS in all six
Debug/Release platform runs.

The R9 Clang ASan/UBSan job is **PASS**: clipboard **46/46**, R4 x264/BGRA
**18/18**, bounded R1/R3 transport/security/licensing **30/30**, native
R2/R3 GSS **24/24**, R10 Linux CredSSP **4/4**, native R5 X11 **23/23**,
and bounded fuzzer **1/1**. Its current bounded R1/R3 regex still selects the
pre-existing licensing state/length/order cases but does **not** select the
three new Server License Request cases, so sanitizer-specific execution of
those three is **NOT RUN** and is not claimed.

Documentation policy **PASS**. Installed SDK downstream consumer **1/1 PASS**
and ZIP package creation/upload PASS on Linux, macOS, and Windows. No unrelated
hosted failure is present on this exact R3 implementation SHA.

Canonical owner-local `~/rdp-server/build/`, owner Linux/X11, Windows MSYS2
CLANG64/Clang 23, macOS 27, genuine positive Kerberos/logind admission, and
Microsoft-client licensing/Share/desktop acceptance remain **NOT RUN**.
Production R3 still deliberately stops at `AwaitServerLicenseRequest`
because no authoritative owner currently supplies CSPRNG server-random plus
product/scope provisioning. The serializer and receipt fence are ready, but
that missing provisioning/integration boundary prevents a standards-correct
live request from being emitted. **M2/M3 remain OPEN / NOT ACCEPTED.**

## R6 DXGI outer-owner callback reentry hardening (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared `main`:** `452a13f1e79acce64d12bda488f07564887cfc68`.

Audit of the production `WindowsDxgiDuplicationOwner` confirmed that its
release callback was invoked before the owner slot was cleared, so synchronous
`close()` reentry could observe and release the same COM reference again.
`open()` also had no operation guard: terminal close requested by factory,
enumeration, description, device, output-interface or duplication callbacks
could tear down partly constructed state before the callback returned, and a
nested `open()` could enter before factory publication.

The outer owner keeps the existing single-threaded ownership model and adds two
local state guards. `operationInProgress_` defers terminal teardown until the
active `open()` callback boundary returns; `teardownInProgress_` rejects
overlapping teardown from release-callback reentry. Owned slots are detached
with `std::exchange` before invoking external release callbacks. Every native
callback is followed by a terminal-cancellation check before the next native
operation. Temporary adapter/output enumeration references are released exactly
once, including failure-with-pointer results, while the selected-adapter alias
remains retained for owner teardown. Device-epoch allocation now saturates on
exhaustion instead of wrapping back to a usable generation.

Five production-linked behaviors are added to the existing Windows desktop
fixture and central registry:
`windows.capture-dxgi-duplication-owner-release-reentry`,
`windows.capture-dxgi-duplication-owner-open-cancel-reentry`,
`windows.capture-dxgi-duplication-owner-partial-result-cleanup`,
`windows.capture-dxgi-duplication-owner-ambiguous-reentry`, and
`windows.capture-dxgi-duplication-owner-child-close-order`. They cover
release reentry, cancellation at actual `open()` phases, nested-open denial,
failure callbacks that still assign owned references, same/different-adapter
ambiguity after retention, and child retirement before parent DXGI/D3D11
release.

Canonical owner-local `~/rdp-server/build/` configure/build/full CTest is
**NOT RUN** in this connector environment because the checkout is unavailable;
no alternate build root, branch or worktree was created. Exact-SHA hosted
Linux/GCC, macOS/Clang, Windows/MSVC Debug+Release, focused Windows native
preflight, R9 sanitizer, documentation-policy and SDK/package evidence is
**PENDING** after publication. Owner Windows MSYS2 CLANG64/Clang23, genuine
R2/R3 Windows admission, live DXGI/SendInput and Microsoft-client M4 acceptance
remain **NOT RUN/BLOCKED**. **M4 remains OPEN / NOT ACCEPTED.**



## R5 pointer echo-authority rollover exact-SHA hosted receipt (2026-10-16)

Implementation `3a5180ef5f3bcb387a2c6ee161aba2fa7a7e77d6`, Actions
`38910706437`, completed **SUCCESS**. Linux/GCC, macOS/Clang and
Windows/MSVC protocol jobs all completed successfully together with
documentation policy and installed-SDK/package gates. The shared Clang
ASan/UBSan R5 selection passed **23/23**, including
`x11.pointer-xi2-remote-echo-suppression`; the R10 CredSSP sanitizer group
also passed **4/4**. Untagged prerelease publication was correctly skipped.

This validates the remote/local echo-authority rollover correction under the
hosted matrix. Canonical owner `~/rdp-server/build`, owner Linux/X11,
Windows MSYS2 CLANG64/Clang23, macOS 27 and Microsoft-client M3 acceptance
remain **NOT RUN/OPEN**.

## R5 XI2 destructor retirement (2026-10-16; exact-SHA CI pending)

Lifecycle review found that `X11PointerPositionTracker` had an explicit
idempotent `disconnect()` but a default destructor. Destroying a live
standalone tracker while its borrowed XCB owner remained valid could therefore
leave the client's XI2 root-motion selection installed after the C++ observer
was gone.

The tracker destructor now calls the existing cancellation barrier. New
production-linked CTest `x11.pointer-xi2-destructor-retirement` queries the
real XI2 selected-event mask under ephemeral Xvfb, proves motion selection is
present while the tracker lives, proves scope exit removes it while the same
XCB connection remains healthy, and proves a replacement tracker can subscribe
and retire normally. No event loop, connection, RDP input path or scheduler is
added. The shared R5 ASan/UBSan selector expands from **23** to **24** cases.
Exact-SHA hosted CI is the next gate; canonical owner-platform tests remain
**NOT RUN**.

## R6 DXGI outer-owner callback reentry exact-SHA hosted validation (2026-10-16)

**Implementation:** `54c1685119aa84e01d864d9834c26ed643a13edb`.  
**Actions:** `38911492569`.

The exact implementation SHA is fully green across every hosted job. Windows/MSVC
focused native R6 preflight is **44/44 PASS Debug** and **44/44 PASS Release**.
All five new production-linked cases pass in both configurations:
`windows.capture-dxgi-duplication-owner-release-reentry`,
`windows.capture-dxgi-duplication-owner-open-cancel-reentry`,
`windows.capture-dxgi-duplication-owner-partial-result-cleanup`,
`windows.capture-dxgi-duplication-owner-ambiguous-reentry`, and
`windows.capture-dxgi-duplication-owner-child-close-order`. Full Windows CTest
is **391/391 PASS Debug** and **391/391 PASS Release**, with the same five cases
passing again in both full runs. The installed SDK consumer is **1/1 PASS** and
the remaining Windows package/digest/upload steps pass.

Linux/GCC full CTest is **429/429 PASS Debug** and **429/429 PASS Release**;
macOS/AppleClang full CTest is **362/362 PASS Debug** and **362/362 PASS
Release**. Each hosted platform's installed SDK consumer is **1/1 PASS**. R9
ASan/UBSan selections are all green: clipboard **46/46**, R4 x264/BGRA
**18/18**, bounded R1/R3 protocol **33/33**, native R2/R3 GSSAPI **25/25**,
R10 runtime CredSSP **4/4**, R5 X11 **23/23**, and bounded fuzzer **1/1**.
Documentation policy is **PASS**. The prerelease publication job is
intentionally **SKIPPED**, not a test failure.

The validated R6 contract is terminal and same-thread serialized: a callback
may request `close()`, but no later native construction call runs after that
callback returns; owner slots are detached before external release callbacks;
nested close cannot overlap teardown; partial callback results are released
once; selected-adapter alias semantics remain balanced; and the capture-cycle
child is retired before duplication/context/device references. A terminal owner
cannot publish a device epoch or reopen.

Canonical owner-local `~/rdp-server/build/` execution remains **NOT RUN** in
this connector environment. Owner Windows MSYS2 CLANG64/Clang23 validation is
**NOT RUN**. Live Desktop Duplication/SendInput, genuine Windows R2/R3
authorization and Microsoft-client M4 acceptance remain **NOT RUN/BLOCKED**.
**M4 remains OPEN / NOT ACCEPTED.**

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


## R5 XI2 destructor-retirement exact-SHA hosted receipt (2026-10-16)

Implementation `a158d9ce12504fc9efbdd7feb9ab31dabee3effb`, Actions
`38911816382`, completed **SUCCESS**. Ubuntu/GCC full CTest passed
**430/430** in Debug and **430/430** in Release; the new
`x11.pointer-xi2-destructor-retirement` case passed in both configurations.
The shared Clang ASan/UBSan R5 native-X11 selector expanded to **24/24 PASS**
and directly executed the new destructor-retirement case.

macOS/Clang full CTest passed **362/362** in Debug and **362/362** in Release.
Windows/MSVC native preflight passed **44/44** in Debug and Release, and full
CTest passed **391/391** in Debug and **391/391** in Release. Documentation
policy, installed-SDK consumer **1/1**, package/digest/upload gates, all other
sanitizer groups and the bounded fuzzer passed; untagged prerelease publication
was correctly skipped.

This validates that XI2 root-motion selection is retired by normal tracker
destruction while the borrowed XCB owner remains healthy, without adding a
second connection, event loop or input owner. Canonical owner
`~/rdp-server/build`, owner Linux/X11, Windows MSYS2 CLANG64/Clang23,
macOS 27, genuine positive Kerberos/logind/XTEST input and Microsoft-client M3
acceptance remain **NOT RUN/OPEN**. The roadmap's next functional R5 step
remains blocked on R3 exposing its authoritative real input-PDU translation
boundary.


## R7 partial session-watch install retirement regression (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared `main`:** `6b45368b57ec0213212f3e3f42ff9a1ec5ee3d10`.

The process-scoped session watch already treats a failed observer installation
as potentially partial, but the synthetic backend previously returned failure
before retaining any callback state. New offline CTest
`macos.desktop-session-watch-partial-install-retirement` exercises the actual
ambiguous branch: installation retains the scalar recorder/epoch, emits one
registration-time event, reports failure, and its first cleanup removal also
fails.

The production watch must then expose no coverage while remaining internally
registered, keep the sole process reservation held so a second watch receives
`AlreadyRegistered`, and ignore delayed delivery from the partially installed
epoch. After the backend allows removal, retrying `stop()` must retire the
ambiguous registration, release the reservation, permit a replacement watch,
and keep the old delayed callback inert against that replacement revision.

Production source and native reachability are unchanged. The fixture change
only models a native partial-install failure already assumed by
`NativeSessionChangeWatch::startWithCallbacks()`. Ordinary CTest installs no
AppKit observer, requests no TCC permission, and performs no live capture,
cursor sampling or Quartz input. The architecture note is also corrected so it
no longer describes the already-landed session watch as future work.

Source/registry/documentation review is **PASS**. Canonical owner-local
`~/rdp-server/build/` execution is **NOT RUN** in this connector environment;
exact-SHA hosted Linux/GCC, macOS/AppleClang, Windows/MSVC, sanitizer,
documentation-policy and SDK/package evidence are **PENDING** after
publication. Genuine non-forgeable macOS R2/R3 admission, owner macOS 27 live
fast-user-switch delivery and Microsoft-client M5 acceptance remain
**NOT RUN/OPEN**. **M5 remains OPEN/BLOCKED**.

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
