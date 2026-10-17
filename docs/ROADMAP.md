## Cross-platform owner-command checkout-path correction (2026-10-16; owner re-test pending)

The owner's first macOS execution of the mandated one-line command at
`bdcb68520c5339aa9866f2e7d5949cf6b5c9c056` is **CONFIGURE FAIL** before any
compile or CTest. The shell successfully entered `~/rdp-server`, while CMake
reported the same case-preserving checkout as
`/Users/keivanmoradi/RDP-server`; the local-path guard compared those strings
lexically and rejected the case-only alias.

The correction keeps both policy fences: local work must still resolve from
`~/rdp-server`, and the only build root is still `<checkout>/build`. Existing
filesystem paths are now resolved before comparison, with case-insensitive
spelling accepted on macOS/Windows only after the `~/rdp-server` candidate is
known to exist. Windows/MSYS2 additionally translates the shell `HOME` through
`cygpath -m` when available and also considers `USERPROFILE`; this avoids
assuming that MSYS2 `~` and the Windows profile directory are identical.

New CTest `project.local-checkout-path-comparison` locks exact,
case-insensitive and strict-case comparison behavior without creating another
build root. Hosted exact-SHA configure/build/full CTest and the owner's rerun of
the unchanged command are **PENDING**. Do not claim owner macOS or Windows
MSYS2 PASS until those reports arrive.

## R1 terminal TLS/EOF readiness exact-SHA validation (2026-10-16)

**Implementation:** \`9b8f6092e4a0265688ec3bbf51b10cd34db8746e\`.  
**Win32 fixture correction:** \`cd3b5173149f4c93fad5c04afdab3bce3b901937\`.  
**Corrected Actions:** \`39004697959\` — **SUCCESS**.

The implementation publication replaced scheduler-yield terminal-read retries
with a dedicated real-loopback behavior,
\`transport.tcp-owned-tls-terminal-readiness\`, while leaving production R1
socket/BIO/SSL code unchanged. Its first Actions run \`39004463035\` provided
partial evidence only: macOS/AppleClang passed the new case as test #164 in
both configurations and full suites were **446/446 PASS** Debug + Release.
Linux/GCC and R9 stopped before R1 execution on the concurrently inherited R8
X11 clipboard compile error (\`fileUri_\` / \`fileUriLength_\`), and
Windows/MSVC exposed the R1 test-only Win32 \`min\` macro collision at the
client-readiness helper. Those failed legs are not counted as R1 PASS.

Correction \`cd3b5173...\` replaces only the macro-sensitive \`std::min\`
expression with an equivalent explicit duration comparison. Exact corrected
hosted evidence:

- Linux/GCC full CTest: **528/528 PASS Debug** and **528/528 PASS Release**;
  the new test is #164 and passes in both.
- macOS/AppleClang: **447/447 PASS Debug** and **447/447 PASS Release**;
  the new test is #164 and passes in both.
- Windows/MSVC native preflight: **51/51 PASS Debug + Release**; full CTest:
  **477/477 PASS Debug** and **477/477 PASS Release**; the new test is #164
  and passes in both.
- R9 Clang ASan/UBSan bounded R1/R3 MCS/CredSSP/licensing selection:
  **91/91 PASS**; \`transport.tcp-owned-tls-terminal-readiness\` executes as
  item **76/91** and passes. The separately flattened CredSSP credential corpus
  is **4/4 PASS**.
- Other sanitizer groups also pass: clipboard **61/61**, portable graphics
  **34/34**, x264/BGRA **20/20**, RDPGFX capabilities **4/4**, native
  R2/R3 GSS **29/29**, R2 PAM verifier **1/1**, direct Linux runtime security
  **10/10**, native X11 **33/33**, and bounded fuzzer **1/1**.
- Documentation policy and the independent R7 sanitizer job pass. Installed
  SDK consumer **1/1**, package generation and artifact upload pass on all
  three hosted platforms; untagged prerelease publication is correctly
  **SKIPPED**.

The new behavior proves two terminal distinctions through real nonblocking
readiness: client \`close_notify\` becomes R1 \`TlsClosed\`, while raw peer EOF
becomes \`TransportClosed\`; both leave the sole R1 owner inactive with closed
I/O interest, and later raw-EOF read replay remains terminal. Client OpenSSL
WANT direction is waited with a bounded native readiness fixture and the
server advances only through \`OwnedPreauthTcpConnection::pollSocketOnce\`;
no scheduler sleep/yield or hidden SSL retry is used in the behavior.

Canonical owner-local \`~/rdp-server/build/\`, owner Linux/X11, Windows MSYS2
CLANG64/Clang 23 and macOS 27 remain **NOT RUN** in this connector
environment. This is transport-lifetime evidence only: no R2 admission,
licensing authority, live grant publication, Share activation or client
acceptance is implied.

**Next R1:** retain the existing dependency gate. Do not add another
transport/publication surface until R10 supplies a real CAL-issuing authority
and R2 exposes fresh authorization for live grant slices/completion, or a later
Share-activation boundary demonstrates a concrete bounded R1 transport
mismatch.

## R2 authenticated delegated-account binding boundary (2026-10-16)

R2 now has the next fail-closed final-CredSSP identity boundary. The canonical
password-credential parser can derive only one bounded 32-byte local UNIX
account candidate from `TSPasswordCreds.userName`; it still exports no password
or borrowed field view. The supported form requires an empty `domainName`.
Nonempty domains, `DOMAIN\\user`, realm suffixes, Unicode/confusable account
names, uppercase/case rewriting, `root`, overlength names and unsupported
credential types are denied rather than normalized.

`ConsoleIdentityPolicy::matchPrincipalAccountCandidate()` is a read-only
`CandidateOnly` query over the service-owned mapping. It requires the exact
provider-derived Kerberos principal, exact local account and the nonzero policy
generation captured when the per-connection GSS owner is configured. A changed
generation, missing rule, mismatch, service principal, or principal with
multiple configured local accounts denies. It performs no NSS/logind lookup and
cannot issue a native lease.

The live final-authInfo path now requires the original R1-owned HYBRID
connection, exact reader/writer, delivered server binding reply, pinned TLS
certificate, live GSS context/principal and unchanged bound policy generation
before it will unwrap credentials. Candidate extraction and policy matching
occur synchronously while provider plaintext is protected by
`SensitiveBytesGuard`; the plaintext is cleansed before provider-buffer
release. The candidate is not persisted. This increment remains terminal
deny-only: PAM is **not invoked**, the private final-credential completion latch
remains false, no `LinuxConsoleAdmissionLease` is issued and R3 is not opened.

Dedicated coverage is
`security.credssp-delegated-account-extraction`,
`security.credssp-delegated-domain-identity-denials`,
`security.console-policy-delegated-account-binding`,
`security.gssapi-credssp-delegated-account-origin-denials`, and
`security.credssp-delegated-account-sensitive-retirement`. Portable
credential/policy cases are included in bounded ASan/UBSan without the
MIT-krb5 LSan suppression; the origin case is in the native GSS selection.
Hosted exact-SHA validation for this publication is pending. Positive
Kerberos/PAM/NSS/logind/Microsoft-client acceptance and M2 remain
**BLOCKED / NOT RUN**.

## R9 final CredSSP adversarial-parser hosted convergence (2026-10-16)

**Validated shared integration SHA:** `bdcb68520c5339aa9866f2e7d5949cf6b5c9c056`.  
**Actions:** `39004774467` — **SUCCESS**.

The three new production-backed R9 CTests are centrally registered once and
execute through the existing `test_owned_credssp_tsrequest` binary:

- `security.credssp-password-credential-nested-der-mutations`
- `security.credssp-password-credential-length-boundary-denials`
- `security.credssp-password-credential-utf16-mutation-boundaries`

Linux/GCC Debug and Release are **528/528 PASS** in each configuration.
macOS/AppleClang Debug and Release run **447** tests each and both jobs pass.
Windows/MSVC Debug and Release run **477** tests each and both jobs pass.
Installed SDK consumer/package checks pass on all three hosted platforms.
The R9 Clang ASan/UBSan job passes; its fail-closed registry preflight finds
strict-fields plus all three new cases and the dedicated instrumented
credential selection is **4/4 PASS** with leak detection enabled and no GSS
leak suppression applied to parser tests.

The bounded corpora remain test-only: a 59-byte canonical password seed with
236 bytewise mutations plus 8 structured cases; a 40-vector DER/length corpus
including 9 outer and 9 nested malformed encodings and the valid 8191-byte
maximum; and a 96-vector UTF-16LE matrix with an independent test-only Unicode
oracle. Repeated parsing is deterministic and input bytes remain unchanged.
A structure-preserving payload mutation may still parse successfully only when
the independent payload oracle accepts it.

Historical failures remain part of the evidence trail. At
`d82e9836b5457f43293ca46bc3c712c0565e1188`, workflow `39004093895`
failed the R9 combined sanitizer selection before execution because CMake
reported `Too many parentheses` and `Total Tests: 0`; R9 corrected that by
keeping the existing cross-road selection intact and adding a flat dedicated
credential selector. At `da9d3e21c4c684d553e20a4d2594f2911cdabe00`,
workflow `39004533589` had the R9 sanitizer, Linux and macOS jobs green but
failed Windows `Compile Debug` in the R1 readiness fixture because Win32's
`min` macro expanded `std::min`; R1 corrected that in
`cd3b5173149f4c93fad5c04afdab3bce3b901937`. The final convergence workflow
is green and R9 was not implicated in that R1 compile failure.

These tests establish bounded structural parsing and memory-safety evidence;
they do **not** establish successful password verification or native admission.
Existing GSS/native-admission denial tests remain the authentication boundary.
Owner same-SHA Linux/X11, Windows MSYS2 CLANG64/Clang 23, macOS 27, genuine
Kerberos/PAM/NSS/logind positive authorization, Microsoft-client end-to-end
HYBRID admission and M1-M6 external acceptance remain **NOT RUN / BLOCKED** as
applicable.

## R7 cursor GUI-session revocation exact-SHA validation (2026-10-16)

**Implementation:** `1d4f154bd548b11dcf95ac671ecdd3e4d5a5d288`.  
**Implementation Actions:** `39004615992`.  
**Validated clean descendant:** `cd3b5173149f4c93fad5c04afdab3bce3b901937`.  
**Validation Actions:** `39004697959` — **SUCCESS**.

The implementation SHA's dedicated R7 GCC ASan/UBSan job passed all 10
`macos.desktop-session-*` cases, the exact input session-watch case **1/1**,
and the new `macos.cursor-session-watch-revocation` case **1/1**. Its
macOS Debug run also passed all five cursor cases, including the new case, but
the overall implementation workflow was not accepted because an immediately
preceding R1 test failed `transport.tcp-native-accept-batch-budget-handoff` on
macOS and hit a Win32 `min` macro compile error on Windows. Those failures were
outside R7; R1 corrected the test-only portability issue in the next descendant.

At clean descendant `cd3b5173...`, whose only intervening change is R1 test
code/docs, the unchanged R7 implementation passes the complete hosted matrix:
macOS/AppleClang **447/447 Debug** and **447/447 Release**; Linux/GCC
**528/528 Debug** and **528/528 Release**; Windows/MSVC native preflight
**51/51 Debug + Release** and full **477/477 Debug + Release**. The cursor
session-watch case passes in every applicable full suite (#375 macOS, #432
Linux, #421 Windows). The dedicated R7 GCC ASan/UBSan job again passes
**10/10 + 1/1 input + 1/1 cursor**. The broader R9 Clang ASan/UBSan job,
documentation policy, installed SDK consumer, package, digest and artifact
stages all pass. Untagged prerelease publication is skipped as intended.

This validates only synthetic production-backed revocation semantics and Apple
compile/link of the quarantined native sampler. Canonical owner-local
`~/rdp-server/build/`, owner Linux/X11, Windows MSYS2 CLANG64/Clang 23 and
macOS 27 remain **NOT RUN** here. Genuine macOS 27 fast-user-switch delivery,
TCC/native cursor/capture/input and Microsoft-client M5 remain **NOT RUN**.
The next authority-bearing R7 gate remains **BLOCKED** on a genuine
non-forgeable R2/R3 macOS desktop admission capability; no watch revision,
geometry fact or synthetic test callback is admission. **M5 remains OPEN / NOT
ACCEPTED.**

## R8 bounded multi-file X11 handoff exact-SHA validation (2026-10-16)

**Implementation/fix:** `013b834eaab7b863d1257d8e4730677260746581` +
`7318bb23fbcde4f9051f08eec06ff8c6b9a218ba`.
**Actions:** [39004494523](https://github.com/k1moradi/RDP-server/actions/runs/39004494523).

The first implementation run exposed one R8-owned Linux compile error from a
stale single-file cleanup field in `disconnect()`; the follow-up fix reuses
the canonical `clearFileHandoff()` path. At the fixed SHA, Linux/GCC full
CTest is **527/527 PASS** in Debug and **527/527 PASS** in Release. The new
`clipboard.x11-completed-multi-file-uri-handoff` case passes in both. The
installed SDK consumer is **1/1 PASS**, and Linux package/artifact steps pass.

R9 Clang ASan/UBSan completes successfully. The complete clipboard-labelled
selection is **61/61 PASS**, including the new multi-file case. Its additional
selected groups are also green: portable RDPGFX **34/34**, x264/BGRA **20/20**,
RDPGFX capabilities **4/4**, bounded R1/R3 transport/security **91/91**,
runtime security **4/4**, native GSS/R2/R3 **29/29**, direct runtime-security
**10/10**, native X11 **33/33**, and bounded fuzzer **1/1**.

macOS/AppleClang full CTest is **446/446 PASS** in Debug and Release with its
downstream consumer/package gates green. The Linux-only X11 multi-file target
is not registered there. Windows focused native preflight is **51/51 PASS**,
but full Windows Debug compilation stops in unrelated R1
`tests/test_owned_preauth_session.cpp:1541` with MSVC C2589 before ordinary
full CTest; Windows Release/package are therefore **NOT RUN** in this workflow.
No R8 source appears in that failing diagnostic. A descendant R1 commit later
addresses that Windows fixture boundary; it is not an R8 ownership change.
Documentation policy and the independent R7 macOS sanitizer job pass.

Accordingly, the R8 multi-file X11 boundary has exact-SHA Linux Debug/Release
and ASan/UBSan evidence, plus unaffected macOS regression evidence. The overall
workflow conclusion is **FAIL** solely because of the unrelated R1 Windows
compile blocker; do not reinterpret that as Windows or real-client acceptance
for this Linux-only increment.

Canonical owner-local `~/rdp-server/build`, owner Linux/X11, Windows
MSYS2 CLANG64/Clang23, macOS27, live Nautilus/Dolphin/Wayland portal use,
authenticated Microsoft-client file copy, remote directory-tree mapping and
performance remain **NOT RUN/OPEN**.

**Next R8:** define a bounded explicit directory-tree mapping/capability
contract that never constructs local paths from untrusted remote names, then
extend completed-set handoff to Windows/macOS and real-client acceptance.

## R1 terminal-readiness Win32 macro correction (2026-10-16; exact-SHA CI pending)

**Implementation:** \`9b8f6092e4a0265688ec3bbf51b10cd34db8746e\`.  
**Implementation Actions:** \`39004463035\`.  
**Correction base:** \`1d4f154bd548b11dcf95ac671ecdd3e4d5a5d288\`.

The new \`transport.tcp-owned-tls-terminal-readiness\` behavior compiled and
passed on macOS/AppleClang as test #164 in both Debug and Release
(**446/446 PASS** each). The implementation-SHA Linux and R9 jobs stopped
before R1 execution on the inherited R8 X11 clipboard compile error
(\`fileUri_\` / \`fileUriLength_\` after the multi-file member replacement);
R8 corrected that independently in \`7318bb23fbcde4f9051f08eec06ff8c6b9a218ba\`.

Windows/MSVC exposed an R1 test-only portability bug: the new bounded
client-readiness helper used \`std::min(remaining, maximumWait)\`, but a Win32
\`min\` macro had already been introduced before this translation unit's later
\`NOMINMAX\` guard, producing C2589 at the helper call. The correction replaces
that expression with an explicit duration comparison/ternary. It changes no
deadline, readiness direction, socket behavior, production source or R1
ownership contract.

The corrected descendant must pass the new CTest on Linux/GCC,
macOS/AppleClang and Windows/MSVC Debug/Release and under the bounded R9
R1/R3 sanitizer selection before this increment is accepted. Canonical
owner-local \`~/rdp-server/build/\` and owner-platform evidence remain
**NOT RUN**.

## R7 cursor GUI-session revocation fence (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared main:** `00b0aa8a3c58fd6866a3574f85e7d85c74ad9cd5`.

R7's capture and input consumers already pin the process-scoped
`NativeSessionChangeWatch` revision, but the quarantined cursor snapshot
boundary still used only display generation/topology. A fast-user switch can
leave display geometry unchanged, so an old owned cursor shape could otherwise
remain structurally valid across GUI-session replacement.

This increment makes the watch revision part of `MacCursorSnapshot` identity.
The native private sampler pins active coverage before its first cursor read;
`makeMacCursorSnapshot` requires that caller-pinned revision and revalidates it
before publication. Existing snapshots fail `valid()` and expose an empty
`pixels()` span after a later session event. A revision is revocation state
only: the AppKit sampler stays translation-unit-private and no R2/R3 admission,
R4 scheduler/protocol publication, TCC prompt, event tap or input capability is
created.

Dedicated portable CTest `macos.cursor-session-watch-revocation` keeps geometry
and topology unchanged, constructs an owned shape, injects a switch-away/back,
proves the old shape becomes unreadable and rejects reconstruction with the old
revision. The road-local GCC ASan/UBSan job now builds the existing cursor test
executable and selects this exact case in addition to guard/input coverage.
Ordinary tests install only synthetic callbacks and never read AppKit cursor
state.

Canonical owner-local `~/rdp-server/build/` execution is **NOT RUN** in this
connector environment; no alternate persistent build root is created.
Exact-publication-SHA hosted Debug/Release, R7 sanitizer, documentation-policy
and SDK/package evidence are **PENDING**. The next authority-bearing R7 gate is
unchanged and remains **BLOCKED** on genuine non-forgeable R2/R3 macOS desktop
admission, followed by owner macOS 27 fast-user-switch/TCC/native testing and
Microsoft-client M5 acceptance. **M5 remains OPEN / NOT ACCEPTED.**

## R5 XI2 stale-motion generation fence exact-SHA hosted validation (2026-10-16)

**Implementation:** `366303f35156cdd00c125dfa976d72bc23016bb3`.  
**Optional-build guard correction / validated SHA:** `2cdb16e42e1b642fcfb02c0a34f581b53e202598`.  
**Actions:** `39004283125` — workflow overall **FAIL** only because the
separate bounded R1/R3 MCS/CredSSP/licensing sanitizer selector is rejected by
CTest with `RegularExpression::compile(): Too many parentheses`. The later R5
native-X11 sanitizer step executes independently and is fully green.

Exact validated evidence:
- **Linux/GCC:** **525/525 PASS** in Debug and **525/525 PASS** in Release.
  `x11.desktop-resource-pointer-randr-stale-motion-isolation` is test #471
  and passes in **0.04 s** in both configurations. Installed SDK consumer
  **1/1 PASS**, package generation, digest and artifact upload pass.
- **macOS/AppleClang:** **445/445 PASS** in Debug and **445/445 PASS** in
  Release. Installed SDK consumer **1/1 PASS**, package/digest/upload pass.
  Native X11 execution is intentionally absent on this host.
- **Windows/MSVC:** focused native preflight **51/51 PASS** in Debug and
  **51/51 PASS** in Release; full CTest **475/475 PASS** in Debug and
  **475/475 PASS** in Release. Installed SDK consumer **1/1 PASS** and
  package/digest/upload pass. Native X11 execution is intentionally absent.
- **R9 Clang ASan/UBSan native X11:** the fail-closed selector discovers
  exactly **33** R5 behaviors and completes **33/33 PASS**. The new stale-motion
  case is selected as **32/33** (central test #471) and passes in **0.04 s**.
  No ASan/UBSan finding is reported in the R5 selection.
- **Documentation policy:** PASS. The independent R7 sanitizer job also passes.
  Untagged prerelease publication is skipped as intended.

The validated native sequence is one-XCB-owner only. A helper completes a real
Xvfb RandR resize from **1280x720 to 1024x600** and then warps the root pointer
before the production aggregate consumes the queued transition. R5 rebuilds its
geometry-bound children on the same XCB connection, consumes only the new
tracker's synchronous `QueryPointer` snapshot, rejects the queued pre-generation
XI2 motion using the `XISelectEvents` request-sequence floor, then accepts a
fresh post-rebuild motion normally.

The optional-build correction is also part of the validated SHA: the new
aggregate behavior is compiled only when `RDP_TEST_XINPUT_POINTER` is present,
matching its registration and preserving supported Linux builds where optional
`xcb-xinput` development support is unavailable.

Canonical owner-local `~/rdp-server/build/` testing remains **NOT RUN** in
this connector environment; no alternate persistent build root was created.
Owner Linux/X11, Windows MSYS2 CLANG64/Clang 23 and macOS 27 M1 evidence,
genuine R2/R3-admitted XTEST operation and Microsoft-client M3 acceptance remain
**NOT RUN / OPEN**. Current source still exposes no R3 authenticated,
already-decoded bounded Share/Input or Fast-Path Input handoff, so functional
R5 input translation remains **BLOCKED ON R3**; R5 does not add a competing
RDP parser, authorization token, session owner or scheduler.

## R9 CredSSP adversarial-corpus oracle refinement (2026-10-16; exact-SHA CI pending)

The three production-backed credential tests now carry explicit bounded corpus
oracles rather than relying on production acceptance as their own expectation.
The canonical password seed is exactly 59 bytes; its nested-DER test performs
236 bytewise complement/insertion/removal/truncation cases plus 8 explicit
structured field/tag/trailing cases. Any successful one-byte mutation must lie
inside one of the known unchanged-length text payloads and independently pass
the small test-only UTF-16LE oracle.

The length test contains exactly 40 parsed vectors: the required small and DER
transition sizes, 4094..4097 field boundaries, 9 malformed outer length
encodings, 9 malformed nested length encodings (including nonminimal,
leading-zero, indefinite, truncated/excessive length-of-length, unavailable
declared length, and inflation/deflation), the largest representable valid
8191-byte credential, an exactly-8192-byte trailing-data denial, and an
8193-byte over-limit denial. The near-cap fixture is found by a bounded
descending scan and never allocates from hostile declared lengths.

The Unicode test contains exactly 96 vectors across domain, username and
password and beginning/middle/end positions. A separate test-only oracle checks
BMP characters, valid surrogate pairs, malformed high/low ordering, embedded
NUL, pair truncation, odd byte counts and permitted/forbidden empty fields.
This remains structural evidence only; existing
`security.gssapi-credssp-authinfo-terminal-denials`,
`security.gssapi-native-os-admission-capability-denials`, and
`runtime.linux-connection-aggregate-premature-admission-denial` retain the
independent no-native-admission boundary. Exact hosted and sanitizer evidence
for this refinement is **PENDING**.

## R8 multi-file X11 disconnect compile repair (2026-10-16; exact-SHA CI pending)

Implementation `013b834eaab7b863d1257d8e4730677260746581` reached hosted CI
Actions `39004341947`. Linux/GCC Debug failed during
`rdp-server-linux-x11-clipboard` compilation because the final
`disconnect()` cleanup still named the pre-multi-file fields
`fileUri_`/`fileUriLength_`. The production multi-file state itself had
already replaced those fields with the canonical list owner. macOS compiled
successfully because the X11 target is Linux-only.

This follow-up removes the stale duplicate cleanup and reuses
`clearFileHandoff()`, which already clears the canonical URI list, file count,
generation and file-offered state. No protocol, ownership, native-format or
test semantics change. The original exact-SHA run is **FAIL** for Linux compile
and cannot validate this R8 increment; descendant exact-SHA hosted CI is
required.

## R1 owned-TLS terminal close readiness hardening (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared \`main\`:** \`c1112051ed5a81db34bdfc4cf8193e9bc114cdb5\`.

R1's real loopback application-I/O cancellation coverage still had two
scheduler-\`yield()\` retry loops after TLS establishment: one while producing
a client \`close_notify\`, and one while waiting for the server to observe
clean TLS closure/raw TCP EOF. That timing pattern is unnecessary now that R1
has the bounded one-step socket poller used by the rest of the owned-TLS
readiness fixtures.

New dedicated CTest
\`transport.tcp-owned-tls-terminal-readiness\` stays in the existing
\`test_owned_preauth_session\` executable. It uses a short-lived ephemeral
loopback TCP connection and real OpenSSL TLS. The client side waits only for
the exact WANT_READ/WANT_WRITE direction through a bounded native \`select\`
fixture with a five-second monotonic deadline. The server side advances only
through \`OwnedPreauthTcpConnection::pollSocketOnce\` and explicitly resubmits
the same caller-owned read span. Clean \`close_notify\` must produce
\`TlsClosed\`; raw peer close must produce \`TransportClosed\`; both must leave
R1 inactive with \`Closed\` I/O interest, and raw EOF replay remains terminal.

The existing \`transport.tcp-owned-tls-application-cancellation\` behavior now
retains the independent deadline-cancellation and malformed-record
\`FatalTlsFailure\` cases. No production socket/BIO/SSL code, application-I/O
bound, retry policy, authorization state, licensing lifecycle or listener
surface changes. The bounded R9 R1/R3 sanitizer selector explicitly requires
the new test.

Canonical owner-local \`~/rdp-server/build/\` configure/build/full CTest is
**NOT RUN** in this connector environment; no alternate persistent build root
or branch is created. Exact publication-SHA Linux/GCC, macOS/AppleClang,
Windows/MSVC Debug/Release, R9 sanitizer, documentation-policy and SDK/package
evidence are **PENDING**. Owner Linux/X11, Windows MSYS2 CLANG64/Clang 23,
macOS 27 and real-client acceptance remain **NOT RUN**.

**Next R1:** this closes test-harness nondeterminism only. Do not add another
transport/publication surface until R10 supplies a real CAL-issuing authority
and R2 exposes fresh live grant authorization, or a later Share-activation
boundary demonstrates a concrete bounded R1 transport mismatch.

## R9 CredSSP sanitizer selector split (2026-10-16; exact-SHA CI pending)

The first adversarial credential-corpus sanitizer publication exposed a CI
selection limit rather than a parser defect: the pre-existing combined
R1/R3/licensing CTest regular expression exceeded CMake's regex parenthesis
budget after R9 added three nested alternatives. The job failed closed with
`RegularExpression::compile(): Too many parentheses` and `Total Tests: 0`.
Ordinary hosted Linux/macOS builds for the corrected test source were green,
so this incident is test-registration/execution infrastructure, owned by R9.

The existing cross-road selector is restored to its prior R2 strict-fields
shape. The same ASan/UBSan step now uses a second flat
`^security\.credssp-password-credential-` selector, performs an explicit
`ctest -N` registry preflight for strict-fields plus all three new R9 cases,
and executes that bounded group with leak detection enabled and no GSS leak
suppression. No R1/R3/R4/R5/R8/R10 selection is removed. Exact correction-SHA
hosted validation is **PENDING**; owner-local and real-provider/client gates
remain **NOT RUN**.

## R8 bounded multi-file X11 handoff (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared main:** `2cdb16e42e1b642fcfb02c0a34f581b53e202598`. The existing R8 Linux
descriptor materializer and completed-file X11 URI handoff remain the native
building blocks. This increment extends only the completed presentation set:
up to the existing 64 remote-file bound may be published atomically after each
caller-selected destination independently reaches `Complete`.

`X11ClipboardAdapter::publishCompletedFiles` accepts a span of completed
`LinuxClipboardFileDestination` proofs. Every member must be non-null,
complete, from the exact current synchronized `RemoteTransfer` generation,
and expose a caller-bound strict local `file:///` URI. Duplicate URIs are
rejected. The adapter copies only bounded URI metadata into one fixed
allocation-free canonical LF-separated buffer; it never copies file bodies,
opens paths or derives a local path from FILEDESCRIPTORW.

The aggregate canonical URI metadata is capped below 64 KiB so the derived
`text/uri-list` payload (CRLF after every URI) remains within one direct X11
property write. GNOME/Nautilus receives `copy\n<uri1>\n<uri2>...` without a
trailing empty URI; KDE's copy marker remains `0`. The existing single-file
API delegates to the multi-file path. Once one completed set owns X11 for a
generation, changing that set behind the same ownership transition is refused;
a new remote generation or genuine local owner transition is required.

Dedicated CTest:
`clipboard.x11-completed-multi-file-uri-handoff`. It materializes two real
build-root files sequentially through the production `RemoteTransfer`
FileContents owner, proves a partially completed set is not publishable,
rejects duplicate destination URIs, validates exact URI-list/GNOME/KDE
payloads, rejects same-generation set mutation, and rejects the stale set after
generation replacement. Ordinary CTest uses the injected XCB seam and never
touches a live user's clipboard or file manager. R9 sanitizer selection now
enumerates this case before running the complete clipboard label.

This advances bounded **multi-file** handoff only. The current portable
FILEDESCRIPTORW parser intentionally retains safe leaf names and rejects path
separators, so it does not preserve authoritative remote tree hierarchy.
Directory-tree reconstruction therefore remains **BLOCKED** until R8 has an
explicit bounded hierarchy/mapping contract that cannot synthesize local paths
from untrusted remote names. Live Nautilus/Dolphin paste, Wayland portal
FileTransfer, authenticated Microsoft-client file copy, owner Linux/X11 and
performance remain **NOT RUN/OPEN**.

Canonical owner-local `~/rdp-server/build` configure/build/full CTest is
**NOT RUN** in this connector environment; no alternate build root was
created. Exact-publication-SHA hosted Linux/GCC, R9 ASan/UBSan, full
cross-platform regression and documentation-policy evidence are **PENDING**.

**Next R8 after hosted validation:** define the bounded explicit directory-tree
mapping/capability contract (caller-selected local destinations, no remote-name
path construction), then extend completed-set handoff across Windows/macOS and
real-client acceptance.

## R5 XI2 optional-build guard correction (2026-10-16; exact-SHA CI pending)

**Correction parent:** `366303f35156cdd00c125dfa976d72bc23016bb3`.

Immediate diff review found the new aggregate stale-motion function was placed
just after the existing `RDP_TEST_XINPUT_POINTER` block even though its
dispatcher and CTest registration were correctly conditional on the optional
XInput2 target. Hosted Linux installs XInput2 and would not expose that omission,
but a supported Linux build with the desktop aggregate and no `xcb-xinput`
development package could compile the test executable without
`RDP_TEST_XINPUT_POINTER` and still see pointer-only helper references.

The correction only wraps
`syntheticXvfbPointerRandrStaleMotionIsolation()` in the same compile-time
feature guard as the existing pointer event/RandR behaviors. Production XI2
generation-fence semantics, CTest registration, sanitizer selection and test
assertions are unchanged. Exact correction-SHA hosted validation is **PENDING**.

## R5 XI2 stale-motion generation isolation (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared `main`:** `deabb822e2f795a2b2cde37979246beb7e876334`.

Current R3 source still exports no authenticated already-decoded Share/Input or
Fast-Path Input event handoff, so functional R5 translation remains blocked and
this increment stays inside the existing native owner. The prior XDamage RandR
regression established that queued native events need explicit generation
provenance. Source review found the geometry-bound XI2 pointer tracker had the
same class of gap: after RandR rebuild it matched queued motion only by XGE
extension opcode, XI2 motion type and root window.

`X11PointerPositionTracker` now records the request sequence of its successful
checked `XISelectEvents` subscription. Its event matcher rejects XCB
`full_sequence` values older than that generation floor using bounded 32-bit
serial arithmetic; disconnect clears the floor with the rest of the borrowed
native identity. The constructor's synchronous `QueryPointer` snapshot remains
a current-state observation and is intentionally not treated as a queued event.

New production-backed CTest
`x11.desktop-resource-pointer-randr-stale-motion-isolation` remains in the
existing `test_x11_desktop_resources` executable and uses the same one
production XCB connection. An independent helper completes the real Xvfb resize
from 1280x720 to 1024x600, then warps the root pointer before the aggregate
consumes RandR. After the transactional rebuild, the test consumes only the
replacement tracker's synchronous pointer snapshot, drains the queued old XI2
motion without allowing a pending coordinate to reappear, then requires a fresh
post-rebuild warp to publish normally. The existing pointer tracker synthetic
fixtures now stamp their injected XGE records with a synchronized current XCB
request sequence so they continue exercising the production generation check.

The shared R9 Clang ASan/UBSan R5 selector and exact-name preflight include the
new case, expanding the expected native-X11 selection from **32** to **33**
behaviors. No second XCB owner, event loop, RDP parser, scheduler or authority
surface is added.

Canonical owner-local `~/rdp-server/build/` configure/build/CTest is **NOT
RUN** in this connector environment; no alternate persistent build root is
created. Exact publication-SHA Linux/GCC, macOS/AppleClang, Windows/MSVC,
R9 sanitizer, documentation-policy and SDK/package evidence are **PENDING**.
Owner Linux/X11, Windows MSYS2 CLANG64/Clang 23, macOS 27, genuine admitted
XTEST operation and Microsoft-client M3 acceptance remain **NOT RUN / OPEN**.
Functional R5 input integration remains **BLOCKED ON R3**.

## R10 licensing provisioning hosted validation (2026-10-16)

**Implementation:** `35cfda594f45c15e14966579f05cadb4bc5db8f1`.  
**Windows portability correction:** `4ec2b8c5ece830e28427c8501b98ff943465372b`.  
**Validated unchanged descendant:** `a9a656e9c5dc93b8316a6ae1298d658ff4ffcba6`.  
**Actions:** `38978665476` — **SUCCESS**.

The administrator-facing R10 licensing preflight is now hosted-validated on
the corrected source. Comparison from the Windows correction through the
validated descendant shows no change to `src/server/runtime/main.cpp`,
`runtime_licensing_context.*`, `tests/check_runtime_entrypoint.cmake` or
`tests/check_runtime_licensing_context.cmake`. The six centrally registered
process CTests execute the production `rdp-server` binary and all pass:

- `runtime.licensing-cli-valid-provisioning`
- `runtime.licensing-cli-incomplete-configuration`
- `runtime.licensing-cli-invalid-product-identity`
- `runtime.licensing-cli-credential-file-denials`
- `runtime.licensing-cli-existing-check-compatibility`
- `runtime.licensing-cli-service-still-disabled`

Linux/GCC is **521/521 PASS Debug + 521/521 PASS Release**; the six R10 CLI
cases are tests **332-337**. macOS/AppleClang is **442/442 PASS Debug +
442/442 PASS Release**; the six cases are tests **280-285**. Windows/MSVC
focused native preflight is **51/51 PASS Debug + 51/51 PASS Release** and full
CTest is **472/472 PASS Debug + 472/472 PASS Release**; the six cases are again
tests **280-285**, proving the `std::numeric_limits<uint32_t>::max` Win32-macro
correction.

The Clang ASan/UBSan bounded licensing/security selection is **90/90 PASS**.
It actually runs five R10 process cases instrumented:
valid provisioning, incomplete configuration, invalid product identity,
credential-file denials and service-still-disabled. The legacy-check
compatibility case remains covered by all six ordinary hosted Debug/Release
suites and is not claimed as sanitizer-executed. Documentation policy, the
independent R7 sanitizer, downstream installed-SDK consumers and package
artifact gates pass on the validated descendant.

This validates only explicit bounded provisioning and non-listening startup
preflight. It does not create a CAL, licensing authority, R2 lease, listener,
authenticated user, live R3 grant publication, Share activation or
Microsoft-client acceptance. Canonical owner-local `~/rdp-server/build/` and
owner Linux/X11, Windows MSYS2 CLANG64/Clang 23 and macOS 27 remain
**NOT RUN**, so M1 remains open.

**Next R10:** do not treat an administrator-provided opaque CAL or the existing
`RdpLicensingAuthorityGrant` snapshot as authority. The next functional
boundary is a concrete service-owned CAL-issuing authority whose nonzero
generation/fingerprint are freshly revalidated with each issuance result; only
then can R2/R3 consider live receipt-bound New License publication. M2 remains
**BLOCKED / NOT ACCEPTED**.

## R9 final CredSSP structural-corpus validation (2026-10-16)

Three new behavior-named tests use `test_owned_credssp_tsrequest` and real R2 `inspectCredSspCredentials`: `security.credssp-password-credential-nested-der-mutations`, `security.credssp-password-credential-length-boundary-denials`, and `security.credssp-password-credential-utf16-mutation-boundaries`. The bounded deterministic corpus covers every one-byte complement, insertion, removal and truncation of a domain/user/password seed; duplicate/missing/reordered nested context fields; malformed length headers and 0x81/0x82 boundaries; field sizes through 4096; near-total-8192 rejection; and BMP, surrogate, NUL, odd-length and empty-field cases at multiple code-unit positions. Structural success is not R2 authentication, PAM success or native lease issuance. The R9 CI selection includes all three tests and fail-closed registry checks; actual instrumented results must be confirmed from the exact publication workflow. Owner Linux/X11, Windows CLANG64, macOS 27 and real-client acceptance remain NOT RUN here.

## R2 Linux PAM verifier exact-SHA validation (2026-10-16)

**Validated implementation/integration SHA:** `d2a1ac10ac3c5ecd64b7d34b3777e2121119f678`.  
**Actions:** `38978066830` — **SUCCESS**.

The real Linux-PAM verifier groundwork is validated without enabling admission.
Linux/GCC Debug + Release are **521/521 PASS** and the PAM denial case is
test **#319** in both. macOS/AppleClang is **442/442 PASS** Debug + Release
without PAM. Windows/MSVC native preflight is **51/51 PASS** Debug + Release
and full suites are **472/472 PASS** Debug + Release. R9 Clang ASan/UBSan
compiles the production PAM target and executes the exact PAM denial selection
**1/1 PASS**; native GSS/R2/R3 is **29/29**, direct Linux runtime security
**10/10**, native X11 **32/32**, and the fuzzer **1/1**, all PASS.
Documentation policy, R7 sanitizer, SDK consumers and packaging pass.

This closes only the standalone real-provider verifier boundary. Final
CredSSP remains terminal deny-only and the private completion latch remains
false. The next R2 work is authenticated extraction of the confidential
`TSPasswordCreds` username plus exact immutable
Kerberos-principal-to-local-account policy matching before PAM invocation.
Positive Kerberos/PAM/NSS/logind admission and M2 remain **BLOCKED / NOT RUN**.
Owner-local `~/rdp-server/build/` remains **NOT RUN** in this connector.

## R5 RandR stale-damage generation fence exact-SHA hosted validation (2026-10-16)

**Production correction:** `741015795132a623033fabfff624a2a4794088e1`.  
**Actions:** `38977250042` — workflow overall **FAIL** only because the
concurrently expanded R1/R3 licensing sanitizer selector is rejected by CTest
before execution with `RegularExpression::compile(): Too many parentheses`.
The R5 sanitizer step runs later in the same job and is independently green.

The first test-only publication
`c1d5296dcd2b1cc50126188970a6cb4a50658898` correctly exposed the missing
generation fence: Ubuntu/GCC Debug ran **518** tests with **517/518 PASS** and
only `x11.desktop-resource-randr-stale-damage-isolation` failed because the
replacement damage tracker observed a queued notification before any deliberate
post-rebuild draw. The correction records the successful initial
`XDamageSubtract` request sequence and rejects older XCB `full_sequence`
notifications with bounded 32-bit serial arithmetic.

Exact correction-SHA evidence:
- **Linux/GCC:** **520/520 PASS** in Debug and **520/520 PASS** in Release.
  `x11.desktop-resource-randr-stale-damage-isolation` passes in both modes as
  test #462. Installed SDK consumer **1/1 PASS**, ZIP package, digest and
  artifact upload pass.
- **macOS/AppleClang:** **442/442 PASS** in Debug and **442/442 PASS** in
  Release. Installed SDK consumer **1/1 PASS**, package/digest/upload pass.
  Native X11 execution is intentionally absent on this host.
- **Windows/MSVC:** native preflight **51/51 PASS** in both configurations;
  full CTest **472/472 PASS** in Debug and **472/472 PASS** in Release.
  Installed SDK consumer **1/1 PASS**, package/digest/upload pass. Native X11
  execution is intentionally absent on this host.
- **R9 Clang ASan/UBSan native X11:** the fail-closed selector discovers
  exactly **32** R5 cases and completes **32/32 PASS**. The new stale-damage
  case is **27/32 PASS** in 0.04 s; pixel parity, RandR capture generation,
  terminal capture denial and XShm lifetime cases remain green.
- **Documentation policy:** PASS. The independent R7 sanitizer side job also
  passes. Untagged prerelease publication is skipped as intended.

The new native oracle uses the existing independently checked helper XCB drawing
path and the deterministic `kFirstPixelPattern`/`kSecondPixelPattern`.
It resizes real Xvfb geometry from **1280x720 to 1024x600**, retains the same
production XCB connection identity, drains the pre-rebuild Damage event without
publishing replacement-generation damage, captures the already-drawn first
pattern through the rebuilt XShm child, then requires a fresh real XDamage
observation and exact little-endian B/G/R bytes for the second pattern. Packed
row stride remains four bytes per captured pixel; the padding lane is not used
as alpha. No borrowed framebuffer span crosses capture, rebuild or disconnect.

Canonical owner-local `~/rdp-server/build/` testing remains **NOT RUN** in
this connector environment; no alternate persistent build root was created.
Owner Linux/X11, Windows MSYS2 CLANG64/Clang 23 and macOS 27 evidence required
for M1 remains outstanding. No live Microsoft-client desktop, M2/M3 acceptance
or R4 graphics delivery is claimed. Functional R5 input integration remains
**BLOCKED ON R3** until R3 exports its authenticated already-decoded bounded
Share/Input or Fast-Path Input event contract; R5 continues to consume only its
existing typed native input boundary and does not add protocol authority.

## R2 Linux PAM password-verifier boundary (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared main:** `5b5f349f96195c42eaf0e67ab5445d9887d0b195`.

R2 adds a real Linux-PAM password-verifier component without wiring it to the private final-CredSSP completion latch or native admission. `LinuxPamPasswordVerifier` is Linux-only, noninstalled and enabled only by `RDP_SERVER_TEST_LINUX_PAM=ON`, which requires the existing Linux GSSAPI test mode. There is no fake verifier, caller-supplied success Boolean or public lease path.

The verifier uses explicit one-shot PAM service configuration, bounded policy-compatible local account input, bounded UTF-16LE password validation, allocation-free UTF-8 conversion into a cleansed stack buffer, a single-password PAM conversation, real `pam_authenticate`, and real `pam_acct_mgmt`. Username prompts and extra secret prompts fail closed. Dedicated CTest `security.linux-pam-password-verifier-denials` uses no credential fixture and calls the real host PAM stack only with a deliberately nonexistent synthetic account; only Denied or ProviderFailure are accepted.

Hosted Linux and R9 install `libpam0g-dev`, enable the PAM gate, build the production verifier and execute the exact CTest. `ownedCredSspCredentialAuthorizationComplete_` remains false and final authInfo remains terminal deny-only. The next R2 step is authenticated in-provider extraction of `TSPasswordCreds.userName` and exact match to the immutable Kerberos-principal→local-account policy mapping before PAM can participate in any positive path. Real positive Kerberos/PAM/NSS/logind authorization and M2 remain **BLOCKED / NOT RUN**.

Canonical owner-local `~/rdp-server/build/` testing is **NOT RUN** in this connector environment. Exact-SHA hosted platform/sanitizer/docs/package evidence is **PENDING**.

## R5 RandR stale-damage sequence-fence correction (2026-10-16; exact-SHA CI pending)

**Correction parent:** `83d05e8076982545e57b75b78f5f5b212ddde865`.  
**First test publication:** `c1d5296dcd2b1cc50126188970a6cb4a50658898`.  
**First Actions:** `38976824134`.

The new `x11.desktop-resource-randr-stale-damage-isolation` case exposed the
intended generation boundary instead of passing immediately. Ubuntu/GCC Debug
built the real X11 target and ran **518** CTests; **517/518 passed**. The sole
failure was the new R5 case at
`tests/test_x11_desktop_resources.cpp:878`: after the aggregate had published
the resized generation and before any deliberate post-rebuild drawing,
`damageNotificationCount()` was already nonzero. The adjacent existing
pixel-parity, RandR capture-generation, capture-terminal-denial and other X11
cases passed. This is executable evidence that resource/event identity alone
does not provide the generation fence the event-budget contract requires.

The smallest R5 production correction stays inside the existing
`X11DamageTracker`. Successful construction records the request sequence of
the initial checked `XDamageSubtract`, which is the point after earlier
server-side damage is intentionally cleared. `handles()` now rejects a queued
Damage event whose XCB `full_sequence` predates that generation floor using
bounded 32-bit serial arithmetic before checking the native Damage XID. Normal
post-initialization events remain eligible; disconnect clears the floor with the
rest of the borrowed native state.

No second XCB owner, event loop, RDP parser, scheduler or authorization surface
is added. The already-registered dedicated CTest and R9 exact-name sanitizer
preflight remain unchanged. Canonical owner-local `~/rdp-server/build/`
execution is still **NOT RUN** in this connector environment; no alternate
persistent build root was created. Exact correction-SHA Linux/GCC
Debug+Release, macOS/AppleClang Debug+Release, Windows/MSVC Debug+Release, R9
ASan/UBSan native X11, documentation policy and SDK/package validation are
**PENDING**. Functional R5 input translation remains **BLOCKED ON R3** pending
R3's authenticated already-decoded Share/Input or Fast-Path Input event
contract.

## R10 Windows licensing-preflight portability correction (2026-10-16; exact-SHA CI pending)

R10 implementation `35cfda594f45c15e14966579f05cadb4bc5db8f1` reached
Actions `38976348381`. Linux/GCC passed **515/515 Debug + 515/515 Release**
and installed SDK consumer **1/1**; macOS/AppleClang passed **438/438 Debug +
438/438 Release** and consumer **1/1**. Documentation policy and the independent
R7 sanitizer passed. Windows/MSVC failed Debug compilation before CTest because
`windows.h` expanded the function-like `max` macro in the bounded
product-version parser.

This correction changes no licensing/configuration semantics: the parser caches
the same `uint32_t` limit via macro-safe
`(std::numeric_limits<std::uint32_t>::max)()`. Existing six licensing CLI
CTests remain the behavior gate. Owner-local `~/rdp-server/build/` remains
**NOT RUN** here. Exact-correction-SHA hosted platform, R9 sanitizer, docs and
SDK/package validation are **PENDING**.

## R5 RandR stale-damage generation isolation (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared `main`:** `fd1b6a687718f3887c3169a2b4b0bcda129d2d40`.

The requested XShm pixel-parity, RandR capture-generation and terminal-capture
denial boundaries are already present and have later descendant sanitizer
evidence, so this increment does not duplicate them. Current-source review
instead found one narrower unproved event-budget invariant: the existing RandR
helper says events queued behind a geometry transition are offered only to the
replacement geometry-bound trackers, but no CTest deliberately queued an old
XDamage notification behind that transition.

New production-backed CTest
`x11.desktop-resource-randr-stale-damage-isolation` stays in the existing
`test_x11_desktop_resources` dispatcher. On an ephemeral 1280x720x24 Xvfb
server, an independent helper XCB client completes a real resize to 1024x600
and then performs checked deterministic drawing before the production aggregate
processes the queued RandR event. The aggregate must stop at the transition,
transactionally rebuild on the same XCB connection, then drain the queued
old-generation Damage event without incrementing or publishing damage from the
replacement tracker. The already-drawn BGRX pixels remain capturable through
the rebuilt XShm child; a second distinct post-rebuild drawing must produce a
fresh real XDamage observation and exact B/G/R capture.

This is test-only because the existing production stop/rebuild ordering already
implements the intended contract. No R2 admission, R3 protocol/input parsing,
R4 scheduler, second XCB owner or native event loop is added. The shared R9
Clang ASan/UBSan native-X11 selector and fail-closed registry preflight now
include the new behavior, expanding the expected R5 selection from **31** to
**32** cases.

Canonical owner-local `~/rdp-server/build/` configure/build/CTest is
**NOT RUN** in this connector environment because the synchronized owner
checkout is unavailable; no alternate persistent build root was created.
Exact-publication-SHA Linux/GCC Debug+Release, macOS/AppleClang Debug+Release,
Windows/MSVC Debug+Release, R9 sanitizer, documentation-policy and SDK/package
evidence are **PENDING**. Owner Linux/X11, Windows MSYS2 CLANG64/Clang 23,
macOS 27 and Microsoft-client M3 acceptance remain **NOT RUN / OPEN**. The
next functional R5 input translation remains **BLOCKED ON R3** until R3
exports its authoritative authenticated already-decoded bounded Share/Input or
Fast-Path Input event contract.

## R8 Windows completed-file Explorer handoff exact-SHA hosted validation (2026-10-16)

**Implementation:** `74b5fb33484e961479a652204d35864ecfc77fd8`.
**Actions:** [38975977794](https://github.com/k1moradi/RDP-server/actions/runs/38975977794) — **SUCCESS**.

The exact implementation SHA is green across the complete hosted matrix. Ubuntu/GCC full CTest is **507/507 PASS** in Debug and Release. macOS/AppleClang full CTest is **430/430 PASS** in Debug and Release. Windows/MSVC focused native preflight is **51/51 PASS** in Debug and Release, and full CTest is **460/460 PASS** in Debug and Release. The dedicated `clipboard.windows-completed-file-hdrop-handoff` case passes on all hosted operating systems.

R9 Clang ASan/UBSan is **PASS**. Its complete clipboard-labelled selection is **60/60 PASS**, including the new CF_HDROP handoff. The same sanitizer job passes its additional selected groups at **33/33**, **20/20**, **4/4**, **80/80**, **29/29**, **10/10**, **31/31**, plus bounded fuzzer **1/1**. Documentation policy, R7 macOS session sanitizers, downstream installed-SDK consumer, package/digest and artifact steps all pass.

This evidence validates the bounded completed-file Windows presentation contract and native Win32 compile/link coverage. It does **not** claim live Explorer paste, owner Windows MSYS2 CLANG64/Clang23, authenticated Microsoft-client file copy, directory-tree materialization or performance. Canonical owner-local `~/rdp-server/build` remains **NOT RUN** in this connector environment.

**Next R8:** bounded multi-file/directory-tree materialization and handoff without whole-tree prefetch or path derivation from remote metadata, then real-client file-copy acceptance.



## R1 owned-TLS licensing cancellation and stale-receipt fence (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared main:** \`2e9b5775077a28593dc6d717c6daecbc3db3141c\`.

The newer R1 bounded-readiness fixture increment
\`0a376216a88733082926c49b3932f70d80af2133\` now has meaningful exact-SHA
hosted evidence in Actions run \`38975448171\`: Linux/GCC **503/503 Debug +
503/503 Release PASS**, macOS/AppleClang **426/426 Debug + 426/426 Release
PASS**, Windows/MSVC **456/456 Debug + 456/456 Release PASS**, and the bounded
R1/R3 Clang ASan/UBSan selection **77/77 PASS**. Both
\`transport.tcp-owned-tls-application-partial-write\` and
\`transport.tcp-owned-r3-connect-response-slice\` executed in every hosted
Debug/Release suite and as selected sanitizer tests. This supersedes the
earlier zero-job workflow as R1 validation evidence.

R1 now adds two production-backed cross-road cancellation regressions without
changing production transport or licensing code:
\`transport.tcp-owned-r3-license-request-cancel-replay\` and
\`transport.tcp-owned-r3-platform-challenge-cancel-replay\`. Both use the real
ephemeral loopback \`OwnedPreauthTcpConnection\`, OpenSSL TLS and the existing
R3 receipt gates. The License Request case proves cancellation before any write
and after a real positive forced-fragment TLS write: only the accepted prefix
advances the R3 suffix receipt, R1 becomes terminal, explicit R3 gate
retirement closes licensing without delivery, and both current and older
receipts are rejected. It does not claim already accepted TLS bytes were
retracted. The Platform Challenge case deterministically cancels before the
94-byte packet is written, proves R1 closure alone cannot mutate R3, then
explicitly retires the R3 gate and rejects stale completion/requeue.

The existing WANT path remains bounded and direction-exact: the License Request
case preserves the current span/receipt across zero-byte WANT and polls only
R1's recorded interest before retry. The already validated application-I/O,
License Request, Platform Challenge and cancellation tests provide the
complementary short-packet/WANT/read coverage; no scheduler sleep, hidden retry,
second TLS reader, transport-to-R3 coordinator or duplicate lifecycle is added.
The optional truncated-inbound fixture is not duplicated in this increment
because R1 exposes plaintext byte progress only and has no frame-forwarding
owner; incomplete-frame assembly remains the existing caller/R3 boundary.

R3's validated \`RdpLicensingAuthorityGrant\` snapshot and R10's administrator
licensing provisioning preflight remain offline/non-live authority boundaries.
They create no receipt-bound New/Upgrade publication, so they do not justify a
new R1 transport surface. R1's 18 KiB application-I/O ceiling and sole
socket/BIO/SSL ownership remain unchanged.

Canonical owner-local \`~/rdp-server/build/\` execution is **NOT RUN** in this
connector environment because the synchronized checkout is unavailable; no
alternate persistent build root, branch or patch artifact is created. Exact
publication-SHA hosted platform, sanitizer, documentation-policy and
SDK/package evidence for the two new cases is pending. M1 owner-platform
same-SHA evidence remains **NOT RUN** and M2/M3 remain **OPEN / NOT ACCEPTED**.


## R4 client decode-backlog observation exact-SHA hosted receipt (2026-10-16)

**Implementation:** `35833ba667a110ec859e04958d2a4ef269616012`.  
**Actions:** `38976220846` — **SUCCESS**.

The sole R4 presentation owner now exposes the already-owned
FRAME_ACKNOWLEDGE backlog facts without creating a throttle policy:
`expectingFrameAcknowledgements()`, `clientQueueDepthAvailable()` and
`clientQueueDepthBytes()`. Positive finite `queueDepth` values remain client
buffered-byte counts; zero remains explicitly unavailable, and suspension
clears the count and ACK expectation.

Dedicated production-backed
`graphics.frame-ack-backpressure-observation` passed in every normal hosted
configuration and under the portable R4 sanitizer gate:
- **Linux/GCC:** Debug **509/509 PASS**, Release **509/509 PASS**; new case
  **#270** in both.
- **macOS/Clang:** Debug **432/432 PASS**, Release **432/432 PASS**; new case
  **#255** in both.
- **Windows/MSVC:** focused native preflight **51/51 PASS** in Debug and
  Release; full Debug **462/462 PASS**, Release **462/462 PASS**; new case
  **#255** in both.
- **Clang ASan+UBSan portable R4 RDPGFX:** **34/34 PASS**; the new case is
  selected and passes as item **14/34**. Existing R4 x264/BGRA remains
  **20/20 PASS** and RDPGFX capability negotiation remains **4/4 PASS**.
- Documentation policy, independent R7 sanitizer, installed-SDK consumer,
  package/digest/upload and all remaining configured sanitizer/fuzzer groups
  PASS; untagged prerelease publication is correctly SKIPPED.

This closes the observation-boundary increment only. No frame-rate threshold,
timer, additional queue, second scheduler, DVC router or authorization path is
introduced. Canonical owner-local `~/rdp-server/build` validation and owner
Linux/X11, Windows MSYS2 CLANG64/Clang 23 and macOS 27 commands remain
**NOT RUN** in this connector environment. Genuine authenticated R3
`Microsoft::Windows::RDS::Graphics` DVC admission/full-send, native capture
performance and Microsoft-client visible graphics acceptance remain
**BLOCKED/NOT RUN**. Gate B and M3/M4/M5 remain **OPEN**.

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



## R1 owned-TLS licensing cancellation exact validation (2026-10-16)

**Implementation:** \`597b2871a64096f419844aefa4a6004a9e2c2e65\`.  
**Implementation Actions:** \`38976677537\` — R1-relevant Linux/macOS/R9 **PASS**; Windows blocked by an unrelated R10 compile failure.  
**Clean Windows descendant:** \`4ec2b8c5ece830e28427c8501b98ff943465372b\`.  
**Descendant Actions:** \`38976909719\` — Windows/MSVC **PASS**.

The two new R1/R3 cancellation regressions are centrally registered exactly
once and execute real production \`OwnedPreauthTcpConnection\` TLS plus the
existing R3 receipt gates:

- \`transport.tcp-owned-r3-license-request-cancel-replay\`
- \`transport.tcp-owned-r3-platform-challenge-cancel-replay\`

At the implementation SHA, Linux/GCC passed **517/517 Debug + 517/517
Release** and macOS/AppleClang passed **440/440 Debug + 440/440 Release**.
Both new cases passed in both configurations. The bounded R9 Clang ASan/UBSan
licensing/security selection passed **88/88**, with the License Request
cancellation case executing as selected test 69/88 and the Platform Challenge
case as 71/88. Documentation policy and the independent R7 sanitizer job also
passed. The successful Linux/macOS jobs completed their downstream SDK
consumer/package gates.

The implementation-SHA Windows job compiled the updated
\`test_owned_preauth_session\` target, then failed before full CTest execution
in concurrently added R10 \`src/server/runtime/main.cpp\`: Win32's \`max\`
macro expanded a \`std::numeric_limits<std::uint32_t>::max()\` expression
(C2589/C2059). R10 corrected that boundary in
\`4ec2b8c5ece830e28427c8501b98ff943465372b\`. R1's test source is unchanged
between those SHAs. On that clean descendant Windows/MSVC passed native
preflight **51/51 Debug + 51/51 Release** and full CTest **470/470 Debug +
470/470 Release**; both R1 cancellation cases passed in both configurations
and the installed SDK consumer passed 1/1. The descendant's later Linux
failure is separately attributable to the newly added R5
\`x11.desktop-resource-randr-stale-damage-isolation\` regression and does not
replace the implementation-SHA Linux evidence.

The License Request regression proves two distinct terminal paths. Cancellation
before the first application write leaves R3 at \`NotStarted\` until the caller
explicitly closes its gate. The positive-partial path forces a 1024-byte TLS
fragment ceiling and requires one actual R1 progress result in the range
**1..1024 bytes**, strictly smaller than the pending request; that exact
returned byte count alone is reported to R3. R3 rotates only the slice receipt
and preserves the exact remaining suffix. Subsequent R1 cancellation makes
future writes \`TransportClosed\`; explicit gate retirement moves licensing to
\`Closed\`, clears the pending publication and rejects both the current and
older receipts. Previously accepted TLS bytes are not claimed to have been
retracted.

The short Server Platform Challenge is cancelled deterministically before
delivery. R1 teardown alone leaves R3 at \`AwaitServerDecision /
PlatformChallengeRequired\`; explicit challenge-gate retirement then closes the
lifecycle, clears the challenge, rejects stale completion and denies requeue.
Duplicate R1/R3 cancellation is harmless. The cancellation fixture does not
force a short-packet WANT; direction-exact WANT and stable caller-owned retry
semantics remain covered by the already exact-SHA validated owned-TLS
application, License Request and Platform Challenge readiness cases. No
scheduler sleep, hidden retry, second TLS owner/reader or R1-to-R3 coordinator
was introduced.

Canonical owner-local \`~/rdp-server/build/\` execution remains **NOT RUN** in
this connector environment. Same-integration-SHA owner Linux/X11, Windows
MSYS2 CLANG64/Clang 23 and macOS 27 evidence remains **NOT RUN**, so M1 is not
accepted. Genuine R2 final credential authorization, a concrete R10
CAL-issuing authority, R2-authorized live grant publication and Share
activation remain open, so M2/M3 remain **OPEN / NOT ACCEPTED**.



**Current shared-main descendant validation:** \`a9a656e9c5dc93b8316a6ae1298d658ff4ffcba6\`,
Actions \`38978665476\` — **SUCCESS**. No R1 transport source changed between
the implementation SHA and this descendant; the intervening transport-source
changes are confined to R3 licensing. Linux/GCC full CTest is **521/521 PASS**
in both Debug and Release, macOS/AppleClang is **442/442 PASS** in both, and
Windows/MSVC is **472/472 PASS** in both with the focused native preflight
**51/51 PASS** in both configurations. The R1 cancellation cases remain tests
#159 and #161 and pass in all six full hosted runs. The bounded R9
Clang ASan/UBSan R1/R3 licensing selection is **90/90 PASS**; it explicitly
runs the License Request cancellation case as item 71/90 and the Platform
Challenge cancellation case as item 73/90. Documentation policy, R7
session-watch sanitizers, installed SDK consumers, package generation and
artifact upload also pass; the untagged prerelease remains correctly skipped.

This newer evidence does not unblock another R1 implementation. R2's validated
PAM component is still a denial-only subordinate verifier and cannot mint final
CredSSP/native admission. R3's validated License Grant receipt gate remains
detached from the live MCS session and has no R2 publication API, while R10
still has no real CAL-issuing authority owner. Per the existing Next R1 gate,
adding another transport writer, direct SSL path, detached grant-through-TLS
fixture or second coordinator now would duplicate already-bounded ownership
without proving the required live authorization boundary.

**Next R1:** do not enlarge or duplicate the transport for R3's new
\`RdpServerLicenseGrantWriteGate\` yet. Its complete New License packet is
already bounded below R1's 18 KiB application-I/O ceiling, and the gate is
explicitly not embedded in the live MCS session or exposed through R2. Once
R10 supplies the real authority owner and R2 exposes fresh authorization for
the live grant slices/completion, verify that final publication through the
sole R1-owned TLS writer. Otherwise wait for the first live Share-activation
boundary that demonstrates a concrete bounded transport mismatch.

## R3 bounded licensing sanitizer selector correction (2026-10-16)

The corrected grant-gate source descendant `f41d2a4b41362bbaf7bd5d6e030ea917dabe2796`
compiled and passed ordinary Debug coverage on Linux and macOS, but R9's
bounded R1/R3 licensing step did not execute: CTest rejected its selector with
`RegularExpression::compile(): Too many parentheses`. This was a selector
construction failure, not an ASan/UBSan finding and not a production/test
binary failure.

This correction flattens only the newly added
`license-grant-(...|write-receipts|write-denials)` alternatives, removing one
nested regex group while preserving the exact selected test names and existing
explicit registration greps. Production code, CTest registration, authority
correlation, grant bytes and receipt behavior are unchanged. Exact-SHA
sanitizer and full hosted validation remain required before acceptance.

## R3 authority-correlated New License receipt-gate hosted validation (2026-10-16)

**Implementation:** `525e235e1cc86ae978cf910020511bfcba4f4338`.  
**Compile-order correction:** `83d05e8076982545e57b75b78f5f5b212ddde865`.  
**Sanitizer-selector correction:** `dd9ebf76bb1087a25733f74744d155a1f903d1b8`.  
**Validated descendant:** `d2a1ac10ac3c5ecd64b7d34b3777e2121119f678`.  
**Actions:** `38978066830` — **SUCCESS**.

The validated descendant contains the R3 grant-gate production source unchanged
from the implementation/fix chain plus the flattened bounded sanitizer
selector. Linux/GCC full CTest is **521/521 PASS Debug** and **521/521 PASS
Release**. macOS/AppleClang is **442/442 PASS Debug** and **442/442 PASS
Release**. Windows/MSVC focused native preflight is **51/51 PASS** in both
configurations and full CTest is **472/472 PASS Debug** plus **472/472 PASS
Release**. Both new cases,
`transport.licensing-server-license-grant-write-receipts` and
`transport.licensing-server-license-grant-write-denials`, pass in all six
full hosted configurations.

R9 Clang ASan/UBSan is **PASS**. Its bounded R1/R3 licensing selection is
**90/90 PASS** and explicitly enumerates/runs both new grant receipt cases
(**PASS**). Other configured groups also pass: clipboard **60/60**, portable
graphics **34/34**, x264/BGRA **20/20**, RDPGFX capabilities **4/4**, native
R2/R3 GSS **29/29**, R2 PAM verifier **1/1**, direct Linux runtime security
**10/10**, native X11 **32/32**, and bounded fuzzer **1/1**. The separate R7
macOS session-watch ASan/UBSan job also **PASS**.

Documentation policy, installed SDK downstream consumer, package generation,
digest/artifact upload on Linux/macOS/Windows all **PASS**. Untagged protocol
prerelease publication is correctly **SKIPPED**.

The validated behavior remains deliberately detached from live R2/session
publication. A configured `RdpLicensingAuthorityGrant` is correlation data,
not CAL authority. The gate requires the exact authority generation/fingerprint,
the cryptographically reached `NewLicenseIssuanceRequired` branch, immutable
product identity and derived licensing keys; it preserves stable bytes through
backpressure/partial writes and moves only the detached licensing lifecycle to
`Licensed` after exact full accepted-byte delivery. Upgrade publication and
the CLIENT_LICENSE_INFO valid-client path remain unavailable.

Canonical owner-local `~/rdp-server/build/`, owner Linux/X11, Windows MSYS2
CLANG64/Clang 23, macOS 27, genuine Kerberos/logind positive admission, a real
CAL-issuing licensing authority, Microsoft-client New License acceptance,
Share activation and desktop acceptance remain **NOT RUN / OPEN**.

**Next R3:** do not expose this gate through the live session until R10 supplies
a concrete licensing-authority owner whose current generation/fingerprint can
be freshly revalidated and R2 can authorize every slice/completion. In
parallel, implement CLIENT_LICENSE_INFO CAL trust/signature,
product/version/expiration and HWID validation before any
STATUS_VALID_CLIENT path. **M2/M3 remain OPEN / NOT ACCEPTED.**



## R4 client decoded-frame observation (2026-10-16; exact-SHA CI pending)

**Starting reconciled shared `main`:** `bdcb68520c5339aa9866f2e7d5949cf6b5c9c056`.

MS-RDPEGFX FRAME_ACKNOWLEDGE carries both the already-retained client
`queueDepth` and `totalFramesDecoded`, a uint32 count of frames decoded
since connection initiation. R4 previously parsed the latter and discarded it.
The existing generation-bound `GfxFrameAckWindow` now retains the **raw latest
valid** decoded-frame count and exposes it through the sole
`GfxPresentationLifecycle`. A separate availability bit distinguishes a
legitimate reported zero from "no valid ACK observed yet".

Malformed and stale-generation PDUs cannot mutate the observation.
Valid unmatched ACKs do update it because they remain valid client telemetry.
ACK suspension preserves the count reported in the suspension PDU while ACK
expectation becomes false; channel reset/disconnect clears value and
availability. No monotonicity rule, wrap arithmetic, decoded-rate calculation,
timer, throttle threshold, queue, second scheduler or DVC authority is added.

New production-backed CTests are
`graphics.frame-ack-decode-progress` and
`graphics.frame-ack-decode-progress-observation`. The portable R4
Clang ASan/UBSan selector is extended with fail-closed registry preflight for
both cases.

Canonical owner-local `~/rdp-server/build` execution is **NOT RUN** in this
connector environment. Exact-SHA Linux/GCC, macOS/AppleClang and Windows/MSVC
Debug/Release, portable R4 sanitizer, documentation policy and SDK/package
evidence are required after publication. Genuine authenticated R3
`Microsoft::Windows::RDS::Graphics` DVC admission/full-send, measured
decode-lag throttle calibration, native capture performance and
Microsoft-client visible graphics remain **BLOCKED/NOT RUN**. Gate B and
M3/M4/M5 remain **OPEN**.
