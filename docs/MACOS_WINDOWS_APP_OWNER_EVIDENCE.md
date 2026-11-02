## R6 P0 — bind CredSSP failure to the same typed first-error event (2026-11-01)

**Authoring parent:** `8a2aff2c6a94abd9c68d3aaa36ba966904ac4d46`. Review of the closed v3 physical-client
differential found a validation gap without a schema gap: the four client
stages already carry same-attempt original-record digests, but
`type2_accepted_by_credssp=FAIL` could pass while the separate
`first_client_error` was only a generic, untimed UI observation. That did
not establish the requested CredSSP/provider parsing **and typed first error**
boundary.

Keep the existing private/public v3 schemas. A claimed stage-2 FAIL now
requires a bounded private `provider_category_exact` and first-error UTC
timestamp at the exact UTC instant of that source-bound
`type2_accepted_by_credssp` client event. The stage event remains the owner
of the original-record SHA-256, attempt ID, connection ID, client version and
observation-window provenance. A generic/untimed error or a different event
instant fails with fixed redacted categories and masks all four public client
stages to `NOT_OBSERVED`. The digest is still correlation metadata, not an
attestation of the private record contents. Existing UTF-8/lone-surrogate,
closed-category, digest-uniqueness, client/server namespace and cross-attempt
anti-splice rules are unchanged.

The dedicated
`paired_provenance_credssp_failure_requires_same_typed_first_error_event`
negative/positive fixture runs under the existing
`interop.windows-client-ab-stage-provenance-splice-denials` CTest for both
macOS Windows App and Windows 11 mstsc rows. No production TLS/NTLM/CredSSP,
collector, secret, trust, listener, native admission or client-launch behavior
changes.

Dependency review: exact-SHA R1/R10 hosted qualification at
`beda2c08f02752d3235d0731afa4a69b552b88bc` closes the prior internal
transport/scheduler software blocker. The remaining R6 gate is external:
an R9-nominated exact-SHA owner candidate plus separately authorized original
first-party client evidence. The 8.956 ms physical Windows App attempt still
has no original client Type-2 TLS receipt/decryption record; do not splice the
older 34.7 ms attempt or hosted SSPI. General CI and hosted Microsoft SSPI for
this publication SHA remain separate **PENDING** gates; physical A/B remains
**BLOCKED / INCONCLUSIVE** until owner authorization and evidence exist.

## R6 P0 — macOS four-stage client provenance negative parity (2026-11-01)

**Reviewed parent:** `28eac2cde4556f37c47bd93448bcd01b14011cec`. The closed private A/B v3 schema already
supports four separate client-origin observations: Type-2 TLS
receipt/decryption, CredSSP/provider acceptance or typed first failure,
Type-3 construction and Type-3-bearing client TLS submission. The
macOS row previously lacked the full PASS/FAIL plus negative-origin fixture
coverage already exercised for Windows. Extend the existing
`paired_provenance_` test selector for **each** macOS stage and both
observed states. A source-bound, same-attempt original client record
is accepted as *evidence input*; relabeling it as `server-transport` or
using the neighboring mstsc attempt ID must produce a fixed typed FAIL
and mask all four macOS stages to `NOT_OBSERVED` in the public result.
The Windows row remains independently unobserved and private attempt IDs
never enter shared JSON. No collector invocation or external client occurs;
original digest metadata still does not attest its content.

The 8.956 ms physical macOS Windows App row remains distinct from the
older 34.7 ms attempt and hosted Microsoft SSPI. Server-local TLS 1.3,
Type-2 flags `0xe08a8235`, zero later observed client TLS bytes, no
Type 3/alert and peer FIN **cannot establish client receipt**. Per-attempt
AV IDs, 126-byte Type-2 length, cipher, SNI/IP target, exact-IP-SAN
certificate fingerprint, credential choice and server SHA must come from
original records of **that same attempt**, not a neighboring trace.

**Verification:** source/CTest-selector review PASS; local canonical
Python, CMake full Debug/Release CTest, sanitizers and benchmark NOT RUN
(no mounted checkout/GitHub DNS). Exact-publication-SHA hosted Microsoft
SSPI and general CI PENDING independently; neither qualifies physical
Windows App. Next gate: R9 nominates an exact-SHA candidate, then the
owner separately authorizes macOS Windows App and Windows 11 mstsc
attempts **and** read-only inspection of existing first-party diagnostics.
Keep attempt/connection IDs, original-record digests, UTC windows and
the first typed error private. Never access Keychain, collect secrets,
change certificate trust, launch clients or enable capture here.
If no original Type-2 client receipt/decryption exists, physical A/B is
BLOCKED / INCONCLUSIVE.

## R6 original-record timestamp anti-splice invariant (2026-11-01)

Review parent `9c71295082b1a7369056109a1d872fddaccb62a9` found one private provenance inconsistency:
the v3 validator checked source-kind consistency for repeated client
`source_record_sha256` values, but did not reject two different event instants
for the very same original record. Keep the closed schema and public summary.
Within one physical attempt, a digest reused for multiple independent client
stages now must have the same UTC-normalized event instant as well as the
same supported source kind. Different offsets encoding the same instant remain
valid; distinct digests may use distinct timestamps within the existing
bounded attempt window. On disagreement emit only the fixed
`WINDOWS_CLIENT_SOURCE_EVENT_TIME_CONFLICT` or
`MACOS_CLIENT_SOURCE_EVENT_TIME_CONFLICT` denial, never a digest, timestamp,
provider text, path, credential, token, or raw event.

The new `paired_provenance_original_record_timestamp_splice_is_denied`
negative/positive controls run in the existing ordinary
`interop.windows-client-ab-stage-provenance-splice-denials` CTest, without a
new executable, test registration, dependency, or production TLS/NTLM change.
The read-only owner evidence contract and all existing first-error Unicode,
closed category, digest uniqueness and cross-attempt denials remain intact.
A digest is provenance correlation, not an attestation of a physical event.
Local Python, focused/full Debug/Release CTest, sanitizers and benchmarks
**NOT RUN** in this GitHub-connector environment; exact-publication hosted
CI **PENDING**.

The reported 8.956 ms physical Windows App Type-2-to-FIN attempt still lacks
the earliest original client TLS receipt/decryption observation. Keep its
metadata and attempt ID separate from the older ~34.7 ms attempt and hosted
SSPI; no password rejection or Type-3 production fix is inferred. Future
owner A/B requires exact-SHA R9 nomination and explicit separate consent
for the actual client attempts and reading existing first-party diagnostics;
no Keychain, trust, credential, client launch, packet capture or native access.

## R6 independent four-stage audit for the 8.956 ms attempt (2026-11-01)

Review at parent `4728faea8f207ed0f760192d311fc3d603ee3ffc` found no representability gap in the closed
private v3 pair: client Type-2 TLS receipt/decryption, CredSSP/provider parsing
and typed first error, Type-3 construction, and Type-3-bearing TLS submission
are already four independent source-bound stages. The existing provenance
fixture is strengthened so every stage can stand alone with client-origin
evidence and every one fails closed when the same record is labeled
`server-transport`. No schema bump or production TLS/NTLM change is justified.

Keep the latest reported physical row separate: TLS 1.3, direct NTLM Type 2
`0xe08a8235`, zero later server-observed client TLS bytes, no Type 3 or TLS
alert, and peer FIN after 8.956 ms. Those server facts do **not** prove client
receipt/decryption, a provider parse result or password rejection. Do not
attach the earlier ~34.7 ms row or hosted SSPI material to this connection.
Likewise, Type-2 AV IDs/126-byte length, negotiated cipher, SNI versus numeric
IP target, exact-IP-SAN certificate fingerprint, app credential-source choice
and server SHA belong to this attempt only when the original same-attempt
source actually records them; otherwise they remain uncorrelated rather than
being copied from a neighboring attempt.

**Future owner A/B, still NOT RUN:** first obtain an R9-nominated exact-SHA
candidate and explicit owner authorization for each macOS Windows App and
Windows 11 mstsc attempt **and** permission to read already-existing
first-party diagnostics. Preserve separate attempt/connection IDs and private
source digests; verify the same server SHA/certificate/endpoint/target and
deliberate credential source; then record the first actually observed client
boundary and typed provider error, if any. This checklist never accesses
Keychain, collects secrets, changes trust policy, launches a client or enables
packet capture. If first-party client evidence is absent, the differential is
**BLOCKED / INCONCLUSIVE**.

## R6 reported 8.956 ms Type-2/FIN: first missing client observation (2026-11-01)

**New owner-reported case (original files not supplied):** Linux TLS 1.3,
direct NTLM Type 2 `0xe08a8235`, no post-Type-2 client TLS bytes, no Type
3 or TLS alert, peer FIN after 8.956 ms. The separately documented ~34.7
ms attempt and hosted Windows SSPI `COMPLETE_PASS` belong to different
sources. Do not invent an attempt/connection ID or move an earlier profile,
AV-list, certificate, cipher, credential selection or first error to the
new connection. The earliest missing independent fact is **first-party
client TLS receipt/decryption of that exact Type 2**.

The closed private v3 pairing already has independent fields for:
`type2_received` (client TLS receipt/decryption),
`type2_accepted_by_credssp` (client provider parse outcome/typed
first error), `type3_generated` (client construction), and
`type3_delivered` (submission to client TLS). Absent original
first-party evidence must stay `NOT_OBSERVED`. Server-local Type-2
delivery or FIN cannot populate a client field. A first-error event may
lag the terminal server observation by at most 120 seconds but must not
predate the original attempt; do not also cap it to 120 seconds from
attempt start. The existing source binding remains closed, and record digests
are correlation only, not attestation.

**Future owner A/B checklist — NOT RUN and not authorized:** After R9
nominates an exact-SHA candidate with separate general CI and hosted
Microsoft SSPI receipts, obtain explicit owner authorization for the
particular macOS Windows App and Windows 11 mstsc sessions **and** for
reading their already-available first-party diagnostic evidence. For
each attempt separately, retain its private source hash, ID,
connection ID, server SHA, endpoint, app/OS build, negotiated TLS
version/cipher, SNI versus numeric-IP target, exact IP SAN and leaf
certificate fingerprint, unchanged trust-warning choice, negotiated
Type-2 flags/AV IDs and 126-byte-length check, deliberately selected
credential source and bounded UTC event window. Record the *first
actually observed* client-side step or typed first-error category and
time, then leave later stages `NOT_OBSERVED` unless independent
same-attempt records support them. Check client-event source identity
and hashes against those originals, without ever collecting NTLM
tokens, passwords, keys, raw UI errors or protected authInfo.
Do not access Keychain, change credentials or trust policy, launch
clients, enable packet capture or native input under this checklist.
If no client-side event is available, report BLOCKED/INCONCLUSIVE
rather than inferring password rejection or a protocol defect.


## R6 private first-error projection and original client-source reuse (2026-11-01)

A source audit of the current R6 v3 paired validator confirms that invalid Windows first-error categories/sources, missing fields, and malformed nested evidence already use fixed typed FAIL codes and redacted public fallbacks. However, the upstream R5 macOS summary independently reflected untrusted private client UI codes, first-client-error category/source and first-error event timestamp. Malformed strings/lists/dictionaries could reach a shared result, and the read-only validate CLI's exception message could disclose a private path. The correction bounds public UI codes to numeric/hex or `not-recorded`, validates the six-field first-client-error record, paired aware timestamps and optional bounded provider details, and emits fixed `FIRST_CLIENT_ERROR_INVALID`/`CLIENT_UI_CODE_INVALID` failures with `unknown`, `not-observed`, and null public error fallbacks. CLI validation exceptions use a fixed error message. The existing public schemas and fields are unchanged. Collection behavior remains separate.

R6 v3 now rejects identical original client-event SHA-256 digests assigned to the separate Windows App and mstsc attempts, case-insensitively; the same original record may still support multiple stages of a single attempt. The old per-event SHA, certificate, endpoint, attempt, connection, source/client application/version, credential, target identity and time-window checks remain in force. Digests/correlation cannot attest that a real client event happened; do not splice events or infer Type-2 receipt from server-local TLS accepted bytes.

New isolated offline CTest: `interop.windows-client-ab-malformed-macos-first-error-projection-denials` uses string/list/dict/absent-field sentinels and fixed CLI diagnostic assertions. Existing `interop.windows-client-ab-stage-provenance-splice-denials` covers reused digests and legitimate distinct-source evidence. The original `interop.windows-client-ab-invalid-first-error-redaction-denials` remains untouched. R6 physical A/B is NOT RUN/unauthorized. A future approved pair needs R9 exact-SHA manual nomination plus separate owner consent, same server SHA/certificate fingerprint, endpoint, TLS profile, CredSSP target, deliberate credential-source selection and separate same-attempt client-stage observations for: (1) Type-2 TLS ciphertext receipt/decryption, (2) CredSSP TSRequest/NTLM Type-2 parse accept/reject, (3) Type-3 token construction, and (4) Type-3 TLS-record submission. No credential logging, capture, certificate workaround, trust change or native Windows activation.

Hosted Microsoft SSPI artifact `r9-microsoft-interop-379f05d3ff3a31df5ae80cd7f437b508c23653f9` (Actions 41250520319) has `COMPLETE_PASS`, `authinfo=yes`, `credentials-verified=yes`, required missing NB-computer/domain AV negative denials, and bad server binding denial. It is memory-BIO/SSPI evidence, NOT physical client Type-2 receipt. Physical owner trace has locally committed Type 2, zero post-Type-2 client TLS bytes, no observed Type 3, and peer FIN after approximately 34.7ms. The first unproven step is the client's reception/decryption of Type 2. Hosted at 379f05d3: Windows MSVC full Debug/Release and focused native WTS/DXGI/SendInput CTests PASS, Windows Clang 23 PASS, sanitizer lane PASS; these historical results do not qualify a new SHA. Newer R10 graphics-first-frame/ACK full-CTest failure is unrelated to this validator and requires separate correction. Source, registry and non-disclosure logic review PASS; connector-local configure/Python/CTest/MSVC/Clang/sanitizer execution NOT RUN (no local GitHub checkout). Publication-SHA hosted checks PENDING.

## R6 fail-closed public first-client-error category (2026-10-31)

For the existing closed v3 A/B record, the private Windows
`first_client_error.normalized_category` is not arbitrary public text.
Only `credential`, `trust`, `negotiation`, `cancellation`,
`transport`, `unknown` and `not-observed` are public tokens.
An invalid string/non-string category or source must yield typed
`WINDOWS_FIRST_ERROR_INVALID` and a redacted FAIL summary with
`first_client_error_category=unknown`, not a raw private echo or an
uncaught type error. Preserve the original client record privately.
This offline hardening does not authorize client diagnostics/capture,
a physical Windows App/mstsc attempt, certificate/Group Policy changes,
credential replacement or Windows desktop activation.

## R6 current-head A/B provenance recheck (2026-10-31)

The closed paired schema remains `rdp-server.windows-client-ab-pair.v3`;
no new field is warranted. A usable Windows App versus Windows 11 mstsc pair
must keep the same exact server SHA, destination/service endpoint, certificate
fingerprint, server TLS profile and target identity while separately recording
the original client application/version, attempt ID, connection ID, bounded
observation interval and credential-source choice. Username and Session
Password must be deliberately entered as specified for each row without
logging the password or NTLM/CredSSP secrets; a pre-existing/default saved
credential is not an acceptable substitute.

Client-side provenance is stage-specific. The earliest discriminating
observations are, in order, receipt/decryption of server TLS application data,
parsing/acceptance or rejection of the CredSSP/NTLM Type 2, Type-3
construction, and submission of the next client TLS record. A server-local
Type-2 commit or peer FIN cannot populate any of those client fields. The
existing v3 validator already enforces this; the companion offline regression
now also explicitly rejects a nested source record whose server SHA, service
endpoint, attempt ID and original client application came from another
attempt. Supported same-attempt client Core/UI/provider evidence may be used
read-only if owner-authorized. Do not enable packet capture/monitoring, alter
certificate trust, Group Policy or credentials, or perform the physical A/B
until the R9 exact-SHA manual candidate and separate owner authorization both
exist.

## R6 rejected-private-summary fixed-output contract (2026-10-31)

A v3 pair with invalid client-stage, Type-3, native-admission or Windows
build/mstsc numeric-version input returns FAIL and fixed redacted fallback
NOT_OBSERVED/NOT_REACHED/INVALID, never the original private string. Windows
versions are dotted numeric; nonconforming originals remain owner-private.
Absent client-stage keys also report FAIL instead of leaking an exception.
The offline `interop.windows-client-ab-invalid-private-summary-redaction`
fixture tests sentinel non-disclosure and missing-stage rejection; no real
client, packet diagnostic, credential, TLS policy or native owner is enabled.

## R6 current closed-schema paired client-source evidence v3 (2026-10-31)

The R5 private macOS collection manifest stays
`rdp-server.macos-windows-app-owner-evidence.v2`. The **separate paired
supplement** is now `rdp-server.windows-client-ab-pair.v3` and its redacted
output is `rdp-server.windows-client-ab-redacted.v3`. V2 paired supplements
are deliberately rejected; no silent conversion or loosening of required
fields. The existing R6 A/B consent and collection procedure below remains
unchanged. Neither format can authorize R2/native Admission.

**Exact private A/B supplement schema.** Root has only `schema`, `macos`
and `windows`. Both rows retain all v2 mandatory fields; v3 additionally
requires `attempt_id_exact`, `target_identity_exact`,
`client_stage_evidence` and `server_type3_evidence`. Each row's
`source_binding` must contain **exactly** `server_sha`,
`server_certificate_sha256`, `destination_exact`,
`service_endpoint_exact`, `attempt_time_utc`, `connection_id`,
`terminal_time_utc`, `observation_window_start_utc`,
`observation_window_end_utc`, `attempt_id_exact`,
`client_application_exact`, `client_version_exact`,
`target_identity_exact`, and `credential_source_choice`.
The client identity is `Windows App` with exact
`<version>+<build>` for macOS and `mstsc.exe` with its exact file version
for Windows. Row A's credential-source choice must equal the R5 manifest's
explicitly selected saved-credential source; row B's must equal the
deliberate explicit-entry source. Both target identities must be the same
literal negotiated target, not merely similar destination IP text, and both
owner-assigned attempt IDs must be different. Root or nested extra keys fail.

`client_stage_evidence` has **exactly four** keys:
`type2_received`, `type2_accepted_by_credssp`, `type3_generated`,
`type3_delivered`. Each `NOT_OBSERVED` stage requires a JSON null
evidence value. Each claimed `PASS` or `FAIL` requires a same-attempt
**client-origin** event with exactly `source_kind`
(`client-provider-event` or `owner-approved-client-diagnostic`),
`source_record_sha256` (64 hexadecimal characters),
`client_application_exact`, `client_version_exact`,
`attempt_id_exact`, `connection_id`, and `event_time_utc`.
The timestamp must fall within that source's bounded observation window.
The record digest refers to a private original client event; the validator
checks the digest's shape and correlation, **not** its truth or signature.
A locally committed Type 2, server FIN, generic error or server-side byte
count is not a client-origin event. If no client event actually establishes
decryption/Type-2 parsing, leave that stage `NOT_OBSERVED`.

`server_type3_evidence` must be null unless the matching server stage
matrix says `type3_received=PASS`. A positive Type 3 requires exactly
`source_record_sha256`, `attempt_id_exact`, `connection_id` and
`event_time_utc` from that original server record, bound to the same
server-side observation window. A Type 3 seen on another connection can
never close an earlier FIN-only attempt even if the two have the same IP,
server SHA, Type-2 bytes, and approximate timestamps.

**First discriminating client-side evidence:** distinguish (1) reception
and decryption of server TLS application data, (2) decoded CredSSP
`TSRequest` and Type 2 acceptance or provider rejection, (3) SSPI/NTLM
Type 3 construction, and (4) actual client TLS-record submission. Do not
infer any step from the next, from a peer FIN, or from the hosted memory-BIO
oracle. The v3 four-stage client map covers Type-2 receipt, Type-2
acceptance, Type-3 construction and local delivery; preserve any separate
TLS decryption or attempted-submission observation privately with
same-attempt source provenance and do not add unapproved fields to this
closed schema. Cross-client/server clock order remains
`ORDER_UNDETERMINED`.

**Eligibility and safe diagnostics:** the controlled pair is still **NOT
RUN / unauthorized** until an R9 manually approved exact-SHA candidate
and distinct owner consent. Keep the same server SHA, numeric endpoint,
selected TLS certificate/fingerprint, literal CredSSP target identity,
configured Username and independently entered Session Password. On macOS
Windows App explicitly select/re-enter a newly created saved credential
for this attempt and inspect only the application's documented optional
Core/UI logging when separately authorized. On Windows 11 mstsc explicitly
prompt/re-enter and verify the selected identity; never assume that
`/prompt` proves the credential source. Do not remove cached credentials,
change certificate trust/Group Policy/Schannel, start a packet monitor,
activate ETW/packet capture or enable native desktop. An owner-approved
read-only client-provider observation is useful only when the underlying
event actually exists; no client implementation or version can be
inferred from the server's FIN.

**Offline gate:** `interop.windows-client-ab-stage-provenance-splice-denials`
covers server-local Type-2-as-client receipt, Type 3 from a different server
connection, a Type 3 client event from a different attempt, target/version/
credential mismatches, fabricated events on unobserved stages and events
outside the original window. The existing
`interop.windows-client-ab-evidence-contradiction-denials` continues all
earlier closed-schema checks. This work does not run a client or attest that
a submitted evidence record is genuine.

## R6 executable paired Windows App vs mstsc evidence contract (2026-10-30)

The existing R5 private macOS schema-v2 manifest remains row A's primary
collector record. The paired supplement is now closed schema
`rdp-server.windows-client-ab-pair.v3`; it is evidence correlation only,
never a client launcher, credential verifier or R2 native-Admission authority.

Each row records the exact nonsecret service endpoint in addition to the
destination, TLS configuration profile and certificate fingerprint. Every
supplemental server fact is bound to one `source_binding` containing the exact
server SHA, certificate fingerprint, destination, service endpoint, client
attempt time, Linux connection ID, terminal time and bounded observation
window. A mismatch is an invalid pair rather than permission to splice facts
from a nearby attempt. In particular, the approximately 68 ms current
Type-2-to-FIN observation and the earlier approximately 9.5 ms observation with
a different certificate fingerprint are different attempts and must remain
separate.

Client-side security evidence is independent of the server stage matrix. Record
exactly these four client observations as `PASS`, `FAIL` or
`NOT_OBSERVED`: `type2_received`, `type2_accepted_by_credssp`,
`type3_generated`, and `type3_delivered`. Local server Type 2 commit,
zero post-Type-2 server bytes, TCP FIN, TLS silence or a generic UI error cannot
fill any of those client fields. Conversely, a client-side token-generation or
local-delivery observation does not manufacture server-side Type 3 receipt.

For the controlled macOS row, the R5 private manifest must explicitly record
the selected credential and whether it was created/replaced for that attempt;
the pair supplement sets `deliberately_reentered=true` only when the owner
actually re-entered the independent Session Password. For Windows 11
`mstsc.exe`, the private credential object is
`{source:"explicitly-entered", deliberately_reentered:true,
saved_credential_use:"none", username_exact:<private>,
session_password_intentionally_matched:true}`. If a saved/default Windows
credential is used or cannot be ruled out without changing the credential
store, record that fact privately and mark the controlled B row invalid; do not
delete or rewrite the store. Passwords, NTLM/token bytes and delegated
credentials are never copied into either manifest.

Run only on locally controlled private inputs after the R9 candidate and
separate owner authorization:

    python3 scripts/macos_windows_app_owner_evidence.py validate private-macos-v2.json
    python3 scripts/windows_client_ab_evidence.py private-macos-v2.json private-ab-pair-v3.json > redacted-ab.json

The paired validator invokes the full R5 macOS validator, rejects unapproved
fields and cross-attempt/source contradictions, and emits only allowlisted
redacted facts. It deliberately keeps cross-source event order
`ORDER_UNDETERMINED`. Physical A/B remains **BLOCKED / NOT RUN** until the
manual R9 exact-SHA owner-candidate gate passes and the owner separately
authorizes both clients.

## R6 round-one controlled physical A/B execution worksheet (2026-10-30)

**Eligibility before any connection:** R9 must nominate one exact 40-character
`main` SHA with all mandatory Linux/macOS/Windows, GUI, sanitizer and
documentation producers green, and the manually dispatched
`r9_credssp_owner_candidate=true` gate must independently **PASS** for that
same SHA. Obtain separate owner authorization for both clients and the real
server. An ordinary-push skipped candidate, an offline Microsoft SSPI result
or a green Windows-only producer is **not** eligibility. Do not run either
physical client, change a credential store, trust, Group Policy, registry,
firewall, TermService or native capture/input as part of preparation.

**Server preflight, owner terminal, canonical existing checkout only:**

```sh
cd ~/rdp-server
git switch main
git pull --ff-only origin main
git rev-parse HEAD
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build build --config Debug --parallel 2
ctest --test-dir build -C Debug --output-on-failure
```

Require that the printed SHA equals the approved R9 candidate and that full
CTest passes. Preserve the full result privately. With explicit owner consent,
prepare **one** selected listener/standalone credential and one unchanged TLS
certificate; note the listener selection, exact destination IP string,
certificate SHA-256 fingerprint, configured standalone Username and whether
the separately entered Session Password is intentionally identical in both
clients. The Linux OS account password is **not** the application Session
Password. Record exact values only in the private owner evidence, never the
shared diagnostic summary. Do not restart, rotate, change destination text or
change credentials between A and B; invalidate the pair if this occurs.

**A — macOS Windows App, one deliberate attempt.** Record OS and Windows App
version/build. In the existing Remote PC card's **Edit -> Saved credential**
control, record whether a saved credential already existed, whether the owner
explicitly created/replaced/re-entered it for this attempt, which saved entry
was selected, and whether its Username matches the standalone Username
(yes/no) and password matches the Session Password (yes/no only). Use an
explicitly selected matching saved credential for the controlled row; an
`Ask when required`/unknown credential is useful only as a separately labeled
diagnostic row and does **not** satisfy the comparison. Do not disclose or
export saved-secret contents. Using the documented **Help -> Troubleshooting
-> Logging** UI, choose owner-controlled Core/UI log levels and a fresh output
folder, Start Logging, make exactly one connection, then Stop Logging. Note
warning shown/accepted, exact UI result, first typed Core/UI provider event
when actually present, and an offset-aware attempt time. Create and validate
the existing schema-v2 manifest using this document's commands and the same
Linux connection, keeping all raw logs private.

**B — Windows 11 `mstsc.exe`, one deliberate attempt.** Only after A is
captured, record Windows build and the mstsc file version. Inspect the
connection UI's displayed Username/credential selection and record whether a
saved credential already existed, whether it was explicitly re-entered or
replaced for this attempt, and whether the displayed Username and intentionally
entered password match the same standalone pair (yes/no only). The
owner-authorized `mstsc.exe /v:<exact-same-IP> /prompt` option requests a
credential prompt, but the operator must still confirm which account is
actually selected; do not assume a prompt bypasses machine policy. Never pass
the password on the command line. Do not use `/restrictedAdmin`,
`/remoteGuard`, a gateway or an implicit OS login as a supposedly equivalent
delegating control. If a preexisting saved credential cannot be distinguished
from the intended explicit entry without changing the store, mark B
`INVALID_CREDENTIAL_CONTROL` and stop rather than deleting it. Record the
same warning decision, client-visible error, exact destination and
offset-aware correlation, with any separately owner-approved client diagnostics
when available; do not invent a private mstsc log path.

**For both rows, preserve separately:** exact server SHA and certificate
fingerprint; exact service endpoint and destination; client/OS versions; saved
credential existed/selected/re-entered-or-replaced facts; Username and Session
Password matching booleans; client UI warning/result and first *actually
observed* provider/category/time; Linux connection ID, offset-aware terminal
time and the exact observation window; TLS/cipher, Type 1 flags, Type 2 flags
and fully committed status, post-Type-2 server-observed TLS byte count,
first-byte/EOF/alert facts, Type 3, pubKeyAuth, authInfo,
CredentialsVerified, native Admission and first terminal stage. Separately
record client-side Type 2 received, Type 2 accepted by CredSSP, Type 3
generated and Type 3 locally delivered without inferring any one from the
server. **Local Type 2 write completion is not peer-consumption proof**, a zero
server-observed post-Type-2 byte count is not proof that the client emitted
nothing, and FIN or generic `0x204` never identifies a credential, policy or
certificate root cause.

| Priority | Candidate cause (not established) | Required discriminator / owner |
| --- | --- | --- |
| 1 | Wrong selected, stale or absent client credential | Verify the explicit saved/prompt source, match booleans and client-side credential category. R5/R6 client evidence first |
| 2 | Local certificate or trust decision | Compare warning actions and exact client trust/provider category. An unmatched warning decision invalidates the A/B pair |
| 3 | Client CredSSP/delegation restriction or local token non-emission | A *client-side* event proving Type 2 was consumed plus refusal/no next token; inspect policy read-only. No unauthorised policy change |
| 4 | Common live peer/server compatibility boundary | Both controlled clients stop after Type 2, with no earlier typed client cause. This prioritizes investigation, **not** a Type 2 or TLS rewrite |
| 5 | Server R1/R2 parsing after Type 2 | Server receives post-Type-2 bytes: hand off the first observed TLS/TSRequest/token or protected-authInfo failure to R1/R2 |
| 6 | Native session/Share path | Genuine Type 3 and verified credentials: R2 then R10 must independently establish native Admission before R3/Share. A hosted credential PASS never does so |

**Comparison decision:** A stops after Type 2 but B emits Type 3 -> focus on
macOS client-specific state; both stop -> seek a common requirement or two
explicit client-side causes; both emit Type 3 -> advance to production proof,
pubKeyAuth/authInfo and R2. A different SHA, destination, identity,
certificate or client-warning decision -> **INCONCLUSIVE**, not a negative
proof. Preserve event order within each source; report
`ORDER_UNDETERMINED` across unverified client/server clocks. Stop at the
first independently demonstrated failure and retain all private material under
owner control. No physical execution is authorized by this worksheet.

**Independent documentation:** Microsoft CredSSP
`InitializeSecurityContext` requires `ISC_REQ_DELEGATE` for nonempty
delegated credentials. The project's positive memory-BIO fixture explicitly
supplies Unicode `User` / `Password`, empty domain, a chosen target,
Schannel profile and delegation intent, and has already reached production
`CredentialsVerified`. Neither macOS Windows App's saved-credential
selection nor Windows 11 mstsc's UI/policy are exercised by that fixture;
terminal `ISC_RET_DELEGATE=no` in the verified NTLM path does not negate the
nonempty final authInfo. Do not rerun the already-qualified synthetic matrix
to stand in for A/B.

Microsoft references:
<https://learn.microsoft.com/windows-app/user-account-settings-add-remove-manage>,
<https://learn.microsoft.com/windows-app/troubleshoot-collect-logs>,
<https://learn.microsoft.com/windows-server/administration/windows-commands/mstsc>,
<https://learn.microsoft.com/windows/win32/secauthn/initializesecuritycontext--credssp>,
<https://learn.microsoft.com/windows/security/identity-protection/remote-credential-guard>.

# macOS Windows App physical owner-evidence procedure

## R5 P0 evidence validator and first-client-error contract (2026-10-29)

The current physical symptom is the Windows App UI error code `0x204` while
the correlated Linux attempt reaches TLS, Direct NTLM Type 1, fully commits the
unchanged production Type 2, waits for Type 3 and then observes peer EOF. A bare
`0x204` is **not** a credential, trust, CredSSP-negotiation or cancellation
classification. Keep it as the UI code and report the first more-specific
client-side event only when the same-attempt Core/UI log carries an explicit
provider category/code. Otherwise use `unknown` or `not-observed`; do not
promote the server's peer EOF into a client cause.

Microsoft's supported macOS collection surface exposes **Core log level** and
**UI log level**, but its public collection documentation does not define a
stable internal provider/event-category vocabulary. Therefore the project owns
only this normalized diagnostic taxonomy:

- category: `credential`, `trust`, `negotiation`, `cancellation`,
  `transport`, `unknown`, or `not-observed`;
- source: `core`, `ui`, `ui-error`, `core-and-ui`, or
  `not-observed`.

For a specific category other than `unknown`, retain the **exact** observed
provider category/code and event timestamp in the private manifest. Never put
those raw provider fields, the exact UI message, Username, log paths/hashes or
Linux connection identifier in the R2/R6 summary.

The schema-v2 collector now also records the exact server certificate SHA-256
fingerprint and the server-observed stage matrix: TLS established, Type 1,
Type 2 fully committed, post-Type-2 client-byte count, Type 3, pubKeyAuth,
authInfo, `CredentialsVerified` and typed terminal outcome. Existing schema-v2
consumers remain valid; the additional fields are evidence, never authority.

For the next physical row, also record the R1/R10 timing-attribution scalars
from the **same Linux connection**: Accepted-to-TLS, TLS-to-Type-1,
Type-1-to-Type-2 queue, Type-2 creation-to-delivery, Type-2-to-peer-EOF,
pre-auth elapsed-at-peer-EOF, optional first post-Type-2 client TLS-byte age,
the pre-TLS Read/Write/active-work/TLS-work/unattributed/socket-poll/
ready-to-service fields, and both R10 stage-local app-wait/peer-wait-upper/
service-work/native-maintenance/service-call/max-app-gap groups. These values
are single-attempt diagnostics, not latency benchmarks.

The validator requires that timing set for a current R5/R6 physical row. Missing
or internally contradictory timing is an evidence failure. If either early R10
native-maintenance counter is nonzero, the evidence itself remains valid but the
redacted summary reports `EARLY_NATIVE_MAINTENANCE_OBSERVED` and marks
pre-auth native isolation unqualified. Do not convert that observation into a
credential, trust, transport, or client diagnosis; it is a server-side
scheduling/isolation finding only.

Run the new read-only validator on the private manifest:

```sh
python3 scripts/macos_windows_app_owner_evidence.py validate owner-evidence.json
```

It emits `rdp-server.macos-windows-app-redacted-diagnostic.v1`. The exact
destination is represented only by SHA-256, the Username and Linux connection
ID are presence/redaction facts, and raw logs remain outside the summary.
Validation fails explicitly for missing supported logs, incomplete logging
lifecycle, missing/invalid certificate fingerprint, invalid credential control,
missing/inconsistent server-stage fields, missing Linux correlation, malformed
timestamps, or an absolute client/server timestamp delta greater than 120
seconds. That 120-second bound is only a same-attempt correlation ceiling, not
an authentication timeout or performance target. Passing it never establishes
cross-source event order; the summary remains `ORDER_UNDETERMINED`.

For an R6 A/B pair, the validator may additionally receive the Windows-row
server SHA, destination, certificate fingerprint, explicitly entered Username,
Session-Password-match state and certificate-warning decision. Any mismatch is
an explicit `AB_*` failure; non-comparable warning decisions are
`CERTIFICATE_DECISION_NOT_COMPARABLE`. The comparison reports only booleans
and never emits the peer Username or exact destination.

This is the reusable client-side evidence procedure for an owner-authorized
Windows App for macOS attempt against the Linux/X11 RDP-server host. It is
diagnostic only. It does not authorize a production protocol, certificate,
authentication, native Admission, MCS, Share, graphics, input or clipboard
change.

Microsoft documents Windows App for macOS logging through the application UI:
**Help -> Troubleshooting -> Logging**, choose Core/UI log levels and an output
folder, start logging, reproduce the issue, then stop logging. Use that supported
workflow. Do not guess or depend on a private Windows App log path.

Reference:
<https://learn.microsoft.com/windows-app/troubleshoot-collect-logs>

The current Windows App release history is published at:
<https://learn.microsoft.com/windows-app/whats-new>

## R6 paired physical-client A/B with Windows 11 mstsc

This macOS evidence bundle is row A of the R6 physical-client comparison. It
must be reviewed **before** interpreting the Linux peer-close record or the
Windows row. The comparison is owner-authorized physical evidence only; it is
never a hosted-CI test.

### Pair invariants

Use one R9-nominated exact server SHA for both rows and record it before either
attempt. Keep the same running RDP-server instance/listener when possible so
the generated certificate identity, configured standalone Username, independent
Session Password and destination IP remain unchanged. Do not Stop/Start,
replace credentials, rotate TLS identity, change destination spelling or modify
production TLS/NTLM/CredSSP policy between rows. If any of those change, the
pair is invalid and both rows must be repeated.

The destination is the same **exact IP string** in Windows App and
`mstsc.exe`. Both clients must receive the same standalone application
credential: exact configured Username plus the same independent Session
Password, entered through each client UI. Never place the password in a shell,
command line, manifest, GitHub artifact or acceptance record.

Record the exact server certificate SHA-256 fingerprint once for the pair. For
each client record whether a certificate warning appeared and, if so, whether
the owner accepted it. Do not alter Keychain, Windows certificate stores or
client security policy to manufacture parity. If warning/trust decisions are
not comparable, mark the A/B result
`CERTIFICATE_DECISION_NOT_COMPARABLE` and stop interpretation at that fact.

### Row A — macOS Windows App first external evidence

Run the existing R5 procedure above and retain its typed
`rdp-server.macos-windows-app-owner-evidence.v2` manifest, original supported
Core/UI logs when available, exact client-visible error, Windows App
version/build, certificate-warning decision, Linux connection ID/timestamp and
complete Linux terminal record. Review the same-attempt Core/UI log before
assigning meaning to the server-side Type-2/EOF sequence.

A macOS row without this R5 evidence bundle is `INCOMPLETE` for the R6
comparison even when the server terminal record is available.

### Row B — physical Windows 11 mstsc

Only after row A has been captured, use an owner-authorized physical Windows 11
machine if one is available. Record the Windows OS build and the
`mstsc.exe` file version. Connect to the same exact destination IP and
explicitly supply the same standalone Username and independent Session Password
through the Remote Desktop client UI.

Do not use a CI runner, a hosted VM's account credential, implicit current-user
credentials or a password supplied on a command line. If the client uses an
existing saved/default credential and the operator cannot prove it is the
standalone credential for this pair, record
`INVALID_CREDENTIAL_CONTROL` and do not interpret the row.

Record the client-visible result/error and the same server-side correlation
fields as row A: connection ID, offset-aware terminal timestamp and complete
terminal record. No new client-side logging mechanism is required merely to
make the rows symmetric; use owner-approved Windows diagnostics if already
available, but do not invent a private `mstsc.exe` log path.

### R9 comparison record

For both rows, fill every stage explicitly rather than carrying success
forward:

| Field | macOS Windows App | Windows 11 mstsc |
| --- | --- | --- |
| Server SHA | exact 40-char SHA | same SHA required |
| Server certificate SHA-256 | exact fingerprint | same fingerprint required |
| Destination | exact IP string | same exact IP string |
| Standalone Username | exact configured value | same value required |
| Session Password matched | yes/no only | yes/no only |
| Client version | Windows App version/build | Windows build + mstsc file version |
| Certificate warning shown | yes/no | yes/no |
| Certificate warning accepted | yes/no/not-applicable | yes/no/not-applicable |
| R5 typed Core/UI log | available/unavailable + manifest/log references | not-applicable |
| Exact client-visible error/result | exact text or none shown | exact text or none shown |
| TLS established | PASS/FAIL | PASS/FAIL |
| Type 1 received | PASS/FAIL/NOT_REACHED | PASS/FAIL/NOT_REACHED |
| Production Type 2 fully committed | PASS/FAIL/NOT_REACHED | PASS/FAIL/NOT_REACHED |
| Post-Type-2 client data | bytes/frame facts from existing diagnostics | bytes/frame facts from existing diagnostics |
| Type 3 received | PASS/FAIL/NOT_REACHED | PASS/FAIL/NOT_REACHED |
| pubKeyAuth reached | PASS/FAIL/NOT_REACHED | PASS/FAIL/NOT_REACHED |
| authInfo reached | PASS/FAIL/NOT_REACHED | PASS/FAIL/NOT_REACHED |
| CredentialsVerified reached | PASS/FAIL/NOT_REACHED | PASS/FAIL/NOT_REACHED |
| Typed terminal outcome | exact server category | exact server category |
| Linux connection ID / terminal time | exact / offset-aware | exact / offset-aware |

Interpretation is deliberately narrow:

- macOS stops after Type 2 while `mstsc.exe` sends Type 3: investigate
  macOS Windows App credential/delegation/settings/policy first.
- both clients stop after the same production Type 2 without Type 3:
  investigate a common live-client/server interoperability requirement.
- both send Type 3: move the comparison boundary forward into proof
  verification, pubKeyAuth, authInfo and later authentication stages.
- any mismatch in SHA, destination, explicit credential control or certificate
  comparability makes the pair inconclusive; repeat under controlled inputs.

No result in this table authorizes a production wire change by itself.

### R2 handoff — first client-side typed failure

Only after an exact-SHA R9 manual candidate **PASS** and owner authorization,
review each physical client attempt's original, same-attempt evidence in its
native order. For macOS, use the R5 Core/UI logs and exact UI error; for
Windows 11, use the exact `mstsc.exe` UI result and any owner-approved native
diagnostics actually available. Identify the **earliest explicit client-side
typed failure** (provider category/error code and redacted exact message),
its source, original event timestamp when available and the matching client
attempt. A Linux Type-2-commit/FIN record is not a client-side failure code.

Send R2 a **private, redacted** evidence handoff for each comparable row:
client OS/app versions, exact server SHA and destination, certificate identity
and warning decision, explicit credential-control/match yes-no facts, earliest
client-side typed failure with source and timestamp, and the correlated Linux
connection ID, offset-aware terminal time and independently observed protocol
stage matrix. Preserve raw logs and the R5 manifest in the owner-controlled
evidence bundle; never commit usernames, raw client logs, passwords, NTLM
material or delegated credentials.

When no client-side typed failure is present, report `NOT_OBSERVED` and the
exact UI result; when log order across sources cannot be established, report
`ORDER_UNDETERMINED` and retain the separate first events instead of
inventing an overall earliest failure. Do not order client and server events
by comparing clocks with unverified synchronization. R2 owns subsequent
credential/delegation/account-policy investigation **only when supported by
that client evidence**; otherwise route the first independently demonstrated
failure to its actual stage owner. This handoff is diagnostic, never R2
authentication authority or permission to change TLS, NTLM Type 2,
certificate identity, server policy or downstream Admission/Share.

## Non-negotiable safety boundary

- Do **not** add, remove, import, persist or otherwise change any macOS
  Keychain/trust-store certificate for this attempt.
- Do not disable certificate verification, Gatekeeper, macOS privacy controls
  or Windows App security policy.
- Never record the Session Password or the Windows App saved-credential
  password in the manifest, notes, command line or repository. The helper has
  no password argument.
- Do not use the Linux account password as the Windows App saved password unless
  the owner intentionally made that password identical to the independent
  RDP-server Session Password.
- If a certificate warning appears, record whether it appeared and whether the
  owner explicitly accepted that warning. Do not pre-trust the certificate to
  make the warning disappear.
- A server-side EOF after Type 2/Await-Type-3 is transport evidence only. It is
  **not** evidence that Windows App rejected the certificate or that the
  Session Password was wrong.
- Never commit the evidence manifest, captured client logs, usernames,
  credentials, NTLM challenge/response material, passwords, tokens or other
  owner-specific private evidence to this repository.

## Required credential-controlled next attempt

For the next physical qualification run, configure the Remote PC entry in
Windows App with an **explicit Saved credential selected**. That saved
credential must contain:

- **Username:** the exact Username shown/configured by RDP-server for this
  standalone credential;
- **Password:** the exact independent Session Password configured in
  RDP-server.

Treat those values as the two ends of the same standalone application
credential. Do not substitute the Linux account password unless the owner
intentionally chose the same secret for both. Record only whether the server
GUI credential and Windows App saved credential were intentionally matched;
never record the password itself.

A run using **Ask when required / none** or another credential state may still
be diagnostic, but it does not satisfy this credential-controlled next gate.

## Before the attempt

1. On the Linux server, begin the owner receipt with `git rev-parse HEAD`
   before build/test, as required by the Agent-9 owner-candidate gate. Record
   that exact 40-character SHA, then complete the canonical full CTest run and
   record its full result before starting the physical connection attempt.
2. On the Mac, close any active Windows App connection. Record the destination
   exactly as it will be entered; do not normalize an IP address, hostname,
   service prefix or whitespace after the attempt.
3. Record the Remote PC Saved credential state as exactly one of:
   `explicit-saved-selected`, `ask-when-required-or-none`, or `other`.
   When an explicit saved credential is selected, record its exact Username,
   whether it was newly created for this attempt, and whether its Username and
   password were intentionally matched to the RDP-server Username and Session
   Password. Do not record the password.
4. In Windows App choose **Help -> Troubleshooting -> Logging**. Record the
   exact Core log level and UI log level selected. Choose a fresh
   owner-controlled output folder for this attempt.
5. Select **Start Logging** before initiating the RDP connection and record
   that logging was started.
6. Do not change Keychain or certificate trust settings.

Microsoft's documented logging procedure intentionally lets the owner choose
the output folder, so this project does not rely on an undocumented client log
location.

## During and immediately after the same attempt

Record all of the following from that one attempt:

- full CTest result for the exact server SHA recorded before the attempt;
- Windows App version and build;
- exact destination string entered;
- whether an explicit Saved credential was selected (`yes`/`no`) and the
  typed Remote PC Saved credential state;
- exact Username entered in the saved credential, or `not-applicable` when no
  saved credential was selected;
- whether that credential was newly created for the attempt;
- whether the Windows App saved credential and RDP-server standalone credential
  were intentionally matched;
- whether a certificate warning appeared;
- if it appeared, whether the owner accepted it;
- exact client-side failure/error text, or the literal note `none shown`;
- exact attempt time with an explicit UTC offset;
- exact Core/UI log levels and whether Start Logging occurred before the
  attempt;
- the Windows App client-side log files produced by the selected logging
  folder, when available;
- the correlated Linux connection ID, Linux terminal-event timestamp with an
  explicit UTC offset, and complete Linux terminal failure record.

Immediately after the failure, return to **Help -> Troubleshooting -> Logging**
and select **Stop Logging**. Record that logging was stopped, preserve the
same-attempt output folder, and do not mix logs from a later retry into it.

## Read-only manifest helper

`scripts/macos_windows_app_owner_evidence.py` is deliberately read-only with
respect to the supplied application and log inputs. It:

- reads `Contents/Info.plist` only from the `.app` path explicitly supplied by
  the owner and records `CFBundleShortVersionString` + `CFBundleVersion`;
- records the typed Saved credential state, exact saved Username when
  applicable, newly-created yes/no state and intentional server/client match
  yes/no state, but has no password input or output;
- records whether logging was started before and stopped after the attempt;
- records an exact Linux connection ID plus offset-aware Linux terminal-event
  timestamp for same-attempt correlation;
- reads only the log directory explicitly supplied by the owner;
- rejects symlinks in that log tree;
- bounds the inventory to 256 regular files and 512 MiB total;
- records relative file names, byte counts and SHA-256 hashes, never log
  contents;
- writes the JSON manifest to standard output only;
- has no Keychain, trust-store, Windows App preference or network mutation.

Example, replacing every placeholder with values from the same attempt:

```sh
mkdir -p build/owner-evidence
python3 scripts/macos_windows_app_owner_evidence.py \
  --app "/actual/path/to/Windows App.app" \
  --server-sha "0123456789abcdef0123456789abcdef01234567" \
  --attempt-time "2026-10-27T05:30:00-07:00" \
  --destination "192.168.1.5" \
  --saved-credential-state explicit-saved-selected \
  --saved-credential-username "exact Username shown by RDP-server" \
  --saved-credential-newly-created yes \
  --server-client-credentials-intentionally-matched yes \
  --certificate-warning yes \
  --certificate-warning-accepted yes \
  --error-text "exact Windows App error text" \
  --core-log-level "level selected in Windows App" \
  --ui-log-level "level selected in Windows App" \
  --logging-started yes \
  --logging-stopped yes \
  --linux-connection-id "exact Linux connection ID" \
  --linux-terminal-time "2026-10-27T05:30:07-07:00" \
  --logs "/owner/chosen/windows-app-log-folder" \
  > build/owner-evidence/macos-windows-app-attempt.json
```

The application path above is an example argument, not a repository assumption.
Use the actual installed `.app` path. The helper does not discover or inspect
private application directories. There is intentionally no password argument.

If Windows App's supported logging control is unavailable or no log file is
produced, do not fabricate a path. Record the reason explicitly instead:

```sh
python3 scripts/macos_windows_app_owner_evidence.py \
  --app "/actual/path/to/Windows App.app" \
  --server-sha "0123456789abcdef0123456789abcdef01234567" \
  --attempt-time "2026-10-27T05:30:00-07:00" \
  --destination "192.168.1.5" \
  --saved-credential-state ask-when-required-or-none \
  --saved-credential-username not-applicable \
  --saved-credential-newly-created not-applicable \
  --server-client-credentials-intentionally-matched not-applicable \
  --certificate-warning no \
  --certificate-warning-accepted not-applicable \
  --error-text "exact Windows App error text" \
  --core-log-level "not recorded" \
  --ui-log-level "not recorded" \
  --logging-started no \
  --logging-stopped no \
  --linux-connection-id "exact Linux connection ID" \
  --linux-terminal-time "2026-10-27T05:30:07-07:00" \
  --logs-unavailable-reason "supported logging control unavailable or produced no file" \
  > build/owner-evidence/macos-windows-app-attempt.json
```

`--certificate-warning-accepted` must be `not-applicable` when no warning
appeared, and must be `yes` or `no` when a warning appeared. For
`ask-when-required-or-none`, the saved Username, newly-created state and
server/client match state must all be `not-applicable`. The attempt and Linux
terminal timestamps must both be ISO-8601 with explicit UTC offsets so the
manifest can emit UTC correlation values.

## Evidence bundle and interpretation

The owner evidence bundle consists of the manifest JSON, the original Windows
App log files from the selected output folder when available, and the complete
Linux terminal record from the same attempt. Review client logs before sharing
them outside the owner evidence channel; do not publish credentials, usernames
or private identifiers in Git.

The client log and exact UI error may identify a client credential/delegation
or policy boundary. In their absence, the server-side progression

`TLS -> Type 1 -> Type 2 fully committed -> Await-Type-3 -> EOF`

supports only the observed peer-close boundary. Because Type 3 was not
received, it does **not** demonstrate a wrong Session Password. It also does
not distinguish missing/unsaved credential material, client-side credential or
delegation policy, certificate/user policy, user cancellation or another
typed client-side failure. Production remains `fixed-name / RDP-SERVER` until
new external evidence authorizes a narrower change.
