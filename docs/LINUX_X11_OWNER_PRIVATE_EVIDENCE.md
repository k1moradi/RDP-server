# Linux/X11 owner-private native acceptance — R5/R2

**Status: NOT RUN.** This is an owner-only procedure and a separate schema;
it does not extend the macOS Windows-App evidence tool. A green offline test,
Xvfb frame, or Windows App Type 2 receipt is **not** a Linux seat0/R2 result.
Do not conduct live desktop capture, XTEST input, desktop/seat inspection or
client connections without explicit authorization from the affected owner.

## Qualification before an owner attempt

1. The R9 owner nominates **one exact 40-hex main source SHA**. Check Linux
   full Debug/Release, Windows/macOS mandatory producers, and R9's native
   Linux ASan/UBSan job on that same SHA. The native R5 selection must be
   exactly **45/45 PASS**, including
   `x11.desktop-resource-inflight-frame-borrow-authority-retirement` and
   `x11.desktop-resource-reentrant-authority-loss-damage-dispatch`.
   The older **44/44** receipt does not qualify the 45th test. Do not
   promote skipped, queued, build-failed or stale-SHA jobs.
2. Require the separate manually dispatched
   `r9_credssp_owner_candidate=true` gate at the nominated SHA and
   independent owner authorization for **each** physical attempt.
   If upstream GSSAPI/OpenSSL/CAL compilation or any required producer is red,
   stop at offline validation, not a client connection.
3. On the **owner's approved canonical checkout**, after CI unblocks, the
   repeatable Linux build checks are:

   ```sh
   cd ~/rdp-server
   git switch main
   git pull --ff-only origin main
   git rev-parse HEAD                   # compare privately with nominated SHA
   cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
   cmake --build build --parallel 2
   ctest --test-dir build -C Debug --output-on-failure
   cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
   cmake --build build --parallel 2
   ctest --test-dir build -C Release --output-on-failure
   ```

   The R9 sanitizer workflow in `.github/workflows/ci.yml` owns the
   fail-closed `r5_expected_test_count=45` selector, required-name sentinels,
   and instrumented Xvfb CTest execution. Confirm its **exact SHA**, all
   45 individual results and both required regressions; do not substitute
   the unsanitized full CTest count for that receipt.

## Private physical procedure — prepare only; never auto-execute

The following commands are **read-only pre-listener checks** to be run only
on the owner's authorized machine, not by the validator or CI:

```sh
id -u
printf 'session-present=%s display-present=%s\n' "${XDG_SESSION_ID:+yes}" "${DISPLAY:+yes}"
loginctl show-session "$XDG_SESSION_ID" \
    -p Type -p Seat -p Active -p State -p LockedHint -p User
```

Record only typed facts in the manifest. The owner must privately establish
`Type=x11`, graphical `Seat=seat0`, `Active=yes`, unlocked current
session, display actually selected by the app, and the server process UID
equal to that session's owner UID (after launch, privately compare
`ps -o uid= -p <approved-server-pid>` to the session user). Never publish
the UID, session ID, username, display/XID, destination or client logs.

1. **Before listener:** start the normal GUI with **Sharing OFF**. Verify
   no listener and no native XCB/XShm/XDamage/XFixes/RandR/XTEST owner.
   Record the exact repository SHA and client type/version. Configure the
   standalone Username and independently chosen Session Password privately;
   never put the password, its hash or the Username in the manifest.
2. **Consent:** explicitly turn Sharing ON in the owner GUI. Observe a fresh
   owner grant/consent generation and enabled listener. If there is no explicit
   grant, record `owner_grant_recorded=false` and do **not** mark admission
   PASS. Record whether selected/saved Username, Session Password and
   credential entry intentionally match (`true`, `false` or `null`).
3. **Remote authentication:** from the separately authorized client (Windows
   App or mstsc), privately record the bounded R10 accepted-client correlation
   ID as `provenance.attempt_id`, then observe TLS, Type 1, Type 2, Type 3,
   pubKeyAuth, authInfo and `CredentialsVerified` for that **same
   connection**. Every observed downstream producer receipt must carry that
   same attempt ID. A client FIN before Type 3 is not a credential failure or
   successful admission.
4. **Independent R2:** observe genuine native Admission using the real R2
   protected visitor, exact principal/TLS binding, graphical seat0,
   current/unlocked session, process/native UID equality, fresh Linux
   session generation and current consent epoch. Record independent
   R2 admission generation and independently observed R2-bound consent
   generation (`generations.admission_consent`), equal to the owner grant.
   A positive Admission must also record the same accepted-client attempt ID
   in `provenance.native_admission_attempt_id` and the fixed producer class
   `linux-console-admission-broker`. Those values document where the
   observation came from; they are never authorization. Never invent a
   positive lease from client credentials, matched generations, geometry or
   XIDs.
5. **Graphics:** after R2 PASS, observe R3 MCS/GCC/licensing, Share and
   GraphicsReady separately, then actual native XShm first-frame delivery
   and its **matching** R4 ACK in the same capture generation. Copy the same
   private attempt ID beside the observed Share, first-frame and ACK producer
   receipts; a crossed ID is a contradiction even when all generations match.
   Record only typed PASS/FAIL/NOT_OBSERVED; do not store pixels or borrow
   buffers.
6. **Input and resize:** with owner-authorized input, count committed
   keyboard and mouse posts (no key/button payloads). Correlate the observed
   input dispatch and RandR replacement with the same private attempt ID.
   Confirm XFixes cursor observation privately. Trigger an authorized RandR
   resize, record the strictly replacement capture generation and rejection
   of the retired frame/ACK/geometry. No event/XID or correlation scalar
   becomes admission authority.
7. **Retirement:** in separate authorized runs exercise Stop, lock, logout
   and switch-user. Record each event, whether R2 lease and X11 capture
   were terminally retired, session-generation change (where observed),
   and **zero** posts or frames after revocation. A lock or Stop may keep the same
   Linux session generation; logout/switch-user must not claim a live
   retired session as a replacement. Native loss must suppress XTEST
   cleanup posts; do not store XCB event or XShm pixel references.
8. **Fresh reconnect:** after session restoration and **another explicit
   owner grant**, independently re-check the current unlocked seat0/UID owner,
   authenticate again through CredentialsVerified, then record new consent, R2
   admission and X11 capture generations. The reconnect must have a new
   private `reconnect.provenance.attempt_id`; copy that same ID beside its
   CredentialsVerified, native Admission, Share, first-frame and ACK producer
   observations, and record the same fixed R2 admission producer class.
   Record the new R2-bound
   `reconnect.admission_consent_generation` equal to the fresh owner grant.
   A valid reconnect must not reuse the retired attempt ID, R2 admission or
   capture generation. Require new Share/GraphicsReady, actual new first frame
   and matching ACK independently. If not reached, record `NOT_OBSERVED`,
   never an inferred PASS.

A private record is one **same-attempt** observation, not a merger of
unrelated client/server attempts. Use separate records for separate Stop,
lock, logout and switch-user runs. No steps above were executed during
round-one preparation.

## Independently pinned accepted connection and owner grant

The closed private v2 manifest checks stage attempt IDs and consent epochs,
but cannot detect a *whole* internally consistent relabeling to a different
R10 accepted client or an independently incorrect owner epoch. Privately
copy **separate** R9 nominated source SHA, R10 accepted-client ID for each
attempt and owner sharing-grant generation, rather than copying these from
the manifest being validated. A matching native logind session number does
not establish that the accepted connection is the same. An R10 client ID
is scoped to its actual process/listener lifetime: record listener
Stop/replacement separately and do not infer uniqueness across restarts.

The required independent local-only pins file is closed and bounded to
4 KiB. Example fields and values are **synthetic**, not acceptance evidence:

```json
{
  "schema": "rdp-server.linux-x11-owner-evidence-pins.v1",
  "source_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "accepted_client_id": 100,
  "owner_consent_generation": 10,
  "reconnect_accepted_client_id": 101,
  "reconnect_owner_consent_generation": 11
}
```

Use JSON `null` for genuinely unobserved initial/reconnect fields. Both
files remain private (mode 0600); no client ID, consent generation, source
SHA, usernames, addresses, audit IDs, XIDs, pixels or input payloads enter
the public output. The independent receipts help detect accidental
cross-connection and cross-epoch splices, but cannot cryptographically
attest a handwritten manifest or authorize an R2 lease.

## R10 borrowed-X11 teardown and positive frame handoff

On the serialized owner thread, revoke owner authority before further
network or native operations; retire the R8 clipboard first, then
`X11DesktopResources::retireAfterAuthorizationLoss()` so held XTEST
keys/buttons are cleared **without** releases into a replaced session.
Retire input, optional XI2 pointer observer, XDamage, XShm and cursor
children before the sole XCB connection; only then release the
R3/R2/authentication aggregate and sole R1 TLS socket, followed by the
listener. A graceful held-input release is permissible only while native
authorization is still current. Never retain borrowed pixel spans or
XCB event references across callback return. Replacement must create
a fresh R2 lease and capture generation.

For a real accepted Linux frame, separately correlate source SHA, exact
R10 accepted connection, CredentialsVerified, current R2 seat0 owner
and explicit consent epoch, R3 Share and joined graphics DVC,
CREATE_SURFACE/MAP_SURFACE_TO_OUTPUT accepted-byte receipts,
current XShm geometry/capture generation, complete R1 frame delivery and
the matching current-generation R4 FRAME_ACK. R10's
`DesktopVisible` after completing the write is not sufficient for
client-visible acceptance without the matching ACK. Prove a new
post-RandR frame/ACK, zero input/frame publication after revocation,
and a fresh owner on reconnect. Missing evidence is NOT_OBSERVED;
physical owner testing is still unauthorized.

## v2 manifest contract

The standalone validator is `scripts/linux_x11_owner_evidence.py`.
Its sole input is JSON of schema `rdp-server.linux-x11-owner-evidence.v2`;
v1 is intentionally rejected because it cannot prove same-attempt producer
correlation. The public redacted projection remains v1 because its shape is
unchanged and contains no attempt IDs.
the complete required key set is shown below. All missing/unobserved
generations must be JSON `null`; all stage values are exactly
`PASS`, `FAIL`, or `NOT_OBSERVED`. Private generations are
nonzero integer scalars; no credential values or raw native IDs are accepted.
The `source_sha` must be the exact tested checkout commit.

```json
{
  "schema": "rdp-server.linux-x11-owner-evidence.v2",
  "source_sha": "<replace-with-exact-40-hex-sha>",
  "provenance": {
    "attempt_id": null,
    "credentials_verified_attempt_id": null,
    "native_admission_attempt_id": null,
    "native_admission_producer": null,
    "share_attempt_id": null,
    "first_frame_attempt_id": null,
    "matching_ack_attempt_id": null,
    "input_attempt_id": null,
    "randr_attempt_id": null
  },
  "client": {"type": "unobserved", "version": "unobserved"},
  "sharing": {"initial": "OFF", "enabled": false, "owner_grant_recorded": false, "consent_generation": null},
  "credentials": {"username_matches": null, "session_password_matches": null, "selected_credential_matches": null},
  "seat": {"graphical": null, "seat0": null, "unlocked": null, "current_session": null, "process_uid_matches_owner": null},
  "generations": {"linux_session": null, "r2_admission": null, "native_capture": null, "admission_consent": null},
  "frame": {"first_frame_capture_generation": null, "ack_capture_generation": null},
  "stages": {
    "tls": "NOT_OBSERVED", "type1": "NOT_OBSERVED", "type2": "NOT_OBSERVED",
    "type3": "NOT_OBSERVED", "pubkeyauth": "NOT_OBSERVED",
    "authinfo": "NOT_OBSERVED", "credentials_verified": "NOT_OBSERVED",
    "native_admission": "NOT_OBSERVED", "mcs": "NOT_OBSERVED",
    "share": "NOT_OBSERVED", "graphics_ready": "NOT_OBSERVED",
    "first_frame": "NOT_OBSERVED", "matching_ack": "NOT_OBSERVED",
    "keyboard_dispatch": "NOT_OBSERVED", "mouse_dispatch": "NOT_OBSERVED",
    "randr_replacement": "NOT_OBSERVED"
  },
  "input": {"keyboard_posts": 0, "mouse_posts": 0, "posts_after_revocation": 0},
  "randr": {"replacement_capture_generation": null},
  "retirements": [],
  "reconnect": {
    "observed": false, "owner_grant_recorded": false,
    "consent_generation": null, "admission_consent_generation": null, "linux_session_generation": null,
    "r2_admission_generation": null, "native_capture_generation": null,
    "provenance": {
      "attempt_id": null,
      "credentials_verified_attempt_id": null,
      "native_admission_attempt_id": null,
      "native_admission_producer": null,
      "share_attempt_id": null,
      "first_frame_attempt_id": null,
      "matching_ack_attempt_id": null
    },
    "seat": {"graphical": null, "seat0": null, "unlocked": null, "current_session": null, "process_uid_matches_owner": null},
    "stages": {"credentials_verified": "NOT_OBSERVED", "native_admission": "NOT_OBSERVED", "share": "NOT_OBSERVED",
               "graphics_ready": "NOT_OBSERVED", "first_frame": "NOT_OBSERVED",
               "matching_ack": "NOT_OBSERVED"},
    "first_frame_capture_generation": null, "ack_capture_generation": null,
    "posts_after_revocation": 0
  }
}
```

An observed retirement is a record such as
`{"kind":"stop","r2_retired":true,"capture_retired":true,
"posts_after_revocation":0,"frames_after_revocation":0,"linux_session_generation_after":123}`
with **owner-private illustrative** scalar generation (never a public value).
Allowed kinds: `stop`, `lock`, `logout`, `switch_user` (at most one retirement per same-attempt record).
The template's SHA is deliberately invalid; replace it before validation.
A syntactically valid all-`NOT_OBSERVED` record proves no physical success.

Run **offline only**, with a private input file restricted to the owner:

```sh
umask 077
python3 scripts/linux_x11_owner_evidence.py --input /private/path/attempt.json --pins /private/path/independent-pins.json > /private/path/redacted.json
python3 tests/test_linux_x11_owner_evidence.py --script scripts/linux_x11_owner_evidence.py
```

The validator cross-checks independently observed R2-bound consent generations
against owner grant generations at initial Admission and reconnect. It also
requires each observed CredentialsVerified/native Admission/Share/frame/ACK
producer receipt to match its containing attempt ID, requires input/RandR
observations to match the initial attempt, requires the native Admission
producer class to be `linux-console-admission-broker`, and rejects reconnect
attempt-ID reuse. These are provenance checks, not authority checks. An
admitted session may legitimately have no capture generation until graphics
begins; admission alone never proves Share, first frame or input.

The validator requires each reported first-frame generation to equal its active native capture generation and each matching ACK generation to equal that first-frame generation (including reconnect). It rejects crossed producer-attempt IDs, contradictory status/generation/input claims, extra
keys (including any raw UID, session ID, Username, destination, XIDs, pixels
or input payloads), duplicate JSON keys and oversized input. Its stdout is
allowlisted to typed stages/retirement outcomes and non-identifying
generation-change booleans; source SHA, client version, numeric generations,
counters and all private identifiers never appear in that projection.
Neither the validator nor its tests imports or calls the R2 native visitor,
X11 capture, event polling, XTEST or authentication components.

**Lifetime audit:** R2's synchronous `visitNativeDesktopSelection` remains
the sole native authority boundary; its borrowed view cannot escape. R10
constructs the native aggregate only after GraphicsReady through that
visitor. R5's `consumeR4Frame` observes the borrowed XShm span only inside
the callback and validates aggregate/capture/geometry *after* callback
return; native loss suppresses input releases, retires children before XCB
and invalidates prior event, XID, frame and native capture generations.
This new offline JSON path stores **only copied scalar facts** and cannot
extend any native lease, XCB event, XShm pixel or credential lifetime.
