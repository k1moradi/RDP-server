## R8 exact-SHA post-Share Clipboard denial qualification and current dependency graph (2026-11-01)

**Validated R8 source SHA:** `d241d4947f053227c7d35a02c882f0eca8089d52`,
GitHub Actions `41305124720`. This closes the pending execution evidence for
the strengthened Share-era Clipboard denial without changing production
Clipboard authority.

- Ubuntu protocol Debug and Release each pass **1090/1090** ordinary CTests.
  `security.macos-share-activated-clipboard-permission-denial`,
  `security.macos-share-activated-clipboard-scope-classifier-denial` and
  `security.macos-post-join-clipboard-view-input-denial` pass in both
  configurations.
- macOS protocol Debug and Release each pass **866/866** ordinary CTests; the
  same three R8 denials pass in both configurations.
- Windows Debug executes and passes all three R8 denials. Its full job then
  ends **905/908** on three independent positive Share/Graphics fixture
  teardown crashes. Agent R1 has since published
  `e28a8d5aae14f661e24d9279f7359731fa2a3901`, reordering the shared
  synthetic fixture so R2 retires before its borrowed R3 session. That source
  fix does not alter R8 production behavior; its exact-SHA hosted
  qualification is still pending at this record.
- The exact `d241d494` R9 ASan/UBSan job passes the fixed Clipboard selector
  **107/107**, separate destination finalization **1/1**, X11 callback
  retirement **3/3**, and static CLIPRDR **9/9**.

Dependency refresh confirms the former R8 construction blocker is resolved:
R10's persistent Linux post-Share scheduler now owns one
`LinuxPreparedClipboardOwner`, routes authenticated CLIPRDR through the
existing R2/R3 gateways, and uses the sole R1 TLS writer. This is composition,
not authorization. `kLinuxProductionClipboardActivationApproved = false`
remains literal, the product GUI continues requesting
`allowClipboard = false`, and the current macOS native issuer still selects
View plus optional Input only. Joined `cliprdr`, Licensed,
`ShareActivated`, GraphicsReady and channel membership remain independent
from native Clipboard authority.

No additional Share-era permission CTest is warranted. The existing concrete
R2 classifier regression already supplies decoder-valid FORMAT_LIST and
FILECONTENTS_RESPONSE on fresh joined-cliprdr ShareActivated fixtures with
View|Input and no Clipboard, then requires terminal R1/R2/R3 retirement and
rejected late activation, queued writes and write receipts. No physical
clipboard operation, file transfer, product-valid OS lease or native owner was
created.

**Remaining R8 activation blockers:** keep the Linux production gate false
until the separately required real Windows App video/input/Stop acceptance is
recorded, and do not enable macOS Clipboard until a genuine independent native
Clipboard issuer exists. The Windows positive-fixture crash has a published
source fix and is therefore no longer a design blocker, but whole-project
same-SHA Windows qualification remains pending until that fix is exercised.

