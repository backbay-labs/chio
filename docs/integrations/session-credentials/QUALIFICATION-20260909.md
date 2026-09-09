# Session credential qualification, 2026-09-09

Confidence is high for the bounded behaviors below. This record is a shared
kernel qualification; it does not accept any of the six agent hosts.

Source baseline: `ca478135865238ed738723270f93da0c431232c2`, isolated branch
`codex/mcp-session-credentials-20260909`. The authoritative resource-context fix
`e0161f1c0` was cherry-picked as `ac547cc210`. Credential and owner call-fence
implementation: `30ad0ea0d74bb6609b4e2894bfafb7492445e068`.

The tested immutable CLI artifact is
`/tmp/chio-session-credentials-candidate-20260909/chio`, SHA256
`e73950c1586187f24b0250cb4e6753009e51652b64be4ea93840f07d4e664ae4`.
The CLI package still reports `0.1.0`; that version alone does not identify this
candidate. The independently observed filesystem resource is image
`sha256:0106edcb15a1c0d12d914ea0504f0e63ec85f5e6fdd3825b4d7a0d1367af3991`
(`linux/arm64`) running in Docker on macOS. The image contains the separately
pinned official MCP filesystem server. No public release qualification is claimed.

The full remote MCP library suite passed 53 tests with no failures, ignored
tests, or filtered cases. Five of these are new credential/store/owner-journal
regressions. A subsequent lint correction boxed the large reservation enum;
the resulting source passed `cargo clippy -p chio-mcp-remote --lib -- -D warnings`,
built the CLI, and passed the real resource cases below. The final combined
kernel build with the concurrent approval and startup repairs still needs its
own required checks. Cargo used the main checkout's target directory only as a
build cache, `CARGO_INCREMENTAL=0`, `CARGO_BUILD_JOBS=2`, and default debug profiles.

## Actual resource results

[Run 3 raw cases](evidence/20260909-run3/cases.json) records **24 passed, zero
failed, zero skipped**. Its private runtime is
`/tmp/chio-session-credential-resource-20260909-3`, random TCP port `56483`, and
Docker volume `chio-required-credentials-6e9501377a53`. The kernel was stopped and
the volume and databases retained. The test operated only on its own resources.

| Boundary | Observed behavior |
|---|---|
| Observer control | A direct resource-owner write changed the same forbidden file; the independent observer detected it, then verified restoration |
| Retained identity | Delegated context exactly matched the exchanged public binding; filtered tools matched the explicit selection |
| Useful work and retry | A real kernel-dispatched write changed the file; an exact retry returned the persisted identical result |
| Tool boundary | `move_file` was covered by the underlying wildcard grant but absent from the credential; the direct attempt was rejected and no move occurred |
| Issuance and operator APIs | Credential attempts to initialize, access admin health, exchange another credential, or revoke were rejected |
| Session boundary | Using the credential with another actual session produced no file |
| Authority | Expired credential, revoked credential, and revoked capability attempts produced no file |
| Kernel denial | Forbidden write preserved the original bytes; a later new request ID remained fenced |
| Aggregate budget | Eight permitted writes consumed the one shared grant; the ninth produced no overflow file |
| Lost response | A real write occurred before the transparent stdio relay delayed its response; the HTTP client timed out, then a new request ID was refused with no new effect |
| Rotation | Exchanging another credential retained the same capabilities and pending-call fence; no new effect followed |
| Restart | Known useful work resumed under the same retained session; uncertain work remained fenced after restart |
| Lost owner session state | Removing the test's retained session database made the old credential unusable; no new session was minted and no effect occurred |

[Request timings](evidence/20260909-run3/timings.json) are local observations,
not a comparative benchmark. The 14 HTTP-200 tool requests, including completed
replay and signed denials, ranged from 6.309 ms through 762.541 ms, with median
485.1815 ms. The intentionally timed-out request is excluded from that range.

## Retained failures and limits

[Run 1](evidence/20260909-run1/runner.log) stopped after two successful observer
controls because the harness passed both `--authority-db` and
`--authority-seed-file`, which the kernel correctly rejected. The harness now
uses only the durable authority database. [Run 2](evidence/20260909-run2/cases.json)
passed 23 cases; run 3 added actual credential rotation under an unresolved call.
No failed run was replaced with fabricated or synthetic acceptance.

Both operator secrets were scanned against all retained raw files and were
absent. Exchanged bearer secrets are absent from the evidence as well. The
operator-only runtime files intentionally retain credentials outside the
committed evidence. [SHA256SUMS](evidence/SHA256SUMS) binds the raw records.

Pending or uncertain calls have no automatic unfencing procedure. The delivered
operator procedure is inspect the original receipt/resource outcome, revoke
uncertain authority, and retain the history. An explicit new operator authority
decision must not be presented as an automatic retry. Host confinement, actual
host journal tampering, protected release publication, and the combined
approval/startup/credential artifact remain separate program requirements.
