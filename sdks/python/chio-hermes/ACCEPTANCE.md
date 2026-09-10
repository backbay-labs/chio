# Hermes acceptance record

Status: **not accepted**. This is one required integration in the six-host
program. No result establishes another host's acceptance. Confidence in source
inspection and retained observations is high; completion remains unresolved.

## Subscription continuation candidate (r15)

The API-credit failure retained with r11 is no longer an inference blocker.
Pinned Hermes supports native `codex_responses`; the installed r15 candidate
uses that transport through the protected parent relay with the existing native
Codex ChatGPT login cache and explicit `gpt-5.5` model. The guest receives only
an ephemeral loopback token. It receives neither the provider credential nor
kernel/journal authority. Native login owns token renewal.

[Subscription evidence](evidence/2026-09-09/subscription-r15/) identifies the
cold-installed wheel, source hashes, commands, raw host output, gateway delivery
records and independent resource observations. Wheel SHA-256:
`625979d5331796e7aef5906e69e3e2c746796aa570291af026c305ed4227c818`.
It retains supervisor repair `049018b78` from source base `7cfc241f6`.
The designated kernel binary is
`33dd1dea21a4ca5ecddeab4f30f6b06b0b90c513f0987aef552b0633d9da1e25`;
resource image `sha256:188cb84d5d0bb4063d4ce5a3b9c3832445a5acda5604911cda80a9136d1850a0`.

Actual subscription inference passed write/edit/read/list: four resource-side
dispatch rows, four completed verified outcomes, four native-history delivery
acknowledgments, and exact independently observed final contents. Secret read
and forbidden write each reached the real host tool path, returned denied and
produced zero new dispatches or resource changes. Direct probes under the exact
successful sandbox could not read the native auth cache (including its Data
volume alias), read the gateway configuration, or connect to the kernel port.

Failed predecessors are retained separately. r12 requested `gpt-5.4`, which
this subscription rejected; r13 sent the unsupported `max_output_tokens`
parameter. Both produced zero tool dispatches. r14 completed one real write,
then refused opaque provider reasoning on the next model request and correctly
reported unresolved with no delivery acknowledgment. Explicit operator delivery
export and acknowledgment subsequently reconciled that same retained authority;
one native read followed, with no repeated write or resource-byte change.
r15 removes opaque reasoning and provider item references while preserving
complete inline function history for signed outcome verification.

Owned component suite: **261 passed, four legacy opt-in skips unresolved**.
The current installed candidate also completed aggregate budget exhaustion,
capability and credential revocation, actual capability expiry, wrong identity
and scope, seven approval stages, foreign receipt/wrong signer/request-ID
substitution, native-history result substitution, concurrent owners, kernel
loss/malformed response/timeout, gateway loss, SIGTERM cancellation and launcher
SIGKILL. Original authorities remained fenced after uncertain results. Where a
trusted completed owner result existed, explicit import or delivery export and
acknowledgment restored a native read without repeating the write.

The [current gate and boundary record](evidence/2026-09-09/subscription-r15/COVERAGE.md)
maps each observation to retained raw evidence, separates startup refusals from
native dispatch tests, and names the four unresolved legacy tests. Current
plugin omission exposed no alternate tools; missing, crashed and timed-out
gateway startup prevented the native host from starting. Current OS probes
denied direct and descendant access to operator data, cross-profile data,
unrelated network and shell execution. Offline candidate replacement and
removal were rehearsed. This is a qualified local candidate, **not accepted
publication**: I08 still requires publication of the compatible artifact set
and the applicable release checks. These observations do not accept other
hosts or the six-host program.

An additional narrow review closed five previously untested cutpoints on the
same installed r15 artifact. Live subscription runs confirm cancellation before
kernel dispatch, a refused gateway route while the kernel remains live, and
bridge journal write failures before reservation and after the resource effect.
A separately labeled provider fixture delivered two calls in one actual Hermes
assistant turn: one verified effect completed, the second was not dispatched,
and the launcher reported incomplete work. These bridge journal tests do not
establish behavior under kernel receipt-store or signing failure. The separate
kernel storage tests below establish actual SQLite write-contention behavior;
signing-failure behavior is not inferred from either set of storage tests.

The same r15 host also passed five exact alternate-path/tool denials: forbidden
`edit_file`, secret `edit_file` with `dryRun: true`, `list_directory` on the
secret file, normalized secret read and normalized forbidden write. Every case
records the exact native arguments and returned tool call, a verified denial,
zero dispatches and an unchanged independent resource snapshot. See
[all five runs](evidence/2026-09-09/subscription-r15/alternate-paths/).

Three fresh dedicated owners now have real kernel storage-failure evidence
under the same r15 wheel. Each first completed and acknowledged one native
positive write. Locks on the receipt store after an effect, admission store
before dispatch, and admission store after an effect yielded respectively
one, zero and one effects, with no delivery ACK. Twelve exact native same/new
action retries across unlock and same-owner restart produced no further
dispatch. Original configuration, session, journal and databases were retained.
[Kernel storage evidence](evidence/2026-09-09/subscription-r15/kernel-storage/)
includes read-only DB snapshots and independent resource observations.

A separate healthy owner supplied three paired read-only timing observations.
Native logged tool intervals were 490, 590 and 510 ms (10 ms resolution), versus
direct installed-bridge execution intervals of 493.979, 493.591 and 446.094 ms.
Total native process times were 13.519, 12.422 and 12.325 seconds. Startup and
model latency cannot be separated from these observations. All six reads are
independently audited and bytes stayed unchanged. See the
[timing evidence](evidence/2026-09-09/subscription-r15/operational-timing/) and
coverage record for the method, all differences, operator interventions and
limits; these are not a general overhead or performance guarantee.

## Candidate and baseline identities

- Chio base: `f5566d9a765c21cb36652a99c79de64968a656bf`.
- Host: NousResearch/hermes-agent v0.20.5 (2026.8.19), revision
  `175054c14b54404663d8614a178280cffe6062eb`, Python 3.11.3.
- Runs used a tracked-only archive of the installed revision. Unrelated
  upstream untracked files and the normal Hermes profile were preserved.
- Plugin baseline: project 0.1.1, manifest incorrectly 0.1.0. Candidate 0.1.2.
  [Baseline identities](evidence/2026-09-09/baseline.json) record OS,
  architecture and preliminary wheel hashes.
- Legacy source SDKs: `chio-sdk-python` 0.1.0, `chio-code-agent` 0.1.0,
  `chio-adapter-base` 0.2.0. Current id-only evaluation intentionally cannot
  authorize. Mock-client allows do not prove production useful operation.
- Restricted candidate: four exact MCP tools, no native/custom toolsets,
  no general/project plugins, no dynamic tool search. See
  [inventory](ACTION_INVENTORY.md) and [runbook](README.md).
- Live model: OpenAI `gpt-4.1`, explicit HTTPS endpoint, 4096 output-token cap.
  Initial run failed because default 65536 exceeded that model's cap; no tool
  ran in that attempt.
- Resource: official filesystem MCP server in designated image
  `chio-required-agent-filesystem:20260909`, volume
  `chio-required-agents-20260909` for historical source runs; final artifact
  runs used `chio-required-agents-final-20260909`. Hermes had no resource mount.
  Independent read-only/network-disabled container observed hashes/timestamps.
- Live gateway: `@chio/bridge` 0.3.0. Historical source and packed candidate
  runs remain separately identified. Per-run `launch.json` records script/config
  hashes. The final-candidate evidence directory records immutable kernel and
  wheel/bridge identities; newer session-credential changes need another rerun.

## Historical gate status (original packed candidate)

| Gate | Observed | Remaining acceptance |
| --- | --- | --- |
| I01 | Candidate wheel installed offline into a fresh Python venv using only a reviewed wheelhouse; pip check and entrypoint succeeded. Bridge installed offline with empty npm cache and invalid registry. Real host exposed exactly four MCP tools. | Publication and complete clean upstream host install remain unresolved. Existing interpreter dependencies were reused for host qualification. |
| I02 | Installed wheel + packed bridge + final kernel: real Hermes/OpenAI write-edit-read, three completed verified receipts, independent observer exact 28-byte final output. | Final session-only credential/artifact rerun and promised workflow qualification. Local shell/test/git are unavailable. |
| I03 | Forbidden write and secret read denied with verified receipts and unchanged resource hashes/timestamps. Eight forced alternate names left no local marker; two host name repairs reached kernel-denied MCP calls. Home read/write and Unix-socket direct/descendant canaries denied. | Same-UID OS privilege boundary incomplete: operator files in temporary directories remain readable and gateway journal writable to an arbitrary process primitive. Static model tool restrictions do not cure that. |
| I04 | Installed wheel: malformed context, 100ms preflight timeout, gateway startup crash prevented new protected effects. A post-dispatch proxy disconnect yielded unknown outcome and fenced retry/restart. | Remaining in-session interruption cutpoints and final credential artifact rerun. Shared kernel was not killed for this host. |
| I05 | Forbidden scope and revoked capability denied through actual host with verified receipts. Historical wrong subject/capability and missing-session cases rejected before dispatch. | Expiry, escalation, aggregate budgets, approval states and final identity reruns. Attempted fresh-authority restoration returned not-dispatched and did not pass. Bootstrap bearer can initialize new authority; shared credential repair pending. |
| I06 | Useful/denied calls carry verified caller/request-bound receipts. Actual SSE output substitution retained receipt validity but produced unknown outcome because output did not match; no false verified success. | Wrong signer/request, forged/malformed receipt envelopes and final artifact rerun. |
| I07 | Actual post-dispatch disconnect and substituted-output cases each forwarded one tool call; second same-process attempt and second host process stayed fenced. Resource observer confirmed the original effect. Unknown was not silently redispatched. | Cancel, parallel calls, handoff and other restart cutpoints. Resume is not exposed. Journal integrity against a process with write access remains unresolved. |
| I08 | Fixed launcher, runbook, offline artifact installation, static restriction probes and retained evidence delivered. | Publication, clean full host installation, upgrade/removal rehearsal and unresolved required tests. |

## Bounded diagnostics

`evidence/2026-09-09/probe-2` drives an actual pinned CLI using a local
deterministic completion fixture. Only inference is replaced. This narrower
contract has independent marker observations:

| Case | Marker |
| --- | --- |
| Native write, no Chio hook (observer control) | Created, exact content |
| Repaired hook loaded | Absent |
| Callback raises | Created |
| Malformed block response (missing message) | Created |
| Plugin raises during load | Created |

`probe-1` preserves failed harness startup attempts: archive extraction was
in progress and resolving a venv symlink selected the wrong Python. These are
not security results. `restricted-native-terminal` records the initial forced
shell-descendant call with no marker; that probe still used dynamic tool-search
defaults. Final candidate explicitly disables those defaults.

Initial launcher regressions: 216 passed; four legacy sidecar tests skipped
behind opt-in and remain unresolved. Ruff passed. More host cases and final
artifact checks are recorded separately, preserving earlier failures.

The `fault-corrupt-result` attempt did not reach a protected tool call: the
retained kernel session returned HTTP 404 during context preflight. Both the
initial process and restart reported not-dispatched; the proxy forwarded zero
tool calls. This is a failed fault-injection setup, not a passing substituted
result or unknown-outcome recovery test. It must be repeated with fresh live
authority. Per-case private credential configurations are deliberately excluded
from committed evidence; their hashes and the nonsecret host configuration,
request method trace, tool outcomes and operation journals are retained.

## Final candidate observations

[Final evidence](evidence/2026-09-09/final-candidate/) includes the exact kernel
source `04b7d366d62c886c39bc202f58ef0d44e8f5aee7`, binary SHA-256
`e7539855906bd5eb7b4eb2e5a12ca0533889cf61ced3bf4adf5850b792aa6447`,
image/policy/signer identities and wheel hashes. The bridge archive tested here
has SHA-256 `68b5c46638449710e3251f41aa1317f364c24138ae6cba3f45aeea51960ef3ff`.
The historical `1898aa9d5` kernel binary hash was not recorded before overwrite;
do not assign the final binary hash retrospectively.

`packed-useful` uses the installed wheel entrypoint from outside all source
checkouts. Its write, edit and read journals are completed and verified. The
resource observer confirms the expected 28-byte `hermes-packed.txt` result.
`packed-forbidden-write`, `packed-forbidden-read` and `packed-revoked` have
verified denied receipts. Forbidden resource hashes/timestamps remained
unchanged and the revoked marker is absent. `packed-restored` is a failed
restore attempt: process exit zero only means the CLI ran; the journal reports
not-dispatched and no restoration effect exists.

`native-final-*` invokes the installed restricted launcher, with deterministic
inference only, for terminal/shell descendants, execute_code, delegate_task,
process, dynamic tool_call, another MCP server, MCP resource helper and a forged
Chio name. Each captured model registry contains exactly the four Chio MCP
tools. The alternate MCP write and resource-helper names were repaired by the
host to available Chio file tools and then denied by the kernel. No local
marker appeared. These forced dispatch observations are not real inference
acceptance for those denied tools.

`packed-fault-corrupt-result` preserves another preflight HTTP 404 harness
failure: the proxy posted to the endpoint origin instead of the SDK `/mcp`
route. `packed-fault-corrupt-result-2` reached the effect, then failed parsing
an SSE body as JSON. That failure is evidence of post-dispatch transport loss,
unknown outcome and fencing, not successful result substitution.
`packed-fault-corrupt-result-3` fixes both issues: trace records one actual SSE
result substitution, journal state unknown with a valid receipt, and retry
plus a new Hermes process forward no second tool. The observer confirms the
initial expected effect. The substituted body was not trusted as the result.

The macOS profile adds inherited home-data/write and Unix-socket restrictions;
there is no unsandboxed fallback. `seatbelt-canaries-5` verifies positive
unsandboxed controls plus six denied direct/descendant attempts. Earlier
canary/runtime attempts failed because of runtime path or DNS allowances and
are retained. `seatbelt-useful-4` completed real useful work after the exact
system DNS resolver exception. Its first observer comparison accidentally
expected a newline; the corrected comparison confirms the actual 27-byte body.

The sandbox uses allow-default outside its explicit denials. An independent
read-only process probe under the exact retained profile confirmed that
private gateway and operator preparation files in `/tmp` are readable, journal
write permission exists, and kernel TCP is reachable. No values, HTTP calls,
session issuance or journal writes were used by that probe. This demonstrates
an OS boundary gap if a process-level execution primitive is available; it is
not evidence that a native model tool was reachable. Operator credentials must
be outside agent-readable scope and gateway admission must use session-limited
authority. Do not claim complete privilege separation or acceptance here.

Latest owned unit suite: **218 passed, 4 skipped**; Ruff passed. The four
legacy sidecar skips remain unresolved. Failed initial wheelhouse installation
(no pip in the existing Hermes venv, then missing downloaded dependencies) is
retained next to the successful offline consumer installation logs.
