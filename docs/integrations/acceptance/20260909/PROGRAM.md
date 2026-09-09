# Required six-host integration execution record

Status: **in progress, zero of six integrations accepted**. Confidence is high
in the recorded observations and unresolved failures. No source commit, unit
test total, locally installed package or historical host run closes I01-I08.

The authoritative requirement is planning commit
`d1d99f881ed2547367e45d1715f3c41c8c21589d`, document
`docs/strategy/chio-direction/19-priority-agent-integrations.md`, SHA256
`716c066323889ce54f0dfe6988dfbc7fa76b0c27c8afc7c8d0287f686b786099`.
That planning checkout has a different Git common directory from the main
kernel checkout. Its untracked document 13 was preserved. The initial paths,
revisions, dirty files, environment and document hashes are in
[source-baseline.json](raw/source-baseline.json). All six remain mandatory;
three accepted systems would only be an intermediate milestone.

## Current host records

Paths in this table are relative to `/Users/connor/Medica/backbay/standalone`.
Each plugin worktree is `.worktrees/required-agent-integrations-20260909` unless
another path is shown. Exact source and package dependency snapshots are in
[source-checkpoint-preack.json](raw/source-checkpoint-preack.json). These are
local candidate identities, not a published version combination.

| Host | Pinned runtime | Recorded implementation and observations | Remaining acceptance work |
|---|---|---|---|
| Claude Code | 2.1.266 | `chio-claude-code-plugin/acceptance/2026-09-09/REPORT.md`: restricted launcher, real host with local Messages fixture, actual kernel write/edit/read/list, disabled native tools, denials and receipt fault cases | Process sandbox and HTTP bridge completed an actual-host/local-model-fixture workflow on the acknowledgement kernel. Authenticated model access, additional boundary/fault tests and approvals remain and usable recovery; publish tested artifacts |
| Codex | 0.153.4 | `chio-codex-plugin/acceptance/2026-09-09/final/FOLLOWUP.md`: actual provider and host workflows, independent effects, hooks fail open, restricted launcher and truthful terminal status repairs | Actual provider/host write-edit-read-list passed in the default-deny process boundary on the acknowledgement kernel. Rerun wrong-resource prevention before effect, full budget/recovery, owner acknowledgement and approvals on final artifacts; publish |
| Cursor | GUI 3.19.13; CLI 2026.09.08-6caf4ff | `chio-cursor-plugin/evidence/final/BOUNDARY-REVIEW.md`: extension installation/activation/removal, real MCP discovery, actual process probes | Isolated authentication missing; hosted AgentService exposes remote/cloud tool paths whose prevention is unqualified. Protected prompt mode must refuse until its bounded protocol is established. Useful real workflow and all dependent gates unresolved |
| Hermes | 0.20.5; upstream `175054c14b54404663d8614a178280cffe6062eb` | `arc/.worktrees/hermes-required-integration-20260909/sdks/python/chio-hermes`: pinned public source installation, restricted four-tool host, real provider/kernel effects, receipt fault and restart cases | Qualify tightened process confinement and local model relay with final gateway; owner acknowledgement, host approvals and full I01-I08; four legacy opt-in sidecar skips remain explicit |
| Pi Agent | `@earendil-works/pi-coding-agent@0.85.1`; upstream `d981de1229ef899957bbe968bc8dcda02a21f477` | New `chio-pi-plugin`: stock AgentSession, one Chio custom tool, no discovered extensions or native tools, actual provider/kernel workflows, default-deny macOS process tests | Final bridge acknowledgement, approvals, budget and full recovery reruns; standalone installation and publication of the matching candidate |
| OpenClaw | 2026.5.20 (`e510042`) | `chio-open-claw-plugin/native/ACCEPTANCE.md`: native runtime plugin and container boundary, actual host/kernel effects and lifecycle tests; original hosted chat gateway preserved | New scoped credential/owner acknowledgement, approvals, native budget/revocation, latest profile repair and final packaging reruns; publish |

All eight gates are open for the program. Individual passed cases in host records
are bounded to their recorded source, artifact and configuration. Counts from
different builds cannot be combined into a final passing host matrix. No result
from one host substitutes for another host's missing case.

## Retained delivery failures and repairs

The bridge could acknowledge a completed result before the host received its
HTTP response. A dropped-response regression caused a replacement request to
execute. This is an I07 failure in the prior packaged HTTP candidates. The
repair retains the fence until an actual host returns the exact delivery proof.
Codex and Claude launchers consume host tool-result history. The earlier Pi guest proof
round trip was replaced by parent acknowledgement of native history. The later host records below qualify bounded repairs; full acceptance
is still open. The first repaired artifact had a malformed MCP capability
announcement and failed Codex and Claude initialization with zero dispatches.
Both failures are retained; no older passing host result closes this gap.

The corrected bridge artifact `b7785282b4f4` passed 11 actual kernel/resource
response-loss and recovery checks. Current cold-installed Codex, Pi and Claude
packages each independently exercised loss of the complete HTTP result before
the real host received it. Each original write occurred once, restart/resume
remained fenced, and explicit operator recovery permitted a subsequent useful
read without repeating the write. Codex and Pi used actual OpenAI providers;
Claude used its actual host with a local Messages fixture. The ordinary current
host cuts also passed: Codex five cases, Pi three cases, and Claude four cases.
These bounded observations do not close the complete I01-I08 matrix. See each
host's new `host-delivery` evidence directory. Hermes is being moved to the same
launcher-owned transport; OpenClaw and Cursor remain independently mandatory.


## Demonstrated shared repairs

- The shipped CLI reports `0.1.0` and has SHA256
  `c8d7ee8dc4ffdbed4a864b5984f931164a2b320e1a3d914adcb61d0636c354c3`.
  It lacks the required modern runtime surfaces. The new source retains that
  version label, so candidates are selected by source and binary hashes.
- SDK `0.1.1-rc.1` verifies the current content-addressed receipt with trusted
  signer and request/result bindings. Its package passed 108 tests and a clean
  consumer installation. The bridge returns distinct authorization, execution,
  evidence and unknown states. Old self-signer or local-policy checks are not
  accepted as kernel execution evidence.
- The MCP edge now exposes signed execution evidence and the actual resource
  owner before dispatch. An actual Codex test demonstrated that checking a
  wrong expected resource only after execution was too late. The repair must
  pass a final real-host rerun.
- A macOS SQLite identity defect prevented kernel startup. The existing local
  `fstat` repair was copied into this isolated worktree without altering the
  original dirty files and passed the targeted tests and lint.
- Native policy supports a single aggregate invocation limit. A demonstrated
  explicit-grant bypass of confirmation constraints is repaired. Exact bound
  approvals include caller/session, capability, request, tool and canonical
  arguments; pending/rejected approval does not dispatch the action. See the
  [approval record](../shared-approval-qualification-20260909/REPORT.md), including
  the failed predecessor candidate.
- Operator-issued credentials restrict the guest to one retained session and
  four tools. They cannot initialize new authority or reach admin APIs. The
  owner persists pending execution fences and exact completed-response replay.
  [Credential qualification](../../session-credentials/QUALIFICATION-20260909.md)
  records the first 24 actual kernel/resource cases. The
  [delivery acknowledgement candidate](../../session-credentials/DELIVERY-ACK-20260909.md)
  passed 34 actual kernel/resource cases, including complete response loss,
  erased guest journals, rotation, restart, forged acknowledgements and exact
  replay recovery. New request IDs remain fenced until verified completion has
  been durably retained and acknowledged.
- Receipt reconciliation repeatedly verified entire checkpoint histories while
  starting a session. A verified SQLite batch read replaces that repeated work
  without bypassing corruption checks. Combined library tests passed: control
  plane 764, kernel 1,104, remote MCP 53, MCP edge 112, schema 2. Startup timing
  [qualification](session-startup/README.md) remains separate from those functional tests.
- The isolated filesystem image now independently records forwarded requests
  and rejects imported symbolic links, hardlinks and special files before
  starting the official server. Five actual container cases passed. Audit write
  failure prevented the resource write; independent alias reads proved the
  negative controls were effective. See [resource observations](raw/resource-audit-run2/results.json).

## Candidate identities and limitations

The current kernel includes the terminal tool-error acknowledgement repair at
`d8c5f53705173e614a853bad6c0a85acfdf1212b`, binary SHA256
`33dd1dea21a4ca5ecddeab4f30f6b06b0b90c513f0987aef552b0633d9da1e25`.
It passed 38 actual kernel/resource cases and 55 remote library tests. The
predecessor mishandled a known filesystem error discovered by a clean-installed
Codex run. All earlier host passes remain bounded to their recorded artifacts.

The preceding acknowledgement kernel was built from
`8501b0058dfcbccd858ae2cdeda82948fb1e9a08`, equivalent to root code `31c28d05c3`.
Its SHA256 is
`0e683f6f7cc8f21816b10641e3c18fba2dd1445fbcd28752cd3260d8ac5edb5a`.
The bridge source `c77861d` produces the self-contained candidate tarball SHA256
`c22c8dd094e39249484b3f4631d9ee6728db76bfd9e6f1f767c22538ab18a0ff`.
It passed 116 component tests and an empty-cache offline consumer installation.
The launcher-owned HTTP transport keeps kernel credentials and durable journals
outside the guest process. Closing or killing the launcher closes the transport.
Shared real-kernel ordinary and approval cases are recorded in the bridge repo;
every host must still qualify that contract independently.

The historical combined pre-acknowledgement kernel was built from
`25d5717a5bcfd228391dbeee61d8d57f3c5e6177`, equivalent to the kernel crate contents
at root commit `f516b0d1e1`, and copied before any later build. Its SHA256 is
`d0b87623cb3dd227f79cd3178b32bb04e35b48ddcb9dab63c6598d79b8e13b66`.
The audited filesystem image identity is
`sha256:188cb84d5d0bb4063d4ce5a3b9c3832445a5acda5604911cda80a9136d1850a0`.
Neither artifact is a published accepted release. Earlier evidence naming
`e7539855906b...` or exploratory kernels remains historical. The oldest running
kernel's binary hash was not captured before the shared build path changed;
[its observations](raw/shared-exploratory-observations.json) explicitly retain
that missing provenance instead of assigning a later hash.

The resource runbook's initial restart test returned the recorded completed
write without overwriting an independent operator sentinel. Its subsequent new
read failed before dispatch. That is partial replay evidence and an unresolved
readiness failure, not a passing recovery gate. Raw stdout, stderr and the
independent observation are in [runbook-initial](raw/runbook-initial/observations.json).

## Delivery and next acceptance cut

The [resource-owner runbook](../../../../integrations/required-agents/README.md)
uses explicit kernel/image identities, isolated operator state, independent
resource and audit volumes, and retained databases. Host packages are built and
installed through cold consumer directories with self-contained Chio
dependencies; public upstream host dependencies stay explicitly pinned. Final
packages must be rebuilt after the acknowledgement/approval bridge contract is
settled, then installed and exercised through each real host.

The bridge implements explicit approval proposals/resume, durable delivery
acknowledgement and operator lock recovery. Outstanding work is real-host
qualification of those behaviors, final process boundaries and every remaining
host-specific I01-I08 case. Cursor authentication and its bounded
hosted execution contract, and Claude's isolated model credential, are external
inputs under investigation. Required checks that cannot run remain unresolved.
Publication must preserve the existing release and security gates. No public
release, independent adoption or research novelty is claimed by this record.

## Native HTTP host qualification and received-result repair

All six remain mandatory and unaccepted (0/6). Hermes source `65671a01c`,
qualified by `cbb5d5e0a`, completed useful write/edit/read/list through the real
Hermes/OpenAI host, plus forbidden read/write and final-response-loss recovery.
The cold-installed wheel has four useful deliveries, zero forbidden dispatches,
and same-authority restart fencing until the operator reads and acknowledges
the exact retained outcome. Python and descendant process probes observed the
selected TCP positive controls and denied home/other-profile data, filesystem
aliases, hardlinks, shell execution, Unix sockets and unrelated TCP access.
The initial framework-bootstrap probe failure is retained separately.

The native OpenClaw launcher now keeps kernel credentials and journals outside
the agent. Its cold-installed archive builds a pinned host image without a
private sibling or host filesystem share. Source `8928eba` and the owning
repository's `native/evidence/2026-09-09/http-host-delivery` record useful work,
forbidden read/write, response-loss recovery and substituted output through the
actual OpenClaw/OpenAI host, with independent resource observations. Native
container process boundaries and the remaining gates still need qualification.

Final-hop result substitution exposed a concrete evidence defect in Pi and
OpenClaw: both older guests accepted forged result text under an authentic
unchanged decision receipt, reported completion and acknowledged delivery.
Bridge `b8cef33` adds received-result verification, retaining the existing MCP
protocol. Its artifact SHA256 is
`eb4392bf298595d52d92610ea82c6e64d6f534718fe575bc5ea9a583c5810a4b`;
119 component tests passed without skips. Repaired Pi and OpenClaw guests now
verify the result hash and expected host operation before acknowledgement.
Both real hosts reject the same substitution, return unresolved, retain the
original resource read, and leave delivery unacknowledged. Each host's 18-test
component suite and its own real-host observations are retained separately.

Pi artifact SHA256:
`6c994035ef3d3b51f6f4db3859cead726afe9e5dc710642b782be9beeb466bbb`.
OpenClaw artifact SHA256:
`96f67ee343d14f7ba40d2ff6986fc3b79887ee53179a6399156249cee8ac5c79`.
OpenClaw image:
`sha256:38ab384535544261d851394a9d6ef59d9c6de5b7367652464f977f7a8bc890a6`.
All use kernel `33dd1dea21a4`; these are qualified subsets, not published
accepted releases. Full authority/approval/budget/revocation, kernel and plugin
faults, later crash cutpoints, cancellation and lifecycle gates remain open.
Cursor's isolated authentication and bounded hosted execution contract and
Claude's isolated provider credential remain external inputs. No synthetic
fixture or another host's result closes those missing real-host cases.

The subsequent acknowledgement-confirmation-loss cutpoint failed in both Pi
`6c994035ef3d...` and OpenClaw `96f67ee343d...`. After receiving the signed result,
the guest sent its proof, but the HTTP acknowledgement response was lost. Both
reported uncertainty and, after restart with the same authority, dispatched a
replacement write. Each independent resource audit records two writes and the
replacement content. The owning repositories retain `ack-confirmation-loss`
evidence. Their preceding bounded passes do not resolve this I07 failure.

The repair under qualification moves acknowledgement into the trusted model
relay, after the native host echoes the full verified result in conversation
history. Bridge source `0d31365` exposes exact received-outcome acknowledgement;
its archive is `7d9e34f7408a316e35125982a23faaecfd2f31f4da6b50ca8eab287c2c918f67`.
The 119-test existing suite and expanded six-case HTTP suite passed. Pi and
OpenClaw package rebuilds and real-host reruns are required before claiming the
specific failure resolved. No host is accepted.

The native-history candidates now pass the specific predecessor ACK-response
fault with actual Pi and OpenClaw: each completed one original write, the
resource observer recorded one dispatch, and the parent journal confirmed the
result from native history. No guest acknowledgement response exists for the
injector to drop. Both candidates also passed their own five actual-host cases
(useful work, forbidden read/write, result loss/recovery and result substitution).
Pi archive: `380c7ab33de2dd5ccdfd5b3ff5b8ad079e87800d32d4282398ceefe2f7b712d3`.
OpenClaw archive: `f93ea8480937bf85fe07910a0260a24baaefc0089a4e3c213a311cb21efff0e1`.
Exact images, commands and observations are in each owning repository's
`evidence/2026-09-09/native-history-ack` record (under `native/` for OpenClaw).
Later host/plugin crash cutpoints and the full required matrix remain open.

## Current authority and received-result checkpoint

All six remain mandatory and zero are accepted. Exact artifacts and raw
observations are committed in each owning repository. The current source
checkpoints are Codex `cb2433d`, Claude `5a7d69a`, Pi `93f4567`, OpenClaw
`b3fb4fd`, and Hermes approval repair `c29b9d3c3`.

Codex, Hermes, Pi and OpenClaw each executed seven approval stages through the
actual native host and OpenAI provider: pending, missing decision, changed
arguments, approved resume, completed replay, pending rejection and rejected
resume. Only approved resume caused an effect. Exact native calls, arguments,
return identities and all additional model attempts are retained. Independent
resource observers saw one approved write, no substituted/rejected write and
no replay dispatch. Hermes initially omitted chio_resume from native MCP
filtering; its r7 resume observations lacked a native call and are failed
coverage. The r8 repair exposes this gateway control tool without widening the
four-tool session credential.

Aggregate budgets were exercised separately through each of those four hosts:
write/edit/read completed, the fourth list call received a signed invocation
budget denial, and the resource audit contains exactly three new dispatches.
Claude also passed this budget case through the actual executable and kernel,
with a local Messages fixture. No authenticated Anthropic result is claimed.

Final-hop result substitution exposed additional failures in Codex and Claude:
the old launchers acknowledged authentic delivery proofs carrying substituted
result bytes. Codex reported the forged content; Claude forwarded it in native
history to the local model fixture. Both repairs verify the complete received
outcome before acknowledgement and another model turn. Their new cold-installed
candidates reject the substituted result with zero acknowledgements. Codex also
passed useful work, forbidden reads/writes, response loss with fenced restart
and explicit recovery, approvals and the three-call aggregate budget. Claude
passed useful work plus forbidden/native probes, result loss and the budget
case using the local fixture. Previous failed evidence remains committed.

| Host | Current local candidate SHA256 | Evidence directory in owning repository |
|---|---|---|
| Codex | `860811efcdebea7a4c9fe4db7b9a4c9eb764b55c0fadd4dc6e9429447e7813b6` | `acceptance/2026-09-09/received-result` |
| Claude | `21129a251ff57f52024efeaa4cca4c1b74d8971b7ffb3ce81cb0701af20b64f8` | `acceptance/2026-09-09/received-result` |
| Pi | `b6f38bfb2c129e00d6e8c5c74b5b92ec4d527d26a81683316683abc690afac2c` | `evidence/2026-09-09/authority` |
| OpenClaw | `d7b364ff015b283907056064f8fa92658694b154f5217881ec77c97612863d2a` | `native/evidence/2026-09-09/authority` |
| Hermes r8 | `ae93ce01524b78a824a7a150dfa0367952c98b33c77ef270fce759415098aba2` | `sdks/python/chio-hermes/evidence/2026-09-09/authority` |

These five candidates use kernel `33dd1dea21a4`. The TypeScript candidates use
bridge `7d9e34f7408a`; Hermes r8 uses `b7785282b4f4` with its private complete
outcome verifier. Hermes budget evidence in the authority directory uses r7,
as its artifact record explicitly states. No results across different builds
are silently combined into an accepted matrix.

OpenClaw's actual container boundary probe passed in the running host and a
Node descendant: isolated state writes worked, protected resource/operator
files, Docker socket, control and plugin writes, root writes and direct host
TCP were denied. The trusted relay's TCP positive control succeeded with zero
guest connections observed. Host image for the r2 archive is
`sha256:98404ca86440e10066733abc421e8af82a40571f46d244c0dec14ea99d5a6d08`.
The earlier probe image and exact evidence remain separately recorded in
`native/evidence/2026-09-09/container-boundary`.

Full remaining identity/scope/revocation, fault/cancellation/crash cutpoints,
and supported upgrade/recovery/removal qualification remain open. The public
installer still delivers the incompatible historical CLI. None of these
archives is a published accepted release. Cursor still requires isolated
host authentication and a bounded hosted protocol; Claude requires isolated
Anthropic provider access. Those external inputs do not waive other hosts'
remaining tests or the six-of-six completion requirement.
