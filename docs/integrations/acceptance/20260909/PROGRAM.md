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
| Claude Code | 2.1.266 | `chio-claude-code-plugin/acceptance/2026-09-09/REPORT.md`: restricted launcher, real host with local Messages fixture, actual kernel write/edit/read/list, disabled native tools, denials and receipt fault cases | Qualify new process sandbox, authenticated model access, final kernel/bridge, owner acknowledgement, approvals and usable recovery; publish tested artifacts |
| Codex | 0.153.4 | `chio-codex-plugin/acceptance/2026-09-09/final/FOLLOWUP.md`: actual provider and host workflows, independent effects, hooks fail open, restricted launcher and truthful terminal status repairs | Qualify process confinement, rerun wrong-resource prevention before effect, full budget/recovery, owner acknowledgement and approvals on final artifacts; publish |
| Cursor | GUI 3.19.13; CLI 2026.09.08-6caf4ff | `chio-cursor-plugin/evidence/final/BOUNDARY-REVIEW.md`: extension installation/activation/removal, real MCP discovery, actual process probes | Isolated authentication missing; hosted AgentService exposes remote/cloud tool paths whose prevention is unqualified. Protected prompt mode must refuse until its bounded protocol is established. Useful real workflow and all dependent gates unresolved |
| Hermes | 0.20.5; upstream `175054c14b54404663d8614a178280cffe6062eb` | `arc/.worktrees/hermes-required-integration-20260909/sdks/python/chio-hermes`: pinned public source installation, restricted four-tool host, real provider/kernel effects, receipt fault and restart cases | Qualify tightened process confinement and local model relay with final gateway; owner acknowledgement, host approvals and full I01-I08; four legacy opt-in sidecar skips remain explicit |
| Pi Agent | `@earendil-works/pi-coding-agent@0.85.1`; upstream `d981de1229ef899957bbe968bc8dcda02a21f477` | New `chio-pi-plugin`: stock AgentSession, one Chio custom tool, no discovered extensions or native tools, actual provider/kernel workflows, default-deny macOS process tests | Final bridge acknowledgement, approvals, budget and full recovery reruns; standalone installation and publication of the matching candidate |
| OpenClaw | 2026.5.20 (`e510042`) | `chio-open-claw-plugin/native/ACCEPTANCE.md`: native runtime plugin and container boundary, actual host/kernel effects and lifecycle tests; original hosted chat gateway preserved | New scoped credential/owner acknowledgement, approvals, native budget/revocation, latest profile repair and final packaging reruns; publish |

All eight gates are open for the program. Individual passed cases in host records
are bounded to their recorded source, artifact and configuration. Counts from
different builds cannot be combined into a final passing host matrix. No result
from one host substitutes for another host's missing case.

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
  records 24 actual kernel/resource cases. A further delivery acknowledgement
  barrier is required for a completed response lost downstream of the kernel;
  that follow-on is not included in the pre-acknowledgement candidate.
- Receipt reconciliation repeatedly verified entire checkpoint histories while
  starting a session. A verified SQLite batch read replaces that repeated work
  without bypassing corruption checks. Combined library tests passed: control
  plane 764, kernel 1,104, remote MCP 53, MCP edge 112, schema 2. Startup timing
  qualification remains separate from those functional tests.
- The isolated filesystem image now independently records forwarded requests
  and rejects imported symbolic links, hardlinks and special files before
  starting the official server. Five actual container cases passed. Audit write
  failure prevented the resource write; independent alias reads proved the
  negative controls were effective. See [resource observations](raw/resource-audit-run2/results.json).

## Candidate identities and limitations

The combined pre-acknowledgement kernel was built from
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

Outstanding work includes explicit host approval proposals/resume, durable
delivery acknowledgement, operator lock recovery, final process boundaries and
all host-specific missing I01-I08 cases. Cursor authentication and its bounded
hosted execution contract, and Claude's isolated model credential, are external
inputs under investigation. Required checks that cannot run remain unresolved.
Publication must preserve the existing release and security gates. No public
release, independent adoption or research novelty is claimed by this record.
