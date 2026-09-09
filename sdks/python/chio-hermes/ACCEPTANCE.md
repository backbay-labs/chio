# Hermes acceptance record

Status: **not accepted**. This is one required integration in the six-host
program. No result establishes another host's acceptance. Confidence in source
inspection and retained observations is high; completion remains unresolved.

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
  `chio-required-agents-20260909`. Hermes had no mount or Docker socket.
  Independent read-only/network-disabled container observed hashes/timestamps.
- Live gateway: `@chio/bridge` 0.3.0 source candidate. Per-run `launch.json`
  records script/config hashes. Packed qualification is separate.

## Gate status

| Gate | Observed | Remaining acceptance |
| --- | --- | --- |
| I01 | Candidate wheels built/installed into disposable target; real host discovered plugin and four restricted MCP tools. | Public artifacts and clean documented end-user install unresolved. Existing interpreter dependencies reused for source qualification. |
| I02 | Real Hermes/live OpenAI/real kernel write-edit-read: three completed verified outcomes. Observer confirmed only `hermes-final.txt` changed. | Final packed combination and promised workflow qualification. Local shell/test/git not exposed by candidate. |
| I03 | Real forbidden write/secret read denied with verified receipts; observer hashes/timestamps unchanged. Forced native shell under static mode produced no local marker. Legacy mode failed on hook exceptions/malformed return/load failure. | Complete alternate paths, name repair, tampering, subprocess, delegation and utility-path negative controls on final artifact. |
| I04 | Unreachable kernel yielded not-dispatched/unverified; no file. Malformed execution context and a 100ms preflight timeout also returned not-dispatched with zero forwarded tools. Legacy fail-open modes excluded. | Final artifact rerun, gateway crash/omission and in-session cutpoints. Shared kernel not killed for this host. |
| I05 | Forbidden resource scope denied through host. Wrong pinned subject and capability rejected by context binding before dispatch. Missing kernel session rejected before dispatch. | Expiry, revocation, escalation, aggregate budgets and approval states. Source cases need final artifact rerun. |
| I06 | Useful and denied calls carried verified caller/request-bound evidence. | Wrong signer/request/result substitution and malformed/forged evidence host cases. |
| I07 | Gateway retains journal/operation IDs; launcher refuses reused profile. | Retry, cancel, parallel calls, unknown outcomes, restart, resume and handoff/fencing. Resume not exposed. |
| I08 | Launcher, restrictions, operation/recovery/upgrade/removal runbook, reproducible diagnostics and evidence provided. | Publication, install/upgrade/removal rehearsal and all remaining required tests. |

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

No resource mount or Docker socket was configured for Hermes, and no native
shell/code tools were exposed. These local host runs used the operator's macOS
UID; OS-level inability of that process to access the operator's Docker daemon
socket has not been demonstrated. Do not infer an OS sandbox or complete
process privilege separation from tool-name restrictions.
