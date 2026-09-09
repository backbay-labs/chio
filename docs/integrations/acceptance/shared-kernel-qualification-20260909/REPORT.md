# Shared kernel qualification, 2026-09-09

Status: seven bounded shared-contract cases passed. No agent host is accepted
by this record. Confidence is high in the recorded resource effects and
the tested denial/recovery behavior; complete six-host acceptance remains
unverified here.

Tested source: `04b7d366d62c886c39bc202f58ef0d44e8f5aee7` in the program's
integration worktree. The native policy invocation-limit prerequisite was
implemented at `e528971f5` and cherry-picked into that source. The source
includes current SDK receipt compatibility, the MCP execution-evidence/context
extension and macOS descriptor identity correction.

The binary SHA-256 is
`e7539855906bd5eb7b4eb2e5a12ca0533889cf61ced3bf4adf5850b792aa6447`.
It reports `chio-cli 0.1.0`; that version label alone cannot distinguish it from
the incompatible original public installer. The resource image is
`sha256:0106edcb15a1c0d12d914ea0504f0e63ec85f5e6fdd3825b4d7a0d1367af3991`,
containing `@modelcontextprotocol/server-filesystem` pinned to `2026.8.31`.
Environment: macOS 26.4 (25E246), Docker client 28.3.3. The final run started
at 2026-09-09 15:43:45 UTC. Script hashes, binary identity, policies and outcomes
are retained in [the final manifest](final/manifest.json).

| Case | Result and independently observed effect | Relevant gate slice |
|---|---|---|
| Authority and replay | Useful write succeeded. Conflicting stable request, forbidden path and ungranted `move_file` produced no target file. Wrong bearer/session failed. Agent bearer could not access admin API. Revocation blocked subsequent writes before and after restart. Fresh operator-issued authority restored useful work. | I03, I05, I07 portions |
| Expiration | Write before expiry succeeded; new write after expiry produced no file. | I05 expiration |
| Unknown after dispatch | Actual filesystem reply was held before the kernel received it. File effect was observed, kernel killed, and same session/request restored. Retry remained unknown and did not overwrite an independent sentinel. | I07 crash uncertainty |
| Cancellation after dispatch | Real MCP cancellation finished while resource reply remained held. After restart, same request did not overwrite the sentinel. | I07 cancellation uncertainty |
| Approval artifact rejection | A legitimate read succeeded. Required write with no governed intent and a malformed approval token both produced no file. | I05 partial approval validation |
| Shared grant budget | Write and read consumed one wildcard grant's quota of two. Third write produced no file, and restart did not replenish the quota. Admin observation reported one grant with `invocationCount: 2`. | I05 bounded grant quota, I07 restart |
| Parallel grant budget | Four concurrent writes produced exactly two files, with two successful kernel result projections. Restart left the same grant exhausted. | I05/I07 concurrent quota |

Each final case has `raw.json`, `policy.yaml` and `kernel.log`. The unknown and
cancellation cases additionally retain the actual resource reply at the
dispatch cutpoint. `SHA256SUMS` identifies retained public evidence. Private
tokens, signing material and SQLite state are intentionally excluded.
The reusable runner is
[shared_kernel.py](../../../../integrations/required-agents/qualification/shared_kernel.py)
and its response barrier is
[stdio_response_barrier.py](../../../../integrations/required-agents/qualification/stdio_response_barrier.py).

## Limits and discovered failures

- A completed duplicate in the same live session returns `isError` with
  `request ... already has authoritative lineage in this session` and no
  receipt. It suppresses redispatch but does not return the completed result.
  After kernel restart, the retained session's same request returns the
  original signed receipt without touching the resource again. The initial
  runner expected a receipt in both cases and failed; that discovery and raw
  evidence are preserved under `initial-discovery/`.
- A retry retained as `OutcomeUnknownAfterDispatch` produces a signed Deny
  for the retry. Its signed reason names that retained state, but the receipt
  lacks structured admission-state metadata and the diagnostic envelope says
  `terminalState: completed`. The original effect was independently observed.
  Consumers must preserve original uncertainty and must not reinterpret this
  retry denial as proof that the original operation had no effect.
- Invocation quota is keyed by capability ID and grant index. Separate grants
  have separate quotas. The test explicitly initialized a fresh session after
  exhaustion and observed a successful new write under a fresh capability.
  The untrusted host must not possess the session-admission bearer. The
  trusted operator/gateway must retain and enforce the approved session.
  A bearer-exposed host mode cannot claim an aggregate persistent budget from
  this per-grant mechanism alone.
- The approval case does not establish a supported operator workflow for
  pending, rejected and granted approval tokens. The selected hosted MCP
  admin API does not expose the sidecar's separate approval issuance/respond
  endpoints. Missing/malformed artifacts were exercised; real approval state
  transitions and useful approved writes remain unresolved.
- This runner observes the MCP contract and the resource. It does not run any
  of the six agent hosts, exercise a published installation, verify every
  receipt through a packaged host verifier, or establish protection of an
  agent's OS/configuration boundary. I01/I02/I04/I06/I08 and the remaining
  I03/I05/I07 paths require their own host evidence.
- Initial container cleanup raced Docker's `--rm` removal and reported
  cleanup errors. The runner now waits on removal of its own disposable
  volume. All final cases completed without cleanup errors. These earlier
  cleanup failures are retained rather than hidden.

Required cases were not skipped by the final shared run. The unresolved
requirements above are not counted as passes.
