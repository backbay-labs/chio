# Wave 1B: §6 evaluation honesty audit

USENIX Security empirical-systems review of the reversible-action draft's
evaluation chapter against four code gaps flagged in the README. The README's
code claims were cross-checked against
`/Users/connor/Medica/backbay/standalone/clawdstrike/apps/agent/src-tauri/src/api_server.rs`
and `Monitor.swift`; all four hold under direct inspection.

## 1. The "four reversible variants" claim

§5 names the four reversible variants explicitly: file quarantine, persistence
disable, process-tree suspend, and egress restriction. The §5 "Rollback
executor" paragraph asserts each has a content-hash-gated inverse:
"File quarantine's inverse reads the artifact, hashes it, verifies
content-hash parity against the recorded forward hash, refuses the operation
if the original target path now exists, and issues the inverse
\codepath{fs::rename}." The same shape is asserted for the other three.

§6 measures all four as latency rows ("Forward executor latency, four
reversible variants" and "Rollback executor latency, four reversible
variants"). Cross-check against the code: `execute_quarantine_file_rollback`,
`execute_disable_persistence_rollback`, `execute_suspend_process_tree_rollback`,
and `execute_restrict_egress_rollback` all exist in `api_server.rs`. The
abstract's claim that "four reversible action variants have real OS executors
with content-hash-gated rollback constructors" is structurally supported by
the code for the file-rename pairs; the process-tree pair uses SIGSTOP/SIGCONT
rather than a content hash, and the egress pair uses a policy-file path
rather than artifact hashing. The abstract's "content-hash-gated" qualifier
therefore over-generalizes: only two of the four pairs are literally
content-hash-gated. §5 hedges process-tree suspend ("substrate records which
pids in the original set have since exited and reports the partial-inverse
status"), but the abstract does not.

## 2. The destructive path as deployment gap

§6 reports the destructive subclass as a deployment gap, not a measurement.
The "Destructive subclass" paragraph is unambiguous: "The destructive
subclass is reported as a deployment gap rather than a measurement... The
empirical claim about the destructive subclass is therefore the
substrate-level reduction \thm{destructive_action_requires_bilateral_admission},
not a deployed measurement." Table~\ref{tab:eval-ra} marks the destructive
row as "withheld; not wired." The README's framing holds: §6 does not
quietly fold the destructive path into the latency numbers.

## 3. TTL scheduler load-bearing or operator-dependent?

§5 does not claim a background scheduler. §6's "Sensor and scheduler gaps"
paragraph is honest: "The TTL auto-expiry scheduler is similarly absent: the
\codepath{/expire} HTTP endpoint exists but no background task invokes it on
a counter advance." §9's first bullet is direct: "The headline composition
theorem is unfalsifiable against the current binary without the scheduler;
'terminates within its TTL' is operator-dependent rather than type-level."
Cross-check: the only `tokio::time::interval` calls in `api_server.rs` are
for fleet-secret sync and openclaw heartbeat; no expiry task is wired. The
draft acknowledges this as a limitation in two places and marks the row
"withheld; scheduler absent" in Table~\ref{tab:eval-ra}. This claim is the
draft's most honest engagement with its own code.

## 4. Three of seven executors — honest count?

The forward executors named in §5 are file quarantine, persistence disable,
process-tree suspend, and egress restriction, plus "destructive executors"
referenced in §6's deployment-gap paragraph. The code shows seven forward
executors: quarantine_file, disable_persistence, suspend_process_tree,
restrict_egress, revoke_grant, collect_evidence, and (via the dispatch in
`execute_edr_response_action`) a terminate-process-tree path. Only four
have `_rollback` variants. §9's "Missing inverse executors" bullet lists
"Process-tree terminate, grant revoke, and (in the substrate's taxonomy)
network isolate" as destructive without inverses. This is close but not
exact: the code's third missing-rollback executor is `collect_evidence`,
not `network isolate`. §9 substitutes a substrate-taxonomy term for the
code-level reality. Revoke-grant's destructive nature IS acknowledged in
§9; it is not treated as if it had a rollback. The collect-evidence
omission is the cleanest miss: the code has a forward executor for it,
no rollback, and neither §5 nor §9 names it. This is a small but
USENIX-noticeable count discrepancy.

## 5. macOS Endpoint Security sensor

§6's "Sensor and scheduler gaps" paragraph is candid: "the entitlement is
declared, the class is structurally present, but \codepath{es_new_client}
is not called and no event stream is ingested. The sensor-to-decision
latency is therefore not measurable on the current deployment instance."
§9's "Sensor stub on macOS Endpoint Security" bullet scopes sensor-state
attestation correctly to "the Network Extension verdict path, the
tool-preflight admission hook, and the package-manager runtime guard."
Cross-check against Monitor.swift confirms: the EndpointSecurity module
is imported, the class is declared, but no subscription call exists. The
draft does not claim ES-based measurements anywhere. This row is
honestly reported.

## 6. Ledger-append-after-effect race

The assumption ledger in §9 names this directly: "The deployment instance
appends the execution receipt AFTER the side effect runs; a crash between
effect and append leaves a live side effect with no execution record." The
"Crash safety on the ledger append" bullet repeats it and prescribes the
write-ahead pattern: "A write-ahead ledger pattern (append a pending record
before the effect, then mark succeeded after) would close this; the
substrate model and the headline theorem do not require it, but the
empirical chapter's 'rollback closes the chain' claim is weakened by the
crash window." Cross-check against `api_server.rs`: `fs::rename` at line
12105 precedes `append_and_receipt_edr_response_execution` at line 12115;
the same ordering recurs at 12192/12202 for persistence disable. The race
is real, the draft names it, and the README's WAL framing is reproduced in
§9. §6 itself does NOT mention the race; the limitation is exiled to §9.
A USENIX reviewer would expect §6 to flag the race in the latency-rollback
narrative rather than relying on §9 to absorb it.

## 7. USENIX-grade evaluation register

The chapter is short (under one page), names what it cannot measure, and
substitutes a measurement-status table for latency tables. It does not
report N runs, confidence intervals, hardware, kernel versions, or
sample sizes; "the rename is microseconds on a local filesystem" is the
strongest numeric claim and it is unmoored from a measurement protocol.
Strongest sentence: "Absent measurements are marked rather than
estimated." This is the chapter's defensible spine. Weakest sentence:
"the rename is microseconds on a local filesystem and the signing path
is dominated by canonical-JSON serialization rather than by Ed25519."
A USENIX Security reviewer reads this as folklore, not measurement; no
sample size, no hardware, no distribution. The chapter is closer to a
measurement-plan than a measurement chapter; the register is "honest
internal evaluation" rather than "USENIX evaluation."

The voice rules hold: no em dashes, no "this paper" or "we extend," no
internal version notes, no branch names. §5's "The substrate's chosen
trust granularity for the response engine" and §6's "deployment instance"
phrasing stays on what IS rather than project history. One soft flag:
§5's "the response engine does not yet wire" leans toward project-history
voice; "is not wired" or "the deployment instance carries the single-signer
path only" would stay cleaner. The README's voice discipline is largely
preserved.

## Bottom line

Unfalsifiable against current code:
- The TTL composition theorem's empirical anchor (no background scheduler).
- The destructive-class bilateral admission (not wired; one keypair).
- Sensor-to-decision latency on macOS ES (no subscription).
- "Rollback closes the chain" under crash (append-after-effect race).

Acknowledged as limitations:
- TTL scheduler absence (§6 paragraph, §9 bullet, table row).
- Destructive subclass not wired (§6 paragraph, §9 bullets, table row).
- macOS ES stub (§6 paragraph, §9 bullet, scoped to NE / preflight / pkg).
- Ledger-append race (§9 ledger row and bullet; absent from §6 prose).
- Single-actor bilateral collapse and operator-key custody (§9).
- The rfl-gate risk on the headline theorem (§9).

Quietly claimed:
- "Content-hash-gated rollback constructors" generalized across all four
  pairs in the abstract; only quarantine and persistence-disable are
  literally content-hash-gated. Process-tree suspend and egress restriction
  use different inverse mechanics. §5 hedges; the abstract does not.
- The seven-executor / three-missing breakdown is presented in §9 as
  "terminate, revoke, isolate"; the code's third missing rollback is
  collect-evidence, not network-isolate. A reviewer who reads the code
  will catch this.
- The append-after-effect race is absent from §6; a reader who stops at
  §6 sees "rollback closes the chain" without the crash-window caveat.

Defensibility at USENIX: the draft is materially honest. The four headline
gaps named by the README are reported as gaps in §6 or §9. The remaining
risks are stylistic over-generalization in the abstract, a misnamed third
destructive executor in §9, and a §6 that reads as a measurement plan
rather than a measurement chapter. A reviewer who reads §9 charitably will
accept the chapter; a reviewer who reads only the abstract and §6 will
score it down for absence of statistical apparatus, not for dishonesty.
