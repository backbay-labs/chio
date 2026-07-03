# Retired: Chio M2 merge runbook

Status: retired on 2026-07-03. Do not execute this as PR #937 merge guidance.
The real PR #937 lane reconciliation was merge commit `4f1c58ef1` on
`chio/autonomous-commerce-brainstorm`, with parents `d5049b588` and
`f355490ef`. That merge is pushed, both lanes are ancestors of the head, and
the origin security fixes were preserved through the merge.

This file is retained only as historical planning context for a different
`chio/m2-build` merge. Its stale "9 ahead" and "72 workspace failures are a
pass" statements are superseded and must not be used as launch-readiness
evidence.

## Historical Scope

Execution runbook for landing the M2 economy stack (netting, prepaid, x402
signing, EAS/Verax conformance, vgrade pricing, XCC) plus the M0 Pass and M1
launch stacks onto the demo lineage. Merge direction is fixed: bring
`chio/m2-build` INTO `chio/autonomous-commerce-brainstorm` on a fresh integration
branch. Do NOT merge the brainstorm branch into m2-build (that would force the
3,961-file remediation-gates pass through m2-build history). Grounded in the
Wave-5 merge audit (`tasks/w4f12i3xq.output` -> `result.merge`), re-confirmed
with read-only git plumbing on 2026-07-02.

## 0. Ground-truth re-confirmation (read-only, already run)

```bash
git merge-base chio/autonomous-commerce-brainstorm chio/m2-build
# 3931b972f1ce8856ec125ba78d7c6f98b911256a  (2026-06-24 "fix: close launch remediation gates")

git rev-list --left-right --count chio/autonomous-commerce-brainstorm...chio/m2-build
# 9   155   (launch branch 9 ahead, m2-build 155 ahead)

git merge-tree --write-tree --name-only \
  chio/autonomous-commerce-brainstorm chio/m2-build
# writes tree 3548cfd10786867714979a53ec3ade0cdbfe5eac and lists 5 CONFLICT files
```

Result: identical to the audit. The launch branch has NOT advanced since the
audit (still 9 ahead), so the conflict set did not grow. Actual conflict count
today is 5, matching the audit's ~5. `contracts/` is untouched on both sides
since the merge-base; `Cargo.lock`, `settlement.rs`, and `settlement_proof.rs`
auto-merge textually. The 5 real conflicts today:

1. `crates/economy/chio-web3/src/tests.rs`
2. `crates/products/chio-cli/src/cli/dispatch/proof.rs`
3. `crates/products/chio-cli/tests/proof_doctor.rs`
4. `crates/products/chio-proof-room/src/tests/support.rs`
5. `scripts/check-chio-transaction-passport.sh`

## 1. Git command sequence

Prerequisite: the in-flight cargo run in this checkout must have finished, and no
build lock held. m2-build is checked out in another worktree, so merge from THIS
checkout (do not check out m2-build).

```bash
# 1. Create the integration branch off the launch branch HEAD.
git switch -c chio/m2-into-brainstorm chio/autonomous-commerce-brainstorm

# 2. Merge m2-build. Expect exactly the 5 conflicts above; everything else
#    auto-merges. Use --no-ff so the merge commit is explicit.
git merge --no-ff chio/m2-build
#   -> Automatic merge failed; fix conflicts and then commit the result.

# 3. Inspect the conflict set (should be the 5 files from section 0).
git diff --name-only --diff-filter=U
```

## 2. Per-conflict-file resolution

Resolve in this order. After each file, `git add <file>`.

1. `crates/economy/chio-web3/src/tests.rs` (biggest, take the UNION).
   m2 added ~905 test lines for x402 and finality; the launch branch added ~252
   for the settlement-rpc egress contract (`714d14498`). Keep BOTH test bodies.
   Do not drop either side; these are non-overlapping test functions that both
   must survive. Confirm no duplicate `fn` names after the union.

2. `crates/products/chio-cli/src/cli/dispatch/proof.rs`.
   Prefer the launch branch's proof-CLI shape (it carries the egress-contract
   env wiring from `714d14498` via `dispatch/proof/env.rs`), then re-apply m2's
   deltas on top. Do not lose m2's new proof subcommand surface.

3. `crates/products/chio-cli/tests/proof_doctor.rs`.
   Same principle: keep the launch branch's assertions plus m2's added cases.
   Union of expectations; keep every fail-closed assertion from both sides.

4. `crates/products/chio-proof-room/src/tests/support.rs`.
   Prefer the launch branch (recursive-swarm max-depth fixture `9b4b62348`,
   hygiene-cap and CI-wait hardening), then fold in any m2 helper additions.

5. `scripts/check-chio-transaction-passport.sh`.
   Reconcile both sides' checks, keep every check from both, keep fail-closed
   (`set -euo pipefail`, non-zero exit on any missing/invalid field). When in
   doubt, keep the stricter check.

Then finalize:

```bash
git add -A
git commit    # completes the merge commit
```

## 3. The two semantic traps (files auto-merge, meaning does not)

### Trap 1: egress contract vs the new x402 / anchor / finality RPC paths

Two egress guards were added INDEPENDENTLY on each side and both auto-merge, so
neither conflicts but their combined coverage must be checked by hand:

- Launch branch `714d14498` added the egress allowlist to the proof-serve path
  (`crates/products/chio-proof-room/src/lib.rs`,
  `crates/products/chio-cli/src/cli/dispatch/proof/env.rs`).
- m2-build added `chio_egress_contract::HttpEgressContract` to the settlement RPC
  path (`crates/economy/chio-settle/src/config.rs`,
  `settlement_devnet_rpc_egress_contract`, loopback-only, rejects non-loopback).

Fix: confirm every outbound RPC in the MERGED settlement + proof-serve path is
gated by one of these two egress contracts. Audit m2's new call sites:

```bash
git grep -n -E "eth_send|submit_call|rpc|independent_chain_head|chain_head" \
  crates/economy/chio-web3/src/anchors.rs \
  crates/economy/chio-web3/src/x402_signing.rs \
  crates/economy/chio-web3/src/settlement_proof.rs \
  crates/economy/chio-settle/src/evm
```

`x402_signing.rs` and `anchors.rs` are preparation/validation only (no live RPC
found), and `settlement_proof.rs` verifies an independent chain head rather than
fetching it. The live submit path is `chio-settle::evm` under the config.rs
egress contract. Confirm the proof-serve egress allowlist and the chio-settle
egress contract together cover the demo's finality-fetch and x402 submit flows.
If any call site reaches the network without an `HttpEgressContract`, add the
guard and a regression test before proceeding.

### Trap 2: stale spec/schemas/MANIFEST.sha256 for the `ungrounded` enum

m2-build added the `ungrounded` finality value to
`spec/schemas/chio-web3/v1/public-settlement-verifier-report.schema.json` but did
NOT update its hash in `spec/schemas/MANIFEST.sha256`. Both files auto-merge, so
the merged tree carries the new schema content with the OLD hash:

```
# manifest hash on both branches (STALE after merge):
5a7d11b9b6a2b67b5ec296fa6589be675084704824fa4b3c833363c67a398f0d
# actual sha256 of the merged schema (with "ungrounded"):
b4021564101ed0e4170f5de9411801caadb0577de06d0f4d5443a1764d71b689
```

`scripts/check-chio-schema-registry.sh` will fail closed on this. There is no
dedicated xtask writer for this manifest; regenerate it deterministically per
that script's own algorithm (sha256 per tracked schema, sorted paths, plus the
manifest self-hash), then verify:

```bash
python3 - <<'PY'
import hashlib, pathlib, subprocess
root = pathlib.Path('.')
manifest_rel = 'spec/schemas/MANIFEST.sha256'
extras = {manifest_rel, 'spec/schemas/registry.json', 'spec/schemas/VERSION'}
tracked = subprocess.run(['git','ls-files','-z','--','spec/schemas'],
                         check=True, stdout=subprocess.PIPE).stdout.decode().split('\0')
paths = sorted(p for p in tracked if p.endswith('.schema.json') or p in extras)
def h(p): return hashlib.sha256((root/p).read_bytes()).hexdigest()
without_self = ''.join(f"{h(p)}  {p}\n" for p in paths if p != manifest_rel)
self_hash = hashlib.sha256(without_self.encode()).hexdigest()
content = ''.join((f"{self_hash}  {manifest_rel}\n" if p == manifest_rel
                   else f"{h(p)}  {p}\n") for p in paths)
(root/manifest_rel).write_text(content)
print("regenerated", manifest_rel)
PY
bash scripts/check-chio-schema-registry.sh    # must print: OK Chio schema registry metadata
git add spec/schemas/MANIFEST.sha256 && git commit --amend --no-edit
```

## 4. Post-merge verification checklist

Run only after the in-flight cargo run releases the build lock. The full gate:

```bash
cargo build --workspace \
  && cargo test --workspace \
  && cargo clippy --workspace -- -D warnings \
  && cargo fmt --all -- --check
```

Regenerate `Cargo.lock` via a real workspace build rather than trusting the
textual auto-merge. Targeted crates that MUST be green (touched economy +
proof-room surface):

- `chio-web3` (settlement, settlement_proof, x402, finality; the conflict-1 union).
- `chio-credit` (netting + prepaid DO-NOT-WEAKEN flag locks).
- `chio-settle` (egress contract config, EIP-3009 prepare).
- `chio-cli`, `chio-proof-room` (proof CLI + proof-room fixtures).
- `chio-conformance` (eas_verax_display_only_projection,
  eas_attestation_not_anchoring_inclusion_proof,
  x402_payment_does_not_authorize_tool_call, slash-lane, capital-book).

Script and acceptance gates:

- `bash scripts/check-chio-schema-registry.sh` (trap 2; must pass).
- `bash scripts/check-chio-transaction-passport.sh` (conflict 5).
- `bash scripts/check-chio-proof-room-release-truth.sh`.
- Re-run launch acceptance (`xtask` launch acceptance). Expect
  `docs/release/M2-DIGEST-BASELINE.md` to need re-stamping: m2's baseline was
  computed before the launch branch's remediation pass, so the digest is stale
  after merge. Re-run the M2-3 re-green procedure and commit the new baseline.

Compare any failures against the known-good baseline before blaming the merge:
72 workspace failures are PRE-EXISTING (not caused by M0/M1/M2), and the M1-12
end-to-end test is wall-clock sensitive. A failure set that matches that
baseline is a pass for merge purposes.

## 5. Rollback

The integration branch is disposable and the launch branch is never touched by
this procedure. To abort:

```bash
# mid-merge, before committing:
git merge --abort

# after committing the merge, to discard the whole attempt:
git switch chio/autonomous-commerce-brainstorm
git branch -D chio/m2-into-brainstorm
```

`chio/autonomous-commerce-brainstorm` and `chio/m2-build` are unchanged in both
cases. Demo work re-points at `chio/m2-into-brainstorm` once it is green; fold
back to the launch branch (or open a PR against `main`) per founder preference.
