# trajectory-2 Wave-Opener Strategy and Integration Branch Plan

Operational doc for the orchestrator that picks up `AUTONOMOUS-PROMPT.md`.
Concretizes how Wave 1 actually opens, how each subsequent wave hands off,
and how the four pre-flight items in `EXECUTION-BOARD.md` section 2 land
before any P0 wave-opener runs.

This is operational glue. Sources of truth remain `EXECUTION-BOARD.md`,
`freezes.yml`, `decisions.yml`, and the per-milestone narratives. House
rules: no em-dashes (U+2014), conventional commits, fail-closed.

---

## 1. Integration branch

### Naming convention

```
project/roadmap-trajectory-2-YYYY-MM-DD
```

`YYYY-MM-DD` is the date the branch is created. trajectory-1 used the
same pattern (`project/roadmap-04-25-2026`); trajectory-2 inherits the
shape with a `-trajectory-2-` infix to disambiguate. Example for a
2026-04-30 branch creation: `project/roadmap-trajectory-2-2026-04-30`.

### When to create

Create the branch immediately after `project/roadmap-04-25-2026`
(trajectory-1) is squash-merged to `main`. The trajectory-1 sentinel is a
single squash commit on `main` whose subject begins
`feat(trajectory-1):` or `chore(trajectory-1): close`. The orchestrator
must verify that commit is reachable from `origin/main` before opening
the trajectory-2 branch:

```bash
git fetch origin --prune
TRAJ1_SENTINEL=$(git log origin/main --grep='trajectory-1' --max-count=1 --format=%H)
test -n "${TRAJ1_SENTINEL}" || { echo "trajectory-1 not yet on main"; exit 1; }
git branch project/roadmap-trajectory-2-$(date -u +%Y-%m-%d) origin/main
git push -u origin project/roadmap-trajectory-2-$(date -u +%Y-%m-%d)
```

### Branch ruleset

trajectory-2 inherits the trajectory-1 ruleset on `main` (required PR,
merge queue, conventional-commits regex, signed commits if enabled) and
adds one required-check entry per freeze id from `freezes.yml`. The
trajectory-1 `m05-freeze-guard` check is reused for the M05 freeze
(`m05-adversarial-corpus-pivot`) with widened path globs added in
M05.P1.T1.

The freeze-guard pattern is `m{nn}-freeze-guard`. Required checks for
trajectory-2:

- `m03-freeze-guard / freeze-guard` (covers `m03-attest-verify-pivot` and `m03-pq-primitives-pivot`)
- `m04-freeze-guard / freeze-guard` (covers `m04-revocation-oracle-pivot` and `m04-delegation-pivot`)
- `m05-freeze-guard / freeze-guard` (existing, covers `m05-adversarial-corpus-pivot`)
- `m10-freeze-guard / freeze-guard` (covers `m10-custody-issuer-pivot`)

The ruleset attaches to the trajectory-2 integration branch (not
`main`), since trajectory-2 PRs target the integration branch per
`HANDOFF-PROMPT.md` section 3. `main` keeps only the trajectory-1
ruleset until trajectory-2 closes and squash-merges.

---

## 2. Pre-flight checklist (the four pending items)

Per `EXECUTION-BOARD.md` section 2, items 1, 3, 5, 7 ship in the
trajectory-2 authoring commit (already on disk). Items 2, 4, 8, 9 land
in this Wave 0 follow-up before any feature work opens. Items 8, 9, 10,
and 4 are the four pending pre-flight items.

### 2.1 EXECUTION-LOG.ndjson (item 8)

Path: `.planning/trajectory-2/EXECUTION-LOG.ndjson`.

Owner: orchestrator. Created on first append. The orchestrator is
authorized to create the file with its initial `resume` event during the
section 5 pre-flight of `AUTONOMOUS-PROMPT.md`.

Initial entry (paste-ready; substitute the ULID generator from
`AUTONOMOUS-PROMPT.md` section 12):

```bash
ULID=$(python3 -c '
import time, secrets
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
n = (int(time.time() * 1000) << 80) | int.from_bytes(secrets.token_bytes(10), "big")
out = []
for _ in range(26):
    out.append(CROCKFORD[n & 0x1F]); n >>= 5
print("".join(reversed(out)))')
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
mkdir -p .planning/trajectory-2
printf '{"event_id":"%s","ts":"%s","type":"resume","wave":"wave-0-authoring","ticket_id":null,"actor":"orchestrator","payload":{"reason":"trajectory-2 cold start","prior_session":null}}\n' \
  "${ULID}" "${TS}" >> .planning/trajectory-2/EXECUTION-LOG.ndjson
```

Subsequent events use the envelope schema in `AUTONOMOUS-PROMPT.md`
section 12. Append-only NDJSON; rotate at 100 MB to
`EXECUTION-LOG.YYYY-MM-DD.ndjson`. Add the merge-driver entry to
`.gitattributes` (mirrors trajectory-1):

```bash
printf '%s\n' \
  '.planning/trajectory-2/EXECUTION-LOG.ndjson  merge=union  text=auto' \
  >> .gitattributes
```

### 2.2 m{nn}-freeze-guard branch ruleset rewrites (item 9)

Owner: infra. Each freeze id in `freezes.yml` resolves to one
`m{nn}-freeze-guard.yml` workflow under `.github/workflows/`. The M03,
M04, and M10 workflows are authored as the first wave-opener ticket of
each milestone (M03.P1.T1, M04.P1.T1, M10.P1.T1). M05 reuses the
existing trajectory-1 `m05-freeze-guard.yml` with widened path globs
written into `freezes.yml` already.

Once a freeze-guard workflow is visible as a check on its first PR,
register the required check via `gh api`. Replace `${BRANCH}` with the
trajectory-2 integration branch name from section 1.

Create the ruleset (one-time, at trajectory-2 open):

```bash
BRANCH=project/roadmap-trajectory-2-$(date -u +%Y-%m-%d)
gh api repos/bb-connor/arc/rulesets \
  --method POST \
  -f name="trajectory-2-freezes" \
  -f target=branch \
  -f enforcement=active \
  -f 'conditions[ref_name][include][]=refs/heads/'"${BRANCH}" \
  -f 'rules[][type]=pull_request' \
  -f 'rules[][type]=required_status_checks' \
  -f 'rules[][parameters][required_status_checks][][context]=m03-freeze-guard / freeze-guard' \
  -f 'rules[][parameters][required_status_checks][][context]=m04-freeze-guard / freeze-guard' \
  -f 'rules[][parameters][required_status_checks][][context]=m05-freeze-guard / freeze-guard' \
  -f 'rules[][parameters][required_status_checks][][context]=m10-freeze-guard / freeze-guard'
```

If the four guards are not all visible yet (M04 / M10 land late), open
the ruleset with only the M03 and M05 contexts and patch in M04 / M10
when their wave-openers ship:

```bash
RULESET_ID=$(gh api "repos/bb-connor/arc/rulesets" --jq '.[] | select(.name=="trajectory-2-freezes") | .id')
gh api "repos/bb-connor/arc/rulesets/${RULESET_ID}" \
  --method PUT \
  --input - <<'JSON'
{ "rules": [ /* full updated rules array including m04-freeze-guard / freeze-guard */ ] }
JSON
```

Each freeze-guard workflow follows the trajectory-1 m05 shape (see
`/.github/workflows/m05-freeze-guard.yml`): on every PR, diff against
merge-base, parse the freeze id from `freezes.yml`, fail if a non-owner
milestone touches a frozen `path_glob`. The trust-boundary classifier
leg (`trust-boundary/cosmetic` vs `trust-boundary/substantive`) is
preserved.

### 2.3 scripts/install-orchestrator-tools.sh (item 10)

The trajectory-1 stub at `scripts/install-orchestrator-tools.sh` already
pins `mikefarah/yq v4.44.3` and `jq 1.7.1` (verified). trajectory-2
inherits it as-is. No new wave-opener work; the orchestrator runs:

```bash
bash scripts/install-orchestrator-tools.sh
test -f .planning/trajectory/tool-versions.lock || { echo "tool lock missing"; exit 1; }
yq --version | grep -F 'v4.44.3'
jq --version | grep -F '1.7.1'
```

If the trajectory-1 stub is ever absent or the pinned versions drift,
schedule a Wave 0 follow-up to re-pin (yq v4.x, jq 1.7+). Do not
improvise. This rule is from `AUTONOMOUS-PROMPT.md` section 15.

### 2.4 CODEOWNERS regen for trajectory-2 trust-boundary paths (item 4)

Owner: sequencer. The dual-trajectory regenerator lives at
`.planning/trajectory-2/scripts/regen-codeowners.sh`. It reads both
`.planning/trajectory/OWNERS.toml` and
`.planning/trajectory-2/OWNERS.toml`, merges overlapping globs by
union-of-reviewers, propagates the `review_x2` flag to a
`# trust-boundary; review_x2` comment on each affected line, and emits
the canonical `CODEOWNERS` at the workspace root with most-specific
globs sorted last (CODEOWNERS later-pattern-wins semantics).

The trajectory-1 script (`scripts/regen-codeowners.sh`) remains in place
for trajectory-1 standalone regen and is left unmodified so trajectory-1
CI continues to behave as documented.

Paste-ready Wave 0 sequence:

```bash
# 1. Sanity-check both OWNERS manifests parse cleanly
yq -p=toml '.' .planning/trajectory/OWNERS.toml   > /dev/null
yq -p=toml '.' .planning/trajectory-2/OWNERS.toml > /dev/null

# 2. Regenerate CODEOWNERS using the dual-trajectory script
.planning/trajectory-2/scripts/regen-codeowners.sh

# 3. Inspect the diff before committing
git diff -- CODEOWNERS

# 4. Self-test (validates non-empty + every non-comment line has a
#    path token and at least one @handle token)
.planning/trajectory-2/scripts/regen-codeowners.sh --self-test
```

The trajectory-2 Wave 0 pre-flight script
(`.planning/trajectory-2/scripts/preflight-trajectory-2.sh`) compares
`CODEOWNERS` mtime against both OWNERS.toml inputs and re-invokes
`.planning/trajectory-2/scripts/regen-codeowners.sh` automatically when
either source is newer. Schedule the regen commit immediately after the
freezes / decisions / toolchain commits and before any P0 wave-opener.

---

## 3. Wave 1 boot sequence

Exact ordered steps the orchestrator runs to open Wave 1. Each step is a
gate; do not advance until the previous step is green.

### Step 1: verify trajectory-1 closed on main

```bash
git fetch origin --prune
git log origin/main --grep='trajectory-1' --max-count=1 --oneline
```

Confirm the sentinel commit exists. If absent, halt-and-ping with
trigger 11 (operator-discretion: "trajectory-1 not yet on main").

### Step 2: create the integration branch

```bash
DATE=$(date -u +%Y-%m-%d)
BRANCH="project/roadmap-trajectory-2-${DATE}"
git checkout -b "${BRANCH}" origin/main
git push -u origin "${BRANCH}"
```

Record the branch name in `EXECUTION-STATE.json` under
`integration_branch`. Atomic write (tmp + fsync + rename + .bak).

### Step 3: pre-flight items 2.1 to 2.4

Run sections 2.1, 2.2, 2.3, 2.4 above in order. Each commits to the
integration branch with conventional-commits messages:

```bash
git commit -m "chore(trajectory-2): seed EXECUTION-LOG.ndjson"
git commit -m "ci(trajectory-2): add freeze-guard branch ruleset"
git commit -m "chore(trajectory-2): pin orchestrator toolchain (verified)"
git commit -m "chore(trajectory-2): regen CODEOWNERS for trust-boundary paths"
git push origin "${BRANCH}"
```

### Step 4: Cargo.lock wave-opener chain

Per `EXECUTION-BOARD.md` section 2, the Wave 1 P0 lock-bump order is:

```
M06.P0.T2 -> M02.P0.T2 -> M01.P0.T1
```

Rationale: M06 lands the `dhat` workspace pin and owns the watched
single-version check that includes `dashmap`. The orchestrator schedules
lock-touching openers strictly serially through
the merge queue (concurrency=1 for `Cargo.lock`-touching PRs).

```bash
# Step 4a: M06.P0.T2 (dhat pin + watched single-version check)
git worktree add .worktrees/wave-W1/m06/p0.t2 -b wave/W1/m06/p0.t2-pin-dhat-and-lockfile-bump "${BRANCH}"
# spawn gsd-executor sub-agent with M06.P0.T2 ticket spec
# wait for merge into ${BRANCH}; gate: cargo build --workspace green

# Step 4b: M02.P0.T2 (cargo-mutants harness deps)
git worktree add .worktrees/wave-W1/m02/p0.t2 -b wave/W1/m02/p0.t2-cargo-lock-bump-and-mutants-pin "${BRANCH}"
# spawn gsd-executor; wait for merge

# Step 4c: M01.P0.T1 (error-codes + lsp deps)
git worktree add .worktrees/wave-W1/m01/p0.t1 -b wave/W1/m01/p0.t1-pin-errors-and-lsp-deps "${BRANCH}"
# spawn gsd-executor; wait for merge
```

### Step 5: verify each opener green CI before any P1 ticket opens

After each merge, run on the integration branch:

```bash
git checkout "${BRANCH}" && git pull --ff-only
cargo build --workspace \
  && cargo test --workspace \
  && cargo clippy --workspace -- -D warnings \
  && cargo fmt --all -- --check
```

Red one-liner = halt-and-ping (trigger 2).

### Step 6: open P1 of M01, M02, M06 in parallel

After all three openers merge and the integration branch is green, fan
out the P1 tickets per the `EXECUTION-BOARD.md` section 5 concurrency
caps (per-milestone soft 6 / hard 10; trajectory soft 25 / hard 40).
Spawn sub-agents in one batch via Agent tool calls with
`run_in_background: true`. M01 / M02 / M06 are not trust-boundary; the
4-in-flight cap does not apply.

---

## 4. Wave 2 boot sequence

Wave 2 is the trust-boundary wave (M03, M04, M05). Wave 1 must be 100%
merged before any Wave 2 P0 wave-opener runs. No overlap.

### Wave 2 gate verification

```bash
git checkout "${BRANCH}" && git pull --ff-only
# All M01, M02, M06 tickets show status: merged in EXECUTION-STATE.json.
yq -p=yaml -o=json -e \
  'all(.[] | select(.milestone | test("^M0[126]$")); .status=="merged")' \
  .planning/trajectory-2/tickets/manifest.yml
# Workspace one-liner green
cargo build --workspace && cargo test --workspace \
  && cargo clippy --workspace -- -D warnings \
  && cargo fmt --all -- --check
```

### Freeze activation triggers

Per `freezes.yml`:

- `m03-attest-verify-pivot` and `m03-pq-primitives-pivot` open on
  M03.P1.T1 merge. Both freezes activate on the same trigger; the
  guard workflow loads both freeze rows and unions their `path_globs`
  for the M03 P1..P2 overlap window. The overlap is recorded
  canonically via the `overlap_with` field on each row in
  `freezes.yml`; that field is the source of truth, not narrative
  prose. M03 P3 keeps only `m03-attest-verify-pivot` active
  (`m03-pq-primitives-pivot` ends at M03.P2.T6).
- `m04-revocation-oracle-pivot` opens on M04.P1.T1 merge.
  `m04-delegation-pivot` opens later on M04.P3.T1 merge. During the
  M04.P3.T1..M04.P3.T5 window both M04 freezes are active and the
  `m04-freeze-guard` required-check unions both rows' `path_globs`.
  The overlap is recorded canonically via the `overlap_with` field
  on each row in `freezes.yml`; consult that field rather than this
  paragraph.
- `m05-adversarial-corpus-pivot` opens on M05.P1.T1 merge. M05.P1.T1
  also widens the existing m05-freeze-guard `path_globs` to include the
  trajectory-2 paths (`crates/chio-adversarial-suite/**`,
  `fuzz/fuzz_targets/wasm_guard_escape.rs`,
  `crates/chio-wasm-guards/tests/escape/**`,
  `crates/chio-attest-verify/src/policy.rs`,
  `spec/security/chio-threat-model.v1.json`,
  `crates/chio-conformance/tests/threats/**`).

The orchestrator records each freeze activation as a
`freeze_activated` event in `EXECUTION-LOG.ndjson` and sets the
corresponding state field in `EXECUTION-STATE.json`.

### Cross-freeze ordering (from freezes.yml footer)

- `m03-attest-verify-pivot` must close before
  `m04-revocation-oracle-pivot` end_trigger merges (M04.P1.T3 carries
  the soft_dep on M03 PQ-hybrid surface; M03 surface concretizes in
  M03.P2 HybridBackend integration).
- `m05-adversarial-corpus-pivot` overlap on
  `crates/chio-attest-verify/src/policy.rs` is sequenced: M05.P4 lands
  AFTER M03.P3 closes.
- `m10-custody-issuer-pivot` opens AFTER both M03 and M04 freezes close
  so the issuer can sign via M03 hybrid surface and revoke via M04
  oracle. (Wave 4 boundary.)

### Security x2 review activation

Per D04 and `AUTONOMOUS-PROMPT.md` section 4 / section 8, every PR
under a Wave 2 trust-boundary path receives Security x2 review in
addition to `@bb-connor`.

The orchestrator spawns two reviewer instances per PR via the Agent
tool:

```text
Agent #1: subagent_type=Plan, model=opus,    no shared scratchpad
Agent #2: subagent_type=Plan, model=sonnet,  no shared scratchpad
```

Each instance receives only the diff and the role checklist; no prior
reviewer's verdict is passed. Disagreement = halt-and-ping (trigger 10).

The trust-boundary trigger is any path matching a
`freezes.yml.path_globs` row whose `trust_boundary: true`. The
orchestrator computes the set per PR via the diff and the freeze
register.

### Wave 2 concurrency

Trust-boundary cap: 4 in-flight per milestone (vs 6 / 10 default).
Trajectory-wide cap: 25 / 40 unchanged.

---

## 5. Wave 3 and Wave 4

### Wave 3: M07 (adoption beachhead) + M08 (chio-arena)

Opens after Wave 2 closes (all M03 / M04 / M05 tickets merged, all
freeze end_triggers merged). M07 and M08 are not trust-boundary; the
Wave 1 concurrency caps apply (6 / 10 per milestone, 25 / 40 across).

P0 wave-opener Cargo.lock chain inside Wave 3: M07.P0.T1 -> M08.P0.T1
(M07 introduces five new provider crates; M08 wakes `chio-arena` and
depends on the M07 verdict-matrix wiring per D14 auto-promotion).
Confirm the order against the per-milestone P0 ticket files at run
time. Same merge-queue concurrency=1 discipline as Wave 1.

Wave 3 gate (`EXECUTION-BOARD.md` section 6f W3):
- 8-provider cross-provider verdict equality required-CI green (M07).
- Arena determinism gate green on the three reference scenarios (M08).

### Wave 4: M09 (economic + lineage) -> M10 (custody + model cards)

Opens after Wave 3 closes. Per D02, M09 ships before M10 because
lineage anchoring unblocks M10 P5. M09 and M10 may overlap once
M09.P3 (lineage anchor surface) lands, but the recommended order is
M09 first.

`m10-custody-issuer-pivot` opens on M10.P1.T1 merge. Its path_globs
(`crates/chio-custody-hw/**`,
`sdks/typescript/packages/passkey/src/**`) do not overlap with M09;
the freeze sequences cleanly inside Wave 4.

Wave 4 gate (`EXECUTION-BOARD.md` section 6f W4):
- Marketplace settlement end-to-end demo green (M09).
- Passkey-to-revocation round-trip green within the M04 epoch bound
  (M10).
- The four global trajectory-close gates (see section 8 below).

---

## 6. Cargo.lock contention

### Within-wave serialization

The wave-opener chain serializes Cargo.lock writes within each wave:

- Wave 1: M06.P0.T2 -> M02.P0.T2 -> M01.P0.T1
- Wave 2: M03.P0.T1 -> M04.P0.T1 -> M05.P0.T1 (verify against
  per-milestone P0 files at run time; the M03 first means revocation
  oracle deps land on top of PQ surface deps)
- Wave 3: M07.P0.T1 -> M08.P0.T1
- Wave 4: M09.P0.T1 -> M10.P0.T1

PRs touching `Cargo.lock` route through GitHub's merge queue with
`concurrency=1`. Pure-code PRs bypass.

### Cross-wave serialization

Cross-wave Cargo.lock writes are serialized by the strict wave gate
(no Wave-N P0 ticket runs before all Wave-(N-1) tickets merged).

### Hot-fix lane

`hotfix/<slug>` branches with the `[trajectory-2]` label may write
Cargo.lock outside the chain, with a single-reviewer override
documented in the affected milestone's audit doc (matches the
`bypass_lane: "hotfix/* + [trajectory-2]"` field in `freezes.yml`).
The orchestrator records every bypass as a `freeze_bypass` audit
event.

### Merge-driver shape

Mirrors trajectory-1's `Cargo.lock` merge driver
(`scripts/cargo-lock-merge.sh`, registered via `.gitattributes`):

```
# .gitattributes (existing)
Cargo.lock merge=cargo-lock-regen
```

Driver behavior (already on disk, do not re-author):

1. On conflict, run `cargo update --workspace` to regenerate the
   lockfile from the merged Cargo.toml tree.
2. Assert reproducibility via `cargo metadata --locked`.
3. Refuse to run if Cargo.toml conflicts remain unresolved.

Authors register the driver in their local clone once via
`scripts/setup-git-merge-drivers.sh` (trajectory-1 carry-over).
trajectory-2 inherits without modification.

---

## 7. Halt-and-resume integration

### Halt protocol

`AUTONOMOUS-PROMPT.md` section 9 enumerates 16 halt triggers and
section 12 documents the state-write atomic protocol. On halt:

1. Write the audit event first (`halt_triggered`).
2. Write `EXECUTION-STATE.json` second (atomic tmp + fsync + rename).
3. Post a chat message with the halt event id, trigger id, and a
   one-paragraph context summary.

### Resume protocol

Reference `HANDOFF-PROMPT.md` (the general continuation prompt) for
session pickup. The orchestrator on resume:

1. Reads `EXECUTION-STATE.json` (or `.bak` if malformed).
2. Validates in-progress ticket set against open PRs via `gh pr list`.
3. Cross-checks per-ticket `merged_sha` fields against the
   integration-branch git log.
4. Continues from the recorded checkpoint.

A specific pause-point summary may live at
`.planning/trajectory-2/CONTINUE-PROMPT.md`; prefer that doc when
present.

### trajectory-2-specific halt triggers (12 to 16)

From `AUTONOMOUS-PROMPT.md` section 9 and `EXECUTION-BOARD.md`
section 7. For each, the recovery action:

- **(12) Lean theorem fails CI.** `lake build` over
  `formal/lean4/Chio/Capability/Delegation.lean` fails on an M04 PR.
  Recovery: open `formal/lean4/counterexamples/<sha>.lean` capturing
  the failing case; revert the offending diff; re-spawn the M04
  executor with the counterexample injected into context. Do not
  skip the lean gate.
- **(13) Threat-model gap.** M05 P5 gate reports a threat ID with no
  green test mapping. Recovery: either cover the threat (executor
  adds the missing test under
  `crates/chio-conformance/tests/threats/`) or revert the threat row
  registration. Fail-closed; the gate stays red until one path
  succeeds.
- **(14) Mutation regression.** A trust-boundary crate's
  cargo-mutants kill-rate drops below 80% (D06 floor). Recovery: PR
  comment lists surviving mutants; merge blocked until either a test
  catches them or `mutants.toml` skip-with-rationale is added (the
  rationale must cite the survivor by id).
- **(15) Verdict-matrix divergence.** M02 P5 cross-SDK matrix
  reports any divergence across the five primary kernels (D07: Rust,
  Python, TypeScript node-http, WASM browser kernel, Go). Recovery:
  fail-closed; root cause is almost always canonicalization or
  scope-set encoding drift; spawn a debug executor scoped to
  `crates/chio-core-types/src/canonical*.rs` (or the analogous SDK
  path). The Wave 2 freeze on `chio-core-types` may apply.
- **(16) WASM guard escape panic.** `wasm_guard_escape.rs`
  libFuzzer target panics or escapes linear memory. P0 incident.
  Recovery: halt the trajectory worktree; capture failing module
  hash; open `crates/chio-wasm-guards/incidents/<sha>.md`; do not
  reschedule M05 P3 until the issue is root-caused.

Triggers 12, 13, 16 are trajectory-wide halts (the gate is global).
Triggers 14, 15 are per-ticket halts; other-wave work continues.

---

## 8. Trajectory close-out

Per `EXECUTION-BOARD.md` section 9, trajectory-2 closes when:

### Ticket count

All 319 tickets across `tickets/M{nn}/P{n}.yml` are status `merged`.
Verify:

```bash
yq -N ea '[.[]] | length' .planning/trajectory-2/tickets/M*/P*.yml
yq -p=yaml -o=json -e 'all(.[]; .status=="merged")' \
  .planning/trajectory-2/tickets/manifest.yml
```

Both must report 319 / true.

### Four global gates green on integration branch

- `mutation-coverage` >= 80% across the six trust-boundary D06 crates
  (`chio-policy`, `chio-credentials`, `chio-attest-verify`,
  `chio-kernel-core`, `chio-guards`, `chio-anchor`).
- `threat-model-coverage` = 100% (M05 P5 gate; every registered
  threat ID has a green test mapping).
- `verdict-matrix` divergence count = 0 across the five D07 SDK
  languages (Rust, Python, TypeScript node-http, WASM browser
  kernel, Go).
- `lean-build` green over the four delegation theorems
  (`formal/lean4/Chio/Capability/Delegation.lean`).

### Archive and bump

```bash
mkdir -p .planning/trajectory-2/archive
cp .planning/trajectory-2/EXECUTION-STATE.json \
   .planning/trajectory-2/archive/EXECUTION-STATE-CLOSED.json
git add .planning/trajectory-2/archive/EXECUTION-STATE-CLOSED.json
```

Bump `.planning/STATE.md` (if present) to record trajectory-2
completion. Author `.planning/trajectory-2/RETROSPECTIVE.md` per
`AUTONOMOUS-PROMPT.md` section 14 (total tickets merged, total halts,
total reviewer-bounce count, total wall-clock, mutation kill-rate per
D06 crate, verdict-matrix divergence history, threat-model-coverage
trajectory).

### Squash-merge to main

The trajectory-2 integration branch is ready for human review and a
single squash-merge to `main` once the user confirms the four gates.
Per `HANDOFF-PROMPT.md` section 9, trajectory-2 close does not
auto-merge to `main`.

### trajectory-3 review

D03 defers two wildcard items out of trajectory-2 scope:

- V02 `chio-zk-verify` (zk verifier surface)
- V07 `chio-mesh` (consensus / federation)

After trajectory-2 squash-merges, begin a trajectory-3 review with
those two items as starting candidates plus any deferrals captured in
`.planning/trajectory-2/RETROSPECTIVE.md` and
`.planning/trajectory-2/RECONCILE-NEEDED.md` /
`.planning/trajectory-2/SCOPE-CREEP-AMBIGUOUS.md`.

---

## 9. References

| Doc | Sections | Used in |
|-----|----------|---------|
| `.planning/trajectory-2/EXECUTION-BOARD.md` | 2 (wave plan + pre-flight), 4 (freezes), 5 (concurrency), 7 (failure modes), 8 (audit), 9 (close) | 2, 3, 4, 7, 8 |
| `.planning/trajectory-2/AUTONOMOUS-PROMPT.md` | 5 (pre-flight), 6 (wave protocol), 8 (sub-agents), 9 (halts), 12 (state + ULID) | 2.1, 3, 4, 7 |
| `.planning/trajectory-2/HANDOFF-PROMPT.md` | 2 (pickup), 3 (branch model), 9 (close) | 1, 3, 7, 8 |
| `.planning/trajectory-2/freezes.yml` | all six freeze rows + cross-freeze ordering footer | 1, 2.2, 4, 5 |
| `.planning/trajectory-2/decisions.yml` | D02 (M09 before M10), D03 (V02 / V07 deferred), D04 (Security x2), D06 (six trust-boundary crates), D07 (five primary kernels), D11 (14-Kani cap) | 4, 5, 7, 8 |
| `.planning/trajectory/EXECUTION-BOARD.md` (trajectory-1) | 1 item 12 (Cargo.lock merge driver), 5 (file ownership), 7 (review pipeline) | 1, 6 (template inheritance) |

End of trajectory-2 wave-opener strategy.
