# R4 Merge Topology and Planning Ownership

Date: 2026-05-08
Scope owner: Wave 1 Worker A, graph and PR topology
Audit source: `reviews/FOURTH-ROUND-CODE-SECURITY-AUDIT-2026-05-08.md`

## Verdict

The old advertised merge train is invalid and must not be used. The release
source train starts with Lane B enforcement, not with a planning-led release
sequence. PR #620 is the sole owner for `.planning/trajectory-5/**`; source,
evidence, mutation, and threat PRs must not carry planning files.

Do not tag `v0.1.0-bounded-chiodome` from the current PR set. Release packaging
#618 remains last and must be regenerated from merged `main` after upstream
source and evidence branches land.

## Planning Ownership

PR #620 owns all trajectory-5 planning truth:

- `.planning/trajectory-5/**`
- ship-bar planning ledgers
- readiness and closeout coordination docs
- merge-topology records and simulation logs

Current non-planning branch cleanup result:

| PR | Role | Planning paths after cleanup |
|---|---|---:|
| #602 | TLA evidence | 0 |
| #603 | mutation aggregate owner | 0 |
| #604 | threat batch 1 | 0 |
| #608 | threat batch 2 | 0 |
| #616 | threat batch 3 | 0 |
| #619 | chio-attest-verify mutation evidence | 0 |
| #621 | chio-guards mutation evidence | 0 |
| #622 | chio-anchor mutation evidence | 0 |
| #623 | chio-policy mutation evidence | 0 |
| #626 | chio-kernel-core mutation evidence | 0 |

Per-crate mutation PRs are narrowed to their own
`audits/evidence/mutants/<crate>/**` tree plus matching
`audits/mutation/per-crate-configs/<crate>.toml`. Shared aggregate state,
the root README mutation banner, and Lane A triage scripts belong to #603.

## R4 Replacement Strategy

1. Merge or keep #620 as the planning truth record. Treat it as planning
   control data, not as a release signal.
2. Create a clean Lane B enforcement integration branch from current `main`.
   Land enforcement sources before canary/demo/release packaging. The source
   order is:
   - #606 async trait foundation
   - #612 single-entry verifier, rebased to B1-only if needed
   - #611 receipt v2 fail-closed
   - #609 anchor batch async-only
   - #610 DSSE signing foundation
3. Merge evidence after Lane B enforcement is real:
   - #601 and #602 formal evidence
   - #603 mutation aggregate owner
   - #619, #621, #622, #623, #626 per-crate mutation evidence
   - #624 and #625 after their owners confirm the same ownership rule
4. Threat evidence is not clean as three independent PRs. #604 merges cleanly
   into main, but #608 conflicts after #604. #616 is not currently a safe
   replacement for #608 because #608 has newer branch-tip fixes. The valid
   strategy is for the threat owner to collapse/rebase #604, #608, and #616
   into one threat-evidence line, most likely with #616 as the consolidation
   PR. Until that happens, do not mark #608 superseded and do not advertise
   #608 -> #616 as merge-clean.
5. Lane C is a canary only until Lane B is merged and evidence is rerun.
   Rebase #614, #615, and #617 after #610 and #612 land.
6. #618 release packaging is last. Regenerate release notes, fixtures,
   ship-bar status, and `releases.toml` from merged `main`; only then evaluate
   whether a tag is allowed.

## Local Merge Simulation

Command shape:

```bash
git worktree add --detach /tmp/arc-r4-sim4.15uzIT/work origin/main
git -C /tmp/arc-r4-sim4.15uzIT/work merge --no-edit --no-stat <origin/pr/N>
```

Simulation metadata:

```text
base=708c7bb33d origin/main
refs_refreshed=2026-05-08T21:35:24Z
```

Owned branch sequence:

```text
merge #620 (cbe1736e5a) ... OK
merge #602 (124d8a8869) ... OK
merge #603 (d9b0219f75) ... OK
merge #619 (0dc573e6e9) ... OK
merge #621 (6f4095b600) ... OK
merge #622 (1c0317bcc0) ... OK
merge #623 (feb4559c19) ... OK
merge #626 (ed3e772bfe) ... OK
```

Threat branch current state:

```text
merge #604 (ae633d478e) ... OK
merge #608 (46cbaece80) ... CONFLICT
  crates/chio-conformance/tests/threats/agent_velocity_abuse.rs
  crates/chio-conformance/tests/threats/behavioral_sequence_attack.rs
  crates/chio-conformance/tests/threats/cumulative_data_exfiltration.rs
  crates/chio-conformance/tests/threats/device_key_extraction.rs
  crates/chio-conformance/tests/threats/mobile_attestation_replay.rs
  crates/chio-conformance/tests/threats/pii_phi_exposure.rs
  crates/chio-conformance/tests/threats/play_integrity_token_replay.rs
```

The #608 conflict is owned by the threat-evidence lane, not by planning
topology. #616 was not reached in that simulation because #608 blocks first.

## review finding Status

| Finding | Status after this update |
|---|---|
| P0-001 | Closed for planning truth. The false advertised train is removed and replaced by a simulated graph plus explicit conflict list. |
| P0-008 | Closed for planning truth. The plan now separates Lane B enforcement, Lane A evidence, Lane C canary, and release packaging. |
| P1-011 | Closed for owned branches. `.planning/trajectory-5/**` is centralized in #620 for the target PR set. |
| P1-013 | Partial. Titles can be cleaned, but AI/trajectory branch names still require PR recreation or branch rename outside this planning-file cleanup. |
| P2-003 | Partial. Per-crate mutation branches no longer carry aggregate README or shared triage files. Known source duplicate cleanup outside the owned set remains with source/evidence owners. |
