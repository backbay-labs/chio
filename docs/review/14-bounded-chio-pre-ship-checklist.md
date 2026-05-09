# Bounded ARC Pre-Ship Checklist

Date: 2026-04-15
Authority: `v3.18 Bounded ARC Ship Readiness Closure`

## Purpose

This is the executable pre-ship checklist for the bounded ARC release
boundary.

It is intentionally narrower than the stronger security or comptroller-thesis
stories. Every unchecked item is a release blocker unless the corresponding
claim or surface is explicitly downgraded.

Use this together with:

- [13-ship-blocker-ladder.md](./13-ship-blocker-ladder.md)
- `.planning/ROADMAP.md` `v3.18` phases `417-421`
- `.planning/REQUIREMENTS.md` `TRUTH5-*`, `DELEG5-*`, `HOST5-*`, `PROV5-*`,
  and `BOUND5-*`

## Release Rule

Bounded ARC is ready to ship only when every item below is either:

- `[x]` complete with cited evidence, or
- explicitly downgraded by changing the corresponding public claim

## Phase 417: Claim Discipline and Planning Truth Closure

- [ ] `TRUTH5-01` README, release docs, review docs, and ship-facing product docs all align to one bounded ARC claim.
- [ ] `TRUTH5-01` Stronger unshipped claims are explicitly excluded: strong formal-verification boundary, verifier-backed runtime assurance, transparency-log/non-repudiation semantics, consensus-grade HA, and proved market position.
- [ ] `TRUTH5-02` `.planning/PROJECT.md`, `.planning/MILESTONES.md`, `.planning/ROADMAP.md`, `.planning/REQUIREMENTS.md`, and `.planning/STATE.md` agree on latest completed milestone, active milestone, archive status, and next action.
- [ ] `TRUTH5-02` No stale `v3.17` text remains that still reads as active or unstarted ship work.

**Primary evidence files**

- `README.md`
- `docs/release/QUALIFICATION.md`
- `docs/release/RELEASE_AUDIT.md`
- `docs/COMPETITIVE_LANDSCAPE.md`
- `.planning/PROJECT.md`
- `.planning/MILESTONES.md`
- `.planning/ROADMAP.md`
- `.planning/REQUIREMENTS.md`
- `.planning/STATE.md`

## Phase 418: Delegation Runtime Boundary Closure

- [x] `DELEG5-01` The runtime ships fail-closed delegation-chain admission: the kernel validates chain signatures, requires persisted ancestor snapshots, enforces delegator/delegatee continuity, checks delegated scope ceilings plus declared attenuations, and rejects missing or revoked ancestors.
- [x] `DELEG5-01` The runtime and qualification boundary now agree on the delegated-authority guarantees that are actually enforced.
- [x] `DELEG5-02` Ship-facing docs describe recursive delegated-authority admission only to the extent the runtime now enforces it.
- [x] `DELEG5-02` Examples and qualification docs no longer teach weaker caller-presented lineage semantics than the shipped kernel.

**Primary evidence files**

- `docs/review/02-delegation-enforcement-remediation.md`
- `crates/arc-core-types/src/capability.rs`
- `crates/arc-kernel/src/kernel/mod.rs`
- `spec/PROTOCOL.md`
- `docs/release/QUALIFICATION.md`
- relevant examples under `examples/`

## Phase 419: Hosted/Auth Profile Truth Closure

- [ ] `HOST5-01` One recommended bounded hosted/auth profile is documented and used consistently across README, runbooks, qualification docs, and examples.
- [ ] `HOST5-01` `shared_hosted_owner` and non-DPoP paths are explicitly marked compatibility-bounded where applicable.
- [ ] `HOST5-02` Ship-facing docs no longer say or imply that stolen capabilities are generally worthless unless the active profile actually enforces that.
- [ ] `HOST5-02` Ship-facing docs no longer say or imply strong multi-tenant isolation for shared hosted ownership unless that profile actually ships.

**Primary evidence files**

- `docs/review/06-authentication-dpop-remediation.md`
- `docs/review/09-session-isolation-remediation.md`
- `crates/arc-kernel/src/dpop.rs`
- `crates/arc-cli/src/remote_mcp/oauth.rs`
- hosted/auth runbooks and examples

## Phase 420: Governed Provenance Truth Closure

- [ ] `PROV5-01` Governed call-chain and related evidence surfaces distinguish asserted, observed, and verified provenance, or are explicitly narrowed to preserved caller context.
- [ ] `PROV5-01` Authorization-context and reviewer-pack exports use the same provenance model.
- [ ] `PROV5-02` No bounded-release doc or contract surface treats caller-supplied governed provenance as authenticated upstream truth unless that verified class exists.
- [ ] `PROV5-02` Receipt and report semantics clearly state what ARC observed locally versus what it merely preserved.

**Primary evidence files**

- `docs/review/04-provenance-call-chain-remediation.md`
- `crates/arc-core-types/src/capability.rs`
- `crates/arc-kernel/src/receipt_support.rs`
- `crates/arc-store-sqlite/src/receipt_store.rs`
- authorization-context and reviewer-pack docs/tests

## Phase 421: Bounded Operational Profile and Release Gate

- [ ] `BOUND5-01` One bounded operational profile exists for trust-control, budgets, and receipts.
- [ ] `BOUND5-01` The profile explicitly excludes consensus-grade HA, distributed-linearizable spend truth, and transparency-log semantics from the bounded ARC claim.
- [ ] `BOUND5-02` Release qualification docs and commands include one bounded ARC gate that records what is local-only, leader-local, compatibility-only, or otherwise bounded.
- [ ] `BOUND5-03` This checklist is filled in with concrete evidence and sign-off status before bounded ARC ship.
- [ ] `BOUND5-03` The final bounded ARC release package points reviewers to the exact commands and artifact locations needed to verify the bounded ship claim.

**Primary evidence files**

- `docs/review/05-non-repudiation-remediation.md`
- `docs/review/07-ha-control-plane-remediation.md`
- `docs/review/08-distributed-budget-remediation.md`
- `docs/release/QUALIFICATION.md`
- `scripts/qualify-release.sh`
- bounded release/profile docs created in `v3.18`

## Suggested Verification Commands

Run these after the lane is implemented:

```bash
rg -n "Lean 4 verified|formally verified protocol specification|P1-P5 are proven in Lean 4|non-repudiation|append-only ledger|HA clustered control plane|atomic budget enforcement|comptroller of the agent economy" README.md docs .planning

git diff --check -- README.md docs/review docs/release .planning
```

Then add any lane-specific release or qualification commands produced by phases
`417-421`.

## Sign-Off

- [ ] Engineering sign-off: bounded runtime semantics match the bounded claim
- [ ] Docs sign-off: ship-facing docs and examples match the bounded claim
- [ ] Release sign-off: qualification gate and artifacts exist for bounded ARC
- [ ] Review sign-off: no Track A P0 blocker remains open without an explicit downgrade
