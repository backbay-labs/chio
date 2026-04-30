# RESEARCH-M04: Recursive Delegation and Revocation Oracle

Scope: M04 P0 wave-opener ready-pack. This note is for the first implementation PRs only. It is not an implementation plan for P1-P5 and must not be used to justify touching protected trust-boundary implementation paths before their owning tickets open.

## Inputs Read

- `.planning/trajectory-2/04-recursive-delegation-revocation-oracle.md`
- `.planning/trajectory-2/tickets/M04/P0.yml`
- `.planning/trajectory-2/decisions.yml` entries `D11` and `D12`
- `.planning/trajectory-2/freezes.yml`
- `.planning/trajectory-2/ci-stubs/m04-freeze-guard.yml`
- `.planning/trajectory-2/ci-stubs/apalache-delegation.yml`
- Existing delegation surface in `crates/chio-core-types/src/capability.rs`
- Existing revocation surfaces in `crates/chio-kernel/src/revocation_store.rs`, `crates/chio-kernel/src/revocation_runtime.rs`, and `crates/chio-store-sqlite/src/revocation_store.rs`
- Formal surfaces in `formal/rust-verification/kani-public-harnesses.toml`, `crates/chio-kernel-core/src/kani_public_harnesses.rs`, `formal/tla/RevocationPropagation.tla`, `formal/MAPPING.md`, and `formal/proof-manifest.toml`
- Workspace and ownership surfaces in `Cargo.toml` and `.github/CODEOWNERS`

## Locked Decisions

- `D11`: M04 adds exactly 4 new public Kani harnesses and caps the public surface at about 14 total. P0 must not propose extra public Kani targets.
- `D12`: `Capability::Delegate` ships behind `delegation_v2` through P4 and flips default-on only after P5 acceptance. P0 must not add the enum variant or runtime behavior.

## Existing Surfaces

- `crates/chio-core-types/src/capability.rs` already has `DelegationLink`, `DelegationLinkBody`, `DelegationLink::sign`, and `validate_delegation_chain`. The P3 helper should wrap this surface instead of replacing link encoding.
- `crates/chio-kernel/src/revocation_store.rs` owns the current `RevocationStore` trait and `InMemoryRevocationStore`.
- `crates/chio-kernel/src/revocation_runtime.rs` owns `RevocationStoreError` and `RevocationRecord`.
- `crates/chio-store-sqlite/src/revocation_store.rs` persists revoked capability IDs today. M04 P1 explicitly starts with in-memory sparse-Merkle primitives and defers SQLite-backed sparse-Merkle storage.
- `formal/rust-verification/kani-public-harnesses.toml` already lists 14 lane harness function names, but its `covered_symbols` list has 10 symbols. Treat the M04 "10 baseline plus 4" claim as the public covered-symbol baseline named by the milestone, and re-measure before editing the audit doc.
- `formal/MAPPING.md` currently maps `RevocationPropagation.tla` invariants and the existing Kani harnesses. P4 must add new rows in the same PR as any new invariant or harness.
- `.github/CODEOWNERS` is generated from `.planning/trajectory/OWNERS.toml` by `scripts/regen-codeowners.sh`. Do not hand-edit it unless the generator source of truth is intentionally changed too.

## P0 Files To Touch

### M04.P0.T1

Files:

- `Cargo.toml`
- `Cargo.lock`

Implementation notes:

- Add `rs_merkle = "1.5"` under `[workspace.dependencies]`.
- Refresh `Cargo.lock` with Cargo.
- Keep this PR to dependency resolution only. Do not add the oracle crate in T1 unless the executor intentionally bundles T1 and T2 and says so in the PR.

Gate:

```bash
grep -q 'rs_merkle' Cargo.toml && cargo metadata --quiet --format-version 1 >/dev/null
```

### M04.P0.T2

Files:

- `Cargo.toml`
- `Cargo.lock`
- `crates/chio-revocation-oracle/Cargo.toml`
- `crates/chio-revocation-oracle/src/lib.rs`
- `crates/chio-revocation-oracle/tests/scaffold.rs`

Implementation notes:

- Add the new workspace member near the identity, credentials, and federation crates.
- Follow neighbor crate style: workspace package fields, `publish = false` where local crates use it, and `lib.name = "chio_revocation_oracle"`.
- Keep `src/lib.rs` a true scaffold. Do not implement sparse-Merkle, gossip, signed roots, freshness, or revocation checks in P0.
- Avoid a dependency from the oracle crate to `chio-kernel`; the current `RevocationStore` trait lives there, but that is the wrong direction for a lower-level oracle crate to lock in during scaffold work.

Gate:

```bash
test -f crates/chio-revocation-oracle/Cargo.toml && cargo build -p chio-revocation-oracle --quiet && cargo test -p chio-revocation-oracle --quiet
```

### M04.P0.T3

Files:

- `.planning/audits/M04-delegation-revocation.md`

Implementation notes:

- Record starting counts exactly as baseline claims and, where possible, with live reproduction commands:
  - 10 public Kani covered symbols, with no widening beyond the 4 future delegation additions.
  - 1 existing TLA module, `formal/tla/RevocationPropagation.tla`.
  - 0 Lean delegation theorems.
  - 254 LoC baseline revocation implementation surface named by the milestone.
- If live counts differ from the 2026-04-29 milestone counts, write both the milestone baseline and the measured value with date and command.
- Do not claim the oracle, gossip path, `Capability::Delegate`, or acceptance harness exists.

Gate:

```bash
test -f .planning/audits/M04-delegation-revocation.md && grep -q '10 Kani' .planning/audits/M04-delegation-revocation.md && grep -q 'RevocationPropagation.tla' .planning/audits/M04-delegation-revocation.md
```

### M04.P0.T4

Files:

- `.github/CODEOWNERS`
- `.planning/trajectory-2/freezes.yml`

Implementation notes:

- The ticket gate wants exact CODEOWNERS hits for `crates/chio-core-types/src/capability.rs` and `crates/chio-federation/src/lib.rs`.
- Opening state has a generated CODEOWNERS line for `crates/chio-core-types/src/capability*.rs`, but no visible exact `crates/chio-federation/src/lib.rs` owner line.
- Opening `freezes.yml` has `m04-revocation-oracle-pivot` over P1-P3 and `m04-delegation-pivot` over P3-P5. The P0 ticket header says the end-of-P0 freeze covers `crates/chio-core-types/src/capability.rs` and `crates/chio-federation/src/lib.rs` for P3-P4. Resolve this mismatch explicitly in the implementation PR.
- Prefer updating the owner generator input and regenerating CODEOWNERS. If hand-editing is unavoidable, call out why the generated-file rule was bypassed.
- Run `cargo xtask trajectory regen-manifest` if the touched trajectory surface requires it.

Gate:

```bash
grep -q 'crates/chio-core-types/src/capability.rs' .github/CODEOWNERS && grep -q 'crates/chio-federation/src/lib.rs' .github/CODEOWNERS && grep -q 'm04-' .planning/trajectory-2/freezes.yml
```

## Freeze-Guard Considerations

- M04 has two trust-boundary freezes:
  - `m04-revocation-oracle-pivot`: P1-P3 over `crates/chio-revocation-oracle/**`, `crates/chio-credentials/src/revocation*.rs`, and `crates/chio-federation/src/revocation*.rs`.
  - `m04-delegation-pivot`: P3-P5 over `crates/chio-core-types/src/capability*.rs`, `crates/chio-kernel/src/delegation*.rs`, `formal/lean4/Chio/Capability/Delegation.lean`, and `formal/tla/DelegationDepthBound.tla`.
- During M04 P3, the guard unions both freeze rows. Any non-M04 PR touching either set fails closed unless titled with the accepted M04 or bypass prefix.
- P0 should not touch `crates/chio-core-types/src/capability.rs`, `crates/chio-federation/src/lib.rs`, `crates/chio-kernel/src/delegation*.rs`, or formal delegation implementation files. P0 freeze work should be metadata and ownership only.
- The freeze-guard stub says it should be copied to `.github/workflows/m04-freeze-guard.yml` as part of the M04.P1 wave-opener, not necessarily P0. Do not prematurely activate it unless the ticket is amended.

## Formal and Kani Constraints

- Public Kani budget is capped by `D11`. Future P4 names are:
  - `verify_delegate_no_widen`
  - `verify_delegation_receipt_canonical`
  - `verify_revocation_view_freshness`
  - `verify_oracle_inclusion_soundness`
- Do not add any P0 Kani harness.
- P4 must update all of these together when the actual harnesses land:
  - `crates/chio-kernel-core/src/kani_public_harnesses.rs`
  - `formal/rust-verification/kani-public-harnesses.toml`
  - `formal/MAPPING.md`
  - `formal/proof-manifest.toml`
- P4 TLA work adds `formal/tla/DelegationDepthBound.tla` and `formal/tla/MCDelegationDepthBound.cfg`. It must not replace `formal/tla/RevocationPropagation.tla`.
- P4 adds `RevocationFreshness` to `RevocationPropagation.tla` additively and preserves existing invariant names.
- Lean work adds `formal/lean4/Chio/Chio/Capability/Delegation.lean` and import wiring only when P4 opens. `D12` requires `delegation_v2` to stay off by default until P5 acceptance.

## First PR Shape

Recommended first PR: **`[M04] P0 opener: pin rs_merkle and scaffold revocation oracle`**.

Include:

- M04.P0.T1 and M04.P0.T2 only, if the team wants a single opener PR.
- `Cargo.toml` workspace dependency pin.
- `Cargo.lock` refresh.
- `crates/chio-revocation-oracle/` scaffold with placeholder test.

Exclude:

- `Capability::Delegate`
- Any edit to `crates/chio-core-types/src/capability.rs`
- Any edit to `crates/chio-federation/src/lib.rs`
- Sparse-Merkle implementation
- Signed epoch roots
- Federation gossip
- RevocationView cache
- Formal proof, TLA, or Kani additions
- CODEOWNERS and freeze edits unless the team intentionally makes P0.T4 the first PR instead

PR body should cite:

- `D11` for the Kani cap.
- `D12` for the feature-flag boundary.
- `m04-revocation-oracle-pivot` and `m04-delegation-pivot` for freeze context.
- The exact gate commands for included tickets.

## P0 Close Gate Bundle

Run the included ticket gates plus a narrow formatting check for edited docs:

```bash
cargo metadata --quiet --format-version 1 >/dev/null
cargo build -p chio-revocation-oracle --quiet
cargo test -p chio-revocation-oracle --quiet
test -f .planning/audits/M04-delegation-revocation.md
grep -q '10 Kani' .planning/audits/M04-delegation-revocation.md
grep -q 'RevocationPropagation.tla' .planning/audits/M04-delegation-revocation.md
grep -q 'm04-' .planning/trajectory-2/freezes.yml
```

If P0.T4 lands, also run the exact CODEOWNERS grep gate from the ticket and verify generated ownership does not drift.

## Open Questions For Implementers

- Should P0.T4 amend the M04 delegation freeze from P3-P5 to P3-P4, or should the ticket header be treated as stale and the freeze register remain authoritative through P5?
- Should the exact `crates/chio-federation/src/lib.rs` CODEOWNERS line be generated from `.planning/trajectory/OWNERS.toml`, or should the trajectory-2 owner source be introduced first?
- Should the audit doc record the Kani baseline as 10 covered symbols or 14 harness lane entries? The milestone text uses 10 as the baseline; the current file lists 14 lane harness function names.
