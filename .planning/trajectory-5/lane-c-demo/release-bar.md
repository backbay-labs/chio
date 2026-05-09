# `v0.1.0-bounded-chiodome` Release Truth Boundary

This file is not release notes, not tag authorization, and not evidence that a
public package is ready. It is the release-truth boundary for the Lane C canary
planning branch. Anything copied from this file into real release notes must be
rechecked against merged source, generated fixtures, CI, and package metadata at
release time.

Current status: **BLOCKED/PARTIAL**.

There is no `v0.1.0-bounded-chiodome` release claim in this branch. The branch
may describe the intended canary and its evidence requirements, but it must not
say that the canary has shipped, is ready, is MET, or has produced artifacts
unless those artifacts exist in the branch and the gate records them as complete.

## Evidence Required Before Any Release Claim

The bounded canary can only move out of partial status after all of the following
are true on the integrated source branch:

1. Lane B hot-path enforcement is integrated from source, including B1
   single-entry capability verification, B2 receipt-v2 fail-closed behavior, B3
   anchor-batch async-only enforcement, and B4 full DSSE PAE conformance.
2. `examples/chiodome-bilateral/` exists with a runnable recipe, at least two
   transcript JSON files, golden `chio receipt explain` output, and pinned
   `receipt.json`, `envelope.json`, and `checkpoint.json` under
   `examples/chiodome-bilateral/fixtures/v0.1.0-bounded-chiodome/`.
3. The root bounded package metadata, if present, records a non-pending
   `release_status` and a 40-hex `integrated_merge_sha` under
   `[v0_1_0_bounded_chiodome]`.
4. C5 selective disclosure remains outside the current canary release boundary.
   The compatibility marker at
   `.planning/trajectory-5/lane-c-demo/c5-selective-disclosure-status.toml`
   records the non-claim only.

Until those are true, the only honest wording is that the canary remains
blocked or partial.

## Allowed Current Claim

The only current claim allowed from this branch is:

> The Lane C canary is a planned bounded integration canary. It remains
> blocked or partial until Lane B source enforcement, canary fixtures, package
> metadata, and assurance evidence are regenerated from merged source.

## Forbidden Current Claims

Do not claim any of the following from this branch:

1. That `v0.1.0-bounded-chiodome` has shipped or is ready to ship.
2. That the release tag includes a fixture tarball, required CI check, signed
   tag, release audit row, or GitHub release body.
3. That a selective-disclosure, zk, BBS+, or BBS proof artifact exists for this
   canary.
4. That C5 has implemented a `bbs-stub`, `zk`, `chio-zk-receipts`, or
   `chio.selective-disclosure-proof.v1` production path.
5. That the canary proves production multi-tenant deployment, permissionless
   federation, consensus-grade high availability, live web3 activation, public
   transparency logging, or standards-body acceptance.

## What The Canary May Eventually Claim

After the evidence above exists and passes the strict gate, the canary may claim
only the following bounded properties:

1. Two Chio kernels completed one bounded cross-kernel invocation in the canary
   scenario.
2. The invocation produced inspectable local receipts and a bilateral envelope
   from the integrated source path.
3. The canary used local development settlement and local evidence artifacts.
4. `chio receipt explain` rendered the committed canary fixtures.
5. Any omitted component is named as omitted or deferred.

Those future claims still would not imply a 1.0 product, a public network, a
production federation, or a general release.

## C5 Selective-Disclosure Non-Claim

C5 is currently **deferred to v0.2** for this branch.

The normative selective-disclosure spec currently names a `chio-zk-receipts`
workspace member behind a default-off `zk` feature. The current repo state on
this branch does not provide that crate, does not add a `zk` or `bbs-stub`
selective-disclosure feature, and does not provide auditor-view proof fixtures.
The existing `crates/chio-federation/` crate is a federation crate; its current
`Cargo.toml` has no `bbs-stub` feature and no BBS+/AnonCreds dependency tree.

The machine-readable source of truth for this boundary is
`.planning/trajectory-5/lane-c-demo/c5-selective-disclosure-status.toml`.
`scripts/check-bounded-ship-bar.sh` may still treat that marker as PARTIAL while
C5 is deferred because the checker name and row are legacy compatibility
surfaces. That compatibility output is not a current release or closure row. If
the marker claims evidence completion without real implementation and fixture
evidence, the checker must still fail.

## Non-Claims That Must Survive Release Editing

If release notes are drafted later, these non-claims must remain visible:

1. Not a production multi-tenant deployment.
2. Not a permissionless federation.
3. Not consensus-grade high availability.
4. No live web3 activation.
5. Not a transparency-log artifact.
6. No selective-disclosure, zk, or BBS proof claim unless a future protocol-owned
   branch adds real implementation and proof fixtures.
7. No standards ratification claim.
8. No mutation, threat, Kani, TLA+, or Lean uplift beyond the measured evidence
   in the relevant audit artifacts.

## Gate Commands

Relevant local checks:

```bash
bash .planning/trajectory-5/tools/planning-preflight.sh
bash scripts/check-bounded-ship-bar.sh
bash scripts/check-bounded-ship-bar.sh --diagnostic
bash scripts/tests/check-bounded-ship-bar.test.sh
```

The strict compatibility checker is expected to fail while the branch remains
partial. The diagnostic command is the honest snapshot mode for in-progress
planning and evidence review.
