# C5 Selective-Disclosure Boundary

Current status: **DEFERRED TO v0.2**.

This branch does not implement, ship, or claim a selective-disclosure auditor
view. It records the boundary so future release work cannot accidentally turn a
research/spec direction into a product, zk, BBS+, or proof claim.

## Current Source Truth

The normative selective-disclosure document is
`spec/CHIODOS_SELECTIVE_DISCLOSURE.md`.

That spec currently says v0.1 selective disclosure is scoped to BBS+ secondary
commitments, a frozen predicate language, and a
`chio.selective-disclosure-proof.v1` envelope. It also names a new workspace
member `chio-zk-receipts` behind a default-off `zk` Cargo feature.

The current repo state on this branch does not match that implementation shape:

1. `crates/chio-zk-receipts/` is not present.
2. `crates/chio-federation/Cargo.toml` does not define `bbs-stub`.
3. No BBS+/AnonCreds dependency tree is assembled for this branch.
4. No auditor-view proof fixture exists under
   `examples/chiodome-bilateral/fixtures/auditor-view/`.
5. No conformance fixture proves unauthorized selective disclosure rejection.

Therefore C5 is not part of the current bounded canary evidence set.

## Machine-Readable Marker

The status marker is:

```text
.planning/trajectory-5/lane-c-demo/c5-selective-disclosure-status.toml
```

The current marker records `status = "deferred_to_v0_2"`. The strict
ship-bar gate reports that as PARTIAL, not MET. If a future branch changes the
marker to an evidence-complete status without adding the implementation crate,
feature, and proof fixtures, the gate reports a release-truth failure.

## Allowed Current Wording

Allowed wording:

> C5 selective disclosure is deferred to v0.2. The current canary may ship only
> as a five-artifact bundle with no auditor-view proof, no zk claim, and no
> BBS+ proof claim unless a future evidence branch adds the missing
> implementation and fixtures.

## Forbidden Current Wording

Do not write:

1. The demo emits a `chio.selective-disclosure-proof.v1` envelope.
2. The demo verifies a hidden refund amount predicate.
3. The branch ships BBS+, BBS, zk, or selective-disclosure proof support.
4. `crates/chio-federation` owns a `bbs-stub` selective-disclosure feature.
5. The release includes `auditor-view/proof.json` or
   `auditor-view/predicate-failed.json`.

## Future Evidence Required To Reopen C5

A future implementation branch may reopen C5 only after it adds all of the
following:

1. The implementation crate and default-off feature named by the normative spec,
   or an explicit spec change coordinated with the protocol owner.
2. Build evidence for the BBS+/AnonCreds dependency tree against the current
   workspace MSRV.
3. Canonical proof and negative fixtures under the canary fixture tree.
4. A conformance or smoke test proving unauthorized or over-disclosing views
   fail closed.
5. Updated marker values in
   `.planning/trajectory-5/lane-c-demo/c5-selective-disclosure-status.toml`.

Until then, C5 remains deferred and any release-facing artifact must say so.
