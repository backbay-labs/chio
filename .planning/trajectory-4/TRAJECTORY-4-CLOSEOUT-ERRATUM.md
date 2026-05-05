# Trajectory 4 Closeout Erratum

Status: reopened for trj4 closeout remediation.

The previous trajectory 4 closeout claim is superseded by this erratum. The trj4 review found that several evidence gates were marked closed while their implementation, conformance, CI, and formal artifacts were still incomplete or proposed.

Until this remediation branch completes, trj4 must not be represented as fully delivered. Closure requires:

- `cargo test --workspace` green from a clean checkout.
- Active evidence registry entries backed by real artifacts.
- Formal theorem entries present in the formal toolchain, not only in spec-side proposed buckets.
- Hot-path enforcement for capability negotiation, signed-artifact schemas, receipt v2 DAG verification, mobile attestation, anchor witnesses, egress contracts, and metrics.
- Executable conformance tests for the negative cases listed in the trajectory 4 closeout plan.

This file is intentionally conservative: it records that the release claim was premature rather than trying to paper over missing evidence with proposed status.
