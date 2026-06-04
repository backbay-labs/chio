# chio-attest-loopback Architecture

## Boundary

`chio-attest-loopback` owns the deterministic offline buyer and auditor proof-package harness. It generates fixture receipts, governance material, workflow receipts, verifier trust bundles, and verifier reports for the Chio attestation path.

## Internal Surfaces

The crate serves two modes. Fixture mode builds the full loopback package from deterministic seeds. Runtime mode accepts externally supplied signed tool receipts, or signed receipts plus DSSE envelopes and workflow steps, then binds them into the same verifier package shape.

## Trust Invariants

The trust boundary is runtime material intake. A supplied receipt must match the fixture vendor slot, carry a valid signature from the expected vendor key, and bind the loopback workflow action payload before the crate generates or accepts downstream proof material. Runtime artifacts also have to match the issued lease, governance receipt, parent-step hash chain, DSSE envelope, output hash, and consistency anchor.

## Current Hardening

Current hardening: runtime receipts now validate their signed action hash, `workflowId`, case reference, tool name, and loopback metadata before `proof_package_from_runtime_receipts` can build a package from them.

## Verification Focus

Tests should keep fixture determinism separate from runtime-material acceptance and should reject mismatched vendor slots, bad receipt signatures, stale leases, broken workflow lineage, and inconsistent DSSE envelopes.
