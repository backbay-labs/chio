# chio-enterprise-export Design

## D9 Crate Home Decision

`chio-enterprise-export` stays in `crates/platform` as the verifier for enterprise evidence export bundles. It composes transaction passports, data-governance reports, approval cases, telemetry projections, control maps, and risk comptroller reports.

The default homes considered were control-plane and products. Control-plane owns runtime service wiring; products expose commands and UI. This crate is a reusable offline verifier so CLI, Proof Room, and tests can share one enterprise truth path.

## Boundary

This crate owns enterprise export artifact validation and enterprise verifier reports. It does not create tenant exports, store regulated data, run SIEM delivery, or approve customer workflows.

## Invariants

Approval, receipt, risk, and passport signatures verify against pinned trust sets. Export evidence is digest-bound to the transaction passport and fails closed on missing retention, governance, telemetry, or control-map evidence.
