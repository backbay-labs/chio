# chio-trust-market-context Design

## D9 Crate Home Decision

`chio-trust-market-context` stays in `crates/platform` as the verifier for trust-market evidence used by commerce and enterprise proof bundles. It checks discovery, selection, scorecards, reputation imports, SLA evidence, collateral, guarantees, jurisdiction, and risk links.

The default homes considered were `chio-market`, reputation, and risk. Those homes own their domain primitives. This crate verifies a composed proof context across those domains without becoming a market executor or reputation service.

## Boundary

This crate owns trust-market proof verification and trust-market verifier reports. It does not select providers at runtime, update reputation, enforce SLAs live, or authorize settlement.

## Invariants

Market receipts are signature-checked against pinned market authority keys. Risk evidence refs must point to verified report evidence. Unsupported market claims are limited and reported instead of silently accepted.
