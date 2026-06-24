# chio-commerce-order Design

## D9 Crate Home Decision

`chio-commerce-order` stays in `crates/platform` as the offline verifier for commerce order proof evidence. It validates order replay, payment lifecycle evidence, provider trust evidence, settlement packet bindings, mandate projections, and risk-comptroller links.

The default homes considered were `chio-market`, `chio-credit`, and `chio-settle`. Those crates own marketplace, credit, or settlement execution concerns. This crate verifies a cross-domain proof bundle and must not become a live market or payment executor.

## Boundary

This crate owns commerce proof replay and produces commerce verifier reports. It consumes risk and settlement evidence through explicit artifacts, but it does not move funds, price markets, select providers at runtime, or issue risk decisions.

## Invariants

Replay is deterministic. AP2, x402, and ACP-Commerce evidence is payload-bound by digest. Provider and receipt signatures verify against pinned keys supplied by the caller.
