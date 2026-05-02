# M06: Focused Formal Invariants + Supply-Chain Hygiene v2

**Wave:** W2  |  **Trust-boundary:** yes  |  **Tickets:** 28  |  **Effort weeks:** 7/10/14

## In one paragraph

M06 closes the highest-value formal assumptions (4 named Apalache
invariants on a kernel-state subset, NOT a full FSM per D04) and
ships supply-chain hygiene v2 (cargo-vet adoption, SBOM publication
per release, CVE alert pipeline; not crate consolidation per D05).
Release gates are dual: QUALIFICATION (formal half) + RELEASE_AUDIT
(supply-chain half). Apalache contractor (Informal Systems primary,
Runtime Verification fallback) signs off the 4 invariants; M09
HITRUST assessor consumes the SBOM; M08 reviewer cites the Apalache
invariant set.

## Phases at a glance

| Phase | Tickets | One-liner |
|-------|---------|-----------|
| P0 | 4 | Audit baseline + invariant shortlist + Apalache contractor scoping |
| P1 | 6 | Apalache scaffold + 4 invariant specs + nightly CI lane |
| P2 | 5 | cargo-vet top-50 audits + standalone workflow + 50-100 row exemption chase-down |
| P3 | 5 | SBOM workflow + source-tree scan + cosign signing + M09 handshake |
| P4 | 5 | cargo-audit + osv-scanner workflow + GitHub Issues routing + deny.toml refresh |
| P5 | 3 | Apalache contractor sign-off + audit doc closure |

## Locked decisions

- D04 focused invariants only; full FSM deferred to trajectory-4
- D05 API-tier + supply-chain only; consolidation 88->70 deferred to
  trajectory-4

## Active freezes

m06-supply-chain-pivot (P2-P4) and m06-revocation-oracle-pivot (P1-P2).

## When this milestone is done

- 3-4 named Apalache invariants closed; spec checked-in under
  `formal/apalache/`.
- cargo-vet enforced in CI; SBOM published per release.
- CVE-alert workflow live; M09 HITRUST assessor consumes the SBOM.
