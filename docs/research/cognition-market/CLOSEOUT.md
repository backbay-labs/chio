# Cognition Market Roadmap Closeout

## Decision

The activated cognition-market roadmap is implementation-complete. M0 through
M6, M8, and M9 are merged into `main` through PRs #1032, #1033, #1034, #1035,
#1036, #1049, #1051, and #1053. The shipped profile is the bounded
single-operator deterministic-replay market. It is not a cross-organization
fair-exchange claim.

M7 remains conditional and unbuilt. Its trigger was re-evaluated on 2026-08-21
and remains false because no verified bilateral seller and buyer deployment
request exists. The ignored `cognition_market_cross_org_escrow` test remains
the fail-first activation seam. A real bilateral request must first start and
accept ADR-C; it does not silently widen this release profile.

## Exact-candidate evidence

Run the focused closeout gate from a clean candidate commit:

```bash
./scripts/qualify-cognition-market.sh
```

The gate executes the bounded-profile contract, production-router composition,
authenticated public purchase route, zero-charge digest-mismatch lane, CLI
Finding surface, transaction passport, open-market flow, and authenticated
SQLite pool ledger. It rejects a dirty worktree, a mismatched hosted candidate
SHA, or skipped CLI transport evidence.

The public purchase gate dogfoods the real same-second revocation-cursor
regression found while running the full release gate. It sells the verified
fix as a signed Finding through the production router, authoritative
coordinator, durable kernel, reference seller, SQLite authority, and local
reversible-hold capture path. Qualification fails unless the cycle records one
capture, one seller invocation, the signed delivery and purchase artifacts,
and byte-identical replay without a second capture.

The generated release artifact is:

```text
target/release-qualification/cognition-market/qualification.json
```

The report binds the exact candidate SHA, every gate command, the digest of
each log, the dogfood transaction, the M7 disposition, the four approved
claims, and the two audited assumptions. `scripts/qualify-release.sh` runs this gate before constructing the
top-level release artifact manifest, so hosted Release Qualification retains
the same evidence.

## Claim boundary

The approved cognition-market claims are:

- `claim.finding.delivery_digest_bound`
- `claim.finding.evidence_bound`
- `claim.finding.status_fresh`
- `claim.finding.bond_backed`

The surviving audited assumptions are:

- `ASSUME-FINDING-STATUS-OPERATOR-COMPLETENESS`
- `ASSUME-FINDING-SELLER-TOOL-SERVER`

Status freshness does not prove operator insertion completeness. Delivery and
bond evidence do not prove seller-side external effects, future solvency, or
cross-organization fair exchange.

## Release completion contract

Roadmap implementation completion and public release authorization are
separate decisions. The release candidate is evidence-complete only when:

1. the focused cognition-market gate passes on a clean commit;
2. the repository's local release gates pass;
3. GitHub `CI` and `Release Qualification` pass on the exact final `main` SHA;
4. the hosted release artifact contains the cognition-market report and its
   logs; and
5. an operator explicitly decides whether to tag and publish that candidate.

Until the hosted gates and operator decision are recorded, this document does
not claim public GA availability.
