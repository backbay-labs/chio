# Chiodos 6.2: Verifier-Owned Workflow Trust Contract

Status: implemented locally, pending PR review and merge.

Chiodos 6.2 closes the verifier-owned trust boundary for offline buyer and
auditor proof packages. The verifier, not the package, owns BBS issuer trust,
peer pins, accepted ladder references, action-class policy, revocation epoch,
and accepted workflow-intersection hashes.

## Guardrails

- Runtime changes must have runnable tests or a script gate.
- Planning names stay in `.planning/trajectory-6.2`; crate code, fixture names,
  script names, protocol docs, and CLI output use product names only.
- Proof packages may carry workflow-intersection artifacts for audit
  portability, but acceptance requires verifier-owned trust material.
- Reveal-set BBS remains the only selective-disclosure claim.
- Hidden range predicates, VC Data Integrity BBS interop, zkVM support,
  networked orchestration, and pheromone runtime are out of scope.

## SHA Of Record

- Baseline: `2c653b26abbb4677608628f2a020e92c4b25128b`
