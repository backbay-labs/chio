# Chiodos 6.1: Strict Verifier Productization

Status: active execution lane.

Chiodos 6.1 turns the v0.1 buyer and auditor proof package into a production
verifier surface. The lane closes the strict bilateral predicate gap, moves
proof-package verification out of the example crate, and adds a CLI verifier
plus acceptance gates that fail closed.

## Guardrails

- Runtime changes must have runnable tests or a script gate.
- Planning names stay in `.planning/trajectory-6.1`; crate code, fixture names,
  script names, protocol docs, and CLI output use product names only.
- The strict verifier must not accept `chio.bilateral-signature-slice.v1` as
  Chiodos conformance evidence.
- Real BBS reveal-set disclosure remains in scope.
- Hidden range predicates, VC Data Integrity interop, zkVM support, and
  networked orchestration remain out of scope.

## SHA Of Record

- Baseline: `fa254c742f4026985894f75e68868a29c5178a60`
