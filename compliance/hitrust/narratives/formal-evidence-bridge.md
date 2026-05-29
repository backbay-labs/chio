# Formal Evidence Bridge for HITRUST

**Scope:** Chio healthcare design-partner deployment (this assessed release)
**Evidence source:** in-repository TLA+, Apalache, Lean, and Kani artifacts (`formal/`)

> **Status: internal readiness.** This explains, in plain language, the
> formal-method evidence that already exists in the repository. It is a
> reading aid, not a claim of certification.

## Plain-English summary

The `formal/` tree contributes formal-method evidence for a narrow set of
trust-boundary properties. These models are not a proof of the entire
Chio system. They are bounded, focused checks that support selected
HITRUST rows about access control, auditability, revocation, and
development assurance. The authoritative cross-reference from each named
property to the Rust call site it constrains is `formal/MAPPING.md`.

## Invariant mapping

| Formal invariant | What it means for the assessor | HITRUST mapping |
|-----------------|--------------------------------|-----------------|
| MonotoneLogApalache | Receipt-log state only advances; prior committed entries are not silently removed. | audit controls, integrity, operations |
| RevocationCutCompleteness | Revocation cuts remove future authority for revoked grants within the modeled boundary. | access control, incident containment |
| ReceiptBeforeAllow | A modeled allow decision has receipt evidence before the operation is considered complete. | audit controls, compliance evidence |
| KernelTransitionCancelSafe | Canceled kernel transitions do not leave an allowed tool call without the modeled checks. | fail-closed operations, development assurance |

## Limits

- The TLA+ and Apalache models are scoped to focused invariants.
- They do not replace tests, code review, or runtime monitoring.
- They do not cover out-of-tree HR, BAA, provider, or design-partner
  operations evidence.
- Any control row that needs production sampling still requires real
  operational evidence that does not yet exist (see
  `compliance/hitrust/operational-samples.md`).

## Evidence handling

The formal specs, configs, and run records live in the `formal/` tree
and are enforced in CI (`.github/workflows/apalache-safety.yml`,
`.github/workflows/apalache-temporal.yml`, and the
`scripts/check-mapping.sh` gate referenced by `formal/MAPPING.md`). This
should be treated as supporting evidence for development and integrity
controls, not as a standalone certification artifact.
