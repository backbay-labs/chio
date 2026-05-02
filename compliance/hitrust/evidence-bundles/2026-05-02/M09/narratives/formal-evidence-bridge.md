# Formal Evidence Bridge for HITRUST Assessors

**Milestone:** M09.P2.T7
**Scope:** Chio v3.18 healthcare design-partner deployment
**Evidence source:** M06 TLA+ and Apalache invariants

## Plain-English summary

M06 contributes formal-method evidence for a narrow set of trust-boundary
properties. These models are not a proof of the entire Chio system. They
are bounded, focused checks that support selected HITRUST rows about
access control, auditability, revocation, and development assurance.

## Invariant mapping

| M06 invariant | What it means for the assessor | HITRUST mapping |
|---------------|--------------------------------|-----------------|
| MonotoneLogApalache | Receipt-log state only advances; prior committed entries are not silently removed. | audit controls, integrity, operations |
| RevocationCutCompleteness | Revocation cuts remove future authority for revoked grants within the modeled boundary. | access control, incident containment |
| ReceiptBeforeAllow | A modeled allow decision has receipt evidence before the operation is considered complete. | audit controls, compliance evidence |
| KernelTransitionCancelSafe | Canceled kernel transitions do not leave an allowed tool call without the modeled checks. | fail-closed operations, development assurance |

## Limits

- The TLA+ and Apalache models are scoped to focused invariants.
- They do not replace tests, code review, or runtime monitoring.
- They do not cover out-of-tree HR, BAA, provider, or design-partner
  operations evidence.
- Any assessor row that needs production sampling still requires P3 or
  P4 evidence.

## Evidence handling

The P3 evidence bundle includes the formal specs, configs, run records,
and M06 audit doc. The assessor should treat this as supporting
evidence for development and integrity controls, not as a standalone
certification artifact.
