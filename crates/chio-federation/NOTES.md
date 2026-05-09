# chio-federation NOTES

## Bilateral Verifier Schema Completion

The bilateral verifier in `bilateral_verifier.rs` is currently labeled
a **partial local verifier**, not the full full §7 conformance
verifier. This note records the explicit work deferred to a future
schema-completion milestone.

### Open items

1. **Predicate schema completion** (`bilateral_dsse::BilateralPredicate`):
   add the `tool_args_hash` field that
   `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §5/§6 list as
   required, and reject envelopes that omit it. Review the predicate
   for any internal non-schema fields and either remove them or move
   them outside the signed Statement.

2. **Error mapping precision**: the verifier currently maps
   parseable-base64-but-schema-malformed Statement JSON to
   `dsse.malformed` instead of `statement.malformed`. Update the
   error mapping to match the spec §7.1 codes one-to-one for all
   parse paths.

3. **Subject digest binding shape**: the producer side hashes
   `ChioReceiptBody`. Review the verifier's resolution path to confirm
   it re-hashes the body retrieved from the receipt store and returns
   `subject.digest_mismatch` (not `statement.malformed`) when the
   digest disagrees.

4. **Step coverage matrix**: produce a step-by-step coverage matrix
   against the spec §7 list (steps 1-17), explicitly mark each step
   as "covered", "partial", or "deferred", and pin the matrix in this
   file or its successor doc.

### Why this is deferred

The `chio-federation` crate already builds with the partial verifier in
production (callers do not advertise full §7 conformance based on its
output), so the honest move is to ship the partial verifier with the
relabeled module doc and let a future focused change close the schema gaps.
