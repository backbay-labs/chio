# chio-provider-conformance Architecture

## Boundaries

- `capture.rs` owns the NDJSON capture schema and fixture path helpers.
- `assertions.rs` owns canonical JSON and verdict comparison helpers.
- `replay.rs` owns fixture loading, fixture-shape validation, provider replay orchestration, invocation comparison, verdict comparison, and lowered-response assertions.
- `src/bin/record.rs` owns live re-recording for credential-backed providers and atomic fixture replacement.
- `tests/` owns provider corpus totals, replay coverage, and cross-provider normalized receipt equality.

## Pain Points

- `replay.rs` is the central trust boundary for fixture ingestion, but it combines path discovery, schema validation, provider-specific replay, stream chronology checks, and lowering assertions in one large module.
- Fixture validation checks schema, non-empty identifiers, and intra-file `fixture_id` consistency, but it does not bind the embedded `fixture_id` to the NDJSON filename.
- Fixture validation also relies on provider-specific replay code to catch mixed-provider records, leaving generic `load_fixture` weaker than the conformance corpus contract.

## Constraints

- Preserve public replay APIs and existing feature flags.
- Preserve canonical JSON byte stability for invocation, verdict, and lowered-response assertions.
- Preserve fail-closed behavior: malformed captures, provider drift, fixture id drift, and missing verdicts must error before replay evidence is trusted.
- Do not edit generated artifacts or fixture captures unless a parser invariant proves they are already wrong.

## Affected Dependents

- Provider replay tests call `load_fixture` and provider-specific replay entrypoints.
- The `record` binary writes the same capture schema and already validates the requested scenario id on write.
- Release qualification consumes replay results as conformance evidence.

## Planned Improvement

Tighten generic fixture ingestion by binding fixture ids to their filename stem and by rejecting mixed-provider records inside one NDJSON fixture. This moves fixture identity validation into the owning conformance boundary instead of leaving it to per-provider replay callers.
