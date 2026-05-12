# Chiodos 6.16 Tickets

- C6.16-001, Integrator: Create branch, planning docs, baseline SHA, ticket map, final gates, no-planning-metadata rule, and 6.17 shadow note.
- C6.16-002, Export Contract: Add Rust types, schemas, registry entries, manifest body signing, trusted exporter parsing, duplicate rejection, and golden fixtures.
- C6.16-003, Export Builder: Implement bundle creation with clean output-dir enforcement, relative paths only, canonical hashes, byte counts, artifact roles, retention classes, safety claims, and source-chain validation.
- C6.16-004, Export Verification: Verify signed manifests, trusted exporter status/windows, canonical file hashes, source assurance hash, package/report hash chain, path safety, and unsupported schema rejection.
- C6.16-005, Replay: Rebuild the assurance package from bundled source reports, compare canonical hashes, reject unexpected JSON artifacts, and emit replay reports.
- C6.16-006, Retention: Add dry-run retention profile/report logic over bundle roots. Block pruning for referenced artifacts, stale unverified bundles, replay failures, missing route-owner review, and legal-hold classes.
- C6.16-007, Recovery Drills: Add executable drills for stale normalized evidence, missing delivery evidence, missing route-owner review, expired assurance package, bad export signature, path traversal, and secret-looking fields.
- C6.16-008, CLI And Dashboard: Add CLI subcommands, parse tests, schema-valid JSON output, dashboard lifecycle card, API tests, component tests, and graceful missing-report behavior.
- C6.16-009, Fixtures And Negatives: Add committed export, replay, retention, drill, trusted exporter, signing-key, and negative corpus fixtures. Include wrong-expected-code detection in the gate.
- C6.16-010, Assurance: Add gate script, CI workflow, final verification, PR, zero unresolved review threads, merge, and post-merge gate rerun.
