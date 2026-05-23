# Chiodos 6.20 Tickets

## C6.20-001 Integrator

Create the branch, active planning docs, exact stacked baseline SHA, ticket map, final gates, no-planning-metadata rule, and 6.21 shadow note.

Status: completed

## C6.20-002 Review Contract

Add Rust types, schema constants, schemas, registry entries, parsers, profile validation, report rows, stable review codes, and golden fixtures.

Status: completed

## C6.20-003 Evidence Loader

Add CLI-side local report loading for archive package reports, restore drill reports, physical archive drill reports, and retention handoff reports. Reuse package verification when archive packages are present.

Status: completed

## C6.20-004 Chain Review

Verify local kernel consistency, package id, package generation, previous manifest continuity, package report hash, package manifest hash, restore drill acceptance, trusted packager/exporter status, and source report freshness.

Status: completed

## C6.20-005 Sampling Review

Enforce minimum sampled member count and sample coverage basis points per package generation. Fail closed on stale, missing, zero, or insufficient physical readback evidence.

Status: completed

## C6.20-006 Handoff Drift

Compare allowed retention aliases and retention handoff reports across package generations. Reject unknown alias, alias drift, duplicate handoff evidence, stale handoff evidence, source hash mismatch, and claims of completed external custody.

Status: completed

## C6.20-007 CLI

Add `retention external-review`, parse tests, schema-valid output, clear nonzero errors for malformed inputs, and `accepted=false` reports for unhealthy but well-formed evidence.

Status: completed

## C6.20-008 Fixtures And Negatives

Add healthy, insufficient-sample, alias-drift, missing-restore, missing-readback, missing-handoff, and quarantined package fixtures. Make the negative corpus executable with wrong-expected-code detection.

Status: completed

## C6.20-009 Dashboard And Docs

Add dashboard API, types, cards, tests, and update relay runbook, observability docs, dashboard README, and Chiodos pheromone spec.

Status: completed

## C6.20-010 Assurance

Run final gates, open PR, confirm zero unresolved review threads, merge after CI is available, and rerun external-retention, archive-hardening, archive-package, archive, export, assurance, delivery, handoff, alert routing, bounded, diagnostic, and threat-mutant gates on `main`.

Status: in progress
