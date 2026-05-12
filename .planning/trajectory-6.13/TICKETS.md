# Chiodos 6.13 Tickets

## C6.13-001 Integrator

Status: complete

Create branch, planning docs, baseline SHA, final gates, no-planning-metadata rule, and 6.14 shadow note.

## C6.13-002 Handoff Contract

Status: complete

Add Rust types, schema files, registry entries, parsers, duplicate rejection, stale profile rejection, and golden fixtures.

## C6.13-003 Dry-Run Evaluator

Status: complete

Evaluate alert report, trend report, routing profile, and handoff profile into schema-valid readiness evidence without dispatch.

## C6.13-004 CLI

Status: complete

Add `relay alert handoff`, schema-valid JSON output, stable errors, and parse tests.

## C6.13-005 Negative Corpus

Status: complete

Make alert routing and handoff negative cases executable with stable expected failure codes.

## C6.13-006 Dashboard

Status: complete

Fetch alert and trend reports independently, preserve firing alert visibility when trend is missing, and select primary route by severity.

## C6.13-007 Docs And Examples

Status: complete

Add receiver handoff examples using bounded labels and local refs only. Refresh runbook wording and dashboard README.

## C6.13-008 Assurance

Status: complete pending PR review and post-merge rerun

Add the handoff gate script, wire CI path triggers, run final verification, open PR, resolve review threads, merge, and rerun gates on `main`.
