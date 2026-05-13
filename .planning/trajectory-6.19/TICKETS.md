# Chiodos 6.19 Tickets

## C6.19-001 Integrator

Create the branch, record the stacked baseline SHA, add the planning packet, final gates, no-planning-metadata rule, and 6.20 shadow note.

Status: completed

## C6.19-002 Safe Archive Helper

Add reusable `chio-cli` tar/gzip reader, writer, staging, path, entry type, duplicate, size, and ratio validation helpers.

Status: completed

## C6.19-003 Archive Package Refactor

Move 6.18 archive package CLI IO onto the shared helper while keeping relay semantic verification in `chio-pheromone-relay`.

Status: completed

## C6.19-004 Package Generations

Add package generation and previous manifest continuity to archive package create, verify, report schemas, and CLI.

Status: completed

## C6.19-005 Guard Install Hardening

Replace `.arcguard` install unpacking with the safe helper and fail closed on unsafe manifest names, links, extra members, duplicate wasm, and existing targets.

Status: completed

## C6.19-006 Conformance Extraction Hardening

Replace raw conformance archive unpacking with the safe helper while preserving checksum-first behavior.

Status: completed

## C6.19-007 Restore Drill Contract

Add restore profile/report schemas, Rust types, fixture reports, and pure local restore/readback drill evaluation.

Status: completed

## C6.19-008 CLI And Gates

Add restore-drill CLI, executable restore negative corpus, and the archive hardening gate script with default, schema-only, and negative-only modes.

Status: completed

## C6.19-009 Dashboard And Docs

Add dashboard API, types, cards, tests, and update relay runbook, observability docs, dashboard README, and Chiodos pheromone spec text.

Status: completed

## C6.19-010 Assurance

Add CI path triggers, run final gates, open PR, resolve all review threads, merge, and rerun archive-hardening and archive-package gates on `main`.

Status: in progress
