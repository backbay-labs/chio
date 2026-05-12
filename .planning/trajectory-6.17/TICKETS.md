# Chiodos 6.17 Tickets

## C6.17-001 Integrator

Create the active branch, record the baseline SHA, add this planning packet, and keep planning metadata under `.planning`.

Status: completed

## C6.17-002 Archive Contract

Add archive profile and archive report types, schemas, registry entries, parser validation, duplicate bundle and path rejection, and golden fixtures.

Status: completed

## C6.17-003 Closeout Contract

Add closeout profile and closeout report types, stable closeout codes, and checks for verified bundle, replay match, retention safety, recovery drill status, and route-review presence.

Status: completed

## C6.17-004 Verification Flow

Reuse existing export bundle verification, replay, retention, and recovery drill logic. Surface per-bundle failures as quarantine or closeout-blocked rows where possible.

Status: completed

## C6.17-005 CLI

Add `archive plan` and `closeout review` commands under the relay alert assurance CLI with schema-valid JSON output and parse tests.

Status: completed

## C6.17-006 Fixtures And Negatives

Add archive and closeout profiles, reports, and executable negatives for untrusted exporter, missing file, legal hold, and wrong expected code detection.

Status: completed

## C6.17-007 Dashboard And Docs

Extend the existing relay alert assurance card with archive and closeout lifecycle state. Missing reports render unknown and do not hide active alert or delivery state.

Status: completed

## C6.17-008 Assurance

Add the archive gate script, CI path triggers, run final verification, open PR, resolve review threads, merge, and rerun the new gate on main.

Status: in progress
