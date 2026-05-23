# Chiodos 6.18 Tickets

## C6.18-001 Integrator

Create the active branch, record the baseline SHA, add this planning packet, and keep planning metadata under `.planning`.

Status: completed

## C6.18-002 Bundle Identity

Add optional bundle ids for relay alert assurance export and use root-relative portable bundle labels when reading bundle roots.

Status: completed

## C6.18-003 Archive Package Contract

Add signed archive package manifest, trusted archive packager, package report, schemas, registry entries, fixture documents, and pure verifier checks in `chio-pheromone-relay`.

Status: completed

## C6.18-004 Package CLI

Add archive package create and verify commands. Keep tar/gzip filesystem IO in `chio-cli` and verify package signatures, selected members, nested export bundle signatures, archive readiness, closeout binding, and safety claims.

Status: completed

## C6.18-005 Safe Extraction

Add verified extraction plan construction and archive package extraction. Reject unsafe paths, unsupported entry types, duplicates, resource overflow, unlisted members, missing members, and hash mismatches before writing.

Status: completed

## C6.18-006 Physical Readback

Add local physical archive evidence and readback drill reports. Make no external custody or storage claims.

Status: completed

## C6.18-007 Retention Handoff

Add local retention handoff evidence and readiness reports using bounded aliases and local hashes only.

Status: completed

## C6.18-008 Dashboard And Docs

Extend relay alert assurance dashboard, runbooks, and observability docs with local archive package, extraction, physical readback, and handoff readiness states.

Status: completed

## C6.18-009 Assurance

Add archive package gate script and CI workflow, run final verification, open PR, resolve review threads, merge, and rerun the new gate on main.

Status: in progress
