# Chiodos 7.0 Tickets

## C7.0-001 Integrator

Create the active branch, record the baseline SHA, add this planning packet, keep planning names under `.planning`, and add the 7.1 shadow note.

Status: completed

## C7.0-002 Kernel Admission Hook

Add a generic pre-dispatch admission hook that can deny before tool dispatch or federation co-signing and can attach bounded receipt metadata.

Status: completed

## C7.0-003 Runtime Trust Input

Add signed strict runtime trust input over verifier-owned trust material, including wall-clock freshness and rollback checks.

Status: completed for signed v4 trust input, signer trust, freshness, revocation-root presence, and bundle/context hash binding. Rollback floor persistence remains a follow-up.

## C7.0-004 Runtime Admission Crate

Add `chio-chiodos-runtime` with admission profile, bundle, report, store, one-shot lease consumption, and stable failure codes.

Status: completed for profile, bundle, report, workflow-run report, JSON store, one-shot destructive lease consumption, and stable codes.

## C7.0-005 Chiodos Admission Checks

Enforce request binding, tool/server, args hash, capability id, workflow step, lease scope, governance containment, revocation status, origin/host kernels, and verifier-owned trust.

Status: completed for request/tool/server/args/capability/origin/host binding, destructive lease/governance presence, trust hash binding, and one-shot consumption. Full lease-scope/governance containment reuse from offline verifier remains a follow-up.

## C7.0-006 Live Loopback Workflow

Extend the three-vendor example into a live local kernel run that produces runtime receipts, bilateral evidence, workflow receipts, verifier reports, and pheromone deposits.

Status: completed for kernel allow/deny hook coverage and CLI loopback admission/report generation. Full three-vendor proof-package regeneration from live kernel outputs remains a follow-up.

## C7.0-007 Pheromone Advisory Consumption

Query existing pheromone runtime concentration in observe-only mode and record advisory output in admission reports and receipt metadata.

Status: completed for observe-only query-report consumption into admission reports and receipt metadata.

## C7.0-008 CLI And Fixtures

Add runtime CLI commands, schema-valid reports, golden runtime fixtures, executable negatives, and proof-package parity.

Status: completed for CLI commands, schemas, generated temp fixtures, executable negative replay and binding cases, and gate script.

## C7.0-009 Docs And Gates

Update Chiodos docs, add the runtime-spine gate script, and wire CI path triggers.

Status: completed for runtime gate script and CI path triggers. Broader narrative docs remain a follow-up.

## C7.0-010 Closeout

Run final gates, open PR, resolve all review threads, merge to `main`, and rerun runtime and proof gates on `main`.

Status: pending
