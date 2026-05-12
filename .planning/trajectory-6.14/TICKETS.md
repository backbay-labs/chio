# Chiodos 6.14 Tickets

## C6.14-001 Integrator

Create the branch, active planning docs, baseline SHA, ticket map, final gate checklist, and no-planning-metadata rule.

## C6.14-002 Delivery Contract

Add relay alert delivery profile, delivery report, acknowledgement report, handoff drift report, and negative corpus contracts with parser validation, duplicate rejection, secret-marker rejection, stale profile rejection, schemas, registry entries, and golden fixtures.

## C6.14-003 Delivery Import Evaluator

Validate downstream result artifacts against handoff route readiness, receiver aliases, target refs, route aliases, alert codes, dedupe keys, severity floors, runbook refs, source hashes, and freshness windows.

## C6.14-004 Acknowledgement Evidence

Add acknowledgement reports for delivered, accepted, failed, delayed, duplicate, unknown, and operator-acknowledged downstream outcomes using bounded labels only.

## C6.14-005 Handoff Drift

Compare handoff and delivery report directories for route alias drift, severity weakening, missing firing alert codes, runbook drift, receiver drift, stale windows, and missing critical delivery evidence.

## C6.14-006 CLI

Add delivery import, acknowledge, and drift commands with schema-valid JSON output and parse tests. Do not add send, notify, URL, credential, or request-body flags.

## C6.14-007 Dashboard

Add delivery and handoff cards to the existing dashboard. Missing delivery reports render unknown and do not hide firing alert state.

## C6.14-008 Fixtures And Negatives

Add delivery-result fixtures and executable negatives for stale handoff, mismatched route, missing dedupe key, unknown receiver, duplicate result, secret-looking fields, unbounded labels, missing evidence, and severity or runbook drift.

## C6.14-009 Assurance

Add the delivery gate script, CI path triggers, docs refresh, final verification, PR, review-thread cleanup, merge, and post-merge gate rerun.
