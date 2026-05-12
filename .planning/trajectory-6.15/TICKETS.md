# Chiodos 6.15 Tickets

## C6.15-001 Integrator

Create the branch, planning docs, baseline SHA, ticket map, no-planning-metadata rule, final gates, and 6.16 shadow note.

## C6.15-002 Normalization Contract

Add normalization profile and report contracts with schemas, Rust types, parser validation, fixtures, duplicate rejection, ambiguous mapping rejection, and secret or URL rejection.

## C6.15-003 Normalizer CLI

Generate canonical delivery evidence from local Alertmanager and SIEM-style fixture drops, plus a normalization report.

## C6.15-004 Source-Bound Drift

Add long-window drift v2 with source-hash binding and executable negatives for cross-handoff masking.

## C6.15-005 Route Review Packets

Add route-owner profile and review packet generation with bounded owner aliases and no contact material.

## C6.15-006 Assurance Package

Bind the full alert evidence chain into one operator-safe package with stable checks and action codes.

## C6.15-007 Dashboard And Docs

Add the assurance card and update runbooks to show observe, alert, trend, handoff, normalize, delivery import, acknowledge, drift-window, review, assurance package, and raw store last.

## C6.15-008 Fixtures And Negatives

Add golden fixtures and executable negatives for stale source, ambiguous mapping, secret-looking field, URL, unbounded label, unknown receiver, source hash mismatch, later-delivery masking, duplicate result across reports, route owner missing, route owner stale, severity weakening, runbook drift, and wrong expected code.

## C6.15-009 Assurance

Add gate script, schema registry entries, CI workflow, final verification, PR, review-thread cleanup, merge, and post-merge gate rerun.
