# ADR-0004: First Receipt Backend

- Status: Implemented
- Decision owner: trust lane

## Context

Chio currently stores receipts in memory.

`v1` requires durable receipts, but there are several ways to get there:

- SQLite first
- append-only local file first
- remote receipt service first

## Decision

Chio will use SQLite as the first durable receipt backend.

The receipt persistence interface should be abstract enough to support later backends such as:

- local append-only file
- remote receipt service
- object store plus index
- transparency-log service

## Rationale

SQLite is the best first backend because it gives:

- durability
- queryability
- deterministic local setup
- easy CI and fixture support
- less operational complexity than a remote service

Append-only files are simpler to write but weaker for querying and evolution.

A remote service first would slow feature delivery by making trust infrastructure a prerequisite for everything.

## Consequences

### Positive

- fast path to durable receipts
- easy local developer mode
- straightforward integration tests

### Negative

- still a single-node persistence story at first
- application-layer append-only semantics must be enforced deliberately

## Required follow-up

- define receipt-store interface before implementation
- decide schema for request ID, session ID, capability ID, timestamp, and decision indexes
- define migration path from SQLite to remote receipt service

## Non-goal

This ADR does not define the final transparency or witness model for receipts. It only chooses the first durable backend.
