# ADR-0021: Hosted Market Storage Authority And Transition-Rule Ownership

- Status: Accepted
- Decision owner: cognition-market hosted lane
- Related: ADR-0017, ADR-0019, ADR-0020

## Context

The cognition market ships two durable stacks. The single-operator profile
runs on SQLite (`chio-store-sqlite` finding stores: market, purchase,
challenge, status). The hosted profile runs on PostgreSQL
(`chio-finding-market-store-postgres`) with forced row-level security,
per-tenant advisory locking, and an event-sourced domain journal. A signed
per-tenant authority-transition artifact moves a tenant between them through
the modes `shadow`, `frozen`, `rollback_window`, `authoritative`, and
`retired`.

Until this decision, three copies of market semantics could drift
independently: the SQLite stores' lifecycle checks, the Postgres store's
domain grammar, and the HTTP edge's own table binding write routes to event
kinds and artifact schemas. The hosted hardening wave closed several
transition bypasses that were symptoms of exactly this duplication.

## Decision

### 1. One authoritative store per tenant, Postgres-authoritative endgame

For hosted deployments PostgreSQL is the authoritative store. SQLite remains
the single-operator local profile and is never authoritative for a hosted
tenant outside a cutover. During cutover, authority is defined solely by the
tenant's durable authority mode; at most one store is authoritative for a
tenant at any instant, and every mode change requires the signed
authority-transition artifact evaluated inside the store's transition
function. No code path may infer authority from any other signal.

### 2. The domain event grammar is single-sourced

`chio-finding-market-port` owns the canonical grammar: the closed set of
domain event kinds, the aggregate family each mutates, and the exact signed
artifact schema each payload must verify against
(`HostedMarketDomainEventKind`, `HostedAggregateKind`). The HTTP edge derives
its write-route table from this grammar and storage adapters validate against
it. A second encoding of any part of this binding is a defect.

### 3. Transition-rule ownership

Each lifecycle state machine has exactly one enforcement point:

| Machine | Owner |
|---------|-------|
| Hosted authority mode (`shadow` ... `retired`) | The Postgres store's signed-transition path; callers submit artifacts, never state |
| Challenge liability lifecycle (`open` ... `settled`) | The SQLite challenge store's guarded transitions behind the finality coordinator |
| Finding status feed (live, pending, retracted) | The status store floor plus the status-proof verifier (ADR-0020) |
| Domain event admission (kind, aggregate, schema, revision) | The port grammar plus the storage adapter's revision check |

A surface that needs one of these decisions consults the owner; it does not
re-derive the rule. If the hosted profile later enforces challenge liability
directly, the SQLite transition table moves into a store-neutral module first
and both stores execute that module.

## Consequences

- The edge cannot admit a write whose kind, aggregate, and schema disagree
  with storage, because both read one table.
- Store adapters (current and future) implement the port's backend trait and
  grammar; a SQLite hosted adapter or a second SQL backend would reuse both
  unchanged.
- Cutover correctness reviews concentrate on one transition function per
  machine instead of auditing every caller.
