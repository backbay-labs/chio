# ADR-0022: Sequencing The Store And Kernel Decomposition

- Status: Accepted
- Decision owner: cognition-market platform lane
- Related: ADR-0019, ADR-0021

## Context

Two aggregates in this workspace have grown past the size where a reader can
hold them: `chio-store-sqlite` is 188,099 lines across 228 files behind one
write connection, and `ChioKernel` carries `impl` blocks in 30 files. Both
were repeatedly named in review as the structural debt behind slower builds,
unclear ownership, and the single-writer ceiling on the self-hosted profile.

The obvious response, splitting them, is not one change. Measuring the seams
first shows why.

A first count of the four SQLite finding stores (market, purchase,
challenge, status) suggested heavy coupling: 19,921 lines reaching helper
names about 530 times. Reading what those names resolve to corrects the
picture, and the correction is the reason to measure rather than estimate.
`sqlite_error`, `invariant`, `require_identifier` and `admission_error` are
defined separately in each store against that store's own error type. They
are duplication, not coupling, and they leave with the store that owns them.

What the four stores actually import from the rest of the crate is two
things: `SqliteServingOwner` and `admission_operation_store::verify_active_owner`,
plus references among themselves. The pool ledger, 3,749 lines, reaches
crate internals nine times, all URI and path helpers.

The foundation is therefore small and specific: the serving owner with its
lease, rollback anchor and commit chains, the owner verification every read
and write fences on, and the SQLite URI and path helpers. It is not the
sprawling surface the raw reference count implied.

`ChioKernel`'s lanes are not uniform either. The finding-market lane already
compiles behind a default-off feature, which means its seam is understood and
its dependencies are cut. The session, dispatch, and evaluation lanes have no
such boundary.

Landing either decomposition as one change would put a 1,102-test suite and
the kernel's admission path through a rewrite whose blast radius nobody can
review honestly.

## Decision

### 1. Foundation before extraction

No store leaves `chio-store-sqlite` until the foundation it depends on is a
named, documented surface: the serving owner and its custody machinery, the
owner verification every read and write fences on, and the URI and path
helpers. The per-store error constructors are not part of it and travel with
their stores.

### 2. Extract in coupling order, not size order

The pool ledger goes first because its nine references make it a rehearsal
rather than a migration. The status store follows, since its legality rule
already moved to `chio-finding` (see below) and what remains is persistence.
The purchase, challenge, and market stores go last and together, because
they reference each other directly: the market store consults
`sales_blocked_tx` in the purchase store and `status_for_purchase_tx` in the
status store, so splitting them apart in separate steps would create a
dependency cycle between crates that does not exist between modules.

### 3. Rules leave before tables do

Where a store's behaviour is a rule rather than persistence, the rule moves
to the crate that owns the domain vocabulary and the store keeps its rows.
The finding status admission rule has already made this move: it lives in
`chio-finding` behind `FindingStatusSource`, and the SQLite store keeps only
the referential integrity of its own tables. This is the pattern for the
rest.

The SQLite authority is the only implementor of that source, and will stay
so until the hosted profile has the facts the rule needs. Hosted PostgreSQL
stores status as event projections with no feed floor, no per-finding
non-inclusion proof, and no epoch record; its catalog answers the coarser
question of what to stop advertising. No step in this sequence may assume a
hosted integration that does not exist.

### 4. The kernel decomposes by lane, feature-gated lanes first

`ChioKernel` is decomposed one lane at a time, starting with lanes that
already carry a compile-time boundary. Each extracted lane becomes a type
that borrows what it needs from the kernel rather than an `impl ChioKernel`
block, and the kernel keeps a thin method that delegates, so no caller
changes in the same commit that moves the logic.

### 5. Every step keeps the suite green on its own

No step in either sequence may depend on a later step to restore a passing
build. A sequence that cannot stop halfway is a single change wearing a
plan's clothing.

## Consequences

The decomposition takes several changes rather than one, and the crate and
god-type sizes stay in the file-hygiene allowlist until their steps land.
That is the cost of a decomposition that can be reviewed.

In exchange each step is independently reversible, and the coupling
measurements above give the sequence an order that will not need revisiting.

The rule extraction in step 3 does not by itself make two authorities agree,
and this record should not be read as claiming it does. Today one authority
implements the rule. What the extraction buys is that the decision is no
longer buried in that authority's row loading, so the next profile to need
it inherits the rule instead of writing a second one; agreement follows only
when a profile can supply the facts the rule sequences, which for hosted
PostgreSQL means a status-proof store it does not have.
