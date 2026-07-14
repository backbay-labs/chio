# chio-bounded architecture

## Overview

`chio-bounded` is a pure, dependency-free library crate: no I/O, no async
runtime, and (outside the test-only `cfg(loom)` target) no dependencies at
all. It sits underneath any Chio serving process that keeps an in-memory
cache, ring buffer, or receipt mirror, and closes one specific failure mode:
an unbounded collection with no visibility into its size. Both collections
own a `SizeGauge` and enforce their capacity on every write.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Crate doc and the three public re-exports (`BoundedMap`, `SizeGauge`, `Ring`). |
| `src/ring.rs` | `Ring<T>`: fixed-capacity append-only buffer, oldest-first eviction. |
| `src/bounded_map.rs` | `BoundedMap<K, V>`: capacity-bounded, optionally idle-TTL-swept map with approximate-LRU eviction. |
| `src/gauge.rs` | `SizeGauge`: cloneable atomic live-count handle. |
| `src/sync.rs` | Private `Arc`/`AtomicUsize`/`Ordering` shim: std types by default, loom's models under `--cfg loom`. |

## Eviction and sweep

`BoundedMap` tracks insertion order in a side `VecDeque<(K, u64)>` keyed by a
monotonic per-insert sequence number, not a linked hash map:

1. `insert` assigns the next `seq` and appends `(key, seq)` to `order`, even
   when the key already exists, so a re-insert becomes the newest entry
   without removing the old `order` entry.
2. `evict_oldest` pops from the front of `order` and compares the popped
   `seq` against the key's current entry. A mismatch means the popped
   position is a stale duplicate left by a later re-insert, and is skipped.
3. Once `order` grows past `2 * capacity`, `compact_order` rebuilds it from
   the live entries sorted by `seq`, reclaiming stale duplicates in
   O(n log n) amortized over `capacity` inserts.
4. Every 256 inserts (`sweep_interval`), `sweep_idle` runs; it is a no-op when
   `idle_ttl_secs == 0`, otherwise it drops entries whose `last_seen_secs` is
   at or before `now_secs - idle_ttl_secs`. `get` refreshes `last_seen_secs`
   but does not move the entry in `order`, so a frequently-read key is
   protected from the TTL sweep but not from oldest-insert eviction.

`Ring<T>` has no analogous state: it is a `VecDeque<T>` that pops the front on
overflow.

## Invariants and failure modes

- `capacity == 0` disables both collections: `push` / `insert` store nothing
  and hand the item straight back rather than panicking or silently dropping
  it.
- `len()` never exceeds `capacity()` on either collection. The property test
  in `bounded_map.rs` and the stress and loom tests under `tests/` assert
  this under random operation sequences and concurrent access through an
  external `Mutex`.
- `SizeGauge::set` is `pub(crate)`: only `Ring` and `BoundedMap` can mutate a
  gauge, so a consumer holding a cloned gauge can only read it.
- `Ring::clone` gives the clone a fresh, independent `SizeGauge` seeded to the
  current length, so pushing to a cloned snapshot can never corrupt the
  owner's gauge.
- Neither collection is internally synchronized; concurrent access requires
  an external lock, as both the stress test (`tests/stress_bounded_map.rs`)
  and the loom model (`tests/loom_bounded_map.rs`) do.

## Dependencies

None at compile time outside `std`. `loom` is a `cfg(loom)`-gated,
workspace-pinned dependency used only by the nightly `--cfg loom` build of
`tests/loom_bounded_map.rs`. `proptest` is a workspace-pinned dev-dependency
used by the property test in `src/bounded_map.rs`. No `chio-*` crate is a
dependency; this crate sits at the base of the dependency graph.
