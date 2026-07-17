# chio-bounded

Reusable bounded in-memory collections for Chio serving processes: a
capacity-and-TTL map, an append-only ring, and a live size gauge shared by
both. The crate's one invariant: no long-lived collection in a serving process
exists without a capacity policy and a live size metric.

## Responsibilities

- Provide `Ring<T>`, a fixed-capacity append-only buffer that evicts
  oldest-first and hands the evicted item back to the caller.
- Provide `BoundedMap<K, V>`, a capacity-bounded cache with approximate-LRU
  eviction (oldest-insert order) and an optional idle-TTL sweep.
- Provide `SizeGauge`, a cloneable atomic handle to a collection's live entry
  count, readable by any holder but mutable only from inside this crate.
- Treat `capacity == 0` as an explicit disabled mode on both collections:
  nothing is stored, and each item is handed straight back.

## Public API

- `Ring<T>` - `with_capacity(capacity, gauge)`, `push(item) -> Option<T>`,
  `iter()`, `len()`, `is_empty()`, `capacity()`. `Clone` (where `T: Clone`)
  produces a snapshot with its own independent `SizeGauge`.
- `BoundedMap<K, V>` - `new(capacity, idle_ttl_secs, gauge)`,
  `insert(key, value, now_secs) -> Option<(K, V)>`,
  `get(&mut self, key, now_secs) -> Option<&V>` (refreshes the idle timestamp,
  hence `&mut self`), `len()`, `is_empty()`, `capacity()`.
- `SizeGauge` - `new()`, `get() -> usize`. Construct one per collection and
  clone it out to whatever reads live counts (a telemetry exporter, a health
  check); the collection itself is the only writer.

## Usage

```rust
use chio_bounded::{BoundedMap, SizeGauge};

let gauge = SizeGauge::new();
let mut cache: BoundedMap<String, Vec<u8>> =
    BoundedMap::new(1024, 300, gauge.clone());

// `insert` returns the evicted (key, value) pair when capacity forces an
// eviction, so the caller can persist it before it drops.
if let Some((evicted_key, evicted_value)) = cache.insert(key, value, now_secs) {
    // persist-before-drop
}

// Elsewhere, e.g. a telemetry exporter: read the live count without locking.
let live = gauge.get();
```

## Testing

`cargo test -p chio-bounded` runs the unit, property, and std-thread stress
tests. The exhaustive loom concurrency model is nightly-only and not part of
that run:

```
RUSTFLAGS="--cfg loom" cargo test -p chio-bounded --test loom_bounded_map
```

## See also

- `chio-kernel` - uses `Ring` for its `ReceiptLog` and `ChildReceiptLog`
  mirrors and `BoundedMap` for the federation dual-signed-receipt and
  DSSE-envelope stores.
- `chio-http-session` - uses `Ring` for the session journal and tool-call
  sequence.
