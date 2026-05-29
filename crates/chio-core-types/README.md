# chio-core-types

`chio-core-types` holds the shared Chio substrate types (capability, receipt,
manifest, and session boundaries). These are the
protocol-wide types that stay stable while heavier domain crates split away
from the compatibility facade.

The crate is `no_std + alloc` by source: under `--no-default-features` every
module compiles against `core` and `alloc` only, which is what lets
`chio-kernel-core` cross-compile to `wasm32-unknown-unknown` and other embedded
targets. The default `std` feature re-enables `std`-backed error impls.

Depend on `chio-core-types` when you need the canonical Chio shapes without the
broader `chio-core` surface. For signing and verification helpers, use
`chio-core`.
