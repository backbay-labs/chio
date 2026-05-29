# chio-runtime-core

`chio-runtime-core` is the live Chio runtime admission layer for
kernel-mediated cross-vendor workflows. It holds the historical implementation
behind the public `chio-runtime` facade: admission, trust-floor enforcement,
orchestration, operations, and proof regeneration.

New callers should depend on `chio-runtime` for the stable surface. Use this
crate directly only when you need an internal that the facade does not re-export.
