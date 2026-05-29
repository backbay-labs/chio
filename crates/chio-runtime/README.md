# chio-runtime

`chio-runtime` is the public Chio runtime admission and orchestration boundary.
It is a facade that exposes only the runtime admission, trust-floor,
orchestration, operations, and proof-regeneration APIs that Chio runtime
callers need. The historical implementation still lives in `chio-runtime-core`
while the public crate boundary moves to Chio names.

Depend on `chio-runtime` rather than `chio-runtime-core` for the stable runtime
API surface.
