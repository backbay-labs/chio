# chio-guard-registry

`chio-guard-registry` owns the OCI distribution surface for `.arcguard`
wasm-component artifacts: digest-pinned OCI pull, publish, and offline cache
support for guard modules. Registry transport and artifact shape checks stay
local to this crate. Sigstore verification is delegated to
`chio-attest-verify` and uses explicit caller-supplied bundle bytes; this crate
does not discover Sigstore material through OCI referrers.

Use this crate to distribute or fetch signed WASM guard modules. The runtime
that executes the fetched modules is `chio-wasm-guards`.
