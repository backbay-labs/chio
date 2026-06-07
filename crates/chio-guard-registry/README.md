# chio-guard-registry

`chio-guard-registry` owns the OCI distribution surface for `.arcguard`
wasm-component artifacts: digest-pinned OCI pull, publish, and offline cache
support for guard modules. Registry transport and artifact shape checks stay
local to this crate. Sigstore verification is delegated to
`chio-attest-verify`. Pulls use explicit caller-supplied bundle bytes when
present; otherwise they discover Sigstore bundle material through OCI referrers.
When a Sigstore policy is supplied, missing or unverified bundle material denies
before cache admission.

Use this crate to distribute or fetch signed WASM guard modules. The runtime
that executes the fetched modules is `chio-wasm-guards`.
