# chio-guard-registry

`chio-guard-registry` owns the OCI distribution surface for `.arcguard`
wasm-component artifacts: cosign-verified pull and publish of guard modules
with offline cache support. Registry transport and artifact shape checks stay
local to this crate, while Sigstore verification is delegated to
`chio-attest-verify`.

Use this crate to distribute or fetch signed WASM guard modules. The runtime
that executes the fetched modules is `chio-wasm-guards`.
