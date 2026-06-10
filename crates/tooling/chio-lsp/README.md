# chio-lsp

`chio-lsp` is the Chio language server. It hosts a `tower-lsp` server and a
`dashmap`-backed document cache shared by the diagnostics, completion, hover,
and go-to-definition subsystems for `chio.yaml`, tool manifests, and the guard
DSL. Wire schemas under `spec/schemas/chio-wire/v1/` are loaded read-only. The
server stops at the document boundary; it does not run the kernel.

Use this crate to power editor tooling for Chio configuration and guard
authoring.
