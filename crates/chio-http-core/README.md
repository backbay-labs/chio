# chio-http-core

`chio-http-core` defines the protocol-agnostic HTTP security types shared by
every HTTP substrate adapter in Chio: the request model, caller identity,
session context, HTTP receipts, and verdicts. It is the foundation for
`chio-openapi`, `chio-config`, `chio api protect`, and the language-specific
middleware crates.

Use this crate when building an HTTP-facing Chio integration that needs the
shared request and verdict shapes without committing to a specific transport.
