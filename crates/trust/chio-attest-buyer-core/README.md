# chio-attest-buyer-core

`chio-attest-buyer-core` is the offline proof-package verifier for Chio buyers
and auditors. It performs the full proof replay behind the public boundary in
`chio-attest-buyer`, with no network dependency.

Use this crate when you need the hardened verification core directly. Most
callers should depend on `chio-attest-buyer` for the public API and Chio data
types.
