# chio-attest-loopback

`chio-attest-loopback` is a deterministic loopback proof-package and runtime
harness library for Chio buyer and auditor verification. It generates proof
packages and replays them through the verifier so the attestation path can be
exercised end to end and regenerated reproducibly.

Use this crate in tests and tooling that need a self-contained attestation
loop. The verification boundary it exercises is `chio-attest-buyer`.
