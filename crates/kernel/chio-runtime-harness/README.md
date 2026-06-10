# chio-runtime-harness

`chio-runtime-harness` is a live runtime loopback harness library for Chio. It
drives the runtime admission and orchestration path end to end so proof
artifacts can be regenerated deterministically.

Use this crate in tests and tooling that need to exercise the live runtime and
reproduce its proof output. The runtime surface it drives is `chio-runtime`.
