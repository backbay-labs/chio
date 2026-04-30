# Rust Kernel Verdict Driver

This driver is the Rust-only first path for the verdict matrix. It loads the
hash-pinned scenario corpus, evaluates each scenario with the same fail-closed
ordering the kernel exposes to SDK drivers, and emits the semantic tuple used
by the diff oracle:

- `verdict`
- `reason_code`
- `scope_set`

The driver is registered as the `verdict_matrix_rust_driver` integration test
on the parent `chio-conformance` package so CI can run the exact ticket gate:

```bash
cargo test -p chio-conformance --test verdict_matrix_rust_driver --quiet
```

Unsupported scenarios must report `unsupported`. The current P4 corpus requires
only `rust-kernel`, so any unsupported scenario in this driver is a test
failure.
