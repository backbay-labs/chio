# Rust Kernel Verdict Driver

This driver is the Rust-only first path for the verdict matrix. It loads the
hash-pinned scenario corpus, evaluates each scenario through `ChioKernel`, and
emits the semantic tuple used by the diff oracle:

- `verdict`
- `reason_code`
- `scope_set`

The driver is registered as the `verdict_matrix_rust_driver` integration test
on the parent `chio-conformance` package so CI can run the same local gate:

```bash
cargo test -p chio-conformance --test verdict_matrix_rust_driver --quiet
```

Unsupported scenarios must report `unsupported`. The active corpus requires
only `rust-kernel`, so any unsupported scenario in this driver is a test
failure.

## Kernel Boundary

Each scenario builds a real in-process kernel, registers a tool server, issues
the scenario capability through the kernel authority, optionally revokes that
capability through the kernel revocation store, and evaluates a
`ToolCallRequest`. Allow and deny receipts are signed by the kernel.

The scenario format is driver-neutral, so the Rust driver adapts a few labels
to native Rust inputs:

- `capability_scopes` labels map to `ToolGrant` entries for the scenario tool.
- Input redaction allow cases are recorded as signed receipt metadata because
  the current pre-execution `Guard` trait returns only allow or deny.
- Output redaction uses the kernel post-invocation hook pipeline.
- Replay cases use the kernel execution-nonce verification path. The
  trace-missing case maps the strict-mode missing-nonce gate to the matrix
  error tuple because `ToolCallResponse` does not carry an error verdict.

Those adapter steps are limited to translating neutral scenario inputs into
existing Rust kernel surfaces. They do not replace the kernel verdict path with
local scenario logic.
