# chio-kernel benchmark runner contract

The `dispatch_allow` benchmark measures a real allow verdict through
`ChioKernel::evaluate_tool_call`, capability validation, scope matching, guard
pipeline dispatch, in-process tool-server invocation, and allow receipt
construction. It must not use a synthetic counter or the previous
`black_box(0_u64)` probe.

Reference runner:

- 4-core Linux x86_64 host.
- Rust toolchain pinned by the workspace.
- Warm cargo cache and no network access during the timed benchmark.
- Default `chio-kernel` features, including `legacy-sync` and `delegation_v2`.
- In-process benchmark tool server only. External network, filesystem, and
  mTLS transport costs are excluded by design.

Contract for future dispatch benches:

- Fixture setup happens outside the timed loop.
- The timed loop performs exactly one kernel dispatch and checks the returned
  verdict.
- Errors fail closed by panicking the benchmark process.
- New dispatch fixtures should live beside the bench that consumes them and
  should document any runner assumptions here.
