# TRJ4-046 WASM guard resource exhaustion

- Test: `crates/chio-conformance/tests/threats/wasm_guard_resource_exhaustion.rs`
- Coverage: pins runnable WASM guard escape fixtures.
- Fixtures pinned: fuel exhaustion, oversized memory, deep recursion, and table growth.
- Negative behavior: each pinned fixture retains its fail-closed trap assertion name.
