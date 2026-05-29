# Chio C++ SDK Completion Roadmap

This file is the coordinator-owned lock table and evidence plan for the
long-horizon C++ SDK completion effort.

## Baseline

- Baseline commit: `99d1f884a` (`feat: bootstrap chio c++ sdk`)
- Starting gates that were green locally:
  - `./scripts/check-chio-cpp.sh`
  - `./scripts/check-chio-cpp-release.sh`
  - `cargo clippy -p chio-bindings-ffi -- -D warnings`
  - `cargo clippy -p chio-conformance -- -D warnings`
  - C++ live conformance MCP core and tasks through `--peer cpp`

## File Ownership

| Owner | Write scope |
| --- | --- |
| Coordinator | `Cargo.toml`, `.github/**`, `scripts/**`, SDK matrix, conformance runner, main `sdks/cpp/chio-cpp/**`, this file |
| Worker A | `crates/chio-bindings-ffi/**`, optional `tests/abi/**` |
| Worker H | `sdks/guard/chio-guard-cpp/**` |
| Worker I | `sdks/cpp/chio-cpp-kernel/**`, `crates/chio-cpp-kernel-ffi/**` |

Agents must not edit outside their write scope. Shared-file changes are
coordinator-only.

## Required Completion Gates

- ABI: generated header freshness, exported symbol snapshot, C ABI smoke tests,
  Rust FFI unit tests, and FFI clippy.
- SDK: C++ unit tests, CMake build with curl on/off, install plus
  `find_package`, release script, and typed/raw API agreement tests.
- Conformance: live C++ MCP core, tasks, auth, notifications, and nested
  callbacks before matrix entries become green.
- Packaging: Linux, macOS, and Windows CMake consumer smoke; Conan
  `test_package`; vcpkg build; sanitizer job.
- Kernel: independent `chio-cpp-kernel` package build and tests; optional
  Rust-backed `chio-cpp-kernel-ffi` C ABI check; no dependency from the main
  client SDK to the kernel package.

## Status Tracking

- Stage 0: complete. Baseline checkpoint and ownership table are recorded here.
- Stage 1: complete. The FFI ABI exposes version/build-info calls, generated
  header freshness, symbol snapshots, and C smoke coverage.
- Stage 2: complete. The SDK has private JSON parsing, richer errors,
  typed models, typed responses, and `Result<void>` helpers.
- Stage 3: complete. `ClientBuilder`, curl transport hardening, retry, timeout,
  cancellation, tracing, and test transports are implemented.
- Stage 4: complete. C++ streaming requests and notification callbacks pass live
  notifications evidence.
- Stage 5: complete. OAuth discovery, PKCE, token exchange, token providers, and
  live auth evidence are implemented.
- Stage 6: complete. Receipt/capability verifiers, DPoP builder abstractions,
  `ToolClient`, `SessionPool`, and HTTP substrate middleware are present.
- Stage 7: complete locally. CMake install/export, Conan/vcpkg metadata, release
  checks, sanitizer/leak CI lanes, and OS package smoke workflow are wired.
- Stage 8: complete. `chio-guard-cpp` has a native package, WIT/WASI scripts,
  path guard example, and native smoke script.
- Stage 9: complete. `chio-cpp-kernel` is a separate package with independent
  CMake build, tests, install/export, example, and an optional Rust-backed
  `chio-cpp-kernel-ffi` path over `chio-kernel-core`.

## Current Evidence

- `./scripts/check-chio-cpp.sh`
- `cargo test -p chio-conformance --test mcp_core_cpp_live -- --nocapture`
- `cargo test -p chio-conformance --test tasks_cpp_live -- --nocapture`
- `cargo test -p chio-conformance --test auth_cpp_live -- --nocapture`
- `cargo test -p chio-conformance --test notifications_cpp_live -- --nocapture`
- `cargo test -p chio-conformance --test nested_callbacks_cpp_live -- --nocapture`
- `./sdks/cpp/chio-cpp-kernel/scripts/check-with-ffi.sh`
