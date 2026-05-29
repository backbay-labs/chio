# WASM Guard Runtime -- Long-Range Implementation Roadmap

> **This document is a long-range roadmap, not the v1 plan.**
> The scoped v1 implementation is defined in `05-V1-DECISION.md`.
> Items in this document that conflict with 05 (CLI tooling, guest SDKs,
> non-Rust SDKs, `chio.yaml` config field) are deferred to v2 or later.
> Read this document for architectural context and future direction;
> read 05 for what ships next.

## 1. Current State

The codebase already has a well-structured foundation for WASM guards:

| Crate | Status | Role |
|-------|--------|------|
| `chio-kernel` | Stable | Defines `Guard` trait, `GuardContext`, `Verdict` |
| `chio-guards` | Stable | 15+ built-in Rust guards (path, egress, PII, velocity, etc.) |
| `chio-wasm-guards` | Scaffold | ABI types, config, `WasmGuard` -> `Guard` adapter, wasmtime backend |
| `chio-config` | Stable | `wasm_guards` section in `chio.yaml`, `WasmGuardEntry` schema |

The `chio-wasm-guards` crate already contains:
- `WasmGuardAbi` trait abstracting the WASM backend
- `GuardRequest` / `GuardVerdict` types for the host-guest boundary
- `WasmGuardConfig` with fuel limits, priority, advisory mode
- `WasmGuard` that implements `chio_kernel::Guard` by delegating to a `WasmGuardAbi` backend
- `WasmGuardRuntime` that manages multiple loaded guards
- A `wasmtime-runtime` feature flag with a working `WasmtimeBackend`
- `MockWasmBackend` for testing
- `chio-config` already parses `wasm_guards` entries from `chio.yaml`

What is missing: a guest-side SDK, a CLI workflow, a guard manifest/packaging format,
host function imports, and integration wiring between `chio-config` and the kernel
startup path.

> **ABI decision:** This plan targets the **raw core-WASM ABI** already in
> the codebase (`evaluate(ptr, len) -> i32`, JSON over linear memory,
> `wasm32-unknown-unknown`). WIT/Component Model is deferred to v2.
> See `02-WASM-RUNTIME-LANDSCAPE.md` Section 3.5 for rationale.


## 2. Crate Architecture

### Decision: No new crates needed for the host side

The existing `chio-wasm-guards` crate is the correct home for all host-side WASM
runtime code. It already depends on `chio-kernel` and `chio-core`, implements the
`Guard` trait, and has the wasmtime backend behind a feature flag. Adding more
host-side crates would fragment responsibility.

### New crate: `chio-guard-sdk` (guest-side)

A new crate is needed for the guest side. WASM modules compiled from Rust need
a thin library that:

1. Deserializes the `GuardRequest` from linear memory
2. Provides a typed API for returning `Allow` / `Deny { reason }`
3. Handles the `#[no_std]`-friendly allocation dance
4. Exports the expected ABI entry point

This is analogous to how `chio-mcp-adapter` wraps external MCP servers -- except
here we are wrapping user-authored WASM code behind the `Guard` trait.

```
crates/
  chio-guard-sdk/         # NEW -- guest-side Rust SDK
    Cargo.toml
    src/
      lib.rs             # #[chio_guard] macro + typed API
      alloc.rs           # Guest-side allocator for shared memory
      request.rs         # GuardRequest deserialization (mirrors abi.rs)
      response.rs        # Verdict encoding into linear memory
```

For non-Rust languages (TypeScript, Python, Go), the guest SDK will be
language-specific packages that generate the same ABI exports. These live in
`sdks/guard/`:

```
sdks/guard/
  chio-guard-ts/          # AssemblyScript / ts2wasm guard SDK
  chio-guard-py/          # componentize-py or Extism PDK for Python
  chio-guard-go/          # TinyGo guard SDK
```


## 3. ABI Design

### 3.1 Exported Functions (guest must export)

The current ABI in `chio-wasm-guards/src/abi.rs` uses a minimal contract:

```text
// Required exports from the WASM module:

memory          -- WebAssembly linear memory (exported)
evaluate(request_ptr: i32, request_len: i32) -> i32
                -- 0 = Allow, 1 = Deny, negative = error

// Optional exports:

chio_alloc(size: i32) -> i32
                -- Guest-side allocator. If present, the host calls this
                   to allocate space for the request JSON instead of
                   writing at offset 0. This avoids clobbering the
                   guest's own heap.

chio_free(ptr: i32, size: i32)
                -- Frees memory previously allocated via chio_alloc.
```

**Decision point: keep the current offset-0 protocol or require `chio_alloc`?**

Recommendation: support both. If the guest exports `chio_alloc`, use it. Otherwise
fall back to writing at offset 0 (the current behavior). This keeps trivial C/Zig
guards simple while giving Rust/Go/AS guards proper memory safety.

### 3.2 Deny Reason Protocol

The current implementation reads a NUL-terminated string from offset 64 KiB in
guest memory. This works but is fragile. A better protocol:

```text
// After evaluate() returns 1 (Deny), the host checks for an exported function:

chio_deny_reason(ptr_out: i32, len_out: i32) -> i32
                -- Guest writes (ptr, len) of a UTF-8 reason string into
                   the two i32 slots. Returns 0 on success, -1 if no
                   reason is available.
```

If `chio_deny_reason` is not exported, fall back to the offset-64K convention
for backward compatibility.

### 3.3 Host Functions (imported by the guest)

The WASM linker should provide these host imports under the `chio` namespace:

```text
chio.log(level: i32, msg_ptr: i32, msg_len: i32)
                -- Emit a tracing log line at the given level.
                   0=trace, 1=debug, 2=info, 3=warn, 4=error.

chio.get_config(key_ptr: i32, key_len: i32, val_out_ptr: i32, val_out_len: i32) -> i32
                -- Read a guard-specific config value. Returns the
                   actual length, or -1 if the key does not exist.
                   The config values come from the guard manifest's
                   `config` block.

chio.get_time_unix_secs() -> i64
                -- Current wall-clock time. Deterministic in replay mode.
```

These are registered on the `Linker<T>` before instantiation. The current
`WasmtimeBackend` creates a bare `Linker<()>` -- it needs a `WasmHostState`
struct instead:

```rust
struct WasmHostState {
    /// Guard-specific configuration key-value pairs.
    config: HashMap<String, String>,
    /// Captured log lines (drained after each invocation).
    logs: Vec<(tracing::Level, String)>,
}
```


### 3.4 Data Serialization

**Decision: JSON across the boundary.**

Rationale:
- `GuardRequest` is already serialized as JSON in the current implementation
- JSON is the lingua franca for every target language
- MessagePack would save ~30% on the wire but adds a dependency in every
  guest language SDK and is not human-debuggable
- For guards, the request payload is typically < 4 KiB -- serialization cost
  is negligible compared to WASM instantiation overhead

Keep JSON. If profiling shows it matters later, add a `content-type` byte at
offset 0 of the serialized buffer (0x00 = JSON, 0x01 = MessagePack) and handle
both in the host.


## 4. Integration Points in `chio-kernel`

### 4.1 Where `WasmGuard` Implements `Guard`

Already done. `chio-wasm-guards/src/runtime.rs` contains:

```rust
impl Guard for WasmGuard {
    fn name(&self) -> &str { &self.name }
    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> {
        // Builds GuardRequest from GuardContext, calls backend.evaluate()
    }
}
```

This is correct. The `WasmGuard` delegates to whatever `WasmGuardAbi`
backend is loaded (wasmtime, mock, or a future wasmer/wasm3 backend).

### 4.2 WASM Runtime Lifecycle

**Decision: one `Engine` shared, one `Store` per invocation.**

The current `WasmtimeBackend::evaluate` already creates a fresh `Store<()>` per
call, which is the right pattern -- it gives each invocation its own fuel budget
and prevents state leakage between invocations. The `Engine` and compiled
`Module` are reused (module compilation is expensive).

For a pooled model (if guard invocation latency matters at scale), consider
pre-instantiating a pool of `Instance` objects. But this is premature --
wasmtime module instantiation is ~50us, well within the guard evaluation budget.

### 4.3 Per-Guard vs Shared Runtime

**Decision: per-guard backend instances, shared engine.**

Each `WasmGuard` holds its own `Mutex<Box<dyn WasmGuardAbi>>`. This means each
guard has its own compiled module. The wasmtime `Engine` (which holds the
compiler/JIT) can be shared across guards via an `Chio<Engine>`:

```rust
pub struct WasmtimeBackend {
    engine: Chio<Engine>,       // Shared across all guards
    module: Option<Module>,    // Per-guard compiled module
    fuel_limit: u64,
}
```

The current code creates a new `Engine` per backend. This should be changed to
accept an `Chio<Engine>` in the constructor.

### 4.4 Startup Wiring: `chio.yaml` -> Kernel

The missing integration is the bridge between `chio-config`'s `wasm_guards`
entries and the kernel's `add_guard` call. This belongs in the CLI / proxy
startup code (likely `chio-acp-proxy` or `chio-cli`), not in the kernel itself:

```rust
// In the startup path (chio-cli or chio-acp-proxy):
use chio_wasm_guards::{WasmGuardConfig, WasmGuardRuntime};
use chio_wasm_guards::runtime::wasmtime_backend::WasmtimeBackend;

fn load_wasm_guards(
    entries: &[chio_config::WasmGuardEntry],
    kernel: &mut ChioKernel,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut runtime = WasmGuardRuntime::new();

    for entry in entries {
        let config = WasmGuardConfig {
            name: entry.name.clone(),
            path: entry.path.clone(),
            fuel_limit: entry.fuel_limit,
            priority: entry.priority,
            advisory: entry.advisory,
        };
        runtime.load_guard(&config, |bytes, fuel| {
            let mut backend = WasmtimeBackend::new()?;
            backend.load_module(bytes, fuel)?;
            Ok(Box::new(backend))
        })?;
    }

    // NOTE: WasmGuardRuntime does NOT sort by priority despite its
    // doc-comment claim. The caller must sort if priority ordering
    // is desired. Sort entries before loading, or sort the output
    // of into_guards().
    for guard in runtime.into_guards() {
        kernel.add_guard(guard);
    }
    Ok(())
}
```

### 4.5 Guard Registration Options

The `WasmGuardConfig` currently supports a filesystem `path`. Future options:

| Source | Config field | Notes |
|--------|-------------|-------|
| Local file | `path: /etc/chio/guards/pii.wasm` | Current |
| HTTP URL | `url: https://registry.chio.world/guards/pii/1.0.0` | Download + cache |
| Inline base64 | `wasm_base64: AGFzbQEA...` | Embedded in config (small guards only) |
| OCI registry | `oci: ghcr.io/org/pii-guard:1.0` | Pull from container registry |

Recommendation: implement `path` first (already works), then `url` with a
content-addressed cache directory. OCI support can come later via the
`oci-distribution` crate.


## 5. Guest-Side SDK Design (Rust)

### 5.1 Developer Experience

A Rust guard author should write:

```rust
// my_guard/src/lib.rs
use chio_guard_sdk::prelude::*;

#[chio_guard]
fn evaluate(req: GuardRequest) -> GuardVerdict {
    if req.tool_name == "delete_file" && req.arguments["path"] == "/etc/passwd" {
        GuardVerdict::deny("cannot delete /etc/passwd")
    } else {
        GuardVerdict::allow()
    }
}
```

Compile with:

```bash
cargo build --target wasm32-unknown-unknown --release
```

### 5.2 SDK Internals

The `#[chio_guard]` proc macro generates:

```rust
#[no_mangle]
pub extern "C" fn evaluate(ptr: i32, len: i32) -> i32 {
    // 1. Read JSON bytes from linear memory at (ptr, len)
    // 2. Deserialize into GuardRequest
    // 3. Call the user's function
    // 4. If Deny, write reason string at the deny-reason offset
    // 5. Return 0 (Allow) or 1 (Deny)
}

#[no_mangle]
pub extern "C" fn chio_alloc(size: i32) -> i32 {
    // Allocate `size` bytes and return the pointer
}

#[no_mangle]
pub extern "C" fn chio_free(ptr: i32, size: i32) {
    // Free the allocation
}
```

The SDK crate would have:
- `chio-guard-sdk` (library) -- types + glue
- `chio-guard-sdk-macros` (proc-macro crate) -- the `#[chio_guard]` attribute

### 5.3 Non-Rust Guest SDKs

**TypeScript (AssemblyScript):**

```typescript
// guard.ts
import { GuardRequest, allow, deny } from "@chio-protocol/guard-sdk";

export function evaluate(ptr: i32, len: i32): i32 {
  const req = GuardRequest.parse(ptr, len);
  if (req.toolName === "delete_file") {
    return deny("blocked dangerous tool");
  }
  return allow();
}
```

**Python (via componentize-py or Extism PDK):**

```python
# guard.py
from chio_guard_sdk import guard, allow, deny

@guard
def evaluate(req):
    if req.tool_name == "execute_shell" and "rm -rf" in req.arguments.get("command", ""):
        return deny("blocked dangerous command")
    return allow()
```

**Go (via TinyGo):**

```go
package main

import "github.com/backbay-labs/chio/sdks/guard/chio-guard-go"

//export evaluate
func evaluate(ptr, len int32) int32 {
    req := chio.ParseRequest(ptr, len)
    if req.ToolName == "delete_file" {
        return chio.Deny("blocked")
    }
    return chio.Allow()
}
```

Each language SDK is a thin wrapper that handles memory management for that
language's WASM compilation toolchain.


## 6. Guard Manifest / Packaging

### 6.1 Guard Manifest Format

Each WASM guard should ship with a manifest (separate from the tool server
manifest in `chio-manifest`). This is a YAML/JSON file:

```yaml
# guard-manifest.yaml
schema: "chio.guard.v1"
name: "pii-redaction-guard"
version: "1.2.0"
description: "Detects and blocks PII in tool arguments"
author: "ACME Corp"
license: "MIT"

# The WASM binary (relative to this manifest)
wasm: "./pii_guard.wasm"

# Target ABI version
abi_version: 1

# Expected fuel consumption (informational)
typical_fuel: 500000

# Configuration schema (JSON Schema)
config_schema:
  type: object
  properties:
    patterns_file:
      type: string
      description: "Path to custom PII patterns"
    sensitivity:
      type: string
      enum: ["low", "medium", "high"]
      default: "medium"

# SHA-256 hash of the .wasm binary for integrity verification
wasm_sha256: "a1b2c3d4..."
```

### 6.2 Packaging Structure

A distributable guard is a directory or tarball:

```
pii-guard-1.2.0/
  guard-manifest.yaml
  pii_guard.wasm
  README.md  (optional)
```

Or a single `.arcguard` file (gzipped tar):

```bash
chio guard pack ./pii-guard/    # produces pii-guard-1.2.0.arcguard
chio guard install pii-guard-1.2.0.arcguard
```

### 6.3 Manifest Verification

On load, the host:
1. Reads `guard-manifest.yaml`
2. Verifies `wasm_sha256` matches the actual `.wasm` file
3. Validates `abi_version` is supported
4. Parses `config_schema` and validates config values from the manifest's
   `config` block (v1). In v1.1, `chio.yaml` `wasm_guards[].config` values
   override manifest defaults.
5. Loads the `.wasm` module via the `WasmGuardAbi` backend

The manifest types belong in `chio-wasm-guards` since they are host-side
concerns (the guest does not read its own manifest).


## 7. CLI Integration

### 7.1 New Subcommands for `chio` CLI

```
chio guard new <name>           # Scaffold a new guard project
chio guard build                # Compile to wasm32-unknown-unknown
chio guard test                 # Run the guard against test fixtures
chio guard pack                 # Package into .arcguard
chio guard install <path|url>   # Install into /etc/chio/guards/
chio guard list                 # List installed guards
chio guard inspect <path>       # Print manifest + ABI info
chio guard bench <path>         # Measure fuel consumption on sample inputs
```

These subcommands live in `chio-cli/src/cli/guard.rs` (new module).

### 7.2 Test Fixtures

`chio guard test` loads the compiled `.wasm` and runs it against fixture files:

```yaml
# tests/block_passwd.yaml
description: "Should deny access to /etc/passwd"
request:
  tool_name: read_file
  server_id: fs-server
  agent_id: agent-test
  arguments:
    path: /etc/passwd
  scopes:
    - "fs-server:read_file"
expected: deny
expected_reason_contains: "passwd"
```


## 8. Remaining Work in `chio-wasm-guards`

### 8.1 WasmtimeBackend Improvements

The current wasmtime backend works but needs:

1. **Shared `Chio<Engine>`** -- avoid creating one engine per guard
2. **`chio_alloc` support** -- check for the export, use it if present
3. **Host function registration** -- `chio.log`, `chio.get_config`, `chio.get_time_unix_secs`
4. **`WasmHostState` instead of `()`** -- carry config + log buffer in the Store
5. **`chio_deny_reason` support** -- check for the export as an alternative to offset-64K

### 8.2 Integration with `chio-config`

Wire up the `wasm_guards` config entries to actual guard loading in the
startup path. This involves more than a single call -- see
`05-V1-DECISION.md` Sections 4-5 for the full v1 contract:

1. Sort `WasmGuardEntry` list by priority before loading (runtime does
   not sort).
2. For each entry, locate the adjacent `guard-manifest.yaml` and load
   config from the manifest (v1 uses manifest-only config, not `chio.yaml`).
3. Register HushSpec-compiled guards first (via `compile_policy()`), then
   WASM guards, then the advisory pipeline.

### 8.3 Fuel Reporting in Receipts

When a WASM guard runs, the fuel consumed should be recorded in the receipt's
metadata so operators can monitor guard cost:

```rust
// After evaluation:
let fuel_remaining = store.get_fuel().unwrap_or(0);
let fuel_consumed = self.fuel_limit.saturating_sub(fuel_remaining);
// Attach to receipt metadata
```

### 8.4 Security Hardening

- **WASI disabled** -- do not link WASI imports. Guards must not have filesystem
  or network access. The only imports are the `chio.*` host functions.
- **Memory limits** -- cap guest linear memory growth (e.g., 16 MiB max).
- **Epoch interruption** -- as a secondary timeout mechanism alongside fuel metering,
  configure wasmtime epoch interruption to hard-kill guards that somehow evade
  fuel accounting.
- **Module validation** -- reject modules that import anything outside the `chio`
  namespace.


## 9. Phased Implementation Plan

> **Phase 1 = v1.** See `05-V1-DECISION.md` for the scoped, authoritative
> v1 plan. Phases 2-4 are deferred to v2+.

### Phase 1: Host-side completion -- v1 (see 05-V1-DECISION.md)

- Add `Chio<Engine>` sharing across guards
- Add `WasmHostState` with config + log buffer
- Register `chio.log`, `chio.get_config`, `chio.get_time_unix_secs` host functions
- Add `chio_alloc` / `chio_deny_reason` protocol support
- Add guard manifest parsing + SHA-256 verification
- Wire `chio-config` `wasm_guards` entries into kernel startup
- Add memory limit enforcement
- Add module import validation (reject non-`chio` imports)
- Enrich `GuardRequest` with host-extracted action context
- Fix priority sorting (sort externally before loading)
- Benchmark spike (load time, instantiation, latency, fuel, memory)

### Phase 2: Guest-side Rust SDK -- v2

- Create `chio-guard-sdk` crate (library)
- Create `chio-guard-sdk-macros` crate (proc-macro for `#[chio_guard]`)
- Implement guest-side allocator
- Implement `GuardRequest` deserialization + `GuardVerdict` encoding
- Add host function bindings (`chio::log`, `chio::get_config`)
- Create example guard using the SDK
- Add integration test: compile example guard -> load in WasmtimeBackend -> evaluate

### Phase 3: CLI tooling -- v2

- Add `chio guard new` scaffolding
- Add `chio guard build` (wraps `cargo build --target wasm32-unknown-unknown`)
- Add `chio guard test` with fixture format
- Add `chio guard inspect` and `chio guard bench`
- Add `chio guard pack` / `chio guard install`

### Phase 4: Non-Rust guest SDKs + WIT migration -- v2+

- Define WIT interface, migrate from raw ABI
- TypeScript/AssemblyScript guard SDK (`sdks/guard/chio-guard-ts`)
- Python guard SDK (`sdks/guard/chio-guard-py`)
- Go guard SDK (TinyGo, `sdks/guard/chio-guard-go`)
- Cross-language conformance test suite


## 10. Key Decision Summary

> See `05-V1-DECISION.md` for the authoritative v1 decisions. This table
> covers both v1 and long-range choices.

| Decision | Choice | Version | Rationale |
|----------|--------|---------|-----------|
| ABI contract | Raw core-WASM (`evaluate(ptr, len) -> i32`) | v1 | Already implemented, validate before migrating |
| ABI contract | WIT / Component Model | v2 | Type-safe bindings, multi-language SDK generation |
| Host-side crate | Existing `chio-wasm-guards` | v1 | Already structured correctly |
| Guest-side crate | New `chio-guard-sdk` | v2 | Deferred until ABI is stable |
| WASM runtime | wasmtime (behind feature flag) | v1 | Already integrated, mature, fuel metering |
| Serialization format | JSON | v1 | Already used, universal, debuggable |
| Memory protocol | `chio_alloc` with offset-0 fallback | v1 | Backward-compatible, safe for GC languages |
| Instance lifecycle | Fresh `Store` per invocation, shared `Engine` | v1 | Isolation without compilation cost |
| WASI | Disabled | v1 | Guards must not have filesystem/network access |
| Config source | Guard manifest file | v1 | `chio.yaml` schema needs change for `config` field |
| Config source | `chio.yaml` `wasm_guards[].config` | v1.1 | Requires `WasmGuardEntry` schema change |
| Guard packaging | `guard-manifest.yaml` + `.wasm` binary | v1 | Inspectable, integrity-verified |
| CLI integration | `chio guard` subcommand family | v2 | Follows existing `chio` CLI patterns |
| Non-Rust SDKs | TypeScript, Python, Go | v2+ | After WIT migration |


## 11. File Reference

Existing files relevant to this work:

- `crates/chio-wasm-guards/src/lib.rs` -- crate root, re-exports
- `crates/chio-wasm-guards/src/abi.rs` -- `GuardRequest`, `GuardVerdict`, `WasmGuardAbi` trait
- `crates/chio-wasm-guards/src/config.rs` -- `WasmGuardConfig` with fuel/priority/advisory
- `crates/chio-wasm-guards/src/error.rs` -- `WasmGuardError` enum
- `crates/chio-wasm-guards/src/runtime.rs` -- `WasmGuard`, `WasmGuardRuntime`, `WasmtimeBackend`, `MockWasmBackend`
- `crates/chio-kernel/src/kernel/mod.rs` (line 451) -- `Guard` trait definition
- `crates/chio-kernel/src/kernel/mod.rs` (line 463) -- `GuardContext` struct
- `crates/chio-kernel/src/runtime.rs` (line 17) -- `Verdict` enum
- `crates/chio-guards/src/pipeline.rs` -- `GuardPipeline` (pattern for composing guards)
- `crates/chio-config/src/schema.rs` (line 41) -- `wasm_guards: Vec<WasmGuardEntry>`
- `crates/chio-mcp-adapter/src/lib.rs` -- pattern for wrapping external systems behind Chio traits
