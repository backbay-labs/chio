# WASM Runtime Landscape for Chio Guard Execution

Research document covering WASM runtime options, ABI patterns, the Component
Model, guest SDK toolchains, and security considerations for running
user-supplied guard/policy functions inside the Chio kernel.


---

## Table of Contents

1. [Rust WASM Runtimes](#1-rust-wasm-runtimes)
2. [proxy-wasm as Analogue](#2-proxy-wasm-as-analogue)
3. [Component Model and WIT](#3-component-model-and-wit)
4. [Guest SDK Patterns](#4-guest-sdk-patterns)
5. [Security Considerations](#5-security-considerations)
6. [Recommendations for Chio](#6-recommendations-for-chio)

---

## 1. Rust WASM Runtimes

### 1.1 Wasmtime

**Maintainer:** Bytecode Alliance (Mozilla, Fastly, Intel, Microsoft)
**License:** Apache-2.0 with LLVM-exception
**Current version:** 29.x (as used in `chio-wasm-guards`)

#### Sandboxing and Isolation

Wasmtime provides strong sandboxing guarantees grounded in the WebAssembly
specification itself. Each module instance has its own isolated linear memory
with no shared address space between instances. The runtime enforces
capability-based security -- a module has zero ambient authority and can only
access resources explicitly provided by the host through imports. Wasmtime
undergoes regular third-party security audits and has a published security
policy with a CVE response process.

#### Performance

- **JIT compilation via Cranelift:** Near-native execution speed for
  compute-bound workloads. Cranelift compiles faster than LLVM while
  producing code within 2-10% of LLVM-quality.
- **AOT compilation:** Modules can be pre-compiled to native code and cached
  on disk, reducing cold-start to module deserialization time (~3ms on modern
  hardware for moderately sized modules).
- **Winch baseline compiler:** Alternative to Cranelift that compiles faster
  with slightly worse code quality. Useful when compilation latency matters
  more than peak throughput.
- **Cold start:** ~3ms typical on x86_64, suitable for per-request guard
  evaluation if modules are pre-compiled.

#### CPU Metering: Fuel vs. Epochs

Wasmtime offers two complementary mechanisms for bounding CPU consumption:

**Fuel metering** (`Config::consume_fuel`):
- Deterministic instruction-level accounting. Most instructions consume 1
  unit of fuel; `nop`, `drop`, `block`, `loop` consume 0.
- The host sets a fuel budget via `Store::set_fuel()` before each invocation.
  When fuel reaches zero, execution traps.
- Overhead: 15-30% slowdown in benchmarks due to maintaining a per-instruction
  counter. SpiderMonkey-on-WASM benchmarks show up to 2x slowdown vs.
  unmetered execution.
- Deterministic: the same inputs with the same fuel budget will always produce
  the same outcome (allow/deny/trap). This property is valuable for
  reproducible policy evaluation.

**Epoch interruption** (`Config::epoch_interruption`):
- Coarse-grained wall-clock interruption. The host increments a global epoch
  counter (e.g., from a background timer thread). At function prologues and
  loop backedges, the guest checks whether the current epoch exceeds its
  deadline.
- Overhead: ~10% slowdown (checks are a single load + compare-and-branch).
- Non-deterministic: interruption happens at the next check point after the
  epoch advances, not at a precise instruction count.
- Better suited to wall-clock timeouts than budgeting.

**Recommendation for Chio:** Use fuel metering for guard evaluation. Guards are
short-lived policy checks, not long-running computations, so the overhead is
acceptable and determinism is valuable for audit/debugging. Keep epoch
interruption available as a hard wall-clock backstop (e.g., 100ms timeout)
for defense in depth.

#### Memory Limits

Wasmtime's `ResourceLimiter` trait provides fine-grained control:

```rust
pub trait ResourceLimiter {
    fn memory_growing(
        &mut self,
        current: usize,   // current memory in bytes
        desired: usize,    // requested memory in bytes
        maximum: Option<usize>,
    ) -> Result<bool, Error>;

    fn table_growing(
        &mut self,
        current: u32,
        desired: u32,
        maximum: Option<u32>,
    ) -> Result<bool, Error>;
}
```

The host attaches a `ResourceLimiter` to a `Store` via `Store::limiter()`.
Returning `Ok(false)` from `memory_growing` denies the allocation, causing
the guest to trap. This allows capping per-guard memory at, for example,
1 MiB or 4 MiB -- far more than a policy function should need.

An async variant (`ResourceLimiterAsync`) exists for use with
`Config::async_support`.

#### Async Support

Wasmtime has first-class async support:

- `Config::async_support(true)` enables async execution.
- Host functions can be defined as `async fn`, allowing the guest to call
  host functions that internally await (e.g., for external policy lookups).
- Guest execution is represented as a Rust `Future`, compatible with Tokio.
- The `wasmtime-wasi` crate provides an "ambient Tokio runtime" -- WASI
  host functions are implemented as async Rust on top of Tokio.
- `tokio::time::timeout` can be applied to the entire guest execution Future
  for wall-clock cancellation.

This integrates cleanly with the Chio kernel, which is async Rust.

#### WASI Support and Selective Capabilities

Wasmtime provides the most complete WASI implementation:

- **WASI Preview 1 (wasip1):** Stable, widely supported.
- **WASI Preview 2 (wasip2):** Stable since 2025, production-ready. Adds
  sockets, HTTP, and a proper component-model interface.

WASI follows a capability-based model. The host must explicitly grant each
capability:

| Capability | How to Grant | Can Restrict |
|------------|-------------|--------------|
| Filesystem | `WasiCtxBuilder::preopened_dir()` | Specific paths only |
| Stdout/Stderr | `WasiCtxBuilder::inherit_stdout()` | Can redirect to buffer |
| Environment vars | `WasiCtxBuilder::env()` | Explicit allowlist |
| Clock | `WasiCtxBuilder::wall_clock()` | Can provide fake clock |
| Random | `WasiCtxBuilder::secure_random()` | Can provide deterministic source |
| Network | `WasiCtxBuilder::socket_addr_check()` | Allowlist of addresses |
| HTTP | `wasmtime_wasi_http` | Per-request policy |

**For Chio guards:** Provide ZERO WASI capabilities by default. Guard functions
are pure computations: they receive a JSON request and return a verdict. They
should not need filesystem, network, or even clock access. If a guard needs
external data, the host should provide it through explicit ABI imports, not
WASI ambient capabilities.

#### Dependency Tree

Wasmtime has a substantial dependency tree due to Cranelift. With default
features, expect ~200+ transitive crate dependencies. However, Wasmtime offers
extensive feature flags to reduce this:

- `--no-default-features` strips out component-model, cache, profiling,
  parallel-compilation, and more.
- Minimal features for Chio: `runtime`, `cranelift` (or `winch` for smaller
  builds), `consume_fuel`.
- Pre-compiling modules offline removes the need for Cranelift in production
  builds entirely (use only the `runtime` feature).

Compile time is non-trivial (~60-90s clean build on modern hardware) but
this is a one-time cost amortized across incremental builds.

#### Maturity

Wasmtime is the reference implementation for WebAssembly standards. It is
used in production by Fastly (Compute@Edge), Fermyon (Spin), Shopify, and
others. The Bytecode Alliance provides long-term governance. The project
has regular releases, comprehensive CI, fuzzing, and security audits.

---

### 1.2 Wasmer

**Maintainer:** Wasmer Inc.
**License:** MIT
**Current version:** 5.x

#### Key Characteristics

- Multiple compiler backends: Cranelift, LLVM, and Singlepass (a fast
  single-pass compiler).
- Singlepass compiler enables very fast compilation (~1ms for small modules)
  with moderate execution speed -- potentially useful if guards are loaded
  dynamically per-request and cannot be pre-compiled.
- Module deserialization is up to 50% faster than Wasmer 4.x thanks to rkyv
  zero-copy deserialization.
- WASIX: Wasmer's non-standard extension to WASI Preview 1 adding fork(),
  extended networking, etc. This is a pragmatic but non-standard approach.
- WASI Preview 2 support added in 3.x/4.x but lags behind Wasmtime.
- Component Model support is in progress but not yet at parity with Wasmtime.

#### Metering

Wasmer supports instruction metering through a middleware system. The
`wasmer-middlewares` crate provides a `Metering` middleware that injects
fuel checks at compilation time, similar to Wasmtime's fuel metering but
implemented as a compiler transform.

#### Concerns for Chio

- **Standards lag:** Wasmer has historically prioritized usability over
  standards compliance. WASIX is a fork of WASI that may cause ecosystem
  fragmentation.
- **Component Model:** Not yet at Wasmtime's level of support, which matters
  if Chio adopts WIT-based guard interfaces.
- **Governance:** Single-company project vs. Wasmtime's multi-stakeholder
  Bytecode Alliance.
- **Async:** Wasmer has async support but it is less mature than Wasmtime's
  Tokio integration.

---

### 1.3 wasm3 / wasm3-rs

**Maintainer:** Volodymyr Shymanskyy (minimal maintenance)
**License:** MIT
**Type:** Pure interpreter (no JIT/AOT)

#### Key Characteristics

- Extremely fast cold start (~microseconds) because there is no compilation
  step.
- Very small footprint (~64 KiB RAM overhead).
- Execution speed is 10-100x slower than JIT runtimes due to interpretation.
- Written in C; `wasm3-rs` provides Rust bindings.
- **Maintenance concern:** The project is in minimal maintenance mode. The
  primary maintainer's house was destroyed in the Ukraine invasion and
  development of new features has stopped.
- No WASI Preview 2 support, no Component Model support.
- No fuel metering built in (would need custom implementation).

#### Assessment for Chio

wasm3 is not recommended for Chio. While the fast cold start is attractive,
the lack of fuel metering, stalled maintenance, missing WASI P2/Component
Model support, and the fact that guards need predictable execution budgets
(not raw speed) make it unsuitable. The 10-100x execution overhead is also a
concern for latency-sensitive guard evaluation on the hot path.

---

### 1.4 Comparison Matrix

| Feature | Wasmtime | Wasmer | wasm3 |
|---------|----------|--------|-------|
| Execution model | JIT (Cranelift) / AOT | JIT (Cranelift/LLVM/Singlepass) / AOT | Interpreter |
| Cold start | ~3ms (AOT: <1ms) | ~2ms (Singlepass: <1ms) | ~0.01ms |
| Execution speed | Near-native | Near-native | 10-100x slower |
| Fuel metering | Native | Via middleware | None |
| Epoch interruption | Native | No | No |
| Memory limits | ResourceLimiter trait | Via middleware | Manual |
| Async host functions | First-class (Tokio) | Partial | No |
| WASI Preview 2 | Production-ready | Partial | No |
| Component Model | Production-ready | In progress | No |
| WIT/bindgen | Full support | Partial | No |
| Governance | Bytecode Alliance | Wasmer Inc. | Single maintainer |
| Maintenance | Active, regular releases | Active | Minimal |
| Security audits | Regular third-party | Occasional | None |
| Dependency count | ~200+ (reducible) | ~150+ | ~20 |

---

## 2. proxy-wasm as Analogue

Envoy's proxy-wasm ABI is the closest existing analogue to what Chio needs
for WASM guard execution. It defines how a host (proxy) exposes context to
guest (WASM filter) modules.

### 2.1 Architecture

```
+------------------+       +-------------------+
|  Host (Envoy)    |       |  Guest (WASM)     |
|                  |       |                   |
|  +-----------+   | ABI   |  +-----------+    |
|  | Root Ctx  |<--------->|  | Root Ctx  |    |
|  +-----------+   |       |  +-----------+    |
|  | Stream Ctx|<--------->|  | HTTP Ctx  |    |
|  +-----------+   |       |  +-----------+    |
+------------------+       +-------------------+
```

### 2.2 Context Model

proxy-wasm uses a two-tier context system:

- **Root Context (ID 0):** Created at filter configuration time. Handles
  plugin lifecycle, configuration, and timer callbacks. One per filter
  instance.
- **Per-Stream Context:** Created for each HTTP request/TCP connection.
  Handles request/response headers, body, and trailers. Receives a unique
  context ID.

All callbacks include a context identifier as the first parameter to
distinguish between contexts.

**Lesson for Chio:** The root context / per-invocation context split maps
cleanly to Chio's model. A guard module could have a root context for
initialization (loading config, compiling regexes, etc.) and a per-request
context for each `evaluate()` call.

### 2.3 ABI Contract

The proxy-wasm ABI v0.2.1 defines two sets of functions:

**Guest exports (callbacks the host invokes):**

| Function | Purpose |
|----------|---------|
| `proxy_on_context_create` | New context (root or per-stream) |
| `proxy_on_new_connection` | New TCP connection |
| `proxy_on_request_headers` | HTTP request headers received |
| `proxy_on_request_body` | HTTP request body chunk |
| `proxy_on_response_headers` | HTTP response headers received |
| `proxy_on_response_body` | HTTP response body chunk |
| `proxy_on_log` | Stream completed, emit logs |
| `proxy_on_done` | Context is being destroyed |
| `proxy_on_tick` | Timer fired (root context only) |
| `proxy_on_configure` | Configuration data available |

**Host imports (functions the guest calls):**

| Function | Purpose |
|----------|---------|
| `proxy_get_buffer_bytes` | Read host buffer (headers, body, etc.) |
| `proxy_set_buffer_bytes` | Mutate host buffer |
| `proxy_get_header_map_pairs` | Read all headers as pairs |
| `proxy_get_header_map_value` | Read single header value |
| `proxy_add_header_map_value` | Add a header |
| `proxy_replace_header_map_value` | Replace a header |
| `proxy_get_property` | Read arbitrary host property |
| `proxy_set_property` | Set a host property |
| `proxy_send_local_response` | Send response without proxying |
| `proxy_log` | Emit a log message |
| `proxy_get_current_time_nanoseconds` | Read clock |
| `proxy_set_tick_period_milliseconds` | Configure timer |

All host functions return `proxy_status_t` indicating success/failure.

### 2.4 Memory Sharing

proxy-wasm uses a **copy-based** memory model, not shared memory:

1. Host owns its memory (headers, body buffers, properties).
2. Guest owns its linear memory.
3. When the guest needs host data, it calls a host function (e.g.,
   `proxy_get_buffer_bytes`). The host copies the data into guest linear
   memory at a location the guest specifies.
4. When the guest provides data to the host (e.g., sending a response),
   it writes data into its own linear memory and passes a pointer + length
   to the host. The host copies the data out.

This copy-based approach is safer than shared memory -- the guest cannot
directly corrupt host state -- but adds overhead proportional to data size.

### 2.5 Configuration Passing

Configuration is passed through the `proxy_on_configure` callback:

1. Host calls `proxy_on_configure(context_id, config_size)`.
2. Guest calls `proxy_get_buffer_bytes(BufferType::PluginConfiguration, ...)`
   to read the configuration data into guest memory.
3. Configuration is typically JSON or protobuf.

### 2.6 Lessons for Chio Guard ABI

The current `chio-wasm-guards` ABI is simpler than proxy-wasm but can learn
from its design:

| proxy-wasm Pattern | Chio Equivalent | Status |
|-------------------|----------------|--------|
| Root context for config | Guard init with config JSON | Not yet implemented |
| Per-stream context | Per-request evaluate | Implemented |
| Host property access | Guard context fields | Partially (JSON blob) |
| Copy-based memory | Copy-based (JSON at offset 0) | Implemented |
| Return action enum | Return verdict i32 | Implemented |
| Structured logging | Host `chio.log` import | Not yet implemented |

**Key improvements planned for v1** (see `05-V1-DECISION.md`):

1. **Configuration via manifest:** Guards receive static configuration
   at load time from `guard-manifest.yaml`, accessed via `chio.get_config`.
2. **Host function imports:** `chio.log`, `chio.get_config`,
   `chio.get_time_unix_secs` registered on the linker.
3. **Structured deny reasons:** `chio_deny_reason` guest export as an
   alternative to the NUL-terminated string at offset 64 KiB.

---

## 3. Component Model and WIT

### 3.1 Current Status

The WebAssembly Component Model and WIT (WebAssembly Interface Types) have
reached production readiness for server-side workloads as of 2025:

- **WASI Preview 2 (WASI 0.2.0):** Stable since January 2024. All interfaces
  defined in WIT.
- **Wasmtime:** Full Component Model support, including `wasmtime::component`
  module and the `bindgen!` macro for generating Rust bindings from WIT.
- **Wasmer:** Partial support, catching up.
- **Threading:** Not yet supported in the Component Model. This is acceptable
  for guard functions which are single-threaded by nature.
- **Async (Preview 3):** In development, expected 2026-2027. Will add true
  async/await to the Component Model. For now, async is handled at the host
  level.

### 3.2 What WIT Provides

WIT is an Interface Description Language (IDL) for defining contracts between
WASM components:

```wit
// guard.wit -- hypothetical Chio guard interface

package chio:guard@0.1.0;

/// The verdict a guard returns.
enum verdict {
    allow,
    deny,
}

/// A structured deny response.
record deny-reason {
    message: string,
    code: option<string>,
}

/// Read-only request context provided to the guard.
record guard-request {
    tool-name: string,
    server-id: string,
    agent-id: string,
    arguments: string,  // JSON-encoded
    scopes: list<string>,
}

/// Static configuration passed at guard load time.
record guard-config {
    name: string,
    parameters: string,  // JSON-encoded operator config
}

/// The interface a guard component must implement.
interface evaluator {
    /// Initialize the guard with static configuration.
    /// Called once at load time.
    configure: func(config: guard-config) -> result<_, string>;

    /// Evaluate a tool-call request.
    /// Returns allow or deny with optional reason.
    evaluate: func(request: guard-request) -> result<verdict, deny-reason>;
}

/// The world a guard component targets.
world guard {
    export evaluator;

    /// Optional: host-provided logging.
    import chio:guard/logging@0.1.0;
}
```

### 3.3 How bindgen Works with Wasmtime

On the host side, `wasmtime::component::bindgen!` generates Rust types and
traits from the WIT definition:

```rust
wasmtime::component::bindgen!({
    world: "guard",
    path: "wit/guard.wit",
    async: true,
});
```

This generates:
- Rust enums/structs matching WIT types (`Verdict`, `DenyReason`,
  `GuardRequest`, `GuardConfig`).
- A trait the host implements for imported interfaces (e.g., logging).
- A struct for instantiating and calling the exported interface.

The `bindgen!` macro handles all serialization/deserialization across the
component boundary automatically -- no manual JSON serialization, no manual
pointer/length passing.

### 3.4 Pros vs. Raw ABI

| Aspect | Raw ABI (current) | Component Model + WIT |
|--------|-------------------|----------------------|
| Type safety | Manual (JSON + i32 conventions) | Automatic (generated bindings) |
| Versioning | Ad-hoc | WIT package versioning (`@0.1.0`) |
| Multi-language | Each language re-implements ABI | wit-bindgen generates for all |
| Tooling | Minimal | wit-bindgen, jco, componentize-py |
| Complexity | Low | Medium (new concepts, tools) |
| Overhead | JSON serde + copy | Component Model canonical ABI (more efficient) |
| Ecosystem maturity | N/A | Production-ready (2025+) |
| Binary size | Core WASM only | Component adds ~10-50 KiB overhead |
| Debugging | printf-style | WIT-aware tooling emerging |
| Guest compilation | `wasm32-unknown-unknown` | `wasm32-wasip2` / componentize |

### 3.5 Recommendation

> **DECISION (updated after review):** Ship v1 on the **raw core-WASM ABI**
> that the codebase already implements. Plan WIT/Component Model as a v2
> migration, not a v1 requirement.

**Rationale for raw ABI first:**

1. The code (`chio-wasm-guards/src/abi.rs`, `runtime.rs`) already implements a
   working raw ABI with `evaluate(ptr, len) -> i32`.
2. Adopting WIT now would require rewriting the host backend, the ABI types,
   and introducing new compilation toolchains (`cargo-component`,
   `componentize-py`, `jco`) before the basic contract is validated.
3. The v1 goal is to validate the execution envelope (latency, fuel, memory)
   on real Chio workloads -- the serialization format is not the bottleneck.
4. WIT migration can be done non-destructively later: support both raw modules
   (legacy) and components (new) during transition.

**WIT remains the long-term target** because of type-safe bindings, automatic
multi-language SDK generation, and interface versioning. But investing in both
raw ABI and WIT simultaneously would build two ecosystems. Ship one first.

The migration path (v2):

1. Define the guard WIT interface (as sketched in Section 3.3).
2. Implement the host side using `wasmtime::component::bindgen!`.
3. Support both raw core modules (legacy) and components (new) during
   transition.
4. Publish the WIT package for guard authors to target.

---

## 4. Guest SDK Patterns

> **v1 targets raw core-WASM only** (`wasm32-unknown-unknown`, no Component
> Model). The language toolchains below are documented as **v2 research** --
> they show what becomes possible after a WIT migration, but none of them
> are part of the v1 implementation. See `05-V1-DECISION.md` Section 1.

### 4.1 Language Support Matrix (v2 research)

| Language | Tool | Target | Component Model | Maturity |
|----------|------|--------|----------------|----------|
| Rust | `cargo-component` / `wit-bindgen` | `wasm32-wasip2` | Full | Production |
| Python | `componentize-py` | CPython-in-WASM | Full | Usable, caveats |
| TypeScript/JS | `jco` (ComponentizeJS) | StarlingMonkey | Full | Usable |
| Go | TinyGo | `wasip2` | Full (2025+) | Usable |
| C/C++ | `wit-bindgen-c` | `wasm32-wasi` | Via adapter | Partial |
| AssemblyScript | Direct | `wasm32` | No | Raw ABI only |

### 4.2 Rust via Component Model (v2 -- deferred)

> **Not part of v1.** v1 guards target `wasm32-unknown-unknown` with the raw
> `evaluate(ptr, len) -> i32` ABI. The `cargo-component` workflow below
> becomes relevant after the WIT migration in v2.

Rust is the most natural fit for WASM guard authoring:

```bash
cargo install cargo-component
cargo component new --lib my-guard
```

The `wit-bindgen` crate generates guest-side bindings:

```rust
wit_bindgen::generate!({
    world: "guard",
    path: "../wit/guard.wit",
});

struct MyGuard;

impl Guest for MyGuard {
    fn configure(config: GuardConfig) -> Result<(), String> {
        // Parse config.parameters JSON
        Ok(())
    }

    fn evaluate(request: GuardRequest) -> Result<Verdict, DenyReason> {
        if request.tool_name == "dangerous_tool" {
            Err(DenyReason {
                message: "Tool is blocked by policy".to_string(),
                code: Some("TOOL_BLOCKED".to_string()),
            })
        } else {
            Ok(Verdict::Allow)
        }
    }
}

export!(MyGuard);
```

Compiles to a ~50 KiB component. No runtime overhead beyond the WASM
execution itself.

### 4.3 Python (via componentize-py)

```bash
pip install componentize-py
componentize-py -d ./wit -w guard componentize app -o guard.wasm
```

**Limitations:**
- Bundles CPython interpreter into the WASM component. Resulting binary is
  ~10-15 MiB.
- Execution is 3-5x slower than native CPython, which itself is interpreted.
  Total overhead vs. a Rust guard: ~100-500x.
- All imports must be resolvable at build time (no dynamic imports).
- PyPy JIT does not work in WASM (no JIT support expected until 2027-2028).

**Assessment:** Acceptable for simple guards that do string matching or JSON
field checks. Not suitable for compute-intensive policy evaluation. The large
binary size means pre-compilation and caching are essential.

### 4.4 TypeScript/JavaScript (via jco)

```bash
npx jco componentize -w wit -o guard.wasm guard.js
```

**How it works:** jco embeds the StarlingMonkey JS engine (SpiderMonkey-based)
into the WASM component.

**Limitations:**
- Binary size: ~5-8 MiB (JS engine embedded).
- Execution overhead: 5-20x vs. native, depending on workload.
- No access to Node.js APIs.
- async/await in JS is not yet mapped to Component Model async.

**Assessment:** Viable for organizations with TypeScript/JavaScript policy
expertise. The overhead is acceptable for guard functions that do simple
checks. Larger than Rust but smaller than Python.

### 4.5 Go (via TinyGo)

```bash
tinygo build -target=wasip2 -o guard.wasm .
```

**Current status:** TinyGo has merged WASI P2 support into its dev branch
(2025). Components can be compiled directly from TinyGo's CLI with
`-target=wasip2`.

**Limitations:**
- TinyGo does not support the full Go standard library (no `reflect`, limited
  `net`, etc.).
- Binary size: ~500 KiB to 2 MiB typical.
- Garbage collector runs inside WASM linear memory (small GC pause risk).

**Assessment:** Good option for Go shops. TinyGo's restrictions are unlikely
to matter for guard functions that primarily do JSON parsing and field checks.

### 4.6 Guest SDK Strategy

> **v1:** Raw core-WASM ABI only (`wasm32-unknown-unknown`). Guest SDKs are
> deferred to v2. Guard authors target the raw `evaluate(ptr, len) -> i32`
> contract documented in `03-IMPLEMENTATION-PLAN.md` Section 3.
>
> **v2 (deferred):** Once the raw ABI is validated on real workloads:
> 1. Define and publish a WIT interface as the canonical guard contract.
> 2. Provide a Rust SDK crate (`chio-guard-sdk`) with helpers.
> 3. Document componentize-py and jco workflows for Python/TS authors.
> 4. Accept both raw core modules (legacy) and components (new).

---

## 5. Security Considerations

### 5.1 Attack Surface Analysis

Running user-supplied WASM introduces the following attack surfaces:

#### 5.1.1 Runtime Bugs (Sandbox Escape)

The WASM sandbox relies on the correctness of the runtime implementation.
Known historical issues:

- **Wasmtime externref confusion (2024):** A regression allowed a module to
  confuse a host-managed GC reference with a raw integer, potentially
  leading to memory disclosure. Fixed promptly.
- **Wasmer path traversal:** A flaw in WASI filesystem path translation
  allowed modules to bypass directory restrictions. Fixed.
- **V8 WASM bugs:** CVE-2025-5419 (heap corruption via crafted WASM). This
  is in V8/browser context, not Wasmtime, but illustrates that JIT compilers
  are a source of bugs.

**Mitigation:**
- Use Wasmtime (most audited, best CVE response process).
- Keep Wasmtime up to date (subscribe to security advisories).
- Run the WASM runtime in a separate process with minimal OS privileges
  (defense in depth beyond the WASM sandbox).
- Disable unnecessary Wasmtime features to reduce attack surface.

#### 5.1.2 Resource Exhaustion

A malicious guard could attempt to exhaust host resources:

| Attack | Mitigation |
|--------|-----------|
| Infinite loop | Fuel metering (deterministic) + epoch interruption (wall-clock) |
| Memory bomb (`memory.grow` in loop) | `ResourceLimiter` capping at 1-4 MiB |
| Table growth | `ResourceLimiter::table_growing` returning false |
| Stack overflow (deep recursion) | Wasmtime's configurable stack limit (`Config::max_wasm_stack`) |
| Compilation bomb (huge module) | Cap module size at load time, compilation timeout |

#### 5.1.3 Side Channels

WASM modules share the host CPU and may attempt timing side channels:

- **Clock access:** Do not provide WASI clock to guards. Without
  `clock_time_get`, timing attacks are much harder.
- **Fuel consumption as side channel:** A guard could infer information
  about the host by measuring how much fuel it has remaining. This is a
  theoretical concern; in practice, guards see only the request context
  provided to them.

**Mitigation:** Deny all WASI capabilities. Guards are pure functions
operating on provided context only.

#### 5.1.4 Supply Chain

Users uploading `.wasm` files is analogous to uploading executable code:

- **Module signing:** Require guards to be signed by an authorized key.
  The Chio manifest system already has a signing infrastructure that can
  be extended to guard modules.
- **Content hashing:** Store and verify SHA-256 hashes of loaded modules
  in the receipt log.
- **Review process:** In production deployments, guard modules should go
  through a review/approval process before deployment, similar to how
  proxy-wasm filters are managed in service mesh deployments.

#### 5.1.5 Information Disclosure via Guard Context

The `GuardRequest` struct exposes tool arguments to the guard. A malicious
guard that always returns "allow" could be used to exfiltrate data if it
has any I/O capability.

**Mitigation:**
- Zero WASI capabilities (no network, no filesystem, no stdout).
- No host-provided I/O functions beyond logging (and logging can be
  rate-limited and audited).
- Consider redacting sensitive argument fields before passing to guards
  based on operator configuration.

### 5.2 Defense-in-Depth Checklist

```
[x] Fuel metering with configurable per-guard budget
[x] Memory limit via ResourceLimiter (default: 4 MiB)
[ ] Epoch interruption as wall-clock backstop (100ms default)
[ ] Zero WASI capabilities by default
[ ] Module size limit at load time (e.g., 10 MiB)
[ ] Module signature verification before loading
[ ] Module hash recorded in receipt log
[ ] ResourceLimiter denying table growth
[ ] Max WASM stack depth configured
[ ] Guard execution in dedicated thread pool (isolate from kernel I/O)
[ ] Rate limiting on host-provided logging functions
[ ] Separate process option for maximum isolation
```

---

## 6. Recommendations for Chio

### 6.1 Runtime Choice: Wasmtime

**Wasmtime is the clear choice.** It leads in:
- Security posture (audits, CVE process, Bytecode Alliance governance)
- Component Model / WIT support (production-ready)
- Async integration (first-class Tokio support)
- Fuel metering and resource limiting (native, well-tested)
- WASI capability control (fine-grained)
- Ecosystem momentum (Fermyon Spin, Fastly, wasmCloud all use it)

The existing `chio-wasm-guards` crate already uses Wasmtime v29, which is
the right foundation.

### 6.2 v1 (see `05-V1-DECISION.md` for authoritative scope)

1. **Add `ResourceLimiter`** to cap memory per guard invocation.
2. **Add host function imports** for structured logging (`chio.log`), config
   access (`chio.get_config`), and wall-clock time (`chio.get_time_unix_secs`).
3. **Add `chio_alloc` / `chio_deny_reason`** export support.
4. **Add module size and import validation** at load time.
5. **Benchmark spike** -- module load, instantiation, p50/p99 evaluate
   latency, fuel overhead.

> Epoch interruption and async host support are deferred to v1.1 and v2
> respectively. The kernel Guard trait is sync; see `05-V1-DECISION.md`
> Section 2.

### 6.3 v2 (Component Model Migration)

1. **Define the guard WIT interface** (`chio:guard@0.1.0`).
2. **Implement Component Model host** using `wasmtime::component::bindgen!`.
3. **Support dual mode:** Accept both core WASM modules (raw ABI) and
   Component Model components.
4. **Publish `chio-guard-sdk`** Rust crate for guard authors.
5. **Document guest SDK workflows** for Python (componentize-py), TypeScript
   (jco), and Go (TinyGo).
6. **Provide example guards** in each supported language.

### 6.4 Long-Term

1. **Module signing and verification** integrated with Chio manifest system.
2. **Guard marketplace:** Curated, signed guards for common policy patterns
   (PII detection, rate limiting, scope enforcement).
3. **Preview 3 async adoption** when Component Model async stabilizes
   (expected 2026-2027) -- enables guards to make async host calls for
   external policy lookups.
4. **Guard testing framework:** A `cargo-component`-based test harness that
   lets guard authors test their modules locally against mock Chio contexts.

---

## Sources

- [WebAssembly Runtime Benchmarks 2026](https://wasmruntime.com/en/benchmarks)
- [Choosing a WebAssembly Run-Time](https://blog.colinbreck.com/choosing-a-webassembly-run-time/)
- [Wasmtime vs Wasmer vs WasmEdge Comparison 2026](https://reintech.io/blog/wasmtime-vs-wasmer-vs-wasmedge-wasm-runtime-comparison-2026)
- [Wasmtime Security Documentation](https://docs.wasmtime.dev/security.html)
- [Wasmtime ResourceLimiter](https://docs.wasmtime.dev/api/wasmtime/trait.ResourceLimiter.html)
- [Wasmtime Fuel Metering (Issue #4109)](https://github.com/bytecodealliance/wasmtime/issues/4109)
- [Wasmtime Interrupting Execution](https://docs.wasmtime.dev/examples-interrupting-wasm.html)
- [Wasmtime Config API](https://docs.wasmtime.dev/api/wasmtime/struct.Config.html)
- [Wasmtime Epoch Interruption PR #3699](https://github.com/bytecodealliance/wasmtime/pull/3699)
- [Wasmtime Minimal Embedding](https://docs.wasmtime.dev/examples-minimal.html)
- [Wasmtime Feature Flags](https://lib.rs/crates/wasmtime/features)
- [Wasmtime WASI Capabilities](https://github.com/bytecodealliance/wasmtime/blob/main/docs/WASI-capabilities.md)
- [Wasmtime WASI Async Runtime](https://docs.wasmtime.dev/api/wasmtime_wasi/runtime/index.html)
- [proxy-wasm Specification](https://github.com/proxy-wasm/spec)
- [proxy-wasm ABI v0.2.1](https://github.com/proxy-wasm/spec/tree/main/abi-versions/v0.2.1)
- [proxy-wasm Rust SDK](https://github.com/proxy-wasm/proxy-wasm-rust-sdk)
- [WebAssembly in Envoy](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/advanced/wasm)
- [Envoy WASM Extensions Explained](https://thenewstack.io/wasm-modules-and-envoy-extensibility-explained-part-1/)
- [Envoy WASM Plugins Case Study](https://eli.thegreenplace.net/2023/plugins-case-study-envoy-wasm-extensions/)
- [WASM Component Model Introduction](https://component-model.bytecodealliance.org/)
- [WIT Reference](https://component-model.bytecodealliance.org/design/wit.html)
- [wasmtime::component::bindgen Documentation](https://docs.wasmtime.dev/api/wasmtime/component/macro.bindgen.html)
- [wit-bindgen Repository](https://github.com/bytecodealliance/wit-bindgen)
- [WASI Preview 2 vs WASIX 2026](https://wasmruntime.com/en/blog/wasi-preview2-vs-wasix-2026)
- [Wasmtime vs Wasmer 2026](https://wasmruntime.com/en/blog/wasmtime-vs-wasmer-2026)
- [Introducing Wasmer 5.0](https://wasmer.io/posts/introducing-wasmer-v5)
- [componentize-py Repository](https://github.com/bytecodealliance/componentize-py)
- [jco Repository](https://github.com/bytecodealliance/jco)
- [TinyGo WASI P2 Support](https://wasmcloud.com/blog/compile-go-directly-to-webassembly-components-with-tinygo-and-wasi-p2/)
- [Introducing Componentize-Py (Fermyon)](https://www.fermyon.com/blog/introducing-componentize-py)
- [Python WebAssembly Performance](https://johal.in/debugging-python-interpreter-performance-in-webassembly-container-environments/)
- [WASM Security (WebAssembly.org)](https://webassembly.org/docs/security/)
- [WASM Sandbox Escape Analysis](https://medium.com/@instatunnel/the-wasm-breach-escaping-backend-webassembly-sandboxes-05ad426051fc)
- [WebAssembly Security Vulnerabilities](https://www.geoedge.com/webassembly-a-new-attack-uncovered/)
- [wasm3 Repository](https://github.com/wasm3/wasm3)
- [WebAssembly Runtimes Survey (ACM)](https://dl.acm.org/doi/full/10.1145/3714465)
- [Wasmtime 1.0 Performance](https://bytecodealliance.org/articles/wasmtime-10-performance)
- [clawbox-sandbox Crate](https://crates.io/crates/clawbox-sandbox)
