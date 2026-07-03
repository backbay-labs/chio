# Portable Kernel Architecture: `chio-kernel-core` Extraction


> The WASM kernel build is the single largest surface multiplier in the Chio
> roadmap. It unlocks browser agents, edge workers (Cloudflare Workers, Deno
> Deploy), mobile (iOS/Android via FFI), browser extensions, and IoT. This
> document covers the extraction of a portable, `no_std`-compatible kernel core
> from the existing `chio-kernel` crate, the dependency analysis required to
> reach `wasm32-unknown-unknown`, the target matrix, platform adapter
> contracts, and the migration path from the current monolithic kernel.

---

## 1. The Split: `chio-kernel-core` vs `chio-kernel`

### 1.1 Design Principle

The Chio kernel's security-critical logic -- capability validation, scope
checking, guard evaluation, DPoP verification, receipt signing -- is pure
computation over signed data structures. None of it requires an async runtime,
a filesystem, or a network socket. The current `chio-kernel` crate couples this
pure logic with IO-dependent infrastructure (tokio, rusqlite, ureq) that
prevents compilation to WASM or bare-metal targets.

The fix is a clean two-crate split:

```
chio-kernel-core (no_std + alloc)        chio-kernel (full, std)
---------------------------------       ---------------------------------
capability validation                   depends on chio-kernel-core
scope checking                          tokio async runtime
guard pipeline (sync)                   rusqlite receipt persistence
DPoP proof verification                 ureq HTTP client (price oracles)
receipt signing (Ed25519 + SHA-256)     HTTP/stdio transport layer
in-memory receipt buffer (Vec)          async guard adapters
Merkle checkpoint construction          session management (RwLock)
budget accounting (in-memory)           tool server dispatch
revocation checking (in-memory set)     persistent budget/revocation stores
```

`chio-kernel-core` is the portable TCB. `chio-kernel` is a thin orchestration
shell that wires `chio-kernel-core` to platform IO.

### 1.2 Crate Boundaries

**`chio-kernel-core`** contains:

- `KernelCore` struct: holds keypair, CA trust set, guards, in-memory receipt
  buffer, in-memory budget map, in-memory revocation set, DPoP nonce cache.
- All types currently in `kernel/mod.rs` that do not reference tokio, rusqlite,
  or ureq: `KernelError`, `KernelConfig` (subset), `GuardContext`,
  `StructuredErrorReport`, `MatchingGrant`, `ReceiptContent`.
- The `Guard` trait (already sync: `fn evaluate(&self, ctx: &GuardContext) ->
  Result<Verdict, KernelError>`).
- The `Verdict` enum.
- Capability validation: signature verification, time-bound checks, scope
  matching, delegation chain walking, subject binding.
- DPoP proof verification (already pure crypto over `LruCache`).
- Receipt signing and Merkle checkpoint construction.
- Budget accounting against in-memory `HashMap<CapabilityId, u64>`.
- Revocation checking against in-memory `HashSet<CapabilityId>`.

**`chio-kernel`** contains:

- `ChioKernel` struct: wraps `KernelCore`, adds `dyn ReceiptStore`,
  `dyn ToolServerConnection`, `dyn PaymentAdapter`, `dyn PriceOracle`,
  `dyn ResourceProvider`, `dyn PromptProvider`, session map, async dispatch.
- `ReceiptStore` trait and SQLite implementation (via `chio-store-sqlite`).
- `ToolServerConnection` trait and HTTP/stdio implementations.
- Async guard adapters that wrap sync `Guard` trait calls.
- Session management with `RwLock<HashMap<SessionId, Session>>`.
- Transport layer (HTTP server, stdio pipe).
- Price oracle HTTP client (ureq).
- All existing public API surface re-exported unchanged.

### 1.3 Feature Flag Strategy

During migration, `chio-kernel` gains a `full` feature (enabled by default) that
gates IO-dependent code. This allows incremental extraction without breaking
downstream crates.

```toml
# chio-kernel/Cargo.toml
[features]
default = ["full"]
full = ["dep:tokio", "dep:rusqlite", "dep:ureq"]
```

Code that touches IO is gated:

```rust
#[cfg(feature = "full")]
pub mod transport;

#[cfg(feature = "full")]
pub mod receipt_store_sqlite;
```

Once `chio-kernel-core` is extracted as a standalone crate, the feature flags
are removed and `chio-kernel` unconditionally depends on `chio-kernel-core` plus
its IO dependencies.

---

## 2. Dependency Analysis

### 2.1 WASM-Compatible (stays in `chio-kernel-core`)

| Dependency | WASM status | Notes |
|---|---|---|
| `ed25519-dalek` | Compiles cleanly to `wasm32` | Pure Rust, no system calls. |
| `sha2` | Compiles cleanly to `wasm32` | Pure Rust, software implementation. |
| `serde` / `serde_json` | Compiles cleanly to `wasm32` | Standard serialization. |
| `hex` | Compiles cleanly to `wasm32` | Pure Rust encoding. |
| `ryu` | Compiles cleanly to `wasm32` | Float formatting for canonical JSON. |
| `thiserror` | Compiles cleanly to `wasm32` | Derive macro, no runtime dep. |
| `lru` | Compiles cleanly to `wasm32` | Used by DPoP nonce cache. |
| `url` | Compiles cleanly to `wasm32` | URI parsing for scope matching. |
| `percent-encoding` | Compiles cleanly to `wasm32` | URI component encoding. |
| `tracing` | Compiles cleanly to `wasm32` | Subscriber provided by host. |

### 2.2 Conditional (needs feature gating)

| Dependency | Issue | Resolution |
|---|---|---|
| `rand_core` / `getrandom` | `OsRng` needs platform entropy | `getrandom` with `js` feature for browser, `wasi` feature for WASI. Injected via trait in core. |
| `uuid` (v7) | Depends on `getrandom` for timestamp-random | Same `getrandom` feature gating. Alternatively, accept caller-provided IDs in core. |
| `std::time::SystemTime` | Not available in `no_std` | Core accepts `u64` Unix timestamps from caller. No `SystemTime::now()` calls in core. |
| `std::time::Instant` | Not available in `no_std` or WASM | Replace with caller-injected monotonic clock or remove (used for DPoP freshness). |
| `std::sync::{Mutex, RwLock}` | Available in `std` but not `no_std` | Core uses `alloc` only. Single-threaded WASM does not need locks. Use `spin::Mutex` behind a feature flag, or accept `&mut self` in core API. |

### 2.3 DROP from Core

| Dependency | Reason | Replacement in core |
|---|---|---|
| `tokio` | Async runtime, not available in WASM single-threaded context | Core API is fully synchronous. |
| `rusqlite` | SQLite FFI, links native C library | In-memory `Vec<ChioReceipt>` ring buffer in core. Platform adapters persist externally. |
| `ureq` | HTTP client for price oracle | Core accepts pre-resolved price data. Platform adapters fetch prices. |
| `chio-appraisal` | Runtime attestation, may have system deps | Inject attestation records. Core verifies signatures only. |
| `chio-governance` | May pull transitive IO deps | Extract pure evaluation logic if needed, or inject results. |

### 2.4 `getrandom` Configuration Per Target

```toml
# chio-kernel-core/Cargo.toml

[target.'cfg(target_arch = "wasm32")'.dependencies]
getrandom = { version = "0.2", features = ["js"] }

[target.'cfg(target_os = "wasi")'.dependencies]
getrandom = { version = "0.2", features = ["wasi"] }
```

The `js` feature routes entropy to `crypto.getRandomValues()` in browsers and
Cloudflare Workers. The `wasi` feature routes to the WASI random API.

---

## 3. Target Matrix

### 3.1 Supported Targets

| Target triple | Environment | Priority | Status |
|---|---|---|---|
| `wasm32-unknown-unknown` | Browser, Cloudflare Workers, Deno Deploy | P0 | Core build proven in repo; browser qualification still pending |
| `wasm32-wasip1` | Wasmtime, WasmEdge, Deno (WASI mode) | P0 | Planned next proof after the current browser-target build gate |
| `x86_64-unknown-linux-gnu` | Server (current default) | P0 | Working today |
| `aarch64-apple-darwin` | macOS (current dev) | P0 | Working today |
| `aarch64-apple-ios` | iOS via UniFFI/C FFI | P1 | Host FFI tests and device staticlib build are scripted in repo |
| `aarch64-linux-android` | Android via UniFFI/C FFI | P1 | Host FFI tests are scripted; real shared-lib qualification requires a provisioned NDK host |
| `x86_64-pc-windows-msvc` | Windows desktop | P2 | Likely works, untested |
| `thumbv7em-none-eabihf` | Cortex-M embedded (no_std) | P3 (stretch) | Requires full no_std, no alloc fallback |

### 3.2 Binary Size Estimates

Estimates based on comparable Rust WASM crates (ed25519-dalek + sha2 + serde):

| Target | Estimated size | Notes |
|---|---|---|
| `wasm32-unknown-unknown` (release, wasm-opt) | 180-250 KB | Core only, no transport. Comparable to `ring` WASM builds. |
| `wasm32-wasip1` (release) | 200-280 KB | Slightly larger due to WASI shims. |
| `aarch64-apple-ios` (static lib) | 400-600 KB | Includes ed25519-dalek native. Acceptable for mobile. |
| `aarch64-linux-android` (shared lib) | 400-600 KB | Same as iOS estimate. |
| `thumbv7em-none-eabihf` | 80-120 KB | Would require `no_std` + `no_alloc` subset. Stretch goal. |

Size budget target: under 300 KB for the WASM build. This keeps load time
under 50ms on a cold Cloudflare Worker start.

### 3.3 Build Verification Matrix

CI adds cross-compilation checks for each target:

```yaml
# .github/workflows/portable.yml (sketch)
jobs:
  wasm-browser:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: rustup target add wasm32-unknown-unknown
      - run: cargo build -p chio-kernel-core --target wasm32-unknown-unknown --release
      - run: wasm-opt -Oz -o kernel-core.wasm target/wasm32-unknown-unknown/release/chio_kernel_core.wasm
      - run: test $(stat -c%s kernel-core.wasm) -lt 307200  # 300 KB gate

  wasm-wasi:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: rustup target add wasm32-wasip1
      - run: cargo build -p chio-kernel-core --target wasm32-wasip1 --release

  ios:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4
      - run: rustup target add aarch64-apple-ios
      - run: cargo build -p chio-kernel-core --target aarch64-apple-ios --release
```

---

## 4. Platform Adapters

Each deployment environment provides a platform adapter that implements the
IO contracts that `chio-kernel-core` does not handle: entropy, persistence,
time, and transport. `chio-kernel-core` defines trait boundaries; adapters
implement them.

### 4.1 Trait Boundaries

```rust
/// Entropy source for receipt IDs and DPoP nonces.
pub trait EntropySource {
    fn fill_bytes(&self, dest: &mut [u8]);
}

/// Clock for capability time-bound checks and DPoP freshness.
pub trait Clock {
    /// Current Unix timestamp in seconds.
    fn now_unix_secs(&self) -> u64;
}

/// Optional persistent receipt storage.
/// Core uses an in-memory ring buffer by default.
pub trait ReceiptSink {
    fn persist(&mut self, receipt: &ChioReceipt) -> Result<(), ReceiptSinkError>;
}

/// Optional price data provider for cross-currency budget enforcement.
pub trait PriceProvider {
    fn get_rate(&self, base: &str, quote: &str) -> Result<f64, PriceProviderError>;
}
```

### 4.2 Browser Adapter (`chio-kernel-wasm`)

Bindings via `wasm-bindgen`. Published as an npm package.

| Concern | Implementation |
|---|---|
| Entropy | `crypto.getRandomValues()` via `getrandom` `js` feature |
| Clock | `Date.now()` / `performance.now()` via `js_sys` |
| Receipt persistence | IndexedDB via `idb` crate or `wasm-bindgen` JS interop |
| Transport | Not applicable -- browser host calls `evaluate()` directly |
| Guard loading | WASM guards loaded as nested modules or compiled JS functions |

```rust
// Sketch: wasm-bindgen surface
#[wasm_bindgen]
pub struct BrowserKernel {
    core: KernelCore<WebEntropy, WebClock>,
}

#[wasm_bindgen]
impl BrowserKernel {
    #[wasm_bindgen(constructor)]
    pub fn new(config_json: &str) -> Result<BrowserKernel, JsValue> { ... }

    pub fn evaluate(&mut self, request_json: &str) -> Result<String, JsValue> { ... }

    pub fn verify_capability(&self, token_json: &str) -> Result<String, JsValue> { ... }

    pub fn sign_receipt(&mut self, verdict_json: &str) -> Result<String, JsValue> { ... }
}
```

### 4.3 Edge Worker Adapter (`chio-kernel-edge`)

For Cloudflare Workers, Deno Deploy, and similar V8-isolate runtimes.

| Concern | Implementation |
|---|---|
| Entropy | `crypto.getRandomValues()` (same as browser) |
| Clock | `Date.now()` (same as browser) |
| Receipt persistence | KV store binding (Cloudflare KV, Deno KV) via host JS interop |
| Transport | Worker fetch handler calls `evaluate()` on each request |
| Guard loading | Compiled into the WASM module at build time |

Edge workers are the highest-value target after desktop. A Cloudflare Worker
running `chio-kernel-core` can enforce capability-based security on tool
invocations at the edge with sub-millisecond overhead, without a sidecar
process or a round-trip to a central kernel.

### 4.4 Mobile Adapter (iOS / Android)

Bindings via UniFFI (preferred) or raw C FFI.

| Concern | Implementation |
|---|---|
| Entropy | OS entropy (`SecRandomCopyBytes` on iOS, `/dev/urandom` on Android) |
| Clock | `SystemTime::now()` (available on mobile std targets) |
| Receipt persistence | SQLite (available natively on both platforms) |
| Transport | In-process function calls from Swift/Kotlin |
| Guard loading | Compiled into the static/shared library |

```swift
// Sketch: Swift via UniFFI
let config = KernelCoreConfig(
    keypairHex: "...",
    caPublicKeys: ["..."],
    policyHash: "..."
)
let kernel = try KernelCore(config: config)
let verdict = try kernel.evaluate(requestJson: toolCallJson)
```

Repo-local qualification commands for the mobile adapter:

```bash
cargo test -p chio-kernel-mobile --test ffi_roundtrip
./scripts/qualify-mobile-kernel.sh
```

The qualification script records each lane as `pass`, `fail`, or
`environment_dependent` so iOS and Android support claims stay tied to
actual toolchain availability on the qualifying host. The overall gate fails
unless at least one target-backed iOS or Android lane runs and passes.

### 4.5 Desktop (Current Model)

No changes required. The existing `chio-kernel` crate continues to work as a
standalone sidecar process. After extraction, `chio-kernel` depends on
`chio-kernel-core` and provides the tokio runtime, SQLite persistence, HTTP
transport, and all current functionality unchanged.

```
Desktop: chio-kernel (binary)
    |
    +-- chio-kernel-core (library, pure computation)
    +-- tokio (async runtime)
    +-- rusqlite (receipt persistence)
    +-- ureq (price oracle HTTP)
```

---

## 5. API Surface of `chio-kernel-core`

All public methods are synchronous, pure, and deterministic given an entropy
source and clock.

### 5.1 Core Operations

```rust
impl<E: EntropySource, C: Clock> KernelCore<E, C> {
    /// Validate a capability token and evaluate guards against a tool call.
    ///
    /// This is the primary entry point. It performs, in order:
    /// 1. Capability signature verification
    /// 2. Time-bound validation (via injected Clock)
    /// 3. Revocation check (in-memory set)
    /// 4. Scope matching (server + tool + resource)
    /// 5. Delegation chain validation
    /// 6. Subject binding (DPoP if required)
    /// 7. Budget check and hold (in-memory map)
    /// 8. Guard pipeline evaluation (all registered guards, fail-closed)
    ///
    /// Returns Verdict::Allow or Verdict::Deny. Never panics.
    pub fn evaluate(
        &mut self,
        request: &ToolCallRequest,
        dpop_proof: Option<&DpopProof>,
    ) -> Result<Verdict, KernelError>;

    /// Sign a receipt attesting to a kernel decision.
    ///
    /// Produces an Ed25519-signed ChioReceipt over the canonical JSON of the
    /// receipt body. Appends to the in-memory receipt buffer and advances the
    /// Merkle checkpoint if the batch threshold is reached.
    pub fn sign_receipt(
        &mut self,
        verdict: Verdict,
        request: &ToolCallRequest,
        metadata: Option<serde_json::Value>,
    ) -> Result<ChioReceipt, KernelError>;

    /// Verify a capability token's signature and structure.
    ///
    /// Does NOT check time bounds or revocation -- use evaluate() for full
    /// validation. This is useful for offline token inspection.
    pub fn verify_capability(
        &self,
        token: &CapabilityToken,
    ) -> Result<ChioScope, KernelError>;

    /// Add a capability ID to the in-memory revocation set.
    pub fn revoke(&mut self, capability_id: &str);

    /// Drain the in-memory receipt buffer.
    ///
    /// Platform adapters call this periodically to persist receipts to
    /// IndexedDB, KV, SQLite, or other durable storage.
    pub fn drain_receipts(&mut self) -> Vec<ChioReceipt>;

    /// Register a guard in the evaluation pipeline.
    pub fn add_guard(&mut self, guard: Box<dyn Guard>);

    /// Return the current Merkle checkpoint root hash, if any.
    pub fn checkpoint_root(&self) -> Option<&str>;
}
```

### 5.2 Design Constraints

- **No `async`.** Every method is synchronous. The caller (platform adapter or
  `chio-kernel` orchestrator) owns the async runtime if one exists.
- **No `SystemTime::now()`.** Time comes from the injected `Clock` trait.
  This makes the core deterministic and testable with a mock clock.
- **No `OsRng` directly.** Entropy comes from the injected `EntropySource`
  trait. This allows browser, WASI, and bare-metal entropy sources.
- **No filesystem or network.** Receipts accumulate in a `Vec` ring buffer.
  The caller drains and persists them.
- **Fail-closed.** Any error during guard evaluation, capability verification,
  or budget enforcement results in `Verdict::Deny`. This invariant is
  enforced in `chio-kernel-core` and cannot be overridden by platform adapters.
- **`Send + Sync` guards.** The `Guard` trait requires `Send + Sync`. On
  single-threaded WASM, this is satisfied trivially. On multi-threaded
  targets, guards must be thread-safe.

---

## 6. Migration Path

### Phase 1: Feature-Flag Existing Code

Modify `chio-kernel/Cargo.toml` to make IO dependencies optional behind a
`full` feature (default on). Gate all IO-touching modules. Verify the
workspace still compiles with `cargo build --workspace` and all tests pass.

Estimated scope: 1-2 days. No behavioral changes.

```
chio-kernel/
  Cargo.toml          # Add [features] full = [tokio, rusqlite, ureq]
  src/
    lib.rs            # #[cfg(feature = "full")] on transport, receipt_store, etc.
    kernel/mod.rs     # Split ChioKernel into core fields + #[cfg(feature = "full")] IO fields
```

### Phase 2: Extract `chio-kernel-core`

Create `crates/kernel/chio-kernel-core/` with the pure-computation subset. Move types,
traits, and validation logic. `chio-kernel` depends on `chio-kernel-core` and
re-exports its public API.

```
crates/
  chio-kernel-core/
    Cargo.toml        # no_std + alloc, no IO deps
    src/
      lib.rs          # KernelCore, Guard, Verdict, KernelError, etc.
      capability.rs   # Validation logic extracted from kernel/mod.rs
      dpop.rs         # DPoP verification (moved from chio-kernel)
      receipt.rs      # Receipt signing + Merkle checkpoint
      budget.rs       # In-memory budget accounting
      revocation.rs   # In-memory revocation set
  chio-kernel/
    Cargo.toml        # depends on chio-kernel-core + tokio + rusqlite + ureq
    src/
      lib.rs          # ChioKernel wraps KernelCore, adds IO
```

Current in-repo proof command:

```bash
./scripts/check-portable-kernel.sh
```

It proves both:

1. `cargo build -p chio-kernel-core --no-default-features`
2. `cargo build -p chio-kernel-core --target wasm32-unknown-unknown --no-default-features`

Broader qualification still layers on top of that:

3. `cargo test -p chio-kernel-core`
4. `cargo test -p chio-kernel`
5. `cargo build --workspace`

Estimated scope: 3-5 days.

### Phase 3: Platform Adapter Crates

Create adapter crates for each target environment:

```
crates/
  chio-kernel-wasm/        # wasm-bindgen bindings for browser
  chio-kernel-edge/        # Cloudflare Workers / Deno Deploy adapter
  chio-kernel-mobile/      # UniFFI bindings for iOS/Android
```

Each adapter crate depends on `chio-kernel-core` and implements the trait
boundaries (`EntropySource`, `Clock`, `ReceiptSink`).

Estimated scope: 1-2 weeks per adapter.

### Phase 4: CI and Size Gates

Add cross-compilation targets to CI. Enforce binary size limits per target.
Publish `chio-kernel-wasm` to npm. Publish `chio-kernel-mobile` UniFFI bindings
to CocoaPods/Maven. The repo-local qualification entry points are now
`./scripts/check-portable-kernel.sh`, `./scripts/qualify-portable-browser.sh`,
and `./scripts/qualify-mobile-kernel.sh`.

### Dependency Graph After Extraction

```
chio-core-types (pure data + crypto, already WASM-ready)
    |
chio-core (canonical JSON, signing, receipts)
    |
chio-kernel-core (validation, guards, DPoP, receipts -- portable)
    |
    +-- chio-kernel (full: tokio + rusqlite + ureq + transport)
    |       |
    |       +-- chio-mcp-edge, chio-a2a-edge, chio-acp-edge, chio-cli ...
    |
    +-- chio-kernel-wasm (browser: wasm-bindgen + IndexedDB)
    |
    +-- chio-kernel-edge (workers: WASI + KV)
    |
    +-- chio-kernel-mobile (iOS/Android: UniFFI + native SQLite)
```

---

## 7. Security Considerations

### 7.1 TCB Surface

`chio-kernel-core` is the portable TCB. Its correctness properties must hold on
every target:

- **Fail-closed invariant.** Any error path produces `Verdict::Deny`.
- **Signature verification.** Ed25519 verification uses `ed25519-dalek` on all
  targets. No platform-specific crypto substitution.
- **Canonical JSON determinism.** `canonical_json_bytes()` must produce
  identical output on all targets. This is already the case (Rust float
  formatting via `ryu` is deterministic).
- **No ambient authority.** The core never reads environment variables,
  files, or network state. All inputs are explicit function arguments.

### 7.2 Entropy Quality

Browser and edge targets use `crypto.getRandomValues()` which is
cryptographically secure. WASI targets use the host's entropy source. The
`EntropySource` trait does not enforce quality -- deployments on constrained
hardware (Cortex-M) must ensure the injected source meets cryptographic
requirements.

### 7.3 Side-Channel Resistance

Ed25519-dalek uses constant-time operations. SHA-256 in `sha2` is not
constant-time but is used only for content hashing (not secret-dependent). No
additional side-channel concerns from the WASM compilation target.

---

## 8. Open Questions

1. **`alloc` vs `no_std` + `no_alloc`.** The initial extraction targets
   `no_std` + `alloc` (covers WASM, mobile, most embedded). A `no_alloc`
   subset for bare-metal Cortex-M would require static buffers and bounded
   data structures. This is a stretch goal; the `alloc` boundary covers all
   P0-P2 targets.

2. **Guard trait async variant.** Some platform adapters may want async guards
   (e.g., a browser guard that checks IndexedDB). The core `Guard` trait is
   sync. Async guards can be implemented in the platform adapter layer by
   blocking on the future before calling into core, or by providing a separate
   `AsyncGuard` trait in `chio-kernel` (not core).

3. **Receipt buffer size limit.** The in-memory `Vec<ChioReceipt>` in core
   needs a configurable upper bound to prevent OOM on constrained targets.
   When the buffer is full, options are: reject new operations (fail-closed),
   evict oldest receipts (lossy), or signal the platform adapter to drain.

4. **`chio-core` portability.** `chio-core` sits between `chio-core-types` and
   `chio-kernel-core`. It must also compile to WASM. Current audit shows no
   blocking dependencies, but this needs verification with a CI build gate.

5. **Transitive dependency audit.** `chio-kernel` depends on `chio-governance`,
   `chio-credit`, `chio-market`, `chio-open-market`, `chio-listing`,
   `chio-underwriting`, and `chio-appraisal`. These must NOT be dependencies
   of `chio-kernel-core`. The core kernel evaluates capabilities and guards;
   governance and market logic stays in the full kernel or in dedicated crates
   that the platform adapter can optionally include.
