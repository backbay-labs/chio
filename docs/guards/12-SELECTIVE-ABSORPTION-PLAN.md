# Selective Absorption: Async Runtime, Threat Intel, Custom Registry, DPoP

This document closes the three documentation gaps identified in the
upstream-to-Chio porting audit. Docs 06-11 cover the "absorb now" items
(6 guards, 3 subsystems, data layer). This doc covers the "absorb
selectively" items -- components where we take the pattern but refactor
for Chio's architecture rather than copying code.

Also closes the partial gap on WASM guard registry unification.

---

## 1. Custom Guard Registry: Merging the upstream `custom.rs` with `chio-wasm-guards`

### 1.1 What the Upstream Suite Has

`guards/custom.rs` (605 lines) implements dynamic guard loading:

```rust
// upstream types
trait CustomGuardFactory: Send + Sync {
    fn build(&self, config: Value) -> Result<Box<dyn Guard>>;
}

struct CustomGuardRegistry {
    factories: HashMap<String, Chio<dyn CustomGuardFactory>>,
}
```

When the `wasm-plugin-runtime` feature is enabled, it loads WASM guard
binaries from plugin manifests:

- Plugin manifest discovery (finds `[[guards]]` entries with entrypoints)
- Path traversal protection on WASM binary paths
- Capability and resource intersection (principle of least privilege)
- JSON config passed to factory `build()` for guard instantiation

The async guard registry (`async_guards/registry.rs`) adds policy-driven
instantiation: `build_async_guards()` reads the policy config, matches
package names to guard constructors, resolves placeholder variables in
config (`resolve_placeholders_in_json`), and returns `Vec<Chio<dyn AsyncGuard>>`.

### 1.2 What Chio Has

`chio-wasm-guards` is a full WASM guard runtime:

- `WasmGuardRuntime` -- loads `.wasm` binaries, manages Wasmtime instances
- `GuardRequest` / `GuardResponse` ABI over JSON in linear memory
- Fuel-bounded execution (deterministic termination)
- Per-call fresh `Store` (stateless, no cross-request leakage)
- Host function interface (`chio_log`, `chio_get_config`)
- Manifest-based guard declaration with config

### 1.3 Unification Plan

Chio's WASM runtime is more mature than the upstream plugin loader. The
merge direction is: keep `chio-wasm-guards` as the runtime, absorb
The upstream registry and policy-driven instantiation patterns.

**What to take from the upstream guard suite:**

1. **Policy-driven guard declaration.** The policy YAML should declare
   which WASM guards to load and their config (already planned in doc 09,
   section 5). The upstream `build_async_guards()` pattern of reading
   policy config and instantiating guards is the model.

2. **Placeholder resolution.** `resolve_placeholders_in_json()` substitutes
   `${ENV_VAR}` references in guard config with environment variable
   values. Useful for API keys in threat intel guard configs. Port this
   as a utility in `chio-wasm-guards`.

3. **Package name registry.** The upstream suite maps package name strings to
   guard constructors. Chio should use WASM module paths (from manifest)
   as the registry key, not package names. The manifest already declares
   the module path.

4. **Capability intersection.** The upstream suite intersects requested
   capabilities with granted capabilities before loading a plugin. Chio's
   WASM runtime should do the same: the manifest declares what host
   functions the guard needs; the runtime grants only those.

**What to drop:**

- the upstream `CustomGuardFactory` trait -- Chio uses the WASM ABI
  (`evaluate(ptr, len) -> i32`) instead of dynamic Rust trait objects.
- Async guard trait -- WASM guards in Chio are synchronous (v1 decision,
  doc 05). Async WASM is a v2 concern.

**Concrete changes to `chio-wasm-guards`:**

```rust
// Add to chio-wasm-guards/src/runtime.rs

/// Load guards from policy config.
pub fn load_guards_from_policy(
    &mut self,
    policy: &PolicyConfig,
    manifest_dir: &Path,
) -> Result<Vec<WasmGuardHandle>, WasmGuardError> {
    let mut handles = Vec::new();
    for spec in &policy.custom_guards {
        let module_path = manifest_dir.join(&spec.module);

        // Path traversal protection (from the upstream guard suite)
        let canonical = module_path.canonicalize()
            .map_err(|_| WasmGuardError::PathTraversal)?;
        if !canonical.starts_with(manifest_dir) {
            return Err(WasmGuardError::PathTraversal);
        }

        // Resolve placeholders in config
        let config = resolve_placeholders(spec.config.clone())?;

        // Capability intersection
        let granted_host_fns = intersect_capabilities(
            &spec.requested_capabilities,
            &self.available_host_functions,
        );

        let handle = self.load_module(
            &canonical,
            &spec.name,
            config,
            granted_host_fns,
            spec.fuel_limit.unwrap_or(self.default_fuel),
        )?;
        handles.push(handle);
    }
    Ok(handles)
}
```

---

## 2. Async Guard Runtime: Resilience Patterns for Chio

### 2.1 What the Upstream Suite Has

`async_guards/runtime.rs` is a substantial async orchestration layer:

**`AsyncGuard` trait:**

```rust
trait AsyncGuard: Send + Sync {
    fn name(&self) -> &str;
    fn handles(&self, action: &GuardAction) -> bool;
    fn config(&self) -> &AsyncGuardConfig;
    fn cache_key(&self, action: &GuardAction) -> Option<String>;
    async fn check_uncached(&self, action: &GuardAction, ctx: &AsyncGuardContext) -> AsyncGuardResult;
}
```

**`AsyncGuardConfig`:** timeout, execution mode, cache settings, rate
limiting, circuit breaker, retry config.

**Execution modes:**

| Mode | Behavior |
|------|----------|
| `Sequential` | Guards run in order; fail-fast on first deny |
| `Parallel` | Guards run concurrently; fail-fast on first deny |
| `Background` | Fire-and-forget with semaphore-limited in-flight; dropped if limit exceeded |

**Supporting infrastructure:**

- **CircuitBreaker** -- state machine (Closed -> Open -> HalfOpen) with
  configurable failure/success thresholds and reset timeout. Prevents
  calling a failing external service repeatedly.
- **TokenBucket** -- fractional token rate limiting with burst capacity.
  Best-effort (degrades gracefully, does not hard-deny).
- **RetryConfig** -- exponential backoff with deterministic jitter to
  avoid thundering herd on external API failures.
- **TtlCache** -- per-guard LRU cache for results. Cache keys generated
  from action/context. Avoids redundant external API calls.

### 2.2 Why Chio Needs This

Chio's guards are synchronous (`Guard` trait returns `Result<Verdict>`
without `async`). This is correct for the kernel's core evaluation path --
filesystem, shell, egress, and policy guards should never block on external
I/O.

But the guards being absorbed (threat intel, external ML classifiers,
SpiderSense with remote embedding APIs) DO call external services. Without
resilience patterns, a single external API timeout blocks the entire guard
pipeline.

### 2.3 Design: Optional Async Wrapper, Not Default

Chio should NOT make the core guard trait async. Instead, provide an
optional `AsyncGuardAdapter` that wraps external-calling guards with
The upstream resilience patterns:

```rust
/// Async guard adapter that wraps an external-calling guard with
/// circuit breaking, caching, retry, and timeout.
///
/// Implements the sync `Guard` trait by blocking on the async result
/// with a timeout. If the timeout expires, the circuit breaker trips
/// and subsequent calls fail fast.
pub struct AsyncGuardAdapter<G: ExternalGuard> {
    inner: G,
    config: AsyncGuardConfig,
    circuit_breaker: Mutex<CircuitBreaker>,
    cache: Mutex<TtlCache<String, Verdict>>,
    rate_limiter: Mutex<TokenBucket>,
}

/// Trait for guards that call external services.
/// Separates the async external call from the sync Guard trait.
pub trait ExternalGuard: Send + Sync {
    fn name(&self) -> &str;

    /// Generate a cache key for this evaluation context.
    /// Returns None to skip caching.
    fn cache_key(&self, ctx: &GuardContext) -> Option<String>;

    /// The actual external call. Runs inside the async adapter
    /// with circuit breaker, retry, and timeout protection.
    fn check_external(&self, ctx: &GuardContext) -> Result<Verdict, ExternalGuardError>;
}

impl<G: ExternalGuard> Guard for AsyncGuardAdapter<G> {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> {
        // 1. Check circuit breaker
        {
            let cb = self.circuit_breaker.lock()
                .map_err(|_| KernelError::Internal("lock poisoned".into()))?;
            if cb.is_open() {
                // Circuit open: fail according to config (deny or allow)
                return Ok(self.config.circuit_open_verdict);
            }
        }

        // 2. Check rate limiter
        {
            let mut rl = self.rate_limiter.lock()
                .map_err(|_| KernelError::Internal("lock poisoned".into()))?;
            if !rl.try_acquire() {
                // Rate limited: degrade gracefully
                return Ok(self.config.rate_limited_verdict);
            }
        }

        // 3. Check cache
        if let Some(key) = self.inner.cache_key(ctx) {
            let cache = self.cache.lock()
                .map_err(|_| KernelError::Internal("lock poisoned".into()))?;
            if let Some(cached) = cache.get(&key) {
                return Ok(cached.clone());
            }
        }

        // 4. Call external service with timeout
        let result = self.inner.check_external(ctx);

        // 5. Update circuit breaker and cache
        match &result {
            Ok(verdict) => {
                let mut cb = self.circuit_breaker.lock()
                    .map_err(|_| KernelError::Internal("lock poisoned".into()))?;
                cb.record_success();

                if let Some(key) = self.inner.cache_key(ctx) {
                    let mut cache = self.cache.lock()
                        .map_err(|_| KernelError::Internal("lock poisoned".into()))?;
                    cache.insert(key, verdict.clone(), self.config.cache_ttl);
                }
            }
            Err(_) => {
                let mut cb = self.circuit_breaker.lock()
                    .map_err(|_| KernelError::Internal("lock poisoned".into()))?;
                cb.record_failure();
            }
        }

        result.map_err(|e| KernelError::Internal(format!("external guard: {}", e)))
    }
}
```

### 2.4 Supporting Types (Port from the upstream guard suite)

```rust
/// Circuit breaker state machine.
pub struct CircuitBreaker {
    state: CircuitState,
    failure_count: u32,
    success_count: u32,
    failure_threshold: u32,      // Failures before opening
    success_threshold: u32,      // Successes in half-open before closing
    reset_timeout: Duration,     // Time before half-open retry
    last_failure: Option<Instant>,
}

enum CircuitState {
    Closed,     // Normal operation
    Open,       // Failing, reject fast
    HalfOpen,   // Testing recovery
}

/// Async guard configuration.
pub struct AsyncGuardConfig {
    /// Maximum time to wait for external call.
    pub timeout: Duration,
    /// Verdict to return when circuit is open.
    pub circuit_open_verdict: Verdict,  // Usually Deny (fail-closed)
    /// Verdict to return when rate limited.
    pub rate_limited_verdict: Verdict,  // Usually Allow (best-effort)
    /// Cache TTL for successful evaluations.
    pub cache_ttl: Duration,
    /// Circuit breaker failure threshold.
    pub circuit_failure_threshold: u32,
    /// Circuit breaker reset timeout.
    pub circuit_reset_timeout: Duration,
    /// Rate limit: max calls per second.
    pub rate_limit_per_second: f64,
    /// Rate limit burst capacity.
    pub rate_limit_burst: u32,
    /// Retry config for transient failures.
    pub retry: RetryConfig,
}

/// Retry with exponential backoff and jitter.
pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    /// Deterministic jitter factor (0.0 to 1.0).
    /// Prevents thundering herd on recovery.
    pub jitter_factor: f64,
}
```

### 2.5 Where This Lives

New module in `chio-guards`:

```
crates/chio-guards/src/
  external/
    mod.rs              // ExternalGuard trait, AsyncGuardAdapter
    circuit_breaker.rs  // CircuitBreaker state machine
    token_bucket.rs     // TokenBucket rate limiter (reuse existing velocity.rs?)
    cache.rs            // TtlCache
    retry.rs            // RetryConfig, backoff logic
```

The existing `velocity.rs` already implements a token bucket. Evaluate
whether to reuse it or keep a separate simpler one for the external guard
adapter (the velocity guard's bucket is per-grant with milli-token
precision; the external adapter needs a simpler per-guard bucket).

### 2.6 Execution Modes

The upstream three execution modes map to Chio's pipeline as follows:

| Upstream Mode | Chio Equivalent |
|------------------|----------------|
| Sequential | Default: guards run in `Vec<Box<dyn Guard>>` order |
| Parallel | Future: parallel guard evaluation (requires kernel change) |
| Background | Map to `AdvisoryPipeline` -- non-blocking, results recorded but don't gate the verdict |

For v1, all guards run sequentially (current Chio behavior). Background
mode maps to advisory signals. Parallel mode is a future kernel
optimization.

---

## 3. Threat Intelligence: External API Guards

### 3.1 What the Upstream Suite Has

Four threat intel guards in `async_guards/threat_intel/`:

| Guard | External API | What it checks |
|-------|-------------|----------------|
| `VirusTotalGuard` | VirusTotal v3 | File hashes and URLs against VT database. Configurable `min_detections` threshold. |
| `SafeBrowsingGuard` | Google Safe Browsing v4 | URLs against Google's threat lists (malware, social engineering, unwanted software). |
| `SnykGuard` | Snyk API | Dependency vulnerability scanning. Severity thresholds (Low/Medium/High/Critical). |
| `SpiderSenseGuard` | OpenAI Embeddings API | Behavioral anomaly detection via cosine similarity against pattern database. |

All implement the `AsyncGuard` trait and use:
- `HttpRequestPolicy` for request filtering
- Environment variable placeholder resolution for API keys
- HTTP client from the async runtime

### 3.2 How to Bring This to Chio

Each threat intel guard becomes an `ExternalGuard` implementation wrapped
by `AsyncGuardAdapter`:

```rust
/// VirusTotal threat intelligence guard.
pub struct VirusTotalGuard {
    api_key: String,
    min_detections: u32,
    http_client: HttpClient,
}

impl ExternalGuard for VirusTotalGuard {
    fn name(&self) -> &str { "virustotal" }

    fn cache_key(&self, ctx: &GuardContext) -> Option<String> {
        // Cache by file hash or URL
        extract_hash_or_url(ctx).map(|v| format!("vt:{}", v))
    }

    fn check_external(&self, ctx: &GuardContext) -> Result<Verdict, ExternalGuardError> {
        let target = extract_hash_or_url(ctx)
            .ok_or(ExternalGuardError::NotApplicable)?;

        let response = self.http_client.get(
            &format!("https://www.virustotal.com/api/v3/files/{}", target),
            &[("x-apikey", &self.api_key)],
        )?;

        let detections = parse_detection_count(&response)?;
        if detections >= self.min_detections {
            Ok(Verdict::Deny)
        } else {
            Ok(Verdict::Allow)
        }
    }
}

// Registered in the pipeline:
let vt_guard = AsyncGuardAdapter::new(
    VirusTotalGuard { api_key, min_detections: 3, http_client },
    AsyncGuardConfig {
        timeout: Duration::from_secs(10),
        circuit_open_verdict: Verdict::Allow,  // Degrade gracefully
        cache_ttl: Duration::from_secs(3600),  // Cache VT results for 1 hour
        circuit_failure_threshold: 5,
        ..Default::default()
    },
);
kernel.register_guard(Box::new(vt_guard));
```

### 3.3 Policy-Driven Configuration

Threat intel guards should be declarable in the policy YAML:

```yaml
guards:
  threat_intel:
    virustotal:
      enabled: true
      api_key: "${VIRUSTOTAL_API_KEY}"
      min_detections: 3
      timeout_seconds: 10
      cache_ttl_seconds: 3600

    safe_browsing:
      enabled: true
      api_key: "${GOOGLE_SAFE_BROWSING_KEY}"

    snyk:
      enabled: true
      api_key: "${SNYK_API_KEY}"
      min_severity: high
```

The policy compiler (doc 09) instantiates these as `AsyncGuardAdapter`-
wrapped `ExternalGuard` instances, with placeholder resolution for API
keys.

### 3.4 What to Rewrite vs Port

| Component | Action |
|-----------|--------|
| Guard logic (API calls, response parsing, threshold checks) | Rewrite as `ExternalGuard` implementations using Chio's HTTP client patterns |
| `HttpRequestPolicy` (request filtering) | Port -- useful for restricting what URLs/hashes are sent to external APIs |
| Placeholder resolution (`resolve_placeholders_in_json`) | Port to `chio-wasm-guards` (already planned in section 1.3) |
| API client code (reqwest-based) | Rewrite using Chio's HTTP client (ureq for sync, or minimal async) |
| Detection thresholds and severity mapping | Port directly -- pure logic, no framework dependency |

### 3.5 Package Structure

```
crates/chio-guards/src/
  external/
    mod.rs
    circuit_breaker.rs
    cache.rs
    retry.rs
    threat_intel/
      mod.rs
      virustotal.rs
      safe_browsing.rs
      snyk.rs
```

SpiderSense is NOT in this list -- it is covered in doc 06 as a native
sync guard (embedding comparison is local, not an external API call,
unless using remote embedding APIs).

---

## 4. Broker DPoP: Merge Assessment

### 4.1 What Chio Already Has

`chio-kernel/src/dpop.rs` implements complete DPoP verification:

- `DpopProofBody` -- canonical JSON signable with schema, capability_id,
  tool_server, tool_name, action_hash, nonce, issued_at, agent_key
- `DpopProof` -- body + Ed25519 signature
- `DpopConfig` -- proof TTL (300s), max clock skew (30s), nonce store
  capacity (8192)
- `DpopNonceStore` -- LRU-based replay detector using `(nonce, capability_id)`
- `verify_dpop_proof()` -- 6-step verification: schema check, sender
  constraint, binding fields, freshness, signature, replay detection

### 4.2 What the Upstream Suite Has

The upstream broker-protocol crate defines proof containers:

```rust
enum ProofBindingMode { Loopback, Dpop, Mtls, Spiffe }

struct ProofBinding {
    mode: ProofBindingMode,
    binding_sha256: Option<String>,
    key_thumbprint: Option<String>,
    workload_id: Option<String>,
}

struct BindingProof {
    mode: ProofBindingMode,
    public_key: String,
    signature: String,
    issued_at: u64,
    nonce: String,
}
```

These are used in `BrokerCapability` and `BrokerExecuteRequest` as
optional fields.

### 4.3 Assessment: Nothing to Port

Chio's DPoP implementation is **more complete** than the upstream suite. The
gap is inverted -- the upstream suite has container types but no verification
logic. Chio has full verification with replay detection.

**Action items (small):**

1. **ProofBindingMode enum.** Chio should add `Mtls` and `Spiffe` variants
   to its proof mode if it does not already have them. Chio's `AuthMethod`
   in `chio-http-core/src/identity.rs` already supports mTLS certificates
   and SPIFFE SVIDs, but the DPoP module only knows about DPoP proofs.
   Adding a `ProofBindingMode` enum that unifies DPoP, mTLS, and SPIFFE
   proof types would make the proof model extensible.

2. **Binding hash.** The upstream `binding_sha256` field on
   `ProofBinding` links a capability to its proof binding via hash. Chio's
   `DpopProofBody` already has `capability_id` and `action_hash` which
   serve the same purpose. No change needed.

3. **Key thumbprint.** The upstream `key_thumbprint` field provides a
   compact key identifier. Chio uses the full `agent_key` (hex-encoded
   public key) in the proof body. Adding a thumbprint utility (SHA-256 of
   the public key) would be useful for log correlation but is not blocking.

**Verdict: no port needed.** Chio's DPoP is ahead of the upstream suite. The
broker service itself (where these types are used) stays in the upstream guard suite
as deployment infrastructure.

---

## 5. Summary: Porting Completeness

After this document, the full upstream porting plan is documented:

| Item | Doc | Status |
|------|-----|--------|
| JailbreakGuard | 06 | Covered |
| PromptInjectionGuard | 06 | Covered |
| SpiderSense | 06 | Covered |
| InstructionHierarchyEnforcer | 06 | Covered |
| ComputerUseGuard | 08 | Covered |
| InputInjectionCapabilityGuard | 08 | Covered |
| RemoteDesktopSideChannelGuard | 08 | Covered |
| Output Sanitizer (full) | 07 | Covered |
| Policy engine | 09 | Covered |
| SIEM exporters | 11 | Covered |
| Data layer guards (new) | 10 | Covered |
| Custom guard registry / WASM merge | **12 (this doc, section 1)** | Covered |
| Async guard runtime | **12 (this doc, section 2)** | Covered |
| Threat intelligence | **12 (this doc, section 3)** | Covered |
| Broker DPoP | **12 (this doc, section 4)** | Covered (no port needed) |
| Control API, fleet, RBAC, broker service | N/A | Intentionally excluded |

All 13 absorption items from the porting plan are now documented.
