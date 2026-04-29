# Milestone 06: WASM Guard Platform

WIT host imports, OCI registry, Sigstore verification, hot-reload, and per-guard observability.

## Summary

Milestones v4.0 through v4.2 (closed 2026-04-15) shipped the wasmtime-based WASM guard runtime, the Rust guard SDK, the WIT scaffold, and four guest SDKs. The result is a working sandbox: signed (Ed25519) `.arcguard` bundles distributed as sidecar files, a single exported `evaluate` function, raw host imports wired ad hoc through `Linker::func_wrap`, and synchronous module compilation on every load. M06 turns that sandbox into a platform. It bundles the four highest-leverage WASM follow-on themes (WIT-native host surface, OCI distribution with Sigstore, hot-reload, and per-guard observability) into one milestone because they are mutually reinforcing: a WIT-native surface is the contract that registry artifacts publish against, the registry is what hot-reload pulls from, and the observability layer is what proves a hot swap was safe. None of this is on the critical path for M01 through M05, but it is the precondition for treating guards as a first-class supply-chain artifact.

## Why now

Three signals push this onto the v4.3 slot. First, `wit/chio-guard/world.wit` still pins `chio:guard@0.1.0` with a single `evaluate` export and only a `types` interface; host calls live in `crates/chio-wasm-guards/src/host.rs` as three raw `Linker::func_wrap` registrations (`chio.log` at line 110, `chio.get_config` at line 159, `chio.get_time_unix_secs` at line 221). Four guest SDKs (Rust, TS via jco, Python via componentize-py, Go via tinygo) now consume that raw shape, so every additional host call doubles the migration cost. Second, manifest distribution is sidecar-only: `manifest.rs` resolves a `.wasm` plus a detached `.wasm.sig` Ed25519 signature by path, with no content-addressed pull. Third, `runtime.rs` has only ad hoc `tracing::warn!` and a `last_fuel_consumed` field; there are no spans on `evaluate`, no histograms, and no Prometheus surface. We have the data and no way to read it.

## Phases

### Phase 1: WIT-native host imports and resources

Effort: L (10 working days). Drives a coordinated four-SDK release.

Today's `wit/chio-guard/world.wit` is `chio:guard@0.1.0` with a single `world guard` block exporting `evaluate: func(request: guard-request) -> verdict` and importing only `types`. Phase 1 lands the verbatim 0.2.0 skeleton below. The change is **additive only**: the package version literal becomes `0.2.0`, two new interfaces (`host`, `policy-context`) are added, two new `import` lines land on the `world` block, and the `types` interface is preserved verbatim from 0.1.0. No field is renamed, removed, or retyped, so guest SDKs only need regeneration to pick up the new host imports; existing `verdict`/`guard-request` call sites in guest code keep compiling unchanged.

Verbatim 0.2.0 WIT skeleton (drop-in replacement for `wit/chio-guard/world.wit`):

```wit
package chio:guard@0.2.0;

interface types {
    // Verbatim from on-disk wit/chio-guard/world.wit @ 0.1.0; types are
    // unchanged across the 0.1 -> 0.2 bump. The 0.2 delta is purely additive:
    // new `interface host`, new `interface policy-context`, two `import`
    // lines on the world. No field is renamed, removed, or retyped.
    variant verdict {
        allow,
        deny(string),
    }
    record guard-request {
        tool-name: string,
        server-id: string,
        agent-id: string,
        arguments: string,
        scopes: list<string>,
        action-type: option<string>,
        extracted-path: option<string>,
        extracted-target: option<string>,
        filesystem-roots: list<string>,
        matched-grant-index: option<u32>,
    }
}

interface host {
    log: func(level: u32, msg: string);
    get-config: func(key: string) -> option<string>;
    get-time-unix-secs: func() -> u64;
    fetch-blob: func(handle: u32, offset: u64, len: u32) -> result<list<u8>, string>;
}

interface policy-context {
    resource bundle-handle {
        constructor(id: string);
        read: func(offset: u64, len: u32) -> result<list<u8>, string>;
        close: func();
    }
}

world guard {
    use types.{verdict, guard-request};
    import host;
    import policy-context;
    export evaluate: func(request: guard-request) -> verdict;
}
```

Host interface signature in Rust (post-`bindgen!`):

```rust
#[wasmtime::component::bindgen(world = "chio:guard/guard@0.2.0", async = true)]
mod bindings {}

#[async_trait::async_trait]
impl bindings::chio::guard::host::Host for GuardHost {
    async fn log(&mut self, level: u32, msg: String) -> wasmtime::Result<()> { /* ... */ }
    async fn get_config(&mut self, key: String) -> wasmtime::Result<Option<String>> { /* ... */ }
    async fn get_time_unix_secs(&mut self) -> wasmtime::Result<u64> { /* ... */ }
    async fn fetch_blob(&mut self, handle: u32, offset: u64, len: u32)
        -> wasmtime::Result<Result<Vec<u8>, String>> { /* ... */ }
}
```

The `policy-context::bundle-handle` resource lands as a `wasmtime::component::Resource<BundleHandle>` with the host owning the table. Per M05 coordination (see Cross-doc references), `bindgen!` is invoked with `async = true` from day one and the host-trait bodies are `async fn` even when the in-process implementation is initially synchronous (the body may `await` only `ready()` futures until M05 P1.T3 lands). This avoids a second guest-visible signature change once M05 makes the guard pipeline truly non-blocking.

M10 namespace reservation: Phase 1 commits the placeholder file `wit/chio-guards-redact/world.wit` containing only `package chio:guards@0.1.0;` and a `// reserved for M10; concrete redactor world ships there` comment. M10's `chio:guards/redact@0.1.0` host call is `redact-payload: func(payload: list<u8>, classes: redact-class) -> result<redacted-payload, string>` (where `redact-class` is the WIT `flags` type defined in M10's "Redactor host call shape"); the function slots into this namespace additively. M06 does NOT implement the redactor; it provides the host harness M10 plugs into.

Replace `register_host_functions` in `host.rs` with `wasmtime::component::bindgen!`-generated host wiring; delete `func_wrap` calls at host.rs:110/159/221 and the JSON-serialization shim that compensates for them. Add a manifest field `wit_world: "chio:guard/guard@0.2.0"` and a semver gate that rejects 0.1.x components at load time with a migration-guide pointer.

First commit (Phase 1, Task 1):
- Subject: `feat(wasm-guards): bump WIT world to chio:guard@0.2.0 with host interface and policy-context resource`
- Files touched: `wit/chio-guard/world.wit`, `wit/chio-guards-redact/world.wit` (new placeholder), `crates/chio-wasm-guards/Cargo.toml` (wasmtime feature flags), `docs/guards/MIGRATION-0.1-to-0.2.md` (new).

Phase 1 task breakdown (atomic):

1. **(P1.T1, S, 1d)** Land the 0.2.0 WIT file and the M10 namespace placeholder. Commit subject above.
2. **(P1.T2, M, 2d)** Replace `register_host_functions` in `crates/chio-wasm-guards/src/host.rs` with `bindgen!`-generated host wiring; delete `Linker::func_wrap` calls at host.rs:110/159/221 and the JSON-serialization shim. Commit: `refactor(wasm-guards): replace func_wrap host imports with bindgen!-generated wiring`.
3. **(P1.T3, M, 2d)** Implement the `policy-context::bundle-handle` resource table and the `fetch-blob` host call against the existing content-bundle store. Commit: `feat(wasm-guards): implement policy-context bundle-handle resource and fetch-blob host call`.
4. **(P1.T4, M, 2d)** Add manifest field `wit_world: "chio:guard/guard@0.2.0"` and a semver gate that rejects 0.1.x components at load time with a migration-guide pointer. Commit: `feat(manifest): gate guard load on wit_world semver and emit migration pointer on mismatch`.
5. **(P1.T5, L, 2d)** Guest SDK migration train: single PR atomically bumps Rust 0.1 -> 0.2, regenerates TS via `jco transpile`, regenerates Python via `componentize-py bindings`, regenerates Go via `wit-bindgen-go`. Commit: `feat(guard-sdks): atomically migrate Rust/TS/Python/Go guest SDKs to chio:guard@0.2.0`.
6. **(P1.T6, S, 1d)** Add the M01 conformance fixtures targeting 0.2.0 (`tests/corpora/wit-0.2.0/*.json` exercising `host.fetch-blob` and `bundle-handle`). Commit: `test(conformance): add chio:guard@0.2.0 fixtures for fetch-blob and bundle-handle`.

Guest SDK migration train (single PR, atomic version bump):

| SDK | Package | Caller-visible change |
|-----|---------|-----------------------|
| Rust | `chio-guard-sdk` 0.1 -> 0.2 | `host::log/get_config/get_time` keep signatures; new `host::fetch_blob` and `PolicyContext` resource added. Macro re-exports unchanged. |
| TypeScript | `@chio-protocol/guard-sdk` regenerated via `jco transpile` against 0.2.0 WIT | `host.fetchBlob()` added; existing imports same names. |
| Python | `chio_guard_sdk` regenerated via `componentize-py bindings` | New `host.fetch_blob()`; everything else stable. |
| Go | `chio-guard-sdk-go` regenerated via `wit-bindgen-go` (tinygo target) | New `host.FetchBlob`; package path unchanged. |

Exit criteria: world.wit declares `host` interface, `policy-context` resource, and pins 0.2.0; `chio-wasm-guards` builds with `bindgen!` and zero `func_wrap` host calls; all four guest SDKs publish 0.2.0; the M01 conformance suite passes against 0.2.0 only. M06 owns the additive guard-conformance fixtures; if M01 ships first, M01's conformance harness is the host these fixtures plug into and M06 lands the WIT 0.2.0 fixtures itself.

### Phase 2: Guard registry, OCI distribution, Sigstore

Effort: L (8 working days).

Promote `.arcguard` to a wasm-component OCI artifact (media type `application/vnd.chio.guard.v2+wasm`) with the manifest as a sibling config blob. Use `oci-distribution` (decision 8 in `.planning/trajectory/README.md`; already in the `sigstore-rs` dep tree, so no second registry client). Implement `chio guard publish` and `chio guard pull` in a new `chio-guard-registry` crate, supporting refs like `oci://ghcr.io/chio/tool-gate@sha256:...`.

OCI artifact schema (verbatim, layer order is normative):

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.chio.guard.v2+wasm",
  "config": {
    "mediaType": "application/vnd.chio.guard.config.v2+json",
    "digest": "sha256:<config-blob-sha256>",
    "size": <bytes>
  },
  "layers": [
    {
      "mediaType": "application/vnd.chio.guard.wit.v2",
      "digest": "sha256:<wit-blob-sha256>",
      "size": <bytes>,
      "annotations": {"org.chio.layer.role": "wit"}
    },
    {
      "mediaType": "application/vnd.chio.guard.module.v2+wasm",
      "digest": "sha256:<wasm-blob-sha256>",
      "size": <bytes>,
      "annotations": {"org.chio.layer.role": "wasm"}
    },
    {
      "mediaType": "application/vnd.chio.guard.manifest.v2+json",
      "digest": "sha256:<manifest-blob-sha256>",
      "size": <bytes>,
      "annotations": {"org.chio.layer.role": "manifest"}
    }
  ],
  "annotations": {
    "org.chio.guard.wit_world": "chio:guard/guard@0.2.0",
    "org.chio.guard.signer_subject": "https://github.com/chio-protocol/.github/.../release.yml@refs/tags/v*"
  }
}
```

Layer ordering is normative: `wit` first, `wasm` second, `manifest` third. Pullers verify each layer in order so a tampered WIT (the contract) is rejected before its associated wasm bytes are touched.

Config blob shape (`application/vnd.chio.guard.config.v2+json`):

```json
{
  "schema_version": "chio.guard.config.v2",
  "wit_world": "chio:guard/guard@0.2.0",
  "signer_public_key": "ed25519:<base64>",
  "fuel_limit": 5000000,
  "memory_limit_bytes": 16777216,
  "epoch_id_seed": "<ulid>"
}
```

Cosign verification (every pull, before cache write):

```
cosign verify-blob \
  --bundle ${cache}/<digest>/sigstore-bundle.json \
  --certificate-identity-regexp '^https://github\.com/chio-protocol/.+/\.github/workflows/release\.yml@refs/tags/v.+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ${cache}/<digest>/module.wasm
```

Layer cosign keyless verification on top of the existing Ed25519 envelope: Fulcio cert subject pinned to the regex above, Rekor inclusion proof required, OIDC issuer fixed for release builds (developer builds run the same regex against the public Sigstore staging instance).

Reuse the `chio-attest-verify` crate that lands in M09 (supply-chain attestation) for the Fulcio/Rekor client and trust-root pinning. Do not fork a parallel verifier. M09 Phase 3 fixes the trait surface: M06 calls `AttestVerifier::verify_bundle(artifact, bundle_json, expected)` against the cached `sigstore-bundle.json` for on-disk loads and `AttestVerifier::verify_bytes(artifact, signature, certificate_pem, expected)` for streamed network loads. The `ExpectedIdentity` struct is the single source of truth for the OIDC identity-and-issuer regex; M06 must not duplicate it.

Offline cache layout:

```
${XDG_CACHE_HOME:-~/.cache}/chio/guards/<sha256-digest>/
    manifest.json          # OCI image manifest (verbatim, content-addressed)
    config.json            # chio guard config (wit_world, signer_public_key, ...)
    wit.bin                # raw WIT bytes (layer 1)
    module.wasm            # the component (layer 2)
    sigstore-bundle.json   # Rekor entry + cert chain
```

Failure modes (deny-by-default):

- Network reachable, signature fails -> deny load, structured error.
- Network down, digest cached and verified -> allow (offline mode).
- Network down, digest not cached -> deny.
- Ed25519 valid, Sigstore mismatched (or vice versa) -> deny; do not let one mode mask the other.

First commit (Phase 2, Task 1):
- Subject: `feat(guard-registry): scaffold chio-guard-registry crate with oci-distribution client`
- Files touched: `crates/chio-guard-registry/Cargo.toml` (new), `crates/chio-guard-registry/src/lib.rs` (new), `crates/chio-guard-registry/src/oci.rs` (new), workspace `Cargo.toml`.

Phase 2 task breakdown:

1. **(P2.T1, M, 1.5d)** Scaffold `chio-guard-registry` crate with `oci-distribution` client and credential helper integration. Commit subject above.
2. **(P2.T2, M, 1.5d)** Implement `chio guard publish` with three-layer push (WIT, wasm, manifest in that order) and config blob. Commit: `feat(cli): chio guard publish pushes three-layer OCI artifact with config blob`.
3. **(P2.T3, M, 1.5d)** Implement `chio guard pull` with content-addressed cache write at `${XDG_CACHE_HOME}/chio/guards/<digest>/`. Commit: `feat(cli): chio guard pull resolves and caches OCI artifacts by sha256`.
4. **(P2.T4, M, 2d)** Wire cosign keyless verification through `chio-attest-verify` (M09); reject on Fulcio subject mismatch, missing Rekor proof, or wrong OIDC issuer. Commit: `feat(guard-registry): cosign keyless verify with Fulcio subject and Rekor proof gating`.
5. **(P2.T5, S, 1d)** Implement offline-mode policy: cached-and-verified allow, uncached-and-offline deny, dual-mode mismatch deny. Commit: `feat(guard-registry): fail-closed offline mode and dual-mode signature reconciliation`.
6. **(P2.T6, S, 0.5d)** Integration test against a `testcontainers`-spawned zot registry covering publish, pull, tampered-artifact rejection, wrong-subject rejection, offline cache hit, offline cache miss. Commit: `test(guard-registry): zot integration suite for publish/pull/verify/offline paths`.

Exit criteria: `chio guard publish ./tool-gate` pushes to a local zot registry; `chio guard pull oci://...@sha256:...` resolves through cache; cosign verification rejects a tampered artifact and a wrong-subject cert; offline mode succeeds with the network unplugged when the digest is cached and fails closed when it is not; every load path emits a structured event distinguishing Ed25519-only, Sigstore-only, and dual-verified outcomes.

### Phase 3: Hot-reload and atomic swap

Effort: M (6 working days).

Add `Engine::reload(guard_id, new_module_bytes) -> Result<EpochId>` to the runtime. Reuse the shared `wasmtime::Engine` from `host::create_shared_engine` and back each guard with `arc_swap::ArcSwap<LoadedModule>` (chosen for lock-free reads on the hot path; `evaluate` does a single `load_full()` and never blocks). In-flight calls finish on the old module; new calls land on the new epoch once the swap publishes. Wire two triggers: a `notify`-based file watcher on the guard directory and a registry-poll task keyed by digest.

Canary fixture set (N=32). The corpus is curated by hand, frozen at fixture-commit time, sha256-stamped in `tests/corpora/<guard_id>/canary/MANIFEST.sha256`, and never regenerated programmatically. Representative fixtures:

```
tests/corpora/<guard_id>/canary/
    01_allow_basic.json                    # smallest happy path, allow with no rewrite
    02_allow_with_metadata.json            # allow path that exercises host.get_config
    08_allow_unicode_payload.json          # allow with multibyte UTF-8 in payload
    12_deny_oversize_payload.json          # deny via payload-length policy
    14_deny_disallowed_tool_id.json        # deny via tool-id allowlist
    16_deny_jailbreak.json                 # deny via prompt-injection regex pack
    20_deny_pii_email.json                 # deny via PII regex (email)
    22_rewrite_redact_email.json           # rewrite path: email replaced with [REDACTED]
    24_rewrite_truncate_long_string.json   # rewrite path: payload truncated
    28_fuel_boundary_just_under.json       # allow path that consumes ~95% of fuel limit
    30_fetch_blob_round_trip.json          # exercises policy-context::bundle-handle
    32_allow_with_redact.json              # allow path that emits a redact-class event
    # ... 20 additional fixtures spanning the seven-class deny taxonomy
    MANIFEST.sha256                        # one line per fixture: <sha256>  <filename>
    PROVENANCE.md                          # provenance rules (see below)
```

Provenance rules (encoded in `PROVENANCE.md`):
- Each fixture is hand-curated by the guard author when the guard is first published.
- Fixtures are frozen on commit. A fixture change is a guard major-version bump.
- `MANIFEST.sha256` lists `<sha256>  <filename>` for each fixture; the canary harness verifies the manifest before running.
- The harness rejects a guard whose fixture count != 32 or whose manifest hash does not match.

Canary harness behavior: before flipping the swap, run the 32 fixtures against the new module under the same fuel and memory limits as production. Require byte-identical verdict bytes for all 32 fixtures. Any mismatch aborts the swap and emits `chio.guard.reload.canary_failed`.

Rollback exit conditions (post-swap watchdog): if M >= 5 consecutive evaluations on the new epoch return error-class verdicts (trap, fuel exhaustion, deserialization failure) within a sliding 60s window, atomically swap back to the previous epoch and emit `chio.guard.reload.rolled_back`. Document drain semantics in `docs/guards/15-HOT-RELOAD.md`.

Hot-reload race fix (registry-poll burst). A registry-poll loop and a file-watcher event can both fire for the same `guard_id` within milliseconds. Fix:

- **Per-guard mutex.** Each `guard_id` owns a `tokio::sync::Mutex<ReloadSlot>` keyed in a `DashMap`. Different guards reload concurrently; the same guard serializes.
- **5s debounce window.** A reload request stamps `ReloadSlot::last_attempt_at = Instant::now()`. A subsequent request within 5s collapses into the most recent one and the older request is dropped (last-write-wins on the trigger; the actual swap still uses the freshest module bytes).
- **Monotonic sequence number.** Each accepted reload increments `ReloadSlot::seq: u64`. The post-swap watchdog tags rollback events with `seq`; receipts carry `guard.reload_seq` so a flapping guard is observable in the metric stream.

Deterministic race repro test (`crates/chio-wasm-guards/tests/reload_race.rs`):

```rust
#[tokio::test]
async fn registry_poll_burst_does_not_double_swap() {
    let runtime = test_runtime().await;
    let g = runtime.load_guard("burst-test").await.unwrap();

    // Fire 100 reload requests in a tight loop; debounce must collapse to 1.
    let handles: Vec<_> = (0..100)
        .map(|i| {
            let r = runtime.clone();
            let id = g.id().clone();
            tokio::spawn(async move { r.reload(&id, module_bytes(i)).await })
        })
        .collect();
    for h in handles { let _ = h.await; }

    // Exactly one swap must have completed; seq must be 1.
    assert_eq!(runtime.guard(&g.id()).reload_seq(), 1);
    // Final module bytes must match the LAST (i=99) attempted bytes (last-write-wins).
    assert_eq!(runtime.guard(&g.id()).module_digest(), digest_of(module_bytes(99)));
}
```

The test is deterministic because the debounce window (5s) is dwarfed by the spawn-and-join wall time on CI hardware, and the last-write-wins rule resolves all interleavings to the same final state.

First commit (Phase 3, Task 1):
- Subject: `feat(wasm-guards): add ArcSwap-backed LoadedModule with epoch tracking`
- Files touched: `crates/chio-wasm-guards/src/runtime.rs`, `crates/chio-wasm-guards/src/epoch.rs` (new), `crates/chio-wasm-guards/Cargo.toml` (`arc_swap = "1"`).

Phase 3 task breakdown:

1. **(P3.T1, M, 1d)** Land `ArcSwap<LoadedModule>` and `EpochId` (monotonic u64). Commit subject above.
2. **(P3.T2, M, 1d)** Add `Engine::reload(guard_id, bytes) -> Result<EpochId>`. Commit: `feat(wasm-guards): implement Engine::reload with atomic ArcSwap publish`.
3. **(P3.T3, M, 1d)** Wire `notify`-based file watcher and a `tokio::time::interval` registry-poll task. Commit: `feat(wasm-guards): file-watcher and registry-poll reload triggers`.
4. **(P3.T4, M, 1d)** Implement per-guard `Mutex<ReloadSlot>` + 5s debounce + sequence number. Commit: `feat(wasm-guards): per-guard reload mutex with 5s debounce and monotonic seq`.
5. **(P3.T5, M, 1d)** Implement N=32 canary harness reading `tests/corpora/<guard_id>/canary/` with `MANIFEST.sha256` verification. Commit: `feat(wasm-guards): canary harness for 32-fixture pre-swap verification`.
6. **(P3.T6, S, 0.5d)** Implement post-swap watchdog with `M>=5 errors / 60s` rollback. Commit: `feat(wasm-guards): post-swap watchdog with M>=5/60s rollback to prior epoch`.
7. **(P3.T7, S, 0.5d)** Land the deterministic race-repro test above and a 100rps no-drop test. Commit: `test(wasm-guards): deterministic reload-race repro and 100rps no-drop`.

Exit criteria: a guard swaps under 100 rps load without dropped requests or boundary-inconsistent verdicts; canary failure rolls back without operator intervention; rollback observable in receipts (epoch id pinned per evaluation) and metrics; reload-race test passes deterministically on CI.

### Phase 4: Per-guard observability

Effort: M (4 working days).

Spans (all under the `chio` namespace, OpenTelemetry-compatible). The five span names below are normative; consumers ingest by exact name match.

1. `chio.guard.evaluate` (root). Fields: `guard.id`, `guard.version`, `guard.digest`, `guard.epoch`, `guard.reload_seq`, `verdict`.
2. `chio.guard.host_call`. Fields: `host.name` (one of `log`/`get_config`/`get_time_unix_secs`/`fetch_blob`).
3. `chio.guard.fetch_blob`. Fields: `bundle.id`, `bytes`.
4. `chio.guard.reload`. Fields: `outcome` (one of `applied`/`canary_failed`/`rolled_back`), `reload_seq`.
5. `chio.guard.verify`. Fields: `mode` (one of `ed25519`/`sigstore`/`dual`), `result` (one of `ok`/`fail`).

Prometheus metric families (locked, verbatim names, units in name per `metrics`-crate convention):

| Metric name | Type | Labels | Unit | Buckets |
|-------------|------|--------|------|---------|
| `chio_guard_eval_duration_seconds` | histogram | `guard_id`, `verdict` | seconds | `le = [0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]` |
| `chio_guard_fuel_consumed_total` | counter | `guard_id` | fuel units | n/a |
| `chio_guard_verdict_total` | counter | `guard_id`, `verdict` | count | n/a |
| `chio_guard_deny_total` | counter | `guard_id`, `reason_class` | count | n/a |
| `chio_guard_reload_total` | counter | `guard_id`, `outcome` | count | n/a |
| `chio_guard_host_call_duration_seconds` | histogram | `guard_id`, `host_fn` | seconds | `le = [0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1]` |
| `chio_guard_module_bytes` | gauge | `guard_id`, `epoch` | bytes | n/a |

Label semantics: `guard_id` is the manifest digest prefix (12 chars). `verdict` is `allow`/`deny`/`rewrite`/`error`. `reason_class` is one of seven values: `policy`, `pii`, `secret`, `prompt_injection`, `oversize`, `fuel`, `trap`. `host_fn` mirrors `host.name` from the span (`log`/`get_config`/`get_time_unix_secs`/`fetch_blob`). `outcome` mirrors the `chio.guard.reload` span field (`applied`/`canary_failed`/`rolled_back`). `epoch` is the `EpochId` rendered as a decimal u64.

Cardinality cap: reject guard registration if more than 1024 distinct guards are loaded in one runtime (1024 * |verdict|=4 = 4096 active series for `chio_guard_verdict_total`, well under any reasonable Prom budget). Wire a Prometheus exporter into `chio-kernel`'s existing observability surface.

Grafana dashboard (`docs/guards/dashboards/guard-platform.json`) layout:

- Row 1: deny rate (stacked by `reason_class`), p50/p99 eval latency from `chio_guard_eval_duration_seconds`.
- Row 2: fuel consumption distribution (heatmap), top-10 guards by deny count.
- Row 3: reload outcomes timeline from `chio_guard_reload_total`, host-call latency by `host_fn` from `chio_guard_host_call_duration_seconds`.
- Row 4: verification mode breakdown, module size by epoch from `chio_guard_module_bytes`.

First commit (Phase 4, Task 1):
- Subject: `feat(wasm-guards): emit five-span tree under chio.guard.* namespace`
- Files touched: `crates/chio-wasm-guards/src/runtime.rs`, `crates/chio-wasm-guards/src/observability.rs` (new), `crates/chio-wasm-guards/Cargo.toml` (`tracing`, `tracing-opentelemetry` features).

Phase 4 task breakdown:

1. **(P4.T1, S, 1d)** Emit the five `chio.guard.*` spans with exact field sets. Commit subject above.
2. **(P4.T2, M, 1d)** Register the seven Prometheus metric families with locked names, units, labels, and bucket layouts. Commit: `feat(wasm-guards): register seven Prometheus metric families with locked names and buckets`.
3. **(P4.T3, S, 0.5d)** Cardinality cap: refuse 1025th guard registration with structured error. Commit: `feat(wasm-guards): enforce 1024-guard cardinality cap on metrics registration`.
4. **(P4.T4, S, 0.5d)** Wire the Prometheus exporter into `chio-kernel`'s observability surface. Commit: `feat(kernel): expose guard metrics on /metrics endpoint via existing exporter`.
5. **(P4.T5, M, 1d)** Commit `docs/guards/dashboards/guard-platform.json` Grafana dashboard. Commit: `docs(guards): Grafana dashboard for guard platform with four-row layout`.

Exit criteria: every receipt-bearing evaluation produces a five-span tree; Prometheus scrape returns all seven metric families with the exact names above; dashboard renders against a recorded fixture; `cargo test --workspace --features metrics` passes.

## Rollback storyboard (post-incident runbook)

Scenario: Guard `tool-gate@1.4.0` ships, the watchdog observes M=5 error-class verdicts within 60s on the new epoch, the kernel auto-rolls back to N-1 (the prior epoch). The runbook then is:

1. **Alert routing.** The `chio_guard_reload_total{outcome="rolled_back"}` counter increment fires a Prometheus alert (`ChioGuardAutoRollback`) routed to PagerDuty service `chio-runtime`. Severity `S2`. Alert body includes `guard_id`, `reload_seq`, prior `epoch`, new (rolled-back-from) `epoch`, and a Tempo deep-link to the `chio.guard.reload` span tree.
2. **Operator triage (15 minutes).** On-call confirms via `chio guard status <guard_id>`: current epoch, last-five evaluations and their error classes, sigstore verification mode, OCI digest. Operator does NOT manually re-promote; auto-rollback is authoritative.
3. **Root-cause directory.** Each rollback writes `${XDG_STATE_HOME:-~/.local/state}/chio/incidents/<utc-iso8601>-<guard_id>-<reload_seq>/` containing: `event.json` (the rollback event), `failed_module.wasm` (the new module bytes that were rolled back), `failed_module.manifest.json`, `last_5_eval_traces.ndjson` (one frame per failing evaluation, fully redacted via the M06 redactor), and `prior_epoch_module.sha256` (digest only; the prior wasm is still in the cache).
4. **Post-mortem template.** A blank `POST_MORTEM.md` lands in the incident directory with sections: *Trigger*, *Detection latency* (alert fire to operator ack), *Root cause class* (one of: WIT contract drift, fuel-limit regression, PII regex over-match, host-call signature mismatch, supply-chain artifact mismatch), *Fix* (link to PR), *Prevention* (which canary fixture would have caught this; if none, what new fixture is added).
5. **Re-promotion path.** A fixed guard ships with a bumped patch version and a new OCI digest; the canary corpus must include a regression fixture covering the failed class. The kernel refuses to re-promote a digest that already triggered a rollback (digest blocklist persisted in `${XDG_STATE_HOME}/chio/guards/blocklist.json`); only a strictly newer digest can promote.
6. **Telemetry SLO.** Auto-rollback is expected to be silent in steady state. A rate of more than one `outcome="rolled_back"` per guard per 30 days is a release-engineering alert (`ChioGuardRollbackChurn`, S3) that tracks supply-chain hygiene rather than runtime correctness.

## NEW sub-tasks (Round-2 additions, M06-scope)

The three tasks below are net-new from Round 2 and not in the original phase breakdown. The `(NEW)` tag is retained inline so the diff reviewer can find them.

- **(NEW) Canary fixture provenance harness.** Add `crates/chio-wasm-guards/tests/canary_provenance.rs` that walks `tests/corpora/*/canary/MANIFEST.sha256`, recomputes each fixture sha256, and rejects any drift. Wired into the default `cargo test --workspace` lane so an accidental fixture edit fails CI.
- **(NEW) Rollback incident directory writer.** Implement the `${XDG_STATE_HOME}/chio/incidents/.../` writer described in the storyboard, with the redactor applied to `last_5_eval_traces.ndjson` before write. Lives in `crates/chio-wasm-guards/src/incident.rs`.
- **(NEW) Digest blocklist enforcement.** Persistent `blocklist.json` of guard digests that previously triggered an auto-rollback; `chio guard pull` and `Engine::reload` both consult it and refuse with structured error code `E_GUARD_DIGEST_BLOCKLISTED`. Lives in `crates/chio-wasm-guards/src/blocklist.rs` with a CLI escape hatch `chio guard blocklist remove <digest>` (control-plane capability gated).

## End-to-end integration test (phase boundary)

`tests/integration/guard_platform_e2e.rs` MUST pass before M06 closes. Single test exercises: build a guard against `chio:guard@0.2.0`, `chio guard publish` to a zot registry running in a `testcontainers` container, pull it through the cache on a second runtime instance, verify both Ed25519 and Sigstore signatures (Fulcio against the staging trust root), hot-swap it under 100 rps load with 32 canary fixtures, attempt a follow-up swap that fails canary and assert rollback to the prior epoch, then assert Prometheus exposes non-zero values for all seven metric families and that emitted receipts carry the `guard.epoch` field.

Pass criteria: zero dropped requests during swap, byte-identical verdicts on canary corpus, rolled-back epoch matches pre-swap epoch id, all metric families present with sensible bounds (p99 latency < 50ms on CI hardware, fuel counter monotonic), receipts validate against the existing receipt schema.

## Risks

- **wasmtime minor-version churn**: `bindgen!` output and the component-model API have shifted in 25.x and 26.x. Pin `wasmtime` exactly in `Cargo.toml` and add a CI job that bumps weekly to surface drift early.
- **OCI 1.1 feature evolution**: artifact references and subject fields keep evolving. Target OCI 1.0 image-spec for the manifest format with a 1.1 referrers fallback when the registry advertises it.
- **Sigstore bundle format**: `sigstore-rs` is pre-1.0 and the bundle JSON has changed. Pin the bundle schema version in `chio-attest-verify` and version-gate manifests.
- **Guest SDK toolchain drift**: jco, componentize-py, and tinygo each track wit-bindgen at their own pace. Lock all four toolchains to a known-good wit-bindgen release in `tools/versions.toml` and gate SDK CI on it.
- **Hot-reload race during registry-poll burst**: serialize per `guard_id` (mutex above), and add a debounce window (default 5s) on the file watcher so editor save-storms do not produce a reload chain.
- **Observability cardinality blowup**: enforce the 1024-guard cap and the 12-char digest prefix; add a Prometheus relabel rule example in the docs that drops `guard` if cardinality limits are tight.

## Cross-doc references

- **M09 supply-chain attestation** lands the `chio-attest-verify` crate (Fulcio/Rekor client, trust-root pinning). M06 Phase 2 MUST consume it; do not fork a parallel verifier.
- **M05 async kernel** changes host-call semantics from sync to async-await. Phase 1 host wiring MUST model host calls as `async fn` from day one in the WIT-derived host trait (see M05 Round-2 addenda, "Coordination with M06"), even if the in-process body is initially synchronous; this avoids a second migration when M05's guard-pipeline async surface lands. Reciprocally, M05 Phase 1 must not alter the input/output payload shape of the three current host calls (`chio.log` host.rs:110, `chio.get_config` host.rs:159, `chio.get_time_unix_secs` host.rs:221) while M06 Phase 1's `bindgen!` migration is in flight; payload bytes are part of the cross-milestone contract. If both milestones run in parallel, M06 Phase 1 blocks on M05's P1.T3 commit landing first so `bindgen!` targets the async-native host trait directly.
- **M01 conformance suite** is the harness host. M06 Phase 1 MUST add guard-side fixtures targeting `chio:guard@0.2.0` and exercising `host.fetch-blob` and `policy-context`. If M06 ships before M01 stabilizes the suite-publishing flow, the fixtures land in `crates/chio-conformance/` directly and migrate later. Coordinate with M01's Phase 4 (conformance suite packaging) so the fixtures are included in the published crate's `include` list.
- **M10 redactor host call.** M10's `chio-tee` invokes the WASM guard pipeline through a `redact` policy class. M06 Phase 1 reserves the `chio:guards/redact@0.1.0` interface namespace alongside `chio:guard@0.2.0` by committing `wit/chio-guards-redact/world.wit` containing only `package chio:guards@0.1.0;` plus a `// reserved for M10` comment. The concrete redactor world ships in M10 (see M10 Section "Redactor host call shape"); the normative host-imported function is `redact-payload: func(payload: list<u8>, classes: redact-class) -> result<redacted-payload, string>` inside `interface redact { ... }`, with `world redactor { import redact; }`. M06 does not implement redactors itself; it provides the namespace placeholder and the host harness M10 plugs into.

## Dependencies

Builds directly on v4.0 through v4.2. Phase 2 reuses M09's Sigstore tooling. Phase 1 should anticipate M05's async host-call shape. Independent of M02 through M04.

## Out of scope

Multi-tenant registry policy (deferred to M11), policy-context resources beyond content-bundle reads (M07), and cross-runtime guard portability (M12).
