# Milestone 08: Browser/Edge WASM SDK (`@chio-protocol/browser` + Cloudflare Workers + Vercel Edge)

Owner: SDK / runtime track. Status: planned. Anchors: `RELEASE_AUDIT`, `QUALIFICATION`, `BOUNDED_OPERATIONAL_PROFILE`, `spec/PROTOCOL.md`, M01 conformance corpus.

## Goal

Ship `@chio-protocol/browser`, a verify-side TypeScript/WASM SDK under 300 KB gzipped that lets any JavaScript runtime parse and verify Chio receipts and capability tokens with no sidecar. Wire that same WASM artifact into Cloudflare Workers, Vercel Edge, and Deno Deploy build matrices so "trust kernel that runs anywhere" stops being prose and starts being a published package any consumer can `npm i` and run in a browser tab, an edge function, or a Durable Object.

## Why now

The repo already contains the load-bearing piece: `crates/chio-kernel-browser/` is a `no_std + alloc` `wasm-bindgen` facade over `chio-kernel-core` with `BrowserClock`, `WebCryptoRng`, and three exported entry points (`evaluate`, `sign_receipt`, `verify_capability`) plus a fresh-seed minter. `crates/chio-kernel-browser/examples/demo.html` (with the companion `demo.js`) and `crates/chio-kernel-browser/tests/wasm_bindings.rs` (gated on `wasm-bindgen-test = "0.3"`) already drive the artifact end to end, and the README documents a wasm-pack flow producing a ~0.45 MB stripped `chio_kernel_browser_bg.wasm`. Nothing in `sdks/typescript/` consumes it. The TS surface ships six standalone packages under `sdks/typescript/packages/` (`node-http`, `ai-sdk`, `express`, `fastify`, `elysia`, `conformance`) all targeting Node/Bun via tsc + vitest with `file:` cross-deps; there is no top-level workspace `package.json`, no browser bundle, no Workers entrypoint, no Vercel Edge target, no Deno target, no Hono adapter, no published `@chio-protocol/browser` package, and no wasm-pack invocation in `sdks/typescript/scripts/` (only `package-check.sh` lives there today). The killer demo (a static page that verifies a real M04 receipt fixture against trusted issuer keys with no server round trip) is a few hundred TS lines plus a build-matrix entry away. Without it, the "verify anywhere" claim is hollow and every JS-runtime ecosystem (Workers, Edge, Deno, Bun-native) re-implements receipt parsing by hand.

## In scope

- A new TS package `sdks/typescript/packages/browser/` (`@chio-protocol/browser`) that re-exports a browser-friendly subset of the `chio-kernel-browser` wasm-bindgen surface: `verifyReceipt`, `parseReceipt`, `parseCapabilityToken`, plus a typed `BindingError` shape mirroring the Rust crate.
- Per-runtime wasm tooling, picked explicitly:
  - Browser (`@chio-protocol/browser`): `wasm-pack build --target web` producing ESM that fetch+instantiates the `.wasm`. Output staged under `dist/web/`.
  - Cloudflare Workers (`@chio-protocol/workers`): `wasm-pack build --target bundler` plus a workerd-compatible `import wasmModule from "./chio_kernel_browser_bg.wasm"` (no `nodejs_compat` required). Future Component-Model path noted as a follow-up via `jco transpile`.
  - Vercel Edge (`@chio-protocol/edge`): `wasm-pack build --target web` consumed as an Edge Function with `export const config = { runtime: "edge" }`.
  - Deno Deploy (`@chio-protocol/deno`): primary path is `wasm-pack --target web` with `import.meta.url` for the wasm; `jco`-generated Component bindings tracked as the convergent path once `jco` ships stable Deno targets.
  - Bun: shares the `--target bundler` artifact with Node-ish glue; a Phase 3 Bun-native variant skips wasm-pack JS glue and uses `Bun.file().arrayBuffer()` directly.
- A build script `sdks/typescript/scripts/build-wasm.sh` invoked from each package's `npm run build` that regenerates the wasm artifact and stages outputs under `<package>/dist/`. The script pins `wasm-pack` and `wasm-bindgen-cli` versions in `rust-toolchain.toml`-adjacent metadata to defend against wasm-bindgen drift.
- Per-runtime size budgets enforced in CI by `sdks/typescript/scripts/size-budget.sh` and recorded in `sdks/typescript/scripts/size-budget.json`:
  - `@chio-protocol/browser`: < 300 KB gzipped (target), <= 450 KB stripped wasm baseline.
  - `@chio-protocol/workers`: < 1 MB compressed total worker bundle (Cloudflare hard limit on free + paid is 3 MB compressed; we hold ourselves to 1 MB to leave headroom for user code), < 350 KB gzipped for the SDK contribution alone.
  - `@chio-protocol/edge`: < 1 MB compressed Edge Function bundle (Vercel limit is 1 MB compressed for Edge), < 350 KB gzipped for the SDK contribution alone.
  - `@chio-protocol/deno`: < 400 KB gzipped (Deno Deploy isolate limit is 50 MB but cold-start scales with size).
- A demo page checked in under `docs/demo/` (GitHub Pages root, locked) that verifies a real receipt fixture from the M04 replay corpus (`tests/replay/fixtures/`) against trusted issuer keys, surfaces the verdict and signing key in the DOM, includes an engineering-output banner, and is deployable as a static artifact.
- CI build matrix covering `wasm32-unknown-unknown` build, `wasm-pack --target web`, `--target bundler`, `--target nodejs`, plus runtime smoke tests on Workers (Miniflare/workerd), Edge (`@vercel/edge` runtime simulator), and Deno (`deno test`).
- Conformance subset (M01 scenarios that do not require a full kernel: receipt verify, capability verify, canonical-JSON byte equivalence) wired so each runtime target executes the same vector corpus and gates CI on byte-for-byte agreement with the Rust oracle. The exact subset is enumerated in `sdks/typescript/packages/conformance/src/browser-subset.ts` and referenced from M01's conformance manifest so the corpus stays single-sourced.

## Out of scope

- Full kernel-in-browser. The browser is verify-side only; agent-side evaluation, guard execution, and tool-server orchestration remain server side.
- Browser-side signing of root capabilities. **Hard prohibition**, not just "not yet": root capability authorities and root signing keys MUST NEVER live in a browser, Worker, Edge function, or any user-reachable JS runtime. Phase 3 considers delegated subkey signing only, gated on a documented trust-boundary review and provenance chain back to a server-side root.
- Guard execution in the browser. WASM guards (`chio-wasm-guards`) are M06 territory and stay there; M08 explicitly carves out the receipt/capability verify subset of the kernel surface and inherits no guard-execution path. If guard verification ever runs in-browser it slots in behind a Phase 4 gate with its own threat model.
- Bundling the wasm artifact for native React Native or iOS WebView; mobile is `crates/chio-kernel-mobile`'s milestone.
- Browser-side TEE attestation capture (M10 territory).
- Republishing the existing `@chio-protocol/*` Node/Bun packages under a new namespace. The browser/edge surface ships under fresh package names; the existing packages are unaffected.

## Success criteria (measurable)

- `@chio-protocol/browser` published to npm under the existing `@chio-protocol` org with semver, exporting `verifyReceipt`, `parseReceipt`, `parseCapabilityToken` and TypeScript `.d.ts` declarations generated from `chio_kernel_browser.d.ts`.
- Gzipped tarball size of `@chio-protocol/browser` < 300 KB measured by a CI script (`scripts/size-budget.sh`); regression fails the build.
- Demo page (engineering output, not a release artifact) deployed at a stable URL, loading a real M04 receipt fixture and rendering verdict, signing key, and elapsed `verifyReceipt` time in < 5 ms on baseline Apple Silicon.
- Four runtime targets pass the M01 conformance subset against the same vector corpus: browser (`@chio-protocol/browser`), Cloudflare Workers (`@chio-protocol/workers`), Vercel Edge (`@chio-protocol/edge`), Deno Deploy (`@chio-protocol/deno`). Subset includes `tests/bindings/vectors/{canonical,receipt,capability}/v1.json`.
- CI size-budget gate green; CI conformance-bytes gate green; the browser path is added to `formal/diff-tests/` as an additional differential target for canonical-JSON byte equivalence (M01 dependency).

## Phase breakdown

### Phase 1: `@chio-protocol/browser` (verify-only)

Sub-goal: package the existing wasm-bindgen artifact as a publishable npm module with a verify-only TS surface and prove the demo path.

Effort: **L, ~7-9 days**.

First commit (exact):

- Message: `feat(browser-sdk): scaffold @chio-protocol/browser verify-only package`
- Touches:
  - `sdks/typescript/packages/browser/package.json` (name `@chio-protocol/browser`, `engines`, `exports` map)
  - `sdks/typescript/packages/browser/tsconfig.json`
  - `sdks/typescript/packages/browser/src/index.ts` (re-export stubs for `verifyReceipt`, `parseReceipt`, `parseCapabilityToken`)
  - `sdks/typescript/scripts/build-wasm.sh` (initial wasm-pack invocation)

Atomic tasks (5):

1. Add `crates/chio-kernel-browser/src/lib.rs` `verify_receipt(envelope: &[u8], trusted_issuers: &JsValue) -> Result<JsValue, BindingError>` wasm-bindgen entry plus a `wasm-bindgen-test` covering the M04 fixture. Effort: M, 2 days.
2. Land `sdks/typescript/scripts/build-wasm.sh` invoking `wasm-pack build --target web --out-dir sdks/typescript/packages/browser/dist/web` with pinned `wasm-pack` and `wasm-bindgen-cli` versions read from `rust-toolchain.toml`-adjacent metadata. Effort: S, 1 day.
3. Author `sdks/typescript/packages/browser/src/index.ts` thin TS wrappers; re-export the wasm-pack-emitted `chio_kernel_browser.d.ts` types as the canonical surface. Effort: M, 2 days.
4. Land `sdks/typescript/scripts/size-budget.sh` plus `sdks/typescript/scripts/size-budget.json` recording the four per-runtime budgets; wire into `npm run build` post-step. Effort: S, 1 day.
5. Author `docs/demo/index.html` and `docs/demo/main.ts` consuming `tests/replay/fixtures/<stable-public-fixture>.json`; render verdict, signing key, elapsed time; include the engineering-output banner (see Demo path lock below). Effort: M, 2 days.

Exit: `bun run build` regenerates the wasm artifact, `bun run test` runs the demo headless via Playwright, gzipped output < 300 KB, demo verifies a fixture in < 5 ms.

### Phase 2: Edge runtime targets

Sub-goal: publish `@chio-protocol/workers`, `@chio-protocol/edge`, `@chio-protocol/deno` and prove conformance subset on each.

Effort: **L, ~10-12 days**.

First commit (exact):

- Message: `feat(workers-sdk): scaffold @chio-protocol/workers with bundler wasm import`
- Touches:
  - `sdks/typescript/packages/workers/package.json`
  - `sdks/typescript/packages/workers/src/index.ts`
  - `sdks/typescript/packages/workers/wrangler.toml` (smoke-test fixture only, no `nodejs_compat`)
  - `sdks/typescript/scripts/build-wasm.sh` (extend with `--target bundler` invocation)

Atomic tasks (7):

1. Extend `sdks/typescript/scripts/build-wasm.sh` to emit per-runtime artifacts (`web`, `bundler`, `nodejs`) into per-package `dist/` subdirs. Effort: S, 1 day.
2. Author `sdks/typescript/packages/workers/` with `WebAssembly.instantiate` against a bundler-imported `.wasm`, no `nodejs_compat`. Effort: M, 2 days.
3. Author `sdks/typescript/packages/edge/` with `export const config = { runtime: "edge" }` and `wasm-pack --target web` artifact. Effort: M, 2 days.
4. Author `sdks/typescript/packages/deno/` consuming `import.meta.url`-resolved `.wasm`. Effort: M, 2 days.
5. Land `sdks/typescript/packages/conformance/src/browser-subset.ts` enumerating the conformance subset (see Conformance subset definition below). Effort: S, 1 day.
6. Wire the GitHub Actions matrix (see Per-runtime CI matrix below) to invoke conformance-subset against each runtime via Miniflare (Workers), `@vercel/edge` simulator (Edge), and `deno test` (Deno). Effort: M, 2 days.
7. Land `formal/diff-tests/tests/browser_canonical_json_diff.rs` (see Browser-runtime differential test below). Effort: M, 2 days.

Exit: all four runtimes return identical bytes for every vector in the conformance subset; size-budget gate green per target; CI matrix is the gating job for any change under `crates/chio-kernel-browser/` or `sdks/typescript/packages/{browser,workers,edge,deno}/`.

### Phase 3: Sign + capability minting (HARD-DEFERRED, gated by trust-boundary review)

Sub-goal: extend the surface beyond verify-only **only if** a written trust-boundary review approves a delegated-subkey model. Default posture for v1 is "out of scope, ship verify-only and revisit"; Phase 3 MUST NOT block M08 closeout. M08 ships at Phase 2.

Effort (only if review approves): **L, ~10-14 days**. Effort if rejected: **S, 1 day** to write the rationale-recorded note.

First commit (exact, gated):

- This commit MUST NOT land before `docs/trust-boundary-browser-signing.md` is checked in and approved by the security owner of record.
- Message: `feat(browser-sdk): add delegated-subkey signRequest behind trust-boundary review`
- Touches:
  - `crates/chio-kernel-browser/src/lib.rs` (new `sign_request_with_subkey` wasm-bindgen entry; `signRoot` MUST NOT be added)
  - `sdks/typescript/packages/browser/src/sign.ts` (new file; gated under an explicit `experimental` export)
  - `formal/diff-tests/tests/browser_delegated_subkey_diff.rs` (proptest invariants on the delegation chain)

Hard requirements before any browser-side signing ships:

- A `docs/trust-boundary-browser-signing.md` review (template inline below) covering attacker model (XSS, malicious extension, supply-chain), key-material lifecycle (subkey provisioning, scope, expiry, revocation), and provenance chain rooted in a server-side authority.
- Delegated subkeys MUST be scope-narrowed (single-purpose, time-bounded, audience-bound), MUST be re-issued by a server-side authority, and MUST carry an explicit `delegation` chain in the capability they sign.
- Root capability signing remains forbidden in the browser; a `signRoot` entry point is not added even behind a feature flag.

Trust-boundary review document (template, inline; this is the file to land at `docs/trust-boundary-browser-signing.md`):

```
# Trust-boundary review: browser-side delegated subkey signing

Status: [draft | approved | rejected]
Approver: [security owner of record]
Date: [YYYY-MM-DD]

## 1. Scope of delegated subkeys
- Audience binding: which audiences may a browser-resident subkey sign for?
- Time bounds: maximum subkey lifetime; refresh cadence.
- Scope narrowing: which capability scopes are permitted; which are forbidden (root, mint, delegate).
- Quantitative limits: per-session signing budget, per-minute rate, per-origin cap.

## 2. Signer provenance
- Server-side authority that issues the subkey.
- Provisioning channel (TLS-pinned fetch, signed bootstrap envelope, etc).
- Delegation chain shape: how the receipt encodes [root -> intermediate -> browser-subkey].
- Verification path: how a verifier confirms a browser-signed receipt traces back to a server-side root.

## 3. Revocation surface
- Revocation list distribution channel.
- Maximum staleness tolerated by verifiers.
- Subkey-leak response runbook.
- Audit trail: where revocations are logged and how they are signed.

## 4. Threat model
- XSS: what an attacker who runs JS in the page can sign for.
- Malicious browser extension: capability boundary against extension-injected JS.
- Supply-chain compromise of `@chio-protocol/browser`: blast radius and recovery.
- Stolen subkey replayed from a non-browser context.
- Compromised CA / TLS-MITM during subkey provisioning.

## 5. Decision
- [ ] Approved. Phase 3 may proceed with the constraints above.
- [ ] Rejected. M08 ships at Phase 2; this document records rationale.
```

Phase 3 is gated by this document's approval signature. Without an `Approved` checkbox and an approver name, the Phase 3 first commit must not land.

Atomic tasks (only if approved) (5):

1. Author `docs/trust-boundary-browser-signing.md` from the template above; secure approver signoff. Effort: M, 2 days.
2. Add `sign_request_with_subkey` wasm-bindgen entry in `crates/chio-kernel-browser/src/lib.rs`; no `signRoot`. Effort: M, 3 days.
3. Author `sdks/typescript/packages/browser/src/sign.ts` exposing `signRequestWithDelegatedSubkey`; export under `experimental` only. Effort: M, 2 days.
4. Land `formal/diff-tests/tests/browser_delegated_subkey_diff.rs` proptest invariants (delegation-chain integrity, audience-mismatch reject, expired-subkey reject, missing-delegation reject). Effort: M, 3 days.
5. Land `chio-receipt-stream` single-receipt incremental parser passing the M04 fixture subset (full chunked replay deferred). Effort: M, 3 days.

Exit: trust-boundary review checked in and approved; delegated subkey provenance has a property-based differential test in `formal/diff-tests/`; stream parser passes the M04 fixture corpus subset; if the review rejects browser signing, Phase 3 closes with a "not pursued, rationale recorded" note and the milestone ships at Phase 2.

## Dependencies

- **M01 conformance suite** supplies the vector corpus this milestone ships against. M01 must explicitly publish the "browser-runnable subset" (receipt verify, capability verify, canonical-JSON byte equivalence) as a named manifest so this milestone consumes a versioned subset rather than a hand-picked sample. The browser path is added as an additional differential target for canonical-JSON byte equivalence.
- **M04 receipt fixtures** under `tests/replay/fixtures/` power the demo page and the stream-parser tests if Phase 3 proceeds. M04 must keep at least one stable, public-key-only fixture in the corpus that does not embed sensitive issuer state, since the demo page is loaded from a static origin.
- **M06 (WASM guards)** is explicitly out of scope. WASM guards do NOT run in the browser kernel; the browser surface stops at receipt and capability verification. This boundary is normative: anyone wiring guard execution into the browser bundle must open a new milestone with its own threat model.
- **M10 (TEE / browser-side capture)** is out of scope here. Browser-side TEE attestation, if it ever exists, is M10's problem.
- `crates/chio-kernel-browser/` is the wasm source of truth. Any signature change there ripples into all four runtime adapters; CI gates regen of `chio_kernel_browser.d.ts` with `git diff --exit-code`.

## Risks and mitigations

- **WASM size constraints**: mitigated by `wasm-opt -Oz`, dead-code elimination through `chio-kernel-core` `default-features = false`, and per-target tree-shaking. The < 300 KB gzipped browser budget is below the current ~0.45 MB stripped wasm baseline; enforcement may force a `serde-wasm-bindgen` replacement or a leaner JSON path.
- **WebCryptoRng entropy availability**: legacy embedded webviews and a few enterprise managed browsers still ship without `crypto.subtle.getRandomValues`. `WebCryptoRng` is fail-closed (zero-seed refusal already lands `weak_entropy`) and the module gates on `crypto.subtle` at load. Older Edge runtimes without `crypto.subtle` are explicitly unsupported. CI records the minimum supported browser/runtime matrix.
- **Workers CPU budget**: free-tier Workers is bounded at 10 ms wall-clock per request and paid tiers at 30 s but with sub-50 ms targets typical; cold-start instantiation of a 0.45 MB wasm can blow the budget. Mitigated by caching the instantiated `WebAssembly.Module` at the global scope (Workers re-uses the global between requests), avoiding the `serde-wasm-bindgen` JSON path on Workers (raw `Uint8Array` + `TextDecoder`), and recording p50/p99 verify latency on Workers in CI as a gating metric.
- **Vercel Edge cold-start**: large wasm modules slow cold-start on Edge. Mitigated by per-runtime budget (< 1 MB compressed bundle), inlined wasm import to skip a second fetch, and a CI gate that fails if instantiate-to-first-verify exceeds a budget.
- **TC39 ESM wasm-import status**: the `import wasmModule from "./foo.wasm"` syntax is still in flight (Stage 3 source-phase imports / wasm-import). Mitigated by shipping both `wasm-pack --target web` (fetch + instantiate) and `--target bundler` (bundler-mediated import) artifacts and selecting per-runtime; the `@chio-protocol/edge` and `@chio-protocol/workers` packages document the bundler path as authoritative for v1.
- **wasm-bindgen version drift**: `wasm-bindgen` library and `wasm-bindgen-cli` MUST match exactly or runtime crashes appear. Mitigated by pinning both in workspace metadata, publishing the pinned version in `sdks/typescript/scripts/build-wasm.sh`, and adding a CI check that fails on drift.
- **CF Workers `nodejs_compat` polyfill cost**: enabling `nodejs_compat` adds substantial compatibility-layer weight and can violate the size budget. Mitigated by NOT enabling `nodejs_compat` on `@chio-protocol/workers`; the bindings stay on Web-platform primitives only (`crypto.subtle`, `TextDecoder`, `WebAssembly`). Documented as a hard constraint.
- **Workers runtime restrictions**: no `Date.now()` drift attacks because Workers freezes time during a request; no eval; CPU budget tight (see above). Verify-only surface is well-suited.
- **Drift between Rust wire types and TS surface**: mitigated by generating the TS declarations from `chio_kernel_browser.d.ts` (wasm-pack output) rather than hand-typing, gating CI on `git diff --exit-code` after regen.

## Per-runtime CI matrix (verbatim)

The full GitHub Actions workflow lives at `.github/workflows/web-sdk.yml`. Drop this file in verbatim:

```yaml
name: web-sdk

on:
  push:
    branches: [main]
    paths:
      - 'crates/chio-kernel-browser/**'
      - 'sdks/typescript/packages/browser/**'
      - 'sdks/typescript/packages/workers/**'
      - 'sdks/typescript/packages/edge/**'
      - 'sdks/typescript/packages/deno/**'
      - 'sdks/typescript/packages/conformance/**'
      - 'sdks/typescript/scripts/build-wasm.sh'
      - 'sdks/typescript/scripts/size-budget.sh'
      - 'sdks/typescript/scripts/size-budget.json'
      - '.github/workflows/web-sdk.yml'
  pull_request:
    paths:
      - 'crates/chio-kernel-browser/**'
      - 'sdks/typescript/packages/{browser,workers,edge,deno,conformance}/**'
      - '.github/workflows/web-sdk.yml'

jobs:
  build-wasm:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: wasm32-unknown-unknown
      - name: Install wasm-pack (pinned)
        run: cargo install wasm-pack --version "$(cat .tooling/wasm-pack.version)" --locked
      - name: Install wasm-bindgen-cli (pinned, must match wasm-bindgen lib version)
        run: cargo install wasm-bindgen-cli --version "$(cat .tooling/wasm-bindgen.version)" --locked
      - name: Build all wasm targets
        run: bash sdks/typescript/scripts/build-wasm.sh
      - uses: actions/upload-artifact@v4
        with:
          name: wasm-artifacts
          path: sdks/typescript/packages/{browser,workers,edge,deno}/dist/

  conformance:
    needs: build-wasm
    strategy:
      fail-fast: false
      matrix:
        target:
          - browser
          - workers
          - edge
          - deno
        include:
          - target: browser
            runner: playwright
            budget_kb: 300
          - target: workers
            runner: miniflare
            budget_kb: 350
          - target: edge
            runner: vercel-edge-sim
            budget_kb: 350
          - target: deno
            runner: deno-test
            budget_kb: 400
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/download-artifact@v4
        with:
          name: wasm-artifacts
          path: sdks/typescript/packages/
      - uses: oven-sh/setup-bun@v2
      - uses: denoland/setup-deno@v2
      - name: Install JS deps
        run: bun install --frozen-lockfile
      - name: Size budget gate (${{ matrix.target }} <= ${{ matrix.budget_kb }} KB gzip)
        run: bash sdks/typescript/scripts/size-budget.sh ${{ matrix.target }} ${{ matrix.budget_kb }}
      - name: Conformance subset (${{ matrix.target }})
        run: bun run --filter @chio-protocol/conformance test:${{ matrix.target }}
      - name: Cold-start budget (Workers and Edge only)
        if: matrix.target == 'workers' || matrix.target == 'edge'
        run: bun run --filter @chio-protocol/conformance bench:cold-start:${{ matrix.target }}

  diff-tests:
    needs: build-wasm
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Browser canonical-JSON differential
        run: cargo test -p chio-formal-diff-tests --test browser_canonical_json_diff
```

The size-budget gate is per-target and lives in the matrix step labeled "Size budget gate". Failure to stay under the gzipped budget fails the job. Cold-start budget runs on Workers and Edge only because those runtimes have the tightest cold-start envelope.

(NOTE: an earlier draft referenced `browser-edge.yml`; the canonical filename is `web-sdk.yml`. Any leftover `browser-edge.yml` references in this doc should be treated as renamed to `web-sdk.yml`.)

## wasm-pack vs jco decision tree

Phase 1 and Phase 2 use `wasm-pack` per runtime. Phase 4 runs a `jco` spike for Component Model convergence.

Per-runtime `wasm-pack --target` matrix:

| Runtime | `wasm-pack --target` | Loader pattern | Notes |
|---|---|---|---|
| `@chio-protocol/browser` | `web` | `fetch(new URL("./chio_kernel_browser_bg.wasm", import.meta.url)).then(WebAssembly.instantiateStreaming)` | ESM, browser-native. |
| `@chio-protocol/workers` | `bundler` | `import wasmModule from "./chio_kernel_browser_bg.wasm"; await WebAssembly.instantiate(wasmModule, imports)` | bundler-mediated; no `nodejs_compat`. |
| `@chio-protocol/edge` | `web` | inlined wasm import; `export const config = { runtime: "edge" }` | matches Vercel Edge Function loader. |
| `@chio-protocol/deno` | `web` | `await WebAssembly.instantiateStreaming(fetch(new URL("./chio_kernel_browser_bg.wasm", import.meta.url)))` | uses `import.meta.url` resolution. |
| Bun (Phase 3 native) | (no wasm-pack glue) | `await WebAssembly.instantiate(await Bun.file("./chio_kernel_browser_bg.wasm").arrayBuffer())` | skips wasm-pack JS glue for size win. |

Phase 4 jco spike (concrete):

- Command:
  ```
  jco transpile target/wasm32-unknown-unknown/release/chio_kernel_browser.wasm \
      --out sdks/typescript/packages/browser/dist/jco/ \
      --instantiation async \
      --tla-compat
  ```
- Spike location: `sdks/typescript/scripts/jco-spike.sh` (new, Phase 4 only).
- Success criteria for the spike:
  1. `jco transpile` emits a working ESM module that the browser package can import without modification to the public TS surface.
  2. Size of the jco-emitted bundle is within +/- 15% of the wasm-pack `--target web` bundle.
  3. The conformance subset passes byte-identically against the jco artifact.
  4. There is a documented migration path from wasm-bindgen ABI to Component Model worlds.
- A spike that fails any of the four criteria closes Phase 4 with a "not adopted, retry next minor" note. A spike that passes all four opens a Phase 5 to migrate runtimes one by one, starting with Deno (cleanest Component Model integration today).

## Demo path lock

The demo deploys to **GitHub Pages from `docs/demo/`**. This is the locked path; do not relocate.

Build pipeline:

- Workflow: `.github/workflows/demo-pages.yml` (new; not the same workflow as `web-sdk.yml`).
- Trigger: push to `main` whose changeset touches `docs/demo/**` or any path that produces a wasm artifact (`crates/chio-kernel-browser/**`, `sdks/typescript/packages/browser/**`).
- Source of the wasm artifact: the demo workflow downloads the `wasm-artifacts` artifact from the latest successful `web-sdk.yml` run on `main`, copies the `@chio-protocol/browser` `dist/web/` output into `docs/demo/dist/`, and publishes `docs/demo/` via `actions/deploy-pages@v4`.
- Rebuild cadence: on every push to `main` that touches the watched paths. Manual rebuilds via `workflow_dispatch`.
- The demo URL is treated as engineering output, not a release artifact. The HTML at `docs/demo/index.html` MUST include a visible banner:

```html
<div role="note" class="engineering-output-banner">
  This page is engineering output, not a release. It demonstrates the
  @chio-protocol/browser verify path against a fixture from the M04 replay
  corpus. It is not a substitute for an audited release of the SDK.
</div>
```

This banner MUST be present and visible without scrolling on a 1080p viewport.

## Conformance subset definition

M01 ships the full vector corpus. M08's browser/edge runtimes pass a named, versioned subset, NOT the full corpus. The subset is intentionally narrow (verify-only):

- `tests/bindings/vectors/canonical/v1.json` ALL CASES: canonical-JSON round-trip (encode-and-compare bytes).
- `tests/bindings/vectors/receipt/v1.json` cases tagged `verify_only: true`: receipt verify against a trusted-issuer set.
- `tests/bindings/vectors/capability/v1.json` cases tagged `verify_only: true`: capability-token verify.

Explicitly excluded from the M08 subset:

- Receipt and capability **signing** vectors (Phase 1 and Phase 2 of M08 are verify-only; signing waits on Phase 3 trust-boundary review).
- `manifest`, `hashing`, `signing` corpora (server-side concerns).
- Any vector requiring fresh entropy or live time (verify-only path is deterministic).

The subset manifest lives at `sdks/typescript/packages/conformance/src/browser-subset.ts` and exports a `BROWSER_SUBSET_V1` constant referenced from M01's conformance manifest. M01 owns the corpus; M08 owns the subset selector. The subset is versioned (`v1`); a `v2` subset requires a coordinated bump in both milestones.

## Browser-runtime differential test

Per the M01 cross-doc invariant, the browser path lands as a canonical-JSON differential target.

- File: `formal/diff-tests/tests/browser_canonical_json_diff.rs`.
- Asserts: for every input in `tests/bindings/vectors/canonical/v1.json`, the bytes produced by `@chio-protocol/browser` (executed via `wasm-bindgen-test` against the same wasm artifact CI publishes) are byte-identical to the bytes produced by `chio_core_types::canonical::canonicalize` on the Rust oracle.
- Invariants (proptest):
  1. Round-trip: `oracle(input) == browser(input)` for every fixture in the canonical corpus.
  2. Byte-equality: assert via `assert_eq!(oracle_bytes.as_slice(), browser_bytes.as_slice())` (not string equality, not parsed equality).
  3. Encoder rejection parity: any input the oracle rejects (NaN, Infinity, lone surrogate keys), the browser path must also reject with a `BindingError::CanonicalizeRejected` shape.
  4. Empty-collection parity: `{}` and `[]` encode identically in both paths.
  5. UTF-16 key ordering parity: object keys with supplementary-plane code points sort identically.
  6. Number shortest-form parity: `1e21`, `5e-324`, `9007199254740993`, `0.1 + 0.2`, `-0` all encode identically.

This test is gated on M01 Phase 2 (vector corpus freeze). It does not depend on M01 Phase 3 codegen; it consumes the corpus directly.

## New sub-tasks (Round-2 additions)

Three sub-tasks not previously called out, in M08 scope:

- **(NEW) Pin wasm tooling versions in `.tooling/` metadata files**: land `.tooling/wasm-pack.version` and `.tooling/wasm-bindgen.version` text files holding the pinned versions. The `web-sdk.yml` workflow reads them; the build script reads them; CI fails if either drifts vs the version recorded in `Cargo.lock` for the `wasm-bindgen` library. Effort: S, 1 day.
- **(NEW) Add `engines` field plus `exports` map to every new package's `package.json`**: each of `@chio-protocol/{browser,workers,edge,deno}` declares its supported runtime in `engines` (where the npm semantics allow) and uses `exports` conditional resolution to route `worker`, `edge-light`, `deno`, `browser`, and `default` conditions to the correct artifact. Effort: S, 1 day.
- **(NEW) Land `docs/demo/CNAME` and `docs/demo/.nojekyll` plus a banner snapshot test**: GitHub Pages requires `.nojekyll` to serve dotfiles and wasm MIME types correctly; a Playwright snapshot test asserts the engineering-output banner is rendered above the fold on the demo page. Effort: S, 1 day.

## Code touchpoints

Created:

- `/Users/connor/Medica/backbay/standalone/arc/sdks/typescript/packages/browser/` (new package, `@chio-protocol/browser`)
- `/Users/connor/Medica/backbay/standalone/arc/docs/demo/` (M04-fixture demo page; GitHub Pages root)
- `/Users/connor/Medica/backbay/standalone/arc/sdks/typescript/packages/workers/` (new package, `@chio-protocol/workers`)
- `/Users/connor/Medica/backbay/standalone/arc/sdks/typescript/packages/edge/` (new package, `@chio-protocol/edge`)
- `/Users/connor/Medica/backbay/standalone/arc/sdks/typescript/packages/deno/` (new package, `@chio-protocol/deno`)
- `/Users/connor/Medica/backbay/standalone/arc/sdks/typescript/scripts/build-wasm.sh` (wasm-pack invocation)
- `/Users/connor/Medica/backbay/standalone/arc/sdks/typescript/scripts/size-budget.sh` (gzip-size CI gate)
- `/Users/connor/Medica/backbay/standalone/arc/.github/workflows/web-sdk.yml` (build matrix + conformance subset)
- `/Users/connor/Medica/backbay/standalone/arc/.github/workflows/demo-pages.yml` (GitHub Pages publish for `docs/demo/`)
- `/Users/connor/Medica/backbay/standalone/arc/.tooling/wasm-pack.version` (pinned tool version)
- `/Users/connor/Medica/backbay/standalone/arc/.tooling/wasm-bindgen.version` (pinned tool version)
- `/Users/connor/Medica/backbay/standalone/arc/docs/demo/.nojekyll` (GitHub Pages serve override)
- `/Users/connor/Medica/backbay/standalone/arc/formal/diff-tests/tests/browser_canonical_json_diff.rs` (additional differential target)

Modified:

- `/Users/connor/Medica/backbay/standalone/arc/crates/chio-kernel-browser/src/lib.rs` (add `verify_receipt` wasm-bindgen entry consuming a `ChioReceipt` envelope plus trusted issuer set)
- `/Users/connor/Medica/backbay/standalone/arc/crates/chio-kernel-browser/examples/demo.html` (link to the new TS demo, retire the inline JS variant)
- `/Users/connor/Medica/backbay/standalone/arc/sdks/typescript/package.json` (workspace registers the four new packages)
- `/Users/connor/Medica/backbay/standalone/arc/sdks/typescript/packages/conformance/src/index.ts` (export a runtime-agnostic conformance subset runner)

## Open questions

Decisions resolved upstream in the trajectory README on 2026-04-25:

- **Namespace**: `@chio-protocol/*` (user-confirmed; do not provision `@chio`).
- **Monorepo location**: `sdks/typescript/packages/` (existing TS surface, with per-package `engines`/`exports` gating consumption).
- **wasm-bindgen vs jco**: Phase 2 uses `wasm-bindgen` per-runtime. Phase 4 spike on `jco transpile` evaluates Component Model convergence.
- **Demo deployment**: GitHub Pages from `docs/demo/`, framed as engineering output (not a release artifact).

Still open, deferred to mid-execution:

- **JSON path on Workers**: keep `serde-wasm-bindgen` (uniform, larger) or hand-roll `TextDecoder` plus `JSON.parse` (smaller, two parsing paths). Decide after the first measured Workers bundle in Phase 2.
- **Stream parser scope** (Phase 3): partial single-receipt incremental parse vs the full chunked-receipt protocol (M04 dependency). Recommended: partial; defer full chunked replay to a follow-up.
- **Bun-native target**: Phase 3 alongside delegated signing or a separate Phase 4. Bundle-size win is real but the Bun loader API is still moving.
