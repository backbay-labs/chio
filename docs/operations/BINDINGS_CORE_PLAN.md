> **Status:** superseded - SDKs live under `sdks/` (e.g. `sdks/typescript/chio-ts`), not `packages/sdk/`; the `crates/chio-bindings-wasm` crate is planned, not yet created.

# Chio Bindings Core Plan

## Goal

Add SDKs for TypeScript, Python, and Go without turning the Rust runtime into a giant cross-language ABI surface.

Language-specific implementation research for this plan lives in:

- [research/10-sdk-typescript-plan.md](../research/10-sdk-typescript-plan.md)
- [research/11-sdk-python-plan.md](../research/11-sdk-python-plan.md)
- [research/12-sdk-go-plan.md](../research/12-sdk-go-plan.md)

The recommended model is:

- Rust is the truth for protocol and security invariants.
- conformance is the truth for cross-language parity.
- each language SDK keeps an idiomatic transport and authoring layer.

Short-horizon execution sequencing for this plan lives in
[SDK_PARITY_EXECUTION_ROADMAP.md](SDK_PARITY_EXECUTION_ROADMAP.md).

This follows the existing project direction:

- MCP-compatible edge, Chio-native core
- evidence-driven compatibility claims
- native authoring ergonomics without hiding the security model

## Decision Summary

Do not make all SDK behavior flow through FFI.

Instead:

1. centralize deterministic invariant logic in a small Rust bindings core
2. expose that core through narrow WASM and native bridges
3. keep session, transport, auth, streaming, and authoring APIs native to each language
4. use the existing conformance harness plus new vector tests to prove parity

## Why This Boundary

This repo already proves that parity pressure is mostly at the edge:

- lifecycle and negotiation
- auth and discovery
- notifications and subscriptions
- tasks and cancellation
- nested sampling, elicitation, and roots

Those are SDK and transport problems, not just serialization problems.

If the project pushes all of that through Rust bindings too early, it will:

- over-couple SDK releases to kernel internals
- make packaging and debugging harder in every language
- create unstable browser, wheel, and CGO release burdens
- freeze the wrong boundary before the SDK shapes are proven

## Design Rules

### Rule 1: Rust owns deterministic invariants

The bindings core should own only logic where byte-for-byte equivalence matters:

- canonical JSON
- hashing
- signature verification and signing helpers
- capability parsing and validation helpers
- receipt parsing and verification helpers
- manifest parsing and verification helpers
- stable policy compilation or policy hashing helpers if needed

### Rule 2: SDKs own transport and developer experience

Each language SDK should own:

- remote HTTP and stream handling
- session lifecycle
- auth helpers
- notification callbacks
- task polling and cancellation UX
- nested-flow callback orchestration
- idiomatic types, errors, and async model

### Rule 3: Conformance is more important than shared implementation

Parity should be enforced by:

- shared golden vectors for invariant logic
- live multi-language conformance runs against the Rust edge
- language-specific behavior tests around retries, auth, cancellation, and callbacks

### Rule 4: Optional native acceleration only

Native bridges should be optional where possible:

- TS should work without WASM
- Python should work without the native module for remote-edge usage
- Go should work with `CGO_ENABLED=0` for remote-edge usage

The default path should never require native compilation just to talk to a remote Chio edge.

## Proposed Repository Layout

```text
crates/
  chio-binding-helpers/
  chio-bindings-ffi/
  chio-bindings-wasm/

tests/
  bindings/
    vectors/
    matrix/

packages/
  sdk/
    chio-ts/
    chio-py/
      chio-native/
    chio-go/
```

## Crate Responsibilities

### `crates/chio-binding-helpers`

Purpose:

- stable Rust facade designed for bindings consumers

Dependencies:

- `chio-core`
- `chio-manifest`
- `chio-policy` only if policy helpers are intentionally included

Must not depend on:

- `chio-kernel`
- `chio-cli`
- transport code
- remote trust services
- edge session orchestration

Recommended modules:

- `canonical`
- `hashing`
- `signing`
- `capabilities`
- `receipts`
- `manifest`
- `policy` only for compile-and-hash or load-and-hash helpers
- `errors`
- `fixtures`

Recommended API shape:

- byte-oriented or JSON-string-oriented helpers
- stable error codes
- no direct exposure of deep internal types unless they are intentionally frozen

Example surface:

- `canonicalize_json(input) -> String`
- `hash_sha256(bytes) -> [u8; 32]`
- `verify_receipt(receipt_json, signer_keys) -> VerificationResult`
- `parse_capability(json) -> CapabilityView`
- `verify_manifest(manifest_json, trust_roots) -> ManifestVerification`
- `compile_policy(input_yaml) -> CompiledPolicyArtifact`

### `crates/chio-bindings-ffi`

Purpose:

- narrow C ABI for languages that need native linkage

Primary consumers:

- Go via CGO
- future C-compatible ecosystems
- Python only if a C ABI is needed beyond PyO3

Shape:

- C ABI over string and byte buffers
- opaque handles only for reusable compiled objects
- explicit allocation and free functions
- explicit error retrieval

Should not:

- mirror all internal Rust structs one-to-one
- expose async flows
- expose kernel/session runtime state

### `crates/chio-bindings-wasm`

Purpose:

- browser and Node-safe deterministic helpers

Primary consumers:

- TS SDK optional acceleration
- browser verification and receipt tooling

Scope:

- canonical JSON
- hashing
- signature verification
- receipt verification
- capability and manifest helpers where payload sizes are reasonable

Should not:

- embed the full edge client
- embed task or nested-flow runtime logic
- attempt to run the kernel in-browser as the primary SDK path

## Shared Test Artifacts

### `tests/bindings/vectors/`

These files are the stable parity contract for invariant logic.

Recommended fixtures:

- canonical JSON inputs and outputs
- hash vectors
- Ed25519 sign and verify vectors
- capability parse and verify vectors
- receipt allow, deny, and interrupted verification vectors
- manifest verification vectors
- policy compile or policy hash vectors if exposed

Format:

- JSON files generated by Rust tests
- consumed by TS, Python, and Go unit tests

### `tests/bindings/matrix/`

These files track SDK feature coverage by language and maturity:

- invariant helpers
- remote edge lifecycle
- tools/resources/prompts
- notifications
- tasks
- auth
- nested flows

This is distinct from the main conformance harness. It records SDK surface progress, not only edge protocol progress.

## SDK Layout and Language Strategy

## TypeScript

### Package layout

```text
sdks/typescript/chio-ts/
  src/
    client/
    transport/
    session/
    auth/
    tasks/
    resources/
    prompts/
    nested/
    invariants/
  test/
```

### Recommended implementation model

- pure TS remote-edge client is the default
- optional WASM module backs invariant helpers only
- no requirement for native addons

### TS scope by layer

Local invariant helpers:

- canonical JSON
- hash and verify helpers
- receipt verification
- capability and manifest inspection helpers

Remote-edge SDK:

- initialize and negotiate capabilities
- tools, resources, prompts
- notifications and subscriptions
- tasks, progress, cancellation
- auth discovery and challenge handling
- nested sampling, elicitation, and roots callbacks

### TS implementation notes

- prefer `fetch` plus an internal stream parser for remote HTTP
- support both browser and Node where practical
- keep the callback API idiomatic to JS promises and event handlers
- make WASM lazy and optional

### TS acceptance bar

- package can replace bespoke JS peer logic for current conformance waves
- invariant tests pass against shared vectors
- package works with and without the WASM dependency

## Python

### Package layout

```text
sdks/python/chio-py/
  src/chio/
    client/
    session/
    auth/
    tasks/
    nested/
    invariants/
  chio-native/
    Cargo.toml
    pyproject.toml
    src/
  tests/
```

### Recommended implementation model

- pure Python remote-edge SDK is the default
- PyO3 native module is the preferred Python-native bridge
- do not require the C ABI for normal Python packaging

### Python scope by layer

Pure Python:

- remote HTTP edge client
- session lifecycle
- auth helpers
- tasks and nested-flow callbacks
- typed exceptions and dataclasses

PyO3 native module:

- canonical JSON
- hashing
- signature helpers
- receipt verification
- capability and manifest helpers
- optional policy compile or validation helpers

### Python implementation notes

- use `abi3` wheels to keep packaging stable
- use `httpx` for remote-edge transport
- keep the package useful even when the native extension is missing
- reserve fail-closed behavior for security-sensitive local helpers, not for remote-edge transport itself

### Python acceptance bar

- package can replace bespoke Python peer logic for current conformance waves
- wheels build for the main supported platforms
- shared vectors pass with and without the native extension where fallback behavior exists

## Go

### Package layout

```text
sdks/go/chio-go/
  client/
  session/
  auth/
  tasks/
  nested/
  invariants/
  internal/native/
```

### Recommended implementation model

- pure Go remote-edge SDK is the default
- optional CGO bridge consumes `chio-bindings-ffi`
- `CGO_ENABLED=0` remains supported for remote-edge usage

### Go scope by layer

Pure Go:

- remote HTTP client
- session lifecycle
- auth discovery
- tasks and notifications
- nested-flow support
- idiomatic context-based cancellation

Optional native bridge:

- canonical JSON
- hash and verify helpers
- receipt verification
- capability and manifest helpers

### Go implementation notes

- keep the main package free of mandatory CGO
- hide CGO behind build tags or a subpackage
- use `context.Context` everywhere for cancellation and deadlines
- make the first release remote-edge-first, not native-engine-first

### Go acceptance bar

- basic remote-edge SDK works with `CGO_ENABLED=0`
- native helpers pass shared vectors when enabled
- initial Go peer coverage exists before calling the package parity-ready

## What Must Not Go Into Bindings Core

The following should stay out of `chio-binding-helpers` in the first rollout:

- full session state machines
- remote HTTP clients
- auth-code or token-exchange workflows
- task schedulers
- nested callback routers
- kernel execution and mediation runtime
- trust-control service clients

Those surfaces are still evolving and are better expressed natively in each language.

## Rollout Order

## Phase 0: contract freeze

Objective:

- define the bindings boundary before building packages

Deliverables:

- final list of invariant helpers in scope
- stable error taxonomy for bindings
- first shared vector format
- first SDK feature matrix

Exit criteria:

- the team can answer "is this SDK behavior parity or invariant parity?"
- every proposed binding entrypoint has an owning test class

## Phase 1: `chio-binding-helpers`

Objective:

- centralize invariant logic behind one bindings-friendly Rust facade

Deliverables:

- `crates/chio-binding-helpers`
- vector generator tests
- stable JSON fixtures under `tests/bindings/vectors/`

Exit criteria:

- Rust vectors are generated from one crate, not ad hoc per SDK
- no dependency on `chio-kernel` or edge transport code

## Phase 2: TypeScript alpha

Reason to do this first:

- existing JS peer coverage already exists
- WASM is optional and bounded
- it proves the remote-edge SDK shape quickly

Deliverables:

- `sdks/typescript/chio-ts`
- invariant helper layer with optional WASM backend
- remote HTTP client for current conformance waves

Exit criteria:

- TS package replaces the bespoke JS peer transport code
- vector tests are green
- current JS conformance waves still pass through the package

## Phase 3: Python alpha

Reason to do this second:

- existing Python peer coverage already exists
- PyO3 is a cleaner Python-native path than a C ABI-first design
- wheel packaging is tractable once the bindings-core boundary is stable

Deliverables:

- `sdks/python/chio-py`
- `sdks/python/chio-py/chio-native`
- optional native invariants module
- remote HTTP client for current conformance waves

Exit criteria:

- Python package replaces the bespoke peer transport code
- vector tests are green
- native wheels build in CI for the target matrix

## Phase 4: Go alpha

Reason to do this third:

- there is no existing Go conformance peer yet
- CGO complexity is real and should not define the earlier architecture
- the remote-edge client can ship before native linkage

Deliverables:

- `sdks/go/chio-go`
- pure Go remote-edge client
- optional `internal/native` bridge using `chio-bindings-ffi`

Exit criteria:

- remote-edge client works with `CGO_ENABLED=0`
- vector tests are green in pure Go or native-backed mode as appropriate
- first Go peer or equivalent integration coverage exists

## Phase 5: parity hardening

Objective:

- move from working packages to credible parity claims

Deliverables:

- TS, Python, and Go feature matrix
- release gating that runs vector tests and conformance suites
- docs for when to use local invariant helpers versus remote-edge APIs

Exit criteria:

- parity claims are grounded in checked-in evidence
- SDK docs clearly separate supported and unsupported surfaces

## Implementation Checklist

## Milestone A: create the Rust core

Tasks:

- add `crates/chio-binding-helpers`
- define a bindings-safe error model
- add vector generation tests
- write a short `BINDINGS_API.md` if the surface grows beyond a few modules

## Milestone B: ship TS remote-edge package

Tasks:

- scaffold `sdks/typescript/chio-ts`
- move current JS peer transport logic into reusable library code
- add optional WASM loading for invariant helpers
- run current JS conformance waves through the package

## Milestone C: ship Python remote-edge package plus PyO3 helpers

Tasks:

- scaffold `sdks/python/chio-py`
- add `httpx` transport and session handling
- add `chio-native` with `abi3`
- run current Python conformance waves through the package

## Milestone D: ship Go remote-edge package

Tasks:

- scaffold `sdks/go/chio-go`
- add context-aware remote HTTP client
- add optional CGO helpers
- create first Go integration coverage

## Risks

- putting too much runtime logic into the bindings core
- making WASM or native modules mandatory for ordinary SDK usage
- building three SDKs before the vector contract is stable
- claiming parity from shared implementation instead of evidence

## Mitigations

- freeze a narrow bindings scope first
- keep transport and session logic language-native
- make vectors and conformance gating mandatory
- add Go only after TS and Python package shapes are proven

## Recommended Immediate Next Moves

1. Add `crates/chio-binding-helpers` with only canonical JSON, hashing, signature, receipt, capability, and manifest helpers.
2. Add `tests/bindings/vectors/` and generate the first canonical JSON, hash, and receipt verification fixtures from Rust.
3. Scaffold `sdks/typescript/chio-ts` and route the existing JS peer through it for remote HTTP coverage.
4. After the TS package shape stabilizes, scaffold `sdks/python/chio-py` plus a minimal PyO3 module.
5. Start Go only after the TS and Python packages prove that the bindings-core boundary is small enough.

## Recommendation

Use "Rust as truth" for invariant logic, not for the whole SDK runtime.

That gives Chio:

- one trustworthy implementation of byte-sensitive security primitives
- evidence-backed multi-language parity
- SDKs that still feel native in TS, Python, and Go
- a rollout path that matches the current E8 sequencing instead of fighting it
