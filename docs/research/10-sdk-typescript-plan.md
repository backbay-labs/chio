# TypeScript SDK Plan

> Historical, pre-rename design note. Paths and names below (for example `packages/sdk/arc-ts`) reflect the original ARC-era plan and are kept as a record; they are not current.
> The TypeScript SDK shipped as `@chio-protocol/sdk` at `sdks/typescript/chio-ts`.

## Goal

Build a TypeScript SDK that is good enough to replace the current JS conformance peer code and then grow into the maintained JS/TS client surface for the ARC edge.

The first release should optimize for:

- remote-edge interoperability
- stable session and callback behavior
- easy installation
- browser and Node viability without native addons

It should not optimize first for:

- maximal Rust reuse
- full browser-without-bundler support
- shipping WASM on day one

## Current Repo Starting Point

Local evidence:

- the current JS peer is hand-rolled and already covers initialization, auth, session reuse, nested callbacks, transcript capture, and scenario execution in one file: [tests/conformance/peers/js/client.mjs](../../tests/conformance/peers/js/client.mjs)
- the peer is ESM-only today: [tests/conformance/peers/js/package.json](../../tests/conformance/peers/js/package.json)
- `arc-core` is intentionally runtime-free and already states it is suitable for WASM and embedded environments: [crates/arc-core/src/lib.rs](../../crates/chio-core/src/lib.rs)

Implication:

- the fastest path is to turn the existing JS peer transport and session logic into a library package
- deterministic helpers can be added separately without blocking the remote-edge SDK

## Recommended Product Split

### `@arc/sdk`

Purpose:

- the main TS package
- pure TypeScript by default
- owns remote-edge protocol interaction
- may optionally use a WASM helper package for invariant logic

Should include:

- streamable HTTP transport
- session lifecycle
- auth discovery helpers
- tasks and progress
- notifications and subscriptions
- nested sampling, elicitation, and roots callback routing
- pure TS invariant helpers for day-one usability

### `@arc/sdk-wasm`

Purpose:

- optional acceleration and byte-identity helper package
- compiled from `crates/arc-bindings-wasm`
- not required for ordinary SDK usage

Should include:

- canonical JSON
- hash helpers
- signature helpers
- receipt verification
- capability and manifest helpers

Should not include:

- session transport
- OAuth helpers
- SSE handling
- callback routers

## Why This Split

Official `wasm-bindgen` and `wasm-pack` guidance makes the deployment target matter:

- `wasm-bindgen` supports different outputs for bundlers, web pages, Node.js, and Deno
- `--target web` is for direct browser ES modules and does not use NPM dependencies
- `wasm-pack build` defaults to the bundler mode and has distinct output behavior for `bundler`, `nodejs`, `web`, and `no-modules`

That means a single NPM package trying to be:

- a full remote-edge SDK
- a browser-native package
- a Node package
- and a WASM delivery vehicle

will accumulate packaging complexity fast.

The cleanest initial model is:

- `@arc/sdk` stays pure TS and easy to install
- `@arc/sdk-wasm` stays optional and narrowly scoped

## Recommended Repository Layout

```text
packages/sdk/arc-ts/
  package.json
  tsconfig.json
  tsup.config.ts
  src/
    index.ts
    client/
    transport/
    auth/
    session/
    tasks/
    resources/
    prompts/
    nested/
    invariants/
    types/
  test/
```

If the optional WASM package ships separately:

```text
crates/arc-bindings-wasm/
packages/sdk/arc-ts-wasm/
```

The `arc-ts-wasm` package can either:

- wrap the generated output from `wasm-pack`
- or publish the generated output directly if the release workflow is simple enough

## Package Format Recommendation

Initial recommendation:

- ESM-first package
- generated type declarations
- CJS compatibility only if it is cheap

Reasoning:

- the current conformance peer is already ESM
- Node 20+ is a reasonable minimum for the SDK
- browser-facing code is simpler if the package is not bent around legacy CommonJS early

If CJS is added later:

- keep it for the pure TS package only
- do not block initial delivery on dual-package + WASM packaging complexity

## Transport Design

### First-class protocol target

The TS SDK should target the ARC MCP-compatible edge over remote HTTP first.

The first-class transport should:

- POST JSON-RPC requests to `/mcp`
- support `application/json` and `text/event-stream`
- maintain `MCP-Session-Id`
- maintain `MCP-Protocol-Version`
- parse terminal responses and out-of-band notifications from the same stream

### Internal transport modules

Recommended modules:

- `transport/http.ts`
- `transport/sse.ts`
- `transport/errors.ts`
- `session/session.ts`
- `session/router.ts`

The logic currently embedded in the conformance peer should be extracted into:

- request execution
- terminal response collection
- notification dispatch
- session initialization and teardown
- transcript/debug hooks

### Callback model

The TS SDK needs explicit support for nested client callbacks:

- `sampling/createMessage`
- `elicitation/create`
- `notifications/elicitation/complete`
- `roots/list`

Recommended API shape:

- a `Session` object with registered handlers
- one handler surface per callback family
- fail-closed defaults if handlers are missing

Example shape:

```ts
const session = await client.initialize({
  onSample: async (request) => ({ ... }),
  onElicitForm: async (request) => ({ ... }),
  onElicitUrl: async (request) => ({ ... }),
  onRootsList: async () => ({ roots: [...] }),
});
```

The SDK should own:

- correlation IDs
- callback routing
- protocol version propagation
- session cleanup

## Auth Design

The current JS peer already proves two initial auth modes matter:

- static bearer
- local OAuth discovery plus authorization-code flow

Recommended auth modules:

- `auth/static.ts`
- `auth/protected-resource.ts`
- `auth/oauth-local.ts`
- `auth/pkce.ts`

The SDK should not bake auth into transport internals. Instead:

- auth should provide token providers
- transport should consume bearer tokens from that provider

This makes it easier to add:

- manual token injection
- refresh tokens
- external enterprise auth adapters

## Invariant Helpers

### Day-one recommendation

Ship pure TS invariant helpers first.

Candidates:

- canonical JSON
- SHA-256
- signature verification
- receipt verification

Reason:

- these can be tested immediately against shared vectors
- they keep installation trivial
- they let the remote-edge SDK ship before WASM packaging is stable

### WASM follow-up

Once vector tests exist and the remote-edge package shape is stable:

- add `@arc/sdk-wasm`
- lazily load it from `@arc/sdk`
- use it as an optional backend for invariant helpers

Recommended target sequence:

1. `bundler`
2. optional Node-specific packaging if needed
3. browser-without-bundler only if there is a real use case

## Build and Tooling Recommendation

Initial recommendation:

- TypeScript 5.x
- `tsup` for bundling
- `vitest` for tests
- Node 20+ minimum

Why:

- matches the existing peer's environment expectations
- keeps the first package thin
- avoids framework lock-in

## Test Strategy

### Unit tests

Test:

- argument validation
- transport parsing
- session lifecycle behavior
- callback routing
- auth helpers
- invariant helper vectors

### Integration tests

Run the existing JS conformance waves through the package instead of the hand-rolled peer script.

Migration path:

1. keep `client.mjs` as a thin CLI shim
2. move actual protocol logic into `packages/sdk/arc-ts`
3. import the package from `client.mjs`
4. later replace the peer shim entirely if helpful

### Vector tests

Consume:

- `tests/bindings/vectors/canonical/*.json`
- `tests/bindings/vectors/receipt/*.json`
- `tests/bindings/vectors/capability/*.json`

The TS SDK should be the first non-Rust consumer of those vectors.

## Release Strategy

### Alpha 1

Scope:

- pure TS package
- initialize
- notifications/initialized
- tools/resources/prompts
- tasks/result and tasks/cancel
- auth discovery helpers
- nested callbacks

Success condition:

- JS conformance peer can be reimplemented as a thin wrapper around the package

### Alpha 2

Scope:

- typed public APIs
- better error model
- transcript/debug hooks
- initial invariant helper module

### Alpha 3

Scope:

- optional WASM helper package
- vector-backed invariant parity

## Risks

### Risk: browser and Node concerns get mixed too early

Mitigation:

- keep first release Node-focused
- treat browser support as an explicit tracked target, not an accidental side effect

### Risk: WASM packaging slows the whole SDK

Mitigation:

- make WASM optional
- ship pure TS invariant helpers first

### Risk: callback handling is under-specified

Mitigation:

- migrate the current conformance peer behavior almost literally first
- tighten API shape only after that behavior is covered by tests

### Risk: auth logic becomes transport-coupled

Mitigation:

- define token-provider interfaces early
- keep OAuth flow code in a dedicated auth layer

## Open Questions

- Should the first public package be ESM-only or dual ESM/CJS?
- Is browser support a first-release requirement or a post-alpha target?
- Should the optional WASM package be published separately or bundled as an internal optional dependency?
- Do we want sync transcript hooks only, or structured event observers for all protocol traffic?

## Recommended First Implementation Slice

1. Create `packages/sdk/arc-ts`.
2. Move the current remote HTTP JSON-RPC logic out of [tests/conformance/peers/js/client.mjs](../../tests/conformance/peers/js/client.mjs) into `transport/` and `session/`.
3. Keep `client.mjs` as a CLI wrapper that imports the new package.
4. Add pure TS invariant helpers behind a small `invariants/` module.
5. Point the JS conformance runner at the package-backed peer.

## Research Inputs

Local:

- [tests/conformance/peers/js/client.mjs](../../tests/conformance/peers/js/client.mjs)
- [tests/conformance/peers/js/package.json](../../tests/conformance/peers/js/package.json)
- [crates/arc-core/src/lib.rs](../../crates/chio-core/src/lib.rs)
- [../BINDINGS_CORE_PLAN.md](../operations/BINDINGS_CORE_PLAN.md)

External:

- `wasm-bindgen` deployment guide: <https://rustwasm.github.io/docs/wasm-bindgen/reference/deployment.html>
- `wasm-pack` build target docs: <https://rustwasm.github.io/docs/wasm-pack/print.html>
