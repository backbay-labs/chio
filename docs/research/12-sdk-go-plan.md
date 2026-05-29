# Go SDK Plan

> Historical, pre-rename design note. Paths and names below (for example `packages/sdk/arc-go`) reflect the original ARC-era plan and are kept as a record; they are not current.
> The Go SDK shipped as `chio-go` at `sdks/go/chio-go`, with the wire client `chio-go-http` at `sdks/go/chio-go-http`.

## Goal

Build a Go SDK that is installable and usable for remote-edge interaction without requiring CGO, while leaving room for a narrow optional native bridge later.

The Go plan should optimize for:

- ordinary `go get` usability
- `CGO_ENABLED=0` remote-edge support
- idiomatic `context.Context`-based control flow
- narrow and explicit native boundaries if they arrive later

It should not optimize first for:

- binding all Rust logic into Go
- mandatory CGO
- prebuilt native library distribution on day one

## Current Repo Starting Point

Local evidence:

- there is no Go peer yet in the ARC repo
- the current interop harness exercises JS and Python peers only: [docs/archive/epics/E8-migration-conformance-and-sdks.md](../archive/epics/E8-migration-conformance-and-sdks.md)
- `arc-core` is intentionally free of runtime dependencies and already documents itself as suitable for embedded and WASM-style environments: [crates/arc-core/src/lib.rs](../../crates/chio-core/src/lib.rs)

Implication:

- Go should start with a pure Go remote-edge client
- native linkage should be deferred until the SDK shape is proven

## Recommended Product Model

### `arc-go`

Purpose:

- the main Go module
- pure Go by default
- owns remote-edge transport, sessions, auth, tasks, and nested callbacks

Should include:

- HTTP transport
- JSON-RPC request/response types
- streamable HTTP parsing
- session management
- auth helpers
- task and nested-flow support
- pure Go invariant helpers where practical

### Optional `native` subpackage

Purpose:

- optional CGO-backed narrow bridge to `arc-bindings-ffi`
- only for deterministic helper functions

Should include:

- canonical JSON
- hash helpers
- signature helpers
- receipt verification
- capability and manifest helpers

Should not include:

- remote transport
- session lifecycle
- callbacks into Go from Rust
- kernel or trust-control clients

## Why This Model

The official Go `cgo` docs reinforce several constraints:

- files importing `"C"` are only built when cgo is enabled
- cgo is disabled by default for many cross-compile situations
- `#cgo` directives and build constraints become part of the package contract
- pointer-passing rules are strict and runtime-checked

That means CGO is not a safe foundation for the first Go SDK release if we want:

- simple `go get`
- wide platform usability
- easy cross-compilation

So the default Go package should remain pure Go.

## Recommended Repository Layout

```text
packages/sdk/arc-go/
  go.mod
  client/
  transport/
  session/
  auth/
  tasks/
  nested/
  invariants/
  internal/
    protocol/
    sse/
  native/
    bridge_cgo.go
    bridge_stub.go
    include/
```

If the native bridge ships later:

- generated headers should come from `crates/arc-bindings-ffi`
- the Go package should consume them behind build tags

## Package API Recommendation

Recommended top-level API:

- `client.Client`
- `client.New(baseURL, options...)`
- `Session`
- request-specific typed methods where the protocol is stable

Key design rule:

- use `context.Context` for all cancellable operations

Examples:

- `Initialize(ctx context.Context, opts InitializeOptions) (*Session, error)`
- `CallTool(ctx context.Context, ...)`
- `TasksResult(ctx context.Context, taskID string)`

## Transport Design

### First release target

Target the remote HTTP ARC edge first.

The Go SDK should support:

- `initialize`
- `notifications/initialized`
- remote HTTP session reuse
- streamable HTTP parsing
- auth discovery
- tasks
- nested callbacks

### Internal modules

Recommended modules:

- `transport/http.go`
- `transport/stream.go`
- `session/session.go`
- `session/router.go`
- `auth/static.go`
- `auth/oauth_local.go`

### Callback design

Like the JS and Python SDKs, Go must support nested client callbacks:

- `sampling/createMessage`
- `elicitation/create`
- `notifications/elicitation/complete`
- `roots/list`

Recommended API model:

- handler interfaces or function options on `Session`

Example shape:

```go
session, err := client.Initialize(ctx, arc.InitializeOptions{
    OnSample: func(ctx context.Context, req arc.SampleRequest) (arc.SampleResponse, error) {
        ...
    },
    OnRootsList: func(ctx context.Context) (arc.RootsResponse, error) {
        ...
    },
})
```

The SDK should own:

- correlation IDs
- protocol version propagation
- callback routing
- fail-closed missing-handler behavior

## Auth Design

The Go SDK should support the same first two auth modes:

- static bearer
- local OAuth discovery and authorization-code flow

Recommended modules:

- `auth/static.go`
- `auth/protected_resource.go`
- `auth/oauth_local.go`
- `auth/pkce.go`

As in the other SDKs:

- auth should produce token providers
- transport should consume tokens

## Invariant Helpers

### Pure Go first

The first Go SDK should implement a small set of invariant helpers in pure Go:

- canonical JSON
- SHA-256
- signature verification
- receipt verification

Why:

- pure Go keeps installation and cross-compilation simple
- it avoids native distribution questions blocking the remote-edge SDK
- it allows early vector-test consumption before any CGO work

### Optional native second

Only after the pure Go client is stable should the repo consider:

- `native` subpackage
- `arc-bindings-ffi`
- CGO-backed helper acceleration

Even then:

- the top-level remote-edge SDK should not require CGO

## Native Bridge Design

### Build tags

Use the standard Go build split:

- `//go:build cgo`
- `//go:build !cgo`

This should live in paired files such as:

- `bridge_cgo.go`
- `bridge_stub.go`

### C boundary rules

The optional bridge should:

- accept `[]byte` or `string`
- pass only plain buffers and scalar values across C
- use explicit free functions for returned buffers
- avoid callbacks entirely in the first design

Do not:

- pass Go-managed objects through C
- depend on long-lived Go pointers in Rust
- build a callback-heavy API around `runtime/cgo.Handle` unless there is a proven need

The official `cgo` docs do document `runtime/cgo.Handle`, but it should be treated as an escape hatch, not the primary design.

### Linking and distribution problem

This is the hardest Go-specific issue.

Questions that must be answered before shipping native support:

- where do the target-specific Rust libraries come from?
- are they vendored in the repo?
- are they fetched during release packaging?
- are users expected to build them locally?

Initial recommendation:

- do not ship native linkage in the first public Go alpha

## Distribution Recommendation

### First release

Ship only the pure Go package.

Benefits:

- works with `CGO_ENABLED=0`
- works in standard Go CI and cross-compilation flows
- avoids Rust toolchain assumptions

### Later native option

If there is demand for native helper acceleration:

- publish clear per-platform support docs
- keep native support opt-in
- keep stubs working when native support is unavailable

## Test Strategy

### Unit tests

Test:

- stream parsing
- session lifecycle
- auth helpers
- callback routing
- pure Go invariant helpers

### Vector tests

The Go SDK should consume the same Rust-generated vector fixtures as TS and Python.

This is especially important if Go keeps pure Go implementations for invariant logic.

### Integration tests

Go should get its own interop coverage before any parity claim is made.

Recommended path:

1. add `packages/sdk/arc-go`
2. write Go integration tests against a local ARC edge
3. once stable, add a Go peer to the conformance harness

## Release Strategy

### Alpha 1

Scope:

- pure Go client
- remote HTTP edge support
- current conformance-wave-equivalent behavior

Success condition:

- Go integration tests cover the same session and callback families as the current JS and Python peers

### Alpha 2

Scope:

- pure Go invariant helpers
- shared vector test consumption
- improved auth support

### Alpha 3

Scope:

- optional `native` subpackage, only if there is real demand
- explicit platform matrix and build instructions

## Risks

### Risk: CGO becomes the default path accidentally

Mitigation:

- keep the main package pure Go
- hide native support behind a dedicated subpackage and build tags

### Risk: native library distribution becomes a release trap

Mitigation:

- do not promise native support early
- ship the remote-edge client first

### Risk: pointer and memory rules create subtle crashes

Mitigation:

- keep the C ABI narrow
- avoid callbacks
- pass only plain buffers and explicit lengths

### Risk: no Go peer means the API drifts from the harness reality

Mitigation:

- add Go integration tests before public parity claims
- add a Go conformance peer once the package shape stabilizes

## Open Questions

- Is a Go SDK required for the first public SDK milestone, or only after TS and Python?
- Should invariant helpers remain pure Go permanently unless benchmarks justify native linkage?
- If native linkage lands, how will per-platform Rust libraries be packaged and released?
- Do we need both sync and streaming observer APIs, or will `context.Context` plus callbacks be enough?

## Recommended First Implementation Slice

1. Create `packages/sdk/arc-go` as a pure Go module.
2. Implement the remote HTTP client, session lifecycle, and nested callback routing in pure Go.
3. Add integration tests against a local ARC edge.
4. Add pure Go invariant helpers and vector tests.
5. Revisit CGO only after the package proves useful without it.

## Research Inputs

Local:

- [../BINDINGS_CORE_PLAN.md](../operations/BINDINGS_CORE_PLAN.md)
- [../archive/epics/E8-migration-conformance-and-sdks.md](../archive/epics/E8-migration-conformance-and-sdks.md)
- [crates/arc-core/src/lib.rs](../../crates/chio-core/src/lib.rs)

External:

- Go `cgo` docs: <https://pkg.go.dev/cmd/cgo>
- Go build constraint docs: <https://pkg.go.dev/go/build/constraint>
