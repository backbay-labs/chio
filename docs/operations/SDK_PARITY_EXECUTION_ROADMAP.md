# Chio SDK Parity Execution Roadmap

## Purpose

Turn the current bindings and SDK planning into a short-horizon execution roadmap that is concrete enough to run for the next 4 to 6 weeks.

This roadmap is intentionally narrower than the full repo roadmap. It optimizes for one outcome:

- make SDK parity real enough that Chio has a credible multi-language adoption surface

It does not replace the broader release-closeout work tracked in [POST_REVIEW_EXECUTION_PLAN.md](../archive/POST_REVIEW_EXECUTION_PLAN.md). It is the interop and adoption lane that should feed into that closeout.

## Execution Status

As of 2026-03-20, the roadmap has materially advanced beyond the original starting point:

- `chio-ts` is package-backed across the current live conformance surface
- `chio-py` exists as a pure Python package and backs the current live conformance peer
- `chio-go` exists as a pure Go module with live MCP core, tasks, auth, notifications, and nested-callback conformance coverage and no mandatory CGO
- the SDK feature matrix and repo parity script now provide checked-in parity evidence across TS, Python, and Go

The remaining work after this execution pass is mostly hardening and adoption work:

- package polish and release ergonomics
- examples and adoption-facing docs
- deciding whether TS/Python invariant rows should remain `package_backed` or gain additional live evidence
- optional native acceleration only after the remote-edge package boundaries remain stable

## Current Starting Point

At the start of this roadmap, the repo already has:

- `crates/chio-binding-helpers` with canonical JSON, hashing, signing, receipt, capability, and manifest helpers
- checked-in shared vectors under `tests/bindings/vectors/`
- `sdks/typescript/chio-ts` invariant helpers plus a low-level transport/session layer
- the JS conformance peer importing shared transport code from `chio-ts`
- live MCP core, tasks, auth, notifications, and nested-callback JS and Python conformance green against the remote edge

The repo does not yet have:

- a first-class `chio-ts` client/session API
- a `sdks/python/chio-py` package
- a `sdks/go/chio-go` package
- a checked-in SDK feature matrix with release gates

## North Star

By the end of this roadmap, Chio should be able to say all of the following with checked-in evidence:

- TypeScript has a package-backed remote-edge SDK that replaces the bespoke JS peer logic for current conformance areas.
- Python has a package-backed remote-edge SDK that replaces the bespoke Python peer logic for current conformance areas.
- Go has a pure Go remote-edge SDK foundation with real conformance coverage and no mandatory CGO.
- parity claims are backed by vectors, live conformance, and a checked-in feature matrix

## Guardrails

These constraints hold for the full roadmap:

- `chio-binding-helpers` stays invariant-only
- no session runtime, auth flows, callback routers, or trust-control clients move into Rust bindings
- WASM, PyO3, CGO, and C ABI work are explicitly deferred unless a milestone says otherwise
- pure remote-edge usability beats native acceleration in this window

## Success Conditions

The roadmap is successful if all of the following are true:

1. `chio-ts` exposes a real `Client` and `Session` API and the JS peer becomes mostly scenario code.
2. `chio-py` exists as a pure Python package and the Python peer routes through it.
3. `chio-go` exists as a pure Go module and proves at least the first meaningful remote-edge slice with `CGO_ENABLED=0`.
4. vectors and conformance gates are the evidence source for parity claims.
5. native acceleration remains optional and does not define package boundaries.

## Explicit Non-Goals

Do not spend this 4 to 6 week window on:

- `crates/chio-bindings-ffi`
- `crates/chio-bindings-wasm`
- `sdks/python/chio-py/chio-native`
- Go CGO bridge work
- browser-first packaging work
- moving full SDK runtime logic behind Rust FFI

Those can start after TS and Python package-backed parity is proven and after Go package shape is stable.

## Milestone Plan

## Milestone 1: Contract And Evidence Freeze

Timebox:

- Week 1

Objective:

- make SDK parity measurable before adding more package surface

Deliverables:

- `docs/BINDINGS_API.md` or equivalent short API contract for `chio-binding-helpers`
- checked-in SDK feature matrix under `tests/bindings/matrix/`
- one script or CI lane that names the required parity checks by language
- explicit alpha support table for TS, Python, and Go

Tasks:

- freeze the current `chio-binding-helpers` public surface and stable error taxonomy
- define the SDK feature rows:
  - invariants
  - initialize/session
  - tools/resources/prompts
  - notifications/subscriptions
  - tasks
  - auth
  - nested callbacks
- define status labels such as `planned`, `in_progress`, `package_backed`, `conformance_green`
- wire the matrix into CI or a verification script, even if some rows are still `planned`

Acceptance bar:

- every bindings-core entrypoint has an owning vector or unit test class
- the matrix is checked in and reviewed in the repo
- CI or a repo script names the parity evidence path for TS and Python
- no new bindings-core API is added without a vector or a documented reason it is not vector-backed

## Milestone 2: TypeScript Alpha Completion

Timebox:

- Week 2

Objective:

- turn `chio-ts` from low-level helpers into the first real package-backed SDK

Deliverables:

- `sdks/typescript/chio-ts/src/client/`
- `sdks/typescript/chio-ts/src/session/`
- `sdks/typescript/chio-ts/src/auth/`
- `sdks/typescript/chio-ts/src/tasks/`
- `sdks/typescript/chio-ts/src/nested/`
- public `Client` and `Session` API exported from the package root
- updated README with alpha scope, examples, and unsupported surfaces

Tasks:

- add `Client` and `Session` types on top of the current transport layer
- move request execution, session lifecycle, callback routing, and auth discovery out of peer-only code
- keep transcript/debug hooks available so the conformance peer can still emit artifacts
- reduce `tests/conformance/peers/js/client.mjs` to scenario and transcript glue

Acceptance bar:

- `chio-ts` root exports more than invariants and transport
- the JS peer uses package modules for all remote-edge behavior in current conformance areas
- `npm --prefix sdks/typescript/chio-ts test` is green
- MCP core, tasks, auth, notifications, and nested-callback live conformance is green with the JS peer backed by `chio-ts`
- the README clearly marks the package as alpha and lists unsupported surfaces explicitly

## Milestone 3: Python Foundation

Timebox:

- Week 3

Objective:

- establish the pure Python package boundary without introducing native packaging complexity

Deliverables:

- `sdks/python/chio-py/pyproject.toml`
- `sdks/python/chio-py/src/chio/`
- Python errors, models, invariants, transport, and session modules
- vector tests for Python invariant helpers

Tasks:

- scaffold the package layout
- add pure Python canonical JSON, hashing, signing, receipt, capability, and manifest helpers as needed
- consume the checked-in shared vectors
- implement `httpx`-based remote transport primitives
- define typed exceptions and dataclass-style request/response models

Acceptance bar:

- `pip install -e sdks/python/chio-py` works without a Rust toolchain
- Python vector tests are green against the checked-in shared fixtures
- the package can initialize a remote session and perform low-level request execution in tests
- no PyO3 or maturin dependency is required for the package to function

## Milestone 4: Python Alpha Completion

Timebox:

- Week 4

Objective:

- replace the bespoke Python peer with the package-backed SDK

Deliverables:

- Python `Client` and `Session` API
- auth discovery helpers
- tasks and nested callback routing
- package-backed conformance peer
- Python README and examples

Tasks:

- move the current peer transport and callback logic into `sdks/python/chio-py`
- keep transcript/debug hooks available to the peer
- route the existing Python peer through the package for all current scenarios
- document the alpha surface and explicit non-goals

Acceptance bar:

- MCP core, tasks, auth, notifications, and nested-callback live conformance is green with the Python peer backed by `chio-py`
- Python vector tests remain green
- the package is still pure Python
- `chio-native` remains deferred and is not required for any current parity claim

## Milestone 5: Go Alpha Foundation

Timebox:

- Week 5

Objective:

- create the first pure Go SDK foundation without CGO

Deliverables:

- `sdks/go/chio-go/go.mod`
- `sdks/go/chio-go/client/`
- `sdks/go/chio-go/transport/`
- `sdks/go/chio-go/session/`
- `sdks/go/chio-go/auth/`
- `sdks/go/chio-go/invariants/`
- first Go vector tests

Tasks:

- scaffold the module and package layout
- add pure Go invariant helpers where practical
- consume the shared vectors
- implement context-aware remote HTTP transport and session initialization
- create a first Go peer or equivalent integration harness path

Acceptance bar:

- `CGO_ENABLED=0` build and test path works
- Go vector tests are green
- the Go SDK can initialize, negotiate protocol version, and execute the MCP core remote-edge slice
- no CGO bridge exists in the critical path

## Milestone 6: Go Coverage And Parity Hardening

Timebox:

- Week 6

Objective:

- turn the three-language SDK effort into a defensible parity claim

Deliverables:

- expanded Go support for tasks, auth, notifications, and nested callbacks
- a checked-in SDK parity report or matrix update
- CI or qualification lane that runs the package-backed parity checks
- adoption docs pointing users at TS, Python, and Go alpha surfaces

Tasks:

- push Go through as much of the current live conformance surface as the week allows
- mark unsupported Go surfaces explicitly rather than implying hidden parity
- add or tighten scripts that run:
  - Rust vectors
  - TS tests
  - Python tests
  - live conformance for package-backed peers
- document when to use invariant helpers versus the remote-edge client APIs

Acceptance bar:

- TS and Python are `package_backed` and `conformance_green` across current conformance areas
- Go is at minimum `package_backed` for the first remote-edge slice and `conformance_green` for its supported area set
- the matrix clearly distinguishes `supported now` from `planned next`
- the repo has one obvious parity evidence path instead of ad hoc commands

## Recommended Weekly Sequence

### Week 1

- freeze bindings contract
- add feature matrix
- add parity evidence script and docs

### Week 2

- finish TS alpha API
- route JS peer fully through `chio-ts`
- keep all live conformance areas green

### Week 3

- scaffold `chio-py`
- land Python vectors and transport/session foundation

### Week 4

- finish Python alpha API
- route Python peer through `chio-py`
- keep all live conformance areas green

### Week 5

- scaffold `chio-go`
- land Go invariants, transport, and first peer coverage

### Week 6

- expand Go conformance area coverage
- harden parity matrix, CI, examples, and alpha support docs

## Risk Kill Order

The main execution risks should be reduced in this order:

1. unclear parity definition
2. TS package API drift while the JS peer still owns real behavior
3. Python packaging complexity creeping in too early
4. Go scope blowing up into CGO or browser-like packaging work
5. parity claims being made without checked-in evidence

## Decision Rules During Execution

Use these rules to keep the roadmap on track:

- if a feature is needed only for byte-sensitive invariant equivalence, prefer `chio-binding-helpers`
- if a feature is about transport, callbacks, auth, tasks, or ergonomics, keep it native to the language SDK
- if a native bridge would delay package-backed remote-edge parity, defer it
- if Go support would force CGO before remote-edge shape is proven, defer that portion
- if parity cannot be proven with vectors or live conformance, do not claim it

## Exit State

At the end of this roadmap, the desired project state is:

- `chio-binding-helpers` is stable and still small
- `chio-ts` is the real JS/TS remote-edge package for current conformance behavior
- `chio-py` is the real Python remote-edge package for current conformance behavior
- `chio-go` exists as a real pure Go SDK foundation
- parity status is visible in the repo and backed by repeatable checks

That is the point where optional acceleration work becomes justified:

- WASM for TS
- PyO3 for Python
- CGO or C ABI for Go

Before that point, those would mostly add release burden without adding enough adoption value.
