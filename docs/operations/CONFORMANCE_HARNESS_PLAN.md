# Cross-Language Conformance Harness Plan

## Goal

Build the first real E8 Slice A execution plan:

- JS peer coverage
- Python peer coverage
- spec-fixture coverage
- generated compatibility reporting

The purpose is not to prove that Chio passes its own tests.

The purpose is to prove that:

- stock external MCP peers can interoperate with Chio
- Chio stays aligned with the MCP spec as it evolves
- compatibility claims are generated from artifacts instead of prose

## Why this comes next

Chio's remaining blockers are now adoption and proof, not missing core runtime primitives.

The repo already has strong local integration coverage in `crates/products/chio-cli/tests`, especially:

- `mcp_serve.rs`
- `mcp_serve_http.rs`
- `mcp_auth_server.rs`
- `trust_cluster.rs`

Those tests prove that the implementation behaves coherently end to end.

They do not yet prove:

- interoperability with external JavaScript peers
- interoperability with external Python peers
- published compatibility status by feature area
- stable regression detection against versioned spec scenarios

That is what this harness must add.

## Principles

### 1. Generated truth, not hand-written truth

The compatibility matrix must be produced from test artifacts.

No manually maintained pass/fail table should be treated as authoritative.

That includes expected gaps.

If a scenario is intentionally tracked as an expected failure for a specific deployment shape, the generated matrix should surface it as `xfail`, not hide it in prose or flatten it into an undifferentiated failure.

### 2. Separate peer interoperability from Chio self-tests

Keep three layers distinct:

- local Chio integration tests
- external peer interoperability tests
- versioned spec-scenario conformance tests

That separation prevents an external-peer failure from being misread as a core runtime regression.

### 3. Test both Chio deployment shapes

The harness must cover:

- wrapped MCP mode
- native Chio-backed MCP edge mode
- remote HTTP hosting where relevant

If a scenario only works on one path, the report should say that explicitly.

### 4. Preserve security semantics in the report

Chio is not only an MCP shim.

The harness should record both:

- MCP compatibility outcome
- Chio-specific trust outcome when relevant

Examples:

- deny receipts exist
- nested child lineage exists
- auth step-up or insufficient-scope behavior is correct

### 5. Version scenarios explicitly

Scenarios should carry spec-version metadata.

That lets Chio track:

- current latest MCP behavior
- older compatibility requirements where still relevant
- extension or experimental scenarios separately from core spec scenarios

## Scope

## In scope

- fixture-driven interoperability tests
- JS and Python peers
- generated JSON artifacts
- generated Markdown compatibility matrix
- scenario tagging by transport, feature area, peer role, and spec version
- CI-friendly separation between fast and slow suites

## Out of scope

- native Chio authoring SDK
- migration examples
- transport redesign
- multi-region conformance infrastructure

Those remain later E8 or E9 work.

## Proposed Repo Layout

```text
tests/
  conformance/
    README.md
    scenarios/
      lifecycle/
      tools/
      resources/
      prompts/
      sampling/
      elicitation/
      tasks/
      auth/
      subscriptions/
      remote/
    peers/
      js/
      python/
    fixtures/
      policies/
      manifests/
      transcripts/
    reports/
      .gitkeep

crates/
  chio-conformance/
    src/
      lib.rs
      scenario.rs
      runner.rs
      report.rs
      peer/
      fixture/
```

Notes:

- `chio-conformance` should own scenario loading, report generation, and peer process orchestration.
- The existing `chio-cli/tests` suite should remain intact and continue to act as the implementation-focused integration suite.
- External peer assets should live under `tests/conformance/peers`, not inside `crates/products/chio-cli/tests`.

## Test Layers

### Layer 1: local contract tests

Keep the current Chio-controlled integration tests as the fast correctness layer.

Primary purpose:

- validate internal behavior cheaply
- localize regressions before external orchestration starts

Existing assets to reuse:

- `crates/products/chio-cli/tests/mcp_serve.rs`
- `crates/products/chio-cli/tests/mcp_serve_http.rs`
- `crates/products/chio-cli/tests/mcp_auth_server.rs`
- `crates/products/chio-cli/tests/trust_cluster.rs`

### Layer 2: peer interoperability tests

Run real JS and Python peers against Chio.

Initial target permutations:

- JS client -> Chio stdio-wrapped server
- JS client -> Chio remote HTTP edge
- Python client -> Chio stdio-wrapped server
- Python client -> Chio remote HTTP edge
- Chio client/wrapper -> JS server
- Chio client/wrapper -> Python server

This layer proves that wire behavior and lifecycle behavior are not only self-consistent, but interoperable.

### Layer 3: spec-scenario conformance tests

Run scenario catalogs with explicit expected outcomes.

These should not depend on one peer implementation.

They should encode MCP expectations such as:

- initialization ordering
- negotiated capability use
- tool call result shape
- task lifecycle shape
- auth discovery and token flow behavior
- notification semantics
- streamable HTTP session behavior

### Layer 4: generated reporting

Every harness run should emit:

- raw JSON results
- summarized Markdown matrix
- failure details grouped by surface area

The Markdown report is for humans.

The JSON artifact is the source of truth.

Current shipped areas:

- MCP core: remote HTTP request/response coverage against live JS and Python peers
- Tasks: remote HTTP task coverage with explicit `xfail` support for known wrapped-tool gaps
- Auth: remote HTTP authorization coverage against the local OAuth-capable edge
- Notifications: remote HTTP notification and subscription coverage against a wrapped server that emits real upstream change notifications
- Nested callbacks: remote HTTP sampling, elicitation, and roots callback coverage

## Scenario Taxonomy

Every scenario should declare:

- `id`
- `title`
- `area`
- `spec_versions`
- `transport`
- `peer_role`
- `deployment_mode`
- `required_capabilities`
- `expected_outcome`
- `notes`

Recommended top-level areas:

- `lifecycle`
- `tools`
- `resources`
- `prompts`
- `sampling`
- `elicitation`
- `tasks`
- `auth`
- `subscriptions`
- `remote`
- `trust_extensions`

`trust_extensions` should be clearly separated from core MCP pass/fail so the matrix does not blur standard compliance with Chio-native guarantees.

## Initial Scenario Areas

## MCP Core: minimum credible matrix

Goal:

- prove that the harness itself works
- publish the first generated report

Scenarios:

- initialize
- ping
- tools/list
- tools/call simple text
- resources/list
- resources/read
- prompts/list
- prompts/get
- remote initialize over HTTP

Peers:

- one JS peer
- one Python peer

## Tasks And Eventing: feature-rich parity

Scenarios:

- sampling/createMessage
- elicitation/create form mode
- URL-mode elicitation completion
- tasks/get/result/cancel
- resources/subscribe and updates
- prompts/resources list_changed
- completion/complete
- logging/setLevel and notifications

## Auth And Remote Hosting

Scenarios:

- protected-resource metadata
- authorization-server metadata
- authorization code with PKCE
- token exchange
- scope challenge handling
- wrong audience rejection
- session reuse / stale session behavior

## Trust Extensions

Scenarios:

- deny receipt emission
- child-request receipt lineage
- cancelled vs incomplete terminal semantics
- shared control-plane revocation effect
- budget enforcement visibility

This area should appear in separate report sections so it does not contaminate MCP pass-rate claims.

## Compatibility Matrix Design

The matrix should be keyed by:

- feature area
- scenario
- peer language/runtime
- client/server role
- deployment mode
- transport
- spec version

Suggested status values:

- `pass`
- `fail`
- `unsupported`
- `skipped`
- `xfail`

Suggested dimensions:

- peer: `js`, `python`, `rust-reference`, `chio-self`
- role: `client_to_chio_server`, `chio_client_to_server`
- mode: `wrapped_stdio`, `native_stdio`, `remote_http`

## CI Structure

Use a staged CI model.

### Job A: fast local integration

- existing workspace tests
- no external runtime bootstrapping

### Job B: JS interop

- install Node dependencies once
- run selected JS peer scenarios
- emit JSON result artifact

### Job C: Python interop

- install Python environment once
- run selected Python peer scenarios
- emit JSON result artifact

### Job D: matrix generation

- merge artifacts from A, B, and C
- emit Markdown summary
- fail CI on any non-allowed regression

### Job E: nightly extended suite

- longer remote/auth/subscription scenarios
- slower recovery/failover or multi-process remote tests

## Acceptance Criteria for Slice A

- the repo contains a fixture format, not only ad hoc tests
- at least one JS peer and one Python peer run in CI
- the first generated matrix is committed as an artifact or report output
- the report distinguishes MCP-core scenarios from Chio-extension scenarios
- failures are localized by area and peer, not buried inside one large integration test

## Risks

### Risk: the harness overfits to one external SDK

Mitigation:

- use multiple peers
- keep scenario expectations spec-driven
- avoid importing another SDK's exact helper abstractions

### Risk: slow and flaky orchestration

Mitigation:

- keep a small MCP core suite for PRs
- move heavy remote/auth scenarios to nightly
- require deterministic fixture setup and explicit timeouts

### Risk: ambiguous report semantics

Mitigation:

- separate MCP-core from Chio-specific assertions
- record exact scenario IDs and versions in artifacts
- use machine-readable statuses and only derive Markdown from them

## Recommended First Deliverables

1. `tests/conformance/README.md`
2. `tests/conformance/scenarios/` with MCP core scenarios
3. `tests/conformance/peers/js/`
4. `tests/conformance/peers/python/`
5. `crates/tooling/chio-conformance` runner
6. generated `docs/reports/compatibility-matrix.md`

## Bottom Line

The first E8 slice should not start by polishing SDK ergonomics.

It should start by building a harness that can answer, continuously and with artifacts:

- which MCP scenarios Chio passes
- with which peers
- over which transports
- in which deployment modes

That is the minimum proof layer required before broader migration and SDK work makes sense.
