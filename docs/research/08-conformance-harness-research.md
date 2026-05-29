# Conformance Harness Research

## Purpose

This document researches how ARC should build E8 Slice A:

- cross-language interoperability testing
- versioned spec-scenario testing
- generated compatibility reporting

It is grounded in:

- ARC's current shipped test surface
- the local `../rust-sdk` reference repository
- the current MCP spec

## Current ARC Baseline

ARC already has stronger repo-local integration coverage than it did when E8 was first planned.

The important current assets are:

- `crates/arc-cli/tests/mcp_serve.rs`
- `crates/arc-cli/tests/mcp_serve_http.rs`
- `crates/arc-cli/tests/mcp_auth_server.rs`
- `crates/arc-cli/tests/trust_cluster.rs`

What those tests already cover well:

- wrapped stdio MCP edge behavior
- remote Streamable HTTP edge behavior
- resources, prompts, completion, logging
- nested sampling and elicitation
- task-oriented execution
- auth-server and token-exchange flows
- distributed control-plane failover and replication

That means E8 should not rebuild basic integration confidence from scratch.

It should reuse this local suite as the implementation-controlled layer and add the missing external and report-driven layers on top.

## What Is Missing Today

ARC still lacks four things:

### 1. Real external peers

Current tests are overwhelmingly driven by ARC-owned harness logic and mock servers.

That is useful, but not enough to make ecosystem claims.

### 2. A scenario catalog

The repo has many strong end-to-end tests, but they are encoded as test code rather than as a reusable scenario inventory with stable IDs, tags, versions, and expected outcomes.

### 3. Generated compatibility reporting

The repo does not yet generate a compatibility matrix from execution artifacts.

As a result, compatibility status still has to be inferred from raw test files.

### 4. CI stratification for interop

There is no explicit split between:

- fast local correctness
- cross-language interop
- slower remote/auth/regression scenarios

That will matter once JS and Python orchestration is added.

## Official MCP Constraints the Harness Must Respect

The current MCP spec makes a few design requirements especially important for conformance:

- lifecycle ordering and capability negotiation are strict
- optional features are negotiated and must not be assumed
- HTTP transport behavior is versioned and capability-sensitive
- authorization behavior has discovery, challenge, token, and audience-binding rules
- tasks, notifications, and utility methods are separate protocol surfaces, not just optional metadata

Primary spec references:

- Lifecycle: <https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle>
- Authorization: <https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization>
- Tasks: <https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/tasks>

Implication for ARC:

The harness must test negotiated behavior, not just happy-path method availability.

## What the Local Rust SDK Gets Right

The local `../rust-sdk` repo is useful as a testing-shape reference.

Useful patterns worth copying:

### 1. Real JS and Python peer tests

`crates/rmcp/tests/test_with_js.rs` and `crates/rmcp/tests/test_with_python.rs` validate interoperability against actual external runtimes rather than only synthetic mocks.

ARC should copy that discipline.

### 2. Separate conformance binaries

The `conformance/src/bin/server.rs` and `conformance/src/bin/client.rs` layout is useful because it creates a stable test target for scenario-driven execution.

ARC should likely do the same through a dedicated harness crate instead of piling more orchestration into `arc-cli/tests`.

### 3. Published result artifacts

The `conformance/results/2026-02-25-rust-sdk-assessment.md` and remediation docs show the value of generated assessment output.

ARC should copy the reporting discipline, even if it does not copy the exact tier model.

### 4. Scenario naming and inventory

The rust-sdk assessment shows named scenario inventory such as:

- `server-tools-list`
- `server-prompts-get-with-args`
- `auth/scope-step-up`

ARC should adopt stable scenario IDs early so results remain comparable over time.

## What Not to Copy from the Local Rust SDK

ARC should not blindly copy:

### 1. Runtime assumptions

ARC has a different security center:

- capabilities
- guards
- signed receipts
- explicit trust-plane behavior

The harness must preserve those distinctions rather than flattening ARC into “just another MCP runtime.”

### 2. The tier audit model

The rust-sdk assessment mixes:

- conformance
- docs
- roadmap
- triage process
- release management

That may be useful for program management, but it is too broad for the first ARC conformance harness.

ARC should start with protocol and interoperability truth first.

### 3. One-SDK-centric truth

The local rust-sdk is useful as a reference peer.

It should not become the canonical oracle for protocol behavior.

The MCP spec remains the source of truth.

## Recommended Harness Architecture

## 1. Keep current ARC integration tests as the base layer

Do not replace:

- `mcp_serve.rs`
- `mcp_serve_http.rs`
- `mcp_auth_server.rs`
- `trust_cluster.rs`

Those are still the fastest way to localize implementation regressions.

## 2. Add a dedicated conformance layer above them

Use a separate harness with:

- scenario descriptors
- peer adapters
- artifact generation

This should not be modeled as one giant integration test file.

## 3. Treat peers as interchangeable adapters

The harness should have peer adapters for:

- JS
- Python
- Rust reference peer
- ARC self-controlled peers where needed

Scenarios should be written once and mapped onto peer adapters where possible.

## 4. Distinguish MCP-core and ARC-extension assertions

There should be two report lanes:

- MCP core compatibility
- ARC extension and trust semantics

That avoids overstating compatibility while still making ARC-specific guarantees visible.

## Proposed Scenario Families

## Family A: lifecycle and negotiation

- initialize
- initialized notification ordering
- protocol version mismatch
- negotiated capability absence
- ping before and after initialize

## Family B: primary server surfaces

- tools/list
- tools/call
- resources/list
- resources/read
- prompts/list
- prompts/get

## Family C: interactive client surfaces

- sampling/createMessage
- elicitation/create form mode
- elicitation/create URL mode
- notifications/elicitation/complete
- roots/list

## Family D: long-running operations

- tasks/get
- tasks/result
- tasks/cancel
- progress notifications
- cancellation notifications

## Family E: notification and catalog behavior

- resources/subscribe
- resources/unsubscribe
- notifications/resources/updated
- notifications/resources/list_changed
- notifications/prompts/list_changed
- notifications/tools/list_changed
- logging/setLevel
- log notifications

## Family F: remote and auth behavior

- Streamable HTTP initialize
- session reuse
- session rejection and stale session handling
- protected-resource metadata
- authorization-server metadata
- auth code with PKCE
- token exchange
- insufficient scope and step-up behavior

## Family G: ARC-specific trust behavior

- deny receipts
- child-request receipts
- cancelled vs incomplete outcomes
- distributed revocation effect
- shared budget effect

## Proposed Slice A Implementation Order

### Step 1

Create the scenario model and report model.

Without that, peer tests will sprawl and become another pile of ad hoc integration code.

### Step 2

Add one JS peer and one Python peer for the initial scenarios only.

Keep the first set deliberately small:

- initialize
- tools/list
- tools/call
- resources/list
- prompts/list

### Step 3

Generate the first Markdown matrix from JSON artifacts.

Do this before broadening coverage.

If the report shape is wrong, it is cheaper to fix early.

### Step 4

Expand to remote/auth and interactive surfaces.

That should come after the harness format and peer adapters are already stable.

## Main Risks

### Risk: conformance scope explodes

ARC now has a lot of surface area.

If Slice A tries to encode every existing integration test as a fixture immediately, it will stall.

Recommendation:

- publish an initial matrix first
- expand by scenario family after the first report exists

### Risk: external peers become flaky infrastructure

JS and Python environments are slower and more failure-prone than pure Rust tests.

Recommendation:

- use explicit peer bootstrap scripts
- keep PR suites small
- move larger auth/remote suites to nightly

### Risk: the report overstates compatibility

ARC has experimental and ARC-specific features on the edge.

Recommendation:

- separate standard MCP pass/fail from experimental extension coverage
- explicitly label `experimental`, `extension`, and `ARC-specific`

## Research Conclusion

ARC is ready for E8 Slice A.

Not because the problem is solved, but because the prerequisites are now genuinely in place:

- strong local integration coverage
- remote hosting
- task semantics
- nested flows
- auth server flows
- distributed control-plane behavior

The next highest-leverage move is to turn those repo-local guarantees into published compatibility evidence.

That means:

- scenario catalog first
- JS and Python peers second
- generated matrix third

Then use the failures to drive the rest of E8.
