# E8: Migration, Conformance, and SDKs

## Status

In progress.

Slice A research and planning are now documented in:

- [CONFORMANCE_HARNESS_PLAN.md](../../operations/CONFORMANCE_HARNESS_PLAN.md)
- [../research/08-conformance-harness-research.md](../../research/08-conformance-harness-research.md)
- [../research/09-compatibility-matrix-design.md](../../research/09-compatibility-matrix-design.md)

The first implementation slice is now scaffolded:

- `crates/chio-conformance` exists as the scenario/result/report model crate
- `tests/conformance/` now contains the initial scenario catalog
- JS and Python peer directories now exist as explicit harness targets
- the repo can already generate a Markdown compatibility matrix from JSON result artifacts

The next live execution slice is now shipped:

- `tests/conformance/fixtures/wave1/` contains a reusable upstream MCP fixture and policy
- the JS and Python peers now execute real Streamable HTTP client scenarios
- `chio-conformance-runner` boots `chio mcp serve-http`, runs both peers, collects JSON artifacts, and generates a Markdown matrix
- `crates/chio-conformance/tests/wave1_live.rs` validates the end-to-end harness against a live local Chio edge

The next compatibility-expansion slice is now underway:

- `tests/conformance/scenarios/wave2/` covers task-oriented remote HTTP scenarios
- `tasks-call-get-result` is green across the JS and Python peers
- `tasks-cancel` is now green across the JS and Python peers under the bounded pre-execution cancellation window
- the generated matrix now distinguishes hard failures from expected failures instead of flattening both into `fail`

The next auth/discovery slice is now shipped:

- `tests/conformance/scenarios/wave3/` covers remote HTTP authorization behavior
- the conformance runner now supports `--auth-mode oauth-local`
- the JS and Python peers now execute protected-resource metadata discovery, authorization-server metadata discovery, auth-code + PKCE session initialization, token-exchange session initialization, and unauthenticated challenge validation
- `crates/chio-conformance/tests/wave3_auth_live.rs` validates the end-to-end OAuth-backed remote edge against live JS and Python peers
- the generated auth matrix is green at `tests/conformance/reports/generated/wave3-auth.md`

The next notification/subscription slice is now shipped:

- `tests/conformance/scenarios/wave4/` covers remote HTTP notifications and resource subscriptions
- the wrapped fixture now advertises `resources.subscribe`, resource `listChanged`, prompt `listChanged`, and tool `listChanged`, and emits upstream notifications through a real wrapped tool path
- the JS and Python peers now validate `resources/subscribe`, forwarded `notifications/resources/updated`, and forwarded resource/tool/prompt `list_changed` notifications
- `crates/chio-conformance/tests/wave4_notifications_live.rs` validates the end-to-end notification slice against live JS and Python peers
- the generated notifications matrix is green at `tests/conformance/reports/generated/wave4-notifications.md`

The next nested-flow slice is now shipped:

- `tests/conformance/scenarios/wave5/` covers remote HTTP nested-flow interoperability
- the wrapped fixture now issues live `sampling/createMessage`, form-mode `elicitation/create`, URL-mode `elicitation/create`, `notifications/elicitation/complete`, and `roots/list` requests through real wrapped tool calls
- the JS and Python peers now respond to nested sampling, elicitation, and roots callbacks over remote HTTP and validate the resulting tool outputs
- `crates/chio-conformance/tests/wave5_nested_flows_live.rs` validates the end-to-end nested-flow slice against live JS and Python peers
- the generated nested-flows matrix is green at `tests/conformance/reports/generated/wave5-nested-flows.md`
- the remote HTTP runtime now allows notification/response POSTs to temporarily own a stream when no request stream is active, which closes the `notifications/initialized` -> `roots/list` gap that was blocking remote nested-flow coverage

This is the adoption epic.

Preconditions expected before starting:

- remote MCP-compatible hosting exists or is close enough for realistic deployment tests
- wrapped and direct stdio paths are already feature-rich and well covered locally

What this epic is for:

- prove compatibility claims against real peers
- make native Chio server authoring cheaper than low-level trait wiring
- publish migration paths instead of expecting users to reverse-engineer them from tests

## Suggested issue title

`E8: build conformance harness, migration fixtures, and native authoring SDK`

## Problem

Chio now has a strong local implementation story, but its compatibility and adoption story still depends too much on repo-local confidence.

That blocks:

- credible claims against existing MCP ecosystems
- easy regression detection across client/server implementations
- third-party native Chio adoption

## Outcome

By the end of E8:

- compatibility claims are generated from tests and fixtures
- Chio has a published interop matrix against real MCP peers
- native Chio providers can be authored through a higher-level service/router model
- migration from wrapped MCP servers to native Chio servers is documented and example-backed

## Scope

In scope:

- cross-language interop fixtures
- conformance reporting
- migration guides and examples
- higher-level native authoring abstractions
- generated helpers or schema bindings if they materially improve ergonomics

Out of scope:

- remote transport primitives themselves
- deep performance tuning
- release-candidate hardening beyond compatibility-critical gaps

## Primary files and areas

- `crates/chio-mcp-adapter`
- `crates/chio-kernel`
- new SDK or helper crates if added
- `tests`
- `docs`

## Sequencing note

This epic should start with proof before polish.

Order:

1. build the interop harness and matrix
2. use the failures to drive compatibility fixes
3. then add the native authoring SDK surface once the runtime contract is stable enough

The most important practical implication is:

- do not start by adding more ad hoc integration tests
- start by creating a scenario model, peer adapters, and generated reporting

## Proposed implementation slices

### Slice A: interop harness

Requirements:

- fixture-driven method and notification coverage
- cross-language peers in at least JavaScript, Python, and Rust
- compatibility reports generated from test results

Responsibilities:

- test both wrapped MCP flows and native Chio-backed MCP edge flows
- make failures easy to localize by surface area

More detailed execution guidance now exists:

- keep the current `crates/chio-cli/tests` suite as the fast local integration layer
- add a dedicated conformance harness above it, not inside it
- start with a small initial matrix before expanding to auth and advanced notifications
- separate MCP-core scenarios from Chio-extension scenarios in the generated report

### Slice B: migration fixtures

Requirements:

- representative wrapped-server deployments
- migration docs from MCP server to wrapped Chio edge
- migration docs from wrapped MCP server to native Chio provider

Responsibilities:

- show realistic incremental adoption paths
- keep examples small enough to stay maintained

### Slice C: native authoring SDK

Requirements:

- higher-level service abstraction over current low-level provider traits
- handler/router ergonomics for tools and contextual surfaces
- preserve direct access to lower-level primitives where necessary

Responsibilities:

- improve developer ergonomics without hiding the kernel/security model
- keep the public surface coherent across tools, resources, prompts, and nested flows

## Task breakdown

### `T8.1` Cross-language compatibility suite

- add JS peer tests
- add Python peer tests
- add Rust peer tests against an external MCP runtime where helpful
- publish a generated compatibility matrix

Recommended execution order inside `T8.1`:

1. define scenario descriptors and JSON result artifacts
2. add one JS peer and one Python peer for the initial scenarios only
3. generate the first Markdown matrix from JSON artifacts
4. expand to remote/auth and interactive scenario families after the report shape is stable

### `T8.2` Security and behavior conformance suite

- denial receipts
- nested-flow lineage
- stream terminal states
- cancellation and task semantics
- remote-session auth behavior once E7 lands

### `T8.3` Migration docs and fixtures

- wrapped MCP deployment replacement guide
- native Chio provider example set
- explicit “when to wrap vs when to port” guidance

### `T8.4` Native authoring SDK

- introduce service/router abstractions over low-level provider traits
- add typed handler helpers for tools, resources, prompts, and nested-flow callbacks
- preserve escape hatches for advanced use cases

## Reference patterns

Useful references to study, not copy blindly:

- RMCP’s JS and Python peer tests
- RMCP’s published compatibility reporting style
- RMCP’s service/handler layering for server authoring ergonomics

Chio should take the harness discipline and SDK ergonomics, not import another runtime’s assumptions wholesale.

## Dependencies

- depends on E7 remote runtime being usable enough for realistic deployment tests
- depends on E3 through E6 already being stable enough to freeze fixtures around

## Risks

- writing a compatibility matrix that overfits Chio’s own behavior instead of the spec
- building a high-level SDK before the runtime contract is stable
- adding abstractions that hide security-critical details from authors

## Mitigations

- drive the matrix from real peer fixtures and spec scenarios
- keep SDK layers thin and composable
- document the authority/receipt model directly in SDK examples

## Acceptance criteria

- compatibility matrix is generated from tests, not hand-written
- at least one JS peer and one Python peer are exercised in CI
- migration docs cover both wrapped MCP and native Chio paths
- native authoring examples use a higher-level service abstraction instead of only low-level traits

## Definition of done

- interop harness merged
- generated compatibility report merged
- migration guides and maintained examples merged
- native authoring SDK surface merged
- cross-language compatibility CI passing
