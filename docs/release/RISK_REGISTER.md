# Risk Register

This register tracks known risks for the v1-only pre-release candidate.

## Critical Engineering Backlog

| Risk | Severity | Mitigation status | Notes |
| --- | --- | --- | --- |
| TOCTOU between guard verdict and tool execution in wrapper integrations | CRITICAL | partially mitigated | Kernel dispatch now verifies and consumes `ToolCallRequest::execution_nonce` in strict mode before tool-server invocation. `chio mcp wrap --strict-execution-nonce` now executes allowed calls through that nonce-presenting kernel path. The default `chio mcp wrap` compatibility path and advisory `/v1/evaluate` remain weaker because they do not execute through nonce consumption. |
| Agent memory stores ungoverned (RAG, scratchpads, conversation history) | HIGH | planned | Memory-write constraints and read receipts |
| Sidecar bypass: agents can call tools without mediation | HIGH | open | Tool-server auth, network enforcement, honest trust taxonomy |
| No PyPI/npm packages published; SDKs path-only | CRITICAL | open | CI publishing for Python and TypeScript SDKs |
| No `MockChioClient` or dry-run testing without live kernel | HIGH | planned | `chio_sdk.testing` fixtures |
| Fanout lane (lane c) inbound-join confidentiality residual (iroh-gossip 0.101) | LOW (informational) | contained | SCOPE: library-only. The fanout lane is NOT exposed through the shipped `chio` CLI (the `IrohLane` enum has only Pheromone/Revocation/Bilateral; `parse_iroh_lanes` rejects the rest), so the shipped binary does NOT leak treaty traffic today. BOUND: a federation-admitted non-party can PASSIVELY OBSERVE forwarded frames but CANNOT INJECT an accepted frame (receive-side treaty-party gate, fanout.rs:592-597; swarm/treaty binding, fanout.rs:717-727); topic-per-treaty routing keeps other treaties' traffic off the swarm (observe-only). CAUSE: iroh-gossip 0.101 exposes no inbound-admission hook (fanout.rs:59-97). Upstream FR: see the anchor in fanout.rs + ADAPTER-SPEC section 7. RE-RATE TRIGGER: re-rate to HIGH and revisit this wording if lane c (fanout) is ever wired into the `chio` CLI or any shipped product surface, or if any release claim depends on treaty confidentiality against a passive federation-admitted observer. |

## Release and qualification risks

| Risk | Current posture | Mitigation |
| --- | --- | --- |
| Hosted workflow results are not observable from every local environment | local launch evidence is complete, but external publication stays on hold until hosted CI is green | require hosted `CI` and `Release Qualification` success before tagging |
| Cluster replication remains deterministic leader/follower rather than consensus-based | acceptable for supported deployment scope, not for stronger distributed-trust claims | keep consensus work out of release claims and future milestone separately |
| Enterprise federation does not yet provide automatic SCIM lifecycle management | acceptable for current provider-admin and observability scope | keep provider-admin records explicit and fail closed when incomplete |
| Portable trust does not synthesize cross-issuer reputation | intentional design choice, not a regression | document per-credential evaluation semantics and avoid broader claims |
| A2A still lacks custom auth beyond the shipped matrix | known boundary for partner integrations | keep unsupported schemes explicit and fail closed during discovery/invocation |
| Formal verification depends on audited external assumptions and strict Rust-linkage gates | controlled by the implementation-linked proof manifest, P1-P10 theorem inventory, assumption registry, Aeneas production extraction plus equivalence, public Kani harnesses, no-bypass checks, executable tests, and qualification artifacts | keep protocol, partner, website, and release claims tied to `formal/proof-manifest.toml`, `formal/assumptions.toml`, `formal/theorem-inventory.json`, `target/formal/proof-report.json`, `docs/reference/CLAIM_REGISTRY.md`, and strict verification gates |
| Distributed revocation convergence depends on weak-fair connected opportunities, clock skew, and partition healing | the bounded model and one-origin production trace projection are implemented, but temporal reliability and multi-origin production refinement remain unestablished | keep `ASSUME-NETWORK-TRANSPORT` required; do not claim end-to-end distributed revocation verification or a finite evaluation-count bound |
| Untrusted wasm guards execute inside the wasmtime process boundary | Chio models and tests its typed verdict mapping and resource fail-closure, but wasmtime interpreter, compiler, JIT, and sandbox correctness remain `ASSUME-WASM-ENGINE` | keep guards blocking unless explicitly advisory, retain fuel and memory caps, run both wasm escape and structure-aware fuzz targets, and prohibit full engine information-flow claims |

## Formal Verification Claim Rules

This risk is considered controlled for the current release only under these
rules:

- do not describe Chio as formally verified without also naming the published
  audited assumptions and implementation-linked boundary
- do not say P1-P10 prove concrete crypto libraries, OS clocks, TLS, SQLite,
  subprocess isolation, hosted registries, external chains, clustering, or
  settlement from first principles
- do not say the wasm boundary theorems verify wasmtime internals or establish
  full engine information-flow non-interference
- do not say Creusot/Kani production refinement is complete unless the strict
  Rust verification lane has actually passed in CI; release qualification
  enforces this with protected strict report generation immediately followed
  by `scripts/check-proof-report.sh --require-strict`, which validates report
  structure and source binding without replaying the proof commands
- do say Chio's security-critical protocol semantics are formally verified and
  implementation-linked, subject to `formal/proof-manifest.toml`,
  `formal/assumptions.toml`, and `formal/theorem-inventory.json`
- do require the proof report to include gate status, tool versions, theorem
  source locations, tracked artifact hashes, and generated Aeneas artifact
  hashes before using release-facing formal claims
- do say runtime and partner-facing claims outside that boundary are backed by
  Rust tests, conformance tests, smoke tests, and release qualification
- do not describe distributed revocation convergence as assumption-free or
  end-to-end verified while `ASSUME-NETWORK-TRANSPORT` is required
