# Example Surface Matrix

This matrix maps the examples in [`examples/`](./) to the Chio surface each one teaches. The first table covers the core teaching examples (flagships, the `hello-*` family, and the guard examples); the [Specialized and integration examples](#specialized-and-integration-examples) table below it covers the narrower demos and integration references.

Support directories such as [`_shared/`](./_shared/), [`policies/`](./policies/), and [`run-hello-smokes.sh`](./run-hello-smokes.sh) are intentionally excluded because they are scaffolding rather than teaching examples.

| Example | Kind | Chio surfaces taught | What it demonstrates | Primary run path |
| --- | --- | --- | --- | --- |
| [`agent-commerce-network/`](./agent-commerce-network/) | Flagship | `trust serve`, `api protect`, MCP edge, evidence review, federation-style artifact flow | Real multi-party economic workflow with approvals, budgets, settlement, disputes, and reviewer verification | [`README.md`](./agent-commerce-network/README.md) |
| [`internet-of-agents-incident-network/`](./internet-of-agents-incident-network/) | Flagship | recursive delegation, OpenAI SDK orchestration, MCP internal tools, ACP external jobs, offline evidence review | Cross-org incident response with a live happy path for customer-to-provider authority narrowing and "internet of agents" execution contracts | [`README.md`](./internet-of-agents-incident-network/README.md) |
| [`internet-of-agents-web3-network/`](./internet-of-agents-web3-network/) | Flagship | `trust serve`, `api protect`, MCP HTTP edge, recursive delegation, RFQ routing, x402 requirements, web3 settlement dispatch, passports, reputation, federation, budgets, behavioral feed, guardrails, optional Base Sepolia evidence | Four-org Chio-mediated service order with multi-provider RFQ selection, two-hop subcontracting, dispute remediation, observability, adversarial controls, and settlement dispatch bound to the Chio web3 validation ladder | [`README.md`](./internet-of-agents-web3-network/README.md) |
| [`hello-tool/`](./hello-tool/) | Native service | Native Chio service builder, manifest signing, manifest pricing | Native Chio tool/resource/prompt registration without wrapped MCP | [`README.md`](./hello-tool/README.md) |
| [`docker/`](./docker/) | Quickstart topology | `trust serve`, hosted MCP edge, receipt dashboard | Smallest containerized governed call path with live receipt inspection | [`README.md`](./docker/README.md) |
| [`anthropic-sdk/`](./anthropic-sdk/) | Ecosystem client | Hosted Chio session, tool mapping, trust receipt lookup | Claude tool use over Chio-governed hosted tools | [`README.md`](./anthropic-sdk/README.md) |
| [`openai-compatible/`](./openai-compatible/) | Ecosystem client | Hosted Chio session, OpenAI-compatible function mapping, trust receipt lookup | OpenAI-style function calling over Chio-governed hosted tools | [`README.md`](./openai-compatible/README.md) |
| [`langchain/`](./langchain/) | Ecosystem client | Python Chio SDK, hosted HTTP edge, trust receipt lookup | LangChain `StructuredTool` execution while Chio remains in the enforcement path | [`README.md`](./langchain/README.md) |
| [`hello-trust-control/`](./hello-trust-control/) | Control-plane adjunct | Trust capability issuance, status, revocation, `chio check`, `chio evidence verify` | Direct trust-plane lifecycle plus offline receipt verification without an app surface | [`smoke.sh`](./hello-trust-control/smoke.sh) |
| [`hello-receipt-verify/`](./hello-receipt-verify/) | Control-plane adjunct | Offline evidence verification, receipt lineage inspection, tamper detection | Verify a captured evidence package locally and prove that tampering fails | [`smoke.sh`](./hello-receipt-verify/smoke.sh) |
| [`hello-openapi-sidecar/`](./hello-openapi-sidecar/) | HTTP sidecar | `chio api protect` with OpenAPI, sidecar receipts, capability-gated side effects | Governing a plain upstream app directly from an OpenAPI spec, with no framework SDK in the app. Recommended first web-backend path. | [`smoke.sh`](./hello-openapi-sidecar/smoke.sh) |
| [`hello-fastapi/`](./hello-fastapi/) | HTTP framework | `chio-asgi`, `chio-fastapi` | FastAPI-native Chio interception and receipt-bearing request handling. Recommended second web-backend path after the sidecar example. | [`smoke.sh`](./hello-fastapi/smoke.sh) |
| [`hello-django/`](./hello-django/) | HTTP framework | `chio-django` | Django middleware-style Chio governance on safe and side-effect routes | [`smoke.sh`](./hello-django/smoke.sh) |
| [`hello-fastify/`](./hello-fastify/) | HTTP framework | `@chio-protocol/fastify` | Fastify plugin-based Chio governance with receipt-bearing routes | [`smoke.sh`](./hello-fastify/smoke.sh) |
| [`hello-elysia/`](./hello-elysia/) | HTTP framework | `@chio-protocol/elysia` | Elysia integration with Chio request governance and sidecar-backed receipts | [`smoke.sh`](./hello-elysia/smoke.sh) |
| [`hello-express/`](./hello-express/) | HTTP framework | `@chio-protocol/express` | Express middleware path for deny/allow flows with receipts | [`smoke.sh`](./hello-express/smoke.sh) |
| [`hello-chi/`](./hello-chi/) | HTTP framework | `chio-go-http` | Go `chi` integration with Chio HTTP enforcement | [`smoke.sh`](./hello-chi/smoke.sh) |
| [`hello-spring-boot/`](./hello-spring-boot/) | HTTP framework | `chio-spring-boot` | JVM/Spring Boot Chio filter chain on safe and governed routes | [`smoke.sh`](./hello-spring-boot/smoke.sh) |
| [`hello-dotnet/`](./hello-dotnet/) | HTTP framework | `ChioMiddleware` | ASP.NET Chio middleware for allow/deny and receipt-bearing responses | [`smoke.sh`](./hello-dotnet/smoke.sh) |
| [`hello-drogon/`](./hello-drogon/) | HTTP framework | `sdks/cpp/chio-drogon` | C++ Drogon middleware using `chio::drogon::ChioMiddleware`; local smoke skips when CMake or Drogon is unavailable | [`smoke.sh`](./hello-drogon/smoke.sh) |
| [`hello-mcp/`](./hello-mcp/) | Protocol edge | MCP edge runtime | Authoritative MCP request handling over JSON-RPC with Chio semantics | [`smoke.sh`](./hello-mcp/smoke.sh) |
| [`hello-a2a/`](./hello-a2a/) | Protocol edge | A2A edge runtime | Authoritative A2A send plus deferred task lifecycle through Chio | [`smoke.sh`](./hello-a2a/smoke.sh) |
| [`hello-acp/`](./hello-acp/) | Protocol edge | ACP edge runtime | ACP invoke plus deferred stream/resume lifecycle through Chio | [`smoke.sh`](./hello-acp/smoke.sh) |
| [`guards/tool-gate/`](./guards/tool-gate/) | Guard example | `chio-guard-sdk` basic verdict logic | Tool-name-based allow/deny policy in a tiny WASM guard | [`src/lib.rs`](./guards/tool-gate/src/lib.rs) |
| [`guards/enriched-inspector/`](./guards/enriched-inspector/) | Guard example | `chio-guard-sdk` enriched fields + host functions | Enriched request inspection and host-function-based path blocking in a WASM guard | [`src/lib.rs`](./guards/enriched-inspector/src/lib.rs) |

## Specialized And Integration Examples

These examples are narrower than the core set above: they target a single integration point, a federation slice, or an evidence-format handoff, and most run as a one-shot fixture or packaging check rather than a long-lived service.

| Example | Kind | Chio surfaces taught | What it demonstrates | Primary run path |
| --- | --- | --- | --- | --- |
| [`bilateral-invocation/`](./bilateral-invocation/) | Federation demo | Bilateral cosign, DSSE signature-slice envelope, partial local verifier | Local end-to-end bilateral cosigned invocation between two `did:chio` kernels, printing the verdict, lease, and wire envelope | [`src/main.rs`](./bilateral-invocation/src/main.rs) |
| [`chio-3vendor/`](./chio-3vendor/) | Federation demo | `chio-attest-loopback` proof packages, selective disclosure, pheromone relay fixtures | Deterministic three-vendor (buyer, two providers, auditor) attestation and bilateral-cosign fixture flow | [`README.md`](./chio-3vendor/README.md) |
| [`chiodome-bilateral/`](./chiodome-bilateral/) | Federation demo | `chio_federation::bilateral_dsse`, Web3 checkpoint statement, `chio mcp serve` policy wrapper | Cross-org refund cosign envelope plus an `mcp-remote` stdio-to-HTTP bridge around a local KB MCP | [`README.md`](./chiodome-bilateral/README.md) |
| [`cross-provider-policy/`](./cross-provider-policy/) | Policy demo | One Chio policy evaluated across eight native provider adapters | Byte-equal verdicts for semantically equivalent tool calls across OpenAI, Anthropic, Bedrock, Gemini, Mistral, Groq, Ollama, and Cohere fixtures, with no live credentials | [`README.md`](./cross-provider-policy/README.md) |
| [`eval-receipt-ingest/`](./eval-receipt-ingest/) | Evidence handoff | `chio.eval-report.bundle.v1`, eval-receipt sign and verify | Packages verdict-matrix receipt fixtures into a signed eval-report bundle and round-trips it through `chio-eval-receipt verify-fixture` | [`metr/README.md`](./eval-receipt-ingest/metr/README.md) |
| [`istio-ext-authz/`](./istio-ext-authz/) | Mesh integration | `chio-envoy-ext-authz` gRPC adapter, Istio `AuthorizationPolicy` CUSTOM action | Routing Istio ext_authz checks through the Chio adapter so passing responses carry an `x-chio-receipt-id` header | [`README.md`](./istio-ext-authz/README.md) |
| [`otel-genai/`](./otel-genai/) | Observability integration | OTel GenAI contract, receipt and span bidirectional lookup | Looking up a GenAI tool-call span by receipt id and a signed receipt by span id through the OTLP export path | [`README.md`](./otel-genai/README.md) |
| [`tee-sidecar/`](./tee-sidecar/) | Packaging smoke | `chio-tee` container packaging, sidecar TOML, spool volume | Building and wiring the TEE sidecar container next to an application container | [`README.md`](./tee-sidecar/README.md) |

## Suggested Learning Order

1. [`hello-openapi-sidecar/`](./hello-openapi-sidecar/) to understand the sidecar model directly.
2. [`hello-fastapi/`](./hello-fastapi/) for the first framework-native follow-on.
3. One additional HTTP framework hello that matches your stack.
4. [`hello-trust-control/`](./hello-trust-control/) and [`hello-receipt-verify/`](./hello-receipt-verify/) for the control-plane and evidence model.
5. [`hello-mcp/`](./hello-mcp/), [`hello-a2a/`](./hello-a2a/), or [`hello-acp/`](./hello-acp/) for protocol-native surfaces.
6. [`hello-tool/`](./hello-tool/) when you want to move from wrapped adapters to a native Chio service.
7. [`agent-commerce-network/`](./agent-commerce-network/) when you want the full real-world composition.
8. [`internet-of-agents-incident-network/`](./internet-of-agents-incident-network/) when you want the full recursive delegation and cross-org "internet of agents" composition.
9. [`internet-of-agents-web3-network/`](./internet-of-agents-web3-network/) when you want Chio-mediated recursive agent commerce, trust routing, and web3 settlement evidence in one qualification bundle.
