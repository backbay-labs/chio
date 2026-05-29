# Examples

If you only want the supported first steps:

- Docker smoke path: [`docker/`](./docker/)
- Web backend path: [`hello-openapi-sidecar/`](./hello-openapi-sidecar/), then [`hello-fastapi/`](./hello-fastapi/)
- Native Chio tool example: [`hello-tool/`](./hello-tool/)

This directory has two layers:

- flagship examples that show Chio as a real control plane in a multi-process or multi-operator setting
- small `hello-*` examples that isolate one surface at a time and can be understood in a few minutes

For a one-page map of what each example teaches, see [EXAMPLE_SURFACE_MATRIX.md](./EXAMPLE_SURFACE_MATRIX.md).

For web backends, the supported order is:

1. [`hello-openapi-sidecar/`](./hello-openapi-sidecar/)
2. [`hello-fastapi/`](./hello-fastapi/)

See [`docs/guides/WEB_BACKEND_QUICKSTART.md`](../docs/guides/WEB_BACKEND_QUICKSTART.md) for the shared verification flow.

## Current Flagship Examples

- [`agent-commerce-network/`](./agent-commerce-network/): buyer/provider/reviewer topology with approvals, budgets, settlement, federation, and live receipt capture
- [`internet-of-agents-incident-network/`](./internet-of-agents-incident-network/): recursive cross-org incident-response network with a live happy path for OpenAI SDK orchestration, MCP tools, ACP provider jobs, and offline review
- [`internet-of-agents-web3-network/`](./internet-of-agents-web3-network/): four-org Chio-mediated agent-commerce web3 topology with RFQ routing, subcontracted review, trust-control, API sidecars, MCP edges, passports, reputation, federation, budgets, x402-style payment proof, guardrails, and optional Base Sepolia evidence
- [`hello-tool/`](./hello-tool/): minimal Rust-native tool example
- [`docker/`](./docker/): local containerized smoke path
- [`anthropic-sdk/`](./anthropic-sdk/), [`openai-compatible/`](./openai-compatible/), [`langchain/`](./langchain/): ecosystem-specific slices

## Hello Example Contract

The `hello-*` family follows one shared contract:

1. Expose one safe read path such as `GET /hello` or a discovery/list call.
2. Expose one governed path such as `POST /echo`, `tool/invoke`, or `message/send`.
3. Show the deny path without a capability token where applicable.
4. Show the allow path with a capability token or authoritative session.
5. Capture or print at least one Chio receipt or receipt id.
6. Ship with one smoke command.

Use the root runner to list or execute the current smoke set:

```bash
./run-hello-smokes.sh --list
./run-hello-smokes.sh hello-fastapi hello-fastify
./run-hello-smokes.sh
```

## Implemented Hello Examples

### Control Plane Adjuncts

| Example | Surface | Runtime | Smoke |
| --- | --- | --- | --- |
| [`hello-trust-control/`](./hello-trust-control/) | Trust service + capability lifecycle + offline evidence verification | `./run-trust.sh` | `./smoke.sh` |
| [`hello-receipt-verify/`](./hello-receipt-verify/) | Captured evidence package + offline verification | fixture package only | `./smoke.sh` |

### HTTP Framework Surfaces

| Example | Surface | Runtime | Smoke |
| --- | --- | --- | --- |
| [`hello-openapi-sidecar/`](./hello-openapi-sidecar/) | OpenAPI + `chio api protect` sidecar | `./run.sh` | `./smoke.sh` |
| [`hello-fastapi/`](./hello-fastapi/) | FastAPI + `chio-asgi` | `./run.sh` | `./smoke.sh` |
| [`hello-django/`](./hello-django/) | Django + `chio-django` | `./run.sh` | `./smoke.sh` |
| [`hello-fastify/`](./hello-fastify/) | Fastify + `@chio-protocol/fastify` | `./run.sh` | `./smoke.sh` |
| [`hello-elysia/`](./hello-elysia/) | Elysia + `@chio-protocol/elysia` | `./run.sh` | `./smoke.sh` |
| [`hello-express/`](./hello-express/) | Express + `@chio-protocol/express` | `./run.sh` | `./smoke.sh` |
| [`hello-chi/`](./hello-chi/) | Go `chi` + `chio-go-http` | `./run.sh` | `./smoke.sh` |
| [`hello-spring-boot/`](./hello-spring-boot/) | Spring Boot + `chio-spring-boot` | `./run.sh` | `./smoke.sh` |
| [`hello-dotnet/`](./hello-dotnet/) | ASP.NET + `ChioMiddleware` | `./run.sh` | `./smoke.sh` |
| [`hello-drogon/`](./hello-drogon/) | C++ Drogon + `chio::drogon::ChioMiddleware` | `./run.sh` | `./smoke.sh` (skips when CMake or Drogon is unavailable) |

### Protocol And Agent Surfaces

| Example | Surface | Runtime | Smoke |
| --- | --- | --- | --- |
| [`hello-mcp/`](./hello-mcp/) | MCP edge over stdio JSON-RPC | `./run-edge.sh serve` | `./smoke.sh` |
| [`hello-a2a/`](./hello-a2a/) | A2A edge with authoritative send + deferred task lifecycle | `./run-edge.sh serve` | `./smoke.sh` |
| [`hello-acp/`](./hello-acp/) | ACP edge with invoke + deferred stream/resume lifecycle | `./run-edge.sh serve` | `./smoke.sh` |

## Build Order That Landed

1. `hello-openapi-sidecar`
2. `hello-fastapi`
3. `hello-fastify`
4. `hello-chi`
5. `hello-express`
6. `hello-django`
7. `hello-elysia`
8. `hello-spring-boot`
9. `hello-dotnet`
10. `hello-drogon`
11. `hello-mcp`
12. `hello-a2a`
13. `hello-acp`

That sequence gave:

- one Python HTTP path
- one TypeScript HTTP path
- one Go HTTP path
- then the remaining framework wrappers (including the C++/Drogon path)
- then the protocol-native and agent surfaces

## Standard Shape

Every hello example converges on roughly this structure:

```text
hello-<surface>/
  README.md
  policy.yaml or config/
  run.sh or run-edge.sh
  smoke.sh
  app/ or src/
```

## Adjunct Candidates

The next small examples should avoid broadening the matrix with thin variants. The strongest follow-ons are federation-aware surfaces that add a distinct protocol path.

## Relationship To `agent-commerce-network`

The `hello-*` examples are the small, surface-specific teaching layer.

The `agent-commerce-network` example is the "how these surfaces combine in the real world" layer.

The `internet-of-agents-incident-network` example is the "how recursive delegation, OpenAI SDK orchestration, MCP, ACP, and cross-org authority all compose together" layer.

The `internet-of-agents-web3-network` example is the "how Chio-mediated cross-org agent commerce binds to the official Chio web3 validation ladder" layer.
