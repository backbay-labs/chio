# Chio SDKs

This directory is the single home for every Chio SDK. SDKs are grouped first by
language, with two cross-language directories for distinct kinds of artifact.

## Layout

| Path | What lives here |
|------|-----------------|
| `cpp/` | C++ host SDKs: `chio-cpp` (core client), `chio-cpp-kernel` (in-process kernel binding), `chio-drogon` (Drogon web-framework middleware). |
| `dotnet/` | .NET middleware (`ChioMiddleware`). |
| `go/` | Go SDKs: `chio-go` (hand-written core client) and `chio-go-http` (oapi-codegen wire-typed client). |
| `guard/` | WASM guard *guest* SDKs, a distinct kind (built out-of-tree, loaded as components, not host clients): `chio-guard-{cpp,go,py,ts}`. |
| `jvm/` | JVM SDKs and the Gradle composite: `chio-sdk-jvm`, `chio-spring-boot`, `chio-streaming-flink`, `chio-kernel-mobile`. |
| `k8s/` | Kubernetes controller, CRDs, and admission webhooks. |
| `lambda/` | AWS Lambda extension (Rust) and the Python Lambda runtime. |
| `python/` | Python SDKs: `chio-py` (the pure in-process `chio-sdk`), `chio-sdk-python` (the thin sidecar client and adapter base), and the framework adapters (`chio-django`, `chio-langgraph`, and so on). |
| `rust/` | Rust guard SDK compatibility shim (`chio-guard-sdk-compat`) re-exporting the canonical `crates/chio-guard-sdk`. |
| `swift/` | Swift / Apple-platform SDK and App Attest support. |
| `typescript/` | The published core `chio-ts` (`@chio-protocol/sdk`) plus the framework-integration workspace under `typescript/packages/`. |

## Two cores per language

Python, Go, and TypeScript each ship two complementary core SDKs, by design:

- An **in-process** core that performs verification inside the application
  process: `python/chio-py` (module `chio`), `go/chio-go`, `typescript/chio-ts`.
- A **sidecar / wire** client that delegates enforcement to a colocated kernel:
  `python/chio-sdk-python` (module `chio_sdk`), `go/chio-go-http`, and the
  TypeScript `node-http` integration.

Most applications want the sidecar client. The in-process core is the
self-contained reference surface and the conformance anchor.
