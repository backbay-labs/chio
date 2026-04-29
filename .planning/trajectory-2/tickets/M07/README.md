# M07: Adoption Beachhead Pack

**Wave:** W3  |  **Trust-boundary:** no  |  **Tickets:** 40  |  **Effort:** 57.00 days

## In one paragraph

M07 ships `@chio/ai-sdk-middleware` and `@chio/next` for Vercel AI SDK adoption, an `arc mcp wrap` CLI that turns any stdio MCP server into a verdict-gated subprocess for Cursor/Claude Desktop/Continue/Zed, five new provider adapters (Gemini/Mistral/Groq/Ollama/Cohere) that flip the cross-provider matrix from 3 to 8, three `create-chio-app` templates with a TTFRH < 60s gate, and four deployment-shape SDK drivers (JVM/dotnet/Lambda/k8s) closing the D07 deferral by extending the M02 cross-language verdict matrix from 5 to 9 drivers.

## Phases at a glance

| Phase | Tickets | One-liner |
|---|---|---|
| P0 | 4 | Audit doc + Cargo.lock bump + ProviderId extension + npm name reservations + TTFRH scaffold |
| P1 | 6 | `@chio/ai-sdk-middleware` (`wrapWithChio`) + `@chio/next` Route Handler + Edge/Node split |
| P2 | 6 | `arc mcp wrap` subcommand + IDE config emitters (Cursor/Claude Desktop/Continue/Zed) |
| P3 | 6 | Provider adapters: Gemini, Mistral, Groq (lift/lower + 12 fixtures + bench each) |
| P4 | 6 | Provider adapters: Ollama, Cohere + 8-provider matrix flip to required-CI |
| P5 | 6 | Three templates (Next/FastAPI/Cloudflare) + `create-chio-app` + TTFRH gate + telemetry sentinel |
| P6 | 6 | Deployment-shape SDK drivers (JVM/dotnet/Lambda/k8s) + M02 verdict-matrix manifest extension + required-CI flip + smoke gate (closes D07 deferral) |

## Load-bearing artifacts

- `sdks/typescript/packages/chio-ai-sdk-middleware/` (M07.P1.T1)
- `sdks/typescript/packages/chio-next/` (M07.P1.T3)
- `crates/chio-cli/src/cli/mcp.rs` `arc mcp wrap` (M07.P2.T1)
- `crates/chio-{gemini,mistral,groq,ollama,cohere}-tools-adapter/` (P3.T1, P3.T3, P3.T5, P4.T1, P4.T3)
- `crates/chio-provider-conformance/fixtures/{gemini,mistral,groq,ollama,cohere}/` (60 fixtures total)
- 8-provider verdict-equality oracle required-CI (M07.P4.T5)
- `sdks/typescript/templates/{next-ai-sdk-receipts,fastapi-langchain,cloudflare-worker}/` (P5.T1-T3)
- `sdks/typescript/packages/create-chio-app/` (M07.P5.T4)
- `crates/chio-conformance/verdict_matrix/drivers/{jvm,dotnet,lambda,k8s}/` (P6.T1-T4)
- M02 verdict-matrix manifest 9-driver flip required-CI (M07.P6.T5)

## Cross-trajectory deps

- trajectory-1 M07 fabric trait - exercised under scale by 5 new adapters
- trajectory-1 M08 size-budget gate - applied to new TS packages
- trajectory-2 M01 error registry - consumed by per-provider error doctests
- trajectory-2 M02 verdict-matrix - new adapters register as drivers (M07.P1.T5)
- trajectory-2 M06 twiggy artifact - budget enforcement lands here

## Locked decisions

- D17 Five new providers: Gemini, Mistral, Groq, Ollama, Cohere; matrix grows from 3 to 8
- D18 Three create-chio-app templates: Next.js, FastAPI, Cloudflare Worker; TTFRH < 60 s gate
- D07 (M02) closure: M07.P6 ships JVM/dotnet/Lambda/k8s verdict-matrix drivers; M02 axis grows from 5 to 9 drivers

## Active freezes

none.

## When this milestone is done

- 5 new provider crates build on `cargo build --workspace`, tests pass, clippy clean.
- 2 new TS packages (`@chio/ai-sdk-middleware`, `@chio/next`) build, tests pass, size-budget gate green.
- `arc mcp wrap` end-to-end test wraps a real MCP server and asserts verdict gating + attestation header round-trip.
- 60 new conformance fixtures (12 per provider); 8-provider verdict-equality oracle required-CI on a hash-pinned scenario corpus.
- 3 templates committed; `create-chio-app` ships; TTFRH bench < 60 s p99 per template on the reference 4-core Linux runner; gate is required-CI.
- Telemetry-free first-run sentinel green per template.
- 4 deployment-shape SDK drivers (JVM/dotnet/Lambda/k8s) registered in the M02 hash-pinned manifest; cross-deployment smoke gate green; D07 deferral closed in the audit doc.
