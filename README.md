<p align="center">
  <img src="assets/hero.png" alt="Chio" width="900" />
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/MSRV-1.93-orange?style=flat-square&logo=rust" alt="MSRV: 1.93">
</p>

<h1 align="center">Chio</h1>

<p align="center">
  <strong>Governed tool access for AI systems</strong><br/>
  <em>Capability validation, fail-closed policy, budgets, and signed receipts</em>
  <!-- chio-mutants-banner:start -->
  <br/>
  <strong>Mutation kill: 31%</strong> - six-crate trust-boundary mutation baseline, mixed sweep/shard n=375 viable mutants - 2026-04-29
  <!-- chio-mutants-banner:end -->
</p>

<p align="center">
  <a href="#start-here">Start Here</a>&nbsp;&nbsp;&middot;&nbsp;&nbsp;
  <a href="#supported-paths">Supported Paths</a>&nbsp;&nbsp;&middot;&nbsp;&nbsp;
  <a href="#cli">CLI</a>&nbsp;&nbsp;&middot;&nbsp;&nbsp;
  <a href="#sdks">SDKs</a>&nbsp;&nbsp;&middot;&nbsp;&nbsp;
  <a href="#examples">Examples</a>&nbsp;&nbsp;&middot;&nbsp;&nbsp;
  <a href="spec/PROTOCOL.md">Protocol Spec</a>
</p>

---

Chio is the runtime and trust-control layer that sits between an agent and the
actions it can take. It validates capabilities, enforces policy and budgets,
and produces signed receipts for every governed decision.

## Start Here

1. Install Chio: [docs/install/README.md](docs/install/README.md)
2. Run the guided local walkthrough: [docs/PROGRESSIVE_TUTORIAL.md](docs/PROGRESSIVE_TUTORIAL.md)
3. Pick the supported path that matches your use case:
   - Existing MCP server or coding-agent flow:
     [docs/guides/MIGRATING-FROM-MCP.md](docs/guides/MIGRATING-FROM-MCP.md)
   - Web backend:
     [docs/guides/WEB_BACKEND_QUICKSTART.md](docs/guides/WEB_BACKEND_QUICKSTART.md)
   - Native Chio tool server:
     [docs/NATIVE_ADOPTION_GUIDE.md](docs/NATIVE_ADOPTION_GUIDE.md)

## Supported Paths

### MCP Migration And Coding Agents

Start with the supported policy-backed path:

- scaffold or copy `examples/policies/canonical-hushspec.yaml`
- run `chio mcp serve --policy ./policy.yaml ...`
- prove one deny, one allow, and one receipt using the migration guide

Guide:
[docs/guides/MIGRATING-FROM-MCP.md](docs/guides/MIGRATING-FROM-MCP.md)

### Web Backends

The supported order is:

1. [examples/hello-openapi-sidecar/README.md](examples/hello-openapi-sidecar/README.md)
2. [examples/hello-fastapi/README.md](examples/hello-fastapi/README.md)

Shared verification flow:
[docs/guides/WEB_BACKEND_QUICKSTART.md](docs/guides/WEB_BACKEND_QUICKSTART.md)

### Native Chio Tool Servers

For native Chio authoring, start with the native adoption guide and the minimal
tool example:

- [docs/NATIVE_ADOPTION_GUIDE.md](docs/NATIVE_ADOPTION_GUIDE.md)
- [examples/hello-tool/README.md](examples/hello-tool/README.md)

## CLI

The supported operator and local-development entrypoints are:

- `chio check`: evaluate a single governed tool call and inspect the verdict
- `chio mcp serve`: wrap an MCP server with Chio governance
- `chio mcp serve-http`: expose the governed MCP edge over Streamable HTTP
- `chio trust serve`: run the shared trust-control service

Install and verification instructions live in
[docs/install/README.md](docs/install/README.md).

## SDKs

| Language | Package | Package README |
| --- | --- | --- |
| TypeScript | `@chio-protocol/sdk` | [packages/sdk/chio-ts/README.md](packages/sdk/chio-ts/README.md) |
| Python | `chio-sdk` | [packages/sdk/chio-py/README.md](packages/sdk/chio-py/README.md) |
| Go | `chio-go` | [packages/sdk/chio-go/README.md](packages/sdk/chio-go/README.md) |

The primary Python and TypeScript packages include runnable quickstarts and
canonical example links back to the supported web-backend flow.

## Examples

- Example index: [examples/README.md](examples/README.md)
- Surface map: [examples/EXAMPLE_SURFACE_MATRIX.md](examples/EXAMPLE_SURFACE_MATRIX.md)
- Docker smoke path: [examples/docker/README.md](examples/docker/README.md)

## Current Boundary

- Supported candidate surface:
  [docs/release/RELEASE_CANDIDATE.md](docs/release/RELEASE_CANDIDATE.md)
- Repo-local go or hold record:
  [docs/release/RELEASE_AUDIT.md](docs/release/RELEASE_AUDIT.md)
- Qualification lanes and required evidence:
  [docs/release/QUALIFICATION.md](docs/release/QUALIFICATION.md)

## More

- Install options: [docs/install/README.md](docs/install/README.md)
- Progressive tutorial: [docs/PROGRESSIVE_TUTORIAL.md](docs/PROGRESSIVE_TUTORIAL.md)
- Protocol specification: [spec/PROTOCOL.md](spec/PROTOCOL.md)
- Formal boundary and claims: [docs/reference/CLAIM_REGISTRY.md](docs/reference/CLAIM_REGISTRY.md)
- Release and operations docs: [docs/release/](docs/release/)

## License

Apache-2.0. See [LICENSE](LICENSE).
