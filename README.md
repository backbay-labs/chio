<p align="center">
  <img src="docs/assets/hero.png" alt="Chio" width="900" />
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/MSRV-1.93-orange?style=flat-square&logo=rust" alt="MSRV: 1.93">
  <a href="https://github.com/backbay-labs/chio/actions/workflows/ci.yml"><img src="https://github.com/backbay-labs/chio/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="docs/README.md"><img src="https://img.shields.io/badge/docs-read-blue?style=flat-square" alt="Docs"></a>
</p>

<h1 align="center">Chio</h1>

<p align="center">
  <strong>Governed tool access for AI systems</strong><br/>
  <em>Capability validation, fail-closed policy, budgets, and signed receipts</em>
</p>

<p align="center">
  <a href="#what-is-chio">What</a>&nbsp;&nbsp;&middot;&nbsp;&nbsp;
  <a href="#why-chio">Why</a>&nbsp;&nbsp;&middot;&nbsp;&nbsp;
  <a href="#quickstart">Quickstart</a>&nbsp;&nbsp;&middot;&nbsp;&nbsp;
  <a href="#architecture">Architecture</a>&nbsp;&nbsp;&middot;&nbsp;&nbsp;
  <a href="#integrations-and-sdks">Integrations</a>&nbsp;&nbsp;&middot;&nbsp;&nbsp;
  <a href="#security-and-trust">Security</a>&nbsp;&nbsp;&middot;&nbsp;&nbsp;
  <a href="docs/README.md">Docs</a>&nbsp;&nbsp;&middot;&nbsp;&nbsp;
  <a href="spec/PROTOCOL.md">Spec</a>
</p>

---

## What is Chio

Chio is a Rust runtime and trust-control layer that sits between an AI agent and
the tool calls it is allowed to make. A trusted kernel mediates every governed
call: it validates time-bounded, cryptographically verifiable capability tokens,
runs a guard pipeline over inputs and outputs before anything crosses a trust
boundary, enforces policy and budgets, and signs an append-only receipt for every
decision (allow, deny, cancelled, incomplete).

MCP tells agents how to call tools. Chio proves what they were allowed to do,
what it cost, and what happened. The core primitive is a signed, capability-bound
receipt for every decision: for any agent action there is a verifiable record of
what was authorized and what occurred.

## Why Chio

- **No identity, delegation, budget, or receipt at the tool-call layer today.**
  A plain tool-call wire format moves arguments; it does not prove who the agent
  is, what it was allowed to do, or that the action was authorized.
- **Fail-closed by design.** Errors during evaluation deny access. Invalid
  policies are rejected at load time. The kernel will not allow a call it cannot
  also sign a receipt for.
- **Native policy and guards.** Policy is written in HushSpec and compiled to
  native guards. No external policy engine is required.
- **Wraps existing ecosystems instead of replacing them.** MCP, A2A,
  ACP-Client, ACP-Commerce, OpenAPI, and AG-UI become governed Chio tool
  servers, while the kernel keeps dispatch and receipt authority.

## Quickstart

Chio is pre-release (0.1.0) and not yet published to a package registry, so build
the `chio` binary from source:

```bash
git clone https://github.com/backbay-labs/chio.git
cd chio
cargo build --release -p chio-cli   # produces ./target/release/chio
./target/release/chio --help
```

For the current source install path and the planned binary/Homebrew release
contract, see [docs/install/README.md](docs/install/README.md).

Now evaluate a single tool call against a policy. The example policy
[`examples/policies/hushspec-tool-allow.yaml`](examples/policies/hushspec-tool-allow.yaml)
allows a narrow read-only tool surface and blocks everything else. Chio is
fail-closed: it signs a receipt for every decision, so `chio check` needs a
receipt database to record one.

An allowed call (`read_file` is in the allowlist) returns `ALLOW` and exits 0:

```bash
./target/release/chio --receipt-db /tmp/chio.db check \
  --policy examples/policies/hushspec-tool-allow.yaml \
  --tool read_file --params '{"path":"README.md"}'
```

```
verdict:    ALLOW
tool:       read_file
server:     *
receipt_id: 84c7f76d...
policy:     40f2f61d...
mode:       preflight
```

A call to a tool that is not in the allowlist returns `DENY` and exits 2:

```bash
./target/release/chio --receipt-db /tmp/chio.db check \
  --policy examples/policies/hushspec-tool-allow.yaml \
  --tool delete_database --params '{}'
```

```
verdict:    DENY
tool:       delete_database
reason:     requested tool delete_database on server * is not in capability scope
receipt_id: 66db67f0...
```

Both decisions are recorded as signed receipts. List them as one JSON object per
line (the read fails closed without an explicit tenant boundary, so pass
`--admin-all` for this local demo):

```bash
./target/release/chio --receipt-db /tmp/chio.db receipt list --admin-all
```

Each line carries the decision verdict, the policy hash, the signing kernel key,
and an Ed25519 signature over the receipt.

> Status: 0.1.0, pre-release. APIs and wire surfaces may change before the first
> stable release tag.

## Choose your path

- **Migrating an MCP server or coding-agent flow:**
  [docs/guides/MIGRATING-FROM-MCP.md](docs/guides/MIGRATING-FROM-MCP.md)
- **Protecting a web backend:**
  [docs/guides/WEB_BACKEND_QUICKSTART.md](docs/guides/WEB_BACKEND_QUICKSTART.md)
- **Authoring a native Chio tool server:**
  [docs/start-here/NATIVE_ADOPTION_GUIDE.md](docs/start-here/NATIVE_ADOPTION_GUIDE.md)

For a guided local walkthrough, start with the
[progressive tutorial](docs/start-here/PROGRESSIVE_TUTORIAL.md).

## Architecture

Chio is built from five components:

1. **Agent** - the untrusted, LLM-powered process that consumes tools via
   capability tokens.
2. **Runtime Kernel** - the trusted mediator (the TCB) that validates
   capabilities, runs the guard pipeline, and signs receipts.
3. **Tool Servers** - sandboxed processes that implement tools, isolated from
   each other and from the agent.
4. **Capability Authority** - issues, scopes, and revokes time-bounded capability
   tokens.
5. **Receipt Log** - the append-only, Merkle-committed log of signed attestations
   over every decision and tool call.

```
Agent --(capability token)--> Runtime Kernel (TCB) --(guard pipeline)--> Tool Servers
                                     |
                                     +--> signs --> Receipt Log
```

The crates a user usually touches are the `chio` CLI (`chio-cli`),
`chio-api-protect` (a zero-code reverse proxy that protects HTTP APIs with Chio
receipts), and the libraries `chio-kernel`, `chio-policy`, and `chio-guards`. The
workspace ships many more internal crates; the full crate map and component
detail live in [AGENTS.md](AGENTS.md) and
[docs/architecture/](docs/architecture/).

## Integrations and SDKs

Chio governs tool calls across MCP, A2A, ACP-Client, ACP-Commerce, OpenAPI,
AG-UI, and provider-native tool formats (OpenAI, Anthropic, Bedrock, Gemini,
Cohere, Groq, Mistral, Ollama). The kernel owns dispatch and receipt authority
for the surfaces it mediates.

| Language | Package | README |
| --- | --- | --- |
| TypeScript | `@chio-protocol/sdk` | [sdks/typescript/chio-ts/README.md](sdks/typescript/chio-ts/README.md) |
| Python | `chio-sdk` | [sdks/python/chio-py/README.md](sdks/python/chio-py/README.md) |
| Go | `chio-go` | [sdks/go/chio-go/README.md](sdks/go/chio-go/README.md) |

Additional language targets are in progress; see the
[SDK index](sdks/README.md).

## Security and trust

Chio exists for the non-repudiation story, so security is the design center:

- **Fail-closed.** Errors deny access; invalid policy is rejected at load.
- **Defined trust boundary.** Only the Runtime Kernel is trusted (the TCB). The
  agent and tool servers are untrusted and isolated.
- **Canonical signing.** Signed payloads use canonical JSON (RFC 8785) so
  receipts and attestations are byte-stable and verifiable.

Report vulnerabilities privately per [SECURITY.md](SECURITY.md). The normative
threat model lives in [spec/SECURITY.md](spec/SECURITY.md) and the coverage map in
[docs/security/threat-coverage.md](docs/security/threat-coverage.md).

## Examples

- Example index: [examples/README.md](examples/README.md)
- One-page surface map: [examples/EXAMPLE_SURFACE_MATRIX.md](examples/EXAMPLE_SURFACE_MATRIX.md)
- Docker smoke path: [examples/docker/README.md](examples/docker/README.md)

## Project status

Chio is pre-release at version 0.1.0. The kernel, native policy (HushSpec) and
guard runtime, the receipt and attestation pipeline, the protocol edges, and the
TypeScript, Python, and Go SDKs all exist as code. The current Chio-owned
protocol, schema, SDK, and runtime surfaces are v1-only; older `v2.x` and `v3.x`
labels in planning and research docs are internal milestone labels, not protocol
or wire compatibility versions. Nothing is tagged or published yet. See
[CHANGELOG.md](CHANGELOG.md) for the in-progress baseline, and
[docs/release/QUALIFICATION.md](docs/release/QUALIFICATION.md),
[docs/release/RELEASE_CANDIDATE.md](docs/release/RELEASE_CANDIDATE.md), and
[docs/release/RELEASE_AUDIT.md](docs/release/RELEASE_AUDIT.md) for what the
project will and will not claim, the release-candidate status, and the release
qualification audit.

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) for the
workflow and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community expectations.
Before opening a pull request, run the verification gate (`make gate` for the
minimal check, or `make ci` for the full PR-tier lane CI enforces):

```bash
make gate
```

```bash
cargo build --workspace && \
cargo test --workspace && \
cargo clippy --workspace -- -D warnings && \
cargo fmt --all -- --check
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
