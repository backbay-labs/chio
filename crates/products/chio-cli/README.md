# chio-cli

Builds the `chio` binary (`src/bin/chio.rs`, `default-run`), the operator-facing
entry point for the Chio protocol (`[package.metadata.chio] public_entrypoint =
true`). It parses commands with clap, dispatches each to a local implementation
module or an internal `chio-*` crate, and renders human or JSON output. Policy
evaluation, signing, and verification live in the crates it wraps
(`chio-kernel`, `chio-control-plane`, and the domain crates under Dependencies
in `ARCHITECTURE.md`), not in this crate.

Commands span five areas: running and hosting governed agent sessions (`run`,
`check`, `mcp`, `api`, `start`); trust-plane administration and audit (`trust`,
`receipt`, `evidence`, `reputation`, `did`, `passport`); offline verification
and replay (`proof`, `commerce`, `certify`, `cert`, `attest`, `replay`,
`workflow`); WASM guard authoring and the guard marketplace (`guard`, `bind`);
and cross-kernel federation, live-runtime orchestration, and the pheromone
relay (`federation`, `runtime`, `pheromone`, `arena`, `lineage`, `settle`,
`conformance`). `doctor` and `init` cover environment diagnostics and project
scaffolding.

## Responsibilities

- Parse the `chio` command line (`Cli`/`Commands` in `src/cli/types.rs`) and
  dispatch each of 29 top-level commands to an implementation function
  (`src/cli/dispatch/mod.rs::run`).
- Run a policy-governed agent subprocess over a framed stdio transport
  (`chio run`), and evaluate one-off tool calls without a subprocess
  (`chio check`).
- Host governed edges: an HTTP sidecar (`chio api protect` / `chio start`) and
  an MCP edge over stdio or HTTP (`chio mcp serve[-http]`), plus a
  manifest-gated MCP wrapper (`chio mcp wrap`).
- Administer local or remote (`--control-url`) trust-plane state: capability
  revocation, credit/liability/underwriting artifacts, receipts, evidence
  packages, DID resolution, Agent Passports, and verifier policies.
- Verify and replay signed artifacts offline: Transaction Passport proof
  bundles (`chio proof`/`chio commerce`), receipt logs (`chio replay`),
  compliance certificates (`chio cert`), conformance certifications
  (`chio certify`), and attestation/supply-chain evidence (`chio attest`).
- Author, build, test, sign, and publish WASM guards, and browse the guard
  marketplace (`chio guard`).
- Operate cross-kernel federation, live-runtime orchestration, and the
  pheromone relay (`chio federation`, `chio runtime`, `chio pheromone`).
- Diagnose local environment health (`chio doctor`) and scaffold a runnable
  example project (`chio init`).
- Install a redacting tracing subscriber so a field an untrusted payload
  smuggled through cannot forge additional operator log lines
  (`src/cli/dispatch/mod.rs`).

## Public API

Full flag reference: `chio <command> [<subcommand>...] --help`.

| Command | Subcommands | Purpose |
|---|---|---|
| `run` | - | Spawn an agent subprocess and enforce policy via the kernel. |
| `check` | - | Evaluate a single tool call against a policy, no subprocess. |
| `init` | - | Scaffold a runnable example project with a governed demo flow. |
| `api` | `protect` | Protect an HTTP API behind an OpenAPI spec-backed sidecar. |
| `mcp` | `wrap`, `serve`, `serve-http` | Wrap or host an MCP-compatible edge behind the kernel. |
| `trust` | 26 groups: `serve`, `provider`, `federation-policy`, `revoke`, `facility`, `bond`, `loss`, `liability-provider`, `liability-market`, `underwriting-input`, `underwriting-decision`, `underwriting-appeal`, `capital-book`, `capital-instruction`, `capital-allocation`, `credit-scorecard`, `credit-backtest`, `provider-risk-package`, `appraisal`, `behavioral-feed`, `exposure-ledger`, `evidence-share`, `authorization-context`, `federated-issue`, `federated-delegation-policy-create`, `status` | Manage local and remote trust-plane state. |
| `receipt` | `list`, `health`, `flush`, `audit`, `retention`, `checkpoint`, `explain` | Query, audit, and repair the receipt store. |
| `evidence` | `export`, `verify`, `import`, `federation-policy` | Export and verify offline evidence packages. |
| `certify` | `check`, `verify`, `registry` (11 more) | Certify conformance evidence and publish results. |
| `did` | `resolve` | Resolve `did:chio` identifiers into DID Documents. |
| `passport` | `generate`, `create`, `verify`, `evaluate`, `present`, `policy`, `challenge`, `status`, `issuance`, `oid4vp` | Issue, verify, and present Agent Passport bundles. |
| `proof` | `assemble`, `collect`, `verify`, `explain`, `fixture`, `serve`, `export`, `doctor` | Verify and operate on Transaction Passport proof bundles. |
| `commerce` | `verify` | Verify commerce proof bundles and payment evidence. |
| `workflow` | `preflight` | Validate read-only workflow planning evidence. |
| `reputation` | `local`, `compare` | Compute and compare local reputation scorecards. |
| `cert` | `generate`, `verify`, `inspect` | Generate, verify, and inspect ACP session compliance certificates. |
| `guard` | `new`, `build`, `inspect`, `test`, `bench`, `pack`, `publish`, `pull`, `blocklist`, `install`, `sign`, `verify`, `market` | WASM guard lifecycle: author, build, sign, publish, pull. |
| `conformance` | `run`, `fetch-peers` | Run the cross-language conformance harness. |
| `federation` | `authority` (issue, checkpoint, trust-bundle), `treaty` (intersect, admit, verify-packet) | Produce and verify cross-kernel federation artifacts. |
| `attest` | `buyer`, `supply-chain`, `runtime-quote` | Verify offline attestation evidence and buyer proof packages. |
| `runtime` | `admit`, `sign-trust-input`, `policy`, `peer-weights`, `pheromone`, `orchestrate`, `ops`, `run-loopback` | Evaluate local live-runtime admission artifacts. |
| `pheromone` | `receive`, `query`, `relay` (relay nests ~45 more, 7 levels deep) | Receive, query, and relay pheromone artifacts. |
| `finding` | `publish`, `search`, `verify`, `buy` | Publish, discover, verify, and purchase cognition-market findings. Requires the `cognition-market-experimental` feature. |
| `replay <log>` | `traffic` | Re-verify a captured receipt log against the current build. |
| `settle` | `status` | Inspect pending, settled, and dead-lettered settlements. |
| `lineage` | `query`, `diff`, `roots` | Query, diff, and list anchored roots in the lineage DAG. |
| `doctor` | - | Diagnose toolchain, registry, OTEL, and `chio.yaml` health. |
| `arena` | `run`, `replay`, `evolve` | Run, replay, and evolve chio-arena scenarios. |
| `bind` | - | Bind a provider under a signed model card. |
| `start` | - | Start the sidecar with zero-config defaults (thin wrapper over `api protect`). |

A few command names collide in ways worth flagging:

- `chio cert` (ACP session compliance certificates) is unrelated to
  `chio certify` (conformance certification artifacts).
- `chio trust` and `chio receipt` are separate top-level commands, even though
  `chio receipt`'s implementation lives under `src/cli/trust/receipt/`.
- `chio runtime pheromone` (evaluate a policy, no state change) is distinct
  from the top-level `chio pheromone` command tree.
- `chio proof collect --kind replay` (a Proof Room bundle kind) is unrelated
  to the top-level `chio replay` command.
- `chio passport` (Agent Passport identity bundles) is unrelated to
  `chio proof`'s Transaction Passport artifacts.

### Global flags

Accepted before or after the subcommand; every one is optional.

| Flag | Effect |
|---|---|
| `--json` | Short alias for `--format json`. |
| `--format <human\|json>` | Output format for results and terminal error reporting. Default `human`. |
| `--receipt-db <PATH>` | SQLite path for durable receipt persistence. |
| `--revocation-db <PATH>` | SQLite path for durable capability revocation persistence. |
| `--authority-seed-file <PATH>` | Persistent capability-authority seed file. |
| `--authority-db <PATH>` | SQLite path for shared capability-authority state. |
| `--budget-db <PATH>` | SQLite path for durable shared capability budget state. |
| `--session-db <PATH>` | SQLite path for durable remote MCP session tombstones. |
| `--control-url <URL>` | Shared trust-control service base URL; switches supporting commands to the remote backend. |
| `--control-token <TOKEN>` | Bearer token for the trust-control service. Prefer the `CHIO_CONTROL_TOKEN` env var over argv so the bearer does not leak via `ps`. |

## Usage

```sh
chio run --policy policy.yaml -- python agent.py

chio check --policy policy.yaml --tool fs.read --params '{"path": "/tmp/x"}'

chio mcp serve --policy policy.yaml --server-id fs -- \
  npx -y @modelcontextprotocol/server-filesystem /tmp
```

## Feature flags

| Flag | Effect |
|---|---|
| `tee-quotes` | Enables `chio-attest-verify/tee-quotes`: TCB-collateral parsing for `chio attest runtime-quote verify` (Intel TDX, AMD SEV-SNP, AWS Nitro). |
| `iroh` | Links `chio-federation-transport-iroh` into the binary. Off by default so the shipped `chio` keeps the smaller supply-chain surface. |
| `cognition-market-experimental` | Compiles the `chio finding` family and forwards to `chio-control-plane/cognition-market-experimental`, whose finding routes carry the same flag. Default builds link none of the finding crates. |

## Testing

`cargo test -p chio-cli`

CLI-parse tests drive `Cli::try_parse_from` on an 8 MiB-stack thread
(`cli/types.rs`'s `cli_env_tests::parse_cli`) because the monomorphized clap
parser for the many-variant `Commands` enum overflows the default libtest
worker stack. Black-box integration tests live under `tests/` (roughly one
file per command family) and spawn the built `chio` binary via
`chio-test-support`; fixtures live under `tests/fixtures/`,
`tests/proof_cli_contract/`, and `tests/replay_traffic/`; snapshot tests
(`insta`) live under `tests/snapshots/`.

## See also

- `chio-control-plane` - policy loading, kernel construction, and most of the
  remote and local trust/passport/certify business logic this crate dispatches
  into.
- `chio-kernel` - session and tool-call evaluation behind `run`, `check`, and
  the MCP edge.
- `chio-mcp-adapter`, `chio-mcp-remote` - MCP edge hosting behind
  `mcp serve[-http]`.
- `chio-guard-registry`, `chio-wasm-guards` - OCI publish/pull and WASM
  build/inspect/test behind `guard`.
- `chio-arena`, `chio-replay-corpus` - scenario execution and bundle format
  behind `arena` and `replay`.
- `chio-proof-room`, `chio-commerce-order` - Transaction Passport bundle
  format and commerce-order verification behind `proof` and `commerce`.
