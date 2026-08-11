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
| `finding` | `publish`, `search`, `verify`, `buy`, `challenge`, `status` | Publish, discover, verify, purchase, dispute, and inspect cognition-market findings. |
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

### Cognition-market input files

`chio finding` takes three operator-supplied JSON documents. Each is read
strict raw-first: bounded read, then a canonical-bytes check, then a
closed-shape parse, then a typed round-trip equality check. A file that is
not exactly its own canonical serialization is refused rather than
normalized into acceptance, because the digests it carries are only
meaningful against exact bytes.

`chio finding verify --trust-roots <FILE>` pins the four verifier roots:
`governance_authority` (bare Ed25519 hex), `profile` (a signed
`chio.finding.challenge-verifier-profile.v1` envelope), `admitted_kernel_keys`
(an array of bare Ed25519 hex keys), `collateral_authority`, and an optional
`trusted_time` in unix seconds. Without `trusted_time` the local clock is
used and the report says so. Status verification additionally requires the
paired `status_operator_authorization` and `status_freshness_policy` object;
the latter carries a nonzero `max_epoch_age_secs`, while its evaluation clock
is the same trusted time recorded in the report.

`chio finding verify --evidence <FILE>` supplies resolved evidence:
`receipts` (each `{receipt, inclusion_proof}`), `checkpoints`, and an
optional `bond_snapshot` of `{backing, store_snapshot}`. The collateral
authority must sign `store_snapshot`, which binds the exact backing-envelope
digest, allocation, Finding, liveness, acceptance time, and evaluation time.
A portable status proof is carried as `status_proof_input_b64`, preserving the
exact canonical
`chio.finding.status-proof-input.v1` bytes. It is accepted only when the paired
status trust fields above are pinned and `--status-rollback-floor <FILE>` names
durable per-feed high-water state. The same floor file may be shared with
`chio finding status`; a signed proof below its retained map epoch or a
same-epoch conflicting root fails closed. Sticky retractions are partitioned
into immutable records under the sibling `<FILE>.retractions/` directory, so
operators must retain that directory with the floor file. Every member is
optional; a facet whose evidence is absent reports unavailable and is never
collapsed into a verified badge.

`chio finding challenge --evidence <FILE>` supplies the operator half of a
challenge. It is exactly the registered `chio.finding.challenge.v1` body
minus the four fields the command derives rather than accepts (`schema`,
`challenge_id`, `finding_id`, and `finding_artifact_sha256`, the last two
taken from the artifact the venue serves). Every key below, at every depth,
is in canonical order, which is the order the file must use, and every field
is required:

```json
{
  "affected_deliveries": [
    {
      "checkpoint_ref": "checkpoints/venue-wedge/9001",
      "checkpoint_sha256": "<64 hex>",
      "receipt_id": "delivery-receipt-42",
      "receipt_sha256": "<64 hex>"
    }
  ],
  "authorization": { "buyer_submission": { "...": "..." } },
  "evidence": { "digest_mismatch": { "...": "..." } },
  "filed_at": 1750000000,
  "listing": {
    "backing_envelope_sha256": "<64 hex>",
    "listing_id": "finding-listing-01",
    "profile_envelope_sha256": "<64 hex>",
    "terms_envelope_sha256": "<64 hex>",
    "venue_admission_envelope_sha256": "<64 hex>"
  }
}
```

- `listing` is copied from the venue's current signed admission envelope
  (`GET /v1/findings/{id}/admission`). The CLI holds no pinned venue key, so
  it binds what the operator copied and leaves authentication of that
  envelope to the coordinator that resolves it.
- `filed_at` is supplied rather than read from the local clock, so the same
  inputs always assemble the same challenge and therefore the same
  content-addressed `challenge_id`.
- `authorization` is the artifact's closed union. `buyer_submission` carries
  `challenger`, `dispute_fee_terminal`, `dispute_lock_ref`, and `standing`;
  `venue_audit` carries `audit_epoch_envelope_sha256`,
  `authorization_digest`, and `selection_digest`, and no challenger, fee,
  bond, forfeiture, or reward member exists in it at all. The branch must
  agree with `--venue-audit`: a buyer submission is refused under that flag
  rather than stripped down into an audit.
- `evidence` is the artifact's other closed union, and its branch must equal
  `--class`. `digest_mismatch` carries `deny_checkpoint_ref`,
  `deny_receipt_ref`, and `failed_delivery_envelope_sha256`;
  `evidence_invalid` carries `challenged_checkpoint_ref`,
  `challenged_evidence_receipt_refs`, and
  `purchase_record_envelope_sha256`; `replay_contradiction` carries
  `purchase_record_envelope_sha256`, the canonical
  `chio.finding.replay-recipe-input.v1` text as `recipe_preimage`, and
  `reproduction` (each entry a `checkpoint_ref`, the canonical
  `chio.finding.replay-observation.v1` text as `observation_bytes`, and a
  `receipt_ref`).
- `standing` must match the evidence class: a denied reveal creates no
  purchase record, so `digest_mismatch` stands on `failed_delivery` while
  the other two stand on `finalized_purchase`, and the standing digest must
  equal the digest the evidence branch already names.

The assembled body is checked against the registered challenge schema and
its own validator, then the closed guarantee/evidence compatibility matrix
is checked against the fetched finding, all before anything is signed. A
buyer submission is then signed under `--challenger-key` (an Ed25519 seed
file of 64 hex characters), which must hold exactly the challenger the
document names. A venue audit is signed by the venue's pinned audit
authority, which this surface does not hold, so its dry run emits the body
alone and reports no envelope digest.

A buyer submission sends the signed envelope to
`POST /v1/findings/{finding_id}/challenges` when `--control-url` and a control
bearer are configured. Supply the bearer with `CHIO_CONTROL_TOKEN` where
possible, or with `--control-token`; `--dry-run` assembles and signs without
transmitting. The venue-audit branch remains dry-run only because this CLI
does not hold the venue's pinned audit-authority key, so a non-dry-run venue
audit refuses rather than sending an unsigned body.

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
