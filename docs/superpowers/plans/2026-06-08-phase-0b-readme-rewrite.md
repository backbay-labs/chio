# Phase 0b (README rewrite) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Replace the current 134-line, link-heavy, process-first `README.md` with a value-first ~230-line front door (within the spec's 150-220 band on non-blank content, ~180 non-blank) that opens with what Chio is, carries one real runnable quickstart (one allow, one deny, one signed receipt), accurate badges, and a curated set of verified links.

**Architecture:** A single-file prose change to the repo-root `README.md`. No code, no crate, no workflow touched. The new README follows the 12-section outline in spec section 2.5 and research section 3. Every link target was verified to exist on disk; every shell command in the quickstart was executed against the freshly built `chio` binary and its real output is captured below.

**Tech Stack:** Markdown. Verification uses the existing `chio` CLI binary (`crates/chio-cli`, `default-run = "chio"`, `crates/chio-cli/Cargo.toml:9,17-18`) and the example policy `examples/policies/hushspec-tool-allow.yaml`.

This plan is independent of and lower-risk than the keystone plan `docs/superpowers/plans/2026-06-08-phase-1-crate-paths-guard.md` (which owns the xtask `check-crate-paths` guard and the script/`coverage/`/`.codex/` Phase 0 cleanup). This plan implements only the spec's "Phase 0 - quick wins: Rewrite the README" item. It does not delete scripts, does not touch `.gitignore`, and does not move files. The two plans can land in either order.

---

## Ground facts (verified against the tree on 2026-06-08)

These are the load-bearing facts the README states. Each was checked before writing this plan; do not restate any number not in this list.

- Workspace version `0.1.0`, MSRV / `rust-version = "1.93"`, `edition = "2021"`, `license = "Apache-2.0"`, `repository = "https://github.com/backbay-labs/chio"` (root `Cargo.toml:171-175`).
- Single binary `chio` from `chio-cli` (`crates/chio-cli/Cargo.toml:9` `default-run = "chio"`, `:17-18` `[[bin]] name = "chio"`).
- `chio --version` prints `chio-cli 0.1.0`; `chio --help` top line is `CLI binary for the Chio runtime kernel` (verified by running the built binary).
- Policy language is HushSpec (`chio-policy` crate description; `examples/policies/canonical-hushspec.yaml` header `hushspec: "0.1.0"`).
- CI workflow file `.github/workflows/ci.yml`, `name: CI`, triggers on push/pull_request to `main` (`.github/workflows/ci.yml:1,22-26`). GitHub Actions badge URL: `https://github.com/backbay-labs/chio/actions/workflows/ci.yml/badge.svg`.
- Security contact `security@backbay.io`; copyright holder Backbay Labs (`SECURITY.md:16`, `NOTICE`).
- Three real SDKs: TypeScript `@chio-protocol/sdk` (`sdks/typescript/chio-ts/README.md`), Python `chio-sdk` (`sdks/python/chio-py/README.md`), Go `chio-go` (`sdks/go/chio-go/README.md`). SDK index `sdks/README.md`.
- Hero image `assets/hero.png` exists.

Link targets that exist on disk (all verified present; the README must link only these):
`LICENSE`, `NOTICE`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, `AGENTS.md`, `spec/PROTOCOL.md`, `spec/SECURITY.md`, `docs/README.md`, `docs/install/README.md`, `docs/start-here/PROGRESSIVE_TUTORIAL.md`, `docs/guides/MIGRATING-FROM-MCP.md`, `docs/guides/WEB_BACKEND_QUICKSTART.md`, `docs/start-here/NATIVE_ADOPTION_GUIDE.md`, `docs/architecture/`, `docs/security/threat-coverage.md`, `docs/release/`, `docs/release/QUALIFICATION.md`, `examples/README.md`, `examples/EXAMPLE_SURFACE_MATRIX.md`, `examples/docker/README.md`, `examples/policies/hushspec-tool-allow.yaml`, `sdks/README.md`, `sdks/typescript/chio-ts/README.md`, `sdks/python/chio-py/README.md`, `sdks/go/chio-go/README.md`.

Deliberately NOT linked (per spec 2.5 "keep out" + research section 3): `docs/reference/CLAIM_REGISTRY.md`, `docs/release/RELEASE_CANDIDATE.md`, `docs/release/RELEASE_AUDIT.md`, `docs/start-here/VISION.md`, `examples/eval-receipt-ingest/metr/README.md`, comptroller/web3/pheromone runbooks. (These exist but are release-gating / strategic / partner surfaces that dilute the first-contact signal.)

---

## Quickstart commands (executed; real output captured)

The quickstart in the README uses exactly these commands. They were run against the binary built from this tree. The kernel is fail-closed: it cannot persist a signed receipt without a receipt store, so `chio check` requires `--receipt-db` to reach an ALLOW verdict (without it the verdict fails closed to DENY with reason `durable receipt persistence unavailable`). The README states this honestly.

Build (debug build was run and finished successfully; release build uses the same crate):

```bash
cargo build --release -p chio-cli   # produces ./target/release/chio
```

Allow case (exit 0):

```bash
./target/release/chio --receipt-db /tmp/chio.db \
  check --policy examples/policies/hushspec-tool-allow.yaml \
  --tool read_file --params '{"path":"README.md"}'
```

Real output (stderr tracing elided; exit code 0):

```
verdict:    ALLOW
tool:       read_file
server:     *
receipt_id: 84c7f76df3104fa17def518e36d3cf14f4f40242b40fee3da3f991e06d7ec8c2
policy:     40f2f61df886735c86ae541a9d4dc0e3423fd4ac23c974f9b8762c4f4304dba4
source:     6d5729b428f9b9de637b07ecc3cb8899b9fe5e85efe3530de5d5e722bb009d4f
mode:       preflight
fixture:    false
```

Deny case (exit 2, tool not in the allowlist):

```bash
./target/release/chio --receipt-db /tmp/chio.db \
  check --policy examples/policies/hushspec-tool-allow.yaml \
  --tool delete_database --params '{}'
```

Real output:

```
verdict:    DENY
tool:       delete_database
server:     *
reason:     requested tool delete_database on server * is not in capability scope
receipt_id: 66db67f045494adef680692fe0a3ec37af349c7a968d1dbd71e819baa7c9e070
policy:     40f2f61df886735c86ae541a9d4dc0e3423fd4ac23c974f9b8762c4f4304dba4
source:     6d5729b428f9b9de637b07ecc3cb8899b9fe5e85efe3530de5d5e722bb009d4f
mode:       preflight
fixture:    false
```

Receipt log (both decisions persisted as signed receipts; `--admin-all` is required because reads fail closed without a tenant boundary):

```bash
./target/release/chio --receipt-db /tmp/chio.db receipt list --admin-all
```

Emits one JSON receipt per line; each carries `"decision":{"verdict":"allow"|"deny"}`, a `policy_hash`, a `kernel_key`, and an Ed25519 `signature`. (Verified: the ALLOW row shows `"verdict":"allow"`, the DENY row `"verdict":"deny"` with the scope reason, each with a distinct `signature`.)

---

## Task 1: Capture the current README as the rollback reference

- [ ] Confirm the working tree README matches what this plan rewrites (134 lines, leads with "Start Here").

  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && wc -l README.md && sed -n '37p' README.md
  ```

  Expected output:

  ```
       134 README.md
  ## Start Here
  ```

  If the line count or `## Start Here` heading differs, STOP: the README has changed since this plan was written; re-read it and reconcile before proceeding.

- [ ] Confirm the working tree is clean for `README.md` so the rewrite is a single reviewable diff.

  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && git status --porcelain README.md
  ```

  Expected output: empty (no lines). If `README.md` already shows as modified, STOP and inspect; do not overwrite uncommitted edits.

## Task 2: Verify every link target still resolves (fail-closed: no dead links)

- [ ] Run the link-existence check for every path the new README will reference. This is the fail-closed gate: any `MISS` line means do not write that link.

  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && for p in \
    LICENSE NOTICE SECURITY.md CONTRIBUTING.md CODE_OF_CONDUCT.md CHANGELOG.md AGENTS.md \
    spec/PROTOCOL.md spec/SECURITY.md \
    docs/README.md docs/install/README.md docs/start-here/PROGRESSIVE_TUTORIAL.md \
    docs/guides/MIGRATING-FROM-MCP.md docs/guides/WEB_BACKEND_QUICKSTART.md \
    docs/start-here/NATIVE_ADOPTION_GUIDE.md docs/architecture docs/security/threat-coverage.md \
    docs/release docs/release/QUALIFICATION.md \
    examples/README.md examples/EXAMPLE_SURFACE_MATRIX.md examples/docker/README.md \
    examples/policies/hushspec-tool-allow.yaml \
    sdks/README.md sdks/typescript/chio-ts/README.md sdks/python/chio-py/README.md sdks/go/chio-go/README.md \
    assets/hero.png; do
    if [ -e "$p" ]; then echo "OK   $p"; else echo "MISS $p"; fi
  done
  ```

  Expected output: every line begins with `OK`. There must be zero `MISS` lines. If any line is `MISS`, remove that link from the README content in Task 4 (do not invent an alternate path).

## Task 3: Verify the quickstart commands still produce ALLOW / DENY / a signed receipt

This proves the README's quickstart is real before it is written. The CLI surface (`--receipt-db` global flag, `check --policy/--tool/--params`, `receipt list --admin-all`) is defined in `crates/chio-cli/src/cli/types.rs:60-62,280-305,331-335` and the receipt-read tenant gate in `receipt list`.

- [ ] Build the binary (release; reuses the workspace cache from the prior debug build).

  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && cargo build --release -p chio-cli 2>&1 | tail -1
  ```

  Expected: a `Finished \`release\` profile` line (a cold release build can take several minutes).

- [ ] Confirm version and the help banner.

  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && ./target/release/chio --version && ./target/release/chio --help | head -1
  ```

  Expected output:

  ```
  chio-cli 0.1.0
  CLI binary for the Chio runtime kernel
  ```

- [ ] Run the ALLOW case and assert exit 0 + `verdict:    ALLOW`.

  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && rm -f /tmp/chio.db && \
  ./target/release/chio --receipt-db /tmp/chio.db check \
    --policy examples/policies/hushspec-tool-allow.yaml \
    --tool read_file --params '{"path":"README.md"}' 2>/dev/null; echo "exit=$?"
  ```

  Expected: a block whose first line is `verdict:    ALLOW` and a final line `exit=0`.

- [ ] Run the DENY case and assert exit 2 + `verdict:    DENY`.

  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && \
  ./target/release/chio --receipt-db /tmp/chio.db check \
    --policy examples/policies/hushspec-tool-allow.yaml \
    --tool delete_database --params '{}' 2>/dev/null; echo "exit=$?"
  ```

  Expected: first line `verdict:    DENY`, a `reason:     requested tool delete_database on server * is not in capability scope` line, and a final line `exit=2`.

- [ ] Confirm both decisions are persisted as signed receipts.

  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && \
  ./target/release/chio --receipt-db /tmp/chio.db receipt list --admin-all 2>/dev/null \
    | grep -c '"signature"'
  ```

  Expected output: `2` (one signed receipt per decision). If this prints anything other than `2`, STOP: the quickstart prose in Task 4 over-claims; reconcile the commands with their real behavior before writing.

## Task 4: Write the new README

- [ ] Overwrite `/Users/connor/Medica/backbay/standalone/arc/README.md` with EXACTLY the following content. (Use the Write tool with this full file body. Do not paraphrase; this is the prose deliverable. House rule: no em dashes - the content below uses only hyphens and parentheses.)

````markdown
<p align="center">
  <img src="assets/hero.png" alt="Chio" width="900" />
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
- **Wraps existing ecosystems instead of replacing them.** MCP, A2A, ACP,
  OpenAPI, and AG-UI become governed Chio tool servers, while the kernel keeps
  dispatch and receipt authority.

## Quickstart

Chio is pre-release (0.1.0) and not yet published to a package registry, so build
the `chio` binary from source:

```bash
git clone https://github.com/backbay-labs/chio.git
cd chio
cargo build --release -p chio-cli   # produces ./target/release/chio
./target/release/chio --help
```

For prebuilt release binaries and the Homebrew tap, see
[docs/install/README.md](docs/install/README.md).

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
> tagged release.

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

Chio governs tool calls across MCP, A2A, ACP, OpenAPI, AG-UI, and provider-native
tool formats (OpenAI, Anthropic, Bedrock, Gemini, Cohere, Groq, Mistral, Ollama).
The kernel owns dispatch and receipt authority for the surfaces it mediates.

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
[CHANGELOG.md](CHANGELOG.md) for the in-progress baseline and
[docs/release/QUALIFICATION.md](docs/release/QUALIFICATION.md) for what the
project will and will not claim.

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) for the
workflow and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community expectations.
Before opening a pull request, run the full verification gate (the same one CI
enforces):

```bash
cargo build --workspace && \
cargo test --workspace && \
cargo clippy --workspace -- -D warnings && \
cargo fmt --all -- --check
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
````

## Task 5: Self-check the written README

- [ ] Assert there are no em dashes (U+2014) anywhere in the file (house rule, fail-closed).

  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && grep -nP '\x{2014}' README.md; echo "emdash-exit=$?"
  ```

  Expected output: no matching lines and `emdash-exit=1` (grep exit 1 = zero matches). If any line prints, replace the em dash with a hyphen or parentheses and rerun.

- [ ] Assert that every local link in the new README resolves on disk (re-check fail-closed: extract each `](path)` target that is not an external URL or in-page anchor, and confirm it exists).

  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && \
  grep -oE '\]\(([^)]+)\)' README.md | sed -E 's/^\]\(//; s/\)$//' \
    | grep -vE '^(https?:|#)' | sort -u \
    | while read -r p; do [ -e "$p" ] && echo "OK   $p" || echo "MISS $p"; done
  ```

  Expected output: every line begins with `OK`. Zero `MISS` lines. If any `MISS` appears, fix or remove that link.

- [ ] Assert that every HTML `href="..."`/`src="..."` link in the new README resolves on disk too (the header and nav use raw HTML, which the markdown `](path)` pass above does not catch; re-check fail-closed: extract each local href/src target that is not an external URL or in-page anchor, and confirm it exists).

  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && \
  grep -oE '(href|src)="[^"]+"' README.md | sed -E 's/^(href|src)="//; s/"$//' \
    | grep -vE '^(https?:|#)' | sort -u \
    | while read -r p; do [ -e "$p" ] && echo "OK $p" || echo "MISS $p"; done
  ```

  Expected output: every line begins with `OK`, covering `LICENSE`, `assets/hero.png`, `docs/README.md`, and `spec/PROTOCOL.md`. Zero `MISS` lines. If any `MISS` appears, fix or remove that link.

- [ ] Confirm no forbidden surfaces leaked into the README (spec 2.5 "keep out": no CLAIM_REGISTRY, RELEASE_CANDIDATE, RELEASE_AUDIT, VISION, metr partner ingest, comptroller/web3/pheromone runbook links, no market-size claims, no artifact counts).

  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && \
  grep -niE 'CLAIM_REGISTRY|RELEASE_CANDIDATE|RELEASE_AUDIT|VISION|metr/|comptroller|pheromone|trillion|McKinsey|artifact count' README.md; \
  echo "forbidden-exit=$?"
  ```

  Expected output: no matching lines and `forbidden-exit=1`. If any line prints, remove the offending text. (Note: `web3` is allowed to be absent; do not add it.)

- [ ] Confirm the file is in the expected size band (~150-220 lines per spec 2.5).

  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && wc -l README.md
  ```

  Expected: a line count between 150 and 235. (The content above is ~230 lines including blank separators; ~180 non-blank.) If it is far outside this band, the wrong content was written; re-do Task 4.

- [ ] Render-sanity: confirm the value-first structure (first H2 is "What is Chio", and "Start Here"/"Supported Paths"/"Current Boundary"/"External Evidence" headings from the old README are gone).

  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && grep -nE '^## ' README.md
  ```

  Expected headings in order: `## What is Chio`, `## Why Chio`, `## Quickstart`, `## Choose your path`, `## Architecture`, `## Integrations and SDKs`, `## Security and trust`, `## Examples`, `## Project status`, `## Contributing`, `## License`. There must be no `## Start Here`, `## Supported Paths`, `## Current Boundary`, or `## External Evidence` heading.

## Task 6: Commit

- [ ] Stage and commit only the README (conventional commit; the working branch is already a feature branch off `main`, so no new branch is needed).

  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && git add README.md && git status --porcelain
  ```

  Expected output: exactly one line, `M  README.md`. If any other path appears, unstage it (`git restore --staged <path>`); this plan changes only `README.md`.

- [ ] Create the commit.

  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && git commit -m "$(cat <<'EOF'
docs: rewrite README value-first with a runnable quickstart

Replace the process-first, link-heavy README with a value-first front
door: what Chio is, why it exists, a real allow/deny/signed-receipt
quickstart against examples/policies/hushspec-tool-allow.yaml, the
five-component architecture, the three real SDKs, a security/trust
section, and an honest 0.1.0 pre-release status. Add a CI-status and
docs badge alongside the existing License and MSRV badges. Every link
target was verified to exist; no crates.io/npm/PyPI version badges
since 0.1.0 is unreleased.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
  ```

  Expected: a commit summary line referencing `README.md` changed.

- [ ] Confirm the commit landed and the tree is clean for the README.

  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && git log --oneline -1 && git status --porcelain README.md
  ```

  Expected: the top commit is `docs: rewrite README value-first ...` and `git status --porcelain README.md` prints nothing.

---

## Self-Review

### (1) Spec-item to task mapping (spec section 2.5 / research section 3)

The README outline has 12 sections plus acceptance criteria. Mapping each to the written content in Task 4:

| Spec 2.5 item | Covered by |
| --- | --- |
| 1. Header: hero, name, tagline, subtitle, badges (License, MSRV 1.93, CI status, docs), nav row | Task 4 header block: `assets/hero.png`, `Chio`, "Governed tool access for AI systems", subtitle, four badges (License, MSRV 1.93, CI via `ci.yml`, docs), nav row with What/Why/Quickstart/Architecture/Integrations/Security/Docs/Spec |
| 2. What is Chio (kernel framing + "MCP tells agents how / Chio proves what" + signed capability-bound receipt) | `## What is Chio` (2 paragraphs, the exact VISION one-liner, the receipt primitive) |
| 3. Why Chio (4 bullets: no identity/delegation/budget/receipt; fail-closed; native HushSpec; wraps MCP/A2A/ACP/OpenAPI) | `## Why Chio` (4 bullets, exact set) |
| 4. Quickstart (one install line + one runnable allow/deny/receipt + status note) | `## Quickstart` (from-source build, allow, deny, receipt list, status blockquote) |
| 5. Choose your path (3 bullets: MCP / web backend / native) | `## Choose your path` (3 bullets + tutorial pointer) |
| 6. Architecture (five components + kernel-as-mediator + pointer to docs/architecture + AGENTS.md; name only crates a user touches) | `## Architecture` (numbered five components, ASCII diagram, names `chio`/`chio-api-protect`/`chio-kernel`/`chio-policy`/`chio-guards`, links AGENTS.md + docs/architecture/) |
| 7. Integrations and SDKs (protocols one-liner + three real SDKs + others in progress) | `## Integrations and SDKs` (protocol list, SDK table, SDK index link) |
| 8. Security and trust (fail-closed, TCB boundary, RFC 8785; link SECURITY.md + threat model) | `## Security and trust` (3 bullets; SECURITY.md, spec/SECURITY.md, docs/security/threat-coverage.md) |
| 9. Examples pointer | `## Examples` (index, surface matrix, docker) |
| 10. Project status (honest 0.1.0 paragraph) | `## Project status` (0.1.0, v1-only, internal-label disclaimer, CHANGELOG + QUALIFICATION) |
| 11. Contributing (link + four-command gate) | `## Contributing` (CONTRIBUTING.md, CODE_OF_CONDUCT.md, four-command gate) |
| 12. License (Apache-2.0, LICENSE + NOTICE) | `## License` |
| Acceptance: value-first | First H2 is "What is Chio"; no "Start Here"/"Supported Paths"/"Current Boundary" headings (Task 5 grep enforces) |
| Acceptance: real quickstart | Commands executed in Task 3 with captured ALLOW/DENY/receipt output |
| Acceptance: accurate badges, no premature crates.io/npm/PyPI | Four badges only; Task 5 forbidden-grep + outline forbid version badges |
| Acceptance: describes what IS, no milestone history / artifact counts / market claims | Task 5 forbidden-grep blocks trillion/McKinsey/artifact-count/CLAIM_REGISTRY/etc. |
| Acceptance: no em dashes | Task 5 em-dash grep |
| Acceptance: MSRV 1.93 + version 0.1.0 confirmed from root Cargo.toml | Ground facts section (Cargo.toml:171-175) |

Gaps: none. Every outline item maps to written prose. The optional `SUPPORT.md` / "Getting help" add from research section 4 is explicitly out of scope for this README rewrite (it is a separate top-level-doc addition, not part of the spec's Phase 0 "Rewrite the README" item) and is intentionally omitted to keep this plan single-responsibility.

### (2) Placeholder red-flag scan

Scanned the plan for TBD / TODO / "implement later" / "similar to Task N" / "add error handling" / "write tests for the above". None present. The README body in Task 4 is the complete final file text, not a description. Every command shows expected output. The quickstart receipt_id/policy hashes in the rendered README are intentionally truncated with `...` (they are run-specific and non-deterministic across machines); this is presentation, not a placeholder, and the plan's Task 3 verifies the real (untruncated) values and the verdict/exit invariants that ARE stable. This is called out so a reviewer does not mistake the `...` for an unfilled blank.

### (3) Type / name / path consistency

- Binary name `chio`, crate `chio-cli`, `default-run = "chio"`: consistent across ground facts, Task 3, and the README quickstart (`cargo build --release -p chio-cli` -> `./target/release/chio`). Verified against `crates/chio-cli/Cargo.toml:9,17-18`.
- CLI flags used (`--receipt-db` global, `check --policy/--tool/--params`, `receipt list --admin-all`) match `crates/chio-cli/src/cli/types.rs` (`--receipt-db` at `:60-62`; `Check` at `:280-305`; `Receipt` at `:331-335`; `receipt list` tenant gate observed at runtime). The README does not reference any flag not present in that file.
- Policy file `examples/policies/hushspec-tool-allow.yaml`: same path in ground facts, Task 2 link check, Task 3 commands, and the README. It is `tool_access`-only (no output-sensitive guards), which is why preflight mode yields a clean ALLOW; the heavier `canonical-hushspec.yaml` was deliberately NOT used because it does not cleanly ALLOW `read_file` in preflight (its guard pipeline yields a non-ALLOW exit, confirmed at runtime), which would make the quickstart confusing.
- Badge URLs: License/MSRV reuse the exact shields.io strings already in the repo; CI badge uses the verified `ci.yml` workflow path and `main` branch; docs badge points at `docs/README.md` (exists). No crates.io/npm/PyPI badge (0.1.0 unreleased).
- Version `0.1.0` and MSRV `1.93` stated identically in the header badge, the Quickstart status note, the Project status section, and the ground facts (Cargo.toml:171-175).
- Repo URL `https://github.com/backbay-labs/chio` matches `Cargo.toml:175` and `CONTRIBUTING.md:42`.

All three self-review checks were run; no inconsistencies remain to fix.
