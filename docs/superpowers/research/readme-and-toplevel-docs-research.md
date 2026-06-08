# Chio: README and Top-Level Documentation Research

Research source material for rewriting the README and top-level docs accurately.
Read-only investigation; no source, scripts, configs, or workflows were modified.

Scope of evidence: `README.md`, `AGENTS.md`, `docs/README.md`, `CLAUDE.md`,
`spec/PROTOCOL.md` (intro), `CHANGELOG.md`, `RELEASE_AUDIT.md`, `CONTRIBUTING.md`,
`SECURITY.md`, `NOTICE`, `LICENSE`, root `Cargo.toml`, key crate manifests, the
`chio-cli` command surface, the `sdks/` and `examples/` trees, and the
`.github/workflows/` inventory.

---

## 1. What Chio Is (accurate)

### One-paragraph definition

Chio is a Rust runtime and trust-control layer that sits between an AI agent and
the actions (tool calls) it is allowed to take. A trusted kernel mediates every
governed tool call: it validates time-bounded, cryptographically verifiable
capability tokens, runs a guard pipeline over inputs and outputs before anything
crosses a trust boundary, enforces policy and budgets, and signs an append-only,
Merkle-committed receipt for every decision (allow, deny, cancelled, incomplete).
The design goal is non-repudiation: for any agent action there exists a signed,
timestamped, capability-bound proof of what was authorized and what happened.
Chio ships native policy and guard engines (no external policy engine required)
and wraps existing ecosystems (MCP, A2A, ACP, OpenAPI, AG-UI, and provider tool
formats) as governed Chio tool servers so that the kernel owns dispatch and
receipt authority. The project was formerly named ARC.

### Core value proposition

The clearest framing comes from `docs/start-here/VISION.md`:
"MCP tells agents how to call tools. Chio proves what they were allowed to do,
what it cost, and what happened." The core primitive is the signed,
capability-bound receipt. Differentiators versus a plain tool-call wire format
(MCP): identity, capability delegation, fail-closed policy enforcement, budget
metering, and non-repudiable receipts, fused at the protocol layer rather than
bolted on as an audit sidecar.

### The five components (from AGENTS.md)

1. Agent: untrusted, LLM-powered process that consumes tools via capability
   tokens.
2. Runtime Kernel: trusted mediator (the TCB) that validates capabilities, runs
   the guard pipeline, and signs receipts.
3. Tool Servers: sandboxed processes implementing tools, isolated from each
   other and from the agent.
4. Capability Authority: issues, scopes, and revokes time-bounded capability
   tokens.
5. Receipt Log: append-only, Merkle-committed log of signed attestations over
   every decision and tool call.

### The main surfaces a user actually interacts with

The workspace ships ~107 crates (`crates/` count) under the `chio-*` prefix.
Most are internal. The user-facing surface is much smaller. Crates marked
`public_entrypoint = true` in their `Cargo.toml` metadata: `chio-cli`,
`chio-core`, `chio-kernel`, `chio-guards`, `chio-policy`, `chio-manifest`,
`chio-control-plane`, `chio-conformance`, `chio-mcp-edge`, `chio-mcp-adapter`,
`chio-mcp-remote`, `chio-hosted-mcp`, `chio-api-protect`, `chio-wall`.

Primary products and the binary:
- `chio-cli` builds the single `chio` binary (`default-run = "chio"`). Described
  as "CLI binary for the Chio runtime kernel."
- `chio-api-protect`: "Zero-code reverse proxy that protects HTTP APIs with Chio
  receipts."
- `chio-wall` / `chio-wall-core`: a companion product (Chio-Wall) built on Chio
  for recording tool-boundary control evidence (information-domain separation).

The supported CLI entrypoints the README highlights:
- `chio check`: evaluate a single governed tool call and inspect the verdict.
- `chio api protect`: protect an HTTP API with the zero-code reverse proxy.
- `chio mcp serve`: wrap an MCP server with Chio governance.
- `chio mcp serve-http`: expose the governed MCP edge over Streamable HTTP.
- `chio trust serve`: run the shared trust-control service.

The actual top-level CLI command set is much larger (from
`crates/chio-cli/src/cli/types.rs`): Run, Check, Init, Api, Mcp, Trust, Receipt,
Evidence, Certify, Did, Passport, Reputation, Cert, Guard, Conformance,
Federation, Attest, Runtime, Pheromone, Replay, Settle, Lineage, Doctor, Arena,
Bind. So the binary surface spans far beyond the five "supported" entrypoints;
many subcommands map to research/economics/web3 surfaces.

Core library crates (descriptions from manifests):
- `chio-core`: "Core types for the Chio protocol."
- `chio-kernel`: "Chio runtime kernel: capability validation, guard evaluation,
  receipt signing."
- `chio-guards`: "Security guards for the Chio runtime kernel."
- `chio-policy`: "HushSpec policy format ... parse, validate, merge, evaluate,
  and compile to Chio guards." (Policy language is named HushSpec.)
- `chio-manifest`: "Chio tool server manifest format: definitions, signing,
  verification."
- `chio-control-plane`: "Trust-control service, client, and shared runtime
  support for Chio."

### Crate map groups (AGENTS.md + Cargo.toml workspace sections)

Core & types; Kernel variants (incl. `chio-kernel-browser`, `chio-kernel-mobile`
for WASM/mobile); Guards & policy; Protocol adapters & edges (MCP, A2A, ACP,
OpenAPI, AG-UI, Envoy ext-authz, plus per-provider tool adapters: OpenAI,
Anthropic, Bedrock, Gemini, Cohere, Groq, Mistral, Ollama); Economics &
settlement (`chio-credit`, `chio-market`, `chio-settle`, `chio-link`,
`chio-anchor`, `chio-underwriting`, `chio-appraisal`, `chio-web3`); Supply-chain
attestation (`chio-attest-*`, `chio-tee*`, `chio-weights`, `chio-custody-hw`);
Identity / credentials / federation (`chio-did`, `chio-credentials`,
`chio-federation`, `chio-governance`, `chio-reputation`); Observability
(`chio-siem`, `chio-metering`); Control plane & storage; HTTP & session.

### Supported protocols and adapters

- MCP (Model Context Protocol): wrapped where Chio owns dispatch and receipt
  authority; hosted/remote provider-executed activity is trace-only unless a
  live kernel-mediated dispatch boundary is proven.
- A2A v1.0.0: consumed through `chio-a2a-adapter` only where receipt authority is
  backed by a live kernel authorization receipt.
- ACP (`chio-acp-edge`, `chio-acp-proxy`), OpenAPI (`chio-openapi`,
  `chio-openapi-mcp-bridge`), AG-UI (`chio-ag-ui-proxy`), Envoy ext-authz.
- Provider-native tool adapters: OpenAI Responses, Anthropic Messages, Bedrock
  Converse (these three have recorded conformance evidence per `RELEASE_AUDIT.md`),
  plus Gemini, Cohere, Groq, Mistral, Ollama.
- Identity: `did:chio` method, Agent Passports, OAuth/JWT federation admission,
  SPIFFE / Azure workload identity, DPoP sender-constrained invocation.

### SDKs

README table lists three primary SDKs:
- TypeScript: `@chio-protocol/sdk` (`sdks/typescript/chio-ts`)
- Python: `chio-sdk` (`sdks/python/chio-py`)
- Go: `chio-go` (`sdks/go/chio-go`)

The `sdks/` tree is broader and includes aspirational / partial language targets:
`cpp`, `dotnet`, `go`, `guard`, `jvm`, `k8s`, `lambda`, `python`, `rust`,
`swift`, `typescript`. `docs/operations/SDK_PARITY_EXECUTION_ROADMAP.md` exists,
which signals SDK parity is still in progress (TS/Python/Go are the real ones).

### Current maturity / release status (what IS vs aspirational)

What IS shipped / true today:
- Workspace version is `0.1.0` (root `Cargo.toml`); MSRV / rust-version 1.93.
- Repository identity: `https://github.com/backbay-labs/chio`. License: Apache-2.0
  (`LICENSE`, `NOTICE` "Chio, Copyright 2026 Backbay Labs"). Security contact:
  `security@backbay.io`.
- Protocol spec `spec/PROTOCOL.md` is "Version: 1.0", dated 2026-04-14, status
  "Current bounded Chio release profile." All Chio-owned protocol/schema/SDK/
  runtime surfaces are v1-only.
- The kernel, native policy (HushSpec) and guard runtime, receipt/attestation
  pipeline, MCP/A2A/ACP/OpenAPI/AG-UI edges, provider adapters, and TS/Python/Go
  SDKs exist as code. CI is extensive: 73 files under `.github/workflows/`
  including fuzzing (ClusterFuzzLite), formal verification (Apalache/Kani),
  cargo-vet, conformance matrices, bench regression.

What is explicitly pre-release / bounded / aspirational (per the docs' own framing):
- `CHANGELOG.md`: "The first public baseline, version 0.1.0, is in preparation
  and has not yet been tagged or released." Everything is `[Unreleased]`.
- README, SECURITY.md, CONTRIBUTING.md, PROTOCOL.md all repeat: "Chio is
  pre-release."
- Older `v2.x`/`v3.x` labels in planning/release/research docs are internal
  milestone labels, not protocol or wire compatibility versions (README is
  careful to say this).
- Many surfaces (web3 anchor/settle/link, autonomy/insurance automation,
  pheromone relay, public identity network, comptroller) are described as
  "bounded" runtimes plus "machine-readable artifacts" that are evidence-only
  unless a live kernel-mediated dispatch path exists. PROTOCOL.md is explicit:
  artifact/extension/web3/directory data "cannot widen signed Chio truth or
  capability scope."
- `docs/start-here/VISION.md` is labeled strategic narrative, not the
  authoritative claim gate; it cites market-size and competitor framing that
  should not appear as factual headline claims in a README.
- The authoritative claim boundary lives in `docs/reference/CLAIM_REGISTRY.md`
  and `docs/release/QUALIFICATION.md`; release go/hold state in
  `docs/release/RELEASE_AUDIT.md` and `RELEASE_CANDIDATE.md`.

Per the owner's stated preference: describe what IS. Do not headline internal
milestone version history, artifact counts, branch names, or market-size
projections.

---

## 2. Current README Problems

The current `README.md` is 134 lines. It is link-heavy and reasonably honest
about scope, but it does not function as a first-contact README for a serious OSS
infrastructure project. Specific problems:

1. No real quickstart. There is no copy-pasteable install command and no minimal
   runnable example inline. Every path is a link out to `docs/`. A new visitor
   cannot see Chio do anything (one deny, one allow, one receipt) without leaving
   the README. The single most important thing (`cargo install` or a download +
   `chio check ...`) is absent.

2. Audience confusion / "supported paths" framing leads with process, not value.
   The body opens with three "supported paths" and a "Current Boundary" section
   before the reader understands what Chio does or why. The structure reads like
   an internal release-gating index rather than a product front door.

3. Insider vocabulary with no definitions. Terms like "trust-control service,"
   "HushSpec," "governed decision," "supported candidate surface,"
   "qualification lanes," "external evidence," and "bounded operational profile"
   appear without explanation. These are meaningful internally but opaque to an
   outside reader.

4. Weak / minimal badges. Only License and MSRV badges. For a repo with 73 CI
   workflows there is no build/CI status, no crates.io / npm / PyPI version, no
   docs link, no security/fuzzing badge. (Note: 0.1.0 is unreleased, so package
   badges may be premature, but a CI status badge is warranted.)

5. No architecture overview. The README never shows the five-component model or
   a diagram of where the kernel/guards/receipts sit relative to the agent and
   tool servers. The clearest explanation (AGENTS.md five components, the
   "MCP tells agents how / Chio proves what" line) is buried in AGENTS.md and
   docs/start-here/VISION.md, not surfaced.

6. Hero image carries the load. The visual identity (`assets/hero.png`) is the
   only thing communicating "what is this" above the fold besides the one-line
   tagline; if the image fails to load, the top of the README is nearly empty.

7. Link sprawl into a sprawling docs tree. The README links to ~20 docs paths;
   `docs/` itself contains 320 markdown files across 37 subdirectories and
   `spec/` has 27 more. Many links point at release/qualification/comptroller/
   web3 runbooks that are not relevant to a first-time reader and dilute the
   "where do I start" signal.

8. Security/trust posture under-sold. Chio's entire reason to exist is the
   security/non-repudiation story, yet the README has no "Security and trust"
   section. SECURITY.md exists and is good, but the README does not summarize the
   fail-closed posture, the TCB boundary, or link to the threat model
   (`spec/SECURITY.md`, `docs/security/threat-coverage.md`).

9. Status signal is muddled. "Chio is pre-release ... v1-only ... older v2.x/v3.x
   labels are internal" is a defensive disclaimer about version labels rather
   than a clear maturity statement a user can act on ("0.1.0, pre-release, APIs
   may change, not yet on crates.io").

10. No contributing / community pointer in the body. CONTRIBUTING.md,
    CODE_OF_CONDUCT.md, and SECURITY.md all exist and are solid, but the README
    only links LICENSE at the very bottom. No "Contributing" or "Security"
    section.

What the current README does well (keep): honest scoping of supported vs
aspirational; the SDK table; pointer to `spec/PROTOCOL.md`; Apache-2.0 clarity;
careful disclaiming of internal milestone labels.

---

## 3. Proposed README Outline

Target: a serious OSS infrastructure README, roughly 150-220 lines, value-first,
with one runnable example, then links into `docs/`. Keep the no-em-dash and
fail-closed conventions. Describe what IS; do not headline milestone history,
artifact counts, branch names, or market projections.

1. Header block
   - Hero image (keep `assets/hero.png`), project name "Chio".
   - One-line tagline: "Governed tool access for AI systems."
   - One-line subtitle: capability validation, fail-closed policy, budgets, and
     signed receipts.
   - Badges: License (Apache-2.0), MSRV 1.93, CI status, and a docs link. Hold
     crates.io/npm/PyPI version badges until 0.1.0 is actually published.
   - A short nav row (What / Why, Quickstart, Architecture, Integrations,
     Security, Docs, Spec).

2. What is Chio (3-5 sentences, no jargon)
   - The kernel-between-agent-and-tools framing, plus the one-liner from VISION:
     "MCP tells agents how to call tools. Chio proves what they were allowed to
     do, what it cost, and what happened." State the core primitive: a signed,
     capability-bound receipt for every decision.

3. Why Chio (the problem, 3-4 bullets)
   - No identity, delegation, budget, or receipt at the tool-call layer today.
   - Fail-closed by design: errors deny; invalid policy rejects at load.
   - Native policy (HushSpec) and guards; no external policy engine required.
   - Wraps existing ecosystems (MCP, A2A, ACP, OpenAPI) rather than replacing
     them, while the kernel keeps dispatch and receipt authority.

4. Quickstart (the critical missing piece)
   - Install: the single supported install line (GitHub release binary or
     Homebrew tap) plus `chio --help` to verify. Reference `docs/install`.
   - Minimal end-to-end example inline: scaffold/copy
     `examples/policies/canonical-hushspec.yaml`, run `chio check ...` against a
     sample tool call, show one deny, one allow, and the resulting signed
     receipt. This is the "prove one deny, one allow, one receipt" flow the
     migration guide already describes; surface it inline.
   - Status note: "0.1.0, pre-release. APIs and wire surfaces may change before
     the first tagged release."

5. Choose your path (condensed from current "Supported Paths")
   - MCP migration / coding agents -> `docs/guides/MIGRATING-FROM-MCP.md`
   - Web backend -> `docs/guides/WEB_BACKEND_QUICKSTART.md`
   - Native Chio tool server -> `docs/start-here/NATIVE_ADOPTION_GUIDE.md`
   - Keep this to three short bullets, not the current multi-subsection block.

6. Architecture overview (new, brief)
   - The five components (Agent, Runtime Kernel/TCB, Tool Servers, Capability
     Authority, Receipt Log) as a short list or simple ASCII/diagram.
   - One sentence on the kernel as the trusted mediator that signs receipts.
   - Pointer to `docs/architecture/` and `AGENTS.md` for the crate map. Do not
     enumerate 107 crates in the README; name only the handful a user touches
     (`chio` CLI, `chio-api-protect`, `chio-kernel`, `chio-policy`,
     `chio-guards`).

7. Integrations and SDKs
   - Protocols/adapters one-liner (MCP, A2A, ACP, OpenAPI, AG-UI, provider tool
     formats), linking the integration docs.
   - SDK table: TypeScript `@chio-protocol/sdk`, Python `chio-sdk`, Go `chio-go`
     (the three real ones). Note other languages are in progress, link the SDK
     index rather than implying parity.

8. Security and trust posture (new)
   - Fail-closed summary, the TCB boundary, canonical JSON (RFC 8785) for signed
     payloads.
   - Link `SECURITY.md` (disclosure) and `spec/SECURITY.md` /
     `docs/security/threat-coverage.md` (threat model).

9. Examples
   - Point to `examples/README.md` and the docker smoke path; do not list all 37
     example directories.

10. Project status and roadmap
    - One honest paragraph: 0.1.0, pre-release, v1 protocol profile, not yet
      tagged/published. Link `docs/release/` for the qualification/claim
      boundary, but frame it as "what we will and will not claim" rather than as
      an internal gate index. Link `CHANGELOG.md`.

11. Contributing
    - Short paragraph + link to `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and the
      verification gate (the four-command build/test/clippy/fmt line).

12. License
    - Apache-2.0, link `LICENSE` and `NOTICE`.

Things to deliberately NOT put in the README: the large-document status table
(belongs in docs/README.md, already there); comptroller/web3/pheromone runbook
links; internal milestone version history; artifact counts; market-size and
competitor claims from VISION.

---

## 4. Top-Level Doc-Set Recommendation

### Files that already exist at root and are good (keep, light edits only)

- `README.md` (rewrite per outline above).
- `LICENSE` (Apache-2.0) and `NOTICE`: correct, keep.
- `CONTRIBUTING.md`: strong already (build, verification gate, house rules,
  conventional commits, PR flow, DCO-style license-of-contributions). Keep;
  ensure it stays the single source for the contributor workflow so README only
  summarizes and links.
- `CODE_OF_CONDUCT.md`: Contributor Covenant, keep.
- `SECURITY.md`: strong coordinated-disclosure policy with `security@backbay.io`,
  SLAs, safe harbor, supported-versions note. Keep; README should link it.
- `CHANGELOG.md`: Keep a Changelog format, currently `[Unreleased]` toward
  0.1.0. Keep; this is the right place for version history (not the README).
- `AGENTS.md`: canonical agent/contributor overview with the five components and
  crate map. Keep as the deep "what is this and how is it organized" companion;
  README's architecture section links here.
- `CLAUDE.md`: agent entry point, fine as-is.

### Recommended minimal top-level doc set (target end state)

Required for a serious OSS infra repo, in priority order:
- `README.md` (front door, per outline).
- `LICENSE`, `NOTICE` (present, good).
- `CONTRIBUTING.md` (present, good).
- `CODE_OF_CONDUCT.md` (present, good).
- `SECURITY.md` (present, good).
- `CHANGELOG.md` (present, good).
- `docs/` as the documentation hub with `docs/README.md` as its index (present).

Consider adding (currently missing):
- `SUPPORT.md` or a "Getting help" section: where to ask questions
  (issues vs discussions). Low effort, helps OSS hygiene.
- A `.github/` issue/PR template set if not already present (the repo has a
  `.github/workflows/README.md` but template presence was not confirmed in this
  pass).
- A `GOVERNANCE.md` only once the project opens up to external maintainers;
  premature at 0.1.0, note as future.

### How README should link into docs/

The README is the front door; `docs/README.md` is the hub. The README should
link only a curated handful and let `docs/README.md` carry the full index:
- Install: `docs/install/README.md`
- First run: `docs/start-here/PROGRESSIVE_TUTORIAL.md`
- The three adoption guides (MCP, web backend, native).
- Architecture: `docs/architecture/` + `AGENTS.md`.
- Protocol spec: `spec/PROTOCOL.md` (the normative root).
- Security/threat model: `SECURITY.md` + `spec/SECURITY.md`.
- Full docs index: `docs/README.md`.

### Docs-tree observation (informs a separate cleanup, not this README task)

`docs/` holds 320 markdown files across 37 subdirectories; `spec/` adds 27. The
docs index already distinguishes live contracts from roadmap/research/historical
material and labels large documents by currentness, which is good practice. The
README should not try to mirror this; it should point at `docs/README.md` and let
the hub do the routing. The volume of release/comptroller/web3/pheromone runbook
material at the top level of `docs/README.md` is a candidate for a later
"archive vs live" pass, but that is out of scope for the README rewrite.

### Root-directory sprawl note (context, not a README change)

The repo root has ~52 entries including build/artifact directories that arguably
should not be tracked or surfaced (`_apalache-out`, `coverage`, `target`,
`arena`). This is a separate professionalization concern from the README; flagged
here only so the README's "architecture/layout" section does not accidentally
document throwaway directories as if they were part of the project structure.

---

## Appendix: Key facts with sources

- Workspace crate count: 107 (`ls crates/`). AGENTS.md says "~105".
- Version 0.1.0, MSRV 1.93, repo `github.com/backbay-labs/chio`, Apache-2.0
  (root `Cargo.toml`, `LICENSE`, `NOTICE`).
- Protocol spec: v1.0, 2026-04-14, "Current bounded Chio release profile"
  (`spec/PROTOCOL.md`).
- Policy language is named HushSpec (`chio-policy` description; README references
  `examples/policies/canonical-hushspec.yaml`).
- Public-entrypoint crates (14): chio-cli, chio-core, chio-kernel, chio-guards,
  chio-policy, chio-manifest, chio-control-plane, chio-conformance, chio-mcp-edge,
  chio-mcp-adapter, chio-mcp-remote, chio-hosted-mcp, chio-api-protect, chio-wall.
- Single binary: `chio` (from `chio-cli`, `default-run = "chio"`).
- Three real SDKs: TS `@chio-protocol/sdk`, Python `chio-sdk`, Go `chio-go`;
  other languages in `sdks/` are in-progress.
- CI: 73 workflow files in `.github/workflows/`.
- README is 134 lines; AGENTS.md 58; CHANGELOG 39; PROTOCOL.md 3073.
- Security contact: security@backbay.io; copyright holder: Backbay Labs.
