# Agent G: Proof Room + Developer Experience

Confidence: high for source inventory and product gaps, moderate for schedule estimates. This document is a research and planning draft only. It proposes no code changes.

## Executive Position

Chio has enough real proof machinery to show a serious trust story, but the current developer and enterprise experience is fragmented. The proof path is split across `chio receipt`, `chio evidence`, `chio replay`, `chio lineage`, `chio attest buyer`, `chio-wall`, the IOA web3 Evidence Console, static demo viewers, release scripts, and partner proof documents. That fragmentation weakens the product claim more than any single missing verifier feature.

The launch surface should converge on a single concept: Proof Room. Proof Room is the human and machine review surface for "what happened, who authorized it, which boundary mediated it, which evidence was authenticated, which claims are only local or advisory, and which denials prove the system fails closed." The developer entrypoint should converge on `chio proof`.

The strongest recommendation is to stop treating the web3 Evidence Console, lineage viewer, proof-package verifier, receipt dashboard, and release docs as separate stories. They should become one review kit with one signed bundle format, one verifier report, one UI, one CLI namespace, and explicitly labeled claim levels.

## Current Assets

### CLI Surfaces

- `crates/chio-cli/src/main.rs:1-15` documents the basic Chio CLI contract as `chio run`, `chio check`, and `chio mcp serve`.
- `crates/chio-cli/src/main.rs:84-115` wires parsed CLI options into `dispatch_cli::run`.
- `crates/chio-cli/src/cli/types.rs:46-98` already exposes global proof-relevant switches: `--json`, `--format`, `--receipt-db`, `--revocation-db`, `--authority-seed-file`, `--authority-db`, `--budget-db`, `--session-db`, `--control-url`, and `--control-token`.
- `crates/chio-cli/src/cli/types.rs:267-561` defines the current top-level command set. The proof-relevant commands are `run` (`270-278`), `check` (`281-305`), `init` (`308-311`), `receipt` (`332-335`), `evidence` (`338-341`), `certify` (`344-347`), `attest` (`391-395`), `replay` (`427`), `lineage` (`447-450`), `doctor` (`467`), and `start` (`527-560`).
- `crates/chio-cli/src/cli/dispatch.rs:47-133` dispatches current commands. There is no top-level `Proof` command today.
- `crates/chio-cli/src/scaffold.rs:14-57` implements `chio init`, writing `Cargo.toml`, `README.md`, `policy.yaml`, `.gitignore`, `src/bin/hello_server.rs`, and `src/bin/demo.rs`, then printing next steps. This is useful for local developer onboarding, but it does not produce a portable proof bundle.
- `crates/chio-cli/src/cli/types/receipt.rs:3-124` defines `chio receipt list`, `health`, `flush`, `checkpoint status/create/verify`, and `explain`. It includes an important tenant boundary: receipt reads require `--tenant` or `--admin-all` (`37-43`, `95-101`).
- `crates/chio-cli/src/cli/types/receipt.rs:62-72` and `88-93` state that bilateral receipt explain mode performs structural inspection and does not perform Ed25519 verification. This is correct, but dangerous if surfaced as a final proof verdict.
- `crates/chio-cli/src/cli/types/receipt.rs:126-224` defines `chio evidence export`, `verify`, `import`, and federation policy creation. `evidence export --require-proofs` is available at `157-159`.
- `crates/chio-cli/src/cli/replay.rs:66-144` implements replay verification and exit codes. Replay can require a trusted kernel public key unless `--from-tee` is set, and it distinguishes verdict drift, signature mismatch, parse error, schema mismatch, and redaction mismatch.
- `crates/chio-cli/src/cli/dispatch.rs:451-529` dispatches `chio attest buyer`, `supply-chain`, and `runtime-quote`. Buyer commands include proof-package verification, packet verification, and explanation.
- `crates/chio-attest-buyer/README.md:1-10` defines the public buyer proof verification boundary and delegates full proof replay to the hardened verifier core.
- `crates/chio-attest-buyer-core/README.md:1-9` describes an offline proof-package verifier with no network dependency.
- `crates/chio-attest-buyer/src/api.rs:201-220` exposes `verify_proof_package_json(proof_package_json, verifier_trust_bundle_json, verification_context_json) -> ChioProofVerificationReport`.

### Receipt Dashboard, Static Verification, And Proof Artifacts

- `crates/chio-wall/README.md:1-9` describes a companion product CLI that exports and validates a bounded Chio-Wall control-path package plus a Chio evidence bundle. This is a product-specific proof surface, not the generic proof room.
- `crates/chio-wall/src/commands.rs:56-74` includes export summary fields for a control package and `chio_evidence_dir`.
- `crates/chio-eval-receipt/README.md:1-18` describes a reference verifier for `chio.eval-report.bundle.v1`: schema validation, corpus SHA-256 recomputation, detached memo-signature checks, fail-closed behavior, and a closed schema.
- `crates/chio-eval-receipt/README.md:31-41` lists verifier entrypoints: `verify`, `verify-fixture`, `verify-memo`, and Python bindings.
- `crates/chio-eval-receipt/src/bin/cli.rs:8-15` explicitly warns that `synthetic-test-sample` is intentionally not `sigstore-cosign`; real partner cryptographic attestation is deferred.
- `crates/chio-attest-verify/README.md:1-6` says `chio-attest-verify` is the single source of truth for Sigstore verification.
- `crates/chio-attest-verify/README.md:28-36` says `verify_bundle` runs keyless verification but currently returns `rekor_inclusion_verified=false`; callers that require Rekor inclusion must deny while that remains false.
- `scripts/check-chio-proof-package.sh:27-35` lists proof-package fixture paths for selective disclosure, buyer-auditor packages, trust bundles, verification context, verifier reports, negative cases, and schema registry.
- `scripts/check-chio-proof-package.sh:59-205` checks schema, verifier report acceptance, BBS reveal-set claims, unsupported-predicate denial, trust-bundle disclosure policy, bilateral envelopes, leases, governance receipts, authority fields, and negative corpus breadth.
- `scripts/check-chio-proof-package.sh:284-295` states that the offline verifier lives in `chio-attest-buyer-core`, the top-level CLI verify verb was removed, and tests now run through lower-level crates and scripts.
- `.github/workflows/chio-proof-package.yml:1-15` and `40-56` run the proof-package script for relevant paths.
- `scripts/generate-proof-report.sh:219-248` writes `target/formal/proof-report.json` with boundary status, target, property coverage, assumptions, claim gate, gate results, tool versions, artifact hashes, source locations, git, and CI metadata.
- `scripts/check-proof-report.sh:6-53` generates the proof report if missing and requires the expected schema, gates, tool versions, artifact hashes, source locations, git metadata, and claim gate.

### Lineage Demo

- `crates/chio-lineage/README.md:1-9` describes a provenance and lineage DAG indexer for signed receipts, capabilities, signed receipt-lineage statements, OTEL receipt export, and replay corpus integration.
- `docs/demo/lineage/README.md:1-10` documents a static viewer with no build step.
- `docs/demo/lineage/README.md:13-29` defines the demo wire format: `schema_version = "chio.lineage.graph/v1"`, produced by `chio lineage query --emit demo --json > lineage.json`.
- `docs/demo/lineage/README.md:30-41` intentionally forbids import maps, bundlers, and CDNs.
- `docs/demo/lineage/README.md:43-54` makes evidence classes visible and warns that asserted edges must not be treated as verified edges.
- `docs/demo/lineage/index.html:14-50` provides file loading, sample loading, node table, edge table, and empty-state rendering.
- `docs/demo/lineage/lineage.js:65-89` rejects schema mismatch and renders summary plus truncation metadata.
- `docs/demo/index.html:20-35` warns that the browser demo is not an audited release substitute, then exposes a browser receipt verification demo.

### IOA Web3 App And Evidence Console

- `examples/internet-of-agents-web3-network/README.md:1-20` describes the flagship local-realism example for Chio-mediated agent commerce over web3. It uses four organizations, local receipts by default, optional Base Sepolia evidence, and blocked mainnet.
- `examples/internet-of-agents-web3-network/README.md:22-52` defines the scenario: treasury, procurement, provider, subcontractor, and auditor agents mediated by `chio trust serve`, `chio api protect`, and `chio mcp serve-http`. It includes passport, reputation, federation, evidence export/import, signed approval, x402-style payment proof, runtime degradation, telemetry, and adversarial denials.
- `examples/internet-of-agents-web3-network/README.md:54-92` gives the running path: build `chio`, run `./scripts/qualify-web3-local.sh`, run `examples/internet-of-agents-web3-network/smoke.sh`, optionally choose `--artifact-dir`, optionally require Base Sepolia evidence, and use `./scripts/qualify-web3-examples.sh`.
- `examples/internet-of-agents-web3-network/README.md:94-114` documents the Evidence Console and the `CHIO_RUN_E2E=1` path.
- `examples/internet-of-agents-web3-network/README.md:150-187` documents the artifact contract, including `bundle-manifest.json`, `review-result.json`, `summary.json`, topology, receipts, and domain artifacts.
- `examples/internet-of-agents-web3-network/README.md:189-193` states that `review-result.json` fails closed on missing artifacts, unmediated paths, denial controls that do not deny, budget/reconciliation failures, wrong provider, missing lineage, and Base Sepolia requirements when enabled.
- `examples/internet-of-agents-web3-network/README.md:195-224` lists what the scenario proves, including two-hop subcontracting, high-risk release approval, rail denial, runtime degradation, telemetry, adversarial denials, and provider admission.
- `examples/internet-of-agents-web3-network/smoke.sh:7-14` makes Playwright e2e opt-in through `CHIO_RUN_E2E=1` or preinstalled dependencies.
- `examples/internet-of-agents-web3-network/smoke.sh:74-112` runs the scenario and, when e2e is enabled, builds/starts the Next app and runs Playwright.
- `examples/internet-of-agents-web3-network/app/README.md:1-6` says the Evidence Console is offline-first, verifies SHA-256 in-browser, and fails closed on missing or corrupted bundle files.
- `examples/internet-of-agents-web3-network/app/README.md:106-121` documents fail-closed behavior.
- `examples/internet-of-agents-web3-network/app/lib/bundle.ts:169-178` states that `review-result.json` is excluded from `manifest.sha256` because the verifier writes it after the manifest is sealed. It is advisory and must not drive the authenticated verdict.
- `examples/internet-of-agents-web3-network/app/components/BundleProvider.tsx:155-169` derives the effective UI verdict only from authenticated state and hash mismatch, not from the unauthenticated review result.
- `examples/internet-of-agents-web3-network/internet_web3/artifacts.py:71-86` writes the bundle manifest and excludes `bundle-manifest.json`, `run-result.json`, and `review-result.json` from hashes.
- `examples/internet-of-agents-web3-network/scenario/lib.sh:217-254` runs the orchestrator, verifies the bundle, and writes `review-result.json` after manifest creation.
- `examples/internet-of-agents-web3-network/internet_web3/verify.py:13-154` lists required artifacts.
- `examples/internet-of-agents-web3-network/internet_web3/verify.py:239-680` performs manifest hash checks, delegation checks, Chio topology checks, receipt checks, budget/reconciliation checks, passport/federation/reputation/provider checks, runtime and observability checks, adversarial checks, web3 rail checks, and summary assertion checks.
- `examples/internet-of-agents-web3-network/internet_web3/adversarial.py:8-70` defines six adversarial controls: prompt injection, invoice tampering, quote replay, expired capability, unauthorized settlement route, and forged passport. It writes denial artifacts and a summary with `decision: deny`.
- `scripts/qualify-web3-examples.sh:16-106` runs the IOA smoke path and verifies required files, review status, provenance, RFQ, lineage, runtime, observability, denials, web3 statuses, summary assertions, and the six adversarial denials.

### Docker Quickstart And Progressive Tutorial

- `examples/docker/README.md:1-8` defines the deployable local onboarding path: `chio trust serve` with a receipt dashboard on `http://127.0.0.1:8940`, `chio mcp serve-http` on `http://127.0.0.1:8931`, and a wrapped demo MCP server.
- `examples/docker/README.md:9-16` gives the quickstart: `docker compose up -d --build` and `python3 smoke_client.py`.
- `examples/docker/README.md:18-26` says the smoke performs one governed `echo_text` call, queries the resulting receipt, and prints the viewer URL plus receipt id.
- `examples/docker/compose.yaml:3-40` defines the local services, ports, healthcheck, and environment variables.
- `examples/docker/smoke_client.py:90-150` initializes the MCP session, lists tools, calls `echo_text`, gets a session capability, queries the trust-service receipts, and prints session/capability/tool result/receipt/viewer information.
- `docs/start-here/PROGRESSIVE_TUTORIAL.md:1-8` says the tutorial is the shortest honest path from concept to governed call.
- `docs/start-here/PROGRESSIVE_TUTORIAL.md:26-42` points to the Docker demo stack and default ports/token.
- `docs/start-here/PROGRESSIVE_TUTORIAL.md:73-121` explains wrapping a tool with `chio mcp serve-http` and using the smoke client to prove session initialization, capability issuance, governed execution, and receipt persistence.
- `docs/start-here/PROGRESSIVE_TUTORIAL.md:122-151` covers receipt querying and the dashboard viewer.
- `docs/start-here/PROGRESSIVE_TUTORIAL.md:153-193` covers delegation through federation policy and federated issuance.

### SDK Templates And Create-App

- `sdks/typescript/packages/create-chio-app/README.md:1-11` defines `npx create-chio-app <template>` and says templates are copied locally without outbound calls during TTFRH.
- `sdks/typescript/packages/create-chio-app/README.md:13-29` lists templates: `next-ai-sdk-receipts`, `fastapi-langchain`, and `cloudflare-worker`.
- `sdks/typescript/packages/create-chio-app/src/index.ts:1-5` uses plain Node without external dependencies.
- `sdks/typescript/packages/create-chio-app/src/index.ts:51-63` prints help text from template metadata.
- `sdks/typescript/packages/create-chio-app/src/index.ts:93-145` parses commands, lists templates, refuses to overwrite an existing destination, copies a template, and prints next commands plus benchmark command.
- `sdks/typescript/packages/create-chio-app/src/templates.ts:14-39` defines the three template descriptors, next commands, and benchmark runner.
- `sdks/typescript/templates/next-ai-sdk-receipts/README.md:1-44` documents a Next + AI SDK receipts viewer with no outbound calls and an in-memory sink.
- `sdks/typescript/templates/fastapi-langchain/README.md:1-40` documents a FastAPI + LangChain static receipts viewer with no outbound calls.
- `sdks/typescript/templates/cloudflare-worker/README.md:1-41` documents a Cloudflare Worker + KV receipts template with no outbound calls.

### Release And Install Docs

- `docs/install/README.md:1-34` presents GitHub release binaries, Homebrew, Docker/container, and next steps as install paths.
- `docs/install/BINARY_DISTRIBUTION.md:1-16` presents pre-built sidecar binaries and supported platforms.
- `docs/install/BINARY_DISTRIBUTION.md:18-50` presents Homebrew and Docker distribution examples.
- `docs/install/BINARY_DISTRIBUTION.md:52-99` documents archive downloads and checksum verification.
- `docs/install/VERIFY.md:1-14` says every release artifact has Sigstore keyless `.sig` and `.pem` files and can be verified by the same Rust crate or cosign.
- `docs/install/VERIFY.md:25-47` says `chio attest verify` wraps the crate and documents the OIDC identity contract.
- `docs/install/VERIFY.md:210-220` says the channel inventory currently fully describes PyPI and npm, while native archives, OCI, SLSA, and docs recipes land later.
- `docs/install/PUBLISHING.md:1-14` documents SDK OIDC Trusted Publishing with no long-lived tokens.
- `docs/install/PUBLISHING.md:56-99` lists package inventory.
- `docs/install/PUBLISHING.md:185-200` provides a release checklist.
- `docs/install/PUBLISHING.md:251-341` documents binary-release supply-chain artifacts, cosign archive signing, sidecar-image signing, and verification.
- `docs/release/RELEASE_AUDIT.md:1-10` says the audit is a repo-local pre-release evidence inventory, not the authoritative public release-go document.
- `docs/release/RELEASE_AUDIT.md:60-70` says the bounded ship decision is to continue pre-release evaluation and hold external release/GA until explicit decision.
- `docs/release/RELEASE_AUDIT.md:121-148` requires hosted CI and release qualification before tag.
- `docs/release/RELEASE_CANDIDATE.md:1-18` defines pre-release v1-only framing and launch SKU bounds.
- `docs/release/RELEASE_CANDIDATE.md:35-61` separates local gates, hosted publication gates, and operator decision gates.
- `docs/release/RELEASE_CANDIDATE.md:114-119` keeps external tag and publication on hold.
- `docs/release/GA_CHECKLIST.md:1-7` states that checked items are local-only unless hosted CI observed and must not be cited as production readiness.
- `docs/release/GA_CHECKLIST.md:17-39` leaves hosted CI, release qualification, web3 bundle, and final decision unchecked.
- `scripts/check-release-inputs.sh:6-72` rejects tracked generated/cache artifacts and enforces release-audit readiness wording.
- `scripts/qualify-release.sh:16-183` runs release gates, checks package peer publication, executes conformance/certification paths, and writes artifact manifests plus `SHA256SUMS`.

### Enterprise And Partner Proof Docs

- `docs/release/PARTNER_PROOF.md:1-11` frames the partner proof as reviewer-facing evidence, not the authoritative release-go document.
- `docs/release/PARTNER_PROOF.md:18-29` says local technical evidence qualifies for internal and partner review, not public GA. External tag/publication and web3 deployment remain on hold.
- `docs/release/PARTNER_PROOF.md:30-148` lists broad claims partners can rely on.
- `docs/release/PARTNER_PROOF.md:149-230` lists core evidence.
- `docs/release/PARTNER_PROOF.md:231-280` states non-claims and integration posture.
- `docs/release/CHIO_WEB3_PARTNER_PROOF.md:1-19` is a compact web3 reviewer package, also not authoritative release-go.
- `docs/release/CHIO_WEB3_PARTNER_PROOF.md:20-30` permits local web3 go while holding external deployment/publication until hosted workflow evidence and operator approval.
- `docs/release/CHIO_WEB3_PARTNER_PROOF.md:31-128` covers reviewer-reliable claims, core evidence, end-to-end trace, and caveats.
- `docs/release/CHIO_WEB3_READINESS_AUDIT.md:1-15` says local web3 runtime and reviewed promotion are go, while external deployment is on hold.
- `docs/release/CHIO_WEB3_READINESS_AUDIT.md:81-125` lists promotion gates and public deployment blockers.
- `docs/release/CHIO_UNIVERSAL_CONTROL_PLANE_PARTNER_PROOF.md:1-15` makes a stronger but bounded control-plane claim and defers OpenAI integration.
- `docs/release/CHIO_UNIVERSAL_CONTROL_PLANE_PARTNER_PROOF.md:33-45` points to matrix, command, and artifact root.
- `docs/release/CHIO_COMPTROLLER_FEDERATED_PROOF.md:1-9` frames federated proof as bounded multi-operator proof, not adoption evidence.
- `docs/release/CHIO_COMPTROLLER_FEDERATED_PROOF.md:31-40` says visibility does not imply trust and stale/out-of-scope evidence fails closed.
- `docs/release/CHIO_COMPTROLLER_FEDERATED_PROOF.md:49-58` gives qualification command and bundle root.

## Exact Gaps

1. There is no top-level `chio proof` namespace. Proof tasks are scattered across `receipt`, `evidence`, `replay`, `lineage`, `attest buyer`, `chio-wall`, release scripts, and example-specific verifiers. This is a product gap, not merely a naming issue: users cannot discover the proof path from `chio --help` without already knowing Chio internals.

2. There is no single authenticated proof bundle format spanning receipts, lineage, proof packages, web3 artifacts, verifier reports, and release/package metadata. The IOA web3 bundle has `bundle-manifest.json`, but `review-result.json` is explicitly excluded from authenticated hashes because it is written after the manifest is sealed (`examples/internet-of-agents-web3-network/app/lib/bundle.ts:169-178`, `internet_web3/artifacts.py:71-86`). The UI handles this correctly by refusing to treat review-result as authenticated, but Proof Room needs a sealed verifier envelope if it wants to show a final pass/fail.

3. Verifier semantics are inconsistent across surfaces. `receipt explain` is structural and not Ed25519 verification. `chio replay` performs receipt replay with exit-code semantics. `chio evidence verify` verifies evidence bundles. `chio-attest-buyer-core` verifies proof packages offline. `chio-eval-receipt` verifies eval bundles but warns that synthetic fixtures are not real partner cryptographic attestation. `chio-attest-verify` centralizes Sigstore verification but may return `rekor_inclusion_verified=false`. A reviewer needs one matrix of "checked, not checked, not applicable, failed".

4. The first-run demo proves an allow path, not a denial path. `examples/docker` is the right one-command onboarding candidate, but it only performs a governed `echo_text` call and receipt lookup. It does not include a simple denied call, expired capability, policy mismatch, or missing scope case. The richer IOA web3 example has denial depth, but it is too heavy for a first five-minute proof path.

5. The strongest denial matrix lives in the IOA web3 example, not in a generic proof room. Six adversarial denials and additional guardrails exist in `internet_web3/adversarial.py`, `internet_web3/verify.py`, and `scripts/qualify-web3-examples.sh`, but they are scenario-local. Product reviewers need those denials normalized as reusable proof-room concepts.

6. The lineage viewer and Evidence Console are separate proof readers. `docs/demo/lineage` correctly preserves asserted/observed/verified evidence classes, while the IOA Evidence Console verifies bundle file hashes and renders web3-specific artifacts. They should be one Proof Room evidence graph with scenario-specific panels.

7. `chio-wall` is a bounded product proof surface, not the general receipt dashboard. It exports a Chio-Wall control-path package plus evidence bundle. Treating it as the generic proof room would overfit the product-specific control-path story.

8. SDK templates create local receipt viewers but not exportable proof packages. `create-chio-app` has a strong no-egress TTFRH story, and the templates show receipts, but there is no "export proof", "open in Proof Room", or "verify this demo" workflow.

9. Release/install docs overstate or conflict with the actual release posture. Install docs show GitHub release binaries, Homebrew, Docker, versioned images, and archive URLs. Release docs repeatedly say external publication and GA are on hold until hosted gates and operator decision. `docs/install/BINARY_DISTRIBUTION.md` uses `backbay-labs`, while `docs/install/PUBLISHING.md` and `docs/install/VERIFY.md` use `backbay-industries` examples (`docs/install/BINARY_DISTRIBUTION.md:21-40`, `docs/install/PUBLISHING.md:114`, `136`, `441`, `docs/install/VERIFY.md:50`, `59`, `122`, `183`). This must be resolved before launch.

10. Release verification documentation is not presented as a live truth source. `docs/install/VERIFY.md:210-220` says only PyPI and npm are fully described while native archives, OCI, SLSA, and docs recipes land later; `docs/install/PUBLISHING.md:251-341` already describes native and OCI signing flows. Reviewers will not know which state is current.

11. Enterprise proof docs are strong but sprawling. `PARTNER_PROOF.md`, `CHIO_WEB3_PARTNER_PROOF.md`, `CHIO_WEB3_READINESS_AUDIT.md`, `CHIO_UNIVERSAL_CONTROL_PLANE_PARTNER_PROOF.md`, and `CHIO_COMPTROLLER_FEDERATED_PROOF.md` are valuable, but they are not a single review kit with claims, evidence, commands, caveats, verification status, and non-claims.

12. There is no product-level claim registry. The repo has release audits, proof reports, verifier reports, and partner proofs, but no single structured table mapping claim -> source artifact -> verifier -> proof level -> caveat -> last checked commit -> pass/fail.

## One-Command Demo Path

The launch demo path should have three tiers. Tier 0 must be the default for a new developer. Tier 1 is the flagship Proof Room scenario. Tier 2 is release qualification and must not be presented as the first-run path.

### Tier 0: Five-Minute Governed Call

Run from the repo root:

```bash
bash -lc 'cd examples/docker && docker compose up -d --build && python3 smoke_client.py'
```

Expected output:

- MCP session initialization succeeds.
- A governed `echo_text` tool call succeeds through `chio mcp serve-http`.
- The trust service persists a receipt.
- The smoke prints `receiptId` and the viewer URL.
- The reviewer opens `http://127.0.0.1:8940/?token=demo-token`.

This should become the first Proof Room entrypoint, but it needs one denial case before launch. The minimal addition is a second smoke call that lacks the required scope or targets a forbidden tool, then prints the denial receipt id next to the allow receipt id.

### Tier 1: Flagship Proof Room Scenario

Run from the repo root:

```bash
CHIO_RUN_E2E=1 examples/internet-of-agents-web3-network/smoke.sh --artifact-dir target/proof-room/ioa-web3-service-order
```

Expected output:

- Four-organization topology starts.
- Chio sidecars and MCP edges mediate cross-org calls.
- The service-order scenario completes.
- The verifier writes `review-result.json`.
- Playwright runs the Evidence Console against the generated bundle.
- The reviewer opens the generated Proof Room bundle from `target/proof-room/ioa-web3-service-order`.

This should be marketed as the "full trust network proof", not the starter tutorial.

### Tier 2: Qualification

Run only for release or launch evidence collection:

```bash
./scripts/qualify-web3-examples.sh
./scripts/check-chio-proof-package.sh
./scripts/check-proof-report.sh
./scripts/check-release-inputs.sh
./scripts/qualify-release.sh
```

These are gates, not onboarding commands. They should feed Proof Room reports, but should not be the first user experience.

## Proof Room Information Architecture

Proof Room should be a reviewer-grade app and a static-exportable artifact reader. It should have the following top-level structure.

1. Overview
   - Current verdict: pass, fail, partial, or advisory.
   - Claim level: local demo, hosted CI, release-signed, external attested, or not claimed.
   - Source commit, branch, run timestamp, tool versions, and artifact digest.
   - Clear statement of non-claims, especially "not GA" or "not public release" when applicable.

2. Demo Launcher
   - One-command Docker path.
   - One-command IOA web3 path.
   - Copyable qualification commands.
   - Environment checks for Docker, Python, cargo-built `chio`, bun/pnpm for UI e2e, and optional Base Sepolia evidence.

3. Scenario Library
   - `docker-governed-echo`: allow plus denial.
   - `ioa-web3-service-order`: four-org commerce scenario.
   - `lineage-receipt-demo`: static lineage graph.
   - `eval-report-bundle`: eval receipt verifier.
   - `buyer-auditor-proof-package`: selective-disclosure proof package.
   - `wall-control-package`: Chio-Wall bounded control-path package.

4. Evidence Console
   - Receipt list and receipt details.
   - Capability chain.
   - Policy decision.
   - Guard inputs and outputs.
   - Replay status.
   - Redaction status.
   - Tenant/admin boundary status.

5. Lineage
   - DAG nodes and edges.
   - Evidence class labels: asserted, observed, verified.
   - Truncation and root metadata.
   - Diff view for two runs.

6. Denials
   - Denial matrix by scenario.
   - Required negative cases.
   - Denial receipt ids.
   - Policy, capability, budget, identity, web3 rail, and artifact-integrity denial reasons.

7. Verifier
   - Bundle manifest and hash coverage.
   - Signature checks.
   - Replay checks.
   - Schema checks.
   - Sigstore checks.
   - Rekor inclusion status.
   - Unsupported proof feature denials.
   - Advisory files excluded from authenticated verdict.

8. Enterprise Review Kit
   - Claim registry.
   - Evidence index.
   - Questionnaire answers.
   - Installation and release state.
   - Security architecture summary.
   - Non-claims and caveats.
   - Raw artifact download.

9. Release And Package Truth
   - Which packages are source-only, locally built, published, signed, or not yet published.
   - Which owner/org names are canonical.
   - Which install commands are verified against live release artifacts.
   - Which gates are local-only versus hosted CI observed.

10. Raw Artifacts
    - Manifest.
    - Verifier report.
    - Receipts.
    - Lineage graph.
    - Proof package.
    - Trust bundle.
    - Release/package metadata.
    - Logs.

## Verifier UI Requirements

The verifier UI must be stricter than a dashboard. It should behave like an auditor's reading room.

1. The primary verdict must come from authenticated state. An advisory file such as IOA `review-result.json` may be displayed, but it must not be allowed to flip the final Proof Room verdict unless it is sealed into a signed verifier envelope.

2. The UI must distinguish:
   - Manifested and hash-verified artifacts.
   - Manifested but missing artifacts.
   - Present but unmanifested artifacts.
   - Advisory artifacts.
   - Locally generated reports.
   - Hosted CI reports.
   - Externally signed release artifacts.

3. Every proof claim must show the checker that produced it. Examples: receipt replay, evidence verification, buyer proof verifier, eval receipt verifier, web3 verifier, Sigstore verifier, release qualification script, or manual operator decision.

4. The UI must show unsupported proof features as explicit denials, not omissions. The proof-package gate already forbids unsupported hidden range predicates, VC Data Integrity, and zkVM claims; Proof Room should surface those boundaries.

5. `rekor_inclusion_verified=false` must be visible as a supply-chain caveat and must fail any claim level that requires Rekor inclusion.

6. Evidence classes must remain visible in all graph views. Asserted, observed, and verified edges must never collapse into one "proof" color.

7. Denial cases must be first-class. A scenario that only proves an allow path should not get a "trust network proof" badge.

8. The UI must have deterministic offline behavior. If a bundle is complete, local file or static hosting should be enough. If network lookup is required, the UI must say exactly which claim depends on it.

9. Error messages must be productized. "Hash mismatch in `summary.json`" is useful. "Could not load bundle" is not enough.

10. The UI must show source commit, run command, artifact root, generated timestamp, verifier tool versions, and schema versions.

11. Raw JSON must remain downloadable and copyable. Enterprise reviewers will need machine-readable artifacts for internal review.

12. The UI must include "what this does not prove" next to every high-level claim.

## `chio proof` CLI And API

The CLI should introduce a single proof namespace while preserving existing lower-level commands.

### Proposed CLI

```text
chio proof init [--template docker|ioa-web3|buyer-auditor|wall]
chio proof run <scenario> [--artifact-dir DIR] [--e2e] [--require-live-chain]
chio proof verify <bundle-dir|bundle.tar.zst> [--trust-bundle FILE] [--require rekor|hosted-ci|denials|release-signed]
chio proof explain <bundle-dir> [--claim CLAIM_ID] [--json]
chio proof serve <bundle-dir> [--port PORT]
chio proof export <bundle-dir> --out proof-room.tar.zst [--include-logs] [--redact PROFILE]
chio proof doctor [--scenario SCENARIO]
```

Aliases can route to existing commands:

- `chio proof verify --kind evidence` -> `chio evidence verify`.
- `chio proof verify --kind buyer-package` -> `chio attest buyer verify-proof`.
- `chio proof replay` -> `chio replay`.
- `chio proof lineage` -> `chio lineage query`.

The important product rule is that `chio proof verify` must produce one normalized `ProofVerificationReport`, even when the underlying checker is specialized.

### Proposed API

Create a stable public proof API around these shapes:

- `ProofBundle`: root bundle descriptor, manifest, scenario id, schema version, artifact list, artifact digests, signing envelope, and optional redaction profile.
- `ProofManifest`: authenticated file inventory with digest algorithm, artifact class, sensitivity class, producer, and whether the artifact participates in the primary verdict.
- `ProofClaim`: claim id, human label, proof level, required artifacts, checker, status, caveat, and source refs.
- `ProofArtifact`: path, media type, schema, digest, producer, trust class, and UI renderer hint.
- `ProofDenial`: denial id, scenario, expected reason, observed receipt, policy/capability/guard source, and verifier status.
- `ProofVerificationReport`: normalized pass/fail/partial result, checked claims, skipped claims, failed claims, advisory artifacts, unauthenticated artifacts, source commit, tool versions, and checker provenance.

Existing verifier APIs should be adapters:

- `chio_attest_buyer::verify_proof_package_json` for buyer proof packages.
- `chio evidence verify` internals for evidence bundles.
- `chio replay` internals for receipt replay and canonical exit-code mapping.
- `chio lineage query` for graph emission.
- `chio-eval-receipt` for eval bundles.
- `chio-attest-verify` for Sigstore verification.
- IOA `internet_web3.verify.verify_bundle` for scenario-specific web3 proof claims until those claims become generic checkers.

## Enterprise Review Kit

Proof Room should export an enterprise review kit as a single signed archive plus a human-readable index. The archive should include:

1. Executive summary
   - What was run.
   - What passed.
   - What failed or was not claimed.
   - Proof level: local, hosted, release-signed, external, or advisory.

2. Claim registry
   - Claim id.
   - Claim text.
   - Proof level.
   - Required evidence.
   - Checker.
   - Result.
   - Caveat.
   - Source file refs.

3. System architecture packet
   - Five Chio components.
   - Trust boundaries.
   - Capability lifecycle.
   - Guard pipeline.
   - Receipt-log model.
   - Failure and fail-closed rules.

4. Evidence index
   - Receipts.
   - Capabilities.
   - Policies.
   - Proof packages.
   - Trust bundles.
   - Lineage graph.
   - Release/package artifacts.
   - Logs.

5. Denial matrix
   - Negative case.
   - Expected failure.
   - Actual decision.
   - Denial receipt.
   - Guard/policy/capability source.

6. Supply-chain packet
   - Artifact signatures.
   - OIDC identity.
   - Rekor inclusion status.
   - Checksums.
   - SBOM/SLSA status where available.
   - Package publication truth.

7. Release posture packet
   - Pre-release, RC, GA, or published.
   - Hosted CI status.
   - Operator decision status.
   - External publication status.
   - Installation commands that are actually valid for the current release state.

8. Questionnaire mapping
   - Access control.
   - Audit logging.
   - Data redaction.
   - Tenant isolation.
   - Key management.
   - Incident review.
   - Supply chain.
   - Change management.

9. Non-claims
   - No public GA if release docs still hold it.
   - No mainnet deployment if mainnet remains blocked.
   - No Rekor-inclusion claim while `rekor_inclusion_verified=false`.
   - No partner cryptographic-attestation claim from synthetic eval fixtures.
   - No OpenAI integration claim if deferred.

## Release And Package Truth Cleanup

The release/package docs need a hard truth pass before launch. The current problem is not a lack of documentation. It is that the docs mix aspirational install paths, local pre-release gates, and future publication recipes.

Required cleanup:

1. Pick one canonical GitHub owner and package namespace. Current docs use both `backbay-labs` and `backbay-industries` in install and verification examples. That will create failed copy-paste commands and weaken reviewer confidence.

2. Split install docs into three explicit states:
   - Source build: always available if the repo builds locally.
   - Local Docker demo: available through `examples/docker`.
   - Published release artifacts: available only when a tagged release, archive, checksum, signature, and verification command are live.

3. Do not present `latest`, `0.1.0`, Homebrew formula, GHCR image, or GitHub release archive commands as active install paths unless the assets exist and are verified. Until then, label them as publication recipes or future release commands.

4. Reconcile `docs/install/VERIFY.md:210-220` with `docs/install/PUBLISHING.md:251-341`. If native archives and OCI signing are real launch gates, VERIFY should not say those recipes land later. If they are future work, PUBLISHING should label them as future publication procedure.

5. Add a generated package-truth table:
   - Package/channel.
   - Expected owner.
   - Expected version/tag.
   - Published: yes/no.
   - Signature present: yes/no.
   - Checksum present: yes/no.
   - Verification command.
   - Last verified timestamp.
   - Source of truth.

6. Put release posture at the top of every install/proof page. If GA is on hold, the first screen should say so.

7. Make `scripts/qualify-release.sh` produce a Proof Room release bundle instead of just writing artifacts under `target/release-qualification`.

## Demo Scenarios And Denial Cases

### Scenario 1: Docker Governed Echo

Purpose: quickest demonstration that a tool call is mediated and receipted.

Allow path:

- Start trust service, receipt dashboard, MCP edge, and wrapped demo server.
- Initialize MCP session.
- List tools.
- Call `echo_text`.
- Query receipt.
- Open receipt dashboard.

Required denial to add:

- Attempt a tool call outside the policy or scope.
- Expect denial.
- Persist denial receipt.
- Show allow receipt and deny receipt side by side.

### Scenario 2: IOA Web3 Service Order

Purpose: flagship launch proof for multi-organization mediated commerce.

Allow path:

- Atlas Operator delegates bounded budget.
- Procurement runs RFQ through Chio-protected market broker.
- ProofWorks is selected through passport, reputation, budget, runtime, and federation evidence.
- ProofWorks subcontracts CipherWorks with narrowed two-hop capability.
- Settlement agent routes payment and emits web3 settlement evidence.
- Auditor verifies through read-only evidence edge.

Existing denial and guardrail cases:

- Invalid SPIFFE identity.
- Overspend.
- Velocity burst.
- Prompt injection.
- Invoice tampering.
- Quote replay.
- Expired capability.
- Unauthorized settlement route.
- Forged passport.
- Mainnet blocked.
- Wrong provider selected.
- Missing lineage.
- Missing receipt.
- Missing or corrupted artifact.
- Missing Base Sepolia evidence when required.

### Scenario 3: Buyer-Auditor Proof Package

Purpose: enterprise selective-disclosure review.

Denial cases:

- Unsupported hidden range predicate.
- Unsupported VC Data Integrity claim.
- Unsupported zkVM claim.
- Bad schema.
- Missing trust-bundle disclosure policy.
- Missing revocation checkpoint.
- Invalid bilateral envelope.
- Invalid lease.
- Negative corpus regression.

### Scenario 4: Release Proof

Purpose: prove that a published artifact is the artifact reviewers think it is.

Denial cases:

- Missing checksum.
- Signature absent.
- OIDC identity mismatch.
- Rekor inclusion required but false.
- Owner/org mismatch.
- Version/tag mismatch.
- Hosted CI required but missing.
- Local-only gate cited as production readiness.

## Tests And Gates

Existing gates that should feed Proof Room:

- `bash -lc 'cd examples/docker && docker compose up -d --build && python3 smoke_client.py'`
- `CHIO_RUN_E2E=1 examples/internet-of-agents-web3-network/smoke.sh --artifact-dir target/proof-room/ioa-web3-service-order`
- `./scripts/qualify-web3-examples.sh`
- `./scripts/check-chio-proof-package.sh`
- `./scripts/check-proof-report.sh`
- `./scripts/check-release-inputs.sh`
- `./scripts/qualify-release.sh`
- `chio replay` with trusted kernel key or TEE mode, depending on artifact origin.
- `chio evidence verify` with `--require-proofs` when the claim requires proof material.
- `chio attest buyer verify-proof` for buyer-auditor proof packages.
- `chio lineage query --emit demo --json` for graph export.
- Evidence Console Playwright e2e through `CHIO_RUN_E2E=1`.

New gates needed:

1. Proof bundle schema gate
   - Validate `ProofBundle`, `ProofManifest`, `ProofClaim`, `ProofDenial`, and `ProofVerificationReport`.

2. Signed verifier envelope gate
   - Seal the verifier result into the authenticated bundle or sign it as a detached envelope.
   - UI primary verdict must come from this envelope.

3. Docker denial gate
   - Starter demo must emit at least one denial receipt.

4. Proof UI fail-closed gate
   - Playwright tests for missing file, hash mismatch, schema mismatch, unauthenticated review result, and advisory-only proof state.

5. CLI golden-output gate
   - `chio proof verify --json` should have stable snapshots for pass, fail, partial, and advisory bundles.

6. Claim registry completeness gate
   - Every high-level UI claim must map to a source artifact and checker.

7. Release truth gate
   - Install docs fail if they reference a published package path that is not present in the package-truth table.

8. Evidence-class regression gate
   - Lineage UI must not collapse asserted, observed, and verified edge classes.

9. Negative corpus floor
   - Buyer proof and IOA web3 denial corpora must meet minimum count and named-case expectations.

10. No local-only overclaim gate
    - Docs fail if local-only gates are cited as GA, public release, production readiness, or external publication.

## Phased Plan

### Phase 0: Truth And Entry Path

Scope:

- Make `examples/docker` the official Tier 0 Proof Room quickstart.
- Add a documented denial expectation to the product plan.
- Normalize release posture language across install, release, and partner proof docs.
- Create a package-truth table design.

Exit gate:

- A reviewer can run one command, see one allow receipt, and understand what denial will be added before launch.
- No install page presents unpublished assets as live.

### Phase 1: Proof Bundle Contract

Scope:

- Define `ProofBundle`, `ProofManifest`, `ProofClaim`, `ProofDenial`, and `ProofVerificationReport`.
- Map IOA web3 bundle fields into the contract.
- Map buyer proof-package verification into the contract.
- Define signed or sealed verifier envelope semantics.

Exit gate:

- One bundle can represent authenticated artifacts, advisory artifacts, denials, claims, and verifier results without ambiguity.

### Phase 2: `chio proof`

Scope:

- Add `chio proof verify`, `explain`, `serve`, `export`, `doctor`, and `run` as a discoverable namespace.
- Preserve existing lower-level commands.
- Normalize JSON report output.
- Add golden tests for pass/fail/partial/advisory outputs.

Exit gate:

- A user can discover the proof path from `chio --help` and can verify a bundle without knowing which lower-level verifier applies.

### Phase 3: Proof Room UI

Scope:

- Reuse the IOA Evidence Console for authenticated bundle loading, fail-closed behavior, and artifact rendering.
- Merge lineage viewer concepts into the graph tab.
- Add scenario library, denial matrix, verifier tab, release truth tab, and raw artifact tab.

Exit gate:

- The UI can render the Docker starter proof, IOA web3 proof, lineage graph, buyer proof package report, and release proof report with consistent claim levels.

### Phase 4: Enterprise Review Kit

Scope:

- Export a signed review kit with executive summary, claim registry, evidence index, denial matrix, supply-chain packet, release posture packet, questionnaire mapping, and non-claims.
- Provide static HTML and machine-readable JSON.

Exit gate:

- A partner can review the kit offline and determine exactly what is proven, what is not proven, and which commands produced the evidence.

### Phase 5: SDK And Template Integration

Scope:

- Add Proof Room export commands to `create-chio-app` templates.
- Add a receipts-to-proof flow for Next, FastAPI, and Cloudflare templates.
- Keep the no-outbound TTFRH promise.

Exit gate:

- A template user can create an app, run a governed call, export a proof bundle, and open it in Proof Room without learning IOA web3 internals.

## Top Five Recommendations

1. Build `chio proof` as the canonical developer entrypoint. Keep `receipt`, `evidence`, `replay`, `lineage`, and `attest buyer` as expert subcommands, but do not make launch reviewers assemble the proof story manually.

2. Create one signed Proof Room bundle format and one normalized verifier report. The current unauthenticated `review-result.json` handling is careful, but a launch proof needs a sealed final verdict.

3. Promote the Docker quickstart to the Tier 0 demo and add a denial receipt. A proof product that starts with only an allow path undersells fail-closed security.

4. Merge the IOA Evidence Console and lineage viewer into Proof Room. The web3 app has the best artifact-verification UI, while the lineage demo has the right evidence-class semantics. They belong together.

5. Clean release/package truth before public launch. The install docs, verification docs, publishing docs, and release posture docs must agree on owner, package state, signing state, and whether a command is live or a future publication recipe.
