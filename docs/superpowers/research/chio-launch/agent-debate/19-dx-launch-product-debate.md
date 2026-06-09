# Agent 19 DX Launch Product Debate

Status: debate and plan-edit proposal
Role: developer experience and launch-product operator
Scope: Proof Room, first-run evidence, release truth, developer tooling, and launch review surfaces
Confidence: high for product sequencing, moderate for exact implementation homes until the `chio proof` namespace lands.

## Executive Verdict

The current research package is directionally right but still too verifier-internal. It proves that Chio can become a proof layer, but it does not yet specify enough of the product path that a skeptical developer, buyer, or partner would actually run.

The strongest product argument is this: a proof layer that needs an insider to assemble evidence is not a launch product. The launch experience needs one canonical path:

1. Install or run from source.
2. Run one command that produces both an allow and a deny.
3. Verify the same bundle through `chio proof verify`.
4. Open the same report in a static Proof Room.
5. Run `chio proof doctor` to explain environment, release, fixture, and verifier health.
6. See exact non-claims when a feature is not covered.

The UI must never become the source of truth. The CLI verifier and signed verifier report are canonical. The Proof Room is a reader, not a judge. Hosted mode is a distribution surface, not a trust root.

## Debate Positions

### Position A: Keep The First Sprint Pure

Argument: the first implementation sprint already has a strict stop rule: one valid minimal Transaction Passport verifies and one invalid policy digest mismatch fails through `chio proof verify`. Expanding it with doctor, playground, plugins, SDK generators, or hosted Proof Room risks turning a clean verifier slice into product sprawl.

This position is mostly correct. The first sprint should not absorb the whole launch experience. If the minimal verifier is unstable, every product surface becomes theater.

Weakness: a pure verifier slice still leaves the launch path under-specified. The project needs a DX slice immediately after the minimal verifier, or the next agents will create scattered demos again.

### Position B: Build The Full Product Surface Now

Argument: Chio is launching a trust network, not a library. Developers expect playgrounds, generated SDKs, a hosted viewer, docs quickstarts, IDE affordances, and conformance badges. Waiting too long makes the proof story technically strong but commercially illegible.

This position is emotionally satisfying and operationally dangerous. Most of those surfaces amplify the proof path; they do not define it. Building them before the canonical verifier report creates more places for claims to drift.

Weakness: it conflates discoverability with proof. A playground or plugin that renders unauthenticated state is worse than no playground.

### Position C: Add Thin Product Contracts Now, Defer Heavy Surfaces

Recommendation: adopt Position C.

Define the product contracts now, wire only the first-run and doctor slice immediately after the minimal verifier, and defer surfaces that can safely consume the signed verifier report later.

The near-term product must include:

- `chio proof doctor`;
- first-run evidence with one allow and one denial;
- static Proof Room bundle contract;
- release truth gate;
- docs quickstart tied to actual commands and current release state;
- negative fixtures for every public path.

The near-term product must not include:

- arbitrary hosted execution;
- open fixture marketplace;
- IDE extension with its own verifier;
- broad SDK generators;
- certification-style conformance passport claims;
- a playground that mints or edits proof verdicts.

## Feature Additions

| Capability | Launch decision | Add now | Defer | Required failure mode |
| --- | --- | --- | --- | --- |
| `chio proof doctor` | P0 | Diagnostic command for verifier, fixtures, Docker, release truth, and docs references. | Repair automation and environment mutation. | Missing verifier, missing fixture, stale docs claim, missing release evidence, and network-only dependency all fail with named codes. |
| First-run evidence | P0 | Stage 0 quickstart must produce one allow receipt, one denial receipt, a minimal Transaction Passport, and a verifier report. | Commerce and swarm first-run paths. | Quickstart without a denial receipt fails launch gate. |
| Proof Room static mode | P0 | Offline static viewer over signed bundle and verifier report. | Rich hosted collaboration. | UI-generated verdict is forbidden; missing signed report fails. |
| Proof Room hosted mode | P1 | Hosted reader for immutable signed bundles with commit, release, and fixture evidence. | Accounts, uploads from untrusted users, mutable hosted verdicts. | Hosted bundle whose commit or release evidence is stale fails release truth. |
| Playground | P1 | Read-only fixture playground that runs canned valid and invalid bundles. | Arbitrary user tools, remote execution, payment flows. | Playground state must be labeled synthetic or fixture-backed; unsupported claims fail closed. |
| Conformance Passport | P1 | Signed passport over conformance fixture matrix, verifier versions, negative cases, and implementation identity. | Certification program, partner badges, broad ecosystem claims. | Passport without negative cases or current verifier hash fails. |
| SDK generators | P1 | Manifest-driven generators for proof export hooks and quickstart verification commands. | Full SDK rewrites across languages. | Generated code that bypasses kernel mediation or omits receipt export fails. |
| Fixture marketplace | P2 | Curated static catalog of signed fixture bundles. | Open marketplace, third-party uploads, ratings, monetization. | Unsigned fixture, unknown schema, or fixture script execution fails. |
| VS Code/browser plugin | P2 | Viewer shell that opens local signed bundles and shells out to `chio proof verify`. | Plugin-owned verifier, auto-upload, background scanning. | Cached or plugin-derived verdict not backed by current CLI report fails. |
| Docs quickstarts | P0 | One source-backed quickstart for source checkout, Docker, fixture verify, static Proof Room, and release truth. | Marketing tutorial expansion. | Command in docs must pass or be explicitly marked unavailable. |
| Release truth | P0 | Gate for package, binary, Docker, hosted demo, tag, Sigstore, Rekor, chain, and docs claims. | Claims about future public availability. | Any public availability claim without current evidence fails. |

## Product Ground Rules

1. The CLI verifier is canonical. Proof Room, playground, plugin, and docs all consume its report.
2. The first-run path must include an allow and a denial. An allow-only demo does not prove fail-closed behavior.
3. Every public claim needs a positive fixture, negative fixture, verifier module or test, and display path.
4. Hosted mode cannot change the verdict. It can only serve an immutable bundle and current release evidence.
5. `chio proof doctor` is diagnostic. It can say why proof cannot be established, but it cannot bless a proof by itself.
6. Release truth is a launch gate, not documentation polish.
7. The Proof Room must preserve non-claims. Unsupported protocol projections, synthetic attestations, unavailable packages, and advisory evidence need visible labels.

## Exact Plan Edits

### Edit 1: `architecture/07-proof-room-system.md`

Add this section after `CLI Surface`:

```markdown
## Product Modes

The Proof Room has two modes:

1. Static mode: local or static-hosted files only. It loads `chio.proof-room.bundle.v1`, verifies hashes, renders `chio.proof-room.verifier-report.v1`, and performs no network calls.
2. Hosted mode: a hosted reader for immutable signed bundles. Hosted mode may add convenience links, release evidence, and sharing, but it must not compute a different verdict than `chio proof verify`.

The source of truth is always the signed verifier report produced by the CLI. UI state, hosted API state, screenshots, and post-hoc review summaries are advisory.
```

Add this section after `Release Truth Gate`:

```markdown
## First-Run Evidence

The first-run experience must emit:

- one allowed governed action;
- one denied governed action;
- one minimal Transaction Passport;
- one evidence graph;
- one verifier report;
- one static Proof Room bundle;
- one `chio proof doctor --scenario single-call-authority --json` report.

The first-run path fails the launch gate if it only proves an allowed call.
```

Add this section after `Negative Fixtures`:

```markdown
## Product Negative Fixtures

Product surfaces need their own negative controls:

- doctor reports missing verifier binary;
- doctor reports stale fixture path;
- static Proof Room rejects a UI-only verdict;
- hosted Proof Room rejects stale commit or release evidence;
- quickstart gate rejects a command that requires private credentials;
- docs gate rejects a public release claim without current release evidence;
- playground rejects unsupported claims without a matching verifier report;
- plugin rejects cached verdicts not backed by current CLI output.
```

### Edit 2: `plans/07-proof-room-implementation.md`

Insert this phase between `Phase 0 - CLI Contract` and `Phase 1 - Minimal Docker Quickstart`:

```markdown
## Phase 0A - Doctor And Product Report Contract

Tasks:

1. Add `chio proof doctor --scenario <fixture-id> --json`.
2. Define doctor report fields: `schema`, `scenario`, `checks[]`, `release_truth`, `fixtures`, `commands`, `docs_refs`, and `verdict`.
3. Ensure doctor distinguishes diagnostic failure from proof verification failure.
4. Add named failure codes for missing verifier, missing fixture, stale docs claim, private credential requirement, and unavailable release evidence.

Tests:

- missing fixture path returns nonzero with `proof-room.fixture.missing`;
- unavailable release evidence returns nonzero with `proof-room.release.unavailable`;
- doctor output is deterministic JSON for the same checkout and fixture;
- doctor never emits `verified` for a proof bundle without invoking `chio proof verify`.
```

Replace `Phase 1 - Minimal Docker Quickstart` tasks with this stricter version:

```markdown
Tasks:

1. Add a Docker quickstart for Tier 0.
2. Include one valid allowed call and one denied call.
3. Run CLI verifier inside the container or from the host against the emitted bundle.
4. Emit a static Proof Room bundle.
5. Emit first-run evidence paths in machine-readable form.

Tests:

- fresh Docker run succeeds;
- denied call produces a denial receipt and named verifier claim;
- invalid fixture fails;
- no private credentials are required;
- `chio proof doctor --scenario single-call-authority --json` passes only after the valid and invalid paths both exist.
```

Add this phase after `Phase 2 - Static Proof Room`:

```markdown
## Phase 2A - Hosted Mode Contract

Tasks:

1. Define hosted bundle metadata for commit, release tag, fixture id, verifier hash, and generated-at time.
2. Keep hosted mode read-only over immutable signed bundles.
3. Add visible labels for advisory hosted metadata.

Tests:

- hosted metadata cannot override verifier verdict;
- stale commit or release evidence fails the release truth gate;
- hosted bundle still opens in static mode without network.
```

Add this phase after `Phase 5 - Launch Review Kit`:

```markdown
## Phase 6 - Docs Quickstart And Product Extensions

Tasks:

1. Add a source-checkout quickstart.
2. Add a Docker quickstart.
3. Add a static Proof Room quickstart.
4. Add a release truth quickstart.
5. Add extension contracts for playground, conformance passport, SDK generators, fixture catalog, and plugin viewer.

Tests:

- every quickstart command is exercised by a local gate;
- unavailable release paths are visibly marked unavailable;
- extension docs link to verifier report contracts and do not introduce new proof semantics.
```

### Edit 3: `indices/proof-room-fixture-catalog.md`

Add this section after `Stage 0: Single Call Authority`:

```markdown
## Stage 0 Product Overlay

Stage 0 must also emit first-run product evidence:

- `artifacts/release/release-truth.json`;
- `artifacts/release/doctor-report.json`;
- `artifacts/docs/quickstart-command-log.json`;
- `artifacts/ui/static-proof-room-load.json`;
- `negatives/product/missing-fixture/`;
- `negatives/product/ui-only-verdict/`;
- `negatives/product/stale-release-claim/`;
- `negatives/product/private-credential-required/`.

Acceptance evidence:

- doctor report lists every check with a stable code;
- docs command log binds commands to exit status and output digest;
- static Proof Room load report binds the UI to the verifier report hash;
- release truth report marks unavailable public artifacts as unavailable rather than implied available.
```

Add these rows to the bundle layout under `artifacts/release/`:

```text
    release-truth.json
    doctor-report.json
    docs-command-log.json
    static-proof-room-load.json
```

Add these rows to the negative bundle layout:

```text
    product-missing-fixture/
    product-ui-only-verdict/
    product-stale-release-claim/
    product-private-credential-required/
    product-plugin-cached-verdict/
    product-playground-unsupported-claim/
```

### Edit 4: `indices/execution-slice-contract.md`

Add this row to `Default homes`:

```markdown
| Product DX and launch truth | `chio-cli`, existing examples, static bundle viewer, docs quickstarts, release scripts | proof semantics in UI, plugin, playground, or hosted service |
```

Add this row to `Phase 0 Team Shape`:

```markdown
| DX launch slice | first-run evidence contract, proof doctor diagnostics, release truth gate, docs quickstart command log | `chio-cli` proof dispatch, `examples/docker`, `fixtures/chio-launch`, static viewer harness, docs quickstart paths |
```

Add this subsection after `First Sprint Stop Rule`:

```markdown
## DX Slice Stop Rule

The first DX slice is complete only when the minimal verifier slice already passes and `chio proof doctor --scenario single-call-authority --json` proves:

1. the valid minimal passport verifies;
2. the invalid policy digest mismatch fails with a named code;
3. first-run evidence includes one allow and one denial;
4. docs quickstart commands are backed by a command log;
5. release claims are backed by current evidence or visibly marked unavailable.
```

Add these items to `Ambitious Feature Backlog`:

```markdown
9. proof doctor diagnostics over verifier, fixture, docs, Docker, and release truth state;
10. first-run evidence bundle with allow and deny paths;
11. static and hosted Proof Room mode contract;
12. conformance passport over fixture matrix and verifier versions;
13. manifest-driven SDK proof-export generators;
14. curated signed fixture catalog;
15. VS Code and browser viewer shells that delegate verification to `chio proof verify`.
```

### Edit 5: `plans/09-first-implementation-sprint.md`

Do not weaken the existing completion gate. Add this section after `Completion Gate`:

```markdown
## Immediate Follow-On DX Slice

This slice starts only after the minimal Transaction Passport verifier and policy digest mismatch fixture pass.

Goal: turn the minimal verifier into a first-run launch proof without expanding proof semantics.

Create or modify:

- `crates/chio-cli/src/cli/types.rs`
- `crates/chio-cli/src/cli/dispatch.rs`
- `crates/chio-cli/src/cli/dispatch/proof.rs`
- `crates/chio-cli/tests/proof_doctor.rs`
- `fixtures/chio-launch/minimal-passport/first-run-evidence/`
- `docs/start-here/PROOF_ROOM_QUICKSTART.md`
- `scripts/check-chio-proof-room-release-truth.sh`
- `scripts/tests/check-chio-proof-room-release-truth.test.sh`

Red-first tests:

- `proof_doctor_reports_missing_fixture`
- `proof_doctor_runs_valid_and_invalid_minimal_passport`
- `proof_doctor_rejects_quickstart_without_denial`
- `release_truth_rejects_unavailable_public_artifact_claim`

Commands:

```bash
cargo test -p chio-cli --test proof_verify
cargo test -p chio-cli --test proof_doctor
scripts/check-chio-proof-room-release-truth.sh
```

Stop boundary:

- no hosted service;
- no plugin;
- no marketplace;
- no broad SDK generator;
- no conformance badge;
- no UI verdict logic beyond reading the CLI verifier report.
```

## First Slice

The first DX slice should be `DX-0A: First-Run Evidence And Doctor Gate`.

It must not start before the existing minimal verifier sprint passes. The current first sprint is a verifier foundation; keep it that way.

### Goal

Produce a launchable five-minute proof path over the minimal Transaction Passport:

- one valid minimal passport verifies;
- one policy digest mismatch fails;
- one allow receipt is visible;
- one denial receipt is visible;
- `chio proof doctor` explains whether the first-run path is launchable;
- docs quickstart commands are backed by command logs;
- release availability claims are either proven current or visibly unavailable.

### Write Scope

Allowed paths:

- `crates/chio-cli/src/cli/types.rs`
- `crates/chio-cli/src/cli/dispatch.rs`
- `crates/chio-cli/src/cli/dispatch/proof.rs`
- `crates/chio-cli/tests/proof_doctor.rs`
- `fixtures/chio-launch/minimal-passport/first-run-evidence/`
- `docs/start-here/PROOF_ROOM_QUICKSTART.md`
- `scripts/check-chio-proof-room-release-truth.sh`
- `scripts/tests/check-chio-proof-room-release-truth.test.sh`

Do not touch shared schema registries in this slice unless the registry owner has already accepted the doctor report schema. If the doctor report schema is not registry-backed yet, emit an internal diagnostic JSON with a clearly non-signed schema value and do not advertise it as proof.

### Red-First Tests

1. `proof_doctor_reports_missing_fixture`: pass a missing fixture path and require nonzero exit plus `proof-room.fixture.missing`.
2. `proof_doctor_runs_valid_and_invalid_minimal_passport`: require the doctor to run both the valid and invalid minimal fixtures and report the expected pass and fail.
3. `proof_doctor_rejects_quickstart_without_denial`: construct first-run evidence with only an allow path and require `proof-room.first-run.denial-missing`.
4. `release_truth_rejects_unavailable_public_artifact_claim`: add a docs or release claim for an unavailable artifact and require the release truth script to fail with `proof-room.release.unavailable`.

### Final Commands

```bash
cargo test -p chio-cli --test proof_verify
cargo test -p chio-cli --test proof_doctor
scripts/check-chio-proof-room-release-truth.sh
```

### Stop Boundary

This slice does not build a hosted Proof Room, marketplace, plugin, playground, conformance passport, or SDK generator. It only creates the diagnostic and first-run evidence contract that those later surfaces must consume.

## Negative Fixture Floor

| Surface | Negative fixture | Expected failure code | Why it matters |
| --- | --- | --- | --- |
| Minimal verifier | policy digest mismatch | `transaction.policy_digest_mismatch` | Proves real authority mismatch, not just malformed JSON. |
| Doctor | missing fixture path | `proof-room.fixture.missing` | Prevents fake green doctor output. |
| Doctor | verifier command unavailable | `proof-room.verifier.unavailable` | Separates environment failure from proof failure. |
| First-run evidence | no denial receipt | `proof-room.first-run.denial-missing` | Blocks allow-only launch demos. |
| Static Proof Room | UI-only verdict | `proof-room.ui.verdict-unauthenticated` | Keeps UI from minting proof. |
| Static Proof Room | verifier report hash mismatch | `proof-room.report.hash-mismatch` | Binds display to CLI output. |
| Hosted Proof Room | stale commit evidence | `proof-room.hosted.commit-stale` | Blocks stale hosted demos. |
| Hosted Proof Room | missing release evidence | `proof-room.release.unavailable` | Blocks public availability overclaims. |
| Playground | unsupported claim rendered as proven | `proof-room.playground.unsupported-claim` | Keeps demos from becoming false conformance evidence. |
| Conformance Passport | missing negative cases | `conformance.passport.negative-cases-missing` | A pass-only conformance badge is not credible. |
| SDK generator | generated code bypasses Chio mediation | `sdk.generator.kernel-bypass` | Prevents quickstarts from teaching unsafe integration. |
| Fixture catalog | unsigned fixture bundle | `fixture.signature.missing` | Blocks marketplace poisoning. |
| Fixture catalog | unknown schema | `fixture.schema.unsupported` | Preserves fail-closed registry behavior. |
| VS Code/browser plugin | cached verdict without current CLI report | `plugin.verdict.cache-stale` | Keeps extensions from becoming unverifiable authorities. |
| Docs quickstart | private credential required | `docs.quickstart.private-credential-required` | Keeps first-run evidence reproducible. |
| Docs quickstart | command output drift | `docs.quickstart.command-drift` | Prevents docs from lagging behind CLI behavior. |
| Release truth | package, binary, Docker image, tag, hosted demo, chain, or Rekor claim lacks current evidence | `proof-room.release.unavailable` | Makes release posture explicit. |
| Standards copy | ambiguous bare `ACP` wording | `standards.copy.ambiguous-acp` | Enforces protocol naming discipline. |

## What To Defer

| Capability | Defer until | Reason |
| --- | --- | --- |
| Hosted Proof Room accounts and uploads | Static mode and immutable hosted reader pass release truth | User uploads introduce trust, abuse, retention, and provenance problems unrelated to the first launch proof. |
| Open fixture marketplace | Curated signed catalog exists | An open marketplace before signature, schema, and execution restrictions is a supply-chain risk. |
| VS Code/browser plugin | Static Proof Room bundle contract is stable | Extensions should delegate verification to CLI reports; they should not create a second verifier. |
| Broad SDK generators | One manifest-driven generator proves export hooks safely | Generators can accidentally normalize bypass patterns if built before the proof export contract. |
| Conformance badges | Conformance Passport has negative fixtures and verifier hashes | A badge without negative controls is marketing, not conformance. |
| Live playground with arbitrary tools | Read-only fixture playground exists | Arbitrary execution will pull the team into sandboxing and product safety before the proof story is stable. |
| Hosted commerce and settlement demo | Stage 1 verifier and release truth pass | Public settlement claims have a much higher overclaim risk than Stage 0. |

## Release Truth Position

Bad release truth will damage Chio more than a missing plugin. If docs claim a GitHub release binary, Homebrew formula, Docker image, npm package, PyPI package, hosted demo, chain transaction, Rekor inclusion, or GA posture, the Proof Room bundle must contain current evidence or mark the claim unavailable.

Release truth is not only a docs script. It is a product feature. A buyer should be able to open the Proof Room and see:

- what was verified;
- what was not checked;
- what is unavailable;
- what is synthetic;
- what is advisory;
- which command regenerated the report;
- which commit and release evidence the report binds.

The exact public posture should be conservative: source-checkout and local static proof can launch before public binary or hosted claims. Public package claims should wait for current package evidence.

## Final Recommendation

Keep the first implementation sprint focused on the minimal Transaction Passport verifier and policy digest mismatch. Immediately after it passes, run `DX-0A: First-Run Evidence And Doctor Gate`.

That sequence gives Chio a launchable developer path without diluting proof semantics:

1. `chio proof verify` establishes the proof root.
2. `chio proof doctor` establishes whether the developer can reproduce it.
3. first-run evidence proves both allow and deny.
4. static Proof Room renders the same signed report.
5. release truth prevents public availability overclaims.

Everything else can follow as a consumer of the signed verifier report.
