# Direction D: Iroh Containment + Assurance Hygiene Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land five independent, off-critical-path hygiene fixes that make Chio's iroh/assurance posture honest and durably contained without expanding attack surface: reconcile two same-commit stale ADR/spec items, file and anchor an upstream iroh-gossip inbound-admission feature request, add a scope-accurate RISK_REGISTER row plus an experimental marker on the library-only fanout lane, feature-gate iroh out of the DEFAULT shipped `chio` binary (with a CI leg so the gated tests do not rot), and give the Swift SDK its first automated CI.

**Architecture:** Four of the five tasks are documentation, tracking, and CI-workflow edits with no runtime contract. The one code-shaping task (M4) mirrors Cargo's optional-dependency + `dep:` feature pattern to make `iroh` and `chio-federation-transport-iroh` optional on `chio-cli`, cfg-gates every iroh use site behind `feature = "iroh"`, keeps the `--iroh-*` clap flags always defined, and adds a fail-closed handler in the inner serve/tick path so a non-iroh build rejects `--iroh-enable` with a clear error instead of clap "unknown argument" or a silent no-op. Containment is NOT removal: the adapter crate stays a workspace member and a chio-conformance dev-dep, so the workspace compile still builds iroh.

**Tech Stack:** Rust (workspace, edition 2021+, clap 4, tokio, thiserror), iroh 1.0.1 / iroh-gossip 0.101 / iroh-blobs 0.103 (adapter crate), GitHub Actions (ubuntu-latest for the Rust legs; macos runners for the Swift lane), Swift Package Manager 5.7 + xcodebuild + iOS Simulator, `gh` CLI (off-repo issue filing), `ripgrep` (`rg`) for machine-checkable doc assertions.

## Global Constraints

Every task's requirements implicitly include this section. Values are copied verbatim from the project house rules and the Direction D spec.

- No em-dashes (U+2014) anywhere in code, comments, or documentation. Use hyphens (`-`) or parentheses.
- Clippy `unwrap_used = "deny"` and `expect_used = "deny"` are enforced workspace-wide; this applies to test code too, so use `let Some(..) = .. else { panic! }` / `let Ok(..) = .. else { panic! }` / `match`, never `.unwrap()` / `.expect(..)`.
- Fail-closed: errors deny access; invalid inputs reject; a missing capability (for example, a build without the `iroh` feature) returns a clear error rather than degrading silently.
- Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `ci:`, `chore:`, `refactor:`), and every commit message ends with the trailer:
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`
- No `cargo --workspace` in local verification. Verify scoped with `-p <crate>` only. (The `.github/workflows/ci.yml` file already contains `--workspace` steps; adding scoped legs to it is fine, but do NOT run `--workspace` locally.)
- Before every local `cargo` invocation: `rm -rf target/debug/incremental` and set `CARGO_INCREMENTAL=0`. The command form used throughout is:
  `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo <scoped-subcommand> ...`
- Scoped verify only: build/clippy/test exactly the crate(s) a task touches (`-p chio-cli`, `-p chio-federation-transport-iroh`), never the whole workspace, and never the crates a task does not touch.

---

## File Structure

Files created or modified, grouped by task, with the one responsibility each carries.

**Task 1 (M1) - reconcile two same-commit stale doc items:**
- Modify `docs/adr/ADR-0014-iroh-federation-transport.md:43-50` - rewrite the "New open item surfaced by the build" block as RESOLVED in place (history preserved), citing commit `7f8e156d3` and the two context tags + schema v2.
- Modify `docs/research/iroh/ADAPTER-SPEC.md` (section 7, the `signer_id -> EndpointId` binding-home bullet) - append a one-line RESOLVED note for the SAME commit; do not delete the original open framing.
- Read-only evidence (no edit): `crates/trust/chio-federation-transport-iroh/src/identity.rs:49,57,65,83,101`.

**Task 2 (M2) - upstream FR + in-repo anchors:**
- Off-repo: one GitHub issue on `n0-computer/iroh-gossip`.
- Modify `crates/trust/chio-federation-transport-iroh/src/lanes/fanout.rs` (residual doc block, near `:94-97`) - add the `//! Upstream tracking: <URL>` anchor.
- Modify `docs/research/iroh/ADAPTER-SPEC.md` (section 7, the "Topic-membership admission + revocation eviction latency" bullet) - anchor the same URL as the spec-level tracking home.

**Task 3 (M3) - RISK_REGISTER row + experimental marker:**
- Modify `docs/release/RISK_REGISTER.md` - add one bounded, scope-accurate row plus a re-rate trigger note.
- Modify `crates/trust/chio-federation-transport-iroh/src/lanes/fanout.rs` - add an `EXPERIMENTAL (lane c)` banner to the module header AND a one-line marker on the `pub struct FanoutLane` at `:814`.
- Modify `crates/trust/chio-federation-transport-iroh/src/lib.rs:21` - mark the `lanes::fanout` bullet EXPERIMENTAL.

**Task 4 (M4) - feature-gate iroh out of the default binary + CI leg:**
- Modify `crates/products/chio-cli/Cargo.toml:47-48` (optional deps) and the `[features]` block (`:125-126`, add the `iroh` feature; the only pre-existing feature is `tee-quotes`, there are zero pre-existing `optional = true` deps, so this introduces the first `dep:` optional-dep pattern in this crate).
- Modify `crates/products/chio-cli/src/cli/chio/dispatch/pheromone.rs:11-12,55-58` - cfg-gate `mod iroh_mount;` and its `pub(crate) use` re-export block.
- Modify `crates/products/chio-cli/src/cli/chio/dispatch/pheromone/iroh_mount.rs` - the whole module compiles only under `feature = "iroh"` (gated at the `mod` site above; no in-file change required unless a stray non-iroh item exists).
- Modify `crates/products/chio-cli/src/cli/chio/dispatch/pheromone/relay.rs:1-7` (split the mixed `use super::{..}` block), the serve body (`cmd_chio_pheromone_relay_serve`, fn at `:126`, `load_iroh_serve_inputs` call at `:152`), the tick body (`cmd_chio_pheromone_relay_tick`, fn at `:402`), the iroh helper fns `parse_iroh_peer_addr_book` (`:528`) and `drain_due_batches_over_iroh` (`:598`), and their `#[cfg(test)]` tests - add the fail-closed guard and cfg-gate every iroh use site.
- Read-only (keep unchanged, flags stay always-defined): `crates/products/chio-cli/src/cli/chio/types/pheromone/relay.rs` (Serve iroh flags `:91-132`, Tick iroh flags `:233-279`) and the outer dispatch `crates/products/chio-cli/src/cli/dispatch/pheromone.rs:55-94,119-156` (it threads args unconditionally into the inner fns; the guard lives in the inner fns, not here).
- Modify `.github/workflows/ci.yml` (the `check` job, after "Workspace tests" near `:178`) - add the `-p chio-cli --features iroh` build+clippy+test legs.
- Read-only context to cite in the feature comment: `deny.toml:62-71` (the iroh -> netwatch -> netdev -> plist -> quick-xml RUSTSEC-2026-0194 / 0195 chain), `Cargo.toml:85` (adapter is a workspace member), `crates/tooling/chio-conformance/Cargo.toml:99,189-190` (adapter is a chio-conformance dev-dep).

**Task 5 (M5) - Swift SDK first CI:**
- Create `.github/workflows/swift-sdk.yml` - macOS runner + iOS Simulator `xcodebuild test` lane against the committed xcframework, path-triggered on `sdks/swift/**`, asserting a nonzero executed-test count.
- Read-only (unchanged under lane A): `sdks/swift/Package.swift` (iOS-only, `.systemLibrary(name: "ChioFFI")` + `.binaryTarget(name: "ChioKernel")`), `sdks/swift/Sources/ChioFFI/module.modulemap`, `sdks/swift/Frameworks/ChioKernel.xcframework/ios-arm64_x86_64-simulator/Headers/` (carries `chio_kernel_mobileFFI.h` + `.modulemap`), `sdks/swift/Tests/ChioTests/IntegrationTests.swift`, `sdks/swift/Tests/ChioTests/AppAttestTests.swift`, `scripts/build-ios-framework.sh:1-90` (only the optional drift lane invokes it).

---

## Task 1: M1 - Reconcile the two same-commit stale doc items (ADR-0014 + ADAPTER-SPEC section 7)

Pure docs, zero build risk, land first. The reviewer refinement is folded in: commit `7f8e156d3` resolved BOTH the ADR-0014:43-50 domain-separation open item AND the ADAPTER-SPEC section 7 `signer_id -> EndpointId` binding-home bullet. Do NOT claim "section 7 needs no change." ADR-0014:33-42's tally already records the signer-binding as resolved, so that block stays unchanged.

**Files:**
- Modify: `docs/adr/ADR-0014-iroh-federation-transport.md:43-50`
- Modify: `docs/research/iroh/ADAPTER-SPEC.md` (section 7, `signer_id -> EndpointId` bullet)
- Read-only evidence: `crates/trust/chio-federation-transport-iroh/src/identity.rs:49,57,65,83,101`

**Interfaces:** None (documentation only).

- [ ] **Step 1: Confirm the cited commit is an ancestor of HEAD (evidence gate)**

Run: `git merge-base --is-ancestor 7f8e156d3 HEAD && echo ANCESTOR-OK`
Expected: prints `ANCESTOR-OK` (exit 0). If it does not, stop: the citation is unsafe.

- [ ] **Step 2: Re-read the two stale blocks and the evidence lines**

Run: `sed -n '43,50p' docs/adr/ADR-0014-iroh-federation-transport.md` and `rg -n 'signer_id -> EndpointId. binding home|needs a home - likely anchored at' docs/research/iroh/ADAPTER-SPEC.md` and `sed -n '49p;57p;65p;83p;101p' crates/trust/chio-federation-transport-iroh/src/identity.rs`
Expected: ADR block reads as OPEN; the ADAPTER-SPEC bullet says "needs a home - likely anchored at `KernelTrustExchange`"; identity.rs shows the `...v2` schema string (`:49`), `TRANSPORT_ENDORSEMENT_CONTEXT = b"chio.iroh.transport-endorsement.v1"` (`:57`), `REVOCATION_SIGNER_ENDORSEMENT_CONTEXT = b"chio.iroh.revocation-signer-endorsement.v1"` (`:65`), and the two preimage builders (`:83`, `:101`).

- [ ] **Step 3: Rewrite the ADR-0014:43-50 block as RESOLVED in place (preserve history)**

Replace the block that begins `- **New open item surfaced by the build:**` and ends `...before the oracle\n  endorsement is added.` with, verbatim (note: the word "planned" is deliberately kept off any line that also contains "oracle" so the acceptance greps stay clean):

```markdown
- **Resolved open item surfaced by the build (surfaced and fixed same-day
  2026-07-03, commit `7f8e156d3`):** a passport-endorsement domain-separation
  gap. *As originally surfaced (retained for the audit trail):* the per-entry
  endorsement signed the bare 32 `transport_endpoint_id` bytes with no domain tag
  (`identity.rs`), and a second endorsement over another bare 32-byte ed25519
  value (the revocation-signer / oracle key), signed with the same passport key,
  would have been cross-replayable against the first without domain separation
  (cross-protocol signature-confusion). **RESOLVED** by commit `7f8e156d3`
  ("feat(iroh-transport): domain-separate endorsements + anchor revocation
  signer-binding in the issuer-signed directory", a verified ancestor of HEAD):
  the two endorsement kinds now sign distinct, length-prefixed, injective
  preimages under distinct domain-separation context tags -
  `TRANSPORT_ENDORSEMENT_CONTEXT = b"chio.iroh.transport-endorsement.v1"`
  (`identity.rs:57`) built by `transport_endorsement_preimage` (`identity.rs:83`),
  and `REVOCATION_SIGNER_ENDORSEMENT_CONTEXT =
  b"chio.iroh.revocation-signer-endorsement.v1"` (`identity.rs:65`) built by
  `revocation_signer_endorsement_preimage` (`identity.rs:101`) - each committing
  to its tag plus `kernel_id` plus the endorsed field(s), so the two kinds are
  non-cross-replayable. The peer-directory bundle schema was bumped to
  `...peer-directory-bundle.v2` (`identity.rs:49`). The revocation-signer (oracle)
  endorsement is IMPLEMENTED in-tree, not a future item.
```

- [ ] **Step 4: Append a RESOLVED note to the ADAPTER-SPEC section 7 `signer_id -> EndpointId` bullet (do not delete the open framing)**

At the end of the section 7 bullet that currently ends `... distinct from the\n  pheromone directory.`, append a new paragraph continuation, verbatim:

```markdown
  **RESOLVED (2026-07-03, commit `7f8e156d3`; the open framing above is retained
  for history):** the binding was anchored in the crate's own issuer-signed
  transport directory, NOT `KernelTrustExchange`. `TransportDirectoryEntry` gained
  an additive `#[serde(default)] revocation_signers: Vec<RevocationSignerEntry> {
  signer_id, oracle_public_key, oracle_endorsement }`, and `verify_bundle` projects
  a DERIVED `VerifiedSignerDirectory` (`signer_id -> (EndpointId,
  Ed25519RootVerifier)`) inside `VerifiedDirectory`, inheriting the body-hash pin,
  issuer signature, validity window, and rollback machinery; duplicate `signer_id`
  and removed operators are rejected/suppressed fail-closed. Schema bumped to
  `...v2`. `KernelTrustExchange` carries the kernel key not the oracle root, has no
  `EndpointId`, and is a TOFU self-claim, so it was explicitly NOT chosen (matches
  ADR-0014 Status update, decision tally).
```

- [ ] **Step 5: Verify the ADR machine-checkable assertions**

Run:
```bash
rg -n '7f8e156d3' docs/adr/ADR-0014-iroh-federation-transport.md
rg -n 'transport-endorsement.v1|revocation-signer-endorsement.v1' docs/adr/ADR-0014-iroh-federation-transport.md
rg -in 'planned oracle|oracle-key endorsement would' docs/adr/ADR-0014-iroh-federation-transport.md ; echo "exit=$?"
rg -in 'oracle.*planned|planned.*oracle' docs/adr/ADR-0014-iroh-federation-transport.md ; echo "exit=$?"
```
Expected: the first prints a hit; the second prints BOTH tag lines; the third and fourth print nothing and each report `exit=1` (rg exit 1 = no match, which is the pass condition). If either negative grep reports `exit=0`, reword the offending line so no single line contains both "oracle" and "planned".

- [ ] **Step 6: Verify the ADAPTER-SPEC reconciliation**

Run: `rg -n '7f8e156d3|RESOLVED \(2026-07-03' docs/research/iroh/ADAPTER-SPEC.md`
Expected: prints the RESOLVED note in section 7 (at least one hit for the commit + one for the RESOLVED marker).

- [ ] **Step 7: Commit**

```bash
git add docs/adr/ADR-0014-iroh-federation-transport.md docs/research/iroh/ADAPTER-SPEC.md
git commit -m "docs(iroh): mark domain-separation + signer-binding items resolved by 7f8e156d3

Reconcile the two same-commit stale doc items: ADR-0014's passport-endorsement
domain-separation open item and ADAPTER-SPEC section 7's signer_id -> EndpointId
binding-home bullet were both resolved by 7f8e156d3. Rewrite each as RESOLVED
in place (history preserved), citing the two domain-separation context tags and
the schema v2 bump.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: M2 - File the upstream iroh-gossip inbound-admission FR and anchor its URL in-repo

Off-repo action plus two in-repo anchors. The FR body already exists verbatim at `fanout.rs:70-94` and the ask at `:92-94`. The reviewer refinements are folded in: gate the filing behind a duplicate-check, and anchor the URL in ADAPTER-SPEC section 7's topic-membership bullet as well (not only fanout.rs), so the spec-level open decision points at the tracking issue.

**Files:**
- Off-repo: one issue on `n0-computer/iroh-gossip`.
- Modify: `crates/trust/chio-federation-transport-iroh/src/lanes/fanout.rs` (residual doc block, after `:94`)
- Modify: `docs/research/iroh/ADAPTER-SPEC.md` (section 7, "Topic-membership admission + revocation eviction latency" bullet)

**Interfaces:** An upstream GitHub issue (off-repo) plus a single in-repo URL anchor comment reused in both doc homes. No code contract.

- [ ] **Step 1: Duplicate-check upstream before filing (gate)**

Run (requires `gh` auth; if unavailable, do the equivalent web search):
```bash
gh search issues --repo n0-computer/iroh-gossip --state all 'inbound admission' 'JoinOptions predicate' 'NeighborJoinRequested' 'reject join' 'hyparview on_join'
gh search issues --repo n0-computer/iroh --state all 'gossip inbound admission predicate'
```
Expected: review the hits. If an equivalent inbound-admission-predicate request already exists, SKIP filing and use its URL as `<URL>` in Steps 3-4 (note "existing upstream issue, reused" in the commit body). Only file a new issue if none matches.

- [ ] **Step 2: File the FR on n0-computer/iroh-gossip (if no duplicate)**

Run:
```bash
gh issue create --repo n0-computer/iroh-gossip \
  --title "Feature request: per-topic/per-peer inbound admission predicate for gossip joins (iroh-gossip 0.101)" \
  --body "$(cat <<'BODY'
### Problem

We build a per-treaty gossip surface on iroh-gossip 0.101 and need to gate INBOUND
neighbor joins on an application predicate. Verified against 0.101:

- The membership protocol admits inbound joins UNCONDITIONALLY: `hyparview::HyparView::on_join`
  adds the joining peer with `Priority::High`, and `add_active` ALWAYS succeeds for a
  high-priority join (evicting a random slot if full). No application predicate is consulted.
- `JoinOptions` (the only per-subscription config) carries just `bootstrap` and
  `subscription_capacity`: no per-peer/per-topic admission callback or ACL.
- There is no pre-acceptance event: `iroh_gossip::api::Event` is only
  `NeighborUp`/`NeighborDown`/`Received`/`Lagged`; `NeighborUp` fires AFTER the peer is
  already in the active view, and a neighbor cannot be rejected then.
- The mounted `ProtocolHandler::accept` for `iroh_gossip::ALPN` admits ALL connections
  (a single gossip connection multiplexes every topic, so per-topic gating at the
  connection layer is not possible either).

### Ask

Either (a) a per-topic/per-peer inbound admission predicate in `JoinOptions`, OR (b) a
pre-acceptance `NeighborJoinRequested` event with the ability to DENY the join.

### Why

Without either, a peer that computes a deterministic (non-secret) `TopicId` and dials a
member can be admitted as a gossip neighbor and passively observe forwarded frames, with
no application hook to refuse the join before it enters the active view.
BODY
)"
```
Expected: prints the created issue URL. Capture it as `<URL>` (for example `https://github.com/n0-computer/iroh-gossip/issues/NNN`). If you lack authority or `gh` auth to file, use the tracked placeholder `TODO(iroh-gossip-admission-FR): file + backfill URL - owner: <you>, 2026-07-07` as `<URL>` in Steps 3-4 and backfill later.

- [ ] **Step 3: Anchor the URL in the fanout.rs residual doc block**

In `crates/trust/chio-federation-transport-iroh/src/lanes/fanout.rs`, immediately after line 97 (the `//! This is a documented API limitation, NOT a closed gap.` line that closes the residual section), insert:

```rust
//!
//! Upstream tracking (filed against iroh-gossip 0.101): <URL>
```

- [ ] **Step 4: Anchor the same URL in ADAPTER-SPEC section 7's topic-membership bullet**

In `docs/research/iroh/ADAPTER-SPEC.md`, at the end of the section 7 bullet titled "Topic-membership admission + revocation eviction latency" (the one ending `... bounded by\n  directory propagation latency.`), append:

```markdown
  Upstream tracking (inbound-admission predicate FR, iroh-gossip 0.101): <URL>
```

- [ ] **Step 5: Verify both anchors**

Run:
```bash
rg -n 'Upstream tracking' crates/trust/chio-federation-transport-iroh/src/lanes/fanout.rs
rg -n 'inbound-admission predicate FR' docs/research/iroh/ADAPTER-SPEC.md
```
Expected: each prints the anchored `<URL>` (or the `TODO(iroh-gossip-admission-FR)` placeholder pre-backfill).

- [ ] **Step 6: Confirm the doc-comment change still compiles the adapter (scoped)**

Run: `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo build -p chio-federation-transport-iroh`
Expected: `Finished` with no errors (doc-comment-only change; no code path altered).

- [ ] **Step 7: Commit**

```bash
git add crates/trust/chio-federation-transport-iroh/src/lanes/fanout.rs docs/research/iroh/ADAPTER-SPEC.md
git commit -m "docs(iroh): anchor upstream iroh-gossip inbound-admission FR in fanout + ADAPTER-SPEC

File (or reuse) the upstream iroh-gossip 0.101 inbound-admission-predicate feature
request and anchor its URL in the fanout residual doc block and in ADAPTER-SPEC
section 7's topic-membership bullet. Containment (M3 risk row + experimental
marker) is the durable mitigation; the FR is necessary but not sufficient.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: M3 - Bounded RISK_REGISTER row + experimental marker on the library-only fanout lane

One RISK_REGISTER row worded to the verified bound and scope (library-only, inject-blocked/observe-only, with a re-rate trigger), plus an EXPERIMENTAL marker in three doc-comment homes. The row must NOT assert the shipped `chio` binary leaks treaty traffic (the fanout lane is not CLI-wired: the CLI `IrohLane` enum has only Pheromone/Revocation/Bilateral, and `parse_iroh_lanes` accepts only `pheromone`).

**Files:**
- Modify: `docs/release/RISK_REGISTER.md`
- Modify: `crates/trust/chio-federation-transport-iroh/src/lanes/fanout.rs` (module header + `pub struct FanoutLane` at `:814`)
- Modify: `crates/trust/chio-federation-transport-iroh/src/lib.rs:21`

**Interfaces:** A RISK_REGISTER row (Risk | Severity | Mitigation status | Notes) with embedded scope + bound + re-rate trigger; an `EXPERIMENTAL (lane c)` doc-comment banner. No runtime contract.

- [ ] **Step 1: Add the bounded risk row under "Critical Engineering Backlog"**

In `docs/release/RISK_REGISTER.md`, append a row to the "Critical Engineering Backlog" table (the one with header `| Risk | Severity | Mitigation status | Notes |`), immediately after the existing last row of that table:

```markdown
| Fanout lane (lane c) inbound-join confidentiality residual (iroh-gossip 0.101) | LOW (informational) | contained | SCOPE: library-only. The fanout lane is NOT exposed through the shipped `chio` CLI (the `IrohLane` enum has only Pheromone/Revocation/Bilateral; `parse_iroh_lanes` rejects the rest), so the shipped binary does NOT leak treaty traffic today. BOUND: a federation-admitted non-party can PASSIVELY OBSERVE forwarded frames but CANNOT INJECT an accepted frame (receive-side treaty-party gate, fanout.rs:592-597; swarm/treaty binding, fanout.rs:717-727); topic-per-treaty routing keeps other treaties' traffic off the swarm (observe-only). CAUSE: iroh-gossip 0.101 exposes no inbound-admission hook (fanout.rs:59-97). Upstream FR: see the anchor in fanout.rs + ADAPTER-SPEC section 7. RE-RATE TRIGGER: re-rate to HIGH and revisit this wording if lane c (fanout) is ever wired into the `chio` CLI or any shipped product surface, or if any release claim depends on treaty confidentiality against a passive federation-admitted observer. |
```

- [ ] **Step 2: Add the EXPERIMENTAL banner to the fanout.rs module header**

In `crates/trust/chio-federation-transport-iroh/src/lanes/fanout.rs`, insert a new banner line as the very first line of the module doc (before the existing `//! Lane c: cross-operator fan-out ...` on line 1):

```rust
//! EXPERIMENTAL (lane c): library-only, not CLI-wired; carries a documented
//! passive-observation residual (see the "Residual exposure" section below and
//! docs/release/RISK_REGISTER.md). Do not gate any release claim on this lane.
//!
```

- [ ] **Step 3: Add the marker on the FanoutLane type**

In the same file, immediately above `pub struct FanoutLane {` (line 814, just under the existing struct doc-comment ending at `:812` and the `#[derive(Debug, Clone)]` at `:813`), add a doc line. Place it as the last line of the struct's doc-comment (keep it inside the `///` block that precedes the derive), for example after the line ending `... spawned `gossip` on.):`:

```rust
///
/// EXPERIMENTAL (lane c): library-only, not wired into the `chio` CLI; see the
/// module-level residual-exposure note and docs/release/RISK_REGISTER.md.
```

- [ ] **Step 4: Mark the lib.rs fanout bullet EXPERIMENTAL**

In `crates/trust/chio-federation-transport-iroh/src/lib.rs`, change line 21 from:

```rust
//! - [`lanes::fanout`]: cross-operator fan-out over iroh-gossip per-treaty topics.
```

to:

```rust
//! - [`lanes::fanout`]: cross-operator fan-out over iroh-gossip per-treaty topics.
//!   EXPERIMENTAL (lane c): library-only, not CLI-wired; passive-observation residual.
```

- [ ] **Step 5: Verify the row and markers**

Run:
```bash
rg -in 'fanout|passive.?observ' docs/release/RISK_REGISTER.md
rg -in 'library-only' docs/release/RISK_REGISTER.md
rg -in 'inject|observe-only' docs/release/RISK_REGISTER.md
rg -in 're-rate' docs/release/RISK_REGISTER.md
rg -in 'EXPERIMENTAL' crates/trust/chio-federation-transport-iroh/src/lanes/fanout.rs crates/trust/chio-federation-transport-iroh/src/lib.rs
```
Expected: the risk row is returned; its text contains `library-only`, an injection-blocked phrasing (`inject` / `observe-only`), and a `re-rate` trigger; the EXPERIMENTAL marker appears in both fanout.rs (module header AND struct) and lib.rs. Confirm by eye that the row does NOT claim the shipped `chio` binary leaks treaty traffic.

- [ ] **Step 6: Confirm the adapter still compiles + clippy clean (scoped)**

Run:
```bash
rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo build -p chio-federation-transport-iroh
rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo clippy -p chio-federation-transport-iroh -- -D warnings
```
Expected: both `Finished` with no warnings (doc-comment-only change).

- [ ] **Step 7: Commit**

```bash
git add docs/release/RISK_REGISTER.md crates/trust/chio-federation-transport-iroh/src/lanes/fanout.rs crates/trust/chio-federation-transport-iroh/src/lib.rs
git commit -m "docs(risk): add bounded fanout inbound-join residual row + mark lane c experimental

Add a scope-accurate RISK_REGISTER row (library-only, inject-blocked/observe-only,
LOW/informational, with a re-rate-to-HIGH trigger if lane c is ever CLI-wired) and
an EXPERIMENTAL marker on the FanoutLane type, the fanout module header, and the
lib.rs lane list. Does not claim the shipped binary leaks treaty traffic.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: M4 - Feature-gate iroh out of the DEFAULT shipped chio binary + add a CI leg

Make `iroh` and `chio-federation-transport-iroh` optional on `chio-cli` behind a default-off `iroh` feature, cfg-gate every iroh use site, keep the `--iroh-*` flags always defined, and add a fail-closed handler in the INNER serve/tick fns. Reviewer refinements folded in: the `#[cfg(not(feature = "iroh"))]` arm must consume ALL iroh_* params (not only `iroh_enable`) to survive `-D warnings`; place the fail-closed error inside `cmd_chio_pheromone_relay_serve` / `cmd_chio_pheromone_relay_tick` (where `load_iroh_serve_inputs` is cfg-gated), not the outer dispatch; keep the gated tests in a CI leg; and state plainly that the workspace still compiles iroh (containment != removal: the adapter is a workspace member at `Cargo.toml:85` and a chio-conformance dev-dep at `chio-conformance/Cargo.toml:99,189-190`).

This is the only task with a real "break the default build" failure mode. The exhaustiveness proof is the two-state clippy/build acceptance in Steps 9-11.

**Files:**
- Modify: `crates/products/chio-cli/Cargo.toml:47-48` and `[features]` (`:125-126`)
- Modify: `crates/products/chio-cli/src/cli/chio/dispatch/pheromone.rs:11-12,55-58`
- Modify: `crates/products/chio-cli/src/cli/chio/dispatch/pheromone/relay.rs:1-7` (imports), serve/tick bodies + iroh helpers + tests
- Modify: `.github/workflows/ci.yml` (`check` job, after "Workspace tests")
- Keep unchanged: `crates/products/chio-cli/src/cli/chio/types/pheromone/relay.rs`, `crates/products/chio-cli/src/cli/dispatch/pheromone.rs`, `crates/products/chio-cli/src/cli/chio/dispatch/pheromone/iroh_mount.rs` (the whole module is gated at its `mod` site)

**Interfaces:**
- Produces: a cargo feature `iroh = ["dep:chio-federation-transport-iroh", "dep:iroh"]` on `chio-cli` (default-off).
- Produces: a private helper `fn reject_iroh_enable_without_feature(iroh_enable: bool) -> Result<(), CliError>` (in `relay.rs`, compiled only under `#[cfg(not(feature = "iroh"))]`), returning `Err(CliError::cli_other_error(...))` whose message contains `built without the \`iroh\` feature` when `iroh_enable` is true, else `Ok(())`.
- Consumes: `CliError::cli_other_error(String) -> CliError` (already used across relay.rs).

- [ ] **Step 1: Write the failing fail-closed test (default, non-iroh build)**

In `crates/products/chio-cli/src/cli/chio/dispatch/pheromone/relay.rs`, inside the existing `#[cfg(test)] mod tests { ... }` block (near `:975`), add:

```rust
#[cfg(not(feature = "iroh"))]
#[test]
fn iroh_enable_without_feature_is_rejected_fail_closed() {
    let Err(err) = super::reject_iroh_enable_without_feature(true) else {
        panic!("--iroh-enable must be rejected on a build without the `iroh` feature");
    };
    let msg = err.to_string();
    assert!(
        msg.contains("built without the `iroh` feature"),
        "unexpected error message: {msg}"
    );
    // Fail-closed, not a clap parse error.
    assert!(!msg.contains("unknown argument"), "must not be a clap error: {msg}");
    // With the flag off, the guard is a no-op.
    assert!(super::reject_iroh_enable_without_feature(false).is_ok());
}
```

- [ ] **Step 2: Run the test to confirm it fails (function does not exist yet)**

Run: `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-cli iroh_enable_without_feature_is_rejected_fail_closed`
Expected: FAIL to compile with `cannot find function \`reject_iroh_enable_without_feature\`` (the default build has no `iroh` feature, so the `#[cfg(not(feature = "iroh"))]` test is active).

- [ ] **Step 3: Add the fail-closed guard helper**

In `relay.rs`, add the helper next to the serve/tick fns (outside the test module), compiled only when the feature is off:

```rust
/// Fail-closed guard for builds without the `iroh` cargo feature. When the operator
/// passes `--iroh-enable` but the binary was compiled without `--features iroh`, reject
/// with a clear, actionable error instead of clap "unknown argument" or a silent no-op.
#[cfg(not(feature = "iroh"))]
fn reject_iroh_enable_without_feature(iroh_enable: bool) -> Result<(), CliError> {
    if iroh_enable {
        return Err(CliError::cli_other_error(
            "Chio iroh transport: this `chio` binary was built without the `iroh` feature; \
             rebuild with `--features iroh` to use --iroh-enable"
                .to_string(),
        ));
    }
    Ok(())
}
```

- [ ] **Step 4: Split the mixed import block in relay.rs and gate the iroh imports**

Replace the `use super::{ ... };` block at `relay.rs:1-7` (which mixes iroh and non-iroh symbols) with a non-iroh block plus a feature-gated iroh block:

```rust
use super::{
    build_peer_directory_bundle_trust, load_chio_verified_workflow_resolver,
    load_chio_workflow_verifier_trust_bundle, read_utf8_json_file, unix_now_ms,
    write_json_string, write_pretty_json,
};
#[cfg(feature = "iroh")]
use super::{
    build_iroh_outbound_endpoint, build_iroh_router, iroh_transport_metrics_prometheus,
    load_iroh_serve_inputs, IrohServeInputs,
};
```

(Preserve any other non-iroh names actually present in the original block; the exact non-iroh set is whatever remains after removing the five iroh names above. Confirm with `rg -n 'use super' crates/products/chio-cli/src/cli/chio/dispatch/pheromone/relay.rs` before editing.)

- [ ] **Step 5: Gate the iroh serve body and add the fail-closed guard at the top of cmd_chio_pheromone_relay_serve**

In `cmd_chio_pheromone_relay_serve` (fn at `:126`), replace the unconditional `load_iroh_serve_inputs(...)` call (`:152`) region with a two-state block, and gate every downstream iroh use (`iroh_inputs`, `iroh_mount_plan`, the metrics registration at `:250-253`, the `build_iroh_router` mount at `:267-310`) behind `#[cfg(feature = "iroh")]`:

```rust
#[cfg(feature = "iroh")]
let iroh_inputs = load_iroh_serve_inputs(
    iroh_enable,
    iroh_transport_directory,
    iroh_transport_directory_state,
    iroh_transport_key,
    iroh_bind_addr,
    iroh_relay_url,
    iroh_lanes,
)?;
#[cfg(not(feature = "iroh"))]
{
    reject_iroh_enable_without_feature(iroh_enable)?;
    // Consume every remaining iroh_* param so the non-iroh build is clippy-clean under -D warnings.
    let _ = (
        iroh_transport_directory,
        iroh_transport_directory_state,
        iroh_transport_key,
        iroh_bind_addr,
        iroh_relay_url,
        iroh_lanes,
    );
}
```

Then wrap each block that references `iroh_inputs` / `iroh_mount_plan` / `iroh_transport_metrics_prometheus` / `build_iroh_router` in `#[cfg(feature = "iroh")]`. Under `not(feature = "iroh")` those variables never exist, so the serve path is byte-for-byte the pre-change HTTP path once `iroh_enable` is false.

- [ ] **Step 6: Gate the iroh tick body and add the guard at the top of cmd_chio_pheromone_relay_tick**

In `cmd_chio_pheromone_relay_tick` (fn at `:402`), add the same two-state guard at the top (its param set adds `iroh_peer_addr`, so include it in the consume tuple), and gate the iroh drain path (`build_iroh_outbound_endpoint`, `drain_due_batches_over_iroh`, `parse_iroh_peer_addr_book`) behind `#[cfg(feature = "iroh")]`:

```rust
#[cfg(not(feature = "iroh"))]
{
    reject_iroh_enable_without_feature(iroh_enable)?;
    let _ = (
        iroh_transport_directory,
        iroh_transport_directory_state,
        iroh_transport_key,
        iroh_bind_addr,
        iroh_relay_url,
        iroh_peer_addr,
        iroh_lanes,
    );
}
```

- [ ] **Step 7: Gate the iroh-only helper fns and their tests**

Add `#[cfg(feature = "iroh")]` to `fn parse_iroh_peer_addr_book` (`:528`), `fn drain_due_batches_over_iroh` (`:598`), and to each of their `#[cfg(test)]` unit tests (`parse_iroh_peer_addr_book_parses_and_groups_multi_homed_recipients`, `parse_iroh_peer_addr_book_is_empty_for_no_entries`, `parse_iroh_peer_addr_book_rejects_malformed_entries_fail_closed`, and `iroh_tick_drains_the_outbox_and_folds_an_unresolvable_recipient_into_retry`). These are iroh-only and must not compile in the default build.

- [ ] **Step 8: Gate the iroh_mount module and its re-exports in the dispatch mod**

In `crates/products/chio-cli/src/cli/chio/dispatch/pheromone.rs`, add `#[cfg(feature = "iroh")]` on line 11-12:

```rust
#[cfg(feature = "iroh")]
#[path = "pheromone/iroh_mount.rs"]
mod iroh_mount;
```

and on the re-export block at `:55-58`:

```rust
#[cfg(feature = "iroh")]
pub(crate) use self::iroh_mount::{
    build_iroh_outbound_endpoint, build_iroh_router, iroh_transport_metrics_prometheus,
    load_iroh_serve_inputs, IrohServeInputs,
};
```

- [ ] **Step 9: Make the deps optional and add the `iroh` feature in Cargo.toml**

In `crates/products/chio-cli/Cargo.toml`, change lines 47-48 to:

```toml
chio-federation-transport-iroh = { workspace = true, optional = true }
iroh = { version = "1.0", default-features = false, features = ["tls-ring"], optional = true }
```

and change the `[features]` block (currently only `tee-quotes`) to add the `iroh` feature with the honesty-boundary comment:

```toml
[features]
tee-quotes = ["chio-attest-verify/tee-quotes"]
# Default-OFF. Gating iroh out of the shipped `chio` binary shrinks its size and
# supply-chain surface (for example the iroh -> netwatch -> netdev -> plist -> quick-xml
# RUSTSEC-2026-0194 / 0195 chain, deny.toml:62-71). It does NOT remove iroh from
# `cargo build --workspace` / `cargo test --workspace`: chio-federation-transport-iroh
# stays a workspace member (root Cargo.toml:85) and a chio-conformance dev-dep
# (crates/tooling/chio-conformance/Cargo.toml:189-190). Containment, not removal.
iroh = ["dep:chio-federation-transport-iroh", "dep:iroh"]
```

- [ ] **Step 10: Prove the default build is exhaustively gated (default, non-iroh)**

Run:
```bash
rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo build -p chio-cli
rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo clippy -p chio-cli -- -D warnings
```
Expected: both succeed. Any `cannot find` / `unresolved import` / `unused variable` / `dead_code` error means a stray iroh use site is ungated or an iroh_* param is unconsumed - fix it and re-run. This is the primary exhaustiveness gate.

- [ ] **Step 11: Prove the iroh-feature build + clippy is clean (feature on)**

Run:
```bash
rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo build -p chio-cli --features iroh
rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo clippy -p chio-cli --features iroh -- -D warnings
```
Expected: both succeed (the guard helper and its test are `#[cfg(not(feature = "iroh"))]`, so they vanish here and cause no unused-fn warning).

- [ ] **Step 12: Run the fail-closed test (default) and the gated tests (feature on)**

Run:
```bash
rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-cli iroh_enable_without_feature_is_rejected_fail_closed
rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo test -p chio-cli --features iroh
```
Expected: the first passes on the default build; the second runs and passes the ~17 iroh-gated unit tests (13 in iroh_mount.rs + the 4 iroh tests in relay.rs).

- [ ] **Step 13: Prove the shipped-binary tree drops iroh, the feature tree keeps it**

Run:
```bash
cargo tree -p chio-cli -e no-dev | rg -q iroh && echo "LEAK: iroh in default non-dev tree" || echo "OK: iroh absent from default shipped tree"
cargo tree -p chio-cli --features iroh -e no-dev | rg -n '^.*iroh' | head
```
Expected: the first prints `OK: iroh absent from default shipped tree`; the second prints iroh entries. (`-e no-dev` excludes the chio-conformance dev-dep edge, so the default result is genuinely iroh-free.)

- [ ] **Step 14: Add the CI leg to ci.yml so the gated tests do not rot**

In `.github/workflows/ci.yml`, in the `check` job, immediately after the "Workspace tests" step (near `:178`), add:

```yaml
      - name: chio-cli iroh feature (shipped binary excludes iroh; workspace still compiles it)
        env:
          CARGO_BUILD_JOBS: "1"
          RUSTFLAGS: "${{ env.CHIO_CI_RUSTFLAGS }} -C debuginfo=0"
        run: |
          cargo build -p chio-cli --features iroh
          cargo clippy -p chio-cli --features iroh -- -D warnings

      - name: chio-cli iroh feature tests (keep the ~17 gated iroh_mount/relay tests alive)
        env:
          CARGO_BUILD_JOBS: "1"
          RUSTFLAGS: "${{ env.CHIO_CI_RUSTFLAGS }} -C debuginfo=0"
        run: cargo test -p chio-cli --features iroh
```

(These are scoped `-p chio-cli` legs; the pre-existing `--workspace` steps in ci.yml are unchanged. The `rm -rf target/debug/incremental` / `CARGO_INCREMENTAL=0` prelude is a LOCAL constraint and is not required inside CI, which starts from a clean or cached tree.)

- [ ] **Step 15: Verify the CI leg is present and well-formed**

Run: `rg -n 'chio-cli --features iroh' .github/workflows/ci.yml`
Expected: three hits (build, clippy, test) under the two new step names.

- [ ] **Step 16: Commit**

```bash
git add crates/products/chio-cli/Cargo.toml \
        crates/products/chio-cli/src/cli/chio/dispatch/pheromone.rs \
        crates/products/chio-cli/src/cli/chio/dispatch/pheromone/relay.rs \
        .github/workflows/ci.yml
git commit -m "feat(chio-cli): feature-gate iroh out of the default binary, fail closed when absent

Make iroh + chio-federation-transport-iroh optional behind a default-off \`iroh\`
feature; cfg-gate every iroh use site (mod iroh_mount, relay serve/tick bodies,
iroh helper fns + tests). Keep the --iroh-* clap flags always defined; add an
inner fail-closed guard so --iroh-enable on a non-iroh build errors clearly
instead of clap 'unknown argument'. The non-iroh arm consumes every iroh_* param
to stay -D warnings clean. Add a scoped CI leg so the ~17 gated tests do not rot.
Containment, not removal: the workspace compile still builds iroh (adapter is a
workspace member + chio-conformance dev-dep).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: M5 - Swift SDK first CI (xcodebuild test on macOS against the committed xcframework)

Lane shape A (lowest change, no source edit): the package is iOS-only with an iOS-only binaryTarget, so plain `swift test` on macOS cannot compile it. Drive the existing simulator-safe tests with `xcodebuild test` against an iOS Simulator. Reviewer refinements folded in: do NOT hardcode `-scheme Chio` (use the test-inclusive `Chio-Package` scheme); ASSERT a nonzero executed-test count (a 0-test filter is a false green); pin the simulator destination via `xcrun simctl list`; and confirm the `ChioFFI` systemLibrary modulemap resolves against the `ios-arm64_x86_64-simulator` slice's Headers.

**Files:**
- Create: `.github/workflows/swift-sdk.yml`
- Read-only (unchanged): `sdks/swift/Package.swift`, `sdks/swift/Sources/ChioFFI/module.modulemap`, `sdks/swift/Frameworks/ChioKernel.xcframework/ios-arm64_x86_64-simulator/Headers/`, `sdks/swift/Tests/ChioTests/{IntegrationTests,AppAttestTests}.swift`, `scripts/build-ios-framework.sh`

**Interfaces:** A new CI workflow with a pinned iOS Simulator destination contract (`platform=iOS Simulator`, device name + OS runtime resolved at job start) and a nonzero-test-count assertion. No source-code contract under lane A.

- [ ] **Step 1: Confirm the sim slice carries the FFI header + modulemap the ChioFFI target resolves against**

Run:
```bash
ls sdks/swift/Frameworks/ChioKernel.xcframework/ios-arm64_x86_64-simulator/Headers/
cat sdks/swift/Sources/ChioFFI/module.modulemap
```
Expected: the Headers dir lists `chio_kernel_mobileFFI.h` and `chio_kernel_mobileFFI.modulemap`; the ChioFFI modulemap declares `framework module ChioKernel { umbrella header "chio_kernel_mobileFFI.h" ... }`. This confirms the simulator slice provides the umbrella header the `.systemLibrary(name: "ChioFFI")` + `.binaryTarget(name: "ChioKernel")` pair link against, so lane A's sim build resolves. (If the sim slice lacked the header, lane A would need adjustment.)

- [ ] **Step 2: Confirm the tests are simulator-safe (no Secure Enclave / real DCAppAttestService)**

Run: `rg -n 'MockAppAttestService|XCTAssertThrowsError|DCAppAttestService' sdks/swift/Tests/ChioTests/`
Expected: `IntegrationTests.swift` only asserts the FFI entries (`attestAppAttest`, `verifyMobileReceipt`) THROW for mock inputs; `AppAttestTests.swift` uses an injected `MockAppAttestService`; no direct `DCAppAttestService` use in tests. Total executed tests will be 3 (`testForwardToKernelFlowUsesSevenEntrySurface`, `testGenerateKeyAndAttestationEnvelope`, `testGenerateAssertionBindsChallengeHash`), which the nonzero-count assertion in Step 4 protects.

- [ ] **Step 3: Confirm the test-inclusive scheme name (avoid the false-green `-scheme Chio` trap)**

The plan pins `-scheme Chio-Package` (the package-wide scheme SwiftPM generates, which includes the `ChioTests` target). The library-only `Chio` scheme does NOT include tests and would report success while running zero tests. The workflow (Step 4) runs `xcodebuild -list` first and greps for `Chio-Package` so a future scheme rename fails loudly rather than silently running the wrong scheme.

- [ ] **Step 4: Create `.github/workflows/swift-sdk.yml`**

Write the file:

```yaml
name: Swift SDK

on:
  push:
    paths:
      - ".github/workflows/swift-sdk.yml"
      - "sdks/swift/**"
  pull_request:
    paths:
      - ".github/workflows/swift-sdk.yml"
      - "sdks/swift/**"

permissions:
  contents: read

concurrency:
  group: swift-sdk-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

jobs:
  xcodebuild-test:
    name: Swift SDK (iOS Simulator xcodebuild test)
    runs-on: macos-latest
    defaults:
      run:
        working-directory: sdks/swift
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5

      - name: Select Xcode and show toolchain
        run: |
          sudo xcode-select -p
          xcodebuild -version
          swift --version

      - name: Confirm the test-inclusive scheme exists (no hardcoded -scheme Chio false green)
        run: |
          xcodebuild -list -project . 2>/dev/null || xcodebuild -list
          xcodebuild -list | grep -qw "Chio-Package" \
            || { echo "::error::expected the test-inclusive 'Chio-Package' scheme"; exit 1; }

      - name: Pin an available iOS Simulator destination
        id: sim
        run: |
          # Pick the newest available iOS runtime + an iPhone device from it, fail closed if none.
          RUNTIME=$(xcrun simctl list runtimes --json \
            | python3 -c "import sys,json; r=[x for x in json.load(sys.stdin)['runtimes'] if x['isAvailable'] and 'iOS' in x['name']]; print(sorted(r,key=lambda x:x['version'])[-1]['identifier'] if r else '')")
          if [ -z "$RUNTIME" ]; then echo "::error::no available iOS Simulator runtime"; exit 1; fi
          DEVICE=$(xcrun simctl list devices --json \
            | python3 -c "import sys,json,os; d=json.load(sys.stdin)['devices'].get(os.environ['RUNTIME'],[]); a=[x for x in d if x.get('isAvailable') and x['name'].startswith('iPhone')]; print(a[0]['name'] if a else '')" )
          if [ -z "$DEVICE" ]; then echo "::error::no available iPhone simulator for $RUNTIME"; exit 1; fi
          OSVER=$(echo "$RUNTIME" | sed -E 's/.*iOS-([0-9]+)-([0-9]+).*/\1.\2/')
          echo "device=$DEVICE" >> "$GITHUB_OUTPUT"
          echo "osver=$OSVER" >> "$GITHUB_OUTPUT"
          echo "Pinned destination: platform=iOS Simulator,name=$DEVICE,OS=$OSVER"
        env:
          RUNTIME: ""

      - name: xcodebuild test (Chio-Package on the pinned simulator)
        run: |
          set -o pipefail
          xcodebuild test \
            -scheme Chio-Package \
            -destination "platform=iOS Simulator,name=${{ steps.sim.outputs.device }},OS=${{ steps.sim.outputs.osver }}" \
            -resultBundlePath "$RUNNER_TEMP/ChioTests.xcresult" \
            | tee "$RUNNER_TEMP/xcodebuild.log"

      - name: Assert a NONZERO executed-test count (guard against a 0-test false green)
        run: |
          # xcodebuild prints "Executed N tests, ..." per suite; require at least one N >= 1.
          if ! grep -Eq 'Executed [1-9][0-9]* test' "$RUNNER_TEMP/xcodebuild.log"; then
            echo "::error::no tests were executed (0-test filter is a false green)"; exit 1
          fi
          grep -E 'Executed [0-9]+ test' "$RUNNER_TEMP/xcodebuild.log" | tail -n 1
```

- [ ] **Step 5: (Optional) Add a nightly/manual xcframework-drift lane (kept out of the fast PR lane)**

If catching FFI drift is wanted, add a second job (gated on `workflow_dispatch` and/or `schedule`) that runs `bash scripts/build-ios-framework.sh` to rebuild `ChioKernel.xcframework` from the current Rust FFI (needs full Xcode + `aarch64-apple-ios` / `-sim` + `x86_64-apple-ios` Rust targets + uniffi-bindgen + lipo, per `scripts/build-ios-framework.sh:1-90`), then re-runs the sim tests. Do NOT put this in the PR lane (cost/time). A stale committed xcframework would otherwise pass CI against old symbols.

```yaml
  xcframework-drift:
    name: Swift SDK xcframework drift (nightly/manual)
    if: github.event_name == 'workflow_dispatch' || github.event_name == 'schedule'
    runs-on: macos-14
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5
      - name: Rebuild the xcframework from the current Rust FFI
        run: bash scripts/build-ios-framework.sh
      - name: Re-run the sim tests against the rebuilt framework
        working-directory: sdks/swift
        run: |
          set -o pipefail
          xcodebuild -list | grep -qw "Chio-Package"
          xcodebuild test -scheme Chio-Package \
            -destination "platform=iOS Simulator,name=iPhone 15" \
            | tee "$RUNNER_TEMP/drift.log"
          grep -Eq 'Executed [1-9][0-9]* test' "$RUNNER_TEMP/drift.log"
```

(If you add the `schedule` trigger, add it to the top-level `on:` block; otherwise keep only `workflow_dispatch` so the drift job is manual.)

- [ ] **Step 6: Verify the workflow is well-formed and path-triggered**

Run:
```bash
test -f .github/workflows/swift-sdk.yml && echo EXISTS
rg -n 'runs-on: macos' .github/workflows/swift-sdk.yml
rg -n 'xcodebuild test' .github/workflows/swift-sdk.yml
rg -n 'iOS Simulator' .github/workflows/swift-sdk.yml
rg -n 'sdks/swift/\*\*' .github/workflows/swift-sdk.yml
rg -n 'Chio-Package' .github/workflows/swift-sdk.yml
rg -n 'Executed \[1-9\]' .github/workflows/swift-sdk.yml
rg -n '\-scheme Chio\b' .github/workflows/swift-sdk.yml ; echo "hardcoded-Chio-exit=$?"
```
Expected: `EXISTS`; `runs-on: macos-*` present; `xcodebuild test` present; `iOS Simulator` destination present; `sdks/swift/**` path trigger present; `Chio-Package` present; the nonzero-count guard present; and the last grep for a bare `-scheme Chio` (word boundary, not `Chio-Package`) reports `hardcoded-Chio-exit=1` (no match = pass). If it matches, replace the bare `Chio` scheme with `Chio-Package`.

- [ ] **Step 7: Validate the YAML parses (no macOS runner needed locally)**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/swift-sdk.yml')); print('YAML OK')"`
Expected: prints `YAML OK`. (The authoritative test is the workflow itself running green on a macOS runner in CI; local YAML validation is the pre-merge gate.)

- [ ] **Step 8: Commit**

```bash
git add .github/workflows/swift-sdk.yml
git commit -m "ci(swift): add first Swift SDK CI (iOS Simulator xcodebuild test)

Add a macOS-runner lane that drives the existing simulator-safe ChioTests via
xcodebuild against the committed iOS xcframework. Use the test-inclusive
Chio-Package scheme (not the library-only Chio scheme), pin the simulator
destination via xcrun simctl list, and assert a nonzero executed-test count so a
0-test filter cannot masquerade as green. Path-triggered on sdks/swift/**.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Whole-direction sanity gate (run after all five tasks)

Direction D is off the critical path and touches none of `chio-kernel/src/budget_store.rs`, the api-protect sidecar path, or chio-metering. Confirm scoped verification stays green (never `--workspace` locally):

- [ ] `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo clippy -p chio-federation-transport-iroh -- -D warnings` - clean.
- [ ] `rm -rf target/debug/incremental && CARGO_INCREMENTAL=0 cargo clippy -p chio-cli -- -D warnings` and `... -p chio-cli --features iroh -- -D warnings` - both clean.
- [ ] `cargo tree -p chio-cli -e no-dev | rg -q iroh || echo OK` - prints `OK` (iroh absent from the shipped tree).
- [ ] `cargo fmt -p chio-cli -p chio-federation-transport-iroh -- --check` - clean.
- [ ] `grep -rnP '\x{2014}' docs/superpowers/plans/2026-07-07-direction-d-iroh-assurance-hygiene.md docs/adr/ADR-0014-iroh-federation-transport.md docs/research/iroh/ADAPTER-SPEC.md docs/release/RISK_REGISTER.md crates/trust/chio-federation-transport-iroh/src/lanes/fanout.rs crates/trust/chio-federation-transport-iroh/src/lib.rs ; echo "em-dash-exit=$?"` - reports `em-dash-exit=1` (no U+2014 introduced; the `\x{2014}` codepoint form detects em-dashes without embedding one).

## Execution ordering notes

- M1 (Task 1), M4 (Task 4), and M5 (Task 5) are mutually independent and can run concurrently.
- M3 (Task 3) has a SOFT dependency on M2 (Task 2): the RISK_REGISTER row and the fanout anchor both reference the upstream FR URL. Land M3 with the `TODO(iroh-gossip-admission-FR)` placeholder if the URL is not yet minted, and backfill.
- No task depends on Directions A/B/C, and none of them depend on this direction. Do not let A/B/C take a hard dependency on iroh; it remains a deferred Year-2 transport.
