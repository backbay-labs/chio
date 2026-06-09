# Agent I: Consistency And Artifact Naming Audit

Status: launch research refinement audit
Scope: `docs/superpowers/research/chio-launch`
Confidence: high for internal consistency and naming findings. Moderate for external standard freshness because this pass did not re-open public standards sources.

## Verdict

The package now has the right center of gravity: `indices/artifact-registry.md` and `architecture/09-integration-contracts.md` are the strongest source-of-truth documents. The main problem is that older raw drafts and one later Agent K review still use names that those source-of-truth files explicitly supersede. That creates a real launch risk because these are not just prose labels. The package treats schema IDs as verifier compatibility boundaries.

The second problem is gate drift. The gate index, roadmap, and Agent K fixture strategy do not yet agree on fixture count, risk coverage, or canonical CLI command spelling.

## Canonical Naming Recommendation

Use `indices/artifact-registry.md` as the canonical schema-ID registry for this research package. Its rules are explicit:

- Use `schema_id` for signed or verifier-facing artifacts.
- Use dot-separated domain groups and hyphenated artifact names.
- Do not use underscores in schema IDs.
- Add new signed artifacts to `spec/schemas/registry.json` before any verifier accepts them.
- Treat raw agent-draft names as source notes that are superseded by the registry.

One field-name decision still needs owner confirmation: the artifact registry says `schema_id`, while later execution audit text warns that existing signed-artifact registry language may use `schema`. Pick one JSON field name before implementation and update every fixture, schema example, and verifier report to match it.

Recommended canonical command namespace:

- `chio proof fixture list`
- `chio proof fixture generate <fixture-id> --out DIR`
- `chio proof collect --kind <kind> --artifact-dir DIR --out DIR`
- `chio proof verify <bundle-dir|bundle.tar.zst>`
- `chio proof explain <bundle-dir> --claim <claim-id>`
- `chio proof serve <bundle-dir>`
- `chio proof export <bundle-dir> --out FILE`
- `chio proof doctor`

Do not use `chio proof-room bundle` as the canonical command spelling. Treat `chio proof room` as a possible alias only if the CLI owner wants an alias.

Canonical product names:

- Transaction Passport
- Transaction Evidence Graph
- Commerce Order Context
- Swarm Task Graph
- Disclosure Capsule
- Signed Lineage Subgraph
- Public Web3 Settlement Proof Bundle
- Risk Comptroller Report
- Proof Room Bundle
- Agent Web Proof Envelope

## Findings

### P0 - Active refinement docs still use noncanonical schema IDs

Evidence:

- `indices/artifact-registry.md:14-18` defines the naming rules and says raw draft names are superseded by canonical names.
- `indices/artifact-registry.md:60-72` lists noncanonical names that should not be used in canonical plans.
- `agent-reviews/11-proof-room-fixture-strategy.md:42` uses `chio.transaction_passport.v1`.
- `agent-reviews/11-proof-room-fixture-strategy.md:279` uses `chio.proof_room_bundle.v1`.
- `agent-reviews/11-proof-room-fixture-strategy.md:508` again uses `chio.proof_room_bundle.v1`.
- `agent-drafts/03-swarm-authority-recursive-delegation.md:82` uses `chio.swarm_task_graph.v1`.
- `agent-drafts/03-swarm-authority-recursive-delegation.md:154` uses `chio.swarm_continuation_token.v1`.
- `agent-drafts/03-swarm-authority-recursive-delegation.md:237` uses `chio.swarm_join_receipt.v1`.
- `agent-drafts/03-swarm-authority-recursive-delegation.md:279` uses `chio.route_plan_receipt.v1`.

Impact:

The Agent K file is not merely a raw draft. It is a later fixture strategy document, so its schema names are likely to be copied into implementation. If those names reach schemas, fixtures, or tests, the verifier registry will fork between underscore IDs and canonical hyphen IDs.

Fix:

Replace active noncanonical names outside the registry's avoid list:

- `chio.transaction_passport.v1` -> `chio.transaction-passport.v1`
- `chio.proof_room_bundle.v1` -> `chio.proof-room.bundle.v1`
- `chio.swarm_task_graph.v1` -> `chio.swarm.task-graph.v1`
- `chio.swarm_continuation_token.v1` -> `chio.swarm.continuation-token.v1`
- `chio.swarm_join_receipt.v1` -> `chio.swarm.join-receipt.v1`
- `chio.route_plan_receipt.v1` -> `chio.swarm.route-plan-receipt.v1`

Also expand the registry's noncanonical-name list so it includes every drift name still present in raw drafts, not only the first subset.

### P0 - Proof Room fixture gates conflict and omit first-class risk coverage

Evidence:

- `indices/verification-gates.md:49-70` says the launch proof room should contain at least three fixtures, with risk comptroller evidence only conditional inside the recursive swarm fixture.
- `agent-reviews/11-proof-room-fixture-strategy.md:21-30` says the minimum public catalog has four staged fixtures and that fewer than four is insufficient.
- `INDEX.md:14` includes commerce, settlement, risk, and insurance context in the launch thesis.
- `INDEX.md:56` says risk and insurance claims must resolve through a risk comptroller report.
- `indices/verification-gates.md:15` defines a dedicated Risk gate.
- `agent-reviews/11-proof-room-fixture-strategy.md:343-429` defines eight exact gates but has no dedicated risk gate.
- `agent-reviews/11-proof-room-fixture-strategy.md:431-452` defines the negative fixture floor but has no risk negative such as unreconciled reserve, double consumption, stale reputation, missing coverage binding, or wrong payout settlement.
- `agent-reviews/12-risk-facility-capital-deepening.md:89` supplies the missing Proof Room risk fixture set.
- `agent-reviews/12-risk-facility-capital-deepening.md:159-170` supplies concrete risk launch gates, but Agent K's gate floor has not adopted them.

Impact:

The package can pass the Agent K gate suite while still failing the stated launch thesis for risk and insurance. That is not a harmless omission because risk is one of the five hard launch claims in the index.

Fix:

Make the fixture strategy canonical and explicit:

- Minimum public catalog should be four stages if Agent K is the intended update.
- Add a Risk Comptroller stage or add risk artifacts and risk negatives to the commerce stage.
- Add an exact Risk gate between Commerce and Recursive Delegation, or state that commerce cannot pass when risk claims are enabled unless `chio.risk.comptroller-report.v1` passes.
- Add risk negatives to the floor: double reserve consumption, missing coverage binding, stale reputation, wrong payout settlement, reserve adequacy below threshold, and unreconciled claim state.

### P1 - `schema` versus `schema_id` is not settled

Evidence:

- `indices/artifact-registry.md:14` says to use `schema_id` for signed or verifier-facing artifact identifiers.
- `plans/09-first-implementation-sprint.md:61` says minimal JSON schemas should require `schema_id`.
- `agent-reviews/11-proof-room-fixture-strategy.md:279` uses `schema: "chio.proof_room_bundle.v1"`.
- `agent-reviews/14-execution-slicing-tdd-audit.md:377-383` explicitly says the first implementation sprint must decide between `schema` and `schema_id`, and warns not to introduce `schema_id` unless the protocol chooses that field.

Impact:

This is distinct from the schema-ID spelling problem. Even with the right canonical ID string, fixtures and verifier code will diverge if some artifacts encode the field as `schema` and others encode it as `schema_id`.

Fix:

Make a single protocol-level decision before implementation. If the existing signed-artifact machinery already standardizes on `schema`, revise `indices/artifact-registry.md` and first-sprint examples. If launch chooses `schema_id`, revise Agent K's bundle layout and every fixture example to use `schema_id`.

### P1 - Risk deepening adds new artifact names that are not yet in the registry

Evidence:

- `indices/artifact-registry.md:49-53` currently canonically lists risk comptroller report, facility state report, coverage decision, claim case file, and capital adequacy report.
- `agent-reviews/12-risk-facility-capital-deepening.md:75` proposes a Facility passport.
- `agent-reviews/12-risk-facility-capital-deepening.md:79` proposes `chio.risk.actuarial-backtest-report.v1`.
- `agent-reviews/12-risk-facility-capital-deepening.md:83` proposes a claim appeal artifact.
- `agent-reviews/12-risk-facility-capital-deepening.md:85` proposes a sanction and reserve ledger.
- `agent-reviews/12-risk-facility-capital-deepening.md:87` proposes a portfolio reconciliation report.

Impact:

Agent L materially improves the risk story, but several of its artifacts are registry candidates. If they stay as prose names, risk implementation will repeat the same drift that the artifact registry is trying to prevent.

Fix:

Classify each Agent L artifact as one of:

- canonical schema ID to add to `indices/artifact-registry.md`;
- internal report section under an existing canonical artifact;
- future-scope name that must not appear in implementation plans yet.

At minimum, decide whether Facility passport, claim appeal, sanction/reserve ledger, portfolio reconciliation report, and actuarial backtest report are launch-scope schemas.

### P1 - Agent J challenges the core Transaction Passport naming decision

Evidence:

- `INDEX.md:46-47` says a Transaction Passport must be the signed root artifact and must bind a typed evidence graph.
- `INDEX.md:62` calls the signed Transaction Passport the missing launch feature.
- `indices/artifact-registry.md:24` canonically registers `chio.transaction-passport.v1`.
- `agent-reviews/10-codebase-alignment-audit.md:97-114` recommends treating the artifact as a composed proof package by default and says to rename "transaction passport" in the implementation plan to "transaction proof package" unless the product intentionally wants to reuse the passport term.

Impact:

This is a direct product and artifact-name conflict. The main package says Transaction Passport is the launch root. Agent J says that name may be wrong because the repo already has Agent Passport and proof-package machinery. If unresolved, implementers will split between `passport`, `proof package`, and `proof-room bundle` semantics.

Fix:

Make an owner-level decision and document it in `INDEX.md`, `indices/artifact-registry.md`, and `architecture/01-transaction-passport-system.md`:

- If the product name remains Transaction Passport, add a note distinguishing it from Agent Passport and explaining why it is not merely `chio.attest.proof-package.v1`.
- If Agent J's naming wins, rename the root artifact and registry row before implementation starts.

Do not let both names remain canonical.

### P1 - External standards source log conflicts with Agent M refresh

Evidence:

- `indices/external-standards-source-log.md:12` says the A2A current dev specification is the checked source.
- `agent-reviews/13-external-standards-refresh.md:15` says the latest official public A2A spec is Agent2Agent Protocol v0.3.0, not v1.0.0.
- `agent-reviews/13-external-standards-refresh.md:46-47` lists the v0.3.0 and latest A2A URLs as the official source entries.
- `indices/external-standards-source-log.md:15` says OpenAPI 3.1.1 describes API operations.
- `agent-reviews/13-external-standards-refresh.md:16` says the latest published OpenAPI version is 3.2.0, while Chio currently supports a narrower 3.0.x and 3.1.x story unless 3.2 fixtures are added.
- `agent-reviews/13-external-standards-refresh.md:51` lists OpenAPI 3.2.0, latest, and 3.1.1 source URLs.

Impact:

The package now has two standards logs with different freshness and version language. Launch copy will drift unless Agent M's refresh is either promoted into `indices/external-standards-source-log.md` or explicitly marked as a separate review pending incorporation.

Fix:

Promote Agent M's corrected table into `indices/external-standards-source-log.md` or add a cross-reference saying Agent M supersedes the earlier source log for A2A, OpenAPI, SLSA, SD-JWT, BBS, Sigstore, and ACP naming. Then update `plans/08-agent-web-proof-envelope-implementation.md` to require the source log and Agent M review to agree before launch wording ships.

### P1 - Transaction Passport schema IDs conflict inside the raw transaction draft

Evidence:

- `agent-drafts/01-transaction-passport-evidence-graph.md:44` names `chio.transaction-passport.v1` and `chio.transaction-proof-package.v1`.
- `agent-drafts/01-transaction-passport-evidence-graph.md:74` names `chio.transaction.passport.v1`.
- `agent-drafts/01-transaction-passport-evidence-graph.md:89` names `chio.transaction.evidence-graph.v1`.
- `agent-drafts/01-transaction-passport-evidence-graph.md:127` names `chio.transaction.proof-package.v1`.
- `indices/artifact-registry.md:24-28` canonically names `chio.transaction-passport.v1`, `chio.transaction.evidence-graph.v1`, `chio.transaction.claim-set.v1`, `chio.transaction.verifier-policy.v1`, and `chio.transaction.verifier-report.v1`.

Impact:

The draft alternates between `transaction-passport` and `transaction.passport`, and between `transaction-proof-package` and `transaction.proof-package`. The canonical registry does not include a proof-package schema ID at all. That is a direct path to duplicate schema work.

Fix:

Mark the raw draft section as superseded by `indices/artifact-registry.md`, or normalize the raw draft to the canonical transaction family. If a package manifest is still needed, decide whether it is `chio.proof-room.bundle.v1`, a transaction-local manifest, or just a bundle layout inside the Proof Room artifact. Do not leave two transaction proof-package names in circulation.

### P1 - Lineage and disclosure naming is split between draft and architecture

Evidence:

- `agent-drafts/04-lineage-disclosure-privacy.md:271` names `chio.lineage-subgraph-export.v1`.
- `agent-drafts/04-lineage-disclosure-privacy.md:389` names `chio.disclosure-leakage-ledger.v1`.
- `architecture/04-lineage-disclosure-system.md:106` names `chio.lineage.signed-subgraph.v1`.
- `architecture/04-lineage-disclosure-system.md:144` names `chio.disclosure.leakage-ledger.v1`.
- `indices/artifact-registry.md:40-44` makes the architecture names canonical.

Impact:

The draft names describe roughly the same concepts but with a different namespace. Implementation workers could create export-shaped artifacts while the architecture expects transaction-bound proof artifacts.

Fix:

Use:

- `chio.lineage.signed-subgraph.v1`
- `chio.disclosure.leakage-ledger.v1`
- `chio.disclosure.capsule.v1`
- `chio.disclosure.verifier-privacy-profile.v1`

If the term "export" is still useful, keep it as a command or packaging operation, not as the schema ID.

### P1 - CLI command spelling is inconsistent

Evidence:

- `agent-drafts/07-proof-room-developer-experience.md:351-357` proposes `chio proof init`, `run`, `verify`, `explain`, `serve`, `export`, and `doctor`.
- `architecture/07-proof-room-system.md:17-21` lists `chio proof collect`, `verify`, `explain`, `room`, and `fixture`.
- `indices/source-map.md:149-152` lists `chio proof collect`, `verify`, `explain`, and `chio proof-room bundle`.
- `agent-reviews/11-proof-room-fixture-strategy.md:303-314` lists the richest and clearest command set under `chio proof`.
- `plans/00-roadmap.md:31` only names `chio proof collect` and `chio proof verify`.

Impact:

The package is converging on `chio proof`, but there are still three incompatible command idioms: `chio proof room`, `chio proof-room bundle`, and the richer Agent K subcommand layout. CLI spelling becomes documentation debt fast because examples, fixture gates, and tests will copy it.

Fix:

Make Agent K's `chio proof` namespace canonical, then update architecture, source map, and roadmap references. Keep the first sprint small, but do not leave separate public command names for the same action.

### P1 - Public settlement naming makes "passport" ambiguous

Evidence:

- `agent-drafts/05-public-runtime-settlement-passport-web3.md:1` is titled "Public Runtime Settlement Passport + Web3 Proof Architecture".
- `agent-drafts/05-public-runtime-settlement-passport-web3.md:181-189` defines `Web3SettlementProofBundle` with schema `chio.web3-settlement-proof-bundle.v1`, but also names the primary verifier `chio web3 settlement passport verify`.
- `architecture/05-public-settlement-passport-system.md:1` is titled "Public Runtime And Web3 Settlement Proof".
- `architecture/05-public-settlement-passport-system.md:11` says `chio.web3-settlement-proof-bundle.v1` is the launch artifact.
- `plans/05-public-settlement-passport-implementation.md:1` is titled "Public Settlement Proof Implementation Plan".

Impact:

"Settlement Passport" competes with the already central Transaction Passport. The actual canonical artifact is a proof bundle that attaches to the Transaction Passport, not a second passport root.

Fix:

Use "Public Web3 Settlement Proof Bundle" for the artifact and reserve "Transaction Passport" for the signed root. Rename command examples away from `settlement passport verify` unless a product owner intentionally wants a nested passport concept.

### P2 - Agent Web naming is mostly fixed but the raw draft title still points at the wrong source of truth

Evidence:

- `agent-drafts/08-external-standards-proof-envelope.md:1` is titled "External Standards Proof Envelope".
- `agent-drafts/08-external-standards-proof-envelope.md:39` promotes `Agent Web Proof Envelope`.
- `architecture/08-agent-web-proof-envelope-system.md:1` uses "Agent Web Proof Envelope And Standards Alignment".
- `architecture/08-agent-web-proof-envelope-system.md:30` names `chio.agent-web-proof-envelope.v1`.
- `indices/artifact-registry.md:56-58` names the Agent Web schema family.

Impact:

This is lower risk because the architecture and registry agree. The remaining issue is reader orientation: a worker starting from the draft title may use "external standards proof envelope" as the product name.

Fix:

Keep "External Standards" as the research topic and "Agent Web Proof Envelope" as the artifact. Add one sentence at the top of the raw draft saying the canonical artifact name is `Agent Web Proof Envelope`.

### P2 - The completion standard is stale after second-pass additions

Evidence:

- `INDEX.md:35` now lists `architecture/09-integration-contracts.md`.
- `INDEX.md:38-40` now lists the artifact registry, external standards source log, and risk register.
- `INDEX.md:42` now lists `plans/09-first-implementation-sprint.md`.
- `INDEX.md:72-77` still says completion requires eight architecture outlines, eight implementation plans, a source map, gate index, and roadmap.

Impact:

The index correctly acknowledges second-pass files, but the completion standard still describes the first-pass package. That makes future reviewers unsure whether the new registry, risk register, source log, integration contracts, sprint plan, and agent reviews are required or optional.

Fix:

Update the completion standard to distinguish:

- eight domain raw drafts;
- eight domain architecture outlines;
- eight domain build plans;
- cross-cutting architecture files;
- cross-cutting indices;
- first implementation sprint plan;
- agent review files.

### P2 - Registry implementation requirements are strong, but most domain plans do not point to them

Evidence:

- `indices/artifact-registry.md:76-83` requires schema files, registry entries, Rust constants or generated bindings, positive fixtures, negative unknown-schema fixtures, and fail-closed verifier behavior for every verifier-facing signed artifact.
- `architecture/09-integration-contracts.md:10-20` repeats the "registry before verifier" contract.
- `plans/01-transaction-passport-implementation.md:15-19` defines schemas and tests but does not explicitly point to the registry file or signed-artifact constant requirement.
- `plans/03-swarm-authority-implementation.md:15-18` says add schemas and canonical JSON rules but not registry entries or constants.
- `plans/05-public-settlement-passport-implementation.md:15-19` defines settlement artifacts but not registry entries or constants.
- `plans/08-agent-web-proof-envelope-implementation.md:30-33` defines envelope schemas but not registry entries or constants.

Impact:

The first sprint plan is strong, but the domain plans can still be executed as schema-only work. That weakens the fail-closed launch gate.

Fix:

Add a common "Registry acceptance" paragraph or checklist to every domain plan that creates a signed artifact, pointing to `indices/artifact-registry.md` and `architecture/09-integration-contracts.md`.

### P3 - The source log is indexed, but gate ownership is still implied

Evidence:

- `indices/external-standards-source-log.md:3-5` marks the log as refreshed on 2026-06-09 with high confidence for source URLs and naming.
- `indices/external-standards-source-log.md:43-51` requires re-opening the source set before public launch.
- `plans/08-agent-web-proof-envelope-implementation.md:15-22` requires taxonomy and copy lint.

Impact:

The pieces are present, but the owner path is implicit. The external source refresh could be missed unless the Agent Web plan explicitly names the source log as an input and output.

Fix:

In `plans/08-agent-web-proof-envelope-implementation.md`, make `indices/external-standards-source-log.md` the required source and required update target for the taxonomy phase.

## Prioritized Fix List

1. Fix noncanonical schema IDs in `agent-reviews/11-proof-room-fixture-strategy.md` and raw swarm draft references. This is the highest priority because it can poison implementation fixtures.
2. Resolve the `schema` versus `schema_id` field-name decision before any fixture or verifier work.
3. Resolve the fixture-count conflict by adopting the four-stage catalog or updating Agent K. Add risk coverage either as a fifth stage or as a required commerce-stage subgate.
4. Add Agent L's risk gate and risk negative fixture floor to Agent K's proof-room strategy.
5. Classify new Agent L risk artifacts into canonical registry entries, sections of existing artifacts, or future-scope names.
6. Resolve Agent J's Transaction Passport versus transaction proof package naming challenge.
7. Promote Agent M's external standards refresh into the source log or mark the source log as superseded.
8. Normalize the transaction draft schema IDs and decide whether a transaction proof package exists as a canonical schema or is folded into `chio.proof-room.bundle.v1`.
9. Normalize lineage and disclosure schema names to the registry names.
10. Freeze the public CLI spelling under `chio proof` and remove `chio proof-room bundle` from canonical docs.
11. Rename public settlement prose so the artifact is always the Public Web3 Settlement Proof Bundle and only the root artifact is called a Transaction Passport.
12. Update the completion standard in `INDEX.md` to include second-pass cross-cutting docs, first sprint plan, and agent reviews.
13. Add a registry acceptance paragraph to every domain implementation plan that creates a signed artifact.
14. Link the Agent Web plan explicitly to the external standards source log refresh gate.

## Checks Performed

- Listed all files under `docs/superpowers/research/chio-launch`.
- Reviewed `INDEX.md`, architecture files, indices, plans, raw drafts, and existing agent reviews, including Agent J, Agent K, Agent L, Agent M, and Agent N files present during validation.
- Searched for schema IDs with underscores and older dotted or hyphenated variants.
- Searched for bare `ACP` conflicts and command-name drift.
- Checked for non-ASCII characters and unresolved placeholder strings in the audited tree.

No non-ASCII characters were found in the audited tree during this pass.
