# Trajectory-3 CI Debt

The original trajectory-3 closeout admin-merged 62 PRs (#443-#504) without
waiting for hosted CI. Trajectory-3.1 establishes a single consolidated
replay anchor: the post-trajectory-3.1-close main HEAD will be subjected to
the full required-check suite (Build/lint/test, MSRV, cargo-vet, cargo-deny,
freeze-guard, bench-regression). When that run lands green, every PR below
is considered replayed-green via the consolidated main, because main now
contains the merge commit of every PR below.

## Consolidated replay anchor

- target_main_sha: TODO_TRJ3_1_CLOSE_SHA   (parent agent fills this in at trajectory-3.1 close)
- target_run_url:  TODO_TRJ3_1_CLOSE_RUN   (parent agent fills this in once CI greens on the close commit)
- replay_method:   consolidated-main-green-via-trajectory-3-1
- replay_rationale: |
  Per the trajectory-3.1 prompt strategy 2-3, "trigger workflows on main
  HEAD if main now contains all those merge commits; one green CI run on
  a recent main covers many PRs at once." Trajectory-3.1 chose the
  consolidated path because all 62 entries share the same gating
  workflow (CI), and main is monotonic across them.

## Replayed-via-consolidated-main entries

- PR #443 (`f0e777310446c67e238b4bac29b4bb35f418ceaf`): M08.P0 vendor-coordinate docs. Replayed via consolidated-main anchor (see above). Original-skip-reason: docs-only RFP, vendor dossier, handoff manifest, and outbound package log.
- PR #444 (`9c8f34aa7e5b532c755e43f5f493e89e58514482`): M09.P0 vendor-coordinate docs. Replayed via consolidated-main anchor (see above). Original-skip-reason: docs-only SSP, HITRUST scope boundary, assessor RFP, BAA pre-flight, and ticket stamps.
- PR #445 (`c1efd4c0e648ad1e31678045d86deda0447422de`): M03.P1 infra/docs. Replayed via consolidated-main anchor (see above). Original-skip-reason: CI liveness audit entries, billing runbook, workflow inventory matrix, and Linux-only PR-tier comment.
- PR #446 (`f2281a9671e7a0f7fd671cc4bc5dd11fc94daf1a`) (non-CI gate: Sidecar Image / admin override audit workflow): M03.P2 CI triage. Replayed via consolidated-main anchor (see above). Original-skip-reason: bypass catalog, Sidecar Image Dockerfile repair, escalation routing, admin override audit workflow, and ticket stamps.
- PR #447 (`17702d39218c1166992fdcf2c8bee9bbbcea69f3`) (non-CI gate: reproducible-build): M03.P3 reproducible-build pipeline. Replayed via consolidated-main anchor (see above). Original-skip-reason: release profile pins, Rust toolchain pin, reproducible-build workflow, hash gate, rebuild script, and ticket stamps.
- PR #448 (`0e3ac59cda7ca4ee14f34b32a9f726d96415b6f0`) (non-CI gate: checksum-index auto-PR): M03.P4 release evidence. Replayed via consolidated-main anchor (see above). Original-skip-reason: SLSA probe tag, checksum-index auto-PR workflow, checksum-index cosign signature, release evidence docs, and ticket stamps.
- PR #449 (`5dace08f614cb4827090042afb624409545f91a3`): M03.P5 stabilization ledger. Replayed via consolidated-main anchor (see above). Original-skip-reason: final v3.18 green replay, checksum-index publication, SLSA provenance asset, third-party rebuilder response, and ticket stamps.
- PR #450 (`22a2853ddbbcce8e775b4af1e8703c0fb12461ba`): M03.P0 audit baseline catch-up. Replayed via consolidated-main anchor (see above). Original-skip-reason: audit hard-count confirmation, billing runbook stamp, rebuilder lane stamp, reproducibility carve-out, and ticket stamps.
- PR #451 (`a2ac8e3d6baa1e17664af82d53445302c6484443`): M01.P0 healthcare pilot baseline. Replayed via consolidated-main anchor (see above). Original-skip-reason: audit hard counts, contract memo and BAA posture, onboarding plan, topology pin, PagerDuty contract memo, and ticket stamps.
- PR #452 (`e2fe51843f5b36149df18fe0ab0abe68236b959b`) (non-CI gate: heartbeat): M01.P1 operator runbook and PagerDuty wiring. Replayed via consolidated-main anchor (see above). Original-skip-reason: bounded profile, SLO, incident, PagerDuty override, rotation, heartbeat workflow, and ticket stamps.
- PR #453 (`24c3b87f93d75b455de37c4ef1da2c5c2143077d`): M01.P2 capacity and onboarding rehearsal. Replayed via consolidated-main anchor (see above). Original-skip-reason: capacity harness, shadow-capture script, capacity report, quota lane sizing, rehearsal log, and ticket stamps.
- PR #454 (`229373c07516eb1281e05236d625b493c78b737d`) (non-CI gate: schema-linter): M01.P3 audit-log schema and PHI policy. Replayed via consolidated-main anchor (see above). Original-skip-reason: export schema v1, CEF emitter and golden test, PHI policy, schema-linter workflow, schema-negotiation receipt, and ticket stamps.
- PR #455 (`e16bd39821e80ec40a9439301a66d2f1bdfde201`): M01.P4 observation evidence. Replayed via consolidated-main anchor (see above). Original-skip-reason: weekly incident reviews, PHI-leak audit rows, 30-day incident rollup, bounded-profile-hold attestation, and ticket stamps.
- PR #456 (`39cdbe176462e4c64525395148294de5a9ad9bd3`): M01.P5 milestone closure. Replayed via consolidated-main anchor (see above). Original-skip-reason: audit-handoff freeze open, ops sign-off memo, runbook URL, schema v1 path, success criteria closure, and ticket stamps.
- PR #457 (`b1e519ca1d92be40fc6dd74eaf2734227dfad1ea`): M02.P0 AI-lab partner baseline. Replayed via consolidated-main anchor (see above). Original-skip-reason: audit baseline, partner scoping, outreach receipts, METR contract, eval-receipt placeholder crate, and ticket stamps.
- PR #458 (`6320d07faa72f3fbd06135a93e2ed6d11a6f9485`): M02.P1 partner commitment package. Replayed via consolidated-main anchor (see above). Original-skip-reason: partner identity docs, METR Q&A, bundle sketch, partnership-note draft, and ticket stamps.
- PR #459 (`10f5064e55ba0fc74b6b40bd665299da5f5200d4`): M02.P2 evidence-export contract. Replayed via consolidated-main anchor (see above). Original-skip-reason: export contract docs, unsigned bundle helper, export roundtrip fixtures, audit mapping link, and ticket stamps.
- PR #460 (`b0bc369667625998b03a5022f6b44cc472978c3d`) (non-CI gate: schema-lint): M02.P3 eval-report bundle implementation. Replayed via consolidated-main anchor (see above). Original-skip-reason: schema, verifier CLI, PyO3 binding, golden vector regen, schema-lint workflow, and ticket stamps.
- PR #461 (`029479b291c4b8eeeec38952cb28ab33a6bab4ce`): M02.P4 partner integration spike. Replayed via consolidated-main anchor (see above). Original-skip-reason: METR ingest sample, partner feedback audit docs, optional partner_review schema/verifier checks, and ticket stamps.
- PR #462 (`64ef66b63c7b40cd92b721086000430a711a90b4`): M02.P5 conformance memo closeout. Replayed via consolidated-main anchor (see above). Original-skip-reason: memo verifier CLI, signed METR memo artifacts, audit closure, README partnership note, and ticket stamps.
- PR #463 (`5e9c65126422fea5306cd41e38d0413b15fa44fd`) (non-CI gate: mutants): M04.P0 mutation baseline audit. Replayed via consolidated-main anchor (see above). Original-skip-reason: mutation-gate audit baseline, trajectory-3 mutants-baseline.toml, and ticket stamps.
- PR #464 (`581a09519b7d0d9ecdc2f6e7d37083b570fc2bbd`): M04.P1 mutation survivor sweep tests. Replayed via consolidated-main anchor (see above). Original-skip-reason: credentials, kernel-core, attest-verify, policy, guards, anchor mutation-gap tests, audit evidence, and ticket stamps.
- PR #465 (`01b75ee4df744b34c4375e2581d4c15bc284837f`): M04.P2 verdict-matrix Python and Go driver activation. Replayed via consolidated-main anchor (see above). Original-skip-reason: driver status flips, 48-scenario Python and Go local semantic emitters, conformance schema-map repair, audit evidence, and ticket stamps.
- PR #466 (`58b6fd9872d08c9d3c5775c762f5756025b4a44f`) (non-CI gate: mutants): M04.P3 mutation lane honest-floor gate flip. Replayed via consolidated-main anchor (see above). Original-skip-reason: release-state activation, mutants gate threshold enforcement, rollback override dry-run, audit evidence, and ticket stamps.
- PR #467 (`d4e89385aeaaaf24e04238faa7e0864a0c07083d`) (non-CI gate: verdict-matrix required driver): M04.P4 verdict-matrix Python and Go required driver flip. Replayed via consolidated-main anchor (see above). Original-skip-reason: required workflow job, docs required-driver list, audit evidence, and ticket stamps.
- PR #468 (`98a23dcff8db4a7d3de87750275af4106975f12e`) (non-CI gate: mutants): M04.P5 mutation gate audit closeout. Replayed via consolidated-main anchor (see above). Original-skip-reason: audit closure, post-flip mutants baseline, committed run-capture JSON evidence, and ticket stamps.
- PR #469 (`6f7bc8b63189fa7065f9b03a80c8d6918fe0dd6f`): M05.P0 threat coverage baseline and freeze path reconciliation. Replayed via consolidated-main anchor (see above). Original-skip-reason: audit baseline, coverage.yaml/JSON reconciliation, freeze amendment, and ticket stamps.
- PR #470 (`bb942d5bedf91591a02c68b268c72bdc529b2716`): M05.P1 weights_hash_spoof coverage closure. Replayed via consolidated-main anchor (see above). Original-skip-reason: loaded-weight digest contract, adapter availability surfaces, threat conformance body, coverage flips, and ticket stamps.
- PR #471 (`6bc2b0992bdeeae5514712cd7c0e880c39d8e9d2`): M05.P2 dispatch_allow real-check closure. Replayed via consolidated-main anchor (see above). Original-skip-reason: kernel benchmark fixture, reference-runner contract, production allow dispatch Criterion body, ticket stamps, and local smoke evidence.
- PR #472 (`82b3472c9ace0fee90e4d0dc4f72ffd599a3fd5f`): M05.P3 dispatch_allow_dhat placeholder eviction. Replayed via consolidated-main anchor (see above). Original-skip-reason: real allow dispatch allocation probe, nonzero dhat budgets, audit measurement table, ticket stamp, and local smoke evidence.
- PR #473 (`58dc936f61715026e85079dfcf13b0c324047f8b`): M05.P4 coverage gate flip. Replayed via consolidated-main anchor (see above). Original-skip-reason: fail-closed threat coverage script, state-matrix shell test, threat model schema update, advisory deferrals, and conformance threat bodies.
- PR #474 (`8e2c515621ade9286b0ddda7c4a9039cc72089ec`): M05.P5 closeout and M08 handoff. Replayed via consolidated-main anchor (see above). Original-skip-reason: regenerated threat coverage docs, zero-partial audit closeout, post-flip workflow URL capture, and ticket stamps.
- PR #475 (`53c0fca5471778c769a8eec59185e624b68b0e19`): W1 closeout checkpoint. Replayed via consolidated-main anchor (see above). Original-skip-reason: regenerated trajectory-3 manifest, execution-state W2 advancement, and M02.P4 stamp correction.
- PR #476 (`f6a9786129ded9c89fa9576930ec16984210f4b3`): M10.P0 APN pre-roll. Replayed via consolidated-main anchor (see above). Original-skip-reason: Bedrock MCP audit opening, APN packet record, MCP conformance pin, execution-state update, manifest regeneration, and ticket stamps.
- PR #477 (`fb38169ab88125386dce4146ece923ea82c308e3`): M06.P0 formal and supply-chain audit baseline. Replayed via consolidated-main anchor (see above). Original-skip-reason: audit hard-count drift record, top-50 dependency centrality, contractor fallback scoping, cargo-audit baseline, manifest regeneration, and ticket stamps.
- PR #478 (`5413a0814ec0446b529779ce409fdcf0ade62f70`) (non-CI gate: apalache-nightly): M06.P1 Apalache kernel-state subset. Replayed via consolidated-main anchor (see above). Original-skip-reason: Common.tla bounds, four typed invariant specs/configs, apalache-nightly workflow, formal mapping rows, manifest regeneration, and ticket stamps.
- PR #479 (`54b24b2d450b65f59ae3ff23374b363b849959d2`) (non-CI gate: cargo-vet standalone): M06.P2 cargo-vet config and workspace import audit. Replayed via consolidated-main anchor (see above). Original-skip-reason: expanded vet certifications, exemption reduction, standalone cargo-vet workflow, audit sign-off, manifest regeneration, and ticket stamps.
- PR #480 (`2293da4727a759abe62da0d7bbe5cb889c34790f`) (non-CI gate: SBOM): M06.P3 SBOM generation pipeline and per-release publication. Replayed via consolidated-main anchor (see above). Original-skip-reason: standalone SBOM workflow, Syft source-scan config, cosign SBOM signing, HITRUST assessor handoff, manifest regeneration, and ticket stamps.
- PR #481 (`7db78b1aa95a0a4d7848e337ab2a9f74edd73f85`) (non-CI gate: CVE-alert / osv-scanner): M06.P4 CVE-alert workflow. Replayed via consolidated-main anchor (see above). Original-skip-reason: cargo-audit and osv-scanner monitor, GitHub Issue routing, deny.toml advisory refresh, Wasmtime lockfile bump, CVE monitor sign-off, manifest regeneration, and ticket stamps.
- PR #482 (`b1b41bb26d1e400c161d255ca74cb9c3918c981f`) (non-CI gate: apalache-nightly): M06.P5 Apalache contractor sign-off and audit closure. Replayed via consolidated-main anchor (see above). Original-skip-reason: apalache-nightly replay, 7 consecutive nightly evidence, formal audit closeout, assumption discharge update, M06 complete state, manifest regeneration, and ticket stamps.
- PR #483 (`26bf959a121075fe4994292e677ebac9f2d4ab5a`): M07.P0 mobile kernel inventory and audit baseline. Replayed via consolidated-main anchor (see above). Original-skip-reason: mobile qualification replay, binding preview docs, mobile threat-model row additions, manifest regeneration, and ticket stamps.
- PR #484 (`c5b1f640e45ce3254b0456bc806d9e4c6490d6f6`): M07.P1 mobile kernel seven-entry C-ABI surface. Replayed via consolidated-main anchor (see above). Original-skip-reason: App Attest, Play Integrity, mobile receipt shells, cross-FFI parity corpus, binding docs, and ticket stamps.
- PR #485 (`f97c1249c3e206deb26ae928fd33a25db1e6cf7a`): M07.P2 iOS Swift framework and App Attest lane. Replayed via consolidated-main anchor (see above). Original-skip-reason: SPM scaffold, iOS framework script, Swift App Attest and Secure Enclave helpers, custody App Attest verifier, XCTest harness, audit evidence, and ticket stamps.
- PR #486 (`f9fc4cdabf882e38a62e8ae16f0f4ac823d805df`): M07.P3 Android Kotlin AAR and Play Integrity lane. Replayed via consolidated-main anchor (see above). Original-skip-reason: Gradle scaffold, Android AAR script, Play Integrity and Keystore wrappers, custody Play Integrity verifier, instrumentation harness, audit evidence, and ticket stamps.
- PR #487 (`98994ac7c0c77bf83ca323ca95e713eb50d3f836`): M07.P4 mobile receipt oracle queue and round trip. Replayed via consolidated-main anchor (see above). Original-skip-reason: iOS Keychain queue, Android EncryptedSharedPreferences queue, receipt poster retry policy, mobile error URNs, M01 hosted-oracle fixtures, oracle round-trip test, audit evidence, and ticket stamps.
- PR #488 (`57758ee2f8cb5f1a0abb96aa8c1e34f253d9019a`): M07.P5 mobile MVP patient-app demo closeout. Replayed via consolidated-main anchor (see above). Original-skip-reason: Expo Module bridge package, Expo config plugin, restricted design-partner demo evidence, mobile threat coverage flips, audit closeout, and ticket stamps.
- PR #489 (`3d73fa539de055ce3ef370b7dc99401a8fa0dadf`): M10.P1 Bedrock integration package. Replayed via consolidated-main anchor (see above). Original-skip-reason: AWS listing scaffold, Python SDK, Marketplace entitlement and metering crate, region pin, data-flow diagrams, manifest regeneration, and ticket stamps.
- PR #490 (`575b804d85581c5c04d19970dcf39fad28f4f8e2`): M10.P2 MCP adapter conformance package. Replayed via consolidated-main anchor (see above). Original-skip-reason: Streamable HTTP transport, OAuth PKCE and RFC9728 PRM helpers, pinned conformance harness, registry record, AgentCore Gateway fixture, manifest regeneration, and ticket stamps.
- PR #491 (`ac22222125578760f4cf3f394f89ecf78bb800a3`): M10.P3 Marketplace listing artifact submission. Replayed via consolidated-main anchor (see above). Original-skip-reason: customer README, SAM-validated Quick Launch template, IAM customer attach policy, pricing dimensions, support SLA, security-review architecture, EULA and terms, manifest regeneration, and ticket stamps.
- PR #492 (`65e40dc769e90c03211a1d70e607e7e2ac3e52ac`): M10.P4 Reviewer round-trips and listing approval. Replayed via consolidated-main anchor (see above). Original-skip-reason: reviewer log, round-trip resolution record, marketing category submission, listing approval audit attestation, post-listing smoke test, manifest regeneration, and ticket stamps.
- PR #493 (`3ae362f62fbd7c943efe5ec9785dc41e93c02ac4`): M10.P5 MCP conformance entry and APN blog draft. Replayed via consolidated-main anchor (see above). Original-skip-reason: MCP registry publication record, publication conformance pin, APN blog package, audit closeout, execution-state W2/W3 closeout, manifest regeneration, and ticket stamps.
- PR #494 (`7df993e88ee154d8bd69c8b79e5f0c8bc3db8b64`): M08.P1 Vendor booking and scoping addenda. Replayed via consolidated-main anchor (see above). Original-skip-reason: vendor onboarding record, scoping-question responses, SOW addenda, vendor selection record, M04 and M05 handoff addenda, cemented-surface freeze attestation, manifest regeneration, and ticket stamps.
- PR #495 (`8242caa404548c0384417dac12e882b912c92750`): M08.P2 Active review first half. Replayed via consolidated-main anchor (see above). Original-skip-reason: active-review question responses, mid-P2 status memo, P2 open review-surface count pin, manifest regeneration, and ticket stamps.
- PR #496 (`313035368f77331eac753dc833d1bbeed818dc99`): M08.P3 Active review second half and preliminary findings. Replayed via consolidated-main anchor (see above). Original-skip-reason: reviewer question responses, preliminary findings memo, halt-15 template, cross-milestone notifications, manifest regeneration, and ticket stamps.
- PR #497 (`a893bc9097f96695c7c3ab4a48c8bded94acb547`): M08.P4 Remediation and vendor signoff. Replayed via consolidated-main anchor (see above). Original-skip-reason: exporter projection wording remediation, vendor sign-off receipt, mid-remediation checkpoint, remediation-log compile, manifest regeneration, and ticket stamps.
- PR #498 (`160bb52776df84a58750483ea008d639dcb13bc3`): M08.P5 Final report closeout. Replayed via consolidated-main anchor (see above). Original-skip-reason: draft review, final report PDF and hash, releases.toml audit evidence, closure attestations, Chio response memo, M08 execution-state closeout, manifest regeneration, and ticket stamps.
- PR #499 (`e27b83aa69172c46f51280d930aa7652811bbe0f`): M09.P1 HITRUST gap assessment. Replayed via consolidated-main anchor (see above). Original-skip-reason: MyCSF portal provisioning, readiness questionnaire, control narratives, assessor walkthrough notes, inherited evidence inventory, gap report intake, manifest regeneration, execution-state update, and ticket stamps.
- PR #500 (`0b3b140d6781884d8efbf8fac9c8de4467268c38`): M09.P2 HITRUST remediation work. Replayed via consolidated-main anchor (see above). Original-skip-reason: control mapping cleanup, access-review policy, key-rotation policy, incident response runbook, AWS encryption pointer, evidence-pack script, formal bridge, de-identification policy, remediation audit log, manifest regeneration, execution-state update, and ticket stamps.
- PR #501 (`0e9db9264010338c1ffe7c7a6b97e59d7f9c39fd`): M09.P3 HITRUST evidence package finalization. Replayed via consolidated-main anchor (see above). Original-skip-reason: M06 SBOM prerequisite confirmation, M01 BOP sample manifest, dated evidence bundle generation, MyCSF upload receipt, package completeness confirmation, P4 start date, evidence pointer updates, bundle-script idempotency fix, manifest regeneration, execution-state update, and ticket stamps.
- PR #502 (`13ced1b94a2ef2c7ac0f46c5aed3b795a15cfa20`): M09.P4 HITRUST assessor engagement. Replayed via consolidated-main anchor (see above). Original-skip-reason: sample testing, operator interviews, week 25/27/28/30/31 follow-up evidence windows, draft report intake, clarification log, P4 audit closeout, path-stable evidence bundle hash update, manifest regeneration, execution-state update, and ticket stamps.
- PR #503 (`7831e382d493e7e9e01c75c372cd6bf76d36eb9b`): M09.P5 HITRUST certificate issuance and audit closure. Replayed via consolidated-main anchor (see above). Original-skip-reason: final report submission, HITRUST QA pass, certificate record, renewal trigger, public landing page, releases.toml activation evidence, M09 complete execution-state update, vendor-lanes closeout, manifest regeneration, and ticket stamps.
- PR #504 (`6e3cad9dc94d58cffb508841dd2b73b54e6ebc16`): trajectory-3 closeout blocker reconciliation. Replayed via consolidated-main anchor (see above). Original-skip-reason: stale audit-placeholder cleanup, late M08/M09 vendor P0 ticket stamp reconciliation, manifest regeneration, closeout blocker file, M10 public live recheck evidence, execution-state closeout_blocked update, and cargo build smoke.

## Trajectory-3.1 wave PRs

The trajectory-3.1 wave PRs (#509-#518) auto-merged before branch protection
was tightened on 2026-05-03. The consolidated-main green retroactively
anchors these too, since main contains every one of their merge commits and
the same CI suite gates them.

- PR #509: trajectory-3.1 wave entry. Replayed via consolidated-main anchor (see above). Original-skip-reason: auto-merged before 2026-05-03 branch protection tightening.
- PR #510: trajectory-3.1 wave entry. Replayed via consolidated-main anchor (see above). Original-skip-reason: auto-merged before 2026-05-03 branch protection tightening.
- PR #511: trajectory-3.1 wave entry. Replayed via consolidated-main anchor (see above). Original-skip-reason: auto-merged before 2026-05-03 branch protection tightening.
- PR #512: trajectory-3.1 wave entry. Replayed via consolidated-main anchor (see above). Original-skip-reason: auto-merged before 2026-05-03 branch protection tightening.
- PR #513: trajectory-3.1 wave entry. Replayed via consolidated-main anchor (see above). Original-skip-reason: auto-merged before 2026-05-03 branch protection tightening.
- PR #514: trajectory-3.1 wave entry. Replayed via consolidated-main anchor (see above). Original-skip-reason: auto-merged before 2026-05-03 branch protection tightening.
- PR #515: trajectory-3.1 wave entry. Replayed via consolidated-main anchor (see above). Original-skip-reason: auto-merged before 2026-05-03 branch protection tightening.
- PR #516: trajectory-3.1 wave entry. Replayed via consolidated-main anchor (see above). Original-skip-reason: auto-merged before 2026-05-03 branch protection tightening.
- PR #517: trajectory-3.1 wave entry. Replayed via consolidated-main anchor (see above). Original-skip-reason: auto-merged before 2026-05-03 branch protection tightening.
- PR #518: trajectory-3.1 wave entry. Replayed via consolidated-main anchor (see above). Original-skip-reason: auto-merged before 2026-05-03 branch protection tightening.

## Non-CI-gated entries

The following entries reference workflows OTHER than the standard CI suite
(Build/lint/test, MSRV, cargo-vet, cargo-deny, freeze-guard, bench-regression).
Their gating workflow is NOT exercised by the consolidated-main CI run, so
they require individual replay or trajectory-4 deferral. Status:
`requires-individual-replay-or-deferral`. Trajectory-3.1's workflow
restoration phase (Phase 2) or trajectory-4 should pick these up.

- PR #446 (non-CI gate: Sidecar Image / admin override audit workflow): M03.P2 CI triage. Status: requires-individual-replay-or-deferral.
- PR #447 (non-CI gate: reproducible-build): M03.P3 reproducible-build pipeline. Status: requires-individual-replay-or-deferral.
- PR #448 (non-CI gate: checksum-index auto-PR): M03.P4 release evidence. Status: requires-individual-replay-or-deferral.
- PR #452 (non-CI gate: heartbeat): M01.P1 operator runbook and PagerDuty wiring. Status: requires-individual-replay-or-deferral.
- PR #454 (non-CI gate: schema-linter): M01.P3 audit-log schema and PHI policy. Status: requires-individual-replay-or-deferral.
- PR #460 (non-CI gate: schema-lint): M02.P3 eval-report bundle implementation. Status: requires-individual-replay-or-deferral.
- PR #463 (non-CI gate: mutants): M04.P0 mutation baseline audit. Status: requires-individual-replay-or-deferral.
- PR #466 (non-CI gate: mutants): M04.P3 mutation lane honest-floor gate flip. Status: requires-individual-replay-or-deferral.
- PR #467 (non-CI gate: verdict-matrix required driver): M04.P4 verdict-matrix Python and Go required driver flip. Status: requires-individual-replay-or-deferral.
- PR #468 (non-CI gate: mutants): M04.P5 mutation gate audit closeout. Status: requires-individual-replay-or-deferral.
- PR #478 (non-CI gate: apalache-nightly): M06.P1 Apalache kernel-state subset. Status: requires-individual-replay-or-deferral.
- PR #479 (non-CI gate: cargo-vet standalone): M06.P2 cargo-vet config and workspace import audit. Status: requires-individual-replay-or-deferral.
- PR #480 (non-CI gate: SBOM): M06.P3 SBOM generation pipeline and per-release publication. Status: requires-individual-replay-or-deferral.
- PR #481 (non-CI gate: CVE-alert / osv-scanner): M06.P4 CVE-alert workflow. Status: requires-individual-replay-or-deferral.
- PR #482 (non-CI gate: apalache-nightly): M06.P5 Apalache contractor sign-off and audit closure. Status: requires-individual-replay-or-deferral.
