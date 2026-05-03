# Milestone 02: AI-Lab Evaluation Infrastructure Beachhead

> **Trajectory-3.1 disclaimer (2026-05-03):** No real partner cryptographic
> attestation has been received. The signature scheme `synthetic-test-sample`
> (formerly `cosign-github-oidc-test`) used by the M02 conformance memo is a
> self-generated SHA-256 test sample, not a vendor-issued cosign or
> GitHub-OIDC signature. Real partner-issued cryptographic attestation is
> deferred to trajectory-4 (M02-followup). Sigstore / cosign / OIDC
> references in the body below describe the original M02 trajectory-3 plan.

## Lens

Adoption / protocol. M02 is the second customer-anchor milestone of
trajectory-3. The dominant lens is adoption (an external AI-lab
customer that consumes Chio receipts) crossed with protocol (the
receipt format must be admissible in the partner's published eval
cards). The work is partner-grade infrastructure: an eval-report
receipt envelope, a reference verifier, an integration sample, and a
partner-signed conformance memo. New substrate is minimal; new
partner-facing surface is what ships.

Trust-boundary: yes.

## Why this is on the trajectory

**Release-gate anchor:** PROTOCOL.

The verdict's per-milestone block names AI-lab evaluations as the
second load-bearing customer because the substrate they need
(deterministic verdict receipts, signed kernel-anchored evidence,
batch-verifiable bundles for eval cards) is exactly what trajectory-2
shipped at the wire layer and exactly what no published evaluation
artifact today consumes. The trajectory-2 closeout
(`.planning/audits/M02-mutation-and-verdict-matrix.md`) records that
the verdict-matrix corpus is hash-pinned, the Rust kernel driver is
`active` at 48/48 passing, and the cross-language drivers ship at
`partial-capability` or `unsupported`. Trajectory-3 inherits that
substrate: M04 closes the cross-language driver promotion under the
`m02-m04-verdict-matrix-coupling` freeze; M02 here ships the
partner-facing artifacts that wrap the existing receipt body in a
form an AI-lab evaluations team can ingest into their published eval
cards.

The customer is named explicitly: one of Anthropic evaluations team,
METR, or Apollo Research, contracted by end of week 1 per D10. The
release gate fires when a partner-signed conformance memo lands in the
audit doc within 7 days of P5 close (D15 freshness rule).

The trajectory-2 artifacts that create the precondition for M02 are:

- The hash-pinned verdict-matrix corpus at
  `crates/chio-conformance/verdict_matrix/` (48 scenarios, sha256
  `47e8d5394c807196d9567d97515e786cb1abfb0c7676e54db269ca82c735422f`).
- The receipt body schema at
  `spec/schemas/chio-wire/v1/receipt/record.schema.json` and the
  inclusion-proof schema at
  `spec/schemas/chio-wire/v1/receipt/inclusion-proof.schema.json`.
- The Rust-kernel driver at
  `crates/chio-conformance/verdict_matrix/drivers/rust/` shipped
  `active` (48/48 passing) and is the canonical source of receipts
  that M02 wraps in bundles.
- Trajectory-2 M02 P5.T6 hash-pinned the scenario manifest; M02 here
  consumes that manifest read-only.

What M02 deliberately does NOT attack:

- Cross-language driver promotion (Python `partial-capability ->
  passing`, Go `unsupported -> passing`). M04 owns that promotion
  per the `m02-m04-verdict-matrix-coupling` freeze. The freeze
  rationale references those drivers because the manifest under
  `crates/chio-conformance/verdict_matrix/` is shared between M02
  reads (bundles cite the corpus sha) and M04 edits (driver state
  flips). Serializing the two milestones is what the freeze enforces.

## Prior-art reckoning

Trajectory-2 already shipped, in scope of M02:

- **Verdict-matrix harness at `crates/chio-conformance/verdict_matrix/`.**
  Scenario format spec at `verdict_matrix/SCENARIOS.md`,
  hash-pinned `manifest.toml`, four scenario categories
  (`capability_subset`, `revocation_propagation`, `replay_verdict`,
  `redaction_determinism`), five drivers (Rust active; Python and
  WASM partial; Go unsupported; TypeScript transport-client). M02
  consumes this read-only.
- **Receipt format under `spec/schemas/chio-wire/v1/receipt/`.**
  Record schema, inclusion-proof schema, READMEs. The receipt body
  signature covers the canonical body bytes per RFC 8785 (per
  trajectory-1 M01 canonical-JSON work). M02 does not propose any
  edit to the inner receipt body byte layout.
- **Provider-conformance fixtures at
  `crates/chio-provider-conformance/fixtures/{anthropic,bedrock,openai}/`.**
  Soft-dep substrate; M02 does not require these but the partner
  integration spike at P4 may exercise scenarios that exercise
  provider-specific edges.
- **Trajectory-2 M02 audit doc** at
  `.planning/audits/M02-mutation-and-verdict-matrix.md` recording
  driver inventory and the corpus hash.

What M02 changes (additive only):

- New wire-adjacent surface: `spec/eval/receipt-format.v1.json` (a
  new directory under `spec/`, separate from `spec/schemas/`). This
  is a new schema published as a sibling to the existing wire schemas,
  not an edit to the wire path.
- New crate: `crates/chio-eval-receipt/` reference verifier (Rust
  primary; Python binding under `crates/chio-eval-receipt/py/`).
- New tests/bindings vector: `tests/bindings/vectors/eval/v1.json`
  (golden bundle fixture, mirroring the existing `receipt/v1.json`
  pattern).
- New examples directory: `examples/eval-receipt-ingest/<partner-slug>/`
  with the integration sample.
- New audit-doc entries under
  `.planning/trajectory-3/audits/M02-ai-lab.md` and the partner-signed
  memo + signature files.

What M02 preserves:

- The hash-pinned verdict-matrix corpus and its manifest.
- The chio-wire receipt body schemas and their existing canonical-JSON
  signature surface.
- All five existing verdict-matrix drivers and their current statuses
  (M04 promotes them; M02 does not).
- The provider-conformance fixtures.

Customer named explicitly: one of Anthropic evaluations team, METR,
Apollo Research (D10; contracted by end of week 1). Vendor shortlist
dossiers are in `.planning/trajectory-3/research/m02/RESEARCH.md`
section "AI-lab partner candidate dossiers"; P0.T2 produces a 1-pager
recommendation at
`.planning/trajectory-3/research/m02/PARTNER-SCOPING.md`.

## Hard counts (measured 2026-04-30)

Reproduce these counts via the audit doc commands at
`.planning/trajectory-3/audits/M02-ai-lab.md` section 2.

- Verdict-matrix scenario count the eval-report bundle wraps: **48**.
- Verdict-matrix corpus sha256:
  **`47e8d5394c807196d9567d97515e786cb1abfb0c7676e54db269ca82c735422f`**.
- Verdict-matrix scenario categories: 4 (each at 12 scenarios:
  `capability_subset`, `revocation_propagation`, `replay_verdict`,
  `redaction_determinism`).
- Verdict-matrix non-Rust driver state today (M04 will move; M02
  records read-only): 1 `active` (Rust), 1 `partial-capability`
  (Python, 12/48), 1 `partial` (WASM browser, 12/48), 1
  `transport-client` (TypeScript node-http, 0/48 without sidecar),
  1 `unsupported-no-local-verdict-emitter` (Go, 0/48).
- Receipt body schema bytes: `spec/schemas/chio-wire/v1/receipt/record.schema.json`
  (size pinned by trajectory-2 M01).
- Eval-report receipt format files in repo today: 0 (M02 P3 ships
  the first).
- Reference-verifier crates in repo today: 0 (M02 P3 ships
  `crates/chio-eval-receipt/`).
- Partner shortlist members (D10): 3 (Anthropic evaluations team,
  METR, Apollo Research).
- Partner contracted in week 1: TBD; P0.T4 records.

## Workspace dependency state

M02 is mostly additive. Pinned by trajectory-2 and reused (do not
re-pin):

- `serde_json` (workspace pin) for the bundle deserializer.
- `sha2` (workspace pin) for hashing canonicalized payload.
- `ed25519-dalek` (workspace pin in chio-credentials) for one of the
  three signature options (the bundle supports ed25519, sigstore-cosign,
  and minisign per format spec; ed25519 is the offline-friendly
  default).

New pins introduced by M02 (lock in P3 when the verifier crate lands;
re-check crates.io for then-current latest patch on Wave-1 open day):

- `serde_jcs` or equivalent RFC 8785 JSON Canonicalization Scheme
  implementation. Required because the bundle outer signature covers
  the bundle minus its `signatures` field under RFC 8785
  canonicalization. If `serde_jcs` is not the right pin, swap to
  `jcs-canonicalize` or implement a small wrapper around
  `serde_json::to_value` + ordered-key serialization. The pin lives
  in `crates/chio-eval-receipt/Cargo.toml`.
- (Python binding only) `pyo3` workspace pin if not already present.
  The binding is build-system-only; it does not affect the runtime
  Rust workspace dep tree.
- (Test-only) `cosign` v2.x as a CI tool dependency for the round-trip
  signature self-test. Pin in `.github/workflows/verdict-matrix.yml`
  (or the M02-specific `eval-receipt-bundle.yml` workflow if the lane
  is its own file). Cosign is invoked as a CLI; no Cargo dep.

External services M02 contracts with:

- **Sigstore Rekor / cosign OIDC** as the default partner-anchored
  signature path (D10 partner verifies via cosign + GitHub OIDC
  identity). PGP detached signatures stay as a fallback.
- **Partner-side ingest pipeline** (Inspect for Anthropic, vivaria
  for METR, Apollo's internal scoring pipeline). Integration spike
  at P4 produces a 50-100 line script that runs end-to-end inside the
  partner's pipeline language.

## Scope

### In

- New eval-report receipt format spec v1 at
  `spec/eval/receipt-format.v1.json` (schema id
  `chio.eval-report.bundle.v1`). RFC 8785 canonicalization on the
  bundle minus `signatures`; partner-anchored outer signature; inner
  Chio receipt bodies preserved byte-for-byte.
- Reference verifier at `crates/chio-eval-receipt/` (Rust crate +
  CLI `chio eval-receipt verify <bundle-path>`).
- Python binding at `crates/chio-eval-receipt/py/`
  (`chio-eval-receipt-py` published to PyPI under M02 release).
- Golden bundle fixture at `tests/bindings/vectors/eval/v1.json`,
  sha-pinned in the bundle manifest, regenerable via an `xtask` entry.
- Schema-linter integration: `cargo test -p chio-eval-receipt --test
  schema_lint` runs in CI.
- Evidence-export contract: a documented mapping between a
  `verdict_matrix` scenario run output and the bundle wrapping it
  (P2 lands the contract markdown plus a small Rust helper at
  `crates/chio-eval-receipt/src/export.rs`).
- Partner integration sample at
  `examples/eval-receipt-ingest/<partner-slug>/` with a Python or Go
  driver script depending on partner pipeline language.
- Partner-signed conformance memo at
  `.planning/trajectory-3/audits/M02-memo.md` plus
  `M02-memo.sig` (cosign) committed within 7 days of P5 close.
- Public partnership note: a markdown entry in the README or a
  blog post on the project site, cross-referenced from the audit doc.

### Out (and why)

- Cross-language driver promotion (Python `partial-capability ->
  passing` and Go `unsupported -> passing`). Owned by M04 per the
  `m02-m04-verdict-matrix-coupling` freeze. M02 does not edit
  `drivers/python/run_scenarios.py` or `drivers/go/run_scenarios.go`.
- JVM / dotnet / Lambda / k8s drivers (deferred per trajectory-2 D07
  consequences and trajectory-2 M07 P6).
- Multi-partner integration in week 1; one partner is M02 scope per
  D10 ("single named partner with no fallback" was rejected; the
  shortlist provides bench fallbacks but only one partner ships in
  M02).
- Sigstore Rekor transparency-log entries (DSSE / Rekor inclusion
  proofs). Considered but rejected for v1 of the bundle format;
  deferred to trajectory-4 as the DSSE v2 / Rekor inclusion-proof
  follow-up (the research doc notes DSSE as a v2 option per partner
  request).
- ISO 42001 mapping (D02 deferred to post-trajectory-3).
- New verdict-matrix scenarios. The bundle wraps the existing 48; new
  scenarios surface under M04 or M05 if at all.
- A separate hosted CI lane for the eval-receipt linter. M02 lane
  runs inside the existing verdict-matrix workflow; M03 owns hosted
  CI capacity.

## Phases

### P0: Audit baseline + partner shortlist scoping + week-1 contract

Stage the audit doc, produce the 1-pager partner-scoping memo from
the research dossiers, open three parallel outreach threads, contract
one partner by end of week 1.

- M02.P0.T1: Pin M02 audit doc P0 baseline (corpus sha, scenario
  count, driver inventory).
- M02.P0.T2: Author partner-scoping 1-pager at
  `.planning/trajectory-3/research/m02/PARTNER-SCOPING.md`.
- M02.P0.T3: Open three parallel outreach threads (Anthropic, METR,
  Apollo); record outreach receipts in the customer evidence log.
- M02.P0.T4: Contract one partner; record name, contract URL, and
  acceptance criteria.
- M02.P0.T5: Wave-opener PR: Cargo workspace stage for
  `crates/chio-eval-receipt/` placeholder + audit doc cross-references.

### P1: Partner pick committed + week-1 deadline tickets

Lock the partner identity into the milestone artifacts, draft the
acceptance-criteria Q&A with the partner, freeze the bundle format
sketch for partner sign-off so P3 spec implementation stays on a
stable target.

- M02.P1.T1: Commit the partner identity into the audit doc closure
  block and the README of `.planning/trajectory-3/tickets/M02/`.
- M02.P1.T2: Draft partner Q&A: signature scheme (cosign vs PGP),
  bundle-ingest pipeline language (Python vs Go), eval-card citation
  commitment window. Land partner-side replies into the audit
  evidence log.
- M02.P1.T3: Freeze a textual sketch of the bundle format under
  `.planning/trajectory-3/research/m02/BUNDLE-SKETCH.md` so the
  partner can pre-review while P3 implements.
- M02.P1.T4: Open the partnership-note draft PR (blog or README
  entry) with placeholders for the P5-filled URL and signed-memo
  hash. Keeps the partnership-note path warm.

### P2: Evidence-export contract

Specify how a verdict-matrix scenario run produces a bundle. Document
the field mapping from the scenario output (Rust kernel driver's
emitted receipt) to the outer envelope's `eval_run` block. Ship a
small Rust helper that performs the export.

- M02.P2.T1: Write the evidence-export contract markdown at
  `crates/chio-eval-receipt/EXPORT-CONTRACT.md` mapping verdict-matrix
  scenario output to bundle envelope fields.
- M02.P2.T2: Implement `crates/chio-eval-receipt/src/export.rs`: a
  function `export_scenario_run(receipts: &[Receipt], run_meta:
  EvalRunMeta) -> Bundle` that produces an unsigned bundle.
- M02.P2.T3: Unit-test the export against three trajectory-2 sample
  scenarios (one per `capability_subset`, `revocation_propagation`,
  `replay_verdict`).
- M02.P2.T4: Document the partner-side mapping (their pipeline
  output -> EvalRunMeta) in `EXPORT-CONTRACT.md` and link from the
  audit doc.

### P3: Eval-report receipt format implementation

Land the format spec, the verifier crate, the Python binding, the
golden vector, and the schema linter integration.

- M02.P3.T1: Draft `spec/eval/receipt-format.v1.json` schema
  (`chio.eval-report.bundle.v1`).
- M02.P3.T2: Implement `crates/chio-eval-receipt/src/lib.rs` with
  `verify_bundle(bundle_json) -> Result<VerifiedBundle, BundleError>`
  and the CLI binary at `crates/chio-eval-receipt/src/bin/cli.rs`.
- M02.P3.T3: Ship the Python binding at `crates/chio-eval-receipt/py/`
  with pyo3, a smoke test, and a publish-to-PyPI dry-run.
- M02.P3.T4: Generate and check in the golden bundle fixture at
  `tests/bindings/vectors/eval/v1.json` plus the regen script under
  `xtask/src/eval_receipt_regen.rs`.
- M02.P3.T5: Wire the schema linter into CI
  (`.github/workflows/verdict-matrix.yml` or a new
  `eval-receipt-bundle.yml`); make the lane required on PRs touching
  `spec/eval/**` or `crates/chio-eval-receipt/**`.

### P4: Partner integration spike + sample eval-report ingest

Build the partner-pipeline-language sample, run the spike inside the
partner's environment, capture feedback inside the D15 7-day window.

- M02.P4.T1: Ship `examples/eval-receipt-ingest/<partner-slug>/`
  with a 50-100 line script that runs three verdict-matrix scenarios
  end-to-end, packages output as a bundle, signs the bundle with a
  test cosign identity, and verifies the bundle round-trips.
- M02.P4.T2: Run the spike inside the partner pipeline (or with a
  partner engineer pair-running). Capture a green CI run URL that
  exercises the bundle path.
- M02.P4.T3: Record partner feedback in
  `.planning/trajectory-3/research/m02/PARTNER-INTEGRATION.md`
  (D15 7-day freshness window applies to each entry).
- M02.P4.T4: Apply non-breaking format edits if partner review
  surfaces gaps; bundle format is still pre-freeze until P5.

### P5: Partner-signed conformance memo received

Produce the draft memo, hand to partner, receive signed memo, fill
audit doc closure block, ship the partnership-note PR.

- M02.P5.T1: Draft 1-page partner-facing memo per the template in
  the research doc; hand to partner counterparty.
- M02.P5.T2: Receive signed memo + cosign signature; verify the
  signature locally (CI must round-trip green); commit at
  `.planning/trajectory-3/audits/M02-memo.md` plus
  `M02-memo.sig`.
- M02.P5.T3: Fill audit doc closure attestations; flip M02 status
  to `closed`.
- M02.P5.T4: Publish the partnership-note (blog or README entry);
  record URL in the audit doc.

## Cross-milestone interactions

Hard deps (other trajectory-3 milestones):

- **M03 hosted CI** (`.planning/trajectory-3/03-hosted-ci-truth-and-reproducible-builds.md`).
  M02's CI lane (P3.T5) registers a new required-check on PRs
  touching `spec/eval/**` or `crates/chio-eval-receipt/**`. M03
  ships hosted CI restoration; if M03 lags, M02 P3.T5 falls back to
  a stub workflow that runs locally and `xtask`-driven (the lane
  flips to required-CI once M03 closes).
- **M04 verdict-matrix promotion**
  (`.planning/trajectory-3/04-mutation-and-verdict-matrix-promotion.md`).
  Path overlap on `crates/chio-conformance/verdict_matrix/manifest.toml`
  is the basis for the `m02-m04-verdict-matrix-coupling` freeze in
  `.planning/trajectory-3/freezes.yml`. M02 reads the manifest's
  `corpus_sha256` and embeds it in bundle metadata; M04 edits driver
  state under the same manifest. The freeze sequences M02 P2-P3
  (manifest-reads) before M04.P3 (manifest-edits) opens, so
  trajectory-3 internals do not race against each other on the
  manifest.

Soft deps (cross-trajectory references as string sentences in
ticket files):

- "Trajectory-2 M02 P5.T6 hash-pinned the verdict-matrix scenario
  manifest at `crates/chio-conformance/verdict_matrix/manifest.toml`;
  M02 (trajectory-3) consumes the manifest read-only."
- "Trajectory-2 M01 RFC 8785 canonical-JSON vectors at
  `crates/chio-conformance/tests/vectors_oracle.rs` are the
  byte-equality net the bundle outer canonicalization relies on."
- "Trajectory-1 M07 provider-conformance fixtures under
  `crates/chio-provider-conformance/fixtures/{anthropic,bedrock,openai}/`
  feed the partner integration spike at P4 if the partner exercises
  provider-specific edges."

Downstream consumers in trajectory-3:

- **M04** consumes the M02 P3 spec as the format M04 promotes drivers
  to emit (driver promotion includes "the driver's emitted receipt
  bytes round-trip through the M02 verifier"). M04 does NOT modify
  the spec.
- **M08** independent crypto-protocol review
  (`.planning/trajectory-3/08-independent-crypto-protocol-review.md`)
  cites the M02 conformance memo as one of the external-reference
  inputs to M08's vendor scoping. The memo is a partner-attested
  statement that the inner receipt signature surface is admissible
  in published cards; M08 reviewer checks that statement against
  their own protocol review.
- **M09** HITRUST i1 assessment
  (`.planning/trajectory-3/09-hitrust-i1-assessment.md`) does not
  consume M02 directly; M02's evidence is partner-attested rather
  than control-mapped.

## Risks and mitigations

1. **All three D10 partners decline** (halt trigger 12). Mitigation:
   P0.T3 spawns three parallel outreach threads in week 1; halt-
   and-ping for the operator at end of week 2 if no contract. D10
   names the bench: substitute candidates per operator authorization
   (Redwood Research, ARC-Evals successor, Anthropic Frontier Red
   Team direct).

2. **Partner withdrawal mid-flight** (between P3 and P5; halt 12 fires).
   Mitigation: P4.T4 ticket carries a "memo-only fallback" branch.
   If withdrawal fires, the milestone ships the spec, the verifier,
   and the integration sample without a partner-signed memo; audit
   doc records the withdrawal cause in the customer evidence log;
   halt 12 triggers next-partner contracting in parallel with M04.
   The interim partner feedback captured in
   `PARTNER-INTEGRATION.md` survives into the audit doc as
   evidence of engagement attempted.

3. **Bundle format diverges from partner pipeline** (mid-P4 review).
   Mitigation: P1.T3 freezes a textual sketch of the bundle format
   for partner sign-off in week 2-3, giving the partner 4-5 weeks to
   flag divergences before P3 spec implementation freezes the JSON
   schema. P4.T4 leaves a non-breaking-edit window open until P5
   handoff.

4. **Partner publishes their eval card without crediting Chio.**
   Mitigation: the conformance memo template in the research doc
   carries explicit attribution language; the partnership-note PR
   cross-references the memo. Recovery: the audit doc still records
   the memo as evidence of conformance; public credit is a soft
   target, not a release-gate dependency.

5. **Partner-signed memo cosign identity fails to resolve.**
   Mitigation: P5.T2 acceptance criterion includes "verifier
   round-trip green on CI" against the partner's published OIDC
   subject. If the signature does not verify, do NOT commit; back-
   channel to partner for re-sign with the corrected identity.
   Fallback: PGP detached signature with the partner's published
   PGP fingerprint (the audit doc records the fingerprint).

6. **Spec linter false-positive on partner-shipped bundle.**
   Mitigation: P3.T5 ships the linter; P4.T1 sample exercises the
   linter end-to-end; CI catches any drift. If the partner finds a
   linter false-positive during spike, P4.T4 ships the linter fix
   pre-freeze.

7. **Sigstore / cosign service availability outage during P5 sign
   ceremony.** Mitigation: PGP detached signature is the documented
   fallback. The signed memo can re-issue under cosign once the
   service is back up; the PGP-signed memo remains the
   audit-of-record receipt during the outage window.

8. **`m02-m04-verdict-matrix-coupling` freeze gates M02 against M04**
   (the freeze overlaps on `crates/chio-conformance/verdict_matrix/`).
   Mitigation: M02 P2-P3 read the manifest only; M02 does not edit
   driver entries. The freeze enforces ordering so the partner-facing
   bundle path lands stable before M04 opens its driver-edit window.
   If M04 wants to start P3 earlier than M02 P3 closes, the operator
   can hot-fix bypass per the freeze's bypass lane (label
   `[trajectory-3]` on a `hotfix/*` branch).

## Success criteria

- `spec/eval/receipt-format.v1.json` published with schema id
  `chio.eval-report.bundle.v1`; passes the schema linter; sha-pinned
  in the audit doc closure block.
- `crates/chio-eval-receipt/` reference verifier landed; `cargo test
  -p chio-eval-receipt --quiet` green; `chio eval-receipt verify`
  CLI binary produces a `verified: true; signatures: <N>; receipts:
  <M>` line on the golden vector.
- `crates/chio-eval-receipt/py/` Python binding published as
  `chio-eval-receipt-py` to PyPI; partner-side Python ingest works
  end-to-end.
- `tests/bindings/vectors/eval/v1.json` golden bundle checked in;
  regen path documented under `xtask/`.
- `examples/eval-receipt-ingest/<partner-slug>/` integration sample
  runs end-to-end and round-trips through the verifier; CI run URL
  recorded in the audit doc.
- Partner-signed conformance memo committed at
  `.planning/trajectory-3/audits/M02-memo.md` plus `.sig` within 7
  days of P5 close (D15 freshness window enforced by audit-doc CI
  check).
- Cosign signer identity (or PGP fingerprint) recorded in the audit
  doc closure block; signature verifies locally and on CI.
- Verdict-matrix CI run cited in the memo is green; the corpus
  sha256 in the bundle metadata equals the manifest's corpus_sha256
  (`47e8d539...`).
- Partnership-note (blog or README entry) published; URL recorded
  in the audit doc.
- M04.P3 may open after the `m02-m04-verdict-matrix-coupling` freeze
  end-trigger fires (M02.P3 close), so the driver promotion lands on
  a stable manifest-read substrate.
