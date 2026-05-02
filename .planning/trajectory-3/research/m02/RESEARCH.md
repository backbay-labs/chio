# M02 Research: AI-Lab Evaluation Infrastructure Beachhead

**Trajectory:** trajectory-3
**Milestone:** M02
**Wave:** W1
**Phase:** RESEARCH
**Date:** 2026-04-30
**Inputs cited:**
- `.planning/trajectory-3/02-ai-lab-evaluation-beachhead.md`
- `.planning/trajectory-3/audits/M02-ai-lab.md`
- `.planning/trajectory-3/tickets/M02/README.md`
- `.planning/trajectory-3/decisions.yml` (D10, D15)
- `.planning/trajectory-2/02-mutation-and-cross-sdk-differential.md`
- `.planning/audits/M02-mutation-and-verdict-matrix.md` (closeout, sections 5.x)
- `crates/chio-conformance/verdict_matrix/` (drivers, manifest, scenarios)
- `spec/schemas/chio-wire/v1/receipt/`

## Executive framing

M02 is the second customer-anchor milestone on trajectory-3. The lens is
adoption (first non-Backbay customer) crossed with protocol (the receipt
format must be admissible in a public AI-lab eval card). The scope, after
audit reckoning, is narrow: pick one of three named partners by end of
week 1 (D10), publish an eval-report receipt format spec, deliver a
partner-grade integration sample, and receive a partner-signed
conformance memo within 7 days of P5 close (D15).

The trajectory-2 audit closeout (`.planning/audits/M02-mutation-and-verdict-matrix.md`,
section "Driver Inventory") already records that 3 of 4 non-Rust drivers
ship as `unsupported` or partial. M02 (trajectory-3) here does NOT
attack the full driver promotion (that is M04 work per
`.planning/trajectory-3/04-mutation-and-verdict-matrix-promotion.md`); the
trajectory-3 02 milestone doc and the audit template only require the
Python and Go drivers to flip to `passing`, and the bulk of the W1
milestone budget should be spent on partner-facing infrastructure: the
eval-report receipt envelope, the integration sample, and the signed
conformance memo. M04 will pull the cross-driver promotion through to
required-CI.

## AI-lab partner candidate dossiers

D10 names three candidates. Public-source dossier shape for each
(citations are public-doc URLs; the IMPLEMENT-phase agent will refresh
within the D15 7-day freshness window before the contract ticket
merges):

### Anthropic evaluations team

- Public posture: Anthropic's "Responsible Scaling Policy" and the
  Frontier Red Team / model-card eval section publish quantitative
  evaluation results per Claude release. Tool-use evaluations (SWE-bench,
  agentic browsing, Computer Use) are reported with verdict-style pass
  / fail counts plus methodological notes.
  References: `https://www-cdn.anthropic.com/...responsible-scaling-policy.pdf`,
  `https://www.anthropic.com/news/claude-...-system-card`.
- Eval pipeline shape (public): Inspect
  (`https://github.com/UKGovernmentBEIS/inspect_ai`) is the Anthropic-and-AISI-aligned
  eval framework. Inspect emits per-task `EvalLog` JSON with scorer
  outputs; that JSON is the natural ingest surface for a Chio receipt
  envelope (one envelope per scored sample).
- Signed-evaluation artifacts today: model-card PDFs are published
  unsigned. Internal artifacts likely use git provenance + reviewer
  sign-off rather than cryptographic signing.
- Preferred integration: library + sidecar. Inspect tasks run as Python;
  a `chio-eval` Python helper that wraps the verdict-matrix driver and
  returns receipt-bearing scorer output is the lowest-friction shape.
- Risk note: Anthropic is an Anthropic-internal team; cycle time on a
  formal partner contract may exceed 6 weeks. Use METR / Apollo as the
  fallback if the contract is not signed by end of week 1 (D10
  fallback path).

### METR

- Public posture: METR (formerly ARC Evals) publishes long-form task
  reports for autonomy / agentic capability evaluations. Reports include
  numerical scores plus qualitative methodology notes
  (`https://metr.org/blog/...`).
- Eval pipeline shape (public): METR's `vivaria` platform
  (`https://github.com/METR/vivaria`) orchestrates agent runs and
  collects per-step traces. Traces include tool calls, environment
  state, scoring rubric outputs - the same surface a Chio receipt log
  would attach to.
- Signed-evaluation artifacts today: published evaluation reports are
  PDFs / blog posts; underlying run logs are on GitHub but not signed.
- Preferred integration: hosted sidecar + receipt log export. METR runs
  evals in cloud sandboxes; a Chio sidecar inside the sandbox plus a
  post-run receipt-log export-to-bundle path matches their workflow.
- Risk note: METR is a small org; partner cycle time is likely fastest
  but their attention is fragmented across many evaluations. Scope the
  M02 ask to "ingest a single sample eval-report bundle and sign a
  one-page conformance memo," NOT "instrument every METR run."

### Apollo Research

- Public posture: Apollo publishes scheming / deception evaluations
  (`https://www.apolloresearch.ai/research`) and contributed to the
  Frontier Model Forum evaluation standards work. Reports are PDF
  reports with evidence appendices.
- Eval pipeline shape (public): Apollo runs scenarios against frontier
  models with structured prompt sequences and behavioral scoring; their
  emphasis on reproducibility (full transcripts, scoring rubrics) makes
  them a strong fit for a deterministic-receipt substrate.
- Signed-evaluation artifacts today: PDF reports + appendix transcripts;
  no cryptographic signing observed.
- Preferred integration: library import. Apollo's tooling is mostly
  research-grade Python; they would consume a `chio-sdk-python` import +
  a receipt verifier in their existing scoring pipeline.
- Risk note: Apollo's small team and long-form reports mean a quick
  conformance memo is plausible but a deep integration is not. Scope
  M02 around the memo path.

### Recommendation for week-1 contract selection

Rank by partner-cycle-time-to-signed-memo: METR > Apollo > Anthropic.
Rank by public-evidence-weight (citation in their published cards):
Anthropic > Apollo > METR. The partner-scoping doc shipped at P0 should
present both rankings and let the operator pick. The audit doc keeps
the un-picked two on the bench as fallbacks per D10.

## Verdict-matrix driver state inventory

Source of truth: `.planning/audits/M02-mutation-and-verdict-matrix.md`
section "Driver Inventory" plus the live source files under
`crates/chio-conformance/verdict_matrix/drivers/`.

| Driver | Path | trajectory-2 closeout status | trajectory-3 M02 expectation |
|--------|------|------------------------------|------------------------------|
| Rust kernel | `drivers/rust/` | `active` (passing, all 48 scenarios) | unchanged |
| Python SDK | `drivers/python/run_scenarios.py` | `partial-capability` (12 of 48 emit local tuples; 36 `unsupported` via `unsupported_reason()`) | flip to `passing` at all 48 (M02 P2) |
| TypeScript node-http | `drivers/typescript/run_scenarios.ts` | `transport-client` (48/48 `unsupported` without sidecar) | unchanged in M02; M04 promotes |
| WASM browser | `drivers/wasm-browser/run.sh` | `partial` (12 of 48 via `evaluate_pure`; 36 `unsupported`) | unchanged in M02; M04 promotes |
| Go SDK | `drivers/go/run_scenarios.go` | `unsupported-no-local-verdict-emitter` (48/48 `unsupported`) | flip to `passing` at all 48 (M02 P3) |

### Python driver gap analysis

Reading `drivers/python/run_scenarios.py` lines 188-199
(`unsupported_reason`):

- Non-`tool.call` operations are rejected. The corpus has 12
  `replay_verdict` and 12 `redaction_determinism` and 12
  `revocation_propagation` scenarios that do not all map to a plain
  tool-call path; the SDK must grow scenario adapters for replay,
  redaction, and revocation paths.
- Revoked-capability scenarios are rejected. The Python `MockChioClient`
  in `sdks/python/chio-sdk-python/src/chio_sdk/testing.py` does not
  expose a revocation API.

Concrete promotion work:
1. Extend `MockChioClient` to expose `revoke_capability(token_id)` and
   surface revoked tokens through the policy callback.
2. Add a `replay_verdict` evaluator: load the trace fixture, recompute
   the deterministic content hash, return the appropriate
   `urn:chio:error:replay:*` reason code on mismatch.
3. Add a `redaction_determinism` evaluator: run the guard pipeline
   (input then output) and emit `urn:chio:error:guard:input-redacted`
   or `:output-redacted` per scenario expectation.
4. Add a `revocation_propagation` evaluator: combine (1) with the
   token-state propagation across an evaluate-then-revoke-then-evaluate
   sequence.

Estimated effort: 2-3 person-days per category (8-12 person-days
total). All work lives in
`sdks/python/chio-sdk-python/src/chio_sdk/testing.py` plus
`crates/chio-conformance/verdict_matrix/drivers/python/run_scenarios.py`;
no kernel changes required.

### Go driver gap analysis

Reading `drivers/go/run_scenarios.go` lines 122-148:

- The driver currently forces every scenario to `unsupported` after
  scenario validation. There is no `MockChioClient` analog in the Go
  SDK (`sdks/go/chio-go-http/`), only the HTTP transport client.

Concrete promotion work:
1. Build a `chio-go-http/testing` package mirroring the Python
   `MockChioClient` semantics: in-process policy callback, capability
   token state, revocation, evidence attachment.
2. Wire `run_scenarios.go` to drive the four scenario categories
   (capability, replay, redaction, revocation).
3. Hook into the existing `verdict_matrix_test.go` cross-language test
   under `sdks/go/chio-go-http/`.

Estimated effort: 6-9 person-days (Go has no equivalent of the Python
`testing.py`; building it from scratch is the bulk of the work). No
kernel changes required.

### Note on M02 versus M04 scope

M02 promotes Python and Go to `passing` (the partner needs at least one
non-Rust driver to consume their language stack). M04 promotes the
remaining `transport-client` / `partial` drivers (TypeScript node-http,
WASM browser) and flips the verdict-matrix CI lane to "all drivers
required green" rather than "Rust kernel required + others advisory."
This research doc's phase outline below sticks to M02 scope only.

## Eval-report receipt format proposal

### Constraints

The format must:
1. Wrap an existing Chio receipt (per
   `spec/schemas/chio-wire/v1/receipt/record.schema.json`) without
   modifying the receipt body byte layout. The receipt's signature
   covers the canonical body; any wrapper must be additive.
2. Be admissible in a published eval card. That means: deterministic
   serialization, third-party-verifiable signature, and a stable
   reference URI.
3. Carry eval-pipeline metadata: scenario ID, scoring rubric ID, model
   identifier, eval run ID, run timestamp, scorer outputs.
4. Allow batch verification (an eval card cites N receipts, not one).

### Recommended format: signed bundle layered on RFC 8785

Wire format: a single JSON document at
`spec/eval/receipt-format.v1.json` defining the schema
`chio.eval-report.bundle.v1`. Fields:

```
{
  "schema": "chio.eval-report.bundle.v1",
  "bundle_id": "<uuidv7>",
  "eval_run": {
    "run_id": "<partner-scoped string>",
    "started_at": "<rfc3339>",
    "ended_at": "<rfc3339>",
    "model_id": "<partner-scoped string, e.g. 'claude-sonnet-4-7'>",
    "scoring_rubric": "<URI or partner-scoped string>"
  },
  "receipts": [
    {
      "scorer_label": "<partner-scoped>",
      "scorer_verdict": "<partner-scoped enum: pass | fail | partial>",
      "chio_receipt": { ...full receipt per chio-wire/v1/receipt/record... }
    }
  ],
  "canonicalization": "rfc8785",
  "signatures": [
    {
      "signer": "<DID or PGP fingerprint or sigstore identity>",
      "algorithm": "<ed25519 | sigstore-cosign | minisign>",
      "signature": "<hex>",
      "covers": "rfc8785(self minus signatures)"
    }
  ]
}
```

Why RFC 8785 (JCS): the AI-lab partner publishes eval cards as
human-readable artifacts. RFC 8785 (`https://datatracker.ietf.org/doc/html/rfc8785`)
gives byte-stable JSON canonicalization that any third party can
recompute, and our existing receipt body already uses a deterministic
serializer (per
`crates/chio-core-types/src/receipt.rs` per the schema doc).

Why a separate signature envelope: the inner Chio receipt signature is
kernel-anchored; the outer bundle signature is partner-anchored. Both
must verify independently. The outer signature is what the partner
attests "I ran this eval and these are the receipts."

Alternatives considered:

- **Sigstore-bundled (cosign + Rekor):** Strong supply-chain story but
  adds Rekor dependency. Recommend keeping this as a v2 format option
  once we ship the eval-receipt format and one partner has shipped a
  card. Citation: `https://docs.sigstore.dev/cosign/signing/...`.
- **JOSE / JWS embedded in JSON:** Standard but the JWS payload is
  opaque-base64; reviewers cannot read the receipt by eye. Reject for
  v1.
- **DSSE (Dead Simple Signing Envelope):** Used by SLSA / in-toto.
  Stronger than raw RFC 8785 + ed25519 but heavier ceremony. Possible
  v2 option per partner request.

### Reference verifier

Ship `crates/chio-eval-receipt/` with:
- `verify_bundle(bundle_json) -> Result<VerifiedBundle, BundleError>`
- A CLI: `chio eval-receipt verify <path>`
- A `chio-eval-receipt-py` thin Python binding (so the partner verifies
  in their pipeline language).

The verifier must:
1. Recompute RFC 8785 canonicalization, exclude `signatures`, verify
   each outer signature.
2. For each `receipts[]`, verify the inner `chio_receipt.signature`
   against the receipt body per existing chio-core-types logic.
3. Check schema validity against `spec/eval/receipt-format.v1.json`.

## Conformance assertion mechanics

### Question: how does the partner sign the memo?

D10 says "partner-signed conformance memo." Concretely the artifact is
a 1-page PDF or markdown document plus a detached signature. The signing
options:

| Option | Pros | Cons | Recommendation |
|--------|------|------|----------------|
| PGP detached signature | Universally accepted, no infra | Most partners do not have published PGP keys; key management is a chore | Use only if partner already publishes a PGP key |
| Sigstore (cosign + OIDC identity) | Identity-anchored, no key mgmt, ties to GitHub identity | Requires partner to have a GitHub account they can use as the OIDC identity | **Default recommendation** |
| Notarized PDF (DocuSign et al.) | Familiar to non-engineering partners | Not third-party verifiable without DocuSign account; weak provenance | Fallback only |
| Inline GitHub commit signature | Partner makes a PR adding the memo to the audit doc; the commit's signature IS the assertion | Best provenance; commit hash in the audit doc is the link | Use as a complement to (2) |

Recommended primary path: partner opens a PR against the trajectory-3
worktree adding `.planning/trajectory-3/audits/M02-ai-lab.md` section
"Closure attestations" with:
1. The 1-page memo committed alongside (under `.planning/trajectory-3/audits/M02-memo.md`
   or `.planning/trajectory-3/audits/M02-memo.pdf`).
2. A cosign signature file
   (`.planning/trajectory-3/audits/M02-memo.sig`) tied to the partner's
   GitHub OIDC identity.
3. The partner-side reviewer is the commit author (signed commit).

The audit doc records (per its template):
- Memo URL + hash.
- Cosign signer identity.
- Commit SHA.
- Receipt date (must be within 7 days of P5 close per D15).

### What if the partner cannot use cosign?

P5 ticket carries a "fallback path: PGP detached signature on the memo
PDF" branch. The audit doc records the PGP fingerprint and the partner
publishes the fingerprint on their public site. Less defensible against
"who signed this" but acceptable.

## Per-phase research findings (P0-P5)

### P0: audit baseline + partner shortlist scoping + week-1 contract

Findings:
- The audit doc template at
  `.planning/trajectory-3/audits/M02-ai-lab.md` already has the right
  shape: hard counts, customer evidence log, closure attestations.
- "Hard counts at P0" must record: 2 unsupported drivers (Python, Go);
  48 scenarios (corpus_sha256 47e8d539...); 1 partner contracted plus 2
  on the fallback bench.

P0 ticket scaffold (5 tickets):
- `M02.P0.T1`: write audit doc P0 baseline (drivers, scenarios, sha).
- `M02.P0.T2`: produce partner-scoping doc at
  `.planning/trajectory-3/research/m02/PARTNER-SCOPING.md`
  (one-pager per candidate plus rank).
- `M02.P0.T3`: open three outreach threads (Anthropic, METR, Apollo) in
  parallel; record outreach receipts in the audit doc evidence log.
- `M02.P0.T4`: contract one partner by end of week 1; record name +
  acceptance criteria in the audit doc.
- `M02.P0.T5`: P0 wave-opener PR merge.

Halt-trigger reminder: if all three decline by end of week 2, halt 12
fires and waits for operator authorization before substituting.

### P1: eval-report receipt format spec

Findings:
- The receipt body schema exists at
  `spec/schemas/chio-wire/v1/receipt/record.schema.json`. The bundle
  schema goes one level up at `spec/eval/receipt-format.v1.json` (new
  directory).
- Schema linter: the existing `tests/bindings/vectors/receipt/v1.json`
  pattern means the IMPLEMENT phase ships
  `tests/bindings/vectors/eval/v1.json` with a fixture bundle plus a
  `chio-eval-receipt`-targeted self-test under
  `crates/chio-eval-receipt/tests/`.

P1 ticket scaffold (4 tickets):
- `M02.P1.T1`: draft `spec/eval/receipt-format.v1.json` schema.
- `M02.P1.T2`: ship `crates/chio-eval-receipt/` reference verifier.
- `M02.P1.T3`: ship Python binding + CLI for the verifier.
- `M02.P1.T4`: schema linter integration + golden bundle vector.

### P2: Python driver `unsupported -> passing`

Findings: see "Python driver gap analysis" above. Effort 8-12
person-days. No kernel work.

P2 ticket scaffold (4 tickets):
- `M02.P2.T1`: extend `MockChioClient` with revocation API + tests.
- `M02.P2.T2`: add replay-verdict evaluator path in the driver.
- `M02.P2.T3`: add redaction-determinism + revocation-propagation
  evaluators.
- `M02.P2.T4`: flip manifest entry `python-sdk` from
  `partial-capability` to `passing`; assert all 48 scenarios pass in
  CI.

### P3: Go driver `unsupported -> passing`

Findings: see "Go driver gap analysis" above. Effort 6-9 person-days.
Build the Go testing package from scratch.

P3 ticket scaffold (4 tickets):
- `M02.P3.T1`: scaffold `sdks/go/chio-go-http/testing/` package
  (mirror of Python testing.py).
- `M02.P3.T2`: implement scenario evaluators.
- `M02.P3.T3`: rewrite `drivers/go/run_scenarios.go` to drive the new
  testing package.
- `M02.P3.T4`: flip manifest entry `go-http-sdk` to `passing`;
  cross-language diff in CI must stay green.

### P4: partner integration spike + sample eval-report ingest

Findings:
- Partner integration sample lives under
  `examples/eval-receipt-ingest/<partner>/` (partner-named after
  contract).
- Sample shape: a 50-100 line Python or Go script that runs three
  verdict-matrix scenarios end-to-end, packages the output as a
  bundle, signs the bundle with a test cosign identity, and verifies
  the bundle round-trips.
- Plus a 1-page "How a partner consumes this" README.

P4 ticket scaffold (4 tickets):
- `M02.P4.T1`: ship `examples/eval-receipt-ingest/` with a Python
  sample.
- `M02.P4.T2`: ship a Go sample (parallel; depends on P3 completion).
- `M02.P4.T3`: integration-spike doc at
  `.planning/trajectory-3/research/m02/PARTNER-INTEGRATION.md`
  capturing partner feedback receipts (D15 7-day window).
- `M02.P4.T4`: open a partnership-note PR draft (blog or shared README
  entry).

### P5: partner-signed conformance memo received

Findings:
- The memo is a 1-page document; template below in this doc under
  "External evidence shape."
- Closure attestations: memo URL + hash, verdict-matrix CI run URL,
  partnership-note URL.
- D15 7-day freshness: the audit doc CI check (per D15
  consequences) requires per-receipt date stamps.

P5 ticket scaffold (4 tickets):
- `M02.P5.T1`: produce partner-facing draft memo for partner to
  sign.
- `M02.P5.T2`: receive signed memo + signature; commit under
  `.planning/trajectory-3/audits/`.
- `M02.P5.T3`: fill audit doc closure attestations + flip status to
  `closed`.
- `M02.P5.T4`: publish partnership-note PR (blog or README); record
  URL.

## Cross-milestone dependencies

| Direction | Other milestone | Nature |
|-----------|-----------------|--------|
| M02 -> M04 | M04 verdict-matrix promotion | M02's Python + Go drivers are the load-bearing prereq for M04's "all drivers required green" CI flip. M04 starts no earlier than M02 P3 close. |
| M03 -> M02 | M03 hosted CI for partner-facing CI artifacts | M03 ships hosted CI; M02 P4 sample ingest references the hosted CI artifact-publishing surface. M02 can ship a stub if M03 lags. |
| M01 -> M02 | M01 Opus pilot | Not blocking. M01 is a separate customer-anchor; the audit infrastructure (per-receipt date stamps, D15 freshness window) is shared. |
| M02 -> M07/M08/M09 | None | M02 evidence is partner-attested; downstream milestones do not depend on M02's specific format. |

The trajectory-3 04 milestone doc
(`.planning/trajectory-3/04-mutation-and-verdict-matrix-promotion.md`)
should explicitly cite "M02 Python + Go drivers are P0 prereq."

## Partnership risk register

1. **All three partners decline** (halt trigger 12). Mitigation: P0
   spawns three parallel outreach threads; halt-and-ping by end of week
   2 if no contract. Recovery: operator authorizes substitute (e.g.
   ARC-Evals successor org, internal Anthropic Frontier Red Team
   directly, or a smaller eval shop like Redwood Research).
2. **Partner declines after week 6** (post-P3, mid-P4). Mitigation:
   P4 ticket carries a "memo-only fallback" branch: ship the spec, the
   verifier, and the integration sample WITHOUT a partner-signed memo;
   audit doc records "partner withdrew at week N" with cause; halt 12
   triggers next-partner contracting.
3. **Partner's eval pipeline diverges from our format** (mid-P4
   review). Mitigation: P1 ships in week 4 to give partner 4-5 weeks
   to flag divergences. Format edits are fine pre-P5; post-P5 freeze
   is in effect (D15 freshness rule).
4. **Partner publishes their eval card without crediting Chio.**
   Mitigation: the conformance memo template (below) carries explicit
   attribution language; the partnership-note PR cross-references the
   memo. Recovery: the audit doc still records the memo as evidence;
   public-credit is a soft target.
5. **Partner-signed memo is received but the cosign identity does not
   resolve.** Mitigation: P5.T2 acceptance criterion includes "verifier
   round-trip green on CI"; if signature does not verify, do NOT
   commit; back-channel to partner for re-sign.
6. **Python or Go driver gap is larger than the 8-12 / 6-9 person-day
   estimate.** Mitigation: D08-style honest threshold applies; ship
   subset-passing if needed, document gap in audit doc, flip the
   manifest entry to `passing-with-known-gaps` rather than slip the
   partner memo. M04 closes the residual gap.
7. **Receipt format spec linter fails on the partner-shipped bundle.**
   Mitigation: P1.T4 ships the linter; P4.T1 sample exercises the
   linter; CI catches drift.

## External evidence shape: 1-page conformance memo template

Path when committed: `.planning/trajectory-3/audits/M02-memo.md`
plus optional `.pdf` mirror.

```markdown
# Chio Receipt Conformance Memo

**Issuer:** <Partner organization>
**Issuer representative:** <Name, role>
**Issue date:** <YYYY-MM-DD>
**Memo version:** v1

## Statement

We, <Partner organization>, attest that we have evaluated the Chio
receipt format (commit <git sha> of github.com/<chio-repo>) for use as
the verdict-evidence substrate in our tool-use evaluation pipeline.
Specifically:

1. We ingested <N> sample eval-report bundles
   (`chio.eval-report.bundle.v1`) generated by the Chio
   verdict-matrix conformance harness against our pipeline scenarios.
2. We verified each bundle using the reference verifier
   (`crates/chio-eval-receipt/`) against the canonical schema at
   `spec/eval/receipt-format.v1.json`.
3. We confirmed that the receipt format provides:
   (a) deterministic serialization (RFC 8785),
   (b) third-party-verifiable kernel-anchored signatures on each
       inner receipt,
   (c) partner-anchored signatures on the outer bundle,
   (d) sufficient eval-pipeline metadata (run ID, scoring rubric,
       model ID) for our published eval cards.

We commit to citing Chio receipts in <one or more> of our published
eval cards or research notes within <agreed window, e.g. 90 days> of
this memo.

## Caveats

<Partner-supplied caveats, e.g. "We have not exercised the WASM browser
driver path" or "Our pipeline currently consumes the bundle as JSON,
not PDF.">

## Reproduction

Verifier command:

    chio eval-receipt verify <path-to-bundle.json>

Expected output: `verified: true; signatures: <N>; receipts: <M>`.

## Signatures

Partner signature: cosign / PGP / commit-signature attached as
`M02-memo.sig` adjacent to this file.

Chio maintainer countersignature (acknowledgement): commit signature
on the merge of this memo to the trajectory-3 audit doc.
```

This template is intentionally short. A 1-page memo is what an AI-lab
legal-and-research-ops team can sign in days, not weeks. Longer memos
slip; shorter memos are what gets us the customer evidence inside the
D15 freshness window.

## Recommended ticket scaffold

Total tickets: 25 (P0=5, P1=4, P2=4, P3=4, P4=4, P5=4).

Wave-opener (P0.T5) and wave-closer (P5.T4) are the trajectory-style
opener / closer pattern. Trust-boundary marker stays at `yes` per the
README (the receipt format spec touches the wire surface).

Effort calibration (per `.planning/trajectory-3/02-...md` "Trust-boundary"
header `Effort weeks: 6/9/13`):
- 6-week path: P0 (wk1), P1 (wk2-4), P2+P3 in parallel (wk3-5), P4
  (wk5), P5 (wk6).
- 9-week path adds slack at P2/P3 and at P5 partner review.
- 13-week path is the contingency where partner cycle time stretches.

Concrete artifacts shipped (per scope):
- `.planning/trajectory-3/research/m02/PARTNER-SCOPING.md` (P0).
- `spec/eval/receipt-format.v1.json` (P1).
- `crates/chio-eval-receipt/` (P1).
- `examples/eval-receipt-ingest/<partner>/` (P4).
- `.planning/trajectory-3/research/m02/PARTNER-INTEGRATION.md` (P4).
- `.planning/trajectory-3/audits/M02-memo.md` + `.sig` (P5).
- partnership-note (blog or README PR; P5).

Cross-driver work (P2, P3) lands inside
`crates/chio-conformance/verdict_matrix/drivers/{python,go}/` plus the
SDKs (`sdks/python/chio-sdk-python/`, `sdks/go/chio-go-http/`).

## Open questions for IMPLEMENT phase

1. **Partner identity for the contract ticket.** The IMPLEMENT-phase
   agent needs the operator's pick from the three D10 candidates
   before P0.T4 can land. Recommend the partner-scoping doc forces a
   decision in week 1.
2. **Outer-signature algorithm default.** Cosign requires the partner
   to have a GitHub identity they can use as the OIDC subject. If the
   partner is internal to Anthropic, the OIDC subject is their
   anthropic.com email-mapped GitHub account; this is straightforward.
   For METR / Apollo, confirm the subject in the contract ticket.
3. **Bundle-verifier crate location.** Should `chio-eval-receipt` live
   in the workspace as a primary crate or under
   `crates/conformance-tools/` as a sub-crate? Recommend primary crate
   so it can be published to crates.io for partner consumption.
4. **Receipt-bundle fixture.** Where does the
   `tests/bindings/vectors/eval/v1.json` golden vector come from?
   Recommend: deterministic generation from the Rust kernel running
   3-5 capability_subset scenarios, captured as a checked-in fixture
   plus a regen script under `xtask/`.
5. **Public partnership note location.** Blog post on
   `chio-protocol.dev` (TBD whether that domain is live) or a markdown
   entry in the README linking to the partner's eval card? Recommend
   both: README entry is mandatory; blog post is optional.
6. **CI gating policy for the bundle linter.** Should the linter be
   `required: true` from week 4 (P1 close) or advisory until P5? Lean
   `required` so the partner-shipped sample at P4 cannot diverge.
7. **Memo file format: markdown or PDF.** Markdown is reviewable in
   the audit PR diff; PDF carries notarial weight for some legal
   teams. Default markdown; allow PDF mirror.
8. **Withdrawal-replay path.** If partner withdraws between P4 and P5,
   does the partner's interim feedback (captured in
   PARTNER-INTEGRATION.md) survive into the audit doc as evidence?
   Recommend yes; D15 still applies to the freshness of THAT receipt.
9. **Scope of the conformance assertion.** The memo template above
   asserts conformance against a specific git sha. If we ship a
   bundle-format v1.1 fix post-memo, do we re-issue the memo? Lean
   no: the v1 memo stands; v1.1 is a separate engagement.

## Appendix: file-path index for IMPLEMENT phase

Source paths cited above (all relative to repo root unless noted):

- `crates/chio-conformance/verdict_matrix/manifest.toml`
- `crates/chio-conformance/verdict_matrix/scenarios/{capability_subset,redaction_determinism,replay_verdict,revocation_propagation}/`
- `crates/chio-conformance/verdict_matrix/drivers/python/run_scenarios.py`
- `crates/chio-conformance/verdict_matrix/drivers/go/run_scenarios.go`
- `crates/chio-conformance/verdict_matrix/drivers/typescript/run_scenarios.ts`
- `crates/chio-conformance/verdict_matrix/drivers/wasm-browser/run.sh`
- `sdks/python/chio-sdk-python/src/chio_sdk/testing.py`
- `sdks/python/chio-sdk-python/tests/test_verdict_matrix.py`
- `sdks/go/chio-go-http/`
- `spec/schemas/chio-wire/v1/receipt/record.schema.json`
- `spec/schemas/chio-wire/v1/receipt/inclusion-proof.schema.json`
- `.planning/audits/M02-mutation-and-verdict-matrix.md` (trajectory-2 closeout)
- `.planning/trajectory-3/02-ai-lab-evaluation-beachhead.md`
- `.planning/trajectory-3/audits/M02-ai-lab.md`
- `.planning/trajectory-3/tickets/M02/{README.md,P0..P5.yml}`
- `.planning/trajectory-3/decisions.yml` (D10, D15)

External references:
- RFC 8785 JSON Canonicalization Scheme: `https://datatracker.ietf.org/doc/html/rfc8785`
- Sigstore cosign: `https://docs.sigstore.dev/cosign/signing/overview/`
- DSSE: `https://github.com/secure-systems-lab/dsse`
- Inspect (Anthropic / AISI eval framework): `https://github.com/UKGovernmentBEIS/inspect_ai`
- METR vivaria: `https://github.com/METR/vivaria`
- METR public posts: `https://metr.org/blog/`
- Apollo Research: `https://www.apolloresearch.ai/research`
- Anthropic Responsible Scaling Policy: `https://www.anthropic.com/news/responsible-scaling-policy`
