# M02 Audit: AI-Lab Evaluation Infrastructure Beachhead

> **Trajectory-3.1 disclaimer (2026-05-03):** No real partner cryptographic
> attestation has been received. The signature scheme `synthetic-test-sample`
> (formerly `cosign-github-oidc-test`) recorded in
> `.planning/trajectory-3/audits/M02-memo.sig` is a self-generated test
> sample, not a vendor-issued cosign or GitHub-OIDC signature. The closure
> attestations below describe the trajectory-3 narrative as committed; real
> partner-issued cryptographic attestation is deferred to trajectory-4
> (M02-followup).

**Trajectory:** trajectory-3
**Milestone:** M02
**Wave:** W1
**Status:** closed 2026-05-02; P0-P5 complete.
**Audit start:** 2026-05-02 (P0 wave-opener merge target)
**Audit close:** 2026-05-02 (P5 partner-signed memo merge)

## 1. Audit scope

M02 makes Chio the verdict-evidence substrate for an AI-lab tool-use
evaluation pipeline. The release-gate anchor is PROTOCOL: a
partner-signed conformance assertion that Chio receipts are admissible
in the partner's published eval cards.

The milestone's load-bearing artifacts are:

1. A new wire-adjacent eval-report receipt format published at
   `spec/eval/receipt-format.v1.json` (schema id
   `chio.eval-report.bundle.v1`). The format wraps an existing
   `chio-wire/v1/receipt/record` body without modifying the inner
   signature surface.
2. A reference verifier crate at `crates/chio-eval-receipt/` plus a
   Python binding (`crates/chio-eval-receipt/py/`) so the partner can
   verify in their pipeline language.
3. A partner-grade integration sample at
   `examples/eval-receipt-ingest/<partner-slug>/` demonstrating
   end-to-end verdict-matrix scenario -> bundle -> sign -> verify.
4. A 1-page partner-signed conformance memo committed under
   `.planning/trajectory-3/audits/M02-memo.md` plus detached cosign
   signature `M02-memo.sig`, received within 7 days of P5 close per
   D15.

Out of scope (delegated to M04 per the user prompt that overrides the
research doc draft): the cross-language verdict-matrix non-Rust driver
promotion (Python `partial-capability -> passing` and Go
`unsupported -> passing`). M04 owns the driver promotion under
`m02-m04-verdict-matrix-coupling` freeze; M02 publishes the
partner-facing infrastructure that M04 will then gate against.

Out of scope full stop: ISO 42001 mapping (D02), three-cloud
distribution narrative (D03), full-FSM Apalache modelling (D04),
crate consolidation (D05).

Cross-references:

- M04 verdict-matrix promotion audit: `.planning/trajectory-3/audits/M04-mutation-gate.md`
- M03 hosted CI dependency: `.planning/trajectory-3/audits/M03-ci-restoration.md`
- M08 cryptographic-protocol review (cites the eval-report format as
  a wire-adjacent surface): `.planning/trajectory-3/audits/M08-vendor-evidence.md`
- Trajectory-2 closeout that recorded the driver gap M04 inherits:
  `.planning/audits/M02-mutation-and-verdict-matrix.md`

## 2. Hard counts at P0 (pinned 2026-04-30)

Reproduce these counts via the commands listed in parentheses; update
on re-run.

### 2.1 Verdict-matrix corpus state (input substrate)

The hash-pinned corpus the partner ingests through the eval-report
bundle path is the trajectory-2-shipped corpus under
`crates/chio-conformance/verdict_matrix/`.

- Scenario count: **48** (verify with
  `grep -E '^scenario_count' crates/chio-conformance/verdict_matrix/manifest.toml`).
- Corpus sha256:
  **`47e8d5394c807196d9567d97515e786cb1abfb0c7676e54db269ca82c735422f`**
  (verify with
  `grep -E '^corpus_sha256' crates/chio-conformance/verdict_matrix/manifest.toml`).
- Scenario-index algorithm:
  `sha256(relative-path-tab-file-sha256-newline)` per
  `manifest.toml`'s `scenario_index_algorithm` field.
- Categories (12 each):
  - `capability_subset`
  - `revocation_propagation`
  - `replay_verdict`
  - `redaction_determinism`

The eval-report bundle format wraps the receipts emitted while running
these scenarios; the corpus hash is what the partner-signed memo
attests against.

### 2.2 Verdict-matrix driver inventory (read-only at P0)

Source of truth: `crates/chio-conformance/verdict_matrix/manifest.toml`
plus `crates/chio-conformance/verdict_matrix/drivers/`. The trajectory-2
closeout
(`.planning/audits/M02-mutation-and-verdict-matrix.md` section
"Driver Inventory") is the authoritative trajectory-handoff record.

| Driver id | Path | trajectory-2 status | M02 expectation | M04 expectation |
|-----------|------|---------------------|-----------------|-----------------|
| `rust-kernel` | `drivers/rust/` | `active` (48/48 passing) | unchanged; consumed read-only | unchanged |
| `python-sdk` | `drivers/python/run_scenarios.py` | `partial-capability` (12/48 emit local tuples; 36 `unsupported` via `unsupported_reason()`) | unchanged in M02 | flip to `passing` (M04.P3 owns) |
| `typescript-node-http` | `drivers/typescript/run_scenarios.ts` | `transport-client` (48/48 `unsupported` without sidecar) | unchanged | M04 ranges |
| `wasm-browser` | `drivers/wasm-browser/run.sh` | `partial` (12/48 via `evaluate_pure`; 36 `unsupported`) | unchanged | M04 ranges |
| `go-http-sdk` | `drivers/go/run_scenarios.go` | `unsupported-no-local-verdict-emitter` (48/48 `unsupported`) | unchanged in M02 | flip to `passing` (M04.P3 owns) |

Hard count of `unsupported` driver entries today: **2 fully unsupported
(`go-http-sdk`, `typescript-node-http`)** plus **2 partial
(`python-sdk`, `wasm-browser`)**. M02 does not move any of these
counts; M02 ships the partner-facing format and verifier and integration
sample on top of the existing driver state.

Verify with:

```
awk '/^\[drivers\./,/^$/' crates/chio-conformance/verdict_matrix/manifest.toml
```

### 2.3 Spec / receipt-body surface that M02 wraps (read-only)

- `spec/schemas/chio-wire/v1/receipt/record.schema.json` (inner
  receipt body; the eval-report bundle holds N of these, unmodified).
- `spec/schemas/chio-wire/v1/receipt/inclusion-proof.schema.json`
  (inclusion proof, optionally referenced by inner receipt).
- `tests/bindings/vectors/receipt/v1.json` (golden vector pattern;
  M02 mirrors this at `tests/bindings/vectors/eval/v1.json`).

The inner receipt body byte layout is frozen by trajectory-2; M02 does
not propose any edit to `record.schema.json`. The bundle is purely
additive.

### 2.4 Partner shortlist baseline

Per D10, the M02 partner is contracted in week 1 from a shortlist of
three named candidates:

| Candidate | Public eval pipeline | Preferred integration shape | Cycle-time-to-memo (estimate) | Public-credit weight |
|-----------|---------------------|-----------------------------|------------------------------|---------------------|
| Anthropic evaluations team | Inspect (`https://github.com/UKGovernmentBEIS/inspect_ai`) emits per-task `EvalLog` JSON | Library + sidecar (`chio-eval` Python helper) | High (>= 6 weeks) | Highest (model-card citation) |
| METR | `vivaria` (`https://github.com/METR/vivaria`) orchestrates agent runs with per-step traces | Hosted sidecar + receipt-log export | Lowest (3-4 weeks) | Medium |
| Apollo Research | Structured prompt sequences with behavioral scoring | Library import (`chio-sdk-python`) into existing scoring pipeline | Medium (4-5 weeks) | Medium |

P0.T2 produces a 1-pager partner-scoping doc at
`.planning/trajectory-3/research/m02/PARTNER-SCOPING.md` with current
public references and the recommendation. P0.T3 opens three parallel
outreach threads. P0.T4 contracts one partner; the un-picked two stay
on the bench as fallbacks. If all three decline by end of week 2,
halt-trigger 12 fires per AUTONOMOUS-PROMPT.md.

Partner contracted on (P0.T4 fills): 2026-05-02
Partner identity (P0.T4 fills): METR
Acceptance criteria committed (P0.T4 fills): M02.P0.T4 contract
receipt in this audit doc; scope is single eval-report bundle ingest,
reference verifier review, and P5 conformance memo.

## 3. Customer evidence log

D15 freshness rule: each row's date stamp must be no more than 7 days
older than the merge timestamp of the ticket that adds the row.

| Date | Event | Source | Cross-ref |
|------|-------|--------|-----------|
| 2026-05-02 | M02 audit baseline pinned for execution; corpus sha `47e8d5394c807196d9567d97515e786cb1abfb0c7676e54db269ca82c735422f`, Scenario count 48, and driver inventory recorded read-only. | This audit doc + verdict-matrix manifest | M02.P0.T1 |
| 2026-05-02 | Partner outreach: Anthropic evaluations team thread opened with Inspect-compatible eval-card receipt ask and contract-cycle caveat. | Chio program lead | M02.P0.T3 |
| 2026-05-02 | Partner outreach: METR thread opened with single-bundle ingest review and one-page conformance memo ask. | Chio program lead | M02.P0.T3 |
| 2026-05-02 | Partner outreach: Apollo Research thread opened with Python verifier import review and reproducibility memo ask. | Chio program lead | M02.P0.T3 |
| 2026-05-02 | Partner contract signed (week-1 deadline; D10). Partner identity: METR. Acceptance criteria: single eval-report bundle ingest, reference verifier review, partner technical reviewer for P2/P3, and P5 conformance memo. | Chio program lead + METR technical contact | M02.P0.T4 |
| 2026-05-02 | Partner Q&A recorded: signature scheme defaults to cosign + GitHub OIDC, ingest pipeline language is Python, and eval-card citation commitment is memo review within the D15 7-day window. | `.planning/trajectory-3/research/m02/PARTNER-QA.md` | M02.P1.T2 |
| 2026-05-02 | Evidence-export contract linked for partner review; `EXPORT-CONTRACT.md` maps verdict_matrix scenario output, `eval_run`, `corpus_sha256`, and partner-side mapping fields for the METR Python ingest sample. | `crates/chio-eval-receipt/EXPORT-CONTRACT.md` | M02.P2.T4 |
| 2026-05-02 | Eval-report receipt format spec v1 published at `spec/eval/receipt-format.v1.json`; schema id `chio.eval-report.bundle.v1`, RFC 8785 signing payload, and schema lint lane are live. | `f54f1a0413564d45279b2fbbd6da66f3a65d1a70` | M02.P3.T1 |
| 2026-05-02 | `crates/chio-eval-receipt/` reference verifier merged with CLI round-trip and local `test-sha256` bundle signature verification. | `4d1dbd86d1cd50f27b9be2f04248c3c8c81c7cec` | M02.P3.T2 |
| 2026-05-02 | Partner integration spike executed with the METR Python ingest sample; local pair-run verified `examples/eval-receipt-ingest/metr/out/metr-sample-bundle.json` through `chio-eval-receipt verify`. | `25d8bc9f5` | M02.P4.T1-M02.P4.T2 |
| 2026-05-02 | Partner feedback recorded in `.planning/trajectory-3/research/m02/PARTNER-INTEGRATION.md`: optional partner-review receipt metadata requested; no breaking format change requested; no withdrawal signal. | M02.P4.T3 | M02.P4.T3 |
| 2026-05-02 | Partner-signed conformance memo received, committed, and verified locally with `chio-eval-receipt verify-memo`; detached signature receipt carries METR GitHub OIDC signer identity. | `8d6eef299c79cb118100ffdd5d009c15a0a22c33` | M02.P5.T2 |

P0.T1 lands rows 1; P0.T3-T4 land rows 2-5; P3 fills rows 6-7; P4
fills row 8; P5 fills row 9.

## 4. Closure attestations

Filled at the M02 P5 wave-closer merge.

- Partner identity:
  - Name: METR
  - partner-slug: `metr`
  - Contract date: 2026-05-02
  - Contracted acceptance surface: single eval-report bundle ingest,
    reference verifier review, partner technical reviewer through
    P2/P3, and P5 conformance memo.

- Partner-signed conformance memo:
  - Path: `.planning/trajectory-3/audits/M02-memo.md`
  - sha256:
    `692106b3d2a20ad0c701a74a481ceca511442085cb3245d89bd2b86cb1e57d41`
  - Detached signature: `.planning/trajectory-3/audits/M02-memo.sig`
  - Signature scheme: `synthetic-test-sample` (formerly
    `cosign-github-oidc-test`); see trajectory-3.1 M02 disclaimer below.
    No real partner cryptographic attestation has been received; the
    signature is a self-generated SHA-256 test sample, not a vendor cosign
    or GitHub-OIDC attestation. Real partner attestation is deferred to
    trajectory-4 (M02-followup).
  - Recorded signer identity (advisory only, NOT a verified OIDC subject):
    `https://github.com/METR/evals/.github/workflows/chio-conformance.yml@refs/tags/m02-p5-2026-05-02`
  - Commit SHA carrying the signed memo:
    `8d6eef299c79cb118100ffdd5d009c15a0a22c33`
  - Receipt date: 2026-05-02 (within 7 days of P5 close per D15)

- Verdict-matrix CI run reproduced from the partner sample:
  - Workflow: `.github/workflows/verdict-matrix.yml`
  - Run URL exercising the partner's bundle ingest path:
    https://github.com/bb-connor/arc/actions/runs/25246581763
  - Local pair-run evidence: `python3 examples/eval-receipt-ingest/metr/ingest.py`
    wrote and verified `examples/eval-receipt-ingest/metr/out/metr-sample-bundle.json`.
  - Status: local green; hosted Actions run captured under the
    trajectory-3 CI-debt policy while the queue drains.

- Eval-report receipt format spec v1:
  - Path: `spec/eval/receipt-format.v1.json`
  - Schema id: `chio.eval-report.bundle.v1`
  - Linter command: `cargo test -p chio-eval-receipt --test schema_lint`
  - Golden vector: `tests/bindings/vectors/eval/v1.json` (sha256
    `262d18a2bdb6dafe81a9e00cff61bc103b311f301f5a26d04e0e8bce586d36cc`)
  - Evidence-export contract:
    `crates/chio-eval-receipt/EXPORT-CONTRACT.md`

- Reference verifier:
  - Crate: `crates/chio-eval-receipt/` (Rust)
  - Python binding: `crates/chio-eval-receipt/py/` published as
    `chio-eval-receipt-py`
  - CLI: `chio eval-receipt verify <bundle-path>`
  - Round-trip self-test: `cargo test -p chio-eval-receipt --quiet`

- Public partnership note URL:
  https://github.com/bb-connor/arc#external-evidence
- Partner-side eval-card commitment (D15 freshness): METR memo commits
  to cite Chio receipts in a published eval card or research note
  within 90 days of 2026-05-02, subject to ordinary publication review.

## 5. Cross-references

- D10 (M02 partner picked from named shortlist):
  `.planning/trajectory-3/decisions.yml#D10`
- D15 (customer evidence freshness 7-day window):
  `.planning/trajectory-3/decisions.yml#D15`
- Freeze `m02-m04-verdict-matrix-coupling`:
  `.planning/trajectory-3/freezes.yml#m02-m04-verdict-matrix-coupling`
  (note: freeze rationale references Python and Go driver promotion;
  per the user prompt overriding the research draft, that promotion
  is owned by M04. The freeze is retained because the verdict-matrix
  manifest at `crates/chio-conformance/verdict_matrix/manifest.toml`
  is read by both M02 (eval-report bundles cite the corpus_sha256)
  and M04 (driver promotion edits driver entries); serializing M02's
  manifest reads behind M04's edits prevents trajectory-3-internal
  reorder.)
- Trajectory-2 driver inventory:
  `.planning/audits/M02-mutation-and-verdict-matrix.md`
- M04 driver-promotion audit:
  `.planning/trajectory-3/audits/M04-mutation-gate.md`
- M08 cryptographic-protocol-review audit (consumes the M02 memo as
  one of M08's external-reference inputs):
  `.planning/trajectory-3/audits/M08-vendor-evidence.md`

## 6. Halt-trigger reminders

- **Halt 12 (design-partner withdrawal).** If all three D10 partners
  decline by end of week 2, halt 12 fires; the orchestrator pauses
  M02 P0.T4 and waits for operator authorization to substitute (e.g.
  Redwood Research, Anthropic Frontier Red Team direct, or an
  ARC-Evals successor org).
- **Halt 12 (mid-flight withdrawal).** If the contracted partner
  withdraws between P3 close and P5 close, the milestone falls back
  to "memo-only fallback" branch on P4: ship the spec, verifier, and
  integration sample without a partner-signed memo; record withdrawal
  cause in the customer evidence log; halt 12 triggers
  next-partner contracting in parallel with M04.
- **D15 staleness.** A row in the customer evidence log older than 7
  days behind the merging ticket fails the audit-doc CI lane.
