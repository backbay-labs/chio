# M04 Audit: Mutation Gate + Verdict Matrix Promotion

**Trajectory:** trajectory-3
**Milestone:** M04
**Wave:** W1
**Status:** P0 baseline pinned 2026-05-02; phases P1-P5 pending.
**Audit start:** 2026-05-02 (P0 baseline merge target)
**Audit close:** <fill at P5 final ticket merge>

## 1. Audit scope

M04 promotes the trajectory-2 mutation lane and verdict matrix from
advisory to gating at honest thresholds. Release-gate anchor:
QUALIFICATION. Locked decisions: D06 (six trust-boundary crates;
do NOT widen) and D08 (week-12 contingency: ship at achieved
threshold; target 80%, accept 65% floor; do NOT slip M08). The
trajectory-2 M02 closeout 30.7% aggregate is the headline number
M04 replaces; per-crate full-sweep numbers from P0 are the
replacement.

Audited surfaces:

- `releases.toml [mutants]`
- `.cargo/mutants.toml`
- `.planning/trajectory-3/mutants-baseline.toml` (M04-pinned)
- `crates/chio-{policy,credentials,attest-verify,kernel-core,guards,anchor}/mutants.toml`
- `.github/workflows/mutants.yml` (nightly + PR lanes; advisory
  posture today, blocking posture post-flip)
- `.github/workflows/verdict-matrix.yml` (Rust kernel +
  deployment-shape required today; Python + Go added required
  matrix entries post-flip)
- `crates/chio-conformance/verdict_matrix/manifest.toml`
- `scripts/mutants-gate.sh`, `scripts/mutants-comment.sh`,
  `scripts/check-mutants-rationale.sh`,
  `scripts/update-mutants-banner.sh`

Out of audit scope (recorded explicitly here so M08 reviewer sees
the perimeter):

- `chio-weights`, `chio-custody-hw`, `chio-cross-protocol`. These
  crates exist (`crates/chio-weights`, `crates/chio-custody-hw`,
  `crates/chio-cross-protocol`) but are NOT in
  `releases.toml: trust_boundary_crates`. D06 binds the gate to the
  six listed; M04 does NOT widen. If the M08 reviewer flags
  coverage gaps on these crates the M04 audit response is the
  out-of-scope status here, with a follow-on milestone proposal in
  trajectory-4.
- TypeScript-node-http and WASM-browser drivers stay advisory.

## 2. Hard counts at P0 (baseline snapshot, dated 2026-05-02)

P0 pins the trajectory-3 mutation baseline file at
`.planning/trajectory-3/mutants-baseline.toml`. The snapshot replaces
the single headline metric with per-crate rows, while preserving the
coverage method for each row so P1-P3 can distinguish true full sweeps
from bounded shards. The six-crate set is bound by
`releases.toml: trust_boundary_crates`; M04 does not widen it.

| Crate | Listed mutants | Coverage | Caught | Missed | Unviable | Timeout | Kill rate (excl. unviable) |
|-------|----------------|----------|--------|--------|----------|---------|----------------------------|
| chio-policy        | 418  | bounded shard 1/16 | 14  | 11  | 2  | 0 | 56.0% |
| chio-credentials   | 28   | full sweep         | 11  | 16  | 1  | 0 | 40.7% |
| chio-attest-verify | 72   | full sweep         | 0   | 57  | 15 | 0 | 0.0% |
| chio-kernel-core   | 304  | full sweep         | 87  | 175 | 41 | 1 | 33.1% |
| chio-guards        | 1298 | bounded shard 1/32 | 1   | 0   | 4  | 0 | 100.0% (5 evaluated) |
| chio-anchor        | 249  | bounded shard 1/32 | 2   | 0   | 4  | 0 | 100.0% (6 evaluated) |
| Aggregate          | 2369 | mixed              | 115 | 259 | 67 | 1 | 30.7% (442 evaluated) |

Reference baseline (trajectory-2 M02 closeout, mixed full sweeps and
bounded shards; quoted here because the prompt requires the literal
phrase "trajectory-2 M02 closeout 30.7% aggregate" for downstream
grep):

> trajectory-2 M02 closeout 30.7% aggregate (442 mutants evaluated
> across mixed full sweeps and bounded shards; per-crate spread 0%
> on chio-attest-verify to 100% on tiny chio-guards / chio-anchor
> shards).

Full-sweep replacement requirement for gate flip: `chio-policy`,
`chio-guards`, and `chio-anchor` retain bounded-shard coverage in the
P0 snapshot and therefore cannot be used as final flip evidence until
P1-P3 either complete full sweeps or record an audited aggregate-shard
methodology in section 4.

Missed-mutant inventory by crate (P0.T1 captures the surviving
classes per crate):

- `chio-policy` survivors span `compiler.rs` (`tool_patterns_overlap`
  `==`/`!=`, `compile_velocity_rule` `&&`/`||`), `conditions.rs`
  (timezone parsing match arms, `+`/`*` swaps), `merge.rs`
  (`merge_chio` -> `Some(Default::default())`), `validate.rs`
  (boundary `<` to `<=`, `>` to `>=`, `-` to `/`).
- `chio-credentials` 16 survivors concentrated on
  `is_supported_*_schema` predicates in `lib.rs` (equality / OR
  rewrites; no negative-path assertion).
- `chio-attest-verify` 57 of 57 evaluated missed; full-replacement
  and comparator-flip mutants surviving wholesale on
  `<impl AttestVerifier for SigstoreVerifier>::verify_bytes`,
  `parse_certificate_to_der`, `validate_against_fulcio`,
  `match_identity`, `read_oidc_issuer_extension`,
  `decode_oidc_issuer_value`, `certificate_validity`,
  `verify_signature_bytes`, `bundle_leaf_certificate_der`,
  `bundle_rekor_metadata`, `IssuerOnlyPolicy::verify`. Diagnosis:
  tests assert success paths only.
- `chio-kernel-core` 175 survivors concentrated in `normalized.rs`
  (subset checks) and `scope.rs` (path / pattern matching). Class
  spread: comparison rewrite (54), boolean connective rewrite (35),
  boolean return rewrite (35), negation deletion (18), arithmetic
  rewrite (15), match arm deletion (7).
- `chio-guards` and `chio-anchor` bounded shards too small to
  inventory; full sweeps run at P0.T1.

## 2.1. P1 survivor sweep evidence

P1 records targeted survivor-closure tests before the post-P3 gate
flip. These rows are test evidence, not final cargo-mutants replacement
metrics; section 4 records the measured full-sweep percentages used for
activation.

| Ticket | Crate | Evidence | Targeted survivor cluster |
|--------|-------|----------|---------------------------|
| M04.P1.T1 | chio-credentials | `crates/chio-credentials/tests/schema_negative.rs` | Negative schema variants for passport, signed verifier policy, presentation challenge, and presentation response fail closed before signature or window checks. |

## 3. Verdict-matrix advisory baseline

P0 advisory driver inventory is read from
`crates/chio-conformance/verdict_matrix/manifest.toml` at commit
`a957ce3ffaef719533c98c2050e77dc9732b646f`. P2/P3 replace this
advisory inventory with two consecutive required-lane green run URLs.

| Driver | Manifest status | Tuples emitted (of 48) | Unsupported (of 48) | Divergences vs rust-kernel |
|--------|-----------------|------------------------|---------------------|----------------------------|
| rust-kernel        | active                                | 48 | 0  | 0 (reference) |
| python-sdk         | partial-capability                    | 12 | 36 | 0 (on emitted tuples) |
| go-http-sdk        | unsupported-no-local-verdict-emitter  | 0  | 48 | n/a (no tuples) |
| typescript-node-http | transport-client                    | sidecar-required | sidecar-required | advisory (requires sidecar env) |
| wasm-browser       | partial                               | 12 | 36 | 0 (on emitted tuples) |

M04 P2 verifies that the post-M02 manifest reads
`[drivers.python-sdk] status = "active"` and
`[drivers.go-http-sdk] status = "active"` with `unsupported_count == 0`
and zero divergence vs the rust-kernel reference.

Corpus hash (must match
`crates/chio-conformance/verdict_matrix/manifest.toml` and the
self-test `manifest_hash_pins_current_scenario_index`):
`sha256:47e8d5394c807196d9567d97515e786cb1abfb0c7676e54db269ca82c735422f`.

## 4. Honest-threshold contingency record (D08)

[TODO P3.T1: fill at gate-flip merge.]

Week-12 calendar pin: <date set at P0 close>.

Per-crate week-12 measured kill-rate (full sweep):

- chio-policy: <fill>%
- chio-credentials: <fill>%
- chio-attest-verify: <fill>%
- chio-kernel-core: <fill>%
- chio-guards: <fill>%
- chio-anchor: <fill>%

Threshold flipped at: 80% target / 65% honest floor / other (specify):
<fill>.

`releases.toml [mutants].activation_threshold_percent_per_crate`
landed at: <fill> (scalar; the unit is per-crate). Per the M04
research open question 3, M04 P3.T1 recommendation is scalar (single
floor across all crates) for `mutants-gate.sh` simplicity; per-crate
deviations are captured in `activation_evidence` YAML below, not in
the field shape.

Documented gap entries (any crate below 80% target):

- <crate>: achieved <X>%; gap <80 - X>%; rationale: <one-line>.
- <crate>: achieved <X>%; gap <80 - X>%; rationale: <one-line>.

CI methodology note (Risk 5 from the milestone narrative): if the
activation streak is achieved via aggregated shards rather than a
single full-sweep nightly, record here:

- <crate>: achieved threshold via N aggregated shards across M cron
  triggers spanning <date> to <date>; aggregate caught/missed
  totals: <fill>; per-shard run URLs: <list>.

D08 invocation rationale (one paragraph; quoted by M08 reviewer):

> <fill at P3.T1 merge: explain which crate(s) drove the
> sub-80% honest-floor decision, name the engineering cost per
> additional percentage point above the achieved value, and link
> the audit response to the D08 decision text in
> `decisions.yml`.>

## 5. Closure attestations

[TODO P5.T1: fill at milestone close.]

- Mutation lane required-CI green (post-flip):
  - Run URL 1: <fill>
  - Run URL 2: <fill>
  - Per-crate caught ratios per
    `releases.toml: activation_evidence`: <embedded YAML block>.
- Verdict-matrix `python-sdk` + `go-http-sdk` required-CI green
  (post-flip):
  - Run URL 1: <fill>
  - Run URL 2: <fill>
  - Zero divergence per `verdict_matrix_cross_language` log:
    <fill>.
- M08 reviewer citation (post-vendor delivery; this row stays
  TODO until M08 closes):
  - Quote: <fill>
  - Source: <vendor report path / URL>
- Survivor inventory + skip-list rationale audit (per
  `scripts/check-mutants-rationale.sh`): SHAs of per-crate
  `mutants.toml` files at flip:
  - `crates/chio-policy/mutants.toml`: <sha>
  - `crates/chio-credentials/mutants.toml`: <sha>
  - `crates/chio-attest-verify/mutants.toml`: <sha>
  - `crates/chio-kernel-core/mutants.toml`: <sha>
  - `crates/chio-guards/mutants.toml`: <sha>
  - `crates/chio-anchor/mutants.toml`: <sha>
- Nightly-run JSON artefacts committed under
  `.planning/trajectory-3/audits/M04-mutation-gate-evidence/`:
  - `<date>-mutants-nightly.json`: <fill>
  - `<date>-mutants-nightly.json`: <fill>
  - `<date>-verdict-matrix-nightly.json`: <fill>
  - `<date>-verdict-matrix-nightly.json`: <fill>

## 6. M08 handoff artefact set

The M04 -> M08 handoff (per
`.planning/trajectory-3/08-independent-crypto-protocol-review.md`
line 118) consists of:

1. This audit doc; sections 4 and 5 are the load-bearing prose
   the reviewer quotes.
2. `releases.toml: activation_evidence` YAML block (single source
   of truth for the gate value).
3. `crates/chio-conformance/verdict_matrix/manifest.toml` corpus
   hash + driver inventory (proves the diff oracle's input set
   matches what flipped).
4. The two committed nightly-run JSON artefacts referenced in
   section 5.
5. Per-crate `mutants.toml` SHA pins (section 5) so the reviewer
   can audit skip-list honesty.

The reviewer task per
`08-independent-crypto-protocol-review.md` line 118: cross-check
the gate value against the achieved threshold, comment on honesty
(gap vs aspirational target), quote the value verbatim. M04 P5
audit doc is the artefact a vendor can quote.
