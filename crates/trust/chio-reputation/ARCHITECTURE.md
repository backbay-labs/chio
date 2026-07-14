# chio-reputation architecture

## Overview

`chio-reputation` is a pure library: no I/O, no async runtime, no storage, and
`#![forbid(unsafe_code)]`. It scores agents from caller-supplied evidence
rather than reading receipts or capabilities itself, but it is not a passive
data cruncher: it independently re-verifies receipt integrity (kernel-key
trust, id, signature, action hash) before any receipt contributes to a score,
and it fails closed when that trust anchor is absent. The crate deliberately
excludes `chio-kernel` from its dependency graph so kernel-side issuance
policy can depend on it without creating a cycle.

Two scoring paths coexist and never call each other: a continuous, weighted
local scorecard (`model.rs` / `score.rs` / `compare.rs` / `issuance.rs`) for
descriptive scoring and cross-operator trust import, and a narrow
deterministic feed-to-tier model (`feed.rs` / `feeds/` / `tier.rs`) for
discrete marketplace-visibility gating.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Crate root. Shared constants, `receipt_integrity_valid` / `receipt_authority_valid`, and `include!` of `model.rs`, `score.rs`, `compare.rs`, `issuance.rs`, `tests.rs` directly into the crate-root module. Declares `feed`, `feeds`, `tier` as real submodules and re-exports `feed`'s and `tier`'s public items at the crate root. |
| `src/model.rs` (included) | `LocalReputationCorpus` and its record types, `ReputationConfig` / `ReputationWeights`, `MetricValue`, the eight per-metric structs, `LocalReputationScorecard`, and the imported-signal types. |
| `src/score.rs` (included) | `compute_local_scorecard` and the eight `compute_*` functions that derive each scorecard metric from the corpus. |
| `src/compare.rs` (included) | Shared numeric helpers (`weighted_average`, `decay_weight`, `clamp01`, `contribute_metric`) and capability-lineage comparison (`scope_reduced`, `budget_reduced`, `grant_scope_reduced`) used by delegation hygiene. |
| `src/issuance.rs` (included) | `build_imported_reputation_signal` and imported-identity field validation for cross-operator trust signals. |
| `src/tests.rs` (included) | Unit tests over the included modules, sharing their namespace through `include!`. |
| `src/feed.rs` | `ReputationFeed` trait, `ScoreDelta`, `compose_deltas` (max-composition), `min_delta` (AND-companion), `MAX_FEED_DELTA`. |
| `src/feeds/mod.rs` | Declares the two bundled feed submodules. |
| `src/feeds/arena_survival.rs` | `ArenaSurvivalFeed`: delta = survival rate over `ArenaRoundOutcome`s. |
| `src/feeds/cross_provider_equality.rs` | `CrossProviderEqualityFeed`: delta = agreement rate over `VerdictCaseOutcome`s with at least two providers observed. |
| `src/tier.rs` | `ReputationTier`, threshold constants, `tier_from_deltas`, `tier_threshold`, `satisfies_floor`. |

The `include!`-ed files are not Rust modules: their contents live directly in
the `chio_reputation` crate-root namespace (`chio_reputation::LocalReputationCorpus`,
not `chio_reputation::model::LocalReputationCorpus`). `tests.rs`'s
`#[cfg(test)] mod tests` block reaches the private `receipt_integrity_valid`
defined in `lib.rs` through a plain `use super::*;` because both live in the
same generated file.

## Scoring paths

**Local scorecard** (`compute_local_scorecard`):

1. Filter `corpus.receipts` to those attributed to `subject_key` (via receipt
   metadata attribution, falling back to capability-lineage lookup) and
   passing `receipt_integrity_valid`.
2. Filter `corpus.capabilities` to those owned or delegated by `subject_key`.
3. Compute each of the eight metrics independently; a metric with no evidence
   reports `MetricValue::Unknown` rather than `0.0`.
4. `contribute_metric` weights and sums only `Known` metrics; `composite_score`
   is `weighted_sum / effective_weight_sum`, or `Unknown` if no metric had
   evidence.

**Imported signal** (`build_imported_reputation_signal`):

1. Compute the subject's local scorecard unconditionally, even if the import
   is later rejected.
2. Validate provenance identity fields (share id, issuer, partner, signer) for
   emptiness, whitespace, and control characters.
3. Check the caller's `ImportedTrustPolicy`: proof requirement, issuer/signer
   allowlists, max signal age, monotonic import/export timestamps, required
   trust mode.
4. Attenuate the composite score by `policy.attenuation_factor` only when
   every check passes (`accepted == true`); otherwise `attenuated_composite_score`
   is `None` and `reasons` records why.

**Feed and tier** (`ReputationFeed` to `tier_from_deltas`):

1. A caller projects ground truth (arena leaderboard rows, verdict-matrix
   runs) into a feed's `Observation` type.
2. `ReputationFeed::observe` returns a `ScoreDelta` clamped to
   `[0.0, MAX_FEED_DELTA]`.
3. `tier_from_deltas` uses `compose_deltas` (per-feed maximum) for the
   `tier_1` / `tier_2` cutoffs, and additionally requires `min_delta` to clear
   `TIER_3_PER_FEED_THRESHOLD` across at least two distinct `feed_id`s for
   `tier_3`.

## Invariants and failure modes

- `ReputationConfig::default()` has an empty `trusted_kernel_keys` set, so
  every receipt fails `receipt_integrity_valid` (kernel-key trust, receipt id
  derivation, signature, action hash) and receipt-derived metrics become
  `Unknown`. The first integrity check against an empty trust set logs one
  `tracing::warn!`; a process-wide `AtomicBool` (`EMPTY_TRUSTED_KEYS_WARNED`)
  keeps later checks silent.
- `receipt_authority_valid` additionally requires `receipt.is_allowed()`.
  Denied, cancelled, or incomplete receipts can pass integrity (and count
  toward reliability) without passing authority (and so do not count toward
  least-privilege tool usage).
- `ReputationConfig::with_trusted_kernel_keys` drops empty or
  whitespace-padded key strings so a malformed key cannot become a false
  trust anchor.
- `ScoreDelta::from_value` maps non-finite or negative inputs to `0.0` and
  caps at `MAX_FEED_DELTA`; a feed can never emit a negative delta.
- `tier_from_deltas` is monotonic: raising any single delta cannot lower the
  resulting tier (property-tested in `tests/feed_monotonicity.rs`). `tier_3`
  requires at least two distinct `feed_id`s independently clearing
  `TIER_3_PER_FEED_THRESHOLD`; repeated deltas from one `feed_id` cannot reach
  `tier_3` regardless of value.
- `build_imported_reputation_signal` rejects, rather than silently trims,
  missing share/issuer/partner/signer identity, non-monotonic
  `imported_at < exported_at`, and identity fields carrying surrounding
  whitespace or control characters.
- `#![forbid(unsafe_code)]` at the crate root.

## Dependencies

Internal: `Cargo.toml` declares
`chio-core = { package = "chio-core-types", path = "../../core/chio-core-types" }`,
so every `chio_core::` reference in this crate's source (`capability::scope`,
`receipt::body`, `receipt::decision`, `receipt::metadata`, `receipt::kinds`,
`crypto::Keypair`) resolves to `chio-core-types`, not the `chio-core` facade
crate. This crate has no dependency on `chio-kernel`, `chio-arena`,
`chio-conformance`, or any storage crate; callers project ground truth into
this crate's own observation and record shapes instead.

External: `serde` / `serde_json` for corpus, config, and signal
(de)serialization; `thiserror` for `ReputationError`; `tracing` for the
one-shot trust-misconfiguration warning. Dev-only: `proptest` for the feed and
tier monotonicity properties in `tests/feed_monotonicity.rs`.

## Extension points

`ReputationFeed` is implementable outside this crate: define an `Observation`
type and an `observe` function returning a `ScoreDelta` in
`[0.0, MAX_FEED_DELTA]`. The trait is sealed only by convention.
`tier_from_deltas` composes any slice of `ScoreDelta` regardless of which feed
produced it, so a downstream feed's deltas gate marketplace tiers the same way
the two bundled feeds (`feeds::arena_survival`, `feeds::cross_provider_equality`)
do.
