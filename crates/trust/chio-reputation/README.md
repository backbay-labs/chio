# chio-reputation

`chio-reputation` computes deterministic reputation scores and marketplace
tiers for Chio agents from caller-supplied evidence: persisted receipts,
capability-lineage records, and budget-usage records. The crate is pure and
storage-agnostic. It has no dependency on `chio-kernel` or any storage crate,
so kernel-side issuance policy and marketplace tooling can depend on it
without a dependency cycle.

Two independent scoring paths share the crate: a weighted local scorecard
(`compute_local_scorecard`) for descriptive scoring and cross-operator trust
import, and a feed/tier system (`ReputationFeed`, `ReputationTier`) for
discrete marketplace-visibility gating.

## Responsibilities

- Compute a weighted `LocalReputationScorecard` (boundary pressure, resource
  stewardship, least privilege, history depth, specialization, delegation
  hygiene, reliability, incident correlation) from a `LocalReputationCorpus`,
  excluding metrics with no evidence from the composite average instead of
  scoring them zero.
- Fail closed on receipt evidence: a receipt only counts once its kernel key
  is in `ReputationConfig::trusted_kernel_keys` and its id, signature, and
  action hash all verify.
- Detect delegation-hygiene reductions (scope, TTL, budget) between a parent
  and child `CapabilityLineageRecord` by walking `ChioScope` grants.
- Validate and, when accepted, attenuate an `ImportedReputationSignal` from
  another operator against a caller's `ImportedTrustPolicy` (proof
  requirement, issuer/signer allowlists, max age, monotonic timestamps, trust
  mode).
- Compose `ReputationFeed` observations (arena survival, cross-provider
  equality) into `ScoreDelta`s and map them to a discrete `ReputationTier`
  (`tier_0`-`tier_3`), with a distinct-feed gate at `tier_3` for Sybil
  resistance.

## Public API

Local scorecard (crate root):

- `compute_local_scorecard(subject_key, now, &LocalReputationCorpus, &ReputationConfig) -> LocalReputationScorecard`
- `LocalReputationCorpus`, `CapabilityLineageRecord`,
  `CapabilityLineageScopeJsonInput`, `BudgetUsageRecord`, `IncidentRecord` -
  corpus input shapes
- `ReputationConfig`, `ReputationWeights` - scoring configuration;
  `ReputationConfig::with_trusted_kernel_keys` is the only way to make receipt
  evidence count
- `LocalReputationScorecard` and its metric fields (`BoundaryPressureMetrics`,
  `ResourceStewardshipMetrics`, `LeastPrivilegeMetrics`, `HistoryDepthMetrics`,
  `SpecializationMetrics`, `DelegationHygieneMetrics`, `ReliabilityMetrics`,
  `IncidentCorrelationMetrics`, `MetricValue`)
- `ReputationError`

Imported signals (crate root):

- `build_imported_reputation_signal(subject_key, provenance, &corpus, now, &config, &policy) -> ImportedReputationSignal`
- `ImportedReputationProvenance`, `ImportedIssuerIdentity`,
  `ImportedTrustPolicy`, `ImportedTrustMode`, `ImportedReputationSignal`

Feeds and tiers (`feed`, `feeds`, `tier` modules; `feed` and `tier` re-export
at the crate root):

- `ReputationFeed` trait, `ScoreDelta`, `compose_deltas`, `min_delta`,
  `MAX_FEED_DELTA`
- `feeds::arena_survival::{ArenaSurvivalFeed, ArenaRoundOutcome, ArenaRoundsObservation}`
- `feeds::cross_provider_equality::{CrossProviderEqualityFeed, VerdictCaseOutcome, VerdictMatrixObservation}`
- `ReputationTier`, `tier_from_deltas`, `tier_threshold`, `satisfies_floor`,
  `MAX_COMPOSED_SCORE`, `TIER_1_THRESHOLD`, `TIER_2_THRESHOLD`,
  `TIER_3_THRESHOLD`, `TIER_3_PER_FEED_THRESHOLD`

## Usage

```rust
use chio_reputation::{compute_local_scorecard, LocalReputationCorpus, ReputationConfig};

let config = ReputationConfig::default()
    .with_trusted_kernel_keys([kernel.public_key().to_hex()]);
let corpus = LocalReputationCorpus::default();
let scorecard = compute_local_scorecard("agent-1", now, &corpus, &config);
```

`ReputationConfig::default()` has an empty trust set, which fails every
receipt closed; populate `trusted_kernel_keys` before scoring or
receipt-derived metrics stay `Unknown`.

## Testing

`cargo test -p chio-reputation`

## See also

- `chio-core-types` - supplies the receipt, capability-scope, and crypto types
  this crate scores against (imported here as `chio_core` via a `Cargo.toml`
  package alias).
- `chio-control-plane` - consumes `ReputationConfig` and
  `compute_local_scorecard` for reputation-gated issuance policy.
- `chio-guard-registry` - filters marketplace guard visibility by
  `ReputationTier`.
- `chio-credentials` - builds portable reputation exports on top of
  `LocalReputationScorecard`.
