# Chio Pheromone Substrate

**Status:** v1 (Chio-owned pre-release; wire-frozen against `chio.pheromone-deposit.v1` and the sibling pheromone schemas)

**Revision history (pre-v1 drafting passes):**
- First drafting pass (2026-05-04): initial wire freeze; sqrt(N) cap framed as a Sybil-cost reducer; newcomer-discount cybersec default `N = 28`; observation-cost commitments required only for `cost_committed_only` subject classes.
- Second drafting pass (2026-05-04): three corrections. (1) `sqrt(N)` cap reframed honestly as a cost-shifter, not a cost-reducer (section 5.4). (2) Newcomer-discount default lowered to `N = 8` epochs across sectors (section 6); the prior `N = 28` is retained as a high-assurance opt-in. (3) Observation-cost commitments are now REQUIRED by default for any subject class that the participant's ladder manifest declares `destructive: true` (section 7); the previous `cost_committed_only` flag survives as a way to opt non-destructive classes into the same requirement. Wire format unchanged across these passes; the changes affect default substrate behaviour and operator guidance, not the canonical bytes.

This specification freezes the wire format for the chio-pheromone
substrate. Cross-trust pheromone surfaces in `chio-federation`,
`chio-market`, `chio-governance`, and `chio-workflow` ship against the v1 wire
format defined here; post-v1 revisions remain backward-compatible per the
additive rule in `PROTOCOL.md` section 2.

The crate boundary is a new `chio-pheromone` workspace member depending
only on `chio-core-types` and `chio-credentials` (reputation is not a
dependency; outcomes feed reputation via outcome receipts, not the other
way around). Federation gossip lives in a thin sibling module under
`chio-federation`, mirroring how `chio-revocation-oracle` and
`../crates/trust/chio-federation/src/revocation_gossip.rs` factor today.

Key words MUST, SHOULD, and MAY are used per RFC 2119. Canonical JSON
follows RFC 8785 (JCS): UTF-8, sorted object keys, no insignificant
whitespace, exact-form numbers. Signed bodies are signed over the JCS
encoding of the body with the `signature` field omitted.

**Consistency model.** All pheromone deposits are intrinsically
`crdt-commutative` in the sense defined by `spec/CHIO_LADDER.md`
section 4.1: the merge operation is concentration accumulation, FIFO
gossip with no supersession means partition-divergent peers converge
automatically on reconnect, and exponential decay bounds the
divergence window. A ladder manifest that classifies a pheromone-deposit
action class as `totally-ordered` or `quorum-required` MUST be rejected
at handshake with `ladder.consistency_class_mismatch`; pheromones are
not the right substrate for those semantics.

---

## 1. Schema Inventory

| Schema id | Artifact | Section |
|---|---|---|
| `chio.pheromone-deposit.v1` | Single signed pheromone deposit | 2 |
| `chio.pheromone-deposit-gossip.v1` | Bilateral gossip envelope for one deposit | 3 |
| `chio.pheromone-batch.v1` | Coalesced per-peer batch of gossip envelopes | 3 |
| `chio.pheromone-concentration.v1` | Result of a concentration query at an anchored epoch | 4 |
| `chio.pheromone-cost-commitment.v1` | Optional observation-cost reference attached to a deposit | 7 |
| `chio.pheromone-transit-policy.v1` | Receiver-owned relay authorization policy | 3 |

Unknown schema ids MUST be rejected fail-closed (see `PROTOCOL.md` section
2 compatibility rule).

---

## 2. PheromoneDeposit

### 2.1 Body

`chio.pheromone-deposit.v1` carries one signed deposit. The body is the
canonical JSON object below with the `signature` field excluded; the
signature is computed over that body and reattached as the value of
`signature` in the on-the-wire artifact.

| Field | Type | Required | Description |
|---|---|---|---|
| `schema` | string | Yes | MUST be `"chio.pheromone-deposit.v1"` |
| `kernel_id` | string | Yes | `did:chio` of the depositing kernel; pinned at federation handshake |
| `agent_passport_key_hash` | string | Yes | SHA-256 hex of the agent passport public key (see section 5) |
| `agent_passport_jwk_thumbprint` | string | Yes | RFC 7638 JWK thumbprint of the same key, for cross-format binding |
| `subject_class` | string | Yes | Domain-supplied class identifier (threat class, signal class, compliance class) |
| `subject_class_namespace` | string | Yes | Reverse-DNS namespace owning the class (e.g. `dev.chio.cybersec.mitre-attack`) |
| `indicator` | object | Yes | Opaque-to-substrate indicator payload; canonical JSON object |
| `severity` | string | Yes | One of `"low" \| "medium" \| "high" \| "critical"` |
| `confidence` | number | Yes | Initial deposit strength in `[0.0, 1.0]`; finite, no NaN/Infinity |
| `timestamp_unix_ms` | u64 | Yes | Deposit time in unix milliseconds (decay origin) |
| `decay_half_life_secs` | number | Yes | Per-deposit half-life in seconds; finite, strictly positive |
| `evaporation_floor` | number | No | Optional per-deposit GC floor; defaults to substrate config (see section 8) |
| `nonce` | string | Yes | 128-bit base64url replay nonce, unique within `(kernel_id, agent_passport_key_hash, replay_window)` |
| `treaty_scope` | string[] | Yes | Treaty ids under which this deposit may be gossiped (empty list means local-only) |
| `cost_commitment` | object | No | `chio.pheromone-cost-commitment.v1` body when present (see section 7) |
| `workflow_context` | object | No | Origin-owned `chio.pheromone-workflow-context.v1` body binding this deposit to workflow receipt evidence (see section 2.5) |
| `signature` | string | Yes | Ed25519 signature over the JCS encoding of this object with `signature` removed |

The `signature` field uses the self-describing encoding from
`PROTOCOL.md` section 4.1. Hybrid prefixes (`hybrid:<classical>:<pq>:<alg_set>`)
MUST be accepted by verifiers that already accept hybrid signatures elsewhere
in the Chio stack; v1 substrates MAY decline hybrid material but MUST then
reject deposits that present it rather than silently downgrade.

### 2.2 Canonical JSON ordering

Implementations MUST serialize the deposit body using RFC 8785 JCS. Object
keys are sorted lexicographically by code-point. Numbers are represented in
the shortest round-trip form. The `indicator` object is itself canonical-JSON-
encoded recursively; substrates MUST NOT re-order its keys (the depositor's
own canonicalization is authoritative).

### 2.3 Signing rule

The signing key is the agent passport key (Ed25519 by default; hybrid
prefixed per section 2.1). Kernel keys MUST NOT be used to sign deposits;
verifiers MUST reject any deposit whose `signature` validates only against a
kernel key. This is the source-diversity load-bearing property called out in
section 5.

### 2.4 Replay window

A deposit's `(kernel_id, agent_passport_key_hash, nonce)` tuple is unique
within a sliding replay window. The window length is a substrate
configuration parameter; the recommended default is 24 hours. Deposits
outside the window MUST be rejected with `replay_window_exceeded`.

### 2.5 Workflow context

`workflow_context`, when present, is origin-owned and part of the signed
deposit body. Relays MUST NOT rewrite it. Receivers MUST treat any mismatch
between this context and locally resolved workflow evidence as fail-closed
with `workflow_context_mismatch`.

`chio.pheromone-workflow-context.v1`:

| Field | Type | Required | Description |
|---|---|---|---|
| `schema` | string | Yes | MUST be `"chio.pheromone-workflow-context.v1"` |
| `workflow_id` | string | Yes | Workflow id the deposit comments on |
| `workflow_receipt_id` | string | Yes | Stable workflow receipt id |
| `workflow_receipt_sha256` | string | Yes | SHA-256 of the canonical workflow receipt artifact |
| `workflow_intersection_id` | string | Yes | Chio workflow-intersection artifact id |
| `workflow_intersection_sha256` | string | Yes | SHA-256 of the canonical workflow intersection artifact |
| `step_index` | u64 | Yes | Workflow step index |
| `tool_receipt_id` | string | Yes | Tool receipt id referenced by the step |
| `bilateral_dsse_sha256` | string | Yes | SHA-256 of the strict bilateral DSSE envelope for the step |
| `consistency_anchor` | string | Yes | Consistency anchor expected by the strict bilateral predicate |

The context carries ids and hashes only. Raw workflow inputs, tool arguments,
indicators, and private customer data MUST NOT be copied into this object.

---

## 3. Federation Gossip

The gossip pattern mirrors `../crates/trust/chio-federation/src/revocation_gossip.rs`:
bilateral push queues, per-peer FIFO ring, deterministic flush. Pheromones
differ from revocation roots in two ways: (a) **no supersession**: a newer
deposit never replaces an older one (concentration is a sum, not a current
state); (b) **per-origin rate limit**: every peer enforces a token bucket
keyed on `(kernel_id, agent_passport_key_hash)` of the originating depositor,
not the gossiping peer.

### 3.1 PheromoneDepositGossip envelope

`chio.pheromone-deposit-gossip.v1`:

| Field | Type | Required | Description |
|---|---|---|---|
| `schema` | string | Yes | MUST be `"chio.pheromone-deposit-gossip.v1"` |
| `deposit` | object | Yes | A `chio.pheromone-deposit.v1` body (signature included) |
| `origin_kernel_id` | string | Yes | MUST equal `deposit.kernel_id`; mirrored outside for cheap routing |
| `gossiping_peer_kernel_id` | string | Yes | The bilateral peer pushing this frame (may differ from `origin_kernel_id`) |
| `treaty_id` | string | Yes | The treaty under which this frame is scoped; MUST appear in `deposit.treaty_scope` |
| `ts_unix_ms` | u64 | Yes | Sender wall-clock at frame emission, for freshness gating |
| `transit_chain` | object | No | Relay-owned `chio.pheromone-transit-chain.v1`; absent for direct treaty gossip |

Receivers MUST run the structural envelope check (schema + origin agreement),
then validate treaty authorization. Direct gossip has no `transit_chain` and
requires `treaty_id` to appear in `deposit.treaty_scope`. Relayed gossip MAY
use a downstream `treaty_id` absent from `deposit.treaty_scope` only when the
transit chain proves an ingress treaty in scope and every hop is authorized by
fresh pinned ladder material. Receivers then run `validate_deposit`
(signature, replay nonce, diversity caps, observation-cost gate where
required) before merging the deposit into local storage. Failures are dropped
fail-closed.

### 3.1.1 Transit chain

`chio.pheromone-transit-chain.v1` is relay-owned envelope metadata. It is not
part of the origin-signed deposit body, and relays MAY append hops without
invalidating the origin signature. Receivers MUST reject a transit chain that
is empty, exceeds the local hop cap, repeats a kernel id, breaks hop
adjacency, uses stale ladder references, omits a required ladder intersection,
or declares a non-`crdt-commutative` pheromone action class.

Each hop carries:

| Field | Type | Required | Description |
|---|---|---|---|
| `from_kernel_id` | string | Yes | Kernel id sending the deposit on this hop |
| `to_kernel_id` | string | Yes | Kernel id receiving the deposit on this hop |
| `treaty_id` | string | Yes | Treaty authorizing this hop |
| `ladder_manifest_ref` | object | Yes | Fresh pinned ladder manifest reference for the sending peer |
| `ladder_intersection_id` | string | Yes | Co-signed ladder intersection authorizing the pheromone class |
| `action_class_id` | string | Yes | Action class, normally `whisker.pheromone_deposit` or a deployment alias |
| `emitted_at_unix_ms` | u64 | Yes | Sender wall-clock when this hop was emitted |

The first hop's treaty MUST appear in `deposit.treaty_scope`. The last hop's
treaty MUST equal the enclosing gossip frame's `treaty_id`.

### 3.1.2 Transit policy

`chio.pheromone-transit-policy.v1` is verifier-owned receiver input. It
declares accepted relay hubs, ingress treaty ids, egress treaty ids, subject
class namespaces, maximum hop count, and validity window. Package-carried or
frame-carried material MUST NOT add transit trust.

### 3.2 PheromoneBatch envelope

`chio.pheromone-batch.v1` is the per-peer flush product. Like
`RevocationGossipBatch`, batches are never empty (peers with no pending
frames are omitted from the flush result).

| Field | Type | Required | Description |
|---|---|---|---|
| `schema` | string | Yes | MUST be `"chio.pheromone-batch.v1"` |
| `recipient_kernel_id` | string | Yes | Bilateral peer this batch is addressed to |
| `treaty_id` | string | Yes | Subscription treaty scope (one batch per peer per treaty per flush) |
| `frames` | object[] | Yes | Strictly FIFO sequence of `chio.pheromone-deposit-gossip.v1` envelopes |
| `flushed_at_unix_ms` | u64 | Yes | Batch construction wall-clock |

Frames within a batch are delivered in FIFO order. The substrate MUST NOT
reorder by epoch or coalesce by deposit identity (contrast with the
revocation-root case, where same-epoch coalescing is correct).

### 3.3 Subscription scope

Subscription is per-treaty: a peer subscribes to `(peer_kernel_id, treaty_id)`
on the push queue. A deposit is enqueued for a peer iff the peer holds a
subscription whose `treaty_id` is contained in the deposit's `treaty_scope`.
Treaty handshake (out of scope here; lives with the ladder manifest in
`spec/CHIO_LADDER.md` to be written) defines the subject-class allowlist
within a treaty.

### 3.4 Per-origin rate limit

Every receiver enforces a token bucket keyed on
`(origin_kernel_id, deposit.agent_passport_key_hash, treaty_id)`. The
bucket capacity and refill rate are substrate configuration; defaults
SHOULD be tuned so honest agents under steady load consume well below 50%
of the bucket. Frames whose origin tuple has exhausted its bucket MUST be
dropped with `rate_limit_exhausted` (the deposit is not stored; concentration
queries cannot reference it; the gossip layer MAY surface a metric).

### 3.5 Catch-up

v1 does not specify a catch-up protocol analogous to
`RevocationCatchupRequest`. Pheromones decay (section 8) and are not
canonical state that diverges if missed; receivers recover via newer
deposits. Post-v1 revisions MAY add bounded historical replay; v1
does not require it.

---

## 4. Concentration Query

### 4.1 PheromoneConcentration result

`chio.pheromone-concentration.v1` is the response shape returned by the
`query_concentration` substrate method:

| Field | Type | Required | Description |
|---|---|---|---|
| `schema` | string | Yes | MUST be `"chio.pheromone-concentration.v1"` |
| `subject_class` | string | Yes | Class queried |
| `subject_class_namespace` | string | Yes | Namespace queried |
| `total_strength` | number | Yes | Sum of decayed, weighted strengths over surviving deposits |
| `unweighted_total_strength` | number | Yes | Same sum without per-peer reputation weighting (for diagnostics) |
| `distinct_origin_pairs` | u64 | Yes | Count of distinct `(kernel_id, agent_passport_key_hash)` pairs contributing |
| `peak_confidence` | number | Yes | Max raw `confidence` among contributing deposits before decay or weighting |
| `reputation_epoch` | u64 | Yes | The chio-anchor epoch the reputation closure was pinned to (see 4.3) |
| `evaluated_at_unix_ms` | u64 | Yes | Substrate wall-clock at which `t = now` was sampled for decay |
| `treaty_scopes` | string[] | Yes | Sorted unique set of treaty ids whose deposits contributed |

### 4.2 `concentration_weighted` interface

The reputation-weighted form takes a peer-weight closure injected by the
chio runtime. The substrate stays unaware of reputation; this preserves the
"no cycle into chio-reputation" property.

```rust
fn query_concentration_weighted(
    subject_class: &SubjectClass,
    now_unix_ms: u64,
    reputation_epoch: u64,
    peer_weight: &dyn Fn(&KernelId, u64) -> f64,
) -> Result<PheromoneConcentration, SubstrateError>;
```

The closure receives the contributing kernel id and the
`reputation_epoch` and returns a finite weight in `[0.0, 1.0]`. Returning
`NaN`, `Infinity`, or a value outside `[0.0, 1.0]` MUST cause the
substrate to fail-closed with `weight_out_of_range`. Per-deposit
contribution to `total_strength` is:

```
weighted_contribution = strength_at(t) * peer_weight(kernel_id, reputation_epoch)
                      * newcomer_discount(passport, reputation_epoch)
```

`unweighted_total_strength` is the same sum with `peer_weight` and
`newcomer_discount` both replaced by `1.0`.

### 4.3 Reputation epoch pinning

`reputation_epoch` is a chio-anchor epoch identifier (see
`../crates/economy/chio-anchor/src/lib.rs`). Pinning makes results reproducible:
a third party that reconstructs from the deposit corpus and the same
anchored reputation snapshot recovers the same `total_strength`.
Substrates MUST refuse a query whose `reputation_epoch` is unknown to
the local anchor view (no silent fallback to the latest epoch).

---

## 5. Source Diversity Rules

### 5.1 Per-agent passport signing

Deposits MUST be signed by per-agent passport keys (the keys minted under
`chio.agent-passport.v1`; see `../crates/trust/chio-credentials/src/lib.rs`).
Kernel keys are explicitly rejected: a deposit whose verifying key matches
the kernel's federation identity MUST be rejected with
`unknown_origin_agent`.

### 5.2 Origin counting

Origin diversity is counted as the number of distinct
`(kernel_id, agent_passport_key_hash)` pairs contributing to a
concentration. A single kernel running ten passports counts as ten origins
only if all ten are bound to live, non-revoked agent passports under that
kernel's federation handshake; revoked or expired passports MUST NOT count.

### 5.3 Per-pair token bucket

Every substrate enforces a token bucket per
`(kernel_id, agent_passport_key_hash, subject_class)` per anchored epoch.
Overruns reject the deposit fail-closed with `diversity_cap_exceeded`. The
bucket parameters are configurable; the recommended default leaves
substantial headroom for honest agents (see `docs/PHEROMONES.md` for the
swarm-team-six tuning that motivates these defaults).

### 5.4 Per-kernel sqrt(N) cap

Each receiving kernel MUST cap, per subject-class per window, the number
of distinct `agent_passport_key_hash` values it accepts from any single
origin kernel at `ceil(sqrt(active_peers_in_treaty))`, where
`active_peers_in_treaty` is the count of bilateral peers admitted under
the treaty during the window. Overruns reject the marginal deposit with
`sqrt_n_passport_cap_exceeded`. The window length SHOULD be aligned with
the reputation epoch cadence so cap exhaustion and reputation snapshots
turn over together.

**Honest framing of what the cap does** (corrected in a pre-v1
drafting pass from earlier framing). The cap is a **cost-shifter, not
a cost-reducer**. For a fixed dollar budget, the `sqrt(N)` term cancels out of
the closed-form attacker-budget expression: an adversary capped on
passport keys per kernel is forced to provision more cover operator-orgs
to spread the same passport mass, and the operator-org admission cost
absorbs the savings on key issuance one-for-one. The cap therefore does
not reduce the total dollar cost of mounting a Sybil flood; it shifts
the cost between line items. Tightening the cap to `log(N)` would
provide zero additional economic protection. The reasons the cap is
nonetheless mandatory are forensic, not economic: (1) it forces the
attacker's operator-org admissions onto the federation handshake
surface, where they are visible artefacts that can be sanctioned by
out-of-band governance (`chio-governance` Sanction case against the
issuing org); (2) it prevents a single compromised kernel from
mass-minting passports without observable footprint; and (3) it caps
the per-kernel reputation-graph fan-out so collusion-cluster Jaccard
penalties (defined in `chio-reputation`) remain computable in bounded
time. Calibrate the cap with these forensic properties in mind, not as
a quantitative Sybil deterrent.

The substrate-layer defenses that DO move the dollar-cost breakeven are
the newcomer discount horizon `N` (section 6), the observation-cost
commitment requirement (section 7), and the underlying passport-issuance
cost `C` set by the participant's identity policy (hardware attestation
versus software keys).

---

## 6. Newcomer Discount

A passport's effective weight in concentration aggregation is
`min(1.0, age_in_anchored_epochs(passport, reputation_epoch) / N)`,
where the age is the count of chio-anchor epochs between the passport's
first observation under the treaty and `reputation_epoch`, inclusive.
`N` is the participant's `newcomer_discount_horizon`, declared in the
ladder manifest.

**Default**: `N = 8` epochs across all sectors (revised in a pre-v1
drafting pass from the earlier cybersec default of `N = 28`). The
`N = 8` is the breakeven point at which (a) the newcomer-discount linearly amortises the
passport-issuance cost in the attacker-budget formula and (b) honest
agents reach full weight within operationally reasonable onboarding
(about a week at one epoch per day) without giving low-cost Sybil
passports a useful fraction of weight before sanction can land.
`N` MAY be raised (the pre-v1 cybersec `N = 28` is retained as a
high-assurance opt-in for sectors that are willing to trade onboarding
latency for adversary-budget headroom)
and MAY be lowered for fast-churn sectors with strong out-of-band
identity verification, but participants SHOULD NOT lower `N` below `4`
without an explicit out-of-band roster issuer (see
Tier 1 high-assurance sectors).

The discount mitigates whitewashing: a freshly minted passport from a
sanctioned org carries no weight until it accumulates anchored history.
Combine with the passport-revocation bridge
(`chio-revocation-oracle::passport_bridge`) so freshly-issued passports
inherit org-level sanctions.

---

## 7. Observation-Cost Commitment

Depositors attach a verifiable reference to the telemetry observation
that produced the deposit. The `cost_commitment` field on the deposit
body carries a `chio.pheromone-cost-commitment.v1` object:

| Field | Type | Required | Description |
|---|---|---|---|
| `schema` | string | Yes | MUST be `"chio.pheromone-cost-commitment.v1"` |
| `telemetry_chain_root` | string | Yes | SHA-256 hex of the depositor's telemetry hash chain head at observation time |
| `chain_position` | u64 | Yes | Index within the chain at which the observation was recorded |
| `chain_position_proof` | string | Yes | Chain inclusion proof (canonical JSON; depositor-defined shape) |
| `observed_at_unix_ms` | u64 | Yes | Wall-clock at which the underlying observation was recorded |

**When the substrate MUST require this field** (revised in a pre-v1
drafting pass):

1. **Always**, for any subject class that the participant's ladder
   manifest (`spec/CHIO_LADDER.md`) declares `destructive: true`.
   This is the v1 default; observation-cost commitments add a multiplicative
   term `m_oc` to the attacker-budget formula that no passport-key-cap
   manipulation can offset, and
   destructive subject classes are exactly the ones whose poisoning
   produces irreversible harm. Substrates MUST reject deposits in
   destructive classes that arrive without a `cost_commitment` field
   with `observation_cost_commitment_required`.

2. **Optionally**, for any subject class explicitly flagged
   `cost_committed_only` in the ladder manifest. This was the
   earlier-drafting-pass trigger (now widened) and survives as the way
   to opt non-destructive classes into the same requirement (e.g., a
   detection-deposit class whose downstream consumers run automated
   actions).

3. **Never required by the substrate** for non-destructive,
   non-`cost_committed_only` classes. Depositors MAY still attach a
   commitment voluntarily; receivers MAY weight uncommitted deposits
   lower as a matter of local reputation policy, but the substrate
   itself MUST NOT reject them.

The substrate MUST NOT itself verify the chain inclusion proof; that
is the responsibility of the chio runtime, which MAY weight or
discount deposits whose commitments fail later verification (this
preserves substrate simplicity and keeps the verification surface in
the runtime where reputation lives).

This field implements the verifiable observation-cost commitment requirement,
which prevents a peer from co-signing without originating evidence.

---

## 8. Decay and Garbage Collection

Per-deposit strength at time `t` (unix milliseconds, internally converted
to seconds for the decay arithmetic) is:

```
s(t) = confidence * 2 ^ ( -((t - t0) / 1000) / half_life )
```

where `t0 = timestamp_unix_ms` and `half_life = decay_half_life_secs`.
For `t <= t0`, `s(t) = confidence`. The formula is identical to the
swarm-team-six reference (`docs/PHEROMONES.md` section 3) and to
`PheromoneDeposit::strength_at` in
`crates/swarm-pheromone/src/substrate.rs`.

A deposit is **evaporated** when `s(t) < evaporation_floor`. The
substrate-level `evaporation_floor` default is `0.01`; per-deposit
overrides take precedence. `gc_evaporated(now_unix_ms)` walks the local
store and removes evaporated deposits, returning the count. Evaporated
deposits MUST NOT contribute to concentration queries even before GC
removes them: the query path applies the same threshold inline.

GC is a storage optimization; correctness does not require frequent
runs. Recommended cadence is one minute for high-volume subject classes,
one hour otherwise.

---

## 9. Substrate Trait Surface

The crate exports a single `PheromoneSubstrate` trait. Storage backends
(in-memory reference, local journal reference, JetStream / NATS adapter,
SQL adapter) live in adapter crates so the "no host required" property
from `PROTOCOL.md` survives.

```rust
#[async_trait]
pub trait PheromoneSubstrate: Send + Sync {
    async fn deposit(&self, deposit: PheromoneDeposit)
        -> Result<(), SubstrateError>;

    async fn query_deposits(&self, query: DepositQuery)
        -> Result<Vec<PheromoneDeposit>, SubstrateError>;

    async fn query_concentration(
        &self,
        subject_class: &SubjectClass,
        now_unix_ms: u64,
        reputation_epoch: u64,
        peer_weight: &dyn Fn(&KernelId, u64) -> f64,
    ) -> Result<PheromoneConcentration, SubstrateError>;

    async fn gc_evaporated(&self, now_unix_ms: u64)
        -> Result<usize, SubstrateError>;
}
```

JSON return shapes: `deposit` returns nothing on success or a
`{"error": <code>, "detail": <string>}` envelope; `query_deposits`
returns an array of `chio.pheromone-deposit.v1` objects;
`query_concentration` returns one `chio.pheromone-concentration.v1`
object; `gc_evaporated` returns
`{"removed_count": <u64>, "evaluated_at_unix_ms": <u64>}`.

The trait is intentionally narrow. Higher-level helpers (escalation
records, threat-class config storage) that the swarm-team-six reference
exposes are runtime concerns, not substrate concerns.

---

## 10. Failure Modes

All rejections are fail-closed: the substrate refuses to store the
deposit, refuses to enqueue it for gossip, and refuses to count it in
concentration queries. Error codes are stable strings used in the
canonical error envelope (see `spec/errors/`).

| Code | Cause |
|---|---|
| `signature_invalid` | Ed25519 (or hybrid) verification failed |
| `signature_key_mismatch` | `agent_passport_key_hash` does not match the verifying key used |
| `unknown_origin_agent` | Verifying key is not a passport key admitted under `kernel_id` (or is a kernel key) |
| `kernel_key_used_for_deposit` | Verifying key matches a kernel federation identity |
| `replay_window_exceeded` | `(kernel_id, agent_passport_key_hash, nonce)` already seen within window |
| `treaty_scope_violation` | Gossip frame's `treaty_id` not present in `deposit.treaty_scope` |
| `unknown_treaty` | `treaty_id` is not currently subscribed |
| `rate_limit_exhausted` | Per-origin token bucket exhausted for the relevant `(origin, treaty)` |
| `diversity_cap_exceeded` | Per-pair token bucket exhausted for the epoch |
| `sqrt_n_passport_cap_exceeded` | Origin kernel has exceeded `ceil(sqrt(active_peers))` passports for the class |
| `observation_cost_commitment_required` | Subject class is `cost_committed_only` and `cost_commitment` is absent |
| `weight_out_of_range` | Reputation closure returned a value outside `[0.0, 1.0]` or non-finite |
| `unknown_reputation_epoch` | `reputation_epoch` is not present in the local anchor view |
| `confidence_out_of_range` | `confidence` is non-finite or outside `[0.0, 1.0]` |
| `half_life_invalid` | `decay_half_life_secs` is non-finite, zero, or negative |
| `unsupported_schema` | `schema` field does not match a known v1 identifier |
| `subject_class_unknown` | Subject class not in the treaty's allowlist |

Error envelopes follow the `chio.error.v1` shape used elsewhere in the
spec; see `spec/errors/README.md`.

---

## 11. Optional ZK Selective Disclosure (deferred to selective-disclosure spec)

The selective-disclosure mechanism for chio receipts (including
pheromone deposits) is normatively specified in
`spec/CHIO_SELECTIVE_DISCLOSURE.md` (v1). The high-level
direction:

- BBS+ projection over the deposit body (`bbs-2023` cryptosuite plus
  AnonCreds v2 `RangeStatement` predicates) enabling proofs of the
  form "concentration in class C at anchored epoch E exceeds threshold
  T" without revealing indicators or per-deposit confidences.
- Ed25519 signature over JCS remains the authoritative wire signature
  on a deposit; the BBS+ signature is a secondary commitment over the
  same projected messages.
- Predicate language frozen at `eq` / `cmp(<, <=, >, >=)` /
  `member(merkle_root)`, AND-composed up to 8 clauses.
- A zkVM (Risc0/SP1 + Groth16 wrap) escape hatch covers chained-receipt
  proofs and predicates over the Ed25519 signature itself; not in
  v1 of the disclosure spec.

This pheromone spec does not freeze the BBS+ wire shape itself. The
disclosure spec owns the `bbs_messages()` projection ordering, the
disclosure envelope schema, and the verification algorithm.
Implementations MAY emit BBS+ material under an experimental
`bbs_v01_messages` field on a deposit; receivers MUST ignore unknown
fields per the additive-fields rule. The field name tracks the
disclosure-spec projection identifier and MUST be updated as that
identifier evolves.

---

## 12. Test Corpus Expectations

The `chio-pheromone` crate ships, at minimum, the following fixtures
under `crates/trust/chio-pheromone/tests/fixtures/`:

1. **deposit-roundtrip.json**: a valid deposit body, its JCS encoding,
   and its Ed25519 signature; re-canonicalize, re-sign, verify
   bit-exact equality.
2. **deposit-signature-tamper.json**: same deposit with one byte of
   `confidence` flipped; MUST fail with `signature_invalid`.
3. **deposit-kernel-key.json**: deposit signed by a kernel federation
   key; MUST be rejected with `kernel_key_used_for_deposit`.
4. **gossip-roundtrip.json**: a `chio.pheromone-batch.v1` carrying
   three gossip envelopes; push through an in-memory bilateral queue,
   assert FIFO preservation, no coalescing, per-treaty scoping.
5. **concentration-weighted.json**: deposits across three origin
   kernels at known confidences and timestamps; evaluate
   `query_concentration_weighted` with a closure assigning
   `(kernel_a -> 0.8, kernel_b -> 0.5, kernel_c -> 0.0)` at a fixed
   `reputation_epoch`; assert `total_strength` and
   `unweighted_total_strength` to within `1e-9`.
6. **diversity-cap-negative.json**: origin kernel pushes
   `ceil(sqrt(active_peers)) + 1` distinct passports for one subject
   class in one window; assert marginal rejection with
   `sqrt_n_passport_cap_exceeded` while prior deposits remain stored.
7. **per-pair-bucket-negative.json**: a single
   `(kernel_id, agent_passport_key_hash)` exhausts its bucket; the
   next deposit in the epoch is rejected with `diversity_cap_exceeded`.
8. **observation-cost-required.json**: a deposit in a
   `cost_committed_only` class without `cost_commitment` is rejected
   with `observation_cost_commitment_required`.
9. **newcomer-discount.json**: a passport first seen at
   `reputation_epoch - 5` queried at `reputation_epoch` with `N = 28`;
   discount factor is `5/28` and the strength contribution matches.
10. **decay-table.json**: tabulated `(confidence, half_life, elapsed)`
    triples and expected `s(t)` values matching the worked examples in
    `docs/PHEROMONES.md`.

Each fixture is reproducible from its inputs via the canonical-JSON and
signing rules in sections 2.2 and 2.3; CI MUST regenerate and diff to
guard against silent format drift.

---

## 13. Open Questions Deferred Post-v1

- Catch-up replay (section 3.5).
- BBS+ projection ordering and secondary-keypair binding (section 11).
- Cross-domain subject-class translation tables (the
  `subject_class_namespace` field is forward-compatible; translation
  rules live with the ladder manifest spec).
- Hybrid-signature acceptance policy on the substrate side.
