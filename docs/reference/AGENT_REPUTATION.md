# Agent Reputation System

**Status:** Design proposal with local scoring, issuance gating, `did:chio`, and Agent Passport alpha implemented in the current pre-release v1 branch
**Authors:** Chio Protocol Team

> Historical internal milestone note. `v2.x` labels in this document are
> pre-release implementation milestones, not Chio-owned protocol, schema, SDK,
> or runtime versions. Current protocol posture is v1-only.

---

## 1. Overview

Chio already emits most of the raw events needed to build a comprehensive local
agent reputation system. Every tool invocation -- whether allowed, denied,
cancelled, or incomplete -- produces a signed `ChioReceipt` appended to the
configured receipt store; the bundled SQLite-backed store enforces append-only
semantics through `BEFORE UPDATE` / `BEFORE DELETE` triggers and is paired with
signed Merkle checkpoints and inclusion proofs.
Every capability token records its scope, delegation chain, time bounds, and
invocation budget.

Those local persistence prerequisites are present in the current
pre-release v1 branch:

1. A capability lineage index keyed by `capability_id`, so receipts can be
   joined to `CapabilityToken.subject`, issuer, grants, and delegation
   metadata without replaying issuance logs.
2. Deterministic receipt-side attribution metadata, so a receipt can be joined
   to the matched grant and acting subject without inference.

These are local storage changes, not new external telemetry. Local scoring
can therefore be computed reproducibly from persisted local state.

Three properties make this uniquely valuable:

1. **Completeness.** The Kernel is the sole nexus for all tool access.
   There is no side channel an agent can use to act without producing a
   receipt. The audit trail is total.

2. **Integrity.** Receipts are Ed25519-signed by the Kernel and stored in
   the configured receipt store; the bundled SQLite-backed store enforces
   append-only semantics through `BEFORE UPDATE` / `BEFORE DELETE` triggers.
   Merkle checkpoints and inclusion proofs are implemented in the pre-release
   v1 durability path, enabling tamper-evident receipt verification locally
   and in exported evidence bundles.

3. **Network effects.** If a portable, cryptographically verifiable agent
   reputation layer gains adoption, each additional receipt and each
   additional participating operator make the signal more useful.

---

## 2. Metrics Derivable from Receipts and Local Lineage Data

Every metric below is computable from fields that already exist on
`ChioReceipt`, `CapabilityToken`, `DelegationLink`, and the existing budget
usage records, provided the runtime persists the local join paths described in
Section 1.

**Note on agent identification:** Current v1 receipts can carry
`metadata.attribution.subject_key`, which provides the acting agent's public
key directly. The capability lineage index is still needed when the scorer
needs the full grant set, issuer history, or delegation chain for that
capability.

**Metric availability tiers:**
- **Direct from receipts:** boundary pressure, reliability, history depth, tool diversity
- **Receipts + receipt attribution:** agent identity, per-grant budget discipline
- **Receipts + capability lineage index:** least privilege, delegation hygiene, risk weighting
- **Receipts + external incident reports:** incident correlation

### 2.1 Deny Ratio (boundary_pressure)

How often the agent hits enforcement boundaries.

**Receipt fields used:**
- `decision.verdict` -- one of `Allow`, `Deny`, `Cancelled`, `Incomplete`
- `policy_hash` -- SHA-256 of the policy that was applied
- `tool_name` / `tool_server` -- which tool triggered the denial
- `evidence[].guard_name` -- which guard denied (e.g. `forbidden-path`, `shell-command`, `egress-allowlist`)

**Computation:**

```
boundary_pressure(agent, policy, window) =
    count(decision == Deny) / count(all receipts)
    where receipt.policy_hash == policy
    and   receipt.timestamp in window
```

Normalized by `policy_hash` so that an agent operating under a strict policy
is not penalized relative to one under a permissive policy. A high deny ratio
under a permissive policy is a stronger negative signal than a high deny ratio
under a restrictive one.

**Granularity variants:**
- Per-guard deny ratio (which guards fire most often)
- Per-tool deny ratio (which tools the agent misuses)
- Deny streak length (consecutive denials suggest confused or adversarial behavior)

### 2.2 Budget Discipline (resource_stewardship)

How efficiently the agent uses its allotted invocation budget.

**Capability fields used:**
- `scope.grants[].max_invocations` -- budget ceiling per tool grant
- Receipt or budget-usage count per `(capability_id, grant_index)` --
  actual consumption. Budget tracking in the Kernel is keyed by the pair
  `(capability_id, grant_index)`, not by `capability_id` alone, because a
  single capability may contain multiple grants with independent budgets.

**Computation:**

```
resource_stewardship(agent, capability_id, grant_index) =
    actual_invocations / max_invocations
    where receipt.capability_id == capability_id
    and   grant_index matches the specific grant
    and   receipt.decision == Allow
```

In that internal milestone this metric can use `receipt.metadata.attribution.grant_index` as the
deterministic receipt-side grant join. The lineage index remains useful for
recovering the full grant definition and delegation context for that receipt.

A score near 1.0 means the agent consumes its full budget. A score near 0.0
means the agent requested a large budget but used little of it. Neither
extreme is inherently good or bad -- the signal is in the pattern across
many capabilities:

- Consistently near 0.0: agent over-requests authority (hoarding)
- Consistently at 1.0 with subsequent re-requests: agent under-budgets
- Erratic variance: agent behavior is unpredictable

### 2.3 Scope Parsimony (least_privilege_score)

Whether the agent requests the narrowest scope sufficient for its task.

**Capability fields used:**
- `scope.grants[]` -- the full set of `ToolGrant` entries
- `scope.grants[].operations` -- `invoke`, `read_result`, `delegate`, etc.
- `scope.grants[].constraints` -- `PathPrefix`, `DomainExact`, etc.
- Receipt `tool_name` values -- which tools were actually invoked

**Computation:**

```
least_privilege_score(agent, capability_id) =
    |tools_actually_used| / |tools_in_scope|
    * constraint_density_factor
    * operation_narrowness_factor
```

Where:
- `tools_actually_used` = distinct `tool_name` values in receipts for this capability
- `tools_in_scope` = count of `ToolGrant` entries in the capability's `ChioScope`
  (note: `ChioScope` also contains `resource_grants` and `prompt_grants`;
  these are excluded from tool-focused metrics but may inform future
  resource-usage scoring)
- `constraint_density_factor` = bonus for having non-empty `constraints` on grants
- `operation_narrowness_factor` = bonus for requesting only `invoke` vs. `invoke + delegate`

An agent that requests `[invoke, delegate, read_result]` on 10 tools but only
invokes 2 of them scores poorly. An agent that requests `[invoke]` on exactly
the 2 tools it uses, with `PathPrefix` constraints, scores well.

### 2.4 History Depth

How long and how actively the agent has been operating.

**Receipt fields used:**
- `id` -- UUIDv7, encodes creation timestamp in the high bits
- `timestamp` -- unix seconds

**Computation:**

```
history_depth(agent) = {
    receipt_count:  total receipts
    active_days:    distinct calendar days with at least one receipt
    first_seen:     min(receipt.timestamp)
    last_seen:      max(receipt.timestamp)
    span_days:      (last_seen - first_seen) / 86400
    activity_ratio: active_days / span_days
}
```

A high `receipt_count` with a low `span_days` means the agent is new but
prolific. A high `span_days` with a high `activity_ratio` means the agent
is established and consistently active. Both dimensions matter.

### 2.5 Tool Diversity (specialization_index)

Whether the agent uses a broad or narrow set of tools.

**Receipt fields used:**
- `tool_name` -- which tool was invoked
- `tool_server` -- which server hosts the tool

**Computation:**

```
specialization_index(agent, window) =
    shannon_entropy(tool_distribution)
    where tool_distribution = frequency of each (tool_server, tool_name) pair
    across all receipts in window
```

High entropy means the agent uses many tools roughly equally. Low entropy means
the agent hammers one or two tools. Neither is inherently bad, but extreme
specialization is suspicious if combined with a high deny ratio on the
concentrated tool.

### 2.6 Delegation Hygiene

Whether the agent delegates responsibly when it has `Delegate` authority.

**Capability fields used:**
- `delegation_chain[]` -- the `DelegationLink` entries
- `delegation_chain[].attenuations` -- `RemoveTool`, `ReduceBudget`, `ShortenExpiry`, etc.
- `delegation_chain[].delegator` / `delegation_chain[].delegatee`
- `scope.grants[].max_invocations` vs. parent's budget

**Computation:**

```
delegation_hygiene(agent) = {
    attenuation_rate:  fraction of delegations that include at least one Attenuation
    ttl_reduction:     mean(parent_expires_at - child_expires_at) / mean(parent_ttl)
    budget_cap_rate:   fraction of delegations where child max_invocations < parent
    depth_violations:  count of delegations rejected for exceeding max_delegation_depth
}
```

Good hygiene: every delegation attenuates scope, shortens TTL, and caps
the budget. Bad hygiene: passing through full authority with maximum TTL.

### 2.7 Completion Rate (reliability_score)

Whether the agent's tool calls reach successful terminal states.

**Receipt fields used:**
- `decision.verdict` -- `Allow` (the tool call was allowed and executed),
  `Cancelled`, `Incomplete`

**Computation:**

```
reliability_score(agent, window) = {
    completion_rate: count(Allow) / count(Allow + Cancelled + Incomplete)
    cancellation_rate: count(Cancelled) / count(Allow + Cancelled + Incomplete)
    incompletion_rate: count(Incomplete) / count(Allow + Cancelled + Incomplete)
}
```

Note that `Deny` receipts are excluded from reliability scoring because denials
reflect the policy boundary, not the agent's execution reliability. A high
`incompletion_rate` suggests the agent starts operations it cannot finish
(stream terminations, timeouts).

### 2.8 Incident Correlation

Linking external harm reports back to specific receipts.

**Fields used:**
- `receipt.id` -- unique receipt identifier
- `MerkleProof` -- inclusion proof from the `MerkleTree`
- `receipt.content_hash` -- SHA-256 of the evaluated content

**Mechanism:**

When an external party reports harm (data exfiltration, unauthorized action,
compliance violation), the report references specific receipt IDs. The receipt
log provides:

1. Merkle inclusion proof that the receipt existed at the claimed time
2. The exact `content_hash` of what was evaluated
3. The `policy_hash` showing which policy was in effect
4. The `evidence[]` array showing which guards ran and their verdicts

Incident correlation is a manual/semi-automated process in the local stage,
becoming automated once cross-organizational aggregation enables pattern
detection across operators.

---

## 3. Composite Risk Score

Individual metrics are combined into a weighted vector score.

### 3.1 Score Vector

```
reputation_vector(agent) = [
    boundary_pressure,        // 0.0 = never denied,   1.0 = always denied
    resource_stewardship,     // 0.0 = never used,     1.0 = fully consumed
    least_privilege_score,    // 0.0 = over-scoped,    1.0 = perfect fit
    history_depth_normalized, // 0.0 = brand new,      1.0 = established
    specialization_index,     // 0.0 = single tool,    1.0 = maximum diversity
    delegation_hygiene,       // 0.0 = passes all auth, 1.0 = always attenuates
    reliability_score,        // 0.0 = never completes, 1.0 = always completes
    incident_count_inverse,   // 0.0 = many incidents,  1.0 = no incidents
]
```

### 3.2 Weighted Composite

```
composite_score(agent) =
    w_boundary   * (1 - boundary_pressure) +
    w_steward    * stewardship_fit +
    w_privilege  * least_privilege_score +
    w_history    * history_depth_normalized +
    w_diversity  * min(specialization_index, diversity_cap) +
    w_delegation * delegation_hygiene +
    w_reliable   * reliability_score +
    w_incident   * incident_count_inverse

where stewardship_fit = 1 - abs(resource_stewardship - target_utilization)
```

**Local scoring rule:** unavailable metrics are `unknown`, not `0.0`.
When a metric cannot yet be computed because the required local join path is
missing or the agent lacks enough history, weights are renormalized across the
available metrics:

```
effective_composite(agent) =
    sum(w_i * m_i for available metrics) /
    sum(w_i for available metrics)
```

Tier promotion rules may still require specific metrics. If a mandatory metric
is unavailable, the agent remains in its current tier.

### 3.3 Default Weights

Weights are policy-configurable via HushSpec extensions (see Section 7).
Default values:

| Weight | Default | Rationale |
|--------|---------|-----------|
| `w_boundary` | 0.20 | High deny rates are the strongest negative signal |
| `w_steward` | 0.10 | Budget discipline is important but secondary |
| `w_privilege` | 0.15 | Least privilege adherence is a core security property |
| `w_history` | 0.10 | Track record provides baseline trust |
| `w_diversity` | 0.05 | Low weight -- some agents are legitimately specialized |
| `w_delegation` | 0.15 | Delegation without attenuation is dangerous |
| `w_reliable` | 0.15 | Agents that start what they finish are preferable |
| `w_incident` | 0.10 | External reports are high-signal but rare |

### 3.4 Example Scoring

**Mature, well-behaved agent:**
```
boundary_pressure      = 0.02  (2% deny rate)
resource_stewardship   = 0.75  (reasonable utilization)
least_privilege_score  = 0.90  (tight scoping)
history_depth_norm     = 0.95  (12 months of history)
specialization_index   = 0.60  (moderate tool diversity)
delegation_hygiene     = 0.85  (attenuates most delegations)
reliability_score      = 0.98  (almost always completes)
incident_count_inverse = 1.00  (no incidents)

composite = 0.20*(0.98) + 0.10*(0.92) + 0.15*(0.90) + 0.10*(0.95)
          + 0.05*(0.60) + 0.15*(0.85) + 0.15*(0.98) + 0.10*(1.00)
          = 0.916
```

**New agent with concerning behavior:**
```
boundary_pressure      = 0.35  (35% deny rate)
resource_stewardship   = 0.05  (requests big budgets, uses little)
least_privilege_score  = 0.20  (requests broad scope)
history_depth_norm     = 0.05  (2 days of history)
specialization_index   = 0.10  (hammers one tool)
delegation_hygiene     = 0.00  (no delegations yet)
reliability_score      = 0.60  (40% incomplete)
incident_count_inverse = 0.80  (1 incident)

composite = 0.20*(0.65) + 0.10*(0.42) + 0.15*(0.20) + 0.10*(0.05)
          + 0.05*(0.10) + 0.15*(0.00) + 0.15*(0.60) + 0.10*(0.80)
          = 0.376
```

---

## 4. Trust Bootstrapping

New agents have no history. The bootstrapping problem is solved through
graduated onboarding, staked reputation, and probationary periods.

### 4.1 Graduated Onboarding via Capability Tiers

New agents begin with narrow-scope capabilities and earn broader access
through demonstrated good behavior.

**Tier progression:**

```
Tier 0 (Probationary)
  - scope: read-only tools only (Operation::Read, Operation::Get)
  - max_invocations: 50 per capability
  - max_delegation_depth: 0 (no delegation)
  - TTL: 60 seconds
  - constraints: PathPrefix restricted to safe directories

Tier 1 (Standard)
  - scope: read + invoke on non-destructive tools
  - max_invocations: 500 per capability
  - max_delegation_depth: 1
  - TTL: 300 seconds

Tier 2 (Trusted)
  - scope: full invoke on most tools
  - max_invocations: 5000 per capability
  - max_delegation_depth: 3
  - TTL: 1800 seconds
  - constraints relaxed

Tier 3 (Elevated)
  - scope: all operations including Delegate
  - max_invocations: uncapped
  - max_delegation_depth: 5
  - TTL: 3600 seconds
```

Promotion requires sustained good scores across all metrics. Demotion is
immediate upon a single qualifying incident (see Section 7 for asymmetric
transitions).

### 4.2 Staked Reputation

When Agent A delegates capabilities to Agent B, Agent A's reputation is
partially bound to Agent B's behavior. This creates an incentive structure
for responsible delegation.

**Mechanism:**

```
reputation_bond(delegator, delegatee) = {
    bond_fraction: 0.1  // 10% of delegator's score is at risk
    decay_on_incident: 0.5  // delegator loses 50% of bond on delegatee incident
    recovery_period: 30 days
}
```

If the delegatee causes an incident, the delegator's composite score is
reduced by `bond_fraction * decay_on_incident`. This is computed from
the delegation chain in the `CapabilityToken`:

- `delegation_chain[].delegator` identifies who vouched
- `delegation_chain[].attenuations` show whether the delegator was prudent
- Better attenuation reduces the delegator's penalty (if the delegator
  restricted scope, they exercised due diligence)

### 4.3 Probationary Period

The first 1000 receipts (or 30 days, whichever comes later) constitute the
probationary period.

During probation:
- Composite score is capped at 0.60 regardless of actual metrics
- Capability tier is capped at Tier 1 (Standard)
- Delegation authority is not granted
- All metrics are computed but marked as `provisional`

After probation:
- The score cap is lifted
- Historical receipts continue to contribute (they are not discarded)
- The agent becomes eligible for Tier 2 promotion

---

## 5. Portable Trust Credentials

Agent reputation must be portable across organizations and Kernel operators.
Chio receipts are already signed and timestamped. Merkle commitment was tracked
under an internal pre-release milestone; the current public protocol posture is
v1-only. They are natural candidates for standardized verifiable credentials.

### 5.1 Receipt-Derived Reputation Attestations as W3C Verifiable Credentials

The portable credential unit is not a literal 1:1 wrapper around a single
`ChioReceipt`. It is an attestation computed over a bounded receipt set
(for example, "this agent's behavior during the last 30 days under this
Kernel"), signed by the issuing authority and linked back to the underlying
receipt log via receipt IDs, Merkle roots, or inclusion proofs.

A receipt-derived reputation attestation maps to a W3C Verifiable Credential
(VC) like this:

| VC Field | Chio Source |
|----------|-----------------|
| `@context` | `["https://www.w3.org/2018/credentials/v1", "https://chio.world/credentials/v1"]` |
| `type` | `["VerifiableCredential", "ChioReputationAttestation"]` |
| `issuer` | Kernel or authority key that computed the attestation |
| `issuanceDate` | Attestation issuance time |
| `credentialSubject.id` | Agent's Ed25519 public key from the capability lineage index |
| `credentialSubject.metrics` | Aggregated reputation vector for the attested interval |
| `proof.type` | `Ed25519Signature2020` |
| `proof.verificationMethod` | `did:chio:{kernel_key_hex}#key-1` |
| `proof.proofValue` | Attestation signature |

### 5.2 Agent Passport

An Agent Passport is a wallet-held bundle of one or more reputation
attestations. The portable-credential stage can ship with single-issuer
passports. The cross-organizational stage expands them into richer
cross-organizational bundles and composite attestations.

```
AgentPassport {
    subject:      did:chio:{agent_public_key_hex}
    credentials:  Vec<VerifiableCredential>
    merkle_roots: Vec<Hash>  // one per issuing Kernel (MerkleTree::root() returns Hash)
    issued_at:    DateTime
    valid_until:  DateTime
}
```

Each credential in the passport is independently verifiable. A relying
party can:

1. Verify each VC's Ed25519 signature against the claimed Kernel key
2. Verify Merkle inclusion proofs linking VCs back to receipt logs
3. Compute a cross-organizational composite score by aggregating metrics
4. Weight credentials by the trust it places in each issuing Kernel

This alpha now ships in `crates/trust/chio-credentials` and via the CLI commands
`chio passport create`, `chio passport evaluate`, `chio passport verify`, and
`chio passport present`. The current implementation is intentionally
single-issuer: each passport is a bundle of one or more independently
verifiable reputation credentials from the same issuing operator.

The first relying-party verifier lane is also now shipped. A verifier policy
can evaluate a presented passport against issuer allowlisting, metric
thresholds, checkpoint coverage, receipt-log URL presence, and attestation-age
requirements without custom glue code. In the current alpha this policy is
applied per embedded credential, and the passport is accepted if at least one
credential satisfies the policy. Cross-credential aggregation semantics remain
explicitly out of scope until the multi-issuer model is specified.

### 5.3 did:chio DID Method

Chio agents already have Ed25519 keypairs. The `did:chio` method provides
a decentralized identifier scheme:

```
did:chio:{hex-encoded-ed25519-public-key}

Example:
did:chio:a1b2c3d4e5f6...  (64 hex characters)
```

**DID Document:**

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:chio:a1b2c3d4e5f6...",
  "verificationMethod": [{
    "id": "did:chio:a1b2c3d4e5f6...#key-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:chio:a1b2c3d4e5f6...",
    "publicKeyMultibase": "z6Mk..."
  }],
  "authentication": ["did:chio:a1b2c3d4e5f6...#key-1"],
  "assertionMethod": ["did:chio:a1b2c3d4e5f6...#key-1"]
}
```

Resolution: the DID document is self-certifying. The public key is the
identifier. No registry lookup is needed for basic resolution. Extended
resolution (service endpoints, delegation metadata) can be published to
a Chio receipt log as a special `did:chio:update` receipt type.

This basic resolver now ships in `crates/trust/chio-did` and is exposed via
`chio did resolve`. The current shipped service type is
`ChioReceiptLogService`, which allows an operator-local resolver to attach one
or more receipt-log URLs without changing the self-certifying base identity.

### 5.4 Selective Disclosure

Agents may not want to reveal their full reputation history to every relying
party. Selective disclosure allows an agent to prove specific claims without
revealing the underlying data.

**Baseline (portable-credential stage):** The agent presents a subset of VCs
from its passport. Each VC contains aggregated metrics for a time period, not
individual receipts.

**Advanced (cross-organizational stage):** Zero-knowledge proofs over the Merkle tree allow the
agent to prove statements like "my deny ratio is below 5% over the last 90
days" without revealing which tools were used or which policies were in effect.
See Section 8.2.

---

## 6. Gaming Resistance

A reputation system is only useful if it resists manipulation. Chio's
architecture provides several structural advantages, supplemented by
explicit countermeasures.

### 6.1 Risk-Weighted Receipts

Not all tool invocations carry equal risk. A successful `file_read` on a
public directory is less meaningful than a successful `shell_exec` with
network access.

**Tool risk classification:**

| Risk Level | Examples | Receipt Weight |
|------------|----------|----------------|
| Low | `file_read` (constrained path), `get_prompt` | 1x |
| Medium | `file_write`, `http_get` (allowlisted domain) | 3x |
| High | `shell_exec`, `http_post`, `file_write` (broad path) | 5x |
| Critical | `shell_exec` (unconstrained), `delegate` (full scope) | 10x |

Risk classification is derived from the `ToolGrant`, so it requires the local
capability lineage index:
- `operations` containing `Delegate` increases risk
- Absence of `constraints` (no `PathPrefix`, no `DomainExact`) increases risk
- `max_invocations: None` (uncapped) increases risk

Reputation gains from low-risk operations are capped, preventing an agent
from farming reputation by making millions of trivial read calls.

### 6.2 Temporal Decay

Recent behavior is more informative than historical behavior. All metrics
apply a 30-day half-life exponential decay.

```
decayed_weight(receipt) = 2^(-(now - receipt.timestamp) / (30 * 86400))
```

A receipt from today has weight 1.0. A receipt from 30 days ago has weight
0.5. A receipt from 90 days ago has weight 0.125. This means:

- An agent cannot rest on historical good behavior indefinitely
- Recovery from bad behavior is possible but slow (the bad receipts must
  age out while good receipts accumulate)
- Seasonal patterns are smoothed out

### 6.3 Entropy Requirement

An agent's reputation must be built across a minimum diversity of tools and
servers. A `specialization_index` below a configurable threshold (default:
0.3 on the Shannon entropy scale) triggers a score penalty.

This prevents an agent from building reputation by invoking a single
low-risk tool millions of times. Legitimate agents naturally use multiple
tools; reputation farmers tend to concentrate on the cheapest operation.

### 6.4 Sybil Resistance

**Capability-gated identity:** An agent's identity is its Ed25519 public key,
bound to capabilities via the `subject` field on `CapabilityToken`. Creating
a new identity requires obtaining capabilities from a Capability Authority,
which is an administratively controlled process.

**Delegation graph analysis:** The `delegation_chain` on every capability
creates a graph of trust relationships. Sybil agents -- multiple identities
controlled by one operator -- tend to produce distinctive graph patterns:

- Star topology: one delegator, many delegatees with similar behavior
- Rapid delegation chains with minimal attenuation
- Temporal clustering: many new agents appearing simultaneously

These patterns are detectable from local receipt + capability-lineage data,
using the `delegator` and `delegatee` fields in `DelegationLink`.

### 6.5 Non-Transferable Reputation

Reputation is bound to the agent's Ed25519 key. There is no mechanism to
transfer reputation to a new key without re-earning it. Key rotation is
supported via a `did:chio:update` receipt signed by both the old and new
keys, which transfers history but requires proof of control over both keys.

This prevents reputation markets (buying/selling established identities)
because the buyer cannot prove they control the original key without the
seller's cooperation, and the seller loses access upon transfer.

---

## 7. Graduated Authority

Reputation feeds back into capability issuance through HushSpec policy
extensions.

### 7.1 HushSpec Policy Extensions

The HushSpec policy schema is extended with a `reputation` section under
`extensions`:

```yaml
hushspec: "0.1.0"
name: "reputation-gated-policy"
description: "Capability tiers gated by agent reputation score"

extensions:
  reputation:
    scoring:
      weights:
        boundary_pressure: 0.20
        resource_stewardship: 0.10
        least_privilege: 0.15
        history_depth: 0.10
        tool_diversity: 0.05
        delegation_hygiene: 0.15
        reliability: 0.15
        incident_correlation: 0.10
      temporal_decay_half_life_days: 30
      probationary_receipt_count: 1000
      probationary_min_days: 30
      probationary_score_ceiling: 0.60

    tiers:
      probationary:
        score_range: [0.0, 0.40]
        max_scope:
          operations: [read, get]
          max_invocations: 50
          max_cost_per_invocation: { units: 100, currency: "USD" }
          max_total_cost: { units: 1000, currency: "USD" }
          max_delegation_depth: 0
          ttl_seconds: 60
          constraints_required: true
        promotion:
          target: standard
          min_score: 0.40
          min_receipts: 1000
          min_days: 30
          required_metrics:
            boundary_pressure_max: 0.10
            reliability_min: 0.80

      standard:
        score_range: [0.40, 0.65]
        max_scope:
          operations: [read, get, invoke]
          max_invocations: 500
          max_cost_per_invocation: { units: 500, currency: "USD" }
          max_total_cost: { units: 5000, currency: "USD" }
          max_delegation_depth: 1
          ttl_seconds: 300
          constraints_required: false
        promotion:
          target: trusted
          min_score: 0.65
          min_receipts: 10000
          min_days: 90
          required_metrics:
            boundary_pressure_max: 0.05
            reliability_min: 0.90
            least_privilege_min: 0.70
        demotion:
          target: probationary
          triggers:
            - type: score_below
              threshold: 0.30
            - type: incident_reported
            - type: deny_streak
              count: 20

      trusted:
        score_range: [0.65, 0.85]
        max_scope:
          operations: [read, get, invoke, read_result]
          max_invocations: 5000
          max_cost_per_invocation: { units: 2000, currency: "USD" }
          max_total_cost: { units: 25000, currency: "USD" }
          max_delegation_depth: 3
          ttl_seconds: 1800
        promotion:
          target: elevated
          min_score: 0.85
          min_receipts: 50000
          min_days: 180
          required_metrics:
            boundary_pressure_max: 0.03
            reliability_min: 0.95
            delegation_hygiene_min: 0.80
            least_privilege_min: 0.80
        demotion:
          target: standard
          triggers:
            - type: score_below
              threshold: 0.55
            - type: incident_reported
            - type: delegation_incident

      elevated:
        score_range: [0.85, 1.0]
        max_scope:
          operations: [read, get, invoke, read_result, delegate, subscribe]
          max_invocations: null  # uncapped
          max_cost_per_invocation: { units: 5000, currency: "USD" }
          max_total_cost: { units: 100000, currency: "USD" }
          max_delegation_depth: 5
          ttl_seconds: 3600
        demotion:
          target: trusted
          triggers:
            - type: score_below
              threshold: 0.75
            - type: incident_reported
            - type: delegation_incident
```

### 7.2 Asymmetric Transitions

Promotion and demotion are deliberately asymmetric:

**Promotion (slow):**
- Requires sustained score above threshold for `min_days`
- Requires minimum receipt count (demonstrated track record)
- Requires specific per-metric minimums (no single weak dimension)
- Evaluated periodically (daily or weekly)

**Demotion (fast):**
- Triggered immediately by any qualifying event
- Single incident report can demote by one tier
- Deny streak (configurable, default 20 consecutive denials) triggers demotion
- Score drop below threshold triggers demotion on next evaluation

The asymmetry encodes a core principle: trust is earned slowly and lost
quickly. An agent that has operated well for 6 months can lose its elevated
status in a single incident, but recovering that status requires another
sustained period of good behavior.

### 7.3 Tier Enforcement

The Capability Authority reads the agent's current tier from the reputation
system before issuing capabilities. The `max_scope` for the agent's tier
acts as a ceiling on what the CA will issue:

```
capability_issuance(agent, requested_scope) =
    if requested_scope.is_subset_of(tier.max_scope):
        issue(requested_scope)
    else:
        deny("requested scope exceeds tier ceiling")
```

This is now part of the current unreleased v1 capability-authority wrapper. The wrapper
materializes `extensions.reputation` from HushSpec, computes the subject's
local scorecard from persisted receipts, capability lineage, and budget usage,
and denies issuance when the requested TTL or grant scope exceeds the current
tier ceiling.

Operators can now inspect the exact same local evaluation path without bespoke
SQLite queries or Rust glue. `chio reputation local --subject-public-key ...`
computes the scorecard directly from persisted state, and trust-control exposes
the same report over `GET /v1/reputation/local/:subject_key` when running with
service auth. Those operator surfaces reuse the issuance-time corpus assembly,
probationary logic, and tier resolution code path so support/debugging does not
drift from enforcement.

The current implementation enforces:
- TTL ceiling
- allowed operations
- required constraints on tool grants
- per-grant invocation ceilings
- per-grant monetary ceilings (`max_cost_per_invocation`, `max_total_cost`)
- delegation disabled vs delegation eligible (`max_delegation_depth == 0`)

One nuance remains: the current `CapabilityToken` model does not yet encode a
portable numeric per-capability delegation-depth ceiling beyond "delegation
allowed or not." Tier values above zero therefore gate delegate eligibility,
while exact numeric depth tiers remain follow-on token-schema work.

---

## 8. Privacy

Agent reputation data is sensitive. The system must balance transparency
(relying parties need to assess trust) with privacy (agents should not be
forced to reveal their full operational history).

### 8.1 Baseline: Aggregated Statistics Only

In the local stage, reputation is computed locally by each Kernel operator. Only
aggregated statistics are shared:

- Composite score (single number)
- Tier level (probationary / standard / trusted / elevated)
- Receipt count and history span
- No individual receipt data crosses organizational boundaries

This is sufficient for internal use (one organization managing its own
agents) and basic cross-organizational queries ("is this agent at least
Tier 2 somewhere?").

### 8.2 Advanced: ZK Proofs over Receipt Merkle Tree

In the cross-organizational stage, zero-knowledge proofs enable
privacy-preserving reputation verification. The Merkle tree structure of the
receipt log is the proof substrate.

**Example provable statements:**

- "My deny ratio is below 5% over the last 90 days" (without revealing
  which tools or which policies)
- "I have more than 10,000 receipts from at least 3 distinct Kernel
  operators" (without revealing which operators)
- "My composite score exceeds 0.70" (without revealing individual metrics)

**Proof construction:**

The agent constructs a ZK-SNARK or Bulletproof over:
1. The Merkle root (publicly known, committed to the receipt log)
2. The agent's receipts (private witness)
3. The claimed predicate (public statement)

The verifier checks the proof against the known Merkle root without learning
the receipts. This requires the receipt log to publish periodic signed roots.
Chio does not already have this via Spine; the roadmap requires adding
kernel-signed checkpoints over the Merkle-committed receipt log first, with
any witness layer remaining optional follow-on work.

### 8.3 Data Sovereignty

The agent controls its own reputation data:

- Receipts are stored in the Kernel's receipt log, but the agent holds
  copies of its own receipts (received as part of the tool call response)
- The agent chooses which VCs to include in its passport
- The agent chooses which relying parties to present credentials to
- No central authority can revoke an agent's access to its own historical
  receipts

The Kernel operator can publish aggregate statistics about agents that
operate within its domain, but cannot unilaterally share individual
receipt-level data without the agent's consent (enforced by selective
disclosure in the VC layer).

---

## 9. Architecture

```
+-------------------+     +-------------------+     +-------------------+
|   Org A Kernel    |     |   Org B Kernel    |     |   Org C Kernel    |
|                   |     |                   |     |                   |
|  Receipt Log      |     |  Receipt Log      |     |  Receipt Log      |
|  (Merkle Tree)    |     |  (Merkle Tree)    |     |  (Merkle Tree)    |
|                   |     |                   |     |                   |
|  Local Reputation |     |  Local Reputation |     |  Local Reputation |
|  Computation      |     |  Computation      |     |  Computation      |
+--------+----------+     +--------+----------+     +--------+----------+
         |                          |                          |
         |  Aggregated metrics      |  Aggregated metrics      |
         |  + Merkle roots          |  + Merkle roots          |
         v                          v                          v
+--------+----------------------------------------------------+----------+
|                                                                         |
|                      Reputation Aggregator (cross-org)                  |
|                                                                         |
|  - Collects VCs from participating Kernels                              |
|  - Computes cross-org composite scores                                  |
|  - Validates Merkle inclusion proofs                                    |
|  - Detects Sybil patterns across delegation graphs                      |
|  - Publishes signed reputation attestations                             |
|                                                                         |
+--------+------------------------+------------------------+--------------+
         |                        |                        |
         v                        v                        v
+--------+----------+  +----------+---------+  +-----------+---------+
|                   |  |                    |  |                     |
|  VC Issuance      |  |  Agent Passports   |  |  Capability         |
|                   |  |                    |  |  Authorities        |
|  - Signs VCs with |  |  - Agent-held      |  |                     |
|    aggregator key  |  |    credential      |  |  - Query reputation |
|  - Embeds Merkle  |  |    bundles         |  |    before issuing   |
|    proofs          |  |  - Selective       |  |    capabilities     |
|  - Publishes to   |  |    disclosure      |  |  - Enforce tier     |
|    VC registry    |  |  - did:chio DIDs   |  |    ceilings         |
|                   |  |                    |  |                     |
+-------------------+  +--------------------+  +---------------------+
```

**Data flow:**

1. Each Kernel produces receipts and commits them to its local Merkle tree
2. Local reputation is computed from receipts plus local capability-lineage and
   budget joins (local stage -- no cross-org deps)
3. Kernels publish aggregated metrics and Merkle roots to the Reputation
   Aggregator (cross-organizational stage)
4. The Aggregator validates proofs, computes cross-org scores, detects Sybil
   patterns
5. The Aggregator issues VCs that agents collect into passports
6. Capability Authorities query the Aggregator (or verify agent-presented
   VCs directly) before issuing capabilities

---

## 10. Commercialization Hypotheses

If cross-organizational reputation becomes useful in practice, it could create
durable network effects. This section describes possible commercialization
shapes; it is not part of the protocol's technical dependency graph.

### 10.1 Credit-Bureau-Like Service

One possible product shape is a credit-bureau-like aggregator: it collects
behavioral attestations from multiple sources, computes standardized scores,
and sells access to those scores. The analogy to consumer credit bureaus is
useful for intuition, but it is still a hypothesis that needs market
validation:

- **Data suppliers** (Kernel operators) contribute receipt-derived behavioral
  data in exchange for access to the aggregate scores of agents that interact
  with them
- **Data consumers** (Capability Authorities, platform operators) query
  scores before granting access
- **Data subjects** (agents) benefit from portable reputation that reduces
  friction when accessing new tool servers

### 10.2 Revenue Streams

| Revenue Source | Description | Stage |
|---------------|-------------|-------|
| Cross-org reputation queries | Per-query fee for composite score lookups | Cross-org |
| VC issuance | Fee per Verifiable Credential issued to agents | Portable credentials |
| Compliance audits | Receipt log analysis for regulatory compliance | Local |
| Premium analytics | Detailed behavioral analytics for Kernel operators | Portable credentials |
| Reputation insurance | Coverage against losses from agents with good scores | Cross-org |

### 10.3 Potential Network Effects

**Data network effect:** Each new Kernel operator that contributes attested
behavior data could make the aggregate scores more accurate for all
participants. An agent's score from a single operator is useful; a score from
many operators could become materially more trustworthy.

**Standards leverage:** The `did:chio` DID method, the VC schema, and the
reputation scoring algorithm could become de facto standards if adoption
grows. Competing systems would then face pressure either to interoperate or to
build lower-value incompatible alternatives.

**Switching costs:** Once an agent has built reputation across multiple
organizations, migrating to a different protocol may mean abandoning that
reputation. Once a Capability Authority integrates reputation-gated
issuance, switching protocols also means rebuilding the integration.

---

## 11. Implementation Stages

### Internal Reputation Computation (local stage)

**Timeline:** Ready to begin on top of the current local data substrate. This
stage does not require cross-organizational coordination; it builds directly on
the capability lineage index and receipt attribution path described in Section
1.

**Scope:**
- Implement reputation metrics computation from persisted receipts, the local
  capability lineage index, and budget usage records
- Treat metrics as direct, join-based, or external-input, rather than assuming
  every metric comes from the raw receipt envelope alone
- Renormalize the composite score over available metrics instead of treating
  unavailable metrics as zero
- Local to each Kernel operator (no cross-org communication)
- Composite score computation with configurable weights
- HushSpec policy extension for tier definitions. **Note:** The `Extensions`
  struct in `chio-policy/src/models.rs` uses `#[serde(deny_unknown_fields)]`,
  so adding an `extensions.reputation` field requires modifying that struct
  to include a `reputation: Option<ReputationExtension>` variant.
- Tier-gated capability issuance in the Capability Authority

**Deliverables:**
- `chio-reputation` crate with metric computation functions
- HushSpec `extensions.reputation` schema in `chio-policy`
- Integration with `chio-kernel` for reputation-gated capability issuance
- Verification checklist showing the required local joins exist
- CLI commands: `chio reputation score <agent-id>`,
  `chio reputation history <agent-id>`
- Unit tests for all metric computations and tier transitions

**Non-goals for this stage:**
- No cross-organizational data sharing
- No VC issuance
- No DID method registration
- No ZK proofs

### Portable Credentials (portable-credential stage)

**Timeline:** Active. `did:chio`, single-issuer passport creation, verification,
filtered presentation, challenge-bound presentation, and local-versus-portable
comparison are now shipped. Multi-issuer aggregation and richer VC
distribution flows remain open.

**Scope:**
- `did:chio` DID method specification and resolver
- W3C Verifiable Credential schema for reputation attestations
- Agent Passport data structure and serialization
- VC issuance endpoint on the Kernel
- Selective disclosure (present subset of VCs)
- Single-issuer passports first; multi-issuer aggregation can remain a cross-organizational-stage concern

**Deliverables:**
- `did:chio` method specification document
- `chio-did` crate with self-certifying DID parsing and DID Document resolution
- `chio-credentials` crate with VC creation, serialization, verification, and single-issuer passport bundling
- CLI command: `chio did resolve`
- Agent Passport CLI: `chio passport create`, `chio passport evaluate`, `chio passport verify`, `chio passport present`, `chio passport challenge ...`
- Operator comparison surfaces: `chio reputation compare`, `POST /v1/reputation/compare/:subject_key`, and dashboard portable-comparison panel
- VC verification library for relying parties

**Dependencies:**
- The local stage must be stable (reputation metrics are the VC payload)
- Ed25519 key management must support key rotation (for DID updates)

### Cross-Organizational Aggregation (cross-organizational stage)

**Timeline:** After portable-credential adoption

**Scope:**
- Reputation Aggregator service (receives VCs from multiple Kernels)
- Cross-org composite score computation
- Sybil detection across delegation graphs
- ZK proof generation and verification for privacy-preserving queries
- Reputation query API for Capability Authorities

**Deliverables:**
- `chio-aggregator` service with API
- ZK proof circuit for Merkle tree membership and predicate verification
- Sybil detection module (delegation graph analysis)
- Cross-org reputation query protocol specification
- Compliance audit tooling

**Dependencies:**
- The portable-credential stage must be adopted by multiple organizations (need real cross-org data)
- ZK proof toolchain selection (Groth16, Plonk, or Bulletproofs)
- Legal framework for cross-organizational data sharing
