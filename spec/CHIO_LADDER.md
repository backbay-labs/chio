# Chio Governance Ladder Manifest

**Status:** v1 (Chio-owned pre-release; wire-frozen against `chio.federation.governance-ladder-manifest.v1`)

This specification defines the **chio governance ladder manifest**, the
signed per-participant artefact that declares how each cross-trust action
class maps to a governance mode and a consistency model. Peers cannot declare
or interpret each other's governance intensity without it.

The ladder manifest is signed and pinned at the federation handshake
([../crates/trust/chio-federation/src/trust_establishment.rs](../crates/trust/chio-federation/src/trust_establishment.rs))
and feeds [../crates/trust/chio-governance/src/lib.rs](../crates/trust/chio-governance/src/lib.rs)
case kinds when validation fails.

The keywords MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, MAY are to be
interpreted as described in RFC 2119. Canonical JSON serialisation follows
RFC 8785 (JCS).

---

## 1. Roles And Lifecycle

A chio participant publishes one ladder manifest per **domain**
(cybersec, financial, compliance, or any other). The manifest:

1. Is signed by the participant's federation kernel key.
2. Is pinned bilaterally at handshake time and stored alongside the
   `FederationPeer` record.
3. Is intersected with the peer's manifest into a co-signed
   `chio.federation.ladder-intersection.v1` artefact (section 6) that gates
   all subsequent cross-trust actions in that treaty scope.
4. Is replaced only by a co-signed
   `chio.federation.governance-ladder-amendment.v1` artefact (section 8).

A peer that cannot present a verifiable manifest for a requested treaty
scope MUST be refused at handshake. Failure modes are enumerated in
section 7 and each becomes a fileable
`GenericGovernanceCaseKind::Dispute`.

---

## 2. Manifest JSON Schema

The manifest schema identifier is `chio.federation.governance-ladder-manifest.v1`. The full JSON
Schema (Draft 2020-12) follows. Implementations MUST validate inbound
manifests against this schema before signature verification.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "chio.federation.governance-ladder-manifest.v1",
  "title": "Chio Governance Ladder Manifest",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "schema",
    "manifest_id",
    "participant_id",
    "domain",
    "ladder_version",
    "modes",
    "default_unmapped_mode",
    "destructive_floor",
    "action_classes",
    "ladder_refusal_policy",
    "signature"
  ],
  "properties": {
    "schema": {
      "type": "string",
      "const": "chio.federation.governance-ladder-manifest.v1"
    },
    "manifest_id": {
      "type": "string",
      "pattern": "^[A-Za-z0-9._:-]{1,128}$",
      "description": "Stable identifier under the participant namespace."
    },
    "participant_id": {
      "type": "string",
      "description": "did:chio identifier of the publishing kernel."
    },
    "domain": {
      "type": "string",
      "enum": ["cybersec", "financial", "compliance", "supply_chain", "other"],
      "description": "Domain taxonomy. `other` requires a non-empty `domain_label`."
    },
    "domain_label": {
      "type": "string",
      "minLength": 1,
      "maxLength": 64,
      "description": "Human-readable label. REQUIRED iff `domain == \"other\"`."
    },
    "ladder_version": {
      "type": "string",
      "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+$",
      "description": "Semantic version of this manifest body."
    },
    "modes": {
      "type": "array",
      "items": {
        "type": "string",
        "enum": [
          "observation",
          "guarded",
          "receipt_backed",
          "partition_contingency",
          "maintenance"
        ]
      },
      "minItems": 5,
      "uniqueItems": true,
      "description": "All five modes MUST be enumerated. Order is informative; intensity is fixed by section 3."
    },
    "default_unmapped_mode": {
      "type": "string",
      "enum": ["receipt_backed", "partition_contingency", "maintenance"],
      "description": "Mode applied to unknown action classes. SHOULD be `receipt_backed` and MUST NOT be `observation` or `guarded`."
    },
    "destructive_floor": {
      "type": "string",
      "enum": ["receipt_backed", "partition_contingency", "maintenance"],
      "description": "Lowest mode at which `destructive: true` may be declared. Enforced by validation rule `ladder.destructive_downgrade`."
    },
    "action_classes": {
      "type": "array",
      "minItems": 1,
      "items": { "$ref": "#/$defs/actionClass" }
    },
    "ladder_refusal_policy": {
      "type": "object",
      "additionalProperties": false,
      "required": ["on_unknown_class", "on_intersection_empty", "on_floor_disagreement"],
      "properties": {
        "on_unknown_class": {
          "type": "string",
          "enum": ["fall_back_to_default", "refuse"]
        },
        "on_intersection_empty": {
          "type": "string",
          "enum": ["refuse", "scope_to_intersection"]
        },
        "on_floor_disagreement": {
          "type": "string",
          "enum": ["refuse", "raise_to_higher_floor"]
        },
        "on_alias_conflict": {
          "type": "string",
          "enum": ["refuse", "prefer_local"]
        }
      }
    },
    "signature": { "$ref": "#/$defs/signature" }
  },
  "allOf": [
    {
      "if": { "properties": { "domain": { "const": "other" } } },
      "then": { "required": ["domain_label"] }
    }
  ],
  "$defs": {
    "actionClass": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "id",
        "mode",
        "destructive",
        "cross_org_visibility",
        "evidence_required",
        "co_sign",
        "consistency_model"
      ],
      "properties": {
        "id": {
          "type": "string",
          "pattern": "^[a-z][a-z0-9._-]{0,127}$"
        },
        "title": { "type": "string", "maxLength": 80 },
        "mode": {
          "type": "string",
          "enum": [
            "observation",
            "guarded",
            "receipt_backed",
            "partition_contingency",
            "maintenance"
          ]
        },
        "destructive": { "type": "boolean" },
        "cross_org_visibility": {
          "type": "string",
          "enum": ["private", "treaty_only", "federated", "public"]
        },
        "evidence_required": {
          "type": "array",
          "items": {
            "type": "string",
            "enum": [
              "listing",
              "trust_activation",
              "certification",
              "registry_search",
              "operator_report",
              "external",
              "workflow_receipt",
              "anchor_epoch",
              "passport_presentation"
            ]
          },
          "uniqueItems": true
        },
        "co_sign": {
          "type": "string",
          "enum": [
            "none",
            "bilateral_if_cross_org",
            "bilateral_required",
            "n_of_m"
          ]
        },
        "co_sign_quorum": {
          "type": "object",
          "additionalProperties": false,
          "required": ["n", "m"],
          "properties": {
            "n": { "type": "integer", "minimum": 2 },
            "m": { "type": "integer", "minimum": 2 },
            "scope": { "type": "string", "enum": ["treaty", "kernel", "operator"] }
          },
          "description": "REQUIRED iff `co_sign == \"n_of_m\"`. `n <= m` MUST hold."
        },
        "partition_fallback": {
          "type": "object",
          "additionalProperties": false,
          "required": ["lease_kind", "blast_radius_cap", "ttl_secs"],
          "properties": {
            "lease_kind": {
              "type": "string",
              "enum": ["narrow_destructive", "scoped_observation", "delegated_action"]
            },
            "blast_radius_cap": {
              "type": "object",
              "additionalProperties": false,
              "required": ["unit", "max"],
              "properties": {
                "unit": {
                  "type": "string",
                  "enum": ["host", "subject", "credential", "amount_minor", "count"]
                },
                "max": { "type": "integer", "minimum": 1 }
              }
            },
            "ttl_secs": { "type": "integer", "minimum": 1, "maximum": 86400 }
          }
        },
        "consistency_model": {
          "type": "string",
          "enum": ["crdt-commutative", "totally-ordered", "quorum-required"]
        },
        "consistency_anchor": {
          "type": "string",
          "enum": ["chio-anchor", "hash-chain", "frost-quorum"],
          "description": "REQUIRED for `totally-ordered` (hash-chain or chio-anchor) and `quorum-required` (frost-quorum)."
        },
        "aliases": {
          "type": "array",
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": ["domain", "id"],
            "properties": {
              "domain": { "type": "string" },
              "id": { "type": "string" }
            }
          },
          "uniqueItems": true
        }
      },
      "allOf": [
        {
          "if": { "properties": { "co_sign": { "const": "n_of_m" } } },
          "then": { "required": ["co_sign_quorum"] }
        },
        {
          "if": { "properties": { "consistency_model": { "const": "totally-ordered" } } },
          "then": { "required": ["consistency_anchor"] }
        },
        {
          "if": { "properties": { "consistency_model": { "const": "quorum-required" } } },
          "then": { "required": ["consistency_anchor"] }
        }
      ]
    },
    "signature": {
      "type": "object",
      "additionalProperties": false,
      "required": ["signer_key", "alg", "value"],
      "properties": {
        "signer_key": { "type": "string", "description": "Hex-encoded Ed25519 or hybrid prefix." },
        "alg": { "type": "string", "enum": ["ed25519", "hybrid:ed25519:mldsa65"] },
        "value": { "type": "string", "description": "Hex-encoded signature over canonical JSON of the body excluding `signature`." }
      }
    }
  }
}
```

---

## 3. Mode Definitions

The five modes are ordered by intensity. Intensity comparisons in
sections 5-7 use `observation < guarded < receipt_backed <
partition_contingency < maintenance`. (Maintenance is the highest
intensity because it requires authenticated operator presence, not
because it is operationally most destructive.)

Each mode mirrors the in-production STS consensus contract.

### 3.1 Observation

**Coverage:** signal ingest, detection, investigation, correlation,
durable memory, status publication, decoy operation, listing browse.

**Required artefacts:** signed pheromone deposits or signed listings only.
Receipts are emitted but no governance receipt is required.

**Forbidden actions:** any action whose `destructive` flag is `true`;
mutation of peer-owned state; cross-org credential modification.

### 3.2 Guarded

**Coverage:** non-destructive escalation, decoy deployment, advisory
listing publication, low-amount quote issuance, charter publication
preview.

**Required artefacts:** policy validation evidence and ordinary signed
audit trail; no governance receipt required.

**Forbidden actions:** any destructive action; any action that mutates
shared cross-org state without bilateral co-signature.

### 3.3 Receipt-Backed

**Coverage:** destructive response (block, isolate, revoke), binding
financial commitments, sanction enforcement, passport state changes,
charter amendments.

**Required artefacts:** signed governance receipt under
[../crates/trust/chio-governance/src/lib.rs](../crates/trust/chio-governance/src/lib.rs);
bilateral co-signature when `co_sign != "none"`; workflow receipt at the
boundary tick.

**Forbidden actions:** execution under partition without a valid
contingency lease; execution without the consistency anchor named for
the action's `consistency_model`.

### 3.4 Partition-Contingency

**Coverage:** the destructive subset of receipt-backed actions when the
federation is partitioned and the action class declares a
`partition_fallback` block.

**Required artefacts:** valid staged contingency lease (within the
declared `blast_radius_cap` and `ttl_secs`); enhanced receipt referencing
the lease; mandatory reconciliation case at heal time.

**Forbidden actions:** any action that lacks a staged lease; any action
whose `partition_fallback.lease_kind` is unset; any action whose
`consistency_model` is `quorum-required` (FROST quorum cannot be assembled
under partition by definition).

### 3.5 Maintenance

**Coverage:** operator review, evidence export, replay, key rotation,
charter rotation, manifest amendment.

**Required artefacts:** authenticated operator session; per-action
audit; explicit operator presence in the receipt body.

**Forbidden actions:** any cross-org execution; any non-operator-driven
mutation; any action without an authenticated operator identity.

---

## 4. Consistency Model Semantics

The bilateral co-signing layer alone leaves the partition-divergent co-sign
window open.
Each action class therefore declares a `consistency_model` and (for two
of the three) a `consistency_anchor`.

### 4.1 `crdt-commutative`

**Qualifying classes:** observations and deposits whose merge operation
is commutative and absorbs divergence: pheromone deposits, IOC listings,
status updates, advisory findings, public credential listings.

**Signature shape:** bilateral tree under
[../crates/trust/chio-federation/src/bilateral.rs](../crates/trust/chio-federation/src/bilateral.rs).
No anchor field is required.

**Divergent co-sign handling:** convergence is automatic on reconnect.
A↔B and B↔C signing different deposits at overlapping windows is
expected and well-defined: both deposits enter the substrate and decay
or get evicted independently.

**Residual:** none for the merge property itself; reputation weighting
of conflicting deposits is the receiver's local concern.

### 4.2 `totally-ordered`

**Qualifying classes:** workflow steps, sequential capability grants,
charter amendments, tier promotions, scoped sanction lifecycle.

**Signature shape:** bilateral tree plus a `consistency_anchor` of either
`hash-chain` (parent receipt SHA-256 in the body) or `chio-anchor` (epoch
root from
[../crates/economy/chio-anchor/src/lib.rs](../crates/economy/chio-anchor/src/lib.rs)).

**Divergent co-sign handling:** detected at verification. A receipt whose
parent-hash or anchor-epoch does not match the receiver's view of the
sequence MUST be rejected and a `GenericGovernanceCaseKind::Dispute` MUST
be filed.

**Residual:** transient races where two co-signed receipts both reference
the same parent. The later-arriving receipt is rejected; the loser
re-issues against the new parent.

### 4.3 `quorum-required`

**Qualifying classes:** destructive actions that mutate shared state with
no commutative interpretation: revocations of jointly-issued credentials,
multi-party settlements, treaty-wide sanctions, passport invalidations
that span issuing orgs.

**Signature shape:** FROST-aggregated Ed25519 signature over canonical
JSON of the action body, with `consistency_anchor: "frost-quorum"` and
quorum scope declared in `co_sign_quorum`. Bilateral trees are
**insufficient** and MUST be rejected for this model.

**Divergent co-sign handling:** structurally impossible: only one
quorum-aggregated signature can succeed per body hash within a quorum
epoch.

**Residual:** operational overhead of FROST signing-key custody and the
pre-handshake key-share ceremony. The opt-in is per-class precisely so
this overhead is paid only where needed.

A manifest MUST be rejected at handshake with
`ladder.consistency_underspecified` if any `destructive: true` class
declares `crdt-commutative`.

---

## 5. Worked Examples

The three example ladders below are normative reference profiles. Real
deployments MUST publish their own manifest; these illustrate the shape.
Signature blocks are elided for brevity.

### 5.1 Cybersec Ladder (mirrors STS verbatim)

```json
{
  "schema": "chio.federation.governance-ladder-manifest.v1",
  "manifest_id": "sts.cybersec.ladder.2026-05-04",
  "participant_id": "did:chio:sts-reference",
  "domain": "cybersec",
  "ladder_version": "1.0.0",
  "modes": ["observation", "guarded", "receipt_backed", "partition_contingency", "maintenance"],
  "default_unmapped_mode": "receipt_backed",
  "destructive_floor": "receipt_backed",
  "ladder_refusal_policy": {
    "on_unknown_class": "fall_back_to_default",
    "on_intersection_empty": "refuse",
    "on_floor_disagreement": "refuse",
    "on_alias_conflict": "refuse"
  },
  "action_classes": [
    {
      "id": "whisker.pheromone_deposit",
      "title": "Whisker pheromone deposit",
      "mode": "observation",
      "destructive": false,
      "cross_org_visibility": "treaty_only",
      "evidence_required": ["listing"],
      "co_sign": "none",
      "consistency_model": "crdt-commutative"
    },
    {
      "id": "stalker.investigation_publish",
      "title": "Stalker investigation finding",
      "mode": "observation",
      "destructive": false,
      "cross_org_visibility": "treaty_only",
      "evidence_required": ["listing", "registry_search"],
      "co_sign": "none",
      "consistency_model": "crdt-commutative"
    },
    {
      "id": "weaver.incident_correlate",
      "title": "Weaver incident correlation",
      "mode": "observation",
      "destructive": false,
      "cross_org_visibility": "treaty_only",
      "evidence_required": ["listing", "workflow_receipt"],
      "co_sign": "none",
      "consistency_model": "crdt-commutative"
    },
    {
      "id": "sphinx.memory_publish",
      "title": "Sphinx durable memory write",
      "mode": "observation",
      "destructive": false,
      "cross_org_visibility": "private",
      "evidence_required": ["listing"],
      "co_sign": "none",
      "consistency_model": "crdt-commutative"
    },
    {
      "id": "calico.decoy_deploy",
      "title": "Calico decoy deployment",
      "mode": "guarded",
      "destructive": false,
      "cross_org_visibility": "private",
      "evidence_required": ["operator_report"],
      "co_sign": "none",
      "consistency_model": "totally-ordered",
      "consistency_anchor": "hash-chain"
    },
    {
      "id": "kitten.detector_promote",
      "title": "Kitten detector promotion",
      "mode": "guarded",
      "destructive": false,
      "cross_org_visibility": "treaty_only",
      "evidence_required": ["operator_report", "workflow_receipt"],
      "co_sign": "none",
      "consistency_model": "totally-ordered",
      "consistency_anchor": "hash-chain"
    },
    {
      "id": "tom.escalation_receipt",
      "title": "Tom non-destructive escalation",
      "mode": "guarded",
      "destructive": false,
      "cross_org_visibility": "treaty_only",
      "evidence_required": ["trust_activation"],
      "co_sign": "bilateral_if_cross_org",
      "consistency_model": "totally-ordered",
      "consistency_anchor": "hash-chain"
    },
    {
      "id": "pouncer.block_egress",
      "title": "Pouncer BlockEgress",
      "mode": "receipt_backed",
      "destructive": true,
      "cross_org_visibility": "treaty_only",
      "evidence_required": ["trust_activation", "workflow_receipt", "anchor_epoch"],
      "co_sign": "bilateral_if_cross_org",
      "consistency_model": "totally-ordered",
      "consistency_anchor": "chio-anchor",
      "partition_fallback": {
        "lease_kind": "narrow_destructive",
        "blast_radius_cap": { "unit": "host", "max": 8 },
        "ttl_secs": 900
      }
    },
    {
      "id": "pouncer.isolate_host",
      "title": "Pouncer IsolateHost",
      "mode": "receipt_backed",
      "destructive": true,
      "cross_org_visibility": "treaty_only",
      "evidence_required": ["trust_activation", "workflow_receipt", "anchor_epoch"],
      "co_sign": "bilateral_if_cross_org",
      "consistency_model": "totally-ordered",
      "consistency_anchor": "chio-anchor",
      "partition_fallback": {
        "lease_kind": "narrow_destructive",
        "blast_radius_cap": { "unit": "host", "max": 4 },
        "ttl_secs": 600
      }
    },
    {
      "id": "pouncer.revoke_credential",
      "title": "Pouncer RevokeCredential (cross-issuer)",
      "mode": "receipt_backed",
      "destructive": true,
      "cross_org_visibility": "federated",
      "evidence_required": ["trust_activation", "passport_presentation", "anchor_epoch"],
      "co_sign": "n_of_m",
      "co_sign_quorum": { "n": 2, "m": 3, "scope": "treaty" },
      "consistency_model": "quorum-required",
      "consistency_anchor": "frost-quorum"
    }
  ]
}
```

### 5.2 Financial Ladder

Drawn from
[../crates/economy/chio-autonomy/src/lib.rs](../crates/economy/chio-autonomy/src/lib.rs),
[../crates/economy/chio-market/src/lib.rs](../crates/economy/chio-market/src/lib.rs),
[../crates/economy/chio-credit/src/lib.rs](../crates/economy/chio-credit/src/lib.rs),
and [../crates/economy/chio-settle/src/lib.rs](../crates/economy/chio-settle/src/lib.rs).

```json
{
  "schema": "chio.federation.governance-ladder-manifest.v1",
  "manifest_id": "treasury.financial.ladder.2026-05-04",
  "participant_id": "did:chio:treasury-reference",
  "domain": "financial",
  "ladder_version": "1.0.0",
  "modes": ["observation", "guarded", "receipt_backed", "partition_contingency", "maintenance"],
  "default_unmapped_mode": "receipt_backed",
  "destructive_floor": "receipt_backed",
  "ladder_refusal_policy": {
    "on_unknown_class": "refuse",
    "on_intersection_empty": "refuse",
    "on_floor_disagreement": "refuse",
    "on_alias_conflict": "refuse"
  },
  "action_classes": [
    {
      "id": "market.bid_publish",
      "title": "Open-market BidRequest publication",
      "mode": "observation",
      "destructive": false,
      "cross_org_visibility": "federated",
      "evidence_required": ["listing"],
      "co_sign": "none",
      "consistency_model": "crdt-commutative"
    },
    {
      "id": "market.ask_response",
      "title": "AskResponse advisory quote",
      "mode": "guarded",
      "destructive": false,
      "cross_org_visibility": "treaty_only",
      "evidence_required": ["listing", "operator_report"],
      "co_sign": "none",
      "consistency_model": "totally-ordered",
      "consistency_anchor": "hash-chain"
    },
    {
      "id": "autonomy.pricing_decision",
      "title": "AutonomousPricingDecision (within envelope)",
      "mode": "guarded",
      "destructive": false,
      "cross_org_visibility": "treaty_only",
      "evidence_required": ["operator_report", "workflow_receipt"],
      "co_sign": "none",
      "consistency_model": "totally-ordered",
      "consistency_anchor": "hash-chain"
    },
    {
      "id": "autonomy.capital_pool_recommendation",
      "title": "CapitalPoolOptimization recommendation",
      "mode": "guarded",
      "destructive": false,
      "cross_org_visibility": "private",
      "evidence_required": ["operator_report"],
      "co_sign": "none",
      "consistency_model": "crdt-commutative"
    },
    {
      "id": "credit.scorecard_publish",
      "title": "CreditScorecard publication",
      "mode": "observation",
      "destructive": false,
      "cross_org_visibility": "treaty_only",
      "evidence_required": ["listing", "trust_activation"],
      "co_sign": "none",
      "consistency_model": "crdt-commutative"
    },
    {
      "id": "credit.facility_bind",
      "title": "Credit facility binding (IOU mint)",
      "mode": "receipt_backed",
      "destructive": true,
      "cross_org_visibility": "federated",
      "evidence_required": ["trust_activation", "workflow_receipt", "anchor_epoch"],
      "co_sign": "bilateral_required",
      "consistency_model": "totally-ordered",
      "consistency_anchor": "chio-anchor",
      "partition_fallback": {
        "lease_kind": "narrow_destructive",
        "blast_radius_cap": { "unit": "amount_minor", "max": 10000 },
        "ttl_secs": 300
      }
    },
    {
      "id": "market.liability_auto_bind",
      "title": "LiabilityAutoBindDecision",
      "mode": "receipt_backed",
      "destructive": true,
      "cross_org_visibility": "federated",
      "evidence_required": ["trust_activation", "passport_presentation", "workflow_receipt", "anchor_epoch"],
      "co_sign": "bilateral_required",
      "consistency_model": "totally-ordered",
      "consistency_anchor": "chio-anchor"
    },
    {
      "id": "settle.commitment",
      "title": "SettlementCommitment dispatch",
      "mode": "receipt_backed",
      "destructive": true,
      "cross_org_visibility": "federated",
      "evidence_required": ["trust_activation", "workflow_receipt", "anchor_epoch"],
      "co_sign": "n_of_m",
      "co_sign_quorum": { "n": 2, "m": 3, "scope": "treaty" },
      "consistency_model": "quorum-required",
      "consistency_anchor": "frost-quorum"
    },
    {
      "id": "settle.rollback",
      "title": "AutonomousRollbackPlan execution",
      "mode": "receipt_backed",
      "destructive": true,
      "cross_org_visibility": "treaty_only",
      "evidence_required": ["operator_report", "workflow_receipt"],
      "co_sign": "bilateral_required",
      "consistency_model": "totally-ordered",
      "consistency_anchor": "chio-anchor",
      "partition_fallback": {
        "lease_kind": "delegated_action",
        "blast_radius_cap": { "unit": "amount_minor", "max": 5000 },
        "ttl_secs": 600
      }
    },
    {
      "id": "settle.evidence_export",
      "title": "Settlement evidence export and replay",
      "mode": "maintenance",
      "destructive": false,
      "cross_org_visibility": "private",
      "evidence_required": ["operator_report"],
      "co_sign": "none",
      "consistency_model": "totally-ordered",
      "consistency_anchor": "hash-chain"
    }
  ]
}
```

Workflow composition in the Chio verifier uses two verifier-owned
classes layered over this profile:

- `workflow.grant_issue`: guarded, non-destructive, and used when a
  verifier accepts one workflow grant as the parent of several
  pairwise vendor intersections.
- `workflow.aggregate_publish`: guarded, non-destructive, and used when
  a verifier accepts a vendor co-signed aggregate workflow receipt as
  the workflow-level evidence object.

Strict Chio verifier trust bundles MUST include these product-owned
class names. Non-strict manifests MAY carry deployment-specific aliases,
but those aliases do not satisfy strict workflow-package verification
unless mapped to the product-owned classes by verifier-owned policy.

### 5.3 Compliance Ladder

Drawn from
[../crates/trust/chio-governance/src/lib.rs](../crates/trust/chio-governance/src/lib.rs)
and
[../crates/trust/chio-credentials/src/lib.rs](../crates/trust/chio-credentials/src/lib.rs).

```json
{
  "schema": "chio.federation.governance-ladder-manifest.v1",
  "manifest_id": "regulator.compliance.ladder.2026-05-04",
  "participant_id": "did:chio:regulator-reference",
  "domain": "compliance",
  "ladder_version": "1.0.0",
  "modes": ["observation", "guarded", "receipt_backed", "partition_contingency", "maintenance"],
  "default_unmapped_mode": "receipt_backed",
  "destructive_floor": "receipt_backed",
  "ladder_refusal_policy": {
    "on_unknown_class": "fall_back_to_default",
    "on_intersection_empty": "refuse",
    "on_floor_disagreement": "refuse",
    "on_alias_conflict": "refuse"
  },
  "action_classes": [
    {
      "id": "registry.passport_listing",
      "title": "Agent passport listing publication",
      "mode": "observation",
      "destructive": false,
      "cross_org_visibility": "federated",
      "evidence_required": ["listing"],
      "co_sign": "none",
      "consistency_model": "crdt-commutative"
    },
    {
      "id": "governance.charter_publish",
      "title": "Charter publication (initial)",
      "mode": "guarded",
      "destructive": false,
      "cross_org_visibility": "public",
      "evidence_required": ["listing", "operator_report"],
      "co_sign": "none",
      "consistency_model": "totally-ordered",
      "consistency_anchor": "hash-chain"
    },
    {
      "id": "governance.case_file_dispute",
      "title": "Dispute case filing",
      "mode": "guarded",
      "destructive": false,
      "cross_org_visibility": "treaty_only",
      "evidence_required": ["listing", "registry_search"],
      "co_sign": "bilateral_if_cross_org",
      "consistency_model": "totally-ordered",
      "consistency_anchor": "hash-chain",
      "aliases": [
        { "domain": "cybersec", "id": "tom.escalation_receipt" }
      ]
    },
    {
      "id": "governance.case_file_freeze",
      "title": "Freeze case filing",
      "mode": "receipt_backed",
      "destructive": true,
      "cross_org_visibility": "federated",
      "evidence_required": ["trust_activation", "registry_search", "anchor_epoch"],
      "co_sign": "bilateral_required",
      "consistency_model": "totally-ordered",
      "consistency_anchor": "chio-anchor",
      "partition_fallback": {
        "lease_kind": "scoped_observation",
        "blast_radius_cap": { "unit": "subject", "max": 4 },
        "ttl_secs": 1800
      }
    },
    {
      "id": "governance.case_enforce_sanction",
      "title": "Sanction enforcement against operator",
      "mode": "receipt_backed",
      "destructive": true,
      "cross_org_visibility": "federated",
      "evidence_required": ["trust_activation", "registry_search", "operator_report", "anchor_epoch"],
      "co_sign": "n_of_m",
      "co_sign_quorum": { "n": 3, "m": 5, "scope": "treaty" },
      "consistency_model": "quorum-required",
      "consistency_anchor": "frost-quorum"
    },
    {
      "id": "credentials.passport_revoke",
      "title": "Passport revocation",
      "mode": "receipt_backed",
      "destructive": true,
      "cross_org_visibility": "federated",
      "evidence_required": ["trust_activation", "passport_presentation", "anchor_epoch"],
      "co_sign": "n_of_m",
      "co_sign_quorum": { "n": 2, "m": 3, "scope": "treaty" },
      "consistency_model": "quorum-required",
      "consistency_anchor": "frost-quorum",
      "aliases": [
        { "domain": "cybersec", "id": "pouncer.revoke_credential" }
      ]
    },
    {
      "id": "credentials.tier_demote",
      "title": "Trust-tier demotion",
      "mode": "receipt_backed",
      "destructive": true,
      "cross_org_visibility": "federated",
      "evidence_required": ["trust_activation", "registry_search", "anchor_epoch"],
      "co_sign": "bilateral_required",
      "consistency_model": "totally-ordered",
      "consistency_anchor": "chio-anchor",
      "partition_fallback": {
        "lease_kind": "scoped_observation",
        "blast_radius_cap": { "unit": "subject", "max": 16 },
        "ttl_secs": 3600
      }
    },
    {
      "id": "governance.appeal_resolve",
      "title": "Appeal resolution",
      "mode": "receipt_backed",
      "destructive": false,
      "cross_org_visibility": "treaty_only",
      "evidence_required": ["registry_search", "operator_report"],
      "co_sign": "bilateral_required",
      "consistency_model": "totally-ordered",
      "consistency_anchor": "hash-chain"
    },
    {
      "id": "governance.charter_rotate",
      "title": "Charter rotation (operator-driven)",
      "mode": "maintenance",
      "destructive": false,
      "cross_org_visibility": "public",
      "evidence_required": ["operator_report"],
      "co_sign": "none",
      "consistency_model": "totally-ordered",
      "consistency_anchor": "hash-chain"
    }
  ]
}
```

---

## 6. Cross-Domain Handshake Protocol

Two manifests are reconciled at handshake time into a co-signed
intersection artefact.

### 6.1 Intersection Artefact Schema

The intersection schema identifier is
`chio.federation.ladder-intersection.v1`. JSON Schema (Draft 2020-12):

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "chio.federation.ladder-intersection.v1",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "schema",
    "intersection_id",
    "treaty_scope",
    "left_manifest",
    "right_manifest",
    "intersected_classes",
    "destructive_floor",
    "produced_at",
    "co_signature"
  ],
  "properties": {
    "schema": { "type": "string", "const": "chio.federation.ladder-intersection.v1" },
    "intersection_id": { "type": "string", "pattern": "^[A-Za-z0-9._:-]{1,128}$" },
    "treaty_scope": { "type": "string", "minLength": 1 },
    "left_manifest": { "$ref": "#/$defs/manifestRef" },
    "right_manifest": { "$ref": "#/$defs/manifestRef" },
    "destructive_floor": {
      "type": "string",
      "enum": ["receipt_backed", "partition_contingency", "maintenance"]
    },
    "intersected_classes": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["intersected_id", "left_id", "right_id", "mode", "co_sign", "consistency_model"],
        "properties": {
          "intersected_id": { "type": "string" },
          "left_id": { "type": "string" },
          "right_id": { "type": "string" },
          "mode": { "type": "string" },
          "co_sign": { "type": "string" },
          "consistency_model": { "type": "string" },
          "alias_collapsed_from": {
            "type": "array",
            "items": { "type": "string" }
          }
        }
      }
    },
    "produced_at": { "type": "integer", "minimum": 0 },
    "co_signature": {
      "type": "object",
      "additionalProperties": false,
      "required": ["left", "right"],
      "properties": {
        "left": { "$ref": "chio.federation.governance-ladder-manifest.v1#/$defs/signature" },
        "right": { "$ref": "chio.federation.governance-ladder-manifest.v1#/$defs/signature" }
      }
    }
  },
  "$defs": {
    "manifestRef": {
      "type": "object",
      "additionalProperties": false,
      "required": ["manifest_id", "participant_id", "ladder_version", "sha256"],
      "properties": {
        "manifest_id": { "type": "string" },
        "participant_id": { "type": "string" },
        "ladder_version": { "type": "string" },
        "sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
      }
    }
  }
}
```

### 6.2 Workflow Intersection Artifact

The package-level workflow intersection schema identifier is
`chio.attest.workflow-intersection.v1`. It is not a replacement for a
pairwise ladder intersection. It binds several pairwise intersections
under one workflow grant so an offline verifier can check the complete
workflow composition without trusting package-owned policy.

The artifact MUST include:

- `workflow_id` and `workflow_grant_id`.
- One `pairwise_intersection_refs` entry for each vendor peer used by
  the workflow.
- One `step_class_bindings` entry for each workflow step, binding step
  index, tool name, verifier action-class id, and peer kernel id.
- One `required_vendor_signers` entry for each detached aggregate
  workflow co-signature the verifier requires.
- `aggregate_workflow_receipt_sha256`, the SHA-256 of the canonical
  workflow receipt body.

Acceptance also requires a verifier-owned trust bundle entry with the
artifact's canonical SHA-256. A package-carried workflow intersection is
portable audit evidence, not a trust root.

### 6.3 Reconciliation Rules

Given left and right manifests for a requested treaty scope:

1. **Higher-intensity-wins.** For each class id present in both
   manifests, the intersected `mode` MUST be the higher-intensity of the
   two (per the ordering in section 3). Likewise the intersected
   `co_sign` MUST be the strictest of the two (`bilateral_required >
   bilateral_if_cross_org > none`; `n_of_m` is strictest where present
   and the larger `n` MUST be taken). The intersected
   `consistency_model` MUST be the strictest of the two (`quorum-required
   > totally-ordered > crdt-commutative`).
2. **Alias-collapse.** If a class on one side declares an `aliases` entry
   matching a class id on the other side, the two MUST be treated as the
   same class for intersection. The intersected entry MUST list both
   source ids in `alias_collapsed_from`. Conflicting alias declarations
   (each side claims the other is its alias under different intersected
   ids) MUST be refused with `ladder.alias_conflict`.
3. **destructive_floor.** The intersected `destructive_floor` MUST be the
   higher of the two declared floors. If the two floors differ by more
   than one rung in the section 3 ordering, the handshake MUST be
   refused with `ladder.missing_floor`.
4. **Unknown classes.** Classes present on only one side fall back to the
   other side's `default_unmapped_mode`. They are added to
   `intersected_classes` only if both sides' refusal policies agree
   (`fall_back_to_default` on both sides). Otherwise they are dropped
   from the treaty surface.
5. **Empty intersection.** If `intersected_classes` would be empty for
   the requested treaty scope, the handshake MUST be refused with
   `ladder.intersection_empty`.

The intersection MUST be co-signed by both kernels before any cross-trust
action is dispatched. The co-signed artefact is pinned to the
`FederationPeer` record under the same store as the handshake envelope.

---

## 7. Validation Rules And Error Codes

A manifest, intersection, or amendment that fails any of the rules below
MUST be rejected, and the failure MUST be recordable as a
`GenericGovernanceCaseKind::Dispute` carrying the error code as the
finding code extension.

| Code | Meaning |
| --- | --- |
| `ladder.invalid_schema` | Body fails JSON Schema validation, signature does not verify, or canonical-JSON re-serialisation produces a different hash. |
| `ladder.destructive_downgrade` | An action class declares `destructive: true` at a mode lower than `destructive_floor`. |
| `ladder.missing_floor` | `destructive_floor` is absent, or differs from the peer's by more than one rung at intersection time. |
| `ladder.consistency_underspecified` | A `destructive: true` class declares `consistency_model: crdt-commutative`, or a `totally-ordered` / `quorum-required` class omits its `consistency_anchor`. |
| `ladder.alias_conflict` | Two manifests' `aliases` declarations cannot be reconciled into a single intersected id. |
| `ladder.partition_overcap` | A `partition_fallback.blast_radius_cap.max` exceeds the treaty-scope cap, or `ttl_secs` exceeds the manifest-wide ceiling implied by the floor. |
| `ladder.co_sign_visibility_contradiction` | `co_sign: none` is paired with `cross_org_visibility: federated` or `public` for a `destructive: true` class, or `bilateral_required` is paired with `cross_org_visibility: private`. |
| `ladder.unknown_class_default_too_low` | `default_unmapped_mode` is `observation` or `guarded`, or is lower-intensity than the destructive_floor. |
| `ladder.quorum_misdeclared` | `co_sign: n_of_m` is declared without `co_sign_quorum`, or `n > m`, or `consistency_model != quorum-required`. |
| `ladder.intersection_empty` | Section 6 reconciliation produced no class for the requested treaty scope. |
| `ladder.amendment_downgrade_unsigned` | An amendment downgrades an action class without co-signature from every active peer (section 8). |
| `ladder.amendment_stale` | An amendment references a `prior_manifest_sha256` that is no longer current at any active peer. |
| `ladder.consistency_class_mismatch` | An action class is declared with a `consistency_model` incompatible with the substrate it targets (e.g. a pheromone-deposit class declared `totally-ordered` or `quorum-required`; per `spec/CHIO_PHEROMONE.md` introduction, pheromones are intrinsically `crdt-commutative`). |

Implementations SHOULD surface these codes verbatim in the
`GenericGovernanceFinding.code_extension` field so a third party can
replay the dispute deterministically.

---

## 8. Amendment Protocol

A published manifest is changed only by a co-signed amendment artefact.
The amendment schema identifier is `chio.federation.governance-ladder-amendment.v1`.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "chio.federation.governance-ladder-amendment.v1",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "schema",
    "amendment_id",
    "manifest_id",
    "participant_id",
    "prior_manifest_sha256",
    "next_manifest_sha256",
    "change_kind",
    "rotation_deadline",
    "produced_at",
    "self_signature"
  ],
  "properties": {
    "schema": { "type": "string", "const": "chio.federation.governance-ladder-amendment.v1" },
    "amendment_id": { "type": "string", "pattern": "^[A-Za-z0-9._:-]{1,128}$" },
    "manifest_id": { "type": "string" },
    "participant_id": { "type": "string" },
    "prior_manifest_sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
    "next_manifest_sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
    "change_kind": {
      "type": "string",
      "enum": ["upgrade_only", "mixed", "downgrade_only"]
    },
    "rotation_deadline": {
      "type": "integer",
      "minimum": 0,
      "description": "Unix seconds. Peers MUST adopt by this time or the amendment is treated as expired."
    },
    "produced_at": { "type": "integer", "minimum": 0 },
    "self_signature": { "$ref": "chio.federation.governance-ladder-manifest.v1#/$defs/signature" },
    "peer_co_signatures": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["peer_id", "signature"],
        "properties": {
          "peer_id": { "type": "string" },
          "signature": { "$ref": "chio.federation.governance-ladder-manifest.v1#/$defs/signature" }
        }
      }
    }
  },
  "allOf": [
    {
      "if": { "properties": { "change_kind": { "enum": ["mixed", "downgrade_only"] } } },
      "then": { "required": ["peer_co_signatures"] }
    }
  ]
}
```

### 8.1 Backwards-Compatibility Rules

An **upgrade** raises an action class's intensity (mode, co_sign, or
consistency_model). An upgrade-only amendment requires only
`self_signature` plus federation-gossip notification; peers MUST adopt by
`rotation_deadline`.

A **downgrade** lowers any of those fields, removes a `partition_fallback`
cap (making it more permissive), widens `cross_org_visibility`, or
weakens `destructive_floor`. A `mixed` or `downgrade_only` amendment MUST
carry a `peer_co_signatures` entry from every peer with an active
intersection referencing the manifest. Missing co-signatures MUST cause
rejection with `ladder.amendment_downgrade_unsigned`.

A removed action class is treated as a downgrade unless the class did
not appear in any active intersection.

`rotation_deadline` MUST NOT be earlier than `produced_at + 24h` for
downgrades and MAY be as low as `produced_at + 1h` for upgrades. After
the deadline, peers that have not adopted MUST either accept the new
manifest or be removed from the federation graph; the local kernel files
a `GenericGovernanceCaseKind::Freeze` against the unresponsive peer.

### 8.2 Adoption

Adoption is the act of replacing the pinned manifest in the
`FederationPeer` record with the body whose canonical-JSON SHA-256 equals
`next_manifest_sha256` and re-running section 6 against every active
peer. The previous intersection is superseded; existing in-flight
receipts retain their original intersection reference and remain
verifiable.

---

## 9. Open Items

- BBS+ projection of the manifest body so a peer can prove "we declare a
  class X at receipt_backed" without revealing the full class table.
- The `chio-pheromone` substrate spec is the sibling gating spec;
  pheromone-deposit action classes pin to its wire format.
- A `ladder.dispute_resolution` workflow that turns a section 7 finding
  into an actionable `GenericGovernanceCaseEvaluation` with named
  remediation steps.
