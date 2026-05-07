# Chiodos Three-Vendor Worked Fixture

**Status:** Research / illustrative
**Date:** 2026-05-04
**Companion specs:**
[CHIODOS_CONCEPT.md](CHIODOS_CONCEPT.md) v1.1,
[CHIODOS_PHEROMONE.md](../../spec/CHIODOS_PHEROMONE.md) v0.1,
[CHIODOS_LADDER.md](../../spec/CHIODOS_LADDER.md) v0.1.

This fixture walks one buyer (Buyer Corp) through a customer-support
workflow that composes three vendors:

- Vendor A (DataCo): customer-record provider; tool `customer_record.read`.
- Vendor B (LlamaWorks): LLM drafting provider; tool `draft.support_response`.
- Vendor C (PaySwift): payments provider; tool `refund.execute`.

A buyer auditor (Buyer Corp Compliance) must later verify every
cross-vendor action under selective disclosure: customer PII is
withheld; only "refund <= $250 was issued to a verified KYC-tier-2
customer" is revealed. Gaps surfaced are tabulated in section 11. JSON
sketches are illustrative (not strict canonical JSON); fields annotated
`// illustrative, not normative` make a choice neither spec yet pins.

---

## 1. Federation Handshake And Ladder Intersection

Buyer Corp performs three separate bilateral handshakes (one per
vendor). Each handshake exchanges
[PeerHandshakeEnvelope](../../crates/chio-federation/src/trust_establishment.rs)
challenges, then immediately exchanges
[chio.chiodos-ladder.v1](../../spec/CHIODOS_LADDER.md) manifests and
produces a co-signed `chio.chiodos-ladder-intersection.v1` per pair.

Buyer Corp publishes a **buyer-side ladder** (a hybrid of the financial
and compliance reference profiles in
[CHIODOS_LADDER.md](../../spec/CHIODOS_LADDER.md) section 5).

### 1.1 Handshake envelope (Buyer Corp -> Vendor A; symmetric in reverse)

```json
{
  "challenge": {
    "schema": "chio.federation-kernel-handshake.v1",
    "localKernelId": "did:chio:buyer-corp", "remoteKernelId": "did:chio:dataco",
    "nonce": "9c8a4f2e6d1b47a0b3e5f6c7d8e9f0a1", "timestamp": 1746360000
  },
  "declaredPublicKey": "ed25519:0xBUYER_CORP_PUB",
  "signature": "ed25519:0xBUYER_CORP_HANDSHAKE_SIG"
}
```

Vendor A returns the symmetric envelope signed by `did:chio:dataco`.

After both envelopes verify and the rotation window is set
(`DEFAULT_ROTATION_WINDOW_SECS = 12h`), each side pins a
`FederationPeer` record. **Immediately after pinning**, both sides
exchange `chio.chiodos-ladder.v1` bodies. (Section 11 Gap G1: the
handshake envelope schema does not yet carry a manifest reference; the
exchange is illustrated as a follow-on RPC.)

### 1.2 Buyer Corp ladder manifest (excerpt; relevant classes only)

```json
{
  "schema": "chio.chiodos-ladder.v1",
  "manifest_id": "buyer.support-ops.ladder.2026-05-04",
  "participant_id": "did:chio:buyer-corp",
  "domain": "financial",
  "ladder_version": "1.0.0",
  "modes": ["observation", "guarded", "receipt_backed", "partition_contingency", "maintenance"],
  "default_unmapped_mode": "receipt_backed",
  "destructive_floor": "receipt_backed",
  "ladder_refusal_policy": {
    "on_unknown_class": "refuse", "on_intersection_empty": "refuse",
    "on_floor_disagreement": "refuse", "on_alias_conflict": "refuse"
  },
  "action_classes": [
    {
      "id": "data.customer_record_read", "mode": "guarded", "destructive": false,
      "cross_org_visibility": "treaty_only",
      "evidence_required": ["trust_activation", "passport_presentation"],
      "co_sign": "bilateral_required",
      "consistency_model": "totally-ordered", "consistency_anchor": "hash-chain"
    },
    {
      "id": "llm.draft_support_response", "mode": "guarded", "destructive": false,
      "cross_org_visibility": "treaty_only", "evidence_required": ["workflow_receipt"],
      "co_sign": "bilateral_required",
      "consistency_model": "totally-ordered", "consistency_anchor": "hash-chain"
    },
    {
      "id": "payments.refund_execute", "mode": "receipt_backed", "destructive": true,
      "cross_org_visibility": "federated",
      "evidence_required": ["trust_activation", "workflow_receipt", "anchor_epoch", "passport_presentation"],
      "co_sign": "bilateral_required",
      "consistency_model": "totally-ordered", "consistency_anchor": "chio-anchor",
      "partition_fallback": {
        "lease_kind": "narrow_destructive",
        "blast_radius_cap": { "unit": "amount_minor", "max": 10000 }, "ttl_secs": 300
      }
    },
    {
      "id": "workflow.grant_issue", "mode": "guarded", "destructive": false,
      "cross_org_visibility": "treaty_only", "evidence_required": ["workflow_receipt"],
      "co_sign": "none",
      "consistency_model": "totally-ordered", "consistency_anchor": "hash-chain"
    }
  ],
  "signature": { "signer_key": "ed25519:0xBUYER_CORP_PUB", "alg": "ed25519", "value": "ed25519:0xBUYER_CORP_LADDER_SIG" }
}
```

`workflow.grant_issue` is `// illustrative, not normative` (Gap G2:
no current ladder profile in
[CHIODOS_LADDER.md](../../spec/CHIODOS_LADDER.md) section 5 lists this
class, yet the workflow hand-off requires it).

Vendor A (DataCo), Vendor B (LlamaWorks), and Vendor C (PaySwift)
publish manifests in the `financial` domain covering their respective
tool classes with the same `co_sign: "bilateral_required"` and
`consistency_model: "totally-ordered"` settings. PaySwift declares
`payments.refund_execute` with an alias to `compliance::settle.commitment`.

### 1.3 Ladder intersection artefact (Buyer Corp <-> PaySwift)

Computed per [CHIODOS_LADDER.md](../../spec/CHIODOS_LADDER.md) section 6
reconciliation rules:

```json
{
  "schema": "chio.chiodos-ladder-intersection.v1",
  "intersection_id": "buyer-payswift.support-ops.2026-05-04",
  "treaty_scope": "treaty:buyer-payswift:support-ops",
  "left_manifest":  { "manifest_id": "buyer.support-ops.ladder.2026-05-04", "participant_id": "did:chio:buyer-corp", "ladder_version": "1.0.0", "sha256": "1111aa..." },
  "right_manifest": { "manifest_id": "payswift.financial.ladder.2026-05-04", "participant_id": "did:chio:payswift", "ladder_version": "1.0.0", "sha256": "2222bb..." },
  "destructive_floor": "receipt_backed",
  "intersected_classes": [
    {
      "intersected_id": "payments.refund_execute",
      "left_id": "payments.refund_execute", "right_id": "payments.refund_execute",
      "mode": "receipt_backed", "co_sign": "bilateral_required",
      "consistency_model": "totally-ordered"
    }
  ],
  "produced_at": 1746360120,
  "co_signature": {
    "left":  { "signer_key": "ed25519:0xBUYER_CORP_PUB", "alg": "ed25519", "value": "ed25519:0xINT_LEFT_SIG" },
    "right": { "signer_key": "ed25519:0xPAYSWIFT_PUB",  "alg": "ed25519", "value": "ed25519:0xINT_RIGHT_SIG" }
  }
}
```

The Buyer<->DataCo intersection covers `data.customer_record_read`; the
Buyer<->LlamaWorks intersection covers `llm.draft_support_response`. The
three intersections are stored alongside the corresponding
`FederationPeer` records.

(Section 11 Gap G2 reprise: none of the three intersections covers
`workflow.grant_issue`. The buyer's kernel issues the workflow grant
locally and that action's cross-org effect is implicit in the per-step
receipts.)

---

## 2. Open-Market BidRequest, AskResponses, AcceptedBid

Buyer Corp posts one
[BidRequest](../../crates/chio-open-market/src/bidding.rs) per vendor
under the `support-ticket-fulfillment` listing namespace.

### 2.1 BidRequest (to Vendor C / PaySwift)

```json
{
  "schema": "chio.marketplace.bid-request.v1",
  "agentId": "did:chio:buyer-corp:agent:support-orchestrator-1",
  "listingId": "listing:payswift:refund.execute:v1",
  "maxPricePerCall": { "units": 35, "currency": "USD" }, "windowSeconds": 600,
  "requestedScope": {
    "serverId": "payswift.refund-server", "toolName": "refund.execute",
    "maxInvocations": 1,
    "capabilityScopePrefix": "tool:payswift:refund.execute:tier2-le-25000c"
  },
  "issuedAt": 1746360300
}
```

### 2.2 AskResponse (PaySwift -> Buyer)

```json
{
  "schema": "chio.marketplace.ask-response.v1",
  "listingId": "listing:payswift:refund.execute:v1",
  "agentId": "did:chio:buyer-corp:agent:support-orchestrator-1",
  "bidDigest": "sha256:bid-buyer-payswift-001",
  "quotedPrice": { "units": 30, "currency": "USD" },
  "tokenOffer": {
    "id": "cap:payswift:refund:wf-001:001", "subject": "ed25519:0xBUYER_AGENT_PUB",
    "scopes": ["tool:payswift:refund.execute:tier2-le-25000c"],
    "issuedAt": 1746360305, "expiresAt": 1746360905,
    "issuer": "ed25519:0xPAYSWIFT_PUB", "signature": "ed25519:0xPAYSWIFT_TOKEN_SIG"
  },
  "issuedAt": 1746360305, "expiresAt": 1746360905
}
```

DataCo and LlamaWorks return identical-shape AskResponses with
`tool:dataco:customer_record.read` and
`tool:llamaworks:draft.support_response` scopes.

### 2.3 AcceptedBid (Buyer Corp -> all three vendors)

```json
{
  "schema": "chio.marketplace.accepted-bid.v1",
  "listingId": "listing:payswift:refund.execute:v1",
  "agentId": "did:chio:buyer-corp:agent:support-orchestrator-1",
  "bidDigest": "sha256:bid-buyer-payswift-001",
  "askDigest": "sha256:ask-payswift-001",
  "bidReceiptId": "rcpt:buyer:bid-accept:wf-001:c",
  "quotedPrice": { "units": 30, "currency": "USD" }, "acceptedAt": 1746360310,
  "tokenId": "cap:payswift:refund:wf-001:001",
  "tokenSubject": "ed25519:0xBUYER_AGENT_PUB", "tokenExpiresAt": 1746360905
}
```

The three accepted bids mint three capability tokens that the buyer's
workflow authority composes into one workflow grant (section 3).

---

## 3. Workflow Start: SkillManifest And Grant

The buyer's
[WorkflowAuthority](../../crates/chio-workflow/src/authority.rs) issues
a workflow grant binding the three capability tokens to one workflow
execution. The skill manifest sketch:

```json
{
  "schema": "chio.skill-manifest.v1",
  "skill_id": "buyer.support-ticket-refund-flow", "version": "1.0.0",
  "name": "Support ticket triage with refund",
  "steps": [
    { "step_index": 0, "server_id": "dataco.crm-server", "tool_name": "customer_record.read",
      "input_contract": { "required_fields": ["ticket_id"] },
      "output_contract": { "produced_fields": ["customer_record"] } },
    { "step_index": 1, "server_id": "llamaworks.draft-server", "tool_name": "draft.support_response",
      "input_contract": { "required_fields": ["customer_record", "ticket_id"] },
      "output_contract": { "produced_fields": ["draft_response", "anomaly_signal"] } },
    { "step_index": 2, "server_id": "payswift.refund-server", "tool_name": "refund.execute",
      "input_contract": { "required_fields": ["customer_record", "draft_response"] },
      "output_contract": { "produced_fields": ["refund_id"] } }
  ],
  "budget_envelope": { "units": 100, "currency": "USD" }, "max_duration_secs": 120
}
```

The grant references the three minted tokens by id. Because no chiodos
intersection covers `workflow.grant_issue` (section 11 Gap G2), the
grant is locally signed only.

---

## 4. Step 1 - Vendor A Invocation (DataCo customer_record.read)

The buyer agent calls `dataco.crm-server.customer_record.read`.
DataCo's kernel (Org B in
[bilateral.rs](../../crates/chio-federation/src/bilateral.rs)
nomenclature; tool host) signs first, then asks the buyer kernel (Org
A; origin) to co-sign.

### 4.1 Inner ChioReceipt body (illustrative)

```json
{
  "schema": "chio.receipt.v1", "id": "rcpt:dataco:wf-001:step0",
  "issued_at": 1746360315,
  "agent_id": "did:chio:buyer-corp:agent:support-orchestrator-1",
  "tool_invocation": {
    "server_id": "dataco.crm-server", "tool_name": "customer_record.read",
    "args_hash": "sha256:7a1d...", "result_hash": "sha256:b9e0..."
  },
  "capability_id": "cap:dataco:customer_record:wf-001:001",
  "workflow_grant_id": "wfg:buyer:wf-001", "parent_receipt_id": null,
  "consistency_anchor": { "kind": "hash-chain", "value": null },
  "kernel_key": "ed25519:0xDATACO_PUB", "signature": "ed25519:0xDATACO_RECEIPT_SIG"
}
```

`parent_receipt_id: null` because this is the first step. The
`consistency_anchor` field is an `// illustrative, not normative` choice;
[CHIODOS_LADDER.md](../../spec/CHIODOS_LADDER.md) section 4.2 names the
anchor type but [chio-workflow](../../crates/chio-workflow/src/receipt.rs)
does not yet store one inside `StepRecord` (Gap G3).

### 4.2 Bilateral co-signed wrapper

```json
{
  "schema": "chio.federation-dual-signed-receipt.v1",
  "body": { "...": "the ChioReceipt above..." },
  "orgAKernelId": "did:chio:buyer-corp",
  "orgBKernelId": "did:chio:dataco",
  "orgASignature": "ed25519:0xBUYER_COSIGN_SIG_S0",
  "orgBSignature": "ed25519:0xDATACO_COSIGN_SIG_S0"
}
```

Both signatures are over the canonical bytes of `CoSigningBody` (see
[bilateral.rs](../../crates/chio-federation/src/bilateral.rs) lines
39-77). Either side independently verifies via
[`DualSignedReceipt::verify`](../../crates/chio-federation/src/bilateral.rs).

The intersected ladder class
`treaty:buyer-dataco:support-ops/data.customer_record_read` requires
`bilateral_required` co-signing, so the wrapper is the load-bearing
receipt; the inner receipt alone is insufficient.

---

## 5. Step 2 - Vendor B Invocation (LlamaWorks draft.support_response)

LlamaWorks consumes `customer_record` produced by step 0 and emits the
drafted response.

### 5.1 Inner ChioReceipt body

```json
{
  "schema": "chio.receipt.v1", "id": "rcpt:llamaworks:wf-001:step1",
  "issued_at": 1746360355,
  "agent_id": "did:chio:buyer-corp:agent:support-orchestrator-1",
  "tool_invocation": {
    "server_id": "llamaworks.draft-server", "tool_name": "draft.support_response",
    "args_hash": "sha256:c4f1...", "result_hash": "sha256:d23e..."
  },
  "capability_id": "cap:llamaworks:draft:wf-001:001",
  "workflow_grant_id": "wfg:buyer:wf-001",
  "parent_receipt_id": "rcpt:dataco:wf-001:step0",
  "parent_receipt_sha256": "sha256:88e0...",
  "consistency_anchor": { "kind": "hash-chain", "value": "sha256:88e0..." },
  "lineage_step_index": 1,
  "kernel_key": "ed25519:0xLLAMAWORKS_PUB", "signature": "ed25519:0xLLAMAWORKS_RECEIPT_SIG"
}
```

The `parent_receipt_sha256` field is the hash-chain consistency anchor
required by `consistency_model: "totally-ordered"`. (Gap G3:
[chio-workflow `StepRecord`](../../crates/chio-workflow/src/receipt.rs)
lacks both `parent_receipt_sha256` and `consistency_anchor` fields. The
ladder spec requires them.)

### 5.2 Bilateral co-signed wrapper

Same shape as section 4.2 with `orgBKernelId: "did:chio:llamaworks"`,
`orgASignature: "ed25519:0xBUYER_COSIGN_SIG_S1"`, and
`orgBSignature: "ed25519:0xLLAMAWORKS_COSIGN_SIG_S1"`.

---

## 6. Step 3 - Vendor C Invocation (PaySwift refund.execute)

PaySwift's tool is destructive
(`payments.refund_execute -> receipt_backed`,
`destructive: true`). Three artefacts mesh together: a capability lease
narrowing the minted token, a governance receipt from the buyer kernel
authorising the destructive call, and the bilateral co-signed
invocation receipt.

### 6.1 Capability lease (narrowing the minted token to this call)

```json
{
  "schema": "chio.capability-lease.v1",
  "lease_id": "lease:payswift:refund:wf-001:c-001",
  "token_id": "cap:payswift:refund:wf-001:001",
  "agent_id": "did:chio:buyer-corp:agent:support-orchestrator-1",
  "narrowed_scopes": ["tool:payswift:refund.execute:amount_minor=24999:currency=USD:customer_id_hash=sha256:abc..."],
  "issued_at": 1746360390, "expires_at": 1746360510,
  "kernel_key": "ed25519:0xBUYER_CORP_PUB", "signature": "ed25519:0xBUYER_LEASE_SIG"
}
```
(Schema is `// illustrative, not normative`.)

(`chio.capability-lease.v1` is `// illustrative, not normative`; chio
has [CapabilityToken](../../crates/chio-open-market/src/bidding.rs) with
re-mint semantics but no separate "narrowing lease" schema. The chiodos
ladder's `partition_fallback.lease_kind` references
`narrow_destructive`, which presumes such an artefact.)

### 6.2 Governance receipt (Buyer kernel authorises destructive call)

```json
{
  "schema": "chio.governance-receipt.v1",
  "id": "gov:buyer:refund-authz:wf-001:c-001",
  "case_kind": "destructive_authorization",
  "subject": { "kernel_id": "did:chio:payswift", "tool": "refund.execute", "amount_minor": 24999, "currency": "USD" },
  "evidence": [
    { "kind": "trust_activation", "ref": "trust:buyer:dataco:tier2-confirmed:1746360320" },
    { "kind": "passport_presentation", "ref": "pp:buyer:agent-1:tier2:1746360318" },
    { "kind": "workflow_receipt", "ref": "wfr:buyer:wf-001:partial:step1" },
    { "kind": "anchor_epoch", "ref": "anchor:buyer:epoch-2026-05-04T00:00Z:#7341" }
  ],
  "issued_at": 1746360395,
  "kernel_key": "ed25519:0xBUYER_CORP_PUB", "signature": "ed25519:0xBUYER_GOV_SIG"
}
```

This is the `evidence_required: ["trust_activation", "workflow_receipt",
"anchor_epoch", "passport_presentation"]` bundle from the intersected
`payments.refund_execute` class.

### 6.3 Inner ChioReceipt and bilateral co-signed wrapper

```json
{
  "schema": "chio.receipt.v1", "id": "rcpt:payswift:wf-001:step2",
  "issued_at": 1746360400,
  "agent_id": "did:chio:buyer-corp:agent:support-orchestrator-1",
  "tool_invocation": {
    "server_id": "payswift.refund-server", "tool_name": "refund.execute",
    "args_hash": "sha256:e9a4...", "result_hash": "sha256:f2c1..."
  },
  "capability_id": "cap:payswift:refund:wf-001:001",
  "lease_id": "lease:payswift:refund:wf-001:c-001",
  "governance_receipt_id": "gov:buyer:refund-authz:wf-001:c-001",
  "workflow_grant_id": "wfg:buyer:wf-001",
  "parent_receipt_id": "rcpt:llamaworks:wf-001:step1",
  "parent_receipt_sha256": "sha256:c1d4...",
  "consistency_anchor": { "kind": "chio-anchor", "value": "anchor:buyer:epoch-2026-05-04T00:00Z:#7341" },
  "lineage_step_index": 2, "destructive": true,
  "outcome": {
    "refund_id": "refund:payswift:R-2026-05-04-89421",
    "amount_minor": 24999, "currency": "USD", "kyc_tier_at_time": "tier2"
  },
  "kernel_key": "ed25519:0xPAYSWIFT_PUB", "signature": "ed25519:0xPAYSWIFT_RECEIPT_SIG"
}
```

The dual-signed wrapper has the same shape as section 4.2 with
`orgBKernelId: "did:chio:payswift"` and the corresponding step-2
signatures.

The `chio-anchor` consistency anchor is mandated by the intersected
`consistency_model: "totally-ordered"` with
`consistency_anchor: "chio-anchor"`. The `lease_id` and
`governance_receipt_id` fields on the inner receipt are
`// illustrative, not normative` (Gap G4).

---

## 7. Workflow Finalisation

The buyer's
[WorkflowAuthority](../../crates/chio-workflow/src/authority.rs) builds
the final
[WorkflowReceipt](../../crates/chio-workflow/src/receipt.rs).

```json
{
  "id": "wfr:buyer:wf-001",
  "schema": "chio.workflow-receipt.v1",
  "started_at": 1746360300,
  "completed_at": 1746360410,
  "skill_id": "buyer.support-ticket-refund-flow",
  "skill_version": "1.0.0",
  "agent_id": "did:chio:buyer-corp:agent:support-orchestrator-1",
  "session_id": "sess:buyer:support-2026-05-04-001",
  "capability_id": "wfg:buyer:wf-001",
  "outcome": { "status": "completed" },
  "steps": [
    {
      "step_index": 0, "server_id": "dataco.crm-server", "tool_name": "customer_record.read",
      "allowed": true, "tool_receipt_id": "rcpt:dataco:wf-001:step0", "outcome": "success",
      "duration_ms": 240, "cost": { "units": 5, "currency": "USD" }, "output_hash": "sha256:b9e0...",
      "dual_signed_receipt_ref": "dsr:buyer-dataco:wf-001:step0",
      "parent_receipt_sha256": null,
      "consistency_anchor": { "kind": "hash-chain", "value": null }
    },
    {
      "step_index": 1, "server_id": "llamaworks.draft-server", "tool_name": "draft.support_response",
      "allowed": true, "tool_receipt_id": "rcpt:llamaworks:wf-001:step1", "outcome": "success",
      "duration_ms": 1820, "cost": { "units": 18, "currency": "USD" }, "output_hash": "sha256:d23e...",
      "dual_signed_receipt_ref": "dsr:buyer-llamaworks:wf-001:step1",
      "parent_receipt_sha256": "sha256:88e0...",
      "consistency_anchor": { "kind": "hash-chain", "value": "sha256:88e0..." }
    },
    {
      "step_index": 2, "server_id": "payswift.refund-server", "tool_name": "refund.execute",
      "allowed": true, "tool_receipt_id": "rcpt:payswift:wf-001:step2", "outcome": "success",
      "duration_ms": 940, "cost": { "units": 30, "currency": "USD" }, "output_hash": "sha256:f2c1...",
      "dual_signed_receipt_ref": "dsr:buyer-payswift:wf-001:step2",
      "governance_receipt_ref": "gov:buyer:refund-authz:wf-001:c-001",
      "parent_receipt_sha256": "sha256:c1d4...",
      "consistency_anchor": { "kind": "chio-anchor", "value": "anchor:buyer:epoch-2026-05-04T00:00Z:#7341" },
      "destructive": true, "amount_minor": 24999, "currency": "USD", "kyc_tier_at_time": "tier2"
    }
  ],
  "total_cost": { "units": 53, "currency": "USD" }, "duration_ms": 110000,
  "kernel_key": "ed25519:0xBUYER_CORP_PUB", "signature": "ed25519:0xBUYER_WF_SIG"
}
```

The chiodos-specific fields on each step
(`dual_signed_receipt_ref`, `governance_receipt_ref`,
`parent_receipt_sha256`, `consistency_anchor`, `destructive`,
`amount_minor`, `currency`, `kyc_tier_at_time`) are
`// illustrative, not normative`; today's
[StepRecord](../../crates/chio-workflow/src/receipt.rs) carries none
of them (Gap G3).

The aggregate workflow receipt is signed by the **buyer kernel only**.
For chiodos posture this is asymmetric: each per-step bilateral receipt
has joint authorship, but the aggregator does not. (Gap G5: should the
workflow receipt itself be co-signed by all participating vendors? The
current schema has no slot for vendor signatures over the aggregate.)

---

## 8. Auditor Disclosure (BBS+ Selective Disclosure)

The buyer's auditor (Buyer Corp Compliance) requests proof of
"refund <= $250 was issued to a verified KYC-tier-2 customer" without
seeing the customer record or the draft response.

[CHIODOS_CONCEPT.md](CHIODOS_CONCEPT.md) section 7 hard problem 4 leans
BBS+ (`bbs-2023` + AnonCreds v2 `RangeStatement`). v0.1
[CHIODOS_PHEROMONE.md](../../spec/CHIODOS_PHEROMONE.md) defers BBS+ to
v0.2. There is no normative BBS+ projection of `WorkflowReceipt` in the
specs (Gap G6).

The illustrative envelope below assumes that v0.2 will adopt the same
BBS+ projection lane the pheromone spec sketches in section 11.

### 8.1 BBS+ disclosure envelope (illustrative)

```json
{
  "schema": "chio.workflow-receipt-bbs-disclosure.v1",
  "subject_workflow_receipt_id": "wfr:buyer:wf-001",
  "subject_workflow_receipt_sha256": "sha256:9ce4...",
  "issuer_kernel_id": "did:chio:buyer-corp",
  "bbs_messages_projection_version": 1,
  "disclosed_fields": {
    "schema": "chio.workflow-receipt.v1",
    "skill_id": "buyer.support-ticket-refund-flow",
    "outcome.status": "completed",
    "steps[2].server_id": "payswift.refund-server",
    "steps[2].tool_name": "refund.execute",
    "steps[2].destructive": true,
    "steps[2].currency": "USD",
    "steps[2].kyc_tier_at_time": "tier2"
  },
  "predicate_proofs": [
    { "predicate": "RangeStatement", "field": "steps[2].amount_minor",
      "operator": "<=", "value": 25000 }
  ],
  "withheld_fields": [
    "agent_id", "session_id", "steps[0].*", "steps[1].*",
    "steps[2].tool_invocation.args_hash", "steps[2].tool_invocation.result_hash",
    "steps[2].outcome.refund_id", "steps[2].output_hash"
  ],
  "anchor_epoch": "anchor:buyer:epoch-2026-05-04T00:00Z:#7341",
  "bbs_secondary_signature": { "issuer_bbs_pub": "bls12-381:0xBUYER_BBS_PUB", "proof": "bbs-proof:0xPROOF_BLOB" },
  "ed25519_authoritative_signature_ref": "ed25519:0xBUYER_WF_SIG"
}
```

The schema id, the `bbs_messages` projection ordering over
`WorkflowReceipt`, and the field-path syntax are all
`// illustrative, not normative` (Gap G6). `kyc_tier_at_time` is
disclosed verbatim (categorical equality, no predicate needed).
`RangeStatement` mirrors the AnonCreds v2 predicate cited in
[CHIODOS_CONCEPT.md](CHIODOS_CONCEPT.md) section 7. The Ed25519
signature remains authoritative; the BBS+ proof is a secondary
commitment, mirroring
[CHIODOS_PHEROMONE.md](../../spec/CHIODOS_PHEROMONE.md) section 11.

---

## 9. Pheromone Deposit (Second-Wave; Optional)

During step 1, LlamaWorks's drafting agent detects suspicious prompt
injection patterns embedded in the customer's ticket text. It deposits
a pheromone in its local substrate and gossips to peers under the
treaty.

### 9.1 PheromoneDeposit (LlamaWorks-local)

```json
{
  "schema": "chio.pheromone-deposit.v1", "kernel_id": "did:chio:llamaworks",
  "agent_passport_key_hash": "sha256:0xLLAMAWORKS_DRAFT_AGENT_PASSPORT_HASH",
  "agent_passport_jwk_thumbprint": "jwk-thumb:abcd...",
  "subject_class": "prompt_injection.indirect.customer_input",
  "subject_class_namespace": "dev.chio.cybersec.mitre-atlas",
  "indicator": {
    "pattern_hash": "sha256:1a2b...", "ticket_id_hash": "sha256:cust-ticket-887766",
    "vendor_workflow_id_hash": "sha256:wf-001-hash"
  },
  "severity": "medium", "confidence": 0.72,
  "timestamp_unix_ms": 1746360350000, "decay_half_life_secs": 3600,
  "nonce": "AO5fQrN2u4G7xLhz9PSjmQ==",
  "treaty_scope": ["treaty:buyer-llamaworks:support-ops", "treaty:buyer-dataco:support-ops", "treaty:buyer-payswift:support-ops"],
  "signature": "ed25519:0xLLAMAWORKS_AGENT_DEPOSIT_SIG"
}
```

Signed by an **agent passport key**, not the kernel key (see
[CHIODOS_PHEROMONE.md](../../spec/CHIODOS_PHEROMONE.md) section 5.1).
Listing three buyer-side treaties in `treaty_scope` exposes Gap G7:
LlamaWorks has no direct bilateral treaty with DataCo or PaySwift; the
deposit must be hub-relayed by Buyer Corp.

### 9.2 PheromoneDepositGossip envelopes

```json
{
  "schema": "chio.pheromone-deposit-gossip.v1", "deposit": { "...": "above..." },
  "origin_kernel_id": "did:chio:llamaworks",
  "gossiping_peer_kernel_id": "did:chio:llamaworks",
  "treaty_id": "treaty:buyer-llamaworks:support-ops", "ts_unix_ms": 1746360350500
}
```

Buyer Corp re-gossips to DataCo and PaySwift under their respective
treaties:

```json
{
  "schema": "chio.pheromone-deposit-gossip.v1", "deposit": { "...": "same body..." },
  "origin_kernel_id": "did:chio:llamaworks",
  "gossiping_peer_kernel_id": "did:chio:buyer-corp",
  "treaty_id": "treaty:buyer-dataco:support-ops", "ts_unix_ms": 1746360351000
}
```

(Gap G7: the relayed envelope's `treaty_id` is **not** in the
originator's `treaty_scope` under any treaty Buyer Corp shares with
DataCo. The spec's section 3.1 receiver check rejects this envelope; a
transit-treaty rule is unspecified.) Receivers MUST still run
`validate_deposit` (signature, replay nonce, per-origin bucket).

---

## 10. Replay-Verification Walk

A third-party auditor reconstructs Buyer Corp's evidence corpus and
performs:

1. Verify each `chio.federation-dual-signed-receipt.v1` against the two pinned `FederationPeer` records.
2. For each step, recompute `parent_receipt_sha256` and assert it matches `consistency_anchor.value` (hash-chain or chio-anchor epoch root).
3. Verify the governance receipt bundles all four required evidence kinds named by the intersected class.
4. Verify the `chio.workflow-receipt.v1` aggregate signature against the buyer kernel pubkey.
5. Verify the BBS+ disclosure envelope against the buyer's secondary BBS+ pubkey, the named anchor epoch, and the disclosed projection.
6. Verify each ladder intersection co-signature and confirm every step's action-class id is in the intersection's `intersected_classes`.

Steps 2, 3, and 5 cannot run against today's schemas (Gaps G3, G6, G9, G10).

---

## 11. Gaps Surfaced

Each gap is a wire- or schema-level mesh failure exposed by the
fixture. Recommended fixes are consolidated in section 13.

- **G1. Handshake envelope omits ladder-manifest reference.**
  [trust_establishment.rs:108-114](../../crates/chio-federation/src/trust_establishment.rs)
  defines `PeerHandshakeEnvelope` as `{challenge, declared_public_key,
  signature}`. No slot for `manifest_sha256`, `manifest_id`, or the
  manifest body. The handshake completes and pins the peer before any
  governance contract is exchanged.

- **G2. No ladder reference profile lists workflow grant classes.**
  [CHIODOS_LADDER.md:462-897](../../spec/CHIODOS_LADDER.md) section 5
  has no `workflow.grant_issue` (mints the workflow grant) or
  `workflow.aggregate_publish` (publishes the aggregate WorkflowReceipt).
  The buyer-side grant binds three vendor tokens; the aggregate is
  load-bearing for joint-commit posture (see G5).

- **G3. `StepRecord` cannot carry chiodos invocation context.**
  [receipt.rs:95-118](../../crates/chio-workflow/src/receipt.rs) has
  only `tool_receipt_id`. The fixture needs
  `dual_signed_receipt_sha256`, `governance_receipt_id`,
  `parent_receipt_sha256`, `consistency_anchor`, and `destructive` on
  every step.

- **G4. No `chio.capability-lease.v1` schema exists.**
  [CHIODOS_LADDER.md:241-244](../../spec/CHIODOS_LADDER.md)'s
  `lease_kind` enum (`narrow_destructive`, `scoped_observation`,
  `delegated_action`) has no wire format in
  [chio-open-market](../../crates/chio-open-market/src/bidding.rs) or
  [chio-workflow](../../crates/chio-workflow/src/grant.rs). Step 3
  demands a narrowing lease that pins amount and customer-id-hash to
  one minted token.

- **G5. Aggregate WorkflowReceipt is single-kernel-signed.**
  [receipt.rs:46-49](../../crates/chio-workflow/src/receipt.rs) signs
  the aggregate with the buyer kernel only. Per-step bilateral
  receipts are jointly committed, but the aggregate is not. A
  third-party verifier cannot confirm the joint plan without trusting
  the buyer's view.

- **G6. BBS+ projection over WorkflowReceipt is undefined.**
  [CHIODOS_PHEROMONE.md:442-465](../../spec/CHIODOS_PHEROMONE.md)
  section 11 sketches BBS+ for one deposit body. The auditor's
  predicate ("amount_minor <= 25000") targets a **nested per-step
  field** in `WorkflowReceipt`. There is no projection-ordering rule,
  no field-path syntax, and no defined home for the BBS+ secondary
  signature.

- **G7. Hub-relayed pheromone gossip is unspecified.** The fixture
  relays a LlamaWorks deposit through Buyer Corp to DataCo and
  PaySwift under different treaties. The receiver check
  ([CHIODOS_PHEROMONE.md:139-141](../../spec/CHIODOS_PHEROMONE.md))
  rejects envelopes whose `treaty_id` is not in
  `deposit.treaty_scope`. Either the originator must enumerate
  downstream treaties transitively (impossible without discovery), or
  a transit-treaty rule must be added.

- **G8. No artefact tying multiple pairwise intersections under one
  workflow grant.** Three intersections (Buyer<->A, Buyer<->B,
  Buyer<->C), one per class. Nothing asserts that they coherently
  bound `wf-001`.

- **G9. `consistency_anchor` is declared per-class but its value is
  per-instance.** [CHIODOS_LADDER.md:265-269](../../spec/CHIODOS_LADDER.md)
  pins the **kind** at manifest time; the per-step receipt MUST carry
  the **value** (parent SHA-256, anchor-epoch id, or FROST-quorum
  scope id). No per-instance carrier is required today.

- **G10. Governance receipt schema is referenced but unnormalised.**
  [chio-governance](../../crates/chio-governance/src/lib.rs) has
  `GenericGovernanceCaseKind::{Dispute, Freeze, Sanction, Appeal}`.
  Step 3 needs a `DestructiveAuthorization` kind plus a
  `chio.governance-receipt.v1` schema enumerating the
  ladder-named evidence kinds.

- **G11. Pheromone deposits lack a workflow back-reference.** The
  prompt-injection deposit is causally tied to `wf-001` but the
  substrate has no typed `workflow_context` field; cross-incident
  replay across vendors must reconstruct the linkage from opaque
  indicator hashes.

---

## 12. Open Spec Items Exposed

Items not yet owed in either spec's open-items list:

1. **Disclosure envelope schema.** `chio.workflow-receipt-bbs-disclosure.v1` id, projection ordering, predicate-proof envelope, field-path syntax.
2. **BBS+ secondary signature placement on receipts.** Parallel field on the body, detached envelope (used in section 8), or sidecar artefact indexed by receipt id.
3. **Workflow-grant class semantics.** Non-destructive grant emission and how `evidence_required: ["workflow_receipt"]` gates destructive children.
4. **Transit-chain placement.** Inside the signed deposit body (breaks originator signature) or in the gossip envelope (preferred).
5. **Destructive-authorization receipt content.** Whether it mirrors `cross_org_visibility` and `partition_fallback.blast_radius_cap` so auditors can re-check the cap without re-walking the manifest.

---

## 13. Recommended Next Spec Edits (consolidated)

In priority order, with file:line pointers:

1. [CHIODOS_LADDER.md:265-269](../../spec/CHIODOS_LADDER.md): add per-instance `consistency_anchor_value` requirement (G9).
2. [CHIODOS_LADDER.md:462-606](../../spec/CHIODOS_LADDER.md) financial profile: add `workflow.grant_issue` and `workflow.aggregate_publish` classes (G2, G5).
3. [chio-workflow `StepRecord`](../../crates/chio-workflow/src/receipt.rs) lines 95-118: add `dual_signed_receipt_sha256`, `governance_receipt_id`, `parent_receipt_sha256`, `consistency_anchor`, `destructive` (G3).
4. [chio-workflow `WorkflowReceipt`](../../crates/chio-workflow/src/receipt.rs) lines 16-49: add optional vendor co-signatures over the aggregate canonical body (G5).
5. [trust_establishment.rs `PeerHandshakeEnvelope`](../../crates/chio-federation/src/trust_establishment.rs) lines 108-114: add `declared_ladder_manifest_sha256` and `declared_ladder_manifest_id` (G1).
6. New spec `spec/CHIODOS_CAPABILITY_LEASE.md`: freeze `chio.capability-lease.v1` to back the `partition_fallback.lease_kind` enum (G4).
7. [CHIODOS_PHEROMONE.md:114-141](../../spec/CHIODOS_PHEROMONE.md) section 3: add transit-treaty rule and `transit_chain` field (G7).
8. [CHIODOS_PHEROMONE.md:55-81](../../spec/CHIODOS_PHEROMONE.md) section 2.1: add optional `workflow_context` field (G11).
9. [CHIODOS_LADDER.md](../../spec/CHIODOS_LADDER.md) new section 6.x: `chio.chiodos-workflow-intersection.v1` tying multiple pairwise intersections under one workflow grant (G8).
10. [chio-governance](../../crates/chio-governance/src/lib.rs): add `GenericGovernanceCaseKind::DestructiveAuthorization` and freeze `chio.governance-receipt.v1` (G10).
11. New spec `spec/CHIODOS_DISCLOSURE.md`: freeze `chio.workflow-receipt-bbs-disclosure.v1`, the BBS+ projection over `WorkflowReceipt`, the field-path syntax (G6, item 12.1).

---

## 14. Out Of Scope

- Quorum-required (`frost-quorum`) action classes (refund cap kept
  bilateral_required).
- Partition-contingency lease execution (G4 is referenced, not
  exercised).
- Sanction enforcement, revocation gossip, `passport_bridge`.
- Cross-domain intersection (all manifests are `financial`).
- Hybrid (PQC) signatures.

---

## 15. Status

Research / illustrative. Every JSON sketch annotated `// illustrative,
not normative` makes a choice the companion specs leave open. Adopting
the section-13 edits should shrink the gap list to G6 and G8 (BBS+
projection and workflow-intersection artefact) plus whatever surfaces
from re-review.
