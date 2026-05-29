# Chio Web3 Trust Boundary Decisions

Status: **Decision record**
Date: 2026-03-30
Authors: Protocol Architecture
Scope: arc-anchor, arc-settle, arc-link

> Realization status (2026-04-02): these decisions are now realized across
> [CHIO_WEB3_PROFILE.md](../standards/CHIO_WEB3_PROFILE.md),
> [CHIO_LINK_PROFILE.md](../standards/CHIO_LINK_PROFILE.md),
> [CHIO_ANCHOR_PROFILE.md](../standards/CHIO_ANCHOR_PROFILE.md), and
> [CHIO_SETTLE_PROFILE.md](../standards/CHIO_SETTLE_PROFILE.md). Where the
> research used older contract names or left choices open, the shipped names
> and boundaries in those profiles supersede this document.

---

## 1. Context

Chio's web3 integration spans three planned crates:

- **arc-anchor** -- blockchain anchoring of the receipt log Merkle roots for tamper evidence
- **arc-settle** -- on-chain USDC escrow, conditional release against receipt evidence, and bond/slash mechanics
- **arc-link** -- oracle price feeds for cross-currency budget enforcement, Chainlink Functions/Automation, and cross-chain delegation transport

Each crate has a research document that describes technical options and tradeoffs. However, six trust-boundary questions remain unanswered across those documents. These questions are not implementation details -- they define where Chio's trust model ends and the blockchain layer begins. Answering them inconsistently across crates would fragment the security model.

This document makes binding decisions for all six questions. Every decision is grounded in Chio's existing primitives: `ArcReceipt`, `CapabilityToken`, `KernelCheckpoint`, `MerkleTree`/`MerkleProof`, `GuardEvidence`, `did:arc` identity, and the `RuntimeAttestationAppraisal` family.

---

## 2. Decision 1: Verifier Discovery

**How does a third party discover which chain(s) an operator anchors to?**

### Decision

Verifier discovery uses a two-layer scheme:

1. **Primary: `did:arc` DID document service endpoint.** The operator's `did:arc:{ed25519-pubkey}` identity document is extended with an `anchorService` entry listing the chains, contract addresses, and operator EVM addresses used for anchoring. The DID document is self-certifying (signed by the same Ed25519 key), so no external registry is required for resolution.

2. **Secondary: Canonical shared `ArcAnchorRegistry` contract on each supported chain.** Chio publishes a single contract instance per chain (Base as primary, Arbitrum as secondary). The contract is keyed by `msg.sender` (operator EVM address), so any verifier who knows the canonical contract address and the operator's EVM address can query `getLatest(operatorAddress)` or scan `Anchored` events without any off-chain discovery step.

The `did:arc` document structure for anchor service endpoints:

```json
{
  "id": "did:arc:{operator-ed25519-pubkey}",
  "service": [
    {
      "id": "#anchor",
      "type": "ArcAnchorService",
      "serviceEndpoint": {
        "chains": [
          {
            "chainId": "eip155:8453",
            "contract": "0x<canonical-registry-address>",
            "operatorAddress": "0x<secp256k1-address>"
          }
        ],
        "bitcoinAnchorMethod": "opentimestamps"
      }
    }
  ]
}
```

### Rationale

Chio already ships `did:arc` as its self-certifying DID method. The DID document is the natural place for service endpoint discovery -- this follows the DID Core specification's service endpoint pattern. The canonical contract address per chain eliminates the bootstrap problem: a verifier only needs to know which chain to check, not which contract instance the operator deployed.

DNS-based discovery (e.g., `_arc-anchor.operator.example.com`) was considered but rejected because it introduces a dependency on the DNS trust hierarchy, which is orthogonal to Chio's Ed25519-based identity model. On-chain registry discovery (a meta-registry listing all operators) was considered but rejected because it adds governance overhead for who can register and creates a centralization chokepoint.

### Alternatives Considered

- **DNS TXT records**: Simple and widely understood, but DNS is mutable and operator-controlled in ways that break the self-certifying property of `did:arc`. A DNS hijack could redirect verifiers to a rogue contract.
- **On-chain operator registry**: A single contract where operators self-register. This introduces governance questions (who deploys the registry? who can write?) and makes the registry itself a trust dependency. Rejected for v1; may be reconsidered if a neutral governance body emerges.
- **Well-known HTTP endpoint** (`/.well-known/arc-anchor`): Requires the operator to run an HTTP service, which not all operators want. Also introduces TLS-CA trust dependency.

### Implications

- arc-anchor must emit `did:arc` service endpoint metadata as part of its configuration output.
- arc-settle can read anchor roots from the canonical contract address without any discovery step.
- Verifier tooling needs a `did:arc` resolver that handles the `anchorService` extension.

---

## 3. Decision 2: Operator Identity Binding

**How does an on-chain anchor connect back to a specific Chio operator's `did:arc` identity?**

### Decision

The binding mechanism is a **key-binding certificate**: the operator's Ed25519 key signs a canonical JSON message containing the secp256k1 public key (or derived EVM address) used for on-chain transactions. This certificate is:

1. **Published on-chain once** during operator registration, stored in the `ArcAnchorRegistry` contract as an event.
2. **Embedded in the `did:arc` document** under the `anchorService` entry.
3. **Verifiable off-chain** by any party that knows the operator's Ed25519 public key.

The certificate format:

```json
{
  "schema": "arc.key-binding-certificate.v1",
  "ed25519_public_key": "<hex-encoded-ed25519-pubkey>",
  "evm_address": "0x<derived-from-secp256k1-pubkey>",
  "chain_scope": ["eip155:8453", "eip155:42161"],
  "purpose": ["anchor", "settle"],
  "issued_at": 1743292800,
  "expires_at": 1774828800
}
```

The certificate is signed by the Ed25519 key: `signature = Ed25519.sign(canonical_json(certificate_body), ed25519_private_key)`.

The same secp256k1 key (and therefore the same EVM address) is reused across arc-anchor and arc-settle. This means the operator manages exactly two keys total: one Ed25519 (authoritative Chio identity) and one secp256k1 (EVM transaction signing).

### Rationale

Chio's trust model places Ed25519 as the root of identity. Any on-chain action must be traceable back to an Ed25519 identity to maintain the protocol's security invariant. A key-binding certificate signed by the Ed25519 key creates a cryptographic chain from on-chain EVM address back to `did:arc`.

The certificate is time-bounded (`issued_at`/`expires_at`) to support key rotation. When the operator rotates either key, a new certificate is issued and published. The old certificate remains valid for verification of historical anchors until its `expires_at`.

The `purpose` field explicitly scopes the certificate to `anchor` and/or `settle` operations. This prevents a key intended only for anchoring from being used to authorize settlement releases, even though it is the same EVM address. The purpose field is enforced by the on-chain contracts via an access-control check at registration time.

### Alternatives Considered

- **Derive secp256k1 from Ed25519**: Mathematically non-trivial (different curves). Derivation schemes exist but are non-standard and auditable only with difficulty. Rejected because auditability matters more than key-management convenience.
- **On-chain Ed25519 verification of the binding**: The certificate could be verified on-chain via Chainlink Functions or ZK proof. This is over-engineered for v1 -- the binding only needs to be established once during registration, and off-chain verification is sufficient for the registration ceremony.
- **No explicit binding**: Trust the operator to self-report their EVM address in the DID document. This has no cryptographic backing and is trivially spoofable.

### Implications

- arc-anchor and arc-settle share the same secp256k1 key, avoiding a third key.
- The `ArcAnchorRegistry` contract should accept a `registerOperator` transaction that emits the binding certificate as an event (for on-chain discoverability).
- Key rotation requires re-registration and a new certificate. The `ArcAnchorRegistry` should store a history of operator certificates, not just the latest one.
- The certificate must be stored in the operator's local configuration for the arc-anchor and arc-settle daemons to reference during startup.

---

## 4. Decision 3: Proof Bundle Format

**When an operator needs to prove a receipt was anchored, what does the proof bundle contain?**

### Decision

The canonical proof bundle is called an `AnchorInclusionProof` and contains four layers:

```json
{
  "schema": "arc.anchor-inclusion-proof.v1",
  "receipt": { "<full ArcReceipt as canonical JSON>" },
  "receipt_inclusion": {
    "checkpoint_seq": 1042,
    "merkle_root": "<32-byte hex>",
    "tree_size": 100,
    "proof": ["<sibling hash 1>", "<sibling hash 2>", "..."],
    "leaf_index": 37
  },
  "checkpoint_statement": {
    "schema": "arc.checkpoint_statement.v1",
    "checkpoint_seq": 1042,
    "batch_start_seq": 104101,
    "batch_end_seq": 104200,
    "tree_size": 100,
    "merkle_root": "<32-byte hex>",
    "issued_at": 1743292800,
    "kernel_key": "<ed25519 pubkey hex>",
    "signature": "<ed25519 signature hex>"
  },
  "chain_anchor": {
    "chain_id": "eip155:8453",
    "contract_address": "0x<canonical-registry>",
    "operator_address": "0x<evm-address>",
    "tx_hash": "0x<transaction-hash>",
    "block_number": 12345678,
    "block_hash": "0x<block-hash>",
    "anchored_merkle_root": "<32-byte hex>",
    "anchored_checkpoint_seq": 1042
  },
  "bitcoin_anchor": {
    "method": "opentimestamps",
    "ots_proof": "<base64-encoded .ots file>",
    "bitcoin_block_height": 890123,
    "bitcoin_block_hash": "<block-hash>"
  },
  "super_root_inclusion": {
    "super_root": "<32-byte hex>",
    "proof": ["<sibling hash 1>", "..."],
    "leaf_index": 2,
    "aggregated_checkpoint_range": [1040, 1049]
  },
  "key_binding_certificate": {
    "schema": "arc.key-binding-certificate.v1",
    "ed25519_public_key": "<hex>",
    "evm_address": "0x<address>",
    "signature": "<ed25519 signature>"
  }
}
```

Not all fields are always present:

- `bitcoin_anchor` and `super_root_inclusion` are present only if the receipt's checkpoint has been aggregated into a Bitcoin super-root.
- `chain_anchor` is always present (the L2 anchor is the primary layer).
- `key_binding_certificate` is always present to close the trust chain from EVM address back to `did:arc`.

### Verification procedure

A verifier checks the proof bundle in this order:

1. **Receipt signature**: Verify `receipt.signature` against `receipt.kernel_key` using Ed25519. This proves the kernel signed the receipt.
2. **Receipt inclusion**: Recompute the Merkle leaf hash as `SHA256(0x00 || canonical_json(receipt_body))` and verify the inclusion proof against `receipt_inclusion.merkle_root` using the RFC 6962 algorithm (0x01 node prefix, carry-last-node-up for odd levels).
3. **Checkpoint statement**: Verify `checkpoint_statement.signature` against `checkpoint_statement.kernel_key`. Confirm `checkpoint_statement.merkle_root == receipt_inclusion.merkle_root`.
4. **Key binding**: Verify the `key_binding_certificate.signature` against the Ed25519 key. Confirm `key_binding_certificate.ed25519_public_key == receipt.kernel_key`. Confirm `key_binding_certificate.evm_address == chain_anchor.operator_address`.
5. **Chain anchor**: Query the `ArcAnchorRegistry` contract at `chain_anchor.contract_address` on chain `chain_anchor.chain_id`. Read the `Anchored` event at `chain_anchor.tx_hash` or query `anchors[operator_address][checkpoint_seq]`. Confirm the on-chain `merkleRoot` matches `chain_anchor.anchored_merkle_root`.
6. **Bitcoin anchor** (optional): If present, verify the `.ots` proof against a Bitcoin block header. Confirm the committed hash matches the super-root (or the checkpoint root directly if no super-root aggregation was used).
7. **Super-root inclusion** (optional): If present, verify the checkpoint root's inclusion in the super-root using a second Merkle inclusion proof.

If all checks pass, the verifier has cryptographic proof that the receipt existed when the chain anchor was published and has not been modified since.

### Rationale

The proof bundle is self-contained -- a verifier needs only the bundle, an EVM RPC endpoint, and optionally a Bitcoin node (or OTS verifier) to fully validate. No interaction with the operator is required after the bundle is obtained.

The bundle includes the full receipt (not just a hash) because the verifier needs to inspect receipt contents (decision, evidence, financial metadata) in addition to proving existence. Including the checkpoint statement allows the verifier to confirm the Merkle root's provenance without trusting the operator's claim about which checkpoint a receipt belongs to.

### Alternatives Considered

- **Hash-only bundle** (receipt hash + proof, without the full receipt): Lighter, but forces the verifier to obtain the receipt from the operator separately, which defeats the self-contained property.
- **On-chain proof storage**: Storing inclusion proofs on-chain would make them publicly queryable but at significant gas cost. Rejected -- proofs are produced and verified off-chain, with only the Merkle root published on-chain.
- **CBOR encoding** instead of JSON: More compact, but Chio uses canonical JSON as its signing format throughout. Mixing CBOR for proof bundles would introduce a serialization inconsistency.

### Implications

- arc-anchor must produce `AnchorInclusionProof` bundles on demand (given a receipt ID).
- arc-core should define the `AnchorInclusionProof` struct and its verification function.
- The proof bundle format becomes part of Chio's public contract -- once shipped, it must remain backward-compatible.
- Verifier tooling (CLI or library) should accept a proof bundle and return a pass/fail verdict with detailed step-by-step results.

---

## 5. Decision 4: Oracle Evidence in Receipts

**When a price oracle is consulted for budget enforcement, should the oracle evidence be included in the receipt?**

### Decision

Yes. Oracle evidence is included in the receipt's `evidence` array as a `GuardEvidence` entry with `guard_name: "CrossCurrencyOracleGuard"`. The `details` field carries a canonical JSON object with the oracle data used for the budget decision.

The evidence entry structure:

```json
{
  "guard_name": "CrossCurrencyOracleGuard",
  "verdict": true,
  "details": "{\"base\":\"ETH\",\"quote\":\"USD\",\"rate_numerator\":300000,\"rate_denominator\":100,\"source\":\"chainlink\",\"feed_address\":\"0x639Fe6ab55C921f74e7fac1ee960C0B6293ba612\",\"updated_at\":1743292740,\"max_age_seconds\":3600,\"cache_age_seconds\":45,\"converted_cost_units\":300,\"original_cost_units\":100000000000000,\"original_currency\":\"ETH\",\"grant_currency\":\"USD\"}"
}
```

Additionally, for governed transactions with financial metadata, the `FinancialReceiptMetadata` carries a new optional field `oracle_evidence`:

```rust
pub struct FinancialReceiptMetadata {
    // ... existing fields ...
    /// Oracle price evidence used for cross-currency conversion, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oracle_evidence: Option<OracleConversionEvidence>,
}

pub struct OracleConversionEvidence {
    pub base_currency: String,
    pub quote_currency: String,
    pub rate_numerator: u128,
    pub rate_denominator: u128,
    pub source: String,
    pub updated_at: u64,
    pub cache_age_seconds: u64,
}
```

This dual placement -- in both `evidence` (for guard pipeline auditability) and `metadata.financial.oracle_evidence` (for economic reconciliation) -- follows the existing pattern where guard verdicts and financial metadata are tracked independently.

### Rationale

Chio's receipts are the immutable audit trail. If a budget decision depended on an oracle price, that price is part of the decision's provenance. Omitting it would mean the receipt is incomplete evidence -- a verifier could see that a cross-currency charge was made but not verify that the exchange rate used was reasonable at the time.

Including oracle evidence also supports:

- **Dispute resolution**: If a tool server claims the exchange rate was unfair, the receipt contains the exact rate, its source, its freshness, and the conversion arithmetic. The dispute has a concrete evidence basis.
- **Regulatory audit**: Auditors examining agent spending can verify that cross-currency conversions used market rates, not manipulated values.
- **Post-hoc manipulation detection**: If the oracle source is later discovered to have been manipulated at a specific timestamp, receipts containing that timestamp's price can be flagged for review.

The evidence is placed in the `details` field (as a JSON string) rather than as a separate top-level receipt field because Chio's `GuardEvidence` is the established mechanism for recording per-guard decision context. This preserves backward compatibility -- existing receipt consumers that do not understand oracle evidence will see it as opaque guard details.

### Alternatives Considered

- **Separate oracle evidence array on the receipt**: Cleaner, but requires an arc-core schema change to the `ArcReceiptBody`. Using the existing `evidence` array avoids a breaking change.
- **Oracle evidence in metadata only** (not in guard evidence): This would decouple oracle data from the guard pipeline, making it invisible to guard-aware tooling. Rejected -- the oracle lookup is functionally a guard check (it gates whether the invocation proceeds), so it belongs in the guard evidence.
- **No oracle evidence in receipts** (record only in the price cache or operator logs): This would make the receipt's budget decision unverifiable by third parties. Rejected -- receipts must be self-contained evidence.

### Implications

- arc-link's `PriceOracle` trait implementation must return sufficient data for the kernel to populate the `GuardEvidence` entry (source, feed address, timestamp, rate).
- The kernel's `check_and_increment_budget` path must construct a `GuardEvidence` entry when cross-currency conversion is used.
- Receipt storage and export must handle the slightly larger evidence payload. At roughly 300 bytes per oracle evidence entry, this is negligible relative to typical receipt sizes.
- `FinancialReceiptMetadata` in arc-core gains an optional `oracle_evidence` field. This is an additive schema change.

---

## 6. Decision 5: DON-based vs Direct Verification Policy

**When is Chainlink Functions (DON-based, optimistic) verification acceptable, and when must verification be direct (on-chain or local)?**

### Decision

The policy is tiered by economic value at stake and verification context:

| Context | Verification Method | Trust Model |
|---------|-------------------|-------------|
| Receipt inclusion for batch micro-settlement (<$10 per receipt) | Merkle proof against published root | Operator-attested root; on-chain Merkle proof verification (trustless once root is published) |
| Individual settlement ($10-$1000) | Dual-sign (secp256k1) with `ecrecover` | Direct on-chain verification; no DON dependency |
| Individual settlement (>$1000) | Dual-sign + L1 finality wait (12.8 min) | Direct on-chain verification + L1 settlement assurance |
| Receipt anchoring (tamper evidence) | Operator publishes Merkle root to canonical contract | Operator-attested; verified by any third party via chain query |
| Ed25519 delegation chain verification for on-chain registration | Off-chain verification at registration time | Verified by the registering party; binding certificate published as event |
| Ed25519 batch verification for anchoring audit | Chainlink Functions (DON consensus) | DON-attested; acceptable for audit-grade evidence |
| Ed25519 verification for high-value on-chain actions (>$10,000) | ZK proof (Groth16) or Solana native Ed25519 precompile | Trustless; no DON dependency |
| Cross-chain delegation proof for pre-positioned tokens | Merkle root anchored on home chain + off-chain proof distribution | Operator-attested root; verified locally by the consuming chain's contract |

**The core rule**: Chainlink Functions (DON-based verification) is acceptable when the value at stake is below $10,000 and the verification is for audit or evidence purposes (not for direct fund release). For any on-chain action that directly releases funds, verification must be either (a) on-chain Merkle proof, (b) `ecrecover` of a secp256k1 dual-signature, or (c) native Ed25519 on Solana. The DON is never the sole gatekeeper for fund release.

**Challenge mechanism for DON results**: When Chainlink Functions is used for batch receipt verification (audit anchoring), the full receipt batch data is emitted as an on-chain event log. Any party can re-verify the batch off-chain and detect DON misbehavior. If a discrepancy is found, the operator can submit a corrected root. For future phases, UMA's optimistic oracle can serve as a formal dispute layer with economic penalties for incorrect DON results.

### Rationale

Chainlink Functions runs `@noble/ed25519` in a Deno sandbox across a DON of 8-31 nodes using OCR 2.0 consensus. This is "optimistic" in the sense that it tolerates up to f Byzantine nodes in a 3f+1 configuration, but a coordinated attack by f+1 nodes could forge a verification result. The DON's staked collateral is typically much less than the value of a high-value delegation or settlement.

For micro-settlements and audit anchoring, the DON risk is acceptable because:

- The value at stake per receipt is small (the cost of a single tool invocation, typically sub-dollar).
- The alternative (on-chain Ed25519 verification at 500k+ gas) costs more than the settlement amount.
- Merkle proofs provide a second, independent verification path that does not depend on the DON.

For high-value settlements, the DON risk is not acceptable because:

- A forged verification result could release thousands of dollars to the wrong party.
- Direct verification methods (dual-sign ecrecover, ZK proof, Solana native) are available and economically justified at these values.

### Alternatives Considered

- **DON-only for all verification**: Simpler architecture, but creates a systemic risk where DON compromise affects all Chio settlements. Rejected.
- **Never use DON**: Forces dual-signing or ZK for all on-chain interactions, including low-value audit anchoring. This adds unnecessary key management complexity for operators who only want tamper evidence. Rejected -- DON verification is a reasonable trust trade for audit-grade (non-fund-releasing) operations.
- **Fixed dollar threshold** ($1,000 for all contexts): Too rigid. The threshold should vary by context -- $10 for micro-settlement (where gas cost is the binding constraint) vs $10,000 for delegation registration (where one-time ZK proving cost is amortized over many invocations).

### Implications

- arc-settle must enforce the tiered verification policy in its `releaseWithProof` and `releaseWithSignature` contract functions. The contract does not need to know about DON internals; it simply offers two release paths (Merkle proof and ecrecover).
- arc-link's Chainlink Functions integration is scoped to batch receipt verification for audit anchoring, not for direct fund release.
- Operators who want DON-free operation can disable the Chainlink Functions path entirely and rely on the daemon-based anchoring model (operator publishes roots directly).
- The tiered thresholds are operator-configurable, not protocol-hardcoded. An operator with higher risk tolerance can lower the ZK threshold; a conservative operator can require dual-sign for all amounts.

---

## 7. Decision 6: Root Publication Ownership

**Who is authorized to anchor? Only the kernel operator? Can delegates anchor on behalf of an operator?**

### Decision

Root publication is restricted to the **kernel operator** by default, with an explicit **delegate registration** mechanism for operators who want to separate the anchoring role from the kernel role.

The authorization model:

1. **Primary publisher**: The kernel operator's secp256k1 address (bound to their Ed25519 identity via the key-binding certificate). This address is registered in the `ArcAnchorRegistry` contract at setup time and is the only address authorized to call `anchor()` for that operator's checkpoint sequence.

2. **Delegate publishers**: The operator can register up to N delegate addresses (configurable, default: 3) via a `registerDelegate(address delegate, uint64 expiresAt)` function on the `ArcAnchorRegistry`. Delegate registration requires a transaction from the operator's primary address. Delegates can call `anchor()` on behalf of the operator, and the emitted `Anchored` event records both the operator identity and the delegate address.

3. **Delegate revocation**: The operator can revoke a delegate at any time via `revokeDelegate(address delegate)`. Revocation is immediate -- the delegate's next `anchor()` call will revert.

4. **Chainlink Automation as delegate**: When using Chainlink Automation for scheduled anchoring, the Automation upkeep's forwarder address is registered as a delegate. This allows Automation to publish roots on behalf of the operator without the operator's private key being accessible to the DON.

The contract interface addition:

```solidity
// On ArcAnchorRegistry
function registerDelegate(address delegate, uint64 expiresAt) external;
function revokeDelegate(address delegate) external;
function isAuthorizedPublisher(address operator, address publisher) external view returns (bool);

// Modified anchor() function
function anchor(
    address operator,        // the operator this anchor belongs to
    bytes32 merkleRoot,
    uint64 checkpointSeq,
    // ... remaining fields
) external {
    require(
        msg.sender == operator || isAuthorizedDelegate(operator, msg.sender),
        "unauthorized publisher"
    );
    // ... store and emit
}
```

**Who bears liability for incorrect roots?** The operator. A delegate is authorized to publish on behalf of the operator, but the operator is responsible for the correctness of the roots. If a delegate publishes an incorrect root (whether through compromise or malfunction), the operator's anchoring history is affected. This is analogous to how a TLS certificate authority is responsible for certificates issued by its subordinate CAs.

### Rationale

The kernel operator is the natural root publisher because:

- The kernel signs checkpoints. The operator controls the kernel's Ed25519 key. Publishing roots is a direct extension of the checkpoint-signing authority.
- The `msg.sender`-keyed storage in the `ArcAnchorRegistry` already ties anchors to the operator's EVM address.
- Fail-closed semantics: if the operator is offline, anchoring pauses but receipts continue to be signed and checkpointed locally. No data is lost.

Delegate support is necessary because:

- High-availability deployments may run the anchoring daemon on separate infrastructure from the kernel.
- Chainlink Automation (a recommended alternative to a self-hosted daemon) requires its forwarder address to be authorized.
- Multi-region deployments may have different infrastructure publishing to different chains, all on behalf of the same operator.

The delegate count is bounded (default: 3) to limit the attack surface. Each additional delegate is another key that, if compromised, could publish incorrect roots. The expiration field (`expiresAt`) ensures stale delegates are automatically deauthorized.

### Alternatives Considered

- **Operator-only, no delegates**: Simplest, but prevents Chainlink Automation integration and makes HA deployment harder. Rejected because operational flexibility matters for production.
- **Open publication** (anyone can publish roots for any operator): Eliminates the liveness dependency on the operator, but allows griefing (anyone could publish invalid roots for an operator). Rejected -- anchoring must be authorized.
- **Multisig publication** (M-of-N delegates must agree): Strongest security, but adds coordination overhead for every anchor. Overkill for an operation that happens every few minutes. Rejected for v1; may be reconsidered if an operator's anchor history has legal significance.
- **On-chain checkpoint verification** (the contract verifies the checkpoint's Ed25519 signature before accepting the root): This would make delegate authorization unnecessary because the contract would trust the checkpoint signature, not the publisher. However, on-chain Ed25519 verification is the very problem that the dual-signing and Merkle-root approaches exist to avoid. Rejected until EVM Ed25519 precompiles are available.

### Implications

- The `ArcAnchorRegistry` contract gains delegate management functions.
- arc-anchor's daemon configuration must specify whether it operates as the operator's primary address or as a delegate.
- Chainlink Automation integration requires a registration step where the upkeep's forwarder address is added as a delegate.
- The key-binding certificate (Decision 2) covers only the operator's primary address. Delegates do not need their own Ed25519 binding -- they are authorized by the operator's on-chain transaction, which is itself traceable to the operator's `did:arc` via the key-binding certificate.

---

## 8. Summary: Trust Boundary Map

The following diagram shows what trusts what in Chio's web3 integration. Arrows point from the trusting party to the trusted party. Solid lines indicate cryptographic verification; dashed lines indicate trust-by-delegation or attestation.

```
+-------------------------------------------------------------------+
|                         ARC KERNEL (TCB)                          |
|                                                                   |
|  Ed25519 signing    Checkpoint Merkle trees    Budget enforcement  |
|  Receipt creation   Guard evaluation           Capability validation|
+---+-----+-------+---+---+---+---+---+---+---+---+---+---+--------+
    |     |       |   |   |
    |     |       |   |   +---> [Oracle Price Cache]
    |     |       |   |              |
    |     |       |   |              | reads (off-chain)
    |     |       |   |              v
    |     |       |   |     +----------------+     +----------------+
    |     |       |   |     | Chainlink Feed |     | Pyth Hermes    |
    |     |       |   |     | (on-chain,     |     | (off-chain,    |
    |     |       |   |     |  DON consensus)|     |  provider-     |
    |     |       |   |     +----------------+     |  signed)       |
    |     |       |   |                            +----------------+
    |     |       |   |
    |     |       |   +---> [Key-Binding Certificate]
    |     |       |              |
    |     |       |              | Ed25519 signs secp256k1 binding
    |     |       |              v
    |     |       |     +---------------------+
    |     |       |     | Operator EVM Address |
    |     |       |     | (secp256k1)          |
    |     |       |     +--+---+-----------+---+
    |     |       |        |   |           |
    |     |       |        |   |           |
    |     |       v        v   v           v
    |     |  +---------+ +--------+  +----------+
    |     |  | arc-    | | arc-   |  | arc-     |
    |     |  | anchor  | | settle |  | link     |
    |     |  | daemon  | | daemon |  | oracle   |
    |     |  +---------+ +--------+  +----------+
    |     |       |           |
    |     |       v           v
    |     |  +----------------------------------+
    |     |  | ArcAnchorRegistry (on-chain)     |
    |     |  | - Stores Merkle roots            |
    |     |  | - Keyed by operator EVM address   |
    |     |  | - Delegate authorization          |
    |     |  +----------------------------------+
    |     |       |
    |     |       v
    |     |  +----------------------------------+
    |     |  | ArcEscrow (on-chain)             |
    |     |  | - Reads roots from registry      |
    |     |  | - Verifies Merkle proofs          |
    |     |  | - Verifies ecrecover (dual-sign) |
    |     |  | - Releases USDC                  |
    |     |  +----------------------------------+
    |     |
    |     v
    |  +----------------------------------+
    |  | OpenTimestamps / Bitcoin         |
    |  | - Super-root aggregation         |
    |  | - Highest assurance anchor       |
    |  +----------------------------------+
    |
    v
+----------------------------------+
| Third-Party Verifier             |
| - Checks AnchorInclusionProof   |
| - Verifies Ed25519 receipt sig  |
| - Verifies Merkle inclusion     |
| - Queries on-chain registry     |
| - Optionally verifies OTS proof |
+----------------------------------+
```

**Trust assumptions by layer:**

| Layer | Trust Assumption | Failure Mode |
|-------|-----------------|--------------|
| Chio Kernel (Ed25519 receipts) | Kernel private key is not compromised | Forged receipts |
| Checkpoint Merkle tree | Kernel correctly batches receipts | Incorrect tree; detected by receipt-level verification |
| Key-binding certificate | Ed25519 key holder controls the secp256k1 key | Broken identity chain; detected by verifier |
| ArcAnchorRegistry (L2) | L2 sequencer is honest for soft finality; Ethereum L1 for hard finality | Reorg risk for recent anchors (mitigated by Bitcoin layer) |
| Oracle price feeds | DON consensus (Chainlink) or provider signing (Pyth) is honest | Incorrect cross-currency conversion; bounded by staleness checks and circuit-breaker |
| Chainlink Functions | DON consensus is honest | Incorrect batch verification; mitigated by on-chain event logs for re-verification |
| Bitcoin anchor (OTS) | Bitcoin proof-of-work is honest | Timestamp forgery (infeasible for Bitcoin) |

---

## 9. Implications for Each Crate

### 9.1 arc-anchor

**New types to define:**

- `AnchorInclusionProof` (Decision 3) -- the canonical proof bundle struct, with a `verify()` method.
- `KeyBindingCertificate` (Decision 2) -- the Ed25519-to-secp256k1 binding artifact.

**Contract changes:**

- `ArcAnchorRegistry` gains `registerDelegate`, `revokeDelegate`, and `isAuthorizedPublisher` functions (Decision 6).
- The `anchor()` function signature changes to accept an explicit `operator` parameter so delegates can publish on behalf of operators (Decision 6).
- Operator registration emits a `KeyBindingCertificatePublished` event containing the binding certificate for on-chain discoverability (Decision 2).

**DID document extension:**

- The arc-anchor daemon must produce `did:arc` service endpoint metadata listing anchor chains and contract addresses (Decision 1). This metadata should be emitted as a configuration artifact that the operator can publish.

**Proof bundle generation:**

- arc-anchor must implement `generate_inclusion_proof(receipt_id) -> AnchorInclusionProof` by combining the receipt, its Merkle inclusion proof, the checkpoint statement, the chain anchor record, and the key-binding certificate (Decision 3).

### 9.2 arc-settle

**Verification path enforcement:**

- The `ArcEscrow` contract's `releaseWithProof` function reads roots from the shared `ArcAnchorRegistry`, not a separate contract (Decision 1 and Decision 3).
- The tiered verification policy (Decision 5) is enforced at the Rust daemon level, not in the contract. The daemon selects whether to call `releaseWithProof` (Merkle path for batch) or `releaseWithSignature` (dual-sign for individual). The contract itself accepts either path.

**Key management:**

- arc-settle reuses the same secp256k1 key as arc-anchor, bound by the same `KeyBindingCertificate` (Decision 2). No additional key management.

**Oracle evidence in settlement reconciliation:**

- When arc-settle reconciles on-chain settlements against receipts, it can read the `oracle_evidence` field from `FinancialReceiptMetadata` (Decision 4) to verify that the settlement amount matches the oracle-converted charge.

### 9.3 arc-link

**Oracle evidence production:**

- The `PriceOracle` trait implementation must return enough data for the kernel to populate both the `GuardEvidence` entry and the `OracleConversionEvidence` struct (Decision 4). Specifically: source identifier, feed address, rate as numerator/denominator, `updated_at` timestamp, and cache age.

**Chainlink Functions scope:**

- Functions-based Ed25519 verification is scoped to audit anchoring (batch receipt verification), not fund release (Decision 5). The arc-link integration should clearly document this boundary.

**Chainlink Automation as delegate:**

- When using Automation for scheduled anchoring, the upkeep's forwarder address must be registered as a delegate on the `ArcAnchorRegistry` (Decision 6). arc-link's Automation setup flow should include this registration step.

**CCIP delegation transport:**

- Cross-chain delegation uses the Merkle root approach (anchor delegation roots on a home chain, distribute proofs off-chain), not full CCIP message transport (Decision 5). CCIP is reserved for pre-positioning delegation bundles where latency is not critical.

---

## Appendix: Decision Cross-Reference to Open Questions

| Decision | Source Document | Original Open Question |
|----------|----------------|----------------------|
| 1 (Verifier Discovery) | arc-anchor sec. 12, item 3; arc-anchor sec. 9.4 "gap in verification chain" | "Should Chio publish a canonical contract address per chain?" and "How does a verifier discover which operator's contract and chain to query?" |
| 2 (Operator Identity Binding) | arc-settle sec. 14.2, item 4; arc-anchor sec. 12.2, item 5 | "How to prove that an Ed25519 key and a secp256k1 key belong to the same entity?" and "Should the EVM signing key be derived from the kernel's Ed25519 key?" |
| 3 (Proof Bundle Format) | arc-anchor sec. 12.3, item 7 | "What is the canonical format for an anchor proof that a verifier can independently check?" |
| 4 (Oracle Evidence in Receipts) | arc-link sec. 13.1 | "Should oracle prices be signed and included in receipts as evidence?" |
| 5 (DON vs Direct Verification) | arc-link sec. 13.4; arc-link sec. 4.4 | "Is the DON trust assumption acceptable for all delegation depths?" and "Chainlink Functions-based verification is optimistic, not trustless" |
| 6 (Root Publication Ownership) | arc-settle sec. 14.1, item 1; arc-anchor sec. 13.4 | "Who publishes Merkle roots?" and "Chainlink Automation as alternative root publisher" |
