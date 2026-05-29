# Chio-Settle Protocol Decisions

Status: Decision document
Date: 2026-03-30
Authors: Engineering
Prerequisite: CHIO_SETTLE_RESEARCH.md, CHIO_ANCHOR_RESEARCH.md, CHIO_LINK_RESEARCH.md

> Realization status (2026-04-02): these decisions are now realized by the
> shipped `arc-settle` runtime and official contract package. The authoritative
> runtime boundary is [CHIO_SETTLE_PROFILE.md](../standards/CHIO_SETTLE_PROFILE.md).
> Several research names were superseded in implementation: `ArcReceiptVerifier`
> converged into `IArcRootRegistry`, and `ArcSettleRegistry` converged into
> `IArcIdentityRegistry`.

---

## 1. Context

The arc-settle research document is thorough and technically sound, but it
deliberately left seven protocol-level questions open. Those open questions
block arc-settle from becoming an engineering problem. This document makes
concrete, binding decisions on each one.

**What this decides:** identity binding, root publication ownership, settlement
evidence format, dispute policy, bond lifecycle triggers, settlement failure
recovery, and multi-chain consistency.

**What this unblocks:** implementation of the `arc-settle` crate, deployment of
the `ArcEscrow`, `ArcBondVault`, and `ArcReceiptVerifier` contracts, and the
operational runbook for kernel operators who want on-chain settlement.

**Notation:** Chio types referenced here (e.g., `ArcReceipt`, `CreditBondTerms`,
`CapitalExecutionRailKind`, `SettlementStatus`, `MonetaryAmount`) refer to the
structs in `crates/arc-core/src/`. Solidity types refer to the interfaces
proposed in CHIO_SETTLE_RESEARCH.md section 7.

---

## 2. Decision A: Identity Binding

### Decision

Chio uses Ed25519 keys (`did:arc` identities). EVM settlement uses secp256k1
addresses. The binding between them is a **signed attestation certificate**
stored in an **on-chain registry**.

The binding flow:

1. The Chio entity (kernel operator, agent, or tool server) generates a binding
   certificate: the Ed25519 private key signs a canonical JSON message of the
   form:

   ```json
   {
     "schema": "arc.identity-binding.v1",
     "arc_public_key": "<hex-encoded Ed25519 public key>",
     "chain_id": "<CAIP-2 identifier, e.g. eip155:8453>",
     "settlement_address": "<EVM address, 0x-prefixed checksummed>",
     "issued_at": 1743292800,
     "expires_at": 1774828800,
     "nonce": "<random 16-byte hex>"
   }
   ```

2. The entity submits `(arc_entity_id, settlement_address, binding_proof)` to
   `ArcSettleRegistry.registerEntity()`. The `binding_proof` is the canonical
   JSON bytes plus the Ed25519 signature.

3. The registry stores the mapping. On-chain, the contract trusts `msg.sender`
   as the settlement address and stores the binding proof as an event for
   off-chain auditors. The contract does not verify Ed25519 on-chain (too
   expensive); verification is performed off-chain by any party that reads the
   `EntityRegistered` event.

4. For Solana bindings, the same certificate format is used with
   `"chain_id": "solana:mainnet"` and a base58-encoded settlement address. The
   Solana program verifies the Ed25519 signature natively via the
   `Ed25519SigVerify111111111111111111111111111` precompile.

**Struct definition (Rust side):**

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityBindingCertificate {
    pub schema: String,                   // "arc.identity-binding.v1"
    pub arc_public_key: String,           // hex Ed25519 pubkey
    pub chain_id: String,                 // CAIP-2 chain identifier
    pub settlement_address: String,       // 0x-prefixed or base58
    pub issued_at: u64,                   // unix seconds
    pub expires_at: u64,                  // unix seconds
    pub nonce: String,                    // 16-byte random hex
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedIdentityBinding {
    pub certificate: IdentityBindingCertificate,
    pub signature: Signature,             // Ed25519 signature over canonical JSON of certificate
}
```

**Trust model:** The binding is as strong as the Ed25519 private key's secrecy.
If an attacker controls the Ed25519 key, they can bind it to any address. This
is acceptable because Ed25519 key compromise already defeats all of Chio's trust
guarantees. The binding certificate has a TTL (`expires_at`) and must be
refreshed before expiry. Rotation requires registering a new binding and
revoking the old one (the registry supports overwriting by `arc_entity_id`).

### Rationale

- On-chain Ed25519 verification on EVM is too expensive (500k+ gas). Off-chain
  verification of the binding certificate is sufficient because the on-chain
  contract already authenticates via `msg.sender` (secp256k1/ECDSA).
- A pure off-chain binding (no registry) would require every counterparty to
  independently verify the certificate. The on-chain registry provides a single
  lookup point while the emitted event provides the full certificate for
  independent verification.
- Solana gets native Ed25519 verification of the binding for free.

### Alternatives Considered

1. **On-chain Ed25519 verification of the binding at registration time**: ~500k
   gas on EVM. Not justified for a one-time registration when off-chain
   verification achieves the same security property.
2. **DID document extension**: Publish the binding in the `did:arc` DID document
   as a `service` endpoint. Considered too fragile -- DID resolution is not
   on-chain and cannot be used by the escrow contract.
3. **No registry, purely off-chain binding**: Works but requires every
   counterparty to verify the binding independently and trust their own
   verification. The registry amortizes this trust.

### Implications

- `ArcSettleRegistry.sol` must emit an `EntityRegistered(bytes32 arcEntityId, address settlementAddress, bytes bindingProof)` event.
- The binding certificate has a maximum TTL of 365 days. Operators must
  re-register before expiry.
- Key rotation for the Ed25519 key requires a new binding certificate. The old
  binding remains valid until its `expires_at` unless explicitly revoked.
- The `arc_entity_id` is `keccak256(arc_public_key)` -- a 32-byte deterministic
  identifier derived from the Ed25519 public key.

---

## 3. Decision B: Root Publication Ownership

### Decision

**The kernel operator publishes Merkle roots.** There is a single authorized
publisher per operator identity. Delegation to a hot wallet is supported via
the registry.

Specifically:

1. The kernel operator registers their Ethereum address as an authorized
   operator via `ArcSettleRegistry.registerOperator(operatorAddress, operatorCertificate)`. The `operatorCertificate` is a `SignedIdentityBinding`
   proving the operator's Ed25519 key controls the given Ethereum address.

2. The `ArcReceiptVerifier` contract's `publishRoot()` function checks
   `ArcSettleRegistry.isAuthorizedOperator(msg.sender)` before accepting a root.

3. **Delegation to a hot key:** The operator may designate a separate hot wallet
   for root publication by calling
   `ArcSettleRegistry.delegatePublisher(hotAddress, ttlSeconds)`. The hot key
   can publish roots on behalf of the operator but cannot modify the operator's
   registration. Delegation expires after `ttlSeconds` (maximum: 604800 seconds
   / 7 days) and must be renewed.

4. **Liveness guarantee:** Root publication frequency is configured per
   operator. The recommended default is every 60 seconds or every 100 receipts,
   whichever comes first (matching `KernelConfig.checkpoint_batch_size`). The
   contract does not enforce liveness -- it only enforces that
   `checkpoint_seq` is monotonically increasing per operator.

5. **Unauthorized publication prevention:** The `publishRoot()` function
   reverts with `UnauthorizedOperator` if `msg.sender` is neither a registered
   operator nor a delegated publisher for a registered operator.

**On-chain access control:**

```solidity
function publishRoot(
    bytes32 root,
    uint256 batchTimestamp,
    uint256 receiptCount,
    uint64  checkpointSeq,
    uint64  batchStartSeq,
    uint64  batchEndSeq
) external {
    require(
        registry.isAuthorizedOperator(msg.sender) ||
        registry.isDelegatedPublisher(msg.sender),
        "UnauthorizedOperator"
    );
    require(checkpointSeq > latestSeq[_resolveOperator(msg.sender)], "SeqMustIncrease");
    // ... store root and emit event
}
```

### Rationale

- The kernel operator is the natural publisher because they already run the
  checkpoint pipeline and hold the receipt log.
- A decentralized publisher set (threshold agreement among multiple parties)
  adds complexity without clear benefit in v1 -- the kernel operator is already
  a trust dependency for receipt signing.
- Hot key delegation reduces the blast radius of the operator's cold key being
  online for routine operations.

### Alternatives Considered

1. **Decentralized root publisher set (M-of-N threshold):** Stronger liveness
   and censorship resistance, but requires coordination infrastructure that
   does not exist yet. Deferred to v2.
2. **Chainlink Automation as publisher:** The Automation upkeep calls a
   Chainlink Function that fetches the latest checkpoint and publishes the root.
   This removes the operator from the publishing loop but introduces a DON
   trust dependency. Considered a v2 option, not v1.
3. **Permissionless publication (anyone can publish if they provide a valid
   checkpoint signature):** Requires on-chain Ed25519 verification of the
   checkpoint signature, which is too expensive on EVM. Viable on Solana.

### Implications

- The operator must run a background service that polls for new checkpoints and
  submits `publishRoot()` transactions. This is the `arc-anchor` daemon
  described in CHIO_ANCHOR_RESEARCH.md section 9.2.
- Gas costs for root publication are the operator's responsibility. At ~52k gas
  per root on Base, this is ~$0.003 per publication or ~$130/year at one
  publication per minute.
- If the operator goes offline, no new roots are published, and no new Merkle
  proof-based settlements can occur. Escrows with deadlines will eventually
  trigger refunds via the timeout path. This is acceptable for v1.
- On Solana, permissionless publication becomes viable because the settlement
  program can verify the checkpoint's Ed25519 signature natively. This should
  be implemented in the Solana program from the start.

---

## 4. Decision C: Settlement Evidence Format

### Decision

Settlement evidence is the data bundle submitted to an escrow contract to
prove that a tool call occurred and the budget was consumed. Two formats exist,
corresponding to the two settlement paths.

### Path 1: Dual-Signature Evidence (individual settlement)

Used for high-value settlements where latency matters and the settlement
happens before the next root publication.

**Solidity struct:**

```solidity
struct DualSignEvidence {
    // Receipt identity
    bytes32 receiptId;         // keccak256 of the ARC receipt ID string
    bytes32 capabilityId;      // keccak256 of the capability token ID
    bytes32 escrowId;          // escrow this evidence is claiming against

    // Financial data
    uint256 settledAmount;     // amount to release, in token minor units (USDC: 6 decimals)
    address token;             // ERC-20 token address (USDC)

    // Receipt digest
    bytes32 receiptHash;       // keccak256(canonical_json(ArcReceiptBody))

    // secp256k1 settlement signature
    uint8 v;
    bytes32 r;
    bytes32 s;
    // ecrecover(receiptHash, v, r, s) must equal the operator's registered settlement address
}
```

**Rust struct (off-chain construction):**

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DualSignSettlementEvidence {
    pub receipt_id: String,
    pub capability_id: String,
    pub escrow_id: [u8; 32],
    pub settled_amount: u64,           // in token minor units
    pub token_address: String,         // 0x-prefixed
    pub receipt_hash: [u8; 32],        // keccak256(canonical_json(receipt_body))
    pub settlement_signature: Secp256k1Signature,
}
```

The kernel produces this evidence by:
1. Serializing the `ArcReceiptBody` to canonical JSON.
2. Computing `keccak256` of the canonical JSON bytes (not SHA-256 -- keccak256
   is used because `ecrecover` on EVM operates on keccak256 digests).
3. Signing the keccak256 digest with the operator's secp256k1 settlement key.
4. Packaging the result into `DualSignSettlementEvidence`.

The escrow contract verifies by:
1. `ecrecover(receiptHash, v, r, s)` to recover the signer address.
2. Checking that the recovered address matches the `operatorKey` stored in the
   `EscrowTerms`.
3. Checking that `settledAmount <= escrow.amount`.
4. Checking that the escrow has not already been released.
5. Checking that `block.timestamp < escrow.deadline`.

### Path 2: Merkle Proof Evidence (batch settlement)

Used for micro-transactions settled after a root is published.

**Solidity struct:**

```solidity
struct MerkleProofEvidence {
    // Receipt identity
    bytes32 receiptId;
    bytes32 capabilityId;
    bytes32 escrowId;

    // Financial data
    uint256 settledAmount;
    address token;

    // Merkle proof components
    bytes32 root;              // must match a published root for the operator
    bytes32 leafHash;          // SHA-256(0x00 || canonical_json(ArcReceiptBody))
    bytes32[] proof;           // Merkle inclusion path (RFC 6962-compatible)

    // Leaf data for verification
    bytes receiptData;         // ABI-encoded receipt summary (see below)
}
```

The `receiptData` field contains an ABI-encoded subset of the receipt needed
for the escrow to validate the claim:

```solidity
struct ReceiptSummary {
    bytes32 receiptId;
    bytes32 capabilityId;
    uint256 costCharged;       // in currency minor units
    string  currency;          // "USD"
    uint8   decision;          // 0 = Allow, 1 = Deny, 2 = Cancelled, 3 = Incomplete
    uint8   settlementStatus;  // 0 = NotApplicable, 1 = Pending, 2 = Settled, 3 = Failed
}
```

The escrow contract verifies by:
1. `MerkleProof.verify(proof, root, leafHash)` using OpenZeppelin's library.
2. Checking that `root` is a published root for the escrow's operator
   (via `ArcReceiptVerifier`).
3. Decoding `receiptData` and checking that `decision == Allow` and
   `settlementStatus == Pending || settlementStatus == Settled`.
4. Checking `settledAmount <= escrow.amount` and `settledAmount <= costCharged`
   (converted to token minor units).
5. Checking that the escrow has not already been released.

**Leaf hash computation:** The leaf hash uses Chio's existing RFC 6962
convention: `SHA-256(0x00 || leaf_bytes)` where `leaf_bytes` is the canonical
JSON serialization of `ArcReceiptBody`. On-chain, the contract recomputes
`keccak256(receiptData)` and checks it matches `receiptId` from the decoded
data. The actual Merkle tree uses SHA-256 (matching Chio's tree), so the
`leafHash` field is a SHA-256 digest. The contract trusts the Merkle proof
against the published SHA-256 root.

**Critical note on hash function:** Chio's Merkle tree uses SHA-256, but EVM
natively provides `keccak256`. The `ArcReceiptVerifier` contract must use an
inline SHA-256 precompile (address `0x02`, 60 gas per 32-byte word) for proof
verification. This is available on all EVM chains. OpenZeppelin's
`MerkleProof.verify` uses `keccak256` by default; a custom `verifySha256`
implementation is needed. Gas impact: ~2000 additional gas per proof step
compared to keccak256, for a total of ~55k gas for a 20-level tree.

### Rationale

- Two paths are necessary because the gas/latency tradeoff differs by orders
  of magnitude between high-value individual settlements and micro-transactions.
- The `DualSignEvidence` path requires no root publication latency and costs
  ~60k gas (dominated by `ecrecover` at 3k gas plus storage writes).
- The `MerkleProofEvidence` path amortizes root publication cost across the
  batch but adds publication latency (up to 60 seconds at default config).
- The `ReceiptSummary` struct is intentionally minimal -- only the fields
  the escrow contract needs for verification. Full receipt data is available
  off-chain via the receipt log.

### Alternatives Considered

1. **Single evidence format (Merkle-only):** Simpler contract but forces all
   settlements to wait for root publication. Unacceptable for time-sensitive
   high-value settlements.
2. **Full receipt on-chain:** Submitting the entire `ArcReceiptBody` as calldata
   wastes gas on fields the contract does not need (tool_server, tool_name,
   evidence array, etc.).
3. **ZK proof of receipt validity:** ~300k gas for Groth16 verification. More
   expensive than dual-sign (~60k) and Merkle proof (~55k). Deferred to v2
   for batch verification of large receipt sets.

### Implications

- The kernel must compute both SHA-256 (for the Merkle tree) and keccak256
  (for the dual-sign path) over receipt bodies. These are independent hashes
  with different purposes.
- The `ArcReceiptVerifier` contract must implement SHA-256-based Merkle proof
  verification, not keccak256-based.
- arc-settle must track which escrows use which evidence path and route claims
  accordingly.

---

## 5. Decision D: Dispute Policy

### Decision

Chio settlement uses a **two-tier optimistic dispute model** with escalation.

### Tier 1: Optimistic Window (on-chain)

Every settlement has a mandatory **dispute window** after evidence submission
and before funds become withdrawable. During this window, a designated
disputer can challenge the settlement.

**Time windows:**

| Settlement value | Dispute window | Who can dispute |
|-----------------|---------------|-----------------|
| < $10           | 0 seconds (immediate finality) | No dispute window |
| $10 -- $1,000   | 3600 seconds (1 hour) | Escrow depositor or registered operator |
| $1,000 -- $10,000 | 14400 seconds (4 hours) | Escrow depositor or registered operator |
| > $10,000       | 86400 seconds (24 hours) | Escrow depositor or registered operator |

**Contract flow:**

```solidity
function releaseWithSignature(...) external {
    // ... verify evidence ...
    escrow.releaseTimestamp = block.timestamp + disputeWindow(escrow.amount);
    escrow.state = EscrowState.PendingRelease;
    emit ReleasePending(escrowId, escrow.releaseTimestamp);
}

function finalizeRelease(bytes32 escrowId) external {
    require(escrow.state == EscrowState.PendingRelease, "NotPending");
    require(block.timestamp >= escrow.releaseTimestamp, "DisputeWindowOpen");
    // Transfer funds to beneficiary
    IERC20(escrow.token).transfer(escrow.beneficiary, escrow.settledAmount);
    escrow.state = EscrowState.Released;
}

function disputeRelease(bytes32 escrowId, bytes calldata disputeEvidence) external {
    require(escrow.state == EscrowState.PendingRelease, "NotPending");
    require(block.timestamp < escrow.releaseTimestamp, "WindowClosed");
    require(
        msg.sender == escrow.depositor ||
        registry.isAuthorizedOperator(msg.sender),
        "UnauthorizedDisputer"
    );
    escrow.state = EscrowState.Disputed;
    escrow.disputeEvidence = disputeEvidence;
    emit Disputed(escrowId, msg.sender);
}
```

The `disputeEvidence` is an ABI-encoded blob containing:

```solidity
struct DisputeEvidence {
    uint8   reason;            // 0 = InvalidReceipt, 1 = DoubleClaim, 2 = AmountMismatch,
                               // 3 = CapabilityRevoked, 4 = ServiceNotDelivered
    bytes32 conflictingReceiptId;  // optional: receipt ID that contradicts the claim
    bytes   proofData;         // reason-specific proof (e.g., revocation proof, duplicate receipt)
}
```

### Tier 2: Off-chain Arbitration

Once an escrow enters `Disputed` state, the dispute is resolved off-chain by
the **operator's arbitration authority**. This is initially the kernel operator
themselves (for operator-mediated disputes) or a designated arbitrator specified
in the escrow terms.

**Arbitration flow:**

1. The dispute is logged on-chain (`Disputed` event with evidence).
2. The arbitration authority has **604800 seconds (7 days)** to submit a
   resolution.
3. Resolution is submitted via `resolveDispute(escrowId, resolution)` where
   `resolution` is:
   - `ReleaseTobeneficiary` -- original release proceeds
   - `RefundToDepositor` -- full refund
   - `SplitSettlement(uint256 beneficiaryShare, uint256 depositorShare)` --
     partial resolution
4. Only the registered arbitrator address can call `resolveDispute()`.
5. If no resolution is submitted within 7 days, the escrow auto-refunds to the
   depositor. This fail-closed default protects depositors from unresponsive
   arbitrators.

**Arbitrator designation:**

```solidity
struct EscrowTerms {
    // ... existing fields ...
    address arbitrator;       // address authorized to resolve disputes
    uint256 disputeWindow;    // seconds (overrides default if > minimum for tier)
    uint256 arbitrationDeadline; // seconds after dispute for resolution (default: 604800)
}
```

If `arbitrator` is `address(0)`, the operator's registered address is used as
the default arbitrator.

### Rationale

The two-tier model is inspired by UMA's optimistic oracle pattern: optimistic
acceptance with a challenge period, escalating to human judgment only when
disputed. This minimizes on-chain cost (most settlements will never be
disputed) while providing a credible dispute path.

- **UMA parallel:** UMA's asserter posts a bond and the assertion is accepted
  after a liveness period unless disputed. Chio's escrow deposit serves as the
  implicit bond. UMA escalates to DVM (token holder vote); Chio escalates to a
  designated arbitrator.
- **Kleros parallel:** Kleros uses crowdsourced jurors for dispute resolution.
  Chio defers to a designated arbitrator for v1 simplicity, but the
  `arbitrator` address could point to a Kleros arbitration contract
  (ERC-792-compatible) in v2.
- **Optimistic Rollup parallel:** OP Stack uses a 7-day challenge period for
  state root disputes. Chio's 7-day arbitration deadline mirrors this.

### Alternatives Considered

1. **No dispute mechanism (immediate finality):** Simpler but provides no
   recourse for fraud or errors. Unacceptable for settlements above trivial
   amounts.
2. **Fully decentralized arbitration (Kleros/Aragon Court) from v1:** Adds
   external protocol dependency, juror staking economics, and UX complexity.
   Premature for a system that does not yet have production settlement volume.
3. **UMA optimistic oracle as dispute layer:** The UMA DVM resolves disputes
   via token holder vote within 48-96 hours. Viable but couples Chio to UMA
   token economics. Better as a v2 integration option.
4. **Stake-based disputing (disputer must post a bond):** Considered for
   anti-griefing but deferred. In v1, only the depositor and operator can
   dispute, and the 7-day auto-refund limits the attack surface.

### Implications

- The escrow contract has five states: `Created`, `PendingRelease`, `Released`,
  `Disputed`, `Refunded`. The state machine is strictly ordered and
  non-reversible except via dispute resolution.
- Settlements under $10 have no dispute window (immediate finality). This is
  a deliberate tradeoff: the cost of disputing micro-payments exceeds the
  value at risk.
- The arbitration authority is a single address in v1. This is a
  centralization point. Upgrading to a multisig or Kleros contract is a
  contract-level change, not a protocol change.
- arc-settle must monitor for `Disputed` events and alert the operator.

---

## 6. Decision E: Bond Lifecycle On-chain

### Decision

`CreditBond` collateral locked in `ArcBondVault` follows a state machine
mirroring the off-chain `CreditBondLifecycleState` enum: `Active`, `Superseded`,
`Released`, `Impaired`, `Expired`.

### Slash Triggers

Slashing occurs when the off-chain credit loss lifecycle reaches a
`ReserveSlash` event (see `CreditLossLifecycleEventKind::ReserveSlash` in
`credit.rs`). The slash evidence is:

```solidity
struct SlashEvidence {
    bytes32 bondId;              // ARC CreditBond ID (keccak256)
    bytes32 lossEventId;         // CreditLossLifecycleArtifact.event_id (keccak256)
    uint256 slashAmount;         // amount to slash in token minor units
    address[] beneficiaries;     // addresses receiving slashed funds
    uint256[] shares;            // per-beneficiary amounts (must sum to slashAmount)
    bytes32 receiptHash;         // keccak256 of the signed loss lifecycle artifact JSON
    uint8 v; bytes32 r; bytes32 s; // secp256k1 signature from operator
}
```

**Who submits slash evidence:** Only the registered operator (or their
delegated publisher) can submit slash evidence. This prevents griefing -- a
random third party cannot slash bonds.

**Slash flow:**

1. The off-chain kernel generates a `CreditLossLifecycleArtifact` with
   `event_kind: ReserveSlash` and signs it with Ed25519.
2. arc-settle produces a secp256k1 dual-signature over the artifact's
   keccak256 hash.
3. arc-settle calls `ArcBondVault.impairBond(vaultId, slashEvidence)`.
4. The contract verifies `ecrecover` against the operator's registered
   address.
5. The contract transfers `slashAmount` from the bond vault to the
   specified beneficiaries.
6. The bond's on-chain state transitions to `Impaired`.

### Release Triggers

Release occurs on normal completion:

1. The operator calls `ArcBondVault.releaseBond(vaultId, releaseEvidence)`
   with a dual-signed `CreditLossLifecycleArtifact` of kind `ReserveRelease`.
2. The contract returns collateral to the bond principal's registered address.
3. The bond's on-chain state transitions to `Released`.

### Expiry

If the bond's `expiresAt` timestamp passes with no impairment or explicit
release, anyone can call `ArcBondVault.expireRelease(vaultId)` to return
collateral to the principal. This prevents permanent fund lock-up.

### Anti-griefing

1. **Only operators can slash:** The `impairBond` function checks
   `registry.isAuthorizedOperator(msg.sender)`.
2. **Slash requires dual-signature:** The operator must produce a valid
   secp256k1 signature over the loss event artifact, proving the off-chain
   kernel authorized the slash.
3. **Appeal window:** Before on-chain slash execution, the
   `CreditLossLifecycleArtifact` has an optional `appeal_window_ends_at`
   field. The `ArcBondVault` contract enforces:
   ```solidity
   require(
       block.timestamp >= appealWindowEndsAt,
       "AppealWindowOpen"
   );
   ```
   The appeal window default is **259200 seconds (3 days)**. During this window,
   the bond principal can submit an appeal to the operator's off-chain
   arbitration authority (same authority used for escrow disputes). If the
   appeal succeeds, the operator simply does not submit the slash transaction.
4. **Maximum slash cap:** The contract enforces `slashAmount <= bond.collateralAmount`. A single slash can take at most the full collateral.
5. **No partial slash accumulation:** Each `impairBond` call is final for that
   bond. If multiple loss events occur, the operator must issue a superseding
   bond (`CreditBondLifecycleState::Superseded`) with adjusted collateral.

### Rationale

- The operator is the only party with the off-chain context to determine that
  a loss event justifies slashing. On-chain automation of slash decisions
  requires the loss lifecycle logic to be replicated in Solidity, which is
  impractical given the complexity of `CreditLossLifecycleReport`.
- The appeal window provides a safety net against operator error without
  requiring on-chain dispute infrastructure (the appeal is resolved off-chain;
  the on-chain contract simply delays execution).

### Alternatives Considered

1. **Automated on-chain slashing via Chainlink Functions:** Functions could
   evaluate loss criteria and trigger slashes. But this introduces a DON trust
   dependency for a high-stakes financial operation. Rejected for v1.
2. **Slash requires depositor counter-signature:** Adds depositor approval to
   the slash flow. Rejected because the depositor (the bonded agent) has an
   incentive to block legitimate slashes.
3. **Slash via governance multisig:** Adds decentralization but also latency
   and governance overhead. Deferred to v2.

### Implications

- The `ArcBondVault` must store `appealWindowEndsAt` per bond.
- arc-settle must compute the appeal window end from the
  `CreditLossLifecycleArtifact.appeal_window_ends_at` field and delay the
  on-chain transaction accordingly.
- Bond collateral is denominated in USDC (matching `CreditBondTerms.collateral_amount.currency`). The conversion from Chio minor units (cents)
  to USDC minor units (micro-dollars) uses the `CurrencyDecimals` config:
  `on_chain_amount = arc_units * 10_000` for USD (cents to 6-decimal USDC).

---

## 7. Decision F: Settlement Failure Recovery

### Decision

Settlement failures are handled at three levels: transaction-level, batch-level,
and chain-level.

### Transaction-Level Failure

When a single on-chain transaction reverts:

1. arc-settle detects the revert via Alloy's transaction receipt (`status == 0`).
2. arc-settle parses the revert reason from `returndata`.
3. The off-chain `SettlementStatus` remains `Pending` (not updated to `Failed`
   until retries are exhausted).
4. arc-settle retries with exponential backoff: delays of 2, 4, 8, 16, 32
   seconds (5 retries maximum). Retry resubmits with +10% gas price on each
   attempt.
5. If all retries fail, `SettlementStatus` transitions to `Failed` and an
   `UnderwritingReasonCode::FailedSettlementExposure` signal is emitted.
6. The operator is alerted. Manual intervention may be required.

**Transient vs. permanent failures:**

| Failure type | Retryable | Action |
|-------------|-----------|--------|
| Insufficient gas | Yes | Resubmit with higher gas |
| Nonce collision | Yes | Reset nonce from chain state |
| Escrow expired | No | Update status to `Failed`, trigger refund path |
| USDC blacklisted | No | Update status to `Failed`, alert operator |
| USDC paused | Yes (delayed) | Queue for retry, poll `paused()` every 60 seconds |
| Contract revert (logic) | No | Update status to `Failed`, log revert reason |

### Batch-Level Failure

When processing a batch of Merkle proof releases:

1. Each claim in the batch is an independent transaction (or, if using
   multicall, an independent sub-call).
2. **Batch failure is not atomic.** Successful claims are recorded even if
   other claims in the batch fail.
3. arc-settle tracks per-receipt settlement status. Each receipt has its own
   `SettlementStatus` independent of the batch.
4. Failed claims within a batch are retried individually with the same
   exponential backoff policy.
5. If a batch is submitted as a multicall and the multicall itself reverts
   (e.g., gas limit exceeded), arc-settle falls back to individual claim
   submission.

### Chain-Level Failure (Reorg)

On optimistic rollups (Base, Arbitrum), a sequencer reorg can revert recently
confirmed transactions. arc-settle uses a **tiered confirmation policy**:

| Settlement value | Confirmation requirement | Approximate time |
|-----------------|------------------------|------------------|
| < $10           | 1 L2 block | ~2 seconds |
| $10 -- $1,000   | Sequencer confirmation (soft finality) | ~2 seconds |
| $1,000 -- $10,000 | L1 data posting | ~13 minutes |
| > $10,000       | L1 finality (Ethereum finalization) | ~13 minutes |

**What happens when a confirmed settlement is reorged:**

1. arc-settle maintains a `pending_confirmations` table that tracks settlement
   transactions awaiting the required confirmation depth.
2. If a transaction that was counted as confirmed is later absent from the
   canonical chain (detected via block hash mismatch on re-query):
   a. `SettlementStatus` reverts from `Settled` back to `Pending`.
   b. The transaction is resubmitted.
   c. The exposure ledger's `settled_units` is decremented and `pending_units`
      is incremented.
3. The off-chain receipt's settlement metadata is updated to reflect the
   rollback. A new `ExposureLedgerEvidenceKind::SettlementReconciliation`
   evidence reference is emitted.

**Off-chain state does NOT automatically roll back.** The kernel's receipt
(the Ed25519-signed `ArcReceipt`) is immutable -- it records what happened at
evaluation time. Only the settlement metadata (which is stored separately in
the receipt store, not in the signed receipt body) is updated.

### Rationale

- Non-atomic batch processing is essential: a single failing claim should not
  block settlement of other valid claims.
- Tiered confirmation matches the economic risk: the cost of a reorg-based
  double-spend on a $5 settlement does not justify waiting 13 minutes.
- Off-chain receipt immutability is a protocol invariant. Settlement status is
  mutable metadata, not part of the signed receipt.

### Alternatives Considered

1. **Atomic batch settlement (all-or-nothing):** Simpler accounting but means
   one bad claim blocks the entire batch. Rejected.
2. **Always wait for L1 finality:** Too slow for micro-payments. A $0.50
   settlement should not require a 13-minute wait.
3. **Optimistic off-chain settlement (assume success, reconcile later):**
   Faster UX but creates accounting discrepancies. Rejected in favor of
   explicit confirmation tracking.

### Implications

- arc-settle needs a `pending_confirmations` SQLite table tracking
  `(tx_hash, settlement_value, required_confirmations, current_confirmations, block_hash)`.
- The reconciliation service must poll for block hash stability on the required
  confirmation depth before marking a settlement as final.
- The exposure ledger's `settled_units` and `pending_units` may fluctuate
  during reorg events. Downstream consumers (underwriting, credit scoring)
  must tolerate this.

---

## 8. Decision G: Multi-chain Consistency

### Decision

**Base L2 is the source of truth for settlement state. Bitcoin and Solana
anchors are supplementary attestation layers, not settlement authorities.**

### Consistency Model

Chio operates on three chains with different roles:

| Chain | Role | Data stored | Authority level |
|-------|------|-------------|-----------------|
| Base (EVM L2) | Primary settlement | Escrow state, bond state, Merkle roots, identity bindings | Authoritative for fund custody and settlement state |
| Solana | Secondary settlement + anchoring | Ed25519-native escrow, Merkle roots via Memo | Authoritative for Solana-settled transactions only |
| Bitcoin | Anchoring only | Merkle root timestamps via OTS | Non-authoritative; provides timestamp assurance only |

### Cross-chain Merkle Root Divergence

The same `KernelCheckpoint` Merkle root may be published to Base, Solana, and
Bitcoin. These publications are independent events. They may occur at different
times and may cover different checkpoint ranges (e.g., Bitcoin anchoring
aggregates multiple checkpoints).

**Invariants:**

1. A Merkle root published on Base and the same root published on Solana are
   equivalent in content. They commit the same receipt set.
2. A Bitcoin OTS anchor commits a super-root (hash of multiple checkpoint
   roots). A verifier must trace from the OTS proof to the super-root, then
   from the super-root to the individual checkpoint root, then from the
   checkpoint root to the receipt leaf.
3. Settlement claims reference a specific chain's root. An escrow on Base
   only accepts roots published on Base. A Solana program only accepts roots
   published on Solana. There is no cross-chain root reference.

### Source of Truth for Disputes

If a settlement is disputed, the on-chain state of the settlement chain
(Base or Solana) is authoritative. Bitcoin anchors provide timestamp evidence
but do not participate in dispute resolution.

**Example:** A settlement happens on Base. The receipts are also anchored to
Bitcoin via OTS. The depositor disputes the settlement. The arbitrator
examines the Base on-chain evidence (escrow state, published root, Merkle
proof). The Bitcoin anchor proves the receipt existed at a certain time but
does not override the Base settlement state.

### Multi-chain Settlement Routing

When a `CapitalExecutionInstruction` specifies `rail.kind: OnChain`, the
`rail.jurisdiction` field (CAIP-2 identifier) determines the settlement chain:

| `jurisdiction` value | Settlement chain | Evidence verification |
|---------------------|------------------|----------------------|
| `eip155:8453` | Base | Dual-sign (ecrecover) or Merkle proof (SHA-256) |
| `eip155:42161` | Arbitrum | Dual-sign (ecrecover) or Merkle proof (SHA-256) |
| `solana:mainnet` | Solana | Native Ed25519 receipt verification |

The operator publishes roots to all chains where they have active escrows. An
operator who only uses Base does not need to publish to Solana, and vice versa.

### Consistency Between Off-chain State and On-chain State

The off-chain receipt store (SQLite) is the primary record of what happened.
On-chain state is a settlement artifact derived from off-chain receipts.

**Reconciliation rule:** arc-settle's reconciliation service polls on-chain
events and updates the exposure ledger. If on-chain state diverges from
off-chain state (e.g., a transaction the off-chain system thought succeeded
actually reverted), the **on-chain state wins for financial settlement** and
the off-chain metadata is corrected.

This means:
- If the off-chain ledger says `settled` but the on-chain escrow is still
  `PendingRelease`, the off-chain ledger is corrected to `pending`.
- If the on-chain escrow shows `Released` but the off-chain ledger says
  `pending`, the off-chain ledger is corrected to `settled`.
- The signed `ArcReceipt` itself is never modified. Only the mutable
  settlement metadata layer is updated.

### Rationale

- A single source-of-truth chain simplifies reasoning about settlement finality.
  Multi-chain atomic settlement (e.g., funds on Base, proof on Solana, timestamp
  on Bitcoin, all required to agree) would create liveness dependencies across
  three independent chains.
- Per-chain independence means a Bitcoin mempool delay does not block a Base
  settlement, and a Solana outage does not prevent Base escrow operations.
- The reconciliation rule ("on-chain wins") is consistent with how traditional
  payment systems work: the bank's ledger is authoritative, and internal
  records are corrected to match.

### Alternatives Considered

1. **Require all three chains to anchor the same root before settlement is
   final:** Strongest consistency but creates a liveness dependency on the
   slowest chain (Bitcoin at ~60 minutes for 6 confirmations). Rejected.
2. **Cross-chain Merkle proof relay via CCIP:** Use Chainlink CCIP to
   transport Merkle proofs from one chain to another. Technically feasible but
   adds 10-20 minutes of latency per relay and $0.09-0.50 per message.
   Deferred to v2 for cross-chain settlement scenarios.
3. **Single-chain-only (Base only, no Solana or Bitcoin):** Simpler but
   sacrifices Solana's native Ed25519 advantage and Bitcoin's timestamp
   assurance. Rejected.

### Implications

- Each settlement chain has its own `ArcReceiptVerifier` contract (or Solana
  program) with independent root publication.
- The `anchor_records` table in SQLite must track `(checkpoint_seq, chain, tx_hash, status)` per chain independently.
- Operators who settle on multiple chains must run publication services for
  each chain and fund gas/fees on each chain independently.
- Cross-chain USDC transfer (e.g., agent on Base pays tool server whose wallet
  is on Arbitrum) is out of scope for v1. Both parties must be on the same
  chain for a given escrow. Circle CCTP can be integrated in v2.

---

## 9. Summary: Settlement Flow Diagram

End-to-end flow from tool call to settled funds.

### Flow A: High-Value Individual Settlement (Dual-Sign, Base)

```
Time
 |
 |  T+0s     Agent presents CapabilityToken to Kernel
 |            Kernel validates, dispatches tool call
 |
 |  T+1s     Tool server executes, returns result
 |            Kernel signs ArcReceipt (Ed25519)
 |            Kernel produces DualSignSettlementEvidence (secp256k1)
 |
 |  T+2s     arc-settle calls ArcEscrow.releaseWithSignature()
 |            Contract verifies ecrecover, sets state = PendingRelease
 |            Dispute window starts (1h for $10-$1k, 4h for $1k-$10k)
 |
 |  T+3602s  (assuming $500 settlement, 1h dispute window, no dispute)
 |            Anyone calls ArcEscrow.finalizeRelease()
 |            USDC transferred to tool server's address
 |            SettlementStatus updated to Settled
 |
 |  T+3603s  arc-settle updates exposure ledger
 |            Reconciliation complete
```

### Flow B: Micro-Transaction Batch Settlement (Merkle Proof, Base)

```
Time
 |
 |  T+0s     Multiple tool calls execute over 60 seconds
 |            Kernel signs receipts, accumulates into Merkle tree
 |
 |  T+60s    Kernel builds checkpoint (100 receipts)
 |            Operator publishes root: ArcReceiptVerifier.publishRoot()
 |
 |  T+61s    arc-settle constructs MerkleProofEvidence for each claim
 |            arc-settle calls ArcEscrow.releaseWithProof() per claim
 |            (or batched via multicall)
 |            Immediate finality (no dispute window for <$10)
 |
 |  T+63s    USDC transferred to tool servers
 |            SettlementStatus updated to Settled for each receipt
 |            Exposure ledger reconciled
```

### Flow C: Bond Slash (Base)

```
Time
 |
 |  T+0      Off-chain: delinquency detected, CreditLossLifecycleArtifact
 |            created with event_kind = ReserveSlash
 |            appeal_window_ends_at set to T + 259200s (3 days)
 |
 |  T+259200s Appeal window expires (no appeal submitted)
 |
 |  T+259201s arc-settle calls ArcBondVault.impairBond()
 |            Contract verifies operator signature, appeal window expired
 |            Collateral distributed to beneficiaries
 |            Bond state = Impaired
 |
 |  T+259202s Off-chain CreditBondLifecycleState updated to Impaired
 |            Exposure ledger updated
```

### Flow D: Dispute Resolution

```
Time
 |
 |  T+0s     Settlement evidence submitted, PendingRelease state
 |
 |  T+1800s  Depositor calls disputeRelease() (within dispute window)
 |            Escrow state = Disputed
 |            Dispute event emitted
 |
 |  T+1801s  Operator/arbitrator begins off-chain review
 |            Examines receipt log, tool server logs, capability validity
 |
 |  T+86400s Arbitrator calls resolveDispute(escrowId, SplitSettlement(70%, 30%))
 |            Contract distributes: 70% to beneficiary, 30% to depositor
 |            Escrow state = Released
 |
 |  -- OR if no resolution by T+604800s (7 days) --
 |
 |  T+604800s Anyone calls expireDispute(escrowId)
 |            Full refund to depositor (fail-closed)
```

---

## 10. What This Unblocks

With these seven decisions made, arc-settle can proceed to engineering. The
concrete next steps are:

### Immediate (Sprint 1)

1. **Add `OnChain` variant to `CapitalExecutionRailKind`** in
   `crates/arc-core/src/credit.rs`. This is a one-line enum addition.

2. **Define `IdentityBindingCertificate` and `SignedIdentityBinding`** in a new
   `crates/arc-core/src/settlement.rs` module.

3. **Write the Solidity contracts** using the interfaces specified here:
   `ArcSettleRegistry.sol`, `ArcReceiptVerifier.sol`, `ArcEscrow.sol`,
   `ArcBondVault.sol`. Target: Foundry project under `contracts/`.

4. **Implement SHA-256-based Merkle proof verification** in Solidity using the
   `0x02` precompile, matching Chio's RFC 6962 tree construction.

### Near-term (Sprint 2)

5. **Build the `arc-settle` Rust crate** with the structure from
   CHIO_SETTLE_RESEARCH.md section 8.4. Priority modules: `client.rs` (Alloy
   provider), `escrow.rs` (create/release/refund), `dual_sign.rs` (secp256k1
   signing via `k256`).

6. **Implement the reconciliation service** (`reconcile.rs`) that polls
   on-chain events and updates the exposure ledger.

7. **Deploy contracts to Base Sepolia** for integration testing.

### Medium-term (Sprint 3-4)

8. **Implement Solana settlement program** with native Ed25519 receipt
   verification. This eliminates the dual-signing complexity for Solana-settled
   transactions.

9. **Integrate arc-anchor's root publication** with arc-settle's
   `ArcReceiptVerifier` so a single root publication serves both anchoring and
   settlement.

10. **Build the dispute monitoring and alerting pipeline** in arc-settle,
    connected to operator notification infrastructure.

### Deferred (v2)

11. Decentralized arbitration (Kleros/UMA integration as `arbitrator` address).
12. Cross-chain settlement via Circle CCTP.
13. ZK batch verification of Ed25519 signatures (Groth16/Halo2).
14. Permissionless root publication on EVM (pending Ed25519 precompile adoption).
15. Circle Gateway Nanopayments integration for sub-$0.10 settlements.
