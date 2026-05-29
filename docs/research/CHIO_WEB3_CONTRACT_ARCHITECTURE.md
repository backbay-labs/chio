# Chio Web3 Contract Architecture: Unified On-Chain Interface

Status: Architecture Specification
Date: 2026-03-30
Authors: Engineering
Inputs: CHIO_ANCHOR_RESEARCH.md, CHIO_SETTLE_RESEARCH.md, CHIO_LINK_RESEARCH.md

> Realization status (2026-04-02): this architecture is now realized in the
> shipped contract package under `contracts/`, the bindings in
> `crates/arc-web3-bindings/`, and the standards boundary in
> [CHIO_WEB3_PROFILE.md](../standards/CHIO_WEB3_PROFILE.md). The authoritative
> package inventory is `docs/standards/CHIO_WEB3_CONTRACT_PACKAGE.json`; it
> keeps four contracts immutable and the identity registry owner-managed and
> mutable.

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [Design Principles](#2-design-principles)
3. [Canonical Contract Set](#3-canonical-contract-set)
4. [Contract Interaction Diagram](#4-contract-interaction-diagram)
5. [Deployment Strategy](#5-deployment-strategy)
6. [Canonical Chain Configuration](#6-canonical-chain-configuration)
7. [Gas Budget Analysis](#7-gas-budget-analysis)
8. [Ed25519 Verification Strategy](#8-ed25519-verification-strategy)
9. [How Each Crate Uses the Contracts](#9-how-each-crate-uses-the-contracts)

---

## 1. Problem Statement

Three Chio research documents independently propose overlapping on-chain contract designs:

**CHIO_ANCHOR_RESEARCH.md** proposes `ArcAnchorRegistry` -- a minimal Merkle root storage contract. The operator calls `anchor()` with checkpoint metadata. The contract stores one `Anchor` struct per operator per checkpoint sequence number. No on-chain proof verification. ~45k-52k gas per anchor. No admin, no pause, no upgradeability.

**CHIO_SETTLE_RESEARCH.md** proposes four contracts:
- `ArcReceiptVerifier` -- Merkle root registry (similar to ArcAnchorRegistry) PLUS on-chain Merkle proof verification PLUS secp256k1 signature verification for the dual-signing path.
- `ArcEscrow` -- conditional escrow for tool call settlement, with release via Merkle proof or dual-sign evidence.
- `ArcBondVault` -- collateral locking for `CreditBond` enforcement with slash/release mechanics.
- `ArcSettleRegistry` -- maps Chio entity keys (Ed25519) to Ethereum addresses and manages operator authorization.

**CHIO_LINK_RESEARCH.md** proposes a third shape:
- `ArcAnchor.sol` -- Merkle root storage with timestamp and receipt count (different field set from the anchor doc's `ArcAnchorRegistry`).
- `ArcDelegationVerifier.sol` -- Chainlink Functions consumer for Ed25519 batch verification.
- `ArcPriceResolver.sol` -- optional on-chain price resolution wrapping Chainlink feeds.

Additionally, the sample configuration in arc-link's section 12.4 uses **Arbitrum** feed addresses (`chain_id = 42161`, addresses `0x639Fe6ab...`, `0x50834F31...`, `0x6ce18586...`) despite all three documents converging on **Base** as the primary chain.

Both the anchor and settle documents independently noted in their cross-integration sections that the `ArcAnchorRegistry` and `ArcReceiptVerifier` should be the same contract, but neither document produced that unified design. This document does.

### Why unification matters

1. **Double gas costs.** Publishing the same Merkle root to two contracts (one for tamper-evidence, one for settlement) wastes gas and creates an operational synchronization burden.
2. **Root divergence risk.** If the anchor root and settlement root are published at different times or to different contracts, a verifier could see inconsistent state.
3. **Operator confusion.** Three documents, three contract shapes, and no canonical answer about which one to deploy.
4. **Configuration drift.** The arc-link config hardcodes Arbitrum addresses while every document recommends Base as primary. A canonical config prevents this.

---

## 2. Design Principles

These principles are derived from Chio's core philosophy and the three research documents' shared conclusions.

1. **Fail-closed.** On-chain contracts must never release funds on ambiguous evidence. If a proof is invalid, the contract reverts. If a deadline passes without valid release, funds return to the depositor. No admin override.

2. **Immutable deployment.** Chio's fail-closed philosophy favors immutable contracts over upgradeable proxies. Proxy patterns introduce a governance trust assumption (who controls the upgrade?) that conflicts with Chio's minimize-trust model. Exception: the identity registry (IArcIdentityRegistry) uses a minimal owner for operator registration, since operator sets change over time.

3. **Single Merkle root source of truth.** One contract publishes and stores Merkle roots per operator. All downstream consumers (escrow, bond vault, external verifiers, arc-anchor verifiers) read from the same root.

4. **Separation of concerns.** Root publication, escrow logic, bond logic, identity mapping, and price resolution are separate contracts with clean interfaces. Composability via contract-to-contract calls, not monolithic state.

5. **Minimal on-chain state.** Prefer events for auditability and storage writes only where on-chain reads are required (e.g., escrow balances, published roots). Events are cheaper and sufficient for off-chain indexing.

6. **Ed25519 stays authoritative off-chain.** On-chain verification uses secp256k1 (dual-signing) for individual settlements and Merkle proofs for batch settlements. Ed25519 verification never happens on EVM. Solana programs use native Ed25519 verification directly.

7. **Stablecoin-first.** USDC is the primary settlement token. All escrow and bond amounts are denominated in ERC-20 stablecoins. No native ETH handling in settlement contracts.

8. **Multi-operator by default.** Every contract is keyed by operator address. Multiple Chio kernel operators share a single contract deployment. No per-operator contract instances.

---

## 3. Canonical Contract Set

Five contracts, one shared deployment per chain.

```
IArcRootRegistry.sol     -- Unified Merkle root publication and proof verification
IArcEscrow.sol           -- Conditional USDC escrow with Merkle proof and dual-sign release
IArcBondVault.sol        -- CreditBond collateral locking with slash/release
IArcIdentityRegistry.sol -- Maps ARC Ed25519 identities to on-chain addresses
IArcPriceResolver.sol    -- Optional on-chain price feed wrapper (Chainlink AggregatorV3)
```

### 3.1 IArcRootRegistry

This contract unifies `ArcAnchorRegistry` (from arc-anchor), `ArcReceiptVerifier` (from arc-settle), and `ArcAnchor` (from arc-link) into a single interface. It is the on-chain source of truth for receipt batch Merkle roots.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IArcRootRegistry
/// @notice Unified Merkle root publication and proof verification.
///         Serves both arc-anchor (tamper-evidence) and arc-settle (settlement evidence).
///         Replaces: ArcAnchorRegistry, ArcReceiptVerifier, ArcAnchor.sol
interface IArcRootRegistry {

    /// @notice Metadata stored per published root.
    struct RootEntry {
        bytes32 merkleRoot;
        uint64  checkpointSeq;
        uint64  batchStartSeq;
        uint64  batchEndSeq;
        uint64  treeSize;
        uint64  publishedAt;
        bytes32 operatorKeyHash;  // keccak256 of the operator's Ed25519 public key
    }

    /// @notice Emitted when a new Merkle root is published.
    /// @dev Contains all fields for off-chain indexing without storage reads.
    event RootPublished(
        address indexed operator,
        uint64  indexed checkpointSeq,
        bytes32 merkleRoot,
        uint64  batchStartSeq,
        uint64  batchEndSeq,
        uint64  treeSize,
        uint64  publishedAt,
        bytes32 operatorKeyHash
    );

    /// @notice Publish a new Merkle root for a receipt batch.
    /// @dev checkpointSeq must strictly increase per operator (append-only).
    ///      Caller is the operator (msg.sender is the operator's EVM address).
    ///      Must be a registered operator in the IArcIdentityRegistry.
    function publishRoot(
        bytes32 merkleRoot,
        uint64  checkpointSeq,
        uint64  batchStartSeq,
        uint64  batchEndSeq,
        uint64  treeSize,
        bytes32 operatorKeyHash
    ) external;

    /// @notice Publish multiple roots in a single transaction (catch-up scenario).
    /// @dev All entries must have strictly increasing checkpointSeq values.
    ///      The operatorKeyHash applies to all entries in the batch.
    function publishRootBatch(
        bytes32[] calldata merkleRoots,
        uint64[]  calldata checkpointSeqs,
        uint64[]  calldata batchStartSeqs,
        uint64[]  calldata batchEndSeqs,
        uint64[]  calldata treeSizes,
        bytes32   operatorKeyHash
    ) external;

    /// @notice Verify that a leaf (receipt hash) is included in a published root.
    /// @param proof    The Merkle inclusion proof (sibling hashes).
    /// @param root     The root to verify against (must have been published by `operator`).
    /// @param leafHash The hash of the receipt to verify (SHA256(0x00 || receipt_bytes)).
    /// @param operator The operator who published the root.
    /// @return valid   True if the proof verifies against the published root.
    function verifyInclusion(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 leafHash,
        address operator
    ) external view returns (bool valid);

    /// @notice Read the latest root entry for an operator.
    function getLatestRoot(address operator) external view returns (RootEntry memory);

    /// @notice Read a specific root entry by operator and checkpoint sequence.
    function getRoot(address operator, uint64 checkpointSeq) external view returns (RootEntry memory);

    /// @notice Read the latest checkpoint sequence number for an operator.
    function getLatestSeq(address operator) external view returns (uint64);
}
```

**Design notes:**

- `publishedAt` is set by `block.timestamp` inside the implementation, not passed by the caller. This prevents timestamp spoofing.
- `operatorKeyHash` is `keccak256(ed25519_public_key_bytes)`, providing a binding between the EVM address (msg.sender) and the Chio Ed25519 identity without putting raw Ed25519 keys on-chain.
- `verifyInclusion` uses OpenZeppelin's `MerkleProof.verify` internally. Chio uses RFC 6962-compatible Merkle trees (0x00 leaf prefix, 0x01 node prefix, carry-last-node-up for odd levels). The Solidity implementation must match this construction. OpenZeppelin's `MerkleProof` uses a different convention (sorted pairs), so the implementation must use a custom verifier that matches RFC 6962 semantics. This is an implementation detail, not an interface concern.
- The `operator` parameter on `verifyInclusion` ensures that escrow contracts verify receipts against the correct operator's roots, preventing cross-operator proof confusion.

### 3.2 IArcEscrow

Conditional USDC escrow for tool call settlement. Replaces the `IArcEscrow` from arc-settle with tighter integration to `IArcRootRegistry`.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IArcEscrow
/// @notice Conditional escrow for ARC tool call settlement.
///         Funds are locked on creation and released on valid receipt evidence
///         or refunded after deadline.
interface IArcEscrow {

    struct EscrowTerms {
        bytes32 capabilityId;     // ARC capability token ID (keccak256)
        address depositor;        // Agent paying for tool access
        address beneficiary;      // Tool server receiving payment
        address token;            // ERC-20 token address (USDC)
        uint256 maxAmount;        // Maximum settlement amount (in token decimals)
        uint256 deadline;         // Unix timestamp: auto-refund after this time
        address operator;         // Expected operator who publishes roots
        bytes32 operatorKeyHash;  // Expected operator's Ed25519 key hash
    }

    /// @notice Emitted when a new escrow is created.
    event EscrowCreated(
        bytes32 indexed escrowId,
        bytes32 indexed capabilityId,
        address indexed depositor,
        address beneficiary,
        address token,
        uint256 maxAmount,
        uint256 deadline,
        address operator
    );

    /// @notice Emitted when escrow funds are released to the beneficiary.
    event EscrowReleased(
        bytes32 indexed escrowId,
        uint256 amount,
        bytes32 receiptHash
    );

    /// @notice Emitted when escrow funds are partially released.
    event EscrowPartialRelease(
        bytes32 indexed escrowId,
        uint256 amount,
        uint256 remaining,
        bytes32 receiptHash
    );

    /// @notice Emitted when escrow funds are refunded to the depositor.
    event EscrowRefunded(bytes32 indexed escrowId, uint256 amount);

    /// @notice Create a new escrow. Caller must have approved `token` transfer.
    /// @dev Transfers `maxAmount` of `token` from depositor to this contract.
    function createEscrow(EscrowTerms calldata terms) external returns (bytes32 escrowId);

    /// @notice Create escrow using EIP-2612 permit (gasless approval).
    function createEscrowWithPermit(
        EscrowTerms calldata terms,
        uint256 permitDeadline,
        uint8 v, bytes32 r, bytes32 s
    ) external returns (bytes32 escrowId);

    /// @notice Release funds via Merkle proof (batch settlement path).
    /// @param escrowId      The escrow to release from.
    /// @param proof          Merkle inclusion proof for the receipt.
    /// @param root           The published root the proof is against.
    /// @param receiptHash    Hash of the receipt (leaf in the Merkle tree).
    /// @param settledAmount  Amount to release (must be <= maxAmount).
    /// @dev Verifies proof against IArcRootRegistry. Root must have been
    ///      published by the escrow's designated operator.
    function releaseWithProof(
        bytes32 escrowId,
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 receiptHash,
        uint256 settledAmount
    ) external;

    /// @notice Release funds via secp256k1 dual-signature (individual settlement path).
    /// @param escrowId       The escrow to release from.
    /// @param receiptHash    keccak256(canonical_json(receipt_body)).
    /// @param settledAmount  Amount to release.
    /// @param v, r, s        secp256k1 signature over receiptHash from the operator's
    ///                       settlement key (bound to Ed25519 key via IArcIdentityRegistry).
    function releaseWithSignature(
        bytes32 escrowId,
        bytes32 receiptHash,
        uint256 settledAmount,
        uint8 v, bytes32 r, bytes32 s
    ) external;

    /// @notice Partial release for metered billing or incremental settlement.
    /// @dev Can be called multiple times. Total released must not exceed maxAmount.
    function partialReleaseWithProof(
        bytes32 escrowId,
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 receiptHash,
        uint256 amount
    ) external;

    /// @notice Refund after deadline. Callable by anyone once block.timestamp > deadline.
    function refund(bytes32 escrowId) external;

    /// @notice Read escrow state.
    function getEscrow(bytes32 escrowId) external view returns (
        EscrowTerms memory terms,
        uint256 deposited,
        uint256 released,
        bool refunded
    );
}
```

**Design notes:**

- `releaseWithProof` calls `IArcRootRegistry.verifyInclusion(proof, root, receiptHash, terms.operator)` internally. The escrow contract does not reimplement Merkle verification.
- `releaseWithSignature` uses `ecrecover` to recover the signer from the receipt hash and signature, then verifies the signer is the registered settlement key for `terms.operator` via `IArcIdentityRegistry`.
- Only the `beneficiary` (or a registered relayer) can call release functions. This prevents frontrunning by extracting signatures from the mempool.
- `createEscrowWithPermit` combines EIP-2612 permit + transferFrom in one transaction, eliminating the two-step approve-then-deposit flow.
- The escrow does not support native ETH. All amounts are ERC-20.

### 3.3 IArcBondVault

Collateral locking for Chio's `CreditBond` lifecycle. Maps directly to `CreditBondDisposition` (Lock, Hold, Release, Impair) and `CreditBondLifecycleState` (Active, Superseded, Released, Impaired, Expired).

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IArcBondVault
/// @notice Collateral locking for CreditBond enforcement.
///         Supports lock, release, impair (slash), and auto-expire.
interface IArcBondVault {

    struct BondTerms {
        bytes32 bondId;              // ARC CreditBond ID (keccak256)
        bytes32 facilityId;          // Associated credit facility ID
        address principal;           // Bond holder (agent)
        address token;               // Collateral token (USDC)
        uint256 collateralAmount;    // CreditBondTerms.collateral_amount (in token decimals)
        uint256 reserveAmount;       // CreditBondTerms.reserve_requirement_amount
        uint256 expiresAt;           // Bond expiration timestamp
        uint16  reserveRatioBps;     // Basis points (from CreditBondTerms.reserve_ratio_bps)
        address operator;            // Operator authorized to impair/release
    }

    event BondLocked(
        bytes32 indexed bondId,
        bytes32 indexed facilityId,
        address indexed principal,
        address token,
        uint256 collateralAmount,
        uint256 expiresAt
    );

    event BondReleased(
        bytes32 indexed bondId,
        uint256 returnedAmount
    );

    event BondImpaired(
        bytes32 indexed bondId,
        uint256 slashedAmount,
        uint256 returnedAmount
    );

    event BondExpired(
        bytes32 indexed bondId,
        uint256 returnedAmount
    );

    /// @notice Lock collateral for a new bond. Caller must have approved token transfer.
    function lockBond(BondTerms calldata terms) external returns (bytes32 vaultId);

    /// @notice Release collateral on normal completion.
    /// @dev Only the designated operator can call. Must provide receipt evidence
    ///      (Merkle proof or dual-signature) proving the bond lifecycle reached Released.
    function releaseBond(
        bytes32 vaultId,
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 evidenceHash
    ) external;

    /// @notice Impair (slash) collateral.
    /// @param vaultId        The bond vault entry.
    /// @param slashAmount    Amount to slash from collateral.
    /// @param beneficiaries  Addresses to distribute slashed funds to.
    /// @param shares         Proportional shares per beneficiary (must sum to slashAmount).
    /// @param proof          Merkle proof of the impairment evidence.
    /// @param root           Published root the proof verifies against.
    /// @param evidenceHash   Hash of the impairment evidence receipt.
    function impairBond(
        bytes32 vaultId,
        uint256 slashAmount,
        address[] calldata beneficiaries,
        uint256[] calldata shares,
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 evidenceHash
    ) external;

    /// @notice Auto-release after expiry with no impairment.
    /// @dev Callable by anyone once block.timestamp > expiresAt.
    ///      Returns full collateral to principal.
    function expireRelease(bytes32 vaultId) external;

    /// @notice Read bond vault state.
    function getBond(bytes32 vaultId) external view returns (
        BondTerms memory terms,
        uint256 lockedAmount,
        uint256 slashedAmount,
        bool released,
        bool expired
    );
}
```

**Design notes:**

- `releaseBond` and `impairBond` require Merkle proof evidence from `IArcRootRegistry`, ensuring that bond state changes are backed by signed kernel receipts.
- Only the designated `operator` can call `releaseBond` and `impairBond`. This prevents unauthorized bond manipulation.
- `expireRelease` is callable by anyone after expiry, similar to the escrow `refund` pattern. This prevents bonds from being locked indefinitely if the operator disappears.
- Slash distribution is explicit: the caller provides beneficiary addresses and share amounts. The contract verifies that shares sum to slashAmount.

### 3.4 IArcIdentityRegistry

Maps Chio Ed25519 identities to on-chain addresses and manages operator authorization. This is the only contract with an admin role (for operator registration).

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IArcIdentityRegistry
/// @notice Maps ARC Ed25519 identities to EVM addresses.
///         Manages operator authorization for root publication and settlement.
interface IArcIdentityRegistry {

    struct OperatorRecord {
        bytes32 edKeyHash;        // keccak256(ed25519_public_key_bytes)
        address settlementKey;    // secp256k1 address for dual-sign verification
        uint64  registeredAt;     // Registration timestamp
        bool    active;           // Whether the operator is currently authorized
    }

    struct EntityRecord {
        bytes32 arcEntityId;      // keccak256(did:arc:entity_identifier)
        address settlementAddress; // On-chain settlement address
        address operator;         // Operator that registered this entity
        uint64  registeredAt;
        bool    active;
    }

    event OperatorRegistered(
        address indexed operatorAddress,
        bytes32 indexed edKeyHash,
        address settlementKey
    );

    event OperatorDeactivated(address indexed operatorAddress);

    event EntityRegistered(
        bytes32 indexed arcEntityId,
        address indexed settlementAddress,
        address indexed operator
    );

    /// @notice Register an ARC kernel operator.
    /// @param operatorAddress  The operator's EVM address (used for publishRoot, etc.).
    /// @param edKeyHash        keccak256 of the operator's Ed25519 public key.
    /// @param settlementKey    The operator's secp256k1 address for dual-sign verification.
    /// @param bindingProof     Off-chain proof that the Ed25519 key authorized this binding.
    ///                         Verified off-chain by the registry admin before calling.
    /// @dev Only callable by the registry admin. The binding proof is stored as an event
    ///      for transparency but is not verified on-chain (Ed25519 verification is not
    ///      feasible on EVM).
    function registerOperator(
        address operatorAddress,
        bytes32 edKeyHash,
        address settlementKey,
        bytes calldata bindingProof
    ) external;

    /// @notice Deactivate an operator. Does not affect existing escrows or bonds.
    function deactivateOperator(address operatorAddress) external;

    /// @notice Register an ARC entity's settlement address.
    /// @dev Callable by a registered operator on behalf of entities in their domain.
    function registerEntity(
        bytes32 arcEntityId,
        address settlementAddress,
        bytes calldata bindingProof
    ) external;

    /// @notice Check if an address is an authorized operator.
    function isOperator(address addr) external view returns (bool);

    /// @notice Get the settlement key for an operator (for dual-sign ecrecover checks).
    function getSettlementKey(address operator) external view returns (address);

    /// @notice Get the settlement address for an ARC entity.
    function getEntityAddress(bytes32 arcEntityId) external view returns (address);

    /// @notice Get the full operator record.
    function getOperator(address operator) external view returns (OperatorRecord memory);
}
```

**Design notes:**

- The `bindingProof` parameter contains the Ed25519-signed certificate binding the secp256k1 key. It is stored as event data for transparency and off-chain auditability, but NOT verified on-chain (because Ed25519 verification is gas-prohibitive on EVM).
- The admin role is the sole trust assumption in the contract set. It should be a multisig (e.g., Safe) with a timelock for deactivations. For maximum decentralization, a future version could replace the admin with a stake-weighted registration mechanism.
- The same secp256k1 key registered here is used by the operator to submit `publishRoot` transactions (via msg.sender) and by the escrow contract to verify `releaseWithSignature` dual-signatures.

### 3.5 IArcPriceResolver

Optional on-chain price resolution wrapping Chainlink AggregatorV3. Used by downstream contracts or off-chain readers who want a single Chio-curated view of price feeds.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IArcPriceResolver
/// @notice Optional on-chain price feed wrapper for ARC settlement contracts.
///         Provides staleness-checked price reads from Chainlink AggregatorV3.
///         Not required for core settlement -- included for on-chain price
///         verification in bond collateral adequacy checks.
interface IArcPriceResolver {

    struct PriceFeed {
        address aggregator;       // Chainlink AggregatorV3 proxy address
        uint256 maxStalenessSeconds; // Maximum acceptable age
        uint8   decimals;         // Feed decimals
        string  description;      // e.g., "ETH / USD"
    }

    /// @notice Get the latest price for a registered feed pair.
    /// @param base  Base currency code hash (keccak256("ETH")).
    /// @param quote Quote currency code hash (keccak256("USD")).
    /// @return price     The price in the feed's native decimals.
    /// @return decimals  The number of decimals in the price.
    /// @return updatedAt The timestamp of the last feed update.
    /// @dev Reverts if the feed is stale (updatedAt + maxStaleness < block.timestamp).
    function getPrice(bytes32 base, bytes32 quote)
        external
        view
        returns (int256 price, uint8 decimals, uint256 updatedAt);

    /// @notice Register a new price feed pair.
    /// @dev Only callable by the contract admin.
    function registerFeed(
        bytes32 base,
        bytes32 quote,
        address aggregator,
        uint256 maxStalenessSeconds
    ) external;

    /// @notice Check the L2 sequencer uptime feed.
    /// @return up        True if the sequencer is up.
    /// @return startedAt Timestamp when the sequencer last came up.
    function sequencerStatus() external view returns (bool up, uint256 startedAt);
}
```

**Design notes:**

- The price resolver is NOT required for escrow or bond operations. It is an optional utility. The kernel consumes prices off-chain via the `PriceOracle` trait (arc-link). On-chain price reads are only needed for advanced use cases like automated bond adequacy checks.
- Staleness is enforced at the contract level. If the Chainlink feed has not updated within `maxStalenessSeconds`, the call reverts. This matches Chio's fail-closed philosophy.
- The L2 sequencer uptime check (via Chainlink's L2 Sequencer Uptime Feed) is included because stale prices on L2 during sequencer downtime are a known risk.

---

## 4. Contract Interaction Diagram

```
                    +-------------------------+
                    | IArcIdentityRegistry    |
                    | (operator + entity      |
                    |  registration)          |
                    +------------+------------+
                                 |
                   isOperator()  |  getSettlementKey()
                                 |
              +------------------+------------------+
              |                                     |
              v                                     v
+-------------------------+           +-------------------------+
| IArcRootRegistry        |           | IArcEscrow              |
| (Merkle root publish    |<----------| (conditional escrow     |
|  + inclusion verify)    |  verify   |  with proof/sig release)|
+------------+------------+  Inclusion+------------+------------+
             |                                     |
             |  reads roots                        |  reads prices (optional)
             |                                     |
             v                                     v
+-------------------------+           +-------------------------+
| IArcBondVault           |           | IArcPriceResolver       |
| (collateral lock/slash  |           | (Chainlink feed wrapper)|
|  with proof evidence)   |           +-------------------------+
+-------------------------+

Off-chain callers:

arc-anchor daemon  -->  publishRoot()
                        publishRootBatch()

arc-settle crate   -->  createEscrow()
                        releaseWithProof()
                        releaseWithSignature()
                        lockBond()
                        releaseBond()
                        impairBond()

arc-link crate     -->  getPrice() (off-chain via alloy RPC)
                        Chainlink Automation triggers (optional)

Verifiers          -->  getRoot()
                        verifyInclusion()
```

**Data flow for batch settlement (the most common path):**

```
1. Kernel signs receipts with Ed25519
2. Kernel batches receipts into MerkleTree, produces KernelCheckpoint
3. arc-anchor daemon calls IArcRootRegistry.publishRoot(merkleRoot, ...)
4. Agent deposits USDC via IArcEscrow.createEscrow(terms)
5. Tool server executes, kernel signs receipt
6. Tool server (or relayer) calls IArcEscrow.releaseWithProof(
       escrowId, merkleProof, root, receiptHash, settledAmount
   )
7. IArcEscrow internally calls IArcRootRegistry.verifyInclusion(...)
8. On success, USDC transfers from escrow to beneficiary
```

**Data flow for dual-sign individual settlement:**

```
1. Kernel signs receipt with Ed25519 (authoritative)
2. Kernel produces secp256k1 dual-signature over keccak256(receipt_body)
3. Agent deposits USDC via IArcEscrow.createEscrow(terms)
4. Tool server calls IArcEscrow.releaseWithSignature(
       escrowId, receiptHash, settledAmount, v, r, s
   )
5. IArcEscrow calls ecrecover(receiptHash, v, r, s) -- 3,000 gas
6. IArcEscrow calls IArcIdentityRegistry.getSettlementKey(terms.operator)
7. Verifies recovered address == settlementKey
8. On match, USDC transfers from escrow to beneficiary
```

---

## 5. Deployment Strategy

### 5.1 Base Mainnet (Primary)

All five contracts are deployed on Base (Chain ID: 8453).

**Deployment order:**
1. `IArcIdentityRegistry` -- deployed first; other contracts reference it.
2. `IArcRootRegistry` -- references the identity registry for operator authorization.
3. `IArcPriceResolver` -- standalone; configured with Base Chainlink feed addresses.
4. `IArcEscrow` -- references root registry and identity registry.
5. `IArcBondVault` -- references root registry and identity registry.

**Deterministic deployment:** Use CREATE2 via a factory contract to ensure identical addresses across all chains. The salt includes the Chio protocol version to allow clean upgrades via new deployments.

**Immutability:** All contracts except IArcIdentityRegistry are deployed without proxy patterns. IArcIdentityRegistry uses a minimal Ownable pattern (not a full proxy) because the operator set changes over time.

### 5.2 Solana (Secondary)

Solana programs replace the EVM contracts for operators who want native Ed25519 verification.

**Solana program equivalents:**

| EVM Contract | Solana Program | Key Difference |
|-------------|---------------|----------------|
| IArcRootRegistry | arc_root_registry program | Stores roots in PDAs per operator |
| IArcEscrow | arc_escrow program | Verifies Ed25519 receipts NATIVELY via Ed25519SigVerify precompile -- no dual-signing needed |
| IArcBondVault | arc_bond_vault program | Same, with native Ed25519 |
| IArcIdentityRegistry | arc_identity program | Simpler -- no secp256k1 binding needed since Ed25519 is native |
| IArcPriceResolver | Not needed | Pyth feeds consumed directly via CPI |

**Key advantage on Solana:** The entire dual-signing complexity disappears. Chio receipts are verified directly using the Solana Ed25519 precompile program. This is the strongest argument for Solana as a parallel settlement rail.

### 5.3 Secondary EVM Chains

For Arbitrum or other EVM L2s, deploy the same contract set with the same CREATE2 addresses. The only configuration difference is the Chainlink feed addresses in IArcPriceResolver.

### 5.4 Cross-Chain Root Availability

If arc-settle has escrows on multiple chains, the same Merkle root must be published on each chain. Options:

1. **Independent publication** (recommended for v1): The arc-anchor daemon publishes the same root to each chain where escrows exist. Cost: ~$0.01 per chain per root. Simple and reliable.
2. **CCIP relay** (v2): Publish on Base, use Chainlink CCIP to relay the root to other chains. Cost: $0.09-0.10 per relay. Adds latency (minutes). Overkill for a 32-byte hash.
3. **Off-chain root distribution** (alternative): Publish only on Base. Off-chain verifiers fetch the root from Base and submit it alongside their Merkle proof on the destination chain. This requires the escrow to trust the submitted root, which defeats the purpose.

Recommendation: Option 1 (independent publication) for v1. The cost is negligible and avoids cross-chain latency.

---

## 6. Canonical Chain Configuration

### 6.1 Base Mainnet Addresses

The following addresses are canonical for Chio's primary deployment on Base (Chain ID: 8453).

**Core tokens:**

| Token | Address | Decimals | Notes |
|-------|---------|----------|-------|
| USDC (Circle native) | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` | 6 | Native USDC on Base, NOT bridged |
| EURC (Circle native) | `0x60a3E35Cc302bFA44Cb288Bc5a4F316Fdb1adb42` | 6 | Native EURC on Base |
| WETH | `0x4200000000000000000000000000000000000006` | 18 | Wrapped ETH predeploy |

**Chainlink Data Feed addresses (Base Mainnet):**

| Pair | Proxy Address | Decimals | Heartbeat | Deviation |
|------|--------------|----------|-----------|-----------|
| ETH / USD | `0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70` | 8 | 1200s (20m) | 0.15% |
| BTC / USD | `0x64c911996D3c6aC71f9b455B1E8E7266BcbD848F` | 8 | 1200s (20m) | 0.15% |
| USDC / USD | `0x7e860098F58bBFC8648a4311b374B1D669a2bc6B` | 8 | 86400s (24h) | 0.1% |
| LINK / USD | `0x17CAb8FE31cA45e4684Ea7bCB9D30Ba03e38BF2C` | 8 | 1200s (20m) | 0.5% |

**Chainlink L2 Sequencer Uptime Feed (Base Mainnet):**

| Feed | Address |
|------|---------|
| L2 Sequencer Uptime | `0xBCF85224fc0756B9Fa45aA7892530B47e10b6433` |

**EAS (Ethereum Attestation Service) on Base:**

| Contract | Address |
|----------|---------|
| EAS | `0x4200000000000000000000000000000000000021` |
| SchemaRegistry | `0x4200000000000000000000000000000000000020` |

### 6.2 Corrected Configuration (replacing Arbitrum addresses from arc-link)

The arc-link research document's section 12.4 used Arbitrum addresses. The canonical configuration for Chio uses Base:

```toml
[price_oracle]
primary = "chainlink"
fallback = "pyth"
refresh_interval_seconds = 60
max_price_age_seconds = 1200     # Match Base ETH/USD heartbeat
circuit_breaker_divergence_pct = 5.0
twap_enabled = true
twap_window_seconds = 600
rpc_endpoint = "https://mainnet.base.org"

[price_oracle.chainlink]
chain_id = 8453  # Base Mainnet
sequencer_uptime_feed = "0xBCF85224fc0756B9Fa45aA7892530B47e10b6433"
feeds = [
    { pair = "ETH/USD", address = "0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70", heartbeat = 1200, deviation_bps = 15 },
    { pair = "USDC/USD", address = "0x7e860098F58bBFC8648a4311b374B1D669a2bc6B", heartbeat = 86400, deviation_bps = 10 },
    { pair = "BTC/USD", address = "0x64c911996D3c6aC71f9b455B1E8E7266BcbD848F", heartbeat = 1200, deviation_bps = 15 },
    { pair = "LINK/USD", address = "0x17CAb8FE31cA45e4684Ea7bCB9D30Ba03e38BF2C", heartbeat = 1200, deviation_bps = 50 },
]

[price_oracle.pyth]
hermes_url = "https://hermes.pyth.network"
feeds = [
    { pair = "ETH/USD", id = "0xff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace" },
    { pair = "BTC/USD", id = "0xe62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43" },
    { pair = "USDC/USD", id = "0xeaa020c61cc479712813461ce153894a96a6c00b21ed0cfc2798d1f9a9e9c94a" },
]
```

### 6.3 Solana Mainnet Addresses

| Resource | Address / Program ID |
|----------|---------------------|
| USDC (SPL Token) | `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v` |
| Ed25519 Verify Program | `Ed25519SigVerify111111111111111111111111111` |
| Memo Program | `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr` |
| Pyth Price Feed (ETH/USD) | `JBu1AL4obBcCMqKBBxhpWCNUt136ijcuMZLFvTP7iWdB` |

---

## 7. Gas Budget Analysis

All estimates use Base L2 gas pricing at 2025-2026 levels. Estimates include execution gas only; L1 data posting adds 60-80% overhead that varies with Ethereum mainnet congestion. Apply a 3x safety margin for production budgeting.

### 7.1 Per-Operation Gas Estimates

| Operation | Contract | Estimated Gas | Est. USD (Base) | Notes |
|-----------|----------|--------------|-----------------|-------|
| Publish root | IArcRootRegistry | ~52,000 | ~$0.005 | 2x SSTORE + event |
| Publish root batch (10) | IArcRootRegistry | ~250,000 | ~$0.02 | Amortizes 21k base tx |
| Verify inclusion (view) | IArcRootRegistry | ~30,000 | Free (view call) | MerkleProof.verify |
| Create escrow | IArcEscrow | ~120,000 | ~$0.02 | SSTORE + ERC-20 transferFrom |
| Create escrow with permit | IArcEscrow | ~150,000 | ~$0.02 | permit() + transferFrom |
| Release with Merkle proof | IArcEscrow | ~80,000 | ~$0.01 | verify + ERC-20 transfer |
| Release with signature | IArcEscrow | ~60,000 | ~$0.01 | ecrecover + transfer |
| Partial release | IArcEscrow | ~85,000 | ~$0.01 | verify + transfer + accounting |
| Refund | IArcEscrow | ~55,000 | ~$0.005 | ERC-20 transfer + state clear |
| Lock bond | IArcBondVault | ~110,000 | ~$0.015 | SSTORE + transferFrom |
| Release bond | IArcBondVault | ~80,000 | ~$0.01 | verify + transfer |
| Impair bond | IArcBondVault | ~150,000 | ~$0.02 | verify + N transfers |
| Expire release | IArcBondVault | ~60,000 | ~$0.008 | transfer + state clear |
| Register operator | IArcIdentityRegistry | ~70,000 | ~$0.01 | 3x SSTORE + event |
| Register entity | IArcIdentityRegistry | ~50,000 | ~$0.007 | 2x SSTORE + event |
| Read price | IArcPriceResolver | ~10,000 | Free (view call) | delegatecall to aggregator |

### 7.2 Cost Projections by Operator Size

**Small operator** (100 tool invocations/day):

| Activity | Frequency | Daily Cost |
|----------|-----------|-----------|
| Root publication | 1/day (1 checkpoint) | $0.005 |
| Escrow create/release | 10/day (high-value only) | $0.30 |
| Bond operations | 1/week | $0.004 |
| **Total** | | **~$0.31/day** |

**Medium operator** (1,000 tool invocations/day):

| Activity | Frequency | Daily Cost |
|----------|-----------|-----------|
| Root publication | 10/day (10 checkpoints) | $0.05 |
| Escrow create/release | 50/day | $1.50 |
| Bond operations | 5/day | $0.10 |
| **Total** | | **~$1.65/day** |

**Large operator** (100,000 tool invocations/day):

| Activity | Frequency | Daily Cost |
|----------|-----------|-----------|
| Root publication | 1,000/day | $5.00 |
| Batch settlement (Merkle) | 100 batches/day | $1.00 |
| Bond operations | 50/day | $1.50 |
| **Total** | | **~$7.50/day** |

For large operators, the batch Merkle settlement path amortizes cost across many receipts. Sub-cent settlements should use the Merkle proof path or Circle Gateway Nanopayments rather than individual escrows.

---

## 8. Ed25519 Verification Strategy

### 8.1 The Problem

Chio signs all receipts and capability tokens with Ed25519. The EVM natively supports only secp256k1 (`ecrecover` at 3,000 gas). There is no production Ed25519 precompile on any EVM chain.

### 8.2 Unified Strategy (Three Tiers)

The three research documents each proposed different approaches. The unified strategy layers them by settlement value and chain:

**Tier 1: Merkle Root Commitment (default for EVM, all settlement sizes)**

- The kernel publishes Merkle roots of receipt batches via `IArcRootRegistry.publishRoot()`.
- Settlement claims use `IArcEscrow.releaseWithProof()` with a Merkle inclusion proof.
- No signature verification on-chain at all. Gas cost: ~80k for release (50k for proof verification + 30k for transfer).
- Latency: must wait for the next root publication (configurable, typically every 100 receipts or 60 seconds).
- This is the recommended default path for all EVM settlement.

**Tier 2: Dual-Signing with secp256k1 (EVM, individual high-value settlements)**

- The kernel maintains a secondary secp256k1 keypair bound to its Ed25519 key via `IArcIdentityRegistry`.
- For individual settlements that cannot wait for the next root publication, the kernel produces a secp256k1 signature over `keccak256(canonical_json(receipt_body))`.
- `IArcEscrow.releaseWithSignature()` uses `ecrecover` (3,000 gas) to verify.
- Gas cost: ~60k for release. No latency beyond receipt generation.
- Introduces dual-key management: the secp256k1 key must be provisioned, rotated, and backed up alongside the Ed25519 key. The binding certificate (Ed25519 signing a message containing the secp256k1 pubkey) must be refreshed on key rotation.

**Tier 3: Native Ed25519 on Solana (Solana settlement rail)**

- Solana's `Ed25519SigVerify111111111111111111111111111` precompile verifies Ed25519 signatures natively at compute-unit cost.
- Chio receipts are verified directly -- no dual-signing, no Merkle proof intermediary needed (though Merkle proofs are still used for batch efficiency).
- This eliminates the entire dual-key management complexity for operators who settle on Solana.
- Recommended for operators who prioritize cryptographic purity (single key scheme) over EVM ecosystem access.

### 8.3 What is NOT recommended

- **Pure Solidity Ed25519 verification**: 500k-1.25M gas per signature. Impractical.
- **EIP-665 precompile**: Stagnant since 2018. No chain has implemented it. Cannot depend on it.
- **Chainlink Functions for Ed25519**: Introduces DON trust assumption with no on-chain challenge mechanism. Acceptable as an optional "trust-but-verify" layer for arc-anchor batch verification, but NOT acceptable as the primary settlement verification path. Settlement funds must not depend on DON honesty.
- **ZK proofs of Ed25519**: ~300k gas (Groth16) with 6-second proving time. Viable for future batch verification (amortized to ~3k gas per signature for 99-signature batches), but operationally complex for v1. Monitor for v2.

### 8.4 Phased Rollout

| Phase | EVM Path | Solana Path | When |
|-------|----------|-------------|------|
| v1 | Tier 1 (Merkle) + Tier 2 (dual-sign) | Tier 3 (native Ed25519) | Initial deployment |
| v2 | Add ZK batch verification option | Same | When ZK provers mature |
| v3 | Native Ed25519 if RIP-7696 adopted | Same | If/when rollups adopt RIP-7696 |

---

## 9. How Each Crate Uses the Contracts

### 9.1 arc-anchor

**Primary interaction:** `IArcRootRegistry.publishRoot()` and `IArcRootRegistry.publishRootBatch()`

**Flow:**
1. The arc-anchor daemon polls `kernel_checkpoints` from the receipt store for new checkpoints.
2. For each new checkpoint, calls `publishRoot()` on the IArcRootRegistry contract on each configured chain.
3. Stores the transaction hash and confirmation status in the local `anchor_records` table.
4. For Bitcoin anchoring, aggregates multiple checkpoint roots into a super-root and submits via OpenTimestamps or OP_RETURN. This is independent of the EVM contracts.

**Configuration consumed:**
- IArcRootRegistry contract address (per chain)
- Operator EVM address (msg.sender for publishRoot)
- RPC endpoints (Base primary, optional secondary chains)

**Data mapping:**

| Chio type | Contract field |
|----------|---------------|
| `KernelCheckpoint.merkle_root` | `merkleRoot` (bytes32) |
| `KernelCheckpoint.checkpoint_seq` | `checkpointSeq` (uint64) |
| `KernelCheckpoint.batch_start_seq` | `batchStartSeq` (uint64) |
| `KernelCheckpoint.batch_end_seq` | `batchEndSeq` (uint64) |
| `KernelCheckpoint.tree_size` | `treeSize` (uint64) |
| `keccak256(KernelCheckpoint.kernel_key)` | `operatorKeyHash` (bytes32) |

### 9.2 arc-settle

**Primary interactions:** All five contracts.

**Escrow flow (CapitalExecutionInstructionAction mapping):**

| Chio Action | Contract Call |
|-----------|--------------|
| `LockReserve` | `IArcEscrow.createEscrow()` or `IArcBondVault.lockBond()` |
| `HoldReserve` | No-op (funds already locked on-chain) |
| `ReleaseReserve` | `IArcEscrow.releaseWithProof()` or `IArcBondVault.releaseBond()` |
| `TransferFunds` | `IArcEscrow.releaseWithSignature()` (immediate transfer) |
| `CancelInstruction` | `IArcEscrow.refund()` (after deadline) |

**Bond lifecycle (CreditBondLifecycleState mapping):**

| Chio State | Contract Call |
|-----------|--------------|
| `Active` | `IArcBondVault.lockBond()` |
| `Superseded` | Lock new bond, release old via `releaseBond()` |
| `Released` | `IArcBondVault.releaseBond()` |
| `Impaired` | `IArcBondVault.impairBond()` |
| `Expired` | `IArcBondVault.expireRelease()` |

**Settlement status tracking:**

| `SettlementStatus` | On-chain meaning |
|-------------------|------------------|
| `NotApplicable` | No escrow created for this receipt |
| `Pending` | Escrow created, release not yet called |
| `Settled` | `releaseWithProof` or `releaseWithSignature` confirmed on-chain |
| `Failed` | On-chain transaction reverted |

**MonetaryAmount to ERC-20 conversion:**

Chio's `MonetaryAmount.units` represents minor units (cents for USD). USDC on-chain uses 6 decimals (1 USD = 1,000,000 micro-units). Conversion: `on_chain_amount = arc_units * 10_000` for USD/cents. This factor MUST be configurable per currency via a `CurrencyDecimals` mapping, not hardcoded.

**CapitalExecutionRail extension:**

```rust
pub enum CapitalExecutionRailKind {
    Manual,
    Api,
    Ach,
    Wire,
    Ledger,
    Sandbox,
    OnChain,  // NEW: routes through IArcEscrow or IArcBondVault
}
```

The `jurisdiction` field on `CapitalExecutionRail` maps to CAIP-2 chain identifiers:
- `"eip155:8453"` -- Base Mainnet
- `"eip155:42161"` -- Arbitrum One
- `"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"` -- Solana Mainnet

### 9.3 arc-link

**Primary interactions:** `IArcPriceResolver` (optional on-chain reads) and off-chain Chainlink/Pyth consumption.

**Off-chain oracle consumption (the primary path):**
1. The kernel's `PriceOracle` trait reads Chainlink AggregatorV3 feeds via alloy RPC calls against the Base Mainnet feed addresses listed in section 6.
2. Pyth Hermes API is the fallback, consumed via `reqwest` HTTP client.
3. The local price cache provides TWAP and staleness tracking.

**On-chain interaction (optional):**
- `IArcPriceResolver.getPrice()` -- used by on-chain contracts that need price data (e.g., bond collateral adequacy checks).
- Chainlink Automation upkeeps -- can trigger `publishRoot()` on IArcRootRegistry as an alternative to the arc-anchor daemon.

**Configuration alignment:**

All three crates share these configuration elements, which MUST be unified in a single config section to prevent drift:

```toml
[arc_web3]
primary_chain = "base"
primary_chain_id = 8453
rpc_endpoint = "https://mainnet.base.org"
operator_address = "0x..."       # EVM address for publishRoot and escrow operations
root_registry = "0x..."          # IArcRootRegistry deployment address
escrow = "0x..."                 # IArcEscrow deployment address
bond_vault = "0x..."             # IArcBondVault deployment address
identity_registry = "0x..."     # IArcIdentityRegistry deployment address
price_resolver = "0x..."        # IArcPriceResolver deployment address (optional)

[arc_web3.tokens]
usdc = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"  # Base USDC
eurc = "0x60a3E35Cc302bFA44Cb288Bc5a4F316Fdb1adb42"  # Base EURC

[arc_web3.feeds]
eth_usd = "0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70"
btc_usd = "0x64c911996D3c6aC71f9b455B1E8E7266BcbD848F"
usdc_usd = "0x7e860098F58bBFC8648a4311b374B1D669a2bc6B"
link_usd = "0x17CAb8FE31cA45e4684Ea7bCB9D30Ba03e38BF2C"
sequencer_uptime = "0xBCF85224fc0756B9Fa45aA7892530B47e10b6433"

[arc_web3.solana]
chain = "solana-mainnet"
rpc_endpoint = "https://api.mainnet-beta.solana.com"
usdc_mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
```

### 9.4 Shared alloy Bindings

All three crates should share a single `arc-web3-bindings` crate (or module) that uses alloy's `sol!` macro to generate Rust types from the Solidity interfaces:

```rust
use alloy::sol;

sol! {
    #[sol(rpc)]
    interface IArcRootRegistry {
        struct RootEntry {
            bytes32 merkleRoot;
            uint64  checkpointSeq;
            uint64  batchStartSeq;
            uint64  batchEndSeq;
            uint64  treeSize;
            uint64  publishedAt;
            bytes32 operatorKeyHash;
        }

        event RootPublished(
            address indexed operator,
            uint64  indexed checkpointSeq,
            bytes32 merkleRoot,
            uint64  batchStartSeq,
            uint64  batchEndSeq,
            uint64  treeSize,
            uint64  publishedAt,
            bytes32 operatorKeyHash
        );

        function publishRoot(
            bytes32 merkleRoot,
            uint64  checkpointSeq,
            uint64  batchStartSeq,
            uint64  batchEndSeq,
            uint64  treeSize,
            bytes32 operatorKeyHash
        ) external;

        function verifyInclusion(
            bytes32[] calldata proof,
            bytes32 root,
            bytes32 leafHash,
            address operator
        ) external view returns (bool valid);

        function getLatestRoot(address operator) external view returns (RootEntry memory);
        function getRoot(address operator, uint64 checkpointSeq) external view returns (RootEntry memory);
        function getLatestSeq(address operator) external view returns (uint64);
    }
}
```

This shared binding ensures all three crates use identical ABI encodings and prevents type mismatch across crate boundaries.

---

## Appendix A: Migration from Research Document Designs

For implementers referencing the original research documents, this table maps old contract names to the unified set:

| Original (Document) | Unified Interface | Notes |
|---------------------|-------------------|-------|
| `ArcAnchorRegistry` (anchor) | `IArcRootRegistry` | Field set expanded to include proof verification |
| `ArcReceiptVerifier` (settle) | `IArcRootRegistry` | Root publication + proof verification merged |
| `ArcAnchor.sol` (link) | `IArcRootRegistry` | Different field names normalized |
| `ArcEscrow` (settle) | `IArcEscrow` | Unchanged except references IArcRootRegistry |
| `ArcBondVault` (settle) | `IArcBondVault` | Added proof evidence requirements |
| `ArcSettleRegistry` (settle) | `IArcIdentityRegistry` | Renamed; expanded to cover both settle and anchor operator registration |
| `ArcDelegationVerifier` (link) | Removed | Chainlink Functions-based Ed25519 is NOT recommended as a settlement path; retained as optional off-chain verification in arc-link |
| `ArcPriceResolver` (link) | `IArcPriceResolver` | Unchanged |

## Appendix B: Merkle Tree Compatibility Note

Chio uses an RFC 6962-compatible (Certificate Transparency style) Merkle tree:
- Leaf hashes: `SHA256(0x00 || leaf_bytes)`
- Node hashes: `SHA256(0x01 || left || right)`
- Odd-level handling: carry the last node upward unchanged (no leaf duplication)

OpenZeppelin's `MerkleProof.verify` uses a **different** convention (sorted pair hashing without domain separation prefixes). The `IArcRootRegistry` implementation MUST use a custom Merkle verification function that matches Chio's RFC 6962 construction. Using OpenZeppelin's default `MerkleProof` will produce incorrect verification results.

A reference Solidity implementation of RFC 6962-compatible verification:

```solidity
function verifyRFC6962(
    bytes32[] calldata proof,
    bytes32 root,
    bytes32 leaf,
    uint256 leafIndex,
    uint256 treeSize
) internal pure returns (bool) {
    bytes32 computedHash = leaf; // Already prefixed: SHA256(0x00 || data)
    for (uint256 i = 0; i < proof.length; i++) {
        if (leafIndex % 2 == 0) {
            computedHash = sha256(abi.encodePacked(bytes1(0x01), computedHash, proof[i]));
        } else {
            computedHash = sha256(abi.encodePacked(bytes1(0x01), proof[i], computedHash));
        }
        leafIndex /= 2;
    }
    return computedHash == root;
}
```

Note: This uses `sha256` (the EVM precompile at address 0x02, ~60 gas per call) rather than `keccak256`. Chio's Merkle tree uses SHA-256, not Keccak-256. The EVM sha256 precompile makes this efficient.
