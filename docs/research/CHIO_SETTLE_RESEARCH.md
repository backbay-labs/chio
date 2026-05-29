# Chio-Settle: On-Chain Settlement Rail Research

Status: Research draft (reviewed 2026-03-30)
Date: 2026-03-30
Authors: Engineering
Reviewer: Technical Review

> Realization status (2026-04-02): this document fed the shipped bounded
> `arc-settle` runtime, but the authoritative runtime boundary is now
> [CHIO_SETTLE_PROFILE.md](../standards/CHIO_SETTLE_PROFILE.md) plus
> [CHIO_WEB3_PROFILE.md](../standards/CHIO_WEB3_PROFILE.md). Several research
> names were superseded in implementation: the shared Merkle-root contract is
> `IArcRootRegistry`, the operator-binding contract is
> `IArcIdentityRegistry`, and the official contract package is mostly
> immutable with the identity registry as the one owner-managed mutable
> exception. For shipped behavior, prefer `crates/arc-settle/`, `contracts/`,
> and the checked-in standards or release docs over this draft's open options.

---

## 1. Executive Summary

Chio already models a complete economic substrate: `MonetaryAmount` in capability tokens, `CapitalExecutionInstruction` for directing fund movements, `CapitalExecutionRail` / `CapitalExecutionRailKind` for settlement rail types, `CreditBond` / `CreditBondTerms` for bonded execution, and a full underwriting-credit-loss lifecycle. The existing `CapitalExecutionRailKind` enum includes `Manual`, `Api`, `Ach`, `Wire`, `Ledger`, and `Sandbox` -- but no on-chain rail.

**arc-settle** closes this gap by adding a new `CapitalExecutionRailKind::OnChain` variant backed by EVM smart contracts that implement stablecoin escrow, conditional release against signed receipt evidence, and bond/slash mechanics. The crate would be a Rust library (built on Alloy) that translates Chio's `CapitalExecutionInstruction` artifacts into on-chain transactions and monitors their settlement.

Key findings from this research:

- **Chain selection**: Base is the recommended primary EVM target -- native USDC, sub-cent transaction costs, deep Coinbase ecosystem integration, and the x402 agent payment standard. **Solana** is a strong secondary target due to native Ed25519 verification via its precompile program, eliminating the hardest EVM integration challenge entirely.
- **Ed25519 on EVM** is the hardest design problem. No EVM chain has a production Ed25519 precompile. Practical options are: (a) dual-signing with secp256k1 for on-chain evidence, (b) ZK proof of Ed25519 signature (~300k gas via Groth16), or (c) a Merkle commitment approach where only a root hash goes on-chain.
- **Alloy** (v1.0, stable since May 2025) is the clear choice for Rust-to-EVM interaction. ethers-rs is deprecated.
- **x402** (Coinbase) is an active agent payment standard (5.8k GitHub stars, 717 commits, active daily development as of March 2026) worth monitoring. x402 supports EVM, Solana, Aptos, and Stellar chains. Chio's own protocol provides stronger attestation guarantees, but x402 compatibility could widen adoption.
- **Circle Gateway Nanopayments** enable gas-free USDC payments down to $0.000001, purpose-built for AI agents and high-frequency sub-cent transactions. This is directly relevant for Chio micro-settlement and could serve as an alternative to custom escrow for low-value settlements.
- **ERC-4337 account abstraction** and paymaster patterns can eliminate gas management complexity for agents by allowing USDC-denominated fee payment.

---

## 2. Existing Agent Payment/Settlement Projects

### 2.1 x402 (Coinbase)

The most directly relevant project in this space. x402 revives the HTTP 402 status code for machine-to-machine payments.

**Architecture**: Client sends HTTP request; server responds with 402 + payment requirements; client signs a USDC transfer authorization (EIP-3009 `TransferWithAuthorization`); server verifies via a "facilitator" service and settles on-chain.

**Current state** (March 2026): The x402 repository under github.com/coinbase/x402 has 5.8k stars, 1.4k forks, and 717 commits with active daily development. Framework adapters exist for Express, Hono, and Fastify. Supported chains include EVM (Base, Polygon), Solana, Aptos, and Stellar. Stripe integrated in February 2026 for USDC payments on Base. On-chain settlement volume remains modest relative to traditional payment rails.

**Supported tokens**: USDC and EURC natively (via EIP-3009); any ERC-20 via Permit2 with gas sponsorship.

**Supported chains**: Base, Polygon, Solana, Aptos, Stellar via the CDP facilitator.

**Relevance to Chio**: x402 solves a narrower problem (HTTP API monetization) than arc-settle (full escrow, bond, and conditional release). However, x402's use of EIP-3009 `TransferWithAuthorization` for gasless USDC movement is a pattern arc-settle should adopt. Chio could optionally expose an x402-compatible payment surface for tool servers that want HTTP-native billing.

### 2.2 Fetch.ai Autonomous Payments

Fetch.ai announced AI-to-AI payments launching January 2026. Each AI agent operates with a dedicated wallet and user-defined spending limits. On-chain settlement uses USDC or FET tokens with optional transaction confirmations requiring user approval before finalization.

**Relevance to Chio**: Fetch.ai's spending-limit model mirrors Chio's `max_total_cost` on `ToolGrant`. The difference is that Chio enforces limits at the kernel layer with cryptographic receipts, while Fetch.ai relies on wallet-level configuration. Chio's approach is stronger -- the kernel is the trusted computing base and spending limits are capability-attenuated, not just wallet-configured.

### 2.3 Autonolas (Olas)

Autonolas provides autonomous agent services including an "AI Portfolio Manager" operating on Base, Optimism, and Mode with multiple stablecoins. Agents implement strategies autonomously 24/7.

**Relevance to Chio**: Olas demonstrates multi-chain agent execution but does not provide the attestation or receipt infrastructure that Chio has. Olas agents could potentially be wrapped as Chio tool servers with arc-settle providing the settlement rail.

### 2.4 Virtuals Protocol

Virtuals Protocol creates tokenized AI agents that engage in on-chain commerce. Recent integrations include Arbitrum (March 2026) and XRP Ledger (March 2026). The protocol focuses on agent-to-agent transactions with escrowed jobs and programmable settlement.

**Relevance to Chio**: Virtuals' "escrowed jobs" concept is closest to Chio's governed transaction model. However, Virtuals is focused on launching agent tokens (speculative) rather than providing verifiable settlement infrastructure. Chio's signed receipt log and credit bond system provide the accountability layer that Virtuals lacks.

### 2.5 SingularityNET (AGIX / ASI Alliance)

SingularityNET operates a decentralized AI service marketplace where developers publish algorithms and users pay with AGIX tokens. The ASI:Chain DevNet launched November 2025 as a Layer 1 blockDAG. Over 3 billion inference tokens processed via ASI:Cloud.

**Relevance to Chio**: SingularityNET's marketplace model (pay-per-inference with smart contract settlement) validates the agent economy thesis. However, AGIX uses a proprietary token rather than stablecoins, limiting composability. Chio's stablecoin-first approach avoids token risk.

### 2.6 Morpheus AI

Morpheus is building decentralized AI agent infrastructure with a focus on compute marketplace and agent-to-agent coordination. Less mature than the above projects.

### 2.7 Chainlink CRE (Cross-chain Runtime Environment)

Chainlink provides three relevant layers: (a) CCIP for cross-chain value transfer, (b) CRE for off-chain computation verification before on-chain payment release, and (c) data feeds for price/condition verification. Chainlink's CRE model -- verify real-world conditions off-chain, then trigger on-chain release -- maps closely to Chio's receipt-then-settle pattern.

### 2.8 Circle Gateway Nanopayments

Circle's Gateway product includes a Nanopayments feature that enables gas-free USDC payments down to $0.000001, purpose-built for AI agents, usage-based billing, and high-frequency sub-cent transactions. Nanopayments extends the Gateway unified balance with batched settlement, meaning individual micro-transactions are aggregated and settled in larger batches to amortize gas costs.

**Relevance to Chio**: Nanopayments directly addresses Chio's micro-settlement challenge. For tool invocations costing fractions of a cent, building custom escrow contracts is over-engineered. Integrating with Gateway Nanopayments could provide immediate sub-cent settlement capability without custom smart contract deployment. The tradeoff is dependency on Circle's infrastructure and loss of Chio's self-sovereign settlement model. **Recommendation**: Evaluate Nanopayments as a v1 fast path for micro-settlement (sub-$0.10), with custom escrow contracts for higher-value governed transactions where Chio's full receipt evidence model adds value.

**Key takeaway**: No existing project combines Chio's three strengths: (1) capability-attenuated spending limits with cryptographic receipts, (2) a full underwriting and credit lifecycle, and (3) verifiable settlement. arc-settle would be unique in providing all three.

---

## 3. Stablecoin Settlement Patterns

### 3.1 USDC Smart Contract Architecture

Circle's USDC follows the OpenZeppelin Proxy Upgrade Pattern:
- **Implementation contract** (`FiatTokenV2_2.sol`) contains core token logic
- **Proxy contract** (`FiatTokenProxy.sol`) enables upgrades

Key interfaces relevant to arc-settle:

| Function | Purpose | Gas (approx) |
|----------|---------|-------------|
| `transfer(to, amount)` | Direct transfer | ~65k |
| `transferFrom(from, to, amount)` | Transfer with prior approval | ~75k |
| `approve(spender, amount)` | Grant spending allowance | ~46k |
| `permit(owner, spender, value, deadline, v, r, s)` | EIP-2612 gasless approval | ~80k |
| `transferWithAuthorization(from, to, value, validAfter, validBefore, nonce, v, r, s)` | EIP-3009 meta-transaction | ~85k |

**Administrative controls** that arc-settle must handle:
- **Blacklisting**: USDC can blacklist addresses. Escrow contracts must validate counterparties pre-commitment and handle the case where an address is blacklisted mid-escrow.
- **Pausing**: Circle can pause all USDC transfers. Escrow contracts need timeout/recovery mechanisms.
- **Upgrades**: USDC is a proxy contract. arc-settle should reference the proxy address, not the implementation.

### 3.2 EIP-2612 Permit (Gasless Approvals)

EIP-2612 extends ERC-20 with a `permit` function that takes an EIP-712 typed signature and updates the allowance mapping. This enables:
- Users approve token spending without holding ETH
- Approval + action in a single atomic transaction
- Nonce-protected replay resistance bound to chain ID and contract address

**Relevance to arc-settle**: An agent can sign a permit off-chain, and the escrow contract can call `permit()` + `transferFrom()` in one transaction. This eliminates the two-step approve-then-transfer flow and reduces the agent's need to hold native gas tokens.

### 3.3 EIP-3009 TransferWithAuthorization

EIP-3009 goes further than EIP-2612 by enabling direct transfer via signed authorization, without a separate approval step. The signer authorizes a specific transfer (from, to, amount, time window, nonce) and any relayer can submit it.

**This is x402's settlement mechanism** and is the recommended pattern for arc-settle's basic fund movement. USDC and EURC support EIP-3009 natively.

### 3.4 Request Network

Request Network provides decentralized invoicing with an escrow feature. Funds are held until conditions are met, with a flat $2/payment fee. The Commerce Escrow module (v0.60.0) supports conditional release and recurring payments.

**Pattern**: Invoice creation -> escrow lock -> condition verification -> release or refund.

### 3.5 Superfluid (Streaming Payments)

Superfluid enables continuous per-second token streaming via Constant Flow Agreements (CFA). Fees apply only when starting/stopping streams, not for continuous flow. Any ERC-20 can be "wrapped" into a Super Token with streaming capabilities.

**Relevance to arc-settle**: Streaming payments could map to Chio's metered billing model, where tool servers charge per-unit-of-work. A Superfluid stream could back a `ToolGrant` with `max_total_cost`, with the stream rate matching the expected consumption. This is a future extension, not a v1 requirement.

### 3.6 Gnosis Pay

Gnosis Pay connects Safe smart contract wallets to Visa card rails, settling stablecoin payments at point-of-sale. It demonstrates the pattern of: smart contract wallet (custody) -> on-chain settlement -> traditional payment rail bridging.

**Relevance to arc-settle**: Gnosis Pay validates the model of smart contract wallets as settlement endpoints. Chio agents could hold funds in Safe-style wallets that arc-settle interacts with.

---

## 4. Escrow Contract Patterns

### 4.1 OpenZeppelin ConditionalEscrow

OpenZeppelin's `ConditionalEscrow` is an abstract contract that only allows withdrawal if a condition is met (defined by an overridable `withdrawalAllowed()` function). The library also provides:
- `Escrow`: Base escrow with deposit/withdraw for designated payees
- `RefundEscrow`: Escrow that can be set to refund all depositors
- `MerkleProof`: Verification of Merkle tree membership proofs

**Limitation**: OpenZeppelin's escrow contracts historically handle ETH, not ERC-20 tokens. Building an ERC-20 conditional escrow requires combining `ConditionalEscrow` logic with `IERC20.transferFrom`.

### 4.2 Kleros Escrow

Kleros provides a decentralized escrow with dispute resolution:
1. Funds locked in escrow smart contract
2. Automatic release if no dispute before timeout
3. If disputed, Kleros court jurors adjudicate
4. Smart contract enforces the ruling (ERC-792 arbitration standard)
5. Appeals supported with escalating juror panels

**Pattern for arc-settle**: The timeout-based auto-release with dispute escalation maps to Chio's credit loss lifecycle. An escrow could auto-release after the receipt window closes, with a dispute mechanism backed by Chio's underwriting decisions.

### 4.3 Conditional Release via Signed Evidence

The pattern most relevant to arc-settle:

```
1. Agent A deposits USDC into escrow contract, referencing a capability_id
2. Agent B (tool server) executes the tool call
3. ARC kernel signs a receipt (Decision::Allow + SettlementStatus::Pending)
4. Receipt evidence is submitted to the escrow contract
5. Contract verifies the evidence and releases funds to Agent B
6. If no valid receipt within the timeout, funds return to Agent A
```

This requires the escrow contract to verify receipt evidence on-chain -- the core Ed25519 challenge discussed in section 5.

### 4.4 Merkle Commitment Pattern (Recommended)

Instead of verifying individual signatures on-chain, the Chio kernel periodically publishes a Merkle root of recent receipts to the escrow contract. Claims are then verified via Merkle proof:

```
1. Kernel accumulates receipts into a Merkle tree
2. Kernel publishes root hash on-chain (single transaction, ~45k gas)
3. Claimant submits: receipt data + Merkle proof
4. Contract verifies: MerkleProof.verify(proof, root, leaf_hash)
5. Contract releases funds if leaf matches expected receipt structure
```

**Advantages**:
- No Ed25519 verification on-chain
- Amortizes gas cost across all receipts in the batch
- Merkle proof verification is ~50k gas regardless of tree size
- Compatible with Chio's existing receipt log (already Merkle-committed)

**Disadvantages**:
- Introduces latency (must wait for root publication)
- Requires the kernel operator to submit root transactions (operational burden)
- Root publisher becomes a liveness dependency

### 4.5 Bond/Slash Contract

For `CreditBond` enforcement, a bond contract:

```
1. Agent deposits collateral (CreditBondTerms.collateral_amount)
2. Contract locks funds for the bond duration (CreditBondArtifact.expires_at)
3. On normal completion (lifecycle_state == Released):
   - Collateral returned minus any settled claims
4. On impairment (lifecycle_state == Impaired):
   - Collateral slashed per the impairment terms
   - Slashed funds distributed to affected counterparties
5. On expiry with no action: collateral auto-released
```

This maps directly to Chio's existing `CreditBondDisposition` enum: `Lock`, `Hold`, `Release`, `Impair`.

---

## 5. Ed25519 on EVM (Critical Design Question)

Chio signs all receipts and capability tokens with Ed25519. The EVM natively supports only secp256k1 via the `ecrecover` precompile (3,000 gas). Verifying Ed25519 signatures on EVM is the single hardest integration challenge for arc-settle.

### 5.1 Option A: Pure Solidity Ed25519 Verification

**Implementation**: Libraries like `chengwenxi/Ed25519` implement curve arithmetic in Solidity.

**Gas cost**: ~500,000 to 1,250,000 gas per signature verification. At current L2 gas prices (~$0.01/tx for simple transfers), a single Ed25519 verification would cost $0.50-$1.25 -- orders of magnitude more expensive than the settlement amount for micro-transactions.

**Note on benchmarks**: The daimo-eth/p256-verifier project provides efficient on-chain secp256r1 (P-256) verification at ~330k gas, which led to RIP-7212 adoption. No equivalent production-grade Ed25519 Solidity library exists at a similar optimization level. The p256-verifier project (205 stars, last commit May 2024) demonstrates that precompile proposals driven by concrete gas benchmarks can gain traction -- this may be a path for Ed25519 advocacy.

**Verdict**: Impractical for production use. Only viable for very high-value settlements where the verification cost is negligible relative to the amount.

### 5.2 Option B: EIP-665 Precompile

**Specification**: Precompile at address 0x9, 2,000 gas, 128-byte input (message + pubkey + signature), 4-byte output.

**Status**: **Stagnant**. Proposed in 2018, never adopted by Ethereum mainnet. No L2 has implemented it either.

**Verdict**: Cannot depend on this. If it were adopted, it would be the ideal solution -- but there is no timeline or commitment.

### 5.3 Option C: RIP-7696 Generic DSM Precompile

**Specification**: A Rollup Improvement Proposal for generic double-scalar multiplication across multiple curves including Ed25519/Curve25519. Gas costs: 4,000 (ecMulmuladd) or 2,500 (ecMulmuladdB4).

**Status**: **Draft** as of March 2024. Precompile address TBD. Explicitly lists Ed25519 as a use case for bridges with Cosmos/Solana ecosystems.

**Verdict**: Promising but not yet implemented on any chain. Worth monitoring. If adopted by Base or Arbitrum, it would enable ~5,000 gas Ed25519 verification (DSM + hash operations).

### 5.4 Option D: ZK Proof of Ed25519 Signature

**Approach**: Generate a Groth16 (or Halo2) proof off-chain that an Ed25519 signature is valid, then verify the proof on-chain using a Solidity verifier.

**Performance** (Electron Labs' ed25519-circom):
- Circuit constraints: ~2.5M per signature
- Witness generation: ~6 seconds
- Proving time: ~6 seconds (single), ~16 minutes (99-signature batch)
- On-chain verification: ~300,000 gas (Groth16 pairing check)
- Proof size: 192 bytes (Groth16)

**Halo2 alternative**: Axiom's halo2-lib has an Ed25519 verification circuit. Halo2 avoids the trusted setup ceremony but has larger proofs.

**Batching**: A single proof can verify up to 99 signatures, making per-signature cost as low as ~3,000 gas when amortized.

**Verdict**: Technically viable but operationally complex. Requires a proving service (6-second latency per proof) and a verification contract. Best suited for batch settlement where the proving cost is amortized.

### 5.5 Option E: Dual-Signing (Recommended for v1)

**Approach**: Chio entities that need to interact with on-chain settlement maintain a secondary secp256k1 keypair alongside their primary Ed25519 keypair. The kernel signs receipts with both keys. On-chain contracts use `ecrecover` (3,000 gas) to verify the secp256k1 signature.

**Implementation**:
1. Add `settlement_key: Option<secp256k1::PublicKey>` to kernel configuration
2. When generating receipts for governed transactions with on-chain settlement, produce a secondary secp256k1 signature over `keccak256(canonical_json(receipt_body))`
3. Store the secondary signature in `receipt.metadata.settlement_signature`
4. On-chain contracts verify via `ecrecover`

**Advantages**:
- 3,000 gas verification (cheapest option)
- Battle-tested EVM primitive
- No ZK infrastructure required
- No latency beyond receipt generation

**Disadvantages**:
- Introduces a second key management concern
- The secp256k1 signature is not part of Chio's core trust model (Ed25519 remains authoritative)
- Requires trust that the entity controlling both keys is the same

**Key management complexity (understated risk)**: Dual-signing is operationally more burdensome than it appears. Every Chio kernel deployment must now provision, rotate, and back up two distinct key types with different cryptographic properties. The Ed25519 key lives in Chio's signing infrastructure; the secp256k1 key must interoperate with EVM wallet tooling (hardware wallets, HSMs, KMS). Key rotation requires updating both keys atomically -- if the Ed25519 key rotates but the binding certificate for the secp256k1 key is not refreshed, on-chain verification will fail. Operators running multiple kernels (HA configurations) must synchronize both key sets across nodes, doubling the surface area for misconfiguration. The binding certificate (Ed25519 signing a message containing the secp256k1 pubkey) must itself be stored and retrieved -- adding a third artifact to manage alongside the two keys.

**Mitigation**: The Ed25519 receipt remains the canonical proof. The secp256k1 signature is only used for on-chain evidence submission. A binding between the two keys can be established by having the Ed25519 key sign a certificate binding the secp256k1 public key, published on-chain during escrow setup.

### 5.6 Option F: Merkle Root Commitment (Recommended for batch settlement)

**Approach**: Avoid individual signature verification entirely. The kernel publishes periodic Merkle roots of receipt batches. On-chain claims use Merkle proofs (leaf inclusion), not signature verification.

**Gas cost**: ~50,000 gas for Merkle proof verification (using OpenZeppelin's `MerkleProof.verify`). Root publication: ~45,000 gas per batch.

**Advantages**:
- No Ed25519 or secp256k1 verification on-chain at all
- Gas cost independent of signature scheme
- Naturally aligns with Chio's existing Merkle-committed receipt log

**Disadvantages**:
- Requires the kernel operator to publish roots (operational dependency)
- Introduces settlement latency (wait for next root publication)
- Root publisher must be trusted or decentralized

### 5.7 Option G: Solana as Settlement Rail (Native Ed25519)

**Approach**: Use Solana instead of (or alongside) EVM for settlement. Solana has a native Ed25519 signature verification precompile program (`Ed25519SigVerify111111111111111111111111111`) that verifies Ed25519 signatures as native code within the validator, bypassing the VM entirely.

**How it works**: The Ed25519 program accepts a transaction instruction containing the count of signatures to verify, followed by offset structs pointing to the signature (64 bytes), public key (32 bytes), and message data within the transaction. If any signature fails, the entire transaction is rejected.

**Advantages**:
- Native Ed25519 verification at compute-unit cost, not hundreds of thousands of gas
- No dual-signing required -- Chio's existing Ed25519 receipts can be verified directly
- USDC is native on Solana with high liquidity
- Sub-second finality (~400ms)
- x402 already supports Solana settlement

**Disadvantages**:
- Solana's programming model (accounts, programs, PDAs) is fundamentally different from EVM
- Smaller DeFi composability ecosystem than EVM L2s for escrow patterns
- Rust-native development (positive for Chio's Rust codebase, but different toolchain from Foundry/Solidity)
- Network stability has been less consistent historically than EVM L2s

**Verdict**: Solana is the strongest alternative settlement rail specifically because it eliminates the Ed25519 challenge. For a v2 multi-chain strategy, deploying settlement programs on Solana alongside EVM escrow contracts would allow Chio to use native signatures on Solana and dual-signing/Merkle proofs on EVM, choosing the optimal path per settlement.

### 5.8 Recommended Strategy

**Phase 1 (v1)**: Dual-signing (Option E) for individual, high-value EVM settlements. Merkle root commitment (Option F) for batch settlement of micro-transactions on EVM. This combination covers all EVM settlement sizes with reasonable gas costs.

**Phase 1.5**: Evaluate Solana settlement (Option G) as a parallel rail. If the agent ecosystem on Solana is sufficient, deploy Solana programs that verify Chio Ed25519 receipts natively -- no dual-signing complexity.

**Phase 2**: If RIP-7696 is adopted by Base/Arbitrum, migrate to native Ed25519 verification on EVM. If ZK proof infrastructure matures (faster provers, lower gas), add ZK batch verification as an option.

**Phase 3**: If EIP-665 is ever adopted, it becomes the optimal EVM path at 2,000 gas.

---

## 6. Chain Selection Analysis

### 6.1 Comparison Matrix

| Factor | Base | Arbitrum | Optimism | Polygon PoS | Solana |
|--------|------|----------|----------|-------------|--------|
| **ERC-20 transfer cost** | <$0.01 | ~$0.009 | ~$0.01 | ~$0.008 | ~$0.001 |
| **Native USDC** | Yes | Yes | Yes | Yes | Yes |
| **USDC liquidity** | High ($4.3B DeFi TVL) | Highest (deep USDT/USDC) | Moderate | High ($500M+ USDC) | Very High |
| **Soft finality** | ~1s | ~260ms | ~2s | ~2s | ~400ms |
| **Hard finality** | ~12.8 min (L1) | ~12.8 min (L1) | ~12.8 min (L1) | ~2-3 min (PoS) | ~400ms (single slot) |
| **Rollup type** | Optimistic (OP Stack) | Optimistic (Nitro) | Optimistic (OP Stack) | PoS sidechain | L1 (PoH+PoS) |
| **Ed25519 support** | None (precompile needed) | None | None | None | **Native precompile** |
| **Developer tooling** | Excellent (Coinbase CDP) | Excellent (Stylus/Rust) | Good | Good | Excellent (Anchor/Rust) |
| **Agent ecosystem** | Strong (x402, Coinbase) | Growing (Virtuals) | Moderate | Moderate | Growing (x402 support) |

### 6.2 Recommendation: Base as Primary EVM, Solana as Primary Non-EVM

**Base** is the recommended primary EVM chain for arc-settle:

1. **Native USDC with Circle APIs**: Direct integration with Circle's minting/redeeming infrastructure. No bridging required.
2. **x402 ecosystem alignment**: If Chio tool servers want to offer HTTP-native billing via x402, Base is where that ecosystem lives (Coinbase facilitator, Stripe integration).
3. **Coinbase distribution**: The largest US exchange provides on/off-ramp liquidity directly to Base.
4. **Cost efficiency**: Sub-cent ERC-20 transfers make micro-settlement viable.
5. **Embedded wallets and account abstraction**: Coinbase's developer platform provides wallet infrastructure that could simplify agent key management.

**Solana** as the primary non-EVM chain:

1. **Native Ed25519**: Eliminates the entire dual-signing / ZK proof complexity. Chio receipts can be verified directly on-chain.
2. **Sub-second finality**: ~400ms slot time suits latency-sensitive tool calls.
3. **Rust-native**: Chio is a Rust project; Solana programs are written in Rust. Shared toolchain and potential code reuse.
4. **x402 support**: x402 already supports Solana, validating the agent payment use case on this chain.

**Arbitrum** as secondary EVM:

1. **Deepest DeFi liquidity**: For large settlements, Arbitrum has the most liquid markets.
2. **Fastest EVM soft finality**: ~260ms sequencer confirmation is ideal for latency-sensitive tool calls.
3. **Stylus (Rust smart contracts)**: Arbitrum's Stylus allows writing smart contracts in Rust, which could enable shared code between arc-settle and the on-chain contracts.

### 6.3 Multi-Chain Architecture

arc-settle should be chain-agnostic at the interface level:

```
CapitalExecutionRail {
    kind: OnChain,
    rail_id: "base-mainnet" | "arbitrum-one" | "solana-mainnet",
    custody_provider_id: "arc-escrow-v1",
    source_account_ref: Some("0x..." | "base58..."),  // agent wallet address
    destination_account_ref: Some("0x..." | "base58..."), // tool server wallet address
    jurisdiction: Some("eip155:8453" | "solana:mainnet"), // CAIP-2 chain ID
}
```

Note: `source_account_ref` and `destination_account_ref` are `Option<String>` in the actual `CapitalExecutionRail` struct, not required fields. The mapping above uses `Some(...)` to reflect this. The `jurisdiction` field maps naturally to CAIP-2 chain identifiers.

---

## 7. Recommended Contract Architecture

### 7.1 Contract Overview

Three core contracts, plus a registry:

```
ArcEscrow.sol          -- Conditional escrow for tool call settlement
ArcBondVault.sol       -- Collateral locking for CreditBond enforcement
ArcReceiptVerifier.sol -- Merkle root registry + proof verification
ArcSettleRegistry.sol  -- Maps ARC entity keys to on-chain addresses
```

### 7.2 ArcReceiptVerifier

The foundation contract that other contracts depend on for receipt evidence verification.

```solidity
interface IArcReceiptVerifier {
    // Operator publishes a batch of receipt Merkle roots
    function publishRoot(
        bytes32 root,
        uint256 batchTimestamp,
        uint256 receiptCount
    ) external;

    // Verify a receipt is included in a published batch
    function verifyReceipt(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 receiptHash
    ) external view returns (bool);

    // For dual-signing: verify secp256k1 signature on receipt data
    function verifySettlementSignature(
        bytes32 receiptHash,
        uint8 v, bytes32 r, bytes32 s,
        address expectedSigner
    ) external pure returns (bool);
}
```

**Root publication**: The Chio kernel operator publishes roots periodically (e.g., every 60 seconds or every 100 receipts, whichever comes first). Each root is timestamped and immutable once published.

**Operator authorization**: Only registered operators can publish roots. Operator registration requires a binding certificate (Ed25519 key signs a message containing the operator's Ethereum address, verified off-chain during registration).

### 7.3 ArcEscrow

Conditional escrow that locks USDC and releases based on receipt evidence.

```solidity
interface IArcEscrow {
    struct EscrowTerms {
        bytes32 capabilityId;    // ARC capability token ID
        address depositor;       // Agent paying for tool access
        address beneficiary;     // Tool server receiving payment
        address token;           // USDC address
        uint256 amount;          // Max settlement amount
        uint256 deadline;        // Auto-refund timestamp
        bytes32 operatorKey;     // Expected receipt signer (hashed)
    }

    // Create escrow (depositor calls after USDC approval)
    function createEscrow(EscrowTerms calldata terms) external returns (bytes32 escrowId);

    // Release via Merkle proof (batch settlement)
    function releaseWithProof(
        bytes32 escrowId,
        bytes32[] calldata proof,
        bytes32 root,
        bytes calldata receiptData,
        uint256 settledAmount
    ) external;

    // Release via dual-sign (individual settlement)
    function releaseWithSignature(
        bytes32 escrowId,
        bytes calldata receiptData,
        uint256 settledAmount,
        uint8 v, bytes32 r, bytes32 s
    ) external;

    // Refund after deadline (if no valid release)
    function refund(bytes32 escrowId) external;

    // Partial release for metered billing
    function partialRelease(
        bytes32 escrowId,
        uint256 amount,
        bytes calldata evidence
    ) external;
}
```

**EIP-3009 variant**: For gasless escrow creation, a `createEscrowWithAuthorization` function accepts a signed `TransferWithAuthorization` from the depositor, combining deposit + escrow creation in one call.

**EIP-2612 variant**: A `createEscrowWithPermit` function accepts a permit signature, calls `permit()` then `transferFrom()` in one transaction.

### 7.4 ArcBondVault

Collateral locking for `CreditBond` enforcement.

```solidity
interface IArcBondVault {
    struct BondTerms {
        bytes32 bondId;           // ARC CreditBond ID
        bytes32 facilityId;       // Associated credit facility
        address principal;        // Bond holder (agent)
        address token;            // Collateral token (USDC)
        uint256 collateralAmount; // CreditBondTerms.collateral_amount
        uint256 reserveAmount;    // CreditBondTerms.reserve_requirement_amount
        uint256 expiresAt;        // Bond expiration timestamp
        uint16 reserveRatioBps;   // Basis points
    }

    function lockBond(BondTerms calldata terms) external returns (bytes32 vaultId);

    // Release collateral (normal completion)
    function releaseBond(bytes32 vaultId, bytes calldata evidence) external;

    // Impair (slash) collateral
    function impairBond(
        bytes32 vaultId,
        uint256 slashAmount,
        address[] calldata beneficiaries,
        uint256[] calldata shares,
        bytes calldata evidence
    ) external;

    // Auto-release after expiry with no impairment
    function expireRelease(bytes32 vaultId) external;
}
```

### 7.5 ArcSettleRegistry

Maps Chio identities to Ethereum addresses and manages operator authorization.

```solidity
interface IArcSettleRegistry {
    // Register an ARC entity's settlement address
    // (requires off-chain verification of Ed25519 key binding)
    function registerEntity(
        bytes32 arcEntityId,
        address settlementAddress,
        bytes calldata bindingProof
    ) external;

    // Register a kernel operator authorized to publish roots
    function registerOperator(
        address operatorAddress,
        bytes calldata operatorCertificate
    ) external;

    function getSettlementAddress(bytes32 arcEntityId) external view returns (address);
    function isAuthorizedOperator(address operator) external view returns (bool);
}
```

### 7.6 Gas Cost Estimates

| Operation | Estimated Gas | Cost at $0.01/transfer (Base L2) |
|-----------|-------------|----------------------|
| Escrow creation | ~120k | ~$0.02 |
| Release with Merkle proof | ~80k | ~$0.01 |
| Release with ecrecover | ~60k | ~$0.01 |
| Merkle root publication | ~45k | ~$0.007 |
| Bond lock | ~100k | ~$0.015 |
| Bond release | ~70k | ~$0.01 |
| Bond impairment | ~150k | ~$0.02 |

**Gas estimate methodology note**: These estimates assume Base L2 gas pricing at 2025-2026 levels. They are order-of-magnitude estimates based on comparable DeFi operations (Uniswap V3 swaps ~150k gas, Aave deposits ~200k gas). Actual costs will vary based on: (a) contract implementation complexity (storage slot usage, event emission), (b) L1 data posting costs (which fluctuate with Ethereum mainnet congestion), and (c) whether the contract uses upgradeable proxy patterns (which add ~2.5k gas per delegatecall). The "$0.01/transfer" column uses the Base L2 gas price as of early 2026; L1 data costs are typically 60-80% of total L2 transaction cost and can spike during high Ethereum mainnet activity.

These costs are viable for settlements above ~$0.10. For true micro-payments (sub-cent), the Merkle batch approach amortizes root publication across many settlements. **For sub-cent settlements, Circle Gateway Nanopayments may be more cost-effective than custom escrow** -- see section 2.8.

---

## 8. Rust Ecosystem for EVM

### 8.1 Alloy (Recommended)

**Alloy** (v1.0, released May 2025) is the successor to ethers-rs and the clear choice for new Rust EVM projects.

**Key features**:
- `sol!` macro: Compile-time Solidity parser generating type-safe Rust bindings. Replaces ethers-rs's `abigen`.
- Provider system: Generic providers (static dispatch for libraries) and `DynProvider` (type erasure for applications). Supports HTTP, WebSocket, and IPC transports.
- Performance: 35-60% faster U256 arithmetic than ethers-rs. Static ABI encoding up to 10x faster.
- Multi-chain: Generic over the `Network` trait. Ships with Ethereum defaults, extensible via `op-alloy` for OP Stack chains.
- Multicall: Explicit batching and transparent `CallBatchLayer` for RPC call aggregation.

**Adoption**: Powers Foundry, Reth, Arbitrum Stylus, OP Kona.

**Example usage for arc-settle**:

```rust
use alloy::sol;

sol! {
    #[sol(rpc)]
    interface IArcEscrow {
        function createEscrow(EscrowTerms calldata terms) external returns (bytes32);
        function releaseWithProof(
            bytes32 escrowId,
            bytes32[] calldata proof,
            bytes32 root,
            bytes calldata receiptData,
            uint256 settledAmount
        ) external;
    }
}
```

### 8.2 ethers-rs (Deprecated)

ethers-rs has been officially deprecated. All users are directed to migrate to Alloy. No new features or security fixes.

### 8.3 Supporting Crates

| Crate | Purpose | Status |
|-------|---------|--------|
| `alloy` | Core EVM interaction | Stable v1.0 |
| `alloy-core` | Primitives (U256, Address, Bytes) | Stable |
| `op-alloy` | OP Stack extensions (Base, Optimism) | Active |
| `foundry-rs` | Testing and deployment tooling | Active |
| `revm` | EVM implementation in Rust (for local testing) | Active |
| `k256` | secp256k1 operations (for dual-signing) | Stable |
| `solana-sdk` | Solana program interaction | Stable |
| `anchor-lang` | Solana program framework (if writing Solana programs) | Stable |

### 8.4 arc-settle Crate Structure

```
crates/arc-settle/
  src/
    lib.rs              -- Public API: settle(), lock_bond(), publish_root()
    client.rs           -- Alloy provider management, chain connection
    escrow.rs           -- ArcEscrow contract interactions
    bond.rs             -- ArcBondVault contract interactions
    verifier.rs         -- ArcReceiptVerifier interactions
    registry.rs         -- ArcSettleRegistry interactions
    merkle.rs           -- Merkle tree construction for receipt batches
    dual_sign.rs        -- secp256k1 secondary signature generation
    types.rs            -- On-chain type mappings to/from arc-core types
    error.rs            -- Settlement-specific errors
    reconcile.rs        -- On-chain event monitoring and state reconciliation
    revert.rs           -- Settlement failure handling and recovery
  Cargo.toml
```

Dependencies:
```toml
[dependencies]
arc-core = { path = "../arc-core" }
alloy = { version = "1.0", features = ["full"] }
op-alloy = { version = "0.x" }
k256 = "0.13"
```

---

## 9. Integration Points with Chio's Economic Layer

### 9.1 CapitalExecutionRailKind Extension

Add a new variant to the existing enum:

```rust
pub enum CapitalExecutionRailKind {
    Manual,
    Api,
    Ach,
    Wire,
    Ledger,
    Sandbox,
    OnChain,  // NEW: EVM/Solana smart contract settlement
}
```

### 9.2 CapitalExecutionRail Mapping

The existing `CapitalExecutionRail` struct maps directly:

| Chio field | On-chain meaning | Code note |
|-----------|-----------------|-----------|
| `kind` | `OnChain` | New variant |
| `rail_id` | Contract address (e.g., ArcEscrow deployment) | `String` |
| `custody_provider_id` | "arc-settle-v1" | `String` |
| `source_account_ref` | Depositor wallet address | `Option<String>` -- may be None if determined at execution time |
| `destination_account_ref` | Beneficiary wallet address | `Option<String>` -- may be None if determined at execution time |
| `jurisdiction` | CAIP-2 chain identifier (e.g., "eip155:8453", "solana:mainnet") | `Option<String>` |

### 9.3 CapitalExecutionInstruction Flow

The existing `CapitalExecutionInstructionAction` enum maps to on-chain operations:

| Chio Action | On-chain Operation |
|-----------|-------------------|
| `LockReserve` | `ArcEscrow.createEscrow()` or `ArcBondVault.lockBond()` |
| `HoldReserve` | No-op (funds already locked on-chain) |
| `ReleaseReserve` | `ArcEscrow.releaseWithProof()` or `ArcBondVault.releaseBond()` |
| `TransferFunds` | `ArcEscrow.releaseWithSignature()` (immediate transfer) |
| `CancelInstruction` | `ArcEscrow.refund()` |

### 9.4 SettlementStatus Integration

The existing `SettlementStatus` enum on receipts tracks on-chain state:

| SettlementStatus | On-chain state |
|-----------------|---------------|
| `NotApplicable` | No on-chain settlement for this receipt |
| `Pending` | Escrow created, awaiting release |
| `Settled` | Funds released on-chain (tx confirmed) |
| `Failed` | On-chain transaction reverted |

Note: The current `SettlementStatus` enum has exactly four variants: `NotApplicable`, `Pending`, `Settled`, and `Failed`. There is no `Reconciled` variant. Off-chain reconciliation that confirms on-chain state is tracked via `ExposureLedgerEvidenceKind::SettlementReconciliation` evidence references on the exposure ledger, not as a separate settlement status. If a `Reconciled` status is needed for arc-settle, it would require an arc-core schema change.

### 9.5 CreditBond Lifecycle Mapping

| CreditBondLifecycleState | ArcBondVault action |
|--------------------------|-------------------|
| `Active` | `lockBond()` -- collateral locked |
| `Superseded` | Lock new bond, release old |
| `Released` | `releaseBond()` -- collateral returned |
| `Impaired` | `impairBond()` -- collateral slashed |
| `Expired` | `expireRelease()` -- auto-return |

### 9.6 MonetaryAmount Currency Mapping

Chio's `MonetaryAmount.currency` maps to on-chain tokens:

| Chio currency | On-chain token | Chain |
|-------------|---------------|-------|
| "USD" | USDC | Base/Arbitrum/Polygon/Solana |
| "EUR" | EURC | Base |
| "USDC" | USDC (explicit) | Base/Arbitrum/Polygon/Solana |

The `MonetaryAmount.units` field (u64, minor units) maps to ERC-20 amounts. Per the code comment in `capability.rs`, `MonetaryAmount.units` represents "amount in the currency's smallest unit (e.g. cents for USD)". USDC on-chain uses 6 decimal places (1 USD = 1,000,000 micro-units). arc-settle must handle this conversion: `on_chain_amount = arc_units * 10_000` for USD-denominated amounts where Chio uses cents.

**Important**: This conversion factor is currency-specific and must be configurable. If Chio later changes its minor-unit convention (e.g., using micro-dollars natively), this conversion would break. arc-settle should define an explicit `CurrencyDecimals` configuration mapping rather than hardcoding `10_000`.

### 9.7 Exposure Ledger Integration

The existing `ExposureLedgerCurrencyPosition` tracks settlement state that arc-settle observes:

- `reserved_units` -- funds locked in on-chain escrow
- `settled_units` -- funds released on-chain
- `pending_units` -- escrow created, release pending
- `failed_units` -- on-chain transaction reverted
- `provisional_loss_units` -- bond impairment pending

arc-settle provides a reconciliation service that polls on-chain state and updates the exposure ledger via `SettlementReconciliation` evidence references.

### 9.8 Underwriting Integration

The underwriting system already tracks settlement health:
- `UnderwritingReasonCode::PendingSettlementExposure` -- raised when on-chain settlements are delayed
- `UnderwritingReasonCode::FailedSettlementExposure` -- raised when on-chain transactions revert
- `UnderwritingEvidenceKind::SettlementReconciliation` -- arc-settle publishes reconciliation evidence

### 9.9 Market Layer Integration

The liability market layer already has settlement instruction/receipt artifacts:
- `LIABILITY_CLAIM_SETTLEMENT_INSTRUCTION_ARTIFACT_SCHEMA` -- directs on-chain settlement for claim payouts
- `LIABILITY_CLAIM_SETTLEMENT_RECEIPT_ARTIFACT_SCHEMA` -- records on-chain settlement confirmation

---

## 10. Account Abstraction and Gas Management

### 10.1 ERC-4337 Account Abstraction

ERC-4337 defines account abstraction without consensus-layer protocol changes. It introduces UserOperations (structured intents), an EntryPoint contract, smart contract accounts, and Paymasters. Key components:

- **UserOperation**: A struct containing sender, nonce, calldata, gas limits, and signature. Unlike traditional transactions, UserOperations are signed by the smart account's custom validation logic, not restricted to secp256k1.
- **EntryPoint**: A singleton contract that validates and executes UserOperations.
- **Smart Contract Account**: Implements `validateUserOp()` -- can use any signature scheme, including Ed25519 with a custom validation module.
- **Paymaster**: A third-party contract that sponsors gas for UserOperations, allowing agents to transact without holding ETH.

**Relevance to arc-settle**: ERC-4337 addresses two arc-settle challenges:

1. **Custom signature validation**: A smart contract account could implement Ed25519 validation in its `validateUserOp()` function. While this moves the gas cost to account validation rather than escrow verification, it consolidates signature verification at the account level. Combined with ERC-4337 bundlers batching multiple UserOperations, this could amortize Ed25519 gas costs.

2. **Gas sponsorship via Paymasters**: Agents do not need to hold ETH. An Chio operator (or the tool server) can deploy a Paymaster that pays gas in exchange for USDC deduction from the escrow. This aligns with Chio's economic model: the agent's `MonetaryAmount` budget covers all costs, including gas.

**Implementation pattern for Chio agents**:
- Each Chio agent identity maps to a smart contract account (Safe, Kernel, or custom)
- The account validates UserOperations using the agent's Ed25519 key (via a validation module)
- A Paymaster contract accepts USDC payment for gas sponsorship
- arc-settle submits settlement actions as UserOperations rather than raw transactions

### 10.2 Safe{Core} Protocol for Agent Wallets

Safe (formerly Gnosis Safe) provides modular smart account infrastructure with:
- Multi-signature and threshold schemes
- Custom validation modules (could support Ed25519)
- Guard contracts that can enforce spending policies
- Transaction execution with delegatecall for composability

An Chio agent could use a Safe as its on-chain wallet, with:
- A custom guard module enforcing Chio capability constraints (spending limits, tool-server whitelists)
- The Safe's module system enabling arc-settle to execute settlement transactions on behalf of the agent
- Recovery mechanisms via social recovery or the Chio operator

### 10.3 Intent-Based Settlement

Intent-based architectures (CoW Protocol, UniswapX) offer a pattern relevant to arc-settle:

- **CoW Protocol**: Users sign "intent to trade" messages rather than raw transactions. Professional solvers compete to find optimal execution paths. Benefits include MEV protection (solvers absorb MEV risk), batch settlement at uniform clearing prices, and gas abstraction (users pay fees in sell tokens, not ETH).

- **Relevance to arc-settle**: Chio's `CapitalExecutionInstruction` is already an intent -- it specifies what should happen (lock, release, transfer) without specifying exactly how. arc-settle could translate these intents to on-chain execution via a solver network rather than direct contract calls. Benefits: (a) MEV protection for settlement transactions, (b) gas optimization via batching, (c) cross-chain settlement via solver routing. This is a v2+ consideration, not v1.

---

## 11. Recommended Architecture

### 11.1 High-Level Architecture

```
+------------------+     +------------------+     +------------------+
|   ARC Kernel     |     |   arc-settle     |     |   EVM Chain      |
|                  |     |   (Rust crate)   |     |   (Base/Arb)     |
|  Receipt signing +---->+ Instruction      +---->+ ArcEscrow.sol    |
|  Budget enforce  |     |   translation    |     | ArcBondVault.sol |
|  Merkle tree     +---->+ Root publication +---->+ ArcVerifier.sol  |
|                  |     |   Reconciliation |<----+ Events/Logs      |
+------------------+     +------------------+     +------------------+
                                |
                                v (optional, Phase 1.5)
                          +------------------+
                          |   Solana         |
                          |   (native Ed25519)|
                          |   ArcEscrow.rs   |
                          +------------------+
```

### 11.2 Settlement Flows

**Flow A: Pre-funded Escrow (high-value tool calls)**

1. Operator or agent creates escrow via `ArcEscrow.createEscrow()` with USDC
2. Chio kernel processes tool call, signs receipt with Decision::Allow
3. Kernel produces secp256k1 dual-signature on receipt
4. Tool server (or relayer) calls `ArcEscrow.releaseWithSignature()`
5. USDC transferred to tool server's address
6. arc-settle updates `SettlementStatus` to `Settled` in Chio receipt store

**Flow B: Batch Merkle Settlement (micro-transactions)**

1. Multiple tool calls execute with monetary budgets
2. Chio kernel accumulates receipts into a Merkle tree
3. Kernel operator publishes Merkle root via `ArcReceiptVerifier.publishRoot()`
4. Individual claimants submit Merkle proofs to `ArcEscrow.releaseWithProof()`
5. Or: a settlement service batch-processes all claims in one round

**Flow C: Bond Collateral Lifecycle**

1. Agent locks collateral via `ArcBondVault.lockBond()` per `CreditBondTerms`
2. Tool execution proceeds with the bond as backing
3. On normal completion: `ArcBondVault.releaseBond()` returns collateral
4. On loss event: `ArcBondVault.impairBond()` slashes per loss lifecycle
5. Bond state changes reflected in Chio's `CreditBondLifecycleState`

### 11.3 Key Design Decisions

1. **Stablecoin-first**: USDC is the primary settlement token. No native cryptocurrency exposure for agents.
2. **Dual verification**: secp256k1 for individual settlements, Merkle proofs for batch settlement.
3. **Fail-closed on-chain**: If the escrow contract cannot verify evidence, funds remain locked (not released). Timeout-based refund is the safety net.
4. **Kernel is the root of trust**: On-chain contracts verify evidence produced by the kernel. The kernel's Ed25519 identity remains authoritative; on-chain verification is a secondary attestation.
5. **Chain-agnostic interface**: arc-settle's Rust API is parametric over chain. Deploying to a new chain requires only contract deployment and configuration.

### 11.4 What arc-settle Does NOT Do

- **Custody**: arc-settle does not hold private keys for agents. Agents manage their own wallets. arc-settle provides the contract interaction layer.
- **Price feeds**: arc-settle does not provide exchange rates or token pricing. Chio's monetary amounts are denominated in specific currencies; the on-chain contracts settle in the corresponding stablecoin. Cross-currency conversion is the responsibility of arc-link.
- **Bridging**: arc-settle does not bridge funds between chains. Cross-chain settlement via CCTP (Circle) or CCIP (Chainlink) is a future concern.
- **Gas management**: arc-settle submits transactions but does not manage gas token (ETH) balances. Operators need gas; agents can use EIP-3009/EIP-2612 for gasless token operations. ERC-4337 Paymasters are the recommended path for full gas abstraction.

---

## 12. Security Analysis

### 12.1 MEV and Frontrunning Risks

Settlement transactions on public blockchains are visible in the mempool before confirmation. This creates several attack vectors:

**Frontrunning escrow release**: An attacker observing a `releaseWithSignature` transaction in the mempool could extract the receipt signature and submit their own release transaction with a higher gas price. **Mitigation**: The escrow contract must verify that `msg.sender` is authorized (beneficiary or registered relayer), not just that the signature is valid. Additionally, using Flashbots Protect or similar private mempool services on L2s prevents transaction visibility.

**Sandwich attacks on bond liquidation**: If bond impairment involves swapping collateral, an attacker could sandwich the swap. **Mitigation**: Bond impairment in arc-settle distributes USDC directly to beneficiaries, not via DEX swaps. No swap-based MEV exposure.

**Merkle root frontrunning**: An attacker who observes a root publication transaction could attempt to submit a fraudulent root before the legitimate one. **Mitigation**: Only registered operators can publish roots (access control on `ArcReceiptVerifier`). Use private submission channels (Flashbots) for root publication.

**Sequencer-level MEV on L2**: L2 sequencers (Base, Arbitrum) have the ability to reorder transactions. For arc-settle, the primary risk is the sequencer delaying or reordering settlement transactions. **Mitigation**: Chio's fail-closed design means that delays do not cause fund loss -- funds remain in escrow until a valid release or timeout. Sequencer censorship resistance is an L2-level concern that arc-settle cannot solve unilaterally.

### 12.2 Settlement Failure and Revert Handling

On-chain transactions can fail for multiple reasons. arc-settle must handle each:

**Transaction revert**: The EVM transaction executes but reverts (e.g., insufficient escrow balance, expired deadline, blacklisted address). arc-settle must:
1. Detect the revert via Alloy's transaction receipt (status = 0)
2. Parse the revert reason from returndata
3. Update `SettlementStatus` to `Failed` in the Chio receipt store
4. Emit an `UnderwritingReasonCode::FailedSettlementExposure` signal
5. Retry if the failure is transient (gas estimation, nonce collision) with exponential backoff
6. Escalate to operator alert if retries are exhausted

**Transaction not mined**: The transaction is submitted but never included in a block (gas too low, sequencer congestion). arc-settle must:
1. Monitor transaction status with a configurable timeout (e.g., 5 minutes)
2. If not mined within timeout, resubmit with higher gas or via a different RPC endpoint
3. Use nonce management to prevent double-settlement (if the original tx eventually mines)

**Chain reorganization**: On optimistic rollups, the sequencer can reorg recent blocks. For settlement below a configurable threshold, accept soft finality. For high-value settlements, wait for L1 confirmation (~12.8 min) before updating `SettlementStatus` to `Settled`. Implement a `SettlementConfirmationPolicy`:
```
Low value (<$10):    Accept after 1 L2 confirmation
Medium value ($10-$1000): Accept after sequencer finality (~1-2 seconds)
High value (>$1000): Wait for L1 finality (~12.8 minutes)
```

**Escrow timeout without release**: If the deadline passes without a valid release, anyone can call `refund()`. arc-settle should monitor escrow deadlines and automatically trigger refunds for expired escrows to prevent funds from being locked indefinitely (the contract allows anyone to call `refund()` after deadline, but automatic monitoring ensures timely recovery).

**Partial failure in batch settlement**: When processing a batch of Merkle proof releases, some may succeed and others fail. arc-settle must track per-receipt settlement status and not treat batch failure as atomic -- successful releases should be recorded even if others in the batch fail.

### 12.3 USDC Blacklisting and Regulatory Freeze Risk

USDC's administrative controls create risks unique to regulated stablecoins:

- **Mid-escrow blacklisting**: If Circle blacklists an escrow participant's address after funds are deposited, the escrow contract cannot transfer USDC to or from that address. Funds become permanently stuck. **Mitigation**: (a) Pre-flight blacklist check before escrow creation via USDC's `isBlacklisted()` view function, (b) operator-controlled recovery address as a fallback beneficiary in escrow terms, (c) time-limited escrows to bound exposure duration.

- **Global USDC pause**: Circle can pause all USDC transfers. During a pause, all escrow operations (create, release, refund) fail. **Mitigation**: arc-settle should detect paused state via USDC's `paused()` view function and queue operations for retry once unpaused, with operator alerting.

- **Proxy upgrade risk**: USDC is an upgradeable proxy contract. A malicious or buggy upgrade could change transfer behavior. **Mitigation**: arc-settle should always reference the proxy address and test against the current implementation. Monitor Circle's upgrade announcements.

---

## 13. Regulatory Considerations

### 13.1 Money Transmission

Operating an escrow service that holds user funds and facilitates transfers may constitute money transmission under US federal law (FinCEN) and state money transmitter licensing regimes. Key questions:

- **Who is the money transmitter?** If the Chio operator controls the escrow contract's admin keys and can direct fund releases, the operator may be classified as a money transmitter. If the smart contract is fully autonomous (no admin control, deterministic release based on receipt evidence), the analysis may differ, but regulators have not issued clear guidance on autonomous smart contract escrow.

- **State licensing**: 49 US states (all except Montana) require money transmitter licenses. Multi-state licensing is a significant operational burden (12-18 months, $500k+ in compliance costs).

- **Exemptions to evaluate**: (a) Agent-of-the-payee exemption (the escrow acts as agent of the tool server receiving payment), (b) payment processor exemption (if arc-settle only facilitates payments between identified parties), (c) smart contract exemption (no clear precedent).

- **International**: EU's MiCA regulation, UK's FCA e-money regime, and Singapore's MAS Payment Services Act all have analogous requirements for custodial services.

**Recommendation**: arc-settle's v1 should be designed so that the operator never takes custody of funds -- the escrow contract is the custodian, and release is deterministic based on cryptographic evidence. This non-custodial architecture provides the strongest argument against money transmitter classification. Legal review is required before production deployment.

### 13.2 Securities Law Implications of Bonding

`CreditBond` collateral locking may create instruments that could be classified as securities under US law:

- **Investment contract (Howey test)**: If agents lock collateral with the expectation of profit (e.g., earning yield on escrowed funds, or the collateral appreciating in value), the bond could be an investment contract. **Mitigation**: arc-settle bonds should use stablecoins (no appreciation expectation) and should not generate yield by default (see section 14, question 9 on yield-bearing escrow).

- **Note (Reves test)**: If the bond resembles a promissory note (promise to return funds at a future date plus interest), it may be a security. **Mitigation**: CreditBond collateral is returned at par (no interest), which helps avoid note classification.

- **Commodity interest**: CFTC may assert jurisdiction if the bonding arrangement involves speculation on digital asset prices.

**Recommendation**: CreditBond on-chain enforcement should be designed as a pure collateral lock with at-par return, no yield, and no secondary market. This minimizes securities law risk. Legal review required.

### 13.3 Sanctions Compliance

OFAC (Office of Foreign Assets Control) sanctions apply to on-chain transactions. arc-settle must:
- Screen counterparty addresses against OFAC SDN (Specially Designated Nationals) list
- Monitor for addresses associated with sanctioned entities (Chainalysis, TRM Labs APIs)
- Implement address screening before escrow creation and bond locking
- Handle the case where an address is added to the sanctions list mid-escrow (similar to USDC blacklisting)

---

## 14. Open Questions

### 14.1 Operational

1. **Who publishes Merkle roots?** The kernel operator is the natural candidate, but this creates a single point of liveness failure. Options: (a) operator publishes, (b) decentralized set of root publishers with threshold agreement, (c) Chainlink Automation for scheduled publication.

2. **Gas sponsorship**: Should arc-settle sponsor gas for agents, or require agents to hold ETH? ERC-4337 Paymasters are the recommended approach -- they allow USDC-denominated gas payment, aligning with Chio's stablecoin-first model. The Paymaster can deduct gas costs from the escrow balance.

3. **Escrow sizing**: For pre-funded escrow, how should the escrow amount relate to `max_total_cost`? Options: (a) escrow the full `max_total_cost` upfront, (b) escrow a rolling window amount, (c) escrow per-invocation amounts.

### 14.2 Security

4. **Dual-key binding**: How to prove that an Ed25519 key and a secp256k1 key belong to the same entity? Options: (a) Ed25519 signs a certificate containing the secp256k1 pubkey, verified off-chain at registration, (b) on-chain registry with governance controls, (c) both.

5. **USDC blacklisting**: If an escrow participant's address is blacklisted by Circle mid-escrow, funds are permanently stuck in the contract. Mitigation: time-limited escrows with fallback to an operator-controlled recovery address. See also section 12.3.

6. **Reorg risk**: On optimistic rollups, a sequencer reorg could revert a settlement. For amounts above a threshold, should arc-settle wait for L1 finality (~12.8 min)? See section 12.2 for a proposed `SettlementConfirmationPolicy`.

### 14.3 Economic

7. **Settlement fee model**: Should arc-settle charge a fee? Options: (a) free (operator absorbs gas costs), (b) percentage-based fee deducted from settlement, (c) flat per-settlement fee.

8. **Multi-token support**: Should arc-settle support tokens beyond USDC? DAI (decentralized, no blacklisting risk) and EURC (euro settlements) are natural candidates.

9. **Yield on escrowed funds**: Escrowed USDC sitting in a contract earns nothing. Should the escrow contract deposit into a yield-bearing vault (e.g., Aave, Morpho) during the escrow period? This adds smart contract risk but could offset gas costs. **Regulatory note**: yield-bearing escrow may trigger securities classification -- see section 13.2.

### 14.4 Technical

10. **Contract upgradeability**: Should the settlement contracts be upgradeable (proxy pattern) or immutable? Upgradeability adds flexibility but introduces trust assumptions. Recommendation: upgradeable with a timelock and multisig governance.

11. **Event-driven reconciliation**: arc-settle needs to observe on-chain events (EscrowCreated, FundsReleased, BondImpaired) and update Chio's internal state. Options: (a) poll via Alloy provider, (b) subscribe to events via WebSocket, (c) use an indexer (The Graph, Goldsky).

12. **Testing strategy**: Foundry for Solidity contract testing. Alloy + revm for Rust integration testing against a local EVM. Anvil (from Foundry) for forked mainnet testing.

13. **Deployment pipeline**: Contracts need to be deployed once per chain and registered in the ArcSettleRegistry. The deployment addresses become part of arc-settle's configuration. Deterministic deployment (CREATE2) ensures the same address across all chains.

### 14.5 Protocol Evolution

14. **x402 compatibility surface**: Should Chio tool servers optionally support x402's HTTP 402 flow? This would let any x402 client pay for Chio tool access without understanding Chio's full capability model. The tool server would translate x402 payment into a Chio governed transaction.

15. **Superfluid streaming integration**: For long-running metered tool access (e.g., GPU compute), a Superfluid stream could provide continuous settlement without individual transactions per invocation. This maps to `ToolGrant` with `max_total_cost` backed by a stream rate.

16. **Cross-chain settlement**: If an agent on Base needs to pay a tool server on Arbitrum, how does settlement work? Options: (a) require both parties on same chain, (b) use Circle CCTP for cross-chain USDC transfer (burn on source, mint on destination -- permissionless protocol with Fast Transfer option), (c) use Chainlink CCIP, (d) use Circle Gateway for chain-abstracted unified balance. CCTP is the recommended approach for v2 as it provides native USDC movement without bridge risk.

17. **Circle Gateway Nanopayments integration**: For micro-settlement below $0.10, should arc-settle delegate to Nanopayments rather than custom escrow? This trades self-sovereignty for operational simplicity and cost efficiency. Evaluate based on production volume patterns.

---

## 15. Cross-Integration Dependencies

This section maps how arc-settle interacts with the two companion research crates: arc-anchor (blockchain anchoring for receipt tamper-evidence) and arc-link (Chainlink/oracle integration for cross-currency budget enforcement and cross-chain operations).

### 15.1 arc-settle and arc-anchor

**Shared infrastructure**: Both arc-settle and arc-anchor publish data to EVM L2 chains. They share:
- The Alloy-based Rust client for chain interaction
- Operator key management (the same Ethereum address may publish both Merkle roots for anchoring and Merkle roots for settlement)
- Gas management infrastructure (same ETH balance funds both)

**Merkle root convergence**: arc-anchor publishes `KernelCheckpoint` Merkle roots to an `ArcAnchorRegistry` contract for tamper-evidence. arc-settle publishes receipt Merkle roots to an `ArcReceiptVerifier` contract for settlement claims. These are conceptually the same Merkle tree -- the receipt log is both the audit trail (arc-anchor) and the settlement evidence (arc-settle).

**Recommended integration**: A single Merkle root publication should serve both purposes. The `ArcReceiptVerifier` contract used by arc-settle should be the same contract (or a compatible superset) as the `ArcAnchorRegistry` used by arc-anchor. This avoids:
- Double gas costs for publishing the same root to two contracts
- Divergence between the anchored root and the settlement root
- Separate operator registration flows

The combined contract would be deployed once per chain and shared by both crates. arc-anchor provides tamper-evidence semantics (any third party can verify receipt inclusion); arc-settle adds settlement semantics (escrow release gated on receipt inclusion proof against the same root).

**Sequencing dependency**: arc-anchor can operate independently of arc-settle (anchoring is useful even without on-chain settlement). arc-settle depends on a root publication mechanism that arc-anchor also needs. Build arc-anchor's root publication first, then arc-settle consumes the published roots.

**Chain selection alignment**: Both documents recommend Base as the primary L2 target. Deploying the shared root registry on Base first, with Arbitrum as secondary, aligns both crates.

### 15.2 arc-settle and arc-link

**Price feeds for settlement**: arc-link provides the `PriceOracle` trait for cross-currency budget enforcement. arc-settle needs price data in one specific scenario: when the escrow amount (USDC) must be derived from a Chio `MonetaryAmount` denominated in a different currency (e.g., EUR -> USDC conversion). arc-settle should consume arc-link's price cache for this conversion rather than implementing its own oracle integration.

**Cross-chain settlement via CCIP**: arc-link researches Chainlink CCIP for cross-chain delegation transport. The same CCIP infrastructure could support cross-chain settlement: an escrow on Base releases funds, and CCIP transfers the USDC to the beneficiary on Arbitrum. arc-link's CCIP integration would be the transport layer; arc-settle would be the settlement logic that triggers it.

**Chainlink Functions for Ed25519 verification**: arc-link documents the possibility of using Chainlink Functions to run Ed25519 verification off-chain (via `@noble/ed25519` in the Deno sandbox) and report results on-chain. This is an alternative to arc-settle's dual-signing approach for on-chain receipt verification. The tradeoff is: dual-signing has no DON trust dependency but adds key management complexity; Chainlink Functions has a DON trust dependency but avoids a second key. For v1, dual-signing is recommended (no external dependency); Chainlink Functions can be added as an alternative verification path in v2.

**Chainlink Automation for settlement triggers**: arc-link documents Chainlink Automation for periodic Merkle root anchoring. The same Automation infrastructure could trigger:
- Periodic batch settlement processing (execute all pending Merkle proof releases)
- Escrow deadline monitoring (trigger refunds for expired escrows)
- Bond expiry processing (trigger `expireRelease` for matured bonds)

**L2 Sequencer Uptime Feeds**: arc-link documents Chainlink's L2 Sequencer Uptime Feeds. arc-settle should check sequencer uptime before submitting settlement transactions on L2 chains, using the same feed infrastructure that arc-link uses for price staleness detection.

### 15.3 Three-Crate Dependency Graph

```
arc-link (oracles, CCIP, Automation)
    |
    +-- provides: PriceOracle, CCIP transport, Automation triggers
    |
    v
arc-settle (settlement logic)
    |
    +-- provides: escrow management, bond vault, settlement flows
    +-- consumes: arc-link prices, arc-anchor Merkle roots
    |
    v
arc-anchor (tamper-evidence anchoring)
    |
    +-- provides: Merkle root publication, receipt inclusion proofs
    +-- shares: root registry contract with arc-settle
```

**Build order recommendation**: (1) arc-anchor (simplest -- just root publication), (2) arc-link (price feeds needed by kernel and arc-settle), (3) arc-settle (depends on both).

---

## 16. Reviewer Notes

This section documents changes made during the technical review of the original research document.

### 16.1 Factual Corrections

1. **SettlementStatus::Reconciled removed from section 9.4.** The original document listed `Reconciled` as a variant of `SettlementStatus`. The actual code in `crates/arc-core/src/receipt.rs` defines exactly four variants: `NotApplicable`, `Pending`, `Settled`, `Failed`. There is no `Reconciled` variant. Off-chain reconciliation is tracked via `ExposureLedgerEvidenceKind::SettlementReconciliation` evidence references, not as a receipt settlement status.

2. **CapitalExecutionRail field optionality noted in section 9.2.** The original document mapped `source_account_ref` and `destination_account_ref` as if they were required fields. In the actual `CapitalExecutionRail` struct, both are `Option<String>`. The mapping table now reflects this.

3. **MonetaryAmount.units convention clarified in section 9.6.** Added explicit reference to the code comment in `capability.rs` (line 168: "Amount in the currency's smallest unit (e.g. cents for USD)") and noted the risk of hardcoding the USDC conversion factor.

4. **x402 details updated in section 2.1.** The original document described x402 as co-founded by Coinbase and Cloudflare via an "x402 Foundation." Research shows x402 is hosted under github.com/coinbase/x402 (not a separate foundation repository). Updated supported chains to include Solana, Aptos, and Stellar based on the actual repository's e2e test configurations and commit history.

### 16.2 New Sections Added

5. **Section 2.8 (Circle Gateway Nanopayments)**: Added coverage of Circle's Nanopayments product, which directly competes with custom escrow for sub-cent agent settlements. This was a significant gap -- the original document proposed building custom escrow for all settlement sizes without evaluating managed alternatives for micro-payments.

6. **Section 5.7 (Solana as Settlement Rail)**: Added analysis of Solana's native Ed25519 precompile program. This is arguably the most impactful addition -- Solana eliminates the entire Ed25519-on-EVM challenge that consumes three pages of the document. The original research was EVM-centric and missed the most obvious solution to its hardest problem.

7. **Section 10 (Account Abstraction and Gas Management)**: Added coverage of ERC-4337, Paymasters, Safe{Core} Protocol, and intent-based settlement (CoW Protocol). The original document's treatment of gas management was limited to "operators need gas; agents can use EIP-3009" -- underselling the ERC-4337 ecosystem that directly solves agent gas abstraction.

8. **Section 12 (Security Analysis)**: Added detailed analysis of MEV/frontrunning risks, settlement failure handling (transaction revert, not-mined, chain reorg, batch partial failure), and USDC blacklisting/regulatory freeze. The original document mentioned these as open questions but did not analyze attack vectors or mitigations.

9. **Section 13 (Regulatory Considerations)**: Added analysis of money transmission law, securities law implications of bonding, and OFAC sanctions compliance. These were entirely absent from the original document despite arc-settle handling real money.

10. **Section 15 (Cross-Integration Dependencies)**: Added mapping of how arc-settle interacts with arc-anchor and arc-link, including shared infrastructure, Merkle root convergence, and a recommended build order.

### 16.3 Key Management Complexity

11. **Section 5.5 expanded.** The original document's treatment of dual-signing understated the operational complexity. Added detailed analysis of key rotation, HA synchronization, and binding certificate management. Dual-signing is still recommended for v1, but the document now honestly characterizes the operational burden rather than presenting it as a minor implementation detail.

### 16.4 Architecture Adjustments

12. **Chain selection expanded.** Added Solana to the comparison matrix and recommendation. Changed the recommendation from "Base primary, Arbitrum secondary" to "Base primary EVM, Solana primary non-EVM, Arbitrum secondary EVM."

13. **Multi-chain architecture updated.** The `CapitalExecutionRail` mapping now includes Solana addresses and CAIP-2 identifiers for Solana.

14. **Crate structure expanded.** Added `reconcile.rs` and `revert.rs` modules to the arc-settle crate structure to handle the settlement failure scenarios documented in section 12.

15. **Gas estimate methodology note added.** The original gas estimates were presented as precise numbers without explaining assumptions. Added a methodology note explaining these are order-of-magnitude estimates based on comparable DeFi operations.

### 16.5 Items Not Changed

- The core recommendation of dual-signing + Merkle proofs for EVM settlement is sound and was not changed.
- The contract architecture (ArcEscrow, ArcBondVault, ArcReceiptVerifier, ArcSettleRegistry) is well-designed and was not altered.
- The Alloy recommendation and crate ecosystem analysis is accurate and current.
- The existing agent payment project survey (sections 2.1-2.7) is factually accurate based on available information and was only lightly updated (x402 details).
