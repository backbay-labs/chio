# arc-link Future Tracks: Beyond Price Oracles

Status: Research / Backlog
Authors: Engineering
Date: 2026-03-30

> Realization status (2026-04-02): these tracks remain backlog or bounded
> overlays. The shipped v1 runtime is documented in
> [CHIO_LINK_PROFILE.md](../standards/CHIO_LINK_PROFILE.md). Bounded automation,
> CCIP coordination, and payment-interop that did ship are defined by
> [CHIO_AUTOMATION_PROFILE.md](../standards/CHIO_AUTOMATION_PROFILE.md),
> [CHIO_CCIP_PROFILE.md](../standards/CHIO_CCIP_PROFILE.md), and
> [CHIO_PAYMENT_INTEROP_PROFILE.md](../standards/CHIO_PAYMENT_INTEROP_PROFILE.md).

---

## Overview

This document captures Chainlink and ecosystem integration research that is adjacent to -- but not part of -- the [arc-link v1 price oracle crate](./CHIO_LINK_RESEARCH.md). These tracks are worth pursuing after the core oracle integration ships, but each has a different owner or dependency chain.

| Track | Likely Owner | Depends On | Priority |
|-------|-------------|------------|----------|
| CCIP for cross-chain delegation | arc-link | arc-link v1 (oracle), arc-anchor | Low (v2+) |
| Chainlink Functions for Ed25519 | arc-settle / trust boundary | arc-anchor, arc-settle | Medium |
| Chainlink Automation for anchoring | arc-anchor | arc-anchor | Medium |
| x402 protocol comparison | arc-settle | arc-settle | Low |
| Chainlink BUILD program | Business / BD | arc-link v1 production usage | Low |

---

## 1. CCIP for Cross-Chain Capability Delegation

### 1.1 What CCIP Is

Chainlink's Cross-Chain Interoperability Protocol (CCIP) is a cross-chain messaging protocol with three core capabilities:

1. **Arbitrary messaging** -- send encoded `bytes` to a receiving contract on another chain.
2. **Token transfers** -- move tokens cross-chain using burn-and-mint, lock-and-mint, or lock-and-unlock mechanisms.
3. **Programmable token transfers** -- combine tokens with arbitrary data.

The architecture has two layers:

**Off-chain:**
- A **Committing DON** observes source-chain events and builds consensus-based commit reports.
- An **Executing DON** validates pending messages and triggers execution on the destination chain.
- A **Risk Management Network** independently monitors for anomalies (defense-in-depth).

**On-chain:**
- A single immutable **Router** contract per chain.
- **OnRamp** contracts on the source chain handle fee estimation, token locking/burning, and message dispatch.
- **OffRamp** contracts on the destination chain accept commit reports, release/mint tokens, and route messages to receivers.

### 1.2 Supported Chains

As of early 2026, CCIP connects 60+ blockchain networks including EVM chains (Ethereum, Arbitrum, Base, Optimism, Polygon, Avalanche, BNB Chain, Linea) and non-EVM chains (Solana with v1.6, Aptos). 15 blockchains have adopted CCIP as their canonical cross-chain infrastructure.

### 1.3 Service Limits

| Limit | Value |
|-------|-------|
| Maximum message data length | 30 KB |
| Message execution gas limit | 3,000,000 |
| Maximum distinct tokens per transfer | 1 |

A serialized Chio `DelegationLink` chain (including Ed25519 signatures and attenuations) would typically be 1-5 KB in canonical JSON, well within the 30 KB limit.

### 1.4 Fees

| Lane Type | Premium (LINK) | Premium (Native) |
|-----------|---------------|------------------|
| Ethereum lanes (messaging only) | $0.45 | $0.50 |
| Non-Ethereum lanes (messaging only) | $0.09 | $0.10 |
| Token transfers | 0.063% of value | 0.07% of value |

### 1.5 Latency

| Source Chain | Approximate Finality | CCIP E2E Latency |
|-------------|---------------------|-------------------|
| Ethereum | ~15 minutes | ~20 minutes |
| Arbitrum | ~7-10 minutes | ~10-15 minutes |
| Base | ~7-10 minutes | ~10-15 minutes |
| Avalanche | ~1 second | ~2-5 minutes |
| Solana | ~400ms | ~2-5 minutes |

### 1.6 Could CCIP Transport Chio Delegation Proofs?

**Yes, with significant caveats on latency.** CCIP can transport arbitrary bytes cross-chain, so a serialized delegation chain fits within the 30 KB message limit. The receiving contract would need to:

1. Deserialize the delegation chain.
2. Verify Ed25519 signatures (the expensive part -- see section 2).
3. Store or emit the verified delegation for on-chain capability enforcement.

The main concerns are:

- **Latency is a deal-breaker for real-time delegation.** 2-20 minutes is far too slow for interactive tool invocation flows. Chio capability tokens have typical lifetimes of minutes to hours. A 20-minute CCIP hop on Ethereum-origin lanes consumes a material fraction of a short-lived token's validity window. For Arbitrum-to-Base (the most likely Chio lane), expect 10-15 minutes.
- **Cost.** $0.09-0.50 per message. Reasonable for high-value delegations but expensive for frequent micro-delegations.
- **Ed25519 on EVM.** The receiving chain cannot natively verify Ed25519 signatures. This must be handled via Chainlink Functions or a pre-verification step.

**Recommendation:** For v1, avoid CCIP for real-time delegation. Instead, use a Merkle proof approach: anchor delegation roots on a single chain, distribute proofs off-chain, and verify locally. CCIP is better suited to batch transport of pre-verified delegation bundles where latency is not user-facing.

### 1.7 Multi-Chain Identity Questions

If Chio delegation proofs eventually exist on multiple chains via CCIP:

- **Revocation propagation.** Revocation must be fail-safe: if the revocation message is delayed, the destination chain should treat the capability as suspect (configurable policy).
- **Home chain.** The CA's `home_chain` should be part of its configuration, with all revocations originating from the home chain.
- **Token ID.** The `CapabilityToken.id` is already a UUID. Chain context should be in the transport metadata, not the token itself.
- **Minimum token validity.** Cross-chain delegations should have longer time windows to account for transport latency: minimum `expires_at - issued_at` should be at least 2x the expected CCIP latency for the lane.

---

## 2. Chainlink Functions for Ed25519 Verification

### 2.1 How Functions Work

Chainlink Functions enables serverless off-chain computation executed by a DON. The flow:

1. A smart contract sends a request containing JavaScript source code and arguments.
2. Each DON node independently executes the code in a sandboxed **Deno runtime**.
3. Nodes reach consensus on the result using OCR 2.0.
4. The aggregated result is delivered on-chain to a callback function.

### 2.2 Service Limits

| Limit | Value |
|-------|-------|
| Supported language | JavaScript (Deno runtime) |
| Max execution time | 10 seconds |
| Max memory | 128 MB |
| Max request size | 30 KB |
| Max returned value size | 256 bytes |
| Max HTTP requests per execution | 5 |
| Max callback gas limit | 300,000 |

### 2.3 Ed25519 Verification Use Case

The problem: EVM has no Ed25519 precompile (EIP-665 was proposed but never adopted). Verifying Ed25519 on-chain in Solidity costs 300,000-500,000 gas per signature, which is prohibitively expensive.

**Proposed solution:** Use Functions to run Ed25519 verification off-chain and report the boolean result on-chain.

```javascript
// Chainlink Function source code (pseudocode)
import * as ed from "https://esm.sh/@noble/ed25519";

const publicKey = args[0];  // hex-encoded Ed25519 public key
const signature = args[1];  // hex-encoded signature
const message = args[2];    // canonical JSON bytes

const isValid = await ed.verifyAsync(
  hexToBytes(signature),
  hexToBytes(message),
  hexToBytes(publicKey)
);

return Functions.encodeUint256(isValid ? 1 : 0);
```

**Feasibility:**
- Ed25519 verification in JavaScript takes ~1ms per signature. Even a 10-link delegation chain completes well under 10 seconds.
- A single boolean (32 bytes as uint256) fits within the 256-byte return limit.
- On L2s, total cost per request is typically $0.01-0.05.

### 2.4 Security Analysis: Optimistic, Not Trustless

**This is critical.** Functions-based Ed25519 verification is "optimistic verification" -- the DON attests to the result, not the chain itself.

1. **Collusion threshold.** The DON uses OCR 2.0, tolerating up to f Byzantine nodes in a 3f+1 configuration. Typical DON sizes are 8-31 nodes.
2. **Economic security.** DON node stakes are typically much less than the value of high-value delegations. There is no guarantee that cost-of-attack exceeds value-at-risk.
3. **No challenge mechanism.** Unlike UMA's optimistic oracle, there is no built-in dispute/challenge period for Functions results.

**Mitigations:**
- For high-value delegations, require dual verification: Functions result AND a secondary proof.
- Include full delegation chain data as an on-chain event log so anyone can re-verify off-chain.
- Monitor DON node diversity.
- Consider UMA's optimistic oracle as a dispute layer for contestable results.

### 2.5 Ownership Note

**The trust-boundary document should govern when DON-based verification is acceptable.** This decision is not purely an arc-link concern -- it affects the security properties of any on-chain delegation or receipt verification. The trust boundary doc should define:
- Maximum grant value for DON-only verification.
- When dual verification is required.
- Whether ZK-based Ed25519 proofs (via SP1, Risc0) are preferred for high-value use cases.

### 2.6 Receipt Batch Verification

Functions could also verify batches of Chio receipts and report summary hashes on-chain:

1. Function receives a batch of receipt canonical JSON and their Ed25519 signatures.
2. Verifies each signature.
3. Computes a Merkle root over verified receipts.
4. Returns the root (32 bytes) on-chain.

**Practical limit:** The 30 KB request size cap limits batch size. A typical Chio receipt is 500-1000 bytes, so roughly 20-50 receipts per batch. For larger batches, pre-compute the Merkle root off-chain and use Functions only for random-sampling spot-checks.

---

## 3. Chainlink Automation for Receipt Anchoring

### 3.1 Trigger Types

Chainlink Automation supports three triggers:

1. **Time-based (CRON)** -- execute on a schedule. Directly maps to periodic Merkle root anchoring.
2. **Custom logic** -- Automation nodes evaluate off-chain conditions and execute when met.
3. **Log triggers** -- triggered by specific on-chain events/logs.

### 3.2 Periodic Merkle Root Anchoring Pattern

1. Deploy an `ArcAnchor` contract with a `pushRoot(bytes32 root, uint64 timestamp, uint64 receiptCount)` function.
2. Register a time-based Automation upkeep with a CRON expression (e.g., `0 */6 * * *` for every 6 hours).
3. The upkeep calls a Chainlink Function that:
   a. Fetches the latest receipt batch from an off-chain API.
   b. Verifies Ed25519 signatures on each receipt.
   c. Computes the Merkle root.
   d. Returns the root.
4. The Automation callback stores the root on-chain.

This combines Automation (trigger) + Functions (computation) + on-chain storage (anchor).

### 3.3 Event-Driven Anchoring

Beyond CRON, Automation's log trigger enables:
- **Receipt-based triggering.** If arc-settle emits on-chain events when escrow funds are deposited, a log-trigger upkeep could automatically initiate the verification and settlement pipeline.
- **Threshold triggering.** A custom logic upkeep could monitor unanchored receipt count and trigger when a batch threshold is reached.

### 3.4 Settlement Triggers

Automation can also trigger:
- **Budget reconciliation** when a capability expires.
- **Stale price alerting** to trigger fallback behavior.
- **Reserve release** when delegation bonds expire without claims.

### 3.5 Costs

On L2s, typical costs are $0.01-0.10 per execution. Time-based triggers with infrequent schedules (every few hours) are very economical.

### 3.6 Ownership Note

**arc-anchor owns the anchoring trigger story.** Chainlink Automation is a trigger mechanism, and the arc-anchor crate should decide whether to use it vs. a simple operator-run cron job. arc-link's role is limited to providing the Automation client library if arc-anchor chooses Chainlink as the trigger.

---

## 4. x402 Protocol

### 4.1 What x402 Is

The x402 protocol (HTTP 402 "Payment Required") is emerging as a standard for autonomous agent payments, with adoption by Coinbase, Google Cloud, AWS, and others. It revives the HTTP 402 status code for machine-to-machine payments.

### 4.2 Architecture

Client sends HTTP request; server responds with 402 + payment requirements; client signs a USDC transfer authorization (EIP-3009 `TransferWithAuthorization`); server verifies via a "facilitator" service and settles on-chain.

### 4.3 Chio Relevance

- x402 solves a narrower problem (HTTP API monetization) than Chio (full capability-mediated economic substrate).
- x402's use of EIP-3009 for gasless USDC movement is a pattern arc-settle could adopt.
- Chio capability tokens could serve as the authorization layer for x402 payments (the capability authorizes the spend, x402 executes the transfer).
- x402 settlement is USDC-on-chain. When grants are not denominated in USDC, this creates a natural requirement for arc-link's oracle integration.

### 4.4 Ownership Note

**x402 is an arc-settle concern, not arc-link.** The payment execution and settlement semantics belong to arc-settle. arc-link only intersects if x402 settlement requires currency conversion (i.e., non-USDC grants settling via x402).

---

## 5. Chainlink BUILD Program

### 5.1 What BUILD Is

The Chainlink BUILD program provides early and mid-stage projects with:
- Dedicated technical support and early access to new Chainlink products.
- Co-marketing and ecosystem introductions.
- Access to the Chainlink Rewards program.

### 5.2 Chio Relevance

If arc-link becomes a production dependency on Chainlink infrastructure (Data Feeds + potentially Functions + Automation + CCIP), joining BUILD could provide material benefits: priority support, early access to Data Streams, and potential co-marketing. The tradeoff is that BUILD participants are expected to allocate a portion of their native tokens to the Chainlink Rewards program. For a protocol-level project like Chio, this depends on tokenomics decisions.

### 5.3 Recommendation

Defer until arc-link v1 is in production and the team has a clear view of Chainlink usage volume. The BUILD application is stronger with demonstrated integration usage.

---

## 6. Oracle Comparison: Comprehensive Matrix

For reference, here is the full oracle comparison that was in the original research document. This is useful context for future evaluation of additional backends.

| Feature | Chainlink Feeds | Chainlink Streams | Pyth | RedStone | API3 | UMA | Chronicle | Flare FTSOv2 |
|---------|----------------|------------------|------|----------|------|-----|-----------|-------------|
| Model | Push | Pull | Pull | Modular | First-party | Optimistic | Push (Schnorr) | Enshrined |
| Update latency | Min-hours | Sub-second | 400ms | On-demand | Sec-min | Hours | Minutes | ~1.8s |
| Feed count | 1000+ | 100+ | 500+ | 1300+ | 200+ | N/A | 100+ | 1000 |
| Chain count | 30+ | Limited | 50+ | 100+ | 40+ | ETH focus | 10+ | Flare only |
| Rust SDK | No (alloy) | Yes (official) | Limited | No | No | No | No | No |
| Off-chain read | RPC call | WebSocket/REST | Hermes API | JavaScript | JavaScript | N/A | RPC call | RPC call |
| Cost (off-chain) | Free (RPC) | Subscription | Free (Hermes) | Free (API) | Free (RPC) | N/A | Free (RPC) | Free (RPC) |
| Trust model | DON consensus | DON + on-chain verify | Provider signing | Provider signing | First-party | Token vote | Schnorr aggregate | Protocol-enshrined |

---

## 7. Estimated Gas Costs for Future Tracks

For planning purposes, these are estimated on-chain costs for the future tracks (all on Base Mainnet):

| Operation | Estimated Cost | Frequency |
|-----------|---------------|-----------|
| Anchor Merkle root (on-chain) | $0.01-0.05 | Every 6 hours |
| Chainlink Function (Ed25519) | $0.01-0.05 | Per batch (~20-50 receipts) |
| CCIP delegation transport | $0.09-0.10 | Per delegation |
| Automation upkeep | $0.01-0.05 | Per trigger |

At steady state with moderate usage (1000 tool invocations/day, daily anchoring, weekly cross-chain delegations), the on-chain cost for all future tracks would be approximately $0.50-2.00 per day.

**Note:** These estimates use 2025-2026 L2 gas prices, which have been historically low due to EIP-4844. Apply a 3x safety margin for budgeting.

---

## 8. References

### CCIP
- [CCIP Documentation](https://docs.chain.link/ccip)
- [CCIP Architecture Overview](https://docs.chain.link/ccip/concepts/architecture/overview)
- [CCIP Service Limits (EVM)](https://docs.chain.link/ccip/service-limits/evm)
- [CCIP Billing](https://docs.chain.link/ccip/billing)
- [Send Arbitrary Data via CCIP](https://docs.chain.link/ccip/tutorials/evm/send-arbitrary-data)

### Functions
- [Chainlink Functions](https://docs.chain.link/chainlink-functions)
- [Functions Service Limits](https://docs.chain.link/chainlink-functions/resources/service-limits)
- [Functions Billing](https://docs.chain.link/chainlink-functions/resources/billing)

### Automation
- [Automation Concepts](https://docs.chain.link/chainlink-automation/concepts/automation-concepts)
- [Automation Log Triggers](https://docs.chain.link/chainlink-automation/guides/log-trigger)

### BUILD Program
- [Chainlink BUILD Program](https://chain.link/build-program)

### x402
- [x402 Protocol](https://www.x402.org/)
- [x402 on Base](https://docs.base.org/base-app/agents/x402-agents)

### Agent Economy Context
- [Web3 AI Agent Sector Analysis](https://blockeden.xyz/blog/2026/02/07/web3-ai-agent-sector-analysis/)
- [CCIP: 11,000 Banks Getting Direct Blockchain Access](https://blockeden.xyz/blog/2026/01/12/chainlink-ccip-cross-chain-interoperability-tradfi-bridge/)

### UMA (Dispute Resolution)
- [How UMA's Oracle Works](https://docs.uma.xyz/protocol-overview/how-does-umas-oracle-work)
