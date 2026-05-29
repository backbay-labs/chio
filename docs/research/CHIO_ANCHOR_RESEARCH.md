# Chio-Anchor: Blockchain Anchoring for the Chio Receipt Log

> Research document -- produced 2026-03-30.
> Status: **Draft / Research Only** -- no implementation code.
>
> Realization status (2026-04-02): this document fed the shipped bounded
> `arc-anchor` runtime, but the authoritative runtime boundary is now
> [CHIO_ANCHOR_PROFILE.md](../standards/CHIO_ANCHOR_PROFILE.md) plus
> [CHIO_WEB3_PROFILE.md](../standards/CHIO_WEB3_PROFILE.md). For shipped proof
> bundles, discovery artifacts, and qualification claims, prefer the checked-in
> `ARC_ANCHOR_*` standards artifacts and the `crates/arc-anchor/` runtime.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Existing Approaches](#2-existing-approaches)
3. [Bitcoin Anchoring](#3-bitcoin-anchoring)
4. [EVM / L2 Anchoring](#4-evm--l2-anchoring)
5. [Solana Anchoring](#5-solana-anchoring)
6. [Data Availability Layers](#6-data-availability-layers)
7. [Recommended Contract Design](#7-recommended-contract-design)
8. [Rust Ecosystem](#8-rust-ecosystem)
9. [Integration Points with Chio](#9-integration-points-with-arc)
10. [Recommended Architecture](#10-recommended-architecture)
11. [Compliance and Legal Value](#11-compliance-and-legal-value)
12. [Open Questions](#12-open-questions)
13. [Cross-Integration Dependencies](#13-cross-integration-dependencies)
14. [Reviewer Notes](#14-reviewer-notes)

---

## 1. Executive Summary

Chio already produces a Merkle-committed, append-only receipt log. Every tool
invocation -- whether allowed or denied -- generates a signed `ArcReceipt`.
The kernel periodically batches receipts into `KernelCheckpoint` statements
that commit a Merkle root over a contiguous range of receipt sequence numbers
(default batch size: 100 receipts, configured via `checkpoint_batch_size` in
`KernelConfig`).

**arc-anchor** extends this trust model beyond the operator's own
infrastructure by periodically writing the checkpoint Merkle root to one or
more public blockchains. This gives any third-party verifier the ability to
prove:

- A given receipt existed at the time the anchor was published.
- The receipt log has not been retroactively altered since that point.
- The operator's checkpoint statements are consistent over time.

The core insight is that Chio's existing `KernelCheckpoint` already contains
the `merkle_root` (a 32-byte SHA-256 hash stored as `arc_core::hashing::Hash`)
that needs to be anchored. The arc-anchor crate only needs to (a) read
finalized checkpoints from the receipt store and (b) publish that 32-byte root
to one or more chains.

**Note on the Merkle tree implementation**: Chio uses an RFC 6962-compatible
(Certificate Transparency style) Merkle tree. Leaf hashes are computed as
`SHA256(0x00 || leaf_bytes)` and node hashes as
`SHA256(0x01 || left || right)`. The tree does not duplicate the last leaf when
the level has an odd number of nodes -- it carries the last node upward
unchanged (left-balanced, append-only semantics). This is significant for
anchoring because on-chain verifiers or off-chain proof checkers must use the
same tree construction algorithm; a verifier that assumes "duplicate last" leaf
padding will reject valid proofs.

**Recommendation**: A multi-tier anchoring strategy.

- **Primary (high-frequency, low-cost)**: Anchor every N checkpoints to an
  EVM L2 (Base recommended) via a minimal Merkle root registry contract.
  Cost: < $0.01 per anchor. Finality: seconds.
- **Secondary (low-frequency, high-assurance)**: Aggregate L2 anchors into a
  daily or weekly Bitcoin commitment via the OpenTimestamps protocol.
  Cost: $0.00 (public calendars). Finality: ~60 minutes (6 blocks).
- **Optional (high-throughput, low-cost)**: Solana via the Memo program for
  operators who want sub-second finality without the EVM dependency.
  Cost: ~$0.0003 per anchor. Finality: ~400ms.

This gives operators sub-minute tamper-evidence on L2 with the ultimate
settlement guarantee of Bitcoin, at a combined cost well under $1/day for
typical workloads.

---

## 2. Existing Approaches

### 2.1 OpenTimestamps (OTS)

**What it is**: An open-source protocol (created by Peter Todd) that
aggregates an unlimited number of document hashes into a Merkle tree and
anchors the root to Bitcoin via a single OP_RETURN transaction.

**How it works**:

1. Client computes SHA-256 of data, prepends a random 128-bit nonce, and
   sends the hash to one or more calendar servers.
2. Calendar servers aggregate incoming hashes into a per-block Merkle tree.
3. Once per block (~10 min), the calendar writes the tree root into an
   OP_RETURN output on the Bitcoin blockchain.
4. The calendar returns a compact `.ots` proof file containing the Merkle
   path from the client's hash to the Bitcoin block header.

**Key properties**:

- Infinite scalability: one Bitcoin transaction covers all timestamps in a
  block window.
- Verification is trustless -- anyone with a Bitcoin node can confirm.
- Current calendars operate at sub-1-sat/vB fee rates.
- Four public calendars exist; operators can run private ones.
- A Rust library exists: `opentimestamps` crate (parsing, verification,
  serialization of `.ots` proofs).

**Calendar server reliability**: Peter Todd addressed concerns about calendar
availability in a January 2025 blog post. The OTS calendars embed hashes in
OP_RETURN outputs of 40 bytes or less, which is within the default relay limit
of Bitcoin Knots (40 bytes) and Bitcoin Core (80 bytes per output). Even if
Bitcoin Knots tightened its relay policy further, OTS could fall back to
alternative commitment schemes (e.g., embedding the hash in a pay-to-taproot
address tweak). At worst, the calendar would need a direct connection to a
mining pool -- and since a single calendar produces at most 144 transactions
per day, the capacity requirements are negligible. In practice, OTS has
operated continuously since 2016 with minimal downtime. However, the protocol
currently depends on four public calendar servers
(`alice.btc.calendar.opentimestamps.org`, `bob.btc.calendar.opentimestamps.org`,
`finney.calendar.eternitywall.com`, and a Blockstream-hosted instance). If all
four go down simultaneously, timestamps are delayed but not lost -- the client
retains the hash and can re-submit when service resumes. Operators who need
guaranteed availability should run a private calendar server (the software is
open-source).

**Relevance to Chio**: OTS is the cheapest possible Bitcoin anchor. Chio could
submit its checkpoint Merkle root to an OTS calendar and receive back a proof
tying that root to a specific Bitcoin block. The downside is latency -- you
must wait for the next block (up to ~10 min) and ideally 6 confirmations
(~60 min) for strong finality.

### 2.2 Chainpoint

**What it is**: A protocol (by Tierion) for generating blockchain-anchored
proofs via a hierarchical aggregation network.

**Architecture**:

1. Clients submit hashes to **Gateways**.
2. Gateways aggregate into a Merkle tree and forward roots to **Cores**.
3. Cores run a Tendermint-based "Calendar" chain and periodically anchor to
   Bitcoin.

**Key properties**:

- Multi-tier aggregation reduces per-hash cost.
- Proofs are JSON-LD documents (Chainpoint v4 format).
- The network has had availability issues; the public infrastructure has been
  less reliable than OpenTimestamps in recent years.
- No actively maintained Rust library.

**Relevance to Chio**: Chainpoint's architecture is instructive (hierarchical
aggregation is similar to what Chio would do internally), but the protocol
itself is not recommended as a dependency due to operational reliability
concerns. The Chainpoint proof format is also heavier than OTS.

### 2.3 Ethereum Attestation Service (EAS)

**What it is**: A free, open protocol for making on-chain (or off-chain)
attestations on any EVM-compatible chain. Deployed on Ethereum mainnet, Base,
Optimism, Arbitrum, Polygon, Scroll, zkSync, Celo, Linea, and others.

**Contract architecture** (two contracts):

1. **SchemaRegistry** -- register a schema defining the structure of your
   attestation data.
2. **EAS** -- make attestations against a registered schema, optionally with
   a resolver contract for on-chain verification or payment logic.

**Deployed addresses** (selected chains):

| Chain        | EAS Contract                                 | SchemaRegistry                               |
|-------------|----------------------------------------------|----------------------------------------------|
| Ethereum    | `0xA1207F3BBa224E2c9c3c6D5aF63D0eb1582Ce587` | `0xA7b39296258348C78294F95B872b282326A97BDF` |
| Base        | `0x4200000000000000000000000000000000000021` | `0x4200000000000000000000000000000000000020` |
| Optimism    | `0x4200000000000000000000000000000000000021` | `0x4200000000000000000000000000000000000020` |
| Arbitrum    | `0xbD75f629A22Dc1ceD33dDA0b68c546A1c035c458` | `0xA310da9c5B885E7fb3fbA9D66E9Ba6Df512b78eB` |

**Relevance to Chio**: EAS provides a ready-made on-chain attestation
framework. Chio could register a schema like
`(bytes32 merkleRoot, uint64 checkpointSeq, uint64 batchStartSeq, uint64 batchEndSeq, bytes32 kernelKey)`
and create attestations for each anchor. The advantage is interoperability --
anyone can query EAS for Chio anchors. The disadvantage is that EAS
attestations cost more gas than a raw storage write because of the schema
machinery and event overhead.

### 2.4 Ceramic Network

**What it is**: A decentralized data network where mutable "streams" are
cryptographically signed and periodically anchored to Ethereum for
tamper-evident timestamps.

**How it works**:

- Data is organized into append-only streams of signed events.
- The Ceramic Anchor Service (CAS) periodically aggregates stream tips into
  a Merkle tree and writes the root to Ethereum.
- Conflict resolution uses "earliest anchor wins" -- the stream update with
  the earlier blockchain timestamp prevails.

**Relevance to Chio**: Ceramic's model is conceptually similar to arc-anchor
(append-only event log + periodic Merkle anchoring). However, Ceramic is a
full data network with its own replication layer -- far more than Chio needs.
The CAS component is interesting as a reference design for batched Ethereum
anchoring.

### 2.5 OriginStamp

**What it is**: A commercial timestamping service that anchors hashes to
Bitcoin, Ethereum, and other chains. Offers an API for programmatic use.

**Relevance to Chio**: Useful as a fallback or convenience layer, but
introduces a third-party dependency. Not recommended as the primary anchor
path for a protocol that values self-sovereignty.

### 2.6 AI/Agent-Specific Audit Anchoring

As of early 2026, no production system specifically anchors AI/agent audit
trails to blockchains using Merkle roots. The closest analogues are:

- **Chainlink Functions + Automation for receipt anchoring** (described in the
  arc-link research doc) -- Chainlink's documentation cites periodic Merkle
  root publication as a use case for Automation triggers.
- **Fetch.ai agent audit logs** -- Fetch.ai stores agent execution history
  but does not provide blockchain-anchored tamper evidence.
- **Virtuals Protocol escrowed jobs** -- on-chain evidence of job completion
  but not Merkle-committed audit trails.

Chio would be a first mover in providing Merkle-committed, blockchain-anchored
agent audit trails with standard inclusion proofs. This is a differentiator
worth emphasizing in positioning.

---

## 3. Bitcoin Anchoring

### 3.1 OP_RETURN

**Mechanism**: Create a Bitcoin transaction with an `OP_RETURN` output
containing the 32-byte Merkle root (plus an optional prefix tag, e.g.,
`ARC\x01` for 4 bytes of protocol identification).

**Properties**:

- OP_RETURN outputs are provably unspendable -- they do not pollute the UTXO
  set.
- Maximum data: 80 bytes per output (standard relay limit per output;
  Bitcoin Core 30.0 raised `datacarriersize` to 100,000 bytes for
  non-standard transactions, but 80 per output remains the standard relay
  convention).
- 32 bytes for the Merkle root + 4 bytes for a tag = 36 bytes, well within
  the 40-byte threshold that even Bitcoin Knots relays by default.

**Cost estimate** (2025-2026 fee environment):

| Fee Rate    | Tx Size (~160 vB) | Cost (sats) | Cost (USD @ $60k BTC) |
|------------|-------------------|-------------|----------------------|
| 1 sat/vB   | 160 vB            | 160         | ~$0.10               |
| 10 sat/vB  | 160 vB            | 1,600       | ~$0.96               |
| 50 sat/vB  | 160 vB            | 8,000       | ~$4.80               |

During low-fee periods (common in 2025), costs are well under $1. During fee
spikes, costs can exceed $5.

**Finality**: 1 confirmation ~10 min; 6 confirmations ~60 min (considered
irreversible for most purposes).

### 3.2 Taproot Commitments

**Mechanism**: Embed the Merkle root in the tweak of a Taproot output's
internal public key. The commitment is invisible on-chain unless the script
path is spent.

**Properties**:

- More private than OP_RETURN -- the commitment is not visible in the
  transaction data unless revealed.
- Slightly more complex to construct and verify.
- The Taproot output is spendable (unlike OP_RETURN), so the committed funds
  can be reclaimed.
- Verification requires knowledge of the internal public key and the
  commitment scheme.

**Cost**: Similar to OP_RETURN (the commitment adds no extra on-chain bytes
if using key-path spend), but the output must be funded with at least the
dust limit (~546 sats).

**Tradeoffs vs. OP_RETURN**:

| Aspect          | OP_RETURN              | Taproot Commitment       |
|----------------|------------------------|--------------------------|
| Visibility     | Plainly visible        | Hidden until revealed    |
| UTXO impact    | None (unspendable)     | Creates a UTXO           |
| Complexity     | Simple                 | More complex             |
| Verification   | Trivial                | Requires internal key    |
| Fund recovery  | Not possible           | Funds recoverable        |

**Recommendation**: OP_RETURN is simpler and more transparent for an audit
protocol whose entire purpose is public verifiability. Taproot commitments
add unnecessary complexity without clear benefit for Chio's use case.

### 3.3 OpenTimestamps Integration

**Mechanism**: Instead of crafting a raw Bitcoin transaction, submit the
Merkle root to an OTS calendar server. Receive an `.ots` proof linking the
root to a Bitcoin block.

**Properties**:

- Zero marginal cost per timestamp (the calendar aggregates many timestamps
  into one transaction).
- Latency: must wait for the calendar's next aggregation cycle plus block
  confirmation.
- Proof files are compact (~500 bytes to 2 KB).
- Rust library available (`opentimestamps` crate).

**Operational considerations**:

- Public calendar servers are the main liveness dependency. If all four
  public calendars are unreachable, timestamping is delayed until they return.
  The client-side library retains the hash locally and can retry.
- OTS proofs are "incomplete" until the Bitcoin transaction is mined. The
  `.ots` file is first returned with a calendar commitment (seconds), then
  upgraded to a Bitcoin commitment once the transaction confirms (minutes to
  hours). Arc-anchor must handle both states and track proof upgrades.
- Private calendar operation costs one Bitcoin transaction per block
  (~144/day). At 1 sat/vB this is roughly $14/day at $60k BTC -- meaningful
  for small operators but trivial for enterprise use.

**Cost**: Free (public calendars absorb transaction fees). Private calendar
operation costs one Bitcoin transaction per block (~144/day).

**Recommendation**: OTS is ideal as the Bitcoin anchoring path for Chio. It
provides the strongest possible timestamp guarantee at zero marginal cost.
The tradeoff is latency (minutes to hours), which is acceptable for a
secondary assurance layer.

---

## 4. EVM / L2 Anchoring

### 4.1 Chain Selection

The three leading EVM L2 candidates for Chio anchoring are:

| Chain     | Type              | Finality  | Base Fee (2025) | Notes                        |
|----------|-------------------|-----------|----------------|------------------------------|
| Base     | Optimistic Rollup | ~2 sec    | ~0.005 gwei    | Coinbase-operated, high volume |
| Arbitrum | Optimistic Rollup | ~250 ms   | ~0.01 gwei     | Largest L2 by TVL            |
| Optimism | Optimistic Rollup | ~2 sec    | ~0.005 gwei    | OP Stack, EAS pre-deployed   |

All three are EVM-equivalent, meaning SSTORE gas costs match Ethereum's
schedule (20,000 gas for a cold write to a new slot). The actual USD cost is
dramatically lower because L2 gas prices are orders of magnitude cheaper.

**Cost estimate for storing a 32-byte hash on L2**:

A minimal `anchor()` function that writes one `bytes32` to storage and emits
an event costs approximately:

- Execution gas: ~45,000 gas (SSTORE + event emission + calldata)
- L1 data fee: variable, typically 1,000-5,000 gas-equivalent
- Total effective cost: **< $0.01** on Base/Optimism at 2025-2026 gas prices

At current rates, anchoring every 100 receipts (one checkpoint) to Base costs
well under a penny. Even anchoring every single checkpoint, the annual cost
for a busy operator (10,000 checkpoints/year) would be under $100.

**Important caveat on finality**: Base and Optimism are optimistic rollups.
Their "soft finality" (~2 seconds) reflects sequencer confirmation, but
**hard finality** requires L1 settlement (~12.8 minutes for data posting,
plus the 7-day challenge window for full fraud-proof security). For anchor
verification purposes, a verifier must decide how much finality they require:

- **Sequencer confirmation** (seconds): sufficient for operational monitoring
  and fast tamper detection.
- **L1 data posting** (~13 minutes): the anchor data has been posted to
  Ethereum and would survive a sequencer failure.
- **Challenge period expiry** (~7 days): the anchor is irrevocable. No fraud
  proof can undo it.

For Chio's use case, sequencer confirmation is likely sufficient for day-to-day
operations, with the Bitcoin anchor providing the ultimate assurance layer.
But the document should not conflate L2 "finality" with Bitcoin-level
irreversibility.

### 4.2 EAS vs. Custom Contract

**Using EAS**:

- Pros: pre-deployed on all target chains, standardized schema, built-in
  indexing via EAS scan, no contract deployment needed.
- Cons: higher gas cost per attestation (~70,000-100,000 gas due to schema
  resolution and EAS storage overhead), less flexible event structure.

**Using a custom Merkle root registry contract**:

- Pros: minimal gas cost (~45,000 gas), exact event structure for Chio's
  needs, no dependency on EAS availability.
- Cons: requires deploying and maintaining a contract on each target chain.

**Recommendation**: Deploy a minimal custom contract. The gas savings are
meaningful at scale, and Chio benefits from a purpose-built event structure
that indexers can subscribe to directly. EAS can be supported as an optional
secondary output for interoperability.

---

## 5. Solana Anchoring

### 5.1 Why Consider Solana

Solana offers several properties that make it attractive as an anchoring
target, particularly for high-throughput operators:

- **Sub-second finality**: ~400ms slot times with optimistic confirmation.
- **Extremely low cost**: A basic transaction costs 5,000 lamports
  (~$0.0003 at $120 SOL). With priority fees for guaranteed inclusion, still
  under $0.001.
- **High throughput**: Thousands of transactions per second, so anchor
  transactions are unlikely to face congestion delays.
- **Memo Program**: Solana's built-in Memo program
  (`MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`) accepts arbitrary UTF-8
  data in a transaction, logged to the transaction log. A hex-encoded
  32-byte Merkle root (64 characters) plus a short prefix (e.g., `ARC:`)
  fits easily within the compute budget.

### 5.2 Anchoring via Memo Program

**Mechanism**: Submit a Solana transaction with a Memo instruction containing
the Chio checkpoint metadata (Merkle root, checkpoint sequence, timestamp).

**Cost**: ~5,000 lamports base fee + optional priority fee. At $120 SOL, this
is approximately $0.0003 per anchor -- roughly 30x cheaper than an L2 EVM
anchor.

**Verification**: A verifier queries the Solana transaction log for the Memo
program, parses the Chio-prefixed data, and compares against the expected
checkpoint root. Solana transaction history is available via RPC and multiple
block explorers.

### 5.3 Anchoring via a Solana Program

For structured data and on-chain queryability, Chio could deploy a small
Solana program (smart contract) that stores anchor records in program-derived
accounts. This would allow direct on-chain reads by other Solana programs.

**Cost**: Higher than Memo (account rent exemption: ~0.002 SOL per anchor
account), but still sub-cent at current prices.

### 5.4 Tradeoffs vs. EVM L2

| Aspect          | EVM L2 (Base)          | Solana                   |
|----------------|------------------------|--------------------------|
| Finality       | ~2s (sequencer)        | ~400ms (optimistic)      |
| Cost           | < $0.01                | < $0.001                 |
| Ecosystem      | EVM tooling, Alloy     | Different tooling, `solana-sdk` |
| Settlement     | Inherits from Ethereum | Independent chain        |
| Rust support   | Alloy (mature)         | `solana-sdk` (mature)    |
| arc-settle tie | Direct (shared chain)  | Requires bridging        |

**Recommendation**: Solana is a strong candidate as an additional anchoring
tier for operators who want the cheapest and fastest anchors. However, it
should not replace the EVM L2 tier because arc-settle (on-chain settlement)
targets EVM chains -- having anchors and settlement on the same chain
simplifies the verification flow for receipt-backed escrow release. Solana
anchoring is best positioned as a third option alongside L2 and Bitcoin,
particularly for operators with high anchor volume who do not need on-chain
settlement integration.

---

## 6. Data Availability Layers

Two emerging data availability (DA) networks are worth evaluating as
alternatives or complements to direct L2 anchoring.

### 6.1 Celestia

**What it is**: A modular blockchain focused exclusively on data availability.
Rollups and applications publish data blobs to Celestia, which guarantees
availability via data availability sampling (DAS). Light nodes can verify DA
without downloading entire blocks.

**Properties**:

- **Blob submission**: Applications submit arbitrary data blobs (up to 2 MB
  per transaction in current mainnet). A 32-byte Merkle root plus metadata
  would be a tiny blob.
- **Cost**: Celestia blob fees are a function of blob size and network
  demand. For a ~100-byte anchor blob, costs are negligible -- well under
  $0.01.
- **Finality**: Celestia blocks are produced every ~12 seconds. Finality is
  provided by the Tendermint consensus (~12 seconds for single-slot
  finality).
- **Verification**: DAS allows light clients to verify blob availability
  with O(sqrt(n)) samples. This is stronger than L2 sequencer confirmation
  but weaker than Bitcoin's proof-of-work.

**Relevance to Chio**: Celestia is an interesting middle ground -- faster
finality than Bitcoin, cheaper than L2, and with stronger availability
guarantees than a single L2 sequencer. However, Celestia adds a new chain
dependency without the ecosystem benefits of EVM (where arc-settle lives) or
the settlement guarantees of Bitcoin. It is best suited for operators who want
high-frequency DA-proven anchoring without paying EVM gas.

**Rust support**: Celestia has a Rust client library (`celestia-node` and
`celestia-types` crates), though the ecosystem is less mature than Alloy.

### 6.2 EigenDA

**What it is**: A data availability layer built on EigenLayer's restaking
mechanism. Secured by ~200 operators and millions of restaked ETH and EIGEN.
Mainnet supports 10 MB/s throughput with ambitions for 100+ MB/s.

**Properties**:

- **Architecture**: Disperser nodes distribute data blobs across EigenDA
  operators using erasure coding. Operators attest to blob availability.
  A DA certificate is posted to Ethereum L1 for verification.
- **Cost**: Lower than Ethereum calldata (the primary cost of L2 DA), with
  pricing set by the restaking market.
- **Integration**: Primarily designed for rollup DA (replacing Ethereum
  calldata). Not a natural fit for single-hash anchoring.

**Relevance to Chio**: EigenDA is overkill for anchoring a 32-byte hash. Its
value proposition is high-throughput DA for rollup block data, not lightweight
timestamping. Unless Chio wants to publish full receipt batches (not just
roots), EigenDA adds complexity without meaningful benefit over a simple L2
storage write. **Not recommended for v1.**

---

## 7. Recommended Contract Design

### 7.1 Minimal Merkle Root Registry

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ArcAnchorRegistry
/// @notice Minimal on-chain registry for ARC receipt log Merkle roots.
contract ArcAnchorRegistry {
    struct Anchor {
        bytes32 merkleRoot;
        uint64  checkpointSeq;
        uint64  batchStartSeq;
        uint64  batchEndSeq;
        uint64  treeSize;
        uint64  issuedAt;
        bytes32 kernelKey; // first 32 bytes of the kernel's Ed25519 pubkey
    }

    /// Emitted when a new Merkle root is anchored.
    event Anchored(
        address indexed operator,
        uint64  indexed checkpointSeq,
        bytes32 merkleRoot,
        uint64  batchStartSeq,
        uint64  batchEndSeq,
        uint64  treeSize,
        uint64  issuedAt,
        bytes32 kernelKey
    );

    /// operator address -> checkpoint_seq -> Anchor
    mapping(address => mapping(uint64 => Anchor)) public anchors;

    /// operator address -> latest checkpoint_seq
    mapping(address => uint64) public latestSeq;

    /// Submit an anchor. Caller is the operator.
    function anchor(
        bytes32 merkleRoot,
        uint64  checkpointSeq,
        uint64  batchStartSeq,
        uint64  batchEndSeq,
        uint64  treeSize,
        uint64  issuedAt,
        bytes32 kernelKey
    ) external {
        require(checkpointSeq > latestSeq[msg.sender], "seq must increase");

        anchors[msg.sender][checkpointSeq] = Anchor({
            merkleRoot:    merkleRoot,
            checkpointSeq: checkpointSeq,
            batchStartSeq: batchStartSeq,
            batchEndSeq:   batchEndSeq,
            treeSize:      treeSize,
            issuedAt:      issuedAt,
            kernelKey:     kernelKey
        });

        latestSeq[msg.sender] = checkpointSeq;

        emit Anchored(
            msg.sender,
            checkpointSeq,
            merkleRoot,
            batchStartSeq,
            batchEndSeq,
            treeSize,
            issuedAt,
            kernelKey
        );
    }

    /// Read the latest anchor for an operator.
    function getLatest(address operator) external view returns (Anchor memory) {
        uint64 seq = latestSeq[operator];
        return anchors[operator][seq];
    }
}
```

### 7.2 Design Decisions

**Multi-operator support**: The contract is keyed by `msg.sender` (the
operator's Ethereum address). Multiple Chio operators can anchor to the same
contract instance without interfering with each other.

**Monotonic sequence enforcement**: `checkpointSeq` must strictly increase per
operator. This prevents replay attacks and ensures the anchor chain is
append-only.

**Event-centric**: The `Anchored` event contains all fields needed for
off-chain indexing. A verifier can reconstruct the full anchor history from
event logs without reading storage (cheaper for light clients).

**No admin/pause**: The contract is stateless from a governance perspective.
No owner, no pause, no upgradability. This matches Chio's fail-closed
philosophy.

**No on-chain proof verification**: The contract does not verify Merkle proofs
on-chain. Proof verification happens off-chain by the verifier, who fetches
the anchored root and checks a receipt's inclusion proof against it. This
keeps the contract minimal and gas-efficient.

**Gas cost analysis**: The `anchor()` function performs:
- One `SSTORE` to a new mapping slot (20,000 gas for cold write)
- One `SSTORE` to update `latestSeq` (5,000 gas for warm write after first
  anchor, 20,000 for the first ever anchor by that operator)
- Event emission with 7 fields (~4,000 gas for topic hashing + log data)
- Calldata cost for the 7 parameters (~2,000 gas)
- Base transaction cost (21,000 gas)

Total: ~47,000-52,000 gas for subsequent anchors by the same operator. On
Base at 0.005 gwei base fee, this is approximately $0.003. The original
estimate of "~45,000 gas" is correct for execution gas but omits the 21,000
base transaction cost; the all-in cost is still well under $0.01.

**Potential concern -- storage growth**: The `anchors` mapping stores a full
`Anchor` struct per operator per checkpoint. For a high-volume operator doing
1,000 checkpoints/day, this creates ~365,000 mapping entries per year. Each
entry is ~7 storage slots. This is not a problem for L2 state size (EVM
state is cheap on L2), but operators should be aware that the on-chain
storage is permanent. An alternative design would emit events only (no
storage writes), reducing gas to ~26,000 per anchor. The tradeoff is that
`getLatest()` would no longer work -- verifiers would need an indexer.

### 7.3 Batch Submission Variant

For operators who want to anchor less frequently but still commit multiple
checkpoints, a batch variant:

```solidity
function anchorBatch(
    bytes32[] calldata merkleRoots,
    uint64[]  calldata checkpointSeqs,
    uint64[]  calldata batchStartSeqs,
    uint64[]  calldata batchEndSeqs,
    uint64[]  calldata treeSizes,
    uint64[]  calldata issuedAts,
    bytes32   kernelKey
) external {
    // Loop and emit individual Anchored events for each entry.
    // Amortizes the base transaction cost over multiple anchors.
}
```

This is useful if an operator is offline for a period and needs to catch up.

**Design note**: The batch function shares a single `kernelKey` across all
entries. This is correct for catch-up scenarios (same kernel), but would not
work if the kernel key rotated mid-batch. A more robust design would accept
`kernelKey` per entry, at the cost of additional calldata.

---

## 8. Rust Ecosystem

### 8.1 EVM Interaction: Alloy

**Crate**: `alloy` (v1.0 stable, released May 2025)

**What it is**: The successor to `ethers-rs`, built by Paradigm. Alloy is the
standard Rust toolkit for EVM interaction. It powers Reth, Foundry, Revm, and
SP1 zkVM.

**Key features for arc-anchor**:

- `sol!` macro: compile-time Solidity parser that generates type-safe Rust
  bindings. Chio can define the `ArcAnchorRegistry` interface directly in Rust
  without ABI JSON files.
- `ProviderBuilder`: connect to any EVM node (Base, Arbitrum, Optimism) with
  a single abstraction.
- Transaction signing and submission with gas estimation.
- 35-60% faster arithmetic than `ethers-rs`; 10x faster ABI encoding.
- Network-generic via the `Network` trait; OP-stack chains supported via
  `op-alloy`.

**Maturity**: Production-ready. Stable 1.0 release. Actively maintained.
`ethers-rs` is officially deprecated in favor of Alloy.

**Example usage for arc-anchor** (conceptual):

```rust
use alloy::sol;

sol! {
    #[sol(rpc)]
    contract ArcAnchorRegistry {
        event Anchored(
            address indexed operator,
            uint64 indexed checkpointSeq,
            bytes32 merkleRoot,
            uint64 batchStartSeq,
            uint64 batchEndSeq,
            uint64 treeSize,
            uint64 issuedAt,
            bytes32 kernelKey
        );

        function anchor(
            bytes32 merkleRoot,
            uint64 checkpointSeq,
            uint64 batchStartSeq,
            uint64 batchEndSeq,
            uint64 treeSize,
            uint64 issuedAt,
            bytes32 kernelKey
        ) external;
    }
}
```

### 8.2 Bitcoin Interaction: rust-bitcoin and BDK

**`bitcoin` crate** (rust-bitcoin):

- Core library for Bitcoin data structures, script building, transaction
  construction, and serialization.
- Supports OP_RETURN output construction.
- Mature and well-maintained. Used by virtually all Bitcoin Rust projects.
- Does not handle wallet operations, UTXO selection, or broadcasting.

**`bdk_wallet` (Bitcoin Dev Kit)** (v2.0):

- Full wallet library built on `rust-bitcoin` and `rust-miniscript`.
- Handles UTXO selection, fee estimation, transaction signing, and
  broadcasting.
- Supports Electrum, Esplora, and compact block filter backends.
- Reached stable 2.0 in 2025 with improved performance and test coverage.
- Suitable for building the Bitcoin anchor path if Chio manages its own UTXO
  set for OP_RETURN transactions.

**`opentimestamps` crate**:

- Rust library for parsing, verifying, and serializing OpenTimestamps proofs.
- Maintained by the official OpenTimestamps project.
- Supports `.ots` file format, calendar interaction, and proof verification.
- If Chio uses the OTS path, this crate handles proof management.

### 8.3 Solana Interaction

**`solana-sdk` crate**:

- Official Rust SDK for interacting with Solana.
- Supports transaction construction, signing, and submission.
- Mature, actively maintained by the Solana Labs / Anza team.
- `spl-memo` crate provides a `build_memo()` helper for constructing Memo
  instructions.

**`solana-client` crate**:

- RPC client for querying Solana state, submitting transactions, and
  confirming results.
- Supports both HTTP and WebSocket transports.

### 8.4 Crate Summary

| Crate              | Purpose                    | Maturity    | Recommended |
|-------------------|----------------------------|-------------|-------------|
| `alloy`           | EVM/L2 contract interaction | Stable 1.0  | Yes         |
| `op-alloy`        | OP-stack (Base/Optimism)    | Stable      | Yes         |
| `bitcoin`         | Bitcoin primitives          | Stable      | Yes         |
| `bdk_wallet`      | Bitcoin wallet operations   | Stable 2.0  | Yes (if direct BTC) |
| `opentimestamps`  | OTS proof handling          | Stable      | Yes (if OTS path) |
| `solana-sdk`      | Solana transaction building | Stable      | Yes (if Solana path) |
| `solana-client`   | Solana RPC client           | Stable      | Yes (if Solana path) |
| `ethers`          | Legacy EVM interaction      | Deprecated  | No          |

---

## 9. Integration Points with Chio

### 9.1 Existing Receipt Infrastructure

Chio's receipt pipeline already provides everything arc-anchor needs:

1. **`ArcReceipt`** (`crates/arc-core/src/receipt.rs`): Signed proof of a
   tool call evaluation. Contains `id`, `timestamp`, `capability_id`,
   `tool_server`, `tool_name`, `decision`, `content_hash`, `policy_hash`,
   `evidence`, `kernel_key`, and `signature`. The `Decision` enum supports
   `Allow`, `Deny`, `Cancelled`, and `Incomplete` variants -- all of which
   generate receipts that should be anchored.

2. **`ChildRequestReceipt`** (`crates/arc-core/src/receipt.rs`): A separate
   receipt type for nested child requests under a parent tool call. These are
   also signed and stored but are tracked in a separate table
   (`arc_child_request_receipts`). Arc-anchor should consider whether child
   receipts are included in checkpoint Merkle trees or tracked separately.
   Currently, `build_checkpoint` in `checkpoint.rs` uses only tool receipts.

3. **`KernelCheckpoint`** (`crates/arc-kernel/src/checkpoint.rs`): Signed
   statement committing a batch of receipts to a Merkle root. Contains:
   - `schema` -- "arc.checkpoint_statement.v1"
   - `checkpoint_seq` -- monotonic counter
   - `batch_start_seq` / `batch_end_seq` -- receipt sequence range
   - `tree_size` -- number of leaves
   - `merkle_root` -- the 32-byte `Hash` to anchor
   - `issued_at` -- Unix timestamp
   - `kernel_key` -- the kernel's signing key
   The checkpoint body is signed via `keypair.sign(&canonical_json_bytes(&body))`.

4. **`MerkleTree`** (`crates/arc-core/src/merkle.rs`): RFC 6962-compatible
   Merkle tree implementation. Supports `from_leaves`, `from_hashes`, `root`,
   and `inclusion_proof`. The `from_hashes` constructor is relevant for
   super-root aggregation (building a tree from checkpoint roots).

5. **`SqliteReceiptStore`** (`crates/arc-store-sqlite/src/receipt_store.rs`):
   Persists receipts and checkpoints. The `kernel_checkpoints` table stores:
   - `checkpoint_seq`, `batch_start_seq`, `batch_end_seq`
   - `tree_size`, `merkle_root`
   - `issued_at`, `statement_json`, `signature`, `kernel_key`

   The store also supports archival via `ATTACH DATABASE` to an archive file,
   with `kernel_checkpoints` duplicated in the archive. Arc-anchor's polling
   must handle the case where old checkpoints have been moved to the archive.

6. **`maybe_trigger_checkpoint`** (`crates/arc-kernel/src/lib.rs`): Triggers
   a checkpoint when `(current_seq - last_checkpoint_seq) >= checkpoint_batch_size`.
   This is the natural hook point for arc-anchor.

### 9.2 Integration Architecture

arc-anchor sits **downstream** of the checkpoint pipeline:

```
Receipt -> Receipt Store -> Checkpoint (every 100 receipts)
                                  |
                           arc-anchor daemon
                           +-------------------+
                           |  Poll new         |
                           |  checkpoints      |
                           |       |           |
                           |  Anchor to L2     |--> Base / Arbitrum
                           |       |           |
                           |  Anchor to Solana |--> Solana (optional)
                           |       |           |
                           |  Aggregate for    |
                           |  Bitcoin anchor   |--> OTS / OP_RETURN
                           |       |           |
                           |  Store anchor     |
                           |  receipts         |--> anchor_records table
                           +-------------------+
```

### 9.3 New Database Table: `anchor_records`

The receipt store needs a new table to track which checkpoints have been
anchored and where:

```sql
CREATE TABLE IF NOT EXISTS anchor_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    checkpoint_seq INTEGER NOT NULL,
    chain TEXT NOT NULL,           -- "base", "arbitrum", "solana", "bitcoin", "ots"
    tx_hash TEXT,                  -- blockchain transaction hash
    block_number INTEGER,          -- block the anchor was confirmed in
    block_hash TEXT,               -- block hash for additional verification
    merkle_root TEXT NOT NULL,     -- the anchored root (for cross-reference)
    status TEXT NOT NULL,          -- "pending", "confirmed", "failed"
    submitted_at INTEGER NOT NULL, -- when we submitted the anchor tx
    confirmed_at INTEGER,          -- when we observed confirmation
    proof_json TEXT,               -- OTS proof or on-chain proof data
    error TEXT,                    -- error message if status = "failed"
    retry_count INTEGER NOT NULL DEFAULT 0,
    last_retry_at INTEGER          -- when we last retried a failed anchor
);

CREATE INDEX IF NOT EXISTS idx_anchor_records_checkpoint
    ON anchor_records(checkpoint_seq);
CREATE INDEX IF NOT EXISTS idx_anchor_records_chain
    ON anchor_records(chain);
CREATE INDEX IF NOT EXISTS idx_anchor_records_status
    ON anchor_records(status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_anchor_records_chain_seq
    ON anchor_records(chain, checkpoint_seq);
```

**Note on migrations**: The `SqliteReceiptStore` currently creates all tables
in its `open()` constructor via `CREATE TABLE IF NOT EXISTS`. Adding the
`anchor_records` table follows the same pattern -- it should be added to the
constructor's `execute_batch` block. No separate migration framework is needed
for SQLite, but the table creation must be idempotent.

### 9.4 Anchor Verification Flow

A third-party verifier who wants to confirm a receipt's integrity:

1. Obtain the `ArcReceipt` and its `ReceiptInclusionProof` from the operator.
2. The inclusion proof references a `checkpoint_seq` and `merkle_root`.
3. Look up the `anchor_record` for that `checkpoint_seq` on the desired chain.
4. Verify the on-chain anchor:
   - **L2**: Read the `Anchored` event from the `ArcAnchorRegistry` contract.
     Confirm the `merkleRoot` matches.
   - **Bitcoin/OTS**: Verify the `.ots` proof against a Bitcoin block header.
     Confirm the committed hash matches the checkpoint's `merkle_root`.
   - **Solana**: Query the Solana transaction log for the Memo instruction.
     Confirm the embedded root matches.
5. Verify the receipt's Merkle inclusion proof against the confirmed root.
   **Critical**: The verifier must use the same RFC 6962-compatible Merkle
   tree algorithm (0x00 leaf prefix, 0x01 node prefix, carry-last-node-up
   for odd levels). A mismatch in tree construction will produce different
   roots.
6. Verify the receipt's Ed25519 signature against the kernel key.

If all checks pass, the verifier has cryptographic proof that:
- The receipt existed when the anchor was created.
- The receipt has not been altered since then.
- The operator's kernel signed the receipt.

**Gap in the verification chain**: The current design does not address how a
verifier discovers which operator's contract and chain to query. A future
extension should define a discovery mechanism -- either a canonical registry
contract address published by Chio, or a DID document extension that lists the
operator's anchor targets.

---

## 10. Recommended Architecture

### 10.1 Crate Structure

```
crates/arc-anchor/
+-- Cargo.toml
+-- src/
|   +-- lib.rs              -- Public API, AnchorConfig, AnchorService
|   +-- evm.rs              -- EVM/L2 anchoring via Alloy
|   +-- bitcoin.rs          -- Bitcoin anchoring (OP_RETURN or OTS)
|   +-- ots.rs              -- OpenTimestamps calendar client
|   +-- solana.rs           -- Solana anchoring via solana-sdk
|   +-- registry.rs         -- On-chain ArcAnchorRegistry bindings (sol! macro)
|   +-- types.rs            -- AnchorRecord, AnchorStatus, ChainTarget
|   +-- verification.rs     -- Anchor proof verification logic
|   +-- super_root.rs       -- Multi-checkpoint aggregation for Bitcoin
+-- tests/
    +-- evm_anchor.rs
    +-- bitcoin_anchor.rs
    +-- solana_anchor.rs
```

### 10.2 Configuration

```rust
pub struct AnchorConfig {
    /// Which chains to anchor to. At least one required.
    pub targets: Vec<ChainTarget>,

    /// How many checkpoints to accumulate before anchoring to Bitcoin.
    /// Example: 10 means one Bitcoin anchor per 1,000 receipts
    /// (at the default checkpoint_batch_size of 100).
    pub bitcoin_aggregation_factor: u64,

    /// EVM anchoring: anchor every N checkpoints. Default: 1 (every checkpoint).
    pub evm_anchor_interval: u64,

    /// Solana anchoring: anchor every N checkpoints. Default: 1 (every checkpoint).
    pub solana_anchor_interval: u64,

    /// Maximum retry attempts for failed anchors.
    pub max_retries: u32,

    /// Backoff base duration (milliseconds) for retry logic.
    pub retry_backoff_base_ms: u64,

    /// Path to the operator's EVM signing key (for L2 transactions).
    pub evm_signer_key_path: Option<PathBuf>,

    /// Bitcoin wallet configuration (for direct OP_RETURN).
    pub bitcoin_wallet_config: Option<BitcoinWalletConfig>,

    /// OTS calendar server URLs (for OpenTimestamps path).
    pub ots_calendar_urls: Vec<String>,

    /// Solana RPC URL and signer keypair path.
    pub solana_config: Option<SolanaAnchorConfig>,
}

pub enum ChainTarget {
    Base { rpc_url: String, contract_address: Address },
    Arbitrum { rpc_url: String, contract_address: Address },
    Optimism { rpc_url: String, contract_address: Address },
    BitcoinOpReturn { rpc_url: String },
    OpenTimestamps { calendar_urls: Vec<String> },
    Solana { rpc_url: String },
}
```

### 10.3 Anchoring Daemon Lifecycle

1. **Startup**: Read `anchor_records` table to determine the last anchored
   `checkpoint_seq` per chain.
2. **Poll loop**: Periodically query `kernel_checkpoints` for new checkpoints
   with `checkpoint_seq > last_anchored_seq`.
3. **EVM anchor**: For each new checkpoint (or batch per `evm_anchor_interval`),
   call `ArcAnchorRegistry.anchor()` on each configured L2.
4. **Solana anchor** (if configured): For each new checkpoint (or batch per
   `solana_anchor_interval`), submit a Memo transaction.
5. **Bitcoin aggregation**: Accumulate checkpoint roots. When
   `bitcoin_aggregation_factor` checkpoints have been collected, compute a
   "super-root" (Merkle root of the checkpoint roots) and submit to Bitcoin
   via OTS or OP_RETURN.
6. **Confirmation tracking**: Monitor transaction receipts. Update
   `anchor_records` status from `pending` to `confirmed` when the on-chain
   transaction is finalized.
7. **OTS proof upgrade**: For OTS anchors, periodically check whether
   incomplete proofs have been upgraded to Bitcoin commitments. Update the
   `proof_json` field when the upgrade is available.
8. **Retry logic**: Failed submissions are retried with exponential backoff
   up to `max_retries`. Each retry increments `retry_count` and updates
   `last_retry_at` in the `anchor_records` table.

### 10.4 Super-Root Aggregation for Bitcoin

Since Bitcoin anchoring is expensive relative to L2, Chio should aggregate
multiple checkpoint roots before anchoring:

```
Checkpoint 101: root_101
Checkpoint 102: root_102
  ...
Checkpoint 110: root_110

Super-root = MerkleTree::from_hashes([root_101, ..., root_110]).root()

Anchor super-root to Bitcoin.
```

A verifier can then prove a specific checkpoint's inclusion in the super-root
using a standard Merkle inclusion proof, and then prove a receipt's inclusion
in that checkpoint's tree. This is a two-level Merkle proof.

**Implementation note**: The `MerkleTree::from_hashes` constructor in
`arc-core/src/merkle.rs` already accepts `Vec<Hash>` and produces a tree
whose root can serve as the super-root. The `inclusion_proof` method generates
the audit path. This means the super-root aggregation logic is a thin wrapper
around existing Chio primitives -- no new Merkle code is needed.

### 10.5 Fail-Closed Semantics

Consistent with Chio's design philosophy:

- Anchor failures do NOT block the receipt pipeline. Receipts continue to be
  signed and checkpointed regardless of anchor status.
- Failed anchors are logged and retried, but never silently dropped.
- The `anchor_records` table provides a complete audit trail of anchor
  attempts, including failures.
- Operators can configure alerting on anchor failures via the existing
  compliance report infrastructure.
- If all configured anchor targets fail simultaneously for an extended period,
  the daemon should log a critical-severity alert but must not halt checkpoint
  production.

### 10.6 Cost Model

**Typical operator** (1,000 tool invocations/day):

- 10 checkpoints/day (at batch size 100)
- 10 L2 anchors/day: 10 x $0.005 = **$0.05/day**
- 10 Solana anchors/day: 10 x $0.0003 = **$0.003/day**
- 1 Bitcoin anchor/day (via OTS): **$0.00/day** (public calendar)
- Or 1 Bitcoin OP_RETURN/day: **$0.10-$1.00/day** depending on fees

**High-volume operator** (100,000 tool invocations/day):

- 1,000 checkpoints/day
- 1,000 L2 anchors/day: 1,000 x $0.005 = **$5/day**
- 1,000 Solana anchors/day: 1,000 x $0.0003 = **$0.30/day**
- 10 Bitcoin anchors/day (via OTS): **$0.00/day**
- Or 1 aggregated Bitcoin OP_RETURN/day: **$0.10-$1.00/day**

**Hidden costs not included above**:

- RPC endpoint fees: Alchemy/Infura charge $49-399/month for production tiers.
  Self-hosted nodes eliminate this but require infrastructure.
- EVM gas funding: The operator's Ethereum address needs ETH on each L2 for
  gas. At $0.005/anchor and 1,000 anchors/day, this is $5/day -- but the
  operator must pre-fund the address and monitor the balance.
- Solana SOL funding: Similarly, the Solana signer needs SOL. At the volumes
  above, the balance draw is negligible.

---

## 11. Compliance and Legal Value

### 11.1 SOC 2 Relevance

SOC 2 Type II reports assess controls over a period of time and require
evidence of log integrity, change detection, and audit trail completeness. The
Trust Services Criteria (TSC) relevant to arc-anchor include:

- **CC7.2 (System Operations)**: Requires monitoring for unauthorized
  changes. Blockchain-anchored Merkle roots provide tamper-evident proof that
  the audit log has not been modified.
- **CC8.1 (Change Management)**: Requires controls to detect unauthorized
  changes. An anchor chain creates an independent, immutable reference point.
- **CC6.1 (Logical and Physical Access Controls)**: Requires audit logging
  of access. Chio's signed receipts satisfy this; anchoring strengthens the
  non-repudiation claim.

Blockchain anchors do not replace SOC 2 controls but provide **additional
evidence** that auditors can cite as a compensating or strengthening control.
The value is highest when the anchor is on a public, independently verifiable
chain (Bitcoin or Ethereum L1) rather than a permissioned ledger.

### 11.2 ISO 27001 Relevance

ISO 27001:2022 Annex A control **A.12.4.2 (Protection of log information)**
requires protection against tampering and unauthorized access. Blockchain
anchoring directly supports this control by providing cryptographic evidence
that logs have not been retroactively modified.

### 11.3 eIDAS and Qualified Timestamps

The EU's eIDAS regulation recognizes "qualified electronic time stamps" as
having legal effect equivalent to paper timestamps. A qualified timestamp
requires issuance by a Qualified Trust Service Provider (QTSP). Bitcoin
anchoring does not satisfy eIDAS requirements on its own (no QTSP
involvement), but it can complement a QTSP-issued timestamp by providing an
independent corroboration layer. Some European enterprises may find value in a
dual approach: QTSP for legal standing, blockchain for tamper evidence.

### 11.4 Practical Value

The most concrete compliance value of arc-anchor is in **audit defense**:
when a regulator or counterparty questions whether an agent's audit trail has
been backdated or altered, the operator can point to a specific Bitcoin block
or L2 transaction and prove that the Merkle root was published at a known
time. This shifts the burden of proof -- the challenger must now argue that
the blockchain itself was manipulated, which is infeasible for Bitcoin and
extremely difficult for major L2s.

---

## 12. Open Questions

### 12.1 Protocol Design

1. **Should arc-anchor be in-process or a separate daemon?** Running as a
   background task within the Chio kernel keeps the architecture simple, but
   coupling blockchain I/O to the kernel introduces latency risk. A separate
   daemon process that reads from the receipt store is cleaner but adds
   operational complexity. **Recommendation**: A separate daemon (or at least
   a separate async task with its own tokio runtime) is preferable. The
   kernel should remain focused on capability evaluation and receipt signing.
   Blockchain I/O is inherently unreliable (RPC timeouts, gas estimation
   failures, chain reorganizations) and should not pollute the kernel's
   critical path.

2. **Should the on-chain contract store the full checkpoint metadata or just
   the root?** Storing only `(checkpointSeq, merkleRoot)` minimizes gas.
   Storing the full `Anchor` struct costs more but makes on-chain queries
   richer. The recommended design above includes full metadata because L2
   storage is cheap enough. An events-only variant (no storage writes) is
   also viable for operators who prioritize cost over on-chain queryability.

3. **Should Chio publish a canonical contract address per chain?** If Chio
   deploys a single registry contract on each supported L2, any operator can
   anchor to it. This creates a shared public good. Alternatively, each
   operator could deploy their own contract instance. **Recommendation**: A
   canonical shared contract is strongly preferred. It simplifies verifier
   tooling, enables cross-operator anchor discovery, and reduces deployment
   burden for operators.

4. **Cross-chain root aggregation**: Should the L2 anchors themselves be
   periodically aggregated and anchored to Bitcoin? This would provide
   a single Bitcoin proof covering all L2 anchors in a window. This aligns
   with the super-root pattern described in section 10.4.

### 12.2 Key Management

5. **EVM signing key**: The operator needs an Ethereum-compatible signing key
   to submit L2 transactions. Should this be derived from the kernel's
   Ed25519 key, or should it be a separate secp256k1 key? (Derivation is
   non-trivial since Ed25519 and secp256k1 are different curves.)
   **Note**: The arc-settle research doc recommends maintaining a secondary
   secp256k1 key with a binding certificate signed by the Ed25519 key. The
   same key and binding could be reused for arc-anchor, avoiding a third key.

6. **Gas funding**: The operator's EVM address needs ETH to pay gas on each
   L2. How should this be managed? Options include: pre-funding with manual
   monitoring, a paymaster contract (ERC-4337 account abstraction), or a
   bundler service. The arc-anchor daemon should monitor the signer's balance
   and alert when it falls below a configurable threshold.

### 12.3 Verification

7. **Proof format**: What is the canonical format for an "anchor proof" that
   a verifier can independently check? It should include the receipt, the
   inclusion proof, the checkpoint statement, and the on-chain anchor
   reference (tx hash + chain).

8. **Light client verification**: Can a verifier check an L2 anchor without
   running a full node? On optimistic rollups, the verifier trusts the
   sequencer for recent state but can verify against L1 after the challenge
   period (~7 days). On Solana, a verifier can query any public RPC endpoint.
   On Bitcoin (via OTS), the verifier needs access to block headers but not
   the full chain.

### 12.4 Implementation Priorities

9. **Phase 1**: L2 anchoring only (Base, via Alloy). This covers the primary
   use case (fast, cheap, tamper-evidence) and validates the integration
   pattern.

10. **Phase 2**: Bitcoin anchoring via OpenTimestamps. Adds the "ultimate
    settlement" layer.

11. **Phase 3**: Direct OP_RETURN for operators who want to self-custody their
    Bitcoin anchoring without depending on OTS calendars.

12. **Phase 4**: EAS integration as an optional output for cross-protocol
    attestation interoperability.

13. **Phase 5**: Solana anchoring for high-throughput operators who want
    sub-second finality at minimal cost.

---

## 13. Cross-Integration Dependencies

Arc-anchor does not exist in isolation. It shares infrastructure, contracts,
and design patterns with the other two planned on-chain extensions:
**arc-settle** (on-chain settlement) and **arc-link** (oracle and cross-chain
integration).

### 13.1 Shared Contract: ArcReceiptVerifier (arc-settle)

The arc-settle research doc proposes an `ArcReceiptVerifier` contract with a
`publishRoot(root, batchTimestamp, receiptCount)` function. This contract is
functionally equivalent to the `ArcAnchorRegistry` proposed in this document
-- both store Merkle roots on-chain for later verification.

**Recommendation**: These should be the **same contract** or at least share
the same root storage. If arc-settle's `ArcEscrow` contract verifies
Merkle proofs against a published root, and arc-anchor independently publishes
roots to a different contract, verifiers face a confusing dual-root situation.
A unified `ArcAnchorRegistry` contract should serve both purposes:

- arc-anchor publishes roots for tamper-evidence (audit use case).
- arc-settle's escrow contracts read roots from the same registry for
  conditional fund release (settlement use case).
- arc-link's Automation triggers can push to the same registry.

The contract interface should be the union of both requirements:
```
ArcAnchorRegistry.anchor()     -- called by arc-anchor daemon
ArcAnchorRegistry.getLatest()  -- read by arc-settle's ArcEscrow
ArcAnchorRegistry.anchors()    -- read by arc-settle's Merkle proof verification
```

### 13.2 Shared Chain Selection

All three research docs converge on **Base** as the primary L2:
- arc-anchor: Base for low-cost Merkle root storage.
- arc-settle: Base for USDC escrow and settlement (native USDC, x402 ecosystem).
- arc-link: Chainlink feeds available on Base; Automation deployed on Base.

This convergence is beneficial -- a single L2 reduces the operator's gas
funding requirements (one ETH balance instead of three) and simplifies the
verification flow (one chain to query). The operator's EVM address can
be shared across all three crates.

### 13.3 Shared Key Management

The arc-settle doc proposes a dual-signing approach: Ed25519 for Chio-native
signing, secp256k1 for on-chain evidence. The secp256k1 key is bound to the
Ed25519 key via a certificate.

Arc-anchor needs an EVM signing key to submit anchor transactions. If this is
the same secp256k1 key used by arc-settle, the operator manages two keys
total (Ed25519 + secp256k1) rather than three. The key binding certificate
should cover both use cases.

### 13.4 Chainlink Automation (arc-link)

The arc-link research doc proposes using Chainlink Automation (time-based
CRON triggers) to periodically anchor Merkle roots. This is an alternative to
arc-anchor's daemon-based polling approach.

**Comparison**:

| Aspect | arc-anchor daemon | Chainlink Automation |
|--------|------------------|---------------------|
| Trigger | Poll-based (configurable interval) | CRON schedule |
| Liveness | Depends on daemon uptime | Depends on Chainlink DON |
| Cost | Daemon infrastructure only | Automation fee ($0.01-0.10/exec) |
| Flexibility | Full control over retry logic | Limited to Automation API |
| Ed25519 access | Direct (reads from receipt store) | Requires off-chain API + Functions |

**Recommendation**: For Phase 1, use the daemon approach (simpler, no external
dependency). Chainlink Automation is a valid alternative for operators who
want to avoid running a persistent process, but it introduces a dependency on
Chainlink's DON and requires exposing a receipt batch API that Chainlink
Functions can call. This is a Phase 4+ consideration.

### 13.5 Merkle Root as Settlement Precondition

In arc-settle's "Flow B: Batch Merkle Settlement," the escrow contract
verifies receipt inclusion via Merkle proofs against a published root. This
means **root publication is a liveness requirement for batch settlement** --
if the arc-anchor daemon goes down and stops publishing roots, batch
settlements halt.

This has implications for the fail-closed design:
- arc-anchor's publish failure should be treated as a critical alert, not
  just an audit concern.
- arc-settle should have a fallback path (dual-signing / direct release)
  for high-priority settlements when roots are unavailable.
- The `anchor_records` table should be queried by arc-settle to determine
  whether a root has been published before accepting a Merkle proof claim.

### 13.6 Integration Dependency Graph

```
arc-core (MerkleTree, Receipt, Hash)
    |
    +-- arc-kernel (Checkpoint, build_checkpoint)
    |       |
    |       +-- arc-anchor (publish roots, track anchors)
    |       |       |
    |       |       +-- ArcAnchorRegistry.sol (shared with arc-settle)
    |       |
    |       +-- arc-settle (escrow, bond, Merkle proof verification)
    |       |       |
    |       |       +-- ArcEscrow.sol (reads roots from ArcAnchorRegistry)
    |       |       +-- ArcBondVault.sol
    |       |
    |       +-- arc-link (oracle, Automation triggers)
    |               |
    |               +-- Chainlink Automation (alternative root publisher)
    |               +-- Chainlink Functions (Ed25519 batch verification)
    |
    +-- arc-store-sqlite (receipt_store, kernel_checkpoints, anchor_records)
```

---

## 14. Reviewer Notes

This section documents changes made during technical review (2026-03-30).

### Corrections

1. **Merkle tree algorithm specificity**: Added detailed description of Chio's
   RFC 6962-compatible Merkle tree construction (0x00 leaf prefix, 0x01 node
   prefix, carry-last-node-up for odd levels) to the executive summary and
   verification flow. The original document did not mention this, which is a
   critical detail -- a verifier using a different tree construction would
   reject valid proofs.

2. **OP_RETURN size context**: Clarified the distinction between Bitcoin
   Core's `datacarriersize` (raised to 100,000 in v30.0 for non-standard
   transactions) and the per-output relay limit (still 80 bytes). Also noted
   that Chio's 36-byte payload fits within Bitcoin Knots' default 40-byte
   limit, which is relevant given the Knots/OCEAN controversy.

3. **Gas cost breakdown**: The original "~45,000 gas" estimate for the
   anchor() function was execution gas only. Added a full breakdown including
   the 21,000-gas base transaction cost, yielding a more accurate ~47,000-
   52,000 total. The USD cost conclusion (< $0.01) is unchanged.

4. **Checkpoint source verification**: Verified that `KernelCheckpointBody`
   in `crates/arc-kernel/src/checkpoint.rs` contains exactly the fields
   described (schema, checkpoint_seq, batch_start_seq, batch_end_seq,
   tree_size, merkle_root, issued_at, kernel_key). The `Hash` type is from
   `arc_core::hashing`, not a raw `[u8; 32]`. The contract's `bytes32` maps
   correctly via `Hash::as_bytes()`.

5. **ChildRequestReceipt gap**: The original document only discussed
   `ArcReceipt` but the codebase also has `ChildRequestReceipt` (for nested
   child requests). Added a note in section 9.1 about whether child receipts
   should be included in checkpoint trees.

6. **Receipt store archival**: Added a note about the archive table for
   `kernel_checkpoints` that exists in the SQLite store. Arc-anchor's polling
   must handle archived checkpoints gracefully.

### New Sections

7. **Section 5 (Solana Anchoring)**: Added analysis of Solana as an
   anchoring target. Solana offers ~30x cost reduction vs. EVM L2 and
   sub-second finality. The Memo program provides a zero-deployment-cost
   anchoring mechanism. Positioned as a third tier alongside L2 and Bitcoin.

8. **Section 6 (Data Availability Layers)**: Added analysis of Celestia
   and EigenDA. Celestia is a reasonable alternative for high-frequency DA
   anchoring. EigenDA is overkill for hash anchoring and not recommended.

9. **Section 11 (Compliance and Legal Value)**: Added analysis of SOC 2,
   ISO 27001, and eIDAS relevance. Blockchain anchors strengthen compliance
   posture but do not replace traditional audit controls.

10. **Section 13 (Cross-Integration Dependencies)**: Added analysis of how
    arc-anchor interacts with arc-settle and arc-link. Key finding: the
    `ArcAnchorRegistry` and `ArcReceiptVerifier` should be the same contract
    to avoid dual-root confusion.

### Deepened Analysis

11. **OpenTimestamps reliability**: Added detailed information from Peter
    Todd's January 2025 blog post about OTS compatibility with Bitcoin Knots
    and OCEAN mining pool policies. Added operational details about calendar
    server dependencies and proof upgrade lifecycle.

12. **L2 finality nuance**: Added a subsection in 4.1 distinguishing
    sequencer confirmation, L1 data posting, and challenge period expiry as
    three levels of L2 "finality." The original document treated L2 finality
    as a single concept.

13. **Storage growth concern**: Added analysis of the storage implications of
    the `anchors` mapping for high-volume operators, and suggested an
    events-only variant as an alternative.

14. **Verification discovery gap**: Noted that the document does not address
    how verifiers discover which contract and chain to query for a given
    operator's anchors.

15. **Hidden cost analysis**: Added RPC endpoint fees and gas pre-funding to
    the cost model.

16. **AI/agent audit trail landscape**: Researched whether any existing
    projects do Merkle root anchoring for AI/agent audit trails. Found none
    in production. Noted Chio's first-mover position.

17. **Super-root implementation note**: Added observation that
    `MerkleTree::from_hashes` already supports the super-root aggregation
    pattern, so no new Merkle code is needed.

---

## References

### Protocols and Standards

- OpenTimestamps -- https://opentimestamps.org/
- OpenTimestamps (Wikipedia) -- https://en.wikipedia.org/wiki/OpenTimestamps
- Peter Todd on OTS and Knots/OCEAN -- https://petertodd.org/2025/opentimestamps-and-knots-ocean
- Chainpoint -- https://chainpoint.org/
- Ethereum Attestation Service -- https://attest.org/
- EAS Documentation -- https://docs.attest.org/
- EAS Contracts (GitHub) -- https://github.com/ethereum-attestation-service/eas-contracts
- Ceramic Network -- https://ceramic.network/

### Bitcoin Technical References

- BIP 341 (Taproot) -- https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
- OP_RETURN -- https://www.spark.money/glossary/op-return
- Bitcoin Transaction Fees -- https://bitcoinfees.net/

### EVM and L2 References

- Base Network Fees -- https://docs.base.org/base-chain/network-information/network-fees
- Optimism EAS Contracts -- https://docs.optimism.io/chain/identity/contracts-eas
- L2 Gas Fee Markets (2025 Statistics) -- https://coinlaw.io/gas-fee-markets-on-layer-2-statistics/
- Ethereum Merkle Proofs for Offline Data Integrity -- https://ethereum.org/developers/tutorials/merkle-proofs-for-offline-data-integrity/

### Solana References

- Solana Fees -- https://solana.com/docs/core/fees
- Solana Memo Program -- https://spl.solana.com/memo
- solana-sdk crate -- https://crates.io/crates/solana-sdk
- spl-memo crate -- https://crates.io/crates/spl-memo

### Data Availability References

- Celestia -- https://celestia.org/what-is-celestia/
- EigenDA -- https://www.eigenda.xyz/

### Compliance References

- SOC 2 Trust Services Criteria -- https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2
- ISO 27001:2022 -- https://www.iso.org/standard/27001
- eIDAS Regulation -- https://digital-strategy.ec.europa.eu/en/policies/eidas-regulation

### Rust Crates

- Alloy v1.0 (Paradigm) -- https://www.paradigm.xyz/2025/05/introducing-alloy-v1-0
- Alloy Documentation -- https://alloy.rs/
- Alloy (GitHub) -- https://github.com/alloy-rs/alloy
- rust-bitcoin -- https://crates.io/crates/bitcoin
- Bitcoin Dev Kit (BDK) -- https://bitcoindevkit.org/
- BDK (GitHub) -- https://github.com/bitcoindevkit/bdk
- rust-opentimestamps (GitHub) -- https://github.com/opentimestamps/rust-opentimestamps
- opentimestamps crate -- https://crates.io/crates/opentimestamps

### Chio Source References

- `crates/arc-core/src/receipt.rs` -- ArcReceipt, ChildRequestReceipt, Decision, ToolCallAction
- `crates/arc-core/src/merkle.rs` -- MerkleTree, MerkleProof (RFC 6962)
- `crates/arc-core/src/hashing.rs` -- Hash type, SHA-256 utilities
- `crates/arc-kernel/src/checkpoint.rs` -- KernelCheckpoint, KernelCheckpointBody, build_checkpoint, ReceiptInclusionProof
- `crates/arc-store-sqlite/src/receipt_store.rs` -- SqliteReceiptStore, kernel_checkpoints table
- `crates/arc-kernel/src/lib.rs` -- maybe_trigger_checkpoint, checkpoint_batch_size, DEFAULT_CHECKPOINT_BATCH_SIZE (100)

### Cross-Document References

- `docs/research/CHIO_SETTLE_RESEARCH.md` -- ArcReceiptVerifier, ArcEscrow, dual-signing, Merkle commitment settlement
- `docs/research/CHIO_LINK_RESEARCH.md` -- Chainlink Automation for periodic anchoring, Functions for Ed25519 batch verification
