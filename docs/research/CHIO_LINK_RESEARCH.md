# arc-link v1: Price Oracle Integration for Chio Budget Enforcement

Status: Research
Authors: Engineering
Date: 2026-03-30

> Realization status (2026-04-02): this research fed the shipped bounded
> `arc-link` runtime, but the authoritative runtime boundary is now
> [CHIO_LINK_PROFILE.md](../standards/CHIO_LINK_PROFILE.md) plus
> [CHIO_WEB3_PROFILE.md](../standards/CHIO_WEB3_PROFILE.md). For shipped chain
> inventory and receipt-side FX authority, prefer
> `docs/standards/CHIO_LINK_BASE_MAINNET_CONFIG.json` and
> `authority = arc_link_runtime_v1`. The adjacent backlog topics remain in
> [CHIO_LINK_FUTURE_TRACKS.md](./CHIO_LINK_FUTURE_TRACKS.md).

---

## 1. Executive Summary

Chio's economic substrate enforces multi-currency monetary budgets on capability tokens. The `MonetaryAmount` type (defined in `crates/arc-core/src/capability.rs`) supports arbitrary currency codes (USD, EUR, USDC, ETH), and the kernel charges costs in minor-unit integers against per-grant caps. However, when a grant's budget is denominated in one currency (e.g., USD) and the tool server settles in another (e.g., ETH), the kernel has no native mechanism for currency conversion. The `ExposureLedgerSupportBoundary` already models this gap explicitly: `cross_currency_netting_supported: false`.

**arc-link** is the crate that bridges Chio's off-chain Rust kernel with oracle infrastructure to solve one problem well:

**Price feeds for cross-currency budget enforcement.** A USD-denominated grant must be able to gate an ETH-denominated tool invocation. This requires a reliable, timely ETH/USD exchange rate.

**Scope boundary.** This document covers only the off-chain price oracle integration needed for kernel-level budget enforcement. Adjacent integration topics -- CCIP for cross-chain delegation, Chainlink Functions for Ed25519 verification, Chainlink Automation for receipt anchoring, and the x402 protocol -- are documented separately in [CHIO_LINK_FUTURE_TRACKS.md](./CHIO_LINK_FUTURE_TRACKS.md).

**Key findings:**

- For off-chain price consumption in Rust, the recommended path is reading Chainlink aggregator contracts via `alloy` RPC calls with local staleness caching. Pyth's pull model is a strong secondary option for lower-latency use cases.
- Chainlink's Data Streams product (pull-based, sub-second) should be evaluated as a premium tier for latency-sensitive budget enforcement. An official Rust SDK exists (`chainlink-data-streams-sdk` v1.2.1 on crates.io).
- Multi-oracle aggregation (Chainlink primary + Pyth fallback, with circuit-breaker) follows battle-tested DeFi patterns (Aave, MakerDAO/Sky, GMX).
- Oracle manipulation and flash loan attacks are a material risk vector. The kernel must defend against them with TWAP smoothing and cross-oracle divergence detection.
- All sample configurations target **Base Mainnet** (chain ID 8453), consistent with arc-anchor and arc-settle chain selection.

---

## 2. Chainlink Data Feeds

### 2.1 Architecture

Chainlink Data Feeds use a decentralized aggregation model with three layers:

1. **Oracle nodes.** Independent node operators fetch off-chain data (exchange prices, etc.) and submit reports.
2. **Aggregator contracts.** On-chain smart contracts that collect node reports, compute a median, and store the result. Each feed has a dedicated aggregator.
3. **Proxy contracts.** Stable-address proxies that point to the current aggregator. Consumers interact with proxies so that aggregator upgrades are transparent.

Consumers read feeds through the **AggregatorV3Interface**:

```solidity
function latestRoundData() external view returns (
    uint80 roundId,
    int256 answer,       // price in the feed's base denomination
    uint256 startedAt,
    uint256 updatedAt,   // timestamp of last update -- critical for staleness
    uint80 answeredInRound
);

function decimals() external view returns (uint8);
function description() external view returns (string memory);
```

Updates are triggered by two conditions (whichever fires first):
- **Deviation threshold**: the off-chain aggregate deviates from the on-chain value by more than X%.
- **Heartbeat interval**: a maximum time between updates regardless of price movement.

### 2.2 Base Mainnet Feed Addresses (Verified)

These addresses are verified against data.chain.link as of 2026-03-30.

| Pair | Proxy Address | Deviation | Heartbeat | Decimals |
|------|--------------|-----------|-----------|----------|
| ETH/USD | `0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70` | 0.15% | ~5 min | 8 |
| BTC/USD | `0x64c911996D3c6aC71f9b455B1E8E7266BcbD848F` | 0.1% | ~3 min | 8 |
| USDC/USD | `0x7e860098F58bBFC8648a4311b374B1D669a2bc6B` | 0.3% | ~19 hr | 8 |
| LINK/USD | `0x17CAb8FE31E32f08326e5E27412894e49B0f9D65` | 0.5% | ~24 hr | 8 |

Note: Base Mainnet feeds have tighter deviation thresholds and shorter heartbeats for volatile assets (ETH, BTC) compared to Ethereum Mainnet, reflecting cheaper L2 gas costs. Stablecoin feeds (USDC/USD) have wider heartbeats because the price rarely deviates.

For crypto/crypto pairs (e.g., ETH/USDC), compose ETH/USD and USDC/USD. Chainlink does not generally provide direct crypto/crypto feeds; composition through USD is the standard pattern.

### 2.3 Consuming Feeds from Rust (Off-Chain)

There is no dedicated Rust Chainlink SDK for Data Feeds. The standard approach is to call the aggregator contract's `latestRoundData()` via an EVM RPC call using the `alloy` crate (v1.0, released May 2025, successor to `ethers-rs`).

```rust
use alloy::sol;

sol! {
    interface AggregatorV3Interface {
        function latestRoundData() external view returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );
        function decimals() external view returns (uint8);
    }
}

// Usage
let provider = ProviderBuilder::new().on_http(rpc_url);
let aggregator = AggregatorV3Interface::new(feed_address, &provider);
let (round_id, answer, started_at, updated_at, answered_in_round) =
    aggregator.latestRoundData().call().await?;
let decimals = aggregator.decimals().call().await?;
```

The `alloy::sol!` macro generates Rust bindings from the ABI. Multicall batching (supported by alloy) allows reading multiple feeds in a single RPC round-trip.

### 2.4 Costs

Reading Chainlink Data Feeds is **free for off-chain consumers**. There is no subscription or API key required. You pay only for the RPC endpoint you use to read blockchain state.

### 2.5 Risks and Limitations

- **Staleness.** The heartbeat guarantees a maximum age, but during that window the price could move significantly. The kernel must implement staleness checks: reject any price where `block.timestamp - updatedAt > max_acceptable_age`.
- **Oracle failure.** If the Chainlink network stops updating a feed, stale prices persist indefinitely. The kernel must have a fallback policy (deny if stale, or fall back to a secondary oracle).
- **L2 sequencer uptime.** On L2 chains, the sequencer can go down. Chainlink provides L2 Sequencer Uptime Feeds that should be checked before trusting L2 price data.
- **Feed availability.** Not all pairs exist on all chains. The kernel's price resolution logic must handle missing feeds gracefully.

---

## 3. Chainlink Data Streams (Low-Latency Pull Oracle)

### 3.1 Architecture

Chainlink Data Streams is a separate product from Data Feeds, designed for latency-sensitive applications. It uses a **pull-based** design:

1. A Decentralized Oracle Network (DON) signs price reports off-chain at sub-second intervals.
2. Reports are delivered to consumers off-chain (via WebSocket or REST).
3. The consumer submits the signed report on-chain in the same transaction that uses the price, where it is verified cryptographically.

### 3.2 Report Schemas

Data Streams supports multiple report formats:

| Schema | Asset Class | Key Fields |
|--------|------------|------------|
| Crypto Advanced (v3) | Cryptocurrency | `price`, `bid`, `ask` (LWBA) |
| RWA Standard (v8) | Real-world assets | `midPrice`, `marketStatus`, `lastUpdateTimestamp` |
| RWA Advanced (v11) | Real-world assets | `mid`, `bid`, `ask`, `bidVolume`, `askVolume`, `lastTradedPrice` |

The Crypto Advanced schema includes Liquidity-Weighted Bid and Ask (LWBA) prices, which provide a pricing spread reflecting actual order book depth. This is more informative than a single mid price for budget enforcement decisions.

### 3.3 Rust SDK

Chainlink provides an official Rust SDK for Data Streams:

- **`chainlink-data-streams-sdk`** (v1.2.1 on crates.io) -- client SDK for consuming Data Streams feeds.
- **`chainlink-data-streams-report`** (v1.2.1 on crates.io) -- report parsing and verification.

Source: [github.com/smartcontractkit/data-streams-sdk/rust](https://github.com/smartcontractkit/data-streams-sdk/tree/main/rust). Last updated December 2025.

This is the only official Chainlink product with a maintained Rust SDK. For arc-link, this means Data Streams integration could be cleaner than the alloy-based Data Feeds approach, at the cost of requiring a Chainlink subscription.

### 3.4 Chio Relevance

- **Sub-second resolution** is valuable for volatile-asset budget enforcement where Data Feeds' heartbeat (minutes) is too coarse.
- **LWBA spreads** can feed into risk-aware budget enforcement: a wide bid-ask spread could trigger more conservative (lower) price assumptions for cross-currency conversion.
- **Cost model**: Data Streams requires a subscription (unlike the free Data Feeds). This makes it a premium tier for high-value or latency-sensitive use cases, not a wholesale replacement for Data Feeds.

### 3.5 Limitations

- Requires a Chainlink subscription and integration with the Streams verifier network.
- Currently focused on crypto and RWA assets -- fiat FX pairs (EUR/USD, GBP/USD) may still require Data Feeds.
- More complex integration than a simple `latestRoundData()` call.

---

## 4. Pyth Network (Secondary Oracle)

### 4.1 Architecture

Pull oracle. Data providers (exchanges, market makers) publish signed price updates to **Pythnet** (a Solana-based appchain). The off-chain **Hermes** service aggregates these and exposes them via REST API and WebSocket streams.

### 4.2 Key Characteristics

- **Update frequency:** 400ms (vs Chainlink Data Feeds' heartbeat-dependent minutes to hours).
- **Fee model:** No subscription fee for Hermes API access. Consumer pays gas only if submitting on-chain.
- **Confidence intervals:** Each price update includes a confidence band, useful for risk-aware budget enforcement.
- **Feed coverage:** 500+ price feeds including crypto, equities, FX, and commodities.

### 4.3 Base Mainnet Pyth Feed IDs (Verified)

These IDs are verified against the Hermes API as of 2026-03-30.

| Pair | Feed ID |
|------|---------|
| ETH/USD | `0xff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace` |
| BTC/USD | `0xe62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43` |
| USDC/USD | `0xeaa020c61cc479712813461ce153894a96a6c00b21ed0cfc2798d1f9a9e9c94a` |

### 4.4 Consuming from Rust

The `pyth-sdk-rs` repository primarily contains Solana on-chain crates. The last substantive update was August 2025 (v0.10.6), with a deprecation notice directing users toward newer products (Pyth Lazer). For Chio's off-chain kernel, the Hermes REST API is the practical consumption path:

```rust
// Fetch latest ETH/USD price from Hermes
let url = format!(
    "https://hermes.pyth.network/v2/updates/price/latest?ids[]={}",
    ETH_USD_FEED_ID
);
let response: PythPriceUpdate = reqwest::get(&url).await?.json().await?;
```

A simple `reqwest`-based client avoids taking a dependency on the Solana runtime.

### 4.5 Limitations

- **Hermes is a centralized bottleneck.** If Hermes goes down, the kernel loses access to Pyth prices entirely. Unlike Chainlink's on-chain feeds, which persist their last value in contract storage, Hermes availability is a real-time dependency. Chio must treat Hermes as a fallback, not a sole source.
- Pyth's data providers are first-party (exchanges themselves), which is both a strength (low latency, direct data) and a risk (provider collusion is theoretically easier than Chainlink's node operator network).
- Less battle-tested for high-value DeFi than Chainlink (though TVS is growing rapidly).

### 4.6 Chio Relevance

- Pyth's 400ms updates are ideal for volatile-asset budget enforcement where Chainlink's heartbeat is too coarse.
- The pull model aligns well with Chio's off-chain kernel: the kernel fetches the price only when it needs to enforce a cross-currency budget.
- Confidence intervals can be mapped to Chio's risk tiers -- wider confidence could trigger more conservative budget enforcement.

---

## 5. Alternative Oracle Networks (Summary)

This section provides a brief assessment of other oracle networks for completeness. None are recommended for v1, but they inform the trait design.

| Network | Model | Update Latency | Feed Count | Rust SDK | v1 Candidate? |
|---------|-------|---------------|------------|----------|---------------|
| RedStone | Modular (pull/push/ERC-7412) | On-demand | 1300+ | No | No -- JavaScript-only integration |
| API3 | First-party (Airnode) | Sec-min | 200+ | No | No -- OEV architecture in transition |
| UMA | Optimistic (challenge-based) | Hours | N/A | No | No -- too slow for price feeds |
| Chronicle | Push (Schnorr/MuSig2) | Minutes | 100+ | No | No -- narrow ecosystem (MakerDAO/Sky) |
| Flare FTSOv2 | Enshrined (protocol-level) | ~1.8s | 1000 | No | No -- requires Flare chain |

**Key takeaway:** No alternative oracle has a Rust SDK or a compelling advantage over Chainlink + Pyth for Chio's specific use case (off-chain price reads from a Rust kernel targeting Base). The `PriceOracle` trait should be generic enough to support any backend, but v1 ships with Chainlink and Pyth only.

---

## 6. Off-Chain Price Consumption Strategy

### 6.1 Option A: Chainlink Feeds via RPC (Primary)

**Approach:** The Rust kernel calls `latestRoundData()` on Chainlink aggregator contracts via an EVM RPC endpoint using `alloy`.

**Pros:**
- Most battle-tested source. Chainlink secures $20B+ in TVS.
- No API key required. Just an RPC endpoint.
- Data is on-chain and cryptographically committed.

**Cons:**
- Requires an RPC endpoint (Alchemy, Infura, or self-hosted node).
- Price staleness bounded by heartbeat.
- Single point of failure if the RPC endpoint is down.

### 6.2 Option B: Pyth Hermes API (Secondary)

**Approach:** The Rust kernel fetches prices from Pyth's Hermes REST API.

**Pros:**
- 400ms update frequency -- dramatically fresher than Chainlink's heartbeat.
- Simple to consume from Rust (`reqwest`).
- Includes confidence intervals.

**Cons:**
- Hermes is a centralized service.
- If Hermes goes down, the kernel loses price access.

### 6.3 Option C: Multi-Oracle Aggregation

**Approach:** The kernel reads from multiple oracles and uses a median or circuit-breaker pattern.

**DeFi precedent:**
- Aave uses Chainlink as primary with Pyth as fallback on certain chains.
- MakerDAO (Sky) uses Chronicle as primary with Chainlink as a secondary circuit-breaker.
- GMX uses a "fast price" from Chainlink Data Streams with a reference price from Chainlink Data Feeds, rejecting trades where the two diverge beyond a threshold.
- The standard pattern is median-of-three or primary-with-circuit-breaker, not weighted average.

### 6.4 Option D: Local Price Cache with Periodic Refresh

**Approach:** The kernel maintains an in-process price cache. A background task periodically fetches from oracles and updates the cache. Budget enforcement reads from the cache.

**Pros:**
- Decouples budget enforcement latency from oracle latency.
- The kernel never blocks on an RPC call during tool invocation.
- Staleness is explicitly tracked in the cache entry.

**Cons:**
- Prices can be stale between refresh intervals.
- Must handle cache miss (no price available at all) gracefully.

### 6.5 Recommendation

**For v1: Option D (local cache) backed by Option A (Chainlink RPC) as primary and Option B (Pyth Hermes) as secondary.**

The kernel should:
1. Run a background `PriceRefresher` task that polls Chainlink feeds via alloy every 60 seconds (configurable).
2. If Chainlink is stale (beyond heartbeat) or unavailable, fall back to Pyth Hermes.
3. Store each price with its `updated_at` timestamp and source.
4. On budget enforcement, read from the cache. If the price is older than `max_price_age` (configurable per currency pair), deny the invocation with a clear error: "cross-currency budget enforcement failed: stale price for ETH/USD".
5. Expose the cache state in the operator report for observability.
6. **Circuit-breaker:** If Chainlink and Pyth report prices that diverge by more than a configurable threshold (e.g., 5%), deny cross-currency invocations and alert the operator. This protects against oracle manipulation or data feed divergence during market dislocations.

This pattern matches Chio's existing architectural principle of fail-closed enforcement with operator visibility.

### 6.6 Global Staleness Scenario

**What happens if all oracle sources go stale simultaneously?**

This is a real risk during network-wide events: an L2 sequencer outage could stale Chainlink feeds on that L2; a Hermes infrastructure failure could take out Pyth globally; and mass network congestion could delay updates across multiple providers.

The kernel's response must be deterministic:
1. If the cached price age exceeds `max_price_age`, cross-currency budget enforcement is **denied** (fail-closed).
2. Same-currency budget enforcement (USD grant + USD tool cost) continues unaffected -- no oracle needed.
3. The operator report surface should clearly distinguish "oracle stale" from "budget exhausted" denials.
4. An optional "grace mode" could be configured per-operator: during a total oracle blackout, the kernel could apply a pessimistic exchange rate (e.g., the last known rate minus 10% for volatility buffer) for a configurable grace window (e.g., 5 minutes). This prevents a total operational shutdown while maintaining conservative budget enforcement.

---

## 7. Oracle Manipulation Defenses

### 7.1 Spot Price Manipulation

Chainlink Data Feeds are resistant to spot manipulation because they aggregate across many independent nodes and exchanges. However, Pyth's first-party model (exchanges self-report) has a smaller trust set. A colluding group of exchanges could temporarily move Pyth's reported price.

**Chio-specific risk:** An attacker could manipulate a price feed to make a cheap tool invocation appear more expensive (draining the grant budget faster) or make an expensive invocation appear cheap (exceeding the grant's intended spending limit).

### 7.2 Flash Loan Price Oracle Attacks

Classic DeFi flash loan attacks exploit spot-price oracles by manipulating DEX prices. Chio's off-chain kernel is inherently resistant to atomic flash loan attacks because the kernel reads prices from on-chain aggregators (not DEX spot prices), and the read + budget enforcement + tool invocation sequence is not atomic with any on-chain transaction. However, DEX-based oracle sources or Data Streams' DEX State Price feeds could be vulnerable.

### 7.3 TWAP vs Spot for Budget Enforcement

Using spot prices introduces volatility risk: a brief price spike could cause an invocation to pass budget checks at an anomalous rate.

**Recommendation:** The kernel's price cache should support an optional **time-weighted average price (TWAP)** mode:
- Maintain a circular buffer of the last N price observations (e.g., 10 observations over 10 minutes).
- Use the TWAP rather than the latest spot price for cross-currency conversion.
- TWAP smooths out transient price movements and is more resistant to manipulation.
- For stablecoin pairs (USDC/USD, USDT/USD), spot is sufficient since deviation from peg is the signal, not the absolute price.

### 7.4 Oracle Extractable Value (OEV)

OEV is the value that can be extracted by controlling the timing and ordering of oracle price updates -- analogous to MEV but specific to oracle-dependent operations.

For Chio, OEV manifests as: if a price update would trigger a budget exhaustion or cause a delegation bond to become undercollateralized, the entity controlling update timing can front-run affected transactions.

**Mitigations:**
- Use Chainlink's push-based feeds where update timing is determined by the decentralized DON, not by any single party.
- If using Pyth's pull model (where the consumer controls when to submit the price on-chain), ensure the kernel always uses the most recent available price, not a cherry-picked historical one.

---

## 8. Kernel Integration

### 8.1 Current Budget Flow

The kernel's `check_and_increment_budget` method in `crates/arc-kernel/src/lib.rs` currently:

1. Iterates matching grants sorted by specificity.
2. For monetary grants, reads `max_cost_per_invocation` and `max_total_cost` from the `ToolGrant`.
3. Extracts currency from either `max_cost_per_invocation` or `max_total_cost` (with a fallback default of "USD").
4. Calls `budget_store.try_charge_cost()` with raw `u64` units.
5. All arithmetic is in the grant's native currency (no conversion).

The gap: when `max_total_cost.currency = "USD"` but the tool server reports cost in `"ETH"`, the kernel has no way to convert. The budget store operates entirely in the grant's native currency units and has no oracle awareness.

### 8.2 Proposed PriceOracle Trait

```rust
pub trait PriceOracle: Send + Sync {
    /// Get the exchange rate from `base` to `quote`.
    /// Returns the rate as a rational (numerator, denominator) to avoid floating point.
    /// For ETH/USD at $3000, returns (3000_00, 1) with USD in cents.
    fn get_rate(
        &self,
        base: &str,
        quote: &str,
    ) -> Result<ExchangeRate, PriceOracleError>;
}

pub struct ExchangeRate {
    pub base: String,
    pub quote: String,
    pub rate_numerator: u128,
    pub rate_denominator: u128,
    pub decimals: u8,
    pub updated_at: u64,
    pub source: String,
    pub max_age_seconds: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum PriceOracleError {
    #[error("no feed configured for {base}/{quote}")]
    NoPairAvailable { base: String, quote: String },
    #[error("price stale: age {age_seconds}s exceeds max {max_age_seconds}s for {pair}")]
    Stale { pair: String, age_seconds: u64, max_age_seconds: u64 },
    #[error("oracle sources diverge by {divergence_pct:.2}% for {pair} (threshold: {threshold_pct:.2}%)")]
    CircuitBreakerTripped { pair: String, divergence_pct: f64, threshold_pct: f64 },
    #[error("oracle backend unavailable: {0}")]
    Unavailable(String),
}
```

### 8.3 Kernel Injection

The `PriceOracle` trait is injected into `ArcKernel` as an optional dependency, following the same pattern as `BudgetStore`:

```rust
pub struct ArcKernel {
    // ... existing fields ...
    budget_store: Box<dyn BudgetStore>,
    price_oracle: Option<Box<dyn PriceOracle>>,  // new
}
```

When `price_oracle` is `None`, the kernel behaves exactly as today: cross-currency invocations are denied because no conversion is possible. This preserves backward compatibility and the fail-closed invariant.

### 8.4 Conversion Step

The conversion inserts between "extract currency from grant" and "call budget_store.try_charge_cost()":

```rust
// In check_and_increment_budget, after extracting grant currency:
let effective_cost_units = if tool_currency != grant_currency {
    let oracle = self.price_oracle.as_ref()
        .ok_or(KernelError::NoCrossCurrencyOracle)?;
    let rate = oracle.get_rate(&tool_currency, &grant_currency)?;
    convert_units(tool_cost_units, &rate)?
} else {
    tool_cost_units
};
```

### 8.5 Integer Arithmetic for Currency Conversion

All Chio monetary amounts are `u64` minor units. The exchange rate must be applied as a rational number (numerator/denominator) to avoid floating-point precision loss:

```
Tool cost: 10^15 wei (0.001 ETH)
ETH/USD rate: 3000.00 (represented as 300000 / 100)
USD cost: 10^15 * 300000 / (10^18 * 100) = 3 USD = 300 cents
```

The `convert_units` function must:
- Perform multiplication before division to maximize precision.
- Use `u128` intermediates to prevent overflow for reasonable values.
- Check for overflow at each intermediate step.
- Round up (ceiling division) when converting to the budget currency, to maintain the conservative (fail-closed) invariant -- the grant holder never gets more purchasing power than intended.

### 8.6 Receipt Evidence

Oracle prices used for cross-currency conversion should be signed and included in receipts as evidence. The receipt's `metadata` field should include:
- The price used for conversion.
- Its source (Chainlink, Pyth).
- Its `updated_at` timestamp.

This makes the economic decision auditable and enables post-hoc verification.

### 8.7 ExposureLedger Cross-Currency Netting

With arc-link providing exchange rates, `ExposureLedgerSupportBoundary.cross_currency_netting_supported` can be flipped to `true`. The exposure ledger would:

1. Normalize all currency positions to a common reporting currency (USD by default).
2. Use oracle prices at the time of each receipt to compute the normalized amount.
3. Store both the original and normalized amounts in `ExposureLedgerReceiptEntry`.

### 8.8 Credit Scorecard Implications

Oracle integration enables:
- Cross-currency netting in credit scoring.
- Capital allocation decisions that consider multi-currency exposure.
- Risk-adjusted credit bands that account for currency volatility.

### 8.9 Delegation Bond Pricing

When `GovernedAutonomyTier::Delegated` requires a delegation bond (`requires_delegation_bond() == true`), the bond amount may be denominated differently from the delegated capability's budget. Oracle pricing enables:
- Bond requirements specified in a stable currency (USD) for delegations over volatile-asset budgets.
- Real-time bond adequacy checks during delegation chain validation.

---

## 9. Cross-Integration Dependencies

### 9.1 arc-link <-> arc-anchor

**Shared dependency: alloy.** Both arc-link and arc-anchor use alloy for EVM interaction. They should share provider configuration (RPC endpoint, chain ID) to avoid redundant connections.

**Chain selection alignment.** arc-anchor recommends Base as the primary L2 for anchoring. arc-link's oracle consumption defaults to Base's Chainlink feeds for consistency.

### 9.2 arc-link <-> arc-settle

**Oracle prices for settlement currency conversion.** arc-settle handles stablecoin escrow and conditional release. When a grant is denominated in USD but the tool server settles in ETH (or vice versa), arc-link provides the exchange rate needed to:
- Calculate the correct escrow amount at deposit time.
- Verify that the released amount matches the receipt's cost after currency conversion.
- Evaluate bond collateral adequacy in the `ArcBondVault` contract.

**Capital execution rail mapping.** arc-settle introduces `CapitalExecutionRailKind::OnChain`. The `CapitalExecutionRail` includes a `jurisdiction` field that maps to CAIP-2 chain identifiers. arc-link's oracle configuration must cover every chain where arc-settle operates.

### 9.3 Shared Configuration Surface

All three crates share configuration elements that should be unified:

| Config Element | Used By | Notes |
|---------------|---------|-------|
| RPC endpoint(s) | All three | Use the same provider pool |
| Chain ID | All three | Must agree on target chain (Base: 8453) |
| Operator Ethereum address | arc-anchor, arc-settle | Same operator identity |
| Chainlink feed addresses | arc-link, arc-settle | arc-link is the source of truth |
| ArcAnchorRegistry address | arc-anchor, arc-settle | arc-settle reads roots from arc-anchor's registry |

---

## 10. Implementation Plan

### 10.1 Crate Structure

```
crates/
  arc-link/
    src/
      lib.rs             # PriceOracle trait definition + ExchangeRate types
      chainlink.rs       # Chainlink Data Feeds reader via alloy
      pyth.rs            # Pyth Hermes client via reqwest
      cache.rs           # Local price cache with staleness tracking + TWAP
      circuit_breaker.rs # Cross-oracle divergence detection
      convert.rs         # Integer-safe currency conversion arithmetic
      config.rs          # Feed registry, staleness policy, chain config
    Cargo.toml           # deps: alloy, reqwest, tokio, thiserror
```

### 10.2 Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `alloy` | 1.x | EVM contract calls for Chainlink feed reads |
| `reqwest` | 0.12+ | HTTP client for Pyth Hermes API |
| `tokio` | 1.x | Async runtime for background price refresh |
| `thiserror` | 2.x | Error types |
| `serde` / `serde_json` | 1.x | Config and Hermes response deserialization |

Optional (for Data Streams premium tier):
| `chainlink-data-streams-sdk` | 1.2.x | Official Chainlink Data Streams client |
| `chainlink-data-streams-report` | 1.2.x | Report parsing and verification |

### 10.3 Configuration

```toml
[price_oracle]
primary = "chainlink"
fallback = "pyth"
refresh_interval_seconds = 60
max_price_age_seconds = 600
circuit_breaker_divergence_pct = 5.0
exchange_rate_margin_pct = 2.0
twap_enabled = true
twap_window_seconds = 600

[price_oracle.chainlink]
chain_id = 8453  # Base Mainnet
rpc_endpoint = "https://base-mainnet.g.alchemy.com/v2/..."
feeds = [
    { pair = "ETH/USD", address = "0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70", decimals = 8 },
    { pair = "BTC/USD", address = "0x64c911996D3c6aC71f9b455B1E8E7266BcbD848F", decimals = 8 },
    { pair = "USDC/USD", address = "0x7e860098F58bBFC8648a4311b374B1D669a2bc6B", decimals = 8 },
    { pair = "LINK/USD", address = "0x17CAb8FE31E32f08326e5E27412894e49B0f9D65", decimals = 8 },
]

[price_oracle.pyth]
hermes_url = "https://hermes.pyth.network"
feeds = [
    { pair = "ETH/USD", id = "0xff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace" },
    { pair = "BTC/USD", id = "0xe62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43" },
    { pair = "USDC/USD", id = "0xeaa020c61cc479712813461ce153894a96a6c00b21ed0cfc2798d1f9a9e9c94a" },
]
```

### 10.4 Phased Delivery

**Phase 1: Core trait + Chainlink backend**
- `PriceOracle` trait definition.
- `ChainlinkFeedReader` backend using alloy.
- Local cache with staleness tracking.
- Integration into kernel's `check_and_increment_budget`.
- Fail-closed on stale or missing prices.
- Unit tests with mocked feeds.

**Phase 2: Pyth fallback + circuit-breaker**
- `PythHermesClient` backend.
- Primary/fallback logic in cache.
- Circuit-breaker for cross-oracle divergence.
- TWAP circular buffer.
- Operator report surface for cache state.

**Phase 3: Exposure ledger + credit integration**
- Enable `cross_currency_netting_supported` in exposure ledger.
- Store both original and normalized amounts in receipt entries.
- Cross-currency credit scorecard.

**Phase 4 (optional): Data Streams premium tier**
- Integrate `chainlink-data-streams-sdk`.
- LWBA-aware budget enforcement (use bid for pessimistic conversion).
- Subscription management.

---

## 11. Open Questions

### 11.1 Trust Boundary

Chio's existing trust model places the kernel in the TCB. Introducing an oracle dependency moves the trust boundary. Questions:

- **Should oracle prices be signed and included in receipts?** Recommendation: yes. This makes economic decisions auditable.
- **If a price feed was wrong, should receipts be challengeable?** This is where UMA integration (future track) becomes relevant.
- **Does the kernel need to validate the oracle's on-chain consensus?** For v1, `latestRoundData()` plus staleness check is sufficient. Deep consensus validation adds complexity with marginal security gain given Chainlink's track record.

### 11.2 Currency Pair Coverage

Chio's `MonetaryAmount.currency` is a free-form string. Not every currency pair has an oracle feed.

- **Should the kernel maintain a registry of supported cross-currency pairs?** Yes. The `price_oracle.feeds` configuration is this registry.
- **What happens when a grant uses a currency with no oracle feed?** Fail-closed. `PriceOracle::get_rate` returns `NoPairAvailable`, and the kernel denies the invocation.
- **Should grant issuance validate currency feed availability?** Recommended. The Capability Authority should warn (but not block) when issuing a grant with a currency not in the oracle registry.

### 11.3 Settlement Currency Mismatch

- **Who bears the exchange rate risk?** The grant issuer (who set the USD cap). The kernel applies the conversion conservatively (round up when converting to grant currency) to protect the issuer.
- **Should the kernel apply a safety margin?** Yes. The configurable `exchange_rate_margin_pct` (default 2%) buffers against price movement between budget check and actual settlement.
- **Should `BudgetChargeResult` record both original and converted amounts?** Yes. Essential for reconciliation.

### 11.4 Gas Cost Projections

| Operation | Estimated Cost (Base) | Frequency |
|-----------|----------------------|-----------|
| Read price feed (off-chain) | Free (RPC only) | Per invocation |

At steady state, arc-link v1 incurs zero on-chain costs. All oracle reads are off-chain RPC calls. The only recurring cost is the RPC endpoint itself (Alchemy free tier covers ~300M compute units/month, sufficient for frequent polling).

---

## 12. References

### Chainlink
- [Data Feeds Documentation](https://docs.chain.link/data-feeds)
- [Data Feeds API Reference](https://docs.chain.link/data-feeds/api-reference)
- [Data Feeds Architecture](https://docs.chain.link/architecture-overview/architecture-overview)
- [Using Data Feeds on EVM Chains](https://docs.chain.link/data-feeds/using-data-feeds)
- [Data Streams Overview](https://docs.chain.link/data-streams)
- [Data Streams Report Schemas](https://docs.chain.link/data-streams/reference/report-schema-overview)
- [Data Streams LWBA Prices](https://docs.chain.link/data-streams/concepts/liquidity-weighted-prices)
- [Data Streams Rust SDK](https://github.com/smartcontractkit/data-streams-sdk/tree/main/rust)
- [Base ETH/USD Feed](https://data.chain.link/feeds/base/mainnet/eth-usd)
- [Base BTC/USD Feed](https://data.chain.link/feeds/base/mainnet/btc-usd)
- [Base USDC/USD Feed](https://data.chain.link/feeds/base/mainnet/usdc-usd)

### Pyth Network
- [Pull Oracle Architecture](https://docs.pyth.network/price-feeds/core/pull-updates)
- [Hermes Service](https://docs.pyth.network/price-feeds/core/how-pyth-works/hermes)
- [Price Feed IDs](https://docs.pyth.network/price-feeds/core/price-feeds/price-feed-ids)
- [Best Practices](https://docs.pyth.network/price-feeds/core/best-practices)
- [Pyth Rust SDK](https://github.com/pyth-network/pyth-sdk-rs)

### Alloy (Rust EVM Toolkit)
- [Alloy v1.0 Announcement](https://www.paradigm.xyz/2025/05/introducing-alloy-v1-0)
- [Alloy GitHub](https://github.com/alloy-rs/alloy)
