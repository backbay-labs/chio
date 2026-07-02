# Chio Token Invariants (One-Pager)

Date: 2026-07-02. Status: brainstorm, decision-support.
Scope: hard invariants ANY future Chio token must satisfy. They bind every phase of the
existing gate (no-token -> credit -> staking -> governance, M0-M6 in
`CHIO-TOKEN-AND-CONTRACTS-PLAN.md`) and the Chio Pass posture in
`CHIO-BENEVOLENT-TOKEN-DESIGN.md`. Sources: `CHIO-TOKEN-EXTERNAL-LANDSCAPE-2026-07.md`,
the Kite/Virtuals teardown, and the five-mechanism grounded brainstorm.
Framing: fail-closed; a violation is a design rejection, not a trade-off. Nothing here is
legal advice; legal-adjacent rows are questions for counsel, not conclusions (Section 2).

## 1. Invariants

1. **The token is never in the payment or settlement path, permanently.** No required
   settlement asset, no forced pairing, no mandatory token denomination anywhere.
   Why: Kite settles in stablecoins yet skims a commission on every agent transaction into
   open-market KITE buys (https://kite.foundation/tokenomics); Virtuals force-pairs every
   agent token against VIRTUAL with LP locked 10 years, the core of its extraction
   reputation (https://whitepaper.virtuals.io/about-virtuals/capital-formation-layer/virtuals-launch-mechanics.md).
   Binds: `spec/PROTOCOL.md` settlement, USDC-only `ChioEscrow`/`ChioBondVault`, the x402
   adapter (`crates/kernel/chio-kernel/src/payment.rs`, `crates/economy/chio-settle/src/payments.rs`).

2. **No fee-to-buyback loop.** Protocol fee revenue is never converted into open-market
   token buys or "continuous buy pressure"; any holder value ties to disclosed real revenue.
   Why: Kite's Phase 2 does exactly this (https://kite.foundation/tokenomics), and Virtuals'
   buyback/burn accrual collapsed with a 97% revenue drop (https://ownyourmind.ai/projects/virtuals/).
   Counsel question: does manufactured price support read as Howey profit expectation?
   Binds: no fee leg exists today in the x402 flow; any Phase-3 `FeeRouter`/`ChioTreasury`.

3. **No stake-to-serve.** Providers, builders, and module operators never post token
   collateral as a precondition to activate or serve; bonds stay voluntary USDC self-restitution.
   Why: Kite makes module owners lock KITE to activate services, taxing the supply side
   before it earns anything (https://www.binance.com/en-BH/square/post/32974338471593).
   Binds: operator admission; `ChioBondVault` remains self-slash-only opt-in collateral.

4. **No forfeiture of gifted value (never regress the gift).** Gifted tokens are freely
   claimable and sellable; claiming never voids future distributions; the free baseline
   (Pass tier_0 feeds, free trust-feed reads, day-zero compute allotment) only improves.
   Why: Kite's piggy bank permanently voids all future emissions to any address that claims
   and sells, turning a gift into a threat (https://www.gate.com/crypto-wiki/article/what-is-the-kite-token-economic-model-and-how-does-it-support-ai-agent-payments).
   Binds: Chio Pass refresh-on-genuine-use gates NEW allotment only, never claws back.

5. **Published community-allocation composition, per-bucket on-chain addresses.** The exact
   split (usage gifts vs grants vs liquidity) is itemized at TGE with verifiable addresses.
   Why: Kite's 48% "community" is un-itemized foundation discretion; the only disclosed
   slices are a 1.5% Binance Launchpool and 0.5% marketing, and trackers contradict the
   official unlock terms (https://kite.foundation/tokenomics vs https://dropstab.com/coins/kite-2/vesting).
   Binds: anchor the composition digest in `ChioRootRegistry` so drift is provable.

6. **Usage-earned continuous distribution, no calendar cliffs.** Community supply streams
   per epoch against Merkle-proven metered usage; nothing unlocks on a date.
   Why: KITE's calendar unlocks are recurring negative catalysts (-3.8% on the June 2026
   $12.35M unlock, -13% on an unlock warning) (https://coinmarketcap.com/top-stories/6a1e521ce1de341d4442b1d3/);
   the loved precedents are retroactive usage gifts (https://coingape.com/education/uniswap-airdrop-case-study/).
   Binds: eligibility proven against published roots via `ChioRootRegistry.verifyInclusion`
   over signed receipt/metering history; no published farmable formula pre-snapshot.

7. **Honest float at TGE.** Circulating supply is high relative to FDV with small insider
   overhang; no debut whose story is a future unlock wall.
   Why: KITE's $929M FDV against $179M float is the market's top cited sell-off fear and
   the token sits -67% from ATH (https://coinmarketcap.com/cmc-ai/kite/price-analysis/).
   Binds: M6 gate input; model float against KITE's unlock calendar as the baseline.

8. **Live non-speculative utility at TGE, or no TGE.** The token does real protocol work on
   day one (e.g. burn-to-credit into the closed-loop prepaid projection, per Helium Data
   Credits, https://docs.helium.com/tokens/data-credit/); "utility later" phases fail this gate.
   Why: KITE deferred gas/staking/governance to Phase 2 mainnet and hit its all-time low the
   day after listing (https://www.binance.com/en-BH/square/post/32974338471593).
   Binds: M6 is conditional and may never fire; the Phase-1 escrow-socketed credit is the sink.

9. **Penalty and anti-abuse proceeds never accrue to insiders.** Slash, tax, or sniper-trap
   proceeds go to harmed parties or the community fund, never team wallets.
   Why: Virtuals routes sniper-tax buybacks to the team wallet (3-month cliff, 9-month
   vest), so insiders profit from abuse (https://whitepaper.virtuals.io/about-virtuals/capital-formation-layer/virtuals-launch-mechanics.md).
   Binds: `ChioBondVault` slash beneficiaries; M4 `ChioSlashableBondVault` restitution routes
   to buyers via the partner of record, per the comptroller `market_slash` lane.

10. **No discretionary emergency intervention; circuit breakers are predeclared.** Dispute
    conditions and settlement prices are written ex ante into contracts and ADRs, with no
    override path, and never a settlement price that turns protocol loss into protocol profit.
    Why: Hyperliquid's JELLY intervention force-settled at the attacker's entry price,
    flipping a $13.5M loss into ~$700k profit and drawing "FTX 2.0" criticism
    (https://www.coindesk.com/markets/2025/03/26/hyperliquid-delists-jellyjelly-after-vault-squeezed-in-usd13m-tussle).
    Binds: escrow dispute handling and the M4 slashing/adjudication ADRs (anti-JELLY policy).

11. **Recompute-only projections for any token-adjacent balance; no chain RPC in the TCB.**
    Holdings- or stake-gated behavior enters the kernel only as a signed attestation through
    the existing `chio-credentials` verification path, never a live balance call; balances
    and weights are deterministic projections over already-signed truth, fail-closed on
    inconsistency.
    Why: internal precedent, the M2 closed-loop prepaid VIEW (`chio-credit` `prepaid.rs`)
    and the determinism boundary in `crates/economy/chio-settle/ARCHITECTURE.md`; breaking
    it puts RPC trust and consensus liveness inside the trusted computing base.
    Binds: every mechanism in the five-mechanism brainstorm; kernel `budget_store` metering.

12. **Genesis constraints, recorded now so fundraising cannot erode them.** No VC or
    market-maker allocation; community share strictly greater than insider share; roughly
    1-year insider cliff plus multi-year linear vest; live product with real non-artificial
    volume before TGE.
    Why: Hyperliquid's genesis (31% to users, zero VC/MM, ~1-year contributor cliff) is the
    goodwill benchmark (https://forklog.com/en/hype-or-a-new-standard-what-hyperliquids-airdrop-historys-most-generous-teaches-us/);
    Kite's investor-first debut (32% insiders, no user gift, $883M FDV) is the counterexample
    (https://www.coindesk.com/business/2025/11/03/ai-payments-startup-kite-debuts-token-with-usd263m-trading-volume-in-first-two-hours).
    Binds: the M6 design freeze; Hyperliquid is a reference only, never a venue (standing
    constraint: Chio deploys only on Solana/Base/ETH).

13. **No future-token promises pre-token, in any channel.** Points-like language, snapshot
    hints, and public telemetry that implies a future drop are all in scope of the
    no-future-value recital.
    Why: EigenLayer's points program became "the largest information asymmetry in crypto"
    and a broken social contract at drop (https://www.coindesk.com/tech/2024/05/09/eigenlayers-eigen-airdrop-might-signal-demise-of-once-popular-points).
    Binds: Pass issuance terms, comms policy, and all externally visible metrics.

## 2. Counsel questions raised by these invariants (questions, not conclusions)

- Invariant 2: does any fee-linked value accrual (even burn) create Howey profit expectation?
- Invariants 6, 12: does a retroactive gift over Pass-era usage re-characterize the Pass as
  the consideration leg of an integrated scheme, and what may be distributed to US persons?
- Invariant 8: does burn-to-credit (Helium-style) alter the closed-loop prepaid exemption
  analysis already gating Phase 1?
- Invariant 13: what points-adjacent language, if any, is safe before a safe harbor exists?
