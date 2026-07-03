# Chio Token - Securities Counsel Briefing Packet (Preparation Only)

Date: 2026-07-02. Status: PREPARATION ONLY. This document is not legal advice and reaches
no legal conclusions; it assembles facts, reference cases, and QUESTIONS for securities
counsel, and the founder (a US person) decides if and when any of it goes. Format mirrors
the M2 fail-closed gate package (`docs/release/M2-GATE-PACKAGE.md` on `chio/m2-build`):
each mechanism is a gate, every gate is BLOCKED-EXTERNAL, and the house invariant holds:
FAIL-CLOSED, every gate defaults to NO until counsel answers. Sources:
`CHIO-TOKEN-EXTERNAL-LANDSCAPE-2026-07.md` (Sections 4 and 6) and its research sweeps.

## 0. Cover note: what needs NO counsel gate to prototype

Three mechanisms rank lowest on securities surface and can be prototyped now (devnet and
internal only, nothing public, no announcement):

1. **Stake-weighted attestation.** Utility staking with no yield leg: writing weighted
   trust signals requires a bond in the token-generic `ChioBondVault` (self-slash-only,
   stake returned at expiry); reads of all trust feeds stay free per the Pass design.
2. **Bond collateral.** A future CHIO as `BondTerms.token` / `EscrowTerms.token` in the
   existing immutable contracts; collateral, not investment, no reward emission.
3. **Points with no token-promise language.** Usage-based points scoring net fees paid
   (Hyperliquid copy-list rank 1), anti-sybil rules, and ZERO token-promise language in
   any program text, telemetry, or comms (the EigenLayer lesson).

Caveats: "no counsel gate to prototype" is not "no counsel ever"; each still gets a
counsel pass before anything public, and adding any yield or reward leg moves it below.

## 1. Gate index

| Gate | Mechanism | Status |
|------|-----------|--------|
| TOK-GATE-RB | Settlement rebates (holdings-scaled vs usage-scaled-with-cap) | BLOCKED-EXTERNAL |
| TOK-GATE-AD | Retroactive airdrop to US persons (incl. announcement timing) | BLOCKED-EXTERNAL |
| TOK-GATE-VLT | Pooled underwriting / credits vault | BLOCKED-EXTERNAL |
| TOK-GATE-STK | Staking emissions yield | BLOCKED-EXTERNAL |
| TOK-GATE-BB | Fee-funded buyback / burn | BLOCKED-EXTERNAL |

All BLOCKED-EXTERNAL: none can be resolved by code. Each closes only on a counsel answer.

## 2. TOK-GATE-RB: settlement rebates

**Mechanism.** Active users receive a share of settlement activity back as spendable Chio
usage credit, landing in the M2-17 closed-loop prepaid VIEW (USD-denominated,
non-transferable, refund-to-original-funder-only). Two variants: rebate tier scaled by
CHIO holdings or stake, versus rebate scaled by the user's own usage with a holdings cap.

**Reference facts.** Hyperliquid staking tiers grant trading-fee discounts from 5% (10+
HYPE) to 40% (500k+ HYPE), added May 2025
(https://hyperliquid.gitbook.io/hyperliquid-docs/hypercore/staking). Helium Data Credits
are the
non-transferable USD-pegged usage-unit precedent ($0.00001, single-user, minted only by
burning HNT) (https://docs.helium.com/tokens/data-credit/). Note: no protocol fee leg
exists in Chio's x402 flow today; any rebate base is future work.

**Questions for counsel.** (a) Does a holdings-scaled rebate read as a dividend-like
profit expectation under Howey, even paid in non-transferable prepaid credit rather than
cash? (b) Is usage-scaled-with-cap materially lower surface, and where is the line?
(c) Does the Helium-style non-transferable credit destination change the analysis?

**Engineering gated.** The fee-point design (where a fee leg and rebate base enter the
x402/settlement path), the rebate recompute-only projection, and any tier attestation
into the kernel. The audit documenting that no fee leg exists today is not gated.

## 3. TOK-GATE-AD: retroactive airdrop to US persons

**Mechanism.** A genesis distribution gifted free to entities with Merkle-proven genuine
historical usage in the receipt log, claimable against already-published
`ChioRootRegistry` roots, insiders excluded, tiers skewed to small users; nothing sold.

**Reference facts.** Hyperliquid genesis (2024-11-29): 310M of 1B (31%) to 94,000+ users
pro rata to points, no claim step, zero VC/exchange/market-maker allocations, ~$1.2B at
launch price
(https://forklog.com/en/hype-or-a-new-standard-what-hyperliquids-airdrop-historys-most-generous-teaches-us/,
https://www.okx.com/learn/hyperliquid-airdrop-tokenomics-perp-dex). Uniswap announced
criteria only after the snapshot (https://coingape.com/education/uniswap-airdrop-case-study/);
Jito excluded core contributors and skewed to small holders
(https://www.jito.network/blog/jto-airdrop-eligibility-and-allocation-specifications/).
Kite is the counterexample: no user gift, 12% investors / 20% team, $883M FDV debut
(https://kite.foundation/tokenomics). EigenLayer excluded the US entirely and drew
backlash for it
(https://www.coindesk.com/tech/2024/05/09/eigenlayers-eigen-airdrop-might-signal-demise-of-once-popular-points).

**Questions for counsel.** (a) Does a free retroactive distribution to US persons carry
Securities Act surface absent any sale, and what changes if a Project Crypto safe harbor
lands (Section 7)? (b) Announcement timing: does announcing, or even implying, a future
snapshot re-characterize the pre-token usage program as pre-sale marketing, or the Chio
Pass as the consideration leg of an integrated scheme (does the no-retroactive-claim
recital hold)? (c) Is snapshot-before-announcement (Uniswap shape) the posture to
preserve, and what evidence (attested usage, insider exclusion) should be banked?
(d) Recipient and issuer tax treatment.

**Engineering gated.** The Base claim contract verifying eligibility via
`ChioRootRegistry.verifyInclusion`, any snapshot spec, and ALL public signals or
points-to-token language. The offline eligibility analyzer (farmability and sybil-capture
numbers only, no snapshot, no announcement) is not gated.

## 4. TOK-GATE-VLT: pooled underwriting / credits vault

**Mechanism.** An open USDC vault where depositors capitalize agent credit float or
escrow-failure coverage and share pro rata in settlement-fee or premium income, priced by
the existing chio-underwriting premium engine. Users get subsidized or free coverage; the
design copies the no-performance-fee, open-deposit, transparent-PnL shape.

**Reference facts.** Hyperliquid HLP: protocol-owned vault open to any USDC holder,
pro-rata PnL share, no performance fee, roughly 15-30% APR most quarters, $136.9M
cumulative profit, peak TVL ~$604M
(https://www.coingecko.com/learn/hyperliquid-hlp-vault-analysis).

**Questions for counsel.** (a) Is pooled third-party capital earning pro-rata fee share
from Chio's managerial efforts an investment contract under Howey, and does the
no-performance-fee open-deposit design change anything? (b) Does underwriting escrow
coverage implicate state insurance or surplus-lines regulation? (c) Would depositor
restrictions (accredited-only, protocol-owned-capital-only) or a captive structure lower
the surface enough to matter? (d) Does the analysis shift if deposits are CHIO not USDC?

**Engineering gated.** Any vault contract, deployment, or premium-engine integration with
pooled outside capital. The actuarial sizing spike (memo only, no code) is not gated.

## 5. TOK-GATE-STK: staking emissions yield

**Mechanism.** Stakers lock CHIO and receive yield paid from a future-emissions reserve
(distinct from the no-yield staking in the cover note). Hyperliquid's version funds ~2.3%
APY from reserves at a rate inversely proportional to sqrt(total staked).

**Reference facts.** Hyperliquid staking: ~2.3% APY from the future-emissions reserve,
1-day undelegation lock, validator commission anti-rug rule; separately, staking tiers
grant fee discounts with no yield leg
(https://hyperliquid.gitbook.io/hyperliquid-docs/hypercore/staking). The sweep flags
emissions-funded yield as resembling prior SEC staking-action fact patterns
(https://goplussecurity.medium.com/hyperliquid-buyback-burn-and-staking-mechanism-research-report-72e0e1765fd9).

**Questions for counsel.** (a) Does yield paid from an emissions reserve (not from fees
on its face) still present the staking-program fact pattern from prior SEC actions?
(b) Is staking-for-fee-discounts-only, with no yield leg, outside that pattern? (c) Does
self-staking vs delegated staking-as-a-service change the analysis? (d) Would CLARITY
maturity treatment (Section 7) alter how staking rewards are characterized?

**Engineering gated.** Any emissions schedule, reward-distribution contract, or published
APY. Tier-threshold modeling for discount-only staking is not gated (post-token anyway).

## 6. TOK-GATE-BB: fee-funded buyback / burn

**Mechanism.** A fixed share of protocol fees routes automatically to an on-chain fund
that buys CHIO on the open market and/or burns it, with no discretionary leg. The
landscape memo ranks this last on the copy-list and bars it from leading the narrative.

**Reference facts.** Hyperliquid Assistance Fund: ~97% of perp fees (raised toward 99%
by an ~85% validator vote, Dec 2025) buy HYPE continuously in-protocol; $1B+ cumulative
buybacks by late 2025; a Dec 2025 vote recognized ~13% of circulating supply (~$920M) as
burned
(https://goplussecurity.medium.com/hyperliquid-buyback-burn-and-staking-mechanism-research-report-72e0e1765fd9,
https://www.dlnews.com/articles/defi/hyperliquid-hype-token-buyback-1bn-but-is-it-sustainable/,
https://thedefiant.io/news/tokens/hyperliquid-proposes-burning-13-percent-of-circulating-token-supply).
Virtuals is the cautionary case: a buyback-led narrative plus forced token pairing read
as extractive once revenue crashed 96% (Jan-June 2025) and the token sat ~87% off ATH
(https://www.dextools.io/tutorials/what-is-virtuals-protocol-ai-agents-base-guide-2026).

**Questions for counsel.** (a) Is a fee-funded open-market buyback the strongest
profit-expectation fact pattern here, as the research sweep assumes? (b) Rank the
variants: open-market buyback, usage-linked burn (EIP-1559 style, Helium burn-to-credit),
fee-discounts-only. (c) Does full on-chain automation with no discretion materially
change the Howey analysis? (d) What public-statement discipline follows if any is
adopted, given buybacks must never lead the value narrative?

**Engineering gated.** Any `FeeRouter`/`ChioTreasury` buyback leg (itself Phase-3-gated;
no fee rail exists today) and any public material mentioning buybacks. The internal
buyback-capacity economics model is not gated.

## 7. Timing: the regulatory window (questions, not conclusions)

- **CLARITY Act (H.R. 3633).** Passed the House in 2025; Senate vote expected mid-2026;
  rules effective late 2026-2027. Creates a maturity pathway from SEC-style treatment to
  CFTC digital-commodity treatment once the network is decentralized and the token has
  real in-ecosystem utility
  (https://www.congress.gov/bill/119th-congress/house-bill/3633/text,
  https://www.arnoldporter.com/en/perspectives/advisories/2025/08/clarifying-the-clarity-act).
  Ask: do the maturity criteria map onto Chio's Phase 3 decentralization gate, and does
  utility-first design confer the statutory advantage it appears to?
- **SEC Project Crypto.** Chairman Atkins (2025-11-12) directed staff to propose
  purpose-fit disclosures, exemptions, and safe harbors explicitly covering airdrops and
  network rewards; a16z filed a formal safe-harbor proposal 2025-03-13; a compliant
  retroactive-gift window may open in late 2026
  (https://www.sec.gov/newsroom/speeches-statements/atkins-111225-secs-approach-digital-assets-inside-project-crypto,
  https://www.sec.gov/about/crypto-task-force/written-submission/a16z-crypto-safe-harbor-proposal-03132025).
  Ask: what evidence should be banked now, and does a retroactive gift over Pass-era
  usage risk re-characterizing the Pass (see TOK-GATE-AD question b)?
- **Entity wrapper: Wyoming DUNA vs offshore foundation.** The DUNA is a16z's recommended
  US-native nonprofit wrapper; foundation-governed neutrality (x402 Foundation, Kite
  Foundation) remains the enterprise-credibility standard
  (https://a16zcrypto.com/posts/article/big-ideas-crypto-2025/).
  Ask: DUNA vs offshore trade-offs for a US-person founder, and at which phase (the M5
  governance handoff?) an entity wrapper becomes load-bearing.

Interaction note: the gated mechanisms compound (an airdrop seeding a yield-bearing
vault looks more like an investment contract than either alone); review as one package.

## 8. Standing constraints (DO-NOT-WEAKEN)

- FAIL-CLOSED: every gate above stays closed until counsel answers; silence means NO.
- US-person founder; deployment only on Solana, Base, or Ethereum; Hyperliquid is a
  mechanism reference, never a venue.
- The token never enters the payment path; settlement stays USDC.
- No token-promise language in any public telemetry, points, or comms pending TOK-GATE-AD.
- Preparation only; not legal advice; nothing here is a conclusion.
