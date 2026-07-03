# Chio Token External Landscape and Mechanism Reference (2026-07)

Date: 2026-07-02.
Status: research memo, produced by an agent research sweep (two cited reports: an
agentic-commerce token landscape and a Hyperliquid mechanism reference study, plus a
product cross-reference pass over this repo).
Scope: what the external market, the goodwill record, and the regulatory window say about
the strategy already decided in `CHIO-TOKEN-AND-CONTRACTS-PLAN.md` (the fail-closed gate:
no-token -> credit -> staking -> governance, milestones M0-M6) and the Chio Pass design in
`CHIO-BENEVOLENT-TOKEN-DESIGN.md` (soulbound, non-transferable, non-redeemable,
access-plus-allotment, no money leg). Both companion docs currently live on the
`chio/token-contracts-brainstorm` branch.
Framing: this memo changes NO gate. It supplies external evidence for gates that already
exist and names where the evidence strengthens, corrects, or adds detail. Nothing in
Section 6 is legal advice; it is a list of questions for counsel.

---

## 1. Executive summary

The external record, as of 2026-07-02, validates the two decisions this repo has already
made and sharpens both.

1. **Tokenless-at-launch is what the winners do.** Every serious agentic-commerce rail
   (x402, Skyfire, Payman, Mastercard Agent Pay for Machines, Stripe/Tempo MPP, Google
   AP2) is tokenless and settles in USDC or fiat; every token-bearing player in the niche
   (Virtuals, ElizaOS, Fetch/ASI, Kite) put the token in the payment or launch path and
   carries a mixed-to-extractive reputation. The plan doc's Phase 0 posture is the
   observed dominant strategy, not a compromise (Section 2).
2. **The Chio Pass is on the right side of the goodwill ledger.** The best-loved token
   events are retroactive, usage-based gifts with insiders excluded (Uniswap, Jito,
   Optimism RetroPGF, Hyperliquid genesis); the worst are prospective points programs
   with vague promises (EigenLayer) and forced token purchase in the payment flow
   (Virtuals). The Pass already encodes the winning shape: retroactive snapshots over
   genuine receipts, no published farmable formula, no future-token wink (Section 3).
3. **Hyperliquid is a reference to copy, never a venue to use** (standing jurisdiction
   constraint: Chio deploys only on Solana/Base/ETH). Its mechanisms rank cleanly by
   copy-value, from usage-based points (copy now, pre-token) down to buyback/burn
   (post-token, counsel-gated, strongest Howey surface). Its failures (the JELLY
   intervention, validator centralization, closed-source node) convert directly into Chio
   policy: predeclared circuit breakers, open source, no discretionary override
   (Section 4).
4. **Kite is the competitor to beat, and it is beatable on distribution.** Kite proves a
   US-adjacent, VC-backed token launch is viable in exactly Chio's niche, but its
   investor-first distribution (12% investors / 20% team, no user gift, $883M FDV debut)
   leaves the benevolence wedge wide open (Section 5).
5. **A regulatory window may open in late 2026** (CLARITY Act maturity pathway, SEC
   Project Crypto safe-harbor work, Wyoming DUNA). A utility-first, gift-heavy,
   retroactive design aligns with all three currents; the window changes timing questions
   for counsel, not the gate itself (Section 6).

Net effect on the roadmap: M0/M1 unchanged and externally corroborated; M2 gains a
published precedent (Helium Data Credits) for the counsel packet; M4 gains the anti-JELLY
circuit-breaker requirement as reference facts; M5/M6 gain genesis-shape constraints that
should be recorded now so later fundraising cannot quietly violate them (Section 7).

---

## 2. The tokenless-rails finding and what it means for sequencing

Every rail that matters in 2026 agentic commerce runs without a native token:

- **x402 (Coinbase)**: no token, zero protocol fees, USDC settlement, governance in the
  x402 Foundation (Coinbase + Cloudflare; members include Google, Visa, AWS, Circle,
  Anthropic, Vercel). By March 2026: 119M transactions on Base, 35M on Solana (~$600M
  annualized), but CoinDesk found only ~$28k/day of real volume, much of it gamed or test
  traffic ([CoinDesk](https://www.coindesk.com/markets/2026/03/11/coinbase-backed-ai-payments-protocol-wants-to-fix-micropayment-but-demand-is-just-not-there-yet), [x402 docs](https://docs.cdp.coinbase.com/x402/welcome)). That ~$28k/day figure is the
  thin-demand baseline the plan doc already uses in its Phase 3 gate and kill-criteria;
  it is now independently sourced. The "x402 ecosystem tokens" (PING and the ~$826M
  category) are third-party speculation, not protocol utility ([Trust Wallet](https://trustwallet.com/blog/cryptocurrency/what-is-x402-and-ping), [CoinGecko](https://www.coingecko.com/en/categories/x402-ecosystem)).
- **Skyfire**: no crypto token; KYAPay settles in USDC and the "PAY token" in its docs is
  an access credential, not a tradable asset; Dec 2025 end-to-end demo with Visa
  Intelligent Commerce ([Skyfire](https://skyfire.xyz/product/), [Business Wire](https://www.businesswire.com/news/home/20251218520399/en/Skyfire-Demonstrates-Secure-Agentic-Commerce-Purchase-Using-the-KYAPay-Protocol-and-Visa-Intelligent-Commerce), [Apify docs](https://docs.apify.com/platform/integrations/skyfire)).
- **Payman**: no token, no ICO; $3M pre-seed, regulated fiat rails ([ICO Drops](https://icodrops.com/payman/), [Payman](https://paymanai.com/)).
- **Incumbents**: Mastercard Agent Pay for Machines (June 2026) ([Mastercard](https://www.mastercard.com/us/en/news-and-trends/press/2026/june/mastercard-launches-agent-pay-for-machines.html), [Fortune](https://fortune.com/2026/06/10/mastercard-ai-payments-protocol-launch-agentic-finance/)),
  Stripe/Tempo Machine Payments Protocol (2026-03-18; 100+ services; partners include
  Anthropic, OpenAI, Shopify, Visa), and Google AP2. Six protocols define the 2026 stack
  (ACP, UCP, AP2, MCP, x402, stablecoin rails); none is token-gated ([Agentic Plug](https://agenticplug.ai/current-state-of-agentic-commerce)).

The token-bearing counterexamples are cautionary, not aspirational:

- **Virtuals (VIRTUAL, Base)**: forced pairing (every agent-token launch must bond
  against VIRTUAL) is the clearest extractive pattern in the space; revenue crashed 96%
  Jan-June 2025 and the token sits ~87% off ATH even with real ACP usage ([DEXTools](https://www.dextools.io/tutorials/what-is-virtuals-protocol-ai-agents-base-guide-2026), [CoinStats](https://coinstats.app/ai/a/investment-analysis-virtual-protocol), [Traders Union](https://tradersunion.com/news/cryptocurrency-news/show/1501104-virtuals-protocol-price-prediction/)).
- **ElizaOS (ex ai16z)**: fair launch, then a rebrand-and-swap raising supply 6.6B ->
  11B; utility remains thin relative to how widely the Eliza framework is used without
  the token ([Crypto.com](https://crypto.com/us/product-news/ai16z-token-swap-and-rebrand-to-elizaos), [Coinspeaker](https://www.coinspeaker.com/ai16z-falls-12-7-platform-officially-rebrands-elizaos/), [crypto.news](https://crypto.news/elizaos-token-rises-170-in-48-hours-following-rebrand-platform-expansion/), [Decrypt](https://decrypt.co/295717/meet-ai16z-dao-an-ai-based-investment-project-that-aims-to-upend-silicon-valley)).
- **Fetch.ai/ASI**: FET is nominally the payment rail, yet its own flagship AI-to-AI
  payments demo settles via Visa and USDC as well as FET; Ocean exited the alliance over
  tokenomics control ([ASI](https://superintelligence.io/asi-token-fet/), [Fetch.ai](https://www.fetch.ai/blog/world-s-first-ai-to-ai-payment-for-real-world-transactions), [DEXTools](https://www.dextools.io/tutorials/what-is-fetch-ai-asi-alliance-fet-token-ai-agents-guide-2026)).

**Sequencing implications.** (a) Keep any future token out of the payment path
permanently: the credit, rebate, and retro-reward layers are the only defensible homes,
never a required settlement or pairing asset. The plan doc already confines value to USDC
in `ChioEscrow`/`ChioBondVault`; this is external proof that posture is also the
market-winning one. (b) Tokenless neutrality is itself an asset: x402's zero-fee,
foundation-governed stance is what earned Visa, Google, Cloudflare, and Anthropic as
members. If Chio wants enterprise rail adoption first, USDC-only settlement now and a
token only after usage is real (the CLARITY maturity logic, Section 6) is a defensible
terminal strategy, not just a phase. (c) The first public product motion (the x402
pay-per-call vending-machine demo from the product sweep) is fully token-independent and
consistent with M0.

---

## 3. Goodwill winners vs anti-patterns

### Winners (retroactive, usage-based, insiders excluded)

- **Uniswap (2020)**: 400 UNI to ~250,000 past users, 15% of supply, snapshot before
  announcement. Still the canonical template: reward past users, not future farmers, and
  announce criteria only after the snapshot ([CoinGape](https://coingape.com/education/uniswap-airdrop-case-study/), [Uniswap gov](https://gov.uniswap.org/t/learn-requirements-how-to-claim-your-400-uni/1025)).
- **Jito (Solana, Dec 2023)**: 10% of supply retroactive (~$225M), tiers deliberately
  skewed toward small holders, anti-sybil filtering, core contributors excluded from the
  community drop; remembered as one of Solana's most goodwill-positive launches ([Jito](https://www.jito.network/blog/jto-airdrop-eligibility-and-allocation-specifications/), [Decrypt](https://decrypt.co/209010/jito-airdrop-hands-out-225-million-solana-users)).
- **Optimism RetroPGF**: 60M+ OP paid for demonstrated past impact rather than promises;
  the standard non-extractive ecosystem-funding model on an ETH L2 ([Optimism](https://www.optimism.io/blog/announcing-the-results-of-retropgf-2), [Gitcoin](https://gitcoin.co/blog/wtf-is-retro-funding)).
- **Helium Data Credits** (now on Solana): the cleanest speculation/usage split. DCs are
  USD-pegged ($0.00001), non-transferable, single-user, minted only by burning HNT, so
  real usage consumes the speculative asset while users pay a stable price ([Helium docs](https://docs.helium.com/tokens/data-credit/), [OKX](https://www.okx.com/en-us/learn/helium-deflationary-tokenomics-burn-mint)). This
  is the strongest published pattern matching Chio's benevolent constraint: if a
  transferable CHIO ever clears the M6 gate, burn-to-credit (token burns mint
  non-transferable USD-denominated prepaid credit) is the sink mechanism to evaluate, and
  the non-transferable USD-pegged credit shape is exactly the Phase 1 escrow-socketed
  prepaid unit the plan already specifies.
- **Blackbird (Base)**: value flows to diners and merchants first, token second; merchants
  pay ~2% (below card rails) and keep their data; governance in a separate token ([TechCrunch](https://techcrunch.com/2025/04/08/blackbird-gobbles-up-50m-for-its-blockchain-based-payment-loyalty-app-for-restaurants/), [CoinDesk](https://www.coindesk.com/tech/2025/02/26/blackbird-blockchain-restaurant-loyalty-app-goes-live-with-flynet-mainnet)).

### Anti-patterns (prospective, vague, extractive)

- **EigenLayer (May 2024)**: non-transferable token at drop, only 5% in Season 1, 30
  countries excluded (including the US), linear allocations favoring whales; widely
  called a broken social contract. Robert Leshner: "Points create the largest information
  asymmetry that exists in crypto" ([CoinDesk](https://www.coindesk.com/tech/2024/05/09/eigenlayers-eigen-airdrop-might-signal-demise-of-once-popular-points), [The Defiant](https://thedefiant.io/news/research-and-opinion/eigenlayer-airdrop-outcry-shows-how-points-are-raising-trader-expectations), [Blockworks](https://blockworks.co/news/empire-newsletter-eigenlayer-airdrop-criticisms)).
- **LayerZero**: adversarial sybil theater (self-report and keep 15%) drew backlash even
  where technically justified ([Unchained](https://unchainedcrypto.com/why-layerzeros-new-anti-sybil-policy-is-getting-both-backlash-and-praise/)).
- **Virtuals' buyback-led narrative**: fee-funded burns read as extractive when fees
  force token demand and revenue is narrative-dependent (sources in Section 2). Never
  lead the value story with buyback-and-burn; any burn is a byproduct of the credit mint,
  not the pitch.
- **Points-before-token generally** accrues "expectation debt" unless conversion rules
  are transparent and the token is transferable at TGE ([DeFi Prime](https://defiprime.com/points-based-token-distribution-programs-web3), [Crypto.com Research](https://crypto.com/en/research/points-farming-may-2024)).

**Fit with the Pass.** The benevolent doc already amputated the future-token wink, uses
retroactive unpredictable snapshots over genuine signed-receipt history, and excludes any
published farmable formula. The external record confirms each choice and adds one
refinement: if any pre-token measurement program ever becomes visible externally (even
implicitly), it inherits the EigenLayer risk profile, so the no-token-promise recital
must extend to all public telemetry and comms, not just Pass issuance terms. One
correction to the sweep itself: the landscape report assumed Chio has EAS attestations as
a snapshot substrate; on this branch EAS is research-only
(`docs/research/CHIO_ANCHOR_RESEARCH.md`; implementation on `chio/m2-build`, unmerged).
The native substrate for any eligibility snapshot is `chio-credentials` attested DIDs
plus `ChioRootRegistry`-anchored receipt history.

---

## 4. The Hyperliquid copy-list (reference only; never a venue)

Standing constraint: Hyperliquid is a mechanism reference, not a chain to deploy on.
What worked, load-bearing facts:

- **Genesis**: 310M of 1B (31%) airdropped 2024-11-29 to 94,000+ users pro rata to
  points, no claim step, zero VC/exchange/market-maker allocations, no community lockups;
  ~$1.2B at launch price, the largest airdrop in crypto history, with a live high-volume
  product before the token ([ForkLog](https://forklog.com/en/hype-or-a-new-standard-what-hyperliquids-airdrop-historys-most-generous-teaches-us/), [CoinGecko](https://www.coingecko.com/learn/what-is-hyperliquid-and-what-the-hyperliquid-airdrop-means-for-defi), [Crypto Economy](https://crypto-economy.com/hyperliquids-onchain-empire-no-vc-no-presale-just-44-of-perp-market/)).
  Contributors: 23.8%, ~1-year cliff then daily linear unlocks to 2028 ([OKX](https://www.okx.com/learn/hyperliquid-airdrop-tokenomics-perp-dex)).
- **Points**: multi-season program rewarding sustained real volume, penalizing wash
  trading ([PANews](https://www.panewslab.com/en/articles/zena4u1n), [Hyperliquid docs](https://hyperliquid.gitbook.io/hyperliquid-docs/points)).
- **Fees to community**: ~97-99% of perp fees route to an Assistance Fund that buys (and
  since Dec 2025 burns) HYPE, automated in-protocol; official framing is that fees are
  "entirely directed to the community" ([GoPlus research](https://goplussecurity.medium.com/hyperliquid-buyback-burn-and-staking-mechanism-research-report-72e0e1765fd9), [fee docs](https://hyperliquid.gitbook.io/hyperliquid-docs/trading/fees), [DL News](https://www.dlnews.com/articles/defi/hyperliquid-hype-token-buyback-1bn-but-is-it-sustainable/), [The Defiant](https://thedefiant.io/news/tokens/hyperliquid-proposes-burning-13-percent-of-circulating-token-supply)).
- **Staking tiers**: fee discounts from 5% (10+ HYPE) to 40% (500k+ HYPE) ([staking docs](https://hyperliquid.gitbook.io/hyperliquid-docs/hypercore/staking), [Levex](https://levex.com/en/blog/hype-staking-tiers-rewards)).
- **HLP vault**: open USDC deposits, no performance fee, transparent PnL ([CoinGecko](https://www.coingecko.com/learn/hyperliquid-hlp-vault-analysis), [Eco](https://eco.com/support/en/articles/15197987-hyperliquid-vault-strategies-2026-hlp-and-user-vaults-explained)).

**Ranked copy-list for Chio** (rank, verdict, next step):

1. **Usage-based points program (copy, works pre-token).** Score NET fees paid (x402
   settlement fees, escrow completion rate, attestation quality), not raw volume;
   anti-sybil rules analogous to the wash-trading penalties; zero token-promise language
   pending counsel review.
2. **Hard-coded fees-to-community routing (copy, pre-token).** "Team takes nothing from
   fees" is the core of why HYPE accrual does not feel extractive. For Chio: a fee-split
   hook routing a fixed share of protocol fees to an on-chain community fund on
   Base/Solana, fail-closed on misconfiguration. Constraint from the plan doc: the four
   value contracts are immutable, so this ships as a new deployment or routing layer, and
   no fee rail exists until the Phase-3-gated `FeeRouter`/`ChioTreasury` work.
3. **Staking tiers for fee discounts (copy, post-token only).** Lowest securities surface
   of the token mechanics; model thresholds so the top tier is reachable by heavy
   agentic-commerce users, not just whales.
4. **Assistance-Fund buyback/burn analog (copy with caution, post-token, counsel-gated).**
   Fully automated on-chain if ever built, but buybacks are the strongest Howey fact
   pattern in the whole study; compare open-market buyback vs usage-linked burn vs
   fee-discounts-only in a counsel memo before committing publicly.
5. **Prepaid-credits vault (adapt, not copy).** Chio's analog to HLP is a USDC vault
   backing agent credit float that earns settlement fees, not trading PnL; copy the
   no-performance-fee, open-deposit, transparent-PnL design; pooled-investment surface,
   hold behind the counsel gate.
6. **Dutch auction for scarce slots (adapt, low priority).** The 31-hour HIP-1 auction
   pattern could price verified merchant or namespace slots with proceeds to the
   community fund, but HIP-1's main criticism is pricing out small projects ([PANews](https://www.panewslab.com/en/articles/jr6sr9ed), [Listing.Help](https://listing.help/hyperliquid-listing-cost/)); decide whether any
   Chio resource is genuinely scarce first.
7. **Genesis shape (copy when a token exists).** No VC or market-maker allocation,
   community share larger than insider share, ~1-year cliff plus multi-year linear
   contributor vesting, live product with real volume before TGE. Record these as
   constraints NOW so later fundraising cannot quietly violate them (Section 7, M6).

**The anti-JELLY policy (adopt as standing Chio policy).** In the March 2025 JELLY
incident, validators reached quorum in about two minutes to delist a manipulated market
and force-settle at the attacker's entry price rather than market price, flipping a
$13.5M HLP loss into a ~$700k profit and drawing "FTX 2.0" criticism ([CoinDesk](https://www.coindesk.com/markets/2025/03/26/hyperliquid-delists-jellyjelly-after-vault-squeezed-in-usd13m-tussle), [OAK Research](https://oakresearch.io/en/analyses/investigations/hyperliquid-jelly-attack-context-vulnerability-team-solution)).
Separately, five foundation validators controlled 81%+ of stake on a closed-source node
binary ([The Block](https://www.theblock.co/post/333559/hyperliquid-responds-to-community-concerns-over-validator-issues), [Crypto Briefing](https://cryptobriefing.com/hyperliquid-validator-concerns/)). The
translations for Chio, all consistent with the fail-closed house rules:

- No discretionary emergency intervention, ever. Chio has no validator set (it inherits
  Solana/Base/ETH consensus), so the equivalent surface is escrow dispute handling:
  predeclare circuit-breaker conditions and settlement prices ex ante in the escrow
  contracts and ADRs, with no override path.
- Never settle a dispute at a price that converts protocol losses into protocol profit at
  user expense.
- No closed-source contract or node code; no single party holding a governance-halting
  stake share.
- Sustainability caveat on mechanism 4: buybacks front-load demand and must scale with
  real revenue against vesting overhang ([DL News](https://www.dlnews.com/articles/defi/hyperliquid-hype-token-buyback-1bn-but-is-it-sustainable/), [AInvest](https://www.ainvest.com/news/hyperliquid-deflationary-supply-shock-buybacks-rewards-2603/)).

---

## 5. Competitive positioning vs Kite

Kite is the closest token-bearing competitor: a purpose-built agent-payments L1, natively
x402-integrated, $33M+ raised from PayPal Ventures, General Catalyst, and Coinbase
Ventures. KITE debuted 2025-11-03 at a $159M cap / $883M FDV with $263M first-hours
volume; supply 10B with 48% community, 12% investors, 20% team ([CoinDesk](https://www.coindesk.com/business/2025/11/03/ai-payments-startup-kite-debuts-token-with-usd263m-trading-volume-in-first-two-hours), [GlobeNewswire](https://www.globenewswire.com/news-release/2025/10/27/3174837/0/en/kite-announces-investment-from-coinbase-ventures-to-advance-agentic-payments-with-the-x402-protocol.html), [Kite Foundation](https://kite.foundation/tokenomics)).

What Kite proves and leaves open:

- It proves a US-adjacent, VC-backed token launch is now viable in exactly this niche,
  which matters for the Phase 3/M6 feasibility question.
- Its distribution reads investor-first: high FDV at debut, 32% to insiders, no
  retroactive user gift. That is the opening. A majority-community, usage-gifted
  distribution (Jito-style tiers, insiders excluded, plus RetroPGF-style impact rounds
  for agent and tool builders instead of emissions) is simultaneously Chio's benevolence
  story and its competitive wedge.
- Kite bet on its own L1; Chio's neutrality bet (ride x402/AP2/ACP on Base and Solana
  rather than owning a chain) is the opposite wedge and pairs with Section 2.
- Before any M6 design freeze: run the competitive teardown of Kite's tokenomics and
  Virtuals' ACP fee flows into a concrete do/do-not table.

The Pass sharpens the contrast today, pre-token: Kite gives new users nothing until they
buy; Chio gifts attested newcomers free trust-feed reads and a real compute allotment on
day zero, with nothing to buy and nothing to dump.

---

## 6. Regulatory window (questions for counsel; explicitly not legal advice)

Nothing here is a legal conclusion. These are the three currents the sweep found and the
questions they raise, to fold into the plan doc's research items 1-8 (which gate every
phase escalation). The founder is a US person, which is why all of this routes through
counsel before any snapshot, points language, or token design freeze.

1. **CLARITY Act (H.R. 3633)**: passed the House in 2025; Senate vote expected mid-2026;
   rules effective late 2026-2027. Creates a maturity pathway where a token starts under
   SEC-style rules and graduates to CFTC digital-commodity treatment once the network is
   decentralized and the token has real in-ecosystem utility ([Congress.gov](https://www.congress.gov/bill/119th-congress/house-bill/3633/text), [Arnold & Porter](https://www.arnoldporter.com/en/perspectives/advisories/2025/08/clarifying-the-clarity-act), [TradingKey](https://www.tradingkey.com/analysis/cryptocurrencies/more/261765460-crypto-clarity-act-stablecoin-america-sec-cftc-rwa-defi-coinbase-usdc-usdt-tradingkey)).
   Counsel questions: do the maturity criteria map onto the plan doc's Phase 3
   decentralization gate, and does utility-first design confer the statutory advantage it
   appears to?
2. **SEC Project Crypto**: Chairman Atkins (2025-11-12) directed staff to propose
   purpose-fit disclosures, exemptions, and safe harbors explicitly covering airdrops and
   network rewards; a16z filed a formal safe-harbor proposal 2025-03-13 ([SEC speech](https://www.sec.gov/newsroom/speeches-statements/atkins-111225-secs-approach-digital-assets-inside-project-crypto), [a16z submission](https://www.sec.gov/about/crypto-task-force/written-submission/a16z-crypto-safe-harbor-proposal-03132025), [Sidley](https://www.sidley.com/en/insights/newsupdates/2025/11/breaking-down-project-crypto-sec-chairman-atkins-outlines-next-phase-of-digital-asset-oversight)).
   Counsel questions: if an airdrop/network-reward safe harbor lands in late 2026, what
   evidence should Chio bank in advance (attested usage history, insider-exclusion
   rules), and does a retroactive gift over Pass-era usage risk re-characterizing the
   Pass as the consideration leg of an integrated scheme (the M6 no-retroactive-claim
   recital exists precisely to prevent this)?
3. **Wyoming DUNA**: a16z's recommended US-native nonprofit wrapper for token governance,
   positioned against offshore Cayman foundations; foundation-governed neutrality (x402
   Foundation, Kite Foundation) remains the enterprise-credibility standard ([a16z](https://a16zcrypto.com/posts/article/big-ideas-crypto-2025/), [The Defiant](https://thedefiant.io/news/nfts-and-web3/a16z-predict-ai-agents-dunas-and-tokenization-will-drive-crypto-innovation-in-2025)).
   Counsel questions: DUNA vs offshore foundation trade-offs for a US-person founder, and
   at which phase (M5 governance handoff?) an entity wrapper becomes load-bearing.

Additional flagged mechanisms for the same counsel packet, with Hyperliquid as the
reference case (facts and URLs in Section 4): fee-funded buybacks/burns (classic
profit-expectation pattern), a pooled USDC credits vault paying pro-rata fee share
(investment-contract resemblance), staking yield paid from emissions reserves, and any
points program that implies a future token (pre-sale-marketing characterization risk;
see also the points expectation-debt sources in Section 3).

---

## 7. Implications for the M0-M6 roadmap

Milestone-by-milestone read against `CHIO-TOKEN-AND-CONTRACTS-PLAN.md` as amended by
`CHIO-BENEVOLENT-TOKEN-DESIGN.md` Section 6:

- **M0 (hardened tokenless launch + Pass): unchanged, now externally corroborated.**
  Section 2 is the market evidence for tokenlessness; Section 3 the goodwill evidence for
  the Pass shape. One addition: extend the existing no-future-value recital into a comms
  policy covering all public telemetry and points-like language (the EigenLayer lesson).
  The x402 vending-machine demo is the natural M0-era public showcase and needs no token;
  its known gaps (no in-repo x402 facilitator, placeholder Base Sepolia deployment
  manifest) are product work, not token work.
- **M1 (off-chain netting collapse): unchanged.** Still the kill-evidence against any
  on-chain credit token; no external finding disturbs it.
- **M2 (closed-loop prepaid credit on escrow): same gate, better precedent.** Helium Data
  Credits (Section 3) is the published, widely-respected instance of a non-transferable
  USD-pegged usage unit coexisting with (and later consuming) a speculative asset. Add it
  to the counsel packet for research items 3-4 as the reference design; note that any
  burn-to-credit mechanism presupposes M6, not M2.
- **M3 (USDC self-restitution bonds): unchanged; one post-token candidate noted.**
  Staking-tiers-for-fee-discounts (copy-list rank 3) is the lowest-surface token utility
  if a token ever exists, but it requires both a token and a fee rail, so it files behind
  the M6 gate, not M3.
- **M4 (involuntary slashing + adjudication): adopt the anti-JELLY policy as an explicit
  gate input.** The plan already requires a dispute window, independent adjudicator, and
  veto committee (research item 6). Add: predeclared circuit-breaker conditions and
  settlement prices written ex ante into the escrow/slashing ADRs, no discretionary
  override path, and never a settlement price that converts protocol loss into protocol
  profit (Section 4 JELLY facts as the reference case).
- **M5 (governance handoff): add the entity question.** Resolve the DUNA-vs-foundation
  choice (Section 6) with counsel before `transferAdmin` to a Governor+Timelock, since
  the wrapper determines who the governed registry legally is.
- **M6 (conditional transferable CHIO): record the genesis constraints now.** If M6 ever
  fires: no VC or market-maker allocation; community share strictly greater than insider
  share; ~1-year cliff and multi-year linear contributor vesting; live product with real,
  non-artificial volume before TGE; retroactive usage-gifted distribution with insiders
  excluded and small-user tier skew; no buyback-led narrative; burn-to-credit as the
  utility sink to evaluate first. Writing these into the design doc today is cheap and
  prevents later fundraising pressure from quietly eroding them (Hyperliquid rank 7; Kite
  as the counterexample). Evaluate fees-to-community routing (copy-list rank 2) when a
  fee rail exists; under the current plan that is Phase 3 (`FeeRouter`/`ChioTreasury`),
  arriving as a new deployment beside the immutable spine.

**Watch items** (fold into existing review cadence): Senate CLARITY progress and any SEC
Regulation Crypto proposal text; x402 Foundation governance and any x402-official token
signal; Kite tokenomics execution post-vesting. All three can shift Phase 1-3 timing
windows without changing the gate structure.
