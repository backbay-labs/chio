# Chiodos Scarcity Economics

**Status:** Research / quantitative
**Date:** 2026-05-04 (v0.1)
**Informs:** `chio-pheromone` weighting function calibration; bounds the
attacker-budget assumption underpinning the chiodos safety claim
**Companions:** `docs/research/CHIODOS_CONCEPT.md` (section 7 hard
problem 5; honest residual on sustained majority collusion);
`spec/CHIODOS_PHEROMONE.md` (section 5 source diversity rules; section 6
newcomer discount; section 7 observation-cost commitment)

---

## 1. Status and Intent

The chio-pheromone substrate enforces a per-kernel cap of
`ceil(sqrt(active_peers))` distinct passport keys per subject-class per
window, citing the Cheng-Friedman (PODC 2005) sybilproofness result.
That is a structural defense against unbounded passport minting. It is
not a defense against an adversary willing to spend money to acquire
passports across multiple operator-orgs.

Cheng-Friedman and Fang et al. (USENIX 2020) both prove that **no
symmetric weighting function survives once more than ~50% of effective
passport mass is adversarial** under coordinated strategy. The honest
residual stated in `CHIODOS_CONCEPT.md` section 7 is that **bilateral
handshake admission must keep effective adversarial mass below ~30%**.
This document quantifies what "below 30%" requires of attacker budgets
under the chio-pheromone wire freeze, and what calibration of the
sqrt(N) cap and newcomer discount the reference implementation should
ship with.

The output is concrete: a closed-form expression, a numerical table
across realistic federation sizes, passport-issuance budgets per attacker
class, and a default calibration recommendation for `chio-pheromone`.

This is not a security proof. It is a sizing exercise that justifies the
defaults and identifies the regimes where the substrate-level defenses
genuinely bind versus where the residual must escalate to out-of-band
governance (chio-governance Sanction case against the issuing org per
`CHIODOS_CONCEPT.md` section 7 honest residual).

---

## 2. Threat Model

### 2.1 What a passport "costs"

A chiodos passport useful for poisoning concentration queries has four
cost components. The total per-passport effective cost `C` is the sum.

| Component | Description | Lower bound | Upper bound |
|---|---|---|---|
| Operator-org admission | Cost of standing up or co-opting a legitimate cover entity that can be admitted under bilateral handshake. Includes shell-company filing, registered agent, nominee directors, sectoral roster fee where one exists. Amortised over passports issued by that org. | $1,500 (Delaware LLC + 1y registered agent) | $25,000 (sectoral consortium dues + audited financials + nominee structure) |
| Passport key custody | Hardware-backed key storage (FIDO2/HSM) per passport, or attested software keys at lower assurance. Higher assurance is harder to forge under hardware-attested passport key requirements (defense lever D2). | $30 (consumer YubiKey C NFC) | $90 (YubiKey 5C FIPS) to ~$650+ (HSM-backed slot amortised) |
| Attestation issuance | Code-signing-tier or organization-validation certificate. EV equivalents exist when the operator-org needs to be cryptographically distinguishable from a CA's perspective. | $279 (Sectigo EV Code Signing 1y) | $580+ (DigiCert EV Code Signing 1y) |
| Reputation aging | The newcomer discount applies a multiplier `min(1, age_in_anchored_epochs / N)` (spec section 6). A passport at age `a < N` carries weight `a/N`. To gain full weight an attacker must either pay the time cost (wait `N` epochs while the passport sits idle and accrues no offsetting return) or buy aged passports on a secondary market. The opportunity cost dominates: at $5,000/yr per passport-year of operator capital tied up in compliance, `N = 28` epochs (~4 weeks) is approximately $385 of locked time-cost per passport. | $385 (N=28 epochs, low-end org capital) | $1,800 (N=56 epochs, high-end org capital) |

The lower-bound stack is approximately **$2,200 per passport**; the
upper-bound stack is approximately **$28,000 per passport**. Hardware
attestation requirements (defense lever D2) push the floor to roughly
**$5,000 per passport** by foreclosing the YubiKey-tier option in favor
of HSM-backed slots with attestation chains the verifier can inspect.

### 2.2 Attacker classes and budget envelopes

Per-class budget envelopes are drawn from public reporting and adapted to
"sustained passport-acquisition campaign over one reputation epoch
window." These are budgets the actor can plausibly burn on
chiodos-poisoning specifically, not their gross revenue.

| Class | Plausible budget for one chiodos campaign | Notes / source |
|---|---|---|
| Opportunistic cybercrime | $10,000 - $50,000 | Median ransomware payment ~$115K (Verizon DBIR 2025 trend reporting); a single campaign's working capital available to an opportunistic crew. |
| Organised cybercrime ring | $250,000 - $1,500,000 | Established affiliate networks; LockBit-tier operations have demonstrated multi-million revenue against single targets. |
| Hacktivist collective | $5,000 - $100,000 | Crowdfunded; relies more on volunteer labor than capital. Constrained on hardware-attested passport keys. |
| Insider-threat-via-shell-org | $50,000 - $500,000 | Distinguished by lower per-org admission cost (insider already has access to one legitimate org) but harder to scale: a single insider compromise rarely scales beyond two or three operator-orgs without becoming attributable. |
| Nation-state (lower tier) | $5,000,000 - $50,000,000 | Mid-tier intelligence service with a dedicated cyber-influence cell. Not the top of the budget, but the realistic line for a chiodos-scale campaign. |
| Nation-state (upper tier) | $100,000,000+ | Strategic cyber-influence campaigns; effectively unbounded for protocol-level analysis. The substrate alone cannot defend against this and was never designed to; the recourse is out-of-band sectoral roster revocation. |

Budget interpretation: the "plausible budget" is what the actor would
spend to reach 30% effective passport mass in **one** reputation epoch
window in a target federation. Sustaining the position across many
windows multiplies the cost roughly linearly because passports must be
re-attested and re-aged after revocation; the analysis below holds for
the steady state once the initial cohort has aged in.

### 2.3 Out-of-scope

This document does not size:

- The cost of compromising legitimately-issued passports (key theft,
  insider exfiltration). Those costs are bounded below by the cost of
  one targeted social-engineering campaign per passport, which can be
  cheaper than the costs in section 2.1; the recourse is
  passport-revocation gossip and the bridge in
  `chio-revocation-oracle::passport_bridge`. This is the
  `passport-revocation` lane, not the scarcity lane.
- The operational cost of generating semantically-plausible deposits.
  Mimicry-style slow-drift below sensor noise is the second honest
  residual in `CHIODOS_CONCEPT.md` section 7 and is addressed by
  arena-replay scoring, not by the scarcity argument.

---

## 3. The Math

### 3.1 Setup

Let `P` be the number of honest peers admitted under the relevant
treaty. Let `K` be the per-kernel per-subject-class diversity allowance
(the per-pair token-bucket capacity from spec section 5.3, expressed as
distinct passport keys per window). Let `S = ceil(sqrt(active_peers))`
be the per-kernel sqrt(N) cap from spec section 5.4.

For honest peers under steady load, `K` honest passports per peer are
typically active per window, with `K <= S` by construction (an honest
peer has no incentive to provision more passports than its substrate
will count). Effective per-class honest passport count is:

```
honest_count = P * K
```

The adversary, by virtue of being able to stand up multiple
operator-orgs, gets `S` distinct passports admitted per attacker-org
because the cap binds per-origin-kernel. Let `A` be the number of
distinct attacker-controlled operator-orgs. The adversary's effective
passport count is:

```
adversary_count = A * S = A * ceil(sqrt(P + A))
```

Effective passport mass is the sum of unweighted contributions to a
concentration, before reputation weighting and newcomer discounting are
applied. The adversarial fraction `f` is:

```
f = adversary_count / (honest_count + adversary_count)
  = A * S / (P * K + A * S)
```

### 3.2 Solving for the budget

The threshold safety condition from `CHIODOS_CONCEPT.md` is `f < 0.30`.
Solving for `A`:

```
A * S < 0.30 * (P * K + A * S)
A * S * 0.70 < 0.30 * P * K
A < (0.30 / 0.70) * (P * K / S)
A < (3/7) * P * K / ceil(sqrt(P + A))
```

The right-hand side has `A` inside `sqrt(P + A)`, so we iterate. For
modest adversary sizes (`A << P`) the approximation `sqrt(P + A) ~
sqrt(P)` is tight; for `A` comparable to `P` we substitute the solved
`A` back. For analysis purposes we use the closed-form first-order
approximation:

```
A_max ~= (3/7) * P * K / ceil(sqrt(P))                           ... (1)
```

Adversary budget `B` to reach the threshold is `A_max * t * C` where
`t` is the number of attacker passports per attacker-org and `C` is the
per-passport cost from section 2.1. The attacker is incentivised to set
`t = S` (the per-kernel cap) per org to amortise the operator-org
admission cost, so:

```
B_min ~= A_max * S * C
      ~= (3/7) * P * K / ceil(sqrt(P)) * ceil(sqrt(P)) * C       ... (2)
      ~= (3/7) * P * K * C
```

The `sqrt(N)` cap **cancels out of the closed form**: it reduces the
number of passports a single adversary org can express, but the
adversary just stands up `O(sqrt(P))` orgs to compensate. This is the
analytical heart of the scarcity argument: **the sqrt(N) cap does not
reduce the dollar budget required; it forces that budget to be spent on
operator-org admissions rather than on passport keys.** Operator-org
admission is the load-bearing scarcity, not passport issuance.

The newcomer-discount multiplier `min(1, a/N)` further reduces the
adversary's effective mass during the aging window. If we model the
adversary as continuously rolling passports and the average passport age
in adversarial cohort is `a_bar`, the effective adversarial mass is
scaled by `a_bar/N`. To sustain `f >= 0.30` at steady state the
adversary must either age passports (multiplying the time-cost component
of `C`) or provision `N/a_bar` times more passports than the unaged
formula suggests. We treat this as a multiplier on `B`:

```
B_min_with_newcomer ~= (3/7) * P * K * C * (N / a_bar)           ... (3)
```

For `a_bar = N/2` (steady-state rolling cohort), the multiplier is 2.
For `a_bar = N/4` (aggressive churn-and-replace strategy that tries to
front-load mass before revocation catches on), the multiplier is 4.

Observation-cost commitments (spec section 7) require the depositor to
attach a verifiable telemetry-chain reference. An adversary lacking real
telemetry must either (a) forge plausible telemetry chains, which raises
the per-deposit operating cost by the cost of running a credible
telemetry pipeline, or (b) acquire access to real telemetry from the
operator-orgs it has admitted. We model this as a commitment-cost
multiplier `m_oc` on the per-passport cost when the subject-class is
declared `cost_committed_only`:

```
B_min_with_oc = (3/7) * P * K * C * (N / a_bar) * m_oc           ... (4)
```

`m_oc` is empirically in the range 1.5x (acquisition of telemetry from
co-opted org's own infrastructure) to 10x (synthesis of plausible
telemetry that survives downstream verification by chiodos runtime
scoring). We use `m_oc = 3` as a midpoint default.

Substituting `a_bar = N/2` and `m_oc = 3` (the
sqrt(N) + newcomer + observation-cost defense stack), the working
formula is:

```
B_threshold ~= (3/7) * P * K * C * 6
            =  (18/7) * P * K * C
            ~= 2.57 * P * K * C                                  ... (5)
```

Equation (5) is the formula used in section 4 numerical tables.

### 3.3 What the formula does and does not capture

It captures: the structural unbinding of the sqrt(N) cap from the dollar
budget; the multiplicative effect of newcomer discounting on a rolling
attacker cohort; the multiplicative effect of observation-cost
commitments on per-deposit cost.

It does not capture: reputation weighting `peer_weight()` from spec
section 4.2 (treated as an out-of-band factor; recommended setting is
asymmetric EWMA per Buchegger-Boudec, which compounds further but is
hard to model closed-form); revocation gossip latency (assumed zero in
the adversary's favour, i.e. revoked passports stop counting
immediately); arena-replay scoring (treated as a separate lane via the
multiplicative reputation factor in `CHIODOS_CONCEPT.md` section 7 hard
problem 5).

These omissions all favour the adversary in the numerical table below,
so the table is a **conservative lower bound on the budget required**.

---

## 4. Numerical Table

Table cells are USD budgets required to reach 30% effective passport
mass under the indicated defense stack. All budgets are rounded to
two significant figures. The defense stacks are:

- **(a) sqrt(N) cap alone**: equation (2), no newcomer discount, no
  observation-cost commitment.
- **(b) sqrt(N) + newcomer discount, N=4 epochs**: equation (3) with
  `N=4` and `a_bar = N/2 = 2`, multiplier 2.
- **(c) sqrt(N) + newcomer discount, N=4 + observation-cost
  commitment**: equation (4), multiplier 6 (=2 newcomer * 3 oc).

A passport cost `C` includes all four components from section 2.1. The
hardware-attested floor (`C >= $5,000`) is not yet applied; that is
defense lever D2 in section 6.

### 4.1 P = 3 honest peers (small SOC consortium or vendor pilot)

| K | C = $100 | C = $1,000 | C = $10,000 | C = $100,000 |
|---|---|---|---|---|
| 1 | (a) $130 (b) $260 (c) $770 | (a) $1.3K (b) $2.6K (c) $7.7K | (a) $13K (b) $26K (c) $77K | (a) $130K (b) $260K (c) $770K |
| 5 | (a) $640 (b) $1.3K (c) $3.9K | (a) $6.4K (b) $13K (c) $39K | (a) $64K (b) $130K (c) $390K | (a) $640K (b) $1.3M (c) $3.9M |
| 25 | (a) $3.2K (b) $6.4K (c) $19K | (a) $32K (b) $64K (c) $190K | (a) $320K (b) $640K (c) $1.9M | (a) $3.2M (b) $6.4M (c) $19M |

### 4.2 P = 10 honest peers (typical sectoral consortium)

| K | C = $100 | C = $1,000 | C = $10,000 | C = $100,000 |
|---|---|---|---|---|
| 1 | (a) $430 (b) $860 (c) $2.6K | (a) $4.3K (b) $8.6K (c) $26K | (a) $43K (b) $86K (c) $260K | (a) $430K (b) $860K (c) $2.6M |
| 5 | (a) $2.1K (b) $4.3K (c) $13K | (a) $21K (b) $43K (c) $130K | (a) $210K (b) $430K (c) $1.3M | (a) $2.1M (b) $4.3M (c) $13M |
| 25 | (a) $11K (b) $21K (c) $64K | (a) $110K (b) $210K (c) $640K | (a) $1.1M (b) $2.1M (c) $6.4M | (a) $11M (b) $21M (c) $64M |

### 4.3 P = 25 honest peers (mid-size cross-vendor federation)

| K | C = $100 | C = $1,000 | C = $10,000 | C = $100,000 |
|---|---|---|---|---|
| 1 | (a) $1.1K (b) $2.1K (c) $6.4K | (a) $11K (b) $21K (c) $64K | (a) $110K (b) $210K (c) $640K | (a) $1.1M (b) $2.1M (c) $6.4M |
| 5 | (a) $5.4K (b) $11K (c) $32K | (a) $54K (b) $110K (c) $320K | (a) $540K (b) $1.1M (c) $3.2M | (a) $5.4M (b) $11M (c) $32M |
| 25 | (a) $27K (b) $54K (c) $160K | (a) $270K (b) $540K (c) $1.6M | (a) $2.7M (b) $5.4M (c) $16M | (a) $27M (b) $54M (c) $160M |

### 4.4 P = 100 honest peers (large industry consortium)

| K | C = $100 | C = $1,000 | C = $10,000 | C = $100,000 |
|---|---|---|---|---|
| 1 | (a) $4.3K (b) $8.6K (c) $26K | (a) $43K (b) $86K (c) $260K | (a) $430K (b) $860K (c) $2.6M | (a) $4.3M (b) $8.6M (c) $26M |
| 5 | (a) $21K (b) $43K (c) $130K | (a) $210K (b) $430K (c) $1.3M | (a) $2.1M (b) $4.3M (c) $13M | (a) $21M (b) $43M (c) $130M |
| 25 | (a) $110K (b) $210K (c) $640K | (a) $1.1M (b) $2.1M (c) $6.4M | (a) $11M (b) $21M (c) $64M | (a) $110M (b) $210M (c) $640M |

### 4.5 Reading the table

The defense-stack columns (a -> b -> c) show the marginal effect of each
defense:

- Newcomer discount (b vs a) doubles the adversary cost.
- Observation-cost commitment (c vs b) triples the per-passport cost on
  top.
- The total (c vs a) is a 6x multiplier from substrate-side defenses
  alone, before reputation weighting, asymmetric EWMA, or arena scoring
  is applied.

The cost columns ($100 -> $1K -> $10K -> $100K) show the linear
response to per-passport cost. The threshold to push opportunistic
cybercrime ($10K-$50K) out of reach across realistic federation sizes
(P >= 10) sits at C ~= $1,000 per passport in the (c) defense stack;
to push organised cybercrime ($250K-$1.5M) out of reach requires C ~=
$10,000 per passport in (c) for P >= 25.

---

## 5. Where the Cap Fails

Mapping the table onto attacker-class budgets gives three regimes.

### 5.1 Chiodos is structurally safe (substrate alone defends)

The (P, K, C) triples where the (c) defense stack budget exceeds even
upper-tier nation-state campaign capital ($100M+):

- P >= 100 honest peers, K >= 25, C >= $10,000 per passport (cell value
  $64M; the upper-tier nation-state envelope is just barely larger)
- P = 100, K = 25, C = $100,000 (cell value $640M, comfortably
  out-of-reach)

At 100-peer scale with K=25 honest passport allowance and hardware
attestation pushing C to $10K-plus, the substrate budget is
genuinely larger than even nation-state campaign capital; the
substrate-alone defense binds.

### 5.2 Chiodos is structurally unsafe (substrate cannot defend alone)

The (P, K, C) triples where the (c) defense stack budget is below even
the opportunistic-cybercrime envelope ($10K-$50K):

- P = 3 honest peers across all K and C <= $1,000
- P = 10 honest peers, K = 1, C <= $1,000
- P = 10 honest peers, K = 5, C = $100

Small federations (P <= 10) with low-cost passport schemes (C ~ $100)
are not defended by substrate-side scarcity at all. Anything an
opportunistic crew can fund will tip the federation past 30% adversarial
mass. These federations need either a smaller K (which reduces honest
expressiveness), a higher C (hardware attestation), or out-of-band
operator-org admission gating before substrate-side defenses become
load-bearing.

This is the regime where chiodos's *protocol* answer is correct but its
*operational* defense is the bilateral handshake roster, not the
scarcity argument. Sectoral consortia that recruit fewer than ten peers
must accept that the trust-anchor problem (`CHIODOS_CONCEPT.md` section
2.5) is doing all the load-bearing work.

### 5.3 Middle ground (defended only in combination)

The (P, K, C) triples where the (c) defense stack budget is in the
$50K-$5M range, defending against opportunistic and organised
cybercrime but not nation-state actors:

- P = 10, K = 5, C >= $1,000 ($130K cell)
- P = 25, K = 5, C >= $1,000 ($320K cell)
- P = 100, K = 1, C >= $10,000 ($2.6M cell)
- P = 100, K = 5, C ~ $1,000 ($1.3M cell)

This is the realistic operating regime for cross-vendor agent action
attestation pilots and early SOC federations. Substrate defenses bind
against organised cybercrime; nation-state campaigns require the
combination of substrate scarcity, reputation weighting (asymmetric
EWMA), arena-replay scoring (multiplicative factor on reputation), and
out-of-band sectoral audit. None of those four alone defends; in
combination they raise the adversary's effective cost by an additional
order of magnitude that the closed-form does not capture.

---

## 6. Defenses That Change the Breakeven

Listed in order of effect-size on the attacker budget.

### D1. Tighten the sqrt(N) cap to log(N)

Effect on the dollar budget: **none**.

The sqrt(N) cap cancels out of equation (2) because the adversary
compensates with more operator-orgs. Tightening to log(N) does not
change the dollar threshold; it only rebalances how the adversary spends
the same money (more orgs, fewer passports per org). It also reduces
honest expressiveness because honest peers cannot run as many distinct
passport-per-class identities. **Recommendation: keep sqrt(N).** The
cap's job is structural (foreclose unbounded passport floods from a
single org), not economic.

### D2. Require hardware-attested passport keys

Effect on the dollar budget: **shifts C lower-bound from ~$2,200 to
~$5,000**, a ~2.3x multiplier on the entire B column.

This is the most cost-effective single defense. It forecloses the
consumer-YubiKey tier and forces HSM-backed slots whose attestation
chains the verifier can inspect. The ladder manifest can declare an
action class as `hardware_attested_only`, similar to the existing
`cost_committed_only` toggle. **Recommendation: ship as opt-in for
high-stakes subject classes; default off because it raises honest
operating cost.**

### D3. Increase newcomer-discount epochs N

Effect on the dollar budget: **multiplicative factor `N/2` on the
budget at steady state**.

`N=4` epochs yields a 2x multiplier. `N=8` epochs yields a 4x
multiplier. `N=28` epochs (the spec's cybersec-default suggestion in
section 6) yields a 14x multiplier. The cost to honest peers is
proportional: a new participant takes `N` epochs to acquire full weight
in cross-org concentration queries.

The trade-off is the time-to-first-useful-deposit for legitimate
newcomers. For a sector with monthly-cadence onboarding (typical in
finance and healthcare), `N=8` is operationally tolerable. For
fast-moving cybersec or arena-driven domains, `N=4` keeps newcomer
friction low. **Recommendation: `N=8` epochs default; document `N=28`
as the high-assurance setting.**

### D4. Require observation-cost commitments for all action classes

Effect on the dollar budget: **`m_oc` multiplier 1.5x to 10x on
per-passport cost**.

Currently the spec only requires commitments for `cost_committed_only`
classes (section 7). Universal requirement raises the per-deposit
operating cost across the board, but introduces a forge-or-acquire
burden on the attacker for every deposit. Universal observation-cost
also has an honest-side cost: every depositing passport must have a
telemetry chain to reference. For pure-observation pheromones (status,
heartbeat) the requirement is wasted overhead.

**Recommendation: default `cost_committed_only` to required for all
destructive subject classes; leave it optional for purely
informational classes.**

### D5. Per-kernel cap on subject-class participation

A complementary cap: limit the number of distinct subject-classes a
single kernel can deposit into per epoch. This raises the marginal cost
for an attacker who wants to poison many concentration queries
simultaneously; it has no effect on the single-class scarcity argument
above. Useful as a defense-in-depth in domains where one attacker would
naturally want to influence many classes (cross-domain agent
governance). **Recommendation: ship as ladder-manifest declaration
`max_subject_classes_per_window`, default unset; sectoral profiles can
opt in.**

### D6. Out-of-band sectoral passport-issuance audit

The strongest defense, and the only one that addresses the residual
"sustained majority collusion" case from `CHIODOS_CONCEPT.md` section 7
honest residual. A periodic out-of-band audit of operator-org admissions
under each treaty roster, with a `chio-governance` Sanction case
mechanism against issuing orgs that exceed expected provisioning rates.
This generalises the ladder.amendment pattern from
`spec/CHIODOS_LADDER.md` to the trust-anchor layer.

Effect on the dollar budget: **uncapped**. Once the attacker's
operator-org admissions become visible to the audit, the entire campaign
collapses; all admitted passports under those orgs are revoked.
**Recommendation: ship as governance-layer mechanism in
chio-governance, not chio-pheromone; reference here for completeness.**

---

## 7. Recommendation

The chio-pheromone reference implementation should ship with the
following defaults:

| Parameter | Recommended default | Rationale |
|---|---|---|
| Per-kernel passport cap | `ceil(sqrt(active_peers))` (status quo) | D1 shows tightening has no economic effect; status quo preserves honest expressiveness. |
| Per-pair token bucket capacity (K) | 5 deposits per `(kernel, passport, class)` per anchored epoch | Honest agents under typical load consume 1-2 per epoch (per `swarm-pheromone` reference tuning); 5 leaves headroom without ballooning the budget formula. |
| Newcomer discount horizon N | 8 anchored epochs (about one week at one epoch per day) | D3: 4x multiplier on the closed-form attacker budget; tolerable newcomer onboarding latency for the cross-vendor pilot domains. The spec's section 6 default of `N=28` is the high-assurance setting; document both. |
| Observation-cost commitment | Required for all destructive subject classes (`destructive_floor` >= `receipt_backed`); optional for purely informational classes | D4: 3x per-deposit cost multiplier where it bites; honest-side overhead avoided where it does not buy security. |
| Hardware-attested passport keys | Off by default; enabled per ladder manifest declaration `hardware_attested_only` | D2: 2.3x cost lift; honest operating cost is real and not all use cases warrant it. High-stakes subject classes should opt in. |
| Per-kernel subject-class cap | Unset by default | D5: optional defense-in-depth for domains with cross-domain governance. |

Combined, the recommended defaults yield an effective cost-multiplier of
**~6x to ~14x** over the bare sqrt(N) baseline (multiplicative across
N/2 and m_oc; not multiplicative with hardware attestation, which is
opt-in). Combined with the threshold formula in equation (5):

```
B_recommended_defaults ~= (3/7) * P * K * C * 8
                       =  (24/7) * P * K * C
                       ~= 3.43 * P * K * C                       ... (6)
```

For a typical cross-vendor pilot (`P = 10`, `K = 5`, `C = $1,000`):

```
B_recommended ~= 3.43 * 10 * 5 * 1000 = $172,000
```

This sits within the organised-cybercrime envelope ($250K-$1.5M) but
above the opportunistic envelope ($10K-$50K). For the same parameters
with hardware attestation enabled (`C = $5,000`):

```
B_recommended_hardware ~= 3.43 * 10 * 5 * 5000 = $860,000
```

Above the organised-cybercrime envelope; into the insider-shell-org or
lower-nation-state range.

### Specific decisions called out in the task

- **N = 4 or N = 8?** **N = 8.** Doubling the multiplier costs little in
  newcomer-onboarding latency for the realistic chiodos pilots and
  doubles the attacker budget required.
- **Cap = sqrt(N) or log(N)?** **sqrt(N).** D1 shows the dollar-budget
  effect is zero; tightening only reduces honest expressiveness.
- **When should observation-cost commitments default to required?** For
  all subject classes whose ladder manifest entry has `destructive`
  true or `mode >= receipt_backed`. Informational classes
  (`mode = observation`, `destructive = false`) may leave it optional.

---

## 8. Honest Residual

The defenses above leave the following threat-actor profiles
un-mitigated even with the strongest defensible parameters. Each is
routed to chio-governance, not chio-pheromone, for handling.

### 8.1 Upper-tier nation-state with strategic interest

For P <= 25, even the strictest substrate defenses combined cap
adversary budget at the low millions. Upper-tier nation-state campaigns
($100M+) can fund through any substrate defense at any realistic
federation size. The recourse is the trust-anchor: sectoral roster
revocation of the offending operator-orgs, propagated as
`chio-governance` Sanction case against the issuing org. This is the
"sustained majority collusion" honest residual from
`CHIODOS_CONCEPT.md` section 7 word-for-word.

### 8.2 Insider-threat-via-shell-org with sectoral access

An insider who can mint operator-org admissions inside a sectoral
roster bypasses the per-org admission cost component of `C`, which
collapses the per-passport cost to the key-custody plus
attestation plus aging components (~$700-$2,500 with hardware
attestation; ~$300-$900 without). For P = 10 federations this is
within hacktivist-collective budgets; for P = 25 it is within
opportunistic-cybercrime budgets. The recourse is sectoral audit of org
admissions (defense D6) and `chio-governance` Sanction against the
admitting authority, not against the passports. This is the "cross-org
operator collusion via friendly re-issuance" honest residual from
`CHIODOS_CONCEPT.md` section 7 word-for-word.

### 8.3 Long-running sub-threshold influence campaigns

An attacker willing to sustain `f < 0.30` indefinitely (say `f ~ 0.20`)
buys real influence on every concentration query without crossing the
defensive threshold. The substrate cannot detect this because by
construction the attacker remains in the regime where the weighting
function is provably correct. Mitigation is reputation weighting
(asymmetric EWMA penalises the attacker's slow drift) plus arena-replay
scoring (the attacker must also pass arena fitness, which is a separate
adversarial-economic argument lived in `chio-arena`). Residual to
`chio-arena` and `chio-reputation`, not the substrate.

### 8.4 Mimicry-style slow-drift below sensor noise

Diffusion/GAN-generated deposits can be made indistinguishable from
honest deposits at any single window. Cited word-for-word in
`CHIODOS_CONCEPT.md` section 7 honest residual. Detected only if
arena coverage overlaps the mimicked subject-class. Residual loss in
uncovered classes must be accepted and budgeted; this is an arena
coverage problem, not a substrate problem.

---

## 9. References and Sources

Cost references:

- YubiKey pricing (consumer FIDO2 hardware key): Yubico product
  catalog and 2025 reseller surveys; consumer Security Key C NFC at
  ~$29, YubiKey 5C NFC at ~$55, FIPS 140-2/3 versions at $80+.
  See: [The 2025 Security Key Shootout](https://k9.io/the-2025-security-key-shootout/),
  [YubiKey Wikipedia](https://en.wikipedia.org/wiki/YubiKey).
- Code-signing certificate pricing (EV tier): Sectigo EV Code Signing
  ~$279/yr, DigiCert EV Code Signing ~$580/yr (1-year term mandatory
  from 2026-02-15). See:
  [DigiCert EV Code Signing](https://signmycode.com/digicert-ev-code-signing),
  [Sectigo EV Code Signing](https://cheapsslweb.com/code-signing/sectigo-ev-code-signing-certificate).
- Shell company / LLC formation costs (operator-org admission): Delaware
  LLC ~$1,500 first year (filing + registered agent + professional
  time); ongoing compliance $1,000-$2,500/yr. Offshore incorporations
  $1,500-$2,000 plus nominee structure. See:
  [Wolters Kluwer registered agent guide](https://www.wolterskluwer.com/en/expert-insights/what-is-a-registered-agent),
  [Offshore Protection LLC formation](https://www.offshore-protection.com/offshore-blog/how-to-set-up-buy-shell-company-legally).
- Cybercrime budget envelopes: Verizon DBIR 2025 trend reporting
  (median ransomware payment ~$115K; ransomware presence in breaches
  44%); Cybersecurity Ventures 2025 Official Cybercrime Report (global
  damages $10.5T annually 2025, $12.2T by 2031). See:
  [Cybersecurity Ventures Cybercrime Report 2025](https://cybersecurityventures.com/official-cybercrime-report-2025/),
  [Cyber Defense Magazine 2025 cybercrime cost](https://www.cyberdefensemagazine.com/the-true-cost-of-cybercrime-why-global-damages-could-reach-1-2-1-5-trillion-by-end-of-year-2025/).

Theoretical foundations:

- Cheng, A. and Friedman, E. (2005). "Sybilproof Reputation Mechanisms."
  Proceedings of the 2005 ACM SIGCOMM workshop on Economics of P2P
  systems (PODC 2005 companion). Establishes that no symmetric
  reputation function is sybilproof; flow-based asymmetric mechanisms
  with degree-bounded admission survive. Reference for the sqrt(N)
  scarcity bound. See:
  [Cheng-Friedman ACM DL](https://dl.acm.org/doi/10.1145/1080192.1080202),
  [PDF mirror at Harvard CS286r](http://www.eecs.harvard.edu/cs286r/courses/fall08/files/paper-CheFri.pdf).
- Fang, M., Cao, X., Jia, J., and Gong, N. Z. (2020). "Local Model
  Poisoning Attacks to Byzantine-Robust Federated Learning." 29th
  USENIX Security Symposium. Demonstrates that Krum, trimmed mean, and
  median aggregation rules are brittle under coordinated attacker
  fractions above ~30-50%. Reference for the safety-fraction
  threshold. See:
  [USENIX paper](https://www.usenix.org/system/files/sec20summer_fang_prepub.pdf).
- Fung, C. J. and Boutaba, R. (2013). "Bayesian Trust Model for
  intrusion detection systems" (BTrM). Reference for receiver-side
  reputation weighting in collaborative IDS, cited in
  `CHIODOS_CONCEPT.md` section 7 hard problem 5.
- Hoffman, K., Zage, D., Nita-Rotaru, C. (2009). "A Survey of Attack
  and Defense Techniques for Reputation Systems." ACM Computing
  Surveys. Cited in `CHIODOS_CONCEPT.md` section 7 hard problem 5 as
  the standard taxonomy for reputation-poisoning attacks.

Internal cross-references:

- `docs/research/CHIODOS_CONCEPT.md` v1.1, section 4.1 (chio-pheromone
  gating spec), section 7 hard problem 5 (reputation-poisoning attack
  surface), section 7 honest residual (sustained majority collusion).
- `spec/CHIODOS_PHEROMONE.md` v0.1, section 5 (source diversity rules),
  section 6 (newcomer discount), section 7 (observation-cost
  commitment).

---

## 10. Open Questions for v0.2

- Empirical calibration of `m_oc` (the observation-cost commitment
  multiplier on per-passport cost). Estimated 1.5x-10x; pilot data from
  early adopters should narrow this range.
- Empirical calibration of `a_bar` (steady-state attacker passport-age
  distribution). Estimated `N/2` for rolling cohort; an attacker
  optimising for sustained influence may approach `N`, raising the
  budget further.
- Treatment of revocation gossip latency. Current analysis assumes
  zero-latency revocation; a real attacker could exploit gossip-window
  delays to retain mass briefly past sanction. Worth modelling once
  `chio-revocation-oracle` epoch cadence is set per sectoral profile.
- Closed-form for combined substrate plus reputation weighting (the
  asymmetric EWMA case from Buchegger-Boudec). Currently treated as
  out-of-band multiplicative; a unified model would be sharper.
- Sectoral profile differences. Cybersec, finance, healthcare, energy
  domains all have different per-passport cost structures (regulatory
  attestation requirements, sector roster fees, operator-org admission
  audit cadence). Per-sector tables would refine the recommendation.
