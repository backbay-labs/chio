# Risk Comptroller Facility and Insurance/Capital Architecture

Branch: `research/chio-launch-trust-network`
Scope: research and planning only
Mode: no code changes
Confidence: high for current-source observations, moderate for proposed sequencing and actuarial sizing, low for external carrier, reinsurer, or regulated-capital assumptions until partner requirements are known.

## Position

Chio already has the raw pieces for a credible risk-finance stack: signed underwriting inputs and decisions, exposure ledgers, credit scorecards, credit facilities, reserve-backed bonds, capital-book reports, capital instructions, liability-market providers, quotes, bound coverage, claim packages, disputes, adjudications, payout instructions, payout receipts, settlement instructions, settlement receipts, portable passports, portable reputation, and bounded web3 execution. The problem is not absence of primitives.

The problem is that these primitives are not yet governed by one canonical facility state machine and one risk comptroller projection. Without that projection, launch copy can truthfully say Chio has evidence-bound underwriting and claim orchestration, but it cannot yet say Chio runs a capital facility, insurance cover, reserve policy, claim appeal, slash, payout, reimbursement, and recovery book as one controlled financial system.

The correct architecture is a `Risk Comptroller Facility`: a deterministic, signed state projection over existing artifacts. It should not replace underwriting, credit, market, settlement, governance, reputation, or passport crates. It should reconcile them, fail closed when they disagree, and publish one facility passport that capital providers, insurers, buyers, and operators can verify.

## Current Assets

| Area | What exists | Source refs |
| --- | --- | --- |
| Trust-control risk-finance routes | The protocol lists operator report, behavioral-feed, underwriting-input, exposure-ledger, credit-scorecard, settlements, economic-completion-flow, reputation compare, portable reputation summary/event/evaluate routes. | `spec/PROTOCOL.md:1297-1322` |
| Behavioral and underwriting evidence surfaces | Behavioral-feed is a signed insurer/risk export over receipts, governed actions, settlement, metering, and optional reputation. Underwriting-input is a signed policy input over receipts, reputation, certification, runtime assurance, settlement, metering, and shared evidence. | `spec/PROTOCOL.md:1784-1817` |
| Underwriting decision surface | Underwriting decisions are deterministic operator-facing artifacts with outcomes `approve`, `reduce_ceiling`, `step_up`, and `deny`; issued decisions are immutable, premium state is explicit, and appeals do not rewrite prior receipts. | `spec/PROTOCOL.md:1819-1864`, `crates/chio-underwriting/src/decision.rs:18-25`, `crates/chio-underwriting/src/decision.rs:165-230` |
| Underwriting evidence model | Inputs include receipt counts, governed decisions, runtime assurance, pending/failed settlement, metered actions, shared evidence refs, reputation, certification, compliance, and signals. | `crates/chio-underwriting/src/lib.rs:196-374` |
| Premium model | Premium pricing is deterministic, compliance-score banded, and optionally adjusted by behavioral anomaly. It fails closed on invalid or missing score. | `crates/chio-underwriting/src/premium.rs:1-29`, `crates/chio-underwriting/src/premium.rs:82-170`, `crates/chio-underwriting/src/premium.rs:293-383` |
| Marketplace credit limits | Marketplace limit calculation has hard-coded reputation-tier ceilings and denies revoked certification. | `crates/chio-underwriting/src/marketplace_limits.rs:39-43`, `crates/chio-underwriting/src/marketplace_limits.rs:77-109` |
| Exposure ledger | The exposure ledger is a signed economic-position surface with per-receipt governed ceiling, reserve, settlement, provisional-loss, recovered amount, quoted premium, and persisted underwriting decision projections. It explicitly does not claim cross-currency netting, claim-adjudication closure, or recovery lifecycle. | `spec/PROTOCOL.md:1881-1902`, `crates/chio-credit/src/lib.rs:220-343` |
| Credit scorecard | Subject-scoped scorecards summarize reputation support, settlement discipline, loss pressure, and exposure stewardship, but they are not capital allocation by themselves. | `spec/PROTOCOL.md:1922-1938`, `crates/chio-credit/src/lib.rs:347-518` |
| Facility policy and issuance | Credit facilities support `grant`, `manual_review`, and `deny`, with lifecycle, credit limit, utilization ceiling, reserve ratio, concentration cap, TTL, and capital source. The protocol explicitly says this is not a live capital market and does not execute bonds, slash reserves, or clear external capital by itself. | `spec/PROTOCOL.md:2074-2096`, `crates/chio-credit/src/lib.rs:520-636` |
| Credit bonds and reserve states | Credit bonds support `lock`, `hold`, `release`, and `impair`, with active/released/impaired/expired lifecycles, facility references, collateral, reserve requirement, outstanding exposure, reserve ratio, coverage ratio, and capital source. | `spec/PROTOCOL.md:2324-2347`, `crates/chio-credit/src/lib.rs:720-836` |
| Capital book | The capital book is a source-of-funds ledger over receipts, facilities, bonds, and loss lifecycle; it fails closed on missing subject, contradictory counterparty, mixed currency, more than one live facility/bond, or no active granted facility. | `spec/PROTOCOL.md:2133-2151`, `crates/chio-credit/src/credit/capital_book_query.rs:1-130`, `crates/chio-credit/src/credit/capital_and_execution.rs:6-164` |
| Capital instructions | Capital instructions support `lock_reserve`, `hold_reserve`, `release_reserve`, `transfer_funds`, and `cancel_instruction`, with authority chain, execution window, rail, intended state, reconciled state, observed execution, and fail-closed validation. Intent is separate from observed execution. | `spec/PROTOCOL.md:2153-2193`, `crates/chio-credit/src/credit/capital_and_execution.rs:168-303`, `crates/chio-credit/src/credit/capital_and_execution.rs:305-520` |
| Capital allocation | Capital allocation is simulation-first with outcomes `allocate`, `queue`, `manual_review`, and `deny`; it can draft instructions but is not proof of external execution. | `spec/PROTOCOL.md:2195-2235`, `crates/chio-credit/src/credit/capital_and_execution.rs:547-663` |
| Bonded execution controls | Bonded execution simulation has a kill switch, max autonomy, minimum runtime assurance, call-chain requirement, locked-reserve requirement, and delinquency denial. | `crates/chio-credit/src/credit/capital_and_execution.rs:683-813` |
| Loss lifecycle and reserve control | Loss lifecycle events cover delinquency, recovery, reserve release, reserve slash, and write-off. Reserve control has execution states and appeal states, and support boundaries include immutable lifecycle, bond projection, reserve-control execution, and appeal window support. | `spec/PROTOCOL.md:2349-2379`, `crates/chio-credit/src/risk_reports.rs:19-61`, `crates/chio-credit/src/risk_reports.rs:84-203` |
| Provider risk package | Provider risk packages assemble exposure, scorecard, facility policy, compliance, latest facility, runtime assurance, certification, recent loss history, and evidence refs for external capital review; autonomous pricing and liability market are explicitly outside that report. | `spec/PROTOCOL.md:2114-2131`, `crates/chio-credit/src/risk_reports.rs:455-674` |
| Liability provider registry | Providers have admitted carrier, surplus line, captive, and risk pool types; coverage classes include tool execution, data breach, financial loss, professional liability, and regulatory response; policies include jurisdictions, currencies, evidence requirements, max coverage, claims support, quote TTL, and bound coverage support. | `crates/chio-market/src/provider.rs:12-96` |
| Quote, pricing authority, placement, and bound coverage | Quote request/response, pricing authority, placement, bound coverage, and auto-bind artifacts validate provider policy, signed risk packages, facility, underwriting decision, capital book, currency, coverage, premium, quote TTL, provider claims support, authority envelopes, and capital availability. | `crates/chio-market/src/quote.rs:21-177`, `crates/chio-market/src/quote.rs:337-587`, `crates/chio-market/src/placement.rs:13-290` |
| Claim package and dispute artifacts | Claim packages bind signed bound coverage, exposure, bond, loss event, claimant, event time, amount, claim reference, narrative, receipt ids, and evidence refs. Claim responses support acknowledged/accepted/denied; disputes require denied or partial responses; adjudications support claim-upheld, provider-upheld, and partial-settlement outcomes. | `crates/chio-market/src/claim.rs:13-171`, `crates/chio-market/src/claim.rs:173-375` |
| Payout and settlement artifacts | Payout instruction requires payable adjudication, signed capital instruction, `transfer_funds`, facility commitment source, matching amount/currency/subject, fresh execution window, and no preexisting observed execution. Payout receipt, settlement instruction, and settlement receipt then reconcile observed amount and counterparties. | `crates/chio-market/src/settlement.rs:21-42`, `crates/chio-market/src/settlement.rs:87-275`, `crates/chio-market/src/settlement.rs:277-591` |
| Legacy insurance flow | `insurance_flow` connects deterministic premium pricing, market bind, claim evidence, and settlement handoff. It validates policy in force, currency, receipt evidence, digest/signature, coverage cap, and claim lane kind. Default coverage is 100x quoted premium. | `crates/chio-market/src/insurance_flow.rs:1-49`, `crates/chio-market/src/insurance_flow.rs:185-252`, `crates/chio-market/src/insurance_flow.rs:326-459`, `crates/chio-market/src/insurance_flow.rs:576-717` |
| Web3 settlement boundary | The official web3 surface binds approved capital instructions to ERC-20 approval, escrow, release, refund, and bond-vault lifecycle, then projects chain state to execution receipts. It is not permissionless settlement, automatic dispute adjudication, custodian service, or regulated insurer. | `spec/PROTOCOL.md:2274-2292` |
| Autonomous insurance automation boundary | The protocol names autonomous pricing input/authority/decision, capital-pool optimization/simulation, execution/rollback/comparison/drift, and qualification matrix artifacts, all bounded by authority envelopes, rollback, human interrupt, and web3 truth. | `spec/PROTOCOL.md:2307-2322` |
| Trust-control handler gates | Risk-finance handlers require admin read for reports and service auth plus receipt DB or authority material for issuance, capital, facility, bond, loss, provider, quote, placement, bound coverage, claims, payout, and settlement routes. | `crates/chio-control-plane/src/trust_control/risk_finance_handlers.rs:15-50`, `crates/chio-control-plane/src/trust_control/risk_finance_handlers.rs:105-199`, `crates/chio-control-plane/src/trust_control/risk_finance_handlers.rs:201-614`, `crates/chio-control-plane/src/trust_control/risk_finance_handlers.rs:616-1158` |
| Route registry | Control-plane route constants cover underwriting, exposure, scorecard, capital book, capital instructions, allocations, facility, bonds, bond loss, backtest, provider risk, liability providers, quote, pricing, placement, bound coverage, claims, payout, settlement, and portable reputation. | `crates/chio-control-plane/src/trust_control/service_types.rs:140-183`, `crates/chio-control-plane/src/trust_control/service_types.rs:190-207` |
| Persistence | SQLite stores signed underwriting decisions and appeals, facilities, bonds, loss lifecycle, liability providers, quotes, authorities, placements, bound coverages, auto-bind decisions, claim packages, responses, disputes, adjudications, payout instructions/receipts, and settlement instructions/receipts with duplicate rejection and parent existence checks. | `crates/chio-store-sqlite/src/receipt_store/underwriting_credit.rs:4-260`, `crates/chio-store-sqlite/src/receipt_store/liability_market.rs:4-260`, `crates/chio-store-sqlite/src/receipt_store/liability_claims.rs:4-1087` |
| Governance and market slashing | Governance defines signed charters, leases, action classes, and governance receipt artifacts. Open-market penalty artifacts support hold bond, slash bond, and reverse slash, with proposed/enforced/reversed/denied/superseded states and bounded evaluation. | `crates/chio-governance/src/lib.rs:1-7`, `crates/chio-open-market/src/penalty.rs:17-180`, `crates/chio-open-market/src/evaluation.rs:27-176`, `crates/chio-open-market/src/evaluation.rs:356-496` |
| Local reputation | Reputation scoring is storage-agnostic, verifies receipt integrity against trusted kernel keys, and scores boundary pressure, resource stewardship, least privilege, history depth, specialization, delegation hygiene, reliability, and incidents. | `crates/chio-reputation/src/lib.rs:1-7`, `crates/chio-reputation/src/lib.rs:50-73`, `crates/chio-reputation/src/model.rs:66-158`, `crates/chio-reputation/src/score.rs:1-126` |
| Portable reputation | Portable reputation signs summary and negative-event artifacts; evaluation requires subject agreement, unique issuers, allowed issuers, bounded freshness, and weighting profile. Unsupported, stale, future-dated, duplicate, blocked, or contradictory inputs fail closed. | `spec/PROTOCOL.md:1942-1953`, `crates/chio-credentials/src/portable_reputation.rs:99-224`, `crates/chio-credentials/src/portable_reputation.rs:322-412`, `crates/chio-credentials/src/portable_reputation.rs:522-792` |
| Agent passport and OID4VCI/OID4VP | Chio issues agent passport, verifier policy, presentation challenge/response, cross-issuer portfolio, trust pack, and migration schemas. OID4VCI can deliver native Chio passport, SD-JWT VC, or JWT VC profiles. OID4VP supports one narrow verifier-side bridge over the passport credential lane with direct-post JWT. | `spec/PROTOCOL.md:2451-2488`, `spec/PROTOCOL.md:2489-2623`, `spec/PROTOCOL.md:2625-2648`, `crates/chio-credentials/src/artifact.rs:280-321`, `crates/chio-credentials/src/oid4vp.rs:1-120`, `crates/chio-credentials/src/oid4vp.rs:716-1010` |

## Exact Gaps

1. No canonical risk comptroller root artifact. Existing artifacts are individually strong, but there is no signed `facility_state_report` or `risk_comptroller_report` that reconciles underwriting, facility, bond, reserve, capital book, coverage, claim, payout, settlement, reputation, slashing, and passport state into one fail-closed projection. Confidence: high.

2. No canonical facility state machine. Facility, bond, capital allocation, liability coverage, claim, payout, settlement, and loss lifecycle each define local states. There is no single state-transition contract that says which artifact advances the facility, which artifact freezes it, and which artifact closes it. Confidence: high.

3. Underwriting is not actuarial. Current premium pricing is a deterministic compliance-score band with optional behavioral anomaly adjustment. Legacy insurance flow defaults coverage to 100x quoted premium. There is no frequency/severity model, loss triangle, IBNR reserve, tail capital, credibility weighting, attachment/exhaustion curve, or reinsurance cession model. Confidence: high.

4. Facility issuance is not capital execution. The protocol is explicit that facility policy/issuance does not lock collateral, execute bonds, slash reserves, clear external capital, or perform autonomous insurer pricing. Capital instructions separate intended state from observed execution. Confidence: high.

5. Exposure ledger is not a full insurance ledger. It intentionally does not claim cross-currency netting, claim-adjudication closure, or recovery lifecycle. It includes reserve, provisional loss, recovered amount, and premium projections, but not earned premium, unearned premium, loss adjustment expense, IBNR, salvage, subrogation, ceded reinsurance, or regulatory capital. Confidence: high.

6. Capital book is not a multi-provider capital stack. The current capital book fails closed on more than one live facility/bond and mixed currency. That is correct for safety, but insufficient for a launch trust network that wants senior capital, first-loss reserve, reinsurer, facility provider, insurer, and custodian layers. Confidence: high.

7. Claim workflow has no dedicated appeal artifact. Underwriting appeals exist, reserve-control appeal windows exist, and claim disputes/adjudications exist. There is no first-class claim appeal that reopens or escalates an adjudication while preserving payout/slash holds. Confidence: high.

8. Reserve slashing and market slashing are separate. Credit loss lifecycle has reserve slash. Open-market penalties have hold/slash/reverse slash. There is no unified sanction ledger that prevents double-slashing, orders claim payout before punitive slash, or reconciles reserve-control appeal state with governance reversal state. Confidence: high.

9. Payout and settlement are artifact-complete but not portfolio-complete. A single claim can produce a payout instruction, payout receipt, settlement instruction, and settlement receipt. There is no portfolio-level reconciliation across all open claims, provider reimbursements, reinsurance recoveries, facility reimbursements, and write-offs. Confidence: high.

10. Passport and proof are not wired into risk finance as gates. Chio has agent passports, OID4VCI, OID4VP, lifecycle status, portable reputation, and portable negative events. Risk-finance flows do not yet require a passport presentation, active lifecycle resolution, issuer allowlist, subject match, or portable negative-event evaluation before underwriting, facility allocation, binding, payout, or slash. Confidence: high.

11. Provider risk package is review input, not binding cover. It packages the right evidence for external capital review, but it is not a policy, not a capital commitment, not a claim reserve, and not an executable facility. Confidence: high.

12. Runtime gates are distributed across handlers and validators. Individual routes require admin read, service auth, receipt DB, authority material, signatures, windows, source types, currency match, and parent existence. There is no single runtime gate set that can be audited as "facility is allocatable", "coverage is bindable", "claim is payable", "reserve is slashable", or "portfolio is healthy". Confidence: high.

13. The current liability market is not a regulated insurer marketplace. Provider registry is curated, provider support boundary is not automatic trust admission or permissionless federation, and web3 settlement explicitly does not make Chio a custodian or regulated insurer. Confidence: high.

14. No risk data mart. The system can produce reports and backtests, but there is no canonical loss-development dataset keyed by subject, facility, policy, coverage class, tool class, receipt type, runtime assurance, reputation band, jurisdiction, premium, claim, payout, recovery, and settlement lag. Confidence: high.

15. No launch-facing facility passport. There is no portable artifact that says: this subject has active passport status, approved underwriting, granted facility, held reserve, active bond, bound coverage, allocatable capital, no blocking negative events, no delinquency, and current claim/reserve status, with evidence refs. Confidence: high.

## Canonical Facility State Machine

The facility should be modeled as an append-only event projection. Existing signed artifacts are events; the risk comptroller is the deterministic projector. Current state is derived, never edited in place.

| Canonical state | Entry artifact or condition | Required exits | Fail-closed conditions |
| --- | --- | --- | --- |
| `evidence_cold` | No fresh behavioral-feed, underwriting-input, exposure-ledger, reputation, runtime assurance, or passport evidence. | Build signed evidence inputs. | Any attempt to underwrite, allocate, quote, bind, or pay. |
| `evidence_ready` | Signed behavioral-feed, underwriting-input, exposure-ledger, scorecard, runtime/certification evidence, and optional portable reputation evaluation are fresh and subject-aligned. | `underwriting_pending`. | Missing subject, stale evidence, mismatched tool/server, mixed currency, untrusted kernel keys, blocked portable negative event. |
| `underwriting_pending` | Underwriting decision report or issue request is in process. | `underwriting_approved`, `underwriting_reduced`, `underwriting_step_up`, or `underwriting_denied`. | Missing compliance score when required, insufficient history, stale receipt history, missing certification/runtime assurance, failed settlement backlog above policy threshold. |
| `underwriting_approved` | Active signed decision with outcome `approve`, active lifecycle, approved review state, and premium state either quoted or not applicable by policy. | `facility_policy_evaluated`, `underwriting_appealed`, `underwriting_superseded`, `underwriting_expired`. | Decision inactive, superseded, denied, open accepted appeal replacement missing, premium withheld when coverage requested. |
| `underwriting_reduced` | Active signed decision with outcome `reduce_ceiling`; budget recommendation reduces but does not deny. | `facility_policy_evaluated` with reduced limit. | Caller requests unreduced ceiling or policy treats reduction as manual review. |
| `underwriting_step_up` | Active signed decision requires higher assurance tier or remediation. | `evidence_ready` after remediation or `facility_manual_review`. | Allocating, quoting, binding, or payout before step-up completion. |
| `underwriting_denied` | Active signed decision denies. | `underwriting_appealed` or terminal close. | Any facility grant, quote, bind, allocation, or payout unless a signed accepted appeal creates replacement decision. |
| `underwriting_appealed` | Open underwriting appeal exists. | Accepted appeal with replacement decision, rejected appeal, or expired appeal. | Facility increase, coverage bind, reserve release, or punitive slash while appeal affects the amount or permission being disputed. |
| `facility_policy_evaluated` | Credit facility policy evaluated from exposure, scorecard, and underwriting. | `facility_granted`, `facility_manual_review`, or `facility_denied`. | Multiple active facilities, mixed currency, expired underwriting, unsupported capital source, utilization/concentration breach. |
| `facility_granted` | Active signed facility artifact with `grant`, limit, utilization ceiling, reserve ratio, concentration cap, TTL, and capital source. | `reserve_required`, `facility_expired`, `facility_superseded`, `facility_suspended`. | No active granted facility, expired TTL, subject mismatch, currency mismatch, utilization ceiling exceeded. |
| `reserve_required` | Facility terms or bond terms require reserve. | `reserve_locked`, `reserve_held`, or `facility_manual_review`. | Allocating capital without required reserve math. |
| `reserve_locked` | Active bond or capital instruction locks reserve. | `reserve_held`, `reserve_released`, `bond_impaired`. | Missing bond, inactive bond, missing authority chain, stale execution window, observed execution mismatch. |
| `reserve_held` | Bond or capital instruction holds required reserve; no delinquency blocks autonomy. | `capital_allocatable`, `reserve_release_pending`, `reserve_slash_pending`, `bond_impaired`. | Held reserve below requirement, open reserve-control appeal blocking movement, outstanding delinquency. |
| `capital_book_open` | Capital book resolves one subject, one currency, active facility/bond, and authoritative source-of-funds report. | `capital_allocatable`, `manual_capital_review`, or `capital_denied`. | Missing subject, contradictory counterparty, mixed currency, multiple live facilities/bonds, no active granted facility. |
| `capital_allocatable` | Allocation decision outcome is `allocate`, or `queue` if policy allows queued execution. | `capital_instruction_pending`, `coverage_quotable`, or `manual_capital_review`. | Simulation-only decision treated as observed execution, external execution claimed without observed receipt. |
| `capital_instruction_pending` | Signed instruction with action, source, amount, authority chain, execution window, rail, intended state, and unreconciled observed state. | `capital_execution_matched`, `capital_execution_mismatched`, or `instruction_cancelled`. | Authority missing/stale, custodian mismatch, amount/currency mismatch, source/action mismatch, stale window. |
| `capital_execution_matched` | Observed execution is present and reconciled as matched. | `coverage_quotable`, `payout_receipted`, or `settlement_receipted`. | Using a mismatched observed execution as capital truth. |
| `coverage_quotable` | Provider policy supports jurisdiction/currency/evidence, provider risk package is signed, facility/capital/underwriting are current. | `coverage_quoted` or `coverage_declined`. | Provider inactive, max coverage exceeded, evidence requirement missing, provider does not support claims when claims are required. |
| `coverage_quoted` | Quote response terms match request and provider policy. | `pricing_authorized`, `placement_pending`, or quote expiry. | Quote expired, coverage/premium/currency/effective window mismatch. |
| `pricing_authorized` | Pricing authority validates facility, underwriting, capital book, coverage cap, premium cap, and authority envelope. | `placement_pending`, `auto_bind_denied`, or `manual_bind_review`. | Coverage exceeds facility limit/provider max/capital book committed amount, underwriting inactive, budget denied, auto-bind without provider support. |
| `coverage_bound` | Bound coverage validates placement, policy number, effective window, premium, provider support for bound coverage and claims. | `claim_open`, `coverage_expired`, `coverage_cancelled`. | Claim event outside coverage window, claim amount over coverage, provider does not support claims. |
| `claim_open` | Claim package validates signed bound coverage, exposure ledger, bond, loss event, claimant, amount, event time, receipt refs, and subject/currency consistency. | `claim_acknowledged`, `claim_denied`, `claim_accepted`. | Duplicate receipt refs, claim amount <= 0, amount greater than coverage, event outside coverage, mixed-currency exposure, subject mismatch. |
| `claim_acknowledged` | Provider response acknowledges without payment decision. | `claim_accepted`, `claim_denied`, or stale-response review. | Treating acknowledgment as payable adjudication. |
| `claim_accepted` | Provider accepts covered amount <= claim amount. | `payout_ready` or `dispute_open` if partial. | Accepted amount above claim/coverage or missing covered amount. |
| `claim_denied` | Provider denies with reason. | `dispute_open` or terminal provider-upheld close. | Dispute missing denied/partial response. |
| `dispute_open` | Claim dispute exists over denied or partial response. | `adjudicated`. | Payout, reserve release, or reserve slash before adjudication if dispute is material. |
| `adjudicated` | Adjudication outcome is claim-upheld, provider-upheld, or partial-settlement with valid amount semantics. | `appeal_window_open`, `payout_ready`, or terminal close. | Awarded amount missing when required, awarded amount present when forbidden, amount above claim. |
| `appeal_window_open` | Reserve-control or claim policy creates a time-bound hold before release/slash/payout finality. | `appeal_window_closed`, `claim_appealed`, or policy-defined emergency payout. | Reserve slash, reserve release, or final write-off before appeal window closure when policy requires hold. |
| `claim_appealed` | Proposed new artifact: claim appeal over adjudication or payout/slash decision. | Appeal accepted with replacement adjudication, appeal rejected, or appeal expired. | Rewriting original claim response/adjudication rather than issuing a new superseding appeal artifact. |
| `reserve_release_pending` | Loss lifecycle event or reserve-control source permits release. | `reserve_released` after authority/execution/reconciliation. | Open appeal, unresolved payout, outstanding delinquency, or missing authority. |
| `reserve_slash_pending` | Loss lifecycle event permits reserve slash. | `reserve_slashed` after authority/execution/reconciliation, or reversal through appeal/governance. | Double slash, punitive slash before claim payout priority, slash without reserve-control source, slash while appeal open unless explicit emergency policy. |
| `payout_ready` | Payable adjudication exists and payout amount is bounded. | `payout_instructed`. | Provider-upheld outcome, zero/negative award, award above claim/coverage, no capital source. |
| `payout_instructed` | Payout instruction validates adjudication and signed transfer-funds capital instruction with unreconciled observed execution. | `payout_matched` or `payout_amount_mismatch`. | Capital instruction already claims observed execution, source is not facility commitment, subject/amount/currency/window mismatch. |
| `payout_matched` | Payout receipt observes amount/currency/window matching the instruction. | `settlement_instructed`, `recovery_open`, or `claim_closed_paid`. | Amount mismatch treated as paid. |
| `settlement_instructed` | Settlement instruction validates matched payout receipt, capital book, kind, amount, topology, authority chain, window, and rail. | `settlement_matched`, `settlement_amount_mismatch`, or `settlement_counterparty_mismatch`. | Settlement amount above payout, capital book subject mismatch, missing payer/custodian authority. |
| `settlement_matched` | Settlement receipt observes amount/currency/payer/payee matching instruction. | `recovery_open`, `reimbursed`, `claim_closed_paid`. | Counterparty mismatch or amount mismatch treated as final. |
| `recovery_open` | Recovery, reinsurance reimbursement, facility reimbursement, or subrogation expected. | `recovered`, `written_off`, or `reserve_slashed`. | Recovery counted before observed execution. |
| `recovered` | Loss lifecycle recovery or settlement receipt records matched recovery. | `claim_closed_recovered`, `reserve_release_pending`. | Recovery currency mismatch, subject mismatch, duplicate recovery id. |
| `written_off` | Loss lifecycle write-off records unrecovered balance. | Terminal close or governance review. | Write-off while payout or recovery still pending under policy. |
| `facility_closed` | Facility expired, superseded, denied, fully released, or closed after all claims/recoveries/reserves settle. | None except new facility cycle. | Closing with open claim, open payout, open settlement mismatch, open reserve-control appeal, or unresolved slashing reversal. |

## Runtime Gates

These gates should be exposed as one risk-comptroller report and enforced before any new issue, bind, payout, settlement, reserve release, or reserve slash route.

1. Evidence gate: require fresh signed behavioral-feed, underwriting-input, exposure-ledger, credit-scorecard, runtime assurance, certification if policy requires it, and receipt DB access. Reject missing subject, unsupported query scope, tool name without tool server, stale receipt window, untrusted kernel keys, or contradictory shared evidence.

2. Passport gate: require active lifecycle resolution for any portable passport used as underwriting, facility, provider, claimant, or capital-provider evidence. Reject stale, superseded, revoked, not-found, malformed, unsigned, wrong-subject, wrong-holder, unsupported profile, or issuer-not-allowed presentations. Current OID4VP supports exactly one requested credential, so multi-party gates must run one presentation per actor or use a bounded portfolio policy.

3. Portable reputation gate: evaluate portable summaries and negative events only through local weighting policy. Reject stale, future-dated, duplicate issuer, subject mismatch, issuer-not-allowed, probationary when policy rejects it, and locally blocking events such as `payment_default`, `fraud_signal`, or `dispute_loss`.

4. Underwriting gate: require active signed underwriting decision, approved review state, permitted outcome, active lifecycle, and premium state compatible with the requested action. `approve` permits normal facility evaluation, `reduce_ceiling` clamps all downstream limits, `step_up` blocks until remediation, and `deny` blocks unless an accepted appeal creates a replacement decision.

5. Facility gate: require one active granted facility for one subject and one currency. Reject no active facility, expired TTL, more than one live facility/bond where the current capital book cannot reconcile them, mixed currency, utilization breach, concentration breach, reserve ratio breach, or stale underwriting.

6. Reserve and bond gate: require active bond/reserve state when policy or bonded execution requires it. Reject inactive, impaired, expired, insufficient, unreconciled, open-delinquency, stale execution window, missing authority, or appeal-blocked reserve state.

7. Capital book gate: require source-of-funds authoritative report with one subject, one currency, matching facility/bond, and no contradictory counterparty. Reject simulation-only allocation as execution proof.

8. Capital instruction gate: require action/source compatibility, positive amount, matching currency, authority chain, source-owner approval, custodian approval when rail requires it, non-expired execution window, intended state, and no impossible reconciliation. `transfer_funds` must reference governed receipt or completion-flow provenance when funds move for a receipt.

9. Provider/coverage gate: require active provider policy for jurisdiction/currency, required evidence refs, signed provider risk package, active facility, active underwriting, capital book capacity, quote TTL, and provider support for claims/bound coverage when binding coverage. Reject auto-bind when provider policy does not support it.

10. Claim gate: require signed bound coverage, exposure ledger, bond, loss event, claimant, claim amount/currency, event time inside coverage window, unique receipt ids, and subject alignment across exposure/bond/loss/coverage. Reject oversized claims and mixed-currency exposure.

11. Dispute/adjudication gate: require dispute only after denied or partially accepted response. Require adjudication amount semantics to match outcome. Reject payout until there is a payable adjudication or accepted claim path under policy.

12. Appeal/slash gate: require appeal-window status before reserve release or reserve slash. Reject double slash, slash before payout priority when policy requires claim-first ordering, slash without reserve-control source, and punitive market slash without enforced governance/market penalty authority.

13. Payout gate: require payable adjudication and signed transfer-funds capital instruction whose observed execution is intentionally absent. Reject payout instruction if the capital instruction already claims observed execution, because the payout receipt must be the explicit execution proof.

14. Settlement gate: require matched payout receipt, signed capital book, settlement topology, payer/payee/beneficiary roles, payer authority, custodian authority, window, rail, and amount <= payout. Reject amount mismatch and counterparty mismatch as final settlement.

15. Closure gate: require no open underwriting appeal that changes limit, no open claim/dispute/appeal, no open payout, no settlement mismatch, no unreconciled recovery, no appeal-blocked reserve control, and no unresolved reverse-slash/governance event.

## Exposure, Reserve, and Capital Ledger Design

The risk comptroller should publish a signed `facility_ledger_projection` over six ledgers. Each row is immutable and hash-bound to signed source artifacts. Derived balances are reproducible from ordered rows. No ledger may silently net currencies.

### 1. Exposure Ledger

Purpose: measure gross and governed financial exposure by subject, facility, policy, tool, receipt, and currency.

Required keys:

- `subject_key`
- `facility_id`
- `underwriting_decision_id`
- `capability_id`
- `agent_subject`
- `tool_server`
- `tool_name`
- `receipt_id`
- `completion_flow_row_id`
- `currency`
- `event_time`
- `evidence_refs`

Required balances:

- `governed_ceiling`
- `financial_amount`
- `pending_settlement_amount`
- `failed_settlement_amount`
- `settled_amount`
- `provisional_loss_amount`
- `recovered_amount`
- `quoted_premium_amount`
- `active_quoted_premium_amount`

Core invariant:

`net_open_exposure = financial_amount + pending_settlement_amount + failed_settlement_amount + provisional_loss_amount - settled_amount - recovered_amount`

The formula is a comptroller projection, not a claim about the current crate. It must be bounded by the existing exposure-ledger support boundary until claim adjudication and recovery are fully integrated.

### 2. Reserve Ledger

Purpose: prove required, locked, held, released, slashed, impaired, and appeal-blocked reserves.

Required keys:

- `reserve_account_id`
- `facility_id`
- `bond_id`
- `capital_instruction_id`
- `loss_lifecycle_event_id`
- `reserve_control_source_id`
- `currency`
- `appeal_state`
- `execution_state`
- `authority_chain_hash`
- `rail_id`
- `observed_execution_ref`

Required balances:

- `required_reserve`
- `locked_reserve`
- `held_reserve`
- `released_reserve`
- `slashed_reserve`
- `impaired_reserve`
- `appeal_blocked_reserve`

Core invariants:

- `held_reserve + locked_reserve >= required_reserve` for `capital_allocatable`.
- `released_reserve` is allowed only when all policy-defined claim, recovery, and appeal holds are closed.
- `slashed_reserve` must reference exactly one reserve-control source and must be idempotent by `reserve_control_source_id`.
- Open-market penalty slash and credit reserve slash are separate sources and must not consume the same reserved amount twice.

### 3. Capital Book Ledger

Purpose: track source-of-funds and movement authority.

Required keys:

- `capital_source_id`
- `source_kind`
- `source_role`
- `facility_id`
- `bond_id`
- `capital_provider_id`
- `custodian_id`
- `capital_instruction_id`
- `allocation_decision_id`
- `currency`
- `authority_chain_hash`
- `execution_window`
- `rail_kind`

Required balances:

- `committed_capital`
- `held_capital`
- `drawable_capital`
- `drawn_capital`
- `disbursed_capital`
- `released_capital`
- `repaid_capital`
- `impaired_capital`
- `unreconciled_instruction_amount`

Core invariants:

- `drawable_capital = committed_capital - held_capital - drawn_capital - impaired_capital`, clamped at zero.
- `transfer_funds` cannot be counted as disbursed until a matched observed execution exists.
- Capital allocation can reserve intent, but it cannot satisfy payout, settlement, or coverage capacity without matching capital-book and instruction gates.

### 4. Claim Ledger

Purpose: account for reported claims, provider decisions, disputes, adjudications, payout, settlement, reimbursement, recovery, and write-off.

Required keys:

- `claim_id`
- `bound_coverage_id`
- `policy_number`
- `provider_id`
- `claimant_subject`
- `facility_id`
- `bond_id`
- `loss_lifecycle_event_id`
- `claim_response_id`
- `dispute_id`
- `adjudication_id`
- `appeal_id`
- `payout_instruction_id`
- `payout_receipt_id`
- `settlement_instruction_id`
- `settlement_receipt_id`
- `currency`

Required balances:

- `reported_claim_amount`
- `accepted_claim_amount`
- `denied_claim_amount`
- `disputed_claim_amount`
- `awarded_claim_amount`
- `paid_claim_amount`
- `settled_claim_amount`
- `reimbursed_amount`
- `recovered_amount`
- `write_off_amount`
- `loss_adjustment_expense`

Core invariants:

- `awarded_claim_amount <= reported_claim_amount` and `reported_claim_amount <= bound_coverage_limit`.
- `paid_claim_amount` requires matched payout receipt.
- `settled_claim_amount` requires matched settlement receipt.
- `recovered_amount` requires loss lifecycle recovery or matched settlement receipt of recovery/reimbursement kind.
- Denied/provider-upheld claims carry zero payable amount unless a later accepted appeal supersedes the adjudication.

### 5. Premium Ledger

Purpose: connect pricing, quote, bound coverage, premium collection, earned premium, and reserve/capital charge.

Required keys:

- `quote_id`
- `pricing_authority_id`
- `placement_id`
- `bound_coverage_id`
- `underwriting_decision_id`
- `provider_id`
- `facility_id`
- `coverage_class`
- `jurisdiction`
- `currency`

Required balances:

- `quoted_premium`
- `bound_premium`
- `collected_premium`
- `earned_premium`
- `unearned_premium`
- `expense_load`
- `risk_margin`
- `capital_charge`
- `ceded_premium`

Core invariants:

- `bound_premium` must match quote terms and bound coverage.
- `collected_premium` must reference observed payment or settlement proof before treated as cash.
- `earned_premium` accrues over effective coverage period; launch MVP can use straight-line earning but must label it explicitly.

### 6. Slashing and Governance Ledger

Purpose: prevent punitive, reserve-control, and market slashes from conflicting.

Required keys:

- `sanction_case_id`
- `governance_receipt_id`
- `open_market_penalty_id`
- `reserve_control_source_id`
- `bond_id`
- `facility_id`
- `claim_id`
- `appeal_id`
- `currency`

Required balances:

- `bond_held_amount`
- `bond_slashed_amount`
- `reverse_slashed_amount`
- `claim_priority_reserved_amount`
- `punitive_available_amount`

Core invariants:

- Claim payout priority and punitive slash priority must be explicit in facility policy.
- Reverse slash must reference prior enforced hold/slash.
- Reserve slash must not exceed held reserve not already consumed by payout, impairment, or prior slash.
- Governance sanctions block local admission only when enforced and bound to current local trust activation truth.

## Claim, Dispute, Appeal, Slash, and Payout Lifecycle

1. Claim package: claimant submits signed bound coverage, exposure ledger, credit bond, loss lifecycle event, event time, amount, receipt ids, and narrative. The comptroller validates subject, coverage window, currency, amount <= coverage, no duplicate receipt refs, exposure support boundary, and loss-event-to-bond linkage.

2. Claim response: provider acknowledges, accepts, or denies. Acceptance must include covered amount <= claim amount. Denial must include reason. Acknowledgment is not payable.

3. Dispute: claimant disputes a denial or partial acceptance. A dispute against a fully accepted claim is invalid unless a future policy defines amount or timing dispute separately.

4. Adjudication: adjudicator upholds claim, upholds provider, or awards partial settlement. Award semantics are strict: claim-upheld and partial-settlement require awarded amount; provider-upheld forbids awarded amount.

5. Claim appeal: add a new artifact, not present today, for appeal over adjudication, payout mismatch, settlement mismatch, or reserve slash. It must reference original claim, response, dispute, adjudication, and requested remedy. It must never rewrite prior signed artifacts. Accepted appeal issues a replacement adjudication or replacement reserve-control event and marks the prior result superseded for future projection only.

6. Appeal hold: while claim appeal or reserve-control appeal is open, policy must decide which actions are held. Conservative default: hold reserve release, punitive slash, write-off, and facility closure; permit emergency claimant payout only when facility policy says claim-first payout outranks appeal finality.

7. Reserve slash decision: reserve slash is allowed only from credit loss lifecycle/reserve-control source or a governance/market penalty source. The comptroller must pick one accounting lane and prevent double consumption. Slash pending must carry appeal state, authority chain, rail, execution window, observed execution, and reconciliation.

8. Payout instruction: once payable adjudication or accepted claim exists, generate payout instruction subordinate to capital execution truth. It must embed a signed `transfer_funds` capital instruction, source `facility_commitment`, amount equal to awarded amount, subject match, fresh window, and no observed execution.

9. Payout receipt: observed payout execution records amount, currency, receipt ref, and execution time. Matched receipts advance claim to paid. Amount mismatch creates a mismatch state, not final paid state.

10. Settlement instruction: settlement clears recovery, reinsurance reimbursement, or facility reimbursement against the matched payout receipt and signed capital book. It must include payer, payee, beneficiary, authority chain, rail, and window.

11. Settlement receipt: observed settlement execution records amount, currency, payer, payee, and time. Matched receipt advances recovery/reimbursement. Amount or counterparty mismatch blocks closure.

12. Recovery, release, write-off: after payout and settlement/recovery attempts, loss lifecycle events record recovery, reserve release, reserve slash, or write-off. Reserve release requires closed appeal windows and no open payable claim on the same reserve. Write-off requires policy approval and no active recovery route under the selected facility state.

## Actuarial and Pricing Roadmap

The current premium model is intentionally deterministic and useful as a launch bootstrap, but it is not an insurance pricing model. The actuarial roadmap should be explicit.

### Phase A: Data contract

Build an actuarial event table from existing artifacts. Minimum columns:

- subject, issuer, provider, facility, bond, bound coverage, policy number
- tool server, tool name, coverage class, jurisdiction, currency
- underwriting outcome, risk class, reputation band, runtime assurance tier, certification state
- credit limit, utilization, reserve ratio, concentration cap, TTL
- premium quoted, premium bound, coverage limit, effective period
- receipt count, governed count, deny/cancel/incomplete count
- pending settlement, failed settlement, metered action required
- claim reported, accepted, denied, disputed, awarded, paid, recovered, reimbursed, written off
- payout lag, settlement lag, recovery lag, appeal lag
- portable negative event kinds and local blocking state

### Phase B: Deterministic expected-loss model

Replace pure band pricing with:

- `expected_loss = frequency * severity`
- `technical_premium = expected_loss + loss_adjustment_expense + expense_load + risk_margin + capital_charge`
- frequency factors from receipt history, denial/cancel/incomplete rates, settlement backlog, runtime assurance, certification, reputation, and portable negative events
- severity factors from facility limit, tool class, coverage class, jurisdiction, data sensitivity, settlement rail, and concentration
- capital charge from reserve ratio, tail VaR or TVaR proxy, and target return on capital

### Phase C: Backtesting and credibility

Use credit backtest and claim workflow data to measure:

- predicted versus actual claim frequency
- predicted versus actual severity
- premium adequacy by cohort
- reserve adequacy by cohort
- settlement-lag and recovery-lag distributions
- false-deny and false-approve cost
- drift by tool class, provider, jurisdiction, runtime tier, and reputation tier

Credibility should be explicit: new cohorts use conservative priors; mature cohorts earn limited credibility; portable reputation imports adjust priors only through local weighting.

### Phase D: Portfolio capital model

Add portfolio stress:

- top-N subject concentration
- top-N provider concentration
- correlated runtime-assurance failure
- settlement rail outage
- governance slash shock
- major data-breach class event
- portable negative-event contagion scenario

Outputs:

- required reserve by facility
- first-loss tranche
- external capital requirement
- reinsurer attachment/exhaustion
- capital-provider utilization
- facility suspend thresholds

### Phase E: Governed autonomous pricing

Only after Phases A-D have deterministic tests and backtests should Chio turn on autonomous pricing authority. The authority envelope must cap:

- max coverage
- max premium
- max discount
- max capital draw
- allowed coverage classes
- allowed jurisdictions
- allowed provider ids
- required human review thresholds
- rollback conditions
- drift stop conditions

## Proof and Passport Integration

The launch architecture should define a `facility passport` as a Chio-native signed report, not a generic SSI claim.

### Inputs

- Agent passport or cross-issuer portfolio for the subject, with active lifecycle status.
- OID4VCI-delivered native passport, SD-JWT VC, or JWT VC only within Chio's documented profile family.
- OID4VP presentation for current holder proof, issuer allowlist, exact requested disclosures, nonce/state/audience, and holder key binding.
- Portable reputation summaries and negative events evaluated through local weighting.
- Provider risk package.
- Underwriting decision and appeal state.
- Exposure ledger, scorecard, facility artifact, bond artifact, capital book, capital allocation, and capital instruction state.
- Bound coverage, claim workflow, payout, settlement, reserve-control, and loss lifecycle artifacts.

### Facility passport fields

- `facilityPassportId`
- `subjectKey`
- `subjectDid`
- `passportId`
- `passportLifecycleState`
- `passportIssuer`
- `portableCredentialProfile`
- `portableReputationEvaluationHash`
- `blockingNegativeEvents`
- `underwritingDecisionId`
- `underwritingOutcome`
- `premiumState`
- `facilityId`
- `facilityLifecycle`
- `currency`
- `creditLimit`
- `availableLimit`
- `reserveRequired`
- `reserveHeld`
- `reserveAppealBlocked`
- `bondId`
- `bondLifecycle`
- `capitalBookReportId`
- `coverageIds`
- `openClaimCount`
- `payableClaimAmount`
- `paidClaimAmount`
- `unrecoveredLossAmount`
- `slashedReserveAmount`
- `settlementMismatchCount`
- `riskComptrollerState`
- `evidenceRefs`
- `issuedAt`
- `expiresAt`
- `issuer`
- `signature`

### Proof rules

- Subject binding is mandatory: passport subject, underwriting subject, facility subject, capital book subject, bond subject, coverage subject, claim subject, and payout subject must agree or have an explicit signed migration/portfolio entry.
- Lifecycle is mandatory: only `active` portable lifecycle is healthy. Stale, superseded, revoked, notFound, or malformed lifecycle state is a hard deny for new allocation, bind, or payout.
- OID4VP is presentation proof, not capital proof. It proves holder binding and selected disclosure integrity; it does not prove underwriting, reserve, or settlement by itself.
- Portable reputation is input evidence, not a universal oracle. Local weighting, issuer allowlist, freshness, duplicate issuer rejection, probation handling, and blocking event handling remain mandatory.
- Facility passport acceptance requires all referenced signed artifacts to verify and all hashes to match. Missing optional artifacts may reduce capacity, but missing required artifacts deny state advancement.

## Tests and Gates

### Current tests to keep as baseline

- Capital book and allocation CLI coverage: `crates/chio-cli/tests/receipt_query_capital.rs:16`, `crates/chio-cli/tests/receipt_query_capital.rs:330`, `crates/chio-cli/tests/receipt_query_capital.rs:447`, `crates/chio-cli/tests/receipt_query_capital.rs:685`, `crates/chio-cli/tests/receipt_query_capital.rs:901`, `crates/chio-cli/tests/receipt_query_capital.rs:1134`.
- Credit loss lifecycle CLI coverage: `crates/chio-cli/tests/receipt_query_credit_loss.rs:16`.
- Liability claims CLI coverage, including provider risk package, provider issue, quote/placement, bound coverage, claim issue, response/dispute, payout, settlement, duplicate payout receipt rejection, workflow listing, oversized claim rejection, and invalid dispute rejection: `crates/chio-cli/tests/receipt_query_liability_claims.rs:187-203`, `crates/chio-cli/tests/receipt_query_liability_claims.rs:230-416`, `crates/chio-cli/tests/receipt_query_liability_claims.rs:539-641`, `crates/chio-cli/tests/receipt_query_liability_claims.rs:677-864`, `crates/chio-cli/tests/receipt_query_liability_claims.rs:875-904`, `crates/chio-cli/tests/receipt_query_liability_claims.rs:910`, `crates/chio-cli/tests/receipt_query_liability_claims.rs:1215-1241`.
- Legacy insurance flow coverage: `crates/chio-market/tests/insurance_flow.rs`.
- Provider fixture claims shell coverage: `scripts/tests/provider-fixture-claims.test.sh`.
- Passport/OID4VCI/OID4VP/portable lifecycle CLI coverage: `crates/chio-cli/tests/passport.rs`.
- Portable reputation unit coverage: `crates/chio-credentials/src/portable_reputation.rs:877-1060`.

### New gates required for Risk Comptroller Facility

1. State-machine golden projection: given a fixed ordered set of signed artifacts, the risk comptroller emits exactly one facility state, balances, and failure set.

2. Artifact reordering invariance: unordered input artifacts produce the same derived state after canonical ordering by event time, artifact kind priority, and artifact id.

3. Mixed-currency fail-closed: any attempt to net exposure, reserve, capital, payout, or settlement across currencies rejects.

4. Multiple live facility/bond fail-closed: current MVP rejects unless a later multi-source capital policy explicitly supports stacking.

5. Passport stale deny: stale, revoked, superseded, notFound, wrong-subject, wrong-holder, unsupported profile, and issuer-not-allowed passport presentations deny allocation and bind.

6. Portable negative event deny: blocking `PaymentDefault`, `FraudSignal`, or `DisputeLoss` events deny or manual-review facility allocation according to local weighting policy.

7. Underwriting appeal hold: open appeal blocks facility increase, reserve release, and punitive slash when the disputed issue affects limit, loss, or authority.

8. Reserve appeal hold: open reserve-control appeal blocks reserve release and slash unless facility policy carries an explicit emergency exception.

9. Claim-first priority: when policy states claim-first ordering, payout consumes available reserve/capital before punitive slash.

10. No double slash: same reserve-control source or market penalty cannot slash the same reserve twice.

11. Payout instruction truth: payout instruction with pre-observed capital execution rejects; payout receipt must provide execution truth.

12. Settlement topology truth: settlement receipt with wrong payer/payee/beneficiary creates mismatch state and blocks closure.

13. Recovery proof: recovered/reimbursed amount cannot reduce net loss without matched recovery lifecycle or settlement receipt.

14. Facility closure deny: closure rejects with any open claim, dispute, appeal, payout mismatch, settlement mismatch, unreconciled recovery, or unresolved reverse slash.

15. Actuarial backtest reproducibility: pricing backtest inputs, model version, policy snapshot, and outputs are hash-bound and deterministic.

Recommended command gates once implemented:

```bash
cargo test -p chio-cli --test receipt_query_capital
cargo test -p chio-cli --test receipt_query_credit_loss
cargo test -p chio-cli --test receipt_query_liability_claims
cargo test -p chio-market --test insurance_flow
cargo test -p chio-credentials portable_reputation
scripts/tests/provider-fixture-claims.test.sh
```

## Phased Plan

### Phase 0: Freeze the boundary

Deliverables:

- Write a short launch boundary stating that Chio currently provides signed risk-finance artifacts and bounded claim/payout/settlement orchestration, not a regulated insurer, custodian, permissionless capital market, or universal trust oracle.
- Adopt the canonical state names in this document for planning and tests.
- Define `risk_comptroller_state` as a projection over existing artifacts, not a new authority.

Exit criteria:

- Every launch claim can be mapped to an existing source artifact or an explicit future phase.
- No copy claims autonomous insurance pricing, external capital clearing, or reserve slashing unless the matching artifact and execution receipt exist.

### Phase 1: Risk comptroller report

Deliverables:

- Signed `risk_comptroller_report` over subject, currency, underwriting, exposure, facility, bond, reserve, capital book, coverage, claim, payout, settlement, reputation, passport, and governance/slashing state.
- Deterministic projection algorithm and golden fixtures.
- Failure codes for each runtime gate.

Exit criteria:

- Existing artifacts can be loaded and projected into one state without creating new financial behavior.
- Mixed currency, missing subject, stale passport, inactive facility, open appeal, and payout/settlement mismatch all fail closed.

### Phase 2: Facility passport

Deliverables:

- Signed `facility_passport` artifact over the report, with hash-bound refs to source artifacts.
- OID4VP/passport gate for subject identity and lifecycle.
- Portable reputation gate for imported summaries and negative events.

Exit criteria:

- A verifier can answer: "Is this subject currently allocatable, bindable, payable, slashable, or closable?"
- The answer includes evidence refs and failure reasons, not just a score.

### Phase 3: Ledger projection

Deliverables:

- Exposure, reserve, capital, claim, premium, and slashing ledger projections.
- Balance invariants and deterministic reconciliation.
- Claim-first versus slash-first priority as explicit facility policy.

Exit criteria:

- Every amount in a payout, settlement, recovery, release, slash, or write-off is explained by source artifacts.
- No reserve/capital amount can be consumed twice.

### Phase 4: Claim appeal and reserve-control integration

Deliverables:

- Claim appeal artifact and lifecycle.
- Reserve-control appeal integration with payout, release, slash, and closure gates.
- Governance/open-market slash bridge that prevents double-slashing and supports reverse slash.

Exit criteria:

- Adjudication, appeal, payout, reserve release, reserve slash, and reverse slash can coexist without rewriting prior artifacts.
- Facility closure is impossible while material appeal or reversal state is open.

### Phase 5: Actuarial pricing v1

Deliverables:

- Actuarial data mart from reports and ledgers.
- Deterministic expected-loss model with frequency, severity, expense load, risk margin, and capital charge.
- Backtest report by cohort and model version.

Exit criteria:

- Premium and reserve recommendations are reproducible from source artifacts.
- Model drift and loss-ratio thresholds can trigger manual review or quote suspension.

### Phase 6: Capital stack and reinsurance

Deliverables:

- Multi-source capital policy that safely expands beyond current one-live-facility/bond boundary.
- First-loss, facility-provider, insurer, reinsurer, and custodian account roles.
- Reinsurance reimbursement settlement kind with attachment/exhaustion and recoverable balance.

Exit criteria:

- Capital-provider exposure, reserve, payout, reimbursement, and impairment are separable by role.
- Multi-source netting remains single-currency per facility or explicitly denied.

### Phase 7: Governed autonomous insurance automation

Deliverables:

- Autonomous pricing authority, capital-pool optimization, execution, rollback, comparison, drift, and qualification matrix bound to the comptroller report.
- Human interrupt and kill switch wired to allocation, bind, payout, release, and slash gates.

Exit criteria:

- Automation can quote or bind only within explicit authority caps.
- Any drift, mismatch, stale evidence, blocked portable event, or open appeal moves to manual review.

## Strongest Recommendations

1. Build `risk_comptroller_report` before adding any new insurance product behavior. It is the missing control plane that makes existing artifacts commercially legible.

2. Treat the facility state machine as the launch contract. Every route that issues, binds, pays, settles, releases, slashes, or closes should be explainable as a state transition.

3. Wire passport and portable reputation into risk-finance gates, but keep them local-policy inputs. Do not market portable reputation as a global score or passport as capital proof.

4. Separate claim payout, reserve release, reserve slash, and market slash in the ledger. Double-consumption of reserve is the highest-risk accounting failure.

5. Do not ship autonomous insurer pricing claims until actuarial backtests, reserve adequacy, and capital-charge logic exist. The current deterministic premium band is a bootstrap signal, not insurance pricing.
