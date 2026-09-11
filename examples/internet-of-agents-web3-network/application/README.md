# A delegated work order with real escrow

Four Chio kernels turn a service request into retained work and a settled order.
Atlas holds the budget and pays, ProofWorks reviews the escrow specification,
CipherWorks checks its proof-leaf obligations under a two-hop grant, and Meridian
admits providers and independently verifies the resulting receipts.

The application deploys Chio's Solidity identity registry, root registry and
escrow on its own persistent local EVM. A release transaction binds the exact
review receipt to the funded order. A second order produces an incomplete review,
requires separate partial-acceptance approval, releases the accepted amount and
refunds the remainder after the local chain's deadline.

## Run it

Install Rust 1.94.1, Node.js 22 or later, uv, and the matching Chio CLI from
[this public source candidate](https://github.com/backbay-labs/chio/pull/5).
From this directory:

```sh
uv run --locked run.py
```

The launcher builds the host, installs locked JavaScript dependencies, creates a
private run directory, starts the four hosts and local chain, and executes both
orders and a standard x402 report purchase. It stops its own processes on completion and retains all receipts,
transactions, work products, balances and logs. It never overwrites an existing
run or reads another example's qualification report.

`execution.json` is the complete capture. `operations.json` holds each exact
request and response, including refused requests. `atlas/chain-orders/` retains
the actual funding, root-publication, release and refund transactions. Each host
owns `admission.db`, `receipts.db` and `business.db`; `credentials/` and
`operator/` contain private development keys and must not be published.

## Read the application

- `src/main.rs` issues signed capabilities, installs the domain guard, starts the
  four HTTP kernel hosts and persists actual kernel receipts.
- `domain.py` authenticates the capability holder and workload certificate,
  checks current runtime appraisal, enforces exact invoice approval and durable
  treasury exposure, and executes the installed business operations.
- `native_trust.py` creates a native passport from actual kernel receipts, exchanges
  bilateral evidence, verifies holder-bound challenges and obtains a native
  federation-issued capability. Its two-call limit survives host restart.
- `operator_control.py` owns workload registration, application measurement,
  quarantine and independent approval. These functions are not agent tools.
- `chain.mjs` compiles and deploys the actual Chio contracts, funds the order,
  publishes its receipt-bound root and executes release/refund transactions.
- `x402.mjs` uses the official @x402/core and @x402/evm 2.25.0 client and
  facilitator for a real HTTP 402 / PAYMENT-SIGNATURE / PAYMENT-RESPONSE
  exchange. The fixed-price report costs 10,000 local base units. Chio checks
  its separate signed approval before the wallet authorizes payment.
- `LocalPaymentToken.sol` is the local EIP-3009 test asset used by that standard
  exact scheme. It inherits unrestricted test minting and is not a deployable
  production asset. The application contacts only its private chain 31337.
- `evidence.py` verifies the independently selected host key, signature, request
  ID, capability, arguments and exact output for each consumed receipt.
- `run.py` connects the roles and attempts the failure cases through the same
  HTTP entrypoints used for permitted work.

## Give a subcontractor less authority

`issue_delegated_capability` requires the parent's holder to sign a child binding
and the trusted issuer to sign the new token. Each binding preserves the child's
ID, scope, expiry and budget share. The provider holds review and delegation
rights. Its specialist receives only its own review operation, a smaller quota,
and a reduced budget share. It cannot inherit payment tools that the provider
never held. The host checks the signed ancestor snapshots and revocation state
before dispatch.

The ordinary scoped-delegation helper refuses unsupported caveated parents and
multi-hop aggregate-budget or cumulative-approval families. This application's
money limit is enforced independently in Atlas's durable treasury ledger.

## What the run exercises

The three-provider RFQ rejects a provider without completed work and a quote over
the budget. Its admitted provider's quality ratio comes from actual signed review
results, with the small sample count shown explicitly. Later incomplete work
changes the observed ratio and causes a new admission to fail.

The refusal attempts include changed invoice amounts, missing approval,
unsupported rails, quote replay, unrecognized review instructions, forged
membership, stale capabilities, a mismatched workload certificate, quarantined
runtime, repeated settlement and a revoked parent. Revocation and settled order
state are checked again after restarting the same hosts and chain.

The default local operator approves the example's exact invoices under the
included demonstration policy. In an application with a human operator, keep
that key outside the agent process, show the invoice for review, then use:

```sh
uv run --locked operator_control.py approve RUN_DIRECTORY quote.json approval.json
```

The agent submits the resulting signed approval with that exact invoice.
Workload identities use locally issued Ed25519 X.509 certificates with SPIFFE URI
SANs and an explicitly selected CA. Runtime appraisal signs the measured
application source on the local host; it is not a hardware attestation service.
The payment challenge uses the application's `chio-escrow-receipt` scheme. The
local token represents test dollars, and refund qualification records its
explicit advance of local EVM time.

## Recover an interrupted payment

The run deliberately interrupts the first funding operation after the local
chain has mined it, before the publisher records success. The kernel retains an
incomplete outcome. The payer restarts and invokes `recover` with only the order
ID. Recovery reads the exact escrow from the contract, compares all persisted
terms, collects its actual transaction records, and updates the durable order.
It does not fund a second escrow. Unpublished retained intents resume with their
original amount, beneficiary and proof. A caller cannot replace those values in
a recovery request.

The subsequent settlement independently simulates an altered receipt hash and a
wrong beneficiary against the deployed contract. Both calls must revert and
leave balances unchanged before the valid release transaction is sent.

## Inspect native trust

Meridian uses native Chio passport and federation commands behind its installed
admission responsibility. Its verifier policy selects the issuer before seeing a
presentation, requires actual work evidence and consumes each holder challenge
once. The passport attestor explicitly selects ProofWorks' kernel signer; it
never infers a trusted key from submitted history. No synthetic or backdated
receipts are inserted. The native scorecard reports the observed one-work-item
sample; budget-store metrics remain unavailable in that credential, while
Atlas enforces monetary exposure in its own live durable order ledger.

The issuer returns a separate native capability limited to two ProofWorks review
calls. The third call is refused, including after a host restart. The provider's
recursive subcontracting capability is a different grant with a signed parent
chain; the example preserves this distinction in the complete request records.

Run the offline verifier with the auditor key selected separately from the
capture:

```sh
uv run --locked verify.py execution.json --auditor-key YOUR_SELECTED_AUDITOR_KEY
```

It checks every exact request/result against the final auditor's independently
fetched records, all receipt signatures, the capability catalog, selected hosts,
order IDs, settlement records, contract source hash and token balances.

## Standard x402 payment

After settling both work orders, Atlas buys the original signed review from a
local HTTP resource server. This is the standard x402 v2 `exact` EVM scheme,
using an EIP-3009 authorization. The Chio escrow order itself remains a separate
receipt-bound settlement flow; it is not relabeled as an x402 payment.

The client allowlists this run's exact asset, chain, recipient and 10,000-unit
price. The service releases the report only after the official facilitator
confirms its transfer. Changed amount, recipient, signature and network fail;
reusing the payment cannot deliver or transfer twice. The receipt retains the
actual payment headers, transaction, report and before/after balances.

Final balances are buyer 650,000, provider 350,000 and escrow zero, from an
initial 1,000,000 local test units. The provider received 200,000 for complete
work, 140,000 for accepted partial work and 10,000 for the x402 report. The
60,000-unit remainder of the second escrow returned to the buyer.

Payment intent is persisted before transmission. If an x402 publication has an
uncertain outcome, the application refuses automatic repurchase and retains the
nonce and any observed transaction for inspection. The escrow's automatic
recovery demonstrations cover funding, root publication and refund; they do not
claim automatic recovery of the separate HTTP resource server.
