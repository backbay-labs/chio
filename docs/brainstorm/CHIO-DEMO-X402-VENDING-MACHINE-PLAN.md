# Chio Demo: x402 Pay-Per-Call Vending Machine

Status: buildable implementation plan (brainstorm). Target: Chio's first public demo.
Venue: Base Sepolia, USDC only, no native token (US-person jurisdiction constraint).
Grounded in the facilitator design spike (FAC-1..FAC-7) and product Concept 1.

This plan is a 1-2 week cut. It builds ON TOP of the `chio/m2-build` merge and needs a
Base Sepolia contract deployment for the escrow-backed follow-on act (not for act one).

## 1. Demo narrative

30-second story:
1. A provider runs any HTTP API behind `chio api protect` (the `chio-api-protect` sidecar).
2. A buyer agent calls the protected endpoint and gets back `HTTP 402 Payment Required`
   with an x402 `accepts[]` body: USDC on Base Sepolia, an amount, a `payTo`, a resource id.
3. The agent signs an EIP-3009 `transferWithAuthorization` over the USDC contract
   (`0x036CbD53842c5426634e7929541eC2318f3dCF7e`, EIP-712 domain name `USDC`, version `2`),
   attaches it as the `X-PAYMENT` header, and retries.
4. Chio runs its local fail-closed money-safety checks, delegates settlement to a facilitator,
   and once the USDC transfer confirms on Base Sepolia the sidecar returns `200` with the
   real API result plus a Chio payment receipt.
5. The full pay -> verify -> settle -> serve chain (four sha256 digests bound to a transaction
   passport) is served live in the Proof Room via `chio proof serve`, with the on-chain tx hash
   linkable to a Base Sepolia explorer.

Fail-closed failure case (the denial-receipt story, equally important to show):
- The agent replays a spent EIP-3009 nonce, or signs for the wrong `payTo`/amount/asset, or the
  authorization window is expired. Chio's local pre-checks reject BEFORE any broadcast, no nonce
  is burned, and the sidecar returns a fresh `402` (never a partial `200`). If the facilitator
  `/settle` returns `success:false`, the adapter emits `status: refunded` and the Proof Room
  validator rejects the bundle closed (`x402 payment was refunded`,
  `crates/platform/chio-agent-web-interop/src/artifacts/x402.rs:51`). The spectator sees the
  protocol refuse to serve value it was not paid for, with a verifiable denial artifact.

## 2. Architecture: 402 -> EIP-3009 sign -> facilitator settle -> receipt -> Proof Room

Flow and the exact surfaces each step touches (REUSE = exists, BUILD = new work):

- 402 requirements: `crates/economy/chio-settle/src/payments.rs`
  - REUSE `X402PaymentRequirements` (payments.rs:22), `X402SettlementMode::PrepaidAuthorization`
    (payments.rs:15), `build_x402_payment_requirements` (payments.rs:116).
  - BUILD a wire-schema mapper: the Chio projection is not the x402 v1 wire shape
    (scheme/network/maxAmountRequired-as-string/asset-as-contract-address). See FAC-1.
- Sidecar 402 emission: `crates/products/chio-api-protect`
  - REUSE the protect sidecar; BUILD the x402 `accepts[]` responder + `X-PAYMENT` retry handling.
- Agent EIP-3009 signing (payer side): `crates/economy/chio-settle/src/payments.rs`
  - REUSE `prepare_transfer_with_authorization` (payments.rs:473) which emits
    `PreparedTransferWithAuthorization` (payments.rs:59) with the exact `authorization_digest`
    (0x1901 EIP-712 digest, payments.rs:670) the payer signs; `ApprovalBinding` (payments.rs:192)
    binds chain_id/payee/amount/token_contract; `Eip3009NonceStore` gives single-use replay
    rejection. BUILD the payer secp256k1 signing over `authorization_digest` and an ecrecover
    check `== from` on the verify side (spike: not present today). See FAC-3.
- Facilitator settle: BUILD the facilitator client (see section 3, FAC-2). This is the one
  genuinely missing capability: nothing in-repo broadcasts to a public chain
  (`submit_call` uses `eth_sendTransaction`, egress contract is loopback-only).
- Receipt + 4-digest evidence: `crates/platform/chio-agent-web-interop/src/artifacts/x402.rs`
  - REUSE the validator (validated on this branch). It requires four 64-lowercase-hex digests:
    `resource_digest`, `payment_requirements_digest`, `payment_proof_digest`, `settlement_digest`;
    `status` in {authorized, settled} (refunded fails closed); `source_protocol_version` `0.5`;
    matching `transaction_passport_ref`; and `chio_payment_receipt_ref` present in
    `envelope.receipt_refs`. No facilitator signature is required (signature_algorithm `none`).
  - BUILD the evidence adapter (FAC-4) that persists byte-exact artifacts and computes:
    resource_digest = sha256(resource record), payment_requirements_digest = sha256(402 accepts
    entry), payment_proof_digest = sha256(X-PAYMENT payload incl signature),
    settlement_digest = sha256(facilitator /settle response). Digests are over raw persisted
    bytes; any re-serialization silently breaks verification.
- Proof Room serve: `crates/products/chio-cli/src/cli/dispatch/proof/serve.rs`
  - REUSE `chio proof serve` (serves verified bundles through `chio-proof-room` with a static UI).
- Demo storefront + buyer agent: `examples/internet-of-agents-web3-network`
  - REUSE the existing x402-style path (`internet_web3/marketplace.py` fabricates `http_status:402`
    payment-required + satisfaction docs; `clients.py` uses schema `x402.payment-required.local.v1`,
    chain_id `eip155:84532`; `rails.py` rail `base-sepolia-usdc`). BUILD: swap the fabricated
    off-chain proof for a real 402 -> sign -> facilitator-settle -> receipt loop. See FAC-5.

Crate placement for new service code (per AGENTS.md economy group): a new
`crates/economy/chio-x402-facilitator` (axum 0.8 lib + bin), depending on `chio-settle`
(payments + evm) and `chio-egress-contract`, exposing a client feature for adapter-hybrid mode.

## 3. Facilitator decision: adapter-hybrid

Recommendation from the spike: adapter-hybrid. Keep verification-side fail-closed checks in Chio
(reuse `prepare_transfer_with_authorization` + an ecrecover check), delegate on-chain settlement
to a hosted facilitator, then persist request/response artifacts and hash them into the four
digests. Chio re-verifies everything it can locally before and after the external call, never
blindly trusting the facilitator. This avoids the two missing in-repo capabilities (raw EIP-1559
signing, non-loopback settlement egress), which move to phase-2 FAC-6.

- PRIMARY: CDP hosted facilitator `https://api.cdp.coinbase.com/platform/v2/x402`
  (Base Sepolia `eip155:84532`). Auth via `CDP_API_KEY_ID` / `CDP_API_KEY_SECRET`
  (JWT bearer). Free tier 1,000 tx/month then $0.001/tx. Preferred because Connor is already in
  the Coinbase/Base ecosystem; production-supported path.
- FALLBACK (zero-credential): `https://facilitator.x402.rs` (live-probed 2026-07-02;
  advertises `exact` on base-sepolia in v1 `base-sepolia` and v2 `eip155:84532`, no API key).
  Wire this so the demo never blocks on key provisioning.
- NEVER use `https://x402.org/facilitator`. It is DEAD (302-redirects to a Linux Foundation
  WordPress signup; the project moved to the x402 Foundation). Do not reference it anywhere.

Client hygiene: `GET /supported` preflight must fail closed if `exact` + base-sepolia is absent;
route both the RPC URL and the facilitator URL through `HttpEgressContract` allowlists; scheme
allowlist `exact` only; network allowlist the configured chain ids only.

## 4. Milestone plan (FAC-1..FAC-7 -> 1-2 week cut)

Week 1 (payment core):
- FAC-1 wire types: x402 v1 `PaymentRequirements` / `PaymentPayload` (exact/EVM) /
  `SettlementResponse` / `VerifyResponse` with serde `deny_unknown_fields`; network-name mapping
  (`base-sepolia` <-> `eip155:84532`); decimal-string u128 parsing. In `chio-x402-facilitator`.
- FAC-2 facilitator client: `/supported` `/verify` `/settle` with egress pinning; CDP JWT auth
  profile + keyless `facilitator.x402.rs` profile; preflight fail-closed.
- FAC-3 local pre-checks: bridge wire payloads to `prepare_transfer_with_authorization`
  (`ApprovalBinding` from payTo/maxAmountRequired/asset/extra.name); add ecrecover payer-signature
  check over `authorization_digest`. Verify path must NOT consume nonces; settle path MUST.

Week 2 (evidence + demo + CI):
- FAC-4 evidence adapter: persist byte-exact artifacts, compute the four sha256 digests, emit the
  Chio payment receipt, build the `external.x402.payment.v1` subject + manifest (`source_version`
  `0.5`); unit-test against `validate_subject` including refunded and receipt-ref-mismatch cases.
- FAC-5 vending machine demo: extend `examples/internet-of-agents-web3-network` with a real 402
  responder, an EIP-3009 signer funded from the Circle faucet, settlement through FAC-2, and
  proof-bundle emission through FAC-4; document CDP-key and keyless paths in the README.
- FAC-7 hardening/CI: axum fail-closed tests (invalid signature, replayed nonce,
  recipient/amount/asset mismatch, unsupported network/scheme, oversized bodies) + digest
  byte-exactness conformance end to end.

Deferred (NOT demo-blocking): FAC-6 self-hosted settle backend (transferWithAuthorization calldata
`0xe3ee160e`, raw EIP-1559 signing + `eth_sendRawTransaction` via new alloy-consensus /
alloy-signer-local deps, isolated capped gas wallet, durable SQLite `Eip3009NonceStore`, longer
confirmation poll). Land this in phase 2, then flip the demo `facilitator_url` to the in-repo
service. Until then the in-repo service can only settle against local anvil, not Base Sepolia.

## 5. Testnet setup

- Chain: Base Sepolia (`eip155:84532`), the `public-testnet-primary` role in
  `contracts/deployments/base-sepolia.template.json`.
- USDC: `0x036CbD53842c5426634e7929541eC2318f3dCF7e` (EIP-712 domain name `USDC` / `USD Coin`,
  version `2`). This contract is LIVE; act one needs no Chio contract deployment.
- Funding: Circle USDC faucet for Base Sepolia to fund the buyer agent wallet; a small ETH faucet
  balance is only needed if/when FAC-6 self-hosts gas (hosted facilitators pay their own gas).
- Wallet custody options for the demo agent (founder choice):
  1. Raw testnet private key held by the demo agent (simplest, fine for a scripted showcase).
  2. Circle managed balances per `CircleNanopaymentPolicy` (`payments.rs:69`) for a cleaner
     custody story. The facilitator never holds payer keys either way.

## 6. Dependencies and sequencing

1. Merge `chio/m2-build` FIRST. This branch (`chio/autonomous-commerce-brainstorm`) has EAS only
   as research prose and netting only as a disabled `mixed_currency_netting_supported: false`
   flag; `chio/m2-build` carries the newest x402/prepaid economy code
   (`crates/economy/chio-web3/src/x402_signing.rs` ~536 lines, `chio-credit/src/prepaid.rs`,
   `netting.rs`, EAS/Verax conformance). The audited direction is to create an integration branch
   off this branch and `git merge chio/m2-build` (5 predicted conflicts, all in
   proof-room/CLI/test/script territory; two semantic traps: the settlement-rpc egress contract vs
   the new x402 RPC paths, and a stale `spec/schemas/MANIFEST.sha256`). Do the demo on top of the
   merged tree.
2. Base Sepolia contract deployment: `base-sepolia.template.json` still has PLACEHOLDER oracle
   feeds (`<base_sepolia_eth_usd_feed>`, `<base_sepolia_usdc_usd_feed>`, sequencer feed) and no
   confirmed live deployment on this branch. Key distinction:
   - Act one (pay-per-call, prepaid `transferWithAuthorization`) needs ONLY live USDC + a
     facilitator. It does NOT need the oracle feeds filled or `ChioEscrow`/`ChioRootRegistry`
     deployed. Receipts are Chio-side artifacts.
   - Act two (escrow-backed mode) and on-chain receipt-root anchoring DO need `ChioEscrow` /
     `ChioRootRegistry` deployed and (for price resolution) the oracle feeds filled and
     heartbeat-verified. Sequence these after the demo's first cut.
3. Staging into later acts (product Concept 1 roadmap): act one x402 vending machine ->
   act two escrow-backed bounty (`releaseWithProof` on `ChioEscrow`) -> act three recursive swarm
   budget waterfall (W1.1 chain-binding, W1.2 sibling-sum), all on the same rails.
4. Pre-existing test failures do not intersect this path: the current baseline is 21 environmental
   failures, all in `chio-wasm-guards` (missing wasm32 target + missing py guard artifact), none in
   settle/escrow/proof-room. The old "72 pre-existing failures" figure is stale for this branch.

## Referenced files

- `crates/economy/chio-settle/src/payments.rs` (X402PaymentRequirements:22,
  PreparedTransferWithAuthorization:59, ApprovalBinding:192, prepare_transfer_with_authorization:473)
- `crates/platform/chio-agent-web-interop/src/artifacts/x402.rs` (4-digest envelope validator)
- `crates/products/chio-api-protect` (protect sidecar)
- `crates/products/chio-cli/src/cli/dispatch/proof/serve.rs` (`chio proof serve`)
- `examples/internet-of-agents-web3-network` (existing x402-style path to extend)
- `contracts/deployments/base-sepolia.template.json` (USDC live, oracle feeds placeholder)
