# Chio x402 Facilitator: Buildable Design

Status: buildable design (brainstorm). Blocker: this is the #1 gap for the
pay-per-call vending-machine demo (`docs/brainstorm/CHIO-DEMO-X402-VENDING-MACHINE-PLAN.md`).
Venue: Base Sepolia, USDC only (US-person jurisdiction constraint).
Grounded in the facilitator spike (FAC-1..FAC-7) and the real repo surfaces below.

A facilitator accepts a signed x402 payment authorization, gets it settled on-chain,
and returns a settlement result. Chio already has the fail-closed EIP-3009 preparation
core and a digest-bound proof validator; it has no facilitator service and no public-chain
broadcast path. This design fills that gap with the adapter-hybrid: run every check Chio
can locally, delegate the on-chain settle to a hosted facilitator, then persist byte-exact
artifacts and compute the four sha256 digests the envelope validator wants.

## 1. Crate placement and module layout

New crate `crates/economy/chio-x402-facilitator` (library plus an optional axum 0.8 bin).
Per `AGENTS.md:25` the `economy` group owns "settlement rails ... and web3 bindings", which
is exactly this. Depends on `chio-settle` (payments + evm), `chio-egress-contract`
(RPC/facilitator egress pinning, at `crates/protocol/chio-egress-contract`), `chio-core`,
`reqwest` (rustls), `serde`/`serde_json`, `sha2`, `alloy-primitives`, and `secp256k1`
(recovery) which `chio-settle` already pulls in. axum 0.8 is already used by chio-tower,
chio-control-plane, chio-proof-room, chio-cli.

```
crates/economy/chio-x402-facilitator/src/
  lib.rs          re-exports; feature gates (client, service, self-hosted-settle)
  wire.rs         FAC-1  x402 v1 wire types, serde deny_unknown_fields
  mapping.rs      FAC-1/3 wire<->Chio mapping, network normalization, decimal parse
  verify.rs       FAC-3  local pre-checks: bind -> prepare_transfer_with_authorization
                         (or non-consuming digest) + ecrecover(authorization_digest,sig)==from
  client.rs       FAC-2  hosted-facilitator HTTP client (CDP + keyless), /supported preflight
  evidence.rs     FAC-4  byte-exact persistence, 4 sha256 digests, receipt, subject + manifest
  config.rs              network/scheme allowlists, facilitator profile, egress contract
  service.rs            (phase 2, FAC-7) axum GET /supported, POST /verify, POST /settle
  settle_backend.rs    (phase 2, FAC-6) raw EIP-1559 sign + eth_sendRawTransaction
  nonce_sqlite.rs      (durable Eip3009NonceStore; may instead land in chio-settle)
```

## 2. Wire <-> Chio field mapping (the load-bearing table)

x402 v1 (`coinbase/x402` specs) is NOT the Chio-internal projection. `X402PaymentRequirements`
(`crates/economy/chio-settle/src/payments.rs:22`) uses CAIP-2 `chain_id`, token symbols, and
`amount_minor_units: u64`; the wire uses `network` strings, contract-address `asset`, and
decimal-string amounts. `mapping.rs` is the only place the two shapes meet.

### 2a. 402 `accepts[]` PaymentRequirements -> Chio

| x402 v1 wire field | wire type | Chio target |
| --- | --- | --- |
| `scheme` = "exact" | string | validate only (scheme allowlist; reject non-"exact") |
| `network` = "base-sepolia" | string | normalize -> CAIP-2 "eip155:84532" -> `Eip3009Domain.chain_id = 84532` (u64) and `X402PaymentRequirements.chain_id = "eip155:84532"` |
| `maxAmountRequired` = "1000" | decimal string | parse u128 -> `ApprovalBinding.amount_minor_units` and `TransferWithAuthorizationInput.value_minor_units`; checked-cast to u64 for `X402PaymentRequirements.amount_minor_units` |
| `asset` = "0x036C..." | contract address | `Eip3009Domain.verifying_contract` AND `ApprovalBinding.token_contract` (both must equal, per payments.rs:586) |
| `payTo` = "0x..." | address | `ApprovalBinding.payee_address` AND `TransferWithAuthorizationInput.to_address` AND `X402PaymentRequirements.pay_to` |
| `resource` = "https://..." | string | `X402PaymentRequirements.resource`; also drives `resource_digest` source bytes |
| `maxTimeoutSeconds` = 60 | number | fallback `ApprovalBinding.approval_expires_at = now + maxTimeoutSeconds` when no governing approval supplies it |
| `extra.name` = "USDC" | string | `Eip3009Domain.name` AND `ApprovalBinding.token_symbol` (also `currency`/`accepted_tokens`) |
| `extra.version` = "2" | string | `Eip3009Domain.version` |

Network normalization is bidirectional and canonicalized once: internally CAIP-2
("eip155:84532"), at the v1 wire edge "base-sepolia" (v2 already uses "eip155:84532").
`base-sepolia <-> eip155:84532`, `base <-> eip155:8453`. Fail closed on any network not in
the allowlist. Base Sepolia USDC is `0x036CbD53842c5426634e7929541eC2318f3dCF7e`
(EIP-712 domain name "USDC", version "2").

### 2b. X-PAYMENT PaymentPayload.payload.authorization -> Chio + signature check

| x402 v1 wire field | wire type | Chio target |
| --- | --- | --- |
| `from` | address | `TransferWithAuthorizationInput.from_address`; ecrecover target |
| `to` | address | `TransferWithAuthorizationInput.to_address` (must == `payTo`) |
| `value` | decimal string | `TransferWithAuthorizationInput.value_minor_units` u128 (must == `maxAmountRequired`) |
| `validAfter` | decimal string | `TransferWithAuthorizationInput.valid_after` u64 |
| `validBefore` | decimal string | `TransferWithAuthorizationInput.valid_before` u64 |
| `nonce` | bytes32 hex | `TransferWithAuthorizationInput.nonce` |
| `signature` | 65-byte hex | verified: `ecrecover(authorization_digest, signature) == from` |

`authorization_digest` is the exact `0x1901` EIP-712 digest `prepare_transfer_with_authorization`
already emits (`payments.rs:670`); the payer signs it, so ecrecover closes the payer-authenticity gap.

### 2c. Facilitator SettlementResponse -> Chio subject

| x402 v1 wire field | wire type | Chio target |
| --- | --- | --- |
| `success` | bool | true -> subject `status` "settled"; false -> deny, emit `status` "refunded" (validator rejects, x402.rs:51) |
| `transaction` | tx hash | persisted inside the settlement artifact bytes (not a validated subject field); explorer link |
| `network` | string | normalize -> subject `network` |
| `payer` | address | cross-check == `authorization.from` |
| `errorReason` | string? | denial-receipt reason |

VerifyResponse `{isValid, invalidReason?, payer}` is used only as an advisory pre-broadcast probe;
Chio never trusts it in place of its own local checks.

## 3. Adapter-hybrid flow

1. Resource server (sidecar) returns `402` with `accepts[]` built by mapping
   `X402PaymentRequirements` (`build_x402_payment_requirements`, payments.rs:116) to the wire
   PaymentRequirements (2a).
2. Buyer agent signs EIP-3009 over `authorization_digest`, attaches base64 X-PAYMENT, retries.
3. Chio local pre-checks (verify.rs), all fail-closed BEFORE any broadcast:
   a. Parse/validate wire PaymentPayload (`deny_unknown_fields`), decimal-string -> u128/u64.
   b. `scheme == "exact"`, `network` in allowlist.
   c. Build `Eip3009Domain` + `TransferWithAuthorizationInput` + `ApprovalBinding` from
      paymentRequirements (payee=`payTo`, amount=`maxAmountRequired`, token_contract=`asset`,
      token_symbol=`extra.name`, chain from normalized network).
   d. `prepare_transfer_with_authorization(...)` (payments.rs:473) enforces single-use nonce,
      open time window, `validBefore <= approval_expires_at`, and chain/payee/amount/token-contract
      binding, and returns `authorization_digest`. NONCE IS CONSUMED HERE, so this call is made
      only on the settle path; the verify path recomputes the digest without recording the nonce
      (see open questions).
   e. `ecrecover(authorization_digest, payload.signature) == authorization.from`. Fail closed.
4. Delegate on-chain settle to a hosted facilitator via `HttpEgressContract`-pinned reqwest.
   Primary: CDP (`https://api.cdp.coinbase.com/platform/v2/x402`, eip155:84532, JWT from
   `CDP_API_KEY_ID`/`CDP_API_KEY_SECRET`). Zero-credential fallback: keyless
   `https://facilitator.x402.rs` (confirmed live, exact on base-sepolia). Never reference the
   dead `x402.org/facilitator`. `/supported` preflight fails closed if exact+base-sepolia is absent.
5. Persist byte-exact artifacts and compute the four sha256 digests the validator expects
   (`crates/platform/chio-agent-web-interop/src/artifacts/x402.rs:19-31`, all 64 lowercase hex):
   - `resource_digest` = sha256(resource record bytes)
   - `payment_requirements_digest` = sha256(the 402 accepts entry bytes)
   - `payment_proof_digest` = sha256(X-PAYMENT PaymentPayload bytes, incl. signature)
   - `settlement_digest` = sha256(facilitator SettlementResponse bytes)
   Then mint the Chio receipt, set `chio_payment_receipt_ref` (must be in `envelope.receipt_refs`),
   `transaction_passport_ref`, `order_id`, `network`, `asset`, `amount_units` (u64 > 0),
   `status` in {authorized, settled}, and emit the `external.x402.payment.v1` subject plus a
   projection manifest with `source_version` "0.5", `digest_algorithm` sha256,
   `signature_algorithm` "none", `requires_external_signature` false
   (`protocols.rs:247-251`; the manifest asserts x402 is NOT a Chio authority claim).
6. Envelope validator consumes it; Proof Room serves the pay -> verify -> settle -> serve chain.

Digests are over RAW persisted bytes; any re-serialization silently breaks verification, so the
adapter stores exact copies and hashes those, never a re-encoded struct.

## 4. FAC-1..FAC-7 build order

1. FAC-1 (wire.rs + mapping.rs): v1 wire types with `deny_unknown_fields`, network
   normalization, decimal-string u128/u64 parse. Section 2 is the acceptance contract.
2. FAC-3 (verify.rs): bridge wire -> `ApprovalBinding` + call `prepare_transfer_with_authorization`;
   add the ecrecover payer check. Verify path non-consuming, settle path consuming.
3. FAC-2 (client.rs): hosted-facilitator client for `/supported`, `/verify`, `/settle`, egress
   pinning, CDP-JWT and keyless profiles. Enables the adapter-hybrid settle.
4. FAC-4 (evidence.rs): byte-exact persistence, four sha256 digests, Chio receipt, subject +
   manifest. Unit-test against `validate_subject` incl. the refunded and receipt-ref-mismatch cases.
5. FAC-5: vending-machine demo wiring (`examples/internet-of-agents-web3-network`): real 402
   `accepts[]` for USDC on Base Sepolia, Circle-faucet-funded signer, settle via FAC-2, bundle via FAC-4.
6. FAC-6 (settle_backend.rs, phase 2, not demo-blocking): in-repo settle:
   `transferWithAuthorization` calldata (selector `0xe3ee160e`), raw EIP-1559 signing
   (alloy-consensus + alloy-signer-local, new deps) + `eth_sendRawTransaction`, non-devnet
   `HttpEgressContract`, durable SQLite `Eip3009NonceStore`, longer confirm poll, isolated capped gas wallet.
7. FAC-7 (service.rs + tests): axum service exposing `/supported`, `/verify`, `/settle`; fail-closed
   tests (bad signature, replayed nonce, recipient/amount/asset mismatch, unsupported network/scheme,
   oversized bodies); anvil-backed settle integration test via the existing `eth_sendTransaction`
   path; conformance fixtures asserting digest byte-exactness end to end.

## 5. BUILD vs already-exists

Already exists (REUSE, do not rebuild):
- Verify-side money-safety core `prepare_transfer_with_authorization` and every invariant:
  single-use domain-scoped nonce, open time window, approval-expiry bound, chain/payee/amount/
  token-contract binding (`payments.rs:473`), all fail-closed and nonce-preserving on rejection.
- `Eip3009Domain`, `TransferWithAuthorizationInput`, `ApprovalBinding`,
  `PreparedTransferWithAuthorization`, the `0x1901` `authorization_digest`, `X402PaymentRequirements`,
  `build_x402_payment_requirements`, `Eip3009NonceStore` + `InMemoryEip3009NonceStore` (payments.rs).
- secp256k1 recovery already a `chio-settle` dep and exercised (`evm/mod.rs:649 recover_ecdsa`).
- Envelope validator + protocol registration: `external.x402.payment.v1`, source "0.5",
  four-digest + passport + receipt binding (`artifacts/x402.rs`, `protocols.rs:247`).
- `HttpEgressContract` (chio-egress-contract, `reqwest-egress`), reqwest/rustls, tokio, sha2, alloy,
  axum 0.8 - all present in the workspace.

Build (NEW):
- The `chio-x402-facilitator` crate and all modules in Section 1.
- x402 v1 wire types + the mapper (Section 2), incl. base-sepolia <-> eip155:84532 and decimal parse.
- ecrecover-over-`authorization_digest` payer-auth helper (primitive exists; no digest-vs-`from` wrapper).
- A verify-only path that runs binding/time/ecrecover WITHOUT consuming the nonce.
- Hosted-facilitator client with CDP + keyless profiles and `/supported` preflight.
- Evidence adapter (byte-exact bytes -> four digests -> receipt -> subject + manifest).
- Durable SQLite `Eip3009NonceStore` before any restartable deployment.
- Phase 2 only: self-hosted settle backend (calldata encode, raw signing, broadcast, capped gas wallet).
