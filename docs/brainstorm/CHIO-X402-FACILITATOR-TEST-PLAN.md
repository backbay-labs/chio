# Chio x402 Facilitator: Fail-Closed Invariants and Conformance Test Plan

Companion to `CHIO-X402-FACILITATOR-DESIGN.md` (written in parallel). This file
specifies the security invariants the facilitator MUST hold and the negative
conformance suite that proves them. It reuses the money-safety core already
shipped in `chio-settle` and `chio-egress-contract` rather than re-deriving it.

## 1. Grounding (what we build on, read-only)

- `crates/economy/chio-settle/src/payments.rs::prepare_transfer_with_authorization`
  (line 473) is the settlement seam. It already enforces single-use nonce,
  time-window, approval-expiry, and `ApprovalBinding` chain/payee/amount/token
  equality, and fails closed on every mismatch.
- `Eip3009NonceStore` (payments.rs:317) is the single-use replay store. Keys are
  the parsed-canonical `from` + a nonce key that folds `(chain_id,
  verifying_contract)` into the value (payments.rs:617-624), so replay is
  domain-scoped: the same nonce on a different token contract is legitimately
  fresh, the same nonce on the same contract is a replay.
- The nonce is recorded ONLY after every cheap check passes (payments.rs:594),
  so a rejected authorization never burns its nonce.
- Outbound HTTP is governed by `HttpEgressContract`: pinned-DNS resolver enforced
  at connect time (`reqwest_helper.rs::ContractDnsResolver`), `no_proxy`,
  redirects disabled + manually re-validated per hop, and a streaming byte cap
  checked on every chunk (`collect_capped_response`, reqwest_helper.rs:301). The
  settlement RPC path already validates its egress contract at load
  (`config.rs::validate_rpc_egress_contract`, line 271). Facilitator and RPC
  egress MUST follow this same pattern.

## 2. Fail-closed invariants (normative)

- **FC-1 Verify denies on error.** `/verify` maps any failed check to an explicit
  deny; the absence of a positive `valid` result is a denial. Never "valid by
  default".
- **FC-2 Settle is all-or-nothing.** `/settle` returns either a completed
  settlement receipt or an error. There is no 2xx partial-success shape; a
  broadcast that is not confirmed-submitted is a failure.
- **FC-3 Replay store consumed on settle, not verify.** `/verify` performs a
  read-only replay probe and MUST NOT call `record_if_fresh`. Only `/settle`
  records the domain-scoped nonce. This keeps verify idempotent and stops a
  verify from burning (DoS-ing) a payer's nonce.
- **FC-4 Amount/asset/recipient binding.** chain_id, payee, amount, and token
  contract are asserted via `ApprovalBinding`; `token_contract` is REQUIRED for
  the EIP-3009 lane (a symbol alone cannot pin the on-chain token).
- **FC-5 Payer authenticity via ecrecover.** The facilitator recovers the signer
  from `authorization_digest` (payments.rs:670) plus the submitted signature and
  asserts it equals `authorization.from_address`. `payments.rs` builds the digest
  but does NOT recover; ecrecover is the facilitator's responsibility.
- **FC-6 Time-window and approval-expiry.** Accept only when
  `valid_before > now > valid_after` and `valid_before <= approval_expires_at`.
- **FC-7 Network + scheme allowlist.** Only allowlisted `(chain_id, scheme,
  asset)` tuples and known `settlement_mode` enum values are accepted; an unknown
  network, scheme, or asset denies.
- **FC-8 Egress via HttpEgressContract.** Every outbound RPC and facilitator call
  goes through `enforce_url_with_dns` + `send_with_contract`. No raw reqwest, no
  proxy, no auto-redirect, no unbounded body read.
- **FC-9 No payer keys.** The facilitator custodies no payer private key (the
  payer signs EIP-3009 off-chain). A self-hosting broadcaster holds only a capped
  gas wallet: bounded balance, pays gas only, cannot move payer funds.
- **FC-10 Strict decode + body cap.** All wire structs carry
  `#[serde(deny_unknown_fields)]` (payments.rs:21,38,47,58,191); the HTTP body is
  size-capped before parse.
- **FC-11 Idempotency = replay rejection.** A repeated `/settle` for an
  already-settled authorization returns `NonceOutcome::Replayed` and denies; it
  never issues a second broadcast.
- **FC-12 Nonce-store capacity fails closed.** At `DEFAULT_MAX_EIP3009_NONCE_
  ENTRIES` the store errors rather than silently returning `Fresh`
  (payments.rs:426); `gc_expired` is the only prune path.

## 3. Conformance test matrix (one row per invariant)

| ID | Attack / negative case | Expected fail-closed outcome | Tier |
|----|------------------------|------------------------------|------|
| FC-1 | `/verify` with an invalid signature/binding | deny response, no "valid" | anvil |
| FC-2 | Broadcast RPC rejects the tx mid-settle | `/settle` errors, no partial receipt | anvil-fork |
| FC-3 | `/verify` then inspect nonce store | store unchanged; only `/settle` records | anvil |
| FC-3b | `/verify` twice on same nonce | both succeed (probe is read-only) | anvil |
| FC-4 | Redirect payee / inflate amount / swap token contract, same chain | `InvalidBinding` deny; nonce not consumed | anvil |
| FC-5 | Valid binding, signature from a different key | ecrecover mismatch deny | anvil |
| FC-6 | now >= validBefore; now <= validAfter; validBefore > approval expiry | deny; nonce not consumed | anvil |
| FC-7 | Unknown chain_id / unsupported scheme / unlisted asset | deny at requirements check | anvil |
| FC-8 | RPC/facilitator URL to loopback, private IP, or off-allowlist host | `HttpEgressError` deny at pinned-DNS resolve | anvil |
| FC-8b | Oversized / unbounded streaming RPC response | `ResponseTooLarge`, aborted mid-stream | anvil |
| FC-9 | Attempt to make facilitator sign as payer | no signing key present; deny | anvil |
| FC-9b | Gas wallet asked to move more than gas budget | denied by cap | anvil |
| FC-10 | Body with unknown field; oversized body | serde reject; 413/size deny before parse | anvil |
| FC-11 | Replay a completed `/settle` | replay rejection, single on-chain broadcast total | anvil-fork |
| FC-12 | Flood distinct nonces past capacity | capacity error, not `Fresh` | anvil |

## 4. Network-test discipline (mandatory rule)

A sibling egress test previously hung on an unbounded streaming server. Do NOT
repeat that. Every test in this suite that opens a socket MUST:

1. Wrap the network future in `tokio::time::timeout(bound, fut).await` with a
   small explicit bound (a few seconds). A hang MUST surface as a test failure,
   never a wedged CI job.
2. Use a test server that terminates: either it returns a single bounded response
   and shuts down, or (for the byte-cap case) it is detached and tolerant of the
   client closing the connection once the cap fires, exactly as
   `spawn_streaming_chunked_server` does (egress `tests.rs:724`). Never `join` a
   detached streaming server on the current-thread reactor; that deadlocks.
3. Bind the server to `127.0.0.1:0` and pass the concrete authority into a
   test-only `HttpEgressContract` (`permissive_for_tests`), so no test depends on
   external DNS or a live host.

## 5. Local anvil vs Base Sepolia

- **Local anvil (default CI, hermetic).** FC-1, FC-3, FC-3b, FC-4, FC-5, FC-6,
  FC-7, FC-8, FC-8b, FC-9, FC-9b, FC-10, FC-12. These exercise digest, binding,
  replay-store, ecrecover, egress, and decode logic with no real token contract
  and no external network.
- **Forked anvil (`anvil --fork-url <Base>`), still hermetic-ish.** FC-2 and
  FC-11 plus real-USDC acceptance: the actual token contract validates or rejects
  `transferWithAuthorization`, and on-chain nonce consumption is observable. This
  gives real EIP-3009 semantics without a testnet faucet.
- **Base Sepolia (gated, off by default).** Live end-to-end verify -> settle
  against a real RPC and a deployed facilitator relay, real gas estimation,
  real confirmation. `#[ignore]` by default, run behind a feature flag / env
  gate, and every call timeout-bounded per section 4. Never on the money-safety
  critical path of CI.
</content>
</invoke>
