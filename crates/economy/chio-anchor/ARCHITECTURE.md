# chio-anchor architecture

## Overview

`chio-anchor` sits above `chio-core` and `chio-kernel`, turning frozen Chio
checkpoints into external-chain publication requests and turning chain
responses back into verified proofs. It holds no kernel signing key and
evaluates no kernel policy; its job is to mediate between kernel-produced,
already-validated inputs (`KernelCheckpoint`, `ReceiptInclusionProof`,
`EvidenceExportBundle`) and untrusted external systems (EVM RPC nodes,
OpenTimestamps calendars, the Rekor transparency log, Solana). Every
`verify_*`/`confirm_*` entry point re-derives and checks the external
response rather than trusting it: on-chain receipts are matched against a
specific `RootPublished` log, Rekor entries are checked against a pinned-key
signature, OTS proofs are checked against an expected digest and Bitcoin
height. `#![forbid(unsafe_code)]`; the entire crate body is
`#![cfg(feature = "web3")]`, so the crate has zero items without that
default feature.

The crate hosts two independent anchor mechanisms that share no artifact
types. `AnchorInclusionProof` / `AnchorProofBundle` anchor one checkpoint per
proof across an EVM primary lane plus optional Bitcoin OTS and Solana memo
secondary lanes (`bundle.rs`, `bitcoin.rs`, `solana.rs`, `evm/`). Separately,
`chio.anchor_batch.v1` (`AnchorBatch`, `batch.rs`) Merkle-batches checkpoint
ID strings and binds them to a public-witness receipt from `RekorClient` or
`OtsClient` under `WitnessPolicy` (`witness.rs`). The two are verified by
unrelated code paths (`bundle.rs` vs `witness.rs`).

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Facade: module declarations, the flat re-export surface, `AnchorError`, `AnchorServiceConfig`, kernel-checkpoint <-> web3-statement conversions, evidence-bundle projection. |
| `src/automation.rs` | Cron-triggered publication job construction; execution-record validation (state fingerprint, replay window, duplicate suppression, operator override). |
| `src/batch.rs` | `chio.anchor_batch.v1`: builds the checkpoint-ID Merkle tree, binds a witness descriptor, signs and verifies the batch. |
| `src/bundle.rs` | `AnchorProofBundle` fail-closed multi-lane verification; `verify_checkpoint_publication_records` (equivocation and trust-anchor/witness checks). |
| `src/bitcoin.rs` | OTS submission preparation over a checkpoint range, OTS proof parsing, Bitcoin super-root anchor attachment/verification for the proof-bundle family. |
| `src/solana.rs` | Solana memo publication preparation and verification against a checkpoint. |
| `src/discovery.rs` | `AnchorDiscoveryArtifact`: service endpoint metadata, publication policy, runtime freshness classification, discovery-gated bundle verification. |
| `src/evm/types.rs` | `EvmAnchorTarget` and the prepared-publication/receipt/guard/JSON-RPC-envelope types. |
| `src/evm/validation.rs` | `parse_validated_evm_anchor_target`, the single validation boundary for chain id, RPC URL, and addresses. |
| `src/evm/preparation.rs` | `prepare_root_publication`, `prepare_delegate_registration`: binding checks plus ABI call-data encoding. |
| `src/evm/rpc.rs` | `publish_root` (gas estimate + `eth_sendTransaction`) and the shared `rpc_call` JSON-RPC helper. |
| `src/evm/publication.rs` | `confirm_root_publication` (receipt plus `RootPublished` log verification against the checkpoint), `inspect_publication_guard`, `ensure_publication_ready` preflight. |
| `src/evm/verification.rs` | `verify_inclusion_onchain`, calling `verifyInclusionDetailedForKeyHash` on the registry. |
| `src/evm/records.rs`, `src/evm/hashing.rs` | `build_chain_anchor_record`; shared `operator_key_hash` (Ed25519-only) and hash/hex helpers. |
| `src/evm/egress.rs` | `HttpEgressContract` construction/validation for anchor RPC; the devnet helper authorizes loopback only. |
| `src/functions.rs` | Chainlink Functions fallback: bounded batch-verification request preparation and response assessment. |
| `src/ops.rs` | Runtime control plane: `AnchorEmergencyControls::allows`, `classify_anchor_lane`, `AnchorIndexerCursor` lag classification, incident alerts. |
| `src/metrics.rs` (`pub mod`) | `chio_anchor_round_latency_seconds` histogram: atomic counters/buckets, Prometheus text export. |
| `src/witness.rs` | `AnchorWitnessClient` trait, `WitnessState`/`WitnessPolicy` state machine, `evaluate_witness_policy` and its verifier-backed async counterpart. |
| `src/witness/rekor.rs` | Production Rekor client: DSSE publish, pinned-key SET verification, RFC 6962 inclusion-proof recomputation. |
| `src/witness/ots.rs` | Advisory OpenTimestamps witness client; `verify_inclusion` always fails closed for `require_public_witness`. |
| `src/fuzz.rs` (`fuzz` feature) | libFuzzer entry point over `AnchorProofBundle` / `CheckpointTransparencySummary` parse-and-verify. |
| `src/kani_public_harnesses.rs` (`#[cfg(kani)]`) | Model-checked harnesses over `ops.rs` predicates and an algebraic model of `evaluate_witness_policy`. |

## EVM publication lifecycle

1. `EvmAnchorTarget::validate` (`parse_validated_evm_anchor_target`) rejects malformed CAIP-2 `eip155:` chain ids, non-`http(s)` or hostless RPC URLs, and zero or malformed contract/operator/publisher addresses. Every EVM entry point routes through it first.
2. `prepare_root_publication` checks the identity binding (anchor purpose, chain scope, settlement address equal to the operator address) and ABI-encodes `publishRoot`.
3. `publish_root` estimates gas, then dispatches `eth_sendTransaction` through `HttpEgressContract`; the devnet helper (`evm_anchor_devnet_rpc_egress_contract`) authorizes loopback RPC only.
4. `ensure_publication_ready` (via `inspect_publication_guard`) preflights publisher authorization and checkpoint sequencing: `checkpoint_seq` must equal latest+1, and `batch_start_seq` must equal the latest published root's `batch_end_seq`+1 (1 if no root has published yet).
5. `confirm_root_publication` re-fetches the transaction receipt, requires a matching `RootPublished` log at the confirmed block hash and number, and cross-checks the on-chain `getRoot` entry against the checkpoint before returning `EvmPublicationReceipt`.
6. `build_chain_anchor_record` turns the confirmed receipt into a `Web3ChainAnchorRecord`; `verify_inclusion_onchain` independently re-derives inclusion for one receipt against the published root via `verifyInclusionDetailedForKeyHash`.

## Invariants and failure modes

- `#![forbid(unsafe_code)]`; the crate body is entirely gated by `#![cfg(feature = "web3")]`.
- All EVM RPC dispatch is mediated by `HttpEgressContract` (`chio-egress-contract`); target validation itself never resolves DNS, leaving address-class enforcement to the pinned resolver at connect time.
- `AnchorProofBundle` fails closed on schema mismatch, an empty `secondary_lanes` list, an EVM-primary-labeled secondary lane, and any secondary lane whose declaration disagrees with its payload (Bitcoin or Solana data present without the lane declared, or the lane declared without the data).
- `RekorClient` treats the pinned-key SET as the load-bearing authentication; an inlined Merkle inclusion proof is cross-checked against it (RFC 6962) when present but is a no-op when absent. `OtsClient::verify_inclusion` always returns an error: OTS is advisory-only until the receipt schema carries trusted Bitcoin header evidence.
- `AnchorBatchWitnessKind::SolanaMemo` has no `AnchorWitnessClient` implementation in this crate.
- The sync `evaluate_witness_policy` never contacts a witness lane. `verify_anchor_batch_with_witness_policy` fails closed with `AnchorError::SyncRouteRequiresAdvisoryPolicy` when called with `require_public_witness=true` rather than silently downgrading to structural checks. Stale-batch admission under the async path is keyed by the verifier's own `batch_body_hash -> verified_at` cache, never by producer-signed `last_verified`.
- `BatchHashInput`, the hashed view backing `batch_body_hash`, excludes `witness_state`, `witness_id`, and `observed_at`, so attaching a witness receipt to a batch does not change the hash that receipt commits to.
- `bitcoin.rs` (checkpoint super-root anchor) and `witness/ots.rs` (anchor-batch witness) each parse OpenTimestamps proofs independently; they do not share an implementation.

## Dependencies

- `chio-core` (unaliased): `web3::anchors` / `web3::identity` wire types, canonical JSON, hashing, Merkle proofs, signing primitives.
- `chio-kernel`: `checkpoint::{KernelCheckpoint, ReceiptInclusionProof, CheckpointTransparencySummary, ...}` and `evidence_export::EvidenceExportBundle`.
- `chio-web3-bindings` (path dependency, sibling crate): generated `IChioRootRegistry` Solidity bindings for ABI encode/decode.
- `chio-egress-contract` (`reqwest-egress` feature): `HttpEgressContract`, the mediated HTTP client used for all EVM RPC.
- `chio-metrics-spec`: the `chio_anchor_round_latency_seconds` registry constant and bucket boundaries. It is the crate's only non-optional internal dependency, pulled in even though the rest of the crate body is gated behind `web3`.
- `chio-web3` is declared under the `web3` feature but has no direct `chio_web3::` reference anywhere in `src/`.
- External: `alloy-primitives`/`alloy-sol-types` (EVM ABI and address types), `opentimestamps` (Bitcoin OTS parsing, used independently by both OTS surfaces), `p256` (Rekor SET ECDSA verification against a pinned key), `reqwest` (RPC and witness-lane HTTP), `async-trait` (`AnchorWitnessClient`).

## Extension points

`AnchorWitnessClient` is the trait a caller implements to add a witness lane
beyond the built-in `RekorClient` (production) and `OtsClient`
(advisory-only). `evaluate_witness_policy_with_verifier` and
`verify_anchor_batch_with_witness_policy_async` accept any
`&dyn AnchorWitnessClient`.
