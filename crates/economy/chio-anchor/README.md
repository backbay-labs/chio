# chio-anchor

`chio-anchor` publishes Chio checkpoints to external chains and verifies the
proofs that come back. It covers direct EVM root-registry publication and
confirmation, checkpoint-to-Bitcoin super-root aggregation via
OpenTimestamps, canonical Solana memo publication, and fail-closed
multi-lane proof-bundle verification. It also owns a second, independent
mechanism: `chio.anchor_batch.v1`, which Merkle-batches checkpoint IDs and
binds them to a public witness (Rekor or OpenTimestamps).

Nearly all production code lives behind the default `web3` feature; without
it the crate compiles with zero items (`lib.rs` is
`#![cfg(feature = "web3")]`).

## Responsibilities

- Prepare, dispatch, and confirm EVM root-registry publication calls against
  `IChioRootRegistry`, including delegate-publisher authorization and
  publication-sequencing preflight checks.
- Aggregate checkpoints into a Bitcoin super-root and attach/verify an
  OpenTimestamps proof against an `AnchorInclusionProof`.
- Prepare and verify canonical Solana memo publication records.
- Verify `AnchorProofBundle` (the primary EVM proof plus any declared
  Bitcoin OTS / Solana memo secondary lanes) and checkpoint publication
  transparency records.
- Build DID-style anchor-service discovery artifacts, including runtime
  freshness classification and discovery-gated bundle verification.
- Build, sign, and verify `chio.anchor_batch.v1` Merkle batches of
  checkpoint IDs against a `WitnessPolicy`, backed by a production Rekor
  client and an advisory-only OpenTimestamps client.
- Prepare bounded Chainlink Functions fallback-verification requests over a
  receipt batch.
- Track runtime control state: emergency modes, lane health, indexer lag,
  and incident alerts.
- Schedule and validate cron-triggered publication jobs, including delegate
  forwarding and replay-window enforcement.
- Export `chio_anchor_round_latency_seconds` as Prometheus text.

## Public API

Everything below is re-exported flat from the crate root over private lane
modules. `metrics`, and `fuzz` under its feature flag, are the only real
public module paths.

| Area | Key items |
|------|-----------|
| Root (`lib.rs`) | `AnchorError`, `AnchorServiceConfig`, `checkpoint_statement_from_kernel`, `kernel_checkpoint_from_statement`, `build_anchor_inclusion_proof`, `build_anchor_inclusion_proof_from_evidence_bundle` |
| EVM | `EvmAnchorTarget`, `prepare_root_publication`, `prepare_delegate_registration`, `publish_root`, `confirm_root_publication`, `ensure_publication_ready`, `inspect_publication_guard`, `verify_inclusion_onchain`, `build_chain_anchor_record` |
| Bitcoin (checkpoint anchor) | `prepare_ots_submission`, `attach_bitcoin_anchor`, `verify_bitcoin_anchor_for_proof`, `inspect_ots_proof` |
| Solana | `prepare_solana_memo_publication`, `verify_solana_anchor`, `SolanaMemoAnchorRecord` |
| Proof bundle | `AnchorProofBundle`, `verify_proof_bundle`, `verify_checkpoint_publication_records`, `AnchorLaneKind` |
| Discovery | `build_anchor_discovery_artifact`, `build_anchor_discovery_artifact_with_runtime`, `verify_proof_bundle_with_discovery`, `AnchorDiscoveryArtifact` |
| Anchor batch + witness | `AnchorBatch`, `build_anchor_batch`, `verify_anchor_batch`, `verify_anchor_batch_with_witness_policy`, `verify_anchor_batch_with_witness_policy_async`, `WitnessPolicy`, `AnchorWitnessClient`, `RekorClient`, `OtsClient` |
| Functions fallback | `prepare_functions_batch_verification`, `assess_functions_verification`, `ChainlinkFunctionsTarget` |
| Runtime ops | `AnchorEmergencyControls`, `ensure_anchor_operation_allowed`, `classify_anchor_lane`, `AnchorRuntimeReport` |
| Automation | `build_anchor_publication_job`, `assess_anchor_automation_execution`, `AnchorAutomationJob` |
| Metrics (`chio_anchor::metrics`) | `observe_anchor_round_latency_nanos`, `render_anchor_metrics_prometheus`, `anchor_round_count` |

## Feature flags

| Flag | Effect |
|------|--------|
| `web3` (default) | Gates the entire crate body. Without it `chio-anchor` compiles with zero items. |
| `fuzz` | Exposes `chio_anchor::fuzz`, the libFuzzer entry point over `verify_proof_bundle` and `verify_checkpoint_publication_records`. Implies `web3`. Enabled only by the standalone `fuzz` workspace. |
| `kani` | Opt-in toggle for the `#[cfg(kani)]`-gated model-checked harness module. Implies `web3` so a Kani build has a non-empty crate to check. No production code path depends on it. |

## Testing

```
cargo test -p chio-anchor
```

Integration tests under `tests/` (`integration_smoke.rs`,
`mutation_gap_closure.rs`) and the Kani harnesses require the default `web3`
feature. The `fuzz` feature is driven from the standalone `fuzz` workspace,
not from this crate directly.

## See also

- `chio-core` - supplies the wire types this crate anchors (`AnchorInclusionProof`, checkpoint statements, web3 identity bindings).
- `chio-kernel` - supplies `KernelCheckpoint`, receipt inclusion proofs, and evidence-export bundles that feed `build_anchor_inclusion_proof*`.
- `chio-web3-bindings` - generated `IChioRootRegistry` Solidity bindings used to build and decode EVM calls.
- `chio-egress-contract` - mediates all EVM RPC dispatch through `HttpEgressContract`.
