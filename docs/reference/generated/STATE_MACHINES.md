<!-- DO NOT EDIT - regenerate via 'cargo xtask codegen rust'. -->
<!-- Source: spec/statemachines/*.toml -->

# State Machine Reference

These tables are derived reference material. Their cited protocol documents remain authoritative. Each scope statement limits what its transition relation describes.

## Anchor witness metadata

**Machine:** `anchor_witness_state`

**Scope:** Producer-carried AnchorBatch WitnessState metadata changes only. This relation does not encode verifier routing, witness admission policy, or a transport protocol.

**Sources:** `spec/PROTOCOL.md#anchor-batch-public-witness-lane-w23`

### States

| State | Initial | Terminal |
|---|---:|---:|
| `Pending` | yes | no |
| `Witnessed` | no | no |
| `Stale` | no | no |

### Transitions

| From | Message | To | Runtime guards |
|---|---|---|---|
| `Pending` | `record_verified_receipt` | `Witnessed` | `receipt_matches_batch` |
| `Witnessed` | `record_verified_receipt` | `Witnessed` | `receipt_matches_batch` |
| `Witnessed` | `record_verification_failure` | `Stale` | `prior_verification_exists` |
| `Stale` | `record_verified_receipt` | `Witnessed` | `receipt_matches_batch` |
| `Stale` | `record_verification_failure` | `Stale` | `prior_verification_exists` |

The generated conformance relation records 1 non-edges across 3 states and 2 messages.

## Bilateral DSSE producer

**Machine:** `bilateral_dsse_producer`

**Scope:** The strict bilateral DSSE producer from canonical statement construction through local host signing, origin co-signing, and final envelope verification.

**Sources:** `spec/CHIO_BILATERAL_COSIGN_INVOCATION.md#7-verification-algorithm`

### States

| State | Initial | Terminal |
|---|---:|---:|
| `Drafted` | yes | no |
| `HostSigned` | no | no |
| `Cosigned` | no | no |
| `EnvelopeVerified` | no | yes |

### Transitions

| From | Message | To | Runtime guards |
|---|---|---|---|
| `Drafted` | `sign_host` | `HostSigned` | `host_signature_created` |
| `HostSigned` | `request_cosignature` | `Cosigned` | `cosigning_schema_matches`, `origin_signature_valid` |
| `Cosigned` | `verify_envelope` | `EnvelopeVerified` | `signer_keys_independent`, `strict_envelope_valid` |

The generated conformance relation records 9 non-edges across 4 states and 3 messages.
