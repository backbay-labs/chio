# chio-revocation-oracle

Chio's revocation oracle: an append-only Merkle accumulator of revoked
`(subject, epoch_nonce)` keys, published as a signed, timestamped `EpochRoot`
on every epoch tick. Federation and custody components consult it to answer
whether a subject is revoked as of a given epoch, within a caller-configured
freshness window.

The crate is a pure library: no async runtime, no network I/O, no dependency
on `chio-kernel-core`. Transport (federation gossip, catch-up) and mint-time
enforcement (hardware custody) are built by callers on top of the traits and
types here.

## Responsibilities

- Define the `RevocationOracle` trait and ship its only implementation,
  `InMemoryRevocationOracle`: insert a key, answer `contains`, and produce
  inclusion / non-inclusion proofs against the current `EpochRoot`.
- Sign and verify epoch roots (`EpochRootSigner` / `EpochRootVerifier`) with
  Ed25519 over domain-separated, RFC 8785 canonical JSON, so a verify-only
  deployment holds only a pinned public key and can never forge a root.
- Drive the epoch broadcast tick (`tick_and_broadcast`) that signs the
  current root and publishes it to every registered `EpochBroadcaster`.
- Enforce freshness windows (`verify_fresh_epoch_root`) so a stale or
  future-dated root is rejected before a caller treats it as current.
- Bridge `chio-credentials` passport-revocation events onto oracle inserts
  (`passport_bridge`) without the oracle depending on `chio-credentials`.

## Public API

- `RevocationOracle`, `RevocationKey`, `SubjectId`, `EpochNonce`, `EpochRoot`,
  `RootSignature`, `InclusionProof`, `NonInclusionProof`,
  `RevocationOracleError`, `Result` - core types and the oracle trait.
- `sparse_merkle::InMemoryRevocationOracle` - the shipped oracle
  implementation.
- `signer::{Ed25519RootSigner, Ed25519RootVerifier, EpochRootSigner,
  EpochRootVerifier, ALGORITHM_ED25519, DOMAIN_SEPARATION_CONTEXT}` - signing
  and verification.
- `epoch::{SignedEpochRoot, EpochBroadcaster, InMemoryEpochBroadcaster,
  tick_and_broadcast, DEFAULT_EPOCH_TICK_MS}` - epoch ticking and broadcast.
- `freshness::{FreshnessConfig, verify_fresh_epoch_root}` - staleness gating.
- `passport_bridge::{PassportRevocationEvent, apply_passport_revocation,
  PassportRevocationBridgeError}` - passport-lifecycle bridge.

## Usage

```rust
use chio_revocation_oracle::{
    Ed25519RootSigner, EpochNonce, InMemoryRevocationOracle, RevocationKey,
    RevocationOracle, SubjectId,
};

fn revoke_and_prove() -> chio_revocation_oracle::Result<()> {
    let mut oracle = InMemoryRevocationOracle::new();
    let key = RevocationKey::new(SubjectId::from("did:chio:subject-7"), EpochNonce::new(1));
    oracle.insert(key.clone(), 1_700_000_000_000)?;

    let proof = oracle.inclusion_proof(&key)?;
    InMemoryRevocationOracle::verify_inclusion(&proof)?;

    let signer = Ed25519RootSigner::from_signing_key("oracle-a", "generate")?;
    let signed = oracle.signed_epoch_root(&signer)?;
    signed.verify(&signer.verifier())
}
```

## Feature flags

| Flag | Effect |
|------|--------|
| `delegation` | Dev-only. Enables the `swarm_revocation_e2e` and `receipt_chain_proof` integration test targets; no library-side behavior changes. |

## Testing

`cargo test -p chio-revocation-oracle` runs the unit, freshness, and property
tests. `cargo test -p chio-revocation-oracle --features delegation` adds the
3-tier swarm acceptance test (500ms median revoke-to-deny budget) and its
receipt-chain proof reader. `cargo bench -p chio-revocation-oracle` asserts a
200us p99 insert-plus-proof budget over 10k subjects before recording the
Criterion benchmark.

## See also

- `chio-core-types` - supplies the `Keypair` / `PublicKey` / `Signature` and
  canonical-JSON primitives `signer` builds on.
- `chio-federation`, `chio-federation-transport-iroh` - gossip and transport
  layers that push, verify, and merge `SignedEpochRoot`s between kernels.
- `chio-custody-hw` - layers a transactional revocation cascade over
  `InMemoryRevocationOracle` to gate hardware-custody capability minting.
- `chio-credentials` - source of the passport-lifecycle events
  `passport_bridge` consumes.
