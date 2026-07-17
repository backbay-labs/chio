# chio-revocation-oracle architecture

## Overview

The crate is a pure library: no async runtime, no network I/O, and
(deliberately) no dependency on `chio-kernel-core` -- `chio-kernel-core`
defines its own `RevocationViewSubject` / `RevocationSnapshot` types rather
than depending on this crate, so the kernel's read path stays decoupled from
the federation / revocation-oracle layer above it and does not re-verify a
snapshot's signature itself. Trust flows outward instead: `chio-custody-hw`
and `chio-federation` link against this crate, call into it at their own
trust boundaries (credential-mint gate, gossip push/merge), and hand the
verified result to whatever local cache their layer owns. The core design
idea is a type-level split between signing and verifying: `EpochRootSigner`
implementations hold private key material, `EpochRootVerifier`
implementations hold only a pinned public key, so a verify-only deployment
can never forge a root.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Crate root. `forbid(unsafe_code)`; declares the six modules and re-exports the public API. |
| `src/api.rs` | Core types (`SubjectId`, `EpochNonce`, `RevocationKey`, `EpochRoot`, `RootSignature`, `InclusionProof`, `NonInclusionProof`, `RevocationOracleError`) and the `RevocationOracle` trait. |
| `src/sparse_merkle.rs` | `InMemoryRevocationOracle`, the only `RevocationOracle` implementation: an append-only Merkle accumulator over `(subject, epoch_nonce)` leaves. |
| `src/signer.rs` | `Ed25519RootSigner` / `Ed25519RootVerifier` and the `EpochRootSigner` / `EpochRootVerifier` traits; domain-separated signing over canonical JSON. |
| `src/epoch.rs` | `SignedEpochRoot`, the `EpochBroadcaster` trait, `InMemoryEpochBroadcaster`, and `tick_and_broadcast`. |
| `src/freshness.rs` | `FreshnessConfig` and `verify_fresh_epoch_root`: bounds how old a root may be before a caller must treat it as stale. |
| `src/passport_bridge.rs` | `PassportRevocationEvent` and `apply_passport_revocation`: maps passport-lifecycle revocations onto oracle inserts without a `chio-credentials` dependency. |

## Epoch lifecycle

1. A caller inserts a `RevocationKey` via `InMemoryRevocationOracle::insert`.
   The oracle appends a Merkle leaf, advances `epoch` by one, and clamps
   `issued_at_unix_ms` to the max of its previous value and the caller's
   timestamp.
2. `tick_and_broadcast` (or a direct `signed_epoch_root` call) signs the
   current `EpochRoot` with an `EpochRootSigner`, producing a
   `SignedEpochRoot`, and publishes it to every registered
   `EpochBroadcaster`.
3. A remote holder calls `SignedEpochRoot::verify` against a pinned
   `EpochRootVerifier` before merging the root into any local cache.
   Verification checks `signer_id`, `algorithm`, exact 64-byte signature
   length, and the Ed25519 signature over the domain-separated canonical
   JSON bytes.
4. A verifier proves revocation with `inclusion_proof` plus the static
   `InMemoryRevocationOracle::verify_inclusion`, a self-contained Merkle
   audit-path check against `root_hash`. It checks non-revocation with
   `non_inclusion_proof` plus `verify_non_inclusion`, which re-queries the
   live oracle rather than checking a standalone cryptographic absence
   proof.
5. `verify_fresh_epoch_root` gates any received root on `issued_at_unix_ms`:
   one issued in the future is an invalid epoch transition, and one older
   than `max_staleness_ms + offline_grace_ms` is stale.

## Invariants and failure modes

- `insert` fails closed on a duplicate key (`AlreadyRevoked`) and on an
  empty or whitespace-padded `subject_id` (`InvalidRevocationKey`), so no
  leaf is ever minted for a noncanonical subject.
- `issued_at_unix_ms` is monotone non-decreasing across inserts
  (`self.issued_at_unix_ms.max(now_unix_ms)`), so backward clock skew cannot
  make a newer epoch appear to predate an older one to a freshness cache.
- `RevocationOracle` has no removal or expiry method: once inserted, a key
  stays revoked for the life of the oracle.
- `Ed25519RootVerifier::verify_epoch_root` denies on any mismatch (wrong
  `signer_id`, wrong `algorithm` tag, a `signature_bytes` length other than
  64, or a failed Ed25519 check); there is no partial-credit path.
- `InMemoryEpochBroadcaster::new` rejects a zero capacity fail-closed
  (`SignerRejected`); a full queue drops the oldest entry (FIFO) rather than
  the new one, relying on a catch-up path for peers that fell behind.
- `tick_and_broadcast` returns the first broadcaster error it hits and
  stops, so a rejected publish is never swallowed while remaining
  broadcasters keep going silently.
- `DEFAULT_EPOCH_TICK_MS` (250ms) trades gossip-storm avoidance under high
  revoke rates against the 500ms median revoke-to-deny budget the
  `swarm_revocation_e2e` acceptance test enforces.
- `passport_bridge::apply_passport_revocation` maps an oracle
  `AlreadyRevoked` into `PassportRevocationBridgeError::AlreadyApplied` and
  treats it as an idempotent no-op: the epoch does not advance a second
  time, so federation does not re-broadcast a duplicate.

## Dependencies

Internal: `chio-core-types` supplies `Keypair`, `PublicKey`, `Signature`, and
`canonical_json_bytes` (RFC 8785 canonical JSON), used by `signer.rs` for
epoch-root signing and verification. Dev-only: `chio-federation` and
`chio-kernel-core` back the `delegation`-gated swarm acceptance test and are
never linked into the library itself. External: `rs_merkle` implements the
Merkle accumulator and its audit-path proofs; `serde` and `thiserror`
provide artifact (de)serialization and error types; `criterion` and
`proptest` back the throughput benchmark and property tests.

## Extension points

- `RevocationOracle` - implement to back a different storage engine; only
  `InMemoryRevocationOracle` ships here.
- `EpochRootSigner` / `EpochRootVerifier` - implement for a different
  signature scheme; only the Ed25519 pair ships here.
- `EpochBroadcaster` - implement to route signed roots to a real transport;
  only the bounded in-memory queue ships here.
