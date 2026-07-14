# chio-pheromone architecture

## Overview

`chio-pheromone` is the receiver-owned trust boundary for pheromone deposits: a
pure data and validation crate (`#![forbid(unsafe_code)]`) with no I/O and no
network dependency. Every admission decision is a function of an explicit
`PheromoneValidationContext` the caller supplies (passports, kernel keys,
subject-class policy, scarcity policies, trust-floor state); the crate holds no
ambient policy or clock. The only mutable state it owns is the in-memory
bookkeeping inside `InMemoryPheromoneSubstrate`. Durable storage and policy
loading belong to `chio-pheromone-runtime`; moving deposits between kernels over
the network belongs to `chio-pheromone-relay`.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Schema constants, `PheromoneError`, all wire types (deposit, scarcity policy, observation-cost evidence, workflow context, runtime trust-floor state), and the public entry points: `sign_deposit`, `validate_deposit_for_admission`, scarcity-admission resolution, passport-hash helpers. |
| `src/validation.rs` | Fail-closed validation internals: static deposit checks, passport resolution and signature verification, scarcity-policy material checks, observation-cost commitment verification, and the substrate's admission-state commit. Private except for the re-exported `validate_scarcity_policy_material`. |
| `src/substrate.rs` | `PheromoneSubstrate` trait and `InMemoryPheromoneSubstrate`: `Mutex`-guarded deposit store and nonce/scarcity/pair/passport bookkeeping, concentration query, evaporation garbage collection. |

## Admission path

1. **Sign.** `sign_deposit` signs the canonical JSON of a `PheromoneDepositBody`
   with `cost_commitment` cleared, so attaching a commitment after signing
   cannot change the signed bytes.
2. **Admit.** `validate_deposit_for_admission` checks static shape and value
   ranges, matches `treaty_scope` against the subject-class policy, requires a
   cost commitment when the policy demands one, resolves scarcity admission for
   every accepted treaty (selecting the single active policy, recomputing its
   `window_id`/`policy_sha256` to catch tampering, and verifying any required
   observation-cost commitment: statement binding, verifier-root trust and
   non-revocation, signature, and Merkle inclusion), checks the replay window
   and future-timestamp bounds, resolves the origin passport (rejecting
   kernel-signed, unknown, revoked, or time-invalid passports), and verifies
   the deposit signature against that passport's key.
3. **Commit.** `InMemoryPheromoneSubstrate::deposit` calls step 2, then
   `commit_admission_state`: rejects a reused `(kernel, passport, nonce)`,
   enforces each scarcity bucket's `token_capacity`, each `(kernel, passport)`
   pair's `max_deposits_per_pair`, and a sqrt(active-peers)-scaled cap on
   distinct passports per kernel/treaty/window, then stores the deposit.
4. **Query.** `query_concentration` folds stored deposits into total and peak
   strength using half-life decay, a caller-supplied peer weight, and a
   newcomer discount; `gc_evaporated` drops deposits whose decayed strength has
   crossed their evaporation floor.

## Invariants and failure modes

- Every admission check fails closed: unknown schema, malformed or
  out-of-range fields, an unmatched treaty, a missing required cost commitment,
  and malformed observation-cost evidence all return a `PheromoneError` before
  a deposit is admitted.
- A deposit signed by a kernel key is rejected (`KernelKeyUsedForDeposit`) even
  if that key would otherwise resolve to a passport.
- A revoked or time-invalid passport is reported as `UnknownOriginAgent`, the
  same code as an unrecognized passport; the crate does not leak a distinct
  "revoked" signal.
- A scarcity policy's `window_id` and `policy_sha256` are recomputed from its
  own fields and compared to the values carried on the policy; a mismatch is
  tampering (`ScarcityPolicyInvalid`), not authoritative input.
- An observation-cost verifier root is untrusted unless its issuer signature
  verifies against `runtime_policy_issuer_public_keys` and a matching,
  well-formed `runtime_trust_floor_state` entry vouches for it; no matching
  entry means revoked.
- `query_concentration` fails closed on an unknown `reputation_epoch` or a peer
  weight outside `[0.0, 1.0]`/non-finite, instead of defaulting silently.
- `commit_admission_state` runs its nonce, bucket, pair, and passport-cap
  checks under the substrate's mutexes so capacity accounting is atomic per
  process; a poisoned lock becomes `PheromoneError::StorePoisoned`, not a
  panic.

## Dependencies

`chio-core-types` supplies canonical JSON, hashing, Merkle proofs, and the
`Keypair`/`PublicKey`/`Signature`/`SigningAlgorithm` crypto types. `base64`,
`hex`, and `sha2` back passport-hash, JWK-thumbprint, and canonical SHA-256
derivation. `serde`/`serde_json` define the wire types and feed
canonicalization. `thiserror` derives `PheromoneError`. No async runtime,
network, or persistence dependency.

## Extension points

`PheromoneSubstrate` is the trait an alternative admission store implements;
`InMemoryPheromoneSubstrate` is the only implementation in this crate.
