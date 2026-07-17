# Enterprise Hardening Pack Implementation Plan

> Execute this plan in order. Each phase has a narrow build target and a behavioral gate. Do not begin runtime rollout until the key, broker, and cage libraries independently pass their gates.

**Goal:** Deliver transactional authority-key transparency, broker-mediated credential use, and enforced native tool-server confinement without duplicating Chio cryptographic primitives or retaining raw-secret and unconfined fallback paths.

**Design contract:** `docs/superpowers/specs/2026-07-09-enterprise-hardening-design.md`

**Verified baseline:**

- `chio_core_types::merkle` already implements RFC 6962 leaf and node hashing plus inclusion proofs. Extend it with consistency proofs. Do not add another Merkle implementation.
- `chio_manifest::{SignedManifest, verify_manifest, RequiredPermissions}` is the cage admission surface. `chio_core_types::manifest::ToolManifest` is signed, but it is platform-incomplete and lacks registered-key admission, so it cannot be compiled by cage.
- `canonical_json_bytes`, `Keypair::sign_canonical`, `PublicKey::verify_canonical`, and `SigningBackend` are the canonical signing surfaces.
- `nono` 0.11.0 in the reviewed Clawdstrike checkout provides useful Landlock and Seatbelt capability code, but `CapabilitySet::new()` defaults network to `AllowAll`, Linux partial filesystem enforcement returns success, and seccomp notification covers file-open mediation rather than a default-deny syscall allowlist. Chio must correct all three assumptions.
- Clawdstrike's broker shape, generic HTTPS checks, key rotation, Merkle proof tests, audit monitor, capability compiler, preflight, and supervised launcher are adaptation sources. Clawdstrike's non-canonical broker signing, inherited full environment, non-atomic execution counter, and historical-key fallback are not adaptation sources.

## Global constraints

- No em dash characters in code, comments, or documentation.
- `unwrap_used` and `expect_used` remain denied outside narrowly annotated tests.
- Signed payloads use versioned schemas, `#[serde(deny_unknown_fields)]`, RFC 8785 canonical JSON, and Chio signature types.
- All counters and state transitions are checked for overflow.
- All stateful authorization uses transactions or compare-and-swap. No check-then-act logic. Broker execution uses the protocol arc's authoritative `BudgetStore` hold and event API through an injected port, not a broker-owned counter.
- No secret-bearing type implements `Serialize`, `Clone`, or `Debug`.
- No agent-facing or tool-facing API returns credential bytes, a secret file, or a secret environment variable.
- No cage launch succeeds with unsupported, partial, missing, or unconfirmed enforcement.
- The multithreaded runtime does not apply nono or other sandbox operations in a post-fork callback. A fresh, trusted, single-threaded `chio-cage-init` process owns confinement and target exec.
- Grep-only scripts are hygiene checks, not release evidence.
- Every copied or substantially adapted file records provenance and Apache-2.0 attribution before merge.
- Run `cargo fmt --all -- --check`, focused tests, `cargo clippy` for changed crates, and `git diff --check` at the end of every phase.

## Planned file map

### Existing files to modify

- `Cargo.toml`, `Cargo.lock`, `NOTICE`, `deny.toml`
- `crates/core/chio-core-types/src/merkle.rs`
- `crates/platform/chio-manifest/src/lib.rs`
- `crates/platform/chio-manifest/src/validation.rs`
- `crates/platform/chio-store-sqlite/src/encrypted_blob.rs` for zeroizing reads and atomic encrypted-blob plus reference provisioning support
- the existing runtime composition and tool-server launch path selected during Phase 0
- `spec/PROTOCOL.md`, `spec/SECURITY.md`, `docs/security/threat-coverage.md`
- `spec/schemas/registry.json`, `spec/schemas/MANIFEST.sha256`, `spec/schemas/chio-wire/v1/README.md`
- `tests/bindings/vectors/MANIFEST.sha256`
- `crates/tooling/chio-conformance/`, `scripts/check-chio-schema-registry.sh`
- generated Rust, Python, TypeScript, and Go bindings selected by `cargo xtask codegen`
- `crates/core/chio-adversarial-suite/cases/`

### `crates/security/chio-keyring`

- `Cargo.toml`, `src/lib.rs`
- `src/event.rs`, `src/state.rs`, `src/store.rs`, `src/sqlite.rs`
- `src/checkpoint.rs`, `src/sync.rs`, `src/witness.rs`, `src/verifier.rs`
- `src/bin/chio-keylog-witness.rs`, `src/bin/chio-keylog-audit.rs`
- `tests/rotation.rs`, `tests/transparency.rs`, `tests/split_view.rs`

### `crates/security/chio-secret-broker`

- `Cargo.toml`, `src/lib.rs`
- `src/protocol.rs`, `src/proof.rs`, `src/capability.rs`
- `src/backend.rs`, `src/encrypted_blob_backend.rs`, `src/provision.rs`
- `src/provider.rs`, `src/generic_https.rs`, `src/budget.rs`, `src/revocation.rs`
- `src/store.rs`, `src/sqlite.rs`, `src/reconcile.rs`, `src/service.rs`, `src/receipt.rs`
- `src/bin/chio-secret-brokerd.rs`
- `tests/execution.rs`, `tests/concurrency.rs`, `tests/no_secret_crossing.rs`, `tests/network_adversarial.rs`

### `crates/security/chio-cage`

- `Cargo.toml`, `src/lib.rs`
- `src/permissions.rs`, `src/profile.rs`, `src/compile.rs`
- `src/enforcement.rs`, `src/seccomp.rs`, `src/fd_table.rs`, `src/init_protocol.rs`, `src/exec_observer.rs`
- `src/launcher.rs`, `src/supervisor.rs`, `src/receipt.rs`
- `src/bin/chio-cage-init.rs`
- `tests/compile.rs`, `tests/bootstrap.rs`, `tests/linux_enforcement.rs`
- `tests/probes/` for child probe binaries

### Gates and provenance

- `third_party/provenance/clawdstrike-enterprise-hardening.toml`
- `spec/schemas/chio-wire/v1/security/`
- `tests/bindings/vectors/security/`
- `.github/workflows/enterprise-hardening.yml`
- `scripts/check-keyring-transparency.sh`
- `scripts/check-secret-broker-boundary.sh`
- `scripts/check-cage-enforcement.sh`

Paths under the runtime composition layer are deliberately selected in Phase 0 after tracing the current native launch path. Do not guess a wiring file and create a second launcher.

## Phase 0: source, dependency, and integration audit

### Task 0.1: Record adaptation provenance

**Sources to inspect:**

- Clawdstrike `crates/libs/clawdstrike-broker-protocol/src/lib.rs`
- Clawdstrike `crates/services/clawdstrike-brokerd/src/capability.rs`
- Clawdstrike `crates/services/clawdstrike-brokerd/src/provider/generic_https.rs`
- Clawdstrike `crates/libs/clawdstrike/src/pkg/merkle.rs`
- Clawdstrike `crates/services/clawdstrike-registry/src/keys.rs`
- Clawdstrike `crates/services/clawdstrike-registry/src/bin/audit-monitor.rs`
- Clawdstrike `crates/libs/clawdstrike/src/sandbox/capability_builder.rs`
- Clawdstrike `crates/libs/clawdstrike/src/sandbox/preflight.rs`
- Clawdstrike `crates/services/hush-cli/src/sandbox_nono.rs`
- Clawdstrike `crates/services/hush-cli/src/supervised_exec.rs`
- Clawdstrike `infra/vendor/nono/`

- [ ] Add `third_party/provenance/clawdstrike-enterprise-hardening.toml` with the local source repository, exact source commit, source paths, destination paths, Apache-2.0 license, source NOTICE, adaptation notes, and reviewer.
- [ ] Update Chio `NOTICE` for Backbay Industries code that is copied or substantially adapted.
- [ ] Do not copy Spine checkpoint code. It states that it was adapted from AegisNet, and the local checkout does not establish that upstream license.
- [ ] For nono, prefer a pinned upstream dependency whose version, checksum, source, and license are present in the lockfile. If Chio needs a patch to expose real enforcement status, document the upstream commit and patch set in a dedicated vendored directory. Do not copy Clawdstrike's vendored directory without that provenance.
- [ ] Update `deny.toml` only after the dependency graph is known. No broad license wildcard.

**Gate:** A reviewer can trace every adapted block to a licensed source and can distinguish copied code from behavioral reimplementation.

### Task 0.2: Trace the real integration paths

- [ ] Trace all construction and verification of `chio_manifest::SignedManifest` and record the runtime admission point.
- [ ] Trace every native tool-server process launch and identify the one composition owner to replace or wrap.
- [ ] Trace capability revocation and DPoP verification APIs. Select low-level interfaces the broker can consume without introducing a kernel dependency cycle.
- [ ] Trace `SqliteEncryptedBlobStore`, `TenantId`, `TenantKey`, and `BlobHandle` and record the production encrypted credential backend boundary.
- [ ] Trace receipt persistence and select the existing receipt sink used by runtime composition.
- [ ] Enumerate both Chio manifest representations and add a migration note proving which one the cage accepts.
- [ ] Establish an explicit ordering dependency on active-defense Phase 2. Either merge its normative `chio_core_types::manifest::ToolDefinition` plus `chio-manifest` reexports first, or coordinate both arcs in one PR with one owner for the shared files.
- [ ] Do not add enterprise fields to a second `ToolDefinition`. Cage permissions remain fields of the full platform manifest while tool security metadata uses the normative reexported core type.
- [ ] Record the selected paths in the implementation PR description and update this plan if repository movement changed a path.

**Commands:**

```bash
rg -n "SignedManifest|verify_manifest|Command::new|execve|fork|spawn\(" crates
rg -n "Dpop|DPoP|RevocationStore|ReceiptStore" crates/kernel crates/platform crates/core
rg -n "chio_core_types::manifest|chio_manifest::" crates
```

**Gate:** There is one named owner for manifest admission, one for helper launch, one encrypted secret store, and no proposed reverse dependency from `chio-core-types` or `chio-manifest` into a security crate.

### Task 0.3: Pin the Linux enforcement stack

- [ ] Select and pin nono after confirming its source and license.
- [ ] Select and pin a seccomp-BPF compiler capable of a default-deny allowlist. Do not use nono's `openat`/`openat2` notification support as the allowlist.
- [ ] Define the minimum supported Linux kernel, Landlock ABI, CPU architectures, and seccomp feature set in `chio-cage` documentation and CI configuration.
- [ ] Patch or extend nono to expose `RulesetStatus` and add Landlock rules from caller-owned FDs. `chio-cage` must observe and reject `PartiallyEnforced`, and it must not reopen a validated path.
- [ ] Define the pinned `chio-cage-init` binary identity, sealed-memfd launch-plan format, O_PATH FD-table protocol, `execveat` or `fexecve`, and kernel-observed exec-transition requirements.
- [ ] Provision an actual runner matching `[self-hosted, linux, x64, chio-enterprise-security]` with the required Landlock ABI, seccomp, `openat2`, `execveat`, memfd seals, O_PATH behavior, and permitted parent-child `PTRACE_TRACEME` plus `PTRACE_O_TRACEEXEC`. A planned label without an online runner is not release evidence.
- [ ] Run `cargo deny check licenses advisories bans sources` for the proposed graph before implementation continues.

**Gate:** Dependency review explicitly proves network-deny initialization, observable Landlock status, and independent seccomp enforcement.

## Phase 1: generic RFC 6962 consistency proofs

### Task 1.1: Add fixed failing vectors

**Files:** `crates/core/chio-core-types/src/merkle.rs`

- [ ] Add fixed leaf sets for tree sizes 1 through at least 16, including every non-power-of-two boundary.
- [ ] Add expected roots and consistency paths derived from a separately reviewed RFC 6962 implementation or published vectors. Record the vector source.
- [ ] Test valid updates for every `1 <= old_size <= new_size` pair.
- [ ] Test wrong old root, wrong new root, reordered path, truncated path, extended path, zero old size, old size above new size, and index overflow.
- [ ] Cross-check that the append-oriented representation produces the same roots and inclusion proofs as existing `MerkleTree::from_leaves`.

**First command:**

```bash
cargo test -p chio-core-types merkle::tests::consistency
```

Expected before implementation: compile failure because consistency types and methods do not exist.

### Task 1.2: Implement consistency proof types and verification

**Public contract:**

```rust
pub struct MerkleConsistencyProof {
    pub old_size: usize,
    pub new_size: usize,
    pub audit_path: Vec<Hash>,
}

impl MerkleTree {
    pub fn consistency_proof(
        &self,
        old_size: usize,
    ) -> Result<MerkleConsistencyProof>;
}

impl MerkleConsistencyProof {
    pub fn verify(&self, old_root: &Hash, new_root: &Hash) -> Result<()>;
}
```

- [ ] Keep `leaf_hash` and `node_hash` unchanged.
- [ ] Reject malformed proofs and consume the entire audit path.
- [ ] Use checked arithmetic for sizes and indices.
- [ ] Add an append-oriented frontier only if benchmarks show rebuilding is material. It must be an internal optimization producing byte-identical roots.
- [ ] Do not add key-log concepts to `chio-core-types`.

**Gate:**

```bash
cargo test -p chio-core-types merkle
cargo clippy -p chio-core-types --all-targets -- -D warnings
```

All fixed, property, malformed-proof, and cross-check tests pass.

## Phase 2: key-log event and transactional state

### Task 2.1: Scaffold `chio-keyring`

- [ ] Add the workspace member using the workspace package and lint template.
- [ ] Depend on `chio-core-types`, `serde`, `serde_json`, `sha2`, `thiserror`, and `rusqlite` through workspace dependencies. Add no alternate crypto library.
- [ ] Define an unsigned, versioned, `deny_unknown_fields` `KeyLogEventBody` and separate `OldKeyAuthorization`, `NewKeyProofOfPossession`, and `RecoveryAuthorization` signature types.
- [ ] Define `SignedKeyLogEvent { body, authorizations }`. Every authorization signs the same domain-separated canonical bytes of `body`; no signed input contains its own signature.
- [ ] Define canonical Merkle leaf bytes as the complete `SignedKeyLogEvent` envelope. `previous_event_hash` hashes the previous complete canonical envelope, and `body.sequence` equals the zero-based Merkle leaf index.
- [ ] Compute `key_id` from the complete self-describing public-key encoding and algorithm under a versioned domain, not from a truncated display string.
- [ ] Validate that `SigningAlgorithm` matches the `PublicKey` variant.
- [ ] Normal rotation requires valid old-key and new-key signatures over the body. Recovery requires distinct authorized recovery signatures over that body. Genesis uses the configured bootstrap authorization.

**Tests:** body and envelope canonical stability, leaf hash coverage of every signature byte, no self-reference, schema rejection, sequence/index mismatch, predecessor-envelope mismatch, key/algorithm mismatch, duplicate key ID, tampered old signature, tampered new signature, and cross-algorithm substitution.

### Task 2.2: Implement pure state replay

**Public contract:**

```rust
pub struct KeyLogState { /* private fields */ }

impl KeyLogState {
    pub fn replay<'a>(
        events: impl IntoIterator<Item = &'a SignedKeyLogEvent>,
        witnessed_activations: &WitnessedActivationSet,
        policy: &KeyLogPolicy,
    ) -> Result<Self, KeyringError>;

    pub fn active_signing_key(&self) -> Result<&KeyRecord, KeyringError>;
    pub fn verification_key_for_artifact(
        &self,
        key_id: &KeyId,
        artifact_hash: &Hash,
        time_evidence: &ArtifactTimeEvidence,
    ) -> Result<&KeyRecord, KeyringError>;
}
```

- [ ] Make events immutable. Rotation proposal, abort, retirement, and revocation append envelopes rather than modifying old leaves.
- [ ] Enforce exact leaf-index sequence, complete-envelope predecessor hash, authorization, and witness-activation continuity.
- [ ] A rotation envelope creates one pending key. It does not change the active signer until its containing checkpoint has the configured witness threshold and the local activation transaction commits.
- [ ] Enforce exactly one active signing key and at most one pending rotation.
- [ ] Treat an artifact's self-asserted `signed_at` as untrusted metadata. An old-key artifact requires an artifact-hash inclusion proof in a configured Chio receipt checkpoint or another trusted timestamp anchor committed before witnessed activation.
- [ ] A deprecated key verifies only appropriately anchored artifacts inside its `verify_until`; a new key cannot verify an artifact anchored before its witnessed activation.
- [ ] A revoked key verifies nothing after the revocation policy's effective rule, including inside a former overlap window.
- [ ] Emergency recovery requires the configured recovery threshold and emits a distinct operation.
- [ ] There is no fallback to a historical private key when a requested key is unavailable.

**Tests:** genesis, pending rotation, witnessed activation, overlap boundary, trusted artifact anchor, self-backdated old signature, new-key preactivation anchor, abort, retirement, revocation, recovery, duplicate events, sequence gaps, time reversal, unknown predecessor, multiple active keys, unavailable signer, and replay determinism.

### Task 2.3: Implement pending-event SQLite append

**Storage contract:**

- `key_events(sequence PRIMARY KEY, event_id UNIQUE, canonical_envelope, envelope_hash, leaf_hash, operation)`
- `key_state(singleton, active_key_id, pending_key_id, pending_event_id, signing_epoch, last_sequence, last_event_hash, tree_size, root_hash)`
- `key_checkpoints(checkpoint_sequence PRIMARY KEY, tree_size, root_hash, canonical_body, operator_signature, stage)`
- `key_checkpoint_witnesses(checkpoint_hash, witness_id, signature)` with a unique pair

- [ ] Open transactions with write locking appropriate to SQLite so two rotations cannot both read the same head.
- [ ] Validate the candidate event against state inside the transaction.
- [ ] Append the complete envelope, derive the new root with `chio-core-types` Merkle primitives, record a pending key without changing the active key, and create the operator-signed pending checkpoint in the same transaction.
- [ ] Stage the new `SigningBackend` behind a non-cloneable activation gate. No capability, receipt, checkpoint, or other artifact-signing path can request it while pending.
- [ ] Make `KeyringSigningRouter` the only artifact-signing entry point. It acquires the authoritative `(active_key_id, signing_epoch)` shared fence, holds it through backend completion and durable artifact-hash anchoring, and includes the epoch in signed evidence. Do not expose clonable backend handles to callers.
- [ ] Restrict a local SQLite selector to one signing process. Multi-worker signing requires a shared linearizable selector and fenced lease service; unsupported topology fails startup.
- [ ] On serialization, signing, disk-full, uniqueness, or commit failure, leave the prior key active, no new key exposed, and the tree unchanged.
- [ ] Rebuild and compare derived state and root at startup. A mismatch is fatal.

**Tests:** concurrent proposals, injected failure at every write boundary, crash-reopen with pending proposal, backend activation-gate denial, stale signing epoch, multi-worker configuration rejection, duplicate append, disk error, signing error, and full rebuild.

**Gate:** a committed proposal is visible in the log while the old backend remains the only usable signer, and no committed envelope is absent from the tree.

## Phase 3: key checkpoints, witnesses, and verifier

### Task 3.1: Add signed checkpoints

- [ ] Define `KeyLogCheckpointBody` and `SignedKeyLogCheckpoint` exactly as the design contract.
- [ ] Bind schema, log ID, checkpoint sequence, tree size, root, previous checkpoint hash, and issuance time.
- [ ] Sign via Chio canonical signing backends with an operator key distinct from authority keys.
- [ ] Reject root-size mismatch, sequence regression, clock skew beyond policy, wrong operator algorithm, and wrong log ID.

### Task 3.2: Add independent witness signatures and gossip

- [ ] Define a domain-separated witness statement over the checkpoint body hash.
- [ ] Implement a witness service with a durable pinned checkpoint, retained full event log or verified frontier, and a fixed roster identity.
- [ ] Before signing, verify the operator signature and checkpoint chain, RFC 6962 consistency proof, every contiguous complete envelope since the pin, rebuilt new root, event authorizations, and full state replay.
- [ ] In one transaction persist the candidate root and advance the witness pin before returning a signature. A restart cannot permit double signing.
- [ ] Refuse conflicting roots for either a previously observed `(log_id, checkpoint_sequence)` or `(log_id, tree_size)` pair.
- [ ] Verify witness IDs against a configured trust map, reject duplicates, and require `floor(n / 2) + 1` signatures for a fixed roster.
- [ ] Emit durable equivocation evidence when two correctly signed checkpoints conflict.
- [ ] Provide a narrow gossip import/export format containing checkpoints and witness signatures, not private state.

**Tests:** malicious operator fork, omitted middle leaf, invalid event authorization, wrong rebuilt root, stale consistency proof, crash after durable decision before response, restart double-sign attempt, strict-majority boundary, duplicate witness, and gossip conflict.

### Task 3.3: Activate a witnessed rotation transactionally

- [ ] Collect signatures only for the exact pending checkpoint and configured roster.
- [ ] In one activation transaction, reverify the pending event and checkpoint, strict-majority witness signatures, no intervening head change, and staged backend identity.
- [ ] Derive activation ordering and trusted activation time from the witnessed checkpoint and activation commit. Ignore a proposal-supplied `effective_at` as authority for old-key artifact timing.
- [ ] Acquire the exclusive signing-selector lease, wait for prior shared signing leases to finish, store the witnessed checkpoint, increment `signing_epoch`, and switch `active_key_id` from old to new atomically. Only after commit may the router expose the new `SigningBackend`; close the old route before releasing the exclusive lease.
- [ ] A crash before commit leaves the old backend active. A crash after commit reconstructs the new active selector from durable state.
- [ ] Retrying signature collection or activation is idempotent. A stale or conflicting checkpoint cannot activate.
- [ ] Append a witnessed `abort_rotation` while the old key is available, or use threshold recovery when it is not. Never delete a pending proposal.

**Tests:** signer request before witness threshold, threshold-minus-one, artifact-signing race with activation, stale worker after epoch change, crash before activation commit, crash after commit, stale-head activation, mismatched staged backend, idempotent retry, normal abort, and recovery abort. The signing race linearizes entirely before or after activation and never returns an old-key artifact in the new epoch.

### Task 3.4: Implement contiguous synchronization, verifier, and audit monitor

**Verifier update order:** fetch and validate every checkpoint envelope after the pin through the candidate, verify each operator signature, predecessor, and strict-majority witness set where activation is claimed, verify the consistency proof, fetch every event envelope in `[old_size, new_size)`, verify its index, sequence, predecessor, authorizations, and leaf hash, rebuild the new root, replay full state and witnessed activation history, then persist the new pin, checkpoints, and leaves atomically.

- [ ] `PinnedKeyLogVerifier` never updates its pin after any failed step.
- [ ] A new verifier downloads all event and checkpoint envelopes from genesis and rebuilds roots, witnessed activation history, and state. Do not ship a compact snapshot until an authenticated state-proof format is designed.
- [ ] An inclusion proof for one key is never sufficient. `verify_key` consults the fully replayed state and trusted artifact-time evidence bound to the artifact hash.
- [ ] `chio-keylog-audit` polls checkpoints, fetches contiguous leaves and consistency proofs, rebuilds state, gossips accepted checkpoints, and exits nonzero on omission, rollback, fork, insufficient witnesses, or malformed proof.
- [ ] Audit state is written atomically using temp file, fsync, and rename or durable SQLite transaction.

**Tests:** missing first, middle, or final new leaf; wrong sequence; wrong predecessor envelope hash; valid inclusion with later revocation omitted; consistency fork; root rollback; same-size different-root; fresh-client full sync; self-backdated old artifact; stale, duplicate, or unknown witness; checkpoint-chain break; monitor restart; and failed-update pin preservation.

**Gate:**

```bash
cargo test -p chio-keyring --all-targets
cargo clippy -p chio-keyring --all-targets -- -D warnings
```

A strict-majority witness set and two independent monitors accept a valid contiguous growth sequence, refuse an injected split view, and preserve pins across restart.

## Phase 4: broker protocol and authorization

### Task 4.1: Define the broker wire contract

**Files:** `protocol.rs`, `capability.rs`, `proof.rs`

- [ ] Define `CredentialRef`, `BrokerDestination`, `RequestConstraints`, `ProofBinding`, `BrokerCapabilityBody`, `SignedBrokerCapability`, `BrokerRequest`, `BrokerExecuteRequest`, `BrokerExecuteResponse`, and `BrokerExecutionEvidence`.
- [ ] Bind every field listed in the design: parent capability, subject, provider, credential ref, scheme, host, port, exact path/query, method, allowed headers, provider-owned headers, body size and hash, preview hash, redirect policy, response limit, streaming, distinct broker quota key, max executions, time bounds, revocation, and proof key.
- [ ] Normalize hosts, ports, paths, queries, methods, and header names before capability issuance. The signed form is the comparison form.
- [ ] Use bytes or a bounded body wrapper, not `String`, for HTTP bodies.
- [ ] Recompute body hashes from request bytes. A supplied hash is never authoritative.
- [ ] Use Chio canonical JSON and signing types. Do not port Clawdstrike's plain `serde_json::to_vec` signature path.

**Tests:** canonical round trip, unknown fields, every single-field tamper, default-port normalization, case normalization, query mismatch, duplicate header normalization, and oversized decode.

### Task 4.2: Implement proof-of-possession and replay storage

- [ ] Reuse Chio DPoP semantics where dependency direction permits. Otherwise move only the generic proof body into a core type and keep verification in the broker.
- [ ] Bind the proof to broker capability ID, normalized method and destination, recomputed body hash, a canonical digest of all normalized caller-controlled header names and values, a canonical digest of every caller-controlled execution option, nonce, and issuance time.
- [ ] Define a closed canonical schema for caller options and reject duplicate normalized headers. There is no extension map or transport option outside the proof digest.
- [ ] Persist nonce consumption in the same local transaction as the deterministic pending attempt intent before any remote execution reservation.
- [ ] Bound proof clock skew and nonce lifetime.
- [ ] Production configuration requires public-key proof. Loopback bearer binding is a dev/test-only feature and emits a degraded diagnostic that cannot satisfy production readiness.

**Tests:** replay, concurrent replay, wrong key, wrong capability, wrong body, wrong path, added, removed, reordered, duplicate, or changed header, changed streaming or timeout option, unknown option, stale proof, future proof, and nonce-store failure.

### Task 4.3: Validate parent capability and revocation

- [ ] Define narrow `CapabilityLiveness` and `BrokerRevocations` traits in the broker crate.
- [ ] Runtime adapters call existing Chio verification and revocation stores without making the broker library depend on `chio-kernel` internals.
- [ ] Implement the kernel-owned `SupplementalQuotaVerifier` port in runtime composition. It accepts opaque broker-capability bytes and a kernel-built request context, invokes the enterprise verifier, and returns the request-bound supplemental claim. No wire field or broker method returns a kernel quota key directly.
- [ ] Fail closed when either liveness source is unavailable or stale.
- [ ] Check parent capability, subject, audience, and broker revocation before hold authorization, but treat this as preverification rather than the dispatch linearization point.
- [ ] Immediately before dispatch, call the protocol-owned `AdmissionCaptureAuthority` with the operation-bound canonical revocation set and digest plus verified broker-artifact digest. The set must include the leaf parent capability, every verified delegation ancestor, and every broker-capability revocation id.
- [ ] The protocol operation is `CapturePending` during the combined call. Network dispatch begins only after capture returns signed budget and revocation commit indices and the coordinator persists `DispatchCommitted`. A sequential `is_revoked` check followed by budget capture is rejected as non-authoritative.

**Gate:** authorization tests prove every bound field and state source can independently deny dispatch.

## Phase 5: broker service, provider, and durable execution limits

### Task 5.1: Create a service-private secret backend

**Contract:**

```rust
pub(crate) trait SecretBackend: Send + Sync {
    fn materialize(
        &self,
        credential: &CredentialRef,
    ) -> Result<SecretMaterial, BrokerError>;
}
```

- [ ] `SecretMaterial` wraps zeroizing bytes and has an explicitly redacted formatter. It is not public outside the service modules.
- [ ] Implement production `EncryptedBlobSecretBackend` with `chio_store_sqlite::{SqliteEncryptedBlobStore, TenantId, TenantKey, BlobHandle}`. A broker table maps tenant, credential ID, provider, and version to an opaque blob handle and enabled state.
- [ ] Extend the encrypted-blob store with a broker-neutral transaction boundary so the encrypted blob row and opaque versioned reference mapping commit together. A failed provisioning transaction leaves neither a usable reference nor an untracked live credential.
- [ ] Move decrypted `Vec<u8>` directly into `SecretMaterial`, or add a zeroizing read helper to `encrypted_blob.rs` if review finds an extra plaintext allocation. Never convert it to `String`.
- [ ] Deliver `TenantKey` through a sealed read-only inherited FD or reviewed custody-provider API. Validate seals, exact length, ownership, and single read. Environment, argv, ordinary files, constants, and zero-key fallbacks are forbidden.
- [ ] Add an authenticated admin provisioning API authorized by an operator capability or governed approval. Provision, rotate, disable, and delete are tenant-scoped, transactional, and redacted; no response returns credential bytes.
- [ ] Do not implement a plaintext filesystem or environment backend. A canary backend exists only under `cfg(test)`. Vault and HSM drivers can remain deferred.
- [ ] Errors name the credential reference but never include backend values.
- [ ] Panic hooks, tracing fields, HTTP debug logs, and receipt serialization are tested with seeded canary credentials.

**Tests:** authenticated and unauthorized provisioning, tenant crossover, blob tamper, wrong key, invalid or unsealed key FD, startup without custody, credential version rotation, disabled version, redacted admin receipt, and zeroization.

### Task 5.2: Implement crash-reconcilable multi-key reservation

**Authoritative budget contract:**

- [ ] Define an injected `BrokerExecutionBudget` port with idempotent `query_execution_hold`, `authorize_execution_hold`, `reverse_execution_hold`, and `capture_execution_hold` operations. Requests bind invocation ID, parent capability ID, broker capability ID, the complete quota-key set, hold ID, event IDs, and authority metadata.
- [ ] Implement the production adapter with the protocol arc's existing or extended `BudgetStore` authoritative hold and event API. Require `BudgetAuthorityProfile::AuthoritativeHoldEvent`.
- [ ] Add a domain-separated `BudgetQuotaKey` dimension for the verified broker capability ID and its signed `max_executions`. This quota exists even when the parent has no aggregate budget.
- [ ] Build one hold containing the existing per-grant quota, optional derived parent aggregate quota, and broker-capability quota. Deduplicate identical keys but never collapse distinct parent and broker ceilings into one counter.
- [ ] A brokered logical invocation has one invocation ID and hold ID across kernel and broker. Runtime composition authorizes the complete key set once; the broker queries or continues that same hold rather than charging the parent aggregate a second time.
- [ ] Atomic multi-key holds and broker quota support are production prerequisites. If unavailable, broker execution fails closed. Do not approximate with per-process, per-grant-only, or broker-local counters.
- [ ] Unit and protocol tests may use an in-memory implementation of the same port. It must run the same conformance suite as the production adapter.
- [ ] `capture_execution_hold` delegates to `AdmissionCaptureAuthority`, which verifies the set digest, reads latest state for the leaf parent, every delegation ancestor, and every supplemental id, and captures the hold in one transaction or consensus-log entry. Return the checked-set digest, budget and revocation commit indices, and leader epoch together.
- [ ] Require all revocation writes for broker-dispatch capabilities to use that combined authority. Startup rejects a separate revocation writer or a budget backend that cannot prove the shared commit domain.
- [ ] Reverse only where dispatch provably did not begin. A captured execution stays consumed if the upstream times out or the response is rejected or lost.
- [ ] Repeated reverse or capture with the same event ID is idempotent. Conflicting reuse of a hold or event ID is an invariant violation and denial.

**Broker-local evidence storage:**

- `broker_capabilities` stores the signed body hash, expiry, and revocation state for service validation, but not authoritative remaining uses.
- `broker_attempts` stores deterministic request digest, invocation, hold, and event IDs and records `pending`, `held`, `reversed`, `captured`, `completed`, or `failed` for write-ahead intent, evidence, and idempotency.
- `broker_nonces` uniquely stores proof key and nonce until expiry.

- [ ] Derive deterministic attempt, hold, and event IDs from the broker capability ID, invocation ID, proof nonce, and canonical request digest.
- [ ] Expose authenticated local `RegisterAttempt`. Before any remote hold call, runtime composition sends deterministic operation, attempt, hold and event IDs plus non-secret request and proof digests; the broker validates them, inserts and fsyncs the pending intent and nonce association, and returns an idempotent acknowledgement without materializing a credential. A uniqueness conflict loads and reconciles the existing intent; it does not create new IDs.
- [ ] On retry or startup, query authoritative state by hold and event IDs. If held, reversed, or captured, reconcile local state idempotently. If unknown, retry authorization with the same IDs. If unreachable or ambiguous, remain pending and deny dispatch.
- [ ] A recovery worker drains pending intents but never dispatches an already captured request. Operator tooling can inspect and resolve permanently ambiguous authority state without minting replacement IDs.
- [ ] Exactly N concurrent requests capture the broker-capability quota for maximum N, and parent aggregate counts each logical invocation once.
- [ ] A duplicate request never attaches to or reuses another attempt.

**Tests:** crash before remote call, remote hold commit before local acknowledgement, reverse commit before local acknowledgement, combined capture commit before local acknowledgement, restart reconciliation, remote timeout with later query, conflicting ID reuse, aggregate-plus-broker exhaustion permutations, quota-key deduplication, no parent double-charge, leaf and each delegation ancestor revoked after validation, revocation-set omission or mutation, revoked-first denial, captured-first consumption, and rejection of a sequential revocation-check backend.

### Task 5.3: Implement generic HTTPS execution

- [ ] Disable redirects in the client, including provider defaults.
- [ ] Require HTTPS except explicit loopback tests.
- [ ] Resolve DNS, reject restricted address classes, pin the validated address for connection, and verify TLS for the original hostname.
- [ ] Reject caller `Authorization`, `Proxy-Authorization`, `Cookie`, `Host`, hop-by-hop, and provider-owned headers before provider injection.
- [ ] Recompute canonical caller-header and caller-option digests after normalization and compare them with the proof immediately before request preparation.
- [ ] Recompute and compare body hash and preview hash before materializing the credential.
- [ ] Provider adapters inject reviewed authentication schemes only. Arbitrary caller-specified header templates are not accepted.
- [ ] Enforce request, response, and streaming byte limits while streaming, not after buffering an unbounded payload.
- [ ] Strip or reject response headers and bodies that contain configured credential canaries. This is defense in depth.
- [ ] Zeroize transient credential and authorization buffers as soon as the HTTP client has consumed them.

**Tests:** IPv4 and IPv6 restricted ranges, decimal and mixed IP forms, DNS rebinding, redirect to restricted host, TLS mismatch, forbidden headers, provider-header collision, body mismatch, chunked oversize, compressed oversize, timeout, and cancellation.

### Task 5.4: Implement IPC and process-level no-secret tests

- [ ] Expose bounded framed IPC or mTLS endpoints for issue, revoke, status, execute, and authenticated admin provisioning. Authorization is per operation and tenant.
- [ ] Run brokerd as a separate identity where the platform supports it. The tool child receives only the IPC descriptor and opaque capability.
- [ ] Seed a unique credential and inspect tool argv, environment, open readable files, IPC frames, stdout, stderr, structured logs, panic output, and signed receipts. The credential must appear only at the fake upstream.
- [ ] Prove that terminating brokerd fails closed and does not trigger a direct HTTP fallback.

**Gate:**

```bash
cargo test -p chio-secret-broker --all-targets
cargo clippy -p chio-secret-broker --all-targets -- -D warnings
```

The fake upstream observes credential injection, exactly N concurrent attempts dispatch, and no calling-process surface contains the credential.

## Phase 6: typed manifest permissions and cage compiler

### Task 6.1: Extend the platform manifest schema

**Files:** `crates/platform/chio-manifest/src/lib.rs`, `validation.rs`

- [ ] This task is blocked until active-defense Phase 2 has landed or both arcs are executing in one coordinated PR. Rebase before editing and confirm `chio-manifest` reexports the normative core `ToolDefinition`.
- [ ] Preserve that single `ToolDefinition` truth. Do not recreate a platform-local tool shape while changing `RequiredPermissions` or the signed manifest envelope.
- [ ] Add an explicit versioned native syscall profile to `RequiredPermissions`. Use a closed enum or versioned identifier, not an arbitrary syscall list supplied as strings.
- [ ] Add typed network destination parsing with normalized host and explicit port. Preserve the current serialized fields only through an explicit schema migration, not ambiguous dual interpretation.
- [ ] Keep environment permissions as names. Manifest values are never accepted.
- [ ] Land these permission fields in the same strict `chio.manifest.v2` migration owned with active-defense Phase 2. Neither arc may freeze or ship v2 until unified tool types, flow fields, typed cage permissions, syscall profile, and strict nested parsing are all present. Never add them to v1 or defer them to an incompatible successor.
- [ ] Add explicit v1-to-v2 migration fixtures and require operator re-signing. Cage-managed native launch denies v1 and every v2 manifest without an explicit supported syscall profile.

**Tests:** relative paths, root paths, traversal, NULs, duplicates, symlink paths, missing-parent writes, invalid hosts, implicit ports, wildcard hosts, invalid env names, loader env names, absent syscall profile, unknown profile, signature tampering, and schema downgrade.

### Task 6.2: Validate and normalize permissions

**Public contract:**

```rust
pub fn admit(
    signed: &chio_manifest::SignedManifest,
    registered_key: &PublicKey,
    ceilings: &OperatorCeilings,
) -> Result<AdmittedManifest, CageError>;
```

- [ ] Call `chio_manifest::verify_manifest` before reading permissions.
- [ ] Hash the verified canonical manifest and include that digest in `AdmittedManifest`.
- [ ] Open every existing path once with `O_PATH | O_CLOEXEC`, resolve it under `openat2` constraints, and retain its FD plus device, inode, mount, mode, and kind. Validation returns owned descriptors, not names to reopen later.
- [ ] For an exact missing writable file, retain the parent directory FD and securely create it with `openat2`, `O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC`, explicit mode and ownership, then reopen or retain it as `O_PATH`. Reject missing directories, wildcard future children, and any target that cannot be created without a name-resolution race.
- [ ] Open and hash the cage-init helper, target executable, working directory, and required runtime files. Retain all FDs. Reject grants that alias through symlinks, change identity during validation, or widen to `/`.
- [ ] Resolve and reject the complete forbidden-path set before constructing any Landlock grant. Landlock grants are monotonic and cannot be subtracted after insertion.
- [ ] Apply operator ceilings as set intersection and limit minimization. Any attempted widening is a programmer error and denial.
- [ ] Reject `chio_core_types::manifest::ToolManifest` at this boundary. It has an embedded signature but lacks platform permissions and registered-key admission.

### Task 6.3: Compile from deny-all

- [ ] Create `nono::CapabilitySet`, immediately set network mode to `Blocked`, then add validated grants by retained FD through the patched nono API.
- [ ] Collect forbidden paths before adding any allowed Landlock path.
- [ ] For brokered tools, pass one already-connected authenticated Unix-domain IPC FD and deny `socket`, `connect`, and `bind` in seccomp. Do not grant a loopback TCP port: Landlock's connect rule is port-scoped and would also permit remote hosts on that port. Direct egress uses a preconnected or descriptor-passed authenticated proxy channel unless a separately reviewed network namespace supplies stronger destination enforcement.
- [ ] Assign deterministic FD slots for helper, target, working directory, runtime resources, read/write grants, broker IPC, sealed plan, and status channel. Bind each slot to its recorded identity in the canonical plan.
- [ ] Construct the minimal environment from fixed safe keys and permitted parent values. Reject credential names and `LD_*`, `DYLD_*`, language startup hooks, and other configured injection variables.
- [ ] Select a reviewed architecture-specific syscall profile and compute a profile hash.
- [ ] Produce a deterministic canonical `CompiledSandboxProfile` and cage-init plan binding manifest, helper, target, FD-table, nono, seccomp, environment, and operator-ceiling digests. Compilation itself does not apply OS confinement.

**Tests:** determinism, deny-all default, network explicitly blocked, preconnected broker IPC control, remote-host same-port denial, raw socket/connect/bind denial, read/write separation, forbidden-before-allowed ordering, operator narrowing, O_PATH identity retention, path swap after validation, secure exact-file creation, missing-directory rejection, system resource minimization, environment non-inheritance, FD-slot mismatch, helper and target identity, and profile-hash changes for every semantic input.

**Gate:**

```bash
cargo test -p chio-manifest
cargo test -p chio-cage compile
```

An unsigned, invalid, legacy-without-profile, or ambiguous manifest cannot produce a compiled profile.

## Phase 7: actual Linux enforcement

### Task 7.1: Make nono enforcement status observable

- [ ] Add or adapt a nono API that returns the actual Landlock ABI and `RulesetStatus` for filesystem and network rules.
- [ ] Add an API that constructs Landlock `PathBeneath` rules from caller-owned FDs without `PathFd::new(path)` or any pathname reopen. The caller retains ownership through ruleset application.
- [ ] Treat `PartiallyEnforced` and `NotEnforced` as errors whenever the profile requires that class.
- [ ] Hard-require network support whenever any network restriction is requested.
- [ ] Keep network blocked when the manifest declares no network use.
- [ ] Add tests against a mocked status adapter plus real-kernel CI. A mock cannot satisfy the release gate by itself.

### Task 7.2: Install an independent seccomp allowlist

- [ ] Define reviewed syscall profiles per supported architecture and runtime class.
- [ ] Compile filters with default action `KILL_PROCESS` or an explicitly reviewed deny errno for diagnosable development mode. Production uses the fail-stop action selected by security review.
- [ ] Validate the current architecture before filter installation.
- [ ] Set `no_new_privs` before installing the filter.
- [ ] Include only syscalls required for cage-init bootstrap, `execveat` or `fexecve`, runtime startup, declared I/O, signals, and clean exit. Document each broad syscall.
- [ ] Nono seccomp user notification may be disabled or used for separate supervision, but it does not satisfy this task.

**Tests:** forbidden syscall probe, architecture mismatch, filter-install failure, FD-based Landlock rule with pathname replacement, `execveat` target transition, threads where allowed, process creation where denied, and mutation disabling default-deny.

### Task 7.3: Add enforcement evidence types

- [ ] Implement `Unsupported`, `Rejected`, `BootstrapFailed`, `FullyEnforced`, and `Exited` states.
- [ ] `FullyEnforced` requires observed Landlock full enforcement, independent seccomp installation, matching manifest, plan, FD-table, helper, target, and profile hashes, a complete `EnforcementPrepared` record, kernel `PTRACE_EVENT_EXEC`, post-exec image identity matching the retained target, and corroborating CLOEXEC EOF. Target liveness after the exec event is not required.
- [ ] Do not expose `BestEffort`, `Partial`, or `Unconfined` as successful launch outcomes.
- [ ] Include detected ABI and filter digest, not claims inferred from configuration.

**Gate:** Real Linux CI demonstrates that disabling Landlock or seccomp changes a permitted launch into a denied launch, never a degraded success.

## Phase 8: dedicated cage-init and supervised launch

### Task 8.1: Launch and authenticate fresh cage-init

- [ ] Build `chio-cage-init` as a dedicated binary with no async runtime or background threads. Pin its content digest and executable identity in deployment configuration.
- [ ] The multithreaded runtime uses the normal process-spawn path with no custom post-fork callback. It never invokes nono, Landlock, or seccomp itself.
- [ ] Open and retain the expected helper identity before spawn. Before sending the plan or resource FDs, compare `/proc/<pid>/exe` device, inode, and content digest with that pin; kill and reap on mismatch.
- [ ] Put canonical plan bytes in a memfd and apply `F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL`. Pass it read-only with the fixed O_PATH FD table over authenticated local IPC or inherited slots.
- [ ] Create a status pipe with the helper write end `CLOEXEC` and distinct prepared and failure records. Keep a pidfd for identity and reaping. Status EOF is corroboration only and cannot prove exec.
- [ ] Reject set-user-ID, set-group-ID, file-capability, and other privilege-changing helper or target images.

### Task 8.2: Implement single-threaded cage-init

- [ ] At process entry, assert there is exactly one task, initialize no thread pool, and receive only bounded plan and FD-table inputs.
- [ ] Verify parent authentication, memfd seals, plan schema and digest, manifest and profile hashes, helper self-identity, FD count and slot kinds, every `fstat` identity, target digest, and environment and argument bounds.
- [ ] After verification and before confinement, call `PTRACE_TRACEME` and stop. The parent must acknowledge the stop, set `PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL`, and continue the helper. Failure of any trace step denies launch.
- [ ] Close all descriptors not named in the plan. Set identity, resource limits, signal mask, working-directory FD, minimal environment, and `no_new_privs`.
- [ ] Add every Landlock rule from retained FDs through the patched nono API and require full enforcement. Install the independent seccomp filter.
- [ ] Write `EnforcementPrepared` with manifest, plan, FD-table, helper, target, Landlock, seccomp, and trace-session digests.
- [ ] Execute the retained target FD with `execveat(..., AT_EMPTY_PATH)` or `fexecve`. Do not resolve the target path again. Reject script targets in v1; use a retained reviewed interpreter as the target and a separately retained script FD when required.
- [ ] Every failure writes a structured record and exits. The helper never closes the status FD to report success. Successful target exec produces CLOEXEC EOF, but only the kernel exec event establishes the transition.
- [ ] Isolate and document the small audited unsafe surface for FD, memfd, Landlock, seccomp, and exec syscalls with `unsafe_op_in_unsafe_fn` enabled.

### Task 8.3: Implement parent supervision

- [ ] Wait under one deadline for exactly one matching `EnforcementPrepared`, a `PTRACE_EVENT_EXEC` stop, matching post-exec `/proc/<pid>/exe` device, inode, and content digest, and EOF with no extra or failure record.
- [ ] Record `ExecTransitionObserved` while the target is stopped, transition to `FullyEnforced`, then detach and resume it. An immediate target exit still produces the exec event first and then a subsequent `Exited` state.
- [ ] Prepared plus EOF without an exec event, tracee death, EOF before prepared, malformed or duplicate records, prepared then failure, non-EOF, timeout, trace-session mismatch, helper or FD identity mismatch, partial enforcement, or setup failure is `BootstrapFailed`; terminate and reap any remaining process.
- [ ] After success, forward allowed termination signals, monitor the exact pidfd, wait and reap, and record exit or signal status without PID-reuse ambiguity. A ptrace stop is never exposed to target application semantics.
- [ ] Do not retry through the old launcher after any cage failure.

**Tests:** helper substitution, helper path swap, invalid memfd seals, plan tamper, FD count and identity mismatch, target path replacement after validation, privilege-changing target, non-single-threaded init, trace handshake failure, forged or missing exec event, helper `SIGKILL` after prepared, seccomp death after prepared, every structured failure code, truncated status, EOF before prepared, prepared plus exec-failure record, prepared without EOF, exec event with identity mismatch, successful exec event plus CLOEXEC EOF, immediate target exit, timeout, parent cancellation, signal forwarding, descriptor leak, environment leak, and reaping.

### Task 8.4: Run cage-init adversarial probes

Probe binaries attempt:

- forbidden read, write, create, remove, rename, hard link, and symlink traversal;
- path and executable replacement after validation while retained FDs stay fixed;
- allowed read and exact precreated-file write controls;
- forbidden TCP connect and bind, including IPv4 and IPv6;
- forbidden syscall and process creation;
- inherited descriptor reads;
- parent environment reads and dynamic-loader injection;
- execution of undeclared path and script targets.

**Gate:**

```bash
cargo test -p chio-cage --all-targets
cargo clippy -p chio-cage --all-targets -- -D warnings
```

Real-kernel cage-init tests pass in `.github/workflows/enterprise-hardening.yml` on the designated labeled runner, including the parent-child exec-event observer. Other hosts assert `Unsupported` denial and do not count skipped enforcement tests as a pass.

## Phase 9: runtime composition and signed evidence

### Task 9.1: Wire key-log verification

- [ ] Configure operator and witness trust roots and a minimum witness threshold.
- [ ] Route every authority artifact signature through `KeyringSigningRouter`; reject direct `SigningBackend` use in runtime composition and fail startup when signing topology cannot provide the required selector guarantee.
- [ ] Require a fixed witness roster and strict-majority threshold. Persist complete synchronized envelopes, pins, witness decisions, and equivocation evidence durably.
- [ ] Before accepting an authority key, fetch every contiguous leaf since the pin, verify consistency and checkpoint chains, rebuild the root, and replay full state. A single key inclusion proof is insufficient.
- [ ] Require artifact-hash-bound trusted time evidence for old-key verification. Reject self-asserted backdating and new-key artifacts anchored before witnessed activation.
- [ ] Add shadow mode metrics before enforcement, but shadow failure never silently converts an enforced verifier back to legacy trust.

### Task 9.2: Wire broker routing

- [ ] Add broker endpoint and trust configuration to existing config structures.
- [ ] Issue broker capabilities only after the parent Chio capability and policy have passed existing validation.
- [ ] Before authoritative admission, build one complete quota set with per-grant, optional parent aggregate, and broker-capability keys. Kernel and broker share one invocation and hold ID; neither charges it again.
- [ ] Call broker `RegisterAttempt` and persist its acknowledgement in `AdmissionOperation` before the first budget-authority mutation. A registration failure denies without a hold.
- [ ] Install the enterprise `SupplementalQuotaVerifier` and pass the combined `AdmissionCaptureAuthority` plus authoritative hold ports into broker composition. Refuse a guarantee below `AuthoritativeHoldEvent` or any configuration where revocation and capture do not share a commit domain.
- [ ] Route selected provider requests through brokerd and remove direct credential environment/file grants from their tool manifests.
- [ ] Feed broker execution evidence into the existing receipt store.
- [ ] A broker transport or verification failure denies the tool call. There is no direct-provider retry.

### Task 9.3: Replace the native launcher

- [ ] At the single launch owner found in Phase 0, require admitted manifest and `CompiledSandboxProfile` for opted-in servers.
- [ ] Launch the pinned `chio-cage-init` helper through the normal spawn path, verify its live identity, and send only the sealed plan and retained FD table. Remove custom post-fork sandbox callbacks.
- [ ] Pass only the preconnected authenticated broker IPC FD to brokered tools. Do not grant a reconnecting loopback socket or raw network syscalls.
- [ ] Emit a launch receipt only after the parent derives `FullyEnforced` from matching prepared evidence, kernel `PTRACE_EVENT_EXEC`, verified stopped target identity, and corroborating CLOEXEC EOF.
- [ ] Emit terminal evidence for rejection, bootstrap failure, and exit without falsely labeling them enforced runs.
- [ ] After a server is marked cage-required, configuration cannot fall back to the old launcher.

### Task 9.4: Define redacted receipts

- [ ] Key receipt: complete-envelope hash, event stage, tree size, root, checkpoint, operator, roster, witness IDs, transaction, outcome.
- [ ] Broker receipt: capability IDs, subject, hashed credential reference and version, destination/body/header/option digests, quota keys, complete checked revocation-set digest, attempt/hold/event IDs, combined budget and revocation commit indices and leader epoch, provider, status, byte counts, outcome.
- [ ] Cage receipt: manifest/plan/FD-table/helper/target/profile hashes, nono/seccomp versions, observed Landlock ABI/status, bootstrap outcome, process identity, times, and exit.
- [ ] Add seeded secret tests over serialized receipts and all logging formats.

**Gate:** End-to-end invocation proves capability validation, broker execution, cage enforcement, and receipt persistence. Removing any one mechanism causes denial and a truthful failure receipt.

## Phase 10: adversarial evidence, specs, and rollout

### Task 10.1: Add adversarial cases

Add machine-readable cases and caught-mutant tests for:

- `key_log_omission`
- `key_log_noncontiguous_sync`
- `key_log_inconsistent_growth`
- `key_log_split_view`
- `rotation_partial_commit`
- `rotation_unwitnessed_signing`
- `old_key_backdating`
- `broker_secret_boundary_crossing`
- `broker_execution_overspend`
- `broker_parent_double_charge`
- `broker_orphan_hold`
- `broker_proof_replay`
- `broker_unbound_headers`
- `broker_destination_rebinding`
- `broker_revocation_race`
- `broker_plaintext_custody`
- `sandbox_unsigned_manifest`
- `sandbox_partial_enforcement`
- `sandbox_symlink_escape`
- `sandbox_path_swap`
- `sandbox_helper_substitution`
- `sandbox_false_exec_success`
- `sandbox_syscall_escape`
- `sandbox_fd_or_env_leak`

- [ ] Each case has a control that succeeds and a mutant that would succeed if the relevant check were removed.
- [ ] Wire cases into `chio-adversarial-suite`, `chio-arena`, and threat-coverage evidence using existing schemas.
- [ ] Do not mark a threat row closed until the repository's caught-mutant and evidence requirements are met.

### Task 10.2: Add behavioral gate scripts

- [ ] `check-keyring-transparency.sh` runs fixed vectors, contiguous sync, stateful witness, two-stage activation, trusted artifact-time, monitor growth, and split-view tests.
- [ ] `check-secret-broker-boundary.sh` runs encrypted provisioning, process boundary, crash reconciliation, multi-key budget, supplemental-verifier binding, header/option proof, combined revocation-capture races, SSRF, and fake-upstream tests.
- [ ] `check-cage-enforcement.sh` checks designated runner prerequisites, runs FD and helper identity tests, real cage-init probes, bootstrap failures, and signed evidence verification.
- [ ] Scripts fail when required Linux capabilities are missing on the designated release runner. Local non-Linux runs may report unsupported, but cannot produce release evidence.

### Task 10.3: Land schemas, codegen, conformance, and CI

- [ ] Add closed schemas under `spec/schemas/chio-wire/v1/security/` for complete key-log events, checkpoints, witness signatures, sync responses, broker capabilities, request proofs, execute messages, execution evidence, cage-init plans, prepared records, exec-transition observations, enforcement records, and enterprise receipts.
- [ ] Keep every unsigned signed-body schema separate from its signature envelope. Encode header and option digests, quota keys, complete capture revocation-set digest, combined commit metadata, complete-envelope hashes, witnessed stages, and FD identities explicitly.
- [ ] Register every artifact in `spec/schemas/registry.json`, update `spec/schemas/MANIFEST.sha256`, extend `scripts/check-chio-schema-registry.sh` coverage to the security wire directory, and update `spec/schemas/chio-wire/v1/README.md`.
- [ ] Add canonical positive and negative cases under `tests/bindings/vectors/security/` and update `tests/bindings/vectors/MANIFEST.sha256` with `cargo xtask freeze-vectors`.
- [ ] Extend xtask discovery where required, regenerate Rust, Python, TypeScript, and Go bindings, and require `make codegen-check` with no generated diff.
- [ ] Extend `crates/tooling/chio-conformance` native suite and fixture binary for key sync/witness, broker proof/quota/custody, and cage-plan/evidence scenarios.
- [ ] Create `.github/workflows/enterprise-hardening.yml`. Portable jobs run schema registry, codegen, vectors, and conformance. `linux-enforcement` uses `runs-on: [self-hosted, linux, x64, chio-enterprise-security]`, verifies the parent-child `PTRACE_EVENT_EXEC` contract, and runs all cage scripts without skip-to-success behavior.

**Gate:** schema registry, MANIFEST, four-language generated bytes, vectors, native conformance, and the actual designated Linux workflow all pass.

### Task 10.4: Update normative documentation

- [ ] `spec/PROTOCOL.md`: key-log events and checkpoints, broker capabilities and proof bodies, receipt schemas, version and canonicalization rules.
- [ ] `spec/SECURITY.md`: broker TCB, cage enforcement boundary, witness assumptions, failure and revocation semantics.
- [ ] `docs/security/threat-coverage.md`: mechanisms and evidence references without premature closure.
- [ ] Crate READMEs: supported platforms, operational trust roots, key recovery, broker deployment, cage kernel requirements, and residual risks.

### Task 10.5: Execute staged migration

1. Publish key-log checkpoints in shadow mode, synchronize full logs, and operate a strict-majority witness roster plus independent monitors.
2. Complete a pending rotation, witnessed activation, and abort/recovery drill before key-log enforcement.
3. Provision one provider credential through `EncryptedBlobSecretBackend` and run broker audit-only request comparison without returning raw credentials.
4. Enable one-hold broker and parent quota enforcement plus crash reconciliation, then remove direct credential access for that provider.
5. Generate sealed cage-init plans and retained FD tables and compare them with observed requirements without launching targets.
6. Enforce cage-init for a canary tool server on the designated runner, then expand server by server.
7. Turn on key-log pin enforcement only after witnessed checkpoint continuity and trusted artifact-time evidence are established.
8. Remove legacy secret and launcher configuration after all dependents migrate.

Every flag is one-way per deployed tool or provider. Once enforcement is required, an operational failure denies service rather than re-enabling the legacy path.

## Final verification

Run focused gates first:

```bash
./scripts/check-keyring-transparency.sh
./scripts/check-secret-broker-boundary.sh
./scripts/check-cage-enforcement.sh
./scripts/check-chio-schema-registry.sh
make codegen-check
cargo xtask freeze-vectors --check
cargo test -p chio-core-types merkle
cargo test -p chio-manifest
cargo test -p chio-keyring --all-targets
cargo test -p chio-secret-broker --all-targets
cargo test -p chio-cage --all-targets
cargo test -p chio-conformance --all-targets
cargo clippy -p chio-core-types -p chio-manifest -p chio-keyring -p chio-secret-broker -p chio-cage --all-targets -- -D warnings
cargo fmt --all -- --check
cargo deny check
git diff --check
```

Then run workspace gates:

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## Definition of done

- A key verifier updates a pinned checkpoint only after strict-majority witnesses, a true RFC 6962 consistency proof, every contiguous new complete envelope, rebuilt root, and full state replay. Fresh clients rebuild from genesis.
- Rotation remains pending until witnessed activation commits. The generation-fenced signing router serializes artifact signing with activation, no new-key route opens before the transaction, no stale old-key worker can publish in the new epoch, and old-key artifact verification requires trusted preactivation anchoring rather than self-asserted time.
- The production encrypted-blob backend is provisioned through authenticated administration, receives its master key through sealed FD or reviewed custody, and no supported caller surface contains raw credential material.
- Proofs bind body, normalized headers, and caller options. One authoritative multi-key hold enforces per-grant, optional parent aggregate, and distinct broker-capability quotas without double charge. Pending intents and query-by-ID recovery eliminate orphan uncertainty before dispatch.
- Revocation and capture are linearized in one combined authority commit; sequential check-then-capture implementations cannot satisfy production support.
- Cage admission starts from a registered-key-verified platform `SignedManifest`; retained O_PATH FDs remove path reopen races; trusted single-threaded cage-init applies Landlock and seccomp and executes the retained target FD.
- Prepared evidence plus kernel `PTRACE_EVENT_EXEC`, verified post-exec target identity, and corroborating CLOEXEC EOF establish `FullyEnforced`; an immediate target exit is then recorded as `Exited`.
- Enterprise wire schemas are registered and hashed, four-language generated bytes and conformance vectors are current, and the designated Linux workflow passes actual enforcement tests.
- Unsupported and partial enforcement deny launch and are reported truthfully.
- Adapted source has traceable provenance and required Apache-2.0 attribution.
- Adversarial cases and caught mutants produce executable evidence; no threat row is closed by documentation alone.
- Legacy raw-secret and unconfined fallback paths are removed for migrated providers and tools.
