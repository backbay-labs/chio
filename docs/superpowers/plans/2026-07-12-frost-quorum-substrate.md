# FROST Quorum Substrate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a restart-safe FROST Ed25519 authorization substrate with
epoch and same-epoch authorization-slot continuity for every registered
`n_of_m` action class.

**Architecture:** `chio-federation` owns strict roster, domain/action-registry and
verification contracts over upstream `frost-ed25519`.
`chio-federation-authority` owns DKG and local signing, `chio-store-sqlite`
durably persists encrypted signer and fenced coordinator sessions, and
`chio-control-plane` transports authenticated round messages and adapts external
monotonic epoch and authorization-slot anchors. Consumers receive a verified
authorization only from an externally completed slot and consume it against a
rollback-independent resource/effect gate.

**Tech Stack:** Rust 1.93, `frost-ed25519` 3.0.0, RFC 8785 canonical JSON, Ed25519, SQLite, ChaCha20-Poly1305 encrypted blobs, Serde, proptest, cargo-nextest-compatible tests.

---

## File Map

- Modify `Cargo.toml`: pin the workspace FROST dependency.
- Modify `Cargo.lock`: record the reviewed dependency graph.
- Modify `crates/trust/chio-federation/Cargo.toml`: consume the workspace dependency.
- Create `crates/trust/chio-federation/src/frost/{mod.rs,types.rs,roster.rs,verify.rs}`: pure public contract and verifier.
- Modify `crates/trust/chio-federation/src/lib.rs`: export the module.
- Modify `crates/trust/chio-federation/src/bilateral_verifier/cosign.rs`: replace the unconditional `n_of_m` rejection with verified quorum input.
- Modify `crates/trust/chio-federation/src/treaty.rs`: use canonical `n_of_m` vocabulary and required quorum metadata.
- Create `crates/trust/chio-federation/tests/frost_{authorization,roster,vectors}.rs`: public verifier tests.
- Create `crates/trust/chio-federation-authority/src/frost_{ceremony,signer}.rs`: upstream DKG and local signer runtime.
- Modify `crates/trust/chio-federation-authority/src/lib.rs`: export ceremony and signer ports.
- Create `crates/platform/chio-store-sqlite/src/frost_store/{mod.rs,schema.rs,signer.rs,coordinator.rs,rotation.rs}`: durable state.
- Modify `crates/platform/chio-store-sqlite/src/lib.rs`: export store handles.
- Create `crates/platform/chio-store-sqlite/tests/frost_{signer,coordinator,rotation}.rs`: crash, retry, and fencing tests.
- Create `crates/platform/chio-control-plane/src/trust_control/frost.rs`:
  authenticated coordinator service and external `FrostEpochAnchor` plus
  `FrostAuthorizationSlotAnchor` adapters.
- Modify the control-plane trust-control DTO, handler, and route modules that register sibling authority services.
- Create `spec/schemas/chio-frost/`: roster, epoch-checkpoint,
  authorization-slot-checkpoint and authorization schemas and fixtures.
- Modify `spec/schemas/registry.json`, `spec/schemas/MANIFEST.sha256`, `spec/PROTOCOL.md`, and `spec/CHIO_LADDER.md`: protocol and registry parity.
- Modify `crates/core/chio-core-types/src/receipt/lineage.rs` and signed-schema tests only if registry ownership requires the existing envelope alias there; do not duplicate FROST types.
- Create `crates/tooling/chio-conformance/tests/frost_quorum.rs`: cross-crate runtime qualification.

## Task 1: Admit Upstream Cryptography And Define The Message

**Branch:** `chio/frost-p1-verifier-contract`

- [ ] Add a failing public test in
  `crates/trust/chio-federation/tests/frost_authorization.rs` that constructs
  `FrostAuthorizationBodyV1`, recomputes its id, and asserts a changed domain,
  action digest, resource version, or fence changes the canonical signing bytes.

- [ ] Run:

  ```bash
  cargo test -p chio-federation --test frost_authorization
  ```

  Expected: compile failure because `chio_federation::frost` does not exist.

- [ ] Add the exact dependency:

  ```toml
  # Cargo.toml [workspace.dependencies]
  frost-ed25519 = { version = "3.0.0", default-features = false, features = ["serialization"] }
  ```

  Add `frost-ed25519 = { workspace = true }` to `chio-federation` and run
  `cargo tree -p chio-federation -i frost-ed25519` to record that only the trust
  owner depends on it.

- [ ] Implement strict types from the design in
  `crates/trust/chio-federation/src/frost/types.rs`:

  ```rust
  pub enum FrostAuthorizationDomain {
      SettleCommitment,
      ClearingRoundFinalize,
      ChannelClose,
      AdjudicationPanelDecision,
      PouncerRevokeCredential,
      GovernanceCaseEnforceSanction,
      CredentialsPassportRevoke,
      RosterRotate,
  }

  pub struct FrostAuthorizationBodyV1 {
      pub schema: String,
      pub authorization_id: String,
      pub domain: FrostAuthorizationDomain,
      pub ladder_action_class: String,
      pub ladder_contract_digest: String,
      pub quorum_n: u16,
      pub quorum_m: u16,
      pub quorum_scope: String,
      pub scope_id: String,
      pub resource_id: String,
      pub resource_version: u64,
      pub resource_fence: u64,
      pub action_digest: String,
      pub roster_digest: String,
      pub key_epoch: u64,
      pub issued_at: u64,
      pub expires_at: u64,
  }
  ```

  Use `deny_unknown_fields`, closed schema constants, the exact ID domain, and
  the exact `CHIO-FROST-AUTHORIZATION-V1\0` signing prefix. Reject empty ids,
  non-hex digests, zero epochs, inverted validity, and stored-id mismatch.

- [ ] Implement the exhaustive domain/action registry and canonical preimage
  dispatch from the design. Map every currently registered `n_of_m` ladder class
  to its exact canonical ladder-entry digest, `n`, `m`, scope and action preimage,
  including `governance.roster_rotate`; reject any cross-pair or quorum drift. The
  active roster threshold/count and trusted classification of the concrete scope
  id must exactly equal that mapping. Keep
  `AdjudicationPanelDecision` explicitly disabled until WS7 Phase 3 registers its
  action class and preimage.

- [ ] Run the focused test and `cargo check -p chio-federation --all-features`.
  Expected: all pass.

- [ ] Commit:

  ```bash
  git add Cargo.toml Cargo.lock crates/trust/chio-federation
  git commit -m "feat(federation): define FROST authorization contract"
  ```

## Task 2: Implement Active And Historical Verification

- [ ] Add failing tests in `frost_vectors.rs` for an official positive vector and
  wrong group key, altered body, wrong domain, stale active epoch, expired proof,
  and a retired epoch accepted only by historical verification.

- [ ] Run the vector test. Expected: compile failure for missing
  `verify_for_execution`.

- [ ] Implement in `verify.rs`:

  ```rust
  pub fn verify_for_execution(
      proof: &FrostAuthorizationV1,
      expected: &ExpectedFrostAuthorization<'_>,
      active_roster: &VerifiedActiveFrostRoster,
      slot_anchor: &dyn FrostAuthorizationSlotAnchor,
      now: u64,
  ) -> Result<VerifiedFrostAuthorization, FrostVerificationError>;

  pub fn verify_historical_evidence(
      proof: &FrostAuthorizationV1,
      resolver: &dyn HistoricalFrostRosterResolver,
  ) -> Result<HistoricalFrostEvidence, FrostVerificationError>;
  ```

  Add `resolve_active_roster_for_execution(scope, resolver, epoch_anchor, now)`;
  it returns private-constructor `VerifiedActiveFrostRoster` only when the local
  roster equals the authenticated external epoch checkpoint. Keep every result
  constructor private. Active verification must require the exact external
  permanent `Completed` authorization slot, verify its signature/message digest
  and exhaustive domain/action mapping, then check every expected field before
  calling the upstream group verifier. Historical evidence must not convert into
  either execution type.

- [ ] Replace the unconditional `n_of_m` rejection in `cosign.rs` with an input
  that requires `VerifiedFrostAuthorization`. Canonicalize treaty vocabulary to
  `n_of_m`; reject legacy `quorum_required` in production decoding rather than
  accepting two spellings.

- [ ] Correct the ladder claim: the external slot prevents a second message for
  one exact authorization tuple, but a group signature alone does not make an
  effect executable. The consumer's rollback-independent current-resource and
  idempotent-effect gate decides execution. A local-only CAS is insufficient.

- [ ] Run:

  ```bash
  cargo test -p chio-federation --test frost_vectors
  cargo test -p chio-federation bilateral_verifier
  ```

  Expected: all pass, including an `n_of_m` negative without verified FROST.

- [ ] Commit `feat(federation): verify FROST execution authorization`.

## Task 3: Land Roster Schemas And Registry Parity

- [ ] Add failing schema tests for unknown family/version, unsorted participants,
  duplicate verification shares, invalid threshold, missing predecessor, invalid
  domain, and embedded-key trust.

- [ ] Create strict `chio.frost.roster.v1`, `chio.frost.epoch-checkpoint.v1`,
  `chio.frost.authorization-slot-checkpoint.v1` and
  `chio.frost.authorization.v1` schemas plus signed positive and tampered
  fixtures under `spec/schemas/chio-frost/`.

- [ ] Add parity tests that enumerate every ladder `n_of_m` entry and require one
  exact registry row with matching action class, canonical entry digest,
  threshold, participant count and scope. Wrong 2-of-3 versus 3-of-5, wrong
  concrete scope classification, and missing entries reject.

- [ ] Implement `FrostRosterV1` and the active/historical resolver contracts in
  `roster.rs`. Recompute roster ids and digests, require sorted unique participants,
  and validate the ceremony, predecessor, validity, and allowed-domain fields.

- [ ] Update runtime and CLI signed-schema registries, schema coverage,
  `registry.json`, `MANIFEST.sha256`, `PROTOCOL.md`, and `CHIO_LADDER.md` in one
  commit. Run the repository schema-manifest generator already used by neighboring
  families rather than editing the checksum by hand.

- [ ] Run:

  ```bash
  cargo test -p chio-federation frost_roster
  cargo test -p chio-core-types signed_artifact_schema
  cargo test -p chio-conformance frost
  ```

  Expected: all positive, tampered, and unknown-version gates pass.

- [ ] Commit `feat(protocol): register FROST quorum artifacts`.

## Task 4: Implement Restart-Safe DKG And Roster Activation

**Branch:** `chio/frost-p2-durable-signing`

**Entry gate:** Protocol-primitives Task 6's RFC-0006 serving-owner amendment is
merged. Every FROST SQLite store is opened from its shared database-UUID
`open_serving` handle and carries that owner epoch; no FROST-specific lock or
independent mutable reopen is permitted.

- [ ] Write failing ceremony tests that kill and reopen after each upstream DKG
  round, reject a changed participant set, reject a duplicate package, and prove
  dealer-generated fixture rosters cannot enter the production resolver.

- [ ] Implement `frost_ceremony.rs` as a state machine over the upstream DKG
  round APIs. Persist the authenticated transcript digest and local secret output
  before publishing completion. Do not serialize or log secret shares outside the
  custody-encrypted record.

- [ ] Add the roster activation transaction in `frost_store/rotation.rs`. Require
  configured target-roster-authority verification, exact 3-of-5
  `governance.roster_rotate` proof from the active treaty-governance rotation
  roster, checked target epoch increment, new group key, exact target predecessor
  digest, and zero live old-epoch session after burn. The governance signer roster
  is distinct from a target 2-of-3 roster when applicable. Construct a private
  `VerifiedFrostEpochAdvance` over the exact predecessor checkpoint, roster,
  rotation proof, burn summary, clock high-water and next activation fence.

- [ ] Implement `FrostEpochAnchor` in the control-plane composition root. Roster
  activation is `DbStaged -> EpochAnchorAdvanced -> DbActive`; the anchor accepts
  only the verified advance through linearizable compare-and-swap. Startup and
  active resolution deny if the anchor is unavailable, behind, ahead or divergent.
  Recovery completes only an exact anchored stage or discards an unanchored one.

- [ ] Implement the external `FrostAuthorizationSlotAnchor` port and production
  adapter in the same composition root with its own typed namespace. It supports
  only `Absent -> Bound -> Completed | Burned`, retains permanent terminal
  tombstones, and has no SQLite/in-memory production fallback.

- [ ] Run:

  ```bash
  cargo test -p chio-federation-authority frost_ceremony
  cargo test -p chio-store-sqlite --test frost_rotation
  ```

  Expected: every crash resumes the same ceremony or fails closed; no old epoch
  signs after activation, and restoring any pre-rotation SQLite snapshot cannot
  roll back the external active epoch.

- [ ] Commit `feat(federation): add durable FROST ceremony and rotation`.

## Task 5: Persist Nonce And Share State Before Network Output

- [ ] Add failing signer-store tests for these exact states:

  ```text
  prepared -> commitment_published -> share_ready -> completed
  prepared|commitment_published|share_ready -> burned
  ```

  Cover crash before and after encrypted nonce insert, commitment return, share
  insert, share return, completion, and burn.

- [ ] Implement `frost_store/signer.rs` by reusing the encrypted-blob AEAD and
  zeroizing key types. Associated data must include participant, epoch, session,
  authorization, message digest, coordinator id, and fence. Persist commitment
  before return and persist the exact share before return.

- [ ] Derive `authorization_slot_id` from domain/scope/resource/version/fence.
  Before nonce creation or commitment output, linearly bind that slot externally
  to the exact domain/action, authorization, message, roster/epoch and session.
  Enforce at most one local live session for the same binding. Derive `session_id` from the exact
  authorization id, signing-message digest and roster digest, not merely the
  resource/action tuple. Recheck the externally anchored active epoch and exact
  `Bound` slot before nonce creation, commitment return and share return.

- [ ] Implement signer retries: identical authenticated input returns the stored
  bytes; any changed message, roster, authorization, or fence burns and rejects.
  Delete encrypted nonce ciphertext at completion while retaining the non-secret
  tombstone. Never fall back to memory.

- [ ] Add a custody-generation field and test that a copied database without the
  matching custody generation cannot resume signing.

- [ ] Restore same-epoch signer snapshots after slot bind, completion and burn.
  A matching generation resumes only the exact bound message; completed returns
  retained output and burned emits nothing. A conflicting message never reaches
  nonce creation.

- [ ] Run `cargo test -p chio-store-sqlite --test frost_signer`.
  Expected: all crash, retry, mismatch, zeroization, and custody-restore tests pass.

- [ ] Commit `feat(store): persist fenced FROST signer sessions`.

## Task 6: Implement The Fenced Coordinator Service

- [ ] Add failing coordinator tests for two workers claiming one session, retrying
  identical packages, changing the message after commitment, late shares after
  cancel, and crash at every transition.

- [ ] Implement `frost_store/coordinator.rs` with a unique authorization slot,
  sorted commitment/share sets, row version, lease id, lease expiry, and owner
  epoch. A lease timeout allows a higher fence to resume the same session; it does
  not create another session id.

- [ ] Reconcile the coordinator's roster with `FrostEpochAnchor` and its exact
  session/message with `FrostAuthorizationSlotAnchor` before session creation,
  each round transition and aggregation. An anchor mismatch or outage emits no
  new package or proof; a retired epoch or conflicting same-epoch slot cannot
  resume from restored coordinator state.

- [ ] Implement authenticated trust-control request/response DTOs and handlers in
  `trust_control/frost.rs`. Resolve participant identities from the active roster,
  cap message/package sizes, deny unknown fields, and bind every request to the
  coordinator fence.

- [ ] Aggregate only after the persisted threshold share set verifies. Persist the
  final authorization, durably store its complete canonical envelope in the
  external anchor or a rollback-independent content-addressed store, then advance
  the slot `Bound -> Completed` with exact blob/availability and signature digests
  before returning it. A digest-only completion rejects. Cancellation first advances
  `Bound -> Burned`, persists local `burned`, fans out signer burns, and ignores
  late shares. An external terminal conflict emits no authorization.

- [ ] Run:

  ```bash
  cargo test -p chio-store-sqlite --test frost_coordinator
  cargo test -p chio-control-plane frost
  ```

  Expected: one coordinator fence wins and aggregation is at most once.

- [ ] Commit `feat(control-plane): coordinate durable FROST sessions`.

## Task 7: Qualify Rotation, Recovery, And Resource Consumption

**Branch:** `chio/frost-p3-runtime-qualification`

- [ ] Add a tiny conformance anchored-resource fixture whose external CAS consumes
  `(authorization_slot_id, authorization_id, resource_id, version, fence,
  action_digest)` exactly once. Create two conflicting messages for one slot and
  prove only one can become signed; restore the local resource after consumption
  and prove the external head prevents a second execution.

- [ ] Add multi-process tests: stale coordinator owner, stale SQLite serving
  owner, signer restart, coordinator restart, rotation during every signer state,
  old-epoch historical verification, epoch-anchor outage/divergence, and restore
  of each pre-rotation signer/coordinator/roster SQLite snapshot after the anchor
  advances. Also restore signer/coordinator snapshots in the same active epoch
  after slot bind/completion/burn and test slot-anchor outage/divergence.
  Restore a pre-aggregate coordinator snapshot after external completion and
  fetch/verify the exact authorization bytes without re-signing.

- [ ] Add one verifier fixture for every currently registered `n_of_m` ladder
  class using its exact mapped domain, canonical action-digest preimage, trusted
  ladder-entry digest, quorum threshold/count, scope derivation and resource
  id/version/fence. Include roster rotation's exact
  predecessor/new-roster/checkpoint preimage. Assert the reserved WS7 domain is
  disabled because its ladder class does not yet exist. These fixtures qualify
  mapping and signing only; each enabled consumer still owns its
  rollback-independent resource/effect gate and end-to-end execution test.

- [ ] Run:

  ```bash
  cargo test -p chio-conformance --test frost_quorum
  cargo test -p chio-federation --all-features
  cargo test -p chio-federation-authority --all-features
  cargo test -p chio-store-sqlite --all-features frost
  cargo test -p chio-control-plane --all-features frost
  ```

  Expected: all pass with no exact-signer-subset claim.

- [ ] Run dependency and security gates:

  ```bash
  cargo audit
  cargo deny check
  ```

  Expected: exit zero or a repository-approved advisory exception naming the
  exact package, scope, owner, and expiry. No unowned exception is accepted.

- [ ] Commit `test(frost): qualify restart rotation and resource fencing`.

## Task 8: Close The Shared Gate

- [ ] Update the program roadmap with completed P1/P2/P3 commit and PR evidence.
  Do not mark the gate complete from fixtures alone.

- [ ] Run the workspace gate:

  ```bash
  cargo build --workspace
  cargo test --workspace
  cargo clippy --workspace -- -D warnings
  cargo fmt --all -- --check
  ```

  Expected: all commands exit zero.

- [ ] Run `git diff --check` and the repository Rust/file hygiene checks.
  Expected: no whitespace, line-limit, stub, or forbidden-comment failures.

- [ ] Record the final gate as satisfying only the shared FROST prerequisite.
  WS1 Phase 4, WS4 Phase 4 and WS5 Phase 3 must still pass their own anchored
  resource/effect and end-to-end tests before activation. WS7 Phase 3 must first
  register and qualify its action mapping, then pass its anchored claim/coverage
  tests. Existing credential/sanction classes without an owned external resource
  gate remain disabled.

- [ ] Commit `docs(economy): close FROST substrate prerequisite`.
