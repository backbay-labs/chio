# FROST Quorum Substrate Design

- Date: 2026-07-12
- Status: Approved shared prerequisite for registered `n_of_m` actions
- Owners: `chio-federation` (pure contract and verifier),
  `chio-federation-authority` (ceremony and signer runtime),
  `chio-store-sqlite` (durable sessions and checkpoint cache),
  `chio-control-plane` (coordination and external epoch/slot-anchor adapter)

## Goal

Implement the production `n_of_m` authorization required by
`spec/CHIO_LADDER.md` without inventing threshold cryptography, reusing nonces,
accepting stale rosters, or letting a valid group signature authorize a different
resource version. The substrate must survive process death and key rotation and
must expose one execution verifier to every mapped action class.

## Scope and ownership

`chio-federation` already owns cross-operator co-sign and treaty verification.
Its strict verifier currently rejects `n_of_m`, so the new pure module is
`chio_federation::frost`; no economy workstream and no new crate owns a private
quorum implementation.

The implementation uses the reviewed upstream `frost-ed25519` crate for FROST
Ed25519 key generation, round messages, signature shares, aggregation, and group
signature verification. Chio does not implement curve, nonce, interpolation, or
threshold arithmetic. Dependency admission pins the crate and transitive graph,
runs license and vulnerability gates, and records the selected suite version.

`chio-federation-authority` owns participant ceremony and local signing. It does
not expose key shares to the coordinator. `chio-store-sqlite` owns durable
coordinator and local signer-session stores using the repository's encrypted
secret and leased-worker patterns. `chio-control-plane` transports authenticated
round messages and owns no signing material.

## Canonical authorization

`chio.frost.authorization-body.v1` is strict RFC 8785 canonical JSON:

```rust
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

`authorization_id` is SHA-256 over
`"chio.frost.authorization.id.v1\0" || canonical_json(body without id)`.
FROST signs exactly:

```text
"CHIO-FROST-AUTHORIZATION-V1\0" || RFC8785(body)
```

`chio.frost.authorization.v1` carries the complete body, suite id, and detached
group signature. The group public key, roster, threshold, participant shares,
allowed domains, and active epoch resolve from trusted configuration by
`roster_digest`; the envelope never supplies its own trust root.

The verifier owns one exhaustive closed domain/action registry. A domain cannot
be paired with another ladder class, and a registered `n_of_m` class absent from
this table is disabled rather than accepted generically.

| FROST domain | Exact ladder action class | Required quorum | Canonical action-digest preimage |
|---|---|---|---|
| `chio.frost.settle-commitment.v1` | `settle.commitment` | 2 of 3, treaty | settlement body digest, payer, payee, amount/asset, operation id, rail idempotency key, resource version/fence |
| `chio.frost.clearing-round-finalize.v1` | `clearing.round_finalize` | 2 of 3, treaty | round-finalization body, output manifest and acceptance roots, round id, version/fence |
| `chio.frost.channel-close.v1` | `channel.close` | 2 of 3, treaty | close body, final state, escrow reservation version, token-base-unit release, publisher and lifecycle fences |
| `chio.frost.pouncer-revoke-credential.v1` | `pouncer.revoke_credential` | 2 of 3, treaty | credential body/id, issuer and subject, registry and anchor epoch, reason/evidence root, resource version/fence |
| `chio.frost.governance-case-enforce-sanction.v1` | `governance.case_enforce_sanction` | 3 of 5, treaty | case body/id, subject operator, sanction body, evidence root, enforcement target, resource version/fence |
| `chio.frost.credentials-passport-revoke.v1` | `credentials.passport_revoke` | 2 of 3, treaty | passport body/id, issuer and subject, revocation generation, reason/evidence root, resource version/fence |
| `chio.frost.roster-rotate.v1` | `governance.roster_rotate` | 3 of 5, treaty | predecessor/new roster digests, scope, current/new epoch, current checkpoint sequence/digest, activation fence, old-session burn root |

`chio.frost.adjudication-panel-decision.v1` is a reserved enum value, not an
enabled mapping in P1. WS7 Phase 3 must register `adjudication.panel_decision`
and its exact panel/claim/beneficiary/coverage preimage in the ladder and this
table together before its first verifier fixture or execution.

Every preimage excludes the FROST proof, so no digest cycle exists. The verifier
recomputes the registered preimage and requires the exact domain/action/quorum
tuple. `ladder_contract_digest` is SHA-256 over the canonical registered ladder
entry. The body signs that digest, `quorum_n`, `quorum_m`, `quorum_scope`, the
concrete trusted `scope_id`, action digest and resource fence. The active roster
must have exactly the registered threshold and participant count, and the trusted
scope resolver must classify `scope_id` as the registered scope. A group
signature from another contract digest, threshold, count, domain, class, scope,
resource version, or fence rejects.

## Roster and key epochs

`chio.frost.roster.v1` binds:

- roster id and digest;
- authority scope and allowed domains;
- monotonically increasing key epoch;
- threshold and participant count;
- sorted participant ids and verification shares;
- group public key and suite id;
- DKG ceremony transcript digest;
- predecessor roster digest;
- validity window; and
- roster-authority signature.

Participant identifiers and verification shares are unique and canonical.
`1 <= threshold <= participant_count`. Exactly one roster epoch is active for a
scope at an execution time. An old roster may verify historical evidence but
cannot authorize new execution.

The ceremony runtime uses the upstream distributed key generation protocol and
persists each participant's local progress before transmitting the next-round
package. The final roster commits the complete authenticated ceremony transcript.
A dealer-generated test key is allowed only in fixtures and carries a test-only
suite marker that the production resolver rejects.

Rotation requires both the configured target-roster authority and a
`chio.frost.roster-rotate.v1` authorization from the active treaty-governance
rotation roster registered as 3 of 5. Its action binds the target scope,
predecessor/new roster digests and epochs, checkpoint predecessor/sequence,
activation fence and old-session burn root. The governance roster may differ
from a target 2-of-3 financial or credential roster; the target predecessor is
never incorrectly verified against the 3-of-5 rotation class. Rotating the
governance roster itself uses its current generation. Activation atomically
advances the target epoch and records the predecessor relation. It cancels and
burns every incomplete old-epoch signing session before the new epoch can sign.
Rotation never reuses a group key or silently activates a submitted public key.

SQLite roster rows are staging and cache state, not anti-rollback authority. A
production scope requires a `FrostEpochAnchor` outside the signer/coordinator
database backup and restore domain. Its signed
`chio.frost.epoch-checkpoint.v1` binds anchor id and scope, monotonic checkpoint
sequence and predecessor digest, active roster id and digest, key epoch, group
public-key digest, rotation-authorization digest, activation fence, and trusted
clock high-water.

Pure verification constructs a private `VerifiedFrostEpochAdvance`. It requires
sequence plus one, exact predecessor, key epoch plus one, the new roster's exact
predecessor, a changed group key, valid roster-authority signature, the
active governance rotation roster's exact `roster-rotate` authorization,
nondecreasing clock, and
the old-session burn summary. The external anchor accepts only this verified
type through linearizable compare-and-swap. Rotation uses `DbStaged ->
EpochAnchorAdvanced -> DbActive`; recovery may discard an unanchored stage or
complete the exact anchored successor. A restored database that is behind or
divergent, or an unavailable anchor, cannot sign or verify for execution.

Epoch continuity does not prevent rollback within one active epoch. Every
production scope therefore also requires a `FrostAuthorizationSlotAnchor`
outside all signer, coordinator and consumer database backup domains. Its signed
`chio.frost.authorization-slot-checkpoint.v1` binds anchor/scope, slot id and
version, predecessor digest, domain/action pair, resource id/version/fence,
authorization id, exact signing-message and action digests, roster/key epoch,
session id, state `Bound | Completed | Burned`, optional aggregate signature
digest, optional content-addressed canonical authorization blob reference and
availability receipt, and clock high-water.

The external slot lifecycle is `Absent -> Bound -> Completed | Burned`. Before
any signer publishes a commitment, the coordinator compare-and-swaps `Absent ->
Bound` for the exact message. Every signer independently reads that current
checkpoint. A different message for the same slot always conflicts, including
after a coordinated same-epoch snapshot restore. `Completed` is written only
after the external anchor durably stores the complete canonical authorization
envelope or verifies rollback-independent content availability, and binds its
blob and signature digests. `Burned` permits no further signing output. Both are
permanent tombstones. A restored database may resume only the exact externally
bound session and message; if the checkpoint is completed it fetches, verifies
and returns the anchored authorization bytes even when the coordinator database
was restored before aggregation, and if burned it refuses. A digest-only
completion is invalid.

The epoch and slot anchors may share one qualified external service, but use
separate typed namespaces and checkpoints. Neither has a SQLite production
implementation. Missing, unavailable, behind, ahead or divergent slot state
pauses signing and active execution verification until exact reconciliation.

## Verification API

```rust
pub struct ExpectedFrostAuthorization<'a> {
    pub domain: FrostAuthorizationDomain,
    pub ladder_action_class: &'a str,
    pub ladder_contract_digest: &'a str,
    pub scope_id: &'a str,
    pub resource_id: &'a str,
    pub resource_version: u64,
    pub resource_fence: u64,
    pub action_digest: &'a str,
}

pub fn resolve_active_roster_for_execution(
    scope_id: &str,
    resolver: &dyn ActiveFrostRosterResolver,
    epoch_anchor: &dyn FrostEpochAnchor,
    now: u64,
) -> Result<VerifiedActiveFrostRoster, FrostVerificationError>;

pub fn verify_for_execution(
    proof: &FrostAuthorizationV1,
    expected: &ExpectedFrostAuthorization<'_>,
    active_roster: &VerifiedActiveFrostRoster,
    slot_anchor: &dyn FrostAuthorizationSlotAnchor,
    now: u64,
) -> Result<VerifiedFrostAuthorization, FrostVerificationError>;
```

`VerifiedActiveFrostRoster` and `VerifiedFrostAuthorization` have private
constructors. Active resolution reconciles the local roster with the external
epoch checkpoint and rejects an unavailable, behind, ahead or divergent view. The
authorization verifier resolves the exact permanent external `Completed` slot
and checks
strict schema and suite dispatch, authorization id, canonical body, group
signature, signature digest, active roster, the exhaustive domain/action mapping,
every expected field, and validity window. Execution code accepts only this
verified type.

Historical audit uses a separate `verify_historical_evidence` API that permits a
trusted retired epoch at the artifact's issuance time. It cannot produce the
execution type.

A valid FROST group signature proves authorization by the threshold group. It
does not reveal or prove the exact signer subset. If participant attribution is
needed for operations, separately signed participation receipts may be retained
as evidence, but execution and public claims do not infer a subset from the group
signature.

Every consumer consumes the verified authorization against its current
`(resource_id, resource_version, resource_fence)`. FROST's external slot makes a
second conflicting action body for that tuple impossible to sign. The consumer
still determines whether the authorized action can execute. WS4, WS5 and WS7 use
the external multi-resource anchor in
`2026-07-12-economic-state-continuity-design.md`; other irreversible mapped
classes must provide equivalent rollback-independent resource/effect fencing or
remain disabled. A local compare-and-swap alone is not an activation gate.

## Signer-session durability

The local signer-session key is `(participant_id, key_epoch, session_id)`. A
separate `authorization_slot_id` is SHA-256 over domain, scope, resource id,
resource version and fence and prevents concurrent sessions for one execution
slot. `session_id` is SHA-256 over the domain-separated exact authorization id,
signing-message digest and roster digest. It therefore changes when validity,
action class, epoch or any other signed body field changes. One session signs one
exact message.

The external slot checkpoint, not this local uniqueness index, is the
non-equivocation authority. The local signer writes its `prepared` row only for
the exact externally `Bound` session. It rechecks the slot before commitment and
share output; `Completed` returns the retained result, while `Burned` or mismatch
emits nothing.

```text
prepared -> commitment_published -> share_ready -> completed
prepared|commitment_published|share_ready -> burned
```

Before publishing a round-one commitment, the signer persists the exact nonce
package encrypted at rest. Associated data binds participant id, key epoch,
session id, authorization id, message digest, coordinator id, and coordinator
fence. The key-encryption key comes from the configured custody backend and is
never stored in the database or included in snapshots.

Before returning a signature share, the signer persists the exact share and
state `share_ready`. A retry for the same authenticated session returns the same
commitment or share. A retry with a different message, roster, authorization id,
or coordinator fence burns the session and rejects. After completion, nonce
material is securely erased and the non-secret tombstone remains. A store error
fails closed; the signer never falls back to an in-memory nonce.

Signer state is local custody state and is not replicated by database snapshot.
A restored snapshot without the matching custody generation cannot resume
signing. A restored snapshot with a matching generation still reconciles the
external slot and can resume only the same message. It may retain non-secret
historical verification records only.

## Coordinator durability and fencing

The coordinator session binds the same session and message identities, sorted
participant commitments, selected signer set, aggregate result, coordinator
lease id, and monotonically increasing fence. It persists each transition before
sending the next message. Only the active lease may mutate or resume a session.

The coordinator may retry authenticated messages idempotently. It cannot change
the message after commitments exist, reuse a commitment in another session, or
replace participants after share collection begins. Cancellation records
`burned`, tells every reachable signer to burn, and prevents aggregation even if
late shares arrive. A crash resumes the same session or burns it; it never starts
a second session for the same authorization slot while the first is live.

Before creating a session, publishing a commitment, returning a share, or
aggregating, the signer or coordinator resolves both external epoch and slot
checkpoints and requires the exact roster, epoch, session and message. Anchor
outage or mismatch burns or pauses the session without producing new signing
output. An old SQLite snapshot cannot reopen a retired epoch or a same-epoch
authorization slot.

The local SQLite implementation reuses the database-UUID lock, `open_serving`
handle, durable owner epoch, and stale-writer SQL checks owned by
protocol-primitives Task 6's RFC-0006 serving-owner amendment. It does not create
a FROST-specific lock or reopen the file per store. FROST P2 cannot begin its
mutable store work until that shared amendment lands.
HA coordination requires the control-plane consensus leader epoch. A process id,
wall-clock lease alone, or SQLite transaction contention is not a fence.

## Consumer bindings

- WS1 `settle.commitment`: action digest covers the immutable settlement
  commitment, payer/payee, amount, asset, operation id, and rail idempotency key.
- WS4: action digest covers the round-finalization body, lifecycle version,
  round fence, output manifest, and complete acceptance root. Expected action
  class is `clearing.round_finalize`, scope is the trusted governance scope in the
  round core, and resource id/version/fence are the exact round lifecycle tuple.
- WS5: action digest covers the channel close body, final receipt-derived state,
  escrow reservation version, intended token-base-unit release, and publisher
  fence. Expected action class is `channel.close`, scope is the trusted
  settlement-authority scope in the channel open, and resource id/version/fence
  are the exact `ClosePending` lifecycle tuple.
- WS7: action digest covers the panel decision body, semantic claim key, contest
  version, payout beneficiary/destination binding, and coverage reservation. This
  mapping remains disabled until WS7 Phase 3 registers its ladder class.
- Credential revocation and governance sanction use the exact registered
  preimages in the domain/action table. Their current execution paths remain
  disabled until their owners add rollback-independent current-resource and
  idempotent-effect gates.
- Roster rotation uses `governance.roster_rotate`, the predecessor scope/resource
  tuple, and the exact epoch-checkpoint successor preimage above.

Each consumer calls `verify_for_execution`, then advances its authoritative
resource head toward dispatch. Economic consumers bind the completed slot and
authorization in the same external state batch. A proof checked against only a
rollbackable local row is insufficient.

## Error handling

Unknown or unmapped suite, domain, action class, roster, participant, or schema;
missing, unavailable, behind, ahead or divergent epoch/slot anchor; inactive or expired epoch;
signature failure; noncanonical body; stale resource version or
fence; message mismatch; nonce-store or custody failure; coordinator ownership
loss; duplicate authorization use; incomplete rotation; and late old-epoch share
all reject. No path falls back to individual endorsements, an embedded public
key, a test signer, or an in-memory nonce.

## Testing

- Upstream official vectors plus Chio positive, tampered, wrong-domain,
  wrong-action, wrong-resource, stale-fence, stale-epoch, and expiry fixtures.
- Kill before and after slot binding, nonce persistence, commitment publication,
  share persistence, share return, aggregation, slot completion, and consumer
  resource-head advance.
- Retry every signer and coordinator message and prove byte-identical output;
  change one message byte and prove burn/reject with no second share.
- Run two coordinators against one session and prove only the active fence can
  progress it.
- Rotate during every session state; old sessions burn, historical verification
  remains valid, and old epochs cannot execute. Restore every pre-rotation SQLite
  snapshot against the advanced external checkpoint and prove signing and active
  verification deny.
- Restore a signer database without its custody generation and prove signing is
  unavailable rather than regenerated.
- Restore signer and coordinator snapshots within the same active epoch after a
  slot becomes bound, completed or burned. They resume only the exact bound
  message, fetch and return the externally retained completed authorization, or
  refuse; no conflicting commitment or share is produced. Restore a
  pre-aggregate coordinator snapshot after external completion and prove the
  result remains retrievable without re-signing.
- Verify every currently registered `n_of_m` ladder class has exactly one mapped
  domain/preimage fixture, every domain rejects another class, roster rotation
  binds its exact predecessor/successor checkpoint, and the reserved WS7 mapping
  remains disabled before its class registration.
- Verify a group signature never appears in APIs or claims as an exact signer
  subset.
- Run WS1, WS4 and WS5 consumer race/restore tests against their exact
  idempotent or externally anchored resource gates. WS7 runs its equivalent after
  Phase 3 registers the reserved action mapping.

## Implementation phases

1. Verifier contract (`chio/frost-p1-verifier-contract`). Add the upstream
   dependency, pure roster/authorization/domain types, active and historical
   resolvers, execution verifier, ladder vocabulary, schemas, registries,
   fixtures, and conformance negatives in `chio-federation`.
2. Durable signing (`chio/frost-p2-durable-signing`). Add DKG ceremony support,
   encrypted local signer sessions, durable coordinator sessions, ownership
   fencing, authenticated round transport, cancellation/burn, the external epoch
   checkpoint, and staged roster rotation through `chio-federation-authority`,
   `chio-store-sqlite`, and `chio-control-plane`.
3. Runtime qualification (`chio/frost-p3-runtime-qualification`). Qualify the P2
   rotation plus epoch/slot continuity implementation by running the crash,
   retry, multi-process, same-epoch restore, custody-restore, rotation, exhaustive
   registered-domain, and generic anchored-resource matrices. This phase gates
   WS1 Phase 4, WS4 Phase 4 and WS5 Phase 3. WS7 Phase 3 later adds and qualifies
   its disabled action mapping before panel execution.
