# ADR-0020: Finding Status Feed Governance

- Status: Accepted
- Decision owner: cognition-market venue and trust-control lane
- Related: ADR-0017, ADR-0018, `docs/market/ARCHITECTURE.md` section 4.4
- Implements: cognition-market roadmap decision ADR-B

## Context

A Finding can be sold only while its admission-pinned status feed proves that
the exact Finding key is absent. M5 also creates a durable retraction intent
after an appeal-final enforcement decision, but it deliberately cannot publish
that intent until the seller impairment is final. The existing revocation
oracle cannot close this gap. Its append-only Merkle root and local
`NonInclusionProof` do not provide a portable proof of absence, and its signed
root does not bind a status feed or sparse-map proof semantics.

The status boundary therefore needs an independently signed artifact, a true
sparse authenticated map, a durable rollback floor, and an operational rule
for insert completeness. A fresh root proves consistency with its included
keys. It does not prove that an operator included every eligible intent.

## Decision

### 1. Feed ownership and authorization

The qualified M6 profile is venue-operated. Governance authorizes one status
operator for each stable `feed_id` and pins its role, public key, key epoch,
validity interval, rotation chain, and revocation state. Verification requires
the outer status-epoch signer and any nested signer to resolve to that same
authorization. An embedded or caller-selected key cannot authorize itself.

Key rotation preserves the feed identity, sparse-map semantics, fixed key
domain, and durable map-epoch floor. Rotation never resets the map or makes a
previously observed retraction live.

### 2. Fixed key domain and sparse-map semantics

The `chio.finding.status.v1` protocol selects numeric `key_domain_nonce`
`3318287169837494` (`0x0bc9f6f00559b6`). This is the first 53 bits, in network
bit order, of SHA-256 over the UTF-8 protocol-domain label. Selecting a value
below `2^53` preserves exact I-JSON and RFC 8785 interoperability. The number is
a selected wire constant. Implementations compare it to the constant and do
not derive or negotiate it at runtime.

The status backend is a 256-bit sparse authenticated map with versioned,
domain-separated key, empty-leaf, occupied-leaf, and branch hashes. The key
path is derived from the Finding id and fixed numeric nonce. A portable proof
carries the complete fixed-depth sibling path needed to recompute the signed
root. Non-inclusion proves that the exact key path terminates in the defined
empty leaf. The append-only revocation tree and its local absence query are a
different backend and always reject under the status verifier.

`map_epoch` is an independent monotonically advancing root-generation counter.
It never changes a Finding's key. The signed `chio.finding.status-epoch.v1`
artifact binds the feed, fixed nonce, map epoch, operator authorization,
backend and proof-semantics versions, sparse root parameters, root, anchoring
references, and validity interval. Exact RFC 8785 canonical signed artifact
bytes are the authority presented to a verifier or returned by an
authenticated resolver.

### 3. Rollback, equivocation, and sticky state

Every kernel and buyer that accepts a proof durably stores the high-water
`(map_epoch, epoch_id, root_hash)` tuple for the admission-pinned feed and
operator authorization. A lower epoch rejects. The same epoch with a different
artifact id or root rejects as equivocation. An absent floor after a restart
rejects when the deployment declares an established feed.

Local `pending` and `retracted` observations are sticky. A non-inclusion proof,
whether older or newer, cannot clear either state. Only verified exact signed
epoch bytes from the pinned operator, obtained directly or through an
authenticated pinned resolver, may advance the floor.

### 4. Publication completeness and finality

The appeal-final M5 transition atomically persists its outcome,
`publication_pending`, and one idempotent retraction outbox item before any
external effect. Pending status denies new sales. The item remains
dispatch-ineligible until the exact seller impairment is confirmed final.

After finality, the status worker retries the exact sparse-map insert. It
records the returned signed epoch and portable inclusion proof before clearing
pending. The liability reaches `Settled` only after this publication and every
other required effect are confirmed. Failed, ambiguous, or quarantined
impairment never publishes an irreversible retraction.

Voluntary and cross-operator requests carry an authenticated retraction-intent
receipt and a bounded inclusion SLA. A fresh root that omits a known pending
intent is censorship and remains denied.

### 5. Bond and operations

A qualified operator maintains a live service bond allocated to this feed.
The signed bond policy identifies objective missed-inclusion and equivocation
conditions, the inclusion SLA, evidence source, and penalty path. Admission
rejects a missing, expired, revoked, underfunded, or differently allocated
bond.

Operators publish epochs from an external cron or equivalent operator job.
The workspace does not gain an implicit job daemon. Anchoring cadence and
status cadence are separately configured and monitored.

## Consequences

- Portable inclusion and non-inclusion checks no longer depend on local oracle
  membership state.
- Exact canonical signed epoch bytes, not copied root fields, advance trust.
- Rollback and equivocation become durable protocol failures rather than cache
  hints.
- M5 incidents remain blocked until retraction publication completes after
  impairment finality.
- Operator completeness remains an explicit audited assumption, narrowed by a
  signed intent, inclusion SLA, alerts, and a slashable service bond.
- The default non-market memory profile remains unchanged. The retraction
  resolver is an opt-in fail-closed guard profile.
