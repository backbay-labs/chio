# Chio Finding Market Status Runbook

This runbook covers the M6 venue-operated Finding status feed. It assumes the
single-operator cognition-market profile and the governance decision in
[ADR-0020](../adr/ADR-0020-finding-status-feed-governance.md).

The status feed is a consistency service with a bonded inclusion SLA. A fresh
signed root proves the keys that are in the sparse map and the absence paths it
authenticates. It does not prove that the operator included every eligible
intent. Alerting, signed intents, audit evidence, and the service bond cover
that remaining completeness assumption.

## Fixed protocol values

- Status domain: `chio.finding.status.v1`
- Numeric key-domain nonce: `3318287169837494`
  (`0x0bc9f6f00559b6`)
- Sparse-map depth: 256
- Epoch artifact: `chio.finding.status-epoch.v1`
- Portable proof input: `chio.finding.status-proof-input.v1`

Do not negotiate, relabel, or derive another nonce at runtime. A different
nonce or backend version is another protocol and must reject.

## Operator preflight

Before enabling a status-gated admission, verify all of the following:

1. Governance authorization names the exact stable feed id, operator key, key
   epoch, role, validity interval, rotation predecessor, and revocation state.
2. The configured service bond is live, allocated to that feed and operator,
   and covers the signed missed-inclusion and equivocation conditions.
3. The durable feed database contains its expected high-water floor and exact
   canonical signed epoch bytes. An established feed with a missing floor is
   not an empty feed. It is a fail-closed recovery incident.
4. The local status cache and retraction outbox are available and writable.
5. Anchoring credentials and the external operator cron identity are valid.

Do not enable the qualified profile when any check is unknown.

## Epoch cadence

The workspace does not run an implicit job daemon. Install an operator cron,
timer, or scheduler outside the process and give it a single-writer lease for
the configured feed.

Each cadence run performs this order:

1. Read the durable feed floor, the current canonical finalized anchor set,
   and bounded batches from `list_publication_candidates`,
   `list_non_inclusion_enrollment_candidates`, and
   `list_non_inclusion_refresh_candidates`. The batches include eligible
   pending intents, every active admitted Finding that has not received its
   first proof, published sticky leaves whose current-floor inclusion proof
   needs refresh, and live findings whose non-inclusion proof was displaced by
   an epoch advance or expired.
2. Call `epoch_refresh_required` with that finalized anchor set and the
   cadence's current trusted time. If it returns true and both bounded batches
   are empty, call `publish_epoch_refresh` with the same anchor set and a
   freshly captured trusted time. Then re-query both candidate lists before
   continuing. This root-only publication is mandatory when finalized anchors
   or epoch freshness change without unrelated point work; it advances the
   floor so displaced point proofs become visible to the ordinary refresh
   queries.
3. Confirm that an enforced intent's exact seller impairment is final. A bare
   outcome, bond hold, root publication, failed transaction, or ambiguous
   receipt is not eligible.
4. Insert every eligible key in one transactional sparse-map update.
5. Advance `map_epoch` exactly once, bind the finalized anchor set, sign the
   complete status epoch, and store its exact canonical bytes before making it
   current. When point work was already present, this ordinary publication
   also satisfies the refresh reported by `epoch_refresh_required`.
6. After the final floor advance, query
   `list_non_inclusion_refresh_candidates` again. Merge and deduplicate that
   result with the pre-advance batch, then generate and verify the portable
   inclusion proof for each inserted key and mint current-floor non-inclusion
   proofs for every resulting live refresh candidate before the cadence
   completes. The post-advance query is mandatory because the new epoch can
   displace proofs that were current when step 1 ran.
7. Record the signed epoch and proof against each outbox item, then clear its
   pending marker exactly once.
8. Leave failed items retryable. Quarantine conflicting identities or
   ambiguous finality instead of rewriting them.

There is no public HTTP route for advancing an epoch. HTTP surfaces serve only
the exact durable current epoch and proofs. Keep the publisher on the trusted
operator plane.

## Read and proof checks

The feature-gated control plane serves:

- `GET /v1/findings/status/{feed}/root`
- `GET /v1/findings/status/{feed}/proof/{finding_id}`

Both responses preserve the exact canonical epoch and proof bytes in bounded
base64 fields. Decode and verify them locally. Do not reconstruct signed bytes
from copied JSON fields.

Operators and buyers can perform that exact-byte verification through the CLI:

```bash
chio finding status \
  --id <finding-id> \
  --feed <governance-pinned-feed-id> \
  --operator-authorization <governance-pinned-authorization.json> \
  --service-bond <governance-pinned-current-service-bond.json> \
  --rollback-floor <durable-status-floor.json> \
  --max-epoch-age-secs <deployment-freshness-limit>
```

The command fetches the current proof from the configured control-plane URL,
verifies the proof and embedded signed epoch against the out-of-band operator
authorization, requires a canonical current service bond bound to that exact
feed and operator, requires the served projection to name that bond's exact
evidence digest, applies the configured freshness limit, cross-checks the
response projection, atomically advances the caller-selected durable rollback
floor, and prints the verified status. Reuse the same rollback-floor path for
every query against that feed and stable operator identity. Sticky per-finding
retractions are stored under the sibling `<rollback-floor>.retractions/`
directory, which must be retained and backed up with the floor file. A
transport, canonicalization, signature, lifecycle, digest, feed, finding,
epoch, or sparse-path failure exits nonzero.

The first verified observation against a version-one rollback floor migrates
its epoch tuple to version two and writes every retained retraction id into the
sibling tombstone directory while holding the floor lock. Tombstones are
written before the version-two floor replacement, so an interrupted migration
fails closed and resumes idempotently on the next verified observation.

The standard proof verifier routes `claim.finding.*` bundles through the
cognition-market verifier. Configure its trust inputs out of band before
running `chio proof verify <transaction-passport.json>`:

```bash
export CHIO_TRANSACTION_TRUSTED_ROOT_KEYS=<passport-root-public-key>
export CHIO_FINDING_PROFILE_GOVERNANCE_AUTHORITY_KEY=<profile-governance-public-key>
export CHIO_FINDING_PROFILE_GOVERNANCE_AUTHORITY_POLICY_PATH=<canonical-profile-governance-policy.json>
export CHIO_FINDING_PROFILE_GOVERNANCE_AUTHORITY_STATUS_PATH=<canonical-signed-governance-status.json>
export CHIO_FINDING_VERIFIER_AUTHORITY_KEY=<finding-verifier-public-key>
export CHIO_FINDING_PURCHASE_AUTHORITY_KEY=<purchase-record-public-key>
export CHIO_FINDING_PURCHASE_AUTHORITY_STATUS_PATH=<canonical-signed-purchase-authority-status.json>
export CHIO_FINDING_VERIFIER_AUTHORITY_STATUS_PATH=<canonical-signed-authority-status.json>
export CHIO_FINDING_VERIFIER_STATUS_AUTHORITY_POLICY_PATH=<canonical-authority-status-signer-policy.json>
export CHIO_FINDING_VERIFIER_AUTHORITY_STATUS_CHECKED_AT=<trusted-verification-time>
export CHIO_FINDING_VERIFIER_AUTHORITY_STATUS_MAX_AGE_SECONDS=<deployment-freshness-limit>
export CHIO_FINDING_VERIFIER_PROFILE_ENVELOPE_SHA256=<approved-profile-envelope-digest>
export CHIO_FINDING_VERIFIER_PROFILE_PATH=<canonical-signed-verifier-profile.json>
export CHIO_FINDING_TRUST_ROOT_SNAPSHOT_SHA256=<approved-trust-root-snapshot-digest>
export CHIO_FINDING_RESOLVER_POLICY_SHA256=<approved-resolver-policy-digest>
export CHIO_FINDING_TRUSTED_TIME_INPUT_SHA256=<approved-trusted-time-input-digest>
export CHIO_FINDING_STATUS_OPERATOR_AUTHORIZATION_PATH=<canonical-signed-authorization-envelope.json>
export CHIO_FINDING_STATUS_OPERATOR_AUTHORIZATION_SHA256=<signed-authorization-envelope-digest>
export CHIO_FINDING_STATUS_OPERATOR_AUTHORITY_STATUS_PATH=<canonical-signed-operator-status.json>
export CHIO_FINDING_STATUS_AUTHORITY_DATABASE_PATH=<provisioned-authority.db>
export CHIO_FINDING_STATUS_AUTHORITY_LOCK_ROOT=<secure-authority-lock-directory>
export CHIO_FINDING_STATUS_NOW_UNIX_SECONDS=<trusted-verification-time>
export CHIO_FINDING_STATUS_MAX_AGE_SECONDS=<deployment-freshness-limit>
```

The signed profile is the source of the report signer policy and required
facet floor. Its governance signer must equal both the separately pinned
profile-governance key and policy, and its report signer must equal the
separately pinned verifier key. The verifier loads the profile's exact
canonical bytes, requires their digest to match the out-of-band profile pin,
and verifies the profile signature and lifecycle. It also requires fresh
signed status witnesses for the profile-governance signer, report signer,
purchase-record signer, and status operator from the separately pinned
status-authority policy, requires
that policy to cover each witness observation and the shared current trusted
verification time, and rejects newly backdated artifacts after any key is
revoked or expires. The report must bind the
deployment-pinned trust-root snapshot, resolver policy, and trusted-time
input. Verification fails closed when any profile floor, snapshot commitment,
pin, authorization, durable authority store, trusted time, or freshness limit
is missing or malformed. A delivery-bound claim also requires a purchase
record under the separately pinned purchase authority, within that authority's
lifecycle, and with fresh non-revoked standing. Its exact sale identity must
match the verifier-signed delivery overlay carried by the report.
Provision the authority database and secure lock directory before verification
and reuse them for every bundle from that feed and stable operator identity.
The store advances the signed epoch high-water mark and retains sticky
retraction state before a status-fresh claim can be granted. None of these
trust inputs are derived from the proof bundle.

At minimum, monitoring checks:

- outer signature and governance-pinned operator authorization;
- feed id, fixed nonce, map epoch, backend version, proof version, and root;
- epoch id and digest of the exact signed bytes;
- generated, valid-from, valid-until, and local checked-at bounds;
- 256-level sparse path for the exact Finding id;
- durable high-water floor and same-epoch identity;
- sticky local pending or retracted state;
- current service-bond validity.

A lower epoch, same-epoch different id or root, unsigned answer, resolver
substitution, stale proof, or missing local floor must alert and deny.

## Anchoring cadence

Status publication and external anchoring have separate cadences. The epoch
artifact records its anchor references, but the status worker must not claim an
anchor that is not finalized.

- Publish signed epochs at the status SLA cadence.
- Submit epoch commitments to the configured anchor lane at the anchoring
  cadence.
- Record the finalized anchor reference in a later signed epoch when required
  by policy.
- Alert when an epoch remains unanchored beyond the configured bound.

An anchor failure does not authorize a rollback or a second identity at the
same map epoch.

## Stalled outbox response

For a Finding that remains `publication_pending`, inspect the stages in order:

1. Confirm the liability is `Finalizing`, not appealed, reversed, or merely
   evaluated.
2. Confirm the seller-impair intent and enforcement-root intent are the exact
   identities bound by the signed enforcement artifact.
3. Confirm the impairment receipt is final and unambiguous under the pinned
   chain-finality policy.
4. Confirm the retraction intent is still the original durable item and has not
   been replaced under its key.
5. Confirm the status operator authorization, service bond, signing key, feed
   floor, and sparse-map store are available.
6. Retry the same item. Never mint a replacement intent to bypass a conflict.

Purchases remain denied for the entire investigation. If impairment is failed,
ambiguous, or quarantined, keep retraction dispatch-ineligible. If insertion
succeeded but acknowledgement failed, recover the stored signed epoch and
inclusion proof and reconcile without another map update.

## Equivocation response

Equivocation is any second epoch id or root for an already observed map epoch.

1. Freeze status publication and status-gated purchases for the feed.
2. Preserve both exact signed byte sequences, authorization snapshots, anchor
   references, and observation times.
3. Open the objective service-bond penalty path for equivocation.
4. Audit every buyer and kernel floor for the conflicting epoch.
5. Rotate the operator only through the governance-signed rotation policy.
6. Resume with a strictly greater map epoch and the same feed id, fixed nonce,
   and complete retracted-key set.

Never choose one conflicting root by local timestamp and never reset the epoch
to zero.

## Missed inclusion and voluntary retraction

A voluntary or cross-operator retraction begins with an authenticated signed
intent and its SLA deadline. Record it as sticky pending immediately so a fresh
root that omits it cannot authorize another sale.

When the deadline expires without a verified inclusion proof:

1. Keep the Finding pending and purchases denied.
2. Preserve the signed intent, every intervening signed epoch, and proof
   response.
3. Page the status operator and open the objective missed-inclusion bond path.
4. Insert and publish through the ordinary idempotent worker. Do not use a
   special root or an unsigned repair response.

Clear pending only after the exact intent has a verified inclusion proof in a
signed epoch. A later non-inclusion proof never clears pending or retracted
state.

## Restart and disaster recovery

On restart, load and verify the durable feed floor, exact current signed epoch,
sparse leaves, sticky status rows, and outbox before serving proofs or allowing
purchases. If any required state is missing or inconsistent, keep the feed
unavailable and deny status-gated reads and purchases.

Restore from a backup only when it contains at least the last externally
observed map epoch. Replay retained signed epochs and inclusion evidence into
the local cache, then verify the sparse root before reopening. A backup with a
lower floor is not safe to serve even when its epoch is still within its
validity window.

## Required alerts

- epoch publication misses its cadence;
- an established feed starts without a floor;
- lower-epoch replay or same-epoch equivocation;
- authorization, key epoch, rotation, or revocation mismatch;
- service bond missing, expired, revoked, or below its allocation;
- pending intent exceeds its inclusion SLA;
- outbox retry count or age exceeds the operator threshold;
- impairment remains ambiguous or quarantined;
- status cache is stale or unavailable;
- anchor finalization exceeds its configured cadence;
- resolver identity, feed, lineage, or provenance substitution.

Every alert keeps the affected qualified operation fail-closed until the exact
durable evidence is reconciled.
