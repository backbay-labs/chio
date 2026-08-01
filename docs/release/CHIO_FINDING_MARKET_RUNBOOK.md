# Chio Finding Market Status Runbook

This runbook covers the M6 venue-operated Finding status feed. It assumes the
single-operator cognition-market profile and the governance decision in
[ADR-0019](../adr/ADR-0019-finding-status-feed-governance.md).

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

Before enabling an M6-qualified admission, verify all of the following:

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

1. Read the durable feed floor and all eligible pending intents.
2. Confirm that an enforced intent's exact seller impairment is final. A bare
   outcome, bond hold, root publication, failed transaction, or ambiguous
   receipt is not eligible.
3. Insert every eligible key in one transactional sparse-map update.
4. Advance `map_epoch` exactly once, sign the complete status epoch, and store
   its exact canonical bytes before making it current.
5. Generate and verify the portable inclusion proof for each inserted key.
6. Record the signed epoch and proof against each outbox item, then clear its
   pending marker exactly once.
7. Leave failed items retryable. Quarantine conflicting identities or
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
chio finding status --id <finding-id> --feed <governance-pinned-feed-id>
```

The command fetches the current proof from the configured control-plane URL,
verifies the proof and embedded signed epoch locally, cross-checks the response
projection, and prints the verified status. A transport, canonicalization,
signature, digest, feed, finding, epoch, or sparse-path failure exits nonzero.

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

1. Freeze status publication and M6-qualified purchases for the feed.
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
unavailable and deny M6-qualified reads and purchases.

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
