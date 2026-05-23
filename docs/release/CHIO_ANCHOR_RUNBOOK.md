# Chio Anchor Operator Runbook

## Purpose

This runbook covers the supported operator actions for the shipped
`chio-anchor` runtime originally tracked under internal milestone `v2.36`.

> Version posture: this is a pre-release operator runbook. Internal `v2.x`
> milestone labels are historical planning labels, not Chio-owned protocol,
> schema, SDK, or runtime versions. Current protocol posture is v1-only.

`chio-anchor` is the bounded checkpoint-anchoring surface. It does not release
funds, automate jobs, or widen trust from discovery visibility alone.

## Routine Checks

Before enabling a live anchoring lane for an operator deployment:

1. Review the discovery and ownership artifact in
   `docs/standards/CHIO_ANCHOR_DISCOVERY_EXAMPLE.json`.
2. Confirm the operator binding certificate still covers `anchor` purpose and
   the intended chain scope.
3. Confirm each EVM lane has the intended operator address, publisher address,
   and canonical root-registry contract address.
4. If Bitcoin secondary anchoring is enabled, confirm the configured
   OpenTimestamps calendar list and expected checkpoint aggregation window.
5. If Solana memo publication is enabled, confirm the intended cluster and the
   operator memo-signing key.
6. Run the local qualification commands:
   - `CARGO_TARGET_DIR=target/chio-anchor-verify CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p chio-anchor -- --test-threads=1`
   - `pnpm --dir contracts devnet:smoke`

## EVM Publication

Use the EVM lane as the primary anchor path.

Expected behavior:

- publication readiness checks surface the latest checkpoint sequence and
  whether the current publisher is authorized
- checkpoint publication fails closed if the next sequence would replay or if
  the publisher is not authorized
- confirmation re-reads the stored root entry and rejects metadata drift

Recovery:

1. If the publisher is unauthorized, fix the operator or delegate binding on
   the root registry before retrying.
2. If the checkpoint sequence is stale, reconcile local checkpoint progression
   against the latest on-chain sequence and publish only the next valid root.
3. If confirmation mismatches the checkpoint metadata, treat the lane as
   suspect and stop publication until operator identity and chain state are
   reconciled.

## Bitcoin Secondary Lane

Use the Bitcoin lane only as secondary evidence over one or more already
prepared checkpoints.

Expected behavior:

- Chio aggregates contiguous checkpoints into one super-root
- Chio derives one SHA-256 document digest for OpenTimestamps submission
- imported `.ots` payloads are accepted only if they decode, match that
  document digest, and contain a Bitcoin attestation

Recovery:

1. If the OTS payload is still pending-only, keep the lane informational and
   wait for a Bitcoin attestation before attaching it to a proof bundle.
2. If the OTS payload decodes but points at the wrong digest, reject it and
   regenerate from the correct super-root.
3. If calendar availability is degraded, retain the local submission artifact
   and retry external submission rather than mutating the checkpoint truth.

## Solana Memo Lane

Use the Solana lane only with the built-in Memo program.

Expected behavior:

- Chio emits one canonical memo payload for each anchored checkpoint
- imported memo records are accepted only if the memo program id, memo data,
  checkpoint sequence, and merkle root all match the primary proof

Recovery:

1. If the memo record references the wrong program or wrong payload, reject it
   and re-publish with the canonical memo encoding.
2. If the record matches the payload but the wrong checkpoint sequence, treat
   it as unrelated evidence rather than a partial success.

## Independent Verification

Independent verifier coverage is complete when:

- the primary EVM proof verifies against canonical Chio receipt and checkpoint
  truth
- the imported Bitcoin lane points at the expected Chio super-root digest and a
  Bitcoin attestation
- the imported Solana lane matches the canonical memo payload exactly
- the shared proof bundle does not declare any lane that is absent or
  inconsistent, and does not carry undeclared secondary evidence

If any of those checks fail, Chio should continue failing closed for the
affected lane.

## Compliance And Ownership Notes

- The operator's `did:chio` identity remains the root discovery and ownership
  anchor.
- Delegate publishers do not become the owner of a checkpoint root; they only
  exercise bounded publication authority granted by the operator on the root
  registry.
- Bitcoin and Solana lanes are secondary evidence surfaces and do not replace
  the primary EVM lane for Chio proof ownership.
