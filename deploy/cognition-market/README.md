# Cognition Market Deployment Contract

This directory deploys the hosted market in the approved hybrid topology:

- Kubernetes runs stateless `chio-finding-market-server` replicas, an
  authenticated TLS proxy sidecar, and a least-privilege replication-freshness
  writer. An init check establishes the first freshness fence before the edge
  starts, and the sidecar refreshes it every ten seconds.
- A dedicated migration Job owns schema changes. Runtime pods do not receive
  migration credentials.
- Dedicated Linux KVM hosts run `chio-finding-worker` under systemd. SQLite is
  not mounted or admitted in either production role.

Render the templates with the reviewed release image digests and public DNS
name. The renderer rejects tags, mutable image references, malformed digests,
and non-HTTPS host syntax.

```bash
python3 deploy/cognition-market/render.py \
  --chio-image ghcr.io/bb-connor/arc \
  --chio-digest "$CHIO_IMAGE_SHA256" \
  --proxy-image docker.io/library/nginx \
  --proxy-digest "$NGINX_IMAGE_SHA256" \
  --public-host market.example.com \
  --candidate-sha "$CHIO_CANDIDATE_SHA" \
  --output /tmp/chio-cognition-market.yaml
```

Before applying the Deployment:

1. Apply only the rendered migration Job and its migration NetworkPolicy, then
   require successful completion. Do not start the new Deployment revision
   before the Job exits successfully. Runtime startup also verifies the exact
   embedded migration ledger and fails closed on drift.
2. Provision `chio-finding-market-profile`, `chio-finding-market-runtime`,
   `chio-finding-market-replicator`, `chio-finding-market-proxy`, and
   `chio-finding-market-tls` Secrets through
   the existing secret controller. The profile is canonical JSON with mode
   `trusted_proxy`, listener `127.0.0.1:8080`, trusted peer `127.0.0.1`, and the
   rendered public endpoint.
3. Provision the PostgreSQL CA ConfigMap and enforce separate non-superuser
   migration, runtime, replicator, and worker database roles. The replicator
   Secret exposes only the profile-named replicator database URL and the
   profile-named AuthorityStatus remote-signer token. The runtime container
   must not receive either value.
4. Label only the approved ingress controller, PostgreSQL, and HTTPS egress
   gateway pods and namespaces with the exact `chio.world/market-*` selectors
   in the two NetworkPolicies, then apply the remaining objects. Direct
   arbitrary Internet egress is not admitted. The rolling update keeps the
   previous ReplicaSet for rollback and never makes the canary a public-traffic
   claim.
5. Dispatch `Cognition market dark network canary` on the exact default-branch
   commit. The environment must point to a private canonical profile and a
   private canonical canary-pool manifest on the attested ephemeral runner.
   The pool contains 2 to 128 absolute paths to active signed Findings from
   one issuer. Each attempt selects an unused Finding, requires its run-bound
   first publication to be applied, and permits only its immediate retry to be
   an exact replay. Replenish the pool before it is exhausted. Promote only
   through the signed qualification and canary-decision process.

Rollback changes the Deployment image digest back to the last qualified
ReplicaSet and re-runs readiness and the dark network canary. Migrations are
additive and are not rolled back in place. A failed or incompatible migration
blocks the new server at startup while the previous ready ReplicaSet remains
available.

The profile release block must bind the exact 40-character candidate commit,
artifact digest, and configuration revision. The renderer injects that
candidate and the pinned Chio image digest into the market process, which
fails closed unless both match the profile and serves the bound identity from
the authenticated release endpoint. Buyer canary credentials must allow
`finding.release.read` in addition to the catalog actions so the network
canary can verify the deployed identity before publishing.
The dark-canary environment must also configure
`CHIO_FINDING_NETWORK_ISOLATION_TENANT_ID`,
`CHIO_FINDING_NETWORK_ISOLATION_BUYER_KEY_ID`, and
`CHIO_FINDING_NETWORK_ISOLATION_BUYER_KEY_SECRET` for a distinct enabled
API-key tenant. Those credentials must differ from the publishing tenant's
buyer credentials. The canary authenticates as that second tenant and requires
the first tenant's Finding lookup to return `404`, which exercises the backend
tenant boundary rather than stopping at authentication.

Migration `0016_authenticated_delivery_receipt.sql` intentionally refuses to
upgrade a database that retains the legacy unsigned hosted delivery contract.
Before deploying this revision, export and quarantine any legacy delivery
events, projections, replication records, and rollback outbox entries through
the approved retention procedure. Those records cannot be converted into
kernel-authenticated receipts after issuance.

`CHIO_FINDING_NETWORK_CANARY_POOL` names the manifest, not an individual
Finding. It is canonical JSON with schema
`chio.finding.network-canary-pool.v1` and a `findingPaths` array. The manifest
and every referenced Finding must be absolute, private, regular files owned by
the canary process. Duplicate paths, duplicate Finding IDs, mixed issuers,
inactive Findings, symlinks, and pools outside the 2 to 128 entry bound reject
before any network mutation.

Every principal admitted to submit signed artifacts must carry its signer key
in `capabilityPublicKeyHex`, including principals that authenticate by API key.
The replicated principal record is the authenticated signer pin; a request
cannot select a different artifact signer.

The proxy token, remote-signer tokens, API-key pepper, database URLs, TLS
private key, and network canary credentials are secret values. They must never
enter these manifests, Git, command arguments, or qualification logs. The
proxy token must be 43 to 128 base64url characters; use at least 32 random
bytes and omit base64 padding.
