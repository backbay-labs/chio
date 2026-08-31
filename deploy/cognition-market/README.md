# Cognition Market Deployment Contract

This directory deploys the hosted market in the approved hybrid topology:

- Kubernetes runs stateless `chio-finding-market-server` replicas and an
  authenticated TLS proxy sidecar.
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
  --output /tmp/chio-cognition-market.yaml
```

Before applying the Deployment:

1. Apply only the rendered migration Job and its migration NetworkPolicy, then
   require successful completion. Do not start the new Deployment revision
   before the Job exits successfully. Runtime startup also verifies the exact
   embedded migration ledger and fails closed on drift.
2. Provision `chio-finding-market-profile`, `chio-finding-market-runtime`,
   `chio-finding-market-proxy`, and `chio-finding-market-tls` Secrets through
   the existing secret controller. The profile is canonical JSON with mode
   `trusted_proxy`, listener `127.0.0.1:8080`, trusted peer `127.0.0.1`, and the
   rendered public endpoint.
3. Provision the PostgreSQL CA ConfigMap and enforce separate non-superuser
   migration, runtime, and worker database roles.
4. Label only the approved ingress controller, PostgreSQL, and HTTPS egress
   gateway pods and namespaces with the exact `chio.world/market-*` selectors
   in the two NetworkPolicies, then apply the remaining objects. Direct
   arbitrary Internet egress is not admitted. The rolling update keeps the
   previous ReplicaSet for rollback and never makes the canary a public-traffic
   claim.
5. Dispatch `Cognition market dark network canary` on the exact default-branch
   commit. The environment must point to private canonical profile and Finding
   files on the attested ephemeral runner. Promote only through the signed
   qualification and canary-decision process.

Rollback changes the Deployment image digest back to the last qualified
ReplicaSet and re-runs readiness and the dark network canary. Migrations are
additive and are not rolled back in place. A failed or incompatible migration
blocks the new server at startup while the previous ready ReplicaSet remains
available.

The proxy token, API-key pepper, database URLs, TLS private key, and network
canary credentials are secret values. They must never enter these manifests,
Git, command arguments, or qualification logs. The proxy token must be 43 to
128 base64url characters; use at least 32 random bytes and omit base64 padding.
