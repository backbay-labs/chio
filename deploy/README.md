# Chio sidecar deployment references

Reference deployment manifests for running the Chio kernel as a sidecar
alongside an application container on managed multi-container platforms.

All manifests assume the sidecar listens on `:9090` and exposes `GET /chio/health`.
The application talks to the kernel over `http://localhost:9090`.

See `docs/protocols/CLOUD-SIDECAR-INTEGRATION.md` for the architectural
rationale, the sidecar flag reference, and durable receipt-store options.

## Files

| Path | Purpose |
|------|---------|
| `cloud-run/service.yaml` | Google Cloud Run Knative-style multi-container service |
| `ecs/task-definition.json` | AWS ECS Fargate task definition (two containers, `dependsOn: HEALTHY`) |
| `azure/container-app.bicep` | Azure Container Apps Bicep template with startup/liveness probes |
| `sidecar/Dockerfile` | Multi-stage build producing a distroless nonroot Chio sidecar image |

## Placeholders

These manifests are reference infrastructure -- they are not deploy-ready.
Search and replace the following before applying:

| Placeholder | Meaning |
|-------------|---------|
| `APP_IMAGE_PLACEHOLDER` | Your application container image |
| `ghcr.io/backbay-labs/chio-sidecar:latest` | Chio sidecar image you have built and pushed |
| `PROJECT_ID`, `REGION` | GCP project and region (Cloud Run) |
| `ACCOUNT_ID` | AWS account ID (ECS) |
| `EFS_FILESYSTEM_ID` | ECS EFS filesystem holding the read-only spec/seed shares |
| `EFS_SEED_ACCESS_POINT_ID` | ECS EFS access point for the seed directory |
| Key Vault / Secret Manager ARNs | Pre-created secret references |

## Required secrets

Each manifest delivers the receipt-signing seed as a mounted secret file
(never inline), addressed by `--authority-seed-file`:

- authority signing seed -- the Ed25519 seed the kernel signs receipts with,
  mounted read-only at `/etc/chio/seed/authority.seed` from the platform secret
  store (Secret Manager on Cloud Run, an EFS access point on ECS, Key Vault on
  Azure Container Apps).

Non-secret configuration is passed as CLI flags to the sidecar subcommand
(`chio api protect`), not via environment variables:

- `--listen` -- bind address (default `127.0.0.1:9090`; the manifests bind `0.0.0.0:9090`); the health route is fixed at `/chio/health`
- `--upstream` -- the protected upstream base URL
- `--spec` -- the OpenAPI document the kernel derives its route and scope table from (the operator-provided spec, not the upstream)
- `--receipt-store` -- path to the SQLite audit log, on the read-write receipt volume (see durability caveats below)
- `--authority-seed-file` -- path to the secret-mounted signing seed

The kernel policy is derived from the OpenAPI spec plus these flags; there is no
separately mounted kernel or policy config file.

## Durable receipt store

`--receipt-store` opens a SQLite audit log in WAL mode. WAL coordinates readers
and writers through a shared-memory index that only works when every connection
is on the same host and a local (non-network) filesystem, so the store is a
single-writer, single-host database:

- Give the receipt database a **local (non-network) filesystem**, never a shared
  network filesystem. WAL is not safe over Filestore/NFS, Amazon EFS, or Azure
  Files; the sidecar fails closed at startup if the mounted filesystem cannot
  support WAL rather than run without durability.
- For a **durable** audit trail, give the database a per-instance disk. The ECS
  reference attaches a per-task block volume and expects `desiredCount: 1`. Two
  instances writing one receipt file corrupt it, so run exactly one writer per
  database.
- Cloud Run and Azure Container Apps have **no per-instance persistent disk**, so
  their references run the log on a local in-memory volume: WAL works, but the
  log is lost on every instance or revision recycle. For durable receipts on
  those platforms, front a client-server audit store or move to a per-instance
  disk platform (a StatefulSet PVC, or an ECS task with an attached block
  volume).

## Startup ordering

All three platforms enforce that the app container cannot serve traffic until
the sidecar is healthy:

- **Cloud Run** -- `run.googleapis.com/container-dependencies` annotation plus
  sidecar `startupProbe` on `:9090/chio/health`.
- **ECS Fargate** -- the app waits for the sidecar process to start, and the
  sidecar uses the mounted `/etc/chio/spec/openapi.yaml` plus its own
  `healthCheck` on `:9090/chio/health`. This avoids a startup deadlock where
  spec auto-discovery would need the app healthy before the sidecar could
  report healthy.
- **Azure Container Apps** -- sidecar `startupProbe` plus `readinessProbe` on
  `:9090/chio/health`; the app's own `startupProbe` ensures it does not report
  healthy until it can reach the sidecar.

## Fail-closed behaviour

If the sidecar cannot load its mounted OpenAPI spec or open its durable receipt
store, it exits non-zero. The platform then marks the container unhealthy (ECS,
Azure) or fails the revision (Cloud Run), which prevents the app container from
starting. The restart policies are configured to `always` so transient
failures recover automatically while permanent misconfigurations stay down.

## Quickstart

### Cloud Run

```bash
gcloud run services replace deploy/cloud-run/service.yaml --region us-central1
```

### ECS

```bash
aws ecs register-task-definition \
  --cli-input-json file://deploy/ecs/task-definition.json
```

### Azure Container Apps

```bash
az deployment group create \
  --resource-group my-rg \
  --template-file deploy/azure/container-app.bicep \
  --parameters \
      managedEnvironmentId=/subscriptions/.../managedEnvironments/my-env \
      userAssignedIdentityId=/subscriptions/.../userAssignedIdentities/chio-mi \
      chioAuthoritySeedSecretUri=https://my-kv.vault.azure.net/secrets/chio-authority-seed \
      specStorageName=chio-openapi-spec
```

### Sidecar image

```bash
docker build -f deploy/sidecar/Dockerfile -t ghcr.io/backbay-labs/chio-sidecar:latest .
docker push ghcr.io/backbay-labs/chio-sidecar:latest
```
