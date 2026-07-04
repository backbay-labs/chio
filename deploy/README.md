# Chio sidecar deployment references

Reference deployment manifests for running the Chio kernel as a sidecar
alongside an application container on managed multi-container platforms.

All manifests assume the sidecar listens on `:9090` and exposes `GET /chio/health`.
The application talks to the kernel over `http://localhost:9090`.

See `docs/protocols/CLOUD-SIDECAR-INTEGRATION.md` for the architectural
rationale, env var catalogue, and receipt-sink options.

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
| `EFS_FILESYSTEM_ID` | ECS EFS volume containing `/chio-config/kernel.yaml` and `/chio-config/spec/openapi.yaml` |
| Key Vault / Secret Manager ARNs | Pre-created secret references |

## Required secrets

Each manifest wires the following as secret references (never inline):

- `CHIO_SIGNING_KEY` -- Ed25519 signing key for receipts
- `CHIO_CAPABILITY_AUTHORITY_URL` -- URL of the capability authority

Non-secret configuration is passed as CLI flags to the sidecar subcommand
(`chio api protect`), not via environment variables:

- `--listen` -- bind address (default `127.0.0.1:9090`; the manifests bind `0.0.0.0:9090`); the health route is fixed at `/chio/health`
- `--upstream` -- the protected upstream base URL
- `--spec` -- the OpenAPI spec used to derive tool scopes
- `--receipt-store` -- receipt destination

Kernel and policy configuration is loaded from a mounted `chio.yaml`, which may
reference secrets via `${VAR}` interpolation (see the manifests for the exact flags).

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

If the sidecar cannot load its mounted `chio.yaml` or the policy bundle, it
exits non-zero. The platform then marks the container unhealthy (ECS, Azure)
or fails the revision (Cloud Run), which prevents the app container from
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
      chioSigningKeySecretUri=https://my-kv.vault.azure.net/secrets/chio-signing-key \
      chioCapabilityAuthoritySecretUri=https://my-kv.vault.azure.net/secrets/chio-cap-authority-url
```

### Sidecar image

```bash
docker build -f deploy/sidecar/Dockerfile -t ghcr.io/backbay-labs/chio-sidecar:latest .
docker push ghcr.io/backbay-labs/chio-sidecar:latest
```
