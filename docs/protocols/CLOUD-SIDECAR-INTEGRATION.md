# Cloud Run / ECS Sidecar Integration: Managed Container Deployment

> **Status**: Tier 3 -- proposed April 2026
> **Priority**: Exploratory -- Cloud Run and ECS natively support sidecar
> containers, making them the easiest managed container platforms to deploy
> Chio on. This is a reference deployment pattern more than a new SDK.

## 1. Why Cloud Run and ECS

Chio's sidecar model -- kernel running alongside the application on the same
host, communicating over localhost -- maps directly to how Cloud Run and ECS
handle multi-container tasks. Unlike Lambda (which needs Extensions) or
Kubernetes (which needs admission webhooks), these platforms have first-class
sidecar support with no custom infrastructure.

This document defines reference deployment patterns, not new libraries.
The existing SDKs (`chio-sdk-python`, `@chio-protocol/node-http`,
`chio-go-http`, etc.) work as-is when the sidecar is co-deployed.

### Platform Comparison

| Feature | Cloud Run (GCP) | ECS (AWS) | Azure Container Apps |
|---------|----------------|-----------|---------------------|
| Sidecar support | Multi-container services (GA) | Task Definition with multiple containers | Sidecar containers (GA) |
| Shared localhost | Yes (containers share network namespace) | Yes (within same task) | Yes (within same revision) |
| Startup ordering | Container dependency graph | `dependsOn` with health checks | Startup probes |
| Scaling | Per-request (scales to zero) | Task-based or service-based | Per-request or always-on |
| Min instances | Configurable (0+) | Desired count (0+ with Fargate) | Min replicas (0+) |
| Cold start | Container pull + startup | Container pull + startup | Container pull + startup |

## 2. Architecture

All three platforms follow the same pattern:

```
Managed Container Platform
+-----------------------------------------------------------+
|  Service / Task / Revision                                |
|                                                           |
|  +---------------------+    +---------------------------+ |
|  | Application         |    | Chio Sidecar               | |
|  | Container           |    | Container                 | |
|  |                     |    |                           | |
|  | app --HTTP-->       |--->| :9090 (localhost)         | |
|  |   chio.evaluate()    |    | Capability | Guard | Rcpt | |
|  |   ... do work ...   |    |                           | |
|  |   chio.record()      |    | Startup: load policy      | |
|  +---------------------+    | Shutdown: flush receipts  | |
|                              +---------------------------+ |
|                                                           |
|  Shared: network namespace, localhost, optional volumes    |
+-----------------------------------------------------------+
```

## 3. Google Cloud Run

### 3.1 Service Definition

```yaml
# cloud-run-service.yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: agent-tool-server
  annotations:
    run.googleapis.com/launch-stage: GA
spec:
  template:
    metadata:
      annotations:
        # Keep 1 instance warm; pin to 1 so a single instance keeps one
        # coherent in-memory audit stream. Cloud Run has no per-instance
        # persistent disk, so this reference runs an ephemeral audit log
        # (see section 7 for the durable-platform options).
        autoscaling.knative.dev/minScale: "1"
        autoscaling.knative.dev/maxScale: "1"
        # Container startup ordering
        run.googleapis.com/container-dependencies: '{"app":["chio-sidecar"]}'
    spec:
      containers:
        # Application container
        - name: app
          image: gcr.io/my-project/agent-tool-server:latest
          ports:
            - containerPort: 8080
          env:
            - name: CHIO_SIDECAR_URL
              value: "http://localhost:9090"
          resources:
            limits:
              cpu: "1"
              memory: 512Mi

        # Chio sidecar container
        - name: chio-sidecar
          image: gcr.io/my-project/chio-sidecar:latest
          ports:
            - containerPort: 9090
          # Routes and scopes derive from the operator-provided OpenAPI spec;
          # the signing seed is read from a mounted secret file. Cloud Run has
          # no per-instance persistent disk, so the audit log cannot be durable
          # here: opt into ephemeral in-memory receipts explicitly rather than
          # pointing --receipt-store at scratch storage, which would boot
          # reporting a durable backend yet lose every receipt on revision
          # recycle. See section 7 for a durable audit trail.
          args:
            - "api"
            - "protect"
            - "--upstream"
            - "http://127.0.0.1:8080"
            - "--spec"
            - "/etc/chio/spec/openapi.yaml"
            - "--listen"
            - "0.0.0.0:9090"
            - "--allow-ephemeral-receipts"
            - "--authority-seed-file"
            - "/etc/chio/seed/authority.seed"
          startupProbe:
            httpGet:
              path: /chio/health
              port: 9090
            initialDelaySeconds: 1
            periodSeconds: 1
            failureThreshold: 10
          resources:
            limits:
              cpu: "0.25"
              memory: 64Mi
```

### 3.2 Deploy with gcloud

```bash
# Deploy the multi-container service
gcloud run services replace cloud-run-service.yaml \
  --region us-central1

# Or using gcloud CLI directly
gcloud run deploy agent-tool-server \
  --image gcr.io/my-project/agent-tool-server:latest \
  --add-sidecar=chio-sidecar,image=gcr.io/my-project/chio-sidecar:latest,port=9090 \
  --region us-central1
```

### 3.3 Cloud Run Jobs

Cloud Run Jobs (batch workloads) follow the same pattern:

```yaml
apiVersion: run.googleapis.com/v1
kind: Job
metadata:
  name: agent-batch-job
spec:
  template:
    spec:
      containers:
        - name: worker
          image: gcr.io/my-project/batch-worker:latest
          env:
            - name: CHIO_SIDECAR_URL
              value: "http://localhost:9090"
        - name: chio-sidecar
          image: gcr.io/my-project/chio-sidecar:latest
```

## 4. AWS ECS (Fargate)

### 4.1 Task Definition

```json
{
  "family": "agent-tool-server",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "containerDefinitions": [
    {
      "name": "app",
      "image": "123456789.dkr.ecr.us-east-1.amazonaws.com/agent-tool-server:latest",
      "portMappings": [
        { "containerPort": 8080, "protocol": "tcp" }
      ],
      "environment": [
        { "name": "CHIO_SIDECAR_URL", "value": "http://localhost:9090" }
      ],
      "dependsOn": [
        { "containerName": "chio-sidecar", "condition": "HEALTHY" }
      ],
      "essential": true,
      "cpu": 384,
      "memory": 896
    },
    {
      "name": "chio-sidecar",
      "image": "123456789.dkr.ecr.us-east-1.amazonaws.com/chio-sidecar:latest",
      "portMappings": [
        { "containerPort": 9090, "protocol": "tcp" }
      ],
      "command": [
        "api",
        "protect",
        "--upstream",
        "http://127.0.0.1:8080",
        "--spec",
        "/etc/chio/spec/openapi.yaml",
        "--listen",
        "0.0.0.0:9090",
        "--receipt-store",
        "/var/lib/chio/receipts.db",
        "--authority-seed-file",
        "/etc/chio/seed/authority.seed"
      ],
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:9090/chio/health || exit 1"],
        "interval": 10,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 10
      },
      "essential": false,
      "cpu": 128,
      "memory": 128
    }
  ]
}
```

### 4.2 CDK Definition

```typescript
import * as ecs from "aws-cdk-lib/aws-ecs";

const taskDef = new ecs.FargateTaskDefinition(this, "AgentToolServer", {
  cpu: 512,
  memoryLimitMiB: 1024,
});

const app = taskDef.addContainer("app", {
  image: ecs.ContainerImage.fromEcrRepository(appRepo),
  portMappings: [{ containerPort: 8080 }],
  environment: { CHIO_SIDECAR_URL: "http://localhost:9090" },
});

const sidecar = taskDef.addContainer("chio-sidecar", {
  image: ecs.ContainerImage.fromEcrRepository(chioSidecarRepo),
  portMappings: [{ containerPort: 9090 }],
  command: [
    "api",
    "protect",
    "--upstream",
    "http://127.0.0.1:8080",
    "--spec",
    "/etc/chio/spec/openapi.yaml",
    "--listen",
    "0.0.0.0:9090",
    "--receipt-store",
    "/var/lib/chio/receipts.db",
    "--authority-seed-file",
    "/etc/chio/seed/authority.seed",
  ],
  healthCheck: {
    command: ["CMD-SHELL", "curl -f http://localhost:9090/chio/health || exit 1"],
    interval: cdk.Duration.seconds(10),
    startPeriod: cdk.Duration.seconds(10),
  },
  essential: false,
});

app.addContainerDependencies({
  container: sidecar,
  condition: ecs.ContainerDependencyCondition.HEALTHY,
});
```

## 5. Azure Container Apps

### 5.1 Bicep / ARM Template

```bicep
resource containerApp 'Microsoft.App/containerApps@2023-05-01' = {
  name: 'agent-tool-server'
  location: location
  properties: {
    configuration: {
      ingress: {
        targetPort: 8080
        external: true
      }
    }
    template: {
      containers: [
        {
          name: 'app'
          image: 'myregistry.azurecr.io/agent-tool-server:latest'
          resources: {
            cpu: json('0.75')
            memory: '1.5Gi'
          }
          env: [
            { name: 'CHIO_SIDECAR_URL', value: 'http://localhost:9090' }
          ]
        }
      ]
      initContainers: []
      // Azure Container Apps uses "sidecar" containers
      // that run alongside main containers
      sidecars: [
        {
          name: 'chio-sidecar'
          image: 'myregistry.azurecr.io/chio-sidecar:latest'
          resources: {
            cpu: json('0.25')
            memory: '0.5Gi'
          }
          // Container Apps offers no per-replica persistent disk, so the audit
          // log cannot be durable here: opt into ephemeral in-memory receipts
          // explicitly rather than pointing --receipt-store at scratch storage,
          // which would report a durable backend yet lose every receipt on
          // replica recycle. See section 7 for a durable audit trail.
          args: [
            'api'
            'protect'
            '--upstream'
            'http://127.0.0.1:8080'
            '--spec'
            '/etc/chio/spec/openapi.yaml'
            '--listen'
            '0.0.0.0:9090'
            '--allow-ephemeral-receipts'
            '--authority-seed-file'
            '/etc/chio/seed/authority.seed'
          ]
        }
      ]
    }
  }
}
```

## 6. Chio Sidecar Container

The sidecar container image is shared across all platforms. It is the shipped
`chio` binary (crate `chio-cli`) run as a sidecar subcommand; there is no
separate `chio-sidecar` binary.

### 6.1 Dockerfile

The canonical, maintained image is `deploy/sidecar/Dockerfile`. The snippet
below is an illustrative minimal build. There is no `http-server`, `s3-policy`,
`dynamodb-receipts`, or `bigquery` build feature; the sidecar behaviour is a
runtime subcommand of the single `chio` binary, not a compile-time feature.

```dockerfile
FROM rust:1.82-slim AS builder

WORKDIR /build
COPY . .
RUN cargo build --release --locked -p chio-cli --bin chio

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /build/target/release/chio /usr/local/bin/chio

EXPOSE 9090
# Run the reverse-proxy sidecar (`chio api protect ...`) or the MCP edge
# (`chio mcp serve-http ...`); pass the subcommand and flags at deploy time.
ENTRYPOINT ["/usr/local/bin/chio"]
```

### 6.2 Configuration

The shipped `chio` binary is configured with CLI flags, not environment
variables. The reverse-proxy sidecar subcommand (`chio api protect`) takes its
upstream, listen address, route/scope table, durable audit log, and signing
seed from flags:

| Flag | Description | Notes |
|------|-------------|-------|
| `--upstream <url>` | Base URL of the protected upstream | Localhost within the task/service |
| `--listen <addr>` | Bind address for the kernel ingress | Defaults to `127.0.0.1:9090`; the manifests bind `0.0.0.0:9090` |
| `--spec <path>` | OpenAPI document the kernel derives its route and scope table from | The operator-provided spec, not the upstream |
| `--receipt-store <path>` | Path to the durable SQLite audit log | Backed by the `chio_store_sqlite` backend; place it on a per-instance local disk with a single writer (see section 7) |
| `--authority-seed-file <path>` | Path to the signing seed used to sign receipts | Delivered as a mounted secret file |

The receipt store is a local SQLite database (the `chio_store_sqlite` backend).
Point `--receipt-store` at a path on a per-instance disk with a single writer so
the audit log survives container restarts and revision recycles (see section 7
for the single-writer and local-disk requirements). The reference manifests set
only `CHIO_LOG_LEVEL` in the environment; the route table, receipts, and signing
material are all supplied through the flags above and the mounted spec, seed, and
receipt volumes.

### 6.3 Health Check

```
GET /chio/health

200 OK
{
  "status": "healthy",
  "policy_loaded": true,
  "policy_version": "2026-04-15T10:00:00Z",
  "guards_loaded": 3,
  "uptime_seconds": 3600
}
```

## 7. Durable Receipt Store

The sidecar writes its audit receipts to a local SQLite database (the
`chio_store_sqlite` backend) at the path given by `--receipt-store`, in WAL mode.
WAL coordinates readers and writers through a shared-memory index that only works
when every connection is on the same host and a local (non-network) filesystem,
so the store is a **single-writer, single-host database**:

- **Use a per-instance disk, not a shared network filesystem.** WAL is not safe
  over Filestore/NFS, Amazon EFS, or Azure Files. If the mounted filesystem
  cannot support WAL, the sidecar fails closed at startup rather than run without
  durability, so a network-filesystem mount either refuses to boot or risks
  corruption under concurrent access.
- **Run exactly one writer per database.** Two instances writing the same file
  corrupt it. The Cloud Run and Azure references pin to a single instance; the
  ECS reference attaches a per-task block volume and expects `desiredCount: 1`.

| Platform | Per-instance receipt volume for `/var/lib/chio` |
|----------|--------------------------------------------------|
| GCP Cloud Run | Single instance (`maxScale: 1`); no per-instance persistent disk, so durability depends on the mounted Filestore share and horizontal scale needs a client-server store |
| AWS ECS | A per-task Amazon EBS block volume attached at launch, with the service at `desiredCount: 1` |
| Azure Container Apps | Single replica (`maxReplicas: 1`); no per-replica persistent disk, so durability depends on the mounted Azure Files share and horizontal scale needs a client-server store |

To scale horizontally, give each instance its own receipt database or front a
client-server audit store; do not share one SQLite file across instances. Do not
point `--receipt-store` at an ephemeral (emptyDir-tier) path: the audit log would
be lost on every recycle, breaking receipt continuity. To move receipts onward
(analytics, long-term retention), export from the SQLite store out of band rather
than writing to a remote destination on the hot path.

## 8. Scale-to-Zero Considerations

Cloud Run and Azure Container Apps can scale to zero. When the first
request arrives after a cold start:

1. Platform starts both containers
2. Chio sidecar starts first (dependency ordering)
3. Sidecar loads its OpenAPI spec and opens the receipt store
4. Health check passes
5. Application container starts
6. First request served

**Mitigation for cold start latency:**

- Bundle or mount the OpenAPI spec so no remote fetch is needed at cold start
- Set `minScale: 1` for latency-sensitive services
- Use pre-compiled WASM guards bundled in the image
- Consider the Lambda Extension model for truly ephemeral workloads

## 9. Terraform Module

> **Not yet implemented.** There is no `terraform/` module in this repository
> today. Deploy with the platform-native manifests under `deploy/`: Cloud Run
> `service.yaml`, ECS `task-definition.json`, and Azure `container-app.bicep`. A
> reusable Terraform module that wraps those manifests (wiring the durable
> receipt volume and the mounted spec and seed) is a candidate for future work.

## 10. Package Structure

This is not a new SDK -- it is reference infrastructure:

```
deploy/
  README.md                   # Overview, placeholders, and quickstarts
  SIDECAR_BUILD_GUIDE.md       # Sidecar image build guide

  cloud-run/
    service.yaml              # Cloud Run multi-container service

  ecs/
    task-definition.json      # ECS Fargate task definition

  azure/
    container-app.bicep       # Azure Container Apps

  sidecar/
    Dockerfile                # Chio sidecar container image
```

## 11. Open Questions

1. **Sidecar vs. init container.** Should Chio offer an init-container mode
   that pre-evaluates policy and writes a grant token to a shared volume,
   then exits? This avoids ongoing sidecar resource consumption for simple
   "evaluate once at startup" use cases.

2. **Service mesh interaction.** If the platform already runs a service
   mesh sidecar (Envoy/Istio), adding a Chio sidecar is a third container.
   Should Chio integrate as an Envoy external authorization filter instead?

3. **Multi-region.** For global deployments (Cloud Run multi-region, ECS
   multi-region), should each region's Chio sidecar connect to a regional
   kernel, or a centralized control plane?

4. **GPU workloads.** ML inference containers often use GPUs. The Chio
   sidecar does not need GPU access. Ensure resource allocation does not
   compete with the primary container for GPU memory.
