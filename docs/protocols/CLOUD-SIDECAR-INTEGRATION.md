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
        # Keep at least 1 instance warm to avoid sidecar cold starts
        autoscaling.knative.dev/minScale: "1"
        autoscaling.knative.dev/maxScale: "100"
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
          env:
            - name: CHIO_POLICY_SOURCE
              value: "gs://my-bucket/chio-policy.yaml"
            - name: CHIO_RECEIPT_SINK
              value: "bigquery://my-project.chio_receipts.receipts"
          startupProbe:
            httpGet:
              path: /health
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
      "environment": [
        { "name": "CHIO_POLICY_SOURCE", "value": "s3://my-bucket/chio-policy.yaml" },
        { "name": "CHIO_RECEIPT_SINK", "value": "dynamodb://chio-receipts" }
      ],
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:9090/health || exit 1"],
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
  image: ecs.ContainerImage.fromEcrRepository(arcSidecarRepo),
  portMappings: [{ containerPort: 9090 }],
  environment: {
    CHIO_POLICY_SOURCE: `s3://${policyBucket.bucketName}/chio-policy.yaml`,
    CHIO_RECEIPT_SINK: `dynamodb://${receiptTable.tableName}`,
  },
  healthCheck: {
    command: ["CMD-SHELL", "curl -f http://localhost:9090/health || exit 1"],
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
          env: [
            { name: 'CHIO_POLICY_SOURCE', value: 'https://mystorageaccount.blob.core.windows.net/config/chio-policy.yaml' }
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

> **Proposed surface -- not consumed today.** The shipped `chio` binary does not
> read the environment variables in the table below. Today the sidecar is
> configured with CLI flags (for example
> `chio api protect --upstream <url> --listen 0.0.0.0:9090`, or
> `chio mcp serve-http --policy <file> -- <server cmd>`). Secrets and log level
> reach a loaded config/policy file via `${VAR}` interpolation
> (e.g. `${CHIO_SIGNING_KEY}`, `${CHIO_LOG_LEVEL}`). The variables below are an
> aspirational configuration surface for a future dedicated sidecar binary.

| Variable | Description | Default |
|----------|-------------|---------|
| `CHIO_LISTEN_ADDR` | HTTP listen address | `0.0.0.0:9090` |
| `CHIO_POLICY_SOURCE` | Policy location (file, s3://, gs://) | `/etc/chio/policy.yaml` |
| `CHIO_RECEIPT_SINK` | Receipt destination | `stdout` |
| `CHIO_LOG_LEVEL` | Log level | `info` |
| `CHIO_HEALTH_PATH` | Health check endpoint | `/health` |
| `CHIO_GRANT_TOKEN` | Pre-loaded grant token | (none) |
| `CHIO_POLICY_REFRESH` | Policy refresh interval | `5m` |

### 6.3 Health Check

```
GET /health

200 OK
{
  "status": "healthy",
  "policy_loaded": true,
  "policy_version": "2026-04-15T10:00:00Z",
  "guards_loaded": 3,
  "uptime_seconds": 3600
}
```

## 7. Receipt Sinks by Platform

Each cloud platform has a natural receipt destination:

| Platform | Primary Sink | Secondary Sink |
|----------|-------------|----------------|
| GCP Cloud Run | BigQuery | Cloud Storage |
| AWS ECS | DynamoDB | S3 |
| Azure Container Apps | Cosmos DB | Blob Storage |
| Any | Chio Control Plane | stdout (CloudWatch/Cloud Logging) |

The sidecar supports pluggable sinks. The `CHIO_RECEIPT_SINK` env var
selects the sink:

```
# DynamoDB
CHIO_RECEIPT_SINK=dynamodb://table-name

# BigQuery
CHIO_RECEIPT_SINK=bigquery://project.dataset.table

# S3 (buffered, flushed on shutdown)
CHIO_RECEIPT_SINK=s3://bucket-name/prefix/

# Chio Control Plane
CHIO_RECEIPT_SINK=https://control.chio-protocol.io/v1/receipts

# stdout (for structured log ingestion)
CHIO_RECEIPT_SINK=stdout
```

## 8. Scale-to-Zero Considerations

Cloud Run and Azure Container Apps can scale to zero. When the first
request arrives after a cold start:

1. Platform starts both containers
2. Chio sidecar starts first (dependency ordering)
3. Sidecar loads policy (bundled: ~2ms, cloud storage: ~40-80ms)
4. Health check passes
5. Application container starts
6. First request served

**Mitigation for cold start latency:**

- Bundle policy in the container image (eliminates storage fetch)
- Set `minScale: 1` for latency-sensitive services
- Use pre-compiled WASM guards bundled in the image
- Consider the Lambda Extension model for truly ephemeral workloads

## 9. Terraform Module

```hcl
# Reference Terraform module for deploying Chio-governed services

module "chio_cloud_run" {
  source = "github.com/backbay-labs/chio//terraform/modules/cloud-run-sidecar"

  project_id    = var.project_id
  region        = var.region
  service_name  = "agent-tool-server"

  app_image     = "gcr.io/${var.project_id}/agent-tool-server:latest"
  app_port      = 8080
  app_cpu       = "1"
  app_memory    = "512Mi"

  chio_image     = "gcr.io/${var.project_id}/chio-sidecar:latest"
  chio_cpu       = "0.25"
  chio_memory    = "64Mi"

  policy_source = "gs://${var.policy_bucket}/chio-policy.yaml"
  receipt_sink  = "bigquery://${var.project_id}.chio.receipts"

  min_instances = 1
  max_instances = 100
}
```

## 10. Package Structure

This is not a new SDK -- it is reference infrastructure:

```
deploy/
  cloud-run/
    service.yaml              # Cloud Run multi-container service
    job.yaml                  # Cloud Run Job with sidecar
    README.md

  ecs/
    task-definition.json      # ECS Fargate task definition
    cdk/                      # CDK constructs
      lib/chio-sidecar.ts
    README.md

  azure/
    container-app.bicep       # Azure Container Apps
    README.md

  sidecar/
    Dockerfile                # Chio sidecar container
    Dockerfile.distroless     # Minimal image

  terraform/
    modules/
      cloud-run-sidecar/      # GCP module
      ecs-sidecar/            # AWS module
      aca-sidecar/            # Azure module
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
