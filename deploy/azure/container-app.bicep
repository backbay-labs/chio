// Reference Azure Container Apps deployment with a Chio sidecar.
//
// Placeholders:
//   APP_IMAGE_PLACEHOLDER          -- replace with your application image
//   ghcr.io/backbay-labs/chio-sidecar    -- replace with the sidecar image you pushed
//   Key Vault secrets must be created before deploy; the Container Apps
//   environment's managed identity needs GET on those secrets.
//   The AzureFile-backed spec storage (specStorageName) must be registered on
//   the managed environment before deploy. The receipt store is a single-writer
//   SQLite database in WAL mode, which needs a local filesystem, so it runs on a
//   per-replica local volume rather than an Azure Files share; this template
//   runs one replica for one coherent audit stream (see the maxReplicas and
//   volume notes).
//
// Deploy:
//   az deployment group create \
//     --resource-group my-rg \
//     --template-file deploy/azure/container-app.bicep \
//     --parameters location=eastus ...
//
// Startup ordering: the Chio sidecar declares a startupProbe on :9090/chio/health;
// the app container declares a startupProbe on :8080/healthz that depends on
// the sidecar URL being reachable. The sidecar fails closed if it cannot start
// serving that health endpoint, causing the revision to be marked unhealthy and
// recycled.

@description('Azure region for the container app.')
param location string = resourceGroup().location

@description('Name of the container app.')
param containerAppName string = 'agent-tool-server'

@description('Resource ID of the Container Apps managed environment.')
param managedEnvironmentId string

@description('Application container image (placeholder, override at deploy time).')
param appImage string = 'APP_IMAGE_PLACEHOLDER'

@description('Chio sidecar container image.')
param chioSidecarImage string = 'ghcr.io/backbay-labs/chio-sidecar:latest'

@description('Key Vault URI that holds the authority signing seed, delivered to the sidecar as a mounted secret file.')
param chioAuthoritySeedSecretUri string

@description('User-assigned managed identity resource ID with Key Vault read access.')
param userAssignedIdentityId string

@description('Container Apps environment storage name backing the read-only OpenAPI spec share.')
param specStorageName string

resource containerApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: containerAppName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${userAssignedIdentityId}': {}
    }
  }
  properties: {
    managedEnvironmentId: managedEnvironmentId
    configuration: {
      activeRevisionsMode: 'Single'
      // Prometheus scrape target: the chio-sidecar serves an admin-gated GET
      // /metrics carrying the kernel/edge/alert-pack families on targetPort 9090.
      // Azure Container Apps has no native Prometheus scrape annotation, so the
      // collector sidecar / Managed Prometheus is configured to scrape
      // http://<app>:9090/metrics.
      ingress: {
        external: true
        targetPort: 9090
        transport: 'auto'
        allowInsecure: false
      }
      secrets: [
        {
          name: 'chio-authority-seed'
          keyVaultUrl: chioAuthoritySeedSecretUri
          identity: userAssignedIdentityId
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'app'
          image: appImage
          resources: {
            cpu: json('0.75')
            memory: '1.5Gi'
          }
          env: [
            {
              name: 'CHIO_SIDECAR_URL'
              value: 'http://localhost:9090'
            }
          ]
          probes: [
            {
              type: 'Startup'
              httpGet: {
                path: '/healthz'
                port: 8080
              }
              initialDelaySeconds: 2
              periodSeconds: 2
              failureThreshold: 30
            }
            {
              type: 'Liveness'
              httpGet: {
                path: '/healthz'
                port: 8080
              }
              periodSeconds: 10
              failureThreshold: 3
            }
          ]
        }
        {
          name: 'chio-sidecar'
          image: chioSidecarImage
          // The sidecar image's CMD default is `--help`; override with
          // a long-running subcommand so the probes succeed and the
          // app container becomes ready. Only `args` is set so the
          // image ENTRYPOINT (`/sbin/tini -- /usr/local/bin/chio`) is
          // preserved.
          args: [
            'api'
            'protect'
            '--upstream'
            'http://127.0.0.1:8080'
            '--spec'
            '/etc/chio/spec/openapi.yaml'
            '--listen'
            '0.0.0.0:9090'
            // Container Apps has no per-replica persistent disk, so the audit log
            // cannot be durable here. Opt into ephemeral in-memory receipts
            // explicitly instead of pointing --receipt-store at scratch storage,
            // which would boot reporting a durable backend yet lose every receipt
            // on revision recycle. For a durable audit trail, front a client-server
            // store or run on a per-instance-disk platform.
            '--allow-ephemeral-receipts'
            '--authority-seed-file'
            '/etc/chio/seed/authority.seed'
          ]
          resources: {
            cpu: json('0.25')
            memory: '0.5Gi'
          }
          env: [
            {
              name: 'CHIO_LOG_LEVEL'
              value: 'info'
            }
          ]
          volumeMounts: [
            {
              volumeName: 'chio-openapi-spec'
              mountPath: '/etc/chio/spec'
            }
            {
              volumeName: 'chio-authority-seed'
              mountPath: '/etc/chio/seed'
            }
          ]
          probes: [
            {
              type: 'Startup'
              httpGet: {
                path: '/chio/health'
                port: 9090
              }
              initialDelaySeconds: 1
              periodSeconds: 1
              failureThreshold: 30
            }
            {
              // Process-only liveness: a dependency blip must not restart a
              // container that is still serving. Readiness gates on /chio/health.
              type: 'Liveness'
              httpGet: {
                path: '/chio/live'
                port: 9090
              }
              periodSeconds: 10
              failureThreshold: 3
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/chio/health'
                port: 9090
              }
              periodSeconds: 5
              failureThreshold: 3
            }
          ]
        }
      ]
      volumes: [
        // OpenAPI spec share (read-only). The kernel derives its route and
        // scope table from this operator-provided document, never from the
        // upstream.
        {
          name: 'chio-openapi-spec'
          storageType: 'AzureFile'
          storageName: specStorageName
        }
        // Authority signing seed, delivered from Key Vault as a mounted file.
        {
          name: 'chio-authority-seed'
          storageType: 'Secret'
          secrets: [
            {
              secretRef: 'chio-authority-seed'
              path: 'authority.seed'
            }
          ]
        }
        // No receipt-store volume: this template keeps the audit log in memory
        // (--allow-ephemeral-receipts) because Container Apps offers no per-replica
        // persistent disk. A durable receipt log is a single-writer SQLite database
        // in WAL mode, which needs a local (non-network) filesystem and so cannot
        // run on an Azure Files share. For a durable audit trail, front a
        // client-server audit store or move to a per-instance disk platform (a
        // StatefulSet PVC, or an ECS task with an attached block volume).
      ]
      // The audit log is an explicitly ephemeral in-memory stream, so maxReplicas
      // is pinned to 1: one replica keeps one coherent stream. Fanning out gives
      // each replica its own separate log; for a single durable audit trail across
      // scale or restart, front a client-server audit store.
      scale: {
        minReplicas: 1
        maxReplicas: 1
      }
    }
  }
}

output containerAppFqdn string = containerApp.properties.configuration.ingress.fqdn
output containerAppName string = containerApp.name
