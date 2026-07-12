// Reference Azure Container Apps deployment with a Chio sidecar.
//
// Placeholders:
//   APP_IMAGE_PLACEHOLDER          -- replace with your application image
//   ghcr.io/backbay-labs/chio-sidecar    -- replace with the sidecar image you pushed
//   Key Vault secrets must be created before deploy; the Container Apps
//   environment's managed identity needs GET on those secrets.
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

@description('Key Vault URI that holds the Chio signing key secret.')
param chioSigningKeySecretUri string

@description('Key Vault URI that holds the capability authority URL secret.')
param chioCapabilityAuthoritySecretUri string

@description('User-assigned managed identity resource ID with Key Vault read access.')
param userAssignedIdentityId string

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
          name: 'chio-signing-key'
          keyVaultUrl: chioSigningKeySecretUri
          identity: userAssignedIdentityId
        }
        {
          name: 'chio-capability-authority-url'
          keyVaultUrl: chioCapabilityAuthoritySecretUri
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
            '--listen'
            '0.0.0.0:9090'
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
            {
              name: 'CHIO_SIGNING_KEY'
              secretRef: 'chio-signing-key'
            }
            {
              name: 'CHIO_CAPABILITY_AUTHORITY_URL'
              secretRef: 'chio-capability-authority-url'
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
      scale: {
        minReplicas: 1
        maxReplicas: 20
        rules: [
          {
            name: 'http-scale'
            http: {
              metadata: {
                concurrentRequests: '50'
              }
            }
          }
        ]
      }
    }
  }
}

output containerAppFqdn string = containerApp.properties.configuration.ingress.fqdn
output containerAppName string = containerApp.name
