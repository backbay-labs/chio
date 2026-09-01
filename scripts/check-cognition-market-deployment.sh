#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

template="deploy/cognition-market/kubernetes.yaml.template"
renderer="deploy/cognition-market/render.py"
worker="deploy/cognition-market/systemd/chio-finding-worker.service"
dockerfile="deploy/cognition-market/Dockerfile"
rendered="$(mktemp "${TMPDIR:-/tmp}/chio-market-deployment.XXXXXX")"
trap 'rm -f "${rendered}"' EXIT

python3 "${renderer}" \
  --chio-image ghcr.io/bb-connor/arc \
  --chio-digest aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --proxy-image docker.io/library/nginx \
  --proxy-digest bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --public-host market.example.com \
  --candidate-sha cccccccccccccccccccccccccccccccccccccccc \
  --output "${rendered}"

if grep -E 'image:.*:(latest|main|master)([[:space:]]|$)' "${rendered}" >/dev/null; then
  echo "cognition-market deployment admits a mutable image tag" >&2
  exit 1
fi
if [[ "$(grep -Ec 'image: [^[:space:]]+@sha256:[0-9a-f]{64}$' "${rendered}")" -ne 6 ]]; then
  echo "cognition-market deployment must pin all six container references" >&2
  exit 1
fi
for required in \
  'replicas: 3' \
  'maxUnavailable: 0' \
  'automountServiceAccountToken: false' \
  'runAsNonRoot: true' \
  'readOnlyRootFilesystem: true' \
  'allowPrivilegeEscalation: false' \
  'drop: ["ALL"]' \
  'kind: NetworkPolicy' \
  'name: chio-finding-market-migrate' \
  'name: seed-replication-freshness' \
  'name: replication-freshness' \
  'name: chio-finding-market-replicator' \
  'name: CHIO_FINDING_DEPLOYED_CANDIDATE_SHA' \
  'name: CHIO_FINDING_DEPLOYED_ARTIFACT_SHA256' \
  'value: "cccccccccccccccccccccccccccccccccccccccc"' \
  'value: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' \
  '--replication-check-once' \
  '--replication-check-interval-secs' \
  'ingress: []' \
  'kind: PodDisruptionBudget' \
  'chio.world/market-ingress-client: "true"' \
  'chio.world/market-postgres: "true"' \
  'chio.world/market-egress-gateway: "true"' \
  'secretKeyRef:' \
  '/health/ready' \
  'Chio-Proxy-Authentication' \
  'invalid proxy token' \
  'ssl_protocols TLSv1.3'; do
  if ! grep -F -- "${required}" "${rendered}" >/dev/null; then
    echo "cognition-market deployment omits required contract: ${required}" >&2
    exit 1
  fi
done
if [[ "$(grep -Ec '^FROM .*@sha256:[0-9a-f]{64}( AS [a-z]+)?$' "${dockerfile}")" -ne 2 ]]; then
  echo "cognition-market container stages must use exact image digests" >&2
  exit 1
fi
if grep -Ei '(^|[[:space:]])FROM .*:(latest|main|master)(@|[[:space:]]|$)' "${dockerfile}" >/dev/null; then
  echo "cognition-market container build admits a mutable base tag" >&2
  exit 1
fi
for forbidden in 'sqlite' 'hostPath:' 'privileged: true' 'value: postgres://' 'value: secret'; do
  if grep -Fi "${forbidden}" "${rendered}" >/dev/null; then
    echo "cognition-market deployment contains forbidden contract: ${forbidden}" >&2
    exit 1
  fi
done
for required in \
  'ConditionPathExists=/dev/kvm' \
  'ExecStartPre=/usr/bin/test -r /dev/kvm' \
  'ExecStartPre=/usr/bin/test -w /dev/kvm' \
  'DevicePolicy=closed' \
  'DeviceAllow=/dev/kvm rw' \
  'NoNewPrivileges=yes' \
  'ProtectSystem=strict' \
  'Delegate=yes' \
  'UMask=0077'; do
  if ! grep -F "${required}" "${worker}" >/dev/null; then
    echo "cognition-market worker unit omits required contract: ${required}" >&2
    exit 1
  fi
done

if python3 "${renderer}" \
  --chio-image ghcr.io/bb-connor/arc:latest \
  --chio-digest aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --proxy-image docker.io/library/nginx \
  --proxy-digest bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --public-host market.example.com \
  --candidate-sha cccccccccccccccccccccccccccccccccccccccc \
  --output "${rendered}" >/dev/null 2>&1; then
  echo "cognition-market renderer accepted a tagged image" >&2
  exit 1
fi
if python3 "${renderer}" \
  --chio-image ghcr.io/bb-connor/arc \
  --chio-digest 0000000000000000000000000000000000000000000000000000000000000000 \
  --proxy-image docker.io/library/nginx \
  --proxy-digest bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --public-host market.example.com \
  --candidate-sha cccccccccccccccccccccccccccccccccccccccc \
  --output "${rendered}" >/dev/null 2>&1; then
  echo "cognition-market renderer accepted the zero image digest" >&2
  exit 1
fi
if python3 "${renderer}" \
  --chio-image ghcr.io/bb-connor/arc \
  --chio-digest aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --proxy-image docker.io/library/nginx \
  --proxy-digest bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --public-host market.example.com \
  --candidate-sha 0000000000000000000000000000000000000000 \
  --output "${rendered}" >/dev/null 2>&1; then
  echo "cognition-market renderer accepted the zero candidate SHA" >&2
  exit 1
fi
if python3 "${renderer}" \
  --chio-image ghcr.io/bb-connor/arc \
  --chio-digest aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --proxy-image docker.io/library/nginx \
  --proxy-digest bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --public-host Market.example.com \
  --candidate-sha cccccccccccccccccccccccccccccccccccccccc \
  --output "${rendered}" >/dev/null 2>&1; then
  echo "cognition-market renderer accepted a noncanonical public host" >&2
  exit 1
fi

echo "cognition-market deployment contracts passed"
