#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LINT="$REPO_ROOT/scripts/check-proof-copy.sh"

work="$(mktemp -d -t chio-proof-copy-XXXXXX)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/pass" "$work/bare-acp" "$work/market-overclaim" "$work/universal-overclaim"

cat > "$work/pass/README.md" <<'EOF'
Chio binds ACP-Client and ACP-Commerce evidence by digest.
Chio does not publish a global trust score.
Chio does not operate liquidity pools.
EOF

cat > "$work/bare-acp/README.md" <<'EOF'
Chio offers ACP support across agent workflows.
EOF

cat > "$work/market-overclaim/README.md" <<'EOF'
Chio publishes a global trust score.
EOF

cat > "$work/universal-overclaim/README.md" <<'EOF'
Chio is the universal agent protocol.
EOF

CHIO_PROOF_COPY_ROOTS="$work/pass" "$LINT"

if CHIO_PROOF_COPY_ROOTS="$work/bare-acp" "$LINT" >/tmp/chio-copy-bare-acp.out 2>&1; then
  echo "bare ACP copy unexpectedly passed" >&2
  exit 1
fi
grep -q "standards.copy.ambiguous-acp" /tmp/chio-copy-bare-acp.out

if CHIO_PROOF_COPY_ROOTS="$work/market-overclaim" "$LINT" >/tmp/chio-copy-market.out 2>&1; then
  echo "market overclaim copy unexpectedly passed" >&2
  exit 1
fi
grep -q "copy.market.global-trust-score" /tmp/chio-copy-market.out

if CHIO_PROOF_COPY_ROOTS="$work/universal-overclaim" "$LINT" >/tmp/chio-copy-universal.out 2>&1; then
  echo "universal protocol copy unexpectedly passed" >&2
  exit 1
fi
grep -q "copy.agent-web.universal-protocol" /tmp/chio-copy-universal.out

echo "check-proof-copy.test.sh: proof copy lint positives and negatives passed"
