#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"

bash "${repo_root}/scripts/check-chio-schema-registry.sh"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/chio-schema-registry-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

mkdir -p \
  "${tmp}/scripts" \
  "${tmp}/spec/schemas/chio-transaction/v1" \
  "${tmp}/spec/schemas/unused"
cp "${repo_root}/scripts/check-chio-schema-registry.sh" "${tmp}/scripts/check-chio-schema-registry.sh"

cat >"${tmp}/spec/schemas/chio-transaction/v1/minimal.schema.json" <<'JSON'
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://schemas.chio.example/chio-transaction/v1/minimal.schema.json",
  "type": "object",
  "properties": {
    "schema": { "const": "chio.transaction.minimal.v1" }
  },
  "required": ["schema"],
  "additionalProperties": false
}
JSON

cat >"${tmp}/spec/schemas/registry.json" <<'JSON'
{
  "schema": "chio.schema-registry.v1",
  "artifacts": [
    {
      "schema": "chio.transaction.minimal.v1",
      "artifactKind": "transaction-test",
      "introducedBy": "schema-registry-test",
      "schemaFile": "spec/schemas/chio-transaction/v1/minimal.schema.json",
      "status": "Required"
    }
  ]
}
JSON

printf '1\n' >"${tmp}/spec/schemas/VERSION"
printf '{}\n' >"${tmp}/spec/schemas/unused/stale.extra"

(
  cd "$tmp"
  git init -q
  git config user.email test@example.invalid
  git config user.name test
  git add scripts/check-chio-schema-registry.sh \
    spec/schemas/VERSION \
    spec/schemas/chio-transaction/v1/minimal.schema.json \
    spec/schemas/registry.json
  python3 - <<'PY'
import hashlib
from pathlib import Path

paths = [
    "spec/schemas/VERSION",
    "spec/schemas/chio-transaction/v1/minimal.schema.json",
    "spec/schemas/registry.json",
    "spec/schemas/unused/stale.extra",
]
lines = [
    f"{hashlib.sha256(Path(path).read_bytes()).hexdigest()}  {path}\n"
    for path in paths
]
without_self = "".join(lines).encode("utf-8")
self_hash = hashlib.sha256(without_self).hexdigest()
Path("spec/schemas/MANIFEST.sha256").write_text(
    f"{self_hash}  spec/schemas/MANIFEST.sha256\n" + "".join(lines),
    encoding="utf-8",
)
PY
)

if (cd "$tmp" && bash scripts/check-chio-schema-registry.sh >/tmp/chio-schema-registry-extra.out 2>&1); then
  echo "check-chio-schema-registry.test.sh: expected extra MANIFEST path to fail" >&2
  cat /tmp/chio-schema-registry-extra.out >&2
  exit 1
fi

if ! grep -Fq "MANIFEST.sha256 path set is not deterministic" /tmp/chio-schema-registry-extra.out; then
  echo "check-chio-schema-registry.test.sh: extra path failed for the wrong reason" >&2
  cat /tmp/chio-schema-registry-extra.out >&2
  exit 1
fi

echo "check-chio-schema-registry.test.sh: schema registry contract passed"
