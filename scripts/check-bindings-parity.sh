#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v node >/dev/null 2>&1; then
  echo "bindings parity requires node on PATH" >&2
  exit 1
fi

node --input-type=module <<'NODE'
import { readFileSync } from "node:fs";

const fixture = JSON.parse(readFileSync("tests/bindings/vectors/receipt/v1.json", "utf8"));
for (const testCase of fixture.cases) {
  if (testCase.expected.trust_level !== testCase.receipt.trust_level) {
    throw new Error(`receipt vector ${testCase.id} expected trust_level parity`);
  }
}
NODE

cargo test -p chio-binding-helpers --test vector_fixtures receipt_fixture
npm --prefix sdks/typescript/chio-ts test
./scripts/check-chio-py.sh
(cd sdks/go/chio-go && CGO_ENABLED=0 go test ./...)
