#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
scenario_lib="$repo_root/examples/internet-of-agents-web3-network/scenario/lib.sh"
qualifier="$repo_root/scripts/qualify-web3-examples.sh"

if ! grep -Fq "verify_transaction_passport" "$scenario_lib"; then
  echo "ioa-web3.transaction-passport-smoke: scenario smoke does not verify a transaction passport" >&2
  exit 1
fi

if ! grep -Fq "proof assemble" "$scenario_lib"; then
  echo "ioa-web3.transaction-passport-smoke: smoke must assemble a transaction passport" >&2
  exit 1
fi

if ! grep -Fq "proof verify" "$scenario_lib"; then
  echo "ioa-web3.transaction-passport-smoke: smoke must run chio proof verify on the generated passport" >&2
  exit 1
fi

if ! grep -Fq "check-chio-transaction-passport.sh" "$scenario_lib"; then
  echo "ioa-web3.transaction-passport-smoke: smoke must assert committed transaction-passport negatives reject" >&2
  exit 1
fi

for script in \
  "qualify-web3-e2e.sh" \
  "qualify-web3-promotion.sh" \
  "qualify-web3-ops-controls.sh"
do
  if ! grep -Fq "$script" "$qualifier"; then
    echo "ioa-web3.transaction-passport-smoke: qualifier must generate missing evidence with $script" >&2
    exit 1
  fi
done

for path in \
  "target/web3-e2e-qualification/partner-qualification.json" \
  "target/web3-promotion-qualification/promotion-qualification.json" \
  "target/web3-ops-qualification/incident-audit.json"
do
  if ! grep -Fq "$path" "$qualifier"; then
    echo "ioa-web3.transaction-passport-smoke: qualifier must bind $path" >&2
    exit 1
  fi
done

for flag in \
  "--e2e-report" \
  "--promotion-report" \
  "--ops-audit"
do
  if ! grep -Fq -- "$flag" "$qualifier"; then
    echo "ioa-web3.transaction-passport-smoke: qualifier must pass $flag explicitly" >&2
    exit 1
  fi
done

for path in \
  "transaction-passport/transaction-passport.json" \
  "transaction-passport/verifier-report.json"
do
  if ! grep -Fq "$path" "$qualifier"; then
    echo "ioa-web3.transaction-passport-smoke: qualifier does not require $path" >&2
    exit 1
  fi
done

echo "check-ioa-web3-transaction-passport-smoke.test.sh: transaction passport smoke contract passed"
