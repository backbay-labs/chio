#!/usr/bin/env bash
# run-falsification.sh - Direction-enforced falsification runner for the
# FV-B5 mutation variants. The green artifact must verify; each mutation
# must FAIL verification with a captured verifier error. A mutation that
# verifies means the green property set is too weak, and this script exits
# nonzero so that outcome cannot be read as success.

set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
lib="${here}/ledger/src/lib.rs"
out="${here}/falsification"
verus_bin="${VERUS_BIN:-${HOME}/.local/bin/verus}"

mkdir -p "${out}"

echo "green build:"
"${verus_bin}" "${lib}" --crate-type=lib
echo

status=0
for mutation in mutation_terminal mutation_overflow; do
    log="${out}/${mutation#mutation_}.log"
    if "${verus_bin}" "${lib}" --crate-type=lib --cfg "${mutation}" > "${log}" 2>&1; then
        echo "FALSIFICATION FAILURE: ${mutation} verified" >&2
        status=1
        continue
    fi
    if ! grep -Eq "verification results:: [0-9]+ verified, [1-9][0-9]* errors" "${log}"; then
        echo "FALSIFICATION FAILURE: ${mutation} died without a verifier" >&2
        echo "error (see ${log}); a build breakage is not a falsification" >&2
        status=1
        continue
    fi
    echo "${mutation}: rejected as required (${log})"
done

exit "${status}"
