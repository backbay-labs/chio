#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

source_file="crates/kernel/chio-kernel-core/src/formal_aeneas.rs"
work_dir="target/formal/aeneas-production"
lean_dir="${work_dir}/lean"
artifact_file="${work_dir}/equivalence-artifacts.json"

if [[ ! -f "${lean_dir}/Funs.lean" || ! -f "${lean_dir}/Types.lean" ]]; then
  CHIO_SKIP_AENEAS_EQ=1 ./scripts/check-aeneas-production.sh
fi

python3 - <<'PY'
import hashlib
import json
from pathlib import Path

repo = Path(".")
source_file = repo / "crates/kernel/chio-kernel-core/src/formal_aeneas.rs"
lean_dir = repo / "target/formal/aeneas-production/lean"
artifact_file = repo / "target/formal/aeneas-production/equivalence-artifacts.json"

expected_symbols = [
    "classify_time_window_code",
    "time_window_valid",
    "exact_or_wildcard_covers_by_flags",
    "prefix_wildcard_or_exact_covers_by_flags",
    "optional_u32_cap_is_subset",
    "required_true_is_preserved",
    "monetary_cap_is_subset_by_parts",
    "budget_precheck",
    "budget_commit",
    "dpop_freshness_valid",
    "dpop_admits",
    "nonce_admits",
    "guard_step_allows",
    "revocation_snapshot_denies",
    "receipt_fields_coupled",
]

funs = (lean_dir / "Funs.lean").read_text(encoding="utf-8")
types = (lean_dir / "Types.lean").read_text(encoding="utf-8")

missing = [symbol for symbol in expected_symbols if f"def {symbol}" not in funs]
if missing:
    raise SystemExit(f"Aeneas equivalence missing generated functions: {missing}")
if "BudgetCommitResult" not in types:
    raise SystemExit("Aeneas equivalence missing generated BudgetCommitResult type")

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

artifact_file.parent.mkdir(parents=True, exist_ok=True)
artifact_file.write_text(
    json.dumps(
        {
            "schema": "chio.aeneas-equivalence-artifacts.v1",
            "source": str(source_file),
            "generated": {
                "funs": str(lean_dir / "Funs.lean"),
                "types": str(lean_dir / "Types.lean"),
            },
            "sha256": {
                str(source_file): digest(source_file),
                str(lean_dir / "Funs.lean"): digest(lean_dir / "Funs.lean"),
                str(lean_dir / "Types.lean"): digest(lean_dir / "Types.lean"),
            },
            "symbols": expected_symbols,
        },
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
PY

(
  cd formal/lean4/Chio
  lake build Chio.Proofs.AeneasEquivalence
)

echo "Aeneas equivalence gate passed"
