#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/criterion-compare.sh [--baseline DIR] [--current DIR] [--threshold-percent N] [--dry-run]

Compares Criterion estimate JSON files and fails if any current benchmark is
more than the threshold percent slower than its matching baseline benchmark.
USAGE
}

baseline_dir="${CRITERION_BASELINE_DIR:-target/criterion-baseline}"
current_dir="${CRITERION_CURRENT_DIR:-target/criterion}"
threshold_percent="${CRITERION_THRESHOLD_PERCENT:-10}"
dry_run="false"

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --baseline)
      baseline_dir="${2:?missing value for --baseline}"
      shift 2
      ;;
    --current)
      current_dir="${2:?missing value for --current}"
      shift 2
      ;;
    --threshold-percent)
      threshold_percent="${2:?missing value for --threshold-percent}"
      shift 2
      ;;
    --dry-run)
      dry_run="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

tmp_dir=""
if [[ "$dry_run" == "true" ]]; then
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' EXIT
  baseline_dir="$tmp_dir/baseline"
  current_dir="$tmp_dir/current"
  mkdir -p "$baseline_dir/scope_match/new" "$current_dir/scope_match/new"
  cat > "$baseline_dir/scope_match/new/estimates.json" <<'JSON'
{"median":{"confidence_interval":{"lower_bound":95.0,"upper_bound":105.0},"point_estimate":100.0,"standard_error":1.0}}
JSON
  cat > "$current_dir/scope_match/new/estimates.json" <<'JSON'
{"median":{"confidence_interval":{"lower_bound":104.0,"upper_bound":108.0},"point_estimate":106.0,"standard_error":1.0}}
JSON
fi

python3 - "$baseline_dir" "$current_dir" "$threshold_percent" <<'PY'
import json
import sys
from pathlib import Path

baseline_root = Path(sys.argv[1])
current_root = Path(sys.argv[2])
threshold = float(sys.argv[3])

if not baseline_root.exists():
    raise SystemExit(f"baseline criterion directory not found: {baseline_root}")
if not current_root.exists():
    raise SystemExit(f"current criterion directory not found: {current_root}")

def estimate_files(root):
    return {
        path.relative_to(root): path
        for path in root.rglob("new/estimates.json")
        if path.is_file()
    }

def median_lower_bound(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    try:
        return float(data["median"]["confidence_interval"]["lower_bound"])
    except KeyError as exc:
        raise SystemExit(f"{path} is missing median confidence interval lower_bound") from exc

baseline = estimate_files(baseline_root)
current = estimate_files(current_root)
if not current:
    raise SystemExit(f"no Criterion estimate files found under {current_root}")

new_benchmarks = sorted(str(rel) for rel in current if rel not in baseline)
if new_benchmarks:
    print("Criterion baseline is missing current benchmarks; skipping until baseline refresh:", file=sys.stderr)
    for rel in new_benchmarks:
        print(f"  {rel}", file=sys.stderr)

failures = []
for rel, current_path in sorted(current.items()):
    if rel not in baseline:
        continue
    base_value = median_lower_bound(baseline[rel])
    current_value = median_lower_bound(current_path)
    if base_value <= 0:
        raise SystemExit(f"{baseline[rel]} has non-positive median lower bound {base_value}")
    regression = ((current_value - base_value) / base_value) * 100.0
    print(f"{rel}: baseline={base_value:.3f} current={current_value:.3f} regression={regression:.2f}%")
    if regression > threshold:
        failures.append((rel, regression))

if failures:
    print(f"kernel bench regression gate failed, threshold={threshold:.2f}%", file=sys.stderr)
    for rel, regression in failures:
        print(f"  {rel}: {regression:.2f}%", file=sys.stderr)
    raise SystemExit(1)

if len(current) == len(new_benchmarks):
    print("no baseline-matched Criterion benchmarks found; only new benchmarks were reported")
    raise SystemExit(0)

print(f"kernel bench regression gate passed, threshold={threshold:.2f}%")
PY
