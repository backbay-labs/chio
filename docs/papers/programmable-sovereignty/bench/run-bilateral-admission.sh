#!/usr/bin/env bash
set -euo pipefail

umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
SOURCE="${CHIO_SOURCE:-$ROOT}"
if [[ ! -d "$SOURCE/crates" || ! -f "$SOURCE/Cargo.toml" ]]; then
  echo "CHIO_SOURCE does not name a Chio workspace: $SOURCE" >&2
  exit 2
fi
SOURCE_COMMIT="$(git -C "$SOURCE" rev-parse HEAD)"
if [[ -n "$(git -C "$SOURCE" status --short)" ]]; then
  SOURCE_DIRTY=true
else
  SOURCE_DIRTY=false
fi
BENCHMARK_INPUT_TREE_SHA256="$(
  python3 "$SOURCE/scripts/generate-programmable-sovereignty-artifact.py" \
    --source-commit "$SOURCE_COMMIT" \
    --benchmark-input-digest PS-B01
)"

RESULT_DIR="${CHIO_PAPER_RESULT_DIR:-$SCRIPT_DIR/results}"
TARGET_DIR="${CHIO_TARGET_DIR:-${TMPDIR:-/tmp}/chio-programmable-sovereignty-bilateral-target}"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/chio-bilateral-admission-bench.XXXXXX")"
SAMPLES="${CHIO_BENCH_SAMPLES:-20}"
WARMUPS="${CHIO_BENCH_WARMUPS:-2}"
CRITERION_SAMPLES="${CHIO_CRITERION_SAMPLES:-30}"

case "$SAMPLES:$WARMUPS:$CRITERION_SAMPLES" in
  *[!0-9:]*)
    echo "benchmark sample and warmup counts must be nonnegative integers" >&2
    exit 2
    ;;
esac
if [[ "$SAMPLES" -lt 2 || "$CRITERION_SAMPLES" -lt 10 ]]; then
  echo "CHIO_BENCH_SAMPLES must be at least 2 and CHIO_CRITERION_SAMPLES at least 10" >&2
  exit 2
fi

mkdir -p "$RESULT_DIR" "$TARGET_DIR"
cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

RAW_CSV="$RESULT_DIR/bilateral-admission-raw.csv"
COMPONENT_CSV="$RESULT_DIR/bilateral-admission-components.csv"
RESULT_JSON="$RESULT_DIR/bilateral-admission.json"
INLINE="$RESULT_DIR/bilateral-admission-inline.tex"
ENVIRONMENT="$RESULT_DIR/bilateral-admission-environment.txt"
BUILD_LOG="$RESULT_DIR/bilateral-admission-build.log"
CRITERION_LOG="$RESULT_DIR/bilateral-admission-criterion.log"
NEGATIVE_LOG="$RESULT_DIR/bilateral-admission-negative-matrix.log"

emit_unreported() {
  printf '\\textnormal{[unreported]}\n' > "$INLINE"
}
trap 'emit_unreported' ERR

(
  cd "$SOURCE"
  {
    printf '%s\n' "$SOURCE_COMMIT"
    if [[ "$SOURCE_DIRTY" == true ]]; then
      printf 'worktree=dirty\n'
    else
      printf 'worktree=clean\n'
    fi
    rustc -Vv
    cargo -V
    uname -a
    if command -v lscpu >/dev/null 2>&1; then
      lscpu
    fi
    if [[ -r /proc/meminfo ]]; then
      sed -n '1,3p' /proc/meminfo
    fi
    printf 'profile=release\n'
    printf 'end_to_end_samples=%s\n' "$SAMPLES"
    printf 'end_to_end_warmups=%s\n' "$WARMUPS"
    printf 'criterion_samples=%s\n' "$CRITERION_SAMPLES"
    printf 'runtime_stores=SQLite\n'
  } > "$ENVIRONMENT"

  CARGO_TARGET_DIR="$TARGET_DIR" cargo build --release -p chio-cli --bin chio
  CARGO_TARGET_DIR="$TARGET_DIR" cargo build --release \
    -p chio-spec-validate --bin chio-spec-validate
) > "$BUILD_LOG" 2>&1

CHIO_BIN="$TARGET_DIR/release/chio"
SPEC_VALIDATE_BIN="$TARGET_DIR/release/chio-spec-validate"
if [[ ! -x "$CHIO_BIN" || ! -x "$SPEC_VALIDATE_BIN" ]]; then
  echo "release benchmark binaries were not produced" >&2
  exit 1
fi

run_criterion_bench() {
  local package="$1"
  local bench="$2"
  (
    cd "$SOURCE"
    CARGO_TARGET_DIR="$TARGET_DIR" cargo bench -p "$package" --bench "$bench" -- \
      --sample-size "$CRITERION_SAMPLES" \
      --warm-up-time 1 \
      --measurement-time 3 \
      --noplot
  ) >> "$CRITERION_LOG" 2>&1
}

: > "$CRITERION_LOG"
run_criterion_bench chio-kernel paper_security_components
run_criterion_bench chio-federation bilateral_verify
run_criterion_bench chio-runtime-core cross_boundary_admission
run_criterion_bench chio-attest-buyer-core buyer_verify

printf 'path,sample,elapsed_ns,proof_package_bytes\n' > "$RAW_CSV"

run_hero_sample() {
  local mode="$1"
  local label="$2"
  local sample="$3"
  local out_dir="$WORK_DIR/$label-$sample"
  local log="$WORK_DIR/$label-$sample.log"
  local start_ns
  local end_ns
  start_ns="$(date +%s%N)"
  if ! (
    cd "$SOURCE"
    CHIO_BIN="$CHIO_BIN" \
      CHIO_SPEC_VALIDATE_BIN="$SPEC_VALIDATE_BIN" \
      CHIO_HERO_OUTPUT_DIR="$out_dir" \
      bash scripts/check-chio-treaty-buyer-hero-loop.sh "$mode"
  ) > "$log" 2>&1; then
    cp "$log" "$RESULT_DIR/bilateral-admission-$label-failure.log"
    return 1
  fi
  end_ns="$(date +%s%N)"
  local proof_bytes
  proof_bytes="$(stat -c %s "$out_dir/proof-package.json")"
  printf '%s,%s,%s,%s\n' \
    "$label" "$sample" "$((end_ns - start_ns))" "$proof_bytes" >> "$RAW_CSV"
}

for warmup in $(seq 1 "$WARMUPS"); do
  run_hero_sample --producer-only producer_warmup "$warmup"
  run_hero_sample --packet-only full_warmup "$warmup"
done

for sample in $(seq 1 "$SAMPLES"); do
  run_hero_sample --producer-only producer_without_buyer_review "$sample"
done
for sample in $(seq 1 "$SAMPLES"); do
  run_hero_sample --packet-only full_receiver_admission "$sample"
done

negative_start_ns="$(date +%s%N)"
if ! (
  cd "$SOURCE"
  CARGO_TARGET_DIR="$TARGET_DIR" \
    CHIO_TEST_PROFILE=release \
    bash scripts/check-chio-live-treaty-buyer-closure.sh --matrix-only
) > "$NEGATIVE_LOG" 2>&1; then
  exit 1
fi
negative_end_ns="$(date +%s%N)"
negative_elapsed_ns=$((negative_end_ns - negative_start_ns))

python - "$TARGET_DIR" "$RAW_CSV" "$COMPONENT_CSV" "$RESULT_JSON" "$INLINE" \
  "$SOURCE" "$SAMPLES" "$WARMUPS" "$CRITERION_SAMPLES" "$negative_elapsed_ns" \
  "$SOURCE_COMMIT" "$SOURCE_DIRTY" "$BENCHMARK_INPUT_TREE_SHA256" <<'PY'
import csv
import json
import math
import pathlib
import sys

(
    target_dir,
    raw_csv,
    component_csv,
    result_json,
    inline,
    source,
    samples,
    warmups,
    criterion_samples,
    negative_elapsed_ns,
    source_commit,
    source_dirty,
    benchmark_input_tree_sha256,
) = sys.argv[1:]
target = pathlib.Path(target_dir)

criterion_cases = {
    "receipt_sign": ("receipt_sign", "buyer-closure-shaped Ed25519 receipt"),
    "receipt_verify": ("receipt_verify", "buyer-closure-shaped Ed25519 receipt"),
    "receipt_append_sqlite": ("receipt_append_sqlite", "production SQLite receipt store"),
    "treaty_predispatch_deny": (
        "treaty_predispatch_deny",
        "full kernel path; real hook, SQLite denial receipt, invocation counter",
    ),
    "strict_bilateral_dsse_verify": (
        "strict_bilateral_dsse_verify",
        "two signatures, embedded receipt, treaty bindings",
    ),
    "cross_boundary_admission_allow": (
        "cross_boundary_admission_allow",
        "receiver treaty scope and verified evidence",
    ),
    "buyer_proof_package_verify": (
        "buyer_proof_package_verify",
        "offline three-vendor receiver verification",
    ),
}

def percentile(values, quantile):
    ordered = sorted(values)
    index = max(0, math.ceil(quantile * len(ordered)) - 1)
    return ordered[index]

components = []
for directory_name, (label, note) in criterion_cases.items():
    sample_path = target / "criterion" / directory_name / "new" / "sample.json"
    if not sample_path.is_file():
        raise SystemExit(f"missing Criterion samples: {sample_path}")
    sample = json.loads(sample_path.read_text(encoding="utf-8"))
    observations_us = [
        float(elapsed_ns) / float(iterations) / 1000.0
        for elapsed_ns, iterations in zip(sample["times"], sample["iters"])
    ]
    components.append(
        {
            "component": label,
            "p50_us": percentile(observations_us, 0.50),
            "p99_us": percentile(observations_us, 0.99),
            "samples": len(observations_us),
            "note": note,
        }
    )

with open(raw_csv, newline="", encoding="utf-8") as raw_file:
    raw_rows = list(csv.DictReader(raw_file))

paths = {}
for row in raw_rows:
    if row["path"].endswith("_warmup"):
        continue
    paths.setdefault(row["path"], []).append(int(row["elapsed_ns"]))

path_summaries = {}
for label, observations_ns in paths.items():
    path_summaries[label] = {
        "p50_ms": percentile(observations_ns, 0.50) / 1_000_000.0,
        "p99_ms": percentile(observations_ns, 0.99) / 1_000_000.0,
        "samples": len(observations_ns),
    }

proof_sizes = {
    int(row["proof_package_bytes"])
    for row in raw_rows
    if row["path"] == "full_receiver_admission"
}
if len(proof_sizes) != 1:
    raise SystemExit(f"proof package size was not stable: {sorted(proof_sizes)}")
proof_package_bytes = proof_sizes.pop()

fixture_path = (
    pathlib.Path(source)
    / "examples/chio-3vendor/fixtures/treaty-runtime-negative-corpus.json"
)
threat_fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
threat_cases = len(threat_fixture["cases"])
assumptions = len(threat_fixture["assumptions"])
negative_ms = int(negative_elapsed_ns) / 1_000_000.0

with open(component_csv, "w", newline="", encoding="utf-8") as component_file:
    writer = csv.writer(component_file, lineterminator="\n")
    writer.writerow(["component", "p50_us", "p99_us", "samples", "note"])
    for component in components:
        writer.writerow(
            [
                component["component"],
                f'{component["p50_us"]:.3f}',
                f'{component["p99_us"]:.3f}',
                component["samples"],
                component["note"],
            ]
        )
    for label, summary in path_summaries.items():
        writer.writerow(
            [
                label,
                f'{summary["p50_ms"] * 1000.0:.3f}',
                f'{summary["p99_ms"] * 1000.0:.3f}',
                summary["samples"],
                "release binaries; process and schema-validation costs included",
            ]
        )

document = {
    "schema": "chio.programmable-sovereignty.bilateral-admission-results.v1",
    "commit": source_commit,
    "worktreeDirty": source_dirty == "true",
    "benchmarkInputTreeSha256": benchmark_input_tree_sha256,
    "profile": "release",
    "warmups": int(warmups),
    "samples": int(samples),
    "criterionSamples": int(criterion_samples),
    "stores": {
        "endToEnd": "SQLite",
        "receiptAppend": "SQLite",
    },
    "paths": path_summaries,
    "components": components,
    "negativeMatrix": {
        "cases": threat_cases,
        "elapsedMs": negative_ms,
        "explicitNonTestableAssumptions": assumptions,
    },
    "proofPackageBytes": proof_package_bytes,
    "anchorInclusion": "withheld_outside_core_claim",
}
pathlib.Path(result_json).write_text(
    json.dumps(document, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

full = path_summaries["full_receiver_admission"]
producer = path_summaries["producer_without_buyer_review"]
deny = next(
    component for component in components
    if component["component"] == "treaty_predispatch_deny"
)
component_by_name = {
    component["component"]: component
    for component in components
}
receipt_sign = component_by_name["receipt_sign"]
receipt_verify = component_by_name["receipt_verify"]
receipt_append = component_by_name["receipt_append_sqlite"]
bilateral_verify = component_by_name["strict_bilateral_dsse_verify"]
cross_boundary = component_by_name["cross_boundary_admission_allow"]
buyer_verify = component_by_name["buyer_proof_package_verify"]
proof_package_tex = f"{proof_package_bytes:,}".replace(",", "{,}")
macros = [
    ("PSFullAdmissionPFiftyMs", f'{full["p50_ms"]:.3f}'),
    ("PSFullAdmissionPNinetyNineMs", f'{full["p99_ms"]:.3f}'),
    ("PSFullAdmissionPFiftySec", f'{full["p50_ms"] / 1000.0:.3f}'),
    ("PSFullAdmissionPNinetyNineSec", f'{full["p99_ms"] / 1000.0:.3f}'),
    ("PSProducerPFiftyMs", f'{producer["p50_ms"]:.3f}'),
    ("PSProducerPNinetyNineMs", f'{producer["p99_ms"]:.3f}'),
    (
        "PSBuyerPathMedianDifferenceMs",
        f'{full["p50_ms"] - producer["p50_ms"]:.3f}',
    ),
    ("PSPredispatchDenyPFiftyUs", f'{deny["p50_us"]:.3f}'),
    ("PSPredispatchDenyPNinetyNineUs", f'{deny["p99_us"]:.3f}'),
    ("PSReceiptSignPFiftyUs", f'{receipt_sign["p50_us"]:.3f}'),
    ("PSReceiptSignPNinetyNineUs", f'{receipt_sign["p99_us"]:.3f}'),
    ("PSReceiptVerifyPFiftyUs", f'{receipt_verify["p50_us"]:.3f}'),
    ("PSReceiptVerifyPNinetyNineUs", f'{receipt_verify["p99_us"]:.3f}'),
    ("PSReceiptAppendPFiftyUs", f'{receipt_append["p50_us"]:.3f}'),
    ("PSReceiptAppendPNinetyNineUs", f'{receipt_append["p99_us"]:.3f}'),
    ("PSBilateralVerifyPFiftyUs", f'{bilateral_verify["p50_us"]:.3f}'),
    ("PSBilateralVerifyPNinetyNineUs", f'{bilateral_verify["p99_us"]:.3f}'),
    ("PSCrossBoundaryPFiftyUs", f'{cross_boundary["p50_us"]:.3f}'),
    ("PSCrossBoundaryPNinetyNineUs", f'{cross_boundary["p99_us"]:.3f}'),
    ("PSBuyerVerifyPFiftyUs", f'{buyer_verify["p50_us"]:.3f}'),
    ("PSBuyerVerifyPNinetyNineUs", f'{buyer_verify["p99_us"]:.3f}'),
    ("PSBuyerVerifyPFiftyMs", f'{buyer_verify["p50_us"] / 1000.0:.3f}'),
    ("PSNegativeMatrixSeconds", f'{negative_ms / 1000.0:.1f}'),
    ("PSProofPackageBytes", proof_package_tex),
    ("PSProofPackageKiB", f'{proof_package_bytes / 1024.0:.1f}'),
    ("PSThreatCaseCount", str(threat_cases)),
    ("PSPathSampleCount", str(samples)),
    ("PSCriterionSampleCount", str(criterion_samples)),
]
pathlib.Path(inline).write_text(
    "".join(
        f"\\newcommand{{\\{name}}}{{{value}}}\n"
        for name, value in macros
    ),
    encoding="utf-8",
)
PY

trap - ERR
printf 'bilateral admission benchmark complete: %s\n' "$RESULT_JSON"
