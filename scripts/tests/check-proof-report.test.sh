#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

tmp_dir="$(mktemp -d)"
trace_generated_paths=(
  target/formal/trace-validation.json
  target/formal/receipt-trace/bindings.json
  target/formal/receipt-trace/conformance.ndjson
  target/formal/receipt-trace/conformance.itf.json
  target/formal/receipt-trace/conformance-witness.itf.json
  target/formal/receipt-trace/conformance-observer-key.txt
  target/formal/receipt-trace/native-results.json
  target/formal/receipt-trace/native-report.md
  target/formal/receipt-trace/fixture-http.log
  target/formal/receipt-trace/fixture-good.itf.json
  target/formal/receipt-trace/fixture-good-witness.itf.json
  target/formal/receipt-trace/fixture-good-report.json
  target/formal/receipt-trace/fixture-bad.itf.json
  target/formal/receipt-trace/fixture-bad-witness.itf.json
  target/formal/receipt-trace/fixture-bad-report.json
  target/formal/receipt-trace/fixture-bad.log
)
for slug in "" -monotone -attenuation -freshness; do
  base="target/formal/receipt-trace/runtime-negative${slug}"
  trace_generated_paths+=(
    "${base}.ndjson"
    "${base}.itf.json"
    "${base}-witness.itf.json"
    "${base}-report.json"
    "${base}.log"
  )
done
managed_paths=(
  formal/proof-manifest.toml
  crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs
  crates/protocol/chio-mcp-edge/src/runtime/tool_calls.rs
  docs/reference/CLAIM_REGISTRY.md
  docs/formal/COVERAGE.md
  target/formal/coverage.json
  target/formal/aeneas-production/llbc/formal_aeneas.llbc
  target/formal/aeneas-production/lean/Funs.lean
  target/formal/aeneas-production/lean/Types.lean
  target/formal/aeneas-production/economy/llbc/formal_economy.llbc
  target/formal/aeneas-production/economy/lean/Funs.lean
  target/formal/aeneas-production/economy/lean/Types.lean
  target/formal/aeneas-production/equivalence-artifacts.json
  target/formal/aeneas-production/negative-tests.json
  "${trace_generated_paths[@]}"
)

for path in "${managed_paths[@]}"; do
  if [[ -e "${path}" || -L "${path}" ]]; then
    mkdir -p "${tmp_dir}/backup/$(dirname "${path}")"
    cp -a "${path}" "${tmp_dir}/backup/${path}"
    printf '%s\n' "${path}" >>"${tmp_dir}/present"
  fi
done

cleanup() {
  rm -rf target/formal/proof-report-test target/formal/repo-link
  rm -f \
    target/formal/test-proof-report.json \
    target/formal/failing-proof-report.json \
    target/formal/source-link.json
  for path in "${managed_paths[@]}"; do
    rm -f "${path}"
    if grep -Fxq "${path}" "${tmp_dir}/present" 2>/dev/null; then
      mkdir -p "$(dirname "${path}")"
      cp -a "${tmp_dir}/backup/${path}" "${path}"
    fi
  done
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

python3 - <<'PY'
from pathlib import Path

manifest = Path("formal/proof-manifest.toml")
text = manifest.read_text(encoding="utf-8")
command = '  "cargo xtask gen proof-coverage --check",\n'
if command not in text:
    marker = "gate_commands = [\n"
    if marker not in text:
        raise SystemExit("proof manifest lacks gate_commands")
    text = text.replace(marker, marker + command, 1)
    manifest.write_text(text, encoding="utf-8")

claim_registry = Path("docs/reference/CLAIM_REGISTRY.md")
claim_text = claim_registry.read_text(encoding="utf-8")
if "docs/formal/COVERAGE.md" not in claim_text:
    claim_registry.write_text(
        claim_text + "\nProof coverage: `docs/formal/COVERAGE.md`.\n",
        encoding="utf-8",
    )

coverage_doc = Path("docs/formal/COVERAGE.md")
if not coverage_doc.exists():
    coverage_doc.write_text(
        "<!-- Proof-report contract fixture. -->\n# Proof Coverage\n",
        encoding="utf-8",
    )
PY

real_git="$(command -v git)"
mkdir -p "${tmp_dir}/bin"
cat >"${tmp_dir}/bin/cargo" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >>"${MOCK_CARGO_LOG}"
if [[ "$*" == "xtask gen proof-coverage --check" ]]; then
  if [[ "${MOCK_COVERAGE_FAIL:-0}" == "1" ]]; then
    echo "mock coverage failure" >&2
    exit 9
  fi
  mkdir -p target/formal
  python3 - <<'PY'
import json
import subprocess
from pathlib import Path

commit = subprocess.run(
    ["git", "rev-parse", "HEAD"],
    check=True,
    text=True,
    stdout=subprocess.PIPE,
).stdout.strip()
Path("target/formal/coverage.json").write_text(
    json.dumps({"schema": "chio.proof-coverage.v1", "commit": commit}) + "\n",
    encoding="utf-8",
)
PY
  exit 0
fi
case "$*" in
  "--version")
    echo "cargo fixture version"
    exit 0
    ;;
  "kani --version")
    echo "cargo-kani fixture"
    exit 0
    ;;
  "creusot version")
    echo "cargo-creusot fixture"
    exit 0
    ;;
esac
echo "unexpected Cargo invocation in proof-report fixture: $*" >&2
exit 97
SH
chmod +x "${tmp_dir}/bin/cargo"
cat >"${tmp_dir}/bin/git" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

if [[ "$*" == "status --short" ]]; then
  if [[ -n "${MOCK_GIT_DIRTY:-}" ]]; then
    printf '%s\n' "${MOCK_GIT_DIRTY}"
  fi
  exit 0
fi
exec "${REAL_GIT}" "$@"
SH
chmod +x "${tmp_dir}/bin/git"
for tool in lean lake aeneas charon apalache-mc; do
  cat >"${tmp_dir}/bin/${tool}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
echo "$(basename "$0") fixture version"
SH
  chmod +x "${tmp_dir}/bin/${tool}"
done
export REAL_GIT="${real_git}"
export MOCK_CARGO_LOG="${tmp_dir}/cargo.log"
export PATH="${tmp_dir}/bin:${PATH}"

: >"${MOCK_CARGO_LOG}"
if bash scripts/generate-proof-report.sh --invalid >"${tmp_dir}/invalid-arg.out" 2>&1; then
  echo "proof-report generator accepted an invalid argument" >&2
  exit 1
fi
if [[ -s "${MOCK_CARGO_LOG}" ]]; then
  echo "proof-report generator ran coverage before argument validation" >&2
  exit 1
fi

: >"${MOCK_CARGO_LOG}"
if MOCK_GIT_DIRTY=' M formal/proof-manifest.toml' \
  CHIO_PROOF_REPORT_PATH=target/formal/proof-report-test/dirty.json \
  bash scripts/generate-proof-report.sh >"${tmp_dir}/dirty-generator.out" 2>&1; then
  echo "strict proof-report generator accepted a dirty worktree" >&2
  exit 1
fi
if ! grep -Fq 'strict proof reports require a clean git worktree before gates run' \
  "${tmp_dir}/dirty-generator.out"; then
  cat "${tmp_dir}/dirty-generator.out" >&2
  exit 1
fi
if [[ -s "${MOCK_CARGO_LOG}" ]]; then
  echo "strict proof-report generator ran coverage on a dirty worktree" >&2
  exit 1
fi
if CHIO_RUST_VERIFICATION_METADATA_ONLY=invalid \
  bash scripts/generate-proof-report.sh >"${tmp_dir}/invalid-mode.out" 2>&1; then
  echo "proof-report generator accepted an invalid metadata mode" >&2
  exit 1
fi
if [[ -s "${MOCK_CARGO_LOG}" ]]; then
  echo "proof-report generator ran coverage before mode validation" >&2
  exit 1
fi

source_hash="$(sha256sum formal/proof-manifest.toml | awk '{print $1}')"
if CHIO_PROOF_REPORT_PATH=formal/proof-manifest.toml \
  bash scripts/generate-proof-report.sh --no-run-gates \
  >"${tmp_dir}/tracked-path.out" 2>&1; then
  echo "proof-report generator accepted a tracked output path" >&2
  exit 1
fi
grep -Fq 'must stay under target/formal' "${tmp_dir}/tracked-path.out"
test "$(sha256sum formal/proof-manifest.toml | awk '{print $1}')" = "${source_hash}"

mkdir -p target/formal
rm -f target/formal/repo-link
ln -s "${PWD}" target/formal/repo-link
if CHIO_PROOF_REPORT_PATH=target/formal/repo-link/formal/proof-manifest.json \
  bash scripts/generate-proof-report.sh --no-run-gates \
  >"${tmp_dir}/parent-link.out" 2>&1; then
  echo "proof-report generator followed a report-parent symlink" >&2
  exit 1
fi
grep -Fq 'refusing symlinked report parent' "${tmp_dir}/parent-link.out"
test "$(sha256sum formal/proof-manifest.toml | awk '{print $1}')" = "${source_hash}"

ln -s "${PWD}/formal/proof-manifest.toml" target/formal/source-link.json
if CHIO_PROOF_REPORT_PATH=target/formal/source-link.json \
  bash scripts/generate-proof-report.sh --no-run-gates \
  >"${tmp_dir}/leaf-link.out" 2>&1; then
  echo "proof-report generator followed a report-file symlink" >&2
  exit 1
fi
grep -Fq 'refusing symlinked report file' "${tmp_dir}/leaf-link.out"
test "$(sha256sum formal/proof-manifest.toml | awk '{print $1}')" = "${source_hash}"

report="target/formal/test-proof-report.json"
CHIO_RUST_VERIFICATION_METADATA_ONLY=1 \
CHIO_PROOF_REPORT_PATH="${report}" \
  bash scripts/generate-proof-report.sh
CHIO_PROOF_REPORT_PATH="${report}" bash scripts/check-proof-report.sh \
  >"${tmp_dir}/metadata.out" 2>&1
grep -Fq 'only coverage preflight was executed' "${tmp_dir}/metadata.out"

adapter_source="crates/protocol/chio-mcp-edge/src/runtime/tool_calls.rs"
printf '\n// proof-report adapter source mutation fixture\n' >>"${adapter_source}"
if CHIO_PROOF_REPORT_PATH="${report}" bash scripts/check-proof-report.sh \
  >"${tmp_dir}/adapter-source-mutation.out" 2>&1; then
  echo "proof-report checker accepted a changed adapter gate source" >&2
  exit 1
fi
grep -Fq "tracked hashes hash does not match disk: ${adapter_source}" \
  "${tmp_dir}/adapter-source-mutation.out"
cp -a "${tmp_dir}/backup/${adapter_source}" "${adapter_source}"

kani_source="crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs"
printf '\n// proof-report Kani source mutation fixture\n' >>"${kani_source}"
if CHIO_PROOF_REPORT_PATH="${report}" bash scripts/check-proof-report.sh \
  >"${tmp_dir}/kani-source-mutation.out" 2>&1; then
  echo "proof-report checker accepted a changed Kani proof source" >&2
  exit 1
fi
grep -Fq "tracked hashes hash does not match disk: ${kani_source}" \
  "${tmp_dir}/kani-source-mutation.out"
cp -a "${tmp_dir}/backup/${kani_source}" "${kani_source}"

python3 - "${report}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if report.get("mode") != "metadata_only":
    raise SystemExit("generator did not record metadata_only mode")
statuses = {
    result["command"]: result["status"] for result in report.get("gateResults", [])
}
if statuses.get("cargo xtask gen proof-coverage --check") != "passed":
    raise SystemExit("coverage preflight was not recorded as passed")
if any(
    status != "not_run"
    for command, status in statuses.items()
    if command != "cargo xtask gen proof-coverage --check"
):
    raise SystemExit("metadata-only generator executed a proof gate")
tracked = report.get("artifactHashes", {}).get("tracked", {})
for required in (
    ".kani/harnesses.toml",
    "Cargo.toml",
    "rust-toolchain.toml",
    "formal/adapter-source-inventory.toml",
    "formal/rust-verification/creusot-contracts.toml",
    "formal/rust-verification/kani-harnesses.toml",
    "formal/rust-verification/kani-public-harnesses.toml",
    "formal/rust-verification/creusot-core/Cargo.lock",
    "formal/rust-verification/creusot-core/Cargo.toml",
    "formal/rust-verification/creusot-core/src/lib.rs",
    "formal/rust-verification/creusot-core/why3find.json",
    "docs/formal/COVERAGE.md",
    "docs/reference/CLAIM_REGISTRY.md",
    "docs/release/RISK_REGISTER.md",
    "docs/start-here/VISION.md",
    "spec/PROTOCOL.md",
    "scripts/generate-proof-report.sh",
    "scripts/check-proof-report.sh",
    "scripts/check-creusot-body-sync.sh",
    "scripts/check-creusot-smoke.sh",
    "scripts/check-kani-smoke.sh",
    "scripts/run-kani-manifest.sh",
    "scripts/lean-assumption-audit.lean",
    "scripts/tests/lean-assumption-audit.test.sh",
    "xtask/src/adapter_no_bypass.rs",
    "xtask/src/cli.rs",
    "xtask/src/dispatch.rs",
    "xtask/src/error.rs",
    "xtask/src/main.rs",
    "xtask/src/support.rs",
    "crates/kernel/chio-kernel-core/Cargo.toml",
    "crates/kernel/chio-kernel-core/src/kani_harnesses.rs",
    "crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs",
    "crates/trust/chio-attest-verify/build.rs",
    "crates/protocol/chio-mcp-edge/src/runtime/tool_calls.rs",
):
    if tracked.get(required) != hashlib.sha256(Path(required).read_bytes()).hexdigest():
        raise SystemExit(f"proof report lacks the current hash for {required}")
coverage = report.get("proofCoverage", {})
if coverage.get("path") != "target/formal/coverage.json" or not coverage.get("sha256"):
    raise SystemExit("proof report lacks the generated coverage hash")
if "does not replay proof commands" not in report.get("evidenceBoundary", ""):
    raise SystemExit("proof report does not state its evidence boundary")
locations = report.get("sourceLocations", {})
for theorem_id in (
    "core.scope.empty_isSubsetOf",
    "core.tool_grant.isSubsetOf_refl",
):
    if not isinstance(locations.get(theorem_id, {}).get("line"), int):
        raise SystemExit(f"proof report did not resolve qualified declaration {theorem_id}")
if any(
    not isinstance(location.get("line"), int) or location["line"] <= 0
    for location in locations.values()
):
    raise SystemExit("proof report contains an unresolved source location")
PY

mkdir -p \
  target/formal/aeneas-production/llbc \
  target/formal/aeneas-production/lean \
  target/formal/aeneas-production/economy/llbc \
  target/formal/aeneas-production/economy/lean
printf '%s\n' llbc >target/formal/aeneas-production/llbc/formal_aeneas.llbc
printf '%s\n' funs >target/formal/aeneas-production/lean/Funs.lean
printf '%s\n' types >target/formal/aeneas-production/lean/Types.lean
printf '%s\n' economy-llbc >target/formal/aeneas-production/economy/llbc/formal_economy.llbc
printf '%s\n' economy-funs >target/formal/aeneas-production/economy/lean/Funs.lean
printf '%s\n' economy-types >target/formal/aeneas-production/economy/lean/Types.lean
printf '%s\n' '{}' >target/formal/aeneas-production/equivalence-artifacts.json
python3 - <<'PY'
import hashlib
import json
import tomllib
from pathlib import Path

registry_path = Path("formal/aeneas/negative-tests.toml")
registry_bytes = registry_path.read_bytes()
registry = tomllib.loads(registry_bytes.decode("utf-8"))
results = [
    {
        "name": mutation["name"],
        "status": "killed",
        "expectedGate": mutation["expected_gate"],
        "expectedEvidence": mutation["expected_evidence"],
        "logSha256": "0" * 64,
    }
    for mutation in registry["mutation"]
]
Path("target/formal/aeneas-production/negative-tests.json").write_text(
    json.dumps(
        {
            "schema": "chio.aeneas-negative-tests-report.v1",
            "registry": str(registry_path),
            "registrySha256": hashlib.sha256(registry_bytes).hexdigest(),
            "results": results,
        }
    ),
    encoding="utf-8",
)
PY

python3 - "${tmp_dir}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

tmp_dir = Path(sys.argv[1]).resolve()
trace_generated = [
    "target/formal/trace-validation.json",
    "target/formal/receipt-trace/bindings.json",
    "target/formal/receipt-trace/conformance.ndjson",
    "target/formal/receipt-trace/conformance.itf.json",
    "target/formal/receipt-trace/conformance-witness.itf.json",
    "target/formal/receipt-trace/conformance-observer-key.txt",
    "target/formal/receipt-trace/native-results.json",
    "target/formal/receipt-trace/native-report.md",
    "target/formal/receipt-trace/fixture-http.log",
    "target/formal/receipt-trace/fixture-good.itf.json",
    "target/formal/receipt-trace/fixture-good-witness.itf.json",
    "target/formal/receipt-trace/fixture-good-report.json",
    "target/formal/receipt-trace/fixture-bad.itf.json",
    "target/formal/receipt-trace/fixture-bad-witness.itf.json",
    "target/formal/receipt-trace/fixture-bad-report.json",
    "target/formal/receipt-trace/fixture-bad.log",
]
for slug in ("", "-monotone", "-attenuation", "-freshness"):
    base = f"target/formal/receipt-trace/runtime-negative{slug}"
    trace_generated.extend(
        [
            f"{base}.ndjson",
            f"{base}.itf.json",
            f"{base}-witness.itf.json",
            f"{base}-report.json",
            f"{base}.log",
        ]
    )

for raw_path in trace_generated:
    path = Path(raw_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.name != "bindings.json":
        path.write_text("proof-report trace fixture\n", encoding="utf-8")

invariants = [
    "NoAllowAfterRevoke",
    "MonotoneLog",
    "AttenuationPreserving",
    "RevocationFreshness",
]
checker_binary = (tmp_dir / "bin" / "apalache-mc").resolve()
timeout_binary = (tmp_dir / "bin" / "lean").resolve()

def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

trace_report = {
    "schema": "chio.trace-validation.v1",
    "status": "passed",
    "spec": "formal/tla/RevocationPropagation.tla",
    "traceId": "proof-report-fixture",
    "traceLength": 3,
    "itfStateCount": 5,
    "invariants": invariants,
    "actionCoverage": {
        "revoke": 1,
        "evaluate": 2,
        "postRevocationEvaluate": 1,
    },
    "invariantWitnesses": {
        "allowReceipt": 1,
        "orderedReceiptPair": 1,
        "attenuatedAdmission": 1,
        "nonzeroRevocationEpoch": 1,
    },
    "checker": "Apalache 0.50.1 fixture",
    "checkerBinarySha256": sha256(checker_binary),
    "timeoutBinarySha256": sha256(timeout_binary),
}
trace_report_path = Path("target/formal/trace-validation.json")
trace_report_path.write_text(json.dumps(trace_report) + "\n", encoding="utf-8")

negative_reports = {
    "NoAllowAfterRevoke": "target/formal/receipt-trace/runtime-negative-report.json",
    "MonotoneLog": "target/formal/receipt-trace/runtime-negative-monotone-report.json",
    "AttenuationPreserving": "target/formal/receipt-trace/runtime-negative-attenuation-report.json",
    "RevocationFreshness": "target/formal/receipt-trace/runtime-negative-freshness-report.json",
}
for invariant, raw_path in negative_reports.items():
    report = {
        "schema": "chio.trace-validation.v1",
        "status": "failed",
        "divergence": {
            "failedConjunct": invariant,
            "apalacheEvaluation": {name: name != invariant for name in invariants},
        },
    }
    Path(raw_path).write_text(json.dumps(report) + "\n", encoding="utf-8")

bound_paths = [
    path
    for path in trace_generated
    if path != "target/formal/receipt-trace/bindings.json"
]
bound_paths.extend(
    [
        "formal/tla/RevocationPropagation.tla",
        "formal/tla/trace/TraceCheckRevocationPropagation.tla",
        "formal/tla/trace/TraceEvaluateRevocationPropagation.tla",
        "formal/tla/trace/fixtures/native-conformance-observer-key.txt",
        "formal/tla/trace/negative-registry.toml",
    ]
)
artifact_paths = {"report": "target/formal/trace-validation.json"}
for index, raw_path in enumerate(bound_paths):
    if raw_path != "target/formal/trace-validation.json":
        artifact_paths[f"artifact{index:02d}"] = raw_path
artifact_paths["checkerBinary"] = str(checker_binary)
artifact_paths["timeoutBinary"] = str(timeout_binary)
artifact_hashes = {
    name: sha256(Path(raw_path)) for name, raw_path in artifact_paths.items()
}
bindings = {
    "schema": "chio.trace-artifact-bindings.v1",
    "status": "passed",
    "artifactPaths": artifact_paths,
    "artifactHashes": artifact_hashes,
}
Path("target/formal/receipt-trace/bindings.json").write_text(
    json.dumps(bindings) + "\n", encoding="utf-8"
)
PY

strict_fixture="${tmp_dir}/strict-structural-fixture.json"
python3 - "${report}" "${strict_fixture}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

source, destination = map(Path, sys.argv[1:])
report = json.loads(source.read_text(encoding="utf-8"))
report["mode"] = "strict"
for result in report["gateResults"]:
    result["status"] = "passed"
    result["exitCode"] = 0
generated_paths = [
    "target/formal/aeneas-production/llbc/formal_aeneas.llbc",
    "target/formal/aeneas-production/lean/Funs.lean",
    "target/formal/aeneas-production/lean/Types.lean",
    "target/formal/aeneas-production/economy/llbc/formal_economy.llbc",
    "target/formal/aeneas-production/economy/lean/Funs.lean",
    "target/formal/aeneas-production/economy/lean/Types.lean",
    "target/formal/aeneas-production/equivalence-artifacts.json",
    "target/formal/aeneas-production/negative-tests.json",
    "target/formal/trace-validation.json",
    "target/formal/receipt-trace/bindings.json",
    "target/formal/receipt-trace/conformance.ndjson",
    "target/formal/receipt-trace/conformance.itf.json",
    "target/formal/receipt-trace/conformance-witness.itf.json",
    "target/formal/receipt-trace/conformance-observer-key.txt",
    "target/formal/receipt-trace/native-results.json",
    "target/formal/receipt-trace/native-report.md",
    "target/formal/receipt-trace/fixture-http.log",
    "target/formal/receipt-trace/fixture-good.itf.json",
    "target/formal/receipt-trace/fixture-good-witness.itf.json",
    "target/formal/receipt-trace/fixture-good-report.json",
    "target/formal/receipt-trace/fixture-bad.itf.json",
    "target/formal/receipt-trace/fixture-bad-witness.itf.json",
    "target/formal/receipt-trace/fixture-bad-report.json",
    "target/formal/receipt-trace/fixture-bad.log",
]
for slug in ("", "-monotone", "-attenuation", "-freshness"):
    base = f"target/formal/receipt-trace/runtime-negative{slug}"
    generated_paths.extend(
        [
            f"{base}.ndjson",
            f"{base}.itf.json",
            f"{base}-witness.itf.json",
            f"{base}-report.json",
            f"{base}.log",
        ]
    )
for path in generated_paths:
    report["artifactHashes"]["generated"][path] = hashlib.sha256(
        Path(path).read_bytes()
    ).hexdigest()
trace_report = json.loads(Path("target/formal/trace-validation.json").read_text())
report["traceValidation"] = {
    "result": "passed",
    "schema": trace_report["schema"],
    "spec": trace_report.get("spec"),
    "traceId": trace_report.get("traceId"),
    "traceLength": trace_report.get("traceLength"),
    "itfStateCount": trace_report.get("itfStateCount"),
    "invariants": trace_report["invariants"],
    "actionCoverage": trace_report["actionCoverage"],
    "invariantWitnesses": trace_report["invariantWitnesses"],
    "checker": trace_report.get("checker"),
    "checkerBinarySha256": trace_report.get("checkerBinarySha256"),
    "timeoutBinarySha256": trace_report.get("timeoutBinarySha256"),
    "reportPath": "target/formal/trace-validation.json",
    "bindingsPath": "target/formal/receipt-trace/bindings.json",
    "negativeRegistryPath": "formal/tla/trace/negative-registry.toml",
}
destination.write_text(json.dumps(report), encoding="utf-8")
PY
CHIO_PROOF_REPORT_PATH="${strict_fixture}" \
  bash scripts/check-proof-report.sh --require-strict

python3 - "${strict_fixture}" "${tmp_dir}" <<'PY'
import json
import sys
from copy import deepcopy
from pathlib import Path

source = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
output = Path(sys.argv[2])

def write(name, mutate):
    report = deepcopy(source)
    mutate(report)
    (output / f"{name}.json").write_text(json.dumps(report), encoding="utf-8")

write("wrong-command", lambda report: report["gateResults"][0].update(command="echo pass"))
write(
    "status-exit",
    lambda report: report["gateResults"][0].update(status="passed", exitCode=3),
)
write(
    "dummy-hash",
    lambda report: report["artifactHashes"]["tracked"].update(
        {"scripts/check-proof-report.sh": "0" * 64}
    ),
)
write(
    "failed-tool",
    lambda report: report["toolVersions"]["aeneas"].update(exitCode=1),
)
write(
    "forged-tool",
    lambda report: report["toolVersions"]["aeneas"].update(output=["forged"]),
)
write(
    "stale-commit",
    lambda report: report["git"]["commit"].update(output=["0" * 40]),
)
write(
    "missing-aeneas",
    lambda report: report["artifactHashes"]["generated"].pop(
        "target/formal/aeneas-production/lean/Funs.lean"
    ),
)
write(
    "evidence-boundary",
    lambda report: report.update(evidenceBoundary="proof commands replayed"),
)
write(
    "dirty-worktree",
    lambda report: report["git"]["dirty"].update(
        output=["M formal/proof-manifest.toml"]
    ),
)
write("extra-top-level", lambda report: report.update(forbiddenMetadata="must reject"))
write("extra-ci", lambda report: report["ci"].update(forbiddenMetadata="must reject"))
write(
    "extra-gate-result",
    lambda report: report["gateResults"][0].update(forbiddenMetadata="must reject"),
)
write(
    "extra-claim-gate",
    lambda report: report["claimGate"].update(forbiddenMetadata="must reject"),
)
write(
    "extra-artifact-hashes",
    lambda report: report["artifactHashes"].update(forbiddenMetadata="must reject"),
)
write(
    "extra-proof-coverage",
    lambda report: report["proofCoverage"].update(forbiddenMetadata="must reject"),
)
write(
    "extra-command-record",
    lambda report: report["toolVersions"]["aeneas"].update(
        forbiddenMetadata="must reject"
    ),
)
PY

expect_failure() {
  local fixture="$1"
  local expected="$2"
  if CHIO_PROOF_REPORT_PATH="${tmp_dir}/${fixture}.json" \
    bash scripts/check-proof-report.sh --require-strict \
    >"${tmp_dir}/${fixture}.out" 2>&1; then
    echo "invalid proof report passed: ${fixture}" >&2
    exit 1
  fi
  grep -Fq "${expected}" "${tmp_dir}/${fixture}.out"
}

expect_failure wrong-command 'exact unique manifest command order'
expect_failure status-exit 'passed gate has nonzero exitCode'
expect_failure dummy-hash 'hash does not match disk'
expect_failure failed-tool 'did not record a successful probe'
expect_failure forged-tool 'strict tool probe output is stale or forged'
expect_failure stale-commit 'report commit does not match HEAD'
expect_failure missing-aeneas 'generated hashes path set mismatch'
expect_failure evidence-boundary 'evidenceBoundary does not describe the checker trust boundary'
expect_failure extra-top-level 'top-level key set mismatch'
expect_failure extra-ci 'ci key set mismatch'
expect_failure extra-gate-result 'gateResults[0] key set mismatch'
expect_failure extra-claim-gate 'claimGate key set mismatch'
expect_failure extra-artifact-hashes 'artifactHashes key set mismatch'
expect_failure extra-proof-coverage 'proofCoverage key set mismatch'
expect_failure extra-command-record 'toolVersions.aeneas key set mismatch'

if MOCK_GIT_DIRTY=' M formal/proof-manifest.toml' \
  CHIO_PROOF_REPORT_PATH="${tmp_dir}/dirty-worktree.json" \
  bash scripts/check-proof-report.sh --require-strict \
  >"${tmp_dir}/dirty-worktree.out" 2>&1; then
  echo "strict proof-report checker accepted a dirty worktree" >&2
  exit 1
fi
grep -Fq 'strict proof reports require a clean git worktree' \
  "${tmp_dir}/dirty-worktree.out"

cp target/formal/coverage.json "${tmp_dir}/coverage-valid.json"
python3 - "${strict_fixture}" "${tmp_dir}/stale-coverage.json" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

source, destination = map(Path, sys.argv[1:])
coverage_path = Path("target/formal/coverage.json")
coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
coverage["commit"] = "0" * 40
coverage_path.write_text(json.dumps(coverage) + "\n", encoding="utf-8")
digest = hashlib.sha256(coverage_path.read_bytes()).hexdigest()
report = json.loads(source.read_text(encoding="utf-8"))
report["proofCoverage"]["sha256"] = digest
report["artifactHashes"]["generated"]["target/formal/coverage.json"] = digest
destination.write_text(json.dumps(report), encoding="utf-8")
PY
expect_failure stale-coverage 'coverage artifact commit does not match HEAD'
mv "${tmp_dir}/coverage-valid.json" target/formal/coverage.json

if GITHUB_SHA="$(printf '0%.0s' {1..40})" \
  CHIO_PROOF_REPORT_PATH="${strict_fixture}" \
  bash scripts/check-proof-report.sh --require-strict \
  >"${tmp_dir}/github-sha.out" 2>&1; then
  echo "proof report accepted a mismatched GITHUB_SHA" >&2
  exit 1
fi
grep -Fq 'not bound to one commit' "${tmp_dir}/github-sha.out"

MOCK_COVERAGE_FAIL=1 \
CHIO_RUST_VERIFICATION_METADATA_ONLY=1 \
CHIO_PROOF_REPORT_PATH=target/formal/failing-proof-report.json \
  bash scripts/generate-proof-report.sh >"${tmp_dir}/coverage-fail.out" 2>&1 && {
    echo "proof-report generator accepted a failed coverage preflight" >&2
    exit 1
  }
test -f target/formal/failing-proof-report.json
grep -Fq 'gate failed: cargo xtask gen proof-coverage --check' \
  "${tmp_dir}/coverage-fail.out"

if bash scripts/generate-proof-report.sh --no-run-gates extra >/dev/null 2>&1; then
  echo "proof-report generator accepted extra arguments" >&2
  exit 1
fi
if CHIO_PROOF_REPORT_PATH="${strict_fixture}" \
  bash scripts/check-proof-report.sh --require-strict extra >/dev/null 2>&1; then
  echo "proof-report checker accepted extra arguments" >&2
  exit 1
fi

echo "Proof report content contract passed"
