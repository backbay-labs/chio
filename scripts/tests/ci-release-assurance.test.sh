#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

python3 - <<'PY' "${REPO_ROOT}"
from __future__ import annotations

from pathlib import Path
import re
import sys

repo = Path(sys.argv[1])


def read(path: str) -> str:
    return (repo / path).read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def cargo_fuzz_bins() -> list[str]:
    text = read("fuzz/Cargo.toml")
    bins: list[str] = []
    for block in re.split(r"(?m)^\[\[bin\]\]\s*$", text)[1:]:
        match = re.search(r'(?m)^name\s*=\s*"([^"]+)"', block)
        if match:
            bins.append(match.group(1))
    return bins


def workflow_fuzz_targets() -> list[str]:
    text = read(".github/workflows/fuzz.yml")
    match = re.search(
        r"(?m)^        target:\n((?:          - [A-Za-z0-9_-]+\n)+)",
        text,
    )
    require(match is not None, "fuzz workflow target matrix was not found")
    return [
        line.split("-", 1)[1].strip()
        for line in match.group(1).splitlines()
        if line.strip().startswith("- ")
    ]


def check_apalache_temporal_wording() -> None:
    text = read(".github/workflows/apalache-temporal.yml")
    require(
        "advisory" not in text.lower(),
        "apalache-temporal.yml must not contain advisory wording",
    )


def check_fuzz_matrix_and_smoke_inventory() -> None:
    bins = cargo_fuzz_bins()
    targets = workflow_fuzz_targets()
    missing = sorted(set(bins) - set(targets))
    extra = sorted(set(targets) - set(bins))
    require(not missing, "fuzz workflow matrix omits Cargo targets: " + ", ".join(missing))
    require(not extra, "fuzz workflow matrix contains unknown targets: " + ", ".join(extra))

    smoke = read("fuzz/tests/smoke.rs")
    required_markers = [
        "fuzz_workflow_matrix_matches_cargo_bins",
        "all_matrix_targets_have_declared_smoke_posture",
        "CORPUS_SMOKE_TARGETS",
        "NO_IN_PROCESS_SMOKE_TARGETS",
    ]
    missing_markers = [marker for marker in required_markers if marker not in smoke]
    require(
        not missing_markers,
        "fuzz smoke tests lack inventory guard marker(s): " + ", ".join(missing_markers),
    )


def check_chio_cpp_drogon_coverage() -> None:
    text = read(".github/workflows/chio-cpp.yml")
    markers = [
        '"sdks/cpp/chio-drogon/**"',
        '"scripts/check-chio-drogon*.sh"',
        "./scripts/check-chio-drogon.sh",
        "./scripts/check-chio-drogon-release.sh",
    ]
    missing = [marker for marker in markers if marker not in text]
    require(not missing, "chio-cpp workflow missing chio-drogon marker(s): " + ", ".join(missing))


def check_release_pypi_runs_local_tests_before_build() -> None:
    text = read(".github/workflows/release-pypi.yml")
    test_idx = text.find("name: Run package-local tests")
    build_idx = text.find("name: Build sdist and wheel")
    require(test_idx >= 0, "release-pypi workflow must have a package-local test step")
    require(build_idx >= 0, "release-pypi workflow build step was not found")
    require(test_idx < build_idx, "package-local tests must run before sdist and wheel build")
    require("uv run --extra dev pytest" in text, "package-local test step must run pytest with dev extras")
    require("find tests" in text, "package-local test step must only run where tests exist")


def check_ttfrh_container_lane_is_not_echo_only() -> None:
    text = read(".github/workflows/ttfrh.yml")
    require("docker run" in text, "ttfrh container lane must execute a real container")
    require(
        "cargo run -p ttfrh-bench --release -- --all --p99-budget-ms 60000" in text,
        "ttfrh container lane must run the TTFRH bench inside the container",
    )


checks = [
    check_apalache_temporal_wording,
    check_fuzz_matrix_and_smoke_inventory,
    check_chio_cpp_drogon_coverage,
    check_release_pypi_runs_local_tests_before_build,
    check_ttfrh_container_lane_is_not_echo_only,
]

failures: list[str] = []
for check in checks:
    try:
        check()
    except AssertionError as exc:
        failures.append(f"{check.__name__}: {exc}")

if failures:
    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    raise SystemExit(1)

print("PASS: CI release assurance findings are guarded")
PY
