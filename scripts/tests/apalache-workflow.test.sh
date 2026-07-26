#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

python3 - <<'PY'
from pathlib import Path
import re
import tomllib

safety = Path(".github/workflows/apalache-safety.yml").read_text(encoding="utf-8")
temporal = Path(".github/workflows/apalache-temporal.yml").read_text(encoding="utf-8")
distributed = Path("scripts/check-distributed-revocation-temporal.sh").read_text(
    encoding="utf-8"
)


def job(source: str, name: str, next_name: str | None) -> str:
    start_marker = f"\n  {name}:\n"
    start = source.index(start_marker) + 1
    if next_name is None:
        return source[start:]
    end = source.index(f"\n  {next_name}:\n", start)
    return source[start:end]


shards = job(safety, "apalache_safety_shards", "apalache_scheduled_bounds_and_refinement")
scheduled = job(
    safety,
    "apalache_scheduled_bounds_and_refinement",
    "apalache_verdict",
)
verdict = job(safety, "apalache_verdict", "apalache-negative")
legacy_job = job(
    temporal,
    "revocation_eventually_seen",
    "distributed_revocation_temporal",
)
distributed_job = job(
    temporal,
    "distributed_revocation_temporal",
    "temporal_verdict",
)
temporal_verdict = job(temporal, "temporal_verdict", None)

assert "timeout-minutes: 360" in shards
assert "fail-fast: false" in shards
assert shards.count("            config:") == 9
timeouts = [int(value) for value in re.findall(r"timeout_seconds: ([0-9]+)", shards)]
assert len(timeouts) == 9
assert sum(timeouts) == 33_000
assert max(timeouts) < 360 * 60
assert shards.count("./scripts/check-apalache-positive.sh") == 1

assert "if: github.event_name != 'pull_request'" in scheduled
assert "timeout-minutes: 360" in scheduled
assert scheduled.count("./scripts/check-apalache-positive.sh") == 2
assert scheduled.count("--timeout-seconds 3600") == 2

assert safety.count("name: apalache-subset") == 1
assert "if: ${{ always() }}" in verdict
for dependency in (
    "apalache_contracts",
    "apalache_safety_shards",
    "apalache_scheduled_bounds_and_refinement",
):
    assert f"      - {dependency}" in verdict
assert '[[ "${SCHEDULED_RESULT}" != "skipped" ]]' in verdict
assert '[[ "${SCHEDULED_RESULT}" != "success" ]]' in verdict
assert "apalache-mc check" not in safety
assert "apalache-mc check" not in temporal

assert "timeout-minutes: 120" in distributed_job
legacy_outer_timeout = int(re.search(r"timeout-minutes: ([0-9]+)", legacy_job).group(1))
legacy_inner_timeout = int(re.search(r"--timeout-seconds ([0-9]+)", legacy_job).group(1))
assert legacy_inner_timeout == 3600
assert legacy_outer_timeout * 60 == legacy_inner_timeout + 900
assert legacy_job.count("./scripts/check-apalache-positive.sh") == 1
assert "if: ${{ always() }}" in temporal_verdict
for dependency in ("revocation_eventually_seen", "distributed_revocation_temporal"):
    assert f"      - {dependency}" in temporal_verdict
assert (
    '[[ "${LEGACY_RESULT}" != "success" || "${DISTRIBUTED_RESULT}" != "success" ]]'
    in temporal_verdict
)
assert distributed.count("./scripts/check-apalache-positive.sh") == 3
assert "--timeout-seconds 1800" in distributed
assert "--timeout-seconds 300" in distributed

path_block = re.search(
    r'(?m)^    paths:\n((?:      - "[^"]+"\n)+)',
    safety,
)
assert path_block is not None
workflow_paths = set(re.findall(r'(?m)^      - "([^"]+)"$', path_block.group(1)))


def path_is_covered(source: str) -> bool:
    return any(
        pattern == source
        or (pattern.endswith("/**") and source.startswith(f"{pattern[:-3]}/"))
        for pattern in workflow_paths
    )


with Path("formal/proof-manifest.toml").open("rb") as handle:
    manifest = tomllib.load(handle)
mirror_sources = {
    mirror["rust_source"]
    for mirror in manifest.get("mirror", [])
    if mirror.get("model_file", "").startswith(("formal/apalache/", "formal/tla/"))
}
assert not sorted(source for source in mirror_sources if not path_is_covered(source))

for path in (
    '"crates/kernel/chio-runtime-core/src/admission_hook/**"',
    '"scripts/check-apalache-positive.sh"',
    '"scripts/check-distributed-revocation-temporal.sh"',
    '"scripts/tests/check-apalache-positive.test.sh"',
    '"scripts/tests/apalache-workflow.test.sh"',
):
    assert path in safety
PY

echo "apalache workflow tests passed"
