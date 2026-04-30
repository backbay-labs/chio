from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType


def repo_root() -> Path:
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "crates/chio-conformance/verdict_matrix").exists():
            return parent
    raise RuntimeError(f"could not find repo root from {current}")


def load_driver() -> ModuleType:
    root = repo_root()
    driver_path = (
        root
        / "crates/chio-conformance/verdict_matrix/drivers/python/run_scenarios.py"
    )
    spec = importlib.util.spec_from_file_location(
        "verdict_matrix_python_driver",
        driver_path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load driver from {driver_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


async def test_python_driver_matches_verdict_matrix_corpus() -> None:
    driver = load_driver()
    root = repo_root() / "crates/chio-conformance/verdict_matrix/scenarios"
    report = await driver.run_scenarios(root)

    assert report["driver"] == "python-sdk"
    assert report["total"] == 48
    assert report["passed"] == 12
    assert report["failed"] == 0
    assert report["unsupported"] == 36
    assert len(report["tuples"]) == 12

    read_exact = report["tuples"]["capability-subset-001-read-exact"]
    assert read_exact == {
        "verdict": "allow",
        "reason_code": "urn:chio:error:none",
        "scope_set": ["tool:read"],
    }

    missing_write = report["tuples"]["capability-subset-007-missing-write"]
    assert missing_write["verdict"] == "deny"
    assert (
        missing_write["reason_code"]
        == "urn:chio:error:capability:scope-exceeded"
    )

    trace_missing = report["tuples"].get("replay-verdict-004-missing-trace")
    assert trace_missing is None

    unsupported = {
        outcome["scenario_id"]: outcome
        for outcome in report["outcomes"]
        if outcome["status"] == "unsupported"
    }
    assert unsupported["replay-verdict-004-missing-trace"][
        "diagnostic"
    ] == "python-sdk verdict path has no local replay evaluator"

    prompt_write_scope = driver.scope_for_labels(["prompt:write"])
    assert prompt_write_scope.prompt_grants[0].operations == [
        driver.Operation.INVOKE
    ]
