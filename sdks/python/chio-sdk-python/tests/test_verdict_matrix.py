from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType


def repo_root() -> Path:
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "crates/tooling/chio-conformance/verdict_matrix").exists():
            return parent
    raise RuntimeError(f"could not find repo root from {current}")


def load_driver() -> ModuleType:
    root = repo_root()
    driver_path = (
        root
        / "crates/tooling/chio-conformance/verdict_matrix/drivers/python/run_scenarios.py"
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
    root = repo_root() / "crates/tooling/chio-conformance/verdict_matrix/scenarios"
    report = await driver.run_scenarios(root)

    assert report["driver"] == "python-sdk"
    assert report["total"] == 60
    assert report["passed"] == 60
    assert report["failed"] == 0
    assert report["unsupported"] == 0
    assert len(report["tuples"]) == 60

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

    trace_missing = report["tuples"]["replay-verdict-004-missing-trace"]
    assert trace_missing["verdict"] == "error"
    assert (
        trace_missing["reason_code"]
        == "urn:chio:error:replay:trace-not-found"
    )

    revoked_read = report["tuples"]["revocation-propagation-002-revoked-read"]
    assert revoked_read["verdict"] == "deny"
    assert (
        revoked_read["reason_code"]
        == "urn:chio:error:capability:revoked"
    )

    output_mask = report["tuples"]["redaction-determinism-002-output-mask-read"]
    assert output_mask["verdict"] == "allow"
    assert (
        output_mask["reason_code"]
        == "urn:chio:error:guard:output-redacted"
    )

    carrier_admitted = report["tuples"][
        "delivery-contract-001-carrier-admitted-read"
    ]
    assert carrier_admitted["verdict"] == "deny"
    assert (
        carrier_admitted["reason_code"]
        == "urn:chio:error:kernel:delivery-contract-unsupported-carrier"
    )

    digest_mismatch = report["tuples"]["delivery-contract-006-mismatched-read"]
    assert digest_mismatch["verdict"] == "deny"
    assert (
        digest_mismatch["reason_code"]
        == "urn:chio:error:kernel:delivery-contract-digest-mismatch"
    )

    prompt_write_scope = driver.scope_for_labels(["prompt:write"])
    assert prompt_write_scope.prompt_grants[0].operations == [
        driver.Operation.INVOKE
    ]
