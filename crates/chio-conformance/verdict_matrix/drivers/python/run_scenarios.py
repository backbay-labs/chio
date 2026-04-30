#!/usr/bin/env python3
"""Python SDK verdict-matrix driver."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DRIVER_NAME = "python-sdk"
MATRIX_SERVER_ID = "verdict-matrix"

REASON_NONE = "urn:chio:error:none"
REASON_SCOPE_EXCEEDED = "urn:chio:error:capability:scope-exceeded"
REASON_REVOKED = "urn:chio:error:capability:revoked"
REASON_REPLAY_DRIFT = "urn:chio:error:replay:deterministic-mismatch"
REASON_REPLAY_TRACE_MISSING = "urn:chio:error:replay:trace-not-found"
REASON_INPUT_REDACTED = "urn:chio:error:guard:input-redacted"
REASON_OUTPUT_REDACTED = "urn:chio:error:guard:output-redacted"
REASON_GUARD_DENIED = "urn:chio:error:guard:denied"
REASON_KERNEL_INTERNAL = "urn:chio:error:kernel:internal-error"


@dataclass(frozen=True)
class VerdictTuple:
    verdict: str
    reason_code: str
    scope_set: tuple[str, ...]

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> VerdictTuple:
        return cls(
            verdict=str(value["verdict"]),
            reason_code=str(value["reason_code"]),
            scope_set=tuple(sorted(str(scope) for scope in value["scope_set"])),
        )

    def as_json(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "reason_code": self.reason_code,
            "scope_set": list(self.scope_set),
        }


def repo_root() -> Path:
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "Cargo.toml").exists() and (
            parent / "crates/chio-conformance/verdict_matrix"
        ).exists():
            return parent
    raise RuntimeError(f"could not find repo root from {current}")


def install_sdk_path() -> None:
    sdk_src = repo_root() / "sdks/python/chio-sdk-python/src"
    sys.path.insert(0, str(sdk_src))


install_sdk_path()

from chio_sdk.models import (  # noqa: E402
    CapabilityToken,
    ChioScope,
    Operation,
    PromptGrant,
    ResourceGrant,
    ToolGrant,
)
from chio_sdk.testing import MockChioClient, MockVerdict  # noqa: E402


def scenario_root_default() -> Path:
    return repo_root() / "crates/chio-conformance/verdict_matrix/scenarios"


def load_scenarios(root: Path) -> list[dict[str, Any]]:
    scenarios: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*.json")):
        with path.open("r", encoding="utf-8") as handle:
            scenario = json.load(handle)
        validate_scenario(scenario, path)
        scenarios.append(scenario)
    return scenarios


def validate_scenario(scenario: dict[str, Any], path: Path) -> None:
    for field in ("schema", "id", "category", "script", "expected"):
        if field not in scenario:
            raise ValueError(f"{path} missing required field {field}")
    if scenario["schema"] != "chio.verdict-matrix.scenario.v1":
        raise ValueError(f"{path} has unsupported scenario schema")
    json.loads(str(scenario["script"]["input_json"]))


def supports_requirement(requirement: str) -> bool:
    return requirement in {
        "rust-kernel",
        "python-sdk",
        "kernel-semantics",
    }


def tool_for_scope(label: str) -> str:
    mapping = {
        "tool:read": "files.read",
        "tool:write": "files.write",
        "tool:admin": "system.rotate",
        "telemetry:read": "metrics.query",
        "prompt:read": "prompts.get",
        "prompt:write": "prompts.update",
        "resource:read": "resources.read",
        "tool:call": "tools.invoke",
    }
    try:
        return mapping[label]
    except KeyError as error:
        raise ValueError(f"unsupported capability scope label `{label}`") from error


def scope_for_labels(labels: list[str]) -> ChioScope:
    grants: list[ToolGrant] = []
    resource_grants: list[ResourceGrant] = []
    prompt_grants: list[PromptGrant] = []
    for label in labels:
        tool = tool_for_scope(label)
        if label == "resource:read":
            resource_grants.append(
                ResourceGrant(uri_pattern=tool, operations=[Operation.READ])
            )
        elif label.startswith("prompt:"):
            operation = Operation.INVOKE if label == "prompt:write" else Operation.GET
            prompt_grants.append(
                PromptGrant(prompt_name=tool, operations=[operation])
            )
        else:
            grants.append(
                ToolGrant(
                    server_id=MATRIX_SERVER_ID,
                    tool_name=tool,
                    operations=[Operation.INVOKE],
                )
            )
    return ChioScope(
        grants=grants,
        resource_grants=resource_grants,
        prompt_grants=prompt_grants,
    )


def required_scope(label: str | None) -> ChioScope:
    if label is None:
        return ChioScope()
    return scope_for_labels([label])


def tuple_for(verdict: str, reason_code: str, scope_set: list[str]) -> VerdictTuple:
    return VerdictTuple(
        verdict=verdict,
        reason_code=reason_code,
        scope_set=tuple(sorted(scope_set)),
    )


def scope_label_for_tool(tool_name: str) -> str:
    mapping = {
        "files.read": "tool:read",
        "files.write": "tool:write",
        "system.rotate": "tool:admin",
        "metrics.query": "telemetry:read",
        "prompts.get": "prompt:read",
        "prompts.update": "prompt:write",
        "resources.read": "resource:read",
        "tools.invoke": "tool:call",
    }
    try:
        return mapping[tool_name]
    except KeyError as error:
        raise ValueError(f"unsupported matrix tool `{tool_name}`") from error


def unsupported_reason(scenario: dict[str, Any]) -> str | None:
    script = scenario["script"]
    if script.get("operation") != "tool.call":
        return "python-sdk does not emit non-tool-call verdicts"
    if scenario["category"] != "capability":
        return (
            "python-sdk verdict path has no local "
            f"{scenario['category']} evaluator"
        )
    if script.get("revoked", False):
        return "python-sdk mock capabilities do not expose revocation"
    return None


def tuple_from_receipt(
    receipt: Any,
    scope_set: list[str],
) -> VerdictTuple:
    decision = receipt.decision
    if decision.verdict == "allow":
        reason_code = decision.reason or REASON_NONE
        return tuple_for("allow", reason_code, scope_set)
    if decision.verdict == "deny":
        return tuple_for(
            "deny",
            decision.reason or REASON_KERNEL_INTERNAL,
            scope_set,
        )
    return tuple_for(
        "error",
        decision.reason or REASON_KERNEL_INTERNAL,
        scope_set,
    )


async def evaluate_scenario(scenario: dict[str, Any]) -> VerdictTuple:
    script = scenario["script"]
    scope_set = list(script.get("capability_scopes", []))
    token_by_id: dict[str, CapabilityToken] = {}

    def policy(
        tool_name: str,
        _scope: dict[str, Any],
        context: dict[str, Any],
    ) -> MockVerdict:
        capability_id = str(context.get("capability_id", ""))
        token = token_by_id.get(capability_id)
        if token is None:
            return MockVerdict.deny_verdict(
                REASON_KERNEL_INTERNAL,
                guard="VerdictMatrixCapability",
            )
        required = required_scope(scope_label_for_tool(tool_name))
        if required.is_subset_of(token.scope):
            return MockVerdict.allow_verdict()
        return MockVerdict.deny_verdict(
            REASON_SCOPE_EXCEEDED,
            guard="VerdictMatrixCapability",
        )

    client = MockChioClient(policy=policy, raise_on_deny=False)
    token = await client.create_capability(
        subject=f"matrix-{scenario['id']}",
        scope=scope_for_labels(scope_set),
    )
    token_by_id[token.id] = token
    if not await client.validate_capability(token):
        return tuple_for("error", REASON_KERNEL_INTERNAL, scope_set)
    parameters = json.loads(str(script["input_json"]))
    receipt = await client.evaluate_tool_call(
        capability_id=token.id,
        tool_server=MATRIX_SERVER_ID,
        tool_name=str(script["tool"]),
        parameters=parameters,
    )
    return tuple_from_receipt(receipt, scope_set)


async def run_scenarios(root: Path) -> dict[str, Any]:
    outcomes = []
    tuples: dict[str, Any] = {}
    for scenario in load_scenarios(root):
        expected = VerdictTuple.from_mapping(scenario["expected"])
        unsupported = [
            requirement
            for requirement in scenario.get("requires", [])
            if not supports_requirement(str(requirement))
        ]
        scenario_unsupported = unsupported_reason(scenario)
        if unsupported:
            actual = None
            status = "unsupported"
            diagnostic = f"unsupported requirement `{unsupported[0]}`"
        elif scenario_unsupported is not None:
            actual = None
            status = "unsupported"
            diagnostic = scenario_unsupported
        else:
            actual_tuple = await evaluate_scenario(scenario)
            actual = actual_tuple.as_json()
            status = "pass" if actual_tuple == expected else "fail"
            diagnostic = None
            tuples[scenario["id"]] = actual
        outcomes.append(
            {
                "scenario_id": scenario["id"],
                "status": status,
                "actual": actual,
                "expected": expected.as_json(),
                "diagnostic": diagnostic,
            }
        )
    failed = sum(1 for outcome in outcomes if outcome["status"] == "fail")
    unsupported_count = sum(
        1 for outcome in outcomes if outcome["status"] == "unsupported"
    )
    return {
        "driver": DRIVER_NAME,
        "total": len(outcomes),
        "passed": len(outcomes) - failed - unsupported_count,
        "failed": failed,
        "unsupported": unsupported_count,
        "tuples": tuples,
        "outcomes": outcomes,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--scenario-root",
        type=Path,
        default=scenario_root_default(),
    )
    args = parser.parse_args()
    report = asyncio.run(run_scenarios(args.scenario_root))
    print(json.dumps(report, sort_keys=True, indent=2))
    return 1 if report["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
