"""Tests for chio-iac argument redaction."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from chio_adapter_base.redact import RedactionPolicy
from chio_sdk.testing import allow_all

from chio_iac import (
    ResourceTypeAllowlist,
    chio_pulumi,
    record_resource,
    run_terraform,
)
from chio_iac import terraform as terraform_module


class _Recorder:
    """Replacement for :func:`chio_iac.terraform._run_subprocess`."""

    def __init__(self, *, show_json: dict | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.show_json = show_json or {}

    def __call__(
        self,
        command: list[str],
        *,
        cwd: str | Path | None,
        capture_output: bool,
        env: dict[str, str] | None,
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append(
            {
                "command": list(command),
                "cwd": str(cwd) if cwd else None,
                "capture_output": capture_output,
                "env": env,
            }
        )
        stdout = ""
        if len(command) >= 3 and command[1:3] == ["show", "-json"]:
            stdout = json.dumps(self.show_json)
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=stdout,
            stderr="",
        )


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch) -> _Recorder:
    rec = _Recorder()
    monkeypatch.setattr(terraform_module, "_run_subprocess", rec)
    return rec


@pytest.fixture
def fake_terraform_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> str:
    binary = tmp_path / "terraform-fake"
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    binary.chmod(0o755)
    monkeypatch.setenv("CHIO_IAC_TERRAFORM", str(binary))
    return str(binary)


def _tf_plan(*changes: tuple[str, list[str], str]) -> dict:
    return {
        "format_version": "1.2",
        "resource_changes": [
            {
                "address": address,
                "type": type_,
                "name": address.split(".")[-1],
                "change": {"actions": list(actions)},
            }
            for type_, actions, address in changes
        ],
    }


class TestDefaultPolicyOnTerraform:
    async def test_terraform_plan_default_policy_passes_args_through(
        self,
        recorder: _Recorder,
        fake_terraform_binary: str,
        tmp_path: Path,
    ) -> None:
        chio = allow_all()
        recorder.show_json = _tf_plan(
            ("aws_db_instance", ["create"], "aws_db_instance.primary"),
        )

        await run_terraform(
            "plan",
            ["-var=password=PROD_SECRET"],
            capability_id="cap-plan",
            working_dir=tmp_path,
            chio_client=chio,
        )

        calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(calls) == 1
        params = calls[0].parameters
        assert params["args"] == ["-var=password=PROD_SECRET"]
        assert params["subcommand"] == "plan"


class TestCustomPolicyOnTerraform:
    async def test_terraform_apply_custom_policy_redacts_args(
        self,
        recorder: _Recorder,
        fake_terraform_binary: str,
        tmp_path: Path,
    ) -> None:
        plan_json = _tf_plan(
            ("aws_db_instance", ["create"], "aws_db_instance.primary"),
        )
        (tmp_path / "tfplan").write_text("binary-ish", encoding="utf-8")
        (tmp_path / "tfplan.json").write_text(
            json.dumps(plan_json), encoding="utf-8"
        )

        chio = allow_all()
        custom = RedactionPolicy(
            body_fields={"terraform:apply": ("args",)}
        )

        await run_terraform(
            "apply",
            ["-var=password=PROD_SECRET"],
            capability_id="cap-apply",
            working_dir=tmp_path,
            allowlist=ResourceTypeAllowlist(patterns=["aws_db_*"]),
            chio_client=chio,
            redaction_policy=custom,
        )

        calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(calls) == 1
        params = calls[0].parameters
        original_args = ["-var=password=PROD_SECRET"]
        expected_byte_count = len(str(original_args).encode("utf-8"))
        assert params["args"] == {
            "omitted": True,
            "byte_count": expected_byte_count,
        }
        assert params["subcommand"] == "apply"
        assert params["scope_label"] == "infra:apply"
        assert params["resource_types"] == ["aws_db_instance"]

    async def test_terraform_plan_custom_policy_redacts_args(
        self,
        recorder: _Recorder,
        fake_terraform_binary: str,
        tmp_path: Path,
    ) -> None:
        chio = allow_all()
        recorder.show_json = _tf_plan(
            ("aws_db_instance", ["create"], "aws_db_instance.primary"),
        )
        custom = RedactionPolicy(
            body_fields={"terraform:plan": ("args",)}
        )

        await run_terraform(
            "plan",
            ["-var=password=PROD_SECRET"],
            capability_id="cap-plan",
            working_dir=tmp_path,
            chio_client=chio,
            redaction_policy=custom,
        )

        calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(calls) == 1
        params = calls[0].parameters
        assert isinstance(params["args"], dict)
        assert params["args"]["omitted"] is True
        assert params["args"]["byte_count"] > 0
        assert "tfplan" in params["plan_path"]


class TestCustomPolicyOnPulumi:
    async def test_pulumi_apply_custom_policy_redacts_program(self) -> None:
        chio = allow_all()
        custom = RedactionPolicy(
            body_fields={"pulumi:up": ("program",)}
        )

        @chio_pulumi(
            capability_id="cap-pulumi",
            phase="apply",
            allowlist=ResourceTypeAllowlist(patterns=["aws:rds/*"]),
            chio_client=chio,
            redaction_policy=custom,
        )
        async def my_program() -> str:
            record_resource("aws:rds/instance:Instance", name="db")
            return "ok"

        result = await my_program()
        assert result == "ok"

        calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(calls) == 1
        params = calls[0].parameters
        assert params["program"] == {
            "omitted": True,
            "byte_count": len(b"my_program"),
        }
        assert params["phase"] == "apply"
        assert params["scope_label"] == "infra:apply"
        assert params["resource_types"] == ["aws:rds/instance:Instance"]

    async def test_pulumi_plan_default_policy_passes_through(self) -> None:
        chio = allow_all()

        @chio_pulumi(
            capability_id="cap-pulumi",
            phase="plan",
            chio_client=chio,
        )
        async def my_program() -> str:
            return "ok"

        await my_program()

        calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(calls) == 1
        params = calls[0].parameters
        assert params["program"] == "my_program"
