"""Unit tests for Temporal-sidecar redaction helpers introduced in #794."""

from __future__ import annotations

from chio_adapter_base.redact import RedactionPolicy
from temporalio.worker import ExecuteActivityInput

from chio_temporal.interceptor import (
    _activity_parameters,
    _fixed_positional_param_names,
    _temporal_dict_lift,
)


def test_fixed_positional_param_names_ignores_var_keyword_and_var_positional() -> None:
    def sample(path: str, /, content: str, *extras: str, flag: bool = False) -> None:
        del path, content, extras, flag

    assert _fixed_positional_param_names(sample) == ("path", "content")


def test_temporal_dict_lift_uses_callable_signature_aliases() -> None:
    def chio_file_write(path: str, content: str) -> None:
        del path, content

    policy = RedactionPolicy.chio_default()
    redacted_content = {
        "omitted": True,
        "byte_count": 3,
    }
    lifted = _temporal_dict_lift(
        chio_file_write,
        tool_name="chio_file_write",
        redacted_args=("/tmp/x", redacted_content),
        table_slots=("path", "content"),
        policy=policy,
    )

    assert lifted == [
        {
            "path": "/tmp/x",
            "content": redacted_content,
        }
    ]


def test_temporal_dict_lift_falls_back_to_positional_table_without_callable() -> None:
    policy = RedactionPolicy.chio_default()
    redacted_patch = {
        "omitted": True,
        "byte_count": 4,
    }
    lifted = _temporal_dict_lift(
        None,
        tool_name="chio_file_edit",
        redacted_args=("/etc/cfg", redacted_patch),
        table_slots=("path", "patch"),
        policy=policy,
    )

    assert lifted == [
        {
            "path": "/etc/cfg",
            "patch": redacted_patch,
        }
    ]


def test_activity_parameters_lifts_signature_bound_positional_args() -> None:
    def chio_file_write(path: str, content: str) -> None:
        del path, content

    payload = _activity_parameters(
        ExecuteActivityInput(
            fn=chio_file_write,
            args=["/tmp/x", "PROD_SECRET=abc"],
            executor=None,
            headers={},
        ),
        tool_name="chio_file_write",
        policy=RedactionPolicy.chio_default(),
    )

    assert payload["args"] == [
        {
            "path": "/tmp/x",
            "content": {
                "omitted": True,
                "byte_count": len(b"PROD_SECRET=abc"),
            },
        }
    ]
    assert "PROD_SECRET" not in str(payload)
