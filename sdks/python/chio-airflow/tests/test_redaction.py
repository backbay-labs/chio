"""Tests for `@chio_task` argument redaction (chio-adapter-base wiring).

These tests assert that the TaskFlow `@chio_task` decorator scrubs
secret-bearing kwarg fields BEFORE forwarding them to the Chio
sidecar's ``evaluate_tool_call`` endpoint, so the receipt log never
carries the raw secret bytes. The user function continues to receive
the original (unredacted) arguments.

Source of truth: ``chio_adapter_base.redact.redact_args``.

Why only the TaskFlow path is exercised here: ``ChioOperator`` records
Airflow context fields (``dag_id``, ``run_id``, ``execution_date``,
``logical_date``) for the sidecar parameters payload rather than
per-tool arguments, so it has no body-bearing fields for the default
policy to redact.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from chio_adapter_base.redact import RedactionPolicy
from chio_sdk.testing import allow_all

from chio_airflow import chio_task


class _RecordingTI:
    def __init__(self, task_id: str) -> None:
        self.task_id = task_id
        self.pushed: list[tuple[str, Any]] = []

    def xcom_push(self, key: str, value: Any) -> None:
        self.pushed.append((key, value))


class _FakeDag:
    def __init__(self, dag_id: str) -> None:
        self.dag_id = dag_id


def _install_context(ti: _RecordingTI, *, dag_id: str = "d", run_id: str = "r1") -> Any:
    fake_context = {
        "ti": ti,
        "task_instance": ti,
        "dag": _FakeDag(dag_id),
        "run_id": run_id,
    }
    return patch("airflow.sdk.get_current_context", return_value=fake_context)


def _wrapped_function(decorator_output: Any) -> Any:
    fn = getattr(decorator_output, "function", None)
    assert fn is not None, (
        "chio_task did not return an Airflow TaskFlow decorator with a .function"
    )
    return fn


# ---------------------------------------------------------------------------
# (a) Default policy: chio_file_write.content is replaced by a stub
# ---------------------------------------------------------------------------


class TestDefaultPolicyRedacts:
    def test_chio_file_write_content_is_redacted_in_recorded_parameters(
        self,
    ) -> None:
        chio = allow_all()

        @chio_task(
            capability_id="cap-1",
            tool_server="fs",
            tool_name="chio_file_write",
            chio_client=chio,
        )
        def write_file(path: str, content: str) -> str:
            # The user function still receives the original (unredacted)
            # bytes so the actual write succeeds.
            assert content == "PROD_SECRET=abc123"
            return f"wrote {len(content)} bytes to {path}"

        ti = _RecordingTI(task_id="write_file")
        body = _wrapped_function(write_file)

        with _install_context(ti):
            result = body(path="/tmp/x", content="PROD_SECRET=abc123")

        assert result == "wrote 18 bytes to /tmp/x"

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 1
        forwarded = evaluate_calls[0].parameters
        assert forwarded["args"] == []
        assert forwarded["kwargs"]["path"] == "/tmp/x"
        # Sidecar (and therefore the receipt log) sees a stub instead of
        # the raw secret bytes.
        assert forwarded["kwargs"]["content"] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }

    def test_chio_file_edit_patch_is_redacted_in_recorded_parameters(self) -> None:
        chio = allow_all()

        @chio_task(
            capability_id="cap-1",
            tool_server="fs",
            tool_name="chio_file_edit",
            chio_client=chio,
        )
        def edit_file(path: str, patch: str) -> str:
            assert patch.startswith("@@")
            return "ok"

        ti = _RecordingTI(task_id="edit_file")
        body = _wrapped_function(edit_file)

        diff = "@@ -1,1 +1,1 @@\n-old\n+API_TOKEN=ghp_abcdef\n"
        with _install_context(ti):
            assert body(path="/etc/cfg", patch=diff) == "ok"

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 1
        forwarded = evaluate_calls[0].parameters
        assert forwarded["kwargs"]["path"] == "/etc/cfg"
        assert forwarded["kwargs"]["patch"] == {
            "omitted": True,
            "byte_count": len(diff.encode("utf-8")),
        }


# ---------------------------------------------------------------------------
# (b) Non-targeted tool names pass through unchanged
# ---------------------------------------------------------------------------


class TestUntargetedToolPreserved:
    def test_unknown_tool_name_keeps_kwargs_intact(self) -> None:
        chio = allow_all()

        @chio_task(
            capability_id="cap-1",
            tool_server="srv",
            tool_name="search",
            chio_client=chio,
        )
        def search(query: str, content: str) -> str:
            return f"hit:{query}/{content}"

        ti = _RecordingTI(task_id="search")
        body = _wrapped_function(search)

        with _install_context(ti):
            assert body(query="kw", content="not-a-secret") == "hit:kw/not-a-secret"

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 1
        forwarded = evaluate_calls[0].parameters
        # ``search`` is not in the chio-default policy, so even a
        # ``content`` kwarg passes through unchanged.
        assert forwarded["kwargs"] == {"query": "kw", "content": "not-a-secret"}


# ---------------------------------------------------------------------------
# (c) Custom RedactionPolicy lets adapters extend the field set
# ---------------------------------------------------------------------------


class TestCustomPolicyAppliesAdapterFields:
    def test_custom_policy_redacts_extra_tool_field(self) -> None:
        chio = allow_all()
        custom = RedactionPolicy(
            body_fields={"workspace_secret_push": ("payload", "fallback")}
        )

        @chio_task(
            capability_id="cap-1",
            tool_server="ws",
            tool_name="workspace_secret_push",
            chio_client=chio,
            redaction_policy=custom,
        )
        def push_secret(target: str, payload: str, fallback: str) -> str:
            assert payload == "live-secret"
            assert fallback == "fallback-secret"
            return f"pushed {target}"

        ti = _RecordingTI(task_id="push_secret")
        body = _wrapped_function(push_secret)

        with _install_context(ti):
            assert (
                body(
                    target="vault://prod",
                    payload="live-secret",
                    fallback="fallback-secret",
                )
                == "pushed vault://prod"
            )

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 1
        forwarded = evaluate_calls[0].parameters
        assert forwarded["kwargs"]["target"] == "vault://prod"
        assert forwarded["kwargs"]["payload"] == {
            "omitted": True,
            "byte_count": len(b"live-secret"),
        }
        assert forwarded["kwargs"]["fallback"] == {
            "omitted": True,
            "byte_count": len(b"fallback-secret"),
        }
