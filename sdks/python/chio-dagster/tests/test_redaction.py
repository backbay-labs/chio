"""Tests for chio-dagster argument redaction.

Exercises the redaction logic directly against the internal helpers
(``_compute_parameters`` / ``_run_with_guard``) rather than through a
``materialize`` round-trip; materialization is covered by
``test_chio_asset.py``.
"""

from __future__ import annotations

import asyncio
from typing import Any

from chio_adapter_base.redact import RedactionPolicy
from chio_sdk.testing import allow_all

from chio_dagster.decorators import _compute_parameters, _run_with_guard


class TestDefaultPolicyRedacts:
    def test_positional_chio_file_write_content_is_redacted(self) -> None:
        def chio_file_write(path: str, content: str) -> None:
            return None

        payload = _compute_parameters(
            fn=chio_file_write,
            context=None,
            args=("/tmp/x", "PROD_SECRET=abc123"),
            kwargs={},
            tool_name="chio_file_write",
            redaction_policy=RedactionPolicy.chio_default(),
        )

        assert payload["args"] == [
            "/tmp/x",
            {"omitted": True, "byte_count": len(b"PROD_SECRET=abc123")},
        ]
        assert payload["kwargs"] == {}

    def test_chio_file_write_content_is_redacted_in_payload(self) -> None:
        payload = _compute_parameters(
            context=None,
            args=(),
            kwargs={"path": "/tmp/x", "content": "PROD_SECRET=abc123"},
            tool_name="chio_file_write",
            redaction_policy=RedactionPolicy.chio_default(),
        )
        kwargs = payload["kwargs"]
        assert kwargs["path"] == "/tmp/x"
        assert kwargs["content"] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }

    def test_chio_file_edit_patch_is_redacted(self) -> None:
        payload = _compute_parameters(
            context=None,
            args=(),
            kwargs={"path": "/tmp/x", "patch": "--- a\n+++ b\n@@ secret @@"},
            tool_name="chio_file_edit",
            redaction_policy=RedactionPolicy.chio_default(),
        )
        kwargs = payload["kwargs"]
        assert kwargs["path"] == "/tmp/x"
        assert kwargs["patch"] == {
            "omitted": True,
            "byte_count": len(b"--- a\n+++ b\n@@ secret @@"),
        }

    def test_unrelated_tool_passes_args_through(self) -> None:
        payload = _compute_parameters(
            context=None,
            args=(),
            kwargs={"q": "quantum", "content": "not redacted here"},
            tool_name="search",
            redaction_policy=RedactionPolicy.chio_default(),
        )
        kwargs = payload["kwargs"]
        assert kwargs == {"q": "quantum", "content": "not redacted here"}


class TestCustomPolicy:
    def test_custom_policy_redacts_only_named_fields(self) -> None:
        custom = RedactionPolicy(body_fields={"my_tool": ("body",)})
        payload = _compute_parameters(
            context=None,
            args=(),
            kwargs={"label": "hello", "body": "SECRET_TOKEN=xyz"},
            tool_name="my_tool",
            redaction_policy=custom,
        )
        kwargs = payload["kwargs"]
        assert kwargs["label"] == "hello"
        assert kwargs["body"] == {
            "omitted": True,
            "byte_count": len(b"SECRET_TOKEN=xyz"),
        }

    def test_custom_policy_does_not_redact_default_fields(self) -> None:
        custom = RedactionPolicy(body_fields={"my_tool": ("body",)})
        payload = _compute_parameters(
            context=None,
            args=(),
            kwargs={"path": "/tmp/x", "content": "not-redacted-now"},
            tool_name="chio_file_write",
            redaction_policy=custom,
        )
        kwargs = payload["kwargs"]
        assert kwargs["content"] == "not-redacted-now"


class _NotJsonSafe:
    """Stand-in for a non-JSON-serialisable upstream object."""

    def __repr__(self) -> str:  # pragma: no cover -- diagnostics only
        return "<_NotJsonSafe>"


class TestBothPassesCompose:
    def test_context_arg_is_omitted_but_later_positional_args_are_preserved(self) -> None:
        class _Context:
            run_id = "run-1"

        def ingest(context: Any, dataset: str) -> None:
            return None

        payload = _compute_parameters(
            fn=ingest,
            context=_Context(),
            args=(_Context(), "customers"),
            kwargs={},
            tool_name="ingest",
            redaction_policy=RedactionPolicy.chio_default(),
        )

        assert payload["args"] == ["customers"]
        assert payload["kwargs"] == {}

    def test_redact_runs_first_then_sanitise(self) -> None:
        payload = _compute_parameters(
            context=None,
            args=(),
            kwargs={
                "label": "writer",
                "content": "API_KEY=topsecret",
                "frame": _NotJsonSafe(),
                "context": object(),  # stripped by _sanitise_kwargs
            },
            tool_name="chio_file_write",
            redaction_policy=RedactionPolicy.chio_default(),
        )
        kwargs = payload["kwargs"]

        assert kwargs["content"] == {
            "omitted": True,
            "byte_count": len(b"API_KEY=topsecret"),
        }
        assert kwargs["frame"] == {"__chio_type__": "_NotJsonSafe"}
        assert kwargs["label"] == "writer"
        assert "context" not in kwargs

    def test_redaction_precedes_sanitisation_so_stubs_survive(self) -> None:
        # Order matters. Use a non-JSON-safe stand-in for content so that
        # if _sanitise_kwargs ran FIRST, content would arrive at redact_args
        # already wrapped as {"__chio_type__": "_NotJsonSafe"} (a dict, not
        # a redacted-body envelope). With redact_args running first, content
        # is replaced by the {omitted, byte_count} envelope BEFORE the
        # sanitiser ever sees it, so the dict-shape leak path is closed.
        payload = _compute_parameters(
            context=None,
            args=(),
            kwargs={"path": "/tmp/x", "content": _NotJsonSafe()},
            tool_name="chio_file_write",
            redaction_policy=RedactionPolicy.chio_default(),
        )
        # Shape only: the exact byte_count is an implementation detail of
        # chio_adapter_base._byte_count when the value is a non-JSON-safe
        # object. The proof is that the envelope shape wins, not the
        # __chio_type__ sanitiser dict.
        assert isinstance(payload["kwargs"]["content"], dict)
        assert payload["kwargs"]["content"].get("omitted") is True
        assert payload["kwargs"]["content"].get("byte_count", 0) > 0
        assert "__chio_type__" not in payload["kwargs"]["content"]


class TestRunWithGuardThreadsPolicy:
    def test_default_policy_reaches_evaluate_tool_call(self) -> None:
        chio = allow_all()
        captured: dict[str, Any] = {}

        def body(**kwargs: Any) -> int:
            captured.update(kwargs)
            return 1

        result = asyncio.run(
            _run_with_guard(
                fn=body,
                kind="op",
                args=(),
                kwargs={"path": "/tmp/x", "content": "PROD_SECRET=abc123"},
                tool_name="chio_file_write",
                scope=None,
                capability_id="cap-1",
                tool_server="srv",
                chio_client=chio,
                sidecar_url=None,
                redaction_policy=RedactionPolicy.chio_default(),
                is_async=False,
            )
        )
        assert result == 1
        assert captured == {"path": "/tmp/x", "content": "PROD_SECRET=abc123"}

        eval_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(eval_calls) == 1
        kwargs = eval_calls[0].parameters["kwargs"]
        assert kwargs["path"] == "/tmp/x"
        assert kwargs["content"] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }
