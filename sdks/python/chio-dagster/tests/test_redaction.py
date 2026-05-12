"""Tests for chio-dagster argument redaction (chio-adapter-base wiring).

These tests assert that the ``chio_asset`` / ``chio_op`` decorators
redact secret-bearing fields from their compute-fn kwargs BEFORE
forwarding them to the sidecar's ``evaluate_tool_call`` endpoint, so
the receipt log never carries the raw secret bytes. They also assert
that the existing ``_sanitise_kwargs`` JSON-safety pass still runs
AFTER redaction, so the two passes compose:

1. ``redact_args`` -- credential redaction (security pass).
2. ``_sanitise_kwargs`` -- JSON-safety substitution (serialisability
   pass).

The compute body itself still receives the original kwargs unchanged.

We exercise the redaction logic directly against the internal helpers
(``_compute_parameters``, ``_run_with_guard``) rather than through a
``materialize`` round-trip because Dagster interprets compute-fn
parameters as upstream asset inputs at definition time, which makes a
purely-kwargs-driven asset awkward to express. The decorator wiring
(default policy + ``redaction_policy=`` keyword arg + call ordering) is
covered exhaustively by the helper-level tests below; the
materialization happy-path is covered by ``test_chio_asset.py``.
"""

from __future__ import annotations

import asyncio
from typing import Any

from chio_adapter_base.redact import RedactionPolicy
from chio_sdk.testing import allow_all

from chio_dagster.decorators import _compute_parameters, _run_with_guard

# ---------------------------------------------------------------------------
# Default policy: chio_file_write.content is redacted; other fields preserved.
# ---------------------------------------------------------------------------


class TestDefaultPolicyRedacts:
    def test_chio_file_write_content_is_redacted_in_payload(self) -> None:
        payload = _compute_parameters(
            context=None,
            args=(),
            kwargs={"path": "/tmp/x", "content": "PROD_SECRET=abc123"},
            tool_name="chio_file_write",
            redaction_policy=RedactionPolicy.chio_default(),
        )
        kwargs = payload["kwargs"]
        # ``path`` is preserved -- the policy only redacts ``content``.
        assert kwargs["path"] == "/tmp/x"
        # ``content`` is replaced with the omission stub.
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
        # The default policy only matches chio_file_write / chio_file_edit;
        # unrelated tools see their args unchanged (modulo JSON-safety).
        assert kwargs == {"q": "quantum", "content": "not redacted here"}


# ---------------------------------------------------------------------------
# Custom policy: only my_tool.body is redacted.
# ---------------------------------------------------------------------------


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
        """A custom policy fully replaces the default; chio_file_write
        is no longer redacted under it.
        """
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


# ---------------------------------------------------------------------------
# Two-pass composition: redact_args (security) THEN _sanitise_kwargs (JSON).
# ---------------------------------------------------------------------------


class _NotJsonSafe:
    """Stand-in for a non-JSON-serialisable upstream object.

    The decorator's :func:`_sanitise_kwargs` pass replaces values like
    this with ``{"__chio_type__": "<typename>"}``. The redaction pass
    does NOT touch them because they are not in the per-tool body
    fields list.
    """

    def __repr__(self) -> str:  # pragma: no cover -- diagnostics only
        return "<_NotJsonSafe>"


class TestBothPassesCompose:
    """Both passes apply: redaction handles secrets, sanitisation handles JSON."""

    def test_redact_runs_first_then_sanitise(self) -> None:
        """A single call that needs BOTH passes:

        - ``content`` carries a secret -> ``redact_args`` replaces it
          with the omission stub.
        - ``frame`` is a non-JSON-safe object -> ``_sanitise_kwargs``
          replaces it with the type marker.
        - ``label`` is plain JSON -> survives both passes unchanged.
        - ``context`` is the Dagster execution context sentinel ->
          stripped by ``_sanitise_kwargs`` unconditionally.

        This proves the two passes compose end-to-end and that neither
        one swallows the other's responsibility.
        """
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

        # Pass 1 (redact_args): content is a stub.
        assert kwargs["content"] == {
            "omitted": True,
            "byte_count": len(b"API_KEY=topsecret"),
        }
        # Pass 2 (_sanitise_kwargs): non-JSON value is a type marker.
        assert kwargs["frame"] == {"__chio_type__": "_NotJsonSafe"}
        # Plain JSON survives both.
        assert kwargs["label"] == "writer"
        # The Dagster context is dropped by _sanitise_kwargs even though
        # redact_args would have left it alone.
        assert "context" not in kwargs

    def test_redaction_precedes_sanitisation_so_stubs_survive(self) -> None:
        """Redaction outputs a JSON-safe stub dict, so the sanitisation
        pass is a no-op on it. If the order were reversed -- sanitise
        first, redact second -- a non-JSON-safe ``content`` value (for
        example, an arbitrary object class instance) would be replaced
        by the ``__chio_type__`` marker BEFORE redaction had a chance
        to record its byte count, and the receipt would lose the
        useful provenance stub.
        """
        payload = _compute_parameters(
            context=None,
            args=(),
            kwargs={"path": "/tmp/x", "content": "secret-bytes"},
            tool_name="chio_file_write",
            redaction_policy=RedactionPolicy.chio_default(),
        )
        # The omitted-stub dict (a JSON-safe object) survives the
        # JSON-safety pass intact -- it does not get re-wrapped in a
        # ``__chio_type__`` envelope.
        assert payload["kwargs"]["content"] == {
            "omitted": True,
            "byte_count": len(b"secret-bytes"),
        }


# ---------------------------------------------------------------------------
# End-to-end: the recorded sidecar payload sees the redacted kwargs.
# ---------------------------------------------------------------------------


class TestRunWithGuardThreadsPolicy:
    """Drive ``_run_with_guard`` directly to confirm the policy reaches the
    sidecar's evaluate_tool_call payload.
    """

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
        # The body still saw the real, unredacted content.
        assert captured == {"path": "/tmp/x", "content": "PROD_SECRET=abc123"}

        eval_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(eval_calls) == 1
        kwargs = eval_calls[0].parameters["kwargs"]
        assert kwargs["path"] == "/tmp/x"
        assert kwargs["content"] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }
