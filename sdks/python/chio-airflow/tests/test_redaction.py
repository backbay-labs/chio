"""Tests for `@chio_task` argument redaction."""

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
        # Keyword-only call: positional bucket stays empty; keyword
        # values stay under kwargs.
        assert forwarded["args"] == []
        assert forwarded["kwargs"]["path"] == "/tmp/x"
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


class TestPositionalArgsAreBoundAndRedacted:
    """Regression: positional invocations must not bypass the redactor.

    The wrapper accepts ``*args`` so a caller writing
    ``write_file("/tmp/x", "PROD_SECRET")`` would otherwise leave
    ``content`` in ``parameters["args"]`` unredacted because
    ``redact_args`` keys on parameter names.
    """

    def test_chio_file_write_positional_content_is_redacted(self) -> None:
        chio = allow_all()

        @chio_task(
            capability_id="cap-1",
            tool_server="fs",
            tool_name="chio_file_write",
            chio_client=chio,
        )
        def write_file(path: str, content: str) -> str:
            return f"wrote {len(content)} bytes to {path}"

        ti = _RecordingTI(task_id="write_file")
        body = _wrapped_function(write_file)

        with _install_context(ti):
            result = body("/tmp/x", "PROD_SECRET=abc123")

        assert result == "wrote 18 bytes to /tmp/x"

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 1
        forwarded = evaluate_calls[0].parameters
        # No raw "PROD_SECRET" should leak anywhere in the forwarded
        # parameters payload.
        import json

        serialised = json.dumps(forwarded)
        assert "PROD_SECRET" not in serialised
        # Wire shape preserved: positional values stay positional after
        # redaction; the path goes into args[0], content stub into args[1].
        assert forwarded["args"][0] == "/tmp/x"
        assert forwarded["args"][1] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }
        assert forwarded["kwargs"] == {}

    def test_chio_file_edit_positional_patch_is_redacted(self) -> None:
        chio = allow_all()

        @chio_task(
            capability_id="cap-1",
            tool_server="fs",
            tool_name="chio_file_edit",
            chio_client=chio,
        )
        def edit_file(path: str, patch: str) -> str:
            return "ok"

        ti = _RecordingTI(task_id="edit_file")
        body = _wrapped_function(edit_file)

        diff = "@@ -1,1 +1,1 @@\n-old\n+API_TOKEN=ghp_abc\n"
        with _install_context(ti):
            assert body("/etc/cfg", diff) == "ok"

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        forwarded = evaluate_calls[0].parameters
        import json

        assert "API_TOKEN" not in json.dumps(forwarded)
        # Wire shape: positional path stays in args[0], patch stub in args[1].
        assert forwarded["args"][0] == "/etc/cfg"
        assert forwarded["args"][1] == {
            "omitted": True,
            "byte_count": len(diff.encode("utf-8")),
        }


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
        assert forwarded["kwargs"] == {"query": "kw", "content": "not-a-secret"}


class TestCustomPolicyReplacesDefault:
    def test_custom_policy_does_not_redact_default_fields(self) -> None:
        chio = allow_all()
        custom = RedactionPolicy(body_fields={"my_tool": ("body",)})

        @chio_task(
            capability_id="cap-1",
            tool_server="fs",
            tool_name="chio_file_write",
            chio_client=chio,
            redaction_policy=custom,
        )
        def write_file(path: str, content: str) -> str:
            return f"wrote {len(content)} bytes to {path}"

        ti = _RecordingTI(task_id="write_file")
        body = _wrapped_function(write_file)

        with _install_context(ti):
            assert body(path="/tmp/x", content="not-redacted-now") == (
                "wrote 16 bytes to /tmp/x"
            )

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 1
        forwarded = evaluate_calls[0].parameters
        # Default chio_file_write.content redaction does NOT apply when a
        # custom policy is supplied; the custom policy fully replaces the
        # chio default.
        assert forwarded["kwargs"]["content"] == "not-redacted-now"


class TestVarKeywordSignatureRedacts:
    """Regression: `inspect.Signature.bind_partial` does NOT raise for `**kwargs`.

    A pure-``**kwargs`` callable bound with ``bind_partial(content="SECRET")``
    returns ``{"kw": {"content": "SECRET"}}``; ``redact_args`` keyed on
    ``content`` would then miss it. The fix detects VAR_KEYWORD first and
    redacts directly on the kwargs dict.
    """

    def test_var_keyword_only_function_redacts_content(self) -> None:
        chio = allow_all()

        @chio_task(
            capability_id="cap-1",
            tool_server="fs",
            tool_name="chio_file_write",
            chio_client=chio,
        )
        def write_file(**kwargs: Any) -> str:
            return "ok"

        ti = _RecordingTI(task_id="write_file")
        body = _wrapped_function(write_file)

        with _install_context(ti):
            body(path="/tmp/x", content="PROD_SECRET=abc123")

        forwarded = [
            c for c in chio.calls if c.method == "evaluate_tool_call"
        ][0].parameters
        import json

        assert "PROD_SECRET" not in json.dumps(forwarded)
        assert forwarded["kwargs"]["content"] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }

    def test_named_plus_var_keyword_function_redacts_spillover(self) -> None:
        chio = allow_all()

        @chio_task(
            capability_id="cap-1",
            tool_server="fs",
            tool_name="chio_file_write",
            chio_client=chio,
        )
        def write_file(path: str, **extras: Any) -> str:
            return "ok"

        ti = _RecordingTI(task_id="write_file")
        body = _wrapped_function(write_file)

        with _install_context(ti):
            body(path="/tmp/x", content="PROD_SECRET=abc123")

        forwarded = [
            c for c in chio.calls if c.method == "evaluate_tool_call"
        ][0].parameters
        import json

        assert "PROD_SECRET" not in json.dumps(forwarded)
        assert forwarded["kwargs"]["path"] == "/tmp/x"
        assert forwarded["kwargs"]["content"] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }

    def test_bind_partial_failure_does_not_leak_positional_args(self) -> None:
        # Duplicate keyword: `bind_partial` raises TypeError; we MUST NOT
        # forward the raw positional value into the receipt.
        chio = allow_all()

        @chio_task(
            capability_id="cap-1",
            tool_server="fs",
            tool_name="chio_file_write",
            chio_client=chio,
        )
        def write_file(path: str, content: str) -> str:
            return "ok"

        ti = _RecordingTI(task_id="write_file")
        body = _wrapped_function(write_file)

        with _install_context(ti):
            # The actual call will raise downstream, but the redactor
            # runs first; we just need to confirm the recorded payload
            # never contained the raw secret. Catch the TypeError so the
            # test asserts redactor behaviour, not Python's binding.
            try:
                body("/tmp/x", "PROD_SECRET=abc123", path="/tmp/dup")
            except TypeError:
                pass

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        if evaluate_calls:
            import json

            assert "PROD_SECRET" not in json.dumps(evaluate_calls[0].parameters)


class TestForwardingWrapperRedaction:
    """Regression: ``def fn(*args, **kwargs)`` forwarding wrappers.

    The pure-VAR_KEYWORD branch only redacts ``kwargs``; positional
    arguments hit the wrapper as ``args`` with no parameter names to
    bind against. The fix consults a per-tool positional-name table so
    chio-default tools still get their bodies redacted, while preserving
    the original wire shape (positional values stay in ``args``).
    """

    def test_pure_forwarding_wrapper_redacts_positional_via_tool_table(
        self,
    ) -> None:
        chio = allow_all()

        @chio_task(
            capability_id="cap-1",
            tool_server="fs",
            tool_name="chio_file_write",
            chio_client=chio,
        )
        def write_file(*args: Any, **kwargs: Any) -> str:
            return "ok"

        ti = _RecordingTI(task_id="write_file")
        body = _wrapped_function(write_file)

        with _install_context(ti):
            body("/tmp/x", "PROD_SECRET=abc123")

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        assert len(evaluate_calls) == 1
        forwarded = evaluate_calls[0].parameters
        import json

        assert "PROD_SECRET" not in json.dumps(forwarded)
        # Wire shape preserved: both values stay positional, but the
        # body gets stubbed via the chio_file_write tool table.
        assert forwarded["args"][0] == "/tmp/x"
        assert forwarded["args"][1] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }
        assert forwarded["kwargs"] == {}

    def test_pure_forwarding_wrapper_with_unknown_tool_passes_positional_through(
        self,
    ) -> None:
        chio = allow_all()

        @chio_task(
            capability_id="cap-1",
            tool_server="srv",
            tool_name="some_other_tool",
            chio_client=chio,
        )
        def forward(*args: Any, **kwargs: Any) -> str:
            return "ok"

        ti = _RecordingTI(task_id="forward")
        body = _wrapped_function(forward)

        with _install_context(ti):
            body("payload-1", "payload-2", k="v")

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        forwarded = evaluate_calls[0].parameters
        # Unknown tool: nothing to redact, wire shape is preserved
        # exactly as the caller passed it.
        assert forwarded["args"] == ["payload-1", "payload-2"]
        assert forwarded["kwargs"] == {"k": "v"}


class TestVarPositionalExtrasStayPositional:
    """Regression: extras past fixed positional slots must remain in args.

    A function like ``def fn(a, b, *rest)`` called with three positional
    arguments binds ``a`` and ``b`` by name; the third value lands in
    ``*rest``. The third value has no parameter name to redact against,
    so it must remain in ``parameters["args"]`` rather than vanishing
    or being shoved into ``parameters["kwargs"]``.
    """

    def test_var_positional_extras_remain_in_args(self) -> None:
        chio = allow_all()

        @chio_task(
            capability_id="cap-1",
            tool_server="fs",
            tool_name="chio_file_write",
            chio_client=chio,
        )
        def write_file(path: str, content: str, *extras: Any) -> str:
            return "ok"

        ti = _RecordingTI(task_id="write_file")
        body = _wrapped_function(write_file)

        with _install_context(ti):
            body("/tmp/x", "PROD_SECRET=abc123", "trailing-1", "trailing-2")

        evaluate_calls = [c for c in chio.calls if c.method == "evaluate_tool_call"]
        forwarded = evaluate_calls[0].parameters
        import json

        assert "PROD_SECRET" not in json.dumps(forwarded)
        # Fixed names redact correctly and stay positional; var-positional
        # extras remain as-is in args (no name to bind to).
        assert forwarded["args"][0] == "/tmp/x"
        assert forwarded["args"][1] == {
            "omitted": True,
            "byte_count": len(b"PROD_SECRET=abc123"),
        }
        assert forwarded["args"][2] == "trailing-1"
        assert forwarded["args"][3] == "trailing-2"
        assert forwarded["kwargs"] == {}


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
