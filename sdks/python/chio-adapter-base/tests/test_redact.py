"""Behavioural tests for :mod:`chio_adapter_base.redact`."""

from __future__ import annotations

from chio_adapter_base.redact import RedactArgs, RedactionPolicy, redact_args


def test_redact_args_omits_chio_file_write_content() -> None:
    redacted = redact_args(
        "chio_file_write",
        {"path": "src/main.py", "content": "SECRET=topsecret\n"},
    )
    assert redacted["path"] == "src/main.py"
    assert redacted["content"] == {"omitted": True, "byte_count": 17}


def test_redact_args_omits_chio_file_edit_patch() -> None:
    patch_body = "--- a/src/main.py\n+++ b/src/main.py\n+x = 1\n"
    redacted = redact_args(
        "chio_file_edit", {"path": "src/main.py", "patch": patch_body}
    )
    assert redacted["path"] == "src/main.py"
    assert redacted["patch"]["omitted"] is True
    assert redacted["patch"]["byte_count"] == len(patch_body.encode("utf-8"))


def test_redact_args_passthrough_for_unknown_tool() -> None:
    redacted = redact_args(
        "chio_shell_run", {"command": "ls -la /tmp"}
    )
    assert redacted == {"command": "ls -la /tmp"}


def test_redact_args_passthrough_for_none_tool() -> None:
    redacted = redact_args(None, {"command": "x"})
    assert redacted == {"command": "x"}


def test_redact_args_returns_fresh_dict() -> None:
    src: dict[str, object] = {"path": "x", "content": "y"}
    redacted = redact_args("chio_file_write", src)
    assert redacted is not src
    # Mutating the result must not bleed back into src.
    redacted["path"] = "mutated"
    assert src["path"] == "x"


def test_redact_args_handles_bytes_value() -> None:
    redacted = redact_args(
        "chio_file_write", {"path": "x", "content": b"\xff\xfe binary"}
    )
    assert redacted["content"] == {"omitted": True, "byte_count": 9}


def test_redact_args_handles_bytearray_value() -> None:
    redacted = redact_args(
        "chio_file_write",
        {"path": "x", "content": bytearray(b"\xff\xfe binary")},
    )
    assert redacted["content"] == {"omitted": True, "byte_count": 9}


def test_redact_args_skips_absent_field() -> None:
    redacted = redact_args(
        "chio_file_write", {"path": "x"}
    )
    assert "content" not in redacted
    assert redacted == {"path": "x"}


def test_redact_args_with_custom_policy() -> None:
    policy = RedactionPolicy(body_fields={"my_tool": ("body",)})
    redacted = redact_args(
        "my_tool",
        {"name": "x", "body": "secret-body"},
        policy=policy,
    )
    assert redacted["name"] == "x"
    assert redacted["body"] == {"omitted": True, "byte_count": 11}


def test_redact_args_chio_default_does_not_redact_custom_tool() -> None:
    redacted = redact_args(
        "my_tool", {"body": "secret-body"}
    )
    assert redacted == {"body": "secret-body"}


def test_redaction_policy_chio_default_contents() -> None:
    policy = RedactionPolicy.chio_default()
    assert policy.body_fields["chio_file_write"] == ("content",)
    assert policy.body_fields["chio_file_edit"] == ("patch",)


def test_redact_args_callable_class_redacts() -> None:
    redact = RedactArgs({"my_tool": ("body",)})
    out = redact("my_tool", {"name": "n", "body": "secret"})
    assert out["name"] == "n"
    assert out["body"] == {"omitted": True, "byte_count": 6}


def test_redact_args_callable_class_passthrough_unknown() -> None:
    redact = RedactArgs({"my_tool": ("body",)})
    out = redact("other_tool", {"body": "kept"})
    assert out == {"body": "kept"}


def test_redact_args_byte_count_handles_nonencodable() -> None:
    class _Weird:
        def __str__(self) -> str:
            return "weird-12"

    redacted = redact_args(
        "chio_file_write", {"path": "x", "content": _Weird()}
    )
    # str()-then-encode path; "weird-12" is 8 bytes utf-8.
    assert redacted["content"] == {"omitted": True, "byte_count": 8}
