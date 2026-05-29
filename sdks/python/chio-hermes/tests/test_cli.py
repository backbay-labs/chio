"""`hermes chio` CLI subcommand tests.

Mocks both the chio client and `subprocess.run` so no real chio binary
is required.
"""

from __future__ import annotations

import argparse
import io
import json
import subprocess as _subprocess
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

import pytest
from chio_sdk.models import Operation
from chio_sdk.testing import MockChioClient

from chio_hermes import cli


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hermes chio")
    cli.setup(parser)
    return parser


def _fake_cache_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the CLI at a tmp profile directory."""
    profile_dir = tmp_path / "profiles" / "default"
    profile_dir.mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))

    monkeypatch.setattr(
        cli, "_cache_path", lambda: profile_dir / "chio-capabilities.json"
    )
    return profile_dir


def test_setup_registers_issue_list_revoke() -> None:
    parser = _build_parser()
    subparser_actions = [
        a for a in parser._actions if isinstance(a, argparse._SubParsersAction)
    ]
    assert subparser_actions, "cli.setup must add a subparsers group"
    choices = subparser_actions[0].choices
    for cmd in ("issue", "list", "revoke"):
        assert cmd in choices, f"missing subcommand {cmd!r}; got {list(choices)}"


def test_setup_uses_subcommand_dest() -> None:
    """`dest='subcommand'` so the dispatcher reads `args.subcommand`."""
    parser = _build_parser()
    ns = parser.parse_args(
        ["issue", "--subject", "abc", "--tool-server", "fs"]
    )
    assert ns.subcommand == "issue"


def test_build_scope_uses_INVOKE_operation() -> None:
    scope = cli._build_scope(["fs"], "*")
    assert scope.grants[0].operations == [Operation.INVOKE]


def test_issue_calls_create_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache_dir = _fake_cache_dir(tmp_path, monkeypatch)

    client = MockChioClient()

    # Patch the ChioClient constructor used inside _do_issue so the
    # mock is returned without touching the network.
    class _FakeClientCtor:
        def __init__(self, **_kw: Any) -> None: ...

        def __new__(cls, **_kw: Any) -> Any:  # type: ignore[misc]
            return client

    import chio_sdk.client as _client_mod

    monkeypatch.setattr(_client_mod, "ChioClient", _FakeClientCtor)

    args = argparse.Namespace(
        subcommand="issue",
        tool_server=["fs", "shell", "git"],
        subject="abcd1234abcd1234",
        tool_name="*",
        ttl=3600,
        description="test issue",
        json=True,
        sidecar_url=None,
        timeout=5.0,
    )

    rc = cli.handle(args)
    assert rc in (None, 0)

    create_calls = [c for c in client.calls if c.method == "create_capability"]
    assert create_calls, "expected ChioClient.create_capability to be called"
    call = create_calls[-1]
    grants = call.scope.get("grants", []) if isinstance(call.scope, dict) else []
    server_ids = {g.get("server_id") for g in grants}
    assert {"fs", "shell", "git"}.issubset(server_ids)

    cache = cache_dir / "chio-capabilities.json"
    assert cache.exists(), "issue must write the local capability cache"
    cached = json.loads(cache.read_text(encoding="utf-8"))
    assert cached, "cache must be non-empty after issue"


def test_list_reads_cache_and_prints_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache_dir = _fake_cache_dir(tmp_path, monkeypatch)

    cache_file = cache_dir / "chio-capabilities.json"
    cache_file.write_text(
        json.dumps(
            [
                {
                    "capability_id": "cap-aaaa",
                    "subject": "abcd1234",
                    "tool_servers": ["fs"],
                    "tool_name": "*",
                    "ttl_seconds": 3600,
                    "description": "test",
                    "issued_at": 1700000000,
                    "expires_at": 1700003600,
                    "revoked": False,
                }
            ]
        ),
        encoding="utf-8",
    )

    args = argparse.Namespace(
        subcommand="list",
        json=True,
        active_only=True,
        sidecar_url=None,
        timeout=5.0,
    )

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.handle(args)
    assert rc in (None, 0)

    output = buf.getvalue().strip()
    assert output, "list must print to stdout"
    parsed = json.loads(output)
    assert isinstance(parsed, list)
    serialised = json.dumps(parsed)
    assert "cap-aaaa" in serialised


def test_revoke_invokes_chio_trust_revoke_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache_dir = _fake_cache_dir(tmp_path, monkeypatch)
    cache_file = cache_dir / "chio-capabilities.json"
    cache_file.write_text(
        json.dumps([{"capability_id": "cap-aaaa", "revoked": False}]),
        encoding="utf-8",
    )

    # The revoke handler refuses to shell out without a backend
    # configured; set a control URL so the happy-path argv is observable.
    monkeypatch.setenv("CHIO_CONTROL_URL", "http://127.0.0.1:9091")
    monkeypatch.delenv("CHIO_REVOCATION_DB", raising=False)

    captured: dict[str, Any] = {}

    class _FakeCompleted:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(argv: Any, **kw: Any) -> _FakeCompleted:
        captured["argv"] = list(argv)
        captured["kwargs"] = dict(kw)
        return _FakeCompleted()

    monkeypatch.setattr(_subprocess, "run", fake_run)
    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    args = argparse.Namespace(
        subcommand="revoke",
        capability_id="cap-aaaa",
        reason="test revoke",
        json=False,
        sidecar_url=None,
        timeout=5.0,
    )

    rc = cli.handle(args)
    assert rc in (None, 0)

    assert captured.get("argv") == [
        "chio",
        "trust",
        "revoke",
        "--capability-id",
        "cap-aaaa",
        "--control-url",
        "http://127.0.0.1:9091",
    ]


def test_revoke_refuses_without_backend_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`hermes chio revoke` exits with `chio_revocation_backend_unconfigured`
    when neither CHIO_CONTROL_URL nor CHIO_REVOCATION_DB is set."""
    _fake_cache_dir(tmp_path, monkeypatch)
    monkeypatch.delenv("CHIO_CONTROL_URL", raising=False)
    monkeypatch.delenv("CHIO_REVOCATION_DB", raising=False)

    called = False

    def fake_run(*_a: Any, **_kw: Any) -> Any:
        nonlocal called
        called = True
        raise AssertionError("subprocess.run must NOT be invoked")

    monkeypatch.setattr(_subprocess, "run", fake_run)
    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    args = argparse.Namespace(
        subcommand="revoke",
        capability_id="cap-aaaa",
        reason="",
        json=False,
        sidecar_url=None,
        timeout=5.0,
    )
    rc = cli.handle(args)
    assert rc == 2
    assert called is False


def test_revoke_uses_revocation_db_when_no_control_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CHIO_REVOCATION_DB falls back when CHIO_CONTROL_URL is unset."""
    _fake_cache_dir(tmp_path, monkeypatch)
    monkeypatch.delenv("CHIO_CONTROL_URL", raising=False)
    db_path = tmp_path / "revocations.sqlite"
    monkeypatch.setenv("CHIO_REVOCATION_DB", str(db_path))

    captured: dict[str, Any] = {}

    class _FakeCompleted:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(argv: Any, **_kw: Any) -> _FakeCompleted:
        captured["argv"] = list(argv)
        return _FakeCompleted()

    monkeypatch.setattr(_subprocess, "run", fake_run)
    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    args = argparse.Namespace(
        subcommand="revoke",
        capability_id="cap-bbbb",
        reason="",
        json=False,
        sidecar_url=None,
        timeout=5.0,
    )
    cli.handle(args)
    assert "--revocation-db" in captured["argv"]
    assert str(db_path) in captured["argv"]



# ---------------------------------------------------------------------------
# `hermes chio approvals` subcommand
# ---------------------------------------------------------------------------


def test_setup_registers_approvals_subparser() -> None:
    parser = _build_parser()
    subparser_actions = [
        a for a in parser._actions if isinstance(a, argparse._SubParsersAction)
    ]
    assert "approvals" in subparser_actions[0].choices


def test_approvals_respond_requires_verdict_flag() -> None:
    parser = _build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["approvals", "respond", "ap-1"])


def test_approvals_respond_parses_approve_flag() -> None:
    parser = _build_parser()
    ns = parser.parse_args(
        ["approvals", "respond", "ap-1", "--approve", "--reason", "ok"]
    )
    assert ns.subcommand == "approvals"
    assert ns.approvals_subcommand == "respond"
    assert ns.verdict == "approve"
    assert ns.approval_id == "ap-1"
    assert ns.reason == "ok"


def test_approvals_list_invokes_sdk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = MockChioClient()

    # Pre-populate via the mock's submit_for_approval so the list call
    # has something to return.
    import asyncio

    asyncio.run(
        client.submit_for_approval(
            capability_id="cap-x",
            tool_name="chio_shell_run",
            tool_args={"command": "ls"},
            tool_server="shell",
            summary="ls",
        )
    )

    import chio_sdk.client as _client_mod

    class _Ctor:
        def __new__(cls, **_kw: Any) -> Any:  # type: ignore[misc]
            return client

    monkeypatch.setattr(_client_mod, "ChioClient", _Ctor)
    monkeypatch.setattr(cli, "_approvals_client", lambda _args: client)

    args = argparse.Namespace(
        subcommand="approvals",
        approvals_subcommand="list",
        json=True,
        sidecar_url=None,
        timeout=5.0,
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.handle(args)
    assert rc == 0
    payload = json.loads(buf.getvalue())
    assert isinstance(payload, list)
    assert payload and payload[0]["tool_server"] == "shell"


def test_approvals_respond_invokes_sdk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = MockChioClient()

    import asyncio

    approval_id = asyncio.run(
        client.submit_for_approval(
            capability_id="cap-x",
            tool_name="chio_shell_run",
            tool_args={"command": "rm -rf old"},
            tool_server="shell",
        )
    )

    monkeypatch.setattr(cli, "_approvals_client", lambda _args: client)

    args = argparse.Namespace(
        subcommand="approvals",
        approvals_subcommand="respond",
        approval_id=approval_id,
        verdict="approve",
        reason="ok-cli",
        json=True,
        sidecar_url=None,
        timeout=5.0,
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.handle(args)
    assert rc == 0
    payload = json.loads(buf.getvalue())
    assert payload["approval_id"] == approval_id
    assert payload["outcome"] == "approved"

    respond_calls = [
        c for c in client.calls if c.method == "respond_approval"
    ]
    assert respond_calls and respond_calls[0].context["reason"] == "ok-cli"


def test_approvals_unknown_subcommand_returns_2(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = argparse.Namespace(
        subcommand="approvals",
        approvals_subcommand="bogus",
        json=False,
        sidecar_url=None,
        timeout=5.0,
    )
    rc = cli.handle(args)
    assert rc == 2
