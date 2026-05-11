"""`hermes chio` CLI subcommand tests.

The CLI exposes three subcommands (per FINAL-PLAN section 6):

* ``issue``  -- mints a capability via ``ChioClient.create_capability``
                and writes it to ``~/.hermes/profiles/<active>/chio-capabilities.json``.
* ``list``   -- reads that JSON cache and prints (human or `--json`).
* ``revoke`` -- shells out to ``chio trust revoke --capability-id <id>``
                and updates the cache.

Tests mock both the chio client and ``subprocess.run`` so no real chio
binary is required.
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

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# setup() registers all three subcommands
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# `issue` builds the scope with Operation.INVOKE (uppercase enum member)
# ---------------------------------------------------------------------------


def test_build_scope_uses_INVOKE_operation() -> None:
    scope = cli._build_scope(["fs"], "*")
    assert scope.grants[0].operations == [Operation.INVOKE]


def test_issue_calls_create_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache_dir = _fake_cache_dir(tmp_path, monkeypatch)

    client = MockChioClient()

    # Patch the ChioClient constructor used inside _do_issue to return
    # our mock without touching the network.
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


# ---------------------------------------------------------------------------
# `list` reads the cache (bare list of dicts with `capability_id`).
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# `revoke` shells out to `chio trust revoke ...`
# ---------------------------------------------------------------------------


def test_revoke_invokes_chio_trust_revoke_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache_dir = _fake_cache_dir(tmp_path, monkeypatch)
    cache_file = cache_dir / "chio-capabilities.json"
    cache_file.write_text(
        json.dumps([{"capability_id": "cap-aaaa", "revoked": False}]),
        encoding="utf-8",
    )

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
    ]
