"""Regressions for the static launcher boundary, separate from host acceptance."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import pytest

from chio_hermes import restricted


@pytest.fixture
def launch_args(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> argparse.Namespace:
    host = tmp_path / "host"
    host.mkdir()
    (host / "hermes").write_text("host test fixture")
    monkeypatch.setattr(restricted, "HOST_CONTRACT_HASHES", {
        "hermes": hashlib.sha256((host / "hermes").read_bytes()).hexdigest()
    })
    monkeypatch.delenv("HERMES_MANAGED_DIR", raising=False)
    monkeypatch.setenv("TEST_MODEL_KEY", "test-credential")
    gateway = tmp_path / "gateway.js"
    gateway.write_text("// operator gateway fixture\n")
    config = tmp_path / "gateway.json"
    config.write_text(json.dumps({
        "execution": {"sessionId": "kernel-session", "bearerToken": "never-copy-this-token"},
        "sessionId": "agent-session", "journalDir": str(tmp_path / "journal"),
        "tools": [{"name": "read_text_file", "inputSchema": {"type": "object"}}],
    }))
    config.chmod(0o600)
    query = tmp_path / "query.txt"
    query.write_text("Read a scoped resource")
    return argparse.Namespace(
        host_root=host, host_python=Path(sys.executable), node=Path(sys.executable),
        gateway_script=gateway, gateway_config=config, state_dir=tmp_path / "state",
        query_file=query, model="test-model", model_base_url="http://127.0.0.1:8000/v1",
        model_key_env="TEST_MODEL_KEY", max_turns=3,
    )


def test_launcher_excludes_native_routes_and_parent_configuration(
    launch_args: argparse.Namespace, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HERMES_CONFIG", "/parent/config.yaml")
    monkeypatch.setenv("HERMES_ENABLE_PROJECT_PLUGINS", "true")
    monkeypatch.setenv("PYTHONPATH", "/untrusted/plugin")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "unrelated-provider-secret")
    command, env, workspace = restricted.prepare(launch_args)
    assert command[command.index("-t") + 1] == "mcp-chio"
    assert "--ignore-rules" in command
    assert workspace.name == "empty-workspace"
    assert not list(workspace.iterdir())
    assert not {"HERMES_CONFIG", "PYTHONPATH", "ANTHROPIC_API_KEY"}.intersection(env)
    assert env["HERMES_ENABLE_PROJECT_PLUGINS"] == "false"
    config_path = launch_args.state_dir / "profile" / "config.yaml"
    config = json.loads(config_path.read_text())
    assert config["plugins"]["enabled"] == []
    assert config["hooks"] == {}
    assert config["tools"]["tool_search"]["enabled"] == "off"
    assert set(config["mcp_servers"]) == {"chio"}
    assert config["mcp_servers"]["chio"]["tools"]["include"] == ["read_text_file"]
    assert "never-copy-this-token" not in config_path.read_text()
    assert "test-credential" not in config_path.read_text()


def test_existing_profile_cannot_silently_change_configuration(launch_args: argparse.Namespace) -> None:
    restricted.prepare(launch_args)
    with pytest.raises(FileExistsError):
        restricted.prepare(launch_args)


def test_host_contract_change_refuses_before_profile_creation(launch_args: argparse.Namespace) -> None:
    (launch_args.host_root / "hermes").write_text("changed tool dispatch")
    with pytest.raises(ValueError, match="contract mismatch"):
        restricted.prepare(launch_args)
    assert not launch_args.state_dir.exists()


def test_host_install_credentials_are_never_loaded(launch_args: argparse.Namespace) -> None:
    (launch_args.host_root / ".env").write_text("normal-profile-credential")
    with pytest.raises(ValueError, match="dedicated pinned host"):
        restricted.prepare(launch_args)


def test_gateway_config_symlink_is_rejected(launch_args: argparse.Namespace, tmp_path: Path) -> None:
    alias = tmp_path / "alias.json"
    alias.symlink_to(launch_args.gateway_config)
    launch_args.gateway_config = alias
    with pytest.raises(ValueError, match="private regular file"):
        restricted.prepare(launch_args)


def test_wildcard_cannot_expand_gateway_tool_allowlist(launch_args: argparse.Namespace) -> None:
    config = json.loads(launch_args.gateway_config.read_text())
    config["tools"][0]["name"] = "*"
    with pytest.raises(ValueError, match="without wildcards"):
        restricted.gateway_tool_names(config)
