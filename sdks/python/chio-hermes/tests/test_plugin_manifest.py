"""Verify `plugin.yaml` matches the documented Hermes plugin contract.

Schema-light: asserts the keys and shapes downstream Hermes loaders
rely on without requiring a Hermes runtime.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

# The plugin manifest ships at the package root and is force-included
# into the wheel at `chio_hermes/plugin.yaml`. Validate the source-tree
# copy so tests do not depend on a built wheel.
MANIFEST_PATH = Path(__file__).resolve().parent.parent / "plugin.yaml"


@pytest.fixture(scope="module")
def manifest() -> dict:
    raw = MANIFEST_PATH.read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    assert isinstance(data, dict), "plugin.yaml must parse to a mapping"
    return data


def test_manifest_file_exists() -> None:
    assert MANIFEST_PATH.exists(), f"missing plugin manifest at {MANIFEST_PATH}"


def test_required_top_level_keys(manifest: dict) -> None:
    for key in ("name", "version", "description", "kind"):
        assert key in manifest, f"plugin.yaml missing required key {key!r}"
        assert manifest[key], f"plugin.yaml key {key!r} must be non-empty"


def test_name_matches_entry_point_alias(manifest: dict) -> None:
    # The pyproject entry point is `[project.entry-points."hermes_agent.plugins"]
    # chio = "chio_hermes"`. The plugin name must equal that key so that
    # `plugins.enabled: ["chio"]` in `~/.hermes/config.yaml` toggles us.
    assert manifest["name"] == "chio"


def test_kind_is_standalone(manifest: dict) -> None:
    # The standalone-kind loader is the one that reads `requires_env`
    # in dict form; if `kind` ever changes, the requires_env shape
    # needs a paired update.
    assert manifest["kind"] == "standalone"


def test_requires_env_is_dict_form(manifest: dict) -> None:
    """`requires_env` must be a list of dicts so `password: true` masks the secret."""
    requires_env = manifest.get("requires_env")
    assert isinstance(requires_env, list) and requires_env, (
        "requires_env must be a non-empty list (dict form)"
    )
    for entry in requires_env:
        assert isinstance(entry, dict), (
            "every requires_env entry must be a dict; the standalone-kind "
            "loader silently drops string-form entries"
        )
        assert "name" in entry


def test_requires_env_includes_capability_id_with_password(manifest: dict) -> None:
    """`hermes setup` reads `password` to decide whether to mask the prompt.

    Without this, the long-lived bearer token would be echoed to the
    terminal and any TTY scrollback would carry it.
    """
    by_name = {entry["name"]: entry for entry in manifest["requires_env"]}
    assert "CHIO_CAPABILITY_ID" in by_name
    assert by_name["CHIO_CAPABILITY_ID"].get("password") is True


def test_requires_env_includes_sidecar_url(manifest: dict) -> None:
    by_name = {entry["name"]: entry for entry in manifest["requires_env"]}
    assert "CHIO_SIDECAR_URL" in by_name


EXPECTED_TOOLS = {
    "chio_file_read",
    "chio_file_write",
    "chio_file_edit",
    "chio_file_list",
    "chio_file_search",
    "chio_shell_run",
    "chio_git_status",
    "chio_git_diff",
    "chio_git_log",
    "chio_git_add",
    "chio_git_commit",
    "chio_git_run",
}


def test_provides_tools_lists_twelve_tools(manifest: dict) -> None:
    tools = manifest.get("provides_tools")
    assert isinstance(tools, list)
    assert len(tools) == 12, f"expected 12 tools, got {len(tools)}: {tools}"


def test_provides_tools_all_chio_prefixed(manifest: dict) -> None:
    tools = manifest["provides_tools"]
    for tool in tools:
        assert tool.startswith("chio_"), (
            f"tool {tool!r} must use the `chio_` prefix to avoid colliding "
            "with built-in Hermes tools (read_file, write_file, patch, "
            "search_files, terminal)"
        )


def test_provides_tools_set_matches_expected(manifest: dict) -> None:
    assert set(manifest["provides_tools"]) == EXPECTED_TOOLS


def test_provides_hooks_includes_four_hooks(manifest: dict) -> None:
    hooks = manifest.get("provides_hooks")
    assert isinstance(hooks, list) and hooks, (
        "provides_hooks must be a non-empty list"
    )
    assert set(hooks) == {
        "pre_tool_call",
        "post_tool_call",
        "on_session_start",
        "on_session_end",
    }


def test_provides_hooks_uses_canonical_name(manifest: dict) -> None:
    """Canonical loader only reads `provides_hooks`; `hooks:` is dropped silently."""
    assert "hooks" not in manifest, (
        "use `provides_hooks` (canonical loader name); "
        "`hooks:` is silently dropped"
    )
