"""Shared fixtures for the chio-hermes test suite.

The plugin only consumes the `ctx` object passed into `register(ctx)`,
so a `FakePluginContext` test double is sufficient to verify wiring.
Sidecar interactions run against `chio_sdk.testing.MockChioClient`.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest


@dataclass
class _RegisteredTool:
    name: str
    kwargs: dict[str, Any] = field(default_factory=dict)


@dataclass
class _RegisteredHook:
    name: str
    handler: Callable[..., Any]


@dataclass
class _RegisteredCli:
    name: str
    kwargs: dict[str, Any] = field(default_factory=dict)


@dataclass
class _RegisteredCommand:
    name: str
    kwargs: dict[str, Any] = field(default_factory=dict)


class FakePluginContext:
    """Test double for the Hermes `ctx` argument.

    Records every ``register_*`` call so tests can assert wiring
    without standing up a real Hermes runtime.
    """

    def __init__(self) -> None:
        self.tools: dict[str, _RegisteredTool] = {}
        self.hooks: dict[str, list[Callable[..., Any]]] = {}
        self.cli: dict[str, _RegisteredCli] = {}
        self.cmds: dict[str, _RegisteredCommand] = {}

    def register_tool(self, **kw: Any) -> None:
        name = kw["name"]
        self.tools[name] = _RegisteredTool(name=name, kwargs=dict(kw))

    def register_hook(self, name: str, callback: Callable[..., Any]) -> None:
        self.hooks.setdefault(name, []).append(callback)

    def register_cli_command(self, **kw: Any) -> None:
        name = kw["name"]
        self.cli[name] = _RegisteredCli(name=name, kwargs=dict(kw))

    def register_command(self, **kw: Any) -> None:
        name = kw["name"]
        self.cmds[name] = _RegisteredCommand(name=name, kwargs=dict(kw))


@pytest.fixture
def fake_plugin_context() -> FakePluginContext:
    return FakePluginContext()


@pytest.fixture
def tmp_workspace(tmp_path: Path) -> Path:
    """A tmp_path-based fake git workspace.

    Lays down a project tree with a stub `.git/` so policy checks have
    something to look at; not a real git repo.
    """
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "docs").mkdir()
    (tmp_path / "README.md").write_text("hello\n", encoding="utf-8")
    (tmp_path / ".env").write_text("SECRET=shh\n", encoding="utf-8")
    (tmp_path / "src" / "main.py").write_text("print('hi')\n", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("[core]\n", encoding="utf-8")
    return tmp_path


@pytest.fixture
def tmp_hermes_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Path]:
    """Monkeypatch `_resolve_log_path` to a tmp directory.

    Receipts module imports `get_hermes_home` lazily inside
    `_resolve_log_path`; patching the helper keeps the JSONL writer
    inside the test sandbox.
    """
    home = tmp_path / "hermes-home"
    home.mkdir()
    (home / "logs").mkdir()

    monkeypatch.setenv("HERMES_HOME", str(home))

    import chio_hermes.receipts as _receipts

    monkeypatch.setattr(
        _receipts,
        "_resolve_log_path",
        lambda: home / "logs" / "chio-receipts.jsonl",
        raising=True,
    )
    try:
        import hermes_constants  # type: ignore[import-not-found,unused-ignore]

        monkeypatch.setattr(
            hermes_constants, "get_hermes_home", lambda: home, raising=True
        )
    except ImportError:
        pass

    yield home


@pytest.fixture
def configured_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set the two required env vars so `RuntimeHandle.is_configured()` is True."""
    monkeypatch.setenv("CHIO_SIDECAR_URL", "http://127.0.0.1:9090")
    monkeypatch.setenv("CHIO_CAPABILITY_ID", "cap-test-12345678")


@pytest.fixture
def unconfigured_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip the required env vars so `is_configured()` is False."""
    monkeypatch.delenv("CHIO_SIDECAR_URL", raising=False)
    monkeypatch.delenv("CHIO_CAPABILITY_ID", raising=False)
    monkeypatch.delenv("CHIO_POLICY_FILE", raising=False)


def make_configured_runtime(
    *,
    chio_client: Any | None = None,
    cwd: Path | None = None,
    capability_id: str = "cap-test-12345678",
    policy: Any | None = None,
) -> Any:
    """Build a fully wired :class:`RuntimeHandle` for handler/hook tests.

    Defaults to an allow-all :class:`MockChioClient` and the bundled
    :data:`DEFAULT_POLICY`.
    """
    from chio_code_agent.agent import CodeAgent
    from chio_code_agent.policy import DEFAULT_POLICY
    from chio_sdk.testing import MockChioClient

    from chio_hermes.receipts import ReceiptBuffer
    from chio_hermes.runtime import RuntimeHandle

    client = chio_client if chio_client is not None else MockChioClient()
    workspace = cwd if cwd is not None else Path.cwd()
    pol = policy if policy is not None else DEFAULT_POLICY

    handle = RuntimeHandle(
        chio_client=client,
        capability_id=capability_id,
        cwd=workspace,
        policy=pol,
        receipts=ReceiptBuffer(),
    )
    handle.code_agent = CodeAgent(
        chio_client=client,
        capability_id=capability_id,
        policy=pol,
        cwd=workspace,
    )
    return handle


class SyncFakePluginContext(FakePluginContext):
    """FakePluginContext that exposes a Hermes-faithful sync hook caller.

    Hermes's `PluginManager.invoke_hook` (`hermes_cli/plugins.py:1218-1232`)
    walks registered callbacks and calls each as `ret = cb(**kwargs)`
    with NO await; coroutine returns are silently dropped. Tests use
    `invoke_hook_sync` to mirror that semantics exactly.
    """

    def invoke_hook_sync(self, name: str, **kwargs: Any) -> list[Any]:
        callbacks = self.hooks.get(name, [])
        results: list[Any] = []
        for cb in callbacks:
            ret = cb(**kwargs)
            if ret is not None:
                results.append(ret)
        return results


@pytest.fixture
def sync_fake_plugin_context() -> SyncFakePluginContext:
    return SyncFakePluginContext()


__all__ = [
    "FakePluginContext",
    "SyncFakePluginContext",
    "_RegisteredCli",
    "_RegisteredCommand",
    "_RegisteredHook",
    "_RegisteredTool",
    "configured_env",
    "fake_plugin_context",
    "make_configured_runtime",
    "sync_fake_plugin_context",
    "tmp_hermes_home",
    "tmp_workspace",
    "unconfigured_env",
]
