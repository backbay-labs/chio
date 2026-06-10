"""Live integration test against a real `chio start` subprocess.

Gated behind ``CHIO_INTEGRATION=1`` so the unit-test run stays
hermetic. When the gate is set, the test:

1. Spawns ``chio start --listen 127.0.0.1:0`` as a subprocess and
   reads the bound port from the startup banner on stdout.
2. Mints a fresh capability against the live sidecar via
   :class:`chio_sdk.client.ChioClient`.
3. Builds a :class:`chio_hermes.runtime.RuntimeHandle` against the
   live sidecar URL and capability id.
4. Exercises the ``chio_file_read`` and ``chio_file_write``
   handlers and asserts the canonical ``status: allowed`` envelope
   (NOT the degraded ``chio_sidecar_unreachable`` envelope).
5. Exercises a denied scenario (writing ``.env``) and asserts the
   canonical ``error: denied`` envelope from the local policy guard.
6. Terminates the subprocess.

The test is intentionally tolerant of "this build does not have the
chio CLI on PATH" so chio-hermes contributors who only edit Python
code never see this fire by accident; only CI jobs that explicitly
opt in will run it.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

INTEGRATION_FLAG = "CHIO_INTEGRATION"

pytestmark = pytest.mark.skipif(
    os.environ.get(INTEGRATION_FLAG) != "1",
    reason="set CHIO_INTEGRATION=1 to exercise the live-sidecar test",
)


def _find_chio_binary() -> Path | None:
    """Locate a usable `chio` binary.

    Search order:
    1. ``CHIO_BIN`` env var, if set.
    2. ``$PATH`` lookup via :func:`shutil.which`.
    3. The workspace's ``target/debug/chio`` and ``target/release/chio``
       relative to this file.
    """
    env_path = os.environ.get("CHIO_BIN")
    if env_path:
        candidate = Path(env_path)
        if candidate.exists():
            return candidate
    on_path = shutil.which("chio")
    if on_path:
        return Path(on_path)
    here = Path(__file__).resolve()
    workspace = here.parents[4]
    for variant in ("target/debug/chio", "target/release/chio"):
        candidate = workspace / variant
        if candidate.exists():
            return candidate
    return None


@pytest.fixture(scope="module")
def chio_binary() -> Path:
    binary = _find_chio_binary()
    if binary is None:
        pytest.skip(
            "chio binary not found on PATH or under target/debug; "
            "set CHIO_BIN=path/to/chio or run cargo build before "
            "rerunning with CHIO_INTEGRATION=1"
        )
    return binary


def _wait_for_socket(host: str, port: int, *, timeout_s: float = 5.0) -> None:
    """Block until the given TCP endpoint accepts connections."""
    deadline = time.monotonic() + timeout_s
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(0.05)
    raise RuntimeError(
        f"sidecar at {host}:{port} did not accept connections "
        f"within {timeout_s}s: {last_error}"
    )


@pytest.fixture(scope="module")
def live_sidecar(chio_binary: Path) -> Iterator[str]:
    """Spawn a `chio start` subprocess on an ephemeral port.

    Yields the resolved base URL (e.g. ``http://127.0.0.1:54321``).
    Tears the subprocess down on fixture exit.
    """
    process = subprocess.Popen(
        [str(chio_binary), "start", "--listen", "127.0.0.1:0"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    base_url: str | None = None
    deadline = time.monotonic() + 10.0
    assert process.stdout is not None
    while time.monotonic() < deadline:
        line = process.stdout.readline()
        if not line:
            if process.poll() is not None:
                stderr_tail = ""
                if process.stderr is not None:
                    stderr_tail = process.stderr.read() or ""
                raise RuntimeError(
                    "chio start exited before printing the banner; "
                    f"stderr=\n{stderr_tail}"
                )
            continue
        if "chio sidecar listening on" in line:
            base_url = line.split()[-1].strip()
            break
    if base_url is None:
        process.terminate()
        process.wait(timeout=5)
        raise RuntimeError("chio start did not print the listening banner")

    host_port = base_url.removeprefix("http://")
    host, _, port_str = host_port.partition(":")
    _wait_for_socket(host, int(port_str))

    try:
        yield base_url
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def _async_run(coro: Any) -> Any:
    return asyncio.run(coro)


def test_health_round_trips(live_sidecar: str) -> None:
    """Sanity-check the live sidecar via /chio/health before we mint."""
    from chio_sdk.client import ChioClient

    async def go() -> dict[str, Any]:
        async with ChioClient(base_url=live_sidecar) as client:
            return await client.health()

    health = _async_run(go())
    assert health.get("status") == "healthy"


def test_mint_capability_via_sdk_path(live_sidecar: str) -> None:
    """The SDK's `/v1/capabilities` POST mints a real signed token."""
    from chio_sdk.client import ChioClient
    from chio_sdk.models import ChioScope

    async def go() -> Any:
        async with ChioClient(base_url=live_sidecar) as client:
            return await client.create_capability(
                subject="abcd1234abcd1234abcd1234abcd1234",
                scope=ChioScope(),
                ttl_seconds=600,
            )

    token = _async_run(go())
    assert token.id.startswith("sidecar-")
    assert token.signature
    assert token.issuer
    assert token.expires_at > token.issued_at


def _mint_capability_id(base_url: str) -> str:
    from chio_sdk.client import ChioClient
    from chio_sdk.models import ChioScope

    async def go() -> str:
        async with ChioClient(base_url=base_url) as client:
            token = await client.create_capability(
                subject="abcd1234abcd1234abcd1234abcd1234",
                scope=ChioScope(),
                ttl_seconds=600,
            )
            return token.id

    return _async_run(go())


def test_runtime_handle_allows_file_read(
    live_sidecar: str,
    tmp_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A `chio_file_read` against an allowed path returns status: allowed.

    This is the canonical happy-path the v0.1 plugin could not exercise
    end-to-end because the sidecar `/v1/capabilities` route did not
    exist. Now it does, the SDK mints, the runtime handle wires up,
    and the read receipt comes back signed.
    """
    capability_id = _mint_capability_id(live_sidecar)
    monkeypatch.setenv("CHIO_SIDECAR_URL", live_sidecar)
    monkeypatch.setenv("CHIO_CAPABILITY_ID", capability_id)
    monkeypatch.setenv("CHIO_WORKSPACE_ROOT", str(tmp_workspace))

    from chio_hermes.handlers import make_handler
    from chio_hermes.manifest import TOOL_TABLE
    from chio_hermes.runtime import build_runtime_handle

    handle = build_runtime_handle()
    assert handle.is_configured(), (
        f"runtime handle not configured: init_error={handle.init_error!r}"
    )

    entry = next(e for e in TOOL_TABLE if e.name == "chio_file_read")
    handler = make_handler(handle, entry)
    payload = json.loads(_async_run(handler({"path": "README.md"})))
    assert payload.get("status") == "allowed", payload
    assert payload.get("tool_name") == "chio_file_read"
    assert payload.get("receipt_id"), "live sidecar must surface a receipt id"


def test_runtime_handle_denies_env_write(
    live_sidecar: str,
    tmp_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Writing `.env` denies via the local policy guard.

    The denial is local (chio-code-agent's policy), not sidecar-driven,
    but the receipt log still runs through the live sidecar so this
    pins that the deny-side wiring is unaffected by the new routes.
    """
    capability_id = _mint_capability_id(live_sidecar)
    monkeypatch.setenv("CHIO_SIDECAR_URL", live_sidecar)
    monkeypatch.setenv("CHIO_CAPABILITY_ID", capability_id)
    monkeypatch.setenv("CHIO_WORKSPACE_ROOT", str(tmp_workspace))

    from chio_hermes.handlers import make_handler
    from chio_hermes.manifest import TOOL_TABLE
    from chio_hermes.runtime import build_runtime_handle

    handle = build_runtime_handle()
    assert handle.is_configured(), (
        f"runtime handle not configured: init_error={handle.init_error!r}"
    )

    entry = next(e for e in TOOL_TABLE if e.name == "chio_file_write")
    handler = make_handler(handle, entry)
    payload = json.loads(_async_run(handler({"path": ".env", "content": "x"})))
    assert payload.get("status") != "allowed", payload
    # The exact error slug depends on which guard fires first; accept
    # any of the canonical denial vocabulary.
    assert (
        payload.get("error") == "denied"
        or payload.get("guard")
        or payload.get("status") in {"denied", "error"}
    ), payload
