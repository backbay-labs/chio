"""`hermes chio` CLI subcommand: capability lifecycle helpers.

Three subcommands:

* `issue`  -- mints a capability via `ChioClient.create_capability` and
              caches the metadata in `<hermes_home>/profiles/<active>/
              chio-capabilities.json` so `list` and `revoke` can show it.
* `list`   -- pure local read of the JSON cache; never calls Chio APIs.
* `revoke` -- shells out to `chio trust revoke --capability-id <id>`
              (verified at `crates/chio-cli/src/cli/types.rs:1897-1902`)
              and removes the entry from the local cache on success.

Hermes registers async-capable handler functions but the documented
shape for CLI commands is sync; we use `asyncio.run(...)` internally
for the one async call (`create_capability`).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Cache file resolution
# ---------------------------------------------------------------------------


def _hermes_home() -> Path:
    """Resolve `<hermes_home>` lazily so `chio_hermes` imports without Hermes."""
    try:
        from hermes_constants import get_hermes_home

        return Path(get_hermes_home())
    except Exception:
        return Path.home() / ".hermes"


def _active_profile() -> str:
    """Read the active Hermes profile from env, defaulting to `default`."""
    return os.environ.get("HERMES_PROFILE", "default")


def _cache_path() -> Path:
    """Return the on-disk path for the local capability cache."""
    return _hermes_home() / "profiles" / _active_profile() / "chio-capabilities.json"


def _load_cache() -> list[dict[str, Any]]:
    """Read the capability cache; return an empty list when missing."""
    path = _cache_path()
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        print(
            f"[chio-hermes] failed to read capability cache: {exc}",
            file=sys.stderr,
        )
        return []
    if not isinstance(data, list):
        return []
    return [entry for entry in data if isinstance(entry, dict)]


def _save_cache(entries: list[dict[str, Any]]) -> None:
    """Write the capability cache atomically (simple replace; no locking)."""
    path = _cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    serialised = json.dumps(entries, sort_keys=True, indent=2)
    path.write_text(serialised + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Argparse wiring
# ---------------------------------------------------------------------------


def setup(parser: argparse.ArgumentParser) -> None:
    """Register `issue` / `list` / `revoke` subparsers on `parser`."""
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output where supported.",
    )
    parser.add_argument(
        "--sidecar-url",
        default=None,
        help="Override CHIO_SIDECAR_URL for this invocation.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="HTTP timeout in seconds for sidecar calls (default 5).",
    )

    sub = parser.add_subparsers(dest="subcommand", required=True)

    issue = sub.add_parser("issue", help="Mint a Chio capability for Hermes.")
    issue.add_argument(
        "--subject",
        required=True,
        help="Hex Ed25519 public key of the agent subject.",
    )
    issue.add_argument(
        "--tool-server",
        action="append",
        default=[],
        help="Tool server id to grant (repeatable; e.g. fs, shell, git).",
    )
    issue.add_argument(
        "--tool-name",
        default="*",
        help="Tool name to grant (default: '*').",
    )
    issue.add_argument(
        "--ttl",
        type=int,
        default=3600,
        help="Token lifetime in seconds (default 3600).",
    )
    issue.add_argument(
        "--description",
        default="",
        help="Free-form description recorded in the local cache.",
    )

    listc = sub.add_parser("list", help="List locally cached capabilities.")
    listc.add_argument(
        "--active-only",
        action="store_true",
        help="Hide entries flagged as revoked (default: show all).",
    )

    revoke = sub.add_parser("revoke", help="Revoke a cached capability.")
    revoke.add_argument("capability_id", help="Capability id to revoke.")
    revoke.add_argument(
        "--reason",
        default="",
        help="Free-form reason recorded in the local cache.",
    )


# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------


def _build_scope(tool_servers: list[str], tool_name: str) -> Any:
    """Construct a `ChioScope` with one `ToolGrant` per requested server."""
    from chio_sdk.models import (
        ChioScope,
        Operation,
        ToolGrant,
    )

    grants = [
        ToolGrant(
            server_id=server,
            tool_name=tool_name,
            operations=[Operation.INVOKE],
        )
        for server in tool_servers
    ]
    return ChioScope(grants=grants)


def _do_issue(args: argparse.Namespace) -> int:
    """Implementation for `hermes chio issue`."""
    if not args.tool_server:
        print(
            "error: at least one --tool-server is required",
            file=sys.stderr,
        )
        return 2

    try:
        from chio_sdk.client import ChioClient
    except Exception as exc:  # noqa: BLE001
        print(f"error: chio-sdk-python is not importable: {exc}", file=sys.stderr)
        return 1

    sidecar_url = args.sidecar_url or os.environ.get("CHIO_SIDECAR_URL")
    scope = _build_scope(args.tool_server, args.tool_name)

    async def _run() -> Any:
        client_kwargs: dict[str, Any] = {"timeout": args.timeout}
        if sidecar_url:
            client_kwargs["base_url"] = sidecar_url
        client = ChioClient(**client_kwargs)
        try:
            return await client.create_capability(
                subject=args.subject,
                scope=scope,
                ttl_seconds=args.ttl,
            )
        finally:
            close = getattr(client, "close", None)
            if callable(close):
                try:
                    await close()
                except Exception:  # noqa: BLE001
                    pass

    try:
        token = asyncio.run(_run())
    except Exception as exc:  # noqa: BLE001
        print(f"error: create_capability failed: {exc}", file=sys.stderr)
        return 1

    cap_id = getattr(token, "id", None) or "<unknown>"
    expires_at = getattr(token, "expires_at", None)
    entry = {
        "capability_id": cap_id,
        "subject": args.subject,
        "tool_servers": list(args.tool_server),
        "tool_name": args.tool_name,
        "ttl_seconds": args.ttl,
        "description": args.description,
        "issued_at": int(time.time()),
        "expires_at": expires_at,
        "revoked": False,
    }

    cache = _load_cache()
    cache.append(entry)
    _save_cache(cache)

    if args.json:
        print(json.dumps(entry, sort_keys=True, indent=2))
    else:
        print(f"capability issued: {cap_id}")
        print(f"  subject:       {args.subject}")
        print(f"  tool servers:  {', '.join(args.tool_server)}")
        print(f"  ttl seconds:   {args.ttl}")
        if expires_at is not None:
            print(f"  expires at:    {expires_at}")
        print()
        print(f"  export CHIO_CAPABILITY_ID={cap_id}")
    return 0


def _do_list(args: argparse.Namespace) -> int:
    """Implementation for `hermes chio list`."""
    cache = _load_cache()
    if args.active_only:
        cache = [entry for entry in cache if not entry.get("revoked")]
    if args.json:
        print(json.dumps(cache, sort_keys=True, indent=2))
        return 0
    if not cache:
        print("no cached capabilities found")
        return 0
    for entry in cache:
        cap_id = entry.get("capability_id", "<unknown>")
        servers = ", ".join(entry.get("tool_servers") or [])
        revoked = " [revoked]" if entry.get("revoked") else ""
        print(f"- {cap_id}{revoked}")
        print(f"    subject:      {entry.get('subject', '<unknown>')}")
        print(f"    tool servers: {servers}")
        print(f"    expires_at:   {entry.get('expires_at')}")
        if entry.get("description"):
            print(f"    description:  {entry['description']}")
    return 0


def _do_revoke(args: argparse.Namespace) -> int:
    """Implementation for `hermes chio revoke`."""
    proc = subprocess.run(  # noqa: S603 - argv list, no shell
        ["chio", "trust", "revoke", "--capability-id", args.capability_id],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        print(
            f"error: chio trust revoke exited {proc.returncode}: "
            f"{proc.stderr.strip() or proc.stdout.strip()}",
            file=sys.stderr,
        )
        return proc.returncode or 1

    cache = _load_cache()
    found = False
    for entry in cache:
        if entry.get("capability_id") == args.capability_id:
            entry["revoked"] = True
            entry["revoked_at"] = int(time.time())
            entry["revoke_reason"] = args.reason
            found = True
    if found:
        _save_cache(cache)

    if args.json:
        print(json.dumps({"revoked": args.capability_id, "cached": found}, sort_keys=True))
    else:
        print(f"revoked capability {args.capability_id}")
        if not found:
            print("(no matching local cache entry)")
    return 0


def handle(args: argparse.Namespace) -> int:
    """Dispatch the parsed argparse namespace to the matching subcommand."""
    sub = getattr(args, "subcommand", None)
    if sub == "issue":
        return _do_issue(args)
    if sub == "list":
        return _do_list(args)
    if sub == "revoke":
        return _do_revoke(args)
    print(f"unknown subcommand: {sub!r}", file=sys.stderr)
    return 2


__all__ = ["handle", "setup"]
