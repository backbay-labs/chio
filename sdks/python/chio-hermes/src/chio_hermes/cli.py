"""`hermes chio` CLI subcommand: capability lifecycle helpers."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


def _hermes_home() -> Path:
    # Lazy resolve so chio_hermes imports without Hermes installed.
    try:
        from hermes_constants import get_hermes_home

        return Path(get_hermes_home())
    except Exception:
        return Path.home() / ".hermes"


def _active_profile() -> str:
    return os.environ.get("HERMES_PROFILE", "default")


def _cache_path() -> Path:
    return _hermes_home() / "profiles" / _active_profile() / "chio-capabilities.json"


def _load_cache() -> list[dict[str, Any]]:
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
    # Capability ids are bearer credentials; write tempfile + chmod 0600
    # + os.replace so a concurrent issue (race F15) cannot leave a torn
    # or world-readable file. Parent forced to 0700 on creation.
    path = _cache_path()
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(parent, 0o700)
    except OSError:
        pass
    serialised = json.dumps(entries, sort_keys=True, indent=2) + "\n"
    fd, tmp_name = tempfile.mkstemp(
        prefix=".chio-cap-",
        suffix=".tmp",
        dir=str(parent),
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(serialised)
        try:
            os.chmod(tmp_path, 0o600)
        except OSError:
            pass
        os.replace(tmp_path, path)
    except Exception:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise
    # Re-chmod in case os.replace crossed a filesystem boundary.
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def setup(parser: argparse.ArgumentParser) -> None:
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

    approvals = sub.add_parser(
        "approvals",
        help="Inspect and resolve pending HITL approvals on the sidecar.",
    )
    approvals_sub = approvals.add_subparsers(
        dest="approvals_subcommand", required=True
    )
    approvals_sub.add_parser(
        "list", help="List pending approvals from the sidecar."
    )
    respond = approvals_sub.add_parser(
        "respond",
        help="Approve or deny a pending approval (operator-respond shortcut).",
    )
    respond.add_argument("approval_id", help="Approval id to resolve.")
    verdict_group = respond.add_mutually_exclusive_group(required=True)
    verdict_group.add_argument(
        "--approve",
        dest="verdict",
        action="store_const",
        const="approve",
        help="Approve the held call.",
    )
    verdict_group.add_argument(
        "--deny",
        dest="verdict",
        action="store_const",
        const="deny",
        help="Deny the held call.",
    )
    respond.add_argument(
        "--reason",
        default=None,
        help="Free-form note recorded with the resolution.",
    )


def _build_scope(tool_servers: list[str], tool_name: str) -> Any:
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
    # `chio trust revoke` requires `--control-url` (control plane) or
    # `--revocation-db` (local sqlite). Resolve up front so we surface
    # a clear error rather than the opaque subprocess usage message.
    control_url = os.environ.get("CHIO_CONTROL_URL")
    revocation_db = os.environ.get("CHIO_REVOCATION_DB")
    backend_args: list[str]
    if control_url:
        backend_args = ["--control-url", control_url]
    elif revocation_db:
        backend_args = ["--revocation-db", revocation_db]
    else:
        print(
            "error: chio_revocation_backend_unconfigured: set "
            "CHIO_CONTROL_URL or CHIO_REVOCATION_DB before "
            "`hermes chio revoke`",
            file=sys.stderr,
        )
        return 2

    proc = subprocess.run(  # noqa: S603 - argv list, no shell
        [
            "chio",
            "trust",
            "revoke",
            "--capability-id",
            args.capability_id,
            *backend_args,
        ],
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


def _approvals_client(args: argparse.Namespace) -> Any:
    """Construct a `ChioClient` for approval operations."""
    from chio_sdk.client import ChioClient

    sidecar_url = args.sidecar_url or os.environ.get("CHIO_SIDECAR_URL")
    client_kwargs: dict[str, Any] = {"timeout": args.timeout}
    if sidecar_url:
        client_kwargs["base_url"] = sidecar_url
    return ChioClient(**client_kwargs)


def _do_approvals_list(args: argparse.Namespace) -> int:
    try:
        client = _approvals_client(args)
    except Exception as exc:  # noqa: BLE001
        print(f"error: chio-sdk-python is not importable: {exc}", file=sys.stderr)
        return 1

    async def _run() -> Any:
        try:
            return await client.list_pending_approvals()
        finally:
            try:
                await client.close()
            except Exception:  # noqa: BLE001
                pass

    try:
        rows = asyncio.run(_run())
    except Exception as exc:  # noqa: BLE001
        print(f"error: list_pending_approvals failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        payload = [
            row.model_dump() if hasattr(row, "model_dump") else dict(row)
            for row in rows
        ]
        print(json.dumps(payload, sort_keys=True, indent=2))
        return 0

    if not rows:
        print("no pending chio approvals")
        return 0

    print(f"pending chio approvals ({len(rows)}):")
    for row in rows:
        approval_id = getattr(row, "approval_id", "?")
        tool_server = getattr(row, "tool_server", "?")
        tool_name = getattr(row, "tool_name", "?")
        summary = getattr(row, "summary", "")
        expires_at = getattr(row, "expires_at", "?")
        print(
            f"  - {approval_id} {tool_server}/{tool_name} "
            f"expires={expires_at} summary={summary!r}"
        )
    return 0


def _do_approvals_respond(args: argparse.Namespace) -> int:
    try:
        client = _approvals_client(args)
    except Exception as exc:  # noqa: BLE001
        print(f"error: chio-sdk-python is not importable: {exc}", file=sys.stderr)
        return 1

    async def _run() -> Any:
        try:
            return await client.respond_approval(
                args.approval_id, args.verdict, args.reason
            )
        finally:
            try:
                await client.close()
            except Exception:  # noqa: BLE001
                pass

    try:
        result = asyncio.run(_run())
    except Exception as exc:  # noqa: BLE001
        print(
            f"error: respond_approval failed for {args.approval_id}: {exc}",
            file=sys.stderr,
        )
        return 1

    outcome = getattr(result, "outcome", args.verdict)
    outcome_str = getattr(outcome, "value", str(outcome))
    if args.json:
        payload = (
            result.model_dump() if hasattr(result, "model_dump") else dict(result)
        )
        print(json.dumps(payload, sort_keys=True, indent=2))
        return 0

    print(f"chio approval {args.approval_id} -> {outcome_str}")
    if args.reason:
        print(f"  reason: {args.reason}")
    print(
        "Retry the original tool call to proceed (auto-resume is v0.3 work)."
    )
    return 0


def handle(args: argparse.Namespace) -> int:
    sub = getattr(args, "subcommand", None)
    if sub == "issue":
        return _do_issue(args)
    if sub == "list":
        return _do_list(args)
    if sub == "revoke":
        return _do_revoke(args)
    if sub == "approvals":
        approvals_sub = getattr(args, "approvals_subcommand", None)
        if approvals_sub == "list":
            return _do_approvals_list(args)
        if approvals_sub == "respond":
            return _do_approvals_respond(args)
        print(
            f"unknown approvals subcommand: {approvals_sub!r}",
            file=sys.stderr,
        )
        return 2
    print(f"unknown subcommand: {sub!r}", file=sys.stderr)
    return 2


__all__ = ["handle", "setup"]
