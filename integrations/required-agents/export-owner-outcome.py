#!/usr/bin/env python3
"""Read one retained owner result without dispatching, acknowledging or editing state.

This is an operator-only SQLite export for the pinned local resource owner.
The installed bridge must verify its signature and original request binding
with owner-result-import before using it for explicit delivery recovery.
"""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import stat


def private(path, directory=False):
    info = path.lstat()
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if path.is_symlink() or not expected_type(info.st_mode) or info.st_mode & 0o077:
        raise ValueError("private regular operator path required")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["operator-state", "gateway-config", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--request-id", required=True)
    args = parser.parse_args()
    state = args.operator_state.absolute()
    private(state, True)
    private(args.gateway_config)
    private(args.output.absolute().parent, True)
    config = json.loads(args.gateway_config.read_text())
    database = state / "sessions.sqlite"
    if database.is_symlink() or not database.is_file():
        raise ValueError("owner database must be a regular file inside its private directory")
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        connection.execute("BEGIN")
        row = connection.execute(
            "SELECT record_json,signature FROM remote_session_credential_calls "
            "WHERE session_id=? AND request_id=?",
            (config["execution"]["sessionId"], args.request_id),
        ).fetchone()
    if row is None or len(row[0]) > 1024 * 1024:
        raise ValueError("no bounded retained owner result for this exact operation")
    record = json.loads(row[0])
    if record.get("state") not in ["completed_unacknowledged", "acknowledged"] or record.get("response") is None:
        raise ValueError("owner has no completed result; uncertainty remains fenced")
    payload = {"schema": "chio.gateway.owner-outcome.v1", "record": record, "signature": row[1]}
    fd = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(payload, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(args.output.absolute().parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    print(json.dumps({
        "output": str(args.output), "requestId": args.request_id,
        "protectedDispatch": False, "acknowledgedByExport": False,
        "verifiedByExport": False,
    }))


if __name__ == "__main__":
    main()
