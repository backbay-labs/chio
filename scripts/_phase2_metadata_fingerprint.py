#!/usr/bin/env python3
"""Phase 2 helper: print a stable fingerprint of the cargo resolve graph.

The resolved dependency graph must not change when path deps are rewritten to
workspace deps. We hash, per resolve node, its sorted list of resolved
dependency package ids. A byte-identical SHA before and after the refactor
proves the change is semantically inert.
"""
import hashlib
import json
import subprocess
import sys


def main() -> int:
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1"],
        capture_output=True,
        text=True,
    )
    if out.returncode != 0:
        sys.stderr.write(out.stderr)
        return out.returncode
    meta = json.loads(out.stdout)
    nodes = meta["resolve"]["nodes"]
    fp = {}
    for node in nodes:
        fp[node["id"]] = sorted(dep["pkg"] for dep in node.get("deps", []))
    blob = json.dumps(fp, sort_keys=True)
    digest = hashlib.sha256(blob.encode()).hexdigest()
    print(f"resolve-node-count: {len(fp)}")
    print(f"resolve-sha256: {digest}")
    print(f"workspace-member-count: {len(meta['workspace_members'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
