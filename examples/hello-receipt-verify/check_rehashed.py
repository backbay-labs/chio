"""Require semantic rejection even after an attacker updates package checksums."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def check(binary, original, destination):
    destination.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [binary, "evidence", "verify", "--input", str(original), "--json"],
        check=True,
        capture_output=True,
        timeout=60,
    )
    cases = []
    for name in ("unsigned-lineage", "changed-signed-token", "changed-receipt"):
        package = destination / name
        shutil.copytree(original, package)
        relative = "receipts.ndjson" if name == "changed-receipt" else "capability-lineage.ndjson"
        path = package / relative
        records = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        if name == "unsigned-lineage":
            records[0].pop("signed_capability")
            records[0]["provenance"] = "legacy_projection"
        elif name == "changed-signed-token":
            records[0]["signed_capability"]["subject"] = "01" * 32
        else:
            records[0]["receipt"]["tool_name"] = "substituted_tool"
        path.write_text("".join(json.dumps(record) + "\n" for record in records))
        manifest_path = package / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        for entry in manifest["files"]:
            payload = (package / entry["path"]).read_bytes()
            entry["sha256"] = hashlib.sha256(payload).hexdigest()
            entry["bytes"] = len(payload)
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
        result = subprocess.run(
            [binary, "evidence", "verify", "--input", str(package), "--json"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        (destination / (name + ".stdout.json")).write_text(result.stdout)
        (destination / (name + ".stderr.txt")).write_text(result.stderr)
        if result.returncode == 0:
            raise ValueError("Rehashed malicious package was accepted: " + name)
        # A verifier crash or CLI usage error is not a successful refusal.
        output = json.loads(result.stderr)
        if not output.get("code", "").startswith("urn:chio:error:attest:"):
            raise ValueError("Expected a structured semantic verification failure: " + name)
        cases.append(name)
    return {"refused_rehashed_packages": cases}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chio", default=os.environ.get("CHIO_BIN") or shutil.which("chio"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.chio:
        parser.error("Install the matching Chio CLI or set CHIO_BIN")
    root = Path(__file__).resolve().parent
    if args.output:
        print(json.dumps(check(args.chio, root / "fixtures/minimal-evidence", args.output)))
    else:
        with tempfile.TemporaryDirectory(prefix="chio-rehashed-evidence-") as temporary:
            print(json.dumps(check(args.chio, root / "fixtures/minimal-evidence", Path(temporary))))
