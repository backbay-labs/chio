#!/usr/bin/env python3
"""Verify exact encoded evidence and child manifests from the repository root."""
import gzip
import hashlib
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parent
manifest = json.loads((root / "manifest.json").read_text())
sha = lambda data: hashlib.sha256(data).hexdigest()
for item in manifest["entries"]:
    stored = Path(item["storedPath"]).read_bytes()
    original = gzip.decompress(stored)
    assert len(stored) == item["storedBytes"] and sha(stored) == item["storedSha256"]
    assert len(original) == item["originalBytes"] and sha(original) == item["originalSha256"]
    retained = subprocess.check_output(["git", "cat-file", "blob", item["originalGitBlob"]])
    assert original == retained, item["originalPath"]
checked = 0
for item in manifest["originalChecksumManifests"]:
    path = Path(item["path"])
    if path.suffix == ".json":
        records = json.loads(path.read_text()).items()
    else:
        records = [(line.split("  ", 1)[1], line.split("  ", 1)[0])
                   for line in path.read_text().splitlines()]
    for name, digest in records:
        assert sha((path.parent / name).read_bytes()) == digest, (path, name)
        checked += 1
print(f"Verified {len(manifest['entries'])} exact raw Git blobs and {checked} child checksums.")
