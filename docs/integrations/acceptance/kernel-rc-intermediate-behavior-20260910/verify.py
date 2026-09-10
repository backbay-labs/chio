#!/usr/bin/env python3
"""Verify this immutable intermediate evidence export, without running hosts."""
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
KERNEL = "9f7bc045c97e6c13d9c24641ac426bb61903e3ddab088203a681906ce79d7455"


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def digest(body):
    return hashlib.sha256(body).hexdigest()


def raw(path):
    return json.loads(gzip.decompress((ROOT / (path + ".gz")).read_bytes()))


def main():
    entries = json.loads((ROOT / "files.json").read_text())
    paths = [entry["path"] for entry in entries]
    require(len(paths) == len(set(paths)) == 3340, "raw inventory count or uniqueness changed")
    require({str(path.relative_to(ROOT)) for path in ROOT.rglob("*.gz")} == set(paths), "raw gzip inventory differs from manifest")
    for entry in entries:
        relative = Path(entry["path"])
        require(not relative.is_absolute() and ".." not in relative.parts, "unsafe evidence path")
        path = ROOT / relative
        require(path.is_file() and not path.is_symlink(), "missing or linked raw evidence")
        compressed = path.read_bytes()
        original = gzip.decompress(compressed)
        require(digest(compressed) == entry["sha256"], "compressed hash mismatch: " + str(relative))
        require(digest(original) == entry["originalSha256"], "original hash mismatch: " + str(relative))
        require(len(original) == entry["originalBytes"], "original size mismatch: " + str(relative))
    checksum_paths = []
    for line in (ROOT / "SHA256SUMS").read_text().splitlines():
        expected, name = line.split("  ", 1)
        relative = Path(name)
        require(not relative.is_absolute() and ".." not in relative.parts, "unsafe checksum path")
        path = ROOT / relative
        require(path.is_file() and not path.is_symlink(), "missing or linked checksum target")
        require(digest(path.read_bytes()) == expected, "checksum mismatch: " + name)
        checksum_paths.append(name)
    actual = {str(path.relative_to(ROOT)) for path in ROOT.rglob("*") if path.is_file() and path.name != "SHA256SUMS" and "__pycache__" not in path.parts}
    require(len(checksum_paths) == len(set(checksum_paths)), "duplicate checksum entries")
    require(set(checksum_paths) == actual, "checksum inventory does not cover exact export")
    shared = raw("plain-shared/manifest.json")
    require(shared["binarySha256"] == KERNEL and shared["binaryChangedDuringRun"] is False, "shared binary identity changed")
    require(len(shared["cases"]) == 11 and all(case["status"] == "passed" for case in shared["cases"]), "shared suite outcome changed")
    initial = raw("plain-native/results.json")
    require({row["host"]: row["passed"] for row in initial} == {"claude": False, "codex": True, "pi": True, "hermes": True, "openclaw": True}, "initial workflow outcomes changed")
    failed = raw("plain-native/claude/useful/results.json")
    require(failed[0]["passed"] is False and failed[0]["error"] == "Expected exact real native tool call absent: edit_file", "original Claude failure not retained")
    dispatch = raw("plain-native/claude/useful/useful/workflow/native-dispatch.json")
    require(len(dispatch["calls"]) == 1 and dispatch["calls"][0]["name"] == "mcp__chio__write_file", "original single-call observation changed")
    for group, hosts, commands in [("plain-matrix", ["claude", "codex", "pi", "hermes", "openclaw"], 33), ("claude-contract-matrix", ["claude"], 37)]:
        require(raw(group + "/identity.json")["kernelSha256"] == KERNEL, "matrix kernel identity changed")
        summary = raw(group + "/results.json")
        require(summary == [{"host": host, "passed": True, "cases": commands} for host in hosts], "matrix aggregate result changed")
        for host in hosts:
            runs = raw(group + "/" + host + "/runs.json")
            require(len(runs) == commands and len({run["case"] for run in runs}) == commands, "matrix command inventory changed")
            require(all(run["exitCode"] == 0 and run["timedOut"] is False for run in runs), "matrix driver command failed")
            require(raw(group + "/" + host + "/summary.json")["skips"] == 0, "matrix skip recorded")
    useful = raw("claude-contract-matrix/claude/useful/results.json")
    require(useful[0]["passed"] is True and useful[0]["newDispatchRows"] == 4, "replacement Claude workflow changed")
    sbom = raw("plain-sbom-negative/result.json")
    require(sbom["exitCode"] == 0 and sbom["components"] == 0, "empty inventory negative control changed")
    scan = json.loads((ROOT / "credential-exclusion.json").read_text())
    require(scan["passed"] is True and not scan["matchingPaths"] and scan["rawFilesScanned"] == len(entries), "credential exclusion record incomplete")
    print(json.dumps({"rawFilesVerified": len(entries), "checksumFilesVerified": len(checksum_paths), "sharedSuitesPassed": 11, "originalClaudeUsefulFailed": True, "originalMatrixCommandsPassed": 165, "replacementClaudeCommandsPassed": 37, "acceptedHosts": 0, "claim": "offline evidence consistency only; no native test rerun"}, indent=2))


if __name__ == "__main__":
    main()
