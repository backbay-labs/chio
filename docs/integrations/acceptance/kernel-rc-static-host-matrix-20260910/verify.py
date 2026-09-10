#!/usr/bin/env python3
"""Validate this evidence export offline; never launch a host or container."""
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
HOSTS = ["claude", "codex", "pi", "hermes", "openclaw"]
KERNEL = "c03a8a711dbbd15da2c59655d9ab6d8f0068a20187363db7a78f4b5422ded93e"


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def sha(body):
    return hashlib.sha256(body).hexdigest()


def body(path):
    return gzip.decompress((ROOT / (path + ".gz")).read_bytes())


def raw(path):
    return json.loads(body(path))


def safe(path):
    relative = Path(path)
    require(not relative.is_absolute() and ".." not in relative.parts, "unsafe evidence path")
    return relative


def main():
    entries = json.loads((ROOT / "files.json").read_text())
    names = [entry["path"] for entry in entries]
    require(len(names) == len(set(names)) == 2896, "raw file inventory changed")
    require({str(path.relative_to(ROOT)) for path in ROOT.rglob("*.gz")} == set(names), "gzip inventory differs from manifest")
    for entry in entries:
        path = ROOT / safe(entry["path"])
        require(path.is_file() and not path.is_symlink(), "raw evidence missing or linked")
        compressed = path.read_bytes()
        original = gzip.decompress(compressed)
        require(sha(compressed) == entry["sha256"], "compressed hash mismatch: " + entry["path"])
        require(sha(original) == entry["originalSha256"] and len(original) == entry["originalBytes"], "original identity mismatch: " + entry["path"])
    checks = []
    for line in (ROOT / "SHA256SUMS").read_text().splitlines():
        expected, name = line.split("  ", 1)
        path = ROOT / safe(name)
        require(path.is_file() and not path.is_symlink() and sha(path.read_bytes()) == expected, "checksum mismatch: " + name)
        checks.append(name)
    actual = {str(path.relative_to(ROOT)) for path in ROOT.rglob("*") if path.is_file() and path.name != "SHA256SUMS" and "__pycache__" not in path.parts}
    require(len(checks) == len(set(checks)) and set(checks) == actual, "checksum file coverage differs")
    identity = raw("matrix/identity.json")
    require(identity["kernelSha256"] == KERNEL and identity["kernelSource"] == "bafa02b06de93553cecb6f60b340f3dd8fd9b401", "kernel identity changed")
    require(raw("matrix/results.json") == [{"host": host, "passed": True, "cases": 37} for host in HOSTS], "matrix aggregate outcomes changed")
    snapshots = 0
    script_hashes = set()
    for host in HOSTS:
        runs = raw("matrix/" + host + "/runs.json")
        require(len(runs) == len({run["case"] for run in runs}) == 37, "command count changed")
        require([run["case"] for run in runs[:4]] == ["start-owner", "prepare-resource", "seed-approved-fixture", "useful"], "setup/useful partition changed")
        require(all(run["exitCode"] == 0 and run["timedOut"] is False for run in runs), "driver failure or timeout recorded")
        summary_path = "matrix/" + host + "/summary.json"
        summary = raw(summary_path)
        require(summary["passed"] is True and summary["cases"] == 37 and summary["skips"] == 0, "host summary changed")
        useful = raw("matrix/" + host + "/useful/results.json")
        require(useful[0]["passed"] is True and useful[0]["newDispatchRows"] == 4, "useful workflow outcome changed")
        if host == "claude":
            delivery = raw("matrix/claude/useful/useful/workflow/run.json")["terminal"]["hostDelivery"]
            require(delivery["confirmed"] == 4 and delivery["failed"] is False, "Claude delivery observation changed")
        elif host == "codex":
            delivery = raw("matrix/codex/useful/useful/launch.json")["host_delivery"]
            require(delivery["confirmed"] == 4 and delivery["failed"] is False, "Codex delivery observation changed")
        else:
            acknowledgements = useful[0]["acknowledgements"]
            require(len(acknowledgements) == 4 and all(row["acknowledged"] is True and row["hostDeliveryConfirmed"] is True for row in acknowledgements), "native delivery observations changed")
        for run in runs:
            if "driverSha256" not in run:
                require(run["case"] == "seed-approved-fixture" and run["command"][:2] == ["docker", "run"], "unaccounted unsnapshotted command")
                continue
            snapshot = "matrix/" + host + "/driver-snapshots/" + run["case"] + "-" + Path(run["command"][1]).name
            require(sha(body(snapshot)) == run["driverSha256"] and run["driverUnchangedDuringRun"] is True, "entry-script binding mismatch")
            snapshots += 1
            script_hashes.add(run["driverSha256"])
        stop = raw("completed-owner-stops/" + host + ".json")
        require(stop["host"] == host and stop["exitCode"] == 0 and stop["stateRetained"] is True, "owner shutdown outcome changed")
        require(stop["summarySha256"] == sha(body(summary_path)), "owner shutdown summary binding mismatch")
        require(stop["resourceVolume"] == "chio-required-static-matrix-20260910-" + host and stop["auditVolume"] == stop["resourceVolume"] + "-audit", "owner shutdown volume binding mismatch")
    require(snapshots == 180 and len(script_hashes) == 8, "entry snapshot inventory changed")
    review = raw("source-review/post-run-provenance.json")
    require(review["matrixDriverSha256"] == sha(body("matrix/driver.py")) and review["kernelPostRunSha256"] == KERNEL, "post-run source review binding mismatch")
    for helper in review["siblingHelperSourceComparison"]:
        source = "source-review/" + Path(helper["copiedSource"]).name
        require(sha(body(source)) == helper["sourceSha256"] == helper["currentSha256"], "helper source comparison mismatch")
        require(helper["currentMatchesSource"] is True and not helper["commitsChangingPathThroughRecordBase"], "helper source history changed")
    for line in body("completed-resource-drain/SHA256SUMS").decode().splitlines():
        expected, name = line.split("  ", 1)
        require(sha(body("completed-resource-drain/" + str(safe(name)))) == expected, "original drain checksum mismatch: " + name)
    drain = raw("completed-resource-drain/summary.json")
    require(drain["ownersStopped"] == drain["resourceContainersStopped"] == 22 and drain["namedVolumesPreserved"] == 44 and drain["persistentFilesMissing"] == 0 and not drain["failures"], "historical drain outcome changed")
    scan = json.loads((ROOT / "credential-exclusion.json").read_text())
    require(scan["passed"] is True and scan["rawFilesScanned"] == len(entries) and not scan["matchingPaths"], "credential scan record incomplete")
    print(json.dumps({"rawFilesVerified": len(entries), "checksumFilesVerified": len(checks), "setupCommands": 15, "usefulWorkflows": 5, "matrixCommands": 165, "driverEntrySnapshotsVerified": snapshots, "completedOwnerStops": 5, "historicalDrainedOwners": 22, "acceptedHosts": 0, "claim": "Offline evidence consistency only; no host execution or acceptance promotion"}, indent=2))


if __name__ == "__main__":
    main()
