#!/usr/bin/env python3
"""Verify retained evidence bytes and cross-record identities without executing them."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess


HERE = Path(__file__).resolve().parent


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, help="Optional frozen local binary to hash, never execute")
    parser.add_argument("--repository", type=Path, help="Optional source checkout for immutable Git object checks")
    args = parser.parse_args()
    checksums = {}
    for line in (HERE / "SHA256SUMS").read_text().splitlines():
        checksum, name = line.split("  ", 1)
        require(name not in checksums and not Path(name).is_absolute() and ".." not in Path(name).parts,
                "invalid checksum path")
        checksums[name] = checksum
    actual = {str(p.relative_to(HERE)) for p in HERE.rglob("*") if p.is_file() and p.name != "SHA256SUMS"}
    require(actual == set(checksums), "checksum inventory differs from evidence files")
    for name, expected in checksums.items():
        path = HERE / name
        require(not path.is_symlink() and digest(path.read_bytes()) == expected, f"stored file mismatch: {name}")
    files = json.loads((HERE / "files.json").read_text())["files"]
    manifest = json.loads((HERE / "manifest.json").read_text())
    require(manifest["rawFileCount"] == len(files), "raw file count mismatch")
    require({item["path"] for item in files} == {
        str(p.relative_to(HERE)) for p in (HERE / "raw").rglob("*") if p.is_file()
    }, "raw inventory omits or invents files")
    raw = {}
    for item in files:
        require(item["logicalPath"] not in raw, "duplicate logical raw path")
        encoded = (HERE / item["path"]).read_bytes()
        require(len(encoded) == item["storedBytes"] and digest(encoded) == item["storedSha256"], "compressed identity mismatch")
        require(encoded[:2] == b"\x1f\x8b" and encoded[4:8] == bytes(4), "gzip timestamp is not deterministic")
        decoded = gzip.decompress(encoded)
        require(len(decoded) == item["originalBytes"] and digest(decoded) == item["originalSha256"], "original byte identity mismatch")
        raw[item["logicalPath"]] = decoded

    def record(name):
        return json.loads(raw[name])

    build = record("build/build.json")
    require(raw["build/build.json"] == raw["artifact/build.json"], "copied build metadata differs")
    result = record("artifact/result.json")
    identity = record("artifact/identity.json")
    linkage = record("artifact/linkage.json")
    validation = record("artifact/validation.json")
    binary_hash = manifest["binarySha256"]
    require(build["binarySha256"] == identity["kernelSha256"] == result["kernelSha256"] ==
            linkage["sha256"] == validation["binarySha256"] == binary_hash, "binary identities differ")
    require(build["source"] == identity["kernelSource"] == result["kernelSource"] == manifest["source"], "kernel source identities differ")
    require(build["tree"] == identity["buildSourceTree"] == manifest["sourceTree"], "kernel tree identities differ")
    require(build["exitCode"] == 0 and build["sourceUnchanged"] is True and build["nativeInputsUnchanged"] is True,
            "build did not establish success with stable source and native inputs")
    require(build["binaryBytes"] == identity["size"] == manifest["binaryBytes"], "binary size mismatch")
    require(digest(raw["source/Cargo.lock"]) == build["cargoLockSha256"] == validation["cargoLockSha256"] == manifest["cargoLockSha256"], "Cargo lock identity mismatch")
    require(linkage["passed"] is True and all(c["exit"] == 0 for c in linkage["commands"]), "recorded loader check failed")
    require(all(p.startswith(("/System/Library/", "/usr/lib/")) for p in linkage["dependencies"]), "non-system load dependency")
    require(linkage["commands"][-1]["argv"][0] == "/usr/bin/sandbox-exec" and
            linkage["commands"][-1]["stdout"].strip() == manifest["version"], "missing actual isolated loader startup")
    require(validation["passed"] is True and validation["cataloger"] == "cargo-auditable-binary-cataloger", "embedded Rust validation failed")
    require(digest(raw["artifact/sbom.json"]) == validation["sbomSha256"], "SBOM identity mismatch")
    sbom = record("artifact/sbom.json")
    require(len(sbom["components"]) == validation["inventoryComponents"] and
            len(sbom["dependencies"]) == validation["dependencyEntries"], "SBOM counts differ")
    commands = record("artifact/commands.json")
    require([c["case"] for c in commands] == ["linkage", "syft", "inventory-validation"], "unexpected artifact cases")
    require(all(c["exitCode"] == 0 and c["inputsUnchanged"] is True for c in commands), "artifact case failed or changed inputs")
    for item in manifest["validationSources"]:
        expected = digest(raw["validation-source/" + item["path"]])
        require(expected == item["sha256"] and any(
            value == expected and path.endswith("/" + item["path"])
            for command in commands for path, value in command["inputHashes"].items()
        ), "actual validation source mismatch")
    native = record("native/native-openssl.json")
    scan = record("native/native-openssl-scan.json")
    require(scan["passed"] is True and digest(raw["native/native-openssl.json"]) == scan["native_manifest_sha256"], "native preparation/scan binding mismatch")
    for name, expected in native["files"].items():
        require(any(path.endswith("/install/" + name) and value == expected
                    for path, value in build["nativeMaterialSha256"].items()), "native build material mismatch")
    require(len(build["nativeMaterialSha256"]) == manifest["captureTimeNativeMaterialChecks"], "native material check count mismatch")
    native_output = raw["artifact/openssl-sys-build-output.txt"]
    require(digest(native_output) == result["nativeBuildOutputSha256"] and all(value in native_output for value in (
        b"cargo:rustc-link-lib=static=ssl", b"cargo:rustc-link-lib=static=crypto", b"cargo:version_number=30600040"
    )), "native static linker evidence mismatch")
    require(result["hostAcceptance"] is False and result["published"] is False and all(
        manifest["claims"][key] is False for key in ("hostAcceptance", "published", "hostedReleaseArtifact",
                                                   "completeNativeDependencyInventory", "independentCompleteGraphEquality")
    ), "unsupported acceptance or delivery claim")
    credential_check = json.loads((HERE / "credential-exclusion.json").read_text())
    require(credential_check["passed"] is True and credential_check["matchingPaths"] == [] and
            credential_check["mutableFooterExecuted"] is False and
            credential_check["compressedFilesDecoded"] == len(files) and
            credential_check["executedPrefixSha256"] == digest(raw["validation/credential-collector-prefix.py"]),
            "credential-exclusion evidence differs from the raw inventory")
    copy_checks = json.loads((HERE / "validation.json").read_text())["checks"]
    require(len(copy_checks) == 2 and all(c["exitCode"] == 0 for c in copy_checks), "product-copy checks failed")
    if args.binary:
        with args.binary.open("rb") as stream:
            observed = hashlib.file_digest(stream, "sha256").hexdigest()
        require(observed == binary_hash and args.binary.stat().st_size == manifest["binaryBytes"], "optional frozen binary identity differs")
    if args.repository:
        def git(*arguments):
            return subprocess.check_output(["git", "-C", str(args.repository), *arguments])
        require(git("rev-parse", manifest["source"] + "^{tree}").decode().strip() == manifest["sourceTree"], "Git source tree mismatch")
        for item in files:
            if item["origin"].startswith("git:"):
                _, revision, path = item["origin"].split(":", 2)
                require(digest(git("show", revision + ":" + path)) == item["originalSha256"], "immutable Git input mismatch")
    print(json.dumps({"passed": True, "filesChecked": len(checksums), "rawFilesChecked": len(raw),
                      "binarySha256": binary_hash, "binaryChecked": bool(args.binary),
                      "gitInputsChecked": bool(args.repository), "scope": "Retained local evidence integrity and identity only; no build or host rerun."}, indent=2))


if __name__ == "__main__":
    main()
