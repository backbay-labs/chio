#!/usr/bin/env python3
"""Scan the prepared native OpenSSL binary with a pinned, unfiltered scanner."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import subprocess
import tarfile


SPEC = importlib.util.spec_from_file_location(
    "openssl_recipe", Path(__file__).with_name("prepare-macos-release-openssl.py")
)
RECIPE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECIPE)
GRYPE_VERSION = "0.118.0"
GRYPE_COMMIT = "756eb9a24f7beeafb6871a24e943e8a3ae210695"
GRYPE_ARCHIVES = {
    "arm64": ("darwin_arm64", "938f050bb5076c8aa761867b39843abad2414dfe4cc82b7d36886e634f49c640"),
    "x86_64": ("darwin_amd64", "cfeecf3462321c37ec4bd37dcd8a7f6630cc6c0c9997a07ff34002c5d7ef9bb3"),
}


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def prepared_identity(prepared: Path, target: str) -> dict:
    manifest = json.loads((prepared / "native-openssl.json").read_text())
    required = {"name": "openssl", "version": RECIPE.VERSION, "target": target,
                "source_url": RECIPE.SOURCE_URL, "source_sha256": RECIPE.SOURCE_SHA256,
                "test_command_exit": 0}
    if type(manifest.get("test_command_exit")) is not int or any(
        manifest.get(key) != value for key, value in required.items()
    ):
        raise ValueError("native preparation identity mismatch")
    files = manifest["files"]
    if not {"lib/libssl.a", "lib/libcrypto.a"}.issubset(files) or not any(
        name.startswith("include/") for name in files
    ):
        raise ValueError("native static library identity missing")
    prefix = (prepared / "install").resolve(strict=True)
    for name, expected in files.items():
        relative = Path(name)
        path = prefix / relative
        if relative.is_absolute() or ".." in relative.parts or path.is_symlink() or not (
            name in {"lib/libssl.a", "lib/libcrypto.a"} or name.startswith("include/")
        ) or not path.resolve(strict=True).is_relative_to(prefix) or digest(path) != expected:
            raise ValueError("native installed file identity mismatch")
    if digest(prepared / "commands.json") != manifest["commands_sha256"]:
        raise ValueError("native build command log identity mismatch")
    if digest(Path(RECIPE.__file__)) != manifest["recipe_sha256"]:
        raise ValueError("native preparation recipe identity mismatch")
    license_path = prepared / "source" / f"openssl-{RECIPE.VERSION}" / "LICENSE.txt"
    if digest(license_path) != manifest["license_sha256"]:
        raise ValueError("native license identity mismatch")
    return manifest


def validate_reports(catalog: dict, scan: dict, binary: Path, binary_hash: str,
                     now: datetime | None = None) -> None:
    if catalog.get("bomFormat") != "CycloneDX" or catalog.get("vulnerabilities", []) != []:
        raise ValueError("native scanner catalog invalid or contains vulnerabilities")
    components = catalog.get("components", [])
    discovered = [c for c in components if c.get("type") == "application" and c.get("name") == "openssl"]
    if len(discovered) != 1:
        raise ValueError("scanner did not discover exactly one native OpenSSL")
    component = discovered[0]
    if any(component.get(k) != v for k, v in {
        "version": RECIPE.VERSION, "purl": f"pkg:generic/openssl@{RECIPE.VERSION}",
        "cpe": f"cpe:2.3:a:openssl:openssl:{RECIPE.VERSION}:*:*:*:*:*:*:*",
    }.items()) or {"name": "syft:package:foundBy", "value": "binary-classifier-cataloger"} not in component.get("properties", []):
        raise ValueError("native scanner component identity mismatch")
    observed_files = [c for c in components if c.get("type") == "file" and c.get("name") == str(binary)]
    if len(observed_files) != 1 or {"alg": "SHA-256", "content": binary_hash} not in observed_files[0].get("hashes", []):
        raise ValueError("scanner catalog does not bind the actual native binary")
    if scan.get("source") != {"type": "file", "target": str(binary)}:
        raise ValueError("scanner report source mismatch")
    if scan.get("matches") != [] or scan.get("ignoredMatches", []) != []:
        raise ValueError("native scanner reports findings or ignored findings")
    descriptor = scan["descriptor"]
    if descriptor.get("name") != "grype" or descriptor.get("version") != GRYPE_VERSION:
        raise ValueError("native scanner version mismatch")
    config = descriptor["configuration"]
    if any(config.get(key) not in (None, [], "", False) for key in (
        "ignore", "exclude", "vex-documents", "vex-add", "ignore-wontfix", "ignore-states",
        "only-fixed", "only-notfixed",
    )) or config.get("match", {}).get("stock", {}).get("using-cpes") is not True:
        raise ValueError("native scanner used filters or disabled CPE matching")
    db = descriptor["db"]["status"]
    built = datetime.fromisoformat(db["built"].replace("Z", "+00:00"))
    age = (now or datetime.now(timezone.utc)) - built
    if db.get("valid") is not True or not timedelta(minutes=-5) <= age <= timedelta(hours=120):
        raise ValueError("native scanner database invalid or stale")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared", type=Path, required=True)
    parser.add_argument("--target", choices=RECIPE.TARGETS, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scanner-archive", type=Path, help="Optional checksum-pinned offline tool archive")
    args = parser.parse_args()
    arch = RECIPE.TARGETS[args.target][0]
    if platform.system() != "Darwin" or platform.machine() != arch:
        raise ValueError("requires the requested native macOS architecture")
    prepared = args.prepared.resolve(strict=True)
    native_manifest = prepared_identity(prepared, args.target)
    binary = prepared / "install/bin/openssl"
    before = digest(binary)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    platform_name, expected_archive = GRYPE_ARCHIVES[arch]
    asset = f"grype_{GRYPE_VERSION}_{platform_name}.tar.gz"
    url = f"https://github.com/anchore/grype/releases/download/v{GRYPE_VERSION}/{asset}"
    archive = args.scanner_archive.resolve() if args.scanner_archive else output / asset
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(output / "home"), "LC_ALL": "C"}
    Path(env["HOME"]).mkdir()
    commands = []

    def run(label, command):
        with (output / f"{label}.log").open("wb") as log:
            result = subprocess.run(command, cwd=output, env=env, stdout=log, stderr=subprocess.STDOUT)
        commands.append({"label": label, "argv": command, "exit": result.returncode})
        (output / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        if result.returncode:
            raise ValueError(f"native scanner {label} failed; inspect {output / (label + '.log')}")

    if not args.scanner_archive:
        run("download", ["/usr/bin/curl", "--fail", "--location", "--retry", "2", "--proto", "=https",
                         "--tlsv1.2", "--output", str(archive), url])
    if digest(archive) != expected_archive:
        raise ValueError("native scanner archive checksum mismatch")
    with tarfile.open(archive) as source:
        source.extractall(output / "tool", filter="data")
    scanner = output / "tool/grype"
    run("version", [str(scanner), "version", "--output", "json"])
    version = json.loads((output / "version.log").read_text())
    if version.get("version") != GRYPE_VERSION or version.get("gitCommit") != GRYPE_COMMIT:
        raise ValueError("native scanner executable identity mismatch")
    config = {
        "check-for-app-update": False, "ignore": [], "exclude": [], "vex-documents": [], "vex-add": [],
        "only-fixed": False, "only-notfixed": False, "ignore-states": "",
        "match-upstream-kernel-headers": True, "match": {"stock": {"using-cpes": True}},
        "db": {"cache-dir": str(output / "db"), "validate-age": True, "max-allowed-built-age": "120h"},
    }
    config_path = output / "grype.yaml"
    config_path.write_text(json.dumps(config, indent=2) + "\n")  # JSON is valid YAML.
    catalog_path = output / "native-openssl.catalog.cdx.json"
    scan_path = output / "native-openssl.grype.json"
    run("scan", [str(scanner), f"file:{binary}", "--config", str(config_path), "--fail-on", "negligible",
                 "--output", f"cyclonedx-json={catalog_path}", "--output", f"json={scan_path}"])
    scan = json.loads(scan_path.read_text())
    validate_reports(json.loads(catalog_path.read_text()), scan, binary, before)
    if digest(binary) != before or prepared_identity(prepared, args.target) != native_manifest:
        raise ValueError("native build material changed during scanning")
    result = {
        "passed": True, "native_binary_sha256": before, "target": args.target,
        "native_manifest_sha256": digest(prepared / "native-openssl.json"),
        "native_version": RECIPE.VERSION, "scanner_version": GRYPE_VERSION,
        "scanner_archive_url": url, "scanner_archive_sha256": expected_archive,
        "scanner_binary_sha256": digest(scanner), "config_sha256": digest(config_path),
        "catalog_sha256": digest(catalog_path), "scan_sha256": digest(scan_path),
        "database": scan["descriptor"]["db"],
        "coverage": "Prepared native OpenSSL only; not the full Chio executable or host acceptance.",
    }
    (output / "native-openssl-scan.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"PASS: discovered native OpenSSL {RECIPE.VERSION}; no known or ignored scanner findings")


if __name__ == "__main__":
    main()
