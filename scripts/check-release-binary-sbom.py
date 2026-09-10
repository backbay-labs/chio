#!/usr/bin/env python3
"""Validate the pinned Syft inventory of an executable before release upload."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tomllib
from urllib.parse import quote


CATALOGER = "cargo-auditable-binary-cataloger"
SYFT_VERSION = "1.51.1"
# These are nonoptional runtime dependencies of the CLI, not a package-count floor.
CRITICAL = ("chio-core", "chio-guards", "chio-kernel", "chio-runtime")
CLI_MANIFEST = "crates/products/chio-cli/Cargo.toml"


def digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def object_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON object key")
        result[key] = value
    return result


def package_version(manifest: dict, workspace: dict) -> str:
    version = manifest["package"]["version"]
    if version == {"workspace": True}:
        version = workspace["workspace"]["package"]["version"]
    require(isinstance(version, str) and bool(version), "missing source package version")
    return version


def expected_packages(root: Path, version: str) -> dict[str, str]:
    workspace = tomllib.loads((root / "Cargo.toml").read_text())
    cli = tomllib.loads((root / CLI_MANIFEST).read_text())
    require(cli["package"]["name"] == "chio-cli", "unexpected source CLI package")
    require(package_version(cli, workspace) == version, "release version differs from CLI source")
    expected = {"chio-cli": version}
    for name in CRITICAL:
        dependency = cli["dependencies"][name]
        require(dependency.get("workspace") is True and not dependency.get("optional", False),
                "critical package is no longer a nonoptional CLI dependency")
        path = workspace["workspace"]["dependencies"][name]["path"]
        manifest = tomllib.loads((root / path / "Cargo.toml").read_text())
        require(manifest["package"]["name"] == name, "critical package source identity differs")
        expected[name] = package_version(manifest, workspace)
    return expected


def properties(component: dict) -> dict[str, str]:
    result = {}
    values = component.get("properties", [])
    require(isinstance(values, list), "invalid component properties")
    for value in values:
        require(isinstance(value, dict), "invalid component property")
        name, text = value.get("name"), value.get("value")
        require(isinstance(name, str) and isinstance(text, str), "invalid component property value")
        # Syft may repeat unrelated metadata properties; identity fields must be singular.
        if name.startswith("syft:package:"):
            require(name not in result, "duplicate package identity property")
            result[name] = text
    return result


def validate(document: dict, binary: Path, root: Path, version: str) -> dict:
    require(isinstance(document, dict), "SBOM is not an object")
    require(document.get("bomFormat") == "CycloneDX" and document.get("specVersion") == "1.6",
            "expected CycloneDX 1.6")
    expected = expected_packages(root, version)
    metadata = document.get("metadata", {})
    require(isinstance(metadata, dict), "missing SBOM metadata")
    tools = metadata.get("tools", {})
    require(isinstance(tools, dict), "missing pinned Syft identity")
    syft = [tool for tool in tools.get("components", [])
            if isinstance(tool, dict) and tool.get("name") == "syft"]
    require(len(syft) == 1 and syft[0].get("version") == SYFT_VERSION,
            "unexpected Syft version")
    scanned = metadata.get("component", {})
    binary_hash = digest(binary)
    require(isinstance(scanned, dict) and scanned.get("type") == "file",
            "expected an executable file scan, not a source-tree SBOM")
    require(scanned.get("version") == "sha256:" + binary_hash,
            "SBOM is not bound to the supplied executable SHA256")

    lock = tomllib.loads((root / "Cargo.lock").read_text())
    locked = {(item["name"], item["version"]) for item in lock["package"]}
    components = document.get("components")
    require(isinstance(components, list) and bool(components), "binary dependency inventory is empty")
    refs = {}
    rust = {}
    for component in components:
        require(isinstance(component, dict), "invalid inventory component")
        reference = component.get("bom-ref")
        require(isinstance(reference, str) and bool(reference) and reference not in refs,
                "missing or duplicate component reference")
        refs[reference] = component
        props = properties(component)
        purl = component.get("purl", "")
        require(isinstance(purl, str), "invalid package URL")
        if props.get("syft:package:type") != "rust-crate" and not purl.startswith("pkg:cargo/"):
            continue
        name, package_ver = component.get("name"), component.get("version")
        require(isinstance(name, str) and bool(name) and isinstance(package_ver, str) and bool(package_ver),
                "missing Rust package identity")
        require(props.get("syft:package:foundBy") == CATALOGER,
                "Rust inventory was not cataloged from embedded binary audit data")
        require(props.get("syft:package:language") == "rust" and props.get("syft:package:type") == "rust-crate",
                "inconsistent Rust package classification")
        expected_purl = f"pkg:cargo/{quote(name, safe='')}@{quote(package_ver, safe='')}"
        require(purl == expected_purl, "Rust package URL differs from package identity")
        require((name, package_ver) in locked, "binary Rust package is absent from selected Cargo.lock")
        rust.setdefault(name, []).append((package_ver, reference))
    for name, package_ver in expected.items():
        matches = rust.get(name, [])
        require(len(matches) == 1 and matches[0][0] == package_ver,
                f"missing or unexpected required binary package: {name}")

    dependencies = document.get("dependencies")
    require(isinstance(dependencies, list) and bool(dependencies), "binary dependency relationships are missing")
    known = set(refs)
    if isinstance(scanned.get("bom-ref"), str):
        known.add(scanned["bom-ref"])
    edges = {}
    for entry in dependencies:
        require(isinstance(entry, dict), "invalid dependency entry")
        reference, targets = entry.get("ref"), entry.get("dependsOn", [])
        require(reference in known and reference not in edges and isinstance(targets, list),
                "unknown or duplicate dependency reference")
        require(all(isinstance(target, str) and target in known for target in targets),
                "unresolved binary dependency reference")
        require(len(set(targets)) == len(targets), "duplicate binary dependency edge")
        edges[reference] = targets
    cli_ref = rust["chio-cli"][0][1]
    reachable, pending = set(), [cli_ref]
    while pending:
        reference = pending.pop()
        if reference not in reachable:
            reachable.add(reference)
            pending.extend(edges.get(reference, []))
    require(all(rust[name][0][1] in reachable for name in CRITICAL),
            "required kernel packages are disconnected from the CLI dependency graph")
    return {"schema": "chio.release-binary-sbom-validation.v1", "passed": True,
            "binarySha256": binary_hash, "cliVersion": version,
            "syftVersion": SYFT_VERSION, "cataloger": CATALOGER,
            "requiredPackages": expected, "rustComponents": sum(map(len, rust.values())),
            "inventoryComponents": len(components), "dependencyEntries": len(dependencies),
            "cargoLockSha256": digest(root / "Cargo.lock"),
            "scope": "Embedded Rust inventory validation only. Native library coverage, independently extracted complete graph equality, and source/workspace SBOM equality are not established."}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        if args.report:
            require(args.report.resolve() not in {args.binary.resolve(), args.sbom.resolve()},
                    "validation report must differ from input files")
            # A refused retry must not leave an earlier passing report at the requested path.
            args.report.unlink(missing_ok=True)
        document = json.loads(args.sbom.read_text(), object_pairs_hook=object_pairs)
        result = validate(document, args.binary, args.root, args.expected_version)
        result["sbomSha256"] = digest(args.sbom)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Binary SBOM refused: {error}", file=sys.stderr)
        return 1
    output = json.dumps(result, indent=2) + "\n"
    if args.report:
        args.report.write_text(output)
    print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
