#!/usr/bin/env python3
"""Detect unresolved stub and placeholder surfaces in tracked text files."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import subprocess
import sys


SEARCH_PREFIXES = ("crates/", "tests/", "examples/", "scripts/", "docs/")
MATCH_RE = re.compile(
    r"bbs-stub|not_yet_implemented|advisory only|\bTODO\b|\bFIXME\b|\bHACK\b|"
    r"\bXXX\b|\b[Ss]tubs?\b|\b[Pp]laceholders?\b"
)


@dataclass(frozen=True)
class AllowlistEntry:
    reason: str
    expires: str


@dataclass(frozen=True)
class DenylistEntry:
    reason: str
    until: str


def allow(reason: str, expires: str) -> AllowlistEntry:
    return AllowlistEntry(reason=reason, expires=expires)


ALLOWLIST: dict[str, AllowlistEntry] = {
    "crates/chio-acp-edge/src/bridge.rs": allow(
        "intentional advisory permission preview text, enforcement happens at invoke time",
        "Phase 6.1 review",
    ),
    "crates/chio-acp-proxy/src/kernel_signer.rs": allow(
        "debug-only placeholder string is not used for signature verification",
        "Phase 6.1 review",
    ),
    "crates/chio-federation/Cargo.toml": allow(
        "feature-gated selective-disclosure surface named bbs-stub",
        "Phase 2.2 review",
    ),
    "crates/chio-federation/src/lib.rs": allow(
        "feature-gated selective-disclosure surface named bbs-stub",
        "Phase 2.2 review",
    ),
    "crates/chio-federation/src/selective_disclosure.rs": allow(
        "feature-gated bbs-stub implementation isolated behind cfg(feature = \"bbs-stub\")",
        "Phase 2.2 review",
    ),
    "crates/chio-api-protect/src/proxy/http_util.rs": allow(
        "route-status metadata for the failing sidecar attenuation route",
        "Phase 5.3",
    ),
    "crates/chio-api-protect/src/proxy/router.rs": allow(
        "route registration notes for the failing sidecar attenuation route",
        "Phase 5.3",
    ),
    "crates/chio-anchor/src/batch.rs": allow(
        "reviewed test fixture inside cfg(test)",
        "Phase 7 review",
    ),
    "crates/chio-anchor/src/witness.rs": allow(
        "reviewed test fixture helper",
        "Phase 7 review",
    ),
    "crates/chio-anchor/src/witness/rekor.rs": allow(
        "reviewed test fixture helper",
        "Phase 7 review",
    ),
    "crates/chio-arena/src/promote.rs": allow(
        "reviewed test seam for injecting CHIO_BLESS environment access",
        "Phase 7 review",
    ),
    "crates/chio-attest-verify/src/lib.rs": allow(
        "negative crate invariant text forbids todo and unimplemented macros",
        "Phase 6.1 review",
    ),
    "crates/chio-cli/dashboard/src/components/BudgetSparkline.tsx": allow(
        "UI empty-state placeholder, not an implementation stub",
        "Phase 8.2 review",
    ),
    "crates/chio-cli/dashboard/src/components/FilterSidebar.tsx": allow(
        "HTML input placeholder attributes, not implementation stubs",
        "Phase 8.2 review",
    ),
    "crates/chio-cli/dashboard/src/components/ReceiptTable.tsx": allow(
        "UI Suspense loading placeholder, not an implementation stub",
        "Phase 8.2 review",
    ),
    "crates/chio-cli/dashboard/src/index.css": allow(
        "CSS class for UI empty-state placeholder",
        "Phase 8.2 review",
    ),
    "crates/chio-cli/src/cli/mcp/manifest.rs": allow(
        "generated guard-manifest scaffold intentionally carries review TODO text",
        "Phase 6.1 review",
    ),
    "crates/chio-cli/src/cli/replay/execute.rs": allow(
        "reviewed replay fixture server used for offline evaluation",
        "Phase 7 review",
    ),
    "crates/chio-cli/src/cli/replay/validate.rs": allow(
        "reviewed replay validation fixture placeholder overwritten by signature tests",
        "Phase 7 review",
    ),
    "crates/chio-cli/src/cli/runtime.rs": allow(
        "reviewed local start scaffold OpenAPI document, not a security boundary",
        "Phase 6.1 review",
    ),
    "crates/chio-cli/src/cli/session.rs": allow(
        "reviewed CLI session fixture payload",
        "Phase 7 review",
    ),
    "crates/chio-cli/src/doctor/cosign.rs": allow(
        "reviewed doctor test fixture writes stub JSON under cfg(test)",
        "Phase 7 review",
    ),
    "crates/chio-cli/src/guard.rs": allow(
        "deny-by-default guard scaffold template, not a shipped allow path",
        "Phase 6.1 review",
    ),
    "crates/chio-cli/templates/init/README.md.tmpl": allow(
        "template README for generated example tool server",
        "Phase 8.2 review",
    ),
    "crates/chio-config/src/interpolation.rs": allow(
        "domain placeholder resolution term, not an unfinished implementation",
        "Phase 6.1 review",
    ),
    "crates/chio-conformance/Cargo.toml": allow(
        "conformance feature forwards the explicit bbs-stub feature gate",
        "Phase 8.1 review",
    ),
    "crates/chio-conformance/peers.lock.toml": allow(
        "pre-publication peer lock placeholders are guarded by published=false",
        "Phase 8.2 review",
    ),
    "crates/chio-conformance/src/peers.rs": allow(
        "peer-lock placeholder pins fail closed unless published=false",
        "Phase 8.2 review",
    ),
    "crates/chio-conformance/verdict_matrix/drivers/lambda/src/lib.rs": allow(
        "negative documentation says Lambda availability gate is not a placeholder",
        "Phase 8.2 review",
    ),
    "crates/chio-core-types/src/crypto.rs": allow(
        "reviewed fail-closed comments around non-Ed25519 byte conversions",
        "Phase 3 review",
    ),
    "crates/chio-core-types/src/plan.rs": allow(
        "advisory plan edges are intentional v1 metadata",
        "Phase 3 review",
    ),
    "crates/chio-core-types/src/receipt.rs": allow(
        "advisory trust level is an intentional receipt enum variant",
        "Phase 3.2 review",
    ),
    "crates/chio-custody-hw/src/capability.rs": allow(
        "reviewed pre-signing constructor and cfg(test) fixture language",
        "Phase 6.1 review",
    ),
    "crates/chio-custody-hw/src/issuer.rs": allow(
        "reviewed pre-signing constructor call that is signed before emission",
        "Phase 6.1 review",
    ),
    "crates/chio-custody-hw/src/lib.rs": allow(
        "negative crate-level invariant forbids trust-boundary stubs",
        "Phase 6.1 review",
    ),
    "crates/chio-custody-hw/src/mint.rs": allow(
        "reviewed pre-signing constructor call that is signed before emission",
        "Phase 6.1 review",
    ),
    "crates/chio-custody-hw/src/verifier.rs": allow(
        "reviewed cfg(test) WebAuthn assertion fixture",
        "Phase 7 review",
    ),
    "crates/chio-data-guards/redactors/default/src/lib.rs": allow(
        "phone-number pattern documentation, not a stub marker",
        "Phase 6.1 review",
    ),
    "crates/chio-envoy-ext-authz/proto/envoy/config/core/v3/base.proto": allow(
        "protocol fixture text for opaque Envoy fields",
        "Phase 7 review",
    ),
    "crates/chio-envoy-ext-authz/src/service.rs": allow(
        "reviewed adapter test seam documented in trait comment",
        "Phase 7 review",
    ),
    "crates/chio-guard-registry/src/pull.rs": allow(
        "reserved Sigstore cache slot fails closed with empty bytes",
        "Phase 6.1 review",
    ),
    "crates/chio-http-core/src/routes.rs": allow(
        "route-template placeholder terminology",
        "Phase 6.1 review",
    ),
    "crates/chio-kernel-browser/src/clock.rs": allow(
        "cfg(not wasm32) host-target test stub returns fail-closed time",
        "Phase 6.2 review",
    ),
    "crates/chio-kernel-browser/src/lib.rs": allow(
        "test signing placeholder is replaced before pure receipt signing returns",
        "Phase 6.2 review",
    ),
    "crates/chio-kernel-browser/src/rng.rs": allow(
        "cfg(not wasm32) host-target stub always fails outside browser wasm",
        "Phase 6.2 review",
    ),
    "crates/chio-lineage/src/anchor.rs": allow(
        "signing state explicitly distinguishes unsigned signer hint from real signature",
        "Phase 6.1 review",
    ),
    "crates/chio-log-redact/src/engine.rs": allow(
        "fail-closed redaction placeholder prevents original secret exposure",
        "Phase 6.1 review",
    ),
    "crates/chio-metering/src/export.rs": allow(
        "timestamp fallback text is reviewed and deterministic",
        "Phase 6.1 review",
    ),
    "crates/chio-pheromone-relay/src/metrics.rs": allow(
        "SQL bind placeholder terminology, not an unfinished stub surface",
        "Phase 6.1 review",
    ),
    "crates/chio-policy/src/detection.rs": allow(
        "policy detector name used as domain data and covered by tests",
        "Phase 6.1 review",
    ),
    "crates/chio-provider-conformance/src/replay.rs": allow(
        "feature-gated replay stubs fail with guidance when provider features are absent",
        "Phase 6.1 review",
    ),
    "crates/chio-revocation-oracle/src/signer.rs": allow(
        "reviewed digest-only test signature marker",
        "Phase 7 review",
    ),
    "crates/chio-spec-codegen/src/lib.rs": allow(
        "generator writes placeholder generated mod.rs with canonical header",
        "Phase 8.1",
    ),
    "crates/chio-spec-codegen/src/main.rs": allow(
        "threat-model test-stub generator command surface",
        "Phase 8.1",
    ),
    "crates/chio-spec-codegen/src/threat_coverage_doc.rs": allow(
        "threat-model test-stub documentation generator",
        "Phase 8.1",
    ),
    "crates/chio-spec-codegen/src/threat_model.rs": allow(
        "threat-model test-stub generator, expected to fail closed until populated",
        "Phase 8.1",
    ),
    "crates/chio-store-sqlite/src/receipt_store/evidence_retention.rs": allow(
        "SQL bind placeholder terminology, not an unfinished stub surface",
        "Phase 6.1 review",
    ),
    "crates/chio-tee/src/tap.rs": allow(
        "reviewed TrafficTap test-double implementations",
        "Phase 7 review",
    ),
    "crates/chio-wasm-guards/src/fuzz.rs": allow(
        "fuzz fixture text describing an allocator stub",
        "Phase 7 review",
    ),
    "crates/chio-wasm-guards/src/lib.rs": allow(
        "exports the placeholder-resolution API module",
        "Phase 5.1 review",
    ),
    "crates/chio-wasm-guards/src/placeholders.rs": allow(
        "domain placeholder-resolution API for guard configuration",
        "Phase 5.1 review",
    ),
    "crates/chio-wasm-guards/src/runtime.rs": allow(
        "domain placeholder-resolution API use for guard configuration",
        "Phase 5.1 review",
    ),
    "crates/chio-weights/src/lib.rs": allow(
        "negative crate invariant text forbids verifier and trust-boundary stubs",
        "Phase 6.2 review",
    ),
    "crates/chio-weights/src/lineage.rs": allow(
        "PQ-hybrid signing-state placeholder mirrors explicit unsigned lineage state",
        "Phase 6.2 review",
    ),
}

DENYLIST: dict[str, DenylistEntry] = {
    "crates/chio-api-protect/src/proxy/sidecar.rs": DenylistEntry(
        reason="capability attenuation route still advertises a 501 not_yet_implemented stub",
        until="Phase 5.3 resolves or fail-closes the route",
    )
}


@dataclass(frozen=True)
class Hit:
    path: str
    line: int
    category: str
    text: str
    allowlist: AllowlistEntry | None
    denylist: DenylistEntry | None


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def tracked_files(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return [
        line
        for line in result.stdout.splitlines()
        if line.startswith(SEARCH_PREFIXES)
    ]


def classify(path: str) -> str:
    name = Path(path).name
    suffix = Path(path).suffix
    if "/_generated/" in f"/{path}/" or name in {
        "package-lock.json",
        "Cargo.lock",
    }:
        return "generated"
    if path.startswith("docs/") or suffix in {".md", ".adoc"}:
        return "docs"
    if path.startswith("scripts/"):
        return "scripts"
    if path.startswith("examples/") or "/examples/" in f"/{path}/":
        return "examples"
    if (
        path.startswith("tests/")
        or "/tests/" in f"/{path}/"
        or name == "tests.rs"
        or ".test." in name
        or name.endswith("_test.go")
        or name.endswith("_tests.rs")
    ):
        return "tests"
    return "production"


def read_text(path: Path) -> str | None:
    if not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def collect_hits(root: Path, paths: list[str]) -> list[Hit]:
    hits: list[Hit] = []
    for path in paths:
        text = read_text(root / path)
        if text is None:
            continue
        category = classify(path)
        allowlist = ALLOWLIST.get(path)
        denylist = DENYLIST.get(path)
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not MATCH_RE.search(line):
                continue
            hits.append(
                Hit(
                    path=path,
                    line=line_number,
                    category=category,
                    text=line.strip(),
                    allowlist=allowlist,
                    denylist=denylist,
                )
            )
    return hits


def validate_lists(errors: list[str]) -> None:
    for path, entry in sorted(ALLOWLIST.items()):
        if not entry.reason.strip():
            errors.append(f"{path}: allowlist entry has an empty reason")
        if not entry.expires.strip():
            errors.append(f"{path}: allowlist entry has an empty expiry")
    for path, entry in sorted(DENYLIST.items()):
        if not entry.reason.strip():
            errors.append(f"{path}: denylist entry has an empty reason")
        if not entry.until.strip():
            errors.append(f"{path}: denylist entry has an empty until field")


def print_summary(hits: list[Hit]) -> None:
    print("Stub-surface scan summary")
    counts: dict[str, int] = {}
    for hit in hits:
        counts[hit.category] = counts.get(hit.category, 0) + 1
    for category in sorted(counts):
        print(f"{category}: {counts[category]} hit(s)")

    print("\nProduction hits:")
    production_hits = [hit for hit in hits if hit.category == "production"]
    if not production_hits:
        print("none")
        return
    for hit in production_hits[:120]:
        marker = ""
        if hit.denylist:
            marker = f" denylisted until {hit.denylist.until}"
        elif hit.allowlist:
            marker = f" allowlisted until {hit.allowlist.expires}"
        print(f"{hit.path}:{hit.line}:{marker} {hit.text}")
    if len(production_hits) > 120:
        print(f"... {len(production_hits) - 120} more production hit(s)")


def main() -> int:
    parser = argparse.ArgumentParser(description="Check tracked stub surfaces.")
    parser.add_argument(
        "--root",
        type=Path,
        default=repo_root(),
        help="repository root to inspect",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    errors: list[str] = []
    validate_lists(errors)

    try:
        paths = tracked_files(root)
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip()
        print(f"failed to list tracked files under {root}: {stderr}", file=sys.stderr)
        return 1

    hits = collect_hits(root, paths)
    print_summary(hits)

    failures: list[str] = []
    for hit in hits:
        if hit.category != "production":
            continue
        if hit.denylist:
            failures.append(
                f"{hit.path}:{hit.line}: blocked production stub surface: "
                f"{hit.denylist.reason}; blocked until {hit.denylist.until}"
            )
            continue
        if hit.allowlist:
            continue
        failures.append(
            f"{hit.path}:{hit.line}: production stub-surface hit is not allowlisted: "
            f"{hit.text}"
        )

    failures.extend(errors)
    if failures:
        print("\nStub-surface failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print("\nStub-surface check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
