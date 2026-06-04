#!/usr/bin/env python3
"""Check that broad diffs have explicit review slices."""

from __future__ import annotations

import argparse
import fnmatch
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BROAD_DIFF_FILE_COUNT = 200
BROAD_DIFF_MIN_SLICES = 5


@dataclass(frozen=True)
class ReviewSlice:
    name: str
    description: str
    patterns: tuple[str, ...]


SLICES: tuple[ReviewSlice, ...] = (
    ReviewSlice(
        "architecture-docs",
        "ARCHITECTURE.md files and architecture/reference docs",
        (
            "**/ARCHITECTURE.md",
            "README.md",
            "docs/**",
            "spec/**",
        ),
    ),
    ReviewSlice(
        "core-protocol",
        "core protocol types, canonical bytes, HTTP/session contracts, manifests",
        (
            "crates/chio-core-types/**",
            "crates/chio-core/**",
            "crates/chio-http-core/**",
            "crates/chio-http-session/**",
            "crates/chio-manifest/**",
            "crates/chio-config/**",
            "crates/chio-egress-contract/**",
            "crates/chio-errors/**",
            "crates/chio-binding-helpers/**",
            "crates/chio-workflow/**",
        ),
    ),
    ReviewSlice(
        "kernel-runtime",
        "kernel, runtime, portable/browser/mobile kernels, runtime harnesses",
        (
            "crates/chio-kernel/**",
            "crates/chio-kernel-core/**",
            "crates/chio-kernel-browser/**",
            "crates/chio-kernel-mobile/**",
            "crates/chio-runtime/**",
            "crates/chio-runtime-core/**",
            "crates/chio-runtime-harness/**",
            "crates/chio-tool-call-fabric/**",
            "crates/chio-tower/**",
        ),
    ),
    ReviewSlice(
        "guards-policy",
        "guards, policy evaluation, guard SDKs, and guard registries",
        (
            "crates/chio-guards/**",
            "crates/chio-data-guards/**",
            "crates/chio-external-guards/**",
            "crates/chio-wasm-guards/**",
            "crates/chio-policy/**",
            "crates/chio-guard-sdk/**",
            "crates/chio-guard-sdk-macros/**",
            "crates/chio-guard-registry/**",
            "sdks/guard/**",
            "wit/**",
        ),
    ),
    ReviewSlice(
        "adapters-edges",
        "protocol adapters, provider adapters, edges, bridges, integrations",
        (
            "crates/chio-*-adapter/**",
            "crates/chio-*-edge/**",
            "crates/chio-*-proxy/**",
            "crates/chio-openapi/**",
            "crates/chio-openapi-mcp-bridge/**",
            "crates/chio-cross-protocol/**",
            "crates/chio-ag-ui-proxy/**",
            "crates/chio-edge-metrics/**",
            "crates/chio-envoy-ext-authz/**",
            "crates/chio-hosted-mcp/**",
            "crates/chio-mcp-remote/**",
            "crates/chio-otel-receipt-exporter/**",
            "crates/chio-openai/**",
            "crates/chio-provider-adapter-core/**",
            "integrations/**",
        ),
    ),
    ReviewSlice(
        "storage-control-observability",
        "control plane, stores, metering, SIEM, operational state",
        (
            "crates/chio-control-plane/**",
            "crates/chio-store-sqlite/**",
            "crates/chio-log-redact/**",
            "crates/chio-metering/**",
            "crates/chio-metrics-spec/**",
            "crates/chio-siem/**",
            "crates/chio-revocation-oracle/**",
            "crates/chio-pheromone/**",
            "crates/chio-pheromone-relay/**",
            "crates/chio-pheromone-runtime/**",
        ),
    ),
    ReviewSlice(
        "economics-identity-web3",
        "credit, markets, settlement, identity, federation, governance, Web3",
        (
            "crates/chio-appraisal/**",
            "crates/chio-autonomy/**",
            "crates/chio-credit/**",
            "crates/chio-market/**",
            "crates/chio-open-market/**",
            "crates/chio-settle/**",
            "crates/chio-anchor/**",
            "crates/chio-underwriting/**",
            "crates/chio-link/**",
            "crates/chio-lineage/**",
            "crates/chio-listing/**",
            "crates/chio-weights/**",
            "crates/chio-custody-hw/**",
            "crates/chio-did/**",
            "crates/chio-credentials/**",
            "crates/chio-federation/**",
            "crates/chio-federation-authority/**",
            "crates/chio-governance/**",
            "crates/chio-reputation/**",
            "crates/chio-web3/**",
            "crates/chio-web3-bindings/**",
        ),
    ),
    ReviewSlice(
        "attestation-conformance-formal",
        "attestation, conformance, replay, formal, adversarial, test corpora",
        (
            "crates/chio-attest-*/**",
            "crates/chio-arena/**",
            "crates/chio-conformance/**",
            "crates/chio-eval-receipt/**",
            "crates/chio-provider-conformance/**",
            "crates/chio-adversarial-suite/**",
            "crates/chio-replay-corpus/**",
            "crates/chio-replay-gate/**",
            "crates/chio-selective-disclosure/**",
            "crates/chio-spec-codegen/**",
            "crates/chio-spec-validate/**",
            "crates/chio-tee/**",
            "crates/chio-tee-frame/**",
            "crates/chio-test-support/**",
            "formal/**",
            "tests/**",
        ),
    ),
    ReviewSlice(
        "sdks-examples",
        "language SDKs and runnable examples",
        (
            "crates/chio-bindings-ffi/**",
            "crates/chio-cpp-kernel-ffi/**",
            "sdks/**",
            "examples/**",
        ),
    ),
    ReviewSlice(
        "products-editors-bench",
        "CLI/products, editors, benchmark and demo surfaces",
        (
            "crates/chio-cli/**",
            "crates/chio-api-protect/**",
            "crates/chio-lsp/**",
            "crates/chio-mercury/**",
            "crates/chio-mercury-core/**",
            "crates/chio-wall/**",
            "crates/chio-wall-core/**",
            "bench/**",
            "editors/**",
        ),
    ),
    ReviewSlice(
        "ci-tooling-workspace",
        "CI workflows, scripts, workspace metadata, xtask and scanner config",
        (
            ".github/**",
            "scripts/**",
            "xtask/**",
            "Cargo.toml",
            "Cargo.lock",
            "osv-scanner.toml",
        ),
    ),
)


def changed_files(base_ref: str) -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", f"{base_ref}...HEAD"],
        cwd=REPO_ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    return [line for line in result.stdout.splitlines() if line]


def classify(path: str) -> ReviewSlice | None:
    for review_slice in SLICES:
        for pattern in review_slice.patterns:
            if fnmatch.fnmatch(path, pattern):
                return review_slice
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check changed files are partitioned into reviewable slices."
    )
    parser.add_argument("--base-ref", default="origin/main")
    args = parser.parse_args()

    files = changed_files(args.base_ref)
    by_slice: dict[str, list[str]] = defaultdict(list)
    unclassified: list[str] = []

    for path in files:
        review_slice = classify(path)
        if review_slice is None:
            unclassified.append(path)
        else:
            by_slice[review_slice.name].append(path)

    if unclassified:
        print("unclassified changed paths:", file=sys.stderr)
        for path in unclassified:
            print(f"  {path}", file=sys.stderr)
        return 1

    active = sorted(by_slice)
    if len(files) >= BROAD_DIFF_FILE_COUNT and len(active) < BROAD_DIFF_MIN_SLICES:
        print(
            f"broad diff has {len(files)} files but only {len(active)} review slices",
            file=sys.stderr,
        )
        return 1

    print(f"review slice check passed ({len(files)} files across {len(active)} slices)")
    for name in active:
        review_slice = next(item for item in SLICES if item.name == name)
        print(f"- {name}: {len(by_slice[name])} files - {review_slice.description}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
