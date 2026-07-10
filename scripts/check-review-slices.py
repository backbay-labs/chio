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
            "CONTRIBUTING.md",
            "AGENTS.md",
            "CLAUDE.md",
            "docs/**",
            "spec/**",
        ),
    ),
    ReviewSlice(
        "core-protocol",
        "core protocol types, canonical bytes, HTTP/session contracts, manifests",
        (
            "crates/core/chio-core-types/**",
            "crates/core/chio-core/**",
            "crates/platform/chio-http-core/**",
            "crates/platform/chio-http-session/**",
            "crates/platform/chio-manifest/**",
            "crates/platform/chio-config/**",
            "crates/protocol/chio-egress-contract/**",
            "crates/core/chio-errors/**",
            "crates/sdk/chio-binding-helpers/**",
            "crates/platform/chio-workflow/**",
        ),
    ),
    ReviewSlice(
        "kernel-runtime",
        "kernel, runtime, portable/browser/mobile kernels, runtime harnesses",
        (
            "crates/kernel/chio-kernel/**",
            "crates/kernel/chio-kernel-core/**",
            "crates/kernel/chio-kernel-browser/**",
            "crates/kernel/chio-kernel-mobile/**",
            "crates/kernel/chio-runtime/**",
            "crates/kernel/chio-runtime-core/**",
            "crates/kernel/chio-runtime-harness/**",
            "crates/kernel/chio-runtime-proof-parity/**",
            "crates/kernel/chio-swarm-authority/**",
            "crates/protocol/chio-tool-call-fabric/**",
            "crates/protocol/chio-tower/**",
        ),
    ),
    ReviewSlice(
        "guards-policy",
        "guards, policy evaluation, guard SDKs, and guard registries",
        (
            "crates/guards/chio-guards/**",
            "crates/guards/chio-data-guards/**",
            "crates/guards/chio-external-guards/**",
            "crates/guards/chio-wasm-guards/**",
            "crates/guards/chio-policy/**",
            "crates/sdk/chio-guard-sdk/**",
            "crates/sdk/chio-guard-sdk-macros/**",
            "crates/guards/chio-guard-registry/**",
            "sdks/guard/**",
            "wit/**",
        ),
    ),
    ReviewSlice(
        "adapters-edges",
        "protocol adapters, provider adapters, edges, bridges, integrations",
        (
            "crates/protocol/chio-*-adapter/**",
            "crates/protocol/chio-*-edge/**",
            "crates/protocol/chio-*-proxy/**",
            "crates/protocol/chio-openapi/**",
            "crates/protocol/chio-openapi-mcp-bridge/**",
            "crates/protocol/chio-cross-protocol/**",
            "crates/protocol/chio-ag-ui-proxy/**",
            "crates/protocol/chio-edge-metrics/**",
            "crates/protocol/chio-envoy-ext-authz/**",
            "crates/protocol/chio-hosted-mcp/**",
            "crates/protocol/chio-mcp-remote/**",
            "crates/observability/chio-otel-receipt-exporter/**",
            "crates/protocol/chio-openai-adapter/**",
            "crates/protocol/chio-provider-adapter-core/**",
            "integrations/**",
        ),
    ),
    ReviewSlice(
        "storage-control-observability",
        "control plane, stores, metering, SIEM, operational state",
        (
            "crates/platform/chio-agent-web-interop/**",
            "crates/platform/chio-commerce-order/**",
            "crates/platform/chio-control-plane/**",
            "crates/platform/chio-enterprise-export/**",
            "crates/platform/chio-risk-comptroller/**",
            "crates/platform/chio-store-sqlite/**",
            "crates/platform/chio-transaction-passport/**",
            "crates/platform/chio-trust-market-context/**",
            "crates/platform/chio-workflow-preflight/**",
            "crates/observability/chio-log-redact/**",
            "crates/economy/chio-metering/**",
            "crates/observability/chio-metrics-spec/**",
            "crates/observability/chio-siem/**",
            "crates/trust/chio-revocation-oracle/**",
            "crates/trust/chio-pheromone/**",
            "crates/trust/chio-pheromone-relay/**",
            "crates/trust/chio-pheromone-runtime/**",
        ),
    ),
    ReviewSlice(
        "economics-identity-web3",
        "credit, markets, settlement, identity, federation, governance, Web3",
        (
            "crates/economy/chio-appraisal/**",
            "crates/economy/chio-autonomy/**",
            "crates/economy/chio-credit/**",
            "crates/economy/chio-market/**",
            "crates/economy/chio-open-market/**",
            "crates/economy/chio-settle/**",
            "crates/economy/chio-anchor/**",
            "crates/economy/chio-underwriting/**",
            "crates/economy/chio-link/**",
            "crates/observability/chio-lineage/**",
            "crates/economy/chio-listing/**",
            "crates/trust/chio-weights/**",
            "crates/trust/chio-custody-hw/**",
            "crates/trust/chio-did/**",
            "crates/trust/chio-credentials/**",
            "crates/trust/chio-federation/**",
            "crates/trust/chio-federation-authority/**",
            "crates/trust/chio-governance/**",
            "crates/trust/chio-reputation/**",
            "crates/economy/chio-web3/**",
            "crates/economy/chio-web3-bindings/**",
            "contracts/**",
        ),
    ),
    ReviewSlice(
        "attestation-conformance-formal",
        "attestation, conformance, replay, formal, adversarial, test corpora",
        (
            "crates/trust/chio-attest-*/**",
            "crates/core/chio-arena/**",
            "crates/tooling/chio-conformance/**",
            "crates/sdk/chio-eval-receipt/**",
            "crates/protocol/chio-provider-conformance/**",
            "crates/core/chio-adversarial-suite/**",
            "crates/trust/chio-replay-corpus/**",
            "crates/trust/chio-replay-gate/**",
            "crates/trust/chio-selective-disclosure/**",
            "crates/trust/chio-disclosure-lineage/**",
            "crates/tooling/chio-spec-codegen/**",
            "crates/tooling/chio-spec-validate/**",
            "crates/trust/chio-tee/**",
            "crates/trust/chio-tee-frame/**",
            "crates/tooling/chio-test-support/**",
            "arena/**",
            "formal/**",
            "fuzz/**",
            "fixtures/proof-room/**",
            "tests/**",
        ),
    ),
    ReviewSlice(
        "sdks-examples",
        "language SDKs and runnable examples",
        (
            "crates/sdk/chio-bindings-ffi/**",
            "crates/sdk/chio-cpp-kernel-ffi/**",
            "sdks/**",
            "examples/**",
        ),
    ),
    ReviewSlice(
        "products-editors-bench",
        "CLI/products, editors, benchmark and demo surfaces",
        (
            "crates/products/chio-cli/**",
            "crates/products/chio-proof-room/**",
            "crates/products/proof_fixture_build.rs",
            "crates/products/chio-api-protect/**",
            "crates/tooling/chio-lsp/**",
            "crates/products/chio-mercury/**",
            "crates/products/chio-mercury-core/**",
            "crates/products/chio-wall/**",
            "crates/products/chio-wall-core/**",
            "bench/**",
        ),
    ),
    ReviewSlice(
        "release-ops-evidence",
        "release manifests, audit evidence, and operational knowledge-base files",
        (
            "audits/**",
            "compliance/**",
            "supply-chain/**",
            "tools/knowledge-base/**",
            "CHANGELOG.md",
            "releases.toml",
            "deploy/**",
            "packaging/**",
        ),
    ),
    ReviewSlice(
        "ci-tooling-workspace",
        "CI workflows, scripts, workspace metadata, xtask and scanner config",
        (
            ".github/**",
            ".tooling/**",
            "scripts/**",
            "ci-gates/**",
            "tools/**",
            "xtask/**",
            ".cargo/**",
            ".kani/**",
            ".clusterfuzzlite/**",
            "Cargo.toml",
            "Cargo.lock",
            "package.json",
            "bun.lock",
            "deny.toml",
            "osv-scanner.toml",
            "Makefile",
            "rust-toolchain.toml",
            ".gitignore",
            ".gitattributes",
            ".dockerignore",
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
