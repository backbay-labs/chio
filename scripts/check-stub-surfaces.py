#!/usr/bin/env python3
"""Detect unresolved stub and placeholder surfaces in tracked and untracked text files."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import date
from pathlib import Path
import re
import subprocess
import sys


MATCH_RE = re.compile(
    r"(?i:bbs-stub|not_yet_implemented|advisory only|\btodo!\s*\(|"
    r"\bunimplemented!\s*\(|\bnot implemented\b|\btodo\b|\bfixme\b|\bhack\b|"
    r"\bstubs?\b|\bplaceholders?\b)|\bXXX\b"
)
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


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
    "crates/protocol/chio-acp-edge/src/bridge.rs": allow(
        "intentional advisory permission preview text, enforcement happens at invoke time",
        "2026-12-31",
    ),
    "crates/economy/chio-anchor/src/witness.rs": allow(
        "reviewed test fixture helper",
        "2026-12-31",
    ),
    "crates/economy/chio-anchor/src/witness/rekor.rs": allow(
        "reviewed test fixture helper",
        "2026-12-31",
    ),
    "crates/core/chio-arena/src/promote.rs": allow(
        "reviewed test seam for injecting CHIO_BLESS environment access",
        "2026-12-31",
    ),
    "crates/trust/chio-attest-verify/src/lib.rs": allow(
        "negative crate invariant text forbids live todo and unimplemented constructs",
        "2026-12-31",
    ),
    "crates/products/chio-cli/dashboard/src/components/BudgetSparkline.tsx": allow(
        "UI empty-state placeholder, not an implementation stub",
        "2026-12-31",
    ),
    "crates/products/chio-cli/dashboard/src/components/FilterSidebar.tsx": allow(
        "HTML input placeholder attributes, not implementation stubs",
        "2026-12-31",
    ),
    "crates/products/chio-cli/dashboard/src/components/ReceiptTable.tsx": allow(
        "UI Suspense loading placeholder, not an implementation stub",
        "2026-12-31",
    ),
    "crates/products/chio-cli/dashboard/src/index.css": allow(
        "CSS class for UI empty-state placeholder",
        "2026-12-31",
    ),
    "crates/products/chio-cli/src/cli/mcp/manifest.rs": allow(
        "generated guard-manifest scaffold intentionally carries review TODO text",
        "2026-12-31",
    ),
    "crates/products/chio-cli/src/cli/replay/validate.rs": allow(
        "reviewed replay validation fixture placeholder overwritten by signature tests",
        "2026-12-31",
    ),
    "crates/products/chio-cli/src/cli/session/test_support.rs": allow(
        "reviewed CLI session fixture payload",
        "2026-12-31",
    ),
    "crates/products/chio-cli/src/doctor/cosign.rs": allow(
        "reviewed doctor test fixture writes stub JSON under cfg(test)",
        "2026-12-31",
    ),
    "crates/products/chio-cli/src/guard/new.rs": allow(
        "deny-by-default guard scaffold template, not a shipped allow path",
        "2026-12-31",
    ),
    "crates/products/chio-cli/templates/init/README.md.tmpl": allow(
        "template README for generated example tool server",
        "2026-12-31",
    ),
    "crates/platform/chio-config/src/interpolation.rs": allow(
        "domain placeholder resolution term, not an unfinished implementation",
        "2026-12-31",
    ),
    "crates/tooling/chio-conformance/peers.lock.toml": allow(
        "pre-publication peer lock placeholders are guarded by published=false",
        "2026-12-31",
    ),
    "crates/tooling/chio-conformance/src/peers.rs": allow(
        "peer-lock placeholder pins fail closed unless published=false",
        "2026-12-31",
    ),
    "crates/tooling/chio-conformance/verdict_matrix/drivers/lambda/src/lib.rs": allow(
        "negative documentation says Lambda availability gate is not a placeholder",
        "2026-12-31",
    ),
    "crates/core/chio-core-types/src/crypto.rs": allow(
        "reviewed fail-closed comments around non-Ed25519 byte conversions",
        "2026-12-31",
    ),
    "crates/core/chio-core-types/src/plan.rs": allow(
        "planned dependency edges are recorded as audit metadata in v1",
        "2026-12-31",
    ),
    "crates/core/chio-core-types/src/receipt/kinds.rs": allow(
        "advisory trust level is an intentional receipt enum variant",
        "2026-12-31",
    ),
    "crates/trust/chio-custody-hw/src/lib.rs": allow(
        "negative crate-level invariant forbids trust-boundary stubs",
        "2026-12-31",
    ),
    "crates/trust/chio-custody-hw/src/verifier.rs": allow(
        "reviewed cfg(test) WebAuthn assertion fixture",
        "2026-12-31",
    ),
    "crates/trust/chio-custody-hw/src/attestation/google_root.rs": allow(
        "intentional placeholder-root security warnings; fail "
        "loudly until the real Google Play Integrity key is provisioned",
        "2026-12-31",
    ),
    "crates/trust/chio-custody-hw/src/attestation/play_integrity.rs": allow(
        "intentional placeholder-root security warnings; fail "
        "loudly until the real Google Play Integrity key is provisioned",
        "2026-12-31",
    ),
    "crates/protocol/chio-envoy-ext-authz/proto/envoy/config/core/v3/base.proto": allow(
        "protocol fixture text for opaque Envoy fields",
        "2026-12-31",
    ),
    "crates/protocol/chio-envoy-ext-authz/src/service.rs": allow(
        "reviewed adapter test seam documented in trait comment",
        "2026-12-31",
    ),
    "crates/platform/chio-http-core/src/routes.rs": allow(
        "route-template placeholder terminology",
        "2026-12-31",
    ),
    "crates/kernel/chio-kernel-browser/src/clock.rs": allow(
        "cfg(not wasm32) host-target test stub returns fail-closed time",
        "2026-12-31",
    ),
    "crates/kernel/chio-kernel-browser/src/rng.rs": allow(
        "cfg(not wasm32) host-target stub always fails outside browser wasm",
        "2026-12-31",
    ),
    "crates/observability/chio-lineage/src/anchor.rs": allow(
        "signing state explicitly distinguishes unsigned signer hint from real signature",
        "2026-12-31",
    ),
    "crates/observability/chio-log-redact/src/engine.rs": allow(
        "fail-closed redaction placeholder prevents original secret exposure",
        "2026-12-31",
    ),
    "crates/economy/chio-metering/src/export.rs": allow(
        "timestamp fallback text is reviewed and deterministic",
        "2026-12-31",
    ),
    "crates/trust/chio-pheromone-relay/src/metrics.rs": allow(
        "SQL bind placeholder terminology, not an unfinished stub surface",
        "2026-12-31",
    ),
    "crates/guards/chio-policy/src/detection.rs": allow(
        "policy detector name used as domain data and covered by tests",
        "2026-12-31",
    ),
    "crates/trust/chio-revocation-oracle/src/signer.rs": allow(
        "reviewed digest-only test signature marker",
        "2026-12-31",
    ),
    "crates/tooling/chio-spec-codegen/src/main.rs": allow(
        "reviewed threat-model test-stub generator command surface",
        "2026-12-31",
    ),
    "crates/tooling/chio-spec-codegen/src/threat_coverage_doc.rs": allow(
        "reviewed threat-model test-stub documentation generator",
        "2026-12-31",
    ),
    "crates/tooling/chio-spec-codegen/src/threat_model.rs": allow(
        "reviewed threat-model test-stub generator, expected to fail closed until populated",
        "2026-12-31",
    ),
    "crates/platform/chio-store-sqlite/src/receipt_store/evidence_retention.rs": allow(
        "SQL bind placeholder terminology, not an unfinished stub surface",
        "2026-12-31",
    ),
    "crates/trust/chio-tee/src/tap.rs": allow(
        "reviewed TrafficTap test-double implementations",
        "2026-12-31",
    ),
    "crates/guards/chio-wasm-guards/src/fuzz.rs": allow(
        "fuzz fixture text describing an allocator stub",
        "2026-12-31",
    ),
    "crates/guards/chio-wasm-guards/src/lib.rs": allow(
        "exports the placeholder-resolution API module",
        "2026-12-31",
    ),
    "crates/guards/chio-wasm-guards/src/placeholders.rs": allow(
        "domain placeholder-resolution API for guard configuration",
        "2026-12-31",
    ),
    "crates/guards/chio-wasm-guards/src/runtime/wasmtime_backend.rs": allow(
        "domain placeholder-resolution API use for guard configuration",
        "2026-12-31",
    ),
    "crates/trust/chio-weights/src/lib.rs": allow(
        "negative crate invariant text forbids verifier and trust-boundary stubs",
        "2026-12-31",
    ),
    "crates/trust/chio-weights/src/lineage.rs": allow(
        "PQ-hybrid signing-state placeholder mirrors explicit unsigned lineage state",
        "2026-12-31",
    ),
    "spec/schemas/chio-attest/v1/selective-disclosure-proof.schema.json": allow(
        "schema explicitly rejects proof schema identifiers ending in .stub",
        "2026-12-31",
    ),
    "supply-chain/config.toml": allow(
        "cargo-vet exemptions name the upstream bollard-stubs and proc-macro-hack crates",
        "2026-12-31",
    ),
    "crates/kernel/chio-kernel/src/kernel/construction.rs": allow(
        "comment documents the fail-closed default for stores without rotation support",
        "2026-12-31",
    ),
    "crates/kernel/chio-kernel/src/observability/metrics.rs": allow(
        "documented placeholder gauge; wiring tracked in the observability program",
        "2026-12-31",
    ),
    "crates/kernel/chio-kernel/src/receipt_store.rs": allow(
        "comment documents the fail-closed retention default",
        "2026-12-31",
    ),
    "crates/platform/chio-control-plane/src/trust_control/budget_handlers.rs": allow(
        "comment documents single-node quorum short-circuit semantics",
        "2026-12-31",
    ),
    "crates/platform/chio-control-plane/src/trust_control/cluster/deltas.rs": allow(
        "comment documents the unclustered token shape",
        "2026-12-31",
    ),
    "crates/products/chio-wall/src/commands.rs": allow(
        "test-module coverage of the stub exporter backend",
        "2026-12-31",
    ),
    "crates/tooling/chio-conformance/Cargo.toml": allow(
        "manifest comment explains a test-only dependency",
        "2026-12-31",
    ),
    "crates/trust/chio-federation-transport-iroh/src/identity.rs": allow(
        "tracked transport-key deferral for the pheromone relay",
        "2026-12-31",
    ),
    "crates/trust/chio-federation-transport-iroh/src/lanes/pheromone.rs": allow(
        "test comments contrast the canned-stub path with the QUIC-backed verifier",
        "2026-12-31",
    ),
    "sdks/python/chio-streaming/src/chio_streaming/core.py": allow(
        "docstring documents schema-valid fixture defaults",
        "2026-12-31",
    ),
}

ALLOWLIST_MATCHES: dict[str, tuple[str, ...]] = {
    "crates/protocol/chio-acp-edge/src/bridge.rs": (
        r"permission preview is advisory only; enforcement happens at invoke time",
    ),
    "crates/economy/chio-anchor/src/witness.rs": (
        r"rekor:placeholder",
    ),
    "crates/economy/chio-anchor/src/witness/rekor.rs": (
        r"rekor:placeholder",
    ),
    "crates/core/chio-arena/src/promote.rs": (
        r"CHIO_BLESS gate\. Tests inject a stub",
    ),
    "crates/trust/chio-attest-verify/src/lib.rs": (
        r"contains no `todo!`,",
    ),
    "crates/products/chio-cli/dashboard/src/components/BudgetSparkline.tsx": (
        r"No cost data.*placeholder",
        r"sparkline-placeholder",
    ),
    "crates/products/chio-cli/dashboard/src/components/FilterSidebar.tsx": (
        r'placeholder="(hex key|server name|tool name)\.\.\."',
    ),
    "crates/products/chio-cli/dashboard/src/components/ReceiptTable.tsx": (
        r"sparkline-placeholder",
    ),
    "crates/products/chio-cli/dashboard/src/index.css": (
        r"Budget sparkline placeholder",
        r"sparkline-placeholder",
    ),
    "crates/products/chio-cli/src/cli/mcp/manifest.rs": (
        r"TODO: review the inferred scopes below before promoting",
        r"TODO: review and promote",
    ),
    "crates/products/chio-cli/src/cli/replay/validate.rs": (
        r"Unsigned placeholder matching the schema regex",
        r"unsigned placeholder tenant_sig",
    ),
    "crates/products/chio-cli/src/cli/session/test_support.rs": (
        r'"stub": true',
    ),
    "crates/products/chio-cli/src/doctor/cosign.rs": (
        r'\\"stub\\": true',
    ),
    "crates/products/chio-cli/src/guard/new.rs": (
        r"Replace this stub with real policy logic before shipping",
        r'wasm_sha256: "TODO: run `chio guard build`',
    ),
    "crates/products/chio-cli/templates/init/README.md.tmpl": (
        r"hello_server\.rs.*tool server stub",
    ),
    "crates/platform/chio-config/src/interpolation.rs": (
        r"Leave a placeholder so the rest of parsing can proceed",
    ),
    "crates/tooling/chio-conformance/peers.lock.toml": (
        r"published = false.*placeholder",
        r"placeholder sha256",
    ),
    "crates/tooling/chio-conformance/src/peers.rs": (
        r"placeholder entries.*published = false",
        r"placeholder sha256 pins",
        r"placeholder pins; flip published=true",
    ),
    "crates/tooling/chio-conformance/verdict_matrix/drivers/lambda/src/lib.rs": (
        r"not a placeholder",
    ),
    "crates/core/chio-core-types/src/crypto.rs": (
        r"32-byte placeholder",
        r"all-zero placeholder",
    ),
    "crates/core/chio-core-types/src/plan.rs": (
        r"Advisory only in v1",
    ),
    "crates/core/chio-core-types/src/receipt/kinds.rs": (
        r"advisory only",
    ),
    "crates/trust/chio-custody-hw/src/lib.rs": (
        r"trust-boundary stubs",
    ),
    "crates/trust/chio-custody-hw/src/verifier.rs": (
        r"signature are placeholders",
    ),
    "crates/trust/chio-custody-hw/src/attestation/google_root.rs": (
        r"SECURITY / PLACEHOLDER",
        r"placeholder",
    ),
    "crates/trust/chio-custody-hw/src/attestation/play_integrity.rs": (
        r"SECURITY / PLACEHOLDER",
    ),
    "crates/protocol/chio-envoy-ext-authz/proto/envoy/config/core/v3/base.proto": (
        r"opaque placeholders",
    ),
    "crates/protocol/chio-envoy-ext-authz/src/service.rs": (
        r"tests can stub this trait",
    ),
    "crates/platform/chio-http-core/src/routes.rs": (
        r"`\{id\}` placeholder",
    ),
    "crates/kernel/chio-kernel-browser/src/clock.rs": (
        r"stub so `cargo test -p chio-kernel-browser`",
        r"stub intentionally returns `0`",
    ),
    "crates/kernel/chio-kernel-browser/src/rng.rs": (
        r"Host-target stub",
        r"Native stub that always fails",
    ),
    "crates/observability/chio-lineage/src/anchor.rs": (
        r"stub for a real PQ signature",
    ),
    "crates/observability/chio-log-redact/src/engine.rs": (
        r"fail-closed placeholder",
    ),
    "crates/economy/chio-metering/src/export.rs": (
        r"Falls back to a placeholder",
    ),
    "crates/trust/chio-pheromone-relay/src/metrics.rs": (
        r"placeholders = statuses",
        r"IN \(\{placeholders\}\)",
    ),
    "crates/guards/chio-policy/src/detection.rs": (
        r'"stub"',
        r"detector_name, \"stub\"",
    ),
    "crates/trust/chio-revocation-oracle/src/signer.rs": (
        r"digest-stub-sha256",
    ),
    "crates/tooling/chio-spec-codegen/src/main.rs": (
        r"chio-spec-codegen --threat-model <input\.json> --out <stubs-dir>",
        r"stub Rust test",
        r"threat-stub",
        r"--out <stubs-dir>",
        r"<stubs-dir>",
    ),
    "crates/tooling/chio-spec-codegen/src/threat_coverage_doc.rs": (
        r"threats stub directory",
        r"Test stub",
        r"not yet emitted",
    ),
    "crates/tooling/chio-spec-codegen/src/threat_model.rs": (
        r"threat-stub",
        r"stub source",
        r"Stub test",
        r"stub fails closed",
        r"`unimplemented!\(\)` so the threat-model-coverage CI gate",
        r"replace the `unimplemented!\(\)` call",
        r'unimplemented!\(\\"populate the test body',
        r"presence of `unimplemented!\(\)`",
        r'line\.contains\("unimplemented!\("\)',
        r"Replace the `unimplemented!\(\)` call when editing",
        r'unimplemented!\("fill me"\)',
        r"per-threat stub",
        r"codegen stubs",
        r"Generate one stub",
        r"top-level Rust into the stub",
        r"stub must still parse",
        r"sanitised stub must parse",
        r"let stub",
        r"contains_live_unimplemented_marker",
    ),
    "crates/platform/chio-store-sqlite/src/receipt_store/evidence_retention.rs": (
        r"bind placeholders",
    ),
    "crates/trust/chio-tee/src/tap.rs": (
        r"Stub `TrafficTap` implementation",
    ),
    "crates/guards/chio-wasm-guards/src/fuzz.rs": (
        r"chio_alloc` stub",
    ),
    "crates/guards/chio-wasm-guards/src/lib.rs": (
        r"placeholders",
    ),
    "crates/guards/chio-wasm-guards/src/placeholders.rs": (
        r"[Pp]laceholder",
        r"placeholders",
        r"\$\{VAR",
    ),
    "crates/guards/chio-wasm-guards/src/runtime/wasmtime_backend.rs": (
        r"[Pp]laceholder",
        r"placeholders",
        r"PlaceholderEnv",
        r"PlaceholderError",
        r"resolve_placeholders",
    ),
    "crates/trust/chio-weights/src/lib.rs": (
        r"trust-boundary stubs",
    ),
    "crates/trust/chio-weights/src/lineage.rs": (
        r"signing state placeholder",
    ),
    "spec/schemas/chio-attest/v1/selective-disclosure-proof.schema.json": (
        r'"schema": \{ "pattern": "\\\\.stub\$" \}',
    ),
    "supply-chain/config.toml": (
        r"\[\[exemptions\.bollard-stubs\]\]",
        r"\[\[exemptions\.proc-macro-hack\]\]",
    ),
    "crates/kernel/chio-kernel/src/kernel/construction.rs": (
        r"default unsupported stub",
    ),
    "crates/kernel/chio-kernel/src/observability/metrics.rs": (
        r"hardcoded zero placeholder",
    ),
    "crates/kernel/chio-kernel/src/receipt_store.rs": (
        r"fail-closed stub",
    ),
    "crates/platform/chio-control-plane/src/trust_control/budget_handlers.rs": (
        r"carries a placeholder token",
    ),
    "crates/platform/chio-control-plane/src/trust_control/cluster/deltas.rs": (
        r"placeholder \(unclustered\) token",
    ),
    "crates/products/chio-wall/src/commands.rs": (
        r"dispatches to the stub backend",
        r"stub dispatch succeeds",
    ),
    "crates/tooling/chio-conformance/Cargo.toml": (
        r"supplies the `SignedEpochRoot` type the stub",
    ),
    "crates/trust/chio-federation-transport-iroh/src/identity.rs": (
        r"TODO\(iroh-transport\): when `chio-pheromone-relay` grows a transport-key",
    ),
    "crates/trust/chio-federation-transport-iroh/src/lanes/pheromone.rs": (
        r"\(like a stub\) it never runs the verifier",
        r"the canned stub skips",
    ),
    "sdks/python/chio-streaming/src/chio_streaming/core.py": (
        r"schema-valid placeholders",
    ),
}

DENYLIST: dict[str, DenylistEntry] = {}


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


def scan_files(root: Path) -> list[str]:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return [
        line
        for line in result.stdout.splitlines()
        if line
        and not line.startswith(
            (
                ".git/",
                ".codex/",
                ".agents/",
                ".chio-peers/",
                "target/",
            )
        )
    ]


def classify(path: str) -> str:
    name = Path(path).name
    suffix = Path(path).suffix
    if "/_generated/" in f"/{path}/" or name in {
        "package-lock.json",
        "Cargo.lock",
    }:
        return "generated"
    if path.startswith(".github/ISSUE_TEMPLATE/") or path.startswith(
        ("audits/", "integrations/editors/", "formal/")
    ):
        return "docs"
    if path.startswith("deploy/"):
        return "deployment-templates"
    if path.startswith(".github/workflows/"):
        return "scripts"
    if path.startswith("docs/") or suffix in {".md", ".adoc"}:
        return "docs"
    if path.startswith("scripts/") or "/scripts/" in f"/{path}/":
        return "scripts"
    if path.startswith("examples/") or "/examples/" in f"/{path}/":
        return "examples"
    if (
        path.startswith("tests/")
        or "/src/test/" in f"/{path}/"
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


def validate_review_date(path: str, field: str, value: str) -> str | None:
    if not value.strip():
        return f"{path}: {field} is empty"
    if not DATE_RE.fullmatch(value):
        return f"{path}: {field} must be an ISO date (YYYY-MM-DD), got {value!r}"
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        return f"{path}: {field} is not a valid calendar date: {value!r}"
    if parsed < date.today():
        return f"{path}: {field} date has expired: {value}"
    return None


def validate_lists(errors: list[str]) -> None:
    for path, entry in sorted(ALLOWLIST.items()):
        if not entry.reason.strip():
            errors.append(f"{path}: allowlist entry has an empty reason")
        date_error = validate_review_date(path, "allowlist expiry", entry.expires)
        if date_error:
            errors.append(date_error)
        patterns = ALLOWLIST_MATCHES.get(path)
        if not patterns:
            errors.append(f"{path}: allowlist entry has no reviewed match patterns")
            continue
        for pattern in patterns:
            if not pattern.strip():
                errors.append(f"{path}: allowlist entry has an empty match pattern")
                continue
            try:
                re.compile(pattern)
            except re.error as err:
                errors.append(f"{path}: invalid allowlist pattern {pattern!r}: {err}")
    for path in sorted(set(ALLOWLIST_MATCHES) - set(ALLOWLIST)):
        errors.append(f"{path}: allowlist match patterns exist without allowlist entry")
    for path, entry in sorted(DENYLIST.items()):
        if not entry.reason.strip():
            errors.append(f"{path}: denylist entry has an empty reason")
        date_error = validate_review_date(path, "denylist until", entry.until)
        if date_error:
            errors.append(date_error)


def validate_allowlist_coverage(root: Path, paths: list[str], hits: list[Hit], errors: list[str]) -> None:
    if root != repo_root().resolve():
        return

    scanned = set(paths)
    hits_by_path: dict[str, list[str]] = {}
    for hit in hits:
        hits_by_path.setdefault(hit.path, []).append(hit.text)

    for path, patterns in sorted(ALLOWLIST_MATCHES.items()):
        if path not in scanned:
            errors.append(f"{path}: allowlist entry points at a file outside the scanner set")
            continue
        texts = hits_by_path.get(path, [])
        if not texts:
            errors.append(f"{path}: allowlist entry is stale; no current scanner hits")
            continue
        for pattern in patterns:
            try:
                compiled_pattern = re.compile(pattern)
            except re.error:
                continue
            if not any(compiled_pattern.search(text) for text in texts):
                errors.append(
                    f"{path}: allowlist pattern is stale; no current hit matches {pattern!r}"
                )


def matches_allowlist(hit: Hit) -> bool:
    if hit.allowlist is None:
        return False
    patterns = ALLOWLIST_MATCHES.get(hit.path, ())
    return any(re.search(pattern, hit.text) for pattern in patterns)


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
        elif matches_allowlist(hit):
            marker = f" allowlisted until {hit.allowlist.expires}"
        print(f"{hit.path}:{hit.line}:{marker} {hit.text}")
    if len(production_hits) > 120:
        print(f"... {len(production_hits) - 120} more production hit(s)")


def main() -> int:
    parser = argparse.ArgumentParser(description="Check tracked and untracked stub surfaces.")
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
        paths = scan_files(root)
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip()
        print(f"failed to list git files under {root}: {stderr}", file=sys.stderr)
        return 1

    hits = collect_hits(root, paths)
    validate_allowlist_coverage(root, paths, hits, errors)
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
        if matches_allowlist(hit):
            continue
        if hit.allowlist:
            failures.append(
                f"{hit.path}:{hit.line}: production stub-surface hit does not "
                f"match reviewed allowlist patterns: {hit.text}"
            )
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
