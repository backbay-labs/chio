#!/usr/bin/env python3
"""Generate and validate the programmable-sovereignty paper artifact."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[1]
PAPER = REPO / "docs/papers/programmable-sovereignty"
SUPPLEMENTARY = PAPER / "supplementary"
SOURCE_COMMIT_FILE = SUPPLEMENTARY / "source-commit.txt"
TITLE = "Proof-Carrying Bilateral Admission for Cross-Organization Agent Tool Calls"
GENERATED_AT = "2026-07-25"
TARGET = "USENIX Security 2027 Cycle 1"

THEOREMS = [
    {
        "id": "PS-F01",
        "name": "treaty_admission_iff_predicate_intersection",
        "module": "Chio.Treaty.IntersectionSyntactic",
        "declaration": (
            "Chio.Treaty.IntersectionSyntactic."
            "treaty_admission_iff_predicate_intersection"
        ),
        "path": (
            "formal/lean4/Chio/Chio/Treaty/"
            "IntersectionSyntactic.lean"
        ),
        "axioms": ["propext"],
        "claimClass": "bounded_theorem",
        "scope": "Structural six-conjunct treaty intersection over ReceiptView.",
    },
    {
        "id": "PS-F02",
        "name": "treaty_admission_stable_under_ladder_floor",
        "module": "Chio.Treaty.IntersectionSyntactic",
        "declaration": (
            "Chio.Treaty.IntersectionSyntactic."
            "treaty_admission_stable_under_ladder_floor"
        ),
        "path": (
            "formal/lean4/Chio/Chio/Treaty/"
            "IntersectionSyntactic.lean"
        ),
        "axioms": ["propext"],
        "claimClass": "bounded_theorem",
        "scope": "Satisfied finite ladder floor reduces to treaty admission.",
    },
    {
        "id": "PS-F03",
        "name": "refinesOnConstitution_iff",
        "module": "Chio.Treaty.PredicateLang",
        "declaration": (
            "Chio.Treaty.PredicateLang.refinesOnConstitution_iff"
        ),
        "path": "formal/lean4/Chio/Chio/Treaty/PredicateLang.lean",
        "axioms": ["propext", "Quot.sound"],
        "claimClass": "bounded_theorem",
        "scope": "Boolean no-widening is exact on the declared finite domain.",
    },
    {
        "id": "PS-F04",
        "name": "bridge_decidable_soundness",
        "module": "Chio.Treaty.PredicateLang",
        "declaration": (
            "Chio.Treaty.PredicateLang.bridge_decidable_soundness"
        ),
        "path": "formal/lean4/Chio/Chio/Treaty/PredicateLang.lean",
        "axioms": ["propext", "Quot.sound"],
        "claimClass": "bounded_theorem",
        "scope": "A positive finite check implies semantic no-widening on-domain.",
    },
    {
        "id": "PS-F05",
        "name": "treaty_admission_agrees",
        "module": "Chio.Treaty.BridgeEquivalence",
        "declaration": (
            "Chio.Treaty.BridgeEquivalence.Legacy."
            "treaty_admission_agrees"
        ),
        "path": "formal/lean4/Chio/Chio/Treaty/BridgeEquivalence.lean",
        "axioms": ["propext"],
        "claimClass": "bounded_theorem",
        "scope": "Syntactic and legacy treaty admission agree pointwise.",
    },
    {
        "id": "PS-F06",
        "name": "bounded_amendment_sound",
        "module": "Chio.Treaty.BridgeEquivalence",
        "declaration": (
            "Chio.Treaty.BridgeEquivalence.Legacy."
            "bounded_amendment_sound"
        ),
        "path": "formal/lean4/Chio/Chio/Treaty/BridgeEquivalence.lean",
        "axioms": ["propext", "Quot.sound"],
        "claimClass": "bounded_theorem",
        "scope": "A ConstitutionalDelta is sound only on its carried domain.",
    },
]

PRODUCTION_SYMBOLS = [
    {
        "id": "PS-I01",
        "name": "ChioRuntimeAdmissionHook",
        "path": "crates/kernel/chio-runtime-core/src/admission_hook.rs",
        "pattern": "pub struct ChioRuntimeAdmissionHook",
        "claimClass": "production_enforced",
    },
    {
        "id": "PS-I02",
        "name": "RuntimeAdmissionHook::evaluate",
        "path": "crates/kernel/chio-runtime-core/src/admission_hook.rs",
        "pattern": "fn evaluate(",
        "claimClass": "production_enforced",
    },
    {
        "id": "PS-I03",
        "name": "verify_chio_bilateral_invocation",
        "path": (
            "crates/trust/chio-federation/src/"
            "bilateral_verifier/cosign.rs"
        ),
        "pattern": "pub fn verify_chio_bilateral_invocation(",
        "claimClass": "production_enforced",
    },
    {
        "id": "PS-I04",
        "name": "CrossKernelContinuation",
        "path": "crates/kernel/chio-runtime-core/src/types.rs",
        "pattern": "pub struct CrossKernelContinuation",
        "claimClass": "production_enforced",
    },
    {
        "id": "PS-I05",
        "name": "bounded_treaty_receipt_view_from_verified_artifacts",
        "path": "crates/kernel/chio-runtime-core/src/treaty/predicate.rs",
        "pattern": (
            "pub fn bounded_treaty_receipt_view_from_verified_artifacts("
        ),
        "claimClass": "differentially_aligned",
    },
    {
        "id": "PS-I06",
        "name": "run_runtime_loopback_scenario",
        "path": "crates/kernel/chio-runtime-harness/src/lib.rs",
        "pattern": "pub fn run_runtime_loopback_scenario(",
        "claimClass": "executable_demonstration",
    },
    {
        "id": "PS-I07",
        "name": "verify_package",
        "path": "crates/trust/chio-attest-buyer-core/src/report.rs",
        "pattern": "pub fn verify_package(",
        "claimClass": "production_enforced",
    },
    {
        "id": "PS-I08",
        "name": "BilateralCoSigningError::code",
        "path": "crates/trust/chio-federation/src/bilateral.rs",
        "pattern": "pub fn code(&self)",
        "claimClass": "production_enforced",
    },
]

BEHAVIORAL_TESTS = [
    {
        "id": "PS-T01",
        "command": "cargo test -p chio-formal-diff-tests",
        "claimClass": "differentially_aligned",
    },
    {
        "id": "PS-T02",
        "command": "cargo test -p chio-runtime-core --test runtime_treaty",
        "claimClass": "production_enforced",
    },
    {
        "id": "PS-T03",
        "command": "cargo test -p chio-runtime-core --test runtime_admission",
        "claimClass": "production_enforced",
    },
    {
        "id": "PS-T04",
        "command": "cargo test -p chio-runtime-core --test runtime_buyer_review",
        "claimClass": "production_enforced",
    },
    {
        "id": "PS-T05",
        "command": "cargo test -p chio-runtime-harness",
        "claimClass": "executable_demonstration",
    },
    {
        "id": "PS-T06",
        "command": "cargo test -p chio-federation --lib",
        "claimClass": "production_enforced",
    },
    {
        "id": "PS-T07",
        "command": (
            "bash scripts/check-chio-live-treaty-buyer-closure.sh"
        ),
        "claimClass": "executable_demonstration",
    },
]

BENCHMARKS = [
    {
        "id": "PS-B01",
        "script": (
            "docs/papers/programmable-sovereignty/"
            "bench/run-bilateral-admission.sh"
        ),
        "results": [
            "docs/papers/programmable-sovereignty/bench/results/"
            "bilateral-admission-raw.csv",
            "docs/papers/programmable-sovereignty/bench/results/"
            "bilateral-admission-components.csv",
            "docs/papers/programmable-sovereignty/bench/results/"
            "bilateral-admission.json",
            "docs/papers/programmable-sovereignty/bench/results/"
            "bilateral-admission-inline.tex",
            "docs/papers/programmable-sovereignty/bench/results/"
            "bilateral-admission-environment.txt",
        ],
        "summary": (
            "docs/papers/programmable-sovereignty/bench/results/"
            "bilateral-admission.json"
        ),
    },
    {
        "id": "PS-B02",
        "script": (
            "docs/papers/programmable-sovereignty/"
            "bench/run-replay-corpus.sh"
        ),
        "results": [
            "docs/papers/programmable-sovereignty/bench/results/"
            "replay-corpus.csv",
            "docs/papers/programmable-sovereignty/bench/results/"
            "replay-corpus.json",
            "docs/papers/programmable-sovereignty/bench/results/"
            "replay-corpus-inline.tex",
        ],
        "summary": (
            "docs/papers/programmable-sovereignty/bench/results/"
            "replay-corpus.json"
        ),
    },
]

BENCHMARK_INPUT_ROOTS = [
    ".cargo",
    "Cargo.lock",
    "Cargo.toml",
    "crates",
    "examples",
    "formal",
    "rust-toolchain.toml",
    "scripts",
    "sdks",
    "spec",
]

CORPORA = {
    "positive": [
        "examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json",
        (
            "examples/chio-3vendor/fixtures/runtime-spine/"
            "runtime-evidence-manifest.json"
        ),
    ],
    "negative": [
        "examples/chio-3vendor/fixtures/treaty-runtime-negative-corpus.json"
    ],
}

SOURCE_FILES = [
    "Cargo.lock",
    "rust-toolchain.toml",
    "docs/papers/programmable-sovereignty/CLAIM_LEDGER.md",
    "docs/papers/programmable-sovereignty/README.md",
    "docs/papers/programmable-sovereignty/paper-usenix.tex",
    "docs/papers/programmable-sovereignty/paper-usenix.pdf",
    "docs/papers/programmable-sovereignty/paper.tex",
    *[
        f"docs/papers/programmable-sovereignty/sections/{index:02d}-{name}.tex"
        for index, name in [
            (1, "introduction"),
            (2, "background"),
            (3, "substrate"),
            (4, "model"),
            (5, "implementation"),
            (6, "evaluation"),
            (7, "discussion"),
            (8, "related-work"),
            (9, "limitations"),
            (10, "conclusion"),
        ]
    ],
    "docs/papers/programmable-sovereignty/figures/admission-hook.tex",
    "docs/papers/programmable-sovereignty/figures/treaty-handshake.tex",
    "formal/lean4/Chio/Chio.lean",
    "formal/lean4/Chio/Chio/Treaty/PredicateLang.lean",
    "formal/lean4/Chio/Chio/Treaty/IntersectionSyntactic.lean",
    "formal/lean4/Chio/Chio/Treaty/BridgeEquivalence.lean",
    "formal/diff-tests/src/spec.rs",
    "formal/diff-tests/src/generators.rs",
    "formal/diff-tests/Cargo.toml",
    "formal/diff-tests/tests/treaty_predicate_diff.rs",
    "crates/kernel/chio-runtime-core/src/admission_hook.rs",
    "crates/kernel/chio-runtime-core/src/treaty.rs",
    "crates/kernel/chio-runtime-core/src/treaty/predicate.rs",
    "crates/kernel/chio-runtime-core/src/types.rs",
    "crates/trust/chio-federation/src/bilateral.rs",
    "crates/trust/chio-federation/src/bilateral_verifier/cosign.rs",
    "crates/trust/chio-attest-buyer-core/src/report.rs",
    "crates/kernel/chio-runtime-harness/src/lib.rs",
    "scripts/check-chio-live-treaty-buyer-closure.sh",
    "scripts/check-chio-treaty-buyer-hero-loop.sh",
    "scripts/check-programmable-sovereignty-artifact.sh",
    "scripts/generate-programmable-sovereignty-artifact.py",
    (
        "docs/papers/programmable-sovereignty/"
        "supplementary/README.md"
    ),
    "spec/schemas/chio-federation/v1/"
    "treaty-runtime-negative-fixture-corpus.schema.json",
]

EXCLUDED = [
    {
        "surface": "public anchor inclusion",
        "status": "withheld",
        "reason": "No live transparency-service measurement supports the core claim.",
    },
    {
        "surface": "production constitutional amendment",
        "status": "model_only",
        "reason": "Rust does not enact ConstitutionalDelta witnesses.",
    },
    {
        "surface": "Lean verification of production Rust",
        "status": "not_claimed",
        "reason": "The evidence is generated differential alignment, not refinement.",
    },
    {
        "surface": "organizational independence of signers",
        "status": "operational_assumption",
        "reason": "Two distinct keys may be controlled by one actor.",
    },
    {
        "surface": "wide-area performance and failure recovery",
        "status": "not_evaluated",
        "reason": "The evaluated path is a deterministic single-host loopback.",
    },
    {
        "surface": "legal or territorial sovereignty",
        "status": "not_claimed",
        "reason": "Authority is local to the receiver's receipt-admission boundary.",
    },
]


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"artifact generation failed: {message}")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_bytes(relative: str) -> bytes:
    path = REPO / relative
    if not path.is_file():
        fail(f"required file missing: {relative}")
    return path.read_bytes()


def hash_entry(relative: str) -> dict[str, str]:
    return {"path": relative, "sha256": sha256_bytes(file_bytes(relative))}


def git_output(*args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(REPO), *args],
        check=True,
        text=True,
        capture_output=True,
    )
    return result.stdout.strip()


def git_commit_available(commit: str) -> bool:
    return subprocess.run(
        [
            "git",
            "-C",
            str(REPO),
            "cat-file",
            "-e",
            f"{commit}^{{commit}}",
        ],
        check=False,
        capture_output=True,
    ).returncode == 0


def benchmark_input_tree_sha256(benchmark_id: str, commit: str) -> str:
    benchmark = next(
        (item for item in BENCHMARKS if item["id"] == benchmark_id),
        None,
    )
    if benchmark is None:
        fail(f"unknown benchmark ID: {benchmark_id}")
    try:
        tree = subprocess.run(
            [
                "git",
                "-C",
                str(REPO),
                "ls-tree",
                "-r",
                "--full-tree",
                commit,
                "--",
                *BENCHMARK_INPUT_ROOTS,
                benchmark["script"],
            ],
            check=True,
            capture_output=True,
        ).stdout
    except subprocess.CalledProcessError:
        fail(f"benchmark input commit is unavailable: {commit}")
    if not tree:
        fail(f"benchmark input tree is empty for {benchmark_id}")
    return sha256_bytes(tree)


def validate_benchmark_result_provenance(
    benchmark: dict[str, Any],
    result: dict[str, Any],
    source_commit: str,
    *,
    require_local_source_object: bool,
) -> None:
    if result.get("worktreeDirty") is not False:
        fail(f"{benchmark['id']} result was not produced from a clean worktree")
    producer_commit = result.get("commit")
    if (
        not isinstance(producer_commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", producer_commit) is None
    ):
        fail(f"{benchmark['id']} result commit is not a full SHA")
    recorded_digest = result.get("benchmarkInputTreeSha256")
    if (
        not isinstance(recorded_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", recorded_digest) is None
    ):
        fail(f"{benchmark['id']} result lacks a benchmark input tree digest")

    producer_available = git_commit_available(producer_commit)
    source_available = git_commit_available(source_commit)
    if require_local_source_object and (
        not producer_available or not source_available
    ):
        fail(f"{benchmark['id']} provenance commit is unavailable")

    if producer_available:
        producer_digest = benchmark_input_tree_sha256(
            benchmark["id"],
            producer_commit,
        )
        if producer_digest != recorded_digest:
            fail(f"{benchmark['id']} result input digest does not match its producer")
    if producer_available and source_available:
        if subprocess.run(
            [
                "git",
                "-C",
                str(REPO),
                "merge-base",
                "--is-ancestor",
                producer_commit,
                source_commit,
            ],
            check=False,
        ).returncode != 0:
            fail(f"{benchmark['id']} producer is not an ancestor of pinned source")

    comparison_commit = source_commit if source_available else "HEAD"
    source_digest = benchmark_input_tree_sha256(
        benchmark["id"],
        comparison_commit,
    )
    if source_digest != recorded_digest:
        fail(f"{benchmark['id']} result inputs differ from pinned source")


def resolve_source_commit(
    explicit: str | None,
    *,
    require_local_object: bool,
) -> str:
    candidate = explicit
    if candidate is None and SOURCE_COMMIT_FILE.is_file():
        candidate = SOURCE_COMMIT_FILE.read_text().strip()
    if candidate is None:
        candidate = git_output("rev-parse", "HEAD")
    if re.fullmatch(r"[0-9a-f]{40}", candidate) is None:
        fail("source commit is not a full SHA")
    try:
        return git_output("rev-parse", f"{candidate}^{{commit}}")
    except subprocess.CalledProcessError:
        if require_local_object:
            fail("source commit is not available in local repository history")
        return candidate


def snapshot_paths() -> list[str]:
    paths = [
        *SOURCE_FILES,
        *[benchmark["script"] for benchmark in BENCHMARKS],
        *[
            result
            for benchmark in BENCHMARKS
            for result in benchmark["results"]
        ],
        *[
            path
            for corpus_paths in CORPORA.values()
            for path in corpus_paths
        ],
        (
            "docs/papers/programmable-sovereignty/"
            "supplementary/proof-manifest.toml"
        ),
        (
            "docs/papers/programmable-sovereignty/"
            "supplementary/theorem-inventory.json"
        ),
        (
            "docs/papers/programmable-sovereignty/"
            "supplementary/lean-source.tar.gz"
        ),
    ]
    return sorted(set(paths))


def validate_pinned_snapshot(
    source_commit: str,
    *,
    require_local_object: bool,
) -> None:
    commit_available = subprocess.run(
        [
            "git",
            "-C",
            str(REPO),
            "cat-file",
            "-e",
            f"{source_commit}^{{commit}}",
        ],
        check=False,
        capture_output=True,
    ).returncode == 0
    if not commit_available:
        if require_local_object:
            fail("source commit is not available in local repository history")
        return

    for relative in snapshot_paths():
        try:
            committed = subprocess.run(
                [
                    "git",
                    "-C",
                    str(REPO),
                    "show",
                    f"{source_commit}:{relative}",
                ],
                check=True,
                capture_output=True,
            ).stdout
        except subprocess.CalledProcessError:
            fail(f"pinned commit does not contain required file: {relative}")
        if committed != file_bytes(relative):
            fail(
                "working artifact differs from pinned commit at "
                f"{relative}"
            )


def validate_inputs(
    source_commit: str,
    *,
    require_local_source_object: bool,
) -> None:
    for theorem in THEOREMS:
        text = file_bytes(theorem["path"]).decode("utf-8")
        if re.search(
            rf"\btheorem\s+{re.escape(theorem['name'])}\b",
            text,
        ) is None:
            fail(
                f"theorem {theorem['declaration']} missing from "
                f"{theorem['path']}"
            )
    for symbol in PRODUCTION_SYMBOLS:
        text = file_bytes(symbol["path"]).decode("utf-8")
        if symbol["pattern"] not in text:
            fail(
                f"symbol {symbol['name']} missing from {symbol['path']}"
            )
    for benchmark in BENCHMARKS:
        file_bytes(benchmark["script"])
        for result in benchmark["results"]:
            file_bytes(result)
        summary = json.loads(file_bytes(benchmark["summary"]))
        validate_benchmark_result_provenance(
            benchmark,
            summary,
            source_commit,
            require_local_source_object=require_local_source_object,
        )
    for paths in CORPORA.values():
        for path in paths:
            file_bytes(path)
    negative = json.loads(file_bytes(CORPORA["negative"][0]))
    if len(negative.get("cases", [])) != 20:
        fail("bilateral negative corpus must contain exactly 20 cases")
    threat_ids = [case.get("threatId") for case in negative["cases"]]
    if len(set(threat_ids)) != 20:
        fail("bilateral negative corpus contains duplicate threat IDs")
    if any(case.get("dispatchExpected") is not False for case in negative["cases"]):
        fail("every negative corpus case must set dispatchExpected to false")
    assumptions = negative.get("assumptions", [])
    if [item.get("assumptionId") for item in assumptions] != ["PS-A-01"]:
        fail("negative corpus must carry the PS-A-01 assumption")
    results = json.loads(
        file_bytes(
            "docs/papers/programmable-sovereignty/bench/results/"
            "bilateral-admission.json"
        )
    )
    if results.get("profile") != "release":
        fail("bilateral admission results are not release-profile")
    if results.get("negativeMatrix", {}).get("cases") != 20:
        fail("benchmark summary does not report 20 negative cases")
    validate_pinned_snapshot(
        source_commit,
        require_local_object=require_local_source_object,
    )


def proof_manifest_bytes() -> bytes:
    lines = [
        "[manifest]",
        'schema = "chio.programmable-sovereignty.proof-manifest.v1"',
        f'generated_at = "{GENERATED_AT}"',
        f"paper = {json.dumps(TITLE)}",
        f"target_venue = {json.dumps(TARGET)}",
        'lean_toolchain = "leanprover/lean4:v4.28.0-rc1"',
        'model_boundary = "bounded ReceiptView and explicit finite domains"',
        'implementation_relation = "differential alignment, not extraction or refinement"',
        "",
    ]
    for theorem in THEOREMS:
        lines.extend(
            [
                "[[theorems]]",
                f"id = {json.dumps(theorem['id'])}",
                f"name = {json.dumps(theorem['name'])}",
                f"lean_module = {json.dumps(theorem['module'])}",
                f"lean_declaration = {json.dumps(theorem['declaration'])}",
                f"path = {json.dumps(theorem['path'])}",
                f"claim_class = {json.dumps(theorem['claimClass'])}",
                f"axioms = {json.dumps(theorem['axioms'])}",
                f"scope = {json.dumps(theorem['scope'])}",
                "",
            ]
        )
    return ("\n".join(lines).rstrip() + "\n").encode()


def theorem_inventory_bytes() -> bytes:
    document = {
        "schema": "chio.programmable-sovereignty.theorem-inventory.v1",
        "generatedAt": GENERATED_AT,
        "paper": TITLE,
        "targetVenue": TARGET,
        "leanToolchain": "leanprover/lean4:v4.28.0-rc1",
        "modelBoundary": "bounded ReceiptView and explicit finite domains",
        "implementationRelation": (
            "differential alignment, not extraction or refinement"
        ),
        "theorems": THEOREMS,
    }
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()


def archive_readme() -> bytes:
    theorem_lines = "\n".join(
        f"#print axioms {theorem['declaration']}" for theorem in THEOREMS
    )
    text = f"""# Chio Lean artifact

Paper: {TITLE}
Snapshot date: {GENERATED_AT}

Build from this directory:

```sh
lake build
```

The paper claims only bounded model theorems. It does not claim that this
project verifies the production Rust implementation.

To reproduce the recorded axiom lists:

```lean
import Chio.Treaty.BridgeEquivalence
{theorem_lines}
```
"""
    return text.encode()


def lean_archive_bytes() -> bytes:
    project = REPO / "formal/lean4/Chio"
    files = [
        project / "lean-toolchain",
        project / "lakefile.lean",
        project / "lake-manifest.json",
        project / "Chio.lean",
        *sorted((project / "Chio").rglob("*.lean")),
    ]
    for path in files:
        if not path.is_file():
            fail(f"Lean archive input missing: {path.relative_to(REPO)}")

    output = io.BytesIO()
    with gzip.GzipFile(
        filename="",
        mode="wb",
        fileobj=output,
        mtime=0,
    ) as gz_file:
        with tarfile.open(fileobj=gz_file, mode="w") as archive:
            root_info = tarfile.TarInfo("chio-lean")
            root_info.type = tarfile.DIRTYPE
            root_info.mode = 0o755
            root_info.mtime = 0
            root_info.uid = root_info.gid = 0
            root_info.uname = root_info.gname = "root"
            archive.addfile(root_info)

            entries = [
                ("chio-lean/README.md", archive_readme()),
                *[
                    (
                        "chio-lean/" + path.relative_to(project).as_posix(),
                        path.read_bytes(),
                    )
                    for path in files
                ],
            ]
            for name, data in sorted(entries):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o644
                info.mtime = 0
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                archive.addfile(info, io.BytesIO(data))
    return output.getvalue()


def manifest_bytes(
    proof_bytes: bytes,
    inventory_bytes: bytes,
    archive_bytes: bytes,
    source_commit: str,
    source_commit_bytes: bytes,
) -> bytes:
    source_hashes = [hash_entry(path) for path in SOURCE_FILES]
    benchmark_entries: list[dict[str, Any]] = []
    for benchmark in BENCHMARKS:
        benchmark_entries.append(
            {
                "id": benchmark["id"],
                "script": hash_entry(benchmark["script"]),
                "results": [hash_entry(path) for path in benchmark["results"]],
                "claimClass": "experimentally_measured",
            }
        )
    corpus_entries = {
        kind: [hash_entry(path) for path in paths]
        for kind, paths in CORPORA.items()
    }
    supplementary_entries = [
        {
            "path": (
                "docs/papers/programmable-sovereignty/"
                "supplementary/source-commit.txt"
            ),
            "sha256": sha256_bytes(source_commit_bytes),
        },
        {
            "path": (
                "docs/papers/programmable-sovereignty/"
                "supplementary/proof-manifest.toml"
            ),
            "sha256": sha256_bytes(proof_bytes),
        },
        {
            "path": (
                "docs/papers/programmable-sovereignty/"
                "supplementary/theorem-inventory.json"
            ),
            "sha256": sha256_bytes(inventory_bytes),
        },
        {
            "path": (
                "docs/papers/programmable-sovereignty/"
                "supplementary/lean-source.tar.gz"
            ),
            "sha256": sha256_bytes(archive_bytes),
        },
    ]
    content_items = [
        *source_hashes,
        *[
            benchmark["script"]
            for benchmark in benchmark_entries
        ],
        *[
            result
            for benchmark in benchmark_entries
            for result in benchmark["results"]
        ],
        *[
            corpus
            for corpus_list in corpus_entries.values()
            for corpus in corpus_list
        ],
        *supplementary_entries,
    ]
    content_digest = hashlib.sha256()
    for item in sorted(content_items, key=lambda entry: entry["path"]):
        content_digest.update(item["path"].encode())
        content_digest.update(b"\0")
        content_digest.update(item["sha256"].encode())
        content_digest.update(b"\n")

    toolchain = file_bytes("rust-toolchain.toml").decode()
    rust_match = re.search(r'channel\s*=\s*"([^"]+)"', toolchain)
    if rust_match is None:
        fail("could not parse pinned Rust toolchain")
    document = {
        "schema": "chio.programmable-sovereignty.artifact-manifest.v1",
        "generatedAt": GENERATED_AT,
        "paper": {
            "title": TITLE,
            "target": TARGET,
            "bodyPageLimit": 13,
            "submissionSource": (
                "docs/papers/programmable-sovereignty/paper-usenix.tex"
            ),
        },
        "source": {
            "commit": source_commit,
            "snapshotMode": (
                "recorded source commit plus self-contained "
                "content-addressed snapshot"
            ),
            "contentSetSha256": content_digest.hexdigest(),
        },
        "toolchains": {
            "rust": rust_match.group(1),
            "lean": file_bytes(
                "formal/lean4/Chio/lean-toolchain"
            ).decode().strip(),
            "tex": "TeX Live 2023 or compatible pdflatex and BibTeX",
        },
        "claimClasses": [
            "production_enforced",
            "bounded_theorem",
            "differentially_aligned",
            "experimentally_measured",
            "executable_demonstration",
            "operational_assumption",
            "future_work",
        ],
        "theorems": THEOREMS,
        "productionSymbols": [
            {
                key: value
                for key, value in symbol.items()
                if key != "pattern"
            }
            for symbol in PRODUCTION_SYMBOLS
        ],
        "behavioralTests": BEHAVIORAL_TESTS,
        "benchmarks": benchmark_entries,
        "corpora": corpus_entries,
        "sourceFiles": source_hashes,
        "supplementaryFiles": supplementary_entries,
        "excludedOrWithheld": EXCLUDED,
        "rebuildCommand": (
            "bash scripts/check-programmable-sovereignty-artifact.sh --full"
        ),
    }
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()


def require_equal(path: Path, expected: bytes) -> None:
    if not path.is_file():
        fail(f"generated output missing: {path.relative_to(REPO)}")
    if path.read_bytes() != expected:
        fail(
            f"generated output is stale: {path.relative_to(REPO)}; "
            "run the generator"
        )


def write_output(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate generated files without modifying them",
    )
    parser.add_argument(
        "--source-commit",
        help=(
            "record an explicit full source commit; generation writes it to "
            "supplementary/source-commit.txt"
        ),
    )
    parser.add_argument(
        "--benchmark-input-digest",
        choices=[benchmark["id"] for benchmark in BENCHMARKS],
        help="print the input-tree digest for one retained benchmark",
    )
    args = parser.parse_args()

    source_commit = resolve_source_commit(
        args.source_commit,
        require_local_object=not args.check or args.benchmark_input_digest is not None,
    )
    if args.benchmark_input_digest is not None:
        print(
            benchmark_input_tree_sha256(
                args.benchmark_input_digest,
                source_commit,
            )
        )
        return 0
    source_commit_bytes = f"{source_commit}\n".encode()
    validate_inputs(
        source_commit,
        require_local_source_object=not args.check,
    )
    proof_bytes = proof_manifest_bytes()
    inventory_bytes = theorem_inventory_bytes()
    archive_bytes = lean_archive_bytes()
    manifest = manifest_bytes(
        proof_bytes,
        inventory_bytes,
        archive_bytes,
        source_commit,
        source_commit_bytes,
    )
    outputs = [
        (SOURCE_COMMIT_FILE, source_commit_bytes),
        (SUPPLEMENTARY / "proof-manifest.toml", proof_bytes),
        (SUPPLEMENTARY / "theorem-inventory.json", inventory_bytes),
        (SUPPLEMENTARY / "lean-source.tar.gz", archive_bytes),
        (SUPPLEMENTARY / "artifact-manifest.json", manifest),
    ]
    if args.check:
        for path, data in outputs:
            require_equal(path, data)
        print("programmable sovereignty artifact is current")
    else:
        for path, data in outputs:
            write_output(path, data)
        print("generated programmable sovereignty artifact")
    return 0


if __name__ == "__main__":
    sys.exit(main())
