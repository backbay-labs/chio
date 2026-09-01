#!/usr/bin/env python3
"""Generate a fail-closed hosted cognition-market qualification report."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath


SHA_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GATE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
MODES = ("code-only", "kvm-boundary")
CLAIMS = (
    "claim.finding.hosted_postgres_rls_forced",
    "claim.finding.hosted_runtime_role_least_privilege",
    "claim.finding.hosted_remote_custody",
    "claim.finding.hosted_settlement_transport",
    "claim.finding.hosted_worker_protocol",
)


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def checked_log_path(artifact_root: Path, relative_log: str) -> Path:
    relative = PurePosixPath(relative_log)
    if (
        relative.is_absolute()
        or not relative.parts
        or relative.parts[0] != "logs"
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ValueError(f"unsafe qualification log path: {relative_log!r}")
    path = artifact_root.joinpath(*relative.parts)
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"qualification log is not a regular file: {relative_log}")
    resolved_root = artifact_root.resolve(strict=True)
    resolved_path = path.resolve(strict=True)
    if not resolved_path.is_relative_to(resolved_root):
        raise ValueError(f"qualification log escapes artifact root: {relative_log}")
    return resolved_path


def load_gates(gate_index: Path, artifact_root: Path) -> list[dict[str, str]]:
    gates: list[dict[str, str]] = []
    seen: set[str] = set()
    for line_number, line in enumerate(
        gate_index.read_text(encoding="utf-8").splitlines(), 1
    ):
        fields = line.split("\t")
        if len(fields) != 3:
            raise ValueError(f"gate index line {line_number} must have three fields")
        gate_id, relative_log, command = fields
        if not GATE_ID_RE.fullmatch(gate_id):
            raise ValueError(f"gate index line {line_number} has invalid gate ID")
        if gate_id in seen:
            raise ValueError(f"gate index contains duplicate gate ID: {gate_id}")
        if not command or len(command) > 8192 or any(ord(char) < 0x20 for char in command):
            raise ValueError(f"gate index line {line_number} has invalid command text")
        log_path = checked_log_path(artifact_root, relative_log)
        seen.add(gate_id)
        gates.append(
            {
                "id": gate_id,
                "command": command,
                "result": "passed",
                "log": relative_log,
                "logSha256": digest_file(log_path),
            }
        )
    if not gates:
        raise ValueError("gate index must contain at least one passed gate")
    return gates


def build_report(
    candidate_sha: str,
    mode: str,
    kvm_evidence_sha256: str,
    gate_index: Path,
    report_path: Path,
) -> dict[str, object]:
    if not SHA_RE.fullmatch(candidate_sha):
        raise ValueError("candidate SHA must be 40 or 64 lowercase hexadecimal characters")
    if mode not in MODES:
        raise ValueError(f"mode must be one of: {', '.join(MODES)}")
    kvm_qualified = mode == "kvm-boundary"
    if kvm_qualified != bool(kvm_evidence_sha256):
        raise ValueError("KVM mode and KVM evidence digest must be present together")
    if kvm_evidence_sha256 and not SHA256_RE.fullmatch(kvm_evidence_sha256):
        raise ValueError("KVM evidence digest must be lowercase SHA-256")

    artifact_root = report_path.parent
    if gate_index.parent != artifact_root:
        raise ValueError("gate index and report must share one artifact root")
    gates = load_gates(gate_index, artifact_root)
    decision = (
        "qualified-code-boundary" if mode == "code-only" else "qualified-kvm-boundary"
    )
    return {
        "schema": "chio.finding.hosted-qualification.v1",
        "candidateSha": candidate_sha,
        "generatedAt": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "source": "github-actions"
        if os.environ.get("GITHUB_ACTIONS") == "true"
        else "local",
        "workflowRunId": os.environ.get("GITHUB_RUN_ID"),
        "workflowRunAttempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "mode": mode,
        "decision": decision,
        "codeQualified": True,
        "kvmQualified": kvm_qualified,
        "networkQualified": False,
        "productionReady": False,
        "promotionReady": False,
        "kvmEvidenceSha256": kvm_evidence_sha256 or None,
        "claims": list(CLAIMS),
        "gates": gates,
    }


def write_atomic(report_path: Path, report: dict[str, object]) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{report_path.name}.", dir=report_path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, report_path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--mode", choices=MODES, required=True)
    parser.add_argument("--kvm-evidence-sha256", default="")
    parser.add_argument("--gate-index", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = build_report(
        args.candidate_sha,
        args.mode,
        args.kvm_evidence_sha256,
        args.gate_index,
        args.report,
    )
    write_atomic(args.report, report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
