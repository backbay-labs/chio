#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile


KEY_PATTERN = re.compile(r"[0-9a-f]{64}\n?")
DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}")
INVARIANTS = [
    "NoAllowAfterRevoke",
    "MonotoneLog",
    "AttenuationPreserving",
    "RevocationFreshness",
]
WITNESSES = [
    "allowReceipt",
    "orderedReceiptPair",
    "attenuatedAdmission",
    "nonzeroRevocationEpoch",
]


class StableFile:
    def __init__(self, path: Path, label: str) -> None:
        self.path = path
        self.label = label
        self.data, self.identity = self._read()
        self.sha256 = hashlib.sha256(self.data).hexdigest()

    def _read(self) -> tuple[bytes, tuple[int, int, int, int, int]]:
        absolute = Path(os.path.abspath(self.path))
        parts = absolute.parts
        if not parts or parts[0] != os.sep:
            raise SystemExit(f"receipt trace binding: {self.label} path is invalid: {self.path}")

        directory_fd = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY)
        file_fd = -1
        try:
            for component in parts[1:-1]:
                next_fd = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
                os.close(directory_fd)
                directory_fd = next_fd
            file_fd = os.open(
                parts[-1],
                os.O_RDONLY | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode):
                raise SystemExit(
                    f"receipt trace binding: {self.label} is not a regular file: {self.path}"
                )
            chunks = []
            while chunk := os.read(file_fd, 1024 * 1024):
                chunks.append(chunk)
            after = os.fstat(file_fd)
            identity = (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            if identity != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise SystemExit(
                    f"receipt trace binding: {self.label} changed while it was read"
                )
            current = os.stat(parts[-1], dir_fd=directory_fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
                raise SystemExit(
                    f"receipt trace binding: {self.label} path changed while it was read"
                )
            return b"".join(chunks), identity
        except OSError as error:
            raise SystemExit(
                f"receipt trace binding: cannot read {self.label} without following symlinks: {error}"
            ) from error
        finally:
            if file_fd >= 0:
                os.close(file_fd)
            os.close(directory_fd)

    def confirm_unchanged(self) -> None:
        data, identity = self._read()
        if identity != self.identity or data != self.data:
            raise SystemExit(
                f"receipt trace binding: {self.label} changed during validation"
            )


def decode_json(artifact: StableFile, label: str) -> object:
    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate object key: {key}")
            value[key] = item
        return value

    try:
        return json.loads(
            artifact.data.decode("utf-8"), object_pairs_hook=reject_duplicate_keys
        )
    except (UnicodeError, ValueError) as error:
        raise SystemExit(f"receipt trace binding: cannot parse {label}: {error}") from error


def read_key(artifact: StableFile) -> str:
    try:
        raw = artifact.data.decode("ascii")
    except UnicodeError as error:
        raise SystemExit(
            f"receipt trace binding: {artifact.label} is not ASCII: {error}"
        ) from error
    if KEY_PATTERN.fullmatch(raw) is None:
        raise SystemExit(
            f"receipt trace binding: {artifact.label} must contain one lowercase Ed25519 key"
        )
    return raw.rstrip("\n")


def require_digest(report: dict[str, object], field: str, expected: str) -> None:
    recorded = report.get(field)
    if not isinstance(recorded, str) or DIGEST_PATTERN.fullmatch(recorded) is None:
        raise SystemExit(f"receipt trace binding: report {field} is invalid")
    if recorded != expected:
        raise SystemExit(
            f"receipt trace binding: report {field} does not match its source artifact"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--trace-check-model", required=True, type=Path)
    parser.add_argument("--trace-evaluation-model", required=True, type=Path)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--itf", required=True, type=Path)
    parser.add_argument("--witness", required=True, type=Path)
    parser.add_argument("--checker-binary", required=True, type=Path)
    parser.add_argument("--timeout-binary", required=True, type=Path)
    parser.add_argument("--generated-observer-key", required=True, type=Path)
    parser.add_argument("--pinned-observer-key", required=True, type=Path)
    parser.add_argument("--negative-registry", required=True, type=Path)
    parser.add_argument("--extra-artifact", action="append", default=[])
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def write_atomic(path: Path, value: object) -> None:
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise SystemExit(
                f"receipt trace binding: output is not a regular non-symlink file: {path}"
            )
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main() -> None:
    args = parse_args()
    paths = {
        "report": args.report,
        "model": args.model,
        "traceCheckModel": args.trace_check_model,
        "traceEvaluationModel": args.trace_evaluation_model,
        "log": args.log,
        "itf": args.itf,
        "witness": args.witness,
        "checkerBinary": args.checker_binary,
        "timeoutBinary": args.timeout_binary,
        "generatedObserverKey": args.generated_observer_key,
        "pinnedObserverKey": args.pinned_observer_key,
        "negativeRegistry": args.negative_registry,
    }
    labels = {
        "report": "validation report",
        "model": "model source",
        "traceCheckModel": "trace-check model source",
        "traceEvaluationModel": "trace-evaluation model source",
        "log": "observation log",
        "itf": "ITF projection",
        "witness": "Apalache ITF witness",
        "checkerBinary": "checker binary",
        "timeoutBinary": "timeout binary",
        "generatedObserverKey": "generated observer key",
        "pinnedObserverKey": "pinned observer key",
        "negativeRegistry": "negative registry",
    }
    for raw in args.extra_artifact:
        name, separator, raw_path = raw.partition("=")
        if (
            not separator
            or re.fullmatch(r"[a-z][A-Za-z0-9]*", name) is None
            or name in paths
            or not raw_path
        ):
            raise SystemExit(
                "receipt trace binding: extra artifact must be a unique lower-camel LABEL=PATH"
            )
        paths[name] = Path(raw_path)
        labels[name] = f"extra artifact {name}"
    inputs = {name: StableFile(path, labels[name]) for name, path in paths.items()}

    generated_key = read_key(inputs["generatedObserverKey"])
    pinned_key = read_key(inputs["pinnedObserverKey"])
    if generated_key != pinned_key:
        raise SystemExit(
            "receipt trace binding: generated observer key does not match the checked pin"
        )

    report_value = decode_json(inputs["report"], "validation report")
    if not isinstance(report_value, dict):
        raise SystemExit("receipt trace binding: validation report is not an object")
    report = report_value
    if report.get("schema") != "chio.trace-validation.v1":
        raise SystemExit("receipt trace binding: validation report schema is invalid")
    if report.get("status") != "passed":
        raise SystemExit("receipt trace binding: validation report did not pass")
    if report.get("invariants") != INVARIANTS:
        raise SystemExit("receipt trace binding: validation report invariant set is invalid")
    if report.get("observerKeys") != [pinned_key]:
        raise SystemExit(
            "receipt trace binding: report observer key does not match the checked pin"
        )
    require_digest(
        report,
        "observerKeySetSha256",
        hashlib.sha256(pinned_key.encode("ascii")).hexdigest(),
    )

    expected = {
        "modelSha256": inputs["model"].sha256,
        "traceCheckModelSha256": inputs["traceCheckModel"].sha256,
        "traceEvaluationModelSha256": inputs["traceEvaluationModel"].sha256,
        "logSha256": inputs["log"].sha256,
        "itfSha256": inputs["itf"].sha256,
        "apalacheWitnessSha256": inputs["witness"].sha256,
        "checkerBinarySha256": inputs["checkerBinary"].sha256,
        "timeoutBinarySha256": inputs["timeoutBinary"].sha256,
    }
    for field, digest in expected.items():
        require_digest(report, field, digest)

    action_coverage = report.get("actionCoverage")
    if not isinstance(action_coverage, dict):
        raise SystemExit("receipt trace binding: actionCoverage is invalid")
    if action_coverage.get("revoke", 0) < 1 or action_coverage.get(
        "postRevocationEvaluate", 0
    ) < 1:
        raise SystemExit("receipt trace binding: validation report is action-vacuous")
    invariant_witnesses = report.get("invariantWitnesses")
    if not isinstance(invariant_witnesses, dict) or any(
        not isinstance(invariant_witnesses.get(name), int)
        or invariant_witnesses[name] < 1
        for name in WITNESSES
    ):
        raise SystemExit("receipt trace binding: validation report is invariant-vacuous")

    itf_value = decode_json(inputs["itf"], "ITF projection")
    witness_value = decode_json(inputs["witness"], "Apalache ITF witness")
    itf_states = itf_value.get("states") if isinstance(itf_value, dict) else None
    witness_states = witness_value.get("states") if isinstance(witness_value, dict) else None
    state_count = report.get("itfStateCount")
    expected_witness_state_count = (
        state_count * 2 - 1 if isinstance(state_count, int) and state_count >= 1 else 0
    )
    if (
        not isinstance(state_count, int)
        or state_count < 1
        or not isinstance(itf_states, list)
        or not isinstance(witness_states, list)
        or len(itf_states) != state_count
        or len(witness_states) != expected_witness_state_count
        or sum(
            1
            for index, state in enumerate(witness_states)
            if isinstance(state, dict)
            and state.get("evaluated") is True
            and index % 2 == 0
        )
        != state_count
        or any(
            not isinstance(state, dict)
            or state.get("evaluated") is not (index % 2 == 0)
            for index, state in enumerate(witness_states)
        )
    ):
        raise SystemExit("receipt trace binding: ITF state counts are inconsistent")

    registry = inputs["negativeRegistry"].data.decode("utf-8", errors="strict")
    if 'schema = "chio.runtime-trace-negative.v1"' not in registry:
        raise SystemExit("receipt trace binding: negative registry schema is invalid")

    for artifact in inputs.values():
        artifact.confirm_unchanged()

    binding = {
        "schema": "chio.trace-artifact-bindings.v1",
        "status": "passed",
        "traceId": report.get("traceId"),
        "traceLength": report.get("traceLength"),
        "itfStateCount": state_count,
        "actionCoverage": action_coverage,
        "invariantWitnesses": invariant_witnesses,
        "artifactHashes": {name: artifact.sha256 for name, artifact in inputs.items()},
        "artifactPaths": {name: str(path) for name, path in paths.items()},
    }
    if args.output.exists():
        previous_artifact = StableFile(args.output, "existing binding record")
        previous = decode_json(previous_artifact, "existing binding record")
        if (
            not isinstance(previous, dict)
            or previous.get("schema") != "chio.trace-artifact-bindings.v1"
            or previous.get("status") != "passed"
            or previous.get("artifactHashes") != binding["artifactHashes"]
        ):
            raise SystemExit(
                "receipt trace binding: existing binding record does not match current artifacts"
            )
        previous_artifact.confirm_unchanged()
    write_atomic(args.output, binding)


if __name__ == "__main__":
    main()
