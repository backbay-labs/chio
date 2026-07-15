#!/usr/bin/env python3

"""Strict parsing for Apalache invariant outcomes and ITF traces."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys


class EvidenceError(ValueError):
    """Raised when Apalache evidence is missing or ambiguous."""


_SUFFIX = r"(?:\s+I@[0-9:.]+)?\s*$"
_OUTCOME = re.compile(
    rf"\s*The outcome is:\s+(Error|NoError|ExecutionsTooShort){_SUFFIX}"
)
_NO_ERROR = re.compile(
    rf"\s*Checker reports no error up to computation length\s+([0-9]+){_SUFFIX}"
)
_ERROR_REPORT = re.compile(rf"\s*Checker has found an error{_SUFFIX}")
_INVARIANT_VIOLATION = re.compile(
    rf"\s*State [0-9]+: state invariant [0-9]+ violated\.{_SUFFIX}"
)
_INVARIANT = re.compile(
    rf"\s*>\s*Set an invariant to\s+([A-Za-z_][A-Za-z0-9_]*){_SUFFIX}"
)
_TEMPORAL_PROPERTY = re.compile(
    rf"\s*>\s*Set a temporal property to\s+([A-Za-z_][A-Za-z0-9_]*){_SUFFIX}"
)
_TRACE_NAME = re.compile(r"violation[0-9]+\.itf\.json")
_ANY_VIOLATION_TRACE = re.compile(
    r"(?:MC)?violation(?:[0-9]+)?(?:\.itf)?\.(?:json|tla|out)"
)
_TYPE_TOKEN = re.compile(r"\s*(->|<<|>>|[(){}:,]|[A-Za-z_][A-Za-z0-9_]*)")
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]*)")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise EvidenceError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def _reject_nonfinite(value: str) -> object:
    raise EvidenceError(f"non-standard JSON numeric constant: {value}")


class _TypeParser:
    def __init__(self, source: str) -> None:
        self.tokens: list[str] = []
        position = 0
        while position < len(source):
            match = _TYPE_TOKEN.match(source, position)
            if match is None:
                raise EvidenceError(f"unsupported ITF type syntax: {source}")
            self.tokens.append(match.group(1))
            position = match.end()
        self.position = 0

    def take(self, expected: str | None = None) -> str:
        if self.position >= len(self.tokens):
            raise EvidenceError("truncated ITF type")
        token = self.tokens[self.position]
        if expected is not None and token != expected:
            raise EvidenceError(f"expected {expected} in ITF type, found {token}")
        self.position += 1
        return token

    def peek(self) -> str | None:
        if self.position >= len(self.tokens):
            return None
        return self.tokens[self.position]

    def parse(self) -> tuple[object, ...]:
        value = self.parse_arrow()
        if self.position != len(self.tokens):
            raise EvidenceError(f"unexpected ITF type token: {self.tokens[self.position]}")
        return value

    def parse_arrow(self) -> tuple[object, ...]:
        left = self.parse_atom()
        if self.position < len(self.tokens) and self.tokens[self.position] == "->":
            self.position += 1
            return ("map", left, self.parse_arrow())
        return left

    def parse_atom(self) -> tuple[object, ...]:
        token = self.take()
        if token in {"Bool", "Int", "Str"}:
            return (token.lower(),)
        if token in {"Set", "Seq"}:
            self.take("(")
            element = self.parse_arrow()
            self.take(")")
            return (token.lower(), element)
        if token == "(":
            value = self.parse_arrow()
            self.take(")")
            return value
        if token == "<<":
            elements: list[tuple[object, ...]] = []
            if self.peek() != ">>":
                while True:
                    elements.append(self.parse_arrow())
                    if self.peek() != ",":
                        break
                    self.position += 1
            self.take(">>")
            return ("tuple", tuple(elements))
        if token == "{":
            fields: list[tuple[str, tuple[object, ...]]] = []
            if self.peek() != "}":
                while True:
                    name = self.take()
                    if IDENTIFIER.fullmatch(name) is None:
                        raise EvidenceError(f"invalid ITF record field: {name}")
                    self.take(":")
                    fields.append((name, self.parse_arrow()))
                    if self.peek() != ",":
                        break
                    self.position += 1
            self.take("}")
            if len(fields) != len({name for name, _ in fields}):
                raise EvidenceError("ITF record type repeats a field")
            return ("record", tuple(fields))
        raise EvidenceError(f"unsupported ITF type constructor: {token}")


IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _tagged(value: object, tag: str) -> list[object] | None:
    if not isinstance(value, dict) or set(value) != {tag} or not isinstance(value[tag], list):
        return None
    return value[tag]


def _distinct(values: list[object]) -> bool:
    encoded = [json.dumps(value, sort_keys=True, separators=(",", ":")) for value in values]
    return len(encoded) == len(set(encoded))


def _value_matches(type_node: tuple[object, ...], value: object) -> bool:
    kind = type_node[0]
    if kind == "bool":
        return type(value) is bool
    if kind == "int":
        return (
            isinstance(value, dict)
            and set(value) == {"#bigint"}
            and isinstance(value["#bigint"], str)
            and _INTEGER.fullmatch(value["#bigint"]) is not None
        )
    if kind == "str":
        return isinstance(value, str)
    if kind == "set":
        elements = _tagged(value, "#set")
        return elements is not None and _distinct(elements) and all(
            _value_matches(type_node[1], element) for element in elements
        )
    if kind == "seq":
        return isinstance(value, list) and all(
            _value_matches(type_node[1], element) for element in value
        )
    if kind == "tuple":
        elements = _tagged(value, "#tup")
        if elements is None:
            return False
        expected = type_node[1]
        return len(elements) == len(expected) and all(
            _value_matches(element_type, element)
            for element_type, element in zip(expected, elements, strict=True)
        )
    if kind == "map":
        entries = _tagged(value, "#map")
        if entries is None or not all(isinstance(entry, list) and len(entry) == 2 for entry in entries):
            return False
        keys = [entry[0] for entry in entries]
        return _distinct(keys) and all(
            _value_matches(type_node[1], entry[0])
            and _value_matches(type_node[2], entry[1])
            for entry in entries
        )
    if kind == "record":
        fields = dict(type_node[1])
        return isinstance(value, dict) and set(value) == set(fields) and all(
            _value_matches(field_type, value[name]) for name, field_type in fields.items()
        )
    return False


def parse_outcome(log_path: Path, expected_invariant: str) -> str:
    """Return the unique outcome after validating the configured invariant."""

    log = log_path.read_text(encoding="utf-8")
    outcomes = [
        match.group(1)
        for line in log.splitlines()
        if (match := _OUTCOME.fullmatch(line))
    ]
    invariants = [
        match.group(1)
        for line in log.splitlines()
        if (match := _INVARIANT.fullmatch(line))
    ]
    if outcomes not in (["Error"], ["NoError"], ["ExecutionsTooShort"]):
        raise EvidenceError(
            "expected exactly one Error, NoError, or ExecutionsTooShort "
            f"outcome, found {outcomes}"
        )
    if invariants != [expected_invariant]:
        raise EvidenceError(
            f"expected exactly invariant {expected_invariant}, found {invariants}"
        )
    error_reports = [line for line in log.splitlines() if _ERROR_REPORT.fullmatch(line)]
    invariant_violations = [
        line for line in log.splitlines() if _INVARIANT_VIOLATION.fullmatch(line)
    ]
    if outcomes == ["Error"]:
        if len(error_reports) != 1 or len(invariant_violations) != 1:
            raise EvidenceError(
                "Error outcome lacks one exact invariant-violation summary"
            )
    elif error_reports or invariant_violations:
        raise EvidenceError("non-error outcome contains invariant-error evidence")
    return outcomes[0]


def discover_trace(run_root: Path) -> Path:
    """Return the unique non-empty, non-symlink numbered ITF trace."""

    resolved = run_root.resolve()
    traces = sorted(
        path
        for path in resolved.rglob("violation*.itf.json")
        if _TRACE_NAME.fullmatch(path.name)
        and path.is_file()
        and not path.is_symlink()
        and path.stat().st_size > 0
    )
    if len(traces) != 1:
        raise EvidenceError(
            "expected exactly one numbered non-empty ITF violation trace, "
            f"found {len(traces)}"
        )
    return traces[0]


def validate_trace(trace_path: Path) -> None:
    """Validate the strict ITF shape consumed by the negative-test lane."""

    try:
        trace = json.loads(
            trace_path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_nonfinite,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError("cannot decode ITF trace") from error
    if not isinstance(trace, dict):
        raise EvidenceError("ITF trace must be an object")
    metadata = trace.get("#meta")
    if not isinstance(metadata, dict) or metadata.get("format") != "ITF":
        raise EvidenceError("ITF trace metadata is missing its format")
    params = trace.get("params")
    variables = trace.get("vars")
    if not isinstance(params, list) or not isinstance(variables, list) or not variables:
        raise EvidenceError("ITF trace parameters or variables are invalid")
    names = params + variables
    if (
        not all(isinstance(name, str) and name for name in names)
        or len(set(names)) != len(names)
    ):
        raise EvidenceError("ITF trace names are invalid or repeated")
    var_types = metadata.get("varTypes")
    if (
        not isinstance(var_types, dict)
        or set(var_types) != set(variables)
        or not all(isinstance(value, str) and value for value in var_types.values())
    ):
        raise EvidenceError("ITF trace variable types do not match variables")
    parsed_types = {
        name: _TypeParser(encoded).parse() for name, encoded in var_types.items()
    }
    states = trace.get("states")
    if not isinstance(states, list) or not states:
        raise EvidenceError("ITF trace has no states")
    expected_keys = set(names) | {"#meta"}
    parameter_values: tuple[str, ...] | None = None
    for index, state in enumerate(states):
        if not isinstance(state, dict) or set(state) != expected_keys:
            raise EvidenceError(f"ITF state {index} has the wrong fields")
        state_metadata = state.get("#meta")
        if not isinstance(state_metadata, dict) or state_metadata.get("index") != index:
            raise EvidenceError(f"ITF state {index} has the wrong index")
        encoded_parameters = tuple(
            json.dumps(state[name], sort_keys=True, separators=(",", ":"))
            for name in params
        )
        if parameter_values is None:
            parameter_values = encoded_parameters
        elif encoded_parameters != parameter_values:
            raise EvidenceError(f"ITF state {index} changes a model parameter")
        for name in variables:
            if not _value_matches(parsed_types[name], state[name]):
                raise EvidenceError(
                    f"ITF state {index} variable {name} does not match its declared type"
                )


def classify_completed_run(
    *,
    log_path: Path,
    expected_invariant: str,
    expected_length: int,
    exit_code: int,
    run_root: Path,
    allow_executions_too_short: bool = True,
) -> tuple[str, Path | None]:
    """Classify a completed check using the negative lane's exact contract."""

    if exit_code not in (0, 12):
        raise EvidenceError(f"unexpected Apalache exit code {exit_code}")
    if expected_length < 1:
        raise EvidenceError("expected computation length must be positive")
    outcome = parse_outcome(log_path, expected_invariant)
    if exit_code == 0 and outcome in {"NoError", "ExecutionsTooShort"}:
        if outcome == "ExecutionsTooShort" and not allow_executions_too_short:
            raise EvidenceError(
                "ExecutionsTooShort cannot establish a clean positive baseline"
            )
        lines = log_path.read_text(encoding="utf-8").splitlines()
        no_error_lengths = [
            int(match.group(1))
            for line in lines
            if (match := _NO_ERROR.fullmatch(line))
        ]
        if no_error_lengths != [expected_length] or any(
            _ERROR_REPORT.fullmatch(line) for line in lines
        ):
            raise EvidenceError(
                f"{outcome} lacks the exact bounded no-error summary"
            )
        violation_traces = [
            path
            for path in run_root.resolve().rglob("violation*.itf.json")
            if _TRACE_NAME.fullmatch(path.name)
            and path.is_file()
            and not path.is_symlink()
        ]
        if violation_traces:
            raise EvidenceError(f"{outcome} emitted a numbered violation trace")
        return "survived", None
    if exit_code == 12 and outcome == "Error":
        trace = discover_trace(run_root)
        validate_trace(trace)
        return "killed", trace
    raise EvidenceError(
        f"Apalache exit {exit_code} is inconsistent with outcome {outcome}"
    )


def validate_positive_run(
    *,
    log_path: Path,
    run_root: Path,
    mode: str,
    expected_property: str,
    expected_length: int,
    exit_code: int,
) -> None:
    """Validate complete, non-vacuous evidence from a positive check."""

    if exit_code != 0:
        raise EvidenceError(f"positive Apalache check exited {exit_code}, expected 0")
    if expected_length < 0:
        raise EvidenceError("expected computation length must be non-negative")
    if IDENTIFIER.fullmatch(expected_property) is None:
        raise EvidenceError(f"invalid expected property name: {expected_property}")
    if mode not in {"invariant", "temporal"}:
        raise EvidenceError(f"unsupported positive-check mode: {mode}")
    if not run_root.is_dir():
        raise EvidenceError(f"positive evidence root is not a directory: {run_root}")

    lines = log_path.read_text(encoding="utf-8").splitlines()
    outcomes = [
        match.group(1)
        for line in lines
        if (match := _OUTCOME.fullmatch(line))
    ]
    if outcomes != ["NoError"]:
        raise EvidenceError(
            f"expected exactly one NoError outcome, found {outcomes}"
        )

    configured_pattern = _INVARIANT if mode == "invariant" else _TEMPORAL_PROPERTY
    configured = [
        match.group(1)
        for line in lines
        if (match := configured_pattern.fullmatch(line))
    ]
    if configured != [expected_property]:
        raise EvidenceError(
            f"expected exactly {mode} {expected_property}, found {configured}"
        )
    if mode == "invariant" and any(
        _TEMPORAL_PROPERTY.fullmatch(line) for line in lines
    ):
        raise EvidenceError("invariant check unexpectedly configured a temporal property")

    no_error_lengths = [
        int(match.group(1))
        for line in lines
        if (match := _NO_ERROR.fullmatch(line))
    ]
    if no_error_lengths != [expected_length]:
        raise EvidenceError(
            "NoError outcome lacks the exact requested computation length: "
            f"expected {expected_length}, found {no_error_lengths}"
        )
    if any(_ERROR_REPORT.fullmatch(line) for line in lines) or any(
        _INVARIANT_VIOLATION.fullmatch(line) for line in lines
    ):
        raise EvidenceError("NoError outcome contains violation evidence")

    traces = sorted(
        path
        for path in run_root.resolve().rglob("violation*")
        if _ANY_VIOLATION_TRACE.fullmatch(path.name)
    )
    if traces:
        raise EvidenceError(
            f"NoError outcome emitted {len(traces)} violation trace(s)"
        )


def main(arguments: list[str]) -> int:
    """Expose the shared checks to shell runners without duplicating regexes."""

    if not arguments:
        raise EvidenceError(
            "usage: apalache_evidence.py outcome <log> <invariant> | "
            "positive <log> <run-root> <mode> <property> <length> <exit> | "
            "trace <run-root> | validate-trace <trace>"
        )
    command, *values = arguments
    if command == "outcome" and len(values) == 2:
        print(parse_outcome(Path(values[0]), values[1]))
        return 0
    if command == "positive" and len(values) == 6:
        try:
            expected_length = int(values[4])
            exit_code = int(values[5])
        except ValueError as error:
            raise EvidenceError("positive length and exit must be integers") from error
        validate_positive_run(
            log_path=Path(values[0]),
            run_root=Path(values[1]),
            mode=values[2],
            expected_property=values[3],
            expected_length=expected_length,
            exit_code=exit_code,
        )
        return 0
    if command == "trace" and len(values) == 1:
        print(discover_trace(Path(values[0])))
        return 0
    if command == "validate-trace" and len(values) == 1:
        validate_trace(Path(values[0]))
        return 0
    raise EvidenceError(
        "usage: apalache_evidence.py outcome <log> <invariant> | "
        "positive <log> <run-root> <mode> <property> <length> <exit> | "
        "trace <run-root> | validate-trace <trace>"
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (EvidenceError, OSError, UnicodeError) as error:
        print(f"apalache-evidence: {error}", file=sys.stderr)
        raise SystemExit(1) from error
