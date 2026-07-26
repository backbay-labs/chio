#!/usr/bin/env python3
"""Validate production revocation schedules against the model projection."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any


VARIABLES = [
    "action",
    "originEpoch",
    "viewEpoch",
    "queueEpoch",
    "channelCount",
    "forgedCount",
    "partitioned",
    "localTime",
    "viewIssuedAt",
    "freshnessBound",
    "allowFresh",
]
NUMERIC = set(VARIABLES) - {"action", "partitioned", "allowFresh"}
VARIABLE_TYPES = {
    "action": "Str",
    "originEpoch": "Int",
    "viewEpoch": "Int",
    "queueEpoch": "Int",
    "channelCount": "Int",
    "forgedCount": "Int",
    "partitioned": "Bool",
    "localTime": "Int",
    "viewIssuedAt": "Int",
    "freshnessBound": "Int",
    "allowFresh": "Bool",
}
ROOT_ISSUED_AT_BASE = 1_700_000_000_000
EXPECTED_ACTIONS = {
    "forged-signer-rejected.itf.json": ["Init", "InjectForged", "RejectForged"],
    "loss-duplicate-reorder.itf.json": [
        "Init",
        "Revoke",
        "QueueRoot",
        "Send",
        "Duplicate",
        "Lose",
        "Revoke",
        "QueueRoot",
        "Send",
        "Deliver",
        "Deliver",
    ],
    "partition-heal-catchup.itf.json": [
        "Init",
        "Revoke",
        "QueueRoot",
        "Revoke",
        "QueueRoot",
        "Revoke",
        "QueueRoot",
        "Send",
        "Cut",
        "Lose",
        "Heal",
        "Catchup",
    ],
    "wall-clock-stale-deny.itf.json": [
        "Init",
        "Tick",
        "Tick",
        "Tick",
        "EvaluateDeny",
    ],
}


def fail(path: Path, message: str) -> None:
    raise SystemExit(f"{path}: {message}")


def load(path: Path) -> list[dict[str, Any]]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(path, f"cannot read ITF: {error}")
    if not isinstance(document, dict):
        fail(path, "ITF root must be an object")
    metadata = document.get("#meta")
    if not isinstance(metadata, dict) or metadata.get("format") != "ITF":
        fail(path, "ITF format metadata is missing")
    if metadata.get("varTypes") != VARIABLE_TYPES:
        fail(path, "ITF variable types do not match the revocation projection")
    if document.get("params") != [] or document.get("vars") != VARIABLES:
        fail(path, "ITF variables do not match the revocation projection")
    states = document.get("states")
    if not isinstance(states, list) or len(states) < 2:
        fail(path, "ITF must contain at least two states")
    expected_keys = set(VARIABLES) | {"#meta"}
    for index, state in enumerate(states):
        if not isinstance(state, dict) or set(state) != expected_keys:
            fail(path, f"state {index} has an invalid key set")
        state_meta = state["#meta"]
        if not isinstance(state_meta, dict) or state_meta.get("index") != index:
            fail(path, f"state {index} has an invalid index")
        if not isinstance(state["action"], str):
            fail(path, f"state {index} action is not a string")
        for name in ("partitioned", "allowFresh"):
            if not isinstance(state[name], bool):
                fail(path, f"state {index} {name} is not a boolean")
        for name in NUMERIC:
            if type(state[name]) is not int or state[name] < 0:
                fail(path, f"state {index} {name} is not a natural number")
    return states


def unchanged(
    path: Path,
    index: int,
    previous: dict[str, Any],
    current: dict[str, Any],
    changed: set[str],
) -> None:
    for name in set(VARIABLES) - changed - {"action"}:
        if current[name] != previous[name]:
            fail(path, f"state {index} action {current['action']} changed {name}")


def validate_step(
    path: Path, index: int, previous: dict[str, Any], current: dict[str, Any]
) -> None:
    action = current["action"]
    if action == "Revoke":
        unchanged(path, index, previous, current, {"originEpoch"})
        if current["originEpoch"] != previous["originEpoch"] + 1:
            fail(path, f"state {index} Revoke did not increment the origin epoch")
    elif action == "QueueRoot":
        unchanged(path, index, previous, current, {"queueEpoch"})
        if current["originEpoch"] == 0 or current["queueEpoch"] != current["originEpoch"]:
            fail(path, f"state {index} QueueRoot did not coalesce to the current epoch")
    elif action == "Send":
        unchanged(path, index, previous, current, {"queueEpoch", "channelCount"})
        if previous["queueEpoch"] == 0 or current["queueEpoch"] != 0:
            fail(path, f"state {index} Send did not drain a queued root")
        if current["channelCount"] != previous["channelCount"] + 1:
            fail(path, f"state {index} Send did not add one frame")
    elif action == "Duplicate":
        unchanged(path, index, previous, current, {"channelCount"})
        if previous["channelCount"] == 0 or current["channelCount"] != previous["channelCount"] + 1:
            fail(path, f"state {index} Duplicate did not copy an in-flight frame")
    elif action == "Lose":
        unchanged(path, index, previous, current, {"channelCount"})
        if previous["channelCount"] == 0 or current["channelCount"] + 1 != previous["channelCount"]:
            fail(path, f"state {index} Lose did not remove one in-flight frame")
    elif action == "Deliver":
        unchanged(
            path,
            index,
            previous,
            current,
            {"channelCount", "viewEpoch", "viewIssuedAt"},
        )
        if previous["partitioned"] or previous["channelCount"] == 0:
            fail(path, f"state {index} Deliver was not enabled")
        if current["channelCount"] + 1 != previous["channelCount"]:
            fail(path, f"state {index} Deliver did not consume one frame")
        if not previous["viewEpoch"] <= current["viewEpoch"] <= current["originEpoch"]:
            fail(path, f"state {index} Deliver rewound or forged the high-water mark")
        expected_issued_at = (
            ROOT_ISSUED_AT_BASE + current["viewEpoch"]
            if current["viewEpoch"] > previous["viewEpoch"]
            else previous["viewIssuedAt"]
        )
        if current["viewIssuedAt"] != expected_issued_at:
            fail(path, f"state {index} Deliver did not retain the installed root timestamp")
    elif action == "InjectForged":
        unchanged(path, index, previous, current, {"forgedCount"})
        if current["forgedCount"] != previous["forgedCount"] + 1:
            fail(path, f"state {index} InjectForged did not add one frame")
    elif action == "RejectForged":
        unchanged(path, index, previous, current, {"forgedCount"})
        if previous["forgedCount"] == 0 or current["forgedCount"] + 1 != previous["forgedCount"]:
            fail(path, f"state {index} RejectForged did not consume one frame")
    elif action == "Cut":
        unchanged(path, index, previous, current, {"partitioned"})
        if previous["partitioned"] or not current["partitioned"]:
            fail(path, f"state {index} Cut did not enter a partition")
    elif action == "Heal":
        unchanged(path, index, previous, current, {"partitioned"})
        if not previous["partitioned"] or current["partitioned"]:
            fail(path, f"state {index} Heal did not restore connectivity")
    elif action == "Catchup":
        unchanged(path, index, previous, current, {"viewEpoch", "viewIssuedAt"})
        if previous["partitioned"] or current["viewEpoch"] != current["originEpoch"]:
            fail(path, f"state {index} Catchup did not converge a connected view")
        if current["viewIssuedAt"] != ROOT_ISSUED_AT_BASE + current["viewEpoch"]:
            fail(path, f"state {index} Catchup did not retain the final root timestamp")
    elif action == "Tick":
        unchanged(path, index, previous, current, {"localTime"})
        if current["localTime"] != previous["localTime"] + 1:
            fail(path, f"state {index} Tick did not advance local time")
    elif action == "EvaluateDeny":
        unchanged(path, index, previous, current, set())
        if previous["localTime"] < previous["viewIssuedAt"]:
            fail(path, f"state {index} EvaluateDeny has a future timestamp")
        age = previous["localTime"] - previous["viewIssuedAt"]
        if age <= previous["freshnessBound"]:
            fail(path, f"state {index} EvaluateDeny did not follow wall-clock staleness")
    else:
        fail(path, f"state {index} has unknown action {action!r}")

    if current["viewEpoch"] > current["originEpoch"]:
        fail(path, f"state {index} violates signer-pinned high-water monotonicity")
    if not current["allowFresh"]:
        fail(path, f"state {index} records an allow without fresh evidence")
    expected_view_issued_at = (
        0
        if current["viewEpoch"] == 0
        else ROOT_ISSUED_AT_BASE + current["viewEpoch"]
    )
    if current["viewIssuedAt"] != expected_view_issued_at:
        fail(path, f"state {index} does not bind the view to its signed root timestamp")


def validate(path: Path) -> list[dict[str, Any]]:
    states = load(path)
    actions = [state["action"] for state in states]
    if actions != EXPECTED_ACTIONS[path.name]:
        fail(path, f"unexpected action schedule: {actions}")
    initial = states[0]
    if initial["action"] != "Init":
        fail(path, "initial action must be Init")
    expected_initial = {name: 0 for name in NUMERIC - {"freshnessBound"}}
    if path.name == "wall-clock-stale-deny.itf.json":
        expected_initial.update(
            {
                "originEpoch": 1,
                "viewEpoch": 1,
                "localTime": ROOT_ISSUED_AT_BASE + 1,
                "viewIssuedAt": ROOT_ISSUED_AT_BASE + 1,
            }
        )
    for name, expected_value in expected_initial.items():
        if initial[name] != expected_value:
            fail(path, f"initial {name} must be {expected_value}")
    if initial["freshnessBound"] != 2 or not initial["allowFresh"]:
        fail(path, "initial freshness projection is invalid")
    if initial["partitioned"]:
        fail(path, "initial state must be connected")
    for index in range(1, len(states)):
        validate_step(path, index, states[index - 1], states[index])
    return states


def tla_value(value: Any) -> str:
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if type(value) is int:
        return str(value)
    if isinstance(value, str) and value in {
        "Init",
        "Tick",
        "Revoke",
        "QueueRoot",
        "Send",
        "Duplicate",
        "Lose",
        "Deliver",
        "InjectForged",
        "RejectForged",
        "Cut",
        "Heal",
        "Catchup",
        "EvaluateDeny",
    }:
        return f'"{value}"'
    raise ValueError(f"unsupported TLA value: {value!r}")


def write_tla_projection(
    trace_path: Path, states: list[dict[str, Any]], directory: Path
) -> Path:
    module_suffix = "".join(part.title() for part in trace_path.stem.split("-")).replace(
        ".", ""
    )
    module_name = f"Trace{module_suffix}"
    records = []
    for state in states:
        fields = ",\n            ".join(
            f"{name} |-> {tla_value(state[name])}" for name in VARIABLES
        )
        records.append(f"[\n            {fields}\n        ]")
    concrete_trace = ",\n        ".join(records)
    current_assignments = "\n".join(
        f"    /\\ {name} = ConcreteTrace[1].{name}" for name in VARIABLES
    )
    next_assignments = "\n".join(
        f"        /\\ {name}' = ConcreteTrace[step + 1].{name}" for name in VARIABLES
    )
    variable_vector = ", ".join(["step", *VARIABLES])
    trace_record_type = ", ".join(
        f"{name}: {VARIABLE_TYPES[name]}" for name in VARIABLES
    )
    source = f"""---------------- MODULE {module_name} ----------------
EXTENDS TraceCheckDistributedRevocation, Sequences

VARIABLES
    \\* @type: Int;
    step

traceVars == <<{variable_vector}>>

\\* @type: Seq({{{trace_record_type}}});
ConcreteTrace == <<
        {concrete_trace}
    >>

TraceInit ==
    /\\ step = 1
{current_assignments}

TraceNext ==
    \\/ /\\ step < Len(ConcreteTrace)
        /\\ step' = step + 1
{next_assignments}
        /\\ ProjectionStep
    \\/ /\\ step = Len(ConcreteTrace)
        /\\ UNCHANGED traceVars

TraceSafety ==
    /\\ step \\in 1..Len(ConcreteTrace)
    /\\ ProjectionSafety

=============================================================================
"""
    output = directory / f"{module_name}.tla"
    output.write_text(source, encoding="utf-8")
    return output


def main() -> None:
    if len(sys.argv) not in {2, 3}:
        raise SystemExit(
            "usage: validate-distributed-revocation-trace.py TRACE_DIR [TLA_DIR]"
        )
    directory = Path(sys.argv[1])
    tla_directory = Path(sys.argv[2]) if len(sys.argv) == 3 else None
    if tla_directory is not None:
        tla_directory.mkdir(parents=True, exist_ok=True)
    expected = set(EXPECTED_ACTIONS)
    actual = {path.name for path in directory.glob("*.itf.json")}
    if actual != expected:
        raise SystemExit(
            f"{directory}: expected traces {sorted(expected)}, found {sorted(actual)}"
        )
    generated = []
    for path in sorted(directory.glob("*.itf.json")):
        states = validate(path)
        if tla_directory is not None:
            generated.append(write_tla_projection(path, states, tla_directory))
    message = f"validated {len(expected)} distributed revocation ITF traces"
    if generated:
        message += f" and generated {len(generated)} exact TLA projections"
    print(message)


if __name__ == "__main__":
    main()
