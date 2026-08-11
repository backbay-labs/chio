"""Cross-SDK parity and negative vectors for finding bid ceilings."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, cast

import pytest

from chio_sdk.finding import (
    FindingBidCeilingError,
    FindingBidCeilingInput,
    finding_bid_ceiling,
)


def _vectors() -> list[dict[str, Any]]:
    path = (
        Path(__file__).resolve().parents[4]
        / "tests/bindings/fixtures/cognition-market-finding-bid-ceiling-v1.json"
    )
    return cast(list[dict[str, Any]], json.loads(path.read_text())["valid_cases"])


def _first() -> FindingBidCeilingInput:
    return cast(FindingBidCeilingInput, copy.deepcopy(_vectors()[0]["input"]))


def _rejects(input_value: FindingBidCeilingInput, code: str) -> None:
    with pytest.raises(FindingBidCeilingError) as caught:
        finding_bid_ceiling(input_value)
    assert caught.value.code == code


def test_finding_bid_ceiling_python_parity_matches_shared_rust_and_typescript_goldens() -> None:
    for vector in _vectors():
        input_value = cast(FindingBidCeilingInput, vector["input"])
        assert finding_bid_ceiling(input_value) == vector["expectedCeiling"], vector["id"]


def test_finding_bid_ceiling_accepts_decimal_strings_above_2_pow_53() -> None:
    vector = next(case for case in _vectors() if case["id"] == "above_javascript_safe_integer")
    assert (
        finding_bid_ceiling(cast(FindingBidCeilingInput, vector["input"]))
        == "9007199254740993"
    )


def test_finding_bid_ceiling_rejects_arithmetic_and_binding_negatives() -> None:
    for encoding in ["", "01", "+1", "-1", "1.0", "NaN", 1.5, True]:
        input_value = _first()
        input_value["estimate"]["units"] = cast(Any, encoding)
        _rejects(input_value, "invalid_decimal")

    overflow = _first()
    overflow["estimate"]["units"] = "18446744073709551616"
    _rejects(overflow, "u64_overflow")

    overlong = _first()
    overlong["estimate"]["units"] = "1" * 4_301
    _rejects(overlong, "invalid_decimal")

    bps = _first()
    bps["policy"]["wouldHaveRunBps"] = "10001"
    _rejects(bps, "basis_points_out_of_range")

    currency = _first()
    currency["policy"]["currency"] = "EUR"
    _rejects(currency, "currency_mismatch")

    provenance = _first()
    provenance["estimate"]["provenance"] = "operator_assertion_v1"
    _rejects(provenance, "provenance_unsupported")

    for malformed_provenance in [[], {"source": "buyer"}]:
        provenance = _first()
        cast(dict[str, Any], provenance["estimate"])["provenance"] = malformed_provenance
        _rejects(provenance, "provenance_unsupported")

    stale = _first()
    stale["nowUnixMs"] = stale["estimate"]["validUntilUnixMs"]
    _rejects(stale, "stale_estimate")

    source = _first()
    source["expectedSourceSha256"] = "0" * 64
    _rejects(source, "source_substituted")

    context = _first()
    context["expectedContextSha256"] = "0" * 64
    _rejects(context, "context_substituted")

    replay = _first()
    replay["expectedReplayRecipeSha256"] = "0" * 64
    _rejects(replay, "replay_recipe_substituted")


def test_finding_bid_ceiling_wraps_malformed_string_field_types() -> None:
    for section, field in [
        ("estimate", "currency"),
        ("policy", "currency"),
        ("estimate", "sourceSha256"),
        ("estimate", "contextSha256"),
        ("estimate", "replayRecipeSha256"),
    ]:
        input_value = _first()
        cast(dict[str, Any], input_value[section])[field] = 7
        _rejects(
            input_value,
            "currency_mismatch" if field == "currency" else "digest_malformed",
        )

    for field in [
        "expectedSourceSha256",
        "expectedContextSha256",
        "expectedReplayRecipeSha256",
    ]:
        input_value = _first()
        cast(dict[str, Any], input_value)[field] = None
        _rejects(input_value, "digest_malformed")
