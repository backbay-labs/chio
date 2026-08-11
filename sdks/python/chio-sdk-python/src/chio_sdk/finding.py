"""Buyer-local cognition-market helpers."""

from __future__ import annotations

import re
from typing import Literal, TypedDict

DecimalIntegerInput = str | int
FindingEstimateProvenance = Literal[
    "buyer_metering_history_v1",
    "buyer_fresh_metered_quote_v1",
]

_U64_MAX = 18_446_744_073_709_551_615
_BPS = 10_000
_BPS_DENOMINATOR = _BPS * _BPS * _BPS
_DECIMAL = re.compile(r"^(0|[1-9][0-9]*)$")
_CURRENCY = re.compile(r"^[A-Z0-9]{1,16}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class BuyerFindingEstimate(TypedDict):
    """Caller-carried buyer estimate, not an authenticated quote artifact."""

    units: DecimalIntegerInput
    currency: str
    provenance: FindingEstimateProvenance | str
    sourceSha256: str
    contextSha256: str
    replayRecipeSha256: str
    observedAtUnixMs: DecimalIntegerInput
    validUntilUnixMs: DecimalIntegerInput


class FindingBidCeilingPolicy(TypedDict):
    """Buyer-owned discount and remaining-budget policy."""

    budgetRemainingUnits: DecimalIntegerInput
    currency: str
    wouldHaveRunBps: DecimalIntegerInput
    siblingRedundancyBps: DecimalIntegerInput
    guaranteeClassBps: DecimalIntegerInput


class FindingBidCeilingInput(TypedDict):
    """Complete input to :func:`finding_bid_ceiling`."""

    estimate: BuyerFindingEstimate
    policy: FindingBidCeilingPolicy
    expectedSourceSha256: str
    expectedContextSha256: str
    expectedReplayRecipeSha256: str
    nowUnixMs: DecimalIntegerInput


class FindingBidCeilingError(ValueError):
    """Fail-closed bid-ceiling validation error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def finding_bid_ceiling(input_value: FindingBidCeilingInput) -> str:
    """Compute an exact buyer-local finding bid ceiling.

    The helper does not authenticate a quote producer or the truth of an
    estimate. It binds one caller-carried estimate to the buyer's expected
    source, context, replay recipe, currency, and validity window. Arithmetic
    uses Python integers, rounds down once after the combined basis-point
    product, and caps the result by the buyer's remaining budget.
    """

    estimate_input = input_value["estimate"]
    policy = input_value["policy"]
    _validate_currency(estimate_input["currency"])
    _validate_currency(policy["currency"])
    if estimate_input["currency"] != policy["currency"]:
        _fail("currency_mismatch", "estimate and budget currencies differ")
    provenance = estimate_input["provenance"]
    if not isinstance(provenance, str) or provenance not in {
        "buyer_metering_history_v1",
        "buyer_fresh_metered_quote_v1",
    }:
        _fail("provenance_unsupported", "buyer estimate provenance is not supported")

    _validate_digest(estimate_input["sourceSha256"], "estimate.sourceSha256")
    _validate_digest(estimate_input["contextSha256"], "estimate.contextSha256")
    _validate_digest(
        estimate_input["replayRecipeSha256"], "estimate.replayRecipeSha256"
    )
    _validate_digest(input_value["expectedSourceSha256"], "expectedSourceSha256")
    _validate_digest(input_value["expectedContextSha256"], "expectedContextSha256")
    _validate_digest(
        input_value["expectedReplayRecipeSha256"], "expectedReplayRecipeSha256"
    )
    if estimate_input["sourceSha256"] != input_value["expectedSourceSha256"]:
        _fail("source_substituted", "buyer estimate source digest was substituted")
    if estimate_input["contextSha256"] != input_value["expectedContextSha256"]:
        _fail("context_substituted", "buyer estimate context digest was substituted")
    if (
        estimate_input["replayRecipeSha256"]
        != input_value["expectedReplayRecipeSha256"]
    ):
        _fail(
            "replay_recipe_substituted",
            "buyer estimate replay-recipe digest was substituted",
        )

    estimate = _parse_u64(estimate_input["units"], "estimate.units")
    budget = _parse_u64(
        policy["budgetRemainingUnits"], "policy.budgetRemainingUnits"
    )
    would_run = _parse_bps(policy["wouldHaveRunBps"], "policy.wouldHaveRunBps")
    redundancy = _parse_bps(
        policy["siblingRedundancyBps"], "policy.siblingRedundancyBps"
    )
    guarantee = _parse_bps(
        policy["guaranteeClassBps"], "policy.guaranteeClassBps"
    )
    observed = _parse_u64(
        estimate_input["observedAtUnixMs"], "estimate.observedAtUnixMs"
    )
    valid_until = _parse_u64(
        estimate_input["validUntilUnixMs"], "estimate.validUntilUnixMs"
    )
    now = _parse_u64(input_value["nowUnixMs"], "nowUnixMs")
    if observed >= valid_until:
        _fail("invalid_validity_window", "buyer estimate validity window is invalid")
    if now < observed or now >= valid_until:
        _fail("stale_estimate", "buyer estimate is not live at the supplied clock")

    discounted = (
        estimate * would_run * (_BPS - redundancy) * guarantee // _BPS_DENOMINATOR
    )
    return str(min(discounted, budget))


def _parse_bps(value: DecimalIntegerInput, field: str) -> int:
    parsed = _parse_u64(value, field)
    if parsed > _BPS:
        _fail("basis_points_out_of_range", f"{field} basis points exceed 10000")
    return parsed


def _parse_u64(value: DecimalIntegerInput, field: str) -> int:
    if isinstance(value, bool):
        _fail("invalid_decimal", f"{field} must not be a boolean")
    if isinstance(value, int):
        if value < 0:
            _fail("invalid_decimal", f"{field} must be nonnegative")
        parsed = value
    elif isinstance(value, str) and _DECIMAL.fullmatch(value):
        parsed = int(value)
    else:
        _fail(
            "invalid_decimal",
            f"{field} must be a canonical unsigned decimal-string integer",
        )
    if parsed > _U64_MAX:
        _fail("u64_overflow", f"{field} exceeds the Rust u64 boundary")
    return parsed


def _validate_currency(value: str) -> None:
    if not isinstance(value, str) or not _CURRENCY.fullmatch(value):
        _fail(
            "currency_mismatch",
            "currency must be 1 to 16 uppercase ASCII letters or digits",
        )


def _validate_digest(value: str, field: str) -> None:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        _fail("digest_malformed", f"{field} must be canonical lowercase 64-hex")


def _fail(code: str, message: str) -> None:
    raise FindingBidCeilingError(code, message)
