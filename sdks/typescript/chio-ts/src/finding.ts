/** Buyer-local cognition-market helpers. */

const U64_MAX = 18_446_744_073_709_551_615n;
const BPS = 10_000n;
const BPS_DENOMINATOR = BPS * BPS * BPS;

export type DecimalIntegerInput = string | number;

export type FindingEstimateProvenance =
  | "buyer_metering_history_v1"
  | "buyer_fresh_metered_quote_v1";

export interface BuyerFindingEstimate {
  units: DecimalIntegerInput;
  currency: string;
  provenance: FindingEstimateProvenance | string;
  sourceSha256: string;
  contextSha256: string;
  replayRecipeSha256: string;
  observedAtUnixMs: DecimalIntegerInput;
  validUntilUnixMs: DecimalIntegerInput;
}

export interface FindingBidCeilingPolicy {
  budgetRemainingUnits: DecimalIntegerInput;
  currency: string;
  wouldHaveRunBps: DecimalIntegerInput;
  siblingRedundancyBps: DecimalIntegerInput;
  guaranteeClassBps: DecimalIntegerInput;
}

export interface FindingBidCeilingInput {
  estimate: BuyerFindingEstimate;
  policy: FindingBidCeilingPolicy;
  expectedSourceSha256: string;
  expectedContextSha256: string;
  expectedReplayRecipeSha256: string;
  nowUnixMs: DecimalIntegerInput;
}

export type FindingBidCeilingErrorCode =
  | "invalid_decimal"
  | "u64_overflow"
  | "basis_points_out_of_range"
  | "currency_mismatch"
  | "provenance_unsupported"
  | "source_substituted"
  | "context_substituted"
  | "replay_recipe_substituted"
  | "digest_malformed"
  | "invalid_validity_window"
  | "stale_estimate";

export class FindingBidCeilingError extends Error {
  readonly code: FindingBidCeilingErrorCode;

  constructor(code: FindingBidCeilingErrorCode, message: string) {
    super(message);
    this.name = "FindingBidCeilingError";
    this.code = code;
  }
}

/**
 * Compute a buyer-local finding bid ceiling using exact integer arithmetic.
 *
 * This helper does not authenticate a quote producer or the truth of an
 * estimate. It only binds the caller-carried estimate to the buyer's expected
 * source, context, replay recipe, currency, and validity window. Arithmetic is
 * performed with BigInt, rounded down once after the combined basis-point
 * product, and capped by the buyer's remaining budget.
 */
export function findingBidCeiling(input: FindingBidCeilingInput): string {
  validateCurrency(input.estimate.currency);
  validateCurrency(input.policy.currency);
  if (input.estimate.currency !== input.policy.currency) {
    fail("currency_mismatch", "estimate and budget currencies differ");
  }
  if (
    input.estimate.provenance !== "buyer_metering_history_v1"
    && input.estimate.provenance !== "buyer_fresh_metered_quote_v1"
  ) {
    fail("provenance_unsupported", "buyer estimate provenance is not supported");
  }
  validateDigest(input.estimate.sourceSha256, "estimate.sourceSha256");
  validateDigest(input.estimate.contextSha256, "estimate.contextSha256");
  validateDigest(input.estimate.replayRecipeSha256, "estimate.replayRecipeSha256");
  validateDigest(input.expectedSourceSha256, "expectedSourceSha256");
  validateDigest(input.expectedContextSha256, "expectedContextSha256");
  validateDigest(input.expectedReplayRecipeSha256, "expectedReplayRecipeSha256");
  if (input.estimate.sourceSha256 !== input.expectedSourceSha256) {
    fail("source_substituted", "buyer estimate source digest was substituted");
  }
  if (input.estimate.contextSha256 !== input.expectedContextSha256) {
    fail("context_substituted", "buyer estimate context digest was substituted");
  }
  if (input.estimate.replayRecipeSha256 !== input.expectedReplayRecipeSha256) {
    fail("replay_recipe_substituted", "buyer estimate replay-recipe digest was substituted");
  }

  const estimate = parseU64(input.estimate.units, "estimate.units");
  const budget = parseU64(input.policy.budgetRemainingUnits, "policy.budgetRemainingUnits");
  const wouldRun = parseBps(input.policy.wouldHaveRunBps, "policy.wouldHaveRunBps");
  const redundancy = parseBps(
    input.policy.siblingRedundancyBps,
    "policy.siblingRedundancyBps",
  );
  const guarantee = parseBps(input.policy.guaranteeClassBps, "policy.guaranteeClassBps");
  const observed = parseU64(input.estimate.observedAtUnixMs, "estimate.observedAtUnixMs");
  const validUntil = parseU64(input.estimate.validUntilUnixMs, "estimate.validUntilUnixMs");
  const now = parseU64(input.nowUnixMs, "nowUnixMs");
  if (observed >= validUntil) {
    fail("invalid_validity_window", "buyer estimate validity window is invalid");
  }
  if (now < observed || now >= validUntil) {
    fail("stale_estimate", "buyer estimate is not live at the supplied clock");
  }

  const discounted = estimate
    * wouldRun
    * (BPS - redundancy)
    * guarantee
    / BPS_DENOMINATOR;
  return (discounted < budget ? discounted : budget).toString();
}

function parseBps(value: DecimalIntegerInput, field: string): bigint {
  const parsed = parseU64(value, field);
  if (parsed > BPS) {
    fail("basis_points_out_of_range", `${field} basis points exceed 10000`);
  }
  return parsed;
}

function parseU64(value: DecimalIntegerInput, field: string): bigint {
  let canonical: string;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      fail(
        "invalid_decimal",
        `${field} Number input must be a nonnegative JavaScript safe integer`,
      );
    }
    canonical = String(value);
  } else {
    canonical = value;
  }
  if (!/^(0|[1-9][0-9]*)$/.test(canonical)) {
    fail("invalid_decimal", `${field} must be a canonical unsigned decimal-string integer`);
  }
  const parsed = BigInt(canonical);
  if (parsed > U64_MAX) {
    fail("u64_overflow", `${field} exceeds the Rust u64 boundary`);
  }
  return parsed;
}

function validateCurrency(value: string): void {
  if (!/^[A-Z0-9]{1,16}$/.test(value)) {
    fail("currency_mismatch", "currency must be 1 to 16 uppercase ASCII letters or digits");
  }
}

function validateDigest(value: string, field: string): void {
  if (!/^[0-9a-f]{64}$/.test(value)) {
    fail("digest_malformed", `${field} must be canonical lowercase 64-hex`);
  }
}

function fail(code: FindingBidCeilingErrorCode, message: string): never {
  throw new FindingBidCeilingError(code, message);
}
