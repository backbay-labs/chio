# chio-underwriting Architecture

## Boundary

`chio-underwriting` owns underwriting policy input, decision, simulation, appeal, premium pricing, and marketplace credit-limit contracts. It consumes Chio receipt, appraisal, runtime-assurance, reputation, certification, and settlement evidence without depending on the kernel.

## Internal Surfaces

The main crate models underwriting artifacts and evaluator logic. `premium` owns deterministic premium pricing and fail-closed input validation. `marketplace_limits` owns the reputation-tiered credit-limit helper consumed by market and credit surfaces.

## Trust Invariants

The security constraint is that malformed evidence or pricing inputs must not silently produce broader economic authority. Invalid policies, stale or weak evidence, bad premium configuration, and revoked publisher state must deny, step up, or withhold instead of approving.

## Dependent Surfaces

`chio-market`, `chio-credit`, `chio-appraisal`, and settlement planning code use underwriting outcomes as economic authority inputs. The crate therefore has to distinguish deterministic pricing, appeal handling, and evidence freshness before downstream crates convert a decision into limits, premiums, or settlement exposure.

## Verification Focus

Tests should cover stale evidence, revoked publisher state, appeal paths, malformed policy inputs, non-finite premium thresholds, reputation-tier limits, and deterministic simulation output.

## Improvement Target

Planned improvement: reject non-finite behavioral premium thresholds so anomaly penalties cannot be disabled through an invalid floating-point configuration.
