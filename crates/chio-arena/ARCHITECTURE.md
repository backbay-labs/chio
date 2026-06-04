# chio-arena Architecture

## Boundary

`chio-arena` owns deterministic Chio scenario execution and replay-bundle production. It parses arena scenario TOML, validates deterministic witness material, schedules scenario steps, runs agent/kernel bindings, writes promotion bundles, renders leaderboard output, and supports adversary population coevolution.

## Internal Surfaces

The crate is organized around scenario parsing, deterministic scheduling, virtual clocks and RNG, runtime execution, link routing, promotion outputs, adversary scaffolds, and coevolution helpers. Scenario validation is the boundary that keeps replay fixtures deterministic, provider-independent, and free of inline secrets before runtime execution starts.

## Trust Invariants

The security constraint is deterministic replay integrity. Scenario ids, agents, steps, guards, budgets, scheduler settings, locale, virtual clock, and RNG seed must be canonical enough that replay bundles can be reproduced and compared without hidden provider or ordering drift. Runtime execution must not reinterpret scenario material after validation in a way that changes replay identity.

## Verification Focus

Tests should cover duplicate ids, missing deterministic witness material, virtual clock and RNG stability, promotion-bundle reproducibility, and fail-closed parsing of provider-specific scenario fields.

## Improvement Target

Planned improvement: reject duplicate guard ids during scenario parsing so guard configuration and enforcement references cannot become ambiguous.
