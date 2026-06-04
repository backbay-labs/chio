# chio-autonomy Architecture

## Boundary

`chio-autonomy` owns bounded autonomous pricing, capital optimization, execution, rollback, drift, comparison, and qualification contracts. It ties core monetary amounts, market liability classes, and web3 settlement states into one evidence-referential automation layer.

## Internal Surfaces

The crate is intentionally data-contract heavy: public structs model wire artifacts and validator functions enforce schema ids, required references, authority envelopes, safety gates, rollback coverage, and fail-safe drift behavior.

## Trust Invariants

The core security constraint is bounded execution. A validated artifact must not smuggle broader authority through malformed amounts, loose references, mismatched currencies, or unchecked automation modes.

## Dependent Surfaces

`chio-market`, `chio-credit`, and `chio-settle` consume these artifacts as automation evidence. They rely on this crate to keep monetary fields canonical, rollback coverage explicit, and qualification references stable before any pricing or settlement workflow treats an autonomous recommendation as executable.

## Verification Focus

Tests should cover declared and nested monetary amounts, missing rollback coverage, stale qualification references, unsafe automation modes, and validator rejection before downstream settlement state changes.

## Improvement Target

Planned improvement: make currency validation exact for declared and nested monetary amounts so canonical artifacts cannot differ only by lowercase or padded currency strings.
