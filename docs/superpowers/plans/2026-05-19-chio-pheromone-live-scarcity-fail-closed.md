# Chio pheromone live scarcity fail-closed

## Objective

Remove live no-policy scarcity compatibility from the pheromone substrate.
Live receive and live substrate admission must reject missing
`scarcityPolicies` with `scarcity_policy_missing`; explicit scarcity policy
material is required for accepted deposits.

## Plan

1. Add a failing substrate regression for a signed live deposit with an empty
   `PheromoneValidationContext.scarcity_policies`.
2. Replace `compatibility_scarcity_admissions` in the live admission path with
   `ScarcityPolicyMissing`.
3. Update substrate tests that still model live deposits with empty scarcity
   context to use explicit scarcity policies.
4. Keep runtime policy loader tests proving missing or empty `scarcityPolicies`
   fail before live receive.
5. Run focused pheromone substrate/runtime tests, clippy, formatting,
   whitespace, dash scan, and status.

## Verification

- [x] `cargo test -p chio-pheromone live_deposit_without_scarcity_policy_is_rejected --test pheromone_substrate` fails before implementation.
- [x] `cargo test -p chio-pheromone live_deposit_without_scarcity_policy_is_rejected --test pheromone_substrate`
- [x] `cargo test -p chio-pheromone --test pheromone_substrate`
- [x] `cargo test -p chio-pheromone-runtime --test runtime_receiver`
- [x] `cargo clippy -p chio-pheromone --all-targets -- -D warnings`
- [x] `cargo clippy -p chio-pheromone-runtime --all-targets -- -D warnings`
- [x] `bash scripts/check-chio-pheromone-runtime.sh --schema-only`
- [x] `cargo fmt --all -- --check`
- [x] `git diff --check`
- [x] Unicode dash scan over changed files.
