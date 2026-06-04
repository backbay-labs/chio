# chio-pheromone Architecture

## Boundary

`chio-pheromone` owns Chio's local pheromone signal contracts: signed deposits, concentration queries, scarcity policies, observation-cost commitments, runtime verifier trust roots, workflow context bindings, and in-memory substrate behavior. Runtime receipt handling and relay transport live in `chio-pheromone-runtime` and `chio-pheromone-relay`.

## Internal Surfaces

The crate validates static deposit material, passport identity binding, signature provenance, treaty scope, replay windows, scarcity admission, observation-cost Merkle inclusion, verifier-root trust, and concentration decay. It also exposes deterministic hashes for scarcity policy and window identifiers.

## Trust Invariants

The security constraint is receiver-owned admission accounting. A deposit must consume exactly the scarcity buckets implied by unique accepted treaties, with no replay, kernel-key signing, untrusted verifier root, stale policy, or malformed cost evidence admitted into the local substrate.

## Verification Focus

Tests should cover duplicate treaty scopes, replay windows, verifier-root rejection, policy freshness, cost Merkle inclusion, scarcity-bucket accounting, and deterministic concentration decay. Runtime and relay tests should keep signed local substrate admission separate from transport delivery so a forwarded signal cannot bypass receiver-owned scarcity policy.

## Improvement Target

Planned improvement: reject duplicate treaty scope entries on deposits and scarcity policies so a single signed signal cannot double-count the same treaty bucket. The check belongs beside deposit and policy validation because downstream concentration queries should only observe already-canonical bucket membership.
