# Swarm Authority And Recursive Delegation

Status: architecture outline
Primary source: `../agent-drafts/03-swarm-authority-recursive-delegation.md`
Confidence: high for gap diagnosis, moderate for implementation boundaries.

## Problem

Recursive delegation is the hardest part of the homepage copy. A normal receipt proves one mediated call. A multi-swarm transaction needs proof that every child action was inside a bounded parent authority graph.

The missing artifact is a signed swarm authority contract.

## Core Artifacts

### Swarm Task Graph

`chio.swarm.task-graph.v1` is a signed planning and authority manifest. It does not execute. It defines what may execute.

Fields:

- `graph_id`
- `root_transaction_ref`
- `planner_subject`
- `issuer`
- `created_at`
- `expires_at`
- `max_depth`
- `max_fanout`
- `nodes`
- `edges`
- `joins`
- `budget_pool_ref`
- `revocation_epoch_ref`
- `route_plan_refs`
- `signature`

### Swarm Continuation Token

`chio.swarm.continuation-token.v1` is the portable child-execution authority context.

It binds:

- child task id;
- parent task id or join receipt id;
- parent receipt set;
- graph digest;
- route-plan receipt;
- budget allocation;
- revocation epoch;
- session anchor;
- expiry;
- nonce;
- single-use or resumable mode.

### Delegation Witness Chain

`chio.swarm.delegation-witness-chain.v1` proves parent-to-child attenuation.

Each hop includes:

- parent capability digest;
- child capability digest;
- attenuation rule id;
- scope subset proof;
- expiry comparison;
- issuer/key proof;
- policy digest;
- witness signature.

### Swarm Join Receipt

`chio.swarm.join-receipt.v1` handles fan-in. It is the parent receipt for the next task when multiple upstream tasks join.

It binds:

- join id;
- graph id;
- expected parent set;
- actual parent receipt set;
- join predicate;
- result digest;
- next task id;
- signature.

### Route-Plan Receipt

`chio.swarm.route-plan-receipt.v1` promotes route selection from metadata to authority.

It binds:

- selected route;
- candidate set digest;
- registry snapshot hash;
- bridge id;
- protocol target;
- egress constraints;
- attenuation decision;
- policy digest;
- expiry;
- signature.

## Dispatch Rule

Every child execution path must verify:

1. task is in the signed graph;
2. continuation token is fresh;
3. parent receipt or join receipt is valid;
4. per-hop attenuation witness is valid;
5. route-plan receipt matches selected target;
6. revocation epoch is current;
7. budget allocation is live;
8. graph depth, fanout, and join rules are satisfied.

If metadata and route-plan receipt disagree, dispatch rejects.

## Budget Pools

`chio.swarm.budget-pool.v1` adds graph-level allocation over existing budget primitives.

It should support:

- total budget;
- per-node max;
- per-edge reserve;
- fan-out reservation;
- fan-in release;
- failed-branch release;
- single-use budget leases;
- proof of remaining allocation.

## Revocation Epoch

Continuation tokens must bind a revocation epoch root. A token minted under one epoch cannot be silently resumed after a new incompatible epoch.

Verifier outcomes:

- same epoch and same root: valid if other checks pass;
- newer epoch and ancestor still valid: policy-controlled;
- newer epoch with revoked leaf or ancestor: fail;
- same epoch id with different root: fail.

## Negative Cases

- multi-hop child scope not subset of parent;
- child token reused after side-effecting call;
- route-plan receipt for different protocol target;
- deferred task resume with stale revocation epoch;
- fan-in join missing one parent receipt;
- graph cycle;
- graph exceeds max depth;
- budget allocation double-spent.
