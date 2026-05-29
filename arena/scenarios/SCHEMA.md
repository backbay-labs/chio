# Chio Arena Scenario Schema

Schema id: `chio.arena.scenario/v1`

Arena scenarios are deterministic TOML inputs for `chio-arena`. The v1
schema is intentionally small: it describes the replay witness, offline agent
population, and a stable list of tool-call steps. Runtime code must reject
unknown top-level tables and unknown major schema versions, except for the
reserved `[ext]` table.

## Required Top-Level Fields

```toml
schema_version = "chio.arena.scenario/v1"
id = "walking_skeleton"
title = "Single-agent walking skeleton"
rng_seed = 42
virtual_clock_start = "2026-04-30T00:00:00.000Z"
```

- `schema_version`: must be the literal `chio.arena.scenario/v1`.
- `id`: stable lowercase scenario id. Use ASCII letters, digits, `_`, `.`,
  and `-`.
- `title`: operator-readable scenario title.
- `rng_seed`: unsigned 64-bit seed for deterministic PRNG state.
- `virtual_clock_start`: fixed RFC3339 UTC timestamp. Arena runs must not
  read wall-clock time for receipt bytes.

## Determinism Witness

The required `[determinism]` table records the replay witness extracted by
the parser.

```toml
[determinism]
rng_seed = 42
virtual_clock_start = "2026-04-30T00:00:00.000Z"
scheduler = "single-agent-v1"
locale = "C"
```

The top-level `rng_seed` and `virtual_clock_start` mirror this table for
operator scanning. The parser validates that both copies match.

## Agents

Agents are offline deterministic actors. Model names are string handles only;
they must not imply a provider SDK dependency.

```toml
[[agents]]
id = "agent-a"
role = "operator"
model = "recorded:test-agent"
seed_prompt_ref = "prompts/walking-skeleton.txt"
```

Inline secrets are forbidden. Store prompt material by reference.

## Capability Budgets

Budgets are declarative constraints used by later phases when issuing
capabilities. P1 records them in the determinism witness and runtime manifest.

```toml
[[budgets]]
agent = "agent-a"
server = "filesystem"
tool = "read_file"
max_invocations = 1
```

## Guards

Guard entries are stable ids and configuration references. The scenario DSL
does not embed guard code.

```toml
[[guards]]
id = "native-allowlist"
mode = "enforce"
config_ref = "guards/native-allowlist.toml"
```

## Steps

P1 supports a single-agent ordered step list. Later phases add multi-agent
scheduling without changing the required witness fields.

```toml
[[steps]]
id = "step-1"
agent = "agent-a"
server = "filesystem"
tool = "read_file"
arguments = { path = "/tmp/chio-arena.txt" }
expect_verdict = "allow"
```

`expect_verdict` is one of `allow`, `deny`, or `rewrite`. The runtime records
actual verdicts in `arena.json`.

## Adversaries

Adversary blocks are metadata in the scenario file and become executable
populations when the arena runtime is active. Each `[[adversary]]` entry
(a TOML array-of-tables under the `adversaries` key) describes one population
the runtime instantiates for the scenario.

```toml
[[adversaries]]
class = "walking-skeleton"
population = "none"
seed_ref = "none"
```

### Adversary classes

The arena ships four canonical adversary classes. Each `[[adversary]]` entry
selects one class via the `class` field, names the population through
`population`, and forwards an optional `params` table to the class constructor.

| Class                  | Class id                  | Required params  |
|------------------------|---------------------------|------------------|
| Prompt injection       | `prompt-injection`        | none             |
| Capability overrequest | `capability-overrequest`  | none             |
| Replay attempt         | `replay-attempt`          | `nonce` (string) |
| Scope-superset escape  | `scope-escape`            | none             |

Optional parameter overrides per class are documented on the corresponding
Rust modules under `crates/chio-arena/src/adversary/` (for example,
`patterns` for `prompt-injection` and `replay-attempt`, `variants` for
`capability-overrequest`, and `escalations` for `scope-escape`). Reference
TOML examples for every class live under `arena/scenarios/adversary/`.

Inline secret markers (api keys, bearer tokens, private key blobs) are
forbidden inside `params`; the parser fails closed on any match against the
secret marker list.

```toml
[[adversaries]]
class = "prompt-injection"
population = "default-injection"
seed_ref = "fuzz/artifacts/prompt-injection"
[adversaries.params]
patterns = ["ignore-previous-instructions", "tool-name-spoof"]
```

Note: TOML only recognises the plural array-of-tables form `[[adversaries]]`.
Some documentation tooling greps for the singular `[[adversary]]` token to
locate this section; that is a documentation convention only, never a
scenario file syntax.

## Extension Table

The `[ext]` table is reserved for forward-compatible tool metadata. Unknown
keys outside `[ext]` fail closed.

```toml
[ext]
owner = "team-alpha"
```
