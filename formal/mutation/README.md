# Formal Mutation Evidence

`registry.toml` is the coverage-map input for mutation sensitivity. Each
target names one scheduled lane, its generated report, the represented Rust
paths, and the activation target. The proof coverage generator validates the
paths and applies conservative primary-surface attribution.

The reports are runtime artifacts:

- `target/formal/spec-mutants-report.json`
- `target/formal/proof-mutants/outcomes.json`

A full-cycle result may be promoted into a target's `latest_full_cycle` table
only when the report covers every enumerated mutant. Preserve the exact report
below `formal/mutation/evidence/` and record its SHA-256, commit, UTC completion
time, all four verdict counts, and timeout-aware activation ratio. The proof
coverage generator parses that evidence and requires the expected report
schema, a clean worktree, `full_cycle = true`, a source hash for the target,
the current target source represented in the mutant inventory, matching
per-mutant and aggregate counts, and an exact report hash. The report input set
must equal the complete expected set for its lane. Every recorded input must be
a non-symlink regular file below the repository root and its recorded SHA-256
must match both the current file and the regular file stored in the report's
ancestor commit. A tree object, unrelated commit, missing history, or changed
input rejects promotion. The retained evidence JSON must itself be a
non-symlink regular repository file. The canonical full-inventory digest and
normalized pinned tool versions must match the protected registry ratchets.

The specification lane binds the allowlist, every registered source and CFG,
all sibling TLA+ modules in their source directories, the complete negative
registry with its models, CFGs, sibling TLA+ modules, and runtime test files,
`formal/MAPPING.md`, the mutator, the negative runner, and the shared evidence
parser. The proof lane binds the workspace and kernel-core/core-types Cargo
manifests, `Cargo.lock`, `.cargo/config.toml`, the mutation config, toolchain
pin, runner and oracle scripts (including the scheduled
`scripts/proof-mutants.sh` entrypoint), and
every Rust source below both compiled local crate `src` trees.
Each registry target still requires mutants attributed to that target's own
source even though the promoted full-cycle report binds the complete lane.
Hand-entered counts or subset-only input inventories fail closed.

Specification reports must also contain exactly one positive baseline for
every allowlisted model. Each baseline must repeat the registered source, CFG,
invariant, and bound, record exit 0 and `survived`, and include a finite wall
time and lowercase log hash. Clean models use the safety lane's 10,800-second
budget while generated mutants retain a 300-second limit. The producer runs
these unmodified models before the registered-negative preflight and generated
mutants. Missing, duplicated, failing, or mismatched baseline evidence rejects
both lane scoring and full-cycle promotion.

For a specification target, the `latest_full_cycle` verdict counts and
activation ratio are copied from that target's source aggregate, not from the
global aggregate. The validator recomputes every source aggregate from mutant
verdicts, requires its exact source set, counts, denominator, ratios, target,
and activation result, and rejects any unviable mutant or source below target.
Proof-target observations use the aggregate for their own Rust model file.
The validator recomputes both per-file aggregates and the global aggregate,
requires at least 90 percent activation and 80 percent viable mutants for each,
and rejects contradictory declared results. This source-scoped interpretation
does not change the registry or report schema.

The specification allowlist uses schema
`chio.spec-mutants-allowlist.v1`. It contains 31 exact curated type-valid
probes plus two mandatory registered historical seeds across seven sources.
Edits are restricted to classified `guard-weakening` and
`post-state-corruption` matches in named reachable actions. Deterministic
samples always include both seeds and at least one probe per source. A TLA+
parser or type error is a fail-closed execution error, not an excluded
`unviable` result, and a timeout counts as not killed. Promotion requires the
clean full 33-probe campaign, zero unviable results, and at least 90 percent
activation globally and separately for every source aggregate.

The following count values illustrate a target whose own source has four
mutants. The report may contain additional sources, but their counts are not
copied into this target's observation.

```toml
[target.latest_full_cycle]
commit = "<40 lowercase hex>"
measured_at = "2026-07-10T12:00:00Z"
evidence = "formal/mutation/evidence/<report>.json"
report_sha256 = "<64 lowercase hex>"
enumerated = 4
killed = 4
survived = 0
unviable = 0
timeout = 0
activation_ratio_percent = 100.0
```

Until such a table exists, generated coverage marks the target as
`measurement=pending`. Pending metadata is not a successful mutation result
and does not support a verification claim.

The registry's `historical_evidence` list preserves older campaign reports for
audit only. The proof-coverage generator hashes every listed file, but does not
promote it to a measurement or verification claim. A report becomes current
evidence only through a validated `latest_full_cycle` table whose complete
input inventory matches the worktree.
