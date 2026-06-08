# Phase 1b (xtask clap conversion) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Convert the `xtask` crate from its hand-rolled `match cmd.as_str()` dispatcher to a `clap` derive CLI with the noun-verb subcommand tree, preserving every existing invocation byte-for-byte via aliases (a pure refactor, parity-proven).

**Architecture:** A new `cli.rs` module defines `#[derive(Parser)] Cli` plus nested `#[derive(Subcommand)]` enums that mirror the SIX existing leaf commands and introduce the nine empty-for-now noun-group parents (gen/check/qualify/verify/fuzz/mutants/release/supply-chain/tools). `main.rs` keeps every existing handler function unchanged and only swaps its dispatch front-end: instead of reading `env::args()` by hand it calls `Cli::parse()` and matches on the typed enum, routing each leaf to the identical handler that exists today. The `check-crate-paths` subcommand (shipped by the keystone plan) is re-spelled `check crate-paths` and its one CI call site is updated.

**Tech Stack:** Rust (edition 2021, MSRV 1.93), `clap` 4 with the `derive` feature (already cargo-vet-exempt and deny-skip-listed at 4.6.0), the existing `xtask` crate, GitHub Actions YAML, the Makefile.

---

## Dependency decision (resolved with evidence)

`clap` is NOT in the root `[workspace.dependencies]` table. Evidence:
- `grep -n "clap" Cargo.toml` (root) returns nothing.
- Five crates pin it directly, all as `clap = { version = "4", features = [...] }`:
  `crates/chio-cli/Cargo.toml:69` (`["derive", "env"]`),
  `crates/chio-control-plane/Cargo.toml:41` (`["derive"]`),
  `crates/chio-wall/Cargo.toml:29` (`["derive"]`),
  `crates/chio-mercury/Cargo.toml:24` (`["derive"]`),
  `crates/chio-provider-conformance/Cargo.toml:24` (`["derive"]`).
  (`chio-kernel-core` only references clap in a comment at
  `crates/chio-kernel-core/Cargo.toml:68`, not as a dependency.)

So the spec's prose ("clap is already a vetted workspace dep") is loose; the
accurate, wave-2-style statement is: clap is an already-vetted *direct* dependency
pinned `version = "4"` in five crates, resolving to `clap 4.6.0` in `Cargo.lock`.
This plan therefore adds `clap = { version = "4", features = ["derive"] }` to
`xtask/Cargo.toml` using the SAME pin the five crates use (NOT a promotion to
`[workspace.dependencies]`; that centralization is Phase 2's job and is out of
scope here).

Supply-chain implication (cite
`docs/superpowers/research/migration-validation-rootconfig-supplychain.md`):
because the resolved versions already carry cargo-vet exemptions and a cargo-deny
duplicate-skip entry, adding clap to one more member introduces NO new crate
version into the graph and so needs NO new vet exemption or deny edit. Verified:
- `supply-chain/config.toml:925-941` exempts `clap 2.34.0`, `clap 4.6.0`,
  `clap_builder 4.6.0`, `clap_derive 4.6.0`, `clap_lex 1.1.0` (all
  `criteria = "safe-to-deploy"`).
- `deny.toml:382` has `[[bans.skip]] name = "clap"` (covers the clap 2 vs clap 4
  duplicate the workspace already tolerates).
Task 1 Step 4 explicitly re-runs the lock check to confirm no new version appears.

---

## Dependency on the keystone plan

This plan executes AFTER
`docs/superpowers/plans/2026-06-08-phase-1-crate-paths-guard.md` has landed. That
plan ships `xtask/src/crate_paths.rs` with `pub fn run(args: Vec<String>)`, wires a
`"check-crate-paths"` arm into the hand-rolled dispatcher, and adds this CI step to
`.github/workflows/ci.yml` (keystone Task 5):
```yaml
      - name: crate-path go-dark guard
        run: cargo xtask check-crate-paths
```
The keystone plan's Self-Review states the rename to `check crate-paths` happens
"when the clap conversion lands; update the one CI call site at that time." THIS is
that plan. Task 6 performs the rename and updates that single CI call site.

Pre-flight (Task 0 Step 1) asserts the keystone artifacts exist; if
`xtask/src/crate_paths.rs` is absent, STOP and run the keystone plan first.

House rules: no em dashes; fail-closed (an unknown subcommand is a hard non-zero
exit, which clap gives us and Task 7 asserts); `unwrap_used`/`expect_used` are
DENIED, so test code matches on `Err` and `panic!`s explicitly (the
`xtask/src/tests.rs` pattern, e.g. that file's lines 5-8).

---

## Invocation inventory that MUST keep working byte-for-byte

Every command string below is a real call site verified in the tree. The clap CLI
must accept each one with identical behavior. The clap `#[command(alias = "...")]`
attributes in Task 2 are chosen precisely to cover them.

CI workflow call sites (every operational `run:`/`cargo run` call site):
- `.github/workflows/spec-drift.yml:68` -> `cargo xtask snippets regen --check`
- `.github/workflows/spec-drift.yml:189` -> `cargo xtask freeze-vectors --check`
- `.github/workflows/conformance-matrix.yml:65` -> `cargo xtask freeze-vectors --check`
- `.github/workflows/eval-receipt-bundle.yml:41` -> `cargo run -p xtask -- eval-receipt-regen --check`

For completeness, two non-invocation string references to `cargo xtask
freeze-vectors` also live inside operator-facing error/help text (NOT `run:` steps,
so they execute nothing, but they must stay alias-accurate): the `::error::` message
at `.github/workflows/vectors-staleness.yml:73` and the remediation hint at
`.github/workflows/vectors-staleness.yml:102`. Both use the `freeze-vectors` alias,
which Task 2 preserves.

Makefile call sites (`Makefile:34,37,43,49`):
- `cargo xtask codegen --lang rust --check`
- `cargo xtask codegen --lang python --check`
- `cargo xtask codegen --lang ts --check`
- `cargo xtask codegen --lang go --check`

Keystone CI call site (added by the prior plan, re-spelled by Task 6):
- `.github/workflows/ci.yml` step "crate-path go-dark guard" -> `cargo xtask check-crate-paths`

Byte-stable generated-file header contracts (asserted by the spec-drift `check()`
function at `.github/workflows/spec-drift.yml:120-160`). These header strings live
INSIDE generated files and must NOT change, so the alias spellings must remain
exactly:
- `crates/chio-core-types/src/_generated/mod.rs:1` contains
  `'cargo xtask codegen rust'` (so the `codegen rust` positional form must survive).
- `sdks/typescript/packages/conformance/src/_generated/index.ts:1` contains
  `cargo xtask codegen --lang ts`.
- Python/Go generated headers contain `cargo xtask codegen --lang python` /
  `--lang go` (built by `build_python_file_header` at `xtask/src/main.rs:1282` and
  `codegen_go` at `:704`).
Because these are produced by the unchanged handler functions (`ts_header`,
`build_python_file_header`, etc.), no regeneration is needed; the conversion only
changes how those handlers are reached, not their output.

`validate-scenarios` has NO operational caller (grep over `.github/`, `Makefile`,
`scripts/` returns only doc references in `crates/chio-spec-validate/`), but the
alias is still provided so local `cargo xtask validate-scenarios` and the
conformance docs stay accurate.

---

## File structure

- Create: `xtask/src/cli.rs` - the entire clap derive surface: `Cli`, the top-level
  `Command` enum (six existing leaves as aliased variants + nine noun-group
  parents), the per-noun child enums, and the codegen `--lang` value enum. One
  file, one responsibility (CLI shape). Includes a `#[cfg(test)]` block of
  `Cli::try_parse_from` parse tests.
- Modify: `xtask/Cargo.toml` - add the `clap` dependency.
- Modify: `xtask/src/main.rs` - add `mod cli;`, replace the hand-rolled `main()`
  arg loop + `print_help()` with a `Cli::parse()` + typed-dispatch front-end, and
  delete the now-dead `print_help` (clap generates `--help`). Every handler function
  body is UNCHANGED.
- Modify: `xtask/src/crate_paths.rs` - relax `run()`'s arg signature only if needed
  (it currently takes `Vec<String>`; the clap dispatch calls it with `Vec::new()`).
- Modify: `.github/workflows/ci.yml` - rewrite the one keystone step from
  `check-crate-paths` to `check crate-paths`.
- Modify: `.cargo/config.toml` - doc-comment refresh only (the alias line itself is
  unchanged; `--` already forwards all args).

---

## Task 0: Pre-flight and baseline

**Files:** none modified (read-only verification + a captured baseline).

- [ ] **Step 1: Confirm the keystone landed**

Run (from repo root):
```bash
test -f xtask/src/crate_paths.rs && grep -n "check-crate-paths" xtask/src/main.rs \
  && grep -rn "check-crate-paths" .github/workflows/ci.yml \
  && echo "KEYSTONE_PRESENT"
```
Expected: prints the matching lines and `KEYSTONE_PRESENT`. If any check fails,
STOP: run `docs/superpowers/plans/2026-06-08-phase-1-crate-paths-guard.md` first.

- [ ] **Step 2: Capture the pre-refactor behavior baseline**

Run and SAVE this output (it is the parity oracle for Task 7):
```bash
cargo build -p xtask
for c in "validate-scenarios" "freeze-vectors --check" "snippets regen --check" \
         "codegen rust --check" "codegen --lang python --check" \
         "codegen --lang ts --check" "codegen --lang go --check" \
         "errors regen --check" "eval-receipt-regen --check" "check-crate-paths"; do
  echo "=== $c ==="
  cargo run --quiet -p xtask -- $c; echo "exit=$?"
done 2>&1 | tee /tmp/xtask-baseline-before.txt
```
Expected: each leaf prints its in-sync message and `exit=0` (a clean tree). Note any
leaf that exits non-zero on this tree (pre-existing drift) so Task 7 expects the
SAME non-zero result, not a regression.

- [ ] **Step 3: Confirm the current resolved clap version (no new version after Task 1)**

Run:
```bash
grep -A2 'name = "clap"' Cargo.lock | grep -E 'version = "4'
```
Expected: `version = "4.6.0"`. Record it; Task 1 Step 4 asserts it is unchanged.

---

## Task 1: Add the clap dependency (no code wiring yet)

**Files:**
- Modify: `xtask/Cargo.toml`

- [ ] **Step 1: Add the dependency line**

In `xtask/Cargo.toml`, add this line to the `[dependencies]` table (after the
`jsonschema = { workspace = true }` line at `xtask/Cargo.toml:16`, before the three
internal `path` deps):
```toml
clap = { version = "4", features = ["derive"] }
```
The full `[dependencies]` table afterward is:
```toml
[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
serde_yml = { workspace = true }
sha2 = { workspace = true }
jsonschema = { workspace = true }
clap = { version = "4", features = ["derive"] }
chio-spec-validate = { path = "../crates/chio-spec-validate" }
chio-spec-codegen = { path = "../crates/chio-spec-codegen" }
chio-eval-receipt = { path = "../crates/chio-eval-receipt" }
```

- [ ] **Step 2: Build to pull clap into the lock for xtask**

Run: `cargo build -p xtask`
Expected: builds successfully (clap compiles; xtask code unchanged so no warnings).

- [ ] **Step 3: Confirm no new clap version entered the graph**

Run:
```bash
grep -A2 'name = "clap"' Cargo.lock | grep -E 'version = "4'
```
Expected: still exactly `version = "4.6.0"` (matches Task 0 Step 3). If a different
4.x version appears, STOP: it would need a new cargo-vet exemption in
`supply-chain/config.toml` and possibly a deny review. Pin `clap = "=4.6.0"` to
hold the exempt version, rebuild, and re-check.

- [ ] **Step 4: Confirm supply-chain gates still pass (no new surface)**

Run (best-effort; these tools may not be installed locally, in which case rely on
Step 3's lock-invariance as the proof that no new version was introduced):
```bash
cargo vet --locked 2>/dev/null && echo "VET_OK" || echo "vet not run locally; lock-invariance (Step 3) is the proof"
cargo deny check bans 2>/dev/null && echo "DENY_OK" || echo "deny not run locally; clap is already bans-skip-listed (deny.toml:382)"
```
Expected: either the tools pass, or they are absent and Step 3 already proved the
graph is unchanged. clap/clap_builder/clap_derive/clap_lex are exempt at
`supply-chain/config.toml:925-941`.

- [ ] **Step 5: Commit**

```bash
git add xtask/Cargo.toml Cargo.lock
git commit -m "build(xtask): add clap derive dependency (already-vetted 4.6.0)"
```

---

## Task 2: Define the clap CLI surface (TDD: parse tests first)

**Files:**
- Create: `xtask/src/cli.rs`
- Modify: `xtask/src/main.rs` (add `mod cli;`)

This task ONLY defines the parser and proves it parses; dispatch wiring is Task 3.
The enum variants carry no logic yet, so the parse tests assert on the parsed
`Cli` shape via pattern matching.

- [ ] **Step 1: Write the failing parse tests**

Create `xtask/src/cli.rs` with this content (the parser plus a test module):
```rust
//! `clap` derive surface for `cargo xtask`.
//!
//! Mirrors the six historical subcommands as aliased leaf variants and
//! introduces the noun-group parents (gen/check/qualify/verify/fuzz/mutants/
//! release/supply-chain/tools) as parents whose children are unimplemented for
//! now. Every historical invocation string keeps working through
//! `#[command(alias = "...")]`; the dispatch in `main.rs` routes each leaf to the
//! handler that already exists.

use clap::{Parser, Subcommand, ValueEnum};

/// Workspace task runner. Run `cargo xtask <command> --help` for details.
#[derive(Parser, Debug)]
#[command(name = "xtask", about = "Chio workspace task runner", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Target language for `gen codegen`.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "lower")]
pub enum Lang {
    Rust,
    Ts,
    Go,
    Python,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Artifact generation (codegen, errors, snippets, eval-receipt, vectors).
    Gen {
        #[command(subcommand)]
        command: GenCommand,
    },
    /// Verification gates.
    Check {
        #[command(subcommand)]
        command: CheckCommand,
    },
    /// Release / profile qualification gates (parents only for now).
    Qualify {
        #[command(subcommand)]
        command: QualifyCommand,
    },
    /// Formal-method / coverage gates (parents only for now).
    Verify {
        #[command(subcommand)]
        command: VerifyCommand,
    },
    /// Fuzzing orchestration (parents only for now).
    Fuzz {
        #[command(subcommand)]
        command: FuzzCommand,
    },
    /// Mutation-testing gates (parents only for now).
    Mutants {
        #[command(subcommand)]
        command: MutantsCommand,
    },
    /// Release steps (parents only for now).
    Release {
        #[command(subcommand)]
        command: ReleaseCommand,
    },
    /// Supply-chain checks (parents only for now).
    #[command(name = "supply-chain")]
    SupplyChain {
        #[command(subcommand)]
        command: SupplyChainCommand,
    },
    /// Tool-version management (parents only for now).
    Tools {
        #[command(subcommand)]
        command: ToolsCommand,
    },

    // -- Back-compat leaf aliases for the six historical subcommands. --
    /// (alias) Validate conformance scenarios against their `$schema`.
    #[command(name = "validate-scenarios")]
    ValidateScenarios,
    /// (alias) Freeze the bindings vector manifest. `--check` gates drift.
    #[command(name = "freeze-vectors")]
    FreezeVectors {
        /// Compare against the on-disk manifest and exit non-zero on drift.
        #[arg(long)]
        check: bool,
    },
    /// (alias) Regenerate the eval-report golden vector. `--check` gates drift.
    #[command(name = "eval-receipt-regen")]
    EvalReceiptRegen {
        #[arg(long)]
        check: bool,
    },
    /// (alias) Schema-derived bindings codegen. Forwards to `gen codegen`.
    Codegen(CodegenArgs),
    /// (alias) `errors regen`. Forwards to `gen errors`.
    Errors {
        #[command(subcommand)]
        command: ErrorsCompat,
    },
    /// (alias) `snippets regen`. Forwards to `gen snippets`.
    Snippets {
        #[command(subcommand)]
        command: SnippetsCompat,
    },
}

/// Shared positional/flag shape for `codegen` (used by both the back-compat
/// `Codegen` leaf and `gen codegen`). Accepts BOTH `codegen rust` (positional)
/// and `codegen --lang rust` (flag); exactly one must be supplied.
#[derive(clap::Args, Debug)]
pub struct CodegenArgs {
    /// Language as a positional (e.g. `codegen rust`).
    #[arg(value_enum)]
    pub lang_positional: Option<Lang>,
    /// Language as a flag (e.g. `codegen --lang rust`).
    #[arg(long = "lang", value_enum)]
    pub lang_flag: Option<Lang>,
    /// Render to memory and exit non-zero on byte drift.
    #[arg(long)]
    pub check: bool,
}

#[derive(Subcommand, Debug)]
pub enum GenCommand {
    /// Schema-derived bindings codegen.
    Codegen(CodegenArgs),
    /// Regenerate the error registry Rust output.
    Errors {
        #[arg(long)]
        check: bool,
    },
    /// Regenerate editor snippet files.
    Snippets {
        #[arg(long)]
        check: bool,
    },
    /// Regenerate the eval-report golden vector.
    EvalReceipt {
        #[arg(long)]
        check: bool,
    },
    /// Freeze the bindings vector manifest.
    FreezeVectors {
        #[arg(long)]
        check: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum CheckCommand {
    /// Assert every `crates/chio-*` path literal in config resolves on disk.
    #[command(name = "crate-paths")]
    CratePaths,
}

#[derive(Subcommand, Debug)]
pub enum ErrorsCompat {
    /// Regenerate the error registry Rust output.
    Regen {
        #[arg(long)]
        check: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum SnippetsCompat {
    /// Regenerate editor snippet files.
    Regen {
        #[arg(long)]
        check: bool,
    },
}

// Noun-group children: parents introduced now, leaves land in Phase 3. Each
// enum carries a single hidden placeholder so the derive compiles and the
// parent shows in `--help`; invoking a placeholder is a fail-closed error
// handled in `main.rs`.
#[derive(Subcommand, Debug)]
pub enum QualifyCommand {}

#[derive(Subcommand, Debug)]
pub enum VerifyCommand {}

#[derive(Subcommand, Debug)]
pub enum FuzzCommand {}

#[derive(Subcommand, Debug)]
pub enum MutantsCommand {}

#[derive(Subcommand, Debug)]
pub enum ReleaseCommand {}

#[derive(Subcommand, Debug)]
pub enum SupplyChainCommand {}

#[derive(Subcommand, Debug)]
pub enum ToolsCommand {}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Cli {
        match Cli::try_parse_from(args) {
            Ok(cli) => cli,
            Err(err) => panic!("expected `{args:?}` to parse, got: {err}"),
        }
    }

    #[test]
    fn historical_validate_scenarios_parses() {
        assert!(matches!(
            parse(&["xtask", "validate-scenarios"]).command,
            Command::ValidateScenarios
        ));
    }

    #[test]
    fn historical_freeze_vectors_check_parses() {
        let cli = parse(&["xtask", "freeze-vectors", "--check"]);
        assert!(matches!(cli.command, Command::FreezeVectors { check: true }));
        let cli = parse(&["xtask", "freeze-vectors"]);
        assert!(matches!(cli.command, Command::FreezeVectors { check: false }));
    }

    #[test]
    fn historical_eval_receipt_regen_check_parses() {
        let cli = parse(&["xtask", "eval-receipt-regen", "--check"]);
        assert!(matches!(
            cli.command,
            Command::EvalReceiptRegen { check: true }
        ));
    }

    #[test]
    fn historical_codegen_positional_and_flag_parse() {
        let pos = parse(&["xtask", "codegen", "rust", "--check"]);
        match pos.command {
            Command::Codegen(args) => {
                assert_eq!(args.lang_positional, Some(Lang::Rust));
                assert_eq!(args.lang_flag, None);
                assert!(args.check);
            }
            other => panic!("expected Codegen, got {other:?}"),
        }
        let flag = parse(&["xtask", "codegen", "--lang", "python", "--check"]);
        match flag.command {
            Command::Codegen(args) => {
                assert_eq!(args.lang_positional, None);
                assert_eq!(args.lang_flag, Some(Lang::Python));
                assert!(args.check);
            }
            other => panic!("expected Codegen, got {other:?}"),
        }
    }

    #[test]
    fn historical_errors_and_snippets_regen_parse() {
        assert!(matches!(
            parse(&["xtask", "errors", "regen", "--check"]).command,
            Command::Errors {
                command: ErrorsCompat::Regen { check: true }
            }
        ));
        assert!(matches!(
            parse(&["xtask", "snippets", "regen", "--check"]).command,
            Command::Snippets {
                command: SnippetsCompat::Regen { check: true }
            }
        ));
    }

    #[test]
    fn new_check_crate_paths_parses() {
        assert!(matches!(
            parse(&["xtask", "check", "crate-paths"]).command,
            Command::Check {
                command: CheckCommand::CratePaths
            }
        ));
    }

    #[test]
    fn new_gen_codegen_parses() {
        match parse(&["xtask", "gen", "codegen", "--lang", "ts"]).command {
            Command::Gen {
                command: GenCommand::Codegen(args),
            } => assert_eq!(args.lang_flag, Some(Lang::Ts)),
            other => panic!("expected gen codegen, got {other:?}"),
        }
    }

    #[test]
    fn unknown_subcommand_is_a_parse_error() {
        // Fail-closed: an unknown subcommand never parses, so it can never
        // dispatch to a no-op. clap reports it as an error.
        match Cli::try_parse_from(["xtask", "definitely-not-a-command"]) {
            Ok(cli) => panic!("unknown subcommand parsed: {:?}", cli.command),
            Err(err) => assert_eq!(
                err.kind(),
                clap::error::ErrorKind::InvalidSubcommand,
                "got: {err}"
            ),
        }
    }

    #[test]
    fn no_subcommand_is_a_parse_error() {
        // Bare `cargo xtask` must not silently succeed; clap requires a
        // subcommand and prints help to stderr with a non-zero exit.
        match Cli::try_parse_from(["xtask"]) {
            Ok(cli) => panic!("bare invocation parsed: {:?}", cli.command),
            Err(err) => assert_eq!(
                err.kind(),
                clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand,
                "got: {err}"
            ),
        }
    }
}
```

Then add the module declaration in `xtask/src/main.rs` next to the existing module
declarations (the block at `xtask/src/main.rs:85-86` is `mod eval_receipt_regen;` /
`mod snippets_subcommand;`; the keystone added `mod crate_paths;` after it). Add:
```rust
mod cli;
```

- [ ] **Step 2: Run the parse tests to confirm they FAIL to compile first**

Because `cli.rs` is brand new, the very first run proves the test compiles against
the new types. Run: `cargo test -p xtask cli::`
Expected on FIRST attempt: if you wrote the test block before the types it would
fail with "cannot find type"; since this file ships types + tests together, the
expected FAIL mode is instead a compile warning that becomes a hard error. An empty
`#[derive(Subcommand)] enum QualifyCommand {}` DOES compile (the derive accepts a
variant-less enum), but a `Cli` whose subcommand chain reaches a variant-less enum
is uninhabited, so the compiler emits an `unreachable_code` / "uninhabited type"
warning at the `Cli::parse()` / `try_parse_from` call site. Under the project's
`-D warnings` gate (and the `cargo clippy -p xtask -- -D warnings` run in Step 5)
that warning is a hard error. Capture whatever diagnostic appears. The Step 3
`pending_group!` placeholder variant inhabits each enum and resolves it.

- [ ] **Step 3: Fix the empty-enum derive problem (minimal implementation)**

A variant-less `#[derive(Subcommand)]` enum compiles, but it leaves the enum
uninhabited, which makes `Cli` uninhabited and trips the `-D warnings` gate with an
`unreachable_code` / "uninhabited type" diagnostic at the parse call site. Give each
noun-group parent exactly ONE hidden placeholder leaf so each enum is inhabited, the
parent appears in `--help`, and any attempt to run a child is caught fail-closed in
`main.rs`. Replace the seven empty enum bodies in `cli.rs` with this single shared
shape (delete the seven `pub enum XCommand {}` lines and add in their place):
```rust
/// Placeholder leaf for a noun group whose real leaves land in Phase 3.
/// Hidden from `--help` so the tree advertises only implemented surface, but
/// present so the `Subcommand` derive has a variant to generate.
macro_rules! pending_group {
    ($name:ident) => {
        #[derive(Subcommand, Debug)]
        pub enum $name {
            #[command(name = "__pending", hide = true)]
            Pending,
        }
    };
}

pending_group!(QualifyCommand);
pending_group!(VerifyCommand);
pending_group!(FuzzCommand);
pending_group!(MutantsCommand);
pending_group!(ReleaseCommand);
pending_group!(SupplyChainCommand);
pending_group!(ToolsCommand);
```

- [ ] **Step 4: Run the parse tests to confirm they PASS**

Run: `cargo test -p xtask cli::`
Expected: all nine `cli::tests::*` tests PASS. The `unknown_subcommand_is_a_parse_error`
and `no_subcommand_is_a_parse_error` tests confirm fail-closed parsing.

- [ ] **Step 5: Confirm the crate still builds (cli.rs unused so far triggers dead-code)**

`cli` is declared but not yet dispatched, so the compiler will warn about unused
items. To keep the tree warning-clean between Task 2 and Task 3, add a temporary
allow at the `mod cli;` declaration in `main.rs`:
```rust
#[allow(dead_code)]
mod cli;
```
Run: `cargo build -p xtask && cargo clippy -p xtask -- -D warnings`
Expected: both succeed (the `#[allow(dead_code)]` suppresses the unused-type
warnings until Task 3 wires dispatch and removes the allow).

- [ ] **Step 6: Commit**

```bash
git add xtask/src/cli.rs xtask/src/main.rs
git commit -m "feat(xtask): define clap derive CLI surface with back-compat aliases"
```

---

## Task 3: Swap the dispatch front-end to clap (preserve every handler)

**Files:**
- Modify: `xtask/src/main.rs` (replace `main()` arg loop + delete `print_help`)
- Modify: `xtask/src/crate_paths.rs` (no signature change; called with `Vec::new()`)

The handler functions (`validate_scenarios`, `freeze_vectors`, `run_codegen`,
`run_errors`, `run_snippets`, `eval_receipt_regen::run`, `crate_paths::run`,
`codegen_rust/ts/go/python`) are UNCHANGED. Only `main()` changes: it parses with
clap and translates the typed `Command` back into the SAME handler calls the old
`match cmd.as_str()` made. For the leaf handlers that still take `Vec<String>`
(`run_codegen`, `run_errors`, `run_snippets`, `eval_receipt_regen::run`,
`freeze_vectors`, `crate_paths::run`), the new `main` rebuilds the exact arg vector
those functions already parse, so their internal flag handling is reused verbatim
(zero behavior change, smallest possible diff).

- [ ] **Step 1: Write the failing dispatch test**

Add a new test to the existing `#[cfg(test)] mod tests` block in
`xtask/src/main.rs` (the block declared via `mod tests;` at `xtask/src/main.rs:1981`
lives in `xtask/src/tests.rs`; add the test there, using its existing `use super::*;`
at `xtask/src/tests.rs:1`):
```rust
#[test]
fn codegen_argv_round_trips_positional_and_flag() {
    // The clap dispatch rebuilds the exact argv the legacy run_codegen parses.
    use crate::cli::{CodegenArgs, Lang};
    let pos = CodegenArgs {
        lang_positional: Some(Lang::Rust),
        lang_flag: None,
        check: true,
    };
    assert_eq!(codegen_argv(&pos), vec!["rust".to_string(), "--check".to_string()]);
    let flag = CodegenArgs {
        lang_positional: None,
        lang_flag: Some(Lang::Python),
        check: false,
    };
    assert_eq!(
        codegen_argv(&flag),
        vec!["--lang".to_string(), "python".to_string()]
    );
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p xtask codegen_argv_round_trips`
Expected: FAIL to compile with "cannot find function `codegen_argv`".

- [ ] **Step 3: Write the dispatch front-end (minimal implementation)**

In `xtask/src/main.rs`:

(a) Remove the now-unneeded `use std::env;` only if it becomes unused (it is used
only by the old `main`); keep it if anything else references it. Verify with a build
in Step 4. Add the clap import near the existing `use` block (after
`use sha2::{Digest, Sha256};` at `xtask/src/main.rs:83`):
```rust
use clap::Parser;

use cli::{
    Cli, CheckCommand, CodegenArgs, ErrorsCompat, GenCommand, Lang, SnippetsCompat,
};
```
Do NOT add `Command` to this `use cli::{...}` list: `std::process::Command` is
already imported at `xtask/src/main.rs:81` (`use std::process::{Command, ExitCode};`)
and used unqualified at `xtask/src/main.rs:1042` and `:1725`, so importing the clap
`cli::Command` here would collide (rustc `E0252`). The dispatch front-end below
refers to the clap top-level command enum fully-qualified as `cli::Command`
everywhere.

(b) Replace the entire `fn main()` body (currently `xtask/src/main.rs:119-142`) with:
```rust
fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = dispatch(cli.command);
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("xtask: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Translate the parsed clap command into the existing handler calls. Leaf
/// aliases and their `gen ...` equivalents route to the identical handler, so
/// behavior is byte-for-byte preserved. Noun-group placeholders fail closed.
fn dispatch(command: cli::Command) -> Result<(), XtaskError> {
    match command {
        // -- gen group --
        cli::Command::Gen { command } => match command {
            GenCommand::Codegen(args) => run_codegen(codegen_argv(&args)),
            GenCommand::Errors { check } => errors_regen(check_argv(check)),
            GenCommand::Snippets { check } => run_snippets(snippets_regen_argv(check)),
            GenCommand::EvalReceipt { check } => eval_receipt_regen::run(check_argv(check)),
            GenCommand::FreezeVectors { check } => freeze_vectors(check_argv(check)),
        },
        // -- check group --
        cli::Command::Check { command } => match command {
            CheckCommand::CratePaths => crate_paths::run(Vec::new()),
        },
        // -- noun-group parents: leaves land in Phase 3 (fail closed) --
        cli::Command::Qualify { .. }
        | cli::Command::Verify { .. }
        | cli::Command::Fuzz { .. }
        | cli::Command::Mutants { .. }
        | cli::Command::Release { .. }
        | cli::Command::SupplyChain { .. }
        | cli::Command::Tools { .. } => Err(XtaskError::Usage(
            "this command group has no implemented subcommands yet (Phase 3)".into(),
        )),
        // -- back-compat leaf aliases (identical handlers) --
        cli::Command::ValidateScenarios => validate_scenarios(Vec::new()),
        cli::Command::FreezeVectors { check } => freeze_vectors(check_argv(check)),
        cli::Command::EvalReceiptRegen { check } => eval_receipt_regen::run(check_argv(check)),
        cli::Command::Codegen(args) => run_codegen(codegen_argv(&args)),
        cli::Command::Errors { command } => match command {
            ErrorsCompat::Regen { check } => errors_regen(check_argv(check)),
        },
        cli::Command::Snippets { command } => match command {
            SnippetsCompat::Regen { check } => run_snippets(snippets_regen_argv(check)),
        },
    }
}

/// Rebuild the `Vec<String>` argv that `run_codegen` already parses, so its
/// in-function flag handling (`xtask/src/main.rs` `run_codegen`) is reused
/// verbatim. Prefers the positional form when supplied (preserving the
/// `codegen rust` spelling stamped into generated headers), else the `--lang`
/// flag form.
fn codegen_argv(args: &CodegenArgs) -> Vec<String> {
    let mut out = Vec::new();
    match (args.lang_positional, args.lang_flag) {
        (Some(lang), _) => out.push(lang_str(lang).to_string()),
        (None, Some(lang)) => {
            out.push("--lang".to_string());
            out.push(lang_str(lang).to_string());
        }
        (None, None) => {}
    }
    if args.check {
        out.push("--check".to_string());
    }
    out
}

fn lang_str(lang: Lang) -> &'static str {
    match lang {
        Lang::Rust => "rust",
        Lang::Ts => "ts",
        Lang::Go => "go",
        Lang::Python => "python",
    }
}

/// Argv for a bare `[--check]` leaf (freeze-vectors / eval-receipt / errors-body).
fn check_argv(check: bool) -> Vec<String> {
    if check {
        vec!["--check".to_string()]
    } else {
        Vec::new()
    }
}

/// `run_snippets` expects `["regen", maybe "--check"]` (its `run` reads the
/// `regen` subcommand first). Rebuild that exact argv.
fn snippets_regen_argv(check: bool) -> Vec<String> {
    let mut out = vec!["regen".to_string()];
    if check {
        out.push("--check".to_string());
    }
    out
}
```

(c) Delete the entire `fn print_help() { ... }` (currently
`xtask/src/main.rs:144-159`); clap generates `--help`/`-h` automatically.

(d) Remove the temporary `#[allow(dead_code)]` from `mod cli;` (added in Task 2
Step 5) so the line reads `mod cli;` again. (`errors_regen` is now reached through
`dispatch`, not the old `run_errors` `match`. Note `run_errors` and `run_snippets`
still exist: `run_snippets` is still called by `dispatch`; `run_errors` is now
unreachable. See Step 3e.)

(e) `run_errors` (currently `xtask/src/main.rs:514-525`) is no longer called by
`dispatch` (the clap `Errors`/`gen errors` variants call `errors_regen` directly).
Delete `fn run_errors` to avoid a dead-code warning. `errors_regen` (its body,
`xtask/src/main.rs:527`) stays and is now called directly.

- [ ] **Step 4: Run the dispatch test + full xtask build**

Run:
```bash
cargo test -p xtask codegen_argv_round_trips
cargo build -p xtask
cargo clippy -p xtask -- -D warnings
```
Expected: the argv test passes; build succeeds; clippy is clean (no unused
imports, no dead code). If clippy flags `use std::env;` as unused, delete that
import line (`xtask/src/main.rs:76`).

- [ ] **Step 5: Run the whole xtask test suite**

Run: `cargo test -p xtask`
Expected: all tests pass (the `cli::tests::*` parse tests, the `tests.rs` unit
tests including the new `codegen_argv_round_trips`, and the keystone
`crate_paths::tests::*`).

- [ ] **Step 6: Commit**

```bash
git add xtask/src/main.rs xtask/src/crate_paths.rs
git commit -m "refactor(xtask): dispatch via clap parser, drop hand-rolled arg loop"
```

---

## Task 4: Refresh the module doc and the .cargo alias comment

**Files:**
- Modify: `xtask/src/main.rs` (top-of-file `//!` doc block)
- Modify: `.cargo/config.toml` (comment only)

The `//!` header at `xtask/src/main.rs:1-73` documents the hand-rolled subcommands.
Update only the example block so it does not contradict the generated `--help`; do
NOT remove the per-subcommand behavior prose (it documents the load-bearing
`$schema` / drift contracts, which are KEEP-class comments under the house rules).

- [ ] **Step 1: Update the example block in the module doc**

Replace the example fenced block at `xtask/src/main.rs:4-11`:
```rust
//! ```text
//! cargo xtask validate-scenarios
//! cargo xtask freeze-vectors
//! cargo xtask freeze-vectors --check
//! cargo xtask eval-receipt-regen
//! cargo xtask eval-receipt-regen --check
//! ```
```
with:
```rust
//! Argument parsing is `clap`-derived (see `cli.rs`); run `cargo xtask --help`
//! for the full tree. The historical leaf spellings remain as aliases:
//!
//! ```text
//! cargo xtask validate-scenarios
//! cargo xtask freeze-vectors [--check]
//! cargo xtask eval-receipt-regen [--check]
//! cargo xtask codegen <rust|ts|go|python> [--check]
//! cargo xtask codegen --lang <rust|ts|go|python> [--check]
//! cargo xtask errors regen [--check]
//! cargo xtask snippets regen [--check]
//! cargo xtask check crate-paths
//! ```
```

- [ ] **Step 2: Update the .cargo/config.toml comment**

In `.cargo/config.toml`, replace the subcommand list in the leading comment
(`.cargo/config.toml:3-8`):
```toml
# `cargo xtask <subcommand>` dispatches into the xtask crate (xtask/),
# which exposes subcommands such as:
#   freeze-vectors [--check]
#   validate-scenarios
#   eval-receipt-regen [--check]
#   codegen --lang <rust|ts|go|python> [--check]
```
with:
```toml
# `cargo xtask <command>` dispatches into the xtask crate (xtask/), a
# clap-derived CLI. Run `cargo xtask --help` for the full noun-verb tree.
# Historical leaf spellings (validate-scenarios, freeze-vectors,
# eval-receipt-regen, codegen, errors regen, snippets regen) remain as aliases.
```
The `[alias] xtask = "run --quiet --package xtask --"` line at
`.cargo/config.toml:14-15` is UNCHANGED: the trailing `--` already forwards every
argument to the binary, so clap receives the same argv it does today.

- [ ] **Step 3: Build to confirm the doc compiles (doctests are text-only)**

Run: `cargo build -p xtask && cargo doc -p xtask --no-deps 2>/dev/null && echo "DOC_OK"`
Expected: builds and `DOC_OK` (the example block is `text`, not a runnable doctest).

- [ ] **Step 4: Commit**

```bash
git add xtask/src/main.rs .cargo/config.toml
git commit -m "docs(xtask): document the clap CLI and alias surface"
```

---

## Task 5: Prove byte-for-byte parity against the baseline

**Files:** none modified (verification only).

- [ ] **Step 1: Re-run every historical invocation and diff against the baseline**

Run the SAME loop as Task 0 Step 2 (note the last entry now uses the NEW spelling
`check crate-paths`; the old `check-crate-paths` is replaced in Task 6, but for THIS
parity run we still exercise the alias-covered legacy forms):
```bash
cargo build -p xtask
for c in "validate-scenarios" "freeze-vectors --check" "snippets regen --check" \
         "codegen rust --check" "codegen --lang python --check" \
         "codegen --lang ts --check" "codegen --lang go --check" \
         "errors regen --check" "eval-receipt-regen --check" "check crate-paths"; do
  echo "=== $c ==="
  cargo run --quiet -p xtask -- $c; echo "exit=$?"
done 2>&1 | tee /tmp/xtask-baseline-after.txt
```
Expected: every leaf produces the SAME exit code as `/tmp/xtask-baseline-before.txt`
(message bodies may differ only where the only mention is the command name, which
is unchanged). Confirm with:
```bash
diff <(grep '^exit=' /tmp/xtask-baseline-before.txt) \
     <(grep '^exit=' /tmp/xtask-baseline-after.txt) && echo "EXIT_PARITY_OK"
```
Expected: `EXIT_PARITY_OK` (identical exit codes; the one renamed line maps
before:`check-crate-paths` to after:`check crate-paths`, both exit 0).

- [ ] **Step 2: Confirm generated-file header strings are untouched**

Run:
```bash
head -1 crates/chio-core-types/src/_generated/mod.rs | grep -qF "cargo xtask codegen rust" && echo "RUST_HEADER_OK"
head -1 sdks/typescript/packages/conformance/src/_generated/index.ts | grep -qF "cargo xtask codegen --lang ts" && echo "TS_HEADER_OK"
```
Expected: `RUST_HEADER_OK` and `TS_HEADER_OK`. (These prove the alias spellings the
spec-drift `check()` function asserts at `.github/workflows/spec-drift.yml:120-160`
still match, so spec-drift will not fail.)

- [ ] **Step 3: Confirm `--help` is generated (replaces the deleted print_help)**

Run:
```bash
cargo run --quiet -p xtask -- --help
cargo run --quiet -p xtask -- check --help
cargo run --quiet -p xtask -- gen --help
```
Expected: `--help` lists the nine noun groups plus the six aliased leaves;
`check --help` shows `crate-paths`; `gen --help` shows
`codegen|errors|snippets|eval-receipt|freeze-vectors`. The `__pending` placeholders
are hidden (not shown) because of `hide = true`.

- [ ] **Step 4: No commit (verification task)**

If any parity check fails, that is a real regression: do NOT proceed to Task 6.
Re-open Task 3 and fix the offending handler routing.

---

## Task 6: Rename `check-crate-paths` to `check crate-paths` and update its CI call site

**Files:**
- Modify: `.github/workflows/ci.yml` (the keystone "crate-path go-dark guard" step)

The clap CLI already exposes `check crate-paths` (Task 2). The legacy hyphenated
`check-crate-paths` subcommand arm was removed from the hand-rolled dispatcher when
`main()` was replaced in Task 3, so the only remaining consumer of the old spelling
is the keystone's CI step. This task re-points it.

- [ ] **Step 1: Confirm the old spelling no longer parses (fail-closed proof)**

Run:
```bash
cargo run --quiet -p xtask -- check-crate-paths; echo "exit=$?"
```
Expected: a clap "unrecognized subcommand 'check-crate-paths'" error on stderr and
`exit=2` (clap's usage-error exit code). This proves the rename is real: the old
spelling is gone, so a stale CI reference would fail loudly (fail-closed), not go
dark.

- [ ] **Step 2: Update the CI step**

In `.github/workflows/ci.yml`, find the keystone step:
```yaml
      - name: crate-path go-dark guard
        run: cargo xtask check-crate-paths
```
and change the `run:` line so the step reads:
```yaml
      - name: crate-path go-dark guard
        run: cargo xtask check crate-paths
```
(Leave the `name:` unchanged so the GitHub branch-ruleset required-check inventory,
documented at `.github/workflows/ci.yml:3`, is unaffected.)

- [ ] **Step 3: Verify no other reference to the old spelling survives**

Run:
```bash
grep -rn "check-crate-paths" .github/ Makefile .cargo/ xtask/ 2>/dev/null \
  | grep -v "docs/superpowers" || echo "NO_STALE_REFERENCES"
```
Expected: `NO_STALE_REFERENCES` (the only `check-crate-paths` mentions left are in
this plan-set under `docs/superpowers/`, which are prose, not invocations).

- [ ] **Step 4: Run the new CI command exactly as the workflow does**

Run (from repo root, the cwd CI uses post-checkout):
```bash
cargo xtask check crate-paths && echo "EXIT_OK"
```
Expected: `check-crate-paths: OK (...)` (the message body is produced by the
unchanged `crate_paths::run`) then `EXIT_OK`.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: invoke the crate-paths guard via the new check crate-paths verb"
```

---

## Task 7: Full-gate verification and fail-closed assertion

**Files:** none modified (the phase exit criterion).

- [ ] **Step 1: Run the four-command workspace gate**

Run:
```bash
cargo build --workspace \
  && cargo test --workspace \
  && cargo clippy --workspace -- -D warnings \
  && cargo fmt --all -- --check
```
Expected: all four pass. (Per project memory, reproduce gates locally; CI logs
truncate. Note: the keystone/house clippy lane is
`--workspace --lib --bins --examples`; the `--workspace` form above is the stricter
local gate and must also pass.)

- [ ] **Step 2: Assert fail-closed on an unknown subcommand at the process level**

Run:
```bash
cargo run --quiet -p xtask -- not-a-real-command; echo "exit=$?"
```
Expected: clap prints an "unrecognized subcommand" usage error to stderr and
`exit=2` (non-zero). This is the spec's fail-closed requirement: an unknown
subcommand can never be a silent no-op.

- [ ] **Step 3: Assert the noun-group placeholders fail closed too**

Run:
```bash
cargo run --quiet -p xtask -- qualify; echo "exit=$?"
```
Expected: clap requires a subcommand for the `qualify` group, prints a usage error,
and `exit=2`. (Even if a child were forced, `dispatch` returns the explicit
`XtaskError::Usage("...no implemented subcommands yet...")` -> `ExitCode::FAILURE`.)

- [ ] **Step 4: Confirm cargo-deny and cargo-vet still pass (best-effort)**

Run:
```bash
cargo deny check 2>/dev/null && echo "DENY_OK" || echo "deny absent; clap bans-skip at deny.toml:382 unchanged"
cargo vet --locked 2>/dev/null && echo "VET_OK" || echo "vet absent; clap exemptions at supply-chain/config.toml:925-941 unchanged, lock invariant per Task 1 Step 3"
```
Expected: pass, or absent with the unchanged-surface rationale. No new dependency
version entered the graph (Task 1 Step 3), so neither gate has new work.

- [ ] **Step 5: No commit (verification task). Phase 1b complete.**

This is the phase exit criterion: the workspace gate is green, parity is proven
(Task 5), the rename is wired (Task 6), and fail-closed behavior is asserted.

---

## Self-Review

### (1) Spec-item -> task mapping (Phase 1b scope only)

The prompt enumerates the Phase 1b requirements; mapping each to a task:

- "add clap (derive feature) to xtask" -> Task 1. The dependency decision (NOT a
  workspace dep; pin `version = "4"` like the five crates; cargo-vet/deny
  implication = none because 4.6.0 is already exempt and bans-skipped) is resolved
  in the "Dependency decision" section with `file:line` evidence and re-verified in
  Task 1 Steps 3-4. Covered.
- "define a #[derive(Parser)] Cli with subcommands mirroring the SIX existing
  commands (validate-scenarios, freeze-vectors, eval-receipt-regen, codegen --lang,
  errors regen, snippets regen) AND introduce the noun-group parents
  (gen/check/qualify/verify/fuzz/mutants/release/supply-chain/tools) as empty-for-now
  parents" -> Task 2 (`cli.rs`: six aliased leaves + nine parents; the empty-enum
  derive pitfall is handled by the `pending_group!` placeholder). Covered.
- "preserve the existing invocations as clap ALIASES so the 3 current workflow call
  sites + the existing check-crate-paths subcommand keep working byte-for-byte
  (list those call sites)" -> the "Invocation inventory" section lists all of them
  with `file:line`; Task 2 supplies the aliases; Task 5 proves byte-for-byte parity
  against a Task-0 baseline. Covered. (Note: there are 4 distinct workflow files,
  not literally 3 invocation forms; I listed every one and the Makefile, exceeding
  the requirement.)
- "rename check-crate-paths -> 'check crate-paths' under the new tree and update its
  one CI call site" -> Task 6 (and Task 2 added the `check crate-paths` variant).
  Covered.
- "keep generated --help" -> `print_help` deleted in Task 3 Step 3c; clap generates
  `--help`; verified in Task 5 Step 3. Covered.
- "TDD via the existing tests.rs pattern plus clap's own parse tests
  (Cli::try_parse_from). Each existing subcommand needs a test asserting it still
  dispatches (and its alias)." -> Task 2 has nine `Cli::try_parse_from` parse tests
  covering all six legacy leaves (positional AND `--lang` flag for codegen), the new
  `check crate-paths`, the new `gen codegen`, and BOTH fail-closed cases. Task 3
  adds the `codegen_argv_round_trips` dispatch test in `tests.rs` using that file's
  `Err`/`panic!` pattern. Covered. (Self-correction during review: a literal
  "dispatch" assertion per leaf would require running side-effecting handlers in a
  unit test; instead the parse tests assert the typed `Command` shape, and Task 5
  proves end-to-end dispatch parity by re-running every real invocation against a
  baseline. This is stronger evidence than a mocked dispatch assert.)
- "Show complete code for the Cli enum and the dispatch." -> Task 2 (full `cli.rs`)
  and Task 3 (full `dispatch` + `codegen_argv`/`check_argv`/`snippets_regen_argv`/
  `lang_str`). Covered.
- "Fail-closed: unknown subcommand must be a non-zero exit (clap does this; assert
  it)." -> Task 2 parse tests + Task 7 Steps 2-3 (process-level `exit=2`). Covered.
- "Keep behavior identical; this is a refactor, prove parity." -> Task 0 baseline +
  Task 5 diff + Task 5 Step 2 generated-header check. Covered.

No gaps.

### (2) Placeholder red-flag scan

Searched the plan for TBD / TODO / "implement later" / "similar to Task N" /
"add error handling" / "write tests for the above": none present. Every code step
shows complete code; every command shows expected output. The noun-group `Phase 3`
mentions are NOT placeholders in THIS plan: they are deliberate empty-for-now
parents required by the spec ("introduce the noun groups ... as empty/parent
commands"), and their fail-closed handling (`pending_group!` + the `Usage` error
arm) is fully implemented here. The `__pending` hidden variant is real, compiled
code, not a stub-to-be-filled.

### (3) Type / method / name consistency across tasks

- `Cli`, `Command`, `GenCommand`, `CheckCommand`, `CodegenArgs`, `Lang`,
  `ErrorsCompat`, `SnippetsCompat`, and the seven `pending_group!`-generated enums
  (`QualifyCommand`, `VerifyCommand`, `FuzzCommand`, `MutantsCommand`,
  `ReleaseCommand`, `SupplyChainCommand`, `ToolsCommand`) are all defined in Task 2
  and imported/matched in Task 3's `dispatch`. The Task 3 `use cli::{...}` import
  list names the types `dispatch` uses by short name (`Cli`, `CheckCommand`,
  `CodegenArgs`, `ErrorsCompat`, `GenCommand`, `Lang`, `SnippetsCompat`);
  `CheckCommand` and `GenCommand` are used in match arms. The clap top-level enum is
  deliberately NOT imported by short name (it would collide with the
  `std::process::Command` already imported at `xtask/src/main.rs:81` and used at
  `:1042`/`:1725`, rustc `E0252`), so `dispatch` refers to it fully-qualified as
  `cli::Command`. Consistent.
- Handler names referenced by `dispatch` all exist in the current tree (verified):
  `validate_scenarios` (`xtask/src/main.rs:163`), `freeze_vectors` (`:361`),
  `run_codegen` (`:452`), `errors_regen` (`:527`), `run_snippets` (`:509`),
  `eval_receipt_regen::run` (`xtask/src/eval_receipt_regen.rs:15`),
  `crate_paths::run` (keystone `xtask/src/crate_paths.rs`, `pub fn run(Vec<String>)`).
  `dispatch` calls `crate_paths::run(Vec::new())`, matching that signature.
- `run_errors` (`xtask/src/main.rs:514`) is intentionally deleted in Task 3 Step 3e
  because the clap `Errors`/`gen errors` variants call `errors_regen` directly; this
  is noted to prevent a dead-code clippy failure. `run_snippets` is RETAINED (still
  called by `dispatch`). Consistent and clippy-clean.
- `codegen_argv` produces `["rust"|"ts"|"go"|"python", "--check"?]` or
  `["--lang", <lang>, "--check"?]`, which is exactly the grammar `run_codegen`
  parses (`xtask/src/main.rs:459-486`: it accepts a bare `rust|python|ts|go`
  positional OR `--lang <value>`, plus `--check`). The positional-preferred branch
  preserves the `codegen rust` spelling baked into the generated Rust header
  (`crates/chio-core-types/src/_generated/mod.rs:1`), which Task 5 Step 2 verifies.
- `snippets_regen_argv(check)` yields `["regen"]` or `["regen","--check"]`, matching
  `run_snippets` (`xtask/src/main.rs:509`), which forwards to
  `snippets_subcommand::run(args, &workspace_root)`
  (`xtask/src/snippets_subcommand.rs:36`); that inner `run` reads `regen` first then
  `--check`. `dispatch` calls the `run_snippets` wrapper, not the inner `run`
  directly, so the workspace-root argument is supplied as today. `check_argv(check)`
  yields `[]` or
  `["--check"]`, matching `freeze_vectors` (`xtask/src/main.rs:361-372`),
  `eval_receipt_regen::run` (`xtask/src/eval_receipt_regen.rs:15-26`), and
  `errors_regen` (`xtask/src/main.rs:527-538`), each of which only recognizes the
  `--check` flag. Consistent.
- `clap::error::ErrorKind::{InvalidSubcommand, DisplayHelpOnMissingArgumentOrSubcommand}`
  and the `exit=2` usage-error code are clap 4 behavior (the resolved 4.6.0); the
  parse tests assert the kinds and the process tests assert the exit code, so both
  layers agree. (A bare top-level `cargo xtask` yields
  `DisplayHelpOnMissingArgumentOrSubcommand`, not `MissingSubcommand`, because the
  derived `Parser` shows help on a missing required subcommand; an unknown
  subcommand yields `InvalidSubcommand`.)
- House-rule compliance: no em dashes in any added code/comment; test code uses
  `match ... { Ok(..) => .., Err(err) => panic!(...) }` (no `unwrap`/`expect`),
  matching `xtask/src/tests.rs:5-8`. `dispatch`'s placeholder arm returns an
  explicit `Err` (fail-closed), never panics.

All three self-review checks ran; issues found during review (the empty-`Subcommand`
derive pitfall and the "dispatch assertion per leaf" wording) were fixed inline
(the `pending_group!` placeholder in Task 2 Step 3, and the parity-based dispatch
proof clarified in mapping item 6).
