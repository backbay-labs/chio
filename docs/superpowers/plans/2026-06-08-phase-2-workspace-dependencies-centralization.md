# Phase 2 - Workspace Dependencies Centralization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Centralize every internal Chio crate dependency into the root `[workspace.dependencies]` table (keyed by package name, paths pointing at current `crates/chio-x`), then flip every member manifest's internal path dep to `{ workspace = true }`, with ZERO directory moves, proven semantically inert by a `cargo metadata` resolve-graph fingerprint that is byte-identical before and after.

**Architecture:** This is a pure manifest refactor. The root `Cargo.toml` gains 97 internal-crate entries (joining the lone existing `chio-metrics-spec`); all 97 internal crates get a table entry. Each consuming member manifest rewrites its FLIPPABLE `path = "../chio-x"` / `path = "../../crates/chio-x"` declarations to `{ workspace = true }`, preserving `features =` (25 intra-`crates/` lines), `default-features = false` (10 lines), and `optional = true` (25 lines) attributes while dropping the redundant per-member `version = "0.1.0"`. The 32 renamed-alias lines inside `crates/*` (and the matching aliases in external members) are NOT flipped: cargo inherits a workspace dependency by its KEY, not by `package =`, so a member-side `package =` + `workspace = true` would resolve to the wrong table entry (`chio-core` -> the real `chio-core`, not `chio-core-types`) or fail to parse (`chio-openai` has no table key); those lines stay path-based. Of the 447 single-level `crates/*` path-dep lines, 415 (447 minus the 32 renames) flip; the exact per-group flip count is informational - the hard gate is the resolve-graph fingerprint plus the lockfile and member-count invariants, which must be byte-identical before and after. The four standalone workspaces (`fuzz/`, `crates/chio-conformance/verdict_matrix`, `sdks/rust/chio-guard-sdk-compat`, `sdks/lambda/chio-lambda-extension`) do NOT inherit the root table and are explicitly out of scope here.

**Tech Stack:** Cargo 1.93.0 workspace (resolver 2), TOML manifests, a small idempotent Python rewriter for the mechanical sweep, and `cargo metadata --format-version 1` as the fail-closed semantic-equivalence oracle.

---

## Context and verified facts (read before executing)

This plan implements Phase 2 of `docs/superpowers/specs/2026-06-08-repo-architecture-design.md` (section 3, "Phase 2 - `[workspace.dependencies]` centralization (no moves)") and is the de-risking prerequisite for the eventual Phase 6 crate folder move. It depends on no other plan to run, but the spec sequences it after the Phase 1 keystone plan `docs/superpowers/plans/2026-06-08-phase-1-crate-paths-guard.md` (which ships `cargo xtask check-crate-paths`). That guard checks config-file path literals; it is NOT the verifier for this phase because Phase 2 does not move any path. The verifier here is the `cargo metadata` resolve-graph fingerprint.

All counts below were measured against the working tree at branch `codex/chio-next-10-remediation`:

- 447 single-level `path = "../chio-..."` lines across 94 `crates/*/Cargo.toml` files (the figure the spec calls "447 member path deps").
- 3 double-level `path = "../../chio-..."` lines, all in `crates/chio-conformance/verdict_matrix/Cargo.toml:33-35`. That manifest declares its own `[workspace]` and is OUT OF SCOPE (handled in Phase 6).
- 97 distinct internal packages are consumed by path from root members (excluding `chio-metrics-spec`, already centralized at `Cargo.toml:320`). This is the authoritative number for the centralized table. The spec's prose says "90 missing"; the verified count is 97 because (a) the spec undercounts the nested `chio-data-guards-redactors-default` and the dir/package split `chio-core` + `chio-core-types`, and (b) five crates (`chio-eval-receipt`, `chio-guard-sdk`, `chio-guard-sdk-macros`, `chio-otel-receipt-exporter`, `chio-spec-validate`) are consumed only by external members (`examples/`, `xtask/`, `tests/`) and must be in the table for those flips to resolve. Use 97. Do not use 90.
- 2 dir != package mismatches: directory `crates/chio-openai` publishes package `chio-openai-adapter` (`crates/chio-openai/Cargo.toml:2`); directory `crates/chio-data-guards/redactors/default` publishes package `chio-data-guards-redactors-default`. Both are handled explicitly below.
- 32 internal path-dep lines inside `crates/*` carry a `package = "..."` rename whose value differs from the dependency key: 31 are `chio-core = { package = "chio-core-types", ... }` and 1 is `chio-openai = { package = "chio-openai-adapter", ... }`. These are the CRITICAL lines: cargo inherits a workspace dependency by its KEY, not by `package =`, so a member-side `chio-core = { package = "chio-core-types", workspace = true }` would resolve to the table entry keyed `chio-core` (the real `chio-core` crate, NOT `chio-core-types`), and `chio-openai = { package = "chio-openai-adapter", workspace = true }` would fail to parse (`dependency.chio-openai was not found in workspace.dependencies`, since the only matching table key is `chio-openai-adapter`). These 32 rename lines therefore CANNOT be centralized member-side and stay path-based (see the rewriter guard in Step 2.1). Repo-wide, 44 internal path-dep lines carry a `package =` attribute: the 32 above, 4 more `chio-core` -> `chio-core-types` aliases in external members (`hello-tool`, `otel-genai`, `tests/e2e`, `formal/diff-tests`), 1 alias in the standalone `verdict_matrix`, 1 alias in the standalone `chio-guard-sdk-compat`, and 6 `package =` SELF-named lines (key == package, in `hello-tool`/`otel-genai`/`tests/e2e`) that are redundant but flippable (the rewriter keeps the redundant `package =` and flips them, since the key equals the package).
- 25 lines carry `optional = true`; 25 intra-`crates/` lines carry `features = [...]`; 10 lines carry `default-features = false` (all intra-`crates/`); 44 lines carry `version = "0.1.0"`. (The `optional` and `features` counts are both 25 but are overlapping-not-identical line sets.)

Cargo inheritance rules this plan relies on (all already proven in-tree by non-chio deps, e.g. `reqwest = { workspace = true, default-features = false, features = ["rustls"], optional = true }`):

1. A workspace dependency declared as `chio-x = { path = "crates/chio-x" }` is consumed by a member as `chio-x = { workspace = true }`.
2. `package = "..."`, `features = [...]`, `default-features = false`, and `optional = true` are all permitted on the MEMBER side alongside `workspace = true`. `features` is additive; `default-features = false` overrides per-member.
3. `version` is NOT permitted on a member line that uses `workspace = true` (cargo rejects it). The redundant per-member `version = "0.1.0"` must be DROPPED on the flip. The root table entry stays path-only (no version), matching the existing `chio-metrics-spec` precedent.
4. Because the SAME crate is consumed with conflicting `default-features` by different members (verified for `chio-core-types`, `chio-kernel-core`, `chio-custody-hw`, `chio-link`), the root table entry MUST be path-only. Baking `default-features = false` or `features` into the root entry would force it on all consumers and change the resolved graph. Keep root entries path-only.

The deterministic line transform for every internal path dep is:

```
<key> = { [package = "P",] [version = "0.1.0",] path = "<...>" [, default-features = false] [, features = [...]] [, optional = true] }
```
becomes
```
<key> = { [package = "P",] workspace = true [, default-features = false] [, features = [...]] [, optional = true] }
```

That is: delete any `version = "..."`, replace `path = "..."` with `workspace = true`, keep `package`/`default-features`/`features`/`optional` verbatim and in order.

EXCEPTION (renamed aliases): the transform applies only when the dependency KEY equals its `package =` value (or there is no `package =`). When `package = "P"` differs from the key (the 32 `crates/*` rename lines plus the external `chio-core` aliases), the line is left path-based UNCHANGED, because cargo inherits a workspace dependency by key, not by `package =`. Fully centralizing those would require renaming the dependency key to the real package and updating consuming source (`use chio_core` -> `use chio_core_types`, `use chio_openai` -> ...), which is OUT OF SCOPE for this phase; leaving them path-based is the correct fail-closed choice.

House rules: no em dashes (use hyphens or parentheses); fail-closed (any crate that fails to resolve to `{ workspace = true }`, or any metadata-fingerprint mismatch, stops the phase); `unwrap_used`/`expect_used` are denied in Rust, so the (Python-only) tooling here adds no Rust; if any future Rust test were added it must match on `Err` and `panic!` per `xtask/src/tests.rs`. Do not move any directory in this phase. The repo gate is `cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check`.

---

## Task 0: Establish the fail-closed baseline (metadata fingerprint)

The whole phase is verified against one invariant: the resolved dependency graph (which package depends on which resolved package) must be byte-identical before and after. We capture that fingerprint now.

- [ ] **Step 0.1: Confirm a clean starting tree on a feature branch.** The working tree already has unrelated modifications from prior remediation work; isolate this phase.

  Command:
  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && git status --short && git rev-parse --abbrev-ref HEAD
  ```
  Expected: the branch is `codex/chio-next-10-remediation` (or you create a new branch off it). The listed modified files (e.g. `crates/chio-ag-ui-proxy/src/proxy.rs`, `crates/chio-wasm-guards/Cargo.toml`) are pre-existing and unrelated. If you want isolation, run `git switch -c phase-2-workspace-deps` first. Do not stash the pre-existing changes; just keep Phase 2 commits scoped to manifests.

- [ ] **Step 0.2: Write the fingerprint helper script.** This script prints the resolve-graph SHA, the resolve-node count, and the workspace-member count. It is read-only.

  Create `scripts/_phase2_metadata_fingerprint.py` (temporary helper; deleted in Step 6.3):
  ```python
  #!/usr/bin/env python3
  """Phase 2 helper: print a stable fingerprint of the cargo resolve graph.

  The resolved dependency graph must not change when path deps are rewritten to
  workspace deps. We hash, per resolve node, its sorted list of resolved
  dependency package ids. A byte-identical SHA before and after the refactor
  proves the change is semantically inert.
  """
  import hashlib
  import json
  import subprocess
  import sys


  def main() -> int:
      out = subprocess.run(
          ["cargo", "metadata", "--format-version", "1"],
          capture_output=True,
          text=True,
      )
      if out.returncode != 0:
          sys.stderr.write(out.stderr)
          return out.returncode
      meta = json.loads(out.stdout)
      nodes = meta["resolve"]["nodes"]
      fp = {}
      for node in nodes:
          fp[node["id"]] = sorted(dep["pkg"] for dep in node.get("deps", []))
      blob = json.dumps(fp, sort_keys=True)
      digest = hashlib.sha256(blob.encode()).hexdigest()
      print(f"resolve-node-count: {len(fp)}")
      print(f"resolve-sha256: {digest}")
      print(f"workspace-member-count: {len(meta['workspace_members'])}")
      return 0


  if __name__ == "__main__":
      raise SystemExit(main())
  ```

- [ ] **Step 0.3: Capture the baseline fingerprint to a file.**

  Command:
  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && python3 scripts/_phase2_metadata_fingerprint.py | tee /tmp/phase2-baseline.txt
  ```
  Expected output shape (the SHA is environment-specific; record YOUR value, do not assume this exact hash):
  ```
  resolve-node-count: 1137
  resolve-sha256: <64 hex chars>
  workspace-member-count: 128
  ```
  Fail-closed: if `resolve-node-count` is not 1137 or `workspace-member-count` is not 128, STOP. The tree is not in the state this plan was written against; reconcile before proceeding. Save `/tmp/phase2-baseline.txt`; every later group task diffs against it.

- [ ] **Step 0.4: Capture the baseline lockfile hash.** `Cargo.lock` must not change (no version resolution moves).

  Command:
  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && shasum -a 256 Cargo.lock | tee /tmp/phase2-baseline-lock.txt
  ```
  Expected: one line `<64 hex>  Cargo.lock`. Record it.

---

## Task 1: Add the 97 internal crates to root `[workspace.dependencies]`

This is one edit to one file (`Cargo.toml`). After it, the table declares every internal path ONCE. No member flips yet, so the build is unchanged (members still use their own `path =` lines; the new table entries are simply unused until Task 2+). This is intentionally a separate, reviewable commit.

- [ ] **Step 1.1: Append the internal-crate block to `[workspace.dependencies]`.** The block goes immediately AFTER the existing `chio-metrics-spec = { path = "crates/chio-metrics-spec" }` line (currently the last line of the file, `Cargo.toml:320`). Paths point at CURRENT locations (`crates/chio-x`); the two mismatches are `chio-openai-adapter` -> dir `crates/chio-openai` and the nested redactor.

  Edit `Cargo.toml`: locate the existing final line
  ```toml
  chio-metrics-spec = { path = "crates/chio-metrics-spec" }
  ```
  and append immediately after it:
  ```toml

  # Internal Chio crates centralized here (Phase 2). Each member consumes them as
  # `chio-x = { workspace = true }` (plus per-member features / default-features /
  # optional / package-rename) instead of a scattered `path = "../chio-x"`. Paths
  # point at the crates' CURRENT locations; the later folder move edits only this
  # block. Entries are path-only on purpose: the same crate is consumed with
  # differing default-features by different members, so feature/default-features
  # selection must stay on the member side.
  chio-a2a-adapter = { path = "crates/chio-a2a-adapter" }
  chio-a2a-edge = { path = "crates/chio-a2a-edge" }
  chio-acp-edge = { path = "crates/chio-acp-edge" }
  chio-acp-proxy = { path = "crates/chio-acp-proxy" }
  chio-adversarial-suite = { path = "crates/chio-adversarial-suite" }
  chio-anchor = { path = "crates/chio-anchor" }
  chio-anthropic-tools-adapter = { path = "crates/chio-anthropic-tools-adapter" }
  chio-api-protect = { path = "crates/chio-api-protect" }
  chio-appraisal = { path = "crates/chio-appraisal" }
  chio-arena = { path = "crates/chio-arena" }
  chio-attest-buyer = { path = "crates/chio-attest-buyer" }
  chio-attest-buyer-core = { path = "crates/chio-attest-buyer-core" }
  chio-attest-loopback = { path = "crates/chio-attest-loopback" }
  chio-attest-verify = { path = "crates/chio-attest-verify" }
  chio-autonomy = { path = "crates/chio-autonomy" }
  chio-bedrock-converse-adapter = { path = "crates/chio-bedrock-converse-adapter" }
  chio-binding-helpers = { path = "crates/chio-binding-helpers" }
  chio-cohere-tools-adapter = { path = "crates/chio-cohere-tools-adapter" }
  chio-config = { path = "crates/chio-config" }
  chio-conformance = { path = "crates/chio-conformance" }
  chio-control-plane = { path = "crates/chio-control-plane" }
  chio-core = { path = "crates/chio-core" }
  chio-core-types = { path = "crates/chio-core-types" }
  chio-credentials = { path = "crates/chio-credentials" }
  chio-credit = { path = "crates/chio-credit" }
  chio-cross-protocol = { path = "crates/chio-cross-protocol" }
  chio-custody-hw = { path = "crates/chio-custody-hw" }
  chio-data-guards = { path = "crates/chio-data-guards" }
  chio-data-guards-redactors-default = { path = "crates/chio-data-guards/redactors/default" }
  chio-did = { path = "crates/chio-did" }
  chio-edge-metrics = { path = "crates/chio-edge-metrics" }
  chio-egress-contract = { path = "crates/chio-egress-contract" }
  chio-errors = { path = "crates/chio-errors" }
  chio-eval-receipt = { path = "crates/chio-eval-receipt" }
  chio-external-guards = { path = "crates/chio-external-guards" }
  chio-federation = { path = "crates/chio-federation" }
  chio-federation-authority = { path = "crates/chio-federation-authority" }
  chio-gemini-tools-adapter = { path = "crates/chio-gemini-tools-adapter" }
  chio-governance = { path = "crates/chio-governance" }
  chio-groq-tools-adapter = { path = "crates/chio-groq-tools-adapter" }
  chio-guard-registry = { path = "crates/chio-guard-registry" }
  chio-guard-sdk = { path = "crates/chio-guard-sdk" }
  chio-guard-sdk-macros = { path = "crates/chio-guard-sdk-macros" }
  chio-guards = { path = "crates/chio-guards" }
  chio-hosted-mcp = { path = "crates/chio-hosted-mcp" }
  chio-http-core = { path = "crates/chio-http-core" }
  chio-http-session = { path = "crates/chio-http-session" }
  chio-kernel = { path = "crates/chio-kernel" }
  chio-kernel-browser = { path = "crates/chio-kernel-browser" }
  chio-kernel-core = { path = "crates/chio-kernel-core" }
  chio-lineage = { path = "crates/chio-lineage" }
  chio-link = { path = "crates/chio-link" }
  chio-listing = { path = "crates/chio-listing" }
  chio-log-redact = { path = "crates/chio-log-redact" }
  chio-manifest = { path = "crates/chio-manifest" }
  chio-market = { path = "crates/chio-market" }
  chio-mcp-adapter = { path = "crates/chio-mcp-adapter" }
  chio-mcp-edge = { path = "crates/chio-mcp-edge" }
  chio-mcp-remote = { path = "crates/chio-mcp-remote" }
  chio-mercury-core = { path = "crates/chio-mercury-core" }
  chio-metering = { path = "crates/chio-metering" }
  chio-mistral-tools-adapter = { path = "crates/chio-mistral-tools-adapter" }
  chio-ollama-tools-adapter = { path = "crates/chio-ollama-tools-adapter" }
  chio-open-market = { path = "crates/chio-open-market" }
  chio-openai-adapter = { path = "crates/chio-openai" }
  chio-openapi = { path = "crates/chio-openapi" }
  chio-openapi-mcp-bridge = { path = "crates/chio-openapi-mcp-bridge" }
  chio-otel-receipt-exporter = { path = "crates/chio-otel-receipt-exporter" }
  chio-pheromone = { path = "crates/chio-pheromone" }
  chio-pheromone-relay = { path = "crates/chio-pheromone-relay" }
  chio-pheromone-runtime = { path = "crates/chio-pheromone-runtime" }
  chio-policy = { path = "crates/chio-policy" }
  chio-provider-adapter-core = { path = "crates/chio-provider-adapter-core" }
  chio-provider-conformance = { path = "crates/chio-provider-conformance" }
  chio-replay-corpus = { path = "crates/chio-replay-corpus" }
  chio-reputation = { path = "crates/chio-reputation" }
  chio-revocation-oracle = { path = "crates/chio-revocation-oracle" }
  chio-runtime = { path = "crates/chio-runtime" }
  chio-runtime-core = { path = "crates/chio-runtime-core" }
  chio-runtime-harness = { path = "crates/chio-runtime-harness" }
  chio-selective-disclosure = { path = "crates/chio-selective-disclosure" }
  chio-settle = { path = "crates/chio-settle" }
  chio-siem = { path = "crates/chio-siem" }
  chio-spec-codegen = { path = "crates/chio-spec-codegen" }
  chio-spec-validate = { path = "crates/chio-spec-validate" }
  chio-store-sqlite = { path = "crates/chio-store-sqlite" }
  chio-tee = { path = "crates/chio-tee" }
  chio-tee-frame = { path = "crates/chio-tee-frame" }
  chio-test-support = { path = "crates/chio-test-support" }
  chio-tool-call-fabric = { path = "crates/chio-tool-call-fabric" }
  chio-underwriting = { path = "crates/chio-underwriting" }
  chio-wall-core = { path = "crates/chio-wall-core" }
  chio-wasm-guards = { path = "crates/chio-wasm-guards" }
  chio-web3 = { path = "crates/chio-web3" }
  chio-web3-bindings = { path = "crates/chio-web3-bindings" }
  chio-weights = { path = "crates/chio-weights" }
  chio-workflow = { path = "crates/chio-workflow" }
  ```

- [ ] **Step 1.2: Verify the table parses and every new path resolves.** This is the fail-closed check that no entry points at a nonexistent dir.

  Command:
  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && python3 - <<'PY'
  import re, pathlib, sys
  txt = pathlib.Path("Cargo.toml").read_text()
  start = txt.index("[workspace.dependencies]")
  block = txt[start:]
  bad = []
  count = 0
  for m in re.finditer(r'(?m)^(chio-[a-z0-9-]+)\s*=\s*\{ path = "([^"]+)" \}$', block):
      count += 1
      pkg, p = m.group(1), m.group(2)
      mf = pathlib.Path(p) / "Cargo.toml"
      if not mf.exists():
          bad.append((pkg, p))
  print("internal chio path entries in table:", count)
  if bad:
      print("UNRESOLVED:", bad); sys.exit(1)
  print("all internal chio workspace.dependencies paths resolve OK")
  PY
  ```
  Expected:
  ```
  internal chio path entries in table: 98
  all internal chio workspace.dependencies paths resolve OK
  ```
  Note: 98 = the 97 newly added + the pre-existing `chio-metrics-spec`. Fail-closed: a nonzero exit or any `UNRESOLVED` line stops the phase; fix the offending path in `Cargo.toml`.

- [ ] **Step 1.3: Build to confirm the table is inert (no member uses it yet).**

  Command:
  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && cargo build --workspace 2>&1 | tail -5
  ```
  Expected: `Finished` with no errors. (Cargo allows unused `[workspace.dependencies]` entries; adding them changes nothing until a member writes `workspace = true`.)

- [ ] **Step 1.4: Confirm the resolve fingerprint is unchanged.** Adding unused table entries must not move the graph.

  Command:
  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && python3 scripts/_phase2_metadata_fingerprint.py > /tmp/phase2-after-task1.txt && diff /tmp/phase2-baseline.txt /tmp/phase2-after-task1.txt && echo "FINGERPRINT UNCHANGED"
  ```
  Expected: `diff` prints nothing and you see `FINGERPRINT UNCHANGED`. Fail-closed: any diff stops the phase (means a table entry collided with or shadowed something).

- [ ] **Step 1.5: Commit.**

  Command:
  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && git add Cargo.toml scripts/_phase2_metadata_fingerprint.py && git commit -m "feat: centralize internal crate paths in workspace.dependencies

  Add all 97 internal Chio crates to root [workspace.dependencies] keyed by
  package name with paths at their current crates/chio-x locations. No member
  consumes them yet; this is the single-source-of-truth table that the
  subsequent member flips and the later folder move both build on.

  Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
  ```

---

## Task 2: Build the mechanical sweep tool (the line rewriter)

Flipping the 415 flippable lines (447 single-level `crates/*` path deps minus the 32 renamed aliases the rewriter skips) by hand is error-prone, so the sweep is a single idempotent, scoped rewriter that applies exactly the deterministic transform documented above, to ONLY the manifests you name. It never touches the four standalone workspaces (it operates on explicit file arguments), it leaves renamed-alias lines (key != `package =`) path-based, and it never rewrites a non-internal dependency.

- [ ] **Step 2.1: Write the rewriter.** Create `scripts/_phase2_flip_workspace_deps.py` (temporary helper; deleted in Step 6.3):
  ```python
  #!/usr/bin/env python3
  """Phase 2 helper: flip internal chio path deps to `{ workspace = true }`.

  For each Cargo.toml passed on argv, rewrite every line of the form
      <key> = { [package = "P",] [version = "V",] path = "<...chio-...>" [, ...] }
  to
      <key> = { [package = "P",] workspace = true [, ...] }
  preserving package / default-features / features / optional and dropping any
  version. Only lines whose `path` points at an internal chio crate are touched;
  any other dependency line is left byte-for-byte unchanged. Idempotent: a line
  already using `workspace = true` is skipped.

  RENAMED-DEP GUARD: cargo inherits a workspace dependency by the dependency KEY,
  not by `package = "..."`. A line `chio-core = { package = "chio-core-types",
  workspace = true }` would resolve to the table entry keyed `chio-core` (the real
  chio-core crate), NOT chio-core-types, silently mis-resolving the graph; and
  `chio-openai = { package = "chio-openai-adapter", workspace = true }` would fail
  to parse (`dependency.chio-openai was not found in workspace.dependencies`,
  because the table key is chio-openai-adapter, not chio-openai). So any line whose
  `package = "P"` differs from its dependency key CANNOT be centralized via a
  member-side package= + workspace=true and is left path-based, unchanged. Lines
  whose package equals the key (self-named, redundant) stay flippable. Fail-closed:
  a path-dep line that matches the chio prefix but cannot be parsed into the known
  shape aborts with a nonzero exit and an error naming the file and line.
  """
  import pathlib
  import re
  import sys

  # An internal chio path dep target: ../chio-x, ../../chio-x, ../../crates/chio-x,
  # ../../../crates/chio-x, etc. The package name resolves elsewhere; here we only
  # need to recognize that the path ends in a chio-* crate dir.
  PATH_RE = re.compile(r'path\s*=\s*"((?:\.\./)+(?:crates/)?chio-[a-z0-9/-]+?)"')
  # A single inline-table dep line: `key = { ... }`.
  LINE_RE = re.compile(r'^(?P<indent>\s*)(?P<key>chio-[a-z0-9-]+)\s*=\s*\{(?P<body>.*)\}\s*$')


  def attrs(body: str) -> dict:
      """Parse the inline-table body into an ordered attr map (string values kept raw)."""
      out = {}
      # Split on top-level commas (no nested brackets except features = [...]).
      depth = 0
      cur = ""
      parts = []
      for ch in body:
          if ch == "[":
              depth += 1
          elif ch == "]":
              depth -= 1
          if ch == "," and depth == 0:
              parts.append(cur)
              cur = ""
          else:
              cur += ch
      if cur.strip():
          parts.append(cur)
      for p in parts:
          if "=" not in p:
              continue
          k, v = p.split("=", 1)
          out[k.strip()] = v.strip()
      return out


  def flip_line(line: str, filename: str, lineno: int) -> str:
      m = LINE_RE.match(line)
      if not m:
          return line
      body = m.group("body")
      if "workspace = true" in body or "workspace=true" in body:
          return line  # already flipped; idempotent
      if not PATH_RE.search(body):
          return line  # not an internal chio path dep
      a = attrs(body)
      if "path" not in a:
          sys.stderr.write(f"{filename}:{lineno}: chio path-dep with no parseable path\n")
          raise SystemExit(2)
      # Renamed-dep guard: cargo inherits by KEY, not by package=. If package=
      # differs from the dependency key, member-side package=+workspace=true would
      # resolve to (or fail to find) the wrong table entry, so leave the line
      # path-based and unchanged. Self-named lines (package == key) are flippable.
      if "package" in a:
          pkg = a["package"].strip().strip('"').strip("'")
          if pkg != m.group("key"):
              return line  # renamed dep cannot be centralized; stays path-based
      # Rebuild in canonical order: package, workspace=true, default-features,
      # features, optional. Drop version and path.
      rebuilt = []
      if "package" in a:
          rebuilt.append(f'package = {a["package"]}')
      rebuilt.append("workspace = true")
      if "default-features" in a:
          rebuilt.append(f'default-features = {a["default-features"]}')
      if "features" in a:
          rebuilt.append(f'features = {a["features"]}')
      if "optional" in a:
          rebuilt.append(f'optional = {a["optional"]}')
      known = {"package", "version", "path", "default-features", "features", "optional"}
      unknown = set(a) - known
      if unknown:
          sys.stderr.write(f"{filename}:{lineno}: unexpected attrs {unknown}\n")
          raise SystemExit(2)
      return f'{m.group("indent")}{m.group("key")} = {{ ' + ", ".join(rebuilt) + " }\n"


  def main(argv) -> int:
      changed = 0
      for fn in argv:
          path = pathlib.Path(fn)
          lines = path.read_text().splitlines(keepends=True)
          out = []
          for i, line in enumerate(lines, start=1):
              new = flip_line(line, fn, i)
              if new != line:
                  changed += 1
              out.append(new)
          path.write_text("".join(out))
      print(f"flipped {changed} dependency line(s)")
      return 0


  if __name__ == "__main__":
      raise SystemExit(main(sys.argv[1:]))
  ```

- [ ] **Step 2.2: Unit-check the rewriter against the known attribute shapes (dry, no repo writes).** This proves the transform on every variant the tree contains before you point it at real files.

  Command:
  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && python3 - <<'PY'
  import importlib.util, pathlib, tempfile
  spec = importlib.util.spec_from_file_location("flip", "scripts/_phase2_flip_workspace_deps.py")
  flip = importlib.util.module_from_spec(spec); spec.loader.exec_module(flip)
  cases = {
    'chio-tee-frame = { path = "../chio-tee-frame" }\n':
      'chio-tee-frame = { workspace = true }\n',
    # Renamed dep (key chio-core != package chio-core-types): cargo inherits by
    # key, so this CANNOT be centralized member-side; the rewriter leaves it
    # path-based, UNCHANGED.
    'chio-core = { package = "chio-core-types", path = "../chio-core-types" }\n':
      'chio-core = { package = "chio-core-types", path = "../chio-core-types" }\n',
    'chio-core = { package = "chio-core-types", version = "0.1.0", path = "../chio-core-types" }\n':
      'chio-core = { package = "chio-core-types", version = "0.1.0", path = "../chio-core-types" }\n',
    # Self-named (key == package): redundant but flippable, package kept.
    'chio-kernel = { package = "chio-kernel", path = "../chio-kernel" }\n':
      'chio-kernel = { package = "chio-kernel", workspace = true }\n',
    'chio-core-types = { path = "../chio-core-types", default-features = false }\n':
      'chio-core-types = { workspace = true, default-features = false }\n',
    'chio-federation = { version = "0.1.0", path = "../chio-federation", features = ["demo"] }\n':
      'chio-federation = { workspace = true, features = ["demo"] }\n',
    'chio-web3-bindings = { path = "../chio-web3-bindings", default-features = false, features = ["web3"], optional = true }\n':
      'chio-web3-bindings = { workspace = true, default-features = false, features = ["web3"], optional = true }\n',
    # Renamed dep (key chio-openai != package chio-openai-adapter): no table key
    # named chio-openai exists, so flipping would fail to resolve; the rewriter
    # leaves it path-based, UNCHANGED.
    'chio-openai = { package = "chio-openai-adapter", path = "../chio-openai", features = ["provider-adapter"], optional = true }\n':
      'chio-openai = { package = "chio-openai-adapter", path = "../chio-openai", features = ["provider-adapter"], optional = true }\n',
    'chio-mcp-edge = { path = "../../crates/chio-mcp-edge" }\n':
      'chio-mcp-edge = { workspace = true }\n',
    'chio-guard-sdk = { path = "../../../crates/chio-guard-sdk" }\n':
      'chio-guard-sdk = { workspace = true }\n',
    'serde = { workspace = true, features = ["derive"] }\n':
      'serde = { workspace = true, features = ["derive"] }\n',
    'zeroize = { version = "1.8", features = ["derive"] }\n':
      'zeroize = { version = "1.8", features = ["derive"] }\n',
  }
  ok = True
  for src, want in cases.items():
      got = flip.flip_line(src, "test", 1)
      status = "OK" if got == want else "FAIL"
      if got != want: ok = False
      print(f"[{status}] {src.strip()}\n        -> {got.strip()}")
  print("ALL PASS" if ok else "SOME FAILED")
  PY
  ```
  Expected: every line prints `[OK]`, the two non-chio lines (`serde`, `zeroize`) are returned unchanged, the two renamed-dep lines (`chio-core` aliasing `chio-core-types`, `chio-openai` aliasing `chio-openai-adapter`) are returned UNCHANGED (path-based, because cargo inherits by key not by package=), the self-named `chio-kernel` line flips with its redundant package kept, and the final line is `ALL PASS`. Fail-closed: any `[FAIL]` or `SOME FAILED` means the rewriter is wrong; fix it before touching any manifest.

- [ ] **Step 2.3: Commit the sweep tool.**

  Command:
  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && git add scripts/_phase2_flip_workspace_deps.py && git commit -m "chore: add Phase 2 internal-dep flip helper

  Idempotent, fail-closed rewriter that flips internal chio path deps to
  { workspace = true } while preserving package rename, features,
  default-features, and optional, and dropping redundant version pins. Verified
  against every attribute shape present in the tree.

  Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
  ```

---

## Tasks 3.x: Flip member manifests group by group (one commit per group)

Each group below flips a slice of `crates/*/Cargo.toml` files, then runs the same fail-closed loop: build, fingerprint diff vs baseline, lockfile diff, commit. Groups follow the spec's 11-folder taxonomy so each commit is reviewable and a regression localizes to one domain. A flip that breaks resolution stops the phase.

The shared per-group verification block (referenced as "VERIFY+COMMIT(<group>)") is:
```bash
cd /Users/connor/Medica/backbay/standalone/arc
cargo build --workspace 2>&1 | tail -3
python3 scripts/_phase2_metadata_fingerprint.py > /tmp/phase2-after.txt
diff /tmp/phase2-baseline.txt /tmp/phase2-after.txt && echo "FINGERPRINT UNCHANGED"
shasum -a 256 Cargo.lock | diff /tmp/phase2-baseline-lock.txt - && echo "LOCK UNCHANGED"
```
Fail-closed: if `cargo build` errors, or `diff` prints anything (fingerprint or lock changed), STOP and investigate before committing. The expected output is `Finished`, `FINGERPRINT UNCHANGED`, `LOCK UNCHANGED`.

- [ ] **Step 3.1: Flip the `core` + `kernel` groups.** These are the highest in-degree targets; doing them first surfaces any systemic rewriter problem immediately.

  Command (flip):
  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && python3 scripts/_phase2_flip_workspace_deps.py \
    crates/chio-core/Cargo.toml \
    crates/chio-core-types/Cargo.toml \
    crates/chio-errors/Cargo.toml \
    crates/chio-adversarial-suite/Cargo.toml \
    crates/chio-arena/Cargo.toml \
    crates/chio-kernel/Cargo.toml \
    crates/chio-kernel-browser/Cargo.toml \
    crates/chio-kernel-core/Cargo.toml \
    crates/chio-kernel-mobile/Cargo.toml \
    crates/chio-runtime/Cargo.toml \
    crates/chio-runtime-core/Cargo.toml \
    crates/chio-runtime-harness/Cargo.toml \
    crates/chio-lsp/Cargo.toml
  ```
  Expected: `flipped N dependency line(s)` with N > 0. Then run the VERIFY+COMMIT block above; on success commit:
  ```bash
  git add crates/chio-core crates/chio-core-types crates/chio-errors crates/chio-adversarial-suite crates/chio-arena crates/chio-kernel crates/chio-kernel-browser crates/chio-kernel-core crates/chio-kernel-mobile crates/chio-runtime crates/chio-runtime-core crates/chio-runtime-harness crates/chio-lsp
  git commit -m "refactor: flip core+kernel crates to workspace deps

  Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
  ```

- [ ] **Step 3.2: Flip the `guards` group.**

  Command (flip):
  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && python3 scripts/_phase2_flip_workspace_deps.py \
    crates/chio-data-guards/Cargo.toml \
    crates/chio-data-guards/redactors/default/Cargo.toml \
    crates/chio-external-guards/Cargo.toml \
    crates/chio-guard-registry/Cargo.toml \
    crates/chio-guard-sdk/Cargo.toml \
    crates/chio-guard-sdk-macros/Cargo.toml \
    crates/chio-guards/Cargo.toml \
    crates/chio-policy/Cargo.toml \
    crates/chio-wasm-guards/Cargo.toml
  ```
  Note `crates/chio-wasm-guards/Cargo.toml` is already modified in the working tree (pre-existing change); the flip only edits its chio path-dep lines and leaves the rest intact. Run VERIFY+COMMIT, then:
  ```bash
  git add crates/chio-data-guards crates/chio-external-guards crates/chio-guard-registry crates/chio-guard-sdk crates/chio-guard-sdk-macros crates/chio-guards crates/chio-policy crates/chio-wasm-guards
  git commit -m "refactor: flip guards crates to workspace deps

  Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
  ```

- [ ] **Step 3.3: Flip the `protocol` group.**

  Command (flip):
  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && python3 scripts/_phase2_flip_workspace_deps.py \
    crates/chio-a2a-adapter/Cargo.toml \
    crates/chio-a2a-edge/Cargo.toml \
    crates/chio-acp-edge/Cargo.toml \
    crates/chio-acp-proxy/Cargo.toml \
    crates/chio-ag-ui-proxy/Cargo.toml \
    crates/chio-anthropic-tools-adapter/Cargo.toml \
    crates/chio-bedrock-converse-adapter/Cargo.toml \
    crates/chio-cohere-tools-adapter/Cargo.toml \
    crates/chio-cross-protocol/Cargo.toml \
    crates/chio-edge-metrics/Cargo.toml \
    crates/chio-egress-contract/Cargo.toml \
    crates/chio-envoy-ext-authz/Cargo.toml \
    crates/chio-gemini-tools-adapter/Cargo.toml \
    crates/chio-groq-tools-adapter/Cargo.toml \
    crates/chio-mcp-adapter/Cargo.toml \
    crates/chio-mcp-edge/Cargo.toml \
    crates/chio-mcp-remote/Cargo.toml \
    crates/chio-mistral-tools-adapter/Cargo.toml \
    crates/chio-ollama-tools-adapter/Cargo.toml \
    crates/chio-openai/Cargo.toml \
    crates/chio-openapi/Cargo.toml \
    crates/chio-openapi-mcp-bridge/Cargo.toml \
    crates/chio-provider-adapter-core/Cargo.toml \
    crates/chio-provider-conformance/Cargo.toml \
    crates/chio-tool-call-fabric/Cargo.toml \
    crates/chio-tower/Cargo.toml \
    crates/chio-hosted-mcp/Cargo.toml
  ```
  Note `crates/chio-ag-ui-proxy` has a pre-existing source change (`src/proxy.rs`); the flip touches only its `Cargo.toml`. Run VERIFY+COMMIT, then:
  ```bash
  git add crates/chio-a2a-adapter crates/chio-a2a-edge crates/chio-acp-edge crates/chio-acp-proxy crates/chio-ag-ui-proxy/Cargo.toml crates/chio-anthropic-tools-adapter crates/chio-bedrock-converse-adapter crates/chio-cohere-tools-adapter crates/chio-cross-protocol crates/chio-edge-metrics crates/chio-egress-contract crates/chio-envoy-ext-authz crates/chio-gemini-tools-adapter crates/chio-groq-tools-adapter crates/chio-mcp-adapter crates/chio-mcp-edge crates/chio-mcp-remote crates/chio-mistral-tools-adapter crates/chio-ollama-tools-adapter crates/chio-openai crates/chio-openapi crates/chio-openapi-mcp-bridge crates/chio-provider-adapter-core crates/chio-provider-conformance crates/chio-tool-call-fabric crates/chio-tower crates/chio-hosted-mcp
  git commit -m "refactor: flip protocol crates to workspace deps

  Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
  ```

- [ ] **Step 3.4: Flip the `economy` group.**

  Command (flip):
  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && python3 scripts/_phase2_flip_workspace_deps.py \
    crates/chio-anchor/Cargo.toml \
    crates/chio-appraisal/Cargo.toml \
    crates/chio-autonomy/Cargo.toml \
    crates/chio-credit/Cargo.toml \
    crates/chio-link/Cargo.toml \
    crates/chio-listing/Cargo.toml \
    crates/chio-market/Cargo.toml \
    crates/chio-open-market/Cargo.toml \
    crates/chio-settle/Cargo.toml \
    crates/chio-underwriting/Cargo.toml \
    crates/chio-web3/Cargo.toml \
    crates/chio-web3-bindings/Cargo.toml \
    crates/chio-metering/Cargo.toml
  ```
  Run VERIFY+COMMIT, then:
  ```bash
  git add crates/chio-anchor crates/chio-appraisal crates/chio-autonomy crates/chio-credit crates/chio-link crates/chio-listing crates/chio-market crates/chio-open-market crates/chio-settle crates/chio-underwriting crates/chio-web3 crates/chio-web3-bindings crates/chio-metering
  git commit -m "refactor: flip economy crates to workspace deps

  Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
  ```

- [ ] **Step 3.5: Flip the `trust` group.**

  Command (flip):
  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && python3 scripts/_phase2_flip_workspace_deps.py \
    crates/chio-replay-corpus/Cargo.toml \
    crates/chio-attest-buyer/Cargo.toml \
    crates/chio-attest-buyer-core/Cargo.toml \
    crates/chio-attest-verify/Cargo.toml \
    crates/chio-attest-loopback/Cargo.toml \
    crates/chio-custody-hw/Cargo.toml \
    crates/chio-weights/Cargo.toml \
    crates/chio-tee/Cargo.toml \
    crates/chio-tee-frame/Cargo.toml \
    crates/chio-credentials/Cargo.toml \
    crates/chio-did/Cargo.toml \
    crates/chio-federation/Cargo.toml \
    crates/chio-federation-authority/Cargo.toml \
    crates/chio-governance/Cargo.toml \
    crates/chio-pheromone/Cargo.toml \
    crates/chio-pheromone-relay/Cargo.toml \
    crates/chio-pheromone-runtime/Cargo.toml \
    crates/chio-revocation-oracle/Cargo.toml \
    crates/chio-reputation/Cargo.toml \
    crates/chio-selective-disclosure/Cargo.toml
  ```
  Run VERIFY+COMMIT, then:
  ```bash
  git add crates/chio-replay-corpus crates/chio-attest-buyer crates/chio-attest-buyer-core crates/chio-attest-verify crates/chio-attest-loopback crates/chio-custody-hw crates/chio-weights crates/chio-tee crates/chio-tee-frame crates/chio-credentials crates/chio-did crates/chio-federation crates/chio-federation-authority crates/chio-governance crates/chio-pheromone crates/chio-pheromone-relay crates/chio-pheromone-runtime crates/chio-revocation-oracle crates/chio-reputation crates/chio-selective-disclosure
  git commit -m "refactor: flip trust crates to workspace deps

  Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
  ```

- [ ] **Step 3.6: Flip the `observability` + `platform` + `products` groups.** (`chio-metrics-spec` already uses the workspace dep and is skipped by the idempotent rewriter, so including its manifest is a no-op; it is omitted below for clarity.)

  Command (flip):
  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && python3 scripts/_phase2_flip_workspace_deps.py \
    crates/chio-lineage/Cargo.toml \
    crates/chio-log-redact/Cargo.toml \
    crates/chio-otel-receipt-exporter/Cargo.toml \
    crates/chio-siem/Cargo.toml \
    crates/chio-config/Cargo.toml \
    crates/chio-control-plane/Cargo.toml \
    crates/chio-manifest/Cargo.toml \
    crates/chio-store-sqlite/Cargo.toml \
    crates/chio-workflow/Cargo.toml \
    crates/chio-http-core/Cargo.toml \
    crates/chio-http-session/Cargo.toml \
    crates/chio-api-protect/Cargo.toml \
    crates/chio-cli/Cargo.toml \
    crates/chio-mercury/Cargo.toml \
    crates/chio-mercury-core/Cargo.toml \
    crates/chio-wall/Cargo.toml \
    crates/chio-wall-core/Cargo.toml
  ```
  Run VERIFY+COMMIT, then:
  ```bash
  git add crates/chio-lineage crates/chio-log-redact crates/chio-otel-receipt-exporter crates/chio-siem crates/chio-config crates/chio-control-plane crates/chio-manifest crates/chio-store-sqlite crates/chio-workflow crates/chio-http-core crates/chio-http-session crates/chio-api-protect crates/chio-cli crates/chio-mercury crates/chio-mercury-core crates/chio-wall crates/chio-wall-core
  git commit -m "refactor: flip observability, platform, and products crates to workspace deps

  Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
  ```

- [ ] **Step 3.7: Flip the `sdk` + `tooling` groups.** Excludes the standalone `verdict_matrix` parent (own `[workspace]`, Phase 6). Includes the member `verdict_matrix/drivers/lambda` only if it has internal path deps; per validation it uses only `workspace = true` deps already, so the rewriter is a no-op there. `chio-test-support` and `chio-metrics-spec` have no internal chio deps and are no-ops; safe to include.

  Command (flip):
  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && python3 scripts/_phase2_flip_workspace_deps.py \
    crates/chio-binding-helpers/Cargo.toml \
    crates/chio-bindings-ffi/Cargo.toml \
    crates/chio-cpp-kernel-ffi/Cargo.toml \
    crates/chio-eval-receipt/Cargo.toml \
    crates/chio-conformance/Cargo.toml \
    crates/chio-spec-codegen/Cargo.toml \
    crates/chio-spec-validate/Cargo.toml \
    crates/chio-test-support/Cargo.toml
  ```
  Run VERIFY+COMMIT, then:
  ```bash
  git add crates/chio-binding-helpers crates/chio-bindings-ffi crates/chio-cpp-kernel-ffi crates/chio-eval-receipt crates/chio-conformance/Cargo.toml crates/chio-spec-codegen crates/chio-spec-validate crates/chio-test-support
  git commit -m "refactor: flip sdk and tooling crates to workspace deps

  Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
  ```
  Note: `git add crates/chio-conformance/Cargo.toml` is scoped to the manifest so the staged change cannot accidentally include the untracked-or-standalone `verdict_matrix` subtree.

---

## Task 4: Flip the external (non-crates) root members

These manifests live outside `crates/` but ARE root workspace members, so they inherit the table and can flip too. They use multi-level paths (`../../crates/chio-x`, `../crates/chio-x`, `../../../crates/chio-x`); the rewriter's `PATH_RE` already matches those. The standalone `aws-bedrock/control-plane` and the two `bench/*` and `editors/zed-chio` members carry NO internal chio path deps (verified) so they are not listed.

- [ ] **Step 4.1: Flip integrations, examples, tests, formal, and xtask members.**

  Command (flip):
  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && python3 scripts/_phase2_flip_workspace_deps.py \
    integrations/mcp-adapter/Cargo.toml \
    examples/bilateral-invocation/Cargo.toml \
    examples/chio-3vendor/Cargo.toml \
    examples/cross-provider-policy/Cargo.toml \
    examples/hello-a2a/Cargo.toml \
    examples/hello-acp/Cargo.toml \
    examples/hello-mcp/Cargo.toml \
    examples/hello-tool/Cargo.toml \
    examples/otel-genai/Cargo.toml \
    examples/guards/enriched-inspector/Cargo.toml \
    examples/guards/tool-gate/Cargo.toml \
    tests/e2e/Cargo.toml \
    tests/replay/Cargo.toml \
    formal/diff-tests/Cargo.toml \
    xtask/Cargo.toml
  ```
  Note `tests/e2e/Cargo.toml` is already modified in the working tree (pre-existing change); the flip edits only its chio path-dep lines. Run VERIFY+COMMIT, then:
  ```bash
  git add integrations/mcp-adapter/Cargo.toml examples/bilateral-invocation/Cargo.toml examples/chio-3vendor/Cargo.toml examples/cross-provider-policy/Cargo.toml examples/hello-a2a/Cargo.toml examples/hello-acp/Cargo.toml examples/hello-mcp/Cargo.toml examples/hello-tool/Cargo.toml examples/otel-genai/Cargo.toml examples/guards/enriched-inspector/Cargo.toml examples/guards/tool-gate/Cargo.toml tests/e2e/Cargo.toml tests/replay/Cargo.toml formal/diff-tests/Cargo.toml xtask/Cargo.toml
  git commit -m "refactor: flip external workspace members to workspace deps

  Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
  ```

---

## Task 5: Confirm the four standalone workspaces are untouched (explicit out-of-scope check)

The spec is explicit: `fuzz/`, `crates/chio-conformance/verdict_matrix`, `sdks/rust/chio-guard-sdk-compat`, and `sdks/lambda/chio-lambda-extension` each declare their own `[workspace]` and do NOT inherit the root `[workspace.dependencies]`. Their path deps stay as-is here and are rewritten in Phase 6. This task asserts the sweep did not touch them.

- [ ] **Step 5.1: Assert the four standalone manifests still carry their original path deps.** Fail-closed: any of these flipped to `{ workspace = true }` would be a bug (the dep would not resolve, since the standalone workspace has no such table entry).

  Command:
  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && for f in \
    fuzz/Cargo.toml \
    crates/chio-conformance/verdict_matrix/Cargo.toml \
    sdks/rust/chio-guard-sdk-compat/Cargo.toml \
    sdks/lambda/chio-lambda-extension/Cargo.toml; do
      if grep -qE 'chio-[a-z0-9-]+ *= *\{[^}]*workspace *= *true' "$f"; then
        echo "ERROR: $f was flipped (must stay path-based in Phase 2)"; exit 1
      fi
      n=$(grep -cE 'path *= *"(\.\./)+(crates/)?chio-' "$f"); echo "$f : $n path deps intact"
    done && echo "ALL STANDALONE WORKSPACES UNTOUCHED"
  ```
  Expected: each line reports its intact path-dep count (`fuzz/Cargo.toml` ~23, `verdict_matrix` 3, `chio-guard-sdk-compat` 1, `chio-lambda-extension` 4) and the final line is `ALL STANDALONE WORKSPACES UNTOUCHED`. Fail-closed: any `ERROR:` line means the sweep over-reached; revert that file's flip.

- [ ] **Step 5.2: Confirm git did not stage any standalone-workspace manifest.**

  Command:
  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && git log --oneline -8 --name-only | grep -E 'fuzz/Cargo.toml|verdict_matrix/Cargo.toml|chio-guard-sdk-compat/Cargo.toml|chio-lambda-extension/Cargo.toml' && echo "UNEXPECTED" || echo "NONE OF THE STANDALONE MANIFESTS WERE COMMITTED (correct)"
  ```
  Expected: `NONE OF THE STANDALONE MANIFESTS WERE COMMITTED (correct)`.

---

## Task 6: Full-gate verification and cleanup

- [ ] **Step 6.1: Confirm no flippable internal `path = "../chio-..."` line survives inside the flipped surface.** Every non-renamed internal dep in a root member must now be `{ workspace = true }`. The legitimate remaining `../chio-` / `crates/chio-` path strings are: the four standalone workspaces (Task 5), the root `[workspace.dependencies]` table itself (where the single declaration lives), and the 32 renamed alias lines whose dependency key differs from `package =` (31 `chio-core` aliasing `chio-core-types`, 1 `chio-openai` aliasing `chio-openai-adapter`, plus the four external `chio-core` aliases) - cargo inherits by key not by package=, so those CANNOT be centralized member-side and stay path-based on purpose.

  Command:
  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && python3 - <<'PY'
  import re, pathlib, glob, sys
  standalone = {
    "fuzz/Cargo.toml",
    "crates/chio-conformance/verdict_matrix/Cargo.toml",
    "sdks/rust/chio-guard-sdk-compat/Cargo.toml",
    "sdks/lambda/chio-lambda-extension/Cargo.toml",
  }
  member_globs = ["crates/*/Cargo.toml",
    "crates/chio-data-guards/redactors/default/Cargo.toml",
    "crates/chio-conformance/verdict_matrix/drivers/lambda/Cargo.toml",
    "integrations/aws-bedrock/control-plane/Cargo.toml","integrations/mcp-adapter/Cargo.toml",
    "examples/*/Cargo.toml","examples/guards/*/Cargo.toml","tests/e2e/Cargo.toml","tests/replay/Cargo.toml",
    "formal/diff-tests/Cargo.toml","xtask/Cargo.toml","bench/healthcare-pilot-capacity/Cargo.toml",
    "bench/ttfrh/Cargo.toml","editors/zed-chio/Cargo.toml"]
  files = set()
  [files.update(glob.glob(g)) for g in member_globs]
  files -= standalone
  bad = []
  for f in sorted(files):
      for i, line in enumerate(pathlib.Path(f).read_text().splitlines(), 1):
          if not re.search(r'path\s*=\s*"(?:\.\./)+(?:crates/)?chio-', line):
              continue
          # Whitelist the renamed alias lines: cargo inherits by dependency key,
          # not by package=, so a line whose key differs from its package= CANNOT
          # be centralized member-side and legitimately stays path-based (the 32
          # rename lines: 31 chio-core -> chio-core-types, 1 chio-openai ->
          # chio-openai-adapter, plus the four external chio-core aliases). These
          # are intentionally NOT residual.
          km = re.match(r'\s*([A-Za-z0-9_-]+)\s*=', line)
          pm = re.search(r'package\s*=\s*"([^"]+)"', line)
          if km and pm and pm.group(1) != km.group(1):
              continue
          bad.append(f"{f}:{i}: {line.strip()}")
  if bad:
      print("RESIDUAL INTERNAL PATH DEPS:"); print("\n".join(bad)); sys.exit(1)
  print("no residual internal chio path deps in any flipped member (renamed aliases excepted)")
  PY
  ```
  Expected: `no residual internal chio path deps in any flipped member (renamed aliases excepted)`. The 32 renamed alias lines (key != package) are whitelisted and remain path-based on purpose; only a non-renamed dep still on a `path =` line is RESIDUAL. Fail-closed: any residual line means a flippable manifest was missed; flip it (re-run the rewriter on that one file) and re-verify.

- [ ] **Step 6.2: Run the full repo gate.**

  Command:
  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check
  ```
  Expected: all four commands exit 0; the final `cargo fmt --all -- --check` prints nothing. Manifests are not formatted by `cargo fmt` (it formats Rust source), so the only way this fails is a real compile/test/lint regression - which would mean the flip changed behavior and must be investigated, not waved through. Fail-closed: any nonzero exit stops the phase.

- [ ] **Step 6.3: Final fingerprint and lock confirmation, then remove the temporary helpers.** The resolve graph and lockfile must still match the Task 0 baseline.

  Command:
  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc
  python3 scripts/_phase2_metadata_fingerprint.py > /tmp/phase2-final.txt
  diff /tmp/phase2-baseline.txt /tmp/phase2-final.txt && echo "FINAL FINGERPRINT MATCHES BASELINE"
  shasum -a 256 Cargo.lock | diff /tmp/phase2-baseline-lock.txt - && echo "FINAL LOCK MATCHES BASELINE"
  git rm -q scripts/_phase2_metadata_fingerprint.py scripts/_phase2_flip_workspace_deps.py
  ```
  Expected: `FINAL FINGERPRINT MATCHES BASELINE`, `FINAL LOCK MATCHES BASELINE`, and the two helper scripts are removed from git. Fail-closed: any fingerprint or lock diff at this point is a hard stop; the centralization changed the dependency graph and must be reverted and re-investigated.

- [ ] **Step 6.4: Commit the cleanup.**

  Command:
  ```bash
  cd /Users/connor/Medica/backbay/standalone/arc && git commit -m "chore: remove Phase 2 sweep helpers

  Centralization is complete and gate-verified; the one-shot rewriter and
  fingerprint helper are no longer needed.

  Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
  ```

---

## Self-Review

### (1) Spec-item coverage map (Phase 2 of the design spec, section 3)

| Spec / task requirement | Covered by |
| --- | --- |
| Add the missing internal crates to the root table keyed by package name, paths at current `crates/chio-x` | Task 1 (Step 1.1 lists all 97 entries; Step 1.2 asserts they resolve) |
| Flip each member's path dep to `{ workspace = true }` | Tasks 3.1-3.7 (all `crates/*` members) + Task 4 (external members) |
| Handle the 32 `package =` rename cases (cannot centralize) | Rewriter Step 2.1 guard leaves any line whose `package =` differs from its key path-based, UNCHANGED; Step 2.2 verifies `chio-core`/`chio-openai` renames stay path-based; Step 6.1 whitelists them; table still has `chio-openai-adapter` keyed to dir `crates/chio-openai` for self-named/external consumers |
| Preserve `features =` on the 25 intra-`crates/` cases | Rewriter preserves `features` on flippable lines; Step 2.2 verifies `["demo"]` (`chio-federation`) and `["web3"]` (`chio-web3-bindings`) flip with features kept. The `["provider-adapter"]` case rides on the renamed `chio-openai` line, so the rename guard leaves it path-based (verified UNCHANGED in Step 2.2). |
| Preserve `optional` flags | Rewriter preserves `optional`; Step 2.2 verifies the `optional = true` case |
| Preserve `default-features = false` on the 10 cases | Rewriter preserves it; Step 2.2 verifies; Context section explains why it must stay member-side |
| Exclude the four standalone workspaces (note out-of-scope) | Context section + Task 5 (asserts untouched) + Step 6.1 excludes them |
| Verify dependency graph semantically unchanged (`cargo metadata` / cargo tree diff) | Task 0 baseline + per-group fingerprint diff + Step 6.3 final diff (resolve-graph SHA + member count + lockfile) |
| Fail-closed: any crate that fails to resolve stops the phase | Step 1.2 (path resolution), per-group VERIFY+COMMIT (build + fingerprint), Step 5.1, Step 6.1, Step 6.3 all hard-stop |
| No directory moves | No task moves a directory; all paths stay `crates/chio-x`; Task 1 comment states paths are current locations |
| Small number of mechanical, verifiable tasks with build + diff + commit each | 7 group tasks + 1 external task, each ending in build + metadata diff + lock diff + commit |
| Provide the actual commands | Every step shows the exact command and expected output |

Gaps found and resolved during review:
- The spec says "90 missing internal crates"; the verified count is 97. Resolved by documenting the reconciliation in the Context section and using 97 everywhere (the table, Step 1.2 expects 98 total = 97 + existing `chio-metrics-spec`). Using 90 would have left `chio-eval-receipt`, `chio-guard-sdk`, `chio-guard-sdk-macros`, `chio-otel-receipt-exporter`, `chio-spec-validate`, `chio-data-guards-redactors-default`, and the `chio-core`/`chio-core-types` split unresolvable for external members - a fail-closed build break. Fixed.
- The spec mentions "447 member path deps" but does not call out that `version = "0.1.0"` (44 lines) cannot coexist with `workspace = true`. Resolved by making the rewriter DROP `version` and documenting the Cargo rule (Context rule 3) plus a unit case in Step 2.2.
- The nested redactor (`chio-data-guards-redactors-default`, path `crates/chio-data-guards/redactors/default`) and the `chio-openai` dir/package mismatch are the only non-uniform entries; both are explicitly encoded in the Task 1 table and the Step 2.2 unit cases.
- Renamed deps cannot be centralized member-side: cargo inherits a workspace dependency by its KEY, not by `package =`. A member line `chio-core = { package = "chio-core-types", workspace = true }` resolves to the table entry keyed `chio-core` (the real `chio-core`, an E0425 build break), and `chio-openai = { package = "chio-openai-adapter", workspace = true }` fails to parse (`dependency.chio-openai was not found in workspace.dependencies`). Both were reproduced. Resolved by the rename guard in Step 2.1 (any line whose `package =` differs from its key stays path-based, UNCHANGED), the corrected UNCHANGED expectations in Step 2.2, and the whitelist in Step 6.1. Fully centralizing the 32 renamed lines would require renaming the dependency key and editing consuming source (`use chio_core` -> `use chio_core_types`), which is OUT OF SCOPE for this phase; leaving them path-based is the correct fail-closed choice.

### (2) Placeholder / red-flag scan

- No "TBD", "TODO", "implement later", "similar to Task N", or "write tests for the above" appears. Every code block is complete: the full 97-entry table, the complete rewriter source, the complete fingerprint script, and every shell command with its expected output.
- No deferred IDs or "see above" hand-waves. Each group task lists every file explicitly.
- Expected outputs that are environment-specific (the resolve SHA, the lock SHA) are explicitly flagged as "record YOUR value", with the stable structural invariants (node count 1137, member count 128) given as the hard fail-closed checks.

### (3) Type / name / method consistency

- Helper script names are consistent everywhere: `scripts/_phase2_metadata_fingerprint.py` (Steps 0.2, 0.3, 1.4, 3.x VERIFY, 6.3) and `scripts/_phase2_flip_workspace_deps.py` (Steps 2.1, 2.2, 2.3, 3.x, 4.1). Both are `git rm`-ed in Step 6.3, matching their `git add` in Steps 1.5 and 2.3.
- The rewriter's canonical output order (`package, workspace = true, default-features, features, optional`) is consistent between the Step 2.1 source and the Step 2.2 expected outputs (e.g. `chio-web3-bindings = { workspace = true, default-features = false, features = ["web3"], optional = true }`).
- Package keys in the root table match the package names verified from each crate's `[package] name` (e.g. `chio-openai-adapter` not `chio-openai`; `chio-data-guards-redactors-default`). The member-side renamed-alias lines (`chio-core` aliasing `chio-core-types`, `chio-openai` aliasing `chio-openai-adapter`) are left path-based UNCHANGED by the rewriter's rename guard (cargo inherits by key, not by `package =`), so member source `use chio_core::...` / `use chio_openai::...` continues to compile unchanged.
- The fingerprint invariant (resolve-graph SHA) is the same artifact in Task 0 (baseline), every group (after), and Step 6.3 (final); the diff target file `/tmp/phase2-baseline.txt` is consistent throughout.
- Cargo behavior claims (`version` rejected with `workspace = true`; `default-features`/`features`/`optional`/`package` allowed member-side) are each grounded in an existing in-tree precedent cited in the Context section (`reqwest`, `chio-metrics-spec`).

Self-review checks (1), (2), and (3) were each run; the gaps above were fixed inline. Self-review passed.
