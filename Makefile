# Chio top-level Makefile.
#
# This file is intentionally a thin orchestrator: every target shells out to
# the canonical tool (cargo xtask codegen, the per-language regen scripts) and
# does not duplicate logic. Source of truth for codegen stays in
# `xtask/src/main.rs` and `xtask/codegen-tools.lock.toml`.
#
# Owner: M01 (single-owner trajectory, see EXECUTION-BOARD.md section 5).

.PHONY: codegen-check codegen-check-rust codegen-check-python codegen-check-ts codegen-check-go ts-codegen-deps

# REQUIRES on PATH:
#   - cargo (Rust toolchain) for all four lanes.
#   - uv (https://github.com/astral-sh/uv) for the python lane; the xtask
#     invokes `uv tool run --from datamodel-code-generator==<pin>`.
#   - go (golang.org/dl) for the go lane; the regen script bundles schemas
#     and feeds them to `oapi-codegen v2.4.1`.
#   - npm (Node 18+) for the ts lane; we install the pinned
#     `json-schema-to-typescript@15.0.4` into
#     `sdks/typescript/scripts/node_modules/` via `npm ci` automatically.
# If any of uv / go is missing the per-language `cargo xtask codegen --lang
# <lang> --check` step exits non-zero with a clear error message; we let
# that surface rather than re-implementing the check here.

# Aggregator target: runs all four codegen --check lanes in series and fails
# if any one drifts from committed bytes. Used by the spec-drift CI workflow
# (.github/workflows/spec-drift.yml) and by humans running the gate locally.
codegen-check: codegen-check-rust codegen-check-python codegen-check-ts codegen-check-go
	@echo "codegen-check: all four lanes (rust, python, ts, go) in sync with committed bytes"

codegen-check-rust:
	cargo xtask codegen --lang rust --check

codegen-check-python:
	cargo xtask codegen --lang python --check

# The ts lane needs the pinned `json-schema-to-typescript` install under
# `sdks/typescript/scripts/node_modules/`. We run `npm ci` first as a
# prerequisite so the gate is self-contained on a clean checkout.
codegen-check-ts: ts-codegen-deps
	cargo xtask codegen --lang ts --check

ts-codegen-deps:
	cd sdks/typescript/scripts && npm ci

codegen-check-go:
	cargo xtask codegen --lang go --check
