# Chio top-level Makefile.
#
# Thin orchestrator: every target shells out to cargo, cargo xtask, or an
# existing scripts/*.sh file. Source of truth for codegen stays in
# xtask/src/main.rs and xtask/codegen-tools.lock.toml.
#
# Owner: see CODEOWNERS.
#
# REQUIRES on PATH (by tier):
#   - cargo (Rust 1.93+, see rust-toolchain.toml) for build/test/ci targets.
#   - protobuf-compiler for several workspace crates (CI installs via apt).
#   - uv for python codegen; go for go codegen; npm (Node 20+) for ts codegen.
#   - docker for kb-* and docker-demo targets.
#   - cargo-vet, cargo-deny (optional) for supply-chain targets.
#   - cmake, build-essential, libcurl for sdk-parity and heavy SDK checks.

.DEFAULT_GOAL := help

REPO_ROOT := $(shell git rev-parse --show-toplevel)
CARGO ?= cargo
CHIO_RELEASE := $(REPO_ROOT)/target/release/chio
KB_DIR ?= tools/knowledge-base

.PHONY: help build test test-all fmt fmt-check clippy clean gate chio chio-dev \
	ci ci-workspace proptest-coverage crate-paths \
	codegen codegen-rust codegen-python codegen-ts codegen-go \
	codegen-errors codegen-snippets codegen-vectors codegen-eval-receipt \
	codegen-check codegen-check-rust codegen-check-python codegen-check-ts codegen-check-go \
	ts-codegen-deps spec-drift \
	sdk-parity sdk-bindings-parity sdk-py sdk-go sdk-cpp sdk-drogon sdk-ts-deps \
	vet deny supply-chain \
	qualify-release qualify-trust qualify-portable-browser qualify-mobile-kernel \
	qualify-cross-protocol qualify-bounded \
	coverage fuzz fuzz-budget kani kani-smoke mutants mutants-fuzz-cocoverage \
	docker-demo-up docker-demo-down docker-demo-smoke \
	setup-merge-drivers streaming-test streaming-integration \
	kb-lock-check kb-up kb-down kb-reset kb-reseed kb-update kb-live kb-status \
	kb-smoke kb-eval kb-seed-memory kb-dogfood

# ---------------------------------------------------------------------------
# Tier 1: Daily development
# ---------------------------------------------------------------------------

help:
	@echo "Chio Makefile targets (run make <target>):"
	@echo ""
	@echo "Tier 1 - daily:"
	@echo "  build test test-all fmt fmt-check clippy clean gate chio chio-dev"
	@echo ""
	@echo "Tier 2 - CI:"
	@echo "  ci              PR-tier gate (mirrors ci.yml check job)"
	@echo "  ci-workspace    heavier local gate (formal proof report)"
	@echo "  proptest-coverage crate-paths"
	@echo ""
	@echo "Tier 3 - spec/codegen:"
	@echo "  codegen codegen-rust codegen-python codegen-ts codegen-go"
	@echo "  codegen-errors codegen-snippets codegen-vectors codegen-eval-receipt"
	@echo "  codegen-check codegen-check-rust codegen-check-python codegen-check-ts codegen-check-go"
	@echo "  spec-drift"
	@echo ""
	@echo "Tier 4 - SDK and supply chain:"
	@echo "  sdk-parity sdk-bindings-parity sdk-py sdk-go sdk-cpp sdk-drogon sdk-ts-deps"
	@echo "  vet deny supply-chain"
	@echo ""
	@echo "Tier 5 - heavy (slow):"
	@echo "  qualify-release qualify-trust qualify-portable-browser qualify-mobile-kernel"
	@echo "  qualify-cross-protocol qualify-bounded"
	@echo "  coverage fuzz fuzz-budget kani kani-smoke mutants mutants-fuzz-cocoverage"
	@echo ""
	@echo "Tier 6 - local infra:"
	@echo "  docker-demo-up docker-demo-down docker-demo-smoke"
	@echo "  setup-merge-drivers streaming-test streaming-integration"
	@echo "  kb-up kb-down kb-reset kb-reseed kb-update kb-live kb-status kb-smoke kb-eval"
	@echo "  kb-seed-memory kb-dogfood kb-lock-check"

build:
	$(CARGO) build --workspace

test:
	$(CARGO) test --workspace --exclude chio-wasm-guards
	$(CARGO) test -p chio-wasm-guards --lib

test-all:
	$(CARGO) test --workspace

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

clippy:
	$(CARGO) clippy --workspace --lib --bins --examples -- -D warnings

clean:
	$(CARGO) clean

gate: build test-all clippy fmt-check
	@echo "gate: build, test-all, clippy, and fmt-check passed"

chio:
	$(CARGO) build --release -p chio-cli
	@echo "chio binary: $(CHIO_RELEASE)"

chio-dev:
	$(CARGO) build -p chio-cli

# ---------------------------------------------------------------------------
# Tier 2: CI
# ---------------------------------------------------------------------------

ci:
	./scripts/ci-pr-tier.sh

ci-workspace:
	./scripts/ci-workspace.sh

proptest-coverage:
	./scripts/check-proptest-coverage.sh

crate-paths:
	$(CARGO) xtask check crate-paths

# ---------------------------------------------------------------------------
# Tier 3: Spec / codegen
# ---------------------------------------------------------------------------

codegen: codegen-rust codegen-python codegen-ts codegen-go
	@echo "codegen: all four lanes (rust, python, ts, go) regenerated"

codegen-rust:
	$(CARGO) xtask codegen --lang rust

codegen-python:
	$(CARGO) xtask codegen --lang python

codegen-ts: ts-codegen-deps
	$(CARGO) xtask codegen --lang ts

codegen-go:
	$(CARGO) xtask codegen --lang go

codegen-errors:
	$(CARGO) xtask errors regen

codegen-snippets:
	$(CARGO) xtask snippets regen

codegen-vectors:
	$(CARGO) xtask freeze-vectors

codegen-eval-receipt:
	$(CARGO) xtask eval-receipt-regen

# Aggregator: runs all four codegen --check lanes. Used by spec-drift CI
# (.github/workflows/spec-drift.yml) and humans running the gate locally.
codegen-check: codegen-check-rust codegen-check-python codegen-check-ts codegen-check-go
	@echo "codegen-check: all four lanes (rust, python, ts, go) in sync with committed bytes"

codegen-check-rust:
	$(CARGO) xtask codegen --lang rust --check

codegen-check-python:
	$(CARGO) xtask codegen --lang python --check

codegen-check-ts: ts-codegen-deps
	$(CARGO) xtask codegen --lang ts --check

ts-codegen-deps:
	cd sdks/typescript/scripts && npm ci

codegen-check-go:
	$(CARGO) xtask codegen --lang go --check

spec-drift:
	./scripts/check-chio-owned-v1-only.sh
	$(MAKE) codegen-check
	$(CARGO) xtask snippets regen --check
	./scripts/spec-drift-check.sh

# ---------------------------------------------------------------------------
# Tier 4: SDK and supply chain
# ---------------------------------------------------------------------------

sdk-parity:
	./scripts/check-sdk-parity.sh

sdk-bindings-parity:
	./scripts/check-bindings-parity.sh

sdk-py:
	./scripts/check-chio-py.sh

sdk-go:
	./scripts/check-chio-go.sh

sdk-cpp:
	./scripts/check-chio-cpp.sh

sdk-drogon:
	./scripts/check-chio-drogon.sh

sdk-ts-deps:
	cd sdks/typescript/scripts && npm ci

vet:
	$(CARGO) vet --locked

deny:
	$(CARGO) deny check advisories
	$(CARGO) deny check licenses
	$(CARGO) deny check sources
	$(CARGO) deny check bans
	python3 scripts/check-external-wildcard-deps.py
	python3 scripts/check-cargo-deny-duplicate-baseline.py

supply-chain: vet deny
	@echo "supply-chain: vet and deny passed"

# ---------------------------------------------------------------------------
# Tier 5: Heavy / optional
# ---------------------------------------------------------------------------

qualify-release:
	./scripts/qualify-release.sh

qualify-trust:
	./scripts/qualify-trust-control.sh

qualify-portable-browser:
	./scripts/qualify-portable-browser.sh

qualify-mobile-kernel:
	./scripts/qualify-mobile-kernel.sh

qualify-cross-protocol:
	./scripts/qualify-cross-protocol-runtime.sh

qualify-bounded:
	$(CARGO) xtask qualify bounded-chio

coverage:
	./scripts/run-coverage.sh

# Fuzz budget report for CI minutes (requires gh and jq). Full fuzz runs live
# in .github/workflows/fuzz.yml and cflite workflows.
fuzz-budget:
	./scripts/check-fuzz-budget.sh

fuzz: fuzz-budget

kani:
	./scripts/run-kani-manifest.sh

kani-smoke:
	./scripts/check-kani-smoke.sh

mutants:
	./scripts/mutants-gate.sh

mutants-fuzz-cocoverage:
	./scripts/mutants-fuzz-cocoverage.sh

# ---------------------------------------------------------------------------
# Tier 6: Local infra and subprojects
# ---------------------------------------------------------------------------

docker-demo-up:
	cd examples/docker && docker compose up -d --build

docker-demo-down:
	cd examples/docker && docker compose down -v

docker-demo-smoke:
	cd examples/docker && python3 smoke_client.py

setup-merge-drivers:
	./scripts/setup-git-merge-drivers.sh

streaming-test:
	$(MAKE) -C sdks/python/chio-streaming test

streaming-integration:
	$(MAKE) -C sdks/python/chio-streaming test-integration

# ---------------------------------------------------------------------------
# Knowledge base (tools/knowledge-base)
# ---------------------------------------------------------------------------

kb-up:
	cd $(KB_DIR) && docker compose up -d --build kb-postgres kb-neo4j graphiti-mcp chio-kb-mcp

kb-lock-check:
	cd $(KB_DIR) && uv lock --check

kb-down:
	cd $(KB_DIR) && docker compose down

kb-reset:
	@if [ "$$KB_RESET_VOLUMES" = "1" ]; then cd $(KB_DIR) && docker compose down -v; fi
	cd $(KB_DIR) && docker compose up -d --build kb-postgres kb-neo4j chio-kb-mcp
	cd $(KB_DIR) && docker compose exec -T chio-kb-mcp chio-kb-reset

kb-reseed: kb-reset kb-update kb-seed-memory

kb-update:
	cd $(KB_DIR) && CHIO_KB_MAX_INFLIGHT_COMPONENTS=$${CHIO_KB_MAX_INFLIGHT_COMPONENTS:-8} COCOINDEX_SOURCE_MAX_INFLIGHT_ROWS=$${COCOINDEX_SOURCE_MAX_INFLIGHT_ROWS:-8} docker compose exec -T -e CHIO_KB_MAX_INFLIGHT_COMPONENTS -e COCOINDEX_SOURCE_MAX_INFLIGHT_ROWS chio-kb-mcp cocoindex -d /app update --force chio_kb.index
	cd $(KB_DIR) && docker compose exec -T chio-kb-mcp chio-kb-seed-graph

kb-live:
	cd $(KB_DIR) && CHIO_KB_MAX_INFLIGHT_COMPONENTS=$${CHIO_KB_MAX_INFLIGHT_COMPONENTS:-8} COCOINDEX_SOURCE_MAX_INFLIGHT_ROWS=$${COCOINDEX_SOURCE_MAX_INFLIGHT_ROWS:-8} docker compose exec -e CHIO_KB_MAX_INFLIGHT_COMPONENTS -e COCOINDEX_SOURCE_MAX_INFLIGHT_ROWS chio-kb-mcp cocoindex -d /app update --force --live chio_kb.index

kb-status:
	cd $(KB_DIR) && docker compose ps
	@curl -fsS http://localhost:8111/health
	@printf "\n"
	@curl -fsS http://localhost:8000/health
	@printf "\n"

kb-smoke:
	cd $(KB_DIR) && docker compose exec -T chio-kb-mcp chio-kb-smoke

kb-eval:
	cd $(KB_DIR) && docker compose exec -T chio-kb-mcp chio-kb-eval --suite all --fail-below-a

kb-seed-memory:
	cd $(KB_DIR) && docker compose up -d kb-neo4j graphiti-mcp chio-kb-mcp
	cd $(KB_DIR) && docker compose exec -T chio-kb-mcp chio-kb-seed-memory

kb-dogfood:
	cd $(KB_DIR) && docker compose exec -T chio-kb-mcp chio-kb-eval --suite all --format markdown --fail-below-a > DOGFOOD-REVIEW.md
