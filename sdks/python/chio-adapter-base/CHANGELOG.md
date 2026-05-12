# Changelog

All notable changes to `chio-adapter-base` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Phase 1 scaffold: package layout, public API contract via type-only
  signatures, conformance hooks, and a smoke-test that asserts the
  public surface imports cleanly.
- Submodule layout chosen over flat namespace and over a facade class.
  See `.planning/chio-adapter-base/PLAN.md` section 3 for the design
  rationale.

### Notes
- This is a scaffold. Every primitive raises `NotImplementedError`
  with a docstring pointing at the chio-hermes source the
  implementation will be ported from in Phase 2.
- No production adapter should depend on `0.1.0` until Phase 2 lands
  the actual implementations.
