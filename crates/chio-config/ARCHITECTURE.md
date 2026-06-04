# chio-config Architecture

## Boundary

`chio-config` owns ingestion of operator `chio.yaml` configuration before the
runtime, adapters, guard loaders, and control-plane code wire themselves from
that data. It does not instantiate kernels, start adapters, resolve guard
modules, or open storage connections. Its responsibility is to turn config text
or files into a typed `ChioConfig` only after interpolation, schema
deserialization, defaults, and validation have all succeeded.

## Module Boundaries

- `schema` owns the typed `chio.yaml` shape and serde defaults.
- `interpolation` owns `${VAR}` and `${VAR:-default}` expansion before YAML
  deserialization.
- `validation` owns cross-field checks after typed deserialization, including
  adapter IDs, edge references, auth blocks, kernel fields, and logging values.
- `loader` owns the canonical ingest sequence from file/string to validated
  `ChioConfig`.
- `fuzz` is feature-gated and drives arbitrary bytes through the same loader
  path without adding production dependencies.

## Trust Invariants

- Existing public API entry points must remain compatible:
  `load_from_file`, `load_from_str`, `interpolation::interpolate`, schema
  structs, and `validation::validate`.
- Unknown config fields must continue to fail at parse time through
  `deny_unknown_fields`.
- Missing interpolation variables without defaults must continue to fail closed
  before parsing.
- Loader interpolation must not let environment variables or defaults inject
  new YAML structure, truncate scalar values through comments, or break quoted
  strings.
- Raw `interpolation::interpolate` remains compatibility-oriented; only
  `loader::load_from_str` applies YAML-scalar-safe interpolation.
- Validation must keep returning all detected semantic errors in one pass.
- Bearer and API-key auth headers must be present, non-empty, and unpadded.
- The `fuzz` feature must remain optional and must not affect production
  dependencies.

The loader separates general string interpolation from trusted config
ingestion and moves the YAML-scalar safety invariant to the earliest point in
the load lifecycle:
raw config -> loader-safe interpolation -> YAML deserialization -> validation.

## Verification Focus

Tests should cover unknown-field rejection, missing interpolation variables,
unsafe interpolation defaults, YAML boundary injection attempts, duplicate
adapter and edge ids, missing adapter references, auth block completeness,
blank or padded bearer/API-key headers, logging validation, and optional fuzz
entrypoints staying outside the default dependency graph.
