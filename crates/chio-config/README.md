# chio-config

`chio-config` is the unified `chio.yaml` configuration loader for the Chio
runtime. It parses the `chio.yaml` format with `serde` and
`deny_unknown_fields`, interpolates environment variables (`${VAR}` and
`${VAR:-default}`), runs post-deserialization validation (duplicate IDs, broken
references, incomplete auth), and applies defaults so a minimal config needs
only `kernel` plus one adapter.

Loader interpolation is fail-closed: environment values and defaults that could
change YAML scalar structure, such as line breaks, quote delimiters, comment
markers, control characters, or surrounding whitespace, are rejected before
YAML parsing. The raw `interpolation::interpolate` helper remains available for
non-loader string interpolation.

Use this crate when you are loading or validating operator configuration before
wiring the kernel and its adapters.
