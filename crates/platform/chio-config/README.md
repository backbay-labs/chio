# chio-config

Unified `chio.yaml` configuration loader for the Chio runtime. It turns YAML
text or a file path into a validated `ChioConfig`: environment interpolation,
`serde` deserialization with `deny_unknown_fields`, and post-deserialization
checks (duplicate IDs, broken references, incomplete auth) all run before a
caller sees a config value.

`ChioConfig::to_kernel_config` bridges the file schema into the runtime by
lowering a validated config into `chio_kernel::KernelConfig`. The crate does
not construct a kernel, start adapters, or open storage connections itself.

## Responsibilities

- Parse `chio.yaml` into typed structs; every struct denies unknown fields, so
  a typo in a config key fails at load time.
- Interpolate `${VAR}` and `${VAR:-default}` environment references into the
  raw YAML text before deserialization.
- Reject literal tab characters outside quoted scalars, comments, and block
  scalars before the text reaches the YAML parser.
- Validate the deserialized config: adapter/edge ID uniqueness, edge-to-adapter
  references, auth block completeness, kernel deadline floors, logging enum
  values. Collect every error in one pass instead of stopping at the first.
- Apply defaults so a minimal config needs only `kernel` and one adapter.
- Lower a validated `ChioConfig` into `chio_kernel::KernelConfig`, resolving
  `kernel.signing_key` into an Ed25519 keypair along the way.

## Public API

Re-exported at the crate root:

- `load_from_file(path: &Path) -> Result<ChioConfig, ConfigError>`,
  `load_from_str(yaml: &str) -> Result<ChioConfig, ConfigError>` - the loader
  entry points.
- `ChioConfig` - root config; `to_kernel_config(&self) -> Result<chio_kernel::KernelConfig, ConfigError>`
  lowers it into the runtime kernel config.
- `KernelConfig` - `signing_key`, `receipt_store`, `log_level`, `deadlines`;
  `signing_keypair(&self) -> Result<chio_core::crypto::Keypair, ConfigError>`
  resolves `signing_key` (`"generate"` or a hex Ed25519 seed).
- `AdapterConfig`, `AdapterAuthConfig`, `EdgeConfig`, `ReceiptsConfig`,
  `LoggingConfig`, `TelemetrySection`, `GuardsConfig`, `WasmGuardEntry` - the
  remaining schema sections.
- `ConfigError` - `Io`, `Interpolation`, `Parse`, `Validation(Vec<String>)`, `Kernel`.

Also public via submodules:

- `schema::KernelDeadlinesFileConfig` - `[kernel.deadlines]` scalar budgets;
  `to_hot_path_deadline_config()` overlays them onto
  `chio_kernel::HotPathDeadlineConfig::default()`.
- `interpolation::interpolate(input: &str) -> Result<String, ConfigError>` -
  unrestricted `${VAR}` / `${VAR:-default}` expansion, for callers outside the
  loader path.
- `validation::validate(config: &ChioConfig) -> Result<(), ConfigError>` - run
  the loader's checks against a config assembled some other way.

## Usage

```rust
use chio_config::{load_from_str, ChioConfig};

fn load() -> Result<(), chio_config::ConfigError> {
    let yaml = r#"
kernel:
  signing_key: "generate"

adapters:
  - id: petstore
    protocol: openapi
    upstream: "http://localhost:8000"
"#;

    let config: ChioConfig = load_from_str(yaml)?;
    let kernel_config = config.to_kernel_config()?;
    Ok(())
}
```

## Feature flags

| Flag | Effect |
|------|--------|
| `fuzz` | Exposes `chio_config::fuzz`, the libFuzzer entry point (`fuzz_chio_yaml_parse`) for the YAML-loader trust boundary. Off by default; pulls in `arbitrary`. Enabled only by the standalone `fuzz` workspace at `../../fuzz`. |

## Testing

`cargo test -p chio-config`

## See also

- `chio-kernel` - `to_kernel_config` lowers a validated `ChioConfig` into its `KernelConfig`.
- `chio-core` - supplies `crypto::Keypair`, used to resolve `kernel.signing_key`.
- `chio-wasm-guards` - `wiring::load_wasm_guards` consumes `schema::WasmGuardEntry` to build guards from the `wasm_guards` section.
