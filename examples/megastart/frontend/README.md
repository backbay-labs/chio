# Workshop frontend source

These are the exact authored inputs for the embedded local workshop. The host
serves the compiled assets without Node.js, Next.js, external fonts, or telemetry.
The retained package manifest and lockfile come from the shared website toolchain;
the local entry imports only the components used by this operator.

From this directory, install the locked build tools and verify the embedded bytes:

```sh
bun install --frozen-lockfile --ignore-scripts
CHIO_WORKSHOP_OPERATOR_ROOT=.. node scripts/build-workshop-local.mjs --check
```

To regenerate after editing, omit `--check`, then rebuild the Rust operator.
The asset manifest hashes the authored inputs, every bundled dependency file,
and pinned fonts. The UI build identity is also checked against the local API.
