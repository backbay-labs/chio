# Eval Receipt Binding Vector

`v1.json` is the golden bundle fixture for
`chio.eval-report.bundle.v1`. Regenerate it with:

```text
cargo run -p xtask -- eval-receipt-regen
```

Check mode validates the fixture bytes and then verifies
`tests/bindings/vectors/MANIFEST.sha256`:

```text
cargo run -p xtask -- eval-receipt-regen --check
```
