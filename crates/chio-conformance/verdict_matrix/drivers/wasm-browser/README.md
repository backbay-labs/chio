# WASM Browser Verdict Driver

This driver family runs the browser kernel through the existing
`wasm-pack test --headless --chrome` path. The native Rust integration test
keeps the scenario adapter covered under `cargo test`, while `run.sh` is the
browser gate entrypoint used by the verdict matrix lane.

The browser kernel exposes the portable `evaluate_pure` surface. The current
driver checks the capability subset through that real path and reports the
revocation, replay, and redaction classes as unsupported because
`evaluate_pure` has no revocation store, execution nonce store, or guard
pipeline.
