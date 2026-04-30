# WASM Browser Verdict Driver

This driver family runs the browser kernel through the existing
`wasm-pack test --headless --chrome` path. The native Rust integration test
keeps the scenario adapter covered under `cargo test`, while `run.sh` is the
browser gate entrypoint used by the verdict matrix lane.
