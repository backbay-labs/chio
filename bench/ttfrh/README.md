# TTFRH Bench Scaffold

This crate reserves the time-to-first-receipt-happy-path bench surface for
M07. P0 keeps the runners advisory and dependency-free so Cargo.lock remains
quiet while the template skeletons land.

P5 owns the executable Docker runners, the inherited `ubuntu-24.04` reference
runner pin, and the required CI flip for changes under
`sdks/typescript/templates/**` or `bench/ttfrh/**`.
