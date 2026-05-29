# TTFRH Bench

This crate measures the time-to-first-receipt happy-path across the three
`create-chio-app` template starters. Runners are dependency-free so
`Cargo.lock` stays quiet during ordinary development.

The executable Docker runners use the inherited `ubuntu-24.04` reference
runner pin. The required CI gate triggers on changes under
`sdks/typescript/templates/**` or `bench/ttfrh/**`.
