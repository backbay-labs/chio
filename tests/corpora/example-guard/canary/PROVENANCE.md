# Example Guard Canary Corpus Provenance

This corpus is hand-curated for the example guard hot-reload canary gate.

Rules:

- Fixtures are frozen on commit and are not regenerated programmatically.
- A fixture change is a guard major-version bump.
- `MANIFEST.sha256` contains one `<sha256>  <filename>` line for every JSON fixture.
- The fixture count must remain 32.
- The canary harness verifies the manifest before any replacement module is published.
