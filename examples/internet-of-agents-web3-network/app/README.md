# Chio Evidence Console

A Next.js 15 / App Router / TypeScript interface that renders an artifact
bundle produced by `orchestrate.py`. The app is offline-first, performs
in-browser SHA-256 hash verification on every artifact it fetches, and fails
closed when the bundle is missing or corrupted.

## Bundle schema contract

The UI reads the artifact contract defined by the Python orchestrator. The
normative sources are:

- `internet_web3/artifacts.py::ArtifactStore.write_manifest` -> `bundle-manifest.json`
- `internet_web3/scenario.py::_build_summary` -> `summary.json`
- `internet_web3/verify.py::verify_bundle` -> `review-result.json`
- `internet_web3/scenario.py::_write_topology` -> `chio/topology.json`

`bundle-manifest.json`:

```
{
  "schema": "chio.example.ioa-web3.bundle-manifest.v1",
  "generated_at": <int epoch seconds>,
  "files": ["adversarial/expired_capability-denial.json", ...],
  "sha256": {"adversarial/expired_capability-denial.json": "<raw hex>", ...}
}
```

`summary.json` carries `order_id`, `agent_count`, `capability_count`,
`receipt_counts_by_boundary`, `adversarial_denial_status`,
`guardrail_denial_status`, `base_sepolia_smoke_status`, and a number of
verdict fields. The TypeScript type in `lib/types.ts` reflects the current
orchestrator output; extra fields are tolerated.

`review-result.json` carries `ok: boolean`, `errors: string[]`, and
diagnostic sub-objects (`manifest`, `capabilities`, `web3`, `chio`) that the
UI treats as opaque `unknown`.

## Prerequisites

- Bun 1.3+
- A Chio artifact-dir (either the bundled fixture under
  `tests/fixtures/good-bundle/`, which is a copy of a real orchestrator
  output, or any directory produced by `orchestrate.py` that contains
  `bundle-manifest.json`, `summary.json`, `review-result.json`, and
  `chio/topology.json`).

## Install

```
cd examples/internet-of-agents-web3-network/app
bun install
```

## Dev server

```
CHIO_BUNDLE_DIR="$(pwd)/tests/fixtures/good-bundle" bun run dev
```

Open http://localhost:3000.

## Production (what the smoke uses)

```
bun run build
CHIO_BUNDLE_DIR="$(pwd)/tests/fixtures/good-bundle" bun run start
```

Health probe: `curl http://localhost:3000/api/health` returns
`{ ok: true, bundleDir, manifestSha }` when the manifest is readable.

## Bundle loader endpoints

- `GET /api/health` - returns `{ ok, bundleDir, manifestSha, mode }` when
  the manifest is readable; 500 with a diagnostic otherwise.
- `GET /api/bundle/<rel-path>` - streams the artifact body. Only `.json`
  files are served. Paths are URL-encoded per segment by the client. The
  server rejects null bytes (`\x00`) with a generic 400, enforces a
  two-stage path-traversal guard (lexical `path.relative` plus
  `fs.realpath`), and returns 404 for missing files.

## Env vars

- `CHIO_BUNDLE_DIR` (required). Absolute path to the artifact-dir.
- `CHIO_BUNDLE_MODE` (optional). `server` (default) streams files from the
  server. `static` is reserved and not yet implemented.
- `NEXT_PUBLIC_CHIO_DEV` (optional). Set to `1` to show the minimal tweaks panel.

## Graph layout

The graph assumes the demo's four named organizations with fixed quadrant
coordinates: `atlas`, `proofworks`, `cipherworks`, `meridian`. The layout
table lives in `lib/topology.ts` and the demo ensemble (workloads, sidecars,
MCP) in `lib/orgs.ts`. If the bundle topology carries matching org ids, its
name/role/URL fields are merged in. Extra orgs without layout coordinates
are dropped and a `console.warn` is emitted once per missing node id.

## Base Sepolia transaction count

The `base-sepolia tx` counter is best-effort. The Chrome component
lazy-loads `web3/base-sepolia-smoke.json` and counts
`transactions.length`. If the file is missing or lacks that array, the
counter renders `n/a` and the reason is logged via `console.warn`.

## Fail-closed behavior

- `CHIO_BUNDLE_DIR` unset or empty: every bundle request returns HTTP 500
  from the API. The client surfaces this as an error banner.
- Missing `bundle-manifest.json` in the dir: same behavior.
- Manifest shape mismatch (bad JSON, missing keys): the client renders the
  error banner with a diagnostic.
- Any required eager artifact (`summary.json`, `review-result.json`,
  `chio/topology.json`) missing from `manifest.sha256` or failing to fetch:
  the console flips to the error banner.
- Hash mismatch on any fetched artifact: the top bar verdict flips to
  `FAIL` regardless of what `review.ok` declares, and the first mismatched
  path is rendered in the meta row.
- Artifact missing from the bundle (404 from `/api/bundle/...`): the
  explorer shows an inline load error; lineage links that point at missing
  paths are hidden.

## Fixture regeneration

After you add or modify any file under `tests/fixtures/good-bundle`,
restamp the manifest:

```
bun run stamp-fixture
```

The committed `bundle-manifest.json` was produced by this script and
matches the real manifest schema emitted by `artifacts.py`. The fixture
itself is a copy of a real bundle produced by the orchestrator; update it
by copying a fresh run into `tests/fixtures/good-bundle/` and restamping.
