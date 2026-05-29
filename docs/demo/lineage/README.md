# Chio lineage viewer (static)

A vanilla static viewer for the lineage DAG. Open `index.html`
in a browser. There is no build step, no bundler, no import map, and
no CDN-pinned module loader. The page loads three local files only:

- `index.html`: the page shell.
- `lineage.css`: layout and evidence-class colour cues.
- `lineage.js`: a single ES module loaded via `<script type="module">`.

## Wire format

The viewer reads JSON dumps stamped with `schema_version =
"chio.lineage.graph/v1"`. The same format is produced by:

```bash
chio lineage query --emit demo --json > lineage.json
```

A graph dump has three top-level fields:

- `schema_version` (required): pinned to `chio.lineage.graph/v1`. The
  viewer refuses to render anything else.
- `nodes`: array of `{id, kind, evidence_class, tenant_id?, label?}`.
- `edges`: array of `{from, to, kind, evidence_class}`.
- `truncated` (optional): `{truncated: true, depth_reached: N, limit: M}`
  when a recursive-CTE query reached its bound. The shape matches the
  truncation marker pinned by `chio-lineage::schema::TruncationMarker`.

## No-build constraint

The no-build constraint is intentional:

> JS uses plain ES modules with NO import map and NO transpiler step;
> the README documents the no-build constraint so a starter does not
> add a bundler or a CDN-pinned import map. Loads via
> `<script type="module" src="./lineage.js"></script>` only.

If you find yourself reaching for npm or webpack, stop. The viewer
must keep working from any vanilla static-file server (or `file://`
in browsers that allow ES module loading from disk).

## Evidence class colours

The viewer surfaces the protocol evidence class on every row:

- `asserted`: caller-supplied or imported attributes (yellow).
- `observed`: local kernel runtime truth (green).
- `verified`: signed or proof-checked (purple).

Mixing these without preserving the class is the highest correctness
risk called out in the lineage readiness research doc; the viewer
keeps the class visible so reviewers cannot accidentally treat an
asserted edge as verified.

## Sample button

The "Load sample" button injects an in-memory three-node fixture so
the viewer renders something the first time you open it without
needing a real corpus dump.
