# `chio replay`

Re-evaluate a captured receipt log (or tee NDJSON stream) against the
current build. Re-verifies every Ed25519 signature, recomputes the Merkle
root incrementally, and reports the first divergence by byte offset and
JSON pointer.

This page is a CLI reference. The normative source is the
deterministic-replay contract in `spec/PROTOCOL.md` (the `chio replay`
subcommand surface). The exit-code registry on this page is canonical:
The goldens-replay subsystem owns it, and the tee-replay traffic mode consumes it verbatim without defining new codes.

## Synopsis

```text
chio replay <LOG> [OPTIONS]
```

Surface (lifted from `crates/products/chio-cli/src/cli/types.rs::ReplayArgs` and
the dispatch wiring in `crates/products/chio-cli/src/cli/dispatch`):

```text
ARGS:
  <LOG>                Path to a receipt-log directory or NDJSON stream.

OPTIONS:
      --from-tee           Treat <LOG> as a tee NDJSON stream. When
                           omitted, the reader auto-detects the input
                           shape (directory vs. NDJSON file).
      --expect-root <HEX>  Assert the recomputed Merkle root equals this
                           hex string. Drives exit code 10 (verdict drift)
                           when the recomputed root differs.
      --json               Emit a structured JSON report on stdout (the
                           `chio.replay.report/v1` schema). The report is
                           emitted regardless of exit code; consumers
                           gate on the `schema` field before parsing.
      --bless              (Restricted) Convert <LOG> into a goldens
                           directory. Requires `CHIO_BLESS=1`, a non-
                           empty `BLESS_REASON`, a feature branch, a
                           clean tree outside `tests/replay/goldens/**`
                           and `docs/replay-compat.md`, and an audit-log
                           entry. The bless gate is fail-closed; see
                           the replay-gate rules below for the full rules.
  -h, --help               Print help.
  -V, --version            Print version.
```

## Standalone replay-gate binary

The `tests/replay` crate also ships a narrower binary:

```text
chio-replay-gate <LOG_OR_FIXTURE> [--json] [--expect-root <HEX>] [--bless]
```

This binary is the CI and developer gate for the checked-in
`tests/replay` corpus. It is intentionally not a full replacement for
the production `chio replay` command above. Its validation mode accepts a
goldens root such as `tests/replay/goldens` or a single golden scenario
directory, regenerates candidate bytes from the paired fixture manifests
under `tests/replay/fixtures`, and compares `receipts.ndjson`,
`checkpoint.json`, and `root.hex` as raw bytes.

Supported options:

```text
      --json              Emit chio.replay.report/v1 JSON.
      --expect-root <HEX> Assert the scenario root for a single
                          scenario, or the deterministic aggregate
                          root for a multi-fixture run.
      --bless             Regenerate goldens through the CHIO_BLESS gate.
  -h, --help              Print help.
  -V, --version           Print version.
```

`--bless` accepts a fixture manifest, a fixture directory, or no
positional path. With no path it blesses the full `tests/replay/fixtures`
tree, matching `scripts/bless-replay-goldens.sh`. The binary first
discovers manifests, validates manifest identity, checks that golden
output paths remain under `tests/replay/goldens`, and prepares the
candidate `GoldenSet`s in memory. It then evaluates the existing
`CHIO_BLESS` gate, appends the audit line to
`tests/replay/.bless-audit.log`, and writes goldens through the replay
crate's `GoldenSet` writer. If `CHIO_BLESS=1`, `BLESS_REASON`, the
branch, TTY, CI, dirty-tree, or audit-log checks fail, the command exits
non-zero before touching goldens.

For a clean full-corpus run:

```bash
cargo run -p chio-replay-gate -- tests/replay/goldens --json
```

the standalone gate emits:

```json
{
  "schema": "chio.replay.report/v1",
  "accepted": true,
  "checkedFixtures": 50,
  "computedRoot": "<lowercase hex>",
  "expectedRoot": null,
  "divergences": []
}
```

For a single scenario directory, `computedRoot` is that scenario's
`root.hex`. For a multi-fixture run, `computedRoot` is a deterministic
aggregate over each checked fixture label and root in replay-gate
enumeration order.

The `<LOG>` positional accepts two shapes:

- A directory of signed receipts laid out under
  `tests/replay/goldens/<family>/<name>/` (`receipts.ndjson`,
  `checkpoint.json`, `root.hex`). This is the goldens fixture shape.
- An NDJSON stream (one signed receipt per line). When the stream is an
  tee capture, pass `--from-tee` to skip auto-detection. The frame
  layout is byte-compatible with the goldens NDJSON.

## Exit codes

The goldens-replay subsystem is the source of truth for these codes. The tee-replay traffic mode
(the tee replay harness; see `spec/PROTOCOL.md`) consumes them
verbatim.

| Code | Name                | Meaning                                                                                                                                  |
| ---- | ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| 0    | clean match         | Every receipt (or tee frame) verifies, the Merkle root recomputes, and matches `--expect-root` if supplied.                              |
| 10   | verdict drift       | A receipt's allow / deny decision differs from what the current build issues for the same input. Also fires when `--expect-root` mismatches. |
| 20   | signature mismatch  | Ed25519 verification failed on at least one receipt's or frame's `tenant_sig`.                                                           |
| 30   | parse error         | Malformed JSON or a missing required field. Structural failure before schema validation.                                                 |
| 40   | schema mismatch     | Unsupported `schema_version`, or schema validation failed against the canonical-JSON schema set.                                     |
| 50   | redaction mismatch  | The recorded `redaction_pass_id` is unavailable, or rerunning the redaction manifest produces a different result.                        |

Exit code 1 is reserved for unrelated CLI errors (missing input file,
permission denied, internal panic). Replay-domain failures always map
into 0 / 10 / 20 / 30 / 40 / 50.

### Error-class to exit-code mapping

This table is the authoritative mapping. The tee-replay traffic
mode reuses it without modification.

| Error class                                | Exit |
| ------------------------------------------ | ---- |
| Clean run, no `--expect-root`              | 0    |
| Clean run, `--expect-root` matches         | 0    |
| `--expect-root` hex differs from computed  | 10   |
| Verdict flipped (allow -> deny or inverse) | 10   |
| Guard set added or removed                 | 10   |
| `tenant_sig` Ed25519 verification failed   | 20   |
| NDJSON line not parseable as JSON          | 30   |
| Required field missing                     | 30   |
| `schema_version` unknown                   | 40   |
| Canonical-JSON schema validation failed    | 40   |
| `redaction_pass_id` unavailable            | 50   |
| Rerun redaction yields different manifest  | 50   |

The `merkle_mismatch` divergence shape used inside the
`chio.replay.report/v1` document maps to exit code 10 (verdict-drift
class) when triggered by `--expect-root`; an internal accumulator
disagreement during streaming verification is attributed to the
underlying signature failure (exit 20). See
`crates/products/chio-cli/src/cli/replay/report.rs` for the in-tree mapping
function.

## Flag details

### `--expect-root <HEX>`

Asserts the recomputed Merkle root equals the supplied lowercase-hex
string. The runner streams receipts, folds each one's bytes into a
SHA-256 accumulator, and compares the final root against the
expectation. A mismatch drives exit code 10 (verdict-drift class)
because a root mismatch implies the underlying verdict-bearing bytes
differ, which is what the regression gate exists to catch.

Use `--expect-root` in CI to pin a goldens directory to a known root.
The root for a given fixture lives at
`tests/replay/goldens/<family>/<name>/root.hex`.

### `--from-tee`

Treats `<LOG>` as a tee NDJSON stream rather than a goldens
directory or a generic NDJSON file. The frame shape is the same
canonical-JSON receipt envelope used by the goldens, so the
distinction is mostly about input-shape detection: a directory implies
goldens, a file may be either.

The interplay with the tee-replay subsystem:

- The tee-replay subsystem owns the encoder. The `chio-tee` sidecar
  (`crates/trust/chio-tee/`) writes NDJSON capture files in
  `verdict-only`, `shadow`, and `enforce` modes. See the tee replay
  harness contract in `spec/PROTOCOL.md`.
- The goldens-replay subsystem owns the consumer. `chio replay --from-tee <capture.ndjson>`
  re-verifies every frame's `tenant_sig`, re-derives the verdict, and
  recomputes the root. The exit-code registry is the goldens-replay subsystem's; the tee-replay subsystem does not
  define new codes.
- Graduation path: a captured tee session graduates into the goldens
  fixture corpus via `chio replay --bless --into <goldens-dir>`. The
  bless flow strips `tenant_sig` and request / response blobs, writes
  the goldens directory layout (`receipts.ndjson`, `checkpoint.json`,
  `root.hex`), and the result is a fixture indistinguishable from one
  produced by the goldens driver.
- The sibling tee subcommand `chio replay traffic --from <capture.ndjson>
  --against <policy-path>` runs pre-output replay against a
  workspace-local policy file rather than the current build. Registry-backed
  manifest hashes and package coordinates are not accepted until a real
  resolver can materialize a verified policy. Because
  `chio-tee-frame.v1` carries only request / response SHA-256 hashes,
  not the original Chio tool-server id or redacted response bytes, this
  mode rejects policies with concrete-server grants or post-output
  guards instead of reporting false drift.

When `--from-tee` is omitted, the reader auto-detects: a directory path
becomes the goldens reader, a regular file becomes the NDJSON reader.
Pass `--from-tee` explicitly to opt out of auto-detection (for example,
when piping a stream through a path that is also a directory in some
sandbox layouts).

### `--json`

Emits a single line of JSON on stdout in the `chio.replay.report/v1`
schema, followed by a trailing newline. The report is emitted
regardless of exit code, so a verdict-drift run still produces a
machine-readable diagnosis on stdout while exiting non-zero.

### `--bless`

Restricted to fixture maintainers. Converts `<LOG>` into a goldens
directory. Fails closed unless every replay-gate clause holds:
`CHIO_BLESS=1`, non-empty `BLESS_REASON`, non-`main` non-`release/*`
branch, clean tree outside `tests/replay/goldens/**` and
`docs/replay-compat.md`, TTY on stderr, `CI` unset or `false`, audit-log
entry written to `tests/replay/.bless-audit.log` in the same commit.
CODEOWNERS review on `tests/replay/goldens/**` is the human gate on top.
CI cannot bless: the gate refuses any invocation when `CI=true`.

## JSON output schema

`--json` emits the `chio.replay.report/v1` document. The schema string
`chio.replay.report/v1` is pinned by
`crates/products/chio-cli/src/cli/replay/report.rs::SCHEMA_ID` and the formal
JSON Schema lives at
`spec/schemas/chio-replay-report/v1.schema.json`. PR #186
landed the surface; PR #193 wired it through the live
pipeline.

Shape (verbatim from the in-tree definition):

```json
{
  "schema": "chio.replay.report/v1",
  "log_path": "<positional arg verbatim>",
  "receipts_checked": 0,
  "computed_root": "<lowercase hex>",
  "expected_root": "<lowercase hex>" ,
  "first_divergence": null,
  "exit_code": 0
}
```

`first_divergence` is `null` for a clean run. On divergence it expands
to:

```json
{
  "kind": "verdict_drift",
  "receipt_index": 0,
  "receipt_id": "<id>",
  "json_pointer": "/path/to/field",
  "byte_offset": 0,
  "expected": "<string>",
  "observed": "<string>",
  "detail": "<string>"
}
```

`kind` is one of `verdict_drift`, `signature_mismatch`, `parse_error`,
`schema_mismatch`, `redaction_mismatch`, `merkle_mismatch`. The first
five mirror the canonical exit codes 10 / 20 / 30 / 40 / 50; the sixth
maps to exit code 10 when triggered by `--expect-root` and is purely
for triage attribution.

Consumers MUST byte-match the `schema` field against
`chio.replay.report/v1` before parsing the rest of the document. Any
future schema revision must land with a distinct schema identifier; current
consumers that gate on the schema string will refuse unknown documents and
surface a clear error.

The output is always a single line of JSON followed by `\n`, suitable
for piping through `jq` without buffering surprises.

## Examples

Verify a goldens directory (clean run, exit 0):

```bash
chio replay ./tests/replay/goldens/openai_responses/tool_call_allow/
```

Verify a tee capture and assert the root (drift case, exit 10):

```bash
chio replay capture.ndjson --from-tee --expect-root 7af9c0dead...
```

Re-verify and emit a machine-readable diagnosis on a corrupted log
(signature failure, exit 20; report still printed to stdout):

```bash
chio replay corrupted.ndjson --json
# stdout (single line):
# {"schema":"chio.replay.report/v1","log_path":"corrupted.ndjson", ...
#   "first_divergence":{"kind":"signature_mismatch", ...},"exit_code":20}
```

Pipe the JSON report through `jq` to extract the divergence kind:

```bash
chio replay ./fixtures/run-42/ --json | jq -r '.first_divergence.kind'
# verdict_drift
```

## Composition with other tooling

- Tee captures: `chio-tee` writes NDJSON captures under any of its three
  modes (`verdict-only`, `shadow`, `enforce`); `chio replay --from-tee`
  consumes them. Graduation into the goldens corpus is via `chio replay
  --bless`.
- Replay-gate CI job: `.github/workflows/chio-replay-gate.yml`
  invokes `chio replay` over each goldens directory in the corpus and
  asserts exit code 0. Any divergence fails the gate.
- Cross-version compatibility: the matrix at
  `tests/replay/release_compat_matrix.toml` lists tagged-release
  bundles the current main is expected to replay clean (`compat =
  "supported"`) or best-effort (`compat = "best_effort"`). See
  `docs/replay-compat.md` for the human-readable table.

## See also

- `spec/PROTOCOL.md` deterministic-replay contract (canonical surface,
  exit codes, JSON schema; this page is the user-facing rendering of
  that section).
- `spec/PROTOCOL.md` tee replay harness contract (sibling
  `chio replay traffic --against <policy-path>` mode, which reuses this
  page's exit codes verbatim).
- `crates/products/chio-cli/src/cli/replay/report.rs` (in-tree report builder
  and the `SCHEMA_ID` constant).
- `spec/schemas/chio-replay-report/v1.schema.json` (formal JSON Schema
  for the `chio.replay.report/v1` document).
- `docs/replay-compat.md` (cross-version compatibility table).
