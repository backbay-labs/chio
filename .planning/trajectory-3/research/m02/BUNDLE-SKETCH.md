# Eval-Report Bundle Sketch

**Schema id:** `chio.eval-report.bundle.v1`
**Date frozen:** 2026-05-02
**Partner:** METR
**Canonicalization label:** `rfc8785`

This sketch freezes the partner-review target before P3 publishes the
JSON schema at `spec/eval/receipt-format.v1.json`. It is deliberately
textual: P2 maps verdict-matrix output into this shape, and P3 turns
the shape into a schema, verifier, and golden vector.

## Design Constraints

- The bundle wraps existing Chio receipt records without changing the
  inner receipt body or its signature surface.
- The outer bundle signature covers the bundle after removing the
  `signatures` field and canonicalizing the remaining JSON using
  `rfc8785`.
- The format supports batch verification because an eval card cites a
  run containing many scenario receipts, not a single receipt.
- The format carries partner-pipeline metadata that is not part of the
  inner Chio receipt body: eval run id, scorer version, model target,
  scenario id, corpus hash, and partner ingest metadata.
- The default signature path is `sigstore-cosign` with GitHub OIDC.
  `pgp-detached` remains a fallback signature kind.

## Top-Level Shape

```json
{
  "schema": "chio.eval-report.bundle.v1",
  "bundle_id": "urn:chio:eval-bundle:...",
  "created_at": "2026-05-02T00:00:00Z",
  "producer": {
    "name": "Chio",
    "repository": "https://github.com/bb-connor/arc",
    "commit": "<git-sha>",
    "workflow_run_url": "<github-actions-url-or-local-run-id>"
  },
  "eval_run": {
    "run_id": "metr-verdict-matrix-2026-05-02",
    "partner": "METR",
    "partner_slug": "metr",
    "pipeline": "vivaria-trace-postprocess",
    "pipeline_language": "python",
    "model_under_eval": "<partner-model-label>",
    "scorer": {
      "name": "<rubric-or-scorer-name>",
      "version": "<scorer-version>"
    }
  },
  "corpus": {
    "name": "chio-verdict-matrix",
    "scenario_count": 48,
    "sha256": "47e8d5394c807196d9567d97515e786cb1abfb0c7676e54db269ca82c735422f",
    "manifest_path": "crates/chio-conformance/verdict_matrix/manifest.toml"
  },
  "receipts": [
    {
      "scenario_id": "capability_subset/basic_allow_001",
      "category": "capability_subset",
      "verdict": "allow",
      "receipt": {},
      "receipt_sha256": "<sha256-of-canonical-inner-receipt>",
      "evidence": {
        "trace_id": "<partner-trace-id>",
        "sample_id": "<partner-sample-id>",
        "notes": []
      }
    }
  ],
  "signatures": [
    {
      "kind": "sigstore-cosign",
      "key_id": "<oidc-subject-or-certificate-identity>",
      "signature": "<base64-or-reference>",
      "certificate": "<optional-certificate-or-url>",
      "signed_payload": "bundle_without_signatures:rfc8785"
    }
  ]
}
```

## Field Notes

`schema`
: Required constant `chio.eval-report.bundle.v1`.

`bundle_id`
: Stable URN or URL selected by the producer. The verifier treats it as
  an identifier, not as a trusted location.

`producer`
: Build provenance for the bundle. P3 may validate commit-sha shape,
  but P5 memo verification depends on the signature, not this metadata.

`eval_run`
: Partner-facing run metadata. For METR, `pipeline_language` is
  `python`, and `pipeline` should name the vivaria post-processing
  adapter used by the sample.

`corpus`
: Hash-pinned verdict-matrix input. The sha256 value is copied from
  `crates/chio-conformance/verdict_matrix/manifest.toml`.

`receipts`
: Array of wrapped inner Chio receipt records. P3 schema validation
  checks required wrapper metadata and leaves the inner receipt object
  to the existing `chio-wire/v1/receipt/record.schema.json` verifier.

`receipt_sha256`
: Hash of the inner receipt after its own canonicalization. It gives
  batch verifiers a fast integrity check before full signature
  verification.

`signatures`
: One or more outer signatures. The signature payload is the top-level
  bundle with the entire `signatures` field removed and the remaining
  JSON canonicalized as `rfc8785`.

## Verification Steps

1. Parse JSON and verify `schema == "chio.eval-report.bundle.v1"`.
2. Remove `signatures`, canonicalize as `rfc8785`, and verify at least
   one accepted outer signature.
3. Verify the corpus hash and scenario count match the pinned
   verdict-matrix manifest.
4. For each receipt entry, verify `receipt_sha256` against the inner
   receipt and then run the existing Chio receipt verifier.
5. Emit a compact partner ingest summary containing run id, scenario
   count, failed receipt count, signature kind, and verifier version.

## Partner Review Questions

- Does the `eval_run` block carry enough metadata for the vivaria trace
  post-processing path?
- Should `receipt_sha256` hash the inner receipt object alone or the
  pair `(scenario_id, receipt)`?
- Does METR prefer inline cosign certificate material or URL references
  to the GitHub Actions run artifact?
- Should P5 include the signed memo hash inside a bundle annotation or
  keep it only in the audit doc?
