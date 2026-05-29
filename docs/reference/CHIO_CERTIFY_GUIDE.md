# Chio Certify Guide

`Chio Certify` is the certification layer that turns a conformance evidence
corpus into a signed pass/fail artifact, then publishes or resolves that
artifact through a fail-closed registry when operators need a stable status
surface.

The current surface is intentionally narrow but now covers the operator loop:

- it evaluates an explicit conformance scenario/result corpus
- it applies one fail-closed criteria profile, `conformance-all-pass-v1`
- it signs the resulting artifact with an operator-controlled Ed25519 key
- it can verify a signed artifact locally
- it can publish, list, get, resolve, and revoke signed artifacts in a local
  or trust-control-backed registry

This is still not a public certification marketplace.
It is now a conservative multi-operator discovery contract: operators can
publish to more than one registry, and relying parties can discover
per-operator certification state without collapsing those operators into one
global mutable store.

Passport lifecycle and certification registry state are related but distinct
surfaces. A passport registry answers whether a portable identity artifact is
current for one subject. A certification registry answers whether a signed
tool-server certification artifact is current for one server. Neither registry
silently implies the other.

## Command

```bash
chio certify check \
  --scenarios-dir tests/conformance/scenarios/mcp_core \
  --results-dir target/release-qualification/conformance/mcp_core/results \
  --output target/release-qualification/conformance/mcp_core/certification.json \
  --report-output target/release-qualification/conformance/mcp_core/certification-report.md \
  --tool-server-id demo-server \
  --tool-server-name "Demo Server" \
  --signing-seed-file .chio/certify-ed25519.seed
```

Verify one artifact:

```bash
chio certify verify \
  --input target/release-qualification/conformance/mcp_core/certification.json
```

Publish into a local registry:

```bash
chio certify registry publish \
  --input target/release-qualification/conformance/mcp_core/certification.json \
  --certification-registry-file .chio/certifications.json
```

Resolve the current certification state for one tool server:

```bash
chio certify registry resolve \
  --tool-server-id demo-server \
  --certification-registry-file .chio/certifications.json
```

Use the trust-control service instead of a local file:

```bash
chio --control-url http://127.0.0.1:8940 \
  --control-token "$CHIO_CONTROL_TOKEN" \
  certify registry list
```

Publish across a configured discovery network:

```bash
chio certify registry publish-network \
  --input target/release-qualification/conformance/mcp_core/certification.json \
  --certification-discovery-file .chio/certification-network.json
```

Discover one tool server across multiple operators:

```bash
chio certify registry discover \
  --tool-server-id demo-server \
  --certification-discovery-file .chio/certification-network.json
```

## Criteria Profile

`conformance-all-pass-v1` passes only when all of the following are true:

- the scenario corpus is non-empty
- the result corpus is non-empty
- every result maps to a declared scenario
- every declared scenario has at least one result
- every declared scenario has `expected: "pass"`
- every observed result is `pass`

The command fails closed at the verdict layer:

- `fail`, `unsupported`, `skipped`, and `xfail` all block certification
- unknown-scenario results block certification
- partial coverage blocks certification

## Artifact Shape

The generated JSON artifact contains:

- the stable schema ID for new issuance: `chio.certify.check.v1`
- legacy compatibility verifiers still accept `chio.certify.check.v1`
- the target tool-server identity
- the criteria profile used
- a pass/fail verdict
- summary counts across the evaluated corpus
- explicit findings for partial coverage, unknown scenarios, and non-pass results
- normalized SHA-256 digests of the loaded scenarios, results, and generated report
- the signer's public key and the Ed25519 signature over the canonical JSON body

The artifact is portable: a verifier only needs the body, signature, and public
key to validate integrity.

## Registry Model

The registry stores the signed certification artifact as the immutable payload
and derives a stable `artifactId` from the canonical SHA-256 digest of the full
signed JSON.

Each registry entry tracks:

- `artifactId`
- `artifactSha256`
- `toolServerId` and optional `toolServerName`
- `verdict`
- `checkedAt`
- `publishedAt`
- `status`: `active`, `superseded`, or `revoked`
- optional `supersededBy`
- optional `revokedAt` and `revokedReason`

Publishing a new artifact for the same `toolServerId` automatically supersedes
the previously active artifact. Revocation is explicit and does not silently
reactivate older entries.

`resolve` returns one operator-facing state for a tool server:

- `active`: a current published artifact exists
- `revoked`: no active artifact exists and the latest relevant entry is revoked
- `superseded`: no active artifact exists and only superseded history remains
- `not-found`: the registry has no artifact for that tool server

## Discovery Network

Chio now supports a file-backed certification discovery network that lists
explicit remote operators rather than pretending there is one global registry.

Each operator record names:

- `operatorId`
- optional `operatorName`
- `registryUrl`
- optional `controlToken` for authenticated publish fan-out
- `allowPublish` to opt an operator into multi-publish flows

`chio certify registry discover` queries the public read-only endpoint
`/v1/public/certifications/resolve/{tool_server_id}` on each configured
operator and returns:

- per-operator reachability
- per-operator `active` / `superseded` / `revoked` / `not-found` state
- the operator-scoped current artifact payload when one exists

`chio certify registry publish-network` fans one signed artifact out to all
selected operators that explicitly allow publication and have a configured
service token.

Trust-control can host the same discovery behavior:

```bash
chio trust serve \
  --listen 127.0.0.1:8940 \
  --service-token "$CHIO_CONTROL_TOKEN" \
  --certification-registry-file .chio/certifications.json \
  --certification-discovery-file .chio/certification-network.json
```

The authenticated aggregator surface is:

- `POST /v1/certifications/discovery/publish`
- `GET /v1/certifications/discovery/resolve/{tool_server_id}`

The public read-only discovery surface is:

- `GET /v1/public/certifications/resolve/{tool_server_id}`

This mirrors the passport lifecycle contract intentionally:

- both registries preserve immutable signed artifacts and layer mutable
  operator status beside them
- both registries expose `active` / `superseded` / `revoked` / `not-found`
  resolution instead of deleting history
- both registries can be surfaced locally or through `chio trust serve`

What differs is the identity key:

- passport lifecycle resolves by `passportId` and subject/issuer set
- certification lifecycle resolves by `toolServerId`

Discovery is still conservative:

- operators remain distinct; Chio does not merge them into one global trust root
- discovery returns operator-scoped truth, not synthetic global verdicts
- publication fan-out is explicit and opt-in per operator

## Signing Model

Use a dedicated seed file for certification signing. The command will create it
on first use if it does not already exist.

Treat that file as an operator trust root:

- keep it out of source control
- restrict it to the certification operator
- rotate it deliberately, not per run

If you expose registry operations through `chio trust serve`, configure a
dedicated `--certification-registry-file` on that service and keep the bearer
token explicit with `--service-token`. The same trust-control process can also
host `--passport-statuses-file` when operators want both portable identity
status and certification status on one service boundary.

## Relationship To Release Qualification

`Chio Certify` is built on top of the existing conformance and qualification
pipeline. A typical flow is:

1. run `./scripts/qualify-release.sh`
2. inspect the generated compatibility report and raw results
3. run `chio certify check` against the selected scenario corpus
4. optionally run `chio certify verify` as a local integrity gate
5. publish the signed artifact into the local or remote certification registry
6. use `chio certify registry resolve` to surface the current operator-facing
   status for that tool server
