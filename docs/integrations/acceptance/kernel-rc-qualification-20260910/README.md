# Kernel CLI release candidate preparation

Status: candidate source, not a published or accepted runtime. All six host
integrations remain mandatory. The preceding frozen local bundle remains selected
until replacement artifacts have their own host qualification.

The CLI package has the explicit version `0.1.1-rc.1`. Library package versions
remain unchanged. This distinguishes a new binary from the original public CLI
0.1.0 and the hash-selected development binary that used the same label. Cargo
generated the root lockfile; the supported Docker workspace generator updated
its derived lockfile. This change does not claim any replacement binary tested.

## Publication boundary

The existing binary release workflow previously checked build and tag identity
without requiring the full source qualifier to have succeeded. The new publication
step requires successful CI, security and release-qualification runs for the exact
source on `main` in the same repository. It checks each required job in the latest
attempt of the newest eligible run. An older green run cannot mask a newer failure.
Pending, cancelled, skipped, missing, foreign and truncated results refuse
publication. The checkout and compiled CLI version must match the release SHA
and tag. Existing tag verification, signing, SBOM and provenance steps remain.

Required workflow/job identities are explicit in
`scripts/check-release-source-gates.py`. CI must have a successful `main` push
run. Run `cve-monitor.yml` on `main` after source integration if the scheduled
scan has not covered that commit. The release qualifier runs on `main` pushes;
manual reruns must select that same source. The release tag must identify the
qualified commit. No tag, registry upload or binary publication is performed by
the local preparation checks. SLSA generation and release-asset verification
remain actual hosted release steps, not inferred from this gate.

The existing release workflow can be retried from the same tag after missing
checks complete. A failed source check requires repair and qualification of the
new source; changing the gate or substituting another commit's evidence is not
a recovery procedure.

## Local gate validation

`python3 scripts/tests/check-release-source-gates.test.py` exercises API failure,
run/job identities, latest-attempt selection, incomplete results and real Git
checkout/tag/version checks. Only the GitHub responses are fixtures. These are
publication guard tests, not host or kernel acceptance. The tests also run in
the existing CI structural lane and full release driver. Actionlint validates
both changed workflows. The live GitHub job response was checked for `run_id`,
`head_sha` and `run_attempt` fields before depending on those bindings.
