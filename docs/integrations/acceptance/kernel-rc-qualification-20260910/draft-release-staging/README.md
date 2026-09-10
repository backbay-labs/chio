# Candidate release staging validation, 2026-09-10

This record covers local release-workflow and identity-checker validation. It does
not accept a kernel archive or any agent host. No candidate release was created,
no assets were uploaded, and no release was published by this repair.

The patch starts from `bafa02b06de93553cecb6f60b340f3dd8fd9b401` and includes
the separately demonstrated Syft 1.51.1 validator correction. `validation.json`
binds the reviewed source files by SHA-256 and records commands and exit codes.
All 55 focused test methods passed with zero failures or skips. Workflow lint,
release input inventory, release assurance and whitespace checks also passed.
The draft checker tests use disposable files and injected GitHub response fixtures;
these are regression tests, not hosted release evidence.

The read-only live negative control queried `backbay-labs/chio` and refused to stage
its existing published `v0.1.0` release. The retained release inventory, asset
metadata and refusal stderr establish only that refusal. The old release does not
have the required candidate signature/provenance material, so it cannot supply a
positive signed-candidate control. The pinned SLSA tag identity and upstream action
contracts are retained separately from any release acceptance claim.

The root operator attempted the repository workflow-PR permission setting and
GitHub rejected it with HTTP 409 because organization policy forbids bot-created
or bot-approved PRs. The exact non-secret API response and preceding permission
state are retained as `operator-pr-policy-*.json`. No setting changed. The bounded
fallback retains the OIDC-signed checksum index in an Actions artifact and on the
draft. The job explicitly leaves operator checksum review pending. Promotion's
read-only identity check requires an actual merged PR into canonical `main` with
exactly the signed index and its signature/certificate siblings, unchanged at both
the merge commit and current `main`. It does not waive review, required checks,
cosign, SLSA, source/security gates or any real-host acceptance gate.

Candidate publication remains a trusted operator action after those gates pass.
The identity helper records every release/asset ID and downloaded hash, and refuses
replacement or changed bytes before and after publication. It neither signs nor
publishes anything. A changed archive requires fresh qualification; local binary
results cannot be transferred to a hosted rebuild.

Still unexecuted: hosted draft creation and authenticated download; real cosign and
SLSA verification of candidate bytes; actual operator checksum PR and merged-file
verification; all required real-host cases against those hosted bytes; publication
and the public installation path. None of these are reported as passed or skipped.
See `docs/install/PUBLISHING.md` for the exact retrieval and promotion procedure.
