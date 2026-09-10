# Historical Hermes followup and source preservation

These are previously uncommitted observations from 2026-09-09, retained during
the final source coverage audit. They are **historical evidence, not current
host acceptance**. No host, fault, install or removal case was rerun here.

The source worktree is `hermes-required-integration-20260909` at
`469af30939312d04e33851a8c36a64eed2e60560`, with the original uncommitted files
preserved. This archive was added on a separate worktree based on
`7255e7aedcab8d36e99e459345f3edde55dc58a5`.

## Original scope and outcomes

- Three setup logs preserve earlier dependency/install iterations, including
  failures. They do not replace the [fresh public host installation](../public-host-install/README.md).
- The interrupted-result records use upstream Hermes
  `175054c14b54404663d8614a178280cffe6062eb`, model `gpt-4.1`, the historical
  direct gateway fixture and its then-current Seatbelt profiles. The first
  launcher is terminated after an upstream tool result: exit `-15`, one
  forwarded tool call. The second launcher exits `0`; cumulative forwarding
  remains one call. The resource observer records the original 23-byte effect,
  while the retained journal says `unknown`, `unverified`, and no automatic
  retry. Exit zero alone does not establish successful protected work.
- Both launch records bind gateway script SHA-256
  `e882c579cff0da72476ab60fdca029a7962b84a55440788f12a513d20ed1ac96` and gateway
  configuration SHA-256
  `5d91a08b2db10818b880586b888027989684caec6bd286f4cc5a7850390fcee0`.
  These omitted records do not contain an exact kernel binary identity. No
  identity is reconstructed or borrowed from the later static-kernel runs.
- The Python artifact lifecycle reports isolated installation, replacement,
  dependency checks, entrypoint help and removal. Its old wheel SHA-256 is
  `1525cb1bc3c5eb224ca665c06e4ff6552e7c798aa888c8f8e92859908370d5c3`;
  its new wheel is
  `474dd6a2c1444757519c01ec282849be9a803bb07c7da1a1e3c3810fd91ffbe3`.
  Those are earlier candidates, not the final `625979d...` wheel.
- The six Seatbelt files cover narrow direct/descendant home-read, home-write
  and Unix-socket controls with positive observer checks. Their profile is an
  earlier boundary candidate. They do not establish current complete mediation.

## Preserved source and private exclusions

`raw/omitted-source/scripts/probe_execution_fault.py.gz` is the exact previously
uncommitted interrupted-result helper, SHA-256
`06b96cf5312499a7e0629c3b15bf707b69317f4b757551395ad8ab2730470275`.
It remains an archived source snapshot, not a new current test entrypoint. Its
historical API-key arguments, process-group signal and exit interpretation are
unchanged. Curation checks its syntax without executing it.

`raw/omitted-source/ACTION_INVENTORY.md.gz` preserves the exact omitted draft,
SHA-256 `19aa4ead0678cf8e3ed3ffffb9d8414c40dfc7a7f5cb9dae9922e555b6bcab66`.
That draft still mixed older host-owned journal/kernel-port permissions with
newer default-deny controls. The active [inventory](../../../ACTION_INVENTORY.md)
and [README](../../../README.md) now describe the actual parent-owned HTTP
gateway: the host has neither kernel credentials nor the authoritative journal,
and cannot reach the kernel port. This is a source-document correction only.
Runtime source and frozen wheel/bridge artifacts are unchanged; documentation
changes do not transfer acceptance to a repacked artifact.

Thirty historical observation files and both source drafts are stored as 32
lossless gzip files, including empty files and repeated case-associated output.
`files.json` binds each original path, decoded length/hash and compressed hash.
All decoded bytes were compared to their preserved original files.

Two private runtime `config.yaml` files are excluded from the public archive.
Their paths, lengths and SHA-256 identities are recorded in
`excluded-private-configurations.json`; originals remain untouched. Their
credential fields were included in the exact-value exclusion scan. The five
already-retained public-install files are verified byte-for-byte against their
existing compressed copies and indexed in `already-retained.json`.

Curation scanned known operator/provider/delegated credential values plus
provider-token and private-key patterns, with zero matches in exported files.
This is a bounded credential review, not a claim that arbitrary historical
logs are safe by default. The archive does not remove original failures,
normalize source bytes, or promote rejected boundaries. Current local host
observations remain in the [static-kernel record](../static-kernel-native/README.md).
