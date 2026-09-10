# Published DER dependency qualification

Status: registry `der 0.8.2` selected for the optional workspace dependency, with a non-exportable `safe-to-deploy` delta audit. This is not six-host acceptance or full release qualification. No vendor patch was selected. The default CLI used by the five host matrices still selects DER 0.7.10; its normal/build dependency graphs are byte-identical across all five release targets. Frozen host artifacts are unchanged.

The registry archive SHA256 is `a878c850e9e421b20262e9b41f9c860e4785fa07541c266b62ff9d1ef998a80a`. The source review covers every line of the published 0.8.0 to 0.8.1 and 0.8.1 to 0.8.2 changes retained in the earlier kernel-readiness record. Version 0.8.1 remains rejected because of its nested trailing-data regression. Version 0.8.2 restores the required full-consumption check. No new unsafe code, process execution, filesystem access or network access appears in the delta.

## Executed checks

- Actual Iroh Ed25519/SPKI parser dependency features: 17 tests passed with four accepted valid keys and 59 rejected malformed inputs. This standalone library suite verifies published package checksums and real signature verification under decoded keys.
- Chio optional Iroh transport: 179 tests and two doctests passed, zero skipped, including real local QUIC and authenticated sender checks.
- Published upstream DER all-feature suite: 187 passed, one pre-existing ignored doctest, explicitly not counted as passed.
- Cargo-vet locked: passed (571 fully audited, six partially audited, 736 exempted); no new exemption or relaxed criterion.
- Cargo-deny: advisories, bans, licenses and sources passed.

The hosted source check at `8408ae9996d5f011849406b07490e5ec67928e8d`
passed those four cargo-deny checks and the external wildcard check, then failed
the separate duplicate-version inventory: it still named DER 0.8.0. The inventory
now names the reviewed 0.8.2 selection; no duplicate was added or removed and no
policy was relaxed. `hosted-duplicate-inventory-failure.log.gz` preserves the
complete failed job. The earlier local success did not establish that this
separate inventory was current. The corrected inventory check passes locally;
its new hosted result remains required.

## Audit judgment and known limitation

The existing built-in criterion permits documented discretion; it is not a universal API correctness certificate. The previously reported SetOfRef typed-decoding/comparison defect remains present in the published package. There is no use of that new API in Chio or the inspected Iroh, Ed25519, PKCS8 and SPKI parent paths. The actual deployed parser path rejects the malformed inputs tested above. Based on the complete delta and baseline context, the reviewer judges that this update does not introduce a serious security vulnerability in the selected Chio deployment. Confidence is moderate in that contextual security judgment and high in the executed results and provenance.

The audit is `importable = false`; its notes preserve the defect and require renewed review if SetOfRef is introduced. That flag prevents other projects from importing the judgment automatically. It does not redefine the criterion or mechanically constrain future Chio API usage. No claim is made that all possible uses of this package are correct. See the pinned cargo-vet 0.10.2 criteria and implementation review in the archive, and [the official criterion](https://mozilla.github.io/cargo-vet/built-in-criteria.html).

A separate disposable constructor correction passes 193 upstream tests, while the original source fails three of its new conformance regressions. That experiment confirms the defect and a possible repair; its patch is retained but is not a repository dependency. Its one pre-existing ignored doctest remains explicitly unresolved as a test result, rather than counted as success.

## Evidence

`review-and-tests.tar.gz` contains exact source-review inputs, command outputs, parent conformance evidence, transport results, selected dependency graphs and the unselected patch. `raw-manifest.json` binds every archived file. The historical readiness report describes the earlier unresolved audit state; this record resolves the dependency selection only. Full hosted release qualification and any new runtime artifact qualification remain open.
