# Lossless raw evidence encoding

The [PostgreSQL isolation job](https://github.com/bb-connor/arc/actions/runs/34434603170/job/102736958798)
failed before any PostgreSQL test ran. `cargo fmt --all -- --check` passed, then
the unchanged `git diff --check f5566d9a...HEAD` gate rejected whitespace in ten
new raw evidence files: retained terminal output and nested patch artifacts.
The [comparison](comparison.json) confirms that the qualification driver and
workflow are byte-identical between base and candidate, and that these raw
files were absent from the base. This was candidate evidence packaging, not an
observed database isolation failure. Full hosted qualification still requires
a fresh run after integration.

Raw bytes are now stored as gzip files with timestamp zero and an empty gzip
filename. Authored source and prose remain ordinary text. No Git attributes,
workflow, test selector or whitespace-gate behavior is changed. In particular,
the original failing test output and literal patch context prefixes are not
trimmed or rewritten to make the gate pass.

[manifest.json](manifest.json) maps each original repository path and Git blob
to its compressed path, original/compressed sizes and SHA256 values. Every
decompressed payload was compared byte-for-byte with its original source commit.
Original checksum-manifest identities are retained in the same record; current
child manifests refer to the compressed files. Historical logical paths inside
raw reports continue to identify their original payloads through this map.

Read any payload without changing the checkout:

```sh
gzip -dc docs/integrations/acceptance/20260909/session-startup/aggregate-tests.log.gz
```

The [failed hosted job and local reproduction](hosted-failure/manifest.json)
retain exact captured bytes as gzip, including the command and exit-code
metadata. `validate.py` checks all mapped gzip/decoded hashes against the retained
original Git blobs, verifies the updated child checksum manifests, and refuses
missing or altered data. Run it from the repository root:

```sh
python3 docs/integrations/acceptance/raw-evidence-encoding-20260910/validate.py
git diff --check f5566d9a765c21cb36652a99c79de64968a656bf...HEAD
```

A subsequent readiness evidence commit `a1b8f0453` added 23 more raw logs,
dependency-tree outputs and nested patches with the same representation issue.
Those files use the same lossless encoding and mapping. Its authored report
remains text, and its child checksum manifest is updated. No additional
PostgreSQL or runtime failure is inferred from these retained historical logs.

Confidence: high in the exact failure cause and byte-preserving representation
repair. Neither this packaging check nor the job's title establishes PostgreSQL
test success.
