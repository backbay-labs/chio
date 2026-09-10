# Docker workspace lockfile qualification

The hosted Build, lint, test job failed before compilation because the generated Docker lockfile omitted `libc` from `chio-sqlite-file-identity`. The source crate already requires that dependency for its qualified macOS file identity repair.

The supported generator added exactly that one dependency entry. Its unchanged `--check` command then passed locally. No crate version, production source, workspace lockfile, or verification rule changed. The hosted build must still rerun; this local check is not full build acceptance.

`result.json` records the failed hosted source/job and both original and compressed evidence identities. Decompress each `.gz` file to recover the exact raw transcript. Confidence in this cause and local generator check is high.
