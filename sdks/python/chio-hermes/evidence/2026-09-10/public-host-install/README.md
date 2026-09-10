# Fresh public Hermes host installation

Status: the pinned upstream host was installed into a new environment from a
fresh public Git fetch and an empty uv cache. Dependency and launcher-contract
checks pass. This is I01 prerequisite evidence, not real-host kernel acceptance
or publication of the Chio version combination. Confidence: high.

| Input or observation | Exact identity |
| --- | --- |
| Public upstream | `https://github.com/NousResearch/hermes-agent.git` |
| Source commit | `175054c14b54404663d8614a178280cffe6062eb` |
| Source tree | `b485d3e994bda896e30ba7e3216aadb641b1d8e3` |
| Source status | Clean after installation; installation `.env` absent |
| Host version | `hermes-agent==0.20.5` |
| Chio launcher-contract verifier | Wheel `chio-hermes==0.1.2`, SHA-256 `625979d5331796e7aef5906e69e3e2c746796aa570291af026c305ed4227c818` |
| Python | `3.11.3`; binary SHA-256 `c220ae7b6c2b9da2a4e498c09cdbc64b03b43db96dbbf9f64d26bfbbd698e2bd` |
| uv | `0.12.11 (4b53f66b7)`; binary SHA-256 `787778013dbe20364ec2c00e51952d600edefffa3a5cef44e97a9c7c84694bad` |
| Upstream lock SHA-256 | `64a66f8a0ce1d23ea10c16ca89b7104f1828a8f21cf1dd95d7cb74e4bd3efa10` |
| Upstream pyproject SHA-256 | `f2d8625df7b015c52a7940ac9f6dd51cc89e70ca13548511fb4f293c90926d99` |
| Installed distribution count | 75; `uv pip check` passes |
| Installed dependency freeze SHA-256 | `03aefb187df5352c34a22a9e03ca3de61dccea86e55e6f09ffb2c5696280d89c` |
| Metadata and RECORD inventory SHA-256 | `a231922a44f7ef20bd5692bed24a64f83098d8d8afde74abbbe7b56d4f4a54ef` |

The source directory is
`/tmp/chio-hermes-public-final-install-20260910/source`; the selected host Python
is `/tmp/chio-hermes-public-final-install-20260910/qualified-venv/bin/python`.
The installed dependency inventory has exactly one local distribution:
Hermes itself, in its upstream-supported editable source installation. Its
resolved source path is the new public checkout. The other 74 distributions
come from the upstream locked package sources. No private Chio checkout or
previous host environment supplies a runtime dependency.

The exact commands, controlled environment and exit codes are retained in
`raw/current/runs.json.gz`. The successful installation uses Python 3.11.3 and:

```bash
git init "$HERMES_SOURCE"
git -C "$HERMES_SOURCE" fetch --no-tags --depth=1 \
  https://github.com/NousResearch/hermes-agent.git \
  175054c14b54404663d8614a178280cffe6062eb
git -C "$HERMES_SOURCE" checkout --detach FETCH_HEAD
UV_PROJECT_ENVIRONMENT="$HERMES_VENV" UV_CACHE_DIR="$HERMES_EMPTY_CACHE" \
  uv sync --project "$HERMES_SOURCE" --python 3.11.3 \
  --locked --extra mcp --no-dev --no-python-downloads
```

The executed command selects the exact already-installed Python binary; the
version form above expresses the same version prerequisite. New empty
`XDG_CONFIG_HOME` and cache directories remove ambient user configuration and
previous package cache state. The pinned project configuration remains active.
The selected Chio wheel's `validate_host` function also accepts every pinned
host contract file in this new checkout; its output is retained separately.
The actual pinned `hermes --version` entry point also exits 0 from a separate
empty profile and reports Hermes v0.20.5, Python 3.11.3 and OpenAI SDK 2.24.0.
No provider credentials were supplied and no native model session ran as part
of these installation checks.

Two failed harness attempts remain visible:

- Adding `--no-config` disabled upstream `[tool.uv]` settings, including its
  dependency-age policy. `--locked` correctly refused resolution changes. The
  retry used another new venv and empty cache with the pinned project settings
  active. No lockfile or dependency policy was edited.
- An identity assertion compared the literal `file:///tmp/...` URL with macOS's
  canonical `/private/tmp/...` alias. The corrected assertion parses the URL and
  compares resolved paths. The same installed files and lock remain unchanged.

`raw/prior-relocation/` preserves the earlier source-fetch logs and a successful
replacement of an editable host inside an existing environment. Those records
are historical relocation evidence. They do not replace the new empty-cache,
new-environment installation above. Their original untracked source files remain
untouched.

All raw files use deterministic, lossless gzip. `files.json` binds both original
bytes and compressed identities. The credential scan compares the exported
plaintext against actual known private provider/operator/delegated credentials
without exporting their values. New host, operator and provider profiles are not
included. `SHA256SUMS.json` covers the committed record.
