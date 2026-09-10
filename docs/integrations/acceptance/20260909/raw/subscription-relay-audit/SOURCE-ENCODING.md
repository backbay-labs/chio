# Retained source encoding

One frozen Claude launcher source snapshot is stored as deterministic gzip.
This retains the exact audited bytes while distinguishing a local launch-record
format in audit evidence from the active Chio wire and SDK schema surface.
The version gate and all runtime source files are unchanged.

`source-encoding-20260910.json` binds its original logical path, Git blob,
decoded length and SHA-256, plus the stored gzip length and SHA-256. Existing
`audited-source-identities.json` describes the original decoded snapshot and is
unchanged. The gzip header has no filename and a zero modification timestamp.

To inspect or recreate the original snapshot outside the checkout:

```sh
gzip -dc sources/claude/scripts/restricted.mjs.gz > /tmp/chio-audited-claude-restricted.mjs
shasum -a 256 /tmp/chio-audited-claude-restricted.mjs
```

The decoded SHA-256 must match `originalSha256` in the encoding manifest and
`sha256` for this source in the original audit identity record. Decompression
was also checked byte-for-byte against the recorded commit and blob.
