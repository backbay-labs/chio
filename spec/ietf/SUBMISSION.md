# Chio Protocol submission package

Author: Connor Whelan, Backbay Industries, <mailto:connor@backbay.io>.
Public source and issues: <https://github.com/backbay-labs/chio>.

The canonical source is `draft-whelan-chio-protocol.md`. Expanded RFCXML v3 in `draft-whelan-chio-protocol-00.xml` is the upload artifact; the prepped XML feeds the document reader. Text and PDF are companion renderings.

## Preparation

1. Verify the completed release against the draft's conformance and security requirements. Review [the document checks](CLAIMS.md) and the rendered PDF.
2. Set the source date to the submission date and regenerate every rendering. Confirm the name and revision against any preceding submission before reusing `-00`.
3. Publish the source revision, regenerate the reader and downloads from that exact public revision, and verify source links and artifact hashes.
4. Submit the expanded XML through <https://datatracker.ietf.org/submit/>. Confirm the title, author, stream, intended status, date, and revision. Complete the author's BCP 78/79 declarations and email confirmation.
5. After posting, compare the official rendering and anchors with the reader and downloads. An individual submission does not establish working-group adoption.

## Regeneration

Use kramdown-rfc 1.7.43, xml2rfc 3.34.1, WeasyPrint 70.0, aasvg 0.5.7, idnits 3.1.0, Python 3, Fontconfig, and pdftotext. The repository workflow installs the pinned toolchain; bundled OFL fonts make PDF rendering reproducible.

```sh
make -C spec/ietf
make -C spec/ietf check
```
