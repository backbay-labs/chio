# Submission package for draft-whelan-chio-protocol-00

Prepared September 30, 2026. This is an individual Internet-Draft with intended status Standards Track. It has not been posted: the Datatracker document URL returned HTTP 404 on September 30. The draft is not an adopted working-group document or an RFC.

The single source is `draft-whelan-chio-protocol.md`. The upload file is `draft-whelan-chio-protocol-00.xml`, the expanded RFCXML v3 rendering. The prepped XML is the docs reader's source; the text and PDF are companion renderings. `CLAIMS.md` contains the independent implementation review and its claim limits.

Author: Connor Whelan, Backbay Industries, `connor@backbay.io`. Discussion: `agentproto@ietf.org`; public issues: <https://github.com/backbay-labs/chio/issues>.

## Owner submission steps

1. Review the source, claim ledger, and rendered PDF. Set the source's `date` to the actual submission date if it differs from September 30, 2026, then regenerate and check all outputs. A date change also requires refreshing the website's generated document and downloads.
2. Open <https://datatracker.ietf.org/submit/> and upload `draft-whelan-chio-protocol-00.xml`.
3. Confirm the extracted name, revision `00`, title, author email, IETF stream, Standards Track intended status, date, and generated expiry. Confirm the author's BCP 78/79 declarations in the submission tool.
4. Submit and complete the confirmation email sent to `connor@backbay.io`. Confirm that <https://datatracker.ietf.org/doc/draft-whelan-chio-protocol/> shows revision `00` and the intended metadata.
5. Verify the public Chio source revision used by the website, regenerate its pin/data/downloads, and merge the site PR only after posting. Check the deployed page, downloads, source links, official anchors, and OG image against the posted document.

## Intellectual property answer

The owner answered the submission-checklist question about known patents or patent applications held by the owner, Backbay Industries, or another party: **"None that I am aware of."** This records the answer supplied; it is not a patent search. The author completes the submission tool's declarations and any required disclosure at <https://datatracker.ietf.org/ipr/>.

## Deadline

The internal posting target remains November 1. The [official IETF 127 deadline](https://datatracker.ietf.org/meeting/127/important-dates/) is **November 2, 2026 at 23:59 UTC**, for all Internet-Drafts, including `-00` (verified September 30, 2026). IETF 127 begins November 14 in San Francisco.

## Regeneration and validation

Use kramdown-rfc 1.7.43, xml2rfc 3.34.1, WeasyPrint 70.0, aasvg 0.5.7, idnits 3.1.0, Python 3, and `pdftotext`. The workflow installs the matching versions plus PDF fonts and native dependencies. Place the Ruby gem's executable directory on PATH; `KRAMDOWN=/path/to/kramdown-rfc` is also supported.

```sh
make -C spec/ietf
make -C spec/ietf check
```

The check regenerates all renderings, checks the vector corpus and folded bytes, compares XML/prepped XML/text and extracted PDF text, rejects writer diagnostics and incomplete validation runs, enforces 72-column text, and rejects all idnits errors or warnings. PDF layout comparison requires the matching fonts; Linux CI is the independent cross-platform verification.
