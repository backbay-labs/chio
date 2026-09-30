# PDF fonts

The PDF build uses only this directory's fonts through `FONTCONFIG_FILE`.
System font versions and proprietary fallback fonts cannot change its layout.
The original font files are unmodified and distributed under their adjacent
SIL Open Font License files. `sources.json` records immutable upstream URLs,
sizes, and SHA-256 digests.

Noto Serif supplies body text, Roboto Mono supplies code, and Noto Sans Symbols 2
supplies symbols such as the open-circle list marker. The font configuration
does not include the host's default directories or substitutions.
