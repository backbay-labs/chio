# chio-credentials

`chio-credentials` provides portable reputation credentials and Agent Passport
verification for Chio. The native passport format stays intentionally simple:
credentials are canonically JSON-signed with Ed25519, issuer and subject
identities are `did:chio` identifiers, a passport is an unsigned bundle of
independently verifiable credentials, and verification is pure with no kernel
or storage dependency. A narrower standards-native projection lane supports
external OID4VCI-style issuance, derived from the native passport rather than
replacing it as the source of truth.

Use this crate to issue or verify Chio agent reputation credentials and
passports.
