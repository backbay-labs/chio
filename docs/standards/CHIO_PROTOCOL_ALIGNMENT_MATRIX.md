# Chio Protocol Alignment Matrix

This matrix maps the shipped Chio protocol surfaces to adjacent standards and
ecosystem work. It is an alignment matrix, not a claim that the referenced
standards already define the whole Chio stack.

| Chio concept | Adjacent standard | Current Chio mapping | Boundary / gap |
| --- | --- | --- | --- |
| delegated capability issuance and continuation | GNAP | Chio's capability issuance and continuation model is closest to GNAP-style delegated authorization semantics | Chio uses its own signed capability and receipt artifacts today rather than claiming GNAP wire compatibility |
| signed receipts and evidence export | SCITT | Chio receipts, checkpoints, and export bundles align with the same "signed transparent evidence" problem space | Chio is not yet a SCITT profile and does not claim SCITT interoperability by default |
| runtime attestation and verifier-backed security posture | RATS | Chio's runtime assurance and attestation appraisal work aligns with RATS roles and evidence/appraisal concepts | Chio currently preserves its own receipt and policy binding semantics rather than exposing a full RATS protocol profile |
| sender-constrained protected-resource admission | RFC 9449 (DPoP) | Chio's hosted sender-constrained path aligns with DPoP's proof-of-possession goal | Chio also carries a Chio-native DPoP format and does not claim the native framed lane is RFC 9449 wire-compatible |
| canonical JSON signing and hashing | RFC 8785 | Chio signs capabilities, receipts, and proofs over canonical JSON | This is a direct alignment point and one of Chio's normative dependencies |
| portable trust and credential projection | W3C VC Data Model | Chio passport and portable trust artifacts overlap with VC-style issuer/holder/verifier concerns | Chio remains `did:chio`-first and does not claim generic VC neutrality |
| credential issuance transport | OID4VCI | Chio ships a bounded OID4VCI-compatible issuance lane for passport-style artifacts | The shipped profile is intentionally narrow and not a full multi-format OID4VCI implementation |
| verifier presentation transport | OID4VP | Chio ships a bounded OID4VP-style verifier lane for passport presentation | Chio does not claim broad wallet-network interoperability beyond the documented bounded profile |

## Reading The Matrix

- "aligns with" means Chio solves a related problem using a shape that can be
  compared to the named standard.
- "boundary / gap" records where Chio intentionally remains narrower, different,
  or still incomplete.
- The executable evidence source for the core protocol claims is the native
  conformance lane under `tests/conformance/native/`.
