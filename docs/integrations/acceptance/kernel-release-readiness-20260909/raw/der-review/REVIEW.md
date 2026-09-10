# der 0.8 patch source review

Decision: do not certify 0.8.0 -> 0.8.1 as safe-to-deploy. Published 0.8.1 contains a confirmed nested trailing-data regression. The newer compatible non-yanked 0.8.2 fixes it, but the added SetOfRef parser still has unresolved error-suppression behavior. No blanket safe-to-deploy audit is issued for either delta in this review. This is a source review, not a compiled regression run. Confidence is high for the source findings and published patch identity; application exploitability is not established.

## Source provenance and completeness

Downloaded all archives directly from https://static.crates.io/crates/der/ and verified SHA256 against https://crates.io/api/v1/crates/der/<version>. Complete archive file manifests and complete diffs retained. Read every line of the 0.8.0 -> 0.8.1 diff (1676 lines;14 changed files,1 added test,58 unchanged files) and 0.8.1 -> 0.8.2 diff (433 lines). No archive symlinks or traversal paths accepted while extracting.

- 0.8.0: 71fd89660b2dc699704064e59e9dba0147b903e85319429e131620d022be411b; VCS metadata7784544099435bddfe0fd4c9a0ef4f60ce37093b; registry currently yanked.
- 0.8.1: a69dedd701da44b0536442edf09c81a64b0ab97a7a4a5e3d1971f00027cbc63d; VCS metadata905717f83173b30a92304a57b7412f85c1788be9; registry non-yanked, published2026-07-09.
- 0.8.2: a878c850e9e421b20262e9b41f9c860e4785fa07541c266b62ff9d1ef998a80a; VCS metadata7637997c168f710f02ae4037a9f134c31dc8f9ff; registry non-yanked, published2026-09-05. Latest stable compatible0.8 patch returned by API.

The VCS SHAs above are archive metadata, not separately verified source-tree equality. Registry responses, tarballs, and identities are saved. 0.8.2 changelog says 0.8.0 was yanked to fix a minimal-versions CI check. Parent's cargo-deny output is a yanked-crate error, not a RustSec advisory report.

## Complete delta summary

0.8.1 changes package/VCS/changelog/license metadata; updates the package's standalone Cargo.lock; tightens arbitrary dependency floor to1.4.2 and adds optional derive_arbitrary under arbitrary only; introduces SetOfRef and iterator/comparison/ownership conversions; allows SET OF duplicate elements; changes sorting from insertion sort to sort_unstable_by while retaining first comparator error; introduces shared Position depth state and a depth limit; refactors SliceReader nested reads; adds nesting/sorting/duplicate/borrowed-set tests and one test-only dead-code annotation. No new build script, unsafe block, process launch, network IO, or filesystem IO in the delta.

Positive security changes: sorting changes remove the former quadratic reverse-order sorting path (upstream issue2319); a depth counter refuses split_nested when incremented depth reaches64. This bounds that Reader recursion path, not arbitrary user-written recursive decoders or recursive code that creates fresh readers. Duplicate acceptance is intentional ASN.1 SET OF semantics, not a security waiver; callers needing uniqueness must enforce it separately.

The published package Cargo.lock changes do not migrate into Chio's workspace lockfile. The reviewed Chio lockfile proposal changed der0.8.0 identity/checksum and its pkcs8/spki references only. Parent subsequently retained that rejected proposal at dependency-impact/unaccepted-der-0.8.1.patch and restored Cargo.lock. Its resolved dependency list remains const-oid0.10.2,pem-rfc74681.0.0,zeroize. The new arbitrary option is not selected in that lock entry.

0.8.2 adds AsIntRef/AsUintRef borrowing traits/impls and reexports, restores the nested trailing-data check plus regression test, updates standalone lock/metadata, and removes one lint. It does not change SetOfRef.

## F1: 0.8.1 drops nested full-consumption enforcement

0.8.0/src/reader/slice.rs read_nested invokes nested_reader.finish() before returning success. 0.8.1/src/reader/slice.rs:88-105 instead restores the outer byte view and length and returns the callback result without checking nested remaining bytes. reader.rs:247-264 read_value and decode.rs:112-115 rely on read_nested, so an outer decoder can interpret leftover inner bytes as later outer fields.

Minimal source-derived case: input0102; read_nested(length2, callback reads one byte and returns Ok). 0.8.0 rejects trailing data;0.8.1 returns Ok and leaves byte02 for the outer decoder. The exact restoration appears in 0.8.2/src/reader/slice.rs:100-116, with upstream regression test at:235 onward. Upstream PR https://github.com/RustCrypto/formats/pull/2401 explicitly identifies this regression and is included in0.8.2.

Concrete downstream parser: spki0.8.0/src/algorithm.rs:40 reads only OID and optional parameters; spki.rs:106 then decodes the outer subject_public_key. Source-derived malformed SPKI candidate300b300906022a030500030100 places the bitstring inside the AlgorithmIdentifier length after OID1.2.3 and NULL. The missing nested check permits the outer SubjectPublicKeyInfo parser to consume those remaining inner bytes as the key. This case was not executed and does not establish acceptance by Ed25519-specific validation.

Actual optional Iroh graph reaches der through iroh1.0.1 -> ed25519-dalek3.0.0-rc.0 -> ed255193.0.0 -> pkcs80.11.0/spki0.8.0. iroh1.0.1/src/endpoint/connection.rs:395 invokes VerifyingKey::from_public_key_der on the peer certificate. ed255193.0.0/src/pkcs8.rs:274-278 additionally requires Ed25519 OID and absent parameters, which rejects the generic OID/NULL specimen above. Do not claim demonstrated Iroh authentication bypass.

## F2: SetOfRef still suppresses typed decode/comparison errors

Present unchanged in both0.8.1 and0.8.2:
- src/asn1/set_of.rs:156-176 validates raw elements with AnyRef, not T, then checks ordering over a typed iterator.
- :454 uses T::decode(inner_reader).ok()?, converting malformed/wrong-type elements to end-of-iteration.
- :174 and:361 treat any der_cmp error as a successful ordering comparison (anything except Ok(Greater)).
- :468-469 still advertises the original element count through ExactSizeIterator even when typed decoding ends early.

Source-derived case: SetOfRef::<u8>::from_der([0x31,0x02,0x05,0x00]) is SET OF containing NULL, invalid for SET OF INTEGER. AnyRef accepts NULL and counts1. u8 decode rejects NULL's tag; the iterator returns None, is_sorted_by sees an empty iterator and returns true, and construction succeeds. len reports1 while iteration yields0; re-encoding via iteration produces empty SET OF. No compiled execution was performed. This is sufficient unresolved semantic concern to withhold a generic audit, not a claim of exploitable Chio behavior.

No SetOfRef usage found in Chio crates (excluding generated code), nor in the inspected transitive iroh1.0.1,iroh-base1.0.1,ed25519-dalek3.0.0-rc.0,ed255193.0.0,pkcs80.11.0,spki0.8.0 source. Existing SetOfVec users do not automatically switch to the new borrowed type. The issue's current application reachability is therefore not demonstrated. A future use must not inherit an unqualified audit assertion.

## Selected release-binary impact

Independently byte-compared parent's saved before/after cargo tree outputs for all5 release targets; all identical, all lack der0.8 and iroh. See selected-cli-graph-verification.json for hashes. crates/products/chio-cli/Cargo.toml:43-44 marks Iroh dependencies optional;:133-139 says the feature is default-off. Workspace builds still contain chio-federation-transport-iroh and conformance dev paths. Consequently no selected default CLI runtime graph changes, but workspace release gates remain applicable and cannot be declared satisfied from graph equivalence.

## Next resolving action

Do not adopt0.8.1.0.8.2 is the published alternative that fixes F1, but F2 must be resolved or disproved before this reviewer can issue generic safe-to-deploy certification. Focused source regression cases are supplied for a separately authorized build slot. No speculative crypto patch, vendor fork, new policy criterion, or waiver is proposed. This review creates no audits.toml entry or certification claiming success. The remaining blocker is approval of a compatible dependency version under the existing criteria, not access to the registry or absence of the0.8.2 release.

No repository source was changed, no cargo/build command was run, and no upstream message or disclosure was sent.
