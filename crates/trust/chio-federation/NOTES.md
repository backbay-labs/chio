# chio-federation NOTES

## Bilateral verifier schema completion

The federation crate keeps two separate verifier profiles:

- `chio.bilateral-signature-slice.v1` remains the compatibility profile for
  compatibility local receipt binding.
- `chio.bilateral-cosign-invocation.v1` is the strict Chio profile used by
  `verify_chio_bilateral_invocation`.

Strict Chio verification requires `tool_args_hash`, rejects the compatibility
`receipt_canonical_json` helper field, requires fresh pinned ladder manifest
references, resolves the receipt body from the configured receipt store, checks
the subject digest, resolves lease and governance references, and fails closed
on unknown action classes.

### Remaining Work

1. Produce a step-by-step public coverage matrix against
   the strict treaty-bound bilateral invocation profile.
2. Add interop vectors once an external implementation exists.
3. Keep the signature-slice compatibility profile documented as non-Chio
   conformance evidence.
