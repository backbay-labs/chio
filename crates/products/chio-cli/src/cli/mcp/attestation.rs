// "Chio-verified" attestation header for wrapped tool responses.
//
// Every `tools/call` result that flows through the wrap loop carries a
// `_meta.chio_verified` block that surfaces inside IDEs that render
// custom annotations. The block is small and stable so downstream
// consumers can pattern-match it without parsing the human message:
//
//   {
//     "header": "Chio-verified",
//     "schema": "urn:chio:attest:tool-call/v1",
//     "tool": "<tool name>",
//     "verifier": "chio-attest-verify"
//   }
//
// The `verifier` slot points at the `chio-attest-verify` crate that
// owns the verifier surface; consumers MUST re-run the verifier against
// the receipt before treating the header as authority.

const ATTESTATION_HEADER: &str = "Chio-verified";
pub(crate) const ATTESTATION_SCHEMA: &str = "urn:chio:attest:tool-call/v1";

/// Build the "Chio-verified" attestation header that gets stitched into
/// the `_meta.chio_verified` block of a wrapped `tools/call` response.
pub(crate) fn build_chio_verified_header(tool_name: &str) -> serde_json::Value {
    serde_json::json!({
        "header": ATTESTATION_HEADER,
        "schema": ATTESTATION_SCHEMA,
        "tool": tool_name,
        "verifier": "chio-attest-verify",
    })
}

/// Mutate `payload` in place so the wrapped tool response carries the
/// "Chio-verified" attestation header inside the `_meta` slot. The
/// pre-existing `_meta` value (if any) is preserved.
pub(crate) fn attach_chio_verified_header(payload: &mut serde_json::Value, tool_name: &str) {
    if !payload.is_object() {
        return;
    }

    let header = build_chio_verified_header(tool_name);
    if let Some(map) = payload.as_object_mut() {
        let meta_slot = map
            .entry("_meta".to_string())
            .or_insert(serde_json::Value::Object(serde_json::Map::new()));
        if let Some(meta_map) = meta_slot.as_object_mut() {
            meta_map.insert("chio_verified".to_string(), header);
        } else {
            *meta_slot = serde_json::json!({
                "chio_verified": build_chio_verified_header(tool_name),
            });
        }
    }
}
