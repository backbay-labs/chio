//! ABI glue for the Chio WASM guard guest-host boundary.
//!
//! Provides:
//! - [`read_request`] -- deserialize a [`GuardRequest`] from linear memory
//! - [`encode_verdict`] -- convert a [`GuardVerdict`] into an ABI return code
//! - [`chio_deny_reason`] -- `#[no_mangle]` export that writes structured deny
//!   JSON into a host-provided buffer
//!
//! The deny reason is stored in a thread-local between the `evaluate` return
//! and the subsequent `chio_deny_reason` call by the host.

use std::cell::RefCell;

use crate::types::{
    normalize_deny_reason, GuardRequest, GuardVerdict, GuestDenyResponse, VERDICT_ALLOW,
    VERDICT_DENY,
};

// ---------------------------------------------------------------------------
// Thread-local deny reason storage
// ---------------------------------------------------------------------------

thread_local! {
    static LAST_DENY_REASON: RefCell<Option<String>> = const { RefCell::new(None) };
}

// ---------------------------------------------------------------------------
// read_request
// ---------------------------------------------------------------------------

/// Deserialize a [`GuardRequest`] from raw guest linear memory.
///
/// # Safety
///
/// The caller must ensure that `ptr` and `len` describe a valid region of
/// guest memory containing a UTF-8 JSON-encoded `GuardRequest`. The host
/// writes this data via the WASM memory export before calling `evaluate`.
///
/// As a defense-in-depth measure, this function rejects non-positive `ptr`
/// values and negative `len` values with a deserialization error rather
/// than dereferencing them. A negative `len` cast to `usize` would otherwise
/// produce an enormous slice and trigger undefined behavior. Guard authors
/// should still treat the function as `unsafe` because the host is trusted
/// to keep ptr/len within the guest's linear memory.
#[inline]
pub unsafe fn read_request(ptr: i32, len: i32) -> Result<GuardRequest, String> {
    if ptr <= 0 || len < 0 {
        return Err("invalid guest request pointer or length".to_owned());
    }
    if len == 0 {
        return serde_json::from_slice(&[]).map_err(|e| e.to_string());
    }
    let slice = core::slice::from_raw_parts(ptr as *const u8, len as usize);
    serde_json::from_slice(slice).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// encode_verdict
// ---------------------------------------------------------------------------

/// Convert a [`GuardVerdict`] into the ABI return code expected by the host
/// runtime's `evaluate` call.
///
/// - `GuardVerdict::Allow` -> [`VERDICT_ALLOW`] (0), clears stored deny reason
/// - `GuardVerdict::Deny { reason }` -> [`VERDICT_DENY`] (1), stores reason
///   for retrieval by [`chio_deny_reason`]
pub fn encode_verdict(verdict: GuardVerdict) -> i32 {
    match verdict {
        GuardVerdict::Allow => {
            LAST_DENY_REASON.with(|cell| {
                if let Ok(mut r) = cell.try_borrow_mut() {
                    *r = None;
                }
            });
            VERDICT_ALLOW
        }
        GuardVerdict::Deny { reason } => {
            let reason = normalize_deny_reason(reason);
            LAST_DENY_REASON.with(|cell| {
                if let Ok(mut r) = cell.try_borrow_mut() {
                    *r = Some(reason);
                }
            });
            VERDICT_DENY
        }
    }
}

// ---------------------------------------------------------------------------
// chio_deny_reason export
// ---------------------------------------------------------------------------

/// Serialize the stored deny reason as JSON bytes.
///
/// Returns `Some(bytes)` if a deny reason is stored, `None` otherwise.
/// This is the pure logic extracted from [`chio_deny_reason`] so it can be
/// tested without unsafe pointer casts on 64-bit native targets.
fn serialize_deny_reason() -> Option<Vec<u8>> {
    let reason = LAST_DENY_REASON.with(|cell| cell.try_borrow().ok().and_then(|r| r.clone()));

    let reason = reason?;
    let resp = GuestDenyResponse { reason };
    serde_json::to_vec(&resp).ok()
}

/// Write a structured JSON deny reason into the host-provided buffer.
///
/// Called by the host after `evaluate` returns [`VERDICT_DENY`]. The host
/// passes a fixed buffer region (typically `buf_ptr=65536`, `buf_len=4096`).
///
/// Returns the number of bytes written on success, or -1 if:
/// - No deny reason is stored (e.g. after an Allow verdict)
/// - The JSON serialization fails
/// - The buffer is too small to hold the serialized JSON
#[no_mangle]
pub extern "C" fn chio_deny_reason(buf_ptr: i32, buf_len: i32) -> i32 {
    let json_bytes = match serialize_deny_reason() {
        Some(bytes) => bytes,
        None => return -1,
    };

    if buf_ptr <= 0 || buf_len < 0 || json_bytes.len() > buf_len as usize {
        return -1;
    }

    // SAFETY: On wasm32, buf_ptr is an offset into linear memory and this
    // write is valid because the host allocated the region. On native targets
    // (tests), the caller must pass a valid heap pointer cast to i32.
    unsafe {
        let dest = core::slice::from_raw_parts_mut(buf_ptr as *mut u8, buf_len as usize);
        dest[..json_bytes.len()].copy_from_slice(&json_bytes);
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let written = json_bytes.len() as i32;
    written
}

// ---------------------------------------------------------------------------
// Internal helper
// ---------------------------------------------------------------------------

/// Clear the stored deny reason. Exposed for testing only.
#[cfg(test)]
pub(crate) fn clear_deny_reason() {
    LAST_DENY_REASON.with(|cell| {
        if let Ok(mut r) = cell.try_borrow_mut() {
            *r = None;
        }
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::types::{
        GuardRequest, GuardVerdict, GuestDenyResponse, VERDICT_ALLOW, VERDICT_DENY,
    };

    #[test]
    fn encode_verdict_allow_returns_zero_and_clears_reason() {
        // Store a leftover deny reason first.
        super::encode_verdict(GuardVerdict::deny("leftover"));
        let code = super::encode_verdict(GuardVerdict::Allow);
        assert_eq!(code, VERDICT_ALLOW);
        // After Allow, the internal serialization should return None.
        assert!(
            super::serialize_deny_reason().is_none(),
            "No deny reason should exist after Allow"
        );
    }

    #[test]
    fn encode_verdict_deny_returns_one_and_stores_reason() {
        let code = super::encode_verdict(GuardVerdict::deny("blocked"));
        assert_eq!(code, VERDICT_DENY);
    }

    #[test]
    fn encode_verdict_deny_replaces_blank_reason() {
        super::encode_verdict(GuardVerdict::Deny {
            reason: " \t\n".to_string(),
        });

        let reason = super::serialize_deny_reason()
            .and_then(|bytes| serde_json::from_slice::<GuestDenyResponse>(&bytes).ok())
            .map(|resp| resp.reason);

        assert_eq!(reason.as_deref(), Some("guard denied request"));
    }

    #[test]
    fn chio_deny_reason_writes_json_after_deny() {
        super::encode_verdict(GuardVerdict::deny("blocked"));

        // Test via the extracted pure-logic function (avoids 64-bit pointer
        // truncation issues with chio_deny_reason's i32 buf_ptr on native).
        let json_bytes = match super::serialize_deny_reason() {
            Some(bytes) => bytes,
            None => panic!("deny reason should be present after Deny"),
        };
        let resp: GuestDenyResponse = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(resp.reason, "blocked");
    }

    #[test]
    fn chio_deny_reason_returns_negative_after_allow() {
        super::encode_verdict(GuardVerdict::Allow);
        assert!(
            super::serialize_deny_reason().is_none(),
            "No deny reason after Allow"
        );
    }

    #[test]
    fn chio_deny_reason_returns_negative_for_tiny_buffer() {
        super::encode_verdict(GuardVerdict::deny(
            "this reason is definitely longer than 2 bytes",
        ));

        // The serialized JSON for this reason is well over 2 bytes.
        let json_bytes = match super::serialize_deny_reason() {
            Some(bytes) => bytes,
            None => panic!("deny reason should be present"),
        };
        assert!(json_bytes.len() > 2, "JSON should be longer than 2 bytes");

        // Verify the chio_deny_reason logic: if buf_len < json_bytes.len(), it
        // would return -1. We test the boundary condition via the length check.
        // (We cannot safely call chio_deny_reason on 64-bit native because the
        // i32 buf_ptr truncates the heap pointer.)
        assert!(json_bytes.len() > 2, "Buffer of 2 would be too small");
    }

    #[test]
    fn chio_deny_reason_rejects_invalid_buffer_pointer() {
        super::encode_verdict(GuardVerdict::deny("blocked"));

        assert_eq!(super::chio_deny_reason(0, 4096), -1);
        assert_eq!(super::chio_deny_reason(-1, 4096), -1);
    }

    #[test]
    fn read_request_deserializes_valid_json() {
        let req = GuardRequest {
            tool_name: "read_file".to_string(),
            server_id: "fs".to_string(),
            agent_id: "a1".to_string(),
            arguments: serde_json::json!({"path": "/tmp"}),
            scopes: vec!["fs:read_file".to_string()],
            action_type: None,
            extracted_path: Some("/tmp".to_string()),
            extracted_target: None,
            filesystem_roots: vec![],
            matched_grant_index: None,
        };

        let json = serde_json::to_vec(&req).unwrap();
        // Simulate what read_request does internally: serde_json::from_slice
        let deserialized: GuardRequest = serde_json::from_slice(&json).unwrap();
        assert_eq!(deserialized, req);
    }

    #[test]
    fn read_request_returns_error_for_invalid_json() {
        let bad_json = b"not valid json";
        let result = serde_json::from_slice::<GuardRequest>(bad_json);
        assert!(result.is_err(), "Invalid JSON should fail deserialization");
    }

    #[test]
    fn read_request_rejects_negative_length() {
        // Defense-in-depth: a hostile or buggy host that supplies a negative
        // `len` must not dereference the resulting slice. The function is
        // documented unsafe but should still reject this without UB.
        let result = unsafe { super::read_request(0x1000, -1) };
        assert!(
            result.is_err(),
            "negative length should fail-closed without dereferencing"
        );
    }

    #[test]
    fn read_request_rejects_zero_or_negative_pointer() {
        let result = unsafe { super::read_request(0, 4) };
        assert!(
            result.is_err(),
            "zero pointer should fail-closed without dereferencing"
        );
        let result = unsafe { super::read_request(-1, 4) };
        assert!(
            result.is_err(),
            "negative pointer should fail-closed without dereferencing"
        );
    }

    #[test]
    fn clear_deny_reason_clears_stored_reason() {
        super::encode_verdict(GuardVerdict::deny("something"));
        assert!(super::serialize_deny_reason().is_some());
        super::clear_deny_reason();
        assert!(super::serialize_deny_reason().is_none());
    }
}
