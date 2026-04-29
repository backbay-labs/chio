//! C ABI for deterministic Chio SDK invariant helpers.
//!
//! The ABI intentionally stays narrow: UTF-8 strings and byte buffers in,
//! UTF-8 buffers out, explicit Rust-side deallocation, and no async/session
//! state crossing the boundary.

use std::ffi::CStr;
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use chio_binding_helpers::{Error, ErrorCode};

pub const CHIO_FFI_ABI_VERSION: u32 = 1;
pub const CHIO_FFI_NO_MAX_DELEGATION_DEPTH: u32 = u32::MAX;

pub const CHIO_FFI_STATUS_OK: i32 = 0;
pub const CHIO_FFI_STATUS_ERROR: i32 = 1;
pub const CHIO_FFI_STATUS_PANIC: i32 = 2;
pub const CHIO_FFI_STATUS_NULL_ARGUMENT: i32 = 3;

pub const CHIO_FFI_ERROR_NONE: i32 = 0;
pub const CHIO_FFI_ERROR_INVALID_PUBLIC_KEY: i32 = 1;
pub const CHIO_FFI_ERROR_INVALID_HEX: i32 = 2;
pub const CHIO_FFI_ERROR_INVALID_SIGNATURE: i32 = 3;
pub const CHIO_FFI_ERROR_JSON: i32 = 4;
pub const CHIO_FFI_ERROR_CANONICAL_JSON: i32 = 5;
pub const CHIO_FFI_ERROR_CAPABILITY_EXPIRED: i32 = 6;
pub const CHIO_FFI_ERROR_CAPABILITY_NOT_YET_VALID: i32 = 7;
pub const CHIO_FFI_ERROR_CAPABILITY_REVOKED: i32 = 8;
pub const CHIO_FFI_ERROR_DELEGATION_CHAIN_BROKEN: i32 = 9;
pub const CHIO_FFI_ERROR_ATTENUATION_VIOLATION: i32 = 10;
pub const CHIO_FFI_ERROR_SCOPE_MISMATCH: i32 = 11;
pub const CHIO_FFI_ERROR_SIGNATURE_VERIFICATION_FAILED: i32 = 12;
pub const CHIO_FFI_ERROR_DELEGATION_DEPTH_EXCEEDED: i32 = 13;
pub const CHIO_FFI_ERROR_INVALID_HASH_LENGTH: i32 = 14;
pub const CHIO_FFI_ERROR_MERKLE_PROOF_FAILED: i32 = 15;
pub const CHIO_FFI_ERROR_EMPTY_TREE: i32 = 16;
pub const CHIO_FFI_ERROR_INVALID_PROOF_INDEX: i32 = 17;
pub const CHIO_FFI_ERROR_EMPTY_MANIFEST: i32 = 18;
pub const CHIO_FFI_ERROR_DUPLICATE_TOOL_NAME: i32 = 19;
pub const CHIO_FFI_ERROR_UNSUPPORTED_SCHEMA: i32 = 20;
pub const CHIO_FFI_ERROR_MANIFEST_VERIFICATION_FAILED: i32 = 21;
pub const CHIO_FFI_ERROR_DUPLICATE_SERVER_TOOL: i32 = 22;
pub const CHIO_FFI_ERROR_INTERNAL: i32 = 255;

#[repr(C)]
pub struct ChioFfiBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

#[repr(C)]
pub struct ChioFfiResult {
    pub status: i32,
    pub error_code: i32,
    pub data: ChioFfiBuffer,
}

impl ChioFfiBuffer {
    fn empty() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
        }
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        if bytes.is_empty() {
            return Self::empty();
        }
        let mut boxed = bytes.into_boxed_slice();
        let ptr = boxed.as_mut_ptr();
        let len = boxed.len();
        std::mem::forget(boxed);
        Self { ptr, len }
    }

    fn from_string(value: String) -> Self {
        Self::from_bytes(value.into_bytes())
    }
}

#[no_mangle]
pub extern "C" fn chio_buffer_free(buffer: ChioFfiBuffer) {
    if buffer.ptr.is_null() || buffer.len == 0 {
        return;
    }
    // SAFETY: all non-empty buffers returned by this crate come from
    // `Vec::into_boxed_slice` with exactly this pointer and length.
    unsafe {
        drop(Vec::from_raw_parts(buffer.ptr, buffer.len, buffer.len));
    }
}

fn ok_string(value: String) -> ChioFfiResult {
    ChioFfiResult {
        status: CHIO_FFI_STATUS_OK,
        error_code: CHIO_FFI_ERROR_NONE,
        data: ChioFfiBuffer::from_string(value),
    }
}

fn err_string(status: i32, error_code: i32, message: String) -> ChioFfiResult {
    ChioFfiResult {
        status,
        error_code,
        data: ChioFfiBuffer::from_string(message),
    }
}

fn helper_error_code(error: &Error) -> i32 {
    match error.code() {
        ErrorCode::InvalidPublicKey => CHIO_FFI_ERROR_INVALID_PUBLIC_KEY,
        ErrorCode::InvalidHex => CHIO_FFI_ERROR_INVALID_HEX,
        ErrorCode::InvalidSignature => CHIO_FFI_ERROR_INVALID_SIGNATURE,
        ErrorCode::Json => CHIO_FFI_ERROR_JSON,
        ErrorCode::CanonicalJson => CHIO_FFI_ERROR_CANONICAL_JSON,
        ErrorCode::CapabilityExpired => CHIO_FFI_ERROR_CAPABILITY_EXPIRED,
        ErrorCode::CapabilityNotYetValid => CHIO_FFI_ERROR_CAPABILITY_NOT_YET_VALID,
        ErrorCode::CapabilityRevoked => CHIO_FFI_ERROR_CAPABILITY_REVOKED,
        ErrorCode::DelegationChainBroken => CHIO_FFI_ERROR_DELEGATION_CHAIN_BROKEN,
        ErrorCode::AttenuationViolation => CHIO_FFI_ERROR_ATTENUATION_VIOLATION,
        ErrorCode::ScopeMismatch => CHIO_FFI_ERROR_SCOPE_MISMATCH,
        ErrorCode::SignatureVerificationFailed => CHIO_FFI_ERROR_SIGNATURE_VERIFICATION_FAILED,
        ErrorCode::DelegationDepthExceeded => CHIO_FFI_ERROR_DELEGATION_DEPTH_EXCEEDED,
        ErrorCode::InvalidHashLength => CHIO_FFI_ERROR_INVALID_HASH_LENGTH,
        ErrorCode::MerkleProofFailed => CHIO_FFI_ERROR_MERKLE_PROOF_FAILED,
        ErrorCode::EmptyTree => CHIO_FFI_ERROR_EMPTY_TREE,
        ErrorCode::InvalidProofIndex => CHIO_FFI_ERROR_INVALID_PROOF_INDEX,
        ErrorCode::EmptyManifest => CHIO_FFI_ERROR_EMPTY_MANIFEST,
        ErrorCode::DuplicateToolName => CHIO_FFI_ERROR_DUPLICATE_TOOL_NAME,
        ErrorCode::DuplicateServerTool => CHIO_FFI_ERROR_DUPLICATE_SERVER_TOOL,
        ErrorCode::UnsupportedSchema => CHIO_FFI_ERROR_UNSUPPORTED_SCHEMA,
        ErrorCode::ManifestVerificationFailed => CHIO_FFI_ERROR_MANIFEST_VERIFICATION_FAILED,
    }
}

fn run_ffi<F>(f: F) -> ChioFfiResult
where
    F: FnOnce() -> Result<String, Error>,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(value)) => ok_string(value),
        Ok(Err(error)) => err_string(
            CHIO_FFI_STATUS_ERROR,
            helper_error_code(&error),
            error.to_string(),
        ),
        Err(_) => err_string(
            CHIO_FFI_STATUS_PANIC,
            CHIO_FFI_ERROR_INTERNAL,
            "panic while executing Chio FFI helper".to_string(),
        ),
    }
}

fn read_c_str(ptr: *const c_char, name: &str) -> Result<&str, ChioFfiResult> {
    if ptr.is_null() {
        return Err(err_string(
            CHIO_FFI_STATUS_NULL_ARGUMENT,
            CHIO_FFI_ERROR_INTERNAL,
            format!("{name} must not be null"),
        ));
    }
    // SAFETY: caller promises a valid NUL-terminated C string.
    let raw = unsafe { CStr::from_ptr(ptr) };
    raw.to_str().map_err(|error| {
        err_string(
            CHIO_FFI_STATUS_ERROR,
            CHIO_FFI_ERROR_INTERNAL,
            format!("{name} must be valid UTF-8: {error}"),
        )
    })
}

fn read_bytes(ptr: *const u8, len: usize, name: &str) -> Result<Vec<u8>, ChioFfiResult> {
    if ptr.is_null() && len != 0 {
        return Err(err_string(
            CHIO_FFI_STATUS_NULL_ARGUMENT,
            CHIO_FFI_ERROR_INTERNAL,
            format!("{name} pointer must not be null when length is non-zero"),
        ));
    }
    if len == 0 {
        return Ok(Vec::new());
    }
    // SAFETY: caller promises `ptr` references `len` readable bytes.
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec())
}

fn json<T: serde::Serialize>(value: &T) -> Result<String, Error> {
    serde_json::to_string(value).map_err(Into::into)
}

#[no_mangle]
pub extern "C" fn chio_ffi_abi_version() -> u32 {
    CHIO_FFI_ABI_VERSION
}

#[no_mangle]
pub extern "C" fn chio_ffi_build_info() -> ChioFfiResult {
    #[derive(serde::Serialize)]
    struct BuildInfo<'a> {
        crate_name: &'a str,
        crate_version: &'a str,
        abi_version: u32,
        target: String,
        features: Vec<&'a str>,
    }

    let info = BuildInfo {
        crate_name: env!("CARGO_PKG_NAME"),
        crate_version: env!("CARGO_PKG_VERSION"),
        abi_version: CHIO_FFI_ABI_VERSION,
        target: format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
        features: Vec::new(),
    };
    run_ffi(|| json(&info))
}

#[no_mangle]
pub extern "C" fn chio_canonicalize_json(input_json: *const c_char) -> ChioFfiResult {
    let input = match read_c_str(input_json, "input_json") {
        Ok(value) => value,
        Err(result) => return result,
    };
    run_ffi(|| chio_binding_helpers::canonicalize_json_str(input))
}

#[no_mangle]
pub extern "C" fn chio_sha256_hex_utf8(input_utf8: *const c_char) -> ChioFfiResult {
    let input = match read_c_str(input_utf8, "input_utf8") {
        Ok(value) => value,
        Err(result) => return result,
    };
    ok_string(chio_binding_helpers::sha256_hex_utf8(input))
}

#[no_mangle]
pub extern "C" fn chio_sha256_hex_bytes(input: *const u8, input_len: usize) -> ChioFfiResult {
    let bytes = match read_bytes(input, input_len, "input") {
        Ok(value) => value,
        Err(result) => return result,
    };
    ok_string(chio_binding_helpers::sha256_hex_bytes(&bytes))
}

#[no_mangle]
pub extern "C" fn chio_sign_utf8_message_ed25519(
    input_utf8: *const c_char,
    seed_hex: *const c_char,
) -> ChioFfiResult {
    let input = match read_c_str(input_utf8, "input_utf8") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let seed = match read_c_str(seed_hex, "seed_hex") {
        Ok(value) => value,
        Err(result) => return result,
    };
    run_ffi(|| {
        json(&chio_binding_helpers::sign_utf8_message_ed25519(
            input, seed,
        )?)
    })
}

#[no_mangle]
pub extern "C" fn chio_verify_utf8_message_ed25519(
    input_utf8: *const c_char,
    public_key_hex: *const c_char,
    signature_hex: *const c_char,
) -> ChioFfiResult {
    let input = match read_c_str(input_utf8, "input_utf8") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let public_key = match read_c_str(public_key_hex, "public_key_hex") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let signature = match read_c_str(signature_hex, "signature_hex") {
        Ok(value) => value,
        Err(result) => return result,
    };
    run_ffi(|| {
        Ok(
            chio_binding_helpers::verify_utf8_message_ed25519(input, public_key, signature)?
                .to_string(),
        )
    })
}

#[no_mangle]
pub extern "C" fn chio_sign_json_ed25519(
    input_json: *const c_char,
    seed_hex: *const c_char,
) -> ChioFfiResult {
    let input = match read_c_str(input_json, "input_json") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let seed = match read_c_str(seed_hex, "seed_hex") {
        Ok(value) => value,
        Err(result) => return result,
    };
    run_ffi(|| json(&chio_binding_helpers::sign_json_str_ed25519(input, seed)?))
}

#[no_mangle]
pub extern "C" fn chio_verify_json_signature_ed25519(
    input_json: *const c_char,
    public_key_hex: *const c_char,
    signature_hex: *const c_char,
) -> ChioFfiResult {
    let input = match read_c_str(input_json, "input_json") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let public_key = match read_c_str(public_key_hex, "public_key_hex") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let signature = match read_c_str(signature_hex, "signature_hex") {
        Ok(value) => value,
        Err(result) => return result,
    };
    run_ffi(|| {
        Ok(
            chio_binding_helpers::verify_json_str_signature_ed25519(input, public_key, signature)?
                .to_string(),
        )
    })
}

#[no_mangle]
pub extern "C" fn chio_verify_capability_json(
    input_json: *const c_char,
    now_secs: u64,
    max_delegation_depth: u32,
) -> ChioFfiResult {
    let input = match read_c_str(input_json, "input_json") {
        Ok(value) => value,
        Err(result) => return result,
    };
    let max_depth = if max_delegation_depth == CHIO_FFI_NO_MAX_DELEGATION_DEPTH {
        None
    } else {
        Some(max_delegation_depth)
    };
    run_ffi(|| {
        json(&chio_binding_helpers::verify_capability_json(
            input, now_secs, max_depth,
        )?)
    })
}

#[no_mangle]
pub extern "C" fn chio_verify_receipt_json(input_json: *const c_char) -> ChioFfiResult {
    let input = match read_c_str(input_json, "input_json") {
        Ok(value) => value,
        Err(result) => return result,
    };
    run_ffi(|| json(&chio_binding_helpers::verify_receipt_json(input)?))
}

#[no_mangle]
pub extern "C" fn chio_verify_manifest_json(input_json: *const c_char) -> ChioFfiResult {
    let input = match read_c_str(input_json, "input_json") {
        Ok(value) => value,
        Err(result) => return result,
    };
    run_ffi(|| json(&chio_binding_helpers::verify_signed_manifest_json(input)?))
}

#[cfg(test)]
mod tests {
    use super::{
        chio_buffer_free, chio_canonicalize_json, chio_ffi_abi_version, chio_ffi_build_info,
        chio_sha256_hex_bytes, chio_sha256_hex_utf8, chio_sign_utf8_message_ed25519,
        chio_verify_utf8_message_ed25519, ChioFfiBuffer, CHIO_FFI_STATUS_ERROR,
        CHIO_FFI_STATUS_NULL_ARGUMENT, CHIO_FFI_STATUS_OK,
    };
    use std::ffi::CString;
    use std::os::raw::c_char;

    fn result_to_string(buffer: ChioFfiBuffer) -> String {
        let bytes = if buffer.len == 0 {
            Vec::new()
        } else {
            // SAFETY: test consumes a buffer returned by this crate exactly once.
            unsafe { std::slice::from_raw_parts(buffer.ptr, buffer.len).to_vec() }
        };
        chio_buffer_free(buffer);
        match String::from_utf8(bytes) {
            Ok(value) => value,
            Err(error) => panic!("ffi output must be utf8: {error}"),
        }
    }

    fn c_string(value: &str) -> CString {
        match CString::new(value) {
            Ok(value) => value,
            Err(error) => panic!("test input contained interior nul: {error}"),
        }
    }

    #[test]
    fn canonicalize_roundtrips_over_c_abi() {
        let input = c_string(r#"{"z":1,"a":2}"#);
        let result = chio_canonicalize_json(input.as_ptr());
        assert_eq!(result.status, CHIO_FFI_STATUS_OK);
        assert_eq!(result_to_string(result.data), r#"{"a":2,"z":1}"#);
    }

    #[test]
    fn hashing_roundtrips_over_c_abi() {
        let input = c_string("hello");
        let result = chio_sha256_hex_utf8(input.as_ptr());
        assert_eq!(result.status, CHIO_FFI_STATUS_OK);
        assert_eq!(
            result_to_string(result.data),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn signing_roundtrips_over_c_abi() {
        let input = c_string("hello chio");
        let seed = c_string(&"09".repeat(32));
        let result = chio_sign_utf8_message_ed25519(input.as_ptr(), seed.as_ptr());
        assert_eq!(result.status, CHIO_FFI_STATUS_OK);
        let output = result_to_string(result.data);
        assert!(output.contains("public_key_hex"));
        assert!(output.contains("signature_hex"));
    }

    #[test]
    fn abi_version_is_stable_one() {
        assert_eq!(chio_ffi_abi_version(), 1);
    }

    #[test]
    fn build_info_reports_version_target_and_features() {
        let result = chio_ffi_build_info();
        assert_eq!(result.status, CHIO_FFI_STATUS_OK);
        let output = result_to_string(result.data);
        let parsed: serde_json::Value = match serde_json::from_str(&output) {
            Ok(value) => value,
            Err(error) => panic!("build info must be valid json: {error}; output={output}"),
        };

        assert_eq!(parsed["crate_name"], "chio-bindings-ffi");
        assert_eq!(parsed["crate_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(parsed["abi_version"], 1);
        assert!(parsed["target"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
        assert!(parsed["features"].as_array().is_some());
    }

    #[test]
    fn null_string_argument_returns_null_argument_status() {
        let result = chio_canonicalize_json(std::ptr::null());
        assert_eq!(result.status, CHIO_FFI_STATUS_NULL_ARGUMENT);
        assert!(result_to_string(result.data).contains("input_json must not be null"));
    }

    #[test]
    fn null_bytes_with_nonzero_len_returns_null_argument_status() {
        let result = chio_sha256_hex_bytes(std::ptr::null(), 1);
        assert_eq!(result.status, CHIO_FFI_STATUS_NULL_ARGUMENT);
        assert!(result_to_string(result.data).contains("input pointer must not be null"));
    }

    #[test]
    fn null_bytes_with_zero_len_hashes_empty_buffer() {
        let result = chio_sha256_hex_bytes(std::ptr::null(), 0);
        assert_eq!(result.status, CHIO_FFI_STATUS_OK);
        assert_eq!(
            result_to_string(result.data),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn invalid_utf8_argument_returns_error_status() {
        let input = [0xff_u8, 0x00_u8];
        let result = chio_sha256_hex_utf8(input.as_ptr().cast::<c_char>());
        assert_eq!(result.status, CHIO_FFI_STATUS_ERROR);
        assert!(result_to_string(result.data).contains("input_utf8 must be valid UTF-8"));
    }

    #[test]
    fn malformed_json_returns_error_status() {
        let input = c_string(r#"{"unterminated": true"#);
        let result = chio_canonicalize_json(input.as_ptr());
        assert_eq!(result.status, CHIO_FFI_STATUS_ERROR);
        assert_ne!(result.error_code, 0);
        assert!(!result_to_string(result.data).is_empty());
    }

    #[test]
    fn malformed_hex_returns_error_status() {
        let input = c_string("hello");
        let public_key = c_string("not-hex");
        let signature = c_string("also-not-hex");
        let result = chio_verify_utf8_message_ed25519(
            input.as_ptr(),
            public_key.as_ptr(),
            signature.as_ptr(),
        );
        assert_eq!(result.status, CHIO_FFI_STATUS_ERROR);
        assert_ne!(result.error_code, 0);
        assert!(!result_to_string(result.data).is_empty());
    }

    #[test]
    fn freeing_empty_and_null_buffers_is_noop() {
        chio_buffer_free(ChioFfiBuffer {
            ptr: std::ptr::null_mut(),
            len: 0,
        });
        chio_buffer_free(ChioFfiBuffer {
            ptr: std::ptr::null_mut(),
            len: 16,
        });
    }

    #[test]
    fn abi_symbol_snapshot_lists_exported_functions() {
        let snapshot = include_str!("../../../tests/abi/chio-bindings-ffi.symbols");
        let expected = [
            "chio_buffer_free",
            "chio_canonicalize_json",
            "chio_ffi_abi_version",
            "chio_ffi_build_info",
            "chio_sha256_hex_bytes",
            "chio_sha256_hex_utf8",
            "chio_sign_json_ed25519",
            "chio_sign_utf8_message_ed25519",
            "chio_verify_capability_json",
            "chio_verify_json_signature_ed25519",
            "chio_verify_manifest_json",
            "chio_verify_receipt_json",
            "chio_verify_utf8_message_ed25519",
        ];

        let actual: Vec<&str> = snapshot
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
            .collect();
        assert_eq!(actual, expected);
    }
}
