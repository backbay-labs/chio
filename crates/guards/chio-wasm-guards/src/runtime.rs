//! WASM guard runtime and kernel integration.
//!
//! This module exposes focused runtime children for loaded module state,
//! guard evaluation, backend collection, and the Wasmtime backend.

pub mod backend;
pub(crate) mod evidence;
pub mod guard;
#[cfg(any(test, feature = "test-support"))]
pub mod mock_backend;
pub mod module;
#[cfg(feature = "wasmtime-runtime")]
pub mod wasmtime_backend;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::backend::WasmGuardRuntime;
    use super::guard::WasmGuard;
    use super::mock_backend::MockWasmBackend;
    use crate::abi::{GuardRequest, GuardVerdict, WasmGuardAbi};
    use crate::epoch::EpochId;
    use crate::error::WasmGuardError;
    use chio_core::capability::scope::ChioScope;
    use chio_kernel::{Guard, GuardContext, ToolCallRequest, Verdict};

    fn make_test_capability() -> chio_core::capability::token::CapabilityToken {
        let keypair = chio_core::crypto::Keypair::generate();
        chio_core::capability::token::CapabilityToken::sign(
            chio_core::capability::token::CapabilityTokenBody {
                id: "cap-1".to_string(),
                issuer: keypair.public_key(),
                subject: keypair.public_key(),
                scope: ChioScope::default(),
                issued_at: 0,
                expires_at: u64::MAX,
                delegation_chain: vec![],
                aggregate_invocation_budget: None,
            },
            &keypair,
        )
        .unwrap()
    }

    fn make_test_request() -> ToolCallRequest {
        ToolCallRequest {
            request_id: "req-1".to_string(),
            capability: make_test_capability(),
            tool_name: "test_tool".to_string(),
            server_id: "test_server".to_string(),
            agent_id: "agent-1".to_string(),
            arguments: serde_json::json!({"key": "value"}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        }
    }

    #[test]
    fn mock_allow_backend() {
        let mut backend = MockWasmBackend::allowing();
        backend.load_module(b"fake", 1000).unwrap();

        let guard = WasmGuard::new("test-allow".to_string(), Box::new(backend), false, None);

        let request = make_test_request();
        let scope = ChioScope::default();
        let agent_id = "agent-1".to_string();
        let server_id = "test_server".to_string();

        let ctx = GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let result = guard.evaluate(&ctx);
        assert!(matches!(
            result,
            Ok(decision) if decision.verdict == Verdict::Allow
        ));
    }

    #[test]
    fn mock_deny_backend() {
        let mut backend = MockWasmBackend::denying("blocked by test");
        backend.load_module(b"fake", 1000).unwrap();

        let guard = WasmGuard::new("test-deny".to_string(), Box::new(backend), false, None);

        let request = make_test_request();
        let scope = ChioScope::default();
        let agent_id = "agent-1".to_string();
        let server_id = "test_server".to_string();

        let ctx = GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let result = guard.evaluate(&ctx);
        assert!(matches!(
            result,
            Ok(decision) if decision.verdict == Verdict::Deny
        ));
    }

    #[test]
    fn advisory_guard_allows_on_deny() {
        let mut backend = MockWasmBackend::denying("advisory denial");
        backend.load_module(b"fake", 1000).unwrap();

        let guard = WasmGuard::new("test-advisory".to_string(), Box::new(backend), true, None);
        assert!(guard.is_advisory());

        let request = make_test_request();
        let scope = ChioScope::default();
        let agent_id = "agent-1".to_string();
        let server_id = "test_server".to_string();

        let ctx = GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        // Advisory guards should allow even when the backend denies
        let result = guard.evaluate(&ctx);
        assert!(matches!(
            result,
            Ok(decision) if decision.verdict == Verdict::Allow
        ));
    }

    #[test]
    fn malformed_action_denies_before_backend_even_for_advisory_guard() {
        let mut backend = MockWasmBackend::allowing();
        backend.load_module(b"fake", 1000).unwrap();

        let guard = WasmGuard::new("test-malformed".to_string(), Box::new(backend), true, None);

        let request = make_test_request_with(
            "filesystem",
            serde_json::json!({
                "path": ["/etc/shadow"],
                "file": "/home/user/project/src/main.rs"
            }),
        );
        let scope = ChioScope::default();
        let agent_id = "agent-1".to_string();
        let server_id = "test_server".to_string();

        let ctx = GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let result = guard.evaluate(&ctx);
        assert!(matches!(
            result,
            Ok(decision) if decision.verdict == Verdict::Deny
        ));
    }

    #[test]
    fn runtime_manages_multiple_guards() {
        let mut runtime = WasmGuardRuntime::new();
        assert_eq!(runtime.guard_count(), 0);

        let mut b1 = MockWasmBackend::allowing();
        b1.load_module(b"fake", 1000).unwrap();
        runtime.add_guard(WasmGuard::new("g1".to_string(), Box::new(b1), false, None));

        let mut b2 = MockWasmBackend::denying("no");
        b2.load_module(b"fake", 1000).unwrap();
        runtime.add_guard(WasmGuard::new("g2".to_string(), Box::new(b2), false, None));

        assert_eq!(runtime.guard_count(), 2);

        let boxed = runtime.into_guards();
        assert_eq!(boxed.len(), 2);
    }

    #[test]
    fn guard_request_serialization() {
        let req = GuardRequest {
            tool_name: "read_file".to_string(),
            server_id: "fs-server".to_string(),
            agent_id: "agent-42".to_string(),
            arguments: serde_json::json!({"path": "/etc/passwd"}),
            scopes: vec!["fs-server:read_file".to_string()],
            action_type: None,
            extracted_path: None,
            extracted_target: None,
            filesystem_roots: Vec::new(),
            matched_grant_index: None,
        };

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: GuardRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.tool_name, "read_file");
        assert_eq!(deserialized.scopes.len(), 1);
    }

    #[test]
    fn guard_verdict_helpers() {
        let allow = GuardVerdict::Allow;
        assert!(allow.is_allow());
        assert!(!allow.is_deny());

        let deny = GuardVerdict::Deny {
            reason: Some("bad".to_string()),
        };
        assert!(!deny.is_allow());
        assert!(deny.is_deny());
    }

    #[test]
    fn unloaded_mock_fails() {
        let mut backend = MockWasmBackend::allowing();
        // Do NOT call load_module
        let req = GuardRequest {
            tool_name: "t".to_string(),
            server_id: "s".to_string(),
            agent_id: "a".to_string(),
            arguments: serde_json::Value::Null,
            scopes: vec![],
            action_type: None,
            extracted_path: None,
            extracted_target: None,
            filesystem_roots: Vec::new(),
            matched_grant_index: None,
        };
        let result = backend.evaluate(&req);
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------
    // build_request enrichment tests
    // -------------------------------------------------------------------

    fn make_test_request_with(tool_name: &str, arguments: serde_json::Value) -> ToolCallRequest {
        ToolCallRequest {
            request_id: "req-1".to_string(),
            capability: make_test_capability(),
            tool_name: tool_name.to_string(),
            server_id: "test_server".to_string(),
            agent_id: "agent-1".to_string(),
            arguments,
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        }
    }

    #[test]
    fn build_request_action_type_file_access() {
        let request =
            make_test_request_with("read_file", serde_json::json!({"path": "/etc/passwd"}));
        let scope = ChioScope::default();
        let agent_id = "agent-1".to_string();
        let server_id = "test_server".to_string();

        let ctx = GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let req = WasmGuard::build_request(&ctx);
        assert_eq!(req.action_type.as_deref(), Some("file_access"));
    }

    #[test]
    fn build_request_extracted_path_for_file_access() {
        let request =
            make_test_request_with("read_file", serde_json::json!({"path": "/etc/passwd"}));
        let scope = ChioScope::default();
        let agent_id = "agent-1".to_string();
        let server_id = "test_server".to_string();

        let ctx = GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let req = WasmGuard::build_request(&ctx);
        assert_eq!(req.extracted_path.as_deref(), Some("/etc/passwd"));
    }

    #[test]
    fn build_request_action_type_network_egress() {
        let request = make_test_request_with(
            "fetch",
            serde_json::json!({"url": "https://example.com/api"}),
        );
        let scope = ChioScope::default();
        let agent_id = "agent-1".to_string();
        let server_id = "test_server".to_string();

        let ctx = GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let req = WasmGuard::build_request(&ctx);
        assert_eq!(req.action_type.as_deref(), Some("network_egress"));
        assert_eq!(req.extracted_target.as_deref(), Some("example.com"));
        assert!(
            req.extracted_path.is_none(),
            "network_egress should not set extracted_path"
        );
    }

    #[test]
    fn build_request_action_type_malformed_arguments() {
        let request = make_test_request_with(
            "filesystem",
            serde_json::json!({
                "path": ["/etc/shadow"],
                "file": "/home/user/project/src/main.rs"
            }),
        );
        let scope = ChioScope::default();
        let agent_id = "agent-1".to_string();
        let server_id = "test_server".to_string();

        let ctx = GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let req = WasmGuard::build_request(&ctx);
        assert_eq!(req.action_type.as_deref(), Some("malformed_arguments"));
        assert_eq!(req.extracted_target.as_deref(), Some("path"));
        assert!(req.extracted_path.is_none());
    }

    #[test]
    fn build_request_filesystem_roots_from_context() {
        let request = make_test_request_with(
            "read_file",
            serde_json::json!({"path": "/home/user/file.txt"}),
        );
        let scope = ChioScope::default();
        let agent_id = "agent-1".to_string();
        let server_id = "test_server".to_string();
        let roots = vec!["/home".to_string(), "/tmp".to_string()];

        let ctx = GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: Some(&roots),
            matched_grant_index: None,
        };

        let req = WasmGuard::build_request(&ctx);
        assert_eq!(
            req.filesystem_roots,
            vec!["/home".to_string(), "/tmp".to_string()]
        );
    }

    #[test]
    fn build_request_matched_grant_index_from_context() {
        let request =
            make_test_request_with("read_file", serde_json::json!({"path": "/etc/passwd"}));
        let scope = ChioScope::default();
        let agent_id = "agent-1".to_string();
        let server_id = "test_server".to_string();

        let ctx = GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: Some(3),
        };

        let req = WasmGuard::build_request(&ctx);
        assert_eq!(req.matched_grant_index, Some(3));
    }

    #[test]
    fn build_request_action_type_unknown_for_unrecognized_tool() {
        let request = make_test_request_with("test_tool", serde_json::json!({"key": "value"}));
        let scope = ChioScope::default();
        let agent_id = "agent-1".to_string();
        let server_id = "test_server".to_string();

        let ctx = GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let req = WasmGuard::build_request(&ctx);
        // "test_tool" is not a recognized filesystem/network/shell tool,
        // so extract_action returns McpTool (fallback) which we map to "mcp_tool"
        assert_eq!(req.action_type.as_deref(), Some("mcp_tool"));
    }

    // -------------------------------------------------------------------
    // Receipt metadata tests (manifest_sha256, fuel_consumed, evidence)
    // -------------------------------------------------------------------

    #[test]
    fn wasm_guard_stores_manifest_sha256() {
        let mut backend = MockWasmBackend::allowing();
        backend.load_module(b"fake", 1000).unwrap();

        let guard = WasmGuard::new(
            "test-hash".to_string(),
            Box::new(backend),
            false,
            Some("abcdef0123456789".to_string()),
        );
        assert_eq!(guard.manifest_sha256().as_deref(), Some("abcdef0123456789"));
    }

    #[test]
    fn wasm_guard_manifest_sha256_none_when_unset() {
        let mut backend = MockWasmBackend::allowing();
        backend.load_module(b"fake", 1000).unwrap();

        let guard = WasmGuard::new("test-no-hash".to_string(), Box::new(backend), false, None);
        assert!(guard.manifest_sha256().is_none());
    }

    #[test]
    fn wasm_guard_last_fuel_consumed_none_before_evaluate() {
        let mut backend = MockWasmBackend::allowing();
        backend.load_module(b"fake", 1000).unwrap();

        let guard = WasmGuard::new("test-fuel".to_string(), Box::new(backend), false, None);
        assert!(guard.last_fuel_consumed().is_none());
    }

    #[test]
    fn wasm_guard_initial_epoch_id_is_zero() {
        let mut backend = MockWasmBackend::allowing();
        backend.load_module(b"fake", 1000).unwrap();

        let guard = WasmGuard::new("test-epoch".to_string(), Box::new(backend), false, None);

        assert_eq!(guard.current_epoch_id(), EpochId::INITIAL);
        assert_eq!(guard.loaded_module().epoch_id(), EpochId::INITIAL);
    }

    #[test]
    fn wasm_guard_replace_loaded_module_assigns_monotonic_epoch_ids() {
        let mut backend = MockWasmBackend::allowing();
        backend.load_module(b"fake", 1000).unwrap();
        let guard = WasmGuard::new("test-epoch".to_string(), Box::new(backend), false, None);

        let mut next_backend = MockWasmBackend::allowing();
        next_backend.load_module(b"next", 1000).unwrap();
        let first_replacement = guard
            .replace_loaded_module(Box::new(next_backend), Some("epoch-one".to_string()))
            .unwrap();

        let mut third_backend = MockWasmBackend::allowing();
        third_backend.load_module(b"third", 1000).unwrap();
        let second_replacement = guard
            .replace_loaded_module(Box::new(third_backend), Some("epoch-two".to_string()))
            .unwrap();

        assert_eq!(first_replacement, EpochId::new(1));
        assert_eq!(second_replacement, EpochId::new(2));
        assert!(first_replacement < second_replacement);
        assert_eq!(guard.current_epoch_id(), second_replacement);
        assert_eq!(guard.manifest_sha256().as_deref(), Some("epoch-two"));
    }

    #[test]
    fn replace_loaded_module_clears_previous_instance_pre_cache() -> Result<(), WasmGuardError> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct CacheHookBackend {
            clear_count: Arc<AtomicUsize>,
        }

        impl WasmGuardAbi for CacheHookBackend {
            fn load_module(
                &mut self,
                _wasm_bytes: &[u8],
                _fuel_limit: u64,
            ) -> Result<(), WasmGuardError> {
                Ok(())
            }

            fn evaluate(
                &mut self,
                _request: &GuardRequest,
            ) -> Result<GuardVerdict, WasmGuardError> {
                Ok(GuardVerdict::Allow)
            }

            fn backend_name(&self) -> &str {
                "cache-hook"
            }

            fn clear_instance_pre_cache(&mut self) {
                self.clear_count.fetch_add(1, Ordering::AcqRel);
            }
        }

        let clear_count = Arc::new(AtomicUsize::new(0));
        let guard = WasmGuard::new(
            "cache-hook".to_string(),
            Box::new(CacheHookBackend {
                clear_count: Arc::clone(&clear_count),
            }),
            false,
            None,
        );
        let (_previous, epoch_id) = match guard.replace_loaded_module_with_previous(
            Box::new(CacheHookBackend {
                clear_count: Arc::new(AtomicUsize::new(0)),
            }),
            Some("next".to_string()),
        ) {
            Some(value) => value,
            None => return Err(WasmGuardError::BackendUnavailable),
        };

        assert_eq!(epoch_id, EpochId::new(1));
        assert_eq!(clear_count.load(Ordering::Acquire), 1);
        Ok(())
    }

    #[test]
    fn mock_backend_last_fuel_consumed_returns_none() {
        let mut backend = MockWasmBackend::allowing();
        backend.load_module(b"fake", 1000).unwrap();

        let req = GuardRequest {
            tool_name: "t".to_string(),
            server_id: "s".to_string(),
            agent_id: "a".to_string(),
            arguments: serde_json::Value::Null,
            scopes: vec![],
            action_type: None,
            extracted_path: None,
            extracted_target: None,
            filesystem_roots: Vec::new(),
            matched_grant_index: None,
        };
        let _ = backend.evaluate(&req).unwrap();
        assert!(
            backend.last_fuel_consumed().is_none(),
            "mock backend should not track fuel"
        );
    }

    #[test]
    fn guard_evidence_metadata_returns_json_structure() {
        let mut backend = MockWasmBackend::allowing();
        backend.load_module(b"fake", 1000).unwrap();

        let guard = WasmGuard::new(
            "test-evidence".to_string(),
            Box::new(backend),
            false,
            Some("sha256hex".to_string()),
        );

        let evidence = guard.guard_evidence_metadata();
        assert!(evidence.is_object());
        assert!(evidence.get("fuel_consumed").is_some());
        assert!(
            evidence["fuel_consumed"].is_null(),
            "fuel should be null before evaluate"
        );
        assert_eq!(evidence["manifest_sha256"], "sha256hex");
    }

    #[test]
    fn guard_evidence_metadata_null_when_no_manifest() {
        let mut backend = MockWasmBackend::allowing();
        backend.load_module(b"fake", 1000).unwrap();

        let guard = WasmGuard::new(
            "test-evidence-null".to_string(),
            Box::new(backend),
            false,
            None,
        );

        let evidence = guard.guard_evidence_metadata();
        assert!(evidence["manifest_sha256"].is_null());
    }
}
