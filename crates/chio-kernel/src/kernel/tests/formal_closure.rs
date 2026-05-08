fn formal_closure_receipt_count(path: &std::path::Path) -> u64 {
    let connection = Connection::open(path).unwrap();
    connection
        .query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap()
        .max(0) as u64
}

fn formal_closure_kernel_with_store(prefix: &str) -> (ChioKernel, std::path::PathBuf) {
    let path = unique_receipt_db_path(prefix);
    let mut kernel = ChioKernel::new(make_config());
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));
    (kernel, path)
}

fn formal_closure_assert_one_signed_receipt(path: &std::path::Path, response: &ToolCallResponse) {
    assert_eq!(formal_closure_receipt_count(path), 1);
    assert!(response.receipt.verify_signature().unwrap());
}

struct FormalClosureGuardError;

impl Guard for FormalClosureGuardError {
    fn name(&self) -> &str {
        "formal-closure-error"
    }

    fn evaluate(&self, _ctx: &GuardContext) -> Result<Verdict, KernelError> {
        Err(KernelError::GuardDenied(
            "formal closure guard error".to_string(),
        ))
    }
}

struct FormalClosureToolErrorServer {
    id: String,
}

#[async_trait::async_trait(?Send)]
impl ToolServerConnection for FormalClosureToolErrorServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["read_file".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::GuardDenied(
            "formal closure tool failure".to_string(),
        ))
    }
}

#[test]
fn formal_receipt_totality_allow_persists_one_signed_receipt() {
    let (mut kernel, path) = formal_closure_kernel_with_store("formal-totality-allow");
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));
    let subject = make_keypair();
    let cap = make_capability(
        &kernel,
        &subject,
        make_scope(vec![make_grant("srv-a", "read_file")]),
        3600,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&make_request("formal-allow", &cap, "read_file", "srv-a"))
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    formal_closure_assert_one_signed_receipt(&path, &response);
}

#[test]
fn formal_receipt_totality_out_of_scope_persists_one_signed_receipt() {
    let (mut kernel, path) = formal_closure_kernel_with_store("formal-totality-scope");
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));
    let subject = make_keypair();
    let cap = make_capability(
        &kernel,
        &subject,
        make_scope(vec![make_grant("srv-a", "read_file")]),
        3600,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&make_request(
            "formal-scope",
            &cap,
            "write_file",
            "srv-a",
        ))
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    formal_closure_assert_one_signed_receipt(&path, &response);
}

#[test]
fn formal_receipt_totality_revocation_persists_one_signed_receipt() {
    let (mut kernel, path) = formal_closure_kernel_with_store("formal-totality-revoke");
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));
    let subject = make_keypair();
    let cap = make_capability(
        &kernel,
        &subject,
        make_scope(vec![make_grant("srv-a", "read_file")]),
        3600,
    );
    kernel.revoke_capability(&cap.id).unwrap();

    let response = kernel
        .evaluate_tool_call_blocking(&make_request("formal-revoke", &cap, "read_file", "srv-a"))
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    formal_closure_assert_one_signed_receipt(&path, &response);
}

#[test]
fn formal_receipt_totality_malformed_capability_persists_one_signed_receipt() {
    let (mut kernel, path) = formal_closure_kernel_with_store("formal-totality-malformed");
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));
    let subject = make_keypair();
    let mut cap = make_capability(
        &kernel,
        &subject,
        make_scope(vec![make_grant("srv-a", "read_file")]),
        3600,
    );
    cap.id.push_str("-tampered");

    let response = kernel
        .evaluate_tool_call_blocking(&make_request("formal-malformed", &cap, "read_file", "srv-a"))
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    formal_closure_assert_one_signed_receipt(&path, &response);
}

#[test]
fn formal_receipt_totality_guard_error_persists_one_signed_receipt() {
    let (mut kernel, path) = formal_closure_kernel_with_store("formal-totality-guard");
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));
    kernel.add_guard(Box::new(FormalClosureGuardError));
    let subject = make_keypair();
    let cap = make_capability(
        &kernel,
        &subject,
        make_scope(vec![make_grant("srv-a", "read_file")]),
        3600,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&make_request("formal-guard", &cap, "read_file", "srv-a"))
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    formal_closure_assert_one_signed_receipt(&path, &response);
}

#[test]
fn formal_receipt_totality_dpop_failure_persists_one_signed_receipt() {
    let subject = make_keypair();
    let server = "srv-a";
    let tool = "read_file";
    let (mut kernel, cap) = make_dpop_kernel_and_cap(&subject, server, tool);
    let path = unique_receipt_db_path("formal-totality-dpop");
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));

    let response = kernel
        .evaluate_tool_call_blocking(&make_request("formal-dpop", &cap, tool, server))
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    formal_closure_assert_one_signed_receipt(&path, &response);
}

#[test]
fn formal_receipt_totality_budget_exhaustion_persists_one_signed_receipt() {
    let (mut kernel, path) = formal_closure_kernel_with_store("formal-totality-budget");
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));
    let subject = make_keypair();
    let mut grant = make_grant("srv-a", "read_file");
    grant.max_invocations = Some(0);
    let cap = make_capability(&kernel, &subject, make_scope(vec![grant]), 3600);

    let response = kernel
        .evaluate_tool_call_blocking(&make_request("formal-budget", &cap, "read_file", "srv-a"))
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    formal_closure_assert_one_signed_receipt(&path, &response);
}

#[test]
fn formal_receipt_totality_tool_error_persists_one_signed_receipt() {
    let (mut kernel, path) = formal_closure_kernel_with_store("formal-totality-tool-error");
    kernel.register_tool_server(Box::new(FormalClosureToolErrorServer {
        id: "srv-a".to_string(),
    }));
    let subject = make_keypair();
    let cap = make_capability(
        &kernel,
        &subject,
        make_scope(vec![make_grant("srv-a", "read_file")]),
        3600,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&make_request("formal-tool-error", &cap, "read_file", "srv-a"))
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    formal_closure_assert_one_signed_receipt(&path, &response);
}
