use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use chio_core::capability::{CapabilityToken, CapabilityTokenBody, ChioScope};
use chio_core::crypto::Keypair;
use chio_kernel::{Guard, GuardContext, ToolCallRequest, Verdict};
use chio_wasm_guards::{
    guard_fetch_blob_span, guard_host_call_span, guard_verify_span, runtime::MockWasmBackend,
    Engine, WasmGuard, WasmGuardAbi, WasmGuardError, HOST_FETCH_BLOB, SPAN_GUARD_EVALUATE,
    SPAN_GUARD_FETCH_BLOB, SPAN_GUARD_HOST_CALL, SPAN_GUARD_RELOAD, SPAN_GUARD_VERIFY,
    VERIFY_MODE_ED25519, VERIFY_RESULT_OK,
};
use tracing::field::{Field, Visit};
use tracing::span::Attributes;
use tracing::{Id, Subscriber};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{Layer, Registry};

#[derive(Clone, Debug, Default)]
struct CapturedSpans {
    spans: Arc<Mutex<Vec<CapturedSpan>>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CapturedSpan {
    name: String,
    fields: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug)]
struct SpanIndex(usize);

#[derive(Debug, Default)]
struct FieldVisitor {
    fields: BTreeMap<String, String>,
}

impl Visit for FieldVisitor {
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.fields
            .insert(field.name().to_string(), format!("{value:?}"));
    }
}

#[derive(Clone, Debug)]
struct CaptureLayer {
    captured: CapturedSpans,
}

impl<S> Layer<S> for CaptureLayer
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let mut visitor = FieldVisitor::default();
        attrs.record(&mut visitor);

        let index = {
            let mut spans = self.captured.lock();
            let index = spans.len();
            spans.push(CapturedSpan {
                name: attrs.metadata().name().to_string(),
                fields: visitor.fields,
            });
            index
        };

        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(SpanIndex(index));
        }
    }

    fn on_record(&self, id: &Id, values: &tracing::span::Record<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else {
            return;
        };
        let Some(index) = span.extensions().get::<SpanIndex>().copied() else {
            return;
        };

        let mut visitor = FieldVisitor::default();
        values.record(&mut visitor);

        let mut spans = self.captured.lock();
        if let Some(captured) = spans.get_mut(index.0) {
            captured.fields.extend(visitor.fields);
        }
    }
}

impl CapturedSpans {
    fn lock(&self) -> MutexGuard<'_, Vec<CapturedSpan>> {
        match self.spans.lock() {
            Ok(guard) => guard,
            Err(err) => panic!("span capture lock poisoned: {err}"),
        }
    }

    fn layer(&self) -> CaptureLayer {
        CaptureLayer {
            captured: self.clone(),
        }
    }

    fn snapshot(&self) -> Vec<CapturedSpan> {
        self.lock().clone()
    }
}

fn subscriber(captured: &CapturedSpans) -> impl Subscriber {
    Registry::default().with(captured.layer())
}

fn span_by_name<'a>(spans: &'a [CapturedSpan], name: &str) -> &'a CapturedSpan {
    match spans.iter().find(|span| span.name == name) {
        Some(span) => span,
        None => panic!("missing span named {name} in {spans:?}"),
    }
}

fn field<'a>(span: &'a CapturedSpan, name: &str) -> &'a str {
    match span.fields.get(name) {
        Some(value) => value.trim_matches('"'),
        None => panic!("missing field {name} on span {span:?}"),
    }
}

fn make_test_request() -> ToolCallRequest {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let signer = Keypair::generate();
    let capability = match CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-1".to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope::default(),
            issued_at: 0,
            expires_at: u64::MAX,
            delegation_chain: vec![],
        },
        &signer,
    ) {
        Ok(token) => token,
        Err(err) => panic!("capability signing failed: {err}"),
    };

    ToolCallRequest {
        request_id: "req-1".to_string(),
        capability,
        tool_name: "test_tool".to_string(),
        server_id: "test_server".to_string(),
        agent_id: "agent-1".to_string(),
        arguments: serde_json::json!({"key": "value"}),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    }
}

fn loaded_allowing_backend() -> MockWasmBackend {
    let mut backend = MockWasmBackend::allowing();
    if let Err(err) = backend.load_module(b"fake", 1000) {
        panic!("mock backend failed to load: {err}");
    }
    backend
}

#[test]
fn evaluate_span_records_exact_field_set() {
    let captured = CapturedSpans::default();
    tracing::subscriber::with_default(subscriber(&captured), || {
        let guard = WasmGuard::new_with_metadata(
            "guard-a".to_string(),
            "1.2.3".to_string(),
            Box::new(loaded_allowing_backend()),
            false,
            Some("abc123".to_string()),
        );
        guard.record_reload_seq(42);

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

        let verdict = match guard.evaluate(&ctx) {
            Ok(verdict) => verdict,
            Err(err) => panic!("guard evaluation failed: {err}"),
        };
        assert!(matches!(verdict, Verdict::Allow));
    });

    let spans = captured.snapshot();
    let span = span_by_name(&spans, SPAN_GUARD_EVALUATE);
    assert_eq!(field(span, "guard.id"), "guard-a");
    assert_eq!(field(span, "guard.version"), "1.2.3");
    assert_eq!(field(span, "guard.digest"), "abc123");
    assert_eq!(field(span, "guard.epoch"), "0");
    assert_eq!(field(span, "guard.reload_seq"), "42");
    assert_eq!(field(span, "verdict"), "allow");
}

#[test]
fn host_fetch_blob_and_verify_helpers_emit_exact_fields() {
    let captured = CapturedSpans::default();
    tracing::subscriber::with_default(subscriber(&captured), || {
        let host_span = guard_host_call_span(HOST_FETCH_BLOB);
        let _host_guard = host_span.enter();

        let fetch_span = guard_fetch_blob_span("bundle-1", 128);
        let _fetch_guard = fetch_span.enter();

        let verify_span = guard_verify_span(VERIFY_MODE_ED25519, Some(VERIFY_RESULT_OK));
        let _verify_guard = verify_span.enter();
    });

    let spans = captured.snapshot();
    let host = span_by_name(&spans, SPAN_GUARD_HOST_CALL);
    assert_eq!(field(host, "host.name"), "fetch_blob");

    let fetch = span_by_name(&spans, SPAN_GUARD_FETCH_BLOB);
    assert_eq!(field(fetch, "bundle.id"), "bundle-1");
    assert_eq!(field(fetch, "bytes"), "128");

    let verify = span_by_name(&spans, SPAN_GUARD_VERIFY);
    assert_eq!(field(verify, "mode"), "ed25519");
    assert_eq!(field(verify, "result"), "ok");
}

#[test]
fn reload_path_emits_applied_span() {
    let captured = CapturedSpans::default();
    tracing::subscriber::with_default(subscriber(&captured), || {
        let engine = Engine::new(|_bytes: &[u8]| {
            Ok::<Box<dyn WasmGuardAbi>, WasmGuardError>(Box::new(loaded_allowing_backend()))
        })
        .without_blocklist();
        let guard = WasmGuard::new_with_metadata(
            "guard-a".to_string(),
            "1.2.3".to_string(),
            Box::new(loaded_allowing_backend()),
            false,
            Some("abc123".to_string()),
        );
        if let Err(err) = engine.register_guard("guard-a", guard) {
            panic!("guard registration failed: {err}");
        }
        if let Err(err) = engine.reload("guard-a", b"new-module") {
            panic!("guard reload failed: {err}");
        }
    });

    let spans = captured.snapshot();
    let span = span_by_name(&spans, SPAN_GUARD_RELOAD);
    assert_eq!(field(span, "outcome"), "applied");
    assert_eq!(field(span, "reload_seq"), "0");
}
