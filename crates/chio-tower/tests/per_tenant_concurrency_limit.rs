use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chio_core_types::capability::{CapabilityToken, CapabilityTokenBody, ChioScope};
use chio_core_types::crypto::Keypair;
use chio_kernel::ToolCallRequest;
use chio_tower::{KernelRequest, KernelServiceError, TenantConcurrencyLimitLayer};
use tokio::sync::Notify;
use tower::{service_fn, Service, ServiceExt};
use tower_layer::Layer;

#[derive(Debug)]
struct Recorder {
    active: AtomicUsize,
    max_active: AtomicUsize,
    release: Notify,
}

impl Recorder {
    fn new() -> Self {
        Self {
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
            release: Notify::new(),
        }
    }

    async fn record_call(self: Arc<Self>) -> Result<(), KernelServiceError> {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_active.fetch_max(active, Ordering::SeqCst);
        self.release.notified().await;
        self.active.fetch_sub(1, Ordering::SeqCst);
        Ok(())
    }

    fn max_active(&self) -> usize {
        self.max_active.load(Ordering::SeqCst)
    }
}

fn make_request(request_id: &str, tenant_id: &str) -> KernelRequest {
    let issuer_keypair = Keypair::generate();
    let subject_keypair = Keypair::generate();
    let body = CapabilityTokenBody {
        id: format!("cap-{request_id}"),
        issuer: issuer_keypair.public_key(),
        subject: subject_keypair.public_key(),
        scope: ChioScope::default(),
        issued_at: 1,
        expires_at: 4_102_444_800,
        delegation_chain: vec![],
    };
    let capability = CapabilityToken::sign(body, &issuer_keypair)
        .unwrap_or_else(|error| panic!("capability signing failed: {error}"));
    let call = ToolCallRequest {
        request_id: request_id.to_string(),
        capability,
        tool_name: "echo".to_string(),
        server_id: "srv-a".to_string(),
        agent_id: subject_keypair.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };

    KernelRequest::new(call, tenant_id)
}

async fn wait_for_max_active(recorder: &Recorder, target: usize) {
    let result = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if recorder.max_active() >= target {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;

    if result.is_err() {
        panic!(
            "timed out waiting for max active calls to reach {target}; saw {}",
            recorder.max_active()
        );
    }
}

async fn join_call(handle: tokio::task::JoinHandle<Result<(), KernelServiceError>>) {
    match handle.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => panic!("service call failed: {error}"),
        Err(error) => panic!("join failed: {error}"),
    }
}

#[tokio::test]
async fn same_tenant_calls_share_one_concurrency_slot() {
    let recorder = Arc::new(Recorder::new());
    let inner_recorder = Arc::clone(&recorder);
    let inner = service_fn(move |_request: KernelRequest| {
        let recorder = Arc::clone(&inner_recorder);
        async move { recorder.record_call().await }
    });
    let service = TenantConcurrencyLimitLayer::new(1).layer(inner);

    let mut first_service = service.clone();
    let first = tokio::spawn(async move {
        first_service
            .ready()
            .await?
            .call(make_request("req-a-1", "tenant-a"))
            .await
    });

    wait_for_max_active(&recorder, 1).await;

    let mut second_service = service.clone();
    let second = tokio::time::timeout(Duration::from_millis(100), async move {
        second_service
            .ready()
            .await?
            .call(make_request("req-a-2", "tenant-a"))
            .await
    })
    .await;

    match second {
        Ok(Err(KernelServiceError::Overloaded)) => {}
        Ok(other) => panic!("expected overloaded result, got {other:?}"),
        Err(error) => panic!("overloaded result should not wait: {error}"),
    }
    assert_eq!(
        recorder.max_active(),
        1,
        "same tenant requests must not exceed the active limit"
    );

    recorder.release.notify_one();
    join_call(first).await;

    assert_eq!(recorder.max_active(), 1);
}

#[tokio::test]
async fn different_tenants_have_independent_concurrency_slots() {
    let recorder = Arc::new(Recorder::new());
    let inner_recorder = Arc::clone(&recorder);
    let inner = service_fn(move |_request: KernelRequest| {
        let recorder = Arc::clone(&inner_recorder);
        async move { recorder.record_call().await }
    });
    let service = TenantConcurrencyLimitLayer::new(1).layer(inner);

    let mut first_service = service.clone();
    let first = tokio::spawn(async move {
        first_service
            .ready()
            .await?
            .call(make_request("req-a-1", "tenant-a"))
            .await
    });

    wait_for_max_active(&recorder, 1).await;

    let mut second_service = service.clone();
    let second = tokio::spawn(async move {
        second_service
            .ready()
            .await?
            .call(make_request("req-b-1", "tenant-b"))
            .await
    });

    wait_for_max_active(&recorder, 2).await;
    recorder.release.notify_waiters();

    join_call(first).await;
    join_call(second).await;

    assert_eq!(recorder.max_active(), 2);
}

#[tokio::test]
async fn new_tenants_are_rejected_after_bucket_cap() {
    let inner = service_fn(|_request: KernelRequest| async { Ok::<_, KernelServiceError>(()) });
    let service = TenantConcurrencyLimitLayer::new(1)
        .with_max_tenants(1)
        .layer(inner);

    let mut first_service = service.clone();
    first_service
        .ready()
        .await
        .unwrap_or_else(|error| panic!("first service not ready: {error}"))
        .call(make_request("req-a-1", "tenant-a"))
        .await
        .unwrap_or_else(|error| panic!("first tenant failed: {error}"));

    let mut second_service = service.clone();
    let error = match second_service
        .ready()
        .await
        .unwrap_or_else(|error| panic!("second service not ready: {error}"))
        .call(make_request("req-b-1", "tenant-b"))
        .await
    {
        Ok(()) => panic!("second tenant should be rejected after bucket cap"),
        Err(error) => error,
    };

    assert!(matches!(error, KernelServiceError::Overloaded));
}
