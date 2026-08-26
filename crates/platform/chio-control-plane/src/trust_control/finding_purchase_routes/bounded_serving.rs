use super::*;

use std::sync::Mutex;
use std::time::Duration;

use axum::body::{Body, Bytes};
use futures_util::stream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const FINDING_RESPONSE_CHUNK_BYTES: usize = 64 * 1024;
const FINDING_RESPONSE_EGRESS_DEADLINE: Duration = Duration::from_secs(30);

pub(super) enum PurchaseLaneError {
    Busy,
    Worker,
}

pub(super) async fn execute_purchase<T>(
    lane: Arc<Semaphore>,
    execute: impl FnOnce(tokio::runtime::Handle) -> T + Send + 'static,
) -> Result<(T, OwnedSemaphorePermit), PurchaseLaneError>
where
    T: Send + 'static,
{
    let permit = lane
        .try_acquire_owned()
        .map_err(|_| PurchaseLaneError::Busy)?;
    let runtime = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || (execute(runtime), permit))
        .await
        .map_err(|_| PurchaseLaneError::Worker)
}

pub(super) async fn serve_purchase_response(
    response: Response,
    permit: OwnedSemaphorePermit,
) -> Response {
    if response.status() != StatusCode::OK {
        return response;
    }
    let (parts, body) = response.into_parts();
    let bytes = match axum::body::to_bytes(body, FINDING_PURCHASE_MAX_RESULT_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return purchase_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "purchase_response_failed",
                "finding purchase response could not be served",
            )
        }
    };
    Response::from_parts(parts, leased_json_body(bytes, permit))
}

pub(super) async fn serve_public_proof(
    executor: SharedFindingPurchaseExecutor,
    finding_id: String,
    lane: Arc<Semaphore>,
) -> Response {
    let permit = match lane.try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "finding proof egress lane is busy",
            )
        }
    };
    let proof =
        read_public_proof_blocking(move || executor.public_proof(&finding_id), permit).await;
    match proof {
        Ok((Ok(bytes), permit)) if bytes.len() <= FINDING_PROOF_BUNDLE_MAX_BYTES => {
            let mut response = Response::new(leased_json_body(Bytes::from(bytes), permit));
            *response.status_mut() = StatusCode::OK;
            response
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            response
        }
        Ok((Ok(_), _permit)) => plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "finding proof bundle exceeds its serving bound",
        ),
        Ok((Err(error), _permit)) => public_proof_error_response(error),
        Err(_) => plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "finding proof reader failed",
        ),
    }
}

async fn read_public_proof_blocking(
    read: impl FnOnce() -> Result<Vec<u8>, FindingPublicProofError> + Send + 'static,
    permit: OwnedSemaphorePermit,
) -> Result<
    (
        Result<Vec<u8>, FindingPublicProofError>,
        OwnedSemaphorePermit,
    ),
    tokio::task::JoinError,
> {
    tokio::task::spawn_blocking(move || (read(), permit)).await
}

fn public_proof_error_response(error: FindingPublicProofError) -> Response {
    match error {
        FindingPublicProofError::NotFound => {
            plain_http_error(StatusCode::NOT_FOUND, "finding proof bundle is unavailable")
        }
        FindingPublicProofError::Unavailable => plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "finding proof store is unavailable",
        ),
        FindingPublicProofError::Integrity => plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "retained finding proof failed integrity verification",
        ),
    }
}

struct ResponseStreamState {
    receiver: tokio::sync::mpsc::Receiver<Result<Bytes, std::io::Error>>,
    _lease: Arc<ResponseEgressLease>,
}

struct ResponseEgressLease {
    permit: Mutex<Option<OwnedSemaphorePermit>>,
}

impl ResponseEgressLease {
    fn release(&self) {
        if let Ok(mut permit) = self.permit.lock() {
            permit.take();
        }
    }
}

fn leased_json_body(bytes: Bytes, permit: OwnedSemaphorePermit) -> Body {
    let lease = Arc::new(ResponseEgressLease {
        permit: Mutex::new(Some(permit)),
    });
    let deadline = tokio::time::Instant::now() + FINDING_RESPONSE_EGRESS_DEADLINE;
    let deadline_lease = Arc::downgrade(&lease);
    tokio::spawn(async move {
        tokio::time::sleep_until(deadline).await;
        if let Some(lease) = deadline_lease.upgrade() {
            lease.release();
        }
    });
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        for start in (0..bytes.len()).step_by(FINDING_RESPONSE_CHUNK_BYTES) {
            let end = (start + FINDING_RESPONSE_CHUNK_BYTES).min(bytes.len());
            let send = sender.send(Ok(bytes.slice(start..end)));
            match tokio::time::timeout_at(deadline, send).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) | Err(_) => return,
            }
        }
    });
    let state = ResponseStreamState {
        receiver,
        _lease: lease,
    };
    Body::from_stream(stream::unfold(state, |mut state| async move {
        state.receiver.recv().await.map(|chunk| (chunk, state))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_read_failures_preserve_missing_retryable_and_integrity_classes() {
        assert_eq!(
            public_proof_error_response(FindingPublicProofError::NotFound).status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            public_proof_error_response(FindingPublicProofError::Unavailable).status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            public_proof_error_response(FindingPublicProofError::Integrity).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[tokio::test]
    async fn proof_response_holds_nonqueued_lane_until_body_drop() {
        let lane = Arc::new(Semaphore::new(1));
        let permit = lane
            .clone()
            .try_acquire_owned()
            .unwrap_or_else(|error| panic!("proof permit: {error}"));
        let response = Response::new(leased_json_body(Bytes::from_static(b"{}"), permit));
        assert!(lane.clone().try_acquire_owned().is_err());
        drop(response);
        assert!(lane.try_acquire_owned().is_ok());
    }

    #[tokio::test]
    async fn purchase_response_holds_lane_until_completion_or_cancellation() {
        let lane = Arc::new(Semaphore::new(1));
        let permit = lane
            .clone()
            .try_acquire_owned()
            .unwrap_or_else(|error| panic!("purchase permit: {error}"));
        let payload = vec![b'x'; FINDING_RESPONSE_CHUNK_BYTES * 2 + 1];
        let response = serve_purchase_response(
            (
                StatusCode::OK,
                [(CONTENT_TYPE, "application/json")],
                payload.clone(),
            )
                .into_response(),
            permit,
        )
        .await;
        assert!(lane.clone().try_acquire_owned().is_err());
        let body = axum::body::to_bytes(response.into_body(), payload.len())
            .await
            .unwrap_or_else(|error| panic!("purchase response body: {error}"));
        assert_eq!(body.as_ref(), payload.as_slice());
        assert!(lane.clone().try_acquire_owned().is_ok());

        let permit = lane
            .clone()
            .try_acquire_owned()
            .unwrap_or_else(|error| panic!("purchase permit: {error}"));
        let response = serve_purchase_response(
            (
                StatusCode::OK,
                [(CONTENT_TYPE, "application/json")],
                payload,
            )
                .into_response(),
            permit,
        )
        .await;
        assert!(lane.clone().try_acquire_owned().is_err());
        drop(response);
        assert!(lane.try_acquire_owned().is_ok());
    }

    #[tokio::test]
    async fn cancelled_proof_handler_does_not_release_an_active_reader() {
        let lane = Arc::new(Semaphore::new(1));
        let permit = lane
            .clone()
            .try_acquire_owned()
            .unwrap_or_else(|error| panic!("proof permit: {error}"));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let reader = tokio::spawn(async move {
            read_public_proof_blocking(
                move || {
                    let _ = started_tx.send(());
                    let _ = release_rx.recv();
                    Ok(b"{}".to_vec())
                },
                permit,
            )
            .await
        });
        started_rx
            .await
            .unwrap_or_else(|error| panic!("proof reader start: {error}"));
        reader.abort();
        match reader.await {
            Err(error) => assert!(error.is_cancelled()),
            Ok(_) => panic!("cancelled proof handler unexpectedly completed"),
        }
        assert!(lane.clone().try_acquire_owned().is_err());
        let _ = release_tx.send(());
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if lane.available_permits() == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!("proof permit was not released after the blocking reader exited")
        });
        assert!(lane.try_acquire_owned().is_ok());
    }

    #[test]
    fn purchase_lane_rejects_queued_blocking_work() {
        let lane = Arc::new(Semaphore::new(1));
        let active = lane
            .clone()
            .try_acquire_owned()
            .unwrap_or_else(|error| panic!("purchase permit: {error}"));
        assert!(lane.clone().try_acquire_owned().is_err());
        drop(active);
        assert!(lane.try_acquire_owned().is_ok());
    }
}
