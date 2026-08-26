use super::*;

use std::sync::Mutex;
use std::time::Duration;

use axum::body::Body;
use futures_util::stream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const FINDING_PROOF_CHUNK_BYTES: usize = 64 * 1024;
const FINDING_PROOF_EGRESS_DEADLINE: Duration = Duration::from_secs(30);

pub(super) enum PurchaseLaneError {
    Busy,
    Worker,
}

pub(super) async fn execute_purchase<T>(
    lane: Arc<Semaphore>,
    execute: impl FnOnce(tokio::runtime::Handle) -> T + Send + 'static,
) -> Result<T, PurchaseLaneError>
where
    T: Send + 'static,
{
    let permit = lane
        .try_acquire_owned()
        .map_err(|_| PurchaseLaneError::Busy)?;
    let runtime = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        execute(runtime)
    })
    .await
    .map_err(|_| PurchaseLaneError::Worker)
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
            proof_stream_response(bytes, permit)
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

struct ProofStreamState {
    receiver: tokio::sync::mpsc::Receiver<Result<Vec<u8>, std::io::Error>>,
    _lease: Arc<ProofEgressLease>,
}

struct ProofEgressLease {
    permit: Mutex<Option<OwnedSemaphorePermit>>,
}

impl ProofEgressLease {
    fn release(&self) {
        if let Ok(mut permit) = self.permit.lock() {
            permit.take();
        }
    }
}

fn proof_stream_response(bytes: Vec<u8>, permit: OwnedSemaphorePermit) -> Response {
    let lease = Arc::new(ProofEgressLease {
        permit: Mutex::new(Some(permit)),
    });
    let deadline = tokio::time::Instant::now() + FINDING_PROOF_EGRESS_DEADLINE;
    let deadline_lease = Arc::downgrade(&lease);
    tokio::spawn(async move {
        tokio::time::sleep_until(deadline).await;
        if let Some(lease) = deadline_lease.upgrade() {
            lease.release();
        }
    });
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        for chunk in bytes.chunks(FINDING_PROOF_CHUNK_BYTES) {
            let send = sender.send(Ok(chunk.to_vec()));
            match tokio::time::timeout_at(deadline, send).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) | Err(_) => return,
            }
        }
    });
    let state = ProofStreamState {
        receiver,
        _lease: lease,
    };
    let body = Body::from_stream(stream::unfold(state, |mut state| async move {
        state.receiver.recv().await.map(|chunk| (chunk, state))
    }));
    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
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
        let response = proof_stream_response(b"{}".to_vec(), permit);
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
