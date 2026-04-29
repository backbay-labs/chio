use chio_store_sqlite::{BlobHandle, SqliteEncryptedBlobStore, TenantId, TenantKey};
use chio_tee::{SpoolError, SpooledTraffic, TeeBlobPersistence, TeeBlobSpool};

const MIB: usize = 1024 * 1024;
const SPOOL_CAPACITY_BYTES: usize = 64 * MIB;
const SYNTHETIC_STREAM_BYTES: usize = 256 * MIB;
const MAX_FILL_PERCENT: usize = 80;
const FRAME_BYTES: usize = MIB;
const HALF_FRAME_BYTES: usize = FRAME_BYTES / 2;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReceiptEvent {
    event: &'static str,
    used_bytes: usize,
    attempted_bytes: usize,
    capacity_bytes: usize,
    max_fill_bytes: usize,
}

#[derive(Debug, Default)]
struct ReceiptLog {
    events: Vec<ReceiptEvent>,
}

impl ReceiptLog {
    fn emit_spool_full(
        &mut self,
        used_bytes: usize,
        attempted_bytes: usize,
        capacity_bytes: usize,
        max_fill_bytes: usize,
    ) {
        self.events.push(ReceiptEvent {
            event: "tee.spool_full",
            used_bytes,
            attempted_bytes,
            capacity_bytes,
            max_fill_bytes,
        });
    }

    fn events(&self) -> &[ReceiptEvent] {
        &self.events
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureOutcome {
    Persisted { bytes: usize },
    Dropped { bytes: usize },
}

#[derive(Debug, Default)]
struct CaptureStats {
    offered_bytes: usize,
    persisted_bytes: usize,
    dropped_bytes: usize,
    persisted_frames: usize,
    dropped_frames: usize,
}

impl CaptureStats {
    fn record(&mut self, outcome: CaptureOutcome) {
        match outcome {
            CaptureOutcome::Persisted { bytes } => {
                self.offered_bytes += bytes;
                self.persisted_bytes += bytes;
                self.persisted_frames += 1;
            }
            CaptureOutcome::Dropped { bytes } => {
                self.offered_bytes += bytes;
                self.dropped_bytes += bytes;
                self.dropped_frames += 1;
            }
        }
    }
}

struct BoundedSpool {
    spool: TeeBlobSpool,
    capacity_bytes: usize,
    max_fill_bytes: usize,
    used_bytes: usize,
    receipt_log: ReceiptLog,
    last_persisted: Option<SpooledTraffic>,
}

impl BoundedSpool {
    fn new(spool: TeeBlobSpool, capacity_bytes: usize, max_fill_percent: usize) -> Self {
        Self {
            spool,
            capacity_bytes,
            max_fill_bytes: capacity_bytes * max_fill_percent / 100,
            used_bytes: 0,
            receipt_log: ReceiptLog::default(),
            last_persisted: None,
        }
    }

    fn capture(
        &mut self,
        tenant_id: &TenantId,
        key: &TenantKey,
        request_payload: &[u8],
        response_payload: &[u8],
    ) -> Result<CaptureOutcome, SpoolError> {
        let attempted_bytes = request_payload.len() + response_payload.len();
        if self.used_bytes + attempted_bytes > self.max_fill_bytes {
            self.receipt_log.emit_spool_full(
                self.used_bytes,
                attempted_bytes,
                self.capacity_bytes,
                self.max_fill_bytes,
            );
            return Ok(CaptureOutcome::Dropped {
                bytes: attempted_bytes,
            });
        }

        let traffic =
            self.spool
                .persist_traffic(tenant_id, key, request_payload, response_payload)?;
        let persisted_bytes = traffic.request.plaintext_len + traffic.response.plaintext_len;
        self.used_bytes += persisted_bytes;
        self.last_persisted = Some(traffic);

        Ok(CaptureOutcome::Persisted {
            bytes: persisted_bytes,
        })
    }

    fn used_bytes(&self) -> usize {
        self.used_bytes
    }

    fn max_fill_bytes(&self) -> usize {
        self.max_fill_bytes
    }

    fn receipt_events(&self) -> &[ReceiptEvent] {
        self.receipt_log.events()
    }

    fn last_request_handle(&self) -> Option<&BlobHandle> {
        self.last_persisted
            .as_ref()
            .map(|traffic| &traffic.request.handle)
    }

    fn read_blob(&self, handle: &BlobHandle, key: &TenantKey) -> Result<Vec<u8>, SpoolError> {
        self.spool.read_blob(handle, key)
    }
}

#[test]
fn synthetic_stream_drops_after_eighty_percent_spool_fill_without_crashing(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let db_path = dir.path().join("tee-spool.sqlite3");
    let store = SqliteEncryptedBlobStore::open(&db_path)?;
    let spool = TeeBlobSpool::new(TeeBlobPersistence::new(store));
    let mut bounded = BoundedSpool::new(spool, SPOOL_CAPACITY_BYTES, MAX_FILL_PERCENT);
    let tenant = TenantId::new("tenant-spool-backpressure");
    let key = TenantKey::from_bytes([19; 32]);
    let request_payload = vec![b'r'; HALF_FRAME_BYTES];
    let response_payload = vec![b's'; HALF_FRAME_BYTES];
    let mut stats = CaptureStats::default();

    for _ in 0..(SYNTHETIC_STREAM_BYTES / FRAME_BYTES) {
        let outcome = bounded.capture(&tenant, &key, &request_payload, &response_payload)?;
        stats.record(outcome);
    }

    assert_eq!(stats.offered_bytes, SYNTHETIC_STREAM_BYTES);
    assert!(stats.persisted_frames > 0);
    assert!(stats.dropped_frames > 0);
    assert_eq!(stats.persisted_bytes, bounded.used_bytes());
    assert!(stats.persisted_bytes <= bounded.max_fill_bytes());
    assert_eq!(
        stats.dropped_bytes,
        SYNTHETIC_STREAM_BYTES - stats.persisted_bytes
    );

    let events = bounded.receipt_events();
    assert_eq!(events.len(), stats.dropped_frames);
    assert!(events.iter().all(|event| event.event == "tee.spool_full"));
    assert!(events
        .iter()
        .all(|event| event.used_bytes <= event.max_fill_bytes));
    assert!(events
        .iter()
        .all(|event| event.used_bytes + event.attempted_bytes > event.max_fill_bytes));
    assert!(events
        .iter()
        .all(|event| event.capacity_bytes == SPOOL_CAPACITY_BYTES));

    let Some(last_request_handle) = bounded.last_request_handle() else {
        return Err("expected at least one persisted frame before backpressure".into());
    };
    let last_request = bounded.read_blob(last_request_handle, &key)?;
    assert_eq!(last_request.len(), HALF_FRAME_BYTES);

    Ok(())
}
