#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use chio_federation::revocation_gossip::{
    respond_to_catchup, RevocationCatchupHistory, RevocationCatchupRequest,
    RevocationGossipPushQueue, RevocationRootGossip,
};
use chio_kernel_core::{RevocationSnapshot, RevocationView, RevocationViewSubject};
use chio_revocation_oracle::{
    verify_fresh_epoch_root, Ed25519RootSigner, EpochNonce, FreshnessConfig,
    InMemoryRevocationOracle, RevocationKey, RevocationOracle, SignedEpochRoot, SubjectId,
};
use serde::Serialize;
use serde_json::json;

const PEER: &str = "peer-b";
const TRACE_ENV: &str = "CHIO_DISTRIBUTED_REVOCATION_TRACE_DIR";
const ROOT_ISSUED_AT_BASE: u64 = 1_700_000_000_000;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TraceState {
    action: String,
    origin_epoch: u64,
    view_epoch: u64,
    queue_epoch: u64,
    channel_count: u64,
    forged_count: u64,
    partitioned: bool,
    local_time: u64,
    view_issued_at: u64,
    freshness_bound: u64,
    allow_fresh: bool,
}

impl TraceState {
    fn initial() -> Self {
        Self {
            action: "Init".to_string(),
            origin_epoch: 0,
            view_epoch: 0,
            queue_epoch: 0,
            channel_count: 0,
            forged_count: 0,
            partitioned: false,
            local_time: 0,
            view_issued_at: 0,
            freshness_bound: 2,
            allow_fresh: true,
        }
    }

    fn after(&self, action: &str) -> Self {
        let mut next = self.clone();
        next.action = action.to_string();
        next
    }
}

fn write_trace(name: &str, states: &[TraceState]) {
    let Some(directory) = std::env::var_os(TRACE_ENV) else {
        return;
    };
    let directory = Path::new(&directory);
    fs::create_dir_all(directory).expect("create trace directory");
    let states: Vec<serde_json::Value> = states
        .iter()
        .enumerate()
        .map(|(index, state)| {
            let mut value = serde_json::to_value(state).expect("serialize trace state");
            value
                .as_object_mut()
                .expect("trace state is an object")
                .insert("#meta".to_string(), json!({"index": index}));
            value
        })
        .collect();
    let document = json!({
        "#meta": {
            "format": "ITF",
            "format-description": "https://apalache-mc.org/docs/adr/015adr-trace.html",
            "varTypes": {
                "action": "Str",
                "originEpoch": "Int",
                "viewEpoch": "Int",
                "queueEpoch": "Int",
                "channelCount": "Int",
                "forgedCount": "Int",
                "partitioned": "Bool",
                "localTime": "Int",
                "viewIssuedAt": "Int",
                "freshnessBound": "Int",
                "allowFresh": "Bool"
            }
        },
        "params": [],
        "vars": [
            "action",
            "originEpoch",
            "viewEpoch",
            "queueEpoch",
            "channelCount",
            "forgedCount",
            "partitioned",
            "localTime",
            "viewIssuedAt",
            "freshnessBound",
            "allowFresh"
        ],
        "states": states
    });
    let path = directory.join(format!("{name}.itf.json"));
    fs::write(
        path,
        serde_json::to_vec_pretty(&document).expect("serialize ITF document"),
    )
    .expect("write ITF trace");
}

fn revoke(
    oracle: &mut InMemoryRevocationOracle,
    signer: &Ed25519RootSigner,
    subject: &str,
    nonce: u64,
) -> SignedEpochRoot {
    oracle
        .insert(
            RevocationKey::new(SubjectId::from(subject), EpochNonce::new(nonce)),
            ROOT_ISSUED_AT_BASE.saturating_add(nonce),
        )
        .expect("insert revocation");
    oracle.signed_epoch_root(signer).expect("sign epoch root")
}

fn revoked_through(epoch: u64) -> BTreeSet<RevocationViewSubject> {
    (1..=epoch)
        .map(|number| RevocationViewSubject::from(format!("subject-{number}")))
        .collect()
}

fn install_verified(
    view: &RevocationView,
    frame: &RevocationRootGossip,
    signer: &Ed25519RootSigner,
) -> Result<(), String> {
    frame
        .validate_envelope()
        .map_err(|error| error.to_string())?;
    frame
        .signed_root
        .verify(&signer.verifier())
        .map_err(|error| error.to_string())?;
    let snapshot = RevocationSnapshot {
        epoch: frame.epoch,
        root_hash: frame.signed_root.root.root_hash,
        issued_at_unix_ms: frame.signed_root.root.issued_at_unix_ms,
        revoked: revoked_through(frame.epoch),
    };
    view.install_if_newer(snapshot)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

#[derive(Default)]
struct History {
    roots: BTreeMap<u64, SignedEpochRoot>,
}

impl RevocationCatchupHistory for History {
    fn signed_root_at(&self, epoch: u64) -> Option<SignedEpochRoot> {
        self.roots.get(&epoch).cloned()
    }
}

#[test]
fn loss_duplicate_and_reorder_preserve_monotone_view() {
    let signer = Ed25519RootSigner::from_signing_key("oracle-a", "generate").expect("test signer");
    let mut oracle = InMemoryRevocationOracle::new();
    let queue = RevocationGossipPushQueue::new(4).expect("push queue");
    queue.subscribe(PEER).expect("subscribe peer");
    let view = RevocationView::new();
    let mut trace = vec![TraceState::initial()];

    let first = revoke(&mut oracle, &signer, "subject-1", 1);
    let mut state = trace.last().unwrap().after("Revoke");
    state.origin_epoch = first.root.epoch;
    trace.push(state);

    queue
        .enqueue_signed_root(first)
        .expect("enqueue first root");
    assert_eq!(
        queue.pending_for(PEER).expect("pending first root"),
        Some(1)
    );
    let mut state = trace.last().unwrap().after("QueueRoot");
    state.queue_epoch = 1;
    trace.push(state);
    let first_batch = queue
        .flush_batches_at(1_700_000_000_001)
        .expect("flush first root")
        .pop()
        .expect("first batch");
    let first_frame = first_batch.frames[0].clone();
    assert_eq!(
        queue.pending_for(PEER).expect("first queue drained"),
        Some(0)
    );
    let mut in_flight = vec![first_frame.clone()];
    let mut state = trace.last().unwrap().after("Send");
    state.queue_epoch = 0;
    state.channel_count = 1;
    trace.push(state);

    in_flight.push(first_frame);
    let mut state = trace.last().unwrap().after("Duplicate");
    state.channel_count = 2;
    trace.push(state);
    in_flight.pop().expect("drop duplicate");
    let mut state = trace.last().unwrap().after("Lose");
    state.channel_count = 1;
    trace.push(state);

    let second = revoke(&mut oracle, &signer, "subject-2", 2);
    let mut state = trace.last().unwrap().after("Revoke");
    state.origin_epoch = second.root.epoch;
    trace.push(state);
    queue
        .enqueue_signed_root(second)
        .expect("enqueue second root");
    assert_eq!(
        queue.pending_for(PEER).expect("pending second root"),
        Some(1)
    );
    let mut state = trace.last().unwrap().after("QueueRoot");
    state.queue_epoch = 2;
    trace.push(state);
    let second_batch = queue
        .flush_batches_at(1_700_000_000_002)
        .expect("flush second root")
        .pop()
        .expect("second batch");
    assert_eq!(
        queue.pending_for(PEER).expect("second queue drained"),
        Some(0)
    );
    in_flight.push(second_batch.frames[0].clone());
    let mut state = trace.last().unwrap().after("Send");
    state.queue_epoch = 0;
    state.channel_count = 2;
    trace.push(state);

    let newest = in_flight.pop().expect("newest frame");
    install_verified(&view, &newest, &signer).expect("newest root installs");
    let mut state = trace.last().unwrap().after("Deliver");
    state.view_epoch = newest.epoch;
    state.view_issued_at = newest.signed_root.root.issued_at_unix_ms;
    state.channel_count = 1;
    trace.push(state);

    let stale = in_flight.pop().expect("stale frame");
    let error = install_verified(&view, &stale, &signer).expect_err("stale root is rejected");
    assert!(error.contains("not strictly greater"));
    assert_eq!(view.current_epoch(), newest.epoch);
    let mut state = trace.last().unwrap().after("Deliver");
    state.channel_count = 0;
    trace.push(state);

    write_trace("loss-duplicate-reorder", &trace);
}

#[test]
fn forged_root_is_rejected_by_pinned_signer() {
    let pinned =
        Ed25519RootSigner::from_signing_key("oracle-a", "generate").expect("pinned signer");
    let attacker =
        Ed25519RootSigner::from_signing_key("oracle-z", "generate").expect("attacker signer");
    let mut oracle = InMemoryRevocationOracle::new();
    let forged = revoke(&mut oracle, &attacker, "subject-1", 1);
    let frame = RevocationRootGossip::from_signed(forged, 1_700_000_000_001);
    frame
        .validate_envelope()
        .expect("forged envelope is well formed");
    assert!(frame.signed_root.verify(&pinned.verifier()).is_err());

    let mut trace = vec![TraceState::initial()];
    let mut state = trace.last().unwrap().after("InjectForged");
    state.forged_count = 1;
    trace.push(state);
    let mut state = trace.last().unwrap().after("RejectForged");
    state.forged_count = 0;
    trace.push(state);
    write_trace("forged-signer-rejected", &trace);
}

#[test]
fn partition_suspends_delivery_then_catchup_converges() {
    let signer = Ed25519RootSigner::from_signing_key("oracle-a", "generate").expect("test signer");
    let mut oracle = InMemoryRevocationOracle::new();
    let queue = RevocationGossipPushQueue::new(4).expect("push queue");
    queue.subscribe(PEER).expect("subscribe peer");
    let view = RevocationView::new();
    let mut history = History::default();
    let mut trace = vec![TraceState::initial()];

    for epoch in 1..=3_u64 {
        let root = revoke(&mut oracle, &signer, &format!("subject-{epoch}"), epoch);
        history.roots.insert(epoch, root.clone());
        let mut state = trace.last().unwrap().after("Revoke");
        state.origin_epoch = root.root.epoch;
        trace.push(state);
        queue.enqueue_signed_root(root).expect("enqueue root");
        assert_eq!(
            queue.pending_for(PEER).expect("pending coalesced root"),
            Some(1)
        );
        let mut state = trace.last().unwrap().after("QueueRoot");
        state.queue_epoch = epoch;
        trace.push(state);
    }
    let batch = queue
        .flush_batches_at(1_700_000_000_003)
        .expect("flush coalesced root")
        .pop()
        .expect("coalesced batch");
    assert_eq!(batch.frames.len(), 1);
    assert_eq!(
        queue.pending_for(PEER).expect("coalesced queue drained"),
        Some(0)
    );
    let mut state = trace.last().unwrap().after("Send");
    state.queue_epoch = 0;
    state.channel_count = 1;
    trace.push(state);

    let mut state = trace.last().unwrap().after("Cut");
    state.partitioned = true;
    trace.push(state);
    let _lost_batch = batch;
    let mut state = trace.last().unwrap().after("Lose");
    state.channel_count = 0;
    trace.push(state);
    assert_eq!(view.current_epoch(), 0);

    let mut state = trace.last().unwrap().after("Heal");
    state.partitioned = false;
    trace.push(state);
    let request =
        RevocationCatchupRequest::new(PEER, 1, 3, 1_700_000_000_004).expect("catch-up request");
    let response = respond_to_catchup(&request, "oracle-a", &history, 1_700_000_000_005)
        .expect("catch-up response");
    response.validate_response().expect("contiguous response");
    let latest_issued_at = response
        .frames
        .last()
        .expect("catch-up response has a final root")
        .signed_root
        .root
        .issued_at_unix_ms;
    for frame in &response.frames {
        install_verified(&view, frame, &signer).expect("ascending catch-up root installs");
    }
    assert_eq!(view.current_epoch(), 3);
    let mut state = trace.last().unwrap().after("Catchup");
    state.view_epoch = 3;
    state.view_issued_at = latest_issued_at;
    trace.push(state);
    write_trace("partition-heal-catchup", &trace);
}

#[test]
fn wall_clock_staleness_fails_closed() {
    let signer = Ed25519RootSigner::from_signing_key("oracle-a", "generate").expect("test signer");
    let mut oracle = InMemoryRevocationOracle::new();
    let root = revoke(&mut oracle, &signer, "subject-1", 1);
    let freshness = FreshnessConfig::with_offline_grace(2, 0);
    assert!(
        verify_fresh_epoch_root(&root.root, root.root.issued_at_unix_ms + 2, freshness).is_ok()
    );
    assert!(
        verify_fresh_epoch_root(&root.root, root.root.issued_at_unix_ms + 3, freshness).is_err()
    );

    let mut initial = TraceState::initial();
    initial.origin_epoch = root.root.epoch;
    initial.view_epoch = root.root.epoch;
    initial.local_time = root.root.issued_at_unix_ms;
    initial.view_issued_at = root.root.issued_at_unix_ms;
    let mut trace = vec![initial];
    for _ in 0..3 {
        let mut state = trace.last().unwrap().after("Tick");
        state.local_time = state.local_time.saturating_add(1);
        trace.push(state);
    }
    trace.push(trace.last().unwrap().after("EvaluateDeny"));
    write_trace("wall-clock-stale-deny", &trace);
}
