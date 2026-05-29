// Emergency kill-switch tests.
//
// Included by `src/kernel/tests.rs`, which already imported `super::*`
// and all helper items from `tests/all.rs`. The helpers used here
// (`make_config`, `make_scope`, `make_grant`, `make_keypair`,
// `make_capability`, `make_request`, `EchoServer`) are all defined in
// `tests/all.rs` and visible via the surrounding `tests` module.

// `thread` and `ChioScope` are already in scope from `tests/all.rs` via
// the surrounding `tests.rs` `include!`s. Only pull in items that are not
// already imported.
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::time::Duration;

fn kernel_with_echo() -> (ChioKernel, Keypair, ChioScope) {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));
    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    (kernel, agent_kp, scope)
}

#[test]
fn emergency_stop_forces_deny_on_next_evaluate() {
    let (kernel, agent_kp, scope) = kernel_with_echo();
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    // Baseline: with the kill switch disengaged, a valid capability + guard
    // pipeline should allow.
    let request = make_request("req-allow", &cap, "read_file", "srv-a");
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);

    // Engage the kill switch. Every subsequent evaluation must deny.
    kernel.emergency_stop("operator halted").unwrap();
    assert!(kernel.is_emergency_stopped());

    let denied = make_request("req-deny", &cap, "read_file", "srv-a");
    let response = kernel.evaluate_tool_call_blocking(&denied).unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.as_deref().unwrap_or("");
    assert_eq!(reason, EMERGENCY_STOP_DENY_REASON);
}

#[test]
fn emergency_stop_reason_wins_before_federation_negotiation() {
    let (kernel, agent_kp, scope) = kernel_with_echo();
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    kernel.emergency_stop("operator halted").unwrap();

    let mut denied = make_request("req-stopped-fed", &cap, "read_file", "srv-a");
    denied.federated_origin_kernel_id = Some("kernel.unpinned".to_string());
    let response = kernel.evaluate_tool_call_blocking(&denied).unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(response.reason.as_deref(), Some(EMERGENCY_STOP_DENY_REASON));
}

#[test]
fn emergency_status_exposes_since_and_reason() {
    let (kernel, _, _) = kernel_with_echo();
    assert!(!kernel.is_emergency_stopped());
    assert!(kernel.emergency_stopped_since().is_none());
    assert!(kernel.emergency_stop_reason().is_none());

    kernel.emergency_stop("compromised agent detected").unwrap();
    assert!(kernel.is_emergency_stopped());
    assert!(kernel.emergency_stopped_since().is_some());
    assert_eq!(
        kernel.emergency_stop_reason().as_deref(),
        Some("compromised agent detected")
    );

    kernel.emergency_resume().unwrap();
    assert!(!kernel.is_emergency_stopped());
    assert!(kernel.emergency_stopped_since().is_none());
    assert!(kernel.emergency_stop_reason().is_none());
}

#[test]
fn emergency_stop_then_resume_restores_allow_path() {
    let (kernel, agent_kp, scope) = kernel_with_echo();
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    kernel.emergency_stop("drill").unwrap();
    let denied =
        kernel.evaluate_tool_call_blocking(&make_request("req-1", &cap, "read_file", "srv-a"));
    assert_eq!(denied.unwrap().verdict, Verdict::Deny);

    kernel.emergency_resume().unwrap();

    let response = kernel
        .evaluate_tool_call_blocking(&make_request("req-2", &cap, "read_file", "srv-a"))
        .unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
}

#[test]
fn concurrent_evaluate_and_emergency_stop_is_race_free() {
    // Spawn many evaluator threads and flip the kill switch mid-flight.
    // The kernel must not panic and at least one evaluation must observe
    // the kill switch engaged. All observed denials must use the stable
    // emergency deny reason.
    let (kernel, agent_kp, scope) = kernel_with_echo();
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let shared = Arc::new(kernel);

    let deny_count = Arc::new(AtomicUsize::new(0));
    let allow_count = Arc::new(AtomicUsize::new(0));

    let mut workers = Vec::new();
    for i in 0..16 {
        let kernel = Arc::clone(&shared);
        let cap = cap.clone();
        let deny = Arc::clone(&deny_count);
        let allow = Arc::clone(&allow_count);
        workers.push(thread::spawn(move || {
            // Give the main thread a chance to fire the stop before we start
            // issuing requests, but spread some across pre/post.
            if i % 2 == 0 {
                thread::sleep(Duration::from_millis(1));
            }
            for j in 0..8 {
                let request_id = format!("race-{i}-{j}");
                let request = make_request(&request_id, &cap, "read_file", "srv-a");
                match kernel.evaluate_tool_call_blocking(&request) {
                    Ok(response) => match response.verdict {
                        Verdict::Allow => {
                            allow.fetch_add(1, AtomicOrdering::SeqCst);
                        }
                        Verdict::Deny => {
                            deny.fetch_add(1, AtomicOrdering::SeqCst);
                            assert_eq!(
                                response.reason.as_deref(),
                                Some(EMERGENCY_STOP_DENY_REASON),
                                "only emergency stop should cause a deny in this test"
                            );
                        }
                        Verdict::PendingApproval => {
                            panic!("unexpected pending approval in emergency test");
                        }
                    },
                    Err(error) => panic!("evaluate_tool_call_blocking errored: {error}"),
                }
            }
        }));
    }

    // Engage the kill switch after workers have spawned.
    thread::sleep(Duration::from_millis(2));
    shared.emergency_stop("concurrent drill").unwrap();

    for worker in workers {
        worker.join().expect("worker thread panicked");
    }

    assert!(
        deny_count.load(AtomicOrdering::SeqCst) > 0,
        "expected at least one evaluation to observe the emergency stop"
    );
    // Allow count may legitimately be zero if stop flipped before any worker
    // ran. The invariant we care about is "no panic, and at least one deny".
    let _ = allow_count.load(AtomicOrdering::SeqCst);
}

#[test]
fn emergency_stop_receipt_records_deny_decision() {
    // The early-return path must still produce a signed deny receipt so
    // auditors see the kill-switch denial alongside every other denial.
    let (kernel, agent_kp, scope) = kernel_with_echo();
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    kernel.emergency_stop("audit trail").unwrap();
    let request = make_request("req-receipt", &cap, "read_file", "srv-a");
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        response.receipt.verify_signature().unwrap(),
        "emergency stop deny receipt must verify"
    );
    match response.receipt.decision.clone() {
        Some(Decision::Deny { reason, .. }) => assert_eq!(reason, EMERGENCY_STOP_DENY_REASON),
        other => panic!("expected deny decision, got {other:?}"),
    }
}
