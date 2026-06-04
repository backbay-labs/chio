// Unit tests for DeadLetterQueue bounded growth and drop-oldest behavior.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_siem::dlq::{DeadLetterQueue, FailedEvent};

// -- Helper -------------------------------------------------------------------

fn make_failed_event(error: &str) -> FailedEvent {
    FailedEvent {
        event_json: r#"{"id":"test"}"#.to_string(),
        error: error.to_string(),
        failed_at: 1_700_000_000,
        exporter_name: "test-exporter".to_string(),
    }
}

// -- Tests --------------------------------------------------------------------

/// DLQ never exceeds max_capacity; oldest entries are dropped on overflow.
#[test]
fn dlq_bounded_growth() {
    let mut dlq = DeadLetterQueue::new(5);

    for i in 0..10usize {
        dlq.push(make_failed_event(&format!("error-{i}")));
    }

    assert_eq!(dlq.len(), 5, "DLQ must never exceed max_capacity of 5");

    // The 5 entries that remain must be the most recent ones (indices 5-9).
    let remaining = dlq.drain();
    assert_eq!(remaining.len(), 5);
    for (i, ev) in remaining.iter().enumerate() {
        assert_eq!(
            ev.error,
            format!("error-{}", i + 5),
            "remaining entry at position {i} should be error-{}",
            i + 5
        );
    }
}

/// When capacity is exceeded, the oldest entry is dropped and the newest is retained.
#[test]
fn dlq_drop_oldest_on_overflow() {
    let mut dlq = DeadLetterQueue::new(3);

    dlq.push(make_failed_event("error-0"));
    dlq.push(make_failed_event("error-1"));
    dlq.push(make_failed_event("error-2"));
    // This push overflows: error-0 should be dropped.
    dlq.push(make_failed_event("error-3"));

    let drained = dlq.drain();
    assert_eq!(drained.len(), 3, "DLQ should hold exactly 3 entries");

    let errors: Vec<&str> = drained.iter().map(|ev| ev.error.as_str()).collect();
    assert!(
        !errors.contains(&"error-0"),
        "error-0 (oldest) must have been dropped"
    );
    assert!(errors.contains(&"error-1"), "error-1 must be retained");
    assert!(errors.contains(&"error-2"), "error-2 must be retained");
    assert!(
        errors.contains(&"error-3"),
        "error-3 (newest) must be retained"
    );
}

/// Empty queue operations work correctly: is_empty, len, and drain all return valid results.
#[test]
fn dlq_empty_operations() {
    let mut dlq = DeadLetterQueue::new(100);

    assert!(dlq.is_empty(), "freshly created DLQ must be empty");
    assert_eq!(dlq.len(), 0, "freshly created DLQ must have len 0");

    let drained = dlq.drain();
    assert!(
        drained.is_empty(),
        "draining an empty DLQ must return an empty vec"
    );

    // After drain, the queue should still be empty.
    assert!(
        dlq.is_empty(),
        "DLQ must still be empty after draining nothing"
    );
}

/// Zero-capacity queues drop every incoming event and never retain entries.
#[test]
fn dlq_zero_capacity_drops_incoming() {
    let mut dlq = DeadLetterQueue::new(0);

    dlq.push(make_failed_event("error-0"));

    assert!(dlq.is_empty());
    assert_eq!(dlq.len(), 0);
    assert!(dlq.drain().is_empty());
}
