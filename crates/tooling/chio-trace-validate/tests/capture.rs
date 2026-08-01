mod support;

use chio_core_types::crypto::{Keypair, PublicKey};
use chio_core_types::receipt::{body::ChioReceipt, decision::Decision};
use chio_kernel::{RuntimeTraceEvent, RuntimeTraceObserver};
use chio_trace_validate::{
    decode_observations, ObservationEvent, RuntimeTraceRecorder, TraceError,
};

fn deny_receipt(authority: &Keypair) -> Result<ChioReceipt, TraceError> {
    support::receipt(
        authority,
        "cap-trace-child",
        Decision::Deny {
            reason: "capability revoked".to_string(),
            guard: "revocation_store".to_string(),
        },
        3,
        false,
    )
}

fn allow_receipt(authority: &Keypair) -> Result<ChioReceipt, TraceError> {
    support::receipt(authority, "cap-trace-child", Decision::Allow, 3, false)
}

fn admitted_child(source_sequence: u64) -> RuntimeTraceEvent {
    RuntimeTraceEvent::RevocationAdmission {
        source_sequence,
        request_id: "trace-request-3".to_string(),
        capability_id: "cap-trace-child".to_string(),
        revocation_subject_ids: vec![
            "cap-trace-child".to_string(),
            "cap-trace-parent".to_string(),
        ],
        revoked_capability_id: None,
        delegation_depth: 1,
        delegation_depth_limit: 4,
        admitted: true,
    }
}

fn recorder(authority: &Keypair) -> Result<(RuntimeTraceRecorder, PublicKey), TraceError> {
    let observer = Keypair::from_seed(&[41; 32]);
    let observer_key = observer.public_key();
    Ok((
        RuntimeTraceRecorder::new(authority.public_key(), observer, "callback-order-test")?,
        observer_key,
    ))
}

#[test]
fn recorder_orders_callbacks_by_kernel_source_sequence() -> Result<(), TraceError> {
    let authority = Keypair::from_seed(&[43; 32]);
    let (recorder, observer_key) = recorder(&authority)?;

    recorder.observe(RuntimeTraceEvent::RevocationAdmission {
        source_sequence: 2,
        request_id: "trace-request-3".to_string(),
        capability_id: "cap-trace-child".to_string(),
        revocation_subject_ids: vec![
            "cap-trace-child".to_string(),
            "cap-trace-parent".to_string(),
        ],
        revoked_capability_id: Some("cap-trace-parent".to_string()),
        delegation_depth: 1,
        delegation_depth_limit: 4,
        admitted: false,
    });
    recorder.observe(RuntimeTraceEvent::ReceiptAppended {
        source_sequence: 3,
        receipt: Box::new(deny_receipt(&authority)?),
    });
    recorder.observe(RuntimeTraceEvent::RevocationCommitted {
        source_sequence: 1,
        capability_id: "cap-trace-parent".to_string(),
        newly_revoked: true,
        delegation_depth_limit: 4,
    });

    let encoded = recorder.finish()?;
    let decoded = decode_observations(&encoded, &[observer_key])?;
    let ObservationEvent::Revoke { capability_id, .. } = &decoded.observations()[0].body.event
    else {
        return Err(TraceError::InvalidInput(
            "first observation is not a revocation".to_string(),
        ));
    };
    assert_eq!(capability_id, "cap-trace-parent");
    let ObservationEvent::Evaluate {
        receipt,
        seen_epoch,
        revocation_source_id,
        admission_sequence,
        ..
    } = &decoded.observations()[1].body.event
    else {
        return Err(TraceError::InvalidInput(
            "second observation is not an evaluation".to_string(),
        ));
    };
    assert_eq!(receipt.capability_id, "cap-trace-child");
    assert_eq!(*seen_epoch, 1);
    assert_eq!(revocation_source_id.as_deref(), Some("cap-trace-parent"));
    assert_eq!(*admission_sequence, 2);
    Ok(())
}

#[test]
fn recorder_rejects_a_denial_without_an_exact_source() -> Result<(), TraceError> {
    let authority = Keypair::from_seed(&[43; 32]);
    let (recorder, _) = recorder(&authority)?;
    recorder.observe(RuntimeTraceEvent::RevocationAdmission {
        source_sequence: 1,
        request_id: "trace-request-3".to_string(),
        capability_id: "cap-trace-child".to_string(),
        revocation_subject_ids: vec![
            "cap-trace-child".to_string(),
            "cap-trace-parent".to_string(),
        ],
        revoked_capability_id: None,
        delegation_depth: 1,
        delegation_depth_limit: 4,
        admitted: false,
    });
    recorder.observe(RuntimeTraceEvent::ReceiptAppended {
        source_sequence: 2,
        receipt: Box::new(deny_receipt(&authority)?),
    });

    let error = recorder
        .finish()
        .err()
        .ok_or_else(|| TraceError::InvalidInput("source-free denial was accepted".to_string()))?;
    assert!(error.to_string().contains("no exact revocation source"));
    Ok(())
}

#[test]
fn recorder_rejects_an_unobserved_revocation_source() -> Result<(), TraceError> {
    let authority = Keypair::from_seed(&[43; 32]);
    let (recorder, _) = recorder(&authority)?;
    recorder.observe(RuntimeTraceEvent::RevocationAdmission {
        source_sequence: 1,
        request_id: "trace-request-3".to_string(),
        capability_id: "cap-trace-child".to_string(),
        revocation_subject_ids: vec![
            "cap-trace-child".to_string(),
            "cap-trace-parent".to_string(),
        ],
        revoked_capability_id: Some("cap-trace-parent".to_string()),
        delegation_depth: 1,
        delegation_depth_limit: 4,
        admitted: false,
    });
    recorder.observe(RuntimeTraceEvent::ReceiptAppended {
        source_sequence: 2,
        receipt: Box::new(deny_receipt(&authority)?),
    });

    let error = recorder.finish().err().ok_or_else(|| {
        TraceError::InvalidInput("unobserved revocation source was accepted".to_string())
    })?;
    assert!(error.to_string().contains("missing revoke callback"));
    Ok(())
}

#[test]
fn recorder_rejects_a_revocation_source_after_admission() -> Result<(), TraceError> {
    let authority = Keypair::from_seed(&[43; 32]);
    let (recorder, _) = recorder(&authority)?;
    recorder.observe(RuntimeTraceEvent::RevocationAdmission {
        source_sequence: 1,
        request_id: "trace-request-3".to_string(),
        capability_id: "cap-trace-child".to_string(),
        revocation_subject_ids: vec![
            "cap-trace-child".to_string(),
            "cap-trace-parent".to_string(),
        ],
        revoked_capability_id: Some("cap-trace-parent".to_string()),
        delegation_depth: 1,
        delegation_depth_limit: 4,
        admitted: false,
    });
    recorder.observe(RuntimeTraceEvent::ReceiptAppended {
        source_sequence: 2,
        receipt: Box::new(deny_receipt(&authority)?),
    });
    recorder.observe(RuntimeTraceEvent::RevocationCommitted {
        source_sequence: 3,
        capability_id: "cap-trace-parent".to_string(),
        newly_revoked: true,
        delegation_depth_limit: 4,
    });

    let error = recorder.finish().err().ok_or_else(|| {
        TraceError::InvalidInput("future revocation source was accepted".to_string())
    })?;
    assert!(error.to_string().contains("does not precede admission"));
    Ok(())
}

#[test]
fn recorder_rejects_a_direct_revocation_between_admission_and_append() -> Result<(), TraceError> {
    let authority = Keypair::from_seed(&[43; 32]);
    let (recorder, _) = recorder(&authority)?;
    recorder.observe(admitted_child(1));
    recorder.observe(RuntimeTraceEvent::RevocationCommitted {
        source_sequence: 2,
        capability_id: "cap-trace-child".to_string(),
        newly_revoked: true,
        delegation_depth_limit: 4,
    });
    recorder.observe(RuntimeTraceEvent::ReceiptAppended {
        source_sequence: 3,
        receipt: Box::new(allow_receipt(&authority)?),
    });

    let error = recorder.finish().err().ok_or_else(|| {
        TraceError::InvalidInput("direct interval revocation was accepted".to_string())
    })?;
    assert!(error
        .to_string()
        .contains("between admission and receipt append"));
    Ok(())
}

#[test]
fn recorder_rejects_an_ancestor_revocation_between_admission_and_append() -> Result<(), TraceError>
{
    let authority = Keypair::from_seed(&[43; 32]);
    let (recorder, _) = recorder(&authority)?;
    recorder.observe(admitted_child(1));
    recorder.observe(RuntimeTraceEvent::RevocationCommitted {
        source_sequence: 2,
        capability_id: "cap-trace-parent".to_string(),
        newly_revoked: true,
        delegation_depth_limit: 4,
    });
    recorder.observe(RuntimeTraceEvent::ReceiptAppended {
        source_sequence: 3,
        receipt: Box::new(allow_receipt(&authority)?),
    });

    let error = recorder.finish().err().ok_or_else(|| {
        TraceError::InvalidInput("ancestor interval revocation was accepted".to_string())
    })?;
    assert!(error
        .to_string()
        .contains("between admission and receipt append"));
    Ok(())
}

#[test]
fn recorder_accepts_an_unrelated_revocation_between_admission_and_append() -> Result<(), TraceError>
{
    let authority = Keypair::from_seed(&[43; 32]);
    let (recorder, observer_key) = recorder(&authority)?;
    recorder.observe(admitted_child(1));
    recorder.observe(RuntimeTraceEvent::RevocationCommitted {
        source_sequence: 2,
        capability_id: "cap-trace-unrelated".to_string(),
        newly_revoked: true,
        delegation_depth_limit: 4,
    });
    recorder.observe(RuntimeTraceEvent::ReceiptAppended {
        source_sequence: 3,
        receipt: Box::new(allow_receipt(&authority)?),
    });

    let encoded = recorder.finish()?;
    let decoded = decode_observations(&encoded, &[observer_key])?;
    assert_eq!(decoded.observations().len(), 2);
    Ok(())
}

#[test]
fn recorder_rejects_an_unbounded_source_sequence_without_allocating_its_range(
) -> Result<(), TraceError> {
    let authority = Keypair::from_seed(&[43; 32]);
    let (recorder, _) = recorder(&authority)?;
    recorder.observe(RuntimeTraceEvent::RevocationCommitted {
        source_sequence: u64::MAX,
        capability_id: "cap-trace-child".to_string(),
        newly_revoked: true,
        delegation_depth_limit: 4,
    });

    let error = recorder.finish().err().ok_or_else(|| {
        TraceError::InvalidInput("unbounded source sequence was accepted".to_string())
    })?;
    assert!(error.to_string().contains("every callback exactly once"));
    Ok(())
}
