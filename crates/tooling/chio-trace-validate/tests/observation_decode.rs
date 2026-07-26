mod support;

use chio_core_types::crypto::Keypair;
use chio_trace_validate::{
    decode_observations, encode_observations, ObservationBody, ObservationEvent, SignedObservation,
    TraceError, TRACE_OBSERVATION_SCHEMA,
};

fn observer() -> Keypair {
    Keypair::from_seed(&[17; 32])
}

fn authority() -> Keypair {
    Keypair::from_seed(&[23; 32])
}

fn revoke(sequence: u64) -> Result<SignedObservation, TraceError> {
    revoke_in_trace(sequence, sequence, "decode-trace")
}

fn revoke_in_trace(
    sequence: u64,
    trace_length: u64,
    trace_id: &str,
) -> Result<SignedObservation, TraceError> {
    SignedObservation::sign(
        ObservationBody {
            schema: TRACE_OBSERVATION_SCHEMA.to_string(),
            trace_id: trace_id.to_string(),
            trace_length,
            sequence,
            runtime_event_count: trace_length,
            source_sequence: sequence,
            delegation_depth_limit: 4,
            authority_key: authority().public_key(),
            event: ObservationEvent::Revoke {
                capability_id: "cap-1".to_string(),
                epoch: sequence,
            },
        },
        &observer(),
    )
}

#[test]
fn strict_decode_rejects_a_signed_prefix_and_mixed_trace_identity() -> Result<(), TraceError> {
    let prefix = encode_observations(&[revoke_in_trace(1, 2, "trace-a")?])?;
    let truncated = decode_observations(&prefix, &[observer().public_key()])
        .err()
        .ok_or_else(|| TraceError::InvalidInput("signed prefix was accepted".to_string()))?;
    assert!(truncated.to_string().contains("declares 2 events"));

    let mixed = encode_observations(&[
        revoke_in_trace(1, 2, "trace-a")?,
        revoke_in_trace(2, 2, "trace-b")?,
    ])?;
    let mismatch = decode_observations(&mixed, &[observer().public_key()])
        .err()
        .ok_or_else(|| TraceError::InvalidInput("mixed trace was accepted".to_string()))?;
    assert!(mismatch.to_string().contains("disagrees on trace identity"));
    Ok(())
}

#[test]
fn strict_decode_accepts_a_pinned_signed_observation() -> Result<(), TraceError> {
    let encoded = encode_observations(&[revoke(1)?])?;
    let decoded = decode_observations(&encoded, &[observer().public_key()])?;

    assert_eq!(decoded.observations().len(), 1);
    assert_eq!(decoded.observations()[0].body.sequence, 1);
    Ok(())
}

#[test]
fn strict_decode_rejects_noncanonical_json() -> Result<(), TraceError> {
    let mut encoded = encode_observations(&[revoke(1)?])?;
    let newline = encoded
        .pop()
        .ok_or_else(|| TraceError::InvalidInput("encoded trace is empty".to_string()))?;
    assert_eq!(newline, b'\n');
    encoded.extend_from_slice(b" \n");

    let error = decode_observations(&encoded, &[observer().public_key()])
        .err()
        .ok_or_else(|| {
            TraceError::InvalidInput("noncanonical observation was accepted".to_string())
        })?;
    assert!(error.to_string().contains("canonical JSON"));
    Ok(())
}

#[test]
fn strict_decode_rejects_an_untrusted_observer() -> Result<(), TraceError> {
    let encoded = encode_observations(&[revoke(1)?])?;
    let error = decode_observations(&encoded, &[authority().public_key()])
        .err()
        .ok_or_else(|| TraceError::InvalidInput("untrusted observer was accepted".to_string()))?;

    assert!(error.to_string().contains("not trusted"));
    Ok(())
}

#[test]
fn strict_decode_rejects_signature_tampering() -> Result<(), TraceError> {
    let mut observation = revoke(1)?;
    let ObservationEvent::Revoke { epoch, .. } = &mut observation.body.event else {
        return Err(TraceError::InvalidInput(
            "fixture is not a revoke event".to_string(),
        ));
    };
    *epoch = 2;
    let encoded = encode_observations(&[observation])?;
    let error = decode_observations(&encoded, &[observer().public_key()])
        .err()
        .ok_or_else(|| TraceError::InvalidInput("tampered observation was accepted".to_string()))?;

    assert!(error.to_string().contains("signature"));
    Ok(())
}

#[test]
fn strict_decode_rejects_malformed_lines_and_sequence_gaps() -> Result<(), TraceError> {
    let malformed = decode_observations(b"not-json\n", &[observer().public_key()])
        .err()
        .ok_or_else(|| TraceError::InvalidInput("malformed line was accepted".to_string()))?;
    assert!(malformed.to_string().contains("line 1"));

    let encoded = encode_observations(&[revoke(2)?])?;
    let gap = decode_observations(&encoded, &[observer().public_key()])
        .err()
        .ok_or_else(|| TraceError::InvalidInput("sequence gap was accepted".to_string()))?;
    assert!(gap.to_string().contains("expected sequence 1"));
    Ok(())
}

#[test]
fn evaluation_source_presence_matches_the_seen_epoch() -> Result<(), TraceError> {
    let fixture = support::good_trace()?;
    let decoded = decode_observations(&fixture.ndjson, &[fixture.observer_key])?;
    let mut missing_source = decoded.observations()[2].body.clone();
    let ObservationEvent::Evaluate {
        revocation_source_id,
        ..
    } = &mut missing_source.event
    else {
        return Err(TraceError::InvalidInput(
            "fixture event is not an evaluation".to_string(),
        ));
    };
    *revocation_source_id = None;
    let error = SignedObservation::sign(missing_source, &Keypair::from_seed(&[41; 32]))
        .err()
        .ok_or_else(|| TraceError::InvalidInput("missing source was accepted".to_string()))?;
    assert!(error.to_string().contains("present exactly"));

    let mut unexpected_source = decoded.observations()[0].body.clone();
    let ObservationEvent::Evaluate {
        revocation_source_id,
        ..
    } = &mut unexpected_source.event
    else {
        return Err(TraceError::InvalidInput(
            "fixture event is not an evaluation".to_string(),
        ));
    };
    *revocation_source_id = Some("cap-trace-parent".to_string());
    let error = SignedObservation::sign(unexpected_source, &Keypair::from_seed(&[41; 32]))
        .err()
        .ok_or_else(|| TraceError::InvalidInput("unexpected source was accepted".to_string()))?;
    assert!(error.to_string().contains("present exactly"));
    Ok(())
}

#[test]
fn admitted_evaluation_may_retain_a_prior_revocation_source() -> Result<(), TraceError> {
    let fixture = support::bad_trace()?;
    let decoded = decode_observations(&fixture.ndjson, &[fixture.observer_key])?;
    let ObservationEvent::Evaluate {
        seen_epoch,
        revocation_source_id,
        revocation_admitted,
        ..
    } = &decoded.observations()[2].body.event
    else {
        return Err(TraceError::InvalidInput(
            "fixture event is not an evaluation".to_string(),
        ));
    };
    assert!(*revocation_admitted);
    assert!(*seen_epoch > 0);
    assert!(revocation_source_id.is_some());
    Ok(())
}

#[test]
fn evaluation_source_must_belong_to_the_checked_lineage() -> Result<(), TraceError> {
    let fixture = support::good_trace()?;
    let decoded = decode_observations(&fixture.ndjson, &[fixture.observer_key])?;
    let mut body = decoded.observations()[2].body.clone();
    let ObservationEvent::Evaluate {
        revocation_source_id,
        ..
    } = &mut body.event
    else {
        return Err(TraceError::InvalidInput(
            "fixture event is not an evaluation".to_string(),
        ));
    };
    *revocation_source_id = Some("cap-trace-unrelated".to_string());
    let error = SignedObservation::sign(body, &Keypair::from_seed(&[41; 32]))
        .err()
        .ok_or_else(|| TraceError::InvalidInput("unrelated source was accepted".to_string()))?;
    assert!(error.to_string().contains("outside the checked lineage"));
    Ok(())
}

#[test]
fn evaluation_subjects_must_match_depth_and_remain_unique() -> Result<(), TraceError> {
    let fixture = support::good_trace()?;
    let decoded = decode_observations(&fixture.ndjson, &[fixture.observer_key])?;
    let signer = Keypair::from_seed(&[41; 32]);
    let mut wrong_depth = decoded.observations()[2].body.clone();
    let ObservationEvent::Evaluate {
        revocation_subject_ids,
        ..
    } = &mut wrong_depth.event
    else {
        return Err(TraceError::InvalidInput(
            "fixture event is not an evaluation".to_string(),
        ));
    };
    revocation_subject_ids.pop();
    let error = SignedObservation::sign(wrong_depth, &signer)
        .err()
        .ok_or_else(|| TraceError::InvalidInput("short subject list was accepted".to_string()))?;
    assert!(error.to_string().contains("delegation depth"));

    let mut duplicate = decoded.observations()[2].body.clone();
    let ObservationEvent::Evaluate {
        revocation_subject_ids,
        ..
    } = &mut duplicate.event
    else {
        return Err(TraceError::InvalidInput(
            "fixture event is not an evaluation".to_string(),
        ));
    };
    revocation_subject_ids[1] = revocation_subject_ids[0].clone();
    let error = SignedObservation::sign(duplicate, &signer)
        .err()
        .ok_or_else(|| {
            TraceError::InvalidInput("duplicate subject list was accepted".to_string())
        })?;
    assert!(error.to_string().contains("must be unique"));
    Ok(())
}

#[test]
fn strict_decode_rejects_visible_events_out_of_runtime_source_order() -> Result<(), TraceError> {
    let fixture = support::good_trace()?;
    let decoded = decode_observations(&fixture.ndjson, &[fixture.observer_key])?;
    let signer = Keypair::from_seed(&[41; 32]);
    let mut bodies = decoded
        .observations()
        .iter()
        .map(|observation| observation.body.clone())
        .collect::<Vec<_>>();
    bodies[0].source_sequence = 3;
    bodies[1].source_sequence = 2;
    let observations = bodies
        .into_iter()
        .map(|body| SignedObservation::sign(body, &signer))
        .collect::<Result<Vec<_>, _>>()?;
    let encoded = encode_observations(&observations)?;

    let error = decode_observations(&encoded, &[signer.public_key()])
        .err()
        .ok_or_else(|| TraceError::InvalidInput("out-of-order trace was accepted".to_string()))?;
    assert!(error
        .to_string()
        .contains("increasing runtime source order"));
    Ok(())
}

#[test]
fn strict_decode_rejects_an_unbounded_runtime_count_without_allocating_its_range(
) -> Result<(), TraceError> {
    let mut body = revoke(1)?.body;
    body.runtime_event_count = u64::MAX;
    let observation = SignedObservation::sign(body, &observer())?;
    let encoded = encode_observations(&[observation])?;

    let error = decode_observations(&encoded, &[observer().public_key()])
        .err()
        .ok_or_else(|| {
            TraceError::InvalidInput("unbounded runtime count was accepted".to_string())
        })?;
    assert!(error
        .to_string()
        .contains("every runtime callback exactly once"));
    Ok(())
}
