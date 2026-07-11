use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::{ProjectedAction, ProjectedEvent, TraceError};

#[derive(Debug)]
struct ModelState {
    lifecycle: Vec<Vec<String>>,
    depth: Vec<Vec<u32>>,
    epochs: Vec<Vec<u64>>,
    receipts: Vec<Vec<Value>>,
    pending: Vec<Value>,
    clock: u64,
}

pub(crate) fn build_itf(
    events: &[ProjectedEvent],
    authority_count: usize,
    capability_count: usize,
    depth_max: u32,
    log_sha256: &str,
) -> Result<(Vec<u8>, Vec<Value>), TraceError> {
    let mut model = ModelState {
        lifecycle: vec![vec!["active".to_string(); capability_count]; authority_count],
        depth: vec![vec![0; capability_count]; authority_count],
        epochs: vec![vec![0; capability_count]; authority_count],
        receipts: vec![Vec::new(); authority_count],
        pending: Vec::new(),
        clock: 1,
    };
    let mut states = vec![state_value(0, "init", 0, None, &model)?];

    for event in events {
        let authority = model_index(event.authority, authority_count, "authority")?;
        let capability = model_index(event.capability, capability_count, "capability")?;
        if let ProjectedAction::Evaluate {
            admission_sequence,
            delegation_depth,
            ..
        } = &event.action
        {
            while model.depth[authority][capability] < *delegation_depth {
                if model.lifecycle[authority][capability] == "revoked" {
                    break;
                }
                model.depth[authority][capability] = model.depth[authority][capability]
                    .checked_add(1)
                    .ok_or_else(|| {
                        TraceError::InvalidInput("delegation depth overflow".to_string())
                    })?;
                model.lifecycle[authority][capability] = "attenuated".to_string();
                states.push(state_value(
                    states.len(),
                    "attenuate",
                    *admission_sequence,
                    Some(event),
                    &model,
                )?);
            }
        }

        match &event.action {
            ProjectedAction::Revoke { epoch } => {
                model.lifecycle[authority][capability] = "revoked".to_string();
                model.epochs[authority][capability] = *epoch;
                for target in 0..authority_count {
                    if target == authority {
                        continue;
                    }
                    model.pending.push(json!({
                        "cap": event.capability,
                        "epoch": epoch,
                        "from": event.authority,
                        "to": target + 1,
                    }));
                }
            }
            ProjectedAction::Evaluate {
                verdict,
                receipt_time,
                seen_epoch,
                ..
            } => {
                if *seen_epoch > model.epochs[authority][capability] {
                    let position = model.pending.iter().position(|message| {
                        message.get("to").and_then(Value::as_u64)
                            == u64::try_from(authority + 1).ok()
                            && message.get("cap").and_then(Value::as_u64)
                                == Some(u64::from(event.capability))
                            && message.get("epoch").and_then(Value::as_u64) == Some(*seen_epoch)
                    });
                    if let Some(position) = position {
                        model.pending.remove(position);
                        model.lifecycle[authority][capability] = "revoked".to_string();
                        model.epochs[authority][capability] = *seen_epoch;
                        states.push(state_value(
                            states.len(),
                            "propagate",
                            event.sequence,
                            None,
                            &model,
                        )?);
                    }
                }
                model.receipts[authority].push(json!({
                    "cap": event.capability,
                    "seen_epoch": seen_epoch,
                    "t": receipt_time,
                    "verdict": verdict,
                }));
            }
        }
        model.clock = event
            .sequence
            .checked_add(1)
            .ok_or_else(|| TraceError::InvalidInput("trace clock overflow".to_string()))?;
        states.push(state_value(
            states.len(),
            match &event.action {
                ProjectedAction::Revoke { .. } => "revoke",
                ProjectedAction::Evaluate { .. } => "evaluate",
            },
            event.source_sequence,
            Some(event),
            &model,
        )?);
    }

    let mut root = BTreeMap::new();
    root.insert(
        "#meta",
        json!({
            "format": "ITF",
            "format-description": "https://apalache-mc.org/docs/adr/015adr-trace.html",
            "log_sha256": log_sha256,
            "source": "chio-trace-validate 0.1",
            "spec": "RevocationPropagation",
            "bounds": {
                "CAPS": capability_count,
                "DEPTH_MAX": depth_max,
                "PROCS": authority_count,
            },
            "varTypes": {
                "clock": "Int",
                "depth": "(Int -> (Int -> Int))",
                "pending": "Set({ from: Int, to: Int, cap: Int, epoch: Int })",
                "receipt_log": "(Int -> Seq({ cap: Int, verdict: Str, t: Int, seen_epoch: Int }))",
                "rev_epoch": "(Int -> (Int -> Int))",
                "state": "(Int -> (Int -> Str))",
            },
        }),
    );
    root.insert("params", json!([]));
    root.insert("states", Value::Array(states.clone()));
    root.insert(
        "vars",
        json!([
            "clock",
            "depth",
            "pending",
            "receipt_log",
            "rev_epoch",
            "state"
        ]),
    );
    let mut output = chio_core_types::canonical::canonical_json_bytes(&root)?;
    output.push(b'\n');
    Ok((output, states))
}

fn state_value(
    index: usize,
    action: &str,
    source_sequence: u64,
    event: Option<&ProjectedEvent>,
    model: &ModelState,
) -> Result<Value, TraceError> {
    let mut metadata = serde_json::Map::from_iter([
        ("action".to_string(), json!(action)),
        ("index".to_string(), json!(index)),
        ("sourceSequence".to_string(), json!(source_sequence)),
    ]);
    if let Some(event) = event {
        metadata.insert("authority".to_string(), json!(event.authority));
        metadata.insert("capability".to_string(), json!(event.capability));
        metadata.insert("visibleSequence".to_string(), json!(event.sequence));
        match &event.action {
            ProjectedAction::Revoke { epoch } => {
                metadata.insert("epoch".to_string(), json!(epoch));
            }
            ProjectedAction::Evaluate {
                admission_sequence,
                receipt_time,
                seen_epoch,
                verdict,
                ..
            } => {
                metadata.insert("seenEpoch".to_string(), json!(seen_epoch));
                metadata.insert("receiptTime".to_string(), json!(receipt_time));
                metadata.insert("admissionSequence".to_string(), json!(admission_sequence));
                metadata.insert("verdict".to_string(), json!(verdict));
            }
        }
    }
    Ok(json!({
        "#meta": metadata,
        "clock": model.clock,
        "depth": nested_map(&model.depth)?,
        "pending": {"#set": &model.pending},
        "receipt_log": sequence_map(&model.receipts)?,
        "rev_epoch": nested_map(&model.epochs)?,
        "state": nested_map(&model.lifecycle)?,
    }))
}

fn nested_map<T: SerializeValue>(rows: &[Vec<T>]) -> Result<Value, TraceError> {
    let entries = rows
        .iter()
        .enumerate()
        .map(|(row_index, row)| {
            let row_key = u64::try_from(row_index + 1)
                .map_err(|_| TraceError::InvalidInput("map row index overflow".to_string()))?;
            let columns = row
                .iter()
                .enumerate()
                .map(|(column_index, value)| {
                    let column_key = u64::try_from(column_index + 1).map_err(|_| {
                        TraceError::InvalidInput("map column index overflow".to_string())
                    })?;
                    Ok(json!([column_key, value.to_value()]))
                })
                .collect::<Result<Vec<_>, TraceError>>()?;
            Ok(json!([row_key, {"#map": columns}]))
        })
        .collect::<Result<Vec<_>, TraceError>>()?;
    Ok(json!({"#map": entries}))
}

fn sequence_map(rows: &[Vec<Value>]) -> Result<Value, TraceError> {
    let entries = rows
        .iter()
        .enumerate()
        .map(|(index, values)| {
            let key = u64::try_from(index + 1)
                .map_err(|_| TraceError::InvalidInput("sequence map index overflow".to_string()))?;
            Ok(json!([key, values]))
        })
        .collect::<Result<Vec<_>, TraceError>>()?;
    Ok(json!({"#map": entries}))
}

fn model_index(value: u32, bound: usize, label: &str) -> Result<usize, TraceError> {
    let index = usize::try_from(value.saturating_sub(1))
        .map_err(|_| TraceError::InvalidInput(format!("{label} index overflow")))?;
    if value == 0 || index >= bound {
        return Err(TraceError::InvalidInput(format!(
            "{label} index {value} is outside the projected bound {bound}"
        )));
    }
    Ok(index)
}

trait SerializeValue {
    fn to_value(&self) -> Value;
}

impl SerializeValue for u32 {
    fn to_value(&self) -> Value {
        json!(self)
    }
}

impl SerializeValue for u64 {
    fn to_value(&self) -> Value {
        json!(self)
    }
}

impl SerializeValue for String {
    fn to_value(&self) -> Value {
        json!(self)
    }
}
