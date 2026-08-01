use std::collections::BTreeSet;

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::XtaskError;

const MAX_STATES: usize = 10_000;
const MAX_NAMES: usize = 1_024;
const MAX_NAME_BYTES: usize = 256;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ItfTrace {
    #[serde(rename = "#meta")]
    pub(crate) metadata: Map<String, Value>,
    #[serde(default)]
    pub(crate) params: Vec<String>,
    pub(crate) vars: Vec<String>,
    pub(crate) states: Vec<Map<String, Value>>,
    #[serde(default, rename = "loop")]
    pub(crate) loop_start: Option<usize>,
}

impl ItfTrace {
    pub(crate) fn parse(bytes: &[u8], source: &str) -> Result<Self, XtaskError> {
        let trace: Self = serde_json::from_slice(bytes)
            .map_err(|error| XtaskError::Json(source.to_string(), error))?;
        trace.validate()?;
        Ok(trace)
    }

    fn validate(&self) -> Result<(), XtaskError> {
        if self.metadata.get("format").and_then(Value::as_str) != Some("ITF") {
            return Err(invalid("trace metadata format must be ITF"));
        }
        validate_names(&self.vars, "vars", false)?;
        validate_names(&self.params, "params", true)?;

        let variables = name_set(&self.vars);
        let parameters = name_set(&self.params);
        if !variables.is_disjoint(&parameters) {
            return Err(invalid("trace vars and params must be disjoint"));
        }

        let var_types = self
            .metadata
            .get("varTypes")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("trace metadata must declare varTypes"))?;
        let typed_names: BTreeSet<&str> = var_types.keys().map(String::as_str).collect();
        if typed_names != variables {
            return Err(invalid("varTypes keys must match vars exactly"));
        }
        if var_types.values().any(|value| !value.is_string()) {
            return Err(invalid("varTypes values must be strings"));
        }

        if self.states.is_empty() {
            return Err(invalid("trace must contain at least one state"));
        }
        if self.states.len() > MAX_STATES {
            return Err(invalid("trace exceeds the state limit"));
        }
        if self
            .loop_start
            .is_some_and(|index| index >= self.states.len())
        {
            return Err(invalid("trace loop index is outside the state array"));
        }

        let initial = &self.states[0];
        for parameter in &self.params {
            if !initial.contains_key(parameter) {
                return Err(invalid(format!(
                    "initial state is missing parameter {parameter}"
                )));
            }
        }

        for (index, state) in self.states.iter().enumerate() {
            validate_state(index, state, &variables, &parameters, initial)?;
        }
        Ok(())
    }
}

fn validate_names(names: &[String], label: &str, allow_empty: bool) -> Result<(), XtaskError> {
    if !allow_empty && names.is_empty() {
        return Err(invalid(format!("trace {label} must not be empty")));
    }
    if names.len() > MAX_NAMES {
        return Err(invalid(format!("trace {label} exceeds the name limit")));
    }
    let mut unique = BTreeSet::new();
    for name in names {
        if name.is_empty() || name.len() > MAX_NAME_BYTES {
            return Err(invalid(format!("trace {label} contains an invalid name")));
        }
        if !unique.insert(name.as_str()) {
            return Err(invalid(format!("trace {label} contains duplicate {name}")));
        }
    }
    Ok(())
}

fn validate_state(
    index: usize,
    state: &Map<String, Value>,
    variables: &BTreeSet<&str>,
    parameters: &BTreeSet<&str>,
    initial: &Map<String, Value>,
) -> Result<(), XtaskError> {
    let recorded_index = state
        .get("#meta")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("index"))
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| invalid(format!("state {index} has no valid metadata index")))?;
    if recorded_index != index {
        return Err(invalid(format!(
            "state {index} records metadata index {recorded_index}"
        )));
    }

    for variable in variables {
        if !state.contains_key(*variable) {
            return Err(invalid(format!(
                "state {index} is missing variable {variable}"
            )));
        }
    }
    for name in state.keys() {
        if name != "#meta"
            && !variables.contains(name.as_str())
            && !parameters.contains(name.as_str())
        {
            return Err(invalid(format!(
                "state {index} contains undeclared name {name}"
            )));
        }
    }
    for parameter in parameters {
        if let Some(value) = state.get(*parameter) {
            if initial.get(*parameter) != Some(value) {
                return Err(invalid(format!(
                    "state {index} changes parameter {parameter}"
                )));
            }
        }
    }
    Ok(())
}

fn name_set(names: &[String]) -> BTreeSet<&str> {
    names.iter().map(String::as_str).collect()
}

fn invalid(message: impl Into<String>) -> XtaskError {
    XtaskError::Validation(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace_with_loop(loop_start: usize) -> Vec<u8> {
        format!(
            r##"{{
                "#meta": {{"format": "ITF", "varTypes": {{"x": "Int"}}}},
                "vars": ["x"],
                "states": [
                    {{"#meta": {{"index": 0}}, "x": {{"#bigint": "0"}}}},
                    {{"#meta": {{"index": 1}}, "x": {{"#bigint": "1"}}}}
                ],
                "loop": {loop_start}
            }}"##
        )
        .into_bytes()
    }

    #[test]
    fn valid_loop_marker_is_retained() {
        match ItfTrace::parse(&trace_with_loop(1), "loop.itf.json") {
            Ok(trace) => assert_eq!(trace.loop_start, Some(1)),
            Err(error) => panic!("valid loop trace failed: {error}"),
        }
    }

    #[test]
    fn out_of_range_loop_marker_is_rejected() {
        assert!(ItfTrace::parse(&trace_with_loop(2), "loop.itf.json").is_err());
    }
}
