use std::collections::{BTreeMap, BTreeSet};

use chio_egress_contract::HttpEgressContract;
use chio_openapi::{ChioExtensions, OpenApiSpec, Parameter, ParameterLocation};
use serde_json::{json, Value};

use crate::{BridgeError, BridgedResponse, RouteBinding};

#[derive(Debug, Clone)]
pub(crate) struct RouteDispatch {
    binding: RouteBinding,
    query_parameters: Vec<QueryParameter>,
    requires_request_body: bool,
}

impl RouteDispatch {
    fn new(
        binding: RouteBinding,
        query_parameters: Vec<QueryParameter>,
        requires_request_body: bool,
    ) -> Self {
        Self {
            binding,
            query_parameters,
            requires_request_body,
        }
    }

    pub(crate) fn binding(&self) -> &RouteBinding {
        &self.binding
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QueryParameter {
    name: String,
    required: bool,
}

impl QueryParameter {
    fn from_openapi(parameter: &Parameter) -> Self {
        Self {
            name: parameter.name.clone(),
            required: parameter.required,
        }
    }
}

pub(crate) fn build_route_dispatches(
    spec: &OpenApiSpec,
) -> Result<BTreeMap<String, RouteDispatch>, BridgeError> {
    let mut routes = BTreeMap::new();

    for (path, path_item) in &spec.paths {
        for (method_str, operation) in &path_item.operations {
            let extensions = ChioExtensions::from_operation(&operation.raw);
            if !extensions.should_publish() {
                continue;
            }

            let params = merge_parameters(&path_item.common_parameters, &operation.parameters);
            validate_path_template_parameters(path, &params)?;
            let query_parameters = params
                .iter()
                .filter(|param| param.location == ParameterLocation::Query)
                .map(QueryParameter::from_openapi)
                .collect();
            let tool_name = operation
                .operation_id
                .clone()
                .unwrap_or_else(|| format!("{} {}", method_str.to_uppercase(), path));

            routes.insert(
                tool_name,
                RouteDispatch::new(
                    RouteBinding {
                        method: method_str.to_uppercase(),
                        path: path.clone(),
                    },
                    query_parameters,
                    operation.request_body_schema.is_some() && operation.request_body_required,
                ),
            );
        }
    }

    Ok(routes)
}

fn merge_parameters(path_params: &[Parameter], op_params: &[Parameter]) -> Vec<Parameter> {
    let mut merged: Vec<Parameter> = path_params.to_vec();

    for op_param in op_params {
        let existing = merged
            .iter()
            .position(|param| param.name == op_param.name && param.location == op_param.location);
        if let Some(index) = existing {
            merged[index] = op_param.clone();
        } else {
            merged.push(op_param.clone());
        }
    }

    merged
}

fn validate_path_template_parameters(path: &str, params: &[Parameter]) -> Result<(), BridgeError> {
    let declared_path_parameters: BTreeSet<&str> = params
        .iter()
        .filter(|param| param.location == ParameterLocation::Path)
        .map(|param| param.name.as_str())
        .collect();
    let template_path_parameters = route_path_parameter_names(path)?;
    let template_path_parameter_set: BTreeSet<&str> = template_path_parameters
        .iter()
        .map(String::as_str)
        .collect();
    for name in &template_path_parameters {
        if !declared_path_parameters.contains(name.as_str()) {
            return Err(BridgeError::UpstreamError(format!(
                "OpenAPI bridge route path `{path}` contains undeclared path parameter `{name}`"
            )));
        }
    }
    for name in declared_path_parameters {
        if !template_path_parameter_set.contains(name) {
            return Err(BridgeError::UpstreamError(format!(
                "OpenAPI bridge route path `{path}` declares unused path parameter `{name}`"
            )));
        }
    }
    Ok(())
}

fn route_path_parameter_names(template: &str) -> Result<Vec<String>, BridgeError> {
    let mut names = Vec::new();
    let mut rest = template;

    while let Some(open) = rest.find('{') {
        let after_open = &rest[open + 1..];
        let close = after_open.find('}').ok_or_else(|| {
            BridgeError::UpstreamError(format!(
                "OpenAPI bridge route path `{template}` has an unterminated path parameter"
            ))
        })?;
        let name = &after_open[..close];
        if name.is_empty() {
            return Err(BridgeError::UpstreamError(format!(
                "OpenAPI bridge route path `{template}` has an empty path parameter"
            )));
        }
        names.push(name.to_string());
        rest = &after_open[close + 1..];
    }

    if rest.contains('}') {
        return Err(BridgeError::UpstreamError(format!(
            "OpenAPI bridge route path `{template}` has an unmatched path parameter terminator"
        )));
    }

    Ok(names)
}

pub(crate) fn enforce_dispatch_contract<'a>(
    contract: Option<&'a HttpEgressContract>,
    url: &str,
) -> Result<&'a HttpEgressContract, BridgeError> {
    let contract = contract.ok_or_else(|| {
        BridgeError::UpstreamError(
            "OpenAPI bridge dispatcher requires an HttpEgressContract".to_string(),
        )
    })?;
    contract.enforce_url_with_dns(url, 0).map_err(|err| {
        BridgeError::UpstreamError(format!("HttpEgressContract rejects bridge URL: {err}"))
    })?;
    Ok(contract)
}

pub(crate) fn enforce_bridged_response_body(
    contract: &HttpEgressContract,
    response: &BridgedResponse,
) -> Result<(), BridgeError> {
    let body_bytes = response.observed_body_bytes.ok_or_else(|| {
        BridgeError::UpstreamError(
            "OpenAPI bridge dispatcher must provide observed_body_bytes for response-size enforcement"
                .to_string(),
        )
    })?;
    contract.enforce_response_bytes(body_bytes).map_err(|err| {
        BridgeError::UpstreamError(format!("HttpEgressContract rejects bridge response: {err}"))
    })
}

pub(crate) fn enforce_no_redirect_response(response: &BridgedResponse) -> Result<(), BridgeError> {
    if (300..=399).contains(&response.status) {
        return Err(BridgeError::UpstreamError(format!(
            "OpenAPI bridge dispatchers must not follow redirects; returned HTTP redirect status {}",
            response.status
        )));
    }
    Ok(())
}

pub(crate) fn bridged_tool_response(binding: &RouteBinding, response: BridgedResponse) -> Value {
    let text = serde_json::to_string(&response.body).unwrap_or_else(|_| "{}".to_string());
    json!({
        "content": [{
            "type": "text",
            "text": text,
        }],
        "isError": response.is_error,
        "structuredContent": {
            "httpStatus": response.status,
            "method": binding.method,
            "path": binding.path,
            "body": response.body,
        }
    })
}

pub(crate) fn dispatch_url(
    base_url: &str,
    dispatch: &RouteDispatch,
    arguments: &Value,
) -> Result<String, BridgeError> {
    validate_dispatch_arguments(dispatch, arguments)?;
    let path = expand_route_path(&dispatch.binding.path, arguments)?;
    let mut url = join_base_url_and_path(base_url, &path);
    append_query_parameters(&mut url, &dispatch.query_parameters, arguments)?;
    Ok(url)
}

fn validate_dispatch_arguments(
    dispatch: &RouteDispatch,
    arguments: &Value,
) -> Result<(), BridgeError> {
    if dispatch.requires_request_body {
        validate_required_request_body(arguments)?;
    }
    Ok(())
}

fn validate_required_request_body(arguments: &Value) -> Result<(), BridgeError> {
    match arguments.get("body") {
        Some(Value::Null) | None => Err(missing_required_request_body()),
        Some(_) => Ok(()),
    }
}

fn missing_required_request_body() -> BridgeError {
    BridgeError::UpstreamError("OpenAPI bridge missing required request body `body`".to_string())
}

fn join_base_url_and_path(base_url: &str, path: &str) -> String {
    let base = base_url.trim_end_matches('/');
    if path.starts_with('/') {
        format!("{base}{path}")
    } else {
        format!("{base}/{path}")
    }
}

pub(crate) fn expand_route_path(template: &str, arguments: &Value) -> Result<String, BridgeError> {
    let mut expanded = String::with_capacity(template.len());
    let mut rest = template;

    while let Some(open) = rest.find('{') {
        expanded.push_str(&rest[..open]);
        let after_open = &rest[open + 1..];
        let close = after_open.find('}').ok_or_else(|| {
            BridgeError::UpstreamError(format!(
                "OpenAPI bridge route path `{template}` has an unterminated path parameter"
            ))
        })?;
        let name = &after_open[..close];
        if name.is_empty() {
            return Err(BridgeError::UpstreamError(format!(
                "OpenAPI bridge route path `{template}` has an empty path parameter"
            )));
        }
        let value = path_parameter_value(arguments, name)?;
        expanded.push_str(&percent_encode_component(&value));
        rest = &after_open[close + 1..];
    }

    if rest.contains('}') {
        return Err(BridgeError::UpstreamError(format!(
            "OpenAPI bridge route path `{template}` has an unmatched path parameter terminator"
        )));
    }
    expanded.push_str(rest);
    Ok(expanded)
}

fn append_query_parameters(
    url: &mut String,
    query_parameters: &[QueryParameter],
    arguments: &Value,
) -> Result<(), BridgeError> {
    let mut first = !url.contains('?');
    for parameter in query_parameters {
        let Some(value) = arguments.get(&parameter.name) else {
            if parameter.required {
                return Err(missing_required_query_parameter(&parameter.name));
            }
            continue;
        };
        if parameter.required && query_value_is_effectively_missing(value) {
            return Err(missing_required_query_parameter(&parameter.name));
        }
        append_query_value(url, &mut first, &parameter.name, value)?;
    }
    Ok(())
}

fn query_value_is_effectively_missing(value: &Value) -> bool {
    matches!(value, Value::Null) || matches!(value, Value::Array(values) if values.is_empty())
}

fn missing_required_query_parameter(name: &str) -> BridgeError {
    BridgeError::UpstreamError(format!(
        "OpenAPI bridge missing required query parameter `{name}`"
    ))
}

fn append_query_value(
    url: &mut String,
    first: &mut bool,
    name: &str,
    value: &Value,
) -> Result<(), BridgeError> {
    match value {
        Value::String(value) => append_query_pair(url, first, name, value),
        Value::Number(value) => append_query_pair(url, first, name, &value.to_string()),
        Value::Bool(value) => append_query_pair(url, first, name, &value.to_string()),
        Value::Array(values) => {
            for value in values {
                let text = query_scalar_value(name, value)?;
                append_query_pair(url, first, name, &text);
            }
        }
        Value::Null => {}
        _ => {
            return Err(BridgeError::UpstreamError(format!(
                "OpenAPI bridge query parameter `{name}` must be a string, number, boolean, null, or array of scalar values"
            )));
        }
    }
    Ok(())
}

fn query_scalar_value(name: &str, value: &Value) -> Result<String, BridgeError> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Null => Ok(String::new()),
        _ => Err(BridgeError::UpstreamError(format!(
            "OpenAPI bridge query parameter `{name}` array entries must be scalar values"
        ))),
    }
}

fn append_query_pair(url: &mut String, first: &mut bool, name: &str, value: &str) {
    if *first {
        url.push('?');
        *first = false;
    } else {
        url.push('&');
    }
    url.push_str(&percent_encode_component(name));
    url.push('=');
    url.push_str(&percent_encode_component(value));
}

fn path_parameter_value(arguments: &Value, name: &str) -> Result<String, BridgeError> {
    let value = arguments.get(name).ok_or_else(|| {
        BridgeError::UpstreamError(format!("OpenAPI bridge missing path parameter `{name}`"))
    })?;
    let text = match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => value.to_string(),
        _ => {
            return Err(BridgeError::UpstreamError(format!(
                "OpenAPI bridge path parameter `{name}` must be a string, number, or boolean"
            )));
        }
    };
    if text.is_empty() {
        return Err(BridgeError::UpstreamError(format!(
            "OpenAPI bridge path parameter `{name}` must not be empty"
        )));
    }
    if matches!(text.as_str(), "." | "..") {
        return Err(BridgeError::UpstreamError(format!(
            "OpenAPI bridge path parameter `{name}` must not be a dot segment"
        )));
    }
    Ok(text)
}

fn percent_encode_component(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if is_unreserved_byte(*byte) {
            encoded.push(*byte as char);
        } else {
            encoded.push('%');
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    encoded
}

fn is_unreserved_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'
    )
}
