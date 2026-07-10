//! OpenAPI 3.0 / 3.1 spec parser.
//!
//! Parses both YAML and JSON inputs into a simplified intermediate
//! representation that the manifest generator consumes. The parser uses
//! `serde_json::Value` internally and resolves simple `$ref` pointers within
//! the `#/components/schemas` and `#/components/parameters` namespaces.

use serde_json::Value;

use crate::extensions::ChioExtensions;
use crate::{OpenApiError, Result};

/// A parsed OpenAPI specification.
#[derive(Debug, Clone)]
pub struct OpenApiSpec {
    /// The OpenAPI version string (e.g. "3.0.3" or "3.1.0").
    pub openapi_version: String,
    /// API title from `info.title`.
    pub title: String,
    /// API description from `info.description`.
    pub description: String,
    /// API version from `info.version`.
    pub api_version: String,
    /// Parsed path items keyed by route path.
    pub paths: Vec<(String, PathItem)>,
    /// The raw JSON value -- retained for $ref resolution.
    raw: Value,
}

/// A single path entry containing one or more HTTP operations.
#[derive(Debug, Clone)]
pub struct PathItem {
    /// Path-level parameters shared by all operations on this path.
    pub common_parameters: Vec<Parameter>,
    /// Operations defined on this path (method, operation).
    pub operations: Vec<(String, Operation)>,
}

/// A single HTTP operation (e.g. GET /pets).
#[derive(Debug, Clone)]
pub struct Operation {
    /// The `operationId`, if present.
    pub operation_id: Option<String>,
    /// Human-readable summary.
    pub summary: Option<String>,
    /// Longer description.
    pub description: Option<String>,
    /// Tags for grouping.
    pub tags: Vec<String>,
    /// Parameters (path, query, header, cookie).
    pub parameters: Vec<Parameter>,
    /// Request body schema, if any.
    pub request_body_schema: Option<Value>,
    /// Whether requestBody.required is true. Defaults false per OpenAPI.
    pub request_body_required: bool,
    /// Response schemas keyed by status code.
    pub response_schemas: Vec<(String, Option<Value>)>,
    /// Raw operation object for extension extraction.
    pub raw: Value,
}

/// A single parameter definition.
#[derive(Debug, Clone)]
pub struct Parameter {
    /// Parameter name.
    pub name: String,
    /// Where the parameter appears.
    pub location: ParameterLocation,
    /// Whether the parameter is required.
    pub required: bool,
    /// JSON Schema for the parameter value.
    pub schema: Option<Value>,
    /// Human-readable description.
    pub description: Option<String>,
}

/// Where a parameter appears in the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParameterLocation {
    Path,
    Query,
    Header,
    Cookie,
}

impl OpenApiSpec {
    /// Parse an OpenAPI spec from a string, auto-detecting JSON vs YAML.
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim_start();
        let value: Value = if trimmed.starts_with('{') {
            serde_json::from_str(input)?
        } else {
            parse_yaml_value(input)?
        };
        Self::from_value(value)
    }

    /// Parse an OpenAPI spec from a `serde_json::Value`.
    pub fn from_value(value: Value) -> Result<Self> {
        let openapi_version = value
            .get("openapi")
            .and_then(|v| v.as_str())
            .ok_or_else(|| OpenApiError::MissingField("openapi".to_string()))?
            .to_string();

        // Validate version is 3.x
        if !openapi_version.starts_with("3.") {
            return Err(OpenApiError::UnsupportedVersion(openapi_version));
        }

        let info = value
            .get("info")
            .ok_or_else(|| OpenApiError::MissingField("info".to_string()))?;

        let title = info
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("Untitled API")
            .to_string();

        let description = info
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let api_version = info
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0")
            .to_string();

        let paths_obj = value
            .get("paths")
            .and_then(|v| v.as_object())
            .ok_or_else(|| OpenApiError::MissingField("paths".to_string()))?;

        let mut paths = Vec::new();
        for (path, path_value) in paths_obj {
            let path_item = Self::parse_path_item(path_value, &value)?;
            paths.push((path.clone(), path_item));
        }

        // Sort paths for deterministic output.
        paths.sort_by(|a, b| a.0.cmp(&b.0));

        Ok(Self {
            openapi_version,
            title,
            description,
            api_version,
            paths,
            raw: value,
        })
    }

    /// Resolve a `$ref` pointer (only `#/components/...` pointers).
    fn resolve_ref<'a>(root: &'a Value, ref_str: &str) -> Result<&'a Value> {
        if !ref_str.starts_with("#/") {
            return Err(OpenApiError::UnresolvedRef(ref_str.to_string()));
        }

        let pointer = ref_str.replacen('#', "", 1);
        root.pointer(&pointer)
            .ok_or_else(|| OpenApiError::UnresolvedRef(ref_str.to_string()))
    }

    /// If the value is a `$ref` object, resolve it. Otherwise return the
    /// value as-is.
    fn maybe_resolve<'a>(root: &'a Value, value: &'a Value) -> Result<&'a Value> {
        if let Some(ref_str) = value.get("$ref").and_then(|v| v.as_str()) {
            Self::resolve_ref(root, ref_str)
        } else {
            Ok(value)
        }
    }

    fn parse_path_item(path_value: &Value, root: &Value) -> Result<PathItem> {
        let obj = match path_value.as_object() {
            Some(o) => o,
            None => {
                return Ok(PathItem {
                    common_parameters: Vec::new(),
                    operations: Vec::new(),
                })
            }
        };

        // Path-level parameters.
        let common_parameters = if let Some(params) = obj.get("parameters") {
            Self::parse_parameters(params, root)?
        } else {
            Vec::new()
        };

        let methods = ["get", "post", "put", "patch", "delete", "head", "options"];
        let mut operations = Vec::new();

        for method in &methods {
            if let Some(op_value) = obj.get(*method) {
                let operation = Self::parse_operation(op_value, root)?;
                operations.push((method.to_uppercase(), operation));
            }
        }

        Ok(PathItem {
            common_parameters,
            operations,
        })
    }

    fn parse_operation(op_value: &Value, root: &Value) -> Result<Operation> {
        let operation_id = op_value
            .get("operationId")
            .and_then(|v| v.as_str())
            .map(String::from);

        let summary = op_value
            .get("summary")
            .and_then(|v| v.as_str())
            .map(String::from);

        let description = op_value
            .get("description")
            .and_then(|v| v.as_str())
            .map(String::from);

        let tags = op_value
            .get("tags")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let parameters = if let Some(params) = op_value.get("parameters") {
            Self::parse_parameters(params, root)?
        } else {
            Vec::new()
        };

        let request_body_required = Self::request_body_required(op_value, root)?;
        let request_body_schema = Self::extract_request_body_schema(op_value, root)?;

        let response_schemas = Self::extract_response_schemas(op_value, root)?;

        Ok(Operation {
            operation_id,
            summary,
            description,
            tags,
            parameters,
            request_body_schema,
            request_body_required,
            response_schemas,
            raw: op_value.clone(),
        })
    }

    fn parse_parameters(params_value: &Value, root: &Value) -> Result<Vec<Parameter>> {
        let arr = match params_value.as_array() {
            Some(a) => a,
            None => {
                return Err(OpenApiError::InvalidSpec(
                    "parameters must be an array".to_string(),
                ))
            }
        };

        let mut result = Vec::new();
        for param_value in arr {
            let resolved = Self::maybe_resolve(root, param_value)?;
            let param = Self::parse_single_parameter(resolved, root)?;
            result.push(param);
        }
        Ok(result)
    }

    fn parse_single_parameter(value: &Value, root: &Value) -> Result<Parameter> {
        let name = value
            .get("name")
            .and_then(|v| v.as_str())
            .filter(|name| !name.trim().is_empty())
            .ok_or_else(|| OpenApiError::MissingField("parameter.name".to_string()))?
            .to_string();

        let location_value = value
            .get("in")
            .and_then(|v| v.as_str())
            .filter(|location| !location.trim().is_empty())
            .ok_or_else(|| OpenApiError::MissingField("parameter.in".to_string()))?;

        let location = match location_value {
            "path" => ParameterLocation::Path,
            "query" => ParameterLocation::Query,
            "header" => ParameterLocation::Header,
            "cookie" => ParameterLocation::Cookie,
            _ => {
                return Err(OpenApiError::InvalidSpec(format!(
                    "parameter.in has unsupported location `{location_value}`"
                )))
            }
        };

        let required = if let Some(required_value) = value.get("required") {
            required_value.as_bool().ok_or_else(|| {
                OpenApiError::InvalidSpec("parameter.required must be a boolean".to_string())
            })?
        } else {
            // Path parameters are always required per the OpenAPI spec.
            location == ParameterLocation::Path
        };

        let schema = value
            .get("schema")
            .map(|schema| Self::maybe_resolve(root, schema).cloned())
            .transpose()?;

        let description = value
            .get("description")
            .and_then(|v| v.as_str())
            .map(String::from);

        Ok(Parameter {
            name,
            location,
            required,
            schema,
            description,
        })
    }

    fn extract_request_body_schema(op_value: &Value, root: &Value) -> Result<Option<Value>> {
        let body = match op_value.get("requestBody") {
            Some(b) => Self::maybe_resolve(root, b)?,
            None => return Ok(None),
        };

        // Look for application/json content first, then any content type.
        let content = match body.get("content").and_then(|c| c.as_object()) {
            Some(c) => c,
            None => return Ok(None),
        };

        let media = preferred_content_media(content);

        match media {
            Some(m) => {
                if let Some(schema) = m.get("schema") {
                    let resolved = Self::maybe_resolve(root, schema)?;
                    Ok(Some(resolved.clone()))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    fn request_body_required(op_value: &Value, root: &Value) -> Result<bool> {
        let body = match op_value.get("requestBody") {
            Some(body) => Self::maybe_resolve(root, body)?,
            None => return Ok(false),
        };
        Ok(body
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(false))
    }

    fn extract_response_schemas(
        op_value: &Value,
        root: &Value,
    ) -> Result<Vec<(String, Option<Value>)>> {
        let responses = match op_value.get("responses").and_then(|r| r.as_object()) {
            Some(r) => r,
            None => return Ok(Vec::new()),
        };

        let mut result = Vec::new();
        for (status, resp_value) in responses {
            let resolved = Self::maybe_resolve(root, resp_value)?;
            let schema = Self::extract_content_schema(resolved, root)?;
            result.push((status.clone(), schema));
        }
        Ok(result)
    }

    fn extract_content_schema(resp: &Value, root: &Value) -> Result<Option<Value>> {
        let content = match resp.get("content").and_then(|c| c.as_object()) {
            Some(c) => c,
            None => return Ok(None),
        };

        let media = preferred_content_media(content);

        match media {
            Some(m) => {
                if let Some(schema) = m.get("schema") {
                    let resolved = Self::maybe_resolve(root, schema)?;
                    Ok(Some(resolved.clone()))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    /// Access the raw parsed JSON value for extension extraction.
    #[must_use]
    pub fn raw(&self) -> &Value {
        &self.raw
    }

    /// Extract Chio extensions from an operation's raw value.
    #[must_use]
    pub fn extensions_for(operation: &Operation) -> ChioExtensions {
        ChioExtensions::from_operation(&operation.raw)
    }
}

fn parse_yaml_value(input: &str) -> Result<Value> {
    Ok(serde_yaml::from_str(input)?)
}

fn preferred_content_media(content: &serde_json::Map<String, Value>) -> Option<&Value> {
    content
        .get("application/json")
        .or_else(|| content.values().next())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn op_parameter_schema<'a>(operation: &'a Operation, name: &str) -> Option<&'a Value> {
        operation
            .parameters
            .iter()
            .find(|parameter| parameter.name == name)
            .and_then(|parameter| parameter.schema.as_ref())
    }

    fn minimal_spec_json() -> &'static str {
        r##"{
            "openapi": "3.0.3",
            "info": {
                "title": "Test API",
                "version": "1.0.0"
            },
            "paths": {
                "/pets": {
                    "get": {
                        "operationId": "listPets",
                        "summary": "List all pets",
                        "parameters": [
                            {
                                "name": "limit",
                                "in": "query",
                                "required": false,
                                "schema": { "type": "integer" }
                            }
                        ],
                        "responses": {
                            "200": {
                                "description": "A list of pets",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "array",
                                            "items": { "type": "object" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }"##
    }

    fn minimal_spec_yaml() -> &'static str {
        r##"openapi: "3.1.0"
info:
  title: Test API
  version: "1.0.0"
paths:
  /items:
    get:
      operationId: listItems
      summary: List items
      responses:
        "200":
          description: OK
"##
    }

    #[test]
    fn parse_json_spec() {
        let spec = OpenApiSpec::parse(minimal_spec_json()).unwrap();
        assert_eq!(spec.openapi_version, "3.0.3");
        assert_eq!(spec.title, "Test API");
        assert_eq!(spec.api_version, "1.0.0");
        assert_eq!(spec.paths.len(), 1);

        let (path, item) = &spec.paths[0];
        assert_eq!(path, "/pets");
        assert_eq!(item.operations.len(), 1);
        assert_eq!(item.operations[0].0, "GET");

        let op = &item.operations[0].1;
        assert_eq!(op.operation_id.as_deref(), Some("listPets"));
        assert_eq!(op.parameters.len(), 1);
        assert_eq!(op.parameters[0].name, "limit");
        assert_eq!(op.parameters[0].location, ParameterLocation::Query);
        assert!(!op.parameters[0].required);
    }

    #[test]
    fn parse_yaml_spec() {
        let spec = OpenApiSpec::parse(minimal_spec_yaml()).unwrap();
        assert_eq!(spec.openapi_version, "3.1.0");
        assert_eq!(spec.paths.len(), 1);
        let (path, _) = &spec.paths[0];
        assert_eq!(path, "/items");
    }

    #[test]
    fn preferred_content_media_selects_application_json_when_present() {
        let content = serde_json::json!({
            "text/plain": { "schema": { "type": "string" } },
            "application/json": { "schema": { "type": "object" } }
        });
        let media = preferred_content_media(content.as_object().unwrap()).unwrap();

        assert_eq!(
            media
                .get("schema")
                .and_then(|schema| schema.get("type"))
                .and_then(Value::as_str),
            Some("object")
        );
    }

    #[test]
    fn unsupported_version() {
        let input = r##"{"openapi": "2.0", "info": {"title": "T", "version": "1"}, "paths": {}}"##;
        let err = OpenApiSpec::parse(input).unwrap_err();
        assert!(matches!(err, OpenApiError::UnsupportedVersion(_)));
    }

    #[test]
    fn missing_openapi_field() {
        let input = r##"{"info": {"title": "T", "version": "1"}, "paths": {}}"##;
        let err = OpenApiSpec::parse(input).unwrap_err();
        assert!(matches!(err, OpenApiError::MissingField(_)));
    }

    #[test]
    fn ref_resolution() {
        let input = r##"{
            "openapi": "3.0.3",
            "info": { "title": "T", "version": "1" },
            "paths": {
                "/things": {
                    "get": {
                        "operationId": "getThings",
                        "parameters": [
                            { "$ref": "#/components/parameters/LimitParam" }
                        ],
                        "responses": { "200": { "description": "OK" } }
                    }
                }
            },
            "components": {
                "parameters": {
                    "LimitParam": {
                        "name": "limit",
                        "in": "query",
                        "required": false,
                        "schema": { "type": "integer" }
                    }
                }
            }
        }"##;

        let spec = OpenApiSpec::parse(input).unwrap();
        let (_, item) = &spec.paths[0];
        let op = &item.operations[0].1;
        assert_eq!(op.parameters.len(), 1);
        assert_eq!(op.parameters[0].name, "limit");
    }

    #[test]
    fn parameter_schema_ref_is_resolved() {
        let input = r##"{
            "openapi": "3.0.3",
            "info": { "title": "T", "version": "1" },
            "paths": {
                "/things": {
                    "get": {
                        "operationId": "getThings",
                        "parameters": [
                            {
                                "name": "limit",
                                "in": "query",
                                "schema": { "$ref": "#/components/schemas/Limit" }
                            }
                        ],
                        "responses": { "200": { "description": "OK" } }
                    }
                }
            },
            "components": {
                "schemas": {
                    "Limit": { "type": "integer", "minimum": 1 }
                }
            }
        }"##;

        let spec = OpenApiSpec::parse(input).unwrap();
        let (_, item) = &spec.paths[0];
        let schema = op_parameter_schema(&item.operations[0].1, "limit").unwrap();

        assert_eq!(schema.get("type").and_then(Value::as_str), Some("integer"));
        assert_eq!(schema.get("minimum").and_then(Value::as_i64), Some(1));
        assert!(schema.get("$ref").is_none());
    }

    #[test]
    fn request_body_schema_extracted() {
        let input = r##"{
            "openapi": "3.0.3",
            "info": { "title": "T", "version": "1" },
            "paths": {
                "/pets": {
                    "post": {
                        "operationId": "createPet",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "name": { "type": "string" }
                                        }
                                    }
                                }
                            }
                        },
                        "responses": { "201": { "description": "Created" } }
                    }
                }
            }
        }"##;

        let spec = OpenApiSpec::parse(input).unwrap();
        let (_, item) = &spec.paths[0];
        let op = &item.operations[0].1;
        assert!(op.request_body_schema.is_some());
        assert!(!op.request_body_required);
        let schema = op.request_body_schema.as_ref().unwrap();
        assert_eq!(schema.get("type").and_then(|v| v.as_str()), Some("object"));
    }

    #[test]
    fn request_body_required_is_extracted_after_ref_resolution() {
        let input = r##"{
            "openapi": "3.0.3",
            "info": { "title": "T", "version": "1" },
            "paths": {
                "/pets": {
                    "post": {
                        "operationId": "createPet",
                        "requestBody": { "$ref": "#/components/requestBodies/PetBody" },
                        "responses": { "201": { "description": "Created" } }
                    }
                }
            },
            "components": {
                "requestBodies": {
                    "PetBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": { "type": "string" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }"##;

        let spec = OpenApiSpec::parse(input).unwrap();
        let (_, item) = &spec.paths[0];
        let op = &item.operations[0].1;
        assert!(op.request_body_schema.is_some());
        assert!(op.request_body_required);
    }

    #[test]
    fn path_parameters_required_by_default() {
        let input = r##"{
            "openapi": "3.0.3",
            "info": { "title": "T", "version": "1" },
            "paths": {
                "/pets/{petId}": {
                    "get": {
                        "operationId": "getPet",
                        "parameters": [
                            { "name": "petId", "in": "path", "schema": { "type": "string" } }
                        ],
                        "responses": { "200": { "description": "OK" } }
                    }
                }
            }
        }"##;

        let spec = OpenApiSpec::parse(input).unwrap();
        let (_, item) = &spec.paths[0];
        let op = &item.operations[0].1;
        assert!(op.parameters[0].required);
        assert_eq!(op.parameters[0].location, ParameterLocation::Path);
    }

    #[test]
    fn parameter_missing_name_is_rejected() {
        let input = r##"{
            "openapi": "3.0.3",
            "info": { "title": "T", "version": "1" },
            "paths": {
                "/pets": {
                    "get": {
                        "operationId": "listPets",
                        "parameters": [
                            { "in": "query", "schema": { "type": "string" } }
                        ],
                        "responses": { "200": { "description": "OK" } }
                    }
                }
            }
        }"##;

        let err = OpenApiSpec::parse(input).unwrap_err();

        assert!(matches!(err, OpenApiError::MissingField(ref field) if field == "parameter.name"));
    }

    #[test]
    fn parameter_missing_in_is_rejected() {
        let input = r##"{
            "openapi": "3.0.3",
            "info": { "title": "T", "version": "1" },
            "paths": {
                "/pets": {
                    "get": {
                        "operationId": "listPets",
                        "parameters": [
                            { "name": "limit", "schema": { "type": "string" } }
                        ],
                        "responses": { "200": { "description": "OK" } }
                    }
                }
            }
        }"##;

        let err = OpenApiSpec::parse(input).unwrap_err();

        assert!(matches!(err, OpenApiError::MissingField(ref field) if field == "parameter.in"));
    }

    #[test]
    fn non_array_parameters_rejected() {
        let input = r##"{
            "openapi": "3.0.3",
            "info": {"title": "T", "version": "1"},
            "paths": {
                "/pets": {
                    "get": {
                        "parameters": {"name": "limit", "in": "query"},
                        "responses": { "200": { "description": "OK" } }
                    }
                }
            }
        }"##;

        let err = OpenApiSpec::parse(input).unwrap_err();

        assert!(
            matches!(err, OpenApiError::InvalidSpec(ref message) if message.contains("parameters must be an array"))
        );
    }

    #[test]
    fn unsupported_parameter_location_rejected() {
        let input = r##"{
            "openapi": "3.0.3",
            "info": {"title": "T", "version": "1"},
            "paths": {
                "/pets": {
                    "get": {
                        "parameters": [
                            {"name": "petId", "in": "pat", "required": true}
                        ],
                        "responses": { "200": { "description": "OK" } }
                    }
                }
            }
        }"##;

        let err = OpenApiSpec::parse(input).unwrap_err();

        assert!(
            matches!(err, OpenApiError::InvalidSpec(ref message) if message.contains("unsupported location"))
        );
    }

    #[test]
    fn non_boolean_parameter_required_rejected() {
        let input = r##"{
            "openapi": "3.0.3",
            "info": {"title": "T", "version": "1"},
            "paths": {
                "/pets": {
                    "get": {
                        "parameters": [
                            {"name": "limit", "in": "query", "required": "false"}
                        ],
                        "responses": { "200": { "description": "OK" } }
                    }
                }
            }
        }"##;

        let err = OpenApiSpec::parse(input).unwrap_err();

        assert!(
            matches!(err, OpenApiError::InvalidSpec(ref message) if message.contains("parameter.required"))
        );
    }

    #[test]
    fn missing_paths_field() {
        let input = r##"{"openapi": "3.0.3", "info": {"title": "T", "version": "1"}}"##;
        let err = OpenApiSpec::parse(input).unwrap_err();
        assert!(matches!(err, OpenApiError::MissingField(ref f) if f == "paths"));
    }

    #[test]
    fn missing_info_field() {
        let input = r##"{"openapi": "3.0.3", "paths": {}}"##;
        let err = OpenApiSpec::parse(input).unwrap_err();
        assert!(matches!(err, OpenApiError::MissingField(ref f) if f == "info"));
    }

    #[test]
    fn empty_paths_object() {
        let input =
            r##"{"openapi": "3.0.3", "info": {"title": "T", "version": "1"}, "paths": {}}"##;
        let spec = OpenApiSpec::parse(input).unwrap();
        assert!(spec.paths.is_empty());
        assert_eq!(spec.title, "T");
    }

    #[test]
    fn spec_with_no_operations_on_path() {
        let input = r##"{
            "openapi": "3.0.3",
            "info": {"title": "T", "version": "1"},
            "paths": {
                "/empty": {
                    "parameters": [
                        {"name": "id", "in": "query", "schema": {"type": "string"}}
                    ]
                }
            }
        }"##;
        let spec = OpenApiSpec::parse(input).unwrap();
        assert_eq!(spec.paths.len(), 1);
        let (_, item) = &spec.paths[0];
        assert!(item.operations.is_empty());
        assert_eq!(item.common_parameters.len(), 1);
    }

    #[test]
    fn broken_ref_produces_error() {
        let input = r##"{
            "openapi": "3.0.3",
            "info": {"title": "T", "version": "1"},
            "paths": {
                "/things": {
                    "get": {
                        "parameters": [
                            {"$ref": "#/components/parameters/NonExistent"}
                        ],
                        "responses": {"200": {"description": "OK"}}
                    }
                }
            }
        }"##;
        let err = OpenApiSpec::parse(input).unwrap_err();
        assert!(matches!(err, OpenApiError::UnresolvedRef(_)));
    }

    #[test]
    fn external_ref_produces_error() {
        let input = r##"{
            "openapi": "3.0.3",
            "info": {"title": "T", "version": "1"},
            "paths": {
                "/things": {
                    "get": {
                        "parameters": [
                            {"$ref": "https://example.com/params.yaml#/Limit"}
                        ],
                        "responses": {"200": {"description": "OK"}}
                    }
                }
            }
        }"##;
        let err = OpenApiSpec::parse(input).unwrap_err();
        assert!(matches!(err, OpenApiError::UnresolvedRef(_)));
    }

    #[test]
    fn invalid_json_produces_error() {
        let input = r##"{not valid json"##;
        let err = OpenApiSpec::parse(input).unwrap_err();
        assert!(matches!(err, OpenApiError::InvalidJson(_)));
    }

    #[test]
    fn invalid_yaml_produces_error() {
        let input = "openapi: [unclosed\n";
        let err = OpenApiSpec::parse(input).unwrap_err();
        assert!(matches!(err, OpenApiError::InvalidYaml(_)));
    }

    #[test]
    fn invalid_yaml_does_not_invoke_outer_hook() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let input = "openapi: [unclosed\n";
        let hook_called = Arc::new(AtomicBool::new(false));
        let hook_called_clone = Arc::clone(&hook_called);
        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |_| {
            hook_called_clone.store(true, Ordering::SeqCst);
        }));

        let err = OpenApiSpec::parse(input).unwrap_err();
        std::panic::set_hook(previous_hook);

        assert!(matches!(err, OpenApiError::InvalidYaml(_)));
        assert!(!hook_called.load(Ordering::SeqCst));
    }

    #[test]
    fn fuzz_malformed_yaml_rejected_without_panic() {
        let input = "openapi:ets:\n    get:\n      ope: integer\n      responses:\n        \"201\":\n          description:ope: integer\n      responses:A        \"201\":\n  A list of pets\n";

        assert!(OpenApiSpec::parse(input).is_err());
    }

    #[test]
    fn missing_title_defaults_to_untitled() {
        let input = r##"{
            "openapi": "3.0.3",
            "info": {"version": "1"},
            "paths": {}
        }"##;
        let spec = OpenApiSpec::parse(input).unwrap();
        assert_eq!(spec.title, "Untitled API");
    }

    #[test]
    fn missing_version_defaults_to_000() {
        let input = r##"{
            "openapi": "3.0.3",
            "info": {"title": "T"},
            "paths": {}
        }"##;
        let spec = OpenApiSpec::parse(input).unwrap();
        assert_eq!(spec.api_version, "0.0.0");
    }

    #[test]
    fn chio_extensions_extracted() {
        let input = r##"{
            "openapi": "3.0.3",
            "info": { "title": "T", "version": "1" },
            "paths": {
                "/admin/reset": {
                    "post": {
                        "operationId": "resetSystem",
                        "x-chio-sensitivity": "restricted",
                        "x-chio-approval-required": true,
                        "x-chio-side-effects": true,
                        "responses": { "200": { "description": "OK" } }
                    }
                }
            }
        }"##;

        let spec = OpenApiSpec::parse(input).unwrap();
        let (_, item) = &spec.paths[0];
        let op = &item.operations[0].1;
        let ext = OpenApiSpec::extensions_for(op);
        assert_eq!(
            ext.sensitivity,
            Some(crate::extensions::Sensitivity::Restricted)
        );
        assert_eq!(ext.approval_required, Some(true));
        assert_eq!(ext.side_effects, Some(true));
    }
}
