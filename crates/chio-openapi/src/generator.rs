//! Chio `ToolManifest` generator from parsed OpenAPI specs.
//!
//! Each route + method pair becomes a `ToolDefinition` with an input schema
//! derived from path, query, and body parameters.

use chio_core_types::manifest::{ToolAnnotations, ToolDefinition};
use chio_http_core::HttpMethod;
use serde_json::Value;

use crate::extensions::ChioExtensions;
use crate::parser::{OpenApiSpec, Operation, Parameter, ParameterLocation};
use crate::policy::DefaultPolicy;

/// Configuration for the manifest generator.
#[derive(Debug, Clone)]
pub struct GeneratorConfig {
    /// Server ID to use in the generated manifest body. The manifest itself is
    /// not signed here (the caller signs it with a keypair), so we only
    /// produce `ToolDefinition` values.
    pub server_id: String,
    /// Whether to include response schemas as output_schema on each tool.
    pub include_output_schemas: bool,
    /// Whether to skip operations that have `x-chio-publish: false`.
    pub respect_publish_flag: bool,
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        Self {
            server_id: "openapi-server".to_string(),
            include_output_schemas: true,
            respect_publish_flag: true,
        }
    }
}

/// Generates Chio `ToolDefinition` values from a parsed OpenAPI spec.
pub struct ManifestGenerator {
    config: GeneratorConfig,
}

impl ManifestGenerator {
    /// Create a new generator with the given configuration.
    #[must_use]
    pub fn new(config: GeneratorConfig) -> Self {
        Self { config }
    }

    /// Generate `ToolDefinition` values for all operations in the spec.
    #[must_use]
    pub fn generate_tools(&self, spec: &OpenApiSpec) -> Vec<ToolDefinition> {
        let mut tools = Vec::new();

        for (path, path_item) in &spec.paths {
            for (method_str, operation) in &path_item.operations {
                let extensions = ChioExtensions::from_operation(&operation.raw);

                // Skip operations that opt out of publishing.
                if self.config.respect_publish_flag && !extensions.should_publish() {
                    continue;
                }

                let method = match parse_method(method_str) {
                    Some(m) => m,
                    None => continue,
                };

                // Merge path-level and operation-level parameters.
                let all_params =
                    merge_parameters(&path_item.common_parameters, &operation.parameters);

                let tool =
                    self.build_tool_definition(path, method, operation, &all_params, &extensions);
                tools.push(tool);
            }
        }

        tools
    }

    fn build_tool_definition(
        &self,
        path: &str,
        method: HttpMethod,
        operation: &Operation,
        params: &[Parameter],
        extensions: &ChioExtensions,
    ) -> ToolDefinition {
        let name = operation
            .operation_id
            .clone()
            .unwrap_or_else(|| format!("{} {}", method, path));

        let description = operation
            .summary
            .clone()
            .or_else(|| operation.description.clone())
            .unwrap_or_else(|| format!("{} {}", method, path));

        let input_schema = build_input_schema(
            params,
            &operation.request_body_schema,
            operation.request_body_required,
        );

        let output_schema = if self.config.include_output_schemas {
            build_output_schema(&operation.response_schemas)
        } else {
            None
        };

        let has_side_effects = DefaultPolicy::has_side_effects(method, extensions);

        let annotations = ToolAnnotations {
            read_only: !has_side_effects,
            destructive: method == HttpMethod::Delete,
            idempotent: matches!(
                method,
                HttpMethod::Get | HttpMethod::Put | HttpMethod::Delete
            ),
            requires_approval: extensions.approval_required.unwrap_or(false),
            estimated_duration_ms: None,
        };

        ToolDefinition {
            name,
            description,
            input_schema,
            output_schema,
            pricing: None,
            annotations,
        }
    }
}

/// Parse an uppercase method string into an `HttpMethod`.
fn parse_method(s: &str) -> Option<HttpMethod> {
    match s {
        "GET" => Some(HttpMethod::Get),
        "POST" => Some(HttpMethod::Post),
        "PUT" => Some(HttpMethod::Put),
        "PATCH" => Some(HttpMethod::Patch),
        "DELETE" => Some(HttpMethod::Delete),
        "HEAD" => Some(HttpMethod::Head),
        "OPTIONS" => Some(HttpMethod::Options),
        _ => None,
    }
}

/// Merge path-level and operation-level parameters. Operation-level parameters
/// override path-level parameters with the same name and location.
fn merge_parameters(path_params: &[Parameter], op_params: &[Parameter]) -> Vec<Parameter> {
    let mut merged: Vec<Parameter> = path_params.to_vec();

    for op_param in op_params {
        // Replace any path-level param with the same name+location.
        let existing = merged
            .iter()
            .position(|p| p.name == op_param.name && p.location == op_param.location);
        if let Some(idx) = existing {
            merged[idx] = op_param.clone();
        } else {
            merged.push(op_param.clone());
        }
    }

    merged
}

/// Build a JSON Schema object from path/query parameters and an optional
/// request body schema.
fn build_input_schema(
    params: &[Parameter],
    request_body: &Option<Value>,
    request_body_required: bool,
) -> Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();

    // Add path and query parameters as top-level properties.
    for param in params {
        // Skip header and cookie params from the tool input schema.
        if param.location == ParameterLocation::Header
            || param.location == ParameterLocation::Cookie
        {
            continue;
        }

        let schema = param
            .schema
            .clone()
            .unwrap_or_else(|| serde_json::json!({"type": "string"}));

        let mut prop = if let Value::Object(m) = schema {
            m
        } else {
            let mut m = serde_json::Map::new();
            m.insert("type".to_string(), serde_json::json!("string"));
            m
        };

        if let Some(desc) = &param.description {
            prop.insert("description".to_string(), Value::String(desc.clone()));
        }

        properties.insert(param.name.clone(), Value::Object(prop));

        if param.required {
            required.push(Value::String(param.name.clone()));
        }
    }

    // If there is a request body, add it as a "body" property.
    if let Some(body_schema) = request_body {
        properties.insert("body".to_string(), body_schema.clone());
        if request_body_required {
            required.push(Value::String("body".to_string()));
        }
    }

    let mut schema = serde_json::Map::new();
    schema.insert("type".to_string(), Value::String("object".to_string()));
    schema.insert("properties".to_string(), Value::Object(properties));
    if !required.is_empty() {
        schema.insert("required".to_string(), Value::Array(required));
    }

    Value::Object(schema)
}

/// Build an output schema from the response schemas. Uses the first successful
/// (2xx) response schema found.
fn build_output_schema(responses: &[(String, Option<Value>)]) -> Option<Value> {
    for preferred in &["200", "201"] {
        if let Some(schema) = responses.iter().find_map(|(code, schema)| {
            if code == preferred {
                schema.as_ref()
            } else {
                None
            }
        }) {
            return Some(schema.clone());
        }
    }

    responses
        .iter()
        .find_map(|(code, schema)| code.starts_with('2').then_some(schema.as_ref()).flatten())
        .cloned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::parser::OpenApiSpec;

    fn petstore_spec() -> &'static str {
        r##"{
            "openapi": "3.0.3",
            "info": {
                "title": "Petstore",
                "description": "A sample API for pets",
                "version": "1.0.0"
            },
            "paths": {
                "/pets": {
                    "get": {
                        "operationId": "listPets",
                        "summary": "List all pets",
                        "tags": ["pets"],
                        "parameters": [
                            {
                                "name": "limit",
                                "in": "query",
                                "required": false,
                                "schema": { "type": "integer", "format": "int32" },
                                "description": "How many items to return"
                            }
                        ],
                        "responses": {
                            "200": {
                                "description": "A list of pets",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "array",
                                            "items": { "$ref": "#/components/schemas/Pet" }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "post": {
                        "operationId": "createPet",
                        "summary": "Create a pet",
                        "tags": ["pets"],
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "name": { "type": "string" },
                                            "tag": { "type": "string" }
                                        },
                                        "required": ["name"]
                                    }
                                }
                            }
                        },
                        "responses": {
                            "201": { "description": "Pet created" }
                        }
                    }
                },
                "/pets/{petId}": {
                    "get": {
                        "operationId": "showPetById",
                        "summary": "Info for a specific pet",
                        "tags": ["pets"],
                        "parameters": [
                            {
                                "name": "petId",
                                "in": "path",
                                "required": true,
                                "schema": { "type": "string" },
                                "description": "The id of the pet to retrieve"
                            }
                        ],
                        "responses": {
                            "200": {
                                "description": "Expected response to a valid request",
                                "content": {
                                    "application/json": {
                                        "schema": { "$ref": "#/components/schemas/Pet" }
                                    }
                                }
                            }
                        }
                    },
                    "delete": {
                        "operationId": "deletePet",
                        "summary": "Delete a pet",
                        "tags": ["pets"],
                        "parameters": [
                            {
                                "name": "petId",
                                "in": "path",
                                "required": true,
                                "schema": { "type": "string" }
                            }
                        ],
                        "responses": {
                            "204": { "description": "Pet deleted" }
                        }
                    }
                }
            },
            "components": {
                "schemas": {
                    "Pet": {
                        "type": "object",
                        "properties": {
                            "id": { "type": "integer", "format": "int64" },
                            "name": { "type": "string" },
                            "tag": { "type": "string" }
                        },
                        "required": ["id", "name"]
                    }
                }
            }
        }"##
    }

    #[test]
    fn petstore_generates_four_tools() {
        let spec = OpenApiSpec::parse(petstore_spec()).unwrap();
        let gen = ManifestGenerator::new(GeneratorConfig::default());
        let tools = gen.generate_tools(&spec);

        assert_eq!(tools.len(), 4);

        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"listPets"));
        assert!(names.contains(&"createPet"));
        assert!(names.contains(&"showPetById"));
        assert!(names.contains(&"deletePet"));
    }

    #[test]
    fn get_operations_are_read_only() {
        let spec = OpenApiSpec::parse(petstore_spec()).unwrap();
        let gen = ManifestGenerator::new(GeneratorConfig::default());
        let tools = gen.generate_tools(&spec);

        let list_pets = tools.iter().find(|t| t.name == "listPets").unwrap();
        assert!(list_pets.annotations.read_only);
        assert!(!list_pets.annotations.destructive);
        assert!(list_pets.annotations.idempotent);
    }

    #[test]
    fn post_operations_have_side_effects() {
        let spec = OpenApiSpec::parse(petstore_spec()).unwrap();
        let gen = ManifestGenerator::new(GeneratorConfig::default());
        let tools = gen.generate_tools(&spec);

        let create_pet = tools.iter().find(|t| t.name == "createPet").unwrap();
        assert!(!create_pet.annotations.read_only);
        assert!(!create_pet.annotations.destructive);
        assert!(!create_pet.annotations.idempotent);
    }

    #[test]
    fn delete_operations_are_destructive() {
        let spec = OpenApiSpec::parse(petstore_spec()).unwrap();
        let gen = ManifestGenerator::new(GeneratorConfig::default());
        let tools = gen.generate_tools(&spec);

        let delete_pet = tools.iter().find(|t| t.name == "deletePet").unwrap();
        assert!(!delete_pet.annotations.read_only);
        assert!(delete_pet.annotations.destructive);
        assert!(delete_pet.annotations.idempotent);
    }

    #[test]
    fn input_schema_includes_query_params() {
        let spec = OpenApiSpec::parse(petstore_spec()).unwrap();
        let gen = ManifestGenerator::new(GeneratorConfig::default());
        let tools = gen.generate_tools(&spec);

        let list_pets = tools.iter().find(|t| t.name == "listPets").unwrap();
        let props = list_pets
            .input_schema
            .get("properties")
            .and_then(|p| p.as_object())
            .unwrap();
        assert!(props.contains_key("limit"));
    }

    #[test]
    fn input_schema_includes_path_params_as_required() {
        let spec = OpenApiSpec::parse(petstore_spec()).unwrap();
        let gen = ManifestGenerator::new(GeneratorConfig::default());
        let tools = gen.generate_tools(&spec);

        let show_pet = tools.iter().find(|t| t.name == "showPetById").unwrap();
        let required = show_pet
            .input_schema
            .get("required")
            .and_then(|r| r.as_array())
            .unwrap();
        let required_names: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
        assert!(required_names.contains(&"petId"));
    }

    #[test]
    fn input_schema_includes_request_body() {
        let spec = OpenApiSpec::parse(petstore_spec()).unwrap();
        let gen = ManifestGenerator::new(GeneratorConfig::default());
        let tools = gen.generate_tools(&spec);

        let create_pet = tools.iter().find(|t| t.name == "createPet").unwrap();
        let props = create_pet
            .input_schema
            .get("properties")
            .and_then(|p| p.as_object())
            .unwrap();
        assert!(props.contains_key("body"));
        let required = create_pet
            .input_schema
            .get("required")
            .and_then(Value::as_array)
            .unwrap();
        let required_names: Vec<&str> = required.iter().filter_map(Value::as_str).collect();
        assert!(required_names.contains(&"body"));
    }

    #[test]
    fn input_schema_keeps_optional_request_body_optional() {
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
                                    "schema": { "type": "object" }
                                }
                            }
                        },
                        "responses": { "201": { "description": "Created" } }
                    }
                }
            }
        }"##;

        let spec = OpenApiSpec::parse(input).unwrap();
        let gen = ManifestGenerator::new(GeneratorConfig::default());
        let tools = gen.generate_tools(&spec);

        let create_pet = tools.iter().find(|tool| tool.name == "createPet").unwrap();
        let props = create_pet
            .input_schema
            .get("properties")
            .and_then(Value::as_object)
            .unwrap();
        assert!(props.contains_key("body"));
        let required_names: Vec<&str> = create_pet
            .input_schema
            .get("required")
            .and_then(Value::as_array)
            .map(|required| required.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        assert!(!required_names.contains(&"body"));
    }

    #[test]
    fn output_schema_from_200_response() {
        let spec = OpenApiSpec::parse(petstore_spec()).unwrap();
        let gen = ManifestGenerator::new(GeneratorConfig::default());
        let tools = gen.generate_tools(&spec);

        let list_pets = tools.iter().find(|t| t.name == "listPets").unwrap();
        assert!(list_pets.output_schema.is_some());
        let output = list_pets.output_schema.as_ref().unwrap();
        assert_eq!(output.get("type").and_then(|v| v.as_str()), Some("array"));
    }

    #[test]
    fn fallback_name_when_no_operation_id() {
        let input = r##"{
            "openapi": "3.0.3",
            "info": { "title": "T", "version": "1" },
            "paths": {
                "/health": {
                    "get": {
                        "responses": { "200": { "description": "OK" } }
                    }
                }
            }
        }"##;

        let spec = OpenApiSpec::parse(input).unwrap();
        let gen = ManifestGenerator::new(GeneratorConfig::default());
        let tools = gen.generate_tools(&spec);

        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "GET /health");
    }

    #[test]
    fn x_chio_publish_false_excludes_operation() {
        let input = r##"{
            "openapi": "3.0.3",
            "info": { "title": "T", "version": "1" },
            "paths": {
                "/internal": {
                    "get": {
                        "operationId": "internalEndpoint",
                        "x-chio-publish": false,
                        "responses": { "200": { "description": "OK" } }
                    }
                },
                "/public": {
                    "get": {
                        "operationId": "publicEndpoint",
                        "responses": { "200": { "description": "OK" } }
                    }
                }
            }
        }"##;

        let spec = OpenApiSpec::parse(input).unwrap();
        let gen = ManifestGenerator::new(GeneratorConfig::default());
        let tools = gen.generate_tools(&spec);

        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "publicEndpoint");
    }

    #[test]
    fn approval_required_annotation() {
        let input = r##"{
            "openapi": "3.0.3",
            "info": { "title": "T", "version": "1" },
            "paths": {
                "/danger": {
                    "post": {
                        "operationId": "dangerousAction",
                        "x-chio-approval-required": true,
                        "responses": { "200": { "description": "OK" } }
                    }
                }
            }
        }"##;

        let spec = OpenApiSpec::parse(input).unwrap();
        let gen = ManifestGenerator::new(GeneratorConfig::default());
        let tools = gen.generate_tools(&spec);

        assert_eq!(tools.len(), 1);
        assert!(tools[0].annotations.requires_approval);
    }

    #[test]
    fn path_level_parameters_merged() {
        let input = r##"{
            "openapi": "3.0.3",
            "info": { "title": "T", "version": "1" },
            "paths": {
                "/orgs/{orgId}/members": {
                    "parameters": [
                        { "name": "orgId", "in": "path", "required": true, "schema": { "type": "string" } }
                    ],
                    "get": {
                        "operationId": "listMembers",
                        "parameters": [
                            { "name": "page", "in": "query", "schema": { "type": "integer" } }
                        ],
                        "responses": { "200": { "description": "OK" } }
                    }
                }
            }
        }"##;

        let spec = OpenApiSpec::parse(input).unwrap();
        let gen = ManifestGenerator::new(GeneratorConfig::default());
        let tools = gen.generate_tools(&spec);

        let tool = &tools[0];
        let props = tool
            .input_schema
            .get("properties")
            .and_then(|p| p.as_object())
            .unwrap();
        assert!(props.contains_key("orgId"));
        assert!(props.contains_key("page"));
    }
}
