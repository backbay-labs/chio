use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use chio_core::{
    PromptDefinition, PromptResult, ResourceContent, ResourceDefinition, ResourceTemplateDefinition,
};
use chio_kernel::{
    KernelError, NestedFlowBridge, PromptProvider, ResourceProvider, ToolServerConnection,
    ToolServerEvent,
};
use chio_manifest::{
    validate_manifest, LatencyHint, ManifestError, PricingModel, ToolDefinition, ToolManifest,
    ToolPricing,
};
use serde_json::Value;

type NativeToolHandler = dyn for<'a> Fn(Value, Option<&'a mut dyn NestedFlowBridge>) -> Result<Value, KernelError>
    + Send
    + Sync;
type NativeResourceHandler =
    dyn Fn(&str) -> Result<Option<Vec<ResourceContent>>, KernelError> + Send + Sync;
type NativePromptHandler = dyn Fn(Value) -> Result<PromptResult, KernelError> + Send + Sync;

struct NativeToolRegistration {
    definition: ToolDefinition,
    handler: Arc<NativeToolHandler>,
}

struct NativeResourceRegistration {
    definition: ResourceDefinition,
    handler: Arc<NativeResourceHandler>,
}

struct NativePromptRegistration {
    definition: PromptDefinition,
    handler: Arc<NativePromptHandler>,
}

#[derive(Debug, Clone)]
pub struct NativeTool {
    definition: ToolDefinition,
}

impl NativeTool {
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        input_schema: Value,
    ) -> Self {
        Self {
            definition: ToolDefinition {
                name: name.into(),
                description: description.into(),
                input_schema,
                output_schema: None,
                pricing: None,
                has_side_effects: true,
                latency_hint: None,
            },
        }
    }

    pub fn output_schema(mut self, output_schema: Value) -> Self {
        self.definition.output_schema = Some(output_schema);
        self
    }

    pub fn read_only(mut self) -> Self {
        self.definition.has_side_effects = false;
        self
    }

    pub fn pricing(mut self, pricing: ToolPricing) -> Self {
        self.definition.pricing = Some(pricing);
        self
    }

    pub fn flat_price(mut self, units: u64, currency: impl Into<String>) -> Self {
        self.definition.pricing = Some(ToolPricing {
            pricing_model: PricingModel::Flat,
            base_price: Some(chio_core::MonetaryAmount {
                units,
                currency: currency.into(),
            }),
            unit_price: None,
            billing_unit: None,
        });
        self
    }

    pub fn per_invocation_price(mut self, units: u64, currency: impl Into<String>) -> Self {
        self.definition.pricing = Some(ToolPricing {
            pricing_model: PricingModel::PerInvocation,
            base_price: None,
            unit_price: Some(chio_core::MonetaryAmount {
                units,
                currency: currency.into(),
            }),
            billing_unit: Some("invocation".to_string()),
        });
        self
    }

    pub fn per_unit_price(
        mut self,
        units: u64,
        currency: impl Into<String>,
        billing_unit: impl Into<String>,
    ) -> Self {
        self.definition.pricing = Some(ToolPricing {
            pricing_model: PricingModel::PerUnit,
            base_price: None,
            unit_price: Some(chio_core::MonetaryAmount {
                units,
                currency: currency.into(),
            }),
            billing_unit: Some(billing_unit.into()),
        });
        self
    }

    pub fn hybrid_price(
        mut self,
        base_units: u64,
        unit_units: u64,
        currency: impl Into<String>,
        billing_unit: impl Into<String>,
    ) -> Self {
        let currency = currency.into();
        self.definition.pricing = Some(ToolPricing {
            pricing_model: PricingModel::Hybrid,
            base_price: Some(chio_core::MonetaryAmount {
                units: base_units,
                currency: currency.clone(),
            }),
            unit_price: Some(chio_core::MonetaryAmount {
                units: unit_units,
                currency,
            }),
            billing_unit: Some(billing_unit.into()),
        });
        self
    }

    pub fn latency_hint(mut self, latency_hint: LatencyHint) -> Self {
        self.definition.latency_hint = Some(latency_hint);
        self
    }

    fn into_definition(self) -> ToolDefinition {
        self.definition
    }
}

#[derive(Debug, Clone)]
pub struct NativeResource {
    definition: ResourceDefinition,
}

impl NativeResource {
    pub fn new(uri: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            definition: ResourceDefinition {
                uri: uri.into(),
                name: name.into(),
                title: None,
                description: None,
                mime_type: None,
                size: None,
                annotations: None,
                icons: None,
            },
        }
    }

    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.definition.description = Some(description.into());
        self
    }

    pub fn mime_type(mut self, mime_type: impl Into<String>) -> Self {
        self.definition.mime_type = Some(mime_type.into());
        self
    }

    fn into_definition(self) -> ResourceDefinition {
        self.definition
    }
}

#[derive(Debug, Clone)]
pub struct NativePrompt {
    definition: PromptDefinition,
}

impl NativePrompt {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            definition: PromptDefinition {
                name: name.into(),
                title: None,
                description: None,
                arguments: vec![],
                icons: None,
            },
        }
    }

    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.definition.description = Some(description.into());
        self
    }

    pub fn arguments(mut self, arguments: Vec<chio_core::PromptArgument>) -> Self {
        self.definition.arguments = arguments;
        self
    }

    fn into_definition(self) -> PromptDefinition {
        self.definition
    }
}

pub struct NativeChioServiceBuilder {
    server_id: String,
    server_name: String,
    server_version: String,
    server_description: Option<String>,
    public_key: String,
    tools: Vec<NativeToolRegistration>,
    resources: Vec<NativeResourceRegistration>,
    prompts: Vec<NativePromptRegistration>,
}

impl NativeChioServiceBuilder {
    pub fn new(server_id: impl Into<String>, public_key: impl Into<String>) -> Self {
        let server_id = server_id.into();
        Self {
            server_name: server_id.clone(),
            server_id,
            server_version: "0.1.0".to_string(),
            server_description: None,
            public_key: public_key.into(),
            tools: vec![],
            resources: vec![],
            prompts: vec![],
        }
    }

    pub fn server_name(mut self, server_name: impl Into<String>) -> Self {
        self.server_name = server_name.into();
        self
    }

    pub fn server_version(mut self, server_version: impl Into<String>) -> Self {
        self.server_version = server_version.into();
        self
    }

    pub fn server_description(mut self, server_description: impl Into<String>) -> Self {
        self.server_description = Some(server_description.into());
        self
    }

    pub fn tool<F>(mut self, tool: NativeTool, handler: F) -> Self
    where
        F: Fn(Value) -> Result<Value, KernelError> + Send + Sync + 'static,
    {
        self.tools.push(NativeToolRegistration {
            definition: tool.into_definition(),
            handler: Arc::new(move |arguments, _nested_flow_bridge| handler(arguments)),
        });
        self
    }

    pub fn tool_with_nested_flow<F>(mut self, tool: NativeTool, handler: F) -> Self
    where
        F: for<'a> Fn(Value, Option<&'a mut dyn NestedFlowBridge>) -> Result<Value, KernelError>
            + Send
            + Sync
            + 'static,
    {
        self.tools.push(NativeToolRegistration {
            definition: tool.into_definition(),
            handler: Arc::new(handler),
        });
        self
    }

    pub fn resource<F>(mut self, resource: NativeResource, handler: F) -> Self
    where
        F: Fn(&str) -> Result<Option<Vec<ResourceContent>>, KernelError> + Send + Sync + 'static,
    {
        self.resources.push(NativeResourceRegistration {
            definition: resource.into_definition(),
            handler: Arc::new(handler),
        });
        self
    }

    pub fn static_resource(self, resource: NativeResource, contents: Vec<ResourceContent>) -> Self {
        self.resource(resource, move |_uri| Ok(Some(contents.clone())))
    }

    pub fn prompt<F>(mut self, prompt: NativePrompt, handler: F) -> Self
    where
        F: Fn(Value) -> Result<PromptResult, KernelError> + Send + Sync + 'static,
    {
        self.prompts.push(NativePromptRegistration {
            definition: prompt.into_definition(),
            handler: Arc::new(handler),
        });
        self
    }

    pub fn static_prompt(self, prompt: NativePrompt, result: PromptResult) -> Self {
        self.prompt(prompt, move |_arguments| Ok(result.clone()))
    }

    pub fn build(self) -> Result<NativeChioService, ManifestError> {
        let manifest = ToolManifest {
            schema: "chio.manifest.v1".into(),
            server_id: self.server_id,
            name: self.server_name,
            description: self.server_description,
            version: self.server_version,
            tools: self
                .tools
                .iter()
                .map(|registration| registration.definition.clone())
                .collect(),
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: self.public_key,
        };
        validate_manifest(&manifest)?;

        Ok(NativeChioService {
            manifest,
            tools: Arc::new(
                self.tools
                    .into_iter()
                    .map(|registration| (registration.definition.name.clone(), registration))
                    .collect(),
            ),
            resources: Arc::new(self.resources),
            prompts: Arc::new(
                self.prompts
                    .into_iter()
                    .map(|registration| (registration.definition.name.clone(), registration))
                    .collect(),
            ),
            emitted_events: Arc::new(Mutex::new(vec![])),
        })
    }
}

#[derive(Clone)]
pub struct NativeChioService {
    manifest: ToolManifest,
    tools: Arc<BTreeMap<String, NativeToolRegistration>>,
    resources: Arc<Vec<NativeResourceRegistration>>,
    prompts: Arc<BTreeMap<String, NativePromptRegistration>>,
    emitted_events: Arc<Mutex<Vec<ToolServerEvent>>>,
}

impl NativeChioService {
    pub fn manifest(&self) -> &ToolManifest {
        &self.manifest
    }

    pub fn manifest_clone(&self) -> ToolManifest {
        self.manifest.clone()
    }

    pub fn emit_event(&self, event: ToolServerEvent) {
        if let Ok(mut guard) = self.emitted_events.lock() {
            guard.push(event);
        }
    }
}

impl ToolServerConnection for NativeChioService {
    fn server_id(&self) -> &str {
        &self.manifest.server_id
    }

    fn tool_names(&self) -> Vec<String> {
        self.manifest
            .tools
            .iter()
            .map(|tool| tool.name.clone())
            .collect()
    }

    fn invoke(
        &self,
        tool_name: &str,
        arguments: Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        let registration = self
            .tools
            .get(tool_name)
            .ok_or_else(|| KernelError::ToolNotRegistered(tool_name.to_string()))?;
        (registration.handler)(arguments, nested_flow_bridge)
    }

    fn drain_events(&self) -> Result<Vec<ToolServerEvent>, KernelError> {
        let mut guard = self.emitted_events.lock().map_err(|error| {
            KernelError::ToolServerError(format!("native service event queue poisoned: {error}"))
        })?;
        Ok(guard.drain(..).collect())
    }
}

impl ResourceProvider for NativeChioService {
    fn list_resources(&self) -> Vec<ResourceDefinition> {
        self.resources
            .iter()
            .map(|registration| registration.definition.clone())
            .collect()
    }

    fn list_resource_templates(&self) -> Vec<ResourceTemplateDefinition> {
        vec![]
    }

    fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, KernelError> {
        let Some(registration) = self
            .resources
            .iter()
            .find(|registration| registration.definition.uri == uri)
        else {
            return Ok(None);
        };
        (registration.handler)(uri)
    }
}

impl PromptProvider for NativeChioService {
    fn list_prompts(&self) -> Vec<PromptDefinition> {
        self.prompts
            .values()
            .map(|registration| registration.definition.clone())
            .collect()
    }

    fn get_prompt(
        &self,
        name: &str,
        arguments: Value,
    ) -> Result<Option<PromptResult>, KernelError> {
        let Some(registration) = self.prompts.get(name) else {
            return Ok(None);
        };
        (registration.handler)(arguments).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::{PromptArgument, PromptMessage};
    use chio_kernel::ToolServerEvent;

    #[test]
    fn native_service_builder_registers_tools_resources_and_prompts() {
        let service = NativeChioServiceBuilder::new(
            "srv-native",
            "7b0f6f631f6e66207140ead0b6b2e9418916d2c4b3c7448ba5f7ed27f5c8d038",
        )
        .server_name("Native Service")
        .server_version("0.2.0")
        .server_description("Example native service")
        .tool(
            NativeTool::new(
                "greet",
                "Return a greeting",
                serde_json::json!({
                    "type": "object",
                    "properties": { "name": { "type": "string" } },
                }),
            )
            .output_schema(serde_json::json!({
                "type": "object",
                "properties": { "greeting": { "type": "string" } }
            }))
            .read_only()
            .per_invocation_price(25, "USD")
            .latency_hint(LatencyHint::Instant),
            |arguments| {
                let name = arguments
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("friend");
                Ok(serde_json::json!({ "greeting": format!("Hello, {name}!") }))
            },
        )
        .static_resource(
            NativeResource::new("memory://docs/greeting", "Greeting doc")
                .description("Greeting documentation")
                .mime_type("text/plain"),
            vec![ResourceContent {
                uri: "memory://docs/greeting".to_string(),
                mime_type: Some("text/plain".to_string()),
                text: Some("Use greet with a name field.".to_string()),
                blob: None,
                annotations: None,
            }],
        )
        .static_prompt(
            NativePrompt::new("greet_prompt")
                .description("A prompt that prepares a greeting")
                .arguments(vec![PromptArgument {
                    name: "name".to_string(),
                    title: None,
                    description: Some("Name to greet".to_string()),
                    required: Some(true),
                }]),
            PromptResult {
                description: Some("Greeter prompt".to_string()),
                messages: vec![PromptMessage {
                    role: "user".to_string(),
                    content: serde_json::json!({
                        "type": "text",
                        "text": "Please greet Ada politely."
                    }),
                }],
            },
        )
        .build()
        .expect("build native service");

        assert_eq!(service.server_id(), "srv-native");
        assert_eq!(service.tool_names(), vec!["greet".to_string()]);
        assert_eq!(service.manifest().name, "Native Service");
        assert_eq!(service.manifest().version, "0.2.0");
        assert_eq!(service.manifest().tools.len(), 1);
        assert!(!service.manifest().tools[0].has_side_effects);
        assert_eq!(
            service.manifest().tools[0].pricing.as_ref().map(|pricing| (
                pricing.pricing_model,
                pricing.unit_price.as_ref().map(|amount| amount.units),
                pricing.billing_unit.as_deref(),
            )),
            Some((PricingModel::PerInvocation, Some(25), Some("invocation")))
        );

        let result = service
            .invoke("greet", serde_json::json!({ "name": "Ada" }), None)
            .expect("invoke greet");
        assert_eq!(result["greeting"], "Hello, Ada!");

        let resources = service.list_resources();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].uri, "memory://docs/greeting");

        let resource = service
            .read_resource("memory://docs/greeting")
            .expect("read resource")
            .expect("resource content");
        assert_eq!(resource.len(), 1);
        assert_eq!(
            resource[0].text.as_deref(),
            Some("Use greet with a name field.")
        );

        let prompts = service.list_prompts();
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].name, "greet_prompt");

        let prompt = service
            .get_prompt("greet_prompt", serde_json::json!({ "name": "Ada" }))
            .expect("get prompt")
            .expect("prompt result");
        assert_eq!(prompt.messages.len(), 1);

        service.emit_event(ToolServerEvent::ResourcesListChanged);
        service.emit_event(ToolServerEvent::PromptsListChanged);
        let events = service.drain_events().expect("drain events");
        assert_eq!(
            events,
            vec![
                ToolServerEvent::ResourcesListChanged,
                ToolServerEvent::PromptsListChanged,
            ]
        );
    }

    #[test]
    fn native_tool_pricing_helpers_populate_manifest_metadata() {
        let flat = NativeTool::new("flat", "Flat priced", serde_json::json!({}))
            .flat_price(500, "USD")
            .into_definition();
        assert_eq!(
            flat.pricing.as_ref().map(|pricing| pricing.pricing_model),
            Some(PricingModel::Flat)
        );
        assert_eq!(
            flat.pricing
                .as_ref()
                .and_then(|pricing| pricing.base_price.as_ref())
                .map(|amount| (amount.units, amount.currency.as_str())),
            Some((500, "USD"))
        );

        let per_invocation = NativeTool::new("call", "Per invocation", serde_json::json!({}))
            .per_invocation_price(75, "USD")
            .into_definition();
        assert_eq!(
            per_invocation
                .pricing
                .as_ref()
                .map(|pricing| pricing.pricing_model),
            Some(PricingModel::PerInvocation)
        );
        assert_eq!(
            per_invocation
                .pricing
                .as_ref()
                .and_then(|pricing| pricing.billing_unit.as_deref()),
            Some("invocation")
        );

        let per_unit = NativeTool::new("tokens", "Per unit", serde_json::json!({}))
            .per_unit_price(2, "USD", "1k_tokens")
            .into_definition();
        assert_eq!(
            per_unit
                .pricing
                .as_ref()
                .map(|pricing| pricing.pricing_model),
            Some(PricingModel::PerUnit)
        );
        assert_eq!(
            per_unit
                .pricing
                .as_ref()
                .and_then(|pricing| pricing.billing_unit.as_deref()),
            Some("1k_tokens")
        );

        let hybrid = NativeTool::new("search", "Hybrid priced", serde_json::json!({}))
            .hybrid_price(25, 10, "USD", "document")
            .into_definition();
        assert_eq!(
            hybrid.pricing.as_ref().map(|pricing| pricing.pricing_model),
            Some(PricingModel::Hybrid)
        );
        assert_eq!(
            hybrid
                .pricing
                .as_ref()
                .and_then(|pricing| pricing.base_price.as_ref())
                .map(|amount| amount.units),
            Some(25)
        );
        assert_eq!(
            hybrid
                .pricing
                .as_ref()
                .and_then(|pricing| pricing.unit_price.as_ref())
                .map(|amount| amount.units),
            Some(10)
        );
    }
}
