//! # hello-tool
//!
//! Reusable native Chio service construction for the hello-tool example. The
//! binary wrapper calls [`run`], while tests exercise this library boundary
//! directly.

use std::error::Error;

use chio_core::crypto::Keypair;
use chio_core::{PromptMessage, ResourceContent};
use chio_kernel::{
    KernelError, PromptProvider, ResourceProvider, ToolServerConnection, ToolServerEvent,
};
use chio_mcp_adapter::{
    NativeChioService, NativeChioServiceBuilder, NativePrompt, NativeResource, NativeTool,
};

pub type HelloToolResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

fn greeting_name(arguments: &serde_json::Value) -> Result<&str, KernelError> {
    arguments
        .get("name")
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            KernelError::RequestIncomplete("greet requires string field name".to_string())
        })
}

pub fn build_service(
    public_key_hex: String,
) -> Result<NativeChioService, chio_manifest::ManifestError> {
    NativeChioServiceBuilder::new("srv-hello", public_key_hex)
        .server_name("Hello Tool Server")
        .server_version("0.1.0")
        .server_description("A tiny native Chio service that exposes a tool, resource, prompt, and priced manifest")
        .tool(
            NativeTool::new(
                "greet",
                "Returns a personalized greeting",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "The name to greet"
                        }
                    },
                    "required": ["name"]
                }),
            )
            .output_schema(serde_json::json!({
                "type": "object",
                "properties": {
                    "greeting": { "type": "string" }
                }
            }))
            .read_only()
            .per_invocation_price(25, "USD")
            .latency_hint(chio_manifest::LatencyHint::Instant),
            |arguments| {
                let name = greeting_name(&arguments)?;
                Ok(serde_json::json!({
                    "greeting": format!("Hello, {name}! This greeting was served by a native Chio service.")
                }))
            },
        )
        .static_resource(
            NativeResource::new("memory://hello/template", "Greeting Template")
                .description("A static greeting template used by the hello example")
                .mime_type("text/plain"),
            vec![ResourceContent {
                uri: "memory://hello/template".to_string(),
                mime_type: Some("text/plain".to_string()),
                text: Some("Hello, {name}! This greeting was served by a native Chio service.".to_string()),
                blob: None,
                annotations: None,
            }],
        )
        .static_prompt(
            NativePrompt::new("compose_greeting")
                .description("Creates a user prompt that asks for a polite greeting"),
            chio_core::PromptResult {
                description: Some("Greeting composition prompt".to_string()),
                messages: vec![PromptMessage {
                    role: "user".to_string(),
                    content: serde_json::json!({
                        "type": "text",
                        "text": "Compose a short, polite greeting for Ada."
                    }),
                }],
            },
        )
        .build()
}

pub async fn run() -> HelloToolResult<()> {
    println!("=== Chio hello-tool example ===\n");

    let server_kp = Keypair::generate();
    let service = build_service(server_kp.public_key().to_hex())?;

    println!("Native manifest:");
    println!(
        "  Server: {} ({})",
        service.manifest().name,
        service.server_id()
    );
    for tool in &service.manifest().tools {
        println!("  Tool: {} - {}", tool.name, tool.description);
        if let Some(pricing) = &tool.pricing {
            let quoted = pricing
                .unit_price
                .as_ref()
                .map(|amount| format!("{} {}", amount.units, amount.currency))
                .or_else(|| {
                    pricing
                        .base_price
                        .as_ref()
                        .map(|amount| format!("{} {}", amount.units, amount.currency))
                })
                .unwrap_or_else(|| "n/a".to_string());
            println!(
                "    Pricing: {:?} ({quoted}{})",
                pricing.pricing_model,
                pricing
                    .billing_unit
                    .as_deref()
                    .map(|unit| format!(" per {unit}"))
                    .unwrap_or_default()
            );
        }
    }

    chio_manifest::sign_manifest(service.manifest(), &server_kp)?;
    println!("\nManifest signed successfully.");

    let greeting = service
        .invoke("greet", serde_json::json!({ "name": "World" }), None)
        .await?;
    println!("\nTool invocation:");
    println!("  Input:  {{\"name\":\"World\"}}");
    println!("  Output: {greeting}");

    let resource = service
        .read_resource("memory://hello/template")?
        .ok_or_else(|| {
            KernelError::ToolServerError("hello template resource missing".to_string())
        })?;
    println!("\nResource read:");
    if let Some(first_resource) = resource.first() {
        println!("  URI: {}", first_resource.uri);
        println!("  Text: {}", first_resource.text.as_deref().unwrap_or(""));
    }

    let prompt = service
        .get_prompt("compose_greeting", serde_json::json!({}))?
        .ok_or_else(|| {
            KernelError::ToolServerError("compose_greeting prompt missing".to_string())
        })?;
    println!("\nPrompt:");
    let first_message_text = prompt
        .messages
        .first()
        .and_then(|message| message.content["text"].as_str())
        .unwrap_or("");
    println!("  First message: {first_message_text}");

    service.emit_event(ToolServerEvent::ResourcesListChanged);
    let events = service.drain_events().await?;
    println!("\nLate events:");
    println!("  Count: {}", events.len());

    println!("\n=== done ===");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{build_service, HelloToolResult};
    use chio_core::crypto::Keypair;
    use chio_kernel::{
        KernelError, PromptProvider, ResourceProvider, ToolServerConnection, ToolServerEvent,
    };
    use chio_manifest::PricingModel;

    const TEST_PUBLIC_KEY: &str =
        "7b0f6f631f6e66207140ead0b6b2e9418916d2c4b3c7448ba5f7ed27f5c8d038";

    #[test]
    fn hello_tool_manifest_advertises_pricing_metadata() -> HelloToolResult<()> {
        let service = build_service(TEST_PUBLIC_KEY.to_string())?;
        let tool = &service.manifest().tools[0];

        assert_eq!(tool.name, "greet");
        assert_eq!(
            tool.pricing.as_ref().map(|pricing| pricing.pricing_model),
            Some(PricingModel::PerInvocation)
        );
        assert_eq!(
            tool.pricing
                .as_ref()
                .and_then(|pricing| pricing.unit_price.as_ref())
                .map(|amount| (amount.units, amount.currency.as_str())),
            Some((25, "USD"))
        );
        assert_eq!(
            tool.pricing
                .as_ref()
                .and_then(|pricing| pricing.billing_unit.as_deref()),
            Some("invocation")
        );
        Ok(())
    }

    #[tokio::test]
    async fn hello_tool_service_exercises_native_surfaces() -> HelloToolResult<()> {
        let server_kp = Keypair::generate();
        let service = build_service(server_kp.public_key().to_hex())?;

        let signed_manifest = chio_manifest::sign_manifest(service.manifest(), &server_kp)?;
        assert_eq!(signed_manifest.manifest.server_id, "srv-hello");
        assert_eq!(service.tool_names(), vec!["greet".to_string()]);

        let greeting = service
            .invoke("greet", serde_json::json!({ "name": "Ada" }), None)
            .await?;
        assert_eq!(
            greeting["greeting"].as_str(),
            Some("Hello, Ada! This greeting was served by a native Chio service.")
        );

        let resource = service
            .read_resource("memory://hello/template")?
            .ok_or_else(|| {
                KernelError::ToolServerError("hello template resource missing".to_string())
            })?;
        assert_eq!(resource.len(), 1);
        assert_eq!(resource[0].uri, "memory://hello/template");
        assert_eq!(resource[0].mime_type.as_deref(), Some("text/plain"));

        let prompt = service
            .get_prompt("compose_greeting", serde_json::json!({}))?
            .ok_or_else(|| {
                KernelError::ToolServerError("compose_greeting prompt missing".to_string())
            })?;
        assert_eq!(prompt.messages.len(), 1);
        assert_eq!(prompt.messages[0].role, "user");

        service.emit_event(ToolServerEvent::ResourcesListChanged);
        assert_eq!(
            service.drain_events().await?,
            vec![ToolServerEvent::ResourcesListChanged]
        );
        Ok(())
    }

    #[tokio::test]
    async fn greet_rejects_missing_required_name() -> HelloToolResult<()> {
        let service = build_service(TEST_PUBLIC_KEY.to_string())?;

        let error = match service.invoke("greet", serde_json::json!({}), None).await {
            Ok(value) => {
                return Err(KernelError::ToolServerError(format!(
                    "missing name should fail closed, got {value}"
                ))
                .into());
            }
            Err(error) => error,
        };

        assert!(matches!(error, KernelError::RequestIncomplete(reason) if reason.contains("name")));
        Ok(())
    }
}
