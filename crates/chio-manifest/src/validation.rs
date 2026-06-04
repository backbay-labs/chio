use std::collections::HashSet;

use chio_core::capability::MonetaryAmount;

use crate::{
    ManifestError, PricingModel, RequiredPermissions, ToolDefinition, ToolManifest, ToolPricing,
    TOOL_MANIFEST_SCHEMA,
};

/// Validate that a manifest is structurally well-formed.
///
/// This does not authenticate signer material. Use [`crate::sign_manifest`] or
/// [`crate::verify_manifest`] when the embedded public key must be parsed and
/// matched against a signer.
pub fn validate_manifest(manifest: &ToolManifest) -> Result<(), ManifestError> {
    if manifest.schema != TOOL_MANIFEST_SCHEMA {
        return Err(ManifestError::UnsupportedSchema(manifest.schema.clone()));
    }
    validate_manifest_identity(manifest)?;
    validate_tools(&manifest.tools)?;
    validate_server_tools(manifest)?;
    validate_required_permissions(manifest.required_permissions.as_ref())?;
    Ok(())
}

fn validate_manifest_identity(manifest: &ToolManifest) -> Result<(), ManifestError> {
    validate_manifest_text_field("server_id", &manifest.server_id)?;
    validate_manifest_text_field("name", &manifest.name)?;
    validate_manifest_text_field("version", &manifest.version)?;
    Ok(())
}

fn validate_manifest_text_field(field: &'static str, value: &str) -> Result<(), ManifestError> {
    validate_text_value(field, value)
}

fn validate_text_value(field: &'static str, value: &str) -> Result<(), ManifestError> {
    if value.trim().is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        Err(ManifestError::InvalidManifestField(field))
    } else {
        Ok(())
    }
}

fn validate_tools(tools: &[ToolDefinition]) -> Result<(), ManifestError> {
    if tools.is_empty() {
        return Err(ManifestError::EmptyManifest);
    }

    let mut seen = HashSet::new();
    for tool in tools {
        validate_tool(tool)?;
        if !seen.insert(&tool.name) {
            return Err(ManifestError::DuplicateToolName(tool.name.clone()));
        }
    }

    Ok(())
}

fn validate_tool(tool: &ToolDefinition) -> Result<(), ManifestError> {
    if tool.name.trim().is_empty()
        || tool.name.trim() != tool.name
        || tool.name.chars().any(char::is_control)
    {
        return Err(ManifestError::InvalidToolName(tool.name.clone()));
    }
    if !tool.input_schema.is_object() {
        return Err(ManifestError::InvalidInputSchema(tool.name.clone()));
    }
    if tool
        .output_schema
        .as_ref()
        .is_some_and(|schema| !schema.is_object())
    {
        return Err(ManifestError::InvalidOutputSchema(tool.name.clone()));
    }
    validate_tool_pricing(tool.pricing.as_ref())?;
    Ok(())
}

fn validate_tool_pricing(pricing: Option<&ToolPricing>) -> Result<(), ManifestError> {
    let Some(pricing) = pricing else {
        return Ok(());
    };

    match pricing.pricing_model {
        PricingModel::Flat => {
            require_pricing_amount(pricing.base_price.as_ref(), "tools.pricing.base_price")?;
        }
        PricingModel::PerInvocation | PricingModel::PerUnit => {
            require_pricing_amount(pricing.unit_price.as_ref(), "tools.pricing.unit_price")?;
            require_billing_unit(pricing.billing_unit.as_deref())?;
        }
        PricingModel::Hybrid => {
            require_pricing_amount(pricing.base_price.as_ref(), "tools.pricing.base_price")?;
            require_pricing_amount(pricing.unit_price.as_ref(), "tools.pricing.unit_price")?;
            require_billing_unit(pricing.billing_unit.as_deref())?;
        }
    }

    validate_optional_pricing_amount(pricing.base_price.as_ref())?;
    validate_optional_pricing_amount(pricing.unit_price.as_ref())?;
    if let Some(billing_unit) = pricing.billing_unit.as_deref() {
        validate_text_value("tools.pricing.billing_unit", billing_unit)?;
    }
    Ok(())
}

fn require_pricing_amount(
    amount: Option<&MonetaryAmount>,
    field: &'static str,
) -> Result<(), ManifestError> {
    if amount.is_some() {
        Ok(())
    } else {
        Err(ManifestError::InvalidManifestField(field))
    }
}

fn require_billing_unit(billing_unit: Option<&str>) -> Result<(), ManifestError> {
    if billing_unit.is_some() {
        Ok(())
    } else {
        Err(ManifestError::InvalidManifestField(
            "tools.pricing.billing_unit",
        ))
    }
}

fn validate_optional_pricing_amount(amount: Option<&MonetaryAmount>) -> Result<(), ManifestError> {
    let Some(amount) = amount else {
        return Ok(());
    };
    if is_iso_4217_currency_code(&amount.currency) {
        Ok(())
    } else {
        Err(ManifestError::InvalidManifestField(
            "tools.pricing.currency",
        ))
    }
}

fn is_iso_4217_currency_code(currency: &str) -> bool {
    currency.len() == 3 && currency.bytes().all(|byte| byte.is_ascii_uppercase())
}

fn validate_server_tools(manifest: &ToolManifest) -> Result<(), ManifestError> {
    let mut seen_server_tools = HashSet::new();
    for server_tool in &manifest.server_tools {
        if !seen_server_tools.insert(*server_tool) {
            return Err(ManifestError::DuplicateServerTool(
                server_tool.as_str().to_string(),
            ));
        }
    }

    Ok(())
}

fn validate_required_permissions(
    permissions: Option<&RequiredPermissions>,
) -> Result<(), ManifestError> {
    let Some(permissions) = permissions else {
        return Ok(());
    };

    validate_permission_values(
        "required_permissions.read_paths",
        permissions.read_paths.as_deref(),
    )?;
    validate_permission_values(
        "required_permissions.write_paths",
        permissions.write_paths.as_deref(),
    )?;
    validate_permission_values(
        "required_permissions.network_hosts",
        permissions.network_hosts.as_deref(),
    )?;
    validate_permission_values(
        "required_permissions.environment_variables",
        permissions.environment_variables.as_deref(),
    )?;
    Ok(())
}

fn validate_permission_values(
    field: &'static str,
    values: Option<&[String]>,
) -> Result<(), ManifestError> {
    let Some(values) = values else {
        return Ok(());
    };

    let mut seen = HashSet::new();
    for value in values {
        if value.trim().is_empty() || value.trim() != value || value.chars().any(char::is_control) {
            return Err(ManifestError::InvalidRequiredPermission {
                field,
                value: value.clone(),
            });
        }
        if !seen.insert(value) {
            return Err(ManifestError::DuplicateRequiredPermission {
                field,
                value: value.clone(),
            });
        }
    }

    Ok(())
}
