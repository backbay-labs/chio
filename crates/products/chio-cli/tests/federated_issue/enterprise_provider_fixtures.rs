pub(super) fn enterprise_provider_record(
    provider_id: &str,
    enabled: bool,
    organization_id: &str,
) -> serde_json::Value {
    serde_json::json!({
        "provider_id": provider_id,
        "kind": "oidc_jwks",
        "enabled": enabled,
        "provenance": {
            "configured_from": "manual",
            "source_ref": "operator",
            "trust_material_ref": "jwks:enterprise-login",
            "subject_mapping_source": "manual"
        },
        "trust_boundary": {
            "allowed_issuers": ["https://issuer.enterprise.example"],
            "allowed_tenants": ["tenant-123"],
            "allowed_organizations": [organization_id]
        },
        "issuer": "https://issuer.enterprise.example",
        "jwks_url": "https://issuer.enterprise.example/jwks",
        "tenant_id": "tenant-123",
        "organization_id": organization_id,
        "subject_mapping": {
            "principal_source": "sub",
            "tenant_id_field": "tid",
            "organization_id_field": "org_id",
            "groups_field": "groups",
            "roles_field": "roles"
        }
    })
}

pub(super) fn scim_enterprise_provider_record(
    provider_id: &str,
    enabled: bool,
    organization_id: &str,
) -> serde_json::Value {
    serde_json::json!({
        "provider_id": provider_id,
        "kind": "scim",
        "enabled": enabled,
        "provenance": {
            "configured_from": "manual",
            "source_ref": "operator",
            "trust_material_ref": "scim:enterprise-login",
            "subject_mapping_source": "manual"
        },
        "trust_boundary": {
            "allowed_tenants": ["tenant-123"],
            "allowed_organizations": [organization_id]
        },
        "scim_base_url": "https://issuer.enterprise.example/scim/v2",
        "tenant_id": "tenant-123",
        "organization_id": organization_id,
        "subject_mapping": {
            "principal_source": "userName",
            "tenant_id_field": "tenantId",
            "organization_id_field": "organizationId",
            "groups_field": "groups",
            "roles_field": "roles"
        }
    })
}
