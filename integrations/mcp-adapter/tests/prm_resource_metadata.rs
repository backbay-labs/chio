use chio_mcp_adapter_integration::ProtectedResourceMetadata;

#[test]
fn protected_resource_metadata_records_rfc9728_fields() -> Result<(), Box<dyn std::error::Error>> {
    let metadata = ProtectedResourceMetadata::new(
        "https://mcp.chio.example/mcp",
        "https://auth.chio.example",
        vec!["tools.call".to_string(), "receipts.read".to_string()],
    )?;

    let value = serde_json::to_value(&metadata)?;
    assert_eq!(
        metadata.well_known_path(),
        "/.well-known/oauth-protected-resource"
    );
    assert_eq!(value["resource"], "https://mcp.chio.example/mcp");
    assert_eq!(
        value["authorization_servers"][0],
        "https://auth.chio.example"
    );
    assert_eq!(value["bearer_methods_supported"][0], "header");
    Ok(())
}

#[test]
fn protected_resource_metadata_rejects_empty_scope_set() {
    assert!(ProtectedResourceMetadata::new(
        "https://mcp.chio.example/mcp",
        "https://auth.chio.example",
        vec![],
    )
    .is_err());
}
