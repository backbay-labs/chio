use chio_core_types::Keypair;
use chio_did::{resolve_did_arc, DidChio, DidService, ResolveOptions, RECEIPT_LOG_SERVICE_TYPE};

#[test]
fn did_chio_resolves_with_public_service_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let did = DidChio::from_public_key(Keypair::from_seed(&[9u8; 32]).public_key())?;
    let options = ResolveOptions::default().with_service(DidService::receipt_log(
        &did,
        0,
        "https://trust.example.com/v1/receipts",
    )?);

    let document = resolve_did_arc(&did.to_string(), &options)?;

    assert_eq!(document.id, did.to_string());
    assert_eq!(document.service[0].service_type, RECEIPT_LOG_SERVICE_TYPE);
    assert_eq!(
        document.service[0].service_endpoint,
        "https://trust.example.com/v1/receipts"
    );
    Ok(())
}
