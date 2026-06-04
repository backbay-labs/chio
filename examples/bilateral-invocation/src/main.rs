use bilateral_invocation::{display_prefix, run_demo};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let summary = run_demo()?;

    println!("== bilateral cosigned invocation demo ==");
    println!(
        "  origin kernel:   {} (passport pubkey hex prefix={}…)",
        summary.origin_kernel_id,
        display_prefix(&summary.origin_public_key_hex, 16)
    );
    println!(
        "  tool-host kernel: {} (passport pubkey hex prefix={}…)",
        summary.tool_host_kernel_id,
        display_prefix(&summary.tool_host_public_key_hex, 16)
    );
    println!(
        "  receipt id={}, tool_name={}, decision=Allow",
        summary.receipt_id, summary.receipt_tool_name
    );

    println!();
    println!("== Bilateral co-sign succeeded ==");
    println!("  DualSignedReceipt schema: {}", summary.dual_signed_schema);
    println!(
        "  DSSE signature-slice envelope: payloadType={}, signatures.len={}",
        summary.dsse_payload_type, summary.dsse_signature_count
    );
    println!(
        "  envelope payload (base64, prefix): {}…",
        display_prefix(&summary.dsse_payload, 40)
    );

    println!();
    println!("== Partial local verifier accepted envelope ==");
    println!("  joint_verdict: {}", summary.joint_verdict);
    println!(
        "  resolved lease: id={} issuer={} expires_at_unix_ms={}",
        summary.resolved_lease_id,
        summary.resolved_lease_issuer,
        summary.resolved_lease_expires_at_unix_ms
    );
    println!(
        "  resolved receipt: id={} tool_name={}",
        summary.resolved_receipt_id, summary.resolved_receipt_tool_name
    );

    Ok(())
}
