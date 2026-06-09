#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    include!("tests/support.rs");
    include!("tests/protocol.rs");
    include!("tests/discovery_registry.rs");
    include!("tests/invoke_manifest.rs");
    include!("tests/streaming_lifecycle.rs");
    include!("tests/auth.rs");
    include!("tests/kernel_receipts.rs");
}
