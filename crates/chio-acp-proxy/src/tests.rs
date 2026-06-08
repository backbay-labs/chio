#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    include!("tests/core_support.rs");
    include!("tests/core_guards.rs");
    include!("tests/core_receipts.rs");
    include!("tests/core_protocol.rs");
    include!("tests/core_interceptor.rs");
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod extended_tests {
    include!("tests/extended_support.rs");
    include!("tests/extended_protocol.rs");
    include!("tests/extended_guards.rs");
    include!("tests/extended_interceptor.rs");
    include!("tests/extended_permissions.rs");
    include!("tests/extended_receipts.rs");
    include!("tests/extended_config.rs");
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod attestation_and_telemetry_tests {
    include!("tests/attestation_support.rs");
    include!("tests/attestation_denials.rs");
    include!("tests/attestation_lifecycle.rs");
    include!("tests/attestation_compliance.rs");
    include!("tests/attestation_signer.rs");
    include!("tests/attestation_telemetry_transport.rs");
}
