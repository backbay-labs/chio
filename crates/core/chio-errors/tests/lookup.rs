use chio_errors::{
    diagnostic, diagnostic_from_spec, error, error_from_spec, lookup_error_code,
    lookup_string_code, lookup_string_code_matches, ChioError, Code, Diagnostic, Domain, Severity,
};

#[test]
fn all_domain_slugs_round_trip() {
    let expected = [
        "capability",
        "policy",
        "guard",
        "attest",
        "replay",
        "provider",
        "manifest",
        "kernel",
        "transport",
        "cli",
        "delegation",
        "adversarial",
        "threat",
        "arena",
        "economy",
        "lineage",
        "custody",
        "weights",
        "mobile",
        "transaction",
    ];

    assert_eq!(Domain::ALL.len(), expected.len());

    for (domain, slug) in Domain::ALL.into_iter().zip(expected) {
        assert_eq!(domain.as_str(), slug);
        assert_eq!(Domain::lookup(slug), Some(domain));
        assert_eq!(slug.parse::<Domain>(), Ok(domain));
        assert_eq!(domain.to_string(), slug);
    }
}

#[test]
fn unknown_domain_keeps_input() {
    let result = "unknown".parse::<Domain>();

    assert!(result.is_err());
    assert_eq!(Domain::lookup("unknown"), None);
}

#[test]
fn severity_lookup_accepts_warning_alias() {
    assert_eq!(Severity::lookup("info"), Some(Severity::Info));
    assert_eq!(Severity::lookup("warn"), Some(Severity::Warning));
    assert_eq!(Severity::lookup("warning"), Some(Severity::Warning));
    assert_eq!(Severity::lookup("error"), Some(Severity::Error));
    assert_eq!(Severity::lookup("fatal"), Some(Severity::Fatal));
    assert!(Severity::Fatal > Severity::Error);
    assert_eq!(Severity::Fatal.rank(), 3);
}

#[test]
fn diagnostic_helpers_preserve_typed_fields() {
    let diagnostic = diagnostic(
        "CHIO-CAP-0001",
        Domain::Capability,
        Severity::Error,
        "capability token expired",
    )
    .with_help("request a fresh capability grant");

    assert_eq!(diagnostic.code(), &Code::from("CHIO-CAP-0001"));
    assert_eq!(diagnostic.domain(), Domain::Capability);
    assert_eq!(diagnostic.severity(), Severity::Error);
    assert_eq!(diagnostic.message(), "capability token expired");
    assert_eq!(diagnostic.help(), Some("request a fresh capability grant"));

    let err = diagnostic.clone().into_error();
    assert_eq!(err.diagnostic(), &diagnostic);
    assert_eq!(err.code().as_str(), "CHIO-CAP-0001");
    assert_eq!(err.domain(), Domain::Capability);
    assert_eq!(err.severity(), Severity::Error);
    assert_eq!(err.message(), "capability token expired");
    assert_eq!(err.help(), Some("request a fresh capability grant"));
    assert_eq!(
        err.to_string(),
        "CHIO-CAP-0001 [capability:error]: capability token expired (request a fresh capability grant)"
    );
}

#[test]
fn error_helper_builds_chio_error() {
    let err = error(
        Code::new("CHIO-POL-0001"),
        Domain::Policy,
        Severity::Fatal,
        "policy denied request",
    );

    assert_eq!(err.code().as_str(), "CHIO-POL-0001");
    assert_eq!(err.domain(), Domain::Policy);
    assert_eq!(err.severity(), Severity::Fatal);
    assert_eq!(err.message(), "policy denied request");
}

#[test]
fn registry_bound_constructors_preserve_registry_metadata() {
    let spec = match lookup_error_code("urn:chio:error:capability:expired") {
        Some(spec) => spec,
        None => panic!("registry fixture should contain capability expired"),
    };

    let diagnostic = Diagnostic::from_spec(spec, "token expired before evaluation");

    assert_eq!(diagnostic.code().as_str(), spec.urn);
    assert_eq!(diagnostic.domain(), spec.domain);
    assert_eq!(diagnostic.severity(), spec.severity);
    assert_eq!(diagnostic.message(), "token expired before evaluation");
    assert_eq!(diagnostic.help(), Some(spec.help));
    assert_eq!(diagnostic.registry_spec(), Some(spec));

    let helper_diagnostic = diagnostic_from_spec(spec, "retry with a fresh grant");
    assert_eq!(helper_diagnostic.code().as_str(), spec.urn);
    assert_eq!(helper_diagnostic.help(), Some(spec.help));

    let err = ChioError::from_spec(spec, "capability is stale");
    assert_eq!(err.code().as_str(), spec.urn);
    assert_eq!(err.domain(), spec.domain);
    assert_eq!(err.severity(), spec.severity);
    assert_eq!(err.help(), Some(spec.help));
    assert_eq!(err.registry_spec(), Some(spec));

    let helper_error = error_from_spec(spec, "capability is stale");
    assert_eq!(helper_error.code().as_str(), spec.urn);
    assert_eq!(helper_error.help(), Some(spec.help));
}

#[test]
fn registry_spec_rejects_registered_code_with_mismatched_metadata() {
    let spec = match lookup_error_code("urn:chio:error:capability:expired") {
        Some(spec) => spec,
        None => panic!("registry fixture should contain capability expired"),
    };

    let wrong_domain = diagnostic(
        spec.urn,
        Domain::Manifest,
        spec.severity,
        "registered code with wrong domain",
    );
    assert_eq!(wrong_domain.registry_spec(), None);

    let wrong_severity = diagnostic(
        spec.urn,
        spec.domain,
        Severity::Fatal,
        "registered code with wrong severity",
    );
    assert_eq!(wrong_severity.registry_spec(), None);

    let err = wrong_domain.into_error();
    assert_eq!(err.registry_spec(), None);
}

#[test]
fn free_form_diagnostic_keeps_unregistered_code_compatibility() {
    let diagnostic = diagnostic(
        "CHIO-LOCAL-ONLY",
        Domain::Cli,
        Severity::Error,
        "legacy local diagnostic",
    );

    assert_eq!(diagnostic.code().as_str(), "CHIO-LOCAL-ONLY");
    assert_eq!(diagnostic.registry_spec(), None);
}

#[test]
fn duplicate_string_codes_are_not_silently_first_matched() {
    let matches: Vec<_> = lookup_string_code_matches("CHIO-CLI-JSON").collect();

    assert!(
        matches.len() > 1,
        "registry fixture must keep a duplicate legacy code"
    );
    assert_eq!(lookup_string_code("CHIO-CLI-JSON"), None);
}

#[test]
fn transaction_artifact_hash_mismatch_is_registered() {
    let spec = lookup_error_code("urn:chio:error:transaction:artifact-hash-mismatch")
        .expect("transaction artifact hash mismatch code is registered");

    assert_eq!(spec.domain.as_str(), "transaction");
    assert_eq!(spec.severity, Severity::Error);
    assert_eq!(spec.string_code, "CHIO-TRANSACTION-ARTIFACT-HASH-MISMATCH");
    assert!(spec.consumed_by.contains(&"chio-cli"));
}

#[test]
fn launch_transaction_failure_codes_are_registered() {
    let expected = [
        "urn:chio:error:transaction:passport-schema-unsupported",
        "urn:chio:error:transaction:passport-hash-mismatch",
        "urn:chio:error:transaction:graph-not-closed",
        "urn:chio:error:transaction:graph-cycle",
        "urn:chio:error:transaction:required-claim-missing",
        "urn:chio:error:transaction:artifact-hash-mismatch",
        "urn:chio:error:transaction:identity-not-bound",
        "urn:chio:error:transaction:authorization-not-bound",
        "urn:chio:error:transaction:receipt-uncheckpointed",
        "urn:chio:error:transaction:runtime-proof-rejected",
        "urn:chio:error:transaction:buyer-review-rejected",
        "urn:chio:error:transaction:settlement-unverified",
        "urn:chio:error:transaction:dispute-unbound",
        "urn:chio:error:transaction:transparency-preview-not-allowed",
    ];

    for urn in expected {
        let spec = lookup_error_code(urn)
            .unwrap_or_else(|| panic!("transaction launch failure code is registered: {urn}"));
        assert_eq!(spec.domain, Domain::Transaction);
        assert_eq!(spec.severity, Severity::Error);
        assert!(spec.consumed_by.contains(&"chio-transaction-passport"));
        assert!(spec.consumed_by.contains(&"chio-cli"));
        assert!(spec.consumed_by.contains(&"chio-proof-room"));
    }
}
