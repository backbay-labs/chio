use chio_errors::{
    diagnostic, error, lookup_string_code, lookup_string_code_matches, Code, Domain, Severity,
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
fn duplicate_string_codes_are_not_silently_first_matched() {
    let matches: Vec<_> = lookup_string_code_matches("CHIO-CLI-JSON").collect();

    assert!(
        matches.len() > 1,
        "registry fixture must keep a duplicate legacy code"
    );
    assert_eq!(lookup_string_code("CHIO-CLI-JSON"), None);
}
