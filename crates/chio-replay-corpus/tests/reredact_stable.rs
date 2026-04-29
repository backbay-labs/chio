use chio_replay_corpus::reredact_default;

#[test]
fn default_reredaction_is_stable_for_fixture_blessing() -> Result<(), Box<dyn std::error::Error>> {
    let payload = b"Authorization: Bearer abcdef0123456789abcdef0123456789\r\n\
        contact alice@example.com with ssn 123-45-6789";

    let first = reredact_default(payload)?;
    let second = reredact_default(payload)?;

    assert_eq!(first, second);
    assert_eq!(first.pass_id, "m06-redactors@1.4.0+default");
    assert!(!first.matches.is_empty());

    let body = String::from_utf8(first.bytes)?;
    assert!(body.contains("[REDACTED-BEARER]"));
    assert!(body.contains("[REDACTED-EMAIL]"));
    assert!(body.contains("[REDACTED-SSN]"));
    assert!(!body.contains("alice@example.com"));
    assert!(!body.contains("123-45-6789"));
    Ok(())
}
