use super::yaml_safety::{
    block_scalar_parent_indent_start, has_libyml_scalar_join_overflow_risk,
    has_non_mapping_document_start, has_unclosed_double_quoted_value_scalar, strip_inline_comment,
    MAX_PLAIN_SCALAR_VALUE_WHITESPACE_RUN, MAX_QUOTED_SCALAR_WHITESPACE_RUN,
};
use super::*;

#[test]
fn regression_fuzz_policy_parse_compile_bbaf353() {
    let input = concat!(
        "hushnarrspec: \"0.",
        "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%",
        "scription: Allow a narro     - r      - \"**/.git/*ist_directory\n",
    );

    assert!(HushSpec::parse(input).is_err());
}

#[test]
fn regression_fuzz_policy_parse_compile_2c7fd63() {
    let input = concat!(
        "hushspec: \"0.1.0\"\n",
        "name: block-all\n",
        "description: Deny every tool by default.           currency: \"U\n",
        "    enabled: true\n",
        "    default: block\n",
    );

    assert!(HushSpec::parse(input).is_err());
}

#[test]
fn parse_allows_plain_scalar_with_unpaired_double_quote() {
    let input = concat!(
        "hushspec: \"0.1.0\"\n",
        "name: quoted-description\n",
        "description: A valid plain scalar with a single \" character\n",
    );

    let spec = match HushSpec::parse(input) {
        Ok(spec) => spec,
        Err(err) => panic!("plain scalar quotes should parse: {err}"),
    };
    assert_eq!(
        spec.description.as_deref(),
        Some("A valid plain scalar with a single \" character")
    );
}

#[test]
fn parse_allows_plain_scalar_continuation_starting_with_quote() {
    let input = concat!(
        "hushspec: \"0.1.0\"\n",
        "name: multiline-description\n",
        "description: first line\n",
        "  \"second line\n",
    );

    let spec = match HushSpec::parse(input) {
        Ok(spec) => spec,
        Err(err) => panic!("plain scalar continuation quote should parse: {err}"),
    };
    assert_eq!(
        spec.description.as_deref(),
        Some("first line \"second line")
    );
}

#[test]
fn regression_fuzz_policy_parse_compile_67a1282() {
    let input = concat!(
        "hushspec: \"0.1.0\"\n",
        "name: malformed-sequence-quote\n",
        "rules:\n",
        "  forbidden_paths:\n",
        "    enabled: true\n",
        "    patterns:\n",
        "      - \"**.g. cents). Uncomment to rate-limit invocations or spend.\n",
        "  # human_in_loop:\n",
        "  #   require_confirmation: [\"write_*\", \"run_command\"]\n",
    );

    assert!(has_unclosed_double_quoted_value_scalar(input));
    assert!(HushSpec::parse(input).is_err());
}

#[test]
fn regression_fuzz_policy_parse_compile_e8a595c() {
    let spaces = " ".repeat(MAX_QUOTED_SCALAR_WHITESPACE_RUN + 1);
    let input = format!(
        "hushspec: \"0.{spaces}1.0\"\n\
         name: base\n\n\
         rules:\n\
           shell_commands:\n\
             enabled: true\n\
           tool_access:\n\
             enabled: true\n\
             default: block\n\
            (allow:\n\
               - read_file\n"
    );

    assert!(has_libyml_scalar_join_overflow_risk(&input));
    assert!(HushSpec::parse(&input).is_err());
}

#[test]
fn parse_allows_single_quoted_scalar_with_double_quote() {
    let spaces = " ".repeat(8);
    let input = format!(
        "hushspec: \"0.1.0\"\n\
         name: single-quoted-description\n\
         description: 'prefix \"{spaces}suffix'\n"
    );

    assert!(!has_libyml_scalar_join_overflow_risk(&input));
    let spec = match HushSpec::parse(&input) {
        Ok(spec) => spec,
        Err(err) => panic!("single quoted scalar should parse: {err}"),
    };
    let expected = format!("prefix \"{spaces}suffix");
    assert_eq!(spec.description.as_deref(), Some(expected.as_str()));
}

#[test]
fn parse_rejects_plain_root_scalar_before_libyml() {
    let input = "hushsiption      t\n";

    assert!(has_non_mapping_document_start(input));
    assert!(has_libyml_scalar_join_overflow_risk(input));
    assert!(HushSpec::parse(input).is_err());
}

#[test]
fn parse_rejects_plain_root_url_before_libyml() {
    let input = "https://example.com/policy\n";

    assert!(has_non_mapping_document_start(input));
    assert!(HushSpec::parse(input).is_err());
}

#[test]
fn parse_rejects_plain_mapping_key_join_before_libyml() {
    let input = concat!("hushspec: \"0.1.0\"\n", "description      min_days: 30\n");

    assert!(!has_non_mapping_document_start(input));
    assert!(has_libyml_scalar_join_overflow_risk(input));
    assert!(HushSpec::parse(input).is_err());
}

#[test]
fn parse_rejects_plain_mapping_value_join_before_libyml() {
    let spaces = " ".repeat(MAX_PLAIN_SCALAR_VALUE_WHITESPACE_RUN + 1);
    let input = format!(
        "hushspec: \"0.1.0\"\nname: value-overflow\nrules:\n  shell_commands:\n    enabled: t{spaces}rue\n"
    );

    assert!(!has_non_mapping_document_start(&input));
    assert!(has_libyml_scalar_join_overflow_risk(&input));
    assert!(HushSpec::parse(&input).is_err());
}

#[test]
fn parse_allows_plain_mapping_value_with_normal_spacing() {
    let input = concat!(
        "hushspec: \"0.1.0\"\n",
        "name: spaced-description\n",
        "description: hello      world\n",
    );

    assert!(!has_libyml_scalar_join_overflow_risk(input));
    let spec = match HushSpec::parse(input) {
        Ok(spec) => spec,
        Err(err) => panic!("plain spaced value should parse: {err}"),
    };
    assert_eq!(spec.description.as_deref(), Some("hello      world"));
}

#[test]
fn parse_allows_plain_mapping_value_continuation_with_normal_spacing() {
    let input = concat!(
        "hushspec: \"0.1.0\"\n",
        "name: multiline-spaced-description\n",
        "description: first line\n",
        "  second      line\n",
    );

    assert!(!has_libyml_scalar_join_overflow_risk(input));
    let spec = match HushSpec::parse(input) {
        Ok(spec) => spec,
        Err(err) => panic!("plain spaced value continuation should parse: {err}"),
    };
    assert_eq!(
        spec.description.as_deref(),
        Some("first line second      line")
    );
}

#[test]
fn rules_block_helpers_cover_conditionable_rule_blocks() {
    let mut rules = Rules::default();
    assert!(!rules.has_configured_blocks());

    rules.tool_access = Some(ToolAccessRule {
        enabled: true,
        allow: Vec::new(),
        block: Vec::new(),
        require_confirmation: Vec::new(),
        default: DefaultAction::Allow,
        max_args_size: None,
        require_runtime_assurance_tier: None,
        prefer_runtime_assurance_tier: None,
        require_workload_identity: None,
        prefer_workload_identity: None,
    });
    assert!(rules.has_configured_blocks());
    assert!(rules.clear_block("tool_access"));
    assert!(!rules.has_configured_blocks());

    assert_eq!(RULE_BLOCK_NAMES.len(), 14);
    for block_name in RULE_BLOCK_NAMES {
        let mut empty_rules = Rules::default();
        assert!(
            empty_rules.clear_block(block_name),
            "missing clear_block arm for {block_name}"
        );
    }

    let mut empty_rules = Rules::default();
    assert!(!empty_rules.clear_block("misspelled_rule_block"));
}

#[test]
fn parse_rejects_plain_mapping_value_continuation_join_before_libyml() {
    let spaces = " ".repeat(MAX_PLAIN_SCALAR_VALUE_WHITESPACE_RUN + 1);
    let input = format!(
        "hushspec: \"0.1.0\"\nname: value-overflow\n\
         description: first line\n  second{spaces}line\n"
    );

    assert!(!has_non_mapping_document_start(&input));
    assert!(has_libyml_scalar_join_overflow_risk(&input));
    assert!(HushSpec::parse(&input).is_err());
}

#[test]
fn parse_allows_document_marker_before_mapping() {
    let input = concat!(
        "--- # policy document\n",
        "hushspec: \"0.1.0\"\n",
        "name: document-marker-policy\n"
    );

    assert!(!has_non_mapping_document_start(input));
    let spec = match HushSpec::parse(input) {
        Ok(spec) => spec,
        Err(err) => panic!("document marker policy should parse: {err}"),
    };
    assert_eq!(spec.name.as_deref(), Some("document-marker-policy"));
}

#[test]
fn parse_allows_document_marker_properties_before_mapping() {
    let input = concat!(
        "--- &base !!map\n",
        "hushspec: \"0.1.0\"\n",
        "name: document-property-policy\n"
    );

    assert!(!has_non_mapping_document_start(input));
    let spec = match HushSpec::parse(input) {
        Ok(spec) => spec,
        Err(err) => panic!("document properties before mapping should parse: {err}"),
    };
    assert_eq!(spec.name.as_deref(), Some("document-property-policy"));
}

#[test]
fn parse_allows_root_properties_before_mapping() {
    let input = concat!(
        "&base !!map\n",
        "hushspec: \"0.1.0\"\n",
        "name: root-property-policy\n"
    );

    assert!(!has_non_mapping_document_start(input));
    let spec = match HushSpec::parse(input) {
        Ok(spec) => spec,
        Err(err) => panic!("root properties before mapping should parse: {err}"),
    };
    assert_eq!(spec.name.as_deref(), Some("root-property-policy"));
}

#[test]
fn parse_allows_explicit_key_mapping_start() {
    let input = concat!(
        "? hushspec\n",
        ": \"0.1.0\"\n",
        "name: explicit-key-policy\n",
    );

    assert!(!has_non_mapping_document_start(input));
    let spec = match HushSpec::parse(input) {
        Ok(spec) => spec,
        Err(err) => panic!("explicit-key mapping should parse: {err}"),
    };
    assert_eq!(spec.name.as_deref(), Some("explicit-key-policy"));
}

#[test]
fn parse_allows_first_mapping_value_with_colon() {
    let input = concat!(
        "description: https://example.com/a:b\n",
        "hushspec: \"0.1.0\"\n",
        "name: url-first-policy\n",
    );

    assert!(!has_non_mapping_document_start(input));
    let spec = match HushSpec::parse(input) {
        Ok(spec) => spec,
        Err(err) => panic!("colon-containing mapping value should parse: {err}"),
    };
    assert_eq!(spec.description.as_deref(), Some("https://example.com/a:b"));
}

#[test]
fn document_start_check_keeps_hash_inside_quoted_key() {
    let input = "\"key # name\": value\n";

    assert!(!has_non_mapping_document_start(input));
    assert_eq!(
        strip_inline_comment("\"key # name\": value # trailing"),
        "\"key # name\": value "
    );
}

#[test]
fn parse_allows_block_scalar_with_quoted_long_spaces() {
    let spaces = " ".repeat(MAX_QUOTED_SCALAR_WHITESPACE_RUN + 1);
    let input = format!(
        "hushspec: \"0.1.0\"\nname: block-scalar-description\ndescription: |\n  \"prefix{spaces}suffix\"\n"
    );

    assert!(!has_libyml_scalar_join_overflow_risk(&input));
    let spec = match HushSpec::parse(&input) {
        Ok(spec) => spec,
        Err(err) => panic!("block scalar with quoted content should parse: {err}"),
    };
    let expected = format!("\"prefix{spaces}suffix\"\n");
    assert_eq!(spec.description.as_deref(), Some(expected.as_str()));
}

#[test]
fn single_quoted_whitespace_overflow_rejected_before_libyml() {
    let spaces = " ".repeat(MAX_QUOTED_SCALAR_WHITESPACE_RUN + 1);
    let input = format!(
        "hushspec: \"0.1.0\"\n\
         name: single-quoted-description\n\
         description: 'prefix \"{spaces}suffix'\n"
    );

    assert!(has_libyml_scalar_join_overflow_risk(&input));
    assert!(HushSpec::parse(&input).is_err());
}

#[test]
fn quoted_whitespace_overflow_counts_folded_line_break() {
    let left_spaces = " ".repeat(MAX_QUOTED_SCALAR_WHITESPACE_RUN / 2);
    let right_spaces = " ".repeat(MAX_QUOTED_SCALAR_WHITESPACE_RUN - left_spaces.len());
    let input = format!(
        "hushspec: \"0.1.0\"\n\
         name: folded-quoted-whitespace\n\
         description: \"prefix{left_spaces}\n{right_spaces}suffix\"\n"
    );

    assert!(has_libyml_scalar_join_overflow_risk(&input));
    assert!(HushSpec::parse(&input).is_err());
}

#[test]
fn quoted_whitespace_overflow_resets_escaped_line_break() {
    let spaces = " ".repeat(MAX_QUOTED_SCALAR_WHITESPACE_RUN + 1);
    let input = format!(
        "hushspec: \"0.1.0\"\n\
         name: escaped-folded-quoted-whitespace\n\
         description: \"prefix\\\n{spaces}suffix\"\n"
    );

    assert!(has_libyml_scalar_join_overflow_risk(&input));
    assert!(HushSpec::parse(&input).is_err());
}

#[test]
fn overflow_precheck_resumes_after_single_quoted_scalar() {
    let spaces = " ".repeat(MAX_QUOTED_SCALAR_WHITESPACE_RUN + 1);
    let input = format!(
        "hushspec: \"0.1.0\"\n\
         description: 'has \" inside'\n\
         name: \"bad{spaces}name\"\n"
    );

    assert!(has_libyml_scalar_join_overflow_risk(&input));
    assert!(HushSpec::parse(&input).is_err());
}

#[test]
fn unclosed_double_quote_precheck_detects_nested_sequence_items() {
    let input = concat!(
        "hushspec: \"0.1.0\"\n",
        "name: nested-sequence-quote\n",
        "metadata:\n",
        "  tags:\n",
        "    - - \"unclosed\n",
    );

    assert!(has_unclosed_double_quoted_value_scalar(input));
    assert!(HushSpec::parse(input).is_err());
}

#[test]
fn quoted_whitespace_overflow_rejected_in_nested_sequence_item() {
    let spaces = " ".repeat(MAX_QUOTED_SCALAR_WHITESPACE_RUN + 1);
    let input = format!(
        "hushspec: \"0.1.0\"\n\
         name: nested-sequence-quote\n\
         metadata:\n\
           tags:\n\
             - - \"prefix{spaces}suffix\"\n"
    );

    assert!(has_libyml_scalar_join_overflow_risk(&input));
    assert!(HushSpec::parse(&input).is_err());
}

#[test]
fn parse_allows_multiline_quoted_scalar_comment_content() {
    let input = concat!(
        "hushspec: \"0.1.0\"\n",
        "name: multiline-quoted-description\n",
        "description: \"first\n",
        "# second\"\n",
    );

    let spec = match HushSpec::parse(input) {
        Ok(spec) => spec,
        Err(err) => panic!("comment-like quoted continuation should parse: {err}"),
    };
    assert_eq!(spec.description.as_deref(), Some("first # second"));
}

#[test]
fn quote_precheck_scans_after_closed_scalar_on_same_line() {
    let input = concat!(
        "hushspec: \"0.1.0\"\n",
        "name: second-unclosed-quote\n",
        "description: \"closed\" \"unclosed\n",
    );

    assert!(has_unclosed_double_quoted_value_scalar(input));
    assert!(HushSpec::parse(input).is_err());
    assert!(!has_unclosed_double_quoted_value_scalar(
        "description: \"closed\" # \"comment text\n"
    ));
    assert!(has_unclosed_double_quoted_value_scalar(
        "description: \"closed\"#\"unclosed\n"
    ));
}

#[test]
fn quote_precheck_handles_double_quoted_mapping_key() {
    let input = concat!("hushspec: \"0.1.0\"\n", "\"name\": \"unclosed-policy\n",);

    assert!(has_unclosed_double_quoted_value_scalar(input));
    assert!(HushSpec::parse(input).is_err());
}

#[test]
fn parse_allows_hash_inside_double_quoted_scalar() {
    let input = concat!(
        "hushspec: \"0.1.0\"\n",
        "name: quoted-description\n",
        "description: \"A quoted scalar with # as data\"\n",
    );

    let spec = match HushSpec::parse(input) {
        Ok(spec) => spec,
        Err(err) => panic!("quoted scalar hash should parse: {err}"),
    };
    assert_eq!(
        spec.description.as_deref(),
        Some("A quoted scalar with # as data")
    );
}

#[test]
fn parse_allows_block_scalar_with_unpaired_double_quote() {
    let input = concat!(
        "hushspec: \"0.1.0\"\n",
        "name: block-description\n",
        "description: |\n",
        "  A valid block scalar with a single \" character\n",
    );

    let spec = match HushSpec::parse(input) {
        Ok(spec) => spec,
        Err(err) => panic!("block scalar quotes should parse: {err}"),
    };
    assert_eq!(
        spec.description.as_deref(),
        Some("A valid block scalar with a single \" character\n")
    );
}

#[test]
fn parse_allows_block_scalar_for_quoted_key_with_colon() {
    let input = concat!(
        "hushspec: \"0.1.0\"\n",
        "name: quoted-key-block-scalar\n",
        "extensions:\n",
        "  runtime_assurance:\n",
        "    trusted_verifiers:\n",
        "      local:\n",
        "        schema: local\n",
        "        verifier: test\n",
        "        effective_tier: verified\n",
        "        required_assertions:\n",
        "          \"a:b\": |\n",
        "            foo: \"bar\n",
    );

    let spec = match HushSpec::parse(input) {
        Ok(spec) => spec,
        Err(err) => panic!("quoted key block scalar should parse: {err}"),
    };
    let value = spec
        .extensions
        .and_then(|extensions| extensions.runtime_assurance)
        .and_then(|runtime_assurance| runtime_assurance.trusted_verifiers.get("local").cloned())
        .and_then(|verifier| verifier.required_assertions.get("a:b").cloned());
    assert_eq!(value.as_deref(), Some("foo: \"bar\n"));
}

#[test]
fn parse_allows_sequence_block_scalar_with_unpaired_double_quote() {
    let input = concat!(
        "hushspec: \"0.1.0\"\n",
        "name: sequence-block-pattern\n",
        "rules:\n",
        "  shell_commands:\n",
        "    forbidden_patterns:\n",
        "      - |\n",
        "        \"quoted regex text\n",
    );

    let spec = match HushSpec::parse(input) {
        Ok(spec) => spec,
        Err(err) => panic!("sequence block scalar quotes should parse: {err}"),
    };
    let rules = match spec.rules {
        Some(rules) => rules,
        None => panic!("rules should parse"),
    };
    let shell_commands = match rules.shell_commands {
        Some(shell_commands) => shell_commands,
        None => panic!("shell command rules should parse"),
    };
    assert_eq!(
        shell_commands.forbidden_patterns,
        vec!["\"quoted regex text\n".to_string()]
    );
}

#[test]
fn parse_allows_comment_line_with_unpaired_double_quote() {
    let input = concat!(
        "# note: \"comment-only quote\n",
        "hushspec: \"0.1.0\"\n",
        "name: comment-description\n",
        "description: Valid policy\n",
    );

    let spec = match HushSpec::parse(input) {
        Ok(spec) => spec,
        Err(err) => panic!("comment-only quote should parse: {err}"),
    };
    assert_eq!(spec.name.as_deref(), Some("comment-description"));
}

#[test]
fn block_scalar_detection_uses_last_colon() {
    assert!(block_scalar_parent_indent_start("description: |").is_some());
    assert!(block_scalar_parent_indent_start("\"a:b\": |").is_some());
    assert!(block_scalar_parent_indent_start("'a:b': |").is_some());
    assert!(block_scalar_parent_indent_start("  - |").is_some());
    assert!(block_scalar_parent_indent_start("  - >").is_some());
    assert!(block_scalar_parent_indent_start("  - not-block").is_none());
    assert!(block_scalar_parent_indent_start("# note: |").is_none());
    assert!(block_scalar_parent_indent_start("description: nested: |").is_none());
}
