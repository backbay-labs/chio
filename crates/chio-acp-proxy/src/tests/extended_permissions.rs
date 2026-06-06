#[test]
fn permission_mapper_all_four_kinds() {
    let mapper = PermissionMapper::new(7200);

    let cases = vec![
        ("allow_once", PermissionDecision::AllowOnce),
        (
            "allow_always",
            PermissionDecision::AllowScoped {
                duration_secs: 7200,
            },
        ),
        ("reject_once", PermissionDecision::Deny),
        ("reject_always", PermissionDecision::DenyPermanent),
    ];

    for (kind, expected_decision) in cases {
        let option = PermissionOption {
            option_id: format!("opt-{kind}"),
            name: kind.to_string(),
            kind: kind.to_string(),
        };
        let mapped = mapper.map_option(&option);
        assert_eq!(
            mapped.chio_decision, expected_decision,
            "kind '{kind}' should map to {expected_decision:?}"
        );
        assert_eq!(mapped.original_option_id, format!("opt-{kind}"));
    }
}

#[test]
fn permission_mapper_unknown_kind_defaults_to_deny() {
    let mapper = PermissionMapper::new(3600);
    let option = PermissionOption {
        option_id: "opt-mystery".to_string(),
        name: "Mystery".to_string(),
        kind: "future_kind".to_string(),
    };
    let mapped = mapper.map_option(&option);
    assert_eq!(mapped.chio_decision, PermissionDecision::Deny);
}

#[test]
fn permission_mapper_empty_kind_string_defaults_to_deny() {
    let mapper = PermissionMapper::new(3600);
    let option = PermissionOption {
        option_id: "opt-empty".to_string(),
        name: "Empty".to_string(),
        kind: String::new(),
    };
    let mapped = mapper.map_option(&option);
    assert_eq!(mapped.chio_decision, PermissionDecision::Deny);
}

#[test]
fn permission_mapper_preserves_original_option_id() {
    let mapper = PermissionMapper::new(3600);
    let option = PermissionOption {
        option_id: "unique-id-42".to_string(),
        name: "Allow".to_string(),
        kind: "allow_once".to_string(),
    };
    let mapped = mapper.map_option(&option);
    assert_eq!(mapped.original_option_id, "unique-id-42");
}

#[test]
fn permission_mapper_scoped_duration_reflects_constructor() {
    let mapper = PermissionMapper::new(900); // 15 minutes
    let option = PermissionOption {
        option_id: "opt-scoped".to_string(),
        name: "Always".to_string(),
        kind: "allow_always".to_string(),
    };
    let mapped = mapper.map_option(&option);
    assert_eq!(
        mapped.chio_decision,
        PermissionDecision::AllowScoped { duration_secs: 900 }
    );
}

// ================================================================
// 6. Receipt/Audit Entry
// ================================================================
