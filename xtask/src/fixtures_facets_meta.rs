// Committed-fixture metadata assertions for the alert routing/handoff/delivery/
// assurance facets and the shared label-hygiene / canonical-hash helpers they
// use. Included into `fixtures.rs` via `include!` so it shares that module's
// private helpers (load_json, glob_documents, str_field, invalid,
// metadata_negative_*).

/// Committed-fixture invariants for the handoff facet beyond the negative
/// corpus: the handoff profile must carry no inline secrets, dynamic endpoints,
/// duplicate targets, or duplicate route coverage; the committed handoff report
/// must be dry-run accepted, preserve critical firing visibility, and carry the
/// primary downstream route.
fn metadata_relay_alert_handoff(fixture_dir: &Path) -> Result<(), XtaskError> {
    let profile = load_json(&fixture_dir.join("relay-alert-handoff-profile.json"))?;
    if str_field(&profile, "schema") != Some("chio.pheromone.relay-alert-handoff-profile.v1") {
        return Err(invalid("handoff profile schema mismatch"));
    }
    let mut targets = std::collections::BTreeSet::new();
    let mut route_pairs = std::collections::BTreeSet::new();
    if let Some(receivers) = profile.get("receivers").and_then(Value::as_array) {
        for receiver in receivers {
            if json_contains_secret_marker(receiver) {
                return Err(invalid("handoff receiver may contain inline secret material"));
            }
            if str_field(receiver, "targetRef")
                .map(|t| t.contains("://"))
                .unwrap_or(false)
            {
                return Err(invalid("handoff receiver uses dynamic endpoint"));
            }
            let target = str_field(receiver, "targetRef").unwrap_or_default().to_string();
            if !targets.insert(target) {
                return Err(invalid("duplicate handoff target"));
            }
            let pair = (
                str_field(receiver, "notificationRoute").unwrap_or_default().to_string(),
                str_field(receiver, "opsgenie").unwrap_or_default().to_string(),
            );
            if !route_pairs.insert(pair) {
                return Err(invalid("duplicate handoff route coverage"));
            }
        }
    }

    let report = load_json(&fixture_dir.join("relay-alert-handoff-report.json"))?;
    if report.get("accepted") != Some(&Value::Bool(true))
        || str_field(&report, "code") != Some("accepted")
    {
        return Err(invalid("handoff fixture report must be dry-run accepted"));
    }
    if report.get("criticalFiringCount").and_then(Value::as_i64).unwrap_or(0) < 1 {
        return Err(invalid(
            "handoff fixture report must preserve critical firing alert visibility",
        ));
    }
    if !report_routes_contain(&report, "alertmanager:pagerduty-primary") {
        return Err(invalid("handoff fixture report missing primary downstream route"));
    }

    metadata_negative_ids(
        fixture_dir,
        "relay-alert-handoff-negative-cases.json",
        &HANDOFF_REQUIRED_CASES,
    )
}

/// Committed-fixture invariants for the delivery facet beyond the negative
/// corpus: the delivery profile receivers must carry no secrets / dynamic
/// endpoints / duplicate ids or targets; every committed delivery-evidence
/// fixture must have the right schema, no secret material, only bounded labels,
/// and no forbidden label class; and the committed delivery / acknowledgement /
/// drift reports must be accepted with their expected counts.
fn metadata_relay_alert_delivery(fixture_dir: &Path) -> Result<(), XtaskError> {
    let profile = load_json(&fixture_dir.join("relay-alert-delivery-profile.json"))?;
    if str_field(&profile, "schema") != Some("chio.pheromone.relay-alert-delivery-profile.v1") {
        return Err(invalid("delivery profile schema mismatch"));
    }
    let mut receiver_ids = std::collections::BTreeSet::new();
    let mut targets = std::collections::BTreeSet::new();
    if let Some(receivers) = profile.get("receivers").and_then(Value::as_array) {
        for receiver in receivers {
            if json_contains_secret_marker(receiver) {
                return Err(invalid("delivery receiver may contain secret material"));
            }
            if str_field(receiver, "targetRef")
                .map(|t| t.contains("://"))
                .unwrap_or(false)
            {
                return Err(invalid("delivery receiver uses dynamic endpoint"));
            }
            let receiver_id = str_field(receiver, "receiverId").unwrap_or_default().to_string();
            if !receiver_ids.insert(receiver_id) {
                return Err(invalid("duplicate delivery receiver"));
            }
            let target = str_field(receiver, "targetRef").unwrap_or_default().to_string();
            if !targets.insert(target) {
                return Err(invalid("duplicate delivery target"));
            }
        }
    }

    let allowed_labels = [
        "notification_route",
        "opsgenie",
        "service",
        "severity",
        "status",
        "receiver",
    ];
    let evidence_files =
        glob_documents(fixture_dir, Some("relay-alert-delivery-evidence-*.json"))?;
    for evidence_path in evidence_files {
        let evidence = load_json(&evidence_path)?;
        if str_field(&evidence, "schema") != Some("chio.pheromone.relay-alert-delivery-evidence.v1")
        {
            return Err(invalid("delivery evidence schema mismatch"));
        }
        if json_contains_secret_marker(&evidence) {
            return Err(invalid("delivery evidence may contain secret material"));
        }
        if let Some(labels) = evidence.get("labels").and_then(Value::as_object) {
            for name in labels.keys() {
                if !allowed_labels.contains(&name.as_str()) {
                    return Err(invalid("delivery evidence has unbounded labels"));
                }
                for forbidden in ["peer", "treaty", "hash", "nonce", "cursor", "endpoint"] {
                    if name.contains(forbidden) {
                        return Err(invalid("delivery evidence leaks forbidden label class"));
                    }
                }
            }
        }
    }

    let delivery = load_json(&fixture_dir.join("relay-alert-delivery-report.json"))?;
    if delivery.get("accepted") != Some(&Value::Bool(true))
        || str_field(&delivery, "code") != Some("accepted")
    {
        return Err(invalid("delivery fixture report must be accepted"));
    }
    if delivery.get("deliveredCount").and_then(Value::as_i64).unwrap_or(0) < 1 {
        return Err(invalid(
            "delivery fixture report must include downstream delivery evidence",
        ));
    }
    let ack = load_json(&fixture_dir.join("relay-alert-acknowledgement-report.json"))?;
    if ack.get("accepted") != Some(&Value::Bool(true))
        || ack.get("acknowledgedCount").and_then(Value::as_i64).unwrap_or(0) < 1
    {
        return Err(invalid(
            "acknowledgement fixture report must summarize downstream outcomes",
        ));
    }
    let drift = load_json(&fixture_dir.join("relay-alert-handoff-drift-report.json"))?;
    if drift.get("accepted") != Some(&Value::Bool(true))
        || drift.get("driftCount").and_then(Value::as_i64) != Some(0)
    {
        return Err(invalid("drift fixture report must be accepted"));
    }

    metadata_negative_ids(
        fixture_dir,
        "relay-alert-delivery-negative-cases.json",
        &DELIVERY_REQUIRED_CASES,
    )
}

/// Committed-fixture invariants for the assurance facet beyond the negative
/// corpus: the normalization profile receivers must carry no secrets / dynamic
/// endpoints / duplicate ids; the route-owner profile owners must carry no
/// secrets / contact material (`://` or `@`) / duplicate aliases; and the
/// committed assurance package must preserve the unhealthy active-alert state.
fn metadata_relay_alert_assurance(fixture_dir: &Path) -> Result<(), XtaskError> {
    let profile = load_json(&fixture_dir.join("relay-alert-normalization-profile.json"))?;
    let mut receiver_ids = std::collections::BTreeSet::new();
    if let Some(receivers) = profile.get("receivers").and_then(Value::as_array) {
        for receiver in receivers {
            if json_contains_secret_marker(receiver) {
                return Err(invalid("normalization receiver may contain secret material"));
            }
            if str_field(receiver, "targetRef")
                .map(|t| t.contains("://"))
                .unwrap_or(false)
            {
                return Err(invalid("normalization receiver uses dynamic endpoint"));
            }
            let receiver_id = str_field(receiver, "receiverId").unwrap_or_default().to_string();
            if !receiver_ids.insert(receiver_id) {
                return Err(invalid("duplicate normalization receiver"));
            }
        }
    }

    let owner_profile = load_json(&fixture_dir.join("relay-alert-route-owner-profile.json"))?;
    let mut owner_aliases = std::collections::BTreeSet::new();
    if let Some(owners) = owner_profile.get("owners").and_then(Value::as_array) {
        for owner in owners {
            if json_contains_secret_marker(owner) {
                return Err(invalid("route owner may contain contact or secret material"));
            }
            let encoded = owner.to_string();
            if encoded.contains("://") || encoded.contains('@') {
                return Err(invalid("route owner uses contact material"));
            }
            let alias = str_field(owner, "ownerAlias").unwrap_or_default().to_string();
            if !owner_aliases.insert(alias) {
                return Err(invalid("duplicate route owner"));
            }
        }
    }

    let assurance = load_json(&fixture_dir.join("relay-alert-assurance-package.json"))?;
    if str_field(&assurance, "schema") != Some("chio.pheromone.relay-alert-assurance-package.v1") {
        return Err(invalid("assurance package schema mismatch"));
    }
    if assurance.get("accepted") != Some(&Value::Bool(false)) {
        return Err(invalid(
            "fixture assurance package must preserve unhealthy active-alert state",
        ));
    }
    let has_active = assurance
        .get("operatorActionCodes")
        .and_then(Value::as_array)
        .map(|codes| codes.iter().any(|c| c.as_str() == Some("active_alerts_present")))
        .unwrap_or(false);
    if !has_active {
        return Err(invalid("assurance package missing active alert action code"));
    }

    metadata_negative_case_ids(
        fixture_dir,
        "relay-alert-assurance-negative-cases.json",
        &ASSURANCE_REQUIRED_CASES,
    )
}

/// Committed-fixture invariants for the assurance-export facet beyond the
/// negative corpus: the committed `export-bundle/manifest.json` must have the
/// right schema, a canonical 64-hex source package hash, no forbidden safety
/// claims, and only safe artifact paths free of secret markers.
fn metadata_relay_alert_assurance_export(fixture_dir: &Path) -> Result<(), XtaskError> {
    let manifest = load_json(&fixture_dir.join("export-bundle/manifest.json"))?;
    if str_field(&manifest, "schema")
        != Some("chio.pheromone.relay-alert-assurance-export-manifest.v1")
    {
        return Err(invalid("export manifest schema mismatch"));
    }
    let body = manifest
        .get("body")
        .ok_or_else(|| invalid("export manifest has no body"))?;
    if !is_canonical_sha256(str_field(body, "sourcePackageSha256")) {
        return Err(invalid("export manifest source package hash is malformed"));
    }
    if let Some(claims) = body.get("safetyClaims").and_then(Value::as_array) {
        for claim in claims {
            if matches!(
                claim.as_str(),
                Some("live_notification_delivery") | Some("credentialed_dispatch")
            ) {
                return Err(invalid("export manifest claims live notification delivery"));
            }
        }
    }
    if let Some(artifacts) = body.get("artifacts").and_then(Value::as_array) {
        for artifact in artifacts {
            let path = str_field(artifact, "path").unwrap_or_default();
            if path.starts_with('/')
                || path.contains("..")
                || path.contains('\\')
                || path.contains(':')
            {
                return Err(invalid("unsafe export artifact path"));
            }
            if json_contains_secret_marker(artifact) {
                return Err(invalid("export manifest artifact contains secret marker"));
            }
        }
    }

    metadata_negative_case_ids(
        fixture_dir,
        "relay-alert-assurance-export-negative-cases.json",
        &[
            "invalid_signature",
            "source_hash_mismatch",
            "path_traversal",
            "wrong_expected_code",
        ],
    )
}

/// Whether a report's `routes[].targetRef` set contains a given target. Shared by
/// the handoff metadata assertion (mirrors `alert_routes_contain` in the alert
/// handler, which is defined in a sibling include).
fn report_routes_contain(report: &Value, target: &str) -> bool {
    report
        .get("routes")
        .and_then(Value::as_array)
        .map(|routes| {
            routes
                .iter()
                .any(|route| str_field(route, "targetRef") == Some(target))
        })
        .unwrap_or(false)
}

/// True if the JSON-serialized form of `value` contains a case-insensitive
/// secret marker (the scripts' `(?i)(token|secret|password|bearer|api[_-]?key)`
/// regex over `json.dumps(value)`).
fn json_contains_secret_marker(value: &Value) -> bool {
    let encoded = value.to_string().to_ascii_lowercase();
    for needle in ["token", "secret", "password", "bearer"] {
        if encoded.contains(needle) {
            return true;
        }
    }
    // api_key / api-key / apikey
    contains_api_key(&encoded)
}

/// Match the `api[_-]?key` alternative of the secret-marker regex over an
/// already-lowercased haystack.
fn contains_api_key(lower: &str) -> bool {
    let bytes = lower.as_bytes();
    let mut index = 0;
    while let Some(found) = lower[index..].find("api") {
        let after = index + found + 3;
        let rest = &bytes[after..];
        let key_at = match rest.first() {
            Some(b'_') | Some(b'-') => &rest[1..],
            _ => rest,
        };
        if key_at.starts_with(b"key") {
            return true;
        }
        index = after;
    }
    false
}

/// True if a label value leaks an unbounded identifier: a DID, a treaty ref, a
/// run of 32+ hex chars, or the substrings nonce/cursor/outbox (the routing
/// script's `did:chio|treaty:|[0-9a-f]{32,}|nonce|cursor|outbox` check,
/// case-insensitive).
fn value_leaks_unbounded_label(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if lower.contains("did:chio")
        || lower.contains("treaty:")
        || lower.contains("nonce")
        || lower.contains("cursor")
        || lower.contains("outbox")
    {
        return true;
    }
    // A run of 32 or more hexadecimal characters.
    let mut run = 0usize;
    for ch in lower.chars() {
        if ch.is_ascii_digit() || ('a'..='f').contains(&ch) {
            run += 1;
            if run >= 32 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// True if `value` is a 64-character lowercase hexadecimal string (the scripts'
/// `len(value) == 64 and all(char in "0123456789abcdef")` canonical-hash check).
fn is_canonical_sha256(value: Option<&str>) -> bool {
    match value {
        Some(hex) => {
            hex.len() == 64 && hex.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        }
        None => false,
    }
}
