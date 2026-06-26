use super::*;

pub fn proof_room_fixture_failure_code(error: &str) -> &str {
    match error.split(':').next() {
        Some(code) => code,
        None => error,
    }
}

pub(crate) fn proof_room_fixture_verifier_failure_message(
    fixture_id: &str,
    error: impl std::fmt::Display,
) -> String {
    format!("proof-room.fixture.verify-failed: {fixture_id}: {error}")
}

pub(crate) fn proof_room_failed_verifier_report(
    fixture_id: &str,
    passport: &chio_transaction_passport::TransactionPassport,
    error: &str,
) -> Result<(Vec<u8>, &'static str), (StatusCode, String)> {
    let report = serde_json::json!({
        "schema": "chio.transaction.verifier-report.v1",
        "id": format!("verifier-report-{}", passport.id),
        "issued_at": passport.issued_at,
        "verdict": "failed",
        "passport_id": passport.id,
        "passport_path": "transaction-passport.json",
        "evidence_graph_sha256": passport.evidence_graph_sha256,
        "evidence_graph_path": passport.evidence_graph_path,
        "verifier_policy_sha256": passport.verifier_policy_sha256,
        "verifier_policy_path": passport.verifier_policy_path,
        "failure_code": proof_room_fixture_failure_code(error),
        "error": error,
    });
    let contents = serde_json::to_vec(&report).map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("proof-room.fixture.failed-report-encode: {fixture_id}: {error}"),
        )
    })?;
    Ok((contents, "application/json"))
}

pub(crate) fn proof_room_fixture_verified_report_bytes<T, E>(
    fixture_id: &str,
    passport: &chio_transaction_passport::TransactionPassport,
    result: Result<T, E>,
) -> Result<Vec<u8>, (StatusCode, String)>
where
    T: serde::Serialize,
    E: std::fmt::Display,
{
    let report = match result {
        Ok(report) => report,
        Err(error) => {
            return proof_room_failed_verifier_report(
                fixture_id,
                passport,
                &proof_room_fixture_verifier_failure_message(fixture_id, error),
            )
            .map(|(contents, _)| contents);
        }
    };
    proof_room_fixture_report_bytes(fixture_id, &report)
}

pub(crate) fn proof_room_fixture_report_bytes<T: serde::Serialize>(
    fixture_id: &str,
    report: &T,
) -> Result<Vec<u8>, (StatusCode, String)> {
    serde_json::to_vec(report).map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("proof-room.fixture.report-encode: {fixture_id}: {error}"),
        )
    })
}

pub(crate) fn proof_room_fixture_claim_requirements(
    fixture_id: &str,
    verifier_policy_bytes: &[u8],
) -> Result<SourceVerifierClaimRequirements, (StatusCode, String)> {
    source_verifier_claim_requirements(verifier_policy_bytes).map_err(|error| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "proof-room.fixture.policy-invalid: {fixture_id}: {}",
                proof_room_fixture_policy_error_message(&error)
            ),
        )
    })
}

pub(crate) fn proof_room_fixture_policy_error_message(error: &str) -> String {
    if let Some(error) = error.strip_prefix("proof-room.verifier-policy.invalid-json: ") {
        return format!("verifier policy is not valid JSON: {error}");
    }
    if error == "proof-room.verifier-policy.required-claim-invalid" {
        return "required claim must be a string".to_string();
    }
    error.to_string()
}

#[derive(Clone, Copy)]
pub(crate) enum ProofRoomFixtureReportRoute {
    Commerce,
    DisclosureLineage,
    Swarm,
    PublicSettlement,
    StandaloneRisk,
    TrustMarket,
    Enterprise,
    AgentWeb,
    Runtime,
    MinimalPassport,
}

pub(crate) struct ProofRoomFixtureClaimRoute {
    prefix: &'static str,
    route: ProofRoomFixtureReportRoute,
}

pub(crate) const PRIMARY_PROOF_ROOM_FIXTURE_ROUTES: &[ProofRoomFixtureClaimRoute] = &[
    ProofRoomFixtureClaimRoute {
        prefix: CLAIM_PREFIX_COMMERCE,
        route: ProofRoomFixtureReportRoute::Commerce,
    },
    ProofRoomFixtureClaimRoute {
        prefix: CLAIM_PREFIX_DISCLOSURE,
        route: ProofRoomFixtureReportRoute::DisclosureLineage,
    },
    ProofRoomFixtureClaimRoute {
        prefix: CLAIM_PREFIX_SWARM,
        route: ProofRoomFixtureReportRoute::Swarm,
    },
    ProofRoomFixtureClaimRoute {
        prefix: CLAIM_PREFIX_PUBLIC_SETTLEMENT,
        route: ProofRoomFixtureReportRoute::PublicSettlement,
    },
];

pub(crate) const SECONDARY_PROOF_ROOM_FIXTURE_ROUTES: &[ProofRoomFixtureClaimRoute] = &[
    ProofRoomFixtureClaimRoute {
        prefix: CLAIM_PREFIX_AGENT_WEB,
        route: ProofRoomFixtureReportRoute::AgentWeb,
    },
    ProofRoomFixtureClaimRoute {
        prefix: CLAIM_PREFIX_RUNTIME,
        route: ProofRoomFixtureReportRoute::Runtime,
    },
];

pub(crate) fn proof_room_fixture_asset(
    fixture_id: &str,
    asset_path: &str,
) -> Result<(Vec<u8>, &'static str), (StatusCode, String)> {
    proof_room_fixture_asset_with_root(fixture_id, asset_path, None)
}

pub(crate) fn proof_room_fixture_asset_with_root(
    fixture_id: &str,
    asset_path: &str,
    installed_fixture_root: Option<&Path>,
) -> Result<(Vec<u8>, &'static str), (StatusCode, String)> {
    let fixture = available_fixture_descriptor(fixture_id, installed_fixture_root)?;
    let asset_path = validate_fixture_asset_path(asset_path)?;
    let source = ProofRoomFixtureSource::new(&fixture, installed_fixture_root)?;
    if asset_path == "verifier-report.json" && fixture.kind == "proof-room" {
        let contents = source.file(asset_path, fixture_id)?;
        return Ok((contents, fixture_asset_content_type(asset_path)));
    }
    if asset_path == "verifier-report.json" && fixture.kind == "disclosure-crypto-context" {
        let context_bytes = source.file("verification-context.json", fixture_id)?;
        let report_bytes = source.file("crypto-context-report.json", fixture_id)?;
        let proof_bytes = source.file("selective-disclosure-proof.json", fixture_id)?;
        let privacy_profile_bytes = source.file("verifier-privacy-profile.json", fixture_id)?;
        let contents = crypto_context_verified_report_bytes_with_bbs(
            &context_bytes,
            &report_bytes,
            &proof_bytes,
            &privacy_profile_bytes,
            fixture_id,
        )
        .map_err(|error| (StatusCode::UNPROCESSABLE_ENTITY, error))?;
        return Ok((contents, fixture_asset_content_type(asset_path)));
    }
    if asset_path == "verifier-report.json" && fixture.kind == "negative-disclosure-crypto-context"
    {
        return proof_room_crypto_context_rejection_report(fixture_id, &source);
    }
    if asset_path == "verifier-report.json" && fixture.kind == "workflow-preflight" {
        return proof_room_workflow_preflight_report(fixture_id, &source);
    }
    if asset_path == "verifier-report.json" {
        return proof_room_fixture_verifier_report(fixture_id, &source);
    }
    ensure_fixture_asset_advertised(&fixture, &source, fixture_id, asset_path)?;
    let contents = source.file(asset_path, fixture_id)?;

    Ok((contents, fixture_asset_content_type(asset_path)))
}

pub(crate) fn ensure_fixture_asset_advertised(
    fixture: &ProofRoomAvailableFixture,
    source: &ProofRoomFixtureSource,
    fixture_id: &str,
    asset_path: &str,
) -> Result<(), (StatusCode, String)> {
    let allowed = allowed_fixture_asset_paths(fixture, source, fixture_id)?;
    if allowed.contains(asset_path) {
        return Ok(());
    }
    Err((
        StatusCode::NOT_FOUND,
        format!("proof-room.fixture.asset-not-found: {fixture_id}/{asset_path}"),
    ))
}

pub(crate) fn allowed_fixture_asset_paths(
    fixture: &ProofRoomAvailableFixture,
    source: &ProofRoomFixtureSource,
    fixture_id: &str,
) -> Result<BTreeSet<String>, (StatusCode, String)> {
    let mut allowed = BTreeSet::new();
    insert_allowed_fixture_asset(&mut allowed, "verifier-report.json", fixture_id)?;

    match fixture.kind.as_str() {
        "proof-room" => {
            insert_proof_room_fixture_bundle_assets(&mut allowed, source, fixture_id)?;
        }
        "workflow-preflight" => {
            insert_allowed_fixture_asset(&mut allowed, "preflight-plan.json", fixture_id)?;
        }
        "disclosure-crypto-context" => {
            insert_allowed_fixture_assets(
                &mut allowed,
                fixture_id,
                &[
                    "verification-context.json",
                    "crypto-context-report.json",
                    "selective-disclosure-proof.json",
                    "key-state.json",
                    "revocation-snapshot.json",
                    "transparency-inclusion-proof.json",
                    "verifier-privacy-profile.json",
                ],
            )?;
        }
        "negative-disclosure-crypto-context" => {
            insert_allowed_fixture_assets(
                &mut allowed,
                fixture_id,
                &[
                    "verification-context.json",
                    "selective-disclosure-proof.json",
                    "verifier-privacy-profile.json",
                ],
            )?;
        }
        "transaction-passport" | "negative-transaction-passport" => {
            insert_transaction_fixture_assets(&mut allowed, source, fixture_id)?;
        }
        _ => {}
    }

    Ok(allowed)
}

pub(crate) fn insert_transaction_fixture_assets(
    allowed: &mut BTreeSet<String>,
    source: &ProofRoomFixtureSource,
    fixture_id: &str,
) -> Result<(), (StatusCode, String)> {
    insert_allowed_fixture_assets(
        allowed,
        fixture_id,
        &[
            "transaction-passport.json",
            "evidence-graph.json",
            "verifier-policy.json",
        ],
    )?;

    let Ok(passport_bytes) = source.file("transaction-passport.json", fixture_id) else {
        return Ok(());
    };
    let Ok(passport) =
        serde_json::from_slice::<chio_transaction_passport::TransactionPassport>(&passport_bytes)
    else {
        return Ok(());
    };
    insert_allowed_fixture_asset(allowed, &passport.evidence_graph_path, fixture_id)?;
    insert_allowed_fixture_asset(allowed, &passport.verifier_policy_path, fixture_id)?;

    let Ok(evidence_graph_bytes) = source.file(&passport.evidence_graph_path, fixture_id) else {
        return Ok(());
    };
    let graph = parse_embedded_evidence_graph(&evidence_graph_bytes, "fixture evidence graph")
        .map_err(|error| (StatusCode::UNPROCESSABLE_ENTITY, error))?;
    for node in graph.nodes {
        insert_allowed_fixture_asset(allowed, &node.path, fixture_id)?;
    }
    Ok(())
}

pub(crate) fn insert_proof_room_fixture_bundle_assets(
    allowed: &mut BTreeSet<String>,
    source: &ProofRoomFixtureSource,
    fixture_id: &str,
) -> Result<(), (StatusCode, String)> {
    const BUNDLE_ROOT: &str = "proof-room-bundle";
    insert_allowed_fixture_asset(allowed, BUNDLE_ROOT, fixture_id)?;
    insert_allowed_fixture_asset(allowed, "proof-room-bundle/README.md", fixture_id)?;
    insert_allowed_fixture_asset(allowed, "proof-room-bundle/manifest.json", fixture_id)?;

    let Ok(manifest_bytes) = source.file("proof-room-bundle/manifest.json", fixture_id) else {
        return Ok(());
    };
    let manifest: ProofRoomBundleManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|error| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("proof-room.fixture.manifest-invalid: {fixture_id}: {error}"),
            )
        })?;

    insert_allowed_bundle_ref(
        allowed,
        BUNDLE_ROOT,
        &manifest.transaction_passport_ref.path,
        fixture_id,
    )?;
    insert_allowed_bundle_ref(
        allowed,
        BUNDLE_ROOT,
        &manifest.evidence_graph_ref.path,
        fixture_id,
    )?;
    insert_allowed_bundle_ref(
        allowed,
        BUNDLE_ROOT,
        &manifest.verifier_report_ref.path,
        fixture_id,
    )?;
    if let Some(report_ref) = manifest.proof_room_verifier_report_ref.as_ref() {
        insert_allowed_bundle_ref(allowed, BUNDLE_ROOT, &report_ref.path, fixture_id)?;
    }
    for artifact in &manifest.artifacts {
        insert_allowed_bundle_ref(allowed, BUNDLE_ROOT, &artifact.path, fixture_id)?;
    }
    for negative_case in &manifest.negative_cases {
        insert_allowed_bundle_ref(allowed, BUNDLE_ROOT, &negative_case.path, fixture_id)?;
        insert_proof_room_negative_case_asset_refs(
            allowed,
            source,
            fixture_id,
            BUNDLE_ROOT,
            &negative_case.path,
        )?;
    }
    for coverage in &manifest.receipt_coverage {
        if let Some(artifact_path) = coverage.artifact_path.as_deref() {
            insert_allowed_bundle_ref(allowed, BUNDLE_ROOT, artifact_path, fixture_id)?;
        }
    }
    if let Some(signature) = manifest.signature.as_ref() {
        insert_allowed_bundle_ref(allowed, BUNDLE_ROOT, &signature.signature_ref, fixture_id)?;
    }
    Ok(())
}

pub(crate) fn insert_proof_room_negative_case_asset_refs(
    allowed: &mut BTreeSet<String>,
    source: &ProofRoomFixtureSource,
    fixture_id: &str,
    bundle_root: &str,
    negative_case_path: &str,
) -> Result<(), (StatusCode, String)> {
    if !negative_case_path.ends_with("/transaction-passport.json") {
        return Ok(());
    }
    let Some((negative_dir, _passport_file)) = negative_case_path.rsplit_once('/') else {
        return Ok(());
    };
    let passport_asset_path = format!("{bundle_root}/{negative_case_path}");
    let passport_bytes = source.file(&passport_asset_path, fixture_id)?;
    let passport: chio_transaction_passport::TransactionPassport =
        serde_json::from_slice(&passport_bytes).map_err(|error| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!(
                    "proof-room.fixture.negative-passport-invalid: {fixture_id}: {negative_case_path}: {error}"
                ),
            )
        })?;

    let evidence_graph_path =
        negative_case_bundle_member_path(negative_dir, &passport.evidence_graph_path, fixture_id)?;
    let verifier_policy_path =
        negative_case_bundle_member_path(negative_dir, &passport.verifier_policy_path, fixture_id)?;
    insert_allowed_bundle_ref(allowed, bundle_root, &evidence_graph_path, fixture_id)?;
    insert_allowed_bundle_ref(allowed, bundle_root, &verifier_policy_path, fixture_id)?;

    let evidence_graph_asset_path = format!("{bundle_root}/{evidence_graph_path}");
    let evidence_graph_bytes = source.file(&evidence_graph_asset_path, fixture_id)?;
    let graph = parse_embedded_evidence_graph(
        &evidence_graph_bytes,
        "proof room fixture negative evidence graph",
    )
    .map_err(|error| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "proof-room.fixture.negative-evidence-graph-invalid: {fixture_id}: {evidence_graph_path}: {error}"
            ),
        )
    })?;
    for node in graph.nodes {
        let artifact_path = negative_case_bundle_member_path(negative_dir, &node.path, fixture_id)?;
        insert_allowed_bundle_ref(allowed, bundle_root, &artifact_path, fixture_id)?;
    }
    Ok(())
}

pub(crate) fn negative_case_bundle_member_path(
    negative_dir: &str,
    member_path: &str,
    fixture_id: &str,
) -> Result<String, (StatusCode, String)> {
    validate_fixture_asset_path(member_path).map_err(|(_status, error)| {
        (
            StatusCode::BAD_REQUEST,
            format!("proof-room.fixture.asset-path-invalid: {fixture_id}/{member_path}: {error}"),
        )
    })?;
    let path = format!("{negative_dir}/{member_path}");
    validate_fixture_asset_path(&path).map_err(|(_status, error)| {
        (
            StatusCode::BAD_REQUEST,
            format!("proof-room.fixture.asset-path-invalid: {fixture_id}/{path}: {error}"),
        )
    })?;
    Ok(path)
}

pub(crate) fn insert_allowed_bundle_ref(
    allowed: &mut BTreeSet<String>,
    bundle_root: &str,
    path: &str,
    fixture_id: &str,
) -> Result<(), (StatusCode, String)> {
    validate_fixture_asset_path(path)?;
    let asset_path = format!("{bundle_root}/{path}");
    insert_allowed_fixture_asset(allowed, &asset_path, fixture_id)
}

pub(crate) fn insert_allowed_fixture_assets(
    allowed: &mut BTreeSet<String>,
    fixture_id: &str,
    asset_paths: &[&str],
) -> Result<(), (StatusCode, String)> {
    for asset_path in asset_paths {
        insert_allowed_fixture_asset(allowed, asset_path, fixture_id)?;
    }
    Ok(())
}

pub(crate) fn insert_allowed_fixture_asset(
    allowed: &mut BTreeSet<String>,
    asset_path: &str,
    fixture_id: &str,
) -> Result<(), (StatusCode, String)> {
    validate_fixture_asset_path(asset_path).map_err(|(_status, error)| {
        (
            StatusCode::BAD_REQUEST,
            format!("proof-room.fixture.asset-path-invalid: {fixture_id}/{asset_path}: {error}"),
        )
    })?;
    allowed.insert(asset_path.to_string());
    Ok(())
}

pub(crate) enum ProofRoomFixtureSource {
    Embedded { fixture_root: String },
    Installed { root: PathBuf, fixture_root: String },
}

impl ProofRoomFixtureSource {
    pub(crate) fn new(
        fixture: &ProofRoomAvailableFixture,
        installed_fixture_root: Option<&Path>,
    ) -> Result<Self, (StatusCode, String)> {
        let fixture_root = available_fixture_embedded_root(fixture)?;
        match installed_fixture_root {
            Some(root) => Ok(Self::Installed {
                root: installed_fixture_root_path(root, &fixture.id)?,
                fixture_root,
            }),
            None => Ok(Self::Embedded { fixture_root }),
        }
    }

    pub(crate) fn file(
        &self,
        asset_path: &str,
        fixture_id: &str,
    ) -> Result<Vec<u8>, (StatusCode, String)> {
        match self {
            Self::Embedded { fixture_root } => {
                embedded_fixture_file(fixture_root, asset_path, fixture_id)
                    .map(|bytes| bytes.to_vec())
            }
            Self::Installed { root, fixture_root } => {
                installed_fixture_file(root, fixture_root, asset_path, fixture_id)
            }
        }
    }

    pub(crate) fn artifact_map(
        &self,
        fixture_id: &str,
    ) -> Result<BTreeMap<String, Vec<u8>>, (StatusCode, String)> {
        match self {
            Self::Embedded { fixture_root } => Ok(embedded_fixture_artifact_map(fixture_root)),
            Self::Installed { root, fixture_root } => {
                installed_fixture_artifact_map(root, fixture_root, fixture_id)
            }
        }
    }

    pub(crate) fn installed_file_path(
        &self,
        asset_path: &str,
        fixture_id: &str,
    ) -> Result<Option<PathBuf>, (StatusCode, String)> {
        match self {
            Self::Embedded { .. } => Ok(None),
            Self::Installed { root, fixture_root } => {
                let fixture_dir = installed_fixture_directory(root, fixture_root, fixture_id)?;
                resolve_installed_fixture_asset(root, &fixture_dir, asset_path, fixture_id)
                    .map(Some)
            }
        }
    }
}

pub(crate) fn installed_fixture_root_path(
    installed_fixture_root: &Path,
    fixture_id: &str,
) -> Result<PathBuf, (StatusCode, String)> {
    fs::canonicalize(installed_fixture_root).map_err(|error| {
        (
            StatusCode::NOT_FOUND,
            format!("proof-room.fixture.root-unreadable: {fixture_id}: {error}"),
        )
    })
}

pub(crate) fn installed_fixture_directory(
    installed_fixture_root: &Path,
    fixture_root: &str,
    fixture_id: &str,
) -> Result<PathBuf, (StatusCode, String)> {
    let path = installed_fixture_root.join(fixture_root);
    let path = fs::canonicalize(&path).map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            format!("proof-room.fixture.root-not-found: {fixture_id}"),
        )
    })?;
    if !path.starts_with(installed_fixture_root) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("proof-room.fixture.root-path-escape: {fixture_id}"),
        ));
    }
    if !path.is_dir() {
        return Err((
            StatusCode::NOT_FOUND,
            format!("proof-room.fixture.root-not-found: {fixture_id}"),
        ));
    }
    Ok(path)
}

pub(crate) fn installed_fixture_file(
    installed_fixture_root: &Path,
    fixture_root: &str,
    asset_path: &str,
    fixture_id: &str,
) -> Result<Vec<u8>, (StatusCode, String)> {
    let fixture_dir =
        installed_fixture_directory(installed_fixture_root, fixture_root, fixture_id)?;
    let path = resolve_installed_fixture_asset(
        installed_fixture_root,
        &fixture_dir,
        asset_path,
        fixture_id,
    )?;
    let metadata = fs::metadata(&path).map_err(|error| {
        (
            StatusCode::NOT_FOUND,
            format!("proof-room.fixture.asset-not-found: {fixture_id}/{asset_path}: {error}"),
        )
    })?;
    if !metadata.is_file() {
        return Err((
            StatusCode::NOT_FOUND,
            format!("proof-room.fixture.asset-not-found: {fixture_id}/{asset_path}"),
        ));
    }
    fs::read(&path).map_err(|error| {
        (
            StatusCode::NOT_FOUND,
            format!("proof-room.fixture.asset-not-found: {fixture_id}/{asset_path}: {error}"),
        )
    })
}

pub(crate) fn resolve_installed_fixture_asset(
    installed_fixture_root: &Path,
    fixture_dir: &Path,
    asset_path: &str,
    fixture_id: &str,
) -> Result<PathBuf, (StatusCode, String)> {
    validate_fixture_asset_path(asset_path)?;
    let path = fs::canonicalize(fixture_dir.join(asset_path)).map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            format!("proof-room.fixture.asset-not-found: {fixture_id}/{asset_path}"),
        )
    })?;
    if !path.starts_with(installed_fixture_root) || !path.starts_with(fixture_dir) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("proof-room.fixture.asset-path-escape: {fixture_id}/{asset_path}"),
        ));
    }
    Ok(path)
}

pub(crate) fn installed_fixture_artifact_map(
    installed_fixture_root: &Path,
    fixture_root: &str,
    fixture_id: &str,
) -> Result<BTreeMap<String, Vec<u8>>, (StatusCode, String)> {
    let fixture_dir =
        installed_fixture_directory(installed_fixture_root, fixture_root, fixture_id)?;
    let mut artifacts = BTreeMap::new();
    collect_installed_fixture_artifacts(
        installed_fixture_root,
        &fixture_dir,
        &fixture_dir,
        fixture_id,
        &mut artifacts,
    )?;
    Ok(artifacts)
}

pub(crate) fn collect_installed_fixture_artifacts(
    installed_fixture_root: &Path,
    fixture_dir: &Path,
    directory: &Path,
    fixture_id: &str,
    artifacts: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), (StatusCode, String)> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| {
            (
                StatusCode::NOT_FOUND,
                format!("proof-room.fixture.root-unreadable: {fixture_id}: {error}"),
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            (
                StatusCode::NOT_FOUND,
                format!("proof-room.fixture.root-unreadable: {fixture_id}: {error}"),
            )
        })?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            (
                StatusCode::NOT_FOUND,
                format!("proof-room.fixture.asset-unreadable: {fixture_id}: {error}"),
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("proof-room.fixture.asset-symlink-unsupported: {fixture_id}"),
            ));
        }
        let canonical_path = fs::canonicalize(&path).map_err(|error| {
            (
                StatusCode::NOT_FOUND,
                format!("proof-room.fixture.asset-unreadable: {fixture_id}: {error}"),
            )
        })?;
        if !canonical_path.starts_with(installed_fixture_root)
            || !canonical_path.starts_with(fixture_dir)
        {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("proof-room.fixture.asset-path-escape: {fixture_id}"),
            ));
        }
        if metadata.is_dir() {
            collect_installed_fixture_artifacts(
                installed_fixture_root,
                fixture_dir,
                &canonical_path,
                fixture_id,
                artifacts,
            )?;
        } else if metadata.is_file() {
            let relative_path =
                installed_fixture_relative_path(fixture_dir, &canonical_path, fixture_id)?;
            let contents = fs::read(&canonical_path).map_err(|error| {
                (
                    StatusCode::NOT_FOUND,
                    format!(
                        "proof-room.fixture.asset-unreadable: {fixture_id}/{relative_path}: {error}"
                    ),
                )
            })?;
            artifacts.insert(relative_path, contents);
        } else {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("proof-room.fixture.asset-kind-unsupported: {fixture_id}"),
            ));
        }
    }
    Ok(())
}

pub(crate) fn installed_fixture_relative_path(
    fixture_dir: &Path,
    path: &Path,
    fixture_id: &str,
) -> Result<String, (StatusCode, String)> {
    let relative_path = path.strip_prefix(fixture_dir).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            format!("proof-room.fixture.asset-path-escape: {fixture_id}"),
        )
    })?;
    let relative_path = relative_path.to_string_lossy().replace('\\', "/");
    validate_fixture_asset_path(&relative_path)?;
    Ok(relative_path)
}

pub(crate) fn proof_room_fixture_verifier_report(
    fixture_id: &str,
    source: &ProofRoomFixtureSource,
) -> Result<(Vec<u8>, &'static str), (StatusCode, String)> {
    let passport_bytes = source.file("transaction-passport.json", fixture_id)?;
    let passport: chio_transaction_passport::TransactionPassport =
        serde_json::from_slice(&passport_bytes).map_err(|error| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("proof-room.fixture.passport-invalid: {fixture_id}: {error}"),
            )
        })?;
    let evidence_graph_bytes = source.file(&passport.evidence_graph_path, fixture_id)?;
    let verifier_policy_bytes = source.file(&passport.verifier_policy_path, fixture_id)?;
    let requirements = proof_room_fixture_claim_requirements(fixture_id, &verifier_policy_bytes)?;
    let artifacts = source.artifact_map(fixture_id)?;
    let route = proof_room_fixture_report_route(fixture_id, &requirements, &evidence_graph_bytes)?;
    let contents = proof_room_fixture_route_report_bytes(
        route,
        fixture_id,
        &passport,
        &evidence_graph_bytes,
        &verifier_policy_bytes,
        &artifacts,
    )?;

    Ok((contents, "application/json"))
}

pub(crate) fn proof_room_fixture_report_route(
    fixture_id: &str,
    requirements: &SourceVerifierClaimRequirements,
    evidence_graph_bytes: &[u8],
) -> Result<ProofRoomFixtureReportRoute, (StatusCode, String)> {
    let requires_risk = requirements.requires(CLAIM_PREFIX_RISK);
    let route_risk_through_trust_market = requires_risk
        && embedded_evidence_graph_has_role(
            evidence_graph_bytes,
            is_trust_market_risk_context_role,
        )
        .map_err(|error| proof_room_fixture_invalid(fixture_id, "evidence-graph", error))?;
    let route_risk_through_enterprise = requires_risk
        && embedded_evidence_graph_has_role(evidence_graph_bytes, is_enterprise_risk_context_role)
            .map_err(|error| proof_room_fixture_invalid(fixture_id, "evidence-graph", error))?;

    if let Some(route) =
        first_required_fixture_claim_route(requirements, PRIMARY_PROOF_ROOM_FIXTURE_ROUTES)
    {
        return Ok(route);
    }

    if requires_risk && !route_risk_through_enterprise && !route_risk_through_trust_market {
        return Ok(ProofRoomFixtureReportRoute::StandaloneRisk);
    }
    if requirements.requires(CLAIM_PREFIX_TRUST_MARKET) || route_risk_through_trust_market {
        return Ok(ProofRoomFixtureReportRoute::TrustMarket);
    }
    if requirements.requires(CLAIM_PREFIX_ENTERPRISE) || route_risk_through_enterprise {
        return Ok(ProofRoomFixtureReportRoute::Enterprise);
    }
    if let Some(route) =
        first_required_fixture_claim_route(requirements, SECONDARY_PROOF_ROOM_FIXTURE_ROUTES)
    {
        return Ok(route);
    }

    Ok(ProofRoomFixtureReportRoute::MinimalPassport)
}

pub(crate) fn first_required_fixture_claim_route(
    requirements: &SourceVerifierClaimRequirements,
    routes: &[ProofRoomFixtureClaimRoute],
) -> Option<ProofRoomFixtureReportRoute> {
    routes
        .iter()
        .find(|route| requirements.requires(route.prefix))
        .map(|route| route.route)
}

pub(crate) fn proof_room_fixture_route_report_bytes(
    route: ProofRoomFixtureReportRoute,
    fixture_id: &str,
    passport: &chio_transaction_passport::TransactionPassport,
    evidence_graph_bytes: &[u8],
    verifier_policy_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<u8>, (StatusCode, String)> {
    match route {
        ProofRoomFixtureReportRoute::Commerce => {
            let commerce_bundle =
                embedded_commerce_order_bundle(evidence_graph_bytes, artifacts, None)
                    .map_err(|error| proof_room_fixture_invalid(fixture_id, "commerce", error))?;
            proof_room_fixture_verified_report_bytes(
                fixture_id,
                passport,
                chio_commerce_order::verify_commerce_order(&commerce_bundle),
            )
        }
        ProofRoomFixtureReportRoute::DisclosureLineage => {
            let disclosure_bundle =
                embedded_disclosure_lineage_bundle(evidence_graph_bytes, artifacts).map_err(
                    |error| proof_room_fixture_invalid(fixture_id, "disclosure-lineage", error),
                )?;
            let trust = crate::disclosure_lineage_verifier_trust_from_env().map_err(|error| {
                proof_room_fixture_invalid(fixture_id, "disclosure-lineage", error)
            })?;
            proof_room_fixture_verified_report_bytes(
                fixture_id,
                passport,
                chio_disclosure_lineage::verify_disclosure_lineage_bundle_with_trust(
                    &disclosure_bundle,
                    &trust,
                ),
            )
        }
        ProofRoomFixtureReportRoute::Swarm => {
            let swarm_bundle = embedded_swarm_authority_bundle(evidence_graph_bytes, artifacts)
                .map_err(|error| proof_room_fixture_invalid(fixture_id, "swarm", error))?;
            let trusted_witness_keys = crate::swarm_trusted_witness_keys_for_bundle(&swarm_bundle)
                .map_err(|error| {
                    (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        format!("proof-room.fixture.swarm-invalid: {fixture_id}: {error}"),
                    )
                })?;
            proof_room_fixture_verified_report_bytes(
                fixture_id,
                passport,
                chio_swarm_authority::verify_swarm_authority_bundle(
                    &swarm_bundle,
                    &trusted_witness_keys,
                ),
            )
        }
        ProofRoomFixtureReportRoute::PublicSettlement => {
            let proof_bundle =
                embedded_public_settlement_proof_bundle(evidence_graph_bytes, artifacts).map_err(
                    |error| proof_room_fixture_invalid(fixture_id, "public-settlement", error),
                )?;
            if proof_bundle.transaction_passport_id != passport.id {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!(
                        "proof-room.fixture.public-settlement-invalid: {fixture_id}: passport mismatch: expected {}, got {}",
                        passport.id, proof_bundle.transaction_passport_id
                    ),
                ));
            }
            let mut trust = crate::public_settlement_verifier_trust_from_env(&proof_bundle)
                .map_err(|error| {
                    (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        format!(
                            "proof-room.fixture.public-settlement-invalid: {fixture_id}: {error}"
                        ),
                    )
                })?;
            if proof_bundle.has_trust_market_refs() {
                let trust_market_evidence_graph_bytes = source_scoped_evidence_graph_bytes(
                    evidence_graph_bytes,
                    is_trust_market_evidence_graph_node,
                )
                .map_err(|error| proof_room_fixture_invalid(fixture_id, "trust-market", error))?;
                let trust_market_passport = source_passport_for_evidence_graph(
                    passport,
                    &trust_market_evidence_graph_bytes,
                );
                let trusted_market_authority_keys =
                    crate::trust_market_trusted_authority_keys_from_env().map_err(|error| {
                        proof_room_fixture_invalid(fixture_id, "trust-market", error)
                    })?;
                let report = chio_trust_market_context::verify_trust_market_context(
                    &chio_trust_market_context::TrustMarketBundle {
                        passport: trust_market_passport,
                        evidence_graph_bytes: trust_market_evidence_graph_bytes,
                        root_evidence_graph_bytes: Some(evidence_graph_bytes.to_vec()),
                        verifier_policy_bytes: verifier_policy_bytes.to_vec(),
                        artifacts: artifacts.clone(),
                        trusted_passport_signer_keys:
                            crate::transaction_trusted_root_keys_from_env().map_err(|error| {
                                proof_room_fixture_invalid(fixture_id, "trust-market", error)
                            })?,
                        trusted_market_authority_keys,
                    },
                )
                .map_err(|error| proof_room_fixture_invalid(fixture_id, "trust-market", error))?;
                trust.expected_trust_market_context =
                    Some(public_settlement_trust_market_context_from_trust_market_report(&report));
            }
            proof_room_fixture_verified_report_bytes(
                fixture_id,
                passport,
                chio_web3::settlement_proof::verify_public_settlement_proof(&proof_bundle, &trust),
            )
        }
        ProofRoomFixtureReportRoute::StandaloneRisk => proof_room_fixture_standalone_risk_report(
            fixture_id,
            passport,
            evidence_graph_bytes,
            artifacts,
        ),
        ProofRoomFixtureReportRoute::TrustMarket => {
            let trusted_market_authority_keys =
                crate::trust_market_trusted_authority_keys_from_env().map_err(|error| {
                    (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        format!("proof-room.fixture.trust-market-invalid: {fixture_id}: {error}"),
                    )
                })?;
            proof_room_fixture_verified_report_bytes(
                fixture_id,
                passport,
                chio_trust_market_context::verify_trust_market_context(
                    &chio_trust_market_context::TrustMarketBundle {
                        passport: passport.clone(),
                        evidence_graph_bytes: evidence_graph_bytes.to_vec(),
                        root_evidence_graph_bytes: None,
                        verifier_policy_bytes: verifier_policy_bytes.to_vec(),
                        artifacts: artifacts.clone(),
                        trusted_passport_signer_keys:
                            crate::transaction_trusted_root_keys_from_env().map_err(|error| {
                                proof_room_fixture_invalid(fixture_id, "trust-market", error)
                            })?,
                        trusted_market_authority_keys,
                    },
                ),
            )
        }
        ProofRoomFixtureReportRoute::Enterprise => proof_room_fixture_verified_report_bytes(
            fixture_id,
            passport,
            chio_enterprise_export::verify_enterprise_export(
                &chio_enterprise_export::EnterpriseExportBundle {
                    passport: passport.clone(),
                    evidence_graph_bytes: evidence_graph_bytes.to_vec(),
                    root_evidence_graph_bytes: None,
                    verifier_policy_bytes: verifier_policy_bytes.to_vec(),
                    artifacts: artifacts.clone(),
                    trusted_passport_signer_keys: crate::transaction_trusted_root_keys_from_env()
                        .map_err(|error| {
                        proof_room_fixture_invalid(fixture_id, "enterprise", error)
                    })?,
                    trusted_receipt_kernel_keys:
                        crate::enterprise_trusted_receipt_kernel_keys_from_env().map_err(
                            |error| proof_room_fixture_invalid(fixture_id, "enterprise", error),
                        )?,
                    trusted_approval_signer_keys:
                        crate::enterprise_trusted_approval_signer_keys_from_env().map_err(
                            |error| proof_room_fixture_invalid(fixture_id, "enterprise", error),
                        )?,
                    trusted_risk_comptroller_signer_keys:
                        crate::enterprise_trusted_risk_comptroller_signer_keys_from_env().map_err(
                            |error| proof_room_fixture_invalid(fixture_id, "enterprise", error),
                        )?,
                },
            ),
        ),
        ProofRoomFixtureReportRoute::AgentWeb => proof_room_fixture_verified_report_bytes(
            fixture_id,
            passport,
            match agent_web_verifier_trust_from_env() {
                Ok(agent_web_trust) => chio_agent_web_interop::verify_agent_web_interop_with_trust(
                    &chio_agent_web_interop::AgentWebInteropBundle {
                        passport: passport.clone(),
                        evidence_graph_bytes: evidence_graph_bytes.to_vec(),
                        root_evidence_graph_bytes: None,
                        verifier_policy_bytes: verifier_policy_bytes.to_vec(),
                        artifacts: artifacts.clone(),
                    },
                    &agent_web_trust.with_trusted_passport_signer_keys(
                        crate::transaction_trusted_root_keys_from_env().map_err(|error| {
                            proof_room_fixture_invalid(fixture_id, "agent-web", error)
                        })?,
                    ),
                ),
                Err(error) => Err(
                    chio_transaction_passport::TransactionPassportError::AgentWebClaimFailed(error),
                ),
            },
        ),
        ProofRoomFixtureReportRoute::Runtime => {
            let runtime_artifacts = embedded_runtime_artifacts(evidence_graph_bytes, artifacts)
                .map_err(|error| proof_room_fixture_invalid(fixture_id, "runtime", error))?;
            let runtime_trust = crate::runtime_trust_from_env()
                .map_err(|error| proof_room_fixture_invalid(fixture_id, "runtime", error))?;
            proof_room_fixture_verified_report_bytes(
                fixture_id,
                passport,
                chio_transaction_passport::verify_runtime_security_claims_with_trust(
                    &chio_transaction_passport::RuntimeSecurityBundle {
                        passport: passport.clone(),
                        evidence_graph_bytes: evidence_graph_bytes.to_vec(),
                        root_evidence_graph_bytes: None,
                        verifier_policy_bytes: verifier_policy_bytes.to_vec(),
                        artifacts: runtime_artifacts,
                    },
                    &runtime_trust,
                ),
            )
        }
        ProofRoomFixtureReportRoute::MinimalPassport => {
            let trusted_root_signer_keys = crate::transaction_trusted_root_keys_from_env()
                .map_err(|error| {
                    (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        format!(
                            "proof-room.fixture.minimal-passport-invalid: {fixture_id}: {error}"
                        ),
                    )
                })?;
            proof_room_fixture_verified_report_bytes(
                fixture_id,
                passport,
                chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
                    passport,
                    "transaction-passport.json".to_string(),
                    evidence_graph_bytes,
                    verifier_policy_bytes,
                    artifacts,
                    &trusted_root_signer_keys,
                ),
            )
        }
    }
}

pub(crate) fn proof_room_fixture_standalone_risk_report(
    fixture_id: &str,
    passport: &chio_transaction_passport::TransactionPassport,
    evidence_graph_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<u8>, (StatusCode, String)> {
    let risk_report_value = embedded_risk_comptroller_report_value(evidence_graph_bytes, artifacts)
        .map_err(|error| proof_room_fixture_invalid(fixture_id, "risk", error))?;
    let trusted_risk_comptroller_signer_keys =
        crate::enterprise_trusted_risk_comptroller_signer_keys_from_env()
            .map_err(|error| proof_room_fixture_invalid(fixture_id, "risk", error))?;
    let risk_report = match chio_risk_comptroller::validate_signed_risk_report(
        passport,
        &risk_report_value,
        &trusted_risk_comptroller_signer_keys,
    ) {
        Ok(report) => report,
        Err(error) => {
            return proof_room_failed_verifier_report(
                fixture_id,
                passport,
                &proof_room_fixture_verifier_failure_message(fixture_id, error),
            )
            .map(|(contents, _)| contents);
        }
    };
    let risk_evidence_graph = parse_embedded_evidence_graph(evidence_graph_bytes, "evidence graph")
        .map_err(|error| proof_room_fixture_invalid(fixture_id, "evidence-graph", error))?;
    match chio_risk_comptroller::validate_risk_evidence_refs(&risk_report, |evidence_ref, kind| {
        embedded_risk_evidence_ref_matches(
            &risk_evidence_graph.nodes,
            artifacts,
            evidence_ref,
            kind,
        )
    }) {
        Ok(()) => {}
        Err(error) => {
            return proof_room_failed_verifier_report(
                fixture_id,
                passport,
                &proof_room_fixture_verifier_failure_message(fixture_id, error),
            )
            .map(|(contents, _)| contents);
        }
    }
    proof_room_fixture_report_bytes(
        fixture_id,
        &serde_json::json!({
            "schema": "chio.transaction.verifier-report.v1",
            "id": format!("verifier-report-{}", passport.id),
            "issued_at": passport.issued_at,
            "verdict": "verified",
            "passport_id": passport.id,
            "passport_path": "transaction-passport.json",
            "evidence_graph_sha256": passport.evidence_graph_sha256,
            "evidence_graph_path": passport.evidence_graph_path,
            "verifier_policy_sha256": passport.verifier_policy_sha256,
            "verifier_policy_path": passport.verifier_policy_path,
            "risk_comptroller_report_ref": risk_report.id,
            "order_id": risk_report.order_id,
            "subject": risk_report.subject,
            "verified_claims": [CLAIM_RISK_COMPTROLLER_REPORT_BOUND],
        }),
    )
}

pub(crate) fn proof_room_fixture_invalid(
    fixture_id: &str,
    label: &str,
    error: impl std::fmt::Display,
) -> (StatusCode, String) {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        format!("proof-room.fixture.{label}-invalid: {fixture_id}: {error}"),
    )
}

fn public_settlement_trust_market_context_from_trust_market_report(
    report: &chio_trust_market_context::TrustMarketVerifierReport,
) -> chio_web3::settlement_proof::PublicSettlementTrustMarketContext {
    chio_web3::settlement_proof::PublicSettlementTrustMarketContext {
        collateral_position_ref: report.trust_market_sections.collateral_position_ref.clone(),
        guarantee_decision_ref: report.trust_market_sections.guarantee_decision_ref.clone(),
        sla_remedy_ref: report.trust_market_sections.sla_remedy_ref.clone(),
        slash_authority_ref: report.trust_market_sections.slash_authority_ref.clone(),
    }
}

pub(crate) fn proof_room_crypto_context_rejection_report(
    fixture_id: &str,
    source: &ProofRoomFixtureSource,
) -> Result<(Vec<u8>, &'static str), (StatusCode, String)> {
    let context_bytes = source.file("verification-context.json", fixture_id)?;
    let proof_bytes = source.file("selective-disclosure-proof.json", fixture_id)?;
    let privacy_profile_bytes = source.file("verifier-privacy-profile.json", fixture_id)?;
    crypto_context_rejected_report_bytes_with_bbs(
        &context_bytes,
        &proof_bytes,
        &privacy_profile_bytes,
        fixture_id,
    )
    .map(|contents| (contents, "application/json"))
    .map_err(|error| (StatusCode::UNPROCESSABLE_ENTITY, error))
}

pub(crate) fn proof_room_workflow_preflight_report(
    fixture_id: &str,
    source: &ProofRoomFixtureSource,
) -> Result<(Vec<u8>, &'static str), (StatusCode, String)> {
    let plan_bytes = source.file("preflight-plan.json", fixture_id)?;
    let plan: chio_workflow_preflight::WorkflowPreflightPlan = serde_json::from_slice(&plan_bytes)
        .map_err(|error| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("proof-room.fixture.workflow-preflight-invalid: {fixture_id}: {error}"),
            )
        })?;
    let report = chio_workflow_preflight::evaluate_workflow_preflight(&plan).map_err(|error| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("proof-room.fixture.workflow-preflight-invalid: {fixture_id}: {error}"),
        )
    })?;
    let contents = serde_json::to_vec(&report).map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("proof-room.fixture.workflow-preflight-report: {fixture_id}: {error}"),
        )
    })?;
    Ok((contents, "application/json"))
}

#[derive(serde::Deserialize)]
pub(crate) struct ProofRoomEmbeddedEvidenceGraph {
    pub(crate) nodes: Vec<ProofRoomEmbeddedEvidenceNode>,
}

#[derive(serde::Deserialize)]
pub(crate) struct ProofRoomEmbeddedEvidenceNode {
    pub(crate) id: String,
    pub(crate) role: String,
    pub(crate) schema: String,
    pub(crate) path: String,
    pub(crate) sha256: String,
}

pub(crate) fn parse_embedded_evidence_graph(
    evidence_graph_bytes: &[u8],
    error_prefix: &str,
) -> Result<ProofRoomEmbeddedEvidenceGraph, String> {
    serde_json::from_slice(evidence_graph_bytes)
        .map_err(|error| format!("{error_prefix} is not valid JSON: {error}"))
}

pub(crate) fn embedded_evidence_graph_has_role(
    evidence_graph_bytes: &[u8],
    predicate: fn(&str) -> bool,
) -> Result<bool, String> {
    let graph = parse_embedded_evidence_graph(evidence_graph_bytes, "evidence graph")?;
    Ok(graph.nodes.iter().any(|node| predicate(&node.role)))
}
