use super::*;

use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::{canonical_json_bytes, canonical_json_bytes_from_str, canonical_json_string};
use chio_finding::{
    compute_challenge_id, ensure_challenge_class_compatibility, signed_envelope_sha256,
    FindingAffectedDelivery, FindingChallenge, FindingChallengeAuthorization,
    FindingChallengeAuthorizationKind, FindingChallengeEvidence, FindingChallengeEvidenceKind,
    SignedFindingChallenge, FINDING_CHALLENGE_SCHEMA_V1,
};
use chio_control_plane::trust_control::{
    FindingChallengeSubmissionAuthorization, FindingChallengeSubmissionResponse,
    FindingChallengeSubmissionWrite,
};

use super::finding_verify::{accept_finding_from_venue, AcceptedFinding};

const FINDING_CHALLENGE_SCHEMA_JSON: &str =
    include_str!("../../../../../../../spec/schemas/chio-finding/v1/challenge.schema.json");
const FINDING_CHALLENGE_SCHEMA_LABEL: &str = "chio-finding/v1/challenge.schema.json";

/// Ingest bound for the evidence document. A well-formed document carries
/// at most one recipe preimage and sixteen observation preimages, each
/// itself bounded by the artifact family, so this sits well above any
/// legitimate input and turns a runaway file into a local diagnostic.
pub(super) const FINDING_CHALLENGE_EVIDENCE_MAX_BYTES: usize = 512 * 1024;

/// The operator-supplied half of a challenge.
///
/// Every member is one of the registered artifact's own types, so the
/// document is exactly the challenge body minus the four fields this
/// surface derives rather than accepts: `schema`, `challenge_id`,
/// `finding_id`, and `finding_artifact_sha256`. Both closed unions travel
/// verbatim, which is what makes a mixed-branch or mixed-class document
/// fail at parse time instead of being reassembled into acceptance.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(super) struct FindingChallengeEvidenceDocument {
    affected_deliveries: Vec<FindingAffectedDelivery>,
    authorization: FindingChallengeAuthorization,
    evidence: FindingChallengeEvidence,
    filed_at: u64,
    listing: FindingChallengeListingBinding,
}

/// The listing the challenge disputes, as the venue's current signed
/// admission states it. This surface holds no pinned venue key, so it
/// cannot authenticate that envelope itself; it binds what the operator
/// copied and leaves authentication to the coordinator that resolves the
/// admission.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct FindingChallengeListingBinding {
    backing_envelope_sha256: String,
    listing_id: String,
    profile_envelope_sha256: String,
    terms_envelope_sha256: String,
    venue_admission_envelope_sha256: String,
}

/// A challenge that cleared every local gate: assembled, schema-checked,
/// validated, matched against the finding it targets, and signed when its
/// authorization branch calls for a signature.
#[derive(Debug)]
pub(super) struct PreparedChallenge {
    pub(super) challenge: FindingChallenge,
    pub(super) canonical_challenge: String,
    pub(super) challenge_sha256: String,
    pub(super) signed: Option<SignedFindingChallenge>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn cmd_finding_challenge(
    finding: &str,
    class: FindingChallengeClassArg,
    evidence: &Path,
    challenger_key: Option<&Path>,
    venue_audit: bool,
    dry_run: bool,
    json_output: bool,
    control_url: Option<&str>,
    control_token: Option<&str>,
) -> Result<(), CliError> {
    let url = require_control_url(control_url)?;
    let finding_id = require_finding_id(finding)?;
    let document = load_challenge_evidence_document(evidence)?;

    // Every question answerable from the document alone is answered before
    // the venue is contacted, so a document that could never produce a
    // filable challenge costs no request.
    require_class_agreement(class, &document.evidence)?;
    require_branch_agreement(venue_audit, &document.authorization)?;
    require_challenger_key(&document.authorization, challenger_key)?;
    if !dry_run && venue_audit {
        return Err(live_venue_audit_error());
    }
    let control_token = if dry_run {
        None
    } else {
        Some(require_control_token(control_token)?)
    };

    let accepted = accept_finding_from_venue(url, finding_id)?;
    if accepted.finding.finding_id != finding_id {
        return Err(CliError::cli_other_error(format!(
            "venue served finding {} for the requested id {finding_id}",
            accepted.finding.finding_id
        )));
    }

    let prepared = prepare_challenge(&accepted, document, challenger_key)?;

    if dry_run {
        return emit_prepared_challenge(&prepared, json_output);
    }
    let token = control_token.ok_or_else(|| {
        CliError::cli_other_error("finding challenge submission requires a control token")
    })?;
    submit_prepared_challenge(url, token, &prepared, json_output)
}

fn live_venue_audit_error() -> CliError {
    CliError::cli_other_error(
        "live venue-audit challenges are filed by the configured venue audit scheduler, which holds the pinned audit signing key; re-run with --dry-run to inspect the unsigned challenge body"
            .to_string(),
    )
}

fn submit_prepared_challenge(
    control_url: &str,
    control_token: &str,
    prepared: &PreparedChallenge,
    json_output: bool,
) -> Result<(), CliError> {
    let signed = prepared.signed.as_ref().ok_or_else(live_venue_audit_error)?;
    let canonical_envelope = canonical_json_string(signed)?;
    let endpoint = finding_endpoint(
        control_url,
        &format!(
            "/v1/findings/{}/challenges",
            prepared.challenge.finding_id
        ),
    );
    let response = match ureq::post(&endpoint)
        .set(AUTHORIZATION_HEADER, &format!("Bearer {control_token}"))
        .set("Content-Type", "application/json")
        .send_string(&canonical_envelope)
    {
        Ok(response) => response,
        Err(ureq::Error::Status(status, response)) => {
            return Err(http_status_error(status, response))
        }
        Err(ureq::Error::Transport(error)) => {
            return Err(CliError::transport_error(format!(
                "transport request failed: {error}"
            )))
        }
    };
    let submitted: FindingChallengeSubmissionResponse =
        serde_json::from_reader(response.into_reader())?;
    if submitted.challenge_id != prepared.challenge.challenge_id {
        return Err(CliError::transport_error(
            "challenge submission response named a different challenge id".to_string(),
        ));
    }
    let expected_lock_id = match &prepared.challenge.authorization {
        FindingChallengeAuthorization::BuyerSubmission(submission) => {
            submission.dispute_lock_ref.lock_id.as_str()
        }
        FindingChallengeAuthorization::VenueAudit(_) => return Err(live_venue_audit_error()),
    };
    if submitted.authorization_branch
        != FindingChallengeSubmissionAuthorization::BuyerSubmission
        || submitted.dispute_fee_intent_key.is_none()
        || submitted.dispute_bond_lock_id.as_deref() != Some(expected_lock_id)
    {
        return Err(CliError::transport_error(
            "buyer challenge submission response omitted its durable fee or bond binding"
                .to_string(),
        ));
    }
    emit_submitted_challenge(&submitted, json_output)
}

fn emit_submitted_challenge(
    submitted: &FindingChallengeSubmissionResponse,
    json_output: bool,
) -> Result<(), CliError> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(submitted)?);
        return Ok(());
    }
    let authorization = match submitted.authorization_branch {
        FindingChallengeSubmissionAuthorization::BuyerSubmission => "buyer_submission",
        FindingChallengeSubmissionAuthorization::VenueAudit => "venue_audit",
    };
    let write = match submitted.write {
        FindingChallengeSubmissionWrite::Inserted => "inserted",
        FindingChallengeSubmissionWrite::ExistingSame => "existing_same",
    };
    println!("challenge_id:           {}", submitted.challenge_id);
    println!("authorization_branch:  {authorization}");
    println!("write:                 {write}");
    println!(
        "dispute_fee_intent:    {}",
        submitted.dispute_fee_intent_key.as_deref().unwrap_or("-")
    );
    println!(
        "dispute_bond_lock:     {}",
        submitted.dispute_bond_lock_id.as_deref().unwrap_or("-")
    );
    Ok(())
}

/// The strict raw-first ingress the artifact surfaces apply, run over the
/// evidence document: bounded read, canonical-bytes check, closed-shape
/// parse, and typed round-trip equality. A document that is not exactly
/// its own canonical serialization is rejected rather than normalized,
/// because the digests it carries are only meaningful against exact bytes.
pub(super) fn load_challenge_evidence_document(
    path: &Path,
) -> Result<FindingChallengeEvidenceDocument, CliError> {
    let bytes = fs::read(path)?;
    if bytes.len() > FINDING_CHALLENGE_EVIDENCE_MAX_BYTES {
        return Err(CliError::cli_other_error(format!(
            "{} is {} bytes, above the {FINDING_CHALLENGE_EVIDENCE_MAX_BYTES} byte challenge evidence bound",
            path.display(),
            bytes.len()
        )));
    }
    let raw = String::from_utf8(bytes).map_err(|error| {
        CliError::cli_other_error(format!("{} is not valid UTF-8: {error}", path.display()))
    })?;

    let strict_bytes = canonical_json_bytes_from_str(&raw).map_err(|error| {
        CliError::cli_other_error(format!(
            "{} is not strict canonical I-JSON: {error}",
            path.display()
        ))
    })?;
    if strict_bytes.as_slice() != raw.as_bytes() {
        return Err(CliError::cli_other_error(format!(
            "{} bytes are not the canonical serialization",
            path.display()
        )));
    }

    let document: FindingChallengeEvidenceDocument =
        serde_json::from_str(&raw).map_err(|error| {
            CliError::cli_other_error(format!(
                "{} is not a challenge evidence document: {error}",
                path.display()
            ))
        })?;
    let typed_bytes = canonical_json_bytes(&document)?;
    if typed_bytes != strict_bytes {
        return Err(CliError::cli_other_error(format!(
            "{} typed canonical bytes drift from the accepted raw bytes",
            path.display()
        )));
    }
    Ok(document)
}

/// The named class and the class the document actually carries must be the
/// same one. Disagreement is a refusal: the closed union means one of the
/// two is wrong about what evidence is being presented.
fn require_class_agreement(
    class: FindingChallengeClassArg,
    evidence: &FindingChallengeEvidence,
) -> Result<(), CliError> {
    if class.kind() == evidence.kind() {
        return Ok(());
    }
    Err(CliError::cli_other_error(format!(
        "--class {} does not match the {} evidence the document carries",
        evidence_kind_label(class.kind()),
        evidence_kind_label(evidence.kind())
    )))
}

/// The named authorization branch and the branch the document carries must
/// be the same one. The audit branch admits no challenger, fee, bond,
/// forfeiture, or reward member at all, so a buyer submission is refused
/// under `--venue-audit` rather than stripped down into one.
fn require_branch_agreement(
    venue_audit: bool,
    authorization: &FindingChallengeAuthorization,
) -> Result<(), CliError> {
    match (venue_audit, authorization.kind()) {
        (false, FindingChallengeAuthorizationKind::BuyerSubmission)
        | (true, FindingChallengeAuthorizationKind::VenueAudit) => Ok(()),
        (true, FindingChallengeAuthorizationKind::BuyerSubmission) => {
            Err(CliError::cli_other_error(
                "--venue-audit builds the bondless audit branch, but the document carries a buyer submission with a dispute fee and a dispute bond; the audit branch admits no challenger, fee, bond, forfeiture, or reward"
                    .to_string(),
            ))
        }
        (false, FindingChallengeAuthorizationKind::VenueAudit) => {
            Err(CliError::cli_other_error(
                "the document carries a venue audit authorization; pass --venue-audit to file it"
                    .to_string(),
            ))
        }
    }
}

fn require_challenger_key(
    authorization: &FindingChallengeAuthorization,
    challenger_key: Option<&Path>,
) -> Result<(), CliError> {
    match (authorization.kind(), challenger_key) {
        (FindingChallengeAuthorizationKind::BuyerSubmission, None) => {
            Err(missing_challenger_key_error())
        }
        _ => Ok(()),
    }
}

fn missing_challenger_key_error() -> CliError {
    CliError::cli_other_error(
        "a buyer submission is authorized by the challenger it names, so --challenger-key is required and must hold that challenger's seed"
            .to_string(),
    )
}

/// Assemble, gate, and sign. The order is deliberate: the body is checked
/// against the registered schema and its own validator, and the class is
/// checked against the finding it targets, all before a signature exists.
pub(super) fn prepare_challenge(
    accepted: &AcceptedFinding,
    document: FindingChallengeEvidenceDocument,
    challenger_key: Option<&Path>,
) -> Result<PreparedChallenge, CliError> {
    let mut challenge = FindingChallenge {
        schema: FINDING_CHALLENGE_SCHEMA_V1.to_string(),
        challenge_id: String::new(),
        finding_id: accepted.finding.finding_id.clone(),
        finding_artifact_sha256: accepted.artifact_sha256.clone(),
        listing_id: document.listing.listing_id,
        terms_envelope_sha256: document.listing.terms_envelope_sha256,
        profile_envelope_sha256: document.listing.profile_envelope_sha256,
        venue_admission_envelope_sha256: document.listing.venue_admission_envelope_sha256,
        backing_envelope_sha256: document.listing.backing_envelope_sha256,
        filed_at: document.filed_at,
        affected_deliveries: document.affected_deliveries,
        authorization: document.authorization,
        evidence: document.evidence,
    };
    challenge.challenge_id = compute_challenge_id(&challenge).map_err(|error| {
        CliError::cli_other_error(format!("failed to derive the challenge id: {error}"))
    })?;

    validate_against_registered_schema(&challenge)?;
    challenge.validate().map_err(|error| {
        CliError::cli_other_error(format!("challenge rejected before submission: {error}"))
    })?;
    ensure_challenge_class_compatibility(
        challenge.evidence.kind(),
        accepted.finding.guarantee_class,
        accepted.finding.evidence_class,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "{} evidence cannot challenge finding {}: {error}",
            evidence_kind_label(challenge.evidence.kind()),
            accepted.finding.finding_id
        ))
    })?;

    let signed = match (&challenge.authorization, challenger_key) {
        (FindingChallengeAuthorization::BuyerSubmission(submission), Some(path)) => {
            let keypair = load_challenger_keypair(path)?;
            // The artifact's verifier authorizes a buyer submission by the
            // challenger the body names, so a signature from any other key
            // produces an artifact that can never be accepted.
            if keypair.public_key() != submission.challenger {
                return Err(CliError::cli_other_error(format!(
                    "--challenger-key holds {}, but the document names {} as the challenger",
                    keypair.public_key().to_hex(),
                    submission.challenger.to_hex()
                )));
            }
            Some(
                SignedExportEnvelope::sign(challenge.clone(), &keypair).map_err(|error| {
                    CliError::cli_other_error(format!("failed to sign the challenge: {error}"))
                })?,
            )
        }
        (FindingChallengeAuthorization::BuyerSubmission(_), None) => {
            return Err(missing_challenger_key_error())
        }
        (FindingChallengeAuthorization::VenueAudit(_), _) => None,
    };

    let canonical_challenge = canonical_json_string(&challenge)?;
    let challenge_sha256 = sha256_hex(canonical_challenge.as_bytes());
    Ok(PreparedChallenge {
        challenge,
        canonical_challenge,
        challenge_sha256,
        signed,
    })
}

/// The registered schema describes the signed envelope. A body that has not
/// been signed yet still has to satisfy the body half of it, so the body
/// subschema is lifted out together with the shared definitions it
/// references. Checking against the committed schema rather than a local
/// restatement of it means the two cannot drift.
fn challenge_body_schema() -> Result<serde_json::Value, CliError> {
    let envelope: serde_json::Value = serde_json::from_str(FINDING_CHALLENGE_SCHEMA_JSON)?;
    let definitions = envelope.get("$defs").cloned().ok_or_else(|| {
        CliError::cli_other_error(
            "the registered challenge schema carries no shared definitions".to_string(),
        )
    })?;
    let mut body = envelope
        .get("properties")
        .and_then(|properties| properties.get("body"))
        .cloned()
        .ok_or_else(|| {
            CliError::cli_other_error(
                "the registered challenge schema carries no body subschema".to_string(),
            )
        })?;
    let object = body.as_object_mut().ok_or_else(|| {
        CliError::cli_other_error(
            "the registered challenge body subschema is not an object".to_string(),
        )
    })?;
    object.insert("$defs".to_string(), definitions);
    Ok(body)
}

fn validate_against_registered_schema(challenge: &FindingChallenge) -> Result<(), CliError> {
    let schema = challenge_body_schema()?;
    let value = serde_json::to_value(challenge)?;
    chio_spec_validate::validate_value(
        Path::new(FINDING_CHALLENGE_SCHEMA_LABEL),
        &schema,
        Path::new("challenge body"),
        &value,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "assembled challenge rejected by the challenge schema: {error}"
        ))
    })
}

/// Ed25519 seed file, the spelling the runtime signing surfaces read. The
/// underlying decode error is dropped deliberately: it can quote the
/// offending byte of a secret seed.
fn load_challenger_keypair(path: &Path) -> Result<Keypair, CliError> {
    let seed = fs::read_to_string(path)?;
    Keypair::from_seed_hex(seed.trim()).map_err(|_| {
        CliError::cli_other_error(format!(
            "{} must hold a 32-byte Ed25519 seed as 64 hex characters",
            path.display()
        ))
    })
}

fn evidence_kind_label(kind: FindingChallengeEvidenceKind) -> &'static str {
    match kind {
        FindingChallengeEvidenceKind::DigestMismatch => "digest-mismatch",
        FindingChallengeEvidenceKind::EvidenceInvalid => "evidence-invalid",
        FindingChallengeEvidenceKind::ReplayContradiction => "replay-contradiction",
    }
}

fn authorization_kind_label(kind: FindingChallengeAuthorizationKind) -> &'static str {
    match kind {
        FindingChallengeAuthorizationKind::BuyerSubmission => "buyer_submission",
        FindingChallengeAuthorizationKind::VenueAudit => "venue_audit",
    }
}

/// A venue audit is signed by the venue's pinned audit authority, which
/// this surface does not hold, so its dry run emits the body alone and
/// names the absent envelope rather than implying an unsigned artifact is
/// filable.
fn emit_prepared_challenge(
    prepared: &PreparedChallenge,
    json_output: bool,
) -> Result<(), CliError> {
    let (canonical_envelope, envelope_sha256) = match &prepared.signed {
        Some(signed) => (
            Some(canonical_json_string(signed)?),
            Some(signed_envelope_sha256(signed).map_err(|error| {
                CliError::cli_other_error(format!(
                    "failed to derive the challenge envelope digest: {error}"
                ))
            })?),
        ),
        None => (None, None),
    };
    let authorization = authorization_kind_label(prepared.challenge.authorization.kind());
    let evidence_class = evidence_kind_label(prepared.challenge.evidence.kind());

    if json_output {
        let report = serde_json::json!({
            "finding_id": prepared.challenge.finding_id,
            "challenge_id": prepared.challenge.challenge_id,
            "mode": "dry_run",
            "authorization": authorization,
            "evidence_class": evidence_class,
            "challenge_sha256": prepared.challenge_sha256,
            "envelope_sha256": envelope_sha256,
            "canonical_challenge": prepared.canonical_challenge,
            "canonical_envelope": canonical_envelope,
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("finding_id:          {}", prepared.challenge.finding_id);
    println!("challenge_id:        {}", prepared.challenge.challenge_id);
    println!("mode:                dry_run");
    println!("authorization:       {authorization}");
    println!("evidence_class:      {evidence_class}");
    println!("challenge_sha256:    {}", prepared.challenge_sha256);
    match envelope_sha256.as_deref() {
        Some(digest) => println!("envelope_sha256:     {digest}"),
        None => println!("envelope_sha256:     -"),
    }
    println!("canonical_challenge:");
    println!("{}", prepared.canonical_challenge);
    match canonical_envelope.as_deref() {
        Some(envelope) => {
            println!("canonical_envelope:");
            println!("{envelope}");
        }
        None => println!("canonical_envelope:  -"),
    }
    Ok(())
}
