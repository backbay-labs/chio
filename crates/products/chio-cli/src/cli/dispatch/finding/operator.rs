use super::*;

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chio_control_plane::trust_control::finding_operator_profile::{
    FindingOperatorBuyerProfile, FindingOperatorPaths, FindingOperatorProfile,
    FindingOperatorSecretSeeds, FindingOperatorSellerProfile, FINDING_OPERATOR_PROFILE_SCHEMA,
};
use chio_control_plane::trust_control::finding_operator_filing_resolver::FindingOperatorFilingResolver;
use chio_control_plane::trust_control::finding_operator_purchase::{
    FindingOperatorPurchaseExecutor, FindingOperatorPurchaseStorage,
};
use chio_control_plane::trust_control::finding_operator_seller_routes::{
    FindingSellerSubmissionError, FindingSellerSubmissionExecutor,
    FindingVerifiedFixSubmissionRequest, FindingVerifiedFixSubmissionResponse,
    FindingVoluntaryRetractionRequest, FindingVoluntaryRetractionResponse,
};
use chio_control_plane::trust_control::finding_operator_status::FindingOperatorAuthorityStatusResolver;
use chio_control_plane::trust_control::finding_challenge_coordinator::FindingChallengeCoordinator;
use chio_control_plane::trust_control::finding_status_publisher::FindingStatusEpochPublisher;
use chio_control_plane::trust_control::FindingChallengeSubmissionRuntime;
use chio_control_plane::trust_control::{
    FindingAuthorityPin, FindingMarketConfig, FindingPoolPin, FindingStatusOperatorPin,
    FindingStatusServiceBond, TrustServiceConfig, VenueLedgerRailObserver,
    FINDING_STATUS_OPERATOR_ROLE,
};
use chio_core::{canonical_json_bytes, sha256_hex, Keypair};
use chio_store_sqlite::{
    SqliteAuthorityStore, SqliteFindingOperatorBundleStore,
    SqliteFindingOperatorPaymentAdapter, SqliteFindingPayloadStore, SqliteReceiptStore,
    FindingDisputeLockDisposition, TenantId, TenantKey,
};
use subtle::ConstantTimeEq;

use super::finding_verified_fix::{
    read_canonical_file, reconcile_admission_jobs, write_private_atomic,
};

const PROFILE_FILE: &str = "operator-profile.json";
const CLIENT_PROFILE_FILE: &str = "client-profile.json";
const BUYER_CLIENT_FILE: &str = "buyer-client.json";
const SELLER_CLIENT_FILE: &str = "seller-client.json";
const PROFILE_MAX_BYTES: usize = 1024 * 1024;
const ROLE_WINDOW_SECS: u64 = 10 * 365 * 24 * 60 * 60;
const SELLER_SUBMISSION_JOB_SCHEMA: &str = "chio.finding.seller-submission-job.v1";
const SELLER_SUBMISSION_JOB_MAX_BYTES: usize = 1024 * 1024;
const SELLER_RETRACTION_JOB_SCHEMA: &str = "chio.finding.seller-retraction-job.v2";

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FindingSellerSubmissionJob {
    schema: String,
    request_id: String,
    request_sha256: String,
    seller_principal: String,
    package_path: String,
    result: Option<FindingVerifiedFixSubmissionResponse>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FindingSellerRetractionJob {
    schema: String,
    request_id: String,
    request_sha256: String,
    finding_id: String,
    seller_principal: String,
    intent_b64: Option<String>,
    intent_id: Option<String>,
    result: Option<FindingVoluntaryRetractionResponse>,
}

struct OperatorSellerSubmissionExecutor {
    profile_path: PathBuf,
    reports_directory: PathBuf,
    packages_directory: PathBuf,
    profile: FindingOperatorProfile,
    authority: Arc<SqliteAuthorityStore>,
    sellers: Vec<(String, String, Keypair)>,
    submission_lock: Mutex<()>,
}

impl OperatorSellerSubmissionExecutor {
    fn new(
        profile_path: PathBuf,
        profile: &FindingOperatorProfile,
        paths: &ResolvedOperatorPaths,
        authority: Arc<SqliteAuthorityStore>,
    ) -> Result<Self, String> {
        let sellers = profile
            .sellers
            .iter()
            .map(|seller| {
                Keypair::from_seed_hex(&seller.signing_seed).map(|key| {
                    (
                        seller.principal_id.clone(),
                        seller.bearer_token.clone(),
                        key,
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        Ok(Self {
            profile_path,
            reports_directory: paths.reports_directory.clone(),
            packages_directory: paths.packages_directory.clone(),
            profile: profile.clone(),
            authority,
            sellers,
            submission_lock: Mutex::new(()),
        })
    }

    fn authenticate(&self, token: &str) -> Result<(String, Keypair), FindingSellerSubmissionError> {
        self.sellers
            .iter()
            .find(|(_, expected, _)| bool::from(expected.as_bytes().ct_eq(token.as_bytes())))
            .map(|(principal, _, key)| (principal.clone(), key.clone()))
            .ok_or(FindingSellerSubmissionError::Authentication)
    }

    fn run_submission(
        &self,
        principal: &str,
        request: &FindingVerifiedFixSubmissionRequest,
    ) -> Result<FindingVerifiedFixSubmissionResponse, FindingSellerSubmissionError> {
        request
            .validate()
            .map_err(FindingSellerSubmissionError::Invalid)?;
        let repository = PathBuf::from(&request.repository);
        if !repository.is_absolute() {
            return Err(FindingSellerSubmissionError::Invalid(
                "verified-fix repository must be an absolute path".to_owned(),
            ));
        }
        let request_bytes = canonical_json_bytes(request)
            .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?;
        let request_sha256 = sha256_hex(&request_bytes);
        let package_path = self
            .packages_directory
            .join(format!("{}.draft.json", request.request_id));
        let job_path = self
            .reports_directory
            .join(format!("{}.seller-submission-job.json", request.request_id));
        let mut job = if job_path.exists() {
            let stored: FindingSellerSubmissionJob = read_canonical_file(
                &job_path,
                SELLER_SUBMISSION_JOB_MAX_BYTES,
            )
            .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?;
            if stored.schema != SELLER_SUBMISSION_JOB_SCHEMA
                || stored.request_id != request.request_id
                || stored.request_sha256 != request_sha256
                || stored.seller_principal != principal
                || stored.package_path != package_path.display().to_string()
            {
                return Err(FindingSellerSubmissionError::Conflict);
            }
            stored
        } else {
            let created = FindingSellerSubmissionJob {
                schema: SELLER_SUBMISSION_JOB_SCHEMA.to_owned(),
                request_id: request.request_id.clone(),
                request_sha256,
                seller_principal: principal.to_owned(),
                package_path: package_path.display().to_string(),
                result: None,
            };
            write_private_atomic(
                &job_path,
                &canonical_json_bytes(&created)
                    .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?,
            )
            .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?;
            created
        };
        if let Some(result) = job.result.clone() {
            return Ok(result);
        }

        if !package_path.exists() {
            let mut args = vec![
                "finding".to_owned(),
                "package".to_owned(),
                "verified-fix".to_owned(),
                "--profile".to_owned(),
                self.profile_path.display().to_string(),
                "--repository".to_owned(),
                request.repository.clone(),
                "--base".to_owned(),
                request.base_revision.clone(),
                "--candidate".to_owned(),
                request.candidate_revision.clone(),
                "--topic".to_owned(),
                request.topic.clone(),
                "--seller".to_owned(),
                principal.to_owned(),
                "--price".to_owned(),
                request.price_units.to_string(),
                "--output".to_owned(),
                package_path.display().to_string(),
                "--json".to_owned(),
            ];
            for test in &request.tests {
                args.push("--test".to_owned());
                args.push(test.clone());
            }
            run_chio_success(&args)?;
        }
        let admission = run_chio_json(&[
            "finding".to_owned(),
            "admit".to_owned(),
            "--profile".to_owned(),
            self.profile_path.display().to_string(),
            "--package".to_owned(),
            package_path.display().to_string(),
            "--json".to_owned(),
        ])?;
        let finding_id = admission
            .get("findingId")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                FindingSellerSubmissionError::Internal(
                    "admission response omitted findingId".to_owned(),
                )
            })?
            .to_owned();
        let proof_bundle = admission
            .get("proofBundle")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                FindingSellerSubmissionError::Internal(
                    "admission response omitted proofBundle".to_owned(),
                )
            })?
            .to_owned();
        let activation = admission.get("activation").cloned().ok_or_else(|| {
            FindingSellerSubmissionError::Internal(
                "admission response omitted activation".to_owned(),
            )
        })?;
        let result = FindingVerifiedFixSubmissionResponse {
            schema: "chio.finding.verified-fix-submission-result.v1".to_owned(),
            request_id: request.request_id.clone(),
            seller_principal: principal.to_owned(),
            finding_id,
            proof_bundle,
            activation,
        };
        job.result = Some(result.clone());
        write_private_atomic(
            &job_path,
            &canonical_json_bytes(&job)
                .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?,
        )
        .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?;
        Ok(result)
    }
}

impl FindingSellerSubmissionExecutor for OperatorSellerSubmissionExecutor {
    fn submit(
        &self,
        bearer_token: &str,
        request: &FindingVerifiedFixSubmissionRequest,
    ) -> Result<FindingVerifiedFixSubmissionResponse, FindingSellerSubmissionError> {
        let (principal, _) = self.authenticate(bearer_token)?;
        let _guard = self.submission_lock.lock().map_err(|_| {
            FindingSellerSubmissionError::Pending(
                "verified-fix submission lock is unavailable".to_owned(),
            )
        })?;
        self.run_submission(&principal, request)
    }

    fn retract(
        &self,
        bearer_token: &str,
        request: &FindingVoluntaryRetractionRequest,
    ) -> Result<FindingVoluntaryRetractionResponse, FindingSellerSubmissionError> {
        let (principal, seller_key) = self.authenticate(bearer_token)?;
        request
            .validate()
            .map_err(FindingSellerSubmissionError::Invalid)?;
        let _guard = self.submission_lock.lock().map_err(|_| {
            FindingSellerSubmissionError::Pending(
                "voluntary retraction lock is unavailable".to_owned(),
            )
        })?;
        let job_path = self
            .reports_directory
            .join(format!("{}.seller-retraction-job.json", request.request_id));
        let request_sha256 = sha256_hex(
            &canonical_json_bytes(request)
                .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?,
        );
        let mut job = if job_path.exists() {
            let stored: FindingSellerRetractionJob = read_canonical_file(
                &job_path,
                SELLER_SUBMISSION_JOB_MAX_BYTES,
            )
            .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?;
            if stored.schema != SELLER_RETRACTION_JOB_SCHEMA
                || stored.request_id != request.request_id
                || stored.request_sha256 != request_sha256
                || stored.finding_id != request.finding_id
                || stored.seller_principal != principal
                || stored.intent_b64.is_some() != stored.intent_id.is_some()
            {
                return Err(FindingSellerSubmissionError::Conflict);
            }
            stored
        } else {
            let created = FindingSellerRetractionJob {
                schema: SELLER_RETRACTION_JOB_SCHEMA.to_owned(),
                request_id: request.request_id.clone(),
                request_sha256,
                finding_id: request.finding_id.clone(),
                seller_principal: principal,
                intent_b64: None,
                intent_id: None,
                result: None,
            };
            write_private_atomic(
                &job_path,
                &canonical_json_bytes(&created)
                    .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?,
            )
            .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?;
            created
        };
        if let Some(result) = job.result.clone() {
            if result.request_id != request.request_id
                || result.finding_id != request.finding_id
                || job.intent_id.as_deref() != Some(result.intent_id.as_str())
            {
                return Err(FindingSellerSubmissionError::Conflict);
            }
            return Ok(result);
        }
        let bundle = SqliteFindingOperatorBundleStore::open(
            self.profile_path
                .parent()
                .ok_or_else(|| {
                    FindingSellerSubmissionError::Internal(
                        "operator profile has no parent directory".to_owned(),
                    )
                })?
                .join(&self.profile.paths.operator_database),
        )
        .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?
        .get(&request.finding_id)
        .map_err(|_| {
            FindingSellerSubmissionError::Invalid(
                "retracted Finding is not retained by this operator".to_owned(),
            )
        })?;
        let bundle: chio_control_plane::trust_control::finding_operator_bundle::FindingOperatorBundle =
            serde_json::from_slice(&bundle.bundle_json)
                .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?;
        if bundle.finding.issuer != seller_key.public_key() {
            return Err(FindingSellerSubmissionError::Authentication);
        }
        let status_key = self
            .profile
            .authoring_keys()
            .map_err(FindingSellerSubmissionError::Internal)?
            .status_feed_operator;
        let intent = if let Some(encoded) = job.intent_b64.as_ref() {
            let bytes = STANDARD.decode(encoded).map_err(|_| {
                FindingSellerSubmissionError::Internal(
                    "stored voluntary retraction intent is not base64".to_owned(),
                )
            })?;
            if bytes.len() > SELLER_SUBMISSION_JOB_MAX_BYTES || STANDARD.encode(&bytes) != *encoded {
                return Err(FindingSellerSubmissionError::Internal(
                    "stored voluntary retraction intent is invalid".to_owned(),
                ));
            }
            bytes
        } else {
            let now = unix_time()
                .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?;
            let bytes = chio_control_plane::trust_control::build_operator_voluntary_retraction(
                &self.profile.market,
                &seller_key,
                &status_key,
                &request.finding_id,
                now,
            )
            .map_err(FindingSellerSubmissionError::Internal)?;
            let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| {
                FindingSellerSubmissionError::Internal(
                    "voluntary retraction intent is not valid JSON".to_owned(),
                )
            })?;
            let intent_id = value
                .get("body")
                .and_then(|body| body.get("intent_id"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    FindingSellerSubmissionError::Internal(
                        "voluntary retraction intent omitted intent_id".to_owned(),
                    )
                })?
                .to_owned();
            job.intent_b64 = Some(STANDARD.encode(&bytes));
            job.intent_id = Some(intent_id);
            write_private_atomic(
                &job_path,
                &canonical_json_bytes(&job)
                    .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?,
            )
            .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?;
            bytes
        };
        let expected_intent_id = job.intent_id.clone().ok_or_else(|| {
            FindingSellerSubmissionError::Internal(
                "stored voluntary retraction intent omitted its id".to_owned(),
            )
        })?;
        let intent_value: serde_json::Value = serde_json::from_slice(&intent).map_err(|_| {
            FindingSellerSubmissionError::Internal(
                "stored voluntary retraction intent is not valid JSON".to_owned(),
            )
        })?;
        let intent_body = intent_value.get("body").ok_or_else(|| {
            FindingSellerSubmissionError::Internal(
                "stored voluntary retraction intent omitted its body".to_owned(),
            )
        })?;
        if canonical_json_bytes(&intent_value)
            .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?
            != intent
            || intent_body
                .get("intent_id")
                .and_then(serde_json::Value::as_str)
                != Some(expected_intent_id.as_str())
            || intent_body
                .get("finding_id")
                .and_then(serde_json::Value::as_str)
                != Some(request.finding_id.as_str())
        {
            return Err(FindingSellerSubmissionError::Conflict);
        }
        let encoded_feed = percent_encoding::utf8_percent_encode(
            &self.profile.market.status_feed_operator.feed_id,
            percent_encoding::NON_ALPHANUMERIC,
        );
        let intent_response = post_operator_bytes(
            &format!("http://{}", self.profile.listen),
            &format!("/v1/findings/status/{encoded_feed}/intents"),
            &self.profile.service_token,
            &intent,
        )?;
        let intent_id = intent_response
            .get("intent_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                FindingSellerSubmissionError::Internal(
                    "status intent response omitted intent_id".to_owned(),
                )
            })?
            .to_owned();
        if intent_id != expected_intent_id {
            return Err(FindingSellerSubmissionError::Conflict);
        }
        let publisher = FindingStatusEpochPublisher::new(
            self.authority.finding_status_store(),
            self.profile.market.status_feed_operator.clone(),
            self.profile.market.status_feed_service_bond.clone(),
            status_key,
            self.profile.market.status_max_epoch_age_secs,
        )
        .map_err(FindingSellerSubmissionError::Internal)?;
        // The status ingress samples its commit clock inside the durable
        // transaction. Sample again after that request instead of advancing
        // into a future second, which would make immediate reads look like a
        // clock rollback.
        let publish_now = unix_time()
            .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?;
        let proof = publisher
            .publish_retraction(&intent_id, &[], publish_now)
            .map_err(FindingSellerSubmissionError::Internal)?;
        let result = FindingVoluntaryRetractionResponse {
            schema: "chio.finding.voluntary-retraction-result.v1".to_owned(),
            request_id: request.request_id.clone(),
            finding_id: request.finding_id.clone(),
            intent_id,
            proof_sha256: proof.proof_sha256,
            map_epoch: proof.map_epoch,
            status: "retracted".to_owned(),
        };
        job.result = Some(result.clone());
        write_private_atomic(
            &job_path,
            &canonical_json_bytes(&job)
                .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?,
        )
        .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?;
        Ok(result)
    }
}

fn post_operator_bytes(
    base_url: &str,
    path: &str,
    token: &str,
    bytes: &[u8],
) -> Result<serde_json::Value, FindingSellerSubmissionError> {
    let endpoint = format!("{}{path}", base_url.trim_end_matches('/'));
    let response = match ureq::post(&endpoint)
        .set("authorization", &format!("Bearer {token}"))
        .set("content-type", "application/json")
        .send_bytes(bytes)
    {
        Ok(response) => response,
        Err(ureq::Error::Status(status, response)) => {
            let body = response.into_string().unwrap_or_default();
            return Err(FindingSellerSubmissionError::Invalid(format!(
                "operator status request failed with HTTP {status}: {}",
                body.chars().take(4096).collect::<String>()
            )));
        }
        Err(ureq::Error::Transport(error)) => {
            return Err(FindingSellerSubmissionError::Pending(format!(
                "operator status request failed: {error}"
            )));
        }
    };
    serde_json::from_reader(response.into_reader()).map_err(|_| {
        FindingSellerSubmissionError::Internal(
            "operator status response was not valid JSON".to_owned(),
        )
    })
}

fn run_chio_json(args: &[String]) -> Result<serde_json::Value, FindingSellerSubmissionError> {
    let output = run_chio(args)?;
    serde_json::from_slice(&output)
        .map_err(|_| FindingSellerSubmissionError::Internal("chio subprocess returned invalid JSON".to_owned()))
}

fn run_chio_success(args: &[String]) -> Result<(), FindingSellerSubmissionError> {
    run_chio(args).map(|_| ())
}

fn run_chio(args: &[String]) -> Result<Vec<u8>, FindingSellerSubmissionError> {
    let binary = std::env::current_exe()
        .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?;
    let output = Command::new(binary)
        .args(args)
        .output()
        .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr);
        return Err(FindingSellerSubmissionError::Invalid(
            message.trim().chars().take(4096).collect(),
        ));
    }
    if output.stdout.len() > SELLER_SUBMISSION_JOB_MAX_BYTES {
        return Err(FindingSellerSubmissionError::Internal(
            "chio subprocess response exceeded its size bound".to_owned(),
        ));
    }
    Ok(output.stdout)
}

struct GeneratedRoles {
    venue: Keypair,
    listing: Keypair,
    governance_root: Keypair,
    authority_status: Keypair,
    verifier_report: Keypair,
    collateral: Keypair,
    purchase: Keypair,
    failed_delivery: Keypair,
    challenge_evaluator: Keypair,
    venue_finalization: Keypair,
    market_penalty: Keypair,
    settlement_observer: Keypair,
    anchor_publisher: Keypair,
    audit_authority: Keypair,
    audit_randomness_witness: Keypair,
    status_feed_operator: Keypair,
    fee_schedule_operator: Keypair,
    kernel: Keypair,
}

impl GeneratedRoles {
    fn generate() -> Self {
        Self {
            venue: Keypair::generate(),
            listing: Keypair::generate(),
            governance_root: Keypair::generate(),
            authority_status: Keypair::generate(),
            verifier_report: Keypair::generate(),
            collateral: Keypair::generate(),
            purchase: Keypair::generate(),
            failed_delivery: Keypair::generate(),
            challenge_evaluator: Keypair::generate(),
            venue_finalization: Keypair::generate(),
            market_penalty: Keypair::generate(),
            settlement_observer: Keypair::generate(),
            anchor_publisher: Keypair::generate(),
            audit_authority: Keypair::generate(),
            audit_randomness_witness: Keypair::generate(),
            status_feed_operator: Keypair::generate(),
            fee_schedule_operator: Keypair::generate(),
            kernel: Keypair::generate(),
        }
    }

    fn secrets(&self) -> FindingOperatorSecretSeeds {
        FindingOperatorSecretSeeds {
            venue: self.venue.seed_hex(),
            listing: self.listing.seed_hex(),
            governance_root: self.governance_root.seed_hex(),
            authority_status: self.authority_status.seed_hex(),
            verifier_report: self.verifier_report.seed_hex(),
            collateral: self.collateral.seed_hex(),
            purchase: self.purchase.seed_hex(),
            failed_delivery: self.failed_delivery.seed_hex(),
            challenge_evaluator: self.challenge_evaluator.seed_hex(),
            venue_finalization: self.venue_finalization.seed_hex(),
            market_penalty: self.market_penalty.seed_hex(),
            settlement_observer: self.settlement_observer.seed_hex(),
            anchor_publisher: self.anchor_publisher.seed_hex(),
            audit_authority: self.audit_authority.seed_hex(),
            audit_randomness_witness: self.audit_randomness_witness.seed_hex(),
            status_feed_operator: self.status_feed_operator.seed_hex(),
            fee_schedule_operator: self.fee_schedule_operator.seed_hex(),
            kernel: self.kernel.seed_hex(),
        }
    }
}

pub(super) fn cmd_finding_operator_init(
    directory: &Path,
    listen: SocketAddr,
    buyer_principal: &str,
    buyer_payout: &str,
    seller_principal: &str,
    seller_payout: &str,
    json_output: bool,
) -> Result<(), CliError> {
    set_operator_umask();
    create_secure_directory(directory)?;
    let profile_path = directory.join(PROFILE_FILE);
    if profile_path.exists() {
        return Err(CliError::cli_other_error(format!(
            "operator profile already exists at {}",
            profile_path.display()
        )));
    }
    for child in ["locks", "packages", "reports"] {
        create_secure_directory(&directory.join(child))?;
    }

    let now = unix_time()?;
    let valid_from = now.saturating_sub(60);
    let valid_until = now
        .checked_add(ROLE_WINDOW_SECS)
        .ok_or_else(|| CliError::cli_other_error("operator role window overflowed".to_owned()))?;
    let roles = GeneratedRoles::generate();
    let pin = |label: &str, keypair: &Keypair| FindingAuthorityPin {
        authority_id: format!("local-{label}"),
        key_hex: keypair.public_key().to_hex(),
        key_epoch: 1,
        valid_from,
        valid_until,
        revocation_status_ref: format!("local/revocations/{label}"),
    };
    let status_feed_id = "finding-status/local-cognition-market".to_owned();
    let status_authority = pin("status-feed-operator", &roles.status_feed_operator);
    let market = FindingMarketConfig {
        venue_id: "local-cognition-market".to_owned(),
        venue: pin("venue", &roles.venue),
        listing: pin("listing", &roles.listing),
        governance_root: pin("governance-root", &roles.governance_root),
        authority_status: pin("authority-status", &roles.authority_status),
        verifier_report: pin("verifier-report", &roles.verifier_report),
        collateral: pin("collateral", &roles.collateral),
        purchase: pin("purchase", &roles.purchase),
        failed_delivery: pin("failed-delivery", &roles.failed_delivery),
        challenge_evaluator: pin("challenge-evaluator", &roles.challenge_evaluator),
        venue_finalization: pin("venue-finalization", &roles.venue_finalization),
        market_penalty: pin("market-penalty", &roles.market_penalty),
        settlement_observer: pin("settlement-observer", &roles.settlement_observer),
        anchor_publisher: pin("anchor-publisher", &roles.anchor_publisher),
        max_snapshot_age_secs: 3_600,
        settlement_finality_requirement: chio_settle::FindingFinalityRequirement::Confirmations {
            min_depth: 1,
        },
        audit_authority: pin("audit-authority", &roles.audit_authority),
        audit_randomness_witness: pin(
            "audit-randomness-witness",
            &roles.audit_randomness_witness,
        ),
        audit_pool: FindingPoolPin {
            principal_id: "pool:local-audit".to_owned(),
            rail_destination: "rail:venue-ledger:local-audit".to_owned(),
            currency: "USD".to_owned(),
            authority_epoch: 1,
        },
        challenge_administration_pool: FindingPoolPin {
            principal_id: "pool:local-challenge-administration".to_owned(),
            rail_destination: "rail:venue-ledger:local-challenge-administration".to_owned(),
            currency: "USD".to_owned(),
            authority_epoch: 1,
        },
        community_fund_destination: "0xcccccccccccccccccccccccccccccccccccccccc".to_owned(),
        status_feed_operator_ref: status_feed_id.clone(),
        status_feed_operator: FindingStatusOperatorPin {
            feed_id: status_feed_id,
            role: FINDING_STATUS_OPERATOR_ROLE.to_owned(),
            authority: status_authority,
            rotation_policy_ref: "local/rotation/status-feed".to_owned(),
            authorization_sha256: sha256_hex(b"local-cognition-market-status-authorization-v1"),
            revoked_from: None,
        },
        status_feed_service_bond: FindingStatusServiceBond {
            bond_id: "local-status-service-bond".to_owned(),
            feed_id: "finding-status/local-cognition-market".to_owned(),
            operator_id: "local-status-feed-operator".to_owned(),
            locked_units: 1_000,
            currency: "USD".to_owned(),
            valid_from,
            valid_until,
            inclusion_sla_secs: 3_600,
            missed_inclusion_slash_units: 100,
            equivocation_slash_units: 1_000,
            evidence_sha256: sha256_hex(b"local-cognition-market-status-bond-v1"),
        },
        status_max_epoch_age_secs: 300,
        fee_schedule_operator_keys: vec![roles.fee_schedule_operator.public_key().to_hex()],
    };
    let buyer_key = Keypair::generate();
    let profile = FindingOperatorProfile {
        schema: FINDING_OPERATOR_PROFILE_SCHEMA.to_owned(),
        listen,
        service_token: random_token("service"),
        paths: FindingOperatorPaths {
            authority_database: "authority.db".to_owned(),
            authority_lock_root: "locks".to_owned(),
            operator_database: "operator.db".to_owned(),
            receipt_database: "receipts.db".to_owned(),
            packages_directory: "packages".to_owned(),
            reports_directory: "reports".to_owned(),
        },
        market,
        secrets: roles.secrets(),
        payload_key_hex: Keypair::generate().seed_hex(),
        buyers: vec![FindingOperatorBuyerProfile {
            principal_id: buyer_principal.to_owned(),
            bearer_token: random_token("buyer"),
            signing_seed: buyer_key.seed_hex(),
            payout_destination: buyer_payout.to_owned(),
        }],
        sellers: vec![FindingOperatorSellerProfile {
            principal_id: seller_principal.to_owned(),
            bearer_token: random_token("seller"),
            signing_seed: roles.listing.seed_hex(),
            payout_destination: seller_payout.to_owned(),
        }],
    };
    profile
        .validate()
        .map_err(CliError::cli_other_error)?;
    let profile_bytes = canonical_json_bytes(&profile)?;
    write_secret_new(&profile_path, &profile_bytes)?;
    let client_profile_path = directory.join(CLIENT_PROFILE_FILE);
    let client_profile = profile.client_profile();
    client_profile
        .validate()
        .map_err(CliError::cli_other_error)?;
    write_public_new(&client_profile_path, &canonical_json_bytes(&client_profile)?)?;
    let buyer_client_path = directory.join(BUYER_CLIENT_FILE);
    let buyer_client = profile
        .buyer_client_profiles()
        .into_iter()
        .next()
        .ok_or_else(|| CliError::cli_other_error("buyer client profile is missing".to_owned()))?;
    write_secret_new(&buyer_client_path, &canonical_json_bytes(&buyer_client)?)?;
    let seller_client_path = directory.join(SELLER_CLIENT_FILE);
    let seller_client = profile
        .seller_client_profiles()
        .into_iter()
        .next()
        .ok_or_else(|| CliError::cli_other_error("seller client profile is missing".to_owned()))?;
    write_secret_new(&seller_client_path, &canonical_json_bytes(&seller_client)?)?;

    let paths = ResolvedOperatorPaths::new(directory, &profile.paths);
    SqliteAuthorityStore::provision(&paths.authority_database, &paths.authority_lock_root)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    initialize_operator_database(&paths.operator_database)?;
    SqliteReceiptStore::open(&paths.receipt_database)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;

    let output = serde_json::json!({
        "profile": profile_path,
        "clientProfile": client_profile_path,
        "buyerClient": buyer_client_path,
        "sellerClient": seller_client_path,
        "listen": profile.listen,
        "buyerPrincipal": buyer_principal,
        "sellerPrincipal": seller_principal,
        "schema": FINDING_OPERATOR_PROFILE_SCHEMA,
    });
    if json_output {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("profile:         {}", profile_path.display());
        println!("client_profile:  {}", client_profile_path.display());
        println!("buyer_client:    {}", buyer_client_path.display());
        println!("seller_client:   {}", seller_client_path.display());
        println!("listen:          http://{}", profile.listen);
        println!("buyer_principal: {}", terminal_safe(buyer_principal));
        println!("seller_principal: {}", terminal_safe(seller_principal));
        println!("credentials:     retained in separate mode-0600 client files");
    }
    Ok(())
}

pub(super) fn cmd_finding_operator_serve(profile_path: &Path) -> Result<(), CliError> {
    set_operator_umask();
    let (profile, root) = load_profile(profile_path)?;
    let paths = ResolvedOperatorPaths::new(&root, &profile.paths);
    let authority = Arc::new(
        SqliteAuthorityStore::open_serving(
            &paths.authority_database,
            &paths.authority_lock_root,
        )
        .map_err(|error| CliError::cli_other_error(error.to_string()))?,
    );
    let resolver = Arc::new(
        FindingOperatorAuthorityStatusResolver::new(
            profile.market.authority_status.clone(),
            profile
                .authority_status_key()
                .map_err(CliError::cli_other_error)?,
        )
        .map_err(CliError::cli_other_error)?,
    );
    let executor = Arc::new(
        FindingOperatorPurchaseExecutor::new(
            FindingOperatorPurchaseStorage {
                authority: authority.clone(),
                operator_db_path: paths.operator_database.clone(),
                receipt_db_path: paths.receipt_database.clone(),
                payload_tenant_id: TenantId::new("cognition-market-pilot"),
                payload_key: TenantKey::from_bytes(
                    profile
                        .payload_key_bytes()
                        .map_err(CliError::cli_other_error)?,
                ),
            },
            profile.market.clone(),
            resolver.clone(),
            profile.purchase_keys().map_err(CliError::cli_other_error)?,
            profile
                .buyer_credentials()
                .map_err(CliError::cli_other_error)?,
            &profile.service_token,
        )
        .map_err(CliError::cli_other_error)?,
    );
    let seller_executor = Arc::new(
        OperatorSellerSubmissionExecutor::new(
            profile_path.to_path_buf(),
            &profile,
            &paths,
            authority.clone(),
        )
        .map_err(CliError::cli_other_error)?,
    );
    let rail = Arc::new(VenueLedgerRailObserver);
    let challenge_keys = profile
        .challenge_keys()
        .map_err(CliError::cli_other_error)?;
    let filings = Arc::new(
        FindingOperatorFilingResolver::new(
            SqliteFindingOperatorBundleStore::open(&paths.operator_database)
                .map_err(|error| CliError::cli_other_error(error.to_string()))?,
            profile.market.clone(),
        )
        .map_err(CliError::cli_other_error)?,
    );
    let challenge = Arc::new(
        FindingChallengeCoordinator::new(
            authority.finding_challenge_store(),
            authority.finding_purchase_store(),
            authority.finding_status_store(),
            &profile.market,
            challenge_keys.evaluator,
            challenge_keys.finalization,
            challenge_keys.penalty,
            resolver.clone(),
            rail.clone(),
            filings,
            FindingDisputeLockDisposition::Returned,
        )
        .map_err(|error| CliError::cli_other_error(error.to_string()))?,
    );
    let challenge_runtime = FindingChallengeSubmissionRuntime::new(authority, challenge)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let config = trust_config(&profile, &paths);
    chio_control_plane::trust_control::serve_with_finding_operator_market_runtime(
        config,
        challenge_runtime,
        executor,
        seller_executor,
        rail,
    )
}

pub(super) fn cmd_finding_operator_tick(
    profile_path: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    set_operator_umask();
    let (profile, root) = load_profile(profile_path)?;
    let paths = ResolvedOperatorPaths::new(&root, &profile.paths);
    let bundles = SqliteFindingOperatorBundleStore::open(&paths.operator_database)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let payments = SqliteFindingOperatorPaymentAdapter::open(&paths.operator_database)
        .map_err(CliError::cli_other_error)?;
    let reconciled_jobs = reconcile_admission_jobs(profile_path)?;
    let report = serde_json::json!({
        "schema": "chio.finding.operator-tick.v1",
        "bundleCount": bundles.bundle_count().map_err(|error| CliError::cli_other_error(error.to_string()))?,
        "proofCount": bundles.proof_count().map_err(|error| CliError::cli_other_error(error.to_string()))?,
        "terminalCount": bundles.terminal_count().map_err(|error| CliError::cli_other_error(error.to_string()))?,
        "purchaseJobCount": bundles.purchase_job_count().map_err(|error| CliError::cli_other_error(error.to_string()))?,
        "captureCount": payments.capture_count().map_err(CliError::cli_other_error)?,
        "reconciledJobs": reconciled_jobs,
    });
    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("bundles:         {}", report["bundleCount"]);
        println!("proofs:          {}", report["proofCount"]);
        println!("terminals:       {}", report["terminalCount"]);
        println!("purchase_jobs:   {}", report["purchaseJobCount"]);
        println!("captures:        {}", report["captureCount"]);
        println!("reconciled_jobs: {}", report["reconciledJobs"]);
    }
    Ok(())
}

pub(super) struct ResolvedOperatorPaths {
    pub(super) authority_database: PathBuf,
    pub(super) authority_lock_root: PathBuf,
    pub(super) operator_database: PathBuf,
    pub(super) receipt_database: PathBuf,
    pub(super) packages_directory: PathBuf,
    pub(super) reports_directory: PathBuf,
}

impl ResolvedOperatorPaths {
    pub(super) fn new(root: &Path, paths: &FindingOperatorPaths) -> Self {
        Self {
            authority_database: root.join(&paths.authority_database),
            authority_lock_root: root.join(&paths.authority_lock_root),
            operator_database: root.join(&paths.operator_database),
            receipt_database: root.join(&paths.receipt_database),
            packages_directory: root.join(&paths.packages_directory),
            reports_directory: root.join(&paths.reports_directory),
        }
    }
}

fn trust_config(
    profile: &FindingOperatorProfile,
    paths: &ResolvedOperatorPaths,
) -> TrustServiceConfig {
    TrustServiceConfig {
        listen: profile.listen,
        service_token: profile.service_token.clone(),
        tenant_read_tokens: BTreeMap::new(),
        receipt_db_path: None,
        revocation_db_path: None,
        authority_seed_path: None,
        authority_db_path: None,
        budget_db_path: None,
        joint_authority_db_path: Some(paths.authority_database.clone()),
        fiscal_runtime: None,
        enterprise_providers_file: None,
        federation_policies_file: None,
        scim_lifecycle_file: None,
        verifier_policies_file: None,
        verifier_challenge_db_path: None,
        passport_statuses_file: None,
        passport_issuance_offers_file: None,
        certification_registry_file: None,
        certification_discovery_file: None,
        issuance_policy: None,
        runtime_assurance_policy: None,
        advertise_url: Some(format!("http://{}", profile.listen)),
        allow_local_peer_urls: true,
        certification_public_metadata_ttl_seconds: 300,
        peer_urls: Vec::new(),
        cluster_sync_interval: Duration::from_millis(250),
        roster_policy: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        finding_market: Some(profile.market.clone()),
    }
}

pub(super) fn load_profile(path: &Path) -> Result<(FindingOperatorProfile, PathBuf), CliError> {
    require_secret_file(path)?;
    let raw = fs::read(path)?;
    if raw.is_empty() || raw.len() > PROFILE_MAX_BYTES {
        return Err(CliError::cli_other_error(
            "operator profile is empty or exceeds its size bound".to_owned(),
        ));
    }
    let text = std::str::from_utf8(&raw)
        .map_err(|_| CliError::cli_other_error("operator profile is not UTF-8".to_owned()))?;
    let strict = chio_core::canonical::canonical_json_bytes_from_str(text)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    if strict != raw {
        return Err(CliError::cli_other_error(
            "operator profile is not strict canonical JSON".to_owned(),
        ));
    }
    let profile: FindingOperatorProfile = serde_json::from_slice(&raw)?;
    if canonical_json_bytes(&profile)? != raw {
        return Err(CliError::cli_other_error(
            "operator profile typed serialization is not byte-stable".to_owned(),
        ));
    }
    profile.validate().map_err(CliError::cli_other_error)?;
    let root = path
        .parent()
        .ok_or_else(|| CliError::cli_other_error("operator profile has no parent".to_owned()))?
        .to_path_buf();
    Ok((profile, root))
}

fn initialize_operator_database(path: &Path) -> Result<(), CliError> {
    SqliteFindingOperatorBundleStore::open(path)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    SqliteFindingPayloadStore::open(path)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    SqliteFindingOperatorPaymentAdapter::open(path).map_err(CliError::cli_other_error)?;
    Ok(())
}

fn random_token(label: &str) -> String {
    format!("{label}_{}", Keypair::generate().seed_hex())
}

fn unix_time() -> Result<u64, CliError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| CliError::cli_other_error(error.to_string()))
}

fn create_secure_directory(path: &Path) -> Result<(), CliError> {
    if path.exists() {
        if !path.is_dir() {
            return Err(CliError::cli_other_error(format!(
                "{} is not a directory",
                path.display()
            )));
        }
    } else {
        fs::create_dir(path)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_secret_new(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    use std::io::Write as _;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_public_new(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    write_secret_new(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}

fn require_secret_file(path: &Path) -> Result<(), CliError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(CliError::cli_other_error(
            "operator profile must be a regular non-symlink file".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CliError::cli_other_error(
                "operator profile must not grant group or other permissions".to_owned(),
            ));
        }
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(CliError::cli_other_error(
                "operator profile is not owned by the current user".to_owned(),
            ));
        }
    }
    Ok(())
}

fn set_operator_umask() {
    #[cfg(unix)]
    unsafe {
        libc::umask(0o077);
    }
}
