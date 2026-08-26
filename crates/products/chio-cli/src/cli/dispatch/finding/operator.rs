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
    FindingDisputeLockDisposition, FindingOperatorBundleStoreError, SqliteAuthorityStore,
    SqliteFindingOperatorBundleStore, SqliteFindingOperatorPaymentAdapter,
    SqliteFindingPayloadStore, SqliteReceiptStore, TenantId, TenantKey,
};
use subtle::ConstantTimeEq;

use super::finding_verified_fix::{
    read_canonical_file, reconcile_admission_jobs, run_bounded_output_command_capture,
    write_private_atomic,
};

const PROFILE_FILE: &str = "operator-profile.json";
const CLIENT_PROFILE_FILE: &str = "client-profile.json";
const BUYER_CLIENT_FILE: &str = "buyer-client.json";
const SELLER_CLIENT_FILE: &str = "seller-client.json";
const PROFILE_MAX_BYTES: usize = 1024 * 1024;
const ROLE_WINDOW_SECS: u64 = 10 * 365 * 24 * 60 * 60;
const SELLER_SUBMISSION_JOB_SCHEMA: &str = "chio.finding.seller-submission-job.v1";
const SELLER_SUBMISSION_JOB_MAX_BYTES: usize = 1024 * 1024;
const MAX_RETAINED_SELLER_JOBS: usize = 256;
const SELLER_SUBMISSION_STORAGE_CAP_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const SELLER_SUBMISSION_RESERVED_BYTES: u64 =
    super::finding_verified_fix::REPOSITORY_STAGE_MAX_BYTES + 64 * 1024 * 1024;
const SELLER_SUBMISSION_STORAGE_MAX_ENTRIES: u64 = 100_000;
const SELLER_SUBMISSION_RESERVED_ENTRIES: u64 =
    super::finding_verified_fix::REPOSITORY_STAGE_MAX_ENTRIES + 2;
const SELLER_RETRACTION_JOB_SCHEMA: &str = "chio.finding.seller-retraction-job.v1";
const SELLER_PACKAGE_COMMAND_TIMEOUT: Duration = Duration::from_secs(330);
const SELLER_ADMISSION_COMMAND_TIMEOUT: Duration = Duration::from_secs(300);
const INIT_COMPLETE_FILE: &str = "operator-init-complete.json";

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
    artifact_store: SqliteFindingOperatorBundleStore,
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
            artifact_store: SqliteFindingOperatorBundleStore::open(&paths.operator_database)
                .map_err(|error| error.to_string())?,
            sellers,
            submission_lock: Mutex::new(()),
        })
    }

    fn authenticate_seller(
        &self,
        token: &str,
    ) -> Result<(String, Keypair), FindingSellerSubmissionError> {
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
        let repository =
            approved_seller_repository(&self.profile.seller_repository_root, &repository)?;
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
            require_seller_submission_capacity(
                &self.reports_directory,
                &self.packages_directory,
            )?;
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

        let retained_file_bytes = seller_submission_storage_bytes(
            &self.reports_directory,
            &self.packages_directory,
        )?;
        self.artifact_store
            .reserve_seller_artifact_capacity(
                &request.request_id,
                principal,
                &job.request_sha256,
                retained_file_bytes,
                SELLER_SUBMISSION_RESERVED_BYTES,
                SELLER_SUBMISSION_STORAGE_CAP_BYTES,
            )
            .map_err(seller_artifact_capacity_error)?;

        let outcome: Result<
            FindingVerifiedFixSubmissionResponse,
            FindingSellerSubmissionError,
        > = (|| {
            if !package_path.exists() {
                let mut args = vec![
                    "finding".to_owned(),
                    "package".to_owned(),
                    "verified-fix".to_owned(),
                    "--profile".to_owned(),
                    self.profile_path.display().to_string(),
                    "--repository".to_owned(),
                    repository.display().to_string(),
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
            self.artifact_store
                .commit_seller_artifact_capacity(
                    &request.request_id,
                    principal,
                    &job.request_sha256,
                    &finding_id,
                )
                .map_err(seller_artifact_capacity_error)?;
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
        })();
        match outcome {
            Ok(result) => Ok(result),
            Err(original) => match self.artifact_store.release_seller_artifact_capacity(
                &request.request_id,
                principal,
                &job.request_sha256,
            ) {
                Ok(_) => match reclaim_nonrecoverable_submission_files(
                    &original,
                    &job_path,
                    &package_path,
                ) {
                    Ok(()) => Err(original),
                    Err(cleanup) => Err(FindingSellerSubmissionError::Internal(format!(
                        "{original}; failed verified-fix reclamation failed: {cleanup}"
                    ))),
                },
                Err(cleanup) => Err(FindingSellerSubmissionError::Internal(format!(
                    "{original}; seller artifact capacity cleanup failed: {cleanup}"
                ))),
            },
        }
    }
}

impl FindingSellerSubmissionExecutor for OperatorSellerSubmissionExecutor {
    fn authenticate(&self, bearer_token: &str) -> Result<(), FindingSellerSubmissionError> {
        self.authenticate_seller(bearer_token).map(|_| ())
    }

    fn submit(
        &self,
        bearer_token: &str,
        request: &FindingVerifiedFixSubmissionRequest,
    ) -> Result<FindingVerifiedFixSubmissionResponse, FindingSellerSubmissionError> {
        let (principal, _) = self.authenticate_seller(bearer_token)?;
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
        let (principal, seller_key) = self.authenticate_seller(bearer_token)?;
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
        let (mut job, create_job) = if job_path.exists() {
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
            (stored, false)
        } else {
            (
                FindingSellerRetractionJob {
                    schema: SELLER_RETRACTION_JOB_SCHEMA.to_owned(),
                    request_id: request.request_id.clone(),
                    request_sha256,
                    finding_id: request.finding_id.clone(),
                    seller_principal: principal.clone(),
                    intent_b64: None,
                    intent_id: None,
                    result: None,
                },
                true,
            )
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
        let bundle = self
            .artifact_store
            .get(&request.finding_id)
            .map_err(retraction_bundle_store_error)?;
        let bundle: chio_control_plane::trust_control::finding_operator_bundle::FindingOperatorBundle =
            serde_json::from_slice(&bundle.bundle_json)
                .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?;
        if bundle.finding.issuer != seller_key.public_key() {
            return Err(FindingSellerSubmissionError::Authentication);
        }
        if create_job {
            require_seller_submission_capacity(
                &self.reports_directory,
                &self.packages_directory,
            )?;
            write_private_atomic(
                &job_path,
                &canonical_json_bytes(&job)
                    .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?,
            )
            .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?;
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

fn retraction_bundle_store_error(
    error: FindingOperatorBundleStoreError,
) -> FindingSellerSubmissionError {
    match error {
        FindingOperatorBundleStoreError::NotFound => FindingSellerSubmissionError::Invalid(
            "retracted Finding is not retained by this operator".to_owned(),
        ),
        FindingOperatorBundleStoreError::Unavailable(_) => FindingSellerSubmissionError::Pending(
            "retained Finding bundle is temporarily unavailable".to_owned(),
        ),
        _ => FindingSellerSubmissionError::Internal(
            "retained Finding bundle failed integrity verification".to_owned(),
        ),
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
            return Err(operator_status_error(status, &body));
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

fn operator_status_error(status: u16, body: &str) -> FindingSellerSubmissionError {
    let message = format!(
        "operator status request failed with HTTP {status}: {}",
        body.chars().take(4096).collect::<String>()
    );
    if matches!(status, 408 | 425 | 429 | 500 | 502 | 503 | 504) {
        FindingSellerSubmissionError::Pending(message)
    } else {
        FindingSellerSubmissionError::Invalid(message)
    }
}

fn run_chio_json(args: &[String]) -> Result<serde_json::Value, FindingSellerSubmissionError> {
    let output = run_chio(
        args,
        ChioCommandFailure::Pending,
        SELLER_ADMISSION_COMMAND_TIMEOUT,
    )?;
    serde_json::from_slice(&output)
        .map_err(|_| FindingSellerSubmissionError::Internal("chio subprocess returned invalid JSON".to_owned()))
}

fn run_chio_success(args: &[String]) -> Result<(), FindingSellerSubmissionError> {
    run_chio(
        args,
        ChioCommandFailure::Invalid,
        SELLER_PACKAGE_COMMAND_TIMEOUT,
    )
    .map(|_| ())
}

#[derive(Clone, Copy)]
enum ChioCommandFailure {
    Invalid,
    Pending,
}

fn run_chio(
    args: &[String],
    failure: ChioCommandFailure,
    timeout: Duration,
) -> Result<Vec<u8>, FindingSellerSubmissionError> {
    let binary = std::env::current_exe()
        .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?;
    let mut command = Command::new(binary);
    command.args(args);
    let output = run_bounded_output_command_capture(
        command,
        SELLER_SUBMISSION_JOB_MAX_BYTES,
        timeout,
        "chio seller command",
    )
    .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr);
        return Err(classify_chio_command_failure(
            failure,
            message.trim().chars().take(4096).collect(),
        ));
    }
    Ok(output.stdout)
}

fn classify_chio_command_failure(
    failure: ChioCommandFailure,
    message: String,
) -> FindingSellerSubmissionError {
    match failure {
        ChioCommandFailure::Invalid => FindingSellerSubmissionError::Invalid(message),
        ChioCommandFailure::Pending => FindingSellerSubmissionError::Pending(message),
    }
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
    repository_root: &Path,
    buyer_principal: &str,
    buyer_payout: &str,
    seller_principal: &str,
    seller_payout: &str,
    json_output: bool,
) -> Result<(), CliError> {
    set_operator_umask();
    let repository_root = fs::canonicalize(repository_root)?;
    if !repository_root.is_dir() {
        return Err(CliError::cli_other_error(
            "seller repository root must be an existing directory".to_owned(),
        ));
    }
    let repository_root = repository_root.to_str().ok_or_else(|| {
        CliError::cli_other_error("seller repository root must be valid UTF-8".to_owned())
    })?;
    create_secure_directory(directory)?;
    let profile_path = directory.join(PROFILE_FILE);
    for child in ["locks", "packages", "reports"] {
        create_secure_directory(&directory.join(child))?;
    }

    let profile = if profile_path.exists() {
        let (profile, _) = load_profile(&profile_path)?;
        require_matching_init_request(
            &profile,
            listen,
            repository_root,
            buyer_principal,
            buyer_payout,
            seller_principal,
            seller_payout,
        )?;
        profile
    } else {
        let now = unix_time()?;
        let valid_from = now.saturating_sub(60);
        let valid_until = now.checked_add(ROLE_WINDOW_SECS).ok_or_else(|| {
            CliError::cli_other_error("operator role window overflowed".to_owned())
        })?;
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
            settlement_finality_requirement:
                chio_settle::FindingFinalityRequirement::Confirmations { min_depth: 1 },
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
                authorization_sha256: sha256_hex(
                    b"local-cognition-market-status-authorization-v1",
                ),
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
            seller_repository_root: repository_root.to_owned(),
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
        write_secret_exact_or_new(&profile_path, &profile_bytes)?;
        profile
    };
    let client_profile_path = directory.join(CLIENT_PROFILE_FILE);
    let client_profile = profile.client_profile();
    client_profile
        .validate()
        .map_err(CliError::cli_other_error)?;
    write_public_exact_or_new(&client_profile_path, &canonical_json_bytes(&client_profile)?)?;
    let buyer_client_path = directory.join(BUYER_CLIENT_FILE);
    let buyer_client = profile
        .buyer_client_profiles()
        .map_err(CliError::cli_other_error)?
        .into_iter()
        .next()
        .ok_or_else(|| CliError::cli_other_error("buyer client profile is missing".to_owned()))?;
    write_secret_exact_or_new(&buyer_client_path, &canonical_json_bytes(&buyer_client)?)?;
    let seller_client_path = directory.join(SELLER_CLIENT_FILE);
    let seller_client = profile
        .seller_client_profiles()
        .into_iter()
        .next()
        .ok_or_else(|| CliError::cli_other_error("seller client profile is missing".to_owned()))?;
    write_secret_exact_or_new(&seller_client_path, &canonical_json_bytes(&seller_client)?)?;

    let paths = ResolvedOperatorPaths::new(directory, &profile.paths);
    SqliteAuthorityStore::provision(&paths.authority_database, &paths.authority_lock_root)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    initialize_operator_database(&paths.operator_database)?;
    SqliteReceiptStore::open(&paths.receipt_database)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let completion_path = directory.join(INIT_COMPLETE_FILE);
    write_public_exact_or_new(
        &completion_path,
        &canonical_json_bytes(&serde_json::json!({
            "profileSha256": sha256_hex(&canonical_json_bytes(&profile)?),
            "schema": "chio.finding.operator-init-complete.v1",
        }))?,
    )?;

    let output = serde_json::json!({
        "profile": profile_path,
        "clientProfile": client_profile_path,
        "buyerClient": buyer_client_path,
        "sellerClient": seller_client_path,
        "listen": profile.listen,
        "repositoryRoot": profile.seller_repository_root.clone(),
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
        println!("repository_root: {}", profile.seller_repository_root);
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
    let reconciliation = reconcile_admission_jobs(profile_path)?;
    let report = serde_json::json!({
        "schema": "chio.finding.operator-tick.v1",
        "bundleCount": bundles.bundle_count().map_err(|error| CliError::cli_other_error(error.to_string()))?,
        "proofCount": bundles.proof_count().map_err(|error| CliError::cli_other_error(error.to_string()))?,
        "terminalCount": bundles.terminal_count().map_err(|error| CliError::cli_other_error(error.to_string()))?,
        "purchaseJobCount": bundles.purchase_job_count().map_err(|error| CliError::cli_other_error(error.to_string()))?,
        "captureCount": payments.capture_count().map_err(CliError::cli_other_error)?,
        "reconciledJobs": reconciliation.reconciled_jobs,
        "failedAdmissionJobCount": reconciliation.failed_jobs.len(),
        "failedAdmissionJobs": reconciliation.failed_jobs,
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
        println!(
            "failed_admission_jobs: {}",
            report["failedAdmissionJobCount"]
        );
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

fn require_matching_init_request(
    profile: &FindingOperatorProfile,
    listen: SocketAddr,
    repository_root: &str,
    buyer_principal: &str,
    buyer_payout: &str,
    seller_principal: &str,
    seller_payout: &str,
) -> Result<(), CliError> {
    let matches = profile.listen == listen
        && profile.seller_repository_root == repository_root
        && profile.buyers.len() == 1
        && profile.sellers.len() == 1
        && profile.buyers[0].principal_id == buyer_principal
        && profile.buyers[0].payout_destination == buyer_payout
        && profile.sellers[0].principal_id == seller_principal
        && profile.sellers[0].payout_destination == seller_payout;
    if !matches {
        return Err(CliError::cli_other_error(
            "existing operator profile does not match the requested initialization".to_owned(),
        ));
    }
    Ok(())
}

fn approved_seller_repository(
    configured_root: &str,
    requested: &Path,
) -> Result<PathBuf, FindingSellerSubmissionError> {
    let approved_root = fs::canonicalize(configured_root).map_err(|error| {
        FindingSellerSubmissionError::Internal(format!(
            "seller repository root is unavailable: {error}"
        ))
    })?;
    if !approved_root.is_dir() {
        return Err(FindingSellerSubmissionError::Internal(
            "seller repository root is not a directory".to_owned(),
        ));
    }
    let repository = fs::canonicalize(requested).map_err(|_| {
        FindingSellerSubmissionError::Invalid(
            "verified-fix repository is unavailable to the operator".to_owned(),
        )
    })?;
    if !repository.is_dir() || !repository.starts_with(&approved_root) {
        return Err(FindingSellerSubmissionError::Invalid(
            "verified-fix repository is outside the approved repository root".to_owned(),
        ));
    }
    if repository.to_str().is_none() {
        return Err(FindingSellerSubmissionError::Invalid(
            "verified-fix repository path must be valid UTF-8".to_owned(),
        ));
    }
    Ok(repository)
}

fn require_seller_submission_capacity(
    reports_directory: &Path,
    packages_directory: &Path,
) -> Result<(), FindingSellerSubmissionError> {
    let mut retained_jobs = 0usize;
    for entry in fs::read_dir(reports_directory)
        .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?
    {
        let entry =
            entry.map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".seller-submission-job.json")
            || name.ends_with(".seller-retraction-job.json")
        {
            retained_jobs = retained_jobs.saturating_add(1);
            if retained_jobs >= MAX_RETAINED_SELLER_JOBS {
                return Err(FindingSellerSubmissionError::Pending(
                    "seller job capacity is exhausted".to_owned(),
                ));
            }
        }
    }

    seller_submission_storage_bytes(reports_directory, packages_directory).map(|_| ())
}

fn seller_submission_storage_bytes(
    reports_directory: &Path,
    packages_directory: &Path,
) -> Result<u64, FindingSellerSubmissionError> {

    let maximum_existing_bytes = SELLER_SUBMISSION_STORAGE_CAP_BYTES
        .saturating_sub(SELLER_SUBMISSION_RESERVED_BYTES);
    let maximum_existing_entries = SELLER_SUBMISSION_STORAGE_MAX_ENTRIES
        .saturating_sub(SELLER_SUBMISSION_RESERVED_ENTRIES);
    let mut pending = vec![reports_directory.to_path_buf(), packages_directory.to_path_buf()];
    let mut bytes = 0u64;
    let mut entries = 0u64;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)
            .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?
        {
            let entry = entry
                .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?;
            entries = entries.saturating_add(1);
            if entries > maximum_existing_entries {
                return Err(FindingSellerSubmissionError::Pending(
                    "seller submission storage entry capacity is exhausted".to_owned(),
                ));
            }
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| FindingSellerSubmissionError::Internal(error.to_string()))?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                pending.push(entry.path());
            } else {
                bytes = bytes.saturating_add(metadata.len());
            }
            if bytes > maximum_existing_bytes {
                return Err(FindingSellerSubmissionError::Pending(
                    "seller submission storage capacity is exhausted".to_owned(),
                ));
            }
        }
    }
    Ok(bytes)
}

fn seller_artifact_capacity_error(
    error: FindingOperatorBundleStoreError,
) -> FindingSellerSubmissionError {
    match error {
        FindingOperatorBundleStoreError::SellerArtifactCapacity => {
            FindingSellerSubmissionError::Pending(
                "seller submission storage capacity is exhausted".to_owned(),
            )
        }
        other => FindingSellerSubmissionError::Internal(other.to_string()),
    }
}

fn reclaim_nonrecoverable_submission_files(
    error: &FindingSellerSubmissionError,
    job_path: &Path,
    package_path: &Path,
) -> Result<(), FindingSellerSubmissionError> {
    if !matches!(error, FindingSellerSubmissionError::Invalid(_)) {
        return Ok(());
    }
    remove_submission_file(package_path, "failed verified-fix package")?;
    remove_submission_file(job_path, "failed verified-fix job")
}

fn remove_submission_file(
    path: &Path,
    label: &str,
) -> Result<(), FindingSellerSubmissionError> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(FindingSellerSubmissionError::Internal(format!(
                "cannot remove {label}: {error}"
            )))
        }
    }
    let parent = path.parent().ok_or_else(|| {
        FindingSellerSubmissionError::Internal(format!("{label} path has no parent directory"))
    })?;
    sync_directory(parent).map_err(|error| {
        FindingSellerSubmissionError::Internal(format!(
            "cannot durably remove {label}: {error}"
        ))
    })
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

fn write_secret_exact_or_new(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    if path.exists() {
        require_exact_regular_file(path, bytes)?;
        return set_secret_permissions(path);
    }
    let parent = path.parent().ok_or_else(|| {
        CliError::cli_other_error("operator output path has no parent directory".to_owned())
    })?;
    let temporary = parent.join(format!(
        ".operator-init-{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    write_secret_new(&temporary, bytes)?;
    if let Err(error) = fs::hard_link(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        if path.exists() {
            require_exact_regular_file(path, bytes)?;
            return set_secret_permissions(path);
        }
        return Err(CliError::from(error));
    }
    fs::remove_file(&temporary)?;
    sync_directory(parent)
}

fn write_public_exact_or_new(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    write_secret_exact_or_new(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
    }
    path.parent()
        .ok_or_else(|| {
            CliError::cli_other_error("operator output path has no parent directory".to_owned())
        })
        .and_then(sync_directory)
}

fn require_exact_regular_file(path: &Path, expected: &[u8]) -> Result<(), CliError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(CliError::cli_other_error(format!(
            "{} is not a regular non-symlink file",
            path.display()
        )));
    }
    if metadata.len() != u64::try_from(expected.len()).unwrap_or(u64::MAX) {
        return Err(CliError::cli_other_error(format!(
            "{} already contains different initialization data",
            path.display()
        )));
    }
    let actual = fs::read(path)?;
    if actual != expected {
        return Err(CliError::cli_other_error(format!(
            "{} already contains different initialization data",
            path.display()
        )));
    }
    Ok(())
}

fn set_secret_permissions(path: &Path) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), CliError> {
    let directory = OpenOptions::new().read(true).open(path)?;
    directory.sync_all()?;
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

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn seller_repository_is_confined_to_the_configured_root() {
        let temporary = tempfile::tempdir().unwrap();
        let approved_root = temporary.path().join("approved");
        let repository = approved_root.join("repository");
        let outside = temporary.path().join("outside");
        fs::create_dir_all(&repository).unwrap();
        fs::create_dir(&outside).unwrap();
        let approved_root = fs::canonicalize(approved_root).unwrap();
        let configured_root = approved_root.to_str().unwrap();

        assert_eq!(
            approved_seller_repository(configured_root, &repository).unwrap(),
            fs::canonicalize(&repository).unwrap()
        );
        assert!(matches!(
            approved_seller_repository(configured_root, &outside),
            Err(FindingSellerSubmissionError::Invalid(_))
        ));

        let escape = approved_root.join("escape");
        symlink(&outside, &escape).unwrap();
        assert!(matches!(
            approved_seller_repository(configured_root, &escape),
            Err(FindingSellerSubmissionError::Invalid(_))
        ));
    }

    #[test]
    fn seller_submission_capacity_bounds_jobs_and_storage() {
        let temporary = tempfile::tempdir().unwrap();
        let reports = temporary.path().join("reports");
        let packages = temporary.path().join("packages");
        fs::create_dir(&reports).unwrap();
        fs::create_dir(&packages).unwrap();
        assert!(require_seller_submission_capacity(&reports, &packages).is_ok());

        for index in 0..MAX_RETAINED_SELLER_JOBS {
            let suffix = if index % 2 == 0 {
                "seller-submission-job.json"
            } else {
                "seller-retraction-job.json"
            };
            fs::write(
                reports.join(format!("{index}.{suffix}")),
                b"{}",
            )
            .unwrap();
        }
        assert!(matches!(
            require_seller_submission_capacity(&reports, &packages),
            Err(FindingSellerSubmissionError::Pending(_))
        ));

        for entry in fs::read_dir(&reports).unwrap() {
            fs::remove_file(entry.unwrap().path()).unwrap();
        }
        let oversized = packages.join("oversized.draft.json");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(oversized)
            .unwrap()
            .set_len(
                SELLER_SUBMISSION_STORAGE_CAP_BYTES - SELLER_SUBMISSION_RESERVED_BYTES + 1,
            )
            .unwrap();
        assert!(matches!(
            require_seller_submission_capacity(&reports, &packages),
            Err(FindingSellerSubmissionError::Pending(_))
        ));
    }

    #[test]
    fn retraction_bundle_failures_preserve_missing_retryable_and_integrity_classes() {
        assert!(matches!(
            retraction_bundle_store_error(FindingOperatorBundleStoreError::NotFound),
            FindingSellerSubmissionError::Invalid(_)
        ));
        assert!(matches!(
            retraction_bundle_store_error(FindingOperatorBundleStoreError::Unavailable(
                "database is busy".to_owned()
            )),
            FindingSellerSubmissionError::Pending(_)
        ));
        assert!(matches!(
            retraction_bundle_store_error(FindingOperatorBundleStoreError::DigestMismatch),
            FindingSellerSubmissionError::Internal(_)
        ));
    }

    #[test]
    fn retraction_status_failures_preserve_retryable_operator_responses() {
        assert!(matches!(
            operator_status_error(503, "database is busy"),
            FindingSellerSubmissionError::Pending(_)
        ));
        assert!(matches!(
            operator_status_error(400, "invalid intent"),
            FindingSellerSubmissionError::Invalid(_)
        ));
    }

    #[test]
    fn failed_verified_fix_jobs_reclaim_only_nonrecoverable_files() {
        let temporary = tempfile::tempdir().unwrap();
        let job = temporary.path().join("request.seller-submission-job.json");
        let package = temporary.path().join("request.draft.json");
        fs::write(&job, b"job").unwrap();
        fs::write(&package, b"package").unwrap();
        reclaim_nonrecoverable_submission_files(
            &FindingSellerSubmissionError::Pending("retry".to_owned()),
            &job,
            &package,
        )
        .unwrap();
        assert!(job.exists());
        assert!(package.exists());

        reclaim_nonrecoverable_submission_files(
            &FindingSellerSubmissionError::Invalid("bad revision".to_owned()),
            &job,
            &package,
        )
        .unwrap();
        assert!(!job.exists());
        assert!(!package.exists());
    }

    #[test]
    fn package_failures_are_reclaimable_while_admission_failures_remain_retryable() {
        assert!(matches!(
            classify_chio_command_failure(
                ChioCommandFailure::Invalid,
                "package failed".to_owned()
            ),
            FindingSellerSubmissionError::Invalid(_)
        ));
        assert!(matches!(
            classify_chio_command_failure(
                ChioCommandFailure::Pending,
                "admission failed".to_owned()
            ),
            FindingSellerSubmissionError::Pending(_)
        ));
    }
}
