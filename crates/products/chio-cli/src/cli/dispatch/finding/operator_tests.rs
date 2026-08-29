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
        fs::write(reports.join(format!("{index}.{suffix}")), b"{}").unwrap();
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
        .set_len(SELLER_SUBMISSION_STORAGE_CAP_BYTES - SELLER_SUBMISSION_RESERVED_BYTES + 1)
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
        classify_chio_command_failure(ChioCommandFailure::Invalid, "package failed".to_owned()),
        FindingSellerSubmissionError::Invalid(_)
    ));
    assert!(matches!(
        classify_chio_command_failure(ChioCommandFailure::Pending, "admission failed".to_owned()),
        FindingSellerSubmissionError::Pending(_)
    ));
}
