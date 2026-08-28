use std::time::{SystemTime, UNIX_EPOCH};

use chio_finding_market_store_postgres::{
    HostedJobLease, HostedMarketJob, HostedMarketStoreError, HostedTenantId,
    PostgresFindingMarketStore,
};
use futures_util::{stream, StreamExt as _, TryStreamExt as _};

use crate::executor::FirecrackerExecutor;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostedWorkerRun {
    pub claimed: u32,
    pub completed: u32,
    pub guest_rejected: u32,
    pub retried: u32,
    pub exhausted: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum HostedWorkerServiceError {
    #[error("hosted finding worker configuration is invalid")]
    Configuration,
    #[error("hosted finding worker store is unavailable")]
    Store,
    #[error("hosted finding worker system clock is unavailable")]
    Clock,
}

#[derive(Clone)]
pub struct HostedFindingWorker {
    store: PostgresFindingMarketStore,
    executor: FirecrackerExecutor,
    worker_id: String,
    lease_duration_secs: u64,
    max_attempts: u64,
    retry_base_secs: u64,
}

impl HostedFindingWorker {
    pub fn new(
        store: PostgresFindingMarketStore,
        executor: FirecrackerExecutor,
        worker_id: impl Into<String>,
        lease_duration_secs: u64,
        max_attempts: u32,
        retry_base_secs: u64,
    ) -> Result<Self, HostedWorkerServiceError> {
        let worker_id = worker_id.into();
        if !valid_identifier(&worker_id)
            || !(5..=3_600).contains(&lease_duration_secs)
            || !(1..=20).contains(&max_attempts)
            || !(1..=300).contains(&retry_base_secs)
            || lease_duration_secs <= executor.execution_timeout().as_secs()
        {
            return Err(HostedWorkerServiceError::Configuration);
        }
        Ok(Self {
            store,
            executor,
            worker_id,
            lease_duration_secs,
            max_attempts: u64::from(max_attempts),
            retry_base_secs,
        })
    }

    /// Claim and process one bounded batch for a single tenant.
    pub async fn run_once(
        &self,
        tenant: &HostedTenantId,
    ) -> Result<HostedWorkerRun, HostedWorkerServiceError> {
        let now = current_time()?;
        let limit = u32::try_from(self.executor.max_instances())
            .map_err(|_| HostedWorkerServiceError::Configuration)?
            .min(100);
        let jobs = self
            .store
            .claim_due_jobs(
                tenant,
                &self.worker_id,
                now,
                self.lease_duration_secs,
                limit,
            )
            .await
            .map_err(map_store)?;
        let claimed =
            u32::try_from(jobs.len()).map_err(|_| HostedWorkerServiceError::Configuration)?;
        let outcomes = stream::iter(jobs)
            .map(|job| self.process_job(job, now))
            .buffer_unordered(self.executor.max_instances())
            .try_collect::<Vec<_>>()
            .await?;
        let mut run = HostedWorkerRun {
            claimed,
            completed: 0,
            guest_rejected: 0,
            retried: 0,
            exhausted: 0,
        };
        for outcome in outcomes {
            match outcome {
                JobOutcome::Completed => run.completed += 1,
                JobOutcome::GuestRejected => run.guest_rejected += 1,
                JobOutcome::Retried => run.retried += 1,
                JobOutcome::Exhausted => run.exhausted += 1,
            }
        }
        Ok(run)
    }

    async fn process_job(
        &self,
        job: HostedMarketJob,
        claimed_at: u64,
    ) -> Result<JobOutcome, HostedWorkerServiceError> {
        let lease = HostedJobLease::new(&self.worker_id, job.lease_fence).map_err(map_store)?;
        if job.attempt_count > self.max_attempts {
            self.store
                .exhaust_job(
                    &job.tenant_id,
                    &job.job_id,
                    &lease,
                    "attempt_budget_exhausted",
                    current_time()?,
                )
                .await
                .map_err(map_store)?;
            return Ok(JobOutcome::Exhausted);
        }
        match self.executor.execute(&job, claimed_at).await {
            Ok(result) => {
                self.store
                    .complete_job(
                        &job.tenant_id,
                        &job.job_id,
                        &lease,
                        &result.envelope_json,
                        current_time()?,
                    )
                    .await
                    .map_err(map_store)?;
                Ok(
                    if result.guest_classification
                        == crate::protocol::FindingWorkerExitClassification::Succeeded
                    {
                        JobOutcome::Completed
                    } else {
                        JobOutcome::GuestRejected
                    },
                )
            }
            Err(error) if job.attempt_count >= self.max_attempts => {
                self.store
                    .exhaust_job(
                        &job.tenant_id,
                        &job.job_id,
                        &lease,
                        error.code(),
                        current_time()?,
                    )
                    .await
                    .map_err(map_store)?;
                Ok(JobOutcome::Exhausted)
            }
            Err(error) => {
                let finished_at = current_time()?;
                let exponent = u32::try_from(job.attempt_count.saturating_sub(1))
                    .unwrap_or(u32::MAX)
                    .min(10);
                let delay = self
                    .retry_base_secs
                    .checked_mul(1_u64 << exponent)
                    .ok_or(HostedWorkerServiceError::Configuration)?
                    .min(3_600);
                let retry_at = finished_at
                    .checked_add(delay)
                    .ok_or(HostedWorkerServiceError::Configuration)?;
                self.store
                    .fail_job(
                        &job.tenant_id,
                        &job.job_id,
                        &lease,
                        error.code(),
                        retry_at,
                        finished_at,
                    )
                    .await
                    .map_err(map_store)?;
                Ok(JobOutcome::Retried)
            }
        }
    }
}

enum JobOutcome {
    Completed,
    GuestRejected,
    Retried,
    Exhausted,
}

fn current_time() -> Result<u64, HostedWorkerServiceError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| HostedWorkerServiceError::Clock)
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn map_store(_error: HostedMarketStoreError) -> HostedWorkerServiceError {
    HostedWorkerServiceError::Store
}
