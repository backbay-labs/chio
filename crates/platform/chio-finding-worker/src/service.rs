use std::time::Duration;

use chio_finding_market_store_postgres::{
    HostedJobLease, HostedMarketJob, HostedMarketStoreError, HostedTenantId,
    PostgresFindingMarketStore,
};
use futures_util::{stream, StreamExt as _, TryStreamExt as _};
use tokio_util::sync::CancellationToken;

use crate::executor::FirecrackerExecutor;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedWorkerRun {
    pub claimed: u32,
    pub completed: u32,
    pub guest_rejected: u32,
    pub retried: u32,
    pub exhausted: u32,
    pub cancelled: u32,
    pub claimed_job_ids: Vec<String>,
    pub completed_job_ids: Vec<String>,
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
    lease_heartbeat_secs: u64,
    max_attempts: u64,
    retry_base_secs: u64,
}

impl HostedFindingWorker {
    pub fn new(
        store: PostgresFindingMarketStore,
        executor: FirecrackerExecutor,
        worker_id: impl Into<String>,
        lease_duration_secs: u64,
        lease_heartbeat_secs: u64,
        max_attempts: u32,
        retry_base_secs: u64,
    ) -> Result<Self, HostedWorkerServiceError> {
        let worker_id = worker_id.into();
        if !valid_identifier(&worker_id)
            || !(5..=3_600).contains(&lease_duration_secs)
            || lease_heartbeat_secs == 0
            || lease_heartbeat_secs >= lease_duration_secs
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
            lease_heartbeat_secs,
            max_attempts: u64::from(max_attempts),
            retry_base_secs,
        })
    }

    /// Claim and process one bounded batch for a single tenant.
    pub async fn run_once(
        &self,
        tenant: &HostedTenantId,
    ) -> Result<HostedWorkerRun, HostedWorkerServiceError> {
        let limit = u32::try_from(self.executor.max_instances())
            .map_err(|_| HostedWorkerServiceError::Configuration)?
            .min(100);
        self.run_once_with_limit(tenant, limit).await
    }

    /// Claim and process one batch while enforcing the tenant's configured
    /// concurrency ceiling independently of the host-wide VM capacity.
    pub async fn run_once_with_limit(
        &self,
        tenant: &HostedTenantId,
        tenant_limit: u32,
    ) -> Result<HostedWorkerRun, HostedWorkerServiceError> {
        self.run_once_with_limit_cancellable(tenant, tenant_limit, &CancellationToken::new())
            .await
    }

    /// Claim and process one batch while observing cooperative shutdown.
    pub async fn run_once_with_limit_cancellable(
        &self,
        tenant: &HostedTenantId,
        tenant_limit: u32,
        cancellation: &CancellationToken,
    ) -> Result<HostedWorkerRun, HostedWorkerServiceError> {
        if cancellation.is_cancelled() {
            return Ok(HostedWorkerRun {
                claimed: 0,
                completed: 0,
                guest_rejected: 0,
                retried: 0,
                exhausted: 0,
                cancelled: 0,
                claimed_job_ids: Vec::new(),
                completed_job_ids: Vec::new(),
            });
        }
        let host_limit = u32::try_from(self.executor.max_instances())
            .map_err(|_| HostedWorkerServiceError::Configuration)?
            .min(100);
        if tenant_limit == 0 {
            return Err(HostedWorkerServiceError::Configuration);
        }
        let limit = tenant_limit.min(host_limit);
        let jobs = self
            .store
            .claim_due_jobs(tenant, &self.worker_id, self.lease_duration_secs, limit)
            .await
            .map_err(map_store)?;
        let claimed =
            u32::try_from(jobs.len()).map_err(|_| HostedWorkerServiceError::Configuration)?;
        let claimed_job_ids = jobs.iter().map(|job| job.job_id.clone()).collect();
        let outcomes = stream::iter(jobs)
            .map(|job| self.process_job(job, cancellation.clone()))
            .buffer_unordered(self.executor.max_instances())
            .try_collect::<Vec<_>>()
            .await?;
        let mut run = HostedWorkerRun {
            claimed,
            completed: 0,
            guest_rejected: 0,
            retried: 0,
            exhausted: 0,
            cancelled: 0,
            claimed_job_ids,
            completed_job_ids: Vec::new(),
        };
        for outcome in outcomes {
            match outcome {
                JobOutcome::Completed(job_id) => {
                    run.completed += 1;
                    run.completed_job_ids.push(job_id);
                }
                JobOutcome::GuestRejected => run.guest_rejected += 1,
                JobOutcome::Retried => run.retried += 1,
                JobOutcome::Exhausted => run.exhausted += 1,
                JobOutcome::Cancelled => run.cancelled += 1,
            }
        }
        Ok(run)
    }

    async fn process_job(
        &self,
        job: HostedMarketJob,
        cancellation: CancellationToken,
    ) -> Result<JobOutcome, HostedWorkerServiceError> {
        let lease = HostedJobLease::new(&self.worker_id, job.lease_fence).map_err(map_store)?;
        let job_id = job.job_id.clone();
        if job.attempt_count > self.max_attempts {
            self.store
                .exhaust_job(
                    &job.tenant_id,
                    &job.job_id,
                    &lease,
                    "attempt_budget_exhausted",
                )
                .await
                .map_err(map_store)?;
            return Ok(JobOutcome::Exhausted);
        }
        let heartbeat_duration = Duration::from_secs(self.lease_heartbeat_secs);
        let mut heartbeat = tokio::time::interval_at(
            tokio::time::Instant::now() + heartbeat_duration,
            heartbeat_duration,
        );
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let execution = self.executor.execute(&job, job.updated_at);
        tokio::pin!(execution);
        let execution_result = loop {
            tokio::select! {
                result = &mut execution => break result,
                () = cancellation.cancelled() => return Ok(JobOutcome::Cancelled),
                _ = heartbeat.tick() => {
                    self.store
                        .renew_job_lease(
                            &job.tenant_id,
                            &job.job_id,
                            &lease,
                            self.lease_duration_secs,
                        )
                        .await
                        .map_err(map_store)?;
                }
            }
        };
        match execution_result {
            Ok(result) => {
                self.store
                    .complete_job(&job.tenant_id, &job.job_id, &lease, &result.envelope_json)
                    .await
                    .map_err(map_store)?;
                Ok(
                    if result.guest_classification
                        == crate::protocol::FindingWorkerExitClassification::Succeeded
                    {
                        JobOutcome::Completed(job_id)
                    } else {
                        JobOutcome::GuestRejected
                    },
                )
            }
            Err(error) if job.attempt_count >= self.max_attempts => {
                self.store
                    .exhaust_job(&job.tenant_id, &job.job_id, &lease, error.code())
                    .await
                    .map_err(map_store)?;
                Ok(JobOutcome::Exhausted)
            }
            Err(error) => {
                let exponent = u32::try_from(job.attempt_count.saturating_sub(1))
                    .unwrap_or(u32::MAX)
                    .min(10);
                let delay = self
                    .retry_base_secs
                    .checked_mul(1_u64 << exponent)
                    .ok_or(HostedWorkerServiceError::Configuration)?
                    .min(3_600);
                self.store
                    .fail_job(&job.tenant_id, &job.job_id, &lease, error.code(), delay)
                    .await
                    .map_err(map_store)?;
                Ok(JobOutcome::Retried)
            }
        }
    }
}

enum JobOutcome {
    Completed(String),
    GuestRejected,
    Retried,
    Exhausted,
    Cancelled,
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
