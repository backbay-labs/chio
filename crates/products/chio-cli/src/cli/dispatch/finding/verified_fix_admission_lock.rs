use super::CliError;

use std::fs::{File, OpenOptions};
use std::path::Path;
use std::time::{Duration, Instant};

const ADMISSION_JOB_LOCK_FILE: &str = ".finding-admission-jobs.lock";
const ADMISSION_JOB_LOCK_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug)]
pub(super) struct FindingAdmissionJobLock {
    file: File,
}

impl FindingAdmissionJobLock {
    pub(super) fn acquire(operator_root: &Path) -> Result<Self, CliError> {
        Self::acquire_with_timeout(operator_root, ADMISSION_JOB_LOCK_TIMEOUT)
    }

    fn acquire_with_timeout(operator_root: &Path, timeout: Duration) -> Result<Self, CliError> {
        let path = operator_root.join(ADMISSION_JOB_LOCK_FILE);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options.open(&path).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to open admission-job lock {}: {error}",
                path.display()
            ))
        })?;
        let started = Instant::now();
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Self { file }),
                Err(std::fs::TryLockError::WouldBlock) if started.elapsed() < timeout => {
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err(CliError::cli_io_error(format!(
                        "admission-job lock {} exceeded its deadline",
                        path.display()
                    )));
                }
                Err(std::fs::TryLockError::Error(error)) => {
                    return Err(CliError::cli_io_error(format!(
                        "failed to acquire admission-job lock {}: {error}",
                        path.display()
                    )));
                }
            }
        }
    }
}

impl Drop for FindingAdmissionJobLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn admission_job_lock_serializes_independent_open_files() {
        let root = tempfile::tempdir().unwrap();
        let first = FindingAdmissionJobLock::acquire_with_timeout(
            root.path(),
            Duration::from_millis(50),
        )
        .unwrap();
        let blocked = FindingAdmissionJobLock::acquire_with_timeout(
            root.path(),
            Duration::from_millis(50),
        )
        .unwrap_err();
        assert!(blocked.to_string().contains("exceeded its deadline"));
        drop(first);
        FindingAdmissionJobLock::acquire_with_timeout(
            root.path(),
            Duration::from_millis(50),
        )
        .unwrap();
    }
}
