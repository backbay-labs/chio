//! Bind a hosted endpoint to authority retained by its embedding application.
//!
//! No request field selects a grant. The trusted caller gives each endpoint one
//! immutable worker capability, and shares one admission owner across endpoints.
use super::*;
use chio_core::capability::{
    aggregate_invocation::{verify_aggregate_invocation_budget, AggregateInvocationScope},
    attenuation::scope_hash,
};
use chio_kernel::admission_operation::DurableAdmissionMode;

#[derive(Clone)]
pub struct BoundSessionAuthority {
    root: CapabilityToken,
    worker: CapabilityToken,
    admission: Arc<DurableAdmissionRuntime>,
}

impl BoundSessionAuthority {
    /// Reuse signed authority. This constructor never issues or renews a grant.
    pub fn new(
        root: CapabilityToken,
        worker: CapabilityToken,
        admission: Arc<DurableAdmissionRuntime>,
    ) -> Result<Self, CliError> {
        let binding = Self {
            root,
            worker,
            admission,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn subject(&self) -> &PublicKey {
        &self.worker.subject
    }

    fn validate(&self) -> Result<(), CliError> {
        let signer = self.admission.kernel_keypair().public_key();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| failure("system clock precedes the epoch"))?
            .as_secs();
        if self.root.issuer != signer
            || self.worker.issuer != signer
            || !self.root.verify_signature()?
            || !self.worker.verify_signature()?
            || !self.root.delegation_chain.is_empty()
            || self.worker.delegation_chain.len() != 1
            || self.root.issued_at > now
            || self.worker.issued_at > now
            || self.root.expires_at <= now
            || self.worker.expires_at <= now
        {
            return Err(failure(
                "requires current signed one-hop worker authority from this admission owner",
            ));
        }
        let family =
            verify_aggregate_invocation_budget(&self.root, std::slice::from_ref(&signer), None)?
                .ok_or_else(|| failure("root has no shared invocation allowance"))?;
        let child = verify_aggregate_invocation_budget(&self.worker, &[signer], Some(&self.root))?
            .ok_or_else(|| failure("worker has no shared invocation allowance"))?;
        if family.scope != AggregateInvocationScope::DelegationFamily
            || child.owner_id != family.owner_id
            || child.max_invocations != family.max_invocations
            || self.worker.scope.authorizes_delegation()
        {
            return Err(failure(
                "worker must retain the selected family and cannot delegate",
            ));
        }
        Ok(())
    }

    pub(super) fn install(
        &self,
        kernel: &ChioKernel,
        receipts: Option<&FsPath>,
    ) -> Result<Vec<CapabilityToken>, CliError> {
        self.validate()?;
        if kernel.public_key() != self.root.issuer {
            return Err(failure("kernel signer differs from retained authority"));
        }
        let receipts = receipts.ok_or_else(|| failure("requires a retained receipt store"))?;
        let store = chio_store_sqlite::SqliteReceiptStore::open(receipts)?;
        store
            .record_capability_snapshot(&self.root, None)
            .map_err(|error| failure(&error.to_string()))?;
        store
            .record_capability_snapshot(&self.worker, Some(&self.root.id))
            .map_err(|error| failure(&error.to_string()))?;
        kernel.set_capability_trust_root(self.root.issuer.clone(), scope_hash(&self.root.scope)?);
        kernel
            .register_budget_parent(self.root.id.clone(), 10_000)
            .map_err(|error| failure(&error.to_string()))?;
        Ok(vec![self.worker.clone()])
    }

    pub(super) fn restore(
        &self,
        kernel: &ChioKernel,
        receipts: Option<&FsPath>,
        record: &RemoteSessionResumeRecord,
        policy: &str,
    ) -> Result<Vec<CapabilityToken>, CliError> {
        if record.agent_id != self.worker.subject.to_hex()
            || record.policy_fingerprint.as_deref() != Some(policy)
            || canonical_json_bytes(&record.issued_capabilities)?
                != canonical_json_bytes(&[self.worker.clone()])?
        {
            return Err(failure("retained session differs from its worker, policy, or grant; automatic replacement is forbidden"));
        }
        self.install(kernel, receipts)
    }
}

impl RemoteSessionFactory {
    pub(super) fn new_bound(
        config: RemoteServeHttpConfig,
        binding: BoundSessionAuthority,
    ) -> Result<Self, CliError> {
        binding.validate()?;
        let policy = load_policy(&config.policy_path)?;
        if policy.kernel.durable_admission_mode != DurableAdmissionMode::All
            || !policy.default_capabilities.is_empty()
            || config.session_db_path.is_none()
            || config.receipt_db_path.is_none()
            || config.control_url.is_some()
            || config.budget_db_path.is_some()
            || config.revocation_db_path.is_some()
            || config.authority_db_path.is_some()
            || config.authority_seed_path.is_some()
        {
            return Err(failure("requires durable admission for all calls, private session/receipt stores, no default issuance and no separate authority or accounting"));
        }
        let mut paths = Vec::new();
        if let Some(path) = config.session_db_path.as_deref() {
            paths.push(("session database", path));
        }
        if let Some(path) = config.receipt_db_path.as_deref() {
            paths.push(("receipt database", path));
        }
        validate_distinct_database_paths(&paths)?;
        Ok(Self {
            config,
            durable_admission: Some(binding.admission.clone()),
            bound_authority: Some(binding),
            shared_upstream_owner: Arc::new(StdMutex::new(None)),
            lifecycle_policy: read_session_lifecycle_policy(),
        })
    }
}

fn failure(message: &str) -> CliError {
    CliError::cli_other_error(format!("bound session authority: {message}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[path = "bound_session_tests.rs"]
mod tests;
