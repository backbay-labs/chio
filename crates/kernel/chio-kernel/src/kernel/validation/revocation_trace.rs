use super::*;

impl ChioKernel {
    /// Revoke a capability and all descendants in its delegation subtree.
    ///
    /// When a root capability is revoked, every capability whose
    /// `delegation_chain` contains the revoked ID will also be rejected
    /// on presentation (the kernel checks all chain entries against the
    /// revocation store).
    pub fn revoke_capability(&self, capability_id: &CapabilityId) -> Result<(), KernelError> {
        info!(capability_id = %capability_id, "revoking capability");
        let trace_transition = self.lock_runtime_trace_transition()?;
        let newly_revoked = self.with_revocation_store(|store| Ok(store.revoke(capability_id)?))?;
        let trace_event = if self.runtime_trace_observer.is_some() {
            Some(RuntimeTraceEvent::RevocationCommitted {
                source_sequence: self.allocate_runtime_trace_source_sequence()?,
                capability_id: capability_id.clone(),
                newly_revoked,
                delegation_depth_limit: self.config.max_delegation_depth,
            })
        } else {
            None
        };
        drop(trace_transition);
        if let Some(event) = trace_event {
            self.observe_runtime_trace(event);
        }
        Ok(())
    }

    pub(crate) fn check_tool_call_revocation_admission(
        &self,
        request: &ToolCallRequest,
    ) -> Result<(), KernelError> {
        let trace_transition = self.lock_runtime_trace_transition()?;
        let result = self.check_revocation(&request.capability);
        let revoked_capability_id = match &result {
            Err(KernelError::CapabilityRevoked(capability_id))
            | Err(KernelError::DelegationChainRevoked(capability_id)) => {
                Some(capability_id.clone())
            }
            _ => None,
        };
        let trace_event = if self.runtime_trace_observer.is_some() {
            let revocation_subject_ids = std::iter::once(request.capability.id.clone())
                .chain(
                    request
                        .capability
                        .delegation_chain
                        .iter()
                        .map(|link| link.capability_id.clone()),
                )
                .collect();
            Some(RuntimeTraceEvent::RevocationAdmission {
                source_sequence: self.allocate_runtime_trace_source_sequence()?,
                request_id: request.request_id.clone(),
                capability_id: request.capability.id.clone(),
                revocation_subject_ids,
                revoked_capability_id,
                delegation_depth: u32::try_from(request.capability.delegation_chain.len())
                    .unwrap_or(u32::MAX),
                delegation_depth_limit: self.config.max_delegation_depth,
                admitted: result.is_ok(),
            })
        } else {
            None
        };
        drop(trace_transition);
        if let Some(event) = trace_event {
            self.observe_runtime_trace(event);
        }
        result
    }

    pub(crate) fn observe_runtime_trace(&self, event: RuntimeTraceEvent) {
        if let Some(observer) = &self.runtime_trace_observer {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                observer.observe(event);
            }));
            if result.is_err() {
                warn!("runtime trace observer panicked");
            }
        }
    }
}
