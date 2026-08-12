use super::*;

impl ChioKernel {
    /// Re-run output-aware guard checks over the exact value that is about to
    /// cross the kernel boundary. Any error or panic denies fail-closed.
    pub(crate) fn validate_guarded_output(
        &self,
        request: &ToolCallRequest,
        matched_grant_index: usize,
        output: &ToolServerOutput,
        post_invocation_applied: bool,
    ) -> Result<(), KernelError> {
        let context = GuardContext {
            request,
            scope: &request.capability.scope,
            agent_id: &request.agent_id,
            server_id: &request.server_id,
            session_filesystem_roots: None,
            matched_grant_index: Some(matched_grant_index),
        };
        for guard in self.guards.iter() {
            if !post_invocation_applied
                && !self.post_invocation_pipeline.is_empty()
                && guard.requires_exact_released_output(&context)
            {
                return Err(KernelError::GuardDenied(
                    "exact output binding requires post-invocation validation".to_owned(),
                ));
            }
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                guard.validate_output_before_release(&context, output)
            })) {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    return Err(KernelError::GuardDenied(format!(
                        "guard output validation failed: {error}"
                    )));
                }
                Err(_) => {
                    return Err(KernelError::GuardDenied(
                        "guard output validation panicked (fail-closed)".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}
