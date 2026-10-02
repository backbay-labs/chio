use chio_core::{
    CreateElicitationOperation, CreateElicitationResult, CreateMessageOperation,
    CreateMessageResult, OperationContext, RootDefinition,
};
use chio_kernel::runtime::NestedFlowClient;
use chio_kernel::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

/// The application client supports cancellation. These applications do not offer
/// nested model, root, or elicitation requests, so those fail explicitly.
pub struct ApplicationClient(pub Arc<AtomicBool>);
impl NestedFlowClient for ApplicationClient {
    fn poll_parent_cancellation(&mut self, context: &OperationContext) -> Result<(), KernelError> {
        if self.0.load(Ordering::SeqCst) {
            return Err(KernelError::RequestCancelled {
                request_id: context.request_id.clone(),
                reason: "The operator stopped this task".into(),
            });
        }
        Ok(())
    }
    fn list_roots(
        &mut self,
        _: &OperationContext,
        _: &OperationContext,
    ) -> Result<Vec<RootDefinition>, KernelError> {
        Err(unsupported())
    }
    fn create_message(
        &mut self,
        _: &OperationContext,
        _: &OperationContext,
        _: &CreateMessageOperation,
    ) -> Result<CreateMessageResult, KernelError> {
        Err(unsupported())
    }
    fn create_elicitation(
        &mut self,
        _: &OperationContext,
        _: &OperationContext,
        _: &CreateElicitationOperation,
    ) -> Result<CreateElicitationResult, KernelError> {
        Err(unsupported())
    }
    fn notify_elicitation_completed(
        &mut self,
        _: &OperationContext,
        _: &str,
    ) -> Result<(), KernelError> {
        Ok(())
    }
    fn notify_resource_updated(
        &mut self,
        _: &OperationContext,
        _: &str,
    ) -> Result<(), KernelError> {
        Ok(())
    }
    fn notify_resources_list_changed(&mut self, _: &OperationContext) -> Result<(), KernelError> {
        Ok(())
    }
}
fn unsupported() -> KernelError {
    KernelError::RequestIncomplete(
        "This application client does not support nested requests".into(),
    )
}
