use super::*;
use chio_core::capability::{
    attenuation::{compute_attenuation_witness, delegate, Attenuation, AttenuationProof},
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityTokenAttenuationBody, CapabilityTokenBody},
};
use chio_core::delegation_receipt::ScopeAttenuation;

fn authority() -> (PathBuf, BoundSessionAuthority) {
    let directory = std::env::temp_dir().join(format!(
        "chio-bound-authority-{}",
        Keypair::generate().public_key().to_hex()
    ));
    std::fs::create_dir(&directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let admission =
        Arc::new(DurableAdmissionRuntime::open(&directory.join("admission.db")).unwrap());
    let issuer = admission.kernel_keypair();
    let owner = Keypair::generate();
    let subject = Keypair::generate().public_key();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let root = CapabilityToken::sign_aggregate_family_root(
        CapabilityTokenBody {
            id: "mission".into(),
            issuer: issuer.public_key(),
            subject: owner.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "fs".into(),
                    tool_name: "read_text_file".into(),
                    operations: vec![Operation::Invoke, Operation::Delegate],
                    constraints: vec![],
                    max_invocations: Some(10),
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..Default::default()
            },
            issued_at: now,
            expires_at: now + 3600,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        3,
        &issuer,
    )
    .unwrap();
    let mut scope = root.scope.clone();
    scope.grants[0].operations = vec![Operation::Invoke];
    let delegated = delegate(
        &root,
        &scope,
        &owner,
        &subject,
        ScopeAttenuation {
            steps: vec![Attenuation::RemoveOperation {
                server_id: "fs".into(),
                tool_name: "read_text_file".into(),
                operation: Operation::Delegate,
            }],
            child_expires_at: Some(root.expires_at),
            budget_share_bps: Some(1_000),
        },
        now,
        [1; 16],
    )
    .unwrap();
    let worker = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: "worker".into(),
                issuer: issuer.public_key(),
                subject,
                scope: scope.clone(),
                issued_at: now,
                expires_at: root.expires_at,
                delegation_chain: delegated.complete_chain(),
                aggregate_invocation_budget: root.aggregate_invocation_budget.clone(),
            },
            caveats: vec![],
            scope_attenuations: delegated.attenuation.steps,
            attenuation_proof: AttenuationProof {
                parent_scope_hash: scope_hash(&root.scope).unwrap(),
                child_scope_hash: scope_hash(&scope).unwrap(),
                normalized_subset_proof: compute_attenuation_witness(&root.scope, &scope).unwrap(),
            },
            budget_share_bps: Some(1_000),
        },
        &issuer,
    )
    .unwrap();
    (
        directory,
        BoundSessionAuthority::new(root, worker, admission).unwrap(),
    )
}

#[test]
fn selected_worker_is_not_reissued_on_repeated_binding() {
    let (directory, binding) = authority();
    let original = canonical_json_bytes(&binding.worker).unwrap();
    for _ in 0..3 {
        let next = BoundSessionAuthority::new(
            binding.root.clone(),
            binding.worker.clone(),
            binding.admission.clone(),
        )
        .unwrap();
        assert_eq!(canonical_json_bytes(&next.worker).unwrap(), original);
        assert!(Arc::ptr_eq(&binding.admission, &next.admission));
    }
    drop(binding);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn root_from_another_admission_owner_is_rejected() {
    let (directory, binding) = authority();
    let (other_directory, other) = authority();
    assert!(BoundSessionAuthority::new(
        binding.root.clone(),
        binding.worker.clone(),
        other.admission.clone()
    )
    .is_err());
    drop((binding, other));
    std::fs::remove_dir_all(directory).unwrap();
    std::fs::remove_dir_all(other_directory).unwrap();
}

#[test]
fn altered_allowance_or_worker_identity_is_rejected() {
    let (directory, binding) = authority();
    let mut worker = binding.worker.clone();
    worker
        .aggregate_invocation_budget
        .as_mut()
        .unwrap()
        .max_invocations += 1;
    assert!(
        BoundSessionAuthority::new(binding.root.clone(), worker, binding.admission.clone())
            .is_err()
    );
    let mut worker = binding.worker.clone();
    worker.subject = Keypair::generate().public_key();
    assert!(
        BoundSessionAuthority::new(binding.root.clone(), worker, binding.admission.clone())
            .is_err()
    );
    drop(binding);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn direct_root_cannot_be_used_as_a_worker() {
    let (directory, binding) = authority();
    assert!(BoundSessionAuthority::new(
        binding.root.clone(),
        binding.root.clone(),
        binding.admission.clone()
    )
    .is_err());
    drop(binding);
    std::fs::remove_dir_all(directory).unwrap();
}
